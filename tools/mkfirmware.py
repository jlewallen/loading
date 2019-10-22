#!/usr/bin/env python3

import os
import sys
import struct
import time
import datetime
import argparse
import hashlib
import logging
import lief
import hashlib
import platform
import threading
import utilities

from collections import defaultdict

class FkbWriter:
    def __init__(self, elf_analyzer, fkb_path):
        self.elf = elf_analyzer
        self.fkb_path = fkb_path

    def process(self, name):
        fkbh_section = self.elf.fkbheader()
        if fkbh_section:
            logging.info("Found FKB section: %s bytes" % (fkbh_section.size))
            self.populate_header(fkbh_section, name)
        else:
            logging.info("No specialized handling for binary.")

        self.elf.binary.write(self.fkb_path)

    def populate_header(self, section, name):
        header = FkbHeader(self.fkb_path)
        header.read(section.content)
        header.populate(self.elf, name)
        section.content = header.write(self.elf)

class FkbHeader:
    SIGNATURE_FIELD          = 0
    VERSION_FIELD            = 1
    HEADER_SIZE_FIELD        = 2
    FLAGS_FIELD              = 3
    TIMESTAMP_FIELD          = 4
    BUILD_NUMBER_FIELD       = 5
    VERSION_FIELD            = 6
    BINARY_SIZE_FIELD        = 7
    TABLES_OFFSET_FIELD      = 8
    BINARY_DATA_FIELD        = 9
    BINARY_BSS_FIELD         = 10
    BINARY_GOT_FIELD         = 11
    VTOR_OFFSET_FIELD        = 12
    GOT_OFFSET_FIELD         = 13
    NAME_FIELD               = 14
    HASH_SIZE_FIELD          = 15
    HASH_FIELD               = 16
    NUMBER_SYMBOLS_FIELD     = 17
    NUMBER_RELOCATIONS_FIELD = 18

    def __init__(self, fkb_path):
        self.min_packspec = '<4sIIIII16sIIIIIII256sI128sII'
        self.min_size = struct.calcsize(self.min_packspec)
        self.fkb_path = fkb_path

    def read(self, data):
        self.actual_size = len(data)
        self.extra = bytearray(data[self.min_size:])
        self.fields = list(struct.unpack(self.min_packspec, bytearray(data[:self.min_size])))

    def has_invalid_name(self, value):
        return len(value) == 0 or value[0] == '\0' or value[0] == 0

    def add_table_section(self, ea, table, table_alignment):
        binary_size_before = ea.get_binary_size()

        extra_padding = self.aligned(len(table), table_alignment) - len(table)
        section = lief.ELF.Section()
        section.name = ".data.fkdyn"
        section.type = lief.ELF.SECTION_TYPES.PROGBITS
        section.content = table + bytearray([0] * extra_padding)
        section.add(lief.ELF.SECTION_FLAGS.WRITE)
        section.add(lief.ELF.SECTION_FLAGS.ALLOC)
        section.alignment = 4
        section = ea.binary.add(section, True)
        section.virtual_address = binary_size_before + 0x8000
        logging.info("Dynamic table virtual address: 0x%x" % (section.virtual_address) )

    def populate(self, ea, name):
        self.symbols = bytearray()
        self.relocations = bytearray()

        # Address in the symbol table we write to the image seems totally wrong...
        indices = {}
        index = 0
        for symbol in ea.symbols:
            s = ea.symbols[symbol]
            try:
                self.symbols += struct.pack('<I24s', s[2], bytes(symbol.name, 'utf-8'))
            except:
                raise Exception("Error packing symbol: %s %d %d %d" % (symbol.name, s[0], s[1], s[2]))

            indices[symbol] = index
            index += 1

        for r in ea.relocations:
            self.relocations += struct.pack('<II', indices[r[0]], r[1])

        table_alignment = 2048
        self.table_size = self.aligned(len(self.symbols) + len(self.relocations), table_alignment)

        self.fields[self.TIMESTAMP_FIELD] = ea.timestamp()
        self.fields[self.BINARY_SIZE_FIELD] = ea.get_binary_size() + self.table_size
        self.fields[self.TABLES_OFFSET_FIELD] = ea.get_binary_size()
        self.fields[self.BINARY_DATA_FIELD] = ea.get_data_size()
        self.fields[self.BINARY_BSS_FIELD] = ea.get_bss_size()
        self.fields[self.BINARY_GOT_FIELD] = ea.get_got_size()
        self.fields[self.VTOR_OFFSET_FIELD] = 1024

        self.add_table_section(ea, self.symbols + self.relocations, table_alignment)

        got = ea.got()
        if got:
            self.fields[self.GOT_OFFSET_FIELD] = got.virtual_address - 0x20000000
        else:
            self.fields[self.GOT_OFFSET_FIELD] = 0x0

        fwhash = ea.calculate_hash()
        self.fields[self.HASH_SIZE_FIELD] = len(fwhash)
        self.fields[self.HASH_FIELD] = fwhash
        if name:
            self.fields[self.NAME_FIELD] = name
        if self.has_invalid_name(self.fields[self.NAME_FIELD]):
            self.fields[self.NAME_FIELD] = self.generate_name(ea)

        if 'BUILD_NUMBER' in os.environ:
            self.fields[self.BUILD_NUMBER_FIELD] = int(os.environ['BUILD_NUMBER'])

        self.fields[self.NUMBER_SYMBOLS_FIELD] = len(ea.symbols)
        self.fields[self.NUMBER_RELOCATIONS_FIELD] = len(ea.relocations)

    def aligned(self, size, on):
        if size % on != 0:
            return (size + (on - (size % on)))
        return size

    def generate_name(self, ea):
        name = os.path.basename(self.fkb_path)
        when = datetime.datetime.utcfromtimestamp(ea.timestamp())
        ft = when.strftime("%Y%m%d_%H%M%S")
        return bytes(name + "_" + platform.node() + "_" + ft, 'utf8')

    def write(self, ea):
        new_header = bytearray(bytes(struct.pack(self.min_packspec, *self.fields)))

        logging.info("Code Size: %d" % (ea.code().size))
        logging.info("Data Size: %d" % (ea.get_data_size()))
        logging.info(" BSS Size: %d" % (ea.get_bss_size()))
        logging.info(" GOT Size: %d" % (ea.get_got_size()))
        logging.info(" Dyn size: %d" % (self.table_size))

        logging.info("Name: %s" % (self.fields[self.NAME_FIELD]))
        logging.info("Version: %s" % (self.fields[self.VERSION_FIELD]))
        logging.info("Number: %s" % (self.fields[self.BUILD_NUMBER_FIELD]))
        logging.info("Hash: %s" % (self.fields[self.HASH_FIELD].hex()))
        logging.info("Time: %d" % (self.fields[self.TIMESTAMP_FIELD]))
        logging.info("Binary size: %d bytes" % (self.fields[self.BINARY_SIZE_FIELD]))
        logging.info("GOT: 0x%x" % (self.fields[self.GOT_OFFSET_FIELD]))
        logging.info("Header: %d bytes (%d of extra)" % (len(new_header), len(self.extra)))
        logging.info("Fields: %s" % (self.fields))
        logging.info("Dynamic: syms=%d rels=%d" % (self.fields[self.NUMBER_SYMBOLS_FIELD], self.fields[self.NUMBER_RELOCATIONS_FIELD]))
        logging.info("Dynamic: size=%d" % (self.table_size))

        return new_header + self.extra

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path
        self.raw_cache = {}

    def fkbheader(self):
        try:
            return self.binary.get_section(".data.fkb.header")
        except:
            return None

    def got(self):
        try:
            return self.binary.get_section(".got")
        except:
            return None

    def bss(self):
        try:
            return self.binary.get_section(".bss")
        except:
            return None

    def timestamp(self):
        return int(os.path.getmtime(self.elf_path))

    def get_data_size(self):
        size = 0
        for section in self.binary.sections:
            if lief.ELF.SECTION_FLAGS.WRITE in section.flags_list:
                size += section.size

        return size - self.get_got_size() - self.get_bss_size()

    def get_got_size(self):
        if self.got() is None:
            return 0
        return self.got().size

    def get_bss_size(self):
        if self.bss() is None:
            return 0
        return self.bss().size

    def get_binary_size(self):
        size = 0
        for section in self.binary.sections:
            if lief.ELF.SECTION_FLAGS.ALLOC in section.flags_list:
                size += section.size

        return size

    def calculate_hash(self):
        algo = hashlib.sha1()
        algo.update(bytearray(self.code().content))
        algo.update(bytearray(self.data().content))
        return algo.digest()

    def get_code_address(self):
        return self.binary.get_section(".text").virtual_address

    def code(self):
        return self.binary.get_section(".text")

    def data(self):
        return self.binary.get_section(".data")

    def bss(self):
        return self.binary.get_section(".bss")

    def raw_section_data(self, section):
        if isinstance(section, utilities.Section):
            for s in self.binary.sections:
                if s.name == section.name:
                    return self.raw_section_data(s)
            raise Exception("Oops")
        if section.name in self.raw_cache.keys():
            return self.raw_cache[section.name]
        logging.info("Opening %s...", section.name)
        byte_data = bytearray(section.content)
        self.raw_cache[section.name] = byte_data
        logging.info("Processing %s (%d)", section.name, len(byte_data))
        return byte_data

    def get_section_by_address(self, address):
        for section in self.binary.sections:
            if section.name in [".rel.data", ".rel.text"]:
                continue
            if not section.name in [".text", ".data", ".bss", ".got", ".data.fkb.header", ".data.fkb.launch", ".data.rtt"]:
                continue
            ss = section.virtual_address
            se = ss + section.size
            if address >= ss and address < se:
                return section
        pass

    def investigate_code_relocation(self, r):
        pass

    def investigate_data_relocation(self, r):
        if r.offset >= 0x20000000:
            return
        section = self.get_section_by_address(r.offset)
        if section:
            section_raw = self.raw_section_data(section)
        cs = self.code()
        ds = self.data()
        code_raw = self.raw_section_data(cs)
        data_raw = self.raw_section_data(ds)
        try:
            if r.offset - cs.virtual_address < len(code_raw):
                offset = struct.unpack_from("<I", code_raw, r.offset - cs.virtual_address)[0]
            else:
                pass
                # print(r.section.name, len(code_raw))
                # print(cs.virtual_address, r.offset - cs.virtual_address)
        except Exception as e:
            pass
            # print("FOUND", section)
            # print(cs.virtual_address, r.offset - cs.virtual_address)
            # print(r.section.name, len(code_raw))

    def get_relocations_in_binary(self):
        started = time.time()

        bySectionNameIndex = defaultdict(list)
        for r in self.binary.relocations:
            bySectionNameIndex[r.section.name_idx].append(r)

        logging.info("Done %f", time.time() - started)

        relocations = []

        skipping = self.get_sections_to_skip()

        for s in self.binary.sections:
            if s.name not in skipping:
                relocations += bySectionNameIndex[s.name_idx]

        logging.info("Done %f", time.time() - started)

        return relocations

    def get_sections_to_skip(self):
        return {
            ".debug_loc": 0,
            ".debug_frame": 0,
            ".debug_info": 0,
            ".debug_line": 0,
            ".debug_ranges": 0,
            ".debug_aranges": 0,
        }

    def got_origin(self):
        got = self.got()
        if got:
            return got.virtual_address
        return 0

    def find_relocations(self):
        self.symbols = {}
        self.relocations = []
        self.verbose = False

        skipping = self.get_sections_to_skip()

        symbols = utilities.RejectingDict()

        nsections = len(self.binary.sections)
        elf_symbols = utilities.get_symbols_in_elf(self.elf_path)

        logging.info("Number of Symbols: %d (%d)" % (len(elf_symbols), len(self.binary.symbols)))

        for symbol in elf_symbols:
            if symbol.name in ["$t", "$d", ""]:
                continue

            if symbol.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL:
                if symbol.exported or symbol.shndx != 0:
                    symbols[symbol.index] = "exported"
                else:
                    symbols[symbol.index] = "external"
                    logging.info("External: %s", symbol.name)
            else:
                if symbol.type != lief.ELF.SYMBOL_TYPES.FILE:
                    symbols[symbol.index] = "local"

        logging.info("Exported: %d", len([s for s in symbols if symbols[s] == "exported"]))
        logging.info("External: %d", len([s for s in symbols if symbols[s] == "external"]))
        logging.info("Locals: %d", len([s for s in symbols if symbols[s] == "local"]))

        started = time.time()

        if False:
            relocations = utilities.get_relocations_in_elf(self.elf_path, elf_symbols)
            if len(relocations) > 0:
                for r in relocations:
                    if r.type != lief.ELF.RELOCATION_ARM.GOT_BREL:
                        continue
                    if symbols[r.symbol.index] == "local" or symbols[r.symbol.index] == "exported":
                        values = (r.symbol.size, utilities.relocation_type_name(r.type), r.section.name, r.symbol.value, r.offset, r.section.name, r.section.virtual_address, r.symbol.name)
                        logging.info("Local relocation: size(0x%4x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s" % values)
                        self.investigate_code_relocation(r)
                    elif symbols[r.symbol.index] == "external":
                        values = (r.symbol.size, relocation_type_name(r.type), r.symbol.type, r.symbol.value, r.offset, r.section.name, r.section.virtual_address, r.symbol.name)
                        logging.info("Foreign relocation: size(0x%4x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s" % values)
                        self.investigate_code_relocation(r)

                for r in relocations:
                    if r.section.name in skipping:
                        continue
                    if r.type != lief.ELF.RELOCATION_ARM.ABS32:
                        continue
                    if not r.has_symbol:
                        continue
                    values = (r.symbol.size, utilities.relocation_type_name(r.type), r.symbol.type, r.symbol.value, r.offset, r.section.name, r.section.virtual_address, r.symbol.name)
                    logging.info("DATA: size(0x%04x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s" % values)
                    self.investigate_data_relocation(r)

        got_origin = self.got_origin()
        for r in self.get_relocations_in_binary():
            display = False
            rel_offset = 0
            fixed = None

            if r.type == lief.ELF.RELOCATION_ARM.GOT_BREL:
                # A is the addend for the relocation
                # GOT_ORG is the addressing origin of the Global Offset
                #  Table (the indirection table for imported data
                #  addresses). This value must always be word-aligned. See
                #  4.6.1.8, Proxy generating relocations.
                # GOT(S) is the address of the GOT entry for the symbol
                # GOT(S) + A -GOT_ORG
                fixed = r.address - r.section.virtual_address
                raw = self.raw_section_data(r.section)
                rel_offset = struct.unpack_from("<I", raw, fixed)[0]
                # NOTE This should be the same for all relocations for this symbol!
                self.add_relocation(r.symbol, r.symbol.value, got_origin, rel_offset)
                # display = True

            if r.type == lief.ELF.RELOCATION_ARM.ABS32 and r.has_symbol:
                # S (when used on its own) is the address of the symbol.
                # A is the addend for the relocation
                # T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0 otherwise.
                # (S + A) | T
                fixed = r.address - r.section.virtual_address
                raw = self.raw_section_data(r.section)
                rel_offset = struct.unpack_from("<I", raw, fixed)[0]
                self.add_relocation(r.symbol, r.symbol.value, got_origin, rel_offset)
                # display = True

            if display:
                if fixed is None:
                    fixed = "<none>"
                else:
                    fixed = "0x%x" % (fixed)

                rel = self.got_origin() + rel_offset

                values = (r.symbol.name, r.symbol.size, r.symbol.value, r.symbol.type, r.symbol.binding,
                            r.address, r.size, r.addend, utilities.relocation_type_name(r.type),
                            r.section.name, r.section.virtual_address,
                            fixed, rel_offset, rel)
                logging.info("Relocation: %-50s s.size(0x%4x) s.value=0x%8x s.type=%-22s s.binding=%-26s r.address=0x%8x r.size=0x%4x r.addend=%s r.type=%-10s section=(%s, va=0x%8x) fixed=%10s rel_offset=0x%8x rel=0x%8x" % values)

            if self.verbose:
                symbol = r.symbol
                logging.info(("addend", r.addend, "address", r.address, "has_section", r.has_section,
                                "has_symbol", r.has_symbol, "info", r.info, "is_rel", r.is_rel, "is_rela",
                                r.is_rela, "purpose", r.purpose, "section", r.section, "size", r.size, "type", r.type))
                logging.info(('name', symbol.name, 'binding', symbol.binding,
                                'exported', symbol.exported, 'other', symbol.other, 'function', symbol.is_function,
                                'static', symbol.is_static, 'var', symbol.is_variable, 'info', symbol.information,
                                'shndx', symbol.shndx, 'size', symbol.size, 'type', symbol.type, 'value', symbol.value))

        if False:
            for r in self.binary.dynamic_symbols:
                logging.info("ds: %s", r)

            for r in self.binary.symbols:
                logging.info("ss: %s", r)

            for r in self.binary.dynamic_relocations:
                logging.info("dr: %s", r)

            for r in self.binary.object_relocations:
                logging.info("or: %s", r)

            for r in self.binary.pltgot_relocations:
                logging.info("pg: %s", r)

        logging.info("relocations done")

    def add_relocation(self, symbol, address, got_origin, offset):
        rel = got_origin + offset
        if rel < 0x20000000 or rel > 0x20000000 + 0x00040000:
            return
        if not symbol in self.symbols:
            type = 0
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                type = 1
            self.symbols[symbol] = (type, symbol.size, address, [])

        s = self.symbols[symbol]
        s[3].append(offset)

        self.relocations.append([symbol, offset])

    def analyse(self):
        started = time.time()
        self.binary = lief.ELF.parse(self.elf_path)
        self.find_relocations()
        logging.info("Done, %s elapsed", time.time() - started)

def configure_logging():
    if False:
        lief.Logger.enable()
        lief.Logger.set_level(lief.LOGGING_LEVEL.TRACE)
        lief.Logger.set_verbose_level(10)
    logging.basicConfig(format='%(asctime)-15s %(message)s', level=logging.INFO)

class MkModuleArgs:
    def __init__(self):
        self.no_debug = False

def main():
    configure_logging()

    parser = argparse.ArgumentParser(description='Firmware Preparation Tool')
    parser.add_argument('--no-verbose', dest="no_verbose", action="store_true", help="Don't show verbose commands (default: false)")
    parser.add_argument('--no-debug', dest="no_debug", action="store_true", help="Don't show debug data (default: false)")
    parser.add_argument('--elf', dest="elf_path", default=None, help="")
    parser.add_argument('--fkb', dest="fkb_path", default=None, help="")
    parser.add_argument('--name', dest="name", default=None, help="")
    args, nargs = parser.parse_known_args()

    if args.elf_path:
        logging.info("Processing %s...", args.elf_path)

        ea = ElfAnalyzer(args.elf_path)
        ea.analyse()
        if args.fkb_path:
            fw = FkbWriter(ea, args.fkb_path)
            fw.process(args.name)

if __name__ == "__main__":
    main()
