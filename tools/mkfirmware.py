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

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type

def get_relocations_in_elf(obj):
    rels = []
    with open(obj, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symtable = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_sym'] == 0:
                    continue
                rdata = {}
                rdata["offset"] = int(rel['r_offset'])
                rdata["info"] = rel['r_info']
                rdata["type"] = describe_reloc_type(rel['r_info_type'], elf)
                symbol = symtable.get_symbol(rel['r_info_sym'])
                if symbol['st_name'] == 0:
                    symsec = elf.get_section(symbol['st_shndx'])
                    rdata["name"] = str(symsec.name)
                else:
                    rdata["name"] = str(symbol.name)
                rdata["value"] = symbol["st_value"]
                rels.append(rdata)
    return rels

def get_section_in_elf(obj, section_name):
    sect = {}
    with open(obj, "rb") as f:
        elf = ELFFile(f)
        for i, section in enumerate(elf.iter_sections()):
            if section.name == section_name:
                sect["name"] = section_name
                sect["addr"] = int(section['sh_addr'])
                sect["offset"] = int(section['sh_offset'])
                sect["size"] = int(section['sh_size'])
                sect["data"] = section.data()
                sect["index"] = i
                check(len(sect["data"]) == sect["size"], "Section '%s' real and declared data are different" % section_name)
                break
        else:
            error("Section '%s' not found" % section_name)
    return sect

def relocation_type_name(r):
    for attr, value in lief.ELF.RELOCATION_ARM.__dict__.items():
        if value == r:
            return attr
    return "<unknown>"

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
    BINARY_DATA_FIELD        = 8
    BINARY_BSS_FIELD         = 9
    BINARY_GOT_FIELD         = 10
    VTOR_OFFSET_FIELD        = 11
    GOT_OFFSET_FIELD         = 12
    NAME_FIELD               = 13
    HASH_SIZE_FIELD          = 14
    HASH_FIELD               = 15
    NUMBER_SYMBOLS_FIELD     = 16
    NUMBER_RELOCATIONS_FIELD = 17

    def __init__(self, fkb_path):
        self.min_packspec = '<4sIIIII16sIIIIII256sI128sII'
        self.min_size = struct.calcsize(self.min_packspec)
        self.fkb_path = fkb_path

    def read(self, data):
        self.actual_size = len(data)
        self.extra = bytearray(data[self.min_size:])
        self.fields = list(struct.unpack(self.min_packspec, bytearray(data[:self.min_size])))

    def has_invalid_name(self, value):
        return len(value) == 0 or value[0] == '\0' or value[0] == 0

    def populate(self, ea, name):
        self.symbols = bytearray()
        self.relocations = bytearray()

        indices = {}
        index = 0
        for symbol_name in ea.symbols:
            s = ea.symbols[symbol_name]
            if len(s) >= 24:
                raise Exception("Symbol name too long")
            try:
                self.symbols += struct.pack('<III24s', s[0], s[1], s[2], bytes(symbol_name, 'utf-8'))
            except:
                raise Exception("Error packing symbol: %s %d %d %d" % (symbol_name, s[0], s[1], s[2]))

            indices[symbol_name] = index
            index += 1

        for r in ea.relocations:
            self.relocations += struct.pack('<II', indices[r[0]], r[1])

        self.table_size = len(self.symbols) + len(self.relocations)

        offset = self.aligned(self.table_size, 1024)
        logging.info("Offset: %d", offset)
        # self.extra = bytearray([0] * (offset - self.min_size))

        if self.table_size > len(self.extra):
            raise Exception("Table overflowed: %d > %d" % (self.table_size, len(self.extra)))

        self.fields[self.TIMESTAMP_FIELD] = ea.timestamp()
        self.fields[self.BINARY_SIZE_FIELD] = ea.get_binary_size()
        self.fields[self.BINARY_DATA_FIELD] = ea.get_data_size()
        self.fields[self.BINARY_BSS_FIELD] = ea.get_bss_size()
        self.fields[self.BINARY_GOT_FIELD] = ea.get_got_size()
        self.fields[self.VTOR_OFFSET_FIELD] = 0x4000

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

        return new_header + self.symbols + self.relocations + self.extra[self.table_size:]

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
        if section in self.raw_cache.keys():
            return self.raw_cache[section]
        logging.info("Opening %s...", section.name)
        byte_data = bytearray(section.content)
        self.raw_cache[section] = byte_data
        logging.info("Processing %s (%d)", section.name, len(byte_data))
        return byte_data

    def find_relocations(self):
        self.symbols = {}
        self.relocations = []
        self.verbose = False

        skipping = {
            ".debug_loc": 0,
            ".debug_frame": 0,
            ".debug_info": 0,
            ".debug_line": 0,
            ".debug_ranges": 0,
            ".debug_aranges": 0,
        }

        if len(self.binary.relocations) > 0:
            for r in self.binary.relocations:
                if r.type != lief.ELF.RELOCATION_ARM.GOT_BREL and r.type != lief.ELF.RELOCATION_ARM.ABS32:
                    if False:
                        values = (r.symbol.name, r.symbol.size, relocation_type_name(r.type), r.section.name, r.section.virtual_address, r.symbol.type)
                        logging.info("IGNORING: %s size(0x%x) (%s) section=(%s, va=0x%x) TYPE=%s" % values)
                    continue
                if r.symbol.binding != lief.ELF.SYMBOL_BINDINGS.GLOBAL:
                    if False:
                        values = (r.symbol.name, r.symbol.size, relocation_type_name(r.type), r.section.name, r.section.virtual_address, r.symbol.type)
                        logging.info("IGNORING: %s size(0x%x) (%s) section=(%s, va=0x%x) TYPE=%s" % values)
                    continue
                if r.section.name in skipping:
                    continue
                offset = r.address
                value = r.symbol.value
                fixed = 0
                old = 0
                display = False
                got_offset = 0

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
                    got_offset = struct.unpack_from("<I", raw, fixed)[0]
                    # NOTE This should be the same for all relocations for this symbol!
                    self.add_relocation(r.symbol, value, got_offset)
                    display = True

                if r.type == lief.ELF.RELOCATION_ARM.ABS32:
                    # S (when used on its own) is the address of the symbol.
                    # A is the addend for the relocation
                    # T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0 otherwise.
                    # (S + A) | T
                    fixed = r.address - r.section.virtual_address
                    raw = self.raw_section_data(r.section)
                    old = struct.unpack_from("<I", raw, fixed)[0]
                    display = True

                if display:
                    values = (r.symbol.name, r.symbol.size, offset, fixed, value, relocation_type_name(r.type), r.section.name, r.section.virtual_address, old, r.symbol.type, got_offset)
                    logging.info("Relocation: %s size(0x%x) offset=0x%x fixed=0x%x value=0x%x (%s) section=(%s, va=0x%x) OLD=0x%x TYPE=%s GOT_OFFSET=0x%x" % values)
                if self.verbose and False:
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

    def add_relocation(self, symbol, address, offset):
        name = str(symbol.name)
        if not name in self.symbols:
            type = 0
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                type = 1
            self.symbols[name] = (type, symbol.size, address, [])

        s = self.symbols[name]
        s[3].append(offset)

        self.relocations.append([name, offset])

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

        if False:
            relocs = get_relocations_in_elf(args.elf_path)
            for r in relocs:
                if 'debug' not in r['name']:
                    if r['value'] > 0x8000:
                        print("0x%08x   0x%08x   %20s   0x%08x 0x%08x %s" % (r['offset'], r['info'], r['type'], r['value'], r['value'] - 0x8000 + 0x20000d88, r['name']))
                    else:
                        print("0x%08x   0x%08x   %20s   0x%08x 0x%08x %s" % (r['offset'], r['info'], r['type'], r['value'], r['value'], r['name']))

        ea = ElfAnalyzer(args.elf_path)
        ea.analyse()
        if args.fkb_path:
            fw = FkbWriter(ea, args.fkb_path)
            fw.process(args.name)

if __name__ == "__main__":
    main()
