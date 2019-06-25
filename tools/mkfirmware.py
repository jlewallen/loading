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

def relocation_type_name(r):
    if r == lief.ELF.RELOCATION_ARM.GOT_BREL: return "GOT_BREL"
    if r == lief.ELF.RELOCATION_ARM.ABS32: return "ABS32"
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
    BINARY_SIZE_FIELD        = 5
    VTOR_OFFSET_FIELD        = 6
    GOT_OFFSET_FIELD         = 7
    NAME_FIELD               = 8
    HASH_SIZE_FIELD          = 9
    HASH_FIELD               = 10
    NUMBER_SYMBOLS_FIELD     = 11
    NUMBER_RELOCATIONS_FIELD = 12

    def __init__(self, fkb_path):
        self.min_packspec = '<4sIIIIIII256sI128sII'
        self.min_size = struct.calcsize(self.min_packspec)
        self.fkb_path = fkb_path

    def read(self, data):
        self.actual_size = len(data)
        self.extra = bytearray(data[self.min_size:])
        self.fields = list(struct.unpack(self.min_packspec, bytearray(data[:self.min_size])))

    def populate(self, ea, name):
        self.fields[self.TIMESTAMP_FIELD] = ea.timestamp()
        self.fields[self.BINARY_SIZE_FIELD] = ea.get_binary_size()
        self.fields[self.VTOR_OFFSET_FIELD] = 0x1000

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
        if len(self.fields[self.NAME_FIELD]) == 0 or self.fields[self.NAME_FIELD][0] == '\0':
            self.fields[self.NAME_FIELD] = self.generate_name(ea)

        self.fields[self.NUMBER_SYMBOLS_FIELD] = len(ea.symbols)
        self.fields[self.NUMBER_RELOCATIONS_FIELD] = len(ea.relocations)

    def generate_name(self, ea):
        name = os.path.basename(self.fkb_path)
        when = datetime.datetime.utcfromtimestamp(ea.timestamp())
        ft = when.strftime("%Y%m%d_%H%M%S")
        return name + "_" + platform.node() + "_" + ft

    def write(self, ea):
        new_header = bytearray(bytes(struct.pack(self.min_packspec, *self.fields)))

        symbols = bytearray()
        relocations = bytearray()

        indices = {}
        index = 0
        for name in ea.symbols:
            s = ea.symbols[name]
            symbols += struct.pack('<28sI', bytes(name, 'utf-8'), s[1])
            indices[name] = index
            index += 1

        for r in ea.relocations:
            relocations += struct.pack('<II', indices[r[0]], r[1])

        table_size = len(symbols) + len(relocations)

        logging.info("Name: %s" % (self.fields[self.NAME_FIELD]))
        logging.info("Hash: %s" % (self.fields[self.HASH_FIELD].hex()))
        logging.info("Time: %d" % (self.fields[self.TIMESTAMP_FIELD]))
        logging.info("Binary size: %d bytes" % (self.fields[self.BINARY_SIZE_FIELD]))
        logging.info("GOT: 0x%x" % (self.fields[self.GOT_OFFSET_FIELD]))
        logging.info("Header: %d bytes (%d of extra)" % (len(new_header), len(self.extra)))
        logging.info("Fields: %s" % (self.fields))
        logging.info("Dynamic: syms=%d rels=%d" % (self.fields[self.NUMBER_SYMBOLS_FIELD], self.fields[self.NUMBER_RELOCATIONS_FIELD]))
        logging.info("Dynamic: size=%d" % (table_size))

        # TODO Ensure we have extra space!

        return new_header + symbols + relocations + self.extra[table_size:]

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path

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

    def timestamp(self):
        return int(os.path.getmtime(self.elf_path))

    def get_binary_size(self):
        # This is a good start, will probably need tweaking down the road.
        size = 0
        for section in self.binary.sections:
            if True or section.type == lief.ELF.SECTION_TYPES.PROGBITS or section.type == lief.ELF.SECTION_TYPES.ARM_EXIDX:
                if lief.ELF.SECTION_FLAGS.ALLOC in section.flags_list:
                    size += section.size

        return size

    def calculate_hash(self):
        algo = hashlib.sha1()
        algo.update(bytearray(self.code().content))
        algo.update(bytearray(self.data().content))
        return algo.digest()

    def code(self):
        return self.binary.get_section(".text")

    def data(self):
        return self.binary.get_section(".data")

    def relocations(self):
        code_size = self.code().size
        code_data = bytearray(self.code().content)
        self.symbols = {}
        self.relocations = []

        if len(self.binary.relocations) > 0:
            for r in self.binary.relocations:
                if r.type != lief.ELF.RELOCATION_ARM.GOT_BREL and r.type != lief.ELF.RELOCATION_ARM.ABS32:
                    continue
                if r.symbol.binding != lief.ELF.SYMBOL_BINDINGS.GLOBAL:
                    continue
                offset = r.address
                value = r.symbol.value
                fixed = 0
                old = 0

                if r.type == lief.ELF.RELOCATION_ARM.GOT_BREL:
                    # A is the addend for the relocation
                    # GOT_ORG is the addressing origin of the Global Offset
                    #  Table (the indirection table for imported data
                    #  addresses). This value must always be word-aligned. See
                    #  4.6.1.8, Proxy generating relocations.
                    # GOT(S) is the address of the GOT entry for the symbol
                    # GOT(S) + A -GOT_ORG
                    fixed = r.address - r.section.virtual_address
                    got_offset = struct.unpack_from("<I", bytearray(r.section.content), fixed)[0]
                    # NOTE This should be the same for all relocations for this symbol!
                    self.add_relocation(r.symbol, got_offset)

                if r.type == lief.ELF.RELOCATION_ARM.ABS32:
                    # S (when used on its own) is the address of the symbol.
                    # A is the addend for the relocation
                    # T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0 otherwise.
                    # (S + A) | T
                    fixed = r.address - r.section.virtual_address
                    old = struct.unpack_from("<I", bytearray(r.section.content), fixed)[0]

                if False or r.type == lief.ELF.RELOCATION_ARM.GOT_BREL:
                    values = (r.symbol.name, r.symbol.size, offset, fixed, value, relocation_type_name(r.type), r.section.name, len(r.section.content), r.section.virtual_address, old)
                    logging.info("Relocation: %s (0x%x) offset=0x%x fixed=0x%x value=0x%x (%s) section=(%s 0x%x, va=0x%x) OLD=0x%x" % values)
                if False:
                    symbol = r.symbol
                    logging.info(("addend", r.addend, "address", r.address, "has_section", r.has_section,
                                  "has_symbol", r.has_symbol, "info", r.info, "is_rel", r.is_rel, "is_rela",
                                  r.is_rela, "purpose", r.purpose, "section", r.section, "size", r.size, "type", r.type))
                    logging.info(('name', symbol.name, 'binding', symbol.binding,
                                  'exported', symbol.exported, 'other', symbol.other, 'function', symbol.is_function,
                                  'static', symbol.is_static, 'var', symbol.is_variable, 'info', symbol.information,
                                  'shndx', symbol.shndx, 'size', symbol.size, 'type', symbol.type, 'value', symbol.value))

        for r in self.binary.dynamic_relocations:
            logging.info("dr: %s", r)

        for r in self.binary.object_relocations:
            logging.info("or: %s", r)

    def add_relocation(self, symbol, offset):
        name = str(symbol.name)
        if not name in self.symbols:
            self.symbols[name] = ( name, symbol.size, [] )

        s = self.symbols[name]
        s[2].append(offset)

        self.relocations.append([name, offset])

    def analyse(self):
        self.binary = lief.ELF.parse(self.elf_path)
        self.relocations()

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
        ea = ElfAnalyzer(args.elf_path)
        ea.analyse()
        if args.fkb_path:
            fw = FkbWriter(ea, args.fkb_path)
            fw.process(args.name)

if __name__ == "__main__":
    main()
