#!/usr/bin/env python

import os
import sys
import struct
import argparse
import hashlib
import logging
import lief

# from jinja2 import FileSystemLoader
# from jinja2.environment import Environment

class Section:
    def __init__(self, section):
        self.name = section.name
        self.addr = int(section['sh_addr'])
        self.offset = int(section['sh_offset'])
        self.size = int(section['sh_size'])
        self.data = section.data()

    def __str__(self):
        return "Section<%s %d>" % (self.name, self.size)

class Symbol:
    def __init__(self, symbol):
        self.name = symbol.name
        self.type = symbol['st_info']['type']
        self.bind = symbol['st_info']['bind']
        self.size = symbol['st_size']
        self.visibility = symbol['st_other']['visibility']
        self.section = symbol['st_shndx']
        try:
            self.section = int(sdata["section"])
        except:
            pass
        self.value = int(symbol['st_value'])

    def __str__(self):
        return self.name

class FkbWriter:
    def __init__(self, elf_analyzer, shim_path):
        self.elf = elf_analyzer
        self.shim_path = shim_path

    def get_shim(self):
        if not self.shim_path:
            return bytearray()
        binary = lief.parse(self.shim_path)
        shim_section = binary.get_section(".text")
        logging.info("Found shim - %d bytes" % (shim_section.size))
        return shim_section.content

    def write(self, path):
        code = self.elf.code()
        data = self.elf.data()
        bss = self.elf.bss()

        version = 1
        flags = 0

        # Adjustable header can vary. Fill with gibberish for now. Eventually
        # will contain symbol relocations, etc...
        adj_header = bytearray("IGNORED")

        # Pad to 4 byte alignment.
        if len(adj_header) % 4 > 0:
            adj_header += '\0' * (4 - len(adj_header) % 4)

        fixed_header_size = 7 * 4
        header_size = fixed_header_size + len(adj_header)
        fixed_header = bytearray("UDLM")               # Signature (4b)
        fixed_header += struct.pack("<I", version)     # Version (4b)
        fixed_header += struct.pack("<I", header_size) # Header Size (4b)
        fixed_header += struct.pack("<I", flags)       # Flags Size (4b)
        fixed_header += struct.pack("<I", code.size)   # Code Size (4b)
        fixed_header += struct.pack("<I", data.size)   # Data Size (4b)
        fixed_header += struct.pack("<I", bss.size)    # BSS Size (4b)

        assert len(fixed_header) == fixed_header_size

        header = fixed_header + adj_header

        assert len(header) % 4 == 0

        lief.Logger.enable()
        # lief.Logger.set_verbose_level(9)

        for a in self.elf.binary.segments:
            print(a)

        shim = self.get_shim()

        if False:
            shim_section = lief.ELF.Section(".text.shim", lief.ELF.SECTION_TYPES.PROGBITS)
            shim_section += lief.ELF.SECTION_FLAGS.ALLOC
            shim_section += lief.ELF.SECTION_FLAGS.EXECINSTR
            shim_section.content = shim
            shim_section.alignment = 0x8000
            shim_section.virtual_address = 0x8000

            logging.info("Adding %d (before)" % (shim_section.size))
            shim_section = self.elf.binary.add(shim_section, loaded=True)

            logging.info("Adding %d" % (shim_section.size))

            header_section = lief.ELF.Section(".data.header", lief.ELF.SECTION_TYPES.PROGBITS)
            header_section += lief.ELF.SECTION_FLAGS.ALLOC
            header_section.content = header
            header_section.alignment = 0x8000
            header_section.virtual_address = 0x8000 + len(shim)
            header_section = self.elf.binary.add(header_section, loaded=True)

            logging.info("Adding %d" % (header_section.size))
        else:
            segment = lief.ELF.Segment()

        # TODO Why are the section sizes wrong after adding?
        offset = len(shim) + len(header)

        logging.info("Adjusting .text by %d" % (offset))
        code.virtual_address += offset
        self.elf.binary.segments[0].virtual_address += offset

        logging.info("Entry: %s" % (self.elf.binary.header.entrypoint))

        logging.info("Writing %s" % (path))

        for a in self.elf.binary.segments:
            print(a)

        self.elf.binary.write(path)

        if False:
            with open(path, "wb") as f:
                f.write(shim)
                f.write(header)
                f.write(bytearray(code.content))
                f.write(bytearray(data.content))
                logging.info("Wrote %d bytes of code" % (len(code.content)))
                logging.info("Wrote %d bytes of data" % (len(data.content)))
                logging.info("Wrote %d bytes of header" % (len(header)))

    def change_ep(self, path):
        logging.info("Entry: %s" % (self.elf.binary.header.entrypoint))
        # self.elf.binary.header.entrypoint = 0x
        logging.info("Writing %s", path)
        self.elf.binary.write(path)

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path

    def code(self):
        return self.binary.get_section(".text")

    def data(self):
        return self.binary.get_section(".data")

    def bss(self):
        return self.binary.get_section(".bss")

    def analyse(self):
        self.binary = lief.parse(self.elf_path)

def configure_logging():
    logging.basicConfig(format='%(asctime)-15s %(message)s', level=logging.INFO)

def main():
    configure_logging()

    parser = argparse.ArgumentParser(description='Firmware Preparation Tool')
    parser.add_argument('--no-verbose', dest="no_verbose", action="store_true", help="Don't show verbose commands (default: false)")
    parser.add_argument('--no-debug', dest="no_debug", action="store_true", help="Don't show debug data (default: false)")
    parser.add_argument('--shim', dest="shim_path", default=None, help="")
    parser.add_argument('--elf', dest="elf_path", default=None, help="")
    parser.add_argument('--fkb', dest="fkb_path", default=None, help="")
    args, nargs = parser.parse_known_args()

    if args.fkb_path and args.elf_path:
        ea = ElfAnalyzer(args.elf_path)
        ea.analyse()
        fw = FkbWriter(ea, args.shim_path)
        fw.change_ep(args.fkb_path)

if __name__ == "__main__":
    main()
