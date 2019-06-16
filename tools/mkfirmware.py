#!/usr/bin/env python

import os
import sys
import struct
import argparse
import hashlib
import logging

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type

from jinja2 import FileSystemLoader
from jinja2.environment import Environment

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
        with open(self.shim_path, "rb") as f:
            elf = ELFFile(f)
            for raw_section in elf.iter_sections():
                section = Section(raw_section)
                if section.name == ".text.shim":
                    logging.info("Found shim - %d bytes" % (len(section.data)))
                    return bytearray(section.data)
            return bytearray()

    def write(self, path):
        code = self.elf.sections[".text"]
        data = self.elf.sections[".data"]
        bss = self.elf.sections[".bss"]

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

        shim = self.get_shim()

        with open(path, "wb") as f:
            f.write(shim)
            f.write(header)
            f.write(bytearray(code.data))
            f.write(bytearray(data.data))
            logging.info("Wrote %d bytes of code" % (len(code.data)))
            logging.info("Wrote %d bytes of data" % (len(data.data)))
            logging.info("Wrote %d bytes of header" % (len(header)))

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path
        self.sections = {}

    def analyse(self):
        with open(self.elf_path, "rb") as f:
            elf = ELFFile(f)
            for raw_section in elf.iter_sections():
                section = Section(raw_section)
                self.sections[section.name] = section
                logging.info("Section %s" % (section))
                if isinstance(raw_section, SymbolTableSection):
                    for raw_symbol in raw_section.iter_symbols():
                        symbol = Symbol(raw_symbol)

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
        fw.write(args.fkb_path)

if __name__ == "__main__":
    main()
