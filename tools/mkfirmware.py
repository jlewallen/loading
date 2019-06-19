#!/usr/bin/env python

import os
import sys
import struct
import argparse
import hashlib
import logging
import lief

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

    def fixup_header(self, section):
        header = FkbhHeader()
        header.read(section.content)
        header.fix(self.elf)
        section.content = header.write()

    def process(self, path):
        logging.info("Processing %s...", path)
        fkbh_section = self.elf.fkbh()
        if fkbh_section:
            logging.info("Found FKBH! (%s)" % (fkbh_section.size))
            self.fixup_header(fkbh_section)
            logging.info("Calcualted binary size: %d" % (self.elf.get_binary_size()))
        self.elf.binary.write(path)

class FkbhHeader:
    def read(self, data):
        self.fields = list(struct.unpack('<4sII256sIIIII', bytearray(data)))

    def fix(self, ea):
        self.fields[5] = ea.get_binary_size()
        self.fields[6] = ea.code().size
        self.fields[7] = ea.data().size
        self.fields[8] = ea.bss().size
        print ea.code().size
        print ea.data().size
        print ea.bss().size

    def write(self):
        return bytearray(bytes(struct.pack('<4sII256sIIIII', *self.fields)))

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path

    def fkbh(self):
        try:
            return self.binary.get_section(".data.fkbh")
        except:
            return None

    def get_binary_size(self):
        size = 0
        size += self.code().size
        size += self.data().size
        # size += self.bss().size
        return size

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
        fw.process(args.fkb_path)

if __name__ == "__main__":
    main()
