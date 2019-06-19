#!/usr/bin/env python

import os
import sys
import struct
import argparse
import hashlib
import logging
import lief
import hashlib

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

    def process(self, path, name):
        logging.info("Processing %s...", path)
        fkbh_section = self.elf.fkbh()
        if fkbh_section:
            logging.info("Found FKB section: %s bytes" % (fkbh_section.size))
            self.populate_header(fkbh_section, name)
            logging.info("Binary size: %d bytes" % (self.elf.get_binary_size()))
        else:
            logging.info("No specialized handling for binary.")
        self.elf.binary.write(path)

    def populate_header(self, section, name):
        header = FkbhHeader()
        header.read(section.content)
        header.populate(self.elf, name)
        section.content = header.write()

class FkbhHeader:
    SIGNATURE_FIELD   = 0
    VERSION_FIELD     = 1
    HEADER_SIZE_FIELD = 2
    FLAGS_FIELD       = 3
    TIMESTAMP_FIELD   = 4
    BINARY_SIZE_FIELD = 5
    VTOR_OFFSET_FIELD = 6
    NAME_FIELD        = 7
    HASH_FIELD        = 8

    def __init__(self):
        self.min_packspec = '<4sIIIIII256s128s'
        self.min_size = struct.calcsize(self.min_packspec)

    def read(self, data):
        self.actual_size = len(data)
        self.extra = bytearray(data[self.min_size:])
        self.fields = list(struct.unpack(self.min_packspec, bytearray(data[:self.min_size])))

    def populate(self, ea, name):
        self.fields[self.TIMESTAMP_FIELD] = ea.timestamp()
        self.fields[self.BINARY_SIZE_FIELD] = ea.get_binary_size()
        self.fields[self.VTOR_OFFSET_FIELD] = 0x1000
        self.fields[self.HASH_FIELD] = ea.calculate_hash()
        if name:
            self.fields[self.NAME_FIELD] = name

    def write(self):
        new_header = bytearray(bytes(struct.pack(self.min_packspec, *self.fields)))
        logging.info("Hash: %s" % (self.fields[self.HASH_FIELD].encode('hex')))
        logging.info("Time: %d" % (self.fields[self.TIMESTAMP_FIELD]))
        logging.info("Header: %d bytes (%d of extra)" % (len(new_header), len(self.extra)))
        logging.info("Fields: %s" % (self.fields))
        return new_header + self.extra

class ElfAnalyzer:
    def __init__(self, elf_path):
        self.elf_path = elf_path

    def fkbh(self):
        try:
            return self.binary.get_section(".data.fkbh")
        except:
            return None

    def timestamp(self):
        return int(os.path.getmtime(self.elf_path))

    def get_binary_size(self):
        size = 0
        fkbh = self.fkbh()
        if fkbh:
            size += fkbh.size
        size += self.code().size # This will have padding to align vector table.
        size += self.data().size

        # BSS is uninitialized and unnecessary in the binary.
        # size += self.bss().size
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
    parser.add_argument('--name', dest="name", default=None, help="")
    args, nargs = parser.parse_known_args()

    if args.fkb_path and args.elf_path:
        ea = ElfAnalyzer(args.elf_path)
        ea.analyse()
        fw = FkbWriter(ea, args.shim_path)
        fw.process(args.fkb_path, args.name)

if __name__ == "__main__":
    main()
