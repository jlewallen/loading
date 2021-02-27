#!/usr/bin/env python3

from typing import List, Union, Dict, Optional, Any

import os
import sys
import struct
import time
import datetime
import subprocess
import argparse
import hashlib
import logging
import lief  # type: ignore
import hashlib
import platform
import threading
import utilities
import pyblake2  # type: ignore

from collections import defaultdict


class ElfAnalyzer:
    def __init__(self, dynamic: bool, elf_path: str, increase_size_by: int):
        self.dynamic: bool = dynamic
        self.elf_path: str = elf_path
        self.increase_size_by: int = increase_size_by
        self.raw_cache: Dict[str, Any] = {}
        self.binary: Optional[lief.ELF.Binary] = None
        self.symbols = []
        self.relocations = []

    def timestamp(self) -> int:
        return int(os.path.getmtime(self.elf_path))

    def fkbheader(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".data.fkb.header")
        except:
            return None

    def fkdyn(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".fkdyn")
        except:
            return None

    def code(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".text")
        except:
            return None

    def data(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".data")
        except:
            return None

    def got(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".got")
        except:
            return None

    def bss(self) -> Optional[lief.ELF.Section]:
        assert self.binary
        try:
            return self.binary.get_section(".bss")
        except:
            return None

    def get_got_size(self) -> int:
        g = self.got()
        if g is None:
            return 0
        return g.size

    def get_bss_size(self) -> int:
        s = self.bss()
        if s is None:
            return 0
        return s.size

    def get_binary_size(self) -> int:
        size = self.increase_size_by
        for section in self.get_binary_sections():
            if section:
                size += section.size
        return size

    def get_data_size(self) -> int:
        assert self.binary
        size = 0
        for section in self.binary.sections:
            if lief.ELF.SECTION_FLAGS.WRITE in section.flags_list:
                size += section.size
        return size - self.get_got_size() - self.get_bss_size()

    def calculate_hash(self) -> bytes:
        algo = hashlib.sha1()
        code = self.code()
        if code:
            algo.update(bytearray(code.content))
        data = self.data()
        if data:
            algo.update(bytearray(data.content))
        return algo.digest()

    def get_code_address(self) -> int:
        s = self.code()
        assert s
        return s.virtual_address

    def raw_section_data(self, section):
        assert section
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

    def get_section_by_address(self, address: int):
        assert self.binary
        for section in self.binary.sections:
            if section.name in [".rel.data", ".rel.text"]:
                continue
            if not section.name in [
                ".text",
                ".data",
                ".bss",
                ".got",
                ".data.fkb.header",
                ".data.fkb.launch",
                ".data.rtt",
            ]:
                continue
            ss = section.virtual_address
            se = ss + section.size
            if address >= ss and address < se:
                return section
        pass

    def get_relocations_in_binary(self):
        started = time.time()

        by_section_name_index = defaultdict(list)
        for r in self.binary.relocations:
            if r.has_section:
                by_section_name_index[r.section.name_idx].append(r)

        logging.info("Done %f", time.time() - started)

        relocations = []

        skipping = self.get_sections_to_skip()

        for s in self.binary.sections:
            if s.name not in skipping:
                relocations += by_section_name_index[s.name_idx]

        logging.info("Done %f", time.time() - started)

        for r in self.binary.relocations:
            if r.has_symbol:
                relocations.append(r)

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

        logging.info(
            "Number of Symbols: %d (%d)" % (len(elf_symbols), len(self.binary.symbols))
        )

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

        logging.info(
            "Exported: %d", len([s for s in symbols if symbols[s] == "exported"])
        )

        logging.info(
            "External: %d", len([s for s in symbols if symbols[s] == "external"])
        )

        logging.info("Locals: %d", len([s for s in symbols if symbols[s] == "local"]))

        started = time.time()

        if False:
            relocations = utilities.get_relocations_in_elf(self.elf_path, elf_symbols)
            if len(relocations) > 0:
                for r in relocations:
                    if r.type != lief.ELF.RELOCATION_ARM.GOT_BREL:
                        continue
                    if (
                        symbols[r.symbol.index] == "local"
                        or symbols[r.symbol.index] == "exported"
                    ):
                        values = (
                            r.symbol.size,
                            utilities.relocation_type_name(r.type),
                            r.section.name,
                            r.symbol.value,
                            r.offset,
                            r.section.name,
                            r.section.virtual_address,
                            r.symbol.name,
                        )
                        logging.info(
                            "Local relocation: size(0x%4x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s"
                            % values
                        )
                        self.investigate_code_relocation(r)
                    elif symbols[r.symbol.index] == "external":
                        values = (
                            r.symbol.size,
                            relocation_type_name(r.type),
                            r.symbol.type,
                            r.symbol.value,
                            r.offset,
                            r.section.name,
                            r.section.virtual_address,
                            r.symbol.name,
                        )
                        logging.info(
                            "Foreign relocation: size(0x%4x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s"
                            % values
                        )
                        self.investigate_code_relocation(r)

                for r in relocations:
                    if r.section.name in skipping:
                        continue
                    if r.type != lief.ELF.RELOCATION_ARM.ABS32:
                        continue
                    if not r.has_symbol:
                        continue
                    values = (
                        r.symbol.size,
                        utilities.relocation_type_name(r.type),
                        r.symbol.type,
                        r.symbol.value,
                        r.offset,
                        r.section.name,
                        r.section.virtual_address,
                        r.symbol.name,
                    )
                    logging.info(
                        "DATA: size(0x%04x) (%s) TYPE=%24s VALUE=0x%8x offset=0x%8x section=(%10s, va=0x%8x) %s"
                        % values
                    )
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

            if (
                r.type == lief.ELF.RELOCATION_ARM.ABS32
                or r.type == lief.ELF.RELOCATION_ARM.GLOB_DAT
            ) and r.has_symbol:
                # S (when used on its own) is the address of the symbol.
                # A is the addend for the relocation
                # T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0 otherwise.
                # (S + A) | T
                if r.has_section:
                    fixed = r.address - r.section.virtual_address
                    raw = self.raw_section_data(r.section)
                    rel_offset = struct.unpack_from("<I", raw, fixed)[0]
                    self.add_relocation(
                        r.symbol, r.symbol.value, got_origin, rel_offset
                    )
                else:
                    logging.info(
                        "Reloc: %s %s 0x%x 0x%x 0x%x %x"
                        % (r, r.symbol.name, r.size, r.address, got_origin, r.addend)
                    )
                    self.add_relocation(r.symbol, r.symbol.value, got_origin, 0)
                # display = True

            if display:
                if fixed is None:
                    fixed = "<none>"
                else:
                    fixed = "0x%x" % (fixed)

                rel = self.got_origin() + rel_offset

                values = (
                    r.symbol.name,
                    r.symbol.size,
                    r.symbol.value,
                    r.symbol.type,
                    r.symbol.binding,
                    r.address,
                    r.size,
                    r.addend,
                    utilities.relocation_type_name(r.type),
                    r.section.name,
                    r.section.virtual_address,
                    fixed,
                    rel_offset,
                    rel,
                )
                logging.info(
                    "Relocation: %-50s s.size(0x%4x) s.value=0x%8x s.type=%-22s s.binding=%-26s r.address=0x%8x r.size=0x%4x r.addend=%s r.type=%-10s section=(%s, va=0x%8x) fixed=%10s rel_offset=0x%8x rel=0x%8x"
                    % values
                )

            if self.verbose:
                symbol = r.symbol
                logging.info(
                    (
                        "addend",
                        r.addend,
                        "address",
                        r.address,
                        "has_section",
                        r.has_section,
                        "has_symbol",
                        r.has_symbol,
                        "info",
                        r.info,
                        "is_rel",
                        r.is_rel,
                        "is_rela",
                        r.is_rela,
                        "purpose",
                        r.purpose,
                        "section",
                        r.section,
                        "size",
                        r.size,
                        "type",
                        r.type,
                    )
                )
                logging.info(
                    (
                        "name",
                        symbol.name,
                        "binding",
                        symbol.binding,
                        "exported",
                        symbol.exported,
                        "other",
                        symbol.other,
                        "function",
                        symbol.is_function,
                        "static",
                        symbol.is_static,
                        "var",
                        symbol.is_variable,
                        "info",
                        symbol.information,
                        "shndx",
                        symbol.shndx,
                        "size",
                        symbol.size,
                        "type",
                        symbol.type,
                        "value",
                        symbol.value,
                    )
                )

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

        logging.info("Relocations Done")

    def add_symbol(self, symbol, address):
        if not symbol in self.symbols:
            type = 0
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                type = 1
            self.symbols[symbol] = (type, symbol.size, address, [])
        return self.symbols[symbol]

    def add_relocation(self, symbol, address, got_origin, offset):
        rel = got_origin + offset
        if False and rel < 0x20000000 or rel > 0x20000000 + 0x00040000:
            logging.info("Skip: %s" % [symbol.name, got_origin, offset, rel])
            return

        s = self.add_symbol(symbol, address)

        s[3].append(offset)

        self.relocations.append([symbol, offset])

    def analyse(self):
        started = time.time()
        self.binary = lief.ELF.parse(self.elf_path)
        if self.dynamic:
            self.find_relocations()
        logging.info("Done, %s elapsed", time.time() - started)

    def get_binary_sections(self):
        return [
            self.fkbheader(),
            self.code(),
            self.data(),
            self.bss(),
            self.got(),
            self.fkdyn(),
        ]

    def write_bin(self, bin_path: str):
        with open(bin_path, "wb") as f:
            data = bytearray()
            for section in self.get_binary_sections():
                if section:
                    data += bytearray(section.content)
            f.write(data)

        utilities.append_hash(bin_path)


class FkbHeader:
    SIGNATURE_FIELD = 0
    VERSION_FIELD = 1
    HEADER_SIZE_FIELD = 2
    FLAGS_FIELD = 3
    TIMESTAMP_FIELD = 4
    BUILD_NUMBER_FIELD = 5
    VERSION_FIELD = 6
    BINARY_SIZE_FIELD = 7
    TABLES_OFFSET_FIELD = 8
    BINARY_DATA_FIELD = 9
    BINARY_BSS_FIELD = 10
    BINARY_GOT_FIELD = 11
    VTOR_OFFSET_FIELD = 12
    GOT_OFFSET_FIELD = 13
    NAME_FIELD = 14
    HASH_SIZE_FIELD = 15
    HASH_FIELD = 16
    NUMBER_SYMBOLS_FIELD = 17
    NUMBER_RELOCATIONS_FIELD = 18

    def __init__(self, fkb_path: str, data: bytes):
        self.min_packspec: str = "<4sIIIII16sIIIIIII256sI128sII"
        self.min_size: int = struct.calcsize(self.min_packspec)
        self.fkb_path: str = fkb_path
        self.actual_size = len(data)
        self.extra = bytearray(data[self.min_size :])
        self.fields = list(
            struct.unpack(self.min_packspec, bytearray(data[: self.min_size]))
        )

    def has_invalid_name(self, value: str) -> bool:
        return len(value) == 0 or value[0] == "\0" or value[0] == 0

    def populate(self, ea: "ElfAnalyzer", name: str):
        self.fields[self.TIMESTAMP_FIELD] = ea.timestamp()
        self.fields[self.BINARY_SIZE_FIELD] = ea.get_binary_size()
        self.fields[self.TABLES_OFFSET_FIELD] = ea.get_binary_size()
        self.fields[self.BINARY_DATA_FIELD] = ea.get_data_size()
        self.fields[self.BINARY_BSS_FIELD] = ea.get_bss_size()
        self.fields[self.BINARY_GOT_FIELD] = ea.get_got_size()
        self.fields[self.VTOR_OFFSET_FIELD] = 1024

        got = ea.got()
        if got:
            self.fields[self.GOT_OFFSET_FIELD] = (
                got.virtual_address - 0x20000000
                if got.virtual_address > 0x20000000
                else got.virtual_address
            )
        else:
            self.fields[self.GOT_OFFSET_FIELD] = 0x0

        fwhash = ea.calculate_hash()
        self.fields[self.HASH_SIZE_FIELD] = len(fwhash)
        self.fields[self.HASH_FIELD] = fwhash

        if name:
            self.fields[self.NAME_FIELD] = name

        if self.has_invalid_name(self.fields[self.NAME_FIELD]):
            self.fields[self.NAME_FIELD] = self.generate_name(ea)

        if "BUILD_NUMBER" in os.environ:
            self.fields[self.BUILD_NUMBER_FIELD] = int(os.environ["BUILD_NUMBER"])

        self.fields[self.NUMBER_SYMBOLS_FIELD] = len(ea.symbols)
        self.fields[self.NUMBER_RELOCATIONS_FIELD] = len(ea.relocations)

    def generate_name(self, ea: ElfAnalyzer):
        name = os.path.basename(self.fkb_path)
        when = datetime.datetime.utcfromtimestamp(ea.timestamp())
        ft = when.strftime("%Y%m%d_%H%M%S")
        return bytes(name + "_" + platform.node() + "_" + ft, "utf8")

    def to_bytes(self):
        new_header = bytearray(bytes(struct.pack(self.min_packspec, *self.fields)))

        logging.info("Name: %s" % (self.fields[self.NAME_FIELD]))
        logging.info("Version: %s" % (self.fields[self.VERSION_FIELD]))
        logging.info("Number: %s" % (self.fields[self.BUILD_NUMBER_FIELD]))
        logging.info("Hash: %s" % (self.fields[self.HASH_FIELD].hex()))
        logging.info("Time: %d" % (self.fields[self.TIMESTAMP_FIELD]))
        logging.info("Binary size: %d bytes" % (self.fields[self.BINARY_SIZE_FIELD]))
        logging.info("GOT: 0x%x" % (self.fields[self.GOT_OFFSET_FIELD]))
        logging.info(
            "Header: %d bytes (%d of extra)" % (len(new_header), len(self.extra))
        )
        logging.info(
            "Dynamic: syms=%d rels=%d"
            % (
                self.fields[self.NUMBER_SYMBOLS_FIELD],
                self.fields[self.NUMBER_RELOCATIONS_FIELD],
            )
        )

        return new_header + self.extra


class FkbWriter:
    def __init__(self, elf_analyzer: ElfAnalyzer, fkb_path: str):
        self.ea: ElfAnalyzer = elf_analyzer
        self.fkb_path: str = fkb_path

    def populate_header_section(self, name: str):
        section = self.ea.fkbheader()
        if section is None:
            logging.info("No specialized handling for binary.")
            return
        logging.info("Found FKB section: %s bytes" % (section.size))
        header = FkbHeader(self.fkb_path, section.content)
        header.populate(self.ea, name)
        section.content = header.to_bytes()

    def generate(self, name: str):
        logging.info("Code Size: %d" % (self.ea.code().size))
        logging.info("Data Size: %d" % (self.ea.get_data_size()))
        logging.info(" BSS Size: %d" % (self.ea.get_bss_size()))
        logging.info(" GOT Size: %d" % (self.ea.get_got_size()))
        if False:
            logging.info(" Dyn size: %d" % (self.table_size))

        self.generate_table()

        self.populate_header_section(name)

        self.ea.binary.write(self.fkb_path)

    def generate_table(self):
        symbols = bytearray()
        relocations = bytearray()

        # Address in the symbol table we write to the image seems totally wrong...
        indices = {}
        index = 0
        for symbol in self.ea.symbols:
            s = self.ea.symbols[symbol]
            try:
                symbols += struct.pack("<I24s", s[2], bytes(symbol.name, "utf-8"))
            except:
                raise Exception(
                    "Error packing symbol: %s %d %d %d"
                    % (symbol.name, s[0], s[1], s[2])
                )

            indices[symbol] = index
            index += 1

        for r in self.ea.relocations:
            relocations += struct.pack("<II", indices[r[0]], r[1])

        table_alignment = 4096
        self.table_size = utilities.aligned(
            len(symbols) + len(relocations), table_alignment
        )

        self.add_table_section(symbols + relocations, table_alignment)

        logging.info(
            "Table size: %d (%d)" % (len(symbols) + len(relocations), self.table_size)
        )

    def add_table_section(self, table: bytes, table_alignment: int):
        section = self.ea.fkdyn()
        if not section:
            return

        extra_padding = utilities.aligned(len(table), table_alignment) - len(table)
        section.content = table + bytearray([0] * extra_padding)

        logging.info(
            "Dynamic table virtual address: 0x%x table=%d size=%d padding=%d"
            % (len(table), section.virtual_address, len(section.content), extra_padding)
        )


def make_binary_from_elf(elf_path: str, bin_path: str):
    command = ["arm-none-eabi-objcopy", "-O", "binary", elf_path, bin_path]
    logging.info("Exporting '%s' to '%s'" % (elf_path, bin_path))
    logging.info(" ".join(command))
    subprocess.run(command, check=True)

    utilities.append_hash(bin_path)


def configure_logging():
    if False:
        lief.Logger.enable()
        lief.Logger.set_level(lief.LOGGING_LEVEL.TRACE)
        lief.Logger.set_verbose_level(10)
    logging.basicConfig(format="%(asctime)-15s %(message)s", level=logging.INFO)


def main():
    configure_logging()

    parser = argparse.ArgumentParser(description="Firmware Preparation Tool")
    parser.add_argument(
        "--no-verbose",
        dest="no_verbose",
        action="store_true",
        help="Don't show verbose commands (default: false)",
    )
    parser.add_argument(
        "--no-debug",
        dest="no_debug",
        action="store_true",
        help="Don't show debug data (default: false)",
    )
    parser.add_argument(
        "--elf",
        dest="elf_path",
        default=None,
        help="Path to the compiler generated ELF file.",
    )
    parser.add_argument(
        "--fkb", dest="fkb_path", default=None, help="Path to the fkb ELF to generate."
    )
    parser.add_argument(
        "--bin",
        dest="bin_path",
        default=None,
        help="Path to the raw binary to generate. ",
    )
    parser.add_argument(
        "--name", dest="name", default=None, help="Override firmware name."
    )
    parser.add_argument(
        "--dynamic",
        dest="dynamic",
        default=False,
        action="store_true",
        help="Enable dynamic module mode. Relocations, the whole shebang.",
    )

    args, nargs = parser.parse_known_args()

    if args.elf_path:
        logging.info("Processing %s...", args.elf_path)

        ea: Optional[ElfAnalyzer] = None

        if args.fkb_path:
            increase_size_by = 32 if args.bin_path else 0

            ea = ElfAnalyzer(args.dynamic, args.elf_path, increase_size_by)
            ea.analyse()

            fw = FkbWriter(ea, args.fkb_path)
            fw.generate(args.name)

            if args.bin_path:
                ea.write_bin(args.bin_path)
        else:
            if args.bin_path:
                make_binary_from_elf(args.elf_path, args.bin_path)


if __name__ == "__main__":
    main()
