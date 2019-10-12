import lief

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_reloc_type

class Symbol:
    def __init__(self, section, s):
        self.name = s.name
        sbind = s['st_info']['bind']
        if sbind == "STB_GLOBAL": self.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
        elif sbind == "STB_LOCAL": self.binding = lief.ELF.SYMBOL_BINDINGS.LOCAL
        elif sbind == "STB_WEAK": self.binding = lief.ELF.SYMBOL_BINDINGS.WEAK
        else: raise Exception("Unknown bind: '%s'" % (sbind))
        stype = s['st_info']['type']

        if stype == "STT_FILE": self.type = lief.ELF.SYMBOL_TYPES.FILE
        elif stype == "STT_OBJECT": self.type = lief.ELF.SYMBOL_TYPES.OBJECT
        elif stype == "STT_FUNC": self.type = lief.ELF.SYMBOL_TYPES.FUNC
        elif stype == "STT_NOTYPE": self.type = None
        elif stype == "STT_SECTION": self.type = lief.ELF.SYMBOL_TYPES.SECTION
        else: raise Exception("Unknown stype: '%s'" % (stype))

        self.size = int(s['st_size'])
        self.shndx = s['st_shndx']
        try:
            self.shndx = int(sdata["section"])
            self.exported = s["section"] != "SHN_UNDEF"
        except:
            self.exported = False
        self.value = int(s['st_value'])

class Section:
    def __init__(self, s):
        self.name = s.name
        self.virtual_address = int(s['sh_addr'])

class Relocation:
    def __init__(self, elf, section, symtable, symbol_objects, r):
        self.offset = int(r['r_offset'])
        stype = describe_reloc_type(r['r_info_type'], elf)
        if stype == "R_ARM_GOT_BREL": self.type = lief.ELF.RELOCATION_ARM.GOT_BREL
        elif stype == "R_ARM_ABS32": self.type = lief.ELF.RELOCATION_ARM.ABS32
        elif stype == "R_ARM_THM_CALL": self.type = lief.ELF.RELOCATION_ARM.THM_CALL
        elif stype == "R_ARM_THM_JUMP24": self.type = lief.ELF.RELOCATION_ARM.THM_JUMP24
        elif stype == "R_ARM_TARGET1": self.type = lief.ELF.RELOCATION_ARM.TARGET1
        elif stype == "R_ARM_PREL31": self.type = lief.ELF.RELOCATION_ARM.PREL31
        elif stype == "R_ARM_REL32": self.type = lief.ELF.RELOCATION_ARM.REL32
        else: raise Exception("Unknown rel type: '%s'" % (stype))

        s = symtable.get_symbol(r['r_info_sym'])
        if s['st_name'] != 0:
            self.name = str(s.name)
            self.symbol = symbol_objects[s.name]
            self.has_symbol = True
        else:
            self.has_symbol = False

        try:
            symsec = elf.get_section(s['st_shndx'])
            self.section = Section(symsec)
            self.name = self.section
        except:
            self.section = Section(section)
            self.name = self.section

        self.value = s["st_value"]
        self.address = s["st_value"]

def get_symbols_in_elf(path):
    symbols = {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    s = Symbol(section, symbol)
                    symbols[s.name] = s
    return symbols

def get_relocations_in_elf(path, symbol_objects):
    rels = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                symtable = elf.get_section(section['sh_link'])
                for r in section.iter_relocations():
                    if r['r_info_sym'] == 0:
                        continue
                    rels.append(Relocation(elf, section, symtable, symbol_objects, r))
    return rels

def relocation_type_name(r):
    for attr, value in lief.ELF.RELOCATION_ARM.__dict__.items():
        if isinstance(value, lief.ELF.RELOCATION_ARM) and value == r:
            return attr
    return "<unknown>"
