"""Lookup tables and constants for various file formats."""

# Valid values for the bitness of an executable file
VALID_BITNESS = (8, 16, 32, 64)

# The ELF header et_type value
ELF_ET_TYPE = {
    0: ("ET_NONE", "Unknown"),
    1: ("ET_REL", "Relocatable file"),
    2: ("ET_EXEC", "Executable file"),
    3: ("ET_DYN", "Shared object"),
    4: ("ET_CORE", "Core file")
}

# range of values for OS-specific e_type values (inclusive)
ELF_ET_TYPE_OS_RANGE = (0xfe00, 0xfeff)

# range of values for processor-specific e_type values (inclusive)
ELF_ET_TYPE_PROC_RANGE = (0xff00, 0xffff)

def getElfEtTypeTuple() -> tuple:
    return tuple([(x, ELF_ET_TYPE[x][1].lower()) for x in ELF_ET_TYPE.keys()])

# The possible values for the ELF header e_ident OSABI field
ELF_OSABI = {
    0: ("ELFOSABI_NONE", "System-V"),
    1: ("ELFOSABI_HPUX", "HP-UX"),
    2: ("ELFOSABI_NETBSD", "NetBSD"),
    3: ("ELFOSABI_LINUX", "Linux"),
    6: ("ELFOSABI_SOLARIS", "Solaris"),
    7: ("ELFOSABI_AIX", "AIX"),
    8: ("ELFOSABI_IRIX", "IRIX"),
    9: ("ELFOSABI_FREEBSD", "FreeBSD"),
    10: ("ELFOSABI_TRU64", "Tru64"),
    11: ("ELFOSABI_MODESTO", "Novell Modesto"),
    12: ("ELFOSABI_OPENBSD", "OpenBSD"),
    13: ("ELFOSABI_OPENVMS", "OpenVMS"),
    14: ("ELFOSABI_NSK", "Non-Stop Kernel")
}

def getElfOsabiTuple() -> tuple:
    return tuple([(x, ELF_OSABI[x][1].lower()) for x in ELF_OSABI.keys()])

# The possible values for the ELF program header p_type field
ELF_PH_TYPE = {
    0: ("PT_NULL", "Unused entry"),
    1: ("PT_LOAD", "Loadable segment"),
    2: ("PT_DYNAMIC", "Dynamic linking information"),
    3: ("PT_INTERP", "Interpreter information"),
    4: ("PT_NOTE", "Auxiliary information"),
    5: ("PT_SHLIB", "Reserved"),
    6: ("PT_PHDR", "Program header segment"),
    7: ("PT_TLS", "Thread-local storage template")
}

def getElfPhTypeTuple() -> tuple:
    return tuple([(x, ELF_PH_TYPE[x][1].lower()) for x in ELF_PH_TYPE.keys()])

# range of values for OS-specific p_type values (inclusive)
ELF_PH_TYPE_OS_RANGE = (0x60000000, 0x6fffffff)

# range of values for processor-specific p_type values (inclusive)
ELF_PH_TYPE_PROC_RANGE = (0x70000000, 0x7fffffff)

# The possible values for the ELF section header sh_type field
ELF_SH_TYPE = {
    0: ("SHT_NULL", "Unused entry"),
    1: ("SHT_PROGBITS", "Program data"),
    2: ("SHT_SYMTAB", "Symbol table"),
    3: ("SHT_STRTAB", "String table"),
    4: ("SHT_RELA", "Relocation entries with addends"),
    5: ("SHT_HASH", "Symbol hash table"),
    6: ("SHT_DYNAMIC", "Dynamic linking information"),
    7: ("SHT_NOTE", "Notes"),
    8: ("SHT_NOBITS", "Program space with no data"),
    9: ("SHT_REL", "Relocation entries"),
    0xA: ("SHT_SHLIB", "Reserved"),
    0xB: ("SHT_DYNSYM", "Dynamic linker symbol table"),
    0xE: ("SHT_INIT_ARRAY", "Array of constructors"),
    0xF: ("SHT_FINI_ARRAY", "Array of destructors"),
    0x10: ("SHT_PREINIT_ARRAY", "Array of pre-constructors"),
    0x11: ("SHT_GROUP", "Section group"),
    0x12: ("SHT_SYMTAB_SHNDX", "Extended section indicies"),
    0x13: ("SHT_NUM", "Number of defined types")
}

# range of values for OS-specific sh_type values (inclusive)
ELF_SH_TYPE_OS_RANGE = (0x60000000, 0xffffffff)

def getElfShTypeTuple() -> tuple:
    return tuple([(x, ELF_SH_TYPE[x][1].lower()) for x in ELF_SH_TYPE.keys()])