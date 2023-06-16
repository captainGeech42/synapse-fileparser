"""Lookup tables and constants for various file formats."""

# The program header p_type fields for an ELF
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