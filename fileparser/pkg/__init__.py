import fileparser.consts as f_consts
import fileparser.pkg.defs as f_defs

def get_pkgs():
    """Get package definitions"""

    return (
        {
            "name": f_consts.svc_name,
            "version": f_consts.svc_vers,
            "synapse_minversion": f_consts.svc_minvers,
            "modules": [x.export() for x in f_defs.get_modules()],
            "commands": [x.export() for x in f_defs.get_commands()],
        },
    )