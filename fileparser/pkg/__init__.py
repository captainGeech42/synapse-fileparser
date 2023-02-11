import fileparser.consts as f_consts
import fileparser.pkg.defs as f_defs

async def get_pkgs():
    """Get package definitions"""

    return (
        {
            "name": f_consts.svc_name,
            "version": f_consts.svc_vers,
            "synapse_minversion": f_consts.svc_minvers,
            "modules": [await x.export() for x in f_defs.modules],
            "commands": [await x.export() for x in f_defs.commands],
        },
    )

async def get_evts():
    """Get service event definitions"""

    return {
        "add": {
            "storm": f"[(meta:source={f_consts.svc_guid} :name=zw.fileparser)]"
        }
    }