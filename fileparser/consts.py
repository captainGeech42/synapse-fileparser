svc_name = "zw.fileparser"
svc_guid = "7cf0f7eeb3941bc6c3f80cf8da535e1e"
svc_vers = (0, 1, 0)
svc_minvers = (2, 122, 0)

svc_parseq = "zw.fileparser.parseq"
svc_migrationkey = "zw.fileparser:migrationversion"

svc_evts = {
    "add": {
        "storm": r"""
            // start the parseq dmon
            // TODO: check if one already exists, and bump it of so. otherwise create
            $lib.dmon.add(${ $lib.import(zw.fileparser.dmon).dmonEntry() }, name='$svc_parseq')
        """
            .replace("$svc_parseq", svc_parseq)
    }
}

svc_onload = r"""
$lib.import(zw.fileparser.model).executeMigrations()
"""