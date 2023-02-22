svc_name = "zw.fileparser"
svc_guid = "7cf0f7eeb3941bc6c3f80cf8da535e1e"
svc_vers = (0, 0, 1)
svc_minvers = (2, 122, 0)

svc_parseq = "zw.fileparser.parseq"

svc_evts = {
    "add": {
        "storm": r"""
            // add the meta:source node
            [(meta:source=$svc_guid :name=zw.fileparser)]

            // start the parseq dmon
            // TODO: check if one already exists, and bump it of so. otherwise create
            $lib.dmon.add(${ $lib.import(zw.fileparser.dmon).dmonEntry() }, name='$svc_parseq')

            // execute model migrations
            if (not $lib.model.prop(file:bytes:_exe:arch)) {
                $lib.model.ext.addFormProp(file:bytes, _exe:arch, (str, ({'lower': $lib.true, 'strip': $lib.true})), ({'doc': 'The architecture for the executable'}))
            }
            if (not $lib.model.prop(file:bytes:_mime:pe:exphash)) {
                $lib.model.ext.addFormProp(file:bytes, _mime:pe:exphash, (hash:sha256, ({})), ({'doc': 'The PE export hash of the file as calculated by pefile; https://github.com/erocarrera/pefile .'}))
            }
            if (not $lib.model.prop(file:mime:pe:export:_address)) {
                $lib.model.ext.addFormProp(file:mime:pe:export, _address, (int, ({})), ({'doc': 'The RVA of the exported function'}))
            }
            if (not $lib.model.prop(file:mime:pe:export:_ordinal)) {
                $lib.model.ext.addFormProp(file:mime:pe:export, _ordinal, (int, ({})), ({'doc': 'The ordinal of the export'}))
            }
            if (not $lib.model.form(_zw:file:mime:pe:import)) {
                $lib.model.ext.addForm(_zw:file:mime:pe:import, guid, ({}), ({'doc': 'The fused knowledge of a file:bytes node containing a pe import.'}))

                $lib.model.ext.addFormProp(_zw:file:mime:pe:import, file, (file:bytes, ({})), ({'doc': 'The file containing the import.'}))
                $lib.model.ext.addFormProp(_zw:file:mime:pe:import, dll, (str, ({})), ({'doc': 'The DLL name to import the function from.'}))
                $lib.model.ext.addFormProp(_zw:file:mime:pe:import, name, (str, ({})), ({'doc': 'The name of the function to import.'}))
                $lib.model.ext.addFormProp(_zw:file:mime:pe:import, ordinal, (int, ({})), ({'doc': 'The ordinal of the function to import.'}))
                $lib.model.ext.addFormProp(_zw:file:mime:pe:import, address, (int, ({})), ({'doc': 'The address for the imported function in the source executable.'}))
            }
        """
            .replace("$svc_guid", svc_guid)
            .replace("$svc_parseq", svc_parseq)
    }
}