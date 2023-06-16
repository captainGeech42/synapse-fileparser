import logging
import binascii
import hashlib
from typing import AsyncGenerator

import pefile
import synapse.common as s_common

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class PeParser(f_parser.FileParser):
    # TODO: should we normalize this like ELFs? yes, yes we should
    supported_mimes = ["application/vnd.microsoft.portable-executable", "application/x-dosexec"]

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        pe = pefile.PE(data=filebytes, fast_load=True)
        pe.parse_data_directories([
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])

        # model the imphash/exphash
        imphash = pe.get_imphash()
        if len(imphash) > 0:
            yield self._evt_prop(("file:bytes", sha256), "mime:pe:imphash", imphash)

        exphash = pe.get_exphash()
        if len(exphash) > 0:
            yield self._evt_prop(("file:bytes", sha256), "_mime:pe:exphash", exphash)

        # model the exported symbols
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    name = exp.name.decode("ascii")
                except UnicodeDecodeError:
                    log.error("error parsing %s as pe file: export directory contained an invalid symbol name (hex: %s)", sha256, binascii.hexlify(exp.name).decode())
                    continue

                yield self._evt_node(("file:mime:pe:export", (sha256,name)), [("_address", exp.address), ("_ordinal", exp.ordinal)])
        except AttributeError as e:
            if e.name == "DIRECTORY_ENTRY_EXPORT":
                log.debug("no export directory for %s", sha256)
                pass
            else:
                raise e

        # model the imported symbols
        try:
            for impdll in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = impdll.dll.decode("ascii")
                except UnicodeDecodeError:
                    log.error("error parsing %s as pe file: import directory contained an invalid dll name (hex: %s)", sha256, binascii.hexlify(impdll.dll).decode())
                    continue

                for imp in impdll.imports:
                    props = {
                        "file": sha256,
                        "dll": dll,
                        "address": imp.address
                    }
                    if imp.import_by_ordinal:
                        props["ordinal"] = imp.ordinal
                    else:
                        try:
                            name = imp.name.decode("ascii")
                        except UnicodeDecodeError:
                            log.error("error parsing %s as pe file: import directory contained an invalid import symbol name (hex: %s)", sha256, binascii.hexlify(imp.name).decode())
                            continue
                        props["name"] = name

                    yield self._evt_node(("_zw:file:mime:pe:import", s_common.guid(props)), [(k,v) for k, v in props.items()])
        except AttributeError as e:
            if e.name == "DIRECTORY_ENTRY_IMPORT":
                log.debug("no import directory for %s", sha256)
                pass
            else:
                raise e
            
        # model the PE sections
        for sect in pe.sections:
            try:
                name = sect.Name.rstrip(b"\x00").decode("ascii")
            except UnicodeDecodeError:
                log.error("error parsing %s as pe file: found an invalid section name (hex: %s)", sha256, binascii.hexlify(sect.Name).decode())
                continue

            bytz = sect.get_data()
            sect_hash = hashlib.sha256(bytz, usedforsecurity=False).hexdigest()
            yield await self._evt_bytes(bytz, name=name)

            yield self._evt_node(("file:mime:pe:section", (sha256, name, sect_hash)))