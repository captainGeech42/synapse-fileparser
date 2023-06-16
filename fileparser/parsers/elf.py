import io
import logging
import hashlib
from typing import AsyncGenerator

import lief
import synapse.common as s_common

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class ElfParser(f_parser.FileParser):
    supported_mimes = ["application/x-elf"]

    def _compute_imphash(elf: lief.ELF.Binary) -> str:
        """Compute the imphash of the ELF file"""

        raise NotImplementedError()

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        elf = lief.parse(filebytes)
        if not isinstance(elf, lief.ELF.Binary):
            log.error("failed to parse %s as ELF")
            return
         
        # model the elf segments
        for i in range(len(elf.segments)):
            segm = elf.segments[i]

            bytz = segm.content.tobytes()

            segm_hash = hashlib.sha256(bytz).hexdigest()

            segm_guid = s_common.guid((sha256, segm_hash, i))

            yield self._evt_node(("_zw:file:mime:elf:segment", segm_guid), [
                ("file", sha256),
                ("hash", segm_hash),
                ("size", len(bytz)),
                ("disksize", segm.physical_size),
                ("memsize", segm.virtual_size),
                ("type", segm.type.value),
                ("type:raw", segm.type.value)
            ])

            # model the elf sections within this segment
            for j in range(len(segm.sections)):
                sect = segm.sections[j]

                bytz = sect.content.tobytes()
                sect_hash = hashlib.sha256().hexdigest()

                yield self._evt_node(("_zw:file:mime:elf:section", (sha256, sect.file_offset, sect.name)), [
                    ("segment", segm_guid),
                    ("hash", sect_hash),
                    ("size", sect.size),
                    ("name", sect.name),
                    ("offset", sect.file_offset),
                    ("type", sect.type.value),
                    ("type:raw", sect.type.value)
                ])