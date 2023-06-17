import io
import struct
import logging
import hashlib
from typing import AsyncGenerator

import lief
import synapse.common as s_common

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class ElfParser(f_parser.FileParser):
    supported_mimes = ["application/x-elf"]

    @staticmethod
    def _compute_imphash(elf: lief.ELF.Binary) -> str:
        """Compute the imphash of the ELF file"""

        return hashlib.sha256(",".join([x.name for x in elf.imported_symbols]).encode()).hexdigest()

    @staticmethod
    def _compute_exphash(elf: lief.ELF.Binary) -> str:
        """Compute the exphash of the ELF file"""
        
        return hashlib.sha256(",".join([x.name for x in elf.exported_symbols]).encode()).hexdigest()

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        elf = lief.parse(filebytes)
        if not isinstance(elf, lief.ELF.Binary):
            log.error("failed to parse %s as ELF")
            return
        
        os_val = filebytes[0x7]
        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:os", os_val)
        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:os:raw", os_val)

        type_val = struct.unpack("<H",filebytes[0x10:0x12])[0]
        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:type", type_val)
        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:type:raw", type_val)

        class_val = filebytes[0x4]
        bitness = -1
        if class_val == 1:
            bitness = 32
        elif class_val == 2:
            bitness = 64
        else:
            log.error("invalid EI_CLASS value for %s: %d", sha256, class_val)

        if bitness != -1:
            yield self._evt_prop(("file:bytes", sha256), "_exe:bitness", bitness)

        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:imphash", self._compute_imphash(elf))
        yield self._evt_prop(("file:bytes", sha256), "_mime:elf:exphash", self._compute_exphash(elf))

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