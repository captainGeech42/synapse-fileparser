import io
import logging
import binascii
import hashlib
from typing import AsyncGenerator

import lief
import synapse.common as s_common

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class ElfParser(f_parser.FileParser):
    supported_mimes = ["application/x-elf"]

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        elf = lief.ELF.parse(io=io.BytesIO(filebytes))
        if elf is None:
            log.error("failed to parse %s as ELF")
            return

        # model the elf sections
        for sect in elf.sections:
            if sect.size == 0:
                continue

            # maybe only do PROGBITS and NOBITS sections?
            # for now, do all

            name = sect.name
            bytz = sect.content.tobytes()