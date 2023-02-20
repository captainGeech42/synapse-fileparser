import pefile
import logging
from typing import AsyncGenerator

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class PeParser(f_parser.FileParser):
    supported_mimes = ["application/vnd.microsoft.portable-executable"]

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        pe = pefile.PE(data=filebytes)
        imphash = pe.get_imphash()
        yield await self._evt_prop(("file:bytes", sha256), "mime:pe:imphash", imphash)