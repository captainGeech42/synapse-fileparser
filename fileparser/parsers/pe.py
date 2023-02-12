import pefile
import logging

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class PeParser(f_parser.FileParser):
    supported_mimes = ["application/vnd.microsoft.portable-executable"]

    async def parseFile(self, filebytes: bytes):
        pe = pefile.PE(data=filebytes)
        imphash = pe.get_imphash()
        yield await self._evt_prop("mime:pe:imphash", imphash)
        yield await self._evt_err("test error 123")
        return