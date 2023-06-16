import io
import os
import hashlib
import logging
import zipfile
from datetime import datetime
from typing import AsyncGenerator

import fileparser.parsers.parser as f_parser

log = logging.getLogger(__name__)

class ZipParser(f_parser.FileParser):
    supported_mimes = ["application/zip"]

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[f_parser.ParseEvent, None]:
        with zipfile.ZipFile(io.BytesIO(filebytes), "r") as zf:
            for f in zf.filelist:
                if f.is_dir():
                    continue

                buf = zf.read(f.filename)
                child_sha256 = hashlib.sha256(buf).hexdigest()
                basename = os.path.basename(f.filename)
                mtime = int(datetime(*f.date_time).timestamp() * 1000)

                yield await self._evt_bytes(buf, basename)
                yield await self._evt_node(("file:subfile", (sha256,child_sha256)), [("path", f.filename)])

                # disabled per #1
                # yield await self._evt_node(("file:subfile", (sha256,child_sha256)), [("path", f.filename), ("_archive:mtime", mtime)])