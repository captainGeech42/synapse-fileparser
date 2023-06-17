import struct
import logging
import binascii
import traceback
from typing import AsyncIterator

import magic
import synapse.exc as s_exc
import synapse.axon as s_axon
import synapse.lib.cell as s_cell
import synapse.telepath as s_telepath

import fileparser.api as f_api
import fileparser.parsers as f_parsers

log = logging.getLogger(__name__)

class FileparserCell(s_cell.Cell):

    cellapi = f_api.FileparserApi

    confdefs = {
        "axon": {
            "description": "A telepath URL for a remote axon.",
            "type": "string"
        },
    }

    async def __anit__(self, dirn, conf):
        await s_cell.Cell.__anit__(self, dirn, conf=conf)

        self.onfini(self._onCellFini)

    async def initServiceRuntime(self):
        await super().initServiceRuntime()

        self.axon_url = self.conf.get("axon")
        if not self.axon_url:
            raise s_exc.NeedConfValu(mesg="The fileparser service has no axon url configured")

        self.parsers: dict[str, f_parsers.FileParser] = {}
        for cls in f_parsers.get_parsers():
            p = await cls.anit(self.axon_url)

            for m in cls.supported_mimes:
                self.parsers[m] = p
                p.incref()
            
            await p.fini()

    async def _onCellFini(self):
        for k in self.parsers.keys():
            await self.parsers[k].fini()

    @classmethod
    def getEnvPrefix(cls):
        return (f"SYN_FILEPARSER", f"SYN_{cls.__name__.upper()}", )

    def _getMime(self, buf: bytes) -> str:
        """Get the MIME type for the provided bytes"""

        # libmagic does some wack stuff on elfs, and the enterprise fileparser seems to standardize these
        if buf[:4] == b"\x7fELF":
            return "application/x-elf"
    
        if buf[:2] == b"MZ":
            pe_off = struct.unpack("<I", buf[0x3c:0x40])[0]
            if buf[pe_off:pe_off+4] == b"PE\x00\x00":
                return "application/vnd.microsoft.portable-executable"

        return magic.from_buffer(buf, mime=True)

    async def getSize(self, sha256: str) -> int | None:
        """Get the size of the file from the Axon API"""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi
                try:
                    return await axon.size(binascii.unhexlify(sha256))
                except s_exc.NoSuchFile:
                    return None

    async def getHashes(self, sha256: str) -> dict[str, str] | None:
        """Get the various file hashes from the Axon API. Returns a dict, or None if no bytes available."""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi

                try:
                    return await axon.hashset(binascii.unhexlify(sha256))
                except s_exc.NoSuchFile:
                    return None
    
    async def getMime(self, sha256: str) -> str | None:
        """Detect the proper MIME type for the file"""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi

                buf = b""
                # not all axon implementations support the partial read
                try:
                    async for bytz in axon.get(binascii.unhexlify(sha256)):
                        buf += bytz
                        if len(buf) >= 4096:
                            break
                except s_exc.NoSuchFile:
                    return None

                if len(buf) > 0:
                    return self._getMime(buf)
                else:
                    return None
    
    async def parseFile(self, sha256: str, mime: str | None = None) -> AsyncIterator[f_parsers.ParseEvent]:
        """Parse a file according to the detected or specified MIME type"""

        log.info("parsing file: %s", sha256)

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi

                buf = b""
                try:
                    async for bytz in axon.get(binascii.unhexlify(sha256)):
                        buf += bytz
                except s_exc.NoSuchFile:
                    yield f_parsers.FileParser._evt_err(f"no bytes available for {sha256}")
                    return
                
                if mime is None:
                    mime = self._getMime(buf)

                if mime not in self.parsers:
                    # mesg = f"can't parse {sha256}, no parser available for {mime}"
                    # log.warning(mesg)
                    # yield await f_parsers.FileParser._evt_err(mesg)
                    return
                
                try:
                    async for evt in self.parsers[mime].parseFile(sha256, buf):
                        if evt is None:
                            return
                        yield evt
                except Exception as e:
                    yield f_parsers.FileParser._evt_err(f"unhandled error when parsing {sha256}: {traceback.format_exc()}")