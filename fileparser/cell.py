import logging
import binascii

import synapse.exc as s_exc
import synapse.axon as s_axon
import synapse.lib.cell as s_cell
import synapse.telepath as s_telepath

import fileparser.api as f_api

log = logging.getLogger(__name__)

class FileparserCell(s_cell.Cell):

    cellapi = f_api.FileparserApi

    confdefs = {
        "axon": {
            "description": "A telepath URL for a remote axon.",
            "type": "string"
        },
    }

    async def initServiceRuntime(self):
        await super().initServiceRuntime()

        self.axon_url = self.conf.get("axon")
        if not self.axon_url:
            raise s_exc.NeedConfValu(mesg="The fileparser server has no axon url configured")

    @classmethod
    def getEnvPrefix(cls):
        return (f"SYN_FILEPARSER", f"SYN_{cls.__name__.upper()}", )

    async def getSize(self, sha256: str) -> int | None:
        """Get the size of the file from the Axon API"""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi
                sz = await axon.size(binascii.unhexlify(sha256))

                return sz

    async def getHashes(self, sha256: str) -> dict[str, str]:
        """Get the various file hashes from the Axon API. Returns a dict"""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi
                return await axon.hashset(binascii.unhexlify(sha256))