import logging

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

import fileparser.consts as f_consts
import fileparser.pkg as f_pkg

log = logging.getLogger(__name__)

class FileparserApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """
    A Telepath API for the Fileparser service.
    """

    _storm_svc_name = f_consts.svc_name
    _storm_svc_vers = f_consts.svc_vers
    _storm_svc_evts = f_consts.svc_evts
    _storm_svc_pkgs = f_pkg.get_pkgs()

    @s_cell.adminapi()
    async def getAdminInfo(self):
        return await self.cell.getAdminInfo()

    async def getSize(self, sha256: str):
        await self._reqUserAllowed(("zw", "fileparser", "user"))
        return await self.cell.getSize(sha256)

    async def getHashes(self, sha256: str):
        await self._reqUserAllowed(("zw", "fileparser", "user"))
        return await self.cell.getHashes(sha256)