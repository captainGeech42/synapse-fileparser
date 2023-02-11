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

    async def getStormSvcInfo(self):
        return {
            'name': f_consts.svc_name,
            'vers': f_consts.svc_vers,
            'evts': await f_pkg.get_evts(),
            'pkgs': await f_pkg.get_pkgs()
        }

    async def getData(self, query):
        return await self.cell.getData(query)

    async def getInfo(self):
        await self._reqUserAllowed(("example", "info"))
        return await self.cell.getInfo()

    @s_cell.adminapi()
    async def getAdminInfo(self):
        return await self.cell.getAdminInfo()