import synapse.lib.cell as s_cell

import fileparser.api as f_api

class FileparserCell(s_cell.Cell):

    cellapi = f_api.FileparserApi
    
    async def __anit__(self, dirn, conf):
        await s_cell.Cell.__anit__(self, dirn, conf=conf)

    @classmethod
    def getEnvPrefix(cls):
        return (f"SYN_FILEPARSER", f"SYN_{cls.__name__.upper()}", )