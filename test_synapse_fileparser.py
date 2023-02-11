import copy
import contextlib

import synapse.tests.utils as s_test

import fileparser as fplib

class SynapseFileparserTest(s_test.SynTest):
    
    @contextlib.asynccontextmanager
    async def getTestFileparser(self, conf=None, dirn=None):
        if conf is None:
            conf = {}
        conf = copy.deepcopy(conf)

        with self.withNexusReplay():
            if dirn:
                async with await fplib.FileparserCell.anit(dirn, conf=conf) as cell:
                    yield cell
            else:
                with self.getTestDir() as dirn:
                    async with await fplib.FileparserCell.anit(dirn, conf=conf) as cell:
                        yield cell
    
    async def test_src(self):
        async with self.getTestFileparser() as fp:
            async with self.getTestCore() as core:
                await core.callStorm("service.add fileparser $url", opts={"vars": {"url": fp.getLocalUrl()}})

                mesgs = await core.stormlist("service.list")
                self.stormIsInPrint(fplib.svc_name, mesgs)

                self.assertEqual(await core.count("meta:source=$g +:name=zw.fileparser", opts={"vars": {"g": fplib.svc_guid}}), 1)