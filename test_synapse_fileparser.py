import os
import copy
import asyncio
import aiofiles
import binascii
import contextlib

import synapse.axon as s_axon
import synapse.cortex as s_core
import synapse.tests.utils as s_test

import fileparser as fplib

# HOLY GRAIL REFERENCE FOR TESTING THIS SHIT: https://github.com/vertexproject/synapse/blob/1dc3a2a4fa25537e9a4f88e6923913079ebcf77f/synapse/tests/test_lib_stormsvc.py

class SynapseFileparserTest(s_test.SynTest):
    
    @contextlib.asynccontextmanager
    async def getTestFileparser(self, conf=None, dirn=None) -> tuple[fplib.FileparserCell, s_axon.AxonApi]:
        """Get a test fileparser and it's Axon proxy"""

        if conf is None:
            conf = {}
        conf = copy.deepcopy(conf)

        async with self.getTestAxon() as axon:
            if "axon" not in conf:
                conf["axon"] = axon.getLocalUrl()
            with self.withNexusReplay():
                if dirn:
                    async with await fplib.FileparserCell.anit(dirn, conf=conf) as cell:
                        async with axon.getLocalProxy() as prox:
                            yield (cell, prox)
                else:
                    with self.getTestDir() as dirn:
                        async with await fplib.FileparserCell.anit(dirn, conf=conf) as cell:
                            async with axon.getLocalProxy() as prox:
                                yield (cell, prox)

    @contextlib.asynccontextmanager
    async def getTestFpCore(self, conf=None, dirn=None) -> tuple[fplib.FileparserCell, s_axon.AxonApi, s_core.Cortex]:
        """Get a test fileparser, axon, and a cortex with the storm service initialized"""

        async with self.getTestFileparser(conf=conf, dirn=dirn) as (fp, axon):
            async with self.getTestCore() as core:
                await core.callStorm("service.add fileparser $url", opts={"vars": {"url": fp.getLocalUrl()}})

                # wait for the service to finish initialization
                await core.nodes("$lib.service.wait(fileparser)")

                yield (fp, axon, core)

    @contextlib.asynccontextmanager
    async def getTestFpProxy(self, conf=None, dirn=None) -> tuple[fplib.FileparserCell, fplib.FileparserApi]:
        """Get a test fileparser and the telepath proxy"""

        async with self.getTestFileparser(conf=conf, dirn=dirn) as (fp, _):
            async with fp.getLocalProxy as prox:
                yield (fp, prox)

    async def _t_uploadTestFiles(self, axon: s_axon.AxonApi):
        """Upload all of the test files to the provided Axon cell"""

        for fn in os.listdir("test_files"):
            try:
                async with aiofiles.open(os.path.join("test_files", fn), "rb") as f:
                    buf = await f.read()
                    (sz, _) = await axon.put(buf)
                    self.eq(sz, len(buf))
            except IsADirectoryError:
                continue

    async def test_fileparser(self):
        async with self.getTestFileparser() as (fp, axon):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi

            await self._t_uploadTestFiles(axon)
            
            # test size
            ls_sha256_str = "7effe56efc49e3d252a84d8173712bad05beef4def460021a1c7865247125fee"
            ls_sha256 = binascii.unhexlify(ls_sha256_str)
            sz = await axon.size(ls_sha256)
            self.assertIsNotNone(sz)
            self.eq(await fp.getSize(ls_sha256_str), sz)

            # test hashes
            hs = await axon.hashset(ls_sha256)
            self.eq(await fp.getHashes(ls_sha256_str), hs)

            # test mime
            self.eq(await fp.getMime(ls_sha256_str), "application/x-elf")
            self.eq(await fp.getMime("a7354b9c6297b6b5537d19a12091e7d89bd52e38bc4d9498fa63aa8c3e700cb6"), "application/vnd.microsoft.portable-executable")
            self.eq(await fp.getMime("07807083be9e8a65354e912bd9e7863997b022c210299e60ce25f6e9ddccf1ac"), "application/vnd.microsoft.portable-executable")

    async def test_storm_pkg(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            mesgs = await core.stormlist("service.list")
            self.stormIsInPrint(fplib.svc_name, mesgs)

            mesgs = await core.stormlist("dmon.list")
            self.stormIsInPrint("zw.fileparser.parseq", mesgs)

            self.assertEqual(await core.count("meta:source=$g +:name=zw.fileparser", opts={"vars": {"g": fplib.svc_guid}}), 1)

            await self._t_uploadTestFiles(axon)

            # basic metadata modeling
            ls_sha256_str = "7effe56efc49e3d252a84d8173712bad05beef4def460021a1c7865247125fee"
            ls_sha256 = binascii.unhexlify(ls_sha256_str)
            props = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | return((:size,:md5,:sha1,:sha256,:sha512, :mime))", opts={"vars": {"s": ls_sha256_str}})
            sz = await axon.size(ls_sha256)
            hs = await axon.hashset(ls_sha256)
            self.eq(props, (sz, hs["md5"], hs["sha1"], hs["sha256"], hs["sha512"], "application/x-elf"))

            # exe file modeling
            exe_sha256 = "a7354b9c6297b6b5537d19a12091e7d89bd52e38bc4d9498fa63aa8c3e700cb6"
            imphash = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | return(:mime:pe:imphash)", opts={"vars": {"s": exe_sha256}})
            self.eq(imphash, "a4dc751c02f601828a098e8da5850f7d")

            # zip file modeling
            zip_sha256 = "b74bc4edea0842b3b2f621b4dda553acf277198f3dc744e581e00141ad681ef3"
            mime = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | +{<(seen)- meta:source:name=zw.fileparser} return (:mime)", opts={"vars": {"s": zip_sha256}})
            self.eq(mime, "application/zip")

            # make sure the subfiles get parsed
            while await core.callStorm("return($lib.queue.get(zw.fileparser.parseq).size())") > 0:
                await asyncio.sleep(1)

            self.eq(await core.count("file:bytes=$s -> file:subfile +:path", opts={"vars": {"s": zip_sha256}}), 3)
            self.eq(await core.count("file:subfile=('sha256:b74bc4edea0842b3b2f621b4dda553acf277198f3dc744e581e00141ad681ef3', 'sha256:07b40aacf7008293c886033acac0b9c0ab4d6cef3f4ed66944b61d96a81575e8') +:path=pics/perfection.png"), 1)
            self.eq(await core.count("file:bytes=$s -> file:subfile :child -> file:bytes +:name +:mime", opts={"vars": {"s": zip_sha256}}), 3)
            self.eq(await core.count("file:bytes=$s -> file:subfile :child -> file:bytes +:name=perfection.png +:mime=image/png", opts={"vars": {"s": zip_sha256}}), 1)