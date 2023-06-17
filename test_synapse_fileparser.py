import os
import copy
import asyncio
import logging
import binascii
import contextlib

import aiofiles
import synapse.axon as s_axon
import synapse.cortex as s_core
import synapse.tests.utils as s_test

import fileparser as fplib

logging.getLogger().setLevel(logging.DEBUG)

# HOLY GRAIL REFERENCE FOR TESTING THIS SHIT: https://github.com/vertexproject/synapse/blob/1dc3a2a4fa25537e9a4f88e6923913079ebcf77f/synapse/tests/test_lib_stormsvc.py

class SynapseFileparserTest(s_test.SynTest):
    
    @contextlib.asynccontextmanager
    async def getTestFileparser(self, conf=None, dirn=None) -> tuple[fplib.FileparserCell, s_axon.AxonApi]:
        """Get a test fileparser and it's Axon proxy"""

        if conf is None:
            conf = {}
        conf = copy.deepcopy(conf)

        async with self.getTestAxon() as axon:
            # upload the test files
            await self._t_uploadTestFiles(axon)

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
            
                # upload the test files
                await self._t_uploadTestFiles(axon)

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

    async def test_storm_pkg(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            mesgs = await core.stormlist("service.list")
            self.stormIsInPrint(fplib.svc_name, mesgs)

            mesgs = await core.stormlist("dmon.list")
            self.stormIsInPrint("zw.fileparser.parseq", mesgs)

    async def test_modeling_metadata(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            sha256_str = "3ccef83023c34c3c6b7346deb095e5def257ba70900c74e2e676cbe001bc7a51"
            sha256 = binascii.unhexlify(sha256_str)
            props = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | return((:size,:md5,:sha1,:sha256,:sha512,:mime))", opts={"vars": {"s": sha256_str}})
            sz = await axon.size(sha256)
            hs = await axon.hashset(sha256)
            self.eq(props, (sz, hs["md5"], hs["sha1"], hs["sha256"], hs["sha512"], "text/plain"))
            
            self.eq(await core.count("meta:source=$g +:name=zw.fileparser", opts={"vars": {"g": fplib.svc_guid}}), 1)
            self.eq(await core.count("meta:source:name=zw.fileparser -(seen)> * +file:bytes=$s", opts={"vars": {"s": sha256_str}}), 1)

    async def test_modeling_pe_exe(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            exe_sha256 = "a7354b9c6297b6b5537d19a12091e7d89bd52e38bc4d9498fa63aa8c3e700cb6"
            imphash = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | return(:mime:pe:imphash)", opts={"vars": {"s": exe_sha256}})
            self.eq(imphash, "a4dc751c02f601828a098e8da5850f7d")

            self.eq(await core.count("file:bytes=$s -> file:mime:pe:section", opts={"vars": {"s": exe_sha256}}), 5)
            self.eq(await core.count("file:bytes=$s -> file:mime:pe:section +:name='.text' +:sha256=f1f7784827e0661874fd2af5db275be022125d65eab7a6ae5f356821fea28517", opts={"vars": {"s": exe_sha256}}), 1)
    
    async def test_modeling_pe_dll(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            dll_sha256 = "07807083be9e8a65354e912bd9e7863997b022c210299e60ce25f6e9ddccf1ac"
            mime = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | return(:mime)", opts={"vars": {"s": dll_sha256}})
            self.eq(mime, "application/vnd.microsoft.portable-executable")
            self.eq(await core.count("file:mime:pe:export:file=$s", opts={"vars": {"s": dll_sha256}}), 4)
            self.eq(await core.count("file:bytes=$s +:_mime:pe:exphash=a9624d1572c8950b235070113e4f84fb8dc2104ea2537c680e4e75073505b0b2", opts={"vars": {"s": dll_sha256}}), 1)
            self.eq(await core.count("file:mime:pe:export:file=$s +:name=DllCanUnloadNow +:_address=76032 +:_ordinal=1", opts={"vars": {"s": dll_sha256}}), 1)
            self.eq(await core.count("_zw:file:mime:pe:import:file=$s", opts={"vars": {"s": dll_sha256}}), 52)
            self.eq(await core.count("_zw:file:mime:pe:import:file=$s +:name=malloc +:address=2001330396 -:ordinal", opts={"vars": {"s": dll_sha256}}), 1)
            # TODO: test case for import by ordinal needed
    
    async def test_modeling_zip(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            zip_sha256 = "b74bc4edea0842b3b2f621b4dda553acf277198f3dc744e581e00141ad681ef3"
            mime = await core.callStorm("[file:bytes=$s] | zw.fileparser.parse | +{<(seen)- meta:source:name=zw.fileparser} return (:mime)", opts={"vars": {"s": zip_sha256}})
            self.eq(mime, "application/zip")

            # make sure the subfiles get parsed
            while await core.callStorm("return($lib.queue.get(zw.fileparser.parseq).size())") > 0:
                await asyncio.sleep(1)

            self.eq(await core.count("file:bytes=$s -> file:subfile +:path", opts={"vars": {"s": zip_sha256}}), 3)
            self.eq(await core.count("file:subfile=('sha256:b74bc4edea0842b3b2f621b4dda553acf277198f3dc744e581e00141ad681ef3', 'sha256:07b40aacf7008293c886033acac0b9c0ab4d6cef3f4ed66944b61d96a81575e8') +:path=pics/perfection.png"), 1)
            self.eq(await core.count("file:bytes=$s -> file:subfile :child -> file:bytes +:name +:mime", opts={"vars": {"s": zip_sha256}}), 3)
            self.eq(await core.count("file:bytes=$s -> file:subfile :child -> file:bytes +:name=perfection.png +:mime=image/png", opts={"vars": {"s": zip_sha256, "t": 1676206710000}}), 1)

            # disabled per #1
            # self.eq(await core.callStorm("file:subfile=('sha256:b74bc4edea0842b3b2f621b4dda553acf277198f3dc744e581e00141ad681ef3', 'sha256:07b40aacf7008293c886033acac0b9c0ab4d6cef3f4ed66944b61d96a81575e8') +:path=pics/perfection.png return(:_archive:mtime)"), 1)
            # self.eq(await core.count("file:bytes=$s -> file:subfile +:_archive:mtime -:_archive:ctime -:_archive:atime :child -> file:bytes +:name +:mime", opts={"vars": {"s": zip_sha256}}), 3)
            # self.eq(await core.count("file:bytes=$s -> file:subfile +:_archive:mtime=$t :child -> file:bytes +:name=perfection.png +:mime=image/png", opts={"vars": {"s": zip_sha256, "t": 1676206710000}}), 1) # 1676188710000

    async def test_modeling_elf(self):
        async with self.getTestFpCore() as (fp, axon, core):
            fp: fplib.FileparserCell
            axon: s_axon.AxonApi
            core: s_core.Cortex

            ls_sha256 = "7effe56efc49e3d252a84d8173712bad05beef4def460021a1c7865247125fee"
            self.eq(await core.count("[file:bytes=$s] | zw.fileparser.parse | +:mime='application/x-elf'", opts={"vars": {"s": ls_sha256}}), 1)

            self.eq(await core.count("file:bytes=$s -> _zw:file:mime:elf:segment", opts={"vars": {"s": ls_sha256}}), 13)
            self.eq(await core.count("file:bytes=$s -> _zw:file:mime:elf:segment -> _zw:file:mime:elf:section", opts={"vars": {"s": ls_sha256}}), 23)
            self.eq(await core.callStorm("file:bytes=$s -> _zw:file:mime:elf:segment +:disksize=80273 return ((:hash,:memsize,:size,:type,:type:raw))", opts={"vars": {"s": ls_sha256}}), ("aa1952d71027827a269a56fd57db55878da4950e2bd067afc9fb119292edfcfb", 80273, 80273, 1, 1))
            self.eq(await core.callStorm("file:bytes=$s -> _zw:file:mime:elf:segment -> _zw:file:mime:elf:section +:name='.text' return ((:segment,:hash,:size,:offset,:type,:type:raw))", opts={"vars": {"s": ls_sha256}}), ("46ef0c957dfc0814761fe28ce2457783", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 80227, 16416, 1, 1))

            self.eq(await core.callStorm("file:bytes=$s return((:_mime:elf:imphash,:_mime:elf:exphash))", opts={"vars": {"s": ls_sha256}}), ("68a5cd470d526fa45cfd3ad2190ea02865e22c38889618af9db2f5209278594e", "c48b483cf51b62bc5aaed13d62c8c28a7b5ef9ed7646837aad194beb50fb6732"))
            self.eq(await core.callStorm("file:bytes=$s return((:_mime:elf:os,:_mime:elf:os:raw))", opts={"vars": {"s": ls_sha256}}), (0, 0))
            self.eq(await core.callStorm("file:bytes=$s return((:_mime:elf:type,:_mime:elf:type:raw))", opts={"vars": {"s": ls_sha256}}), (3, 3))
            self.eq(await core.callStorm("file:bytes=$s return(:_exe:bitness)", opts={"vars": {"s": ls_sha256}}), 64)