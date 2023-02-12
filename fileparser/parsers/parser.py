import hashlib
import logging
from typing import Any

import synapse.axon as s_axon
import synapse.lib.base as s_base
import synapse.telepath as s_telepath

log = logging.getLogger(__name__)

ParseEvent = dict[str, Any]

class FileParser(s_base.Base):
    """A FileParser extracts features and relevant metadata from a specified file"""

    # what MIME types can be handled by the parser
    # must be overridden by the child class
    supported_mimes: list[str] = []

    async def __anit__(self, axon_url: str):
        await s_base.Base.__anit__(self)

        self.axon_url = axon_url

        # register an event handler for a new file being created
        # intended to be used for extracted files (archives, certs, etc)    
        async def onNewFile(buf: bytes):
            log.debug("handling zw:fileparser:newfile event")
            return await self._uploadBytes(buf)
        self.on("zw:fileparser:newfile", onNewFile)

    async def _uploadBytes(self, evt):
        """Upload bytes to the axon. Accepts events with the param `bytes`"""

        with s_telepath.withTeleEnv():
            with s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi

                return await axon.put(evt.get("bytes"))

    @classmethod
    async def _evt_prop(cls, prop: str, value: Any, node: str | None = None) -> ParseEvent:
        """Generate an event for setting a property, optionally to the specified node (by default goes on the input file:bytes node)"""
        
        if node is not None:
            np = node.split("=", 1)
        
        evt = {"evt": "prop", "prop": prop, "value": value}
        
        if node is not None:
            evt["form"] = np[0]
            evt["prim"] = np[1]

        return evt
    
    @classmethod
    async def _evt_node(cls, form: str, prim: str, props: list[dict[str, Any]]) -> ParseEvent:
        """Generate an event for creating a new node"""

        return {"evt": "node", "form": form, "prim": prim, "props": props}

    @classmethod
    async def _evt_edge(cls, n1: str, n2: str, edge: str) -> ParseEvent:
        """Generate an event for creating a lightweight edge"""

        n1p = n1.split("=", 1)
        n2p = n2.split("=", 1)

        return {"evt": "edge", "n1": {"form": n1p[0], "prim": n1p[1]}, "n2": {"form": n2p[0], "prim": n2p[1]}, "edge": edge}

    @classmethod
    async def _evt_tag(cls, tag: str, node: str | None = None) -> ParseEvent:
        """Generate an event for adding a tag, optionally to the specified node (by default goes on the input file:bytes node)"""

        if node is not None:
            np = node.split("=", 1)
        
        evt = {"evt": "tag", "tag": tag}
        if node is not None:
            evt["form"] = np[0]
            evt["prim"] = np[1]
        
        return evt
    
    @classmethod
    async def _evt_err(cls, mesg: str) -> ParseEvent:
        """Generate an event for an error that occurred during parsing"""

        return {"evt": "err", "mesg": mesg}
    
    async def _evt_bytes(self, buf: bytes) -> ParseEvent:
        """Generate an event for a new file:bytes to be created"""

        await self.fire("zw:fileparser:newfile", bytes=buf)

        return {"evt": "bytes", "sha256": hashlib.sha256(buf).hexdigest()}

    async def parseFile(self, filebytes: bytes):
        """Parse a file. Must be overridden by child class. Yields ParseEvent objects"""

        raise NotImplementedError