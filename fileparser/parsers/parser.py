import hashlib
import logging
from typing import Any, AsyncGenerator

import synapse.axon as s_axon
import synapse.lib.base as s_base
import synapse.telepath as s_telepath

log = logging.getLogger(__name__)

Node = tuple[str, Any] # form->prim
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

        if evt[0] != "zw:fileparser:newfile":
            log.warning("got a different event for callback: %s", evt[0])
            return

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axon_url) as axon:
                axon: s_axon.AxonApi

                return await axon.put(evt[1].get("bytes"))

    @classmethod
    def _evt_prop(cls, node: Node, prop: str, value: Any) -> ParseEvent:
        """Generate an event for setting a property, optionally to the specified node (by default goes on the input file:bytes node)"""

        if prop.startswith(":"):
            log.warning("removing leading : from prop name: %s", prop)
            prop = prop[1:]

        evt = {"evt": "prop", "prop": prop, "value": value}
        
        if node is not None:
            evt["form"] = node[0]
            evt["prim"] = node[1]

        return evt
    
    @classmethod
    def _evt_node(cls, node: Node, props: list[tuple[str, Any]] = []) -> ParseEvent:
        """Generate an event for creating a new node"""

        _props = []
        for (k, v) in props:
            if k.startswith(":"):
                log.warning("removing leading : from prop name: %s", k)
                k = k[1:]
            _props.append((k, v))

        return {"evt": "node", "form": node[0], "prim": node[1], "props": _props}

    @classmethod
    def _evt_edge(cls, n1: Node, n2: Node, edge: str) -> ParseEvent:
        """Generate an event for creating a lightweight edge"""

        return {"evt": "edge", "n1": {"form": n1[0], "prim": n1[1]}, "n2": {"form": n2[0], "prim": n2[1]}, "edge": edge}

    @classmethod
    def _evt_tag(cls, node: Node, tag: str) -> ParseEvent:
        """Generate an event for adding a tag"""

        if tag.startswith("#"):
            log.warning("removing leading # from tag: %s", tag)
            tag = tag[1:]
        
        evt = {"evt": "tag", "form": node[0], "prim": node[1], "tag": tag}
        
        return evt
    
    @classmethod
    def _evt_err(cls, mesg: str) -> ParseEvent:
        """Generate an event for an error that occurred during parsing"""

        return {"evt": "err", "mesg": mesg}
    
    async def _evt_bytes(self, buf: bytes, name: str | None = None) -> ParseEvent:
        """Generate an event for a new file:bytes to be created"""

        await self.fire("zw:fileparser:newfile", bytes=buf)

        evt = {"evt": "bytes", "sha256": hashlib.sha256(buf).hexdigest()}
        if name is not None:
            evt["name"] = name
        
        return evt

    async def parseFile(self, sha256: str, filebytes: bytes) -> AsyncGenerator[ParseEvent, None]:
        """Parse a file. Must be overridden by child class. Yields ParseEvent objects"""

        raise NotImplementedError