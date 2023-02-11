import os
import aiofiles

class StormLoader:
    """A mixin that loads Storm code from disk"""

    def __init__(self, storm_files: list[str] = []):
        self.storm_files = storm_files
    
    async def load_storm(self) -> str:
        """Load the storm code from disk"""

        code = ""
        for fp in self.storm_files:
            async with aiofiles.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pkg", "storm", fp), "r") as f:
                code += (await f.read()) + "\n"
        
        return code