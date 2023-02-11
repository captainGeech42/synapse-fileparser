import os

class StormLoader:
    """A mixin that loads Storm code from disk"""

    def __init__(self, storm_files: list[str] = []):
        self.storm_files = storm_files
    
    def load_storm(self) -> str:
        """Load the storm code from disk"""

        code = ""
        for fp in self.storm_files:
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storm", fp)
            with open(p, "r") as f:
                code += f.read() + "\n"
        
        return code