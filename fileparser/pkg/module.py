import fileparser.consts as f_consts
import fileparser.pkg.loader as f_loader

class StormModule(f_loader.StormLoader):
    """Definition of a Storm service module"""

    def __init__(self, name: str, code_file: str):
        super().__init__([code_file])

        self.name = name

        self.conf = {"srcguid": f_consts.svc_guid}

    def add_conf(self, name: str, value: str):
        """Add a static configuration option for the module"""

        self.conf[name] = value

        return self

    def export(self) -> dict:
        """Build the module definition for the package to load"""

        return {
            "name": f"{f_consts.svc_name}.{self.name}",
            "modconf": self.conf,
            "storm": self.load_storm()
        }
