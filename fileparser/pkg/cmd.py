import fileparser.consts as f_consts
import fileparser.pkg.loader as f_loader

class StormCommand(f_loader.StormLoader):
    """Definition of a Storm service package command"""

    def __init__(self, name: str, desc: str, code_file: str, input_forms: list[str] = [], output_forms: list[str] = []):
        super().__init__([code_file])

        self.name = name
        self.desc = desc
        self.input_forms = input_forms
        self.output_forms = output_forms

        self.conf = {"srcguid": f_consts.svc_guid}

        self.args = []
    
    def add_arg(self, name: str, options: dict):
        """Add an arg for the command. options follows a similar structure to argparse"""

        self.args.append((name, options))

    def add_conf(self, name: str, value: str):
        """Add a static configuration option for the command"""

        self.conf[name] = value

    async def export(self) -> dict:
        """Build the command definition for the package to load"""

        return {
            "name": f"{f_consts.svc_name}.{self.name}",
            "descr": self.desc,
            "cmdargs": self.args,
            "cmdconf": self.conf,
            "forms": {"input": self.input_forms, "output": self.output_forms},
            "storm": await self.load_storm()
        }