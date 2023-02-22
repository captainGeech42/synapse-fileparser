from typing import Literal

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
    
    def add_flag(self, flag: str, help: str):
        """Add a flag to the command"""

        self.args.append((flag, {"default": False, "action": "store_true", "help": help}))

        return self
    
    def add_arg(self, name: str, arg_type: Literal['int', 'str', 'bool'], help: str, default = None):
        """Add an argument to the command. If $name starts with `--`, arg is a flag, otherwise it's a positional arg."""

        opts = {"help": help, "type": arg_type}
        if default is not None:
            opts["default"] = default

        self.args.append((name, opts))

        return self

    def add_default_args(self):
        """Add default args to the command (--debug and --yield)"""

        self.add_flag("--debug", "Show verbose debug output.")
        self.add_flag("--yield", "Yield the newly created nodes.")

        return self

    def add_conf(self, name: str, value: str):
        """Add a static configuration option for the command"""

        self.conf[name] = value

        return self

    def export(self) -> dict:
        """Build the command definition for the package to load"""

        return {
            "name": f"{f_consts.svc_name}.{self.name}",
            "descr": self.desc,
            "cmdargs": self.args,
            "cmdconf": self.conf,
            "forms": {"input": self.input_forms, "output": self.output_forms},
            "storm": self.load_storm()
        }