"""Definitions for the package commands and modules, which will be made available in the Storm service."""

import fileparser.pkg.cmd as f_cmd
import fileparser.pkg.module as f_module

def get_commands() -> list[f_cmd.StormCommand]:
    forms = [
        "file:bytes",
    ]

    parse_cmd = f_cmd.StormCommand("parse", "Parse a file", "cmd_parse.storm", input_forms=forms, output_forms=forms)
    parse_cmd.add_default_args()
    return [parse_cmd]

def get_modules() -> list[f_module.StormModule]:
    return [
        f_module.StormModule("dmon", "mod_dmon.storm"),
        f_module.StormModule("evt", "mod_evt.storm"),
        f_module.StormModule("migrate", "mod_migrate.storm"),
    ]