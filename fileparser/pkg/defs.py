"""Definitions for the package commands and modules, which will be made available in the Storm service."""

import fileparser.pkg.cmd as f_cmd
import fileparser.pkg.module as f_module
import fileparser.consts as f_consts

def get_commands() -> list[f_cmd.StormCommand]:
    forms = [
        "file:bytes",
    ]

    return [
        f_cmd.StormCommand("parse", "Parse a file", "cmd_parse.storm", input_forms=forms, output_forms=forms)
            .add_default_args(),
    ]

def get_modules() -> list[f_module.StormModule]:
    return [
        f_module.StormModule("dmon", "mod_dmon.storm")
            .add_conf("parseq", f_consts.svc_parseq),
        f_module.StormModule("evt", "mod_evt.storm")
            .add_conf("parseq", f_consts.svc_parseq),
    ]