from typing import Type

from fileparser.parsers.parser import FileParser, ParseEvent

def get_parsers() -> list[Type[FileParser]]:
    import fileparser.parsers.pe
    import fileparser.parsers.zip

    return [
        fileparser.parsers.pe.PeParser,
        fileparser.parsers.zip.ZipParser
    ]