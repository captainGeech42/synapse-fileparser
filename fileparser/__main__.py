import asyncio
import sys

import fileparser.cell as f_cell

if __name__ == "__main__":
    sys.exit(asyncio.run(f_cell.FileparserCell.execmain(sys.argv[1:])))