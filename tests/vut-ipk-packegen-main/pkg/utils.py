import sys
import typing


def error(msg: str) -> typing.NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)
