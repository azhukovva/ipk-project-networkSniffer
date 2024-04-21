# @author (xturyt00)
import typing

import time
import getopt
import signal
import sys

from pkg import Neighbour, error

LONG_OPTS = [
    "host=",
    "port=",
    "mode=",
    "timeout=",
    "help",
]

USAGE = """
Usage:
    python3 packegen.py [OPTIONS]

OPTIONS
--help\t\tshow this message
--host\t\tip address (can be IPv6 address)
--port\t\tport 
--mode\t\tpacket type (tcp|udp|icmp4|igmp|icmp6|arp|ndp|mld)
--timeout\tinterval between packets
"""

SHORT_OPTS = "h"


def sigint(*_):
    sys.exit(0)


def main():
    host = None
    port = None
    mode = None
    timeout = 3

    signal.signal(signal.SIGINT, sigint)

    opts: typing.Optional[list[tuple[str, str]]] = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], SHORT_OPTS, LONG_OPTS)
    except getopt.GetoptError as e:
        error(str(e))

    try:
        for opt, arg in opts:
            if opt == "--host":
                host = arg
            elif opt == "--port":
                port = int(arg)
            elif opt == "--mode":
                mode = arg
            elif opt == "--timeout":
                timeout = int(arg)
            elif opt in ("-h", "--help"):
                print(USAGE)
                sys.exit()
            else:
                error(f"unknown option {opt}. Use --help.")
    except ValueError as e:
        error(f"{e}. Use --help")

    nb = Neighbour(host, port, timeout)

    if mode is None or host is None:
        error("--mode or --host is not defined. Use --help")

    while True:
        nb.send_packet(mode)
        time.sleep(timeout)


if __name__ == "__main__":
    main()
