from dataclasses import dataclass

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6MLReport
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP
from scapy.sendrecv import send, sr1
from scapy.contrib.igmp import IGMP
from scapy.all import Raw

from .utils import error


@dataclass
class Neighbour:
    host: str
    port: int
    timeout: int = 5

    def send_packet(self, mode, message=None, host=None, port=None):
        lmap = {"tcp": TCP, "udp": UDP}

        if message is None:
            message = f"Testing {mode} packet"
        try:
            if mode in {"tcp", "udp"}:
                pack = IP(dst=host or self.host) / lmap[mode](dport=port or self.port) / Raw(load=message)
                sr1(pack, timeout=self.timeout)
                return
            elif mode == "icmp4":
                packet = IP(dst=host or self.host) / ICMP() / message
            elif mode == "igmp":
                packet = IP(dst=host or self.host) / IGMP(type=0x16) / Raw(load=message)
            elif mode == "arp":
                packet = IP(dst=host or self.host) / ARP(pdst=host or self.host) / Raw(load=message)
            elif mode == "ndp":
                packet = IPv6(dst=host or self.host) / ICMPv6ND_NA(tgt=host or self.host, R=0) / message
            elif mode == "mld":
                packet = IPv6(dst=host or self.host) / ICMPv6MLReport() / message
            elif mode == "icmp6":
                packet = IPv6(dst=host or self.host) / ICMPv6EchoRequest() / message
            else:
                error(f"unknown mode {mode}")
                return
            send(packet)

        except Exception as e:
            error(f'Error: {e}')
