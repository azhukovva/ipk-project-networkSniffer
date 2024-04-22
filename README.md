## Network Packet Sniffer
### 🎪 Introduction
A simple network packet sniffer implemented in C using the pcap library. The program allows users to capture and analyze network traffic on a specified interface, with options to filter packets based on protocols, ports, etc.

### 🥵 Features
- Capture network packets on a specified interface
- Filter packets based on various protocols (TCP, UDP, ICMP, ARP, etc.)
- Filter packets based on source and destination ports
- Print detailed information about captured packets, including timestamps, MAC addresses, IP addresses, ports, etc

### 😇 Prerequisites
- libpcap installed

### 🤹 Usage
This project can be compiled using Makefile:
```bash
make
```
```bash
./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```
if only `-i/--interface` is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed.

### 🛠️ Options 
`-i`, `--interface` <interface>: Specify the network interface to sniff on
`-p`, `--port` <port>: Filter packets based on the specified port
`--tcp`, `--udp` `--arp`, `--icmp4`, `--icmp6`: Enable filtering for specific protocols
`-n` <number>: Specify the number of packets to capture

### 💅 Testing 
The program was tested using python tester that can generate packets of various types and send it over the network (see folder "tests").