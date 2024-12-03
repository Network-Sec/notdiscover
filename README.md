## notdiscover
netdiscover clone in python for windows. 

## install
```powershell
$ pip3 install scapy
```

## run
```powershell
$ python3 .\notdiscover.py -r 192.168.2.0/24 -i 7

python3 .\notdiscover.py -r 192.168.2.0/24 -i 7
Scanning network: 192.168.2.0/24
IP Address              MAC Address
-----------------------------------------
192.168.2.2             04:23:1a:23:4b:26
192.168.2.9             23:5a:23:2b:23:ac
192.168.2.17            bc:23:11:23:b6:23
192.168.2.101           e0:28:23:93:23:88

$ python3 .\notdiscover.py -l
Available Interfaces:
Source   Index  Name                                         MAC                    IPv4             IPv6
libpcap  1      Software Loopback Interface 1                00:00:00:00:00:00      127.0.0.1        ::1
libpcap  11     Bluetooth Device (Personal Area Network) #2  8c:23:2b:23:23:23      123.223.123.23
libpcap  14     WAN Miniport (Network Monitor)
libpcap  17     VirtualBox Host-Only Ethernet Adapter        23:00:23:00:00:23      123.123.23.1
libpcap  21     WAN Miniport (IPv6)
libpcap  27     Intel(R) Ethernet Controller (3) 2323-V      ASUSTekCOMPU:23:4b:23  169.223.23.123
libpcap  4      Realtek USB GbE Family Controller            RealtekSemic:23:23:23  123.223.123.123
libpcap  57     Hyper-V Virtual Ethernet Adapter             Microsoft:23:0d:23     172.23.123.1
libpcap  63     WireGuard Tunnel                                                    10.23.0.23
libpcap  7      Intel(R) Ethernet Controller (3) 2323-V #2   ASUSTekCOMPU:03:4b:26  192.123.23.2
libpcap  9      WAN Miniport (IP)
``` 

## Dev
- Little speed & realtime output update by chunking larger ranges
