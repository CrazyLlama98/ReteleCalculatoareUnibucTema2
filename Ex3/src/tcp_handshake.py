from scapy.all import *
import struct

ip = IP()
ip.src = '198.13.0.15'
ip.dst = '198.13.0.14'

## Set DSCP and ECN
ip.tos = int('011110' + '11', 2)


tcp = TCP()
tcp.sport = 54321
tcp.dport = 11000


## SYN ##
tcp.seq = 100
tcp.flags = 'S' # flag de SYN
raspuns_syn_ack = sr1(ip/tcp)

tcp.seq += 1
tcp.ack = raspuns_syn_ack.seq + 1
tcp.flags = 'A'
ACK = ip / tcp

send(ACK)

## Set MSS to 2
optiune_MSS = 'MSS'
opt_index = TCPOptions[1][optiune_MSS]
opt_format = TCPOptions[0][opt_index]
val_MSS = struct.pack(opt_format[1], 2)
tcp.options = [(optiune_MSS, val_MSS)]

## Set TCP Flags ECE, CWR

for ch in "ABC":
    tcp.flags = 'PAEC'
    tcp.ack = raspuns_syn_ack.seq + 1
    rcv = sr1(ip/tcp/ch)
    print rcv
    tcp.seq += 1

tcp.flags = 'PAEC'
tcp.ack = raspuns_syn_ack.seq + 1
rcv = sr1(ip/tcp/"ABC")
print rcv
tcp.seq += 1

tcp.flags = 'R'
tcp.ack = raspuns_syn_ack.seq + 1
send(ip/tcp)
tcp.seq += 1