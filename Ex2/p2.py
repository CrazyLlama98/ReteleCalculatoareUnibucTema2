from scapy.all import Ether
from scapy.all import ARP
from scapy.all import srp

answered, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff") / ARP(pdst = '198.13.13.0/16'), timeout=2)
answered.summary(lambda (s,r): r.sprintf("%psrc% -- %hwsrc%"))