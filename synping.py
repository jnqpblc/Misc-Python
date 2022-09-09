#!/usr/bin/python
import sys
if len(sys.argv) < 2:
    sys.exit('\nUsage: %s {dst_ip} {dst_port}\n' % sys.argv[0])

import socket, random
from scapy.all import *

def get_src_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("1.1.1.1", 80))
  return s.getsockname()[0]

src = get_src_ip()
dst = sys.argv[1]
dport = int(sys.argv[2])
sport = random.randint(1024,65535)
seq = random.randint(1000000000,4000000000)

syn_packet=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='S',seq=seq, window=512)
resp = sr1(syn_packet, verbose=False, retry=0, timeout=1)
if resp is not None:
  print(resp.sprintf("len=%IP.len% ip=%IP.src% ttl=%IP.ttl% %IP.frag% id=%IP.id% sport=" + str(dport) + " flags=%TCP.flags% seq=%TCP.seq% win=%TCP.window%"))
