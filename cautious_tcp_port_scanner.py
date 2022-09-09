#!/usr/bin/python
import sys
if len(sys.argv) < 4:
    sys.exit('\nUsage: %s {time_delay_between_ports} {dst_ip_or_net} {dst_ports_csv_str}\n' % sys.argv[0])

import socket, random, time
from scapy.all import *
from netaddr import *

def get_src_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("1.1.1.1", 80))
  return s.getsockname()[0]

src_ip = get_src_ip()
delay = int(sys.argv[1])
targets_option = sys.argv[2]
ports_option = sys.argv[3]
ports = ports_option.split(',')
src_port = random.randint(1024,65535)
seq = random.randint(1000000000,4000000000)

targets_array = []
for ip in IPNetwork(targets_option):
  for port in ports:
    targets_array.append("%s:%s" % (ip, port))

random.shuffle(targets_array)

for line in targets_array:
  dst_ip = str(line.split(':')[0])
  dst_port = int(line.split(':')[1])
  #print(dst_ip)
  #print(dst_port)
  syn_packet=IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags='S',seq=seq, window=512)
  resp = sr1(syn_packet, verbose=False)
  print(resp.sprintf("len=%IP.len% ip=%IP.src% ttl=%IP.ttl% %IP.frag% id=%IP.id% sport=" + str(dst_port) + " flags=%TCP.flags% seq=%TCP.seq% win=%TCP.window%"))
  time.sleep(delay)
