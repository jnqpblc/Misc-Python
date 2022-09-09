#!/usr/bin/python
# grep '\/tcp' /usr/share/nmap/nmap-services |grep -v '0.000000' |awk '{print $2}' |cut -d'/' -f1 |tr '\n' ',' |sed 's/,$//g;' > nmap-top-ports.csv
# sudo python3 cautious_tcp_port_scanner.py 0 targets.txt nmap-top-ports.csv |tee cautious_tcp_port_scanner.log
# grep 'flags=SA' cautious_tcp_port_scanner.log

import sys
if len(sys.argv) < 4:
    sys.exit('\nUsage: %s {time_delay_between_ports|10|1|0.3} {targets_file} {ports_file_csv}\n' % sys.argv[0])

import socket, random, time
from scapy.all import *
from netaddr import *
from datetime import datetime

def get_src_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("1.1.1.1", 80))
  return s.getsockname()[0]

src_ip = get_src_ip()
delay = float(sys.argv[1])
targets_file = open(sys.argv[2], "r")
ports_option = open(sys.argv[3], "r")
ports = ports_option.read().split(',')
src_port = random.randint(1024,65535)
seq = random.randint(1000000000,4000000000)

targets_array = []

for targets_line in targets_file:
  for ip in IPNetwork(targets_line):
    for port in ports:
      targets_array.append("%s:%s" % (ip, port))

random.shuffle(targets_array)

for line in targets_array:
  dst_ip = str(line.split(':')[0])
  dst_port = int(line.split(':')[1])
  syn_packet=IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq, window=512)
  resp = sr1(syn_packet, verbose=False, retry=0, timeout=1)
  now = datetime.now()
  current_time = now.strftime("%H:%M:%S")
  if resp is not None:
    print(resp.sprintf("len=%IP.len% ip=%IP.src% ttl=%IP.ttl% %IP.frag% id=%IP.id% sport=" + str(dst_port) + " flags=%TCP.flags% seq=%TCP.seq% win=%TCP.window% time=" + current_time))
  time.sleep(delay)
