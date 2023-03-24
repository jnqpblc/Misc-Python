import sys
if len(sys.argv) < 2:
    sys.exit('\nUsage: %s {file_of_spns_from_ad}' % sys.argv[0])

spns_file = sys.argv[1]

import os
from multiprocessing import Pool

def do_work(work_data):
    host = work_data.split(":")[0]
    port = work_data.split(":")[1]
    print("[*] Running nmap +brute on ms-sql://%s:%s" % (host, port))
    nmap_brute = "nmap -Pn -sT -p %s --open --script +ms-sql-* --script-args unpwdb.timelimit=0 -oN - %s > pym-nmap-mssql-brute-output-%s-%s.nmap 2>&1" % (port, host, host, port)
    os.system(nmap_brute)

def pool_handler():
    target_list = []

    with open(spns_file) as f:
        for line in f:
            target_list.append(line.strip())

    p = Pool()
    p.map(do_work, target_list)


if __name__ == '__main__':
    pool_handler()
