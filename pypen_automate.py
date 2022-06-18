import sqlite3, os, sys
banner = """
                    ,-.----.
                    \    /  \                                ,---,                        ___                       ____                ___ 
,-.----.            |   :    \                              '  .' \                     ,--.'|_                   ,'  , `.            ,--.'|_ 
\    /  \           |   |  .\ :             ,---,          /  ;    '.             ,--,  |  | :,'   ,---.       ,-+-,.' _ |            |  | :,' 
|   :    |          .   :  |: |         ,-+-. /  |        :  :       \          ,'_ /|  :  : ' :  '   ,'\   ,-+-. ;   , ||            :  : ' : 
|   | .\ :     .--, |   |   \ : ,---.  ,--.'|'   |        :  |   /\   \    .--. |  | :.;__,'  /  /   /   | ,--.'|'   |  || ,--.--.  .;__,'  /     ,---. 
.   : |: |   /_ ./| |   : .   //     \|   |  ,"' |        |  :  ' ;.   : ,'_ /| :  . ||  |   |  .   ; ,. :|   |  ,', |  |,/       \ |  |   |     /     \ 
|   |  \ :, ' , ' : ;   | |`-'/    /  |   | /  | |        |  |  ;/  \   \|  ' | |  . .:__,'| :  '   | |: :|   | /  | |--'.--.  .-. |:__,'| :    /    /  | 
|   : .  /___/ \: | |   | ;  .    ' / |   | |  | |        '  :  | \  \ ,'|  | ' |  | |  '  : |__'   | .; :|   : |  | ,    \__\/: . .  '  : |__ .    ' / | 
:     |`-'.  \  ' | :   ' |  '   ;   /|   | |  |/         |  |  '  '--'  :  | : ;  ; |  |  | '.'|   :    ||   : |  |/     ," .--.; |  |  | '.'|'   ;   /| 
:   : :    \  ;   : :   : :  '   |  / |   | |--'          |  :  :        '  :  `--'   \ ;  :    ;\   \  / |   | |`-'     /  /  ,.  |  ;  :    ;'   |  / | 
|   | :     \  \  ; |   | :  |   :    |   |/              |  | ,'        :  ,      .-./ |  ,   /  `----'  |   ;/        ;  :   .'   \ |  ,   / |   :    | 
`---'.|      :  \  \`---'.|   \   \  /'---'               `--''           `--`----'      ---`-'           '---'         |  ,     .-./  ---`-'   \   \  / 
  `---`       \  ' ;  `---`    `----'                                                                                    `--`---'                `----' 
               `--`
  by jnqpblc
"""
usage = "\n%s\nUsage: %s <option|setup|help|print|show {output_dir}|masscan {rate} {file_name}|nmapsvc {rate} {file_name}|dnsrecon {file_name}|pyweb|vulnscan|brute|iker {optional ip}|ikeforce {optional ip}>\n" % (banner, sys.argv[0])

if len(sys.argv) < 2:
  sys.exit(usage)

directory_name = "output"
sqlite_database_file = "scan.sqlite"
targets = []

def check_for_output_folder():
  if not os.path.exists(directory_name):
    os.makedirs(directory_name)

def check_for_database():
  if not os.path.exists(sqlite_database_file):
    sys.exit('\n[!] The scan.sqlite database does not exist. You need to run nmapsvc.\n')

def connect_to_database():
  conn = sqlite3.connect(sqlite_database_file)
  return conn.cursor()

check_for_output_folder()

if sys.argv[1] == "setup":
  print("\n[+] Running install commands...\n")
  os.system("sudo apt install masscan nmap whatweb nikto sqlmap dirb ike-scan sqlite3 python2.7-minimal python2-dev build-essential lua-sql-sqlite3 lua-sql-sqlite3-dev")
  with open('/etc/apt/sources.list') as f:
    if 'ubuntu' in f.read():
      os.system("wget http://ftp.us.debian.org/debian/pool/main/s/sqlmap/`curl -s http://ftp.us.debian.org/debian/pool/main/s/sqlmap/ |egrep -o 'sqlmap_[^\"]*all.deb' |sort -u |sort -t'_' -k2 -r |head`; sudo dpkg -i sqlmap_*_all.deb; rm -f sqlmap_*_all.deb")
  f.close()
  os.system("curl https://bootstrap.pypa.io/pip/get-pip.py --output get-pip3.py")
  os.system("curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip2.py")
  os.system("sudo python3 get-pip3.py; rm -f get-pip3.py")
  os.system("sudo python2.7 get-pip2.py; rm -f get-pip2.py")
  os.system("sudo pip2 install pyOpenSSL==17.2.0 pyip pyCrypto")
  os.system("sudo /usr/bin/python2.7 -m pip install --upgrade pip")
  os.system("sudo /usr/bin/python3 -m pip install --upgrade pip")
  os.system("sudo pip3 install --upgrade setuptools validators sslyze netifaces pyCrypto")
  file = open(sys.argv[0], "r")
  for line in file:
    if ("os.system" and "git ") in line:
      try:
        str = line.split('"')[3]
        if "--" in str:
          print(str)
          os.system("%s" % str)
      except:
        continue
    elif ("os.system" and "wget ") in line:
      try:
        str = line.split('"')[3]
        if "--" in str:
          print(str)
          os.system("%s" % str)
      except:
        continue
  sys.exit()

elif sys.argv[1] == "help":
  print("\n[+] %s Supported commands:\n" % sys.argv[0])
  file = open(sys.argv[0], "r")
  for line in file:
    if "sys.argv[1] == \"" in line:
      str = line.split('"')[1]
      if str:
        if str == "pyweb":
          print("    %s {cmd}" % str)
        elif str == "masscan":
          print("    %s {rate} {file_name|domain_name|ip_address}" % str)
        elif str == "nmapsvc":
          print("    %s {mode|masscan|nmap} {rate} {file_name} {ports}" % str)
        elif str == "add":
          print("    %s {ip} {port} {protocol|tcp|udp} {service|https|isakmp} {version|optional|apache|iis}" % str)
        elif str == "import":
          print("    %s {output/pya-masscan-output.xml}" % str)
        else:
          print("    %s" % str)
  os.system('python3 pyweb_automate.py help')
  sys.exit()

elif sys.argv[1] == "show":
  if len(sys.argv) < 3:
    sys.exit(usage)
  elif not os.path.exists(sys.argv[2]):
    sys.exit("\n[!] The supplied directory does not exist.\n")
  else:
    os.system("find %s \( -name \*.txt -o -name \*.nmap \) -exec cat {} \; | egrep -v 'FAILED:|ERROR:| Couldn.t |: false| Can.t |Host is up|^SF-|^SF:' | less -R" % sys.argv[2])
    sys.exit()

elif sys.argv[1] == "print":
  check_for_database()
  import subprocess
  schema = subprocess.run(['sqlite3', 'scan.sqlite', '.schema scandata'], capture_output=True)
  print(schema)
  c = connect_to_database()
  #for row in c.execute("SELECT DISTINCT * from scandata where state not like '%filtered';"):
  for row in c.execute("SELECT DISTINCT * from scandata;"):
    print(row)

elif sys.argv[1] == "add":
  if len(sys.argv) < 6:
    sys.exit('\nUsage: %s add {ip} (port) (protocol|tcp|udp) {service|https|isakmp} (version|optional|apache|iis}\n' % sys.argv[0])
  check_for_database()
  c = connect_to_database()
  # (hostname varchar(100), ip varchar(16), port integer(5), protocol varchar(3), state varchar(20), service varchar(100), version varchar(100));\n", stderr=b'')
  ip = sys.argv[2];
  port = int(sys.argv[3]);
  protocol = sys.argv[4];
  state = sys.argv[5];
  service = sys.argv[6];
  if len(sys.argv) < 8:
    c.execute("INSERT INTO scandata (hostname, ip, port, protocol, state, service, version) VALUES ('', \"%s\", %d, \"%s\", \"%s\", \"%s\", '');" % (ip, port, protocol, state, service))
  else:
    version = sys.argv[7];
    c.execute("INSERT INTO scandata (hostname, ip, port, protocol, state, service, version) VALUES ('', \"%s\", %d, \"%s\", \"%s\", \"%s\", \"%s\");" % (ip, port, protocol, state, service, version))

elif sys.argv[1] == "import":
  if len(sys.argv) < 6:
    sys.exit('\nUsage: %s import {output/pya-masscan-output.xml}\n' % sys.argv[0])
  check_for_database()
  c = connect_to_database()
  file = open(sys.argv[0], "r")
  for line in file:
    if "addr" in line:
      ip = line.split('"')[3]
      port = line.split('"')[9]
      protocol = line.split('"')[7]
      state = line.split('"')[11]
      c.execute("INSERT INTO scandata (hostname, ip, port, protocol, state, service, version) VALUES ('', \"%s\", %d, \"%s\", \"%s\", '', '');" % (ip, port, protocol, state))

elif sys.argv[1] == "clean":
  if len(sys.argv) < 3:
    sys.exit('\nUsage: %s clean {option|all|udp}\n' % sys.argv[0])
  check_for_database()
  c = connect_to_database()
  if sys.argv[2] == "all":
    remove_all_entries_cmd="sqlite3 %s \"DELETE FROM scandata;\"" % (sqlite_database_file)
    os.system(remove_all_entries_cmd)
  elif sys.argv[2] == "udp":
    remove_filtered_udp_cmd="sqlite3 %s \"DELETE FROM scandata WHERE protocol = 'udp' AND state like '%%filtered';\"" % (sqlite_database_file)
    os.system(remove_filtered_udp_cmd)
  else:
    sys.exit('[!] The supplied option failed!')

elif sys.argv[1] == "masscan":
  if len(sys.argv) < 4:
    sys.exit('\nUsage: %s masscan {rate} {file_name|domain_name|ip_address}\n' % sys.argv[0])
  masscan_cmd = ''
  masscan_xml_cmd = ''
  scan_rate = sys.argv[2]
  targets_option = sys.argv[3]
  import validators, time
  filestamp = time.strftime("%Y%m%d-%H%M%S")
  if os.path.exists(targets_option):
    targets = open(targets_option, "r")
    masscan_cmd = "sudo masscan -iL %s -p T:0-65535 --rate %s --banners -oB %s/pya-masscan-output-%s.bin --interface eth0 | tee %s/pya-masscan-output-%s.txt" % (targets_option, scan_rate, directory_name, filestamp, directory_name, filestamp)
    os.system(masscan_cmd)
    masscan_xml_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin -oX %s/pya-masscan-output-%s.xml" % (directory_name, filestamp, directory_name, filestamp)
    os.system(masscan_xml_cmd)
    masscan_txt_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin > %s/pya-masscan-output-%s.txt" % (directory_name, filestamp, directory_name, filestamp)
    os.system(masscan_txt_cmd)
  elif validators.ip_address.ipv4(targets_option):
    targets.append(targets_option)
    masscan_cmd = "sudo masscan -p T:0-65535 --rate %s --banners -oB %s/pya-masscan-output-%s.bin --interface eth0 %s | tee %s/pya-masscan-ipv4-%s-output.txt" % (scan_rate, directory_name, targets, targets, directory_name, targets)
    masscan_txt_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin > %s/pya-masscan-ipv4-%s-output.txt" % (directory_name, targets, directory_name, targets)
    masscan_xml_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin -oX %s/pya-masscan-ipv4-%s-output.xml" % (directory_name, targets, directory_name, targets)
  elif validators.ip_address.ipv6(targets_option):
    targets.append(targets_option)
    masscan_cmd = "sudo masscan -p T:0-65535 --rate 1000 --banners -oB %s/pya-masscan-output-%s.bin --interface eth0 %s | tee %s/pya-masscan-ipv6-%s-output.txt" % (directory_name, targets, targets, directory_name, targets)
    masscan_txt_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin > %s/pya-masscan-ipv6-%s-output.txt" % (directory_name, targets, directory_name, targets)
    masscan_xml_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin -oX %s/pya-masscan-ipv6-%s-output.xml" % (directory_name, targets, directory_name, targets)
  elif validators.domain(targets_option):
    targets.append(targets_option)
    masscan_cmd = "sudo masscan -p T:0-65535 --rate 1000 --banners -oB %s/pya-masscan-output-%s.bin --interface eth0 %s | tee %s/pya-masscan-fqdn-%s-output.txt" % (directory_name, targets, targets, directory_name, targets)
    masscan_txt_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin > %s/pya-masscan-fqdn-%s-output.txt" % (directory_name, targets, directory_name, targets)
    masscan_xml_cmd = "masscan --open --banners --readscan %s/pya-masscan-output-%s.bin -oX %s/pya-masscan-fqdn-%s-output.xml" % (directory_name, targets, directory_name, targets)
  else:
    sys.exit('\n[!] You did not supply a valid targets option or the file does not exist.\n')

elif sys.argv[1] == "nmapsvc":
  if len(sys.argv) < 3:
    sys.exit('\nUsage: %s nmapsvc {mode|masscan|nmap} {rate} {file_name} {ports}\n' % sys.argv[0])
  scan_mode = sys.argv[2]
  min_rate = sys.argv[3]
  targets_file = sys.argv[4]
  if not os.path.exists(targets_file):
    sys.exit('\n[!] The file of IP Addresses to target does not exist.\n')
  if not os.path.exists("sqlite-output.nse"): os.system("wget --quiet https://raw.githubusercontent.com/exitnode/nmap-sqlite-output/master/sqlite-output.nse")
  if scan_mode == "masscan":
    nmapsvc_tcp_cmd = "sudo nmap -Pn -n -sSV -p $(cat %s |awk '{print $4}' |cut -d'/' -f1 |sort -un |tr '\n' ',' |sed 's/,$//g;') --open --version-intensity 3 --min-parallelism 32 $(cat %s |awk '{print $6}' |sort -u |tr '\n' ' ') --min-rate %s --script sqlite-output --script-args dbname=%s,dbtable=scandata -oA %s/pya-nmap-tcp-output" % (targets_file, targets_file, min_rate, sqlite_database_file, directory_name)
    os.system(nmapsvc_tcp_cmd)
  else:
    ports = sys.argv[5]
    print("\n\n[*] Running an nmapsvc version scan on all entries in %s" % (targets_file))
    nmapsvc_tcp_cmd = "sudo nmap -Pn -n -sSV -p %s --open --version-intensity 3 --min-parallelism 32 -iL %s --min-rate %s --script sqlite-output --script-args dbname=%s,dbtable=scandata -oA %s/pya-nmap-tcp-output" % (ports, targets_file, min_rate, sqlite_database_file, directory_name)
    os.system(nmapsvc_tcp_cmd)
    nmapsvc_udp_cmd = "sudo nmap -Pn -n -sU --top-ports 30 --open --version-intensity 3 --min-parallelism 32 -iL %s --min-rate %s --script sqlite-output --script-args dbname=%s,dbtable=scandata -oA %s/pya-nmap-udp-output" % (targets_file, min_rate, sqlite_database_file, directory_name)
    os.system(nmapsvc_udp_cmd)
    remove_filtered_udp_cmd="sqlite3 %s \"DELETE FROM scandata WHERE protocol = 'udp' AND state like '%%filtered';\"" % (sqlite_database_file)
    os.system(remove_filtered_udp_cmd)

elif sys.argv[1] == "dnsrecon":
  if len(sys.argv) < 3:
    sys.exit('\nUsage: %s dnsrecon {file_name}\n' % sys.argv[0])
  targets_file = sys.argv[2]
  if not os.path.exists(targets_file):
    sys.exit('\n[!] The file of IP Ranges or CIDRs to target does not exist.\n')
  dnsrecon_cmd = "for net in `cat %s`; do dnsrecon -t rvl -r $net; done | tee %s/pya-dnsrecon-output-rvl.txt" % (targets_file, directory_name)
  os.system(dnsrecon_cmd)


elif sys.argv[1] == "pyweb":

  #dnsrecon_file = "%s/pya-dnsrecon-output-rvl.txt" % (directory_name)
  #if not os.path.exists(dnsrecon_file):
  #  sys.exit('\n[!] The dnsrecon output file does not exist. You need to run dnsrecon.\n')
  #dnsrecon_cmd = "for host in `grep PTR %s |awk '{print $3}' |sort -u`; do python3 pyweb_automate.py auto https 443 $host /; done" % (dnsrecon_file)
  #os.system(dnsrecon_cmd)

  pyweb_command = sys.argv[2]
  if pyweb_command == "tomcat" or pyweb_command == "nse" or pyweb_command == "brute":
    check_for_database()
    c = connect_to_database()

    for row in c.execute("SELECT DISTINCT ip FROM scandata WHERE protocol = 'tcp';"):
      host_address = row[0]
      service_ports = ''

      for port in c.execute("SELECT DISTINCT port FROM scandata WHERE protocol = 'tcp' AND ip = '%s';" % host_address):
        service_ports = service_ports + str(port[0]) + ","
      service_ports = service_ports[:-1]

      print("\n\n[*] Running %s on nmap://%s:%s\n" % (pyweb_command, host_address, service_ports))
      nmap_pyweb_cmd = "python3 pyweb_automate.py %s nse %s %s" % (pyweb_command, service_ports, host_address)
      print(nmap_pyweb_cmd)

  #elif pyweb_command == "whatweb" or pyweb_command == "nikto" or pyweb_command == "wpscan" or pyweb_command == "sqlmap_crawl" or pyweb_command == "sqlmap_forms" or pyweb_command == "wascan" or pyweb_command == "jexboss" or pyweb_command == "struts_pwn" or pyweb_command == "jetleak" or pyweb_command == "dirb" or pyweb_command == "sslyze":
  else:
    check_for_database()
    c = connect_to_database()

    # pyweb_automate scans for non-encrypted webservers (HTTP).
    for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND (service = 'http' OR service = 'www' OR service = 'http-proxy')"):
      host_address = row[1]
      service_port = row[2]
      service_proto = row[5]

      print("\n\n[*] Running %s on %s://%s:%s\n" % (pyweb_command, service_proto, host_address, service_port))
      http_pyweb_cmd = "python3 pyweb_automate.py %s http %s %s" % (pyweb_command, service_port, host_address)
      os.system(http_pyweb_cmd)

    # pyweb_automate scans for encrypted webservers (SSL/TLS).
    for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND (service LIKE '%https%' OR service LIKE '%ssl%')"):
      host_address = row[1]
      service_port = row[2]
      service_proto = row[5]

      print("\n\n[*] Running %s on %s://%s:%s\n" % (pyweb_command, service_proto, host_address, service_port))
      https_pyweb_cmd = "python3 pyweb_automate.py %s https %s %s" % (pyweb_command, service_port, host_address) 
      os.system(https_pyweb_cmd)


elif sys.argv[1] == "vulnscan":
  check_for_database()
  c = connect_to_database()

  # All scans for non-encrypted webservers (HTTP).
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND (service = 'http' OR service = 'www' OR service = 'http-proxy')"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running whatweb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_whatweb_cmd = "whatweb -a 3 --no-errors http://%s:%s/ | tee %s/pya-whatweb-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_whatweb_cmd)

    print("\n\n[*] Running nikto on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_nikto_cmd = "nikto -timeout 2 -nossl -host http://%s:%s/ -Save . -F xml -output %s/pya-nikto-output-%s-%s-http.xml | tee %s/pya-nikto-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port, directory_name, host_address, service_port)
    os.system(http_nikto_cmd)

    # if using ubuntu, since the repo vrsion is old.
    # wget http://ftp.us.debian.org/debian/pool/main/s/sqlmap/sqlmap_1.5.2-1_all.deb
    # sudo dpkg -i sqlmap_1.5.2-1_all.deb
    # wget http://ftp.us.debian.org/debian/pool/main/s/sqlmap/`curl -s http://ftp.us.debian.org/debian/pool/main/s/sqlmap/ |egrep -o 'sqlmap_[^"]*all.deb' |sort -u |sort -t'_' -k2 -r |head`

    print("\n\n[*] Running sqlmap_crawl on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_sqlmap_crawl_cmd = "sqlmap --random-agent --batch --smart --crawl=4 --threads=3 --level=4 --risk=2 -u http://%s:%s/ | tee %s/pya-sqlmap-crawl-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_sqlmap_crawl_cmd)

    print("\n\n[*] Running sqlmap_forms on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_sqlmap_forms_cmd = "sqlmap --random-agent --batch --smart --crawl=4  --forms --threads=3 --level=4 --risk=2 -u http://%s:%s/ | tee %s/pya-sqlmap-forms-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_sqlmap_forms_cmd)

    if not os.path.exists("tomcat-scan.nse"): os.system("wget --quiet https://raw.githubusercontent.com/sensepost/autoDANE/master/software/tomcat_check/tomcat-scan.nse")
    print("\n\n[*] Running tomcat-scan.nse on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_tomcat_cmd = "nmap -Pn -n -sT -T4 -p %s --script ./tomcat-scan.nse -oA %s/pya-tomcat-scan-output-%s-%s-http %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(http_tomcat_cmd)

    if not os.path.exists("jexboss-joaomatosf"): os.system("git clone --quiet https://github.com/joaomatosf/jexboss jexboss-joaomatosf")
    print("\n\n[*] Running jexboss on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jexboss_cmd = "python3 jexboss-joaomatosf/jexboss.py -u http://%s:%s > %s/pya-jexboss-output-%s-%s-http.txt 2>&1" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jexboss_cmd)

    if not os.path.exists("struts-pwn"): os.system("git clone --quiet https://github.com/mazen160/struts-pwn struts-pwn")
    print("\n\n[*] Running struts-pwn on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_struts_cmd = "python3 struts-pwn/struts-pwn.py --check --url http://%s:%s/ 2>/dev/null | tee %s/pya-struts-pwn-output-%s-%s-http.txt"  % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_struts_cmd)

    print("\n\n[*] Running dirb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_dirb_cmd = "dirb http://%s:%s/ /usr/share/dirb/wordlists/common.txt -o %s/pya-dirb-output-%s-%s-http.txt -r" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_dirb_cmd)

  # All scans for encrypted webservers (SSL/TLS).
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND (service LIKE '%https%' OR service LIKE '%ssl%')"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running whatweb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_whatweb_cmd = "whatweb -a 3 --no-errors https://%s:%s/ | tee %s/pya-whatweb-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_whatweb_cmd)

    print("\n\n[*] Running nikto on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_nikto_cmd = "nikto -timeout 2 -nossl -host https://%s:%s/ -Save . -F xml -output %s/pya-nikto-output-%s-%s-https.xml | tee %s/pya-nikto-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port, directory_name, host_address, service_port)
    os.system(http_nikto_cmd)

    print("\n\n[*] Running sqlmap_crawl on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_sqlmap_crawl_cmd = "sqlmap --random-agent --batch --smart --crawl=4 --threads=3 --level=4 --risk=2 -u https://%s:%s/ | tee %s/pya-sqlmap-crawl-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_sqlmap_crawl_cmd)

    print("\n\n[*] Running sqlmap_forms on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_sqlmap_forms_cmd = "sqlmap --random-agent --batch --smart --crawl=4  --forms --threads=3 --level=4 --risk=2 -u https://%s:%s/ | tee %s/pya-sqlmap-forms-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_sqlmap_forms_cmd)

    if not os.path.exists("tomcat-scan.nse"): os.system("wget --quiet https://raw.githubusercontent.com/sensepost/autoDANE/master/software/tomcat_check/tomcat-scan.nse")
    print("\n\n[*] Running tomcat-scan.nse on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_tomcat_cmd = "nmap -Pn -n -sT -T4 -p %s --script ./tomcat-scan.nse -oA %s/pya-tomcat-scan-output-%s-%s-https %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(http_tomcat_cmd)

    if not os.path.exists("jexboss-joaomatosf"): os.system("git clone --quiet https://github.com/joaomatosf/jexboss jexboss-joaomatosf")
    print("\n\n[*] Running jexboss on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jexboss_cmd = "python3 jexboss-joaomatosf/jexboss.py -u https://%s:%s > %s/pya-jexboss-output-%s-%s-https.txt 2>&1" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jexboss_cmd)

    if not os.path.exists("struts-pwn"): os.system("git clone --quiet https://github.com/mazen160/struts-pwn struts-pwn")
    print("\n\n[*] Running struts-pwn on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_struts_cmd = "python3 struts-pwn/struts-pwn.py --check --url https://%s:%s/ 2>/dev/null | tee %s/pya-struts-pwn-output-%s-%s-https.txt"  % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_struts_cmd)

    print("\n\n[*] Running dirb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_dirb_cmd = "dirb https://%s:%s/ /usr/share/dirb/wordlists/common.txt -o %s/pya-dirb-output-%s-%s-https.txt -r" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_dirb_cmd)

  # Jetty specific scan.
  query = '%jetty%'
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    if not os.path.exists("jetleak-testing-script-gdssecurity"): os.system("git clone --quiet https://github.com/GDSSecurity/Jetleak-Testing-Script jetleak-testing-script-gdssecurity")
    print("\n\n[*] Running jetleak on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jetleak_cmd = "python3 jetleak-testing-script-gdssecurity/jetleak_tester.py http://%s %s | tee %s/pya-jetleak-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jetleak_cmd)

  # All scans for only TCP specific stuff.
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp'"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    #if not os.path.exists("sslyze-nabla-c0d3"): os.system("git clone --quiet https://github.com/nabla-c0d3/sslyze.git sslyze-nabla-c0d3 && sudo pip3 install --upgrade sslyze")
    print("\n\n[*] Running sslyze on %s://%s:%s\n" % (service_proto, host_address, service_port))
    tcp_sslyze_cmd = "python3 -m sslyze --regular %s:%s > %s/pya-sslyze-output-%s-%s.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(tcp_sslyze_cmd)

    print("\n\n[*] Running nmapnse on %s://%s:%s\n" % (service_proto, host_address, service_port))
    tcp_nmapnse_cmd = "nmap -n -Pn -sTV -p %s --script default,vuln,auth,intrusive,brute --script-args 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)' --open -oA %s/pya-nmap-nse-output-%s-%s-tcp %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(tcp_nmapnse_cmd)

  # All scans for only UDP specific stuff.
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'udp' AND state not like '%filtered';"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmapnse on %s://%s:%s\n" % (service_proto, host_address, service_port))
    udp_nmapnse_cmd = "nmap -n -Pn -sUV -p %s --script default,vuln,auth,intrusive,brute --script-args 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)' --open -oA %s/pya-nmap-nse-output-%s-%s-udp %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(udp_nmapnse_cmd)

elif sys.argv[1] == "brute":
  check_for_database()
  c = connect_to_database()
  if not os.path.exists("unix_users.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_users.txt")
  if not os.path.exists("unix_passwords.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_passwords.txt")
  query = '%ssh%'
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmap.ssh-brute on %s://%s:%s\n" % (service_proto, host_address, service_port))
    nmap_ssh_brute = "nmap -p %s --script ssh-brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt --script-args ssh-brute.timeout=4s -oA %s/pya-nmap-ssh-brute-output-%s-%s-ssh %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(nmap_ssh_brute)

  query = '%ftp%'
  for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmap.ftp-brute on %s://%s:%s\n" % (service_proto, host_address, service_port))
    nmap_ssh_brute = "nmap -p %s --script ftp-brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt --script-args ftp-brute.timeout=4s -oA %s/pya-nmap-ftp-brute-output-%s-%s-ftp %s" % (service_port, host_address, service_port, host_address)
    os.system(nmap_ftp_brute)

elif sys.argv[1] == "brute-all":
  check_for_database()
  c = connect_to_database()
  if not os.path.exists("unix_users.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_users.txt")
  if not os.path.exists("unix_passwords.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_passwords.txt")
  for row in c.execute("SELECT DISTINCT * FROM scandata;"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmap +brute on %s://%s:%s\n" % (service_proto, host_address, service_port))
    nmap_brute = "nmap -p %s --script brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt -oA %s/pya-nmap-brute-output-%s-%s-%s %s" % (service_port, directory_name, host_address, service_port, service_proto, host_address)
    os.system(nmap_brute)

elif sys.argv[1] == "iker":
  #if not os.path.exists("iker.py"): os.system("wget --quiet https://raw.githubusercontent.com/jnqpblc/metasploit-db_automate/master/iker.py")
  if not os.path.exists("iker.py"): os.system("curl -sk https://labs.portcullis.co.uk/download/iker_v1.1.tar |tar --extract")
  if not os.path.exists("ikeforce-spiderlabs"): os.system("git clone --quiet https://github.com/SpiderLabs/ikeforce.git ikeforce-spiderlabs")

  if len(sys.argv) == 2:
    check_for_database()
    c = connect_to_database()
    for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'udp' AND service = 'isakmp' AND state not like '%filtered';"):
      host_address = row[1]
      service_port = row[2]
      service_proto = row[5]

      print("\n\n[*] Running iker.py on %s://%s:%s\n" % (service_proto, host_address, service_port))
      iker_cmd = "sudo python2.7 iker.py --clientids ikeforce-spiderlabs/wordlists/groupnames.dic --output %s/pya-iker-output-%s-%s-%s.txt %s" % (directory_name, host_address, service_port, service_proto, host_address)
      os.system(iker_cmd)
  else:
    host_address = sys.argv[2]
    service_port = "500"
    service_proto = "isakmp"

    print("\n\n[*] Running iker.py on %s://%s:%s\n" % (service_proto, host_address, service_port))
    iker_cmd = "sudo python2.7 iker.py --clientids ikeforce-spiderlabs/wordlists/groupnames.dic --output %s/pya-iker-output-%s-%s-%s.txt %s" % (directory_name, host_address, service_port, service_proto, host_address)
    os.system(iker_cmd)

elif sys.argv[1] == "ikeforce":
  if not os.path.exists("ikeforce-spiderlabs"): os.system("git clone --quiet https://github.com/SpiderLabs/ikeforce.git ikeforce-spiderlabs")
  if len(sys.argv) == 2:
    check_for_database()
    c = connect_to_database()
    for row in c.execute("SELECT DISTINCT * FROM scandata WHERE protocol = 'udp' AND service = 'isakmp' AND state not like '%filtered';"):
      host_address = row[1]
      service_port = row[2]
      service_proto = row[5]

      print("\n\n[*] Running ikeforce.py on %s://%s:%s\n" % (service_proto, host_address, service_port))
      ikeforce_cmd = "sudo python2.7 ikeforce-spiderlabs/ikeforce.py %s -a | tee %s/pya-ikeforce-output-%s-%s-%s.txt" % (host_address, directory_name, host_address, service_port, service_proto)
      os.system(ikeforce_cmd)
  else:
    host_address = sys.argv[2]
    service_port = "500"
    service_proto = "isakmp"

    print("\n\n[*] Running ikeforce.py on %s://%s:%s\n" % (service_proto, host_address, service_port))
    ikeforce_cmd = "sudo python2.7 ikeforce-spiderlabs/ikeforce.py %s -a | tee %s/pya-ikeforce-output-%s-%s-%s.txt" % (host_address, directory_name, host_address, service_port, service_proto)
    os.system(ikeforce_cmd)

else:
  sys.exit('[!] The supplied option failed!')
