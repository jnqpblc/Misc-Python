import sqlite3, os, sys
if len(sys.argv) < 2:
  print '''
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
  '''
  sys.exit('\nUsage: %s <option|print|nmapsvc {file_name}|vulnscan|brute|iker {optional ip}|ikeforce {optional ip}>\n' % sys.argv[0])

# apt-get install lua-sql-sqlite3

directory_name = "output"
sqlite_database_file = "scan.sqlite"

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

if sys.argv[1] == "print":
  check_for_database()
  c = connect_to_database()
  for row in c.execute("select * from scandata;"):
    print(row)

elif sys.argv[1] == "masscan":
  if len(sys.argv) < 3:
    sys.exit('\nUsage: %s masscan {file_name}\n' % sys.argv[0])
  targets_file = sys.argv[2]
  if not os.path.exists(targets_file):
    sys.exit('\n[!] The file of IP Addresses to target does not exist.\n')
  print("\n\n[*] Running a masscan portscan on all entires in %s" % (targets_file))
  masscan_cmd = "sudo masscan -iL %s -p T:0-65535 --rate 1000 --banners -oB %s/pya-masscan-output.bin --interface eth0 | tee %s/pya-masscan-output.txt" % (targets_file, directory_name)
  os.system(masscan_cmd)
  masscan_xml_cmd = "masscan --open --banners --readscan %s/pya-masscan-output.bin -oX %s/pya-masscan-output.xml"
  os.system(masscan_xml_cmd)

elif sys.argv[1] == "nmapsvc":
  if len(sys.argv) < 3:
    sys.exit('\nUsage: %s nmapsvc {file_name}\n' % sys.argv[0])
  targets_file = sys.argv[2]
  if not os.path.exists(targets_file):
    sys.exit('\n[!] The file of IP Addresses to target does not exist.\n')
  if not os.path.exists("sqlite-output.nse"):
    os.system("wget --quiet https://raw.githubusercontent.com/exitnode/nmap-sqlite-output/master/sqlite-output.nse")
  print("\n\n[*] Running an nmapsvc version scan on all entries in %s" % (targets_file))
  nmapsvc_tcp_cmd = "nmap -Pn -n -sSV -p- --version-intensity 3 --min-parallelism 32 -iL %s --min-rate 1000 --script sqlite-output --script-args dbname=%s,dbtable=scandata -oA %s/pya-nmap-tcp-output" % (targets_file, sqlite_database_file, directory_name)
  os.system(nmapsvc_tcp_cmd)
  nmapsvc_udp_cmd = "nmap -Pn -n -sU --top-ports 30 --open --version-intensity 3 --min-parallelism 32 -iL %s --min-rate 1000 --script sqlite-output --script-args dbname=%s,dbtable=scandata -oA %s/pya-nmap-udp-output" % (targets_file, sqlite_database_file, directory_name)
  os.system(nmapsvc_udp_cmd)

elif sys.argv[1] == "vulnscan":
  check_for_database()
  c = connect_to_database()

  # All scans for non-encrypted webservers (HTTP).
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp' AND (service = 'http' OR service = 'www' OR service = 'http-proxy')"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running whatweb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_whatweb_cmd = "whatweb -a 3 --no-errors http://%s:%s/ | tee %s/pya-whatweb-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_whatweb_cmd)

    print("\n\n[*] Running nikto on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_nikto_cmd = "nikto -timeout 2 -nossl -host http://%s:%s/ -F xml -output %s/pya-nikto-output-%s-%s-http.xml | tee %s/pya-nikto-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port, directory_name, host_address, service_port)
    os.system(http_nikto_cmd)

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

    if not os.path.exists("wascan-m4ll0k"): os.system("git clone --quiet https://github.com/m4ll0k/WAScan wascan-m4ll0k")
    print("\n\n[*] Running wascan on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_wascan_cmd = "cd wascan-m4ll0k/; python wascan.py --url http://%s:%s/ --scan 5 --ragent | tee ../%s/pya-wascan-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_wascan_cmd)

    if not os.path.exists("jexboss-joaomatosf"): os.system("git clone --quiet https://github.com/joaomatosf/jexboss jexboss-joaomatosf")
    print("\n\n[*] Running jexboss on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jexboss_cmd = "python jexboss-joaomatosf/jexboss.py -u http://%s:%s > %s/pya-jexboss-output-%s-%s-http.txt 2>&1" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jexboss_cmd)

    if not os.path.exists("struts-pwn"): os.system("git clone --quiet https://github.com/mazen160/struts-pwn struts-pwn")
    print("\n\n[*] Running struts-pwn on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_struts_cmd = "python struts-pwn/struts-pwn.py --check --url http://%s:%s/ 2>/dev/null | tee %s/pya-struts-pwn-output-%s-%s-http.txt"  % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_struts_cmd)

    print("\n\n[*] Running dirb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_dirb_cmd = "dirb http://%s:%s/ /usr/share/dirb/wordlists/common.txt -o %s/pya-dirb-output-%s-%s-http.txt -r" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_dirb_cmd)

  # All scans for encrypted webservers (SSL/TLS).
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp' AND (service LIKE '%https%' OR service LIKE '%ssl%')"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running whatweb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_whatweb_cmd = "whatweb -a 3 --no-errors https://%s:%s/ | tee %s/pya-whatweb-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_whatweb_cmd)

    print("\n\n[*] Running nikto on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_nikto_cmd = "nikto -timeout 2 -nossl -host https://%s:%s/ -F xml -output %s/pya-nikto-output-%s-%s-https.xml | tee %s/pya-nikto-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port, directory_name, host_address, service_port)
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

    if not os.path.exists("wascan-m4ll0k"): os.system("git clone --quiet https://github.com/m4ll0k/WAScan wascan-m4ll0k")
    print("\n\n[*] Running wascan on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_wascan_cmd = "cd wascan-m4ll0k/; python wascan.py --url https://%s:%s/ --scan 5 --ragent | tee ../%s/pya-wascan-output-%s-%s-https.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_wascan_cmd)

    if not os.path.exists("jexboss-joaomatosf"): os.system("git clone --quiet https://github.com/joaomatosf/jexboss jexboss-joaomatosf")
    print("\n\n[*] Running jexboss on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jexboss_cmd = "python jexboss-joaomatosf/jexboss.py -u https://%s:%s > %s/pya-jexboss-output-%s-%s-https.txt 2>&1" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jexboss_cmd)

    if not os.path.exists("struts-pwn"): os.system("git clone --quiet https://github.com/mazen160/struts-pwn struts-pwn")
    print("\n\n[*] Running struts-pwn on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_struts_cmd = "python struts-pwn/struts-pwn.py --check --url https://%s:%s/ 2>/dev/null | tee %s/pya-struts-pwn-output-%s-%s-https.txt"  % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_struts_cmd)

    print("\n\n[*] Running dirb on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_dirb_cmd = "dirb https://%s:%s/ /usr/share/dirb/wordlists/common.txt -o %s/pya-dirb-output-%s-%s-https.txt -r" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_dirb_cmd)

  # Jetty specific scan.
  query = '%jetty%'
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    if not os.path.exists("jetleak-testing-script-gdssecurity"): os.system("git clone --quiet https://github.com/GDSSecurity/Jetleak-Testing-Script jetleak-testing-script-gdssecurity")
    print("\n\n[*] Running jetleak on %s://%s:%s\n" % (service_proto, host_address, service_port))
    http_jetleak_cmd = "python jetleak-testing-script-gdssecurity/jetleak_tester.py http://%s %s | tee %s/pya-jetleak-output-%s-%s-http.txt" % (host_address, service_port, directory_name, host_address, service_port)
    os.system(http_jetleak_cmd)

  # All scans for only TCP specific stuff.
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp'"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    if not os.path.exists("sslyze-nabla-c0d3"): os.system("git clone --quiet https://github.com/nabla-c0d3/sslyze.git sslyze-nabla-c0d3 && sudo pip3 install --upgrade sslyze")
    print("\n\n[*] Running sslyze on %s://%s:%s\n" % (service_proto, host_address, service_port))
    tcp_sslyze_cmd = "sslyze --regular %s:%s > pya-sslyze-output-%s-%s.txt" % (host_address, service_port, host_address, service_port)
    os.system(tcp_sslyze_cmd)

    print("\n\n[*] Running nmapnse on %s://%s:%s\n" % (service_proto, host_address, service_port))
    tcp_nmapnse_cmd = "nmap -n -Pn -sTV -p %s --script default,vuln,auth,intrusive,brute --script-args 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)' --open -oA %s/pya-nmap-nse-output-%s-%s-tcp %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(tcp_nmapnse_cmd)

  # All scans for only UDP specific stuff.
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'udp'"):
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
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmap.ssh-brute on %s://%s:%s\n" % (service_proto, host_address, service_port))
    nmap_ssh_brute = "nmap -p %s --script ssh-brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt --script-args ssh-brute.timeout=4s -oA %s/pya-nmap-ssh-brute-output-%s-%s-ssh %s" % (service_port, directory_name, host_address, service_port, host_address)
    os.system(nmap_ssh_brute)

  query = '%ftp%'
  for row in c.execute("SELECT * FROM scandata WHERE protocol = 'tcp' AND version LIKE '%s'" % query):
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
  for row in c.execute("SELECT * FROM scandata;"):
    host_address = row[1]
    service_port = row[2]
    service_proto = row[5]

    print("\n\n[*] Running nmap +brute on %s://%s:%s\n" % (service_proto, host_address, service_port))
    nmap_brute = "nmap -p %s --script brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt -oA %s/pya-nmap-brute-output-%s-%s-%s %s" % (service_port, directory_name, host_address, service_port, service_proto, host_address)
    os.system(nmap_brute)

elif sys.argv[1] == "iker":
  if not os.path.exists("iker.py"): os.system("wget --quiet https://raw.githubusercontent.com/jnqpblc/metasploit-db_automate/master/iker.py")
  if not os.path.exists("ikeforce-spiderlabs"): os.system("git clone --quiet https://github.com/SpiderLabs/ikeforce.git ikeforce-spiderlabs")

  if len(sys.argv) < 2:
    check_for_database()
    c = connect_to_database()
    for row in c.execute("SELECT * FROM scandata WHERE protocol = 'udp' AND service = 'isakmp'"):
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
  if len(sys.argv) < 2:
    check_for_database()
    c = connect_to_database()
    for row in c.execute("SELECT * FROM scandata WHERE protocol = 'udp' AND service = 'isakmp'"):
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
