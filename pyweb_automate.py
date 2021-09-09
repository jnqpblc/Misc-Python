import os, sys
banner = """
                              .---.                               ,---,                        ___                       ____                ___ 
,-.----.                     /. ./|            ,---,             '  .' \                     ,--.'|_                   ,'  , `.            ,--.'|_ 
\    /  \                .--'.  ' ;          ,---.'|            /  ;    '.             ,--,  |  | :,'   ,---.       ,-+-,.' _ |            |  | :,' 
|   :    |              /__./ \ : |          |   | :           :  :       \          ,'_ /|  :  : ' :  '   ,'\   ,-+-. ;   , ||            :  : ' : 
|   | .\ :     .--, .--'.  '   \' .   ,---.  :   : :           :  |   /\   \    .--. |  | :.;__,'  /  /   /   | ,--.'|'   |  || ,--.--.  .;__,'  /     ,---. 
.   : |: |   /_ ./|/___/ \ |    ' '  /     \ :     |,-.        |  :  ' ;.   : ,'_ /| :  . ||  |   |  .   ; ,. :|   |  ,', |  |,/       \ |  |   |     /     \ 
|   |  \ :, ' , ' :;   \  \;      : /    /  ||   : '  |        |  |  ;/  \   \|  ' | |  . .:__,'| :  '   | |: :|   | /  | |--'.--.  .-. |:__,'| :    /    /  | 
|   : .  /___/ \: | \   ;  `      |.    ' / ||   |  / :        '  :  | \  \ ,'|  | ' |  | |  '  : |__'   | .; :|   : |  | ,    \__\/: . .  '  : |__ .    ' / | 
:     |`-'.  \  ' |  .   \    .\  ;'   ;   /|'   : |: |        |  |  '  '--'  :  | : ;  ; |  |  | '.'|   :    ||   : |  |/     ," .--.; |  |  | '.'|'   ;   /| 
:   : :    \  ;   :   \   \   ' \ |'   |  / ||   | '/ :        |  :  :        '  :  `--'   \ ;  :    ;\   \  / |   | |`-'     /  /  ,.  |  ;  :    ;'   |  / | 
|   | :     \  \  ;    :   '  |--" |   :    ||   :    |        |  | ,'        :  ,      .-./ |  ,   /  `----'  |   ;/        ;  :   .'   \ |  ,   / |   :    | 
`---'.|      :  \  \    \   \ ;     \   \  / /    \  /         `--''           `--`----'      ---`-'           '---'         |  ,     .-./  ---`-'   \   \  / 
  `---`       \  ' ;     '---"       `----'  `-'----'                                                                         `--`---'                `----' 
               `--`
  by jnqpblc
"""
usage = "\n%s\nUsage: python %s help\nUsage: python %s show {output_directory}\nUsage: python %s {help|show|auto|<cmd>} {proto} {port} {file_name|domain_name|ip_address} {web_root_dir}\n" % (banner, sys.argv[0], sys.argv[0], sys.argv[0])

if len(sys.argv) < 2:
  sys.exit(usage)

elif sys.argv[1] == "help":
  print("\n[+] Supported commands:\n")
  file = open(sys.argv[0], "r")
  for line in file:
    if "def run_" in line:
      str = line.split('(', 1)[0].split(" ",2)[1].replace('run_', '')
      if str:
        print("    %s" % str)
  sys.exit('')

elif sys.argv[1] == "show":
  if len(sys.argv) < 3:
    sys.exit(usage)
  elif not os.path.exists(sys.argv[2]):
    sys.exit("\n[!] The supplied directory does not exist.\n")
  else:
    os.system("find %s -name '*.txt' -o -name '*.nmap' -exec cat {} \; | less -R" % sys.argv[2])
    sys.exit()

elif len(sys.argv) < 4:
  sys.exit(usage)

directory_name = "AMA"
option = sys.argv[1]
service_proto = sys.argv[2]
service_port = sys.argv[3]
targets_option = sys.argv[4]
web_root = "/"
if len(sys.argv) == 6:
  web_root = sys.argv[5]
user = os.environ.get('USER')
wpscan_api = "Xr3JjnDWgwCm30Ow7pCfkOJwghPYH5twPyZ2Epmoldo"
nikto_config = "/etc/nikto/config.txt"
targets = []

#sys.stdout = open(directory_name + '/' + sys.argv[0] + ".log", 'w')

from requests import get
def get_public_ip():
    #ip = get('https://api.ipify.org').text
    ip = get('https://ifconfig.io/ip').text
    return ip.rstrip()

def check_for_output_folder():
  if not os.path.exists(directory_name):
    os.makedirs(directory_name)

import socket
def check_is_port_open(host, port):
  a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  location = (host, port)
  try:
    result_of_check = a_socket.connect_ex(location)
    if result_of_check == 0:
      return True
  except:
    return False
  a_socket.close()

def run_whatweb(service_proto, host_address, service_port, web_root):
    print("\n\n[*] Running whatweb on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "whatweb -a 3 --no-errors %s://%s:%s%s 2>/dev/null | tee %s/pya-whatweb-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_nikto(service_proto, host_address, service_port, web_root):
    if not os.path.exists(nikto_config): sys.exit("%s does not exist. Please modify the nikto_config variable.")
    print("\n\n[*] Running nikto on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "nikto -config %s -timeout 2 -nossl -host %s://%s:%s%s -F xml -output %s/pya-nikto-output-%s-%s-%s.xml | tee %s/pya-nikto-output-%s-%s-%s.txt" % (nikto_config, service_proto, host_address, service_port, web_root, directory_name, host_address, service_port,service_proto, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_wpscan(service_proto, host_address, service_port, web_root):
    if not os.path.exists("unix_passwords.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_passwords.txt")
    print("\n\n[*] Running wpscan on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "wpscan --url %s://%s:%s%s -t 10 --random-user-agent --detection-mode aggressive --interesting-findings-detection aggressive --wp-version-all --disable-tls-checks --enumerate u,m,ap,at,tt,cb,dbe --passwords unix_passwords.txt --api-token %s --output %s/pya-wpscan-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, wpscan_api, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)
    os.system("cat %s/pya-wpscan-output-%s-%s-%s.txt" % (directory_name, host_address, service_port, service_proto))

# if using ubuntu, since the repo vrsion is old.
# wget http://ftp.us.debian.org/debian/pool/main/s/sqlmap/sqlmap_1.5.2-1_all.deb
# sudo dpkg -i sqlmap_1.5.2-1_all.deb

def run_sqlmap_crawl(service_proto, host_address, service_port, web_root):
    print("\n\n[*] Running sqlmap_crawl on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "sqlmap --random-agent --batch --smart --crawl=4 --threads=3 --level=4 --risk=2 -u %s://%s:%s%s | tee %s/pya-sqlmap-crawl-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_sqlmap_forms(service_proto, host_address, service_port, web_root):
    print("\n\n[*] Running sqlmap_forms on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "sqlmap --random-agent --batch --smart --crawl=4  --forms --threads=3 --level=4 --risk=2 -u %s://%s:%s%s | tee %s/pya-sqlmap-forms-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_nmap_tomcat(service_proto, host_address, service_port, web_root):
    if not os.path.exists("tomcat-scan.nse"): os.system("wget --quiet https://raw.githubusercontent.com/sensepost/autoDANE/master/software/tomcat_check/tomcat-scan.nse")
    print("\n\n[*] Running tomcat-scan.nse on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "nmap -Pn -n -sT -T4 -p %s --script ./tomcat-scan.nse -oA %s/pya-tomcat-scan-output-%s-%s-%s %s" % (service_port, directory_name, host_address, service_port, service_proto, host_address)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_wascan(service_proto, host_address, service_port, web_root):
    if not os.path.exists("wascan-m4ll0k"): os.system("git clone --quiet https://github.com/m4ll0k/WAScan wascan-m4ll0k")
    print("\n\n[*] Running wascan on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "cd wascan-m4ll0k/; python2.7 wascan.py --url %s://%s:%s%s --scan 5 --ragent -v | tee ../%s/pya-wascan-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_jexboss(service_proto, host_address, service_port, web_root):
    if not os.path.exists("jexboss-joaomatosf"): os.system("git clone --quiet https://github.com/joaomatosf/jexboss jexboss-joaomatosf; pip2 install -r jexboss-joaomatosf/requires.txt -q --no-input 2>/dev/null")
    print("\n\n[*] Running jexboss on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "python2.7 jexboss-joaomatosf/jexboss.py -u %s://%s:%s%s > %s/pya-jexboss-output-%s-%s-%s.txt 2>&1" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)
    os.system("rm jexboss_2021*.log")
    os.system("cat %s/pya-jexboss-output-%s-%s-%s.txt" % (directory_name, host_address, service_port, service_proto))

def run_struts_pwn(service_proto, host_address, service_port, web_root):
    if not os.path.exists("struts-pwn"): os.system("git clone --quiet https://github.com/mazen160/struts-pwn struts-pwn")
    print("\n\n[*] Running struts-pwn on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "python2.7 struts-pwn/struts-pwn.py --check --url %s://%s:%s%s 2>/dev/null | tee %s/pya-struts-pwn-output-%s-%s-%s.txt"  % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

# https://stackoverflow.com/questions/5319430/how-do-i-have-python-httplib-accept-untrusted-certs
def run_jetleak(service_proto, host_address, service_port, web_root):
    if not os.path.exists("jetleak-testing-script-gdssecurity"): os.system("git clone --quiet https://github.com/GDSSecurity/Jetleak-Testing-Script jetleak-testing-script-gdssecurity; sed -i 's/HTTPSConnection(url.netloc + \":\" + port/&, context=ssl._create_unverified_context()/g;' jetleak-testing-script-gdssecurity/jetleak_tester.py")
    print("\n\n[*] Running jetleak on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "python2.7 jetleak-testing-script-gdssecurity/jetleak_tester.py %s://%s %s %s | tee %s/pya-jetleak-output-%s-%s-%s.txt" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_dirb(service_proto, host_address, service_port, web_root):
    print("\n\n[*] Running dirb on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "dirb %s://%s:%s%s /usr/share/dirb/wordlists/common.txt -o %s/pya-dirb-output-%s-%s-%s.txt -w -r" % (service_proto, host_address, service_port, web_root, directory_name, host_address, service_port, service_proto)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_sslyze(service_proto, host_address, service_port, web_root):
    if not os.path.exists("sslyze-nabla-c0d3"): os.system("git clone --quiet https://github.com/nabla-c0d3/sslyze.git sslyze-nabla-c0d3 && sudo pip3 install --upgrade sslyze")
    print("\n\n[*] Running sslyze on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "sslyze --regular %s:%s > %s/pya-sslyze-output-%s-%s.txt" % (host_address, service_port, directory_name, host_address, service_port)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)
    os.system("cat %s/pya-sslyze-output-%s-%s.txt" % (directory_name, host_address, service_port))

def run_nmap_scripts(service_proto, host_address, service_port, web_root):
    print("\n\n[*] Running nmapnse on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "nmap -n -Pn -sTV -p %s --script default,vuln,auth,intrusive,brute --script-args http.useragent='Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)' --open -oA %s/pya-nmap-nse-output-%s-%s-tcp %s" % (service_port, directory_name, host_address, service_port, host_address)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

def run_nmap_brute(service_proto, host_address, service_port, web_root):
    if not os.path.exists("unix_users.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_users.txt")
    if not os.path.exists("unix_passwords.txt"): os.system("wget --quiet https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/unix_passwords.txt")
    print("\n\n[*] Running nmap +brute on %s://%s:%s%s" % (service_proto, host_address, service_port, web_root))
    cmd = "nmap -p %s --script brute --script-args userdb=unix_users.txt,passdb=unix_passwords.txt -oA %s/pya-nmap-brute-output-%s-%s-%s %s" % (service_port, directory_name, host_address, service_port, service_proto, host_address)
    print("%s@%s:~$ %s" % (user, get_public_ip(), cmd))
    os.system(cmd)

check_for_output_folder()

import validators

if os.path.exists(targets_option):
  targets = open(targets_option, "r")
elif validators.ip_address.ipv4(targets_option):
  targets.append(targets_option)
elif validators.ip_address.ipv6(targets_option):
  targets.append(targets_option)
elif validators.domain(targets_option):
  targets.append(targets_option)
else:
  sys.exit('\n[!] You did not supply a valid targets option or the file does not exist.\n')

if option == "auto":
  for row in targets:
    host_address = row.rstrip()
    if not check_is_port_open(host_address, int(service_port)):
      print("[!] The host or service was not accessible for %s:%s" % (host_address, service_port))
      break
    run_whatweb(service_proto, host_address, service_port, web_root)
    run_nikto(service_proto, host_address, service_port, web_root)
    run_sqlmap_crawl(service_proto, host_address, service_port, web_root)
    run_sqlmap_forms(service_proto, host_address, service_port, web_root)
    #run_wascan(service_proto, host_address, service_port, web_root)
    run_nmap_tomcat(service_proto, host_address, service_port, web_root)
    run_jexboss(service_proto, host_address, service_port, web_root)
    run_struts_pwn(service_proto, host_address, service_port, web_root)
    run_jetleak(service_proto, host_address, service_port, web_root)
    run_dirb(service_proto, host_address, service_port, web_root)
    run_sslyze(service_proto, host_address, service_port, web_root)
    #run_nmap_scripts(service_proto, host_address, service_port, web_root)
    run_nmap_brute(service_proto, host_address, service_port, web_root)

elif option == "whatweb":
  for row in targets:
    host_address = row.rstrip()
    run_whatweb(service_proto, host_address, service_port, web_root)

elif option == "nikto":
  for row in targets:
    host_address = row.rstrip()
    run_nikto(service_proto, host_address, service_port, web_root)

elif option == "wpscan":
  for row in targets:
    host_address = row.rstrip()
    run_wpscan(service_proto, host_address, service_port, web_root)

elif option == "sqlmap":
  for row in targets:
    host_address = row.rstrip()
    run_sqlmap(service_proto, host_address, service_port, web_root)

elif option == "wascan":
  for row in targets:
    host_address = row.rstrip()
    run_wascan(service_proto, host_address, service_port, web_root)

elif option == "tomcat":
  for row in targets:
    host_address = row.rstrip()
    run_nmap_tomcat(service_proto, host_address, service_port, web_root)

elif option == "jexboss":
  for row in targets:
    host_address = row.rstrip()
    run_jexboss(service_proto, host_address, service_port, web_root)

elif option == "struts_pwn":
  for row in targets:
    host_address = row.rstrip()
    run_struts_pwn(service_proto, host_address, service_port, web_root)

elif option == "jetleak":
  for row in targets:
    host_address = row.rstrip()
    run_jetleak(service_proto, host_address, service_port, web_root)

elif option == "dirb":
  for row in targets:
    host_address = row.rstrip()
    run_dirb(service_proto, host_address, service_port, web_root)

elif option == "sslyze":
  for row in targets:
    host_address = row.rstrip()
    run_sslyze(service_proto, host_address, service_port, web_root)

elif option == "nse":
  for row in targets:
    host_address = row.rstrip()
    run_nmap_scripts(service_proto, host_address, service_port, web_root)

elif option == "brute":
  for row in targets:
    host_address = row.rstrip()
    run_nmap_brute(service_proto, host_address, service_port, web_root)

else:
  sys.exit('[!] The supplied option failed!')

sys.stdout.close()
