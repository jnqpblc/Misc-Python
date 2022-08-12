import os, sys
banner = """
PYHASHCAT AUTOMATE
  by jnqpblc
"""
usage = "\n%s\nUsage: %s <hash_file|~/allthehashes.txt> <rules|none|best64|d3ad0ne|dive|etc>\n" % (banner, sys.argv[0])

if len(sys.argv) < 2:
  sys.exit(usage)

hash_file = sys.argv[1]
rules_option = sys.argv[2]
hashcat_bin="hashcat"
hashcat_folder="/root/hashcat" #no trailing slash, please.
wordlist_directory = "/root/wordlists"
wordlist_array = ["68_linkedin_found.txt","rockyou2021.txt"]
owd = os.getcwd()

if not os.path.exists("%s/%s" % (hashcat_folder, hashcat_bin)):
  sys.exit("\n[!] The internal hashcat location does not exist. Please update the script.\n")
else:
  os.chdir(hashcat_folder)

if not os.path.exists(hash_file):
  sys.exit("\n[!] The supplied hash_file does not exist.\n")

def run_the_katz(hash_file, wordlist, rules_option, hash_type):
  if not os.path.exists(wordlist):
    sys.exit("\n[!] %s does not exist.\n" % wordlist)
  if rules_option == "none":
    os.system("./%s -O -w 4 -D 2 -a 0 -m %s %s %s |grep -v 'unmatched'" % (hashcat_bin, hash_type, hash_file, wordlist))
  else:
    rules_file = "rules/%s.rule" % rules_option
    if not os.path.exists("%s" % rules_file):
      sys.exit("\n[!] The supplied rules_option is not correct or the file can not be found. E.g. best64 == rules/best64.rule\n")
    os.system("./%s -O -w 4 -D 2 -a 0 -m %s -r %s %s %s |grep -v 'unmatched'" % (hashcat_bin, hash_type, rules_file, hash_file, wordlist))

def check_if_hash_type(hash_type_string):
  with open(hash_file) as f:
    if hash_type_string in f.read():
      return "%s found." % hash_type_string
    else:
      return None
  f.close()

#  5500 | NetNTLMv1 / NetNTLMv1+ESS
# 27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)
#  5600 | NetNTLMv2
# 27100 | NetNTLMv2 (NT)
#  1000 | NTLM
# 13100 | Kerberos 5, etype 23, TGS-REP
# 18200 | Kerberos 5, etype 23, AS-REP
# 19600 | Kerberos 5, etype 17, TGS-REP
# 19700 | Kerberos 5, etype 18, TGS-REP

hash_type_array = [':::;1000', 'NETNTLMv1;5500', 'NETNTLMv2;5600', 'krb5tgs$23;13100', 'krb5asrep;18200', 'krb5tgs$17;19600', 'krb5tgs$18;19700']

for i in range(0,len(wordlist_array)):
  wordlist = "%s/%s" % (wordlist_directory, wordlist_array[i])
  for i in range(0,len(hash_type_array)):
    search_term = hash_type_array[i].split(";")[0]
    hash_type = hash_type_array[i].split(";")[1]

    print("\n[*] Running hashcat with search_term: %s, hash_type: %s, rules_option: %s, wordlist: %s\n\n" % (search_term, hash_type, rules_option, wordlist))
    if check_if_hash_type(search_term) is not None:
      run_the_katz(hash_file, wordlist, rules_option, hash_type)

os.chdir(owd)
