import os, sys, requests
usage = '\nSyntax: %s <option|clone|reclone|pull|remove>\n' % (sys.argv[0])
if len(sys.argv) < 2:
        print usage
        sys.exit(1)

OPTION = str(sys.argv[1])

def diff(li1, li2):
  return (list(set(li1) - set(li2)))

def get_repos_local():
  return sorted(os.listdir(os.getcwd()))

def get_repos_remote():
  URL = "https://api.github.com/users/jnqpblc/starred"
  TOKEN = ""
  TMP = []
  for num in range(0, 5):
    per_page = 100
    PARAMS = {'per_page':100, 'page':num}
    if TOKEN:
      HEADERS = {'Authorization': "token " + TOKEN}
      r = requests.get(url = URL, params = PARAMS, headers = HEADERS)
    else:
      r = requests.get(url = URL, params = PARAMS)
    if not r.status_code == 200:
      print '\nSomething when wrong with connection to Github.com.\n'
      sys.exit(1)
    RESP = r.json()
    if "documentation_url" in RESP:
      print RESP['message']
      break
    for obj in RESP:
       TMP.append(obj['clone_url'])
  if TMP:
    return TMP
  else:
    print '\nSomething when wrong with connection to Github.com.\n'
    sys.exit(1)

def clone():
  DATA = get_repos_remote()
  for line in DATA:
    REPO = line.strip('\n').split('/')[4].replace('.git', '').lstrip('.')
    USER = line.strip('\n').split('/')[3]
    os.system('git clone ' + 'https://github.com/' + USER + '/' + REPO + ' ' + REPO + '-' + USER)

def reclone():
  LOCAL = REMOTE = DATA = []
  LOCAL = get_repos_local()
  DATA = get_repos_remote()
  for line in DATA:
    REPO = line.strip('\n').split('/')[4].replace('.git', '').lstrip('.')
    USER = line.strip('\n').split('/')[3]
    REMOTE.append(REPO + "-" + USER)
  REPOS = diff(sorted(REMOTE), LOCAL)
  if not REPOS:
    print '\nNo missing repos. Everything is up-to-date!\n'
    sys.exit(0)
  for line in REPOS:
    os.system('git clone ' + 'https://github.com/' + line.rsplit('-', 1)[1] + '/' + line.rsplit('-', 1)[0] + ' ' + line)

def pull():
  LOCAL = get_repos_local()
  for repo in LOCAL:
    os.system('cd ' + repo + '; ' + 'pwd' + '; ' + 'git pull' + '; ' + 'cd ..')

def remove():
  print "[!] Not currently working! Prints only."
  LOCAL = REMOTE = DATA = []
  LOCAL = get_repos_local()
  DATA = get_repos_remote()
  for line in DATA:
    REPO = line.strip('\n').split('/')[4].replace('.git', '').lstrip('.')
    USER = line.strip('\n').split('/')[3]
    REMOTE.append(REPO + "-" + USER)
  for line in LOCAL:
    if unicode(line) not in sorted(REMOTE):
      print line
      #os.rmdir(line)

if OPTION == 'clone':
  clone()
elif OPTION == 'reclone':
  reclone()
elif OPTION == 'pull':
  pull()
elif OPTION == 'remove':
  remove()
else:
  print '\nDammit Bobby!'
  print usage
  sys.exit(1)
