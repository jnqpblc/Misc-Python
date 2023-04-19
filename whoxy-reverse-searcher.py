#!/usr/bin/python3
import sys
usage = "\nUsage: %s {type|company|name|email|keyword} {search_term}\n" % sys.argv[0]
if len(sys.argv) < 2:
  sys.exit(usage)

type = sys.argv[1]
term = sys.argv[2]

import requests, json

def getApiKey():
  from os import environ
  if environ.get('WHOXY_API_KEY') is None:
    sys.exit("Please set 'WHOXY_API_KEY' environmental variable.")
  else:
    return environ.get('WHOXY_API_KEY')

def doSearch(type, term):
  try:
    if ' ' in term: term = term.replace(' ', '%20')
    key = getApiKey()
    url = "http://api.whoxy.com/?key=%s&reverse=whois&%s=%s&format=json&mode=mini" % (key, type, term)
    req = requests.get(url)
    return json.loads(req.content.decode('utf-8'))
  except Exception as _except:
    print('[ + ] %s'%str(_except))

if __name__ == "__main__":
  if type == "company" or type == "name" or type == "email" or type == "keyword":
    resp = doSearch(type, term)
    if resp.get('search_result'):
      for i in range(len(resp.get('search_result'))):
        print("%s" % resp.get('search_result')[i]['domain_name'])
  else:
    sys.exit(usage)
