import sys
usage = '\nSyntax: %s <host> <port>\n' % (sys.argv[0])
if len(sys.argv) < 3:
  print(usage)
  sys.exit(1)

HOST = str(sys.argv[1])
PORT = str(sys.argv[2])

import pymongo
from addict import Dict

maxSevSelDelay = 2000
myclient = pymongo.MongoClient("mongodb://%s:%s/" % (HOST, PORT), serverSelectionTimeoutMS=maxSevSelDelay)
try:
  status = Dict(myclient.server_info())
  print("\n# server: %s:%s\n# version: %s\n# distro: %s\n# arch: %s\n# os: %s\n" % (HOST, PORT, status.version, status.buildEnvironment.distmod, status.buildEnvironment.distarch, status.buildEnvironment.target_os))
  print("format:\n---\ndatabase\n |_collection\n    |_document\n")
  try:
    for db in myclient.list_database_names():
      print("%s" % db)
      try:
        mydb = myclient[db]
        for collection in mydb.list_collection_names():
          if collection:
            print(" |_%s" % collection)
            documents = mydb.get_collection(collection).find_one()
            if documents:
              for document in documents:
                if document: print("    |_%s" % document)
      except: continue
  except pymongo.errors.OperationFailure as err:
    print("error: %s" % err)
except pymongo.errors.ServerSelectionTimeoutError as err:
  print("\n error: %s" % err)
myclient.close();
