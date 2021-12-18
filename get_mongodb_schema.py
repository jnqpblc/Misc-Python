import sys
usage = '\nSyntax: %s <host> <port>\n' % (sys.argv[0])
if len(sys.argv) < 3:
	print(usage)
	sys.exit(1)

HOST = str(sys.argv[1])
PORT = str(sys.argv[2])

import pymongo
from addict import Dict

myclient = pymongo.MongoClient("mongodb://%s:%s/" % (HOST, PORT))

for db in myclient.list_database_names():
	print("%s" % db)
	mydb = myclient[db]
	for collection in mydb.list_collection_names():
		if collection:
			print(" |_%s" % collection)
			for document in mydb.get_collection(collection).find_one():
				if document: print("    |_%s" % document)

myclient.close();
