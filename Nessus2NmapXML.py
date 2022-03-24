import sys, xmltodict

usage = '\nSyntax: %s <~/nessus_file.nessus>\n' % (sys.argv[0])

if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

nessus_file = str(sys.argv[1])

with open(nessus_file, 'r', encoding='utf-8') as file:
  my_xml = file.read()

# Use xmltodict to parse and convert the XML document
my_dict = xmltodict.parse(my_xml)

print('<?xml version="1.0" encoding="UTF-8"?>')
print('<!DOCTYPE nmaprun>')
print('<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>')
print('<!-- Nmap 7.92 scan initiated Thu Mar 24 09:46:58 2022 as: nmap -Pn -sT -oX scanme.nmap.org scanme.nmap.org -->')
print('<nmaprun scanner="nmap" args="nmap -Pn -sT -oX scanme.nmap.org scanme.nmap.org" start="1648133218" startstr="Thu Mar 24 09:46:58 2022" version="7.92" xmloutputversion="1.05">')
print('<verbose level="0"/>')
print('<debugging level="0"/>')

for ReportHost in my_dict['NessusClientData_v2']['Report']['ReportHost']:

  print('<host starttime="1648133218" endtime="1648133244"><status state="up" reason="user-set" reason_ttl="0"/>')

  for HostProperties in ReportHost['HostProperties']['tag']:
    if HostProperties['@name'] == "host-ip":
      print('<address addr="%s" addrtype="ipv4"/>' % HostProperties['#text'])
    if HostProperties['@name'] == "host-fqdn":
      print('<hostnames><hostname name="%s" type="user"/></hostnames>' % HostProperties['#text'])

  for ReportItem in ReportHost['ReportItem']:
    if ReportItem['plugin_name'] == "Nessus SYN scanner":
      print('<ports>')
      print('<port protocol="%s" portid="%s"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="%s" method="table" conf="3"/></port>' % (ReportItem['@protocol'], ReportItem['@port'], ReportItem['@svc_name']))
      print('</ports>')

  print('<times srtt="101268" rttvar="1497" to="107256"/>')
  print('</host>')

print('<runstats><finished time="1648133244" timestr="Thu Mar 24 09:47:24 2022" summary="Nmap done at Thu Mar 24 09:47:24 2022; 1 IP address (1 host up) scanned in 25.95 seconds" elapsed="25.95" exit="success"/><hosts up="1" down="0" total="1"/>')
print('</runstats>')
print('</nmaprun>')
