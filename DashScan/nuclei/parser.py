#!/usr/share/python3

#nuclei -u 192.168.56.101 -silent -json nuclei_output.json
#nmap -sV -O --top-ports 20000 <ip range> -oX nmap_output.xml

from libnmap.parser import NmapParser
import pandas as pd
import json

nmap_report = NmapParser.parse_fromfile('vulners3.xml')

def network_info():
	dict1 = []
	for a in nmap_report.hosts:
		dict1.append({
		'Address': a.address,
		'HostName': a.hostnames,
		'OpenPorts': a.get_open_ports(),
		'OS': str(str(a.os).split(':')[0])[2:],
		'Services': [b.banner for b in a.services]})
		
	return dict1
		
df1 = pd.DataFrame(network_info())

def vuln_info():
	loads = []
	with open('nuclei.json', 'r') as f:
		for line in f:
			loads.append(json.loads(line))
	dict2 = []
	for i in loads:
		try:
			dict2.append({
			'Address': i['ip'],
			'Vulnerability': i['info']['name'],
			'Description': i['info']['description'],
			'RiskLevel': i['info']['severity'],
			'HostName': i['host'],
			'More-Info': '%s' %(i['matcher-name'])})
		except:
			dict2.append({
			'Address': i['host'],
			'Vulnerability': i['info']['name'],
			'Description': "Na",
			'RiskLevel': i['info']['severity'],
			'HostName': i['host'],
			'More-Info': "Na"})	
	return dict2
	
df2 = pd.DataFrame.from_dict(vuln_info())

#filter by host
def group_vulns_per_addr():
	for i in df1['Address']:
		b = df2.loc[df2['Address'] == i]
	return b
		









