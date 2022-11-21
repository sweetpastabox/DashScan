#!/usr/bin/python3.9

# -*- coding: utf-8 -*-

from libnmap.parser import NmapParser
import pandas as pd

nmap_report = NmapParser.parse_fromfile('vulners3.xml')

#nmap <@ip address> -sV --script vulners -T4 -oX <output.xml>

def cleaner():
	for a in nmap_report.hosts:
		for b in a.services:
			for i in b.scripts_results:
				if i['id'] == 'vulners':
					c = i.get('elements')
					for i in c.keys():
						dict = c.get(i)
						dict['vulns']=dict.pop(None)

cleaner()

def get_elements():
	elements = []
	for a in nmap_report.hosts:
		for b in a.services:
			for i in b.scripts_results:
				if i['id'] == 'vulners':
					c = i.get('elements')
					for y in c.keys():
						v = c[y]
						for n in v['vulns']:
							n["host"] = a.address
							n["service_id"] = b.id
							n["OS"] = str(str(a.os).split(':')[0])[2:]
							n["Name"] = a.hostnames
							n["Open Ports"] = len(a.get_open_ports())
							n["Apps"] = b.banner
							elements.append(n)
					
	return elements

def create_dataframe():
	df = pd.DataFrame(get_elements())
	return df
	

create_dataframe()	
create_dataframe().to_csv('/home/kali/Desktop/dash/test2/export.csv', index=False)
