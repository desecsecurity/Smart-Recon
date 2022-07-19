#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import sys
import datetime
import socket
import requests
import subprocess
import os
import uuid
import shutil
import json
import time
from time import strftime
from pathlib import Path

target = sys.argv[1]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = 'https://localhost:9200/'+target+'-portscan/_doc?refresh'
url_get = 'https://localhost:9200/'+target+'-subdomain/_search'
auth=('admin', '83d875fc-8789-11ec-9757-00505642c2bf')
hora = strftime("%Y-%m-%dT%H:%M:%S")
scanner = 'nmap'
dic_ports = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-nmap'
saida = 'nmap-'+x+'.xml'
ip = sys.argv[2]

def executa():
    subprocess.check_output('docker run --rm --name '+container_name+' -v /docker/data/'+target+'/temp:/data kali-tools:2.0 nmap -sSV -Pn '+ip+' -oX /data/'+saida+' || true', shell=True)

def consulta(ip):
	data = {"size":10000}
	get_doc = requests.get(url_get, headers=headers, auth=auth, data=json.dumps(data), verify=False)
	parse_scan = json.loads(get_doc.text)
	for x in parse_scan['hits']['hits']:
		if(str(x['_source']['server.ip']) == str(ip)):
			return((str(x['_source']['server.ipblock'])))

def parse():
    tree = ET.parse('/docker/data/'+target+'/temp/'+saida)
    root = tree.getroot()
    for i in root.iter('nmaprun'):
        for nmaprun in i:
            if(nmaprun.tag == 'host'):
                for host in nmaprun:
                    if(host.tag == 'address'):
                        if(':' not in host.attrib['addr']):
                            dic_ports['ip_v4'] = host.attrib['addr']
                            dic_ports['network.type'] = host.attrib['addrtype']
                    if(host.tag == 'ports'):
                        for port in host:
                            if(port.tag == 'port'):
                                dic_ports['network.transport'] = port.attrib['protocol']
                                dic_ports['server.port'] = port.attrib['portid']
                                for itens in port:
                                    if(itens.tag == 'state'):
                                        dic_ports['service.state'] = itens.attrib['state']
                                    if(itens.tag == 'service'):
                                        try:
                                            dic_ports['network.protocol'] = itens.attrib['name']
                                        except:
                                            dic_ports['network.protocol'] = ''
                                        try:
                                            dic_ports['application.version.number'] = itens.attrib['version']
                                        except:
                                            dic_ports['application.version.number'] = ''
                                        try:
                                            dic_ports['service.name'] = itens.attrib['product']
                                        except:
                                            dic_ports['service.name'] = ''
                                        dic_ports['server.ipblock'] = consulta(ip)
                                        data = {
                    				            '@timestamp':hora,
                    				            'server.address':ip,
                    				            'network.protocol':dic_ports['network.protocol'],
                    				            'server.ip':ip,
                    				            'server.port':dic_ports['server.port'],
                    				            'server.ipblock':dic_ports['server.ipblock'],
                    				            'server.name':dic_ports['service.name'],
                    				            'server.state':dic_ports['service.state'],
                    				            'network.transport':dic_ports['network.transport'],
                    				            'network.type':dic_ports['network.type'],
                    				            'application.version.number':dic_ports['application.version.number'],
                    				            'vulnerability.scanner.vendor':scanner
            				                    }
                                        r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
                                        print (r.text)
def main():
    executa()
    parse()
    
if __name__== '__main__':
    main()
