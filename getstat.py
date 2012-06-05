#!/usr/bin/env python
# coding: utf-8
import socket
import json
import os

gmetric = "/usr/bin/gmetric"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
	sock.connect(('127.0.0.1', 10381))
	data = json.loads(sock.recv(8192))
	for _filter in data:
		for name in _filter.keys():
			for section in _filter[name].keys():
				for item in _filter[name][section].keys():
					#print("%s -n %s -v %u -t uint32" % (gmetric, '_'.join(["tcpeek", name, section, item]), _filter[name][section][item]))
					os.system("%s -n %s -v %u -t uint32" % (gmetric, '_'.join(["tcpeek", name, section, item]), _filter[name][section][item]))
except socket.error, e:
	print(e)
finally:
	sock.close()
