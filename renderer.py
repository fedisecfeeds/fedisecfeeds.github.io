#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
import json
import datetime
import html

def get_key(kv_item):
	d = kv_item[1]
	if d.get('updated') != None:
		return d['updated']
	else:
		return '0'


def render(jsonblob):
	fedi_cve_feed = json.loads(open(jsonblob, 'r').read())
	# sort
	fedi_cve_feed = {k: v for k, v in sorted(fedi_cve_feed.items(), key=get_key, reverse=True)} 
	# jinja2 rendering
	environment = Environment()
	template = environment.from_string(open("index.html.j2","r").read())
	content = template.render(data=fedi_cve_feed, updated=datetime.datetime.utcnow().isoformat(), escape=html.escape)
	with open('index.html', 'w+') as f:
		f.write(content)
	print('rendered to index.html')

if __name__ == "__main__":
	render('fedi_cve_feed.json')