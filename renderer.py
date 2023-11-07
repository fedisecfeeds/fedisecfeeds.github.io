#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
import json
import datetime

def render(jsonblob):
	fedi_cve_feed = json.loads(open(jsonblob, 'r').read())
	# sort
	fedi_cve_feed = {k: v for k, v in sorted(fedi_cve_feed.items(), key=lambda item: item[1]['cvss3'], reverse=True)} 
	# jinja2 rendering
	environment = Environment()
	template = environment.from_string(open("index.html.j2","r").read())
	html = template.render(data=fedi_cve_feed, updated=datetime.datetime.utcnow().isoformat())
	with open('index.html', 'w+') as f:
		f.write(html)
	print('rendered to index.html')

if __name__ == "__main__":
	render('fedi_cve_feed.json')