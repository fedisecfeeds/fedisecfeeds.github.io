#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
import json


def render(jsonblob):
	fedi_cve_feed = json.loads(open(jsonblob, 'r').read())

	# jinja2 rendering
	environment = Environment()
	template = environment.from_string(open("index.html.j2","r").read())
	html = template.render(data=fedi_cve_feed)
	with open('index.html', 'w+') as f:
		f.write(html)
	print('rendered to index.html')

if __name__ == "__main__":
	render('fedi_cve_feed.json')