#!/usr/bin/env python3

import requests
import json
import os
import time
import datetime
import random

import html2text


# infosec.exchange
IFSX_AUTH_TOKEN = os.getenv("IFSX_AUTH_TOKEN")
#ioc.exchange
IOCX_AUTH_TOKEN = os.getenv("IOCX_AUTH_TOKEN")

start = time.time()

def has_digits(s):
	return any(char.isdigit() for char in s)

def normalize_cve(cvestr):
	'''
	normalize a cve string to CVE-YYYY-ZZZZZ
	'''
	if not (cvestr.upper().startswith("CVE") and has_digits(cvestr) and len(cvestr) > 10): # validate it
		print(f"WARNING: invalid cve str {cvestr}")
		return None
	cve = ''
	cve += cvestr[:3].upper() # first 3 chars
	if cvestr[3].isdigit(): #if the fourth char is a number e.g. cve202312345
		cve += f"-{cvestr[3:7]}-{cvestr[7:].replace('-','').replace('_','')}"
	elif cvestr[3] in ["_", "-"]:
		# a proper CVE string should also work, not just with underscore 
		cve += f"-{cvestr[4:8]}-{cvestr[9:]}"
	else:
		print(f"WARNING: weird cve str {cvestr}")
		return None
	return cve

def redhat_cve_detail(cve):
	'''
	get cve detail from redhats portal
	'''
	url = f'https://access.redhat.com/labs/securitydataapi/cve/{cve}.json'
	r = requests.get(url)
	if r.status_code != 200:
		print(f"WARN: bad redhat api status for {cve}", r.status_code, r.text)
	return r.json()

def nvd_cve_detail(cve):
	'''
	get cve detail (like cvss score) from the nvd api 
	https://nvd.nist.gov/developers/vulnerabilities

	XXX DOESN WORK - NVD HAS WEIRD ASS RATE LIMITS AND IS A SHIT API.
	'''
	url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
	r = requests.get(url, headers={"User-Agent":f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 {random.randrange(0,20000)}"})
	if r.status_code != 200:
		print(f"WARN: bad nvd api status for {cve}", r.status_code, r.text[:100])
		return None
	else:
		return r.json()
	
def cveapi_cve_detail(cve):
	'''
	use cveapi.com
	'''
	url = f'https://v1.cveapi.com/{cve}.json'
	r = requests.get(url)
	if r.status_code != 200:
		print(f"WARN: bad cveapi status for {cve}", r.status_code, r.text[:100])
		return None
	else:
		return r.json()



def first_epss_for_cves_list(cves):
	'''
	get EPSS (Exploit Prediction Scoring System) detail for the list of cves
	'''
	cves = ','.join(cves)
	r = requests.get(f'https://api.first.org/data/v1/epss?cve={cves}')
	return r.json()

def get_hashtag_timeline(instance_url, hashtag, auth_token=None, limit=10):
	'''
	get posts (timeline) of a particular hashtag
	'''
	r = requests.get(f"{instance_url}/api/v1/timelines/tag/{hashtag}?limit={limit}", headers={"Authorization":f"Bearer {auth_token}"})
	if r.status_code != 200:
		print(f"WARN: {instance_url} get_hashtag_timeline api status", r.status_code, r.text)
	return r.json()


def search_poll(instance_url, q, search_type='hashtags', auth_token=None):
	lstart = time.time()
	results = []

	limit = 40
	offset = 0
	total_pages_to_fetch = 5
	curr_page = 0
	while True:
		r = requests.get(f"{instance_url}/api/v2/search?q={q}&type={search_type}&limit={limit}&offset={offset}", headers={"Authorization":f"Bearer {auth_token}"})
		# print("Status:", r.status_code)
		d = r.json()
		# print('keys:', d.keys())
		# print(d)
		results.extend(d[search_type])
		offset += len(d[search_type])
		curr_page += 1

		if len(d[search_type]) < limit or curr_page > total_pages_to_fetch: # done
			break
	print(f'done polling {instance_url}, found {len(results)} {search_type} secs:', time.time() - lstart)
	return results

hashtags = []
hashtags.extend(search_poll("https://infosec.exchange","CVE", auth_token=IFSX_AUTH_TOKEN))
hashtags.extend(search_poll("https://ioc.exchange","CVE", auth_token=IOCX_AUTH_TOKEN))


# get most used, trending past 5 days

cve_counts = {}
cve_posts = {}

for hashtag in hashtags:

	cve = normalize_cve(hashtag['name'])
	if cve == None:
		# skip hashtag that are invalid
		continue
	if cve not in cve_counts:
		cve_counts[cve] = 0
	for hist in hashtag['history'][:5]:
		count = int(hist['uses'])
		cve_counts[cve] += count
		# day = hist['day']

	# get posts
	if cve_counts[cve] > 0:
		if cve not in cve_posts:
			cve_posts[cve] = []
		cve_posts[cve].extend(get_hashtag_timeline("https://infosec.exchange", hashtag['name'], auth_token=IFSX_AUTH_TOKEN))
		cve_posts[cve].extend(get_hashtag_timeline("https://ioc.exchange", hashtag['name'], auth_token=IOCX_AUTH_TOKEN))

for cve in sorted(cve_counts, key=cve_counts.get, reverse=True): # most popular cves
	if cve_counts[cve] != 0:
		print(f"{cve} uniq hashtags:{cve_counts[cve]} posts:{len(cve_posts[cve])}")

h2t = html2text.HTML2Text()


print(f"total {len(cve_posts)} CVEs")

# get epss data
print('getting EPSS data..')
lstart = time.time()
epss_data = first_epss_for_cves_list(list(cve_posts))
print(len(epss_data))
print(epss_data.keys())
print("done getting EPSS data: ", time.time()-lstart)


print("getting CVE details from NVD...")
lstart = time.time()
cve_details = {}
for cve in cve_posts:
	cveapi_data = cveapi_cve_detail(cve)
	# print(cveapi_data)
	if cveapi_data != None:
		try:
			cve_details[cve] = cveapi_data
		except Exception as e:
			print(f"WARN no valid cve info on {cve}:",e)


# one big JSON blob for the page to render
fedi_cve_feed = {} #cve:...

print("done getting CVE details:", time.time()-lstart)
for cve in cve_posts:
	fedi_cve_feed[cve] = {}
	fedi_cve_feed[cve]['posts'] = []

	for post in cve_posts[cve]:
		# created_at
		# convert content to markdown to make XSS-ing this website slightly harder 
		content = "ERROR with html2text parsing"
		try:
			content = h2t.handle(post['content'])
		except Exception as e:
			print("ERROR with html2text parsing:", e)
		fedi_cve_feed[cve]['posts'].append({'account':post['account'],'url':post['url'], 'content':content, 'created_at':post['created_at']})
		fedi_cve_feed[cve]['cvss3'] = 0
		fedi_cve_feed[cve]['severity'] = None

		if cve in cve_details:
			if 'baseMetricV3' in cve_details[cve]['impact']:
				fedi_cve_feed[cve]['cvss3'] = cve_details[cve]['impact']['baseMetricV3']['cvssV3']['baseScore']
				fedi_cve_feed[cve]['severity'] = cve_details[cve]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
			if len(cve_details[cve]['cve']['description']['description_data']) > 0:
				fedi_cve_feed[cve]['description'] = cve_details[cve]['cve']['description']['description_data'][0]['value']
		fedi_cve_feed[cve]['epss'] = None
		for d in epss_data['data']:
			if d['cve'] == cve:
				fedi_cve_feed[cve]['epss'] = float(d['epss']) * 100


		# print(f"{cve} {author_acct} {content}")



outfile = 'fedi_cve_feed.json'
with open(outfile, 'w+') as f:
	json.dump(fedi_cve_feed, f, indent=2)

from renderer import render
render(outfile)

print(f'done, written output to {outfile}. total elapsed:', time.time() - start)

