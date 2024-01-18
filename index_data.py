#!/usr/bin/env python3

import requests
import json
import os
import time
import datetime
import random
import re

import html2text


# infosec.exchange
IFSX_AUTH_TOKEN = os.getenv("IFSX_AUTH_TOKEN")
#ioc.exchange
IOCX_AUTH_TOKEN = os.getenv("IOCX_AUTH_TOKEN")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

TESTMODE = os.getenv("TESTMODE") # for dev only

if TESTMODE:
	print("TESTMODE enabled")

CVE_PATTERN = r'(?i)\bcve\-\d{4}-\d{4,7}'

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
	if r.status_code == 403:
		print("rate limited by assholes at NVD, waiting..")
		time.sleep(6.1)
		r = requests.get(url, headers={"User-Agent":f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 {random.randrange(0,20000)}"})
		return r.json()
	if r.status_code not in [200, 403]:
		print(f"WARN: bad nvd api status for {cve}", r.status_code, r.text[:100])
		return None
	else:
		return r.json()


def first_epss_for_cves_list(cves):
	'''
	get EPSS (Exploit Prediction Scoring System) detail for the list of cves
	'''
	print(f'getting epss data for {len(cves)} cves')
	data = []
	for i in range(0, len(cves), 30):
		cves_csv = ','.join(cves[i:i+30])
		r = requests.get(f'https://api.first.org/data/v1/epss?cve={cves_csv}')
		data.extend(r.json()['data'])
	return data

def get_hashtag_timeline(instance_url, hashtag, auth_token=None, limit=10):
	'''
	get posts (timeline) of a particular hashtag
	'''
	r = requests.get(f"{instance_url}/api/v1/timelines/tag/{hashtag}?limit={limit}", headers={"Authorization":f"Bearer {auth_token}"})
	if r.status_code != 200:
		print(f"WARN: {instance_url} get_hashtag_timeline api status", r.status_code, r.text)
	return r.json()

def get_github_repos(cve):

	github_repos = set() # use set to dedup; cast this back to a list later

	# search generically, without "in:.."
	# > When you omit this qualifier, only the repository name, description, and topics are searched.
	# in:readme sucks and returns false positives instead of actual PoCs
	url = f'https://api.github.com/search/repositories?q={cve}&per_page=100'
	headers = {'Accept':'application/vnd.github+json', 'Authorization': f'Bearer {GITHUB_TOKEN}', 'X-GitHub-Api-Version': '2022-11-28'}
	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		return ['search error']

	for d in r.json()['items']:
		github_repos.add(d['html_url'])

	return list(github_repos)








def search_poll(instance_url, q, search_type='hashtags', auth_token=None, last_days=14):
	'''
	search_type: Specify whether to search for only accounts, hashtags, statuses
	'''
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

def main():


	hashtags = []
	hashtags.extend(search_poll("https://infosec.exchange","CVE", auth_token=IFSX_AUTH_TOKEN))
	hashtags.extend(search_poll("https://ioc.exchange","CVE", auth_token=IOCX_AUTH_TOKEN))


	# get most used, trending past N days
	last_days = 14

	cve_counts = {}
	cve_posts = {}

	for hashtag in hashtags:

		cve = normalize_cve(hashtag['name'])
		if cve == None:
			# skip hashtag that are invalid
			continue
		if cve not in cve_counts:
			cve_counts[cve] = 0
		for hist in hashtag['history'][:last_days]:
			count = int(hist['uses'])
			cve_counts[cve] += count
			# day = hist['day']

		# get posts by hashtag
		if cve_counts[cve] > 0:
			if cve not in cve_posts:
				cve_posts[cve] = []
			cve_posts[cve].extend(get_hashtag_timeline("https://infosec.exchange", hashtag['name'], auth_token=IFSX_AUTH_TOKEN))
			cve_posts[cve].extend(get_hashtag_timeline("https://ioc.exchange", hashtag['name'], auth_token=IOCX_AUTH_TOKEN))

	# get posts by statuses (toots) search
	post_search_results = []
	post_search_results.extend(search_poll("https://infosec.exchange", "CVE-", search_type="statuses", auth_token=IFSX_AUTH_TOKEN, last_days=last_days))
	post_search_results.extend(search_poll("https://ioc.exchange", "CVE-", search_type="statuses", auth_token=IOCX_AUTH_TOKEN, last_days=last_days))
	for result in post_search_results:
		cves = re.findall(CVE_PATTERN, result["content"])
		cves = list(set(cves)) #dedup
		# print('extracted:', cves)
		for cve in cves:
			cve = normalize_cve(cve)
			if cve not in cve_posts:
				cve_posts[cve] = []
			if result not in cve_posts[cve]: # no dup
				cve_posts[cve].append(result)
				if cve not in cve_counts:
					cve_counts[cve] = 0
				cve_counts[cve] += 1


	# for cve in sorted(cve_counts, key=cve_counts.get, reverse=True): # most popular cves
		# if cve_counts[cve] != 0:
		# 	print(f"{cve} uniq hashtags:{cve_counts[cve]} posts:{len(cve_posts[cve])}")

	h2t = html2text.HTML2Text()


	print(f"total {len(cve_posts)} CVEs")
	if TESTMODE:
		print("TESTMODE, limiting number of results..")
		cve_posts = dict([(key, cve_posts[key]) for key in list(cve_posts.keys())[:3]+list(cve_posts.keys())[-2:]])


	# get epss data
	print('getting EPSS data..')
	lstart = time.time()
	epss_data = first_epss_for_cves_list(list(cve_posts.keys()))
	print(len(epss_data))
	# XXX for debugging epss data
	with open('epss.json','w') as f:
		json.dump(epss_data, f, indent=2)
	print("done getting EPSS data: ", time.time()-lstart)


	print("getting CVE details...")
	lstart = time.time()
	cve_details = {}
	for cve in cve_posts:
		cve_data = None
		try:
			cve_data = nvd_cve_detail(cve)
			time.sleep(5.8)
			if cve_data:
				if cve_data['totalResults'] > 0:
					cve_data = cve_data['vulnerabilities'][0]
				else:
					cve_data = None
		except Exception as e:
			print("Exception trying to get cve details:", e)

		if cve_data != None:
			cve_details[cve] = cve_data
		else:
			print(f"WARNING: no cve data found on {cve}")


	# one big JSON blob for the page to render
	fedi_cve_feed = {} #cve:...

	print("done getting CVE details:", time.time()-lstart)

	print("getting github repos..")
	cve_repos = {} # cve:[repo_urls]
	lstart = time.time()
	for cve in cve_posts:
		github_repos = get_github_repos(cve)
		cve_repos[cve] = github_repos
	print("done getting github repos:", time.time()-lstart)


	for cve in cve_posts:
		fedi_cve_feed[cve] = {}
		fedi_cve_feed[cve]['cvss3'] = 0
		fedi_cve_feed[cve]['severity'] = None
		# fedi_cve_feed[cve]['epss'] = 0
		fedi_cve_feed[cve]['epss_severity'] = None
		fedi_cve_feed[cve]['posts'] = []
		fedi_cve_feed[cve]['description'] = "N/A"
		fedi_cve_feed[cve]['repos'] = cve_repos[cve]

		for d in epss_data:
			if d['cve'] == cve:
				fedi_cve_feed[cve]['epss'] = float(d['epss']) * 100
				# epss severity is just done here for coloring; it's not part of any spec that defines levels
				if fedi_cve_feed[cve]['epss'] >= 80:
					fedi_cve_feed[cve]['epss_severity'] = "CRITICAL"
				elif fedi_cve_feed[cve]['epss'] >= 50:
					fedi_cve_feed[cve]['epss_severity'] = "HIGH"
				elif fedi_cve_feed[cve]['epss'] >= 20:
					fedi_cve_feed[cve]['epss_severity'] = "MEDIUM"
				else:
					fedi_cve_feed[cve]['epss_severity'] = "LOW"

		if 'epss' not in fedi_cve_feed[cve]:
			fedi_cve_feed[cve]['epss'] = 0

		for post in cve_posts[cve]:
			# filter using created_at for recent days only
			dt = datetime.datetime.fromisoformat(post['created_at'].split('.')[0])
			if (datetime.datetime.utcnow() - dt) > datetime.timedelta(days=last_days): # more than N last days, skip
				continue

			# convert content to markdown to make XSS-ing this website slightly harder 
			content = "ERROR with html2text parsing"
			try:
				content = h2t.handle(post['content'])
			except Exception as e:
				print("ERROR with html2text parsing:", e)
			fedi_cve_feed[cve]['posts'].append({'account':post['account'],'url':post['url'], 'content':content, 'created_at':post['created_at']})
			

			if cve in cve_details:
				try:
					
					if 'impact' in cve_details[cve]:
						if 'baseMetricV3' in cve_details[cve]['impact']:
							fedi_cve_feed[cve]['cvss3'] = cve_details[cve]['impact']['baseMetricV3']['cvssV3']['baseScore']
							fedi_cve_feed[cve]['severity'] = cve_details[cve]['impact']['baseMetricV3']['cvssV3']['baseSeverity']

					elif 'metrics' in cve_details[cve]['cve']:
						if 'cvssMetricV30' in cve_details[cve]['cve']['metrics']:
							fedi_cve_feed[cve]['cvss3'] = cve_details[cve]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
							fedi_cve_feed[cve]['severity'] = cve_details[cve]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
						if 'cvssMetricV31' in cve_details[cve]['cve']['metrics']:
							fedi_cve_feed[cve]['cvss3'] = cve_details[cve]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
							fedi_cve_feed[cve]['severity'] = cve_details[cve]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']



					if 'description' in cve_details[cve]['cve'] and len(cve_details[cve]['cve']['description']['description_data']) > 0:
						fedi_cve_feed[cve]['description'] = cve_details[cve]['cve']['description']['description_data'][0]['value']
					elif 'descriptions' in cve_details[cve]['cve'] and len(cve_details[cve]['cve']['descriptions']) > 0:
						fedi_cve_feed[cve]['description'] = cve_details[cve]['cve']['descriptions'][0]['value']


				except Exception as e:
					print(f"Error parsing cve detail on {cve}:", e, cve_details[cve])

			# print(f"{cve} {author_acct} {content}")
		if len(fedi_cve_feed[cve]['posts']) == 0:
			# remove cve if there are no posts
			del fedi_cve_feed[cve]



	outfile = 'fedi_cve_feed.json'
	with open(outfile, 'w+') as f:
		json.dump(fedi_cve_feed, f, indent=2)

	from renderer import render
	render(outfile)

	print(f'done, written output to {outfile}. total elapsed:', time.time() - start)

if __name__ == "__main__":
	main()
