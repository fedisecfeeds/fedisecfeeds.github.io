#!/usr/bin/env python3

import requests
import json
import os
import time
import datetime
import random
import re
from urllib.parse import quote_plus
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

# blocked accounts for excessive noise / automation / spam or other reasons.
# we want real posts by real people; not automated bots that spam every CVE
BLOCKED_ACCTS = ['RedPacketSecurity@mastodon.social']

start = time.time()

def has_digits(s):
	return any(char.isdigit() for char in s)

def normalize_cve(cvestr):
	'''
	normalize a cve string to CVE-YYYY-ZZZZZ
	'''
	if not (cvestr.upper().startswith("CVE") and has_digits(cvestr) and len(cvestr) > 10): # validate it
		print(f"INFO: invalid cve str {cvestr}")
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

def ghsa_cve_detail(cve):
	'''
	get cve data from the github security advisory api
	https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
	'''

	time.sleep(2) # rate limit, just to be safe 

	headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {GITHUB_TOKEN}", "X-GitHub-Api-Version": "2022-11-28"}

	url = f'https://api.github.com/advisories?cve_id={cve}'

	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)

	return r.json()




def nvd_cve_detail(cve):
	'''
	get cve detail (like cvss score) from the nvd api 
	https://nvd.nist.gov/developers/vulnerabilities

	it's unreliable AF
	'''
	url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
	r = requests.get(url)
	if r.status_code == 403:
		print("rate limited by assholes at NVD, sleeping.. error message:", r.text)
		time.sleep(6.1)
		r = requests.get(url)
		if r.status_code == 403:
			return None
	if r.status_code not in [200, 403]:
		print(f"WARN: bad nvd api status for {cve}", r.status_code, r.text[:100])
		return None
	else:
		return r.json()

def get_nuclei_template(cve):
	'''
	use github's API to search and return nuclei template
	'''
	headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {GITHUB_TOKEN}", "X-GitHub-Api-Version": "2022-11-28"}
	q = f'repo:projectdiscovery/nuclei-templates {cve}'
	url = f'https://api.github.com/search/code?q={quote_plus(q)}'

	time.sleep(2)
	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)
			return get_nuclei_template(cve)

	d = r.json()
	if 'total_count' not in d:
		return None
	if d['total_count'] > 0:
		for item in d['items']:
			if item['path'].endswith(f"{cve}.yaml"):
				return item['html_url']

	return None

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

	# bloody rate limit
	time.sleep(2)

	# search generically, without "in:.."
	# > When you omit this qualifier, only the repository name, description, and topics are searched.
	# in:readme sucks and returns false positives instead of actual PoCs
	url = f'https://api.github.com/search/repositories?q={cve}&per_page=100'
	headers = {'Accept':'application/vnd.github+json', 'Authorization': f'Bearer {GITHUB_TOKEN}', 'X-GitHub-Api-Version': '2022-11-28'}
	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)
		return ['#search_error']

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

def filter_posts(posts):
	filtered_posts = []
	filtered_count = 0
	for p in posts:
		if p['account']['acct'] in BLOCKED_ACCTS:
			filtered_count += 1
			continue
		filtered_posts.append(p)
	print(f"filtered out {filtered_count} posts")
	return filtered_posts

def main():


	# hashtags = []
	# hashtags.extend(search_poll("https://infosec.exchange","CVE", auth_token=IFSX_AUTH_TOKEN))
	# hashtags.extend(search_poll("https://ioc.exchange","CVE", auth_token=IOCX_AUTH_TOKEN))


	# get most used, trending past N days
	last_days = 14

	cve_counts = {}
	cve_posts = {}

	# for hashtag in hashtags:

	# 	cve = normalize_cve(hashtag['name'])
	# 	if cve == None:
	# 		# skip hashtag that are invalid
	# 		continue
	# 	if cve not in cve_counts:
	# 		cve_counts[cve] = 0
	# 	for hist in hashtag['history'][:last_days]:
	# 		count = int(hist['uses'])
	# 		cve_counts[cve] += count
	# 		# day = hist['day']

	# 	# get posts by hashtag
	# 	if cve_counts[cve] > 0:
	# 		if cve not in cve_posts:
	# 			cve_posts[cve] = []
	# 		cve_posts[cve].extend(filter_posts(get_hashtag_timeline("https://infosec.exchange", hashtag['name'], auth_token=IFSX_AUTH_TOKEN)))
	# 		cve_posts[cve].extend(filter_posts(get_hashtag_timeline("https://ioc.exchange", hashtag['name'], auth_token=IOCX_AUTH_TOKEN)))

	# get posts by statuses (toots) search
	post_search_results = []
	post_search_results.extend(filter_posts(search_poll("https://infosec.exchange", "CVE-", search_type="statuses", auth_token=IFSX_AUTH_TOKEN, last_days=last_days)))
	post_search_results.extend(filter_posts(search_poll("https://ioc.exchange", "CVE-", search_type="statuses", auth_token=IOCX_AUTH_TOKEN, last_days=last_days)))
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

	# h2t = html2text.HTML2Text()


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
			if cve_data == None:
				print("NVD fell thru, using GHSA as a fallback")
				cve_data = ghsa_cve_detail(cve)
				if len(cve_data) == 0:
					cve_data = None
					print(f"WARNING: no cve data found on {cve}")
				else:
					cve_details[cve] = cve_data[0] # for GHSA a JSON list is returned, index the first result
			else:
				# NVD has a even worse schema
				cve_details[cve] = cve_data['vulnerabilities'][0]
		except Exception as e:
			print("Exception trying to get cve details:", e)



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
		# Final stage - fedi_cve_feed is the dictionary that will be pumped to the front end
		fedi_cve_feed[cve] = {}
		fedi_cve_feed[cve]['cvss3'] = 0
		fedi_cve_feed[cve]['severity'] = None
		# fedi_cve_feed[cve]['epss'] = 0
		fedi_cve_feed[cve]['epss_severity'] = None
		fedi_cve_feed[cve]['nuclei'] = get_nuclei_template(cve)
		fedi_cve_feed[cve]['posts'] = []
		fedi_cve_feed[cve]['description'] = "N/A"
		fedi_cve_feed[cve]['repos'] = cve_repos[cve]
		fedi_cve_feed[cve]['updated'] = None

		for d in epss_data:
			if d['cve'] == cve:
				fedi_cve_feed[cve]['epss'] = float(d['epss']) * 100
				# epss severity is just done here for coloring; it's not part of any spec that defines levels
				if fedi_cve_feed[cve]['epss'] >= 50:
					fedi_cve_feed[cve]['epss_severity'] = "CRITICAL"
				elif fedi_cve_feed[cve]['epss'] >= 20:
					fedi_cve_feed[cve]['epss_severity'] = "HIGH"
				elif fedi_cve_feed[cve]['epss'] >= 10:
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

			# # convert content to markdown to make XSS-ing this website slightly harder 
			# content = "ERROR with html2text parsing"
			# try:
			# 	content = h2t.handle(post['content']).replace("- ", "-") # fix link separation issue with dashes
			# except Exception as e:
			# 	print("ERROR with html2text parsing:", e)

			fedi_cve_feed[cve]['posts'].append({'account':post['account'],'url':post['url'], 'content':post['content'], 'created_at':post['created_at']})
			

			if cve in cve_details:
				try:
					# Github security advisory db https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
					if 'description' in cve_details[cve]:  # GHSA
						if 'cvss' in cve_details[cve]:
							fedi_cve_feed[cve]['cvss3'] = cve_details[cve]['cvss']['score']
						if 'description' in cve_details[cve]:
							fedi_cve_feed[cve]['description'] = cve_details[cve]['description']
						# if 'severity' in cve_details[cve]:
						# 	fedi_cve_feed[cve]['severity'] = cve_details[cve]['severity'].upper()

						if fedi_cve_feed[cve]['cvss3']:
							if fedi_cve_feed[cve]['cvss3'] > 0 and fedi_cve_feed[cve]['cvss3'] < 4:
								fedi_cve_feed[cve]['severity'] = 'LOW'
							elif fedi_cve_feed[cve]['cvss3'] > 4 and fedi_cve_feed[cve]['cvss3'] < 7:
								fedi_cve_feed[cve]['severity'] = 'MEDIUM'
							elif fedi_cve_feed[cve]['cvss3'] > 7 and fedi_cve_feed[cve]['cvss3'] < 9:
								fedi_cve_feed[cve]['severity'] = 'HIGH'
							elif fedi_cve_feed[cve]['cvss3'] > 9:
								fedi_cve_feed[cve]['severity'] = 'CRITICAL'

						fedi_cve_feed[cve]['updated'] = str((datetime.datetime.fromisoformat(cve_details[cve]['updated_at'].rstrip("Z"))).isoformat())

						continue


					################### CODE PARSING NVD API ##############
					# The schema sucks
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
					# normalize the date by isoformat
					fedi_cve_feed[cve]['updated'] = str(datetime.datetime.fromisoformat(cve_details[cve]['cve']['lastModified']).isoformat())
						

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
