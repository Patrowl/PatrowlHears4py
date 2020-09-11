from patrowlhears4py.api import PatrowlHearsApi


api = PatrowlHearsApi(
    url='http://localhost:3333',
    auth_token='774c5c9d7908a6d970be392cf54b20ddca1d0319'
)

# print(api.get_latest_vulns())
# print(api.get_vulns_stats())
# print(api.get_vuln(333))
# print(api.get_vuln_exploits(333))
# print(api.get_vuln_threats(333))
# print(api.get_vuln_history(333))
# print(api.toggle_vuln_monitoring(333))
# print(api.toggle_vuln_monitoring(333))  # Yes, twice bro.
# print(api.refresh_vuln_score(333))
# print(api.search_vulns(cveid="CVE-2011-4595"))

# exploit = {
#   "source": "packetstorm",
#   "type": "exploit",
#   "checked_at": "2020-09-10 15:48:11.707857",
#   "id": "35576",
#   "title": "wins.c",
#   "details": "Remote Microsoft Windows 2000 WINS exploit that has connectback shellcode. Works on SP3/SP4.",
#   "md5": "bca4ce46995ede27531c85fe556c98c2",
#   "published_at": "2005-01-02 20:43:36",
#   "view_link": "https://packetstormsecurity.com/files/35576/wins.c.html",
#   "dl_link": "https://packetstormsecurity.com/files/download/35576/wins.c",
#   "CVE": ["CVE-2008-5331"]
# }


exploit = {
    'link': "https://packetstormsecurity.com/files/35576/wins.c.html",
    'cveid': "CVE-2008-5331",
    'notes': "Remote Microsoft Windows 2000 WINS exploit that has connectback shellcode. Works on SP3/SP4.",
    'trust_level': 'high',
    'tlp_level': 'white',
    'source': 'packetstorm',
    'availability': 'public',
    'type': 'unknown',
    'maturity': 'poc',
    'submit_type': 'exploit'
}
print(api.add_exploit(exploit=exploit))
