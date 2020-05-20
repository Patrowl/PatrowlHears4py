from patrowlhears4py.api import PatrowlHearsApi


api = PatrowlHearsApi(
    url='http://test-hears.patrowl.io:8081',
    auth_token='5a13cd99aaa7a4aeafe26ad6296519758b8e32a0'
)

print(api.get_latest_vulns())
print(api.get_vulns_stats())
print(api.get_vuln(333))
print(api.get_vuln_exploits(333))
print(api.get_vuln_threats(333))
print(api.get_vuln_history(333))
print(api.toggle_vuln_monitoring(333))
print(api.toggle_vuln_monitoring(333))  # Yes, twice bro.
print(api.refresh_vuln_score(333))
