from config import api


def test_get_vendors():
    print(api.get_vendors())


def test_get_products():
    print(api.get_products())


def test_add_exploits():
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


test_get_vendors()
test_add_exploits()
test_get_products()
