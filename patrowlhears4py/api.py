import requests
from patrowlhears4py.exceptions import PatrowlHearsException

VULN_ATTRS = {
    'access_authentication': {
        'values': ['NONE', 'SINGLE', 'MULTIPLE'], 'default': 'NONE'
    },
    'access_complexity': {
        'values': ['LOW', 'MEDIUM', 'HIGH'], 'default': 'LOW'
    },
    'access_vector': {
        'values': ['LOCAL', 'ADJACENT_NETWORK', 'NETWORK'], 'default': 'LOCAL'
    },
    'impact_availability': {
        'values': ['NONE', 'PARTIAL', 'COMPLETE'], 'default': 'NONE'
    },
    'impact_confidentiality': {
        'values': ['NONE', 'PARTIAL', 'COMPLETE'], 'default': 'NONE'
    },
    'impact_integrity': {
        'values': ['NONE', 'PARTIAL', 'COMPLETE'], 'default': 'NONE'
    },
}


class PatrowlHearsApi:
    """Python API for PatrowlHears."""

    def __init__(self, url, auth_token, proxies={}, ssl_verify=False, timeout=10):
        """
        Initialize a PatrowlHearsApi object.

        :param url: PatrowlHears base URL
        :param auth_token: The API key
        :param proxies: The HTTP/HTTPS proxy endpoints
        :param ssl_verify: SSL/TLS certificate verification
        :param timeout: Request timeout (in sec)
        """
        self.url = url
        self.auth_token = auth_token
        self.timeout = timeout
        self.rs = requests.Session()
        # self.rs.headers['Authorization'] = 'Token {}'.format(auth_token)
        self.rs.headers.update({'Authorization': 'Token {}'.format(auth_token)})
        self.rs.proxies = proxies
        self.rs.verify = ssl_verify
        self.rs.timeout = timeout

    # Generic command
    def action(self, url, method='GET', data=None, params={}):
        """
        Call a generic action.

        :param url: API endpoint
        :param method: HTTP method ('GET', 'POST', 'DELETE', 'PUT', 'PATCH')
        :param data: HTTP data
        :rtype: json
        """
        if method.upper() not in ['GET', 'POST', 'DELETE', 'PUT', 'PATCH']:
            raise PatrowlHearsException("Bad method: {}".format(method))

        try:
            r = requests.Request(
                method=method.upper(),
                url=self.url+url,
                data=data,
                params=params,
                headers={
                    'Authorization': 'Token {}'.format(self.auth_token),
                    'Content-Type': 'application/json'
                }
            )
            pr = r.prepare()
            return self.rs.send(pr).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln: {}".format(e))

    # Vulnerabilities
    def get_latest_vulns(self):
        """
        Get latest vulnerabilities.

        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/latest").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln: {}".format(e))

    def get_vulns_stats(self):
        """
        Get vulnerability statistics.

        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/stats").json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln stats: {}".format(e))

    def search_vulns(self, cveid=None, monitored=None, search=None, vendor_name=None, product_name=None, product_version=None, cpe=None, page=1, limit=10):
        """
        Get vulnerabilities from criterias.

        :param cveid: CVE-ID
        :param monitored: Return only monitored items
        :param search: search entry
        :param vendor_name: Vendor name
        :param product_name: Product name
        :param product_version: Product version
        :param cpe: CPE vector
        :param page: Page number of results
        :param limit: Max results per page. Default is 10, Max is 100 (Optional)
        :rtype: json
        """
        filters = "?page={}&limit={}".format(page, limit)
        if cveid is not None and cveid != '':
            filters += "&cveid={}".format(cveid)
        if monitored is not None:
            filters += "&monitored={}".format(str(monitored).lower())
        if search is not None and search != '':
            filters += "&search={}".format(str(search))
        if vendor_name is not None and vendor_name != '':
            filters += "&vendor_name={}".format(str(vendor_name).lower())
        if product_name is not None and product_name != '':
            filters += "&product_name={}".format(str(product_name).lower())
        if product_version is not None and product_version != '':
            filters += "&product_version={}".format(str(product_version).lower())
        if cpe is not None and cpe != '':
            filters += "&cpe={}".format(str(cpe).lower())

        try:
            return self.rs.get(self.url+"/api/vulns/?{}".format(filters)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln: {}".format(e))

    def add_vuln(self, vuln):
        """
        Add a new vulnerability.

        :param vuln: Vulnerability dict
        :rtype: json
        """
        attrs = ['summary']
        if all(elem in vuln.keys() for elem in attrs) is False:
            raise PatrowlHearsException("Missing parameters")

        data = {
            'cve_id': '',
            'summary': vuln['summary'],
        }
        for attr in vuln.keys():
            if attr == 'cve_id':
                data.update({'cve_id': vuln['cve_id'].upper()})
            if attr == 'cvss2':
                data.update({'cvss2': vuln['cvss2']})
            if attr == 'cvss2_vector':
                data.update({'cvss2_vector': vuln['cvss2_vector']})
            if attr == 'cvss3':
                data.update({'cvss3': vuln['cvss3']})
            if attr == 'cvss3_vector':
                data.update({'cvss3_vector': vuln['cvss3_vector']})
            if attr == 'cwe':
                data.update({'cwe': vuln['cwe']})
            if attr == 'cpes':
                data.update({'cpes': vuln['cpes']})

            if attr == 'access_authentication':
                if vuln['access_authentication'] in VULN_ATTRS['access_authentication']['values']:
                    data.update({'access_authentication': vuln['access_authentication']})
                else:
                    data.update({'access_authentication': VULN_ATTRS['access_authentication']['default']})
            if attr == 'access_complexity':
                if vuln['access_complexity'] in VULN_ATTRS['access_complexity']['values']:
                    data.update({'access_complexity': vuln['access_complexity']})
                else:
                    data.update({'access_complexity': VULN_ATTRS['access_complexity']['default']})
            if attr == 'access_vector':
                if vuln['access_vector'] in VULN_ATTRS['access_vector']['values']:
                    data.update({'access_vector': vuln['access_vector']})
                else:
                    data.update({'access_vector': VULN_ATTRS['access_vector']['default']})
            if attr == 'impact_confidentiality':
                if vuln['impact_confidentiality'] in VULN_ATTRS['impact_confidentiality']['values']:
                    data.update({'impact_confidentiality': vuln['impact_confidentiality']})
                else:
                    data.update({'impact_confidentiality': VULN_ATTRS['impact_confidentiality']['default']})
            if attr == 'impact_integrity':
                if vuln['impact_integrity'] in VULN_ATTRS['impact_integrity']['values']:
                    data.update({'impact_integrity': vuln['impact_integrity']})
                else:
                    data.update({'impact_integrity': VULN_ATTRS['impact_integrity']['default']})
            if attr == 'impact_availability':
                if vuln['impact_availability'] in VULN_ATTRS['impact_availability']['values']:
                    data.update({'impact_availability': vuln['impact_availability']})
                else:
                    data.update({'impact_availability': VULN_ATTRS['impact_availability']['default']})

            if attr == 'monitored' and type(vuln['monitored']) is bool:
                data.update({'monitored': vuln['monitored']})
            if attr == 'is_exploitable' and type(vuln['is_exploitable']) is bool:
                data.update({'is_exploitable': vuln['is_exploitable']})
            if attr == 'is_confirmed' and type(vuln['is_confirmed']) is bool:
                data.update({'is_confirmed': vuln['is_confirmed']})
            if attr == 'is_in_the_news' and type(vuln['is_in_the_news']) is bool:
                data.update({'is_in_the_news': vuln['is_in_the_news']})
            if attr == 'is_in_the_wild' and type(vuln['is_in_the_wild']) is bool:
                data.update({'is_in_the_wild': vuln['is_in_the_wild']})
            if attr == 'cpes' and type(vuln['cpes']) is str:
                data.update({'cpes': vuln['cpes']})
            if attr == 'products' and type(vuln['products']) is list:
                data.update({'products': vuln['products']})
            if attr == 'references':
                data.update({'references': vuln['references']})

        try:
            return self.rs.post(self.url+"/api/vulns/add", data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to add vuln: {}".format(e))

    def get_vuln(self, vuln_id):
        """
        Get vulnerability info by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln: {}".format(e))

    def get_vuln_exploits(self, vuln_id):
        """
        Get exploits related to a vulnerability by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/exploits".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln exploits: {}".format(e))

    # def add_vuln_exploit(self, vuln_id, exploit):
    #     """
    #     Add exploit related to a vulnerability by his ID.
    #
    #     :param vuln_id: Vulnerability ID
    #     :param exploit: Exploit data (dict)
    #     :rtype: json
    #     """
    #     print(exploit)
        # try:
        #     return self.rs.post(self.url+"/api/vulns/{}/exploits/add".format(vuln_id)).json()
        # except requests.exceptions.RequestException as e:
        #     raise PatrowlHearsException("Unable to retrieve vuln exploits: {}".format(e))

    def get_vuln_threats(self, vuln_id):
        """
        Get threats related to a vulnerability by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/threats".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln threats: {}".format(e))

    def get_vuln_history(self, vuln_id):
        """
        Get vulnerability changes history by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/history".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to get vuln history: {}".format(e))

    def toggle_vuln_monitoring(self, vuln_id):
        """
        Toggle monitoring status of a vulnerability by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/toggle".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to toggle vuln monitoring status: {}".format(e))

    def refresh_vuln_score(self, vuln_id):
        """
        Refresh vulnerability score by his ID.

        :param vuln_id: Vulnerability ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/refresh_score".format(vuln_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to refresh vuln score: {}".format(e))

    def get_data_info(self, since=None, to=None):
        """
        Get static data info.

        :param since: Search data from date (format: YYYY-MM-DD). Optional.
        :param to: Search data to date (format: YYYY-MM-DD). Optional.
        :rtype: json
        """
        url = self.url+"/api/data/export/info?"
        if since is not None:
            url = "{}&since={}".format(url, since)
        if to is not None:
            url = "{}&to={}".format(url, to)
        try:
            return self.rs.get(url).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve data info: {}".format(e))

    def export_data(self, since=None, to=None, limit=None):
        """
        Export static data.

        :param since: Search data from date (format: YYYY-MM-DD). Optional.
        :param to: Search data to date (format: YYYY-MM-DD). Optional.
        :param limit: Limit rows per table. Optional.
        :rtype: json
        """
        url = self.url+"/api/data/export/full?"
        if since is not None:
            url = "{}&since={}".format(url, since)
        if to is not None:
            url = "{}&to={}".format(url, to)
        if limit is not None:
            url = "{}&limit={}".format(url, limit)
        print(url)
        try:
            return self.rs.get(url).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve data: {}".format(e))

    def add_exploit(self, exploit):
        """
        Add exploit (based on CVE-ID).

        :param exploit: Exploit
        :rtype: json
        """
        attrs = ['link', 'cveid']
        if all(elem in exploit.keys() for elem in attrs) is False:
            raise PatrowlHearsException("Missing parameters")

        data = {
            'link': exploit['link'],
            'cveid': exploit['cveid'].upper(),
            'notes': 'Added by PatrowlFeeds',
            'trust_level': 'medium',
            'tlp_level': 'amber',
            'source': 'patrowl',
            'availability': 'public',
            'type': 'unknown',
            'maturity': 'poc',
            'submit_type': 'exploit'
        }
        for attr in exploit.keys():
            if attr == 'notes':
                data.update({'notes': exploit['notes']})
            if attr == 'trust_level':
                data.update({'trust_level': exploit['trust_level']})
            if attr == 'tlp_level':
                data.update({'tlp_level': exploit['tlp_level']})
            if attr == 'source':
                data.update({'source': exploit['source']})
            if attr == 'availability':
                data.update({'availability': exploit['availability']})
            if attr == 'type':
                data.update({'type': exploit['type']})
            if attr == 'maturity':
                data.update({'maturity': exploit['maturity']})

        try:
            return self.rs.post(self.url+"/api/data/submit", data).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve data: {}".format(e))

    def del_org_exploit(self, vuln_id, exploit_id):
        """
        Delete exploit (based on CVE-ID).

        :param vuln_id: Vuln ID
        :param exploit_id: Exploit ID
        :rtype: json
        """
        try:
            return self.rs.get(self.url+"/api/vulns/{}/exploits/{}/del".format(vuln_id, exploit_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to delete exploit: {}".format(e))

    # Vendors and products
    def get_vendors(self, search=None, monitored=False, page=1, limit=10):
        """
        Get vendors.

        :param search: filter on name (Optional)
        :param page: Page number of results (Optional)
        :param monitored: Return only monitored vendors (Optional)
        :param limit: Max results per page. Default is 10, Max is 100 (Optional)
        :rtype: json
        """
        params = "?page={}&limit={}".format(page, limit)
        if search not in [None, '']:
            params += "&search={}".format(search)
        if monitored is True:
            params += "&monitored=true"

        try:
            return self.rs.get(self.url+"/api/kb/vendors/{}".format(params)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to list vendors: {}".format(e))

    def get_products(self, vendor_id=None, search=None, monitored=False, page=1, limit=10):
        """
        Get products from a vendor.

        :param vendor_id: Vendor ID
        :param search: filter on name (Optional)
        :param page: Page number of results (Optional)
        :param monitored: Return only monitored vendors (Optional)
        :param limit: Max results per page. Default is 10, Max is 100 (Optional)
        :rtype: json
        """
        params = "?page={}&limit={}".format(page, limit)
        if vendor_id not in [None, '']:
            params += "&vendor_id={}".format(vendor_id)
        if search not in [None, '']:
            params += "&search={}".format(search)
        if monitored is True:
            params += "&monitored=true"

        try:
            return self.rs.get(self.url+"/api/kb/vendors/{}".format(params)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to list vendors: {}".format(e))
