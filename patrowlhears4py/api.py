import requests

from patrowlhears4py.exceptions import PatrowlHearsException


class PatrowlHearsApi:
    """Python API for PatrowlHears."""

    def __init__(self, url, auth_token, proxies={}, ssl_verify=False, timeout=10):
        """
        Initialize a PatrowlHearsApi object.

        :param url: PatrowlHears URL
        :param auth_token: The API key
        :param proxies: The HTTP/HTTPS proxy endpoints
        :param ssl_verify: SSL/TLS certificate verification
        :param timeout: Request timeout (in sec)
        """
        self.url = url
        self.rs = requests.Session()
        self.rs.headers['Authorization'] = 'Token {}'.format(auth_token)
        self.rs.proxies = proxies
        self.rs.verify = ssl_verify
        self.rs.timeout = timeout

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

    def search_vulns(self, cveid=None, monitored=None):
        """
        Get vulnerabilities from criterias.

        :param cveid: CVE-ID
        :param monitored: Is monitored
        :rtype: json
        """
        filters = ""
        if cveid is not None:
            filters += "&cveid={}".format(cveid)
        if monitored is not None:
            filters += "&monitored={}".format(str(monitored).lower())

        try:
            return self.rs.get(self.url+"/api/vulns/?{}".format(filters)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to retrieve vuln: {}".format(e))

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
        Add exploit (based on CVE-ID)

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
        Delete exploit (based on CVE-ID)

        :param vuln_id: Vuln ID
        :param exploit_id: Exploit ID
        :rtype: json
        """

        try:
            return self.rs.get(self.url+"/api/vulns/{}/exploits/{}/del".format(vuln_id, exploit_id)).json()
        except requests.exceptions.RequestException as e:
            raise PatrowlHearsException("Unable to delete exploit: {}".format(e))
