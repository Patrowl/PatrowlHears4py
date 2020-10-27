from patrowlhears4py.api import PatrowlHearsApi
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get('PATROWLHEARS_BASE_URL', 'http://localhost:3333')
AUTH_TOKEN = os.environ.get('PATROWLHEARS_AUTH_TOKEN', '774c5c9d7908a6d970be392cf54b20ddca1d0319')


api = PatrowlHearsApi(url=BASE_URL, auth_token=AUTH_TOKEN)
