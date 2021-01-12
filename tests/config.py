from patrowlhears4py.api import PatrowlHearsApi
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get('PATROWLHEARS_BASE_URL', 'http://localhost:3333')
AUTH_TOKEN = os.environ.get('PATROWLHEARS_AUTH_TOKEN', '8f6c4507dbaca74e67e8438583e2c0de4bc07fb2')


api = PatrowlHearsApi(url=BASE_URL, auth_token=AUTH_TOKEN)
