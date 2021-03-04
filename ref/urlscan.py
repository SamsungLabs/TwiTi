import requests

SERVER = 'https://urlscan.io'
API_V1 = f'{SERVER}/api/v1'
RESULT_API = f'{API_V1}/result'


class UrlScan:
    def result(self, uuid: str):
        r = requests.get(f'{RESULT_API}/{uuid}')
        r.raise_for_status()
        return r.json()
