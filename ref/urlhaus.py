import requests

SERVER = 'https://urlhaus-api.abuse.ch'
API_V1 = f'{SERVER}/v1'
URLID_API = f'{API_V1}/urlid'
HOST_API = f'{API_V1}/host'


class Urlhaus:
    def query_urlid(self, urlid: str):
        r = requests.post(f'{URLID_API}', {'urlid': urlid})
        r.raise_for_status()
        return r.json()

    def query_host(self, host: str):
        r = requests.post(f'{HOST_API}', {'host': host})
        r.raise_for_status()
        return r.json()
