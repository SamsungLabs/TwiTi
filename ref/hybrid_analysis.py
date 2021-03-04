import logging
import requests
from config import config

logger = logging.getLogger(__name__)

SERVER = 'https://www.hybrid-analysis.com'
API_V2 = f'{SERVER}/api/v2'
FILE_COLLECTION_API = f'{API_V2}/file-collection'


class HybridAnalysis:
    def __init__(self):
        try:
            api_key = config['Hybrid-analysis.com']['API_KEY']
        except KeyError as e:
            raise KeyError("Failed to read configurations for Hybrid-analysis.com") from e
        self.header = {
            'accept': 'application/json',
            'user-agent': 'Falcon Sandbox',
            'api-key': api_key
        }

    def file_collection(self, collection_id: str):
        r = requests.get(f'{FILE_COLLECTION_API}/{collection_id}', headers=self.header)
        r.raise_for_status()
        return r.json()
