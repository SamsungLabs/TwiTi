import logging
import time
from enum import IntEnum
from queue import Queue
from typing import Callable, Optional

import requests
from requests.exceptions import RequestException

from config import config

RATE_LIMIT_EXCEED = 204

SERVER = 'https://www.virustotal.com'
API_V2 = f'{SERVER}/vtapi/v2'
URL_REPORT = f'{API_V2}/url/report'
logger = logging.getLogger(__name__)


class ResponseCode(IntEnum):
    QUEUED = -2
    NOT_FOUND = 0
    OK = 1


def _json(r: requests.Response) -> dict:
    r.raise_for_status()
    if r.status_code == RATE_LIMIT_EXCEED:
        raise RateLimitException()
    return r.json()


def url_report(api_key: str, url: str, all_info: bool = True, scan: bool = False, proxy: bool = False) -> dict:
    params = {
        'apikey': api_key,
        'resource': url,
        'allinfo': all_info,
        'scan': 1 if scan else 0
    }
    return _json(requests.get(URL_REPORT, params=params))


class VirusTotal:
    def __init__(self):
        try:
            self.api_key = config['VirusTotal']['API_KEY'][0]
        except KeyError as e:
            logger.exception("Failed to read configurations for VirusTotal")
            raise KeyError("Failed to read configurations for VirusTotal") from e

    def url_report(self, url: str, all_info: bool = True, scan: bool = False) -> Optional[dict]:
        report = url_report(self.api_key, url, all_info, scan)
        return report if report['response_code'] == ResponseCode.OK else None


class RateLimitException(Exception):
    def __init__(self, message: str = 'Rate limit exceeded'):
        self.message = message
