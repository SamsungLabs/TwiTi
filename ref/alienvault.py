import ipaddress
import logging
import time
from enum import Enum
from functools import wraps

import IndicatorTypes
from OTXv2 import OTXv2, RetryError

from config import config

REQUEST_DELAY = 3
logger = logging.getLogger(__name__)


class HashtypeByLen(Enum):
    MD5 = 32, IndicatorTypes.FILE_HASH_MD5
    SHA1 = 40, IndicatorTypes.FILE_HASH_SHA1
    SHA256 = 64, IndicatorTypes.FILE_HASH_SHA256

    def __new__(cls, *args, **kwargs):
        obj = object.__new__(cls)
        obj._value_ = args[0]
        return obj

    def __init__(self, _, indicator_type):
        self.indicator_type = indicator_type


def _delay_request(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        interval = time.time() - self.prev_request_time
        if interval < REQUEST_DELAY:
            time.sleep(REQUEST_DELAY - interval)
        res = func(self, *args, **kwargs)
        self.prev_request_time = time.time()
        return res
    return wrapper


class AlienVault:
    def __init__(self):
        try:
            api_key = config['AlienVault']['API_KEY']
        except KeyError as e:
            raise KeyError("Failed to read configurations for AlienVault") from e
        self.otx = OTXv2(api_key)
        self.prev_request_time = 0

    @_delay_request
    def ip_report(self, ip: str) -> dict:
        ip_ver = ipaddress.ip_address(ip).version
        indicator = IndicatorTypes.IPv4 if ip_ver == 4 else IndicatorTypes.IPv6
        return self.otx.get_indicator_details_full(indicator, ip)

    @_delay_request
    def file_report(self, file_hash: str) -> dict:
        hash_type = HashtypeByLen(len(file_hash)).indicator_type
        try:
            return self.otx.get_indicator_details_full(hash_type, file_hash)
        except RetryError:
            return {
                'general': self.file_report_only_general(file_hash),
                'analysis': {'malware': {}, 'page_type': 'generic', 'analysis': None}
            }

    @_delay_request
    def file_report_only_general(self, file_hash: str) -> dict:
        hash_type = HashtypeByLen(len(file_hash)).indicator_type
        return self.otx.get_indicator_details_by_section(hash_type, file_hash, 'general')

    @_delay_request
    def url_report(self, url: str) -> dict:
        return self.otx.get_indicator_details_full(IndicatorTypes.URL, url)

    @_delay_request
    def pulse_indicators_report(self, pulse_id: str) -> dict:
        # Experimental parameter limit=5000
        # To reduce the number of http requests with pulses which have
        # huge amount of iocs, limit has been increased to 5000
        return self.otx.get_pulse_indicators(pulse_id, limit=5000)
