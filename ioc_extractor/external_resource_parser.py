import logging
import re
import sys
from collections import defaultdict
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

import requests
from bs4 import BeautifulSoup

from ioc_extractor import INTERESTING_EXTERNALS, ioc_formatter, ioc_polisher
from ioc_extractor.ioc_regex import ioc_regex
from ioc_extractor.ioc_regex_applier import matches_regex
from ref.alienvault import AlienVault
from ref.hybrid_analysis import HybridAnalysis
from ref.urlhaus import Urlhaus
from ref.urlscan import UrlScan
from ref.virustotal import VirusTotal

logger = logging.getLogger(__name__)

PASTEBINSERVER = 'https://pastebin.com/raw/'
hashtypes = ('sha256', 'md5', 'sha1')


def parse_virustotal(link: str) -> Optional[Dict[str, set]]:
    for keyword in ('/file/', '/domain/', '/ip-address/', '/url/'):
        if keyword in link:
            break
    else:
        logger.info(f'Unhandled Virustotal link: {link}')
        return None

    ioc_candidate = link[link.find(keyword) + len(keyword):]
    if ioc_candidate.find('/') != -1:
        ioc_candidate = ioc_candidate[:ioc_candidate.find('/')]

    if keyword == '/file/':
        for hashtype in hashtypes:
            matched = ioc_regex[hashtype].match(ioc_candidate)
            if matched:
                return {hashtype: {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/domain/':
        matched = ioc_regex['domain'].match(ioc_candidate)
        if matched:
            return {'domain': {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/ip-address/':
        matched = ioc_regex['ip'].match(ioc_candidate)
        if matched:
            return {'ip': {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/url/':
        _virustotal = VirusTotal()
        try:
            res = _virustotal.url_report(ioc_candidate, all_info=False, scan=False)
            return {'urls': {res['url']}}
        except Exception as e:
            logger.error(f'While extracting url from VirusTotal, exception occurred: {e}')

    raise Exception(f'Unhandled Virustotal {keyword} link: {link}')


def parse_urlscan(link: str) -> Optional[Dict[str, set]]:
    for keyword in ('/domain/', '/ip/', '/search/', '/result/'):
        if keyword in link:
            break
    else:
        logger.info(f'Unhandled urlscan.io link: {link}')
        return None

    ioc_candidate = link[link.find(keyword) + len(keyword):]
    if ioc_candidate.find('/') != -1:
        ioc_candidate = ioc_candidate[:ioc_candidate.find('/')]

    if keyword == '/domain/':
        matched = ioc_regex['domain'].match(ioc_candidate)
        if matched:
            return {'domain': {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/ip/':
        matched = ioc_regex['ip'].match(ioc_candidate)
        if matched:
            return {'ip': {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/search/':
        return None

    elif keyword == '/result/':
        _urlscan = UrlScan()
        try:
            res = _urlscan.result(ioc_candidate)
            return {'urls': {res['page']['url'], res['task']['url']}, 'ip': {res['page']['ip']}}
        except Exception as e:
            raise Exception(f'While extracting url from urlscan.io, exception occurred: {e}')

    raise Exception(f'Unhandled urlscan.io {keyword} link: {link}')


def parse_hybrid_analysis(link: str) -> Optional[Dict[str, set]]:
    for keyword in ('/sample/', '/file-collection/'):
        if keyword in link:
            break
    else:
        logger.info(f'Unhandled hybrid-analysis link: {link}')
        return None

    ioc_candidate = link[link.find(keyword) + len(keyword):]
    if ioc_candidate.find('/') != -1:
        ioc_candidate = ioc_candidate[:ioc_candidate.find('/')]
    if ioc_candidate.find('?') != -1:
        ioc_candidate = ioc_candidate[:ioc_candidate.find('?')]

    if keyword == '/sample/':
        for hashtype in hashtypes:
            matched = ioc_regex[hashtype].match(ioc_candidate)
            if matched:
                return {hashtype: {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/file-collection/':
        result = defaultdict(set)
        _hybrid_analysis = HybridAnalysis()
        try:
            res = _hybrid_analysis.file_collection(ioc_candidate)
            for f in res['files']:
                for hashtype in hashtypes:
                    matched = ioc_regex[hashtype].match(f['hash'])
                    if matched:
                        result[hashtype].add(matched.group())
            return dict(result)
        except Exception as e:
            raise Exception(f'While extracting file-collection from hybrid-analysis, exception occurred: {e}')

    raise Exception(f'Unhandled hybrid-analysis {keyword} link: {link}')


def parse_urlhaus(link: str) -> Optional[Dict[str, set]]:
    for keyword in ('/tag/', '/host/', '/url/'):
        if keyword in link:
            break
    else:
        logger.info(f'Unhandled urlhaus link: {link}')
        return None

    ioc_candidate = link[link.find(keyword) + len(keyword):]
    if ioc_candidate.find('/') != -1:
        ioc_candidate = ioc_candidate[:ioc_candidate.find('/')]

    if keyword == '/tag/':
        return None

    elif keyword == '/host/':
        for ioctype in ('domain', 'ip'):
            matched = ioc_regex[ioctype].match(ioc_candidate)
            if matched:
                return {ioctype: {matched.group()}, 'inlink_ioc': True}

    elif keyword == '/url/':
        result = defaultdict(set)
        _urlhaus = Urlhaus()
        try:
            res = _urlhaus.query_urlid(ioc_candidate)
            result['urls'].add(res['url'])
            if 'payloads' in res:
                for payload in res['payloads']:
                    for hashtype in hashtypes:
                        if f'response_{hashtype}' in payload and payload[f'response_{hashtype}'] is not None:
                            result[hashtype].add(payload[f'response_{hashtype}'])
                        break
            return dict(result)
        except Exception as e:
            raise Exception(f'While extracting url from urlhaus, exception occurred: {e}')

    raise Exception(f'Unhandled urlhaus {keyword} link: {link}')


def parse_securelist(link: str) -> Optional[Dict[str, set]]:
    # WARNING - Please read ToS (https://www.kaspersky.co.uk/terms-of-use)
    #  before running this sample code. The ToS may be updated later.
    # Commercial use requires a license (2020/12/28).

    if 'securelist.com' not in link:
        return None
    try:
        r = requests.get(link, timeout=10)
        r.raise_for_status()

        bs = BeautifulSoup(r.text, 'html.parser')
        ioc_title = bs.find(
            lambda e: e.name == 'h2' and re.search(r'Indicators of Compromise|IoC', e.text, re.I))

        if ioc_title is None:
            logger.info(f'This link looks like having no IoC: {link}')
            return None

        ioc_texts = []
        for tag in ioc_title.find_next_siblings():
            if tag.name == 'h2':
                break
            ioc_texts.append(tag.get_text('\n', strip=True))

        result = matches_regex(' '.join(ioc_texts))
        result = ioc_polisher(result)

        if result is None:
            return None
        result['rawtext'] = r.text
        return dict(result)
    except Exception as e:
        raise Exception(f'Could not get IoC from {link} due to {e}')


def parse_otx(link: str) -> Optional[Dict[str, set]]:
    keyword = 'otx.alienvault.com/pulse/'
    if keyword in link:
        result = defaultdict(set)
        ioc_candidate = link[link.find(keyword) + len(keyword):]
        if ioc_candidate.find('/') != -1:
            ioc_candidate = ioc_candidate[:ioc_candidate.find('/')]

        try:
            _alienvault = AlienVault()
            indicators = _alienvault.pulse_indicators_report(ioc_candidate)

            ioc_type_dict = {
                'FileHash-MD5': 'md5',
                'FileHash-SHA1': 'sha1',
                'FileHash-SHA256': 'sha256',
                'IPv4': 'ip',
                'CIDR': 'ip',
                'domain': 'domain',
                # According to ioc_regex.py, we also treat subdomains(~= hostname) as domains.
                'hostname': 'domain',
                'URL': 'urls',
            }
            for indicator in indicators:
                if indicator['type'] in ioc_type_dict.keys():
                    result[ioc_type_dict[indicator['type']]].add(indicator['indicator'])
                elif indicator['type'] in ('YARA', 'email', 'CVE'):
                    logger.info(f'skip {indicator["type"]} type IoC from OTX')
                else:
                    logger.info(f'Unknown IoC type "{indicator["type"]}" from OTX: {indicator["indicator"]}')

            return dict(result)
        except Exception as e:
            raise Exception(f'While extracting ioc from otx pulse, exception occurred: {e}')
    else:
        logger.info(f'Unhandled OTX link: {link}')
        return None


def parse_pastebin(link: str) -> Optional[Dict[str, set]]:
    # !!WARNING!!
    # Pastebin recommends to use its own API when scraping the web.
    # If you are likely to make huge traffic,
    #  the code below should be replaced in a different way.

    ioc_candidate = link.split('/')[-1]
    try:
        r = requests.get(PASTEBINSERVER + ioc_candidate, timeout=10)
        if r.status_code == 404:
            return None
        r.raise_for_status()

        bs = BeautifulSoup(r.text, 'html.parser')
        content = bs.text

        result: Dict[str, set] = matches_regex(content)
        result = ioc_polisher(result)

        if result is None:
            return None
        result['rawtext'] = content
        return dict(result)
    except Exception as e:
        raise Exception(f'Could not get IoC from {link} due to {e}')


def parse_malwareconfig(link: str) -> Optional[Dict[str, set]]:
    if 'malwareconfig.com' not in link:
        return None
    md5 = link.split('/')[-1]
    matched = ioc_regex['md5'].match(md5)
    return {'md5': {matched.group()}, 'inlink_ioc': True} if matched else None


def parse_virusbay(link: str) -> Optional[Dict[str, set]]:
    if 'virusbay.io' not in link:
        return None
    md5 = link.split('/')[-1]
    matched = ioc_regex['md5'].match(md5)
    return {'md5': {matched.group()}, 'inlink_ioc': True} if matched else None


def parse_intezer(link: str) -> Optional[Dict[str, set]]:
    if 'analyze.intezer.com' not in link:
        return None
    sha256 = link.split('/')[-1]
    matched = ioc_regex['sha256'].match(sha256)
    return {'sha256': {matched.group()}, 'inlink_ioc': True} if matched else None


def parse_inquest(link: str) -> Optional[Dict[str, set]]:
    if 'labs.inquest.net' not in link:
        return None
    sha256 = link.split('/')[-1]
    matched = ioc_regex['sha256'].match(sha256)
    return {'sha256': {matched.group()}, 'inlink_ioc': True} if matched else None


def parse_malshare(link: str) -> Optional[Dict[str, set]]:
    if 'malshare.io' not in link and 'malshare.com' not in link:
        return None
    query = urlparse(link).query
    hash_value = parse_qs(query)['hash'][0]
    for hashtype in hashtypes:
        matched = ioc_regex[hashtype].match(hash_value)
        if matched:
            return {hashtype: {matched.group()}, 'inlink_ioc': True}


def parse_iris_h(link: str) -> Optional[Dict[str, set]]:
    if 'iris-h.services' not in link:
        return None
    hash_value = link.split('/')[-1].split('#')[0]
    for hashtype in hashtypes:
        matched = ioc_regex[hashtype].match(hash_value)
        if matched:
            return {hashtype: {matched.group()}, 'inlink_ioc': True}


class ExternalParser:
    def __init__(self):
        for domain in INTERESTING_EXTERNALS.keys():
            assert getattr(sys.modules[__name__], f'parse_{INTERESTING_EXTERNALS[domain]}') is not None
        self.ignore_domain = ()

    def parse(self, link: str):
        try:
            for domain in self.ignore_domain:
                if domain in link:
                    return None

            for domain in [k for k in INTERESTING_EXTERNALS.keys() if k not in self.ignore_domain]:
                if domain in link:
                    func = getattr(sys.modules[__name__], f'parse_{INTERESTING_EXTERNALS[domain]}')
                    res = func(link)

                    if res is not None:
                        rawtext = res['rawtext'] if 'rawtext' in res else None
                        inlink_ioc = res['inlink_ioc'] if 'inlink_ioc' in res else False
                        iocs = ioc_formatter(res)

                        return {
                            'iocs': iocs,
                            'source': INTERESTING_EXTERNALS[domain],
                            'rawtext': rawtext,
                            'inlink_ioc': inlink_ioc
                        }
            else:
                return {
                    'iocs': None
                }
        except Exception as e:
            logger.error(e)
            return None
