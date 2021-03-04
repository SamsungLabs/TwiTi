import html
import logging
import re
from typing import Dict, List, Set

import ioc_fanger

from ioc_extractor.ioc_regex import ioc_regex, regex_ignore_domain, regex_ip_inside_url

logger = logging.getLogger(__name__)


def matches_regex(text: str) -> Dict[str, set]:
    res = dict()

    text = html.unescape(text)
    text = ioc_fanger.fang(text)

    urlscandidate = set()
    ipcandidate = set()
    for u in ioc_regex['urls'].findall(text):
        # fix unhandled defanged urls manually
        u = re.sub(r'_//', '://', u)
        u = re.sub(r'^(?:|p|xp)://', 'http://', u)
        u = re.sub(r'^(?:s|ps)://', 'https://', u)
        # sideeffect below: what if domain name starts with 's_' ??
        u = re.sub(r'^s_', 'https://', u)
        u = re.sub(r'^s/', 'https://', u)

        u = re.sub(r'\s', '', u)
        u = re.sub(r'^/', '', u)
        u = re.sub(r'/$', '', u)

        u = re.sub(r'\[', '', u)
        u = re.sub(r'\]', '', u)

        # GroundRule: only treat https://[ip], http://[ip], [ip]:443, [ip]:80 as url, ip otherwise
        if not u.startswith('http'):
            if regex_ip_inside_url.search(u):
                if not any([re.search(rf'{port}(?!\d)', u) for port in (':80', ':443')]):
                    ipcandidate.add(regex_ip_inside_url.search(u).group())
                    continue
        urlscandidate.add(u)

    res.update({'urls': urlscandidate})

    for i in ioc_regex['ip'].findall(text):
        ipcandidate.add(i)

    res.update({'ip': ipcandidate})

    res.update({'email': set(ioc_regex['email'].findall(text))})
    # res['ip'] += ioc_regex['ipv6'].findall(text)
    res.update({'domain': set()})
    domains = ioc_regex['domain'].findall(text)
    for domain in domains:
        if domain not in ' '.join(res['urls']) and domain not in ' '.join(res['email']):
            res['domain'].add(domain)
    res.update({'md5': {h.lower() for h in ioc_regex['md5'].findall(text)}})
    res.update({'sha1': {h.lower() for h in ioc_regex['sha1'].findall(text)}})
    res.update({'sha256': {h.lower() for h in ioc_regex['sha256'].findall(text)}})
    res.update({'sha512': {h.lower() for h in ioc_regex['sha512'].findall(text)}})
    res.update({'filename': set(ioc_regex['filename'].findall(text))})
    res.update({'filepath': set(ioc_regex['filepath'].findall(text))})
    #      res['filepath'] += regex_unix_filepath.findall(text)
    res.update({'registry': set(ioc_regex['registry'].findall(text))})

    return res


def remove_blockchain_hash(li: Set[str]) -> Set[str]:
    for item in li.copy():
        if item.startswith("000"):
            li.remove(item)
    return li


def remove_ignore_domain(li: Set[str]) -> Set[str]:
    for item in li.copy():
        if regex_ignore_domain.search(item):
            li.remove(item)
    return li


def normalize_iocs(text: str) -> str:
    text = html.unescape(text)
    text = ioc_fanger.fang(text)

    for match in ioc_regex['urls'].findall(text):
        if regex_ignore_domain.search(match):
            text = text.replace(match, ' ', 1)
            continue
        u = match
        # fix unhandled defanged urls manually
        u = re.sub(r'_//', '://', u)
        u = re.sub(r'^(?:|p|xp)://', 'http://', u)
        u = re.sub(r'^(?:s|ps)://', 'https://', u)
        # sideeffect below: what if domain name starts with 's_' ??
        u = re.sub(r'^s_', 'https://', u)
        u = re.sub(r'^s/', 'https://', u)

        u = re.sub(r'\s', '', u)
        u = re.sub(r'^/', '', u)
        u = re.sub(r'/$', '', u)

        u = re.sub(r'\[', '', u)
        u = re.sub(r'\]', '', u)

        # GroundRule: only treat https://[ip], http://[ip], [ip]:443, [ip]:80 as url, ip otherwise
        if not u.startswith('http'):
            if regex_ip_inside_url.search(u):
                if not any([re.search(rf'{port}(?!\d)', u) for port in (':80', ':443')]):
                    text = text.replace(match, ' [IP] ', 1)
                    continue
        text = text.replace(match, ' [URL] ', 1)

    for match in ioc_regex['ip'].findall(text):
        text = text.replace(match, ' [IP] ', 1)

    for match in ioc_regex['email'].findall(text):
        text = text.replace(match, ' [EMAIL] ', 1)

    for match in ioc_regex['domain'].findall(text):
        text = text.replace(match, ' [DOMAIN] ', 1)

    for match in ioc_regex['md5'].findall(text):
        text = text.replace(match, ' [HASH] ', 1)

    for match in ioc_regex['sha1'].findall(text):
        text = text.replace(match, ' [HASH] ', 1)

    for match in ioc_regex['sha256'].findall(text):
        text = text.replace(match, ' [HASH] ', 1)

    for match in ioc_regex['sha512'].findall(text):
        text = text.replace(match, ' [HASH] ', 1)

    for match in ioc_regex['filename'].findall(text):
        text = text.replace(match, ' [FILENAME] ', 1)

    for match in ioc_regex['filepath'].findall(text):
        text = text.replace(match, ' [FILEPATH] ', 1)

    for match in ioc_regex['registry'].findall(text):
        text = text.replace(match, ' [REGISTRY] ', 1)

    return text
