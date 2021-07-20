from typing import Optional

from ioc_extractor.ioc_regex_applier import remove_blockchain_hash, remove_ignore_domain

ioc_type_all = ('urls', 'domain', 'ip', 'email', 'md5', 'sha1', 'sha256', 'sha512',
                'filename', 'filepath', 'registry', 'external')
ioc_type_interesting = ('urls', 'domain', 'ip', 'md5', 'sha1', 'sha256', 'external')

# We collected data from the following external links for research use only 
# in compliance with the policy of data owners.
INTERESTING_EXTERNALS = \
    {
        'virustotal.com':           'virustotal',
        'urlscan.io':               'urlscan',
        'otx.alienvault.com':       'otx',
        'pastebin.com':             'pastebin',
        'urlhaus.abuse.ch':         'urlhaus',
        'hybrid-analysis.com':      'hybrid_analysis',
        'securelist.com':           'securelist',
        'malwareconfig.com':        'malwareconfig',
        'virusbay.io':              'virusbay',
        'analyze.intezer.com':      'intezer',
        'labs.inquest.net':         'inquest',
        'malshare.io':              'malshare',
        'malshare.com':             'malshare',
        'iris-h.servicies':         'iris_h'
    }


def ioc_formatter(iocs: dict) -> dict:
    ioc_format = {
        'hashes': {
            'sha1': list(iocs['sha1']) if 'sha1' in iocs else [],
            'sha256': list(iocs['sha256']) if 'sha256' in iocs else [],
            'md5': list(iocs['md5']) if 'md5' in iocs else []
        },
        'ips': list(iocs['ip']) if 'ip' in iocs else [],
        'urls': {
            'urls': list(iocs['urls']) if 'urls' in iocs else [],
            'domain': list(iocs['domain']) if 'domain' in iocs else []
        }
    }
    return ioc_format


def ioc_polisher(iocs: dict) -> Optional[dict]:
    iocs = {ioc_type: iocs[ioc_type] for ioc_type in ioc_type_interesting if ioc_type in iocs}
    iocs['urls'] = remove_ignore_domain(iocs['urls'])
    iocs['domain'] = remove_ignore_domain(iocs['domain'])
    iocs['md5'] = remove_blockchain_hash(iocs['md5'])
    iocs['sha1'] = remove_blockchain_hash(iocs['sha1'])
    iocs['sha256'] = remove_blockchain_hash(iocs['sha256'])

    count = sum(len(v) for v in iocs.values())
    if count == 0:
        return None
    return iocs
