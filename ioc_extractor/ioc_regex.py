# port public ioc_finder module to using regex
# (https://pypi.org/project/ioc-finder/)

import re
from ioc_finder.data_lists import tlds, schemes
from ioc_finder.ioc_grammars import root_key
from typing import List


def _or(li: List) -> str:
    start = '(?:'
    end = ')'
    res = start
    for elem in li:
        #res += '(?:' + elem + ')|'
        res += elem + '|'
    if res[-1] == '|':
        res = res[:-1]
    res += end
    return res


def stringminus(orig: str, operand: str) -> str:
    for c in operand:
        orig = orig.replace(c, '')
    return orig

alphas = '[A-Za-z]'
alphanums = '[0-9A-Za-z]'
hexnums = '[0-9A-Fa-f]'
# https://pythonhosted.org/pyparsing/pyparsing-module.html#printables
printables = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,\-./:;<=>?@[\\]^_`{|}~'
# https://en.wikipedia.org/wiki/Filename
filenameprohibitedchars = '/\\?%*:|"<>\''
emailaccountprohibitedchars = '(),:;<>@[\\]'

# for debug
#schemes = schemes[:10]
#tlds = tlds[:10]
# for debug end

schemes.append('tcp')
schemes = _or([re.escape(scheme) for scheme in schemes])
tlds.append('site')
tlds.append('tk')
tlds = _or([re.escape(tld) for tld in tlds])
root_key = _or([re.escape(str(rootkey)[1:-1])for rootkey in root_key.exprs])
extensions = [
    'exe', 'dll', 'bat', 'sys', 'htm', 'html', 'js', 'jar', 'jpg', 'png', 'vb', 'scr', 'pif', 'chm', 'zip', 'rar',
    'cab', 'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'swf', 'gif', 'sh', 'hta', 'vbe', 'vbs', 'php', 'txt',
    'rtf', 'bmp'
]

regex_ip_string = r"""
                (?<!\.|\d)

                # only accept numbers between 0~255
                (?:
                    (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
                    \.
                ){3}
                (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])

                # subnet prefix
                (?:/\d{1,2})?

                (?!\.\d|\d)
                """
# if IP follows '/', followed by '/' or followed by port, we consider it as URL, rather than IP
regex_ip = re.compile(r'\b(?<!/)' + regex_ip_string + r'(?!/|:[0-9]{1,5})\b', re.VERBOSE)
# IP inside url, different from normal ip, can follow '/', be followed by '/' or be followed by port
regex_ip_inside_url = re.compile(r'\b' + regex_ip_string + r'\b', re.VERBOSE)

# allow CISCO ESA style defangs (\x20 character before a dot)
regex_domain_string = rf'(?:[a-zA-Z0-9][a-zA-Z0-9-]{{0,62}}\x20?\.)+{tlds}'
regex_domain = re.compile(r'\b' + regex_domain_string + r'\b')

# manually add defanged(broken) schemes. ( e.g. 's://', 'xp://', 's_', 's/', ... )
regex_url_string_with_scheme = '' \
    + _or([_or([schemes] + ['s', 'xp', 'p', 'ps', '']) + '[:_]//'] + [r'\bs_', r'\bs/']) \
    + _or([regex_ip_string, regex_domain_string]) \
    + rf"""
        (?:\:[0-9]{{2,5}})?

        [\S]*?

        # CISCO ESA style defangs followed by domain/path characters.
        (?:\x20[\/\.][^\.\/\s]\S*?)*

        (?=
            # ignore zero or more 'end punctuations'
            [\.\?>\"'\)!,}}:;\u201d\u2019\uff1e\uff1c\]]*
            # capture url characters with the pattern above until whitespace or comma or EOL appears
            (?:\s|,|$)
        )
    """
regex_url_string_wo_scheme = rf"""
        /?
        {_or([regex_ip_string, regex_domain_string])}

        (?:
            \:[0-9]{{2,5}}(?:/[\S]+?)?
            |
            /[\S]*?
        )

        #(?:\:[0-9]{{2,5}}(?:/[\S]+)?|/[\S]*)

        # CISCO ESA style defangs followed by domain/path characters.
        (?:\x20[\/\.][^\.\/\s]\S*?)*

        (?=
            # ignore zero or more 'end punctuations'
            [\.\?>\"'\)!,}}:;\u201d\u2019\uff1e\uff1c\]]*
            # capture url characters with the pattern above until whitespace or EOL appears
            (?:\s|$)
        )
"""
regex_url = re.compile(rf'{_or([regex_url_string_with_scheme, regex_url_string_wo_scheme])}', re.VERBOSE)
regex_email = re.compile(rf'\b([{re.escape(stringminus(printables, filenameprohibitedchars))}]+@(?:[a-zA-Z0-9][a-zA-Z0-9-]{{0,62}}\.)+{tlds})\b')

regex_md5 = re.compile(rf'\b({hexnums}{{32}}|{hexnums}{{32}})\b')
regex_sha1 = re.compile(rf'\b({hexnums}{{40}}|{hexnums}{{40}})\b')
regex_sha256 = re.compile(rf'\b({hexnums}{{64}}|{hexnums}{{64}})\b')
regex_sha512 = re.compile(rf'\b({hexnums}{{128}}|{hexnums}{{128}})\b')

regex_filename = re.compile(rf'\b(?<!/)[{re.escape(stringminus(printables, filenameprohibitedchars))}]+\.{_or(extensions)}\b')
regex_windows_filepath = re.compile(r'\b[A-Z]:\\[' + printables.replace('.', '') + r']+\.' + r'[a-zA-Z]{1,5}' + r'\b')
regex_unix_filepath = re.compile(r'\b[a-zA-Z0-9:/~][' + printables.replace('.', '') + r']*\.' + r'[a-zA-Z]{1,5}' + r'\b')
regex_registry = re.compile(rf'\b{root_key}\\[\\A-Za-z0-9-_]+\b')

regex_ipv6 = re.compile(r'(?:(?:[0-9a-fA-F]{1,4}\:){7}[0-9a-fA-F]{1,4})|(?:[0-9a-fA-F]{0,4}\:){1,7}(?:\:[0-9a-fA-F]{0,4}){1,7}')
#regex_bitcoin_address = re.compile(r'\b(1[0-9a-zA-Z]{25,34}|3[0-9a-zA-Z]{25,34}|bc1[0-9a-zA-Z]{11,71})\b')

regex_rt = re.compile(r'^\s*RT:?\s*')
regex_mention = re.compile(r'^\s*@[a-zA-Z0-9_]{1,15}:?\s*')

ignore_domain = ['(?:/|^)t.co(?:/|$)', 'twib', 'bit.ly', 'tinyurl.com', 'huff.to', 'buff.ly', 'goo.gl', 'youtu.be', 'ow.ly']
ignore_domain = _or([ignore.replace(".", "\\.") for ignore in ignore_domain])
regex_ignore_domain = re.compile(rf'{ignore_domain}')

ioc_regex = {
    'urls': regex_url,
    'domain': regex_domain,
    'ip': regex_ip,
    'email': regex_email,
    'md5': regex_md5,
    'sha1': regex_sha1,
    'sha256': regex_sha256,
    'sha512': regex_sha512,
    'filename': regex_filename,
    # TODO add unix filepath
    'filepath': regex_windows_filepath,
    'registry': regex_registry,
    # 'ipv6' : regex_ipv6,
}
