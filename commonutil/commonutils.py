import datetime
import logging
from collections import defaultdict
from typing import List
from urllib.parse import urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)


def get_expanded_links(urls: List[str], threshold_length=32, timeout_sec=10) -> List[str]:
    res = []
    for url in urls:
        if url[:33] == 'https://twitter.com/i/web/status/':
            continue
        # assume url longer than threshold_length has not been shortened
        elif len(url) > threshold_length:
            res.append(url)
        else:
            if '://oal.lu/' in url:
                try:
                    response = requests.get(url, timeout=timeout_sec)
                    parts = urlparse(response.url)
                    url = parse_qs(parts.query)['url'][0]
                except (KeyError, requests.exceptions.ReadTimeout) as e:
                    logger.warning(f'Cannot fully expand: {url} / {e}')
                    res.append(url)
                    continue

            rdir_cnt = 0
            try:
                while rdir_cnt < 10:
                    response = requests.head(url, timeout=timeout_sec)
                    if 300 < response.status_code < 400:
                        new_url_parts = urlparse(response.headers['location'])
                        if new_url_parts.scheme != '':
                            url = response.headers['location']
                        else:
                            previous_parts = urlparse(url)
                            url = f'{previous_parts.scheme}://{previous_parts.netloc}{response.headers["location"]}'
                    elif 400 < response.status_code < 500:
                        response = requests.get(url, timeout=timeout_sec)
                        if response.url == url:
                            break
                        else:
                            new_url_parts = urlparse(response.url)
                            if new_url_parts.scheme != '':
                                url = response.url
                            else:
                                previous_parts = urlparse(url)
                                url = f'{previous_parts.scheme}://{previous_parts.netloc}{response.url}'
                    else:
                        break
                    rdir_cnt += 1
            except requests.exceptions.Timeout:
                logger.warning(f'Request timeout: {url}')
            except Exception as e:
                logger.warning(f'Cannot fully expand: {url} / {e}')

            res.append(url)
    return res

