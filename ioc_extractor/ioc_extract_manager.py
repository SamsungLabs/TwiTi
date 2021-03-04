import datetime
import logging
import re

from multiprocessing import Pool
from typing import List

from commonutil import commonutils
from ioc_extractor import INTERESTING_EXTERNALS, ioc_formatter, ioc_polisher, ioc_type_all
from ioc_extractor.external_resource_parser import ExternalParser
from ioc_extractor.ioc_regex import ioc_regex
from ioc_extractor.ioc_regex_applier import matches_regex
from ner.predict import NER

logger = logging.getLogger(__name__)

pastebin_keyword = ('malware', 'ransomware', 'botnet', 'trojan', 'adware', 'spyware', 'keylogger',
                    'rootkit', 'bootkit', 'ioc', 'malspam', 'phishing', 'spam', 'spamming',
                    'c2', 'payload', 'yara', 'stealer')


class IoCExtractManager:
    for t in ioc_type_all:
        assert t == 'external' or t in ioc_regex

    def __init__(self):
        self.ner = NER()

    def resolve_external_ioc(self, ioc_objects_list, tweet_list):
        external_parser = ExternalParser()
        for ioc_object, tweet in zip(ioc_objects_list, tweet_list):
            if ioc_object is None:
                continue
            for external in ioc_object['externals']:
                # Filter links from pastebin.com by pre-defined keywords set
                if 'pastebin.com' in external['link']:
                    text = tweet['retweeted_status']['full_text'] if 'retweeted_status' in tweet else tweet['full_text']
                    if not any([re.search(k, text, re.IGNORECASE) for k in pastebin_keyword]):
                        entities = self.ner.extract(text)
                        if not any([e[1] == 'malware' for e in entities]):
                            logger.info(f'dropped pastebin: {tweet["full_text"]}')
                            continue

                parsed_external = external_parser.parse(external['link'])
                if parsed_external is not None and parsed_external['iocs'] is not None:
                    external.update({
                        'link': external['link'],
                        'source': parsed_external['source'],
                        'rawtext': parsed_external['rawtext'],
                        'inlink_ioc': parsed_external['inlink_ioc'],
                        'iocs': parsed_external['iocs']
                    })
                elif parsed_external is not None and parsed_external['iocs'] is None:
                    continue
            # ioc_objects.append(ioc_object)
        return ioc_objects_list

    def ioc_extraction(self, tweets: List[dict], expand_external=False):
        """Extract IOC from tweets

        **CAUTION: Be careful when accessing external environments.**
        If you're not sure, just set expand_external as False.
        It is seen that about 90% of meaningful links are extracted without external link expansion

        :param tweets: tweet object from twitter API
        :param expand_external: if True, expands external links by accessing directly
        """

        texts = []
        external_links = []

        for tw in tweets:
            if 'retweeted_status' in tw:
                orig_text = tw['retweeted_status']['full_text']
                entities = tw['retweeted_status']['entities']
            else:
                orig_text = tw['full_text']
                entities = tw['entities']
            texts.append(orig_text)
            external_links.append([url['expanded_url'] if 'expanded_url' in url else url['url'] for url in entities['urls']])

        if expand_external:
            pool = Pool(24)
            external_links = pool.map(commonutils.get_expanded_links, external_links[:])
            pool.close()
            pool.join()

        total_iocs: list = self.extract_iocs(texts, external_links)
        return self.make_ioc_objects(total_iocs, tweets)

    def make_ioc_objects(self, total_iocs, tweetlist):
        objects = []
        assert len(total_iocs) == len(tweetlist)
        for iocs, tw in zip(total_iocs, tweetlist):
            if iocs is None:
                objects.append(None)
                continue

            external_links = \
                [{'link': link, 'source': None, 'rawtext': None, 'inlink_ioc': None, 'iocs': None}
                 for link in iocs['external']]
            obj = {
                'iocs': ioc_formatter(iocs),
                'entities': [],
                'context': [],
                'externals': external_links,
            }
            objects.append(obj)
        return objects

    def extract_iocs(self, texts: List[str], external_links: List[List[str]]) -> List[dict]:
        result = []

        for text, linklist in zip(texts, external_links):
            iocs = matches_regex(text)
            iocs['external'] = {link for link in linklist
                                if any([domain in link for domain in INTERESTING_EXTERNALS.keys()])}

            iocs = ioc_polisher(iocs)
            result.append(iocs)

        return result


if __name__ == "__main__":
    tweets = [

    ]
    ioc_extractor = IoCExtractManager()
    ioc_object_list = ioc_extractor.ioc_extraction(tweets, True)
    ioc_object_list = ioc_extractor.resolve_external_ioc(ioc_object_list, tweets)
    print(ioc_object_list)
