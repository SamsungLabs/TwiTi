import html
import json
import logging
import math
import re
from collections import defaultdict
from typing import List, Optional

import requests
import spacy

from config import config

logger = logging.getLogger(__name__)


class NLP:
    def __init__(self):
        try:
            self._ner_host = config['ner']['host']
        except KeyError as e:
            raise KeyError('Check configuration for NER') from e
        try:
            try:
                self.spacy_en = spacy.load('en')
            except OSError:
                spacy.cli.download('en')
                self.spacy_en = spacy.load('en')
        except Exception as e:
            raise Exception('Failed to load language model') from e

        with open("data/terms_common.json", 'r') as f:
            self.common_words = json.load(f)

    def extract_entities(self, text: str) -> Optional[dict]:
        data = text.encode('utf-8')
        try:
            r = requests.post(self._ner_host, data=data, timeout=360)
            r.raise_for_status()
            raw_entities = r.json()
            entities = defaultdict(set)
            if 'result' in raw_entities and 'tweet' in raw_entities['result']:
                for entity in raw_entities['result']['tweet']:
                    if 'text' in entity and 'type' in entity:
                        entities[entity['type']].add(entity['text'])
            else:
                logger.error(f'extract_entities | {text} | Invalid response')

            return {key: list(value) for key, value in entities.items()}
        except (requests.RequestException, ValueError, ConnectionError, TimeoutError) as e:
            logger.error(f'extract_entities | {text} | {e}')
            return None


    def extract_words(self, text: str, exclude_common_word: bool) -> set:
        words = set()
        doc = self.spacy_en(text)
        words.update(
             token.lemma_ for token in doc if (
                    len(token) > 1
                    and re.search(r'[A-Za-z]', token.text)
                    and not re.search(r'^[0-9]+[-][0-9]+', token.text)
                    and not re.search(r'^[-&.]', token.text)
                    and not re.search(r'\.$', token.text)
                    and not token.is_stop
                    and not (exclude_common_word and token.lemma_ in self.common_words)
                    and token.lemma_ != '-PRON-')
        )
        return words
