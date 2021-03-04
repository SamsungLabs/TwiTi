import json
import logging
import re
from collections import defaultdict
from multiprocessing import Pool
from typing import List

from dateutil import parser

from ner.predict import NER

logger = logging.getLogger(__name__)

with open("data/malware_names.json", 'r') as f:
    _malware_names = json.load(f)
_malware_name_regex = '|'.join([rf'\b{re.escape(name)}\b' for name in _malware_names])

_USING_NER = False
ner = None


def remove_exact_duplicated_texts(docs: List[str]) -> (List[int], List[str]):
    indices = []
    # To improve search speed, manage data with two structures
    unique_texts_set = set()
    unique_texts = []

    for idx, doc in enumerate(docs):
        if doc in unique_texts_set:
            continue
        else:
            unique_texts_set.add(doc)
            unique_texts.append(doc)
            indices.append(idx)

    return indices, unique_texts


def remove_exact_duplicated_tweets(tweets: List[dict]) -> List[dict]:
    # by default, earliest tweet survives

    # TODO: check for performance and the order of output -> decide which to use 'defaultdict' or 'OrderedDict'
    unique_documents = defaultdict()

    for tw in tweets:
        if tw['is_retweeted']:
            orig_text = tw['retweet_data']['document']
        else:
            orig_text = tw['document']

        if orig_text not in unique_documents:
            unique_documents[orig_text] = tw
        else:
            # current tweet is earlier
            if unique_documents[orig_text]['published_time'] > tw['published_time']:
                unique_documents[orig_text] = tw

    return list(unique_documents.values())


def _standardize_tech_words(text: str) -> str:
    """unify technical words according to mapping dictionary"""
    word_dict = {
        'exploit kit': 'exploitkit',
        'wi-fi': 'wifi',
        'c&c': 'c2',
        'cnc': 'c2',
    }
    p_text = text
    for word, representative in word_dict.items():
        p_text = re.sub(rf'{re.escape(word)}s?', representative, p_text, flags=re.IGNORECASE)
    return p_text


def _remove_incomplete_word(text: str) -> str:
    """removes incomplete word due to character limitation"""
    p_text = re.sub(r'[^\s]*…', '', text)
    return p_text


def _remove_retweet_flag(text: str) -> str:
    """removes retweet flag(RT: @username)"""
    p_text = re.sub(r'^RT:?\s*@[a-zA-Z0-9_]{1,15}:?\s*', '', text)
    return p_text


def _remove_prefix_username(text: str) -> str:
    """removes twitter style usernames at the start of the tweet"""
    p_text = text
    while re.search(r'^@[a-zA-Z0-9_]{1,15}', p_text):
        p_text = re.sub(r'^@[a-zA-Z0-9_]{1,15}\s*', '', p_text)
    return p_text


def _remove_postfix_username(text: str) -> str:
    """removes twitter style usernames at the start of the tweet"""
    p_text = text
    while re.search(r'@[a-zA-Z0-9_]{1,15}$', p_text):
        p_text = re.sub(r'\s*@[a-zA-Z0-9_]{1,15}$', '', p_text)
    return p_text


def _remove_date(text: str) -> str:
    """removes date string"""
    words = text.split()
    p_text = ''
    for word in words:
        try:
            parser.parse(word)
        except Exception:
            p_text += f'{word} '
    return p_text.rstrip()


def _remove_special_characters(text: str) -> str:
    """removes some special characters"""
    p_text = re.sub(r'[,;?!$*(){}<=>^~+`\"%#]', ' ', text, flags=re.ASCII)
    p_text = re.sub(r'<([uU]\+.+)>', ' ', p_text)  # remove pesky Unicodes like <U+A>
    return p_text


def _normalize_cve(text: str) -> str:
    """normalize specific CVEs(cve-2020-12345) to [CVE]"""
    p_text = re.sub(r'cve[-][0-9]+[-][0-9]+', ' [cve] ', text)
    return p_text


def _normalize_num(text: str) -> str:
    """removes numbers"""
    p_text = re.sub(r'(?<=[\s^])[0-9]{2,}(?=[\s$])', '[num]', text)
    return p_text


def _normalize_malware_name(text: str) -> str:
    if _USING_NER:
        entities = ner.extract(text)
        malnames = [e[0] for e in entities if e[1] == 'malware']
        p_text = text
        for mal in malnames:
            p_text = re.sub(re.escape(mal), '[malware_name]', p_text, re.IGNORECASE)
    else:  # Use dictionary
        p_text = re.sub(_malware_name_regex, ' [malware_name] ', text, re.IGNORECASE)

    return p_text


def _remove_special_character_wraps_word(word: str) -> str:
    """removes special characters surrounding word"""
    deleted_start = [':', '/']
    deleted_end = ['.', '…', '/', ':', '&']
    new_word = word
    while len(new_word) > 0:
        if any([new_word.startswith(p) for p in deleted_start]):
            new_word = new_word[1:]
        else:
            break

    while len(new_word) > 0:
        if any([new_word.endswith(p) for p in deleted_end]):
            new_word = new_word[0:-1]
        else:
            break

    if len(new_word) >= 2 and new_word[-2] == '’' and new_word[-1] == 's':
        new_word = new_word[0:-2]

    if new_word in ['[', ']', '-', '\'', '"']:
        new_word = ''

    return new_word


def _preprocess_tweet(_text: str) -> str:
    text = _text.strip()
    text = _remove_incomplete_word(text)
    text = _remove_retweet_flag(text)
    text = _standardize_tech_words(text)
    text = _remove_date(text)
    text = _remove_prefix_username(text)
    text = _remove_postfix_username(text)
    text = _remove_special_characters(text)
    text = text.encode('ascii', errors='ignore').decode()

    text = text.lower()

    text = _normalize_cve(text)
    text = _normalize_num(text)
    text = _normalize_malware_name(text)

    text = ' '.join([_remove_special_character_wraps_word(word) for word in text.split()])
    text = re.sub(r'@[a-zA-z0-9_]{1,15}', '[twitter_username]', text)
    text = re.sub(r'\s\s+', ' ', text)

    return text


def _ner_initializer():
    global ner
    ner = NER()


def preprocess_tweets(doc: List[str]) -> List[str]:
    if _USING_NER:
        pool = Pool(initializer=_ner_initializer)
    else:
        pool = Pool()
    res = pool.map(_preprocess_tweet, doc)
    pool.close()
    pool.join()

    return list(res)
