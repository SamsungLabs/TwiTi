import json
import logging
import pickle
import re
from enum import Enum
from multiprocessing import Pool
from pathlib import Path
from typing import List

import pandas as pd
from ioc_fanger import ioc_fanger

from commonutil import preprocessor
from ioc_extractor.ioc_regex_applier import normalize_iocs

logger = logging.getLogger(__name__)

CLASSIFIER_PATH = Path(__file__).parent


class Estimator(Enum):
    LOGISTIC = 0
    RANDOMFOREST = 1
    XGBOOST = 2


class Classifier:
    def __init__(self, model=None, estimator=None, features=None):
        self.model = model
        self.estimator: Estimator = estimator
        self.features: dict = features

    def load(self, model_path: str, estimator: Estimator, feature_path: str):
        with open(model_path, 'rb') as model_file:
            self.model = pickle.load(model_file)
        self.estimator = estimator
        with open(feature_path, 'r') as feature_file:
            self.features = json.load(feature_file)

    def save(self):
        if self.model is None:
            raise Exception('Model object should be set before saving')

        with open(CLASSIFIER_PATH / "model.pkl", "wb") as model_file:
            pickle.dump(self.model, model_file)
        with open(CLASSIFIER_PATH / "features.json", "w") as feature_file:
            json.dump(self.features, feature_file)

    def _build_dataframe_x(self, orig_tweet_documents: List[str]) -> pd.DataFrame:
        normalized_tweet_documents = [normalize_iocs(line) for line in orig_tweet_documents]
        preprocessed_tweet_documents = preprocessor.preprocess_tweets(normalized_tweet_documents)

        dataframe_x = feature_extraction(self.features, orig_tweet_documents, preprocessed_tweet_documents)
        if self.estimator == Estimator.XGBOOST:
            dataframe_x.rename(columns=lambda x: re.sub("[\\[\\]]", "_", x), inplace=True)
        return dataframe_x

    def predict(self, orig_tweet_documents: List[str]) -> pd.Series:
        dataframe_x = self._build_dataframe_x(orig_tweet_documents)
        pred_y = self.model.predict(dataframe_x)
        return pred_y

    def predict_proba(self, orig_tweet_documents: List[str]) -> pd.DataFrame:
        dataframe_x = self._build_dataframe_x(orig_tweet_documents)
        prob = self.model.predict_proba(dataframe_x)
        return prob


tweets = []


def feature_extraction(features: dict, orig_tweet_documents, preprocessed_tweet_documents) -> pd.DataFrame:
    datamatrix = term_marking(preprocessed_tweet_documents, features['words'])
    datamatrix.extend(term_marking(preprocessed_tweet_documents, features['terms']))
    datamatrix.append([False if ioc_fanger.fang(tw) == tw else True for tw in orig_tweet_documents])

    df = pd.DataFrame(datamatrix).transpose()
    df.columns = features['words'] + features['terms'] + ['is_defanged']
    # TODO optimize types
    df = df.astype('int64', errors="raise")
    logger.info(f'There are {len(df.columns)} features')
    return df


def _account_marking(_account: str) -> List[bool]:
    pattern = rf'{re.escape(_account)}(?![a-zA-Z0-9_])'
    marks = [True if re.search(pattern, _text, re.IGNORECASE) else False for _text in tweets]
    assert len(marks) == len(tweets)
    return marks


def account_marking(_tweets: List[str], accounts: List[str]) -> List[List[bool]]:
    pool = Pool(initializer=init_pool, initargs=(_tweets,))
    datamatrix = pool.map(_account_marking, accounts)
    pool.close()
    pool.join()
    return datamatrix


def _term_marking(_term: str) -> List[int]:
    pattern = rf'(?<![^\s]){re.escape(_term)}(?![^\s])'
    counts = [1 if re.search(pattern, _text) else 0 for _text in tweets]
    assert len(counts) == len(tweets)
    return counts


def init_pool(_tweets: List[str]):
    global tweets
    tweets = _tweets

def term_marking(_tweets: List[str], terms: List[str]) -> List[List[int]]:
    pool = Pool(initializer=init_pool, initargs=(_tweets,))
    datamatrix = pool.map(_term_marking, terms)
    pool.close()
    pool.join()
    return datamatrix
