import json
import logging
import re
from collections import Counter
from itertools import chain
from multiprocessing import Pool
from pathlib import Path
from typing import List

import pandas as pd
import xgboost as xgb
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import mutual_info_score
from spacy.attrs import ORTH

import classifier
from classifier import Classifier, Estimator
from commonutil import preprocessor
from commonutil.nlp import NLP
from ioc_extractor.ioc_regex_applier import normalize_iocs

logger = logging.getLogger(__name__)

PATH = Path(__file__).resolve().parent
filepath_inputX = PATH.joinpath("input/tweets_v3.txt")
filepath_inputY = PATH.joinpath("input/labels_v3.txt")

# Load malware keywords
# First, load keyword elements from file
with open("data/ioc_terms_malware.json", 'r') as f:
    _dict_keyword: List = json.load(f)

# Second, if an element is set of words, unzip it
_wordset = Counter(
    chain.from_iterable(
        [keyword["word"] for keyword in _dict_keyword if keyword["type"] == "wordset"]
    )
)
# Next, merge word elements and wordset elements.
# But for words in wordset elements, merge them only if they appear 3 times or more
_dict_keyword = list(
    chain.from_iterable(
        [keyword["word"] for keyword in _dict_keyword if keyword["type"] == "word"]
    )
) + [word for word, cnt in _wordset.items() if cnt >= 3]
# Remove whitespaces, lower capital letters
_dict_keyword = [re.sub(r"\s", "", keyword).lower() for keyword in _dict_keyword]
# Append plural forms
_dict_keyword += [f"{keyword}s" for keyword in _dict_keyword]
dict_keyword = set(_dict_keyword)

# Load ioc keywords
dict_ioc = {"[ip]", "[url]", "[domain]", "[hash]", "[malware_name]"}


def data_to_initial_df():
    try:
        orig_tweet_documents = open(filepath_inputX, "r", encoding="utf-8-sig").read().splitlines()
        data_y = [bool(int(y)) for y in open(filepath_inputY, "r", encoding="utf-8-sig").read().splitlines()]
        if len(orig_tweet_documents) != len(data_y):
            raise ValueError("Size differs between data and label")
    except OSError as e:
        raise Exception(f'Failed to open input dataset for classifier | {e}') from e

    # Preprocess tweets
    pool = Pool()
    normalized_tweet_documents = pool.map(normalize_iocs, orig_tweet_documents)
    pool.close()
    pool.join()

    preprocessed_tweet_documents = preprocessor.preprocess_tweets(normalized_tweet_documents)

    assert len(preprocessed_tweet_documents) == len(data_y)

    df = pd.DataFrame([orig_tweet_documents, normalized_tweet_documents, preprocessed_tweet_documents, data_y]).T
    df.columns = ['orig', 'normalized', 'preprocessed', 'y']
    df = df.astype({'y': bool})

    return df


def extract_words_terms(df):
    _WORD_EXCLUDING_COMMON_WORD = True

    _nlp = NLP()
    _nlp.spacy_en.Defaults.stop_words |= {
        "can't",
        "cant",
        "won't",
        "wont",
        "till",
        "thats",
        "dont",
        "says",
        "said",
    }
    special_cases = [
        "twitter_username",
        "cve",
        "num",
        "malware_name",
        "url",
        "ip",
        "email",
        "domain",
        "hash",
        "filename",
        "filepath",
        "registry",
    ]
    for case in special_cases:
        _nlp.spacy_en.tokenizer.add_special_case(f"[{case}]", [{ORTH: f"[{case}]"}])

    if _WORD_EXCLUDING_COMMON_WORD:
        df['extracted_words'] = df['preprocessed'].map(lambda x: _nlp.extract_words(x, exclude_common_word=True))
    else:
        df['extracted_words'] = df['preprocessed'].map(lambda x: _nlp.extract_words(x, exclude_common_word=False))

    df['extracted_terms'] = pd.Series([[]] * len(df))
    min_window_size = 1
    max_window_size = 2
    for idx, row in df.iterrows():
        termslist = []
        text = row['preprocessed']
        words = text.split()
        for i in range(0, len(words)):
            word = words[i]
            if word in dict_ioc or word in dict_keyword:
                for w in range(min_window_size, max_window_size + 1):
                    if i - w >= 0:
                        termslist.append(" ".join(words[i - w: i + 1]))
                    if i + w < len(words):
                        termslist.append(" ".join(words[i: i + w + 1]))
        df.at[idx, 'extracted_terms'] = termslist

    return df


def mutual_selection(df_x: pd.DataFrame, y, mi_threshold, category=""):
    features = list(df_x.columns)
    mutual_info = [mutual_info_score(df_x[feature], y) for feature in features]

    for mi, feature in zip(mutual_info, features[:]):
        if mi < mi_threshold:
            features.remove(feature)

    logger.info(f"{category} length (after applying MI) : {len(features)}")
    return features


class FeatureScaler(BaseEstimator, TransformerMixin):
    def __init__(self, selected_features=None):
        if selected_features:
            self.selected_features = selected_features
        else:
            self.selected_features = {'words': [], 'terms': []}

    def fit(self, x, y):
        logger.info('fit called')

        _WORD_OCCUR_THRESHOLD = 5
        _WORD_MI_THRESHOLD = 0.0002
        _TERM_OCCUR_THRESHOLD = 5
        _TERM_MI_THRESHOLD = 0.0002

        # Word selection
        target_words = Counter({})
        for words in x['extracted_words']:
            target_words += Counter(words)
        del target_words["[twitter_username]"]

        logger.info(f"word length (occurs >= 1) : {len(target_words)}")
        target_words = [key for key in target_words if target_words[key] >= _WORD_OCCUR_THRESHOLD]
        logger.info(f"word length (occurs >= {_WORD_OCCUR_THRESHOLD}) : {len(target_words)}")

        datamatrix = classifier.term_marking(x['preprocessed'], target_words)

        df_words = pd.DataFrame(datamatrix).transpose()
        df_words.columns = target_words

        word_features = mutual_selection(df_words, y.array, _WORD_MI_THRESHOLD, category="word")

        # Term selection
        terms = Counter({})

        for termslist in x['extracted_terms']:
            terms += Counter(termslist)

        logger.info(f"term length (occurs >= 1) : {len(terms)}")
        terms = [key for key in terms if terms[key] >= _TERM_OCCUR_THRESHOLD]
        # rarely occurs
        for term in terms:
            if len(term.split()) <= 1:
                terms.remove(term)

        logger.info(f"term length (occurs >= {_TERM_OCCUR_THRESHOLD}) : {len(terms)}")

        datamatrix = classifier.term_marking(x['preprocessed'], terms)

        df_terms = pd.DataFrame(datamatrix).transpose()
        df_terms.columns = terms

        term_features = mutual_selection(
            df_terms, y.array, _TERM_MI_THRESHOLD, category="term"
        )

        self.selected_features = {
            "words": word_features,
            "terms": term_features,
        }
        return self

    def transform(self, x, y=None):
        print("transform called")

        dataframe_x = classifier.feature_extraction(
            self.selected_features,
            x['orig'].array,
            x['preprocessed'].array,
        )
        return dataframe_x


def build_model(dataframe_x: pd.DataFrame, data_y: pd.Series, estimator: Estimator):
    if estimator == Estimator.XGBOOST:
        # To avoid XGBoost ValueError('feature_names may not contain [, ] or <')
        dataframe_x.rename(columns=lambda x: re.sub("[\\[\\]]", "_", x), inplace=True)

    if estimator == Estimator.LOGISTIC:
        log_clf = LogisticRegression()
        log_clf.fit(dataframe_x, data_y)
        model = log_clf
    elif estimator == Estimator.RANDOMFOREST:
        rf = RandomForestClassifier(n_estimators=500, max_depth=50, oob_score=False, random_state=12, n_jobs=-1)
        rf.fit(dataframe_x, data_y)
        model = rf
    elif estimator == Estimator.XGBOOST:
        xgbmodel = xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.05,
                                     max_features='auto', min_samples_split=0.01, n_jobs=-1, seed=12)
        xgbmodel.fit(dataframe_x, data_y)
        model = xgbmodel
    else:
        assert False

    return model


def builder_main(estimator_function=Estimator.RANDOMFOREST, save=False):
    df = data_to_initial_df()
    df = extract_words_terms(df)
    feature_scaler = FeatureScaler()

    dataframe_x = feature_scaler.fit_transform(df, df['y'])

    model = build_model(
        dataframe_x,
        df['y'],
        estimator_function,
    )
    _classifier = Classifier(
        model=model, estimator=estimator_function, features=feature_scaler.selected_features
    )

    if save:
        _classifier.save()


if __name__ == "__main__":
    builder_main(save=True)
