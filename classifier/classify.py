import logging
from typing import List

from classifier import Classifier, Estimator


logger = logging.getLogger(__name__)


def classify(model_path, estimator, feature_path,
             orig_tweet_documents: List[str]) -> List[bool]:
    _classifier = Classifier()
    _classifier.load(model_path, estimator, feature_path)

    pred_y = _classifier.predict(orig_tweet_documents)

    return list(pred_y)


if __name__ == "__main__":
    classify("./model.pkl", Estimator.RANDOMFOREST, "./features.json", [])
