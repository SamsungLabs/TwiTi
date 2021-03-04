import json
from argparse import ArgumentParser
from pathlib import Path

from classifier import classifier_builder, classify, Estimator, CLASSIFIER_PATH


def main():
    arg_parser = ArgumentParser(prog="classifier")
    subparsers = arg_parser.add_subparsers(
        dest="command", metavar="command", required=True
    )
    build_parser = subparsers.add_parser("build", help="Build classifier")
    classify_parser = subparsers.add_parser("classify", help="Classify tweets")
    classify_parser.add_argument(
        "tweets", help="File path of tweet data saved as json format",
    )

    args = arg_parser.parse_args()

    if args.command == "build":
        classifier_builder.builder_main(save=True)
    elif args.command == "classify":
        with Path(args.tweets).open() as f:
            tweets = json.load(f)
            tweet_texts = []
            for tweet in tweets:
                if "retweeted_status" in tweet:
                    text = tweet["retweeted_status"]["full_text"]
                else:
                    text = tweet["full_text"]
                tweet_texts.append(text)
        labels = classify.classify(
            CLASSIFIER_PATH / "model.pkl",
            Estimator.RANDOMFOREST,
            CLASSIFIER_PATH / "features.json",
            tweet_texts,
        )
        with Path("./tweet_label.json").open("w") as f:
            json.dump([bool(label) for label in labels], f)


if __name__ == "__main__":
    main()
