import json
from argparse import ArgumentParser
from pathlib import Path

from ioc_extractor.ioc_extract_manager import IoCExtractManager


def main():
    arg_parser = ArgumentParser(
        prog="ioc_extractor",
        description="""\
        Extracts IOC from tweet texts. 
        Input format is list of the Tweet object from Twitter API.
        """,
    )
    arg_parser.add_argument(
        "tweets", help="File path of tweet data saved as json format",
    )
    arg_parser.add_argument(
        "-E",
        "--expand_external",
        action="store_true",
        help="Expand shorten links by directly accessing links. "
        "It has risks to access malicious url",
    )
    args = arg_parser.parse_args()

    with Path(args.tweets).open() as f:
        tweets = json.load(f)

    ioc_extractor = IoCExtractManager()
    ioc_object_list = ioc_extractor.ioc_extraction(
        tweets, args.expand_external
    )
    ioc_object_list = ioc_extractor.resolve_external_ioc(
        ioc_object_list, tweets
    )

    with Path("./extracted_iocs.json").open("w") as f:
        json.dump(ioc_object_list, f)


if __name__ == "__main__":
    main()
