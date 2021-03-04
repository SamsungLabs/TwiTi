import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)
PATH = Path(__file__).resolve().parent

try:
    with open(PATH.joinpath('config.yaml'), 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    with open(PATH.joinpath('log.yaml'), 'r') as f:
        log_config = yaml.load(f, Loader=yaml.FullLoader)
except (IOError, OSError):
    logger.exception("Failed to read config file")
    raise
