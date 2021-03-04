# TwiTi

<p align="center">
    <img src="logo/TwiTi.png">
</p>

TwiTi, a tool for extracting IOCs from tweets, can collect a large number of fresh, accurate IOCs.   
TwiTi does
- classifying whether a tweet contains IOCs or not.
- extracting IOCs from a tweet and also from links mentioned in a tweet.

For more details please refer to our paper,     
"\#Twiti: Social Listening for Threat Intelligence" (TheWebConf 2021)   <!-- TODO: Link to paper -->   
Also, you can find supplementary materials of the paper in [data](data) directory.

## Requirements
### Python
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/release/python-370/)
```bash
pip install -r requirements.txt
```

### NER
TwiTi utilizes NER model for text processing. NER model should be built before run.   
Please refer to [ner/README.md](ner/README.md) for more information.

## Run
Run commands below in ```TwiTi``` directory
### IOC extraction
```bash
python -m ioc_extractor --help
```

### Tweet classification
```bash
python -m classifier --help
```
