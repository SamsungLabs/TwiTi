# NER
We built NER model by fine-tuning [BERT](https://arxiv.org/abs/1810.04805) model. More information about BERT-based NER is described in [Twiti_Appendix.pdf](Twiti_Appendix.pdf).

## Data
We tagged tweets and documents as [IOB2 format](https://en.wikipedia.org/wiki/Inside%E2%80%93outside%E2%80%93beginning_(tagging)) with 7 labels.  
List of labels
- technology 
- malware
- company
- organization
- product
- attack_vector
- cybervulnerability

You can find examples of data in [data](data) directory. 

## Build model
Run command below in ```TwiTi``` directory

```bash
python -m ner.builder
```
