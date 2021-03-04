from pathlib import Path


NER_PATH = Path(__file__).parent
MODEL_PATH = NER_PATH / "model.pth"
MODEL_CONFIG_PATH = NER_PATH / "model_conf.json"
DATA_PATH = NER_PATH / "data"
BERT_INPUT_SEQUENCE_LENGTH = 128
LABELS = {
    "B_technology": 0,
    "I_technology": 1,
    "B_malware": 2,
    "I_malware": 3,
    "B_company": 4,
    "I_company": 5,
    "B_organization": 6,
    "I_organization": 7,
    "B_product": 8,
    "I_product": 9,
    "B_attack_vector": 10,
    "I_attack_vector": 11,
    "B_cybervulnerability": 12,
    "I_cybervulnerability": 13,
    "O": 14,
    "X": 15,
}


def idx2label(idx):
    for label, index in LABELS.items():
        if idx == index:
            return label
