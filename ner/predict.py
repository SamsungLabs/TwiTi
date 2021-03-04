import numpy as np
import torch
from pytorch_pretrained_bert import (
    BertTokenizer,
    BertForTokenClassification,
    BertConfig,
)

from ioc_extractor.ioc_regex import *
from ner import (
    MODEL_PATH,
    MODEL_CONFIG_PATH,
    BERT_INPUT_SEQUENCE_LENGTH,
    LABELS,
    idx2label,
)


def pre_processing(text):
    string = text[:-1].lower() if text[-1] == "." else text.lower()
    string = string.replace("[.]", ".")

    # replace url into urlterm
    urls = [m.group(0) for m in regex_url.finditer(string)]
    for url in urls:
        string = string.replace(url, "urlterm")

    # repalce ip into ipterm
    ips = regex_ip.findall(string)
    for ip in ips:
        string = string.replace(ip, "ipterm")

    # replace email into emailterm
    emails = regex_email.findall(string)
    for email in emails:
        string = string.replace(email, "emailterm")

    # replace domain into domainterm
    domains = regex_domain.findall(string)
    for domain in domains:
        string = string.replace(domain, "domainterm")

    # replace md5 into md5term
    hs = regex_md5.findall(string)
    for h in hs:
        string = string.replace(h, "md5term")

    # replace sha1 into sha1term
    hs = regex_sha1.findall(string)
    for h in hs:
        string = string.replace(h, "sha1term")

    # replace sha256 into sha256term
    hs = regex_sha256.findall(string)
    for h in hs:
        string = string.replace(h, "sha256term")

    # replace sha512 into sha512term
    hs = regex_sha512.findall(string)
    for h in hs:
        string = string.replace(h, "sha512term")

    # replace filename into filenameterm
    filenames = regex_filename.findall(string)
    for filename in filenames:
        string = string.replace(filename, "filenameterm")

    # replace filepath into filepathterm
    filepaths = regex_windows_filepath.findall(string)
    for filepath in filepaths:
        string = string.replace(filepath, "filepathterm")

    # replace registry into registryterm
    registries = regex_registry.findall(string)
    for registry in registries:
        string = string.replace(registry, "registryterm")

    # replace cve-xxxx-xxxx into cvexxxxxxxx in text
    regex_cve = re.compile(r"\b(cve\-\d{4}\-\d{4,7})\b")
    cves = regex_cve.findall(string)
    for cve in cves:
        string = string.replace(cve, cve.replace("-", ""))

    string = string.replace('"', "")
    string = string.replace('"', "")
    string = string.replace("#", "")
    string = string.replace("-", " ")

    return string


def predict(text, model, tokenizer, max_len):
    tokens = tokenizer.tokenize("[CLS] " + text + " [SEP]")

    input_ids = tokenizer.convert_tokens_to_ids(tokens)
    input_ids.extend([0] * (max_len - len(input_ids)))

    attention_mask = [float(i > 0) for i in input_ids]

    input_tensor = torch.tensor([input_ids])
    mask_tensor = torch.tensor([attention_mask])

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device == torch.device("cuda"):
        device_type = "cuda"
    else:
        device_type = "cpu"

    input_tensor = input_tensor.to(device_type)
    mask_tensor = mask_tensor.to(device_type)
    model.to(device_type)

    with torch.no_grad():
        logits = model(
            input_tensor, token_type_ids=None, attention_mask=mask_tensor
        )

    logits = logits.detach().cpu().numpy()
    pred = np.argmax(logits, axis=2)[0]
    pred = [idx2label(i) for i in pred]

    ids = []
    for i, tag in enumerate(pred):
        if tag != "O" and tag != "X":
            ids.append(i)

    entities = []
    for i in ids:
        word = tokens[i]
        s = i + 1
        if s < len(tokens):
            while tokens[s].startswith("##"):
                word += tokens[s][2:]
                s += 1

        entities.append((word, pred[i]))
    return entities


def load_model():
    config = BertConfig.from_json_file(MODEL_CONFIG_PATH)
    model = BertForTokenClassification(config, num_labels=len(LABELS))
    state_dict = torch.load(MODEL_PATH)
    model.load_state_dict(state_dict)
    model.eval()
    return (
        model,
        BertTokenizer.from_pretrained("bert-base-uncased", do_lower_case=True),
    )


def merge_entities(split_entities):
    entities = []
    merged_word = ""
    merged_label = ""
    for e in split_entities:
        word = e[0]
        label = e[1]
        if label.startswith("B_"):
            if merged_word:
                entities.append((merged_word, merged_label))
            merged_word = word
            merged_label = label[2:]
        elif label.startswith("I_"):
            merged_word += f" {word}"
    if merged_word:
        entities.append((merged_word, merged_label))
    return entities


class NER:
    def __init__(self):
        self.model, self.tokenizer = load_model()

    def extract(self, text):
        text = pre_processing(text)
        split_entities = predict(
            text, self.model, self.tokenizer, BERT_INPUT_SEQUENCE_LENGTH
        )
        return merge_entities(split_entities)
