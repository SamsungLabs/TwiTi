import copy
import json
from pathlib import Path

import pandas as pd
import torch
from keras.preprocessing.sequence import pad_sequences
from pytorch_pretrained_bert import BertAdam, BertForTokenClassification
from pytorch_pretrained_bert import BertTokenizer
from torch.nn import CrossEntropyLoss
from torch.utils.data import (
    TensorDataset,
    DataLoader,
    RandomSampler,
)

from ioc_extractor.ioc_regex import *
from ner import (
    MODEL_PATH,
    MODEL_CONFIG_PATH,
    BERT_INPUT_SEQUENCE_LENGTH,
    LABELS,
    DATA_PATH,
)


# Load Data
def load_data(data_path):
    data_path = Path(data_path)
    rows = []
    sent_idx = 1
    for data_file in data_path.glob("*.json"):
        with data_file.open() as f:
            data = json.load(f)
            for labeled_word in data:
                rows.append([sent_idx, labeled_word[0], labeled_word[1]])
                if labeled_word[0] == ".":
                    sent_idx += 1
    return pd.DataFrame(rows, columns=["sentence", "word", "label"])


def getter(df):
    agg_func = lambda s: [
        (w, l)
        for w, l in zip(s["word"].values.tolist(), s["label"].values.tolist())
    ]
    grouped = df.groupby("sentence").apply(agg_func)
    grouped_words = [s for s in grouped]

    sentences = [" ".join([s[0] for s in sent]) for sent in grouped_words]
    labels = [
        [(s[0], s[1]) for s in sent if s[1] != "O"] for sent in grouped_words
    ]

    return list(zip(sentences, labels))


# Process sentences
def process_terms(item):
    string = item[0][:-1] if item[0][-1] == "." else item[0]
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

    string = string.replace("-", " ")

    # replace cve-xxxx-xxxx into cvexxxxxxxx in tag (word)
    tags = copy.deepcopy(item[1])
    for i, tag in enumerate(tags):
        if regex_cve.search(tag[0]):
            tags[i] = (tag[0].replace("-", ""), tag[1])

    return string, tags


# tokenize
def check_word(subword, tokens, idx):
    if len(subword) == 0:
        return True

    if idx + 1 >= len(tokens):
        return False

    tmpword = re.sub("^##", "", tokens[idx + 1])
    if subword.startswith(tmpword):
        return check_word(subword[len(tmpword) :], tokens, idx + 1)
    else:
        return False


def label_X_subword(next_idx, tokens, label):
    if next_idx >= len(tokens):
        return label

    while tokens[next_idx].startswith("##"):
        label[next_idx] = "X"
        next_idx += 1
        if next_idx >= len(tokens):
            return label

    return label


def token_labeling(tokens, word, tag, label):
    for idx, token in enumerate(tokens):
        if word.startswith(token):
            if check_word(word[len(token) :], tokens, idx):
                label[idx] = tag
                label = label_X_subword(idx + 1, tokens, label)

    return label


def label_tokenize(tokenized_sents, processed_tags):
    synch_labels = []
    for idx, label in enumerate(processed_tags):
        synch_label = ["O"] * len(tokenized_sents[idx])
        for tag in label:
            synch_label = token_labeling(
                tokenized_sents[idx], tag[0], tag[1], synch_label
            )
        synch_labels.append(synch_label)

    return synch_labels


# long sent
def remove_long_sent(tokenized_sents, tokenized_tags):
    bert_sents = []
    bert_labels = []

    for x in tokenized_sents:
        if len(x) < BERT_INPUT_SEQUENCE_LENGTH:
            bert_sents.append(x)

    for x in tokenized_tags:
        if len(x) < BERT_INPUT_SEQUENCE_LENGTH:
            bert_labels.append(x)

    print("# of total sentence: {}".format(len(bert_sents)))
    print("# of total labels: {}".format(len(bert_labels)))

    return bert_sents, bert_labels


def build_model(full_fine_tunning=True, batch_size=32, epochs=3):
    df = load_data(DATA_PATH)
    df["word"] = df["word"].str.lower()

    data = getter(df)

    processed_texts = []
    processed_tags = []
    for item in data:
        string, tags = process_terms(item)
        processed_texts.append(string)
        processed_tags.append(tags)

    tokenizer = BertTokenizer.from_pretrained(
        "bert-base-uncased", do_lower_case=True
    )
    tokenized_sents = [
        tokenizer.tokenize("[CLS] " + sent + " [SEP]")
        for sent in processed_texts
    ]
    tokenized_tags = label_tokenize(tokenized_sents, processed_tags)

    bert_sents, bert_labels = remove_long_sent(tokenized_sents, tokenized_tags)

    # indexing
    input_ids = [tokenizer.convert_tokens_to_ids(x) for x in bert_sents]
    label_ids = [[LABELS.get(l) for l in lab] for lab in bert_labels]

    input_ids_pad = pad_sequences(
        input_ids,
        maxlen=BERT_INPUT_SEQUENCE_LENGTH,
        dtype="long",
        truncating="post",
        padding="post",
    )
    labels_ids_pad = pad_sequences(
        label_ids,
        maxlen=BERT_INPUT_SEQUENCE_LENGTH,
        value=LABELS["O"],
        dtype="long",
        truncating="post",
        padding="post",
    )

    attention_masks = []
    for seq in input_ids_pad:
        mask = [float(i > 0) for i in seq]
        attention_masks.append(mask)

    train_data = TensorDataset(
        torch.tensor(input_ids_pad),
        torch.tensor(attention_masks),
        torch.tensor(labels_ids_pad),
    )
    train_sampler = RandomSampler(train_data)
    train_dataloader = DataLoader(
        train_data, sampler=train_sampler, batch_size=batch_size
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    n_gpu = torch.cuda.device_count()
    print("GPU: {}".format(device))
    print("Number of GPUs: {}".format(n_gpu))
    if device == torch.device("cuda"):
        board = torch.cuda.get_device_name()
        print("Board: {}".format(board))

    model = BertForTokenClassification.from_pretrained(
        "bert-base-uncased", num_labels=len(LABELS)
    )

    if device == torch.device("cuda"):
        model.cuda()

    if full_fine_tunning:
        param_optimizer = list(model.named_parameters())
        no_decay = ["bias", "gamma", "beta"]
        optimizer_grouped_parameters = [
            {
                "params": [
                    p
                    for n, p in param_optimizer
                    if not any(nd in n for nd in no_decay)
                ],
                "weight_decay_rate": 0.01,
            },
            {
                "params": [
                    p
                    for n, p in param_optimizer
                    if any(nd in n for nd in no_decay)
                ],
                "weight_decay_rate": 0.0,
            },
        ]
    else:
        param_optimizer = list(model.classifier.named_parameters())
        optimizer_grouped_parameters = [
            {"params": [p for n, p in param_optimizer]}
        ]

    optimizer = BertAdam(optimizer_grouped_parameters, lr=5e-5, warmup=0.1)

    tr_loss_set = []

    for epoch in range(epochs):
        # train
        model.train()

        tr_loss = 0
        nb_tr_steps = 0

        for step, batch in enumerate(train_dataloader):
            batch = tuple(t.to(device) for t in batch)
            b_input_ids, b_input_masks, b_labels = batch

            logits = model(
                b_input_ids, token_type_ids=None, attention_mask=b_input_masks
            )
            loss_fct = CrossEntropyLoss()
            loss = loss_fct(logits.view(-1, len(LABELS)), b_labels.view(-1))

            tr_loss_set.append(loss.item())

            loss.backward()

            # gradient clipping
            torch.nn.utils.clip_grad_norm_(
                parameters=model.parameters(), max_norm=1.0
            )

            optimizer.step()
            model.zero_grad()

            tr_loss += loss.item()
            nb_tr_steps += 1

        print(f"# of EPOCH: {epoch}")
        print("Train loss: {}".format(tr_loss / nb_tr_steps))

    torch.save(model.state_dict(), str(MODEL_PATH))
    model.config.to_json_file(MODEL_CONFIG_PATH)


if __name__ == "__main__":
    build_model()
