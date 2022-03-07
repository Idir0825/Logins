import json


def save_db(file_path: str, data=None):
    if data is None:
        data = {}

    data = data
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def load_db(file_path: str) -> dict:
    with open(file_path, "r") as f:
        data = json.load(f)

    return data
