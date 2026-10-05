import json


def print_json(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))
