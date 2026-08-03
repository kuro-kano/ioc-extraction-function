"""Parsing data from Elastic SIEM to made it easier to craft IoC"""

import json
import re
from pathlib import Path # file path

from flatten_json import flatten as flatten_json

# ./data/example_data.txt
DATA_FILE = Path(__file__).parent / "data" / "example_data.txt"


def load(path):
    """read a JSON file -> Python objects"""
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def clean_path(path):
    """remove list positions like .0 on path output"""
    path = re.sub(r"^\d+\.", "", path)
    return re.sub(r"\.\d+(?=\.|$)", "", path)


def flatten(data):
    """flat JSON data to simple variable"""
    if isinstance(data, list):
        data = {str(i): value for i, value in enumerate(data)}
    return flatten_json(data, separator=".")


def parse(path=DATA_FILE):
    """a SIEM alert file -> {"body.context.hits.0._source.source.ip": "1.2.3.4"}"""
    return flatten(load(path))


# Only runs when this file is executed directly, never on import.
if __name__ == "__main__":
    print(json.dumps(parse(), indent=2, ensure_ascii=False))
