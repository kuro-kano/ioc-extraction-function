"""Parsing data from Elastic SIEM to made it easier to craft IoC (Indicator of Compomise)"""

import json, re
from pathlib import Path

from flatten_json import flatten as flatten_json

# ./data/example_data.txt
DATA_FILE = Path(__file__).parent / "data" / "example_data.txt"

FILTER = re.compile(
    r"headers\.|params\.|query\.|state\.|webhookUrl"
    r"|executionMode|context\.link|context\.title"
    r"|context\.message|conditions|threat\."
    r"|\.(_id|_index|_score|sort)$"
)

def load(path):
    """read a JSON file -> Python objects"""
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def filter(data):
    """return true if `data` is unused data"""
    return bool(FILTER.search(data))


def clean_path(path):
    """remove list positions like .0 on path output"""
    path = re.sub(r"^\d+\.", "", path)
    return re.sub(r"\.\d+(?=\.|$)", "", path)


def flatten(data):
    """flat JSON data to simple variable"""
    if isinstance(data, list):
        data = {str(i): value for i, value in enumerate(data)}
    return flatten_json(data, separator=".")


def main(data):
    """main function... yea main function"""
    flat_data = flatten(data)
    for path, value in flat_data.items():
        field = clean_path(path)
        if filter(field):
            continue
        print(f"{field} = {value}")


main(load(DATA_FILE))
