"""Craft IoC (Indicator of Compromise) from variables of siem_parsing.py"""

import re
import ipaddress
from siem_parsing import clean_path

FILTER = re.compile(
    r"headers\.|params\.|query\.|state\.|webhookUrl"
    r"|executionMode|context\.link|context\.title"
    r"|context\.message|conditions|threat\."
    r"|\.(_id|_index|_score|sort)$"
)

IOC_FIELDS = {
    "email.from.address": "email",
    "email.to.address": "email",
    "email.cc.address": "email",
    "email.subject": "subject",
    "email.message_id": "message_id",
    "source.ip": "ip",
    "url.full": "url",
    "url.original": "url",
    "url.domain": "domain",
    "file.name": "filename",
    "hash.md5": "md5",
    "hash.sha1": "sha1",
    "hash.sha256": "sha256",
}


def filter(path):
    """return true if `path` is envelope noise rather than alert data"""
    return bool(FILTER.search(clean_path(path)))


def find_type(path):
    """look up the IoC type for a path, or None if the field is unknown"""
    field = clean_path(path)
    for name, ioc_type in IOC_FIELDS.items():
        if field == name or field.endswith("." + name):
            return ioc_type
    return None


def clean(value, ioc_type):
    """Normalize value on same ioc type"""
    value = str(value).strip()
    if ioc_type != "subject":
        value = value.strip('"')
    return value


def is_public_ip(value):
    """check value that was public ip or private ip"""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract(flat_data):
    """flat variables -> list of indicators    """
    iocs = []
    for path, value in flat_data.items():
        if filter(path):
            continue
        ioc_type = find_type(path)
        if not ioc_type:
            continue
        iocs.append({"type": ioc_type, "value": clean(value, ioc_type), "path": path})
    return iocs
