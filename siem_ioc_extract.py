"""Craft IoC (Indicator of Compromise) from variables of siem_parsing.py"""

import re
from siem_parsing import clean_path

FILTER = re.compile(
    r"headers\.|params\.|query\.|state\.|webhookUrl"
    r"|executionMode|context\.link|context\.title"
    r"|context\.message|conditions|threat\."
    r"|\.(_id|_index|_score|sort)$"
)

IOC_FIELDS = {
    "source.ip": "ip",
    "destination.ip": "ip",
    "host.ip": "ip",
    "client.ip": "ip",
    "server.ip": "ip",
    "url.full": "url",
    "url.original": "url",
    "url.domain": "domain",
    "dns.question.name": "domain",
    "email.from.address": "email",
    "email.to.address": "email",
    "email.cc.address": "email",
    "email.subject": "subject",
    "email.message_id": "message_id",
    "hash.md5": "md5",
    "hash.sha1": "sha1",
    "hash.sha256": "sha256",
    "file.name": "filename",
    "file.path": "filepath",
    "process.executable": "filepath",
    "parent.executable": "filepath",
    "process.command_line": "command",
    "registry.path": "registry",
    "vulnerability.id": "cve",
}


def is_skipped(path):
    """return true if `path` is envelope noise rather than alert data"""
    return bool(FILTER.search(clean_path(path)))


def find_type(path):
    """look up the IoC type for a path, or None if the field is unknown"""
    field = clean_path(path)
    for name, ioc_type in IOC_FIELDS.items():
        if field == name or field.endswith("." + name):
            return ioc_type
    return None


def extract(flat_data):
    """flat variables -> list of indicators    """
    iocs = []
    for path, value in flat_data.items():
        if is_skipped(path):
            continue
        ioc_type = find_type(path)
        if not ioc_type:
            continue
        iocs.append({"type": ioc_type, "value": value, "path": path})
    return iocs
