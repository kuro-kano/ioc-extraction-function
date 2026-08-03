"""main function to run code"""

from siem_ioc_extract import extract
from siem_parsing import parse


def main():
    """run and print"""
    flat_data = parse()
    iocs = extract(flat_data)

    for ioc in iocs:
        print(f"{ioc['type']:<12} {ioc['value']}")

    print(f"\nvariables : {len(flat_data)}")
    print(f"IoCs      : {len(iocs)}")


main()
