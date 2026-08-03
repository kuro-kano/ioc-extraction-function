"""main function to run code"""

from siem_ioc_extract import extract, is_public_ip
from siem_parsing import parse


def main():
    """run and print"""
    flat_data = parse()
    iocs = extract(flat_data)

    for ioc in iocs:
        # test public_ip function
        # ok_ip = is_public_ip(ioc["value"]) if ioc["type"] == "ip" else ""
        # print(f"{ioc['type']:<12} {ioc['value']} {ok_ip}")

        print(f"{ioc['type']:<12} {ioc['value']} {ioc['path']}\n")

    print(f"\nvariables : {len(flat_data)}")
    print(f"IoCs      : {len(iocs)}")


main()
