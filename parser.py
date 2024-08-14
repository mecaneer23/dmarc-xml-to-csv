"""
Create CSV file with specific information from a DMARC report
"""

from argparse import ArgumentParser
import xml.etree.ElementTree as ET


def parse_row(row: ET.Element) -> tuple[str, str, str]:
    """Parse a single row from a DMARC report"""
    ip = ""
    count = ""
    fail = ""
    for node in row:
        if node.tag == "source_ip":
            ip = node.text or ""
            continue
        if node.tag == "count":
            count = node.text or ""
            continue
        if node.tag == "policy_evaluated":
            for item in node:
                if item.text == "fail":
                    fail += item.tag
    return (ip, fail, count)


def parse_auth_results(auth_results: ET.Element, fail: str) -> tuple[bool, str]:
    """Parse the auth results"""
    auth_pass = True
    domain = ""
    for node in auth_results:
        if node.tag != fail:
            continue
        for item in node:
            if item.tag == "domain":
                domain = item.text or ""
                continue
            if item.tag == "result":
                auth_pass = item.text == "pass"
    return (auth_pass, domain)


def parse_record(record: ET.Element) -> str:
    """Parse all necessary information and return as a csv string"""
    ip = ""
    fail = ""
    count = ""
    auth_pass = True
    domain = ""
    for element in record:
        if element.tag == "row":
            ip, fail, count = parse_row(element)
        if element.tag == "auth_results":
            auth_pass, domain = parse_auth_results(element, fail)
    return ",".join([ip, fail, count, str(auth_pass), domain])


def parse_report(root: ET.Element) -> str:
    """Return a CSV string with all of the desired information from a report"""
    all_csv: list[str] = []
    for element in root:
        if element.tag == "record":
            csv = parse_record(element)
            if csv.split(",")[1]:  # if the record failed
                all_csv.append(csv)
    return "\n".join(all_csv)


def get_args() -> str:
    """Get filepath using argparse"""
    parser = ArgumentParser(description="Create CSV file from a DMARC report")
    parser.add_argument("filepath", help="Path to the DMARC report XML file")
    return parser.parse_args().filepath


def main(filepath: str) -> None:
    """Entry point for parser"""
    tree = ET.parse(filepath)
    root = tree.getroot()

    report = parse_report(root)
    if report:
        print(filepath)
        # print("ip,spf_or_dkim_fail,count,auth pass?,auth domain")
        print(report)
        return
    # print(f"No failed reports in {filepath}")


if __name__ == "__main__":
    main(get_args())
