"""
Create CSV file with specific information from a DMARC report
"""

from argparse import ArgumentParser
import xml.etree.ElementTree as ET


def parse_record(record: ET.Element) -> str:
    """
    This function is stupidly written but I don't feel
    like figuring out how to do it the right way
    """
    ip = ""
    fail = ""
    count = ""
    auth_pass = True
    domain = ""
    for element in record:
        if element.tag == "row":
            for node in element:
                if node.tag == "source_ip":
                    ip = node.text
                    continue
                if node.tag == "count":
                    count = node.text
                    continue
                if node.tag == "policy_evaluated":
                    for item in node:
                        if item.text == "fail":
                            fail += item.tag
        if element.tag == "auth_results":
            for node in element:
                if node.tag == fail:
                    for item in node:
                        if item.tag == "domain":
                            domain = item.text
                            continue
                        if item.tag == "result":
                            auth_pass = item.text == "pass"
                            continue
    return ",".join([ip, fail, count, str(auth_pass), domain])


def parse_report(root: ET.Element) -> str:
    """Return a CSV string with all of the desired information from a report"""
    all_csv: list[str] = []
    for element in root:
        if element.tag == "record":
            csv = parse_record(element)
            if csv.split(",")[1]:
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
