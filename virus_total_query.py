import json
import pandas as pd
import requests
import datetime
from tabulate import tabulate


domains = """
google.com
"""

api_key = API_KEY
result = pd.DataFrame(columns=["domain", "vt", "vendors"])
whitelist = []

request_headers = {
    "Accept": "application/json",
    "x-apikey": api_key,
}


def get_domains():
    domain_list = [
        domain.replace("]", "")
        .replace("[", "")
        .replace("'", "")
        .replace("http:", "")
        .replace("https:", "")
        .replace("www.", "")
        .replace("/", "")
        .replace("*.", "")
        for domain in domains.split()
    ]
    return domain_list


def get_domain_info(domain):
    domain_info_api = f"https://www.virustotal.com/api/v3/domains/{domain}"
    domain_info = requests.get(domain_info_api, headers=request_headers).json()
    return domain_info


def get_downloaded_files(domain):
    file_downloads_api = (
        f"https://www.virustotal.com/api/v3/domains/{domain}/downloaded_files?limit=10"
    )
    file_downloads = requests.get(file_downloads_api, headers=request_headers).json()
    return file_downloads


def get_vendors(response):
    vendor_list = [x for x in response["data"]["attributes"]["last_analysis_results"]]
    return vendor_list


def get_categories(response, vendors):
    categories = pd.DataFrame(
        [
            response["data"]["attributes"]["last_analysis_results"][vendor]["category"]
            for vendor in vendors
        ],
        columns=["category"],
    )
    category_count = categories.groupby(["category"]).size()
    return category_count


def get_file_analysis_vendors(response):
    vendor_list = [x for x in response["attributes"]["last_analysis_results"]]
    return vendor_list


def get_flagging_vendors(vendors):
    mal_flag_vendors = []
    for vendor in vendors:
        if (
            domain_info["data"]["attributes"]["last_analysis_results"][vendor][
                "category"
            ]
            == "malicious"
        ):
            mal_flag_vendors.append(vendor)
        else:
            pass
    return mal_flag_vendors


def get_file_flags(info, vendors):
    mal_flag_vendors = []
    for vendor in vendors:
        if (
            info["attributes"]["last_analysis_results"][vendor]["category"]
            == "malicious"
        ):
            mal_flag_vendors.append(vendor)
        else:
            pass
    return len(mal_flag_vendors)


def iterate_files(response):
    files = response["data"]
    file_list = []
    file_info = {}
    for x in range(0, len(files)):
        file_info.clear()

        try:
            file_info["sha256"] = files[x]["attributes"]["sha256"]
            file_info["file_type"] = files[x]["attributes"]["type_description"]
            file_info["last_analysis_date"] = datetime.datetime.fromtimestamp(
                files[x]["attributes"]["last_analysis_date"]
            ).isoformat()
            file_analysis_vendors = get_file_analysis_vendors(files[x])
            file_info["file_flags"] = get_file_flags(files[x], file_analysis_vendors)
        except:
            file_info["sha256"] = 'not found'
            file_info["file_type"] = 'not found'
            file_info["last_analysis_date"] = 'not found'
            file_analysis_vendors = 'not found'
            file_info["file_flags"] = 'not found'
        
        file_list.append(file_info)

    return file_list


def get_urls(domain):
    urls_api = f"https://www.virustotal.com/api/v3/domains/{domain}/urls?limit=10"

    url_response = requests.get(urls_api, headers=request_headers).json()

    return url_response


if __name__ == "__main__":

    i = 0
    domains = get_domains()
    for domain in domains:
        domain_info = get_domain_info(domain)
        vendors = get_vendors(domain_info)
        vendor_detections = get_flagging_vendors(vendors)
        analysis_stats = domain_info["data"]["attributes"]["last_analysis_stats"]

        try:
            creation_date = datetime.datetime.fromtimestamp(
                domain_info["data"]["attributes"]["creation_date"]
            ).isoformat()
        except KeyError:
            creation_date = "not available"

        general_categories = domain_info["data"]["attributes"]["categories"]
        outgoing_links = domain_info["data"]["links"]

        downloaded_files = get_downloaded_files(domain)
        file_details = iterate_files(downloaded_files)

        urls = get_urls(domain)
        # print(urls)

        # print(f"Domain: {domain}")
        # print(f"Stats: {analysis_stats}")
        # print(f"Flagging Vendors: {vendor_detections}")
        # print(f"Creation Date: {creation_date}")
        # print(f"Categories: {general_categories}")
        # print(f"links: {outgoing_links}")
        # print(f"Downloaded Files:\n{file_details}")
        # analysis_stats = list(analysis_stats.items())
        # infor = [{"Domain" : domain, "Stats" : ["\n".join(analysis_stats)]}]

        stats = ""
        for x, y in analysis_stats.items():
            stats = f"{stats}\n{x}:{y}\n"

        mal_vendors = ""
        for x in vendor_detections:
            mal_vendors = f"{mal_vendors}{x}\n"

        vendor_comments = ""
        for x, y in general_categories.items():
            vendor_comments = f"{vendor_comments}{x} : {y}\n\n"

        info = f"Domain: {domain}\n\nCreation Date: {creation_date}"

        results = [
            {
                "Info": info,
                "Verdicts": stats,
                "Flagging Vendors": mal_vendors,
                "Vendor Comments": vendor_comments,
            }
        ]

        print(tabulate(results, headers="keys", tablefmt="grid"))
        print(tabulate(file_details, headers="keys", tablefmt="grid"))
        print(f"\nlinks: {outgoing_links}\n")

    #         result.at[i, "vendors"] = ", ".join(flagging_vendors)

    #         print(f'Vendors flaggin as malicious:\n{", ".join(malicious_detections)}')

    #         result.at[i, "vendors"] = ", ".join(malicious_detections)

    #         print(category_totals)

    #         if "malicious" in category_totals:
    #             if category_totals["malicious"] >= 4:
    #                 result.at[i, "vt"] = "inspect"
    #             else:
    #                 result.at[i, "vt"] = "extend"
    #                 whitelist.append(domain)
    #         else:
    #             result.at[i, "vt"] = "extend"
    #             whitelist.append(domain)

    #         i += 1

    #     whitelist = pd.DataFrame(whitelist)
    #     whitelist.to_csv("whitelist_extensions.txt", index=False, header=False)
    #     whitelist.to_clipboard("whitelist_extensions.txt", index=False, header=False)

    #     print(result)
    #     print("\n\n----Whitelist----")
    #     print(whitelist)

    # # "data": {
    #         # "attributes":
    #         #      "creation_date"
    #         #      "categories"
    #         #      "total_votes"
    #         #      "links"

    # # {


