# This holds all the logic for the various enterprise differences.

# Imports
from defusedcsv import csv
from time import sleep
import requests


def get_enterprise_version(api_endpoint):
    """
    Get the version of GitHub Enterprise.  It'll be used to account for
    differences between GHES and GHAE and GHEC, like the organization secret
    scanning API not existing outside GHEC.

    GitHub AE returns "GitHub AE" as of M2
    GHES returns the version of GHES that's installed (e.g. "3.4.0")
    """
    if api_endpoint != "https://api.github.com":
        url = f"{api_endpoint}/meta"
        response = requests.get(url)
        if not response.ok:
            raise Exception(response.status_code, response.text)
        return response.json().get("installed_version", "GitHub version not found in response")
    else:
        return "GHEC"


def get_repo_report(url, github_pat):
    """
    Get the `all_repositories.csv` report from GHES / GHAE.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {github_pat}",
    }
    url = f"{url}/stafftools/reports/all_repositories.csv"
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(response.status_code, response.text)
    if response.status_code == 202:  # report needs to be generated
        while response.status_code == 202:
            print("Waiting a minute for the report to be generated ...")
            sleep(60)
            response = requests.get(url, headers=headers)
    elif response.status_code == 200:  # report is ready
        print("Report is ready!  Reading it now ...")
        for row in csv.reader(response.text.splitlines()):  # skip user repos
            if row[2] == "Organization":
                yield f"{row[3]}/{row[5]}"
            else:
                pass
    else:  # something went wrong with fetching the report
        exit(f"Error: {response.status_code} {response.text}")
