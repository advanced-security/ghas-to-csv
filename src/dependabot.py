# This holds all the things that do stuff for code scanning API

# Imports
from defusedcsv import csv
import requests


def list_repo_dependabot_alerts(api_endpoint, github_pat, repo_name):
    """
    Get all the code scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ dependency alerts on the repository
    """

    # Get code scanning alerts
    url = "{}/repos/{}/dependabot/alerts?per_page=100&page=1".format(
        api_endpoint, repo_name
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github+json",
        },
    )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={"Authorization": "token {}".format(github_pat)},
        )
        response_json.extend(response.json())

    print("Found {} dependabot alerts in {}".format(len(response_json), repo_name))

    # Return code scanning alerts
    return response_json


def write_repo_dependabot_list(dependabot_list):
    """
    Write the list of dependabot alerts to a CSV file.

    Inputs:
    - List of dependabot alerts

    Outputs:
    - CSV file of dependabot alerts
    """
    with open("dependabot_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "state",
                "created_at",
                "updated_at",
                "fixed_at",
                "dismissed_at",
                "dismissed_by",
                "dismissed_reason",
                "html_url",
                "dependency_manifest",
                "dependency_ecosystem",
                "dependency_name",
                "severity",
                "ghsa_id",
                "cve_id",
            ]
        )
        for alert in dependabot_list:
            if alert["state"] == "open":
                alert["fixed_at"] = "none"
                alert["dismissed_by"] = "none"
                alert["dismissed_at"] = "none"
                alert["dismissed_reason"] = "none"
            if alert["state"] == "dismissed":
                alert["fixed_at"] = "none"
            if alert["state"] == "fixed":
                alert["dismissed_by"] = "none"
                alert["dismissed_at"] = "none"
                alert["dismissed_reason"] = "none"
            writer.writerow(
                [
                    alert["number"],
                    alert["state"],
                    alert["created_at"],
                    alert["updated_at"],
                    alert["fixed_at"],
                    alert["dismissed_at"],
                    alert["dismissed_by"],
                    alert["dismissed_reason"],
                    alert["html_url"],
                    alert["dependency"]["manifest_path"],
                    alert["dependency"]["package"]["ecosystem"],
                    alert["dependency"]["package"]["name"],
                    alert["security_vulnerability"]["severity"],
                    alert["security_advisory"]["ghsa_id"],
                    alert["security_advisory"]["cve_id"],
                ]
            )
