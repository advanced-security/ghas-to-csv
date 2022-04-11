# This holds all the things that do stuff for code scanning API

# Imports
import csv
import requests


def list_code_scanning_alerts(api_endpoint, github_pat, repo_name):
    """
    Get a list of all code scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ code scanning alerts on the repository
    """

    # Get code scanning alerts
    url = "{}/repos/{}/code-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, repo_name
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/sarif+json",
        },
    )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={"Authorization": "token {}".format(github_pat)},
        )
        response_json.extend(response.json())

    print("Found {} code scanning alerts in {}".format(len(response_json), repo_name))

    # Return code scanning alerts
    return response_json


def write_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List of code scanning alerts

    Outputs:
    - CSV file of code scanning alerts
    """

    # Write code scanning alerts to csv file
    with open("cs_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "fixed_at",
                "dismissed_by",
                "dismissed_at",
                "dismissed_reason",
                "rule_id",
                "rule_severity",
                "rule_tags",
                "rule_description",
                "rule_name",
                "tool_name",
                "tool_version",
                "most_recent_instance_ref",
                "most_recent_instance_state",
                "most_recent_instance_sha",
                "instances_url",
            ]
        )
        for cs in cs_list:
            writer.writerow(
                [
                    cs["number"],
                    cs["created_at"],
                    cs["html_url"],
                    cs["state"],
                    cs["fixed_at"],
                    cs["dismissed_by"],
                    cs["dismissed_at"],
                    cs["dismissed_reason"],
                    cs["rule"]["id"],
                    cs["rule"]["severity"],
                    cs["rule"]["tags"],
                    cs["rule"]["description"],
                    cs["rule"]["name"],
                    cs["tool"]["name"],
                    cs["tool"]["version"],
                    cs["most_recent_instance"]["ref"],
                    cs["most_recent_instance"]["state"],
                    cs["most_recent_instance"]["commit_sha"],
                    cs["instances_url"],
                ]
            )
