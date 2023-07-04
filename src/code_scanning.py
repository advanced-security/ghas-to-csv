# This holds all the things that do stuff for code scanning API

# Imports
from defusedcsv import csv
import requests


def list_repo_code_scanning_alerts(api_endpoint, github_pat, repo_name):
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
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(repo_name, response.status_code, response.text)
        )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(response.links["next"]["url"], headers=headers)
        response_json.extend(response.json())

    print("Found {} code scanning alerts in {}".format(len(response_json), repo_name))

    # Return code scanning alerts
    return response_json


def write_repo_cs_list(cs_list):
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
                "security_severity_level",
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
            if cs["state"] == "open":
                cs["fixed_at"] = "none"
                cs["dismissed_by"] = "none"
                cs["dismissed_at"] = "none"
                cs["dismissed_reason"] = "none"
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
                    cs["rule"].get("security_severity_level", "N/A"),
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


def list_org_code_scanning_alerts(api_endpoint, github_pat, org_name):
    """
    Get a list of all code scanning alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ code scanning alerts on the organization
    """

    # Get code scanning alerts
    url = "{}/orgs/{}/code-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, org_name
    )
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(org_name, response.status_code, response.text)
        )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(response.links["next"]["url"], headers=headers)
        response_json.extend(response.json())

    print("Found {} code scanning alerts in {}".format(len(response_json), org_name))

    # Return code scanning alerts
    return response_json


def write_org_cs_list(cs_list):
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
                "security_severity_level",
                "rule_tags",
                "rule_description",
                "rule_name",
                "tool_name",
                "tool_version",
                "most_recent_instance_ref",
                "most_recent_instance_state",
                "most_recent_instance_sha",
                "instances_url",
                "repo_name",
                "repo_owner",
                "repo_owner_type",
                "repo_owner_isadmin",
                "repo_url",
                "repo_isfork",
                "repo_isprivate",
            ]
        )
        for cs in cs_list:
            if cs["state"] == "open":
                cs["fixed_at"] = "none"
                cs["dismissed_by"] = "none"
                cs["dismissed_at"] = "none"
                cs["dismissed_reason"] = "none"
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
                    cs["rule"].get("security_severity_level", "N/A"),
                    cs["rule"]["tags"],
                    cs["rule"]["description"],
                    cs["rule"]["name"],
                    cs["tool"]["name"],
                    cs["tool"]["version"],
                    cs["most_recent_instance"]["ref"],
                    cs["most_recent_instance"]["state"],
                    cs["most_recent_instance"]["commit_sha"],
                    cs["instances_url"],
                    cs["repository"]["full_name"],
                    cs["repository"]["owner"]["login"],
                    cs["repository"]["owner"]["type"],
                    cs["repository"]["owner"]["site_admin"],
                    cs["repository"]["html_url"],
                    str(cs["repository"]["fork"]),
                    str(cs["repository"]["private"]),
                ]
            )


def list_enterprise_server_code_scanning_alerts(api_endpoint, github_pat, repo_list):
    """
    Get a list of all code scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository list in "org/repo" format (from enterprise.get_repo_report)

    Outputs:
    - List of _all_ code scanning alerts in enterprise that PAT user can access

    Notes:
    - Use `ghe-org-admin-promote` to gain ownership of all organizations.
    - Personal repos will not be reported on, as they cannot use code scanning.
    """

    alerts = []
    while True:
        try:
            repo_name = next(repo_list)  # skip the header by putting this up front
            alerts.append(
                list_repo_code_scanning_alerts(api_endpoint, github_pat, repo_name)
            )
        except StopIteration:
            break
        except Exception as e:
            print(e)
    return alerts


def write_enterprise_server_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.

    Outputs:
    - CSV file of code scanning alerts
    - CSV file of repositories not accessible or without code scanning enabled
    """

    for alert_list in cs_list:
        if type(alert_list) == list:
            print(alert_list)
            with open("cs_list.csv", "a") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "repository",
                        "repo_id",
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
                        "security_severity_level",
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
                for cs in alert_list:  # loop through each alert in the list
                    if cs["state"] == "open":
                        cs["fixed_at"] = "none"
                        cs["dismissed_by"] = "none"
                        cs["dismissed_at"] = "none"
                        cs["dismissed_reason"] = "none"
                    writer.writerow(
                        [
                            cs["repository"]["full_name"],
                            cs["repository"]["id"],
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
                            cs["rule"].get("security_severity_level", "N/A"),
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
        else:
            with open("excluded_repos.csv", "a") as g:
                writer = csv.writer(g)
                writer.writerow([alert_list])


def list_enterprise_cloud_code_scanning_alerts(
    api_endpoint, github_pat, enterprise_slug
):
    """
    Get a list of all code scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope

    Outputs:
    - List of _all_ code scanning alerts in enterprise that PAT user can access
    """

    # Get code scanning alerts
    url = "{}/enterprises/{}/code-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, enterprise_slug
    )
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(
                enterprise_slug, response.status_code, response.text
            )
        )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(response.links["next"]["url"], headers=headers)
        response_json.extend(response.json())

    print(
        "Found {} code scanning alerts in {}".format(
            len(response_json), enterprise_slug
        )
    )

    # Return code scanning alerts
    return response_json


def write_enterprise_cloud_cs_list(cs_list):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.

    Outputs:
    - CSV file of code scanning alerts
    - CSV file of repositories not accessible or without code scanning enabled
    """

    with open("cs_list.csv", "a") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "repository",
                "repo_id",
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
                "security_severity_level",
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
        for cs in cs_list:  # loop through each alert in the list
            if cs["state"] == "open":
                cs["fixed_at"] = "none"
                cs["dismissed_by"] = "none"
                cs["dismissed_at"] = "none"
                cs["dismissed_reason"] = "none"
            writer.writerow(
                [
                    cs["repository"]["full_name"],
                    cs["repository"]["id"],
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
                    cs["rule"].get("security_severity_level", "N/A"),
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
