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
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(repo_name, response.status_code, response.text)
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
                "cvss_score",
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
                    alert["security_advisory"]["cvss"]["score"],
                ]
            )


def list_org_dependabot_alerts(api_endpoint, github_pat, org_name):
    """
    Get a list of all dependabot alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ dependency alerts on the organization
    """

    # Get dependabot alerts
    url = "{}/orgs/{}/dependabot/alerts?per_page=100&page=1".format(
        api_endpoint, org_name
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github+json",
        },
    )
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(org_name, response.status_code, response.text)
        )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={"Authorization": "token {}".format(github_pat)},
        )
        response_json.extend(response.json())

    print("Found {} dependabot alerts in {}".format(len(response_json), org_name))

    # Return dependabot alerts
    return response_json


def list_enterprise_dependabot_alerts(api_endpoint, github_pat, enterprise_slug):
    """
    Get a list of all dependabot alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Enterprise slug (enterprise name URL, documented below)
        - https://docs.github.com/en/rest/reference/enterprise-admin

    Outputs:
    - List of _all_ dependency alerts on the enterprise
    """

    # Get dependabot alerts
    url = "{}/enterprises/{}/dependabot/alerts?per_page=100&page=1".format(
        api_endpoint, enterprise_slug
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github+json",
        },
    )
    if not response.ok:
        raise Exception(
            "API error,{},{},{}".format(
                enterprise_slug, response.status_code, response.text
            )
        )
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={"Authorization": "token {}".format(github_pat)},
        )
        response_json.extend(response.json())

    print(
        "Found {} dependabot alerts in {}".format(len(response_json), enterprise_slug)
    )

    # Return dependabot alerts
    return response_json


def write_org_or_enterprise_dependabot_list(dependabot_list):
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
                "cvss_score",
                "repo_name",
                "repo_owner",
                "repo_owner_type",
                "repo_owner_isadmin",
                "repo_url",
                "repo_isfork",
                "repo_isprivate",
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
                    alert["security_advisory"]["cvss"]["score"],
                    alert["repository"]["full_name"],
                    alert["repository"]["owner"]["login"],
                    alert["repository"]["owner"]["type"],
                    alert["repository"]["owner"]["site_admin"],
                    alert["repository"]["html_url"],
                    str(alert["repository"]["fork"]),
                    str(alert["repository"]["private"]),
                ]
            )
