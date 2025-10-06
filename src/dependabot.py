# This holds all the things that do stuff for dependabot API

# Imports
from defusedcsv import csv
from . import api_helpers


def list_repo_dependabot_alerts(api_endpoint, github_pat, repo_name):
    """
    Get all the dependabot alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ dependency alerts on the repository
    """
    url = f"{api_endpoint}/repos/{repo_name}/dependabot/alerts?per_page=100&after="
    dependabot_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(dependabot_alerts)} dependabot alerts in {repo_name}")
    return dependabot_alerts


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
    url = f"{api_endpoint}/orgs/{org_name}/dependabot/alerts?per_page=100&after="
    dependabot_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(dependabot_alerts)} dependabot alerts in {org_name}")
    return dependabot_alerts


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
    url = f"{api_endpoint}/enterprises/{enterprise_slug}/dependabot/alerts?per_page=100&after="
    dependabot_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(dependabot_alerts)} dependabot alerts in {enterprise_slug}")
    return dependabot_alerts


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
