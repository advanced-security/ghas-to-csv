# This holds all the things that do stuff for secret scanning API

# Imports
from defusedcsv import csv
from . import api_helpers


def get_repo_ss_alerts(api_endpoint, github_pat, repo_name):
    """
    Get all the secret scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ secret scanning alerts on the repository
    """
    url = f"{api_endpoint}/repos/{repo_name}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(ss_alerts)} secret scanning alerts in {repo_name}")
    return ss_alerts


def write_repo_ss_list(secrets_list):
    """
    Write the list of repository secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    if len(secrets_list) == 0:
        print("No secret scanning alerts found")
        return
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "secret_type",
                "secret_type_display_name",
            ]
        )
        for alert in secrets_list:
            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                ]
            )


def get_org_ss_alerts(api_endpoint, github_pat, org_name):
    """
    Get all the secret scanning alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ secret scanning alerts on the organization
    """
    url = f"{api_endpoint}/orgs/{org_name}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(ss_alerts)} secret scanning alerts in {org_name}")
    return ss_alerts


def write_org_ss_list(secrets_list):
    """
    Write the list of organization secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    if len(secrets_list) == 0:
        print("No secret scanning alerts found")
        return
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "secret_type",
                "secret_type_display_name",
                "repo_name",
                "repo_owner",
                "repo_owner_type",
                "repo_owner_isadmin",
                "repo_url",
                "repo_isfork",
                "repo_isprivate",
            ]
        )
        for alert in secrets_list:
            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                    alert["repository"]["full_name"],
                    alert["repository"]["owner"]["login"],
                    alert["repository"]["owner"]["type"],
                    alert["repository"]["owner"]["site_admin"],
                    alert["repository"]["html_url"],
                    str(alert["repository"]["fork"]),
                    str(alert["repository"]["private"]),
                ]
            )


def get_enterprise_ss_alerts(api_endpoint, github_pat, enterprise_slug):
    """
    Get all the secret scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Enterprise slug (enterprise name URL, documented below)
        - https://docs.github.com/en/rest/reference/enterprise-admin

    Outputs:
    - List of _all_ secret scanning alerts on the enterprise
    """
    url = f"{api_endpoint}/enterprises/{enterprise_slug}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(ss_alerts)} secret scanning alerts in {enterprise_slug}")
    return ss_alerts


def write_enterprise_ss_list(secrets_list):
    """
    Write the list of enterprise secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    if len(secrets_list) == 0:
        print("No secret scanning alerts found")
        return
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "secret_type",
                "secret_type_display_name",
                "repo_name",
                "repo_owner",
                "repo_owner_type",
                "repo_owner_isadmin",
                "repo_url",
                "repo_isfork",
                "repo_isprivate",
            ]
        )
        for alert in secrets_list:
            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                    alert["repository"]["full_name"],
                    alert["repository"]["owner"]["login"],
                    alert["repository"]["owner"]["type"],
                    alert["repository"]["owner"]["site_admin"],
                    alert["repository"]["html_url"],
                    str(alert["repository"]["fork"]),
                    str(alert["repository"]["private"]),
                ]
            )
