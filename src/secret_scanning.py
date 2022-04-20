# This holds all the things that do stuff for secret scanning API

# Imports
import csv
import requests


def get_repo_secret_scanning_alerts(api_endpoint, github_pat, repo_name):
    """
    Get all the secret scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ secret scanning alerts on the repository
    """

    # Get secret scanning alerts
    url = "{}/repos/{}/secret-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, repo_name
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github.v3+json",
        },
    )
    response_json = response.json()
    # The secret scanning API returns a code of 404 if there are no alerts,
    # secret scanning is disabled, or the repository is public.
    if response.status_code == 404:
        return ["not found"]
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={
                "Authorization": "token {}".format(github_pat),
                "Accept": "application/vnd.github.v3+json",
            },
        )
        response_json.extend(response.json())

    print("Found {} secret scanning alerts in {}".format(len(response_json), repo_name))

    # Return secret scanning alerts
    return response_json


def write_repo_secrets_list(secrets_list):
    """
    Write the list of repository secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """

    if secrets_list == ["not found"]:
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
            if alert["state"] == "open":
                alert["resolution"] = "none"
                alert["resolved_at"] = "none"
                alert["resolved_by"] = {
                    "login": "none",
                    "type": "none",
                    "site_admin": "none",
                }
            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    alert["resolved_by"]["login"],
                    alert["resolved_by"]["type"],
                    alert["resolved_by"]["site_admin"],
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                ]
            )


def get_org_secret_scanning_alerts(api_endpoint, github_pat, org_name):
    """
    Get all the secret scanning alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ secret scanning alerts on the organization
    """

    # Get secret scanning alerts
    url = "{}/orgs/{}/secret-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, org_name
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github.v3+json",
        },
    )
    response_json = response.json()
    # The secret scanning API returns a code of 404 if there are no alerts,
    # secret scanning is disabled, or the repository is public.
    if response.status_code == 404:
        return ["not found"]
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={
                "Authorization": "token {}".format(github_pat),
                "Accept": "application/vnd.github.v3+json",
            },
        )
        response_json.extend(response.json())

    print("Found {} secret scanning alerts in {}".format(len(response_json), org_name))

    # Return secret scanning alerts
    return response_json


def write_org_secrets_list(secrets_list):
    """
    Write the list of organization secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """

    if secrets_list == ["not found"]:
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
            if alert["state"] == "open":
                alert["resolution"] = "none"
                alert["resolved_at"] = "none"
                alert["resolved_by"] = {
                    "login": "none",
                    "type": "none",
                    "site_admin": "none",
                }
            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    alert["resolved_by"]["login"],
                    alert["resolved_by"]["type"],
                    alert["resolved_by"]["site_admin"],
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


def get_enterprise_secret_scanning_alerts(api_endpoint, github_pat, enterprise_slug):
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

    # Get secret scanning alerts
    url = "{}/enterprises/{}/secret-scanning/alerts?per_page=100&page=1".format(
        api_endpoint, enterprise_slug
    )
    response = requests.get(
        url,
        headers={
            "Authorization": "token {}".format(github_pat),
            "Accept": "application/vnd.github.v3+json",
        },
    )
    response_json = response.json()
    # The secret scanning API returns a code of 404 if there are no alerts,
    # secret scanning is disabled, or the repository is public.
    if response.status_code == 404:
        return ["not found"]
    while "next" in response.links.keys():
        response = requests.get(
            response.links["next"]["url"],
            headers={
                "Authorization": "token {}".format(github_pat),
                "Accept": "application/vnd.github.v3+json",
            },
        )
        response_json.extend(response.json())

    print(
        "Found {} secret scanning alerts in {} enterprise".format(
            len(response_json), enterprise_slug
        )
    )

    # Return secret scanning alerts
    return response_json


def write_enterprise_secrets_list(secrets_list):
    """
    Write the list of enterprise secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """

    if secrets_list == ["not found"]:
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
            if alert["state"] == "open":
                alert["resolution"] = "none"
                alert["resolved_at"] = "none"
                alert["resolved_by"] = {
                    "login": "none",
                    "type": "none",
                    "site_admin": "none",
                }
                writer.writerow(
                    [
                        alert["number"],
                        alert["created_at"],
                        alert["html_url"],
                        alert["state"],
                        alert["resolution"],
                        alert["resolved_at"],
                        alert["resolved_by"]["login"],
                        alert["resolved_by"]["type"],
                        alert["resolved_by"]["site_admin"],
                        alert["secret_type"],
                        alert["secret_type_display_name"],
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
