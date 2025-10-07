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
    - List of _all_ secret scanning alerts on the repository (both default and generic secret types)
    """
    # First call: get default secret types (without any filters), use after= to force object based cursor instead of page based
    url_default = f"{api_endpoint}/repos/{repo_name}/secret-scanning/alerts?per_page=100&after=&hide_secret=true"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list, use after= to force object based cursor instead of page based
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = f"{api_endpoint}/repos/{repo_name}/secret-scanning/alerts?per_page=100&after=&secret_type={generic_secret_types}&hide_secret=true"
    ss_alerts_generic = api_helpers.make_api_call(url_generic, github_pat)

    # Combine results and deduplicate
    combined_alerts = []
    alert_numbers_seen = set()
    duplicates_found = False

    # Add default alerts
    for alert in ss_alerts_default:
        alert_numbers_seen.add(alert["number"])
        combined_alerts.append(alert)

    # Add generic alerts, checking for duplicates
    for alert in ss_alerts_generic:
        if alert["number"] in alert_numbers_seen:
            duplicates_found = True
        else:
            alert_numbers_seen.add(alert["number"])
            combined_alerts.append(alert)

    # Warn if duplicates were found
    if duplicates_found:
        print(
            f"::warning::Duplicate secret scanning alerts detected in {repo_name}. Please report this behavior via an issue to the repository owners as the API behavior may have changed."
        )

    print(
        f"Found {len(combined_alerts)} secret scanning alerts in {repo_name} ({len(ss_alerts_default)} default, {len(ss_alerts_generic)} generic)"
    )
    return combined_alerts


def write_repo_ss_list(secrets_list):
    """
    Write the list of repository secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "updated_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "resolution_comment",
                "secret_type",
                "secret_type_display_name",
                "validity",
                "publicly_leaked",
                "multi_repo",
                "is_base64_encoded",
                "first_location_path",
                "first_location_start_line",
                "first_location_commit_sha",
                "push_protection_bypassed",
                "push_protection_bypassed_by",
                "push_protection_bypassed_at",
                "push_protection_bypass_request_reviewer",
                "push_protection_bypass_request_reviewer_comment",
                "push_protection_bypass_request_comment",
                "push_protection_bypass_request_html_url",
                "assigned_to",
            ]
        )
        for alert in secrets_list:
            first_location = alert.get("first_location_detected") or {}

            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["updated_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert.get("resolution_comment", ""),
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                    alert["validity"],
                    str(alert["publicly_leaked"]),
                    str(alert["multi_repo"]),
                    str(alert["is_base64_encoded"]),
                    first_location.get("path") or first_location.get("pull_request_body_url") or first_location.get("issue_body_url") or first_location.get("discussion_body_url") or "",
                    "" if first_location is None else first_location.get("start_line", ""),
                    "" if first_location is None else first_location.get("commit_sha", ""),
                    str(alert["push_protection_bypassed"]),
                    "" if alert.get("push_protection_bypassed_by") is None else alert["push_protection_bypassed_by"].get("login", ""),
                    alert.get("push_protection_bypassed_at", ""),
                    "" if alert.get("push_protection_bypass_request_reviewer") is None else alert["push_protection_bypass_request_reviewer"].get("login", ""),
                    alert.get("push_protection_bypass_request_reviewer_comment", ""),
                    alert.get("push_protection_bypass_request_comment", ""),
                    alert.get("push_protection_bypass_request_html_url", ""),
                    "" if alert.get("assigned_to") is None else alert["assigned_to"].get("login", ""),
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
    - List of _all_ secret scanning alerts on the organization (both default and generic secret types)
    """
    # First call: get default secret types (without any filters), use after= to force object based cursor instead of page based
    url_default = f"{api_endpoint}/orgs/{org_name}/secret-scanning/alerts?per_page=100&after=&hide_secret=true"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list, use after= to force object based cursor instead of page based
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = (
        f"{api_endpoint}/orgs/{org_name}/secret-scanning/alerts?per_page=100&after=&secret_type={generic_secret_types}&hide_secret=true"
    )
    ss_alerts_generic = api_helpers.make_api_call(url_generic, github_pat)

    # Combine results and deduplicate using composite key (repo + alert number)
    combined_alerts = []
    alert_keys_seen = set()  # Composite key: (repo, alert_number)
    duplicates_found = False

    # Add default alerts
    for alert in ss_alerts_default:
        alert_key = (alert["repository"]["full_name"], alert["number"])
        alert_keys_seen.add(alert_key)
        combined_alerts.append(alert)

    # Add generic alerts, checking for duplicates
    for alert in ss_alerts_generic:
        alert_key = (alert["repository"]["full_name"], alert["number"])
        if alert_key in alert_keys_seen:
            duplicates_found = True
        else:
            alert_keys_seen.add(alert_key)
            combined_alerts.append(alert)

    # Warn if duplicates were found
    if duplicates_found:
        print(
            f"::warning::Duplicate secret scanning alerts detected in {org_name}. Please report this behavior via an issue to the repository owners as the API behavior may have changed."
        )

    print(
        f"Found {len(combined_alerts)} secret scanning alerts in {org_name} ({len(ss_alerts_default)} default, {len(ss_alerts_generic)} generic)"
    )
    return combined_alerts


def write_org_ss_list(secrets_list):
    """
    Write the list of organization secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "updated_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "resolution_comment",
                "secret_type",
                "secret_type_display_name",
                "validity",
                "publicly_leaked",
                "multi_repo",
                "is_base64_encoded",
                "first_location_path",
                "first_location_start_line",
                "first_location_commit_sha",
                "push_protection_bypassed",
                "push_protection_bypassed_by",
                "push_protection_bypassed_at",
                "push_protection_bypass_request_reviewer",
                "push_protection_bypass_request_reviewer_comment",
                "push_protection_bypass_request_comment",
                "push_protection_bypass_request_html_url",
                "assigned_to",
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
            first_location = alert.get("first_location_detected") or {}

            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["updated_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert.get("resolution_comment", ""),
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                    alert["validity"],
                    str(alert["publicly_leaked"]),
                    str(alert["multi_repo"]),
                    str(alert["is_base64_encoded"]),
                    first_location.get("path") or first_location.get("pull_request_body_url") or first_location.get("issue_body_url") or first_location.get("discussion_body_url") or "",
                    "" if first_location is None else first_location.get("start_line", ""),
                    "" if first_location is None else first_location.get("commit_sha", ""),
                    str(alert["push_protection_bypassed"]),
                    "" if alert.get("push_protection_bypassed_by") is None else alert["push_protection_bypassed_by"].get("login", ""),
                    alert.get("push_protection_bypassed_at", ""),
                    "" if alert.get("push_protection_bypass_request_reviewer") is None else alert["push_protection_bypass_request_reviewer"].get("login", ""),
                    alert.get("push_protection_bypass_request_reviewer_comment", ""),
                    alert.get("push_protection_bypass_request_comment", ""),
                    alert.get("push_protection_bypass_request_html_url", ""),
                    "" if alert.get("assigned_to") is None else alert["assigned_to"].get("login", ""),
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
    - List of _all_ secret scanning alerts on the enterprise (both default and generic secret types)
    """
    # First call: get default secret types (without any filters), use after= to force object based cursor instead of page based
    url_default = f"{api_endpoint}/enterprises/{enterprise_slug}/secret-scanning/alerts?per_page=100&after=&hide_secret=true"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list, use after= to force object based cursor instead of page based
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = f"{api_endpoint}/enterprises/{enterprise_slug}/secret-scanning/alerts?per_page=100&after=&secret_type={generic_secret_types}&hide_secret=true"
    ss_alerts_generic = api_helpers.make_api_call(url_generic, github_pat)

    # Combine results and deduplicate using composite key (org + repo + alert number)
    combined_alerts = []
    alert_keys_seen = set()  # Composite key: (org, repo, alert_number)
    duplicates_found = False

    # Add default alerts
    for alert in ss_alerts_default:
        alert_key = (
            alert["repository"]["owner"]["login"],
            alert["repository"]["name"],
            alert["number"]
        )
        alert_keys_seen.add(alert_key)
        combined_alerts.append(alert)

    # Add generic alerts, checking for duplicates
    for alert in ss_alerts_generic:
        alert_key = (
            alert["repository"]["owner"]["login"],
            alert["repository"]["name"],
            alert["number"]
        )
        if alert_key in alert_keys_seen:
            duplicates_found = True
        else:
            alert_keys_seen.add(alert_key)
            combined_alerts.append(alert)

    # Warn if duplicates were found
    if duplicates_found:
        print(
            f"::warning::Duplicate secret scanning alerts detected in {enterprise_slug}. Please report this behavior via an issue to the repository owners as the API behavior may have changed."
        )

    print(
        f"Found {len(combined_alerts)} secret scanning alerts in {enterprise_slug} ({len(ss_alerts_default)} default, {len(ss_alerts_generic)} generic)"
    )
    return combined_alerts


def write_enterprise_ss_list(secrets_list):
    """
    Write the list of enterprise secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "number",
                "created_at",
                "updated_at",
                "html_url",
                "state",
                "resolution",
                "resolved_at",
                "resolved_by_username",
                "resolved_by_type",
                "resolved_by_isadmin",
                "resolution_comment",
                "secret_type",
                "secret_type_display_name",
                "validity",
                "publicly_leaked",
                "multi_repo",
                "is_base64_encoded",
                "first_location_path",
                "first_location_start_line",
                "first_location_commit_sha",
                "push_protection_bypassed",
                "push_protection_bypassed_by",
                "push_protection_bypassed_at",
                "push_protection_bypass_request_reviewer",
                "push_protection_bypass_request_reviewer_comment",
                "push_protection_bypass_request_comment",
                "push_protection_bypass_request_html_url",
                "assigned_to",
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
            first_location = alert.get("first_location_detected") or {}

            writer.writerow(
                [
                    alert["number"],
                    alert["created_at"],
                    alert["updated_at"],
                    alert["html_url"],
                    alert["state"],
                    alert["resolution"],
                    alert["resolved_at"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["login"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["type"],
                    "" if alert["resolved_by"] is None else alert["resolved_by"]["site_admin"],
                    alert.get("resolution_comment", ""),
                    alert["secret_type"],
                    alert["secret_type_display_name"],
                    alert["validity"],
                    str(alert["publicly_leaked"]),
                    str(alert["multi_repo"]),
                    str(alert["is_base64_encoded"]),
                    first_location.get("path") or first_location.get("pull_request_body_url") or first_location.get("issue_body_url") or first_location.get("discussion_body_url") or "",
                    "" if first_location is None else first_location.get("start_line", ""),
                    "" if first_location is None else first_location.get("commit_sha", ""),
                    str(alert["push_protection_bypassed"]),
                    "" if alert.get("push_protection_bypassed_by") is None else alert["push_protection_bypassed_by"].get("login", ""),
                    alert.get("push_protection_bypassed_at", ""),
                    "" if alert.get("push_protection_bypass_request_reviewer") is None else alert["push_protection_bypass_request_reviewer"].get("login", ""),
                    alert.get("push_protection_bypass_request_reviewer_comment", ""),
                    alert.get("push_protection_bypass_request_comment", ""),
                    alert.get("push_protection_bypass_request_html_url", ""),
                    "" if alert.get("assigned_to") is None else alert["assigned_to"].get("login", ""),
                    alert["repository"]["full_name"],
                    alert["repository"]["owner"]["login"],
                    alert["repository"]["owner"]["type"],
                    alert["repository"]["owner"]["site_admin"],
                    alert["repository"]["html_url"],
                    str(alert["repository"]["fork"]),
                    str(alert["repository"]["private"]),
                ]
            )
