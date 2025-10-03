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
    # First call: get default secret types (without any filters)
    url_default = f"{api_endpoint}/repos/{repo_name}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = f"{api_endpoint}/repos/{repo_name}/secret-scanning/alerts?per_page=100&page=1&secret_type={generic_secret_types}"
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


def write_repo_ss_list(secrets_list, include_repo_metadata=False, api_endpoint=None, github_pat=None, repo_name=None):
    """
    Write the list of repository secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls
    - repo_name: Repository name for metadata calls

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        
        # Base headers
        headers = [
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
        
        # Add extended metadata headers if enabled
        if include_repo_metadata:
            headers.extend([
                "repo_teams",
                "repo_topics",
                "repo_custom_properties"
            ])
        
        writer.writerow(headers)
        for alert in secrets_list:
            # Base row data
            row_data = [
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
            
            # Add extended metadata if enabled
            if include_repo_metadata and api_endpoint and github_pat and repo_name:
                try:
                    metadata = api_helpers.get_repo_metadata(api_endpoint, github_pat, repo_name)
                    row_data.extend([
                        ",".join(metadata["teams"]),
                        ",".join(metadata["topics"]),
                        str(metadata["custom_properties"])
                    ])
                except Exception as e:
                    print(f"Warning: Failed to get metadata for {repo_name}: {e}")
                    row_data.extend(["", "", ""])
            elif include_repo_metadata:
                # If metadata is requested but details not provided
                row_data.extend(["", "", ""])
            
            writer.writerow(row_data)


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
    # First call: get default secret types (without any filters)
    url_default = f"{api_endpoint}/orgs/{org_name}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = (
        f"{api_endpoint}/orgs/{org_name}/secret-scanning/alerts?per_page=100&page=1&secret_type={generic_secret_types}"
    )
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
            f"::warning::Duplicate secret scanning alerts detected in {org_name}. Please report this behavior via an issue to the repository owners as the API behavior may have changed."
        )

    print(
        f"Found {len(combined_alerts)} secret scanning alerts in {org_name} ({len(ss_alerts_default)} default, {len(ss_alerts_generic)} generic)"
    )
    return combined_alerts


def write_org_ss_list(secrets_list, include_repo_metadata=False, api_endpoint=None, github_pat=None):
    """
    Write the list of organization secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        
        # Base headers
        headers = [
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
        
        # Add extended metadata headers if enabled
        if include_repo_metadata:
            headers.extend([
                "repo_teams",
                "repo_topics",
                "repo_custom_properties"
            ])
        
        writer.writerow(headers)
        for alert in secrets_list:
            # Base row data
            row_data = [
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
            
            # Add extended metadata if enabled
            if include_repo_metadata and api_endpoint and github_pat:
                try:
                    metadata = api_helpers.get_repo_metadata(api_endpoint, github_pat, alert["repository"]["full_name"])
                    row_data.extend([
                        ",".join(metadata["teams"]),
                        ",".join(metadata["topics"]),
                        str(metadata["custom_properties"])
                    ])
                except Exception as e:
                    print(f"Warning: Failed to get metadata for {alert['repository']['full_name']}: {e}")
                    row_data.extend(["", "", ""])
            elif include_repo_metadata:
                # If metadata is requested but API details not provided
                row_data.extend(["", "", ""])
            
            writer.writerow(row_data)


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
    # First call: get default secret types (without any filters)
    url_default = f"{api_endpoint}/enterprises/{enterprise_slug}/secret-scanning/alerts?per_page=100&page=1"
    ss_alerts_default = api_helpers.make_api_call(url_default, github_pat)

    # Second call: get generic secret types with hardcoded list
    generic_secret_types = "password,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"
    url_generic = f"{api_endpoint}/enterprises/{enterprise_slug}/secret-scanning/alerts?per_page=100&page=1&secret_type={generic_secret_types}"
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
            f"::warning::Duplicate secret scanning alerts detected in {enterprise_slug}. Please report this behavior via an issue to the repository owners as the API behavior may have changed."
        )

    print(
        f"Found {len(combined_alerts)} secret scanning alerts in {enterprise_slug} ({len(ss_alerts_default)} default, {len(ss_alerts_generic)} generic)"
    )
    return combined_alerts


def write_enterprise_ss_list(secrets_list, include_repo_metadata=False, api_endpoint=None, github_pat=None):
    """
    Write the list of enterprise secret scanning alerts to a csv file.

    Inputs:
    - List of secret scanning alerts
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls

    Outputs:
    - CSV file of secret scanning alerts
    """
    # Write secret scanning alerts to csv file
    with open("secrets_list.csv", "w") as f:
        writer = csv.writer(f)
        
        # Base headers
        headers = [
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
        
        # Add extended metadata headers if enabled
        if include_repo_metadata:
            headers.extend([
                "repo_teams",
                "repo_topics",
                "repo_custom_properties"
            ])
        
        writer.writerow(headers)
        for alert in secrets_list:
            # Base row data
            row_data = [
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
            
            # Add extended metadata if enabled
            if include_repo_metadata and api_endpoint and github_pat:
                try:
                    metadata = api_helpers.get_repo_metadata(api_endpoint, github_pat, alert["repository"]["full_name"])
                    row_data.extend([
                        ",".join(metadata["teams"]),
                        ",".join(metadata["topics"]),
                        str(metadata["custom_properties"])
                    ])
                except Exception as e:
                    print(f"Warning: Failed to get metadata for {alert['repository']['full_name']}: {e}")
                    row_data.extend(["", "", ""])
            elif include_repo_metadata:
                # If metadata is requested but API details not provided
                row_data.extend(["", "", ""])
            
            writer.writerow(row_data)
