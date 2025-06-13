# This holds all the things that do stuff for code scanning API

# Imports
from defusedcsv import csv
from . import api_helpers


def list_repo_cs_alerts(api_endpoint, github_pat, repo_name):
    """
    Get a list of all code scanning alerts on a given repository.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name

    Outputs:
    - List of _all_ code scanning alerts on the repository
    """
    url = f"{api_endpoint}/repos/{repo_name}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(code_scanning_alerts)} code scanning alerts in {repo_name}")
    return code_scanning_alerts


def write_repo_cs_list(cs_list, include_repo_metadata=False, api_endpoint=None, github_pat=None, repo_name=None):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List of code scanning alerts
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls
    - repo_name: Repository name for metadata calls

    Outputs:
    - CSV file of code scanning alerts
    """

    with open("cs_list.csv", "w") as f:
        writer = csv.writer(f)
        
        # Base headers
        headers = [
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
            "most_recent_instance_category",
            "most_recent_instance_location_path",
        ]
        
        # Add extended metadata headers if enabled
        if include_repo_metadata:
            headers.extend([
                "repo_teams",
                "repo_topics",
                "repo_custom_properties"
            ])
        
        writer.writerow(headers)
        for cs in cs_list:
            # Base row data
            row_data = [
                cs["number"],
                cs["created_at"],
                cs["html_url"],
                cs["state"],
                cs["fixed_at"],
                cs["dismissed_at"],
                cs["dismissed_by"],
                cs["dismissed_reason"],
                cs["rule"]["id"],
                cs["rule"]["severity"],
                cs["rule"].get("security_severity_level", ""),
                cs["rule"]["tags"],
                cs["rule"]["description"],
                cs["rule"]["name"],
                cs["tool"]["name"],
                cs["tool"]["version"],
                cs["most_recent_instance"]["ref"],
                cs["most_recent_instance"]["state"],
                cs["most_recent_instance"]["commit_sha"],
                cs["instances_url"],
                cs["most_recent_instance"]["category"],
                cs["most_recent_instance"]["location"]["path"],
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


def list_org_cs_alerts(api_endpoint, github_pat, org_name):
    """
    Get a list of all code scanning alerts on a given organization.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Organization name

    Outputs:
    - List of _all_ code scanning alerts on the organization
    """

    url = f"{api_endpoint}/orgs/{org_name}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(code_scanning_alerts)} code scanning alerts in {org_name}")
    return code_scanning_alerts


def write_org_cs_list(cs_list, include_repo_metadata=False, api_endpoint=None, github_pat=None):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List of code scanning alerts
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls

    Outputs:
    - CSV file of code scanning alerts
    """

    # Write code scanning alerts to csv file
    with open("cs_list.csv", "w") as f:
        writer = csv.writer(f)
        
        # Base headers
        headers = [
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
        
        # Add extended metadata headers if enabled
        if include_repo_metadata:
            headers.extend([
                "repo_teams",
                "repo_topics",
                "repo_custom_properties"
            ])
        
        writer.writerow(headers)
        for cs in cs_list:
            # Base row data
            row_data = [
                cs["number"],
                cs["created_at"],
                cs["html_url"],
                cs["state"],
                cs.get("fixed_at", ""),
                cs.get("dismissed_by", ""),
                cs.get("dismissed_at", ""),
                cs.get("dismissed_reason", ""),
                cs["rule"]["id"],
                cs["rule"]["severity"],
                cs["rule"].get("security_severity_level", ""),
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
            
            # Add extended metadata if enabled
            if include_repo_metadata and api_endpoint and github_pat:
                try:
                    metadata = api_helpers.get_repo_metadata(api_endpoint, github_pat, cs["repository"]["full_name"])
                    row_data.extend([
                        ",".join(metadata["teams"]),
                        ",".join(metadata["topics"]),
                        str(metadata["custom_properties"])
                    ])
                except Exception as e:
                    print(f"Warning: Failed to get metadata for {cs['repository']['full_name']}: {e}")
                    row_data.extend(["", "", ""])
            elif include_repo_metadata:
                # If metadata is requested but API details not provided
                row_data.extend(["", "", ""])
            
            writer.writerow(row_data)


def list_enterprise_server_cs_alerts(api_endpoint, github_pat, repo_list):
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
            alerts.append(list_repo_cs_alerts(api_endpoint, github_pat, repo_name))
        except StopIteration:
            break
        except Exception as e:
            print(e)
    return alerts


def write_enterprise_server_cs_list(cs_list, include_repo_metadata=False, api_endpoint=None, github_pat=None):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls

    Outputs:
    - CSV file of code scanning alerts
    - CSV file of repositories not accessible or without code scanning enabled
    """

    for alert_list in cs_list:
        if type(alert_list) == list:
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
                    writer.writerow(
                        [
                            cs["repository"]["full_name"],
                            cs["repository"]["id"],
                            cs["number"],
                            cs["created_at"],
                            cs["html_url"],
                            cs["state"],
                            cs.get("fixed_at", ""),
                            cs.get("dismissed_by", ""),
                            cs.get("dismissed_at", ""),
                            cs.get("dismissed_reason", ""),
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


def list_enterprise_cloud_cs_alerts(api_endpoint, github_pat, enterprise_slug):
    """
    Get a list of all code scanning alerts on a given enterprise.

    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope

    Outputs:
    - List of _all_ code scanning alerts in enterprise that PAT user can access
    """

    url = f"{api_endpoint}/enterprises/{enterprise_slug}/code-scanning/alerts?per_page=100&page=1"
    code_scanning_alerts = api_helpers.make_api_call(url, github_pat)
    print(f"Found {len(code_scanning_alerts)} code scanning alerts in {enterprise_slug}")
    return code_scanning_alerts


def write_enterprise_cloud_cs_list(cs_list, include_repo_metadata=False, api_endpoint=None, github_pat=None):
    """
    Write a list of code scanning alerts to a csv file.

    Inputs:
    - List from list_enterprise_code_scanning_alerts function, which contains
        strings and lists of dictionaries for the alerts.
    - include_repo_metadata: Whether to include extended repo metadata
    - api_endpoint: API endpoint for metadata calls
    - github_pat: GitHub PAT for metadata calls

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
            writer.writerow(
                [
                    cs["repository"]["full_name"],
                    cs["repository"]["id"],
                    cs["number"],
                    cs["created_at"],
                    cs["html_url"],
                    cs["state"],
                    cs.get("fixed_at", ""),
                    cs.get("dismissed_by", ""),
                    cs.get("dismissed_at", ""),
                    cs.get("dismissed_reason", ""),
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
