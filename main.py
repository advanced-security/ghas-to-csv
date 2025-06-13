#!/usr/bin/env python3

"""
This file holds the main function that does all the things.

Inputs:
- GitHub API endpoint (assumes github.com if not specified or run within GHES/GHAE)
- PAT of appropriate scope (assumes the workflow token if not specified)
- Report scope ("enterprise", "organization", "repository")
- Enterprise slug OR organization name OR repository name
- Features to run (comma separated list of "secretscanning", "codescanning", "dependabot")

Outputs:
- CSV file of secret scanning alerts
- CSV file of code scanning alerts
- CSV file of Dependabot alerts
"""

# Import modules
from src import code_scanning, dependabot, enterprise, secret_scanning
import os

# Possible strings indicating feature is not enabled
secret_scanning_disabled_strings = ["secret scanning is not enabled", "secret scanning is disabled"]
dependabot_disabled_strings = ["dependabot alerts are not enabled", "dependabot alerts are disabled"]

# Define the available features
FEATURES = ["secretscanning", "codescanning", "dependabot"]

# Read in config values
api_endpoint = os.getenv("GITHUB_API_URL", "https://api.github.com")
url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
github_pat = os.getenv("GITHUB_PAT", os.getenv("GITHUB_TOKEN"))
report_scope = os.getenv("GITHUB_REPORT_SCOPE", "repository")
scope_name = os.getenv("SCOPE_NAME", os.getenv("GITHUB_REPOSITORY"))
requested_features = os.getenv("FEATURES")
if (requested_features is None) or (requested_features == "all"):
    features = FEATURES
else:
    features = requested_features.split(",")
    for f in features:
        if f not in FEATURES:
            print(f"Invalid feature: {f}. Proceeding without. Valid features are: {FEATURES}")
            features.remove(f)


# Do the things!
if __name__ == "__main__":
    print("Starting GitHub security report...")
    # enterprise scope
    if report_scope == "enterprise":
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_enterprise_ss_alerts(api_endpoint, github_pat, scope_name)
                secret_scanning.write_enterprise_ss_list(secrets_list)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
        # code scanning
        if "codescanning" in features:
            version = enterprise.get_enterprise_version(api_endpoint)
            # For GHES version 3.5 and 3.6 we need to loop through each repo
            # and use the repo level api to get the code scanning alerts.
            # For 3.7 and above we use the enterprise level api to get the code scanning alerts
            if version.startswith("3.5") or version.startswith("3.6"):
                repo_list = enterprise.get_repo_report(url, github_pat)
                cs_list = code_scanning.list_enterprise_server_cs_alerts(api_endpoint, github_pat, repo_list)
                code_scanning.write_enterprise_server_cs_list(cs_list)
            else:
                cs_list = code_scanning.list_enterprise_cloud_cs_alerts(api_endpoint, github_pat, scope_name)
                code_scanning.write_enterprise_cloud_cs_list(cs_list)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_enterprise_dependabot_alerts(api_endpoint, github_pat, scope_name)
                dependabot.write_org_or_enterprise_dependabot_list(dependabot_list)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
    # organization scope
    elif report_scope == "organization":
        # code scanning
        if "codescanning" in features:
            cs_list = code_scanning.list_org_cs_alerts(api_endpoint, github_pat, scope_name)
            code_scanning.write_org_cs_list(cs_list)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_org_dependabot_alerts(api_endpoint, github_pat, scope_name)
                dependabot.write_org_or_enterprise_dependabot_list(dependabot_list)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_org_ss_alerts(api_endpoint, github_pat, scope_name)
                secret_scanning.write_org_ss_list(secrets_list)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
    # repository scope
    elif report_scope == "repository":
        # code scanning
        if "codescanning" in features:
            cs_list = code_scanning.list_repo_cs_alerts(api_endpoint, github_pat, scope_name)
            code_scanning.write_repo_cs_list(cs_list)
        # dependabot alerts
        if "dependabot" in features:
            try:
                dependabot_list = dependabot.list_repo_dependabot_alerts(api_endpoint, github_pat, scope_name)
                dependabot.write_repo_dependabot_list(dependabot_list)
            except Exception as e:
                if any(x in str(e).lower() for x in dependabot_disabled_strings):
                    print("Skipping Dependabot as it is not enabled.")
                    print(e)
                else:
                    raise
        # secret scanning
        if "secretscanning" in features:
            try:
                secrets_list = secret_scanning.get_repo_ss_alerts(api_endpoint, github_pat, scope_name)
                secret_scanning.write_repo_ss_list(secrets_list)
            except Exception as e:
                if any(x in str(e).lower() for x in secret_scanning_disabled_strings):
                    print("Skipping Secret Scanning as it is not enabled.")
                    print(e)
                else:
                    raise
    else:
        exit("Invalid report scope")
