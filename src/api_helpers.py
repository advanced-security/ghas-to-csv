import requests


def make_api_call(url, github_pat):
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(response.status_code, response.text)
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(response.links["next"]["url"], headers=headers)
        response_json.extend(response.json())
    return response_json


def get_repo_metadata(api_endpoint, github_pat, repo_name):
    """
    Get extended repository metadata including teams, topics, and custom properties.
    
    Inputs:
    - API endpoint (for GHES/GHAE compatibility)
    - PAT of appropriate scope
    - Repository name (owner/repo format)
    
    Outputs:
    - Dictionary with teams, topics, and custom_properties
    """
    metadata = {
        "teams": [],
        "topics": [],
        "custom_properties": {}
    }
    
    try:
        # Get repository teams
        teams_url = f"{api_endpoint}/repos/{repo_name}/teams?per_page=100&page=1"
        teams = make_api_call(teams_url, github_pat)
        metadata["teams"] = [team["name"] for team in teams]
    except Exception as e:
        print(f"Warning: Could not fetch teams for {repo_name}: {e}")
        metadata["teams"] = []
    
    try:
        # Get repository details (includes topics)
        repo_url = f"{api_endpoint}/repos/{repo_name}"
        repo_data = make_single_api_call(repo_url, github_pat)
        metadata["topics"] = repo_data.get("topics", [])
    except Exception as e:
        print(f"Warning: Could not fetch repository details for {repo_name}: {e}")
        metadata["topics"] = []
    
    try:
        # Get custom properties
        properties_url = f"{api_endpoint}/repos/{repo_name}/properties"
        properties = make_single_api_call(properties_url, github_pat)
        metadata["custom_properties"] = properties
    except Exception as e:
        print(f"Warning: Could not fetch custom properties for {repo_name}: {e}")
        metadata["custom_properties"] = {}
    
    return metadata


def make_single_api_call(url, github_pat):
    """
    Make a single API call without pagination.
    """
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(response.status_code, response.text)
    return response.json()