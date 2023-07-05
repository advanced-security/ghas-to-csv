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