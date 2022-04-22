# This holds all the logic for the various enterprise differences.

# Imports
import requests


def get_enterprise_version(api_endpoint):
    """
    Get the version of GitHub Enterprise.  It'll be used to account for
    differences between GHES and GHAE and GHEC, like the organization secret
    scanning API not existing outside GHEC.

    GitHub AE returns "GitHub AE" as of M2
    GHES returns the version of GHES that's installed (e.g. "3.4.0")
    """
    if api_endpoint != "https://api.github.com":
        url = "{}/meta".format(api_endpoint)
        response = requests.get(url)
        if "installed_version" in response.json():
            return response.json()["installed_version"]
        else:
            return "unknown version of GitHub"
    else:
        return "GHEC"
