#!/usr/bin/python3
import urllib3
import json
import os

from time import sleep
from pandas import DataFrame

if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()


prisma_api_endpoint = os.getenv("PRISMA_API_ENDPOINT", "https://api.prismacloud.io")
compute_api_endpoint = os.getenv("COMPUTE_API_ENDPOINT", "")
username = os.getenv("PRISMA_USERNAME", "")
password = os.getenv("PRISMA_PASSWORD", "")

headers = {
    "Content-Type": "application/json"
}

SUBNET_NAME = os.getenv("SUBNET_NAME", "")
SECURITY_GROUP_NAME = os.getenv("SECURITY_GROUP_NAME", "")
ORGANIZATION_ID = os.getenv("ORGANIZATION_ID", "")
ORGANIZATION_TYPE = os.getenv("ORGANIZATION_TYPE", "")
SLEEP = int(os.getenv("SLEEP", "5"))
DEBUG = os.getenv("DEBUG", "false") in ("true", "True", "1", "y", "yes")
ISSUES = os.getenv("ISSUES", "Permissions")
SCAN_MODE = os.getenv("SCAN_MODE", "scannedByHub")
PROVIDER = os.getenv("PROVIDER", "azure")
REPORT = os.getenv("REPORT", "Agentless-Issues.csv")

http = urllib3.PoolManager()

class RequestError(Exception):
    pass

def http_request(api_endpoint, path, body={}, method="POST", skip_error=False, debug=DEBUG):
    global prisma_api_endpoint
    global compute_api_endpoint
    global headers
    global username
    global password
    if debug: print(f"Making the following request:\n    URL: {api_endpoint}\n    Path: {path}\n    Method: {method}\n")

    response = http.request(method, f"{api_endpoint}{path}", headers=headers, body=json.dumps(body))

    if response.status == 200:
        return response.data
    
    if response.status == 401 and path not in ("/login", "/api/v1/authenticate"):
        token_body = {
            "username": username,
            "password": password
        }

        if api_endpoint == prisma_api_endpoint:
            token = json.loads(http_request(prisma_api_endpoint, "/login", token_body, debug=debug))["token"]
            headers["X-Redlock-Auth"] = token

        if api_endpoint == compute_api_endpoint:
            token = json.loads(http_request(compute_api_endpoint, "/api/v1/authenticate", token_body, debug=debug))["token"]
            headers["Authorization"] = f"Bearer {token}"
            
        return http_request(api_endpoint, path, body, method, debug)
    
    if response.status == 429:
        sleep(SLEEP)
        return http_request(api_endpoint, path, body, method, debug)

    if not skip_error:
        raise RequestError(f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}")
    
    if debug: print(f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}")
    return "{}"


def getCloudAccountsList(api_endpoint, limit=50, provider="", scan_mode="", debug=DEBUG, errors=""):
    offset = 0
    accounts = []
    response = "first_response"
    base_path = f"/api/v1/cloud-scan-rules?agentlessScanEnabled=true&limit={limit}"
    if provider: base_path = f"{base_path}&cloudProviders={provider}"
    if scan_mode: base_path = f"{base_path}&agentlessScanMode={scan_mode}"
    if errors: base_path = f"{base_path}&agentlessErrCategories={errors}"

    while response:
        path = f"{base_path}&offset={offset}" 
        response = json.loads(http_request(api_endpoint, path, method="GET", debug=debug))
        if response:
            accounts += response
            offset += limit

    if debug: print(f"Total accounts retrieved from Compute Console: {len(accounts)}\n")

    return accounts



def getAgentlessIssues(debug = DEBUG):
    # Load global variables
    global prisma_api_endpoint
    global compute_api_endpoint
    global headers
    global username
    global password

    # Obtain Authentication token
    token_body = {
        "username": username,
        "password": password
    }
    prisma_token = json.loads(http_request(prisma_api_endpoint, "/login", token_body, debug=debug))["token"]
    headers["X-Redlock-Auth"] = prisma_token

    compute_api_endpoint = json.loads(http_request(prisma_api_endpoint, "/meta_info", method="GET", debug=debug))["twistlockUrl"]
    accounts = getCloudAccountsList(compute_api_endpoint, 50, PROVIDER, SCAN_MODE, DEBUG, ISSUES)

    accounts_summary = {
        "subcription_name": [],
        "subcription_id": [],
        "error": []
    }

    for account in accounts:
        accounts_summary["subcription_name"].append(account["credential"]["accountName"])
        accounts_summary["subcription_id"].append(account["credential"]["accountID"])
        for error in account["agentlessAccountState"]["regions"][0]["errorsInfo"]:
            if error["category"] in ISSUES:
                accounts_summary["error"].append(error["error"])


    df = DataFrame.from_dict(accounts_summary)
    df.to_csv(REPORT)

if __name__ == "__main__":
    getAgentlessIssues()