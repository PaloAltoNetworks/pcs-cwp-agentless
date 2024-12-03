#!/usr/bin/python3
import urllib3
import json
import os

from time import sleep
from pandas import read_csv

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
CONFIG_FILE = os.getenv("CONFIG_FILE_AG", "accountGroups.json")
COLUMN_NAME = os.getenv("COLUMN_NAME", "subscriptionId")

http = urllib3.PoolManager()

class RequestError(Exception):
    pass

def http_request(api_endpoint, path, body={}, method="POST", skip_error=False, debug=DEBUG):
    global prisma_api_endpoint
    global headers
    global username
    global password
    if debug: print(f"Making the following request:\n    URL: {api_endpoint}\n    Path: {path}\n    Method: {method}\n")

    response = http.request(method, f"{api_endpoint}{path}", headers=headers, body=json.dumps(body))

    if response.status == 200:
        return response.data
    
    if response.status == 401 and path != "/login":
        token_body = {
            "username": username,
            "password": password
        }

        token = json.loads(http_request(prisma_api_endpoint, "/login", token_body, debug=debug))["token"]
        headers["X-Redlock-Auth"] = token

        return http_request(api_endpoint, path, body, method, debug)
    
    if response.status == 429:
        sleep(SLEEP)
        return http_request(api_endpoint, path, body, method, debug)

    if not skip_error:
        raise RequestError(f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}")
    
    if debug: print(f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}")
    return "{}"

def createAccountGroup(name, account_ids, description = "", validate_accounts = False, debug = DEBUG):
    # Load global variables
    global prisma_api_endpoint
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

    # Validate if Cloud Accounts exists
    if validate_accounts:
        for account_id in account_ids:
            response = json.loads(http_request(prisma_api_endpoint, f"/account/{account_id}/config/status", method="GET", skip_error=True))
            if not response:
                print(f"Account {account_id} is not onboarded on Prisma Cloud tenant")
                account_ids.remove(account_id)
    
    # Validate if Account Group exists 
    group_id = ""
    prisma_account_groups = json.loads(http_request(prisma_api_endpoint, "/cloud/group/name", method="GET", debug=debug))
    
    for prisma_account_group in prisma_account_groups:
        if prisma_account_group["name"] == name:
            group_id = prisma_account_group["id"]
            break

    # Update existing Account Group, else create it
    body = {
        "name": name,
        "accountIds": account_ids,
        "childGroupIds": [],
        "description": description,
        "nonOnboardedCloudAccountIds": []
    }

    if group_id:
        http_request(prisma_api_endpoint, f"/cloud/group/{group_id}", method="PUT", body=body, debug=debug)
    else:
        http_request(prisma_api_endpoint, f"/cloud/group", method="POST", body=body, debug=debug)


if __name__ == "__main__":
    with open(CONFIG_FILE) as config_file:
        config = json.loads(config_file.read())

    for account_group in config:
        description = ""
        validate = False
        name = account_group["name"]
        
        if "description" in account_group: description = account_group["description"]
        if "validate" in account_group: validate = account_group["validate"]

        account_ids_data = read_csv(account_group["file"])
        account_ids = account_ids_data[COLUMN_NAME].to_list()

        createAccountGroup(name, account_ids, description, validate)