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
NON_ONBOARDED_FILE = os.getenv("NON_ONBOARDED_FILE", "nonOnboardedAccounts.json")
VALIDATION_ERRORS = os.getenv("VALIDATION_ERRORS", "validationErrors.json")

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

def createAccountGroup(name, account_ids, description = "", validate_accounts = False, create_account_group = True, debug = DEBUG):
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

    with open(NON_ONBOARDED_FILE) as non_onboarded_file:
        non_onboarded_accounts = json.loads(non_onboarded_file.read())

    with open(VALIDATION_ERRORS) as validation_file:
        validation_errors = json.loads(validation_file.read())

    non_onboarded_accounts[name] = []
    validation_errors[name] = {}
    print(validation_errors)
    account_ids_new = account_ids.copy() 

    # Validate if Cloud Accounts exists
    if validate_accounts:
        for account_id in account_ids:
            response = json.loads(http_request(prisma_api_endpoint, f"/account/{account_id}/config/status", method="GET", skip_error=True))
            if not response:
                print(f"Account {account_id} is not onboarded on Prisma Cloud tenant")
                non_onboarded_accounts[name].append(account_id)
                account_ids_new.remove(account_id)
            else:
                errors = {}
                agentless_enabled = False
                serverless_enabled = False
                for feature in response:
                    if feature["name"] == "Authentication":
                        if feature["status"] == "error":
                            errors["Authentication"] = "error"
                    elif feature["name"] == "Agentless Scanning":
                        agentless_enabled = True
                    elif feature["name"] == "Serverless Function Scanning":
                        serverless_enabled = True
                
                if not agentless_enabled: errors["agentless_enabled"] = False
                if not serverless_enabled: errors["serverless_enabled"] = False
            
                if errors:
                    validation_errors[name][account_id] = errors
    
    # Write report of accounts that are not validated
    with open(NON_ONBOARDED_FILE, "w") as non_onboarded_file:
        non_onboarded_file.write(json.dumps(non_onboarded_accounts))
    
    with open(VALIDATION_ERRORS, "w") as validation_file:
        validation_file.write(json.dumps(validation_errors))
    
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
        "accountIds": account_ids_new,
        "childGroupIds": [],
        "description": description,
        "nonOnboardedCloudAccountIds": []
    }

    if create_account_group:
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
        create_account_group = True
        name = account_group["name"]
        
        if "description" in account_group: description = account_group["description"]
        if "validate" in account_group: validate = account_group["validate"]
        if "create_account_group" in account_group: create_account_group = account_group["create_account_group"] 

        account_ids_data = read_csv(account_group["file"])
        account_ids = account_ids_data[COLUMN_NAME].to_list()

        createAccountGroup(name, account_ids, description, validate, create_account_group)