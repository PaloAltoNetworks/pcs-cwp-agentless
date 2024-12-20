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


BULK_UPDATE_COUNT = int(os.getenv("BULK_UPDATE_COUNT", "20"))
SLEEP = int(os.getenv("SLEEP", "5"))
DEBUG = os.getenv("DEBUG", "false") in ("true", "True", "1", "y", "yes")
CONFIG_FILE = os.getenv("CONFIG_FILE_AG", "accountGroups.json")
COLUMN_SUBSCRIPTIONS = os.getenv("COLUMN_SUBSCRIPTIONS", "subscriptionId")
COLUMN_NAMES = os.getenv("COLUMN_NAMES", "name")
NON_ONBOARDED_FILE = os.getenv("NON_ONBOARDED_FILE", "nonOnboardedAccounts.json")
VALIDATION_ERRORS = os.getenv("VALIDATION_ERRORS", "validationErrors.json")

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


def createAccountGroup(
        name, 
        account_ids, 
        account_names, 
        hub_account_id = "", 
        description = "", 
        validate_accounts = False, 
        dry_run = False, 
        credentials_details = {}, 
        onboard_account = True, 
        additional_groups = ["Default Account Group"],
        excluded_groups = [],
        custom_tags = {},
        include_tags = {},
        scan_cap = "",
        fix_only = False,
        debug = DEBUG
    ):
    # Load global variables
    global prisma_api_endpoint
    global compute_api_endpoint
    global headers
    global username
    global password

    print(f"Generating Account Group: {name}")

    # Obtain Authentication token
    token_body = {
        "username": username,
        "password": password
    }
    prisma_token = json.loads(http_request(prisma_api_endpoint, "/login", token_body, debug=debug))["token"]
    headers["X-Redlock-Auth"] = prisma_token

    if not compute_api_endpoint: compute_api_endpoint = json.loads(http_request(prisma_api_endpoint, "/meta_info", method="GET", debug=debug))["twistlockUrl"]


    with open(NON_ONBOARDED_FILE) as non_onboarded_file:
        non_onboarded_accounts = json.loads(non_onboarded_file.read())

    with open(VALIDATION_ERRORS) as validation_file:
        validation_errors = json.loads(validation_file.read())

    non_onboarded_accounts[name] = []
    validation_errors[name] = {}
    account_ids_new = account_ids.copy()
    update_agentless_accounts = []
    onboard_account_counts = 0

    # Validate if Account Groups exists 
    account_group_ids = []
    excluded_groups_ids = []
    group_id = ""
    
    prisma_account_groups = json.loads(http_request(prisma_api_endpoint, "/cloud/group/name", method="GET", debug=debug))
    

    for prisma_account_group in prisma_account_groups:
        if prisma_account_group["name"] in additional_groups:
            account_group_ids.append(prisma_account_group["id"])

        if prisma_account_group["name"] == name:
            account_group_ids.append(prisma_account_group["id"])
            group_id = prisma_account_group["id"]
    
        if prisma_account_group["name"] in excluded_groups:
            excluded_groups_ids.append(prisma_account_group["id"])

    # Validate if Cloud Accounts exists
    if validate_accounts:
        for account_idx in range(len(account_ids)):
            account_id = account_ids[account_idx]
            account_details = json.loads(http_request(prisma_api_endpoint, f"/v1/cloudAccounts/azureAccounts/{account_id}", method="GET", skip_error=True))
                
            if not account_details:
                print(f"Account {account_id} is not onboarded on Prisma Cloud tenant")
                if not onboard_account:
                    non_onboarded_accounts[name].append(account_id)
                    account_ids_new.remove(account_id)
                else:
                    if credentials_details:
                        
                        new_account_details = {
                            "cloudAccount": {
                                "accountId": account_id,
                                "accountType": "account",
                                "enabled": True,
                                "name": account_names[account_idx],
                                "groupIds": account_group_ids
                            },
                            "clientId": credentials_details["clientId"],
                            "environmentType": "azure",
                            "key": credentials_details["key"],
                            "monitorFlowLogs": True,
                            "servicePrincipalId": credentials_details["servicePrincipalId"],
                            "tenantId": credentials_details["tenantId"],
                            "features": [
                                {
                                    "name": "Agentless Scanning",
                                    "state": "enabled"
                                },
                                {
                                    "name": "Serverless Function Scanning",
                                    "state": "enabled"
                                }
                            ]
                        }
                        if not dry_run:  
                            response = http_request(prisma_api_endpoint, f"/cas/v1/azure_account?skipStatusChecks=true", method="POST", body=new_account_details, debug=debug, skip_error=True)
                            if response == "{}":
                                non_onboarded_accounts[name].append(account_id)
                                account_ids_new.remove(account_id)
                                print(f"Cannot onboard {account_names[account_idx]} due to the name is duplicated. Subscription Id: {account_id}. Account Group: {name}\n")
                            else:
                                print(f"Onboarded account: {account_names[account_idx]}. Subscription Id: {account_id}. Account Group: {name}\n")
                                update_agentless_accounts.append(account_id)
                                onboard_account_counts += 1
                        else:
                            print(f"Onboarded account: {account_names[account_idx]}. Subscription Id: {account_id} Account Group: {name}\n")
                            update_agentless_accounts.append(account_id)        

            else:
                errors = {}
                agentless_enabled = True
                serverless_enabled = True

                for feature in account_details["cloudAccount"]["features"]:
                    if feature["featureName"] == "compute-agentless":
                        agentless_enabled = feature["featureState"] == "enabled"
                    if feature["featureName"] == "compute-serverless-scan":
                        serverless_enabled = feature["featureState"] == "enabled"

                prisma_clientId = account_details["clientId"]

                if not agentless_enabled: 
                    errors["agentless_enabled"] = False
                    if not dry_run: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{account_id}/feature/compute-agentless", body={"state": "enabled"}, method="PATCH", debug=debug)

                if not serverless_enabled: 
                    errors["serverless_enabled"] = False
                    if not dry_run: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{account_id}/feature/compute-serverless-scan", body={"state": "enabled"}, method="PATCH", debug=debug)

                if credentials_details:
                    update_account = False

                    if credentials_details["clientId"] != prisma_clientId:
                        errors["credentials_error"] = True
                        account_details.update(credentials_details)
                        update_agentless_accounts.append(account_id)
                        if debug: print(f"Credentials mistmatch in account {account_id}. Account Group: {name}\n") 
                        update_account = True                      

                for excluded_group_id in excluded_groups_ids:
                    if excluded_group_id in account_details["groupIds"]:
                        update_account = True
                        if debug: print(f"Required to exclude group from Account {account_id}. Account Group: {name}\n") 

                if update_account:
                    group_ids = list((set(account_details["groupIds"]) | set(account_group_ids)) - set(excluded_groups_ids))
                    new_account_details = {
                        "cloudAccount": {
                            "accountId": account_details["cloudAccount"]["accountId"],
                            "accountType": account_details["cloudAccount"]["accountType"],
                            "name": account_details["cloudAccount"]["name"],
                            "groupIds": group_ids
                        },
                        "monitorFlowLogs": account_details["monitorFlowLogs"],
                        "environmentType": account_details["environmentType"],
                        "authMode": account_details["authMode"],
                        "tenantId": account_details["tenantId"],
                        "clientId": account_details["clientId"],
                        "servicePrincipalId": account_details["servicePrincipalId"],
                        "key": account_details["key"]
                    }
                    # Update credentials
                    if not dry_run: http_request(prisma_api_endpoint, f"/cas/v1/azure_account/{account_id}?skipStatusChecks=true", method="PUT", body=new_account_details, debug=debug)
                    if debug: print(f"Updated account {account_id}. Account Group: {account_group['name']} \n")

                if errors:
                    validation_errors[name][account_id] = errors
    
    # Write report of accounts that are not validated
    with open(NON_ONBOARDED_FILE, "w") as non_onboarded_file:
        non_onboarded_file.write(json.dumps(non_onboarded_accounts))
    
    with open(VALIDATION_ERRORS, "w") as validation_file:
        validation_file.write(json.dumps(validation_errors))
    

    # Update existing Account Group, else create it
    body = {
        "name": name,
        "accountIds": account_ids_new,
        "childGroupIds": [],
        "description": description,
        "nonOnboardedCloudAccountIds": []
    }

    if not dry_run:
        if group_id:
            if not fix_only: http_request(prisma_api_endpoint, f"/cloud/group/{group_id}", method="PUT", body=body, debug=debug)
        else:
            if not fix_only: http_request(prisma_api_endpoint, f"/cloud/group", method="POST", body=body, debug=debug)


    accounts_len = len(update_agentless_accounts)
    sleep(SLEEP)

    if accounts_len > 0:
        idx = 0
        while idx < accounts_len:
            if idx + BULK_UPDATE_COUNT < accounts_len:
                accounts_filter = ",".join(update_agentless_accounts[idx:idx+BULK_UPDATE_COUNT])
            else:
                accounts_filter = ",".join(update_agentless_accounts[idx:])

            data = json.loads(http_request(compute_api_endpoint, f"/api/v1/cloud-scan-rules?cloudProviderAccountIDs={accounts_filter}", method="GET", debug=debug))
            if data:
                for account in data:
                    if hub_account_id: 
                        account["agentlessScanSpec"]["hubAccount"] = False
                        account["agentlessScanSpec"]["hubCredentialID"] = hub_account_id
                        account["agentlessScanSpec"]["scanners"] = 0
                        account["agentlessScanSpec"]["autoScale"] = False
                        account["agentlessScanSpec"]["skipPermissionsCheck"] = True

                    if include_tags: 
                        if include_tags == ["none"]:
                            account["agentlessScanSpec"]["includedTags"] = []
                        else:
                            account["agentlessScanSpec"]["includedTags"] = include_tags
                            
                        if "excludedTags" in account["agentlessScanSpec"]:
                            del account["agentlessScanSpec"]["excludedTags"]


                    if custom_tags: 
                        if custom_tags == ["none"]:
                            account["agentlessScanSpec"]["customTags"] = []
                        else:
                            account["agentlessScanSpec"]["customTags"] = custom_tags
                    
                    
                    if scan_cap: account["serverlessScanSpec"]["cap"] = int(scan_cap)

                # Update agentless scanning
                if not dry_run: http_request(compute_api_endpoint,"/api/v1/cloud-scan-rules", data, method="PUT", debug=debug)

            idx += BULK_UPDATE_COUNT
    
    print(f"Total Onboarded Accounts: {onboard_account_counts}")
    print(f"Total modified accounts in agentless: {accounts_len}")




if __name__ == "__main__":
    with open(CONFIG_FILE) as config_file:
        config = json.loads(config_file.read())

    for prisma_config in config:
        dry_run = False

        if "prisma_api_endpoint" in prisma_config: prisma_api_endpoint = os.getenv(prisma_config["prisma_api_endpoint"], "https://api.prismacloud.io")
        if "compute_api_endpoint" in prisma_config: compute_api_endpoint = os.getenv(prisma_config["compute_api_endpoint"], "")
        if "username" in prisma_config: username = os.getenv(prisma_config["username"], "")
        if "password" in prisma_config: password = os.getenv(prisma_config["password"], "")
        if "dry_run" in prisma_config: dry_run = prisma_config["dry_run"]

        for account_group in prisma_config["account_groups"]:
            name = account_group["name"]
            description = ""
            hub_account_id = ""
            validate = False
            credentials_details = {}
            custom_tags = {}
            include_tags = {}
            scan_cap = ""
            fix_only = False
            additional_groups = []
            excluded_groups = []

            if "description" in account_group: description = account_group["description"]
            if "validate" in account_group: validate = account_group["validate"]
            if "credentials" in account_group: credentials_details = json.loads(os.getenv(account_group["credentials"], ""))
            if "hubAccountId" in account_group: hub_account_id = account_group["hubAccountId"]
            if "customTags" in account_group: custom_tags = account_group["customTags"]
            if "includeTags" in account_group: include_tags = account_group["includeTags"]
            if "scanCap" in account_group: scan_cap = account_group["scanCap"]
            if "fixOnly" in account_group: fix_only = account_group["fixOnly"]
            if "additionalGroups" in account_group: additional_groups = account_group["additionalGroups"]
            if "excludedGroups" in account_group: excluded_groups = account_group["excludedGroups"]

            account_ids_data = read_csv(account_group["file"])
            account_ids = account_ids_data[COLUMN_SUBSCRIPTIONS].to_list()
            account_names = account_ids_data[COLUMN_NAMES].to_list()

            createAccountGroup(
                name=name, 
                account_ids=account_ids, 
                account_names=account_names,
                hub_account_id=hub_account_id, 
                description=description, 
                validate_accounts=validate, 
                dry_run=dry_run, 
                credentials_details=credentials_details,
                custom_tags=custom_tags,
                include_tags=include_tags,
                scan_cap=scan_cap,
                fix_only=fix_only,
                additional_groups=additional_groups,
                excluded_groups=excluded_groups
            )