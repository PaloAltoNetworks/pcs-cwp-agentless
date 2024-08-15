#!/usr/bin/python3
import urllib3
import json
import argparse
import os
import sys

from time import sleep

if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

parser = argparse.ArgumentParser(
    prog='python3 configAgentless.py',
    description='This sets up the subnet and security group in Prisma Cloud for Agentless scanning',
    epilog='For further documentation go to: https://github.com/PaloAltoNetworks/pcs-cwp-agentless'
)

PRISMA_API_ENDPOINT = os.getenv("PRISMA_API_ENDPOINT", "https://api.prismacloud.io")
COMPUTE_API_ENDPOINT = os.getenv("COMPUTE_API_ENDPOINT", "")
PRISMA_USERNAME = os.getenv("PRISMA_USERNAME", "")
PRISMA_PASSWORD = os.getenv("PRISMA_PASSWORD", "")
SUBNET_NAME = os.getenv("SUBNET_NAME", "")
SECURITY_GROUP_NAME = os.getenv("SECURITY_GROUP_NAME", "")
ORGANIZATION_ID = os.getenv("ORGANIZATION_ID", "")
ORGANIZATION_TYPE = os.getenv("ORGANIZATION_TYPE", "")
ACCOUNT_GROUPS = os.getenv("ACCOUNT_GROUPS", "").split(",")
ONBOARDING_MODE = os.getenv("ONBOARDING_MODE", "org")
HUB_ACCOUNT_ID = os.getenv("HUB_ACCOUNT_ID", "")
LIMIT = int(os.getenv("LIMIT", "50"))
SLEEP = int(os.getenv("SLEEP", "5"))
BULK_UPDATE_COUNT = int(os.getenv("BULK_UPDATE_COUNT", "20"))

if '' in ACCOUNT_GROUPS: ACCOUNT_GROUPS.remove('')

http = urllib3.PoolManager()

class RequestError(Exception):
    pass

def http_request(api_endpoint, path, body={}, method="POST"):
    global headers
    global prisma_api_endpoint
    global compute_api_endpoint

    response = http.request(method, f"{api_endpoint}{path}", headers=headers, body=json.dumps(body))

    if response.status == 200:
        return response.data
    
    if response.status == 401 and path not in ("/login", "/api/v1/authenticate"):
        token_body = {
            "username": PRISMA_USERNAME,
            "password": PRISMA_PASSWORD
        }
        if api_endpoint == prisma_api_endpoint:
            token = json.loads(http_request(prisma_api_endpoint, "/login", token_body))["token"]
            headers["X-Redlock-Auth"] = token

        if api_endpoint == compute_api_endpoint:
            token = json.loads(http_request(compute_api_endpoint, "/api/v1/authenticate", token_body))["token"]
            headers["Authorization"] = f"Bearer {token}"
            
        return http_request(api_endpoint, path, body, method)
    
    if response.status == 429:
        sleep(SLEEP)
        return http_request(api_endpoint, path, body, method)

    raise RequestError(f"Error making request to {api_endpoint}{path}. Method: {method}. Body: {body}. Error message: {response.data}. Status code: {response.status}")
    

def getCloudAccountsList(api_endpoint, limit=50, provider=""):
    offset = 0
    accounts = []
    response = "first_response"
    base_path = f"/api/v1/cloud-scan-rules?agentlessGeneralScanStatus=on,new,cleanup,scanning&limit={limit}"

    while response:
        path = f"{base_path}&offset={offset}"
        if provider:
            path += f"&cloudProviders={provider}"
     
        response = json.loads(http_request(api_endpoint, path, method="GET"))
        if response:
            accounts += response
            offset += limit

    return accounts


def updateAgentlessConfig(data, api_endpoint, bulk_update_count=20):
    accounts_count = len(data)

    for i in range(0, accounts_count, bulk_update_count):
        if i + bulk_update_count < accounts_count:
            http_request(api_endpoint,"/api/v1/cloud-scan-rules", data[i:i+bulk_update_count], method="PUT")
        else:
            http_request(api_endpoint,"/api/v1/cloud-scan-rules", data[i:], method="PUT")


def format_tags(tags_list, list_name=""):
    tags_formatted = []
    if tags_list == ["none"]:
        return tags_list

    for tag in tags_list:
        if "=" not in tag:
            print(f"Tag '{tag}' has invalid format in tag list '{list_name}'")
            continue

        key, value = tag.split("=")

        if not value:
            print(f"Tag '{key}' doesn't have any value in tag list '{list_name}'")
            continue

        tags_formatted.append({
            "key": key,
            "value": value
        })
    
    return tags_formatted

def update_account_config(
        account, 
        subnet_name, 
        security_group_name, 
        auto_scale, regions, 
        include_tags, 
        exclude_tags,
        custom_tags,
        scan_non_running,
        scanners,
        enforce_permissions_check,
        set_as_hub,
        hub_account_id,
        oci_vcn, 
        oci_excluded_compartments,
        scan_latest,
        scan_cap,
        scan_layers,
        radar_cap,
        radar_latest
    ):
    account_id = account["credential"]["cloudProviderAccountID"]
    cloud_type = account["credential"]["type"]
    del account["modified"]
    del account["credential"]

    # Agentless Parameters
    if cloud_type == "oci":
        if not subnet_name or subnet_name.lower() == "none":
            if oci_vcn and oci_vcn.lower() != "none":
                print("VCN cannot appear without subnet. Subnet Name is required")
                print(f"Skipping account ID: {account_id}...")
                return 0
            
            if security_group_name and security_group_name.lower() != "none":
                if not oci_vcn or oci_vcn.lower() == "none":
                    print("Security group cannot appear without VCN. VCN Name is required")

                print("Security group cannot appear without subnet. Subnet Name is required")
                print(f"Skipping account ID: {account_id}...")
                return 0
        
        else:
            if not oci_vcn or oci_vcn.lower() == "none":
                print("Subnet cannot appear without VCN. VCN Name is required")
                print(f"Skipping account ID: {account_id}...")
                return 0

    if security_group_name: 
        if cloud_type in ("aws", "azure", "oci"):
            if security_group_name.lower() == "none":
                account["agentlessScanSpec"]["securityGroup"] = ""
            else:         
                account["agentlessScanSpec"]["securityGroup"] = security_group_name
        else:
            print(f"{account_id} is not an AWS, Azure or OCI account. Skipped Security Group config")

    if subnet_name: 
        if subnet_name.lower() == "none":
            account["agentlessScanSpec"]["subnet"] = ""
        else:
            account["agentlessScanSpec"]["subnet"] = subnet_name
    
    if auto_scale: account["agentlessScanSpec"]["autoScale"] = auto_scale.lower() == "true"

    if regions: 
        if regions[0].lower() == "none":
            account["agentlessScanSpec"]["regions"] = []
        else:
            account["agentlessScanSpec"]["regions"] = regions

    if oci_excluded_compartments:
        if cloud_type == "oci":
            if oci_excluded_compartments[0].lower() == "none":
                account["agentlessScanSpec"]["ociExcludedCompartments"] = []
            else:
                account["agentlessScanSpec"]["ociExcludedCompartments"] = oci_excluded_compartments
        else:
            print(f"{account_id} is not an OCI account. Skipped Excluded Compartments")

    if oci_vcn: 
        if cloud_type == "oci":
            if oci_vcn.lower() == "none":
                account["agentlessScanSpec"]["ociVcn"] = ""
            else:
                account["agentlessScanSpec"]["ociVcn"] = oci_vcn
        else:
            print(f"{account_id} is not an OCI account. Skipped VCN name setup")

    if include_tags: 
        if include_tags == ["none"]:
            account["agentlessScanSpec"]["includedTags"] = []
        else:
            account["agentlessScanSpec"]["includedTags"] = include_tags
            
        if "excludedTags" in account["agentlessScanSpec"]:
            del account["agentlessScanSpec"]["excludedTags"]

    if exclude_tags: 
        if exclude_tags == ["none"]:
            account["agentlessScanSpec"]["excludedTags"] = []
        else:
            account["agentlessScanSpec"]["excludedTags"] = exclude_tags

        if "includedTags" in account["agentlessScanSpec"]:
            del account["agentlessScanSpec"]["includedTags"]

    if custom_tags: 
        if custom_tags == ["none"]:
            account["agentlessScanSpec"]["customTags"] = []
        else:
            account["agentlessScanSpec"]["customTags"] = custom_tags
    
    if scan_non_running: account["agentlessScanSpec"]["scanNonRunning"] = scan_non_running.lower() == "true"
    if scanners: account["agentlessScanSpec"]["scanners"] = scanners
    if enforce_permissions_check: account["agentlessScanSpec"]["skipPermissionsCheck"] = enforce_permissions_check.lower() == "false"
    if set_as_hub: account["agentlessScanSpec"]["hubAccount"] = set_as_hub == "true"

    if hub_account_id:
        account["agentlessScanSpec"]["hubAccount"] = False
        account["agentlessScanSpec"]["hubCredentialID"] = hub_account_id
        account["agentlessScanSpec"]["scanners"] = 0
        account["agentlessScanSpec"]["autoScale"] = False
        account["agentlessScanSpec"]["skipPermissionsCheck"] = True

    # Severless Parameters
    if scan_latest: account["serverlessScanSpec"]["scanAllVersions"] = scan_latest == "false"
    if scan_cap: account["serverlessScanSpec"]["cap"] = int(scan_cap)

    if cloud_type == "aws":
        if scan_layers: account["serverlessScanSpec"]["scanLayers"] = scan_layers == "true"
        if radar_cap: account["serverlessRadarCap"] = radar_cap
        if radar_latest: account["discoverAllFunctionVersions"] = radar_latest == "false"
    
    return account


if __name__ == "__main__":
    # Agentless Parameters
    parser.add_argument("-a", "--account-ids", nargs='+', default=[], help="Account IDs where the agentless configuration shall be applied")
    parser.add_argument("-H", "--hub-account-id", type=str, default=HUB_ACCOUNT_ID, help="ID of the account to be set as Hub")
    parser.add_argument("-G", "--organization-id", type=str, default=ORGANIZATION_ID, help="Organization ID where the agentless configuration shall be applied to all member accounts")
    parser.add_argument("-T", "--organization-type", type=str, default=ORGANIZATION_TYPE, choices=["aws", "gcp", "azure"], help="Organization type of the Organization ID. Can be: aws, gcp or azure")
    parser.add_argument("-u", "--username", type=str, default=PRISMA_USERNAME, help="Prisma Cloud Access Key Id")
    parser.add_argument("-p", "--password", type=str, default=PRISMA_PASSWORD, help="Prisma Cloud Secret Key")
    parser.add_argument("-P", "--prisma-api-endpoint", type=str, default=PRISMA_API_ENDPOINT, help="Prisma Cloud API Endpoint")
    parser.add_argument("-e", "--compute-api-endpoint", type=str, default=COMPUTE_API_ENDPOINT, help="Prisma Cloud Compute API Endpoint")
    parser.add_argument("-s", "--subnet-name", type=str, default=SUBNET_NAME, help="Subnet Name used for agentless configuration. If set to the value 'none', Prisma Cloud will create the VPC and subnet for you")
    parser.add_argument("-g", "--security-group-name", type=str, default=SECURITY_GROUP_NAME, help="(AWS, Azure and OCI only) Security Group Name used for agentless configuration. If set to the value 'none', Prisma Cloud will create the security group for you")
    parser.add_argument("-x", "--exclude-tags", nargs='+', default=[], help="Exclude hosts based on tags")
    parser.add_argument("-i", "--include-tags", nargs='+', default=[], help="Include hosts based on tags")
    parser.add_argument("-c", "--custom-tags", nargs='+', default=[], help="Custom tags for the spot instance deployed")
    parser.add_argument("-r", "--regions", nargs='+', default=[], help="Scan only certain regions")
    parser.add_argument("-S", "--scanners", type=int, default=1, choices=list(range(1, 11)), help="Maximum number of scanners")
    parser.add_argument("-n","--scan-non-running", type=str, choices=["true", "false"], help="enables or disables scanning of non running hosts")
    parser.add_argument("-A","--auto-scale", type=str, choices=["true", "false"], help="enables or disables autoscaling")
    parser.add_argument("-C","--enforce-permissions-check", type=str, choices=["true", "false"], help="if is set to true the account won't be scanned if there are missing permissions")
    parser.add_argument("-O", "--oci-excluded-compartments", nargs='+', default=[], help="(OCI Only) Exclude by name the compartments to be scanned")
    parser.add_argument("-o", "--oci-vcn", type=str, help="(OCI Only) scan VCN name")
    parser.add_argument("-l", "--limit", type=int, default=LIMIT, help="Set the limit of accounts to be retrieved while getting the accounts information")
    parser.add_argument("-B", "--bulk-update-count", type=int, default=BULK_UPDATE_COUNT, help="Set the amount of accounts to be updated at once")
    parser.add_argument("--set-as-hub", type=str, choices=["true", "false"], help="Set the account as Hub")
    parser.add_argument("--agentless-state", type=str, choices=["enabled", "disabled"], help="Enables or Disables Agentless Scanning from CSPM Console")
    
    # Serverless Arguments
    parser.add_argument("--scan-latest", type=str, choices=["true", "false"], help="if is set to true, it will scan only the latest version of serverless functions")
    parser.add_argument("--scan-cap", type=str, help="The limit of how many functions will be scanned for vulnerabilities and compliance. If set to 0, it will scann all the functions")
    parser.add_argument("--scan-layers", type=str, choices=["true", "false"], help="if is set to true, it will scan the lambda functions layers. Only applicable for AWS cloud accounts")
    parser.add_argument("--radar-cap", type=int, help="The amount of functions to be graphed in the Radar view. Minimum is 1")
    parser.add_argument("--radar-latest", type=str, choices=["true", "false"], help="If set to true, it show the radar view of only the latest version of the functions")
    parser.add_argument("--serverless-state", type=str, choices=["enabled", "disabled"], help="Enables or Disables Serverless Scanning from CSPM Console")

    # General Values
    parser.add_argument("--change-state-only", action='store_true', help="Only updates the state of Serverles or Agentless scanning")
    parser.add_argument("--onboarding-mode", type=str, choices=["org", "single"], default=ONBOARDING_MODE, help="Is the way the accounts were onboarded. Can be 'org' or 'single' for organization level or single account level respectively")
    parser.add_argument("--account-groups", nargs='+', default=ACCOUNT_GROUPS, help="Set the account groups to be used to retrieve the account IDs")


    args = parser.parse_args()

    # Agentless arguments
    account_ids = args.account_ids
    hub_account_id = args.hub_account_id
    organization_id = args.organization_id
    organization_type = args.organization_type
    username = args.username
    password = args.password
    prisma_api_endpoint = args.prisma_api_endpoint
    compute_api_endpoint = args.compute_api_endpoint
    subnet_name = args.subnet_name
    security_group_name = args.security_group_name
    exclude_tags = format_tags(args.exclude_tags, "Excluded Tags")
    include_tags = format_tags(args.include_tags, "Included Tags")
    custom_tags = format_tags(args.custom_tags, "Custom tags")
    scan_non_running = args.scan_non_running
    scanners = args.scanners
    regions = args.regions
    oci_excluded_compartments = args.oci_excluded_compartments
    oci_vcn = args.oci_vcn
    auto_scale = args.auto_scale
    enforce_permissions_check = args.enforce_permissions_check
    limit = args.limit
    bulk_update_count = args.bulk_update_count
    set_as_hub = args.set_as_hub
    agentless_state = args.agentless_state

    # Serverless arguments
    scan_latest = args.scan_latest
    scan_cap = args.scan_cap
    scan_layers = args.scan_layers
    radar_cap = args.radar_cap
    radar_latest = args.radar_latest
    serverless_state = args.serverless_state

    # General values
    change_state_only = args.change_state_only
    onboarding_mode = args.onboarding_mode
    account_groups = args.account_groups

    if exclude_tags and include_tags:
        parser.error("--include-tags and --exclude-tags cannot be used at the same time.")

    if not account_ids and not organization_id and not account_groups:
        parser.error("There's not either --account-ids, --organization-id or --account-groups parameters.")
    
    if not organization_id and not organization_type:   
        parser.error("--organization-id and --organization-type are dependant.")

    if organization_id and not prisma_api_endpoint:   
        parser.error("--prisma-api-endpoint is required if --organization-id is set.")
    
    if hub_account_id and account_ids:   
        if hub_account_id in account_ids:
            account_ids.remove(hub_account_id)

    #Set token variables
    headers = {
        "Content-Type": "application/json"
    }
    token_body = {
        "username": username,
        "password": password
    }

    if not prisma_api_endpoint:
        if not compute_api_endpoint:   
            parser.error("If --prisma-api-endpoint is not set, then --compute-api-endpoint is required.")
    
    else:
        # Retrieve Prisma Cloud token
        prisma_token = json.loads(http_request(prisma_api_endpoint, "/login", token_body))["token"]
        headers["X-Redlock-Auth"] = prisma_token
        
        if not compute_api_endpoint:
            # Get Compute API endpoint
            compute_api_endpoint = json.loads(http_request(prisma_api_endpoint, "/meta_info", method="GET"))["twistlockUrl"]

        if onboarding_mode == "org":
            if agentless_state: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{organization_id}/feature/compute-agentless", body={"state": agentless_state}, method="PATCH")
            if serverless_state: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{organization_id}/feature/compute-serverless-scan", body={"state": serverless_state}, method="PATCH")

            if agentless_state or serverless_state:
                print(f"Changed the state of Org {organization_id}. Agentless: {agentless_state}. Serverless Scan: {serverless_state}")
                if change_state_only:
                    print("Only required to change state")
                    sys.exit(0)


        if account_groups:
            prisma_account_groups = json.loads(http_request(prisma_api_endpoint, "/cloud/group/name", method="GET"))
            account_group_ids = []
            account_ids = []
            for prisma_account_group in prisma_account_groups:
                if prisma_account_group["name"] in account_groups:
                    account_group_ids.append(prisma_account_group["id"])

            accounts_info = json.loads(http_request(prisma_api_endpoint, f"/cloud/name?onlyActive=true&accountGroupIds={','.join(account_group_ids)}&cloudType={organization_type}", method="GET"))
            for account_info in accounts_info:
                if account_info["id"] != hub_account_id and ":" not in account_info["id"]:
                    account_ids.append(account_info["id"])

                    if onboarding_mode == "single":
                        try:
                            if agentless_state: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{account_info['id']}/feature/compute-agentless", body={"state": agentless_state}, method="PATCH")
                            if serverless_state: http_request(prisma_api_endpoint, f"/cas/v1/cloud_account/{account_info['id']}/feature/compute-serverless-scan", body={"state": serverless_state}, method="PATCH")
                        except RequestError as err:
                            print(err)
                            print(f"Removing account {account_info['id']} from Account Ids")
                            account_ids.remove(account_info['id'])


            if (agentless_state or serverless_state) and onboarding_mode == "single":
                print(f"Changed the state of accounts under Account Groups: {', '.join(account_groups)}. Agentless: {agentless_state}. Serverless Scan: {serverless_state}")
                if change_state_only:
                    print("Only required to change state")
                    sys.exit(0)

            print(f"Total Accounts in the Account Groups {', '.join(account_groups)}: {len(account_ids)}")

        elif organization_id:
            account_ids = []
            accounts_info = json.loads(http_request(prisma_api_endpoint, f"/cloud/{organization_type}/{organization_id}/project?excludeAccountGroupDetails=true", method="GET"))
            for account_info in accounts_info:
                if account_info["accountId"] != hub_account_id:
                    account_ids.append(account_info["accountId"])

            print(f"Total Accounts in the Org {organization_id}: {len(account_ids)}")
        
        del headers["X-Redlock-Auth"]

    # Retrieve Compute Console token
    compute_token = json.loads(http_request(compute_api_endpoint, "/api/v1/authenticate", token_body))["token"]
    headers["Authorization"] = f"Bearer {compute_token}"

    # Updating Hub Account
    print(f"Updating Hub Account: {hub_account_id}")
    hub_account = json.loads(http_request(compute_api_endpoint, f"/api/v1/cloud-scan-rules?cloudProviderAccountIDs={hub_account_id}&offset=0&limit=10", method="GET"))[0]
    updated_hub_account = update_account_config(
        hub_account, 
        subnet_name, 
        security_group_name, 
        auto_scale, regions, 
        include_tags, 
        exclude_tags,
        custom_tags,
        scan_non_running,
        scanners,
        enforce_permissions_check,
        "true",
        "",
        oci_vcn, 
        oci_excluded_compartments,
        scan_latest,
        scan_cap,
        scan_layers,
        radar_cap,
        radar_latest
    )

    updateAgentlessConfig([updated_hub_account], compute_api_endpoint)

    accounts = getCloudAccountsList(compute_api_endpoint, limit, organization_type)
    data = []

    if hub_account_id:
        set_as_hub = "false"
        subnet_name = ""
        security_group_name = ""

    for account in accounts:
        account_id = account["credential"]["cloudProviderAccountID"]
        if account_id in account_ids:
            updated_account = update_account_config(
                account, 
                subnet_name, 
                security_group_name, 
                auto_scale, regions, 
                include_tags, 
                exclude_tags,
                custom_tags,
                scan_non_running,
                scanners,
                enforce_permissions_check,
                set_as_hub,
                hub_account_id,
                oci_vcn, 
                oci_excluded_compartments,
                scan_latest,
                scan_cap,
                scan_layers,
                radar_cap,
                radar_latest
            )

            if updated_account:
                data.append(updated_account)

            account_ids.remove(account_id)

    updateAgentlessConfig(data, compute_api_endpoint)
    print(f"Total Accounts Modified: {len(data)}")