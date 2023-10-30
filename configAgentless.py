#!/usr/bin/python3
import requests
import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv()

parser = argparse.ArgumentParser(
    prog='python3 configAgentless.py',
    description='This sets up the subnet and security group in Prisma Cloud for Agentless scanning',
    epilog='For further documentation go to: https://github.com/PaloAltoNetworks/pcs-cwp-agentless'
)

COMPUTE_API_ENDPOINT = os.getenv("COMPUTE_API_ENDPOINT", "api.prismacloud.io")
PRISMA_USERNAME = os.getenv("PRISMA_USERNAME", "")
PRISMA_PASSWORD = os.getenv("PRISMA_PASSWORD", "")
SUBNET_NAME = os.getenv("SUBNET_NAME", "")
SECURITY_GROUP_NAME = os.getenv("SECURITY_GROUP_NAME", "")
SKIP_VERIFY = bool(int(os.getenv("SKIP_VERIFY", "0")))


def getToken(username, password, api_endpoint, verify):
    headers = {
        "Content-Type": "application/json"
    }
    body = {
        "username": username,
        "password": password
    }

    response = requests.post(f"{api_endpoint}/api/v1/authenticate", json=body, headers=headers, verify=verify)
    if response.status_code == 200:
        return response.json()["token"]
    
    print(response.json())
    sys.exit(2)


def getCloudAccountsList(api_endpoint, token, verify):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    response = requests.get(f"{api_endpoint}/api/v1/cloud-scan-rules?project=Central+Console&agentlessScanEnabled=true", headers=headers, verify=verify)
    if response.status_code == 200:
        return response.json()
    
    print(response.json())
    sys.exit(2)


def updateAgentlessConfig(data, api_endpoint, token, verify):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    update = requests.put(f"{api_endpoint}/api/v1/cloud-scan-rules", headers=headers, json=data, verify=verify)
    print(update.text)
    return update.status_code


def format_tags(tags_list, list_name=""):
    tags_formatted = []

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


if __name__ == "__main__":
    parser.add_argument("-a", "--account-ids", nargs='+', default=[], required=True, help="Account IDs where the agentless configuration shall be applied")
    parser.add_argument("-u", "--username", type=str, default=PRISMA_USERNAME, help="Prisma Cloud Access Key Id")
    parser.add_argument("-p", "--password", type=str, default=PRISMA_PASSWORD, help="Prisma Cloud Secret Key")
    parser.add_argument("-e", "--compute-api-endpoint", type=str, default=COMPUTE_API_ENDPOINT, help="Prisma Cloud Compute Api Endpoint")
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
    parser.add_argument("--skip-tls-verify", action="store_false", default=SKIP_VERIFY, help="Skip TLS verification")

    args = parser.parse_args()
    account_ids = args.account_ids
    username = args.username
    password = args.password
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
    verify = not args.skip_tls_verify

    if exclude_tags and include_tags:
        print("Cannot be include tags and exclude tags in the same expression.")
        sys.exit(2)

    token = getToken(username, password, compute_api_endpoint, verify)
    accounts = getCloudAccountsList(compute_api_endpoint, token, verify)
    data = []
    accounts_updated = []

    for account in accounts:
        if account["credential"]["cloudProviderAccountID"] in account_ids:
            account_id = account["credential"]["cloudProviderAccountID"]
            cloud_type = account["credential"]["type"]
            del account["modified"]
            del account["credential"]

            if cloud_type == "oci":
                if not subnet_name or subnet_name.lower() == "none":
                    if oci_vcn and oci_vcn.lower() != "none":
                        print("VCN cannot appear without subnet. Subnet Name is required")
                        print(f"Skipping account ID: {account_id}...")
                        continue
                    
                    if security_group_name and security_group_name.lower() != "none":
                        if not oci_vcn or oci_vcn.lower() == "none":
                            print("Security group cannot appear without VCN. VCN Name is required")

                        print("Security group cannot appear without subnet. Subnet Name is required")
                        print(f"Skipping account ID: {account_id}...")
                        continue
                
                else:
                    if not oci_vcn or oci_vcn.lower() == "none":
                        print("Subnet cannot appear without VCN. VCN Name is required")
                        print(f"Skipping account ID: {account_id}...")
                        continue

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
                account["agentlessScanSpec"]["includedTags"] = include_tags
                if "excludedTags" in account["agentlessScanSpec"]:
                    del account["agentlessScanSpec"]["excludedTags"]

            if exclude_tags: 
                account["agentlessScanSpec"]["excludedTags"] = exclude_tags
                if "includedTags" in account["agentlessScanSpec"]:
                    del account["agentlessScanSpec"]["includedTags"]

            if custom_tags: account["agentlessScanSpec"]["customTags"] = custom_tags
            if scan_non_running: account["agentlessScanSpec"]["scanNonRunning"] = scan_non_running.lower() == "true"
            if scanners: account["agentlessScanSpec"]["scanners"] = scanners
            if enforce_permissions_check: account["agentlessScanSpec"]["skipPermissionsCheck"] = enforce_permissions_check.lower() == "false"

            data.append(account)
            accounts_updated.append(account_id)
            account_ids.remove(account_id)
    
    status_code = updateAgentlessConfig(data, compute_api_endpoint, token, verify)
    
    if status_code == 200:
        if accounts_updated:
            print(f"Successfully updated accounts: {', '.join(accounts_updated)}")
        else:
            print("Successfully updated accounts: None")

        if account_ids:
            print(f"Failed while updating accounts: {', '.join(account_ids)}")
        else:
            print("Failed while updating accounts: None")
    
    else:
        print(f"Verify parameters input, and verify that the user or service account used has a role with read and write access to the Cloud Account Policy permission and, for Prisma Cloud SaaS version, has assigned any account group that contains the Account IDs: {', '.join(accounts_updated + account_ids)}")