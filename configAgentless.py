#!/usr/bin/python3
import requests
import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv()

parser = argparse.ArgumentParser(
    prog='Prisma Cloud Agentless Subnet-SG config',
    description='This sets up the subnet and security group in Prisma Cloud for Agentless scanning',
    epilog=''
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
    return update.status_code


def format_tags(tags_list):
    tags_formatted = []

    for tag in tags_list:
        if "=" not in tag:
            print(f"Invalid format: {tag}")
            continue

        key, value = tag.split("=")

        if not value:
            print(f"Tag {key} doesn't have any value.")
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
    parser.add_argument("-s", "--subnet-name", type=str, default=SUBNET_NAME, help="Subnet Name used for agentless configuration")
    parser.add_argument("-g", "--security-group-name", type=str, default=SECURITY_GROUP_NAME, help="Security Group Name used for agentless configuration")
    parser.add_argument("-x", "--exclude-tags", nargs='+', default=[], help="Exclude hosts based on tags")
    parser.add_argument("-i", "--include-tags", nargs='+', default=[], help="Include hosts based on tags")
    parser.add_argument("-c", "--custom-tags", nargs='+', default=[], help="Custom tags for the spot instance deployed")
    parser.add_argument("-r", "--regions", nargs='+', default=[], help="Scan only certain regions")
    parser.add_argument("-S", "--scanners", type=int, default=1, choices=list(range(1, 11)), help="Maximum number of scanners")
    parser.add_argument("-n","--scan-non-running", type=str, choices=["true", "false"], help="enables or disables scanning of non running hosts")
    parser.add_argument("-A","--auto-scale", type=str, choices=["true", "false"], help="enables or disables autoscaling")
    parser.add_argument("--skip-tls-verify", action="store_false", default=SKIP_VERIFY, help="Skip TLS verification")

    args = parser.parse_args()
    account_ids = args.account_ids
    username = args.username
    password = args.password
    compute_api_endpoint = args.compute_api_endpoint
    subnet_name = args.subnet_name
    security_group_name = args.security_group_name
    exclude_tags = args.exclude_tags
    include_tags = args.include_tags
    custom_tags = args.custom_tags
    scan_non_running = args.scan_non_running
    scanners = args.scanners
    regions = args.regions
    auto_scale = args.auto_scale
    verify = not args.skip_tls_verify

    if exclude_tags and include_tags:
        print("Cannot be include tags and exclude tags in the same expression.")
        sys.exit(2)

    token = getToken(username, password, compute_api_endpoint, verify)
    accounts = getCloudAccountsList(compute_api_endpoint, token, verify)
    data = []
    accounts_updated = []
    for account in accounts:
        if account["credentialId"] in account_ids:
            accounts_updated.append(account["credentialId"])
            del account["modified"]
            del account["credential"]
            if security_group_name: account["agentlessScanSpec"]["securityGroup"] = security_group_name
            if subnet_name: account["agentlessScanSpec"]["subnet"] = subnet_name
            if auto_scale: account["agentlessScanSpec"]["autoScale"] = auto_scale.lower() == "true"
            if regions: account["agentlessScanSpec"]["regions"] = regions
            if include_tags: account["agentlessScanSpec"]["includedTags"] = format_tags(include_tags)
            if exclude_tags: account["agentlessScanSpec"]["excludedTags"] = format_tags(exclude_tags)
            if custom_tags: account["agentlessScanSpec"]["customTags"] = format_tags(custom_tags)
            if scan_non_running: account["agentlessScanSpec"]["scanNonRunning"] = scan_non_running.lower() == "true"
            if scanners: account["agentlessScanSpec"]["scanners"] = scanners

            data.append(account)
            account_ids.remove(account["credentialId"])
    
    status_code = updateAgentlessConfig(data, compute_api_endpoint, token, verify)
    
    if status_code == 200:
        print(f"Successfully updated accounts: {', '.join(accounts_updated)}")
        if account_ids:
            print(f"Failed while updating accounts: {', '.join(account_ids)}")
        else:
            print("Failed while updating accounts: None")
