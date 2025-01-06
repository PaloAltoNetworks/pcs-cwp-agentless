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

SLEEP = int(os.getenv("SLEEP", "5"))
DEBUG = os.getenv("DEBUG", "false") in ("true", "True", "1", "y", "yes")
CATEGORIES = os.getenv("CATEGORIES", "")
REPORT = os.getenv("REPORT", "HostsStatus.csv")

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


def getHostsStatus(debug = DEBUG):
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
    
    # Download Hosts statuses
    hosts_status_path = "/api/v1/agentless/hosts-status/download"
    if CATEGORIES:
        hosts_status_path += f"?categories={CATEGORIES}" 

    data = http_request(compute_api_endpoint, hosts_status_path , method="GET", debug=debug)

    with open(REPORT, "wb") as report:
        report.write(data)
        report.close()


if __name__ == "__main__":
    getHostsStatus()