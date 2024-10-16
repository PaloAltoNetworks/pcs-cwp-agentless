from configAgentless import configAgentless
import os
import json

CONFIG_FILE = os.getenv("CONFIG_FILE", "config.json")

if __name__ == "__main__":

    headers = {
        "Content-Type": "application/json"
    }

    with open(CONFIG_FILE) as config_file:
        config = json.loads(config_file.read())

    find_in_org = config["findInOrg"]
    debug = config["debug"]
    backup = config["backup"]
    limit = config["limit"]
    bulk_update_count = config["bulkUpdateCount"]

    # Configure Account Sets
    for account_set in config["accountSets"]:
        # General parameters
        change_state_only = account_set["changeStateOnly"]
        organization_id = account_set["organizationId"]
        organization_type = account_set["organizationType"]
        account_groups = account_set["accountGroups"]
        account_ids = account_set["accountIds"]
        onboarding_mode = account_set["onboardingMode"]
        scan_mode = account_set["scanMode"]

        # Agentless parameters
        hub_account_id = account_set["agentless"]["hubAccountId"] 
        subnet_name = account_set["agentless"]["subnetName"]
        security_group_name = account_set["agentless"]["securityGroupName"]
        exclude_tags = account_set["agentless"]["excludeTags"]
        include_tags = account_set["agentless"]["includeTags"]
        custom_tags = account_set["agentless"]["customTags"]
        regions = account_set["agentless"]["regions"]
        scanners = account_set["agentless"]["scanners"]
        scan_non_running = account_set["agentless"]["scanNonRunning"]
        auto_scale = account_set["agentless"]["autoScale"]
        enforce_permissions_check = account_set["agentless"]["enforcePermissionsCheck"]
        oci_excluded_compartments = account_set["agentless"]["ociExcludedCompartments"]
        oci_vcn = account_set["agentless"]["ociVcn"]
        set_as_hub = account_set["agentless"]["setAsHub"]
        agentless_state = account_set["agentless"]["agentlessState"]

        # Serverless parameters
        scan_latest = account_set["serverless"]["scanLatest"]
        scan_cap = account_set["serverless"]["scanCap"]
        scan_layers = account_set["serverless"]["scanLayers"]
        radar_cap = account_set["serverless"]["radarCap"]
        radar_latest = account_set["serverless"]["radarLatest"]
        serverless_state = account_set["serverless"]["serverlessState"]

        configAgentless(
            # General values
            organization_id,
            organization_type,
            account_ids,
            change_state_only,
            onboarding_mode,
            account_groups,
            scan_mode,
            debug,
            find_in_org,
            backup,
            # Agentless arguments
            hub_account_id,
            subnet_name,
            security_group_name,
            exclude_tags,
            include_tags,
            custom_tags,
            scan_non_running,
            scanners,
            regions,
            oci_excluded_compartments,
            oci_vcn,
            auto_scale,
            enforce_permissions_check,
            limit,
            bulk_update_count,
            set_as_hub,
            agentless_state,
            # Serverless arguments
            scan_latest,
            scan_cap,
            scan_layers,
            radar_cap,
            radar_latest,
            serverless_state
        )