import boto3
import os
import json
import platform
import configparser
from botocore.exceptions import NoCredentialsError, PartialCredentialsError


# AWS SSO start URL and Region
sso_start_url = "https://awsdoegov.awsapps.com/start/#"
sso_region = "us-east-1"


# AWS Credentials Path
aws_credentials_path = os.path.join(os.getenv("USERPROFILE"), '.aws', 'credentials')
aws_config_path = os.path.join(os.getenv("USERPROFILE"), '.aws', 'config')


# Determine the SSO cache directory based on OS
if platform.system() == "Windows":
    sso_cache_path = os.path.join(os.getenv("USERPROFILE"), ".aws", "sso", "cache")
# else:
#     # Path to AWS SSO cache directory for linux\mac
#     sso_cache_path = os.path.expanduser("~\.aws\sso\cache")


def get_sso_access_token():
    """
    Captures the SSO token from .aws/sso/cache/*.json file after aws sso login is ran
    """
    try:
        # List all files in the SSO cache directory
        files = os.listdir(sso_cache_path)
        for file in files:
            file_path = os.path.join(sso_cache_path, file)
            [print(f"Reading file: {os.path.join(sso_cache_path, file)}") for file in os.listdir(sso_cache_path) if file.endswith(".json")]
            with open(file_path, "r") as f:
                cached_data = json.load(f)
                # Check if the cache belongs to the correct start URL
                if cached_data.get("startUrl") == sso_start_url:
                    access_token = cached_data.get("accessToken")
                    print(f"{access_token}")
                    if access_token:
                        print(f"Found valid access token in file: {file_path}")
                        return cached_data["accessToken"]
                    else:
                        print(f"File {file_path} does not match or is missing 'accessToken'.")
        # Raise an exception if no valid token is found
        raise Exception("No valid access token found in SSO cache.")
    except Exception as e:
        print(f"Error retrieving access token: {e}")
        return None

# Initialize SSO Client
sso_client = boto3.client("sso", region_name=sso_region)


def list_accounts(access_token):
    """
    Gathers a list of accounts that are accessible by the current user
    """
    accounts = []
    try:
        response = sso_client.list_accounts(accessToken=access_token, maxResults=50)
        accounts.extend(response["accountList"])
        # Paginate if there are more accounts
        while "nextToken" in response:
            response = sso_client.list_accounts(accessToken=access_token, maxResults=50, NextToken=response["nextToken"])
            accounts.extend(response["accountList"])
    except Exception as e:
        print(f"Error fetching accounts : {e}")
    return accounts


# Get the roles for a specific account
def list_account_roles(account_id, access_token):
    """
    Gathers a list of account roles the user has access to
    """
    roles = []
    try:
        response = sso_client.list_account_roles(accountId=account_id, accessToken=access_token, maxResults=50)
        roles.extend(response["roleList"])
        # Paginate if there are more roles
        while "nextToken" in response:
            response = sso_client.list_accounts(accountId=account_id, accessToken=access_token, maxResults=50, nextToken=response["nextToken"])
            roles.extend(response["roleList"])
    except Exception as e:
        print(f"Error fetching roles for account {account_id}: {e}")
    return roles

# Get API keys for roles
def get_role_credentials(account_id, role_name, access_token):
    """
    Grab API keys from roles programatically
    """
    try:
        # Grab keys from the roles using SSO token
        response = sso_client.get_role_credentials(
            roleName = role_name,
            accountId = account_id,
            accessToken = access_token
        )

        # Debugging to confirm response structure
        if "roleCredentials" not in response:
            raise ValueError(f"Unexpected response structure: {response}")

        return response["roleCredentials"]

    except sso_client.exceptions.InvalidRequestException as e:
        print(f" invalid request for role '{role_name}' in account '{account_id}': {e}")
    except sso_client.exceptions.UnauthorizedException as e:
        print(f"Unauthorized access for role '{role_name}' in account '{account_id}: {e}")
        print(f"Please run 'aws sso login' to refresh your session.")
    except Exception as e:
        print(f"Unhandled error fetching credentials for role '{role_name}' in account '{account_id}': {e}")
        print(f"Exception type: {type(e).__name__}, Message: {str(e)}")
    return None

def save_aws_profile(account_name, credentials):
    """
    Save AWS profile credentials to .aws/credentials and .aws/config
    """

    # Ensure credentials exist before writing
    if not credentials:
        print(f"Skipping profile setup for {account_name} - No credentials found.")
        return

    access_key = credentials['accessKeyId']
    secret_key = credentials['secretAccessKey']
    session_token = credentials['sessionToken']

    # Ensure AWS credentials/config directory exists
    aws_dir = os.path.dirname(aws_credentials_path)
    if not os.path.exists(aws_dir):
        os.makedirs(aws_dir)  # Fixed: mkdirs -> makedirs
    
    # Load existing credentials file
    credentials_config = configparser.ConfigParser()
    if os.path.exists(aws_credentials_path):
        credentials_config.read(aws_credentials_path)

    # Add/update profile in credentials file
    credentials_config[account_name] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "aws_session_token": session_token
    }

    # Write to .aws/credentials
    with open(aws_credentials_path, "w") as credentials_file:
        credentials_config.write(credentials_file)
    print(f"Profile '{account_name}' saved in credentials file.")

    # Fix for AWS config file formatting
    # Instead of using ConfigParser for the config file, we'll write it manually
    # to ensure it matches the expected AWS format
    
    profile_section = f"[profile {account_name}]"
    config_content = f"{profile_section}\nregion = us-east-1\noutput = json\n\n"
    
    # Read existing config and append/update our profile
    if os.path.exists(aws_config_path):
        with open(aws_config_path, "r") as config_file:
            existing_config = config_file.read()
            
        # Check if profile already exists and update it
        if profile_section in existing_config:
            lines = existing_config.split('\n')
            new_lines = []
            skip_section = False
            
            for line in lines:
                if line == profile_section:
                    skip_section = True
                    continue
                elif skip_section and line.startswith('['):
                    skip_section = False
                
                if not skip_section:
                    new_lines.append(line)
            
            existing_config = '\n'.join(new_lines)
        
        # Combine with our new profile section
        config_content = existing_config.rstrip() + "\n\n" + config_content
    
    # Write the updated config
    with open(aws_config_path, "w") as config_file:
        config_file.write(config_content)
    
    print(f"Profile '{account_name}' saved in config file")

# Main script
if __name__ == "__main__":
    try:
        # Retrieve access token from cache
        access_token = get_sso_access_token()
        if not access_token:
            print("SSO login required. Run 'aws sso login' and try again.")
            exit(1)

        # List all accounts
        accounts = list_accounts(access_token)
        print("Accounts found: ")
        for account in accounts:
            print(f"Account ID: {account['accountId']}, Name: {account['accountName']}")

            # List Roles from the current account
            roles = list_account_roles(account["accountId"], access_token)  # Fixed: Added missing access_token parameter
            for role in roles:
                #  print(f" Role: {role['roleName']}")
                if role["roleName"] == "InfrastructureArchitect":
                    print(f" Found role 'InfrastructureArchitect' in Account ID: {account['accountId']}")
                    # Fetch credentials for the role
                    credentials = get_role_credentials(account['accountId'], role['roleName'], access_token)
                    if credentials:
                        save_aws_profile(account['accountName'], credentials)
                    else:
                        print(f"Failed to get credentials for '{account['accountName']}'")
    except (NoCredentialsError, PartialCredentialsError) as e:
        print("SSO session not found. Run 'aws sso login' first.")
