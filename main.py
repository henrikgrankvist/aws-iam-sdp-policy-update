"""
Improvements:
- Check if AWS account already exists = DONE
- Read AWS accounts from somewhere
- Make more functions of the code
- Read through the AWS accounts that are tried to being added and then evaluate if they fit in a policy or not
- Create new policy if needed and attach it to role = DONE
"""

import boto3
import json
import sys
import botocore.exceptions
import logging

from datetime import datetime

POLICY_MAX_CHARACTER_SIZE = 6144
ROLE_NAME = 'SDP_NameResolver'

new_aws_accounts = ["333456789123", "123476789122", "122276789123", "122276789111"]


def print_json(text):
    print(json.dumps(text, default=datetime_handler, indent=4))

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

def remove_oldest_policy_version(aws, policy_arn):
    """
    Removes the oldest policy version.
    Will only remove a policy version if there are 5 policy versions already.
    Will not try to remove the default policy version
    """
    response = aws.iam_list_policy_versions(policy_arn)

    if len(response["Versions"]) < 5:
        print(f'Policy has only {len(response["Versions"])} policy versions. None has to be removed.')
        return False

    oldest_policy_version = datetime.now().isoformat() # Setting the oldest time to the current time

    for policy_version in response["Versions"]:

        policy_version_createdate = policy_version["CreateDate"].isoformat() # The exact time when the policy version was created

        if policy_version_createdate < oldest_policy_version:

            if policy_version["IsDefaultVersion"]: # skipping if the policy version is the default version
                continue
            
            oldest_policy_version = policy_version_createdate
            policy_to_remove = policy_version["VersionId"]
    
    response = aws.iam_delete_policy_version(policy_arn, policy_to_remove)

    status_code = response["ResponseMetadata"]["HTTPStatusCode"]

    if status_code == 200:
        return policy_to_remove

    return False

def format_iam_policy_arn(aws_account):
    return "arn:aws:iam::" + aws_account + ":role/SDP_NameResolver"

class Aws:
    def __init__(self, client_type, profile="default", region=None):

        self.profile = profile
        self.region = region
        self.client_type = client_type

        self._session = boto3.Session(profile_name=self.profile)
        self._client = self._session.client(self.client_type)

    def iam_list_attached_role_policies(self, role):
        
        response = self._client.list_attached_role_policies(
            RoleName=role
        )

        return response

    def iam_get_policy(self, policy_arn):

        response = self._client.get_policy(
            PolicyArn=policy_arn
        )

        return response

    def iam_get_policy_version(self, policy_arn, version_id):

        response = self._client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )

        return response

    def iam_create_policy_version(self, policy_arn, policy_document, default=True):
        try:
            response = self._client.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(policy_document, indent=4),
                SetAsDefault=default
            )

        except botocore.exceptions.ClientError as error:
            print(f'ERROR: {error.response["Error"]["Message"]}')

            if not error.response["Error"]["Code"] == "LimitExceeded":
                print("Unhandled exception. Exiting...")
            
            return False
        
        return True

    def iam_delete_policy_version(self, policy_arn, version_id):

        response = self._client.delete_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )

        return response

    def iam_list_policy_versions(self, policy_arn):

        response = self._client.list_policy_versions(
            PolicyArn=policy_arn
        )

        return response

    def iam_create_policy(self, policy_name, policy_document):

        response = self._client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document, indent=4),
            Description="SDP AWS Resolver Policy"
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            logging.info(f'Sucessfully created IAM policy {policy_name} with ARN {response["Policy"]["Arn"]}')
            return response["Policy"]["Arn"]

        logging.critical(f'Failed to create IAM Policy {policy_name}')
        return None

    def iam_attach_role_policy(self, role_name, policy_arn):
        
        response = self._client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            logging.info(f'Sucessfully attached IAM policy {policy_name} with ARN {role_name}')
            return True

        logging.critical(f'Failed to attach IAM policy {policy_arn} to role {role_name}')
        return False

def generate_new_policy_name():

    return "Pol_SDP_NameResolver_3"

def empty_policy_document():

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": []
            }
        ]
    }
    

def main():

    fmtStr = "%(asctime)s: %(levelname)s: %(funcName)s: %(message)s"
    dateStr = "%Y-%m-%d %I:%M:%S %p"
    logging.basicConfig(
        level=logging.INFO,
        format=fmtStr,
        datefmt=dateStr
    )

    if len(sys.argv) == 2:
        aws_profile_name = str(sys.argv[1]) # AWS CLI profile name

    else:
        print("Invalid number of argument. Exiting...")
        print("Example: python3 " + sys.argv[0].lower() + " <PROFILE NAME>")
        exit(1)

    aws = Aws("iam", aws_profile_name, "eu-north-1")

    response = aws.iam_list_attached_role_policies(ROLE_NAME)

    policy_with_space = False
    list_of_added_aws_accounts = [] # Save list of all currently added AWS accounts

    # Iterate through the IAM policies attached to the role
    for policy in response["AttachedPolicies"]:

        response = aws.iam_get_policy(policy["PolicyArn"])

        # get_policy_version. This includes the actual content of the policy
        response = aws.iam_get_policy_version(policy["PolicyArn"], response["Policy"]["DefaultVersionId"])

        # Save all currently added AWS accounts from all attached policies
        for aws_account in response["PolicyVersion"]["Document"]["Statement"][0]["Resource"]:
            list_of_added_aws_accounts.append(aws_account.split(":")[4])
        
        # Find a policy where there is space left to add a new AWS account.
        # Have to read the size as a string, otherwise it only count the number of entries in the list
        policy_character_size = len(str(response["PolicyVersion"]["Document"]["Statement"][0]["Resource"])) 


        # -2 because the len() reads the [] characters above
        # +50 because that is the number of characters needed to add one new AWS account in the policy
        if policy_character_size - 2 + 50*len(new_aws_accounts) > POLICY_MAX_CHARACTER_SIZE:
            print(f'Policy {policy["PolicyArn"]} is full ({policy_character_size-2} characters)')
        else:
            print(f'Policy {policy["PolicyArn"]} has room ({policy_character_size-2} characters)')
            policy_with_space = True
            policy_with_space = policy
            policy_document = response["PolicyVersion"]["Document"]

    if policy_with_space:
        print(f'Continuing with policy {policy_with_space["PolicyName"]}')
        
        aws_account_added = False
        for aws_account in new_aws_accounts:

            if aws_account in list_of_added_aws_accounts: # AWS account already exists in one of the attached IAM policies
                logging.info(f"AWS account {aws_account} is already added to a policy")
                continue

            list_of_added_aws_accounts.append(aws_account)
            
            policy_document["Statement"][0]["Resource"].append(format_iam_policy_arn(aws_account))
            aws_account_added = True
        
        if aws_account_added:

            
            result = remove_oldest_policy_version(aws, policy_with_space["PolicyArn"])
            if result:
                print(f'Policy version {result} was removed')

            if aws.iam_create_policy_version(policy_with_space["PolicyArn"], policy_document):
                print("SUCCESS: Policy updated with new AWS account(s)")
            else:
                exit()
            
        else:
            print("INFO: No new AWS account(s) were added to the policy")

    else:
        logging.warning("No policy with free space found. Creating a new IAM policy.")

        new_policy_name = generate_new_policy_name() # Generate an non-ovalapping policy name

        policy_document = empty_policy_document()

        for aws_account in new_aws_accounts:

            if aws_account in list_of_added_aws_accounts: # AWS account already exists in one of the attached IAM policies
                logging.info(f"AWS account {aws_account} is already added to a policy")
                continue
            
            list_of_added_aws_accounts.append(aws_account)
            
            policy_document["Statement"][0]["Resource"].append(format_iam_policy_arn(aws_account))
            aws_account_added = True

        policy_arn = aws.iam_create_policy(new_policy_name, policy_document) # Create a new policy

        response = aws.iam_attach_role_policy(ROLE_NAME, policy_arn)

        


if __name__ == '__main__' :
    main()