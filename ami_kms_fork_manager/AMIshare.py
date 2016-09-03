"""
Copyright 2016 Nicholas Christian
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import print_function

import json
import time

import boto3
import botocore

# User must set path to the config file.
CONFIG_PATH = 'config.json'


def share_ami():
    """Adds permission for each account to be able to use the AMI."""

    print("Sharing AMI...")
    try:
        main_ec2_cli.modify_image_attribute(
            DryRun=True,
            ImageId=ami_id,
            OperationType='add',
            UserIds=account_ids,
            LaunchPermission={'Add': [dict(('UserId', account_number) for account_number in account_ids)]})
    except Exception as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            main_ec2_cli.modify_image_attribute(
                ImageId=ami_id,
                OperationType='add',
                UserIds=account_ids,
                LaunchPermission={'Add': [dict(('UserId', account_number) for account_number in account_ids)]})
        else:
            raise e

    print("Successfully shared the AMI.")


def json_data():
    """Grabs all data from the config file"""
    with open(CONFIG_PATH, 'r') as j:
        read_data = json.loads(j.read())

    return read_data


def revoke_ami_access():
    """Revokes access to the specified AMI."""

    print("Revoking access to AMI...")
    try:
        main_ec2_cli.modify_image_attribute(
            DryRun=True,
            ImageId=ami_id,
            OperationType='remove',
            UserIds=account_ids,
            LaunchPermission={'Remove': [dict(('UserId', account_number) for account_number in account_ids)]})
    except Exception as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            main_ec2_cli.modify_image_attribute(
                ImageId=ami_id,
                OperationType='remove',
                UserIds=account_ids,
                LaunchPermission={'Remove': [dict(('UserId', account_number) for account_number in account_ids)]})
        else:
            raise e


def rollback(amis, put_items):
    """Rollbacks all AWS actions done in case something goes wrong."""
    print("Rolling back...")
    revoke_ami_access()

    for account in amis:
        # STS allows you to connect to other accounts using assumed roles.
        assumed_role = main_sts_cli.assume_rule(
            RoleArn="arn:aws:iam::%s:role/%s" % (account['AccountNumber'], role_name),
            RoleSessionName="AssumedRoleSession%s" % int(time.time()))

        role_credentials = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=role_credentials['AccessKeyId'],
            aws_secret_access_key=role_credentials['SecretAccessKey'],
            aws_session_token=role_credentials['SessionToken'])

        ec2_cli = session.client('ec2', region_name=account['Region'])
        dynadb_cli = session.client('dynamodb', region_name=account['Region'])

        for image_to_delete in amis:
            ec2_cli.deregister_image(ImageId=image_to_delete['AMD_ID'])

        try:
            table = dynadb_cli.Table(config_data['General'][0]['DynamoDBTable'])
            for put_item in put_items:
                table.delete_item(Key=put_item)
        except botocore.exceptions.ClientError as e:
            print(e)
            pass

    print("Finished rolling back.")


def main_share_amis():
    """Main function that shares,copies, and encrypts the AMI in a new account. Also adds specified data into
    DynamoDB."""

    put_item_list = []
    ami_list = []

    try:
        share_ami()
    except botocore.exceptions.ClientError as e:
        print(e)
        print("Unable to share AMI with all accounts.")
        # revoke_ami_access() # May not be needed. Need to test how AWS handles an error here.

    for account_id in account_ids:

        # STS allows you to connect to other accounts using assumed roles.
        assumed_role = main_sts_cli.assume_rule(
            RoleArn="arn:aws:iam::%s:role/%s" % (account_id, role_name),
            RoleSessionName="AssumedRoleSession%s" % int(time.time()))

        role_credentials = assumed_role['Credentials']

        session = boto3.Session(
            aws_access_key_id=role_credentials['AccessKeyId'],
            aws_secret_access_key=role_credentials['SecretAccessKey'],
            aws_session_token=role_credentials['SessionToken'])

        sts_cli = session.client('sts')
        account_num = sts_cli.get_caller_identity().get('Account')

        # Connects to each region and copies the AMI there.
        for acc_data in config_data['Accounts']:
            if account_id == acc_data['AccountNumber']:
                for region_data in acc_data['Regions']:

                    ec2_cli = session.client('ec2', region_name=region_data)
                    dynadb_cli = session.client('dynamodb', region_name=region_data)

                    try:
                        image_description = image_details['Description']
                    except KeyError:
                        image_description = 'None'

                    try:
                        for data in config_data['Accounts']:
                            if account_id == data['AccountNumber']:
                                encrypted_ami = ec2_cli.copy_image(
                                    SourceRegion=region,
                                    SourceImageId=ami_id,
                                    Name=image_details['Name'],
                                    Description=image_description,
                                    Encrypted=True,
                                    KmsKeyId=config_data['RegionEncryptionKeys'][0][region])

                        ami_list.append({'AccountNumber': account_num,
                                         'Region': region,
                                         'AMI_ID': encrypted_ami['ImageId']})
                        print("Created encrypted AMI for %s." % data['AccountNumber'])

                    except botocore.exceptions.ClientError as e:
                        print(e)
                        rollback(amis=ami_list, put_items=put_item_list)

                    # Adds specified data to DynamoDB. This will need to be changed for each person.
                    put_items = {
                        "sourceami": ami_id,
                        "targetami": encrypted_ami['ImageId'],
                        "targetregion": region_data,
                        "targetawsaccountnum": account_num,
                        "companyaccountnum": config_data['General'][0]['CompanyAccountNumber'],
                        "releasedate": config_data['General'][0]['ReleaseDate'],
                        "amiversionnum": config_data['General'][0]['AmiVersionNumber'],
                        "stasisdate": config_data['General'][0]['StasisDate'],
                        "os": config_data['General'][0]['OS'],
                        "osver": config_data['General'][0]['OsVersion'],
                        "comments:": config_data['General'][0]['Comments'],
                        "jobnum": 'jobnum-%s' % int(time.time()),
                        "logicaldelete": 0
                    }

                    try:
                        table = dynadb_cli.Table(config_data['General'][0]['DynamoDBTable'])
                        table.put_item(put_items)
                        put_item_list.append(put_items)
                        print("Put item for %s in %s. " % (data['AccountNumber'], region_data))
                    except Exception as e:  # General exception until a more specific, not even sure if it's needed
                        print(e)
                        rollback(amis=ami_list, put_items=put_item_list)


if __name__ == '__main__':

    main_sts_cli = boto3.client('sts')
    main_ec2_cli = boto3.client('ec2')

    region = boto3.session.Session().region_name

    config_data = json_data()

    ami_id = config_data['General'][0]['AMI_ID']
    role_name = config_data['General'][0]['RoleName']
    account_ids = [account['AccountNumber'] for account in config_data['Account']]
    image_details = main_ec2_cli.describe_images(ImageIds=[ami_id])['Images'][0]

    try:
        main_share_amis()
    finally:
        revoke_ami_access()

    print("Done!")
