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
# -*- coding: utf-8 -*-

from __future__ import print_function

import json
import time

import boto3
import botocore

# User must set path to the config file.
CONFIG_PATH = 'config.json'

MAIN_EC2_CLI = boto3.client('ec2')
MAIN_STS_CLI = boto3.client('sts')
MAIN_DYNA_CLI = boto3.client('dynamodb')
MAIN_DYNA_RESOURCE = boto3.resource('dynamodb')
MAIN_S3_CLI = boto3.client('s3')

REGION = boto3.session.Session().region_name


def config():
    """Grabs all data from the config file"""
    with open(CONFIG_PATH, 'r') as j:
        read_data = json.loads(j.read())

    return read_data


def recreate_image():
    """Images with EC2 BillingProduct codes cannot be copied to another AWS accounts, this creates a new image without
    an EC2 BillingProduct Code."""

    temp_instance = MAIN_EC2_CLI.run_instances(ImageId=ami_id,
                                               MinCount=1,
                                               MaxCount=1,
                                               InstanceType='t2.nano')

    try:
        MAIN_EC2_CLI.get_waiter('instance_running').wait(InstanceIds=temp_instance['Instances'][0]['ImageId'])
    except Exception as CreateInstanceErr:
        MAIN_EC2_CLI.terminate_instances(InstanceIds=temp_instance['Instances'][0]['ImageId'])
        raise CreateInstanceErr

    MAIN_EC2_CLI.create_image(InstanceId=temp_instance['Instances'][0]['InstanceId'],
                              Name='&s-%s ' % (MAIN_EC2_CLI.describe_images(ImageIds=[ami_id])['Images'][0]['Name'],
                                               int(time.time)))

    try:
        MAIN_EC2_CLI.get_waiter('image_exists').wait(ImageIds=[temp_instance['Instances'][0]['InstanceId']])
    except Exception as CreateImageErr:
        raise CreateImageErr

    MAIN_EC2_CLI.terminate_instances(InstanceIds=temp_instance['Instances'][0]['ImageId'])

    return temp_instance['Instances'][0]['ImageId']


def share_ami():
    """Adds permission for each account to be able to use the AMI."""

    print("Sharing AMI...")

    new_ami_id = ami_id
    try:
        MAIN_EC2_CLI.modify_image_attribute(
            ImageId=new_ami_id,
            OperationType='add',
            UserIds=account_ids,
            LaunchPermission={'Add': [dict(('UserId', account_number) for account_number in account_ids)]})
    except botocore.exceptions.ClientError as Err:
        print(Err.response['Error']['Code'])
        if Err.response['Error']['Code'] == 'InvalidRequest':
            new_ami_id = recreate_image()
            MAIN_EC2_CLI.modify_image_attribute(
                ImageId=new_ami_id,
                OperationType='add',
                UserIds=account_ids,
                LaunchPermission={'Add': [dict(('UserId', account_number) for account_number in account_ids)]})

        else:
            raise Err

    return new_ami_id


def revoke_ami_access():
    """Revokes access to the specified AMI."""

    print("Revoking access to AMI...")
    try:
        MAIN_EC2_CLI.modify_image_attribute(
            ImageId=ami_id,
            OperationType='remove',
            UserIds=account_ids,
            LaunchPermission={'Remove': [dict(('UserId', account_number) for account_number in account_ids)]})
    except botocore.exceptions.ClientError as Err:
        raise Err


def json_data_upload(json_data_list):
    """Creates JSON file for computer reading."""
    bucket_key = "%s/%s.json" % (config_data['General'][0]['JSON_S3keyLocation'], int(time.time()))

    for json_data in json_data_list:
        MAIN_S3_CLI.put_object(Bucket=config_data['General'][0]['JSON_S3bucket'],
                               Key=bucket_key,
                               Body=json.dumps(json_data,
                                               sort_keys=True,
                                               indent=4,
                                               separators=(',', ': ')))
    return bucket_key


def create_html_doc(ami_details_list):
    """Creates HTML document for human reading."""

    try:
        image_desc = image_details['Description']
    except KeyError:
        image_desc = 'None'

    s3_input = """
    <!DOCTYPE html>
    <html>
    <body>

    <h3>Source AMI: %s</h3>
    <h3>Name: %s</h3>
    <h3>OS: %s</h3>
    <h3>Description: %s</h3>
    <h3>Date: %s</h3>
    <h3>ARN: %s</h3>

    <p>______________________</p>
    <h3>Encrypted Root AMIs</h3>
    <p>_____________________</p>
    """ % (image_details['ImageId'],
           image_details['Name'],
           config_data['General'][0]['OS'],
           image_desc,
           config_data['General'][0]['ReleaseDate'],
           'arn:aws:ec2:%s::image/%s' % (REGION, image_details['ImageId']))

    for ami_details in ami_details_list:
        s3_input += "<p>Company_account_Number: %s | AWS_Account_Number: %s | AMI: %s" \
                    " | ARN:arn:aws:ec2:%s::image/%s</p>\n\n " % (
                        config_data['General'][0]['CompanyAccountNumber'],
                        ami_details['AccountNumber'],
                        ami_details['AMI_ID'],
                        ami_details['Region'], ami_details['AMI_ID'])

    s3_input += """
    </body>
    </html>"""

    bucket_key = "%s/%s.html" % (config_data['General'][0]['HTML_S3keyLocation'], int(time.time()))

    MAIN_S3_CLI.put_object(Bucket=config_data['General'][0]['HTML_S3bucket'],
                           Key=bucket_key,
                           Body=s3_input)

    return bucket_key


def rollback(amis, put_items, html_keys, json_keys):
    """Rollbacks all AWS actions done in case something goes wrong."""
    print("Rolling back...")
    revoke_ami_access()

    try:
        rollback_table = MAIN_DYNA_RESOURCE.Table(config_data['General'][0]['DynamoDBTable'])
        for rollback_item in put_items:
            rollback_table.delete_item(Key=rollback_item)
    except botocore.exceptions.ClientError as BotoError:
        print(BotoError)
        pass

    for html_key in html_keys:
        MAIN_S3_CLI.delete_object(Bucket=config_data['General'][0]['HTML_S3bucket'],
                                  Key=html_key)
    for json_key in json_keys:
        MAIN_S3_CLI.delete_object(Bucket=config_data['General'][0]['JSON_S3bucket'],
                                  Key=json_key)

    for rollback_account in amis:
        # STS allows you to connect to other accounts using assumed roles.

        rollback_assume_role = MAIN_STS_CLI.assume_rule(
            RoleArn="arn:aws:iam::%s:role/%s" % (rollback_account['AccountNumber'], role_name),
            RoleSessionName="AssumedRoleSession%s" % int(time.time()))

        rollback_role_credentials = rollback_assume_role['Credentials']

        rollback_session = boto3.Session(
            aws_access_key_id=rollback_role_credentials['AccessKeyId'],
            aws_secret_access_key=rollback_role_credentials['SecretAccessKey'],
            aws_session_token=rollback_role_credentials['SessionToken'])

        rollback_ec2_cli = rollback_session.client('ec2', region_name=rollback_account['Region'])

        for image_to_delete in amis:
            rollback_ec2_cli.deregister_image(ImageId=image_to_delete['AMD_ID'])

    print("Finished rolling back.")


if __name__ == '__main__':
    config_data = config()

    ami_id = config_data['General'][0]['AMI_ID']
    role_name = config_data['General'][0]['RoleName']
    account_ids = [account['AccountNumber'] for account in config_data['Accounts']]

    ami_list = []
    json_info_list = []
    put_item_list = []
    html_doc_list = []

    certain_ami_id = share_ami()

    image_details = MAIN_EC2_CLI.describe_images(ImageIds=[certain_ami_id])

    for account_id in account_ids:

        # STS allows you to connect to other accounts using assumed roles.
        assumed_role = MAIN_STS_CLI.assume_role(
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

                    try:
                        image_description = image_details['Images'][0]['Description']
                    except KeyError:
                        image_description = 'None'

                    try:
                        for data in config_data['Accounts']:
                            if account_id == data['AccountNumber']:
                                encrypted_ami = ec2_cli.copy_image(
                                    SourceRegion=REGION,
                                    SourceImageId=ami_id,
                                    Name=image_details['Images'][0]['Name'],
                                    Description=image_description,
                                    Encrypted=True,
                                    KmsKeyId=config_data['RegionEncryptionKeys'][0][REGION])

                            ami_list.append({'AccountNumber': account_num,
                                             'Region': REGION,
                                             'AMI_ID': encrypted_ami['ImageId']})
                            print("Created encrypted AMI for %s." % data['AccountNumber'])

                    except botocore.exceptions.ClientError as e:
                        print(e)
                        rollback(amis=ami_list, put_items=put_item_list, html_keys=[], json_keys=[])

                    # Gathers DB and json values
                    put_item_list.append({
                        'sourceami': ami_id,
                        'targetami': encrypted_ami['ImageId'],
                        'targetregion': region_data,
                        'targetawsaccountnum': account_num,
                        'companyaccountnum': config_data['General'][0]['CompanyAccountNumber'],
                        'releasedate': config_data['General'][0]['ReleaseDate'],
                        'amiversionnum': config_data['General'][0]['AmiVersionNumber'],
                        'stasisdate': config_data['General'][0]['StasisDate'],
                        'os': config_data['General'][0]['OS'],
                        'osver': config_data['General'][0]['OsVersion'],
                        'comments:': config_data['General'][0]['Comments'],
                        'jobnum': 'jobnum-%s' % int(time.time()),
                        'epochtime': int(time.time()),
                        'logicaldelete': 0
                    })

                    j_data = {
                        'awsaccountnumber': account_num,
                        'companyaccountnumber': config_data['General'][0]['CompanyAccountNumber'],
                        'sourceami': ami_id,
                        'targetami': encrypted_ami['ImageId'],
                        'os': config_data['General'][0]['OS'],
                        'osver': config_data['General'][0]['OsVersion'],

                    }

                    json_info_list.append(j_data)

    # Creates HTML and JSON documents
    json_data_upload(json_data_list=json_info_list)
    html_doc_list.append(create_html_doc(ami_details_list=ami_list))

    # Adds entries into a DyanomoDB database
    for put_item in put_item_list:
        try:
            table = MAIN_DYNA_RESOURCE.Table(config_data['General'][0]['DynamoDBTable'])
            table.put_item(put_item)
        except Exception as e:  # General exception until a more specific, not even sure if it's needed
            print(e)
            rollback(amis=ami_list, put_items=put_item_list, html_keys=html_doc_list, json_keys=json_doc_list)

    print("Done!")
