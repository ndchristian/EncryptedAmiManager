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
MAIN_S3_CLI = boto3.client('s3')

REGION = boto3.session.Session().region_name

STUCK_INSTANCES = []
FAILED_ACCOUNTS = []

AMI_LIST = []
JSON_INFO_LIST = []
JSON_DOC_LIST = []
PUT_ITEM_LIST = []
HTML_DOC_LIST = []


def config():
    """Grabs all data from the config file"""
    with open(CONFIG_PATH, 'r') as j:
        read_data = json.loads(j.read())

    return read_data


def create_vpc(function_ec2_cli):
    """Creates a temporary VPC"""

    try:
        print("\tCreating temporary VPC...")
        temp_vpc = function_ec2_cli.create_vpc(CidrBlock='10.0.0.0/16')
        function_ec2_cli.get_waiter('vpc_exists').wait(VpcIds=[temp_vpc['Vpc']['VpcId']])
        function_ec2_cli.get_waiter('vpc_available').wait(VpcIds=[temp_vpc['Vpc']['VpcId']])
        print("\tCreated VPC: %s" % temp_vpc['Vpc']['VpcId'])

        return temp_vpc['Vpc']['VpcId']

    except botocore.exceptions.ClientError as VpcError:
        rollback(amis=AMI_LIST,
                 put_items=PUT_ITEM_LIST,
                 html_keys=HTML_DOC_LIST,
                 json_keys=JSON_DOC_LIST,
                 error=VpcError)


def create_subnet(function_ec2_cli, funct_vpc_id):
    """Creates a temporary subnet"""
    counter = 0
    try:
        print("\tCreating temporary subnet...")
        temp_subnet = function_ec2_cli.create_subnet(VpcId=funct_vpc_id,
                                                     CidrBlock='10.0.1.0/16')
        while True:
            try:
                function_ec2_cli.get_waiter('subnet_available').wait(SubnetIds=[temp_subnet['Subnet']['SubnetId']])

                print("\tCreated subnet: %s" % temp_subnet['Subnet']['SubnetId'])
                return temp_subnet['Subnet']['SubnetId']

            except botocore.exceptions.WaiterError as subnetError:
                # Gives creating the subnet a little more time flexibility
                if counter == 5:
                    function_ec2_cli.delete_vpc(VpcId=funct_vpc_id)
                    rollback(amis=AMI_LIST,
                             put_items=PUT_ITEM_LIST,
                             html_keys=HTML_DOC_LIST,
                             json_keys=JSON_DOC_LIST,
                             error=subnetError)
                else:
                    counter += 1

        print("\tCreated subnet: %s" % temp_subnet['Subnet']['SubnetId'])

        return temp_subnet['Subnet']['SubnetId']

    except botocore.exceptions.ClientError as SubnetError:
        function_ec2_cli.delete_vpc(VpcId=funct_vpc_id)
        rollback(amis=AMI_LIST,
                 put_items=PUT_ITEM_LIST,
                 html_keys=HTML_DOC_LIST,
                 json_keys=JSON_DOC_LIST,
                 error=SubnetError)


def create_sg(function_ec2_cli, funct_vpc_id):
    """Creates a temporary security group"""
    counter = 0
    try:
        print("\tCreating temporary security group...")
        temp_sg = function_ec2_cli.create_security_group(GroupName='TempSG-%s' % int(time.time()),
                                                         Description='Temporary ami_kms_fork_manager security group',
                                                         VpcId=funct_vpc_id)

        while True:
            try:
                function_ec2_cli.describe_security_groups(GroupIds=[temp_sg['GroupId']])

                print("\tCreated temporary security group: %s" % temp_sg['GroupId'])
                return temp_sg['GroupId']

            except botocore.exceptions.ClientError as WaiterError:
                # Gives the creation of the security group a little more of a chance
                if counter == 10:
                    function_ec2_cli.delete_vpc(VpcId=funct_vpc_id)
                    rollback(amis=AMI_LIST,
                             put_items=PUT_ITEM_LIST,
                             html_keys=HTML_DOC_LIST,
                             json_keys=JSON_DOC_LIST,
                             error=WaiterError)
                else:
                    time.sleep(1)
                    counter += 1

        print("\tCreated temporary security group: %s" % temp_sg['GroupId'])

        return temp_sg['GroupId']

    # In case something goes wrong when creating a security group
    except botocore.exceptions.ClientError as SGerror:
        function_ec2_cli.delete_vpc(VpcId=funct_vpc_id)
        rollback(amis=AMI_LIST,
                 put_items=PUT_ITEM_LIST,
                 html_keys=HTML_DOC_LIST,
                 json_keys=JSON_DOC_LIST,
                 error=SGerror)


def recreate_image(ami, function_ec2_cli, securitygroup_id, funct_subnet_id, funct_account_id):
    """Images with EC2 BillingProduct codes cannot be copied to another AWS accounts, this creates a new image without
    an EC2 BillingProduct Code."""
    counter = 0
    tryagain_counter = 0

    temp_sg_details = function_ec2_cli.describe_security_groups(GroupIds=[securitygroup_id])

    while True:
        # Attempts to create a encrypted and unencrypted AMI
        try:
            print("\tCreating temporary instance...")
            temp_instance = function_ec2_cli.run_instances(ImageId=ami,
                                                           MinCount=1,
                                                           MaxCount=1,
                                                           SecurityGroupIds=[securitygroup_id],
                                                           SubnetId=funct_subnet_id,
                                                           InstanceType='t2.micro')

            function_ec2_cli.get_waiter('instance_running').wait(
                InstanceIds=[temp_instance['Instances'][0]['InstanceId']])

            print("\tInstance is now running, stopping instance...")
            function_ec2_cli.stop_instances(InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
            function_ec2_cli.get_waiter('instance_stopped').wait(
                InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
            print("\tInstance: %s has been stopped " % temp_instance['Instances'][0]['InstanceId'])

            original_image_name = function_ec2_cli.describe_images(ImageIds=[ami])['Images'][0]['Name']
            new_image_name = "%s-%s" % (original_image_name, int(time.time()))
            new_image = function_ec2_cli.create_image(InstanceId=temp_instance['Instances'][0]['InstanceId'],
                                                      Name=new_image_name[:128])

            # Checks if the new encrypted image exists and is available
            function_ec2_cli.get_waiter('image_exists').wait(ImageIds=[new_image['ImageId']])
            function_ec2_cli.get_waiter('image_available').wait(ImageIds=[new_image['ImageId']])

            status_check = function_ec2_cli.describe_images(ImageIds=[new_image['ImageId']])

            if status_check['Images'][0]['State'] != 'available':
                print("Something has gone wrong when trying to create %s" % new_image['ImageId'])
            else:
                print("\tImage: %s has been created and is available" % new_image['ImageId'])

            # Adds tags to all temporary resources such as for cost tracking purposes:
            for tag in config_data['Tags']:
                function_ec2_cli.create_tags(Resources=[temp_instance['Instances'][0]['InstanceId'],
                                                        securitygroup_id,
                                                        temp_instance['Instances'][0]['SubnetId'],
                                                        temp_sg_details['SecurityGroups'][0]['VpcId']],
                                             Tags=[{'Key': tag['TagKey'],
                                                    'Value': tag['TagValue']}])

            # Terminates and deletes all temporary resources
            try:
                function_ec2_cli.terminate_instances(InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
                function_ec2_cli.get_waiter('instance_terminated').wait(
                    InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
                function_ec2_cli.delete_security_group(GroupId=securitygroup_id)
                function_ec2_cli.delete_subnet(SubnetId=temp_instance['Instances'][0]['SubnetId'])
                function_ec2_cli.delete_vpc(VpcId=temp_sg_details['SecurityGroups'][0]['VpcId'])
            except botocore.exceptions.ClientError as DeletionError:
                print("\tSomething went wrong when deleteing temporary objects...")
                raise DeletionError

            return new_image['ImageId']

        except botocore.exceptions.ClientError as CreateInstanceErr:
            print(CreateInstanceErr.response['Error']['Code'])
            if CreateInstanceErr.response['Error']['Code'] == 'InvalidGroup.NotFound':
                tryagain_counter += 1

                if tryagain_counter == 3:
                    function_ec2_cli.delete_security_group(GroupId=securitygroup_id)
                    function_ec2_cli.delete_subnet(SubnetId=temp_instance['Instances'][0]['SubnetId'])
                    function_ec2_cli.delete_vpc(VpcId=temp_sg_details['SecurityGroups'][0]['VpcId'])
                    rollback(amis=AMI_LIST,
                             put_items=PUT_ITEM_LIST,
                             html_keys=HTML_DOC_LIST,
                             json_keys=JSON_DOC_LIST,
                             error=CreateInstanceErr)
                else:
                    print("Something when wrong. Trying again...")
                    continue


        except botocore.exceptions.WaiterError:
            function_ec2_cli.terminate_instances(InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
            try:
                function_ec2_cli.get_waiter('instance_terminated').wait(
                    InstanceIds=[temp_instance['Instances'][0]['InstanceId']])
            except botocore.exceptions.WaiterError:
                print("\tInstance: %s cannot be terminated." % temp_instance['Instances'][0]['InstanceId'])
                STUCK_INSTANCES.append(
                    {'AccountID': funct_account_id, 'InstanceID': temp_instance['Instances'][0]['InstanceId']})
            print("\tInstance is currently stuck starting up. Trying again...")

            if counter == 3:
                print("Failed to make an encrypted AMI.")
                FAILED_ACCOUNTS.append(funct_account_id)
                break
            else:
                counter += 1


def share_ami():
    """Adds permission for each account to be able to use the AMI."""

    print("Sharing AMI: %s..." % ami_id)
    share_vpc_id = create_vpc(function_ec2_cli=MAIN_EC2_CLI)
    share_subnet_id = create_subnet(function_ec2_cli=MAIN_EC2_CLI, funct_vpc_id=share_vpc_id)

    new_ami_id = recreate_image(ami=ami_id,
                                function_ec2_cli=MAIN_EC2_CLI,
                                securitygroup_id=create_sg(function_ec2_cli=MAIN_EC2_CLI,
                                                           funct_vpc_id=share_vpc_id),
                                funct_subnet_id=share_subnet_id,
                                funct_account_id='main_account')
    MAIN_EC2_CLI.modify_image_attribute(
        ImageId=new_ami_id,
        OperationType='add',
        UserIds=account_ids,
        LaunchPermission={'Add': [{'UserId': account_number} for account_number in account_ids]})

    return new_ami_id


def revoke_ami_access():
    """Revokes access to the specified AMI."""

    print("Revoking access to AMI...")
    try:
        MAIN_EC2_CLI.modify_image_attribute(
            ImageId=ami_id,
            OperationType='remove',
            UserIds=account_ids,
            LaunchPermission={'Remove': [{'UserId': account_number} for account_number in account_ids]})
    except botocore.exceptions.ClientError as ModifyImageError:
        raise ModifyImageError


def json_data_upload(json_data_list):
    """Creates JSON file for computer reading."""
    bucket_key = "%s/%s.json" % (config_data['General'][0]['JSON_S3keyLocation'], int(time.time()))

    MAIN_S3_CLI.put_object(Bucket=config_data['General'][0]['JSON_S3bucket'],
                           Key=bucket_key,
                           Body=json.dumps({'AmiInfo': json_data_list},
                                           sort_keys=True,
                                           indent=4,
                                           separators=(',', ': ')))
    print("Created JSON output: %s" % bucket_key.split("/")[-1])

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
    """ % (image_details['Images'][0]['ImageId'],
           image_details['Images'][0]['Name'],
           config_data['General'][0]['OS'],
           image_desc,
           config_data['General'][0]['ReleaseDate'],
           'arn:aws:ec2:%s::image/%s' % (REGION, image_details['Images'][0]['ImageId']))

    for ami_details in ami_details_list:
        s3_input += "<p>Company_account_Number: %s | AWS_Account_Number: %s | AMI: %s" \
                    " | Encrypted_AMI: %s  </p>\n\n " % (
                        config_data['General'][0]['CompanyAccountNumber'],
                        ami_details['AccountNumber'],
                        ami_details['AMI_ID'],
                        ami_details['Encrypted_AMI_ID'])

        s3_input += """
    </body>
    </html>"""

    bucket_key = "%s/%s.html" % (config_data['General'][0]['HTML_S3keyLocation'], int(time.time()))
    MAIN_S3_CLI.put_object(Bucket=config_data['General'][0]['HTML_S3bucket'],
                           Key=bucket_key,
                           Body=s3_input)
    print("Created HTML output: %s" % bucket_key.split("/")[-1])

    return bucket_key


def rollback(amis, put_items, html_keys, json_keys, error):
    """Rollbacks all AWS actions done in case something goes wrong."""
    print("Rolling back...")
    revoke_ami_access()

    try:
        if not put_items:
            for rollback_item in put_items:
                MAIN_DYNA_CLI.delete_item(TableName=config_data['General'][0]['DynamoDBTable'],
                                          Key=rollback_item)
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

        rollback_assume_role = MAIN_STS_CLI.assume_role(
            RoleArn="arn:aws:iam::%s:role/%s" % (rollback_account['AccountNumber'], role_name),
            RoleSessionName="AssumedRoleSession%s" % int(time.time()))

        rollback_role_credentials = rollback_assume_role['Credentials']

        rollback_session = boto3.Session(
            aws_access_key_id=rollback_role_credentials['AccessKeyId'],
            aws_secret_access_key=rollback_role_credentials['SecretAccessKey'],
            aws_session_token=rollback_role_credentials['SessionToken'])

        rollback_ec2_cli = rollback_session.client('ec2', region_name=rollback_account['Region'])

        for image_to_delete in amis:
            try:
                rollback_ec2_cli.deregister_image(ImageId=image_to_delete['AMI_ID'])
            except botocore.exceptions.ClientError as deRegisterError:
                print(deRegisterError)
                pass

    print("Finished rolling back.")
    raise error


if __name__ == '__main__':
    config_data = config()

    ami_id = config_data['General'][0]['AMI_ID']
    role_name = config_data['General'][0]['RoleName']
    account_ids = [account['AccountNumber'] for account in config_data['Accounts']]

    for bucket in [config_data['General'][0]['JSON_S3bucket'], config_data['General'][0]['HTML_S3bucket']]:
        try:
            MAIN_S3_CLI.head_bucket(Bucket=bucket)
        except botocore.exceptions.ClientError as NoBucket:
            raise NoBucket

    dynamodb = boto3.resource('dynamodb')

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
            if account_num == acc_data['AccountNumber']:
                print("%s:" % account_num)
                for region_data in acc_data['Regions']:

                    ec2_cli = session.client('ec2', region_name=region_data)

                    try:
                        image_description = image_details['Images'][0]['Description']
                    except KeyError:
                        image_description = 'None'

                    try:
                        vpc_id = create_vpc(function_ec2_cli=ec2_cli)

                        ec2_cli.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name',
                                                                       'Value': 'Temp VPC for AMI push'}])

                        subnet_id = create_subnet(function_ec2_cli=ec2_cli, funct_vpc_id=vpc_id)

                        account_ami = recreate_image(ami=certain_ami_id,
                                                     function_ec2_cli=ec2_cli,
                                                     securitygroup_id=create_sg(function_ec2_cli=ec2_cli,
                                                                                funct_vpc_id=vpc_id),
                                                     funct_subnet_id=subnet_id,
                                                     funct_account_id=account_id)

                        print("Making an encrypted copy of the AMI..")
                        encrypted_ami = ec2_cli.copy_image(
                            SourceRegion=REGION,
                            SourceImageId=account_ami,
                            Name="Encrypted-%s" % image_details['Images'][0]['Name'],
                            Description=image_description,
                            Encrypted=True,
                            KmsKeyId=config_data['RegionEncryptionKeys'][0][REGION])

                        AMI_LIST.append({'AccountNumber': account_num,
                                         'Region': REGION,
                                         'Encrypted_AMI_ID': encrypted_ami['ImageId'],
                                         'AMI_ID': account_ami})
                        print("Created encrypted AMI: %s for %s." % (encrypted_ami['ImageId'], account_id))

                        # Gathers DB and json values

                        put_item = {
                            'sourceami': ami_id,
                            'targetami': account_ami,
                            'encryptedtargetami': encrypted_ami['ImageId'],
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
                            'logicaldelete': 0}

                        PUT_ITEM_LIST.append(put_item)
                        try:
                            table = dynamodb.Table(config_data['General'][0]['DynamoDBTable'])
                            table.put_item(Item=put_item)
                        except Exception as DynaError:
                            rollback(amis=AMI_LIST, put_items=PUT_ITEM_LIST, html_keys=[], json_keys=[],
                                     error=DynaError)

                        print("Items have been added to %s" % config_data['General'][0]['DynamoDBTable'])

                        j_data = {
                            'awsaccountnumber': account_num,
                            'companyaccountnumber': config_data['General'][0]['CompanyAccountNumber'],
                            'sourceami': ami_id,
                            'targetami': account_ami,
                            'encryptedami': encrypted_ami['ImageId'],
                            'os': config_data['General'][0]['OS'],
                            'osver': config_data['General'][0]['OsVersion'],
                            'tempvpc': vpc_id,
                            'tempsubnet': subnet_id

                        }

                        JSON_INFO_LIST.append(j_data)

                    except botocore.exceptions.ClientError as e:
                        rollback(amis=AMI_LIST, put_items=PUT_ITEM_LIST, html_keys=[], json_keys=[], error=e)

# Creates HTML and JSON documents
JSON_DOC_LIST.append(json_data_upload(json_data_list=JSON_INFO_LIST))
HTML_DOC_LIST.append(create_html_doc(ami_details_list=AMI_LIST))

if FAILED_ACCOUNTS:
    print("Failed Accounts: %s" % FAILED_ACCOUNTS)
if STUCK_INSTANCES:
    print("Stuck instances: %s" % STUCK_INSTANCES)

print("Done!")
