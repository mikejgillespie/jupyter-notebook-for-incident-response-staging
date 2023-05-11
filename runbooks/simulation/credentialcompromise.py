import boto3
import time
from datetime import datetime, timedelta
import string
import random
import os

pwd = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase +
                             string.digits, k=8))

usernames = ["arosalez", "adesai", "amansa", "amansa-dev", "dramirez", 
             "jdoe", "mjackson", "mmajor", "mmajor-dev", "nwolf", 
             "nwolf-dev", "rroe", "zwei"]

bucketname = 'simulation-' + ''.join(random.choices(string.ascii_lowercase +
                                 string.digits, k=18))
def simulate():

    boto3.setup_default_session()
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']

    print(f"UserId: {identity['UserId']}\nAccount: {account_id}\nAccount: {identity['Arn']}\n")

    policy = """{
        "Version": "2012-10-17",
        "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:AttachUserPolicy",
            "Resource": "arn:aws:iam::*:user/*"
        }]
    }"""


    iam_client = boto3.client('iam')


    response = iam_client.create_policy(PolicyName='dev-pol', PolicyDocument=policy)


    for username in usernames:
        try:
            response = iam_client.create_user(UserName=f"tdir-workshop-{username}")
        except:
            print(f"User tdir-workshop-{username} exists")

    for username in usernames:
        try:
            response = iam_client.attach_user_policy(
                UserName=f"tdir-workshop-{username}",
                PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
            )
        except:
            print("User already attached")

    for username in ["amansa-dev", "mmajor-dev", "nwolf-dev"]:
        response = iam_client.attach_user_policy(
            UserName=f"tdir-workshop-{username}",
            PolicyArn=f"arn:aws:iam::{account_id}:policy/dev-pol"
        )

    access_keys = []

    for username in ["amansa-dev", "mmajor-dev", "nwolf-dev"]:
        response = iam_client.create_access_key(
            UserName=f"tdir-workshop-{username}"
        )
        access_keys.append({
            "AccessKeyId": response["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": response["AccessKey"]["SecretAccessKey"]
        })

    session = boto3.session.Session(
        aws_access_key_id=access_keys[2]["AccessKeyId"],
        aws_secret_access_key=access_keys[2]["SecretAccessKey"])

    sts_client1 = session.client('sts')

    repeat_util = datetime.now() + timedelta(minutes = 1)

    print("Waiting for Access Keys", end='')

    while datetime.now() < repeat_util:
        try:
            sts_client1.get_caller_identity()
            repeat_util = datetime.now() + timedelta(minutes = -1)
        except:
            time.sleep(5)
            print('.', end='')

    print("\nUser setup complete")        

    iam_client1 = session.client("iam")
    ec2_client1 = session.client("ec2")

    try:
        iam_client1.list_roles()
    except:
        print("No Access")

    try:
        iam_client1.list_users()
    except:
        print("No Access")

    try:    
        iam_client1.list_policies()
    except:
        print("No Access")

    try:
        ec2_client1.describe_instances()
    except:
        print("No Access")

    try:
        iam_client1.attach_user_policy(UserName="tdir-workshop-nwolf-dev", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        time.sleep(10)
        print("Attached Admin to tdir-workshop-nwolf-dev")
    except:
        print("No Access: attach_user_policy1")

    try:                                  
        iam_client1.create_user(UserName="tdir-workshop-sysdev")
        print("User tdir-workshop-sysdev created.")
        time.sleep(10)
    except:
        print("No Access")

    try:                                    
        iam_client1.attach_user_policy(UserName="tdir-workshop-sysdev", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        time.sleep(10)
    except:
        print("No Access attach_user_policy")


    time.sleep(5)


    try:
        response = iam_client1.create_access_key(UserName="tdir-workshop-sysdev")
        access_keys.append({
            "AccessKeyId": response["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": response["AccessKey"]["SecretAccessKey"]
        })
    except Exception as e:
        print(f"No Access: create_access_key {e}")



    time.sleep(5)


    session2 = boto3.session.Session(
        aws_access_key_id=access_keys[3]["AccessKeyId"],
        aws_secret_access_key=access_keys[3]["SecretAccessKey"])

    sts_client2 = session2.client('sts')

    repeat_util = datetime.now() + timedelta(minutes = 1)

    print("Waiting for Access Keys", end='')

    while datetime.now() < repeat_util:
        try:
            sts_client2.get_caller_identity()
            repeat_util = datetime.now() + timedelta(minutes = -1)
        except:
            time.sleep(5)
            print(".", end='')

    print("\nSimulation 1 complete")

    ec2_client = session2.client('ec2')

    response = ec2_client.describe_images(
        Owners=["amazon"],
        Filters= [{
            "Name": "name",
            "Values": ["amzn2-ami-hvm-2.0.*"]
        },
        {
            "Name": "state",
            "Values": ["available"]
        }])

    images = sorted(response["Images"], key=lambda x: x["Name"], reverse=True)
    image1 = images[0]["ImageId"]
    image2 = images[1]["ImageId"]

    print(image1, image2)

    iam_client3 = session2.client('iam')
    ec2_client3 = session2.client('ec2')

    iam_client3.create_login_profile(
        UserName="tdir-workshop-sysdev",
        Password=pwd,
        PasswordResetRequired=True)


    ec2_client3.run_instances(
        ImageId=image1,
        InstanceType="t2.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'tdir-workshop',
                        'Value': 'test-servers'
                    }
                ]
            },
        ])

    ec2_client3.run_instances(
        ImageId=image2,
        InstanceType="t2.nano",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'tdir-workshop',
                        'Value': 'test-servers'
                    }
                ]
            },
        ])

    s3_client3 = session2.client('s3')

    create_bucket_response = s3_client3.create_bucket(ACL='private', Bucket=bucketname)

    s3_client3.put_bucket_tagging( 
        Bucket=bucketname,
        Tagging={
            "TagSet":[{"Key":"tdir-workshop","Value":"test-buckets"}]
        })

    print("Simulation 2 complete")

    iam_client3.list_users()

    try:
        response = iam_client3.create_access_key(UserName="tdir-workshop-nwolf-dev")
        access_keys.append({
            "AccessKeyId": response["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": response["AccessKey"]["SecretAccessKey"]
        })
    except Exception as e:
        print(f"No Access: create_access_key {e}")

    try:
        response = iam_client3.create_access_key(UserName="tdir-workshop-mmajor-dev")
        access_keys.append({
            "AccessKeyId": response["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": response["AccessKey"]["SecretAccessKey"]
        })
    except Exception as e:
        print(f"No Access: create_access_key {e}")

    session4 = boto3.session.Session(
        aws_access_key_id=access_keys[4]["AccessKeyId"],
        aws_secret_access_key=access_keys[4]["SecretAccessKey"])


    sts4 = session4.client('sts')
    repeat_util = datetime.now() + timedelta(minutes = 1)

    print("Waiting for Access Keys", end='')

    while datetime.now() < repeat_util:
        try:
            sts4.get_caller_identity()
            repeat_util = datetime.now() + timedelta(minutes = -1)
        except:
            time.sleep(5)
            print(".", end='')

    i = 0
    print("\nSimulation Phase 3 in Progress", end='')

    while i < 120:
        time.sleep(1)
        print('.', end='')
        i += 1

    iam_client4 = session4.client('iam')
    iam_client4.delete_access_key(
        AccessKeyId=access_keys[3]["AccessKeyId"],
        UserName="tdir-workshop-sysdev")

    iam_client4.detach_user_policy(
        UserName="tdir-workshop-sysdev",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

    iam_client4.delete_login_profile(
        UserName="tdir-workshop-sysdev")

    time.sleep(3)
    iam_client4.delete_user(UserName="tdir-workshop-sysdev")

    print(f"""
    End of Simulation

    *******************************************************************************
    *    SCENARIO: A set of AWS Access Keys have been inadvertently exposed in    *
    *    your account!                                                            *
    *                                                                             *
    *    Use your AWS skills to determine the scope of any unauthorized use       *
    *    and discover what resources need to be contained.  The 'exposed'         *
    *    Access Key ID is shown below.  Take a note of the Access Key ID for      *
    *    use during your detection activities:                                    *
    *                                                                             *
    *    Access Key ID = {access_keys[3]["AccessKeyId"]}                                     *
    *                                                                             *
    *******************************************************************************""")
    
def cleanup():
    boto3.setup_default_session()
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']

    iam_client = boto3.client('iam')

    for username in usernames:
        try:
            response = iam_client.list_attached_user_policies(UserName=f"tdir-workshop-{username}")
            for policies in response["AttachedPolicies"]:
                print(f'{policies["PolicyArn"]}')
                detach_user_policy_response = iam_client.detach_user_policy(
                        UserName=f"tdir-workshop-{username}",
                        PolicyArn=policies["PolicyArn"])
            access_key_response = iam_client.list_access_keys(UserName=f"tdir-workshop-{username}")
            for access_key in access_key_response["AccessKeyMetadata"]:
                iam_client.delete_access_key(
                    UserName=f"tdir-workshop-{username}",
                    AccessKeyId=access_key['AccessKeyId'])
                print(access_key['AccessKeyId'])
            iam_client.delete_user(UserName=f"tdir-workshop-{username}")
        except:
            print(f"user: {username} not found")
    response = iam_client.delete_policy( PolicyArn=f"arn:aws:iam::{account_id}:policy/dev-pol")

    ec2_client = boto3.client('ec2')


    instance_ids = []

    instances_result = ec2_client.describe_instances(Filters=[{"Name": "tag:tdir-workshop", "Values":["test-servers"]}])
    for reservations in instances_result["Reservations"]:
        for instances in reservations["Instances"]:
            instance_ids.append(instances["InstanceId"])

    ec2_client.terminate_instances(InstanceIds=instance_ids)

    os.system(f"aws s3 rm --recursive s3://{bucketname}")
    os.system(f"aws s3api delete-bucket --bucket {bucketname}")
    print("Cleanup Complete")