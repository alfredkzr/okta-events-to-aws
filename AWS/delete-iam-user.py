import boto3

def delete_user_and_dependencies(username):
    iam = boto3.client('iam')

    """
    In order to delete AWS IAM user, it's compulsory to remove the following attachments on the user account before deletion.
    Please refer to boto3 documentation on client.delete_user() for more information.
    """

    # 1. Remove user from any groups
    response = iam.list_groups_for_user(UserName=username)
    for group in response['Groups']:
        group_name = group['GroupName']
        iam.remove_user_from_group(GroupName=group_name, UserName=username)

    # 2. Detach managed policies
    attached_policies = iam.list_attached_user_policies(UserName=username)
    for policy in attached_policies['AttachedPolicies']:
        policy_arn = policy['PolicyArn']
        iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)

    # 3. Delete inline policies
    inline_policies = iam.list_user_policies(UserName=username)
    for policy_name in inline_policies['PolicyNames']:
        iam.delete_user_policy(UserName=username, PolicyName=policy_name)

    # 4. Deactivate and delete MFA devices
    mfa_devices = iam.list_mfa_devices(UserName=username)
    for device in mfa_devices['MFADevices']:
        serial_number = device['SerialNumber']
        iam.deactivate_mfa_device(UserName=username, SerialNumber=serial_number)
        iam.delete_virtual_mfa_device(SerialNumber=serial_number)

    # 5. Delete SSH public keys
    ssh_public_keys = iam.list_ssh_public_keys(UserName=username)
    for ssh_key in ssh_public_keys['SSHPublicKeys']:
        ssh_key_id = ssh_key['SSHPublicKeyId']
        iam.delete_ssh_public_key(UserName=username, SSHPublicKeyId=ssh_key_id)

    # 6. Delete signing certificates
    signing_certificates = iam.list_signing_certificates(UserName=username)
    for cert in signing_certificates['Certificates']:
        cert_id = cert['CertificateId']
        iam.delete_signing_certificate(UserName=username, CertificateId=cert_id)

    # 7. Delete access keys
    access_keys = iam.list_access_keys(UserName=username)
    for key in access_keys['AccessKeyMetadata']:
        access_key_id = key['AccessKeyId']
        iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)

    # 8. Delete the user's login profile
    try:
        iam.delete_login_profile(UserName=username)
    except iam.exceptions.NoSuchEntityException:
        pass

    # 9. Finally, delete the IAM user
    iam.delete_user(UserName=username)

def lambda_handler(event, context):

    #iterate through the events list received from Okta event hook.
    for event in event['data']['events']:
        # IAM username of the user you want to suspend
        username_to_delete = event['target'][0]['alternateId']
        print(f"Deleting {username_to_delete} IAM user")
        iam = boto3.client('iam')
        
        try:
            # Delete the IAM user
            delete_user_and_dependencies(username_to_delete)
            response = {
                'statusCode': 200,
                'body': 'IAM user deleted successfully.'
            }
            print(f"The IAM user, {username_to_delete}, has been deleted succesfully!")
        except Exception as e:
            response = {
                'statusCode': 500,
                'body': 'Error deleting IAM user: {}'.format(str(e))
            }
        
        return response
