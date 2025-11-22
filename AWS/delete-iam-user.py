import boto3
import json
import re
import os
from datetime import datetime
from botocore.exceptions import ClientError

def verify_user_tag(username):
    """
    Verify that the user has the required ManagedBy=Okta tag (optional check).
    This is only enforced if the IAM policy requires it. For tutorials, you can skip this.
    """
    # Optional: Uncomment to enforce tag requirement
    # iam = boto3.client('iam')
    # try:
    #     user_tags = iam.list_user_tags(UserName=username)
    #     managed_by_tag = next(
    #         (tag['Value'] for tag in user_tags.get('Tags', []) 
    #          if tag['Key'] == 'ManagedBy' and tag['Value'] == 'Okta'),
    #         None
    #     )
    #     if not managed_by_tag:
    #         raise ValueError(f"User {username} does not have required ManagedBy=Okta tag")
    #     return True
    # except ClientError as e:
    #     error_code = e.response.get('Error', {}).get('Code', 'Unknown')
    #     if error_code == 'NoSuchEntity':
    #         raise
    #     raise ValueError(f"Error verifying user tag: {error_code}")
    return True  # Skip tag check for tutorial simplicity

def validate_username(username):
    """
    Validate that the username meets AWS IAM username requirements.
    AWS IAM usernames can contain alphanumeric characters and these symbols: +=,.@-_
    """
    if not username:
        raise ValueError("Username cannot be empty")
    
    # AWS IAM username pattern
    if not re.match(r'^[\w+=,.@-]+$', username):
        raise ValueError(f"Invalid username format: {username}")
    
    # Check length (1-64 characters for IAM usernames)
    if len(username) > 64:
        raise ValueError(f"Username too long: {username}")
    
    return True

def is_protected_user(username):
    """
    Check if the user is in the protected list.
    You can also load this from environment variables or Parameter Store.
    """
    # Get protected users from environment variable (comma-separated)
    protected_users_env = os.environ.get('PROTECTED_USERS', 'admin,root,terraform,cloudformation')
    protected_users = [user.strip() for user in protected_users_env.split(',')]
    
    if username.lower() in [user.lower() for user in protected_users]:
        return True
    
    # Additional check: users without 'okta-managed' tag or specific prefix
    # You can customize this based on your naming convention
    allowed_prefix = os.environ.get('ALLOWED_USER_PREFIX', '')
    if allowed_prefix and not username.startswith(allowed_prefix):
        return True
    
    return False

def log_audit_event(username, action, status, details=""):
    """
    Log audit events for compliance and monitoring.
    You can extend this to write to DynamoDB, S3, or CloudWatch Logs Insights.
    """
    audit_log = {
        'timestamp': datetime.utcnow().isoformat(),
        'username': username,
        'action': action,
        'status': status,
        'details': details
    }
    print(f"AUDIT_LOG: {json.dumps(audit_log)}")
    
    # Optional: Write to DynamoDB for persistent audit trail
    # dynamodb = boto3.resource('dynamodb')
    # table = dynamodb.Table(os.environ.get('AUDIT_TABLE', 'okta-iam-audit-log'))
    # table.put_item(Item=audit_log)

def publish_cloudwatch_metric(metric_name, value=1):
    """
    Publish custom CloudWatch metrics for monitoring.
    """
    try:
        cloudwatch = boto3.client('cloudwatch')
        cloudwatch.put_metric_data(
            Namespace='OktaIAMIntegration',
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': 'Count',
                'Timestamp': datetime.utcnow()
            }]
        )
    except Exception as e:
        print(f"Error publishing metric {metric_name}: {e}")

def delete_user_and_dependencies(username):
    """
    Delete an IAM user and all associated dependencies.
    Each step has error handling to ensure partial failures don't stop the process.
    """
    iam = boto3.client('iam')
    errors = []

    print(f"Starting deletion process for user: {username}")

    # 1. Remove user from any groups
    try:
        response = iam.list_groups_for_user(UserName=username)
        for group in response['Groups']:
            group_name = group['GroupName']
            try:
                iam.remove_user_from_group(GroupName=group_name, UserName=username)
                print(f"Removed user from group: {group_name}")
            except Exception as e:
                error_msg = f"Error removing from group {group_name}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing groups: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 2. Detach managed policies
    try:
        attached_policies = iam.list_attached_user_policies(UserName=username)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            try:
                iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)
                print(f"Detached policy: {policy_arn}")
            except Exception as e:
                error_msg = f"Error detaching policy {policy_arn}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing attached policies: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 3. Delete inline policies
    try:
        inline_policies = iam.list_user_policies(UserName=username)
        for policy_name in inline_policies['PolicyNames']:
            try:
                iam.delete_user_policy(UserName=username, PolicyName=policy_name)
                print(f"Deleted inline policy: {policy_name}")
            except Exception as e:
                error_msg = f"Error deleting inline policy {policy_name}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing inline policies: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 4. Deactivate and delete MFA devices
    try:
        mfa_devices = iam.list_mfa_devices(UserName=username)
        for device in mfa_devices['MFADevices']:
            serial_number = device['SerialNumber']
            try:
                iam.deactivate_mfa_device(UserName=username, SerialNumber=serial_number)
                print(f"Deactivated MFA device: {serial_number}")
                # Only delete virtual MFA devices
                if 'mfa/' in serial_number:
                    iam.delete_virtual_mfa_device(SerialNumber=serial_number)
                    print(f"Deleted virtual MFA device: {serial_number}")
            except Exception as e:
                error_msg = f"Error with MFA device {serial_number}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing MFA devices: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 5. Delete SSH public keys
    try:
        ssh_public_keys = iam.list_ssh_public_keys(UserName=username)
        for ssh_key in ssh_public_keys['SSHPublicKeys']:
            ssh_key_id = ssh_key['SSHPublicKeyId']
            try:
                iam.delete_ssh_public_key(UserName=username, SSHPublicKeyId=ssh_key_id)
                print(f"Deleted SSH key: {ssh_key_id}")
            except Exception as e:
                error_msg = f"Error deleting SSH key {ssh_key_id}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing SSH keys: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 6. Delete signing certificates
    try:
        signing_certificates = iam.list_signing_certificates(UserName=username)
        for cert in signing_certificates['Certificates']:
            cert_id = cert['CertificateId']
            try:
                iam.delete_signing_certificate(UserName=username, CertificateId=cert_id)
                print(f"Deleted signing certificate: {cert_id}")
            except Exception as e:
                error_msg = f"Error deleting certificate {cert_id}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing signing certificates: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 7. Delete access keys
    try:
        access_keys = iam.list_access_keys(UserName=username)
        for key in access_keys['AccessKeyMetadata']:
            access_key_id = key['AccessKeyId']
            try:
                iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)
                print(f"Deleted access key: {access_key_id}")
            except Exception as e:
                error_msg = f"Error deleting access key {access_key_id}: {e}"
                print(error_msg)
                errors.append(error_msg)
    except Exception as e:
        error_msg = f"Error listing access keys: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 8. Delete the user's login profile
    try:
        iam.delete_login_profile(UserName=username)
        print(f"Deleted login profile for {username}")
    except iam.exceptions.NoSuchEntityException:
        print(f"No login profile found for {username}")
    except Exception as e:
        error_msg = f"Error deleting login profile: {e}"
        print(error_msg)
        errors.append(error_msg)

    # 9. Finally, delete the IAM user
    try:
        iam.delete_user(UserName=username)
        print(f"Successfully deleted IAM user: {username}")
    except Exception as e:
        error_msg = f"Error deleting user: {e}"
        print(error_msg)
        errors.append(error_msg)
        raise Exception(f"Failed to delete user {username}: {e}")
    
    if errors:
        print(f"Deletion completed with {len(errors)} errors: {errors}")
    
    return errors

def lambda_handler(event, context):
    """
    Main Lambda handler for processing Okta user suspension events.
    """
    print(f"Received event: {json.dumps(event)}")
    
    # Validate event structure
    if 'data' not in event or 'events' not in event['data']:
        error_msg = "Invalid event structure: missing 'data.events'"
        print(f"ERROR: {error_msg}")
        log_audit_event('UNKNOWN', 'VALIDATION_FAILED', 'ERROR', error_msg)
        return {
            'statusCode': 400,
            'body': json.dumps({'error': error_msg})
        }
    
    results = []
    
    # Iterate through all events in the payload
    for idx, okta_event in enumerate(event['data']['events']):
        print(f"\n--- Processing event {idx + 1} of {len(event['data']['events'])} ---")
        
        try:
            # Validate event type
            event_type = okta_event.get('eventType', '')
            print(f"Event type: {event_type}")
            
            # Only process user suspension events
            if event_type != 'user.lifecycle.suspend':
                print(f"Skipping non-suspend event: {event_type}")
                results.append({
                    'event_index': idx,
                    'status': 'skipped',
                    'reason': f'Event type {event_type} not supported'
                })
                continue
            
            # Extract username from event
            if 'target' not in okta_event or not okta_event['target']:
                raise ValueError("Event missing 'target' field")
            
            username_to_delete = okta_event['target'][0].get('alternateId', '').strip()
            
            if not username_to_delete:
                raise ValueError("Unable to extract username from event")
            
            print(f"Processing deletion for user: {username_to_delete}")
            
            # Validate username format
            validate_username(username_to_delete)
            
            # Check if user is protected
            if is_protected_user(username_to_delete):
                error_msg = f"User {username_to_delete} is protected and cannot be deleted"
                print(f"ERROR: {error_msg}")
                log_audit_event(username_to_delete, 'DELETE_ATTEMPT', 'BLOCKED', 'Protected user')
                publish_cloudwatch_metric('ProtectedUserDeletionAttempt')
                results.append({
                    'event_index': idx,
                    'username': username_to_delete,
                    'status': 'blocked',
                    'reason': 'Protected user'
                })
                continue
            
            # Check if user exists (idempotency)
            iam = boto3.client('iam')
            try:
                iam.get_user(UserName=username_to_delete)
            except iam.exceptions.NoSuchEntityException:
                print(f"User {username_to_delete} does not exist (already deleted)")
                log_audit_event(username_to_delete, 'DELETE_ATTEMPT', 'ALREADY_DELETED', 'User not found')
                results.append({
                    'event_index': idx,
                    'username': username_to_delete,
                    'status': 'already_deleted',
                    'reason': 'User does not exist'
                })
                continue
            
            # Optional: Verify user tag (commented out for tutorial simplicity)
            # Uncomment if you want to enforce the ManagedBy=Okta tag requirement
            # try:
            #     verify_user_tag(username_to_delete)
            # except ValueError as e:
            #     error_msg = f"Tag validation failed: {str(e)}"
            #     print(f"ERROR: {error_msg}")
            #     log_audit_event(username_to_delete, 'DELETE_ATTEMPT', 'BLOCKED', error_msg)
            #     publish_cloudwatch_metric('ProtectedUserDeletionAttempt')
            #     results.append({
            #         'event_index': idx,
            #         'username': username_to_delete,
            #         'status': 'blocked',
            #         'reason': 'Missing required ManagedBy=Okta tag'
            #     })
            #     continue
            
            # Log the deletion attempt
            log_audit_event(username_to_delete, 'DELETE_START', 'IN_PROGRESS', f'Okta event: {event_type}')
            
            # Delete the IAM user and dependencies
            errors = delete_user_and_dependencies(username_to_delete)
            
            # Log the result
            if not errors:
                log_audit_event(username_to_delete, 'DELETE_COMPLETE', 'SUCCESS', 'User deleted successfully')
                publish_cloudwatch_metric('IAMUserDeleted')
                results.append({
                    'event_index': idx,
                    'username': username_to_delete,
                    'status': 'success',
                    'message': 'IAM user deleted successfully'
                })
            else:
                log_audit_event(username_to_delete, 'DELETE_COMPLETE', 'PARTIAL_SUCCESS', f'{len(errors)} errors occurred')
                publish_cloudwatch_metric('IAMUserDeletedWithErrors')
                results.append({
                    'event_index': idx,
                    'username': username_to_delete,
                    'status': 'partial_success',
                    'errors': errors
                })
            
        except Exception as e:
            error_msg = f"Error processing event {idx}: {str(e)}"
            print(f"ERROR: {error_msg}")
            # Safely extract username for logging
            try:
                if 'target' in okta_event and okta_event['target'] and len(okta_event['target']) > 0:
                    username = okta_event['target'][0].get('alternateId', 'UNKNOWN')
                else:
                    username = 'UNKNOWN'
            except:
                username = 'UNKNOWN'
            log_audit_event(username, 'DELETE_FAILED', 'ERROR', error_msg)
            publish_cloudwatch_metric('IAMUserDeletionFailed')
            results.append({
                'event_index': idx,
                'username': username,
                'status': 'error',
                'error': str(e)
            })
    
    # Return summary of all processed events
    success_count = sum(1 for r in results if r['status'] == 'success')
    error_count = sum(1 for r in results if r['status'] == 'error')
    
    response = {
        'statusCode': 200 if error_count == 0 else 207,  # 207 = Multi-Status
        'body': json.dumps({
            'message': f'Processed {len(results)} events: {success_count} successful, {error_count} failed',
            'results': results
        })
    }
    
    print(f"\n=== Final Response ===")
    print(json.dumps(response, indent=2))
    
    return response
