import json
import boto3
import os
import base64
import hmac
from botocore.exceptions import ClientError

def get_secret():
    """
    Retrieve the authorization secret from AWS Secrets Manager.
    Set the SECRET_NAME environment variable in your Lambda configuration.
    The secret must be stored as JSON with a 'token' key.
    """
    secret_name = os.environ.get('SECRET_NAME', 'okta-event-hook-secret')
    region_name = os.environ.get('AWS_REGION', 'ap-southeast-1')
    
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        
        # Parse the secret (assuming it's stored as JSON with a 'token' key)
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(get_secret_value_response['SecretString'])
            return secret.get('token', secret.get('authorizationToken', ''))
        else:
            # Binary secret (less common) - convert to base64 string
            binary_secret = get_secret_value_response['SecretBinary']
            return base64.b64encode(binary_secret).decode('utf-8')
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        raise e

def lambda_handler(event, context):
    
    # 1 - Log the event (sanitized - without the authorization token)
    print('*********** The event is: ***************')
    sanitized_event = {k: v for k, v in event.items() if k != 'authorizationToken'}
    sanitized_event['authorizationToken'] = '***REDACTED***'
    print(json.dumps(sanitized_event))
    
    # 2 - Validate that authorizationToken exists
    if 'authorizationToken' not in event or not event['authorizationToken']:
        print("ERROR: Missing authorizationToken in request")
        auth = 'Deny'
    else:
        # 3 - Get the secret from AWS Secrets Manager
        try:
            expected_secret = get_secret()
            
            # 4 - Compare the tokens securely (timing-attack resistant)
            provided_token = event['authorizationToken']
            
            if hmac.compare_digest(provided_token, expected_secret):
                auth = 'Allow'
                print("Authorization successful")
            else:
                auth = 'Deny'
                print("Authorization failed: Invalid token")
        except Exception as e:
            print(f"Authorization failed with exception: {str(e)}")
            auth = 'Deny'
    
    # 5 - Construct and return the response to either allow or deny the permission to invoke the API.
    # For tutorial: You can set API_GATEWAY_ARN as an environment variable, or update the default below
    api_gateway_arn = os.environ.get(
        'API_GATEWAY_ARN',
        'arn:aws:execute-api:us-east-1:YOUR-ACCOUNT-ID:YOUR-API-ID/*/POST/delete-iam-user'
    )
    
    authResponse = {
        "principalId": "okta-event-hook",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Resource": [api_gateway_arn],
                "Effect": auth
            }]
        }
    }
    
    return authResponse
