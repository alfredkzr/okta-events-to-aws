import json


def lambda_handler(event, context):

    # 1 - Log the event
    print('*********** The event is: ***************')
    print(event)

    # 2 - Check if the secret is correct.
    if event['authorizationToken'] == 'VeryStrongSecret123':
        auth = 'Allow'
    else:
        auth = 'Deny'

    # 3 - Construct and return the response. Please change the ARN to your APIGW POST method.
    authResponse = {"principalId": "suspend-iam-user", "policyDocument": {"Version": "2012-10-17", "Statement": [
        {"Action": "execute-api:Invoke", "Resource": ["arn:aws:execute-api:ap-southeast-1:AWS-ACCOUNT-NUMBER:pk6s3cmxr4/*/POST/suspend-iam-user"], "Effect": auth}]}}
    return authResponse
