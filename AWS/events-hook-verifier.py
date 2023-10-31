import json


def lambda_handler(event, context):
    # Check if the "X-Okta-Verification-Challenge" header is present in the event's headers
    if 'params' in event and 'header' in event['params']:
        headers = event['params']['header']
        if 'X-Okta-Verification-Challenge' in headers:
            # Get the value of the "X-Okta-Verification-Challenge" header
            verification_challenge = headers['X-Okta-Verification-Challenge']
            response = {"verification": verification_challenge}

            return response
