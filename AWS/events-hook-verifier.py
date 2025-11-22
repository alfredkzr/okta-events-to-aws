import json


def lambda_handler(event, context):
    """
    Handle Okta Event Hook verification challenge.
    This is called once during the initial setup to verify endpoint ownership.
    
    SECURITY NOTE: This endpoint is intentionally unauthenticated to allow Okta's
    verification process. This is expected behavior per Okta's Event Hook specification.
    The endpoint should only be accessible via GET method and should be rate-limited
    at the API Gateway level. After initial verification, this endpoint is rarely used.
    
    The verification process works as follows:
    1. Okta sends a GET request with X-Okta-Verification-Challenge header
    2. This Lambda returns the challenge value in the response
    3. Okta verifies the response matches the challenge to confirm endpoint ownership
    """
    print(f"Received verification event: {json.dumps(event)}")
    
    # Check if the "X-Okta-Verification-Challenge" header is present in the event's headers
    if 'params' in event and 'header' in event['params']:
        headers = event['params']['header']
        
        # Okta sends the header as 'X-Okta-Verification-Challenge'
        if 'X-Okta-Verification-Challenge' in headers:
            # Get the value of the "X-Okta-Verification-Challenge" header
            verification_challenge = headers['X-Okta-Verification-Challenge']
            
            print(f"Verification challenge received: {verification_challenge}")
            
            # Return the challenge in the required format
            response = {"verification": verification_challenge}
            
            print(f"Returning verification response: {json.dumps(response)}")
            return response
        else:
            print("ERROR: X-Okta-Verification-Challenge header not found in request")
            print(f"Available headers: {list(headers.keys())}")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'X-Okta-Verification-Challenge header not found'})
            }
    else:
        print("ERROR: Invalid event structure - missing 'params.header'")
        print(f"Event structure: {json.dumps(event)}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid event structure'})
        }
