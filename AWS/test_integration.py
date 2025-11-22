"""
Integration test script for Okta Event Hook to AWS Lambda.
This script simulates the full flow without requiring actual AWS/Okta setup.
"""

import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Lambda functions (using importlib to handle hyphens in filenames)
import importlib.util

# Import api-authoriser
spec1 = importlib.util.spec_from_file_location("api_authoriser", os.path.join(os.path.dirname(__file__), "api-authoriser.py"))
api_authoriser = importlib.util.module_from_spec(spec1)
spec1.loader.exec_module(api_authoriser)
authoriser_handler = api_authoriser.lambda_handler

# Import delete-iam-user
spec2 = importlib.util.spec_from_file_location("delete_iam_user", os.path.join(os.path.dirname(__file__), "delete-iam-user.py"))
delete_iam_user = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(delete_iam_user)
delete_user_handler = delete_iam_user.lambda_handler

# Import events-hook-verifier
spec3 = importlib.util.spec_from_file_location("events_hook_verifier", os.path.join(os.path.dirname(__file__), "events-hook-verifier.py"))
events_hook_verifier = importlib.util.module_from_spec(spec3)
spec3.loader.exec_module(events_hook_verifier)
verifier_handler = events_hook_verifier.lambda_handler


def create_mock_okta_event(username='test-user@example.com'):
    """Create a mock Okta event payload."""
    return {
        'data': {
            'events': [{
                'eventType': 'user.lifecycle.suspend',
                'target': [{
                    'alternateId': username,
                    'type': 'User',
                    'id': '00u1234567890abcdef'
                }],
                'published': '2025-01-27T12:00:00.000Z'
            }]
        }
    }


def create_mock_context():
    """Create a mock Lambda context."""
    context = Mock()
    context.function_name = 'test-function'
    context.function_version = '$LATEST'
    context.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
    context.memory_limit_in_mb = '128'
    context.aws_request_id = 'test-request-id'
    return context


def test_full_flow():
    """Test the complete flow from Okta event to IAM user deletion."""
    print("\n" + "="*70)
    print("INTEGRATION TEST: Complete Okta Event Hook Flow")
    print("="*70 + "\n")
    
    # Step 1: Test Event Hook Verification
    print("Step 1: Testing Event Hook Verification...")
    verification_event = {
        'params': {
            'header': {
                'X-Okta-Verification-Challenge': 'test-challenge-abc123'
            }
        }
    }
    
    try:
        verification_result = verifier_handler(verification_event, create_mock_context())
        assert verification_result == {'verification': 'test-challenge-abc123'}
        print("  ✓ Event hook verification successful")
    except Exception as e:
        print(f"  ✗ Event hook verification failed: {e}")
        return False
    
    # Step 2: Test API Authorizer
    print("\nStep 2: Testing API Authorizer...")
    
    # Mock Secrets Manager - need to patch at the module level
    with patch('boto3.session.Session') as mock_session:
        mock_secrets = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_secrets
        mock_secrets.get_secret_value.return_value = {
            'SecretString': json.dumps({'token': 'test-secret-token-12345'})
        }
        
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        
        # Test with valid token
        auth_event_valid = {'authorizationToken': 'test-secret-token-12345'}
        try:
            auth_result = authoriser_handler(auth_event_valid, create_mock_context())
            assert auth_result['policyDocument']['Statement'][0]['Effect'] == 'Allow'
            print("  ✓ Authorization with valid token: ALLOWED")
        except Exception as e:
            print(f"  ✗ Authorization test failed: {e}")
            return False
        
        # Test with invalid token
        auth_event_invalid = {'authorizationToken': 'wrong-token'}
        try:
            auth_result = authoriser_handler(auth_event_invalid, create_mock_context())
            assert auth_result['policyDocument']['Statement'][0]['Effect'] == 'Deny'
            print("  ✓ Authorization with invalid token: DENIED")
        except Exception as e:
            print(f"  ✗ Authorization denial test failed: {e}")
            return False
    
    # Step 3: Test IAM User Deletion Handler
    print("\nStep 3: Testing IAM User Deletion Handler...")
    
    # Mock IAM and CloudWatch
    with patch('boto3.client') as mock_boto:
        mock_iam = MagicMock()
        mock_cw = MagicMock()
        mock_cw.put_metric_data.return_value = {}
        
        def boto_client_side_effect(service_name, **kwargs):
            if service_name == 'iam':
                return mock_iam
            elif service_name == 'cloudwatch':
                return mock_cw
            return MagicMock()
        
        mock_boto.side_effect = boto_client_side_effect
        
        # Setup IAM mocks
        mock_iam.get_user.return_value = {'User': {'UserName': 'test-user@example.com'}}
        mock_iam.list_groups_for_user.return_value = {'Groups': []}
        mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
        mock_iam.list_user_policies.return_value = {'PolicyNames': []}
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
        mock_iam.list_ssh_public_keys.return_value = {'SSHPublicKeys': []}
        mock_iam.list_signing_certificates.return_value = {'Certificates': []}
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
        mock_iam.delete_login_profile.side_effect = mock_iam.exceptions.NoSuchEntityException()
        mock_iam.delete_user.return_value = {}
        
        os.environ['PROTECTED_USERS'] = 'admin,root'
        
        # Test with valid event
        okta_event = create_mock_okta_event('test-user@example.com')
        try:
            delete_result = delete_user_handler(okta_event, create_mock_context())
            assert delete_result['statusCode'] == 200
            body = json.loads(delete_result['body'])
            assert body['results'][0]['status'] == 'success'
            print("  ✓ User deletion handler processed event successfully")
            print(f"    Response: {body['message']}")
        except Exception as e:
            print(f"  ✗ User deletion test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Test with protected user
        protected_event = create_mock_okta_event('admin')
        try:
            delete_result = delete_user_handler(protected_event, create_mock_context())
            body = json.loads(delete_result['body'])
            assert body['results'][0]['status'] == 'blocked'
            print("  ✓ Protected user deletion was blocked")
        except Exception as e:
            print(f"  ✗ Protected user test failed: {e}")
            return False
        
        # Test with wrong event type
        wrong_event = {
            'data': {
                'events': [{
                    'eventType': 'user.lifecycle.create',
                    'target': [{'alternateId': 'test-user@example.com'}]
                }]
            }
        }
        try:
            delete_result = delete_user_handler(wrong_event, create_mock_context())
            body = json.loads(delete_result['body'])
            assert body['results'][0]['status'] == 'skipped'
            print("  ✓ Non-suspend events are skipped")
        except Exception as e:
            print(f"  ✗ Event type filtering test failed: {e}")
            return False
    
    print("\n" + "="*70)
    print("✓ ALL INTEGRATION TESTS PASSED")
    print("="*70 + "\n")
    return True


def test_error_scenarios():
    """Test error handling scenarios."""
    print("\n" + "="*70)
    print("ERROR SCENARIO TESTS")
    print("="*70 + "\n")
    
    context = create_mock_context()
    
    # Test missing authorization token
    print("Testing missing authorization token...")
    with patch('boto3.session.Session'):
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        result = authoriser_handler({}, context)
        assert result['policyDocument']['Statement'][0]['Effect'] == 'Deny'
        print("  ✓ Missing token correctly denied")
    
    # Test invalid event structure
    print("\nTesting invalid event structure...")
    result = delete_user_handler({'invalid': 'structure'}, context)
    assert result['statusCode'] == 400
    print("  ✓ Invalid event structure correctly rejected")
    
    # Test missing username in event
    print("\nTesting missing username in event...")
    invalid_event = {
        'data': {
            'events': [{
                'eventType': 'user.lifecycle.suspend',
                'target': []
            }]
        }
    }
    result = delete_user_handler(invalid_event, context)
    body = json.loads(result['body'])
    assert body['results'][0]['status'] == 'error'
    print("  ✓ Missing username correctly handled")
    
    print("\n✓ ALL ERROR SCENARIO TESTS PASSED\n")
    return True


if __name__ == '__main__':
    print("\n" + "="*70)
    print("OKTA EVENT HOOK TO AWS LAMBDA - INTEGRATION TEST SUITE")
    print("="*70)
    
    success = True
    
    # Run integration tests
    if not test_full_flow():
        success = False
    
    # Run error scenario tests
    if not test_error_scenarios():
        success = False
    
    if success:
        print("\n🎉 ALL TESTS PASSED! The architecture is working correctly.")
        print("\nNext steps:")
        print("1. Deploy the Lambda functions to AWS")
        print("2. Configure API Gateway with the Lambda functions")
        print("3. Set up the Okta Event Hook with your API Gateway URL")
        print("4. Test with a real Okta user suspension")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED. Please review the errors above.")
        sys.exit(1)

