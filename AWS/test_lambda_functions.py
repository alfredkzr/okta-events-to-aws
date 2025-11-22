"""
Test suite for Okta Event Hook Lambda functions.
Run with: python -m pytest test_lambda_functions.py -v
Or use: python test_lambda_functions.py (for basic validation)
"""

import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

# Add current directory to path to import Lambda functions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Lambda functions (using importlib to handle hyphens in filenames)
import importlib.util

# Import api-authoriser
spec1 = importlib.util.spec_from_file_location("api_authoriser", os.path.join(os.path.dirname(__file__), "api-authoriser.py"))
api_authoriser = importlib.util.module_from_spec(spec1)
spec1.loader.exec_module(api_authoriser)
authoriser_handler = api_authoriser.lambda_handler
get_secret = api_authoriser.get_secret

# Import delete-iam-user
spec2 = importlib.util.spec_from_file_location("delete_iam_user", os.path.join(os.path.dirname(__file__), "delete-iam-user.py"))
delete_iam_user = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(delete_iam_user)
delete_user_handler = delete_iam_user.lambda_handler
validate_username = delete_iam_user.validate_username
is_protected_user = delete_iam_user.is_protected_user

# Import events-hook-verifier
spec3 = importlib.util.spec_from_file_location("events_hook_verifier", os.path.join(os.path.dirname(__file__), "events-hook-verifier.py"))
events_hook_verifier = importlib.util.module_from_spec(spec3)
spec3.loader.exec_module(events_hook_verifier)
verifier_handler = events_hook_verifier.lambda_handler


class TestEventsHookVerifier:
    """Test the Okta Event Hook verification Lambda."""
    
    def test_verification_success(self):
        """Test successful verification challenge response."""
        event = {
            'params': {
                'header': {
                    'X-Okta-Verification-Challenge': 'test-challenge-12345'
                }
            }
        }
        context = Mock()
        
        result = verifier_handler(event, context)
        
        assert result == {'verification': 'test-challenge-12345'}
        print("✓ Verification handler returns correct challenge")
    
    def test_verification_missing_header(self):
        """Test verification with missing challenge header."""
        event = {
            'params': {
                'header': {}
            }
        }
        context = Mock()
        
        result = verifier_handler(event, context)
        
        assert result['statusCode'] == 400
        assert 'error' in json.loads(result['body'])
        print("✓ Verification handler rejects missing header")
    
    def test_verification_invalid_structure(self):
        """Test verification with invalid event structure."""
        event = {}
        context = Mock()
        
        result = verifier_handler(event, context)
        
        assert result['statusCode'] == 400
        print("✓ Verification handler handles invalid structure")


class TestAPIAuthoriser:
    """Test the API Gateway authorizer Lambda."""
    
    @patch('boto3.client')
    def test_authorization_success(self, mock_boto_client):
        """Test successful authorization with valid token."""
        # Mock Secrets Manager response
        mock_secrets_client = MagicMock()
        mock_boto_client.return_value = mock_secrets_client
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'token': 'test-secret-token'})
        }
        
        event = {
            'authorizationToken': 'test-secret-token'
        }
        context = Mock()
        
        # Set environment variable
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        
        result = authoriser_handler(event, context)
        
        assert result['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        assert result['principalId'] == 'okta-event-hook'
        print("✓ Authorizer allows valid token")
    
    @patch('boto3.client')
    def test_authorization_invalid_token(self, mock_boto_client):
        """Test authorization failure with invalid token."""
        mock_secrets_client = MagicMock()
        mock_boto_client.return_value = mock_secrets_client
        mock_secrets_client.get_secret_value.return_value = {
            'SecretString': json.dumps({'token': 'correct-token'})
        }
        
        event = {
            'authorizationToken': 'wrong-token'
        }
        context = Mock()
        
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        
        result = authoriser_handler(event, context)
        
        assert result['policyDocument']['Statement'][0]['Effect'] == 'Deny'
        print("✓ Authorizer denies invalid token")
    
    def test_authorization_missing_token(self):
        """Test authorization failure with missing token."""
        event = {}
        context = Mock()
        
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        
        result = authoriser_handler(event, context)
        
        assert result['policyDocument']['Statement'][0]['Effect'] == 'Deny'
        print("✓ Authorizer denies missing token")
    
    @patch('boto3.client')
    def test_secret_retrieval_error(self, mock_boto_client):
        """Test authorization failure when secret cannot be retrieved."""
        mock_secrets_client = MagicMock()
        mock_boto_client.return_value = mock_secrets_client
        mock_secrets_client.get_secret_value.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}},
            'GetSecretValue'
        )
        
        event = {
            'authorizationToken': 'test-token'
        }
        context = Mock()
        
        os.environ['API_GATEWAY_ARN'] = 'arn:aws:execute-api:us-east-1:123456789012:abc123/*/POST/delete-iam-user'
        
        result = authoriser_handler(event, context)
        
        assert result['policyDocument']['Statement'][0]['Effect'] == 'Deny'
        print("✓ Authorizer handles secret retrieval errors")


class TestDeleteIAMUser:
    """Test the IAM user deletion Lambda."""
    
    def test_validate_username_valid(self):
        """Test username validation with valid usernames."""
        valid_usernames = [
            'user@example.com',
            'test-user-123',
            'user.name',
            'user_name',
            'user+test@example.com'
        ]
        
        for username in valid_usernames:
            assert validate_username(username) == True
        print("✓ Username validation accepts valid formats")
    
    def test_validate_username_invalid(self):
        """Test username validation with invalid usernames."""
        invalid_usernames = [
            '',  # Empty
            'a' * 65,  # Too long
            'user with spaces',  # Spaces
            'user#invalid',  # Invalid character
        ]
        
        for username in invalid_usernames:
            try:
                validate_username(username)
                assert False, f"Should have rejected: {username}"
            except ValueError:
                pass
        print("✓ Username validation rejects invalid formats")
    
    def test_is_protected_user(self):
        """Test protected user detection."""
        os.environ['PROTECTED_USERS'] = 'admin,root,terraform'
        
        assert is_protected_user('admin') == True
        assert is_protected_user('root') == True
        assert is_protected_user('terraform') == True
        assert is_protected_user('regular-user') == False
        assert is_protected_user('ADMIN') == True  # Case insensitive
        print("✓ Protected user detection works correctly")
    
    @patch('boto3.client')
    def test_delete_user_valid_event(self, mock_boto_client):
        """Test successful user deletion with valid event."""
        # Mock IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        # Mock user exists
        mock_iam.get_user.return_value = {'User': {'UserName': 'test-user@example.com'}}
        
        # Mock all deletion operations
        mock_iam.list_groups_for_user.return_value = {'Groups': []}
        mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
        mock_iam.list_user_policies.return_value = {'PolicyNames': []}
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
        mock_iam.list_ssh_public_keys.return_value = {'SSHPublicKeys': []}
        mock_iam.list_signing_certificates.return_value = {'Certificates': []}
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
        mock_iam.delete_login_profile.side_effect = mock_iam.exceptions.NoSuchEntityException()
        
        # Mock CloudWatch
        with patch('delete_iam_user.boto3.client') as mock_cw:
            mock_cw.return_value.put_metric_data.return_value = {}
            
            event = {
                'data': {
                    'events': [{
                        'eventType': 'user.lifecycle.suspend',
                        'target': [{
                            'alternateId': 'test-user@example.com'
                        }]
                    }]
                }
            }
            context = Mock()
            
            os.environ['PROTECTED_USERS'] = 'admin,root'
            
            result = delete_user_handler(event, context)
            
            assert result['statusCode'] == 200
            body = json.loads(result['body'])
            assert body['results'][0]['status'] == 'success'
            print("✓ Delete user handler processes valid event successfully")
    
    def test_delete_user_invalid_event_structure(self):
        """Test handler with invalid event structure."""
        event = {
            'invalid': 'structure'
        }
        context = Mock()
        
        result = delete_user_handler(event, context)
        
        assert result['statusCode'] == 400
        body = json.loads(result['body'])
        assert 'error' in body
        print("✓ Delete user handler rejects invalid event structure")
    
    def test_delete_user_wrong_event_type(self):
        """Test handler skips non-suspend events."""
        event = {
            'data': {
                'events': [{
                    'eventType': 'user.lifecycle.create',
                    'target': [{
                        'alternateId': 'test-user@example.com'
                    }]
                }]
            }
        }
        context = Mock()
        
        result = delete_user_handler(event, context)
        
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['results'][0]['status'] == 'skipped'
        print("✓ Delete user handler skips non-suspend events")
    
    def test_delete_user_protected_user(self):
        """Test handler blocks deletion of protected users."""
        event = {
            'data': {
                'events': [{
                    'eventType': 'user.lifecycle.suspend',
                    'target': [{
                        'alternateId': 'admin'
                    }]
                }]
            }
        }
        context = Mock()
        
        os.environ['PROTECTED_USERS'] = 'admin,root'
        
        result = delete_user_handler(event, context)
        
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['results'][0]['status'] == 'blocked'
        assert 'Protected user' in body['results'][0]['reason']
        print("✓ Delete user handler blocks protected users")


def run_basic_tests():
    """Run basic tests without pytest."""
    print("\n" + "="*60)
    print("Running Basic Lambda Function Tests")
    print("="*60 + "\n")
    
    test_classes = [
        TestEventsHookVerifier(),
        TestAPIAuthoriser(),
        TestDeleteIAMUser()
    ]
    
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        class_name = test_class.__class__.__name__
        print(f"\n--- {class_name} ---")
        
        for method_name in dir(test_class):
            if method_name.startswith('test_'):
                try:
                    method = getattr(test_class, method_name)
                    method()
                    passed += 1
                except Exception as e:
                    print(f"✗ {method_name} FAILED: {str(e)}")
                    failed += 1
                    import traceback
                    traceback.print_exc()
    
    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == '__main__':
    # Run basic tests if pytest is not available
    success = run_basic_tests()
    sys.exit(0 if success else 1)

