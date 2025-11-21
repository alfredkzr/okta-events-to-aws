# Okta Event Hooks to AWS Lambda

A tutorial on integrating Okta Event Hooks with AWS Lambda to automate IAM user management.

**Use Case**: Automatically delete AWS IAM users when they are suspended in Okta.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Part A: AWS Setup](#part-a-aws-setup)
- [Part B: Okta Setup](#part-b-okta-setup)
- [Security Configuration](#security-configuration)
- [Testing](#testing)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Overview

This tutorial demonstrates how to build an event-driven integration between Okta and AWS. When a user is suspended in Okta, an event hook triggers an AWS Lambda function that automatically deletes the corresponding IAM user.

**Why build this?**
- **Demonstrate Automation**: Learn how to trigger AWS actions from Okta events
- **Event-Driven Architecture**: Understand how to build secure webhooks with API Gateway and Lambda
- **Security Automation**: Example of how to automate security responses

> **💡 Real World Context**: 
> This tutorial uses "Deleting IAM Users" as a tangible example to demonstrate the integration. In a modern production environment, you should typically use **AWS IAM Identity Center (SSO)** for workforce access rather than managing individual IAM users. 
>
> However, the **patterns** shown here (Event Hooks → API Gateway → Lambda) are applicable to many real-world scenarios, such as:
> - Triggering forensic analysis when a user reports suspicious activity
> - Rotating secrets or keys based on Okta events
> - Updating database permissions or other internal tools
> - Sending custom notifications to Slack/Teams

**What you'll build:**
1. AWS Lambda functions to process Okta events
2. API Gateway endpoint to receive event hooks
3. Secure authorization using AWS Secrets Manager
4. Audit logging and monitoring with CloudWatch

---

## Architecture

```
┌─────────────┐
│    Okta     │  Admin suspends user
│             │
└──────┬──────┘
       │ POST /delete-iam-user
       │ Header: authorizationToken
       ▼
┌─────────────────────┐
│  API Gateway        │
│  /delete-iam-user   │
└──────┬──────────────┘
       │
       ├─> GET  → events-hook-verifier.py (one-time verification)
       │
       └─> POST → api-authoriser.py (validates token)
                  │
                  └─> delete-iam-user.py (deletes IAM user)
                      │
                      ├─> Validates event type
                      ├─> Checks protected users
                      ├─> Deletes IAM user & dependencies
                      └─> Logs to CloudWatch
```

**Flow:**
1. User suspended in Okta → Event Hook triggered
2. Okta sends POST request to API Gateway
3. API Gateway calls Lambda Authorizer to validate token
4. If authorized, main Lambda processes the event
5. Lambda deletes IAM user and all dependencies
6. Audit log written to CloudWatch

---

## Prerequisites

- AWS Account with CLI configured
- Okta Admin access
- Basic knowledge of AWS Lambda and IAM
- Python 3.11+

---

## Part A: AWS Setup

### Step 1: Create Lambda Functions

We need three Lambda functions:

#### 1.1 Event Hook Verifier (One-time verification)

This Lambda handles Okta's one-time verification challenge.

**Create the function:**
```bash
cd AWS
zip events-hook-verifier.zip events-hook-verifier.py

aws lambda create-function \
    --function-name okta-events-verifier \
    --runtime python3.11 \
    --role arn:aws:iam::YOUR-ACCOUNT-ID:role/lambda-execution-role \
    --handler events-hook-verifier.lambda_handler \
    --zip-file fileb://events-hook-verifier.zip \
    --timeout 10 \
    --region us-east-1
```

#### 1.2 API Authorizer (Token validation)

This Lambda validates the authorization token from Okta.

**Create the function:**
```bash
zip api-authoriser.zip api-authoriser.py

aws lambda create-function \
    --function-name okta-api-authoriser \
    --runtime python3.11 \
    --role arn:aws:iam::YOUR-ACCOUNT-ID:role/lambda-execution-role \
    --handler api-authoriser.lambda_handler \
    --zip-file fileb://api-authoriser.zip \
    --timeout 10 \
    --environment Variables="{SECRET_NAME=okta-event-hook-secret}" \
    --region us-east-1
```

#### 1.3 Main Lambda (IAM user deletion)

This Lambda processes Okta events and deletes IAM users.

**Create the function:**
```bash
zip delete-iam-user.zip delete-iam-user.py

aws lambda create-function \
    --function-name okta-delete-iam-user \
    --runtime python3.11 \
    --role arn:aws:iam::YOUR-ACCOUNT-ID:role/lambda-execution-role \
    --handler delete-iam-user.lambda_handler \
    --zip-file fileb://delete-iam-user.zip \
    --timeout 30 \
    --environment Variables="{PROTECTED_USERS=admin,root,terraform}" \
    --region us-east-1
```

**Clean up:**
```bash
rm *.zip
cd ..
```

### Step 2: Create API Gateway

#### 2.1 Create REST API

```bash
# Create API
API_ID=$(aws apigateway create-rest-api \
    --name "Okta-Event-Hook" \
    --region us-east-1 \
    --query 'id' \
    --output text)

echo "API ID: $API_ID"

# Get root resource ID
ROOT_ID=$(aws apigateway get-resources \
    --rest-api-id $API_ID \
    --region us-east-1 \
    --query 'items[0].id' \
    --output text)

# Create resource
RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id $API_ID \
    --parent-id $ROOT_ID \
    --path-part "delete-iam-user" \
    --region us-east-1 \
    --query 'id' \
    --output text)
```

#### 2.2 Create Authorizer

```bash
AUTHORIZER_ID=$(aws apigateway create-authorizer \
    --rest-api-id $API_ID \
    --name "okta-authorizer" \
    --type TOKEN \
    --authorizer-uri "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:YOUR-ACCOUNT-ID:function:okta-api-authoriser/invocations" \
    --identity-source "method.request.header.authorizationToken" \
    --region us-east-1 \
    --query 'id' \
    --output text)

echo "Authorizer ID: $AUTHORIZER_ID"
```

#### 2.3 Create Methods

**GET method (for Okta verification):**
```bash
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --authorization-type NONE \
    --region us-east-1

# Integration with verifier Lambda
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:YOUR-ACCOUNT-ID:function:okta-events-verifier/invocations" \
    --region us-east-1
```

**POST method (for events):**
```bash
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method POST \
    --authorization-type CUSTOM \
    --authorizer-id $AUTHORIZER_ID \
    --region us-east-1

# Integration with main Lambda
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:YOUR-ACCOUNT-ID:function:okta-delete-iam-user/invocations" \
    --region us-east-1
```

#### 2.4 Deploy API

```bash
aws apigateway create-deployment \
    --rest-api-id $API_ID \
    --stage-name prod \
    --region us-east-1

echo "API URL: https://$API_ID.execute-api.us-east-1.amazonaws.com/prod/delete-iam-user"
```

**Save this URL - you'll need it for Okta configuration.**

### Step 3: Grant Lambda Permissions

Allow API Gateway to invoke your Lambda functions:

```bash
# Verifier Lambda
aws lambda add-permission \
    --function-name okta-events-verifier \
    --statement-id apigateway-get \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:us-east-1:YOUR-ACCOUNT-ID:$API_ID/*/GET/delete-iam-user"

# Authorizer Lambda
aws lambda add-permission \
    --function-name okta-api-authoriser \
    --statement-id apigateway-authorizer \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:us-east-1:YOUR-ACCOUNT-ID:$API_ID/authorizers/$AUTHORIZER_ID"

# Main Lambda
aws lambda add-permission \
    --function-name okta-delete-iam-user \
    --statement-id apigateway-post \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:us-east-1:YOUR-ACCOUNT-ID:$API_ID/*/POST/delete-iam-user"
```

---

## Part B: Okta Setup

### Step 1: Create Event Hook

1. Log in to **Okta Admin Console**
2. Go to **Workflow** → **Event Hooks**
3. Click **Create Event Hook**
4. Fill in the details:
   - **Name**: AWS IAM User Deletion
   - **URL**: `https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/delete-iam-user`
   - **Authentication field**: `authorizationToken`
   - **Authentication secret**: (you'll set this after creating the AWS secret)

### Step 2: Verify Event Hook

Click **Verify** to test the endpoint. This will:
- Send a GET request with `X-Okta-Verification-Challenge` header
- Your verifier Lambda will return the challenge
- Okta will confirm the endpoint is valid

### Step 3: Subscribe to Events

1. In the Event Hook configuration, click **Subscribe to events**
2. Select: **User suspended** (`user.lifecycle.suspend`)
3. Click **Save**

Your event hook is now active!

---

## Security Configuration

### 1. Create AWS Secrets Manager Secret

**Generate a strong secret:**
```bash
SECRET=$(openssl rand -base64 32)
echo "Generated secret: $SECRET"
```

**Store in Secrets Manager:**
```bash
aws secretsmanager create-secret \
    --name okta-event-hook-secret \
    --description "Authorization token for Okta Event Hook" \
    --secret-string "{\"token\":\"$SECRET\"}" \
    --region us-east-1
```

**Update Okta Event Hook:**
- Go back to your Event Hook in Okta
- Update **Authentication secret** with the same `$SECRET` value

### 2. Configure Environment Variables

**For api-authoriser Lambda:**
```bash
aws lambda update-function-configuration \
    --function-name okta-api-authoriser \
    --environment Variables="{SECRET_NAME=okta-event-hook-secret}" \
    --region us-east-1
```

**For delete-iam-user Lambda:**
```bash
aws lambda update-function-configuration \
    --function-name okta-delete-iam-user \
    --environment Variables="{PROTECTED_USERS=admin,root,terraform,cloudformation}" \
    --region us-east-1
```

### 3. Apply IAM Policies

The Lambda functions need appropriate IAM permissions. Use the least-privilege policies provided in `AWS/iam-policies/`.

**Update the policy files:**
1. Replace `YOUR-ACCOUNT-ID` with your AWS account ID
2. Replace `REGION` with your region (e.g., `us-east-1`)

**Apply policies:**

```bash
# For api-authoriser Lambda role
aws iam put-role-policy \
    --role-name lambda-execution-role \
    --policy-name SecretsManagerAccess \
    --policy-document file://AWS/iam-policies/api-authoriser-policy.json

# For delete-iam-user Lambda role
aws iam put-role-policy \
    --role-name lambda-execution-role \
    --policy-name IAMUserDeletion \
    --policy-document file://AWS/iam-policies/delete-iam-user-policy.json

# For events-hook-verifier Lambda role
aws iam put-role-policy \
    --role-name lambda-execution-role \
    --policy-name CloudWatchLogsAccess \
    --policy-document file://AWS/iam-policies/events-hook-verifier-policy.json
```

### 4. Tag IAM Users (Optional but Recommended)

For additional security, tag your Okta-managed IAM users:

```bash
aws iam tag-user \
    --user-name user@example.com \
    --tags Key=ManagedBy,Value=Okta
```

The IAM policy in `delete-iam-user-policy.json` restricts deletion to only users with the `ManagedBy=Okta` tag.

---

## Testing

### Create a Test IAM User

```bash
# Create test user
aws iam create-user --user-name test-okta-user@example.com

# Tag it (if using tag-based policy)
aws iam tag-user \
    --user-name test-okta-user@example.com \
    --tags Key=ManagedBy,Value=Okta

# Verify it exists
aws iam get-user --user-name test-okta-user@example.com
```

### Test the Integration

1. **Create the same user in Okta** with email: `test-okta-user@example.com`
2. **Suspend the user in Okta**
3. **Wait 5-10 seconds**
4. **Verify the IAM user was deleted:**

```bash
aws iam get-user --user-name test-okta-user@example.com
# Should return: "NoSuchEntity" error
```

### View Logs

```bash
# View recent Lambda logs
aws logs tail /aws/lambda/okta-delete-iam-user --follow --region us-east-1

# Filter for audit logs
aws logs filter-log-events \
    --log-group-name /aws/lambda/okta-delete-iam-user \
    --filter-pattern "AUDIT_LOG" \
    --start-time $(date -u -d '1 hour ago' +%s)000 \
    --region us-east-1
```

**Expected log output:**
```json
{
  "timestamp": "2025-11-21T14:30:00.000Z",
  "username": "test-okta-user@example.com",
  "action": "DELETE_COMPLETE",
  "status": "SUCCESS",
  "details": "User deleted successfully"
}
```

---

## Monitoring

### CloudWatch Metrics

The Lambda publishes custom metrics to CloudWatch:

- `IAMUserDeleted` - Successful deletions
- `IAMUserDeletionFailed` - Failed deletions
- `ProtectedUserDeletionAttempt` - Attempts to delete protected users

**View metrics:**
```bash
aws cloudwatch list-metrics \
    --namespace OktaIAMIntegration \
    --region us-east-1
```

### Set Up CloudWatch Alarms

**Create SNS topic for alerts:**
```bash
aws sns create-topic --name okta-iam-alerts --region us-east-1

TOPIC_ARN=$(aws sns list-topics \
    --query "Topics[?contains(TopicArn, 'okta-iam-alerts')].TopicArn" \
    --output text)

# Subscribe your email
aws sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol email \
    --notification-endpoint your-email@example.com
```

**Create alarm for failures:**
```bash
aws cloudwatch put-metric-alarm \
    --alarm-name okta-iam-deletion-failures \
    --alarm-description "Alert when IAM user deletion fails" \
    --metric-name IAMUserDeletionFailed \
    --namespace OktaIAMIntegration \
    --statistic Sum \
    --period 300 \
    --evaluation-periods 1 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --alarm-actions "$TOPIC_ARN" \
    --region us-east-1
```

**Create alarm for protected user attempts:**
```bash
aws cloudwatch put-metric-alarm \
    --alarm-name okta-protected-user-attempts \
    --alarm-description "Alert when protected user deletion is attempted" \
    --metric-name ProtectedUserDeletionAttempt \
    --namespace OktaIAMIntegration \
    --statistic Sum \
    --period 300 \
    --evaluation-periods 1 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --alarm-actions "$TOPIC_ARN" \
    --region us-east-1
```

### Enable API Gateway Throttling

Protect your endpoint from abuse:

```bash
aws apigateway update-stage \
    --rest-api-id $API_ID \
    --stage-name prod \
    --patch-operations \
        op=replace,path=/throttle/rateLimit,value=10 \
        op=replace,path=/throttle/burstLimit,value=20 \
    --region us-east-1
```

---

## Troubleshooting

### Issue: Okta returns 401 Unauthorized

**Cause**: Secret mismatch between AWS and Okta

**Fix:**
```bash
# Get secret from AWS
aws secretsmanager get-secret-value \
    --secret-id okta-event-hook-secret \
    --query SecretString \
    --output text

# Verify it matches what's in Okta Event Hook configuration
```

### Issue: Lambda can't access Secrets Manager

**Cause**: Missing IAM permissions

**Fix:**
```bash
# Verify Lambda execution role has Secrets Manager permissions
aws iam get-role-policy \
    --role-name lambda-execution-role \
    --policy-name SecretsManagerAccess
```

### Issue: IAM user not deleted

**Possible causes:**

1. **User doesn't exist in AWS**
   ```bash
   aws iam get-user --user-name USERNAME
   ```

2. **Username mismatch** - Ensure Okta username exactly matches IAM username

3. **User is protected**
   ```bash
   # Check protected users list
   aws lambda get-function-configuration \
       --function-name okta-delete-iam-user \
       --query 'Environment.Variables.PROTECTED_USERS'
   ```

4. **Lambda error** - Check logs:
   ```bash
   aws logs tail /aws/lambda/okta-delete-iam-user --since 10m
   ```

### Issue: Event Hook verification fails

**Cause**: GET method not configured correctly

**Fix:**
- Ensure GET method is linked to `okta-events-verifier` Lambda
- Check Lambda logs for errors
- Verify API Gateway has permission to invoke the Lambda

---

## What Gets Deleted?

When a user is deleted, the Lambda removes:

- ✅ User from all IAM groups
- ✅ All attached managed policies
- ✅ All inline policies
- ✅ All MFA devices
- ✅ All SSH public keys
- ✅ All signing certificates
- ✅ All access keys
- ✅ Login profile (console password)
- ✅ The IAM user itself

**Note**: If any step fails, the Lambda continues with remaining steps and logs all errors.

---

## Security Features

### Input Validation
- Username format validation (AWS IAM requirements)
- Length validation (1-64 characters)
- Character whitelist (alphanumeric + `+=,.@-_`)
- Event type validation (only `user.lifecycle.suspend`)

### Protected Users
Configure users that should never be deleted:
```bash
PROTECTED_USERS=admin,root,terraform,cloudformation
```

### Audit Logging
All actions are logged with:
- Timestamp
- Username
- Action (DELETE_START, DELETE_COMPLETE, etc.)
- Status (SUCCESS, ERROR, BLOCKED)
- Details (error messages, etc.)

### Idempotency
The Lambda handles retries gracefully - if a user is already deleted, it logs it and continues without error.

### Error Handling
Each deletion step has its own error handling. If one step fails, the Lambda continues with remaining steps.

---

## Advanced Configuration

### Prefix-Based Filtering

Only allow deletion of users with a specific prefix:

```bash
aws lambda update-function-configuration \
    --function-name okta-delete-iam-user \
    --environment Variables="{PROTECTED_USERS=admin,root,ALLOWED_USER_PREFIX=okta-}"
```

### DynamoDB Audit Trail (Optional)

Store audit logs in DynamoDB for long-term retention:

```bash
# Create table
aws dynamodb create-table \
    --table-name okta-iam-audit-log \
    --attribute-definitions \
        AttributeName=username,AttributeType=S \
        AttributeName=timestamp,AttributeType=S \
    --key-schema \
        AttributeName=username,KeyType=HASH \
        AttributeName=timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1

# Update Lambda environment
aws lambda update-function-configuration \
    --function-name okta-delete-iam-user \
    --environment Variables="{PROTECTED_USERS=admin,root,AUDIT_TABLE=okta-iam-audit-log}"
```

---

## Scaling Considerations

Okta has a limited number of event hook endpoints. To scale this integration:

1. **Multiple event types**: Process different event types in the same Lambda
2. **Step Functions**: Orchestrate complex workflows
3. **Amazon EventBridge**: Route events to different services
4. **Amazon SQS**: Queue events for asynchronous processing

---

## Cost Estimate

**AWS Free Tier eligible:**
- Lambda: 1M requests/month free
- API Gateway: 1M requests/month free (first 12 months)
- Secrets Manager: $0.40/month per secret
- CloudWatch Logs: 5GB ingestion free

**Estimated monthly cost**: ~$1-2/month (after free tier)

---

## Resources

- [Okta Event Hooks Documentation](https://developer.okta.com/docs/concepts/event-hooks/)
- [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [AWS API Gateway](https://docs.aws.amazon.com/apigateway/)

---

## License

MIT License - Feel free to use and modify for your needs.

---

## Contributing

Found an issue or have a suggestion? Open an issue or pull request!