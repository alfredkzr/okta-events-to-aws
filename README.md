# Introduction
I will show you how to integrate Okta event hooks with AWS API Gateway and process functions using Lambda. Okta workflows is great but you may know it's a very expensive feature so we will write our own code and build our infra on AWS to make this work.

# Example
We will use a simple example to demonstrate the integration between Okta and AWS.

In this scenarion, we will create an automation to suspend the AWS IAM user when Okta user is suspended. Obviously having IAM user is not exactly a good practice but you may still be using it for certain situation.

## Okta Setup
If you don't have an Okta account, you can sign up for developer account to try it out.

1. Set up event hooks
2. Verify event hook
3. Add events to event hooks endpoint

## AWS Setup
Let's create a few AWS services to make this happen.

1. AWS Lambda
-- Create 1 lambda for returning the challenge response back to Okta event hook endpoint to verify.
-- Create 1 Lambda for authorising the APIGW.
-- Create  Lambda will be the main function to process the AWS IAM user suspension.

2. AWS API Gateway
-- Create 1 REST API Gateway.
-- Create authoriser and link it to your lambda authoriser function.
-- Create resource 
-- Create ```POST``` method

3. AWS IAM
-- Create an IAM user

