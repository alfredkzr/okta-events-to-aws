# Introduction
I will show you how to integrate Okta event hooks with AWS API Gateway and process functions using Lambda. Okta workflows is great but you may know it's a very expensive feature so we will write our own code and build our infra on AWS to make this work.

# Example
We will use a simple example to demonstrate the integration between Okta and AWS.

In this scenarion, we will create an automation to suspend the AWS IAM user when Okta user is suspended. Obviously having IAM user is not exactly a good practice but you may still be using it for certain situation.

## Okta Setup
If you don't have an Okta account, you can sign up for developer account to try it out.

1. Set up event hooks
2. Verify event hook
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/67287ef7cdeb9582243b4638f83a8602182127d4/Okta/okta-verify-event-hook.png)
- Please refer to the official docs about verifying event hook. https://developer.okta.com/docs/concepts/event-hooks/#one-time-verification-request
The way your service needs to handle this one-time verification is as follows: The request from Okta contains an HTTP header named x-okta-verification-challenge. Your service needs to read the value of that header and return it in the response body, in a JSON object named verification: that is: { "verification" : "value_from_header" }. The value_from_header is found in the request HTTP header, but you need to send it back in a JSON object.
3. Add events to event hooks endpoint
- Subscribe to event ```User suspended```
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/368457bd064cef0f0129080a518262b7a98b83c1/Okta/okta-event-subscription.png)

## AWS Setup
Let's create a few AWS services to make this happen.

1. AWS Lambda
- Create 1 lambda for returning the challenge response back to Okta event hook endpoint to verify.
- Create 1 Lambda for authorising the APIGW.
- Create  Lambda will be the main function to process the AWS IAM user suspension.

2. AWS API Gateway
- Create 1 REST API Gateway.
- Create authoriser and link it to your lambda authoriser function.
- Create resource 
- Create ```POST``` method

3. AWS IAM
- Create an IAM user

