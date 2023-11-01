# Introduction
I will show you how to integrate Okta event hooks with AWS API Gateway and process functions using Lambda. Okta workflows is great but you may know it's a very expensive feature so we shall write our own code and build our infra on AWS to make awesome workflows.

# Example
Let's use a simple example to demonstrate the integration between Okta and AWS.

In this scenario, we will create an automation to delete the corresponding AWS IAM user when Okta user is suspended. Obviously having IAM user is not a good practice but you may still be using it for certain situation.

## Part A: AWS Setup
Let's create a few AWS services to make this happen.

1. AWS Lambda
- Create 1 Lambda for returning the challenge response back to Okta event hook endpoint to verify.
```events-hook-veriifer.py```
- Create 1 Lambda to serve as the authoriser for the APIGW.
```api-authoriser.py```
- Create 1 Lambda that will be the main function to process Okta event and also the AWS IAM user deletion.
```delete-iam-user.py```
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/lambda-functions.png)

2. AWS API Gateway
- Create 1 REST API Gateway.
- Go to Authorizers and create a new authorizer and the link to the Lambda with ```api-authoriser```. Enter authorizationToken as the Token Source.
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/api-authoriser.png)
- Create resource.

- Create ```GET``` method and then link to the Lambda with ```events-hooker-verifier```
- For the GET method, you will need to add in mapping template. Go to integration request and then under mapping template, type in 

- Create ```POST``` method and then link to the Lambda with ```delete-iam-user.py```

- Add the authorizer to your ```POST``` method which you have just created earlier.

In short, Okta events hook will perform API call GET > events-hook-verifier lambda (1 time event for verification) and POST > api-authoriser > delete-iam-user.

Example screenshot(Please ignore the resource name as I meant to create it as delete-iam-user instead of suspend-iam-user)
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/rest-api.png)

3. AWS IAM
- Create an IAM user with same Okta username for suspension demonstation.

## Part B: Okta Setup
If you don't have an Okta account, you can sign up for developer account to try it out.

1. Set up event hooks
- Go to Workflow > Event Hooks > Create Event Hook 
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/9847381deace3fee7196af974fbf45b31eadc602/Okta/okta-event-hook.png)
- Name :  Any name that makes sense
- URL : Enter the API Gateway URL
- Authentication Field : Enter ```authorizationToken```
- Authentication Secret: Enter the secret of your Lambda API Authoriser

2. Verify event hook
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/67287ef7cdeb9582243b4638f83a8602182127d4/Okta/okta-verify-event-hook.png)
- Please refer to the official docs about verifying event hook. https://developer.okta.com/docs/concepts/event-hooks/#one-time-verification-request
The way your service needs to handle this one-time verification is as follows: The request from Okta contains an HTTP header named x-okta-verification-challenge. Your service needs to read the value of that header and return it in the response body, in a JSON object named verification: that is: { "verification" : "value_from_header" }. The value_from_header is found in the request HTTP header, but you need to send it back in a JSON object.
- Ensure your APIGW (Part A1) is using the verifier Lambda that can return the challenge response code. Once it's verified, you can change it to the main Lambda function.

3. Add events to event hooks endpoint.
- For this demo, subscribe to event ```User suspended```
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/368457bd064cef0f0129080a518262b7a98b83c1/Okta/okta-event-subscription.png)

# Test it
Now create a Okta user with same username as IAM user then suspend it.
It should now automatically delete the IAM user from your AWS account.

Example screenshot from Cloudwatch logs
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/iam-user-deleted.png)

# Others
To enhance security posture, you can also opt to throttle your APIGW and add in IP restrictions to Okta only.


