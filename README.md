# Introduction
I will show you how to integrate Okta event hooks with AWS API Gateway and process functions using Lambda. Okta workflows is great but you may know it's an expensive feature to add so we shall write our own code and build our infra on AWS to make cool workflows.

# Example
Let's use a simple example to demonstrate the integration between Okta and AWS.

In this demo, we will create an automation to delete the corresponding AWS IAM user when Okta user is suspended (e.g. demo-user@gmail.com is suspended in Okta, delete demo-user@gmail.com AWS IAM user). Having IAM user is not a good practice but in your organisation, you may still be using it for certain situation which require long-lived API keys etc so it's important to revoke user access.

## Part A: AWS Setup
Let's create a few AWS services to make this happen.

1. AWS Lambda
- Create 1 Lambda for returning the challenge response back to Okta event hook endpoint to verify.
```events-hook-veriifer.py```
- Create 1 Lambda to serve as a simple authoriser for the APIGW.
```api-authoriser.py```
- Create 1 Lambda that will be the main function to process Okta event and also the AWS IAM user deletion.

Okta event hook sends a list containing different events in same JSON payload within a single API call when there are multiple same events you've subscribed happening at the same time so it's required to iterate through the events to process them accordingly.
```delete-iam-user.py```
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/lambda-functions.png)

2. AWS API Gateway
- Create 1 REST API Gateway.
- Go to Authorizers and create a new authorizer and the link to the Lambda with ```api-authoriser```. Enter ```authorizationToken``` as the Token Source.
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/api-authoriser.png)
- Create resource as ```delete-iam-user``` or anything that is relevant. You will be calling the API with the the resource.
- Within the resource you have created earlier, you will need to create 2 methods.
- Firstly, create ```GET``` method and then link to the Lambda with ```events-hooker-verifier```. This GET method will be used only once for verifiying the okta event hook endpoint.
- In the same the GET method you have just created, you will need to add in mapping template to get the headers. Go to integration request and then under mapping template, type in ```application/json```. Generate template > Method request passthrough.

![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/b1939c7193cc27a208387109923a207cd7bebc81/AWS/screenshots/mapping-template.png)

- Secondly, create ```POST``` method and then link to the Lambda with ```delete-iam-user.py```. This is the main backend function that will process the IAM user deletion automatically based on the incoming Okta event payload.

- Within the same method, add the authorizer to your ```POST``` method which you have just created earlier.

In short, Okta event hook will perform API call for following.
1. Okta > Verify Endpoint Ownership > GET > events-hook-verifier lambda (1 time event for verification) 
2. Okta > Suspend user > POST > api-authoriser > delete-iam-user.

Example screenshot(Please ignore the resource name as I meant to create it as delete-iam-user instead of suspend-iam-user)
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/rest-api.png)

3. AWS IAM
- Create an IAM user with same Okta username for deletion demonstation.

## Part B: Okta Setup

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
- For this demo, subscribe to event ```User suspended```.
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/368457bd064cef0f0129080a518262b7a98b83c1/Okta/okta-event-subscription.png)

# Test it
Now create an Okta user with same username as IAM user then suspend it.
It should now automatically delete the IAM user from your AWS account.

Sample screenshot from Cloudwatch logs to verify that the IAM user has been deleted.
![alt text](https://github.com/alfredkzr/okta-events-to-aws/blob/68bb9c0f10198ce06562e761fec22fb306f17357/AWS/screenshots/iam-user-deleted.png)

# Others
There's finite amount of event hook endpoint you can add in Okta so it's important to plan out how many event hook endpoint you would like to add in order to scale it efficiently. Obviously, you can only enter 1 URL for event hook so in the event that you need to have multiple microservices to process your workflow, you may end up with a more complex architecture or codebase such as processing it with different Lambdas based on eventType, step functions, or simply expanding your code logic.

To elevate security posture, you may also throttle your APIGW and add in IP restrictions to Okta only.