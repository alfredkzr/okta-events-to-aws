import boto3

def lambda_handler(event, context):
    # Replace these with your AWS IAM credentials and region
    aws_access_key_id = 'YOUR_ACCESS_KEY'
    aws_secret_access_key = 'YOUR_SECRET_KEY'
    aws_region = 'us-east-1'  # Replace with your desired AWS region

    # IAM username of the user you want to suspend
    username_to_suspend = 'username_to_suspend'

    # Create an IAM client
    iam_client = boto3.client('iam', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    try:
        # Suspend the IAM user
        iam_client.update_login_profile(
            UserName=username_to_suspend,
            Password='TempPassword',  # Provide a temporary password
            PasswordResetRequired=True
        )

        return f'Successfully suspended IAM user: {username_to_suspend}'

    except iam_client.exceptions.NoSuchEntityException as e:
        return f'IAM user not found: {username_to_suspend}'

    except Exception as e:
        return f'An error occurred: {str(e)}'
