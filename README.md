# Running the Latest AMI in Another Account

This Python script is a prototype of a simple application that allows you to start an EC2 instance (in this case, a Vulnerability Scanner) in another account, and ensure it is the latest version. It simply uses the Boto3 library to check the latest AMI based on a string, then starts or stops that instance in another account by assume an appropriate, already-deployed role in the target account.

The script requires tweaking to fit specific environments, specifically filling in information regarding the target account, the appropriate role to assume, and the instance configuration (vpc, security-groups, subnet, instance-profile, etc).
