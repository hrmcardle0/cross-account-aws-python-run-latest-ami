import boto3
import botocore
import json
import sys
import datetime
from dateutil.tz import tzlocal

client = boto3.client('ec2')

#are we imported?
if __name__ != '__main__':
        exit(1)

#tenant-role mapping
tr_dict = {
        "tenant": {"vpc": "${Vpc-Id}", "subnet": "${Subnet-Id}", "securitygroup": "${SG-Id}", "instanceprofile": "${InstanceProfile}", "keyName": "${KeyName}" }
}

#usage info
if len(sys.argv) == 1:
        print("Start Scanner Usage: python3 run-latest.py [REQ:tenant] [REQ:vpc] [REQ:subnet-id] [REQ:security-group-id] [instance-profile] [key]")
        print("Stop Scanner Usage: python3 run-latest.py --stop [REQ:tenant] [REQ:instance-id]")
        print("Terminate Scanner Usage: python3 run-latest.py --terminate [REQ:tenant] [REQ:instance-id")
        exit(1)

if "--stop" in sys.argv and len(sys.argv) > 1:
        tenant = sys.argv[2]
        role = tr_dict[tenant]["role"]
        id = sys.argv[3]
        print("Stopping Nessus Scanner...")
        try:
                response = client.stop_instances(InstanceIds=[id])
                if response["StoppingInstances"][0]["PreviousState"]["Name"] == "stopped":
                        print("Instance is already stopped!")
                        exit(1)
        except Exception as e:
                print("Exception when stopping: {}".format(e))
                exit(1)
        print("Instance Successfully Stopped")
        exit(0)
if "--terminate" in sys.argv and len(sys.argv) > 1:
        tenant = sys.argv[2]
        role = tr_dict[tenant]["role"]
        id = sys.argv[3]
        print("Terminating Nessus Scanner {}...".format(id))
        try:
                response = client.terminate_instances(InstanceIds=[id])
                if response["TerminatingInstances"][0]["PreviousState"]["Name"] == "terminated":
                        print("Instance is already terminated!")
                        exit(1)
        except Exception as e:
                print("Exception when terminating: {}".format(e))
                exit(1)
        print("Instance Successfully Terminated")
        exit(0)

#assume role helper
assume_role_cache: dict = {}
def assumed_role_session(role_arn: str, base_session: botocore.session.Session = None):
        base_session = base_session or boto3.session.Session()._session
        fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
                client_creator = base_session.create_client,
                source_credentials = base_session.get_credentials(),
                role_arn = role_arn,
                extra_args = {
                #    'RoleSessionName': None # set this if you want something non-default
                }
        )
        creds = botocore.credentials.DeferredRefreshableCredentials(
                method = 'assume-role',
                refresh_using = fetcher.fetch_credentials,
                time_fetcher = lambda: datetime.datetime.now(tzlocal())
        )
        botocore_session = botocore.session.Session()
        botocore_session._credentials = creds
        return boto3.Session(botocore_session = botocore_session)

#get latest nessus AMI
def getLatestAmi():
        try:
                response = client.describe_images(
                        ExecutableUsers=[ 'self' ],
                        Filters=[
                                {
                                        'Name': 'name',
                                        'Values': [
                                                '*scanner*'
                                        ]
                                        #'Name': 'owner-id',
                                        #'Values': [ '859395448770' ]
                                }
                        ]
                )
        except Exception as e:
                print(e)
        ami = (sorted(response["Images"], key=lambda image: image["CreationDate"]))[-1]["ImageId"]
        return ami


#holds scanner information
class Scanner:

        def getLatestAmi(func):
                def inner(self):
                        self._ami = getLatestAmi()
                        print("Latest AMI is: {}".format(self._ami))
                        func(self)
                return inner


        def __init__(self, **kwargs):
                self._tenant = kwargs['tenant']
                self._vpc = kwargs['vpc']
                self._subnet = kwargs['subnet']
                self._sg = kwargs['sg']
                self._profile = kwargs['profile']
                self._key = kwargs['key']

        @property
        def tenant(self):
                return self._tenant

        @tenant.setter
        def tenant(self, new_tenant):
                self._tenant = new_tenant

        @property
        def vpc(self):
                return self._vpc

        @property
        def subnet(self):
                return self._subnet

        @property
        def sg(self):
                return self._sg;

        @property
        def profile(self):
                return self._profile

        @property
        def key(self):
                return self._key

        @getLatestAmi
        def runInstance(self):
                print("Starting Nessus Scanner AMI {} in {} for VPC {}...".format(self._ami, self._tenant, self._vpc))

                #assume role
                session = assumed_role_session('arn:aws-us-east-1:iam::${AccountID}:role/${RoleName}')
                ec2 = boto3.client('ec2')

                #launch instance and return id
                try:
                        response = client.run_instances(ImageId=self._ami, SubnetId=self._subnet, SecurityGroupIds=[self._sg], InstanceType='t3.medium', MinCount=1, MaxCount=1, TagSpecifications=[{'ResourceType':'instance', 'Tags': [{'Key':'Name', 'Value':'Nessus-Scanner'}]}])
                        instance_id = response["Instances"][0]["InstanceId"]
                        print("Successfully Launched Nessus Scanner. ID: {}".format(instance_id))
                except Exception as e:
                        print("Error starting instance: {}".format(e))
                        exit(1)

#parse arguments
init, tenant, vpc, subnet, sg, profile, key = [r for r in sys.argv]

#find info on tenant
scanner = Scanner(tenant=tenant, vpc=tr_dict[tenant]["vpc"], subnet=tr_dict[tenant]["subnet"], sg=tr_dict[tenant]["securitygroup"], profile=tr_dict[tenant]["role"], key=tr_dict[tenant]["keyName"])
scanner.runInstance()
