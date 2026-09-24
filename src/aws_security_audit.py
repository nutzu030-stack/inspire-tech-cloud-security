import json
import os
import boto3
from botocore.exceptions import ClientError


def get_aws_clients():
    """Initializes boto3 clients, falling back to moto mock environment if no credentials exist."""
    region = 'us-east-1'
    
    # Check if credentials are set; if not, configure dummy ones for local testing
    if not os.environ.get('AWS_ACCESS_KEY_ID') and not os.path.exists(os.path.expanduser('~/.aws/credentials')):
        print('[i] No local AWS credentials found. Enabling Mock Mode (moto)...')
        os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
        os.environ['AWS_DEFAULT_REGION'] = region
        
        try:
            from moto import mock_aws
            return mock_aws(), region
        except ImportError:
            print("[!] 'moto' is not installed. Run 'pip install moto' to test offline.")
            return None, region
            
    return None, region


def load_benchmarks():
    config_path = os.path.join(
        os.path.dirname(__file__), '../config/benchmarks.json'
    )
    with open(config_path, 'r') as f:
        return json.load(f)


def audit_security_groups(config):
    print('--- Running Benchmark: Network Exposure & Open Ports ---')
    ec2 = boto3.client('ec2')
    net_config = config['benchmarks']['network_security']
    forbidden_ports = net_config['forbidden_open_ports']

    try:
        response = ec2.describe_security_groups()
        violations = 0

        for sg in response.get('SecurityGroups', []):
            sg_id = sg.get('GroupId')
            sg_name = sg.get('GroupName')

            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort', 0)

                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if from_port in forbidden_ports or from_port == 0:
                            violations += 1
                            print(
                                f'[!] VULNERABILITY FOUND: SG "{sg_name}" ({sg_id}) exposes'
                                f' forbidden port {from_port} to 0.0.0.0/0'
                            )

        if violations == 0:
            print('[+] PASSED: No forbidden ports exposed to the public internet.')
        else:
            print(
                f'[-] FAILED: Detected {violations} security group exposure'
                ' violation(s).'
            )

    except ClientError as e:
        print(f'[x] Error connecting to EC2: {e}')


def audit_s3_buckets(config):
    print('\n--- Running Benchmark: S3 Storage & Public Access ---')
    s3 = boto3.client('s3')

    try:
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            print(f'Checking bucket: {bucket_name}')

            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                block_config = public_access['PublicAccessBlockConfiguration']

                if not all(block_config.values()):
                    print(
                        f'    [!] WARNING: Bucket {bucket_name} does not fully block'
                        ' public access.'
                    )
                else:
                    print(
                        f'    [+] PASSED: Bucket {bucket_name} has strict public access'
                        ' blocks.'
                    )
            except ClientError:
                print(
                    f'    [!] WARNING: Public Access Block configuration is missing on'
                    f' {bucket_name}!'
                )

    except ClientError as e:
        print(f'[x] Error connecting to S3: {e}')


def run_audit():
    print('=== Inspire Tech Solution: Cloud Security Benchmark Tool ===\n')
    benchmark_config = load_benchmarks()
    audit_security_groups(benchmark_config)
    audit_s3_buckets(benchmark_config)
    print('\n=== Audit Execution Complete ===')


if __name__ == '__main__':
    mock_context, region = get_aws_clients()
    
    if mock_context:
        with mock_context:
            print('=== Inspire Tech Solution: Cloud Security Benchmark Tool (Mock Mode) ===\n')
            
            # --- Injected Mock Vulnerability for Presentation Demo ---
            ec2_client = boto3.client('ec2', region_name=region)
            sg_response = ec2_client.create_security_group(
                GroupName='insecure-demo-sg',
                Description='Testing security group scan for presentation'
            )
            sg_id = sg_response['GroupId']
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            print('[i] Mock environment prepared: Injected test security group with Port 22 open.\n')
            # ---------------------------------------------------------

            benchmark_config = load_benchmarks()
            audit_security_groups(benchmark_config)
            audit_s3_buckets(benchmark_config)
            print('\n=== Audit Execution Complete ===')
    else:
        run_audit()