#!/usr/bin/env python
import boto3
import datetime
import requests
import os
import sys

# To use the allowed instance names feature, set the environment variable DISTINCT_RDS_INSTANCE_NAMES
#   Example: export DISTINCT_RDS_INSTANCE_NAMES="mydbinstance1,mydbinstance2"
#   Better yet, set it in your Concourse environment variables configuration.
# Run in test mode (metrics will be displayed but not sent)
#   export TEST=true

rds_client = boto3.client('rds')
cw_client = boto3.client('cloudwatch')

def get_db_instances():
    db_instances = []
    rds_response = rds_client.describe_db_instances()
    db_instances.extend(rds_response['DBInstances'])
    while 'Marker' in rds_response:
        rds_response = rds_client.describe_db_instances(Marker=rds_response['Marker'])
        db_instances.extend(rds_response['DBInstances'])
    return db_instances

def get_instance_tags(db_instance_arn):
    """Get tags for a specific RDS instance"""
    try:
        response = rds_client.list_tags_for_resource(ResourceName=db_instance_arn)
        return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
    except Exception as e:
        print(f"Error getting tags for {db_instance_arn}: {e}")
        return {}

def get_specific_instance_names():
    """Get list of specific instance names from environment variable"""
    # Read from environment variable, default to empty string if not set
    instance_names_str = os.getenv('DISTINCT_RDS_INSTANCE_NAMES', '')
    
    # If empty, return empty list
    if not instance_names_str:
        return []
    
    # Split by comma and strip whitespace from each name
    specific_names = [name.strip() for name in instance_names_str.split(',') if name.strip()]
    
    return specific_names

def filter_db_instances(db_instances):
    """Filter DB instances based on tags or specific names"""
    filtered_instances = []
    
    # Get specific instance names from environment variable
    specific_names = get_specific_instance_names()
    
    for db_instance in db_instances:
        db_identifier = db_instance['DBInstanceIdentifier']
        
        # Check if instance name matches specific names
        if db_identifier in specific_names:
            filtered_instances.append(db_instance)
            print(f"Found {db_identifier} in allowed specific names list.")
            continue
        
        # Get tags for the instance
        db_arn = db_instance['DBInstanceArn']
        tags = get_instance_tags(db_arn)
        
        # Check if instance has both required tags
        if 'deployment' in tags and 'stack' in tags:
            print(f"Found {db_identifier} with required tags.")
            filtered_instances.append(db_instance)
    
    return filtered_instances

def db_to_storage_map():
    # Create a map of DBInstanceIdentifier -> AllocatedStorage
    # These metrics are by default only collected in bytes, need to convert to GB
    db_to_storage = {}
    
    # Get all instances first
    all_db_instances = get_db_instances()
    
    # Filter based on your criteria
    filtered_db_instances = filter_db_instances(all_db_instances)
    
    # Create storage map only for filtered instances
    for db_instance in filtered_db_instances:
        db_to_storage[db_instance["DBInstanceIdentifier"]] = db_instance["AllocatedStorage"] * 1000000000.0
    
    return db_to_storage

def get_free_space(db_instance):
    cloudtrail_response = cw_client.get_metric_statistics(
        Namespace='AWS/RDS', 
        MetricName='FreeStorageSpace',
        Dimensions=[
            {
                'Name': 'DBInstanceIdentifier',
                'Value': db_instance
            },
        ],
        StartTime=(datetime.datetime.now() - datetime.timedelta(minutes=5)),
        EndTime=datetime.datetime.now(),
        Period=60,
        Statistics=['Average'],
    )
    try:
        free_space = min([(lambda x: x['Average'])(datapoint) for datapoint in cloudtrail_response['Datapoints']])
    except:
        # Probably a new born db, could not pull cloudwatch metrics, setting value to 10000000000 (10GB) as minimum size is 20GB
        free_space = 10000000000
        
    return free_space

def get_prometheus_metrics(db_to_storage):
    results = ""
    for db_instance in db_to_storage:
        results += 'aws_rds_disk_allocated{instance="' + db_instance + '"} ' + str(db_to_storage[db_instance]) + '\n'
        results += 'aws_rds_disk_free{instance="' + db_instance + '"} ' + str(get_free_space(db_instance)) + '\n'
    return results

def is_test_mode():
    """Check if TEST environment variable is set to 'true' (case insensitive)"""
    test_env = os.getenv('TEST', 'false').lower()
    return test_env == 'true'

if __name__ == "__main__":
    if not ("GATEWAY_HOST") in os.environ:
        print("GATEWAY_HOST is required.")
        sys.exit(1)
    
    output = get_prometheus_metrics(db_to_storage_map())
    
    # Check if we're in test mode
    if is_test_mode():
        print("\n=== TEST MODE ENABLED ===")
        print("Skipping Prometheus push. Generated metrics:")
        print("=" * 50)
        print(output)
        print("=" * 50)
        print("To send metrics to Prometheus, unset TEST or set TEST=false")
    else:
        # Normal operation - send to Prometheus
        prometheus_url = os.getenv("GATEWAY_HOST") + ":" + os.getenv("GATEWAY_PORT", "9091") + "/metrics/job/aws_rds_storage_check"
        res = requests.put(
            url=prometheus_url,
            data=output,
            headers={'Content-Type': 'application/octet-stream'}
        )
        res.raise_for_status()
        print("Metrics successfully sent to Prometheus")

# TODO - future alerts can use rds_client to alert on:
# AutoMinorVersionUpgrade
# BackupRetentionPeriod
