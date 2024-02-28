#!/usr/bin/env python
import boto3
import datetime
import requests
import os
import sys

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

def db_to_storage_map():
    # Create a map of DBInstanceIdentifier -> AllocatedStorage
    # These metrics are by default only collected in bytes, need to convert to GB
    db_to_storage = {}
    for db_instance in get_db_instances():
        db_to_storage[db_instance["DBInstanceIdentifier"]] = db_instance["AllocatedStorage"] * 1000000000.0
    return db_to_storage

def get_free_space(db_instance):
    cloudtrail_response = cw_client.get_metric_statistics(Namespace='AWS/RDS', MetricName='FreeStorageSpace',
        Dimensions=[
            {
                'Name': 'DBInstanceIdentifier',
                'Value': db_instance
            },
        ],
        StartTime=(datetime.datetime.now() - datetime.timedelta(minutes=5)),
        EndTime=datetime.datetime.now(),
        Period=60,
        Statistics=['Average'],)

    try:
        free_space = min([(lambda x: x['Average'])(datapoint) for datapoint in cloudtrail_response['Datapoints']])
    except:
        #print(f'Probably a new born db, could not pull cloudwatch metrics, setting value to 100000000: {db_instance}')
        free_space = 100000000
        
    return free_space

def get_prometheus_metrics(db_to_storage):
    results = ""
    for db_instance in db_to_storage:
        results += 'aws_rds_disk_allocated{instance="' + db_instance + '"} ' + str(db_to_storage[db_instance]) + '\n'
        results += 'aws_rds_disk_free{instance="' + db_instance + '"} ' + str(get_free_space(db_instance)) + '\n'
    return results


if __name__ == "__main__":
    if not ("GATEWAY_HOST") in os.environ:
        print("GATEWAY_HOST is required.")
        sys.exit(1)

    output = get_prometheus_metrics(db_to_storage_map())
    prometheus_url = os.getenv("GATEWAY_HOST") + ":" + os.getenv("GATEWAY_PORT", "9091") + "/metrics/job/aws_rds_storage_check"

    res = requests.put(url=prometheus_url,
        data=output,
        headers={'Content-Type': 'application/octet-stream'})
    res.raise_for_status()


# TODO - future alerts can use rds_client to alert on:
# AutoMinorVersionUpgrade
# BackupRetentionPeriod
