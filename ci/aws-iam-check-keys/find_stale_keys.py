#!/usr/bin/env python

import boto3
import csv
from datetime import timedelta, datetime
from dateutil.parser import parse
from keys_db_models import (
	IAM_Keys,
	Event_Type,
	Event)
import keys_db_models
import os
import sys
import time
import yaml

# ENV vars/creds
#com_state_file = os.getenv('COM_STATE_FILE')
#gov_state_file = os.getenv('GOV_STATE_FILE')
com_key = os.getenv('IAM_COM_ACCESS_KEY')
com_secret = os.getenv('IAM_COM_SECRET_KEY')
gov_key = os.getenv('IAM_GOV_ACCESS_KEY')
gov_secret = os.getenv('IAM_GOV_SECRET_KEY')
create_tables_bool = os.getenv('IAM_CREATE_TABLES')
profiles_path = os.getenv('PROFILES_PATH')
com_region = "us-east-1"
gov_region = "us-gov-west-1"

# NOTE: If anything changes with the outputs in aws-admin for gov and com
# make sure the delimiter stays the same, or change the below var if it changes
# just make sure that whatever it changes to is consistent with:
# profile name prefix+delimiter+the rest of the string
#
# example:
#
# gov-stg-tool_access_key_id_stalekey -> prefix = gov-stg-tool
# the rest = tool_access_key_id_stalekey
prefix_delimiter = '_'

"""
Reference Table data structure info:
reference_table['user'] = r['user_string']
reference_table['is_wildcard'] = r['is_wildcard']
reference_table['account_type'] = r['account_type']
reference_table['alert'] = r['alert']
reference_table['warning'] = r['warn']
reference_table['violation'] = r['violation']

Credential Report columns:
user
arn
user_creation_time ISO 8601
password_enabled Boolean
password_last_used ISO 8601, N/A
password_last_changed ISO 8601, N/A
password_next_rotation ISO 8601
mfa_active Boolean
access_key_1_active Boolean
access_key_1_last_rotated ISO 8601, N/A
access_key_1_last_used_date ISO 8601, N/A
access_key_1_last_used_region String, N/A
access_key_1_last_used_service String, N/A
access_key_2_active Boolean
access_key_2_last_rotated ISO 8601, N/A
access_key_2_last_used_date ISO 8601, N/A
access_key_2_last_used_region String, N/
access_key_2_last_used_service String, N/
cert_1_active Boolean
cert_1_last_rotated ISO 8601, N/A
cert_2_active Boolean
cert_2_last_rotated ISO 8601, N/A

reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
"""
def check_retention(warn_days, violation_days, key_date):
    """
    Returns True when keys was last rotated more than :days: ago
    """
    key_date = parse(key_date, ignoretz=True)
    if key_date + timedelta(days=int(violation_days)) <= datetime.now():
        return ("violation", True)
    if key_date + timedelta(days=int(warn_days)) <= datetime.now():
        return ("warning",True)

    return (None, False)

def user_dict_for_user(user, reference_table):
    """
    Return the row in the reference table if it exists for the given user
    this helps determine if we are going to look at their keys as some accounts like break.glass etc
    are going to be ignored 
    """
    for row in reference_table:
        if (row['is_wildcard'] == "Y" and user.startswith(row['user_string'])) or user == row['user_string']:
            return row
        
def check_retention_for_key(access_key_last_rotated, user_row, alert, warn_days, violation_days):
    """
    Is the key expired or about to be? Let's warn the user and send some metrics to Prometheus
    """
    if (access_key_last_rotated != 'N/A'):
        (alert_type, expired) = check_retention(warn_days, violation_days, access_key_last_rotated)
        if (expired):
            warn_event, _ = Event_Type.insert_event_type(alert_type)
            iam_user = IAM_Keys.user_from_dict(user_row)
            event = Event.new_event_type_user(warn_event,iam_user)
            #Prometheus metrics here, like event, etc
        if (alert == 'Y'):
            # send an alert to the user here. Alternatively the alert could be in check_access_keys to 
            # cut down on the number of alerts a user gets. Right now it's rare that both keys are being used.
            # email or ??
            print("an alert will go out")

def check_access_keys(user_row, alert, warn_days, violation_days):
    """
    Check both access keys for a given user, if they both exist based on the Reference Table
    """
    
    last_rotated_key1 = user_row['access_key_1_last_rotated']
    last_rotated_key2 = user_row['access_key_2_last_rotated']
    
    if (last_rotated_key1 != 'N/A' ):
        check_retention_for_key(last_rotated_key1, user_row, alert, warn_days, violation_days)
            
    if (last_rotated_key2 != 'N/A' ):
        check_retention_for_key(last_rotated_key2, user_row, alert, warn_days, violation_days)

def check_user_thresholds(user_thresholds, report_row):
    """
    Grab the thresholds from the reference table and pass them on with the row from the credentials report to be used for checking the keys
    """
    warn_days = user_thresholds['warn']
    violation_days = user_thresholds['violation']
    
    if user_thresholds['alert'] == "N" or user_thresholds['warn'] == "" or user_thresholds['violation'] == "":
        warn_days = "60"
        violation_days = "90"
    alert = user_thresholds['alert']
    check_access_keys(report_row, alert, warn_days, violation_days)

def search_for_keys(region_name, profile, reference_table):
    """
    The main search function that reaches out to AWS IAM to grab the credentials report and read in csv
    First let's get a session based on the user access key so we can get all of the users for a given account
    """
  
    session = boto3.Session(region_name=region_name, aws_access_key_id=profile['id'], aws_secret_access_key=profile['secret'])
    iam = session.client('iam')
    
    # Generating the report is an async operation, so we wait for it by sleeping
    # If Python has an async await type of construct it would be good to use that here
    w_time = 0
    while iam.generate_credential_report()['State'] != 'COMPLETE':
        w_time = w_time + 5
        print("Waiting...{}".format(w_time))
        time.sleep(w_time)
    print("Report is ready")
    report = iam.get_credential_report()
    content = report["Content"].decode("utf-8")
    content_lines = content.split("\n")
    
    # file in .gitignore that I want to use for accounts to use here
    # also update onboard docs to say come here and add what is added here as well

    """
    Initiate the reader, convert the csv contents to a list and turn each row into a dict
    to use for the crednetials check
    """
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    not_found = []
    for row in csv_reader:
        user_name = row["user"]
        user_dict = user_dict_for_user(user_name, reference_table)
        if user_dict == None:
            not_found.append(user_name)
        else:
            check_user_thresholds(user_dict, row)
            
    # the not found users could be another Prometheus metric
    for user in not_found:
        print(user)
    # prometheus can receive file with 0, 1 or more

def state_file_to_dict(all_outputs):
    # data structure
    # {new_key = {key1:value, key2:value}}
    # Make this an env var!
    global prefix_delimiter
    output_dict = {}
    for key, value in all_outputs.items():
        profile = {}
        newDict = {}
        new_key_comps = key.split(prefix_delimiter)
        key_prefix = new_key_comps[0]
        new_key = new_key_comps[3]
        # convoluted reversal from terraform outputs - this should not stay!
        if (new_key == 'id'):
            new_key = 'secret' 
        else: 
            new_key = 'id'
        newDict[new_key] = value
        if key_prefix in output_dict:
            # one exists, lets use it!
            profile = output_dict[key_prefix]
            profile[new_key] = value
        else:
            profile[new_key] = value
            output_dict[key_prefix] = profile
    return output_dict

def load_state_files(com_state_file, gov_state_file):
    """
    Clean up yaml from state files for com and gov
    """
    
    com_file = open(com_state_file)
    gov_file = open(gov_state_file)
    com_state = yaml.safe_load(com_file)
    gov_state = yaml.safe_load(gov_file)
    all_outputs_com = com_state['terraform_outputs']
    all_outputs_gov = gov_state['terraform_outputs']
    com_state_dict = state_file_to_dict(all_outputs_com)
    gov_state_dict = state_file_to_dict(all_outputs_gov)
    return(com_state_dict, gov_state_dict)
    
def load_reference_data(csv_file_name):
    """ 
    Load the reference table to an array of dictionaries
    """
    reference_table = []
    with open(csv_file_name) as data:
        for r in csv.DictReader(data):
            reference_table.append(r)
    return reference_table

def main():
    """
    The main function that creates tables, loads the csv for the reference table and kicks off the search for stale keys
    """
    
    # grab the state files from the s3 resources
    args = sys.argv[1:]
    com_state_file = "../../../"+args[0]
    gov_state_file = "../../../"+args[1]

    # timing metrics for testing, not sure if they'll be useful later
    st_cpu_time = time.process_time()
    st = time.time()

    # Flag to create the db tables for the first run or for debugging
    if create_tables_bool == "true":
        print("creating tables...")
        keys_db_models.create_tables()
    
    # pipeline will pull in resource for the csv file so it's local
    reference_table = load_reference_data("seed_thresholds.csv")
    
    # load state files into dicts to be searched
    (com_state_dict, gov_state_dict) = load_state_files(com_state_file, gov_state_file)
    
    # also, it looks like I don't need to pass as many vars to search for keys as profiles has the key and secret region can be hard coded
    # Or I could make region and output? Ask Chris if this makes any sense, i.e. would com or gov ever have more than one region each that I would be searching?
    # Check both com and gov accounts 
    # com first
    for com_key in com_state_dict:
        print(f'searching profile {com_key}')
        search_for_keys(com_region, com_state_dict[com_key], reference_table)
    
    # now gov
    for gov_key in gov_state_dict:
        print(f'searching profile {gov_key}')
        search_for_keys(gov_region, gov_state_dict[gov_key], reference_table)

    et_cpu_time = time.process_time()
    et = time.time()
    
    # get execution time
    res = et_cpu_time - st_cpu_time
    print('CPU Execution time:', res, 'seconds')

    # get the execution time
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')


if __name__ == "__main__":
    main()

# pipeline - vars passed in for creds
# 
# create vars, etc
# 
# cf create app manifest after first push
# 
# Can be in s3 or Credhub, for concourse to pull in ENV vars
# ((blah)) - us fly get pipeline - if interpolated then s3, if not, CredHub
# prod/concourse/pipeline/
# Look at aws-broker
# 75% warning for all but customer, alert after that
# if __name__ == "__main__":
#     if not ("GATEWAY_HOST") in os.environ:
#         print("GATEWAY_HOST is required.")
#         sys.exit(1)
#
#     output = get_prometheus_metrics(db_to_storage_map())
#     prometheus_url = os.getenv("GATEWAY_HOST") + ":" + os.getenv("GATEWAY_PORT",
#                                                                  "9091") + "/metrics/job/aws_rds_storage_check"
#
#     res = requests.put(url=prometheus_url,
#                        data=output,
#                        headers={'Content-Type': 'application/octet-stream'})
#     res.raise_for_status()
#

