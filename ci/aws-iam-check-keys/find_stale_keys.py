#!/usr/bin/env python

import json
import requests
import boto3
import csv
from datetime import date, timedelta, datetime
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

# Debug stuff
key1 = 0
key2 = 0
prometheus_alerts = ""


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
    Returns True when keys was last rotated more than :days: ago by returning a warning type or None
    """
    key_date = parse(key_date, ignoretz=True)
    if key_date + timedelta(days=int(violation_days)) <= datetime.now():
        return "violation"
    if key_date + timedelta(days=int(warn_days)) <= datetime.now():
        return "warning"
    return None

def find_known_user(report_user, all_users_dict):
    """
    Return the row from the users list matching the report user if it exists, this will
    be used for validating thresholds for the key rotation date timeframes
    """

    user_dict = {}
    for an_user_dict in all_users_dict:
        if an_user_dict['user'] in report_user:
            user_dict = an_user_dict
            break
    if not user_dict:
        print(f'User {report_user} not found')

    return user_dict

def event_exists(events, access_key_num):
    """
    Look for an access key rotation based on key number (1 or 2) corresponding
    to the number of access keys a user might have.
    If the same event and key number are found, return the event
    """
    foundEvent = None
    for event in events:
        if (event.access_key_num == access_key_num):
            foundEvent = event
            break
    return foundEvent

def check_retention_for_key(access_key_last_rotated, access_key_num, user_row, warn_days, violation_days, alert):
    """
    Is the key expired or about to be? Let's warn the user and record some metrics to send to Prometheus
    """
    global prometheus_alerts, key1, key2

    if (access_key_last_rotated != 'N/A'):
        alert_type = check_retention(warn_days, violation_days, access_key_last_rotated)
        iam_user = IAM_Keys.user_from_dict(user_row)

        print(f'alert_type: {alert_type}')
        # check that we have a stale key of some kind
        if (alert_type):
            # verify we don't already have an alert!
            events = iam_user.events
            found_event = event_exists(events, access_key_num)
            print(f'found_event: {found_event}')
            event_type, _ = Event_Type.insert_event_type(alert_type)
            scrubbed_arn = user_row["arn"].split(':')[4][-4:]

            if not found_event: 
                # since we don't have an event for this key already, create a new one
                # and create an alert to send to prometheus and add it to the list of alerts
                # some debug code to verify keys being used
                event = Event.new_event_type_user(event_type,iam_user, access_key_num)
                if access_key_num == 1:
                    key1 += 1
                elif access_key_num == 2:
                    key2 += 1

                # create the alert for prometheus (print out for debug purposes)
                # since this is new the alert_sent is set to false. Once an alert is cleared it will be set to true
                time_stamp = time.time()
                # stale_key_num {user="cg-broker-***", alert_type="violation", key="1", last_rotated="2022-12-21T163027+0000"} 1
                if user_row['user'] == "cg-s3-7d693173-0e30-4768-86df-d376a50b41d7":
                    print(f'MARKED_HERE ==== stale_key_num User: {user_row["user"]}-{scrubbed_arn} has an alert of type {alert_type} as the key number {access_key_num} was last rotated: {access_key_last_rotated} 0\n')
                    prometheus_alerts += f'stale_key_num {{user=\"{user_row["user"]}-{scrubbed_arn}\", alert_type=\"{alert_type}\", key=\"{access_key_num}\", last_rotated=\"{access_key_last_rotated}\"}} 0\n'
                else:
                    print(f'stale_key_num 1 User: {user_row["user"]}-{scrubbed_arn} has an alert of type {alert_type} as the key number {access_key_num} was last rotated: {access_key_last_rotated}\n')
                    prometheus_alerts += f'stale_key_num {{user=\"{user_row["user"]}-{scrubbed_arn}\", alert_type=\"{alert_type}\", key=\"{access_key_num}\", last_rotated=\"{access_key_last_rotated}\"}} 1\n'
                event.alert_sent = False
                event.save()
            else:
                # found, so let's update the type
                found_event.set_event_type(event_type)
                new_event_type = Event_Type.get(Event_Type.event_type_name == event_type)
                found_event.event_type = new_event_type
                found_event.save()
                prometheus_alerts += f'stale_key_num {{user=\"{user_row["user"]}-{scrubbed_arn}\", alert_type=\"{alert_type}\", key=\"{access_key_num}\", last_rotated=\"{access_key_last_rotated}\"}} 0\n'

        elif alert_type == None:
            for event in iam_user.events:
                event.cleared = True
                event.cleared_date = date.now()
                # I really don't like this and want to move it somewhere else but lets get it
                # working first
                event.alert_sent = True
                event.save()
                if alert:
                    print(f'stale_key_num 1 User: {user_row["user"]}-{scrubbed_arn} has an alert of type {alert_type} as the key number {access_key_num} was last rotated: {access_key_last_rotated}\n')
                    prometheus_alerts += f'stale_key_num {{\"user={user_row["user"]}-{scrubbed_arn}\", alert_type=\"{alert_type}\", key=\"{access_key_num}\", last_rotated=\"{access_key_last_rotated}\"}} 1\n'

def check_access_keys(user_row, warn_days, violation_days, alert):
    """
    Validate key staleness for both access keys, provided they exist, for a given user
    """
    global key1, key2

    last_rotated_key1 = user_row['access_key_1_last_rotated']
    last_rotated_key2 = user_row['access_key_2_last_rotated']

    if (last_rotated_key1 != 'N/A' ):
        check_retention_for_key(last_rotated_key1, 1, user_row, warn_days, violation_days, alert)

    if (last_rotated_key2 != 'N/A' ):
        check_retention_for_key(last_rotated_key2, 2, user_row, warn_days, violation_days, alert)

def check_user_thresholds(user_thresholds, report_row):
    """
    Grab the thresholds from the reference table and pass them on with the row from the credentials report to be used for checking the keys
    """
    warn_days = user_thresholds['warn']
    violation_days = user_thresholds['violation']
    alert = user_thresholds['alert']

    if warn_days == 0 or violation_days == 0:
        warn_days = os.getenv("WARN_DAYS")
        violation_days = os.getenv("VIOLATION_DAYS")
    check_access_keys(report_row, warn_days, violation_days, alert)

def search_for_keys(region_name, profile, all_users):
    """
    The main search function that reaches out to AWS IAM to grab the credentials report and read in csv
    First let's get a session based on the user access key so we can get all of the users for a given account
    """

    # Grab a session to AWS via the Python boto3 lib
    session = boto3.Session(region_name=region_name, aws_access_key_id=profile['id'], aws_secret_access_key=profile['secret'])
    iam = session.client('iam')

    # Generate credential report for the given profile
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
    to use for the credentials check
    """
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    not_found = []
    for row in csv_reader:
        user_name = row["user"]
        user_dict = find_known_user(user_name, all_users)
        #print(f'user_dict: {user_dict}')
        if not user_dict:
            not_found.append(user_name)
        else:
            check_user_thresholds(user_dict, row)

    # the not found users could be another Prometheus metric, and could be covered here
    # or as it is in user_dict_for_user() function
    #for user in not_found:
        #print(user[0:8])
    #    None
    # prometheus can receive file with 0, 1 or more

def state_file_to_dict(all_outputs):
    # Convert the production state file to a dict 
    # data structure
    # {new_key = {key1:value, key2:value}}
    # Make this an env var!

    # NOTE: If anything changes with the outputs in aws-admin for gov and com
    # make sure the delimiter stays the same, or change the below var if it changes
    # just make sure that whatever it changes to is consistent with:
    # profile name prefix+delimiter+the rest of the string
    #
    # example:
    #
    # gov-stg-tool_access_key_id_stalekey -> prefix = gov-stg-tool
    # the rest = tool_access_key_id_stalekey
    prefix_delimiter = os.getenv('PREFIX_DELIMITER')

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

def load_profiles(com_state_file, gov_state_file):
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

def format_user_dicts(users_list, thresholds):
    """
    Augment the users list to have the threshold information.
    """
    new_dict = {}
    user_list = []
    for key in users_list:
        found_thresholds = [dict for dict in thresholds if dict['account_type'] == "Operators"]
        if found_thresholds:
            found_threshold = found_thresholds[0]
            found_threshold["user"] = key
            user_list.append(found_threshold)
    return user_list

def load_system_users(com_filename, gov_filename, thresholds):
    # Schema for gov or com users after pull out the "users" dict
    # {"user.name":{'aws_groups': ['Operators', 'OrgAdmins']}}
    # translated to:
    # {"user":user_name, "account_type":"Operators"} - note Operators is hardcoded for now
    com_file = open(com_filename)
    gov_file = open(gov_filename)
    com_users_list = list(yaml.safe_load(com_file)["users"])
    gov_users_list = list(yaml.safe_load(gov_file)["users"])
    com_users_list = format_user_dicts(com_users_list, thresholds)
    gov_users_list = format_user_dicts(gov_users_list, thresholds)

    return (com_users_list, gov_users_list)

def load_tf_users(tf_filename, thresholds):
    # Schema for tf_users - need to verify this is correct
    # {user:user_name, account_type:"Platform", is_wildcard: False, alert: True, warn: 165, violation: 180}  
    # Note that all values are hardcoded except the user name

    tf_users = []
    tf_dict = {}
    tf_file = open(tf_filename)
    tf_yaml = yaml.safe_load(tf_file)
    for key in list(tf_yaml['terraform_outputs']):
        if "username" in key:
            found_thresholds = [dict for dict in thresholds if dict['account_type'] == "Platform"] 
            if found_thresholds:
                found_threshold = found_thresholds[0]
                found_threshold["user"] = key
                tf_users.append(found_threshold)
    return tf_users

def load_other_users(other_users_filename):
    # Schema for other_users is
    # {user: user_name, account_type:account_type, is_wildcard: True|False, alert: True|False, warn: warn, violation: violation}
    # Note that all values are hardcoded except the user name
    other_users_file = open(other_users_filename)
    other_users_yaml = yaml.safe_load(other_users_file)

    return other_users_yaml

def load_thresholds(filename):
    """
    This is the file that holds all of the threshold information to be added to the user list dictionaries.
    """
    thresholds_file = open(filename)
    thresholds_yaml = yaml.safe_load(thresholds_file)
    return thresholds_yaml

def main():
    """
    The main function that creates tables, loads the csv for the reference table and kicks off the search for stale keys
    """

    # grab the state files, user files and outputs from cg-provision from the s3 resources
    args = sys.argv[1:]
    com_state_file = os.path.join("../../../",args[0])
    gov_state_file = os.path.join("../../../",args[1])
    com_users_filename = os.path.join("../../../",args[2])
    gov_users_filename = os.path.join("../../../",args[3])
    tf_state_filename = os.path.join("../../../",args[4]+"/state.yml")
    other_users_filename = os.path.join("../../../",args[5]+"/other_iam_users.yml")
    thresholds_filename = os.path.join("../../../prometheus-config/ci/aws-iam-check-keys/thresholds.yml")

    # AWS regions
    com_region = "us-east-1"
    gov_region = "us-gov-west-1"

    thresholds = load_thresholds(thresholds_filename)
    (com_users_list, gov_users_list) = load_system_users(com_users_filename, gov_users_filename, thresholds)
    tf_users = load_tf_users(tf_state_filename, thresholds)
    other_users = load_other_users(other_users_filename)

    # timing metrics for testing, not sure if they'll be useful later
    st_cpu_time = time.process_time()
    st = time.time()

    create_tables_bool = os.getenv('IAM_CREATE_TABLES')
    # Flag to create the db tables for the first run or for debugging
    if create_tables_bool == "True":
        print("creating tables...")
        keys_db_models.create_tables()

    (com_state_dict, gov_state_dict) = load_profiles(com_state_file, gov_state_file)

    for com_key in com_state_dict:
        print(f'searching profile {com_key}')
        all_com_users = com_users_list + tf_users + other_users
        search_for_keys(com_region, com_state_dict[com_key], all_com_users)
    for gov_key in gov_state_dict:
        print(f'searching profile {gov_key}')
        all_gov_users = gov_users_list + tf_users + other_users
        search_for_keys(gov_region, gov_state_dict[gov_key], all_gov_users)

    et_cpu_time = time.process_time()
    et = time.time()

    # get execution time
    res = et_cpu_time - st_cpu_time
    print('CPU Execution time:', res, 'seconds')

    # get the execution time
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')
    print(f'key1: {key1}')
    print(f'key2: {key2}')
    print(f'warnings\n{prometheus_alerts}')


if __name__ == "__main__":
    if not ("GATEWAY_HOST") in os.environ:
        print("GATEWAY_HOST is required.")
        sys.exit(1)
    main()
    prometheus_url = "http://"+os.getenv("GATEWAY_HOST") + ":" + os.getenv("GATEWAY_PORT", "9091") + "/metrics/job/find_stale_keys"

    res = requests.put(url=prometheus_url,
                       data=prometheus_alerts,
                       headers={'Content-Type': 'application/octet-stream'})
    res.raise_for_status()

    #cleared should get zeroed out in database for events after sent to prometheus
    # until they are cleared, they increment for number of alerts. the alert sent is True
    # when they are zeroed out



