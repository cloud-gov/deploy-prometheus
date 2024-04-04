#!/usr/bin/env python

from copy import copy
import csv
from datetime import timedelta, datetime
from dateutil.parser import parse
from pathlib import Path
import os
import sys
import time
import yaml

import requests
import boto3
from playhouse.migrate import PostgresqlMigrator
from playhouse.migrate import *

from keys_db_models import (
    IAM_Keys,
    Event_Type,
    Event)
import keys_db_models
from threshold import Threshold


VIOLATION = "violation"
WARNING = "warning"
OK = ""


def check_retention(warn_days: int, violation_days: int, key_date):
    """
    Returns violation when keys were last rotated more than :violation_days: ago and
    warning when keys were last rotated :warn_days: ago if it is neither None is returned
    """
    key_date = parse(key_date, ignoretz=True)
    violation_days_delta = key_date + timedelta(days=violation_days)
    warning_days_delta = key_date + timedelta(days=warn_days)
    status = OK
    if violation_days_delta <= datetime.now():
        status = VIOLATION
    if warning_days_delta <= datetime.now():
        status = WARNING
    return status, warning_days_delta, violation_days_delta


def find_known_user(report_user, all_users_dict):
    """
    Return the row from the users dictionary matching the report user if it exists and
    not_found list if the user isn't found. This will be used for validating thresholds
    for the key rotation date timeframes as well as help track users not found

    Note that if is_wildcard is true, the search will be a fuzzy search otherwise the
    search will be looking for an exact match.
    """
    not_found = []
    user_dict = {}
    for an_user_dict in all_users_dict:
        if an_user_dict['is_wildcard']:
            if an_user_dict['user'] in report_user:
                user_dict = an_user_dict
                break
        else:
            if an_user_dict['user'] == report_user:
                user_dict = an_user_dict
                break
    if not user_dict:
        not_found.append(report_user)
    return user_dict, not_found


def event_exists(events, access_key_num):
    """
    Look for an access key rotation based on key number (1 or 2) corresponding
    to the number of access keys a user might have.
    If the same event and key number are found, return the event
    An event has an event_type of warning or violation
    """
    found_event = None
    for event in events:
        if event.access_key_num == access_key_num:
            found_event = event
            break
    return found_event


def add_event_to_db(user, alert_type, access_key_num, warning_delta, violation_delta):
    event_type = Event_Type.insert_event_type(alert_type)
    event = Event.new_event_type_user(event_type, user, access_key_num, warning_delta, violation_delta)
    event.cleared = False
    event.alert_sent = False
    event.save()


def update_event(event, alert_type, warning_delta, violation_delta):
    if alert_type:
        event_type = Event_Type.insert_event_type(alert_type)
        event.event_type = event_type
        event.warning_delta = warning_delta
        event.violation_delta = violation_delta
        event.cleared = False
        event.save()
    else:
        event.cleared = True
        event.cleared_date = datetime.now()
        event.save()


def check_retention_for_key(access_key_last_rotated, access_key_num, user_row,
                            warn_days: int, violation_days: int, alert):
    alert_type = ""
    if warn_days and violation_days and access_key_last_rotated != "N/A":
        alert_type, warning_delta, violation_delta = check_retention(warn_days, violation_days,
                                    access_key_last_rotated)
    iam_user = IAM_Keys.user_from_dict(user_row)
    if alert_type:
        events = iam_user.events
        found_event = event_exists(events, access_key_num)
        if found_event:
            update_event(found_event, alert_type, warning_delta, violation_delta)
        elif alert:
            add_event_to_db(iam_user, alert_type, access_key_num, warning_delta, violation_delta)
    else:
        IAM_Keys.check_key_in_db_and_update(user_row, access_key_num)


def send_alerts(cleared, events, db):
    alerts = ""
    with db.atomic() as transaction:
        for event in events:
            # set up the attributes to be sent to prometheus
            user = event.user
            alert_type = event.event_type.event_type_name
            access_key_num = event.access_key_num
            scrubbed_arn = user.arn.split(':')[4][-4:]
            user_string = user.iam_user + "-" + scrubbed_arn
            cleared_int = 0 if cleared else 1

            if access_key_num == 1:
                access_key_last_rotated = user.access_key_1_last_rotated
            else:
                access_key_last_rotated = user.access_key_2_last_rotated

            # append the alert to the string of alerts to be sent to prometheus via the pushgateway
            if event.warning_delta and event.violation_delta:
                alert = f'stale_key_num{{user="{user_string}", alert_type="{alert_type}", warn_date="{event.warning_delta}",\
                violation_date="{event.violation_delta}", key="{access_key_num}", last_rotated="{access_key_last_rotated}"}} {cleared_int}\n'
                alerts += alert
                print(alert)

            # Set the cleared and alert_sent attributes in the database,
            # subject to the metric making it through the gateway
            event.cleared = True if cleared else False
            event.alert_sent = True
            event.save()

        # Send alerts to prometheus to update alerts
        prometheus_url = f'http://{os.getenv("GATEWAY_HOST")}:{os.getenv("GATEWAY_PORT", "9091")}/metrics/job/find_stale_keys'
        res = requests.put(url=prometheus_url,
                           data=alerts,
                           headers={'Content-Type': 'application/octet-stream'}
                           )
        print(res.raise_for_status())
        if res.status_code == 200:
            transaction.commit()
        else:
            print(f'Warning! Metrics failed to record! See Logs status_code: {res.status_code} reason: {res.reason}')
            transaction.rollback()


def send_all_alerts(db):
    try:
        cleared_events = Event.all_cleared_events()
        send_alerts(True, cleared_events, db)
        uncleared_events = Event.all_uncleared_events()
        send_alerts(False, uncleared_events, db)
    except ValueError:
        print(f"{ValueError} an exception occurred while adding alerts to the database")


def check_access_keys(user_row, warn_days: int, violation_days: int, alert):
    """
    Validate key staleness for both access keys, provided they exist, for a
    given user
    """
    last_rotated_key1 = user_row['access_key_1_last_rotated']
    last_rotated_key2 = user_row['access_key_2_last_rotated']

    check_retention_for_key(last_rotated_key1, 1, user_row, warn_days,
                            violation_days, alert)

    check_retention_for_key(last_rotated_key2, 2, user_row, warn_days,
                            violation_days, alert)


def check_user_thresholds(user_threshold: Threshold, report_row):
    """
    Grab the thresholds from the user_thresholds and pass them on with the row
    from the credentials report to be used for checking the keys
    """
    warn_days = user_threshold.warn
    violation_days = user_threshold.violation
    alert = user_thresholds.alert

    if warn_days == 0 or violation_days == 0:
        warn_days = os.getenv("WARN_DAYS")
        warn_days = int(warn_days)
        violation_days = os.getenv("VIOLATION_DAYS")
        violation_days = int(violation_days)
    check_access_keys(report_row, warn_days, violation_days, alert)


def search_for_keys(region_name, profile, all_users):
    """
    The main search function that reaches out to AWS IAM to grab the
    credentials report and read in csv.
    """

    # First let's get a session based on the user access key,
    # so we can get all the users for a given account via the Python boto3 lib
    session = boto3.Session(region_name=region_name,
                            aws_access_key_id=profile['id'],
                            aws_secret_access_key=profile['secret'])
    iam = session.client('iam')

    # Generate credential report for the given profile
    # Generating the report is an async operation, so wait for it by sleeping
    # If Python has async await type of construct it would be good to use here
    w_time = 0
    while iam.generate_credential_report()['State'] != 'COMPLETE':
        w_time = w_time + 5
        print("Waiting...{}".format(w_time))
        time.sleep(w_time)
    print("Report is ready")
    report = iam.get_credential_report()
    content = report["Content"].decode("utf-8")
    content_lines = content.split("\n")

    # Initiate the reader, convert the csv contents to a list and turn each row
    # into a dictionary to use for the credentials check
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    not_found = []
    for row in csv_reader:
        user_name = row['user']

        # Note: second return value in tuple below is ignored for now
        # When we want to do something with unknown users we can hook it up here
        user_dict, _ = find_known_user(user_name, all_users)
        if not user_dict:
            not_found.append(user_name)
        else:
            check_user_thresholds(user_dict, row)


def state_file_to_dict(all_outputs):
    # Convert the production state file to a dict
    # data structure
    # {new_key = {key1:value, key2:value}}

    # NOTE: If anything changes with the outputs in aws-admin for gov and com
    # make sure the delimiter stays the same, or change the below var, set in config.yml, if it
    # changes just make sure that whatever it changes to is consistent with:
    # profile name prefix+delimiter+the rest of the string
    #
    # example:
    #
    # gov-stg-tool_access_key_id_stalekey -> prefix = gov-stg-tool, so the delimiter is '-'
    # the rest = tool_access_key_id_stalekey
    prefix_delimiter = os.getenv('PREFIX_DELIMITER')

    output_dict = {}
    for key, value in all_outputs.items():
        profile = {}
        new_dict = {}
        new_key_comps = key.split(prefix_delimiter)
        key_prefix = new_key_comps[0]
        new_key = new_key_comps[len(new_key_comps)-2]
        new_dict[new_key] = value
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
    with open(com_state_file) as f:
        com_state = yaml.safe_load(f)
    with open(gov_state_file) as f:
        gov_state = yaml.safe_load(f)
    all_outputs_com = com_state['terraform_outputs']
    all_outputs_gov = gov_state['terraform_outputs']
    com_state_dict = state_file_to_dict(all_outputs_com)
    gov_state_dict = state_file_to_dict(all_outputs_gov)
    return com_state_dict, gov_state_dict


def get_platform_thresholds(thresholds: list[Threshold], account_type):
    found_thresholds = [threshold_dict for threshold_dict in thresholds
        if threshold_dict.account_type == account_type]
    if found_thresholds:
        return copy(found_thresholds[0])
    else:
        return None


def format_user_dicts(users_list, thresholds: list[Threshold], account_type):
    """
    Augment the users list to have the threshold information.
    """
    augmented_user_list = []
    for key in users_list:
        found_threshold = get_platform_thresholds(thresholds, account_type)
        found_threshold.user = key
        augmented_user_list.append(found_threshold)
    return augmented_user_list


def load_tf_users(tf_filename, thresholds: list[Threshold]):
    # Schema for tf_users - need to verify this is correct
    # {
    #   user:user_name,
    #   account_type:"Platform",
    #   is_wildcard: False,
    #   alert: True,
    #   warn: 165,
    #   violation: 180
    # }
    # Note that all values are hardcoded except the username
    tf_users = []
    with open(tf_filename) as f:
        tf_yaml = yaml.safe_load(f)
    outputs = tf_yaml['terraform_outputs']
    for key in list(outputs):
        if "username" in key:
            found_threshold = get_platform_thresholds(thresholds, "Platform")
            found_threshold.user = outputs[key]
            tf_users.append(found_threshold)
    return tf_users


def load_other_users(other_users_filename):
    # Schema for other_users is
    # {user: user_name, account_type:account_type, is_wildcard: True|False,
    # alert: True|False, warn: warn, violation: violation}
    # Note that all values are hardcoded except the username
    with open(other_users_filename) as f:
        other_users_yaml = yaml.safe_load(f)

    return other_users_yaml


def load_system_users(filename, thresholds):
    # Schema for gov or com users after pull out the "users" dict
    # {"user.name":{'aws_groups': ['Operators', 'OrgAdmins']}}
    # translated to:
    # {"user":user_name, "account_type":"Operators"} - note Operators is
    # hardcoded for now
    with open(filename) as f:
        users_list = list(yaml.safe_load(f)["users"])
    users_list = format_user_dicts(users_list, thresholds, "Operator")
    return users_list


def load_thresholds(filename: Path) -> list[Threshold]:
    """
    This is the file that holds all the threshold information to be added to
    the user list dictionaries.
    """
    with open(filename) as f:
        thresholds_yaml = yaml.safe_load(f)
    return [Threshold(**threshold) for threshold in thresholds_yaml]


def migrate_db(db):
    migrator = PostgresqlMigrator(db)
    migrate(
        migrator.add_column('event', 'warning_delta', DateTimeField(null=True)),
        migrator.add_column('event', 'violation_delta', DateTimeField(null=True))
    )


def main():
    """
    Create tables if needed, load the thresholds for alerting and kick off the search for stale keys
    If there is a migration to do, do that first!
    """

    # grab the state files, user files and outputs from cg-provision from the
    # s3 buckets for com and gov users
    debug = False
    if ('BASE_DIR' in os.environ):
        debug = True
        base_dir = os.getenv('BASE_DIR')
        #base_dir = "/Users/robertagottlieb/Dev/"
    else:
        base_dir = "../../.."

    base_path = Path(base_dir)
    com_state_file = base_path / "terraform-prod-com-yml/state.yml"
    gov_state_file = base_path / "terraform-prod-gov-yml/state.yml"
    com_users_filename = base_path / "aws-admin/stacks/gov/sso/users.yaml"
    gov_users_filename = base_path / "aws-admin/stacks/com/sso/users.yaml"
    tf_state_filename = base_path / "terraform-yaml-production/state.yml"
    other_users_filename = base_path / "other-iam-users-yml/other_iam_users.yml"
    if debug == True:
        thresholds_filename = "/Users/robertagottlieb/Dev/cg-deploy-prometheus/ci/aws-iam-check-keys/thresholds.yml"
    else:
        thresholds_filename = base_path / "prometheus-config/ci/aws-iam-check-keys/thresholds.yml"

    # AWS regions
    com_region = "us-east-1"
    gov_region = "us-gov-west-1"

    thresholds = load_thresholds(thresholds_filename)
    com_users_list = load_system_users(com_users_filename, thresholds)
    gov_users_list = load_system_users(gov_users_filename, thresholds)
    tf_users = load_tf_users(tf_state_filename, thresholds)
    other_users = load_other_users(other_users_filename)

    # timing metrics for testing, not sure if they'll be useful later
    st_cpu_time = time.process_time()
    st = time.time()

    create_tables_bool = os.getenv('IAM_CREATE_TABLES')
    # Flag for debugging in dev or staging as the initial run creates the tables
    # the rest of the time we'll want to create them for debugging or testing db migrations
    if create_tables_bool == "True":
        print("DEBUG: creating tables...")
        db = keys_db_models.create_tables_debug()
    else:
        print("connecting to database, and creating tables if this is the first run")
        db = keys_db_models.create_tables()

    # Take care of migrations if there are any before searching
    if os.getenv('MIGRATE'):
        migrate_db(db)

    (com_state_dict, gov_state_dict) = load_profiles(com_state_file,
                                                     gov_state_file)

    for com_key in com_state_dict:
        all_com_users = com_users_list + tf_users + other_users
        search_for_keys(com_region, com_state_dict[com_key], all_com_users)
    for gov_key in gov_state_dict:
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
    send_all_alerts(db)


if __name__ == "__main__":
    # Set up the GATEWAY to send alerts to Prometheus
    if "GATEWAY_HOST" not in os.environ:
        print("GATEWAY_HOST is required.")
        sys.exit(1)
    main()
