#!/usr/bin/env python

import argparse
from copy import copy
import csv
from datetime import timedelta, datetime
from dateutil.parser import parse
from environs import Env
from pathlib import Path
import os
import sys
import time
import yaml

import boto3
import requests
from sqlalchemy.orm import Session


from keys_db_models import (
    engine,
    AccessKey,
    IAMKeys,
    EventType,
    Event)
import keys_db_models
from threshold import Threshold
from threshold import AWS_User

VIOLATION = "violation"
WARNING = "warning"
OK = ""


def main():
    """
    Create tables if needed, load the thresholds for alerting and kick off the search for stale keys
    If there is a migration to do, do that first!
    """

    # grab the state files, user files and outputs from cg-provision from the
    # s3 buckets for com and gov users
    env = Env()
    debug = False
    base_dir = env.str("BASE_DIR", None)
    if not base_dir:
        base_dir = "../../../.."
    base_path = Path(base_dir)

    # Parse the CLI for any arguments
    # Note that the default value of 1 is following to allow for levels or other
    # info to be passed later if needed
    parser = argparse.ArgumentParser(description='Arguments for find_stale_keys')
    parser.add_argument('-c', '--create-tables', action="store_true", help='create tables WARNING: This is destructive')
    parser.add_argument('-d', '--debug', action="store_true", help='debug mode no levels for now')
    parser.add_argument('-m', '--migrate', action="store_true", help='run migrations -1 go back a revision default: upgrade')
    args = parser.parse_args()
    if args.debug:
        print("debug")
        debug = True
    if args.migrate:
        print("migrate - either remove this or update it to use alembic")

    # Debug code goes here
    if debug:
        thresholds_filename = "thresholds.yml"
        base_dir = "../../.."
    else:
        thresholds_filename = base_path / "prometheus-config/ci/aws-iam-check-keys/thresholds.yml"

    base_path = Path(base_dir)
    com_state_file = base_path / "terraform-prod-com-yml/state.yml"
    gov_state_file = base_path / "terraform-prod-gov-yml/state.yml"
    com_users_filename = base_path / "aws-admin/stacks/gov/sso/users.yaml"
    gov_users_filename = base_path / "aws-admin/stacks/com/sso/users.yaml"
    tf_state_filename = base_path / "terraform-yaml-production/state.yml"
    other_users_filename = base_path / "other-iam-users-yml/other_iam_users.yml"

    # AWS regions
    com_region = "us-east-1"
    gov_region = "us-gov-west-1"

    thresholds = load_thresholds(thresholds_filename)
    com_users_list = load_system_users(com_users_filename, thresholds)
    gov_users_list = load_system_users(gov_users_filename, thresholds)
    tf_users = load_tf_users(tf_state_filename, thresholds)
    other_users = load_other_users(other_users_filename)

    # checks to see if we are creating tables
    if args.create_tables:
        keys_db_models.create_tables()

    (com_state_dict, gov_state_dict) = load_profiles(com_state_file,
                                                     gov_state_file)

    for com_key in com_state_dict:
        all_com_users = com_users_list + tf_users + other_users
        search_for_keys(com_region, com_state_dict[com_key], all_com_users)
    for gov_key in gov_state_dict:
        all_gov_users = gov_users_list + tf_users + other_users
        search_for_keys(gov_region, gov_state_dict[gov_key], all_gov_users)
    send_all_alerts()


def check_retention(warn_days: int, violation_days: int, access_key_date: str) -> (str, datetime, datetime):
    """
    Returns violation when keys were last rotated more than :violation_days: ago and
    warning when keys were last rotated :warn_days: ago if it is neither None is returned
    """
    key_date = parse(access_key_date, ignoretz=True)
    violation_days_delta = key_date + timedelta(days=violation_days)
    warning_days_delta = key_date + timedelta(days=warn_days)
    status = OK
    if violation_days_delta <= datetime.now():
        status = VIOLATION
    if warning_days_delta <= datetime.now():
        status = WARNING
    return status, warning_days_delta, violation_days_delta


def find_known_user(report_user: str, aws_users: list[AWS_User]) -> (AWS_User, list[dict]):
    """
    Return the row as an AWS_User, from the users dictionary matching the report user if it exists and
    not_found list if the user isn't found. This will be used for validating thresholds
    for the key rotation date timeframes as well as help track users not found

    Note that if is_wildcard is true, the search will be a fuzzy search otherwise the
    search will be looking for an exact match.
    """
    users_not_found = []
    # aws_user:AWS_User = AWS_User(account_type="",is_wildcard=False,warn=0,violation=0,alert=False, user="")
    aws_user = None
    for an_aws_user in aws_users:
        if an_aws_user.is_wildcard:
            if an_aws_user.user in report_user:
                aws_user = an_aws_user
                break
        else:
            if an_aws_user.user == report_user:
                aws_user = an_aws_user
                break
    if not aws_user:
        users_not_found.append(report_user)
    return aws_user, users_not_found


def check_retention_for_key(access_key_last_rotated: str, access_key_num: int, user_row: dict,
                            warn_days: int, violation_days: int, alert: bool):
    alert_type = ""
    warning_delta = None
    violation_delta = None

    if warn_days and violation_days and access_key_last_rotated != "N/A":
        alert_type, warning_delta, violation_delta = check_retention(int(warn_days), int(violation_days),
                                                                     access_key_last_rotated)
    iam_user = IAMKeys.user_from_dict(user_row, access_key_num)
    if alert_type and warning_delta and violation_delta:
        found_event = Event.event_exists(access_key_num, iam_user)
        if found_event:
            Event.update_event(found_event, alert_type, warning_delta, violation_delta)
        elif alert:
            Event.add_event_to_db(iam_user, alert_type, access_key_num, warning_delta, violation_delta)
    else:
        iam_user.check_key_in_db_and_update(user_row, access_key_num)


def send_alerts(cleared: bool, events: list[Event]):
    alerts = ""
    with Session(engine) as session:
        for event in events:
            # set up the attributes to be sent to prometheus
            event = event[0]
            event_user = event.user
            alert_type = event.event_type.event_type_name
            access_key_num = event.access_key_num
            scrubbed_arn = event_user.arn.split(':')[4][-4:]
            user_string = event_user.iam_user + "-" + scrubbed_arn
            cleared_int = 0 if cleared else 1

            access_key = IAMKeys.akey_for_num(event_user, access_key_num)
            access_key_last_rotated = access_key.access_key_last_rotated

            # append the alert to the string of alerts to be sent to prometheus via the pushgateway
            if event.warning_delta and event.violation_delta:
                alert = f'stale_key_num{{user="{user_string}", alert_type="{alert_type}", warn_date="{event.warning_delta}",\
                violation_date="{event.violation_delta}", key="{access_key_num}", last_rotated="{access_key_last_rotated}"}} {cleared_int}\n'
                alerts += alert

            # Set the cleared and alert_sent attributes in the database,
            # subject to the metric making it through the gateway
            event.cleared = True if cleared else False
            event.alert_sent = True
            session.commit()

        print(alerts)
        # Send alerts to prometheus to update alerts
        # TODO: Look at all uses of os.getenv and see if I can replace with Env (or if that is desirable)
        prometheus_url = f'http://{os.getenv("GATEWAY_HOST")}:{os.getenv("GATEWAY_PORT", "9091")}/metrics/job/find_stale_keys'
        try:
            res = requests.put(url=prometheus_url,
                               data=alerts,
                               headers={'Content-Type': 'application/octet-stream'},
                               timeout=60)
        except requests.exceptions.Timeout:
            print("call timed out, see what's up with the server")

        print(res.raise_for_status())
        if res.status_code == 200:
            session.commit()
        else:
            print(f'Warning! Metrics failed to record! See Logs status_code: {res.status_code} reason: {res.reason}')
            session.rollback()


def send_all_alerts():
    try:
        cleared_events = Event.all_cleared_events()
        uncleared_events = Event.all_uncleared_events()
        send_alerts(False, uncleared_events)
        send_alerts(True, cleared_events)
    except ValueError:
        print(f"{ValueError} an exception occurred while adding alerts to the database")


def check_access_keys(user_row: dict, warn_days: int, violation_days: int, alert: bool):
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


def check_user_thresholds(aws_user: AWS_User, report_row: dict):
    """
    Grab the thresholds from the user_thresholds and pass them on with the row
    from the credentials report to be used for checking the keys
    """
    warn_days = aws_user.warn
    violation_days = aws_user.violation
    alert = aws_user.alert
    env = Env()

    if warn_days == 0 or violation_days == 0:
        default_warn_days = env.int("WARN_DAYS", 60)
        warn_days = default_warn_days
        default_violation_days = env.int("VIOLATION_DAYS", 90)
        violation_days = default_violation_days
    check_access_keys(report_row, warn_days, violation_days, alert)


def search_for_keys(region_name: str, profile: dict, all_users: list[AWS_User]):
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
        aws_user, _ = find_known_user(user_name, all_users)
        if not aws_user:
            not_found.append(user_name)
        else:
            check_user_thresholds(aws_user, row)
            # get_user_thresholds(aws_user, row)


def state_file_to_dict(all_outputs: list[dict]):
    """ Convert the production state file to a dict
    data structure
    {new_key = {key1:value, key2:value}}

    NOTE: If anything changes with the outputs in aws-admin for gov and com
    make sure the delimiter stays the same, or change the below var, set in config.yml, if it
    changes just make sure that whatever it changes to is consistent with:
    profile name prefix+delimiter+the rest of the string

    example:

    gov-stg-tool_access_key_id_stalekey -> prefix = gov-stg-tool, so the delimiter is '-'
    the rest = tool_access_key_id_stalekey
    """

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


def get_platform_thresholds(thresholds: list[Threshold], account_type: str):
    found_thresholds = [threshold_dict for threshold_dict in thresholds
                        if threshold_dict.account_type == account_type]
    if found_thresholds:
        return copy(found_thresholds[0])
    else:
        return None


def format_user_dicts(users_list: list, thresholds: list[Threshold], account_type) -> list[Threshold]:
    """
    Augment the users list to have the threshold information.
    """
    augmented_user_list = []
    for key in users_list:
        found_user_threshold = get_platform_thresholds(thresholds, account_type)
        found_user_threshold.user = key
        augmented_user_list.append(found_user_threshold)
    return augmented_user_list


def load_profiles(com_state_file: Path, gov_state_file: Path):
    """
    Clean up yaml from state files for com and gov
    These are the secrets used for assume_role to pull
    user info from the accounts
    """
    with com_state_file.open() as f:
        com_state = yaml.safe_load(f)
    with gov_state_file.open() as f:
        gov_state = yaml.safe_load(f)
    all_outputs_com = com_state['terraform_outputs']
    all_outputs_gov = gov_state['terraform_outputs']
    com_state_dict = state_file_to_dict(all_outputs_com)
    gov_state_dict = state_file_to_dict(all_outputs_gov)
    return com_state_dict, gov_state_dict


def load_tf_users(tf_filename: Path, thresholds: list[Threshold]) -> list[AWS_User]:
    """
    Schema for tf_users - need to verify this is correct
    {
      user:user_name,
      account_type:"Platform",
      is_wildcard: False,
      alert: True,
      warn: 165,
      violation: 180
    }
    Note that all values are hardcoded except the username
    This file is scraped for more users to search for stale keys
    """
    tf_users = []
    with open(tf_filename) as f:
        tf_yaml = yaml.safe_load(f)
    outputs = tf_yaml['terraform_outputs']
    for key in list(outputs):
        if "username" in key:
            found_user_threshold = get_platform_thresholds(thresholds, "Platform")
            found_user_threshold.user = outputs[key]
            tf_users.append(found_user_threshold)
    return tf_users


def load_other_users(other_users_filename: Path) -> list[AWS_User]:
    """
    Schema for other_users is
    {   user: user_name,
        account_type:account_type,
        is_wildcard: True|False,
        alert: True|False,
        warn: warn,
        violation: violation
    }
    Note that all values are hardcoded in the yaml
    AWS_User is a subclass of the threshold dataclass which has the properties
    in the above schema
    """
    with open(other_users_filename) as f:
        other_users_yaml = yaml.safe_load(f)

    return [AWS_User(**other) for other in other_users_yaml]


def load_system_users(filename: Path, thresholds: list[Threshold]) -> list[AWS_User]:
    """
    Schema for gov or com users after pull out the "users" dict
    {"user.name":{'aws_groups': ['Operators', 'OrgAdmins']}}
    translated to:
    {"user":user_name, "account_type":"Operators"} - note Operators is
    hardcoded for now
    """
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


if __name__ == "__main__":
    # Set up the GATEWAY to send alerts to Prometheus
    if "GATEWAY_HOST" not in os.environ:
        print("GATEWAY_HOST is required.")
        sys.exit(1)
    main()
