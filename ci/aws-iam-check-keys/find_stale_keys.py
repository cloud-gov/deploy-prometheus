#!/usr/bin/env python

import argparse

from copy import copy
import csv
from threshold import Threshold

# from alert import Alert
from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway, delete_from_gateway
import boto3
import yaml
import time
import sys
import re
from pathlib import Path
from environs import Env
from dateutil.parser import parse

from datetime import datetime

def main():
    """
    This is where the loading of the various files for reference occurs. This also kicks off the process
    to find the stale keys and then push any alerts out as well.
    """

    # grab the state files, user files and outputs from cg-provision from the
    # s3 buckets for com and gov users
    local_env = Env()
    debug = False
    base_dir = local_env.str("BASE_DIR", None)
    if not base_dir:
        base_dir = "../../.."
    base_path = Path(base_dir)

    # Parse the CLI for any arguments
    # Note that the default value of 1 is following to allow for levels
    # or other info to be passed later if needed
    parser = argparse.ArgumentParser(
        description="Arguments for find_stale_keys")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="debug mode no levels for now"
    )
    args = parser.parse_args()
    if args.debug:
        debug = True

    # Debug code goes here
    if debug:
        thresholds_filename = "ci/aws-iam-check-keys/thresholds.yml"
        base_dir = ".."
        base_path = Path(base_dir)
    else:
        thresholds_filename = "thresholds.yml"

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

    (com_state_dict, gov_state_dict) = load_profiles(
        com_state_file, gov_state_file)

    for com_key in com_state_dict:
        all_com_users = com_users_list + tf_users + other_users
        search_for_keys(com_region, com_state_dict[com_key], all_com_users, com_key)
    for gov_key in gov_state_dict:
        all_gov_users = gov_users_list + tf_users + other_users
        search_for_keys(gov_region, gov_state_dict[gov_key], all_gov_users, gov_key)

def load_thresholds(filename: str) -> list[Threshold]:
    """
    This is the file that holds all the threshold information to be added to
    the user list dictionaries.
    """
    with open(filename) as f:
        thresholds_yaml = yaml.safe_load(f)
    return [Threshold(**threshold) for threshold in thresholds_yaml]


def get_platform_thresholds(thresholds: list[Threshold], account_type: str):
    found_thresholds = [
        threshold_dict
        for threshold_dict in thresholds
        if threshold_dict.account_type == account_type
    ]
    if found_thresholds:
        return copy(found_thresholds[0])
    else:
        return None


def format_user_dicts(
    users_list: list, thresholds: list[Threshold], account_type
) -> list[Threshold]:
    """
    Augment the users list to have the threshold information.
    """
    augmented_user_list = []
    for key in users_list:
        found_user_threshold = get_platform_thresholds(
            thresholds, account_type)
        if found_user_threshold:
            found_user_threshold.user = key
        augmented_user_list.append(found_user_threshold)
    return augmented_user_list


def load_system_users(filename: Path, thresholds: list[Threshold]) -> list[Threshold]:
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


def load_tf_users(tf_filename: Path, thresholds: list[Threshold]) -> list[Threshold]:
    """
    Schema for tf_users - need to verify this is correct
    {
      user:user_name,
      account_type:"Platform",
      is_wildcard: True|False,
      alert: True|False,
      warn: 165, -- the threshold for warning
      violation: 180 -- the threshold for violations
    }
    Note that all values are hardcoded except the username
    This file is scraped for more users to search for stale keys
    """
    tf_users: list[Threshold] = []
    with open(tf_filename) as f:
        tf_yaml = yaml.safe_load(f)
    outputs = tf_yaml["terraform_outputs"]
    for key in list(outputs):
        if "username" in key:
            found_user_threshold = get_platform_thresholds(
                thresholds, "Platform")
            found_user_threshold.user = outputs[key]
            tf_users.append(found_user_threshold)
    return tf_users


def load_other_users(other_users_filename: Path) -> list[Threshold]:
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
    Threshold is a dataclass which has the properties in the above schema
    """
    with open(other_users_filename) as f:
        other_users_yaml = yaml.safe_load(f)

    return [Threshold(**other) for other in other_users_yaml]


def state_file_to_dict(all_outputs: dict):
    """Convert the production state file to a dict
    data structure
    {profile_key = {id:value, secret:value}}
    """
    output_dict = {}
    for key, value in all_outputs.items():
        new_key = re.sub("_.*", "", key)
        if new_key not in output_dict:
            output_dict[new_key] = {}
        if "id" in key:
            output_dict[new_key]["id"] = value
        if "secret" in key:
            output_dict[new_key]["secret"] = value

    return output_dict


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
    all_outputs_com = com_state["terraform_outputs"]
    all_outputs_gov = gov_state["terraform_outputs"]
    com_state_dict = state_file_to_dict(all_outputs_com)
    gov_state_dict = state_file_to_dict(all_outputs_gov)
    return com_state_dict, gov_state_dict


def search_for_keys(region_name: str, profile: dict, all_users: list[Threshold], account: str):
    """
    The main search function that reaches out to AWS IAM to grab the
    credentials report as csv and load it into a list of dictionaries.
    This list is then used to determine the number of days since rotation of the users active key(s)
    The user info and the days since rotation is sent to Prometheus for it to use internal rules to determine
    what is alerted on. Note that some of that is configurable in the thresholds.
    """

    # First let's get a session based on the user access key,
    # so we can get all the users for a given account via the Python boto3 lib
    session = boto3.Session(
        region_name=region_name,
        aws_access_key_id=profile["id"],
        aws_secret_access_key=profile["secret"],
    )
    print(f"about to check: {account}")
    iam = session.client("iam")
    # Generate credential report for the given profile
    # Generating the report is an async operation, so wait for it by sleeping
    # If Python has async await type of construct it would be good to use here
    w_time = 0
    while iam.generate_credential_report()["State"] != "COMPLETE":
        w_time = w_time + 5
        print("Waiting...{}".format(w_time))
        time.sleep(w_time)
    report = iam.get_credential_report()
    content = report["Content"].decode("utf-8")
    content_lines = content.split("\n")

    # Initiate the reader, convert the csv contents to a list and turn each row
    # into a dictionary to use for the credentials check
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    row: dict
    for row in csv_reader:
        user_name = row["user"]
        if user_name == "ephraim.gross":
            print(f"found ephraim: {row}")
        # Note: If the user is unknown, we aren't capturing it, but could here
        # in an else below
        aws_user = find_known_user(user_name, all_users)
        if len(aws_user.account_type) > 0:
            check_keys(aws_user, row, account)


def find_known_user(report_user: str, aws_users: list[Threshold]) -> Threshold:
    """
    Return the row as a Threshold, from the users dictionary matching the
    report user if it exists. This will be used for validating thresholds for
    the key rotation date timeframes
    """
    aws_user = Threshold(
        account_type="", is_wildcard=False, warn=0, violation=0, alert=False
    )

    found = [aws_user for aws_user in aws_users if aws_user.user in report_user]
    if found:
        aws_user = copy(found[0])
    return aws_user


def calc_days_since_rotation(last_rotated: str) -> int:
    last_rotated_days = 0
    last_rotated_date = parse(last_rotated, ignoretz=True)
    today = datetime.today()
    delta = today.date() - last_rotated_date.date()
    last_rotated_days = delta.days
    return last_rotated_days


def del_key(key_dict: dict):
    """
    Send the key(s) to the pushgateway client to let it determine if they
    are stale
    """
    gateway = f'{env.str("GATEWAY_HOST")}:{env.int("GATEWAY_PORT", 9091)}'
    del key_dict["days_since_rotation"]
    del key_dict["last_rotated"]
    del key_dict["key_num"]

    delete_from_gateway(
        gateway, job="find_stale_keys", grouping_key=key_dict
    )


def send_key(key_dict: dict, severity: str):
    """
    Send the key(s) to the pushgateway client to let it determine if they
    are stale
    """
    gateway = f"{env.str('GATEWAY_HOST')}:{env.int('GATEWAY_PORT', 9091)}"
    registry = CollectorRegistry()
    days_since_rotation = key_dict["days_since_rotation"]
    del key_dict["days_since_rotation"]

    key_info = Gauge(
        "last_rotated_days",
        "Send to the pushgateway to see ifaccess key is \
        stale, let it alert if so",
        [
            "user",
            "key_num",
            "user_type",
            "account",
            "last_rotated"
        ],
        registry=registry,
    )
    
    key_info.labels(**key_dict).set(days_since_rotation)
    pushadd_to_gateway(
        gateway, job="find_stale_keys", registry=registry, grouping_key=key_dict
    )

def check_key(key_num: int, last_rotated_key: str, user: Threshold, row: dict, account: str):
    days_since_rotation = calc_days_since_rotation(last_rotated_key)
    user_dict = {"user":row["user"], "key_num": key_num, "user_type": user.account_type, "account": account, "days_since_rotation": days_since_rotation, "last_rotated":last_rotated_key}
    if days_since_rotation >= user.violation and user.account_type:
        print(f"about to send user: {user_dict['user']}")
        send_key(user_dict, "violation")
    elif days_since_rotation >= user.warn:
        print(f"about to send user: {user_dict['user']}")
        send_key(user_dict, "warn")
    else:
        # print(f"about to send rotated for user: {user}")
        print(f"about to del user: {user_dict['user']}")
        del_key(user_dict)


def check_keys(user: Threshold, row: dict, account: str):
    last_rotated_key1 = row["access_key_1_last_rotated"]
    last_rotated_key2 = row["access_key_2_last_rotated"]

    # If we want to alert customers we'll need to modify the alert setting
    # in their threshold to true
    if user.alert:
        if last_rotated_key1 != "N/A":
            check_key(1, last_rotated_key1, user, row, account)
        elif last_rotated_key2 != "N/A":
            check_key(2, last_rotated_key2, user, row, account)


if __name__ == "__main__":
    # Set up the GATEWAY to send alerts to Prometheus
    env = Env()
    try:
        env.str("GATEWAY_HOST")
    except ValueError as err:
        print(f"GATEWAY_HOST missing: {err}")
        sys.exit(1)
    main()