# import json
import csv
import time
import boto3
from datetime import timedelta, datetime
from dateutil.parser import parse
from keys_db_models import (
	IAM_Keys,
	Event_Type,
	Event)
import keys_db_models


db = keys_db_models.db

"""
Reference Table info:
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
reference_table = []

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

def user_dict_for_user(user):
    for row in reference_table:
        if (row['is_wildcard'] == "Y" and user.startswith(row['user_string'])) or user == row['user_string']:
            return row
        
def check_retention_for_key(key_num, access_key_last_rotated, user_row, alert, warn_days, violation_days):
    user = user_row['user']
    if (access_key_last_rotated != 'N/A'):
        (alert_type, expired) = check_retention(warn_days, violation_days, access_key_last_rotated)
        if (expired):
            warn_event, created = Event_Type.insert_event_type(alert_type)
            iam_user = IAM_Keys.user_from_dict(user_row)
            event = Event.new_event_type_user(warn_event,iam_user)

def check_access_keys(user_row, alert, warn_days, violation_days):
    last_rotated_key1 = user_row['access_key_1_last_rotated']
    last_rotated_key2 = user_row['access_key_2_last_rotated']
    
    if (last_rotated_key1 != 'N/A' ):
        check_retention_for_key("1", last_rotated_key1, user_row, alert, warn_days, violation_days)
            
    if (last_rotated_key2 != 'N/A' ):
        check_retention_for_key("2",last_rotated_key2, user_row, alert, warn_days, violation_days)

def check_user_thresholds(user_thresholds, report_row):
    warn_days = user_thresholds['warn']
    violation_days = user_thresholds['violation']
    
    if user_thresholds['alert'] == "N" or user_thresholds['warn'] == "" or user_thresholds['violation'] == "":
        warn_days = "60"
        violation_days = "90"
    alert = user_thresholds['alert']
    check_access_keys(report_row, alert, warn_days, violation_days)

def search_for_keys():
    # read in csv
    session = boto3.Session()
    iam = session.client('iam')

    w_time = 0
    while iam.generate_credential_report()['State'] != 'COMPLETE':
        w_time = w_time + 5
        print("Waiting...{}".format(w_time))
        time.sleep(w_time)
    print("Report is ready")
    report = iam.get_credential_report()
    content = report["Content"].decode("utf-8")
    content_lines = content.split("\n")

    # Initiate the reader, convert that to a list and turn that into a dict
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    not_found = []
    for row in csv_reader:
        user_name = row["user"]
        user_dict = user_dict_for_user(user_name)
        if user_dict == None:
            not_found.append(user_name)
        else:
            check_user_thresholds(user_dict, row)
    
    for user in not_found:
        print(user)
    # prometheus can receive file with 0, 1 or more

def load_reference_data(csv_file_name):
    with open(csv_file_name) as data:
        for r in csv.DictReader(data):
            reference_table.append(r)

def main():
    st_cpu_time = time.process_time()
    st = time.time()

    keys_db_models.create_tables()
    
    # pipeline will pull in resource for the csv file so it's local
    load_reference_data("prometheus-config/ci/aws-iam-check-keys/seed_thresholds.csv")
    search_for_keys()
    
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

