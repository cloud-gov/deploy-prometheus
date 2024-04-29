import datetime
from datetime import datetime
from unittest.mock import patch
from unittest import TestCase

import find_stale_keys
from find_stale_keys import AWS_User

class Test(TestCase):
    def setUp(self):
        self.test_dict = {"user": "break.glass", "arn": "arn:aws:iam::12345678:user/break.glass",\
                          "user_creation_time": "2023-04-12T21:23:57+00:00", "password_enabled": "false",\
                          "password_last_used": "N/A", "password_last_changed": "N/A",\
                          "password_next_rotation": ('foo',), "mfa_active": "false", "access_key_1_active": "true",\
                          "access_key_1_last_rotated": "2023-04-12T21:23:58+00:00",\
                          "access_key_1_last_used_date": "N/A", "access_key_1_last_used_region": "N/A",\
                          "access_key_1_last_used_service": "N/A", "access_key_2_active": "false",\
                          "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A",\
                          "access_key_2_last_used_region": "N/A", "access_key_2_last_used_service": "N/A",\
                          "cert_1_active": "false", "cert_1_last_rotated": "N/A",\
                          "cert_2_active": "false", "cert_2_last_rotated": "N/A"}
        self.aws_users = [
            AWS_User(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=True, user="Ben"),
            AWS_User(account_type="Platform", is_wildcard=True, warn=90, violation=180, alert=True, user="cg-ecr-"),
            AWS_User(account_type="Customer", is_wildcard=False, warn=180, violation=270, alert=False, user="cg-s3-somelonguidishname"),
            AWS_User(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=True, user="Robert"),
            AWS_User(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="Mark"),
            AWS_User(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="James")
        ]

    @patch('find_stale_keys.datetime')
    def test_check_retention(self, mock_datetime):
        mock_date = datetime(2024,4,25)
        mock_datetime.now.return_value = mock_date
        actual = find_stale_keys.check_retention(90, 180, "2024-04-12T21:23:58+00:00")
        expected = (find_stale_keys.OK, datetime(2024,7,11,21,23,58), datetime(2024,10,9,21, 23,58))
        self.assertEqual(actual, expected)

    def test_find_known_user(self):
        # This should fail due to typo in name
        actual = find_stale_keys.find_known_user("cg-s3-somelonguidishname", self.aws_users)
        expected = (AWS_User(account_type="Customer", is_wildcard=False, warn=180, violation=270, alert=False, user="cg-s3-smelonguidishname"),[])
        self.assertEqual(actual, expected)

        # This passes and is an example of Fuzzy searching
        actual = find_stale_keys.find_known_user("cg-s3-somelonguidishname", self.aws_users)
        expected = (AWS_User(account_type="Platform", is_wildcard=True, warn=180, violation=270, alert=False, user="cg-s3-somelonguidishname"),[])
        self.assertEqual(actual, expected)

        # This passes and is an example of exact matching for name
        actual = find_stale_keys.find_known_user("Ben", self.aws_users)
        expected = (AWS_User(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=False, user="Ben"),[])
        self.assertEqual(actual, expected)

        # Maybe a few more tests and one with not found users

    #
    # def test_check_retention_for_key(self):
    #     self.fail()
    #
    # def test_send_alerts(self):
    #     self.fail()
    #
    # def test_send_all_alerts(self):
    #     self.fail()
    #
    # def test_check_access_keys(self):
    #     self.fail()
    #
    # def test_check_user_thresholds(self):
    #     self.fail()
    #
    # def test_search_for_keys(self):
    #     self.fail()
    #
    # def test_state_file_to_dict(self):
    #     self.fail()
    #
    # def test_get_platform_thresholds(self):
    #     self.fail()
    #
    # def test_format_user_dicts(self):
    #     self.fail()
