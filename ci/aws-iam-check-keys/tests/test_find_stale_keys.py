
import datetime
from datetime import datetime
from unittest.mock import patch
from unittest import TestCase

from botocore.utils import datetime2timestamp

from alert import Alert
import find_stale_keys
from threshold import Threshold


class Test(TestCase):
    def setUp(self):
        self.test_dict = {
            "user": "robert.gottlieb",
            "arn": "arn:aws:iam::12345678:user/robert.gottlieb",
            "user_creation_time": "2023-04-12T21:23:57+00:00",
            "password_enabled": "false",
            "password_last_used": "N/A",
            "password_last_changed": "N/A",
            "password_next_rotation": ("foo",),
            "mfa_active": "false",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2023-04-12T21:23:58+00:00",
            "access_key_1_last_used_date": "N/A",
            "access_key_1_last_used_region": "N/A",
            "access_key_1_last_used_service": "N/A",
            "access_key_2_active": "false",
            "access_key_2_last_rotated": "N/A",
            "access_key_2_last_used_date": "N/A",
            "access_key_2_last_used_region": "N/A",
            "access_key_2_last_used_service": "N/A",
            "cert_1_active": "false",
            "cert_1_last_rotated": "N/A",
            "cert_2_active": "false",
            "cert_2_last_rotated": "N/A",
        }
        self.aws_users = [
            Threshold(
                account_type="Operators",
                is_wildcard=False,
                warn=90,
                violation=180,
                alert=True,
                user="Ben",
            ),
            Threshold(
                account_type="Platform",
                is_wildcard=False,
                warn=90,
                violation=180,
                alert=True,
                user="cg-ecr-somelongishthing",
            ),
            Threshold(
                account_type="Customer",
                is_wildcard=True,
                warn=180,
                violation=270,
                alert=False,
                user="cg-s3-somelonguidishname",
            ),
            Threshold(
                account_type="Operators",
                is_wildcard=False,
                warn=90,
                violation=180,
                alert=True,
                user="Robert",
            ),
            Threshold(
                account_type="Platform",
                is_wildcard=False,
                warn=90,
                violation=180,
                alert=True,
                user="Mark",
            ),
            Threshold(
                account_type="Platform",
                is_wildcard=False,
                warn=90,
                violation=180,
                alert=True,
                user="James",
            ),
        ]

    @patch("find_stale_keys.datetime")

    def test_calc_days_since_last_rotation(self):
        last_rotated = f"{datetime.today()}"
        actual = find_stale_keys.calc_days_since_last_rotation(last_rotated)
        expected = 0
        self.assertEqual(actual, expected)

    def test_find_known_user(self):
        # This should fail due to typo in name
        actual = find_stale_keys.find_known_user(
            "cg-s3-somelonguidishname", self.aws_users
        )
        expected = Threshold(
            account_type="Customer",
            is_wildcard=False,
            warn=180,
            violation=270,
            alert=False,
            user="cg-s3-smelonguidishname",
        )
        self.assertNotEqual(actual, expected)

        # This passes due to expected being the same as actual
        actual = find_stale_keys.find_known_user(
            "cg-s3-somelonguidishname", self.aws_users
        )
        expected = Threshold(
            account_type="Customer",
            is_wildcard=True,
            warn=180,
            violation=270,
            alert=False,
            user="cg-s3-somelonguidishname",
        )
        self.assertEqual(actual, expected)

        # This passes and is an example of exact matching for name
        actual = find_stale_keys.find_known_user("Ben", self.aws_users)
        expected = Threshold(
            account_type="Operators",
            is_wildcard=False,
            warn=90,
            violation=180,
            alert=True,
            user="Ben",
        )
        self.assertEqual(actual, expected)

        # This passes and is an example of Fuzzy searching for a Platform user
        actual = find_stale_keys.find_known_user(
            "cg-ecr-somelongishthing", self.aws_users
        )
        expected = Threshold(
            account_type="Platform",
            is_wildcard=False,
            warn=90,
            violation=180,
            alert=True,
            user="cg-ecr-somelongishthing",
        )
        self.assertEqual(actual, expected)

    
