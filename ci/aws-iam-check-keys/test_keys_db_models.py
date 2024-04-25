import unittest
from unittest import TestCase
from keys_db_models import IAMKeys

class TestIAMKeys(TestCase):

    def setUp(self):
        self.test_dict = {"user": "break.glass", "arn": "arn:aws:iam::12345678:user/break.glass", \
                          "user_creation_time": "2023-04-12T21:23:57+00:00", "password_enabled": "false", \
                          "password_last_used": "N/A", "password_last_changed": "N/A", \
                          "password_next_rotation": ('foo',), "mfa_active": "false", "access_key_1_active": "true", \
                          "access_key_1_last_rotated": "2023-04-12T21:23:58+00:00", \
                          "access_key_1_last_used_date": "N/A", "access_key_1_last_used_region": "N/A", \
                          "access_key_1_last_used_service": "N/A", "access_key_2_active": "false", \
                          "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A", \
                          "access_key_2_last_used_region": "N/A", "access_key_2_last_used_service": "N/A",
                          "cert_1_active": "false", "cert_1_last_rotated": "N/A", \
                          "cert_2_active": "false", "cert_2_last_rotated": "N/A"}

    def test_account_for_arn(self):
        arn = self.test_dict["arn"]
        self.assertEqual(IAMKeys.account_for_arn(arn), "12345678")

    def test_clean_dict(self):
        self.expected = {"user": "break.glass", "arn": "arn:aws:iam::12345678:user/break.glass", \
                         "user_creation_time": "2023-04-12T21:23:57+00:00", "password_enabled": False, \
                         "password_last_used": None, "password_last_changed": None, "password_next_rotation": 'foo', \
                         "mfa_active": False, "access_key_1_active": True, \
                         "access_key_1_last_rotated": "2023-04-12T21:23:58+00:00", "access_key_1_last_used_date": None, \
                         "access_key_1_last_used_region": None, "access_key_1_last_used_service": None, \
                         "access_key_2_active": False, "access_key_2_last_rotated": None, \
                         "access_key_2_last_used_date": None, "access_key_2_last_used_region": None, \
                         "access_key_2_last_used_service": None, "cert_1_active": False, "cert_1_last_rotated": None, \
                         "cert_2_active": False, "cert_2_last_rotated": None}
        self.assertEqual(self.expected, IAMKeys.clean_dict(self.test_dict))


if __name__ == "__main__":
    unittest.main()
