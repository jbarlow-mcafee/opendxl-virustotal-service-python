from __future__ import absolute_import
import os
import json
import re
import sys
from tempfile import NamedTemporaryFile
import unittest

if sys.version_info[0] > 2:
    import builtins  # pylint: disable=import-error, unused-import
else:
    import __builtin__  # pylint: disable=import-error

    builtins = __builtin__  # pylint: disable=invalid-name

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

# pylint: disable=wrong-import-position
from mock import patch
import requests_mock
import dxlvtapiservice


class StringMatches(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return re.match(self.pattern, other, re.DOTALL)


class StringDoesNotMatch(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return not re.match(self.pattern, other)


CONF_FILE_NAME = os.path.dirname(os.path.realpath(__file__)) + '/../config/dxlvtapiservice.config'


class VirusTotalTests(unittest.TestCase):
    """
    This class consists of unit tests for VirusTotal. Each unit test is mapped
    to an example published under virustotal module.
    """

    _TEST_HOSTNAME = "www.virustotal.com"
    _TEST_API_KEY = "mytestkey"
    _TEST_URL = "http://www.virustotal.com"
    _TEST_RESOURCE = "1234567890"
    _TEST_IP = "127.0.0.1"
    _TEST_DOMAIN = "027.ru"

    def get_api_endpoint(self, path):
        return "https://" + self._TEST_HOSTNAME + \
               "/" + path

    @staticmethod
    def expected_print_output(detail):
        json_string = json.dumps(detail, sort_keys=True,
                                 separators=(".*", ": "))
        return re.sub(r"(\.\*)+", ".*",
                      re.sub(r"[{[\]}]", ".*", json_string))

    @staticmethod
    def _run_sample(app, sample_file):
        app.run()
        with open(sample_file) as f, \
                patch.object(builtins, 'print') as mock_print:
            sample_globals = {"__file__": sample_file}
            exec (f.read(), sample_globals)  # pylint: disable=exec-used
        return mock_print

    def run_sample(self, sample_file, add_request_mocks_fn):

        with dxlvtapiservice.VirusTotalApiService("sample") as app, \
                NamedTemporaryFile(mode="w+", delete=False) as temp_config_file:
            config = ConfigParser()
            config.read(app._app_config_path)

            if not config.has_section(
                    dxlvtapiservice.VirusTotalApiService.GENERAL_CONFIG_SECTION):
                config.add_section(
                    dxlvtapiservice.VirusTotalApiService.GENERAL_CONFIG_SECTION)

            use_mock_requests = not config.has_option(
                dxlvtapiservice.VirusTotalApiService.GENERAL_CONFIG_SECTION,
                dxlvtapiservice.VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP
            ) or not config.get(
                dxlvtapiservice.VirusTotalApiService.GENERAL_CONFIG_SECTION,
                dxlvtapiservice.VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP
            )
            if use_mock_requests:
                config.set(
                    dxlvtapiservice.VirusTotalApiService.GENERAL_CONFIG_SECTION,
                    dxlvtapiservice.VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP,
                    self._TEST_API_KEY
                )
                config.write(temp_config_file)
                temp_config_file.close()
                app._app_config_path = temp_config_file.name
                with requests_mock.mock(case_sensitive=True) as req_mock:
                    if add_request_mocks_fn:
                        add_request_mocks_fn(req_mock)
                    mock_print = self._run_sample(app, sample_file)
            else:
                mock_print = self._run_sample(app, sample_file)
                req_mock = None
        return (mock_print, req_mock)


    def test_basic_domain_report_example(self):
        """
        Tests the example basic_domain_report_example.py by assessing
        positive and negative scenarios.
        """
        mock_domain_id = "123456"
        expected_domain_detail = {
            "BitDefender category": "parked",
            "Dr.Web category": "known infection source",
            "Forcepoint ThreatSeeker category": "uncategorized",
            "Websense ThreatSeeker category": "uncategorized",
            "Webutation domain info": {"Adult content": "yes", "Verdict": "malicious"},
            "categories": ["parked", "uncategorized"]
        }

        def add_create_request_mocks(req_mock):
            domain_detail_with_id = expected_domain_detail.copy()
            domain_detail_with_id["id"] = mock_domain_id
            domain_json_with_id = json.dumps(domain_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/domain/report"),
                text=domain_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_domain_report_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_domain_request = req_mock.request_history[0]
            expected_domain_request = {"domain": [self._TEST_DOMAIN],
                                       "apikey": [self._TEST_API_KEY]}
            self.assertEqual(expected_domain_request,
                             new_domain_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_domain_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_file_report_example(self):
        """
        Tests the example basic_file_report_example.py by assessing positive
        and negative scenarios.
        """
        mock_req_id = "123456"
        expected_req_detail = {
            "md5": "7657fcb7d772448a6d8504e4b20168b8",
            "resource": "7657fcb7d772448a6d8504e4b20168b8",
            "response_code": 1
        }

        def add_create_request_mocks(req_mock):
            req_detail_with_id = expected_req_detail.copy()
            req_detail_with_id["id"] = mock_req_id
            req_json_with_id = json.dumps(req_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/file/report"),
                text=req_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_file_report_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_file_request = req_mock.request_history[0]
            expected_request = {
                "apikey": [self._TEST_API_KEY],
                "resource": [self._TEST_RESOURCE]
            }
            self.assertEqual(expected_request,
                             new_file_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_req_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_file_rescan_example(self):
        """
        Tests the example basic_file_rescan_example.py by assessing positive and
        negative scenarios.
        """
        mock_req_id = "123456"
        expected_req_detail = {
            "resource": "7657fcb7d772448a6d8504e4b20168b8",
            "response_code": 1,
            "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71"
        }

        def add_create_request_mocks(req_mock):
            req_detail_with_id = expected_req_detail.copy()
            req_detail_with_id["id"] = mock_req_id
            req_json_with_id = json.dumps(req_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/file/rescan"),
                text=req_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_file_rescan_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_request = req_mock.request_history[0]
            expected_request = {
                "apikey": [self._TEST_API_KEY],
                "resource": [self._TEST_RESOURCE]
            }
            self.assertEqual(expected_request,
                             new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_req_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_ip_address_report_example(self):
        """
        Tests the example basic_ip_address_report_example.py by assessing
        positive and negative scenarios.
        """
        mock_req_id = "123456"
        expected_detail = {
            "as_owner": ".masterhost autonomous system",
            "asn": 25532,
            "country": "RU"
        }

        def add_create_request_mocks(req_mock):
            req_detail_with_id = expected_detail.copy()
            req_detail_with_id["id"] = mock_req_id
            req_json_with_id = json.dumps(req_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/ip-address/report"),
                text=req_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_ip_address_report_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_domain_request = req_mock.request_history[0]
            expected_domain_request = {"ip": [self._TEST_IP],
                                       "apikey": [self._TEST_API_KEY]}
            self.assertEqual(expected_domain_request,
                             new_domain_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_url_report_example(self):
        """
        Tests the example basic_url_report_example.py by assessing positive and
        negative scenarios.
        """
        mock_req_id = "123456"
        expected_req_detail = {
            "positives": 0,
            "resource": "http://www.virustotal.com"
            }

        def add_create_request_mocks(req_mock):
            req_detail_with_id = expected_req_detail.copy()
            req_detail_with_id["id"] = mock_req_id
            req_json_with_id = json.dumps(req_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/url/report"),
                text=req_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_url_report_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_request = req_mock.request_history[0]
            expected_request = {"apikey": [self._TEST_API_KEY],
                                "resource": [self._TEST_RESOURCE]}
            self.assertEqual(expected_request,
                             new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_req_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )

    def test_basic_url_scan_example(self):
        """
        Tests the example basic_url_scan_example.py by assessing positive and
        negative scenarios.
        """
        mock_req_id = "123456"
        expected_detail = {
            "resource": "http://www.virustotal.com/",
            "response_code": 1
        }

        def add_create_request_mocks(req_mock):
            req_detail_with_id = expected_detail.copy()
            req_detail_with_id["id"] = mock_req_id
            domain_json_with_id = json.dumps(req_detail_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/url/scan"),
                text=domain_json_with_id)

        sample_file = os.path.dirname(os.path.realpath(__file__)) + \
                      "/../sample/basic/basic_url_scan_example.py"

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            new_request = req_mock.request_history[0]
            expected_request = {"url": [self._TEST_URL],
                                "apikey": [self._TEST_API_KEY]}
            self.assertEqual(expected_request,
                             new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )
