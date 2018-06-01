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


CONF_FILE_NAME = os.path.dirname(os.path.realpath(__file__)) + \
                 '/../config/dxlvtapiservice.config'


class VirusTotalTests(unittest.TestCase):
    """
    This class consists of unit tests for VirusTotal. Each unit test is mapped
    to an example published under virustotal module.
    """

    _TEST_HOSTNAME = "www.virustotal.com"
    _TEST_API_KEY = "mytestkey"

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
            exec(f.read(), sample_globals)  # pylint: disable=exec-used
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
        test_domain = "027.ru"

        expected_domain_detail = {
            "BitDefender category": "parked",
            "Dr.Web category": "known infection source",
            "Forcepoint ThreatSeeker category": "uncategorized",
            "Websense ThreatSeeker category": "uncategorized",
            "Webutation domain info": {"Adult content": "yes", "Verdict": "malicious"},
            "categories": ["parked", "uncategorized"]
        }

        def add_create_request_mocks(req_mock):
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/domain/report"),
                text=json.dumps(expected_domain_detail))

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
            expected_domain_request = {"domain": [test_domain],
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
        test_resource = "7657fcb7d772448a6d8504e4b20168b8"

        expected_report_detail = {
            "md5": test_resource,
            "resource": test_resource,
            "response_code": 1
        }

        def add_create_request_mocks(req_mock):
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/file/report"),
                text=json.dumps(expected_report_detail))

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
                "resource": [test_resource]
            }
            self.assertEqual(expected_request,
                             new_file_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_report_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_file_rescan_example(self):
        """
        Tests the example basic_file_rescan_example.py by assessing positive and
        negative scenarios.
        """
        test_resource = "7657fcb7d772448a6d8504e4b20168b8"

        expected_rescan_detail = {
            "resource": test_resource,
            "response_code": 1,
            "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71"
        }

        def add_create_request_mocks(req_mock):
            req_mock.post(
                self.get_api_endpoint("vtapi/v2/file/rescan"),
                text=json.dumps(expected_rescan_detail))

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
                "resource": [test_resource]
            }
            self.assertEqual(expected_request,
                             new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_rescan_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_ip_address_report_example(self):
        """
        Tests the example basic_ip_address_report_example.py by assessing
        positive and negative scenarios.
        """
        test_ip = "90.156.201.27"

        expected_report_detail = {
            "as_owner": ".masterhost autonomous system",
            "asn": 25532,
            "country": "RU"
        }

        def add_create_request_mocks(req_mock):
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/ip-address/report"),
                text=json.dumps(expected_report_detail))

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
            expected_domain_request = {"ip": [test_ip],
                                       "apikey": [self._TEST_API_KEY]}
            self.assertEqual(expected_domain_request, new_domain_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_report_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )


    def test_basic_url_report_example(self):
        """
        Tests the example basic_url_report_example.py by assessing positive and
        negative scenarios.
        """
        test_resource = "http://www.virustotal.com"

        expected_report_detail = {
            "positives": 0,
            "resource": test_resource
        }

        def add_create_request_mocks(req_mock):
            req_mock.post(
                self.get_api_endpoint("vtapi/v2/url/report"),
                text=json.dumps(expected_report_detail))

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
                                "resource": [test_resource]}
            self.assertEqual(expected_request, new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_report_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )

    def test_basic_url_scan_example(self):
        """
        Tests the example basic_url_scan_example.py by assessing positive and
        negative scenarios.
        """
        test_url_request = "http://www.virustotal.com"
        test_url_response = test_url_request + "/"

        expected_scan_detail = {
            "resource": test_url_response,
            "url": test_url_response,
            "response_code": 1
        }

        def add_create_request_mocks(req_mock):
            req_mock.post(
                self.get_api_endpoint("vtapi/v2/url/scan"),
                text=json.dumps(expected_scan_detail))

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
            expected_request = {"url": [test_url_request],
                                "apikey": [self._TEST_API_KEY]}
            self.assertEqual(expected_request,
                             new_request.qs)

        mock_print.assert_called_once_with(
            StringMatches(self.expected_print_output(expected_scan_detail))
        )
        mock_print.assert_called_once_with(
            StringDoesNotMatch("Error invoking request")
        )
