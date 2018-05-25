from __future__ import absolute_import
import os
import base64
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
import dxlvtapiservice
import requests_mock


class StringMatches(str):
    def __eq__(self, other):
        return self in other


class StringDoesNotMatch(str):
    def __eq__(self, other):
        return self not in other


CONF_FILE_NAME = os.path.dirname(os.path.realpath(__file__)) + '/../config/dxlvtapiservice.config'


class VirusTotalTests(unittest.TestCase):
    """
    This class consists of unit tests for VirusTotal. Each unit test  is mapped to an example published under virustotal 
    module.
    """

    _TEST_HOSTNAME = "www.virustotal.com"
    _TEST_API_KEY = "myspecialkey"
    # _TEST_API_PORT = "443"
    _TEST_API_USER = "myspecialuser"

    def get_api_endpoint(self, path):
        return "https://" + self._TEST_HOSTNAME + \
               "/" + path

    @staticmethod
    def expected_print_output(title, detail):
        return_value = title + json.dumps(
            detail, sort_keys=True,
            separators=(".*", ": ")).replace("{", ".*")
        return re.sub(r"[\[}\]]", "", return_value)

    @staticmethod
    def _run_sample(app, sample_file):
        app.run()
        with open(sample_file) as f, \
                patch.object(builtins, 'print') as mock_print:
            sample_globals = {"__file__": sample_file}
            exec (f.read(), sample_globals)  # pylint: disable=exec-used
        return mock_print

    def run_sample(self, sample_file, add_request_mocks_fn):

        # sample_file1 = os.path.dirname(os.path.realpath(__file__)) + "/../config/dxlvtapiservice.config"


        # dxlvtapiservice.VirusTotalApiService.VTAPI_URL_FORMAT="https://" + self._TEST_HOSTNAME + ":" + self._TEST_API_PORT + \
        #                                                      "/"
        # with dxlvtapiservice.VirusTotalApiService(os.path.dirname(os.path.realpath(__file__))) as app, \
        with dxlvtapiservice.VirusTotalApiService("sample") as app, \
                NamedTemporaryFile(mode="w+", delete=False) as temp_config_file:
            config = ConfigParser()
            config.read(app._app_config_path)
            # config.read(os.path.dirname(os.path.realpath(__file__)) + "/../config/dxlvtapiservice.config")
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
                # temp_config_file.flush()
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

    #################################################################################################################

    # def test_basic_domain_report_example(self):  # pylint: disable=no-self-use
    #     """
    #         Tests the example basic_domain_report_example.py by assessing positive and negative scenarios.
    #     """
    #     config = ConfigParser()
    #     config.read(CONF_FILE_NAME)
    #     sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_domain_report_example.py"
    #     #sample_file1 = os.path.dirname(os.path.realpath(__file__)) + "/../config/dxlvtapiservice.config"
    #     apiKey = config.get('General', 'apiKey')
    #     #The following condition determines if the API key is provided in dxlvtapiservice.config.
    #     #When the API key is present, the real service will be invoked. Otherwise the mock service will be invoked.
    #     if apiKey :
    #         sample_globals = {"__file__": sample_file}
    #         with dxlvtapiservice.VirusTotalApiService("config") as app:
    #             app.run
    #             with open(sample_file) as file, \
    #                     patch.object(builtins, 'print') as mock_print:
    #                 exec (file.read(), sample_globals)  # pylint: disable=exec-used
    #         mock_print.assert_called_with(StringMatches("BitDefender category"))
    #         mock_print.assert_called_with(
    #             StringDoesNotMatch("Error invoking service"))
    #     else:
    #         print "Invoke mock object"
    #
    #         assert False, "Error invoking service"

    #################################################################################################################

    def test_basic_domain_example(self):
        # mock_domain_id = "apikey=mysecretkey"
        mock_domain_id = "123456"
        mock_api_password = "mysecretpassword"
        expected_domain_detail = {
            "BitDefender category": "parked",
            "Dr.Web category": "known infection source",
            "Forcepoint ThreatSeeker category": "uncategorized",
            "Websense ThreatSeeker category": "uncategorized",
            "Webutation domain info": {"Adult content": "yes", "Safety score": 41, "Verdict": "malicious"},
            "categories": ["parked", "uncategorized"]
        }

        def add_create_domain_request_mocks(req_mock):
            domain_detail_with_id = expected_domain_detail.copy()
            domain_detail_with_id["id"] = mock_domain_id
            domain_json_with_id = json.dumps(domain_detail_with_id)
            req_mock.post(self.get_api_endpoint("vtapi/v2/domain/report"),
                          text=domain_json_with_id)
            req_mock.get(
                self.get_api_endpoint("vtapi/v2/domain/report".format(mock_domain_id)),
                text=domain_json_with_id)
            print "Executed add_create_domain_request_mocks"
            # check  self._app.VTAPI_URL_FORMAT

        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_domain_report_example.py"
        print "Sample file ", sample_file

        mock_print, req_mock = self.run_sample(
            sample_file,
            add_create_domain_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            # self.assertEqual(1, request_count)

            new_domain_request = req_mock.request_history[0]
            new_domain_request_payload = new_domain_request.json
            domain_detail_with_source_ref = expected_domain_detail.copy()
            domain_detail_with_source_ref["sourceRef"] = \
                new_domain_request_payload.get("sourceRef", "bogus")
            self.assertEqual(domain_detail_with_source_ref,
                             new_domain_request_payload)

            expected_creds = "Basic {}".format(base64.b64encode(
                "{}:{}".format(self._TEST_API_KEY,
                               mock_api_password).encode("utf8")).decode("utf8"))
            for request in req_mock.request_history:
                self.assertEqual(expected_creds,
                                 request.headers["Authorization"])

        mock_print.assert_any_call(
            StringMatches(
                self.expected_print_output(
                    "Response for the create domain request:",
                    expected_domain_detail
                )
            )
        )
        mock_print.assert_any_call(
            StringMatches(
                self.expected_print_output(
                    "Response for the get domain request:", expected_domain_detail
                )
            )
        )
        mock_print.assert_any_call(StringDoesNotMatch("Error invoking request"))

        def add_search_domain_request_mocks(req_mock):
            req_mock.get(self.get_api_endpoint("vtapi/v2/domain/report?domain=027.ru&apikey=--api-key--"),
                         text=json.dumps(expected_domain_detail))

        mock_print, req_mock = self.run_sample(
            "sample/basic/basic_domain_report_example.py",
            add_search_domain_request_mocks
        )

        if req_mock:
            request_count = len(req_mock.request_history)
            self.assertEqual(1, request_count)

            search_domain_request = req_mock.request_history[0]
            self.assertEqual({
                "query": {"_string": "BitDefender category"}
            }, search_domain_request.json())


        # mock_print.assert_any_call(
        #     StringMatches(
        #         self.expected_print_output(
        #             "Response for the search domain request:",
        #             expected_domain_detail
        #         )
        #     )
        # )
        mock_print.assert_any_call(StringDoesNotMatch("Error invoking request"))
