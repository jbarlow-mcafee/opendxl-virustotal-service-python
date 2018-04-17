import sys
import unittest
import time
import os
import ConfigParser

if sys.version_info[0] > 2:
    import builtins  # pylint: disable=import-error, unused-import
else:
    import __builtin__  # pylint: disable=import-error

    builtins = __builtin__  # pylint: disable=invalid-name

# pylint: disable=wrong-import-position
from mock import patch
import dxlvtapiservice


class StringMatches(str):
    def __eq__(self, other):
        return self in other


class StringDoesNotMatch(str):
    def __eq__(self, other):
        return self not in other


CONF_FILE_NAME = os.path.dirname(os.path.realpath(__file__)) + '/../config/dxlvtapiservice.config'


class ConfigHelper():
    """
    Configuration helper to update VirusTotal config file
    """

    def updateConfig(self):
        config = ConfigParser.ConfigParser()
        config.read(CONF_FILE_NAME)
        config.set('General', 'apiKey', os.environ['VTAPIKEY'])
        for each_section in config.sections():
            for (each_key, each_val) in config.items(each_section):
                config.set(each_section, each_key, each_val)
        # Update config file with additional property
        with open(CONF_FILE_NAME, 'w') as configfile:
            config.write(configfile)
        return config
        # reset new property

    def setKeyEmpty(self, config):
        config.set('General', 'apiKey', '')
        with open(CONF_FILE_NAME, 'w') as configfile:
            config.write(configfile)


class VirtualTotalTests(unittest.TestCase):
    """
    This class consists of unit tests for VirusTotal. Each unit test  is mapped to an example published under virustotal 
    module.
    """

    def test_basic_domain_report_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_domain_report_example.py by assessing positive and negative scenarios. 
        """
        # VirusTotal Public API does not allow more than 4 API calls per minute. Hence wait for 1 min.

        # VirusTotal Public API does not allow more than 4 API calls per minute. Hence wait for 1 min.
        print "Sleep for a minute to get past VirusTotal API restriction"
        time.sleep(60)

        helper = ConfigHelper()
        config = helper.updateConfig()

        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_domain_report_example.py"

        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used
        mock_print.assert_called_with(StringMatches("BitDefender category"))
        mock_print.assert_called_with(
            StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)

    def test_basic_file_report_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_file_report_example.py by assessing positive and negative scenarios. 
        """

        helper = ConfigHelper()
        config = helper.updateConfig()

        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_file_report_example.py"
        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used
        mock_print.assert_called_with(StringMatches("md5"))
        mock_print.assert_called_with(
            StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)

    def test_basic_file_rescan_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_file_rescan_example.py by assessing positive and negative scenarios. 
        """

        helper = ConfigHelper()
        config = helper.updateConfig()

        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_file_rescan_example.py"
        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used

        mock_print.assert_called_with(StringMatches("permalink"))
        mock_print.assert_called_with(
            StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)

    def test_basic_ip_address_report_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_ip_address_report_example.py by assessing positive and negative scenarios. 
        """

        helper = ConfigHelper()
        config = helper.updateConfig()

        sample_file = os.path.dirname(
            os.path.realpath(__file__)) + "/../sample/basic/basic_ip_address_report_example.py"
        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used

        mock_print.assert_called_with(StringMatches("detected_downloaded_samples"))
        mock_print.assert_called_with(
            StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)

    def test_basic_url_report_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_url_report_example.py by assessing positive and negative scenarios. 
        """

        helper = ConfigHelper()
        config = helper.updateConfig()

        # VirusTotal Public API does not allow more than 4 API calls per minute. Hence wait for 1 min.
        print "Sleep for a minute to get past VirusTotal API restriction"
        time.sleep(60)
        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_url_report_example.py"
        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used

        mock_print.assert_called_with(StringMatches("scans"))
        mock_print.assert_called_with(StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)

    def test_basic_url_scan_example(self):  # pylint: disable=no-self-use
        """
            Tests the example basic_url_scan_example.py by assessing positive and negative scenarios. 
        """
        # VirusTotal Public API does not allow more than 4 API calls per minute. Hence wait for 1 min.
        print "Sleep for a minute to get past VirusTotal API restriction"
        time.sleep(60)

        helper = ConfigHelper()
        config = helper.updateConfig()

        sample_file = os.path.dirname(os.path.realpath(__file__)) + "/../sample/basic/basic_url_scan_example.py"
        sample_globals = {"__file__": sample_file}
        with dxlvtapiservice.VirusTotalApiService("config") as app:
            app.run
            with open(sample_file) as file, \
                    patch.object(builtins, 'print') as mock_print:
                exec (file.read(), sample_globals)  # pylint: disable=exec-used

        mock_print.assert_called_with(StringMatches("scan_id"))
        mock_print.assert_called_with(StringDoesNotMatch("Error invoking service"))

        helper.setKeyEmpty(config)
