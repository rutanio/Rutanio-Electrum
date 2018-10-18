import unittest
from electrum_civx.util import format_satoshis, parse_URI

from . import SequentialTestCase


class TestUtil(SequentialTestCase):

    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_negative(self):
        result = format_satoshis(-1234)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def test_format_fee(self):
        result = format_satoshis(1700/1000, 0, 0)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_fee_precision(self):
        result = format_satoshis(1666/1000, 0, 0, precision=6)
        expected = "1.666"
        self.assertEqual(expected, result)

        result = format_satoshis(1666/1000, 0, 0, precision=1)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces(self):
        result = format_satoshis(12340, whitespaces=True)
        expected = "     0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(1234, whitespaces=True)
        expected = "     0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces_negative(self):
        result = format_satoshis(-12340, whitespaces=True)
        expected = "    -0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(-1234, whitespaces=True)
        expected = "    -0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn'})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn'})


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?label=electrum%20test',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'label': 'electrum-civx test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?message=electrum%20test',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'message': 'electrum-civx test', 'memo': 'electrum-civx test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?amount=0.0003',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?test=test',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI('civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
                                {'address': 'CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn', 'amount': 4000, 'label': 'electrum-civx-test', 'message': u'electrum-civx test', 'memo': u'electrum-civx test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('civx:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(BaseException, parse_URI, 'civx:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(BaseException, parse_URI, 'notcivx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn')

    def test_parse_URI_parameter_polution(self):
        self.assertRaises(Exception, parse_URI, 'civx:CaEnKKCdfRChUL7zLz6Ur1S4fYoT3pajmn?amount=0.0003&label=test&amount=30.0')
