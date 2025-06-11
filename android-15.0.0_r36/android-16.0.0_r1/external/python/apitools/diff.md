```diff
diff --git a/MANIFEST.in b/MANIFEST.in
index 7585bef..6c9281a 100644
--- a/MANIFEST.in
+++ b/MANIFEST.in
@@ -1,3 +1,4 @@
+include LICENSE
 include *.py
 include *.txt
 include *.md
diff --git a/METADATA b/METADATA
index e5ecb93..ebf821e 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/python/apitools
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "apitools"
 description: "google-apitools is a collection of utilities to make it easier to build client-side tools, especially those that talk to Google APIs."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/google/apitools"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/google/apitools"
-  }
-  version: "v0.5.31"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2020
-    month: 5
-    day: 14
+    year: 2025
+    month: 1
+    day: 17
+  }
+  homepage: "https://github.com/google/apitools"
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/apitools"
+    version: "v0.5.34"
   }
 }
diff --git a/OWNERS b/OWNERS
index fcb8c0e..86e39cf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@
 # or people with more than 10 commits last year.
 # Please update this list if you find better owner candidates.
 kevcheng@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.rst b/README.rst
index e9eae94..7745469 100644
--- a/README.rst
+++ b/README.rst
@@ -1,3 +1,5 @@
+**DEPRECATED - Please see alternatives below**
+
 google-apitools
 ===============
 
@@ -6,9 +8,14 @@ google-apitools
 ``google-apitools`` is a collection of utilities to make it easier to build
 client-side tools, especially those that talk to Google APIs.
 
-**NOTE**: This library is stable, but in maintenance mode, and not under
-active development. However, any bugs or security issues will be fixed
-promptly.
+**NOTE**: This library is deprecated and unsupported. Please read below for suggested alternatives.
+
+Alternatives to apitools
+-----------------------
+For the official Cloud client libraries used to communicating with Google Cloud APIs, go to https://cloud.google.com/apis/docs/cloud-client-libraries.
+
+To generate Python API client libraries for APIs specified by protos, such as those inside Google, see https://github.com/googleapis/gapic-generator-python. 
+API client library generators for other languages can be found in https://github.com/googleapis.
 
 Installing as a library
 -----------------------
diff --git a/apitools/base/protorpclite/messages.py b/apitools/base/protorpclite/messages.py
index 0d564e9..500a95c 100644
--- a/apitools/base/protorpclite/messages.py
+++ b/apitools/base/protorpclite/messages.py
@@ -1139,12 +1139,14 @@ class FieldList(list):
 
     def append(self, value):
         """Validate item appending to list."""
-        self.__field.validate_element(value)
+        if getattr(self, '_FieldList__field', None):
+            self.__field.validate_element(value)
         return list.append(self, value)
 
     def extend(self, sequence):
         """Validate extension of list."""
-        self.__field.validate(sequence)
+        if getattr(self, '_FieldList__field', None):
+            self.__field.validate(sequence)
         return list.extend(self, sequence)
 
     def insert(self, index, value):
diff --git a/apitools/base/protorpclite/protojson.py b/apitools/base/protorpclite/protojson.py
index 4f3fdeb..aea4aa3 100644
--- a/apitools/base/protorpclite/protojson.py
+++ b/apitools/base/protorpclite/protojson.py
@@ -279,14 +279,33 @@ class ProtoJson(object):
                     message.set_unrecognized_field(key, value, variant)
                 continue
 
+            is_enum_field = isinstance(field, messages.EnumField)
+            is_unrecognized_field = False
             if field.repeated:
                 # This should be unnecessary? Or in fact become an error.
                 if not isinstance(value, list):
                     value = [value]
-                valid_value = [self.decode_field(field, item)
-                               for item in value]
+                valid_value = []
+                for item in value:
+                    try:
+                        v = self.decode_field(field, item)
+                        if is_enum_field and v is None:
+                            continue
+                    except messages.DecodeError:
+                        if not is_enum_field:
+                            raise
+
+                        is_unrecognized_field = True
+                        continue
+                    valid_value.append(v)
+
                 setattr(message, field.name, valid_value)
+                if is_unrecognized_field:
+                    variant = self.__find_variant(value)
+                    if variant:
+                        message.set_unrecognized_field(key, value, variant)
                 continue
+            
             # This is just for consistency with the old behavior.
             if value == []:
                 continue
@@ -294,7 +313,7 @@ class ProtoJson(object):
                 setattr(message, field.name, self.decode_field(field, value))
             except messages.DecodeError:
                 # Save unknown enum values.
-                if not isinstance(field, messages.EnumField):
+                if not is_enum_field:
                     raise
                 variant = self.__find_variant(value)
                 if variant:
@@ -327,7 +346,7 @@ class ProtoJson(object):
 
         elif isinstance(field, message_types.DateTimeField):
             try:
-                return util.decode_datetime(value)
+                return util.decode_datetime(value, truncate_time=True)
             except ValueError as err:
                 raise messages.DecodeError(err)
 
diff --git a/apitools/base/protorpclite/protojson_test.py b/apitools/base/protorpclite/protojson_test.py
index 7a8f875..a5fb97a 100644
--- a/apitools/base/protorpclite/protojson_test.py
+++ b/apitools/base/protorpclite/protojson_test.py
@@ -152,6 +152,8 @@ class ProtojsonTest(test_util.TestCase,
     encoded_string_types = '{"string_value": "Latin"}'
 
     encoded_invalid_enum = '{"enum_value": "undefined"}'
+    
+    encoded_invalid_repeated_enum = '{"enum_value": ["VAL1", "undefined"]}'
 
     def testConvertIntegerToFloat(self):
         """Test that integers passed in to float fields are converted.
@@ -440,7 +442,7 @@ class ProtojsonTest(test_util.TestCase,
         """Test decoding improperly encoded base64 bytes value."""
         self.assertRaisesWithRegexpMatch(
             messages.DecodeError,
-            'Base64 decoding error: Incorrect padding',
+            'Base64 decoding error',
             protojson.decode_message,
             test_util.OptionalMessage,
             '{"bytes_value": "abcdefghijklmnopq"}')
diff --git a/apitools/base/protorpclite/test_util.py b/apitools/base/protorpclite/test_util.py
index 89e3a68..4d45ac9 100644
--- a/apitools/base/protorpclite/test_util.py
+++ b/apitools/base/protorpclite/test_util.py
@@ -428,6 +428,11 @@ class ProtoConformanceTestBase(object):
         <OptionalMessage
           enum_value: (invalid value for serialization type)
           >
+
+      encoded_invalid_repeated_enum:
+        <RepeatedMessage
+          enum_value: (invalid value for serialization type)
+          >
     """
 
     encoded_empty_message = ''
@@ -589,6 +594,19 @@ class ProtoConformanceTestBase(object):
         self.assertEqual(message, decoded)
         encoded = self.PROTOLIB.encode_message(decoded)
         self.assertEqual(self.encoded_invalid_enum, encoded)
+    
+    def testDecodeInvalidRepeatedEnumType(self):
+        # Since protos need to be able to add new enums, a message should be
+        # successfully decoded even if the enum value is invalid. Encoding the
+        # decoded message should result in equivalence with the original
+        # encoded message containing an invalid enum.
+        decoded = self.PROTOLIB.decode_message(RepeatedMessage,
+                                               self.encoded_invalid_repeated_enum)
+        message = RepeatedMessage()
+        message.enum_value = [RepeatedMessage.SimpleEnum.VAL1]
+        self.assertEqual(message, decoded)
+        encoded = self.PROTOLIB.encode_message(decoded)
+        self.assertEqual(self.encoded_invalid_repeated_enum, encoded)
 
     def testDateTimeNoTimeZone(self):
         """Test that DateTimeFields are encoded/decoded correctly."""
diff --git a/apitools/base/protorpclite/util.py b/apitools/base/protorpclite/util.py
index b0ba240..c996312 100644
--- a/apitools/base/protorpclite/util.py
+++ b/apitools/base/protorpclite/util.py
@@ -20,6 +20,7 @@ from __future__ import with_statement
 import datetime
 import functools
 import inspect
+import logging
 import os
 import re
 import sys
@@ -147,7 +148,7 @@ def positional(max_positional_args):
     if isinstance(max_positional_args, six.integer_types):
         return positional_decorator
     else:
-        args, _, _, defaults = inspect.getargspec(max_positional_args)
+        args, _, _, defaults, *_ = inspect.getfullargspec(max_positional_args)
         if defaults is None:
             raise ValueError(
                 'Functions with no keyword arguments must specify '
@@ -238,11 +239,13 @@ class TimeZoneOffset(datetime.tzinfo):
         return datetime.timedelta(0)
 
 
-def decode_datetime(encoded_datetime):
+def decode_datetime(encoded_datetime, truncate_time=False):
     """Decode a DateTimeField parameter from a string to a python datetime.
 
     Args:
       encoded_datetime: A string in RFC 3339 format.
+      truncate_time: If true, truncate time string with precision higher than
+          microsecs.
 
     Returns:
       A datetime object with the date and time specified in encoded_datetime.
@@ -264,7 +267,26 @@ def decode_datetime(encoded_datetime):
     else:
         format_string = '%Y-%m-%dT%H:%M:%S'
 
-    decoded_datetime = datetime.datetime.strptime(time_string, format_string)
+    try:
+        decoded_datetime = datetime.datetime.strptime(time_string,
+                                                      format_string)
+    except ValueError:
+        if truncate_time and '.' in time_string:
+            datetime_string, decimal_secs = time_string.split('.')
+            if len(decimal_secs) > 6:
+                # datetime can handle only microsecs precision.
+                truncated_time_string = '{}.{}'.format(
+                    datetime_string, decimal_secs[:6])
+                decoded_datetime = datetime.datetime.strptime(
+                    truncated_time_string,
+                    format_string)
+                logging.warning(
+                    'Truncating the datetime string from %s to %s',
+                    time_string, truncated_time_string)
+            else:
+                raise
+        else:
+            raise
 
     if not time_zone_match:
         return decoded_datetime
diff --git a/apitools/base/protorpclite/util_test.py b/apitools/base/protorpclite/util_test.py
index 14e7f7e..5d5d3c8 100644
--- a/apitools/base/protorpclite/util_test.py
+++ b/apitools/base/protorpclite/util_test.py
@@ -187,6 +187,13 @@ class DateTimeTests(test_util.TestCase):
             expected = datetime.datetime(*datetime_vals)
             self.assertEquals(expected, decoded)
 
+    def testDecodeDateTimeWithTruncateTime(self):
+       """Test that nanosec time is truncated with truncate_time flag."""
+       decoded = util.decode_datetime('2012-09-30T15:31:50.262343123',
+                                      truncate_time=True)
+       expected = datetime.datetime(2012, 9, 30, 15, 31, 50, 262343)
+       self.assertEquals(expected, decoded)
+
     def testDateTimeTimeZones(self):
         """Test that a datetime string with a timezone is decoded correctly."""
         tests = (
@@ -218,7 +225,8 @@ class DateTimeTests(test_util.TestCase):
                                 '2012-09-30T15:31Z',
                                 '2012-09-30T15:31:50ZZ',
                                 '2012-09-30T15:31:50.262 blah blah -08:00',
-                                '1000-99-99T25:99:99.999-99:99'):
+                                '1000-99-99T25:99:99.999-99:99',
+                                '2012-09-30T15:31:50.262343123'):
             self.assertRaises(
                 ValueError, util.decode_datetime, datetime_string)
 
diff --git a/apitools/base/py/base_api.py b/apitools/base/py/base_api.py
index 1d490c3..3a4071b 100644
--- a/apitools/base/py/base_api.py
+++ b/apitools/base/py/base_api.py
@@ -271,6 +271,9 @@ class BaseApiClient(object):
         self.check_response_func = check_response_func
         self.retry_func = retry_func
         self.response_encoding = response_encoding
+        # Since we can't change the init arguments without regenerating clients,
+        # offer this hook to affect FinalizeTransferUrl behavior.
+        self.overwrite_transfer_urls_with_client_base = False
 
         # TODO(craigcitro): Finish deprecating these fields.
         _ = model
@@ -454,8 +457,11 @@ class BaseApiClient(object):
     def FinalizeTransferUrl(self, url):
         """Modify the url for a given transfer, based on auth and version."""
         url_builder = _UrlBuilder.FromUrl(url)
-        if self.global_params.key:
+        if getattr(self.global_params, 'key', None):
             url_builder.query_params['key'] = self.global_params.key
+        if self.overwrite_transfer_urls_with_client_base:
+            client_url_builder = _UrlBuilder.FromUrl(self._url)
+            url_builder.base_url = client_url_builder.base_url
         return url_builder.url
 
 
diff --git a/apitools/base/py/base_api_test.py b/apitools/base/py/base_api_test.py
index 27b1727..9de1de8 100644
--- a/apitools/base/py/base_api_test.py
+++ b/apitools/base/py/base_api_test.py
@@ -329,6 +329,15 @@ class BaseApiTest(unittest.TestCase):
         self.assertEqual('http://www.example.com/path:withJustColon',
                          http_request.url)
 
+    def testOverwritesTransferUrlBase(self):
+        client = self.__GetFakeClient()
+        client.overwrite_transfer_urls_with_client_base = True
+        client._url = 'http://custom.p.googleapis.com/'
+        observed = client.FinalizeTransferUrl(
+            'http://normal.googleapis.com/path')
+        expected = 'http://custom.p.googleapis.com/path'
+        self.assertEqual(observed, expected)
+
 
 if __name__ == '__main__':
     unittest.main()
diff --git a/apitools/base/py/batch_test.py b/apitools/base/py/batch_test.py
index 90cf4fb..ae8afe6 100644
--- a/apitools/base/py/batch_test.py
+++ b/apitools/base/py/batch_test.py
@@ -357,7 +357,7 @@ class BatchTest(unittest.TestCase):
         self._DoTestConvertIdToHeader('blah', '<%s+blah>')
 
     def testConvertIdThatNeedsEscaping(self):
-        self._DoTestConvertIdToHeader('~tilde1', '<%s+%%7Etilde1>')
+        self._DoTestConvertIdToHeader(' space1', '<%s+%%20space1>')
 
     def _DoTestConvertHeaderToId(self, header, expected_id):
         batch_request = batch.BatchHttpRequest('https://www.example.com')
diff --git a/apitools/base/py/encoding_helper.py b/apitools/base/py/encoding_helper.py
index c962aaf..2d8a449 100644
--- a/apitools/base/py/encoding_helper.py
+++ b/apitools/base/py/encoding_helper.py
@@ -531,10 +531,12 @@ def _ProcessUnknownEnums(message, encoded_message):
     decoded_message = json.loads(six.ensure_str(encoded_message))
     for field in message.all_fields():
         if (isinstance(field, messages.EnumField) and
-                field.name in decoded_message and
-                message.get_assigned_value(field.name) is None):
-            message.set_unrecognized_field(
-                field.name, decoded_message[field.name], messages.Variant.ENUM)
+                field.name in decoded_message):
+            value = message.get_assigned_value(field.name)
+            if ((field.repeated and len(value) != len(decoded_message[field.name])) or
+                    value is None):
+                message.set_unrecognized_field(
+                    field.name, decoded_message[field.name], messages.Variant.ENUM)
     return message
 
 
diff --git a/apitools/base/py/encoding_test.py b/apitools/base/py/encoding_test.py
index 54058a2..a681670 100644
--- a/apitools/base/py/encoding_test.py
+++ b/apitools/base/py/encoding_test.py
@@ -91,7 +91,8 @@ class MessageWithEnum(messages.Message):
 
     field_one = messages.EnumField(ThisEnum, 1)
     field_two = messages.EnumField(ThisEnum, 2, default=ThisEnum.VALUE_TWO)
-    ignored_field = messages.EnumField(ThisEnum, 3)
+    field_three = messages.EnumField(ThisEnum, 3, repeated=True)
+    ignored_field = messages.EnumField(ThisEnum, 4)
 
 
 @encoding.MapUnrecognizedFields('additionalProperties')
@@ -257,6 +258,17 @@ class EncodingTest(unittest.TestCase):
                                                 value_default=None),
                 ('BAD_VALUE', messages.Variant.ENUM))
 
+    def testCopyProtoMessageInvalidRepeatedEnum(self):
+        json_msg = '{"field_three": ["VALUE_ONE", "BAD_VALUE"]}'
+        orig_msg = encoding.JsonToMessage(MessageWithEnum, json_msg)
+        new_msg = encoding.CopyProtoMessage(orig_msg)
+        for msg in (orig_msg, new_msg):
+            self.assertEqual(msg.all_unrecognized_fields(), ['field_three'])
+            self.assertEqual(
+                msg.get_unrecognized_field_info('field_three',
+                                                value_default=None),
+                (['VALUE_ONE', 'BAD_VALUE'], messages.Variant.ENUM))
+
     def testCopyProtoMessageAdditionalProperties(self):
         msg = AdditionalPropertiesMessage(additionalProperties=[
             AdditionalPropertiesMessage.AdditionalProperty(
@@ -279,6 +291,19 @@ class EncodingTest(unittest.TestCase):
                     'field_one', value_default=None),
                 ('BAD_VALUE', messages.Variant.ENUM))
 
+    def testCopyProtoMessageMappingInvalidRepeatedEnum(self):
+        json_msg = '{"key_one": {"field_three": ["VALUE_ONE", "BAD_VALUE"]}}'
+        orig_msg = encoding.JsonToMessage(MapToMessageWithEnum, json_msg)
+        new_msg = encoding.CopyProtoMessage(orig_msg)
+        for msg in (orig_msg, new_msg):
+            self.assertEqual(
+                msg.additionalProperties[0].value.all_unrecognized_fields(),
+                ['field_three'])
+            self.assertEqual(
+                msg.additionalProperties[0].value.get_unrecognized_field_info(
+                    'field_three', value_default=None),
+                (['VALUE_ONE', 'BAD_VALUE'], messages.Variant.ENUM))
+
     def testBytesEncoding(self):
         b64_str = 'AAc+'
         b64_msg = '{"field": "%s"}' % b64_str
@@ -363,6 +388,13 @@ class EncodingTest(unittest.TestCase):
         new_msg = encoding.MessageToJson(msg)
         self.assertEqual('{"key_one": {"field_one": "BAD_VALUE"}}', new_msg)
 
+    def testInvalidRepeatedEnumEncodingInAMap(self):
+        json_msg = '{"key_one": {"field_three": ["VALUE_ONE", "BAD_VALUE"]}}'
+        msg = encoding.JsonToMessage(MapToMessageWithEnum, json_msg)
+        new_msg = encoding.MessageToJson(msg)
+        self.assertEqual(
+            '{"key_one": {"field_three": ["VALUE_ONE", "BAD_VALUE"]}}', new_msg)
+
     def testIncludeFields(self):
         msg = SimpleMessage()
         self.assertEqual('{}', encoding.MessageToJson(msg))
@@ -513,7 +545,8 @@ class EncodingTest(unittest.TestCase):
 
     def testUnknownEnumNestedRoundtrip(self):
         json_with_typo = ('{"outer_key": {"key_one": {"field_one": '
-                          '"VALUE_OEN", "field_two": "VALUE_OEN"}}}')
+                          '"VALUE_OEN", "field_two": "VALUE_OEN", '
+                          '"field_three": ["VALUE_ONE", "BAD_VALUE"]}}}')
         msg = encoding.JsonToMessage(NestedAdditionalPropertiesWithEnumMessage,
                                      json_with_typo)
         self.assertEqual(json.loads(json_with_typo),
diff --git a/apitools/base/py/transfer.py b/apitools/base/py/transfer.py
index e2541e3..0b18132 100644
--- a/apitools/base/py/transfer.py
+++ b/apitools/base/py/transfer.py
@@ -236,7 +236,7 @@ class Download(_Transfer):
 
     @classmethod
     def FromData(cls, stream, json_data, http=None, auto_transfer=None,
-                 **kwds):
+                 client=None, **kwds):
         """Create a new Download object from a stream and serialized data."""
         info = json.loads(json_data)
         missing_keys = cls._REQUIRED_SERIALIZATION_KEYS - set(info.keys())
@@ -249,10 +249,15 @@ class Download(_Transfer):
             download.auto_transfer = auto_transfer
         else:
             download.auto_transfer = info['auto_transfer']
+        if client is not None:
+            url = client.FinalizeTransferUrl(info['url'])
+        else:
+            url = info['url']
+
         setattr(download, '_Download__progress', info['progress'])
         setattr(download, '_Download__total_size', info['total_size'])
         download._Initialize(  # pylint: disable=protected-access
-            http, info['url'])
+            http, url)
         return download
 
     @property
@@ -560,6 +565,9 @@ if six.PY3:
                 return
             self.write(msg._payload)
 
+        def _encode(self, s):
+            return s.encode('ascii', 'surrogateescape')
+
         # Default body handler
         _writeBody = _handle_text
 
@@ -634,7 +642,7 @@ class Upload(_Transfer):
 
     @classmethod
     def FromData(cls, stream, json_data, http, auto_transfer=None,
-                 gzip_encoded=False, **kwds):
+                 gzip_encoded=False, client=None, **kwds):
         """Create a new Upload of stream from serialized json_data and http."""
         info = json.loads(json_data)
         missing_keys = cls._REQUIRED_SERIALIZATION_KEYS - set(info.keys())
@@ -655,9 +663,14 @@ class Upload(_Transfer):
             upload.auto_transfer = auto_transfer
         else:
             upload.auto_transfer = info['auto_transfer']
+        if client is not None:
+          url = client.FinalizeTransferUrl(info['url'])
+        else:
+          url = info['url']
+
         upload.strategy = RESUMABLE_UPLOAD
         upload._Initialize(  # pylint: disable=protected-access
-            http, info['url'])
+            http, url)
         upload.RefreshResumableUploadState()
         upload.EnsureInitialized()
         if upload.auto_transfer:
diff --git a/apitools/base/py/transfer_test.py b/apitools/base/py/transfer_test.py
index 4a9e79c..7961b4b 100644
--- a/apitools/base/py/transfer_test.py
+++ b/apitools/base/py/transfer_test.py
@@ -19,6 +19,7 @@ import string
 import unittest
 
 import httplib2
+import json
 import mock
 import six
 from six.moves import http_client
@@ -243,6 +244,21 @@ class TransferTest(unittest.TestCase):
             self.assertEqual(string.ascii_lowercase + string.ascii_uppercase,
                              download_stream.getvalue())
 
+    # @mock.patch.object(transfer.Upload, 'RefreshResumableUploadState',
+    #                    new=mock.Mock())
+    def testFinalizesTransferUrlIfClientPresent(self):
+        """Tests download's enforcement of client custom endpoints."""
+        mock_client = mock.Mock()
+        fake_json_data = json.dumps({
+            'auto_transfer': False,
+            'progress': 0,
+            'total_size': 0,
+            'url': 'url',
+        })
+        transfer.Download.FromData(six.BytesIO(), fake_json_data,
+                                   client=mock_client)
+        mock_client.FinalizeTransferUrl.assert_called_once_with('url')
+
     def testMultipartEncoding(self):
         # This is really a table test for various issues we've seen in
         # the past; see notes below for particular histories.
@@ -574,3 +590,19 @@ class UploadTest(unittest.TestCase):
 
             # Ensure the mock was called the correct number of times.
             self.assertEquals(make_request.call_count, len(responses))
+
+    @mock.patch.object(transfer.Upload, 'RefreshResumableUploadState',
+                       new=mock.Mock())
+    def testFinalizesTransferUrlIfClientPresent(self):
+        """Tests upload's enforcement of client custom endpoints."""
+        mock_client = mock.Mock()
+        mock_http = mock.Mock()
+        fake_json_data = json.dumps({
+            'auto_transfer': False,
+            'mime_type': '',
+            'total_size': 0,
+            'url': 'url',
+        })
+        transfer.Upload.FromData(self.sample_stream, fake_json_data, mock_http,
+                                 client=mock_client)
+        mock_client.FinalizeTransferUrl.assert_called_once_with('url')
diff --git a/apitools/data/__init__.py b/apitools/data/__init__.py
deleted file mode 100644
index 463cb42..0000000
--- a/apitools/data/__init__.py
+++ /dev/null
@@ -1,20 +0,0 @@
-#!/usr/bin/env python
-#
-# Copyright 2015 Google Inc.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Shared __init__.py for apitools."""
-
-from pkgutil import extend_path
-__path__ = extend_path(__path__, __name__)
diff --git a/apitools/data/apitools_client_secrets.json b/apitools/data/apitools_client_secrets.json
deleted file mode 100644
index 7afd240..0000000
--- a/apitools/data/apitools_client_secrets.json
+++ /dev/null
@@ -1,15 +0,0 @@
-{
-  "installed": {
-    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
-    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
-    "client_email": "",
-    "client_id": "1042881264118.apps.googleusercontent.com",
-    "client_secret": "x_Tw5K8nnjoRAqULM9PFAC2b",
-    "client_x509_cert_url": "",
-    "redirect_uris": [
-      "urn:ietf:wg:oauth:2.0:oob",
-      "oob"
-    ],
-    "token_uri": "https://oauth2.googleapis.com/token"
-  }
-}
diff --git a/apitools/gen/extended_descriptor.py b/apitools/gen/extended_descriptor.py
index 52b34a1..711d2fa 100644
--- a/apitools/gen/extended_descriptor.py
+++ b/apitools/gen/extended_descriptor.py
@@ -416,6 +416,8 @@ class _ProtoRpcPrinter(ProtoPrinter):
         self.__printer('# NOTE: This file is autogenerated and should not be '
                        'edited by hand.')
         self.__printer()
+        self.__printer('from __future__ import absolute_import')
+        self.__printer()
         self.__PrintAdditionalImports(file_descriptor.additional_imports)
         self.__printer()
         self.__printer("package = '%s'", file_descriptor.package)
diff --git a/apitools/gen/gen_client.py b/apitools/gen/gen_client.py
index f842227..17b8d52 100644
--- a/apitools/gen/gen_client.py
+++ b/apitools/gen/gen_client.py
@@ -258,12 +258,12 @@ def main(argv=None):
 
     parser.add_argument(
         '--client_id',
-        default='1042881264118.apps.googleusercontent.com',
+        default='CLIENT_ID',
         help='Client ID to use for the generated client.')
 
     parser.add_argument(
         '--client_secret',
-        default='x_Tw5K8nnjoRAqULM9PFAC2b',
+        default='CLIENT_SECRET',
         help='Client secret for the generated client.')
 
     parser.add_argument(
diff --git a/apitools/gen/gen_client_lib.py b/apitools/gen/gen_client_lib.py
index 1796762..4b93c42 100644
--- a/apitools/gen/gen_client_lib.py
+++ b/apitools/gen/gen_client_lib.py
@@ -168,12 +168,14 @@ class DescriptorGenerator(object):
         else:
             printer('"""Package marker file."""')
         printer()
+        printer('from __future__ import absolute_import')
+        printer()
         printer('import pkgutil')
         printer()
         if self.__init_wildcards_file:
             printer('from %s import *', self.__base_files_package)
             if self.__root_package == '.':
-                import_prefix = ''
+                import_prefix = '.'
             else:
                 import_prefix = '%s.' % self.__root_package
             printer('from %s%s import *',
diff --git a/apitools/gen/gen_client_test.py b/apitools/gen/gen_client_test.py
index a0f30d5..7430101 100644
--- a/apitools/gen/gen_client_test.py
+++ b/apitools/gen/gen_client_test.py
@@ -73,6 +73,8 @@ class ClientGenCliTest(unittest.TestCase):
             init_file = _GetContent(os.path.join(tmp_dir_path, '__init__.py'))
             self.assertEqual("""\"""Package marker file.\"""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/apitools/gen/service_registry.py b/apitools/gen/service_registry.py
index b79f0d1..6d396aa 100644
--- a/apitools/gen/service_registry.py
+++ b/apitools/gen/service_registry.py
@@ -200,6 +200,9 @@ class ServiceRegistry(object):
                 client_info.package, client_info.version)
         printer('# NOTE: This file is autogenerated and should not be edited '
                 'by hand.')
+        printer()
+        printer('from __future__ import absolute_import')
+        printer()
         printer('from %s import base_api', self.__base_files_package)
         if self.__root_package:
             import_prefix = 'from {0} '.format(self.__root_package)
@@ -282,11 +285,10 @@ class ServiceRegistry(object):
                 if k not in ordered_parameters:
                     ordered_parameters.append(k)
         for parameter_name in ordered_parameters:
-            field_name = self.__names.CleanName(parameter_name)
             field = dict(method_description['parameters'][parameter_name])
             if 'type' not in field:
                 raise ValueError('No type found in parameter %s' % field)
-            schema['properties'][field_name] = field
+            schema['properties'][parameter_name] = field
         if body_type is not None:
             body_field_name = self.__GetRequestField(
                 method_description, body_type)
@@ -352,7 +354,7 @@ class ServiceRegistry(object):
             config.max_size = self.__MaxSizeToInt(
                 media_upload_config['maxSize'])
         if 'accept' not in media_upload_config:
-            logging.warn(
+            logging.warning(
                 'No accept types found for upload configuration in '
                 'method %s, using */*', method_id)
         config.accept.extend([
@@ -360,7 +362,7 @@ class ServiceRegistry(object):
 
         for accept_pattern in config.accept:
             if not _MIME_PATTERN_RE.match(accept_pattern):
-                logging.warn('Unexpected MIME type: %s', accept_pattern)
+                logging.warning('Unexpected MIME type: %s', accept_pattern)
         protocols = media_upload_config.get('protocols', {})
         for protocol in ('simple', 'resumable'):
             media = protocols.get(protocol, {})
diff --git a/samples/bigquery_sample/bigquery_v2/__init__.py b/samples/bigquery_sample/bigquery_v2/__init__.py
index 2816da8..f437c62 100644
--- a/samples/bigquery_sample/bigquery_v2/__init__.py
+++ b/samples/bigquery_sample/bigquery_v2/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/bigquery_sample/bigquery_v2/bigquery_v2_client.py b/samples/bigquery_sample/bigquery_v2/bigquery_v2_client.py
index 90552da..84748d6 100644
--- a/samples/bigquery_sample/bigquery_v2/bigquery_v2_client.py
+++ b/samples/bigquery_sample/bigquery_v2/bigquery_v2_client.py
@@ -1,5 +1,8 @@
 """Generated client library for bigquery version v2."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.bigquery_sample.bigquery_v2 import bigquery_v2_messages as messages
 
@@ -8,17 +11,17 @@ class BigqueryV2(base_api.BaseApiClient):
   """Generated client library for service bigquery version v2."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://www.googleapis.com/bigquery/v2/'
-  MTLS_BASE_URL = u''
-
-  _PACKAGE = u'bigquery'
-  _SCOPES = [u'https://www.googleapis.com/auth/bigquery', u'https://www.googleapis.com/auth/bigquery.insertdata', u'https://www.googleapis.com/auth/cloud-platform', u'https://www.googleapis.com/auth/cloud-platform.read-only', u'https://www.googleapis.com/auth/devstorage.full_control', u'https://www.googleapis.com/auth/devstorage.read_only', u'https://www.googleapis.com/auth/devstorage.read_write']
-  _VERSION = u'v2'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://www.googleapis.com/bigquery/v2/'
+  MTLS_BASE_URL = ''
+
+  _PACKAGE = 'bigquery'
+  _SCOPES = ['https://www.googleapis.com/auth/bigquery', 'https://www.googleapis.com/auth/bigquery.insertdata', 'https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-platform.read-only', 'https://www.googleapis.com/auth/devstorage.full_control', 'https://www.googleapis.com/auth/devstorage.read_only', 'https://www.googleapis.com/auth/devstorage.read_write']
+  _VERSION = 'v2'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'BigqueryV2'
-  _URL_VERSION = u'v2'
+  _CLIENT_CLASS_NAME = 'BigqueryV2'
+  _URL_VERSION = 'v2'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -45,7 +48,7 @@ class BigqueryV2(base_api.BaseApiClient):
   class DatasetsService(base_api.BaseApiService):
     """Service class for the datasets resource."""
 
-    _NAME = u'datasets'
+    _NAME = 'datasets'
 
     def __init__(self, client):
       super(BigqueryV2.DatasetsService, self).__init__(client)
@@ -66,15 +69,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'bigquery.datasets.delete',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
-        query_params=[u'deleteContents'],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}',
+        http_method='DELETE',
+        method_id='bigquery.datasets.delete',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
+        query_params=['deleteContents'],
+        relative_path='projects/{projectId}/datasets/{datasetId}',
         request_field='',
-        request_type_name=u'BigqueryDatasetsDeleteRequest',
-        response_type_name=u'BigqueryDatasetsDeleteResponse',
+        request_type_name='BigqueryDatasetsDeleteRequest',
+        response_type_name='BigqueryDatasetsDeleteResponse',
         supports_download=False,
     )
 
@@ -92,15 +95,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.datasets.get',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
+        http_method='GET',
+        method_id='bigquery.datasets.get',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}',
+        relative_path='projects/{projectId}/datasets/{datasetId}',
         request_field='',
-        request_type_name=u'BigqueryDatasetsGetRequest',
-        response_type_name=u'Dataset',
+        request_type_name='BigqueryDatasetsGetRequest',
+        response_type_name='Dataset',
         supports_download=False,
     )
 
@@ -118,15 +121,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.datasets.insert',
-        ordered_params=[u'projectId'],
-        path_params=[u'projectId'],
+        http_method='POST',
+        method_id='bigquery.datasets.insert',
+        ordered_params=['projectId'],
+        path_params=['projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets',
-        request_field=u'dataset',
-        request_type_name=u'BigqueryDatasetsInsertRequest',
-        response_type_name=u'Dataset',
+        relative_path='projects/{projectId}/datasets',
+        request_field='dataset',
+        request_type_name='BigqueryDatasetsInsertRequest',
+        response_type_name='Dataset',
         supports_download=False,
     )
 
@@ -144,15 +147,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.datasets.list',
-        ordered_params=[u'projectId'],
-        path_params=[u'projectId'],
-        query_params=[u'all', u'filter', u'maxResults', u'pageToken'],
-        relative_path=u'projects/{projectId}/datasets',
+        http_method='GET',
+        method_id='bigquery.datasets.list',
+        ordered_params=['projectId'],
+        path_params=['projectId'],
+        query_params=['all', 'filter', 'maxResults', 'pageToken'],
+        relative_path='projects/{projectId}/datasets',
         request_field='',
-        request_type_name=u'BigqueryDatasetsListRequest',
-        response_type_name=u'DatasetList',
+        request_type_name='BigqueryDatasetsListRequest',
+        response_type_name='DatasetList',
         supports_download=False,
     )
 
@@ -170,15 +173,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'bigquery.datasets.patch',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
+        http_method='PATCH',
+        method_id='bigquery.datasets.patch',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}',
-        request_field=u'dataset',
-        request_type_name=u'BigqueryDatasetsPatchRequest',
-        response_type_name=u'Dataset',
+        relative_path='projects/{projectId}/datasets/{datasetId}',
+        request_field='dataset',
+        request_type_name='BigqueryDatasetsPatchRequest',
+        response_type_name='Dataset',
         supports_download=False,
     )
 
@@ -196,22 +199,22 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'bigquery.datasets.update',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
+        http_method='PUT',
+        method_id='bigquery.datasets.update',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}',
-        request_field=u'dataset',
-        request_type_name=u'BigqueryDatasetsUpdateRequest',
-        response_type_name=u'Dataset',
+        relative_path='projects/{projectId}/datasets/{datasetId}',
+        request_field='dataset',
+        request_type_name='BigqueryDatasetsUpdateRequest',
+        response_type_name='Dataset',
         supports_download=False,
     )
 
   class JobsService(base_api.BaseApiService):
     """Service class for the jobs resource."""
 
-    _NAME = u'jobs'
+    _NAME = 'jobs'
 
     def __init__(self, client):
       super(BigqueryV2.JobsService, self).__init__(client)
@@ -220,9 +223,9 @@ class BigqueryV2(base_api.BaseApiClient):
               accept=['*/*'],
               max_size=None,
               resumable_multipart=True,
-              resumable_path=u'/resumable/upload/bigquery/v2/projects/{projectId}/jobs',
+              resumable_path='/resumable/upload/bigquery/v2/projects/{projectId}/jobs',
               simple_multipart=True,
-              simple_path=u'/upload/bigquery/v2/projects/{projectId}/jobs',
+              simple_path='/upload/bigquery/v2/projects/{projectId}/jobs',
           ),
           }
 
@@ -240,15 +243,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Cancel.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.jobs.cancel',
-        ordered_params=[u'projectId', u'jobId'],
-        path_params=[u'jobId', u'projectId'],
+        http_method='POST',
+        method_id='bigquery.jobs.cancel',
+        ordered_params=['projectId', 'jobId'],
+        path_params=['jobId', 'projectId'],
         query_params=[],
-        relative_path=u'project/{projectId}/jobs/{jobId}/cancel',
+        relative_path='project/{projectId}/jobs/{jobId}/cancel',
         request_field='',
-        request_type_name=u'BigqueryJobsCancelRequest',
-        response_type_name=u'JobCancelResponse',
+        request_type_name='BigqueryJobsCancelRequest',
+        response_type_name='JobCancelResponse',
         supports_download=False,
     )
 
@@ -266,15 +269,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.jobs.get',
-        ordered_params=[u'projectId', u'jobId'],
-        path_params=[u'jobId', u'projectId'],
+        http_method='GET',
+        method_id='bigquery.jobs.get',
+        ordered_params=['projectId', 'jobId'],
+        path_params=['jobId', 'projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/jobs/{jobId}',
+        relative_path='projects/{projectId}/jobs/{jobId}',
         request_field='',
-        request_type_name=u'BigqueryJobsGetRequest',
-        response_type_name=u'Job',
+        request_type_name='BigqueryJobsGetRequest',
+        response_type_name='Job',
         supports_download=False,
     )
 
@@ -292,15 +295,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     GetQueryResults.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.jobs.getQueryResults',
-        ordered_params=[u'projectId', u'jobId'],
-        path_params=[u'jobId', u'projectId'],
-        query_params=[u'maxResults', u'pageToken', u'startIndex', u'timeoutMs'],
-        relative_path=u'projects/{projectId}/queries/{jobId}',
+        http_method='GET',
+        method_id='bigquery.jobs.getQueryResults',
+        ordered_params=['projectId', 'jobId'],
+        path_params=['jobId', 'projectId'],
+        query_params=['maxResults', 'pageToken', 'startIndex', 'timeoutMs'],
+        relative_path='projects/{projectId}/queries/{jobId}',
         request_field='',
-        request_type_name=u'BigqueryJobsGetQueryResultsRequest',
-        response_type_name=u'GetQueryResultsResponse',
+        request_type_name='BigqueryJobsGetQueryResultsRequest',
+        response_type_name='GetQueryResultsResponse',
         supports_download=False,
     )
 
@@ -322,15 +325,15 @@ class BigqueryV2(base_api.BaseApiClient):
           upload=upload, upload_config=upload_config)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.jobs.insert',
-        ordered_params=[u'projectId'],
-        path_params=[u'projectId'],
+        http_method='POST',
+        method_id='bigquery.jobs.insert',
+        ordered_params=['projectId'],
+        path_params=['projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/jobs',
-        request_field=u'job',
-        request_type_name=u'BigqueryJobsInsertRequest',
-        response_type_name=u'Job',
+        relative_path='projects/{projectId}/jobs',
+        request_field='job',
+        request_type_name='BigqueryJobsInsertRequest',
+        response_type_name='Job',
         supports_download=False,
     )
 
@@ -348,15 +351,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.jobs.list',
-        ordered_params=[u'projectId'],
-        path_params=[u'projectId'],
-        query_params=[u'allUsers', u'maxResults', u'pageToken', u'projection', u'stateFilter'],
-        relative_path=u'projects/{projectId}/jobs',
+        http_method='GET',
+        method_id='bigquery.jobs.list',
+        ordered_params=['projectId'],
+        path_params=['projectId'],
+        query_params=['allUsers', 'maxResults', 'pageToken', 'projection', 'stateFilter'],
+        relative_path='projects/{projectId}/jobs',
         request_field='',
-        request_type_name=u'BigqueryJobsListRequest',
-        response_type_name=u'JobList',
+        request_type_name='BigqueryJobsListRequest',
+        response_type_name='JobList',
         supports_download=False,
     )
 
@@ -374,22 +377,22 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Query.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.jobs.query',
-        ordered_params=[u'projectId'],
-        path_params=[u'projectId'],
+        http_method='POST',
+        method_id='bigquery.jobs.query',
+        ordered_params=['projectId'],
+        path_params=['projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/queries',
-        request_field=u'queryRequest',
-        request_type_name=u'BigqueryJobsQueryRequest',
-        response_type_name=u'QueryResponse',
+        relative_path='projects/{projectId}/queries',
+        request_field='queryRequest',
+        request_type_name='BigqueryJobsQueryRequest',
+        response_type_name='QueryResponse',
         supports_download=False,
     )
 
   class ProjectsService(base_api.BaseApiService):
     """Service class for the projects resource."""
 
-    _NAME = u'projects'
+    _NAME = 'projects'
 
     def __init__(self, client):
       super(BigqueryV2.ProjectsService, self).__init__(client)
@@ -410,22 +413,22 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.projects.list',
+        http_method='GET',
+        method_id='bigquery.projects.list',
         ordered_params=[],
         path_params=[],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'projects',
+        query_params=['maxResults', 'pageToken'],
+        relative_path='projects',
         request_field='',
-        request_type_name=u'BigqueryProjectsListRequest',
-        response_type_name=u'ProjectList',
+        request_type_name='BigqueryProjectsListRequest',
+        response_type_name='ProjectList',
         supports_download=False,
     )
 
   class TabledataService(base_api.BaseApiService):
     """Service class for the tabledata resource."""
 
-    _NAME = u'tabledata'
+    _NAME = 'tabledata'
 
     def __init__(self, client):
       super(BigqueryV2.TabledataService, self).__init__(client)
@@ -446,15 +449,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     InsertAll.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.tabledata.insertAll',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
+        http_method='POST',
+        method_id='bigquery.tabledata.insertAll',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}/insertAll',
-        request_field=u'tableDataInsertAllRequest',
-        request_type_name=u'BigqueryTabledataInsertAllRequest',
-        response_type_name=u'TableDataInsertAllResponse',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}/insertAll',
+        request_field='tableDataInsertAllRequest',
+        request_type_name='BigqueryTabledataInsertAllRequest',
+        response_type_name='TableDataInsertAllResponse',
         supports_download=False,
     )
 
@@ -472,22 +475,22 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.tabledata.list',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
-        query_params=[u'maxResults', u'pageToken', u'startIndex'],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}/data',
+        http_method='GET',
+        method_id='bigquery.tabledata.list',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
+        query_params=['maxResults', 'pageToken', 'startIndex'],
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}/data',
         request_field='',
-        request_type_name=u'BigqueryTabledataListRequest',
-        response_type_name=u'TableDataList',
+        request_type_name='BigqueryTabledataListRequest',
+        response_type_name='TableDataList',
         supports_download=False,
     )
 
   class TablesService(base_api.BaseApiService):
     """Service class for the tables resource."""
 
-    _NAME = u'tables'
+    _NAME = 'tables'
 
     def __init__(self, client):
       super(BigqueryV2.TablesService, self).__init__(client)
@@ -508,15 +511,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'bigquery.tables.delete',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
+        http_method='DELETE',
+        method_id='bigquery.tables.delete',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
         request_field='',
-        request_type_name=u'BigqueryTablesDeleteRequest',
-        response_type_name=u'BigqueryTablesDeleteResponse',
+        request_type_name='BigqueryTablesDeleteRequest',
+        response_type_name='BigqueryTablesDeleteResponse',
         supports_download=False,
     )
 
@@ -534,15 +537,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.tables.get',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
+        http_method='GET',
+        method_id='bigquery.tables.get',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
         request_field='',
-        request_type_name=u'BigqueryTablesGetRequest',
-        response_type_name=u'Table',
+        request_type_name='BigqueryTablesGetRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -560,15 +563,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'bigquery.tables.insert',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
+        http_method='POST',
+        method_id='bigquery.tables.insert',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables',
-        request_field=u'table',
-        request_type_name=u'BigqueryTablesInsertRequest',
-        response_type_name=u'Table',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables',
+        request_field='table',
+        request_type_name='BigqueryTablesInsertRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -586,15 +589,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'bigquery.tables.list',
-        ordered_params=[u'projectId', u'datasetId'],
-        path_params=[u'datasetId', u'projectId'],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables',
+        http_method='GET',
+        method_id='bigquery.tables.list',
+        ordered_params=['projectId', 'datasetId'],
+        path_params=['datasetId', 'projectId'],
+        query_params=['maxResults', 'pageToken'],
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables',
         request_field='',
-        request_type_name=u'BigqueryTablesListRequest',
-        response_type_name=u'TableList',
+        request_type_name='BigqueryTablesListRequest',
+        response_type_name='TableList',
         supports_download=False,
     )
 
@@ -612,15 +615,15 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'bigquery.tables.patch',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
+        http_method='PATCH',
+        method_id='bigquery.tables.patch',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
-        request_field=u'table',
-        request_type_name=u'BigqueryTablesPatchRequest',
-        response_type_name=u'Table',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
+        request_field='table',
+        request_type_name='BigqueryTablesPatchRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -638,14 +641,14 @@ class BigqueryV2(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'bigquery.tables.update',
-        ordered_params=[u'projectId', u'datasetId', u'tableId'],
-        path_params=[u'datasetId', u'projectId', u'tableId'],
+        http_method='PUT',
+        method_id='bigquery.tables.update',
+        ordered_params=['projectId', 'datasetId', 'tableId'],
+        path_params=['datasetId', 'projectId', 'tableId'],
         query_params=[],
-        relative_path=u'projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
-        request_field=u'table',
-        request_type_name=u'BigqueryTablesUpdateRequest',
-        response_type_name=u'Table',
+        relative_path='projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
+        request_field='table',
+        request_type_name='BigqueryTablesUpdateRequest',
+        response_type_name='Table',
         supports_download=False,
     )
diff --git a/samples/bigquery_sample/bigquery_v2/bigquery_v2_messages.py b/samples/bigquery_sample/bigquery_v2/bigquery_v2_messages.py
index 63a0351..3f66b4c 100644
--- a/samples/bigquery_sample/bigquery_v2/bigquery_v2_messages.py
+++ b/samples/bigquery_sample/bigquery_v2/bigquery_v2_messages.py
@@ -4,6 +4,8 @@ A data platform for customers to create, manage, share and query data.
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import messages as _messages
 from apitools.base.py import encoding
 from apitools.base.py import extra_types
@@ -516,7 +518,7 @@ class CsvOptions(_messages.Message):
   allowQuotedNewlines = _messages.BooleanField(2)
   encoding = _messages.StringField(3)
   fieldDelimiter = _messages.StringField(4)
-  quote = _messages.StringField(5, default=u'"')
+  quote = _messages.StringField(5, default='"')
   skipLeadingRows = _messages.IntegerField(6)
 
 
@@ -653,7 +655,7 @@ class Dataset(_messages.Message):
   etag = _messages.StringField(6)
   friendlyName = _messages.StringField(7)
   id = _messages.StringField(8)
-  kind = _messages.StringField(9, default=u'bigquery#dataset')
+  kind = _messages.StringField(9, default='bigquery#dataset')
   labels = _messages.MessageField('LabelsValue', 10)
   lastModifiedTime = _messages.IntegerField(11)
   location = _messages.StringField(12)
@@ -725,12 +727,12 @@ class DatasetList(_messages.Message):
     datasetReference = _messages.MessageField('DatasetReference', 1)
     friendlyName = _messages.StringField(2)
     id = _messages.StringField(3)
-    kind = _messages.StringField(4, default=u'bigquery#dataset')
+    kind = _messages.StringField(4, default='bigquery#dataset')
     labels = _messages.MessageField('LabelsValue', 5)
 
   datasets = _messages.MessageField('DatasetsValueListEntry', 1, repeated=True)
   etag = _messages.StringField(2)
-  kind = _messages.StringField(3, default=u'bigquery#datasetList')
+  kind = _messages.StringField(3, default='bigquery#datasetList')
   nextPageToken = _messages.StringField(4)
 
 
@@ -924,7 +926,7 @@ class GetQueryResultsResponse(_messages.Message):
   etag = _messages.StringField(3)
   jobComplete = _messages.BooleanField(4)
   jobReference = _messages.MessageField('JobReference', 5)
-  kind = _messages.StringField(6, default=u'bigquery#getQueryResultsResponse')
+  kind = _messages.StringField(6, default='bigquery#getQueryResultsResponse')
   numDmlAffectedRows = _messages.IntegerField(7)
   pageToken = _messages.StringField(8)
   rows = _messages.MessageField('TableRow', 9, repeated=True)
@@ -977,7 +979,7 @@ class Job(_messages.Message):
   etag = _messages.StringField(2)
   id = _messages.StringField(3)
   jobReference = _messages.MessageField('JobReference', 4)
-  kind = _messages.StringField(5, default=u'bigquery#job')
+  kind = _messages.StringField(5, default='bigquery#job')
   selfLink = _messages.StringField(6)
   statistics = _messages.MessageField('JobStatistics', 7)
   status = _messages.MessageField('JobStatus', 8)
@@ -993,7 +995,7 @@ class JobCancelResponse(_messages.Message):
   """
 
   job = _messages.MessageField('Job', 1)
-  kind = _messages.StringField(2, default=u'bigquery#jobCancelResponse')
+  kind = _messages.StringField(2, default='bigquery#jobCancelResponse')
 
 
 class JobConfiguration(_messages.Message):
@@ -1155,7 +1157,7 @@ class JobConfigurationLoad(_messages.Message):
   ignoreUnknownValues = _messages.BooleanField(8)
   maxBadRecords = _messages.IntegerField(9, variant=_messages.Variant.INT32)
   projectionFields = _messages.StringField(10, repeated=True)
-  quote = _messages.StringField(11, default=u'"')
+  quote = _messages.StringField(11, default='"')
   schema = _messages.MessageField('TableSchema', 12)
   schemaInline = _messages.StringField(13)
   schemaInlineFormat = _messages.StringField(14)
@@ -1360,7 +1362,7 @@ class JobList(_messages.Message):
     errorResult = _messages.MessageField('ErrorProto', 2)
     id = _messages.StringField(3)
     jobReference = _messages.MessageField('JobReference', 4)
-    kind = _messages.StringField(5, default=u'bigquery#job')
+    kind = _messages.StringField(5, default='bigquery#job')
     state = _messages.StringField(6)
     statistics = _messages.MessageField('JobStatistics', 7)
     status = _messages.MessageField('JobStatus', 8)
@@ -1368,7 +1370,7 @@ class JobList(_messages.Message):
 
   etag = _messages.StringField(1)
   jobs = _messages.MessageField('JobsValueListEntry', 2, repeated=True)
-  kind = _messages.StringField(3, default=u'bigquery#jobList')
+  kind = _messages.StringField(3, default='bigquery#jobList')
   nextPageToken = _messages.StringField(4)
 
 
@@ -1548,12 +1550,12 @@ class ProjectList(_messages.Message):
 
     friendlyName = _messages.StringField(1)
     id = _messages.StringField(2)
-    kind = _messages.StringField(3, default=u'bigquery#project')
+    kind = _messages.StringField(3, default='bigquery#project')
     numericId = _messages.IntegerField(4, variant=_messages.Variant.UINT64)
     projectReference = _messages.MessageField('ProjectReference', 5)
 
   etag = _messages.StringField(1)
-  kind = _messages.StringField(2, default=u'bigquery#projectList')
+  kind = _messages.StringField(2, default='bigquery#projectList')
   nextPageToken = _messages.StringField(3)
   projects = _messages.MessageField('ProjectsValueListEntry', 4, repeated=True)
   totalItems = _messages.IntegerField(5, variant=_messages.Variant.INT32)
@@ -1614,7 +1616,7 @@ class QueryRequest(_messages.Message):
 
   defaultDataset = _messages.MessageField('DatasetReference', 1)
   dryRun = _messages.BooleanField(2)
-  kind = _messages.StringField(3, default=u'bigquery#queryRequest')
+  kind = _messages.StringField(3, default='bigquery#queryRequest')
   maxResults = _messages.IntegerField(4, variant=_messages.Variant.UINT32)
   preserveNulls = _messages.BooleanField(5)
   query = _messages.StringField(6)
@@ -1662,7 +1664,7 @@ class QueryResponse(_messages.Message):
   errors = _messages.MessageField('ErrorProto', 2, repeated=True)
   jobComplete = _messages.BooleanField(3)
   jobReference = _messages.MessageField('JobReference', 4)
-  kind = _messages.StringField(5, default=u'bigquery#queryResponse')
+  kind = _messages.StringField(5, default='bigquery#queryResponse')
   numDmlAffectedRows = _messages.IntegerField(6)
   pageToken = _messages.StringField(7)
   rows = _messages.MessageField('TableRow', 8, repeated=True)
@@ -1702,7 +1704,7 @@ class StandardQueryParameters(_messages.Message):
     """
     json = 0
 
-  alt = _messages.EnumField('AltValueValuesEnum', 1, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 1, default='json')
   fields = _messages.StringField(2)
   key = _messages.StringField(3)
   oauth_token = _messages.StringField(4)
@@ -1784,7 +1786,7 @@ class Table(_messages.Message):
   externalDataConfiguration = _messages.MessageField('ExternalDataConfiguration', 5)
   friendlyName = _messages.StringField(6)
   id = _messages.StringField(7)
-  kind = _messages.StringField(8, default=u'bigquery#table')
+  kind = _messages.StringField(8, default='bigquery#table')
   lastModifiedTime = _messages.IntegerField(9, variant=_messages.Variant.UINT64)
   location = _messages.StringField(10)
   numBytes = _messages.IntegerField(11)
@@ -1847,7 +1849,7 @@ class TableDataInsertAllRequest(_messages.Message):
     json = _messages.MessageField('JsonObject', 2)
 
   ignoreUnknownValues = _messages.BooleanField(1)
-  kind = _messages.StringField(2, default=u'bigquery#tableDataInsertAllRequest')
+  kind = _messages.StringField(2, default='bigquery#tableDataInsertAllRequest')
   rows = _messages.MessageField('RowsValueListEntry', 3, repeated=True)
   skipInvalidRows = _messages.BooleanField(4)
   templateSuffix = _messages.StringField(5)
@@ -1876,7 +1878,7 @@ class TableDataInsertAllResponse(_messages.Message):
     index = _messages.IntegerField(2, variant=_messages.Variant.UINT32)
 
   insertErrors = _messages.MessageField('InsertErrorsValueListEntry', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'bigquery#tableDataInsertAllResponse')
+  kind = _messages.StringField(2, default='bigquery#tableDataInsertAllResponse')
 
 
 class TableDataList(_messages.Message):
@@ -1893,7 +1895,7 @@ class TableDataList(_messages.Message):
   """
 
   etag = _messages.StringField(1)
-  kind = _messages.StringField(2, default=u'bigquery#tableDataList')
+  kind = _messages.StringField(2, default='bigquery#tableDataList')
   pageToken = _messages.StringField(3)
   rows = _messages.MessageField('TableRow', 4, repeated=True)
   totalRows = _messages.IntegerField(5)
@@ -1951,12 +1953,12 @@ class TableList(_messages.Message):
 
     friendlyName = _messages.StringField(1)
     id = _messages.StringField(2)
-    kind = _messages.StringField(3, default=u'bigquery#table')
+    kind = _messages.StringField(3, default='bigquery#table')
     tableReference = _messages.MessageField('TableReference', 4)
     type = _messages.StringField(5)
 
   etag = _messages.StringField(1)
-  kind = _messages.StringField(2, default=u'bigquery#tableList')
+  kind = _messages.StringField(2, default='bigquery#tableList')
   nextPageToken = _messages.StringField(3)
   tables = _messages.MessageField('TablesValueListEntry', 4, repeated=True)
   totalItems = _messages.IntegerField(5, variant=_messages.Variant.INT32)
diff --git a/samples/dns_sample/dns_v1/__init__.py b/samples/dns_sample/dns_v1/__init__.py
index 2816da8..f437c62 100644
--- a/samples/dns_sample/dns_v1/__init__.py
+++ b/samples/dns_sample/dns_v1/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/dns_sample/dns_v1/dns_v1_client.py b/samples/dns_sample/dns_v1/dns_v1_client.py
index 0666460..f4697b5 100644
--- a/samples/dns_sample/dns_v1/dns_v1_client.py
+++ b/samples/dns_sample/dns_v1/dns_v1_client.py
@@ -1,5 +1,8 @@
 """Generated client library for dns version v1."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.dns_sample.dns_v1 import dns_v1_messages as messages
 
@@ -8,17 +11,17 @@ class DnsV1(base_api.BaseApiClient):
   """Generated client library for service dns version v1."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://www.googleapis.com/dns/v1/'
-  MTLS_BASE_URL = u''
-
-  _PACKAGE = u'dns'
-  _SCOPES = [u'https://www.googleapis.com/auth/cloud-platform', u'https://www.googleapis.com/auth/cloud-platform.read-only', u'https://www.googleapis.com/auth/ndev.clouddns.readonly', u'https://www.googleapis.com/auth/ndev.clouddns.readwrite']
-  _VERSION = u'v1'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://www.googleapis.com/dns/v1/'
+  MTLS_BASE_URL = ''
+
+  _PACKAGE = 'dns'
+  _SCOPES = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-platform.read-only', 'https://www.googleapis.com/auth/ndev.clouddns.readonly', 'https://www.googleapis.com/auth/ndev.clouddns.readwrite']
+  _VERSION = 'v1'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'DnsV1'
-  _URL_VERSION = u'v1'
+  _CLIENT_CLASS_NAME = 'DnsV1'
+  _URL_VERSION = 'v1'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -44,7 +47,7 @@ class DnsV1(base_api.BaseApiClient):
   class ChangesService(base_api.BaseApiService):
     """Service class for the changes resource."""
 
-    _NAME = u'changes'
+    _NAME = 'changes'
 
     def __init__(self, client):
       super(DnsV1.ChangesService, self).__init__(client)
@@ -65,15 +68,15 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'dns.changes.create',
-        ordered_params=[u'project', u'managedZone'],
-        path_params=[u'managedZone', u'project'],
+        http_method='POST',
+        method_id='dns.changes.create',
+        ordered_params=['project', 'managedZone'],
+        path_params=['managedZone', 'project'],
         query_params=[],
-        relative_path=u'projects/{project}/managedZones/{managedZone}/changes',
-        request_field=u'change',
-        request_type_name=u'DnsChangesCreateRequest',
-        response_type_name=u'Change',
+        relative_path='projects/{project}/managedZones/{managedZone}/changes',
+        request_field='change',
+        request_type_name='DnsChangesCreateRequest',
+        response_type_name='Change',
         supports_download=False,
     )
 
@@ -91,15 +94,15 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.changes.get',
-        ordered_params=[u'project', u'managedZone', u'changeId'],
-        path_params=[u'changeId', u'managedZone', u'project'],
+        http_method='GET',
+        method_id='dns.changes.get',
+        ordered_params=['project', 'managedZone', 'changeId'],
+        path_params=['changeId', 'managedZone', 'project'],
         query_params=[],
-        relative_path=u'projects/{project}/managedZones/{managedZone}/changes/{changeId}',
+        relative_path='projects/{project}/managedZones/{managedZone}/changes/{changeId}',
         request_field='',
-        request_type_name=u'DnsChangesGetRequest',
-        response_type_name=u'Change',
+        request_type_name='DnsChangesGetRequest',
+        response_type_name='Change',
         supports_download=False,
     )
 
@@ -117,22 +120,22 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.changes.list',
-        ordered_params=[u'project', u'managedZone'],
-        path_params=[u'managedZone', u'project'],
-        query_params=[u'maxResults', u'pageToken', u'sortBy', u'sortOrder'],
-        relative_path=u'projects/{project}/managedZones/{managedZone}/changes',
+        http_method='GET',
+        method_id='dns.changes.list',
+        ordered_params=['project', 'managedZone'],
+        path_params=['managedZone', 'project'],
+        query_params=['maxResults', 'pageToken', 'sortBy', 'sortOrder'],
+        relative_path='projects/{project}/managedZones/{managedZone}/changes',
         request_field='',
-        request_type_name=u'DnsChangesListRequest',
-        response_type_name=u'ChangesListResponse',
+        request_type_name='DnsChangesListRequest',
+        response_type_name='ChangesListResponse',
         supports_download=False,
     )
 
   class ManagedZonesService(base_api.BaseApiService):
     """Service class for the managedZones resource."""
 
-    _NAME = u'managedZones'
+    _NAME = 'managedZones'
 
     def __init__(self, client):
       super(DnsV1.ManagedZonesService, self).__init__(client)
@@ -153,15 +156,15 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'dns.managedZones.create',
-        ordered_params=[u'project'],
-        path_params=[u'project'],
+        http_method='POST',
+        method_id='dns.managedZones.create',
+        ordered_params=['project'],
+        path_params=['project'],
         query_params=[],
-        relative_path=u'projects/{project}/managedZones',
-        request_field=u'managedZone',
-        request_type_name=u'DnsManagedZonesCreateRequest',
-        response_type_name=u'ManagedZone',
+        relative_path='projects/{project}/managedZones',
+        request_field='managedZone',
+        request_type_name='DnsManagedZonesCreateRequest',
+        response_type_name='ManagedZone',
         supports_download=False,
     )
 
@@ -179,15 +182,15 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'dns.managedZones.delete',
-        ordered_params=[u'project', u'managedZone'],
-        path_params=[u'managedZone', u'project'],
+        http_method='DELETE',
+        method_id='dns.managedZones.delete',
+        ordered_params=['project', 'managedZone'],
+        path_params=['managedZone', 'project'],
         query_params=[],
-        relative_path=u'projects/{project}/managedZones/{managedZone}',
+        relative_path='projects/{project}/managedZones/{managedZone}',
         request_field='',
-        request_type_name=u'DnsManagedZonesDeleteRequest',
-        response_type_name=u'DnsManagedZonesDeleteResponse',
+        request_type_name='DnsManagedZonesDeleteRequest',
+        response_type_name='DnsManagedZonesDeleteResponse',
         supports_download=False,
     )
 
@@ -205,15 +208,15 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.managedZones.get',
-        ordered_params=[u'project', u'managedZone'],
-        path_params=[u'managedZone', u'project'],
+        http_method='GET',
+        method_id='dns.managedZones.get',
+        ordered_params=['project', 'managedZone'],
+        path_params=['managedZone', 'project'],
         query_params=[],
-        relative_path=u'projects/{project}/managedZones/{managedZone}',
+        relative_path='projects/{project}/managedZones/{managedZone}',
         request_field='',
-        request_type_name=u'DnsManagedZonesGetRequest',
-        response_type_name=u'ManagedZone',
+        request_type_name='DnsManagedZonesGetRequest',
+        response_type_name='ManagedZone',
         supports_download=False,
     )
 
@@ -231,22 +234,22 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.managedZones.list',
-        ordered_params=[u'project'],
-        path_params=[u'project'],
-        query_params=[u'dnsName', u'maxResults', u'pageToken'],
-        relative_path=u'projects/{project}/managedZones',
+        http_method='GET',
+        method_id='dns.managedZones.list',
+        ordered_params=['project'],
+        path_params=['project'],
+        query_params=['dnsName', 'maxResults', 'pageToken'],
+        relative_path='projects/{project}/managedZones',
         request_field='',
-        request_type_name=u'DnsManagedZonesListRequest',
-        response_type_name=u'ManagedZonesListResponse',
+        request_type_name='DnsManagedZonesListRequest',
+        response_type_name='ManagedZonesListResponse',
         supports_download=False,
     )
 
   class ProjectsService(base_api.BaseApiService):
     """Service class for the projects resource."""
 
-    _NAME = u'projects'
+    _NAME = 'projects'
 
     def __init__(self, client):
       super(DnsV1.ProjectsService, self).__init__(client)
@@ -267,22 +270,22 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.projects.get',
-        ordered_params=[u'project'],
-        path_params=[u'project'],
+        http_method='GET',
+        method_id='dns.projects.get',
+        ordered_params=['project'],
+        path_params=['project'],
         query_params=[],
-        relative_path=u'projects/{project}',
+        relative_path='projects/{project}',
         request_field='',
-        request_type_name=u'DnsProjectsGetRequest',
-        response_type_name=u'Project',
+        request_type_name='DnsProjectsGetRequest',
+        response_type_name='Project',
         supports_download=False,
     )
 
   class ResourceRecordSetsService(base_api.BaseApiService):
     """Service class for the resourceRecordSets resource."""
 
-    _NAME = u'resourceRecordSets'
+    _NAME = 'resourceRecordSets'
 
     def __init__(self, client):
       super(DnsV1.ResourceRecordSetsService, self).__init__(client)
@@ -303,14 +306,14 @@ class DnsV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'dns.resourceRecordSets.list',
-        ordered_params=[u'project', u'managedZone'],
-        path_params=[u'managedZone', u'project'],
-        query_params=[u'maxResults', u'name', u'pageToken', u'type'],
-        relative_path=u'projects/{project}/managedZones/{managedZone}/rrsets',
+        http_method='GET',
+        method_id='dns.resourceRecordSets.list',
+        ordered_params=['project', 'managedZone'],
+        path_params=['managedZone', 'project'],
+        query_params=['maxResults', 'name', 'pageToken', 'type'],
+        relative_path='projects/{project}/managedZones/{managedZone}/rrsets',
         request_field='',
-        request_type_name=u'DnsResourceRecordSetsListRequest',
-        response_type_name=u'ResourceRecordSetsListResponse',
+        request_type_name='DnsResourceRecordSetsListRequest',
+        response_type_name='ResourceRecordSetsListResponse',
         supports_download=False,
     )
diff --git a/samples/dns_sample/dns_v1/dns_v1_messages.py b/samples/dns_sample/dns_v1/dns_v1_messages.py
index 5d5b77e..fe8c6de 100644
--- a/samples/dns_sample/dns_v1/dns_v1_messages.py
+++ b/samples/dns_sample/dns_v1/dns_v1_messages.py
@@ -5,6 +5,8 @@ authoritative DNS records.
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import messages as _messages
 
 
@@ -43,7 +45,7 @@ class Change(_messages.Message):
   additions = _messages.MessageField('ResourceRecordSet', 1, repeated=True)
   deletions = _messages.MessageField('ResourceRecordSet', 2, repeated=True)
   id = _messages.StringField(3)
-  kind = _messages.StringField(4, default=u'dns#change')
+  kind = _messages.StringField(4, default='dns#change')
   startTime = _messages.StringField(5)
   status = _messages.EnumField('StatusValueValuesEnum', 6)
 
@@ -67,7 +69,7 @@ class ChangesListResponse(_messages.Message):
   """
 
   changes = _messages.MessageField('Change', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'dns#changesListResponse')
+  kind = _messages.StringField(2, default='dns#changesListResponse')
   nextPageToken = _messages.StringField(3)
 
 
@@ -133,7 +135,7 @@ class DnsChangesListRequest(_messages.Message):
   maxResults = _messages.IntegerField(2, variant=_messages.Variant.INT32)
   pageToken = _messages.StringField(3)
   project = _messages.StringField(4, required=True)
-  sortBy = _messages.EnumField('SortByValueValuesEnum', 5, default=u'changeSequence')
+  sortBy = _messages.EnumField('SortByValueValuesEnum', 5, default='changeSequence')
   sortOrder = _messages.StringField(6)
 
 
@@ -263,7 +265,7 @@ class ManagedZone(_messages.Message):
   description = _messages.StringField(2)
   dnsName = _messages.StringField(3)
   id = _messages.IntegerField(4, variant=_messages.Variant.UINT64)
-  kind = _messages.StringField(5, default=u'dns#managedZone')
+  kind = _messages.StringField(5, default='dns#managedZone')
   name = _messages.StringField(6)
   nameServerSet = _messages.StringField(7)
   nameServers = _messages.StringField(8, repeated=True)
@@ -286,7 +288,7 @@ class ManagedZonesListResponse(_messages.Message):
       collection larger than the maximum page size.
   """
 
-  kind = _messages.StringField(1, default=u'dns#managedZonesListResponse')
+  kind = _messages.StringField(1, default='dns#managedZonesListResponse')
   managedZones = _messages.MessageField('ManagedZone', 2, repeated=True)
   nextPageToken = _messages.StringField(3)
 
@@ -306,7 +308,7 @@ class Project(_messages.Message):
   """
 
   id = _messages.StringField(1)
-  kind = _messages.StringField(2, default=u'dns#project')
+  kind = _messages.StringField(2, default='dns#project')
   number = _messages.IntegerField(3, variant=_messages.Variant.UINT64)
   quota = _messages.MessageField('Quota', 4)
 
@@ -330,7 +332,7 @@ class Quota(_messages.Message):
       ChangesCreateRequest in bytes.
   """
 
-  kind = _messages.StringField(1, default=u'dns#quota')
+  kind = _messages.StringField(1, default='dns#quota')
   managedZones = _messages.IntegerField(2, variant=_messages.Variant.INT32)
   resourceRecordsPerRrset = _messages.IntegerField(3, variant=_messages.Variant.INT32)
   rrsetAdditionsPerChange = _messages.IntegerField(4, variant=_messages.Variant.INT32)
@@ -353,7 +355,7 @@ class ResourceRecordSet(_messages.Message):
       TXT, and so on.
   """
 
-  kind = _messages.StringField(1, default=u'dns#resourceRecordSet')
+  kind = _messages.StringField(1, default='dns#resourceRecordSet')
   name = _messages.StringField(2)
   rrdatas = _messages.StringField(3, repeated=True)
   ttl = _messages.IntegerField(4, variant=_messages.Variant.INT32)
@@ -377,7 +379,7 @@ class ResourceRecordSetsListResponse(_messages.Message):
     rrsets: The resource record set resources.
   """
 
-  kind = _messages.StringField(1, default=u'dns#resourceRecordSetsListResponse')
+  kind = _messages.StringField(1, default='dns#resourceRecordSetsListResponse')
   nextPageToken = _messages.StringField(2)
   rrsets = _messages.MessageField('ResourceRecordSet', 3, repeated=True)
 
@@ -413,7 +415,7 @@ class StandardQueryParameters(_messages.Message):
     """
     json = 0
 
-  alt = _messages.EnumField('AltValueValuesEnum', 1, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 1, default='json')
   fields = _messages.StringField(2)
   key = _messages.StringField(3)
   oauth_token = _messages.StringField(4)
diff --git a/samples/fusiontables_sample/fusiontables_v1/__init__.py b/samples/fusiontables_sample/fusiontables_v1/__init__.py
index 2816da8..f437c62 100644
--- a/samples/fusiontables_sample/fusiontables_v1/__init__.py
+++ b/samples/fusiontables_sample/fusiontables_v1/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_client.py b/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_client.py
index b7b6c43..221d8a3 100644
--- a/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_client.py
+++ b/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_client.py
@@ -1,5 +1,8 @@
 """Generated client library for fusiontables version v1."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.fusiontables_sample.fusiontables_v1 import fusiontables_v1_messages as messages
 
@@ -8,17 +11,17 @@ class FusiontablesV1(base_api.BaseApiClient):
   """Generated client library for service fusiontables version v1."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://www.googleapis.com/fusiontables/v1/'
-  MTLS_BASE_URL = u''
-
-  _PACKAGE = u'fusiontables'
-  _SCOPES = [u'https://www.googleapis.com/auth/fusiontables', u'https://www.googleapis.com/auth/fusiontables.readonly']
-  _VERSION = u'v1'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://www.googleapis.com/fusiontables/v1/'
+  MTLS_BASE_URL = ''
+
+  _PACKAGE = 'fusiontables'
+  _SCOPES = ['https://www.googleapis.com/auth/fusiontables', 'https://www.googleapis.com/auth/fusiontables.readonly']
+  _VERSION = 'v1'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'FusiontablesV1'
-  _URL_VERSION = u'v1'
+  _CLIENT_CLASS_NAME = 'FusiontablesV1'
+  _URL_VERSION = 'v1'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -46,7 +49,7 @@ class FusiontablesV1(base_api.BaseApiClient):
   class ColumnService(base_api.BaseApiService):
     """Service class for the column resource."""
 
-    _NAME = u'column'
+    _NAME = 'column'
 
     def __init__(self, client):
       super(FusiontablesV1.ColumnService, self).__init__(client)
@@ -67,15 +70,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'fusiontables.column.delete',
-        ordered_params=[u'tableId', u'columnId'],
-        path_params=[u'columnId', u'tableId'],
+        http_method='DELETE',
+        method_id='fusiontables.column.delete',
+        ordered_params=['tableId', 'columnId'],
+        path_params=['columnId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/columns/{columnId}',
+        relative_path='tables/{tableId}/columns/{columnId}',
         request_field='',
-        request_type_name=u'FusiontablesColumnDeleteRequest',
-        response_type_name=u'FusiontablesColumnDeleteResponse',
+        request_type_name='FusiontablesColumnDeleteRequest',
+        response_type_name='FusiontablesColumnDeleteResponse',
         supports_download=False,
     )
 
@@ -93,15 +96,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.column.get',
-        ordered_params=[u'tableId', u'columnId'],
-        path_params=[u'columnId', u'tableId'],
+        http_method='GET',
+        method_id='fusiontables.column.get',
+        ordered_params=['tableId', 'columnId'],
+        path_params=['columnId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/columns/{columnId}',
+        relative_path='tables/{tableId}/columns/{columnId}',
         request_field='',
-        request_type_name=u'FusiontablesColumnGetRequest',
-        response_type_name=u'Column',
+        request_type_name='FusiontablesColumnGetRequest',
+        response_type_name='Column',
         supports_download=False,
     )
 
@@ -119,15 +122,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.column.insert',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
+        http_method='POST',
+        method_id='fusiontables.column.insert',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/columns',
-        request_field=u'column',
-        request_type_name=u'FusiontablesColumnInsertRequest',
-        response_type_name=u'Column',
+        relative_path='tables/{tableId}/columns',
+        request_field='column',
+        request_type_name='FusiontablesColumnInsertRequest',
+        response_type_name='Column',
         supports_download=False,
     )
 
@@ -145,15 +148,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.column.list',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'tables/{tableId}/columns',
+        http_method='GET',
+        method_id='fusiontables.column.list',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['maxResults', 'pageToken'],
+        relative_path='tables/{tableId}/columns',
         request_field='',
-        request_type_name=u'FusiontablesColumnListRequest',
-        response_type_name=u'ColumnList',
+        request_type_name='FusiontablesColumnListRequest',
+        response_type_name='ColumnList',
         supports_download=False,
     )
 
@@ -171,15 +174,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'fusiontables.column.patch',
-        ordered_params=[u'tableId', u'columnId'],
-        path_params=[u'columnId', u'tableId'],
+        http_method='PATCH',
+        method_id='fusiontables.column.patch',
+        ordered_params=['tableId', 'columnId'],
+        path_params=['columnId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/columns/{columnId}',
-        request_field=u'column',
-        request_type_name=u'FusiontablesColumnPatchRequest',
-        response_type_name=u'Column',
+        relative_path='tables/{tableId}/columns/{columnId}',
+        request_field='column',
+        request_type_name='FusiontablesColumnPatchRequest',
+        response_type_name='Column',
         supports_download=False,
     )
 
@@ -197,22 +200,22 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'fusiontables.column.update',
-        ordered_params=[u'tableId', u'columnId'],
-        path_params=[u'columnId', u'tableId'],
+        http_method='PUT',
+        method_id='fusiontables.column.update',
+        ordered_params=['tableId', 'columnId'],
+        path_params=['columnId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/columns/{columnId}',
-        request_field=u'column',
-        request_type_name=u'FusiontablesColumnUpdateRequest',
-        response_type_name=u'Column',
+        relative_path='tables/{tableId}/columns/{columnId}',
+        request_field='column',
+        request_type_name='FusiontablesColumnUpdateRequest',
+        response_type_name='Column',
         supports_download=False,
     )
 
   class QueryService(base_api.BaseApiService):
     """Service class for the query resource."""
 
-    _NAME = u'query'
+    _NAME = 'query'
 
     def __init__(self, client):
       super(FusiontablesV1.QueryService, self).__init__(client)
@@ -236,15 +239,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           download=download)
 
     Sql.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.query.sql',
-        ordered_params=[u'sql'],
+        http_method='POST',
+        method_id='fusiontables.query.sql',
+        ordered_params=['sql'],
         path_params=[],
-        query_params=[u'hdrs', u'sql', u'typed'],
-        relative_path=u'query',
+        query_params=['hdrs', 'sql', 'typed'],
+        relative_path='query',
         request_field='',
-        request_type_name=u'FusiontablesQuerySqlRequest',
-        response_type_name=u'Sqlresponse',
+        request_type_name='FusiontablesQuerySqlRequest',
+        response_type_name='Sqlresponse',
         supports_download=True,
     )
 
@@ -265,22 +268,22 @@ class FusiontablesV1(base_api.BaseApiClient):
           download=download)
 
     SqlGet.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.query.sqlGet',
-        ordered_params=[u'sql'],
+        http_method='GET',
+        method_id='fusiontables.query.sqlGet',
+        ordered_params=['sql'],
         path_params=[],
-        query_params=[u'hdrs', u'sql', u'typed'],
-        relative_path=u'query',
+        query_params=['hdrs', 'sql', 'typed'],
+        relative_path='query',
         request_field='',
-        request_type_name=u'FusiontablesQuerySqlGetRequest',
-        response_type_name=u'Sqlresponse',
+        request_type_name='FusiontablesQuerySqlGetRequest',
+        response_type_name='Sqlresponse',
         supports_download=True,
     )
 
   class StyleService(base_api.BaseApiService):
     """Service class for the style resource."""
 
-    _NAME = u'style'
+    _NAME = 'style'
 
     def __init__(self, client):
       super(FusiontablesV1.StyleService, self).__init__(client)
@@ -301,15 +304,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'fusiontables.style.delete',
-        ordered_params=[u'tableId', u'styleId'],
-        path_params=[u'styleId', u'tableId'],
+        http_method='DELETE',
+        method_id='fusiontables.style.delete',
+        ordered_params=['tableId', 'styleId'],
+        path_params=['styleId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/styles/{styleId}',
+        relative_path='tables/{tableId}/styles/{styleId}',
         request_field='',
-        request_type_name=u'FusiontablesStyleDeleteRequest',
-        response_type_name=u'FusiontablesStyleDeleteResponse',
+        request_type_name='FusiontablesStyleDeleteRequest',
+        response_type_name='FusiontablesStyleDeleteResponse',
         supports_download=False,
     )
 
@@ -327,15 +330,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.style.get',
-        ordered_params=[u'tableId', u'styleId'],
-        path_params=[u'styleId', u'tableId'],
+        http_method='GET',
+        method_id='fusiontables.style.get',
+        ordered_params=['tableId', 'styleId'],
+        path_params=['styleId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/styles/{styleId}',
+        relative_path='tables/{tableId}/styles/{styleId}',
         request_field='',
-        request_type_name=u'FusiontablesStyleGetRequest',
-        response_type_name=u'StyleSetting',
+        request_type_name='FusiontablesStyleGetRequest',
+        response_type_name='StyleSetting',
         supports_download=False,
     )
 
@@ -353,15 +356,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.style.insert',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
+        http_method='POST',
+        method_id='fusiontables.style.insert',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/styles',
+        relative_path='tables/{tableId}/styles',
         request_field='<request>',
-        request_type_name=u'StyleSetting',
-        response_type_name=u'StyleSetting',
+        request_type_name='StyleSetting',
+        response_type_name='StyleSetting',
         supports_download=False,
     )
 
@@ -379,15 +382,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.style.list',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'tables/{tableId}/styles',
+        http_method='GET',
+        method_id='fusiontables.style.list',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['maxResults', 'pageToken'],
+        relative_path='tables/{tableId}/styles',
         request_field='',
-        request_type_name=u'FusiontablesStyleListRequest',
-        response_type_name=u'StyleSettingList',
+        request_type_name='FusiontablesStyleListRequest',
+        response_type_name='StyleSettingList',
         supports_download=False,
     )
 
@@ -405,15 +408,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'fusiontables.style.patch',
-        ordered_params=[u'tableId', u'styleId'],
-        path_params=[u'styleId', u'tableId'],
+        http_method='PATCH',
+        method_id='fusiontables.style.patch',
+        ordered_params=['tableId', 'styleId'],
+        path_params=['styleId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/styles/{styleId}',
+        relative_path='tables/{tableId}/styles/{styleId}',
         request_field='<request>',
-        request_type_name=u'StyleSetting',
-        response_type_name=u'StyleSetting',
+        request_type_name='StyleSetting',
+        response_type_name='StyleSetting',
         supports_download=False,
     )
 
@@ -431,22 +434,22 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'fusiontables.style.update',
-        ordered_params=[u'tableId', u'styleId'],
-        path_params=[u'styleId', u'tableId'],
+        http_method='PUT',
+        method_id='fusiontables.style.update',
+        ordered_params=['tableId', 'styleId'],
+        path_params=['styleId', 'tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/styles/{styleId}',
+        relative_path='tables/{tableId}/styles/{styleId}',
         request_field='<request>',
-        request_type_name=u'StyleSetting',
-        response_type_name=u'StyleSetting',
+        request_type_name='StyleSetting',
+        response_type_name='StyleSetting',
         supports_download=False,
     )
 
   class TableService(base_api.BaseApiService):
     """Service class for the table resource."""
 
-    _NAME = u'table'
+    _NAME = 'table'
 
     def __init__(self, client):
       super(FusiontablesV1.TableService, self).__init__(client)
@@ -455,17 +458,17 @@ class FusiontablesV1(base_api.BaseApiClient):
               accept=['application/octet-stream'],
               max_size=262144000,
               resumable_multipart=True,
-              resumable_path=u'/resumable/upload/fusiontables/v1/tables/{tableId}/import',
+              resumable_path='/resumable/upload/fusiontables/v1/tables/{tableId}/import',
               simple_multipart=True,
-              simple_path=u'/upload/fusiontables/v1/tables/{tableId}/import',
+              simple_path='/upload/fusiontables/v1/tables/{tableId}/import',
           ),
           'ImportTable': base_api.ApiUploadInfo(
               accept=['application/octet-stream'],
               max_size=262144000,
               resumable_multipart=True,
-              resumable_path=u'/resumable/upload/fusiontables/v1/tables/import',
+              resumable_path='/resumable/upload/fusiontables/v1/tables/import',
               simple_multipart=True,
-              simple_path=u'/upload/fusiontables/v1/tables/import',
+              simple_path='/upload/fusiontables/v1/tables/import',
           ),
           }
 
@@ -483,15 +486,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Copy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.table.copy',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'copyPresentation'],
-        relative_path=u'tables/{tableId}/copy',
+        http_method='POST',
+        method_id='fusiontables.table.copy',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['copyPresentation'],
+        relative_path='tables/{tableId}/copy',
         request_field='',
-        request_type_name=u'FusiontablesTableCopyRequest',
-        response_type_name=u'Table',
+        request_type_name='FusiontablesTableCopyRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -509,15 +512,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'fusiontables.table.delete',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
+        http_method='DELETE',
+        method_id='fusiontables.table.delete',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}',
+        relative_path='tables/{tableId}',
         request_field='',
-        request_type_name=u'FusiontablesTableDeleteRequest',
-        response_type_name=u'FusiontablesTableDeleteResponse',
+        request_type_name='FusiontablesTableDeleteRequest',
+        response_type_name='FusiontablesTableDeleteResponse',
         supports_download=False,
     )
 
@@ -535,15 +538,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.table.get',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
+        http_method='GET',
+        method_id='fusiontables.table.get',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}',
+        relative_path='tables/{tableId}',
         request_field='',
-        request_type_name=u'FusiontablesTableGetRequest',
-        response_type_name=u'Table',
+        request_type_name='FusiontablesTableGetRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -565,15 +568,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           upload=upload, upload_config=upload_config)
 
     ImportRows.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.table.importRows',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'delimiter', u'encoding', u'endLine', u'isStrict', u'startLine'],
-        relative_path=u'tables/{tableId}/import',
+        http_method='POST',
+        method_id='fusiontables.table.importRows',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['delimiter', 'encoding', 'endLine', 'isStrict', 'startLine'],
+        relative_path='tables/{tableId}/import',
         request_field='',
-        request_type_name=u'FusiontablesTableImportRowsRequest',
-        response_type_name=u'Import',
+        request_type_name='FusiontablesTableImportRowsRequest',
+        response_type_name='Import',
         supports_download=False,
     )
 
@@ -595,15 +598,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           upload=upload, upload_config=upload_config)
 
     ImportTable.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.table.importTable',
-        ordered_params=[u'name'],
+        http_method='POST',
+        method_id='fusiontables.table.importTable',
+        ordered_params=['name'],
         path_params=[],
-        query_params=[u'delimiter', u'encoding', u'name'],
-        relative_path=u'tables/import',
+        query_params=['delimiter', 'encoding', 'name'],
+        relative_path='tables/import',
         request_field='',
-        request_type_name=u'FusiontablesTableImportTableRequest',
-        response_type_name=u'Table',
+        request_type_name='FusiontablesTableImportTableRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -621,15 +624,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.table.insert',
+        http_method='POST',
+        method_id='fusiontables.table.insert',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'tables',
+        relative_path='tables',
         request_field='<request>',
-        request_type_name=u'Table',
-        response_type_name=u'Table',
+        request_type_name='Table',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -647,15 +650,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.table.list',
+        http_method='GET',
+        method_id='fusiontables.table.list',
         ordered_params=[],
         path_params=[],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'tables',
+        query_params=['maxResults', 'pageToken'],
+        relative_path='tables',
         request_field='',
-        request_type_name=u'FusiontablesTableListRequest',
-        response_type_name=u'TableList',
+        request_type_name='FusiontablesTableListRequest',
+        response_type_name='TableList',
         supports_download=False,
     )
 
@@ -673,15 +676,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'fusiontables.table.patch',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'replaceViewDefinition'],
-        relative_path=u'tables/{tableId}',
-        request_field=u'table',
-        request_type_name=u'FusiontablesTablePatchRequest',
-        response_type_name=u'Table',
+        http_method='PATCH',
+        method_id='fusiontables.table.patch',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['replaceViewDefinition'],
+        relative_path='tables/{tableId}',
+        request_field='table',
+        request_type_name='FusiontablesTablePatchRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
@@ -699,22 +702,22 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'fusiontables.table.update',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'replaceViewDefinition'],
-        relative_path=u'tables/{tableId}',
-        request_field=u'table',
-        request_type_name=u'FusiontablesTableUpdateRequest',
-        response_type_name=u'Table',
+        http_method='PUT',
+        method_id='fusiontables.table.update',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['replaceViewDefinition'],
+        relative_path='tables/{tableId}',
+        request_field='table',
+        request_type_name='FusiontablesTableUpdateRequest',
+        response_type_name='Table',
         supports_download=False,
     )
 
   class TaskService(base_api.BaseApiService):
     """Service class for the task resource."""
 
-    _NAME = u'task'
+    _NAME = 'task'
 
     def __init__(self, client):
       super(FusiontablesV1.TaskService, self).__init__(client)
@@ -735,15 +738,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'fusiontables.task.delete',
-        ordered_params=[u'tableId', u'taskId'],
-        path_params=[u'tableId', u'taskId'],
+        http_method='DELETE',
+        method_id='fusiontables.task.delete',
+        ordered_params=['tableId', 'taskId'],
+        path_params=['tableId', 'taskId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/tasks/{taskId}',
+        relative_path='tables/{tableId}/tasks/{taskId}',
         request_field='',
-        request_type_name=u'FusiontablesTaskDeleteRequest',
-        response_type_name=u'FusiontablesTaskDeleteResponse',
+        request_type_name='FusiontablesTaskDeleteRequest',
+        response_type_name='FusiontablesTaskDeleteResponse',
         supports_download=False,
     )
 
@@ -761,15 +764,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.task.get',
-        ordered_params=[u'tableId', u'taskId'],
-        path_params=[u'tableId', u'taskId'],
+        http_method='GET',
+        method_id='fusiontables.task.get',
+        ordered_params=['tableId', 'taskId'],
+        path_params=['tableId', 'taskId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/tasks/{taskId}',
+        relative_path='tables/{tableId}/tasks/{taskId}',
         request_field='',
-        request_type_name=u'FusiontablesTaskGetRequest',
-        response_type_name=u'Task',
+        request_type_name='FusiontablesTaskGetRequest',
+        response_type_name='Task',
         supports_download=False,
     )
 
@@ -787,22 +790,22 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.task.list',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'maxResults', u'pageToken', u'startIndex'],
-        relative_path=u'tables/{tableId}/tasks',
+        http_method='GET',
+        method_id='fusiontables.task.list',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['maxResults', 'pageToken', 'startIndex'],
+        relative_path='tables/{tableId}/tasks',
         request_field='',
-        request_type_name=u'FusiontablesTaskListRequest',
-        response_type_name=u'TaskList',
+        request_type_name='FusiontablesTaskListRequest',
+        response_type_name='TaskList',
         supports_download=False,
     )
 
   class TemplateService(base_api.BaseApiService):
     """Service class for the template resource."""
 
-    _NAME = u'template'
+    _NAME = 'template'
 
     def __init__(self, client):
       super(FusiontablesV1.TemplateService, self).__init__(client)
@@ -823,15 +826,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'fusiontables.template.delete',
-        ordered_params=[u'tableId', u'templateId'],
-        path_params=[u'tableId', u'templateId'],
+        http_method='DELETE',
+        method_id='fusiontables.template.delete',
+        ordered_params=['tableId', 'templateId'],
+        path_params=['tableId', 'templateId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/templates/{templateId}',
+        relative_path='tables/{tableId}/templates/{templateId}',
         request_field='',
-        request_type_name=u'FusiontablesTemplateDeleteRequest',
-        response_type_name=u'FusiontablesTemplateDeleteResponse',
+        request_type_name='FusiontablesTemplateDeleteRequest',
+        response_type_name='FusiontablesTemplateDeleteResponse',
         supports_download=False,
     )
 
@@ -849,15 +852,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.template.get',
-        ordered_params=[u'tableId', u'templateId'],
-        path_params=[u'tableId', u'templateId'],
+        http_method='GET',
+        method_id='fusiontables.template.get',
+        ordered_params=['tableId', 'templateId'],
+        path_params=['tableId', 'templateId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/templates/{templateId}',
+        relative_path='tables/{tableId}/templates/{templateId}',
         request_field='',
-        request_type_name=u'FusiontablesTemplateGetRequest',
-        response_type_name=u'Template',
+        request_type_name='FusiontablesTemplateGetRequest',
+        response_type_name='Template',
         supports_download=False,
     )
 
@@ -875,15 +878,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'fusiontables.template.insert',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
+        http_method='POST',
+        method_id='fusiontables.template.insert',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/templates',
+        relative_path='tables/{tableId}/templates',
         request_field='<request>',
-        request_type_name=u'Template',
-        response_type_name=u'Template',
+        request_type_name='Template',
+        response_type_name='Template',
         supports_download=False,
     )
 
@@ -901,15 +904,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'fusiontables.template.list',
-        ordered_params=[u'tableId'],
-        path_params=[u'tableId'],
-        query_params=[u'maxResults', u'pageToken'],
-        relative_path=u'tables/{tableId}/templates',
+        http_method='GET',
+        method_id='fusiontables.template.list',
+        ordered_params=['tableId'],
+        path_params=['tableId'],
+        query_params=['maxResults', 'pageToken'],
+        relative_path='tables/{tableId}/templates',
         request_field='',
-        request_type_name=u'FusiontablesTemplateListRequest',
-        response_type_name=u'TemplateList',
+        request_type_name='FusiontablesTemplateListRequest',
+        response_type_name='TemplateList',
         supports_download=False,
     )
 
@@ -927,15 +930,15 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'fusiontables.template.patch',
-        ordered_params=[u'tableId', u'templateId'],
-        path_params=[u'tableId', u'templateId'],
+        http_method='PATCH',
+        method_id='fusiontables.template.patch',
+        ordered_params=['tableId', 'templateId'],
+        path_params=['tableId', 'templateId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/templates/{templateId}',
+        relative_path='tables/{tableId}/templates/{templateId}',
         request_field='<request>',
-        request_type_name=u'Template',
-        response_type_name=u'Template',
+        request_type_name='Template',
+        response_type_name='Template',
         supports_download=False,
     )
 
@@ -953,14 +956,14 @@ class FusiontablesV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'fusiontables.template.update',
-        ordered_params=[u'tableId', u'templateId'],
-        path_params=[u'tableId', u'templateId'],
+        http_method='PUT',
+        method_id='fusiontables.template.update',
+        ordered_params=['tableId', 'templateId'],
+        path_params=['tableId', 'templateId'],
         query_params=[],
-        relative_path=u'tables/{tableId}/templates/{templateId}',
+        relative_path='tables/{tableId}/templates/{templateId}',
         request_field='<request>',
-        request_type_name=u'Template',
-        response_type_name=u'Template',
+        request_type_name='Template',
+        response_type_name='Template',
         supports_download=False,
     )
diff --git a/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_messages.py b/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_messages.py
index 69f2cfb..361ecfe 100644
--- a/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_messages.py
+++ b/samples/fusiontables_sample/fusiontables_v1/fusiontables_v1_messages.py
@@ -4,6 +4,8 @@ API for working with Fusion Tables data.
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import messages as _messages
 from apitools.base.py import extra_types
 
@@ -72,7 +74,7 @@ class Column(_messages.Message):
   columnId = _messages.IntegerField(2, variant=_messages.Variant.INT32)
   description = _messages.StringField(3)
   graph_predicate = _messages.StringField(4)
-  kind = _messages.StringField(5, default=u'fusiontables#column')
+  kind = _messages.StringField(5, default='fusiontables#column')
   name = _messages.StringField(6)
   type = _messages.StringField(7)
 
@@ -89,7 +91,7 @@ class ColumnList(_messages.Message):
   """
 
   items = _messages.MessageField('Column', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#columnList')
+  kind = _messages.StringField(2, default='fusiontables#columnList')
   nextPageToken = _messages.StringField(3)
   totalItems = _messages.IntegerField(4, variant=_messages.Variant.INT32)
 
@@ -482,7 +484,7 @@ class Geometry(_messages.Message):
 
   geometries = _messages.MessageField('extra_types.JsonValue', 1, repeated=True)
   geometry = _messages.MessageField('extra_types.JsonValue', 2)
-  type = _messages.StringField(3, default=u'GeometryCollection')
+  type = _messages.StringField(3, default='GeometryCollection')
 
 
 class Import(_messages.Message):
@@ -493,7 +495,7 @@ class Import(_messages.Message):
     numRowsReceived: The number of rows received from the import request.
   """
 
-  kind = _messages.StringField(1, default=u'fusiontables#import')
+  kind = _messages.StringField(1, default='fusiontables#import')
   numRowsReceived = _messages.IntegerField(2)
 
 
@@ -518,7 +520,7 @@ class Line(_messages.Message):
     entry = _messages.FloatField(1, repeated=True)
 
   coordinates = _messages.MessageField('CoordinatesValueListEntry', 1, repeated=True)
-  type = _messages.StringField(2, default=u'LineString')
+  type = _messages.StringField(2, default='LineString')
 
 
 class LineStyle(_messages.Message):
@@ -550,7 +552,7 @@ class Point(_messages.Message):
   """
 
   coordinates = _messages.FloatField(1, repeated=True)
-  type = _messages.StringField(2, default=u'Point')
+  type = _messages.StringField(2, default='Point')
 
 
 class PointStyle(_messages.Message):
@@ -600,7 +602,7 @@ class Polygon(_messages.Message):
     entry = _messages.MessageField('EntryValueListEntry', 1, repeated=True)
 
   coordinates = _messages.MessageField('CoordinatesValueListEntry', 1, repeated=True)
-  type = _messages.StringField(2, default=u'Polygon')
+  type = _messages.StringField(2, default='Polygon')
 
 
 class PolygonStyle(_messages.Message):
@@ -656,7 +658,7 @@ class Sqlresponse(_messages.Message):
     entry = _messages.MessageField('extra_types.JsonValue', 1, repeated=True)
 
   columns = _messages.StringField(1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#sqlresponse')
+  kind = _messages.StringField(2, default='fusiontables#sqlresponse')
   rows = _messages.MessageField('RowsValueListEntry', 3, repeated=True)
 
 
@@ -693,7 +695,7 @@ class StandardQueryParameters(_messages.Message):
     csv = 0
     json = 1
 
-  alt = _messages.EnumField('AltValueValuesEnum', 1, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 1, default='json')
   fields = _messages.StringField(2)
   key = _messages.StringField(3)
   oauth_token = _messages.StringField(4)
@@ -778,7 +780,7 @@ class StyleSetting(_messages.Message):
     tableId: Identifier for the table.
   """
 
-  kind = _messages.StringField(1, default=u'fusiontables#styleSetting')
+  kind = _messages.StringField(1, default='fusiontables#styleSetting')
   markerOptions = _messages.MessageField('PointStyle', 2)
   name = _messages.StringField(3)
   polygonOptions = _messages.MessageField('PolygonStyle', 4)
@@ -799,7 +801,7 @@ class StyleSettingList(_messages.Message):
   """
 
   items = _messages.MessageField('StyleSetting', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#styleSettingList')
+  kind = _messages.StringField(2, default='fusiontables#styleSettingList')
   nextPageToken = _messages.StringField(3)
   totalItems = _messages.IntegerField(4, variant=_messages.Variant.INT32)
 
@@ -828,7 +830,7 @@ class Table(_messages.Message):
   columns = _messages.MessageField('Column', 4, repeated=True)
   description = _messages.StringField(5)
   isExportable = _messages.BooleanField(6)
-  kind = _messages.StringField(7, default=u'fusiontables#table')
+  kind = _messages.StringField(7, default='fusiontables#table')
   name = _messages.StringField(8)
   sql = _messages.StringField(9)
   tableId = _messages.StringField(10)
@@ -845,7 +847,7 @@ class TableList(_messages.Message):
   """
 
   items = _messages.MessageField('Table', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#tableList')
+  kind = _messages.StringField(2, default='fusiontables#tableList')
   nextPageToken = _messages.StringField(3)
 
 
@@ -865,7 +867,7 @@ class Task(_messages.Message):
       Changes the type of a column.
   """
 
-  kind = _messages.StringField(1, default=u'fusiontables#task')
+  kind = _messages.StringField(1, default='fusiontables#task')
   progress = _messages.StringField(2)
   started = _messages.BooleanField(3)
   taskId = _messages.IntegerField(4)
@@ -884,7 +886,7 @@ class TaskList(_messages.Message):
   """
 
   items = _messages.MessageField('Task', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#taskList')
+  kind = _messages.StringField(2, default='fusiontables#taskList')
   nextPageToken = _messages.StringField(3)
   totalItems = _messages.IntegerField(4, variant=_messages.Variant.INT32)
 
@@ -911,7 +913,7 @@ class Template(_messages.Message):
 
   automaticColumnNames = _messages.StringField(1, repeated=True)
   body = _messages.StringField(2)
-  kind = _messages.StringField(3, default=u'fusiontables#template')
+  kind = _messages.StringField(3, default='fusiontables#template')
   name = _messages.StringField(4)
   tableId = _messages.StringField(5)
   templateId = _messages.IntegerField(6, variant=_messages.Variant.INT32)
@@ -929,7 +931,7 @@ class TemplateList(_messages.Message):
   """
 
   items = _messages.MessageField('Template', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'fusiontables#templateList')
+  kind = _messages.StringField(2, default='fusiontables#templateList')
   nextPageToken = _messages.StringField(3)
   totalItems = _messages.IntegerField(4, variant=_messages.Variant.INT32)
 
diff --git a/samples/iam_sample/iam_v1.json b/samples/iam_sample/iam_v1.json
index 8e9480e..141b678 100644
--- a/samples/iam_sample/iam_v1.json
+++ b/samples/iam_sample/iam_v1.json
@@ -964,6 +964,12 @@
                   "required": true,
                   "pattern": "^projects\/[^\/]*\/serviceAccounts\/[^\/]*$",
                   "type": "string"
+                },
+                "options.requestedPolicyVersion": {
+                  "description": "Optional. The policy format version to be returned.\nAcceptable values are 0 and 1.\nIf the value is 0, or the field is omitted, policy format version 1 will be\nreturned.",
+                  "location": "query",
+                  "type": "integer",
+                  "format": "int32"
                 }
               },
               "parameterOrder": [
diff --git a/samples/iam_sample/iam_v1/__init__.py b/samples/iam_sample/iam_v1/__init__.py
index 2816da8..f437c62 100644
--- a/samples/iam_sample/iam_v1/__init__.py
+++ b/samples/iam_sample/iam_v1/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/iam_sample/iam_v1/iam_v1_client.py b/samples/iam_sample/iam_v1/iam_v1_client.py
index ed9112e..a4b6b73 100644
--- a/samples/iam_sample/iam_v1/iam_v1_client.py
+++ b/samples/iam_sample/iam_v1/iam_v1_client.py
@@ -1,5 +1,8 @@
 """Generated client library for iam version v1."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.iam_sample.iam_v1 import iam_v1_messages as messages
 
@@ -8,17 +11,17 @@ class IamV1(base_api.BaseApiClient):
   """Generated client library for service iam version v1."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://iam.googleapis.com/'
-  MTLS_BASE_URL = u''
-
-  _PACKAGE = u'iam'
-  _SCOPES = [u'https://www.googleapis.com/auth/cloud-platform']
-  _VERSION = u'v1'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://iam.googleapis.com/'
+  MTLS_BASE_URL = ''
+
+  _PACKAGE = 'iam'
+  _SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
+  _VERSION = 'v1'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'IamV1'
-  _URL_VERSION = u'v1'
+  _CLIENT_CLASS_NAME = 'IamV1'
+  _URL_VERSION = 'v1'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -45,7 +48,7 @@ class IamV1(base_api.BaseApiClient):
   class IamPoliciesService(base_api.BaseApiService):
     """Service class for the iamPolicies resource."""
 
-    _NAME = u'iamPolicies'
+    _NAME = 'iamPolicies'
 
     def __init__(self, client):
       super(IamV1.IamPoliciesService, self).__init__(client)
@@ -67,22 +70,22 @@ that the user has access to.
           config, request, global_params=global_params)
 
     GetPolicyDetails.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'iam.iamPolicies.getPolicyDetails',
+        http_method='POST',
+        method_id='iam.iamPolicies.getPolicyDetails',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'v1/iamPolicies:getPolicyDetails',
+        relative_path='v1/iamPolicies:getPolicyDetails',
         request_field='<request>',
-        request_type_name=u'GetPolicyDetailsRequest',
-        response_type_name=u'GetPolicyDetailsResponse',
+        request_type_name='GetPolicyDetailsRequest',
+        response_type_name='GetPolicyDetailsResponse',
         supports_download=False,
     )
 
   class ProjectsServiceAccountsKeysService(base_api.BaseApiService):
     """Service class for the projects_serviceAccounts_keys resource."""
 
-    _NAME = u'projects_serviceAccounts_keys'
+    _NAME = 'projects_serviceAccounts_keys'
 
     def __init__(self, client):
       super(IamV1.ProjectsServiceAccountsKeysService, self).__init__(client)
@@ -104,16 +107,16 @@ and returns it.
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.keys.create',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.keys.create',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}/keys',
-        request_field=u'createServiceAccountKeyRequest',
-        request_type_name=u'IamProjectsServiceAccountsKeysCreateRequest',
-        response_type_name=u'ServiceAccountKey',
+        relative_path='v1/{+name}/keys',
+        request_field='createServiceAccountKeyRequest',
+        request_type_name='IamProjectsServiceAccountsKeysCreateRequest',
+        response_type_name='ServiceAccountKey',
         supports_download=False,
     )
 
@@ -131,16 +134,16 @@ and returns it.
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys/{keysId}',
-        http_method=u'DELETE',
-        method_id=u'iam.projects.serviceAccounts.keys.delete',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys/{keysId}',
+        http_method='DELETE',
+        method_id='iam.projects.serviceAccounts.keys.delete',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}',
+        relative_path='v1/{+name}',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsKeysDeleteRequest',
-        response_type_name=u'Empty',
+        request_type_name='IamProjectsServiceAccountsKeysDeleteRequest',
+        response_type_name='Empty',
         supports_download=False,
     )
 
@@ -159,16 +162,16 @@ by key id.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys/{keysId}',
-        http_method=u'GET',
-        method_id=u'iam.projects.serviceAccounts.keys.get',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
-        query_params=[u'publicKeyType'],
-        relative_path=u'v1/{+name}',
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys/{keysId}',
+        http_method='GET',
+        method_id='iam.projects.serviceAccounts.keys.get',
+        ordered_params=['name'],
+        path_params=['name'],
+        query_params=['publicKeyType'],
+        relative_path='v1/{+name}',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsKeysGetRequest',
-        response_type_name=u'ServiceAccountKey',
+        request_type_name='IamProjectsServiceAccountsKeysGetRequest',
+        response_type_name='ServiceAccountKey',
         supports_download=False,
     )
 
@@ -186,23 +189,23 @@ by key id.
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys',
-        http_method=u'GET',
-        method_id=u'iam.projects.serviceAccounts.keys.list',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
-        query_params=[u'keyTypes'],
-        relative_path=u'v1/{+name}/keys',
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}/keys',
+        http_method='GET',
+        method_id='iam.projects.serviceAccounts.keys.list',
+        ordered_params=['name'],
+        path_params=['name'],
+        query_params=['keyTypes'],
+        relative_path='v1/{+name}/keys',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsKeysListRequest',
-        response_type_name=u'ListServiceAccountKeysResponse',
+        request_type_name='IamProjectsServiceAccountsKeysListRequest',
+        response_type_name='ListServiceAccountKeysResponse',
         supports_download=False,
     )
 
   class ProjectsServiceAccountsService(base_api.BaseApiService):
     """Service class for the projects_serviceAccounts resource."""
 
-    _NAME = u'projects_serviceAccounts'
+    _NAME = 'projects_serviceAccounts'
 
     def __init__(self, client):
       super(IamV1.ProjectsServiceAccountsService, self).__init__(client)
@@ -224,16 +227,16 @@ and returns it.
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.create',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.create',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}/serviceAccounts',
-        request_field=u'createServiceAccountRequest',
-        request_type_name=u'IamProjectsServiceAccountsCreateRequest',
-        response_type_name=u'ServiceAccount',
+        relative_path='v1/{+name}/serviceAccounts',
+        request_field='createServiceAccountRequest',
+        request_type_name='IamProjectsServiceAccountsCreateRequest',
+        response_type_name='ServiceAccount',
         supports_download=False,
     )
 
@@ -251,16 +254,16 @@ and returns it.
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
-        http_method=u'DELETE',
-        method_id=u'iam.projects.serviceAccounts.delete',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
+        http_method='DELETE',
+        method_id='iam.projects.serviceAccounts.delete',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}',
+        relative_path='v1/{+name}',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsDeleteRequest',
-        response_type_name=u'Empty',
+        request_type_name='IamProjectsServiceAccountsDeleteRequest',
+        response_type_name='Empty',
         supports_download=False,
     )
 
@@ -278,16 +281,16 @@ and returns it.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
-        http_method=u'GET',
-        method_id=u'iam.projects.serviceAccounts.get',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
+        http_method='GET',
+        method_id='iam.projects.serviceAccounts.get',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}',
+        relative_path='v1/{+name}',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsGetRequest',
-        response_type_name=u'ServiceAccount',
+        request_type_name='IamProjectsServiceAccountsGetRequest',
+        response_type_name='ServiceAccount',
         supports_download=False,
     )
 
@@ -305,16 +308,16 @@ and returns it.
           config, request, global_params=global_params)
 
     GetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:getIamPolicy',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.getIamPolicy',
-        ordered_params=[u'resource'],
-        path_params=[u'resource'],
-        query_params=[],
-        relative_path=u'v1/{+resource}:getIamPolicy',
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:getIamPolicy',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.getIamPolicy',
+        ordered_params=['resource'],
+        path_params=['resource'],
+        query_params=['options_requestedPolicyVersion'],
+        relative_path='v1/{+resource}:getIamPolicy',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsGetIamPolicyRequest',
-        response_type_name=u'Policy',
+        request_type_name='IamProjectsServiceAccountsGetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -332,16 +335,16 @@ and returns it.
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts',
-        http_method=u'GET',
-        method_id=u'iam.projects.serviceAccounts.list',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
-        query_params=[u'pageSize', u'pageToken', u'removeDeletedServiceAccounts'],
-        relative_path=u'v1/{+name}/serviceAccounts',
+        flat_path='v1/projects/{projectsId}/serviceAccounts',
+        http_method='GET',
+        method_id='iam.projects.serviceAccounts.list',
+        ordered_params=['name'],
+        path_params=['name'],
+        query_params=['pageSize', 'pageToken', 'removeDeletedServiceAccounts'],
+        relative_path='v1/{+name}/serviceAccounts',
         request_field='',
-        request_type_name=u'IamProjectsServiceAccountsListRequest',
-        response_type_name=u'ListServiceAccountsResponse',
+        request_type_name='IamProjectsServiceAccountsListRequest',
+        response_type_name='ListServiceAccountsResponse',
         supports_download=False,
     )
 
@@ -359,16 +362,16 @@ and returns it.
           config, request, global_params=global_params)
 
     SetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:setIamPolicy',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.setIamPolicy',
-        ordered_params=[u'resource'],
-        path_params=[u'resource'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:setIamPolicy',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.setIamPolicy',
+        ordered_params=['resource'],
+        path_params=['resource'],
         query_params=[],
-        relative_path=u'v1/{+resource}:setIamPolicy',
-        request_field=u'setIamPolicyRequest',
-        request_type_name=u'IamProjectsServiceAccountsSetIamPolicyRequest',
-        response_type_name=u'Policy',
+        relative_path='v1/{+resource}:setIamPolicy',
+        request_field='setIamPolicyRequest',
+        request_type_name='IamProjectsServiceAccountsSetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -386,16 +389,16 @@ and returns it.
           config, request, global_params=global_params)
 
     SignBlob.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:signBlob',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.signBlob',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:signBlob',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.signBlob',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}:signBlob',
-        request_field=u'signBlobRequest',
-        request_type_name=u'IamProjectsServiceAccountsSignBlobRequest',
-        response_type_name=u'SignBlobResponse',
+        relative_path='v1/{+name}:signBlob',
+        request_field='signBlobRequest',
+        request_type_name='IamProjectsServiceAccountsSignBlobRequest',
+        response_type_name='SignBlobResponse',
         supports_download=False,
     )
 
@@ -418,16 +421,16 @@ will fail.
           config, request, global_params=global_params)
 
     SignJwt.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:signJwt',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.signJwt',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:signJwt',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.signJwt',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}:signJwt',
-        request_field=u'signJwtRequest',
-        request_type_name=u'IamProjectsServiceAccountsSignJwtRequest',
-        response_type_name=u'SignJwtResponse',
+        relative_path='v1/{+name}:signJwt',
+        request_field='signJwtRequest',
+        request_type_name='IamProjectsServiceAccountsSignJwtRequest',
+        response_type_name='SignJwtResponse',
         supports_download=False,
     )
 
@@ -446,16 +449,16 @@ for the specified IAM resource.
           config, request, global_params=global_params)
 
     TestIamPermissions.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:testIamPermissions',
-        http_method=u'POST',
-        method_id=u'iam.projects.serviceAccounts.testIamPermissions',
-        ordered_params=[u'resource'],
-        path_params=[u'resource'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}:testIamPermissions',
+        http_method='POST',
+        method_id='iam.projects.serviceAccounts.testIamPermissions',
+        ordered_params=['resource'],
+        path_params=['resource'],
         query_params=[],
-        relative_path=u'v1/{+resource}:testIamPermissions',
-        request_field=u'testIamPermissionsRequest',
-        request_type_name=u'IamProjectsServiceAccountsTestIamPermissionsRequest',
-        response_type_name=u'TestIamPermissionsResponse',
+        relative_path='v1/{+resource}:testIamPermissions',
+        request_field='testIamPermissionsRequest',
+        request_type_name='IamProjectsServiceAccountsTestIamPermissionsRequest',
+        response_type_name='TestIamPermissionsResponse',
         supports_download=False,
     )
 
@@ -477,23 +480,23 @@ The `etag` is mandatory.
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        flat_path=u'v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
-        http_method=u'PUT',
-        method_id=u'iam.projects.serviceAccounts.update',
-        ordered_params=[u'name'],
-        path_params=[u'name'],
+        flat_path='v1/projects/{projectsId}/serviceAccounts/{serviceAccountsId}',
+        http_method='PUT',
+        method_id='iam.projects.serviceAccounts.update',
+        ordered_params=['name'],
+        path_params=['name'],
         query_params=[],
-        relative_path=u'v1/{+name}',
+        relative_path='v1/{+name}',
         request_field='<request>',
-        request_type_name=u'ServiceAccount',
-        response_type_name=u'ServiceAccount',
+        request_type_name='ServiceAccount',
+        response_type_name='ServiceAccount',
         supports_download=False,
     )
 
   class ProjectsService(base_api.BaseApiService):
     """Service class for the projects resource."""
 
-    _NAME = u'projects'
+    _NAME = 'projects'
 
     def __init__(self, client):
       super(IamV1.ProjectsService, self).__init__(client)
@@ -503,7 +506,7 @@ The `etag` is mandatory.
   class RolesService(base_api.BaseApiService):
     """Service class for the roles resource."""
 
-    _NAME = u'roles'
+    _NAME = 'roles'
 
     def __init__(self, client):
       super(IamV1.RolesService, self).__init__(client)
@@ -524,14 +527,14 @@ The `etag` is mandatory.
           config, request, global_params=global_params)
 
     QueryGrantableRoles.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'iam.roles.queryGrantableRoles',
+        http_method='POST',
+        method_id='iam.roles.queryGrantableRoles',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'v1/roles:queryGrantableRoles',
+        relative_path='v1/roles:queryGrantableRoles',
         request_field='<request>',
-        request_type_name=u'QueryGrantableRolesRequest',
-        response_type_name=u'QueryGrantableRolesResponse',
+        request_type_name='QueryGrantableRolesRequest',
+        response_type_name='QueryGrantableRolesResponse',
         supports_download=False,
     )
diff --git a/samples/iam_sample/iam_v1/iam_v1_messages.py b/samples/iam_sample/iam_v1/iam_v1_messages.py
index aaf2bcf..1f3cbe9 100644
--- a/samples/iam_sample/iam_v1/iam_v1_messages.py
+++ b/samples/iam_sample/iam_v1/iam_v1_messages.py
@@ -6,6 +6,8 @@ to Google and make API calls.
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import messages as _messages
 from apitools.base.py import encoding
 
@@ -278,6 +280,9 @@ class IamProjectsServiceAccountsGetIamPolicyRequest(_messages.Message):
   r"""A IamProjectsServiceAccountsGetIamPolicyRequest object.
 
   Fields:
+    options_requestedPolicyVersion: Optional. The policy format version to be
+      returned. Acceptable values are 0 and 1. If the value is 0, or the field
+      is omitted, policy format version 1 will be returned.
     resource: REQUIRED: The resource for which the policy is being requested.
       `resource` is usually specified as a path, such as
       `projects/*project*/zones/*zone*/disks/*disk*`.  The format for the path
@@ -285,7 +290,8 @@ class IamProjectsServiceAccountsGetIamPolicyRequest(_messages.Message):
       `getIamPolicy` documentation.
   """
 
-  resource = _messages.StringField(1, required=True)
+  options_requestedPolicyVersion = _messages.IntegerField(1, variant=_messages.Variant.INT32)
+  resource = _messages.StringField(2, required=True)
 
 
 class IamProjectsServiceAccountsGetRequest(_messages.Message):
@@ -913,7 +919,7 @@ class StandardQueryParameters(_messages.Message):
 
   f__xgafv = _messages.EnumField('FXgafvValueValuesEnum', 1)
   access_token = _messages.StringField(2)
-  alt = _messages.EnumField('AltValueValuesEnum', 3, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 3, default='json')
   bearer_token = _messages.StringField(4)
   callback = _messages.StringField(5)
   fields = _messages.StringField(6)
@@ -958,3 +964,5 @@ encoding.AddCustomJsonEnumMapping(
     StandardQueryParameters.FXgafvValueValuesEnum, '_1', '1')
 encoding.AddCustomJsonEnumMapping(
     StandardQueryParameters.FXgafvValueValuesEnum, '_2', '2')
+encoding.AddCustomJsonFieldMapping(
+    IamProjectsServiceAccountsGetIamPolicyRequest, 'options_requestedPolicyVersion', 'options.requestedPolicyVersion')
diff --git a/samples/servicemanagement_sample/servicemanagement_v1/__init__.py b/samples/servicemanagement_sample/servicemanagement_v1/__init__.py
index 2816da8..f437c62 100644
--- a/samples/servicemanagement_sample/servicemanagement_v1/__init__.py
+++ b/samples/servicemanagement_sample/servicemanagement_v1/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_client.py b/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_client.py
index 25823db..c73b425 100644
--- a/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_client.py
+++ b/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_client.py
@@ -1,5 +1,8 @@
 """Generated client library for servicemanagement version v1."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.servicemanagement_sample.servicemanagement_v1 import servicemanagement_v1_messages as messages
 
@@ -8,17 +11,17 @@ class ServicemanagementV1(base_api.BaseApiClient):
   """Generated client library for service servicemanagement version v1."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://servicemanagement.googleapis.com/'
-  MTLS_BASE_URL = u''
-
-  _PACKAGE = u'servicemanagement'
-  _SCOPES = [u'https://www.googleapis.com/auth/cloud-platform', u'https://www.googleapis.com/auth/service.management']
-  _VERSION = u'v1'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://servicemanagement.googleapis.com/'
+  MTLS_BASE_URL = ''
+
+  _PACKAGE = 'servicemanagement'
+  _SCOPES = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/service.management']
+  _VERSION = 'v1'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'ServicemanagementV1'
-  _URL_VERSION = u'v1'
+  _CLIENT_CLASS_NAME = 'ServicemanagementV1'
+  _URL_VERSION = 'v1'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -47,7 +50,7 @@ class ServicemanagementV1(base_api.BaseApiClient):
   class OperationsService(base_api.BaseApiService):
     """Service class for the operations resource."""
 
-    _NAME = u'operations'
+    _NAME = 'operations'
 
     def __init__(self, client):
       super(ServicemanagementV1.OperationsService, self).__init__(client)
@@ -70,22 +73,22 @@ service.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.operations.get',
-        ordered_params=[u'operationsId'],
-        path_params=[u'operationsId'],
+        http_method='GET',
+        method_id='servicemanagement.operations.get',
+        ordered_params=['operationsId'],
+        path_params=['operationsId'],
         query_params=[],
-        relative_path=u'v1/operations/{operationsId}',
+        relative_path='v1/operations/{operationsId}',
         request_field='',
-        request_type_name=u'ServicemanagementOperationsGetRequest',
-        response_type_name=u'Operation',
+        request_type_name='ServicemanagementOperationsGetRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
   class ServicesAccessPolicyService(base_api.BaseApiService):
     """Service class for the services_accessPolicy resource."""
 
-    _NAME = u'services_accessPolicy'
+    _NAME = 'services_accessPolicy'
 
     def __init__(self, client):
       super(ServicemanagementV1.ServicesAccessPolicyService, self).__init__(client)
@@ -113,22 +116,22 @@ the service.
           config, request, global_params=global_params)
 
     Query.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.accessPolicy.query',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'userEmail'],
-        relative_path=u'v1/services/{serviceName}/accessPolicy:query',
+        http_method='POST',
+        method_id='servicemanagement.services.accessPolicy.query',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['userEmail'],
+        relative_path='v1/services/{serviceName}/accessPolicy:query',
         request_field='',
-        request_type_name=u'ServicemanagementServicesAccessPolicyQueryRequest',
-        response_type_name=u'QueryUserAccessResponse',
+        request_type_name='ServicemanagementServicesAccessPolicyQueryRequest',
+        response_type_name='QueryUserAccessResponse',
         supports_download=False,
     )
 
   class ServicesConfigsService(base_api.BaseApiService):
     """Service class for the services_configs resource."""
 
-    _NAME = u'services_configs'
+    _NAME = 'services_configs'
 
     def __init__(self, client):
       super(ServicemanagementV1.ServicesConfigsService, self).__init__(client)
@@ -151,15 +154,15 @@ any backend services.
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.configs.create',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='POST',
+        method_id='servicemanagement.services.configs.create',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/configs',
-        request_field=u'service',
-        request_type_name=u'ServicemanagementServicesConfigsCreateRequest',
-        response_type_name=u'Service',
+        relative_path='v1/services/{serviceName}/configs',
+        request_field='service',
+        request_type_name='ServicemanagementServicesConfigsCreateRequest',
+        response_type_name='Service',
         supports_download=False,
     )
 
@@ -178,15 +181,15 @@ not specified, the latest service config will be returned.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.configs.get',
-        ordered_params=[u'serviceName', u'configId'],
-        path_params=[u'configId', u'serviceName'],
+        http_method='GET',
+        method_id='servicemanagement.services.configs.get',
+        ordered_params=['serviceName', 'configId'],
+        path_params=['configId', 'serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/configs/{configId}',
+        relative_path='v1/services/{serviceName}/configs/{configId}',
         request_field='',
-        request_type_name=u'ServicemanagementServicesConfigsGetRequest',
-        response_type_name=u'Service',
+        request_type_name='ServicemanagementServicesConfigsGetRequest',
+        response_type_name='Service',
         supports_download=False,
     )
 
@@ -205,15 +208,15 @@ from the newest to the oldest.
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.configs.list',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'pageSize', u'pageToken'],
-        relative_path=u'v1/services/{serviceName}/configs',
+        http_method='GET',
+        method_id='servicemanagement.services.configs.list',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['pageSize', 'pageToken'],
+        relative_path='v1/services/{serviceName}/configs',
         request_field='',
-        request_type_name=u'ServicemanagementServicesConfigsListRequest',
-        response_type_name=u'ListServiceConfigsResponse',
+        request_type_name='ServicemanagementServicesConfigsListRequest',
+        response_type_name='ListServiceConfigsResponse',
         supports_download=False,
     )
 
@@ -237,22 +240,22 @@ Operation<response: SubmitConfigSourceResponse>
           config, request, global_params=global_params)
 
     Submit.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.configs.submit',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='POST',
+        method_id='servicemanagement.services.configs.submit',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/configs:submit',
-        request_field=u'submitConfigSourceRequest',
-        request_type_name=u'ServicemanagementServicesConfigsSubmitRequest',
-        response_type_name=u'Operation',
+        relative_path='v1/services/{serviceName}/configs:submit',
+        request_field='submitConfigSourceRequest',
+        request_type_name='ServicemanagementServicesConfigsSubmitRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
   class ServicesCustomerSettingsService(base_api.BaseApiService):
     """Service class for the services_customerSettings resource."""
 
-    _NAME = u'services_customerSettings'
+    _NAME = 'services_customerSettings'
 
     def __init__(self, client):
       super(ServicemanagementV1.ServicesCustomerSettingsService, self).__init__(client)
@@ -274,15 +277,15 @@ service.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.customerSettings.get',
-        ordered_params=[u'serviceName', u'customerId'],
-        path_params=[u'customerId', u'serviceName'],
-        query_params=[u'expand', u'view'],
-        relative_path=u'v1/services/{serviceName}/customerSettings/{customerId}',
+        http_method='GET',
+        method_id='servicemanagement.services.customerSettings.get',
+        ordered_params=['serviceName', 'customerId'],
+        path_params=['customerId', 'serviceName'],
+        query_params=['expand', 'view'],
+        relative_path='v1/services/{serviceName}/customerSettings/{customerId}',
         request_field='',
-        request_type_name=u'ServicemanagementServicesCustomerSettingsGetRequest',
-        response_type_name=u'CustomerSettings',
+        request_type_name='ServicemanagementServicesCustomerSettingsGetRequest',
+        response_type_name='CustomerSettings',
         supports_download=False,
     )
 
@@ -304,22 +307,22 @@ Operation<response: CustomerSettings>
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'servicemanagement.services.customerSettings.patch',
-        ordered_params=[u'serviceName', u'customerId'],
-        path_params=[u'customerId', u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}/customerSettings/{customerId}',
-        request_field=u'customerSettings',
-        request_type_name=u'ServicemanagementServicesCustomerSettingsPatchRequest',
-        response_type_name=u'Operation',
+        http_method='PATCH',
+        method_id='servicemanagement.services.customerSettings.patch',
+        ordered_params=['serviceName', 'customerId'],
+        path_params=['customerId', 'serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}/customerSettings/{customerId}',
+        request_field='customerSettings',
+        request_type_name='ServicemanagementServicesCustomerSettingsPatchRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
   class ServicesProjectSettingsService(base_api.BaseApiService):
     """Service class for the services_projectSettings resource."""
 
-    _NAME = u'services_projectSettings'
+    _NAME = 'services_projectSettings'
 
     def __init__(self, client):
       super(ServicemanagementV1.ServicesProjectSettingsService, self).__init__(client)
@@ -341,15 +344,15 @@ of the service.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.projectSettings.get',
-        ordered_params=[u'serviceName', u'consumerProjectId'],
-        path_params=[u'consumerProjectId', u'serviceName'],
-        query_params=[u'expand', u'view'],
-        relative_path=u'v1/services/{serviceName}/projectSettings/{consumerProjectId}',
+        http_method='GET',
+        method_id='servicemanagement.services.projectSettings.get',
+        ordered_params=['serviceName', 'consumerProjectId'],
+        path_params=['consumerProjectId', 'serviceName'],
+        query_params=['expand', 'view'],
+        relative_path='v1/services/{serviceName}/projectSettings/{consumerProjectId}',
         request_field='',
-        request_type_name=u'ServicemanagementServicesProjectSettingsGetRequest',
-        response_type_name=u'ProjectSettings',
+        request_type_name='ServicemanagementServicesProjectSettingsGetRequest',
+        response_type_name='ProjectSettings',
         supports_download=False,
     )
 
@@ -371,15 +374,15 @@ Operation<response: ProjectSettings>
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'servicemanagement.services.projectSettings.patch',
-        ordered_params=[u'serviceName', u'consumerProjectId'],
-        path_params=[u'consumerProjectId', u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}/projectSettings/{consumerProjectId}',
-        request_field=u'projectSettings',
-        request_type_name=u'ServicemanagementServicesProjectSettingsPatchRequest',
-        response_type_name=u'Operation',
+        http_method='PATCH',
+        method_id='servicemanagement.services.projectSettings.patch',
+        ordered_params=['serviceName', 'consumerProjectId'],
+        path_params=['consumerProjectId', 'serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}/projectSettings/{consumerProjectId}',
+        request_field='projectSettings',
+        request_type_name='ServicemanagementServicesProjectSettingsPatchRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -403,22 +406,22 @@ Operation<response: ProjectSettings>
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'servicemanagement.services.projectSettings.update',
-        ordered_params=[u'serviceName', u'consumerProjectId'],
-        path_params=[u'consumerProjectId', u'serviceName'],
+        http_method='PUT',
+        method_id='servicemanagement.services.projectSettings.update',
+        ordered_params=['serviceName', 'consumerProjectId'],
+        path_params=['consumerProjectId', 'serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/projectSettings/{consumerProjectId}',
+        relative_path='v1/services/{serviceName}/projectSettings/{consumerProjectId}',
         request_field='<request>',
-        request_type_name=u'ProjectSettings',
-        response_type_name=u'Operation',
+        request_type_name='ProjectSettings',
+        response_type_name='Operation',
         supports_download=False,
     )
 
   class ServicesService(base_api.BaseApiService):
     """Service class for the services resource."""
 
-    _NAME = u'services'
+    _NAME = 'services'
 
     def __init__(self, client):
       super(ServicemanagementV1.ServicesService, self).__init__(client)
@@ -443,15 +446,15 @@ equivalent `google.api.Service`.
           config, request, global_params=global_params)
 
     ConvertConfig.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.convertConfig',
+        http_method='POST',
+        method_id='servicemanagement.services.convertConfig',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'v1/services:convertConfig',
+        relative_path='v1/services:convertConfig',
         request_field='<request>',
-        request_type_name=u'ConvertConfigRequest',
-        response_type_name=u'ConvertConfigResponse',
+        request_type_name='ConvertConfigRequest',
+        response_type_name='ConvertConfigResponse',
         supports_download=False,
     )
 
@@ -471,15 +474,15 @@ Operation<response: ManagedService>
           config, request, global_params=global_params)
 
     Create.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.create',
+        http_method='POST',
+        method_id='servicemanagement.services.create',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'v1/services',
+        relative_path='v1/services',
         request_field='<request>',
-        request_type_name=u'ManagedService',
-        response_type_name=u'Operation',
+        request_type_name='ManagedService',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -499,15 +502,15 @@ Operation<response: google.protobuf.Empty>
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'servicemanagement.services.delete',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='DELETE',
+        method_id='servicemanagement.services.delete',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}',
+        relative_path='v1/services/{serviceName}',
         request_field='',
-        request_type_name=u'ServicemanagementServicesDeleteRequest',
-        response_type_name=u'Operation',
+        request_type_name='ServicemanagementServicesDeleteRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -529,15 +532,15 @@ Operation<response: DisableServiceResponse>
           config, request, global_params=global_params)
 
     Disable.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.disable',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='POST',
+        method_id='servicemanagement.services.disable',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}:disable',
-        request_field=u'disableServiceRequest',
-        request_type_name=u'ServicemanagementServicesDisableRequest',
-        response_type_name=u'Operation',
+        relative_path='v1/services/{serviceName}:disable',
+        request_field='disableServiceRequest',
+        request_type_name='ServicemanagementServicesDisableRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -558,15 +561,15 @@ Operation<response: EnableServiceResponse>
           config, request, global_params=global_params)
 
     Enable.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.services.enable',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='POST',
+        method_id='servicemanagement.services.enable',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}:enable',
-        request_field=u'enableServiceRequest',
-        request_type_name=u'ServicemanagementServicesEnableRequest',
-        response_type_name=u'Operation',
+        relative_path='v1/services/{serviceName}:enable',
+        request_field='enableServiceRequest',
+        request_type_name='ServicemanagementServicesEnableRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -585,15 +588,15 @@ the project's settings for the specified service are also returned.
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.get',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'consumerProjectId', u'expand', u'view'],
-        relative_path=u'v1/services/{serviceName}',
+        http_method='GET',
+        method_id='servicemanagement.services.get',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['consumerProjectId', 'expand', 'view'],
+        relative_path='v1/services/{serviceName}',
         request_field='',
-        request_type_name=u'ServicemanagementServicesGetRequest',
-        response_type_name=u'ManagedService',
+        request_type_name='ServicemanagementServicesGetRequest',
+        response_type_name='ManagedService',
         supports_download=False,
     )
 
@@ -611,15 +614,15 @@ the project's settings for the specified service are also returned.
           config, request, global_params=global_params)
 
     GetAccessPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.getAccessPolicy',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='GET',
+        method_id='servicemanagement.services.getAccessPolicy',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/accessPolicy',
+        relative_path='v1/services/{serviceName}/accessPolicy',
         request_field='',
-        request_type_name=u'ServicemanagementServicesGetAccessPolicyRequest',
-        response_type_name=u'ServiceAccessPolicy',
+        request_type_name='ServicemanagementServicesGetAccessPolicyRequest',
+        response_type_name='ServiceAccessPolicy',
         supports_download=False,
     )
 
@@ -638,15 +641,15 @@ not specified, the latest service config will be returned.
           config, request, global_params=global_params)
 
     GetConfig.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.getConfig',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'configId'],
-        relative_path=u'v1/services/{serviceName}/config',
+        http_method='GET',
+        method_id='servicemanagement.services.getConfig',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['configId'],
+        relative_path='v1/services/{serviceName}/config',
         request_field='',
-        request_type_name=u'ServicemanagementServicesGetConfigRequest',
-        response_type_name=u'Service',
+        request_type_name='ServicemanagementServicesGetConfigRequest',
+        response_type_name='Service',
         supports_download=False,
     )
 
@@ -665,15 +668,15 @@ the project's settings for the specified service are also returned.
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'servicemanagement.services.list',
+        http_method='GET',
+        method_id='servicemanagement.services.list',
         ordered_params=[],
         path_params=[],
-        query_params=[u'category', u'consumerProjectId', u'expand', u'pageSize', u'pageToken', u'producerProjectId'],
-        relative_path=u'v1/services',
+        query_params=['category', 'consumerProjectId', 'expand', 'pageSize', 'pageToken', 'producerProjectId'],
+        relative_path='v1/services',
         request_field='',
-        request_type_name=u'ServicemanagementServicesListRequest',
-        response_type_name=u'ListServicesResponse',
+        request_type_name='ServicemanagementServicesListRequest',
+        response_type_name='ListServicesResponse',
         supports_download=False,
     )
 
@@ -694,15 +697,15 @@ Operation<response: ManagedService>
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'servicemanagement.services.patch',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}',
-        request_field=u'managedService',
-        request_type_name=u'ServicemanagementServicesPatchRequest',
-        response_type_name=u'Operation',
+        http_method='PATCH',
+        method_id='servicemanagement.services.patch',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}',
+        request_field='managedService',
+        request_type_name='ServicemanagementServicesPatchRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -723,15 +726,15 @@ Operation<response: google.api.Service>
           config, request, global_params=global_params)
 
     PatchConfig.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'servicemanagement.services.patchConfig',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}/config',
-        request_field=u'service',
-        request_type_name=u'ServicemanagementServicesPatchConfigRequest',
-        response_type_name=u'Operation',
+        http_method='PATCH',
+        method_id='servicemanagement.services.patchConfig',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}/config',
+        request_field='service',
+        request_type_name='ServicemanagementServicesPatchConfigRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -752,15 +755,15 @@ Operation<response: ManagedService>
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'servicemanagement.services.update',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}',
-        request_field=u'managedService',
-        request_type_name=u'ServicemanagementServicesUpdateRequest',
-        response_type_name=u'Operation',
+        http_method='PUT',
+        method_id='servicemanagement.services.update',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}',
+        request_field='managedService',
+        request_type_name='ServicemanagementServicesUpdateRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
@@ -779,15 +782,15 @@ error if the policy is too large (more than 50 entries across all lists).
           config, request, global_params=global_params)
 
     UpdateAccessPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'servicemanagement.services.updateAccessPolicy',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
+        http_method='PUT',
+        method_id='servicemanagement.services.updateAccessPolicy',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
         query_params=[],
-        relative_path=u'v1/services/{serviceName}/accessPolicy',
+        relative_path='v1/services/{serviceName}/accessPolicy',
         request_field='<request>',
-        request_type_name=u'ServiceAccessPolicy',
-        response_type_name=u'ServiceAccessPolicy',
+        request_type_name='ServiceAccessPolicy',
+        response_type_name='ServiceAccessPolicy',
         supports_download=False,
     )
 
@@ -808,22 +811,22 @@ Operation<response: google.api.Service>
           config, request, global_params=global_params)
 
     UpdateConfig.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'servicemanagement.services.updateConfig',
-        ordered_params=[u'serviceName'],
-        path_params=[u'serviceName'],
-        query_params=[u'updateMask'],
-        relative_path=u'v1/services/{serviceName}/config',
-        request_field=u'service',
-        request_type_name=u'ServicemanagementServicesUpdateConfigRequest',
-        response_type_name=u'Operation',
+        http_method='PUT',
+        method_id='servicemanagement.services.updateConfig',
+        ordered_params=['serviceName'],
+        path_params=['serviceName'],
+        query_params=['updateMask'],
+        relative_path='v1/services/{serviceName}/config',
+        request_field='service',
+        request_type_name='ServicemanagementServicesUpdateConfigRequest',
+        response_type_name='Operation',
         supports_download=False,
     )
 
   class V1Service(base_api.BaseApiService):
     """Service class for the v1 resource."""
 
-    _NAME = u'v1'
+    _NAME = 'v1'
 
     def __init__(self, client):
       super(ServicemanagementV1.V1Service, self).__init__(client)
@@ -848,14 +851,14 @@ equivalent `google.api.Service`.
           config, request, global_params=global_params)
 
     ConvertConfig.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'servicemanagement.convertConfig',
+        http_method='POST',
+        method_id='servicemanagement.convertConfig',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'v1:convertConfig',
+        relative_path='v1:convertConfig',
         request_field='<request>',
-        request_type_name=u'ConvertConfigRequest',
-        response_type_name=u'ConvertConfigResponse',
+        request_type_name='ConvertConfigRequest',
+        response_type_name='ConvertConfigResponse',
         supports_download=False,
     )
diff --git a/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_messages.py b/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_messages.py
index 65b660c..f0c3abe 100644
--- a/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_messages.py
+++ b/samples/servicemanagement_sample/servicemanagement_v1/servicemanagement_v1_messages.py
@@ -4,6 +4,8 @@ The service management API for Google Cloud Platform
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import messages as _messages
 from apitools.base.py import encoding
 from apitools.base.py import extra_types
@@ -105,10 +107,11 @@ class AuthProvider(_messages.Message):
     jwksUri: URL of the provider's public key set to validate signature of the
       JWT. See [OpenID Discovery](https://openid.net/specs/openid-connect-
       discovery-1_0.html#ProviderMetadata). Optional if the key set document:
-      - can be retrieved from    [OpenID Discovery](https://openid.net/specs
-      /openid-connect-discovery-1_0.html    of the issuer.  - can be inferred
-      from the email domain of the issuer (e.g. a Google service account).
-      Example: https://www.googleapis.com/oauth2/v1/certs
+      - can be retrieved from    [OpenID
+      Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html
+      of the issuer.  - can be inferred from the email domain of the issuer
+      (e.g. a Google service account).  Example:
+      https://www.googleapis.com/oauth2/v1/certs
   """
 
   id = _messages.StringField(1)
@@ -3023,7 +3026,7 @@ class StandardQueryParameters(_messages.Message):
 
   f__xgafv = _messages.EnumField('FXgafvValueValuesEnum', 1)
   access_token = _messages.StringField(2)
-  alt = _messages.EnumField('AltValueValuesEnum', 3, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 3, default='json')
   bearer_token = _messages.StringField(4)
   callback = _messages.StringField(5)
   fields = _messages.StringField(6)
diff --git a/samples/storage_sample/storage_v1/__init__.py b/samples/storage_sample/storage_v1/__init__.py
index 2816da8..f437c62 100644
--- a/samples/storage_sample/storage_v1/__init__.py
+++ b/samples/storage_sample/storage_v1/__init__.py
@@ -1,5 +1,7 @@
 """Package marker file."""
 
+from __future__ import absolute_import
+
 import pkgutil
 
 __path__ = pkgutil.extend_path(__path__, __name__)
diff --git a/samples/storage_sample/storage_v1/storage_v1_client.py b/samples/storage_sample/storage_v1/storage_v1_client.py
index 4a8414a..fdfd2d8 100644
--- a/samples/storage_sample/storage_v1/storage_v1_client.py
+++ b/samples/storage_sample/storage_v1/storage_v1_client.py
@@ -1,5 +1,8 @@
 """Generated client library for storage version v1."""
 # NOTE: This file is autogenerated and should not be edited by hand.
+
+from __future__ import absolute_import
+
 from apitools.base.py import base_api
 from samples.storage_sample.storage_v1 import storage_v1_messages as messages
 
@@ -8,17 +11,17 @@ class StorageV1(base_api.BaseApiClient):
   """Generated client library for service storage version v1."""
 
   MESSAGES_MODULE = messages
-  BASE_URL = u'https://www.googleapis.com/storage/v1/'
-  MTLS_BASE_URL = u'https://www.mtls.googleapis.com/storage/v1/'
-
-  _PACKAGE = u'storage'
-  _SCOPES = [u'https://www.googleapis.com/auth/cloud-platform', u'https://www.googleapis.com/auth/cloud-platform.read-only', u'https://www.googleapis.com/auth/devstorage.full_control', u'https://www.googleapis.com/auth/devstorage.read_only', u'https://www.googleapis.com/auth/devstorage.read_write']
-  _VERSION = u'v1'
-  _CLIENT_ID = '1042881264118.apps.googleusercontent.com'
-  _CLIENT_SECRET = 'x_Tw5K8nnjoRAqULM9PFAC2b'
+  BASE_URL = 'https://www.googleapis.com/storage/v1/'
+  MTLS_BASE_URL = 'https://www.mtls.googleapis.com/storage/v1/'
+
+  _PACKAGE = 'storage'
+  _SCOPES = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-platform.read-only', 'https://www.googleapis.com/auth/devstorage.full_control', 'https://www.googleapis.com/auth/devstorage.read_only', 'https://www.googleapis.com/auth/devstorage.read_write']
+  _VERSION = 'v1'
+  _CLIENT_ID = 'CLIENT_ID'
+  _CLIENT_SECRET = 'CLIENT_SECRET'
   _USER_AGENT = 'x_Tw5K8nnjoRAqULM9PFAC2b'
-  _CLIENT_CLASS_NAME = u'StorageV1'
-  _URL_VERSION = u'v1'
+  _CLIENT_CLASS_NAME = 'StorageV1'
+  _URL_VERSION = 'v1'
   _API_KEY = None
 
   def __init__(self, url='', credentials=None,
@@ -47,7 +50,7 @@ class StorageV1(base_api.BaseApiClient):
   class BucketAccessControlsService(base_api.BaseApiService):
     """Service class for the bucketAccessControls resource."""
 
-    _NAME = u'bucketAccessControls'
+    _NAME = 'bucketAccessControls'
 
     def __init__(self, client):
       super(StorageV1.BucketAccessControlsService, self).__init__(client)
@@ -68,15 +71,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.bucketAccessControls.delete',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='DELETE',
+        method_id='storage.bucketAccessControls.delete',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl/{entity}',
+        relative_path='b/{bucket}/acl/{entity}',
         request_field='',
-        request_type_name=u'StorageBucketAccessControlsDeleteRequest',
-        response_type_name=u'StorageBucketAccessControlsDeleteResponse',
+        request_type_name='StorageBucketAccessControlsDeleteRequest',
+        response_type_name='StorageBucketAccessControlsDeleteResponse',
         supports_download=False,
     )
 
@@ -94,15 +97,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.bucketAccessControls.get',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='GET',
+        method_id='storage.bucketAccessControls.get',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl/{entity}',
+        relative_path='b/{bucket}/acl/{entity}',
         request_field='',
-        request_type_name=u'StorageBucketAccessControlsGetRequest',
-        response_type_name=u'BucketAccessControl',
+        request_type_name='StorageBucketAccessControlsGetRequest',
+        response_type_name='BucketAccessControl',
         supports_download=False,
     )
 
@@ -120,15 +123,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.bucketAccessControls.insert',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
+        http_method='POST',
+        method_id='storage.bucketAccessControls.insert',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl',
+        relative_path='b/{bucket}/acl',
         request_field='<request>',
-        request_type_name=u'BucketAccessControl',
-        response_type_name=u'BucketAccessControl',
+        request_type_name='BucketAccessControl',
+        response_type_name='BucketAccessControl',
         supports_download=False,
     )
 
@@ -146,15 +149,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.bucketAccessControls.list',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
+        http_method='GET',
+        method_id='storage.bucketAccessControls.list',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl',
+        relative_path='b/{bucket}/acl',
         request_field='',
-        request_type_name=u'StorageBucketAccessControlsListRequest',
-        response_type_name=u'BucketAccessControls',
+        request_type_name='StorageBucketAccessControlsListRequest',
+        response_type_name='BucketAccessControls',
         supports_download=False,
     )
 
@@ -172,15 +175,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'storage.bucketAccessControls.patch',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='PATCH',
+        method_id='storage.bucketAccessControls.patch',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl/{entity}',
+        relative_path='b/{bucket}/acl/{entity}',
         request_field='<request>',
-        request_type_name=u'BucketAccessControl',
-        response_type_name=u'BucketAccessControl',
+        request_type_name='BucketAccessControl',
+        response_type_name='BucketAccessControl',
         supports_download=False,
     )
 
@@ -198,22 +201,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.bucketAccessControls.update',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='PUT',
+        method_id='storage.bucketAccessControls.update',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/acl/{entity}',
+        relative_path='b/{bucket}/acl/{entity}',
         request_field='<request>',
-        request_type_name=u'BucketAccessControl',
-        response_type_name=u'BucketAccessControl',
+        request_type_name='BucketAccessControl',
+        response_type_name='BucketAccessControl',
         supports_download=False,
     )
 
   class BucketsService(base_api.BaseApiService):
     """Service class for the buckets resource."""
 
-    _NAME = u'buckets'
+    _NAME = 'buckets'
 
     def __init__(self, client):
       super(StorageV1.BucketsService, self).__init__(client)
@@ -234,15 +237,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.buckets.delete',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'ifMetagenerationMatch', u'ifMetagenerationNotMatch'],
-        relative_path=u'b/{bucket}',
+        http_method='DELETE',
+        method_id='storage.buckets.delete',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['ifMetagenerationMatch', 'ifMetagenerationNotMatch'],
+        relative_path='b/{bucket}',
         request_field='',
-        request_type_name=u'StorageBucketsDeleteRequest',
-        response_type_name=u'StorageBucketsDeleteResponse',
+        request_type_name='StorageBucketsDeleteRequest',
+        response_type_name='StorageBucketsDeleteResponse',
         supports_download=False,
     )
 
@@ -260,15 +263,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.buckets.get',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'projection'],
-        relative_path=u'b/{bucket}',
+        http_method='GET',
+        method_id='storage.buckets.get',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'projection'],
+        relative_path='b/{bucket}',
         request_field='',
-        request_type_name=u'StorageBucketsGetRequest',
-        response_type_name=u'Bucket',
+        request_type_name='StorageBucketsGetRequest',
+        response_type_name='Bucket',
         supports_download=False,
     )
 
@@ -286,15 +289,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     GetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.buckets.getIamPolicy',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
+        http_method='GET',
+        method_id='storage.buckets.getIamPolicy',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
         query_params=[],
-        relative_path=u'b/{bucket}/iam',
+        relative_path='b/{bucket}/iam',
         request_field='',
-        request_type_name=u'StorageBucketsGetIamPolicyRequest',
-        response_type_name=u'Policy',
+        request_type_name='StorageBucketsGetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -312,15 +315,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.buckets.insert',
-        ordered_params=[u'project'],
+        http_method='POST',
+        method_id='storage.buckets.insert',
+        ordered_params=['project'],
         path_params=[],
-        query_params=[u'predefinedAcl', u'predefinedDefaultObjectAcl', u'project', u'projection'],
-        relative_path=u'b',
-        request_field=u'bucket',
-        request_type_name=u'StorageBucketsInsertRequest',
-        response_type_name=u'Bucket',
+        query_params=['predefinedAcl', 'predefinedDefaultObjectAcl', 'project', 'projection'],
+        relative_path='b',
+        request_field='bucket',
+        request_type_name='StorageBucketsInsertRequest',
+        response_type_name='Bucket',
         supports_download=False,
     )
 
@@ -338,15 +341,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.buckets.list',
-        ordered_params=[u'project'],
+        http_method='GET',
+        method_id='storage.buckets.list',
+        ordered_params=['project'],
         path_params=[],
-        query_params=[u'maxResults', u'pageToken', u'prefix', u'project', u'projection'],
-        relative_path=u'b',
+        query_params=['maxResults', 'pageToken', 'prefix', 'project', 'projection'],
+        relative_path='b',
         request_field='',
-        request_type_name=u'StorageBucketsListRequest',
-        response_type_name=u'Buckets',
+        request_type_name='StorageBucketsListRequest',
+        response_type_name='Buckets',
         supports_download=False,
     )
 
@@ -364,15 +367,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'storage.buckets.patch',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'predefinedAcl', u'predefinedDefaultObjectAcl', u'projection'],
-        relative_path=u'b/{bucket}',
-        request_field=u'bucketResource',
-        request_type_name=u'StorageBucketsPatchRequest',
-        response_type_name=u'Bucket',
+        http_method='PATCH',
+        method_id='storage.buckets.patch',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'predefinedAcl', 'predefinedDefaultObjectAcl', 'projection'],
+        relative_path='b/{bucket}',
+        request_field='bucketResource',
+        request_type_name='StorageBucketsPatchRequest',
+        response_type_name='Bucket',
         supports_download=False,
     )
 
@@ -390,15 +393,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     SetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.buckets.setIamPolicy',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
+        http_method='PUT',
+        method_id='storage.buckets.setIamPolicy',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
         query_params=[],
-        relative_path=u'b/{bucket}/iam',
-        request_field=u'policy',
-        request_type_name=u'StorageBucketsSetIamPolicyRequest',
-        response_type_name=u'Policy',
+        relative_path='b/{bucket}/iam',
+        request_field='policy',
+        request_type_name='StorageBucketsSetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -416,15 +419,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     TestIamPermissions.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.buckets.testIamPermissions',
-        ordered_params=[u'bucket', u'permissions'],
-        path_params=[u'bucket'],
-        query_params=[u'permissions'],
-        relative_path=u'b/{bucket}/iam/testPermissions',
+        http_method='GET',
+        method_id='storage.buckets.testIamPermissions',
+        ordered_params=['bucket', 'permissions'],
+        path_params=['bucket'],
+        query_params=['permissions'],
+        relative_path='b/{bucket}/iam/testPermissions',
         request_field='',
-        request_type_name=u'StorageBucketsTestIamPermissionsRequest',
-        response_type_name=u'TestIamPermissionsResponse',
+        request_type_name='StorageBucketsTestIamPermissionsRequest',
+        response_type_name='TestIamPermissionsResponse',
         supports_download=False,
     )
 
@@ -442,22 +445,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.buckets.update',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'predefinedAcl', u'predefinedDefaultObjectAcl', u'projection'],
-        relative_path=u'b/{bucket}',
-        request_field=u'bucketResource',
-        request_type_name=u'StorageBucketsUpdateRequest',
-        response_type_name=u'Bucket',
+        http_method='PUT',
+        method_id='storage.buckets.update',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'predefinedAcl', 'predefinedDefaultObjectAcl', 'projection'],
+        relative_path='b/{bucket}',
+        request_field='bucketResource',
+        request_type_name='StorageBucketsUpdateRequest',
+        response_type_name='Bucket',
         supports_download=False,
     )
 
   class ChannelsService(base_api.BaseApiService):
     """Service class for the channels resource."""
 
-    _NAME = u'channels'
+    _NAME = 'channels'
 
     def __init__(self, client):
       super(StorageV1.ChannelsService, self).__init__(client)
@@ -478,22 +481,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Stop.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.channels.stop',
+        http_method='POST',
+        method_id='storage.channels.stop',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'channels/stop',
+        relative_path='channels/stop',
         request_field='<request>',
-        request_type_name=u'Channel',
-        response_type_name=u'StorageChannelsStopResponse',
+        request_type_name='Channel',
+        response_type_name='StorageChannelsStopResponse',
         supports_download=False,
     )
 
   class DefaultObjectAccessControlsService(base_api.BaseApiService):
     """Service class for the defaultObjectAccessControls resource."""
 
-    _NAME = u'defaultObjectAccessControls'
+    _NAME = 'defaultObjectAccessControls'
 
     def __init__(self, client):
       super(StorageV1.DefaultObjectAccessControlsService, self).__init__(client)
@@ -514,15 +517,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.defaultObjectAccessControls.delete',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='DELETE',
+        method_id='storage.defaultObjectAccessControls.delete',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/defaultObjectAcl/{entity}',
+        relative_path='b/{bucket}/defaultObjectAcl/{entity}',
         request_field='',
-        request_type_name=u'StorageDefaultObjectAccessControlsDeleteRequest',
-        response_type_name=u'StorageDefaultObjectAccessControlsDeleteResponse',
+        request_type_name='StorageDefaultObjectAccessControlsDeleteRequest',
+        response_type_name='StorageDefaultObjectAccessControlsDeleteResponse',
         supports_download=False,
     )
 
@@ -540,15 +543,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.defaultObjectAccessControls.get',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='GET',
+        method_id='storage.defaultObjectAccessControls.get',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/defaultObjectAcl/{entity}',
+        relative_path='b/{bucket}/defaultObjectAcl/{entity}',
         request_field='',
-        request_type_name=u'StorageDefaultObjectAccessControlsGetRequest',
-        response_type_name=u'ObjectAccessControl',
+        request_type_name='StorageDefaultObjectAccessControlsGetRequest',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -566,15 +569,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.defaultObjectAccessControls.insert',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
+        http_method='POST',
+        method_id='storage.defaultObjectAccessControls.insert',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
         query_params=[],
-        relative_path=u'b/{bucket}/defaultObjectAcl',
+        relative_path='b/{bucket}/defaultObjectAcl',
         request_field='<request>',
-        request_type_name=u'ObjectAccessControl',
-        response_type_name=u'ObjectAccessControl',
+        request_type_name='ObjectAccessControl',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -592,15 +595,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.defaultObjectAccessControls.list',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'ifMetagenerationMatch', u'ifMetagenerationNotMatch'],
-        relative_path=u'b/{bucket}/defaultObjectAcl',
+        http_method='GET',
+        method_id='storage.defaultObjectAccessControls.list',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['ifMetagenerationMatch', 'ifMetagenerationNotMatch'],
+        relative_path='b/{bucket}/defaultObjectAcl',
         request_field='',
-        request_type_name=u'StorageDefaultObjectAccessControlsListRequest',
-        response_type_name=u'ObjectAccessControls',
+        request_type_name='StorageDefaultObjectAccessControlsListRequest',
+        response_type_name='ObjectAccessControls',
         supports_download=False,
     )
 
@@ -618,15 +621,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'storage.defaultObjectAccessControls.patch',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='PATCH',
+        method_id='storage.defaultObjectAccessControls.patch',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/defaultObjectAcl/{entity}',
+        relative_path='b/{bucket}/defaultObjectAcl/{entity}',
         request_field='<request>',
-        request_type_name=u'ObjectAccessControl',
-        response_type_name=u'ObjectAccessControl',
+        request_type_name='ObjectAccessControl',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -644,22 +647,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.defaultObjectAccessControls.update',
-        ordered_params=[u'bucket', u'entity'],
-        path_params=[u'bucket', u'entity'],
+        http_method='PUT',
+        method_id='storage.defaultObjectAccessControls.update',
+        ordered_params=['bucket', 'entity'],
+        path_params=['bucket', 'entity'],
         query_params=[],
-        relative_path=u'b/{bucket}/defaultObjectAcl/{entity}',
+        relative_path='b/{bucket}/defaultObjectAcl/{entity}',
         request_field='<request>',
-        request_type_name=u'ObjectAccessControl',
-        response_type_name=u'ObjectAccessControl',
+        request_type_name='ObjectAccessControl',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
   class NotificationsService(base_api.BaseApiService):
     """Service class for the notifications resource."""
 
-    _NAME = u'notifications'
+    _NAME = 'notifications'
 
     def __init__(self, client):
       super(StorageV1.NotificationsService, self).__init__(client)
@@ -680,15 +683,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.notifications.delete',
-        ordered_params=[u'notification'],
-        path_params=[u'notification'],
+        http_method='DELETE',
+        method_id='storage.notifications.delete',
+        ordered_params=['notification'],
+        path_params=['notification'],
         query_params=[],
-        relative_path=u'notifications/{notification}',
+        relative_path='notifications/{notification}',
         request_field='',
-        request_type_name=u'StorageNotificationsDeleteRequest',
-        response_type_name=u'StorageNotificationsDeleteResponse',
+        request_type_name='StorageNotificationsDeleteRequest',
+        response_type_name='StorageNotificationsDeleteResponse',
         supports_download=False,
     )
 
@@ -706,15 +709,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.notifications.get',
-        ordered_params=[u'notification'],
-        path_params=[u'notification'],
+        http_method='GET',
+        method_id='storage.notifications.get',
+        ordered_params=['notification'],
+        path_params=['notification'],
         query_params=[],
-        relative_path=u'notifications/{notification}',
+        relative_path='notifications/{notification}',
         request_field='',
-        request_type_name=u'StorageNotificationsGetRequest',
-        response_type_name=u'Notification',
+        request_type_name='StorageNotificationsGetRequest',
+        response_type_name='Notification',
         supports_download=False,
     )
 
@@ -732,15 +735,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.notifications.insert',
+        http_method='POST',
+        method_id='storage.notifications.insert',
         ordered_params=[],
         path_params=[],
         query_params=[],
-        relative_path=u'notifications',
+        relative_path='notifications',
         request_field='<request>',
-        request_type_name=u'Notification',
-        response_type_name=u'Notification',
+        request_type_name='Notification',
+        response_type_name='Notification',
         supports_download=False,
     )
 
@@ -758,22 +761,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.notifications.list',
-        ordered_params=[u'bucket'],
+        http_method='GET',
+        method_id='storage.notifications.list',
+        ordered_params=['bucket'],
         path_params=[],
-        query_params=[u'bucket'],
-        relative_path=u'notifications',
+        query_params=['bucket'],
+        relative_path='notifications',
         request_field='',
-        request_type_name=u'StorageNotificationsListRequest',
-        response_type_name=u'Notifications',
+        request_type_name='StorageNotificationsListRequest',
+        response_type_name='Notifications',
         supports_download=False,
     )
 
   class ObjectAccessControlsService(base_api.BaseApiService):
     """Service class for the objectAccessControls resource."""
 
-    _NAME = u'objectAccessControls'
+    _NAME = 'objectAccessControls'
 
     def __init__(self, client):
       super(StorageV1.ObjectAccessControlsService, self).__init__(client)
@@ -794,15 +797,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.objectAccessControls.delete',
-        ordered_params=[u'bucket', u'object', u'entity'],
-        path_params=[u'bucket', u'entity', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl/{entity}',
+        http_method='DELETE',
+        method_id='storage.objectAccessControls.delete',
+        ordered_params=['bucket', 'object', 'entity'],
+        path_params=['bucket', 'entity', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl/{entity}',
         request_field='',
-        request_type_name=u'StorageObjectAccessControlsDeleteRequest',
-        response_type_name=u'StorageObjectAccessControlsDeleteResponse',
+        request_type_name='StorageObjectAccessControlsDeleteRequest',
+        response_type_name='StorageObjectAccessControlsDeleteResponse',
         supports_download=False,
     )
 
@@ -820,15 +823,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objectAccessControls.get',
-        ordered_params=[u'bucket', u'object', u'entity'],
-        path_params=[u'bucket', u'entity', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl/{entity}',
+        http_method='GET',
+        method_id='storage.objectAccessControls.get',
+        ordered_params=['bucket', 'object', 'entity'],
+        path_params=['bucket', 'entity', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl/{entity}',
         request_field='',
-        request_type_name=u'StorageObjectAccessControlsGetRequest',
-        response_type_name=u'ObjectAccessControl',
+        request_type_name='StorageObjectAccessControlsGetRequest',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -846,15 +849,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objectAccessControls.insert',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl',
-        request_field=u'objectAccessControl',
-        request_type_name=u'StorageObjectAccessControlsInsertRequest',
-        response_type_name=u'ObjectAccessControl',
+        http_method='POST',
+        method_id='storage.objectAccessControls.insert',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl',
+        request_field='objectAccessControl',
+        request_type_name='StorageObjectAccessControlsInsertRequest',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -872,15 +875,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objectAccessControls.list',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl',
+        http_method='GET',
+        method_id='storage.objectAccessControls.list',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl',
         request_field='',
-        request_type_name=u'StorageObjectAccessControlsListRequest',
-        response_type_name=u'ObjectAccessControls',
+        request_type_name='StorageObjectAccessControlsListRequest',
+        response_type_name='ObjectAccessControls',
         supports_download=False,
     )
 
@@ -898,15 +901,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'storage.objectAccessControls.patch',
-        ordered_params=[u'bucket', u'object', u'entity'],
-        path_params=[u'bucket', u'entity', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl/{entity}',
-        request_field=u'objectAccessControl',
-        request_type_name=u'StorageObjectAccessControlsPatchRequest',
-        response_type_name=u'ObjectAccessControl',
+        http_method='PATCH',
+        method_id='storage.objectAccessControls.patch',
+        ordered_params=['bucket', 'object', 'entity'],
+        path_params=['bucket', 'entity', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl/{entity}',
+        request_field='objectAccessControl',
+        request_type_name='StorageObjectAccessControlsPatchRequest',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
@@ -924,22 +927,22 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.objectAccessControls.update',
-        ordered_params=[u'bucket', u'object', u'entity'],
-        path_params=[u'bucket', u'entity', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/acl/{entity}',
-        request_field=u'objectAccessControl',
-        request_type_name=u'StorageObjectAccessControlsUpdateRequest',
-        response_type_name=u'ObjectAccessControl',
+        http_method='PUT',
+        method_id='storage.objectAccessControls.update',
+        ordered_params=['bucket', 'object', 'entity'],
+        path_params=['bucket', 'entity', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/acl/{entity}',
+        request_field='objectAccessControl',
+        request_type_name='StorageObjectAccessControlsUpdateRequest',
+        response_type_name='ObjectAccessControl',
         supports_download=False,
     )
 
   class ObjectsService(base_api.BaseApiService):
     """Service class for the objects resource."""
 
-    _NAME = u'objects'
+    _NAME = 'objects'
 
     def __init__(self, client):
       super(StorageV1.ObjectsService, self).__init__(client)
@@ -948,9 +951,9 @@ class StorageV1(base_api.BaseApiClient):
               accept=['*/*'],
               max_size=None,
               resumable_multipart=True,
-              resumable_path=u'/resumable/upload/storage/v1/b/{bucket}/o',
+              resumable_path='/resumable/upload/storage/v1/b/{bucket}/o',
               simple_multipart=True,
-              simple_path=u'/upload/storage/v1/b/{bucket}/o',
+              simple_path='/upload/storage/v1/b/{bucket}/o',
           ),
           }
 
@@ -971,15 +974,15 @@ class StorageV1(base_api.BaseApiClient):
           download=download)
 
     Compose.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objects.compose',
-        ordered_params=[u'destinationBucket', u'destinationObject'],
-        path_params=[u'destinationBucket', u'destinationObject'],
-        query_params=[u'destinationPredefinedAcl', u'ifGenerationMatch', u'ifMetagenerationMatch'],
-        relative_path=u'b/{destinationBucket}/o/{destinationObject}/compose',
-        request_field=u'composeRequest',
-        request_type_name=u'StorageObjectsComposeRequest',
-        response_type_name=u'Object',
+        http_method='POST',
+        method_id='storage.objects.compose',
+        ordered_params=['destinationBucket', 'destinationObject'],
+        path_params=['destinationBucket', 'destinationObject'],
+        query_params=['destinationPredefinedAcl', 'ifGenerationMatch', 'ifMetagenerationMatch'],
+        relative_path='b/{destinationBucket}/o/{destinationObject}/compose',
+        request_field='composeRequest',
+        request_type_name='StorageObjectsComposeRequest',
+        response_type_name='Object',
         supports_download=True,
     )
 
@@ -1000,15 +1003,15 @@ class StorageV1(base_api.BaseApiClient):
           download=download)
 
     Copy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objects.copy',
-        ordered_params=[u'sourceBucket', u'sourceObject', u'destinationBucket', u'destinationObject'],
-        path_params=[u'destinationBucket', u'destinationObject', u'sourceBucket', u'sourceObject'],
-        query_params=[u'destinationPredefinedAcl', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'ifSourceGenerationMatch', u'ifSourceGenerationNotMatch', u'ifSourceMetagenerationMatch', u'ifSourceMetagenerationNotMatch', u'projection', u'sourceGeneration'],
-        relative_path=u'b/{sourceBucket}/o/{sourceObject}/copyTo/b/{destinationBucket}/o/{destinationObject}',
-        request_field=u'object',
-        request_type_name=u'StorageObjectsCopyRequest',
-        response_type_name=u'Object',
+        http_method='POST',
+        method_id='storage.objects.copy',
+        ordered_params=['sourceBucket', 'sourceObject', 'destinationBucket', 'destinationObject'],
+        path_params=['destinationBucket', 'destinationObject', 'sourceBucket', 'sourceObject'],
+        query_params=['destinationPredefinedAcl', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'ifSourceGenerationMatch', 'ifSourceGenerationNotMatch', 'ifSourceMetagenerationMatch', 'ifSourceMetagenerationNotMatch', 'projection', 'sourceGeneration'],
+        relative_path='b/{sourceBucket}/o/{sourceObject}/copyTo/b/{destinationBucket}/o/{destinationObject}',
+        request_field='object',
+        request_type_name='StorageObjectsCopyRequest',
+        response_type_name='Object',
         supports_download=True,
     )
 
@@ -1026,15 +1029,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Delete.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'DELETE',
-        method_id=u'storage.objects.delete',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch'],
-        relative_path=u'b/{bucket}/o/{object}',
+        http_method='DELETE',
+        method_id='storage.objects.delete',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch'],
+        relative_path='b/{bucket}/o/{object}',
         request_field='',
-        request_type_name=u'StorageObjectsDeleteRequest',
-        response_type_name=u'StorageObjectsDeleteResponse',
+        request_type_name='StorageObjectsDeleteRequest',
+        response_type_name='StorageObjectsDeleteResponse',
         supports_download=False,
     )
 
@@ -1055,15 +1058,15 @@ class StorageV1(base_api.BaseApiClient):
           download=download)
 
     Get.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objects.get',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'projection'],
-        relative_path=u'b/{bucket}/o/{object}',
+        http_method='GET',
+        method_id='storage.objects.get',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'projection'],
+        relative_path='b/{bucket}/o/{object}',
         request_field='',
-        request_type_name=u'StorageObjectsGetRequest',
-        response_type_name=u'Object',
+        request_type_name='StorageObjectsGetRequest',
+        response_type_name='Object',
         supports_download=True,
     )
 
@@ -1081,15 +1084,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     GetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objects.getIamPolicy',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/iam',
+        http_method='GET',
+        method_id='storage.objects.getIamPolicy',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/iam',
         request_field='',
-        request_type_name=u'StorageObjectsGetIamPolicyRequest',
-        response_type_name=u'Policy',
+        request_type_name='StorageObjectsGetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -1114,15 +1117,15 @@ class StorageV1(base_api.BaseApiClient):
           download=download)
 
     Insert.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objects.insert',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'contentEncoding', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'name', u'predefinedAcl', u'projection'],
-        relative_path=u'b/{bucket}/o',
-        request_field=u'object',
-        request_type_name=u'StorageObjectsInsertRequest',
-        response_type_name=u'Object',
+        http_method='POST',
+        method_id='storage.objects.insert',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['contentEncoding', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'name', 'predefinedAcl', 'projection'],
+        relative_path='b/{bucket}/o',
+        request_field='object',
+        request_type_name='StorageObjectsInsertRequest',
+        response_type_name='Object',
         supports_download=True,
     )
 
@@ -1140,15 +1143,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     List.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objects.list',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'delimiter', u'maxResults', u'pageToken', u'prefix', u'projection', u'versions'],
-        relative_path=u'b/{bucket}/o',
+        http_method='GET',
+        method_id='storage.objects.list',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['delimiter', 'maxResults', 'pageToken', 'prefix', 'projection', 'versions'],
+        relative_path='b/{bucket}/o',
         request_field='',
-        request_type_name=u'StorageObjectsListRequest',
-        response_type_name=u'Objects',
+        request_type_name='StorageObjectsListRequest',
+        response_type_name='Objects',
         supports_download=False,
     )
 
@@ -1166,15 +1169,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Patch.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PATCH',
-        method_id=u'storage.objects.patch',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'predefinedAcl', u'projection'],
-        relative_path=u'b/{bucket}/o/{object}',
-        request_field=u'objectResource',
-        request_type_name=u'StorageObjectsPatchRequest',
-        response_type_name=u'Object',
+        http_method='PATCH',
+        method_id='storage.objects.patch',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'predefinedAcl', 'projection'],
+        relative_path='b/{bucket}/o/{object}',
+        request_field='objectResource',
+        request_type_name='StorageObjectsPatchRequest',
+        response_type_name='Object',
         supports_download=False,
     )
 
@@ -1192,15 +1195,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     Rewrite.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objects.rewrite',
-        ordered_params=[u'sourceBucket', u'sourceObject', u'destinationBucket', u'destinationObject'],
-        path_params=[u'destinationBucket', u'destinationObject', u'sourceBucket', u'sourceObject'],
-        query_params=[u'destinationPredefinedAcl', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'ifSourceGenerationMatch', u'ifSourceGenerationNotMatch', u'ifSourceMetagenerationMatch', u'ifSourceMetagenerationNotMatch', u'maxBytesRewrittenPerCall', u'projection', u'rewriteToken', u'sourceGeneration'],
-        relative_path=u'b/{sourceBucket}/o/{sourceObject}/rewriteTo/b/{destinationBucket}/o/{destinationObject}',
-        request_field=u'object',
-        request_type_name=u'StorageObjectsRewriteRequest',
-        response_type_name=u'RewriteResponse',
+        http_method='POST',
+        method_id='storage.objects.rewrite',
+        ordered_params=['sourceBucket', 'sourceObject', 'destinationBucket', 'destinationObject'],
+        path_params=['destinationBucket', 'destinationObject', 'sourceBucket', 'sourceObject'],
+        query_params=['destinationPredefinedAcl', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'ifSourceGenerationMatch', 'ifSourceGenerationNotMatch', 'ifSourceMetagenerationMatch', 'ifSourceMetagenerationNotMatch', 'maxBytesRewrittenPerCall', 'projection', 'rewriteToken', 'sourceGeneration'],
+        relative_path='b/{sourceBucket}/o/{sourceObject}/rewriteTo/b/{destinationBucket}/o/{destinationObject}',
+        request_field='object',
+        request_type_name='StorageObjectsRewriteRequest',
+        response_type_name='RewriteResponse',
         supports_download=False,
     )
 
@@ -1218,15 +1221,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     SetIamPolicy.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.objects.setIamPolicy',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation'],
-        relative_path=u'b/{bucket}/o/{object}/iam',
-        request_field=u'policy',
-        request_type_name=u'StorageObjectsSetIamPolicyRequest',
-        response_type_name=u'Policy',
+        http_method='PUT',
+        method_id='storage.objects.setIamPolicy',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation'],
+        relative_path='b/{bucket}/o/{object}/iam',
+        request_field='policy',
+        request_type_name='StorageObjectsSetIamPolicyRequest',
+        response_type_name='Policy',
         supports_download=False,
     )
 
@@ -1244,15 +1247,15 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     TestIamPermissions.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'GET',
-        method_id=u'storage.objects.testIamPermissions',
-        ordered_params=[u'bucket', u'object', u'permissions'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation', u'permissions'],
-        relative_path=u'b/{bucket}/o/{object}/iam/testPermissions',
+        http_method='GET',
+        method_id='storage.objects.testIamPermissions',
+        ordered_params=['bucket', 'object', 'permissions'],
+        path_params=['bucket', 'object'],
+        query_params=['generation', 'permissions'],
+        relative_path='b/{bucket}/o/{object}/iam/testPermissions',
         request_field='',
-        request_type_name=u'StorageObjectsTestIamPermissionsRequest',
-        response_type_name=u'TestIamPermissionsResponse',
+        request_type_name='StorageObjectsTestIamPermissionsRequest',
+        response_type_name='TestIamPermissionsResponse',
         supports_download=False,
     )
 
@@ -1273,15 +1276,15 @@ class StorageV1(base_api.BaseApiClient):
           download=download)
 
     Update.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'PUT',
-        method_id=u'storage.objects.update',
-        ordered_params=[u'bucket', u'object'],
-        path_params=[u'bucket', u'object'],
-        query_params=[u'generation', u'ifGenerationMatch', u'ifGenerationNotMatch', u'ifMetagenerationMatch', u'ifMetagenerationNotMatch', u'predefinedAcl', u'projection'],
-        relative_path=u'b/{bucket}/o/{object}',
-        request_field=u'objectResource',
-        request_type_name=u'StorageObjectsUpdateRequest',
-        response_type_name=u'Object',
+        http_method='PUT',
+        method_id='storage.objects.update',
+        ordered_params=['bucket', 'object'],
+        path_params=['bucket', 'object'],
+        query_params=['generation', 'ifGenerationMatch', 'ifGenerationNotMatch', 'ifMetagenerationMatch', 'ifMetagenerationNotMatch', 'predefinedAcl', 'projection'],
+        relative_path='b/{bucket}/o/{object}',
+        request_field='objectResource',
+        request_type_name='StorageObjectsUpdateRequest',
+        response_type_name='Object',
         supports_download=True,
     )
 
@@ -1299,14 +1302,14 @@ class StorageV1(base_api.BaseApiClient):
           config, request, global_params=global_params)
 
     WatchAll.method_config = lambda: base_api.ApiMethodInfo(
-        http_method=u'POST',
-        method_id=u'storage.objects.watchAll',
-        ordered_params=[u'bucket'],
-        path_params=[u'bucket'],
-        query_params=[u'delimiter', u'maxResults', u'pageToken', u'prefix', u'projection', u'versions'],
-        relative_path=u'b/{bucket}/o/watch',
-        request_field=u'channel',
-        request_type_name=u'StorageObjectsWatchAllRequest',
-        response_type_name=u'Channel',
+        http_method='POST',
+        method_id='storage.objects.watchAll',
+        ordered_params=['bucket'],
+        path_params=['bucket'],
+        query_params=['delimiter', 'maxResults', 'pageToken', 'prefix', 'projection', 'versions'],
+        relative_path='b/{bucket}/o/watch',
+        request_field='channel',
+        request_type_name='StorageObjectsWatchAllRequest',
+        response_type_name='Channel',
         supports_download=False,
     )
diff --git a/samples/storage_sample/storage_v1/storage_v1_messages.py b/samples/storage_sample/storage_v1/storage_v1_messages.py
index 703d79b..0f70eea 100644
--- a/samples/storage_sample/storage_v1/storage_v1_messages.py
+++ b/samples/storage_sample/storage_v1/storage_v1_messages.py
@@ -4,6 +4,8 @@ Stores and retrieves potentially large, immutable data objects.
 """
 # NOTE: This file is autogenerated and should not be edited by hand.
 
+from __future__ import absolute_import
+
 from apitools.base.protorpclite import message_types as _message_types
 from apitools.base.protorpclite import messages as _messages
 from apitools.base.py import encoding
@@ -203,7 +205,7 @@ class Bucket(_messages.Message):
   defaultObjectAcl = _messages.MessageField('ObjectAccessControl', 3, repeated=True)
   etag = _messages.StringField(4)
   id = _messages.StringField(5)
-  kind = _messages.StringField(6, default=u'storage#bucket')
+  kind = _messages.StringField(6, default='storage#bucket')
   lifecycle = _messages.MessageField('LifecycleValue', 7)
   location = _messages.StringField(8)
   logging = _messages.MessageField('LoggingValue', 9)
@@ -265,7 +267,7 @@ class BucketAccessControl(_messages.Message):
   entityId = _messages.StringField(5)
   etag = _messages.StringField(6)
   id = _messages.StringField(7)
-  kind = _messages.StringField(8, default=u'storage#bucketAccessControl')
+  kind = _messages.StringField(8, default='storage#bucketAccessControl')
   projectTeam = _messages.MessageField('ProjectTeamValue', 9)
   role = _messages.StringField(10)
   selfLink = _messages.StringField(11)
@@ -281,7 +283,7 @@ class BucketAccessControls(_messages.Message):
   """
 
   items = _messages.MessageField('BucketAccessControl', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'storage#bucketAccessControls')
+  kind = _messages.StringField(2, default='storage#bucketAccessControls')
 
 
 class Buckets(_messages.Message):
@@ -297,7 +299,7 @@ class Buckets(_messages.Message):
   """
 
   items = _messages.MessageField('Bucket', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'storage#buckets')
+  kind = _messages.StringField(2, default='storage#buckets')
   nextPageToken = _messages.StringField(3)
 
 
@@ -353,7 +355,7 @@ class Channel(_messages.Message):
   address = _messages.StringField(1)
   expiration = _messages.IntegerField(2)
   id = _messages.StringField(3)
-  kind = _messages.StringField(4, default=u'api#channel')
+  kind = _messages.StringField(4, default='api#channel')
   params = _messages.MessageField('ParamsValue', 5)
   payload = _messages.BooleanField(6)
   resourceId = _messages.StringField(7)
@@ -407,7 +409,7 @@ class ComposeRequest(_messages.Message):
     objectPreconditions = _messages.MessageField('ObjectPreconditionsValue', 3)
 
   destination = _messages.MessageField('Object', 1)
-  kind = _messages.StringField(2, default=u'storage#composeRequest')
+  kind = _messages.StringField(2, default='storage#composeRequest')
   sourceObjects = _messages.MessageField('SourceObjectsValueListEntry', 3, repeated=True)
 
 
@@ -473,10 +475,10 @@ class Notification(_messages.Message):
   etag = _messages.StringField(3)
   event_types = _messages.StringField(4, repeated=True)
   id = _messages.StringField(5)
-  kind = _messages.StringField(6, default=u'storage#notification')
-  object_metadata_format = _messages.StringField(7, default=u'JSON_API_V1')
+  kind = _messages.StringField(6, default='storage#notification')
+  object_metadata_format = _messages.StringField(7, default='JSON_API_V1')
   object_name_prefix = _messages.StringField(8)
-  payload_content = _messages.StringField(9, default=u'OBJECT_METADATA')
+  payload_content = _messages.StringField(9, default='OBJECT_METADATA')
   selfLink = _messages.StringField(10)
   topic = _messages.StringField(11)
 
@@ -491,7 +493,7 @@ class Notifications(_messages.Message):
   """
 
   items = _messages.MessageField('Notification', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'storage#notifications')
+  kind = _messages.StringField(2, default='storage#notifications')
 
 
 class Object(_messages.Message):
@@ -607,7 +609,7 @@ class Object(_messages.Message):
   etag = _messages.StringField(11)
   generation = _messages.IntegerField(12)
   id = _messages.StringField(13)
-  kind = _messages.StringField(14, default=u'storage#object')
+  kind = _messages.StringField(14, default='storage#object')
   md5Hash = _messages.StringField(15)
   mediaLink = _messages.StringField(16)
   metadata = _messages.MessageField('MetadataValue', 17)
@@ -670,7 +672,7 @@ class ObjectAccessControl(_messages.Message):
   etag = _messages.StringField(6)
   generation = _messages.IntegerField(7)
   id = _messages.StringField(8)
-  kind = _messages.StringField(9, default=u'storage#objectAccessControl')
+  kind = _messages.StringField(9, default='storage#objectAccessControl')
   object = _messages.StringField(10)
   projectTeam = _messages.MessageField('ProjectTeamValue', 11)
   role = _messages.StringField(12)
@@ -687,7 +689,7 @@ class ObjectAccessControls(_messages.Message):
   """
 
   items = _messages.MessageField('extra_types.JsonValue', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'storage#objectAccessControls')
+  kind = _messages.StringField(2, default='storage#objectAccessControls')
 
 
 class Objects(_messages.Message):
@@ -705,7 +707,7 @@ class Objects(_messages.Message):
   """
 
   items = _messages.MessageField('Object', 1, repeated=True)
-  kind = _messages.StringField(2, default=u'storage#objects')
+  kind = _messages.StringField(2, default='storage#objects')
   nextPageToken = _messages.StringField(3)
   prefixes = _messages.StringField(4, repeated=True)
 
@@ -782,7 +784,7 @@ class Policy(_messages.Message):
 
   bindings = _messages.MessageField('BindingsValueListEntry', 1, repeated=True)
   etag = _messages.BytesField(2)
-  kind = _messages.StringField(3, default=u'storage#policy')
+  kind = _messages.StringField(3, default='storage#policy')
   resourceId = _messages.StringField(4)
 
 
@@ -806,7 +808,7 @@ class RewriteResponse(_messages.Message):
   """
 
   done = _messages.BooleanField(1)
-  kind = _messages.StringField(2, default=u'storage#rewriteResponse')
+  kind = _messages.StringField(2, default='storage#rewriteResponse')
   objectSize = _messages.IntegerField(3, variant=_messages.Variant.UINT64)
   resource = _messages.MessageField('Object', 4)
   rewriteToken = _messages.StringField(5)
@@ -844,7 +846,7 @@ class StandardQueryParameters(_messages.Message):
     """
     json = 0
 
-  alt = _messages.EnumField('AltValueValuesEnum', 1, default=u'json')
+  alt = _messages.EnumField('AltValueValuesEnum', 1, default='json')
   fields = _messages.StringField(2)
   key = _messages.StringField(3)
   oauth_token = _messages.StringField(4)
@@ -2213,7 +2215,7 @@ class TestIamPermissionsResponse(_messages.Message):
       - storage.objects.update - Update object metadata.
   """
 
-  kind = _messages.StringField(1, default=u'storage#testIamPermissionsResponse')
+  kind = _messages.StringField(1, default='storage#testIamPermissionsResponse')
   permissions = _messages.StringField(2, repeated=True)
 
 
diff --git a/samples/uptodate_check_test.py b/samples/uptodate_check_test.py
index 8ca258e..6e8c9fb 100644
--- a/samples/uptodate_check_test.py
+++ b/samples/uptodate_check_test.py
@@ -59,10 +59,6 @@ class ClientGenCliTest(unittest.TestCase):
                      prefix + '_messages.py',
                      '__init__.py']))
             self.assertEquals(expected_files, set(os.listdir(tmp_dir_path)))
-            if six.PY3:
-                # The source files won't be identical under python3,
-                # so we exit early.
-                return
             for expected_file in expected_files:
                 self.AssertDiffEqual(
                     _GetContent(GetSampleClientPath(
diff --git a/setup.cfg b/setup.cfg
index a5ba8ba..c0fd3aa 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -1,3 +1,6 @@
+[metadata]
+license_files = LICENSE
+
 [pycodestyle]
 count = False
 ignore = E722,E741,W504
diff --git a/setup.py b/setup.py
index f6e26a2..889a075 100644
--- a/setup.py
+++ b/setup.py
@@ -48,7 +48,7 @@ CONSOLE_SCRIPTS = [
 
 py_version = platform.python_version()
 
-_APITOOLS_VERSION = '0.5.31'
+_APITOOLS_VERSION = '0.5.34'
 
 with open('README.rst') as fileobj:
     README = fileobj.read()
diff --git a/tox.ini b/tox.ini
index 09d2afc..29a9251 100644
--- a/tox.ini
+++ b/tox.ini
@@ -1,11 +1,10 @@
 [tox]
 envlist =
-    py27-oauth2client{1,2,3,4}
-    py35-oauth2client{1,2,3,4}
+    py311-oauth2client{1,2,3,4}
 
 [testenv]
 deps =
-    nose
+    nose-py3
     python-gflags
     oauth2client1: oauth2client<1.5dev
     oauth2client2: oauth2client>=2,<=3dev
@@ -18,7 +17,7 @@ passenv = TRAVIS*
 
 [testenv:lint]
 basepython =
-    python2.7
+    python3.11
 commands =
     pip install six google-apitools
     pycodestyle apitools
@@ -28,7 +27,7 @@ deps =
 
 [testenv:cover]
 basepython =
-    python2.7
+    python3.11
 commands =
     nosetests --with-xunit --with-xcoverage --cover-package=apitools --nocapture --cover-erase --cover-tests --cover-branches []
 deps =
@@ -49,7 +48,7 @@ deps =
 
 [testenv:transfer_coverage]
 basepython =
-    python2.7
+    python3.11
 deps =
     mock
     nose
```

