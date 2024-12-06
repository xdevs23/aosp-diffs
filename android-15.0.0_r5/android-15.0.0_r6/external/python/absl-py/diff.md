```diff
diff --git a/.github/workflows/test.yml b/.github/workflows/test.yml
new file mode 100644
index 0000000..ab041a3
--- /dev/null
+++ b/.github/workflows/test.yml
@@ -0,0 +1,50 @@
+name: Test
+
+on: [push, pull_request]
+
+permissions:
+  contents: read
+
+concurrency:
+  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
+  cancel-in-progress: true
+
+jobs:
+  test:
+    if:
+      github.event_name == 'push' || github.event.pull_request.head.repo.full_name !=
+      github.repository
+
+    runs-on: ${{ matrix.os }}
+    strategy:
+      fail-fast: false
+      matrix:
+        python-version: ["3.7", "3.8", "3.9", "3.10", "3.11", "3.12"]
+        os: [ubuntu-latest, macOS-latest, windows-latest]
+
+    steps:
+      - uses: actions/checkout@v3
+
+      - name: Set up Python ${{ matrix.python-version }}
+        uses: actions/setup-python@v4
+        id: setup_python
+        with:
+          python-version: ${{ matrix.python-version }}
+          allow-prereleases: true
+
+      - name: Install virtualenv
+        run: |
+          python -m pip install --upgrade pip
+          python -m pip install --upgrade virtualenv
+      - name: Run tests
+        env:
+          ABSL_EXPECTED_PYTHON_VERSION: ${{ matrix.python-version }}
+          ABSL_COPY_TESTLOGS_TO: ci-artifacts
+        shell: bash
+        run: ci/run_tests.sh
+
+      - name: Upload bazel test logs
+        uses: actions/upload-artifact@v3
+        with:
+          name: bazel-testlogs-${{ matrix.os }}-${{ matrix.python-version }}
+          path: ci-artifacts
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..8d29937
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,39 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["external_python_absl-py_license"],
+}
+
+license {
+    name: "external_python_absl-py_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-MIT",
+    ],
+    license_text: [
+        "LICENSE",
+    ],
+}
+
+python_library_host {
+    name: "absl-py",
+    srcs: [
+        "absl/**/*.py",
+    ],
+    libs: [
+        "typing_extensions",
+    ],
+}
diff --git a/CHANGELOG.md b/CHANGELOG.md
index c8006e9..56f0ce4 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -8,6 +8,68 @@ The format is based on [Keep a Changelog](https://keepachangelog.com).
 
 Nothing notable unreleased.
 
+## 2.1.0 (2024-01-16)
+
+### Added
+
+*   (flags) Added `absl.flags.override_value` function to provide `FlagHolder`
+    with a construct to modify values. The new interface parallels
+    `absl.flags.FlagValues.__setattr__` but checks that the provided value
+    conforms to the flag's expected type.
+*   (testing) Added a new method `absltest.TestCase.assertDataclassEqual` that
+    tests equality of `dataclass.dataclass` objects with better error messages
+    when the assert fails.
+
+### Changed
+
+*   (flags) `absl.flags.argparse_flags.ArgumentParser` now correctly inherits
+    an empty instance of `FlagValues` to ensure that absl flags, such as
+    `--flagfile`, `--undefok` are supported.
+*   (testing) Do not exit 5 if tests were skipped on Python 3.12. This follows
+    the CPython change in https://github.com/python/cpython/pull/113856.
+
+### Fixed
+
+*   (flags) The flag `foo` no longer retains the value `bar` after
+    `FLAGS.foo = bar` fails due to a validation error.
+*   (testing) Fixed an issue caused by
+    [this Python 3.12.1 change](https://github.com/python/cpython/pull/109725)
+    where the test reporter crashes when all tests are skipped.
+
+## 2.0.0 (2023-09-19)
+
+### Changed
+
+*   `absl-py` no longer supports Python 3.6. It has reached end-of-life for more
+    than a year now.
+*   Support Python 3.12.
+*   (logging) `logging.exception` can now take `exc_info` as argument, with
+    default value `True`. Prior to this change setting `exc_info` would raise
+    `KeyError`, this change fixes this behaviour.
+*   (testing) For Python 3.11+, the calls to `absltest.TestCase.enter_context`
+    are forwarded to `unittest.TestCase.enterContext` (when called via instance)
+    or `unittest.TestCase.enterClassContext` (when called via class) now. As a
+    result, on Python 3.11+, the private `_cls_exit_stack` attribute is not
+    defined on `absltest.TestCase` and `_exit_stack` attribute is not defined on
+    its instances.
+*   (testing) `absltest.TestCase.assertSameStructure()` now uses the test case's
+    equality functions (registered with `TestCase.addTypeEqualityFunc()`) for
+    comparing leaves of the structure.
+*   (testing) `abslTest.TestCase.fail()` now names its arguments `(self,
+    msg=None, user_msg=None)`, and not `(self, msg=None, prefix=None)`, better
+    reflecting the behavior and usage of the two message arguments.
+*   `DEFINE_enum`, `DEFINE_multi_enum`, and `EnumParser` now raise errors when
+    `enum_values` is provided as a single string value. Additionally,
+    `EnumParser.enum_values` is now stored as a list copy of the provided
+    `enum_values` parameter.
+*   (testing) Updated `paramaterized.CoopTestCase()` to use Python 3 metaclass
+    idioms. Most uses of this function continued working during the Python 3
+    migration still worked because a Python 2 compatibility `__metaclass__`
+    variables also existed. Now pure Python 3 base classes without backwards
+    compatibility will work as intended.
+*   (testing) `absltest.TestCase.assertSequenceStartsWith` now explicitly fail
+    when passed a `Mapping` or `Set` object as the `whole` argument.
+
 ## 1.4.0 (2023-01-11)
 
 ### New
diff --git a/METADATA b/METADATA
index 2862099..bd42ee1 100644
--- a/METADATA
+++ b/METADATA
@@ -1,23 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update python/absl-py
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/python/absl-py
+# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
 
 name: "abseil-py"
 description: ""
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/abseil/abseil-py"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/abseil/abseil-py.git"
-  }
-  version: "v1.4.0"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 12
-    day: 7
+    year: 2024
+    month: 3
+    day: 27
+  }
+  homepage: "https://github.com/abseil/abseil-py"
+  identifier {
+    type: "Git"
+    value: "https://github.com/abseil/abseil-py.git"
+    version: "v2.1.0"
   }
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index 244b6f0..16fee29 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,5 +1,7 @@
 module(
     name = "abseil-py",
-    version = "1.4.0",
+    version = "2.1.0",
     compatibility_level = 1,
 )
+
+bazel_dep(name = "rules_python", version = "0.28.0")
diff --git a/WORKSPACE b/WORKSPACE
index a964e21..722c605 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -12,3 +12,16 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 workspace(name = "io_abseil_py")
+
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+
+http_archive(
+    name = "rules_python",
+    sha256 = "863ba0fa944319f7e3d695711427d9ad80ba92c6edd0b7c7443b84e904689539",
+    strip_prefix = "rules_python-0.22.0",
+    url = "https://github.com/bazelbuild/rules_python/releases/download/0.22.0/rules_python-0.22.0.tar.gz",
+)
+
+load("@rules_python//python:repositories.bzl", "py_repositories")
+
+py_repositories()
diff --git a/absl/BUILD b/absl/BUILD
index 4e747ea..261c2aa 100644
--- a/absl/BUILD
+++ b/absl/BUILD
@@ -1,3 +1,7 @@
+load("@rules_python//python:py_library.bzl", "py_library")
+load("@rules_python//python:py_test.bzl", "py_test")
+load("@rules_python//python:py_binary.bzl", "py_binary")
+
 licenses(["notice"])
 
 py_library(
diff --git a/absl/app.py b/absl/app.py
index 43d8ca3..d12397b 100644
--- a/absl/app.py
+++ b/absl/app.py
@@ -238,6 +238,7 @@ def _run_main(main, argv):
   elif FLAGS.run_with_profiling or FLAGS.profile_file:
     # Avoid import overhead since most apps (including performance-sensitive
     # ones) won't be run with profiling.
+    # pylint: disable=g-import-not-at-top
     import atexit
     if FLAGS.use_cprofile_for_profiling:
       import cProfile as profile
@@ -248,8 +249,7 @@ def _run_main(main, argv):
       atexit.register(profiler.dump_stats, FLAGS.profile_file)
     else:
       atexit.register(profiler.print_stats)
-    retval = profiler.runcall(main, argv)
-    sys.exit(retval)
+    sys.exit(profiler.runcall(main, argv))
   else:
     sys.exit(main(argv))
 
diff --git a/absl/command_name.py b/absl/command_name.py
index 1996493..9260fee 100644
--- a/absl/command_name.py
+++ b/absl/command_name.py
@@ -47,7 +47,7 @@ def set_kernel_process_name(name):
       proc_comm.write(name[:15])
   except EnvironmentError:
     try:
-      import ctypes
+      import ctypes  # pylint: disable=g-import-not-at-top
     except ImportError:
       return  # No ctypes.
     try:
diff --git a/absl/flags/BUILD b/absl/flags/BUILD
index 33a7b07..f6d24bd 100644
--- a/absl/flags/BUILD
+++ b/absl/flags/BUILD
@@ -1,3 +1,9 @@
+load("@rules_python//python:py_library.bzl", "py_library")
+load("@rules_python//python:py_test.bzl", "py_test")
+load("@rules_python//python:py_binary.bzl", "py_binary")
+
+package(default_visibility = ["//visibility:private"])
+
 licenses(["notice"])
 
 py_library(
diff --git a/absl/flags/__init__.py b/absl/flags/__init__.py
index 6d8ba03..21e05c4 100644
--- a/absl/flags/__init__.py
+++ b/absl/flags/__init__.py
@@ -70,6 +70,7 @@ __all__ = (
     'mark_bool_flags_as_mutual_exclusive',
     # Flag modifiers.
     'set_default',
+    'override_value',
     # Key flag related functions.
     'declare_key_flag',
     'adopt_module_key_flags',
@@ -156,6 +157,7 @@ mark_bool_flags_as_mutual_exclusive = _validators.mark_bool_flags_as_mutual_excl
 
 # Flag modifiers.
 set_default = _defines.set_default
+override_value = _defines.override_value
 
 # Key flag related functions.
 declare_key_flag = _defines.declare_key_flag
diff --git a/absl/flags/__init__.pyi b/absl/flags/__init__.pyi
deleted file mode 100644
index 7bf6842..0000000
--- a/absl/flags/__init__.pyi
+++ /dev/null
@@ -1,106 +0,0 @@
-# Copyright 2017 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-from absl.flags import _argument_parser
-from absl.flags import _defines
-from absl.flags import _exceptions
-from absl.flags import _flag
-from absl.flags import _flagvalues
-from absl.flags import _helpers
-from absl.flags import _validators
-
-# DEFINE functions. They are explained in more details in the module doc string.
-# pylint: disable=invalid-name
-DEFINE = _defines.DEFINE
-DEFINE_flag = _defines.DEFINE_flag
-DEFINE_string = _defines.DEFINE_string
-DEFINE_boolean = _defines.DEFINE_boolean
-DEFINE_bool = DEFINE_boolean  # Match C++ API.
-DEFINE_float = _defines.DEFINE_float
-DEFINE_integer = _defines.DEFINE_integer
-DEFINE_enum = _defines.DEFINE_enum
-DEFINE_enum_class = _defines.DEFINE_enum_class
-DEFINE_list = _defines.DEFINE_list
-DEFINE_spaceseplist = _defines.DEFINE_spaceseplist
-DEFINE_multi = _defines.DEFINE_multi
-DEFINE_multi_string = _defines.DEFINE_multi_string
-DEFINE_multi_integer = _defines.DEFINE_multi_integer
-DEFINE_multi_float = _defines.DEFINE_multi_float
-DEFINE_multi_enum = _defines.DEFINE_multi_enum
-DEFINE_multi_enum_class = _defines.DEFINE_multi_enum_class
-DEFINE_alias = _defines.DEFINE_alias
-# pylint: enable=invalid-name
-
-# Flag validators.
-register_validator = _validators.register_validator
-validator = _validators.validator
-register_multi_flags_validator = _validators.register_multi_flags_validator
-multi_flags_validator = _validators.multi_flags_validator
-mark_flag_as_required = _validators.mark_flag_as_required
-mark_flags_as_required = _validators.mark_flags_as_required
-mark_flags_as_mutual_exclusive = _validators.mark_flags_as_mutual_exclusive
-mark_bool_flags_as_mutual_exclusive = _validators.mark_bool_flags_as_mutual_exclusive
-
-# Flag modifiers.
-set_default = _defines.set_default
-
-# Key flag related functions.
-declare_key_flag = _defines.declare_key_flag
-adopt_module_key_flags = _defines.adopt_module_key_flags
-disclaim_key_flags = _defines.disclaim_key_flags
-
-# Module exceptions.
-# pylint: disable=invalid-name
-Error = _exceptions.Error
-CantOpenFlagFileError = _exceptions.CantOpenFlagFileError
-DuplicateFlagError = _exceptions.DuplicateFlagError
-IllegalFlagValueError = _exceptions.IllegalFlagValueError
-UnrecognizedFlagError = _exceptions.UnrecognizedFlagError
-UnparsedFlagAccessError = _exceptions.UnparsedFlagAccessError
-ValidationError = _exceptions.ValidationError
-FlagNameConflictsWithMethodError = _exceptions.FlagNameConflictsWithMethodError
-
-# Public classes.
-Flag = _flag.Flag
-BooleanFlag = _flag.BooleanFlag
-EnumFlag = _flag.EnumFlag
-EnumClassFlag = _flag.EnumClassFlag
-MultiFlag = _flag.MultiFlag
-MultiEnumClassFlag = _flag.MultiEnumClassFlag
-FlagHolder = _flagvalues.FlagHolder
-FlagValues = _flagvalues.FlagValues
-ArgumentParser = _argument_parser.ArgumentParser
-BooleanParser = _argument_parser.BooleanParser
-EnumParser = _argument_parser.EnumParser
-EnumClassParser = _argument_parser.EnumClassParser
-ArgumentSerializer = _argument_parser.ArgumentSerializer
-FloatParser = _argument_parser.FloatParser
-IntegerParser = _argument_parser.IntegerParser
-BaseListParser = _argument_parser.BaseListParser
-ListParser = _argument_parser.ListParser
-ListSerializer = _argument_parser.ListSerializer
-CsvListSerializer = _argument_parser.CsvListSerializer
-WhitespaceSeparatedListParser = _argument_parser.WhitespaceSeparatedListParser
-EnumClassSerializer = _argument_parser.EnumClassSerializer
-# pylint: enable=invalid-name
-
-# Helper functions.
-get_help_width = _helpers.get_help_width
-text_wrap = _helpers.text_wrap
-flag_dict_to_args = _helpers.flag_dict_to_args
-doc_to_help = _helpers.doc_to_help
-
-# The global FlagValues instance.
-FLAGS = _flagvalues.FLAGS
-
diff --git a/absl/flags/_argument_parser.py b/absl/flags/_argument_parser.py
index 2c4de9b..13dc640 100644
--- a/absl/flags/_argument_parser.py
+++ b/absl/flags/_argument_parser.py
@@ -20,11 +20,18 @@ aliases defined at the package level instead.
 
 import collections
 import csv
+import enum
 import io
 import string
+from typing import Generic, List, Iterable, Optional, Sequence, Text, Type, TypeVar, Union
+from xml.dom import minidom
 
 from absl.flags import _helpers
 
+_T = TypeVar('_T')
+_ET = TypeVar('_ET', bound=enum.Enum)
+_N = TypeVar('_N', int, float)
+
 
 def _is_integer_type(instance):
   """Returns True if instance is an integer, and not a bool."""
@@ -72,25 +79,7 @@ class _ArgumentParserCache(type):
         return type.__call__(cls, *args)
 
 
-# NOTE about Genericity and Metaclass of ArgumentParser.
-# (1) In the .py source (this file)
-#     - is not declared as Generic
-#     - has _ArgumentParserCache as a metaclass
-# (2) In the .pyi source (type stub)
-#     - is declared as Generic
-#     - doesn't have a metaclass
-# The reason we need this is due to Generic having a different metaclass
-# (for python versions <= 3.7) and a class can have only one metaclass.
-#
-# * Lack of metaclass in .pyi is not a deal breaker, since the metaclass
-#   doesn't affect any type information. Also type checkers can check the type
-#   parameters.
-# * However, not declaring ArgumentParser as Generic in the source affects
-#   runtime annotation processing. In particular this means, subclasses should
-#   inherit from `ArgumentParser` and not `ArgumentParser[SomeType]`.
-#   The corresponding DEFINE_someType method (the public API) can be annotated
-#   to return FlagHolder[SomeType].
-class ArgumentParser(metaclass=_ArgumentParserCache):
+class ArgumentParser(Generic[_T], metaclass=_ArgumentParserCache):
   """Base class used to parse and convert arguments.
 
   The :meth:`parse` method checks to make sure that the string argument is a
@@ -106,9 +95,9 @@ class ArgumentParser(metaclass=_ArgumentParserCache):
   member variables must be derived from initializer arguments only.
   """
 
-  syntactic_help = ''
+  syntactic_help: Text = ''
 
-  def parse(self, argument):
+  def parse(self, argument: Text) -> Optional[_T]:
     """Parses the string argument and returns the native value.
 
     By default it returns its argument unmodified.
@@ -128,11 +117,13 @@ class ArgumentParser(metaclass=_ArgumentParserCache):
           type(argument)))
     return argument
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """Returns a string representing the type of the flag."""
     return 'string'
 
-  def _custom_xml_dom_elements(self, doc):
+  def _custom_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     """Returns a list of minidom.Element to add additional flag information.
 
     Args:
@@ -142,33 +133,38 @@ class ArgumentParser(metaclass=_ArgumentParserCache):
     return []
 
 
-class ArgumentSerializer(object):
+class ArgumentSerializer(Generic[_T]):
   """Base class for generating string representations of a flag value."""
 
-  def serialize(self, value):
+  def serialize(self, value: _T) -> Text:
     """Returns a serialized string of the value."""
     return str(value)
 
 
-class NumericParser(ArgumentParser):
+class NumericParser(ArgumentParser[_N]):
   """Parser of numeric values.
 
   Parsed value may be bounded to a given upper and lower bound.
   """
 
-  def is_outside_bounds(self, val):
+  lower_bound: Optional[_N]
+  upper_bound: Optional[_N]
+
+  def is_outside_bounds(self, val: _N) -> bool:
     """Returns whether the value is outside the bounds or not."""
     return ((self.lower_bound is not None and val < self.lower_bound) or
             (self.upper_bound is not None and val > self.upper_bound))
 
-  def parse(self, argument):
+  def parse(self, argument: Text) -> _N:
     """See base class."""
     val = self.convert(argument)
     if self.is_outside_bounds(val):
       raise ValueError('%s is not %s' % (val, self.syntactic_help))
     return val
 
-  def _custom_xml_dom_elements(self, doc):
+  def _custom_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = []
     if self.lower_bound is not None:
       elements.append(_helpers.create_xml_dom_element(
@@ -178,7 +174,7 @@ class NumericParser(ArgumentParser):
           doc, 'upper_bound', self.upper_bound))
     return elements
 
-  def convert(self, argument):
+  def convert(self, argument: Text) -> _N:
     """Returns the correct numeric value of argument.
 
     Subclass must implement this method, and raise TypeError if argument is not
@@ -194,7 +190,7 @@ class NumericParser(ArgumentParser):
     raise NotImplementedError
 
 
-class FloatParser(NumericParser):
+class FloatParser(NumericParser[float]):
   """Parser of floating point values.
 
   Parsed value may be bounded to a given upper and lower bound.
@@ -203,7 +199,11 @@ class FloatParser(NumericParser):
   number_name = 'number'
   syntactic_help = ' '.join((number_article, number_name))
 
-  def __init__(self, lower_bound=None, upper_bound=None):
+  def __init__(
+      self,
+      lower_bound: Optional[float] = None,
+      upper_bound: Optional[float] = None,
+  ) -> None:
     super(FloatParser, self).__init__()
     self.lower_bound = lower_bound
     self.upper_bound = upper_bound
@@ -220,7 +220,7 @@ class FloatParser(NumericParser):
       sh = '%s >= %s' % (self.number_name, lower_bound)
     self.syntactic_help = sh
 
-  def convert(self, argument):
+  def convert(self, argument: Union[int, float, str]) -> float:
     """Returns the float value of argument."""
     if (_is_integer_type(argument) or isinstance(argument, float) or
         isinstance(argument, str)):
@@ -230,12 +230,12 @@ class FloatParser(NumericParser):
           'Expect argument to be a string, int, or float, found {}'.format(
               type(argument)))
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return 'float'
 
 
-class IntegerParser(NumericParser):
+class IntegerParser(NumericParser[int]):
   """Parser of an integer value.
 
   Parsed value may be bounded to a given upper and lower bound.
@@ -244,7 +244,9 @@ class IntegerParser(NumericParser):
   number_name = 'integer'
   syntactic_help = ' '.join((number_article, number_name))
 
-  def __init__(self, lower_bound=None, upper_bound=None):
+  def __init__(
+      self, lower_bound: Optional[int] = None, upper_bound: Optional[int] = None
+  ) -> None:
     super(IntegerParser, self).__init__()
     self.lower_bound = lower_bound
     self.upper_bound = upper_bound
@@ -265,7 +267,7 @@ class IntegerParser(NumericParser):
       sh = '%s >= %s' % (self.number_name, lower_bound)
     self.syntactic_help = sh
 
-  def convert(self, argument):
+  def convert(self, argument: Union[int, Text]) -> int:
     """Returns the int value of argument."""
     if _is_integer_type(argument):
       return argument
@@ -281,15 +283,15 @@ class IntegerParser(NumericParser):
       raise TypeError('Expect argument to be a string or int, found {}'.format(
           type(argument)))
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return 'int'
 
 
-class BooleanParser(ArgumentParser):
+class BooleanParser(ArgumentParser[bool]):
   """Parser of boolean values."""
 
-  def parse(self, argument):
+  def parse(self, argument: Union[Text, int]) -> bool:
     """See base class."""
     if isinstance(argument, str):
       if argument.lower() in ('true', 't', '1'):
@@ -309,15 +311,17 @@ class BooleanParser(ArgumentParser):
 
     raise TypeError('Non-boolean argument to boolean flag', argument)
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return 'bool'
 
 
-class EnumParser(ArgumentParser):
+class EnumParser(ArgumentParser[Text]):
   """Parser of a string enum value (a string value from a given set)."""
 
-  def __init__(self, enum_values, case_sensitive=True):
+  def __init__(
+      self, enum_values: Iterable[Text], case_sensitive: bool = True
+  ) -> None:
     """Initializes EnumParser.
 
     Args:
@@ -330,11 +334,15 @@ class EnumParser(ArgumentParser):
     if not enum_values:
       raise ValueError(
           'enum_values cannot be empty, found "{}"'.format(enum_values))
+    if isinstance(enum_values, str):
+      raise ValueError(
+          'enum_values cannot be a str, found "{}"'.format(enum_values)
+      )
     super(EnumParser, self).__init__()
-    self.enum_values = enum_values
+    self.enum_values = list(enum_values)
     self.case_sensitive = case_sensitive
 
-  def parse(self, argument):
+  def parse(self, argument: Text) -> Text:
     """Determines validity of argument and returns the correct element of enum.
 
     Args:
@@ -360,15 +368,17 @@ class EnumParser(ArgumentParser):
         return [value for value in self.enum_values
                 if value.upper() == argument.upper()][0]
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return 'string enum'
 
 
-class EnumClassParser(ArgumentParser):
+class EnumClassParser(ArgumentParser[_ET]):
   """Parser of an Enum class member."""
 
-  def __init__(self, enum_class, case_sensitive=True):
+  def __init__(
+      self, enum_class: Type[_ET], case_sensitive: bool = True
+  ) -> None:
     """Initializes EnumParser.
 
     Args:
@@ -380,10 +390,6 @@ class EnumClassParser(ArgumentParser):
       TypeError: When enum_class is not a subclass of Enum.
       ValueError: When enum_class is empty.
     """
-    # Users must have an Enum class defined before using EnumClass flag.
-    # Therefore this dependency is guaranteed.
-    import enum
-
     if not issubclass(enum_class, enum.Enum):
       raise TypeError('{} is not a subclass of Enum.'.format(enum_class))
     if not enum_class.__members__:
@@ -410,11 +416,11 @@ class EnumClassParser(ArgumentParser):
           name.lower() for name in enum_class.__members__)
 
   @property
-  def member_names(self):
+  def member_names(self) -> Sequence[Text]:
     """The accepted enum names, in lowercase if not case sensitive."""
     return self._member_names
 
-  def parse(self, argument):
+  def parse(self, argument: Union[_ET, Text]) -> _ET:
     """Determines validity of argument and returns the correct element of enum.
 
     Args:
@@ -427,7 +433,7 @@ class EnumClassParser(ArgumentParser):
       ValueError: Raised when argument didn't match anything in enum.
     """
     if isinstance(argument, self.enum_class):
-      return argument
+      return argument  # pytype: disable=bad-return-type
     elif not isinstance(argument, str):
       raise ValueError(
           '{} is not an enum member or a name of a member in {}'.format(
@@ -442,29 +448,29 @@ class EnumClassParser(ArgumentParser):
       return next(value for name, value in self.enum_class.__members__.items()
                   if name.lower() == key.lower())
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return 'enum class'
 
 
-class ListSerializer(ArgumentSerializer):
+class ListSerializer(Generic[_T], ArgumentSerializer[List[_T]]):
 
-  def __init__(self, list_sep):
+  def __init__(self, list_sep: Text) -> None:
     self.list_sep = list_sep
 
-  def serialize(self, value):
+  def serialize(self, value: List[_T]) -> Text:
     """See base class."""
     return self.list_sep.join([str(x) for x in value])
 
 
-class EnumClassListSerializer(ListSerializer):
+class EnumClassListSerializer(ListSerializer[_ET]):
   """A serializer for :class:`MultiEnumClass` flags.
 
   This serializer simply joins the output of `EnumClassSerializer` using a
   provided separator.
   """
 
-  def __init__(self, list_sep, **kwargs):
+  def __init__(self, list_sep: Text, **kwargs) -> None:
     """Initializes EnumClassListSerializer.
 
     Args:
@@ -475,7 +481,7 @@ class EnumClassListSerializer(ListSerializer):
     super(EnumClassListSerializer, self).__init__(list_sep)
     self._element_serializer = EnumClassSerializer(**kwargs)
 
-  def serialize(self, value):
+  def serialize(self, value: Union[_ET, List[_ET]]) -> Text:
     """See base class."""
     if isinstance(value, list):
       return self.list_sep.join(
@@ -484,12 +490,9 @@ class EnumClassListSerializer(ListSerializer):
       return self._element_serializer.serialize(value)
 
 
-class CsvListSerializer(ArgumentSerializer):
-
-  def __init__(self, list_sep):
-    self.list_sep = list_sep
+class CsvListSerializer(ListSerializer[Text]):
 
-  def serialize(self, value):
+  def serialize(self, value: List[Text]) -> Text:
     """Serializes a list as a CSV string or unicode."""
     output = io.StringIO()
     writer = csv.writer(output, delimiter=self.list_sep)
@@ -501,10 +504,10 @@ class CsvListSerializer(ArgumentSerializer):
     return str(serialized_value)
 
 
-class EnumClassSerializer(ArgumentSerializer):
+class EnumClassSerializer(ArgumentSerializer[_ET]):
   """Class for generating string representations of an enum class flag value."""
 
-  def __init__(self, lowercase):
+  def __init__(self, lowercase: bool) -> None:
     """Initializes EnumClassSerializer.
 
     Args:
@@ -512,7 +515,7 @@ class EnumClassSerializer(ArgumentSerializer):
     """
     self._lowercase = lowercase
 
-  def serialize(self, value):
+  def serialize(self, value: _ET) -> Text:
     """Returns a serialized string of the Enum class value."""
     as_string = str(value.name)
     return as_string.lower() if self._lowercase else as_string
@@ -529,14 +532,16 @@ class BaseListParser(ArgumentParser):
   of the separator.
   """
 
-  def __init__(self, token=None, name=None):
+  def __init__(
+      self, token: Optional[Text] = None, name: Optional[Text] = None
+  ) -> None:
     assert name
     super(BaseListParser, self).__init__()
     self._token = token
     self._name = name
     self.syntactic_help = 'a %s separated list' % self._name
 
-  def parse(self, argument):
+  def parse(self, argument: Text) -> List[Text]:
     """See base class."""
     if isinstance(argument, list):
       return argument
@@ -545,7 +550,7 @@ class BaseListParser(ArgumentParser):
     else:
       return [s.strip() for s in argument.split(self._token)]
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """See base class."""
     return '%s separated list of strings' % self._name
 
@@ -553,10 +558,10 @@ class BaseListParser(ArgumentParser):
 class ListParser(BaseListParser):
   """Parser for a comma-separated list of strings."""
 
-  def __init__(self):
+  def __init__(self) -> None:
     super(ListParser, self).__init__(',', 'comma')
 
-  def parse(self, argument):
+  def parse(self, argument: Union[Text, List[Text]]) -> List[Text]:
     """Parses argument as comma-separated list of strings."""
     if isinstance(argument, list):
       return argument
@@ -574,7 +579,9 @@ class ListParser(BaseListParser):
         raise ValueError('Unable to parse the value %r as a %s: %s'
                          % (argument, self.flag_type(), e))
 
-  def _custom_xml_dom_elements(self, doc):
+  def _custom_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = super(ListParser, self)._custom_xml_dom_elements(doc)
     elements.append(_helpers.create_xml_dom_element(
         doc, 'list_separator', repr(',')))
@@ -584,7 +591,7 @@ class ListParser(BaseListParser):
 class WhitespaceSeparatedListParser(BaseListParser):
   """Parser for a whitespace-separated list of strings."""
 
-  def __init__(self, comma_compat=False):
+  def __init__(self, comma_compat: bool = False) -> None:
     """Initializer.
 
     Args:
@@ -596,7 +603,7 @@ class WhitespaceSeparatedListParser(BaseListParser):
     name = 'whitespace or comma' if self._comma_compat else 'whitespace'
     super(WhitespaceSeparatedListParser, self).__init__(None, name)
 
-  def parse(self, argument):
+  def parse(self, argument: Union[Text, List[Text]]) -> List[Text]:
     """Parses argument as whitespace-separated list of strings.
 
     It also parses argument as comma-separated list of strings if requested.
@@ -616,7 +623,9 @@ class WhitespaceSeparatedListParser(BaseListParser):
         argument = argument.replace(',', ' ')
       return argument.split()
 
-  def _custom_xml_dom_elements(self, doc):
+  def _custom_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = super(WhitespaceSeparatedListParser, self
                     )._custom_xml_dom_elements(doc)
     separators = list(string.whitespace)
diff --git a/absl/flags/_argument_parser.pyi b/absl/flags/_argument_parser.pyi
deleted file mode 100644
index 7e78d7d..0000000
--- a/absl/flags/_argument_parser.pyi
+++ /dev/null
@@ -1,127 +0,0 @@
-# Copyright 2020 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Contains type annotations for _argument_parser.py."""
-
-
-from typing import Text, TypeVar, Generic, Iterable, Type, List, Optional, Sequence, Any
-
-import enum
-
-_T = TypeVar('_T')
-_ET = TypeVar('_ET', bound=enum.Enum)
-
-
-class ArgumentSerializer(Generic[_T]):
-  def serialize(self, value: _T) -> Text: ...
-
-
-# The metaclass of ArgumentParser is not reflected here, because it does not
-# affect the provided API.
-class ArgumentParser(Generic[_T]):
-
-  syntactic_help: Text
-
-  def parse(self, argument: Text) -> Optional[_T]: ...
-
-  def flag_type(self) -> Text: ...
-
-
-# Using bound=numbers.Number results in an error: b/153268436
-_N = TypeVar('_N', int, float)
-
-
-class NumericParser(ArgumentParser[_N]):
-
-  def is_outside_bounds(self, val: _N) -> bool: ...
-
-  def parse(self, argument: Text) -> _N: ...
-
-  def convert(self, argument: Text) -> _N: ...
-
-
-class FloatParser(NumericParser[float]):
-
-  def __init__(self, lower_bound:Optional[float]=None,
-               upper_bound:Optional[float]=None) -> None:
-    ...
-
-
-class IntegerParser(NumericParser[int]):
-
-  def __init__(self, lower_bound:Optional[int]=None,
-               upper_bound:Optional[int]=None) -> None:
-    ...
-
-
-class BooleanParser(ArgumentParser[bool]):
-  ...
-
-
-class EnumParser(ArgumentParser[Text]):
-  def __init__(self, enum_values: Sequence[Text], case_sensitive: bool=...) -> None:
-    ...
-
-
-
-class EnumClassParser(ArgumentParser[_ET]):
-
-  def __init__(self, enum_class: Type[_ET], case_sensitive: bool=...) -> None:
-    ...
-
-  @property
-  def member_names(self) -> Sequence[Text]: ...
-
-
-class BaseListParser(ArgumentParser[List[Text]]):
-  def __init__(self, token: Text, name:Text) -> None: ...
-
-  # Unlike baseclass BaseListParser never returns None.
-  def parse(self, argument: Text) -> List[Text]: ...
-
-
-
-class ListParser(BaseListParser):
-  def __init__(self) -> None:
-    ...
-
-
-
-class WhitespaceSeparatedListParser(BaseListParser):
-  def __init__(self, comma_compat: bool=False) -> None:
-    ...
-
-
-
-class ListSerializer(ArgumentSerializer[List[Text]]):
-  list_sep = ... # type: Text
-
-  def __init__(self, list_sep: Text) -> None:
-    ...
-
-
-class EnumClassListSerializer(ArgumentSerializer[List[Text]]):
-  def __init__(self, list_sep: Text, **kwargs: Any) -> None:
-    ...
-
-
-class CsvListSerializer(ArgumentSerializer[List[Any]]):
-
-  def __init__(self, list_sep: Text) -> None:
-    ...
-
-
-class EnumClassSerializer(ArgumentSerializer[_ET]):
-  def __init__(self, lowercase: bool) -> None:
-    ...
diff --git a/absl/flags/_defines.py b/absl/flags/_defines.py
index 61354e9..c7b102f 100644
--- a/absl/flags/_defines.py
+++ b/absl/flags/_defines.py
@@ -17,8 +17,11 @@ Do NOT import this module directly. Import the flags package and use the
 aliases defined at the package level instead.
 """
 
+import enum
 import sys
 import types
+import typing
+from typing import Text, List, Any, TypeVar, Optional, Union, Type, Iterable, overload
 
 from absl.flags import _argument_parser
 from absl.flags import _exceptions
@@ -27,20 +30,11 @@ from absl.flags import _flagvalues
 from absl.flags import _helpers
 from absl.flags import _validators
 
-# pylint: disable=unused-import
-try:
-  from typing import Text, List, Any
-except ImportError:
-  pass
-
-try:
-  import enum
-except ImportError:
-  pass
-# pylint: enable=unused-import
-
 _helpers.disclaim_module_ids.add(id(sys.modules[__name__]))
 
+_T = TypeVar('_T')
+_ET = TypeVar('_ET', bound=enum.Enum)
+
 
 def _register_bounds_validator_if_needed(parser, name, flag_values):
   """Enforces lower and upper bounds for numeric flags.
@@ -62,6 +56,36 @@ def _register_bounds_validator_if_needed(parser, name, flag_values):
     _validators.register_validator(name, checker, flag_values=flag_values)
 
 
+@overload
+def DEFINE(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    name: Text,
+    default: Any,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    serializer: Optional[_argument_parser.ArgumentSerializer[_T]] = ...,
+    module_name: Optional[Text] = ...,
+    required: 'typing.Literal[True]' = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[_T]:
+  ...
+
+
+@overload
+def DEFINE(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    name: Text,
+    default: Optional[Any],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    serializer: Optional[_argument_parser.ArgumentSerializer[_T]] = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[_T]]:
+  ...
+
+
 def DEFINE(  # pylint: disable=invalid-name
     parser,
     name,
@@ -98,8 +122,31 @@ def DEFINE(  # pylint: disable=invalid-name
     a handle to defined flag.
   """
   return DEFINE_flag(
-      _flag.Flag(parser, serializer, name, default, help, **args), flag_values,
-      module_name, required)
+      _flag.Flag(parser, serializer, name, default, help, **args),
+      flag_values,
+      module_name,
+      required=True if required else False,
+  )
+
+
+@overload
+def DEFINE_flag(  # pylint: disable=invalid-name
+    flag: _flag.Flag[_T],
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: 'typing.Literal[True]' = ...,
+) -> _flagvalues.FlagHolder[_T]:
+  ...
+
+
+@overload
+def DEFINE_flag(  # pylint: disable=invalid-name
+    flag: _flag.Flag[_T],
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+) -> _flagvalues.FlagHolder[Optional[_T]]:
+  ...
 
 
 def DEFINE_flag(  # pylint: disable=invalid-name
@@ -148,7 +195,7 @@ def DEFINE_flag(  # pylint: disable=invalid-name
       fv, flag, ensure_non_none_value=ensure_non_none_value)
 
 
-def set_default(flag_holder, value):
+def set_default(flag_holder: _flagvalues.FlagHolder[_T], value: _T) -> None:
   """Changes the default value of the provided flag object.
 
   The flag's current value is also updated if the flag is currently using
@@ -165,9 +212,36 @@ def set_default(flag_holder, value):
   flag_holder._flagvalues.set_default(flag_holder.name, value)  # pylint: disable=protected-access
 
 
-def _internal_declare_key_flags(flag_names,
-                                flag_values=_flagvalues.FLAGS,
-                                key_flag_values=None):
+def override_value(flag_holder: _flagvalues.FlagHolder[_T], value: _T) -> None:
+  """Overrides the value of the provided flag.
+
+  This value takes precedent over the default value and, when called after flag
+  parsing, any value provided at the command line.
+
+  Args:
+    flag_holder: FlagHolder, the flag to modify.
+    value: The new value.
+
+  Raises:
+    IllegalFlagValueError: The value did not pass the flag parser or validators.
+  """
+  fv = flag_holder._flagvalues  # pylint: disable=protected-access
+  # Ensure the new value satisfies the flag's parser while avoiding side
+  # effects of calling parse().
+  parsed = fv[flag_holder.name]._parse(value)  # pylint: disable=protected-access
+  if parsed != value:
+    raise _exceptions.IllegalFlagValueError(
+        'flag %s: parsed value %r not equal to original %r'
+        % (flag_holder.name, parsed, value)
+    )
+  setattr(fv, flag_holder.name, value)
+
+
+def _internal_declare_key_flags(
+    flag_names: List[str],
+    flag_values: _flagvalues.FlagValues = _flagvalues.FLAGS,
+    key_flag_values: Optional[_flagvalues.FlagValues] = None,
+) -> None:
   """Declares a flag as key for the calling module.
 
   Internal function.  User code should call declare_key_flag or
@@ -195,7 +269,10 @@ def _internal_declare_key_flags(flag_names,
     key_flag_values.register_key_flag_for_module(module, flag_values[flag_name])
 
 
-def declare_key_flag(flag_name, flag_values=_flagvalues.FLAGS):
+def declare_key_flag(
+    flag_name: Union[Text, _flagvalues.FlagHolder],
+    flag_values: _flagvalues.FlagValues = _flagvalues.FLAGS,
+) -> None:
   """Declares one flag as key to the current module.
 
   Key flags are flags that are deemed really important for a module.
@@ -237,7 +314,9 @@ def declare_key_flag(flag_name, flag_values=_flagvalues.FLAGS):
                      'first define it in Python.' % flag_name)
 
 
-def adopt_module_key_flags(module, flag_values=_flagvalues.FLAGS):
+def adopt_module_key_flags(
+    module: Any, flag_values: _flagvalues.FlagValues = _flagvalues.FLAGS
+) -> None:
   """Declares that all flags key to a module are key to the current module.
 
   Args:
@@ -269,7 +348,7 @@ def adopt_module_key_flags(module, flag_values=_flagvalues.FLAGS):
         key_flag_values=flag_values)
 
 
-def disclaim_key_flags():
+def disclaim_key_flags() -> None:
   """Declares that the current module will not define any more key flags.
 
   Normally, the module that calls the DEFINE_xxx functions claims the
@@ -288,6 +367,43 @@ def disclaim_key_flags():
   _helpers.disclaim_module_ids.add(id(module))
 
 
+@overload
+def DEFINE_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: Optional[Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[Text]:
+  ...
+
+
+@overload
+def DEFINE_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[Text]]:
+  ...
+
+
+@overload
+def DEFINE_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: Text,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Text]:
+  ...
+
+
 def DEFINE_string(  # pylint: disable=invalid-name,redefined-builtin
     name,
     default,
@@ -296,8 +412,8 @@ def DEFINE_string(  # pylint: disable=invalid-name,redefined-builtin
     required=False,
     **args):
   """Registers a flag whose value can be any string."""
-  parser = _argument_parser.ArgumentParser()
-  serializer = _argument_parser.ArgumentSerializer()
+  parser = _argument_parser.ArgumentParser[str]()
+  serializer = _argument_parser.ArgumentSerializer[str]()
   return DEFINE(
       parser,
       name,
@@ -305,8 +421,49 @@ def DEFINE_string(  # pylint: disable=invalid-name,redefined-builtin
       help,
       flag_values,
       serializer,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_boolean(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Text, bool, int],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[bool]:
+  ...
+
+
+@overload
+def DEFINE_boolean(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[bool]]:
+  ...
+
+
+@overload
+def DEFINE_boolean(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Text, bool, int],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[bool]:
+  ...
 
 
 def DEFINE_boolean(  # pylint: disable=invalid-name,redefined-builtin
@@ -343,8 +500,54 @@ def DEFINE_boolean(  # pylint: disable=invalid-name,redefined-builtin
     a handle to defined flag.
   """
   return DEFINE_flag(
-      _flag.BooleanFlag(name, default, help, **args), flag_values, module_name,
-      required)
+      _flag.BooleanFlag(name, default, help, **args),
+      flag_values,
+      module_name,
+      required=True if required else False,
+  )
+
+
+@overload
+def DEFINE_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, float, Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[float]:
+  ...
+
+
+@overload
+def DEFINE_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[float]]:
+  ...
+
+
+@overload
+def DEFINE_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[float, Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[float]:
+  ...
 
 
 def DEFINE_float(  # pylint: disable=invalid-name,redefined-builtin
@@ -385,12 +588,56 @@ def DEFINE_float(  # pylint: disable=invalid-name,redefined-builtin
       help,
       flag_values,
       serializer,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
   _register_bounds_validator_if_needed(parser, name, flag_values=flag_values)
   return result
 
 
+@overload
+def DEFINE_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, int, Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[int]:
+  ...
+
+
+@overload
+def DEFINE_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[int]]:
+  ...
+
+
+@overload
+def DEFINE_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[int, Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[int]:
+  ...
+
+
 def DEFINE_integer(  # pylint: disable=invalid-name,redefined-builtin
     name,
     default,
@@ -429,12 +676,56 @@ def DEFINE_integer(  # pylint: disable=invalid-name,redefined-builtin
       help,
       flag_values,
       serializer,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
   _register_bounds_validator_if_needed(parser, name, flag_values=flag_values)
   return result
 
 
+@overload
+def DEFINE_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: Optional[Text],
+    enum_values: Iterable[Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[Text]:
+  ...
+
+
+@overload
+def DEFINE_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    enum_values: Iterable[Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[Text]]:
+  ...
+
+
+@overload
+def DEFINE_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: Text,
+    enum_values: Iterable[Text],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Text]:
+  ...
+
+
 def DEFINE_enum(  # pylint: disable=invalid-name,redefined-builtin
     name,
     default,
@@ -466,9 +757,59 @@ def DEFINE_enum(  # pylint: disable=invalid-name,redefined-builtin
   Returns:
     a handle to defined flag.
   """
-  return DEFINE_flag(
-      _flag.EnumFlag(name, default, help, enum_values, **args), flag_values,
-      module_name, required)
+  result = DEFINE_flag(
+      _flag.EnumFlag(name, default, help, enum_values, **args),
+      flag_values,
+      module_name,
+      required=True if required else False,
+  )
+  return result
+
+
+@overload
+def DEFINE_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, _ET, Text],
+    enum_class: Type[_ET],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    case_sensitive: bool = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[_ET]:
+  ...
+
+
+@overload
+def DEFINE_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    enum_class: Type[_ET],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    case_sensitive: bool = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[_ET]]:
+  ...
+
+
+@overload
+def DEFINE_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[_ET, Text],
+    enum_class: Type[_ET],
+    help: Optional[Text],  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    case_sensitive: bool = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[_ET]:
+  ...
 
 
 def DEFINE_enum_class(  # pylint: disable=invalid-name,redefined-builtin
@@ -501,14 +842,53 @@ def DEFINE_enum_class(  # pylint: disable=invalid-name,redefined-builtin
   Returns:
     a handle to defined flag.
   """
-  return DEFINE_flag(
+  # NOTE: pytype fails if this is a direct return.
+  result = DEFINE_flag(
       _flag.EnumClassFlag(
-          name,
-          default,
-          help,
-          enum_class,
-          case_sensitive=case_sensitive,
-          **args), flag_values, module_name, required)
+          name, default, help, enum_class, case_sensitive=case_sensitive, **args
+      ),
+      flag_values,
+      module_name,
+      required=True if required else False,
+  )
+  return result
+
+
+@overload
+def DEFINE_list(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
+
+
+@overload
+def DEFINE_list(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
+  ...
+
+
+@overload
+def DEFINE_list(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
 
 
 def DEFINE_list(  # pylint: disable=invalid-name,redefined-builtin
@@ -545,8 +925,49 @@ def DEFINE_list(  # pylint: disable=invalid-name,redefined-builtin
       help,
       flag_values,
       serializer,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_spaceseplist(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    comma_compat: bool = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
+
+
+@overload
+def DEFINE_spaceseplist(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    comma_compat: bool = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
+  ...
+
+
+@overload
+def DEFINE_spaceseplist(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    comma_compat: bool = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
 
 
 def DEFINE_spaceseplist(  # pylint: disable=invalid-name,redefined-builtin
@@ -588,8 +1009,86 @@ def DEFINE_spaceseplist(  # pylint: disable=invalid-name,redefined-builtin
       help,
       flag_values,
       serializer,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_multi(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    serializer: _argument_parser.ArgumentSerializer[_T],
+    name: Text,
+    default: Iterable[_T],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_T]]:
+  ...
+
+
+@overload
+def DEFINE_multi(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    serializer: _argument_parser.ArgumentSerializer[_T],
+    name: Text,
+    default: Union[None, _T],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_T]]:
+  ...
+
+
+@overload
+def DEFINE_multi(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    serializer: _argument_parser.ArgumentSerializer[_T],
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[_T]]]:
+  ...
+
+
+@overload
+def DEFINE_multi(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    serializer: _argument_parser.ArgumentSerializer[_T],
+    name: Text,
+    default: Iterable[_T],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_T]]:
+  ...
+
+
+@overload
+def DEFINE_multi(  # pylint: disable=invalid-name
+    parser: _argument_parser.ArgumentParser[_T],
+    serializer: _argument_parser.ArgumentSerializer[_T],
+    name: Text,
+    default: _T,
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_T]]:
+  ...
 
 
 def DEFINE_multi(  # pylint: disable=invalid-name,redefined-builtin
@@ -632,9 +1131,50 @@ def DEFINE_multi(  # pylint: disable=invalid-name,redefined-builtin
   Returns:
     a handle to defined flag.
   """
-  return DEFINE_flag(
+  result = DEFINE_flag(
       _flag.MultiFlag(parser, serializer, name, default, help, **args),
-      flag_values, module_name, required)
+      flag_values,
+      module_name,
+      required=True if required else False,
+  )
+  return result
+
+
+@overload
+def DEFINE_multi_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
+
+
+@overload
+def DEFINE_multi_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
+  ...
+
+
+@overload
+def DEFINE_multi_string(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[Text], Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
 
 
 def DEFINE_multi_string(  # pylint: disable=invalid-name,redefined-builtin
@@ -676,8 +1216,52 @@ def DEFINE_multi_string(  # pylint: disable=invalid-name,redefined-builtin
       default,
       help,
       flag_values,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_multi_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[int], int, Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[int]]:
+  ...
+
+
+@overload
+def DEFINE_multi_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[int]]]:
+  ...
+
+
+@overload
+def DEFINE_multi_integer(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[int], int, Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[int] = ...,
+    upper_bound: Optional[int] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[int]]:
+  ...
 
 
 def DEFINE_multi_integer(  # pylint: disable=invalid-name,redefined-builtin
@@ -722,8 +1306,52 @@ def DEFINE_multi_integer(  # pylint: disable=invalid-name,redefined-builtin
       default,
       help,
       flag_values,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_multi_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[float], float, Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[float]]:
+  ...
+
+
+@overload
+def DEFINE_multi_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[float]]]:
+  ...
+
+
+@overload
+def DEFINE_multi_float(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[float], float, Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    lower_bound: Optional[float] = ...,
+    upper_bound: Optional[float] = ...,
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[float]]:
+  ...
 
 
 def DEFINE_multi_float(  # pylint: disable=invalid-name,redefined-builtin
@@ -768,8 +1396,49 @@ def DEFINE_multi_float(  # pylint: disable=invalid-name,redefined-builtin
       default,
       help,
       flag_values,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_multi_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, Iterable[Text], Text],
+    enum_values: Iterable[Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    enum_values: Iterable[Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[Iterable[Text], Text],
+    enum_values: Iterable[Text],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[Text]]:
+  ...
 
 
 def DEFINE_multi_enum(  # pylint: disable=invalid-name,redefined-builtin
@@ -815,8 +1484,89 @@ def DEFINE_multi_enum(  # pylint: disable=invalid-name,redefined-builtin
       default,
       '<%s>: %s' % ('|'.join(enum_values), help),
       flag_values,
-      required=required,
-      **args)
+      required=True if required else False,
+      **args,
+  )
+
+
+@overload
+def DEFINE_multi_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    # This is separate from `Union[None, _ET, Iterable[Text], Text]` to avoid a
+    # Pytype issue inferring the return value to
+    # FlagHolder[List[Union[_ET, enum.Enum]]] when an iterable of concrete enum
+    # subclasses are used.
+    default: Iterable[_ET],
+    enum_class: Type[_ET],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_ET]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[None, _ET, Iterable[Text], Text],
+    enum_class: Type[_ET],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    *,
+    required: 'typing.Literal[True]',
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_ET]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: None,
+    enum_class: Type[_ET],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[Optional[List[_ET]]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    # This is separate from `Union[None, _ET, Iterable[Text], Text]` to avoid a
+    # Pytype issue inferring the return value to
+    # FlagHolder[List[Union[_ET, enum.Enum]]] when an iterable of concrete enum
+    # subclasses are used.
+    default: Iterable[_ET],
+    enum_class: Type[_ET],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_ET]]:
+  ...
+
+
+@overload
+def DEFINE_multi_enum_class(  # pylint: disable=invalid-name
+    name: Text,
+    default: Union[_ET, Iterable[Text], Text],
+    enum_class: Type[_ET],
+    help: Text,  # pylint: disable=redefined-builtin
+    flag_values: _flagvalues.FlagValues = ...,
+    module_name: Optional[Text] = ...,
+    required: bool = ...,
+    **args: Any
+) -> _flagvalues.FlagHolder[List[_ET]]:
+  ...
 
 
 def DEFINE_multi_enum_class(  # pylint: disable=invalid-name,redefined-builtin
@@ -857,7 +1607,8 @@ def DEFINE_multi_enum_class(  # pylint: disable=invalid-name,redefined-builtin
   Returns:
     a handle to defined flag.
   """
-  return DEFINE_flag(
+  # NOTE: pytype fails if this is a direct return.
+  result = DEFINE_flag(
       _flag.MultiEnumClassFlag(
           name,
           default,
@@ -868,15 +1619,17 @@ def DEFINE_multi_enum_class(  # pylint: disable=invalid-name,redefined-builtin
       ),
       flag_values,
       module_name,
-      required=required,
+      required=True if required else False,
   )
+  return result
 
 
 def DEFINE_alias(  # pylint: disable=invalid-name
-    name,
-    original_name,
-    flag_values=_flagvalues.FLAGS,
-    module_name=None):
+    name: Text,
+    original_name: Text,
+    flag_values: _flagvalues.FlagValues = _flagvalues.FLAGS,
+    module_name: Optional[Text] = None,
+) -> _flagvalues.FlagHolder[Any]:
   """Defines an alias flag for an existing one.
 
   Args:
diff --git a/absl/flags/_defines.pyi b/absl/flags/_defines.pyi
deleted file mode 100644
index 9bc8067..0000000
--- a/absl/flags/_defines.pyi
+++ /dev/null
@@ -1,670 +0,0 @@
-# Copyright 2020 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""This modules contains type annotated stubs for DEFINE functions."""
-
-
-from absl.flags import _argument_parser
-from absl.flags import _flag
-from absl.flags import _flagvalues
-
-import enum
-
-from typing import Text, List, Any, TypeVar, Optional, Union, Type, Iterable, overload, Literal
-
-_T = TypeVar('_T')
-_ET = TypeVar('_ET', bound=enum.Enum)
-
-
-@overload
-def DEFINE(
-    parser: _argument_parser.ArgumentParser[_T],
-    name: Text,
-    default: Any,
-    help: Optional[Text],
-    flag_values : _flagvalues.FlagValues = ...,
-    serializer: Optional[_argument_parser.ArgumentSerializer[_T]] = ...,
-    module_name: Optional[Text] = ...,
-    required: Literal[True] = ...,
-    **args: Any) -> _flagvalues.FlagHolder[_T]:
-  ...
-
-
-@overload
-def DEFINE(
-    parser: _argument_parser.ArgumentParser[_T],
-    name: Text,
-    default: Any,
-    help: Optional[Text],
-    flag_values : _flagvalues.FlagValues = ...,
-    serializer: Optional[_argument_parser.ArgumentSerializer[_T]] = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[_T]]:
-  ...
-
-
-@overload
-def DEFINE_flag(
-    flag: _flag.Flag[_T],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: Literal[True] = ...
-) -> _flagvalues.FlagHolder[_T]:
-  ...
-
-@overload
-def DEFINE_flag(
-    flag: _flag.Flag[_T],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...) -> _flagvalues.FlagHolder[Optional[_T]]:
-  ...
-
-# typing overloads for DEFINE_* methods...
-#
-# - DEFINE_* method return FlagHolder[Optional[T]] or FlagHolder[T] depending
-#   on the arguments.
-# - If the flag value is guaranteed to be not None, the return type is
-#   FlagHolder[T].
-# - If the flag is required OR has a non-None default, the flag value i
-#   guaranteed to be not None after flag parsing has finished.
-# The information above is captured with three overloads as follows.
-#
-# (if required=True and passed in as a keyword argument,
-#  return type is FlagHolder[Y])
-# @overload
-# def DEFINE_xxx(
-#    ... arguments...
-#    default: Union[None, X] = ...,
-#    *,
-#    required: Literal[True]) -> _flagvalues.FlagHolder[Y]:
-#   ...
-#
-# (if default=None, return type is FlagHolder[Optional[Y]])
-# @overload
-# def DEFINE_xxx(
-#    ... arguments...
-#    default: None,
-#    required: bool = ...) -> _flagvalues.FlagHolder[Optional[Y]]:
-#   ...
-#
-# (if default!=None, return type is FlagHolder[Y]):
-# @overload
-# def DEFINE_xxx(
-#    ... arguments...
-#    default: X,
-#    required: bool = ...) -> _flagvalues.FlagHolder[Y]:
-#   ...
-#
-# where X = type of non-None default values for the flag
-#   and Y = non-None type for flag value
-
-@overload
-def DEFINE_string(
-    name: Text,
-    default: Optional[Text],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[Text]:
-  ...
-
-@overload
-def DEFINE_string(
-    name: Text,
-    default: None,
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[Text]]:
-  ...
-
-@overload
-def DEFINE_string(
-    name: Text,
-    default: Text,
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Text]:
-  ...
-
-@overload
-def DEFINE_boolean(
-    name : Text,
-    default: Union[None, Text, bool, int],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[bool]:
-  ...
-
-@overload
-def DEFINE_boolean(
-    name : Text,
-    default: None,
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[bool]]:
-  ...
-
-@overload
-def DEFINE_boolean(
-    name : Text,
-    default: Union[Text, bool, int],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[bool]:
-  ...
-
-@overload
-def DEFINE_float(
-    name: Text,
-    default: Union[None, float, Text],
-    help: Optional[Text],
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[float]:
-  ...
-
-@overload
-def DEFINE_float(
-    name: Text,
-    default: None,
-    help: Optional[Text],
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[float]]:
-  ...
-
-@overload
-def DEFINE_float(
-    name: Text,
-    default: Union[float, Text],
-    help: Optional[Text],
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[float]:
-  ...
-
-
-@overload
-def DEFINE_integer(
-    name: Text,
-    default: Union[None, int, Text],
-    help: Optional[Text],
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[int]:
-  ...
-
-@overload
-def DEFINE_integer(
-    name: Text,
-    default: None,
-    help: Optional[Text],
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[int]]:
-  ...
-
-@overload
-def DEFINE_integer(
-    name: Text,
-    default: Union[int, Text],
-    help: Optional[Text],
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[int]:
-  ...
-
-@overload
-def DEFINE_enum(
-    name : Text,
-    default: Optional[Text],
-    enum_values: Iterable[Text],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name:  Optional[Text] = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[Text]:
-  ...
-
-@overload
-def DEFINE_enum(
-    name : Text,
-    default: None,
-    enum_values: Iterable[Text],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name:  Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[Text]]:
-  ...
-
-@overload
-def DEFINE_enum(
-    name : Text,
-    default: Text,
-    enum_values: Iterable[Text],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name:  Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Text]:
-  ...
-
-@overload
-def DEFINE_enum_class(
-    name: Text,
-    default: Union[None, _ET, Text],
-    enum_class: Type[_ET],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    case_sensitive: bool = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[_ET]:
-  ...
-
-@overload
-def DEFINE_enum_class(
-    name: Text,
-    default: None,
-    enum_class: Type[_ET],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    case_sensitive: bool = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[_ET]]:
-  ...
-
-@overload
-def DEFINE_enum_class(
-    name: Text,
-    default: Union[_ET, Text],
-    enum_class: Type[_ET],
-    help: Optional[Text],
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    case_sensitive: bool = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[_ET]:
-  ...
-
-
-@overload
-def DEFINE_list(
-    name: Text,
-    default: Union[None, Iterable[Text], Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues  = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_list(
-    name: Text,
-    default: None,
-    help: Text,
-    flag_values: _flagvalues.FlagValues  = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
-  ...
-
-@overload
-def DEFINE_list(
-    name: Text,
-    default: Union[Iterable[Text], Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues  = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_spaceseplist(
-    name: Text,
-    default: Union[None, Iterable[Text], Text],
-    help: Text,
-    comma_compat: bool = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_spaceseplist(
-    name: Text,
-    default: None,
-    help: Text,
-    comma_compat: bool = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
-  ...
-
-@overload
-def DEFINE_spaceseplist(
-    name: Text,
-    default: Union[Iterable[Text], Text],
-    help: Text,
-    comma_compat: bool = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_multi(
-    parser : _argument_parser.ArgumentParser[_T],
-    serializer: _argument_parser.ArgumentSerializer[_T],
-    name: Text,
-    default: Union[None, Iterable[_T], _T, Text],
-    help: Text,
-    flag_values:_flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[_T]]:
-  ...
-
-@overload
-def DEFINE_multi(
-    parser : _argument_parser.ArgumentParser[_T],
-    serializer: _argument_parser.ArgumentSerializer[_T],
-    name: Text,
-    default: None,
-    help: Text,
-    flag_values:_flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[_T]]]:
-  ...
-
-@overload
-def DEFINE_multi(
-    parser : _argument_parser.ArgumentParser[_T],
-    serializer: _argument_parser.ArgumentSerializer[_T],
-    name: Text,
-    default: Union[Iterable[_T], _T, Text],
-    help: Text,
-    flag_values:_flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[_T]]:
-  ...
-
-@overload
-def DEFINE_multi_string(
-    name: Text,
-    default: Union[None, Iterable[Text], Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_multi_string(
-    name: Text,
-    default: None,
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
-  ...
-
-@overload
-def DEFINE_multi_string(
-    name: Text,
-    default: Union[Iterable[Text], Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_multi_integer(
-    name: Text,
-    default: Union[None, Iterable[int], int, Text],
-    help: Text,
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[int]]:
-  ...
-
-@overload
-def DEFINE_multi_integer(
-    name: Text,
-    default: None,
-    help: Text,
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[int]]]:
-  ...
-
-@overload
-def DEFINE_multi_integer(
-    name: Text,
-    default: Union[Iterable[int], int, Text],
-    help: Text,
-    lower_bound: Optional[int] = ...,
-    upper_bound: Optional[int] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[int]]:
-  ...
-
-@overload
-def DEFINE_multi_float(
-    name: Text,
-    default: Union[None, Iterable[float], float, Text],
-    help: Text,
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[float]]:
-  ...
-
-@overload
-def DEFINE_multi_float(
-    name: Text,
-    default: None,
-    help: Text,
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[float]]]:
-  ...
-
-@overload
-def DEFINE_multi_float(
-    name: Text,
-    default: Union[Iterable[float], float, Text],
-    help: Text,
-    lower_bound: Optional[float] = ...,
-    upper_bound: Optional[float] = ...,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[float]]:
-  ...
-
-
-@overload
-def DEFINE_multi_enum(
-    name: Text,
-    default: Union[None, Iterable[Text], Text],
-    enum_values: Iterable[Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_multi_enum(
-    name: Text,
-    default: None,
-    enum_values: Iterable[Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[Text]]]:
-  ...
-
-@overload
-def DEFINE_multi_enum(
-    name: Text,
-    default: Union[Iterable[Text], Text],
-    enum_values: Iterable[Text],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[Text]]:
-  ...
-
-@overload
-def DEFINE_multi_enum_class(
-    name: Text,
-    # This is separate from `Union[None, _ET, Text]` to avoid a Pytype issue
-    # inferring the return value to FlagHolder[List[Union[_ET, enum.Enum]]]
-    # when an iterable of concrete enum subclasses are used.
-    default: Iterable[_ET],
-    enum_class: Type[_ET],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[_ET]]:
-  ...
-
-@overload
-def DEFINE_multi_enum_class(
-    name: Text,
-    default: Union[None, _ET, Text],
-    enum_class: Type[_ET],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    *,
-    required: Literal[True],
-    **args: Any) -> _flagvalues.FlagHolder[List[_ET]]:
-  ...
-
-@overload
-def DEFINE_multi_enum_class(
-    name: Text,
-    default: None,
-    enum_class: Type[_ET],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[Optional[List[_ET]]]:
-  ...
-
-@overload
-def DEFINE_multi_enum_class(
-    name: Text,
-    # This is separate from `Union[None, _ET, Text]` to avoid a Pytype issue
-    # inferring the return value to FlagHolder[List[Union[_ET, enum.Enum]]]
-    # when an iterable of concrete enum subclasses are used.
-    default: Iterable[_ET],
-    enum_class: Type[_ET],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[_ET]]:
-  ...
-
-@overload
-def DEFINE_multi_enum_class(
-    name: Text,
-    default: Union[_ET, Text],
-    enum_class: Type[_ET],
-    help: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...,
-    required: bool = ...,
-    **args: Any) -> _flagvalues.FlagHolder[List[_ET]]:
-  ...
-
-
-def DEFINE_alias(
-    name: Text,
-    original_name: Text,
-    flag_values: _flagvalues.FlagValues = ...,
-    module_name: Optional[Text] = ...) -> _flagvalues.FlagHolder[Any]:
-  ...
-
-
-def set_default(flag_holder: _flagvalues.FlagHolder[_T], value: _T) -> None:
-  ...
-
-
-def declare_key_flag(flag_name: Union[Text, _flagvalues.FlagHolder],
-                     flag_values: _flagvalues.FlagValues = ...) -> None:
-  ...
-
-
-
-def adopt_module_key_flags(module: Any,
-                           flag_values: _flagvalues.FlagValues = ...) -> None:
-  ...
-
-
-
-def disclaim_key_flags() -> None:
-  ...
diff --git a/absl/flags/_flag.py b/absl/flags/_flag.py
index 124f137..6711788 100644
--- a/absl/flags/_flag.py
+++ b/absl/flags/_flag.py
@@ -20,15 +20,21 @@ aliases defined at the package level instead.
 
 from collections import abc
 import copy
+import enum
 import functools
+from typing import Any, Dict, Generic, Iterable, List, Optional, Text, Type, TypeVar, Union
+from xml.dom import minidom
 
 from absl.flags import _argument_parser
 from absl.flags import _exceptions
 from absl.flags import _helpers
 
+_T = TypeVar('_T')
+_ET = TypeVar('_ET', bound=enum.Enum)
+
 
 @functools.total_ordering
-class Flag(object):
+class Flag(Generic[_T]):
   """Information about a command-line flag.
 
   Attributes:
@@ -76,10 +82,26 @@ class Flag(object):
   string, so it is important that it be a legal value for this flag.
   """
 
-  def __init__(self, parser, serializer, name, default, help_string,
-               short_name=None, boolean=False, allow_override=False,
-               allow_override_cpp=False, allow_hide_cpp=False,
-               allow_overwrite=True, allow_using_method_names=False):
+  # NOTE: pytype doesn't find defaults without this.
+  default: Optional[_T]
+  default_as_str: Optional[Text]
+  default_unparsed: Union[Optional[_T], Text]
+
+  def __init__(
+      self,
+      parser: _argument_parser.ArgumentParser[_T],
+      serializer: Optional[_argument_parser.ArgumentSerializer[_T]],
+      name: Text,
+      default: Union[Optional[_T], Text],
+      help_string: Optional[Text],
+      short_name: Optional[Text] = None,
+      boolean: bool = False,
+      allow_override: bool = False,
+      allow_override_cpp: bool = False,
+      allow_hide_cpp: bool = False,
+      allow_overwrite: bool = True,
+      allow_using_method_names: bool = False,
+  ) -> None:
     self.name = name
 
     if not help_string:
@@ -108,11 +130,11 @@ class Flag(object):
     self._set_default(default)
 
   @property
-  def value(self):
+  def value(self) -> Optional[_T]:
     return self._value
 
   @value.setter
-  def value(self, value):
+  def value(self, value: Optional[_T]):
     self._value = value
 
   def __hash__(self):
@@ -137,12 +159,12 @@ class Flag(object):
     raise TypeError('%s does not support shallow copies. '
                     'Use copy.deepcopy instead.' % type(self).__name__)
 
-  def __deepcopy__(self, memo):
+  def __deepcopy__(self, memo: Dict[int, Any]) -> 'Flag[_T]':
     result = object.__new__(type(self))
     result.__dict__ = copy.deepcopy(self.__dict__, memo)
     return result
 
-  def _get_parsed_value_as_string(self, value):
+  def _get_parsed_value_as_string(self, value: Optional[_T]) -> Optional[Text]:
     """Returns parsed flag value as string."""
     if value is None:
       return None
@@ -155,7 +177,7 @@ class Flag(object):
         return repr('false')
     return repr(str(value))
 
-  def parse(self, argument):
+  def parse(self, argument: Union[Text, Optional[_T]]) -> None:
     """Parses string and sets flag value.
 
     Args:
@@ -168,7 +190,7 @@ class Flag(object):
     self.value = self._parse(argument)
     self.present += 1
 
-  def _parse(self, argument):
+  def _parse(self, argument: Union[Text, _T]) -> Optional[_T]:
     """Internal parse function.
 
     It returns the parsed value, and does not modify class states.
@@ -185,16 +207,16 @@ class Flag(object):
       raise _exceptions.IllegalFlagValueError(
           'flag --%s=%s: %s' % (self.name, argument, e))
 
-  def unparse(self):
+  def unparse(self) -> None:
     self.value = self.default
     self.using_default_value = True
     self.present = 0
 
-  def serialize(self):
+  def serialize(self) -> Text:
     """Serializes the flag."""
     return self._serialize(self.value)
 
-  def _serialize(self, value):
+  def _serialize(self, value: Optional[_T]) -> Text:
     """Internal serialize function."""
     if value is None:
       return ''
@@ -209,7 +231,7 @@ class Flag(object):
             'Serializer not present for flag %s' % self.name)
       return '--%s=%s' % (self.name, self.serializer.serialize(value))
 
-  def _set_default(self, value):
+  def _set_default(self, value: Union[Optional[_T], Text]) -> None:
     """Changes the default value (and current value too) for this Flag."""
     self.default_unparsed = value
     if value is None:
@@ -222,10 +244,10 @@ class Flag(object):
 
   # This is split out so that aliases can skip regular parsing of the default
   # value.
-  def _parse_from_default(self, value):
+  def _parse_from_default(self, value: Union[Text, _T]) -> Optional[_T]:
     return self._parse(value)
 
-  def flag_type(self):
+  def flag_type(self) -> Text:
     """Returns a str that describes the type of the flag.
 
     NOTE: we use strings, and not the types.*Type constants because
@@ -234,7 +256,9 @@ class Flag(object):
     """
     return self.parser.flag_type()
 
-  def _create_xml_dom_element(self, doc, module_name, is_key=False):
+  def _create_xml_dom_element(
+      self, doc: minidom.Document, module_name: str, is_key: bool = False
+  ) -> minidom.Element:
     """Returns an XML element that contains this flag's information.
 
     This is information that is relevant to all flags (e.g., name,
@@ -286,11 +310,13 @@ class Flag(object):
       element.appendChild(e)
     return element
 
-  def _serialize_value_for_xml(self, value):
+  def _serialize_value_for_xml(self, value: Optional[_T]) -> Any:
     """Returns the serialized value, for use in an XML help text."""
     return value
 
-  def _extra_xml_dom_elements(self, doc):
+  def _extra_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     """Returns extra info about this flag in XML.
 
     "Extra" means "not already included by _create_xml_dom_element above."
@@ -306,7 +332,7 @@ class Flag(object):
     return self.parser._custom_xml_dom_elements(doc)  # pylint: disable=protected-access
 
 
-class BooleanFlag(Flag):
+class BooleanFlag(Flag[bool]):
   """Basic boolean flag.
 
   Boolean flags do not take any arguments, and their value is either
@@ -319,24 +345,45 @@ class BooleanFlag(Flag):
   explicitly unset through either ``--noupdate`` or ``--nox``.
   """
 
-  def __init__(self, name, default, help, short_name=None, **args):  # pylint: disable=redefined-builtin
+  def __init__(
+      self,
+      name: Text,
+      default: Union[Optional[bool], Text],
+      help: Optional[Text],  # pylint: disable=redefined-builtin
+      short_name: Optional[Text] = None,
+      **args
+  ) -> None:
     p = _argument_parser.BooleanParser()
     super(BooleanFlag, self).__init__(
-        p, None, name, default, help, short_name, 1, **args)
+        p, None, name, default, help, short_name, True, **args
+    )
 
 
-class EnumFlag(Flag):
+class EnumFlag(Flag[Text]):
   """Basic enum flag; its value can be any string from list of enum_values."""
 
-  def __init__(self, name, default, help, enum_values,  # pylint: disable=redefined-builtin
-               short_name=None, case_sensitive=True, **args):
+  def __init__(
+      self,
+      name: Text,
+      default: Optional[Text],
+      help: Optional[Text],  # pylint: disable=redefined-builtin
+      enum_values: Iterable[Text],
+      short_name: Optional[Text] = None,
+      case_sensitive: bool = True,
+      **args
+  ):
     p = _argument_parser.EnumParser(enum_values, case_sensitive)
     g = _argument_parser.ArgumentSerializer()
     super(EnumFlag, self).__init__(
         p, g, name, default, help, short_name, **args)
-    self.help = '<%s>: %s' % ('|'.join(enum_values), self.help)
-
-  def _extra_xml_dom_elements(self, doc):
+    # NOTE: parser should be typed EnumParser but the constructor
+    # restricts the available interface to ArgumentParser[str].
+    self.parser = p
+    self.help = '<%s>: %s' % ('|'.join(p.enum_values), self.help)
+
+  def _extra_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = []
     for enum_value in self.parser.enum_values:
       elements.append(_helpers.create_xml_dom_element(
@@ -344,26 +391,32 @@ class EnumFlag(Flag):
     return elements
 
 
-class EnumClassFlag(Flag):
+class EnumClassFlag(Flag[_ET]):
   """Basic enum flag; its value is an enum class's member."""
 
   def __init__(
       self,
-      name,
-      default,
-      help,  # pylint: disable=redefined-builtin
-      enum_class,
-      short_name=None,
-      case_sensitive=False,
-      **args):
+      name: Text,
+      default: Union[Optional[_ET], Text],
+      help: Optional[Text],  # pylint: disable=redefined-builtin
+      enum_class: Type[_ET],
+      short_name: Optional[Text] = None,
+      case_sensitive: bool = False,
+      **args
+  ):
     p = _argument_parser.EnumClassParser(
         enum_class, case_sensitive=case_sensitive)
     g = _argument_parser.EnumClassSerializer(lowercase=not case_sensitive)
     super(EnumClassFlag, self).__init__(
         p, g, name, default, help, short_name, **args)
+    # NOTE: parser should be typed EnumClassParser[_ET] but the constructor
+    # restricts the available interface to ArgumentParser[_ET].
+    self.parser = p
     self.help = '<%s>: %s' % ('|'.join(p.member_names), self.help)
 
-  def _extra_xml_dom_elements(self, doc):
+  def _extra_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = []
     for enum_value in self.parser.enum_class.__members__.keys():
       elements.append(_helpers.create_xml_dom_element(
@@ -371,7 +424,7 @@ class EnumClassFlag(Flag):
     return elements
 
 
-class MultiFlag(Flag):
+class MultiFlag(Generic[_T], Flag[List[_T]]):
   """A flag that can appear multiple time on the command-line.
 
   The value of such a flag is a list that contains the individual values
@@ -392,7 +445,7 @@ class MultiFlag(Flag):
     super(MultiFlag, self).__init__(*args, **kwargs)
     self.help += ';\n    repeat this option to specify a list of values'
 
-  def parse(self, arguments):
+  def parse(self, arguments: Union[Text, _T, Iterable[_T]]):  # pylint: disable=arguments-renamed
     """Parses one or more arguments with the installed parser.
 
     Args:
@@ -407,7 +460,7 @@ class MultiFlag(Flag):
       self.value = new_values
     self.present += len(new_values)
 
-  def _parse(self, arguments):
+  def _parse(self, arguments: Union[Text, Optional[Iterable[_T]]]) -> List[_T]:  # pylint: disable=arguments-renamed
     if (isinstance(arguments, abc.Iterable) and
         not isinstance(arguments, str)):
       arguments = list(arguments)
@@ -420,7 +473,7 @@ class MultiFlag(Flag):
 
     return [super(MultiFlag, self)._parse(item) for item in arguments]
 
-  def _serialize(self, value):
+  def _serialize(self, value: Optional[List[_T]]) -> Text:
     """See base class."""
     if not self.serializer:
       raise _exceptions.Error(
@@ -438,16 +491,18 @@ class MultiFlag(Flag):
     """See base class."""
     return 'multi ' + self.parser.flag_type()
 
-  def _extra_xml_dom_elements(self, doc):
+  def _extra_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = []
     if hasattr(self.parser, 'enum_values'):
-      for enum_value in self.parser.enum_values:
+      for enum_value in self.parser.enum_values:  # pytype: disable=attribute-error
         elements.append(_helpers.create_xml_dom_element(
             doc, 'enum_value', enum_value))
     return elements
 
 
-class MultiEnumClassFlag(MultiFlag):
+class MultiEnumClassFlag(MultiFlag[_ET]):  # pytype: disable=not-indexable
   """A multi_enum_class flag.
 
   See the __doc__ for MultiFlag for most behaviors of this class.  In addition,
@@ -455,26 +510,35 @@ class MultiEnumClassFlag(MultiFlag):
   type.
   """
 
-  def __init__(self,
-               name,
-               default,
-               help_string,
-               enum_class,
-               case_sensitive=False,
-               **args):
+  def __init__(
+      self,
+      name: str,
+      default: Union[None, Iterable[_ET], _ET, Iterable[Text], Text],
+      help_string: str,
+      enum_class: Type[_ET],
+      case_sensitive: bool = False,
+      **args
+  ):
     p = _argument_parser.EnumClassParser(
         enum_class, case_sensitive=case_sensitive)
     g = _argument_parser.EnumClassListSerializer(
         list_sep=',', lowercase=not case_sensitive)
     super(MultiEnumClassFlag, self).__init__(
         p, g, name, default, help_string, **args)
+    # NOTE: parser should be typed EnumClassParser[_ET] but the constructor
+    # restricts the available interface to ArgumentParser[str].
+    self.parser = p
+    # NOTE: serializer should be non-Optional but this isn't inferred.
+    self.serializer = g
     self.help = (
         '<%s>: %s;\n    repeat this option to specify a list of values' %
         ('|'.join(p.member_names), help_string or '(no help available)'))
 
-  def _extra_xml_dom_elements(self, doc):
+  def _extra_xml_dom_elements(
+      self, doc: minidom.Document
+  ) -> List[minidom.Element]:
     elements = []
-    for enum_value in self.parser.enum_class.__members__.keys():
+    for enum_value in self.parser.enum_class.__members__.keys():  # pytype: disable=attribute-error
       elements.append(_helpers.create_xml_dom_element(
           doc, 'enum_value', enum_value))
     return elements
@@ -482,6 +546,10 @@ class MultiEnumClassFlag(MultiFlag):
   def _serialize_value_for_xml(self, value):
     """See base class."""
     if value is not None:
+      if not self.serializer:
+        raise _exceptions.Error(
+            'Serializer not present for flag %s' % self.name
+        )
       value_serialized = self.serializer.serialize(value)
     else:
       value_serialized = ''
diff --git a/absl/flags/_flag.pyi b/absl/flags/_flag.pyi
deleted file mode 100644
index 3506644..0000000
--- a/absl/flags/_flag.pyi
+++ /dev/null
@@ -1,134 +0,0 @@
-# Copyright 2020 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Contains type annotations for Flag class."""
-
-import copy
-import functools
-
-from absl.flags import _argument_parser
-import enum
-
-from typing import Callable, Text, TypeVar, Generic, Iterable, Type, List, Optional, Any, Union, Sequence
-
-_T = TypeVar('_T')
-_ET = TypeVar('_ET', bound=enum.Enum)
-
-
-class Flag(Generic[_T]):
-
-  name = ... # type: Text
-  default = ... # type: Any
-  default_unparsed = ... # type: Any
-  default_as_str = ... # type: Optional[Text]
-  help = ... # type: Text
-  short_name = ... # type: Text
-  boolean = ... # type: bool
-  present = ... # type: bool
-  parser = ... # type: _argument_parser.ArgumentParser[_T]
-  serializer = ... # type: _argument_parser.ArgumentSerializer[_T]
-  allow_override = ... # type: bool
-  allow_override_cpp = ... # type: bool
-  allow_hide_cpp = ... # type: bool
-  using_default_value = ... # type: bool
-  allow_overwrite = ... # type: bool
-  allow_using_method_names = ... # type: bool
-  validators = ... # type: List[Callable[[Any], bool]]
-
-  def __init__(self,
-               parser: _argument_parser.ArgumentParser[_T],
-               serializer: Optional[_argument_parser.ArgumentSerializer[_T]],
-               name: Text,
-               default: Any,
-               help_string: Optional[Text],
-               short_name: Optional[Text] = ...,
-               boolean: bool = ...,
-               allow_override: bool = ...,
-               allow_override_cpp: bool = ...,
-               allow_hide_cpp: bool = ...,
-               allow_overwrite: bool = ...,
-               allow_using_method_names: bool = ...) -> None:
-    ...
-
-
-  @property
-  def value(self) -> Optional[_T]: ...
-
-  def parse(self, argument: Union[_T, Text, None]) -> None: ...
-
-  def unparse(self) -> None: ...
-
-  def _parse(self, argument: Any) -> Any: ...
-
-  def __deepcopy__(self, memo: dict) -> Flag: ...
-
-  def _get_parsed_value_as_string(self, value: Optional[_T]) -> Optional[Text]:
-    ...
-
-  def serialize(self) -> Text: ...
-
-  def flag_type(self) -> Text: ...
-
-
-class BooleanFlag(Flag[bool]):
-  def __init__(self,
-               name: Text,
-               default: Any,
-               help: Optional[Text],
-               short_name: Optional[Text]=None,
-               **args: Any) -> None:
-    ...
-
-
-
-class EnumFlag(Flag[Text]):
-  def __init__(self,
-               name: Text,
-               default: Any,
-               help: Optional[Text],
-               enum_values: Sequence[Text],
-               short_name: Optional[Text] = ...,
-               case_sensitive: bool = ...,
-               **args: Any):
-      ...
-
-
-
-class EnumClassFlag(Flag[_ET]):
-
-  def __init__(self,
-               name: Text,
-               default: Any,
-               help: Optional[Text],
-               enum_class: Type[_ET],
-               short_name: Optional[Text]=None,
-               **args: Any):
-    ...
-
-
-
-class MultiFlag(Flag[List[_T]]):
-  ...
-
-
-class MultiEnumClassFlag(MultiFlag[_ET]):
-  def __init__(self,
-               name: Text,
-               default: Any,
-               help_string: Optional[Text],
-               enum_class: Type[_ET],
-               **args: Any):
-    ...
-
-
diff --git a/absl/flags/_flagvalues.py b/absl/flags/_flagvalues.py
index fd0e631..e25f1d3 100644
--- a/absl/flags/_flagvalues.py
+++ b/absl/flags/_flagvalues.py
@@ -22,13 +22,14 @@ import itertools
 import logging
 import os
 import sys
-from typing import Generic, TypeVar
+from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Text, TextIO, Generic, TypeVar, Union, Tuple
 from xml.dom import minidom
 
 from absl.flags import _exceptions
 from absl.flags import _flag
 from absl.flags import _helpers
 from absl.flags import _validators_classes
+from absl.flags._flag import Flag
 
 # Add flagvalues module to disclaimed module ids.
 _helpers.disclaim_module_ids.add(id(sys.modules[__name__]))
@@ -74,12 +75,16 @@ class FlagValues:
   help for all of the registered :class:`~absl.flags.Flag` objects.
   """
 
+  _HAS_DYNAMIC_ATTRIBUTES = True
+
   # A note on collections.abc.Mapping:
   # FlagValues defines __getitem__, __iter__, and __len__. It makes perfect
   # sense to let it be a collections.abc.Mapping class. However, we are not
   # able to do so. The mixin methods, e.g. keys, values, are not uncommon flag
   # names. Those flag values would not be accessible via the FLAGS.xxx form.
 
+  __dict__: Dict[str, Any]
+
   def __init__(self):
     # Since everything in this class is so heavily overloaded, the only
     # way of defining and using fields is to access __dict__ directly.
@@ -126,7 +131,7 @@ class FlagValues:
     # (is_retired, type_is_bool).
     self.__dict__['__is_retired_flag_func'] = None
 
-  def set_gnu_getopt(self, gnu_getopt=True):
+  def set_gnu_getopt(self, gnu_getopt: bool = True) -> None:
     """Sets whether or not to use GNU style scanning.
 
     GNU style allows mixing of flag and non-flag arguments. See
@@ -138,13 +143,13 @@ class FlagValues:
     self.__dict__['__use_gnu_getopt'] = gnu_getopt
     self.__dict__['__use_gnu_getopt_explicitly_set'] = True
 
-  def is_gnu_getopt(self):
+  def is_gnu_getopt(self) -> bool:
     return self.__dict__['__use_gnu_getopt']
 
-  def _flags(self):
+  def _flags(self) -> Dict[Text, Flag]:
     return self.__dict__['__flags']
 
-  def flags_by_module_dict(self):
+  def flags_by_module_dict(self) -> Dict[Text, List[Flag]]:
     """Returns the dictionary of module_name -> list of defined flags.
 
     Returns:
@@ -153,7 +158,7 @@ class FlagValues:
     """
     return self.__dict__['__flags_by_module']
 
-  def flags_by_module_id_dict(self):
+  def flags_by_module_id_dict(self) -> Dict[int, List[Flag]]:
     """Returns the dictionary of module_id -> list of defined flags.
 
     Returns:
@@ -162,7 +167,7 @@ class FlagValues:
     """
     return self.__dict__['__flags_by_module_id']
 
-  def key_flags_by_module_dict(self):
+  def key_flags_by_module_dict(self) -> Dict[Text, List[Flag]]:
     """Returns the dictionary of module_name -> list of key flags.
 
     Returns:
@@ -171,7 +176,7 @@ class FlagValues:
     """
     return self.__dict__['__key_flags_by_module']
 
-  def register_flag_by_module(self, module_name, flag):
+  def register_flag_by_module(self, module_name: Text, flag: Flag) -> None:
     """Records the module that defines a specific flag.
 
     We keep track of which flag is defined by which module so that we
@@ -184,7 +189,7 @@ class FlagValues:
     flags_by_module = self.flags_by_module_dict()
     flags_by_module.setdefault(module_name, []).append(flag)
 
-  def register_flag_by_module_id(self, module_id, flag):
+  def register_flag_by_module_id(self, module_id: int, flag: Flag) -> None:
     """Records the module that defines a specific flag.
 
     Args:
@@ -194,7 +199,7 @@ class FlagValues:
     flags_by_module_id = self.flags_by_module_id_dict()
     flags_by_module_id.setdefault(module_id, []).append(flag)
 
-  def register_key_flag_for_module(self, module_name, flag):
+  def register_key_flag_for_module(self, module_name: Text, flag: Flag) -> None:
     """Specifies that a flag is a key flag for a module.
 
     Args:
@@ -208,7 +213,7 @@ class FlagValues:
     if flag not in key_flags:
       key_flags.append(flag)
 
-  def _flag_is_registered(self, flag_obj):
+  def _flag_is_registered(self, flag_obj: Flag) -> bool:
     """Checks whether a Flag object is registered under long name or short name.
 
     Args:
@@ -228,7 +233,9 @@ class FlagValues:
       return True
     return False
 
-  def _cleanup_unregistered_flag_from_module_dicts(self, flag_obj):
+  def _cleanup_unregistered_flag_from_module_dicts(
+      self, flag_obj: Flag
+  ) -> None:
     """Cleans up unregistered flags from all module -> [flags] dictionaries.
 
     If flag_obj is registered under either its long name or short name, it
@@ -248,7 +255,7 @@ class FlagValues:
         while flag_obj in flags_in_module:
           flags_in_module.remove(flag_obj)
 
-  def get_flags_for_module(self, module):
+  def get_flags_for_module(self, module: Union[Text, Any]) -> List[Flag]:
     """Returns the list of flags defined by a module.
 
     Args:
@@ -266,7 +273,7 @@ class FlagValues:
 
     return list(self.flags_by_module_dict().get(module, []))
 
-  def get_key_flags_for_module(self, module):
+  def get_key_flags_for_module(self, module: Union[Text, Any]) -> List[Flag]:
     """Returns the list of key flags for a module.
 
     Args:
@@ -293,7 +300,10 @@ class FlagValues:
         key_flags.append(flag)
     return key_flags
 
-  def find_module_defining_flag(self, flagname, default=None):
+  # TODO(yileiyang): Restrict default to Optional[Text].
+  def find_module_defining_flag(
+      self, flagname: Text, default: Optional[_T] = None
+  ) -> Union[str, Optional[_T]]:
     """Return the name of the module defining this flag, or default.
 
     Args:
@@ -318,7 +328,10 @@ class FlagValues:
           return module
     return default
 
-  def find_module_id_defining_flag(self, flagname, default=None):
+  # TODO(yileiyang): Restrict default to Optional[Text].
+  def find_module_id_defining_flag(
+      self, flagname: Text, default: Optional[_T] = None
+  ) -> Union[int, Optional[_T]]:
     """Return the ID of the module defining this flag, or default.
 
     Args:
@@ -343,7 +356,9 @@ class FlagValues:
           return module_id
     return default
 
-  def _register_unknown_flag_setter(self, setter):
+  def _register_unknown_flag_setter(
+      self, setter: Callable[[str, Any], None]
+  ) -> None:
     """Allow set default values for undefined flags.
 
     Args:
@@ -352,7 +367,7 @@ class FlagValues:
     """
     self.__dict__['__set_unknown'] = setter
 
-  def _set_unknown_flag(self, name, value):
+  def _set_unknown_flag(self, name: str, value: _T) -> _T:
     """Returns value if setting flag |name| to |value| returned True.
 
     Args:
@@ -378,7 +393,7 @@ class FlagValues:
         pass
     raise _exceptions.UnrecognizedFlagError(name, value)
 
-  def append_flag_values(self, flag_values):
+  def append_flag_values(self, flag_values: 'FlagValues') -> None:
     """Appends flags registered in another FlagValues instance.
 
     Args:
@@ -397,7 +412,9 @@ class FlagValues:
           raise _exceptions.DuplicateFlagError.from_flag(
               flag_name, self, other_flag_values=flag_values)
 
-  def remove_flag_values(self, flag_values):
+  def remove_flag_values(
+      self, flag_values: 'Union[FlagValues, Iterable[Text]]'
+  ) -> None:
     """Remove flags that were previously appended from another FlagValues.
 
     Args:
@@ -407,7 +424,7 @@ class FlagValues:
     for flag_name in flag_values:
       self.__delattr__(flag_name)
 
-  def __setitem__(self, name, flag):
+  def __setitem__(self, name: Text, flag: Flag) -> None:
     """Registers a new flag variable."""
     fl = self._flags()
     if not isinstance(flag, _flag.Flag):
@@ -430,10 +447,10 @@ class FlagValues:
         # module is simply being imported a subsequent time.
         return
       raise _exceptions.DuplicateFlagError.from_flag(name, self)
-    short_name = flag.short_name
     # If a new flag overrides an old one, we need to cleanup the old flag's
     # modules if it's not registered.
     flags_to_cleanup = set()
+    short_name: str = flag.short_name  # pytype: disable=annotation-type-mismatch
     if short_name is not None:
       if (short_name in fl and not flag.allow_override and
           not fl[short_name].allow_override):
@@ -449,7 +466,7 @@ class FlagValues:
     for f in flags_to_cleanup:
       self._cleanup_unregistered_flag_from_module_dicts(f)
 
-  def __dir__(self):
+  def __dir__(self) -> List[Text]:
     """Returns list of names of all defined flags.
 
     Useful for TAB-completion in ipython.
@@ -459,7 +476,7 @@ class FlagValues:
     """
     return sorted(self.__dict__['__flags'])
 
-  def __getitem__(self, name):
+  def __getitem__(self, name: Text) -> Flag:
     """Returns the Flag object for the flag --name."""
     return self._flags()[name]
 
@@ -467,7 +484,7 @@ class FlagValues:
     """Marks the flag --name as hidden."""
     self.__dict__['__hiddenflags'].add(name)
 
-  def __getattr__(self, name):
+  def __getattr__(self, name: Text) -> Any:
     """Retrieves the 'value' attribute of the flag --name."""
     fl = self._flags()
     if name not in fl:
@@ -481,28 +498,40 @@ class FlagValues:
       raise _exceptions.UnparsedFlagAccessError(
           'Trying to access flag --%s before flags were parsed.' % name)
 
-  def __setattr__(self, name, value):
+  def __setattr__(self, name: Text, value: _T) -> _T:
     """Sets the 'value' attribute of the flag --name."""
     self._set_attributes(**{name: value})
     return value
 
-  def _set_attributes(self, **attributes):
+  def _set_attributes(self, **attributes: Any) -> None:
     """Sets multiple flag values together, triggers validators afterwards."""
     fl = self._flags()
-    known_flags = set()
-    for name, value in attributes.items():
-      if name in self.__dict__['__hiddenflags']:
-        raise AttributeError(name)
-      if name in fl:
-        fl[name].value = value
-        known_flags.add(name)
-      else:
-        self._set_unknown_flag(name, value)
-    for name in known_flags:
-      self._assert_validators(fl[name].validators)
-      fl[name].using_default_value = False
-
-  def validate_all_flags(self):
+    known_flag_vals = {}
+    known_flag_used_defaults = {}
+    try:
+      for name, value in attributes.items():
+        if name in self.__dict__['__hiddenflags']:
+          raise AttributeError(name)
+        if name in fl:
+          orig = fl[name].value
+          fl[name].value = value
+          known_flag_vals[name] = orig
+        else:
+          self._set_unknown_flag(name, value)
+      for name in known_flag_vals:
+        self._assert_validators(fl[name].validators)
+        known_flag_used_defaults[name] = fl[name].using_default_value
+        fl[name].using_default_value = False
+    except:
+      for name, orig in known_flag_vals.items():
+        fl[name].value = orig
+      for name, orig in known_flag_used_defaults.items():
+        fl[name].using_default_value = orig
+      # NOTE: We do not attempt to undo unknown flag side effects because we
+      # cannot reliably undo the user-configured behavior.
+      raise
+
+  def validate_all_flags(self) -> None:
     """Verifies whether all flags pass validation.
 
     Raises:
@@ -515,7 +544,9 @@ class FlagValues:
       all_validators.update(flag.validators)
     self._assert_validators(all_validators)
 
-  def _assert_validators(self, validators):
+  def _assert_validators(
+      self, validators: Iterable[_validators_classes.Validator]
+  ) -> None:
     """Asserts if all validators in the list are satisfied.
 
     It asserts validators in the order they were created.
@@ -550,7 +581,7 @@ class FlagValues:
     if messages:
       raise _exceptions.IllegalFlagValueError('\n'.join(messages))
 
-  def __delattr__(self, flag_name):
+  def __delattr__(self, flag_name: Text) -> None:
     """Deletes a previously-defined flag from a flag object.
 
     This method makes sure we can delete a flag by using
@@ -580,7 +611,7 @@ class FlagValues:
 
     self._cleanup_unregistered_flag_from_module_dicts(flag_obj)
 
-  def set_default(self, name, value):
+  def set_default(self, name: Text, value: Any) -> None:
     """Changes the default value of the named flag object.
 
     The flag's current value is also updated if the flag is currently using
@@ -602,17 +633,19 @@ class FlagValues:
     fl[name]._set_default(value)  # pylint: disable=protected-access
     self._assert_validators(fl[name].validators)
 
-  def __contains__(self, name):
+  def __contains__(self, name: Text) -> bool:
     """Returns True if name is a value (flag) in the dict."""
     return name in self._flags()
 
-  def __len__(self):
+  def __len__(self) -> int:
     return len(self.__dict__['__flags'])
 
-  def __iter__(self):
+  def __iter__(self) -> Iterator[Text]:
     return iter(self._flags())
 
-  def __call__(self, argv, known_only=False):
+  def __call__(
+      self, argv: Sequence[Text], known_only: bool = False
+  ) -> List[Text]:
     """Parses flags from argv; stores parsed flags into this FlagValues object.
 
     All unparsed arguments are returned.
@@ -656,14 +689,14 @@ class FlagValues:
     self.validate_all_flags()
     return [program_name] + unparsed_args
 
-  def __getstate__(self):
+  def __getstate__(self) -> Any:
     raise TypeError("can't pickle FlagValues")
 
-  def __copy__(self):
+  def __copy__(self) -> Any:
     raise TypeError('FlagValues does not support shallow copies. '
                     'Use absl.testing.flagsaver or copy.deepcopy instead.')
 
-  def __deepcopy__(self, memo):
+  def __deepcopy__(self, memo) -> Any:
     result = object.__new__(type(self))
     result.__dict__.update(copy.deepcopy(self.__dict__, memo))
     return result
@@ -680,7 +713,9 @@ class FlagValues:
     """
     self.__dict__['__is_retired_flag_func'] = is_retired_flag_func
 
-  def _parse_args(self, args, known_only):
+  def _parse_args(
+      self, args: List[str], known_only: bool
+  ) -> Tuple[List[Tuple[Optional[str], Any]], List[str]]:
     """Helper function to do the main argument parsing.
 
     This function goes through args and does the bulk of the flag parsing.
@@ -787,8 +822,10 @@ class FlagValues:
             # in format of "--flag value".
             get_value()
           logging.error(
-              'Flag "%s" is retired and should no longer '
-              'be specified. See go/totw/90.', name)
+              'Flag "%s" is retired and should no longer be specified. See '
+              'https://abseil.io/tips/90.',
+              name,
+          )
           continue
 
       if flag is not None:
@@ -818,11 +855,11 @@ class FlagValues:
     unparsed_args.extend(list(args))
     return unknown_flags, unparsed_args
 
-  def is_parsed(self):
+  def is_parsed(self) -> bool:
     """Returns whether flags were parsed."""
     return self.__dict__['__flags_parsed']
 
-  def mark_as_parsed(self):
+  def mark_as_parsed(self) -> None:
     """Explicitly marks flags as parsed.
 
     Use this when the caller knows that this FlagValues has been parsed as if
@@ -831,7 +868,7 @@ class FlagValues:
     """
     self.__dict__['__flags_parsed'] = True
 
-  def unparse_flags(self):
+  def unparse_flags(self) -> None:
     """Unparses all flags to the point before any FLAGS(argv) was called."""
     for f in self._flags().values():
       f.unparse()
@@ -841,7 +878,7 @@ class FlagValues:
     self.__dict__['__flags_parsed'] = False
     self.__dict__['__unparse_flags_called'] = True
 
-  def flag_values_dict(self):
+  def flag_values_dict(self) -> Dict[Text, Any]:
     """Returns a dictionary that maps flag names to flag values."""
     return {name: flag.value for name, flag in self._flags().items()}
 
@@ -849,7 +886,9 @@ class FlagValues:
     """Returns a help string for all known flags."""
     return self.get_help()
 
-  def get_help(self, prefix='', include_special_flags=True):
+  def get_help(
+      self, prefix: Text = '', include_special_flags: bool = True
+  ) -> Text:
     """Returns a help string for all known flags.
 
     Args:
@@ -875,7 +914,8 @@ class FlagValues:
       values = self._flags().values()
       if include_special_flags:
         values = itertools.chain(
-            values, _helpers.SPECIAL_FLAGS._flags().values())  # pylint: disable=protected-access
+            values, _helpers.SPECIAL_FLAGS._flags().values()  # pylint: disable=protected-access  # pytype: disable=attribute-error
+        )
       self._render_flag_list(values, output_lines, prefix)
       return '\n'.join(output_lines)
 
@@ -896,9 +936,10 @@ class FlagValues:
     if include_special_flags:
       self._render_module_flags(
           'absl.flags',
-          _helpers.SPECIAL_FLAGS._flags().values(),  # pylint: disable=protected-access
+          _helpers.SPECIAL_FLAGS._flags().values(),  # pylint: disable=protected-access  # pytype: disable=attribute-error
           output_lines,
-          prefix)
+          prefix,
+      )
     return '\n'.join(output_lines)
 
   def _render_module_flags(self, module, flags, output_lines, prefix=''):
@@ -927,7 +968,7 @@ class FlagValues:
     if key_flags:
       self._render_module_flags(module, key_flags, output_lines, prefix)
 
-  def module_help(self, module):
+  def module_help(self, module: Any) -> Text:
     """Describes the key flags of a module.
 
     Args:
@@ -940,7 +981,7 @@ class FlagValues:
     self._render_our_module_key_flags(module, helplist)
     return '\n'.join(helplist)
 
-  def main_module_help(self):
+  def main_module_help(self) -> Text:
     """Describes the key flags of the main module.
 
     Returns:
@@ -950,7 +991,7 @@ class FlagValues:
 
   def _render_flag_list(self, flaglist, output_lines, prefix='  '):
     fl = self._flags()
-    special_fl = _helpers.SPECIAL_FLAGS._flags()  # pylint: disable=protected-access
+    special_fl = _helpers.SPECIAL_FLAGS._flags()  # pylint: disable=protected-access  # pytype: disable=attribute-error
     flaglist = [(flag.name, flag) for flag in flaglist]
     flaglist.sort()
     flagset = {}
@@ -987,7 +1028,7 @@ class FlagValues:
             '(%s)' % flag.parser.syntactic_help, indent=prefix + '  ')
       output_lines.append(flaghelp)
 
-  def get_flag_value(self, name, default):  # pylint: disable=invalid-name
+  def get_flag_value(self, name: Text, default: Any) -> Any:  # pylint: disable=invalid-name
     """Returns the value of a flag (if not None) or a default value.
 
     Args:
@@ -1109,7 +1150,9 @@ class FlagValues:
     parsed_file_stack.pop()
     return flag_line_list
 
-  def read_flags_from_files(self, argv, force_gnu=True):
+  def read_flags_from_files(
+      self, argv: Sequence[Text], force_gnu: bool = True
+  ) -> List[Text]:
     """Processes command line args, but also allow args to be read from file.
 
     Args:
@@ -1192,7 +1235,7 @@ class FlagValues:
 
     return new_argv
 
-  def flags_into_string(self):
+  def flags_into_string(self) -> Text:
     """Returns a string with the flags assignments from this FlagValues object.
 
     This function ignores flags whose value is None.  Each flag
@@ -1214,7 +1257,7 @@ class FlagValues:
           s += flag.serialize() + '\n'
     return s
 
-  def append_flags_into_file(self, filename):
+  def append_flags_into_file(self, filename: Text) -> None:
     """Appends all flags assignments from this FlagInfo object to a file.
 
     Output will be in the format of a flagfile.
@@ -1228,7 +1271,7 @@ class FlagValues:
     with open(filename, 'a') as out_file:
       out_file.write(self.flags_into_string())
 
-  def write_help_in_xml_format(self, outfile=None):
+  def write_help_in_xml_format(self, outfile: Optional[TextIO] = None) -> None:
     """Outputs flag documentation in XML format.
 
     NOTE: We use element names that are consistent with those used by
@@ -1280,7 +1323,7 @@ class FlagValues:
         doc.toprettyxml(indent='  ', encoding='utf-8').decode('utf-8'))
     outfile.flush()
 
-  def _check_method_name_conflicts(self, name, flag):
+  def _check_method_name_conflicts(self, name: str, flag: Flag):
     if flag.allow_using_method_names:
       return
     short_name = flag.short_name
@@ -1325,7 +1368,14 @@ class FlagHolder(Generic[_T]):
   since the name of the flag appears only once in the source code.
   """
 
-  def __init__(self, flag_values, flag, ensure_non_none_value=False):
+  value: _T
+
+  def __init__(
+      self,
+      flag_values: FlagValues,
+      flag: Flag[_T],
+      ensure_non_none_value: bool = False,
+  ):
     """Constructs a FlagHolder instance providing typesafe access to flag.
 
     Args:
@@ -1359,11 +1409,11 @@ class FlagHolder(Generic[_T]):
   __nonzero__ = __bool__
 
   @property
-  def name(self):
+  def name(self) -> Text:
     return self._name
 
   @property
-  def value(self):
+  def value(self) -> _T:
     """Returns the value of the flag.
 
     If ``_ensure_non_none_value`` is ``True``, then return value is not
@@ -1380,17 +1430,23 @@ class FlagHolder(Generic[_T]):
     return val
 
   @property
-  def default(self):
+  def default(self) -> _T:
     """Returns the default value of the flag."""
     return self._flagvalues[self._name].default
 
   @property
-  def present(self):
+  def present(self) -> bool:
     """Returns True if the flag was parsed from command-line flags."""
     return bool(self._flagvalues[self._name].present)
 
+  def serialize(self) -> Text:
+    """Returns a serialized representation of the flag."""
+    return self._flagvalues[self._name].serialize()
+
 
-def resolve_flag_ref(flag_ref, flag_values):
+def resolve_flag_ref(
+    flag_ref: Union[str, FlagHolder], flag_values: FlagValues
+) -> Tuple[str, FlagValues]:
   """Helper to validate and resolve a flag reference argument."""
   if isinstance(flag_ref, FlagHolder):
     new_flag_values = flag_ref._flagvalues  # pylint: disable=protected-access
@@ -1401,7 +1457,9 @@ def resolve_flag_ref(flag_ref, flag_values):
   return flag_ref, flag_values
 
 
-def resolve_flag_refs(flag_refs, flag_values):
+def resolve_flag_refs(
+    flag_refs: Sequence[Union[str, FlagHolder]], flag_values: FlagValues
+) -> Tuple[List[str], FlagValues]:
   """Helper to validate and resolve flag reference list arguments."""
   fv = None
   names = []
diff --git a/absl/flags/_flagvalues.pyi b/absl/flags/_flagvalues.pyi
deleted file mode 100644
index e25c6dd..0000000
--- a/absl/flags/_flagvalues.pyi
+++ /dev/null
@@ -1,148 +0,0 @@
-# Copyright 2020 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Defines type annotations for _flagvalues."""
-
-
-from absl.flags import _flag
-
-from typing import Any, Dict, Generic, Iterable, Iterator, List, Optional, Sequence, Text, Type, TypeVar
-
-
-class FlagValues:
-
-  def __getitem__(self, name: Text) -> _flag.Flag:  ...
-
-  def __setitem__(self, name: Text, flag: _flag.Flag) -> None:  ...
-
-  def __getattr__(self, name: Text) -> Any:  ...
-
-  def __setattr__(self, name: Text, value: Any) -> Any:  ...
-
-  def __call__(
-      self,
-      argv: Sequence[Text],
-      known_only: bool = ...,
-  ) -> List[Text]: ...
-
-  def __contains__(self, name: Text) -> bool: ...
-
-  def __copy__(self) -> Any: ...
-
-  def __deepcopy__(self, memo) -> Any: ...
-
-  def __delattr__(self, flag_name: Text) -> None: ...
-
-  def __dir__(self) -> List[Text]: ...
-
-  def __getstate__(self) -> Any: ...
-
-  def __iter__(self) -> Iterator[Text]: ...
-
-  def __len__(self) -> int: ...
-
-  def get_help(self,
-               prefix: Text = ...,
-               include_special_flags: bool = ...) -> Text:
-    ...
-
-
-  def set_gnu_getopt(self, gnu_getopt: bool = ...) -> None: ...
-
-  def is_gnu_getopt(self) -> bool: ...
-
-  def flags_by_module_dict(self) -> Dict[Text, List[_flag.Flag]]: ...
-
-  def flags_by_module_id_dict(self) -> Dict[Text, List[_flag.Flag]]: ...
-
-  def key_flags_by_module_dict(self) -> Dict[Text, List[_flag.Flag]]: ...
-
-  def register_flag_by_module(
-    self, module_name: Text, flag: _flag.Flag) -> None: ...
-
-  def register_flag_by_module_id(
-    self, module_id: Text, flag: _flag.Flag) -> None: ...
-
-  def register_key_flag_for_module(
-    self, module_name: Text, flag: _flag.Flag) -> None: ...
-
-  def get_key_flags_for_module(self, module: Any) -> List[_flag.Flag]: ...
-
-  def find_module_defining_flag(
-    self, flagname: Text, default: Any = ...) -> Any:
-    ...
-
-  def find_module_id_defining_flag(
-    self, flagname: Text, default: Any = ...) -> Any:
-    ...
-
-  def append_flag_values(self, flag_values: Any) -> None: ...
-
-  def remove_flag_values(self, flag_values: Any) -> None: ...
-
-  def validate_all_flags(self) -> None: ...
-
-  def set_default(self, name: Text, value: Any) -> None: ...
-
-  def is_parsed(self) -> bool: ...
-
-  def mark_as_parsed(self) -> None: ...
-
-  def unparse_flags(self) -> None: ...
-
-  def flag_values_dict(self) -> Dict[Text, Any]: ...
-
-  def module_help(self, module: Any) -> Text: ...
-
-  def main_module_help(self) -> Text: ...
-
-  def get_flag_value(self, name: Text, default: Any) -> Any: ...
-
-  def read_flags_from_files(
-    self, argv: List[Text], force_gnu: bool = ...) -> List[Text]: ...
-
-  def flags_into_string(self) -> Text: ...
-
-  def append_flags_into_file(self, filename: Text) -> None:...
-
-  # outfile is Optional[fileobject]
-  def write_help_in_xml_format(self, outfile: Any = ...) -> None: ...
-
-
-FLAGS = ...  # type: FlagValues
-
-
-_T = TypeVar('_T')  # The type of parsed default value of the flag.
-
-# We assume that default and value are guaranteed to have the same type.
-class FlagHolder(Generic[_T]):
-  def __init__(
-    self,
-    flag_values: FlagValues,
-    # NOTE: Use Flag instead of Flag[T] is used to work around some superficial
-    # differences between Flag and FlagHolder typing.
-    flag: _flag.Flag,
-    ensure_non_none_value: bool=False) -> None: ...
-
-  @property
-  def name(self) -> Text: ...
-
-  @property
-  def value(self) -> _T: ...
-
-  @property
-  def default(self) -> _T: ...
-
-  @property
-  def present(self) -> bool: ...
diff --git a/absl/flags/_helpers.py b/absl/flags/_helpers.py
index ea02f2d..1ad559c 100644
--- a/absl/flags/_helpers.py
+++ b/absl/flags/_helpers.py
@@ -14,12 +14,15 @@
 
 """Internal helper functions for Abseil Python flags library."""
 
-import collections
 import os
 import re
 import struct
 import sys
 import textwrap
+import types
+from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set
+from xml.dom import minidom
+# pylint: disable=g-import-not-at-top
 try:
   import fcntl
 except ImportError:
@@ -29,6 +32,7 @@ try:
   import termios
 except ImportError:
   termios = None
+# pylint: enable=g-import-not-at-top
 
 
 _DEFAULT_HELP_WIDTH = 80  # Default width of help output.
@@ -56,32 +60,37 @@ _ILLEGAL_XML_CHARS_REGEX = re.compile(
 # This is a set of module ids for the modules that disclaim key flags.
 # This module is explicitly added to this set so that we never consider it to
 # define key flag.
-disclaim_module_ids = set([id(sys.modules[__name__])])
+disclaim_module_ids: Set[int] = set([id(sys.modules[__name__])])
 
 
 # Define special flags here so that help may be generated for them.
 # NOTE: Please do NOT use SPECIAL_FLAGS from outside flags module.
 # Initialized inside flagvalues.py.
-SPECIAL_FLAGS = None
+# NOTE: This cannot be annotated as its actual FlagValues type since this would
+# create a circular dependency.
+SPECIAL_FLAGS: Any = None
 
 
 # This points to the flags module, initialized in flags/__init__.py.
 # This should only be used in adopt_module_key_flags to take SPECIAL_FLAGS into
 # account.
-FLAGS_MODULE = None
+FLAGS_MODULE: types.ModuleType = None
 
 
-class _ModuleObjectAndName(
-    collections.namedtuple('_ModuleObjectAndName', 'module module_name')):
+class _ModuleObjectAndName(NamedTuple):
   """Module object and name.
 
   Fields:
   - module: object, module object.
   - module_name: str, module name.
   """
+  module: types.ModuleType
+  module_name: str
 
 
-def get_module_object_and_name(globals_dict):
+def get_module_object_and_name(
+    globals_dict: Dict[str, Any]
+) -> _ModuleObjectAndName:
   """Returns the module that defines a global environment, and its name.
 
   Args:
@@ -99,7 +108,7 @@ def get_module_object_and_name(globals_dict):
                               (sys.argv[0] if name == '__main__' else name))
 
 
-def get_calling_module_object_and_name():
+def get_calling_module_object_and_name() -> _ModuleObjectAndName:
   """Returns the module that's calling into this module.
 
   We generally use this function to get the name of the module calling a
@@ -121,12 +130,14 @@ def get_calling_module_object_and_name():
   raise AssertionError('No module was found')
 
 
-def get_calling_module():
+def get_calling_module() -> str:
   """Returns the name of the module that's calling into this module."""
   return get_calling_module_object_and_name().module_name
 
 
-def create_xml_dom_element(doc, name, value):
+def create_xml_dom_element(
+    doc: minidom.Document, name: str, value: Any
+) -> minidom.Element:
   """Returns an XML DOM element with name and text value.
 
   Args:
@@ -151,12 +162,12 @@ def create_xml_dom_element(doc, name, value):
   return e
 
 
-def get_help_width():
+def get_help_width() -> int:
   """Returns the integer width of help lines that is used in TextWrap."""
   if not sys.stdout.isatty() or termios is None or fcntl is None:
     return _DEFAULT_HELP_WIDTH
   try:
-    data = fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, '1234')
+    data = fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, b'1234')
     columns = struct.unpack('hh', data)[1]
     # Emacs mode returns 0.
     # Here we assume that any value below 40 is unreasonable.
@@ -169,7 +180,9 @@ def get_help_width():
     return _DEFAULT_HELP_WIDTH
 
 
-def get_flag_suggestions(attempt, longopt_list):
+def get_flag_suggestions(
+    attempt: Optional[str], longopt_list: Sequence[str]
+) -> List[str]:
   """Returns helpful similar matches for an invalid flag."""
   # Don't suggest on very short strings, or if no longopts are specified.
   if len(attempt) <= 2 or not longopt_list:
@@ -226,7 +239,12 @@ def _damerau_levenshtein(a, b):
   return distance(a, b)
 
 
-def text_wrap(text, length=None, indent='', firstline_indent=None):
+def text_wrap(
+    text: str,
+    length: Optional[int] = None,
+    indent: str = '',
+    firstline_indent: Optional[str] = None,
+) -> str:
   """Wraps a given text to a maximum line length and returns it.
 
   It turns lines that only contain whitespace into empty lines, keeps new lines,
@@ -283,7 +301,9 @@ def text_wrap(text, length=None, indent='', firstline_indent=None):
   return '\n'.join(result)
 
 
-def flag_dict_to_args(flag_map, multi_flags=None):
+def flag_dict_to_args(
+    flag_map: Dict[str, Any], multi_flags: Optional[Set[str]] = None
+) -> Iterable[str]:
   """Convert a dict of values into process call parameters.
 
   This method is used to convert a dictionary into a sequence of parameters
@@ -333,7 +353,7 @@ def flag_dict_to_args(flag_map, multi_flags=None):
         yield '--%s=%s' % (key, value)
 
 
-def trim_docstring(docstring):
+def trim_docstring(docstring: str) -> str:
   """Removes indentation from triple-quoted strings.
 
   This is the function specified in PEP 257 to handle docstrings:
@@ -375,7 +395,7 @@ def trim_docstring(docstring):
   return '\n'.join(trimmed)
 
 
-def doc_to_help(doc):
+def doc_to_help(doc: str) -> str:
   """Takes a __doc__ string and reformats it as help."""
 
   # Get rid of starting and ending white space. Using lstrip() or even
diff --git a/absl/flags/argparse_flags.py b/absl/flags/argparse_flags.py
index dd8b505..f05c794 100644
--- a/absl/flags/argparse_flags.py
+++ b/absl/flags/argparse_flags.py
@@ -145,7 +145,7 @@ class ArgumentParser(argparse.ArgumentParser):
           '--helpfull', action=_HelpFullAction,
           default=argparse.SUPPRESS, help='show full help message and exit')
 
-    if self._inherited_absl_flags:
+    if self._inherited_absl_flags is not None:
       self.add_argument(
           '--undefok', default=argparse.SUPPRESS, help=argparse.SUPPRESS)
       self._define_absl_flags(self._inherited_absl_flags)
@@ -153,7 +153,7 @@ class ArgumentParser(argparse.ArgumentParser):
   def parse_known_args(self, args=None, namespace=None):
     if args is None:
       args = sys.argv[1:]
-    if self._inherited_absl_flags:
+    if self._inherited_absl_flags is not None:
       # Handle --flagfile.
       # Explicitly specify force_gnu=True, since argparse behaves like
       # gnu_getopt: flags can be specified after positional arguments.
@@ -172,7 +172,7 @@ class ArgumentParser(argparse.ArgumentParser):
     if undefok is not undefok_missing:
       namespace.undefok = undefok
 
-    if self._inherited_absl_flags:
+    if self._inherited_absl_flags is not None:
       # Handle --undefok. At this point, `args` only contains unknown flags,
       # so it won't strip defined flags that are also specified with --undefok.
       # For Python <= 2.7.8: https://bugs.python.org/issue9351, a bug where
@@ -350,7 +350,7 @@ class _HelpFullAction(argparse.Action):
     parser.print_help()
 
     absl_flags = parser._inherited_absl_flags  # pylint: disable=protected-access
-    if absl_flags:
+    if absl_flags is not None:
       modules = sorted(absl_flags.flags_by_module_dict())
       main_module = sys.argv[0]
       if main_module in modules:
diff --git a/absl/flags/tests/_argument_parser_test.py b/absl/flags/tests/_argument_parser_test.py
index 4281c3f..6f7d191 100644
--- a/absl/flags/tests/_argument_parser_test.py
+++ b/absl/flags/tests/_argument_parser_test.py
@@ -33,12 +33,12 @@ class ArgumentParserTest(absltest.TestCase):
   def test_parse_wrong_type(self):
     parser = _argument_parser.ArgumentParser()
     with self.assertRaises(TypeError):
-      parser.parse(0)
+      parser.parse(0)  # type: ignore
 
     if bytes is not str:
       # In PY3, it does not accept bytes.
       with self.assertRaises(TypeError):
-        parser.parse(b'')
+        parser.parse(b'')  # type: ignore
 
 
 class BooleanParserTest(absltest.TestCase):
@@ -49,7 +49,7 @@ class BooleanParserTest(absltest.TestCase):
 
   def test_parse_bytes(self):
     with self.assertRaises(TypeError):
-      self.parser.parse(b'true')
+      self.parser.parse(b'true')  # type: ignore
 
   def test_parse_str(self):
     self.assertTrue(self.parser.parse('true'))
@@ -59,7 +59,7 @@ class BooleanParserTest(absltest.TestCase):
 
   def test_parse_wrong_type(self):
     with self.assertRaises(TypeError):
-      self.parser.parse(1.234)
+      self.parser.parse(1.234)  # type: ignore
 
   def test_parse_str_false(self):
     self.assertFalse(self.parser.parse('false'))
@@ -86,7 +86,7 @@ class FloatParserTest(absltest.TestCase):
 
   def test_parse_wrong_type(self):
     with self.assertRaises(TypeError):
-      self.parser.parse(False)
+      self.parser.parse(False)  # type: ignore
 
 
 class IntegerParserTest(absltest.TestCase):
@@ -99,9 +99,9 @@ class IntegerParserTest(absltest.TestCase):
 
   def test_parse_wrong_type(self):
     with self.assertRaises(TypeError):
-      self.parser.parse(1e2)
+      self.parser.parse(1e2)  # type: ignore
     with self.assertRaises(TypeError):
-      self.parser.parse(False)
+      self.parser.parse(False)  # type: ignore
 
 
 class EnumParserTest(absltest.TestCase):
@@ -139,7 +139,7 @@ class EnumClassParserTest(parameterized.TestCase):
 
   def test_requires_enum(self):
     with self.assertRaises(TypeError):
-      _argument_parser.EnumClassParser(['apple', 'banana'])
+      _argument_parser.EnumClassParser(['apple', 'banana'])  # type: ignore
 
   def test_requires_non_empty_enum_class(self):
     with self.assertRaises(ValueError):
diff --git a/absl/flags/tests/_flag_test.py b/absl/flags/tests/_flag_test.py
index 1625289..92de6c0 100644
--- a/absl/flags/tests/_flag_test.py
+++ b/absl/flags/tests/_flag_test.py
@@ -142,7 +142,7 @@ class EnumClassFlagTest(parameterized.TestCase):
 
   def test_requires_enum(self):
     with self.assertRaises(TypeError):
-      _flag.EnumClassFlag('fruit', None, 'help', ['apple', 'orange'])
+      _flag.EnumClassFlag('fruit', None, 'help', ['apple', 'orange'])  # type: ignore
 
   def test_requires_non_empty_enum_class(self):
     with self.assertRaises(ValueError):
@@ -186,7 +186,7 @@ class MultiEnumClassFlagTest(parameterized.TestCase):
 
   def test_requires_enum(self):
     with self.assertRaises(TypeError):
-      _flag.MultiEnumClassFlag('fruit', None, 'help', ['apple', 'orange'])
+      _flag.MultiEnumClassFlag('fruit', None, 'help', ['apple', 'orange'])  # type: ignore
 
   def test_requires_non_empty_enum_class(self):
     with self.assertRaises(ValueError):
diff --git a/absl/flags/tests/_flagvalues_test.py b/absl/flags/tests/_flagvalues_test.py
index 46639f2..09071d7 100644
--- a/absl/flags/tests/_flagvalues_test.py
+++ b/absl/flags/tests/_flagvalues_test.py
@@ -323,7 +323,7 @@ class FlagValuesTest(absltest.TestCase):
       _defines.DEFINE_boolean('', 0, '')
 
     with self.assertRaises(_exceptions.Error):
-      _defines.DEFINE_boolean(1, 0, '')
+      _defines.DEFINE_boolean(1, 0, '')  # type: ignore
 
   def test_len(self):
     fv = _flagvalues.FlagValues()
@@ -511,11 +511,9 @@ absl.flags.tests.module_foo:
   def test_invalid_argv(self):
     fv = _flagvalues.FlagValues()
     with self.assertRaises(TypeError):
-      fv('./program')
+      fv('./program')  # type: ignore
     with self.assertRaises(TypeError):
-      fv(b'./program')
-    with self.assertRaises(TypeError):
-      fv(u'./program')
+      fv(b'./program')  # type: ignore
 
   def test_flags_dir(self):
     flag_values = _flagvalues.FlagValues()
@@ -901,6 +899,10 @@ class FlagHolderTest(absltest.TestCase):
     self.parse_flags('--name=new_value')
     self.assertTrue(self.name_flag.present)
 
+  def test_serializes_flag(self):
+    self.parse_flags('--name=new_value')
+    self.assertEqual('--name=new_value', self.name_flag.serialize())
+
   def test_allow_override(self):
     first = _defines.DEFINE_integer(
         'int_flag', 1, 'help', flag_values=self.fv, allow_override=1)
diff --git a/absl/flags/tests/_helpers_test.py b/absl/flags/tests/_helpers_test.py
index 78b9051..daaf98c 100644
--- a/absl/flags/tests/_helpers_test.py
+++ b/absl/flags/tests/_helpers_test.py
@@ -73,8 +73,9 @@ class FlagSuggestionTest(absltest.TestCase):
   def test_suggestions_are_sorted(self):
     sorted_flags = sorted(['aab', 'aac', 'aad'])
     misspelt_flag = 'aaa'
-    suggestions = _helpers.get_flag_suggestions(misspelt_flag,
-                                                reversed(sorted_flags))
+    suggestions = _helpers.get_flag_suggestions(
+        misspelt_flag, list(reversed(sorted_flags))
+    )
     self.assertEqual(sorted_flags, suggestions)
 
 
diff --git a/absl/flags/tests/_validators_test.py b/absl/flags/tests/_validators_test.py
index 9aa328e..cf64cbe 100644
--- a/absl/flags/tests/_validators_test.py
+++ b/absl/flags/tests/_validators_test.py
@@ -20,7 +20,6 @@ failed validator will throw an exception, etc.
 
 import warnings
 
-
 from absl.flags import _defines
 from absl.flags import _exceptions
 from absl.flags import _flagvalues
diff --git a/absl/flags/tests/argparse_flags_test.py b/absl/flags/tests/argparse_flags_test.py
index 5e6f49a..23ae99a 100644
--- a/absl/flags/tests/argparse_flags_test.py
+++ b/absl/flags/tests/argparse_flags_test.py
@@ -179,8 +179,11 @@ class ArgparseFlagsTest(parameterized.TestCase):
     parser.add_argument('--header', help='Header message to print.')
     subparsers = parser.add_subparsers(help='The command to execute.')
 
-    sub_parser = subparsers.add_parser(
-        'sub_cmd', help='Sub command.', inherited_absl_flags=self._absl_flags)
+    # NOTE: The sub parsers don't work well with typing hence `type: ignore`.
+    # See https://github.com/python/typeshed/issues/10082.
+    sub_parser = subparsers.add_parser(  # type: ignore
+        'sub_cmd', help='Sub command.', inherited_absl_flags=self._absl_flags
+    )
     sub_parser.add_argument('--sub_flag', help='Sub command flag.')
 
     def sub_command_func():
@@ -203,11 +206,15 @@ class ArgparseFlagsTest(parameterized.TestCase):
         inherited_absl_flags=self._absl_flags)
     subparsers = parser.add_subparsers(help='The command to execute.')
 
-    subparsers.add_parser(
-        'sub_cmd', help='Sub command.',
+    # NOTE: The sub parsers don't work well with typing hence `type: ignore`.
+    # See https://github.com/python/typeshed/issues/10082.
+    subparsers.add_parser(  # type: ignore
+        'sub_cmd',
+        help='Sub command.',
         # Do not inherit absl flags in the subparser.
         # This is the behavior that this test exercises.
-        inherited_absl_flags=None)
+        inherited_absl_flags=None,
+    )
 
     with self.assertRaises(SystemExit):
       parser.parse_args(['sub_cmd', '--absl_string=new_value'])
@@ -270,10 +277,10 @@ class ArgparseFlagsTest(parameterized.TestCase):
   def test_no_help_flags(self, args):
     parser = argparse_flags.ArgumentParser(
         inherited_absl_flags=self._absl_flags, add_help=False)
-    with mock.patch.object(parser, 'print_help'):
+    with mock.patch.object(parser, 'print_help') as print_help_mock:
       with self.assertRaises(SystemExit):
         parser.parse_args(args)
-      parser.print_help.assert_not_called()
+    print_help_mock.assert_not_called()
 
   def test_helpfull_message(self):
     flags.DEFINE_string(
@@ -399,6 +406,21 @@ class ArgparseFlagsTest(parameterized.TestCase):
     args = parser.parse_args([])
     self.assertEqual(args.magic_number, 23)
 
+  def test_empty_inherited_absl_flags(self):
+    parser = argparse_flags.ArgumentParser(
+        inherited_absl_flags=flags.FlagValues()
+    )
+    parser.add_argument('--foo')
+    flagfile = self.create_tempfile(content='--foo=bar').full_path
+    # Make sure these flags are still available when inheriting an empty
+    # FlagValues instance.
+    ns = parser.parse_args([
+        '--undefok=undefined_flag',
+        '--undefined_flag=value',
+        '--flagfile=' + flagfile,
+    ])
+    self.assertEqual(ns.foo, 'bar')
+
 
 class ArgparseWithAppRunTest(parameterized.TestCase):
 
diff --git a/absl/flags/tests/flags_test.py b/absl/flags/tests/flags_test.py
index 7cacbc8..8adbc94 100644
--- a/absl/flags/tests/flags_test.py
+++ b/absl/flags/tests/flags_test.py
@@ -302,7 +302,11 @@ class FlagsUnitTest(absltest.TestCase):
     flags.DEFINE_integer('l', 0x7fffffff00000000, 'how long to be')
     flags.DEFINE_list('args', 'v=1,"vmodule=a=0,b=2"', 'a list of arguments')
     flags.DEFINE_list('letters', 'a,b,c', 'a list of letters')
-    flags.DEFINE_list('numbers', [1, 2, 3], 'a list of numbers')
+    flags.DEFINE_list(
+        'list_default_list',
+        ['a', 'b', 'c'],
+        'with default being a list of strings',
+    )
     flags.DEFINE_enum('kwery', None, ['who', 'what', 'Why', 'where', 'when'],
                       '?')
     flags.DEFINE_enum(
@@ -346,7 +350,7 @@ class FlagsUnitTest(absltest.TestCase):
     self.assertEqual(FLAGS.l, 0x7fffffff00000000)
     self.assertEqual(FLAGS.args, ['v=1', 'vmodule=a=0,b=2'])
     self.assertEqual(FLAGS.letters, ['a', 'b', 'c'])
-    self.assertEqual(FLAGS.numbers, [1, 2, 3])
+    self.assertEqual(FLAGS.list_default_list, ['a', 'b', 'c'])
     self.assertIsNone(FLAGS.kwery)
     self.assertIsNone(FLAGS.sense)
     self.assertIsNone(FLAGS.cases)
@@ -364,7 +368,7 @@ class FlagsUnitTest(absltest.TestCase):
     self.assertEqual(flag_values['l'], 0x7fffffff00000000)
     self.assertEqual(flag_values['args'], ['v=1', 'vmodule=a=0,b=2'])
     self.assertEqual(flag_values['letters'], ['a', 'b', 'c'])
-    self.assertEqual(flag_values['numbers'], [1, 2, 3])
+    self.assertEqual(flag_values['list_default_list'], ['a', 'b', 'c'])
     self.assertIsNone(flag_values['kwery'])
     self.assertIsNone(flag_values['sense'])
     self.assertIsNone(flag_values['cases'])
@@ -382,7 +386,7 @@ class FlagsUnitTest(absltest.TestCase):
     self.assertEqual(FLAGS['l'].default_as_str, "'9223372032559808512'")
     self.assertEqual(FLAGS['args'].default_as_str, '\'v=1,"vmodule=a=0,b=2"\'')
     self.assertEqual(FLAGS['letters'].default_as_str, "'a,b,c'")
-    self.assertEqual(FLAGS['numbers'].default_as_str, "'1,2,3'")
+    self.assertEqual(FLAGS['list_default_list'].default_as_str, "'a,b,c'")
 
     # Verify that the iterator for flags yields all the keys
     keys = list(FLAGS)
@@ -424,7 +428,7 @@ class FlagsUnitTest(absltest.TestCase):
     self.assertIn('l', FLAGS)
     self.assertIn('args', FLAGS)
     self.assertIn('letters', FLAGS)
-    self.assertIn('numbers', FLAGS)
+    self.assertIn('list_default_list', FLAGS)
 
     # __contains__
     self.assertIn('name', FLAGS)
@@ -688,6 +692,13 @@ class FlagsUnitTest(absltest.TestCase):
         'flag --universe=copernicean: already defined as ptolemaic', FLAGS,
         argv)
 
+    # A flag value error shouldn't modify the value:
+    flags.DEFINE_integer('smol', 1, 'smol flag', upper_bound=5)
+    with self.assertRaises(flags.IllegalFlagValueError):
+      FLAGS.smol = 6
+    self.assertEqual(FLAGS.smol, 1)
+    self.assertTrue(FLAGS['smol'].using_default_value)
+
     # Test single-letter flags; should support both single and double dash
     argv = ('./program', '-q')
     argv = FLAGS(argv)
@@ -787,67 +798,71 @@ class FlagsUnitTest(absltest.TestCase):
     self.assertEqual(FLAGS.get_flag_value('repeat', None), 3)
     self.assertEqual(FLAGS.get_flag_value('name', None), 'giants')
     self.assertEqual(FLAGS.get_flag_value('debug', None), 0)
-    self.assertListEqual([
-        '--alsologtostderr',
-        "--args ['v=1', 'vmodule=a=0,b=2']",
-        '--blah None',
-        '--cases None',
-        '--decimal 666',
-        '--float 3.14',
-        '--funny None',
-        '--hexadecimal 1638',
-        '--kwery None',
-        '--l 9223372032559808512',
-        "--letters ['a', 'b', 'c']",
-        '--logger_levels {}',
-        "--m ['str1', 'str2']",
-        "--m_str ['str1', 'str2']",
-        '--name giants',
-        '--no?',
-        '--nodebug',
-        '--noexec',
-        '--nohelp',
-        '--nohelpfull',
-        '--nohelpshort',
-        '--nohelpxml',
-        '--nologtostderr',
-        '--noonly_check_args',
-        '--nopdb_post_mortem',
-        '--noq',
-        '--norun_with_pdb',
-        '--norun_with_profiling',
-        '--notest0',
-        '--notestget2',
-        '--notestget3',
-        '--notestnone',
-        '--numbers [1, 2, 3]',
-        '--octal 438',
-        '--only_once singlevalue',
-        '--pdb False',
-        '--profile_file None',
-        '--quack',
-        '--repeat 3',
-        "--s ['sing1']",
-        "--s_str ['sing1']",
-        '--sense None',
-        '--showprefixforinfo',
-        '--stderrthreshold fatal',
-        '--test1',
-        '--test_random_seed 301',
-        '--test_randomize_ordering_seed ',
-        '--testcomma_list []',
-        '--testget1',
-        '--testget4 None',
-        '--testspace_list []',
-        '--testspace_or_comma_list []',
-        '--tmod_baz_x',
-        '--universe ptolemaic',
-        '--use_cprofile_for_profiling',
-        '--v -1',
-        '--verbosity -1',
-        '--x 10',
-        '--xml_output_file ',
-    ], args_list())
+    self.assertListEqual(
+        [
+            '--alsologtostderr',
+            "--args ['v=1', 'vmodule=a=0,b=2']",
+            '--blah None',
+            '--cases None',
+            '--decimal 666',
+            '--float 3.14',
+            '--funny None',
+            '--hexadecimal 1638',
+            '--kwery None',
+            '--l 9223372032559808512',
+            "--letters ['a', 'b', 'c']",
+            "--list_default_list ['a', 'b', 'c']",
+            '--logger_levels {}',
+            "--m ['str1', 'str2']",
+            "--m_str ['str1', 'str2']",
+            '--name giants',
+            '--no?',
+            '--nodebug',
+            '--noexec',
+            '--nohelp',
+            '--nohelpfull',
+            '--nohelpshort',
+            '--nohelpxml',
+            '--nologtostderr',
+            '--noonly_check_args',
+            '--nopdb_post_mortem',
+            '--noq',
+            '--norun_with_pdb',
+            '--norun_with_profiling',
+            '--notest0',
+            '--notestget2',
+            '--notestget3',
+            '--notestnone',
+            '--octal 438',
+            '--only_once singlevalue',
+            '--pdb False',
+            '--profile_file None',
+            '--quack',
+            '--repeat 3',
+            "--s ['sing1']",
+            "--s_str ['sing1']",
+            '--sense None',
+            '--showprefixforinfo',
+            '--smol 1',
+            '--stderrthreshold fatal',
+            '--test1',
+            '--test_random_seed 301',
+            '--test_randomize_ordering_seed ',
+            '--testcomma_list []',
+            '--testget1',
+            '--testget4 None',
+            '--testspace_list []',
+            '--testspace_or_comma_list []',
+            '--tmod_baz_x',
+            '--universe ptolemaic',
+            '--use_cprofile_for_profiling',
+            '--v -1',
+            '--verbosity -1',
+            '--x 10',
+            '--xml_output_file ',
+        ],
+        args_list(),
+    )
 
     argv = ('./program', '--debug', '--m_str=upd1', '-s', 'upd2')
     FLAGS(argv)
@@ -857,67 +872,71 @@ class FlagsUnitTest(absltest.TestCase):
 
     # items appended to existing non-default value lists for --m/--m_str
     # new value overwrites default value (not appended to it) for --s/--s_str
-    self.assertListEqual([
-        '--alsologtostderr',
-        "--args ['v=1', 'vmodule=a=0,b=2']",
-        '--blah None',
-        '--cases None',
-        '--debug',
-        '--decimal 666',
-        '--float 3.14',
-        '--funny None',
-        '--hexadecimal 1638',
-        '--kwery None',
-        '--l 9223372032559808512',
-        "--letters ['a', 'b', 'c']",
-        '--logger_levels {}',
-        "--m ['str1', 'str2', 'upd1']",
-        "--m_str ['str1', 'str2', 'upd1']",
-        '--name giants',
-        '--no?',
-        '--noexec',
-        '--nohelp',
-        '--nohelpfull',
-        '--nohelpshort',
-        '--nohelpxml',
-        '--nologtostderr',
-        '--noonly_check_args',
-        '--nopdb_post_mortem',
-        '--noq',
-        '--norun_with_pdb',
-        '--norun_with_profiling',
-        '--notest0',
-        '--notestget2',
-        '--notestget3',
-        '--notestnone',
-        '--numbers [1, 2, 3]',
-        '--octal 438',
-        '--only_once singlevalue',
-        '--pdb False',
-        '--profile_file None',
-        '--quack',
-        '--repeat 3',
-        "--s ['sing1', 'upd2']",
-        "--s_str ['sing1', 'upd2']",
-        '--sense None',
-        '--showprefixforinfo',
-        '--stderrthreshold fatal',
-        '--test1',
-        '--test_random_seed 301',
-        '--test_randomize_ordering_seed ',
-        '--testcomma_list []',
-        '--testget1',
-        '--testget4 None',
-        '--testspace_list []',
-        '--testspace_or_comma_list []',
-        '--tmod_baz_x',
-        '--universe ptolemaic',
-        '--use_cprofile_for_profiling',
-        '--v -1',
-        '--verbosity -1',
-        '--x 10',
-        '--xml_output_file ',
-    ], args_list())
+    self.assertListEqual(
+        [
+            '--alsologtostderr',
+            "--args ['v=1', 'vmodule=a=0,b=2']",
+            '--blah None',
+            '--cases None',
+            '--debug',
+            '--decimal 666',
+            '--float 3.14',
+            '--funny None',
+            '--hexadecimal 1638',
+            '--kwery None',
+            '--l 9223372032559808512',
+            "--letters ['a', 'b', 'c']",
+            "--list_default_list ['a', 'b', 'c']",
+            '--logger_levels {}',
+            "--m ['str1', 'str2', 'upd1']",
+            "--m_str ['str1', 'str2', 'upd1']",
+            '--name giants',
+            '--no?',
+            '--noexec',
+            '--nohelp',
+            '--nohelpfull',
+            '--nohelpshort',
+            '--nohelpxml',
+            '--nologtostderr',
+            '--noonly_check_args',
+            '--nopdb_post_mortem',
+            '--noq',
+            '--norun_with_pdb',
+            '--norun_with_profiling',
+            '--notest0',
+            '--notestget2',
+            '--notestget3',
+            '--notestnone',
+            '--octal 438',
+            '--only_once singlevalue',
+            '--pdb False',
+            '--profile_file None',
+            '--quack',
+            '--repeat 3',
+            "--s ['sing1', 'upd2']",
+            "--s_str ['sing1', 'upd2']",
+            '--sense None',
+            '--showprefixforinfo',
+            '--smol 1',
+            '--stderrthreshold fatal',
+            '--test1',
+            '--test_random_seed 301',
+            '--test_randomize_ordering_seed ',
+            '--testcomma_list []',
+            '--testget1',
+            '--testget4 None',
+            '--testspace_list []',
+            '--testspace_or_comma_list []',
+            '--tmod_baz_x',
+            '--universe ptolemaic',
+            '--use_cprofile_for_profiling',
+            '--v -1',
+            '--verbosity -1',
+            '--x 10',
+            '--xml_output_file ',
+        ],
+        args_list(),
+    )
 
     ####################################
     # Test all kind of error conditions.
@@ -993,7 +1012,7 @@ class FlagsUnitTest(absltest.TestCase):
     # to be raised.
     try:
       sys.modules.pop('absl.flags.tests.module_baz')
-      import absl.flags.tests.module_baz
+      import absl.flags.tests.module_baz  # pylint: disable=g-import-not-at-top
       del absl
     except flags.DuplicateFlagError:
       raise AssertionError('Module reimport caused flag duplication error')
@@ -1236,6 +1255,9 @@ class FlagsUnitTest(absltest.TestCase):
   --letters: a list of letters
     (default: 'a,b,c')
     (a comma separated list)
+  --list_default_list: with default being a list of strings
+    (default: 'a,b,c')
+    (a comma separated list)
   -m,--m_str: string option that can occur multiple times;
     repeat this option to specify a list of values
     (default: "['def1', 'def2']")
@@ -1243,9 +1265,6 @@ class FlagsUnitTest(absltest.TestCase):
     (default: 'Bob')
   --[no]noexec: boolean flag with no as prefix
     (default: 'true')
-  --numbers: a list of numbers
-    (default: '1,2,3')
-    (a comma separated list)
   --octal: using octals
     (default: '438')
     (an integer)
@@ -1261,6 +1280,9 @@ class FlagsUnitTest(absltest.TestCase):
     repeat this option to specify a list of values
     (default: "['sing1']")
   --sense: <Case|case|CASE>: ?
+  --smol: smol flag
+    (default: '1')
+    (integer <= 5)
   --[no]test0: test boolean parsing
   --[no]test1: test boolean parsing
   --testcomma_list: test comma list parsing
@@ -1290,16 +1312,16 @@ class FlagsUnitTest(absltest.TestCase):
   def test_string_flag_with_wrong_type(self):
     fv = flags.FlagValues()
     with self.assertRaises(flags.IllegalFlagValueError):
-      flags.DEFINE_string('name', False, 'help', flag_values=fv)
+      flags.DEFINE_string('name', False, 'help', flag_values=fv)  # type: ignore
     with self.assertRaises(flags.IllegalFlagValueError):
-      flags.DEFINE_string('name2', 0, 'help', flag_values=fv)
+      flags.DEFINE_string('name2', 0, 'help', flag_values=fv)  # type: ignore
 
   def test_integer_flag_with_wrong_type(self):
     fv = flags.FlagValues()
     with self.assertRaises(flags.IllegalFlagValueError):
-      flags.DEFINE_integer('name', 1e2, 'help', flag_values=fv)
+      flags.DEFINE_integer('name', 1e2, 'help', flag_values=fv)  # type: ignore
     with self.assertRaises(flags.IllegalFlagValueError):
-      flags.DEFINE_integer('name', [], 'help', flag_values=fv)
+      flags.DEFINE_integer('name', [], 'help', flag_values=fv)  # type: ignore
     with self.assertRaises(flags.IllegalFlagValueError):
       flags.DEFINE_integer('name', False, 'help', flag_values=fv)
 
@@ -1313,6 +1335,16 @@ class FlagsUnitTest(absltest.TestCase):
     with self.assertRaises(ValueError):
       flags.DEFINE_enum('fruit', None, [], 'help', flag_values=fv)
 
+  def test_enum_flag_with_str_values(self):
+    fv = flags.FlagValues()
+    with self.assertRaises(ValueError):
+      flags.DEFINE_enum('fruit', None, 'option', 'help', flag_values=fv)  # type: ignore
+
+  def test_multi_enum_flag_with_str_values(self):
+    fv = flags.FlagValues()
+    with self.assertRaises(ValueError):
+      flags.DEFINE_multi_enum('fruit', None, 'option', 'help', flag_values=fv)  # type: ignore
+
   def test_define_enum_class_flag(self):
     fv = flags.FlagValues()
     flags.DEFINE_enum_class('fruit', None, Fruit, '?', flag_values=fv)
@@ -1351,13 +1383,14 @@ class FlagsUnitTest(absltest.TestCase):
   def test_enum_class_flag_with_wrong_default_value_type(self):
     fv = flags.FlagValues()
     with self.assertRaises(_exceptions.IllegalFlagValueError):
-      flags.DEFINE_enum_class('fruit', 1, Fruit, 'help', flag_values=fv)
+      flags.DEFINE_enum_class('fruit', 1, Fruit, 'help', flag_values=fv)  # type: ignore
 
   def test_enum_class_flag_requires_enum_class(self):
     fv = flags.FlagValues()
     with self.assertRaises(TypeError):
-      flags.DEFINE_enum_class(
-          'fruit', None, ['apple', 'orange'], 'help', flag_values=fv)
+      flags.DEFINE_enum_class(  # type: ignore
+          'fruit', None, ['apple', 'orange'], 'help', flag_values=fv
+      )
 
   def test_enum_class_flag_requires_non_empty_enum_class(self):
     fv = flags.FlagValues()
@@ -2491,7 +2524,7 @@ class NonGlobalFlagsTest(absltest.TestCase):
   def test_flag_definition_via_setitem(self):
     with self.assertRaises(flags.IllegalFlagValueError):
       flag_values = flags.FlagValues()
-      flag_values['flag_name'] = 'flag_value'
+      flag_values['flag_name'] = 'flag_value'  # type: ignore
 
 
 class SetDefaultTest(absltest.TestCase):
@@ -2545,7 +2578,7 @@ class SetDefaultTest(absltest.TestCase):
     self.flag_values.mark_as_parsed()
 
     with self.assertRaises(flags.IllegalFlagValueError):
-      flags.set_default(int_holder, 'a')
+      flags.set_default(int_holder, 'a')  # type: ignore
 
   def test_failure_on_type_protected_none_default(self):
     int_holder = flags.DEFINE_integer(
@@ -2553,12 +2586,120 @@ class SetDefaultTest(absltest.TestCase):
 
     self.flag_values.mark_as_parsed()
 
-    flags.set_default(int_holder, None)  # NOTE: should be a type failure
+    flags.set_default(int_holder, None)  # type: ignore
 
     with self.assertRaises(flags.IllegalFlagValueError):
       _ = int_holder.value  # Will also fail on later access.
 
 
+class OverrideValueTest(absltest.TestCase):
+
+  def setUp(self):
+    super().setUp()
+    self.flag_values = flags.FlagValues()
+
+  def test_success(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    flags.override_value(int_holder, 2)
+    self.flag_values.mark_as_parsed()
+
+    self.assertEqual(int_holder.value, 2)
+
+  def test_update_after_parse(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+    flags.override_value(int_holder, 2)
+
+    self.assertEqual(int_holder.value, 2)
+
+  def test_overrides_explicit_assignment(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+    self.flag_values.an_int = 3
+    flags.override_value(int_holder, 2)
+
+    self.assertEqual(int_holder.value, 2)
+
+  def test_overriden_by_explicit_assignment(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+    flags.override_value(int_holder, 2)
+    self.flag_values.an_int = 3
+
+    self.assertEqual(int_holder.value, 3)
+
+  def test_multi_flag(self):
+    multi_holder = flags.DEFINE_multi_string(
+        'strs', [], 'some strs', flag_values=self.flag_values
+    )
+
+    flags.override_value(multi_holder, ['a', 'b'])
+    self.flag_values.mark_as_parsed()
+
+    self.assertEqual(multi_holder.value, ['a', 'b'])
+
+  def test_failure_on_invalid_type(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+
+    with self.assertRaises(flags.IllegalFlagValueError):
+      flags.override_value(int_holder, 'a')  # pytype: disable=wrong-arg-types
+
+    self.assertEqual(int_holder.value, 1)
+
+  def test_failure_on_unparsed_value(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+
+    with self.assertRaises(flags.IllegalFlagValueError):
+      flags.override_value(int_holder, '2')  # pytype: disable=wrong-arg-types
+
+  def test_failure_on_parser_rejection(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values, upper_bound=5
+    )
+
+    self.flag_values.mark_as_parsed()
+
+    with self.assertRaises(flags.IllegalFlagValueError):
+      flags.override_value(int_holder, 6)
+
+    self.assertEqual(int_holder.value, 1)
+
+  def test_failure_on_validator_rejection(self):
+    int_holder = flags.DEFINE_integer(
+        'an_int', 1, 'an int', flag_values=self.flag_values
+    )
+    flags.register_validator(
+        int_holder.name, lambda x: x < 5, flag_values=self.flag_values
+    )
+
+    self.flag_values.mark_as_parsed()
+
+    with self.assertRaises(flags.IllegalFlagValueError):
+      flags.override_value(int_holder, 6)
+
+    self.assertEqual(int_holder.value, 1)
+
+
 class KeyFlagsTest(absltest.TestCase):
 
   def setUp(self):
diff --git a/absl/logging/BUILD b/absl/logging/BUILD
index 6c0d1bc..d1881f8 100644
--- a/absl/logging/BUILD
+++ b/absl/logging/BUILD
@@ -1,3 +1,9 @@
+load("@rules_python//python:py_library.bzl", "py_library")
+load("@rules_python//python:py_test.bzl", "py_test")
+load("@rules_python//python:py_binary.bzl", "py_binary")
+
+package(default_visibility = ["//visibility:private"])
+
 licenses(["notice"])
 
 py_library(
diff --git a/absl/logging/__init__.py b/absl/logging/__init__.py
index f4e7967..42166cd 100644
--- a/absl/logging/__init__.py
+++ b/absl/logging/__init__.py
@@ -88,7 +88,6 @@ import struct
 import sys
 import tempfile
 import threading
-import tempfile
 import time
 import timeit
 import traceback
@@ -98,11 +97,13 @@ import warnings
 from absl import flags
 from absl.logging import converter
 
+# pylint: disable=g-import-not-at-top
 try:
   from typing import NoReturn
 except ImportError:
   pass
 
+# pylint: enable=g-import-not-at-top
 
 FLAGS = flags.FLAGS
 
@@ -295,44 +296,76 @@ class _StderrthresholdFlag(flags.Flag):
     self._value = v
 
 
-flags.DEFINE_boolean('logtostderr',
-                     False,
-                     'Should only log to stderr?', allow_override_cpp=True)
-flags.DEFINE_boolean('alsologtostderr',
-                     False,
-                     'also log to stderr?', allow_override_cpp=True)
-flags.DEFINE_string('log_dir',
-                    os.getenv('TEST_TMPDIR', ''),
-                    'directory to write logfiles into',
-                    allow_override_cpp=True)
-flags.DEFINE_flag(_VerbosityFlag(
-    'verbosity', -1,
-    'Logging verbosity level. Messages logged at this level or lower will '
-    'be included. Set to 1 for debug logging. If the flag was not set or '
-    'supplied, the value will be changed from the default of -1 (warning) to '
-    '0 (info) after flags are parsed.',
-    short_name='v', allow_hide_cpp=True))
-flags.DEFINE_flag(
+LOGTOSTDERR = flags.DEFINE_boolean(
+    'logtostderr',
+    False,
+    'Should only log to stderr?',
+    allow_override_cpp=True,
+)
+ALSOLOGTOSTDERR = flags.DEFINE_boolean(
+    'alsologtostderr',
+    False,
+    'also log to stderr?',
+    allow_override_cpp=True,
+)
+LOG_DIR = flags.DEFINE_string(
+    'log_dir',
+    os.getenv('TEST_TMPDIR', ''),
+    'directory to write logfiles into',
+    allow_override_cpp=True,
+)
+VERBOSITY = flags.DEFINE_flag(
+    _VerbosityFlag(
+        'verbosity',
+        -1,
+        (
+            'Logging verbosity level. Messages logged at this level or lower'
+            ' will be included. Set to 1 for debug logging. If the flag was not'
+            ' set or supplied, the value will be changed from the default of -1'
+            ' (warning) to 0 (info) after flags are parsed.'
+        ),
+        short_name='v',
+        allow_hide_cpp=True,
+    )
+)
+LOGGER_LEVELS = flags.DEFINE_flag(
     _LoggerLevelsFlag(
-        'logger_levels', {},
-        'Specify log level of loggers. The format is a CSV list of '
-        '`name:level`. Where `name` is the logger name used with '
-        '`logging.getLogger()`, and `level` is a level name  (INFO, DEBUG, '
-        'etc). e.g. `myapp.foo:INFO,other.logger:DEBUG`'))
-flags.DEFINE_flag(_StderrthresholdFlag(
-    'stderrthreshold', 'fatal',
-    'log messages at this level, or more severe, to stderr in '
-    'addition to the logfile.  Possible values are '
-    "'debug', 'info', 'warning', 'error', and 'fatal'.  "
-    'Obsoletes --alsologtostderr. Using --alsologtostderr '
-    'cancels the effect of this flag. Please also note that '
-    'this flag is subject to --verbosity and requires logfile '
-    'not be stderr.', allow_hide_cpp=True))
-flags.DEFINE_boolean('showprefixforinfo', True,
-                     'If False, do not prepend prefix to info messages '
-                     'when it\'s logged to stderr, '
-                     '--verbosity is set to INFO level, '
-                     'and python logging is used.')
+        'logger_levels',
+        {},
+        (
+            'Specify log level of loggers. The format is a CSV list of '
+            '`name:level`. Where `name` is the logger name used with '
+            '`logging.getLogger()`, and `level` is a level name  (INFO, DEBUG, '
+            'etc). e.g. `myapp.foo:INFO,other.logger:DEBUG`'
+        ),
+    )
+)
+STDERRTHRESHOLD = flags.DEFINE_flag(
+    _StderrthresholdFlag(
+        'stderrthreshold',
+        'fatal',
+        (
+            'log messages at this level, or more severe, to stderr in '
+            'addition to the logfile.  Possible values are '
+            "'debug', 'info', 'warning', 'error', and 'fatal'.  "
+            'Obsoletes --alsologtostderr. Using --alsologtostderr '
+            'cancels the effect of this flag. Please also note that '
+            'this flag is subject to --verbosity and requires logfile '
+            'not be stderr.'
+        ),
+        allow_hide_cpp=True,
+    )
+)
+SHOWPREFIXFORINFO = flags.DEFINE_boolean(
+    'showprefixforinfo',
+    True,
+    (
+        'If False, do not prepend prefix to info messages '
+        "when it's logged to stderr, "
+        '--verbosity is set to INFO level, '
+        'and python logging is used.'
+    ),
+)
 
 
 def get_verbosity():
@@ -414,9 +447,9 @@ def debug(msg, *args, **kwargs):
   log(DEBUG, msg, *args, **kwargs)
 
 
-def exception(msg, *args, **kwargs):
+def exception(msg, *args, exc_info=True, **kwargs):
   """Logs an exception, with traceback and message."""
-  error(msg, *args, **kwargs, exc_info=True)
+  error(msg, *args, exc_info=exc_info, **kwargs)
 
 
 # Counter to keep track of number of log entries per token.
@@ -862,7 +895,8 @@ class PythonHandler(logging.StreamHandler):
     """Flushes all log files."""
     self.acquire()
     try:
-      self.stream.flush()
+      if self.stream and hasattr(self.stream, 'flush'):
+        self.stream.flush()
     except (EnvironmentError, ValueError):
       # A ValueError is thrown if we try to flush a closed file.
       pass
@@ -1178,11 +1212,13 @@ def _get_thread_id():
 
 def get_absl_logger():
   """Returns the absl logger instance."""
+  assert _absl_logger is not None
   return _absl_logger
 
 
 def get_absl_handler():
   """Returns the absl handler instance."""
+  assert _absl_handler is not None
   return _absl_handler
 
 
diff --git a/absl/logging/__init__.pyi b/absl/logging/__init__.pyi
new file mode 100644
index 0000000..5d5bb69
--- /dev/null
+++ b/absl/logging/__init__.pyi
@@ -0,0 +1,290 @@
+# Copyright 2017 The Abseil Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import logging
+from typing import Any, Callable, Dict, NoReturn, Optional, Tuple, TypeVar, Union
+
+from absl import flags
+
+# Logging levels.
+FATAL: int
+ERROR: int
+WARNING: int
+WARN: int  # Deprecated name.
+INFO: int
+DEBUG: int
+
+ABSL_LOGGING_PREFIX_REGEX: str
+
+LOGTOSTDERR: flags.FlagHolder[bool]
+ALSOLOGTOSTDERR: flags.FlagHolder[bool]
+LOG_DIR: flags.FlagHolder[str]
+VERBOSITY: flags.FlagHolder[int]
+LOGGER_LEVELS: flags.FlagHolder[Dict[str, str]]
+STDERRTHRESHOLD: flags.FlagHolder[str]
+SHOWPREFIXFORINFO: flags.FlagHolder[bool]
+
+
+def get_verbosity() -> int:
+  ...
+
+
+def set_verbosity(v: Union[int, str]) -> None:
+  ...
+
+
+def set_stderrthreshold(s: Union[int, str]) -> None:
+  ...
+
+
+# TODO(b/277607978): Provide actual args+kwargs shadowing stdlib's logging functions.
+def fatal(msg: Any, *args: Any, **kwargs: Any) -> NoReturn:
+  ...
+
+
+def error(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def warning(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def warn(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def info(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def debug(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def exception(msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def log_every_n(level: int, msg: Any, n: int, *args: Any) -> None:
+  ...
+
+
+def log_every_n_seconds(
+    level: int, msg: Any, n_seconds: float, *args: Any
+) -> None:
+  ...
+
+
+def log_first_n(level: int, msg: Any, n: int, *args: Any) -> None:
+  ...
+
+
+def log_if(level: int, msg: Any, condition: Any, *args: Any) -> None:
+  ...
+
+
+def log(level: int, msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def vlog(level: int, msg: Any, *args: Any, **kwargs: Any) -> None:
+  ...
+
+
+def vlog_is_on(level: int) -> bool:
+  ...
+
+
+def flush() -> None:
+  ...
+
+
+def level_debug() -> bool:
+  ...
+
+
+def level_info() -> bool:
+  ...
+
+
+def level_warning() -> bool:
+  ...
+
+
+level_warn = level_warning  # Deprecated function.
+
+
+def level_error() -> bool:
+  ...
+
+
+def get_log_file_name(level: int = ...) -> str:
+  ...
+
+
+def find_log_dir_and_names(
+    program_name: Optional[str] = ..., log_dir: Optional[str] = ...
+) -> Tuple[str, str, str]:
+  ...
+
+
+def find_log_dir(log_dir: Optional[str] = ...) -> str:
+  ...
+
+
+def get_absl_log_prefix(record: logging.LogRecord) -> str:
+  ...
+
+
+_SkipLogT = TypeVar('_SkipLogT', str, Callable[..., Any])
+
+def skip_log_prefix(func: _SkipLogT) -> _SkipLogT:
+  ...
+
+
+_StreamT = TypeVar("_StreamT")
+
+
+class PythonHandler(logging.StreamHandler[_StreamT]):
+
+  def __init__(
+      self,
+      stream: Optional[_StreamT] = ...,
+      formatter: Optional[logging.Formatter] = ...,
+  ) -> None:
+    ...
+
+  def start_logging_to_file(
+      self, program_name: Optional[str] = ..., log_dir: Optional[str] = ...
+  ) -> None:
+    ...
+
+  def use_absl_log_file(
+      self, program_name: Optional[str] = ..., log_dir: Optional[str] = ...
+  ) -> None:
+    ...
+
+  def flush(self) -> None:
+    ...
+
+  def emit(self, record: logging.LogRecord) -> None:
+    ...
+
+  def close(self) -> None:
+    ...
+
+
+class ABSLHandler(logging.Handler):
+
+  def __init__(self, python_logging_formatter: PythonFormatter) -> None:
+    ...
+
+  def format(self, record: logging.LogRecord) -> str:
+    ...
+
+  def setFormatter(self, fmt) -> None:
+    ...
+
+  def emit(self, record: logging.LogRecord) -> None:
+    ...
+
+  def flush(self) -> None:
+    ...
+
+  def close(self) -> None:
+    ...
+
+  def handle(self, record: logging.LogRecord) -> bool:
+    ...
+
+  @property
+  def python_handler(self) -> PythonHandler:
+    ...
+
+  def activate_python_handler(self) -> None:
+    ...
+
+  def use_absl_log_file(
+      self, program_name: Optional[str] = ..., log_dir: Optional[str] = ...
+  ) -> None:
+    ...
+
+  def start_logging_to_file(self, program_name=None, log_dir=None) -> None:
+    ...
+
+
+class PythonFormatter(logging.Formatter):
+
+  def format(self, record: logging.LogRecord) -> str:
+    ...
+
+
+class ABSLLogger(logging.Logger):
+
+  def findCaller(
+      self, stack_info: bool = ..., stacklevel: int = ...
+  ) -> Tuple[str, int, str, Optional[str]]:
+    ...
+
+  def critical(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def fatal(self, msg: Any, *args: Any, **kwargs: Any) -> NoReturn:
+    ...
+
+  def error(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def warn(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def warning(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def info(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def debug(self, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def log(self, level: int, msg: Any, *args: Any, **kwargs: Any) -> None:
+    ...
+
+  def handle(self, record: logging.LogRecord) -> None:
+    ...
+
+  @classmethod
+  def register_frame_to_skip(
+      cls, file_name: str, function_name: str, line_number: Optional[int] = ...
+  ) -> None:
+    ...
+
+
+# NOTE: Returns None before _initialize called but shouldn't occur after import.
+def get_absl_logger() -> ABSLLogger:
+  ...
+
+
+# NOTE: Returns None before _initialize called but shouldn't occur after import.
+def get_absl_handler() -> ABSLHandler:
+  ...
+
+
+def use_python_logging(quiet: bool = ...) -> None:
+  ...
+
+
+def use_absl_handler() -> None:
+  ...
diff --git a/absl/logging/tests/logging_test.py b/absl/logging/tests/logging_test.py
index 1c337f9..0faed07 100644
--- a/absl/logging/tests/logging_test.py
+++ b/absl/logging/tests/logging_test.py
@@ -213,6 +213,21 @@ class PythonHandlerTest(absltest.TestCase):
     with self.assertRaises(AssertionError):
       handler.flush()
 
+  def test_ignore_flush_if_stream_is_none(self):
+    # Happens if creating a Windows executable without console.
+    with mock.patch.object(sys, 'stderr', new=None):
+      handler = logging.PythonHandler(None)
+      # Test that this does not fail.
+      handler.flush()
+
+  def test_ignore_flush_if_stream_does_not_support_flushing(self):
+    class BadStream:
+      pass
+
+    handler = logging.PythonHandler(BadStream())
+    # Test that this does not fail.
+    handler.flush()
+
   def test_log_to_std_err(self):
     record = std_logging.LogRecord(
         'name', std_logging.INFO, 'path', 12, 'logging_msg', [], False)
@@ -804,6 +819,11 @@ class LoggingTest(absltest.TestCase):
     # Just verify that this doesn't raise a TypeError.
     logging.exception('%(test)s', {'test': 'Hello world!'})
 
+  def test_exception_with_exc_info(self):
+    # Just verify that this doesn't raise a KeyeError.
+    logging.exception('exc_info=True', exc_info=True)
+    logging.exception('exc_info=False', exc_info=False)
+
   def test_logging_levels(self):
     old_level = logging.get_verbosity()
 
diff --git a/absl/logging/tests/verbosity_flag_test.py b/absl/logging/tests/verbosity_flag_test.py
index ea9944d..44a6034 100644
--- a/absl/logging/tests/verbosity_flag_test.py
+++ b/absl/logging/tests/verbosity_flag_test.py
@@ -27,9 +27,11 @@ assert logging.root.getEffectiveLevel() == logging.ERROR, (
     'logging.root level should be changed to ERROR, but found {}'.format(
         logging.root.getEffectiveLevel()))
 
+# pylint: disable=g-import-not-at-top
 from absl import flags
 from absl import logging as _  # pylint: disable=unused-import
 from absl.testing import absltest
+# pylint: enable=g-import-not-at-top
 
 FLAGS = flags.FLAGS
 
diff --git a/absl/testing/BUILD b/absl/testing/BUILD
index 3173c4b..b9e4790 100644
--- a/absl/testing/BUILD
+++ b/absl/testing/BUILD
@@ -1,3 +1,9 @@
+load("@rules_python//python:py_library.bzl", "py_library")
+load("@rules_python//python:py_test.bzl", "py_test")
+load("@rules_python//python:py_binary.bzl", "py_binary")
+
+package(default_visibility = ["//visibility:private"])
+
 licenses(["notice"])
 
 py_library(
@@ -157,12 +163,16 @@ py_test(
     name = "tests/absltest_sharding_test",
     size = "small",
     srcs = ["tests/absltest_sharding_test.py"],
-    data = [":tests/absltest_sharding_test_helper"],
+    data = [
+        ":tests/absltest_sharding_test_helper",
+        ":tests/absltest_sharding_test_helper_no_tests",
+    ],
     python_version = "PY3",
     srcs_version = "PY3",
     deps = [
         ":_bazelize_command",
         ":absltest",
+        ":parameterized",
         ":tests/absltest_env",
     ],
 )
@@ -176,11 +186,21 @@ py_binary(
     deps = [":absltest"],
 )
 
+py_binary(
+    name = "tests/absltest_sharding_test_helper_no_tests",
+    testonly = 1,
+    srcs = ["tests/absltest_sharding_test_helper_no_tests.py"],
+    deps = [":absltest"],
+)
+
 py_test(
     name = "tests/absltest_test",
     size = "small",
     srcs = ["tests/absltest_test.py"],
-    data = [":tests/absltest_test_helper"],
+    data = [
+        ":tests/absltest_test_helper",
+        ":tests/absltest_test_helper_skipped",
+    ],
     python_version = "PY3",
     srcs_version = "PY3",
     deps = [
@@ -204,6 +224,13 @@ py_binary(
     ],
 )
 
+py_binary(
+    name = "tests/absltest_test_helper_skipped",
+    testonly = 1,
+    srcs = ["tests/absltest_test_helper_skipped.py"],
+    deps = [":absltest"],
+)
+
 py_test(
     name = "tests/flagsaver_test",
     srcs = ["tests/flagsaver_test.py"],
diff --git a/absl/testing/absltest.py b/absl/testing/absltest.py
index 1bbcee7..e43cb82 100644
--- a/absl/testing/absltest.py
+++ b/absl/testing/absltest.py
@@ -20,9 +20,11 @@ tests.
 
 from collections import abc
 import contextlib
+import dataclasses
 import difflib
 import enum
 import errno
+import faulthandler
 import getpass
 import inspect
 import io
@@ -39,47 +41,31 @@ import subprocess
 import sys
 import tempfile
 import textwrap
+import typing
+from typing import Any, AnyStr, BinaryIO, Callable, ContextManager, IO, Iterator, List, Mapping, MutableMapping, MutableSequence, NoReturn, Optional, Sequence, Text, TextIO, Tuple, Type, Union
 import unittest
 from unittest import mock  # pylint: disable=unused-import Allow absltest.mock.
 from urllib import parse
 
-try:
-  # The faulthandler module isn't always available, and pytype doesn't
-  # understand that we're catching ImportError, so suppress the error.
-  # pytype: disable=import-error
-  import faulthandler
-  # pytype: enable=import-error
-except ImportError:
-  # We use faulthandler if it is available.
-  faulthandler = None
-
-from absl import app
+from absl import app  # pylint: disable=g-import-not-at-top
 from absl import flags
 from absl import logging
 from absl.testing import _pretty_print_reporter
 from absl.testing import xml_reporter
 
-# Make typing an optional import to avoid it being a required dependency
-# in Python 2. Type checkers will still understand the imports.
-try:
-  # pylint: disable=unused-import
-  import typing
-  from typing import Any, AnyStr, BinaryIO, Callable, ContextManager, IO, Iterator, List, Mapping, MutableMapping, MutableSequence, Optional, Sequence, Text, TextIO, Tuple, Type, Union
-  # pylint: enable=unused-import
-except ImportError:
-  pass
-else:
-  # Use an if-type-checking block to prevent leakage of type-checking only
-  # symbols. We don't want people relying on these at runtime.
-  if typing.TYPE_CHECKING:
-    # Unbounded TypeVar for general usage
-    _T = typing.TypeVar('_T')
+# Use an if-type-checking block to prevent leakage of type-checking only
+# symbols. We don't want people relying on these at runtime.
+if typing.TYPE_CHECKING:
+  # Unbounded TypeVar for general usage
+  _T = typing.TypeVar('_T')
 
-    import unittest.case
-    _OutcomeType = unittest.case._Outcome  # pytype: disable=module-attr
+  import unittest.case  # pylint: disable=g-import-not-at-top,g-bad-import-order
 
+  _OutcomeType = unittest.case._Outcome  # pytype: disable=module-attr
 
 
+# pylint: enable=g-import-not-at-top
+
 # Re-export a bunch of unittest functions we support so that people don't
 # have to import unittest to get them
 # pylint: disable=invalid-name
@@ -593,8 +579,9 @@ class TestCase(unittest.TestCase):
   longMessage = True
 
   # Exit stacks for per-test and per-class scopes.
-  _exit_stack = None
-  _cls_exit_stack = None
+  if sys.version_info < (3, 11):
+    _exit_stack = None
+    _cls_exit_stack = None
 
   def __init__(self, *args, **kwargs):
     super(TestCase, self).__init__(*args, **kwargs)
@@ -603,17 +590,22 @@ class TestCase(unittest.TestCase):
 
   def setUp(self):
     super(TestCase, self).setUp()
-    # NOTE: Only Python 3 contextlib has ExitStack
-    if hasattr(contextlib, 'ExitStack'):
+    # NOTE: Only Python 3 contextlib has ExitStack and
+    # Python 3.11+ already has enterContext.
+    if hasattr(contextlib, 'ExitStack') and sys.version_info < (3, 11):
       self._exit_stack = contextlib.ExitStack()
       self.addCleanup(self._exit_stack.close)
 
   @classmethod
   def setUpClass(cls):
     super(TestCase, cls).setUpClass()
-    # NOTE: Only Python 3 contextlib has ExitStack and only Python 3.8+ has
-    # addClassCleanup.
-    if hasattr(contextlib, 'ExitStack') and hasattr(cls, 'addClassCleanup'):
+    # NOTE: Only Python 3 contextlib has ExitStack, only Python 3.8+ has
+    # addClassCleanup and Python 3.11+ already has enterClassContext.
+    if (
+        hasattr(contextlib, 'ExitStack')
+        and hasattr(cls, 'addClassCleanup')
+        and sys.version_info < (3, 11)
+    ):
       cls._cls_exit_stack = contextlib.ExitStack()
       cls.addClassCleanup(cls._cls_exit_stack.close)
 
@@ -752,6 +744,9 @@ class TestCase(unittest.TestCase):
     Args:
       manager: The context manager to enter.
     """
+    if sys.version_info >= (3, 11):
+      return self.enterContext(manager)
+
     if not self._exit_stack:
       raise AssertionError(
           'self._exit_stack is not set: enter_context is Py3-only; also make '
@@ -761,6 +756,9 @@ class TestCase(unittest.TestCase):
   @enter_context.classmethod
   def enter_context(cls, manager):  # pylint: disable=no-self-argument
     # type: (ContextManager[_T]) -> _T
+    if sys.version_info >= (3, 11):
+      return cls.enterClassContext(manager)
+
     if not cls._cls_exit_stack:
       raise AssertionError(
           'cls._cls_exit_stack is not set: cls.enter_context requires '
@@ -803,6 +801,7 @@ class TestCase(unittest.TestCase):
   ) -> None:
     """Adds `function` as cleanup when the test case succeeds."""
     outcome = self._outcome
+    assert outcome is not None
     previous_failure_count = (
         len(outcome.result.failures)
         + len(outcome.result.errors)
@@ -822,6 +821,7 @@ class TestCase(unittest.TestCase):
     """Returns whether test is passed. Expected to be called during cleanup."""
     outcome = self._outcome
     if sys.version_info[:2] >= (3, 11):
+      assert outcome is not None
       current_failure_count = (
           len(outcome.result.failures)
           + len(outcome.result.errors)
@@ -930,6 +930,12 @@ class TestCase(unittest.TestCase):
       prefix = [prefix]
       prefix_len = 1
 
+    if isinstance(whole, abc.Mapping) or isinstance(whole, abc.Set):
+      self.fail(
+          'For whole: Mapping or Set objects are not supported, found type: %s'
+          % type(whole),
+          msg,
+      )
     try:
       whole_len = len(whole)
     except (TypeError, NotImplementedError):
@@ -1725,6 +1731,66 @@ class TestCase(unittest.TestCase):
 
     raise self.failureException('\n'.join(message))
 
+  def assertDataclassEqual(self, first, second, msg=None):
+    """Asserts two dataclasses are equal with more informative errors.
+
+    Arguments must both be dataclasses. This compares equality of  individual
+    fields and takes care to not compare fields that are marked as
+    non-comparable. It gives per field differences, which are easier to parse
+    than the comparison of the string representations from assertEqual.
+
+    In cases where the dataclass has a custom __eq__, and it is defined in a
+    way that is inconsistent with equality of comparable fields, we raise an
+    exception without further trying to figure out how they are different.
+
+    Args:
+      first: A dataclass, the first value.
+      second: A dataclass, the second value.
+      msg: An optional str, the associated message.
+
+    Raises:
+      AssertionError: if the dataclasses are not equal.
+    """
+
+    if not dataclasses.is_dataclass(first) or isinstance(first, type):
+      raise self.failureException('First argument is not a dataclass instance.')
+    if not dataclasses.is_dataclass(second) or isinstance(second, type):
+      raise self.failureException(
+          'Second argument is not a dataclass instance.'
+      )
+
+    if first == second:
+      return
+
+    if type(first) is not type(second):
+      self.fail(
+          'Found different dataclass types: %s != %s'
+          % (type(first), type(second)),
+          msg,
+      )
+
+    # Make sure to skip fields that are marked compare=False.
+    different = [
+        (f.name, getattr(first, f.name), getattr(second, f.name))
+        for f in dataclasses.fields(first)
+        if f.compare and getattr(first, f.name) != getattr(second, f.name)
+    ]
+
+    safe_repr = unittest.util.safe_repr  # pytype: disable=module-attr
+    message = ['%s != %s' % (safe_repr(first), safe_repr(second))]
+    if different:
+      message.append('Fields that differ:')
+      message.extend(
+          '%s: %s != %s' % (k, safe_repr(first_v), safe_repr(second_v))
+          for k, first_v, second_v in different
+      )
+    else:
+      message.append(
+          'Cannot detect difference by examining the fields of the dataclass.'
+      )
+
+    raise self.fail('\n'.join(message), msg)
+
   def assertUrlEqual(self, a, b, msg=None):
     """Asserts that urls are equal, ignoring ordering of query params."""
     parsed_a = parse.urlparse(a)
@@ -1765,7 +1831,8 @@ class TestCase(unittest.TestCase):
     # rather than just stopping at the first
     problems = []
 
-    _walk_structure_for_problems(a, b, aname, bname, problems)
+    _walk_structure_for_problems(a, b, aname, bname, problems,
+                                 self.assertEqual, self.failureException)
 
     # Avoid spamming the user toooo much
     if self.maxDiff is not None:
@@ -1818,9 +1885,9 @@ class TestCase(unittest.TestCase):
 
     return super(TestCase, self)._getAssertEqualityFunc(first, second)
 
-  def fail(self, msg=None, prefix=None):
-    """Fail immediately with the given message, optionally prefixed."""
-    return super(TestCase, self).fail(self._formatMessage(prefix, msg))
+  def fail(self, msg=None, user_msg=None) -> NoReturn:
+    """Fail immediately with the given standard message and user message."""
+    return super(TestCase, self).fail(self._formatMessage(user_msg, msg))
 
 
 def _sorted_list_difference(expected, actual):
@@ -1896,7 +1963,9 @@ def _are_both_of_mapping_type(a, b):
       b, abc.Mapping)
 
 
-def _walk_structure_for_problems(a, b, aname, bname, problem_list):
+def _walk_structure_for_problems(
+    a, b, aname, bname, problem_list, leaf_assert_equal_func, failure_exception
+):
   """The recursive comparison behind assertSameStructure."""
   if type(a) != type(b) and not (  # pylint: disable=unidiomatic-typecheck
       _are_both_of_integer_type(a, b) or _are_both_of_sequence_type(a, b) or
@@ -1924,7 +1993,7 @@ def _walk_structure_for_problems(a, b, aname, bname, problem_list):
       if k in b:
         _walk_structure_for_problems(
             a[k], b[k], '%s[%r]' % (aname, k), '%s[%r]' % (bname, k),
-            problem_list)
+            problem_list, leaf_assert_equal_func, failure_exception)
       else:
         problem_list.append(
             "%s has [%r] with value %r but it's missing in %s" %
@@ -1942,7 +2011,7 @@ def _walk_structure_for_problems(a, b, aname, bname, problem_list):
     for i in range(minlen):
       _walk_structure_for_problems(
           a[i], b[i], '%s[%d]' % (aname, i), '%s[%d]' % (bname, i),
-          problem_list)
+          problem_list, leaf_assert_equal_func, failure_exception)
     for i in range(minlen, len(a)):
       problem_list.append('%s has [%i] with value %r but %s does not' %
                           (aname, i, a[i], bname))
@@ -1951,7 +2020,9 @@ def _walk_structure_for_problems(a, b, aname, bname, problem_list):
                           (aname, i, bname, b[i]))
 
   else:
-    if a != b:
+    try:
+      leaf_assert_equal_func(a, b)
+    except failure_exception:
       problem_list.append('%s is %r but %s is %r' % (aname, a, bname, b))
 
 
@@ -2074,7 +2145,7 @@ def _is_in_app_main():
 def _register_sigterm_with_faulthandler():
   # type: () -> None
   """Have faulthandler dump stacks on SIGTERM.  Useful to diagnose timeouts."""
-  if faulthandler and getattr(faulthandler, 'register', None):
+  if getattr(faulthandler, 'register', None):
     # faulthandler.register is not available on Windows.
     # faulthandler.enable() is already called by app.run.
     try:
@@ -2284,7 +2355,7 @@ class TestLoader(unittest.TestLoader):
     for name in dir(testCaseClass):
       if _is_suspicious_attribute(testCaseClass, name):
         raise TypeError(TestLoader._ERROR_MSG % name)
-    names = super(TestLoader, self).getTestCaseNames(testCaseClass)
+    names = list(super(TestLoader, self).getTestCaseNames(testCaseClass))
     if self._randomize_ordering_seed is not None:
       logging.info(
           'Randomizing test order with seed: %d', self._randomize_ordering_seed)
@@ -2307,8 +2378,7 @@ def get_default_xml_output_filename():
         os.path.splitext(os.path.basename(sys.argv[0]))[0] + '.xml')
 
 
-def _setup_filtering(argv):
-  # type: (MutableSequence[Text]) -> None
+def _setup_filtering(argv: MutableSequence[str]) -> bool:
   """Implements the bazel test filtering protocol.
 
   The following environment variable is used in this method:
@@ -2323,16 +2393,20 @@ def _setup_filtering(argv):
 
   Args:
     argv: the argv to mutate in-place.
+
+  Returns:
+    Whether test filtering is requested.
   """
   test_filter = os.environ.get('TESTBRIDGE_TEST_ONLY')
   if argv is None or not test_filter:
-    return
+    return False
 
   filters = shlex.split(test_filter)
   if sys.version_info[:2] >= (3, 7):
     filters = ['-k=' + test_filter for test_filter in filters]
 
   argv[1:1] = filters
+  return True
 
 
 def _setup_test_runner_fail_fast(argv):
@@ -2359,8 +2433,9 @@ def _setup_test_runner_fail_fast(argv):
   argv[1:1] = ['--failfast']
 
 
-def _setup_sharding(custom_loader=None):
-  # type: (Optional[unittest.TestLoader]) -> unittest.TestLoader
+def _setup_sharding(
+    custom_loader: Optional[unittest.TestLoader] = None,
+) -> Tuple[unittest.TestLoader, Optional[int]]:
   """Implements the bazel sharding protocol.
 
   The following environment variables are used in this method:
@@ -2379,8 +2454,10 @@ def _setup_sharding(custom_loader=None):
     custom_loader: A TestLoader to be made sharded.
 
   Returns:
-    The test loader for shard-filtering or the standard test loader, depending
-    on the sharding environment variables.
+    A tuple of ``(test_loader, shard_index)``. ``test_loader`` is for
+    shard-filtering or the standard test loader depending on the sharding
+    environment variables. ``shard_index`` is the shard index, or ``None`` when
+    sharding is not used.
   """
 
   # It may be useful to write the shard file even if the other sharding
@@ -2398,7 +2475,7 @@ def _setup_sharding(custom_loader=None):
   base_loader = custom_loader or TestLoader()
   if 'TEST_TOTAL_SHARDS' not in os.environ:
     # Not using sharding, use the expected test loader.
-    return base_loader
+    return base_loader, None
 
   total_shards = int(os.environ['TEST_TOTAL_SHARDS'])
   shard_index = int(os.environ['TEST_SHARD_INDEX'])
@@ -2427,25 +2504,70 @@ def _setup_sharding(custom_loader=None):
     return [x for x in ordered_names if x in filtered_names]
 
   base_loader.getTestCaseNames = getShardedTestCaseNames
-  return base_loader
+  return base_loader, shard_index
 
 
-# pylint: disable=line-too-long
-def _run_and_get_tests_result(argv, args, kwargs, xml_test_runner_class):
-  # type: (MutableSequence[Text], Sequence[Any], MutableMapping[Text, Any], Type) -> unittest.TestResult
-  # pylint: enable=line-too-long
-  """Same as run_tests, except it returns the result instead of exiting."""
+def _run_and_get_tests_result(
+    argv: MutableSequence[str],
+    args: Sequence[Any],
+    kwargs: MutableMapping[str, Any],
+    xml_test_runner_class: Type[unittest.TextTestRunner],
+) -> Tuple[unittest.TestResult, bool]:
+  """Same as run_tests, but it doesn't exit.
+
+  Args:
+    argv: sys.argv with the command-line flags removed from the front, i.e. the
+      argv with which :func:`app.run()<absl.app.run>` has called
+      ``__main__.main``. It is passed to
+      ``unittest.TestProgram.__init__(argv=)``, which does its own flag parsing.
+      It is ignored if kwargs contains an argv entry.
+    args: Positional arguments passed through to
+      ``unittest.TestProgram.__init__``.
+    kwargs: Keyword arguments passed through to
+      ``unittest.TestProgram.__init__``.
+    xml_test_runner_class: The type of the test runner class.
+
+  Returns:
+    A tuple of ``(test_result, fail_when_no_tests_ran)``.
+    ``fail_when_no_tests_ran`` indicates whether the test should fail when
+    no tests ran.
+  """
 
   # The entry from kwargs overrides argv.
   argv = kwargs.pop('argv', argv)
 
+  if sys.version_info[:2] >= (3, 12):
+    # Python 3.12 unittest changed the behavior from PASS to FAIL in
+    # https://github.com/python/cpython/pull/102051. absltest follows this.
+    fail_when_no_tests_ran = True
+  else:
+    # Historically, absltest and unittest before Python 3.12 passes if no tests
+    # ran.
+    fail_when_no_tests_ran = False
+
   # Set up test filtering if requested in environment.
-  _setup_filtering(argv)
+  if _setup_filtering(argv):
+    # When test filtering is requested, ideally we also want to fail when no
+    # tests ran. However, the test filters are usually done when running bazel.
+    # When you run multiple targets, e.g. `bazel test //my_dir/...
+    # --test_filter=MyTest`, you don't necessarily want individual tests to fail
+    # because no tests match in that particular target.
+    # Due to this use case, we don't fail when test filtering is requested via
+    # the environment variable from bazel.
+    fail_when_no_tests_ran = False
+
   # Set up --failfast as requested in environment
   _setup_test_runner_fail_fast(argv)
 
   # Shard the (default or custom) loader if sharding is turned on.
-  kwargs['testLoader'] = _setup_sharding(kwargs.get('testLoader', None))
+  kwargs['testLoader'], shard_index = _setup_sharding(
+      kwargs.get('testLoader', None)
+  )
+  if shard_index is not None and shard_index > 0:
+    # When sharding is requested, all the shards except the first one shall not
+    # fail when no tests ran. This happens when the shard count is greater than
+    # the test case count.
+    fail_when_no_tests_ran = False
 
   # XML file name is based upon (sorted by priority):
   # --xml_output_file flag, XML_OUTPUT_FILE variable,
@@ -2523,9 +2645,13 @@ def _run_and_get_tests_result(argv, args, kwargs, xml_test_runner_class):
   # on argv, which is sys.argv without the command-line flags.
   kwargs['argv'] = argv
 
+  # Request unittest.TestProgram to not exit. The exit will be handled by
+  # `absltest.run_tests`.
+  kwargs['exit'] = False
+
   try:
     test_program = unittest.TestProgram(*args, **kwargs)
-    return test_program.result
+    return test_program.result, fail_when_no_tests_ran
   finally:
     if xml_buffer:
       try:
@@ -2535,9 +2661,11 @@ def _run_and_get_tests_result(argv, args, kwargs, xml_test_runner_class):
         xml_buffer.close()
 
 
-def run_tests(argv, args, kwargs):  # pylint: disable=line-too-long
-  # type: (MutableSequence[Text], Sequence[Any], MutableMapping[Text, Any]) -> None
-  # pylint: enable=line-too-long
+def run_tests(
+    argv: MutableSequence[Text],
+    args: Sequence[Any],
+    kwargs: MutableMapping[Text, Any],
+) -> None:
   """Executes a set of Python unit tests.
 
   Most users should call absltest.main() instead of run_tests.
@@ -2558,8 +2686,13 @@ def run_tests(argv, args, kwargs):  # pylint: disable=line-too-long
     kwargs: Keyword arguments passed through to
       ``unittest.TestProgram.__init__``.
   """
-  result = _run_and_get_tests_result(
-      argv, args, kwargs, xml_reporter.TextAndXMLTestRunner)
+  result, fail_when_no_tests_ran = _run_and_get_tests_result(
+      argv, args, kwargs, xml_reporter.TextAndXMLTestRunner
+  )
+  if fail_when_no_tests_ran and result.testsRun == 0 and not result.skipped:
+    # Python 3.12 unittest exits with 5 when no tests ran. The exit code 5 comes
+    # from pytest which does the same thing.
+    sys.exit(5)
   sys.exit(not result.wasSuccessful())
 
 
diff --git a/absl/testing/flagsaver.py b/absl/testing/flagsaver.py
index e96c8c5..7df0722 100644
--- a/absl/testing/flagsaver.py
+++ b/absl/testing/flagsaver.py
@@ -137,7 +137,7 @@ def as_parsed(*args, **kwargs):
   flagsaver.flagsaver(). However, where flagsaver.flagsaver() directly sets the
   flags to new values, this function will parse the provided arguments as if
   they were provided on the command line. Among other things, this will cause
-  `FLAGS['flag_name'].parsed == True`.
+  `FLAGS['flag_name'].present == True`.
 
   A note on unparsed input: For many flag types, the unparsed version will be
   a single string. However for multi_x (multi_string, multi_integer, multi_enum)
diff --git a/absl/testing/parameterized.py b/absl/testing/parameterized.py
index 650d6cf..d3d2c2b 100644
--- a/absl/testing/parameterized.py
+++ b/absl/testing/parameterized.py
@@ -159,8 +159,8 @@ inside a tuple::
         self.assertEqual(0, sum(arg))
 
 
-Cartesian product of Parameter Values as Parametrized Test Cases
-================================================================
+Cartesian product of Parameter Values as Parameterized Test Cases
+=================================================================
 
 If required to test method over a cartesian product of parameters,
 `parameterized.product` may be used to facilitate generation of parameters
@@ -217,6 +217,7 @@ import itertools
 import re
 import types
 import unittest
+import warnings
 
 from absl.testing import absltest
 
@@ -697,10 +698,27 @@ def CoopTestCase(other_base_class):  # pylint: disable=invalid-name
   Returns:
     A new class object.
   """
-  metaclass = type(
-      'CoopMetaclass',
-      (other_base_class.__metaclass__,
-       TestGeneratorMetaclass), {})
-  return metaclass(
-      'CoopTestCase',
-      (other_base_class, TestCase), {})
+  # If the other base class has a metaclass of 'type' then trying to combine
+  # the metaclasses will result in an MRO error. So simply combine them and
+  # return.
+  if type(other_base_class) == type:  # pylint: disable=unidiomatic-typecheck
+    warnings.warn(
+        'CoopTestCase is only necessary when combining with a class that uses'
+        ' a metaclass. Use multiple inheritance like this instead: class'
+        f' ExampleTest(paramaterized.TestCase, {other_base_class.__name__}):',
+        stacklevel=2,
+    )
+
+    class CoopTestCaseBase(other_base_class, TestCase):
+      pass
+
+    return CoopTestCaseBase
+  else:
+
+    class CoopMetaclass(type(other_base_class), TestGeneratorMetaclass):  # pylint: disable=unused-variable
+      pass
+
+    class CoopTestCaseBase(other_base_class, TestCase, metaclass=CoopMetaclass):
+      pass
+
+    return CoopTestCaseBase
diff --git a/absl/testing/tests/absltest_filtering_test.py b/absl/testing/tests/absltest_filtering_test.py
index 3bbb219..c4e0ea6 100644
--- a/absl/testing/tests/absltest_filtering_test.py
+++ b/absl/testing/tests/absltest_filtering_test.py
@@ -156,7 +156,12 @@ class TestFilteringTest(absltest.TestCase):
   def test_not_found_filters_py37(self, use_env_variable, use_app_run):
     out, exit_code = self._run_filtered('NotExistedClass.not_existed_method',
                                         use_env_variable, use_app_run)
-    self.assertEqual(0, exit_code)
+    if not use_env_variable and sys.version_info[:2] >= (3, 12):
+      # When test filter is requested with the unittest `-k` flag, absltest
+      # respect unittest to fail when no tests run on Python 3.12+.
+      self.assertEqual(5, exit_code)
+    else:
+      self.assertEqual(0, exit_code)
     self.assertIn('Ran 0 tests', out)
 
   @absltest.skipIf(
diff --git a/absl/testing/tests/absltest_py3_test.py b/absl/testing/tests/absltest_py3_test.py
deleted file mode 100644
index 7c5f500..0000000
--- a/absl/testing/tests/absltest_py3_test.py
+++ /dev/null
@@ -1,44 +0,0 @@
-# Copyright 2020 The Abseil Authors.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Python3-only Tests for absltest."""
-
-from absl.testing import absltest
-
-
-class GetTestCaseNamesPEP3102Test(absltest.TestCase):
-  """This test verifies absltest.TestLoader.GetTestCasesNames PEP3102 support.
-
-    The test is Python3 only, as keyword only arguments are considered
-    syntax error in Python2.
-
-    The rest of getTestCaseNames functionality is covered
-    by absltest_test.TestLoaderTest.
-  """
-
-  class Valid(absltest.TestCase):
-
-    def testKeywordOnly(self, *, arg):
-      pass
-
-  def setUp(self):
-    self.loader = absltest.TestLoader()
-    super(GetTestCaseNamesPEP3102Test, self).setUp()
-
-  def test_PEP3102_get_test_case_names(self):
-    self.assertCountEqual(
-        self.loader.getTestCaseNames(GetTestCaseNamesPEP3102Test.Valid),
-        ["testKeywordOnly"])
-
-if __name__ == "__main__":
-  absltest.main()
diff --git a/absl/testing/tests/absltest_sharding_test.py b/absl/testing/tests/absltest_sharding_test.py
index 9bbb903..aa4c675 100644
--- a/absl/testing/tests/absltest_sharding_test.py
+++ b/absl/testing/tests/absltest_sharding_test.py
@@ -16,16 +16,18 @@
 
 import os
 import subprocess
+import sys
 
 from absl.testing import _bazelize_command
 from absl.testing import absltest
+from absl.testing import parameterized
 from absl.testing.tests import absltest_env
 
 
 NUM_TEST_METHODS = 8  # Hard-coded, based on absltest_sharding_test_helper.py
 
 
-class TestShardingTest(absltest.TestCase):
+class TestShardingTest(parameterized.TestCase):
   """Integration tests: Runs a test binary with sharding.
 
   This is done by setting the sharding environment variables.
@@ -33,7 +35,6 @@ class TestShardingTest(absltest.TestCase):
 
   def setUp(self):
     super().setUp()
-    self._test_name = 'absl/testing/tests/absltest_sharding_test_helper'
     self._shard_file = None
 
   def tearDown(self):
@@ -41,20 +42,24 @@ class TestShardingTest(absltest.TestCase):
     if self._shard_file is not None and os.path.exists(self._shard_file):
       os.unlink(self._shard_file)
 
-  def _run_sharded(self,
-                   total_shards,
-                   shard_index,
-                   shard_file=None,
-                   additional_env=None):
+  def _run_sharded(
+      self,
+      total_shards,
+      shard_index,
+      shard_file=None,
+      additional_env=None,
+      helper_name='absltest_sharding_test_helper',
+  ):
     """Runs the py_test binary in a subprocess.
 
     Args:
       total_shards: int, the total number of shards.
       shard_index: int, the shard index.
-      shard_file: string, if not 'None', the path to the shard file.
-        This method asserts it is properly created.
+      shard_file: string, if not 'None', the path to the shard file. This method
+        asserts it is properly created.
       additional_env: Additional environment variables to be set for the py_test
         binary.
+      helper_name: The name of the helper binary.
 
     Returns:
       (stdout, exit_code) tuple of (string, int).
@@ -72,12 +77,14 @@ class TestShardingTest(absltest.TestCase):
       if os.path.exists(shard_file):
         os.unlink(shard_file)
 
+    helper = 'absl/testing/tests/' + helper_name
     proc = subprocess.Popen(
-        args=[_bazelize_command.get_executable_path(self._test_name)],
+        args=[_bazelize_command.get_executable_path(helper)],
         env=env,
         stdout=subprocess.PIPE,
         stderr=subprocess.STDOUT,
-        universal_newlines=True)
+        universal_newlines=True,
+    )
     stdout = proc.communicate()[0]
 
     if shard_file:
@@ -140,7 +147,12 @@ class TestShardingTest(absltest.TestCase):
     self._assert_sharding_correctness(1)
 
   def test_with_ten_shards(self):
-    self._assert_sharding_correctness(10)
+    shards = 10
+    # This test relies on the shard count to be greater than the number of
+    # tests, to ensure that the non-zero shards won't fail even if no tests ran
+    # on Python 3.12+.
+    self.assertGreater(shards, NUM_TEST_METHODS)
+    self._assert_sharding_correctness(shards)
 
   def test_sharding_with_randomization(self):
     # If we're both sharding *and* randomizing, we need to confirm that we
@@ -156,6 +168,32 @@ class TestShardingTest(absltest.TestCase):
     self.assertEqual(set(first_tests), set(second_tests))
     self.assertNotEqual(first_tests, second_tests)
 
+  @parameterized.named_parameters(
+      ('total_1_index_0', 1, 0, None),
+      ('total_2_index_0', 2, 0, None),
+      # The 2nd shard (index=1) should not fail.
+      ('total_2_index_1', 2, 1, 0),
+  )
+  def test_no_tests_ran(
+      self, total_shards, shard_index, override_expected_exit_code
+  ):
+    if override_expected_exit_code is not None:
+      expected_exit_code = override_expected_exit_code
+    elif sys.version_info[:2] >= (3, 12):
+      expected_exit_code = 5
+    else:
+      expected_exit_code = 0
+    out, exit_code = self._run_sharded(
+        total_shards,
+        shard_index,
+        helper_name='absltest_sharding_test_helper_no_tests',
+    )
+    self.assertEqual(
+        expected_exit_code,
+        exit_code,
+        'Unexpected exit code, output:\n{}'.format(out),
+    )
+
 
 if __name__ == '__main__':
   absltest.main()
diff --git a/absl/testing/tests/absltest_sharding_test_helper_no_tests.py b/absl/testing/tests/absltest_sharding_test_helper_no_tests.py
new file mode 100644
index 0000000..6e7898e
--- /dev/null
+++ b/absl/testing/tests/absltest_sharding_test_helper_no_tests.py
@@ -0,0 +1,25 @@
+# Copyright 2023 The Abseil Authors.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""A helper test program with no tests ran for absltest_sharding_test."""
+
+from absl.testing import absltest
+
+
+class MyTest(absltest.TestCase):
+  pass
+
+
+if __name__ == "__main__":
+  absltest.main()
diff --git a/absl/testing/tests/absltest_test.py b/absl/testing/tests/absltest_test.py
index 68067cf..034cfca 100644
--- a/absl/testing/tests/absltest_test.py
+++ b/absl/testing/tests/absltest_test.py
@@ -16,6 +16,7 @@
 
 import collections
 import contextlib
+import dataclasses
 import io
 import os
 import pathlib
@@ -23,7 +24,10 @@ import re
 import stat
 import string
 import subprocess
+import sys
 import tempfile
+import textwrap
+from typing import Optional
 import unittest
 
 from absl.testing import _bazelize_command
@@ -32,13 +36,20 @@ from absl.testing import parameterized
 from absl.testing.tests import absltest_env
 
 
-class HelperMixin(object):
+class BaseTestCase(absltest.TestCase):
 
-  def _get_helper_exec_path(self):
-    helper = 'absl/testing/tests/absltest_test_helper'
+  def _get_helper_exec_path(self, helper_name):
+    helper = 'absl/testing/tests/' + helper_name
     return _bazelize_command.get_executable_path(helper)
 
-  def run_helper(self, test_id, args, env_overrides, expect_success):
+  def run_helper(
+      self,
+      test_id,
+      args,
+      env_overrides,
+      expect_success,
+      helper_name=None,
+  ):
     env = absltest_env.inherited_env()
     for key, value in env_overrides.items():
       if value is None:
@@ -47,31 +58,48 @@ class HelperMixin(object):
       else:
         env[key] = value
 
-    command = [self._get_helper_exec_path(),
-               '--test_id={}'.format(test_id)] + args
+    if helper_name is None:
+      helper_name = 'absltest_test_helper'
+    command = [self._get_helper_exec_path(helper_name)]
+    if test_id is not None:
+      command.append('--test_id={}'.format(test_id))
+    command.extend(args)
     process = subprocess.Popen(
         command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
         universal_newlines=True)
     stdout, stderr = process.communicate()
     if expect_success:
       self.assertEqual(
-          0, process.returncode,
-          'Expected success, but failed with '
-          'stdout:\n{}\nstderr:\n{}\n'.format(stdout, stderr))
+          0,
+          process.returncode,
+          'Expected success, but failed with exit code {},'
+          ' stdout:\n{}\nstderr:\n{}\n'.format(
+              process.returncode, stdout, stderr
+          ),
+      )
     else:
-      self.assertEqual(
-          1, process.returncode,
+      self.assertGreater(
+          process.returncode,
+          0,
           'Expected failure, but succeeded with '
-          'stdout:\n{}\nstderr:\n{}\n'.format(stdout, stderr))
-    return stdout, stderr
+          'stdout:\n{}\nstderr:\n{}\n'.format(stdout, stderr),
+      )
+    return stdout, stderr, process.returncode
 
 
-class TestCaseTest(absltest.TestCase, HelperMixin):
+class TestCaseTest(BaseTestCase):
   longMessage = True
 
-  def run_helper(self, test_id, args, env_overrides, expect_success):
-    return super(TestCaseTest, self).run_helper(test_id, args + ['HelperTest'],
-                                                env_overrides, expect_success)
+  def run_helper(
+      self, test_id, args, env_overrides, expect_success, helper_name=None
+  ):
+    return super(TestCaseTest, self).run_helper(
+        test_id,
+        args + ['HelperTest'],
+        env_overrides,
+        expect_success,
+        helper_name,
+    )
 
   def test_flags_no_env_var_no_flags(self):
     self.run_helper(
@@ -187,11 +215,12 @@ class TestCaseTest(absltest.TestCase, HelperMixin):
         expect_success=True)
 
   def test_app_run(self):
-    stdout, _ = self.run_helper(
+    stdout, _, _ = self.run_helper(
         7,
         ['--name=cat', '--name=dog'],
         {'ABSLTEST_TEST_HELPER_USE_APP_RUN': '1'},
-        expect_success=True)
+        expect_success=True,
+    )
     self.assertIn('Names in main() are: cat dog', stdout)
     self.assertIn('Names in test_name_flag() are: cat dog', stdout)
 
@@ -223,7 +252,7 @@ class TestCaseTest(absltest.TestCase, HelperMixin):
     self.assertEqual(1, 2)  # the expected failure
 
   def test_expected_failure_success(self):
-    _, stderr = self.run_helper(5, ['--', '-v'], {}, expect_success=False)
+    _, stderr, _ = self.run_helper(5, ['--', '-v'], {}, expect_success=False)
     self.assertRegex(stderr, r'FAILED \(.*unexpected successes=1\)')
 
   def test_assert_equal(self):
@@ -460,33 +489,6 @@ Missing entries:
     set2 = set([(4, 5)])
     self.assertRaises(AssertionError, self.assertSetEqual, set1, set2)
 
-  def test_assert_dict_contains_subset(self):
-    self.assertDictContainsSubset({}, {})
-
-    self.assertDictContainsSubset({}, {'a': 1})
-
-    self.assertDictContainsSubset({'a': 1}, {'a': 1})
-
-    self.assertDictContainsSubset({'a': 1}, {'a': 1, 'b': 2})
-
-    self.assertDictContainsSubset({'a': 1, 'b': 2}, {'a': 1, 'b': 2})
-
-    self.assertRaises(absltest.TestCase.failureException,
-                      self.assertDictContainsSubset, {'a': 2}, {'a': 1},
-                      '.*Mismatched values:.*')
-
-    self.assertRaises(absltest.TestCase.failureException,
-                      self.assertDictContainsSubset, {'c': 1}, {'a': 1},
-                      '.*Missing:.*')
-
-    self.assertRaises(absltest.TestCase.failureException,
-                      self.assertDictContainsSubset, {'a': 1, 'c': 1}, {'a': 1},
-                      '.*Missing:.*')
-
-    self.assertRaises(absltest.TestCase.failureException,
-                      self.assertDictContainsSubset, {'a': 1, 'c': 1}, {'a': 1},
-                      '.*Missing:.*Mismatched values:.*')
-
   def test_assert_sequence_almost_equal(self):
     actual = (1.1, 1.2, 1.4)
 
@@ -1177,16 +1179,18 @@ test case
     self.assertRaises(AssertionError, self.assertTotallyOrdered, [1, 2])
 
   def test_short_description_without_docstring(self):
-    self.assertEquals(
+    self.assertEqual(
         self.shortDescription(),
-        'TestCaseTest.test_short_description_without_docstring')
+        'TestCaseTest.test_short_description_without_docstring',
+    )
 
   def test_short_description_with_one_line_docstring(self):
     """Tests shortDescription() for a method with a docstring."""
-    self.assertEquals(
+    self.assertEqual(
         self.shortDescription(),
         'TestCaseTest.test_short_description_with_one_line_docstring\n'
-        'Tests shortDescription() for a method with a docstring.')
+        'Tests shortDescription() for a method with a docstring.',
+    )
 
   def test_short_description_with_multi_line_docstring(self):
     """Tests shortDescription() for a method with a longer docstring.
@@ -1195,10 +1199,11 @@ test case
     returned used in the short description, no matter how long the
     whole thing is.
     """
-    self.assertEquals(
+    self.assertEqual(
         self.shortDescription(),
         'TestCaseTest.test_short_description_with_multi_line_docstring\n'
-        'Tests shortDescription() for a method with a longer docstring.')
+        'Tests shortDescription() for a method with a longer docstring.',
+    )
 
   def test_assert_url_equal_same(self):
     self.assertUrlEqual('http://a', 'http://a')
@@ -1397,6 +1402,26 @@ test case
         self.assertSameStructure, dict_a, default_b)
     self.assertEmpty(default_b)
 
+  def test_same_structure_uses_type_equality_func_for_leaves(self):
+    class CustomLeaf(object):
+      def __init__(self, n):
+        self.n = n
+
+      def __repr__(self):
+        return f'CustomLeaf({self.n})'
+
+    def assert_custom_leaf_equal(a, b, msg):
+      del msg
+      assert a.n % 5 == b.n % 5
+    self.addTypeEqualityFunc(CustomLeaf, assert_custom_leaf_equal)
+
+    self.assertSameStructure(CustomLeaf(4), CustomLeaf(9))
+    self.assertRaisesWithLiteralMatch(
+        AssertionError,
+        r'a is CustomLeaf(4) but b is CustomLeaf(8)',
+        self.assertSameStructure, CustomLeaf(4), CustomLeaf(8),
+    )
+
   def test_assert_json_equal_same(self):
     self.assertJsonEqual('{"success": true}', '{"success": true}')
     self.assertJsonEqual('{"success": true}', '{"success":true}')
@@ -1447,14 +1472,6 @@ test case
 
 class GetCommandStderrTestCase(absltest.TestCase):
 
-  def setUp(self):
-    super(GetCommandStderrTestCase, self).setUp()
-    self.original_environ = os.environ.copy()
-
-  def tearDown(self):
-    super(GetCommandStderrTestCase, self).tearDown()
-    os.environ = self.original_environ
-
   def test_return_status(self):
     tmpdir = tempfile.mkdtemp(dir=absltest.TEST_TMPDIR.value)
     returncode = (
@@ -1533,7 +1550,7 @@ class EnterContextClassmethodTest(absltest.TestCase):
 class EqualityAssertionTest(absltest.TestCase):
   """This test verifies that absltest.failIfEqual actually tests __ne__.
 
-  If a user class implements __eq__, unittest.failUnlessEqual will call it
+  If a user class implements __eq__, unittest.assertEqual will call it
   via first == second.   However, failIfEqual also calls
   first == second.   This means that while the caller may believe
   their __ne__ method is being tested, it is not.
@@ -1609,22 +1626,14 @@ class EqualityAssertionTest(absltest.TestCase):
     # Compare two distinct objects
     self.assertFalse(i1 is i2)
     self.assertRaises(AssertionError, self.assertEqual, i1, i2)
-    self.assertRaises(AssertionError, self.assertEquals, i1, i2)
-    self.assertRaises(AssertionError, self.failUnlessEqual, i1, i2)
     self.assertRaises(AssertionError, self.assertNotEqual, i1, i2)
-    self.assertRaises(AssertionError, self.assertNotEquals, i1, i2)
-    self.assertRaises(AssertionError, self.failIfEqual, i1, i2)
     # A NeverEqual object should not compare equal to itself either.
     i2 = i1
     self.assertTrue(i1 is i2)
     self.assertFalse(i1 == i2)
     self.assertFalse(i1 != i2)
     self.assertRaises(AssertionError, self.assertEqual, i1, i2)
-    self.assertRaises(AssertionError, self.assertEquals, i1, i2)
-    self.assertRaises(AssertionError, self.failUnlessEqual, i1, i2)
     self.assertRaises(AssertionError, self.assertNotEqual, i1, i2)
-    self.assertRaises(AssertionError, self.assertNotEquals, i1, i2)
-    self.assertRaises(AssertionError, self.failIfEqual, i1, i2)
 
   def test_all_comparisons_succeed(self):
     a = self.AllSame()
@@ -1633,11 +1642,7 @@ class EqualityAssertionTest(absltest.TestCase):
     self.assertTrue(a == b)
     self.assertFalse(a != b)
     self.assertEqual(a, b)
-    self.assertEquals(a, b)
-    self.failUnlessEqual(a, b)
     self.assertRaises(AssertionError, self.assertNotEqual, a, b)
-    self.assertRaises(AssertionError, self.assertNotEquals, a, b)
-    self.assertRaises(AssertionError, self.failIfEqual, a, b)
 
   def _perform_apple_apple_orange_checks(self, same_a, same_b, different):
     """Perform consistency checks with two apples and an orange.
@@ -1654,20 +1659,14 @@ class EqualityAssertionTest(absltest.TestCase):
     self.assertTrue(same_a == same_b)
     self.assertFalse(same_a != same_b)
     self.assertEqual(same_a, same_b)
-    self.assertEquals(same_a, same_b)
-    self.failUnlessEqual(same_a, same_b)
 
     self.assertFalse(same_a == different)
     self.assertTrue(same_a != different)
     self.assertNotEqual(same_a, different)
-    self.assertNotEquals(same_a, different)
-    self.failIfEqual(same_a, different)
 
     self.assertFalse(same_b == different)
     self.assertTrue(same_b != different)
     self.assertNotEqual(same_b, different)
-    self.assertNotEquals(same_b, different)
-    self.failIfEqual(same_b, different)
 
   def test_comparison_with_eq(self):
     same_a = self.EqualityTestsWithEq(42)
@@ -1688,9 +1687,10 @@ class EqualityAssertionTest(absltest.TestCase):
     self._perform_apple_apple_orange_checks(same_a, same_b, different)
 
 
-class AssertSequenceStartsWithTest(absltest.TestCase):
+class AssertSequenceStartsWithTest(parameterized.TestCase):
 
   def setUp(self):
+    super().setUp()
     self.a = [5, 'foo', {'c': 'd'}, None]
 
   def test_empty_sequence_starts_with_empty_prefix(self):
@@ -1732,10 +1732,15 @@ class AssertSequenceStartsWithTest(absltest.TestCase):
     with self.assertRaisesRegex(AssertionError, msg):
       self.assertSequenceStartsWith(['foo', {'c': 'd'}], self.a)
 
-  def test_raise_if_types_ar_not_supported(self):
-    with self.assertRaisesRegex(TypeError, 'unhashable type'):
-      self.assertSequenceStartsWith({'a': 1, 2: 'b'},
-                                    {'a': 1, 2: 'b', 'c': '3'})
+  @parameterized.named_parameters(
+      ('dict', {'a': 1, 2: 'b'}, {'a': 1, 2: 'b', 'c': '3'}),
+      ('set', {1, 2}, {1, 2, 3}),
+  )
+  def test_raise_if_set_or_dict(self, prefix, whole):
+    with self.assertRaisesRegex(
+        AssertionError, 'For whole: Mapping or Set objects are not supported'
+    ):
+      self.assertSequenceStartsWith(prefix, whole)
 
 
 class TestAssertEmpty(absltest.TestCase):
@@ -1940,6 +1945,9 @@ class TestLoaderTest(absltest.TestCase):
     def TestHelperWithDefaults(self, a=5):
       pass
 
+    def TestHelperWithKeywordOnly(self, *, arg):
+      pass
+
   class Invalid(absltest.TestCase):
     """Test case containing a suspicious method."""
 
@@ -1955,7 +1963,7 @@ class TestLoaderTest(absltest.TestCase):
 
   def test_valid(self):
     suite = self.loader.loadTestsFromTestCase(TestLoaderTest.Valid)
-    self.assertEquals(1, suite.countTestCases())
+    self.assertEqual(1, suite.countTestCases())
 
   def testInvalid(self):
     with self.assertRaisesRegex(TypeError, 'TestSuspiciousMethod'):
@@ -1979,7 +1987,7 @@ class InitNotNecessaryForAssertsTest(absltest.TestCase):
       def __init__(self):  # pylint: disable=super-init-not-called
         pass
 
-    Subclass().assertEquals({}, {})
+    Subclass().assertEqual({}, {})
 
   def test_multiple_inheritance(self):
 
@@ -1991,7 +1999,88 @@ class InitNotNecessaryForAssertsTest(absltest.TestCase):
     class Subclass(Foo, absltest.TestCase):
       pass
 
-    Subclass().assertEquals({}, {})
+    Subclass().assertEqual({}, {})
+
+
+@dataclasses.dataclass
+class _ExampleDataclass:
+  comparable: str
+  not_comparable: str = dataclasses.field(compare=False)
+  comparable2: str = 'comparable2'
+
+
+@dataclasses.dataclass
+class _ExampleCustomEqualDataclass:
+  value: str
+
+  def __eq__(self, other):
+    return False
+
+
+class TestAssertDataclassEqual(absltest.TestCase):
+
+  def test_assert_dataclass_equal_checks_a_for_dataclass(self):
+    b = _ExampleDataclass('a', 'b')
+
+    message = 'First argument is not a dataclass instance.'
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual('a', b)
+
+  def test_assert_dataclass_equal_checks_b_for_dataclass(self):
+    a = _ExampleDataclass('a', 'b')
+
+    message = 'Second argument is not a dataclass instance.'
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual(a, 'b')
+
+  def test_assert_dataclass_equal_different_dataclasses(self):
+    a = _ExampleDataclass('a', 'b')
+    b = _ExampleCustomEqualDataclass('c')
+
+    message = """Found different dataclass types: <class '__main__._ExampleDataclass'> != <class '__main__._ExampleCustomEqualDataclass'>"""
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual(a, b)
+
+  def test_assert_dataclass_equal(self):
+    a = _ExampleDataclass(comparable='a', not_comparable='b')
+    b = _ExampleDataclass(comparable='a', not_comparable='c')
+
+    self.assertDataclassEqual(a, a)
+    self.assertDataclassEqual(a, b)
+    self.assertDataclassEqual(b, a)
+
+  def test_assert_dataclass_fails_non_equal_classes_assert_dict_passes(self):
+    a = _ExampleCustomEqualDataclass(value='a')
+    b = _ExampleCustomEqualDataclass(value='a')
+
+    message = textwrap.dedent("""\
+        _ExampleCustomEqualDataclass(value='a') != _ExampleCustomEqualDataclass(value='a')
+        Cannot detect difference by examining the fields of the dataclass.""")
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual(a, b)
+
+  def test_assert_dataclass_fails_assert_dict_fails_one_field(self):
+    a = _ExampleDataclass(comparable='a', not_comparable='b')
+    b = _ExampleDataclass(comparable='c', not_comparable='d')
+
+    message = textwrap.dedent("""\
+        _ExampleDataclass(comparable='a', not_comparable='b', comparable2='comparable2') != _ExampleDataclass(comparable='c', not_comparable='d', comparable2='comparable2')
+        Fields that differ:
+        comparable: 'a' != 'c'""")
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual(a, b)
+
+  def test_assert_dataclass_fails_assert_dict_fails_multiple_fields(self):
+    a = _ExampleDataclass(comparable='a', not_comparable='b', comparable2='c')
+    b = _ExampleDataclass(comparable='c', not_comparable='d', comparable2='e')
+
+    message = textwrap.dedent("""\
+        _ExampleDataclass(comparable='a', not_comparable='b', comparable2='c') != _ExampleDataclass(comparable='c', not_comparable='d', comparable2='e')
+        Fields that differ:
+        comparable: 'a' != 'c'
+        comparable2: 'c' != 'e'""")
+    with self.assertRaisesWithLiteralMatch(AssertionError, message):
+      self.assertDataclassEqual(a, b)
 
 
 class GetCommandStringTest(parameterized.TestCase):
@@ -2011,7 +2100,7 @@ class GetCommandStringTest(parameterized.TestCase):
     self.assertEqual(expected, absltest.get_command_string(command))
 
 
-class TempFileTest(absltest.TestCase, HelperMixin):
+class TempFileTest(BaseTestCase):
 
   def assert_dir_exists(self, temp_dir):
     path = temp_dir.full_path
@@ -2036,8 +2125,9 @@ class TempFileTest(absltest.TestCase, HelperMixin):
         'ABSLTEST_TEST_HELPER_TEMPFILE_CLEANUP': cleanup,
         'TEST_TMPDIR': tmpdir.full_path,
         }
-    stdout, stderr = self.run_helper(0, ['TempFileHelperTest'], env,
-                                     expect_success=False)
+    stdout, stderr, _ = self.run_helper(
+        0, ['TempFileHelperTest'], env, expect_success=False
+    )
     output = ('\n=== Helper output ===\n'
               '----- stdout -----\n{}\n'
               '----- end stdout -----\n'
@@ -2075,12 +2165,13 @@ class TempFileTest(absltest.TestCase, HelperMixin):
 
   def test_temp_file_path_like(self):
     tempdir = self.create_tempdir('foo')
-    self.assertIsInstance(tempdir, os.PathLike)
-
     tempfile_ = tempdir.create_file('bar')
-    self.assertIsInstance(tempfile_, os.PathLike)
 
     self.assertEqual(tempfile_.read_text(), pathlib.Path(tempfile_).read_text())
+    # assertIsInstance causes the types to be narrowed, so calling create_file
+    # and read_text() must be done before these assertions to avoid type errors.
+    self.assertIsInstance(tempdir, os.PathLike)
+    self.assertIsInstance(tempfile_, os.PathLike)
 
   def test_unnamed(self):
     td = self.create_tempdir()
@@ -2210,9 +2301,13 @@ class SkipClassTest(absltest.TestCase):
   def test_incorrect_decorator_call(self):
     with self.assertRaises(TypeError):
 
+      # Disabling type checking because pytype correctly picks up that
+      # @absltest.skipThisClass is being used incorrectly.
+      # pytype: disable=wrong-arg-types
       @absltest.skipThisClass
       class Test(absltest.TestCase):  # pylint: disable=unused-variable
         pass
+      # pytype: enable=wrong-arg-types
 
   def test_incorrect_decorator_subclass(self):
     with self.assertRaises(TypeError):
@@ -2267,6 +2362,8 @@ class SkipClassTest(absltest.TestCase):
     @absltest.skipThisClass('reason')
     class BaseTest(absltest.TestCase):
 
+      foo: int
+
       @classmethod
       def setUpClass(cls):
         super(BaseTest, cls).setUpClass()
@@ -2291,6 +2388,8 @@ class SkipClassTest(absltest.TestCase):
 
     @absltest.skipThisClass('reason')
     class Test(absltest.TestCase):
+      foo: str
+      bar: Optional[str]
 
       @classmethod
       def setUpClass(cls, foo, bar=None):
@@ -2317,6 +2416,7 @@ class SkipClassTest(absltest.TestCase):
       pass
 
     class RequiredBase(absltest.TestCase):
+      foo: str
 
       @classmethod
       def setUpClass(cls):
@@ -2400,6 +2500,30 @@ class SkipClassTest(absltest.TestCase):
     self.assertEmpty(res.errors)
 
 
+class ExitCodeTest(BaseTestCase):
+
+  def test_exits_5_when_no_tests(self):
+    expect_success = sys.version_info < (3, 12)
+    _, _, exit_code = self.run_helper(
+        None,
+        [],
+        {},
+        expect_success=expect_success,
+        helper_name='absltest_test_helper_skipped',
+    )
+    if not expect_success:
+      self.assertEqual(exit_code, 5)
+
+  def test_exits_5_when_all_skipped(self):
+    self.run_helper(
+        None,
+        [],
+        {'ABSLTEST_TEST_HELPER_DEFINE_CLASS': '1'},
+        expect_success=True,
+        helper_name='absltest_test_helper_skipped',
+    )
+
+
 def _listdir_recursive(path):
   for dirname, _, filenames in os.walk(path):
     yield dirname
diff --git a/absl/testing/tests/absltest_test_helper_skipped.py b/absl/testing/tests/absltest_test_helper_skipped.py
new file mode 100644
index 0000000..506fa4a
--- /dev/null
+++ b/absl/testing/tests/absltest_test_helper_skipped.py
@@ -0,0 +1,17 @@
+"""Test helper for ExitCodeTest in absltest_test.py."""
+
+import os
+from absl.testing import absltest
+
+
+if os.environ.get("ABSLTEST_TEST_HELPER_DEFINE_CLASS") == "1":
+
+  class MyTest(absltest.TestCase):
+
+    @absltest.skip("Skipped for testing the exit code behavior")
+    def test_foo(self):
+      pass
+
+
+if __name__ == "__main__":
+  absltest.main()
diff --git a/absl/testing/tests/flagsaver_test.py b/absl/testing/tests/flagsaver_test.py
index b8f91a5..06d5c37 100644
--- a/absl/testing/tests/flagsaver_test.py
+++ b/absl/testing/tests/flagsaver_test.py
@@ -489,7 +489,7 @@ class AsParsedTest(absltest.TestCase):
         r'flagsaver\.as_parsed\(\) cannot parse flagsaver_test_int_flag\. '
         r'Expected a single string or sequence of strings but .*int.* was '
         r'provided\.'):
-      manager = flagsaver.as_parsed(flagsaver_test_int_flag=123)
+      manager = flagsaver.as_parsed(flagsaver_test_int_flag=123)  # pytype: disable=wrong-arg-types
       del manager
 
 
diff --git a/absl/testing/tests/parameterized_test.py b/absl/testing/tests/parameterized_test.py
index 8acbd93..b453d9a 100644
--- a/absl/testing/tests/parameterized_test.py
+++ b/absl/testing/tests/parameterized_test.py
@@ -15,6 +15,7 @@
 """Tests for absl.testing.parameterized."""
 
 from collections import abc
+import os
 import sys
 import unittest
 
@@ -27,7 +28,6 @@ class MyOwnClass(object):
 
 
 def dummy_decorator(method):
-
   def decorated(*args, **kwargs):
     return method(*args, **kwargs)
 
@@ -48,6 +48,7 @@ def dict_decorator(key, value):
   Returns:
     The test decorator
   """
+
   def decorator(test_method):
     # If decorating result of another dict_decorator
     if isinstance(test_method, abc.Iterable):
@@ -62,10 +63,11 @@ def dict_decorator(key, value):
       test_method.testcases = actual_tests
       return test_method
     else:
-      test_suffix = ('_%s_%s') % (key, value)
+      test_suffix = '_%s_%s' % (key, value)
       tests_to_make = ((test_suffix, {key: value}),)
       # 'test_method' here is the original test method
       return parameterized.named_parameters(*tests_to_make)(test_method)
+
   return decorator
 
 
@@ -75,9 +77,7 @@ class ParameterizedTestsTest(absltest.TestCase):
 
   class GoodAdditionParams(parameterized.TestCase):
 
-    @parameterized.parameters(
-        (1, 2, 3),
-        (4, 5, 9))
+    @parameterized.parameters((1, 2, 3), (4, 5, 9))
     def test_addition(self, op1, op2, result):
       self.arguments = (op1, op2, result)
       self.assertEqual(result, op1 + op2)
@@ -85,17 +85,13 @@ class ParameterizedTestsTest(absltest.TestCase):
   # This class does not inherit from TestCase.
   class BadAdditionParams(absltest.TestCase):
 
-    @parameterized.parameters(
-        (1, 2, 3),
-        (4, 5, 9))
+    @parameterized.parameters((1, 2, 3), (4, 5, 9))
     def test_addition(self, op1, op2, result):
       pass  # Always passes, but not called w/out TestCase.
 
   class MixedAdditionParams(parameterized.TestCase):
 
-    @parameterized.parameters(
-        (1, 2, 1),
-        (4, 5, 9))
+    @parameterized.parameters((1, 2, 1), (4, 5, 9))
     def test_addition(self, op1, op2, result):
       self.arguments = (op1, op2, result)
       self.assertEqual(result, op1 + op2)
@@ -103,8 +99,8 @@ class ParameterizedTestsTest(absltest.TestCase):
   class DictionaryArguments(parameterized.TestCase):
 
     @parameterized.parameters(
-        {'op1': 1, 'op2': 2, 'result': 3},
-        {'op1': 4, 'op2': 5, 'result': 9})
+        {'op1': 1, 'op2': 2, 'result': 3}, {'op1': 4, 'op2': 5, 'result': 9}
+    )
     def test_addition(self, op1, op2, result):
       self.assertEqual(result, op1 + op2)
 
@@ -238,13 +234,13 @@ class ParameterizedTestsTest(absltest.TestCase):
     @dict_decorator('cone', 'waffle')
     @dict_decorator('flavor', 'strawberry')
     def test_chained(self, dictionary):
-      self.assertDictEqual(dictionary, {'cone': 'waffle',
-                                        'flavor': 'strawberry'})
+      self.assertDictEqual(
+          dictionary, {'cone': 'waffle', 'flavor': 'strawberry'}
+      )
 
   class SingletonListExtraction(parameterized.TestCase):
 
-    @parameterized.parameters(
-        (i, i * 2) for i in range(10))
+    @parameterized.parameters((i, i * 2) for i in range(10))
     def test_something(self, unused_1, unused_2):
       pass
 
@@ -264,9 +260,7 @@ class ParameterizedTestsTest(absltest.TestCase):
     def test_something(self, op1, op2):
       del op1, op2
 
-  @parameterized.parameters(
-      (1, 2, 3),
-      (4, 5, 9))
+  @parameterized.parameters((1, 2, 3), (4, 5, 9))
   class DecoratedClass(parameterized.TestCase):
 
     def test_add(self, arg1, arg2, arg3):
@@ -276,7 +270,8 @@ class ParameterizedTestsTest(absltest.TestCase):
       self.assertEqual(arg3 + arg2, arg1)
 
   @parameterized.parameters(
-      (a, b, a+b) for a in range(1, 5) for b in range(1, 5))
+      (a, b, a + b) for a in range(1, 5) for b in range(1, 5)
+  )
   class GeneratorDecoratedClass(parameterized.TestCase):
 
     def test_add(self, arg1, arg2, arg3):
@@ -322,14 +317,14 @@ class ParameterizedTestsTest(absltest.TestCase):
 
     @dummy_decorator
     @parameterized.named_parameters(
-        {'testcase_name': 'a', 'arg1': 1},
-        {'testcase_name': 'b', 'arg1': 2})
+        {'testcase_name': 'a', 'arg1': 1}, {'testcase_name': 'b', 'arg1': 2}
+    )
     def test_other_then_parameterized(self, arg1):
       pass
 
     @parameterized.named_parameters(
-        {'testcase_name': 'a', 'arg1': 1},
-        {'testcase_name': 'b', 'arg1': 2})
+        {'testcase_name': 'a', 'arg1': 1}, {'testcase_name': 'b', 'arg1': 2}
+    )
     @dummy_decorator
     def test_parameterized_then_other(self, arg1):
       pass
@@ -380,7 +375,8 @@ class ParameterizedTestsTest(absltest.TestCase):
   @unittest.skipIf(
       (sys.version_info[:2] == (3, 7) and sys.version_info[2] in {0, 1, 2}),
       'Python 3.7.0 to 3.7.2 have a bug that breaks this test, see '
-      'https://bugs.python.org/issue35767')
+      'https://bugs.python.org/issue35767',
+  )
   def test_missing_inheritance(self):
     ts = unittest.makeSuite(self.BadAdditionParams)
     self.assertEqual(1, ts.countTestCases())
@@ -407,9 +403,7 @@ class ParameterizedTestsTest(absltest.TestCase):
     ts = unittest.makeSuite(self.GoodAdditionParams)
     res = unittest.TestResult()
 
-    params = set([
-        (1, 2, 3),
-        (4, 5, 9)])
+    params = set([(1, 2, 3), (4, 5, 9)])
     for test in ts:
       test(res)
       self.assertIn(test.arguments, params)
@@ -432,38 +426,46 @@ class ParameterizedTestsTest(absltest.TestCase):
     short_desc = list(ts)[0].shortDescription()
 
     location = unittest.util.strclass(self.GoodAdditionParams).replace(
-        '__main__.', '')
-    expected = ('{}.test_addition0 (1, 2, 3)\n'.format(location) +
-                'test_addition(1, 2, 3)')
+        '__main__.', ''
+    )
+    expected = (
+        '{}.test_addition0 (1, 2, 3)\n'.format(location)
+        + 'test_addition(1, 2, 3)'
+    )
     self.assertEqual(expected, short_desc)
 
   def test_short_description_addresses_removed(self):
     ts = unittest.makeSuite(self.ArgumentsWithAddresses)
     short_desc = list(ts)[0].shortDescription().split('\n')
-    self.assertEqual(
-        'test_something(<object>)', short_desc[1])
+    self.assertEqual('test_something(<object>)', short_desc[1])
     short_desc = list(ts)[1].shortDescription().split('\n')
-    self.assertEqual(
-        'test_something(<__main__.MyOwnClass>)', short_desc[1])
+    self.assertEqual('test_something(<__main__.MyOwnClass>)', short_desc[1])
 
   def test_id(self):
     ts = unittest.makeSuite(self.ArgumentsWithAddresses)
     self.assertEqual(
-        (unittest.util.strclass(self.ArgumentsWithAddresses) +
-         '.test_something0 (<object>)'),
-        list(ts)[0].id())
+        (
+            unittest.util.strclass(self.ArgumentsWithAddresses)
+            + '.test_something0 (<object>)'
+        ),
+        list(ts)[0].id(),
+    )
     ts = unittest.makeSuite(self.GoodAdditionParams)
     self.assertEqual(
-        (unittest.util.strclass(self.GoodAdditionParams) +
-         '.test_addition0 (1, 2, 3)'),
-        list(ts)[0].id())
+        (
+            unittest.util.strclass(self.GoodAdditionParams)
+            + '.test_addition0 (1, 2, 3)'
+        ),
+        list(ts)[0].id(),
+    )
 
   def test_str(self):
     ts = unittest.makeSuite(self.GoodAdditionParams)
     test = list(ts)[0]
 
     expected = 'test_addition0 (1, 2, 3) ({})'.format(
-        unittest.util.strclass(self.GoodAdditionParams))
+        unittest.util.strclass(self.GoodAdditionParams)
+    )
     self.assertEqual(expected, str(test))
 
   def test_dict_parameters(self):
@@ -486,17 +488,13 @@ class ParameterizedTestsTest(absltest.TestCase):
             '{}.testNormal'.format(full_class_name),
             '{}.test_normal'.format(full_class_name),
         ],
-        short_descs)
+        short_descs,
+    )
 
   def test_successful_product_test_testgrid(self):
-
     class GoodProductTestCase(parameterized.TestCase):
 
-      @parameterized.product(
-          num=(0, 20, 80),
-          modulo=(2, 4),
-          expected=(0,)
-      )
+      @parameterized.product(num=(0, 20, 80), modulo=(2, 4), expected=(0,))
       def testModuloResult(self, num, modulo, expected):
         self.assertEqual(expected, num % modulo)
 
@@ -508,12 +506,13 @@ class ParameterizedTestsTest(absltest.TestCase):
     self.assertTrue(res.wasSuccessful())
 
   def test_successful_product_test_kwarg_seqs(self):
-
     class GoodProductTestCase(parameterized.TestCase):
 
-      @parameterized.product((dict(num=0), dict(num=20), dict(num=0)),
-                             (dict(modulo=2), dict(modulo=4)),
-                             (dict(expected=0),))
+      @parameterized.product(
+          (dict(num=0), dict(num=20), dict(num=0)),
+          (dict(modulo=2), dict(modulo=4)),
+          (dict(expected=0),),
+      )
       def testModuloResult(self, num, modulo, expected):
         self.assertEqual(expected, num % modulo)
 
@@ -525,12 +524,15 @@ class ParameterizedTestsTest(absltest.TestCase):
     self.assertTrue(res.wasSuccessful())
 
   def test_successful_product_test_kwarg_seq_and_testgrid(self):
-
     class GoodProductTestCase(parameterized.TestCase):
 
-      @parameterized.product((dict(
-          num=5, modulo=3, expected=2), dict(num=7, modulo=4, expected=3)),
-                             dtype=(int, float))
+      @parameterized.product(
+          (
+              dict(num=5, modulo=3, expected=2),
+              dict(num=7, modulo=4, expected=3),
+          ),
+          dtype=(int, float),
+      )
       def testModuloResult(self, num, dtype, modulo, expected):
         self.assertEqual(expected, dtype(num) % modulo)
 
@@ -546,8 +548,9 @@ class ParameterizedTestsTest(absltest.TestCase):
 
       class BadProductParams(parameterized.TestCase):  # pylint: disable=unused-variable
 
-        @parameterized.product((dict(num=5, modulo=3), dict(num=7, modula=2)),
-                               dtype=(int, float))
+        @parameterized.product(
+            (dict(num=5, modulo=3), dict(num=7, modula=2)), dtype=(int, float)
+        )
         def test_something(self):
           pass  # not called because argnames are not the same
 
@@ -556,9 +559,11 @@ class ParameterizedTestsTest(absltest.TestCase):
 
       class BadProductParams(parameterized.TestCase):  # pylint: disable=unused-variable
 
-        @parameterized.product((dict(num=5, modulo=3), dict(num=7, modulo=4)),
-                               (dict(foo='bar', num=5), dict(foo='baz', num=7)),
-                               dtype=(int, float))
+        @parameterized.product(
+            (dict(num=5, modulo=3), dict(num=7, modulo=4)),
+            (dict(foo='bar', num=5), dict(foo='baz', num=7)),
+            dtype=(int, float),
+        )
         def test_something(self):
           pass  # not called because `num` is specified twice
 
@@ -577,14 +582,9 @@ class ParameterizedTestsTest(absltest.TestCase):
           pass  # not called because `foo` is specified twice
 
   def test_product_recorded_failures(self):
-
     class MixedProductTestCase(parameterized.TestCase):
 
-      @parameterized.product(
-          num=(0, 10, 20),
-          modulo=(2, 4),
-          expected=(0,)
-      )
+      @parameterized.product(num=(0, 10, 20), modulo=(2, 4), expected=(0,))
       def testModuloResult(self, num, modulo, expected):
         self.assertEqual(expected, num % modulo)
 
@@ -599,13 +599,9 @@ class ParameterizedTestsTest(absltest.TestCase):
     self.assertEmpty(res.errors)
 
   def test_mismatched_product_parameter(self):
-
     class MismatchedProductParam(parameterized.TestCase):
 
-      @parameterized.product(
-          a=(1, 2),
-          mismatch=(1, 2)
-      )
+      @parameterized.product(a=(1, 2), mismatch=(1, 2))
       # will fail because of mismatch in parameter names.
       def test_something(self, a, b):
         pass
@@ -637,6 +633,7 @@ class ParameterizedTestsTest(absltest.TestCase):
 
   def test_generator_tests_disallowed(self):
     with self.assertRaisesRegex(RuntimeError, 'generated.*without'):
+
       class GeneratorTests(parameterized.TestCase):  # pylint: disable=unused-variable
         test_generator_method = (lambda self: None for _ in range(10))
 
@@ -649,74 +646,53 @@ class ParameterizedTestsTest(absltest.TestCase):
     self.assertTrue(res.wasSuccessful())
 
   def test_named_parameters_id(self):
-    ts = sorted(unittest.makeSuite(self.CamelCaseNamedTests),
-                key=lambda t: t.id())
+    ts = sorted(
+        unittest.makeSuite(self.CamelCaseNamedTests), key=lambda t: t.id()
+    )
     self.assertLen(ts, 9)
     full_class_name = unittest.util.strclass(self.CamelCaseNamedTests)
+    self.assertEqual(full_class_name + '.testDictSingleInteresting', ts[0].id())
+    self.assertEqual(full_class_name + '.testDictSomethingBoring', ts[1].id())
     self.assertEqual(
-        full_class_name + '.testDictSingleInteresting',
-        ts[0].id())
-    self.assertEqual(
-        full_class_name + '.testDictSomethingBoring',
-        ts[1].id())
-    self.assertEqual(
-        full_class_name + '.testDictSomethingInteresting',
-        ts[2].id())
-    self.assertEqual(
-        full_class_name + '.testMixedSomethingBoring',
-        ts[3].id())
-    self.assertEqual(
-        full_class_name + '.testMixedSomethingInteresting',
-        ts[4].id())
-    self.assertEqual(
-        full_class_name + '.testSingleInteresting',
-        ts[5].id())
-    self.assertEqual(
-        full_class_name + '.testSomethingBoring',
-        ts[6].id())
-    self.assertEqual(
-        full_class_name + '.testSomethingInteresting',
-        ts[7].id())
+        full_class_name + '.testDictSomethingInteresting', ts[2].id()
+    )
+    self.assertEqual(full_class_name + '.testMixedSomethingBoring', ts[3].id())
     self.assertEqual(
-        full_class_name + '.testWithoutParameters',
-        ts[8].id())
+        full_class_name + '.testMixedSomethingInteresting', ts[4].id()
+    )
+    self.assertEqual(full_class_name + '.testSingleInteresting', ts[5].id())
+    self.assertEqual(full_class_name + '.testSomethingBoring', ts[6].id())
+    self.assertEqual(full_class_name + '.testSomethingInteresting', ts[7].id())
+    self.assertEqual(full_class_name + '.testWithoutParameters', ts[8].id())
 
   def test_named_parameters_id_with_underscore_case(self):
-    ts = sorted(unittest.makeSuite(self.NamedTests),
-                key=lambda t: t.id())
+    ts = sorted(unittest.makeSuite(self.NamedTests), key=lambda t: t.id())
     self.assertLen(ts, 9)
     full_class_name = unittest.util.strclass(self.NamedTests)
     self.assertEqual(
-        full_class_name + '.test_dict_single_interesting',
-        ts[0].id())
-    self.assertEqual(
-        full_class_name + '.test_dict_something_boring',
-        ts[1].id())
-    self.assertEqual(
-        full_class_name + '.test_dict_something_interesting',
-        ts[2].id())
-    self.assertEqual(
-        full_class_name + '.test_mixed_something_boring',
-        ts[3].id())
+        full_class_name + '.test_dict_single_interesting', ts[0].id()
+    )
     self.assertEqual(
-        full_class_name + '.test_mixed_something_interesting',
-        ts[4].id())
+        full_class_name + '.test_dict_something_boring', ts[1].id()
+    )
     self.assertEqual(
-        full_class_name + '.test_single_interesting',
-        ts[5].id())
+        full_class_name + '.test_dict_something_interesting', ts[2].id()
+    )
     self.assertEqual(
-        full_class_name + '.test_something_boring',
-        ts[6].id())
+        full_class_name + '.test_mixed_something_boring', ts[3].id()
+    )
     self.assertEqual(
-        full_class_name + '.test_something_interesting',
-        ts[7].id())
+        full_class_name + '.test_mixed_something_interesting', ts[4].id()
+    )
+    self.assertEqual(full_class_name + '.test_single_interesting', ts[5].id())
+    self.assertEqual(full_class_name + '.test_something_boring', ts[6].id())
     self.assertEqual(
-        full_class_name + '.test_without_parameters',
-        ts[8].id())
+        full_class_name + '.test_something_interesting', ts[7].id()
+    )
+    self.assertEqual(full_class_name + '.test_without_parameters', ts[8].id())
 
   def test_named_parameters_short_description(self):
-    ts = sorted(unittest.makeSuite(self.NamedTests),
-                key=lambda t: t.id())
+    ts = sorted(unittest.makeSuite(self.NamedTests), key=lambda t: t.id())
     actual = {t._testMethodName: t.shortDescription() for t in ts}
     expected = {
         'test_dict_single_interesting': 'case=0',
@@ -734,8 +710,11 @@ class ParameterizedTestsTest(absltest.TestCase):
 
   def test_load_tuple_named_test(self):
     loader = unittest.TestLoader()
-    ts = list(loader.loadTestsFromName('NamedTests.test_something_interesting',
-                                       module=self))
+    ts = list(
+        loader.loadTestsFromName(
+            'NamedTests.test_something_interesting', module=self
+        )
+    )
     self.assertLen(ts, 1)
     self.assertEndsWith(ts[0].id(), '.test_something_interesting')
 
@@ -743,7 +722,9 @@ class ParameterizedTestsTest(absltest.TestCase):
     loader = unittest.TestLoader()
     ts = list(
         loader.loadTestsFromName(
-            'NamedTests.test_dict_something_interesting', module=self))
+            'NamedTests.test_dict_something_interesting', module=self
+        )
+    )
     self.assertLen(ts, 1)
     self.assertEndsWith(ts[0].id(), '.test_dict_something_interesting')
 
@@ -751,7 +732,9 @@ class ParameterizedTestsTest(absltest.TestCase):
     loader = unittest.TestLoader()
     ts = list(
         loader.loadTestsFromName(
-            'NamedTests.test_mixed_something_interesting', module=self))
+            'NamedTests.test_mixed_something_interesting', module=self
+        )
+    )
     self.assertLen(ts, 1)
     self.assertEndsWith(ts[0].id(), '.test_mixed_something_interesting')
 
@@ -886,7 +869,6 @@ class ParameterizedTestsTest(absltest.TestCase):
           pass
 
   def test_double_class_decorations_not_supported(self):
-
     @parameterized.parameters('foo', 'bar')
     class SuperclassWithClassDecorator(parameterized.TestCase):
 
@@ -968,7 +950,6 @@ class ParameterizedTestsTest(absltest.TestCase):
       del test_something
 
   def test_unique_descriptive_names(self):
-
     class RecordSuccessTestsResult(unittest.TestResult):
 
       def __init__(self, *args, **kwargs):
@@ -1009,10 +990,41 @@ class ParameterizedTestsTest(absltest.TestCase):
   def test_subclass_inherits_superclass_test_params_reprs(self):
     self.assertEqual(
         {'test_name0': "('foo')", 'test_name1': "('bar')"},
-        self.SuperclassTestCase._test_params_reprs)
+        self.SuperclassTestCase._test_params_reprs,
+    )
     self.assertEqual(
         {'test_name0': "('foo')", 'test_name1': "('bar')"},
-        self.SubclassTestCase._test_params_reprs)
+        self.SubclassTestCase._test_params_reprs,
+    )
+
+
+# IsolatedAsyncioTestCase is only available in Python 3.8+.
+if sys.version_info[:2] >= (3, 8):
+
+  async def mult(x: float, y: float) -> float:
+    return x * y
+
+  class AsyncTest(unittest.IsolatedAsyncioTestCase, parameterized.TestCase):
+
+    def setUp(self):
+      super().setUp()
+      self.verify_ran = False
+
+    def tearDown(self):
+      super().tearDown()
+
+      # We need the additional check here because originally the test function
+      # would run, but a coroutine results from the execution and is never
+      # awaited, so it looked like a successful test run when in fact the
+      # internal test logic never executed.  If you remove the check for
+      # coroutine and run_until_complete, then set the parameters to fail they
+      # never will.
+      self.assertTrue(self.verify_ran)
+
+    @parameterized.parameters((1, 2, 2), (2, 2, 4), (3, 2, 6))
+    async def test_multiply_expected_matches_actual(self, x, y, expected):
+      self.assertEqual(await mult(x, y), expected)
+      self.verify_ran = True
 
 
 def _decorate_with_side_effects(func, self):
@@ -1022,7 +1034,19 @@ def _decorate_with_side_effects(func, self):
 
 class CoopMetaclassCreationTest(absltest.TestCase):
 
-  class TestBase(absltest.TestCase):
+  class TestBaseMetaclass(type):
+
+    def __init__(cls, name, bases, dct):
+      type.__init__(cls, name, bases, dct)
+      for member_name, obj in dct.items():
+        if member_name.startswith('test'):
+          setattr(
+              cls,
+              member_name,
+              lambda self, f=obj: _decorate_with_side_effects(f, self),
+          )
+
+  class TestBase(absltest.TestCase, metaclass=TestBaseMetaclass):
 
     # This test simulates a metaclass that sets some attribute ('sideeffect')
     # on each member of the class that starts with 'test'. The test code then
@@ -1033,21 +1057,11 @@ class CoopMetaclassCreationTest(absltest.TestCase):
     # since the TestGeneratorMetaclass already overrides __new__. Only one
     # base metaclass can override __new__, but all can provide custom __init__
     # methods.
-
-    class __metaclass__(type):  # pylint: disable=g-bad-name
-
-      def __init__(cls, name, bases, dct):
-        type.__init__(cls, name, bases, dct)
-        for member_name, obj in dct.items():
-          if member_name.startswith('test'):
-            setattr(cls, member_name,
-                    lambda self, f=obj: _decorate_with_side_effects(f, self))
+    pass
 
   class MyParams(parameterized.CoopTestCase(TestBase)):
 
-    @parameterized.parameters(
-        (1, 2, 3),
-        (4, 5, 9))
+    @parameterized.parameters((1, 2, 3), (4, 5, 9))
     def test_addition(self, op1, op2, result):
       self.assertEqual(result, op1 + op2)
 
@@ -1072,6 +1086,20 @@ class CoopMetaclassCreationTest(absltest.TestCase):
     ts.run(res)
     self.assertTrue(list(ts)[0].sideeffect)
 
+  def test_no_metaclass(self):
+    class SimpleMixinTestCase(absltest.TestCase):
+      pass
+
+    with self.assertWarnsRegex(
+        UserWarning,
+        'CoopTestCase is only necessary when combining with a class that uses a'
+        ' metaclass',
+    ) as warning:
+      parameterized.CoopTestCase(SimpleMixinTestCase)
+    self.assertEqual(
+        os.path.basename(warning.filename), 'parameterized_test.py'
+    )
+
 
 if __name__ == '__main__':
   absltest.main()
diff --git a/absl/testing/tests/xml_reporter_test.py b/absl/testing/tests/xml_reporter_test.py
index c0d43a6..0f44f71 100644
--- a/absl/testing/tests/xml_reporter_test.py
+++ b/absl/testing/tests/xml_reporter_test.py
@@ -61,19 +61,26 @@ def xml_escaped_exception_type(exception_type):
   return xml_reporter._escape_xml_attr(str(exception_type))
 
 
-OUTPUT_STRING = '\n'.join([
-    r'<\?xml version="1.0"\?>',
-    ('<testsuites name="" tests="%(tests)d" failures="%(failures)d"'
-     ' errors="%(errors)d" time="%(run_time).3f" timestamp="%(start_time)s">'),
-    ('<testsuite name="%(suite_name)s" tests="%(tests)d"'
-     ' failures="%(failures)d" errors="%(errors)d" time="%(run_time).3f"'
-     ' timestamp="%(start_time)s">'),
-    ('  <testcase name="%(test_name)s" status="%(status)s" result="%(result)s"'
-     ' time="%(run_time).3f" classname="%(classname)s"'
-     ' timestamp="%(start_time)s">%(message)s'),
-    '  </testcase>', '</testsuite>',
-    '</testsuites>',
-])
+# Matches the entire XML output. Captures all <testcase> tags except for the
+# last closing </testcase> in a single group.
+OUTPUT_STRING = """\
+<\\?xml version="1.0"\\?>
+<testsuites name="" tests="%(tests)d" failures="%(failures)d"\
+ errors="%(errors)d" time="%(run_time).3f" timestamp="%(start_time)s">
+<testsuite name="%(suite_name)s" tests="%(tests)d"\
+ failures="%(failures)d" errors="%(errors)d" time="%(run_time).3f"\
+ timestamp="%(start_time)s">
+(  <testcase .*)
+  </testcase>
+</testsuite>
+</testsuites>"""
+
+# Matches a single <testcase> tag and its contents, without the closing
+# </testcase>, which we use as a separator to split multiple <testcase> tags.
+TESTCASE_STRING = """\
+  <testcase name="%(test_name)s" status="%(status)s" result="%(result)s"\
+ time="%(run_time).3f" classname="%(classname)s" timestamp="%(start_time)s">\
+%(message)s"""
 
 FAILURE_MESSAGE = r"""
   <failure message="e" type="{}"><!\[CDATA\[Traceback \(most recent call last\):
@@ -133,9 +140,12 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     return xml_reporter._TextAndXMLTestResult(self.xml_stream, self.stream,
                                               'foo', 0, timer)
 
-  def _assert_match(self, regex, output):
+  def _assert_match(self, regex, output, flags=0):
     fail_msg = 'Expected regex:\n{}\nTo match:\n{}'.format(regex, output)
-    self.assertRegex(output, regex, fail_msg)
+    result = re.match(regex, output, flags)
+    if result is None:
+      self.fail(fail_msg)
+    return result.groups()
 
   def _assert_valid_xml(self, xml_output):
     try:
@@ -174,6 +184,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -181,7 +192,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'passing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -189,7 +204,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_passing_subtest(self):
     start_time = 0
@@ -197,13 +214,14 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result = self._make_result((start_time, start_time, end_time, end_time))
 
     test = MockTest('__main__.MockTest.passing_test')
-    subtest = unittest.case._SubTest(test, 'msg', None)
+    subtest = unittest.case._SubTest(test, 'msg', None)  # pytype: disable=module-attr
     result.startTestRun()
     result.startTest(test)
     result.addSubTest(test, subtest, None)
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -211,7 +229,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': r'passing_test&#x20;\[msg\]',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -219,7 +241,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_passing_subtest_with_dots_in_parameter_name(self):
     start_time = 0
@@ -227,27 +251,26 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result = self._make_result((start_time, start_time, end_time, end_time))
 
     test = MockTest('__main__.MockTest.passing_test')
-    subtest = unittest.case._SubTest(test, 'msg', {'case': 'a.b.c'})
+    subtest = unittest.case._SubTest(test, 'msg', {'case': 'a.b.c'})  # pytype: disable=module-attr
     result.startTestRun()
     result.startTest(test)
     result.addSubTest(test, subtest, None)
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
-        'suite_name':
-            'MockTest',
-        'tests':
-            1,
-        'failures':
-            0,
-        'errors':
-            0,
-        'run_time':
-            run_time,
-        'start_time':
-            re.escape(self._iso_timestamp(start_time),),
+        'suite_name': 'MockTest',
+        'tests': 1,
+        'failures': 0,
+        'errors': 0,
+        'run_time': run_time,
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name':
             r'passing_test&#x20;\[msg\]&#x20;\(case=&apos;a.b.c&apos;\)',
         'classname':
@@ -261,7 +284,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'message':
             ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def get_sample_error(self):
     try:
@@ -311,6 +336,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -318,7 +344,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 1,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -326,7 +356,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': FAILURE_MESSAGE
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_failing_subtest(self):
     start_time = 10
@@ -334,13 +366,14 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result = self._make_result((start_time, start_time, end_time, end_time))
 
     test = MockTest('__main__.MockTest.failing_test')
-    subtest = unittest.case._SubTest(test, 'msg', None)
+    subtest = unittest.case._SubTest(test, 'msg', None)  # pytype: disable=module-attr
     result.startTestRun()
     result.startTest(test)
     result.addSubTest(test, subtest, self.get_sample_failure())
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -348,7 +381,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 1,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': r'failing_test&#x20;\[msg\]',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -356,7 +393,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': FAILURE_MESSAGE
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_error_test(self):
     start_time = 100
@@ -374,6 +413,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
 
     self._assert_valid_xml(xml)
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -381,7 +421,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -389,7 +433,8 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ERROR_MESSAGE
     }
-    self._assert_match(expected_re, xml)
+    (testcase,) = self._assert_match(expected_re, xml, re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_error_subtest(self):
     start_time = 10
@@ -397,13 +442,14 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result = self._make_result((start_time, start_time, end_time, end_time))
 
     test = MockTest('__main__.MockTest.error_test')
-    subtest = unittest.case._SubTest(test, 'msg', None)
+    subtest = unittest.case._SubTest(test, 'msg', None)  # pytype: disable=module-attr
     result.startTestRun()
     result.startTest(test)
     result.addSubTest(test, subtest, self.get_sample_error())
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -411,7 +457,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': r'error_test&#x20;\[msg\]',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -419,7 +469,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ERROR_MESSAGE
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_fail_and_error_test(self):
     """Tests a failure and subsequent error within a single result."""
@@ -440,6 +492,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
 
     self._assert_valid_xml(xml)
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -447,7 +500,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 1,  # Only the failure is tallied (because it was first).
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -456,7 +513,8 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         # Messages from failure and error should be concatenated in order.
         'message': FAILURE_MESSAGE + ERROR_MESSAGE
     }
-    self._assert_match(expected_re, xml)
+    (testcase,) = self._assert_match(expected_re, xml, re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_error_and_fail_test(self):
     """Tests an error and subsequent failure within a single result."""
@@ -476,6 +534,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
 
     self._assert_valid_xml(xml)
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -483,7 +542,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,  # Only the error is tallied (because it was first).
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -492,7 +555,8 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         # Messages from error and failure should be concatenated in order.
         'message': ERROR_MESSAGE + FAILURE_MESSAGE
     }
-    self._assert_match(expected_re, xml)
+    (testcase,) = self._assert_match(expected_re, xml, re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_newline_error_test(self):
     start_time = 100
@@ -510,6 +574,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
 
     self._assert_valid_xml(xml)
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -517,15 +582,20 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    } + '\n'
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
         'result': 'completed',
         'attributes': '',
         'message': NEWLINE_ERROR_MESSAGE
-    } + '\n'
-    self._assert_match(expected_re, xml)
+    }
+    (testcase,) = self._assert_match(expected_re, xml, re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_unicode_error_test(self):
     start_time = 100
@@ -543,6 +613,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
 
     self._assert_valid_xml(xml)
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -550,7 +621,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -558,7 +633,8 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': UNICODE_ERROR_MESSAGE
     }
-    self._assert_match(expected_re, xml)
+    (testcase,) = self._assert_match(expected_re, xml, re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_terminal_escape_error(self):
     start_time = 100
@@ -594,6 +670,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -601,7 +678,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'expected_failing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -609,8 +690,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ''
     }
-    self._assert_match(re.compile(expected_re, re.DOTALL),
-                       self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase, re.DOTALL)
 
   def test_with_unexpected_success_error_test(self):
     start_time = 100
@@ -625,6 +707,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -632,7 +715,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 1,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'unexpectedly_passing_test',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -640,7 +727,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': UNEXPECTED_SUCCESS_MESSAGE
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_with_skipped_test(self):
     start_time = 100
@@ -655,6 +744,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -662,47 +752,81 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'skipped_test_with_reason',
         'classname': '__main__.MockTest',
         'status': 'notrun',
         'result': 'suppressed',
         'message': ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
-  def test_suite_time(self):
+  def test_two_tests_with_time(self):
     start_time1 = 100
     end_time1 = 200
     start_time2 = 400
     end_time2 = 700
-    name = '__main__.MockTest.failing_test'
+    name = '__main__.MockTest.'
     result = self._make_result((start_time1, start_time1, end_time1,
                                 start_time2, end_time2, end_time2))
 
-    test = MockTest('%s1' % name)
+    test = MockTest(f'{name}one_test')
     result.startTestRun()
     result.startTest(test)
     result.addSuccess(test)
     result.stopTest(test)
 
-    test = MockTest('%s2' % name)
+    test = MockTest(f'{name}another_test')
     result.startTest(test)
     result.addSuccess(test)
     result.stopTest(test)
     result.stopTestRun()
     result.printErrors()
 
-    run_time = max(end_time1, end_time2) - min(start_time1, start_time2)
-    timestamp = self._iso_timestamp(start_time1)
-    expected_prefix = """<?xml version="1.0"?>
-<testsuites name="" tests="2" failures="0" errors="0" time="%.3f" timestamp="%s">
-<testsuite name="MockTest" tests="2" failures="0" errors="0" time="%.3f" timestamp="%s">
-""" % (run_time, timestamp, run_time, timestamp)
-    xml_output = self.xml_stream.getvalue()
-    self.assertTrue(
-        xml_output.startswith(expected_prefix),
-        '%s not found in %s' % (expected_prefix, xml_output))
+    start_time = min(start_time1, start_time2)
+    run_time = max(end_time1, end_time2) - start_time
+    start_time_str = re.escape(self._iso_timestamp(start_time))
+    start_time_str1 = re.escape(self._iso_timestamp(start_time1))
+    start_time_str2 = re.escape(self._iso_timestamp(start_time2))
+    expected_re = OUTPUT_STRING % {
+        'suite_name': 'MockTest',
+        'tests': 2,
+        'failures': 0,
+        'errors': 0,
+        'run_time': run_time,
+        'start_time': start_time_str,
+    }
+    expected_testcase1_re = TESTCASE_STRING % {
+        'run_time': end_time1 - start_time1,
+        'start_time': start_time_str1,
+        'test_name': 'one_test',
+        'classname': '__main__.MockTest',
+        'status': 'run',
+        'result': 'completed',
+        'message': ''
+    }
+    expected_testcase2_re = TESTCASE_STRING % {
+        'run_time': end_time2 - start_time2,
+        'start_time': start_time_str2,
+        'test_name': 'another_test',
+        'classname': '__main__.MockTest',
+        'status': 'run',
+        'result': 'completed',
+        'message': ''
+    }
+
+    (testcases,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                      re.DOTALL)
+    [testcase1, testcase2] = testcases.split('\n  </testcase>\n')
+    # Sorting by test name flips the order of the two tests.
+    self._assert_match(expected_testcase2_re, testcase1)
+    self._assert_match(expected_testcase1_re, testcase2)
 
   def test_with_no_suite_name(self):
     start_time = 1000
@@ -717,6 +841,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     expected_re = OUTPUT_STRING % {
         'suite_name': 'MockTest',
@@ -724,7 +849,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': 'bad_name',
         'classname': '__main__.MockTest',
         'status': 'run',
@@ -732,7 +861,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def test_unnamed_parameterized_testcase(self):
     """Test unnamed parameterized test cases.
@@ -759,6 +890,7 @@ class TextAndXMLTestResultTest(absltest.TestCase):
     result.stopTestRun()
     result.printErrors()
 
+    start_time_str = re.escape(self._iso_timestamp(start_time))
     run_time = end_time - start_time
     classname = xml_reporter._escape_xml_attr(
         unittest.util.strclass(test.__class__))
@@ -768,7 +900,11 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'failures': 0,
         'errors': 0,
         'run_time': run_time,
-        'start_time': re.escape(self._iso_timestamp(start_time),),
+        'start_time': start_time_str,
+    }
+    expected_testcase_re = TESTCASE_STRING % {
+        'run_time': run_time,
+        'start_time': start_time_str,
         'test_name': re.escape('test_prefix0&#x20;(&apos;a&#x20;(b.c)&apos;)'),
         'classname': classname,
         'status': 'run',
@@ -776,7 +912,9 @@ class TextAndXMLTestResultTest(absltest.TestCase):
         'attributes': '',
         'message': ''
     }
-    self._assert_match(expected_re, self.xml_stream.getvalue())
+    (testcase,) = self._assert_match(expected_re, self.xml_stream.getvalue(),
+                                     re.DOTALL)
+    self._assert_match(expected_testcase_re, testcase)
 
   def teststop_test_without_pending_test(self):
     end_time = 1200
@@ -792,19 +930,19 @@ class TextAndXMLTestResultTest(absltest.TestCase):
                                                'foo', 1)
     result1 = runner._makeResult()
     result2 = xml_reporter._TextAndXMLTestResult(None, None, None, 0, None)
-    self.failUnless(type(result1) is type(result2))
+    self.assertIs(type(result1), type(result2))
 
   def test_timing_with_time_stub(self):
     """Make sure that timing is correct even if time.time is stubbed out."""
+    saved_time = time.time
     try:
-      saved_time = time.time
       time.time = lambda: -1
       reporter = xml_reporter._TextAndXMLTestResult(self.xml_stream,
                                                     self.stream,
                                                     'foo', 0)
       test = MockTest('bar')
       reporter.startTest(test)
-      self.failIf(reporter.start_time == -1)
+      self.assertNotEqual(reporter.start_time, -1)
     finally:
       time.time = saved_time
 
diff --git a/absl/testing/xml_reporter.py b/absl/testing/xml_reporter.py
index 591eb7e..4fcb60c 100644
--- a/absl/testing/xml_reporter.py
+++ b/absl/testing/xml_reporter.py
@@ -290,7 +290,9 @@ class _TestSuiteResult(object):
       ]
       _print_xml_element_header('testsuite', suite_attributes, stream)
 
-      for test_case_result in suite:
+      # test_case_result entries are not guaranteed to be in any user-friendly
+      # order, especially when using subtests. So sort them.
+      for test_case_result in sorted(suite, key=lambda t: t.name):
         test_case_result.print_xml_summary(stream)
       stream.write('</testsuite>\n')
     stream.write('</testsuites>\n')
@@ -359,6 +361,9 @@ class _TextAndXMLTestResult(_pretty_print_reporter.TextTestResult):
         test_name = test.id() or str(test)
         sys.stderr.write('No pending test case: %s\n' % test_name)
         return
+      if getattr(self, 'start_time', None) is None:
+        # startTest may not be called for skipped tests since Python 3.12.1.
+        self.start_time = self.time_getter()
       test_id = id(test)
       run_time = self.time_getter() - self.start_time
       result.set_run_time(run_time)
@@ -384,7 +389,7 @@ class _TextAndXMLTestResult(_pretty_print_reporter.TextTestResult):
       # reporting here.
       for test_id in self.pending_test_case_results:
         result = self.pending_test_case_results[test_id]
-        if hasattr(self, 'start_time'):
+        if getattr(self, 'start_time', None) is not None:
           run_time = self.suite.overall_end_time - self.start_time
           result.set_run_time(run_time)
           result.set_start_time(self.start_time)
diff --git a/absl/tests/app_test_helper.py b/absl/tests/app_test_helper.py
index f9fbdec..92f7be3 100644
--- a/absl/tests/app_test_helper.py
+++ b/absl/tests/app_test_helper.py
@@ -18,11 +18,11 @@ import os
 import sys
 
 try:
-  import faulthandler
+  import faulthandler  # pylint: disable=g-import-not-at-top
 except ImportError:
   faulthandler = None
 
-from absl import app
+from absl import app  # pylint: disable=g-import-not-at-top
 from absl import flags
 
 FLAGS = flags.FLAGS
diff --git a/ci/run_tests.sh b/ci/run_tests.sh
new file mode 100755
index 0000000..99de7cd
--- /dev/null
+++ b/ci/run_tests.sh
@@ -0,0 +1,31 @@
+#!/bin/bash
+
+# Fail on any error. Treat unset variables an error. Print commands as executed.
+set -eux
+
+# Log environment variables.
+env
+
+# Let the script continue even if "bazel test" fails, so that all tests are
+# always executed.
+exit_code=0
+
+# Log the bazel version for easier debugging.
+bazel version
+bazel test --test_output=errors absl/... || exit_code=$?
+if [[ ! -z "${ABSL_EXPECTED_PYTHON_VERSION}" ]]; then
+    bazel test \
+        --test_output=errors absl:tests/python_version_test \
+        --test_arg=--expected_version="${ABSL_EXPECTED_PYTHON_VERSION}" || exit_code=$?
+fi
+
+if [[ ! -z "${ABSL_COPY_TESTLOGS_TO}" ]]; then
+    mkdir -p "${ABSL_COPY_TESTLOGS_TO}"
+    readonly testlogs_dir=$(bazel info bazel-testlogs)
+    echo "Copying bazel test logs from ${testlogs_dir} to ${ABSL_COPY_TESTLOGS_TO}..."
+    cp -r "${testlogs_dir}" "${ABSL_COPY_TESTLOGS_TO}" || exit_code=$?
+fi
+
+# TODO(yileiyang): Update and run smoke_test.sh.
+
+exit $exit_code
diff --git a/setup.py b/setup.py
index 1a119f5..ec5258a 100644
--- a/setup.py
+++ b/setup.py
@@ -17,15 +17,17 @@
 import os
 import sys
 
+# pylint: disable=g-import-not-at-top
 try:
   import setuptools
 except ImportError:
   from ez_setup import use_setuptools
   use_setuptools()
   import setuptools
+# pylint: enable=g-import-not-at-top
 
-if sys.version_info < (3, 6):
-  raise RuntimeError('Python version 3.6+ is required.')
+if sys.version_info < (3, 7):
+  raise RuntimeError('Python version 3.7+ is required.')
 
 setuptools_version = tuple(
     int(x) for x in setuptools.__version__.split('.')[:2])
@@ -34,7 +36,7 @@ additional_kwargs = {}
 if setuptools_version >= (24, 2):
   # `python_requires` was added in 24.2, see
   # https://packaging.python.org/guides/distributing-packages-using-setuptools/#python-requires
-  additional_kwargs['python_requires'] = '>=3.6'
+  additional_kwargs['python_requires'] = '>=3.7'
 
 _README_PATH = os.path.join(
     os.path.dirname(os.path.realpath(__file__)), 'README.md')
@@ -43,28 +45,34 @@ with open(_README_PATH, 'rb') as fp:
 
 setuptools.setup(
     name='absl-py',
-    version='1.4.0',
+    version='2.1.0',
     description=(
         'Abseil Python Common Libraries, '
-        'see https://github.com/abseil/abseil-py.'),
+        'see https://github.com/abseil/abseil-py.'
+    ),
     long_description=LONG_DESCRIPTION,
     long_description_content_type='text/markdown',
     author='The Abseil Authors',
     url='https://github.com/abseil/abseil-py',
-    packages=setuptools.find_packages(exclude=[
-        '*.tests', '*.tests.*', 'tests.*', 'tests',
-    ]),
+    packages=setuptools.find_packages(
+        exclude=[
+            '*.tests',
+            '*.tests.*',
+            'tests.*',
+            'tests',
+        ]
+    ),
     include_package_data=True,
     license='Apache 2.0',
     classifiers=[
         'Programming Language :: Python',
         'Programming Language :: Python :: 3',
-        'Programming Language :: Python :: 3.6',
         'Programming Language :: Python :: 3.7',
         'Programming Language :: Python :: 3.8',
         'Programming Language :: Python :: 3.9',
         'Programming Language :: Python :: 3.10',
         'Programming Language :: Python :: 3.11',
+        'Programming Language :: Python :: 3.12',
         'Intended Audience :: Developers',
         'Topic :: Software Development :: Libraries :: Python Modules',
         'License :: OSI Approved :: Apache Software License',
```

