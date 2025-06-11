```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index a24efc3..af6eac0 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -29,6 +29,6 @@ jobs:
 
     - name: Check formatting
       run: |
-        python -m pip install pyink
+        python -m pip install pyink==24.3.0
         pyink --check .
 
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 424dc64..3b270a7 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,6 +1,20 @@
 # Mobly Release History
 
 
+## Mobly Release 1.12.4: Improvements
+
+Maintenance release with small improvements and fixes.
+
+### New
+* Introduced `apk_utils` module for Android apk install/uninstall.
+
+### Fixes
+* Bugs in snippet client.
+* Noise in console output on Mac.
+
+[Full list of changes](https://github.com/google/mobly/milestone/31?closed=1)
+
+
 ## Mobly Release 1.12.3: Proper Repeat and Retry Reporting
 Bumping min Python version requirement to 3.11.
 Modernized the repo's packaging mechanism.
diff --git a/CONTRIBUTING.md b/CONTRIBUTING.md
index bca38c3..5d666f3 100644
--- a/CONTRIBUTING.md
+++ b/CONTRIBUTING.md
@@ -48,7 +48,7 @@ Before pushing your changes, you need to lint the code style via `pyink`
 To install `pyink`:
 
 ```sh
-$ pip3 install pyink
+$ pip3 install pyink==24.3.0
 ```
 
 To lint the code:
diff --git a/METADATA b/METADATA
index 2bdc523..a2d8da0 100644
--- a/METADATA
+++ b/METADATA
@@ -7,14 +7,14 @@ description: "Mobly is a Python-based test framework that specializes in support
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 8
-    day: 13
+    year: 2025
+    month: 2
+    day: 25
   }
   homepage: "https://github.com/google/mobly"
   identifier {
     type: "Git"
     value: "https://github.com/google/mobly"
-    version: "1.12.3"
+    version: "a489d904870e349ce47cc972d0f20c4723316cce"
   }
 }
diff --git a/OWNERS b/OWNERS
index eb86f14..6f10248 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,3 +6,5 @@ murj@google.com
 # Mobly team - use for mobly bugs
 angli@google.com
 lancefluger@google.com
+xianyuanjia@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/docs/tutorial.md b/docs/tutorial.md
index f53b948..93122ec 100644
--- a/docs/tutorial.md
+++ b/docs/tutorial.md
@@ -336,11 +336,11 @@ class ManyGreetingsTest(base_test.BaseTestClass):
     # When a test run starts, Mobly calls this function to figure out what
     # tests need to be generated. So you need to specify what tests to generate
     # in this function.
-    def setup_generated_tests(self):
+    def pre_run(self):
         messages = [('Hello', 'World'), ('Aloha', 'Obama'),
                     ('konichiwa', 'Satoshi')]
         # Call `generate_tests` function to specify the tests to generate. This
-        # function can only be called within `setup_generated_tests`. You could
+        # function can only be called within `pre_run`. You could
         # call this function multiple times to generate multiple groups of
         # tests.
         self.generate_tests(
diff --git a/mobly/base_instrumentation_test.py b/mobly/base_instrumentation_test.py
index f41a500..5713422 100644
--- a/mobly/base_instrumentation_test.py
+++ b/mobly/base_instrumentation_test.py
@@ -83,10 +83,7 @@ class _InstrumentationKnownStatusKeys:
   .. code-block:: none
 
     android.app.Instrumentation
-    android.support.test.internal.runner.listener.InstrumentationResultPrinter
-
-  TODO: Convert android.support.* to androidx.*,
-  (https://android-developers.googleblog.com/2018/05/hello-world-androidx.html).
+    androidx.test.internal.runner.listener.InstrumentationResultPrinter
   """
 
   CLASS = 'class'
@@ -119,10 +116,7 @@ class _InstrumentationStatusCodes:
 
   .. code-block:: none
 
-    android.support.test.internal.runner.listener.InstrumentationResultPrinter
-
-  TODO: Convert android.support.* to androidx.*,
-  (https://android-developers.googleblog.com/2018/05/hello-world-androidx.html).
+    androidx.test.internal.runner.listener.InstrumentationResultPrinter
   """
 
   UNKNOWN = None
diff --git a/mobly/base_suite.py b/mobly/base_suite.py
index 06cdeed..1ef0a68 100644
--- a/mobly/base_suite.py
+++ b/mobly/base_suite.py
@@ -14,6 +14,8 @@
 
 import abc
 
+import logging
+
 
 class BaseSuite(abc.ABC):
   """Class used to define a Mobly suite.
@@ -34,11 +36,20 @@ class BaseSuite(abc.ABC):
   def __init__(self, runner, config):
     self._runner = runner
     self._config = config.copy()
+    self._test_selector = None
 
   @property
   def user_params(self):
     return self._config.user_params
 
+  def set_test_selector(self, test_selector):
+    """Sets test selector.
+
+    Don't override or call this method. This should only be used by the Mobly
+    framework.
+    """
+    self._test_selector = test_selector
+
   def add_test_class(self, clazz, config=None, tests=None, name_suffix=None):
     """Adds a test class to the suite.
 
@@ -47,12 +58,27 @@ class BaseSuite(abc.ABC):
       config: config_parser.TestRunConfig, the config to run the class with. If
         not specified, the default config passed from google3 infra is used.
       tests: list of strings, names of the tests to run in this test class, in
-        the execution order. If not specified, all tests in the class are
-        executed.
+        the execution order. Or a string with prefix `re:` for full regex match
+        of test cases; all matched test cases will be executed; an error is
+        raised if no match is found.
+        If not specified, all tests in the class are executed.
+        CLI argument `tests` takes precedence over this argument.
       name_suffix: string, suffix to append to the class name for reporting.
         This is used for differentiating the same class executed with different
         parameters in a suite.
     """
+    if self._test_selector:
+      cls_name = clazz.__name__
+      if (cls_name, name_suffix) in self._test_selector:
+        tests = self._test_selector[(cls_name, name_suffix)]
+      elif cls_name in self._test_selector:
+        tests = self._test_selector[cls_name]
+      else:
+        logging.info(
+            'Skipping test class %s due to CLI argument `tests`.', cls_name
+        )
+        return
+
     if not config:
       config = self._config
     self._runner.add_test_class(config, clazz, tests, name_suffix)
diff --git a/mobly/base_test.py b/mobly/base_test.py
index e5060af..a62fac2 100644
--- a/mobly/base_test.py
+++ b/mobly/base_test.py
@@ -19,6 +19,7 @@ import functools
 import inspect
 import logging
 import os
+import re
 import sys
 
 from mobly import controller_manager
@@ -31,14 +32,13 @@ from mobly import utils
 # Macro strings for test result reporting.
 TEST_CASE_TOKEN = '[Test]'
 RESULT_LINE_TEMPLATE = TEST_CASE_TOKEN + ' %s %s'
+TEST_SELECTOR_REGEX_PREFIX = 're:'
 
 TEST_STAGE_BEGIN_LOG_TEMPLATE = '[{parent_token}]#{child_token} >>> BEGIN >>>'
 TEST_STAGE_END_LOG_TEMPLATE = '[{parent_token}]#{child_token} <<< END <<<'
 
 # Names of execution stages, in the order they happen during test runs.
 STAGE_NAME_PRE_RUN = 'pre_run'
-# Deprecated, use `STAGE_NAME_PRE_RUN` instead.
-STAGE_NAME_SETUP_GENERATED_TESTS = 'setup_generated_tests'
 STAGE_NAME_SETUP_CLASS = 'setup_class'
 STAGE_NAME_SETUP_TEST = 'setup_test'
 STAGE_NAME_TEARDOWN_TEST = 'teardown_test'
@@ -370,10 +370,6 @@ class BaseTestClass:
     try:
       with self._log_test_stage(stage_name):
         self.pre_run()
-      # TODO(angli): Remove this context block after the full deprecation of
-      # `setup_generated_tests`.
-      with self._log_test_stage(stage_name):
-        self.setup_generated_tests()
       return True
     except Exception as e:
       logging.exception('%s failed for %s.', stage_name, self.TAG)
@@ -395,19 +391,6 @@ class BaseTestClass:
     requested is unknown at this point.
     """
 
-  def setup_generated_tests(self):
-    """[DEPRECATED] Use `pre_run` instead.
-
-    Preprocesses that need to be done before setup_class.
-
-    This phase is used to do pre-test processes like generating tests.
-    This is the only place `self.generate_tests` should be called.
-
-    If this function throws an error, the test class will be marked failure
-    and the "Requested" field will be 0 because the number of tests
-    requested is unknown at this point.
-    """
-
   def _setup_class(self):
     """Proxy function to guarantee the base implementation of setup_class
     is called.
@@ -904,8 +887,7 @@ class BaseTestClass:
   def generate_tests(self, test_logic, name_func, arg_sets, uid_func=None):
     """Generates tests in the test class.
 
-    This function has to be called inside a test class's `self.pre_run` or
-    `self.setup_generated_tests`.
+    This function has to be called inside a test class's `self.pre_run`.
 
     Generated tests are not written down as methods, but as a list of
     parameter sets. This way we reduce code repetition and improve test
@@ -926,9 +908,7 @@ class BaseTestClass:
         arguments as the test logic function and returns a string that
         is the corresponding UID.
     """
-    self._assert_function_names_in_stack(
-        [STAGE_NAME_PRE_RUN, STAGE_NAME_SETUP_GENERATED_TESTS]
-    )
+    self._assert_function_names_in_stack([STAGE_NAME_PRE_RUN])
     root_msg = 'During test generation of "%s":' % test_logic.__name__
     for args in arg_sets:
       test_name = name_func(*args)
@@ -1003,7 +983,8 @@ class BaseTestClass:
     """Resolves test method names to bound test methods.
 
     Args:
-      test_names: A list of strings, each string is a test method name.
+      test_names: A list of strings, each string is a test method name or a
+        regex for matching test names.
 
     Returns:
       A list of tuples of (string, function). String is the test method
@@ -1014,21 +995,52 @@ class BaseTestClass:
         This can only be caused by user input.
     """
     test_methods = []
+    # Process the test name selector one by one.
     for test_name in test_names:
-      if not test_name.startswith('test_'):
-        raise Error(
-            'Test method name %s does not follow naming '
-            'convention test_*, abort.' % test_name
+      if test_name.startswith(TEST_SELECTOR_REGEX_PREFIX):
+        # process the selector as a regex.
+        regex_matching_methods = self._get_regex_matching_test_methods(
+            test_name.removeprefix(TEST_SELECTOR_REGEX_PREFIX)
         )
+        test_methods += regex_matching_methods
+        continue
+      # process the selector as a regular test name string.
+      self._assert_valid_test_name(test_name)
+      if test_name not in self.get_existing_test_names():
+        raise Error(f'{self.TAG} does not have test method {test_name}.')
       if hasattr(self, test_name):
         test_method = getattr(self, test_name)
       elif test_name in self._generated_test_table:
         test_method = self._generated_test_table[test_name]
-      else:
-        raise Error('%s does not have test method %s.' % (self.TAG, test_name))
       test_methods.append((test_name, test_method))
     return test_methods
 
+  def _get_regex_matching_test_methods(self, test_name_regex):
+    matching_name_tuples = []
+    for name, method in inspect.getmembers(self, callable):
+      if (
+          name.startswith('test_')
+          and re.fullmatch(test_name_regex, name) is not None
+      ):
+        matching_name_tuples.append((name, method))
+    for name, method in self._generated_test_table.items():
+      if re.fullmatch(test_name_regex, name) is not None:
+        self._assert_valid_test_name(name)
+        matching_name_tuples.append((name, method))
+    if not matching_name_tuples:
+      raise Error(
+          f'{test_name_regex} does not match with any valid test case '
+          f'in {self.TAG}, abort!'
+      )
+    return matching_name_tuples
+
+  def _assert_valid_test_name(self, test_name):
+    if not test_name.startswith('test_'):
+      raise Error(
+          'Test method name %s does not follow naming '
+          'convention test_*, abort.' % test_name
+      )
+
   def _skip_remaining_tests(self, exception):
     """Marks any requested test that has not been executed in a class as
     skipped.
diff --git a/mobly/controllers/android_device.py b/mobly/controllers/android_device.py
index 20c5762..66a40d5 100644
--- a/mobly/controllers/android_device.py
+++ b/mobly/controllers/android_device.py
@@ -139,8 +139,19 @@ def get_info(ads):
 
   Returns:
     A list of dict, each representing info for an AndroidDevice objects.
+    Everything in this dict should be yaml serializable.
   """
-  return [ad.device_info for ad in ads]
+  infos = []
+  # The values of user_added_info can be arbitrary types, so we shall sanitize
+  # them here to ensure they are yaml serializable.
+  for ad in ads:
+    device_info = ad.device_info
+    user_added_info = {
+        k: str(v) for (k, v) in device_info['user_added_info'].items()
+    }
+    device_info['user_added_info'] = user_added_info
+    infos.append(device_info)
+  return infos
 
 
 def _validate_device_existence(serials):
@@ -576,28 +587,6 @@ class AndroidDevice:
     """
     self._user_added_device_info.update({name: info})
 
-  @property
-  def sl4a(self):
-    """Attribute for direct access of sl4a client.
-
-    Not recommended. This is here for backward compatibility reasons.
-
-    Preferred: directly access `ad.services.sl4a`.
-    """
-    if self.services.has_service_by_name('sl4a'):
-      return self.services.sl4a
-
-  @property
-  def ed(self):
-    """Attribute for direct access of sl4a's event dispatcher.
-
-    Not recommended. This is here for backward compatibility reasons.
-
-    Preferred: directly access `ad.services.sl4a.ed`.
-    """
-    if self.services.has_service_by_name('sl4a'):
-      return self.services.sl4a.ed
-
   @property
   def debug_tag(self):
     """A string that represents a device object in debug info. Default value
@@ -844,7 +833,7 @@ class AndroidDevice:
 
   @property
   def is_rootable(self):
-    return not self.is_bootloader and self.build_info['debuggable'] == '1'
+    return self.is_adb_detectable() and self.build_info['debuggable'] == '1'
 
   @functools.cached_property
   def model(self):
@@ -908,6 +897,7 @@ class AndroidDevice:
             % (k, getattr(self, k)),
         )
       setattr(self, k, v)
+      self.add_device_info(k, v)
 
   def root_adb(self):
     """Change adb to root mode for this device if allowed.
diff --git a/mobly/controllers/android_device_lib/adb.py b/mobly/controllers/android_device_lib/adb.py
index 721dcc7..d5af14f 100644
--- a/mobly/controllers/android_device_lib/adb.py
+++ b/mobly/controllers/android_device_lib/adb.py
@@ -198,13 +198,6 @@ class AdbProxy:
 
     if stderr:
       stderr.write(err)
-    logging.debug(
-        'cmd: %s, stdout: %s, stderr: %s, ret: %s',
-        utils.cli_cmd_to_string(args),
-        out,
-        err,
-        ret,
-    )
     if ret == 0:
       return out
     else:
diff --git a/mobly/controllers/android_device_lib/apk_utils.py b/mobly/controllers/android_device_lib/apk_utils.py
new file mode 100644
index 0000000..6c0cc41
--- /dev/null
+++ b/mobly/controllers/android_device_lib/apk_utils.py
@@ -0,0 +1,174 @@
+# Copyright 2024 Google Inc.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import io
+from typing import Iterable, Optional
+
+from mobly import utils
+from mobly.controllers.android_device import AndroidDevice
+from mobly.controllers.android_device_lib import adb
+from mobly.controllers.android_device_lib import errors
+
+
+DEFAULT_TIMEOUT_INSTALL_APK_SEC = 300
+# Error messages from adb.
+ADB_UNINSTALL_INTERNAL_ERROR_MSG = 'DELETE_FAILED_INTERNAL_ERROR'
+
+
+def _execute_adb_install(
+    device: AndroidDevice, install_args: Iterable[str], timeout: int
+) -> None:
+  """Executes the adb install command.
+
+  Args:
+    device: AndroidDevice, Mobly's Android controller object.
+    install_args: list of strings, the args to be added to `adb install` cmd.
+    timeout: int, the number of seconds to wait before timing out.
+
+  Raises:
+    AdbError: installation failed.
+  """
+  stderr_buffer = io.BytesIO()
+  stdout = device.adb.install(
+      install_args, stderr=stderr_buffer, timeout=timeout
+  )
+  stderr = stderr_buffer.getvalue().decode('utf-8').strip()
+  if not _is_apk_install_success(stdout, stderr):
+    adb_cmd = 'adb -s %s install %s' % (device.serial, ' '.join(install_args))
+    raise adb.AdbError(cmd=adb_cmd, stdout=stdout, stderr=stderr, ret_code=0)
+
+
+def _is_apk_install_success(stdout: bytes, stderr: str) -> bool:
+  """Checks output of the adb install command and decides if install succeeded.
+
+  Args:
+    stdout: string, the standard out output of an adb install command.
+    stderr: string, the standard error output of an adb install command.
+
+  Returns:
+    True if the installation succeeded; False otherwise.
+  """
+  if utils.grep('Failure', stdout):
+    return False
+  return any([not stderr, stderr == 'Success', 'waiting for device' in stderr])
+
+
+def _should_retry_apk_install(error_msg: str) -> bool:
+  """Decides whether we should retry adb install.
+
+  Args:
+    error_msg: string, the error message of an adb install failure.
+
+  Returns:
+    True if a retry is warranted; False otherwise.
+  """
+  return 'INSTALL_FAILED_INSUFFICIENT_STORAGE' in error_msg
+
+
+def install(
+    device: AndroidDevice,
+    apk_path: str,
+    timeout: int = DEFAULT_TIMEOUT_INSTALL_APK_SEC,
+    user_id: Optional[int] = None,
+    params: Optional[Iterable[str]] = None,
+) -> None:
+  """Install an apk on an Android device.
+
+  Installing apk is more complicated than most people realize on Android.
+  This is just a util for the most common use cases. If you need special logic
+  beyond this, we recomend you write your own instead of modifying this.
+
+  Args:
+    device: AndroidDevice, Mobly's Android controller object.
+    apk_path: string, file path of an apk file.
+    timeout: int, the number of seconds to wait before timing out.
+    user_id: int, the ID of the user to install the apk for. For SDK>=24,
+        install for the current user by default. Android's multi-user support
+        did not realistically work until SDK 24.
+    params: string list, additional parameters included in the adb install cmd.
+
+  Raises:
+    AdbError: Installation failed.
+    ValueError: Attempts to set user_id on SDK<24.
+  """
+  android_api_version = int(device.build_info['build_version_sdk'])
+  if user_id is not None and android_api_version < 24:
+    raise ValueError('Cannot specify `user_id` for device below SDK 24.')
+  # Figure out the args to use.
+  args = ['-r', '-t']
+  if android_api_version >= 24:
+    if user_id is None:
+      user_id = device.adb.current_user_id
+    args = ['--user', str(user_id)] + args
+  if android_api_version >= 23:
+    args.append('-g')
+  if android_api_version >= 17:
+    args.append('-d')
+  args += params or []
+  args.append(apk_path)
+  try:
+    _execute_adb_install(device, args, timeout)
+    return
+  except adb.AdbError as e:
+    if not _should_retry_apk_install(str(e)):
+      raise
+    device.log.debug('Retrying installation of %s', apk_path)
+    device.reboot()
+    _execute_adb_install(device, args, timeout)
+
+
+def is_apk_installed(device: AndroidDevice, package_name: str) -> bool:
+  """Check if the given apk is already installed.
+
+  Args:
+    device: AndroidDevice, Mobly's Android controller object.
+    package_name: str, name of the package.
+
+  Returns:
+    True if package is installed. False otherwise.
+  """
+  try:
+    out = device.adb.shell(['pm', 'list', 'package'])
+    return bool(utils.grep('^package:%s$' % package_name, out))
+  except adb.AdbError as error:
+    raise errors.DeviceError(device, error)
+
+
+def uninstall(device: AndroidDevice, package_name: str) -> None:
+  """Uninstall an apk on an Android device if it is installed.
+
+  Works for regular app and OEM pre-installed non-system app.
+
+  Args:
+    device: AndroidDevice, Mobly's Android controller object.
+    package_name: string, package name of the app.
+  """
+  if is_apk_installed(device, package_name):
+    try:
+      device.adb.uninstall([package_name])
+    except adb.AdbError as e1:
+      # This error can happen if the package to uninstall is non-system and
+      # pre-loaded by OEM. Try removing it via PackageManager (pm) under UID 0.
+      if ADB_UNINSTALL_INTERNAL_ERROR_MSG in str(e1):
+        device.log.debug(
+            'Encountered uninstall internal error, try pm remove with UID 0.'
+        )
+        try:
+          device.adb.shell(
+              ['pm', 'uninstall', '-k', '--user', '0', package_name]
+          )
+          return
+        except adb.AdbError as e2:
+          device.log.exception('Second attempt to uninstall failed: %s', e2)
+      raise e1
diff --git a/mobly/controllers/android_device_lib/event_dispatcher.py b/mobly/controllers/android_device_lib/event_dispatcher.py
deleted file mode 100644
index 80610ef..0000000
--- a/mobly/controllers/android_device_lib/event_dispatcher.py
+++ /dev/null
@@ -1,443 +0,0 @@
-# Copyright 2016 Google Inc.
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
-from concurrent import futures
-import queue
-import re
-import threading
-import time
-import traceback
-
-
-class EventDispatcherError(Exception):
-  pass
-
-
-class IllegalStateError(EventDispatcherError):
-  """Raise when user tries to put event_dispatcher into an illegal state."""
-
-
-class DuplicateError(EventDispatcherError):
-  """Raise when a duplicate is being created and it shouldn't."""
-
-
-class EventDispatcher:
-  """Class managing events for an sl4a connection."""
-
-  DEFAULT_TIMEOUT = 60
-
-  def __init__(self, sl4a):
-    self._sl4a = sl4a
-    self.started = False
-    self.executor = None
-    self.poller = None
-    self.event_dict = {}
-    self.handlers = {}
-    self.lock = threading.RLock()
-
-  def poll_events(self):
-    """Continuously polls all types of events from sl4a.
-
-    Events are sorted by name and store in separate queues.
-    If there are registered handlers, the handlers will be called with
-    corresponding event immediately upon event discovery, and the event
-    won't be stored. If exceptions occur, stop the dispatcher and return
-    """
-    while self.started:
-      event_obj = None
-      event_name = None
-      try:
-        event_obj = self._sl4a.eventWait(50000)
-      except Exception:
-        if self.started:
-          print("Exception happened during polling.")
-          print(traceback.format_exc())
-          raise
-      if not event_obj:
-        continue
-      elif "name" not in event_obj:
-        print("Received Malformed event {}".format(event_obj))
-        continue
-      else:
-        event_name = event_obj["name"]
-      # if handler registered, process event
-      if event_name in self.handlers:
-        self.handle_subscribed_event(event_obj, event_name)
-      if event_name == "EventDispatcherShutdown":
-        self._sl4a.closeSl4aSession()
-        break
-      else:
-        self.lock.acquire()
-        if event_name in self.event_dict:  # otherwise, cache event
-          self.event_dict[event_name].put(event_obj)
-        else:
-          q = queue.Queue()
-          q.put(event_obj)
-          self.event_dict[event_name] = q
-        self.lock.release()
-
-  def register_handler(self, handler, event_name, args):
-    """Registers an event handler.
-
-    One type of event can only have one event handler associated with it.
-
-    Args:
-      handler: The event handler function to be registered.
-      event_name: Name of the event the handler is for.
-      args: User arguments to be passed to the handler when it's called.
-
-    Raises:
-      IllegalStateError: Raised if attempts to register a handler after
-        the dispatcher starts running.
-      DuplicateError: Raised if attempts to register more than one
-        handler for one type of event.
-    """
-    if self.started:
-      raise IllegalStateError("Can't register service after polling is started")
-    self.lock.acquire()
-    try:
-      if event_name in self.handlers:
-        raise DuplicateError(
-            "A handler for {} already exists".format(event_name)
-        )
-      self.handlers[event_name] = (handler, args)
-    finally:
-      self.lock.release()
-
-  def start(self):
-    """Starts the event dispatcher.
-
-    Initiates executor and start polling events.
-
-    Raises:
-      IllegalStateError: Can't start a dispatcher again when it's already
-        running.
-    """
-    if not self.started:
-      self.started = True
-      self.executor = futures.ThreadPoolExecutor(max_workers=32)
-      self.poller = self.executor.submit(self.poll_events)
-    else:
-      raise IllegalStateError("Dispatcher is already started.")
-
-  def clean_up(self):
-    """Clean up and release resources after the event dispatcher polling
-    loop has been broken.
-
-    The following things happen:
-    1. Clear all events and flags.
-    2. Close the sl4a client the event_dispatcher object holds.
-    3. Shut down executor without waiting.
-    """
-    if not self.started:
-      return
-    self.started = False
-    self.clear_all_events()
-    # At this point, the sl4a apk is destroyed and nothing is listening on
-    # the socket. Avoid sending any sl4a commands; just clean up the socket
-    # and return.
-    self._sl4a.disconnect()
-    self.poller.set_result("Done")
-    # The polling thread is guaranteed to finish after a max of 60 seconds,
-    # so we don't wait here.
-    self.executor.shutdown(wait=False)
-
-  def pop_event(self, event_name, timeout=DEFAULT_TIMEOUT):
-    """Pop an event from its queue.
-
-    Return and remove the oldest entry of an event.
-    Block until an event of specified name is available or
-    times out if timeout is set.
-
-    Args:
-      event_name: Name of the event to be popped.
-      timeout: Number of seconds to wait when event is not present.
-        Never times out if None.
-
-    Returns:
-      The oldest entry of the specified event. None if timed out.
-
-    Raises:
-      IllegalStateError: Raised if pop is called before the dispatcher
-        starts polling.
-    """
-    if not self.started:
-      raise IllegalStateError("Dispatcher needs to be started before popping.")
-
-    e_queue = self.get_event_q(event_name)
-
-    if not e_queue:
-      raise TypeError("Failed to get an event queue for {}".format(event_name))
-
-    try:
-      # Block for timeout
-      if timeout:
-        return e_queue.get(True, timeout)
-      # Non-blocking poll for event
-      elif timeout == 0:
-        return e_queue.get(False)
-      else:
-        # Block forever on event wait
-        return e_queue.get(True)
-    except queue.Empty:
-      raise queue.Empty(
-          "Timeout after {}s waiting for event: {}".format(timeout, event_name)
-      )
-
-  def wait_for_event(
-      self, event_name, predicate, timeout=DEFAULT_TIMEOUT, *args, **kwargs
-  ):
-    """Wait for an event that satisfies a predicate to appear.
-
-    Continuously pop events of a particular name and check against the
-    predicate until an event that satisfies the predicate is popped or
-    timed out. Note this will remove all the events of the same name that
-    do not satisfy the predicate in the process.
-
-    Args:
-      event_name: Name of the event to be popped.
-      predicate: A function that takes an event and returns True if the
-        predicate is satisfied, False otherwise.
-      timeout: Number of seconds to wait.
-      *args: Optional positional args passed to predicate().
-      **kwargs: Optional keyword args passed to predicate().
-
-    Returns:
-      The event that satisfies the predicate.
-
-    Raises:
-      queue.Empty: Raised if no event that satisfies the predicate was
-        found before time out.
-    """
-    deadline = time.perf_counter() + timeout
-
-    while True:
-      event = None
-      try:
-        event = self.pop_event(event_name, 1)
-      except queue.Empty:
-        pass
-
-      if event and predicate(event, *args, **kwargs):
-        return event
-
-      if time.perf_counter() > deadline:
-        raise queue.Empty(
-            "Timeout after {}s waiting for event: {}".format(
-                timeout, event_name
-            )
-        )
-
-  def pop_events(self, regex_pattern, timeout):
-    """Pop events whose names match a regex pattern.
-
-    If such event(s) exist, pop one event from each event queue that
-    satisfies the condition. Otherwise, wait for an event that satisfies
-    the condition to occur, with timeout.
-
-    Results are sorted by timestamp in ascending order.
-
-    Args:
-      regex_pattern: The regular expression pattern that an event name
-        should match in order to be popped.
-      timeout: Number of seconds to wait for events in case no event
-        matching the condition exits when the function is called.
-
-    Returns:
-      Events whose names match a regex pattern.
-      Empty if none exist and the wait timed out.
-
-    Raises:
-      IllegalStateError: Raised if pop is called before the dispatcher
-        starts polling.
-      queue.Empty: Raised if no event was found before time out.
-    """
-    if not self.started:
-      raise IllegalStateError("Dispatcher needs to be started before popping.")
-    deadline = time.perf_counter() + timeout
-    while True:
-      # TODO: fix the sleep loop
-      results = self._match_and_pop(regex_pattern)
-      if len(results) != 0 or time.perf_counter() > deadline:
-        break
-      time.sleep(1)
-    if len(results) == 0:
-      raise queue.Empty(
-          "Timeout after {}s waiting for event: {}".format(
-              timeout, regex_pattern
-          )
-      )
-
-    return sorted(results, key=lambda event: event["time"])
-
-  def _match_and_pop(self, regex_pattern):
-    """Pop one event from each of the event queues whose names
-    match (in a sense of regular expression) regex_pattern.
-    """
-    results = []
-    self.lock.acquire()
-    for name in self.event_dict.keys():
-      if re.match(regex_pattern, name):
-        q = self.event_dict[name]
-        if q:
-          try:
-            results.append(q.get(False))
-          except Exception:
-            pass
-    self.lock.release()
-    return results
-
-  def get_event_q(self, event_name):
-    """Obtain the queue storing events of the specified name.
-
-    If no event of this name has been polled, wait for one to.
-
-    Returns:
-      A queue storing all the events of the specified name.
-      None if timed out.
-
-    Raises:
-      queue.Empty: Raised if the queue does not exist and timeout has
-        passed.
-    """
-    self.lock.acquire()
-    if event_name not in self.event_dict or self.event_dict[event_name] is None:
-      self.event_dict[event_name] = queue.Queue()
-    self.lock.release()
-
-    event_queue = self.event_dict[event_name]
-    return event_queue
-
-  def handle_subscribed_event(self, event_obj, event_name):
-    """Execute the registered handler of an event.
-
-    Retrieve the handler and its arguments, and execute the handler in a
-      new thread.
-
-    Args:
-      event_obj: Json object of the event.
-      event_name: Name of the event to call handler for.
-    """
-    handler, args = self.handlers[event_name]
-    self.executor.submit(handler, event_obj, *args)
-
-  def _handle(
-      self,
-      event_handler,
-      event_name,
-      user_args,
-      event_timeout,
-      cond,
-      cond_timeout,
-  ):
-    """Pop an event of specified type and calls its handler on it. If
-    condition is not None, block until condition is met or timeout.
-    """
-    if cond:
-      cond.wait(cond_timeout)
-    event = self.pop_event(event_name, event_timeout)
-    return event_handler(event, *user_args)
-
-  def handle_event(
-      self,
-      event_handler,
-      event_name,
-      user_args,
-      event_timeout=None,
-      cond=None,
-      cond_timeout=None,
-  ):
-    """Handle events that don't have registered handlers
-
-    In a new thread, poll one event of specified type from its queue and
-    execute its handler. If no such event exists, the thread waits until
-    one appears.
-
-    Args:
-      event_handler: Handler for the event, which should take at least
-        one argument - the event json object.
-      event_name: Name of the event to be handled.
-      user_args: User arguments for the handler; to be passed in after
-        the event json.
-      event_timeout: Number of seconds to wait for the event to come.
-      cond: A condition to wait on before executing the handler. Should
-        be a threading.Event object.
-      cond_timeout: Number of seconds to wait before the condition times
-        out. Never times out if None.
-
-    Returns:
-      A concurrent.Future object associated with the handler.
-      If blocking call worker.result() is triggered, the handler
-      needs to return something to unblock.
-    """
-    worker = self.executor.submit(
-        self._handle,
-        event_handler,
-        event_name,
-        user_args,
-        event_timeout,
-        cond,
-        cond_timeout,
-    )
-    return worker
-
-  def pop_all(self, event_name):
-    """Return and remove all stored events of a specified name.
-
-    Pops all events from their queue. May miss the latest ones.
-    If no event is available, return immediately.
-
-    Args:
-      event_name: Name of the events to be popped.
-
-    Returns:
-      List of the desired events.
-
-    Raises:
-      IllegalStateError: Raised if pop is called before the dispatcher
-        starts polling.
-    """
-    if not self.started:
-      raise IllegalStateError("Dispatcher needs to be started before popping.")
-    results = []
-    try:
-      self.lock.acquire()
-      while True:
-        e = self.event_dict[event_name].get(block=False)
-        results.append(e)
-    except (queue.Empty, KeyError):
-      return results
-    finally:
-      self.lock.release()
-
-  def clear_events(self, event_name):
-    """Clear all events of a particular name.
-
-    Args:
-      event_name: Name of the events to be popped.
-    """
-    self.lock.acquire()
-    try:
-      q = self.get_event_q(event_name)
-      q.queue.clear()
-    except queue.Empty:
-      return
-    finally:
-      self.lock.release()
-
-  def clear_all_events(self):
-    """Clear all event queues and their cached events."""
-    self.lock.acquire()
-    self.event_dict.clear()
-    self.lock.release()
diff --git a/mobly/controllers/android_device_lib/fastboot.py b/mobly/controllers/android_device_lib/fastboot.py
index cac08f1..e4aab8e 100644
--- a/mobly/controllers/android_device_lib/fastboot.py
+++ b/mobly/controllers/android_device_lib/fastboot.py
@@ -17,6 +17,9 @@ from subprocess import Popen, PIPE
 
 from mobly import utils
 
+# Command to use for running fastboot commands.
+FASTBOOT = 'fastboot'
+
 
 def exe_cmd(*cmds):
   """Executes commands in a new shell. Directing stderr to PIPE.
@@ -60,16 +63,17 @@ class FastbootProxy:
 
   def __init__(self, serial=''):
     self.serial = serial
-    if serial:
-      self.fastboot_str = 'fastboot -s {}'.format(serial)
-    else:
-      self.fastboot_str = 'fastboot'
+
+  def fastboot_str(self):
+    if self.serial:
+      return '{} -s {}'.format(FASTBOOT, self.serial)
+    return FASTBOOT
 
   def _exec_fastboot_cmd(self, name, arg_str):
-    return exe_cmd(' '.join((self.fastboot_str, name, arg_str)))
+    return exe_cmd(' '.join((self.fastboot_str(), name, arg_str)))
 
   def args(self, *args):
-    return exe_cmd(' '.join((self.fastboot_str,) + args))
+    return exe_cmd(' '.join((self.fastboot_str(),) + args))
 
   def __getattr__(self, name):
     def fastboot_call(*args):
diff --git a/mobly/controllers/android_device_lib/jsonrpc_shell_base.py b/mobly/controllers/android_device_lib/jsonrpc_shell_base.py
index c6d395b..1a2f304 100755
--- a/mobly/controllers/android_device_lib/jsonrpc_shell_base.py
+++ b/mobly/controllers/android_device_lib/jsonrpc_shell_base.py
@@ -61,8 +61,7 @@ class JsonRpcShellBase:
       else:
         raise Error(
             'Expected one phone, but %d found. Use the -s flag or '
-            'specify ANDROID_SERIAL.'
-            % len(serials)
+            'specify ANDROID_SERIAL.' % len(serials)
         )
     if serial not in serials:
       raise Error('Device "%s" is not found by adb.' % serial)
diff --git a/mobly/controllers/android_device_lib/service_manager.py b/mobly/controllers/android_device_lib/service_manager.py
index 17d5a1f..08fbaa1 100644
--- a/mobly/controllers/android_device_lib/service_manager.py
+++ b/mobly/controllers/android_device_lib/service_manager.py
@@ -122,6 +122,25 @@ class ServiceManager:
       ):
         func(self._service_objects[alias])
 
+  def get_service_alias_by_class(self, service_class):
+    """Gets the aslias name of a registered service.
+
+    The same service class can be registered multiple times with different
+    aliases. When not well managed, duplication and race conditions can arise.
+    One can use this API to de-duplicate as needed.
+
+    Args:
+      service_class: class, the class of a service type.
+
+    Returns:
+      list of strings, the aliases the service is registered with.
+    """
+    aliases = []
+    for alias, service_object in self._service_objects.items():
+      if isinstance(service_object, service_class):
+        aliases.append(alias)
+    return aliases
+
   def list_live_services(self):
     """Lists the aliases of all the services that are alive.
 
diff --git a/mobly/controllers/android_device_lib/services/sl4a_service.py b/mobly/controllers/android_device_lib/services/sl4a_service.py
deleted file mode 100644
index d5c5128..0000000
--- a/mobly/controllers/android_device_lib/services/sl4a_service.py
+++ /dev/null
@@ -1,60 +0,0 @@
-# Copyright 2018 Google Inc.
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
-"""Module for the Sl4aService."""
-
-from mobly.controllers.android_device_lib import sl4a_client
-from mobly.controllers.android_device_lib.services import base_service
-
-
-class Sl4aService(base_service.BaseService):
-  """Service for managing sl4a's client.
-
-  Direct calls on the service object will forwarded to the client object as
-  syntactic sugar. So `Sl4aService.doFoo()` is equivalent to
-  `Sl4aClient.doFoo()`.
-  """
-
-  def __init__(self, device, configs=None):
-    del configs  # Never used.
-    self._ad = device
-    self._sl4a_client = None
-
-  @property
-  def is_alive(self):
-    return self._sl4a_client is not None
-
-  def start(self):
-    self._sl4a_client = sl4a_client.Sl4aClient(ad=self._ad)
-    self._sl4a_client.start_app_and_connect()
-
-  def stop(self):
-    if self.is_alive:
-      self._sl4a_client.stop_app()
-      self._sl4a_client = None
-
-  def pause(self):
-    # Need to stop dispatcher because it continuously polls the device.
-    # It's not necessary to stop the sl4a client.
-    self._sl4a_client.stop_event_dispatcher()
-    self._sl4a_client.clear_host_port()
-
-  def resume(self):
-    # Restore sl4a if needed.
-    self._sl4a_client.restore_app_connection()
-
-  def __getattr__(self, name):
-    """Forwards the getattr calls to the client itself."""
-    if self._sl4a_client:
-      return getattr(self._sl4a_client, name)
-    return self.__getattribute__(name)
diff --git a/mobly/controllers/android_device_lib/sl4a_client.py b/mobly/controllers/android_device_lib/sl4a_client.py
deleted file mode 100644
index ac59f5b..0000000
--- a/mobly/controllers/android_device_lib/sl4a_client.py
+++ /dev/null
@@ -1,168 +0,0 @@
-# Copyright 2016 Google Inc.
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
-"""JSON RPC interface to android scripting engine."""
-
-import time
-
-from mobly import utils
-from mobly.controllers.android_device_lib import event_dispatcher
-from mobly.controllers.android_device_lib import jsonrpc_client_base
-
-_APP_NAME = 'SL4A'
-_DEVICE_SIDE_PORT = 8080
-_LAUNCH_CMD = (
-    'am start -a com.googlecode.android_scripting.action.LAUNCH_SERVER '
-    '--ei com.googlecode.android_scripting.extra.USE_SERVICE_PORT %s '
-    'com.googlecode.android_scripting/.activity.ScriptingLayerServiceLauncher'
-)
-# Maximum time to wait for the app to start on the device (10 minutes).
-# TODO: This timeout is set high in order to allow for retries in
-# start_app_and_connect. Decrease it when the call to connect() has the option
-# for a quicker timeout than the default _cmd() timeout.
-# TODO: Evaluate whether the high timeout still makes sense for sl4a. It was
-# designed for user snippets which could be very slow to start depending on the
-# size of the snippet and main apps. sl4a can probably use a much smaller value.
-_APP_START_WAIT_TIME = 2 * 60
-
-
-class Sl4aClient(jsonrpc_client_base.JsonRpcClientBase):
-  """A client for interacting with SL4A using Mobly Snippet Lib.
-
-  Extra public attributes:
-  ed: Event dispatcher instance for this sl4a client.
-  """
-
-  def __init__(self, ad):
-    """Initializes an Sl4aClient.
-
-    Args:
-      ad: AndroidDevice object.
-    """
-    super().__init__(app_name=_APP_NAME, ad=ad)
-    self._ad = ad
-    self.ed = None
-    self._adb = ad.adb
-
-  def start_app_and_connect(self):
-    """Overrides superclass."""
-    # Check that sl4a is installed
-    out = self._adb.shell('pm list package')
-    if not utils.grep('com.googlecode.android_scripting', out):
-      raise jsonrpc_client_base.AppStartError(
-          self._ad, '%s is not installed on %s' % (_APP_NAME, self._adb.serial)
-      )
-    self.disable_hidden_api_blacklist()
-
-    # sl4a has problems connecting after disconnection, so kill the apk and
-    # try connecting again.
-    try:
-      self.stop_app()
-    except Exception as e:
-      self.log.warning(e)
-
-    # Launch the app
-    self.device_port = _DEVICE_SIDE_PORT
-    self._adb.shell(_LAUNCH_CMD % self.device_port)
-
-    # Try to start the connection (not restore the connectivity).
-    # The function name restore_app_connection is used here is for the
-    # purpose of reusing the same code as it does when restoring the
-    # connection. And we do not want to come up with another function
-    # name to complicate the API. Change the name if necessary.
-    self.restore_app_connection()
-
-  def restore_app_connection(self, port=None):
-    """Restores the sl4a after device got disconnected.
-
-    Instead of creating new instance of the client:
-      - Uses the given port (or find a new available host_port if none is
-      given).
-      - Tries to connect to remote server with selected port.
-
-    Args:
-      port: If given, this is the host port from which to connect to remote
-        device port. If not provided, find a new available port as host
-        port.
-
-    Raises:
-      AppRestoreConnectionError: When the app was not able to be started.
-    """
-    self.host_port = port or utils.get_available_host_port()
-    self._retry_connect()
-    self.ed = self._start_event_client()
-
-  def stop_app(self):
-    """Overrides superclass."""
-    try:
-      if self._conn:
-        # Be polite; let the dest know we're shutting down.
-        try:
-          self.closeSl4aSession()
-        except Exception:
-          self.log.exception(
-              'Failed to gracefully shut down %s.', self.app_name
-          )
-
-        # Close the socket connection.
-        self.disconnect()
-        self.stop_event_dispatcher()
-
-      # Terminate the app
-      self._adb.shell('am force-stop com.googlecode.android_scripting')
-    finally:
-      # Always clean up the adb port
-      self.clear_host_port()
-
-  def stop_event_dispatcher(self):
-    # Close Event Dispatcher
-    if self.ed:
-      try:
-        self.ed.clean_up()
-      except Exception:
-        self.log.exception('Failed to shutdown sl4a event dispatcher.')
-      self.ed = None
-
-  def _retry_connect(self):
-    self._adb.forward(['tcp:%d' % self.host_port, 'tcp:%d' % self.device_port])
-    expiration_time = time.perf_counter() + _APP_START_WAIT_TIME
-    started = False
-    while time.perf_counter() < expiration_time:
-      self.log.debug('Attempting to start %s.', self.app_name)
-      try:
-        self.connect()
-        started = True
-        break
-      except Exception:
-        self.log.debug(
-            '%s is not yet running, retrying', self.app_name, exc_info=True
-        )
-      time.sleep(1)
-    if not started:
-      raise jsonrpc_client_base.AppRestoreConnectionError(
-          self._ad,
-          '%s failed to connect for %s at host port %s, device port %s'
-          % (self.app_name, self._adb.serial, self.host_port, self.device_port),
-      )
-
-  def _start_event_client(self):
-    # Start an EventDispatcher for the current sl4a session
-    event_client = Sl4aClient(self._ad)
-    event_client.host_port = self.host_port
-    event_client.device_port = self.device_port
-    event_client.connect(
-        uid=self.uid, cmd=jsonrpc_client_base.JsonRpcCommand.CONTINUE
-    )
-    ed = event_dispatcher.EventDispatcher(event_client)
-    ed.start()
-    return ed
diff --git a/mobly/controllers/android_device_lib/snippet_client_v2.py b/mobly/controllers/android_device_lib/snippet_client_v2.py
index 41376fb..b26226e 100644
--- a/mobly/controllers/android_device_lib/snippet_client_v2.py
+++ b/mobly/controllers/android_device_lib/snippet_client_v2.py
@@ -45,6 +45,9 @@ _STOP_CMD = (
     f'{_INSTRUMENTATION_RUNNER_PACKAGE}'
 )
 
+# The default timeout for running `_STOP_CMD`.
+_STOP_CMD_TIMEOUT_SEC = 30
+
 # Major version of the launch and communication protocol being used by this
 # client.
 # Incrementing this means that compatibility with clients using the older
@@ -703,7 +706,8 @@ class SnippetClientV2(client_base.ClientBase):
     out = self._adb.shell(
         _STOP_CMD.format(
             snippet_package=self.package, user=self._get_user_command_string()
-        )
+        ),
+        timeout=_STOP_CMD_TIMEOUT_SEC,
     ).decode('utf-8')
 
     if 'OK (0 tests)' not in out:
diff --git a/mobly/controllers/sniffer_lib/local/local_base.py b/mobly/controllers/sniffer_lib/local/local_base.py
index c81b108..0b2f6bf 100644
--- a/mobly/controllers/sniffer_lib/local/local_base.py
+++ b/mobly/controllers/sniffer_lib/local/local_base.py
@@ -81,12 +81,14 @@ class SnifferLocalBase(sniffer.Sniffer):
 
     if sniffer.Sniffer.CONFIG_KEY_CHANNEL in final_configs:
       try:
-        subprocess.check_call([
-            "iwconfig",
-            self._interface,
-            "channel",
-            str(final_configs[sniffer.Sniffer.CONFIG_KEY_CHANNEL]),
-        ])
+        subprocess.check_call(
+            [
+                "iwconfig",
+                self._interface,
+                "channel",
+                str(final_configs[sniffer.Sniffer.CONFIG_KEY_CHANNEL]),
+            ]
+        )
       except Exception as err:
         raise sniffer.ExecutionError(err)
 
diff --git a/mobly/suite_runner.py b/mobly/suite_runner.py
index b0b064c..a7f7cf1 100644
--- a/mobly/suite_runner.py
+++ b/mobly/suite_runner.py
@@ -114,8 +114,10 @@ def _parse_cli_args(argv):
       '--test_case',
       nargs='+',
       type=str,
-      metavar='[ClassA[.test_a] ClassB[.test_b] ...]',
-      help='A list of test classes and optional tests to execute.',
+      metavar='[ClassA[_test_suffix][.test_a] '
+      'ClassB[_test_suffix][.test_b] ...]',
+      help='A list of test classes and optional tests to execute. '
+      'Note: test_suffix based names are only supported when running by suite class',
   )
   parser.add_argument(
       '-tb',
@@ -137,21 +139,63 @@ def _parse_cli_args(argv):
   return parser.parse_known_args(argv)[0]
 
 
-def _find_suite_class():
-  """Finds the test suite class in the current module.
+def _find_suite_classes_in_module(module):
+  """Finds all test suite classes in the given module.
 
-  Walk through module members and find the subclass of BaseSuite. Only
-  one subclass is allowed in a module.
+  Walk through module members and find all classes that is a subclass of
+  BaseSuite.
+
+  Args:
+    module: types.ModuleType, the module object to find test suite classes.
 
   Returns:
-      The test suite class in the test module.
+    A list of test suite classes.
   """
   test_suites = []
-  main_module_members = sys.modules['__main__']
-  for _, module_member in main_module_members.__dict__.items():
+  for _, module_member in module.__dict__.items():
     if inspect.isclass(module_member):
       if issubclass(module_member, base_suite.BaseSuite):
         test_suites.append(module_member)
+  return test_suites
+
+
+def _find_suite_class():
+  """Finds the test suite class.
+
+  First search for test suite classes in the __main__ module. If no test suite
+  class is found, search in the module that is calling
+  `suite_runner.run_suite_class`.
+
+  Walk through module members and find the subclass of BaseSuite. Only
+  one subclass is allowed.
+
+  Returns:
+      The test suite class in the test module.
+  """
+  # Try to find test suites in __main__ module first.
+  test_suites = _find_suite_classes_in_module(sys.modules['__main__'])
+
+  # Try to find test suites in the module of the caller of `run_suite_class`.
+  if len(test_suites) == 0:
+    logging.debug(
+        'No suite class found in the __main__ module, trying to find it in the '
+        'module of the caller of suite_runner.run_suite_class method.'
+    )
+    stacks = inspect.stack()
+    if len(stacks) < 2:
+      logging.debug(
+          'Failed to get the caller stack of run_suite_class. Got stacks: %s',
+          stacks,
+      )
+    else:
+      run_suite_class_caller_frame_info = inspect.stack()[2]
+      caller_frame = run_suite_class_caller_frame_info.frame
+      module = inspect.getmodule(caller_frame)
+      if module is None:
+        logging.debug('Failed to find module for frame %s', caller_frame)
+      else:
+        test_suites = _find_suite_classes_in_module(module)
+
   if len(test_suites) != 1:
     logging.error(
         'Expected 1 test class per file, found %s.',
@@ -161,6 +205,33 @@ def _find_suite_class():
   return test_suites[0]
 
 
+def _print_test_names_for_suite(suite_class):
+  """Prints the names of all the tests in a suite classes.
+
+  Args:
+    suite_class: a test suite_class to be run.
+  """
+  config = config_parser.TestRunConfig()
+  runner = test_runner.TestRunner(
+      log_dir=config.log_path, testbed_name=config.testbed_name
+  )
+  cls = suite_class(runner, config)
+  try:
+    cls.setup_suite(config)
+  finally:
+    cls.teardown_suite()
+
+  last = ''
+  for name in runner.get_full_test_names():
+    tag = name.split('.')[0]
+    # Print tags when we encounter a new one. Prefer this to grouping by
+    # tag first since we should print any duplicate entries.
+    if tag != last:
+      last = tag
+      print('==========> %s <==========' % tag)
+    print(name)
+
+
 def _print_test_names(test_classes):
   """Prints the names of all the tests in all test classes.
   Args:
@@ -197,7 +268,7 @@ def run_suite_class(argv=None):
   cli_args = _parse_cli_args(argv)
   suite_class = _find_suite_class()
   if cli_args.list_tests:
-    _print_test_names([suite_class])
+    _print_test_names_for_suite(suite_class)
     sys.exit(0)
   test_configs = config_parser.load_test_config_file(
       cli_args.config, cli_args.test_bed
@@ -210,6 +281,8 @@ def run_suite_class(argv=None):
       log_dir=config.log_path, testbed_name=config.testbed_name
   )
   suite = suite_class(runner, config)
+  test_selector = _parse_raw_test_selector(cli_args.tests)
+  suite.set_test_selector(test_selector)
   console_level = logging.DEBUG if cli_args.verbose else logging.INFO
   ok = False
   with runner.mobly_logger(console_level=console_level):
@@ -287,8 +360,8 @@ def compute_selected_tests(test_classes, selected_tests):
   that class are selected.
 
   Args:
-    test_classes: list of strings, names of all the classes that are part
-      of a suite.
+    test_classes: list of `type[base_test.BaseTestClass]`, all the test classes
+      that are part of a suite.
     selected_tests: list of strings, list of tests to execute. If empty,
       all classes `test_classes` are selected. E.g.
 
@@ -324,31 +397,81 @@ def compute_selected_tests(test_classes, selected_tests):
     return class_to_tests
 
   # The user is selecting some tests to run. Parse the selectors.
-  # Dict from test_name class name to list of tests to execute (or None for all
-  # tests).
-  test_class_name_to_tests = collections.OrderedDict()
-  for test_name in selected_tests:
-    if '.' in test_name:  # Has a test method
-      (test_class_name, test_name) = test_name.split('.', maxsplit=1)
-      if test_class_name not in test_class_name_to_tests:
-        # Never seen this class before
-        test_class_name_to_tests[test_class_name] = [test_name]
-      elif test_class_name_to_tests[test_class_name] is None:
-        # Already running all tests in this class, so ignore this extra
-        # test.
-        pass
-      else:
-        test_class_name_to_tests[test_class_name].append(test_name)
-    else:  # No test method; run all tests in this class.
-      test_class_name_to_tests[test_name] = None
+  test_class_name_to_tests = _parse_raw_test_selector(selected_tests)
 
-  # Now transform class names to class objects.
-  # Dict from test_name class name to instance.
+  # Now compute the tests to run for each test class.
+  # Dict from test class name to class instance.
   class_name_to_class = {cls.__name__: cls for cls in test_classes}
-  for test_class_name, tests in test_class_name_to_tests.items():
+  for test_tuple, tests in test_class_name_to_tests.items():
+    (test_class_name, test_suffix) = test_tuple
+    if test_suffix != None:
+      raise Error('Suffixed tests only compatible with suite class runs')
     test_class = class_name_to_class.get(test_class_name)
     if not test_class:
-      raise Error('Unknown test_name class %s' % test_class_name)
+      raise Error('Unknown test_class name %s' % test_class_name)
     class_to_tests[test_class] = tests
 
   return class_to_tests
+
+
+def _parse_raw_test_selector(selected_tests):
+  """Parses test selector from CLI arguments.
+
+  This function transforms a list of selector strings (such as FooTest or
+  FooTest.test_method_a) to a dict where keys are a tuple containing
+  (test_class_name, test_suffix) and values are lists of selected tests in
+  those classes. None means all tests in that class are selected.
+
+  Args:
+    selected_tests: list of strings, list of tests to execute of the form:
+      <test_class_name>[_<test_suffix>][.<test_name>].
+
+    .. code-block:: python
+      [
+        'BarTest',
+        'FooTest_A',
+        'FooTest_B'
+        'FooTest_C.test_method_a'
+        'FooTest_C.test_method_b'
+        'BazTest.test_method_a',
+        'BazTest.test_method_b'
+      ]
+
+  Returns:
+    dict: Keys are a tuple of (test_class_name, test_suffix), and values are
+    lists of test names within class.
+      E.g. the example in
+      `tests` would translate to:
+
+      .. code-block:: python
+        {
+          (BarTest, None): None,
+          (FooTest, 'A'): None,
+          (FooTest, 'B'): None,
+          (FooTest,)'C'): ['test_method_a', 'test_method_b'],
+          (BazTest, None): ['test_method_a', 'test_method_b']
+        }
+  """
+  if selected_tests is None:
+    return None
+  test_class_to_tests = collections.OrderedDict()
+  for test in selected_tests:
+    test_class_name = test
+    test_name = None
+    test_suffix = None
+    if '.' in test_class_name:
+      (test_class_name, test_name) = test_class_name.split('.', maxsplit=1)
+    if '_' in test_class_name:
+      (test_class_name, test_suffix) = test_class_name.split('_', maxsplit=1)
+
+    key = (test_class_name, test_suffix)
+    if key not in test_class_to_tests:
+      test_class_to_tests[key] = []
+
+    # If the test name is None, it means all tests in the class are selected.
+    if test_name is None:
+      test_class_to_tests[key] = None
+    # Only add the test if we're not already running all tests in the class.
+    elif test_class_to_tests[key] is not None:
+      test_class_to_tests[key].append(test_name)
+  return test_class_to_tests
diff --git a/mobly/test_runner.py b/mobly/test_runner.py
index 5c97113..b32f5b0 100644
--- a/mobly/test_runner.py
+++ b/mobly/test_runner.py
@@ -126,8 +126,12 @@ def parse_mobly_cli_args(argv):
       '--test_case',
       nargs='+',
       type=str,
-      metavar='[test_a test_b...]',
-      help='A list of tests in the test class to execute.',
+      metavar='[test_a test_b re:test_(c|d)...]',
+      help=(
+          'A list of tests in the test class to execute. Each value can be a '
+          'test name string or a `re:` prefixed string for full regex match of'
+          ' test names.'
+      ),
   )
   parser.add_argument(
       '-tb',
@@ -306,6 +310,53 @@ class TestRunner:
         return None
       return self._end_counter - self._start_counter
 
+  def get_full_test_names(self):
+    """Returns the names of all tests that will be run in this test runner.
+
+    Returns:
+      A list of test names. Each test name is in the format of
+      <test.TAG>.<test_name>.
+    """
+    test_names = []
+    for test_run_info in self._test_run_infos:
+      test_config = test_run_info.config.copy()
+      test_config.test_class_name_suffix = test_run_info.test_class_name_suffix
+      test = test_run_info.test_class(test_config)
+
+      tests = self._get_test_names_from_class(test)
+      if test_run_info.tests is not None:
+        # If tests is provided, verify that all tests exist in the class.
+        tests_set = set(tests)
+        for test_name in test_run_info.tests:
+          if test_name not in tests_set:
+            raise Error(
+                'Unknown test method: %s in class %s', (test_name, test.TAG)
+            )
+          test_names.append(f'{test.TAG}.{test_name}')
+      else:
+        test_names.extend([f'{test.TAG}.{n}' for n in tests])
+
+    return test_names
+
+  def _get_test_names_from_class(self, test):
+    """Returns the names of all the tests in a test class.
+
+    Args:
+      test: module, the test module to print names from.
+    """
+    try:
+      # Executes pre-setup procedures, this is required since it might
+      # generate test methods that we want to return as well.
+      test._pre_run()
+      if test.tests:
+        # Specified by run list in class.
+        return list(test.tests)
+      else:
+        # No test method specified by user, list all in test class.
+        return test.get_existing_test_names()
+    finally:
+      test._clean_up()
+
   def __init__(self, log_dir, testbed_name):
     """Constructor for TestRunner.
 
diff --git a/mobly/utils.py b/mobly/utils.py
index 02125ed..f567c32 100644
--- a/mobly/utils.py
+++ b/mobly/utils.py
@@ -273,19 +273,19 @@ def _collect_process_tree(starting_pid):
 
   while stack:
     pid = stack.pop()
+    if platform.system() == 'Darwin':
+      command = ['pgrep', '-P', str(pid)]
+    else:
+      command = [
+          'ps',
+          '-o',
+          'pid',
+          '--ppid',
+          str(pid),
+          '--noheaders',
+      ]
     try:
-      ps_results = (
-          subprocess.check_output([
-              'ps',
-              '-o',
-              'pid',
-              '--ppid',
-              str(pid),
-              '--noheaders',
-          ])
-          .decode()
-          .strip()
-      )
+      ps_results = subprocess.check_output(command).decode().strip()
     except subprocess.CalledProcessError:
       # Ignore if there is not child process.
       continue
@@ -303,13 +303,15 @@ def _kill_process_tree(proc):
     # The taskkill command with "/T" option ends the specified process and any
     # child processes started by it:
     # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill
-    subprocess.check_output([
-        'taskkill',
-        '/F',
-        '/T',
-        '/PID',
-        str(proc.pid),
-    ])
+    subprocess.check_output(
+        [
+            'taskkill',
+            '/F',
+            '/T',
+            '/PID',
+            str(proc.pid),
+        ]
+    )
     return
 
   failed = []
@@ -495,10 +497,23 @@ def run_command(
     raise subprocess.TimeoutExpired(
         cmd=cmd, timeout=timeout, output=out, stderr=err
     )
+  logging.debug(
+      'cmd: %s, stdout: %s, stderr: %s, ret: %s',
+      cli_cmd_to_string(cmd),
+      out,
+      err,
+      process.returncode,
+  )
   return process.returncode, out, err
 
 
-def start_standing_subprocess(cmd, shell=False, env=None):
+def start_standing_subprocess(
+    cmd,
+    shell=False,
+    env=None,
+    stdout=subprocess.PIPE,
+    stderr=subprocess.PIPE,
+):
   """Starts a long-running subprocess.
 
   This is not a blocking call and the subprocess started by it should be
@@ -510,10 +525,14 @@ def start_standing_subprocess(cmd, shell=False, env=None):
   Args:
     cmd: string, the command to start the subprocess with.
     shell: bool, True to run this command through the system shell,
-      False to invoke it directly. See subprocess.Proc() docs.
+      False to invoke it directly. See subprocess.Popen() docs.
     env: dict, a custom environment to run the standing subprocess. If not
       specified, inherits the current environment. See subprocess.Popen()
       docs.
+    stdout: None, subprocess.PIPE, subprocess.DEVNULL, an existing file
+      descriptor, or an existing file object. See subprocess.Popen() docs.
+    stderr: None, subprocess.PIPE, subprocess.DEVNULL, an existing file
+      descriptor, or an existing file object. See subprocess.Popen() docs.
 
   Returns:
     The subprocess that was started.
@@ -522,8 +541,8 @@ def start_standing_subprocess(cmd, shell=False, env=None):
   proc = subprocess.Popen(
       cmd,
       stdin=subprocess.PIPE,
-      stdout=subprocess.PIPE,
-      stderr=subprocess.PIPE,
+      stdout=stdout,
+      stderr=stderr,
       shell=shell,
       env=env,
   )
diff --git a/pyproject.toml b/pyproject.toml
index 47bbbfc..bb35d30 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -4,7 +4,7 @@ build-backend = "setuptools.build_meta"
 
 [project]
 name = "mobly"
-version = "1.12.3"
+version = "1.12.4"
 description = "Automation framework for special end-to-end test cases"
 requires-python = ">=3.11"
 dependencies = [ "portpicker", "pywin32; platform_system == \"Windows\"", "pyyaml",]
@@ -18,14 +18,14 @@ text = "Apache2.0"
 
 [project.urls]
 Homepage = "https://github.com/google/mobly"
-Download = "https://github.com/google/mobly/tarball/1.12.3"
+Download = "https://github.com/google/mobly/tarball/1.12.4"
 
 [project.optional-dependencies]
 testing = [ "mock", "pytest", "pytz",]
 
 [tool.setuptools]
 include-package-data = false
-script-files = [ "tools/sl4a_shell.py", "tools/snippet_shell.py",]
+script-files = ["tools/snippet_shell.py"]
 
 [tool.pyink]
 line-length = 80
diff --git a/tests/lib/integration_test_suite.py b/tests/lib/integration_test_suite.py
new file mode 100644
index 0000000..dd95ab0
--- /dev/null
+++ b/tests/lib/integration_test_suite.py
@@ -0,0 +1,31 @@
+# Copyright 2024 Google Inc.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+from mobly import base_suite
+from mobly import suite_runner
+from tests.lib import integration_test
+
+
+class IntegrationTestSuite(base_suite.BaseSuite):
+
+  def setup_suite(self, config):
+    self.add_test_class(integration_test.IntegrationTest)
+
+
+def main():
+  suite_runner.run_suite_class()
+
+
+if __name__ == "__main__":
+  main()
diff --git a/tests/lib/mock_android_device.py b/tests/lib/mock_android_device.py
index cbc61f8..923c8c8 100755
--- a/tests/lib/mock_android_device.py
+++ b/tests/lib/mock_android_device.py
@@ -87,6 +87,7 @@ class MockAdbProxy:
       mock_properties=None,
       installed_packages=None,
       instrumented_packages=None,
+      adb_detectable=True,
   ):
     self.serial = serial
     self.fail_br = fail_br
@@ -101,6 +102,7 @@ class MockAdbProxy:
     self.installed_packages = installed_packages
     if instrumented_packages is None:
       instrumented_packages = []
+    self.adb_detectable = adb_detectable
     self.installed_packages = installed_packages
     self.instrumented_packages = instrumented_packages
 
@@ -124,10 +126,13 @@ class MockAdbProxy:
       )
     elif 'pm list instrumentation' in params:
       return bytes(
-          '\n'.join([
-              'instrumentation:%s/%s (target=%s)' % (package, runner, target)
-              for package, runner, target in self.instrumented_packages
-          ]),
+          '\n'.join(
+              [
+                  'instrumentation:%s/%s (target=%s)'
+                  % (package, runner, target)
+                  for package, runner, target in self.instrumented_packages
+              ]
+          ),
           'utf-8',
       )
     elif 'which' in params:
@@ -151,6 +156,12 @@ class MockAdbProxy:
     if expected not in args:
       raise Error('"Expected "%s", got "%s"' % (expected, args))
 
+  def devices(self):
+    out = b'xxxx\tdevice\nyyyy\tdevice'
+    if self.adb_detectable:
+      out += f'\n{self.serial}\tdevice'.encode()
+    return out
+
   def __getattr__(self, name):
     """All calls to the none-existent functions in adb proxy would
     simply return the adb command string.
diff --git a/tests/mobly/base_suite_test.py b/tests/mobly/base_suite_test.py
new file mode 100644
index 0000000..43f9213
--- /dev/null
+++ b/tests/mobly/base_suite_test.py
@@ -0,0 +1,139 @@
+# Copyright 2024 Google Inc.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import io
+import os
+import shutil
+import sys
+import tempfile
+import unittest
+from unittest import mock
+
+from mobly import base_suite
+from mobly import base_test
+from mobly import suite_runner
+from mobly import test_runner
+from mobly import config_parser
+from tests.lib import integration2_test
+from tests.lib import integration_test
+
+
+class FakeTest1(base_test.BaseTestClass):
+
+  def test_a(self):
+    pass
+
+  def test_b(self):
+    pass
+
+  def test_c(self):
+    pass
+
+
+class FakeTest2(base_test.BaseTestClass):
+
+  def test_2(self):
+    pass
+
+
+class FakeTestSuite(base_suite.BaseSuite):
+
+  def setup_suite(self, config):
+    self.add_test_class(FakeTest1, config)
+    self.add_test_class(FakeTest2, config)
+
+
+class FakeTestSuiteWithFilteredTests(base_suite.BaseSuite):
+
+  def setup_suite(self, config):
+    self.add_test_class(FakeTest1, config, ['test_a', 'test_b'])
+    self.add_test_class(FakeTest2, config, ['test_2'])
+
+
+class BaseSuiteTest(unittest.TestCase):
+
+  def setUp(self):
+    super().setUp()
+    self.mock_config = mock.Mock(autospec=config_parser.TestRunConfig)
+    self.mock_test_runner = mock.Mock(autospec=test_runner.TestRunner)
+
+  def test_setup_suite(self):
+    suite = FakeTestSuite(self.mock_test_runner, self.mock_config)
+    suite.set_test_selector(None)
+
+    suite.setup_suite(self.mock_config)
+
+    self.mock_test_runner.add_test_class.assert_has_calls(
+        [
+            mock.call(self.mock_config, FakeTest1, mock.ANY, mock.ANY),
+            mock.call(self.mock_config, FakeTest2, mock.ANY, mock.ANY),
+        ],
+    )
+
+  def test_setup_suite_with_test_selector(self):
+    suite = FakeTestSuite(self.mock_test_runner, self.mock_config)
+    test_selector = {
+        'FakeTest1': ['test_a', 'test_b'],
+        'FakeTest2': None,
+    }
+
+    suite.set_test_selector(test_selector)
+    suite.setup_suite(self.mock_config)
+
+    self.mock_test_runner.add_test_class.assert_has_calls(
+        [
+            mock.call(
+                self.mock_config, FakeTest1, ['test_a', 'test_b'], mock.ANY
+            ),
+            mock.call(self.mock_config, FakeTest2, None, mock.ANY),
+        ],
+    )
+
+  def test_setup_suite_test_selector_takes_precedence(self):
+    suite = FakeTestSuiteWithFilteredTests(
+        self.mock_test_runner, self.mock_config
+    )
+    test_selector = {
+        'FakeTest1': ['test_a', 'test_c'],
+        'FakeTest2': None,
+    }
+
+    suite.set_test_selector(test_selector)
+    suite.setup_suite(self.mock_config)
+
+    self.mock_test_runner.add_test_class.assert_has_calls(
+        [
+            mock.call(
+                self.mock_config, FakeTest1, ['test_a', 'test_c'], mock.ANY
+            ),
+            mock.call(self.mock_config, FakeTest2, None, mock.ANY),
+        ],
+    )
+
+  def test_setup_suite_with_skip_test_class(self):
+    suite = FakeTestSuite(self.mock_test_runner, self.mock_config)
+    test_selector = {'FakeTest1': None}
+
+    suite.set_test_selector(test_selector)
+    suite.setup_suite(self.mock_config)
+
+    self.mock_test_runner.add_test_class.assert_has_calls(
+        [
+            mock.call(self.mock_config, FakeTest1, None, mock.ANY),
+        ],
+    )
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/tests/mobly/base_test_test.py b/tests/mobly/base_test_test.py
index bfc7b75..f389133 100755
--- a/tests/mobly/base_test_test.py
+++ b/tests/mobly/base_test_test.py
@@ -201,6 +201,96 @@ class BaseTestTest(unittest.TestCase):
     actual_record = bt_cls.results.passed[0]
     self.assertEqual(actual_record.test_name, 'test_something')
 
+  def test_cli_test_selection_with_regex(self):
+    class MockBaseTest(base_test.BaseTestClass):
+
+      def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = ('test_never',)
+
+      def test_foo(self):
+        pass
+
+      def test_a(self):
+        pass
+
+      def test_b(self):
+        pass
+
+      def test_something_1(self):
+        pass
+
+      def test_something_2(self):
+        pass
+
+      def test_something_3(self):
+        pass
+
+      def test_never(self):
+        # This should not execute since it's not selected by cmd line input.
+        never_call()
+
+    bt_cls = MockBaseTest(self.mock_test_cls_configs)
+    bt_cls.run(test_names=['re:test_something_.*', 'test_foo', 're:test_(a|b)'])
+    self.assertEqual(len(bt_cls.results.passed), 6)
+    self.assertEqual(bt_cls.results.passed[0].test_name, 'test_something_1')
+    self.assertEqual(bt_cls.results.passed[1].test_name, 'test_something_2')
+    self.assertEqual(bt_cls.results.passed[2].test_name, 'test_something_3')
+    self.assertEqual(bt_cls.results.passed[3].test_name, 'test_foo')
+    self.assertEqual(bt_cls.results.passed[4].test_name, 'test_a')
+    self.assertEqual(bt_cls.results.passed[5].test_name, 'test_b')
+
+  def test_cli_test_selection_with_regex_generated_tests(self):
+    class MockBaseTest(base_test.BaseTestClass):
+
+      def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = ('test_never',)
+
+      def pre_run(self):
+        self.generate_tests(
+            test_logic=self.logic,
+            name_func=lambda i: f'test_something_{i}',
+            arg_sets=[(i + 1,) for i in range(3)],
+        )
+
+      def test_foo(self):
+        pass
+
+      def logic(self, _):
+        pass
+
+      def test_never(self):
+        # This should not execute since it's not selected by cmd line input.
+        never_call()
+
+    bt_cls = MockBaseTest(self.mock_test_cls_configs)
+    bt_cls.run(test_names=['re:test_something_.*', 'test_foo'])
+    self.assertEqual(len(bt_cls.results.passed), 4)
+    self.assertEqual(bt_cls.results.passed[0].test_name, 'test_something_1')
+    self.assertEqual(bt_cls.results.passed[1].test_name, 'test_something_2')
+    self.assertEqual(bt_cls.results.passed[2].test_name, 'test_something_3')
+    self.assertEqual(bt_cls.results.passed[3].test_name, 'test_foo')
+
+  def test_cli_test_selection_with_regex_fail_by_convention(self):
+    class MockBaseTest(base_test.BaseTestClass):
+
+      def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = ('test_never',)
+
+      def test_something(self):
+        pass
+
+    bt_cls = MockBaseTest(self.mock_test_cls_configs)
+    expected_msg = (
+        r'not_a_test_something does not match with any valid test case in '
+        r'MockBaseTest, abort!'
+    )
+    with self.assertRaisesRegex(base_test.Error, expected_msg):
+      bt_cls.run(test_names=['re:not_a_test_something'])
+    self.assertEqual(len(bt_cls.results.passed), 0)
+
   def test_cli_test_selection_fail_by_convention(self):
     class MockBaseTest(base_test.BaseTestClass):
 
@@ -2038,63 +2128,6 @@ class BaseTestTest(unittest.TestCase):
     self.assertEqual(class_record.test_name, 'pre_run')
     self.assertEqual(bt_cls.results.skipped, [])
 
-  # TODO(angli): remove after the full deprecation of `setup_generated_tests`.
-  def test_setup_generated_tests(self):
-    class MockBaseTest(base_test.BaseTestClass):
-
-      def setup_generated_tests(self):
-        self.generate_tests(
-            test_logic=self.logic,
-            name_func=self.name_gen,
-            arg_sets=[(1, 2), (3, 4)],
-        )
-
-      def name_gen(self, a, b):
-        return 'test_%s_%s' % (a, b)
-
-      def logic(self, a, b):
-        pass
-
-    bt_cls = MockBaseTest(self.mock_test_cls_configs)
-    bt_cls.run()
-    self.assertEqual(len(bt_cls.results.requested), 2)
-    self.assertEqual(len(bt_cls.results.passed), 2)
-    self.assertIsNone(bt_cls.results.passed[0].uid)
-    self.assertIsNone(bt_cls.results.passed[1].uid)
-    self.assertEqual(bt_cls.results.passed[0].test_name, 'test_1_2')
-    self.assertEqual(bt_cls.results.passed[1].test_name, 'test_3_4')
-
-  # TODO(angli): remove after the full deprecation of `setup_generated_tests`.
-  def test_setup_generated_tests_failure(self):
-    """Test code path for setup_generated_tests failure.
-
-    When setup_generated_tests fails, pre-execution calculation is
-    incomplete and the number of tests requested is unknown. This is a
-    fatal issue that blocks any test execution in a class.
-
-    A class level error record is generated.
-    Unlike `setup_class` failure, no test is considered "skipped" in this
-    case as execution stage never started.
-    """
-
-    class MockBaseTest(base_test.BaseTestClass):
-
-      def setup_generated_tests(self):
-        raise Exception(MSG_EXPECTED_EXCEPTION)
-
-      def logic(self, a, b):
-        pass
-
-      def test_foo(self):
-        pass
-
-    bt_cls = MockBaseTest(self.mock_test_cls_configs)
-    bt_cls.run()
-    self.assertEqual(len(bt_cls.results.requested), 0)
-    class_record = bt_cls.results.error[0]
-    self.assertEqual(class_record.test_name, 'pre_run')
-    self.assertEqual(bt_cls.results.skipped, [])
-
   def test_generate_tests_run(self):
     class MockBaseTest(base_test.BaseTestClass):
 
@@ -2218,7 +2251,7 @@ class BaseTestTest(unittest.TestCase):
     self.assertEqual(
         actual_record.details,
         "'generate_tests' cannot be called outside of the followin"
-        "g functions: ['pre_run', 'setup_generated_tests'].",
+        "g functions: ['pre_run'].",
     )
     expected_summary = (
         'Error 1, Executed 1, Failed 0, Passed 0, Requested 1, Skipped 0'
diff --git a/tests/mobly/controllers/android_device_lib/adb_test.py b/tests/mobly/controllers/android_device_lib/adb_test.py
index 65c7eb5..689f493 100755
--- a/tests/mobly/controllers/android_device_lib/adb_test.py
+++ b/tests/mobly/controllers/android_device_lib/adb_test.py
@@ -23,10 +23,12 @@ from mobly.controllers.android_device_lib import adb
 # Mock parameters for instrumentation.
 MOCK_INSTRUMENTATION_PACKAGE = 'com.my.instrumentation.tests'
 MOCK_INSTRUMENTATION_RUNNER = 'com.my.instrumentation.runner'
-MOCK_INSTRUMENTATION_OPTIONS = collections.OrderedDict([
-    ('option1', 'value1'),
-    ('option2', 'value2'),
-])
+MOCK_INSTRUMENTATION_OPTIONS = collections.OrderedDict(
+    [
+        ('option1', 'value1'),
+        ('option2', 'value2'),
+    ]
+)
 # Mock android instrumentation commands.
 MOCK_BASIC_INSTRUMENTATION_COMMAND = (
     'am instrument -r -w  com.my'
@@ -638,12 +640,14 @@ class AdbTest(unittest.TestCase):
           b'[sys.wifitracing.started]: [1]\n'
           b'[telephony.lteOnCdmaDevice]: [1]\n\n'
       )
-      actual_output = adb.AdbProxy().getprops([
-          'sys.wifitracing.started',  # "numeric" value
-          'sys.uidcpupower',  # empty value
-          'sendbug.preferred.domain',  # string value
-          'nonExistentProp',
-      ])
+      actual_output = adb.AdbProxy().getprops(
+          [
+              'sys.wifitracing.started',  # "numeric" value
+              'sys.uidcpupower',  # empty value
+              'sendbug.preferred.domain',  # string value
+              'nonExistentProp',
+          ]
+      )
       self.assertEqual(
           actual_output,
           {
diff --git a/tests/mobly/controllers/android_device_lib/apk_utils_test.py b/tests/mobly/controllers/android_device_lib/apk_utils_test.py
new file mode 100644
index 0000000..f6180a7
--- /dev/null
+++ b/tests/mobly/controllers/android_device_lib/apk_utils_test.py
@@ -0,0 +1,323 @@
+# Copyright 2024 Google Inc.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import unittest
+from unittest import mock
+
+from mobly.controllers.android_device_lib import adb
+from mobly.controllers.android_device_lib import apk_utils
+from mobly.controllers.android_device_lib import errors
+
+
+DEFAULT_INSTALL_TIMEOUT_SEC = 300
+APK_PATH = 'some/apk/path'
+
+
+class ApkUtilsTest(unittest.TestCase):
+
+  def setUp(self):
+    super(ApkUtilsTest, self).setUp()
+    self.mock_device = mock.MagicMock()
+    self.mock_device.adb.current_user_id = 0
+
+  def test_install_default_version(self):
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.adb.install.assert_called_with(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_sdk17(self):
+    self.mock_device.build_info = {'build_version_sdk': 17}
+    self.mock_device.adb.getprop.return_value = 'none'
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.adb.install.assert_called_with(
+        ['-r', '-t', '-d', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_sdk23(self):
+    self.mock_device.build_info = {'build_version_sdk': 23}
+    self.mock_device.adb.getprop.return_value = 'none'
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.adb.install.assert_called_with(
+        ['-r', '-t', '-g', '-d', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_sdk25(self):
+    self.mock_device.build_info = {'build_version_sdk': 25}
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.adb.install.assert_called_with(
+        ['--user', '0', '-r', '-t', '-g', '-d', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_with_user_id(self):
+    self.mock_device.build_info = {'build_version_sdk': 25}
+    apk_utils.install(self.mock_device, APK_PATH, user_id=123)
+    self.mock_device.adb.install.assert_called_with(
+        ['--user', '123', '-r', '-t', '-g', '-d', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_with_params(self):
+    param = '--force-queryable'
+    apk_utils.install(self.mock_device, APK_PATH, params=[param])
+    self.mock_device.adb.install.assert_called_with(
+        ['-r', '-t', param, APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_with_user_id_sdk_too_low(self):
+    self.mock_device.build_info = {'build_version_sdk': 21}
+    with self.assertRaisesRegex(
+        ValueError, 'Cannot specify `user_id` for device below SDK 24.'
+    ):
+      apk_utils.install(self.mock_device, APK_PATH, user_id=123)
+
+  def test_install_adb_raise_error_no_retry(self):
+    self.mock_device.adb.install.side_effect = adb.AdbError(
+        cmd='adb install -s xxx', stdout='aaa', stderr='bbb', ret_code=1
+    )
+    with self.assertRaisesRegex(
+        adb.AdbError,
+        'Error executing adb cmd "adb install -s xxx".'
+        ' ret: 1, stdout: aaa, stderr: bbb',
+    ):
+      apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_not_called()
+    self.mock_device.adb.install.assert_called_once_with(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_adb_fail_by_stdout_raise_no_retry(self):
+    self.mock_device.adb.install.return_value = b'Failure'
+    with self.assertRaisesRegex(
+        adb.AdbError,
+        '^Error executing adb cmd "adb -s .* some/apk/path". ret: 0, stdout:'
+        ' .*Failure.*, stderr: $',
+    ):
+      apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_not_called()
+    self.mock_device.adb.install.assert_called_once_with(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  @mock.patch('io.BytesIO')
+  def test_install_adb_fail_by_stderr_raise_no_retry(self, mock_bytes_io):
+    byte_io = mock.MagicMock()
+    byte_io.getvalue.return_value = b'Some error'
+    mock_bytes_io.return_value = byte_io
+    self.mock_device.adb.install.return_value = b''
+    with self.assertRaisesRegex(
+        adb.AdbError,
+        '^Error executing adb cmd "adb -s .* some/apk/path". ret: 0, '
+        'stdout: .*, stderr: Some error',
+    ):
+      apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_not_called()
+    self.mock_device.adb.install.assert_called_once_with(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  @mock.patch('io.BytesIO')
+  def test_install_adb_pass_by_stderr_message(self, mock_bytes_io):
+    byte_io = mock.MagicMock()
+    byte_io.getvalue.return_value = b'Success'
+    mock_bytes_io.return_value = byte_io
+    self.mock_device.adb.install.return_value = b''
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_not_called()
+    self.mock_device.adb.install.assert_called_once_with(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+
+  def test_install_adb_raise_error_retry_also_fail(self):
+    self.mock_device.adb.install.side_effect = adb.AdbError(
+        cmd='adb install -s xxx',
+        stdout='aaa',
+        stderr='[INSTALL_FAILED_INSUFFICIENT_STORAGE]',
+        ret_code=1,
+    )
+    with self.assertRaisesRegex(
+        adb.AdbError,
+        r'Error executing adb cmd "adb install -s xxx".'
+        r' ret: 1, stdout: aaa, stderr:'
+        r' \[INSTALL_FAILED_INSUFFICIENT_STORAGE\]',
+    ):
+      apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_called_once_with()
+    expected_call = mock.call(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+    self.mock_device.adb.install.assert_has_calls(
+        [expected_call, expected_call]
+    )
+
+  def test_install_adb_fail_by_stdout_error_retry_also_fail(self):
+    self.mock_device.adb.install.return_value = (
+        b'Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]'
+    )
+    with self.assertRaisesRegex(
+        adb.AdbError,
+        r'^Error executing adb cmd "adb -s .* some/apk/path". ret: 0, '
+        r'stdout: .*Failure \[INSTALL_FAILED_INSUFFICIENT_STORAGE\].*, '
+        r'stderr: $',
+    ):
+      apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_called_once_with()
+    expected_call = mock.call(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+    self.mock_device.adb.install.assert_has_calls(
+        [expected_call, expected_call]
+    )
+
+  def test_install_adb_raise_error_retry_pass(self):
+    error = adb.AdbError(
+        cmd='adb install -s xxx',
+        stdout='aaa',
+        stderr='[INSTALL_FAILED_INSUFFICIENT_STORAGE]',
+        ret_code=1,
+    )
+    self.mock_device.adb.install.side_effect = [error, b'Success!']
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_called_once_with()
+    expected_call = mock.call(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+    self.mock_device.adb.install.assert_has_calls(
+        [expected_call, expected_call]
+    )
+
+  def test_install_adb_fail_without_raise_retry_pass(self):
+    self.mock_device.adb.install.side_effect = [
+        b'Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]',
+        b'Success!',
+    ]
+    apk_utils.install(self.mock_device, APK_PATH)
+    self.mock_device.reboot.assert_called_once_with()
+    expected_call = mock.call(
+        ['-r', '-t', APK_PATH],
+        timeout=DEFAULT_INSTALL_TIMEOUT_SEC,
+        stderr=mock.ANY,
+    )
+    self.mock_device.adb.install.assert_has_calls(
+        [expected_call, expected_call]
+    )
+
+  def test_uninstall_internal_error_no_retry(self):
+    mock_apk_package = 'some.apk.package'
+    self.mock_device.adb.shell.return_value = (
+        b'package:some.apk.package\npackage:some.other.package\n'
+    )
+    self.mock_device.adb.uninstall.side_effect = [
+        adb.AdbError(cmd=['uninstall'], stdout='', stderr='meh', ret_code=1),
+        Exception('This should never be raised.'),
+    ]
+    with self.assertRaisesRegex(
+        adb.AdbError, 'Error executing adb cmd "uninstall"'
+    ):
+      apk_utils.uninstall(self.mock_device, mock_apk_package)
+
+  def test_uninstall_internal_error_retry_also_fail(self):
+    mock_apk_package = 'some.apk.package'
+    self.mock_device.adb.shell.side_effect = [
+        b'package:some.apk.package\npackage:some.other.package\n',
+        adb.AdbError(
+            cmd=['pm', 'uninstall', '--pid', '0'],
+            stdout='',
+            stderr='',
+            ret_code=1,
+        ),
+    ]
+    self.mock_device.adb.uninstall.side_effect = adb.AdbError(
+        cmd=['uninstall'],
+        stdout=apk_utils.ADB_UNINSTALL_INTERNAL_ERROR_MSG,
+        stderr='meh',
+        ret_code=1,
+    )
+    with self.assertRaisesRegex(
+        adb.AdbError, 'Error executing adb cmd "uninstall"'
+    ):
+      apk_utils.uninstall(self.mock_device, mock_apk_package)
+
+  def test_apk_is_installed(self):
+    self.mock_device.adb.shell.return_value = (
+        b'package:some.apk.package\npackage:some.other.package\n'
+    )
+    self.assertTrue(
+        apk_utils.is_apk_installed(self.mock_device, 'some.apk.package')
+    )
+
+  def test_apk_is_not_installed(self):
+    self.mock_device.adb.shell.return_value = (
+        b'package:some.apk.package\npackage:some.other.package\n'
+    )
+    self.assertFalse(
+        apk_utils.is_apk_installed(self.mock_device, 'unknown.apk.package')
+    )
+
+  def test_apk_is_installed_error(self):
+    self.mock_device.adb.shell.side_effect = adb.AdbError('pm', '', 'error', 1)
+    with self.assertRaisesRegex(errors.DeviceError, 'Error executing adb cmd'):
+      apk_utils.is_apk_installed(self.mock_device, 'some.apk.package')
+
+  def create_mock_system_install_device(self, api_level, code_name='REL'):
+    """Create a mock device with a particular API level.
+
+    Args:
+      api_level: A string reflecting the value of the ro.build.version.sdk
+        property.
+      code_name: The codename of the device's build, defaults to 'REL'
+
+    Returns:
+      A mock object for the AndroidDevice.
+    """
+    self.mock_device.build_info = {
+        'build_version_sdk': bytearray(api_level, 'utf8'),
+        'build_version_codename': code_name,
+    }
+    return self.mock_device
+
+  def mock_apk_metadata(self):
+    """Returns a mock metadata object."""
+    mock_apk_metadata = mock.MagicMock()
+    mock_apk_metadata.package_name = 'mock.package.name'
+    return mock_apk_metadata
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/tests/mobly/controllers/android_device_lib/callback_handler_v2_test.py b/tests/mobly/controllers/android_device_lib/callback_handler_v2_test.py
index a7b8e9f..c47e2e7 100644
--- a/tests/mobly/controllers/android_device_lib/callback_handler_v2_test.py
+++ b/tests/mobly/controllers/android_device_lib/callback_handler_v2_test.py
@@ -108,10 +108,12 @@ class CallbackHandlerV2Test(unittest.TestCase):
 
     event = handler.waitForEvent('AsyncTaskResult', some_condition, 0.01)
     self.assert_event_correct(event, MOCK_RAW_EVENT)
-    mock_event_client.eventWaitAndGet.assert_has_calls([
-        mock.call(MOCK_CALLBACK_ID, 'AsyncTaskResult', mock.ANY),
-        mock.call(MOCK_CALLBACK_ID, 'AsyncTaskResult', mock.ANY),
-    ])
+    mock_event_client.eventWaitAndGet.assert_has_calls(
+        [
+            mock.call(MOCK_CALLBACK_ID, 'AsyncTaskResult', mock.ANY),
+            mock.call(MOCK_CALLBACK_ID, 'AsyncTaskResult', mock.ANY),
+        ]
+    )
 
   def test_get_all(self):
     mock_event_client = mock.Mock()
diff --git a/tests/mobly/controllers/android_device_lib/fastboot_test.py b/tests/mobly/controllers/android_device_lib/fastboot_test.py
index 86b697a..10bc953 100644
--- a/tests/mobly/controllers/android_device_lib/fastboot_test.py
+++ b/tests/mobly/controllers/android_device_lib/fastboot_test.py
@@ -21,6 +21,9 @@ from mobly.controllers.android_device_lib import fastboot
 class FastbootTest(unittest.TestCase):
   """Unit tests for mobly.controllers.android_device_lib.adb."""
 
+  def setUp(self):
+    fastboot.FASTBOOT = 'fastboot'
+
   @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
   @mock.patch('logging.debug')
   def test_fastboot_commands_and_results_are_logged_to_debug_log(
@@ -43,6 +46,82 @@ class FastbootTest(unittest.TestCase):
         123,
     )
 
+  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
+  def test_fastboot_without_serial(self, mock_popen):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_popen.return_value.communicate = mock.Mock(
+        return_value=(expected_stdout, expected_stderr)
+    )
+    mock_popen.return_value.returncode = 123
+
+    fastboot.FastbootProxy().fake_command('extra', 'flags')
+
+    mock_popen.assert_called_with(
+        'fastboot fake-command extra flags',
+        stdout=mock.ANY,
+        stderr=mock.ANY,
+        shell=True,
+    )
+
+  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
+  def test_fastboot_with_serial(self, mock_popen):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_popen.return_value.communicate = mock.Mock(
+        return_value=(expected_stdout, expected_stderr)
+    )
+    mock_popen.return_value.returncode = 123
+
+    fastboot.FastbootProxy('ABC').fake_command('extra', 'flags')
+
+    mock_popen.assert_called_with(
+        'fastboot -s ABC fake-command extra flags',
+        stdout=mock.ANY,
+        stderr=mock.ANY,
+        shell=True,
+    )
+
+  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
+  def test_fastboot_update_serial(self, mock_popen):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_popen.return_value.communicate = mock.Mock(
+        return_value=(expected_stdout, expected_stderr)
+    )
+    mock_popen.return_value.returncode = 123
+
+    fut = fastboot.FastbootProxy('ABC')
+    fut.fake_command('extra', 'flags')
+    fut.serial = 'XYZ'
+    fut.fake_command('extra', 'flags')
+
+    mock_popen.assert_called_with(
+        'fastboot -s XYZ fake-command extra flags',
+        stdout=mock.ANY,
+        stderr=mock.ANY,
+        shell=True,
+    )
+
+  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
+  def test_fastboot_use_customized_fastboot(self, mock_popen):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_popen.return_value.communicate = mock.Mock(
+        return_value=(expected_stdout, expected_stderr)
+    )
+    mock_popen.return_value.returncode = 123
+    fastboot.FASTBOOT = 'my_fastboot'
+
+    fastboot.FastbootProxy('ABC').fake_command('extra', 'flags')
+
+    mock_popen.assert_called_with(
+        'my_fastboot -s ABC fake-command extra flags',
+        stdout=mock.ANY,
+        stderr=mock.ANY,
+        shell=True,
+    )
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/tests/mobly/controllers/android_device_lib/service_manager_test.py b/tests/mobly/controllers/android_device_lib/service_manager_test.py
index 471c83f..2d608d3 100755
--- a/tests/mobly/controllers/android_device_lib/service_manager_test.py
+++ b/tests/mobly/controllers/android_device_lib/service_manager_test.py
@@ -469,6 +469,14 @@ class ServiceManagerTest(unittest.TestCase):
     with self.assertRaisesRegex(service_manager.Error, msg):
       manager.resume_services(['mock_service'])
 
+  def test_get_alias_by_class(self):
+    manager = service_manager.ServiceManager(mock.MagicMock())
+    manager.register('mock_service1', MockService, start_service=False)
+    manager.register('mock_service2', MockService, start_service=False)
+    manager.start_services(['mock_service2'])
+    aliases = manager.get_service_alias_by_class(MockService)
+    self.assertEqual(aliases, ['mock_service1', 'mock_service2'])
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/tests/mobly/controllers/android_device_lib/services/logcat_test.py b/tests/mobly/controllers/android_device_lib/services/logcat_test.py
index 66a20f8..ebf4919 100755
--- a/tests/mobly/controllers/android_device_lib/services/logcat_test.py
+++ b/tests/mobly/controllers/android_device_lib/services/logcat_test.py
@@ -149,7 +149,7 @@ class LogcatTest(unittest.TestCase):
 
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
-      return_value=mock_android_device.MockAdbProxy('1'),
+      return_value=mock_android_device.MockAdbProxy('1', adb_detectable=False),
   )
   @mock.patch(
       'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
@@ -335,8 +335,7 @@ class LogcatTest(unittest.TestCase):
           '{test_name}-{test_begin_time}'.format(
               test_name=test_name, test_begin_time=test_begin_time
           ),
-          'logcat,{mock_serial},fakemodel,{test_name}-{test_begin_time}.txt'
-          .format(
+          'logcat,{mock_serial},fakemodel,{test_name}-{test_begin_time}.txt'.format(
               mock_serial=mock_serial,
               test_name=test_name,
               test_begin_time=test_begin_time,
@@ -458,6 +457,7 @@ class LogcatTest(unittest.TestCase):
   def test__enable_logpersist_with_logpersist(self, MockFastboot, MockAdbProxy):
     mock_serial = '1'
     mock_adb_proxy = MockAdbProxy.return_value
+    mock_adb_proxy.devices.return_value = f'{mock_serial}\tdevice'.encode()
     mock_adb_proxy.getprops.return_value = {
         'ro.build.id': 'AB42',
         'ro.build.type': 'userdebug',
@@ -470,10 +470,12 @@ class LogcatTest(unittest.TestCase):
     ad = android_device.AndroidDevice(serial=mock_serial)
     logcat_service = logcat.Logcat(ad)
     logcat_service._enable_logpersist()
-    mock_adb_proxy.shell.assert_has_calls([
-        mock.call('logpersist.stop --clear'),
-        mock.call('logpersist.start'),
-    ])
+    mock_adb_proxy.shell.assert_has_calls(
+        [
+            mock.call('logpersist.stop --clear'),
+            mock.call('logpersist.start'),
+        ]
+    )
 
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
@@ -488,6 +490,7 @@ class LogcatTest(unittest.TestCase):
   ):
     mock_serial = '1'
     mock_adb_proxy = MockAdbProxy.return_value
+    mock_adb_proxy.devices.return_value = f'{mock_serial}\tdevice'.encode()
     mock_adb_proxy.getprops.return_value = {
         'ro.build.id': 'AB42',
         'ro.build.type': 'user',
@@ -523,6 +526,7 @@ class LogcatTest(unittest.TestCase):
 
     mock_serial = '1'
     mock_adb_proxy = MockAdbProxy.return_value
+    mock_adb_proxy.devices.return_value = f'{mock_serial}\tdevice'.encode()
     mock_adb_proxy.getprops.return_value = {
         'ro.build.id': 'AB42',
         'ro.build.type': 'userdebug',
@@ -557,6 +561,7 @@ class LogcatTest(unittest.TestCase):
 
     mock_serial = '1'
     mock_adb_proxy = MockAdbProxy.return_value
+    mock_adb_proxy.devices.return_value = f'{mock_serial}\tdevice'.encode()
     mock_adb_proxy.getprops.return_value = {
         'ro.build.id': 'AB42',
         'ro.build.type': 'userdebug',
@@ -570,9 +575,11 @@ class LogcatTest(unittest.TestCase):
     ad = android_device.AndroidDevice(serial=mock_serial)
     logcat_service = logcat.Logcat(ad)
     logcat_service._enable_logpersist()
-    mock_adb_proxy.shell.assert_has_calls([
-        mock.call('logpersist.stop --clear'),
-    ])
+    mock_adb_proxy.shell.assert_has_calls(
+        [
+            mock.call('logpersist.stop --clear'),
+        ]
+    )
 
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
@@ -593,6 +600,7 @@ class LogcatTest(unittest.TestCase):
 
     mock_serial = '1'
     mock_adb_proxy = MockAdbProxy.return_value
+    mock_adb_proxy.devices.return_value = f'{mock_serial}\tdevice'.encode()
     mock_adb_proxy.getprops.return_value = {
         'ro.build.id': 'AB42',
         'ro.build.type': 'userdebug',
@@ -608,7 +616,10 @@ class LogcatTest(unittest.TestCase):
     logcat_service._enable_logpersist()
     mock_adb_proxy.shell.assert_not_called()
 
-  @mock.patch('mobly.controllers.android_device_lib.adb.AdbProxy')
+  @mock.patch(
+      'mobly.controllers.android_device_lib.adb.AdbProxy',
+      return_value=mock_android_device.MockAdbProxy('1'),
+  )
   @mock.patch(
       'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
       return_value=mock_android_device.MockFastbootProxy('1'),
diff --git a/tests/mobly/controllers/android_device_lib/services/sl4a_service_test.py b/tests/mobly/controllers/android_device_lib/services/sl4a_service_test.py
deleted file mode 100755
index b6de71b..0000000
--- a/tests/mobly/controllers/android_device_lib/services/sl4a_service_test.py
+++ /dev/null
@@ -1,69 +0,0 @@
-# Copyright 2018 Google Inc.
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
-import unittest
-from unittest import mock
-
-from mobly.controllers.android_device_lib import service_manager
-from mobly.controllers.android_device_lib.services import sl4a_service
-
-
-@mock.patch('mobly.controllers.android_device_lib.sl4a_client.Sl4aClient')
-class Sl4aServiceTest(unittest.TestCase):
-  """Tests for the sl4a service."""
-
-  def test_instantiation(self, _):
-    service = sl4a_service.Sl4aService(mock.MagicMock())
-    self.assertFalse(service.is_alive)
-
-  def test_start(self, mock_sl4a_client_class):
-    mock_client = mock_sl4a_client_class.return_value
-    service = sl4a_service.Sl4aService(mock.MagicMock())
-    service.start()
-    mock_client.start_app_and_connect.assert_called_once_with()
-    self.assertTrue(service.is_alive)
-
-  def test_stop(self, mock_sl4a_client_class):
-    mock_client = mock_sl4a_client_class.return_value
-    service = sl4a_service.Sl4aService(mock.MagicMock())
-    service.start()
-    service.stop()
-    mock_client.stop_app.assert_called_once_with()
-    self.assertFalse(service.is_alive)
-
-  def test_pause(self, mock_sl4a_client_class):
-    mock_client = mock_sl4a_client_class.return_value
-    service = sl4a_service.Sl4aService(mock.MagicMock())
-    service.start()
-    service.pause()
-    mock_client.stop_event_dispatcher.assert_called_once_with()
-    mock_client.clear_host_port.assert_called_once_with()
-
-  def test_resume(self, mock_sl4a_client_class):
-    mock_client = mock_sl4a_client_class.return_value
-    service = sl4a_service.Sl4aService(mock.MagicMock())
-    service.start()
-    service.pause()
-    service.resume()
-    mock_client.restore_app_connection.assert_called_once_with()
-
-  def test_register_with_service_manager(self, _):
-    mock_device = mock.MagicMock()
-    manager = service_manager.ServiceManager(mock_device)
-    manager.register('sl4a', sl4a_service.Sl4aService)
-    self.assertTrue(manager.sl4a)
-
-
-if __name__ == '__main__':
-  unittest.main()
diff --git a/tests/mobly/controllers/android_device_lib/sl4a_client_test.py b/tests/mobly/controllers/android_device_lib/sl4a_client_test.py
deleted file mode 100755
index bf11b07..0000000
--- a/tests/mobly/controllers/android_device_lib/sl4a_client_test.py
+++ /dev/null
@@ -1,95 +0,0 @@
-# Copyright 2017 Google Inc.
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
-import unittest
-from unittest import mock
-
-from mobly.controllers.android_device_lib import jsonrpc_client_base
-from mobly.controllers.android_device_lib import sl4a_client
-from tests.lib import jsonrpc_client_test_base
-from tests.lib import mock_android_device
-
-
-class Sl4aClientTest(jsonrpc_client_test_base.JsonRpcClientTestBase):
-  """Unit tests for mobly.controllers.android_device_lib.sl4a_client."""
-
-  @mock.patch('socket.create_connection')
-  @mock.patch(
-      'mobly.controllers.android_device_lib.snippet_client.'
-      'utils.start_standing_subprocess'
-  )
-  @mock.patch(
-      'mobly.controllers.android_device_lib.snippet_client.'
-      'utils.get_available_host_port'
-  )
-  def test_start_app_and_connect(
-      self,
-      mock_get_port,
-      mock_start_standing_subprocess,
-      mock_create_connection,
-  ):
-    self.setup_mock_socket_file(mock_create_connection)
-    self._setup_mock_instrumentation_cmd(
-        mock_start_standing_subprocess, resp_lines=[b'\n']
-    )
-    client = self._make_client()
-    client.start_app_and_connect()
-    self.assertEqual(8080, client.device_port)
-
-  @mock.patch('socket.create_connection')
-  @mock.patch(
-      'mobly.controllers.android_device_lib.snippet_client.'
-      'utils.start_standing_subprocess'
-  )
-  @mock.patch(
-      'mobly.controllers.android_device_lib.snippet_client.'
-      'utils.get_available_host_port'
-  )
-  def test_app_not_installed(
-      self,
-      mock_get_port,
-      mock_start_standing_subprocess,
-      mock_create_connection,
-  ):
-    self.setup_mock_socket_file(mock_create_connection)
-    self._setup_mock_instrumentation_cmd(
-        mock_start_standing_subprocess, resp_lines=[b'\n']
-    )
-    client = self._make_client(adb_proxy=mock_android_device.MockAdbProxy())
-    with self.assertRaisesRegex(
-        jsonrpc_client_base.AppStartError, '.* SL4A is not installed on .*'
-    ):
-      client.start_app_and_connect()
-
-  def _make_client(self, adb_proxy=None):
-    adb_proxy = adb_proxy or mock_android_device.MockAdbProxy(
-        installed_packages=['com.googlecode.android_scripting']
-    )
-    ad = mock.Mock()
-    ad.adb = adb_proxy
-    ad.build_info = {
-        'build_version_codename': ad.adb.getprop('ro.build.version.codename'),
-        'build_version_sdk': ad.adb.getprop('ro.build.version.sdk'),
-    }
-    return sl4a_client.Sl4aClient(ad=ad)
-
-  def _setup_mock_instrumentation_cmd(
-      self, mock_start_standing_subprocess, resp_lines
-  ):
-    mock_proc = mock_start_standing_subprocess()
-    mock_proc.stdout.readline.side_effect = resp_lines
-
-
-if __name__ == '__main__':
-  unittest.main()
diff --git a/tests/mobly/controllers/android_device_lib/snippet_client_test.py b/tests/mobly/controllers/android_device_lib/snippet_client_test.py
index 5f31c47..2ed251b 100755
--- a/tests/mobly/controllers/android_device_lib/snippet_client_test.py
+++ b/tests/mobly/controllers/android_device_lib/snippet_client_test.py
@@ -59,11 +59,13 @@ class SnippetClientTest(jsonrpc_client_test_base.JsonRpcClientTestBase):
   def test_check_app_installed_fail_target_not_installed(self):
     sc = self._make_client(
         mock_android_device.MockAdbProxy(
-            instrumented_packages=[(
-                MOCK_PACKAGE_NAME,
-                snippet_client._INSTRUMENTATION_RUNNER_PACKAGE,
-                MOCK_MISSING_PACKAGE_NAME,
-            )]
+            instrumented_packages=[
+                (
+                    MOCK_PACKAGE_NAME,
+                    snippet_client._INSTRUMENTATION_RUNNER_PACKAGE,
+                    MOCK_MISSING_PACKAGE_NAME,
+                )
+            ]
         )
     )
     expected_msg = (
@@ -545,11 +547,13 @@ class SnippetClientTest(jsonrpc_client_test_base.JsonRpcClientTestBase):
         MOCK_PACKAGE_NAME,
         snippet_client._INSTRUMENTATION_RUNNER_PACKAGE,
     )
-    mock_do_start_app.assert_has_calls([
-        mock.call(cmd_setsid),
-        mock.call(cmd_nohup),
-        mock.call(cmd_not_persist),
-    ])
+    mock_do_start_app.assert_has_calls(
+        [
+            mock.call(cmd_setsid),
+            mock.call(cmd_nohup),
+            mock.call(cmd_not_persist),
+        ]
+    )
 
   @mock.patch('socket.create_connection')
   @mock.patch(
@@ -687,11 +691,13 @@ class SnippetClientTest(jsonrpc_client_test_base.JsonRpcClientTestBase):
 
   def _make_client(self, adb_proxy=None):
     adb_proxy = adb_proxy or mock_android_device.MockAdbProxy(
-        instrumented_packages=[(
-            MOCK_PACKAGE_NAME,
-            snippet_client._INSTRUMENTATION_RUNNER_PACKAGE,
-            MOCK_PACKAGE_NAME,
-        )]
+        instrumented_packages=[
+            (
+                MOCK_PACKAGE_NAME,
+                snippet_client._INSTRUMENTATION_RUNNER_PACKAGE,
+                MOCK_PACKAGE_NAME,
+            )
+        ]
     )
     ad = mock.Mock()
     ad.adb = adb_proxy
diff --git a/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py b/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
index 07e3d0d..3f3752b 100644
--- a/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
+++ b/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
@@ -112,11 +112,13 @@ class SnippetClientV2Test(unittest.TestCase):
 
   def _make_client(self, adb_proxy=None, mock_properties=None, config=None):
     adb_proxy = adb_proxy or _MockAdbProxy(
-        instrumented_packages=[(
-            MOCK_PACKAGE_NAME,
-            snippet_client_v2._INSTRUMENTATION_RUNNER_PACKAGE,
-            MOCK_PACKAGE_NAME,
-        )],
+        instrumented_packages=[
+            (
+                MOCK_PACKAGE_NAME,
+                snippet_client_v2._INSTRUMENTATION_RUNNER_PACKAGE,
+                MOCK_PACKAGE_NAME,
+            )
+        ],
         mock_properties=mock_properties,
     )
     self.adb = adb_proxy
@@ -180,7 +182,8 @@ class SnippetClientV2Test(unittest.TestCase):
     self.assertIs(self.client._proc, None)
     self.adb.mock_shell_func.assert_any_call(
         f'am instrument --user {MOCK_USER_ID} -w -e action stop '
-        f'{MOCK_SERVER_PATH}'
+        f'{MOCK_SERVER_PATH}',
+        timeout=mock.ANY,
     )
     mock_stop_standing_subprocess.assert_called_once_with(
         mock_start_subprocess.return_value
@@ -424,11 +427,13 @@ class SnippetClientV2Test(unittest.TestCase):
     """Tests that app checker fails without installing instrumentation."""
     self._make_client(
         _MockAdbProxy(
-            instrumented_packages=[(
-                MOCK_PACKAGE_NAME,
-                snippet_client_v2._INSTRUMENTATION_RUNNER_PACKAGE,
-                'not.installed',
-            )]
+            instrumented_packages=[
+                (
+                    MOCK_PACKAGE_NAME,
+                    snippet_client_v2._INSTRUMENTATION_RUNNER_PACKAGE,
+                    'not.installed',
+                )
+            ]
         )
     )
     expected_msg = '.* Instrumentation target not.installed is not installed.'
@@ -437,10 +442,12 @@ class SnippetClientV2Test(unittest.TestCase):
 
   def test_disable_hidden_api_normally(self):
     """Tests the disabling hidden api process works normally."""
-    self._make_client_with_extra_adb_properties({
-        'ro.build.version.codename': 'S',
-        'ro.build.version.sdk': '31',
-    })
+    self._make_client_with_extra_adb_properties(
+        {
+            'ro.build.version.codename': 'S',
+            'ro.build.version.sdk': '31',
+        }
+    )
     self.device.is_rootable = True
     self.client._disable_hidden_api_blocklist()
     self.adb.mock_shell_func.assert_called_with(
@@ -449,20 +456,24 @@ class SnippetClientV2Test(unittest.TestCase):
 
   def test_disable_hidden_api_low_sdk(self):
     """Tests it doesn't disable hidden api with low SDK."""
-    self._make_client_with_extra_adb_properties({
-        'ro.build.version.codename': 'O',
-        'ro.build.version.sdk': '26',
-    })
+    self._make_client_with_extra_adb_properties(
+        {
+            'ro.build.version.codename': 'O',
+            'ro.build.version.sdk': '26',
+        }
+    )
     self.device.is_rootable = True
     self.client._disable_hidden_api_blocklist()
     self.adb.mock_shell_func.assert_not_called()
 
   def test_disable_hidden_api_non_rootable(self):
     """Tests it doesn't disable hidden api with non-rootable device."""
-    self._make_client_with_extra_adb_properties({
-        'ro.build.version.codename': 'S',
-        'ro.build.version.sdk': '31',
-    })
+    self._make_client_with_extra_adb_properties(
+        {
+            'ro.build.version.codename': 'S',
+            'ro.build.version.sdk': '31',
+        }
+    )
     self.device.is_rootable = False
     self.client._disable_hidden_api_blocklist()
     self.adb.mock_shell_func.assert_not_called()
@@ -779,7 +790,8 @@ class SnippetClientV2Test(unittest.TestCase):
     self.assertIs(self.client._proc, None)
     self.adb.mock_shell_func.assert_called_once_with(
         f'am instrument --user {MOCK_USER_ID} -w -e action stop '
-        f'{MOCK_SERVER_PATH}'
+        f'{MOCK_SERVER_PATH}',
+        timeout=mock.ANY,
     )
     mock_stop_standing_subprocess.assert_called_once_with(mock_proc)
     self.assertFalse(self.client.is_alive)
@@ -865,7 +877,8 @@ class SnippetClientV2Test(unittest.TestCase):
     mock_stop_standing_subprocess.assert_called_once_with(mock_proc)
     mock_adb_shell.assert_called_once_with(
         f'am instrument --user {MOCK_USER_ID} -w -e action stop '
-        f'{MOCK_SERVER_PATH}'
+        f'{MOCK_SERVER_PATH}',
+        timeout=mock.ANY,
     )
     self.assertFalse(self.client.is_alive)
     self.assertIs(self.client._conn, None)
@@ -1607,12 +1620,14 @@ class SnippetClientV2Test(unittest.TestCase):
     with self.assertRaises(UnicodeError):
       self.client.make_connection()
 
-    self.client.log.error.assert_has_calls([
-        mock.call(
-            'Failed to decode socket response bytes using encoding utf8: %s',
-            socket_response,
-        )
-    ])
+    self.client.log.error.assert_has_calls(
+        [
+            mock.call(
+                'Failed to decode socket response bytes using encoding utf8: %s',
+                socket_response,
+            )
+        ]
+    )
 
   def test_rpc_sending_and_receiving(self):
     """Test RPC sending and receiving.
@@ -1678,12 +1693,14 @@ class SnippetClientV2Test(unittest.TestCase):
     with self.assertRaises(UnicodeError):
       self.client.send_rpc_request(rpc_request)
 
-    self.client.log.error.assert_has_calls([
-        mock.call(
-            'Failed to decode socket response bytes using encoding utf8: %s',
-            socket_response,
-        )
-    ])
+    self.client.log.error.assert_has_calls(
+        [
+            mock.call(
+                'Failed to decode socket response bytes using encoding utf8: %s',
+                socket_response,
+            )
+        ]
+    )
 
   @mock.patch.object(
       snippet_client_v2.SnippetClientV2, 'send_handshake_request'
diff --git a/tests/mobly/controllers/android_device_test.py b/tests/mobly/controllers/android_device_test.py
index 81c2965..557af5f 100755
--- a/tests/mobly/controllers/android_device_test.py
+++ b/tests/mobly/controllers/android_device_test.py
@@ -153,6 +153,29 @@ class AndroidDeviceTest(unittest.TestCase):
     with self.assertRaisesRegex(android_device.Error, expected_msg):
       android_device.create([1])
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.adb.AdbProxy',
+      return_value=mock_android_device.MockAdbProxy(1),
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
+      return_value=mock_android_device.MockFastbootProxy(1),
+  )
+  @mock.patch('mobly.utils.create_dir')
+  def test_get_info(self, create_dir_mock, FastbootProxy, MockAdbProxy):
+    mock_serial = '1'
+    ad = android_device.AndroidDevice(serial=mock_serial)
+    example_user_object = mock_android_device.MockAdbProxy('magic')
+    # Add an arbitrary object as a device info
+    ad.add_device_info('user_stuff', example_user_object)
+    info = android_device.get_info([ad])[0]
+    self.assertEqual(info['serial'], mock_serial)
+    self.assertTrue(info['build_info'])
+    # User added values should be normalized to strings.
+    self.assertEqual(
+        info['user_added_info']['user_stuff'], str(example_user_object)
+    )
+
   @mock.patch('mobly.controllers.android_device.list_fastboot_devices')
   @mock.patch('mobly.controllers.android_device.list_adb_devices')
   @mock.patch('mobly.controllers.android_device.list_adb_devices_by_usb_id')
@@ -393,6 +416,7 @@ class AndroidDeviceTest(unittest.TestCase):
     self.assertEqual(ad.space, 'the final frontier')
     self.assertEqual(ad.number, 1)
     self.assertEqual(ad.debug_tag, 'my_tag')
+    self.assertEqual(ad.device_info['user_added_info']['debug_tag'], 'my_tag')
 
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
@@ -717,7 +741,7 @@ class AndroidDeviceTest(unittest.TestCase):
 
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
-      return_value=mock_android_device.MockAdbProxy('1'),
+      return_value=mock_android_device.MockAdbProxy('1', adb_detectable=False),
   )
   @mock.patch(
       'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
diff --git a/tests/mobly/suite_runner_test.py b/tests/mobly/suite_runner_test.py
index b1023e7..0a716ed 100755
--- a/tests/mobly/suite_runner_test.py
+++ b/tests/mobly/suite_runner_test.py
@@ -23,13 +23,18 @@ from unittest import mock
 from mobly import base_suite
 from mobly import base_test
 from mobly import suite_runner
+from mobly import test_runner
 from tests.lib import integration2_test
 from tests.lib import integration_test
+from tests.lib import integration_test_suite
 
 
 class FakeTest1(base_test.BaseTestClass):
   pass
 
+  def test_a(self):
+    pass
+
 
 class SuiteRunnerTest(unittest.TestCase):
 
@@ -100,7 +105,8 @@ class SuiteRunnerTest(unittest.TestCase):
   def test_run_suite(self, mock_exit):
     tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
     with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
-      f.write("""
+      f.write(
+          """
         TestBeds:
           # A test bed where adb will find Android devices.
           - Name: SampleTestBed
@@ -109,7 +115,8 @@ class SuiteRunnerTest(unittest.TestCase):
             TestParams:
               icecream: 42
               extra_param: 'haha'
-      """)
+      """
+      )
     suite_runner.run_suite(
         [integration_test.IntegrationTest], argv=['-c', tmp_file_path]
     )
@@ -119,25 +126,32 @@ class SuiteRunnerTest(unittest.TestCase):
   def test_run_suite_with_failures(self, mock_exit):
     tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
     with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
-      f.write("""
+      f.write(
+          """
         TestBeds:
           # A test bed where adb will find Android devices.
           - Name: SampleTestBed
             Controllers:
               MagicDevice: '*'
-      """)
+      """
+      )
     suite_runner.run_suite(
         [integration_test.IntegrationTest], argv=['-c', tmp_file_path]
     )
     mock_exit.assert_called_once_with(1)
 
   @mock.patch('sys.exit')
-  @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
-  def test_run_suite_class(self, mock_find_suite_class, mock_exit):
+  def test_run_suite_class(self, mock_exit):
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = ['test_binary', f'--config={tmp_file_path}']
     mock_called = mock.MagicMock()
 
     class FakeTestSuite(base_suite.BaseSuite):
 
+      def set_test_selector(self, test_selector):
+        mock_called.set_test_selector(test_selector)
+        super().set_test_selector(test_selector)
+
       def setup_suite(self, config):
         mock_called.setup_suite()
         super().setup_suite(config)
@@ -147,28 +161,194 @@ class SuiteRunnerTest(unittest.TestCase):
         mock_called.teardown_suite()
         super().teardown_suite()
 
+    sys.modules['__main__'].__dict__[FakeTestSuite.__name__] = FakeTestSuite
+
+    with mock.patch.object(sys, 'argv', new=mock_cli_args):
+      try:
+        suite_runner.run_suite_class()
+      finally:
+        del sys.modules['__main__'].__dict__[FakeTestSuite.__name__]
+
+    mock_called.setup_suite.assert_called_once_with()
+    mock_called.teardown_suite.assert_called_once_with()
+    mock_exit.assert_not_called()
+    mock_called.set_test_selector.assert_called_once_with(None)
+
+  @mock.patch('sys.exit')
+  @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
+  @mock.patch.object(test_runner, 'TestRunner')
+  def test_run_suite_class_with_test_selection_by_class(
+      self, mock_test_runner_class, mock_find_suite_class, mock_exit
+  ):
+    mock_test_runner = mock_test_runner_class.return_value
+    mock_test_runner.results.is_all_pass = True
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = [
+        'test_binary',
+        f'--config={tmp_file_path}',
+        '--tests',
+        'FakeTest1',
+        'FakeTest1_A',
+    ]
+    mock_called = mock.MagicMock()
+
+    class FakeTestSuite(base_suite.BaseSuite):
+
+      def set_test_selector(self, test_selector):
+        mock_called.set_test_selector(test_selector)
+        super().set_test_selector(test_selector)
+
+      def setup_suite(self, config):
+        self.add_test_class(FakeTest1)
+        self.add_test_class(FakeTest1, name_suffix='A')
+        self.add_test_class(FakeTest1, name_suffix='B')
+
     mock_find_suite_class.return_value = FakeTestSuite
 
-    tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
-    with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
-      f.write("""
-        TestBeds:
-          # A test bed where adb will find Android devices.
-          - Name: SampleTestBed
-            Controllers:
-              MagicDevice: '*'
-      """)
+    with mock.patch.object(sys, 'argv', new=mock_cli_args):
+      suite_runner.run_suite_class()
 
-    mock_cli_args = ['test_binary', f'--config={tmp_file_path}']
+    mock_called.set_test_selector.assert_called_once_with(
+        {('FakeTest1', None): None, ('FakeTest1', 'A'): None},
+    )
+
+  @mock.patch('sys.exit')
+  @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
+  @mock.patch.object(test_runner, 'TestRunner')
+  def test_run_suite_class_with_test_selection_by_method(
+      self, mock_test_runner_class, mock_find_suite_class, mock_exit
+  ):
+    mock_test_runner = mock_test_runner_class.return_value
+    mock_test_runner.results.is_all_pass = True
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = [
+        'test_binary',
+        f'--config={tmp_file_path}',
+        '--tests',
+        'FakeTest1.test_a',
+        'FakeTest1_B.test_a',
+    ]
+    mock_called = mock.MagicMock()
+
+    class FakeTestSuite(base_suite.BaseSuite):
+
+      def set_test_selector(self, test_selector):
+        mock_called.set_test_selector(test_selector)
+        super().set_test_selector(test_selector)
+
+      def setup_suite(self, config):
+        self.add_test_class(FakeTest1)
+        self.add_test_class(FakeTest1, name_suffix='B')
+        self.add_test_class(FakeTest1, name_suffix='C')
+
+    mock_find_suite_class.return_value = FakeTestSuite
 
     with mock.patch.object(sys, 'argv', new=mock_cli_args):
       suite_runner.run_suite_class()
 
-    mock_find_suite_class.assert_called_once()
-    mock_called.setup_suite.assert_called_once_with()
-    mock_called.teardown_suite.assert_called_once_with()
+    mock_called.set_test_selector.assert_called_once_with(
+        {('FakeTest1', None): ['test_a'], ('FakeTest1', 'B'): ['test_a']},
+    )
+
+  @mock.patch.object(sys, 'exit')
+  @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
+  def test_run_suite_class_with_combined_test_selection(
+      self, mock_find_suite_class, mock_exit
+  ):
+    mock_called = mock.MagicMock()
+
+    class FakeTest2(base_test.BaseTestClass):
+
+      def __init__(self, config):
+        mock_called.suffix(config.test_class_name_suffix)
+        super().__init__(config)
+
+      def run(self, tests):
+        mock_called.run(tests)
+        return super().run(tests)
+
+      def test_a(self):
+        pass
+
+      def test_b(self):
+        pass
+
+    class FakeTestSuite(base_suite.BaseSuite):
+
+      def setup_suite(self, config):
+        self.add_test_class(FakeTest2, name_suffix='A')
+        self.add_test_class(FakeTest2, name_suffix='B')
+        self.add_test_class(FakeTest2, name_suffix='C', tests=['test_a'])
+        self.add_test_class(FakeTest2, name_suffix='D')
+        self.add_test_class(FakeTest2)
+
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = [
+        'test_binary',
+        f'--config={tmp_file_path}',
+        '--tests',
+        'FakeTest2_A',
+        'FakeTest2_B',
+        'FakeTest2_C.test_a',
+        'FakeTest2',
+    ]
+
+    mock_find_suite_class.return_value = FakeTestSuite
+    with mock.patch.object(sys, 'argv', new=mock_cli_args):
+      suite_runner.run_suite_class()
+
+    mock_called.suffix.assert_has_calls(
+        [mock.call('A'), mock.call('B'), mock.call('C'), mock.call(None)]
+    )
+    mock_called.run.assert_has_calls(
+        [
+            mock.call(None),
+            mock.call(None),
+            mock.call(['test_a']),
+            mock.call(None),
+        ]
+    )
     mock_exit.assert_not_called()
 
+  @mock.patch('sys.exit')
+  @mock.patch.object(test_runner, 'TestRunner')
+  @mock.patch.object(
+      integration_test_suite.IntegrationTestSuite, 'setup_suite', autospec=True
+  )
+  def test_run_suite_class_finds_suite_class_when_not_in_main_module(
+      self, mock_setup_suite, mock_test_runner_class, mock_exit
+  ):
+    mock_test_runner = mock_test_runner_class.return_value
+    mock_test_runner.results.is_all_pass = True
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = ['test_binary', f'--config={tmp_file_path}']
+
+    with mock.patch.object(sys, 'argv', new=mock_cli_args):
+      integration_test_suite.main()
+
+    mock_setup_suite.assert_called_once()
+
+  @mock.patch('builtins.print')
+  def test_print_test_names_for_suites(self, mock_print):
+    class FakeTestSuite(base_suite.BaseSuite):
+
+      def setup_suite(self, config):
+        self.add_test_class(FakeTest1, name_suffix='A')
+        self.add_test_class(FakeTest1, name_suffix='B')
+        self.add_test_class(FakeTest1, name_suffix='C', tests=['test_a'])
+        self.add_test_class(FakeTest1, name_suffix='D', tests=[])
+
+    suite_runner._print_test_names_for_suite(FakeTestSuite)
+    calls = [
+        mock.call('==========> FakeTest1_A <=========='),
+        mock.call('FakeTest1_A.test_a'),
+        mock.call('==========> FakeTest1_B <=========='),
+        mock.call('FakeTest1_B.test_a'),
+        mock.call('==========> FakeTest1_C <=========='),
+        mock.call('FakeTest1_C.test_a'),
+    ]
+    mock_print.assert_has_calls(calls)
+
   def test_print_test_names(self):
     mock_test_class = mock.MagicMock()
     mock_cls_instance = mock.MagicMock()
@@ -185,6 +365,20 @@ class SuiteRunnerTest(unittest.TestCase):
     mock_cls_instance._pre_run.side_effect = Exception('Something went wrong.')
     mock_cls_instance._clean_up.assert_called_once()
 
+  def _gen_tmp_config_file(self):
+    tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
+    with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
+      f.write(
+          """
+        TestBeds:
+          # A test bed where adb will find Android devices.
+          - Name: SampleTestBed
+            Controllers:
+              MagicDevice: '*'
+      """
+      )
+    return tmp_file_path
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/tests/mobly/test_runner_test.py b/tests/mobly/test_runner_test.py
index bd9a8fd..0bdf512 100755
--- a/tests/mobly/test_runner_test.py
+++ b/tests/mobly/test_runner_test.py
@@ -343,7 +343,8 @@ class TestRunnerTest(unittest.TestCase):
   def test_main(self, mock_exit, mock_find_test):
     tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
     with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
-      f.write("""
+      f.write(
+          """
         TestBeds:
           # A test bed where adb will find Android devices.
           - Name: SampleTestBed
@@ -352,7 +353,8 @@ class TestRunnerTest(unittest.TestCase):
             TestParams:
               icecream: 42
               extra_param: 'haha'
-      """)
+      """
+      )
     test_runner.main(['-c', tmp_file_path])
     mock_exit.assert_not_called()
 
@@ -364,13 +366,15 @@ class TestRunnerTest(unittest.TestCase):
   def test_main_with_failures(self, mock_exit, mock_find_test):
     tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
     with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
-      f.write("""
+      f.write(
+          """
         TestBeds:
           # A test bed where adb will find Android devices.
           - Name: SampleTestBed
             Controllers:
               MagicDevice: '*'
-      """)
+      """
+      )
     test_runner.main(['-c', tmp_file_path])
     mock_exit.assert_called_once_with(1)
 
@@ -389,6 +393,54 @@ class TestRunnerTest(unittest.TestCase):
       with mock.patch.dict('sys.modules', __main__=multiple_subclasses_module):
         test_class = test_runner._find_test_class()
 
+  def test_get_full_test_names(self):
+    """Verifies that calling get_test_names works properly."""
+    config = self.base_mock_test_config.copy()
+    tr = test_runner.TestRunner(self.log_dir, self.testbed_name)
+    with tr.mobly_logger():
+      tr.add_test_class(
+          config, integration_test.IntegrationTest, name_suffix='A'
+      )
+      tr.add_test_class(
+          config, integration_test.IntegrationTest, name_suffix='B'
+      )
+      tr.add_test_class(
+          config, integration2_test.Integration2Test, name_suffix='A'
+      )
+      tr.add_test_class(
+          config, integration2_test.Integration2Test, name_suffix='B'
+      )
+
+    results = tr.get_full_test_names()
+    self.assertIn('IntegrationTest_A.test_hello_world', results)
+    self.assertIn('IntegrationTest_B.test_hello_world', results)
+    self.assertIn('Integration2Test_A.test_hello_world', results)
+    self.assertIn('Integration2Test_B.test_hello_world', results)
+    self.assertEqual(len(results), 4)
+
+  def test_get_full_test_names_test_list(self):
+    """Verifies that calling get_test_names with test list works properly."""
+    config = self.base_mock_test_config.copy()
+    tr = test_runner.TestRunner(self.log_dir, self.testbed_name)
+    with tr.mobly_logger():
+      tr.add_test_class(
+          config, integration_test.IntegrationTest, tests=['test_hello_world']
+      )
+
+    results = tr.get_full_test_names()
+    self.assertIn('IntegrationTest.test_hello_world', results)
+    self.assertEqual(len(results), 1)
+
+  def test_get_full_test_names_test_list_empty(self):
+    """Verifies that calling get_test_names with empty test list works properly."""
+    config = self.base_mock_test_config.copy()
+    tr = test_runner.TestRunner(self.log_dir, self.testbed_name)
+    with tr.mobly_logger():
+      tr.add_test_class(config, integration_test.IntegrationTest, tests=[])
+
+    results = tr.get_full_test_names()
+    self.assertEqual(len(results), 0)
+
   def test_print_test_names(self):
     mock_test_class = mock.MagicMock()
     mock_cls_instance = mock.MagicMock()
diff --git a/tests/mobly/utils_test.py b/tests/mobly/utils_test.py
index fff3803..2891b92 100755
--- a/tests/mobly/utils_test.py
+++ b/tests/mobly/utils_test.py
@@ -47,11 +47,13 @@ def _is_process_running(pid):
   if os.name == 'nt':
     return (
         str(pid)
-        in subprocess.check_output([
-            'tasklist',
-            '/fi',
-            f'PID eq {pid}',
-        ]).decode()
+        in subprocess.check_output(
+            [
+                'tasklist',
+                '/fi',
+                f'PID eq {pid}',
+            ]
+        ).decode()
     )
 
   try:
@@ -120,11 +122,62 @@ class UtilsTest(unittest.TestCase):
     self.assertListEqual(pid_list, [])
 
   @unittest.skipIf(
-      os.name == 'nt',
+      platform.system() != 'Linux',
+      'collect_process_tree only available on Unix like system.',
+  )
+  @mock.patch('subprocess.check_output')
+  def test_collect_process_tree_returns_list_on_linux(self, mock_check_output):
+    # Creates subprocess 777 with descendants looks like:
+    # subprocess 777
+    #   ├─ 780 (child)
+    #   │  ├─ 888 (grandchild)
+    #   │  │    ├─ 913 (great grandchild)
+    #   │  │    └─ 999 (great grandchild)
+    #   │  └─ 890 (grandchild)
+    #   ├─ 791 (child)
+    #   └─ 799 (child)
+    mock_check_output.side_effect = (
+        # ps -o pid --ppid 777 --noheaders
+        b'780\n 791\n 799\n',
+        # ps -o pid --ppid 780 --noheaders
+        b'888\n 890\n',
+        # ps -o pid --ppid 791 --noheaders
+        subprocess.CalledProcessError(-1, 'fake_cmd'),
+        # ps -o pid --ppid 799 --noheaders
+        subprocess.CalledProcessError(-1, 'fake_cmd'),
+        # ps -o pid --ppid 888 --noheaders
+        b'913\n 999\n',
+        # ps -o pid --ppid 890 --noheaders
+        subprocess.CalledProcessError(-1, 'fake_cmd'),
+        # ps -o pid --ppid 913 --noheaders
+        subprocess.CalledProcessError(-1, 'fake_cmd'),
+        # ps -o pid --ppid 999 --noheaders
+        subprocess.CalledProcessError(-1, 'fake_cmd'),
+    )
+
+    pid_list = utils._collect_process_tree(777)
+
+    expected_child_pid_list = [780, 791, 799, 888, 890, 913, 999]
+    self.assertListEqual(pid_list, expected_child_pid_list)
+
+    for pid in [777] + expected_child_pid_list:
+      mock_check_output.assert_any_call(
+          [
+              'ps',
+              '-o',
+              'pid',
+              '--ppid',
+              str(pid),
+              '--noheaders',
+          ]
+      )
+
+  @unittest.skipIf(
+      platform.system() != 'Darwin',
       'collect_process_tree only available on Unix like system.',
   )
   @mock.patch('subprocess.check_output')
-  def test_collect_process_tree_returns_list(self, mock_check_output):
+  def test_collect_process_tree_returns_list_on_macos(self, mock_check_output):
     # Creates subprocess 777 with descendants looks like:
     # subprocess 777
     #   ├─ 780 (child)
@@ -155,7 +208,11 @@ class UtilsTest(unittest.TestCase):
 
     pid_list = utils._collect_process_tree(777)
 
-    self.assertListEqual(pid_list, [780, 791, 799, 888, 890, 913, 999])
+    expected_child_pid_list = [780, 791, 799, 888, 890, 913, 999]
+    self.assertListEqual(pid_list, expected_child_pid_list)
+
+    for pid in [777] + expected_child_pid_list:
+      mock_check_output.assert_any_call(['pgrep', '-P', str(pid)])
 
   @mock.patch.object(os, 'kill')
   @mock.patch.object(utils, '_collect_process_tree')
@@ -169,11 +226,13 @@ class UtilsTest(unittest.TestCase):
     with mock.patch.object(os, 'name', new='posix'):
       utils._kill_process_tree(mock_proc)
 
-    mock_os_kill.assert_has_calls([
-        mock.call(799, signal.SIGTERM),
-        mock.call(888, signal.SIGTERM),
-        mock.call(890, signal.SIGTERM),
-    ])
+    mock_os_kill.assert_has_calls(
+        [
+            mock.call(799, signal.SIGTERM),
+            mock.call(888, signal.SIGTERM),
+            mock.call(890, signal.SIGTERM),
+        ]
+    )
     mock_proc.kill.assert_called_once()
 
   @mock.patch.object(os, 'kill')
@@ -215,13 +274,15 @@ class UtilsTest(unittest.TestCase):
     with mock.patch.object(os, 'name', new='nt'):
       utils._kill_process_tree(mock_proc)
 
-    mock_check_output.assert_called_once_with([
-        'taskkill',
-        '/F',
-        '/T',
-        '/PID',
-        '123',
-    ])
+    mock_check_output.assert_called_once_with(
+        [
+            'taskkill',
+            '/F',
+            '/T',
+            '/PID',
+            '123',
+        ]
+    )
 
   def test_run_command(self):
     ret, _, _ = utils.run_command(self.sleep_cmd(0.01))
@@ -345,6 +406,36 @@ class UtilsTest(unittest.TestCase):
         env=mock_env,
     )
 
+  @mock.patch('subprocess.Popen')
+  def test_start_standing_subproc_with_custom_stdout(self, mock_popen):
+    mock_stdout = mock.MagicMock(spec=io.TextIOWrapper)
+
+    utils.start_standing_subprocess(self.sleep_cmd(0.01), stdout=mock_stdout)
+
+    mock_popen.assert_called_with(
+        self.sleep_cmd(0.01),
+        stdin=subprocess.PIPE,
+        stdout=mock_stdout,
+        stderr=subprocess.PIPE,
+        shell=False,
+        env=None,
+    )
+
+  @mock.patch('subprocess.Popen')
+  def test_start_standing_subproc_with_custom_stderr(self, mock_popen):
+    mock_stderr = mock.MagicMock(spec=io.TextIOWrapper)
+
+    utils.start_standing_subprocess(self.sleep_cmd(0.01), stderr=mock_stderr)
+
+    mock_popen.assert_called_with(
+        self.sleep_cmd(0.01),
+        stdin=subprocess.PIPE,
+        stdout=subprocess.PIPE,
+        stderr=mock_stderr,
+        shell=False,
+        env=None,
+    )
+
   def test_stop_standing_subproc(self):
     p = utils.start_standing_subprocess(self.sleep_cmd(4))
     utils.stop_standing_subprocess(p)
diff --git a/tools/sl4a_shell.py b/tools/sl4a_shell.py
deleted file mode 100755
index 6ad656e..0000000
--- a/tools/sl4a_shell.py
+++ /dev/null
@@ -1,72 +0,0 @@
-#!/usr/bin/env python3.4
-#
-# Copyright 2016 Google Inc.
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
-"""Tool to interactively call sl4a methods.
-
-SL4A (Scripting Layer for Android) is an RPC service exposing API calls on
-Android.
-
-Original version: https://github.com/damonkohler/sl4a
-
-Fork in AOSP (can make direct system privileged calls):
-https://android.googlesource.com/platform/external/sl4a/
-
-Also allows access to Event Dispatcher, which allows waiting for asynchronous
-actions. For more information see the Mobly codelab:
-https://github.com/google/mobly#event-dispatcher
-
-Usage:
-$ sl4a_shell
->>> s.getBuildID()
-u'N2F52'
-"""
-
-import argparse
-import logging
-
-from mobly.controllers.android_device_lib import jsonrpc_shell_base
-from mobly.controllers.android_device_lib.services import sl4a_service
-
-
-class Sl4aShell(jsonrpc_shell_base.JsonRpcShellBase):
-
-  def _start_services(self, console_env):
-    """Overrides superclass."""
-    self._ad.services.register('sl4a', sl4a_service.Sl4aService)
-    console_env['s'] = self._ad.services.sl4a
-    console_env['sl4a'] = self._ad.sl4a
-    console_env['ed'] = self._ad.ed
-
-  def _get_banner(self, serial):
-    lines = [
-        'Connected to %s.' % serial,
-        'Call methods against:',
-        '    ad (android_device.AndroidDevice)',
-        '    sl4a or s (SL4A)',
-        '    ed (EventDispatcher)',
-    ]
-    return '\n'.join(lines)
-
-
-if __name__ == '__main__':
-  parser = argparse.ArgumentParser(description='Interactive client for sl4a.')
-  parser.add_argument(
-      '-s',
-      '--serial',
-      help='Device serial to connect to (if more than one device is connected)',
-  )
-  args = parser.parse_args()
-  logging.basicConfig(level=logging.INFO)
-  Sl4aShell().main(args.serial)
```

