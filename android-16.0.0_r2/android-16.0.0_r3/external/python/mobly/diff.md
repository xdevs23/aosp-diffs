```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 3b270a7..b6f4b4a 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,5 +1,29 @@
 # Mobly Release History
 
+# Mobly Release 1.13: SL4A Removal and Test Suite Improvements
+Removed all SL4A related code. Improved test suite mechanism.
+
+### New
+* Support test case selection and listing for test suites.
+* Support selecting test cases within single test class using regular
+  expressions.
+* Record suite meta information in the test summary file.
+* Support `fastboot` command execution with customized binary path.
+* Support `fastboot` command execution using the latest serial when the device
+  changes its serial during a test.
+* Support getting the service alias by service class.
+
+### Breaking Changes
+* Removal of all SL4A related code.
+* Removal of the `generate_setup_tests` stage, which was deprecated in version
+  1.12.
+
+### Fixes
+* Improved the error message for snippet loading errors.
+* Updated documents and docstrings.
+
+[Full list of changes](https://github.com/google/mobly/milestone/32?closed=1)
+
 
 ## Mobly Release 1.12.4: Improvements
 
diff --git a/METADATA b/METADATA
index a2d8da0..5314fa2 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 2
-    day: 25
+    month: 6
+    day: 5
   }
   homepage: "https://github.com/google/mobly"
   identifier {
     type: "Git"
     value: "https://github.com/google/mobly"
-    version: "a489d904870e349ce47cc972d0f20c4723316cce"
+    version: "e6450d8ef156278413d0c08121e96ffac200d287"
   }
 }
diff --git a/mobly/base_suite.py b/mobly/base_suite.py
index 1ef0a68..c6da6bf 100644
--- a/mobly/base_suite.py
+++ b/mobly/base_suite.py
@@ -37,6 +37,8 @@ class BaseSuite(abc.ABC):
     self._runner = runner
     self._config = config.copy()
     self._test_selector = None
+    self._suite_run_display_name = self.__class__.__name__
+    self._suite_info = {}
 
   @property
   def user_params(self):
@@ -98,3 +100,34 @@ class BaseSuite(abc.ABC):
   def teardown_suite(self):
     """Function used to add post tests cleanup tasks (optional)."""
     pass
+
+  # Methods for sub-classes to record customized suite information to
+  # test summary.
+
+  def set_suite_run_display_name(self, suite_run_display_name):
+    """Interface for sub-classes to set a customized display name.
+
+    This name provides run-specific context intended for display. Default to
+    suite class name. Set this in sub-classes to include run-specific context.
+
+    Args:
+      suite_run_display_name: str, the display name to set.
+    """
+    self._suite_run_display_name = suite_run_display_name
+
+  def get_suite_run_display_name(self):
+    """Returns the suite run display name."""
+    return self._suite_run_display_name
+
+  def set_suite_info(self, suite_info=None):
+    """Interface for sub-classes to set user defined extra info to test summary.
+
+    Args:
+      suite_info: dict, A dict of suite information. Keys and values must be
+        serializable.
+    """
+    self._suite_info = suite_info or {}
+
+  def get_suite_info(self):
+    """Returns suite information."""
+    return self._suite_info
diff --git a/mobly/controllers/android_device.py b/mobly/controllers/android_device.py
index 66a40d5..fe731bc 100644
--- a/mobly/controllers/android_device.py
+++ b/mobly/controllers/android_device.py
@@ -94,8 +94,12 @@ def create(configs):
   """Creates AndroidDevice controller objects.
 
   Args:
-    configs: A list of dicts, each representing a configuration for an
-      Android device.
+    configs: Represents configurations for Android devices, this can take one of
+      the following forms:
+      * str, only asterisk symbol is accepted, indicating that all connected
+        Android devices will be used
+      * A list of dict, each representing a configuration for an Android device.
+      * A list of str, each representing the serial number of Android device.
 
   Returns:
     A list of AndroidDevice objects.
@@ -1049,22 +1053,52 @@ class AndroidDevice:
     self.log.debug('Bugreport taken at %s.', full_out_path)
     return full_out_path
 
-  def take_screenshot(self, destination, prefix='screenshot'):
+  def take_screenshot(
+      self, destination, prefix='screenshot', all_displays=False
+  ):
     """Takes a screenshot of the device.
 
     Args:
       destination: string, full path to the directory to save in.
       prefix: string, prefix file name of the screenshot.
+      all_displays: bool, if true will take a screenshot on all connnected
+        displays, if false will take a screenshot on the default display.
 
     Returns:
-      string, full path to the screenshot file on the host.
+      string, full path to the screenshot file on the host, or
+      list[str], when all_displays is True, the full paths to the screenshot
+        files on the host.
     """
     filename = self.generate_filename(prefix, extension_name='png')
+    filename_no_extension, _ = os.path.splitext(filename)
     device_path = os.path.join('/storage/emulated/0/', filename)
     self.adb.shell(
-        ['screencap', '-p', device_path], timeout=TAKE_SCREENSHOT_TIMEOUT_SECOND
+        ['screencap', '-p', '-a' if all_displays else '', device_path],
+        timeout=TAKE_SCREENSHOT_TIMEOUT_SECOND,
     )
     utils.create_dir(destination)
+    if all_displays:
+      pic_paths = []
+      png_files = [device_path]
+      # iterate over all files that match the filename, if all_displays is true
+      # then filename will get a suffix of display number eg filenmame.png ->
+      # filename_0.png, filename_1.png
+      png_files = (
+          self.adb.shell('ls /storage/emulated/0/*.png')
+          .decode('utf-8')
+          .split('\n')
+      )
+      for device_path in png_files:
+        if device_path.find(filename_no_extension) < 0:
+          continue
+        self.adb.pull([device_path, destination])
+        pic_paths.append(
+            os.path.join(destination, os.path.basename(device_path))
+        )
+        self.log.debug('Screenshot taken, saved on the host: %s', pic_paths[-1])
+        self.adb.shell(['rm', device_path])
+      return pic_paths
+    # handle single screenshot when all_displays=False
     self.adb.pull([device_path, destination])
     pic_path = os.path.join(destination, filename)
     self.log.debug('Screenshot taken, saved on the host: %s', pic_path)
diff --git a/mobly/controllers/android_device_lib/fastboot.py b/mobly/controllers/android_device_lib/fastboot.py
index e4aab8e..0591e20 100644
--- a/mobly/controllers/android_device_lib/fastboot.py
+++ b/mobly/controllers/android_device_lib/fastboot.py
@@ -13,33 +13,42 @@
 # limitations under the License.
 
 import logging
-from subprocess import Popen, PIPE
+from subprocess import PIPE
 
 from mobly import utils
 
+# The default fastboot command timeout settings.
+DEFAULT_TIMEOUT_SEC = 180
+
 # Command to use for running fastboot commands.
 FASTBOOT = 'fastboot'
 
 
-def exe_cmd(*cmds):
-  """Executes commands in a new shell. Directing stderr to PIPE.
+def exe_cmd(*cmds, timeout=DEFAULT_TIMEOUT_SEC):
+  """Executes commands in a new shell. Directing stderr to PIPE, with timeout.
 
   This is fastboot's own exe_cmd because of its peculiar way of writing
   non-error info to stderr.
 
   Args:
     cmds: A sequence of commands and arguments.
+    timeout: The number of seconds to wait before timing out.
 
   Returns:
-    The output of the command run.
+    The output of the command run, in bytes.
 
   Raises:
-    Exception: An error occurred during the command execution.
+    Exception: An error occurred during the command execution or
+      the command timed out.
   """
   cmd = ' '.join(cmds)
-  proc = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
-  (out, err) = proc.communicate()
-  ret = proc.returncode
+  (ret, out, err) = utils.run_command(
+      cmd=cmd,
+      stdout=PIPE,
+      stderr=PIPE,
+      shell=True,
+      timeout=timeout,
+  )
   logging.debug(
       'cmd: %s, stdout: %s, stderr: %s, ret: %s',
       utils.cli_cmd_to_string(cmds),
@@ -69,16 +78,18 @@ class FastbootProxy:
       return '{} -s {}'.format(FASTBOOT, self.serial)
     return FASTBOOT
 
-  def _exec_fastboot_cmd(self, name, arg_str):
-    return exe_cmd(' '.join((self.fastboot_str(), name, arg_str)))
+  def _exec_fastboot_cmd(self, name, arg_str, timeout=DEFAULT_TIMEOUT_SEC):
+    return exe_cmd(
+        ' '.join((self.fastboot_str(), name, arg_str)), timeout=timeout
+    )
 
-  def args(self, *args):
-    return exe_cmd(' '.join((self.fastboot_str(),) + args))
+  def args(self, *args, timeout=DEFAULT_TIMEOUT_SEC):
+    return exe_cmd(' '.join((self.fastboot_str(),) + args), timeout=timeout)
 
   def __getattr__(self, name):
-    def fastboot_call(*args):
+    def fastboot_call(*args, timeout=DEFAULT_TIMEOUT_SEC):
       clean_name = name.replace('_', '-')
       arg_str = ' '.join(str(elem) for elem in args)
-      return self._exec_fastboot_cmd(clean_name, arg_str)
+      return self._exec_fastboot_cmd(clean_name, arg_str, timeout=timeout)
 
     return fastboot_call
diff --git a/mobly/controllers/android_device_lib/services/logcat.py b/mobly/controllers/android_device_lib/services/logcat.py
index 04dcf9d..714954b 100644
--- a/mobly/controllers/android_device_lib/services/logcat.py
+++ b/mobly/controllers/android_device_lib/services/logcat.py
@@ -11,7 +11,6 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-import io
 import logging
 import os
 import time
@@ -121,8 +120,13 @@ class Logcat(base_service.BaseService):
         self.OUTPUT_FILE_TYPE, test_info, 'txt'
     )
     excerpt_file_path = os.path.join(dest_path, filename)
-    with io.open(
-        excerpt_file_path, 'w', encoding='utf-8', errors='replace'
+    with open(
+        excerpt_file_path,
+        'w',
+        encoding='utf-8',
+        errors='replace',
+        # When newline is '', line endings are written without conversion.
+        newline='',
     ) as out:
       # Devices may accidentally go offline during test,
       # check not None before readline().
@@ -195,8 +199,13 @@ class Logcat(base_service.BaseService):
               self._ad, 'Timeout while waiting for logcat file to be created.'
           )
         time.sleep(1)
-      self._adb_logcat_file_obj = io.open(
-          self.adb_logcat_file_path, 'r', encoding='utf-8', errors='replace'
+      self._adb_logcat_file_obj = open(
+          self.adb_logcat_file_path,  # pytype: disable=wrong-arg-types
+          'r',
+          encoding='utf-8',
+          errors='replace',
+          # When newline is '', line endings are read without conversion.
+          newline='',
       )
       self._adb_logcat_file_obj.seek(0, os.SEEK_END)
 
diff --git a/mobly/controllers/android_device_lib/snippet_client_v2.py b/mobly/controllers/android_device_lib/snippet_client_v2.py
index b26226e..9025e2f 100644
--- a/mobly/controllers/android_device_lib/snippet_client_v2.py
+++ b/mobly/controllers/android_device_lib/snippet_client_v2.py
@@ -39,6 +39,19 @@ _LAUNCH_CMD = (
     f' {{snippet_package}}/{_INSTRUMENTATION_RUNNER_PACKAGE}'
 )
 
+_SNIPPET_SERVER_START_ERROR_DEBUG_TIP = """
+Invalid instrumentation result log received during snippet server start:
+{instrumentation_result}
+
+For debugging, please check the following:
+1. Check the server process stdout attached below.
+2. The snippet server logs within the device's logcat file. Search for
+   "SNIPPET START" to locate the relevant process ID.
+
+Server process stdout:
+{server_start_stdout}
+"""
+
 # The command template to stop the snippet server
 _STOP_CMD = (
     'am instrument {user} -w -e action stop {snippet_package}/'
@@ -161,6 +174,7 @@ class SnippetClientV2(client_base.ClientBase):
     self._conn = None
     self._event_client = None
     self._config = config or Config()
+    self._server_start_stdout = []
 
   @property
   def user_id(self):
@@ -285,6 +299,7 @@ class SnippetClientV2(client_base.ClientBase):
     self._proc = self._run_adb_cmd(cmd)
 
     # Check protocol version and get the device port
+    self._server_start_stdout = []
     line = self._read_protocol_line()
     match = re.match('^SNIPPET START, PROTOCOL ([0-9]+) ([0-9]+)$', line)
     if not match or int(match.group(1)) != _PROTOCOL_MAJOR_VERSION:
@@ -293,7 +308,11 @@ class SnippetClientV2(client_base.ClientBase):
     line = self._read_protocol_line()
     match = re.match('^SNIPPET SERVING, PORT ([0-9]+)$', line)
     if not match:
-      raise errors.ServerStartProtocolError(self._device, line)
+      message = _SNIPPET_SERVER_START_ERROR_DEBUG_TIP.format(
+          instrumentation_result=line,
+          server_start_stdout='\n'.join(self._server_start_stdout),
+      )
+      raise errors.ServerStartProtocolError(self._device, message)
     self.device_port = int(match.group(1))
 
   def _run_adb_cmd(self, cmd):
@@ -365,6 +384,7 @@ class SnippetClientV2(client_base.ClientBase):
       errors.ServerStartError: If EOF is reached without any protocol lines
         being read.
     """
+    self._server_start_stdout = []
     while True:
       line = self._proc.stdout.readline().decode('utf-8')
       if not line:
@@ -383,6 +403,7 @@ class SnippetClientV2(client_base.ClientBase):
         self.log.debug('Accepted line from instrumentation output: "%s"', line)
         return line
 
+      self._server_start_stdout.append(line)
       self.log.debug('Discarded line from instrumentation output: "%s"', line)
 
   def make_connection(self):
@@ -446,9 +467,27 @@ class SnippetClientV2(client_base.ClientBase):
       self.log.debug(
           'Failed to connect to localhost, trying 127.0.0.1: %s', str(err)
       )
-      self._conn = socket.create_connection(
-          ('127.0.0.1', self.host_port), _SOCKET_CONNECTION_TIMEOUT
-      )
+      try:
+        self._conn = socket.create_connection(
+            ('127.0.0.1', self.host_port), _SOCKET_CONNECTION_TIMEOUT
+        )
+      except ConnectionRefusedError as err2:
+        ret, _, _ = utils.run_command(
+            f'netstat -tulpn | grep ":{self.host_port}"', shell=True
+        )
+        if ret != 0:
+          raise errors.Error(
+              self._device,
+              'The Adb forward command execution did not take effect. Please'
+              ' check if there are other processes affecting adb forward on the'
+              ' host.',
+          ) from err2
+
+        raise errors.Error(
+            self._device,
+            'Failed to establish socket connection from host to snippet server'
+            ' running on Android device.',
+        ) from err2
 
     self._conn.settimeout(_SOCKET_READ_TIMEOUT)
     self._client = self._conn.makefile(mode='brw')
@@ -679,8 +718,22 @@ class SnippetClientV2(client_base.ClientBase):
       self._stop_port_forwarding()
 
   def _stop_port_forwarding(self):
-    """Stops the adb port forwarding used by this client."""
+    """Stops the adb port forwarding used by this client.
+
+    Although we explicitly forward and track the host port, it can be unforwarded
+    unexpectedly due to flaky USB connections, adb restarts, or external tools
+    (e.g., `adb forward --remove-all`). To prevent unnecessary errors, this method
+    checks if the host port is still forwarded before attempting to remove it.
+    """
     if self.host_port:
+      occupied_ports = adb.list_occupied_adb_ports()
+      if self.host_port not in occupied_ports:
+        self.log.debug(
+            'Host port %s is not currently forwarded by adb, skipping removal.',
+            self.host_port,
+        )
+        self.host_port = None
+        return
       self._device.adb.forward(['--remove', f'tcp:{self.host_port}'])
       self.host_port = None
 
diff --git a/mobly/suite_runner.py b/mobly/suite_runner.py
index a7f7cf1..166627f 100644
--- a/mobly/suite_runner.py
+++ b/mobly/suite_runner.py
@@ -18,9 +18,9 @@ classes. Users can use it as is or customize it based on their requirements.
 
 There are two ways to use this runner.
 
-1. Call suite_runner.run_suite() with one or more individual test classes. This
-is for users who just need to execute a collection of test classes without any
-additional steps.
+1. Call suite_runner.run_suite() with a list of one or more individual test
+classes. This is for users who just need to execute a collection of test
+classes without any additional steps.
 
 .. code-block:: python
 
@@ -30,7 +30,7 @@ additional steps.
   from my.test.lib import bar_test
   ...
   if __name__ == '__main__':
-    suite_runner.run_suite(foo_test.FooTest, bar_test.BarTest)
+    suite_runner.run_suite([foo_test.FooTest, bar_test.BarTest])
 
 2. Create a subclass of base_suite.BaseSuite and add the individual test
 classes. Using the BaseSuite class allows users to define their own setup
@@ -66,21 +66,86 @@ class.
 """
 import argparse
 import collections
+import enum
 import inspect
 import logging
+import os
 import sys
 
 from mobly import base_test
 from mobly import base_suite
 from mobly import config_parser
+from mobly import records
 from mobly import signals
 from mobly import test_runner
+from mobly import utils
 
 
 class Error(Exception):
   pass
 
 
+class TestSummaryEntryType(enum.Enum):
+  """Constants used to record suite level entries in test summary file."""
+
+  SUITE_INFO = 'SuiteInfo'
+
+
+class SuiteInfoRecord:
+  """A record representing the test suite info in test summary.
+
+  This record class is for suites defined by inheriting `base_suite.BaseSuite`.
+  This is not for suites directly assembled via `run_suite`.
+
+  Attributes:
+    suite_class_name: The class name of the test suite class.
+    suite_run_display_name: The name that provides run-specific context intended
+      for display. Default to suite class name. Set this in the suite class to
+      include run-specific context.
+    extras: User defined extra information of the test result. Must be
+      serializable.
+    begin_time: Epoch timestamp of when the suite started.
+    end_time: Epoch timestamp of when the suite ended.
+  """
+
+  KEY_SUITE_CLASS_NAME = 'Suite Class Name'
+  KEY_SUITE_RUN_DISPLAY_NAME = 'Suite Run Display Name'
+  KEY_EXTRAS = 'Extras'
+  KEY_BEGIN_TIME = 'Suite Begin Time'
+  KEY_END_TIME = 'Suite End Time'
+
+  suite_class_name: str
+  suite_run_display_name: str
+  extras: dict
+  begin_time: int | None = None
+  end_time: int | None = None
+
+  def __init__(self, suite_class_name):
+    self.suite_class_name = suite_class_name
+    self.suite_run_display_name = suite_class_name
+    self.extras = dict()
+
+  def suite_begin(self):
+    """Call this when the suite begins execution."""
+    self.begin_time = utils.get_current_epoch_time()
+
+  def suite_end(self):
+    """Call this when the suite ends execution."""
+    self.end_time = utils.get_current_epoch_time()
+
+  def to_dict(self):
+    result = {}
+    result[self.KEY_SUITE_CLASS_NAME] = self.suite_class_name
+    result[self.KEY_SUITE_RUN_DISPLAY_NAME] = self.suite_run_display_name
+    result[self.KEY_EXTRAS] = self.extras
+    result[self.KEY_BEGIN_TIME] = self.begin_time
+    result[self.KEY_END_TIME] = self.end_time
+    return result
+
+  def __repr__(self):
+    return str(self.to_dict())
+
+
 def _parse_cli_args(argv):
   """Parses cli args that are consumed by Mobly.
 
@@ -259,6 +324,13 @@ def _print_test_names(test_classes):
       print(f'{cls.TAG}.{name}')
 
 
+def _dump_suite_info(suite_record, log_path):
+  """Dumps the suite info record to test summary file."""
+  summary_path = os.path.join(log_path, records.OUTPUT_FILE_SUMMARY)
+  summary_writer = records.TestSummaryWriter(summary_path)
+  summary_writer.dump(suite_record.to_dict(), TestSummaryEntryType.SUITE_INFO)
+
+
 def run_suite_class(argv=None):
   """Executes tests in the test suite.
 
@@ -283,12 +355,15 @@ def run_suite_class(argv=None):
   suite = suite_class(runner, config)
   test_selector = _parse_raw_test_selector(cli_args.tests)
   suite.set_test_selector(test_selector)
+  suite_record = SuiteInfoRecord(suite_class_name=suite_class.__name__)
+
   console_level = logging.DEBUG if cli_args.verbose else logging.INFO
   ok = False
-  with runner.mobly_logger(console_level=console_level):
+  with runner.mobly_logger(console_level=console_level) as log_path:
     try:
       suite.setup_suite(config.copy())
       try:
+        suite_record.suite_begin()
         runner.run()
         ok = runner.results.is_all_pass
         print(ok)
@@ -296,6 +371,10 @@ def run_suite_class(argv=None):
         pass
     finally:
       suite.teardown_suite()
+      suite_record.suite_end()
+      suite_record.suite_run_display_name = suite.get_suite_run_display_name()
+      suite_record.extras = suite.get_suite_info().copy()
+      _dump_suite_info(suite_record, log_path)
   if not ok:
     sys.exit(1)
 
diff --git a/pyproject.toml b/pyproject.toml
index bb35d30..1a0c929 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -4,7 +4,7 @@ build-backend = "setuptools.build_meta"
 
 [project]
 name = "mobly"
-version = "1.12.4"
+version = "1.13"
 description = "Automation framework for special end-to-end test cases"
 requires-python = ">=3.11"
 dependencies = [ "portpicker", "pywin32; platform_system == \"Windows\"", "pyyaml",]
@@ -18,7 +18,7 @@ text = "Apache2.0"
 
 [project.urls]
 Homepage = "https://github.com/google/mobly"
-Download = "https://github.com/google/mobly/tarball/1.12.4"
+Download = "https://github.com/google/mobly/tarball/1.13"
 
 [project.optional-dependencies]
 testing = [ "mock", "pytest", "pytz",]
diff --git a/tests/mobly/controllers/android_device_lib/fastboot_test.py b/tests/mobly/controllers/android_device_lib/fastboot_test.py
index 10bc953..5a0b183 100644
--- a/tests/mobly/controllers/android_device_lib/fastboot_test.py
+++ b/tests/mobly/controllers/android_device_lib/fastboot_test.py
@@ -13,28 +13,26 @@
 # limitations under the License.
 
 import unittest
+from subprocess import PIPE
 from unittest import mock
 
 from mobly.controllers.android_device_lib import fastboot
 
 
 class FastbootTest(unittest.TestCase):
-  """Unit tests for mobly.controllers.android_device_lib.adb."""
+  """Unit tests for mobly.controllers.android_device_lib.fastboot."""
 
   def setUp(self):
     fastboot.FASTBOOT = 'fastboot'
 
-  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
+  @mock.patch('mobly.utils.run_command')
   @mock.patch('logging.debug')
   def test_fastboot_commands_and_results_are_logged_to_debug_log(
-      self, mock_debug_logger, mock_popen
+      self, mock_debug_logger, mock_run_command
   ):
     expected_stdout = 'stdout'
     expected_stderr = b'stderr'
-    mock_popen.return_value.communicate = mock.Mock(
-        return_value=(expected_stdout, expected_stderr)
-    )
-    mock_popen.return_value.returncode = 123
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
 
     fastboot.FastbootProxy().fake_command('extra', 'flags')
 
@@ -46,80 +44,137 @@ class FastbootTest(unittest.TestCase):
         123,
     )
 
-  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
-  def test_fastboot_without_serial(self, mock_popen):
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_without_serial(self, mock_run_command):
     expected_stdout = 'stdout'
     expected_stderr = b'stderr'
-    mock_popen.return_value.communicate = mock.Mock(
-        return_value=(expected_stdout, expected_stderr)
-    )
-    mock_popen.return_value.returncode = 123
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
 
     fastboot.FastbootProxy().fake_command('extra', 'flags')
 
-    mock_popen.assert_called_with(
-        'fastboot fake-command extra flags',
-        stdout=mock.ANY,
-        stderr=mock.ANY,
+    mock_run_command.assert_called_with(
+        cmd='fastboot fake-command extra flags',
+        stdout=PIPE,
+        stderr=PIPE,
         shell=True,
+        timeout=180,
     )
 
-  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
-  def test_fastboot_with_serial(self, mock_popen):
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_with_serial(self, mock_run_command):
     expected_stdout = 'stdout'
     expected_stderr = b'stderr'
-    mock_popen.return_value.communicate = mock.Mock(
-        return_value=(expected_stdout, expected_stderr)
-    )
-    mock_popen.return_value.returncode = 123
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
 
     fastboot.FastbootProxy('ABC').fake_command('extra', 'flags')
 
-    mock_popen.assert_called_with(
-        'fastboot -s ABC fake-command extra flags',
-        stdout=mock.ANY,
-        stderr=mock.ANY,
+    mock_run_command.assert_called_with(
+        cmd='fastboot -s ABC fake-command extra flags',
+        stdout=PIPE,
+        stderr=PIPE,
         shell=True,
+        timeout=180,
     )
 
-  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
-  def test_fastboot_update_serial(self, mock_popen):
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_update_serial(self, mock_run_command):
     expected_stdout = 'stdout'
     expected_stderr = b'stderr'
-    mock_popen.return_value.communicate = mock.Mock(
-        return_value=(expected_stdout, expected_stderr)
-    )
-    mock_popen.return_value.returncode = 123
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
 
     fut = fastboot.FastbootProxy('ABC')
     fut.fake_command('extra', 'flags')
     fut.serial = 'XYZ'
     fut.fake_command('extra', 'flags')
 
-    mock_popen.assert_called_with(
-        'fastboot -s XYZ fake-command extra flags',
-        stdout=mock.ANY,
-        stderr=mock.ANY,
+    mock_run_command.assert_called_with(
+        cmd='fastboot -s XYZ fake-command extra flags',
+        stdout=PIPE,
+        stderr=PIPE,
         shell=True,
+        timeout=180,
     )
 
-  @mock.patch('mobly.controllers.android_device_lib.fastboot.Popen')
-  def test_fastboot_use_customized_fastboot(self, mock_popen):
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_use_customized_fastboot(self, mock_run_command):
     expected_stdout = 'stdout'
     expected_stderr = b'stderr'
-    mock_popen.return_value.communicate = mock.Mock(
-        return_value=(expected_stdout, expected_stderr)
-    )
-    mock_popen.return_value.returncode = 123
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
+
     fastboot.FASTBOOT = 'my_fastboot'
 
     fastboot.FastbootProxy('ABC').fake_command('extra', 'flags')
 
-    mock_popen.assert_called_with(
-        'my_fastboot -s ABC fake-command extra flags',
-        stdout=mock.ANY,
-        stderr=mock.ANY,
+    mock_run_command.assert_called_with(
+        cmd='my_fastboot -s ABC fake-command extra flags',
+        stdout=PIPE,
+        stderr=PIPE,
+        shell=True,
+        timeout=180,
+    )
+
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_with_custom_timeout(self, mock_run_command):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
+
+    fastboot.FastbootProxy().fake_command('extra', 'flags', timeout=120)
+
+    mock_run_command.assert_called_with(
+        cmd='fastboot fake-command extra flags',
+        stdout=PIPE,
+        stderr=PIPE,
+        shell=True,
+        timeout=120,
+    )
+
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_args(self, mock_run_command):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
+
+    fastboot.FastbootProxy().args('-w', timeout=180)
+
+    mock_run_command.assert_called_with(
+        cmd='fastboot -w',
+        stdout=PIPE,
+        stderr=PIPE,
+        shell=True,
+        timeout=180,
+    )
+
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_args_with_custom_timeout(self, mock_run_command):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
+
+    fastboot.FastbootProxy().args('-w', timeout=20)
+
+    mock_run_command.assert_called_with(
+        cmd='fastboot -w',
+        stdout=PIPE,
+        stderr=PIPE,
+        shell=True,
+        timeout=20,
+    )
+
+  @mock.patch('mobly.utils.run_command')
+  def test_fastboot_exe_cmd_without_timeout_arg(self, mock_run_command):
+    expected_stdout = 'stdout'
+    expected_stderr = b'stderr'
+    mock_run_command.return_value = (123, expected_stdout, expected_stderr)
+
+    fastboot.exe_cmd('fastboot -w')
+
+    mock_run_command.assert_called_with(
+        cmd='fastboot -w',
+        stdout=PIPE,
+        stderr=PIPE,
         shell=True,
+        timeout=180,
     )
 
 
diff --git a/tests/mobly/controllers/android_device_lib/services/logcat_test.py b/tests/mobly/controllers/android_device_lib/services/logcat_test.py
index ebf4919..961b152 100755
--- a/tests/mobly/controllers/android_device_lib/services/logcat_test.py
+++ b/tests/mobly/controllers/android_device_lib/services/logcat_test.py
@@ -83,12 +83,12 @@ class LogcatTest(unittest.TestCase):
     shutil.rmtree(self.tmp_dir)
 
   def AssertFileContains(self, content, file_path):
-    with open(file_path, 'r') as f:
+    with open(file_path, 'r', newline='') as f:
       output = f.read()
     self.assertIn(content, output)
 
   def AssertFileDoesNotContain(self, content, file_path):
-    with open(file_path, 'r') as f:
+    with open(file_path, 'r', newline='') as f:
       output = f.read()
     self.assertNotIn(content, output)
 
@@ -320,7 +320,7 @@ class LogcatTest(unittest.TestCase):
     def _write_logcat_file_and_assert_excerpts_exists(
         logcat_file_content, test_begin_time, test_name
     ):
-      with open(logcat_service.adb_logcat_file_path, 'a') as f:
+      with open(logcat_service.adb_logcat_file_path, 'a', newline='') as f:
         f.write(logcat_file_content)
       test_output_dir = os.path.join(self.tmp_dir, test_name)
       mock_record = records.TestResultRecord(test_name)
@@ -348,11 +348,12 @@ class LogcatTest(unittest.TestCase):
     # Generate logs before the file pointer is created.
     # This message will not be captured in the excerpt.
     NOT_IN_EXCERPT = 'Not in excerpt.\n'
-    with open(logcat_service.adb_logcat_file_path, 'a') as f:
+    with open(logcat_service.adb_logcat_file_path, 'a', newline='') as f:
       f.write(NOT_IN_EXCERPT)
     # With the file pointer created, generate logs and make an excerpt.
     logcat_service._open_logcat_file()
-    FILE_CONTENT = 'Some log.\n'
+    # Both CR and LF should be preserved no matter the operating system.
+    FILE_CONTENT = 'Some log.\r\nAnother log.\n'
     expected_path1 = _write_logcat_file_and_assert_excerpts_exists(
         logcat_file_content=FILE_CONTENT,
         test_begin_time=123,
diff --git a/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py b/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
index 3f3752b..13f5782 100644
--- a/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
+++ b/tests/mobly/controllers/android_device_lib/snippet_client_v2_test.py
@@ -176,7 +176,11 @@ class SnippetClientV2Test(unittest.TestCase):
       self.client._counter = self.client._id_counter()
 
   def _assert_client_resources_released(
-      self, mock_start_subprocess, mock_stop_standing_subprocess, host_port
+      self,
+      mock_start_subprocess,
+      mock_stop_standing_subprocess,
+      host_port,
+      occupied_adb_ports_mock,
   ):
     """Asserts the resources had been released before the client stopped."""
     self.assertIs(self.client._proc, None)
@@ -192,7 +196,12 @@ class SnippetClientV2Test(unittest.TestCase):
     self.assertIs(self.client._conn, None)
     self.socket_conn.close.assert_called()
     self.assertIs(self.client.host_port, None)
-    self.adb.mock_forward_func.assert_any_call(['--remove', f'tcp:{host_port}'])
+    if self.client.host_port in occupied_adb_ports_mock.return_value:
+      # If the host port is not None, it means the client has been initialized
+      # and the port should be removed.
+      self.adb.mock_forward_func.assert_any_call(
+          ['--remove', f'tcp:{host_port}']
+      )
     self.assertIsNone(self.client._event_client)
 
   @mock.patch(
@@ -211,7 +220,7 @@ class SnippetClientV2Test(unittest.TestCase):
       mock_start_subprocess,
       mock_stop_standing_subprocess,
       mock_socket_create_conn,
-      _,
+      occupied_adb_ports_mock,
   ):
     """Tests the whole lifecycle of the client with sending a sync RPC."""
     socket_resp = [
@@ -234,7 +243,10 @@ class SnippetClientV2Test(unittest.TestCase):
     self.client.stop()
 
     self._assert_client_resources_released(
-        mock_start_subprocess, mock_stop_standing_subprocess, MOCK_HOST_PORT
+        mock_start_subprocess,
+        mock_stop_standing_subprocess,
+        MOCK_HOST_PORT,
+        occupied_adb_ports_mock,
     )
 
     self.assertListEqual(
@@ -263,7 +275,7 @@ class SnippetClientV2Test(unittest.TestCase):
       mock_start_subprocess,
       mock_stop_standing_subprocess,
       mock_socket_create_conn,
-      _,
+      ab_occupied_adb_ports_mock,
   ):
     """Tests the whole lifecycle of the client with sending an async RPC."""
     mock_socket_resp = [
@@ -290,7 +302,10 @@ class SnippetClientV2Test(unittest.TestCase):
     self.client.stop()
 
     self._assert_client_resources_released(
-        mock_start_subprocess, mock_stop_standing_subprocess, MOCK_HOST_PORT
+        mock_start_subprocess,
+        mock_stop_standing_subprocess,
+        MOCK_HOST_PORT,
+        ab_occupied_adb_ports_mock,
     )
 
     self.assertListEqual(
@@ -330,7 +345,7 @@ class SnippetClientV2Test(unittest.TestCase):
       mock_start_subprocess,
       mock_stop_standing_subprocess,
       mock_socket_create_conn,
-      _,
+      ab_occupied_adb_ports_mock,
   ):
     """Tests the whole lifecycle of the client with sending multiple RPCs."""
     # Prepare the test
@@ -397,7 +412,10 @@ class SnippetClientV2Test(unittest.TestCase):
     self.assertListEqual(rpc_results, rpc_results_expected)
     mock_callback_class.assert_has_calls(mock_callback_class_calls_expected)
     self._assert_client_resources_released(
-        mock_start_subprocess, mock_stop_standing_subprocess, MOCK_HOST_PORT
+        mock_start_subprocess,
+        mock_stop_standing_subprocess,
+        MOCK_HOST_PORT,
+        ab_occupied_adb_ports_mock,
     )
     self.assertIsNone(event_client.host_port, None)
     self.assertIsNone(event_client.device_port, None)
@@ -754,6 +772,30 @@ class SnippetClientV2Test(unittest.TestCase):
     self.client.start_server()
     self.assertEqual(123, self.client.device_port)
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'utils.start_standing_subprocess'
+  )
+  def test_start_server_error_message_include_discarded_output(
+      self, mock_start_standing_subprocess
+  ):
+    """Tests that starting server process reports known protocol with junk."""
+    self._make_client()
+    discarded_output = 'java.lang.RuntimeException: Failed to start server'
+    self._mock_server_process_starting_response(
+        mock_start_standing_subprocess,
+        resp_lines=[
+            b'SNIPPET START, PROTOCOL 1 0\n',
+            discarded_output.encode('utf-8'),
+            b'INSTRUMENTATION_RESULT: shortMsg=Process crashed.',
+        ],
+    )
+    with self.assertRaisesRegex(
+        errors.ServerStartProtocolError,
+        discarded_output,
+    ):
+      self.client.start_server()
+
   @mock.patch(
       'mobly.controllers.android_device_lib.snippet_client_v2.'
       'utils.start_standing_subprocess'
@@ -775,8 +817,12 @@ class SnippetClientV2Test(unittest.TestCase):
     ):
       self.client.start_server()
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
-  def test_stop_normally(self, mock_stop_standing_subprocess):
+  def test_stop_normally(self, mock_stop_standing_subprocess, _):
     """Tests that stopping server process works normally."""
     self._make_client()
     mock_proc = mock.Mock()
@@ -803,9 +849,13 @@ class SnippetClientV2Test(unittest.TestCase):
     )
     self.assertIsNone(self.client._event_client)
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
   def test_stop_when_server_is_already_cleaned(
-      self, mock_stop_standing_subprocess
+      self, mock_stop_standing_subprocess, _
   ):
     """Tests that stop server process when subprocess is already cleaned."""
     self._make_client()
@@ -830,9 +880,13 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
   def test_stop_when_conn_is_already_cleaned(
-      self, mock_stop_standing_subprocess
+      self, mock_stop_standing_subprocess, _
   ):
     """Tests that stop server process when the connection is already closed."""
     self._make_client()
@@ -856,10 +910,17 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
   @mock.patch.object(_MockAdbProxy, 'shell', return_value=b'Closed with error.')
   def test_stop_with_device_side_error(
-      self, mock_adb_shell, mock_stop_standing_subprocess
+      self,
+      mock_adb_shell,
+      mock_stop_standing_subprocess,
+      _,
   ):
     """Tests all resources will be cleaned when server stop throws an error."""
     self._make_client()
@@ -888,8 +949,12 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
-  def test_stop_with_conn_close_error(self, mock_stop_standing_subprocess):
+  def test_stop_with_conn_close_error(self, mock_stop_standing_subprocess, _):
     """Tests port resource will be cleaned when socket close throws an error."""
     del mock_stop_standing_subprocess
     self._make_client()
@@ -908,6 +973,10 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
   @mock.patch.object(
       snippet_client_v2.SnippetClientV2, 'create_socket_connection'
@@ -920,6 +989,7 @@ class SnippetClientV2Test(unittest.TestCase):
       mock_send_handshake_func,
       mock_create_socket_conn_func,
       mock_stop_standing_subprocess,
+      _,
   ):
     """Tests that stopping with an event client works normally."""
     del mock_send_handshake_func
@@ -950,6 +1020,10 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.adb.list_occupied_adb_ports',
+      return_value=[12345],
+  )
   @mock.patch('mobly.utils.stop_standing_subprocess')
   @mock.patch.object(
       snippet_client_v2.SnippetClientV2, 'create_socket_connection'
@@ -962,6 +1036,7 @@ class SnippetClientV2Test(unittest.TestCase):
       mock_send_handshake_func,
       mock_create_socket_conn_func,
       mock_stop_standing_subprocess,
+      _,
   ):
     """Tests that client with an event client stops port forwarding once."""
     del mock_send_handshake_func
@@ -982,7 +1057,12 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:12345']
     )
 
-  def test_close_connection_normally(self):
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'adb.list_occupied_adb_ports',
+      return_value=[123],
+  )
+  def test_close_connection_normally(self, _):
     """Tests that closing connection works normally."""
     self._make_client()
     mock_conn = mock.Mock()
@@ -998,7 +1078,12 @@ class SnippetClientV2Test(unittest.TestCase):
         ['--remove', 'tcp:123']
     )
 
-  def test_close_connection_when_host_port_has_been_released(self):
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'adb.list_occupied_adb_ports',
+      return_value=[],
+  )
+  def test_close_connection_when_host_port_has_been_released(self, _):
     """Tests that close connection when the host port has been released."""
     self._make_client()
     mock_conn = mock.Mock()
@@ -1012,7 +1097,12 @@ class SnippetClientV2Test(unittest.TestCase):
     mock_conn.close.assert_called_once_with()
     self.device.adb.mock_forward_func.assert_not_called()
 
-  def test_close_connection_when_conn_have_been_closed(self):
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'adb.list_occupied_adb_ports',
+      return_value=[123],
+  )
+  def test_close_connection_when_conn_have_been_closed(self, _):
     """Tests that close connection when the connection has been closed."""
     self._make_client()
     self.client._conn = None
@@ -1458,6 +1548,65 @@ class SnippetClientV2Test(unittest.TestCase):
         snippet_client_v2._SOCKET_READ_TIMEOUT
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'adb.list_occupied_adb_ports',
+      return_value=[],
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'utils.run_command'
+  )
+  @mock.patch('socket.create_connection')
+  def test_make_connection_when_host_port_is_not_in_listening_state_(
+      self, mock_socket_create_conn, mock_run_cmd, _
+  ):
+    """Tests IOError occurred trying to create a socket connection."""
+    mock_socket_create_conn.side_effect = ConnectionRefusedError(
+        f'[Errno 111] Connection refused.'
+    )
+    mock_run_cmd.return_value = (1, b'', b'')
+    error_msg = 'The Adb forward command execution did not take effect'
+    with self.assertRaisesRegex(errors.Error, error_msg):
+      self._make_client()
+      self.client.device_port = 123
+      self.client.make_connection()
+
+    mock_run_cmd.assert_any_call(
+        f'netstat -tulpn | grep ":{MOCK_HOST_PORT}"', shell=True
+    )
+
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'adb.list_occupied_adb_ports',
+      return_value=[],
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.snippet_client_v2.'
+      'utils.run_command'
+  )
+  @mock.patch('socket.create_connection')
+  def test_make_connection_raise_when_host_port_is_in_listening_state_(
+      self, mock_socket_create_conn, mock_run_cmd, _
+  ):
+    """Tests IOError occurred trying to create a socket connection."""
+    mock_socket_create_conn.side_effect = ConnectionRefusedError(
+        f'[Errno 111] Connection refused.'
+    )
+    mock_run_cmd.return_value = (0, f'127.0.0.1:{MOCK_HOST_PORT}'.encode(), b'')
+    error_msg = (
+        'Failed to establish socket connection from host to snippet server'
+        ' running on Android device.'
+    )
+    with self.assertRaisesRegex(errors.Error, error_msg):
+      self._make_client()
+      self.client.device_port = 123
+      self.client.make_connection()
+
+    mock_run_cmd.assert_any_call(
+        f'netstat -tulpn | grep ":{MOCK_HOST_PORT}"', shell=True
+    )
+
   @mock.patch(
       'mobly.controllers.android_device_lib.snippet_client_v2.'
       'adb.list_occupied_adb_ports',
diff --git a/tests/mobly/controllers/android_device_test.py b/tests/mobly/controllers/android_device_test.py
index 557af5f..640f28c 100755
--- a/tests/mobly/controllers/android_device_test.py
+++ b/tests/mobly/controllers/android_device_test.py
@@ -1159,6 +1159,148 @@ class AndroidDeviceTest(unittest.TestCase):
         ),
     )
 
+  @mock.patch(
+      'mobly.controllers.android_device_lib.adb.AdbProxy',
+      return_value=mock_android_device.MockAdbProxy('1'),
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
+      return_value=mock_android_device.MockFastbootProxy('1'),
+  )
+  @mock.patch('mobly.utils.create_dir')
+  @mock.patch('mobly.logger.get_log_file_timestamp')
+  def test_AndroidDevice_take_screenshot_all_displays(
+      self,
+      get_log_file_timestamp_mock,
+      create_dir_mock,
+      FastbootProxy,
+      MockAdbProxy,
+  ):
+    test_adb_proxy = MockAdbProxy.return_value
+    original_mock_adb_instance_shell = MockAdbProxy.shell
+
+    def custom_shell_for_screenshot(params, timeout=None):
+      if f'ls /storage/emulated/0/*.png' in params:
+        return (
+            b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_17-53-34-450_0.png\n'
+            + b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_17-53-34-450_1.png\n'
+        )
+      return original_mock_adb_instance_shell(params, timeout)
+
+    test_adb_proxy.shell = custom_shell_for_screenshot
+
+    get_log_file_timestamp_mock.return_value = '07-22-2019_17-53-34-450'
+    mock_serial = '1'
+    ad = android_device.AndroidDevice(serial=mock_serial)
+    full_pic_paths = ad.take_screenshot(self.tmp_dir, all_displays=True)
+    self.assertEqual(
+        full_pic_paths,
+        [
+            os.path.join(
+                self.tmp_dir,
+                'screenshot,1,fakemodel,07-22-2019_17-53-34-450_0.png',
+            ),
+            os.path.join(
+                self.tmp_dir,
+                'screenshot,1,fakemodel,07-22-2019_17-53-34-450_1.png',
+            ),
+        ],
+    )
+
+  @mock.patch(
+      'mobly.controllers.android_device_lib.adb.AdbProxy',
+      return_value=mock_android_device.MockAdbProxy('1'),
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
+      return_value=mock_android_device.MockFastbootProxy('1'),
+  )
+  @mock.patch('mobly.utils.create_dir')
+  @mock.patch('mobly.logger.get_log_file_timestamp')
+  def test_AndroidDevice_take_screenshot_all_displays_with_additional_files(
+      self,
+      get_log_file_timestamp_mock,
+      create_dir_mock,
+      FastbootProxy,
+      MockAdbProxy,
+  ):
+    test_adb_proxy = MockAdbProxy.return_value
+    original_mock_adb_instance_shell = MockAdbProxy.shell
+
+    def custom_shell_for_screenshot(params, timeout=None):
+      if f'ls /storage/emulated/0/*.png' in params:
+        return (
+            b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_17-53-34-450_0.png\n'
+            + b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_17-53-34-450_1.png\n'
+            b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_16-53-34-450_0.png\n'
+            + b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_16-53-34-450_1.png\n'
+        )
+      return original_mock_adb_instance_shell(params, timeout)
+
+    test_adb_proxy.shell = custom_shell_for_screenshot
+
+    get_log_file_timestamp_mock.return_value = '07-22-2019_17-53-34-450'
+    mock_serial = '1'
+    ad = android_device.AndroidDevice(serial=mock_serial)
+    full_pic_paths = ad.take_screenshot(self.tmp_dir, all_displays=True)
+    self.assertEqual(
+        full_pic_paths,
+        [
+            os.path.join(
+                self.tmp_dir,
+                'screenshot,1,fakemodel,07-22-2019_17-53-34-450_0.png',
+            ),
+            os.path.join(
+                self.tmp_dir,
+                'screenshot,1,fakemodel,07-22-2019_17-53-34-450_1.png',
+            ),
+        ],
+    )
+
+  @mock.patch(
+      'mobly.controllers.android_device_lib.adb.AdbProxy',
+      return_value=mock_android_device.MockAdbProxy('1'),
+  )
+  @mock.patch(
+      'mobly.controllers.android_device_lib.fastboot.FastbootProxy',
+      return_value=mock_android_device.MockFastbootProxy('1'),
+  )
+  @mock.patch('mobly.utils.create_dir')
+  @mock.patch('mobly.logger.get_log_file_timestamp')
+  def test_AndroidDevice_take_screenshot_all_displays_with_single_display(
+      self,
+      get_log_file_timestamp_mock,
+      create_dir_mock,
+      FastbootProxy,
+      MockAdbProxy,
+  ):
+    test_adb_proxy = MockAdbProxy.return_value
+    original_mock_adb_instance_shell = MockAdbProxy.shell
+
+    def custom_shell_for_screenshot(params, timeout=None):
+      if f'ls /storage/emulated/0/*.png' in params:
+        return (
+            # when there is a single display there is no suffix on the png filename
+            b'/storage/emulated/0/screenshot,1,fakemodel,07-22-2019_17-53-34-450.png\n'
+        )
+      return original_mock_adb_instance_shell(params, timeout)
+
+    test_adb_proxy.shell = custom_shell_for_screenshot
+
+    get_log_file_timestamp_mock.return_value = '07-22-2019_17-53-34-450'
+    mock_serial = '1'
+    ad = android_device.AndroidDevice(serial=mock_serial)
+    full_pic_paths = ad.take_screenshot(self.tmp_dir, all_displays=True)
+    self.assertEqual(
+        full_pic_paths,
+        [
+            os.path.join(
+                self.tmp_dir,
+                'screenshot,1,fakemodel,07-22-2019_17-53-34-450.png',
+            ),
+        ],
+    )
+
   @mock.patch(
       'mobly.controllers.android_device_lib.adb.AdbProxy',
       return_value=mock_android_device.MockAdbProxy('1'),
diff --git a/tests/mobly/suite_runner_test.py b/tests/mobly/suite_runner_test.py
index 0a716ed..a81c098 100755
--- a/tests/mobly/suite_runner_test.py
+++ b/tests/mobly/suite_runner_test.py
@@ -13,20 +13,25 @@
 # limitations under the License.
 
 import io
+import logging
 import os
 import shutil
 import sys
 import tempfile
+import time
 import unittest
 from unittest import mock
 
 from mobly import base_suite
 from mobly import base_test
+from mobly import records
 from mobly import suite_runner
 from mobly import test_runner
+from mobly import utils
 from tests.lib import integration2_test
 from tests.lib import integration_test
 from tests.lib import integration_test_suite
+import yaml
 
 
 class FakeTest1(base_test.BaseTestClass):
@@ -175,10 +180,11 @@ class SuiteRunnerTest(unittest.TestCase):
     mock_called.set_test_selector.assert_called_once_with(None)
 
   @mock.patch('sys.exit')
+  @mock.patch.object(records, 'TestSummaryWriter', autospec=True)
   @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
   @mock.patch.object(test_runner, 'TestRunner')
   def test_run_suite_class_with_test_selection_by_class(
-      self, mock_test_runner_class, mock_find_suite_class, mock_exit
+      self, mock_test_runner_class, mock_find_suite_class, *_
   ):
     mock_test_runner = mock_test_runner_class.return_value
     mock_test_runner.results.is_all_pass = True
@@ -213,10 +219,11 @@ class SuiteRunnerTest(unittest.TestCase):
     )
 
   @mock.patch('sys.exit')
+  @mock.patch.object(records, 'TestSummaryWriter', autospec=True)
   @mock.patch.object(suite_runner, '_find_suite_class', autospec=True)
   @mock.patch.object(test_runner, 'TestRunner')
   def test_run_suite_class_with_test_selection_by_method(
-      self, mock_test_runner_class, mock_find_suite_class, mock_exit
+      self, mock_test_runner_class, mock_find_suite_class, *_
   ):
     mock_test_runner = mock_test_runner_class.return_value
     mock_test_runner.results.is_all_pass = True
@@ -311,12 +318,13 @@ class SuiteRunnerTest(unittest.TestCase):
     mock_exit.assert_not_called()
 
   @mock.patch('sys.exit')
+  @mock.patch.object(records, 'TestSummaryWriter', autospec=True)
   @mock.patch.object(test_runner, 'TestRunner')
   @mock.patch.object(
       integration_test_suite.IntegrationTestSuite, 'setup_suite', autospec=True
   )
   def test_run_suite_class_finds_suite_class_when_not_in_main_module(
-      self, mock_setup_suite, mock_test_runner_class, mock_exit
+      self, mock_setup_suite, mock_test_runner_class, *_
   ):
     mock_test_runner = mock_test_runner_class.return_value
     mock_test_runner.results.is_all_pass = True
@@ -328,6 +336,54 @@ class SuiteRunnerTest(unittest.TestCase):
 
     mock_setup_suite.assert_called_once()
 
+  @mock.patch('sys.exit')
+  @mock.patch.object(
+      utils, 'get_current_epoch_time', return_value=1733143236278
+  )
+  def test_run_suite_class_records_suite_info(self, mock_time, _):
+    tmp_file_path = self._gen_tmp_config_file()
+    mock_cli_args = ['test_binary', f'--config={tmp_file_path}']
+    expected_record = suite_runner.SuiteInfoRecord(
+        suite_class_name='FakeTestSuite'
+    )
+    expected_record.suite_begin()
+    expected_record.suite_end()
+    expected_record.suite_run_display_name = 'FakeTestSuite - Pixel'
+    expected_record.extras = {'version': '1.0.0'}
+    expected_summary_entry = expected_record.to_dict()
+    expected_summary_entry['Type'] = (
+        suite_runner.TestSummaryEntryType.SUITE_INFO.value
+    )
+
+    class FakeTestSuite(base_suite.BaseSuite):
+
+      def setup_suite(self, config):
+        super().setup_suite(config)
+        self.add_test_class(FakeTest1)
+
+      def teardown_suite(self):
+        self.set_suite_run_display_name('FakeTestSuite - Pixel')
+        self.set_suite_info({'version': '1.0.0'})
+
+    sys.modules['__main__'].__dict__[FakeTestSuite.__name__] = FakeTestSuite
+
+    with mock.patch.object(sys, 'argv', new=mock_cli_args):
+      try:
+        suite_runner.run_suite_class()
+      finally:
+        del sys.modules['__main__'].__dict__[FakeTestSuite.__name__]
+
+    summary_path = os.path.join(
+        logging.root_output_path, records.OUTPUT_FILE_SUMMARY
+    )
+    with io.open(summary_path, 'r', encoding='utf-8') as f:
+      summary_entries = list(yaml.safe_load_all(f))
+
+    self.assertIn(
+        expected_summary_entry,
+        summary_entries,
+    )
+
   @mock.patch('builtins.print')
   def test_print_test_names_for_suites(self, mock_print):
     class FakeTestSuite(base_suite.BaseSuite):
@@ -365,6 +421,36 @@ class SuiteRunnerTest(unittest.TestCase):
     mock_cls_instance._pre_run.side_effect = Exception('Something went wrong.')
     mock_cls_instance._clean_up.assert_called_once()
 
+  def test_convert_suite_info_record_to_dict(self):
+    suite_class_name = 'FakeTestSuite'
+    suite_run_display_name = 'FakeTestSuite - Pixel'
+    suite_version = '1.2.3'
+    record = suite_runner.SuiteInfoRecord(suite_class_name=suite_class_name)
+    record.extras = {'version': suite_version}
+    record.suite_begin()
+    record.suite_end()
+    record.suite_run_display_name = suite_run_display_name
+
+    result = record.to_dict()
+
+    self.assertIn(
+        (suite_runner.SuiteInfoRecord.KEY_SUITE_CLASS_NAME, suite_class_name),
+        result.items(),
+    )
+    self.assertIn(
+        (suite_runner.SuiteInfoRecord.KEY_EXTRAS, {'version': suite_version}),
+        result.items(),
+    )
+    self.assertIn(
+        (
+            suite_runner.SuiteInfoRecord.KEY_SUITE_RUN_DISPLAY_NAME,
+            suite_run_display_name,
+        ),
+        result.items(),
+    )
+    self.assertIn(suite_runner.SuiteInfoRecord.KEY_BEGIN_TIME, result)
+    self.assertIn(suite_runner.SuiteInfoRecord.KEY_END_TIME, result)
+
   def _gen_tmp_config_file(self):
     tmp_file_path = os.path.join(self.tmp_dir, 'config.yml')
     with io.open(tmp_file_path, 'w', encoding='utf-8') as f:
```

