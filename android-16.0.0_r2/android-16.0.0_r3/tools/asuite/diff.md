```diff
diff --git a/atest/Android.bp b/atest/Android.bp
index 6753206c..31e542dd 100644
--- a/atest/Android.bp
+++ b/atest/Android.bp
@@ -48,9 +48,6 @@ python_defaults {
 python_defaults {
     name: "atest_binary_defaults",
     defaults: ["atest_defaults"],
-    data: [
-        "bazel/resources/**/*",
-    ],
     exclude_srcs: [
         "integration_tests/*.py",
         "*_unittest.py",
diff --git a/atest/OWNERS b/atest/OWNERS
index c6b67de5..4bf1e22e 100644
--- a/atest/OWNERS
+++ b/atest/OWNERS
@@ -7,4 +7,3 @@ yangbill@google.com
 kellyhung@google.com
 nelsonli@google.com
 jingwen@google.com
-
diff --git a/atest/arg_parser.py b/atest/arg_parser.py
index 68c56c11..9e5103b9 100644
--- a/atest/arg_parser.py
+++ b/atest/arg_parser.py
@@ -18,9 +18,13 @@
 
 import argparse
 
-from atest import bazel_mode
 from atest import constants
 from atest.atest_utils import BuildOutputMode
+from atest.crystalball import perf_mode
+
+_EXTRA_MODULE_MAP = {
+    perf_mode.PERF_MODE_ARG_NAME: perf_mode,
+}
 
 
 def _output_mode_msg() -> str:
@@ -117,28 +121,6 @@ def create_atest_arg_parser():
       const=constants.BUILD_STEP,
       help='Run a build.',
   )
-  parser.add_argument(
-      '--bazel-mode',
-      default=True,
-      action='store_true',
-      help='Run tests using Bazel (default: True).',
-  )
-  parser.add_argument(
-      '--no-bazel-mode',
-      dest='bazel_mode',
-      action='store_false',
-      help='Run tests without using Bazel.',
-  )
-  parser.add_argument(
-      '--bazel-arg',
-      nargs='*',
-      action='append',
-      help=(
-          'Forward a flag to Bazel for tests executed with Bazel; see'
-          ' --bazel-mode.'
-      ),
-  )
-  bazel_mode.add_parser_arguments(parser, dest='bazel_mode_features')
 
   parser.add_argument(
       '-d',
@@ -192,6 +174,16 @@ def create_atest_arg_parser():
       ),
   )
 
+  parser.add_argument(
+      '--class-level-report',
+      default=False,
+      action='store_true',
+      help=(
+          'Summarize the test results by test classes (default: False, which'
+          ' summarizes the test results by test modules).'
+      ),
+  )
+
   hgroup = parser.add_mutually_exclusive_group()
   hgroup.add_argument(
       '--host',
@@ -256,8 +248,9 @@ def create_atest_arg_parser():
       ),
   )
   parser.add_argument(
-      '--smart-test-selection',
+      '--sts',
       default=False,
+      dest='smart_test_selection',
       action='store_true',
       help=(
           'Automatically select test classes based on correlation with code'
@@ -521,21 +514,6 @@ def create_atest_arg_parser():
       help='(For metrics) Do not send metrics.',
   )
 
-  parser.add_argument(
-      '--aggregate-metric-filter',
-      action='append',
-      help=(
-          '(For performance tests) Regular expression that will be used for'
-          ' filtering the aggregated metrics.'
-      ),
-  )
-
-  parser.add_argument(
-      '--perf-itr-metrics',
-      action='store_true',
-      help='(For performance tests) Print individual performance metric.',
-  )
-
   parser.add_argument(
       '--no-checking-device',
       action='store_true',
@@ -560,6 +538,8 @@ def create_atest_arg_parser():
       help='Run tests using atest_local_min.xml as the TF base templates.',
   )
 
+  perf_mode.add_global_arguments(parser)
+
   # This arg actually doesn't consume anything, it's primarily used for
   # the help description and creating custom_args in the NameSpace object.
   parser.add_argument(
@@ -575,6 +555,25 @@ def create_atest_arg_parser():
   return parser
 
 
+def parse_args(argv: list[str]) -> argparse.Namespace:
+  """Parses the command line arguments."""
+  parser = create_atest_arg_parser()
+
+  for arg, module in _EXTRA_MODULE_MAP.items():
+    if arg in argv:
+      module.add_arguments(parser)
+
+  parsed_args = parser.parse_args(argv)
+  if not parsed_args.custom_args:
+    parsed_args.custom_args = []
+
+  for arg, module in _EXTRA_MODULE_MAP.items():
+    if arg in argv:
+      module.process_parsed_args(parsed_args)
+
+  return parsed_args
+
+
 _HELP_DESCRIPTION = """NAME
         atest - A command line tool that allows users to build, install, and run Android tests locally, greatly speeding test re-runs without requiring knowledge of Trade Federation test harness command line options.
 
diff --git a/atest/atest_enum.py b/atest/atest_enum.py
index 2ac3a352..5f7671cc 100644
--- a/atest/atest_enum.py
+++ b/atest/atest_enum.py
@@ -50,14 +50,16 @@ class DetectType(IntEnum):
   MODULE_INFO_INIT_TIME = 19  # Deprecated. Use MODULE_INFO_INIT_MS instead.
   MODULE_MERGE_MS = 20
   NATIVE_TEST_NOT_FOUND = 21
-  BAZEL_WORKSPACE_GENERATE_TIME = 22
+  BAZEL_WORKSPACE_GENERATE_TIME = 22  # Deprecated. Bazel mode has been removed.
   MODULE_LOAD_MS = 23
   MODULE_INFO_INIT_MS = 24
   INIT_AND_FIND_MS = 25
   FOUND_INSTRUMENTATION_TEST = 26
   FOUND_TARGET_ARTIFACTS = 27
   FIND_TEST_IN_DEPS = 28
-  FULL_GENERATE_BAZEL_WORKSPACE_TIME = 29
+  FULL_GENERATE_BAZEL_WORKSPACE_TIME = (
+      29  # Deprecated. Bazel mode has been removed.
+  )
   # Below detect types are used for determine build conditions:
   # 1. *_CLEAN_OUT: when out/ dir is empty or does not exist.
   # 2. *_BPMK_CHANGE: when any Android.bp/Android.mk has changed.
@@ -125,6 +127,12 @@ class DetectType(IntEnum):
   APP_INSTALLATION_SKIPPED_COUNT = 67
   # The count of not skipped app installation while opting in incremental setup
   APP_INSTALLATION_NOT_SKIPPED_COUNT = 68
+  # The number of run errors during the test run
+  RUN_ERROR_COUNT = 69
+  # Whether no test run issue occurred during the Atest invocation
+  HAS_NO_TEST_RUN_ISSUE = 70
+  # Whether no tests are returned with smart test selection
+  STS_SELECT_NO_TEST = 71
 
 
 @unique
@@ -153,6 +161,8 @@ class ExitCode(IntEnum):
   INVALID_TM_ARGS = 19
   INVALID_TM_FORMAT = 20
   INSUFFICIENT_DEVICES = 21
+  FEATURE_NOT_IMPLEMENTED = 22
+  OUTSIDE_REPO = 23
   # The code > 100 are reserved for collecting data only, actually the run
   # doesn't finish at the point.
   COLLECT_ONLY_FILE_NOT_FOUND = 101
diff --git a/atest/atest_execution_info.py b/atest/atest_execution_info.py
index 2e672b08..5f0101e3 100644
--- a/atest/atest_execution_info.py
+++ b/atest/atest_execution_info.py
@@ -23,6 +23,7 @@ import json
 import logging
 import os
 import pathlib
+import re
 import shutil
 import sys
 import time
@@ -69,6 +70,13 @@ _SUMMARY_MAP_TEMPLATE = {
 
 PREPARE_END_TIME = None
 
+_INCLUDE_FILTER_REGEX = re.compile(
+    r'--atest-include-filter (?P<include_filter>[^\s]+)'
+)
+_INVOCATION_FOLDER_REGEX = re.compile(
+    r'Creating temp file at (?P<inv_folder>[^\s]+)'
+)
+
 
 def preparation_time(start_time):
   """Return the preparation time.
@@ -298,6 +306,62 @@ def parse_test_log_and_send_app_installation_stats_metrics(
     logging.debug('An error occurred when accessing certain host logs: %s', e)
 
 
+def append_test_info_to_invocation_pathnames(
+    log_path: pathlib.Path,
+) -> None:
+  """Append test info to invocation paths for a better readability."""
+  if not log_path:
+    return
+
+  # Attempt to find all host logs
+  absolute_host_log_paths = list(log_path.glob(f'**/{_HOST_LOG_PREFIX}*'))
+
+  if not absolute_host_log_paths:
+    return
+
+  try:
+    for host_log_path in absolute_host_log_paths:
+      if not host_log_path.is_file():
+        continue
+
+      # Open the host log and parse test filter and invocation folder names.
+      with open(f'{host_log_path}', 'r') as host_log_file:
+        test_filter = ''
+        invocation_folder_name = ''
+        for line in host_log_file:
+          if not test_filter:
+            include_filters = []
+            for match in _INCLUDE_FILTER_REGEX.finditer(line):
+              single_test_filter = (
+                  match.group('include_filter')
+                  .replace(':', '_')
+                  .replace('#', '_')
+                  .replace('?', '_')
+                  .replace('*', '_')
+              )
+              include_filters.append(single_test_filter)
+            if include_filters:
+              test_filter = '_'.join(include_filters)
+          if not invocation_folder_name:
+            match = _INVOCATION_FOLDER_REGEX.search(line)
+            if match:
+              invocation_folder_name = match.group('inv_folder')
+
+          if invocation_folder_name and test_filter:
+            break
+
+        if invocation_folder_name and test_filter:
+          new_inv_pathname = f'{invocation_folder_name}__{test_filter}'
+          logging.debug(
+              'Renaming %s to %s',
+              invocation_folder_name,
+              new_inv_pathname,
+          )
+          pathlib.Path(invocation_folder_name).replace(new_inv_pathname)
+  except Exception as e:
+    logging.debug('An error occurred when accessing certain host log: %s', e)
+
+
 class AtestExecutionInfo:
   """Class that stores the whole test progress information in JSON format.
 
@@ -360,6 +424,7 @@ class AtestExecutionInfo:
            A json format string.
     """
     self.args = args
+    self.smart_test_selection = '--sts' in args
     self.work_dir = work_dir
     self.result_file_obj = None
     self.args_ns = args_ns
@@ -421,17 +486,6 @@ class AtestExecutionInfo:
         'verbose.log',
     )
 
-    html_path = None
-
-    if self.result_file_obj and not has_non_test_options(self.args_ns):
-      self.result_file_obj.write(
-          AtestExecutionInfo._generate_execution_detail(self.args)
-      )
-      self.result_file_obj.close()
-      atest_utils.prompt_suggestions(self.test_result)
-      html_path = atest_utils.generate_result_html(self.test_result)
-      symlink_latest_result(self.work_dir)
-
     if self.get_exit_code_func:
       main_exit_code = self.get_exit_code_func()
     else:
@@ -446,6 +500,19 @@ class AtestExecutionInfo:
     if log_path:
       print(f'Test logs: {log_path / "log"}')
       parse_test_log_and_send_app_installation_stats_metrics(log_path)
+      if self.smart_test_selection:
+        append_test_info_to_invocation_pathnames(log_path)
+
+    html_path = None
+    if self.result_file_obj and not has_non_test_options(self.args_ns):
+      self.result_file_obj.write(
+          AtestExecutionInfo._generate_execution_detail(self.args)
+      )
+      self.result_file_obj.close()
+      atest_utils.prompt_suggestions(self.test_result)
+      html_path = atest_utils.generate_result_html(self.test_result)
+      symlink_latest_result(self.work_dir)
+
     log_link = html_path if html_path else log_path
     if log_link:
       print(atest_utils.mark_magenta(f'Log file list: file://{log_link}'))
diff --git a/atest/atest_execution_info_unittest.py b/atest/atest_execution_info_unittest.py
index 75c84013..76dbda69 100755
--- a/atest/atest_execution_info_unittest.py
+++ b/atest/atest_execution_info_unittest.py
@@ -427,5 +427,129 @@ class AtestExecutionInfoUnittests(unittest.TestCase):
     return test_info._replace(**kwargs)
 
 
+class RenameInvocationPathnamesTest(fake_filesystem_unittest.TestCase):
+
+  def setUp(self):
+    self.setUpPyfakefs()
+    self.fs.create_dir(pathlib.Path('/logs'))
+
+  def test_append_test_info_to_invocation_pathnames_inv_paths_successfully_renamed(
+      self,
+  ):
+    log_path = pathlib.Path('/logs')
+    inv_path1 = log_path / 'log/stub/local_atest/inv_1'
+    self.fs.create_dir(inv_path1)
+    host_log_path1 = inv_path1 / 'host_log_test1.txt'
+    self.fs.create_file(
+        host_log_path1,
+        contents="""
+        Running tests with filter --some-filter filter_value --atest-include-filter TestAModule:com.package.TestAClass --some-other-filter other_filter_value
+        Creating temp file at /logs/log/stub/local_atest/inv_1
+        """,
+    )
+    inv_path2 = log_path / 'log/stub/local_atest/inv_2'
+    self.fs.create_dir(inv_path2)
+    inv_path3 = log_path / 'log/stub/local_atest/inv_3'
+    self.fs.create_dir(inv_path3)
+    host_log_path2 = inv_path2 / 'host_log_test2.txt'
+    self.fs.create_file(
+        host_log_path2,
+        contents="""
+        Running tests with filter --some-filter filter_value --atest-include-filter TestBModule:com.package.TestBClass#testBMethod --some-other-filter other_filter_value
+        Creating temp file at /logs/log/stub/local_atest/inv_2
+        Creating temp file at /logs/log/stub/local_atest/inv_3
+        """,
+    )
+    inv_path4 = log_path / 'log/stub/local_atest/inv_4'
+    self.fs.create_dir(inv_path4)
+    self.fs.create_dir(
+        log_path
+        / 'log/stub/local_atest/inv_4__TestCModule_com.package.TestCClass'
+    )
+    host_log_path4 = inv_path4 / 'host_log_test4.txt'
+    self.fs.create_file(
+        host_log_path4,
+        contents="""
+        Running tests with filter --some-filter filter_value --atest-include-filter TestCModule:com.package.TestCClass --some-other-filter other_filter_value --include-filter Cts*Test?MyModule
+        Creating temp file at /logs/log/stub/local_atest/inv_4
+        """,
+    )
+
+    aei.append_test_info_to_invocation_pathnames(log_path)
+
+    self.assertFalse(os.path.exists('/logs/log/stub/local_atest/inv_1'))
+    self.assertFalse(os.path.exists('/logs/log/stub/local_atest/inv_2'))
+    self.assertTrue(os.path.exists('/logs/log/stub/local_atest/inv_3'))
+    self.assertFalse(os.path.exists('/logs/log/stub/local_atest/inv_4'))
+    self.assertTrue(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_1__TestAModule_com.package.TestAClass'
+        )
+    )
+    self.assertTrue(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_2__TestBModule_com.package.TestBClass_testBMethod'
+        )
+    )
+    self.assertFalse(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_3__TestBModule_com.package.TestBClass_testBMethod'
+        )
+    )
+    self.assertTrue(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_4__TestCModule_com.package.TestCClass/host_log_test4.txt'
+        )
+    )
+
+  def test_append_test_info_to_invocation_pathnames_inv_paths_no_rename_due_to_no_test_filter(
+      self,
+  ):
+    log_path = pathlib.Path('/logs')
+    inv_path1 = log_path / 'log/stub/local_atest/inv_1'
+    self.fs.create_dir(inv_path1)
+    host_log_path1 = inv_path1 / 'host_log_test1.txt'
+    self.fs.create_file(
+        host_log_path1,
+        contents="""
+        Running tests with filter --some-filter filter_value --include-filter TestAModule:com.package.TestAClass --some-other-filter other_filter_value
+        Creating temp file at /logs/log/stub/local_atest/inv_1
+        """,
+    )
+
+    aei.append_test_info_to_invocation_pathnames(log_path)
+
+    self.assertTrue(os.path.exists('/logs/log/stub/local_atest/inv_1'))
+    self.assertFalse(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_1__TestAModule_com.package.TestAClass'
+        )
+    )
+
+  def test_append_test_info_to_invocation_pathnames_inv_paths_no_rename_due_to_no_inv_path(
+      self,
+  ):
+    log_path = pathlib.Path('/logs')
+    inv_path1 = log_path / 'log/stub/local_atest/inv_1'
+    self.fs.create_dir(inv_path1)
+    host_log_path1 = inv_path1 / 'host_log_test1.txt'
+    self.fs.create_file(
+        host_log_path1,
+        contents="""
+        Running tests with filter --some-filter filter_value --atest-include-filter TestAModule:com.package.TestAClass --some-other-filter other_filter_value
+        Creating super awesome log at /logs/log/stub/local_atest/inv_1
+        """,
+    )
+
+    aei.append_test_info_to_invocation_pathnames(log_path)
+
+    self.assertTrue(os.path.exists('/logs/log/stub/local_atest/inv_1'))
+    self.assertFalse(
+        os.path.exists(
+            '/logs/log/stub/local_atest/inv_1__TestAModule_com.package.TestAClass'
+        )
+    )
+
+
 if __name__ == '__main__':
   unittest.main()
diff --git a/atest/atest_main.py b/atest/atest_main.py
index 7ebbcef6..e4cd9a41 100755
--- a/atest/atest_main.py
+++ b/atest/atest_main.py
@@ -48,7 +48,6 @@ from atest import atest_configs
 from atest import atest_execution_info
 from atest import atest_utils
 from atest import banner
-from atest import bazel_mode
 from atest import bug_detector
 from atest import cli_translator
 from atest import constants
@@ -59,11 +58,13 @@ from atest import test_runner_handler
 from atest.atest_enum import DetectType
 from atest.atest_enum import ExitCode
 from atest.coverage import coverage
+from atest.crystalball import perf_mode
 from atest.metrics import metrics
 from atest.metrics import metrics_base
 from atest.metrics import metrics_utils
 from atest.test_finders import test_finder_utils
 from atest.test_finders import test_info
+from atest.test_finders.smart_test_finder import smart_test_finder
 from atest.test_finders.test_info import TestInfo
 from atest.test_runner_invocation import TestRunnerInvocation
 from atest.tools import indexing
@@ -101,6 +102,7 @@ EXIT_CODES_BEFORE_TEST = [
 _RESULTS_DIR_PRINT_PREFIX = 'Atest results and logs directory: '
 # Log prefix for dry-run run command. May be used in integration tests.
 _DRY_RUN_COMMAND_LOG_PREFIX = 'Internal run command from dry-run: '
+_SMART_TEST_SELECTION_FLAG = '--sts'
 
 
 @dataclasses.dataclass
@@ -207,8 +209,7 @@ def _parse_args(argv: List[str]) -> argparse.Namespace:
   if CUSTOM_ARG_FLAG in argv:
     custom_args_index = argv.index(CUSTOM_ARG_FLAG)
     pruned_argv = argv[:custom_args_index]
-  args = arg_parser.create_atest_arg_parser().parse_args(pruned_argv)
-  args.custom_args = []
+  args = arg_parser.parse_args(pruned_argv)
   if custom_args_index is not None:
     for arg in argv[custom_args_index + 1 :]:
       logging.debug('Quoting regex argument %s', arg)
@@ -320,7 +321,6 @@ def get_extra_args(args) -> Dict[str, str]:
   arg_maps = {
       'all_abi': constants.ALL_ABI,
       'annotation_filter': constants.ANNOTATION_FILTER,
-      'bazel_arg': constants.BAZEL_ARG,
       'collect_tests_only': constants.COLLECT_TESTS_ONLY,
       'experimental_coverage': constants.COVERAGE,
       'custom_args': constants.CUSTOM_ARGS,
@@ -332,7 +332,6 @@ def get_extra_args(args) -> Dict[str, str]:
       'instant': constants.INSTANT,
       'iterations': constants.ITERATIONS,
       'request_upload_result': constants.REQUEST_UPLOAD_RESULT,
-      'bazel_mode_features': constants.BAZEL_MODE_FEATURES,
       'rerun_until_failure': constants.RERUN_UNTIL_FAILURE,
       'retry_any_failure': constants.RETRY_ANY_FAILURE,
       'serial': constants.SERIAL,
@@ -345,6 +344,7 @@ def get_extra_args(args) -> Dict[str, str]:
       'verbose': constants.VERBOSE,
       'use_tf_min_base_template': constants.USE_TF_MIN_BASE_TEMPLATE,
       'smart_test_selection': constants.SMART_TEST_SELECTION,
+      'class_level_report': constants.CLASS_LEVEL_REPORT,
   }
   not_match = [k for k in arg_maps if k not in vars(args)]
   if not_match:
@@ -375,8 +375,10 @@ def _validate_exec_mode(args, test_infos: list[TestInfo], host_tests=None):
   """
   all_device_modes = {x.get_supported_exec_mode() for x in test_infos}
   err_msg = None
+  device_only_test_detected = constants.DEVICE_TEST in all_device_modes
+  host_only_test_detected = constants.DEVICELESS_TEST in all_device_modes
   # In the case of '$atest <device-only> --host', exit.
-  if (host_tests or args.host) and constants.DEVICE_TEST in all_device_modes:
+  if (host_tests or args.host) and device_only_test_detected:
     device_only_tests = [
         x.test_name
         for x in test_infos
@@ -390,11 +392,12 @@ def _validate_exec_mode(args, test_infos: list[TestInfo], host_tests=None):
   # In the case of '$atest <host-only> <device-only> --host' or
   # '$atest <host-only> <device-only>', exit.
   if (
-      constants.DEVICELESS_TEST in all_device_modes
-      and constants.DEVICE_TEST in all_device_modes
+      host_only_test_detected
+      and device_only_test_detected
+      and not args.smart_test_selection
   ):
     err_msg = 'There are host-only and device-only tests in command.'
-  if host_tests is False and constants.DEVICELESS_TEST in all_device_modes:
+  if host_tests is False and host_only_test_detected:
     err_msg = 'There are host-only tests in command.'
   if err_msg:
     atest_utils.print_and_log_error(err_msg)
@@ -406,9 +409,9 @@ def _validate_exec_mode(args, test_infos: list[TestInfo], host_tests=None):
     _validate_adb_devices(args, test_infos)
   # In the case of '$atest <host-only>', we add --host to run on host-side.
   # The option should only be overridden if `host_tests` is not set.
-  if not args.host and host_tests is None:
+  if not args.host and host_tests is None and not device_only_test_detected:
     logging.debug('Appending "--host" for a deviceless test...')
-    args.host = bool(constants.DEVICELESS_TEST in all_device_modes)
+    args.host = host_only_test_detected
 
 
 def _validate_adb_devices(args, test_infos):
@@ -425,12 +428,6 @@ def _validate_adb_devices(args, test_infos):
     return
   if args.no_checking_device:
     return
-  # No need to check local device availability if the device test is running
-  # remotely.
-  if args.bazel_mode_features and (
-      bazel_mode.Features.EXPERIMENTAL_REMOTE_AVD in args.bazel_mode_features
-  ):
-    return
   all_device_modes = {x.get_supported_exec_mode() for x in test_infos}
   device_tests = [
       x.test_name
@@ -695,6 +692,11 @@ class _AtestMain:
     else:
       metrics.LocalDetectEvent(detect_type=DetectType.ATEST_CONFIG, result=0)
 
+    if _SMART_TEST_SELECTION_FLAG in final_args:
+      if CUSTOM_ARG_FLAG not in final_args:
+        final_args.append(CUSTOM_ARG_FLAG)
+      final_args.extend(smart_test_finder.SMART_TEST_SELECTION_CUSTOM_ARGS)
+
     self._args = _parse_args(final_args)
     atest_configs.GLOBAL_ARGS = self._args
     _configure_logging(self._args.verbose, self._results_dir)
@@ -726,7 +728,14 @@ class _AtestMain:
           self._args,
           metrics.get_run_id(),
       )
+      original_android_serial = os.environ.get(constants.ANDROID_SERIAL)
       exit_code = self._run_all_steps()
+      if self._args.smart_test_selection:
+        # Recover the original ANDROID_SERIAL
+        if original_android_serial:
+          os.environ[constants.ANDROID_SERIAL] = original_android_serial
+        elif constants.ANDROID_SERIAL in os.environ:
+          del os.environ[constants.ANDROID_SERIAL]
       detector = bug_detector.BugDetector(final_args, exit_code)
       if exit_code not in EXIT_CODES_BEFORE_TEST:
         metrics.LocalDetectEvent(
@@ -779,6 +788,21 @@ class _AtestMain:
     if not _has_valid_test_mapping_args(self._args):
       return ExitCode.INVALID_TM_ARGS
 
+    if self._args.smart_test_selection:
+      if self._args.tests:
+        atest_utils.colorful_print(
+            'Smart test selection is specified, please remove the specified'
+            f' test references: {self._args.tests}',
+            constants.RED,
+        )
+        return ExitCode.INPUT_TEST_REFERENCE_ERROR
+      if subprocess.run(['git', 'branch'], capture_output=True).returncode != 0:
+        atest_utils.colorful_print(
+            'Smart test selection must work under a repo',
+            constants.RED,
+        )
+        return ExitCode.OUTSIDE_REPO
+
     # Checks whether ANDROID_SERIAL environment variable is set to an empty string.
     if 'ANDROID_SERIAL' in os.environ and not os.environ['ANDROID_SERIAL']:
       atest_utils.print_and_log_warning(
@@ -957,9 +981,7 @@ class _AtestMain:
     translator = cli_translator.CLITranslator(
         mod_info=self._mod_info,
         print_cache_msg=not self._args.clear_cache,
-        bazel_mode_enabled=self._args.bazel_mode,
         host=self._args.host,
-        bazel_mode_features=self._args.bazel_mode_features,
         indexing_thread=indexing_thread,
     )
 
@@ -996,11 +1018,8 @@ class _AtestMain:
   def _inject_default_arguments_based_on_test_infos(
       test_infos: list[test_info.TestInfo], args: argparse.Namespace
   ) -> None:
-    if any(
-        'performance-tests' in info.compatibility_suites for info in test_infos
-    ):
-      if not args.disable_upload_result:
-        args.request_upload_result = True
+    if perf_mode.is_perf_test(test_infos=test_infos):
+      perf_mode.set_default_argument_values(args)
 
   def _handle_list_modules(self) -> int:
     """Print the testable modules for a given suite.
@@ -1216,17 +1235,6 @@ class _AtestMain:
         hostname=platform.node(),
     )
 
-  def _disable_bazel_mode_if_unsupported(self) -> None:
-    if (
-        atest_utils.is_test_mapping(self._args)
-        or self._args.experimental_coverage
-    ):
-      logging.debug('Running test mapping or coverage, disabling bazel mode.')
-      atest_utils.colorful_print(
-          'Not running using bazel-mode.', constants.YELLOW
-      )
-      self._args.bazel_mode = False
-
   def _run_all_steps(self) -> int:
     """Executes the atest script.
 
@@ -1250,8 +1258,6 @@ class _AtestMain:
     if self._args.list_modules:
       return self._handle_list_modules()
 
-    self._disable_bazel_mode_if_unsupported()
-
     if self._args.dry_run:
       return self._handle_dry_run()
 
@@ -1576,16 +1582,47 @@ class _TestModuleExecutionPlan(_TestExecutionPlan):
 
   def execute(self) -> ExitCode:
 
-    reporter = result_reporter.ResultReporter(
-        collect_only=self.extra_args.get(constants.COLLECT_TESTS_ONLY),
-        wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
-        args=self._args,
-        test_infos=self._test_infos,
-    )
+    if self._args.smart_test_selection:
+      reporter = result_reporter.ResultReporter(
+          collect_only=self.extra_args.get(constants.COLLECT_TESTS_ONLY),
+          wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
+          args=self._args,
+          test_infos=self._test_infos,
+          class_level_report=True,
+          runner_errors_as_warnings=True,
+      )
+    else:
+      reporter = result_reporter.ResultReporter(
+          collect_only=self.extra_args.get(constants.COLLECT_TESTS_ONLY),
+          wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
+          args=self._args,
+          test_infos=self._test_infos,
+          class_level_report=self._args.class_level_report,
+      )
     reporter.print_starting_text()
 
     exit_code = ExitCode.SUCCESS
-    for invocation in self._test_runner_invocations:
+    execution_start_time = time.time()
+    for i, invocation in enumerate(self._test_runner_invocations):
+      if self._args.smart_test_selection:
+        if (
+            time.time() - execution_start_time
+            > constants.SMART_TEST_EXECUTION_TIME_LIMIT_IN_MINUTES * 60
+        ):
+          atest_utils.print_and_log_warning(
+              'Smart test run out of time limit (%d minutes). Only %d out of %d'
+              ' invocation(s) of selected tests were executed',
+              constants.SMART_TEST_EXECUTION_TIME_LIMIT_IN_MINUTES,
+              i,
+              len(self._test_runner_invocations),
+          )
+          break
+      print(
+          atest_utils.mark_cyan(
+              f'\nRunning Invocation {i + 1} (out of'
+              f' {len(self._test_runner_invocations)} invocation(s))...'
+          )
+      )
       exit_code |= invocation.run_all_tests(reporter)
 
     atest_execution_info.AtestExecutionInfo.result_reporters.append(reporter)
diff --git a/atest/atest_main_unittest.py b/atest/atest_main_unittest.py
index 8472a622..870e25fe 100755
--- a/atest/atest_main_unittest.py
+++ b/atest/atest_main_unittest.py
@@ -22,6 +22,7 @@ import datetime
 from importlib import reload
 from io import StringIO
 import os
+import subprocess
 import sys
 import tempfile
 import unittest
@@ -32,6 +33,7 @@ from atest import atest_utils
 from atest import constants
 from atest import module_info
 from atest.atest_enum import DetectType
+from atest.atest_enum import ExitCode
 from atest.metrics import metrics
 from atest.metrics import metrics_utils
 from atest.test_finders import test_info
@@ -187,6 +189,36 @@ class AtestUnittests(unittest.TestCase):
     atest_main._validate_exec_mode(parsed_args, test_infos)
     self.assertFalse(parsed_args.host)
 
+  @mock.patch.object(atest_utils, 'get_adb_devices')
+  @mock.patch.object(metrics_utils, 'send_exit_event')
+  def test_validate_exec_mode_no_system_exit_with_smart_test_selection(
+      self, _send_exit, _devs
+  ):
+    """Test _validate_exec_mode."""
+    _devs.return_value = ['127.0.0.1:34556']
+    parsed_args = atest_main._parse_args(['--sts'])
+    host_test_info = test_info.TestInfo(
+        'mod',
+        '',
+        set(),
+        data={},
+        module_class=['NATIVE_TESTS'],
+        install_locations=set(['host']),
+    )
+    device_test_info = test_info.TestInfo(
+        'mod',
+        '',
+        set(),
+        data={},
+        module_class=['NATIVE_TESTS'],
+        install_locations=set(['device']),
+    )
+    test_infos = [device_test_info, host_test_info]
+
+    atest_main._validate_exec_mode(parsed_args, test_infos)
+
+    self.assertFalse(parsed_args.host)
+
   def test_make_test_run_dir(self):
     """Test make_test_run_dir."""
     tmp_dir = tempfile.mkdtemp()
@@ -287,6 +319,44 @@ class AtestMainUnitTests(unittest.TestCase):
 
     self.assertIsNone(pseudo_atest_main._run_build_step())
 
+  @mock.patch.object(
+      atest_main, '_missing_environment_variables', return_value=False
+  )
+  @mock.patch('os.getenv', return_value='/tmp/my_android_build_root')
+  @mock.patch('os.getcwd', return_value='/tmp/my_android_build_root/tools')
+  def test_check_envs_and_args_smart_test_selection_and_test_refs_specified(
+      self, _, __, ___
+  ):
+    pseudo_atest_main = atest_main._AtestMain(argv=[])
+    pseudo_atest_main._args = atest_main._parse_args(
+        argv=['--sts', 'SomeTestModule']
+    )
+
+    self.assertEqual(
+        pseudo_atest_main._check_envs_and_args(),
+        ExitCode.INPUT_TEST_REFERENCE_ERROR,
+    )
+
+  @mock.patch(
+      'subprocess.run',
+      return_value=subprocess.CompletedProcess(args=[], returncode=1),
+  )
+  @mock.patch.object(
+      atest_main, '_missing_environment_variables', return_value=False
+  )
+  @mock.patch('os.getenv', return_value='/tmp/my_android_build_root')
+  @mock.patch('os.getcwd', return_value='/tmp/my_android_build_root/tools')
+  def test_check_envs_and_args_smart_test_selection_not_under_a_repo(
+      self, _, __, ___, ____
+  ):
+    pseudo_atest_main = atest_main._AtestMain(argv=[])
+    pseudo_atest_main._args = atest_main._parse_args(argv=['--sts'])
+
+    self.assertEqual(
+        pseudo_atest_main._check_envs_and_args(),
+        ExitCode.OUTSIDE_REPO,
+    )
+
 
 # pylint: disable=missing-function-docstring
 class AtestUnittestFixture(fake_filesystem_unittest.TestCase):
diff --git a/atest/atest_utils.py b/atest/atest_utils.py
index d50e5739..59bd6b72 100644
--- a/atest/atest_utils.py
+++ b/atest/atest_utils.py
@@ -57,7 +57,7 @@ from atest.metrics import metrics
 from atest.metrics import metrics_utils
 from atest.tf_proto import test_record_pb2
 
-DEFAULT_OUTPUT_ROLLING_LINES = 6
+DEFAULT_OUTPUT_ROLLING_LINES = 8
 _BASH_CLEAR_PREVIOUS_LINE_CODE = '\033[F\033[K'
 _BASH_RESET_CODE = '\033[0m'
 DIST_OUT_DIR = Path(
@@ -83,15 +83,22 @@ BUILD_TOP_HASH = hashlib.md5(
 _DEFAULT_TERMINAL_WIDTH = 80
 _DEFAULT_TERMINAL_HEIGHT = 25
 _BUILD_CMD = 'build/soong/soong_ui.bash'
+_GET_REMOTE_BRANCH_WITH_GOOG_HEAD_CMD = (
+    "cd {}; git branch -r | grep '\\->' | awk '{{print $1}}'"
+)
 _FIND_MODIFIED_FILES_CMDS = (
     'cd {};'
     'local_branch=$(git rev-parse --abbrev-ref HEAD);'
-    "remote_branch=$(git branch -r | grep '\\->' | awk '{{print $1}}');"
+    'remote_branch={}'
     # Get the number of commits from local branch to remote branch.
     'ahead=$(git rev-list --left-right --count $local_branch...$remote_branch '
     "| awk '{{print $1}}');"
     # Get the list of modified files from HEAD to previous $ahead generation.
-    'git diff HEAD~$ahead --name-only'
+    'git diff HEAD~$ahead {}'
+)
+_FIND_UNTRACKED_FILES_CMD = (
+    'for file in $(git ls-files --others --exclude-standard); do wc -l "$file";'
+    ' done'
 )
 _ANDROID_BUILD_EXT = ('.bp', '.mk')
 
@@ -114,6 +121,18 @@ CACHE_VERSION = 1
 _original_sys_stdout = sys.stdout
 
 
+@dataclass(frozen=True)
+class ChangedFileDetails:
+  """Represents the details of a changed file.
+
+  The details include the filename, the number of inserted and deleted lines.
+  """
+
+  filename: str
+  number_of_lines_inserted: int
+  number_of_lines_deleted: int
+
+
 @dataclass
 class BuildEnvProfiler:
   """Represents the condition before and after trigging build."""
@@ -328,6 +347,8 @@ def stream_io_output(
   original_stdout = sys.stdout
   original_stderr = sys.stderr
 
+  original_stdout.write('\n')
+
   lock = threading.Lock()
 
   class SafeStdout:
@@ -591,7 +612,7 @@ def is_test_mapping(args):
   which means the test value is a test group name in TEST_MAPPING file, e.g.,
   `:postsubmit`.
 
-  If --host-unit-test-only or --smart-testing-local was applied, it doesn't
+  If --host-unit-test-only or --smart-test-selection was applied, it doesn't
   intend to be a test_mapping test.
   If any test mapping options is specified, the atest command must also be
   set to run tests in test mapping files.
@@ -603,7 +624,7 @@ def is_test_mapping(args):
       True if the args indicates atest shall run tests in test mapping. False
       otherwise.
   """
-  if args.host_unit_test_only:
+  if any((args.host_unit_test_only, args.smart_test_selection)):
     return False
   if any((args.test_mapping, args.include_subdirs, not args.tests)):
     return True
@@ -886,10 +907,9 @@ def get_cache_root():
   # do this because this directory is periodically cleaned and don't have to
   # worry about the files growing without bound. The files are also much
   # smaller than typical build output and less of an issue. Use build out to
-  # save caches which is next to atest_bazel_workspace which is easy for user
-  # to manually clean up if need. Use product out folder's base name as part
-  # of directory because of there may be different module-info in the same
-  # branch but different lunch target.
+  # save caches which is easy for user to manually clean up if need. Use product
+  # out folder's base name as part of directory because of there may be
+  # different module-info in the same branch but different lunch target.
   return os.path.join(
       get_build_out_dir(),
       'atest_cache',
@@ -1003,6 +1023,24 @@ def clean_test_info_caches(tests, cache_root=None):
         )
 
 
+def _get_remote_branch(git_path: str) -> str:
+  """Gets the remote branch."""
+  remote_branch_lines = (
+      subprocess.check_output(
+          _GET_REMOTE_BRANCH_WITH_GOOG_HEAD_CMD.format(git_path), shell=True
+      )
+      .decode()
+      .splitlines()
+  )
+  if not remote_branch_lines:
+    # TODO(b/413705656): This is hardcoded for `git_main` only. Try to find a
+    # programmatic way if remote HEAD information is not in `git branch -r`.
+    return 'goog/main'
+  return remote_branch_lines[0]
+
+
+# TODO(b/407049787): Remove this function once `get_modified_files_with_details`
+# is proved to be robust.
 def get_modified_files(root_dir):
   """Get the git modified files.
 
@@ -1041,7 +1079,10 @@ def get_modified_files(root_dir):
       for change in modified_wo_commit:
         modified_files.add(os.path.normpath('{}/{}'.format(git_path, change)))
       # Find modified files that are committed but not yet merged.
-      find_modified_files = _FIND_MODIFIED_FILES_CMDS.format(git_path)
+      remote_branch = _get_remote_branch(git_path)
+      find_modified_files = _FIND_MODIFIED_FILES_CMDS.format(
+          git_path, remote_branch, '--name-only'
+      )
       commit_modified_files = (
           subprocess.check_output(find_modified_files, shell=True)
           .decode()
@@ -1054,6 +1095,68 @@ def get_modified_files(root_dir):
   return modified_files
 
 
+def get_modified_files_with_details() -> set[ChangedFileDetails]:
+  """Get the git modified files with change details of the current folder.
+
+  The modified files include all committed changes, uncommitted but tracked
+  changes and untracked changes.
+
+  Returns:
+      A set of modified files altered with changed details since last commit.
+  """
+  modified_files = set()
+  try:
+    remote_branch = _get_remote_branch('.')
+    find_modified_files = _FIND_MODIFIED_FILES_CMDS.format(
+        '.', remote_branch, '--numstat'
+    )
+    commit_modified_files = (
+        subprocess.check_output(find_modified_files, shell=True)
+        .decode()
+        .splitlines()
+    )
+    logging.debug('commit_modified_files: %s', commit_modified_files)
+    for line in commit_modified_files:
+      splitline = line.split()
+      modified_files.add(
+          ChangedFileDetails(
+              filename=splitline[2],
+              number_of_lines_inserted=_get_number_lines_changed(splitline[0]),
+              number_of_lines_deleted=_get_number_lines_changed(splitline[1]),
+          )
+      )
+
+    untracked_modified_files = (
+        subprocess.check_output(_FIND_UNTRACKED_FILES_CMD, shell=True)
+        .decode()
+        .splitlines()
+    )
+    for line in untracked_modified_files:
+      logging.debug('untracked_modified_files: %s', untracked_modified_files)
+      splitline = line.split()
+      modified_files.add(
+          ChangedFileDetails(
+              filename=splitline[1],
+              number_of_lines_inserted=_get_number_lines_changed(splitline[0]),
+              number_of_lines_deleted=0,
+          )
+      )
+  except (OSError, subprocess.CalledProcessError) as err:
+    logging.debug('Exception raised: %s', err)
+  return modified_files
+
+
+def _get_number_lines_changed(file_change_info: str) -> int:
+  number_of_lines_changed = 0
+
+  try:
+    number_of_lines_changed = int(file_change_info)
+  except ValueError:
+    logging.debug('failed to get the num of lines changed.')
+
+  return number_of_lines_changed
+
+
 def delimiter(char, length=_DEFAULT_TERMINAL_WIDTH, prenl=0, postnl=0):
   """A handy delimiter printer.
 
@@ -1937,7 +2040,7 @@ def get_bp_content(filename: Path, module_type: str) -> Dict:
   build_file = Path(filename)
   if not any((build_file.suffix == '.bp', build_file.is_file())):
     return {}
-  start_from = re.compile(f'^{module_type}\s*\{{')
+  start_from = re.compile(rf'^{module_type}\s*\{{')
   end_with = re.compile(r'^\}$')
   context_re = re.compile(
       r'\s*(?P<key>(name|manifest|instrumentation_for))\s*:'
diff --git a/atest/atest_utils_unittest.py b/atest/atest_utils_unittest.py
index a3eac855..258fb672 100755
--- a/atest/atest_utils_unittest.py
+++ b/atest/atest_utils_unittest.py
@@ -352,16 +352,27 @@ class AtestUtilsUnittests(unittest.TestCase):
     want_list = []
     self.assertEqual(want_list, atest_utils._capture_fail_section(test_list))
 
-  def test_is_test_mapping_none_test_mapping_args(self):
+  def test_is_test_mapping_host_unit_test_only_specified(self):
     """Test method is_test_mapping."""
-    non_tm_args = ['--host-unit-test-only']
+    host_unit_test_arg = '--host-unit-test-only'
+    args = arg_parser.create_atest_arg_parser().parse_args([host_unit_test_arg])
 
-    for argument in non_tm_args:
-      args = arg_parser.create_atest_arg_parser().parse_args([argument])
-      self.assertFalse(
-          atest_utils.is_test_mapping(args),
-          'Option %s indicates NOT a test_mapping!' % argument,
-      )
+    self.assertFalse(
+        atest_utils.is_test_mapping(args),
+        'Option %s indicates NOT a test_mapping!' % host_unit_test_arg,
+    )
+
+  def test_is_test_mapping_smart_test_selection_specified(self):
+    """Test method is_test_mapping."""
+    smart_test_selection_arg = '--sts'
+    args = arg_parser.create_atest_arg_parser().parse_args(
+        [smart_test_selection_arg]
+    )
+
+    self.assertFalse(
+        atest_utils.is_test_mapping(args),
+        'Option %s indicates NOT a test_mapping!' % smart_test_selection_arg,
+    )
 
   def test_is_test_mapping_test_mapping_args(self):
     """Test method is_test_mapping."""
@@ -598,20 +609,172 @@ class AtestUtilsUnittests(unittest.TestCase):
     """Test method get_modified_files"""
     mock_co.side_effect = [
         x.encode('utf-8')
-        for x in ['/a/b/', '\n', 'test_fp1.java\nc/test_fp2.java']
+        # The four return values correspond to:
+        # 1. Get Git paths
+        # 2. Get uncommitted changes
+        # 3. Get remote branch
+        # 4. Get committed changes.
+        for x in ['/a/b/', '\n', 'm/main', 'test_fp1.java\nc/test_fp2.java']
     ]
     self.assertEqual(
         {'/a/b/test_fp1.java', '/a/b/c/test_fp2.java'},
         atest_utils.get_modified_files(''),
     )
     mock_co.side_effect = [
-        x.encode('utf-8') for x in ['/a/b/', 'test_fp4', '/test_fp3.java']
+        x.encode('utf-8')
+        # The four return values correspond to:
+        # 1. Get Git paths
+        # 2. Get uncommitted changes
+        # 3. Get remote branch
+        # 4. Get committed changes.
+        for x in ['/a/b/', 'test_fp4', 'm/main', '/test_fp3.java']
     ]
     self.assertEqual(
         {'/a/b/test_fp4', '/a/b/test_fp3.java'},
         atest_utils.get_modified_files(''),
     )
 
+  @mock.patch(
+      'subprocess.check_output',
+      # The three return values correspond to:
+      # 1. Get remote branch, but failed (assuming goog/HEAD -> goog/main
+      # format), so we default to use `goog/main`.
+      # 2. Get committed changes.
+      # 3. Get uncommitted changes
+      side_effect=[
+          b'',
+          b'11 22 tracked_fp1.java\n33 44 c/tracked_fp2.java',
+          b'55 untracked_fp3.java\n66 a/b/untracked_fp4.py',
+      ],
+  )
+  def test_get_modified_files_with_details(self, _):
+    tracked_changed_file_details1 = atest_utils.ChangedFileDetails(
+        filename='tracked_fp1.java',
+        number_of_lines_inserted=11,
+        number_of_lines_deleted=22,
+    )
+    tracked_changed_file_details2 = atest_utils.ChangedFileDetails(
+        filename='c/tracked_fp2.java',
+        number_of_lines_inserted=33,
+        number_of_lines_deleted=44,
+    )
+    untracked_changed_file_details1 = atest_utils.ChangedFileDetails(
+        filename='untracked_fp3.java',
+        number_of_lines_inserted=55,
+        number_of_lines_deleted=0,
+    )
+    untracked_changed_file_details2 = atest_utils.ChangedFileDetails(
+        filename='a/b/untracked_fp4.py',
+        number_of_lines_inserted=66,
+        number_of_lines_deleted=0,
+    )
+
+    modified_files_with_details = atest_utils.get_modified_files_with_details()
+
+    self.assertSetEqual(
+        modified_files_with_details,
+        {
+            tracked_changed_file_details1,
+            tracked_changed_file_details2,
+            untracked_changed_file_details1,
+            untracked_changed_file_details2,
+        },
+    )
+
+  @mock.patch(
+      'subprocess.check_output',
+      # The three return values correspond to:
+      # 1. Get remote branch, assuming goog/HEAD -> goog/main format, and
+      #    succeeded
+      # 2. Get committed changes.
+      # 3. Get uncommitted changes
+      side_effect=[
+          b'goog/main',
+          (
+              b'11 22 tracked_fp1.java\n33 44 c/tracked_fp2.java\n- -'
+              b' tracked_fp3.jar'
+          ),
+          b'',
+      ],
+  )
+  def test_get_modified_files_with_details_only_tracked_changes(self, _):
+    tracked_changed_file_details1 = atest_utils.ChangedFileDetails(
+        filename='tracked_fp1.java',
+        number_of_lines_inserted=11,
+        number_of_lines_deleted=22,
+    )
+    tracked_changed_file_details2 = atest_utils.ChangedFileDetails(
+        filename='c/tracked_fp2.java',
+        number_of_lines_inserted=33,
+        number_of_lines_deleted=44,
+    )
+    tracked_changed_file_details3 = atest_utils.ChangedFileDetails(
+        filename='tracked_fp3.jar',
+        number_of_lines_inserted=0,
+        number_of_lines_deleted=0,
+    )
+
+    modified_files_with_details = atest_utils.get_modified_files_with_details()
+
+    self.assertSetEqual(
+        modified_files_with_details,
+        {
+            tracked_changed_file_details1,
+            tracked_changed_file_details2,
+            tracked_changed_file_details3,
+        },
+    )
+
+  @mock.patch(
+      'subprocess.check_output',
+      # The three return values correspond to:
+      # 1. Get remote branch, but failed (assuming goog/HEAD -> goog/main
+      # format), so we default to use `goog/main`.
+      # 2. Get committed changes.
+      # 3. Get uncommitted changes
+      side_effect=[
+          b'',
+          b'',
+          (
+              b'55 untracked_fp1.java\n66 a/b/untracked_fp2.py\n-'
+              b' untracked_fp3.jar'
+          ),
+      ],
+  )
+  def test_get_modified_files_with_details_only_untracked_changes(self, _):
+    untracked_changed_file_details1 = atest_utils.ChangedFileDetails(
+        filename='untracked_fp1.java',
+        number_of_lines_inserted=55,
+        number_of_lines_deleted=0,
+    )
+    untracked_changed_file_details2 = atest_utils.ChangedFileDetails(
+        filename='a/b/untracked_fp2.py',
+        number_of_lines_inserted=66,
+        number_of_lines_deleted=0,
+    )
+    untracked_changed_file_details3 = atest_utils.ChangedFileDetails(
+        filename='untracked_fp3.jar',
+        number_of_lines_inserted=0,
+        number_of_lines_deleted=0,
+    )
+
+    modified_files_with_details = atest_utils.get_modified_files_with_details()
+
+    self.assertSetEqual(
+        modified_files_with_details,
+        {
+            untracked_changed_file_details1,
+            untracked_changed_file_details2,
+            untracked_changed_file_details3,
+        },
+    )
+
+  @mock.patch('subprocess.check_output', return_value=b'')
+  def test_get_modified_files_with_details_empty_changes(self, _):
+    modified_files_with_details = atest_utils.get_modified_files_with_details()
+
+    self.assertSetEqual(modified_files_with_details, set())
+
   def test_delimiter(self):
     """Test method delimiter"""
     self.assertEqual('\n===\n\n', atest_utils.delimiter('=', 3, 1, 2))
diff --git a/atest/bazel/OWNERS b/atest/bazel/OWNERS
deleted file mode 100644
index c179c755..00000000
--- a/atest/bazel/OWNERS
+++ /dev/null
@@ -1,5 +0,0 @@
-include /OWNERS_ADTE_TEAM
-
-weisu@google.com
-jingwen@google.com
-yangbill@google.com
diff --git a/atest/bazel/atest_bazel_mode.md b/atest/bazel/atest_bazel_mode.md
deleted file mode 100644
index 9ba84a15..00000000
--- a/atest/bazel/atest_bazel_mode.md
+++ /dev/null
@@ -1,127 +0,0 @@
-# Atest Bazel Mode
-Atest is a command line tool that allows users to run Android tests locally
-without requiring knowledge of Trade Federation test harness command line
-options. It wraps the logic and calls Trade Federation under the hood. This is
-what we call Atest Standard Mode in this document.
-
-Atest Bazel Mode creates a synthetic Bazel workspace and executes tests using
-Bazel instead of calling Trade Federation directly. This mode opens up Bazel
-features such as parallelized execution, caching, and remote execution.
-Currently it is able to run all host unit tests only. Capability to run tests
-that requires a device is still work in progress.
-
-##### Table of Contents
-1. [Basic Usage](#basic-usage)
-2. [Advanced Usage](#advanced-usage)
-3. [How It Works](#how-it-works)
-4. [Difference from Atest Standard Mode](#difference-from-atest-standard-mode)
-5. [Frequently Asked Questions](#faq)
-
-## <a name="basic-usage">Basic Usage</a>
-
-Atest Bazel Mode commands take the following form:
-
->```$ atest --bazel-mode --host HelloWorldHostTest```
-<p>Note: "--host" is needed to run the test completely on the host without a device.
-
-To run multiple tests, separate test references with spaces. For example:
-
->```$ atest --bazel-mode --host HelloWorldHostTest fastdeploy_test aapt2_tests```
-
-To run all host unit tests from the current directory:
-
->```$ atest --bazel-mode --host --host-unit-test-only```
-
-## <a name="advanced-usage">Advanced Usage</a>
-
-Use `--bazel-arg` to forward arguments to Bazel. For example, the following
-command increases the test timeout:
-
->```$ atest --bazel-mode --host CtsNNAPITestCases --bazel-arg=--test_timeout=600```
-
-## <a name="how-it-works">How It Works</a>
-Bazel needs a Bazel workspace to execute tests.
-In Atest Bazel Mode, we construct a synthetic workspace using module-info.json.
-The workspace contains required directory structure, symlinks and Bazel BUILD
-files to correctly invoke ```bazel test``` command. The Bazel BUILD files are
-written with customized Bazel rules. An example Build file is as follows:
-
-```
-package(default_visibility = ["//visibility:public"])
-
-load("//bazel/rules:soong_prebuilt.bzl", "soong_prebuilt")
-load("//bazel/rules:tradefed_test.bzl", "tradefed_deviceless_test")
-
-tradefed_deviceless_test(
-    name = "HelloWorldHostTest_host",
-    test = "//platform_testing/tests/example/jarhosttest:HelloWorldHostTest",
-)
-
-soong_prebuilt(
-    name = "HelloWorldHostTest",
-    module_name = "HelloWorldHostTest",
-    files = select({
-        "//bazel/rules:host": glob(["HelloWorldHostTest/host/**/*"]),
-    }),
-)
-```
-
-Atest bazel Mode will create the Bazel workspace on first run, or upon detecting
-a change to module-info.json.
-
-It will then use Bazel query to find out dependencies for the build step.
-
-In the build step, it will use Soong to build those dependencies returned by
-Bazel query.
-
-At last, ```bazel test``` command is executed for the test targets.
-
-## <a name="difference-from-atest-standard-mode">Difference from Atest Standard Mode</a>
-
-Here is a list of major differences from the Atest Standard Mode:
-* In Atest Standard Mode, user can view detailed test case result in the
-terminal, while in Bazel Mode only test target result is showing. For test case
-detail, user would need to look at test logs. The reason Bazel Mode only shows
-the summary result is that atest invokes Bazel command with default parameters.
-Bazel command option "--test_output" is defaulted to be "summary". User has the
-option to view "all" output when we later implement command option passing from
-Atest to Bazel.
-More details about Bazel [--test_output flag](https://docs.bazel.build/versions/main/command-line-reference.html#flag--test_output)
-* In Atest Standard Mode, user can identify tests by module name, class name,
-file path or package name, while in Bazel Mode, we only support module name
-currently. Supporting flexible test finder is work in progress.
-* In Atest Standard Mode, test logs are saved under ```/tmp/atest_result```, while in
-Bazel Mode, test logs are saved under ```$ANDROID_BUILD_TOP/out/atest_bazel_workspace/bazel-testlogs```
-
-
-## <a name="faq">Frequently Asked Questions</a>
-
-### 1. Why my test failed with "error: Read-only file system" in the test log?
-
-Bazel execution is done within a sandbox. The purpose is to create a hermetic
-environment for the test. This could sometimes cause issues if the test writer
-is not careful when reading and writting test data.
-
-For reading, there is not much restriction as the new Bazel sandbox design
-allows all read access to "/" since it mounted "/" as readable in the sandbox.
-
-For writting, Bazel only allows write access to the target's private execroot
-directory and a private $TMPDIR.
-
-More details about [Bazel sandbox.](https://bazel.build/designs/2016/06/02/sandboxing.html)
-
-
-### 2. Why I got "Too many levels of symbolic links" while reading files in Bazel Mode?
-
-Some tests try to read the test data using relative path. This some times does
-not work in Bazel Mode.
-
-In Bazel Mode, Bazel creates symbolic links for all the test artifacts in the
-Bazel private execution root directory in the sandbox. The symbolic links are
-eventially resolved to the physical file in Android source tree.
-Reading the symlink as file without following symlinks may fail with the above
-error message.
-
-One example is C++ android::base::ReadFileToString function. The solution is to
-enable following symbolic link when calling the function.
-More details can be find [here.](https://cs.android.com/android/platform/superproject/+/master:external/googletest/googletest/include/gtest/gtest.h;drc=master;l=2353)
diff --git a/atest/bazel/reporter/Android.bp b/atest/bazel/reporter/Android.bp
deleted file mode 100644
index 74f8cc76..00000000
--- a/atest/bazel/reporter/Android.bp
+++ /dev/null
@@ -1,46 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-java_library_host {
-    name: "bazel-result-reporter",
-    srcs: [
-        "src/com/android/tradefed/result/BazelExitCodeResultReporter.java",
-        "src/com/android/tradefed/result/BazelXmlResultReporter.java"
-    ],
-    // b/267831518: Pin tradefed and dependencies to Java 11.
-    java_version: "11",
-    libs: [
-        "tradefed",
-    ],
-}
-
-java_test_host {
-    name: "bazel-result-reporter-tests",
-    srcs: [
-        "javatests/com/android/tradefed/result/BazelExitCodeResultReporterTest.java",
-        "javatests/com/android/tradefed/result/BazelXmlResultReporterTest.java"
-    ],
-    static_libs: [
-        "bazel-result-reporter",
-        "jimfs",
-        "tradefed",
-    ],
-    test_options: {
-        unit_test: true,
-    },
-}
diff --git a/atest/bazel/reporter/BUILD.bazel b/atest/bazel/reporter/BUILD.bazel
deleted file mode 100644
index e34f2699..00000000
--- a/atest/bazel/reporter/BUILD.bazel
+++ /dev/null
@@ -1,18 +0,0 @@
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "bazel-result-reporter",
-    srcs = glob(["src/**/*.java"]),
-    target_compatible_with = ["//build/bazel_common_rules/platforms/os:linux"],
-    deps = [
-        ":tradefed",
-    ],
-)
-
-java_import(
-    name = "tradefed",
-    jars = [
-        "//tools/tradefederation/prebuilts/filegroups/tradefed:tradefed-prebuilt",
-    ],
-    target_compatible_with = ["//build/bazel_common_rules/platforms/os:linux"],
-)
diff --git a/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelExitCodeResultReporterTest.java b/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelExitCodeResultReporterTest.java
deleted file mode 100644
index 5537aeb0..00000000
--- a/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelExitCodeResultReporterTest.java
+++ /dev/null
@@ -1,162 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.tradefed.result;
-
-import static org.junit.Assert.assertEquals;
-
-import com.android.tradefed.build.BuildInfo;
-import com.android.tradefed.config.OptionSetter;
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.invoker.InvocationContext;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-
-import com.google.common.jimfs.Jimfs;
-
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-
-import java.io.IOException;
-import java.nio.file.FileSystem;
-import java.nio.file.Files;
-import java.nio.file.Path;
-import java.util.HashMap;
-
-@RunWith(JUnit4.class)
-public final class BazelExitCodeResultReporterTest {
-
-    private static final IInvocationContext DEFAULT_CONTEXT = createContext();
-    private static final TestDescription TEST_ID = new TestDescription("FooTest", "testFoo");
-    private static final String STACK_TRACE = "this is a trace";
-
-    private final FileSystem mFileSystem = Jimfs.newFileSystem();
-    private final HashMap<String, Metric> mEmptyMap = new HashMap<>();
-
-    @Test
-    public void writeNoTestsFoundExitCode_noTestsRun() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.invocationEnded(1);
-
-        assertFileContentsEquals("0", exitCodeFile);
-    }
-
-    @Test
-    public void writeRunFailureExitCode_runFailed() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID);
-        reporter.testRunFailed("Error Message");
-        reporter.invocationEnded(1);
-
-        assertFileContentsEquals("6", exitCodeFile);
-    }
-
-    @Test
-    public void writeSuccessExitCode_allTestsPassed() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID);
-        reporter.testEnded(TEST_ID, mEmptyMap);
-        reporter.testRunEnded(3, mEmptyMap);
-        reporter.invocationEnded(1);
-
-        assertFileContentsEquals("0", exitCodeFile);
-    }
-
-    @Test
-    public void writeTestsFailedExitCode_oneTestFailed() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID);
-        reporter.testFailed(TEST_ID, "this is a trace");
-        reporter.testEnded(TEST_ID, mEmptyMap);
-        reporter.testRunEnded(3, mEmptyMap);
-        reporter.invocationEnded(1);
-
-        assertFileContentsEquals("3", exitCodeFile);
-    }
-
-    @Test
-    public void writeRunFailureExitCode_bothRunFailedAndTestFailed() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 2);
-        // First test failed.
-        reporter.testStarted(TEST_ID);
-        reporter.testFailed(TEST_ID, STACK_TRACE);
-        reporter.testEnded(TEST_ID, mEmptyMap);
-        // Second test has run failure.
-        reporter.testStarted(TEST_ID);
-        reporter.testRunFailed("Error Message");
-        reporter.testEnded(TEST_ID, mEmptyMap);
-        reporter.testRunEnded(3, mEmptyMap);
-        reporter.invocationEnded(1);
-
-        // Test Exit Code is RunFailure even when test failure happens before run failure.
-        assertFileContentsEquals("6", exitCodeFile);
-    }
-
-    @Test
-    public void writeRunFailureExitCode_noTestsAndRunFailed() throws Exception {
-        Path exitCodeFile = createExitCodeFilePath();
-        BazelExitCodeResultReporter reporter = createReporter(exitCodeFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 0);
-        reporter.testRunFailed("Error Message");
-        reporter.invocationEnded(1);
-
-        assertFileContentsEquals("6", exitCodeFile);
-    }
-
-    private static IInvocationContext createContext() {
-        IInvocationContext context = new InvocationContext();
-        context.addDeviceBuildInfo("fakeDevice", new BuildInfo("1", "test"));
-        context.setTestTag("test");
-        return context;
-    }
-
-    private static void assertFileContentsEquals(String expected, Path filePath)
-            throws IOException {
-        assertEquals(expected, Files.readAllLines(filePath).get(0));
-    }
-
-    private Path createExitCodeFilePath() {
-        return mFileSystem.getPath("/tmp/test_exit_code.txt");
-    }
-
-    private BazelExitCodeResultReporter createReporter(Path path) throws Exception {
-        BazelExitCodeResultReporter reporter = new BazelExitCodeResultReporter(mFileSystem);
-        OptionSetter setter = new OptionSetter(reporter);
-        setter.setOptionValue("file", path.toString());
-        return reporter;
-    }
-}
diff --git a/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelXmlResultReporterTest.java b/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelXmlResultReporterTest.java
deleted file mode 100644
index a349e546..00000000
--- a/atest/bazel/reporter/javatests/com/android/tradefed/result/BazelXmlResultReporterTest.java
+++ /dev/null
@@ -1,204 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.tradefed.result;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.junit.Assert.assertEquals;
-
-import com.android.tradefed.build.BuildInfo;
-import com.android.tradefed.config.OptionSetter;
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.invoker.InvocationContext;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-
-import com.google.common.jimfs.Jimfs;
-import com.google.common.truth.StringSubject;
-
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-import org.w3c.dom.Document;
-import org.w3c.dom.Node;
-import org.xml.sax.SAXException;
-
-import java.io.IOException;
-import java.nio.file.FileSystem;
-import java.nio.file.Files;
-import java.nio.file.Path;
-import java.util.HashMap;
-
-import javax.xml.parsers.DocumentBuilder;
-import javax.xml.parsers.DocumentBuilderFactory;
-import javax.xml.parsers.ParserConfigurationException;
-
-@RunWith(JUnit4.class)
-public final class BazelXmlResultReporterTest {
-
-    private static final IInvocationContext DEFAULT_CONTEXT = createContext();
-    private static final TestDescription TEST_ID = new TestDescription("FooTest", "testFoo");
-    private static final String STACK_TRACE = "this is a trace";
-
-    private final FileSystem mFileSystem = Jimfs.newFileSystem();
-    private final HashMap<String, Metric> mEmptyMap = new HashMap<>();
-
-    @Test
-    public void writeResultPassed_testPassed() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testEnded(TEST_ID, 10L, mEmptyMap);
-        reporter.testRunEnded(20L, mEmptyMap);
-        reporter.invocationEnded(30L);
-
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testcase", "result", "passed");
-    }
-
-    @Test
-    public void writeStackTrace_testFailed() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testFailed(TEST_ID, "this is a trace");
-        reporter.testEnded(TEST_ID, 10L, mEmptyMap);
-        reporter.testRunEnded(20L, mEmptyMap);
-        reporter.invocationEnded(30L);
-
-        assertThatFileContents(xmlFile).contains("<![CDATA[this is a trace]]>");
-    }
-
-    @Test
-    public void noWriteTestCase_testIgnored() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testIgnored(TEST_ID);
-        reporter.testEnded(TEST_ID, 10L, mEmptyMap);
-        reporter.testRunEnded(20L, mEmptyMap);
-        reporter.invocationEnded(30L);
-
-        assertThatFileContents(xmlFile).doesNotContain("<testcase");
-    }
-
-    @Test
-    public void writeTestCaseResultIncomplete_runFailed() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testRunFailed("Error Message");
-        reporter.invocationEnded(30L);
-
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testcase", "result", "incomplete");
-    }
-
-    @Test
-    public void writeSkipped_testAssumptionFailure() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 1);
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testAssumptionFailure(TEST_ID, "Error Message");
-        reporter.testEnded(TEST_ID, 10L, mEmptyMap);
-        reporter.testRunEnded(20L, mEmptyMap);
-        reporter.invocationEnded(30L);
-
-        assertThatFileContents(xmlFile).contains("<skipped");
-    }
-
-    @Test
-    public void writeTestCount_multipleTests() throws Exception {
-        Path xmlFile = createXmlFilePath();
-        BazelXmlResultReporter reporter = createReporter(xmlFile);
-
-        reporter.invocationStarted(DEFAULT_CONTEXT);
-        reporter.testRunStarted("run", 3);
-        // A failed test.
-        reporter.testStarted(TEST_ID, 0L);
-        reporter.testFailed(TEST_ID, "this is a trace");
-        reporter.testEnded(TEST_ID, 10L, mEmptyMap);
-        // A skipped test.
-        TestDescription skippedTest = new TestDescription("FooTest", "testSkipped");
-        reporter.testStarted(skippedTest, 10L);
-        reporter.testAssumptionFailure(skippedTest, "Error Message");
-        reporter.testEnded(skippedTest, 20L, mEmptyMap);
-        // An ignored test.
-        TestDescription ignoredTest = new TestDescription("FooTest", "testIgnored");
-        reporter.testStarted(ignoredTest, 20L);
-        reporter.testIgnored(ignoredTest);
-        reporter.testEnded(ignoredTest, 30L, mEmptyMap);
-        reporter.testRunEnded(30L, mEmptyMap);
-        reporter.invocationEnded(30L);
-
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testsuite", "tests", "3");
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testsuite", "failures", "1");
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testsuite", "skipped", "1");
-        assertXmlFileContainsTagWithAttribute(xmlFile, "testsuite", "disabled", "1");
-    }
-
-    private static IInvocationContext createContext() {
-        IInvocationContext context = new InvocationContext();
-        context.addDeviceBuildInfo("fakeDevice", new BuildInfo("1", "test"));
-        context.setTestTag("test");
-        return context;
-    }
-
-    private static StringSubject assertThatFileContents(Path filePath) throws IOException {
-        return assertThat(Files.readString(filePath));
-    }
-
-    private static void assertXmlFileContainsTagWithAttribute(
-            Path filePath, String tagName, String attributeName, String attributeValue)
-            throws IOException, SAXException, ParserConfigurationException {
-        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
-        DocumentBuilder dBuilder = factory.newDocumentBuilder();
-        Document doc = dBuilder.parse(Files.newInputStream(filePath));
-        doc.getDocumentElement().normalize();
-        assertNodeContainsAttribute(
-                doc.getElementsByTagName(tagName).item(0), attributeName, attributeValue);
-    }
-
-    private static void assertNodeContainsAttribute(
-            Node node, String attributeName, String attributeValue) {
-        assertEquals(
-                node.getAttributes().getNamedItem(attributeName).getNodeValue(), attributeValue);
-    }
-
-    private Path createXmlFilePath() {
-        return mFileSystem.getPath("/tmp/test.xml");
-    }
-
-    private BazelXmlResultReporter createReporter(Path path) throws Exception {
-        BazelXmlResultReporter reporter = new BazelXmlResultReporter(mFileSystem);
-        OptionSetter setter = new OptionSetter(reporter);
-        setter.setOptionValue("file", path.toString());
-        return reporter;
-    }
-}
diff --git a/atest/bazel/reporter/src/com/android/tradefed/result/BazelExitCodeResultReporter.java b/atest/bazel/reporter/src/com/android/tradefed/result/BazelExitCodeResultReporter.java
deleted file mode 100644
index cbf9621b..00000000
--- a/atest/bazel/reporter/src/com/android/tradefed/result/BazelExitCodeResultReporter.java
+++ /dev/null
@@ -1,128 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.tradefed.result;
-
-import com.android.ddmlib.Log.LogLevel;
-import com.android.tradefed.config.Option;
-import com.android.tradefed.config.OptionClass;
-import com.android.tradefed.log.LogUtil.CLog;
-
-import com.google.common.annotations.VisibleForTesting;
-
-import java.io.IOException;
-import java.io.UncheckedIOException;
-import java.nio.file.FileSystem;
-import java.nio.file.FileSystems;
-import java.nio.file.Files;
-import java.nio.file.Path;
-
-/**
- * A custom Tradefed reporter for Bazel test rules.
- *
- * <p>This custom result reporter computes and exports the exit code for Bazel to determine whether
- * a test target passes or fails. The file is written to a file for downstream test rules to read
- * and is required because Tradefed commands terminate with a 0 exit code despite test failures.
- */
-@OptionClass(alias = "bazel-exit-code-result-reporter")
-public final class BazelExitCodeResultReporter implements ITestInvocationListener {
-
-    private final FileSystem mFileSystem;
-
-    // This is not a File object in order to use an in-memory FileSystem in tests. Using Path would
-    // have been more appropriate but Tradefed does not support option fields of that type.
-    @Option(name = "file", mandatory = true, description = "Bazel exit code file")
-    private String mExitCodeFile;
-
-    private boolean mHasRunFailures;
-    private boolean mHasTestFailures;
-
-    @VisibleForTesting
-    BazelExitCodeResultReporter(FileSystem fs) {
-        this.mFileSystem = fs;
-    }
-
-    public BazelExitCodeResultReporter() {
-        this(FileSystems.getDefault());
-    }
-
-    @Override
-    public void testRunFailed(String errorMessage) {
-        mHasRunFailures = true;
-    }
-
-    @Override
-    public void testRunFailed(FailureDescription failure) {
-        mHasRunFailures = true;
-    }
-
-    @Override
-    public void testFailed(TestDescription test, String trace) {
-        mHasTestFailures = true;
-    }
-
-    @Override
-    public void testFailed(TestDescription test, FailureDescription failure) {
-        mHasTestFailures = true;
-    }
-
-    @Override
-    public void invocationEnded(long elapsedTime) {
-        writeExitCodeFile();
-    }
-
-    private void writeExitCodeFile() {
-        ExitCode code = computeExitCode();
-
-        CLog.logAndDisplay(
-                LogLevel.INFO,
-                "Test exit code file generated at %s. Exit Code %s",
-                mExitCodeFile,
-                code);
-
-        try {
-            Path path = mFileSystem.getPath(mExitCodeFile);
-            Files.createDirectories(path.getParent());
-            Files.write(path, String.valueOf(code.value).getBytes());
-        } catch (IOException e) {
-            throw new UncheckedIOException("Failed to write exit code file.", e);
-        }
-    }
-
-    private ExitCode computeExitCode() {
-        if (mHasRunFailures) {
-            return ExitCode.RUN_FAILURE;
-        }
-
-        if (mHasTestFailures) {
-            return ExitCode.TESTS_FAILED;
-        }
-
-        return ExitCode.SUCCESS;
-    }
-
-    private enum ExitCode {
-        SUCCESS(0),
-        TESTS_FAILED(3),
-        RUN_FAILURE(6);
-
-        private final int value;
-
-        ExitCode(int value) {
-            this.value = value;
-        }
-    }
-}
diff --git a/atest/bazel/reporter/src/com/android/tradefed/result/BazelXmlResultReporter.java b/atest/bazel/reporter/src/com/android/tradefed/result/BazelXmlResultReporter.java
deleted file mode 100644
index 89049efe..00000000
--- a/atest/bazel/reporter/src/com/android/tradefed/result/BazelXmlResultReporter.java
+++ /dev/null
@@ -1,315 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.tradefed.result;
-
-import com.android.ddmlib.Log.LogLevel;
-import com.android.ddmlib.testrunner.TestResult.TestStatus;
-import com.android.tradefed.config.Option;
-import com.android.tradefed.config.OptionClass;
-import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-
-import com.google.common.annotations.VisibleForTesting;
-
-import org.w3c.dom.CDATASection;
-import org.w3c.dom.Document;
-import org.w3c.dom.Element;
-import org.w3c.dom.Node;
-
-import java.io.IOException;
-import java.io.OutputStream;
-import java.io.UncheckedIOException;
-import java.nio.file.FileSystem;
-import java.nio.file.FileSystems;
-import java.nio.file.Files;
-import java.nio.file.Path;
-import java.text.DateFormat;
-import java.text.SimpleDateFormat;
-import java.util.Date;
-import java.util.HashMap;
-import java.util.Locale;
-import java.util.Map;
-import java.util.TimeZone;
-import java.util.TreeMap;
-
-import javax.xml.parsers.DocumentBuilder;
-import javax.xml.parsers.DocumentBuilderFactory;
-import javax.xml.parsers.ParserConfigurationException;
-import javax.xml.transform.OutputKeys;
-import javax.xml.transform.Transformer;
-import javax.xml.transform.TransformerException;
-import javax.xml.transform.TransformerFactory;
-import javax.xml.transform.dom.DOMSource;
-import javax.xml.transform.stream.StreamResult;
-
-/**
- * A custom Tradefed reporter for Bazel XML result reporting.
- *
- * <p>This custom result reporter generates a test.xml file. The file contains detailed test case
- * results and is written to the location provided in the Bazel XML_OUTPUT_FILE environment
- * variable. The file is required for reporting detailed test results to AnTS via Bazel's BES
- * protocol. The XML schema is based on the JUnit test result schema. See
- * https://windyroad.com.au/dl/Open%20Source/JUnit.xsd for more details.
- */
-@OptionClass(alias = "bazel-xml-result-reporter")
-public final class BazelXmlResultReporter implements ITestInvocationListener {
-    private final FileSystem mFileSystem;
-    private TestRunResult mTestRunResult = new TestRunResult();
-
-    // This is not a File object in order to use an in-memory FileSystem in tests.
-    // Using Path would have been more appropriate but Tradefed does not support
-    // option fields of that type.
-    @Option(name = "file", mandatory = true, description = "Bazel XML file")
-    private String mXmlFile;
-
-    @VisibleForTesting
-    BazelXmlResultReporter(FileSystem fs) {
-        this.mFileSystem = fs;
-    }
-
-    public BazelXmlResultReporter() {
-        this(FileSystems.getDefault());
-    }
-
-    @Override
-    public void testRunStarted(String name, int numTests) {
-        testRunStarted(name, numTests, 0);
-    }
-
-    @Override
-    public void testRunStarted(String name, int numTests, int attemptNumber) {
-        testRunStarted(name, numTests, attemptNumber, System.currentTimeMillis());
-    }
-
-    @Override
-    public void testRunStarted(String name, int numTests, int attemptNumber, long startTime) {
-        mTestRunResult.testRunStarted(name, numTests, startTime);
-    }
-
-    @Override
-    public void testRunEnded(long elapsedTime, HashMap<String, Metric> runMetrics) {
-        mTestRunResult.testRunEnded(elapsedTime, runMetrics);
-    }
-
-    @Override
-    public void testRunFailed(String errorMessage) {
-        mTestRunResult.testRunFailed(errorMessage);
-    }
-
-    @Override
-    public void testRunFailed(FailureDescription failure) {
-        mTestRunResult.testRunFailed(failure);
-    }
-
-    @Override
-    public void testRunStopped(long elapsedTime) {
-        mTestRunResult.testRunStopped(elapsedTime);
-    }
-
-    @Override
-    public void testStarted(TestDescription test) {
-        testStarted(test, System.currentTimeMillis());
-    }
-
-    @Override
-    public void testStarted(TestDescription test, long startTime) {
-        mTestRunResult.testStarted(test, startTime);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, HashMap<String, Metric> testMetrics) {
-        testEnded(test, System.currentTimeMillis(), testMetrics);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, long endTime, HashMap<String, Metric> testMetrics) {
-        mTestRunResult.testEnded(test, endTime, testMetrics);
-    }
-
-    @Override
-    public void testFailed(TestDescription test, String trace) {
-        mTestRunResult.testFailed(test, trace);
-    }
-
-    @Override
-    public void testFailed(TestDescription test, FailureDescription failure) {
-        mTestRunResult.testFailed(test, failure);
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, String trace) {
-        mTestRunResult.testAssumptionFailure(test, trace);
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, FailureDescription failure) {
-        mTestRunResult.testAssumptionFailure(test, failure);
-    }
-
-    @Override
-    public void testIgnored(TestDescription test) {
-        mTestRunResult.testIgnored(test);
-    }
-
-    @Override
-    public void invocationEnded(long elapsedTime) {
-        writeXmlFile();
-    }
-
-    private void writeXmlFile() {
-        try (OutputStream os = createOutputStream(); ) {
-            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
-            DocumentBuilder builder = factory.newDocumentBuilder();
-            Document doc = builder.newDocument();
-            doc.setXmlStandalone(true);
-            // Pretty print XML file with indentation.
-            TransformerFactory transformerFactory = TransformerFactory.newInstance();
-            Transformer transformer = transformerFactory.newTransformer();
-            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
-            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
-            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
-
-            writeTestResult(doc, mTestRunResult);
-
-            DOMSource source = new DOMSource(doc);
-            StreamResult result = new StreamResult(os);
-            transformer.transform(source, result);
-        } catch (IOException e) {
-            throw new UncheckedIOException("Failed to write test.xml file", e);
-        } catch (TransformerException | ParserConfigurationException e) {
-            throw new RuntimeException("Failed to write test.xml file", e);
-        }
-
-        CLog.logAndDisplay(LogLevel.INFO, "Test XML file generated at %s.", mXmlFile);
-    }
-
-    private OutputStream createOutputStream() throws IOException {
-        Path path = mFileSystem.getPath(mXmlFile);
-        Files.createDirectories(path.getParent());
-        return Files.newOutputStream(path);
-    }
-
-    private void writeTestResult(Document doc, TestRunResult testRunResult) {
-        // There should be only one top-level testsuites element.
-        Element testSuites = writeTestSuites(doc, testRunResult);
-        doc.appendChild(testSuites);
-
-        Element testSuite = writeTestSuite(doc, testRunResult);
-        testSuites.appendChild(testSuite);
-        // We use a TreeMap to iterate over entries for deterministic output.
-        Map<TestDescription, TestResult> testResults =
-                new TreeMap<TestDescription, TestResult>(testRunResult.getTestResults());
-
-        for (Map.Entry<TestDescription, TestResult> testEntry : testResults.entrySet()) {
-            if (testEntry.getValue().getStatus().equals(TestStatus.IGNORED)) {
-                continue;
-            }
-            testSuite.appendChild(writeTestCase(doc, testEntry.getKey(), testEntry.getValue()));
-        }
-    }
-
-    private Element writeTestSuites(Document doc, TestRunResult testRunResult) {
-        Element testSuites = doc.createElementNS(null, "testsuites");
-
-        writeStringAttribute(testSuites, "name", testRunResult.getName());
-        writeTimestampAttribute(testSuites, "timestamp", testRunResult.getStartTime());
-
-        return testSuites;
-    }
-
-    private Element writeTestSuite(Document doc, TestRunResult testRunResult) {
-        Element testSuite = doc.createElementNS(null, "testsuite");
-
-        writeStringAttribute(testSuite, "name", testRunResult.getName());
-        writeTimestampAttribute(testSuite, "timestamp", testRunResult.getStartTime());
-
-        writeIntAttribute(testSuite, "tests", testRunResult.getNumTests());
-        writeIntAttribute(
-                testSuite, "failures", testRunResult.getNumTestsInState(TestStatus.FAILURE));
-        // The tests were not run to completion because the tests decided that they should
-        // not be run(example: due to a failed assumption in a JUnit4-style tests). Some per-test
-        // setup or tear down may or may not have occurred for tests with this result.
-        writeIntAttribute(
-                testSuite,
-                "skipped",
-                testRunResult.getNumTestsInState(TestStatus.ASSUMPTION_FAILURE));
-        // The tests were disabled with DISABLED_ (gUnit) or @Ignore (JUnit).
-        writeIntAttribute(
-                testSuite, "disabled", testRunResult.getNumTestsInState(TestStatus.IGNORED));
-
-        writeDurationAttribute(testSuite, "time", testRunResult.getElapsedTime());
-
-        return testSuite;
-    }
-
-    private Element writeTestCase(Document doc, TestDescription description, TestResult result) {
-        TestStatus status = result.getStatus();
-        Element testCase = doc.createElement("testcase");
-
-        writeStringAttribute(testCase, "name", description.getTestName());
-        writeStringAttribute(testCase, "classname", description.getClassName());
-        writeDurationAttribute(testCase, "time", result.getEndTime() - result.getStartTime());
-
-        writeStringAttribute(testCase, "status", "run");
-        writeStringAttribute(testCase, "result", status.toString().toLowerCase());
-
-        if (status.equals(TestStatus.FAILURE)) {
-            testCase.appendChild(writeStackTraceTag(doc, "failure", result.getStackTrace()));
-        } else if (status.equals(TestStatus.ASSUMPTION_FAILURE)) {
-            testCase.appendChild(writeStackTraceTag(doc, "skipped", result.getStackTrace()));
-        }
-
-        return testCase;
-    }
-
-    private static Node writeStackTraceTag(Document doc, String tag, String stackTrace) {
-        Element node = doc.createElement(tag);
-        CDATASection cdata = doc.createCDATASection(stackTrace);
-        node.appendChild(cdata);
-        return node;
-    }
-
-    private static void writeStringAttribute(
-            Element element, String attributeName, String attributeValue) {
-        element.setAttribute(attributeName, attributeValue);
-    }
-
-    private static void writeIntAttribute(
-            Element element, String attributeName, int attributeValue) {
-        element.setAttribute(attributeName, String.valueOf(attributeValue));
-    }
-
-    private static void writeTimestampAttribute(
-            Element element, String attributeName, long timestampInMillis) {
-        element.setAttribute(attributeName, formatTimestamp(timestampInMillis));
-    }
-
-    private static void writeDurationAttribute(Element element, String attributeName, long millis) {
-        element.setAttribute(attributeName, formatRunTime(millis));
-    }
-
-    private static String formatRunTime(Long runTimeInMillis) {
-        return String.valueOf(runTimeInMillis / 1000.0D);
-    }
-
-    // Return an ISO 8601 combined date and time string for a specified timestamp.
-    private static String formatTimestamp(Long timestampInMillis) {
-        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
-        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
-        return dateFormat.format(new Date(timestampInMillis));
-    }
-}
diff --git a/atest/bazel/resources/WORKSPACE b/atest/bazel/resources/WORKSPACE
deleted file mode 100644
index 22ff80ff..00000000
--- a/atest/bazel/resources/WORKSPACE
+++ /dev/null
@@ -1,26 +0,0 @@
-register_toolchains(
-    "//prebuilts/build-tools:py_toolchain",
-    "//prebuilts/jdk/jdk21:runtime_toolchain_definition",
-)
-
-# `device_infra` repository provides rules needed to start cuttlefish devices
-# remotely. This repository is loaded when Bazel needs a target from it,
-# otherwise won't load.
-local_repository(
-    name = "device_infra",
-    path = "vendor/google/tools/atest/device_infra",
-)
-
-local_repository(
-    name = "rules_python",
-    path = "external/bazelbuild-rules_python",
-)
-
-load("@rules_python//python:repositories.bzl", "py_repositories")
-
-py_repositories()
-
-local_repository(
-    name = "rules_java",
-    path = "external/bazelbuild-rules_java",
-)
diff --git a/atest/bazel/resources/bazel.sh b/atest/bazel/resources/bazel.sh
deleted file mode 100755
index cf7131f0..00000000
--- a/atest/bazel/resources/bazel.sh
+++ /dev/null
@@ -1,22 +0,0 @@
-#!/bin/bash
-# Script to run Bazel in AOSP.
-#
-# This script sets up startup and environment variables to run Bazel with the
-# AOSP JDK.
-#
-# Usage: bazel.sh [<startup options>] <command> [<args>]
-
-set -eo pipefail
-
-SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
-
-JDK_PATH="${SCRIPT_DIR}"/prebuilts/jdk/jdk21/linux-x86
-BAZEL_BINARY="${SCRIPT_DIR}"/prebuilts/bazel/linux-x86_64/bazel
-
-PROCESS_PATH="${JDK_PATH}"/bin:"${PATH}"
-
-JAVA_HOME="${JDK_PATH}" \
-PATH="${PROCESS_PATH}" \
-  "${BAZEL_BINARY}" \
-  --server_javabase="${JDK_PATH}" \
-  "$@"
diff --git a/atest/bazel/resources/bazelrc b/atest/bazel/resources/bazelrc
deleted file mode 100644
index 29585515..00000000
--- a/atest/bazel/resources/bazelrc
+++ /dev/null
@@ -1,37 +0,0 @@
-# Enable building targets in //external:__subpackages__.
-common --experimental_sibling_repository_layout
-common --experimental_disable_external_package
-
-# Show the full set of flags for observability and debuggability.
-common --announce_rc
-
-# Do not enable BzlMod as the migration to bzlmod has not been done yet
-common --noenable_bzlmod
-
-# Enforce consistent action environment variables to improve remote cache hit
-# rate.
-build --incompatible_strict_action_env
-
-# Use the JDK defined by local_java_runtime in //prebuilts/jdk/jdk<VERSION>
-build --java_runtime_version=jdk21
-
-# Depending on how many machines are in the remote execution instance, setting
-# this higher can make builds faster by allowing more jobs to run in parallel.
-# Setting it too high can result in jobs that timeout, however, while waiting
-# for a remote machine to execute them.
-build:remote --jobs=200
-
-# Enable the remote cache so that action results can be shared across machines,
-# developers, and workspaces.
-build:remote --remote_cache=grpcs://remotebuildexecution.googleapis.com
-
-# Enable remote execution so that actions are performed on the remote systems.
-build:remote --remote_executor=grpcs://remotebuildexecution.googleapis.com
-
-# Set a higher timeout value, just in case.
-build:remote --remote_timeout=3600
-
-# Enable authentication. This will pick up application default credentials by
-# default. You can use --auth_credentials=some_file.json to use a service
-# account credential instead.
-build:remote --google_default_credentials=true
diff --git a/atest/bazel/resources/configs/rbe/config/BUILD b/atest/bazel/resources/configs/rbe/config/BUILD
deleted file mode 100755
index 0bf601f6..00000000
--- a/atest/bazel/resources/configs/rbe/config/BUILD
+++ /dev/null
@@ -1,15 +0,0 @@
-package(default_visibility = ["//visibility:public"])
-
-platform(
-    name = "platform",
-    constraint_values = [
-        "@platforms//os:linux",
-        "@platforms//cpu:x86_64",
-    ],
-    exec_properties = {
-        "container-image": "docker://gcr.io/cloud-marketplace/google/rbe-ubuntu18-04@sha256:48b67b41118dbcdfc265e7335f454fbefa62681ab8d47200971fc7a52fb32054",
-        "gceMachineType": "e2-standard-16",
-        "OSFamily": "Linux",
-    },
-    parents = ["@local_config_platform//:host"],
-)
diff --git a/atest/bazel/resources/device_def/BUILD.bazel b/atest/bazel/resources/device_def/BUILD.bazel
deleted file mode 100644
index 3926fc5f..00000000
--- a/atest/bazel/resources/device_def/BUILD.bazel
+++ /dev/null
@@ -1,21 +0,0 @@
-load("//bazel/rules:soong_prebuilt.bzl", "soong_prebuilt")
-load("//bazel/rules/device:cuttlefish_device.bzl", "cuttlefish_device")
-load("@device_infra//remote_device:download_cvd_artifact.bzl", "build_id", "download_cvd_artifact")
-
-package(default_visibility = ["//visibility:public"])
-
-build_id(
-    name = "cvd_build_id",
-    build_setting_default = "",
-)
-
-download_cvd_artifact(
-    name = "cvd_artifacts",
-    build_id = ":cvd_build_id",
-)
-
-cuttlefish_device(
-    name = "cf_x86_64_phone",
-    out = "android_cuttlefish.sh",
-    build_files = ":cvd_artifacts",
-)
diff --git a/atest/bazel/resources/format_as_soong_module_name.cquery b/atest/bazel/resources/format_as_soong_module_name.cquery
deleted file mode 100644
index 7d784b52..00000000
--- a/atest/bazel/resources/format_as_soong_module_name.cquery
+++ /dev/null
@@ -1,10 +0,0 @@
-def format(target):
-    """Return the module name of a target if built by Soong, '' otherwise."""
-    p = providers(target)
-    if not p:
-        return ""
-    soong_prebuilt_info = p.get(
-        "//bazel/rules:soong_prebuilt.bzl%SoongPrebuiltInfo")
-    if soong_prebuilt_info:
-        return "%s:%s" % (soong_prebuilt_info.module_name, soong_prebuilt_info.platform_flavor)
-    return ""
diff --git a/atest/bazel/resources/rules/BUILD.bazel b/atest/bazel/resources/rules/BUILD.bazel
deleted file mode 100644
index 00cbb2bc..00000000
--- a/atest/bazel/resources/rules/BUILD.bazel
+++ /dev/null
@@ -1,40 +0,0 @@
-load("//bazel/rules:common_settings.bzl", "string_flag")
-load("//bazel/rules:common_settings.bzl", "string_list_flag")
-load("//bazel/rules/device:single_local_device.bzl", "local_device")
-
-package(default_visibility = ["//visibility:public"])
-
-string_flag(
-    name = "platform_flavor",
-    build_setting_default = "",
-)
-
-local_device(
-    name = "local_device",
-    out = "single_local_device.sh",
-)
-
-label_flag(
-    name = "target_device",
-    build_setting_default = ":local_device",
-)
-
-string_list_flag(
-    name = "extra_tradefed_result_reporters",
-    build_setting_default = [],
-)
-
-config_setting(
-    name = "device",
-    flag_values = {":platform_flavor": "device"},
-)
-
-config_setting(
-    name = "host",
-    flag_values = {":platform_flavor": "host"},
-)
-
-exports_files([
-    "tradefed_test.sh.template",
-    "device_test.sh.template",
-])
diff --git a/atest/bazel/resources/rules/common_settings.bzl b/atest/bazel/resources/rules/common_settings.bzl
deleted file mode 100644
index 39dcebcf..00000000
--- a/atest/bazel/resources/rules/common_settings.bzl
+++ /dev/null
@@ -1,57 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Build setting rule.
-
-The rule returns a BuildSettingInfo with the value of the build setting.
-More documentation on how to use build settings at
-https://docs.bazel.build/versions/master/skylark/config.html#user-defined-build-settings
-"""
-
-BuildSettingInfo = provider(
-    doc = "A singleton provider that contains the raw value of a build setting",
-    fields = {
-        "value": "The value of the build setting in the current configuration. " +
-                 "This value may come from the command line or an upstream transition, " +
-                 "or else it will be the build setting's default.",
-    },
-)
-
-def _string_impl(ctx):
-    allowed_values = ctx.attr.values
-    value = ctx.build_setting_value
-
-    if len(allowed_values) == 0 or value in ctx.attr.values:
-        return BuildSettingInfo(value = value)
-    fail("Error setting " + str(ctx.label) + ": invalid value '" + value + "'. Allowed values are " + str(allowed_values))
-
-string_flag = rule(
-    implementation = _string_impl,
-    build_setting = config.string(flag = True),
-    attrs = {
-        "values": attr.string_list(
-            doc = "The list of allowed values for this setting. An error is raised if any other value is given.",
-        ),
-    },
-    doc = "A string-typed build setting that can be set on the command line",
-)
-
-def _impl(ctx):
-    return BuildSettingInfo(value = ctx.build_setting_value)
-
-string_list_flag = rule(
-    implementation = _impl,
-    build_setting = config.string_list(flag = True),
-    doc = "A string list-typed build setting that can be set on the command line",
-)
diff --git a/atest/bazel/resources/rules/device/BUILD.bazel b/atest/bazel/resources/rules/device/BUILD.bazel
deleted file mode 100644
index 3c25c291..00000000
--- a/atest/bazel/resources/rules/device/BUILD.bazel
+++ /dev/null
@@ -1,6 +0,0 @@
-package(default_visibility = ["//visibility:public"])
-
-exports_files([
-    "create_cuttlefish.sh.template",
-    "single_local_device.sh",
-])
diff --git a/atest/bazel/resources/rules/device/create_cuttlefish.sh.template b/atest/bazel/resources/rules/device/create_cuttlefish.sh.template
deleted file mode 100644
index c90b3ae1..00000000
--- a/atest/bazel/resources/rules/device/create_cuttlefish.sh.template
+++ /dev/null
@@ -1,41 +0,0 @@
-#!/bin/bash
-
-DEVICE_IMAGE_PATH="{img_path}"
-DEVICE_IMAGE_DIR=$(dirname "$DEVICE_IMAGE_PATH")
-CVD_HOST_PACKAGE_PATH="{cvd_host_package_path}"
-
-PATH_ADDITIONS="{path_additions}"
-TEST_EXECUTABLE="$1"
-shift
-
-LOCAL_TOOL="$(dirname "$CVD_HOST_PACKAGE_PATH")"
-
-user="$(whoami)"
-
-su - << EOF
-export PATH="${LOCAL_TOOL}:${PATH_ADDITIONS}:${PATH}"
-/usr/sbin/service rsyslog restart
-/etc/init.d/cuttlefish-common start
-/usr/sbin/usermod -aG kvm "${USER}"
-
-pushd "${LOCAL_TOOL}"
-tar xvf "${CVD_HOST_PACKAGE_PATH}"
-popd
-
-pushd "${DEVICE_IMAGE_DIR}"
-unzip -o "${DEVICE_IMAGE_PATH}"
-popd
-
-HOME="${LOCAL_TOOL}" "${LOCAL_TOOL}"/bin/launch_cvd \
-  -daemon \
-  -config=phone \
-  -system_image_dir "${DEVICE_IMAGE_DIR}" \
-  -undefok=report_anonymous_usage_stats,config \
-  -report_anonymous_usage_stats=y \
-  -instance_dir=/tmp/cvd \
-  -guest_enforce_security=false
-adb connect localhost:6520
-exit
-EOF
-
-"${TEST_EXECUTABLE}" "$@"
\ No newline at end of file
diff --git a/atest/bazel/resources/rules/device/cuttlefish_device.bzl b/atest/bazel/resources/rules/device/cuttlefish_device.bzl
deleted file mode 100644
index 2432e822..00000000
--- a/atest/bazel/resources/rules/device/cuttlefish_device.bzl
+++ /dev/null
@@ -1,82 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Rule used to generate a Cuttlefish device environment.
-
-This rule creates a device environment rule to run tests on a Cuttlefish Android
-Virtual Device. Test targets that run in this environment will start a new
-dedicated virtual device for each execution.
-
-Device properties such as the image used can be configured via an attribute.
-"""
-
-load("//bazel/rules:platform_transitions.bzl", "host_transition")
-load("//bazel/rules:device_test.bzl", "DeviceEnvironment")
-load("@device_infra//remote_device:download_cvd_artifact.bzl", "ImageProvider")
-load(
-    "//:constants.bzl",
-    "adb_label",
-)
-
-_BAZEL_WORK_DIR = "${TEST_SRCDIR}/${TEST_WORKSPACE}/"
-
-def _cuttlefish_device_impl(ctx):
-    path_additions = [_BAZEL_WORK_DIR + ctx.file._adb.dirname]
-    image_file = ctx.attr.build_files[ImageProvider].image
-    cvd_host_file = ctx.attr.build_files[ImageProvider].cvd_host_package
-    ctx.actions.expand_template(
-        template = ctx.file._create_script_template,
-        output = ctx.outputs.out,
-        is_executable = True,
-        substitutions = {
-            "{img_path}": _BAZEL_WORK_DIR + image_file.short_path,
-            "{cvd_host_package_path}": _BAZEL_WORK_DIR + cvd_host_file.short_path,
-            "{path_additions}": ":".join(path_additions),
-        },
-    )
-
-    return DeviceEnvironment(
-        runner = depset([ctx.outputs.out]),
-        data = ctx.runfiles(files = [
-            cvd_host_file,
-            ctx.outputs.out,
-            image_file,
-        ]),
-    )
-
-cuttlefish_device = rule(
-    attrs = {
-        "build_files": attr.label(
-            providers = [ImageProvider],
-            mandatory = True,
-        ),
-        "out": attr.output(mandatory = True),
-        "_create_script_template": attr.label(
-            default = "//bazel/rules/device:create_cuttlefish.sh.template",
-            allow_single_file = True,
-        ),
-        # This attribute is required to use Starlark transitions. It allows
-        # allowlisting usage of this rule. For more information, see
-        # https://docs.bazel.build/versions/master/skylark/config.html#user-defined-transitions
-        "_allowlist_function_transition": attr.label(
-            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
-        ),
-        "_adb": attr.label(
-            default = adb_label,
-            allow_single_file = True,
-            cfg = host_transition,
-        ),
-    },
-    implementation = _cuttlefish_device_impl,
-)
diff --git a/atest/bazel/resources/rules/device/single_local_device.bzl b/atest/bazel/resources/rules/device/single_local_device.bzl
deleted file mode 100644
index 552d1e69..00000000
--- a/atest/bazel/resources/rules/device/single_local_device.bzl
+++ /dev/null
@@ -1,24 +0,0 @@
-load("//bazel/rules:device_test.bzl", "DeviceEnvironment")
-
-def _local_device_impl(ctx):
-    ctx.actions.expand_template(
-        template = ctx.file._source_script,
-        output = ctx.outputs.out,
-        is_executable = True,
-    )
-
-    return DeviceEnvironment(
-        runner = depset([ctx.outputs.out]),
-        data = ctx.runfiles(files = [ctx.outputs.out]),
-    )
-
-local_device = rule(
-    attrs = {
-        "_source_script": attr.label(
-            default = "//bazel/rules/device:single_local_device.sh",
-            allow_single_file = True,
-        ),
-        "out": attr.output(mandatory = True),
-    },
-    implementation = _local_device_impl,
-)
diff --git a/atest/bazel/resources/rules/device/single_local_device.sh b/atest/bazel/resources/rules/device/single_local_device.sh
deleted file mode 100644
index c0083c91..00000000
--- a/atest/bazel/resources/rules/device/single_local_device.sh
+++ /dev/null
@@ -1,3 +0,0 @@
-TEST_EXECUTABLE="$1"
-shift
-"${TEST_EXECUTABLE}" "$@"
\ No newline at end of file
diff --git a/atest/bazel/resources/rules/device_test.bzl b/atest/bazel/resources/rules/device_test.bzl
deleted file mode 100644
index 7ae559c7..00000000
--- a/atest/bazel/resources/rules/device_test.bzl
+++ /dev/null
@@ -1,74 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Rules used to run device tests"""
-
-_TEST_SRCDIR = "${TEST_SRCDIR}"
-_BAZEL_WORK_DIR = "%s/${TEST_WORKSPACE}/" % _TEST_SRCDIR
-_PY_TOOLCHAIN = "@bazel_tools//tools/python:toolchain_type"
-_TOOLCHAINS = [_PY_TOOLCHAIN]
-
-DeviceEnvironment = provider(
-    "Represents the environment a test will run under. Concretely this is an " +
-    "executable and any runfiles required to trigger execution in the " +
-    "environment.",
-    fields = {
-        "runner": "depset of executable to to setup test environment and execute test.",
-        "data": "runfiles of all needed artifacts in the executable.",
-    },
-)
-
-def device_test_impl(ctx):
-    runner_script = _BAZEL_WORK_DIR + ctx.attr.run_with[DeviceEnvironment].runner.to_list()[0].short_path
-    test_script = _BAZEL_WORK_DIR + ctx.file.test.short_path
-    script = ctx.actions.declare_file("device_test_%s.sh" % ctx.label.name)
-    path_additions = []
-
-    ctx.actions.expand_template(
-        template = ctx.file._device_test_template,
-        output = script,
-        is_executable = True,
-        substitutions = {
-            "{runner}": runner_script,
-            "{test_script}": test_script,
-        },
-    )
-
-    test_runfiles = ctx.runfiles().merge(
-        ctx.attr.test[DefaultInfo].default_runfiles,
-    )
-    device_runfiles = ctx.runfiles().merge(
-        ctx.attr.run_with[DeviceEnvironment].data,
-    )
-    all_runfiles = test_runfiles.merge_all([device_runfiles])
-    return [DefaultInfo(
-        executable = script,
-        runfiles = all_runfiles,
-    )]
-
-device_test = rule(
-    attrs = {
-        "run_with": attr.label(default = "//bazel/rules:target_device"),
-        "test": attr.label(
-            allow_single_file = True,
-        ),
-        "_device_test_template": attr.label(
-            default = "//bazel/rules:device_test.sh.template",
-            allow_single_file = True,
-        ),
-    },
-    test = True,
-    implementation = device_test_impl,
-    doc = "Runs a test under a device environment",
-)
diff --git a/atest/bazel/resources/rules/device_test.sh.template b/atest/bazel/resources/rules/device_test.sh.template
deleted file mode 100644
index c0e54805..00000000
--- a/atest/bazel/resources/rules/device_test.sh.template
+++ /dev/null
@@ -1,14 +0,0 @@
-#!/bin/bash
-set -e
-set -x
-
-RUNNER_EXECUTABLE="{runner}"
-TEST_EXECUTABLE="{test_script}"
-
-if [ -z "$RUNNER_EXECUTABLE" ]
-then
-  echo "No devices setup script"
-else
-  echo "There is devices setup script"
-  $RUNNER_EXECUTABLE $TEST_EXECUTABLE
-fi
\ No newline at end of file
diff --git a/atest/bazel/resources/rules/platform_transitions.bzl b/atest/bazel/resources/rules/platform_transitions.bzl
deleted file mode 100644
index f3a41866..00000000
--- a/atest/bazel/resources/rules/platform_transitions.bzl
+++ /dev/null
@@ -1,49 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Configuration transitions to change the platform flavor.
-
-These transitions are used to specify the build setting configuration of
-test targets required by test runner rule, because in different use cases,
-test runner requires the test target in different platform flavor and in
-the test target provider rules, the test target will be built based on the
-build setting specified by these transitions.
-
-More documentation on how to use transitions at
-https://docs.bazel.build/versions/main/skylark/config.html#user-defined-transitions
-"""
-
-def _host_transition_impl(settings, attr):
-    _ignore = (settings, attr)
-    return {
-        "//bazel/rules:platform_flavor": "host",
-    }
-
-host_transition = transition(
-    inputs = [],
-    outputs = ["//bazel/rules:platform_flavor"],
-    implementation = _host_transition_impl,
-)
-
-def _device_transition_impl(settings, attr):
-    _ignore = (settings, attr)
-    return {
-        "//bazel/rules:platform_flavor": "device",
-    }
-
-device_transition = transition(
-    inputs = [],
-    outputs = ["//bazel/rules:platform_flavor"],
-    implementation = _device_transition_impl,
-)
diff --git a/atest/bazel/resources/rules/soong_prebuilt.bzl b/atest/bazel/resources/rules/soong_prebuilt.bzl
deleted file mode 100644
index d2cd4754..00000000
--- a/atest/bazel/resources/rules/soong_prebuilt.bzl
+++ /dev/null
@@ -1,226 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Rule used to import artifacts prebuilt by Soong into the Bazel workspace.
-
-The rule returns a DefaultInfo provider with all artifacts and runtime dependencies,
-and a SoongPrebuiltInfo provider with the original Soong module name, artifacts,
-runtime dependencies and data dependencies.
-"""
-
-load("//bazel/rules:platform_transitions.bzl", "device_transition")
-load("//bazel/rules:common_settings.bzl", "BuildSettingInfo")
-
-SoongPrebuiltInfo = provider(
-    doc = "Info about a prebuilt Soong build module",
-    fields = {
-        "module_name": "Name of the original Soong build module",
-        # This field contains this target's outputs and all runtime dependency
-        # outputs.
-        "transitive_runtime_outputs": "Files required in the runtime environment",
-        "transitive_test_files": "Files of test modules",
-        "platform_flavor": "The platform flavor that this target will be built on",
-    },
-)
-
-def _soong_prebuilt_impl(ctx):
-    files = ctx.files.files
-
-    # Ensure that soong_prebuilt targets always have at least one file to avoid
-    # evaluation errors when running Bazel cquery on a clean tree to find
-    # dependencies.
-    #
-    # This happens because soong_prebuilt dependency target globs don't match
-    # any files when the workspace symlinks are broken and point to build
-    # artifacts that still don't exist. This in turn causes errors in rules
-    # that reference these targets via attributes with allow_single_file=True
-    # and which expect a file to be present.
-    #
-    # Note that the below action is never really executed during cquery
-    # evaluation but fails when run as part of a test execution to signal that
-    # prebuilts were not correctly imported.
-    if not files:
-        placeholder_file = ctx.actions.declare_file(ctx.label.name + ".missing")
-
-        progress_message = (
-            "Attempting to import missing artifacts for Soong module '%s'; " +
-            "please make sure that the module is built with Soong before " +
-            "running Bazel"
-        ) % ctx.attr.module_name
-
-        # Note that we don't write the file for the action to always be
-        # executed and display the warning message.
-        ctx.actions.run_shell(
-            outputs = [placeholder_file],
-            command = "/bin/false",
-            progress_message = progress_message,
-        )
-        files = [placeholder_file]
-
-    runfiles = ctx.runfiles(files = files).merge_all([
-        dep[DefaultInfo].default_runfiles
-        for dep in ctx.attr.runtime_deps + ctx.attr.data + ctx.attr.device_data
-    ])
-
-    # We exclude the outputs of static dependencies from the runfiles since
-    # they're already embedded in this target's output. Note that this is done
-    # recursively such that only transitive runtime dependency outputs are
-    # included. For example, in a chain A -> B -> C -> D where B and C are
-    # statically linked, only A's and D's outputs would remain in the runfiles.
-    runfiles = runfiles.merge_all([
-        ctx.runfiles(
-            files = _exclude_files(
-                dep[DefaultInfo].default_runfiles.files,
-                dep[DefaultInfo].files,
-            ).to_list(),
-        )
-        for dep in ctx.attr.static_deps
-    ])
-
-    return [
-        _make_soong_prebuilt_info(
-            ctx.attr.module_name,
-            ctx.attr._platform_flavor[BuildSettingInfo].value,
-            files = files,
-            runtime_deps = ctx.attr.runtime_deps,
-            static_deps = ctx.attr.static_deps,
-            data = ctx.attr.data,
-            device_data = ctx.attr.device_data,
-            suites = ctx.attr.suites,
-        ),
-        DefaultInfo(
-            files = depset(files),
-            runfiles = runfiles,
-        ),
-    ]
-
-soong_prebuilt = rule(
-    attrs = {
-        "module_name": attr.string(),
-        # Artifacts prebuilt by Soong.
-        "files": attr.label_list(allow_files = True),
-        # Targets that are needed by this target during runtime.
-        "runtime_deps": attr.label_list(),
-        # Note that while the outputs of static deps are not required for test
-        # execution we include them since they have their own runtime
-        # dependencies.
-        "static_deps": attr.label_list(),
-        "data": attr.label_list(),
-        "device_data": attr.label_list(
-            cfg = device_transition,
-        ),
-        "suites": attr.string_list(),
-        "_platform_flavor": attr.label(default = "//bazel/rules:platform_flavor"),
-        # This attribute is required to use Starlark transitions. It allows
-        # allowlisting usage of this rule. For more information, see
-        # https://docs.bazel.build/versions/master/skylark/config.html#user-defined-transitions
-        "_allowlist_function_transition": attr.label(
-            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
-        ),
-    },
-    implementation = _soong_prebuilt_impl,
-    doc = "A rule that imports artifacts prebuilt by Soong into the Bazel workspace",
-)
-
-def _soong_uninstalled_prebuilt_impl(ctx):
-    runfiles = ctx.runfiles().merge_all([
-        dep[DefaultInfo].default_runfiles
-        for dep in ctx.attr.runtime_deps
-    ])
-
-    return [
-        _make_soong_prebuilt_info(
-            ctx.attr.module_name,
-            ctx.attr._platform_flavor[BuildSettingInfo].value,
-            runtime_deps = ctx.attr.runtime_deps,
-        ),
-        DefaultInfo(
-            runfiles = runfiles,
-        ),
-    ]
-
-soong_uninstalled_prebuilt = rule(
-    attrs = {
-        "module_name": attr.string(),
-        "runtime_deps": attr.label_list(),
-        "_platform_flavor": attr.label(default = "//bazel/rules:platform_flavor"),
-    },
-    implementation = _soong_uninstalled_prebuilt_impl,
-    doc = "A rule for targets with no runtime outputs",
-)
-
-def _make_soong_prebuilt_info(
-        module_name,
-        platform_flavor,
-        files = [],
-        runtime_deps = [],
-        static_deps = [],
-        data = [],
-        device_data = [],
-        suites = []):
-    """Build a SoongPrebuiltInfo based on the given information.
-
-    Args:
-        runtime_deps: List of runtime dependencies required by this target.
-        static_deps: List of static dependencies required by this target.
-        data: List of data required by this target.
-        device_data: List of data on device variant required by this target.
-        suites: List of test suites this target belongs to.
-
-    Returns:
-        An instance of SoongPrebuiltInfo.
-    """
-    transitive_runtime_outputs = [
-        dep[SoongPrebuiltInfo].transitive_runtime_outputs
-        for dep in runtime_deps
-    ]
-
-    # We exclude the outputs of static dependencies and data dependencies from
-    # the transitive runtime outputs since static dependencies are already
-    # embedded in this target's output and the data dependencies shouldn't be
-    # present in the runtime paths. Note that this is done recursively such that
-    # only transitive runtime dependency outputs are included. For example, in a
-    # chain A -> B -> C -> D where B and C are statically linked or data
-    # dependencies, only A's and D's outputs would remain in the transitive
-    # runtime outputs.
-    transitive_runtime_outputs.extend([
-        _exclude_files(
-            dep[SoongPrebuiltInfo].transitive_runtime_outputs,
-            dep[DefaultInfo].files,
-        )
-        for dep in static_deps + data
-    ])
-    return SoongPrebuiltInfo(
-        module_name = module_name,
-        platform_flavor = platform_flavor,
-        transitive_runtime_outputs = depset(files, transitive = transitive_runtime_outputs),
-        transitive_test_files = depset(
-            # Note that `suites` is never empty for test files. This because
-            # test build modules that do not explicitly specify a `test_suites`
-            # Soong attribute belong to `null-suite`.
-            files if suites else [],
-            transitive = [
-                dep[SoongPrebuiltInfo].transitive_test_files
-                for dep in data + device_data + runtime_deps
-            ],
-        ),
-    )
-
-def _exclude_files(all_files, files_to_exclude):
-    files = []
-    files_to_exclude = {f: None for f in files_to_exclude.to_list()}
-    for f in all_files.to_list():
-        if f not in files_to_exclude:
-            files.append(f)
-    return depset(files)
diff --git a/atest/bazel/resources/rules/tradefed_test.bzl b/atest/bazel/resources/rules/tradefed_test.bzl
deleted file mode 100644
index 7fbc750a..00000000
--- a/atest/bazel/resources/rules/tradefed_test.bzl
+++ /dev/null
@@ -1,479 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Rules used to run tests using Tradefed."""
-
-load(
-    "//:constants.bzl",
-    "aapt2_label",
-    "aapt_label",
-    "adb_label",
-    "atest_script_help_sh_label",
-    "atest_tradefed_label",
-    "atest_tradefed_sh_label",
-    "bazel_result_reporter_label",
-    "compatibility_tradefed_label",
-    "tradefed_label",
-    "tradefed_test_framework_label",
-    "vts_core_tradefed_harness_label",
-)
-load("//bazel/rules:common_settings.bzl", "BuildSettingInfo")
-load("//bazel/rules:device_test.bzl", "device_test")
-load("//bazel/rules:platform_transitions.bzl", "device_transition", "host_transition")
-load("//bazel/rules:tradefed_test_aspects.bzl", "soong_prebuilt_tradefed_test_aspect")
-load("//bazel/rules:tradefed_test_dependency_info.bzl", "TradefedTestDependencyInfo")
-
-TradefedTestInfo = provider(
-    doc = "Info about a Tradefed test module",
-    fields = {
-        "module_name": "Name of the original Tradefed test module",
-    },
-)
-
-_BAZEL_WORK_DIR = "${TEST_SRCDIR}/${TEST_WORKSPACE}/"
-_PY_TOOLCHAIN = "@bazel_tools//tools/python:toolchain_type"
-_JAVA_TOOLCHAIN = "@bazel_tools//tools/jdk:runtime_toolchain_type"
-_TOOLCHAINS = [_PY_TOOLCHAIN, _JAVA_TOOLCHAIN]
-
-_TRADEFED_TEST_ATTRIBUTES = {
-    "module_name": attr.string(),
-    "_tradefed_test_template": attr.label(
-        default = "//bazel/rules:tradefed_test.sh.template",
-        allow_single_file = True,
-    ),
-    "_tradefed_classpath_jars": attr.label_list(
-        default = [
-            atest_tradefed_label,
-            tradefed_label,
-            tradefed_test_framework_label,
-            bazel_result_reporter_label,
-        ],
-        cfg = host_transition,
-        aspects = [soong_prebuilt_tradefed_test_aspect],
-    ),
-    "_atest_tradefed_launcher": attr.label(
-        default = atest_tradefed_sh_label,
-        allow_single_file = True,
-        cfg = host_transition,
-        aspects = [soong_prebuilt_tradefed_test_aspect],
-    ),
-    "_atest_helper": attr.label(
-        default = atest_script_help_sh_label,
-        allow_single_file = True,
-        cfg = host_transition,
-        aspects = [soong_prebuilt_tradefed_test_aspect],
-    ),
-    "_adb": attr.label(
-        default = adb_label,
-        allow_single_file = True,
-        cfg = host_transition,
-        aspects = [soong_prebuilt_tradefed_test_aspect],
-    ),
-    "_extra_tradefed_result_reporters": attr.label(
-        default = "//bazel/rules:extra_tradefed_result_reporters",
-    ),
-    # This attribute is required to use Starlark transitions. It allows
-    # allowlisting usage of this rule. For more information, see
-    # https://docs.bazel.build/versions/master/skylark/config.html#user-defined-transitions
-    "_allowlist_function_transition": attr.label(
-        default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
-    ),
-}
-
-def _add_dicts(*dictionaries):
-    """Creates a new `dict` that has all the entries of the given dictionaries.
-
-    This function serves as a replacement for the `+` operator which does not
-    work with dictionaries. The implementation is inspired by Skylib's
-    `dict.add` and duplicated to avoid the dependency. See
-    https://github.com/bazelbuild/bazel/issues/6461 for more details.
-
-    Note, if the same key is present in more than one of the input dictionaries,
-    the last of them in the argument list overrides any earlier ones.
-
-    Args:
-        *dictionaries: Dictionaries to be added.
-
-    Returns:
-        A new `dict` that has all the entries of the given dictionaries.
-    """
-    result = {}
-    for d in dictionaries:
-        result.update(d)
-    return result
-
-def _tradefed_deviceless_test_impl(ctx):
-    return _tradefed_test_impl(
-        ctx,
-        tradefed_options = [
-            "-n",
-            "--prioritize-host-config",
-            "--skip-host-arch-check",
-        ],
-        test_host_deps = ctx.attr.test,
-    )
-
-tradefed_deviceless_test = rule(
-    attrs = _add_dicts(
-        _TRADEFED_TEST_ATTRIBUTES,
-        {
-            "test": attr.label(
-                mandatory = True,
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-        },
-    ),
-    test = True,
-    implementation = _tradefed_deviceless_test_impl,
-    toolchains = _TOOLCHAINS,
-    doc = "A rule used to run host-side deviceless tests using Tradefed",
-)
-
-def _tradefed_robolectric_test_impl(ctx):
-    def add_android_all_files(ctx, tradefed_test_dir):
-        android_all_files = []
-        for target in ctx.attr._android_all:
-            for f in target.files.to_list():
-                # Tradefed expects a flat `android-all` directory structure for
-                # Robolectric tests.
-                symlink = _symlink(ctx, f, "%s/android-all/%s" % (tradefed_test_dir, f.basename))
-                android_all_files.append(symlink)
-        return android_all_files
-
-    return _tradefed_test_impl(
-        ctx,
-        data = [ctx.attr.jdk],
-        tradefed_options = [
-            "-n",
-            "--prioritize-host-config",
-            "--skip-host-arch-check",
-            "--test-arg",
-            "com.android.tradefed.testtype.IsolatedHostTest:java-folder:%s" % ctx.attr.jdk.label.package,
-        ],
-        test_host_deps = ctx.attr.test,
-        add_extra_tradefed_test_files = add_android_all_files,
-    )
-
-tradefed_robolectric_test = rule(
-    attrs = _add_dicts(
-        _TRADEFED_TEST_ATTRIBUTES,
-        {
-            "test": attr.label(
-                mandatory = True,
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-            "jdk": attr.label(
-                mandatory = True,
-            ),
-            "_android_all": attr.label_list(
-                default = ["//android-all:android-all"],
-            ),
-        },
-    ),
-    test = True,
-    implementation = _tradefed_robolectric_test_impl,
-    toolchains = _TOOLCHAINS,
-    doc = "A rule used to run Robolectric tests using Tradefed",
-)
-
-def _tradefed_device_test_impl(ctx):
-    tradefed_deps = []
-    tradefed_deps.extend(ctx.attr._aapt)
-    tradefed_deps.extend(ctx.attr._aapt2)
-    tradefed_deps.extend(ctx.attr.tradefed_deps)
-
-    test_device_deps = []
-    test_host_deps = []
-
-    if ctx.attr.host_test:
-        test_host_deps.extend(ctx.attr.host_test)
-    if ctx.attr.device_test:
-        test_device_deps.extend(ctx.attr.device_test)
-
-    return _tradefed_test_impl(
-        ctx,
-        tradefed_deps = tradefed_deps,
-        test_device_deps = test_device_deps,
-        test_host_deps = test_host_deps,
-        path_additions = [
-            _BAZEL_WORK_DIR + ctx.file._aapt.dirname,
-            _BAZEL_WORK_DIR + ctx.file._aapt2.dirname,
-        ],
-    )
-
-_tradefed_device_test = rule(
-    attrs = _add_dicts(
-        _TRADEFED_TEST_ATTRIBUTES,
-        {
-            "device_test": attr.label(
-                cfg = device_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-            "host_test": attr.label(
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-            "tradefed_deps": attr.label_list(
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-            "_aapt": attr.label(
-                default = aapt_label,
-                allow_single_file = True,
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-            "_aapt2": attr.label(
-                default = aapt2_label,
-                allow_single_file = True,
-                cfg = host_transition,
-                aspects = [soong_prebuilt_tradefed_test_aspect],
-            ),
-        },
-    ),
-    test = True,
-    implementation = _tradefed_device_test_impl,
-    toolchains = _TOOLCHAINS,
-    doc = "A rule used to run device tests using Tradefed",
-)
-
-def tradefed_device_driven_test(
-        name,
-        test,
-        tradefed_deps = [],
-        suites = [],
-        **attrs):
-    tradefed_test_name = "tradefed_test_%s" % name
-    _tradefed_device_test(
-        name = tradefed_test_name,
-        device_test = test,
-        tradefed_deps = _get_tradefed_deps(suites, tradefed_deps),
-        **attrs
-    )
-    device_test(
-        name = name,
-        test = tradefed_test_name,
-    )
-
-def tradefed_host_driven_device_test(test, tradefed_deps = [], suites = [], **attrs):
-    _tradefed_device_test(
-        host_test = test,
-        tradefed_deps = _get_tradefed_deps(suites, tradefed_deps),
-        **attrs
-    )
-
-def _tradefed_test_impl(
-        ctx,
-        tradefed_options = [],
-        tradefed_deps = [],
-        test_host_deps = [],
-        test_device_deps = [],
-        path_additions = [],
-        add_extra_tradefed_test_files = lambda ctx, tradefed_test_dir: [],
-        data = []):
-    path_additions = path_additions + [_BAZEL_WORK_DIR + ctx.file._adb.dirname]
-
-    # Files required to run the host-side test.
-    test_host_runfiles = _collect_runfiles(ctx, test_host_deps)
-    test_host_runtime_jars = _collect_runtime_jars(test_host_deps)
-    test_host_runtime_shared_libs = _collect_runtime_shared_libs(test_host_deps)
-
-    # Files required to run the device-side test.
-    test_device_runfiles = _collect_runfiles(ctx, test_device_deps)
-
-    # Files required to run Tradefed.
-    all_tradefed_deps = []
-    all_tradefed_deps.extend(ctx.attr._tradefed_classpath_jars)
-    all_tradefed_deps.extend(ctx.attr._atest_tradefed_launcher)
-    all_tradefed_deps.extend(ctx.attr._atest_helper)
-    all_tradefed_deps.extend(ctx.attr._adb)
-    all_tradefed_deps.extend(tradefed_deps)
-
-    tradefed_runfiles = _collect_runfiles(ctx, all_tradefed_deps)
-    tradefed_runtime_jars = _collect_runtime_jars(all_tradefed_deps)
-    tradefed_runtime_shared_libs = _collect_runtime_shared_libs(all_tradefed_deps)
-
-    result_reporters_config_file = _generate_reporter_config(ctx)
-    tradefed_runfiles = tradefed_runfiles.merge(
-        ctx.runfiles(files = [result_reporters_config_file]),
-    )
-
-    py_paths, py_runfiles = _configure_python_toolchain(ctx)
-    java_paths, java_runfiles, java_home = _configure_java_toolchain(ctx)
-    path_additions = path_additions + java_paths + py_paths
-    tradefed_runfiles = tradefed_runfiles.merge_all([py_runfiles, java_runfiles])
-
-    tradefed_test_dir = "%s_tradefed_test_dir" % ctx.label.name
-    tradefed_test_files = []
-
-    for dep in tradefed_deps + test_host_deps + test_device_deps:
-        for f in dep[TradefedTestDependencyInfo].transitive_test_files.to_list():
-            symlink = _symlink(ctx, f, "%s/%s" % (tradefed_test_dir, f.short_path))
-            tradefed_test_files.append(symlink)
-
-    tradefed_test_files.extend(add_extra_tradefed_test_files(ctx, tradefed_test_dir))
-
-    script = ctx.actions.declare_file("tradefed_test_%s.sh" % ctx.label.name)
-    ctx.actions.expand_template(
-        template = ctx.file._tradefed_test_template,
-        output = script,
-        is_executable = True,
-        substitutions = {
-            "{module_name}": ctx.attr.module_name,
-            "{atest_tradefed_launcher}": _abspath(ctx.file._atest_tradefed_launcher),
-            "{atest_helper}": _abspath(ctx.file._atest_helper),
-            "{tradefed_test_dir}": _BAZEL_WORK_DIR + "%s/%s" % (
-                ctx.label.package,
-                tradefed_test_dir,
-            ),
-            "{tradefed_classpath}": _classpath([tradefed_runtime_jars, test_host_runtime_jars]),
-            "{shared_lib_dirs}": _ld_library_path([tradefed_runtime_shared_libs, test_host_runtime_shared_libs]),
-            "{path_additions}": ":".join(path_additions),
-            "{additional_tradefed_options}": " ".join(tradefed_options),
-            "{result_reporters_config_file}": _abspath(result_reporters_config_file),
-            "{java_home}": java_home,
-        },
-    )
-
-    return [
-        DefaultInfo(
-            executable = script,
-            runfiles = tradefed_runfiles.merge_all([
-                test_host_runfiles,
-                test_device_runfiles,
-                ctx.runfiles(tradefed_test_files),
-            ] + [ctx.runfiles(d.files.to_list()) for d in data]),
-        ),
-        TradefedTestInfo(
-            module_name = ctx.attr.module_name,
-        ),
-    ]
-
-def _get_tradefed_deps(suites, tradefed_deps = []):
-    suite_to_deps = {
-        "host-unit-tests": [],
-        "null-suite": [],
-        "device-tests": [],
-        "general-tests": [],
-        "vts": [vts_core_tradefed_harness_label],
-    }
-    all_tradefed_deps = {d: None for d in tradefed_deps}
-
-    for s in suites:
-        all_tradefed_deps.update({
-            d: None
-            for d in suite_to_deps.get(s, [compatibility_tradefed_label])
-        })
-
-    # Since `vts-core-tradefed-harness` includes `compatibility-tradefed`, we
-    # will exclude `compatibility-tradefed` if `vts-core-tradefed-harness` exists.
-    if vts_core_tradefed_harness_label in all_tradefed_deps:
-        all_tradefed_deps.pop(compatibility_tradefed_label)
-
-    return all_tradefed_deps.keys()
-
-def _generate_reporter_config(ctx):
-    result_reporters = [
-        "com.android.tradefed.result.BazelExitCodeResultReporter",
-        "com.android.tradefed.result.BazelXmlResultReporter",
-        "com.android.tradefed.result.proto.FileProtoResultReporter",
-    ]
-
-    result_reporters.extend(ctx.attr._extra_tradefed_result_reporters[BuildSettingInfo].value)
-
-    result_reporters_config_file = ctx.actions.declare_file("result-reporters-%s.xml" % ctx.label.name)
-    _write_reporters_config_file(
-        ctx,
-        result_reporters_config_file,
-        result_reporters,
-    )
-
-    return result_reporters_config_file
-
-def _write_reporters_config_file(ctx, config_file, result_reporters):
-    config_lines = [
-        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
-        "<configuration>",
-    ]
-
-    for result_reporter in result_reporters:
-        config_lines.append("    <result_reporter class=\"%s\" />" % result_reporter)
-
-    config_lines.append("</configuration>")
-
-    ctx.actions.write(config_file, "\n".join(config_lines))
-
-def _configure_java_toolchain(ctx):
-    java_runtime = ctx.toolchains[_JAVA_TOOLCHAIN].java_runtime
-    java_home_path = _BAZEL_WORK_DIR + java_runtime.java_home
-    java_runfiles = ctx.runfiles(transitive_files = java_runtime.files)
-    return ([java_home_path + "/bin"], java_runfiles, java_home_path)
-
-def _configure_python_toolchain(ctx):
-    py_toolchain_info = ctx.toolchains[_PY_TOOLCHAIN]
-    py3_interpreter = py_toolchain_info.py3_runtime.interpreter
-
-    # Create `python` and `python3` symlinks in the runfiles tree and add them
-    # to the executable path. This is required because scripts reference these
-    # commands in their shebang line.
-    py_runfiles = ctx.runfiles(symlinks = {
-        "/".join([py3_interpreter.dirname, "python"]): py3_interpreter,
-        "/".join([py3_interpreter.dirname, "python3"]): py3_interpreter,
-    })
-    py_paths = [
-        _BAZEL_WORK_DIR + py3_interpreter.dirname,
-    ]
-    return (py_paths, py_runfiles)
-
-def _symlink(ctx, target_file, output_path):
-    symlink = ctx.actions.declare_file(output_path)
-    ctx.actions.symlink(output = symlink, target_file = target_file)
-    return symlink
-
-def _collect_runfiles(ctx, targets):
-    return ctx.runfiles().merge_all([
-        target[DefaultInfo].default_runfiles
-        for target in targets
-    ])
-
-def _collect_runtime_jars(deps):
-    return depset(
-        transitive = [
-            d[TradefedTestDependencyInfo].runtime_jars
-            for d in deps
-        ],
-    )
-
-def _collect_runtime_shared_libs(deps):
-    return depset(
-        transitive = [
-            d[TradefedTestDependencyInfo].runtime_shared_libraries
-            for d in deps
-        ],
-    )
-
-def _classpath(deps):
-    runtime_jars = depset(transitive = deps)
-    return ":".join([_abspath(f) for f in runtime_jars.to_list()])
-
-def _ld_library_path(deps):
-    runtime_shared_libs = depset(transitive = deps)
-    return ":".join(
-        [_BAZEL_WORK_DIR + f.dirname for f in runtime_shared_libs.to_list()],
-    )
-
-def _abspath(file):
-    return _BAZEL_WORK_DIR + file.short_path
diff --git a/atest/bazel/resources/rules/tradefed_test.sh.template b/atest/bazel/resources/rules/tradefed_test.sh.template
deleted file mode 100644
index 42a783b7..00000000
--- a/atest/bazel/resources/rules/tradefed_test.sh.template
+++ /dev/null
@@ -1,64 +0,0 @@
-#!/bin/bash
-set -e
-set -x
-
-TEST_MODULE="{module_name}"
-TEST_PATH="{tradefed_test_dir}"
-ATEST_TF_LAUNCHER="{atest_tradefed_launcher}"
-ATEST_HELPER="{atest_helper}"
-SHARED_LIB_DIRS="{shared_lib_dirs}"
-PATH_ADDITIONS="{path_additions}"
-TRADEFED_CLASSPATH="{tradefed_classpath}"
-RESULT_REPORTERS_CONFIG_FILE="{result_reporters_config_file}"
-ATEST_JAVA_HOME="{atest_java_home}"
-read -a ADDITIONAL_TRADEFED_OPTIONS <<< "{additional_tradefed_options}"
-
-# Export variables expected by the Atest launcher script.
-export LD_LIBRARY_PATH="${SHARED_LIB_DIRS}"
-export TF_PATH="${TRADEFED_CLASSPATH}"
-export PATH="${PATH_ADDITIONS}:${PATH}"
-export ATEST_HELPER="${ATEST_HELPER}"
-export JAVA_HOME="${ATEST_JAVA_HOME}"
-
-exit_code_file="$(mktemp /tmp/tf-exec-XXXXXXXXXX)"
-
-"${ATEST_TF_LAUNCHER}" template/atest_local_min \
-    --template:map test=atest \
-    --template:map reporters="${RESULT_REPORTERS_CONFIG_FILE}" \
-    --tests-dir "${TEST_PATH}" \
-    --no-enable-granular-attempts \
-    --no-early-device-release \
-    --include-filter "${TEST_MODULE}" \
-    --skip-loading-config-jar \
-    --log-level-display VERBOSE \
-    --log-level VERBOSE \
-    "${ADDITIONAL_TRADEFED_OPTIONS[@]}" \
-    --bazel-exit-code-result-reporter:file=${exit_code_file} \
-    --bazel-xml-result-reporter:file=${XML_OUTPUT_FILE} \
-    --proto-output-file="${TEST_UNDECLARED_OUTPUTS_DIR}/proto-results" \
-    --use-delimited-api=true \
-    --log-file-path="${TEST_UNDECLARED_OUTPUTS_DIR}" \
-    --compress-files=false \
-    "$@"
-
-# Use the TF exit code if it terminates abnormally.
-tf_exit=$?
-if [ ${tf_exit} -ne 0 ]
-then
-     echo "Tradefed command failed with exit code ${tf_exit}"
-     exit ${tf_exit}
-fi
-
-# Set the exit code based on the exit code in the reporter-generated file.
-exit_code=$(<${exit_code_file})
-if [ $? -ne 0 ]
-then
-  echo "Could not read exit code file: ${exit_code_file}"
-  exit 36
-fi
-
-if [ ${exit_code} -ne 0 ]
-then
-  echo "Test failed with exit code ${exit_code}"
-  exit ${exit_code}
-fi
diff --git a/atest/bazel/resources/rules/tradefed_test_aspects.bzl b/atest/bazel/resources/rules/tradefed_test_aspects.bzl
deleted file mode 100644
index 58affca4..00000000
--- a/atest/bazel/resources/rules/tradefed_test_aspects.bzl
+++ /dev/null
@@ -1,48 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Aspects used to transform certain providers into a TradefedTestDependencyInfo.
-
-Tradefed tests require a TradefedTestDependencyInfo provider that is not
-usually returned by most rules. Instead of creating custom rules to adapt
-build rule providers, we use Bazel aspects to convert the input rule's
-provider into a suitable type.
-
-See https://docs.bazel.build/versions/main/skylark/aspects.html#aspects
-for more information on how aspects work.
-"""
-
-load("//bazel/rules:soong_prebuilt.bzl", "SoongPrebuiltInfo")
-load("//bazel/rules:tradefed_test_dependency_info.bzl", "TradefedTestDependencyInfo")
-
-def _soong_prebuilt_tradefed_aspect_impl(target, ctx):
-    runtime_jars = []
-    runtime_shared_libraries = []
-    for f in target[SoongPrebuiltInfo].transitive_runtime_outputs.to_list():
-        if f.extension == "so":
-            runtime_shared_libraries.append(f)
-        elif f.extension == "jar":
-            runtime_jars.append(f)
-
-    return [
-        TradefedTestDependencyInfo(
-            runtime_jars = depset(runtime_jars),
-            runtime_shared_libraries = depset(runtime_shared_libraries),
-            transitive_test_files = target[SoongPrebuiltInfo].transitive_test_files,
-        ),
-    ]
-
-soong_prebuilt_tradefed_test_aspect = aspect(
-    implementation = _soong_prebuilt_tradefed_aspect_impl,
-)
diff --git a/atest/bazel/resources/rules/tradefed_test_dependency_info.bzl b/atest/bazel/resources/rules/tradefed_test_dependency_info.bzl
deleted file mode 100644
index 2f4689c7..00000000
--- a/atest/bazel/resources/rules/tradefed_test_dependency_info.bzl
+++ /dev/null
@@ -1,33 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
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
-"""Provides dependency information required by Tradefed test rules.
-
-This provider encapsulates information about dependencies that is required for
-setting up the execution environment. Aspects are responsible for converting the
-actual dependency's provider to an instance of this structure. For example, a
-dependency with a `JavaInfo` provider defines several fields for the jars
-required at runtime which is different from what `SoongPrebuiltInfo` exports.
-This essentially shields the test rule's implementation from the different
-provider types.
-"""
-
-TradefedTestDependencyInfo = provider(
-    doc = "Info required by Tradefed rules to run tests",
-    fields = {
-        "runtime_jars": "Jars required on the runtime classpath",
-        "runtime_shared_libraries": "Shared libraries that are required at runtime",
-        "transitive_test_files": "Files of test modules",
-    },
-)
diff --git a/atest/bazel/runner/Android.bp b/atest/bazel/runner/Android.bp
deleted file mode 100644
index 2172bd71..00000000
--- a/atest/bazel/runner/Android.bp
+++ /dev/null
@@ -1,90 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-java_library_host {
-    name: "bazel-test-runner",
-    srcs: [
-        "src/com/android/tradefed/testtype/bazel/BazelTest.java",
-        "src/com/android/tradefed/testtype/bazel/BepFileTailer.java",
-        "src/com/android/tradefed/testtype/bazel/ForwardingTestListener.java",
-        "src/com/android/tradefed/testtype/bazel/BazelTestListener.java",
-        "src/com/android/tradefed/testtype/bazel/NullTestListener.java",
-        "src/com/android/tradefed/testtype/bazel/InvocationLogCollector.java",
-        "src/com/android/tradefed/testtype/bazel/LogPathUpdatingListener.java",
-        "src/com/android/tradefed/testtype/bazel/TestListeners.java",
-        "src/com/android/tradefed/testtype/bazel/SparseTestListener.java",
-        "src/main/protobuf/*.proto",
-    ],
-    // b/267831518: Pin tradefed and dependencies to Java 11.
-    java_version: "11",
-    libs: [
-        "tradefed",
-    ],
-    java_resource_dirs: [
-        "config",
-    ],
-    proto: {
-        type: "full",
-        include_dirs: [
-            "external/protobuf/src",
-        ],
-        canonical_path_from_root: false,
-    },
-}
-
-java_genrule_host {
-    name: "empty-bazel-test-suite",
-    cmd: "BAZEL_SUITE_DIR=$(genDir)/android-bazel-suite && " +
-        "mkdir \"$${BAZEL_SUITE_DIR}\" && " +
-        "mkdir \"$${BAZEL_SUITE_DIR}\"/tools && " +
-        "mkdir \"$${BAZEL_SUITE_DIR}\"/testcases && " +
-        "cp $(location :tradefed) \"$${BAZEL_SUITE_DIR}\"/tools && " +
-        "cp $(location :compatibility-host-util) \"$${BAZEL_SUITE_DIR}\"/tools && " +
-        "cp $(location :compatibility-tradefed) \"$${BAZEL_SUITE_DIR}\"/tools && " +
-        "cp $(location :bazel-test-runner) \"$${BAZEL_SUITE_DIR}\"/testcases && " +
-        "$(location soong_zip) -o $(out) -d -C $(genDir) -D \"$${BAZEL_SUITE_DIR}\" -sha256",
-    out: ["empty-bazel-test-suite.zip"],
-    srcs: [
-        ":tradefed",
-        ":bazel-test-runner",
-        ":compatibility-host-util",
-        ":compatibility-tradefed",
-    ],
-    tools: [
-        "soong_zip",
-    ],
-    dist: {
-        targets: ["empty-bazel-test-suite"],
-    },
-}
-
-java_test_host {
-    name: "bazel-test-runner-tests",
-    srcs: [
-        "tests/src/com/android/tradefed/testtype/bazel/BazelTestTest.java",
-    ],
-    static_libs: [
-        "bazel-test-runner",
-        "tradefed",
-        "mockito",
-        "objenesis",
-    ],
-    test_options: {
-        unit_test: true,
-    },
-}
diff --git a/atest/bazel/runner/config/config/bazel_deviceless_tests.xml b/atest/bazel/runner/config/config/bazel_deviceless_tests.xml
deleted file mode 100644
index e4033cbe..00000000
--- a/atest/bazel/runner/config/config/bazel_deviceless_tests.xml
+++ /dev/null
@@ -1,8 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2022 Google Inc. All Rights Reserved. -->
-<configuration description="A suite to run the Bazel tests contained in the Atest-generated workspace archive." >
-  <option name="null-device" value="true" />
-  <test class="com.android.tradefed.testtype.bazel.BazelTest" />
-  <logger class="com.android.tradefed.log.FileLogger" />
-  <template-include name="reporters" default="empty" />
-</configuration>
diff --git a/atest/bazel/runner/config/config/format_module_name_to_test_target.cquery b/atest/bazel/runner/config/config/format_module_name_to_test_target.cquery
deleted file mode 100644
index 1cc8ec04..00000000
--- a/atest/bazel/runner/config/config/format_module_name_to_test_target.cquery
+++ /dev/null
@@ -1,14 +0,0 @@
-def format(target):
-    """Return a pair of 'module_name target_label' for the given tradefed test target, '' otherwise."""
-    p = providers(target)
-    if not p:
-        return ""
-    tradefed_test_info = p.get(
-        "//bazel/rules:tradefed_test.bzl%TradefedTestInfo")
-    if tradefed_test_info:
-    # Use space as a delimiter as Bazel labels can use many spacial characters in their target
-    # labels. See: https://bazel.build/concepts/labels#target-names
-        return "%s %s" % (tradefed_test_info.module_name, target.label)
-    else:
-        return ""
-    return ""
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java
deleted file mode 100644
index deb88507..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTest.java
+++ /dev/null
@@ -1,996 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.annotations.VisibleForTesting;
-import com.android.tradefed.config.ConfigurationDescriptor;
-import com.android.tradefed.config.Option;
-import com.android.tradefed.config.OptionClass;
-import com.android.tradefed.device.DeviceNotAvailableException;
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.invoker.InvocationContext;
-import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.invoker.logger.InvocationMetricLogger;
-import com.android.tradefed.invoker.logger.InvocationMetricLogger.InvocationMetricKey;
-import com.android.tradefed.invoker.tracing.CloseableTraceScope;
-import com.android.tradefed.invoker.tracing.TracePropagatingExecutorService;
-import com.android.tradefed.log.ITestLogger;
-import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.result.FailureDescription;
-import com.android.tradefed.result.FileInputStreamSource;
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.error.ErrorIdentifier;
-import com.android.tradefed.result.error.TestErrorIdentifier;
-import com.android.tradefed.result.proto.ProtoResultParser;
-import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
-import com.android.tradefed.result.proto.TestRecordProto.TestRecord;
-import com.android.tradefed.testtype.IRemoteTest;
-import com.android.tradefed.util.AbiUtils;
-import com.android.tradefed.util.FileUtil;
-import com.android.tradefed.util.ZipUtil;
-import com.android.tradefed.util.proto.TestRecordProtoUtil;
-
-import com.google.common.collect.BiMap;
-import com.google.common.collect.HashBiMap;
-import com.google.common.collect.HashMultimap;
-import com.google.common.collect.ImmutableBiMap;
-import com.google.common.collect.Maps;
-import com.google.common.collect.SetMultimap;
-import com.google.common.io.CharStreams;
-import com.google.common.io.MoreFiles;
-import com.google.common.io.Resources;
-import com.google.devtools.build.lib.buildeventstream.BuildEventStreamProtos;
-import com.google.protobuf.InvalidProtocolBufferException;
-
-import java.io.File;
-import java.io.FileWriter;
-import java.io.IOException;
-import java.io.FileOutputStream;
-import java.lang.ProcessBuilder.Redirect;
-import java.net.URI;
-import java.net.URISyntaxException;
-import java.nio.file.Files;
-import java.nio.file.Path;
-import java.nio.file.Paths;
-import java.time.Duration;
-import java.util.ArrayList;
-import java.util.Collection;
-import java.util.Collections;
-import java.util.List;
-import java.util.Map.Entry;
-import java.util.Map;
-import java.util.Properties;
-import java.util.Set;
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.Executors;
-import java.util.concurrent.TimeUnit;
-import java.util.function.Consumer;
-import java.util.stream.Collectors;
-import java.util.stream.Stream;
-import java.util.zip.ZipFile;
-
-/** Test runner for executing Bazel tests. */
-@OptionClass(alias = "bazel-test")
-public final class BazelTest implements IRemoteTest {
-
-    public static final String QUERY_ALL_TARGETS = "query_all_targets";
-    public static final String QUERY_MAP_MODULES_TO_TARGETS = "query_map_modules_to_targets";
-    public static final String RUN_TESTS = "run_tests";
-    public static final String BUILD_TEST_ARG = "bazel-build";
-    public static final String TEST_TAG_TEST_ARG = "bazel-test";
-    public static final String BRANCH_TEST_ARG = "bazel-branch";
-    public static final int BAZEL_TESTS_FAILED_RETURN_CODE = 3;
-
-    // Add method excludes to TF's global filters since Bazel doesn't support target-specific
-    // arguments. See https://github.com/bazelbuild/rules_go/issues/2784.
-    // TODO(b/274787592): Integrate with Bazel's test filtering to filter specific test cases.
-    public static final String GLOBAL_EXCLUDE_FILTER_TEMPLATE =
-            "--test_arg=--global-filters:exclude-filter=%s";
-
-    private static final Duration BAZEL_QUERY_TIMEOUT = Duration.ofMinutes(5);
-    private static final String TEST_NAME = BazelTest.class.getName();
-    // Bazel internally calls the test output archive file "test.outputs__outputs.zip", the double
-    // underscore is part of this name.
-    private static final String TEST_UNDECLARED_OUTPUTS_ARCHIVE_NAME = "test.outputs__outputs.zip";
-    private static final String PROTO_RESULTS_FILE_NAME = "proto-results";
-
-    private final List<Path> mTemporaryPaths = new ArrayList<>();
-    private final List<LogFileWithType> mLogFiles = new ArrayList<>();
-    private final Properties mProperties;
-    private final ProcessStarter mProcessStarter;
-    private final Path mTemporaryDirectory;
-    private final ExecutorService mExecutor;
-
-    private Path mRunTemporaryDirectory;
-    private Path mBazelOutputRoot;
-    private Path mJavaTempOutput;
-
-    private enum FilterType {
-        MODULE,
-        TEST_CASE
-    };
-
-    @Option(
-            name = "bazel-test-command-timeout",
-            description = "Timeout for running the Bazel test.")
-    private Duration mBazelCommandTimeout = Duration.ofHours(1L);
-
-    @Option(
-            name = "bazel-test-suite-root-dir",
-            description =
-                    "Name of the environment variable set by CtsTestLauncher indicating the"
-                            + " location of the root bazel-test-suite dir.")
-    private String mSuiteRootDirEnvVar = "BAZEL_SUITE_ROOT";
-
-    @Option(
-            name = "bazel-startup-options",
-            description = "List of startup options to be passed to Bazel.")
-    private final List<String> mBazelStartupOptions = new ArrayList<>();
-
-    @Option(
-            name = "bazel-test-extra-args",
-            description = "List of extra arguments to be passed to Bazel")
-    private final List<String> mBazelTestExtraArgs = new ArrayList<>();
-
-    @Option(
-            name = "bazel-max-idle-timout",
-            description = "Max idle timeout in seconds for bazel commands.")
-    private Duration mBazelMaxIdleTimeout = Duration.ofSeconds(30L);
-
-    @Option(name = "exclude-filter", description = "Test modules to exclude when running tests.")
-    private final List<String> mExcludeTargets = new ArrayList<>();
-
-    @Option(name = "include-filter", description = "Test modules to include when running tests.")
-    private final List<String> mIncludeTargets = new ArrayList<>();
-
-    @Option(
-            name = "bazel-query",
-            description = "Bazel query to return list of tests, defaults to all deviceless tests")
-    private String mBazelQuery = "kind(tradefed_deviceless_test, tests(//...))";
-
-    @Option(
-            name = "report-cached-test-results",
-            description = "Whether or not to report cached test results.")
-    private boolean mReportCachedTestResults = true;
-
-    @Option(
-            name = "report-cached-modules-sparsely",
-            description = "Whether to only report module level events for cached test modules.")
-    private boolean mReportCachedModulesSparsely = false;
-
-    public BazelTest() {
-        this(new DefaultProcessStarter(), System.getProperties());
-    }
-
-    @VisibleForTesting
-    BazelTest(ProcessStarter processStarter, Properties properties) {
-        mProcessStarter = processStarter;
-        mExecutor = TracePropagatingExecutorService.create(Executors.newCachedThreadPool());
-        mProperties = properties;
-        mTemporaryDirectory = Paths.get(properties.getProperty("java.io.tmpdir"));
-    }
-
-    @Override
-    public void run(TestInformation testInfo, ITestInvocationListener listener)
-            throws DeviceNotAvailableException {
-
-        List<FailureDescription> runFailures = new ArrayList<>();
-        long startTime = System.currentTimeMillis();
-        RunStats stats = new RunStats();
-
-        try {
-            initialize();
-            logWorkspaceContents();
-            runTestsAndParseResults(testInfo, listener, runFailures, stats);
-        } catch (AbortRunException e) {
-            runFailures.add(e.getFailureDescription());
-        } catch (IOException | InterruptedException e) {
-            runFailures.add(throwableToTestFailureDescription(e));
-        }
-
-        listener.testModuleStarted(testInfo.getContext());
-        listener.testRunStarted(TEST_NAME, 0);
-        reportRunFailures(runFailures, listener);
-        listener.testRunEnded(System.currentTimeMillis() - startTime, Collections.emptyMap());
-        listener.testModuleEnded();
-
-        addTestLogs(listener);
-        stats.addInvocationAttributes(testInfo.getContext());
-        cleanup();
-    }
-
-    private void initialize() throws IOException {
-        mRunTemporaryDirectory = Files.createTempDirectory(mTemporaryDirectory, "bazel-test-");
-        mBazelOutputRoot = createTemporaryDirectory("java-tmp-out");
-        mJavaTempOutput = createTemporaryDirectory("bazel-tmp-out");
-    }
-
-    private void logWorkspaceContents() throws IOException {
-        Path workspaceDirectory = resolveWorkspacePath();
-
-        try (Stream<String> files =
-                Files.walk(workspaceDirectory)
-                        .filter(Files::isRegularFile)
-                        .map(x -> workspaceDirectory.relativize(x).toString())) {
-
-            Path outputFile = createLogFile("workspace-contents");
-            try (FileWriter writer = new FileWriter(outputFile.toAbsolutePath().toString())) {
-                for (String file : (Iterable<String>) () -> files.iterator()) {
-                    writer.write(file);
-                    writer.write(System.lineSeparator());
-                }
-            }
-        }
-    }
-
-    private void runTestsAndParseResults(
-            TestInformation testInfo,
-            ITestInvocationListener listener,
-            List<FailureDescription> runFailures,
-            RunStats stats)
-            throws IOException, InterruptedException {
-
-        Path workspaceDirectory = resolveWorkspacePath();
-
-        BiMap<String, String> modulesToTargets = listTestModulesToTargets(workspaceDirectory);
-        if (modulesToTargets.isEmpty()) {
-            throw new AbortRunException(
-                    "No targets found, aborting",
-                    FailureStatus.DEPENDENCY_ISSUE,
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-
-        Path bepFile = createTemporaryFile("BEP_output");
-
-        Process bazelTestProcess =
-                startTests(testInfo, modulesToTargets.values(), workspaceDirectory, bepFile);
-
-        try (BepFileTailer tailer = BepFileTailer.create(bepFile)) {
-            bazelTestProcess.onExit().thenRun(() -> tailer.stop());
-            reportTestResults(listener, testInfo, runFailures, tailer, stats, modulesToTargets);
-        }
-
-        // Note that if Bazel exits without writing the 'last' BEP message marker we won't get to
-        // here since the above reporting code throws.
-        int bazelTestExitCode = bazelTestProcess.waitFor();
-
-        // TODO(b/296923373): If there is any parsing issue for a specific module consider reporting
-        // a generic module failure for that module.
-        if (bazelTestExitCode == BAZEL_TESTS_FAILED_RETURN_CODE) {
-            CLog.w("Bazel exited with exit code: %d, some tests failed.", bazelTestExitCode);
-            return;
-        }
-
-        if (bazelTestExitCode == 0) {
-            return;
-        }
-
-        throw new AbortRunException(
-                String.format("%s command failed. Exit code: %d", RUN_TESTS, bazelTestExitCode),
-                FailureStatus.DEPENDENCY_ISSUE,
-                TestErrorIdentifier.TEST_ABORTED);
-    }
-
-    void reportTestResults(
-            ITestInvocationListener listener,
-            TestInformation testInfo,
-            List<FailureDescription> runFailures,
-            BepFileTailer tailer,
-            RunStats stats,
-            BiMap<String, String> modulesToTargets)
-            throws InterruptedException, IOException {
-
-        try (CloseableTraceScope ignored = new CloseableTraceScope("reportTestResults")) {
-            reportTestResultsNoTrace(
-                    listener, testInfo, runFailures, tailer, stats, modulesToTargets);
-        }
-    }
-
-    void reportTestResultsNoTrace(
-            ITestInvocationListener listener,
-            TestInformation testInfo,
-            List<FailureDescription> runFailures,
-            BepFileTailer tailer,
-            RunStats stats,
-            BiMap<String, String> modulesToTargets)
-            throws InterruptedException, IOException {
-
-        BuildEventStreamProtos.BuildEvent event;
-        while ((event = tailer.nextEvent()) != null) {
-            if (event.getLastMessage()) {
-                return;
-            }
-
-            if (!event.hasTestResult()) {
-                continue;
-            }
-
-            stats.addTestResult(event.getTestResult());
-
-            if (!mReportCachedTestResults && isTestResultCached(event.getTestResult())) {
-                continue;
-            }
-
-            try {
-                reportEventsInTestOutputsArchive(
-                        event, listener, testInfo.getContext(), modulesToTargets);
-            } catch (IOException
-                    | InterruptedException
-                    | URISyntaxException
-                    | IllegalArgumentException e) {
-                runFailures.add(
-                        throwableToInfraFailureDescription(e)
-                                .setErrorIdentifier(TestErrorIdentifier.OUTPUT_PARSER_ERROR));
-            }
-        }
-
-        throw new AbortRunException(
-                "Unexpectedly hit end of BEP file without receiving last message",
-                FailureStatus.INFRA_FAILURE,
-                TestErrorIdentifier.OUTPUT_PARSER_ERROR);
-    }
-
-    private static boolean isTestResultCached(BuildEventStreamProtos.TestResult result) {
-        return result.getCachedLocally() || result.getExecutionInfo().getCachedRemotely();
-    }
-
-    private ProcessBuilder createBazelCommand(Path workspaceDirectory, String tmpDirPrefix)
-            throws IOException {
-
-        List<String> command = new ArrayList<>();
-
-        command.add(workspaceDirectory.resolve("bazel.sh").toAbsolutePath().toString());
-        command.add(
-                "--host_jvm_args=-Djava.io.tmpdir=%s"
-                        .formatted(mJavaTempOutput.toAbsolutePath().toString()));
-        command.add(
-                "--output_user_root=%s".formatted(mBazelOutputRoot.toAbsolutePath().toString()));
-        command.add("--max_idle_secs=%d".formatted(mBazelMaxIdleTimeout.toSeconds()));
-
-        ProcessBuilder builder = new ProcessBuilder(command);
-
-        builder.directory(workspaceDirectory.toFile());
-
-        return builder;
-    }
-
-    private BiMap<String, String> listTestModulesToTargets(Path workspaceDirectory)
-            throws IOException, InterruptedException {
-
-        try (CloseableTraceScope ignored = new CloseableTraceScope("listTestModulesToTargets")) {
-            return listTestModulesToTargetsNoTrace(workspaceDirectory);
-        }
-    }
-
-    private BiMap<String, String> listTestModulesToTargetsNoTrace(Path workspaceDirectory)
-            throws IOException, InterruptedException {
-
-        // We need to query all tests targets first in a separate Bazel query call since 'cquery
-        // tests(...)' doesn't work in the Atest Bazel workspace.
-        List<String> allTestTargets = queryAllTestTargets(workspaceDirectory);
-        CLog.i("Found %d test targets in workspace", allTestTargets.size());
-
-        BiMap<String, String> moduleToTarget =
-                queryModulesToTestTargets(workspaceDirectory, allTestTargets);
-
-        Set<String> moduleExcludes = groupTargetsByType(mExcludeTargets).get(FilterType.MODULE);
-        Set<String> moduleIncludes = groupTargetsByType(mIncludeTargets).get(FilterType.MODULE);
-
-        if (!moduleIncludes.isEmpty() && !moduleExcludes.isEmpty()) {
-            throw new AbortRunException(
-                    "Invalid options: cannot set both module-level include filters and module-level"
-                            + " exclude filters.",
-                    FailureStatus.DEPENDENCY_ISSUE,
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-
-        if (!moduleIncludes.isEmpty()) {
-            return Maps.filterKeys(moduleToTarget, s -> moduleIncludes.contains(s));
-        }
-
-        if (!moduleExcludes.isEmpty()) {
-            return Maps.filterKeys(moduleToTarget, s -> !moduleExcludes.contains(s));
-        }
-
-        return moduleToTarget;
-    }
-
-    private List<String> queryAllTestTargets(Path workspaceDirectory)
-            throws IOException, InterruptedException {
-
-        Path logFile = createLogFile("%s-log".formatted(QUERY_ALL_TARGETS));
-
-        ProcessBuilder builder = createBazelCommand(workspaceDirectory, QUERY_ALL_TARGETS);
-
-        builder.command().add("query");
-        builder.command().add(mBazelQuery);
-
-        builder.redirectError(Redirect.appendTo(logFile.toFile()));
-
-        Process queryProcess = startProcess(QUERY_ALL_TARGETS, builder, BAZEL_QUERY_TIMEOUT);
-        List<String> queryLines = readProcessLines(queryProcess);
-
-        waitForSuccessfulProcess(queryProcess, QUERY_ALL_TARGETS);
-
-        return queryLines;
-    }
-
-    private BiMap<String, String> queryModulesToTestTargets(
-            Path workspaceDirectory, List<String> allTestTargets)
-            throws IOException, InterruptedException {
-
-        Path cqueryTestTargetsFile = createTemporaryFile("test_targets");
-        Files.write(cqueryTestTargetsFile, String.join("+", allTestTargets).getBytes());
-
-        Path cqueryFormatFile = createTemporaryFile("format_module_name_to_test_target");
-        try (FileOutputStream os = new FileOutputStream(cqueryFormatFile.toFile())) {
-            Resources.copy(
-                    Resources.getResource("config/format_module_name_to_test_target.cquery"), os);
-        }
-
-        Path logFile = createLogFile("%s-log".formatted(QUERY_MAP_MODULES_TO_TARGETS));
-        ProcessBuilder builder =
-                createBazelCommand(workspaceDirectory, QUERY_MAP_MODULES_TO_TARGETS);
-
-        builder.command().add("cquery");
-        builder.command().add("--query_file=%s".formatted(cqueryTestTargetsFile.toAbsolutePath()));
-        builder.command().add("--output=starlark");
-        builder.command().add("--starlark:file=%s".formatted(cqueryFormatFile.toAbsolutePath()));
-        builder.redirectError(Redirect.appendTo(logFile.toFile()));
-
-        Process process = startProcess(QUERY_MAP_MODULES_TO_TARGETS, builder, BAZEL_QUERY_TIMEOUT);
-
-        List<String> queryLines = readProcessLines(process);
-
-        waitForSuccessfulProcess(process, QUERY_MAP_MODULES_TO_TARGETS);
-
-        return parseModulesToTargets(queryLines);
-    }
-
-    private List<String> readProcessLines(Process process) throws IOException {
-        return CharStreams.readLines(process.inputReader());
-    }
-
-    private BiMap<String, String> parseModulesToTargets(Collection<String> lines) {
-        BiMap<String, String> moduleToTarget = HashBiMap.create(lines.size());
-        StringBuilder errorMessage = new StringBuilder();
-        for (String line : lines) {
-            // Query output format is: "module_name //bazel/test:target" if a test target is a
-            // TF test, "" otherwise, so only count proper targets.
-            if (line.isEmpty()) {
-                continue;
-            }
-
-            String[] splitLine = line.split(" ");
-
-            if (splitLine.length != 2) {
-                throw new AbortRunException(
-                        String.format(
-                                "Unrecognized output from %s command: %s",
-                                QUERY_MAP_MODULES_TO_TARGETS, line),
-                        FailureStatus.DEPENDENCY_ISSUE,
-                        TestErrorIdentifier.TEST_ABORTED);
-            }
-
-            String moduleName = splitLine[0];
-            String targetName = splitLine[1];
-
-            String duplicateEntry;
-            if ((duplicateEntry = moduleToTarget.get(moduleName)) != null) {
-                errorMessage.append(
-                        "Multiple test targets found for module %s: %s, %s\n"
-                                .formatted(moduleName, duplicateEntry, targetName));
-                continue;
-            }
-
-            moduleToTarget.put(moduleName, targetName);
-        }
-
-        if (errorMessage.length() != 0) {
-            throw new AbortRunException(
-                    errorMessage.toString(),
-                    FailureStatus.DEPENDENCY_ISSUE,
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-        return ImmutableBiMap.copyOf(moduleToTarget);
-    }
-
-    private Process startTests(
-            TestInformation testInfo,
-            Collection<String> testTargets,
-            Path workspaceDirectory,
-            Path bepFile)
-            throws IOException {
-
-        Path logFile = createLogFile("%s-log".formatted(RUN_TESTS));
-        Path bazelTraceFile = createLogFile("bazel-trace", ".perfetto-trace", LogDataType.PERFETTO);
-
-        ProcessBuilder builder = createBazelCommand(workspaceDirectory, RUN_TESTS);
-
-        builder.command().addAll(mBazelStartupOptions);
-        builder.command().add("test");
-        builder.command().addAll(testTargets);
-
-        builder.command().add("--build_event_binary_file=%s".formatted(bepFile.toAbsolutePath()));
-
-        builder.command().add("--generate_json_trace_profile");
-        builder.command().add("--profile=%s".formatted(bazelTraceFile.toAbsolutePath().toString()));
-
-        builder.command().add("--test_arg=--test-tag=%s".formatted(TEST_TAG_TEST_ARG));
-        builder.command().add("--test_arg=--build-id=%s".formatted(BUILD_TEST_ARG));
-        builder.command().add("--test_arg=--branch=%s".formatted(BRANCH_TEST_ARG));
-
-        builder.command().addAll(mBazelTestExtraArgs);
-
-        Set<String> testFilters = groupTargetsByType(mExcludeTargets).get(FilterType.TEST_CASE);
-        for (String test : testFilters) {
-            builder.command().add(GLOBAL_EXCLUDE_FILTER_TEMPLATE.formatted(test));
-        }
-        builder.redirectErrorStream(true);
-        builder.redirectOutput(Redirect.appendTo(logFile.toFile()));
-
-        return startProcess(RUN_TESTS, builder, mBazelCommandTimeout);
-    }
-
-    private static SetMultimap<FilterType, String> groupTargetsByType(List<String> targets) {
-        Map<FilterType, List<String>> groupedMap =
-                targets.stream()
-                        .collect(
-                                Collectors.groupingBy(
-                                        s ->
-                                                s.contains(" ")
-                                                        ? FilterType.TEST_CASE
-                                                        : FilterType.MODULE));
-
-        SetMultimap<FilterType, String> groupedMultiMap = HashMultimap.create();
-        for (Entry<FilterType, List<String>> entry : groupedMap.entrySet()) {
-            groupedMultiMap.putAll(entry.getKey(), entry.getValue());
-        }
-
-        return groupedMultiMap;
-    }
-
-    private Process startAndWaitForSuccessfulProcess(
-            String processTag, ProcessBuilder builder, Duration processTimeout)
-            throws InterruptedException, IOException {
-
-        Process process = startProcess(processTag, builder, processTimeout);
-        waitForSuccessfulProcess(process, processTag);
-        return process;
-    }
-
-    private Process startProcess(String processTag, ProcessBuilder builder, Duration timeout)
-            throws IOException {
-
-        CLog.i("Running command for %s: %s", processTag, new ProcessDebugString(builder));
-        String traceTag = "Process:" + processTag;
-        Process process = mProcessStarter.start(processTag, builder);
-
-        // We wait for the process in a separate thread so that we can trace its execution time.
-        // Another alternative could be to start/stop tracing with explicit calls but these would
-        // have to be done on the same thread as required by the tracing facility.
-        mExecutor.submit(
-                () -> {
-                    try (CloseableTraceScope unused = new CloseableTraceScope(traceTag)) {
-                        if (waitForProcessUninterruptibly(process, timeout)) {
-                            return;
-                        }
-
-                        CLog.e("%s command timed out and is being destroyed", processTag);
-                        process.destroy();
-
-                        // Give the process a grace period to properly shut down before forcibly
-                        // terminating it. We _could_ deduct this time from the total timeout but
-                        // it's overkill.
-                        if (!waitForProcessUninterruptibly(process, Duration.ofSeconds(5))) {
-                            CLog.w(
-                                    "%s command did not terminate normally after the grace period"
-                                            + " and is being forcibly destroyed",
-                                    processTag);
-                            process.destroyForcibly();
-                        }
-
-                        // We wait for the process as it may take it some time to terminate and
-                        // otherwise skew the trace results.
-                        waitForProcessUninterruptibly(process);
-                        CLog.i("%s command timed out and was destroyed", processTag);
-                    }
-                });
-
-        return process;
-    }
-
-    private void waitForSuccessfulProcess(Process process, String processTag)
-            throws InterruptedException {
-
-        if (process.waitFor() == 0) {
-            return;
-        }
-
-        throw new AbortRunException(
-                String.format("%s command failed. Exit code: %d", processTag, process.exitValue()),
-                FailureStatus.DEPENDENCY_ISSUE,
-                TestErrorIdentifier.TEST_ABORTED);
-    }
-
-    private void reportEventsInTestOutputsArchive(
-            BuildEventStreamProtos.BuildEvent event,
-            ITestInvocationListener listener,
-            IInvocationContext context,
-            BiMap<String, String> modulesToTargets)
-            throws IOException, InvalidProtocolBufferException, InterruptedException,
-                    URISyntaxException {
-
-        try (CloseableTraceScope ignored =
-                new CloseableTraceScope("reportEventsInTestOutputsArchive")) {
-            reportEventsInTestOutputsArchiveNoTrace(event, listener, context, modulesToTargets);
-        }
-    }
-
-    private void reportEventsInTestOutputsArchiveNoTrace(
-            BuildEventStreamProtos.BuildEvent event,
-            ITestInvocationListener listener,
-            IInvocationContext context,
-            BiMap<String, String> modulesToTargets)
-            throws IOException, InvalidProtocolBufferException, InterruptedException,
-                    URISyntaxException {
-
-        BuildEventStreamProtos.TestResult result = event.getTestResult();
-        BuildEventStreamProtos.File outputsFile =
-                result.getTestActionOutputList().stream()
-                        .filter(file -> file.getName().equals(TEST_UNDECLARED_OUTPUTS_ARCHIVE_NAME))
-                        .findAny()
-                        .orElseThrow(() -> new IOException("No test output archive found"));
-
-        URI uri = new URI(outputsFile.getUri());
-
-        File zipFile = new File(uri.getPath());
-        Path outputFilesDir = Files.createTempDirectory(mRunTemporaryDirectory, "output_zip-");
-        Path delimiter = Paths.get(BRANCH_TEST_ARG, BUILD_TEST_ARG, TEST_TAG_TEST_ARG);
-        listener = new LogPathUpdatingListener(listener, delimiter, outputFilesDir);
-
-        try {
-            String filePrefix = "tf-test-process-";
-            ZipUtil.extractZip(new ZipFile(zipFile), outputFilesDir.toFile());
-
-            // Test timed out, report as failure and upload any test output found for debugging
-            if (result.getStatus() == BuildEventStreamProtos.TestStatus.TIMEOUT) {
-                reportTimedOutTestResults(event, outputFilesDir, modulesToTargets, listener);
-                return;
-            }
-
-            File protoResult = outputFilesDir.resolve(PROTO_RESULTS_FILE_NAME).toFile();
-            TestRecord record = TestRecordProtoUtil.readFromFile(protoResult);
-
-            if (mReportCachedModulesSparsely && isTestResultCached(result)) {
-                listener = new SparseTestListener(listener);
-            }
-
-            // Tradefed does not report the invocation trace to the proto result file so we have to
-            // explicitly re-add it here.
-            List<Consumer<ITestInvocationListener>> extraLogCalls = new ArrayList<>();
-            extraLogCalls.addAll(collectInvocationLogCalls(context, record, filePrefix));
-            extraLogCalls.addAll(collectTraceFileLogCalls(outputFilesDir, filePrefix));
-
-            BazelTestListener bazelListener =
-                    new BazelTestListener(listener, extraLogCalls, isTestResultCached(result));
-            parseResultsToListener(bazelListener, context, record, filePrefix);
-        } finally {
-            FileUtil.recursiveDelete(outputFilesDir.toFile());
-        }
-    }
-
-    private static void reportTimedOutTestResults(
-            BuildEventStreamProtos.BuildEvent event,
-            Path outputFilesDir,
-            BiMap<String, String> modulesToTargets,
-            ITestInvocationListener listener)
-            throws IOException {
-        String label = event.getId().getTestResult().getLabel();
-        String module = modulesToTargets.inverse().get("@" + label);
-
-        IInvocationContext moduleContext = new InvocationContext();
-        String abi = AbiUtils.getHostAbi().iterator().next();
-        moduleContext.addInvocationAttribute("module-id", abi + " " + module);
-        moduleContext.addInvocationAttribute("module-abi", abi);
-        moduleContext.addInvocationAttribute("module-name", module);
-        ConfigurationDescriptor descriptor = new ConfigurationDescriptor();
-        descriptor.addMetadata("module-name", module);
-        descriptor.setModuleName(module);
-        moduleContext.setConfigurationDescriptor(descriptor);
-
-        listener.testModuleStarted(moduleContext);
-        listener.testRunStarted(module, 0);
-        listener.testRunFailed(
-                FailureDescription.create(
-                                "Test timed out, results cannot be processed, but any outputs"
-                                        + " generated will be uploaded.",
-                                FailureStatus.TIMED_OUT)
-                        .setErrorIdentifier(TestErrorIdentifier.TEST_BINARY_TIMED_OUT));
-        listener.testRunEnded(0L, Collections.emptyMap());
-        uploadTestModuleOutputs(listener, outputFilesDir, module);
-        listener.testModuleEnded();
-    }
-
-    private static void uploadTestModuleOutputs(
-            ITestInvocationListener listener, Path outputFilesDir, String module)
-            throws IOException {
-        try (Stream<Path> testOutputs =
-                Files.walk(outputFilesDir).filter(x -> Files.isRegularFile(x))) {
-            testOutputs.forEach(
-                    testOutput -> {
-                        try (FileInputStreamSource source =
-                                new FileInputStreamSource(testOutput.toFile())) {
-                            listener.testLog(
-                                    module + "-" + testOutput.getFileName().toString(),
-                                    LogDataType.TEXT,
-                                    source);
-                        }
-                    });
-        }
-    }
-
-    private static List<Consumer<ITestInvocationListener>> collectInvocationLogCalls(
-            IInvocationContext context, TestRecord record, String filePrefix) {
-
-        InvocationLogCollector logCollector = new InvocationLogCollector();
-        parseResultsToListener(logCollector, context, record, filePrefix);
-        return logCollector.getLogCalls();
-    }
-
-    private static void parseResultsToListener(
-            ITestInvocationListener listener,
-            IInvocationContext context,
-            TestRecord record,
-            String filePrefix) {
-
-        ProtoResultParser parser = new ProtoResultParser(listener, context, false, filePrefix);
-        // Avoid merging serialized invocation attributes into the current invocation context.
-        // Not doing so adds misleading information on the top-level invocation
-        // such as bad timing data. See b/284294864.
-        parser.setMergeInvocationContext(false);
-        parser.processFinalizedProto(record);
-    }
-
-    private static List<Consumer<ITestInvocationListener>> collectTraceFileLogCalls(
-            Path outputFilesDir, String filePrefix) throws IOException {
-
-        List<Consumer<ITestInvocationListener>> logCalls = new ArrayList<>();
-
-        try (Stream<Path> traceFiles =
-                Files.walk(outputFilesDir)
-                        .filter(x -> MoreFiles.getFileExtension(x).equals("perfetto-trace"))) {
-
-            traceFiles.forEach(
-                    traceFile -> {
-                        logCalls.add(
-                                (ITestInvocationListener l) -> {
-                                    l.testLog(
-                                            filePrefix + traceFile.getFileName().toString(),
-                                            // We don't mark this file as a PERFETTO log to
-                                            // avoid having its contents automatically merged in
-                                            // the top-level invocation's trace. The merge
-                                            // process is wonky and makes the resulting trace
-                                            // difficult to read.
-                                            // TODO(b/284328869): Switch to PERFETTO log type
-                                            // once traces are properly merged.
-                                            LogDataType.TEXT,
-                                            new FileInputStreamSource(traceFile.toFile()));
-                                });
-                    });
-        }
-        return logCalls;
-    }
-
-    private void reportRunFailures(
-            List<FailureDescription> runFailures, ITestInvocationListener listener) {
-
-        if (runFailures.isEmpty()) {
-            return;
-        }
-
-        for (FailureDescription runFailure : runFailures) {
-            CLog.e(runFailure.getErrorMessage());
-        }
-
-        FailureDescription reportedFailure = runFailures.get(0);
-        listener.testRunFailed(
-                FailureDescription.create(
-                                String.format(
-                                        "The run had %d failures, the first of which was: %s\n"
-                                                + "See the subprocess-host_log for more details.",
-                                        runFailures.size(), reportedFailure.getErrorMessage()),
-                                reportedFailure.getFailureStatus())
-                        .setErrorIdentifier(reportedFailure.getErrorIdentifier()));
-    }
-
-    private Path resolveWorkspacePath() {
-        String suiteRootPath = mProperties.getProperty(mSuiteRootDirEnvVar);
-        if (suiteRootPath == null || suiteRootPath.isEmpty()) {
-            throw new AbortRunException(
-                    "Bazel Test Suite root directory not set, aborting",
-                    FailureStatus.DEPENDENCY_ISSUE,
-                    TestErrorIdentifier.TEST_ABORTED);
-        }
-
-        // TODO(b/233885171): Remove resolve once workspace archive is updated.
-        return Paths.get(suiteRootPath).resolve("android-bazel-suite/out/atest_bazel_workspace");
-    }
-
-    private void addTestLogs(ITestLogger logger) {
-        for (LogFileWithType logFile : mLogFiles) {
-            try (FileInputStreamSource source =
-                    new FileInputStreamSource(logFile.getPath().toFile(), true)) {
-                logger.testLog(logFile.getPath().toFile().getName(), logFile.getType(), source);
-            }
-        }
-    }
-
-    private void cleanup() {
-        FileUtil.recursiveDelete(mRunTemporaryDirectory.toFile());
-    }
-
-    interface ProcessStarter {
-        Process start(String processTag, ProcessBuilder builder) throws IOException;
-    }
-
-    private static final class DefaultProcessStarter implements ProcessStarter {
-        @Override
-        public Process start(String processTag, ProcessBuilder builder) throws IOException {
-            return builder.start();
-        }
-    }
-
-    private Path createTemporaryDirectory(String prefix) throws IOException {
-        return Files.createTempDirectory(mRunTemporaryDirectory, prefix);
-    }
-
-    private Path createTemporaryFile(String prefix) throws IOException {
-        return Files.createTempFile(mRunTemporaryDirectory, prefix, "");
-    }
-
-    private Path createLogFile(String name) throws IOException {
-        return createLogFile(name, ".txt", LogDataType.TEXT);
-    }
-
-    private Path createLogFile(String name, String extension, LogDataType type) throws IOException {
-        Path logPath = Files.createTempFile(mRunTemporaryDirectory, name, extension);
-
-        mLogFiles.add(new LogFileWithType(logPath, type));
-
-        return logPath;
-    }
-
-    private static FailureDescription throwableToTestFailureDescription(Throwable t) {
-        return FailureDescription.create(t.getMessage())
-                .setCause(t)
-                .setFailureStatus(FailureStatus.TEST_FAILURE);
-    }
-
-    private static FailureDescription throwableToInfraFailureDescription(Exception e) {
-        return FailureDescription.create(e.getMessage())
-                .setCause(e)
-                .setFailureStatus(FailureStatus.INFRA_FAILURE);
-    }
-
-    private static boolean waitForProcessUninterruptibly(Process process, Duration timeout) {
-        long remainingNanos = timeout.toNanos();
-        long end = System.nanoTime() + remainingNanos;
-        boolean interrupted = false;
-
-        try {
-            while (true) {
-                try {
-                    return process.waitFor(remainingNanos, TimeUnit.NANOSECONDS);
-                } catch (InterruptedException e) {
-                    interrupted = true;
-                    remainingNanos = end - System.nanoTime();
-                }
-            }
-        } finally {
-            if (interrupted) {
-                Thread.currentThread().interrupt();
-            }
-        }
-    }
-
-    private static int waitForProcessUninterruptibly(Process process) {
-        boolean interrupted = false;
-
-        try {
-            while (true) {
-                try {
-                    return process.waitFor();
-                } catch (InterruptedException e) {
-                    interrupted = true;
-                }
-            }
-        } finally {
-            if (interrupted) {
-                Thread.currentThread().interrupt();
-            }
-        }
-    }
-
-    private static final class AbortRunException extends RuntimeException {
-        private final FailureDescription mFailureDescription;
-
-        public AbortRunException(
-                String errorMessage, FailureStatus failureStatus, ErrorIdentifier errorIdentifier) {
-            this(
-                    FailureDescription.create(errorMessage, failureStatus)
-                            .setErrorIdentifier(errorIdentifier));
-        }
-
-        public AbortRunException(FailureDescription failureDescription) {
-            super(failureDescription.getErrorMessage());
-            mFailureDescription = failureDescription;
-        }
-
-        public FailureDescription getFailureDescription() {
-            return mFailureDescription;
-        }
-    }
-
-    private static final class ProcessDebugString {
-
-        private final ProcessBuilder mBuilder;
-
-        ProcessDebugString(ProcessBuilder builder) {
-            mBuilder = builder;
-        }
-
-        public String toString() {
-            return String.join(" ", mBuilder.command());
-        }
-    }
-
-    private static final class LogFileWithType {
-        private final Path mPath;
-        private final LogDataType mType;
-
-        public LogFileWithType(Path path, LogDataType type) {
-            mPath = path;
-            mType = type;
-        }
-
-        public Path getPath() {
-            return mPath;
-        }
-
-        public LogDataType getType() {
-            return mType;
-        }
-    }
-
-    private static final class RunStats {
-
-        private int mCachedTestResults;
-
-        void addTestResult(BuildEventStreamProtos.TestResult e) {
-            if (isTestResultCached(e)) {
-                mCachedTestResults++;
-            }
-        }
-
-        void addInvocationAttributes(IInvocationContext context) {
-            InvocationMetricLogger.addInvocationMetrics(
-                    InvocationMetricKey.CACHED_MODULE_RESULTS_COUNT,
-                    Integer.toString(mCachedTestResults));
-        }
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTestListener.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTestListener.java
deleted file mode 100644
index 38b378d2..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BazelTestListener.java
+++ /dev/null
@@ -1,103 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-
-import com.google.common.collect.ImmutableList;
-
-import java.util.List;
-import java.util.function.Consumer;
-
-/**
- * Listener implementation that handles BazelTest-specific result manipulation including reporting
- * all invocation logs as module logs and adding in extra log calls.
- */
-final class BazelTestListener extends ForwardingTestListener {
-
-    private final ITestInvocationListener mDelegate;
-    private final ImmutableList<Consumer<ITestInvocationListener>> mExtraModuleLogCalls;
-    private boolean mInModule;
-    private boolean mModuleCached;
-
-    public BazelTestListener(
-            ITestInvocationListener delegate,
-            List<Consumer<ITestInvocationListener>> extraModuleLogCalls,
-            boolean moduleCached) {
-
-        mDelegate = delegate;
-        mExtraModuleLogCalls = ImmutableList.copyOf(extraModuleLogCalls);
-        mModuleCached = moduleCached;
-    }
-
-    @Override
-    protected ITestInvocationListener delegate() {
-        return mDelegate;
-    }
-
-    @Override
-    public void testLog(String dataName, LogDataType dataType, InputStreamSource dataStream) {
-        if (!mInModule) {
-            return;
-        }
-        delegate().testLog(dataName, dataType, dataStream);
-    }
-
-    @Override
-    public void testLogSaved(
-            String dataName, LogDataType dataType, InputStreamSource dataStream, LogFile logFile) {
-
-        if (!mInModule) {
-            return;
-        }
-        TestListeners.testLogSaved(delegate(), dataName, dataType, dataStream, logFile);
-    }
-
-    @Override
-    public void logAssociation(String dataName, LogFile logFile) {
-        if (!mInModule) {
-            return;
-        }
-        TestListeners.logAssociation(delegate(), dataName, logFile);
-    }
-
-    @Override
-    public void testModuleStarted(IInvocationContext moduleContext) {
-        mInModule = true;
-        if (mModuleCached) {
-            moduleContext.addInvocationAttribute("module-cached", "true");
-        }
-        delegate().testModuleStarted(moduleContext);
-    }
-
-    @Override
-    public void testModuleEnded() {
-        mInModule = false;
-        replayExtraModuleLogCalls();
-        delegate().testModuleEnded();
-    }
-
-    private void replayExtraModuleLogCalls() {
-        for (Consumer<ITestInvocationListener> c : mExtraModuleLogCalls) {
-            c.accept(delegate());
-        }
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BepFileTailer.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BepFileTailer.java
deleted file mode 100644
index 96c12fcd..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/BepFileTailer.java
+++ /dev/null
@@ -1,79 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.google.devtools.build.lib.buildeventstream.BuildEventStreamProtos.BuildEvent;
-import com.google.protobuf.InvalidProtocolBufferException;
-
-import java.io.BufferedInputStream;
-import java.io.FileInputStream;
-import java.io.FileNotFoundException;
-import java.io.IOException;
-import java.nio.file.Path;
-import java.time.Duration;
-
-final class BepFileTailer implements AutoCloseable {
-    private static final Duration BEP_PARSE_SLEEP_TIME = Duration.ofMillis(100);
-
-    private final BufferedInputStream mIn;
-    private volatile boolean mStop;
-
-    static BepFileTailer create(Path bepFile) throws FileNotFoundException {
-        return new BepFileTailer(new BufferedInputStream(new FileInputStream(bepFile.toFile())));
-    }
-
-    private BepFileTailer(BufferedInputStream In) {
-        mIn = In;
-        mStop = false;
-    }
-
-    public BuildEvent nextEvent() throws InterruptedException, IOException {
-        while (true) {
-            boolean stop = mStop;
-
-            // Mark the current position in the input stream.
-            mIn.mark(Integer.MAX_VALUE);
-
-            try {
-                BuildEvent event = BuildEvent.parseDelimitedFrom(mIn);
-
-                // When event is null and we hit EOF, wait for an event to be written and try again.
-                if (event != null) {
-                    return event;
-                }
-                if (stop) {
-                    return null;
-                }
-            } catch (InvalidProtocolBufferException e) {
-                if (stop) {
-                    throw e;
-                }
-                // Partial read. Restore the old position in the input stream.
-                mIn.reset();
-            }
-            Thread.sleep(BEP_PARSE_SLEEP_TIME.toMillis());
-        }
-    }
-
-    @Override
-    public void close() throws IOException {
-        mIn.close();
-    }
-
-    public void stop() {
-        mStop = true;
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/ForwardingTestListener.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/ForwardingTestListener.java
deleted file mode 100644
index 7e06122a..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/ForwardingTestListener.java
+++ /dev/null
@@ -1,206 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.FailureDescription;
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.ILogSaver;
-import com.android.tradefed.result.ILogSaverListener;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-import com.android.tradefed.result.TestDescription;
-import com.android.tradefed.result.TestSummary;
-import com.android.tradefed.result.retry.ISupportGranularResults;
-
-import java.util.HashMap;
-import java.util.Map;
-
-/**
- * Abstract Forwarding Listener class which will forward all listener calls to a given delegate
- * listener.
- */
-abstract class ForwardingTestListener implements ILogSaverListener, ISupportGranularResults {
-
-    protected ForwardingTestListener() {}
-
-    protected abstract ITestInvocationListener delegate();
-
-    @Override
-    public void testLog(String dataName, LogDataType dataType, InputStreamSource dataStream) {
-        delegate().testLog(dataName, dataType, dataStream);
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount) {
-        delegate().testRunStarted(runName, testCount);
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount, int attemptNumber) {
-        delegate().testRunStarted(runName, testCount, attemptNumber);
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount, int attemptNumber, long startTime) {
-        delegate().testRunStarted(runName, testCount, attemptNumber, startTime);
-    }
-
-    @Override
-    public void testRunFailed(String errorMessage) {
-        delegate().testRunFailed(errorMessage);
-    }
-
-    @Override
-    public void testRunFailed(FailureDescription failure) {
-        delegate().testRunFailed(failure);
-    }
-
-    @Override
-    public void testRunEnded(long elapsedTimeMillis, Map<String, String> runMetrics) {
-        delegate().testRunEnded(elapsedTimeMillis, runMetrics);
-    }
-
-    @Override
-    public void testRunEnded(long elapsedTimeMillis, HashMap<String, Metric> runMetrics) {
-        delegate().testRunEnded(elapsedTimeMillis, runMetrics);
-    }
-
-    @Override
-    public void testRunStopped(long elapsedTime) {
-        delegate().testRunStopped(elapsedTime);
-    }
-
-    @Override
-    public void testStarted(TestDescription test) {
-        delegate().testStarted(test);
-    }
-
-    @Override
-    public void testStarted(TestDescription test, long startTime) {
-        delegate().testStarted(test, startTime);
-    }
-
-    @Override
-    public void testFailed(TestDescription test, String trace) {
-        delegate().testFailed(test, trace);
-    }
-
-    @Override
-    public void testFailed(TestDescription test, FailureDescription failure) {
-        delegate().testFailed(test, failure);
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, String trace) {
-        delegate().testAssumptionFailure(test, trace);
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, FailureDescription failure) {
-        delegate().testAssumptionFailure(test, failure);
-    }
-
-    @Override
-    public void testIgnored(TestDescription test) {
-        delegate().testIgnored(test);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, Map<String, String> testMetrics) {
-        delegate().testEnded(test, testMetrics);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, HashMap<String, Metric> testMetrics) {
-        delegate().testEnded(test, testMetrics);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, long endTime, Map<String, String> testMetrics) {
-        delegate().testEnded(test, endTime, testMetrics);
-    }
-
-    @Override
-    public void testEnded(TestDescription test, long endTime, HashMap<String, Metric> testMetrics) {
-        delegate().testEnded(test, endTime, testMetrics);
-    }
-
-    @Override
-    public void invocationStarted(IInvocationContext context) {
-        delegate().invocationStarted(context);
-    }
-
-    @Override
-    public void invocationEnded(long elapsedTime) {
-        delegate().invocationEnded(elapsedTime);
-    }
-
-    @Override
-    public void invocationFailed(Throwable cause) {
-        delegate().invocationFailed(cause);
-    }
-
-    @Override
-    public void invocationFailed(FailureDescription failure) {
-        delegate().invocationFailed(failure);
-    }
-
-    @Override
-    public TestSummary getSummary() {
-        return delegate().getSummary();
-    }
-
-    @Override
-    public void invocationInterrupted() {
-        delegate().invocationInterrupted();
-    }
-
-    @Override
-    public void testModuleStarted(IInvocationContext moduleContext) {
-        delegate().testModuleStarted(moduleContext);
-    }
-
-    @Override
-    public void testModuleEnded() {
-        delegate().testModuleEnded();
-    }
-
-    @Override
-    public void testLogSaved(
-            String dataName, LogDataType dataType, InputStreamSource dataStream, LogFile logFile) {
-
-        TestListeners.testLogSaved(delegate(), dataName, dataType, dataStream, logFile);
-    }
-
-    @Override
-    public void logAssociation(String dataName, LogFile logFile) {
-        TestListeners.logAssociation(delegate(), dataName, logFile);
-    }
-
-    @Override
-    public void setLogSaver(ILogSaver logSaver) {
-        TestListeners.setLogSaver(delegate(), logSaver);
-    }
-
-    @Override
-    public boolean supportGranularResults() {
-        return TestListeners.supportGranularResults(delegate());
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/InvocationLogCollector.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/InvocationLogCollector.java
deleted file mode 100644
index aca85f23..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/InvocationLogCollector.java
+++ /dev/null
@@ -1,87 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-
-import java.util.ArrayList;
-import java.util.List;
-import java.util.function.Consumer;
-
-/** Listener which collects all invocation-level test logs. */
-final class InvocationLogCollector extends NullTestListener {
-
-    private final List<Consumer<ITestInvocationListener>> mLogCalls;
-    private boolean mInModule;
-
-    InvocationLogCollector() {
-        mLogCalls = new ArrayList<>();
-    }
-
-    public List<Consumer<ITestInvocationListener>> getLogCalls() {
-        return mLogCalls;
-    }
-
-    @Override
-    public void testLog(String dataName, LogDataType dataType, InputStreamSource dataStream) {
-        if (mInModule) {
-            return;
-        }
-        mLogCalls.add(
-                (ITestInvocationListener l) -> {
-                    l.testLog(dataName, dataType, dataStream);
-                });
-    }
-
-    @Override
-    public void testModuleStarted(IInvocationContext moduleContext) {
-        mInModule = true;
-    }
-
-    @Override
-    public void testModuleEnded() {
-        mInModule = false;
-    }
-
-    @Override
-    public void testLogSaved(
-            String dataName, LogDataType dataType, InputStreamSource dataStream, LogFile logFile) {
-
-        if (mInModule) {
-            return;
-        }
-        mLogCalls.add(
-                (ITestInvocationListener l) -> {
-                    TestListeners.testLogSaved(l, dataName, dataType, dataStream, logFile);
-                });
-    }
-
-    @Override
-    public void logAssociation(String dataName, LogFile logFile) {
-        if (mInModule) {
-            return;
-        }
-        mLogCalls.add(
-                (ITestInvocationListener l) -> {
-                    TestListeners.logAssociation(l, dataName, logFile);
-                });
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/LogPathUpdatingListener.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/LogPathUpdatingListener.java
deleted file mode 100644
index da6f68d2..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/LogPathUpdatingListener.java
+++ /dev/null
@@ -1,96 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.FileInputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-
-import java.io.File;
-import java.nio.file.Path;
-import java.nio.file.Paths;
-
-/**
- * Listener implementation that will find log files that have been saved to a new location using the
- * given root and delimiter.
- *
- * <p>Changes all log calls to testLog() to pass the file contents directly since original files may
- * have been deleted by the time they are read with the other calls.
- */
-final class LogPathUpdatingListener extends ForwardingTestListener {
-
-    private final ITestInvocationListener mDelegate;
-    private final Path mDelimiter;
-    private final Path mNewRoot;
-
-    public LogPathUpdatingListener(ITestInvocationListener delegate, Path delimiter, Path newRoot) {
-        mDelegate = delegate;
-        mDelimiter = delimiter;
-        mNewRoot = newRoot;
-    }
-
-    @Override
-    protected ITestInvocationListener delegate() {
-        return mDelegate;
-    }
-
-    @Override
-    public void testLogSaved(
-            String dataName, LogDataType dataType, InputStreamSource dataStream, LogFile logFile) {
-
-        // Call testLog() instead to pass file contents directly instead of a reference to a File
-        // which may be deleted before it's read.
-        delegate().testLog(dataName, logFile.getType(), dataStream);
-    }
-
-    @Override
-    public void logAssociation(String dataName, LogFile logFile) {
-        // Call testLog() instead to pass file contents directly instead of a reference to a File
-        // which may be deleted before it's read.
-        delegate()
-                .testLog(
-                        dataName,
-                        logFile.getType(),
-                        new FileInputStreamSource(
-                                new File(findNewArtifactPath(Paths.get(logFile.getPath())))));
-    }
-
-    private String findNewArtifactPath(Path originalPath) {
-        // The log files are stored under
-        // (newRoot)/(delimiter)/inv_xxx/inv_xxx/artifact so the new path is
-        // found by trimming down the original path until it starts with (delimiter) and
-        // appending that to our new root.
-
-        Path relativePath = originalPath;
-        while (!relativePath.startsWith(mDelimiter)
-                && relativePath.getNameCount() > mDelimiter.getNameCount()) {
-            relativePath = relativePath.subpath(1, relativePath.getNameCount());
-        }
-
-        if (!relativePath.startsWith(mDelimiter)) {
-            throw new IllegalArgumentException(
-                    String.format(
-                            "Artifact path '%s' does not contain delimiter '%s' and therefore"
-                                    + " cannot be found",
-                            originalPath, mDelimiter));
-        }
-
-        return mNewRoot.resolve(relativePath).toAbsolutePath().toString();
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/NullTestListener.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/NullTestListener.java
deleted file mode 100644
index e079186c..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/NullTestListener.java
+++ /dev/null
@@ -1,193 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.FailureDescription;
-import com.android.tradefed.result.ILogSaver;
-import com.android.tradefed.result.ILogSaverListener;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-import com.android.tradefed.result.TestDescription;
-import com.android.tradefed.result.TestSummary;
-
-import java.util.HashMap;
-import java.util.Map;
-
-/** Null test listener. */
-abstract class NullTestListener implements ILogSaverListener {
-
-    protected NullTestListener() {}
-
-    @Override
-    public void testLog(String dataName, LogDataType dataType, InputStreamSource dataStream) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount, int attemptNumber) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunStarted(String runName, int testCount, int attemptNumber, long startTime) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunFailed(String errorMessage) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunFailed(FailureDescription failure) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunEnded(long elapsedTimeMillis, Map<String, String> runMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunEnded(long elapsedTimeMillis, HashMap<String, Metric> runMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testRunStopped(long elapsedTime) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testStarted(TestDescription test) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testStarted(TestDescription test, long startTime) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testFailed(TestDescription test, String trace) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testFailed(TestDescription test, FailureDescription failure) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, String trace) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testAssumptionFailure(TestDescription test, FailureDescription failure) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testIgnored(TestDescription test) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testEnded(TestDescription test, Map<String, String> testMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testEnded(TestDescription test, HashMap<String, Metric> testMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testEnded(TestDescription test, long endTime, Map<String, String> testMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testEnded(TestDescription test, long endTime, HashMap<String, Metric> testMetrics) {
-        // Does nothing.
-    }
-
-    @Override
-    public void invocationStarted(IInvocationContext context) {
-        // Does nothing.
-    }
-
-    @Override
-    public void invocationEnded(long elapsedTime) {
-        // Does nothing.
-    }
-
-    @Override
-    public void invocationFailed(Throwable cause) {
-        // Does nothing.
-    }
-
-    @Override
-    public void invocationFailed(FailureDescription failure) {
-        // Does nothing.
-    }
-
-    @Override
-    public TestSummary getSummary() {
-        return null;
-    }
-
-    @Override
-    public void invocationInterrupted() {
-        // Does nothing.
-    }
-
-    @Override
-    public void testModuleStarted(IInvocationContext moduleContext) {
-        // Does nothing.
-    }
-
-    @Override
-    public void testModuleEnded() {
-        // Does nothing.
-    }
-
-    @Override
-    public void testLogSaved(
-            String dataName, LogDataType dataType, InputStreamSource dataStream, LogFile logFile) {
-        // Does nothing.
-    }
-
-    @Override
-    public void logAssociation(String dataName, LogFile logFile) {
-        // Does nothing.
-    }
-
-    @Override
-    public void setLogSaver(ILogSaver logSaver) {
-        // Does nothing.
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/SparseTestListener.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/SparseTestListener.java
deleted file mode 100644
index bfec0380..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/SparseTestListener.java
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.result.ITestInvocationListener;
-
-/** Listener for cached tests that only reports module level events. */
-final class SparseTestListener extends NullTestListener {
-
-    private final ITestInvocationListener mDelegate;
-
-    public SparseTestListener(ITestInvocationListener delegate) {
-        mDelegate = delegate;
-    }
-
-    private ITestInvocationListener delegate() {
-        return mDelegate;
-    }
-
-    @Override
-    public void testModuleStarted(IInvocationContext moduleContext) {
-        moduleContext.addInvocationAttribute("sparse-module", "true");
-        delegate().testModuleStarted(moduleContext);
-    }
-
-    @Override
-    public void testModuleEnded() {
-        delegate().testModuleEnded();
-    }
-}
diff --git a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/TestListeners.java b/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/TestListeners.java
deleted file mode 100644
index 3d7666b1..00000000
--- a/atest/bazel/runner/src/com/android/tradefed/testtype/bazel/TestListeners.java
+++ /dev/null
@@ -1,69 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import com.android.tradefed.result.ILogSaver;
-import com.android.tradefed.result.ILogSaverListener;
-import com.android.tradefed.result.ITestInvocationListener;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-import com.android.tradefed.result.retry.ISupportGranularResults;
-
-/** Utility class for ITestInvocationListener related functionality. */
-final class TestListeners {
-
-    private TestListeners() {}
-
-    static void testLogSaved(
-            ITestInvocationListener listener,
-            String dataName,
-            LogDataType dataType,
-            InputStreamSource dataStream,
-            LogFile logFile) {
-
-        if (!(listener instanceof ILogSaverListener)) {
-            return;
-        }
-
-        ((ILogSaverListener) listener).testLogSaved(dataName, dataType, dataStream, logFile);
-    }
-
-    static void logAssociation(ITestInvocationListener listener, String dataName, LogFile logFile) {
-        if (!(listener instanceof ILogSaverListener)) {
-            return;
-        }
-
-        ((ILogSaverListener) listener).logAssociation(dataName, logFile);
-    }
-
-    static void setLogSaver(ITestInvocationListener listener, ILogSaver logSaver) {
-        if (!(listener instanceof ILogSaverListener)) {
-            return;
-        }
-
-        ((ILogSaverListener) listener).setLogSaver(logSaver);
-    }
-
-    static boolean supportGranularResults(ITestInvocationListener listener) {
-        if (!(listener instanceof ISupportGranularResults)) {
-            return false;
-        }
-
-        return ((ISupportGranularResults) listener).supportGranularResults();
-    }
-}
diff --git a/atest/bazel/runner/src/main/protobuf/build_event_stream.proto b/atest/bazel/runner/src/main/protobuf/build_event_stream.proto
deleted file mode 100644
index 98664146..00000000
--- a/atest/bazel/runner/src/main/protobuf/build_event_stream.proto
+++ /dev/null
@@ -1,1178 +0,0 @@
-// Copyright 2016 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-syntax = "proto3";
-
-package build_event_stream;
-
-import "google/protobuf/duration.proto";
-import "google/protobuf/timestamp.proto";
-import "src/main/protobuf/command_line.proto";
-import "src/main/protobuf/failure_details.proto";
-import "src/main/protobuf/invocation_policy.proto";
-
-option java_package = "com.google.devtools.build.lib.buildeventstream";
-option java_outer_classname = "BuildEventStreamProtos";
-
-// Identifier for a build event. It is deliberately structured to also provide
-// information about which build target etc the event is related to.
-//
-// Events are chained via the event id as follows: each event has an id and a
-// set of ids of children events such that apart from the initial event each
-// event has an id that is mentioned as child id in an earlier event and a build
-// invocation is complete if and only if all direct and indirect children of the
-// initial event have been posted.
-message BuildEventId {
-  // Generic identifier for a build event. This is the default type of
-  // BuildEventId, but should not be used outside testing; nevertheless,
-  // tools should handle build events with this kind of id gracefully.
-  message UnknownBuildEventId {
-    string details = 1;
-  }
-
-  // Identifier of an event reporting progress. Those events are also used to
-  // chain in events that come early.
-  message ProgressId {
-    // Unique identifier. No assumption should be made about how the ids are
-    // assigned; the only meaningful operation on this field is test for
-    // equality.
-    int32 opaque_count = 1;
-  }
-
-  // Identifier of an event indicating the beginning of a build; this will
-  // normally be the first event.
-  message BuildStartedId {}
-
-  // Identifier on an event indicating the original commandline received by
-  // the bazel server.
-  message UnstructuredCommandLineId {}
-
-  // Identifier on an event describing the commandline received by Bazel.
-  message StructuredCommandLineId {
-    // A title for this command line value, as there may be multiple.
-    // For example, a single invocation may wish to report both the literal and
-    // canonical command lines, and this label would be used to differentiate
-    // between both versions.
-    string command_line_label = 1;
-  }
-
-  // Identifier of an event indicating the workspace status.
-  message WorkspaceStatusId {}
-
-  // Identifier on an event reporting on the options included in the command
-  // line, both explicitly and implicitly.
-  message OptionsParsedId {}
-
-  // Identifier of an event reporting that an external resource was fetched
-  // from.
-  message FetchId {
-    // The external resource that was fetched from.
-    string url = 1;
-  }
-
-  // Identifier of an event indicating that a target pattern has been expanded
-  // further.
-  // Messages of this shape are also used to describe parts of a pattern that
-  // have been skipped for some reason, if the actual expansion was still
-  // carried out (e.g., if keep_going is set). In this case, the
-  // pattern_skipped choice in the id field is to be made.
-  message PatternExpandedId {
-    repeated string pattern = 1;
-  }
-
-  message WorkspaceConfigId {}
-
-  message BuildMetadataId {}
-
-  // Identifier of an event indicating that a target has been expanded by
-  // identifying for which configurations it should be build.
-  message TargetConfiguredId {
-    string label = 1;
-
-    // If empty, the id refers to the expansion of the target. If not-empty,
-    // the id refers to the expansion of an aspect applied to the (already
-    // expanded) target.
-    //
-    // For example, when building an apple_binary that depends on proto_library
-    // "//:foo_proto", there will be two TargetConfigured events for
-    // "//:foo_proto":
-    //
-    // 1. An event with an empty aspect, corresponding to actions producing
-    // language-agnostic outputs from the proto_library; and
-    // 2. An event with aspect "ObjcProtoAspect", corresponding to Objective-C
-    // code generation.
-    string aspect = 2;
-  }
-
-  // Identifier of an event introducing a named set of files (usually artifacts)
-  // to be referred to in later messages.
-  message NamedSetOfFilesId {
-    // Identifier of the file set; this is an opaque string valid only for the
-    // particular instance of the event stream.
-    string id = 1;
-  }
-
-  // Identifier of an event introducing a configuration.
-  message ConfigurationId {
-    // Identifier of the configuration; users of the protocol should not make
-    // any assumptions about it having any structure, or equality of the
-    // identifier between different streams.
-    string id = 1;
-  }
-
-  // Identifier of an event indicating that a target was built completely; this
-  // does not include running the test if the target is a test target.
-  message TargetCompletedId {
-    string label = 1;
-
-    // The configuration for which the target was built.
-    ConfigurationId configuration = 3;
-
-    // If empty, the id refers to the completion of the target. If not-empty,
-    // the id refers to the completion of an aspect applied to the (already
-    // completed) target.
-    //
-    // For example, when building an apple_binary that depends on proto_library
-    // "//:foo_proto", there will be two TargetCompleted events for
-    // "//:foo_proto":
-    //
-    // 1. An event with an empty aspect, corresponding to actions producing
-    // language-agnostic outputs from the proto_library; and
-    // 2. An event with aspect "ObjcProtoAspect", corresponding to Objective-C
-    // code generation.
-    string aspect = 2;
-  }
-
-  // Identifier of an event reporting that an action was completed (not all
-  // actions are reported, only the ones that can be considered important;
-  // this includes all failed actions).
-  message ActionCompletedId {
-    string primary_output = 1;
-    // Optional, the label of the owner of the action, for reference.
-    string label = 2;
-    // Optional, the id of the configuration of the action owner.
-    ConfigurationId configuration = 3;
-  }
-
-  // Identifier of an event reporting an event associated with an unconfigured
-  // label. Usually, this indicates a failure due to a missing input file. In
-  // any case, it will report some form of error (i.e., the payload will be an
-  // Aborted event); there are no regular events using this identifier. The
-  // purpose of those events is to serve as the root cause of a failed target.
-  message UnconfiguredLabelId {
-    string label = 1;
-  }
-
-  // Identifier of an event reporting an event associated with a configured
-  // label, usually a visibility error. In any case, an event with such an
-  // id will always report some form of error (i.e., the payload will be an
-  // Aborted event); there are no regular events using this identifier.
-  message ConfiguredLabelId {
-    string label = 1;
-    ConfigurationId configuration = 2;
-  }
-
-  // Identifier of an event reporting on an individual test run. The label
-  // identifies the test that is reported about, the remaining fields are
-  // in such a way as to uniquely identify the action within a build. In fact,
-  // attempts for the same test, run, shard triple are counted sequentially,
-  // starting with 1.
-  message TestResultId {
-    string label = 1;
-    ConfigurationId configuration = 5;
-    int32 run = 2;
-    int32 shard = 3;
-    int32 attempt = 4;
-  }
-
-  // Identifier of an event reporting the summary of a test.
-  message TestSummaryId {
-    string label = 1;
-    ConfigurationId configuration = 2;
-  }
-
-  // Identifier of an event reporting the summary of a target.
-  message TargetSummaryId {
-    string label = 1;
-    ConfigurationId configuration = 2;
-  }
-
-  // Identifier of the BuildFinished event, indicating the end of a build.
-  message BuildFinishedId {}
-
-  // Identifier of an event providing additional logs/statistics after
-  // completion of the build.
-  message BuildToolLogsId {}
-
-  // Identifier of an event providing build metrics after completion
-  // of the build.
-  message BuildMetricsId {}
-
-  // Identifier of an event providing convenience symlinks information.
-  message ConvenienceSymlinksIdentifiedId {}
-
-  oneof id {
-    UnknownBuildEventId unknown = 1;
-    ProgressId progress = 2;
-    BuildStartedId started = 3;
-    UnstructuredCommandLineId unstructured_command_line = 11;
-    StructuredCommandLineId structured_command_line = 18;
-    WorkspaceStatusId workspace_status = 14;
-    OptionsParsedId options_parsed = 12;
-    FetchId fetch = 17;
-    ConfigurationId configuration = 15;
-    TargetConfiguredId target_configured = 16;
-    PatternExpandedId pattern = 4;
-    PatternExpandedId pattern_skipped = 10;
-    NamedSetOfFilesId named_set = 13;
-    TargetCompletedId target_completed = 5;
-    ActionCompletedId action_completed = 6;
-    UnconfiguredLabelId unconfigured_label = 19;
-    ConfiguredLabelId configured_label = 21;
-    TestResultId test_result = 8;
-    TestSummaryId test_summary = 7;
-    TargetSummaryId target_summary = 26;
-    BuildFinishedId build_finished = 9;
-    BuildToolLogsId build_tool_logs = 20;
-    BuildMetricsId build_metrics = 22;
-    WorkspaceConfigId workspace = 23;
-    BuildMetadataId build_metadata = 24;
-    ConvenienceSymlinksIdentifiedId convenience_symlinks_identified = 25;
-  }
-}
-
-// Payload of an event summarizing the progress of the build so far. Those
-// events are also used to be parents of events where the more logical parent
-// event cannot be posted yet as the needed information is not yet complete.
-message Progress {
-  // The next chunk of stdout that bazel produced since the last progress event
-  // or the beginning of the build.
-  string stdout = 1;
-
-  // The next chunk of stderr that bazel produced since the last progress event
-  // or the beginning of the build.
-  string stderr = 2;
-}
-
-// Payload of an event indicating that an expected event will not come, as
-// the build is aborted prematurely for some reason.
-message Aborted {
-  enum AbortReason {
-    UNKNOWN = 0;
-
-    // The user requested the build to be aborted (e.g., by hitting Ctl-C).
-    USER_INTERRUPTED = 1;
-
-    // The user requested that no analysis be performed.
-    NO_ANALYZE = 8;
-
-    // The user requested that no build be carried out.
-    NO_BUILD = 9;
-
-    // The build or target was aborted as a timeout was exceeded.
-    TIME_OUT = 2;
-
-    // The build or target was aborted as some remote environment (e.g., for
-    // remote execution of actions) was not available in the expected way.
-    REMOTE_ENVIRONMENT_FAILURE = 3;
-
-    // Failure due to reasons entirely internal to the build tool, i.e. an
-    // unexpected crash due to programmer error.
-    INTERNAL = 4;
-
-    // A Failure occurred in the loading phase of a target.
-    LOADING_FAILURE = 5;
-
-    // A Failure occurred in the analysis phase of a target.
-    ANALYSIS_FAILURE = 6;
-
-    // Target build was skipped (e.g. due to incompatible CPU constraints).
-    SKIPPED = 7;
-
-    // Build incomplete due to an earlier build failure (e.g. --keep_going was
-    // set to false causing the build be ended upon failure).
-    INCOMPLETE = 10;
-
-    // The build tool ran out of memory and crashed.
-    OUT_OF_MEMORY = 11;
-  }
-  AbortReason reason = 1;
-
-  // A human readable description with more details about there reason, where
-  // available and useful.
-  string description = 2;
-}
-
-// Payload of an event indicating the beginning of a new build. Usually, events
-// of those type start a new build-event stream. The target pattern requested
-// to be build is contained in one of the announced child events; it is an
-// invariant that precisely one of the announced child events has a non-empty
-// target pattern.
-message BuildStarted {
-  string uuid = 1;
-
-  // Start of the build in ms since the epoch.
-  //
-  // Deprecated, use `start_time` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 start_time_millis = 2 [deprecated = true];
-
-  // Start of the build.
-  google.protobuf.Timestamp start_time = 9;
-
-  // Version of the build tool that is running.
-  string build_tool_version = 3;
-
-  // A human-readable description of all the non-default option settings
-  string options_description = 4;
-
-  // The name of the command that the user invoked.
-  string command = 5;
-
-  // The working directory from which the build tool was invoked.
-  string working_directory = 6;
-
-  // The directory of the workspace.
-  string workspace_directory = 7;
-
-  // The process ID of the Bazel server.
-  int64 server_pid = 8;
-}
-
-// Configuration related to the blaze workspace and output tree.
-message WorkspaceConfig {
-  // The root of the local blaze exec root. All output files live underneath
-  // this at "blaze-out/".
-  string local_exec_root = 1;
-}
-
-// Payload of an event reporting the command-line of the invocation as
-// originally received by the server. Note that this is not the command-line
-// given by the user, as the client adds information about the invocation,
-// like name and relevant entries of rc-files and client environment variables.
-// However, it does contain enough information to reproduce the build
-// invocation.
-message UnstructuredCommandLine {
-  repeated string args = 1;
-}
-
-// Payload of an event reporting on the parsed options, grouped in various ways.
-message OptionsParsed {
-  repeated string startup_options = 1;
-  repeated string explicit_startup_options = 2;
-  repeated string cmd_line = 3;
-  repeated string explicit_cmd_line = 4;
-  blaze.invocation_policy.InvocationPolicy invocation_policy = 5;
-  string tool_tag = 6;
-}
-
-// Payload of an event indicating that an external resource was fetched. This
-// event will only occur in streams where an actual fetch happened, not in ones
-// where a cached copy of the entity to be fetched was used.
-message Fetch {
-  bool success = 1;
-}
-
-// Payload of an event reporting the workspace status. Key-value pairs can be
-// provided by specifying the workspace_status_command to an executable that
-// returns one key-value pair per line of output (key and value separated by a
-// space).
-message WorkspaceStatus {
-  message Item {
-    string key = 1;
-    string value = 2;
-  }
-  repeated Item item = 1;
-}
-
-// Payload of an event reporting custom key-value metadata associated with the
-// build.
-message BuildMetadata {
-  // Custom metadata for the build.
-  map<string, string> metadata = 1;
-}
-
-// Payload of an event reporting details of a given configuration.
-message Configuration {
-  string mnemonic = 1;
-  string platform_name = 2;
-  string cpu = 3;
-  map<string, string> make_variable = 4;
-  // Whether this configuration is used for building tools.
-  bool is_tool = 5;
-}
-
-// Payload of the event indicating the expansion of a target pattern.
-// The main information is in the chaining part: the id will contain the
-// target pattern that was expanded and the children id will contain the
-// target or target pattern it was expanded to.
-message PatternExpanded {
-  // Represents a test_suite target and the tests that it expanded to. Nested
-  // test suites are recursively expanded. The test labels only contain the
-  // final test targets, not any nested suites.
-  message TestSuiteExpansion {
-    // The label of the test_suite rule.
-    string suite_label = 1;
-    // Labels of the test targets included in the suite. Includes all tests in
-    // the suite regardless of any filters or negative patterns which may result
-    // in the test not actually being run.
-    repeated string test_labels = 2;
-  }
-
-  // All test suites requested via top-level target patterns. Does not include
-  // test suites whose label matched a negative pattern.
-  repeated TestSuiteExpansion test_suite_expansions = 1;
-}
-
-// Enumeration type characterizing the size of a test, as specified by the
-// test rule.
-enum TestSize {
-  UNKNOWN = 0;
-  SMALL = 1;
-  MEDIUM = 2;
-  LARGE = 3;
-  ENORMOUS = 4;
-}
-
-// Payload of the event indicating that the configurations for a target have
-// been identified. As with pattern expansion the main information is in the
-// chaining part: the id will contain the target that was configured and the
-// children id will contain the configured targets it was configured to.
-message TargetConfigured {
-  // The kind of target (e.g.,  e.g. "cc_library rule", "source file",
-  // "generated file") where the completion is reported.
-  string target_kind = 1;
-
-  // The size of the test, if the target is a test target. Unset otherwise.
-  TestSize test_size = 2;
-
-  // List of all tags associated with this target (for all possible
-  // configurations).
-  repeated string tag = 3;
-}
-
-message File {
-  // A sequence of prefixes to apply to the file name to construct a full path.
-  // In most but not all cases, there will be 3 entries:
-  //  1. A root output directory, eg "bazel-out"
-  //  2. A configuration mnemonic, eg "k8-fastbuild"
-  //  3. An output category, eg "genfiles"
-  repeated string path_prefix = 4;
-
-  // identifier indicating the nature of the file (e.g., "stdout", "stderr")
-  string name = 1;
-
-  oneof file {
-    // A location where the contents of the file can be found. The string is
-    // encoded according to RFC2396.
-    string uri = 2;
-    // The contents of the file, if they are guaranteed to be short.
-    bytes contents = 3;
-  }
-
-  // Digest of the file, using the build tool's configured digest algorithm,
-  // hex-encoded.
-  string digest = 5;
-
-  // Length of the file in bytes.
-  int64 length = 6;
-}
-
-// Payload of a message to describe a set of files, usually build artifacts, to
-// be referred to later by their name. In this way, files that occur identically
-// as outputs of several targets have to be named only once.
-message NamedSetOfFiles {
-  // Files that belong to this named set of files.
-  repeated File files = 1;
-
-  // Other named sets whose members also belong to this set.
-  repeated BuildEventId.NamedSetOfFilesId file_sets = 2;
-}
-
-// Payload of the event indicating the completion of an action. The main purpose
-// of posting those events is to provide details on the root cause for a target
-// failing; however, consumers of the build-event protocol must not assume
-// that only failed actions are posted.
-message ActionExecuted {
-  bool success = 1;
-
-  // The mnemonic of the action that was executed
-  string type = 8;
-
-  // The exit code of the action, if it is available.
-  int32 exit_code = 2;
-
-  // Location where to find the standard output of the action
-  // (e.g., a file path).
-  File stdout = 3;
-
-  // Location where to find the standard error of the action
-  // (e.g., a file path).
-  File stderr = 4;
-
-  // Deprecated. This field is now present on ActionCompletedId.
-  string label = 5 [deprecated = true];
-
-  // Deprecated. This field is now present on ActionCompletedId.
-  BuildEventId.ConfigurationId configuration = 7 [deprecated = true];
-
-  // Primary output; only provided for successful actions.
-  File primary_output = 6;
-
-  // The command-line of the action, if the action is a command.
-  repeated string command_line = 9;
-
-  // List of paths to log files
-  repeated File action_metadata_logs = 10;
-
-  // Only populated if success = false, and sometimes not even then.
-  failure_details.FailureDetail failure_detail = 11;
-}
-
-// Collection of all output files belonging to that output group.
-message OutputGroup {
-  // Ids of fields that have been removed.
-  reserved 2;
-
-  // Name of the output group
-  string name = 1;
-
-  // List of file sets that belong to this output group as well.
-  repeated BuildEventId.NamedSetOfFilesId file_sets = 3;
-
-  // Indicates that one or more of the output group's files were not built
-  // successfully (the generating action failed).
-  bool incomplete = 4;
-}
-
-// Payload of the event indicating the completion of a target. The target is
-// specified in the id. If the target failed the root causes are provided as
-// children events.
-message TargetComplete {
-  bool success = 1;
-
-  // The kind of target (e.g.,  e.g. "cc_library rule", "source file",
-  // "generated file") where the completion is reported.
-  // Deprecated: use the target_kind field in TargetConfigured instead.
-  string target_kind = 5 [deprecated = true];
-
-  // The size of the test, if the target is a test target. Unset otherwise.
-  // Deprecated: use the test_size field in TargetConfigured instead.
-  TestSize test_size = 6 [deprecated = true];
-
-  // The output files are arranged by their output group. If an output file
-  // is part of multiple output groups, it appears once in each output
-  // group.
-  repeated OutputGroup output_group = 2;
-
-  // Temporarily, also report the important outputs directly. This is only to
-  // allow existing clients help transition to the deduplicated representation;
-  // new clients should not use it.
-  repeated File important_output = 4 [deprecated = true];
-
-  // Report output artifacts (referenced transitively via output_group) which
-  // emit directories instead of singleton files. These directory_output entries
-  // will never include a uri.
-  repeated File directory_output = 8;
-
-  // List of tags associated with this configured target.
-  repeated string tag = 3;
-
-  // The timeout specified for test actions under this configured target.
-  //
-  // Deprecated, use `test_timeout` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 test_timeout_seconds = 7 [deprecated = true];
-
-  // The timeout specified for test actions under this configured target.
-  google.protobuf.Duration test_timeout = 10;
-
-  // Failure information about the target, only populated if success is false,
-  // and sometimes not even then. Equal to one of the ActionExecuted
-  // failure_detail fields for one of the root cause ActionExecuted events.
-  failure_details.FailureDetail failure_detail = 9;
-}
-
-enum TestStatus {
-  NO_STATUS = 0;
-  PASSED = 1;
-  FLAKY = 2;
-  TIMEOUT = 3;
-  FAILED = 4;
-  INCOMPLETE = 5;
-  REMOTE_FAILURE = 6;
-  FAILED_TO_BUILD = 7;
-  TOOL_HALTED_BEFORE_TESTING = 8;
-}
-
-// Payload on events reporting about individual test action.
-message TestResult {
-  reserved 1;
-
-  // The status of this test.
-  TestStatus status = 5;
-
-  // Additional details about the status of the test. This is intended for
-  // user display and must not be parsed.
-  string status_details = 9;
-
-  // True, if the reported attempt is taken from the tool's local cache.
-  bool cached_locally = 4;
-
-  // Time in milliseconds since the epoch at which the test attempt was started.
-  // Note: for cached test results, this is time can be before the start of the
-  // build.
-  //
-  // Deprecated, use `test_attempt_start` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 test_attempt_start_millis_epoch = 6 [deprecated = true];
-
-  // Time at which the test attempt was started.
-  // Note: for cached test results, this is time can be before the start of the
-  // build.
-  google.protobuf.Timestamp test_attempt_start = 10;
-
-  // Time the test took to run. For locally cached results, this is the time
-  // the cached invocation took when it was invoked.
-  //
-  // Deprecated, use `test_attempt_duration` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 test_attempt_duration_millis = 3 [deprecated = true];
-
-  // Time the test took to run. For locally cached results, this is the time
-  // the cached invocation took when it was invoked.
-  google.protobuf.Duration test_attempt_duration = 11;
-
-  // Files (logs, test.xml, undeclared outputs, etc) generated by that test
-  // action.
-  repeated File test_action_output = 2;
-
-  // Warnings generated by that test action.
-  repeated string warning = 7;
-
-  // Message providing optional meta data on the execution of the test action,
-  // if available.
-  message ExecutionInfo {
-    // Deprecated, use TargetComplete.test_timeout instead.
-    int32 timeout_seconds = 1 [deprecated = true];
-
-    // Name of the strategy to execute this test action (e.g., "local",
-    // "remote")
-    string strategy = 2;
-
-    // True, if the reported attempt was a cache hit in a remote cache.
-    bool cached_remotely = 6;
-
-    // The exit code of the test action.
-    int32 exit_code = 7;
-
-    // The hostname of the machine where the test action was executed (in case
-    // of remote execution), if known.
-    string hostname = 3;
-
-    // Represents a hierarchical timing breakdown of an activity.
-    // The top level time should be the total time of the activity.
-    // Invariant: `time` >= sum of `time`s of all direct children.
-    message TimingBreakdown {
-      repeated TimingBreakdown child = 1;
-      string name = 2;
-      // Deprecated, use `time` instead.
-      //
-      // TODO(yannic): Remove.
-      int64 time_millis = 3 [deprecated = true];
-      google.protobuf.Duration time = 4;
-    }
-    TimingBreakdown timing_breakdown = 4;
-
-    message ResourceUsage {
-      string name = 1;
-      int64 value = 2;
-    }
-    repeated ResourceUsage resource_usage = 5;
-  }
-  ExecutionInfo execution_info = 8;
-}
-
-// Payload of the event summarizing a test.
-message TestSummary {
-  // Wrapper around BlazeTestStatus to support importing that enum to proto3.
-  // Overall status of test, accumulated over all runs, shards, and attempts.
-  TestStatus overall_status = 5;
-
-  // Total number of shard attempts.
-  // E.g., if a target has 4 runs, 3 shards, each with 2 attempts,
-  // then total_run_count will be 4*3*2 = 24.
-  int32 total_run_count = 1;
-
-  // Value of runs_per_test for the test.
-  int32 run_count = 10;
-
-  // Number of attempts.
-  // If there are a different number of attempts per shard, the highest attempt
-  // count across all shards for each run is used.
-  int32 attempt_count = 15;
-
-  // Number of shards.
-  int32 shard_count = 11;
-
-  // Path to logs of passed runs.
-  repeated File passed = 3;
-
-  // Path to logs of failed runs;
-  repeated File failed = 4;
-
-  // Total number of cached test actions
-  int32 total_num_cached = 6;
-
-  // When the test first started running.
-  //
-  // Deprecated, use `first_start_time` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 first_start_time_millis = 7 [deprecated = true];
-
-  // When the test first started running.
-  google.protobuf.Timestamp first_start_time = 13;
-
-  // When the last test action completed.
-  //
-  // Deprecated, use `last_stop_time` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 last_stop_time_millis = 8 [deprecated = true];
-
-  // When the test first started running.
-  google.protobuf.Timestamp last_stop_time = 14;
-
-  // The total runtime of the test.
-  //
-  // Deprecated, use `total_run` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 total_run_duration_millis = 9 [deprecated = true];
-
-  // The total runtime of the test.
-  google.protobuf.Duration total_run_duration = 12;
-}
-
-// Payload of the event summarizing a target (test or non-test).
-message TargetSummary {
-  // Conjunction of TargetComplete events for this target, including aspects.
-  bool overall_build_success = 1;
-
-  // Repeats TestSummary's overall_status if available.
-  TestStatus overall_test_status = 2;
-}
-
-// Event indicating the end of a build.
-message BuildFinished {
-  // Exit code of a build. The possible values correspond to the predefined
-  // codes in bazel's lib.ExitCode class, as well as any custom exit code a
-  // module might define. The predefined exit codes are subject to change (but
-  // rarely do) and are not part of the public API.
-  //
-  // A build was successful iff ExitCode.code equals 0.
-  message ExitCode {
-    // The name of the exit code.
-    string name = 1;
-
-    // The exit code.
-    int32 code = 2;
-  }
-
-  // Things that happened during the build that could be of interest.
-  message AnomalyReport {
-    // Was the build suspended at any time during the build.
-    // Examples of suspensions are SIGSTOP, or the hardware being put to sleep.
-    // If was_suspended is true, then most of the timings for this build are
-    // suspect.
-    // NOTE: This is no longer set and is deprecated.
-    bool was_suspended = 1;
-  }
-
-  // If the build succeeded or failed.
-  bool overall_success = 1 [deprecated = true];
-
-  // The overall status of the build. A build was successful iff
-  // ExitCode.code equals 0.
-  ExitCode exit_code = 3;
-
-  // End of the build in ms since the epoch.
-  //
-  // Deprecated, use `finish_time` instead.
-  //
-  // TODO(yannic): Remove.
-  int64 finish_time_millis = 2 [deprecated = true];
-
-  // End of the build.
-  google.protobuf.Timestamp finish_time = 5;
-
-  AnomalyReport anomaly_report = 4 [deprecated = true];
-}
-
-message BuildMetrics {
-  message ActionSummary {
-    // The total number of actions created and registered during the build,
-    // including both aspects and configured targets. This metric includes
-    // unused actions that were constructed but not executed during this build.
-    // It does not include actions that were created on prior builds that are
-    // still valid, even if those actions had to be re-executed on this build.
-    // For the total number of actions that would be created if this invocation
-    // were "clean", see BuildGraphMetrics below.
-    int64 actions_created = 1;
-
-    // The total number of actions created this build just by configured
-    // targets. Used mainly to allow consumers of actions_created, which used to
-    // not include aspects' actions, to normalize across the Blaze release that
-    // switched actions_created to include all created actions.
-    int64 actions_created_not_including_aspects = 3;
-
-    // The total number of actions executed during the build. This includes any
-    // remote cache hits, but excludes local action cache hits.
-    int64 actions_executed = 2;
-
-    message ActionData {
-      string mnemonic = 1;
-
-      // The total number of actions of this type executed during the build. As
-      // above, includes remote cache hits but excludes local action cache hits.
-      int64 actions_executed = 2;
-
-      // When the first action of this type started being executed, in
-      // milliseconds from the epoch.
-      int64 first_started_ms = 3;
-
-      // When the last action of this type ended being executed, in
-      // milliseconds from the epoch.
-      int64 last_ended_ms = 4;
-    }
-    // Contains the top N actions by number of actions executed.
-    repeated ActionData action_data = 4;
-
-    // Deprecated. The total number of remote cache hits.
-    int64 remote_cache_hits = 5 [deprecated = true];
-
-    message RunnerCount {
-      string name = 1;
-      int32 count = 2;
-    }
-    repeated RunnerCount runner_count = 6;
-  }
-  ActionSummary action_summary = 1;
-
-  message MemoryMetrics {
-    // Size of the JVM heap post build in bytes. This is only collected if
-    // --memory_profile is set, since it forces a full GC.
-    int64 used_heap_size_post_build = 1;
-
-    // Size of the peak JVM heap size in bytes post GC. Note that this reports 0
-    // if there was no major GC during the build.
-    int64 peak_post_gc_heap_size = 2;
-
-    // Size of the peak tenured space JVM heap size event in bytes post GC. Note
-    // that this reports 0 if there was no major GC during the build.
-    int64 peak_post_gc_tenured_space_heap_size = 4;
-
-    message GarbageMetrics {
-      // Type of garbage collected, e.g. G1 Old Gen.
-      string type = 1;
-      // Number of bytes of garbage of the given type collected during this
-      // invocation.
-      int64 garbage_collected = 2;
-    }
-
-    repeated GarbageMetrics garbage_metrics = 3;
-  }
-  MemoryMetrics memory_metrics = 2;
-
-  message TargetMetrics {
-    // DEPRECATED
-    // No longer populated. It never measured what it was supposed to (targets
-    // loaded): it counted targets that were analyzed even if the underlying
-    // package had not changed.
-    // TODO(janakr): rename and remove.
-    int64 targets_loaded = 1;
-
-    // Number of targets/aspects configured during this build. Does not include
-    // targets/aspects that were configured on prior builds on this server and
-    // were cached. See BuildGraphMetrics below if you need that.
-    int64 targets_configured = 2;
-
-    // Number of configured targets analyzed during this build. Does not include
-    // aspects. Used mainly to allow consumers of targets_configured, which used
-    // to not include aspects, to normalize across the Blaze release that
-    // switched targets_configured to include aspects.
-    int64 targets_configured_not_including_aspects = 3;
-  }
-  TargetMetrics target_metrics = 3;
-
-  message PackageMetrics {
-    // Number of BUILD files (aka packages) successfully loaded during this
-    // build.
-    //
-    // [For Bazel binaries built at source states] Before Dec 2021, this value
-    // was the number of packages attempted to be loaded, for a particular
-    // definition of "attempted".
-    //
-    // After Dec 2021, this value would sometimes overcount because the same
-    // package could sometimes be attempted to be loaded multiple times due to
-    // memory pressure.
-    //
-    // After Feb 2022, this value is the number of packages successfully
-    // loaded.
-    int64 packages_loaded = 1;
-  }
-  PackageMetrics package_metrics = 4;
-
-  message TimingMetrics {
-    // The CPU time in milliseconds consumed during this build.
-    int64 cpu_time_in_ms = 1;
-    // The elapsed wall time in milliseconds during this build.
-    int64 wall_time_in_ms = 2;
-    // The elapsed wall time in milliseconds during the analysis phase.
-    // When analysis and execution phases are interleaved, this measures the
-    // elapsed time from the first analysis work to the last.
-    int64 analysis_phase_time_in_ms = 3;
-  }
-  TimingMetrics timing_metrics = 5;
-
-  message CumulativeMetrics {
-    // One-indexed number of "analyses" the server has run, including the
-    // current one. Will be incremented for every build/test/cquery/etc. command
-    // that reaches the analysis phase.
-    int32 num_analyses = 11;
-    // One-indexed number of "builds" the server has run, including the current
-    // one. Will be incremented for every build/test/run/etc. command that
-    // reaches the execution phase.
-    int32 num_builds = 12;
-  }
-
-  CumulativeMetrics cumulative_metrics = 6;
-
-  message ArtifactMetrics {
-    reserved 1;
-
-    message FilesMetric {
-      int64 size_in_bytes = 1;
-      int32 count = 2;
-    }
-
-    // Measures all source files newly read this build. Does not include
-    // unchanged sources on incremental builds.
-    FilesMetric source_artifacts_read = 2;
-    // Measures all output artifacts from executed actions. This includes
-    // actions that were cached locally (via the action cache) or remotely (via
-    // a remote cache or executor), but does *not* include outputs of actions
-    // that were cached internally in Skyframe.
-    FilesMetric output_artifacts_seen = 3;
-    // Measures all output artifacts from actions that were cached locally
-    // via the action cache. These artifacts were already present on disk at the
-    // start of the build. Does not include Skyframe-cached actions' outputs.
-    FilesMetric output_artifacts_from_action_cache = 4;
-    // Measures all artifacts that belong to a top-level output group. Does not
-    // deduplicate, so if there are two top-level targets in this build that
-    // share an artifact, it will be counted twice.
-    FilesMetric top_level_artifacts = 5;
-  }
-
-  ArtifactMetrics artifact_metrics = 7;
-
-  // Information about the size and shape of the build graph. Some fields may
-  // not be populated if Bazel was able to skip steps due to caching.
-  message BuildGraphMetrics {
-    // How many configured targets/aspects were in this build, including any
-    // that were analyzed on a prior build and are still valid. May not be
-    // populated if analysis phase was fully cached. Note: for historical
-    // reasons this includes input/output files and other configured targets
-    // that do not actually have associated actions.
-    int32 action_lookup_value_count = 1;
-    // How many configured targets alone were in this build: always at most
-    // action_lookup_value_count. Useful mainly for historical comparisons to
-    // TargetMetrics.targets_configured, which used to not count aspects. This
-    // also includes configured targets that do not have associated actions.
-    int32 action_lookup_value_count_not_including_aspects = 5;
-    // How many actions belonged to the configured targets/aspects above. It may
-    // not be necessary to execute all of these actions to build the requested
-    // targets. May not be populated if analysis phase was fully cached.
-    int32 action_count = 2;
-    // How many actions belonged to configured targets: always at most
-    // action_count. Useful mainly for historical comparisons to
-    // ActionMetrics.actions_created, which used to not count aspects' actions.
-    int32 action_count_not_including_aspects = 6;
-    // How many "input file" configured targets there were: one per source file.
-    // Should agree with artifact_metrics.source_artifacts_read.count above,
-    int32 input_file_configured_target_count = 7;
-    // How many "output file" configured targets there were: output files that
-    // are targets (not implicit outputs).
-    int32 output_file_configured_target_count = 8;
-    // How many "other" configured targets there were (like alias,
-    // package_group, and other non-rule non-file configured targets).
-    int32 other_configured_target_count = 9;
-    // How many artifacts are outputs of the above actions. May not be populated
-    // if analysis phase was fully cached.
-    int32 output_artifact_count = 3;
-    // How many Skyframe nodes there are in memory at the end of the build. This
-    // may underestimate the number of nodes when running with memory-saving
-    // settings or with Skybuild, and may overestimate if there are nodes from
-    // prior evaluations still in the cache.
-    int32 post_invocation_skyframe_node_count = 4;
-  }
-
-  BuildGraphMetrics build_graph_metrics = 8;
-
-  // Information about all workers that were alive during the invocation.
-  message WorkerMetrics {
-    // Unique id of worker.
-    int32 worker_id = 1;
-    // Worker process id. If there is no process for worker, equals to zero.
-    uint32 process_id = 2;
-    // Mnemonic of running worker.
-    string mnemonic = 3;
-    // Multiplex or singleplex worker.
-    bool is_multiplex = 4;
-    // Using worker sandbox file system or not.
-    bool is_sandbox = 5;
-    // Shows is worker stats measured at the end of invocation.
-    bool is_measurable = 6;
-
-    // Information collected from worker at some point.
-    message WorkerStats {
-      // Epoch unix time of collection of metrics.
-      int64 collect_time_in_ms = 1;
-      // RSS size of worker process.
-      int32 worker_memory_in_kb = 2;
-      // Epoch unix time of last action started on specific worker.
-      int64 last_action_start_time_in_ms = 3;
-    }
-
-    // Combined workers statistics.
-    repeated WorkerStats worker_stats = 7;
-  }
-
-  repeated WorkerMetrics worker_metrics = 9;
-
-  // Information about host network.
-  message NetworkMetrics {
-    // Information for all the network traffic going on on the host machine during the invocation.
-    message SystemNetworkStats {
-      // Total bytes sent during the invocation.
-      uint64 bytes_sent = 1;
-      // Total bytes received during the invocation.
-      uint64 bytes_recv = 2;
-      // Total packets sent during the invocation.
-      uint64 packets_sent = 3;
-      // Total packets received during the invocation.
-      uint64 packets_recv = 4;
-      // Peak bytes/sec sent during the invocation.
-      uint64 peak_bytes_sent_per_sec = 5;
-      // Peak bytes/sec received during the invocation.
-      uint64 peak_bytes_recv_per_sec  = 6;
-      // Peak packets/sec sent during the invocation.
-      uint64 peak_packets_sent_per_sec = 7;
-      // Peak packets/sec received during the invocation.
-      uint64 peak_packets_recv_per_sec = 8;
-    }
-
-    SystemNetworkStats system_network_stats = 1;
-  }
-
-  NetworkMetrics network_metrics = 10;
-}
-
-// Event providing additional statistics/logs after completion of the build.
-message BuildToolLogs {
-  repeated File log = 1;
-}
-
-// Event describing all convenience symlinks (i.e., workspace symlinks) to be
-// created or deleted once the execution phase has begun. Note that this event
-// does not say anything about whether or not the build tool actually executed
-// these filesystem operations; it only says what logical operations should be
-// performed. This event is emitted exactly once per build; if no symlinks are
-// to be modified, the event is still emitted with empty contents.
-message ConvenienceSymlinksIdentified {
-  repeated ConvenienceSymlink convenience_symlinks = 1;
-}
-
-// The message that contains what type of action to perform on a given path and
-// target of a symlink.
-message ConvenienceSymlink {
-  enum Action {
-    UNKNOWN = 0;
-
-    // Indicates a symlink should be created, or overwritten if it already
-    // exists.
-    CREATE = 1;
-
-    // Indicates a symlink should be deleted if it already exists.
-    DELETE = 2;
-  }
-
-  // The path of the symlink to be created or deleted, absolute or relative to
-  // the workspace, creating any directories necessary. If a symlink already
-  // exists at that location, then it should be replaced by a symlink pointing
-  // to the new target.
-  string path = 1;
-
-  // The operation we are performing on the symlink.
-  Action action = 2;
-
-  // If action is CREATE, this is the target path that the symlink should point
-  // to. If the path points underneath the output base, it is relative to the
-  // output base; otherwise it is absolute.
-  //
-  // If action is DELETE, this field is not set.
-  string target = 3;
-}
-
-// Message describing a build event. Events will have an identifier that
-// is unique within a given build invocation; they also announce follow-up
-// events as children. More details, which are specific to the kind of event
-// that is observed, is provided in the payload. More options for the payload
-// might be added in the future.
-message BuildEvent {
-  reserved 11, 19;
-  BuildEventId id = 1;
-  repeated BuildEventId children = 2;
-  bool last_message = 20;
-  oneof payload {
-    Progress progress = 3;
-    Aborted aborted = 4;
-    BuildStarted started = 5;
-    UnstructuredCommandLine unstructured_command_line = 12;
-    command_line.CommandLine structured_command_line = 22;
-    OptionsParsed options_parsed = 13;
-    WorkspaceStatus workspace_status = 16;
-    Fetch fetch = 21;
-    Configuration configuration = 17;
-    PatternExpanded expanded = 6;
-    TargetConfigured configured = 18;
-    ActionExecuted action = 7;
-    NamedSetOfFiles named_set_of_files = 15;
-    TargetComplete completed = 8;
-    TestResult test_result = 10;
-    TestSummary test_summary = 9;
-    TargetSummary target_summary = 28;
-    BuildFinished finished = 14;
-    BuildToolLogs build_tool_logs = 23;
-    BuildMetrics build_metrics = 24;
-    WorkspaceConfig workspace_info = 25;
-    BuildMetadata build_metadata = 26;
-    ConvenienceSymlinksIdentified convenience_symlinks_identified = 27;
-  }
-}
diff --git a/atest/bazel/runner/src/main/protobuf/command_line.proto b/atest/bazel/runner/src/main/protobuf/command_line.proto
deleted file mode 100644
index d5fa6ace..00000000
--- a/atest/bazel/runner/src/main/protobuf/command_line.proto
+++ /dev/null
@@ -1,102 +0,0 @@
-// Copyright 2017 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-syntax = "proto3";
-package command_line;
-
-// option java_api_version = 2;
-option java_package = "com.google.devtools.build.lib.runtime.proto";
-
-import "src/main/protobuf/option_filters.proto";
-
-// Representation of a Bazel command line.
-message CommandLine {
-  // A title for this command line value, to differentiate it from others.
-  // In particular, a single invocation may wish to report both the literal and
-  // canonical command lines, and this label would be used to differentiate
-  // between both versions. This is a string for flexibility.
-  string command_line_label = 1;
-
-  // A Bazel command line is made of distinct parts. For example,
-  //    `bazel --nomaster_bazelrc test --nocache_test_results //foo:aTest`
-  // has the executable "bazel", a startup flag, a command "test", a command
-  // flag, and a test target. There could be many more flags and targets, or
-  // none (`bazel info` for example), but the basic structure is there. The
-  // command line should be broken down into these logical sections here.
-  repeated CommandLineSection sections = 2;
-}
-
-// A section of the Bazel command line.
-message CommandLineSection {
-  // The name of this section, such as "startup_option" or "command".
-  string section_label = 1;
-
-  oneof section_type {
-    // Sections with non-options, such as the list of targets or the command,
-    // should use simple string chunks.
-    ChunkList chunk_list = 2;
-
-    // Startup and command options are lists of options and belong here.
-    OptionList option_list = 3;
-  }
-}
-
-// Wrapper to allow a list of strings in the "oneof" section_type.
-message ChunkList {
-  repeated string chunk = 1;
-}
-
-// Wrapper to allow a list of options in the "oneof" section_type.
-message OptionList {
-  repeated Option option = 1;
-}
-
-// A single command line option.
-//
-// This represents the option itself, but does not take into account the type of
-// option or how the parser interpreted it. If this option is part of a command
-// line that represents the actual input that Bazel received, it would, for
-// example, include expansion flags as they are. However, if this option
-// represents the canonical form of the command line, with the values as Bazel
-// understands them, then the expansion flag, which has no value, would not
-// appear, and the flags it expands to would.
-message Option {
-  // How the option looks with the option and its value combined. Depending on
-  // the purpose of this command line report, this could be the canonical
-  // form, or the way that the flag was set.
-  //
-  // Some examples: this might be `--foo=bar` form, or `--foo bar` with a space;
-  // for boolean flags, `--nobaz` is accepted on top of `--baz=false` and other
-  // negating values, or for a positive value, the unqualified `--baz` form
-  // is also accepted. This could also be a short `-b`, if the flag has an
-  // abbreviated form.
-  string combined_form = 1;
-
-  // The canonical name of the option, without the preceding dashes.
-  string option_name = 2;
-
-  // The value of the flag, or unset for flags that do not take values.
-  // Especially for boolean flags, this should be in canonical form, the
-  // combined_form field above gives room for showing the flag as it was set
-  // if that is preferred.
-  string option_value = 3;
-
-  // This flag's tagged effects. See OptionEffectTag's java documentation for
-  // details.
-  repeated options.OptionEffectTag effect_tags = 4;
-
-  // Metadata about the flag. See OptionMetadataTag's java documentation for
-  // details.
-  repeated options.OptionMetadataTag metadata_tags = 5;
-}
diff --git a/atest/bazel/runner/src/main/protobuf/failure_details.proto b/atest/bazel/runner/src/main/protobuf/failure_details.proto
deleted file mode 100644
index ea0873c3..00000000
--- a/atest/bazel/runner/src/main/protobuf/failure_details.proto
+++ /dev/null
@@ -1,1306 +0,0 @@
-// Copyright 2020 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// This file's messages describe any failure(s) that occurred during Bazel's
-// handling of a request. The intent is to provide more detail to a Bazel client
-// than is conveyed with an exit code, to help those clients decide how to
-// respond to, or classify, a failure.
-
-syntax = "proto3";
-
-package failure_details;
-
-option java_package = "com.google.devtools.build.lib.server";
-
-import "google/protobuf/descriptor.proto";
-
-message FailureDetailMetadata {
-  uint32 exit_code = 1;
-}
-
-  extend google.protobuf.EnumValueOptions {
-  FailureDetailMetadata metadata = 1078;
-}
-
-// The FailureDetail message type is designed such that consumers can extract a
-// basic classification of a FailureDetail message even if the consumer was
-// built with a stale definition. This forward compatibility is implemented via
-// conventions on FailureDetail and its submessage types, as follows.
-//
-// *** FailureDetail field numbers
-//
-// Field numbers 1 through 100 (inclusive) are reserved for generally applicable
-// values. Any number of these fields may be set on a FailureDetail message.
-//
-// Field numbers 101 through 10,000 (inclusive) are reserved for use inside the
-// "oneof" structure. Only one of these values should be set on a FailureDetail
-// message.
-//
-// Additional fields numbers are unlikely to be needed, but, for extreme future-
-// proofing purposes, field numbers 10,001 through 1,000,000 (inclusive;
-// excluding protobuf's reserved range 19000 through 19999) are reserved for
-// additional generally applicable values.
-//
-// *** FailureDetail's "oneof" submessages
-//
-// Each field in the "oneof" structure is a submessage corresponding to a
-// category of failure.
-//
-// In each of these submessage types, field number 1 is an enum whose values
-// correspond to a subcategory of the failure. Generally, the enum's constant
-// which maps to 0 should be interpreted as "unspecified", though this is not
-// required.
-//
-// *** Recommended forward compatibility strategy
-//
-// The recommended forward compatibility strategy is to reduce a FailureDetail
-// message to a pair of integers.
-//
-// The first integer corresponds to the field number of the submessage set
-// inside FailureDetail's "oneof", which corresponds with the failure's
-// category.
-//
-// The second integer corresponds to the value of the enum at field number 1
-// within that submessage, which corresponds with the failure's subcategory.
-//
-// WARNING: This functionality is experimental and should not be relied on at
-// this time.
-// TODO(mschaller): remove experimental warning
-message FailureDetail {
-  // A short human-readable message describing the failure, for debugging.
-  //
-  // This value is *not* intended to be used algorithmically.
-  string message = 1;
-
-  // Reserved for future generally applicable values. Any of these may be set.
-  reserved 2 to 100;
-
-  oneof category {
-    Interrupted interrupted = 101;
-    ExternalRepository external_repository = 103;
-    BuildProgress build_progress = 104;
-    RemoteOptions remote_options = 106;
-    ClientEnvironment client_environment = 107;
-    Crash crash = 108;
-    SymlinkForest symlink_forest = 110;
-    PackageOptions package_options = 114;
-    RemoteExecution remote_execution = 115;
-    Execution execution = 116;
-    Workspaces workspaces = 117;
-    CrashOptions crash_options = 118;
-    Filesystem filesystem = 119;
-    ExecutionOptions execution_options = 121;
-    Command command = 122;
-    Spawn spawn = 123;
-    GrpcServer grpc_server = 124;
-    CanonicalizeFlags canonicalize_flags = 125;
-    BuildConfiguration build_configuration = 126;
-    InfoCommand info_command = 127;
-    MemoryOptions memory_options = 129;
-    Query query = 130;
-    LocalExecution local_execution = 132;
-    ActionCache action_cache = 134;
-    FetchCommand fetch_command = 135;
-    SyncCommand sync_command = 136;
-    Sandbox sandbox = 137;
-    IncludeScanning include_scanning = 139;
-    TestCommand test_command = 140;
-    ActionQuery action_query = 141;
-    TargetPatterns target_patterns = 142;
-    CleanCommand clean_command = 144;
-    ConfigCommand config_command = 145;
-    ConfigurableQuery configurable_query = 146;
-    DumpCommand dump_command = 147;
-    HelpCommand help_command = 148;
-    MobileInstall mobile_install = 150;
-    ProfileCommand profile_command = 151;
-    RunCommand run_command = 152;
-    VersionCommand version_command = 153;
-    PrintActionCommand print_action_command = 154;
-    WorkspaceStatus workspace_status = 158;
-    JavaCompile java_compile = 159;
-    ActionRewinding action_rewinding = 160;
-    CppCompile cpp_compile = 161;
-    StarlarkAction starlark_action = 162;
-    NinjaAction ninja_action = 163;
-    DynamicExecution dynamic_execution = 164;
-    FailAction fail_action = 166;
-    SymlinkAction symlink_action = 167;
-    CppLink cpp_link = 168;
-    LtoAction lto_action = 169;
-    TestAction test_action = 172;
-    Worker worker = 173;
-    Analysis analysis = 174;
-    PackageLoading package_loading = 175;
-    Toolchain toolchain = 177;
-    StarlarkLoading starlark_loading = 179;
-    ExternalDeps external_deps = 181;
-    DiffAwareness diff_awareness = 182;
-    ModqueryCommand modquery_command = 183;
-    BuildReport build_report = 184;
-  }
-
-  reserved 102; // For internal use
-  reserved 105; // For internal use
-  reserved 109; // For internal use
-  reserved 111 to 113; // For internal use
-  reserved 120; // For internal use
-  reserved 128; // For internal use
-  reserved 131; // For internal use
-  reserved 133; // For internal use
-  reserved 138; // For internal use
-  reserved 143; // For internal use
-  reserved 149; // For internal use
-  reserved 155 to 157; // For internal use
-  reserved 165; // For internal use
-  reserved 170 to 171; // For internal use
-  reserved 176; // For internal use
-  reserved 178; // For internal use
-  reserved 180; // For internal use
-}
-
-message Interrupted {
-  enum Code {
-    // Unknown interrupt. Avoid using this code, instead use INTERRUPTED.
-    INTERRUPTED_UNKNOWN = 0 [(metadata) = { exit_code: 8 }];
-
-    // Command was interrupted (cancelled).
-    INTERRUPTED = 28 [(metadata) = { exit_code: 8 }];
-
-    // The following more specific interrupt codes have been deprecated and
-    // consolidated into INTERRUPTED.
-    DEPRECATED_BUILD = 4 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_BUILD_COMPLETION = 5 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_PACKAGE_LOADING_SYNC = 6 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_EXECUTOR_COMPLETION = 7 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_COMMAND_DISPATCH = 8 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_INFO_ITEM = 9 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_AFTER_QUERY = 10 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_FETCH_COMMAND = 17 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_SYNC_COMMAND = 18 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_CLEAN_COMMAND = 20 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_MOBILE_INSTALL_COMMAND = 21 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_QUERY = 22 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_RUN_COMMAND = 23 [(metadata) = { exit_code: 8 }];
-    DEPRECATED_OPTIONS_PARSING = 27 [(metadata) = { exit_code: 8 }];
-
-    reserved 1 to 3; // For internal use
-    reserved 11 to 16; // For internal use
-    reserved 19; // For internal use
-    reserved 24 to 26; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message Spawn {
-  enum Code {
-    SPAWN_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    // See the SpawnResult.Status Java enum for definitions of the following
-    // Spawn failure codes.
-    NON_ZERO_EXIT = 1 [(metadata) = { exit_code: 1 }];
-    TIMEOUT = 2 [(metadata) = { exit_code: 1 }];
-    // Note: Spawn OUT_OF_MEMORY leads to a BUILD_FAILURE exit_code because the
-    // build tool itself did not run out of memory.
-    OUT_OF_MEMORY = 3 [(metadata) = { exit_code: 1 }];
-    EXECUTION_FAILED = 4 [(metadata) = { exit_code: 34 }];
-    EXECUTION_DENIED = 5 [(metadata) = { exit_code: 1 }];
-    REMOTE_CACHE_FAILED = 6 [(metadata) = { exit_code: 34 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 7 [(metadata) = { exit_code: 1 }];
-    EXEC_IO_EXCEPTION = 8 [(metadata) = { exit_code: 36 }];
-    INVALID_TIMEOUT = 9 [(metadata) = { exit_code: 1 }];
-    INVALID_REMOTE_EXECUTION_PROPERTIES = 10 [(metadata) = { exit_code: 1 }];
-    NO_USABLE_STRATEGY_FOUND = 11 [(metadata) = { exit_code: 1 }];
-    // TODO(b/138456686): this code should be deprecated when SpawnResult is
-    //   refactored to prohibit undetailed failures
-    UNSPECIFIED_EXECUTION_FAILURE = 12 [(metadata) = { exit_code: 1 }];
-    FORBIDDEN_INPUT = 13 [(metadata) = { exit_code: 1 }];
-  }
-  Code code = 1;
-
-  // For Codes describing generic failure to spawn (eg. EXECUTION_FAILED and
-  // EXECUTION_DENIED) the `catastrophic` field may be set to true indicating a
-  // failure that immediately terminated the entire build tool.
-  bool catastrophic = 2;
-
-  // If Code is NON_ZERO_EXIT, the `spawn_exit_code` field may be set to the
-  // non-zero exit code returned by the spawned process to the OS.
-  //
-  // NOTE: This field must not be confused with the build tool's overall
-  // exit code.
-  int32 spawn_exit_code = 3;
-}
-
-message ExternalRepository {
-  enum Code {
-    EXTERNAL_REPOSITORY_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    OVERRIDE_DISALLOWED_MANAGED_DIRECTORIES = 1 [(metadata) = { exit_code: 2 }];
-    BAD_DOWNLOADER_CONFIG = 2 [(metadata) = { exit_code: 2 }];
-    REPOSITORY_MAPPING_RESOLUTION_FAILED = 3 [(metadata) = { exit_code: 37 }];
-  }
-  Code code = 1;
-  // Additional data could include external repository names.
-}
-
-message BuildProgress {
-  enum Code {
-    BUILD_PROGRESS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    OUTPUT_INITIALIZATION = 3 [(metadata) = { exit_code: 36 }];
-    BES_RUNS_PER_TEST_LIMIT_UNSUPPORTED = 4 [(metadata) = { exit_code: 2 }];
-    BES_LOCAL_WRITE_ERROR = 5 [(metadata) = { exit_code: 36 }];
-    BES_INITIALIZATION_ERROR = 6 [(metadata) = { exit_code: 36 }];
-    BES_UPLOAD_TIMEOUT_ERROR = 7 [(metadata) = { exit_code: 38 }];
-    BES_FILE_WRITE_TIMEOUT = 8 [(metadata) = { exit_code: 38 }];
-    BES_FILE_WRITE_IO_ERROR = 9 [(metadata) = { exit_code: 38 }];
-    BES_FILE_WRITE_INTERRUPTED = 10 [(metadata) = { exit_code: 38 }];
-    BES_FILE_WRITE_CANCELED = 11 [(metadata) = { exit_code: 38 }];
-    BES_FILE_WRITE_UNKNOWN_ERROR = 12 [(metadata) = { exit_code: 38 }];
-    BES_UPLOAD_LOCAL_FILE_ERROR = 13 [(metadata) = { exit_code: 38 }];
-    BES_STREAM_NOT_RETRYING_FAILURE = 14 [(metadata) = { exit_code: 45 }];
-    BES_STREAM_COMPLETED_WITH_UNACK_EVENTS_ERROR = 15
-        [(metadata) = { exit_code: 45 }];
-    BES_STREAM_COMPLETED_WITH_UNSENT_EVENTS_ERROR = 16
-        [(metadata) = { exit_code: 45 }];
-    BES_STREAM_COMPLETED_WITH_REMOTE_ERROR = 19
-        [(metadata) = { exit_code: 45 }];
-    BES_UPLOAD_RETRY_LIMIT_EXCEEDED_FAILURE = 17
-        [(metadata) = { exit_code: 38 }];
-    reserved 1, 2, 18; // For internal use
-  }
-  Code code = 1;
-  // Additional data could include the build progress upload endpoint.
-}
-
-message RemoteOptions {
-  enum Code {
-    REMOTE_OPTIONS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    REMOTE_DEFAULT_EXEC_PROPERTIES_LOGIC_ERROR = 1
-        [(metadata) = { exit_code: 2 }];
-    // Credentials could not be read from the requested file/socket/process/etc.
-    CREDENTIALS_READ_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-    // Credentials could not be written to a shared, temporary file.
-    CREDENTIALS_WRITE_FAILURE = 3 [(metadata) = { exit_code: 36 }];
-    DOWNLOADER_WITHOUT_GRPC_CACHE = 4 [(metadata) = { exit_code: 2 }];
-    EXECUTION_WITH_INVALID_CACHE = 5 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message ClientEnvironment {
-  enum Code {
-    CLIENT_ENVIRONMENT_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    CLIENT_CWD_MALFORMED = 1 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message Crash {
-  enum Code {
-    CRASH_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    CRASH_OOM = 1 [(metadata) = { exit_code: 33 }];
-  }
-
-  Code code = 1;
-
-  // The cause chain of the crash, with the outermost throwable first. Limited
-  // to the outermost exception and at most 4 nested causes (so, max size of 5).
-  repeated Throwable causes = 2;
-}
-
-message Throwable {
-  // The class name of the java.lang.Throwable.
-  string throwable_class = 1;
-  // The throwable's message.
-  string message = 2;
-  // The result of calling toString on the deepest (i.e. closest to the
-  // throwable's construction site) 1000 (or fewer) StackTraceElements.
-  // Unstructured to simplify string matching.
-  repeated string stack_trace = 3;
-}
-
-message SymlinkForest {
-  enum Code {
-    SYMLINK_FOREST_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    TOPLEVEL_OUTDIR_PACKAGE_PATH_CONFLICT = 1 [(metadata) = { exit_code: 2 }];
-    TOPLEVEL_OUTDIR_USED_AS_SOURCE = 2 [(metadata) = { exit_code: 2 }];
-    CREATION_FAILED = 3 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message BuildReport {
-  enum Code {
-    BUILD_REPORT_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    BUILD_REPORT_UPLOADER_NEEDS_PACKAGE_PATHS = 1
-        [(metadata) = { exit_code: 36 }];
-    BUILD_REPORT_WRITE_FAILED = 2 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-  // Additional data for partial failures might include the build report that
-  // failed to be written.
-}
-
-message PackageOptions {
-  enum Code {
-    reserved 2, 3;  // For internal use
-
-    PACKAGE_OPTIONS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    PACKAGE_PATH_INVALID = 1 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message RemoteExecution {
-  // The association of some of these options with exit code 2, "command line
-  // error", seems sketchy. Especially worth reconsidering are the channel init
-  // failure modes, which can correspond to failures occurring in gRPC setup.
-  // These all correspond with current Bazel behavior.
-  enum Code {
-    REMOTE_EXECUTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    CAPABILITIES_QUERY_FAILURE = 1 [(metadata) = { exit_code: 34 }];
-    CREDENTIALS_INIT_FAILURE = 2 [(metadata) = { exit_code: 2 }];
-    CACHE_INIT_FAILURE = 3 [(metadata) = { exit_code: 2 }];
-    RPC_LOG_FAILURE = 4 [(metadata) = { exit_code: 2 }];
-    EXEC_CHANNEL_INIT_FAILURE = 5 [(metadata) = { exit_code: 2 }];
-    CACHE_CHANNEL_INIT_FAILURE = 6 [(metadata) = { exit_code: 2 }];
-    DOWNLOADER_CHANNEL_INIT_FAILURE = 7 [(metadata) = { exit_code: 2 }];
-    LOG_DIR_CLEANUP_FAILURE = 8 [(metadata) = { exit_code: 36 }];
-    CLIENT_SERVER_INCOMPATIBLE = 9 [(metadata) = { exit_code: 34 }];
-    DOWNLOADED_INPUTS_DELETION_FAILURE = 10 [(metadata) = { exit_code: 34 }];
-    REMOTE_DOWNLOAD_OUTPUTS_MINIMAL_WITHOUT_INMEMORY_DOTD = 11
-        [(metadata) = { exit_code: 2 }];
-    REMOTE_DOWNLOAD_OUTPUTS_MINIMAL_WITHOUT_INMEMORY_JDEPS = 12
-        [(metadata) = { exit_code: 2 }];
-    INCOMPLETE_OUTPUT_DOWNLOAD_CLEANUP_FAILURE = 13
-        [(metadata) = { exit_code: 36 }];
-    REMOTE_DEFAULT_PLATFORM_PROPERTIES_PARSE_FAILURE = 14
-        [(metadata) = { exit_code: 1 }];
-    ILLEGAL_OUTPUT = 15 [(metadata) = { exit_code: 1 }];
-    INVALID_EXEC_AND_PLATFORM_PROPERTIES = 16 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message Execution {
-  enum Code {
-    EXECUTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    EXECUTION_LOG_INITIALIZATION_FAILURE = 1 [(metadata) = { exit_code: 2 }];
-    EXECUTION_LOG_WRITE_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-    EXECROOT_CREATION_FAILURE = 3 [(metadata) = { exit_code: 36 }];
-    TEMP_ACTION_OUTPUT_DIRECTORY_DELETION_FAILURE = 4
-        [(metadata) = { exit_code: 36 }];
-    TEMP_ACTION_OUTPUT_DIRECTORY_CREATION_FAILURE = 5
-        [(metadata) = { exit_code: 36 }];
-    PERSISTENT_ACTION_OUTPUT_DIRECTORY_CREATION_FAILURE = 6
-        [(metadata) = { exit_code: 36 }];
-    LOCAL_OUTPUT_DIRECTORY_SYMLINK_FAILURE = 7 [(metadata) = { exit_code: 36 }];
-    reserved 8;  // was ACTION_INPUT_FILES_MISSING, now mostly
-                 // SOURCE_INPUT_MISSING
-    LOCAL_TEMPLATE_EXPANSION_FAILURE = 9 [(metadata) = { exit_code: 36 }];
-    INPUT_DIRECTORY_CHECK_IO_EXCEPTION = 10 [(metadata) = { exit_code: 36 }];
-    EXTRA_ACTION_OUTPUT_CREATION_FAILURE = 11 [(metadata) = { exit_code: 36 }];
-    TEST_RUNNER_IO_EXCEPTION = 12 [(metadata) = { exit_code: 36 }];
-    FILE_WRITE_IO_EXCEPTION = 13 [(metadata) = { exit_code: 36 }];
-    TEST_OUT_ERR_IO_EXCEPTION = 14 [(metadata) = { exit_code: 36 }];
-    SYMLINK_TREE_MANIFEST_COPY_IO_EXCEPTION = 15
-        [(metadata) = { exit_code: 36 }];
-    SYMLINK_TREE_MANIFEST_LINK_IO_EXCEPTION = 16
-        [(metadata) = { exit_code: 36 }];
-    SYMLINK_TREE_CREATION_IO_EXCEPTION = 17 [(metadata) = { exit_code: 36 }];
-    SYMLINK_TREE_CREATION_COMMAND_EXCEPTION = 18
-        [(metadata) = { exit_code: 36 }];
-    ACTION_INPUT_READ_IO_EXCEPTION = 19 [(metadata) = { exit_code: 36 }];
-    ACTION_NOT_UP_TO_DATE = 20 [(metadata) = { exit_code: 1 }];
-    PSEUDO_ACTION_EXECUTION_PROHIBITED = 21 [(metadata) = { exit_code: 1 }];
-    DISCOVERED_INPUT_DOES_NOT_EXIST = 22 [(metadata) = { exit_code: 36 }];
-    ACTION_OUTPUTS_DELETION_FAILURE = 23 [(metadata) = { exit_code: 1 }];
-    ACTION_OUTPUTS_NOT_CREATED = 24 [(metadata) = { exit_code: 1 }];
-    ACTION_FINALIZATION_FAILURE = 25 [(metadata) = { exit_code: 1 }];
-    ACTION_INPUT_LOST = 26 [(metadata) = { exit_code: 1 }];
-    FILESYSTEM_CONTEXT_UPDATE_FAILURE = 27 [(metadata) = { exit_code: 1 }];
-    ACTION_OUTPUT_CLOSE_FAILURE = 28 [(metadata) = { exit_code: 1 }];
-    INPUT_DISCOVERY_IO_EXCEPTION = 29 [(metadata) = { exit_code: 1 }];
-    TREE_ARTIFACT_DIRECTORY_CREATION_FAILURE = 30
-        [(metadata) = { exit_code: 1 }];
-    ACTION_OUTPUT_DIRECTORY_CREATION_FAILURE = 31
-        [(metadata) = { exit_code: 1 }];
-    ACTION_FS_OUTPUT_DIRECTORY_CREATION_FAILURE = 32
-        [(metadata) = { exit_code: 1 }];
-    ACTION_FS_OUT_ERR_DIRECTORY_CREATION_FAILURE = 33
-        [(metadata) = { exit_code: 1 }];
-    NON_ACTION_EXECUTION_FAILURE = 34 [(metadata) = { exit_code: 1 }];
-    CYCLE = 35 [(metadata) = { exit_code: 1 }];
-    SOURCE_INPUT_MISSING = 36 [(metadata) = { exit_code: 1 }];
-    UNEXPECTED_EXCEPTION = 37 [(metadata) = { exit_code: 1 }];
-    reserved 38;
-    SOURCE_INPUT_IO_EXCEPTION = 39 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-// Failure details about Bazel's WORKSPACE features.
-message Workspaces {
-  enum Code {
-    WORKSPACES_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    WORKSPACES_LOG_INITIALIZATION_FAILURE = 1 [(metadata) = { exit_code: 2 }];
-    WORKSPACES_LOG_WRITE_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-
-    // See `managed_directories` in
-    // https://bazel.build/rules/lib/globals#workspace.
-    ILLEGAL_WORKSPACE_FILE_SYMLINK_WITH_MANAGED_DIRECTORIES = 3
-        [(metadata) = { exit_code: 1 }];
-    WORKSPACE_FILE_READ_FAILURE_WITH_MANAGED_DIRECTORIES = 4
-        [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message CrashOptions {
-  enum Code {
-    CRASH_OPTIONS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    reserved 1; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message Filesystem {
-  enum Code {
-    FILESYSTEM_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    reserved 1;
-    reserved 2;
-    EMBEDDED_BINARIES_ENUMERATION_FAILURE = 3 [(metadata) = { exit_code: 36 }];
-    SERVER_PID_TXT_FILE_READ_FAILURE = 4 [(metadata) = { exit_code: 36 }];
-    SERVER_FILE_WRITE_FAILURE = 5 [(metadata) = { exit_code: 36 }];
-    DEFAULT_DIGEST_HASH_FUNCTION_INVALID_VALUE = 6
-        [(metadata) = { exit_code: 2 }];
-
-    reserved 7; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message ExecutionOptions {
-  // All numerical exit code associations correspond to pre-existing Bazel
-  // behavior. These associations are suspicious:
-  // - REQUESTED_STRATEGY_INCOMPATIBLE_WITH_SANDBOXING (instead: 2?)
-  // - DEPRECATED_LOCAL_RESOURCES_USED (instead: 2?)
-  // TODO(b/138456686): Revise these after the (intentionally non-breaking)
-  //  initial rollout of FailureDetail-based encoding.
-  enum Code {
-    EXECUTION_OPTIONS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INVALID_STRATEGY = 3 [(metadata) = { exit_code: 2 }];
-    REQUESTED_STRATEGY_INCOMPATIBLE_WITH_SANDBOXING = 4
-        [(metadata) = { exit_code: 36 }];
-    DEPRECATED_LOCAL_RESOURCES_USED = 5 [(metadata) = { exit_code: 36 }];
-    INVALID_CYCLIC_DYNAMIC_STRATEGY = 6 [(metadata) = { exit_code: 36 }];
-    RESTRICTION_UNMATCHED_TO_ACTION_CONTEXT = 7 [(metadata) = { exit_code: 2 }];
-    REMOTE_FALLBACK_STRATEGY_NOT_ABSTRACT_SPAWN = 8
-        [(metadata) = { exit_code: 2 }];
-    STRATEGY_NOT_FOUND = 9 [(metadata) = { exit_code: 2 }];
-    DYNAMIC_STRATEGY_NOT_SANDBOXED = 10 [(metadata) = { exit_code: 2 }];
-
-    reserved 1, 2; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message Command {
-  enum Code {
-    // The name "COMMAND_UNKNOWN" might reasonably be interpreted as "command
-    // not found". The enum's default value should represent a lack of knowledge
-    // about the failure instead.
-    COMMAND_FAILURE_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    COMMAND_NOT_FOUND = 1 [(metadata) = { exit_code: 2 }];
-    ANOTHER_COMMAND_RUNNING = 2 [(metadata) = { exit_code: 9 }];
-    PREVIOUSLY_SHUTDOWN = 3 [(metadata) = { exit_code: 36 }];
-    STARLARK_CPU_PROFILE_FILE_INITIALIZATION_FAILURE = 4
-        [(metadata) = { exit_code: 36 }];
-    STARLARK_CPU_PROFILING_INITIALIZATION_FAILURE = 5
-        [(metadata) = { exit_code: 36 }];
-    STARLARK_CPU_PROFILE_FILE_WRITE_FAILURE = 6
-        [(metadata) = { exit_code: 36 }];
-    INVOCATION_POLICY_PARSE_FAILURE = 7 [(metadata) = { exit_code: 2 }];
-    INVOCATION_POLICY_INVALID = 8 [(metadata) = { exit_code: 2 }];
-    OPTIONS_PARSE_FAILURE = 9 [(metadata) = { exit_code: 2 }];
-    STARLARK_OPTIONS_PARSE_FAILURE = 10 [(metadata) = { exit_code: 2 }];
-    ARGUMENTS_NOT_RECOGNIZED = 11 [(metadata) = { exit_code: 2 }];
-    NOT_IN_WORKSPACE = 12 [(metadata) = { exit_code: 2 }];
-    SPACES_IN_WORKSPACE_PATH = 13 [(metadata) = { exit_code: 36 }];
-    IN_OUTPUT_DIRECTORY = 14 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message GrpcServer {
-  enum Code {
-    GRPC_SERVER_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    GRPC_SERVER_NOT_COMPILED_IN = 1 [(metadata) = { exit_code: 37 }];
-    SERVER_BIND_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-    BAD_COOKIE = 3 [(metadata) = { exit_code: 36 }];
-    NO_CLIENT_DESCRIPTION = 4 [(metadata) = { exit_code: 36 }];
-    reserved 5; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message CanonicalizeFlags {
-  enum Code {
-    CANONICALIZE_FLAGS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    FOR_COMMAND_INVALID = 1 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-// Failure modes described by this category pertain to the Bazel invocation
-// configuration consumed by Bazel's analysis phase. This category is not
-// intended as a grab-bag for all Bazel flag value constraint violations, which
-// instead generally belong in the category for the subsystem whose flag values
-// participate in the constraint.
-message BuildConfiguration {
-  enum Code {
-    BUILD_CONFIGURATION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    PLATFORM_MAPPING_EVALUATION_FAILURE = 1 [(metadata) = { exit_code: 2 }];
-    PLATFORM_MAPPINGS_FILE_IS_DIRECTORY = 2 [(metadata) = { exit_code: 1 }];
-    PLATFORM_MAPPINGS_FILE_NOT_FOUND = 3 [(metadata) = { exit_code: 1 }];
-    TOP_LEVEL_CONFIGURATION_CREATION_FAILURE = 4
-        [(metadata) = { exit_code: 1 }];
-    INVALID_CONFIGURATION = 5 [(metadata) = { exit_code: 2 }];
-    INVALID_BUILD_OPTIONS = 6 [(metadata) = { exit_code: 2 }];
-    MULTI_CPU_PREREQ_UNMET = 7 [(metadata) = { exit_code: 2 }];
-    HEURISTIC_INSTRUMENTATION_FILTER_INVALID = 8
-        [(metadata) = { exit_code: 2 }];
-    CYCLE = 9 [(metadata) = { exit_code: 2 }];
-    CONFLICTING_CONFIGURATIONS = 10 [(metadata) = { exit_code: 2 }];
-    // This can come from either an invalid user-specified option or a
-    // configuration transition. There's no sure-fire way to distinguish the two
-    // possibilities in Bazel, so we go with the more straightforward
-    // command-line error exit code 2.
-    INVALID_OUTPUT_DIRECTORY_MNEMONIC = 11 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message InfoCommand {
-  // The distinction between a failure to write a single info item and a failure
-  // to write them all seems sketchy. Why do they have different exit codes?
-  // This reflects current Bazel behavior, but deserves more thought.
-  enum Code {
-    INFO_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    TOO_MANY_KEYS = 1 [(metadata) = { exit_code: 2 }];
-    KEY_NOT_RECOGNIZED = 2 [(metadata) = { exit_code: 2 }];
-    INFO_BLOCK_WRITE_FAILURE = 3 [(metadata) = { exit_code: 7 }];
-    ALL_INFO_WRITE_FAILURE = 4 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message MemoryOptions {
-  enum Code {
-    MEMORY_OPTIONS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    EXPERIMENTAL_OOM_MORE_EAGERLY_THRESHOLD_INVALID_VALUE = 1
-        [(metadata) = { exit_code: 2 }];
-    EXPERIMENTAL_OOM_MORE_EAGERLY_NO_TENURED_COLLECTORS_FOUND = 2
-        [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message Query {
-  enum Code {
-    QUERY_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    QUERY_FILE_WITH_COMMAND_LINE_EXPRESSION = 1 [(metadata) = { exit_code: 2 }];
-    QUERY_FILE_READ_FAILURE = 2 [(metadata) = { exit_code: 2 }];
-    COMMAND_LINE_EXPRESSION_MISSING = 3 [(metadata) = { exit_code: 2 }];
-    OUTPUT_FORMAT_INVALID = 4 [(metadata) = { exit_code: 2 }];
-    GRAPHLESS_PREREQ_UNMET = 5 [(metadata) = { exit_code: 2 }];
-    QUERY_OUTPUT_WRITE_FAILURE = 6 [(metadata) = { exit_code: 36 }];
-    QUERY_STDOUT_FLUSH_FAILURE = 13 [(metadata) = { exit_code: 36 }];
-    ANALYSIS_QUERY_PREREQ_UNMET = 14 [(metadata) = { exit_code: 2 }];
-    QUERY_RESULTS_FLUSH_FAILURE = 15 [(metadata) = { exit_code: 36 }];
-    // Deprecated - folded into SYNTAX_ERROR.
-    DEPRECATED_UNCLOSED_QUOTATION_EXPRESSION_ERROR = 16
-        [(metadata) = { exit_code: 2 }];
-    VARIABLE_NAME_INVALID = 17 [(metadata) = { exit_code: 7 }];
-    VARIABLE_UNDEFINED = 18 [(metadata) = { exit_code: 7 }];
-    BUILDFILES_AND_LOADFILES_CANNOT_USE_OUTPUT_LOCATION_ERROR = 19
-        [(metadata) = { exit_code: 2 }];
-    BUILD_FILE_ERROR = 20 [(metadata) = { exit_code: 7 }];
-    CYCLE = 21 [(metadata) = { exit_code: 7 }];
-    UNIQUE_SKYKEY_THRESHOLD_EXCEEDED = 22 [(metadata) = { exit_code: 7 }];
-    TARGET_NOT_IN_UNIVERSE_SCOPE = 23 [(metadata) = { exit_code: 2 }];
-    INVALID_FULL_UNIVERSE_EXPRESSION = 24 [(metadata) = { exit_code: 7 }];
-    UNIVERSE_SCOPE_LIMIT_EXCEEDED = 25 [(metadata) = { exit_code: 7 }];
-    INVALIDATION_LIMIT_EXCEEDED = 26 [(metadata) = { exit_code: 7 }];
-    OUTPUT_FORMAT_PREREQ_UNMET = 27 [(metadata) = { exit_code: 2 }];
-    ARGUMENTS_MISSING = 28 [(metadata) = { exit_code: 7 }];
-    RBUILDFILES_FUNCTION_REQUIRES_SKYQUERY = 29 [(metadata) = { exit_code: 7 }];
-    FULL_TARGETS_NOT_SUPPORTED = 30 [(metadata) = { exit_code: 7 }];
-    // Deprecated - folded into SYNTAX_ERROR.
-    DEPRECATED_UNEXPECTED_TOKEN_ERROR = 31 [(metadata) = { exit_code: 2 }];
-    // Deprecated - folded into SYNTAX_ERROR.
-    DEPRECATED_INTEGER_LITERAL_MISSING = 32 [(metadata) = { exit_code: 2 }];
-    // Deprecated - folded into SYNTAX_ERROR.
-    DEPRECATED_INVALID_STARTING_CHARACTER_ERROR = 33
-        [(metadata) = { exit_code: 2 }];
-    // Deprecated - folded into SYNTAX_ERROR.
-    DEPRECATED_PREMATURE_END_OF_INPUT_ERROR = 34
-        [(metadata) = { exit_code: 2 }];
-    // Indicates the user specified invalid query syntax.
-    SYNTAX_ERROR = 35 [(metadata) = { exit_code: 2 }];
-    OUTPUT_FORMATTER_IO_EXCEPTION = 36 [(metadata) = { exit_code: 36 }];
-    SKYQUERY_TRANSITIVE_TARGET_ERROR = 37 [(metadata) = { exit_code: 7 }];
-    SKYQUERY_TARGET_EXCEPTION = 38 [(metadata) = { exit_code: 7 }];
-    INVALID_LABEL_IN_TEST_SUITE = 39 [(metadata) = { exit_code: 7 }];
-    // Indicates any usage of flags that must not be combined.
-    ILLEGAL_FLAG_COMBINATION = 40 [(metadata) = { exit_code: 2 }];
-    // Indicates a non-detailed exception that halted a query. This is a
-    // deficiency in Blaze/Bazel and code should be changed to attach a detailed
-    // exit code to this failure mode.
-    NON_DETAILED_ERROR = 41 [(metadata) = { exit_code: 1 }];
-
-    reserved 7 to 12; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message LocalExecution {
-  enum Code {
-    LOCAL_EXECUTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    LOCKFREE_OUTPUT_PREREQ_UNMET = 1 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message ActionCache {
-  enum Code {
-    ACTION_CACHE_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INITIALIZATION_FAILURE = 1 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message FetchCommand {
-  enum Code {
-    FETCH_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    EXPRESSION_MISSING = 1 [(metadata) = { exit_code: 2 }];
-    OPTIONS_INVALID = 2 [(metadata) = { exit_code: 2 }];
-    QUERY_PARSE_ERROR = 3 [(metadata) = { exit_code: 2 }];
-    QUERY_EVALUATION_ERROR = 4 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message SyncCommand {
-  enum Code {
-    SYNC_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    PACKAGE_LOOKUP_ERROR = 1 [(metadata) = { exit_code: 7 }];
-    WORKSPACE_EVALUATION_ERROR = 2 [(metadata) = { exit_code: 7 }];
-    REPOSITORY_FETCH_ERRORS = 3 [(metadata) = { exit_code: 7 }];
-    REPOSITORY_NAME_INVALID = 4 [(metadata) = { exit_code: 7 }];
-  }
-
-  Code code = 1;
-}
-
-message Sandbox {
-  enum Code {
-    SANDBOX_FAILURE_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INITIALIZATION_FAILURE = 1 [(metadata) = { exit_code: 36 }];
-    EXECUTION_IO_EXCEPTION = 2 [(metadata) = { exit_code: 36 }];
-    DOCKER_COMMAND_FAILURE = 3 [(metadata) = { exit_code: 1 }];
-    NO_DOCKER_IMAGE = 4 [(metadata) = { exit_code: 1 }];
-    DOCKER_IMAGE_PREPARATION_FAILURE = 5 [(metadata) = { exit_code: 1 }];
-    BIND_MOUNT_ANALYSIS_FAILURE = 6 [(metadata) = { exit_code: 1 }];
-    MOUNT_SOURCE_DOES_NOT_EXIST = 7 [(metadata) = { exit_code: 1 }];
-    MOUNT_SOURCE_TARGET_TYPE_MISMATCH = 8 [(metadata) = { exit_code: 1 }];
-    MOUNT_TARGET_DOES_NOT_EXIST = 9 [(metadata) = { exit_code: 1 }];
-    SUBPROCESS_START_FAILED = 10 [(metadata) = { exit_code: 36 }];
-    FORBIDDEN_INPUT = 11 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message IncludeScanning {
-  enum Code {
-    INCLUDE_SCANNING_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INITIALIZE_INCLUDE_HINTS_ERROR = 1 [(metadata) = { exit_code: 36 }];
-    SCANNING_IO_EXCEPTION = 2 [(metadata) = { exit_code: 36 }];
-    INCLUDE_HINTS_FILE_NOT_IN_PACKAGE = 3 [(metadata) = { exit_code: 36 }];
-    INCLUDE_HINTS_READ_FAILURE = 4 [(metadata) = { exit_code: 36 }];
-    ILLEGAL_ABSOLUTE_PATH = 5 [(metadata) = { exit_code: 1 }];
-    // TODO(b/166268889): this code should be deprecated in favor of more finely
-    //  resolved loading-phase codes.
-    PACKAGE_LOAD_FAILURE = 6 [(metadata) = { exit_code: 1 }];
-    USER_PACKAGE_LOAD_FAILURE = 7 [(metadata) = { exit_code: 1 }];
-    SYSTEM_PACKAGE_LOAD_FAILURE = 8 [(metadata) = { exit_code: 36 }];
-    UNDIFFERENTIATED_PACKAGE_LOAD_FAILURE = 9 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-  PackageLoading.Code package_loading_code = 2;
-}
-
-message TestCommand {
-  enum Code {
-    TEST_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NO_TEST_TARGETS = 1 [(metadata) = { exit_code: 4 }];
-    TEST_WITH_NOANALYZE = 2 [(metadata) = { exit_code: 1 }];
-    TESTS_FAILED = 3 [(metadata) = { exit_code: 3 }];
-  }
-
-  Code code = 1;
-}
-
-message ActionQuery {
-  // All numerical exit code associations correspond to pre-existing Bazel
-  // behavior. These associations are suspicious:
-  // - COMMAND_LINE_EXPANSION_FAILURE: this is associated with 2, the numerical
-  //     exit code for "bad Bazel command line", but is generated when an
-  //     action's command line fails to expand, which sounds similar but is
-  //     completely different.
-  // - OUTPUT_FAILURE: this is associated with 6, an undocumented exit code.
-  // - INVALID_AQUERY_EXPRESSION: this is associate with 1, which is not
-  //    documented for (a)query.
-  // TODO(b/138456686): Revise these after the (intentionally non-breaking)
-  //  initial rollout of FailureDetail-based encoding.
-  enum Code {
-    ACTION_QUERY_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 1 [(metadata) = { exit_code: 2 }];
-    OUTPUT_FAILURE = 2 [(metadata) = { exit_code: 6 }];
-    COMMAND_LINE_EXPRESSION_MISSING = 3 [(metadata) = { exit_code: 2 }];
-    EXPRESSION_PARSE_FAILURE = 4 [(metadata) = { exit_code: 2 }];
-    SKYFRAME_STATE_WITH_COMMAND_LINE_EXPRESSION = 5
-        [(metadata) = { exit_code: 2 }];
-    INVALID_AQUERY_EXPRESSION = 6 [(metadata) = { exit_code: 1 }];
-    SKYFRAME_STATE_PREREQ_UNMET = 7 [(metadata) = { exit_code: 2 }];
-    AQUERY_OUTPUT_TOO_BIG = 8 [(metadata) = { exit_code: 7 }];
-    ILLEGAL_PATTERN_SYNTAX = 9 [(metadata) = { exit_code: 2 }];
-    INCORRECT_ARGUMENTS = 10 [(metadata) = { exit_code: 2 }];
-    TOP_LEVEL_TARGETS_WITH_SKYFRAME_STATE_NOT_SUPPORTED = 11
-        [(metadata) = { exit_code: 2 }];
-    SKYFRAME_STATE_AFTER_EXECUTION = 12 [(metadata) = { exit_code: 1 }];
-    LABELS_FUNCTION_NOT_SUPPORTED = 13 [(metadata) = { exit_code: 2 }];
-    TEMPLATE_EXPANSION_FAILURE = 14 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message TargetPatterns {
-  enum Code {
-    TARGET_PATTERNS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    TARGET_PATTERN_FILE_WITH_COMMAND_LINE_PATTERN = 1
-        [(metadata) = { exit_code: 2 }];
-    TARGET_PATTERN_FILE_READ_FAILURE = 2 [(metadata) = { exit_code: 2 }];
-    TARGET_PATTERN_PARSE_FAILURE = 3 [(metadata) = { exit_code: 1 }];
-    PACKAGE_NOT_FOUND = 4 [(metadata) = { exit_code: 1 }];
-    TARGET_FORMAT_INVALID = 5 [(metadata) = { exit_code: 1 }];
-    ABSOLUTE_TARGET_PATTERN_INVALID = 6 [(metadata) = { exit_code: 1 }];
-    CANNOT_DETERMINE_TARGET_FROM_FILENAME = 7 [(metadata) = { exit_code: 1 }];
-    LABEL_SYNTAX_ERROR = 8 [(metadata) = { exit_code: 1 }];
-    TARGET_CANNOT_BE_EMPTY_STRING = 9 [(metadata) = { exit_code: 1 }];
-    PACKAGE_PART_CANNOT_END_IN_SLASH = 10 [(metadata) = { exit_code: 1 }];
-    CYCLE = 11 [(metadata) = { exit_code: 1 }];
-    CANNOT_PRELOAD_TARGET = 12 [(metadata) = { exit_code: 1 }];
-    TARGETS_MISSING = 13 [(metadata) = { exit_code: 1 }];
-    RECURSIVE_TARGET_PATTERNS_NOT_ALLOWED = 14 [(metadata) = { exit_code: 1 }];
-    UP_LEVEL_REFERENCES_NOT_ALLOWED = 15 [(metadata) = { exit_code: 1 }];
-    NEGATIVE_TARGET_PATTERN_NOT_ALLOWED = 16 [(metadata) = { exit_code: 1 }];
-    TARGET_MUST_BE_A_FILE = 17 [(metadata) = { exit_code: 1 }];
-    DEPENDENCY_NOT_FOUND = 18 [(metadata) = { exit_code: 1 }];
-    PACKAGE_NAME_INVALID = 19 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message CleanCommand {
-  enum Code {
-    CLEAN_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    OUTPUT_SERVICE_CLEAN_FAILURE = 1 [(metadata) = { exit_code: 6 }];
-    ACTION_CACHE_CLEAN_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-    OUT_ERR_CLOSE_FAILURE = 3 [(metadata) = { exit_code: 36 }];
-    OUTPUT_BASE_DELETE_FAILURE = 4 [(metadata) = { exit_code: 36 }];
-    OUTPUT_BASE_TEMP_MOVE_FAILURE = 5 [(metadata) = { exit_code: 36 }];
-    ASYNC_OUTPUT_BASE_DELETE_FAILURE = 6 [(metadata) = { exit_code: 6 }];
-    EXECROOT_DELETE_FAILURE = 7 [(metadata) = { exit_code: 36 }];
-    EXECROOT_TEMP_MOVE_FAILURE = 8 [(metadata) = { exit_code: 36 }];
-    ASYNC_EXECROOT_DELETE_FAILURE = 9 [(metadata) = { exit_code: 6 }];
-    ARGUMENTS_NOT_RECOGNIZED = 10 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message ConfigCommand {
-  enum Code {
-    CONFIG_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    TOO_MANY_CONFIG_IDS = 1 [(metadata) = { exit_code: 2 }];
-    CONFIGURATION_NOT_FOUND = 2 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message ConfigurableQuery {
-  enum Code {
-    CONFIGURABLE_QUERY_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    COMMAND_LINE_EXPRESSION_MISSING = 1 [(metadata) = { exit_code: 2 }];
-    EXPRESSION_PARSE_FAILURE = 2 [(metadata) = { exit_code: 2 }];
-    FILTERS_NOT_SUPPORTED = 3 [(metadata) = { exit_code: 2 }];
-    BUILDFILES_FUNCTION_NOT_SUPPORTED = 4 [(metadata) = { exit_code: 2 }];
-    SIBLINGS_FUNCTION_NOT_SUPPORTED = 5 [(metadata) = { exit_code: 2 }];
-    VISIBLE_FUNCTION_NOT_SUPPORTED = 6 [(metadata) = { exit_code: 2 }];
-    ATTRIBUTE_MISSING = 7 [(metadata) = { exit_code: 2 }];
-    INCORRECT_CONFIG_ARGUMENT_ERROR = 8 [(metadata) = { exit_code: 2 }];
-    TARGET_MISSING = 9 [(metadata) = { exit_code: 2 }];
-    STARLARK_SYNTAX_ERROR = 10 [(metadata) = { exit_code: 2 }];
-    STARLARK_EVAL_ERROR = 11 [(metadata) = { exit_code: 2 }];
-    // Indicates failure to correctly define a format function
-    FORMAT_FUNCTION_ERROR = 12 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message DumpCommand {
-  enum Code {
-    DUMP_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NO_OUTPUT_SPECIFIED = 1 [(metadata) = { exit_code: 7 }];
-    ACTION_CACHE_DUMP_FAILED = 2 [(metadata) = { exit_code: 7 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 3 [(metadata) = { exit_code: 7 }];
-    ACTION_GRAPH_DUMP_FAILED = 4 [(metadata) = { exit_code: 7 }];
-    STARLARK_HEAP_DUMP_FAILED = 5 [(metadata) = { exit_code: 8 }];
-     reserved 6; // For internal use
-  }
-
-  Code code = 1;
-}
-
-message HelpCommand {
-  enum Code {
-    HELP_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    MISSING_ARGUMENT = 1 [(metadata) = { exit_code: 2 }];
-    COMMAND_NOT_FOUND = 2 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message MobileInstall {
-  enum Code {
-    MOBILE_INSTALL_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    CLASSIC_UNSUPPORTED = 1 [(metadata) = { exit_code: 2 }];
-    NO_TARGET_SPECIFIED = 2 [(metadata) = { exit_code: 2 }];
-    MULTIPLE_TARGETS_SPECIFIED = 3 [(metadata) = { exit_code: 2 }];
-    TARGET_TYPE_INVALID = 4 [(metadata) = { exit_code: 6 }];
-    NON_ZERO_EXIT = 5 [(metadata) = { exit_code: 6 }];
-    ERROR_RUNNING_PROGRAM = 6 [(metadata) = { exit_code: 6 }];
-  }
-
-  Code code = 1;
-}
-
-message ProfileCommand {
-  enum Code {
-    PROFILE_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    OLD_BINARY_FORMAT_UNSUPPORTED = 1 [(metadata) = { exit_code: 1 }];
-    FILE_READ_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message RunCommand {
-  enum Code {
-    RUN_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NO_TARGET_SPECIFIED = 1 [(metadata) = { exit_code: 2 }];
-    TOO_MANY_TARGETS_SPECIFIED = 2 [(metadata) = { exit_code: 2 }];
-    TARGET_NOT_EXECUTABLE = 3 [(metadata) = { exit_code: 2 }];
-    TARGET_BUILT_BUT_PATH_NOT_EXECUTABLE = 4 [(metadata) = { exit_code: 1 }];
-    TARGET_BUILT_BUT_PATH_VALIDATION_FAILED = 5
-        [(metadata) = { exit_code: 36 }];
-    RUN_UNDER_TARGET_NOT_BUILT = 6 [(metadata) = { exit_code: 2 }];
-    RUN_PREREQ_UNMET = 7 [(metadata) = { exit_code: 2 }];
-    TOO_MANY_TEST_SHARDS_OR_RUNS = 8 [(metadata) = { exit_code: 2 }];
-    TEST_ENVIRONMENT_SETUP_FAILURE = 9 [(metadata) = { exit_code: 36 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 10 [(metadata) = { exit_code: 36 }];
-    NO_SHELL_SPECIFIED = 11 [(metadata) = { exit_code: 2 }];
-    SCRIPT_WRITE_FAILURE = 12 [(metadata) = { exit_code: 6 }];
-    RUNFILES_DIRECTORIES_CREATION_FAILURE = 13 [(metadata) = { exit_code: 36 }];
-    RUNFILES_SYMLINKS_CREATION_FAILURE = 14 [(metadata) = { exit_code: 36 }];
-    TEST_ENVIRONMENT_SETUP_INTERRUPTED = 15 [(metadata) = { exit_code: 8 }];
-  }
-
-  Code code = 1;
-}
-
-message VersionCommand {
-  enum Code {
-    VERSION_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NOT_AVAILABLE = 1 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message PrintActionCommand {
-  enum Code {
-    PRINT_ACTION_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    TARGET_NOT_FOUND = 1 [(metadata) = { exit_code: 1 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-    TARGET_KIND_UNSUPPORTED = 3 [(metadata) = { exit_code: 1 }];
-    ACTIONS_NOT_FOUND = 4 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message WorkspaceStatus {
-  enum Code {
-    WORKSPACE_STATUS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NON_ZERO_EXIT = 1 [(metadata) = { exit_code: 1 }];
-    ABNORMAL_TERMINATION = 2 [(metadata) = { exit_code: 1 }];
-    EXEC_FAILED = 3 [(metadata) = { exit_code: 1 }];
-    PARSE_FAILURE = 4 [(metadata) = { exit_code: 36 }];
-    VALIDATION_FAILURE = 5 [(metadata) = { exit_code: 1 }];
-    CONTENT_UPDATE_IO_EXCEPTION = 6 [(metadata) = { exit_code: 1 }];
-    STDERR_IO_EXCEPTION = 7 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message JavaCompile {
-  enum Code {
-    JAVA_COMPILE_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    REDUCED_CLASSPATH_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-    JDEPS_READ_IO_EXCEPTION = 3 [(metadata) = { exit_code: 36 }];
-    REDUCED_CLASSPATH_FALLBACK_CLEANUP_FAILURE = 4
-        [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message ActionRewinding {
-  enum Code {
-    ACTION_REWINDING_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    LOST_INPUT_TOO_MANY_TIMES = 1 [(metadata) = { exit_code: 1 }];
-    LOST_INPUT_IS_SOURCE = 2 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message CppCompile {
-  enum Code {
-    CPP_COMPILE_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    FIND_USED_HEADERS_IO_EXCEPTION = 1 [(metadata) = { exit_code: 36 }];
-    COPY_OUT_ERR_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-    D_FILE_READ_FAILURE = 3 [(metadata) = { exit_code: 36 }];
-    COMMAND_GENERATION_FAILURE = 4 [(metadata) = { exit_code: 1 }];
-    MODULE_EXPANSION_TIMEOUT = 5 [(metadata) = { exit_code: 1 }];
-    INCLUDE_PATH_OUTSIDE_EXEC_ROOT = 6 [(metadata) = { exit_code: 1 }];
-    FAKE_COMMAND_GENERATION_FAILURE = 7 [(metadata) = { exit_code: 1 }];
-    UNDECLARED_INCLUSIONS = 8 [(metadata) = { exit_code: 1 }];
-    D_FILE_PARSE_FAILURE = 9 [(metadata) = { exit_code: 1 }];
-    COVERAGE_NOTES_CREATION_FAILURE = 10 [(metadata) = { exit_code: 1 }];
-    MODULE_EXPANSION_MISSING_DATA = 11 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message StarlarkAction {
-  enum Code {
-    STARLARK_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    UNUSED_INPUT_LIST_READ_FAILURE = 1 [(metadata) = { exit_code: 36 }];
-    UNUSED_INPUT_LIST_FILE_NOT_FOUND = 2 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message NinjaAction {
-  enum Code {
-    NINJA_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INVALID_DEPFILE_DECLARED_DEPENDENCY = 1 [(metadata) = { exit_code: 36 }];
-    D_FILE_PARSE_FAILURE = 2 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message DynamicExecution {
-  enum Code {
-    DYNAMIC_EXECUTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    XCODE_RELATED_PREREQ_UNMET = 1 [(metadata) = { exit_code: 36 }];
-    ACTION_LOG_MOVE_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-    RUN_FAILURE = 3 [(metadata) = { exit_code: 1 }];
-    NO_USABLE_STRATEGY_FOUND = 4 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
-
-message FailAction {
-  enum Code {
-    FAIL_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INTENTIONAL_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    INCORRECT_PYTHON_VERSION = 2 [(metadata) = { exit_code: 1 }];
-    PROGUARD_SPECS_MISSING = 3 [(metadata) = { exit_code: 1 }];
-    DYNAMIC_LINKING_NOT_SUPPORTED = 4 [(metadata) = { exit_code: 1 }];
-    SOURCE_FILES_MISSING = 5 [(metadata) = { exit_code: 1 }];
-    INCORRECT_TOOLCHAIN = 6 [(metadata) = { exit_code: 1 }];
-    FRAGMENT_CLASS_MISSING = 7 [(metadata) = { exit_code: 1 }];
-    reserved 8, 9; // For internal use
-    CANT_BUILD_INCOMPATIBLE_TARGET = 10 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message SymlinkAction {
-  enum Code {
-    SYMLINK_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    EXECUTABLE_INPUT_NOT_FILE = 1 [(metadata) = { exit_code: 1 }];
-    EXECUTABLE_INPUT_IS_NOT = 2 [(metadata) = { exit_code: 1 }];
-    EXECUTABLE_INPUT_CHECK_IO_EXCEPTION = 3 [(metadata) = { exit_code: 1 }];
-    LINK_CREATION_IO_EXCEPTION = 4 [(metadata) = { exit_code: 1 }];
-    LINK_TOUCH_IO_EXCEPTION = 5 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message CppLink {
-  enum Code {
-    CPP_LINK_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    COMMAND_GENERATION_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    FAKE_COMMAND_GENERATION_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message LtoAction {
-  enum Code {
-    LTO_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    INVALID_ABSOLUTE_PATH_IN_IMPORTS = 1 [(metadata) = { exit_code: 1 }];
-    MISSING_BITCODE_FILES = 2 [(metadata) = { exit_code: 1 }];
-    IMPORTS_READ_IO_EXCEPTION = 3 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message TestAction {
-  enum Code {
-    TEST_ACTION_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    NO_KEEP_GOING_TEST_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    LOCAL_TEST_PREREQ_UNMET = 2 [(metadata) = { exit_code: 1 }];
-    COMMAND_LINE_EXPANSION_FAILURE = 3 [(metadata) = { exit_code: 1 }];
-    DUPLICATE_CPU_TAGS = 4 [(metadata) = { exit_code: 1 }];
-    INVALID_CPU_TAG = 5 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message Worker {
-  enum Code {
-    WORKER_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    MULTIPLEXER_INSTANCE_REMOVAL_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    MULTIPLEXER_DOES_NOT_EXIST = 2 [(metadata) = { exit_code: 1 }];
-    NO_TOOLS = 3 [(metadata) = { exit_code: 1 }];
-    NO_FLAGFILE = 4 [(metadata) = { exit_code: 1 }];
-    VIRTUAL_INPUT_MATERIALIZATION_FAILURE = 5 [(metadata) = { exit_code: 1 }];
-    BORROW_FAILURE = 6 [(metadata) = { exit_code: 1 }];
-    PREFETCH_FAILURE = 7 [(metadata) = { exit_code: 36 }];
-    PREPARE_FAILURE = 8 [(metadata) = { exit_code: 1 }];
-    REQUEST_FAILURE = 9 [(metadata) = { exit_code: 1 }];
-    PARSE_RESPONSE_FAILURE = 10 [(metadata) = { exit_code: 1 }];
-    NO_RESPONSE = 11 [(metadata) = { exit_code: 1 }];
-    FINISH_FAILURE = 12 [(metadata) = { exit_code: 1 }];
-    FORBIDDEN_INPUT = 13 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message Analysis {
-  enum Code {
-    ANALYSIS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    LOAD_FAILURE = 1 [(metadata) = { exit_code: 1 }];
-    // TODO(b/138456686): this code should be deprecated in favor of more finely
-    //   resolved loading-phase codes.
-    GENERIC_LOADING_PHASE_FAILURE = 2 [(metadata) = { exit_code: 1 }];
-    NOT_ALL_TARGETS_ANALYZED = 3 [(metadata) = { exit_code: 1 }];
-    CYCLE = 4 [(metadata) = { exit_code: 1 }];
-    PARAMETERIZED_TOP_LEVEL_ASPECT_INVALID = 5 [(metadata) = { exit_code: 1 }];
-    ASPECT_LABEL_SYNTAX_ERROR = 6 [(metadata) = { exit_code: 1 }];
-    ASPECT_PREREQ_UNMET = 7 [(metadata) = { exit_code: 1 }];
-    ASPECT_NOT_FOUND = 8 [(metadata) = { exit_code: 1 }];
-    ACTION_CONFLICT = 9 [(metadata) = { exit_code: 1 }];
-    ARTIFACT_PREFIX_CONFLICT = 10 [(metadata) = { exit_code: 1 }];
-    UNEXPECTED_ANALYSIS_EXCEPTION = 11 [(metadata) = { exit_code: 1 }];
-    TARGETS_MISSING_ENVIRONMENTS = 12 [(metadata) = { exit_code: 1 }];
-    INVALID_ENVIRONMENT = 13 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_MISSING_FROM_GROUPS = 14 [(metadata) = { exit_code: 1 }];
-    EXEC_GROUP_MISSING = 15 [(metadata) = { exit_code: 1 }];
-    INVALID_EXECUTION_PLATFORM = 16 [(metadata) = { exit_code: 1 }];
-    ASPECT_CREATION_FAILED = 17 [(metadata) = { exit_code: 1 }];
-    CONFIGURED_VALUE_CREATION_FAILED = 18 [(metadata) = { exit_code: 1 }];
-    INCOMPATIBLE_TARGET_REQUESTED = 19 [(metadata) = { exit_code: 1 }];
-    ANALYSIS_FAILURE_PROPAGATION_FAILED = 20 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message PackageLoading {
-  enum Code {
-    PACKAGE_LOADING_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    WORKSPACE_FILE_ERROR = 1 [(metadata) = { exit_code: 1 }];
-    MAX_COMPUTATION_STEPS_EXCEEDED = 2 [(metadata) = { exit_code: 1 }];
-    BUILD_FILE_MISSING = 3 [(metadata) = { exit_code: 1 }];
-    REPOSITORY_MISSING = 4 [(metadata) = { exit_code: 1 }];
-    PERSISTENT_INCONSISTENT_FILESYSTEM_ERROR = 5
-        [(metadata) = { exit_code: 36 }];
-    TRANSIENT_INCONSISTENT_FILESYSTEM_ERROR = 6
-        [(metadata) = { exit_code: 36 }];
-    INVALID_NAME = 7 [(metadata) = { exit_code: 1 }];
-    // was: PRELUDE_FILE_READ_ERROR. Replaced by IMPORT_STARLARK_FILE_ERROR
-    // when the prelude was changed to be loaded as a Starlark module.
-    reserved 8;
-    EVAL_GLOBS_SYMLINK_ERROR = 9 [(metadata) = { exit_code: 1 }];
-    IMPORT_STARLARK_FILE_ERROR = 10 [(metadata) = { exit_code: 1 }];
-    PACKAGE_MISSING = 11 [(metadata) = { exit_code: 1 }];
-    TARGET_MISSING = 12 [(metadata) = { exit_code: 1 }];
-    NO_SUCH_THING = 13 [(metadata) = { exit_code: 1 }];
-    GLOB_IO_EXCEPTION = 14 [(metadata) = { exit_code: 36 }];
-    DUPLICATE_LABEL = 15 [(metadata) = { exit_code: 1 }];
-    INVALID_PACKAGE_SPECIFICATION = 16 [(metadata) = { exit_code: 1 }];
-    SYNTAX_ERROR = 17 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_IN_DIFFERENT_PACKAGE = 18 [(metadata) = { exit_code: 1 }];
-    DEFAULT_ENVIRONMENT_UNDECLARED = 19 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_IN_MULTIPLE_GROUPS = 20 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_DOES_NOT_EXIST = 21 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_INVALID = 22 [(metadata) = { exit_code: 1 }];
-    ENVIRONMENT_NOT_IN_GROUP = 23 [(metadata) = { exit_code: 1 }];
-    PACKAGE_NAME_INVALID = 24 [(metadata) = { exit_code: 1 }];
-    STARLARK_EVAL_ERROR = 25 [(metadata) = { exit_code: 1 }];
-    LICENSE_PARSE_FAILURE = 26 [(metadata) = { exit_code: 1 }];
-    DISTRIBUTIONS_PARSE_FAILURE = 27 [(metadata) = { exit_code: 1 }];
-    LABEL_CROSSES_PACKAGE_BOUNDARY = 28 [(metadata) = { exit_code: 1 }];
-    // Failure while evaluating or applying @_builtins injection. Since the
-    // builtins .bzl files are always packaged with Blaze in production, a
-    // failure here generally indicates a bug in Blaze.
-    BUILTINS_INJECTION_FAILURE = 29 [(metadata) = { exit_code: 1 }];
-    SYMLINK_CYCLE_OR_INFINITE_EXPANSION = 30 [(metadata) = { exit_code: 1 }];
-    OTHER_IO_EXCEPTION = 31 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message Toolchain {
-  enum Code {
-    TOOLCHAIN_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    MISSING_PROVIDER = 1 [(metadata) = { exit_code: 1 }];
-    INVALID_CONSTRAINT_VALUE = 2 [(metadata) = { exit_code: 1 }];
-    INVALID_PLATFORM_VALUE = 3 [(metadata) = { exit_code: 1 }];
-    INVALID_TOOLCHAIN = 4 [(metadata) = { exit_code: 1 }];
-    NO_MATCHING_EXECUTION_PLATFORM = 5 [(metadata) = { exit_code: 1 }];
-    NO_MATCHING_TOOLCHAIN = 6 [(metadata) = { exit_code: 1 }];
-    INVALID_TOOLCHAIN_TYPE = 7 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message StarlarkLoading {
-  enum Code {
-    STARLARK_LOADING_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    CYCLE = 1 [(metadata) = { exit_code: 1 }];
-    COMPILE_ERROR = 2 [(metadata) = { exit_code: 1 }];
-    PARSE_ERROR = 3 [(metadata) = { exit_code: 1 }];
-    EVAL_ERROR = 4 [(metadata) = { exit_code: 1 }];
-    CONTAINING_PACKAGE_NOT_FOUND = 5 [(metadata) = { exit_code: 1 }];
-    PACKAGE_NOT_FOUND = 6 [(metadata) = { exit_code: 1 }];
-    IO_ERROR = 7 [(metadata) = { exit_code: 1 }];
-    LABEL_CROSSES_PACKAGE_BOUNDARY = 8 [(metadata) = { exit_code: 1 }];
-    BUILTINS_ERROR = 9 [(metadata) = { exit_code: 1 }];
-    VISIBILITY_ERROR = 10 [(metadata) = { exit_code: 1 }];
-  }
-
-  Code code = 1;
-}
-
-message ExternalDeps {
-  enum Code {
-    EXTERNAL_DEPS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    MODULE_NOT_FOUND = 1 [(metadata) = { exit_code: 48 }];
-    BAD_MODULE = 2 [(metadata) = { exit_code: 48 }];
-    VERSION_RESOLUTION_ERROR = 3 [(metadata) = { exit_code: 48 }];
-    INVALID_REGISTRY_URL = 4 [(metadata) = { exit_code: 48 }];
-    ERROR_ACCESSING_REGISTRY = 5 [(metadata) = { exit_code: 32 }];
-  }
-
-  Code code = 1;
-}
-
-message DiffAwareness {
-  enum Code {
-    DIFF_AWARENESS_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    DIFF_STAT_FAILED = 1 [(metadata) = { exit_code: 36 }];
-  }
-
-  Code code = 1;
-}
-
-message ModqueryCommand {
-  enum Code {
-    MODQUERY_COMMAND_UNKNOWN = 0 [(metadata) = { exit_code: 37 }];
-    MISSING_ARGUMENTS = 1 [(metadata) = { exit_code: 2 }];
-    TOO_MANY_ARGUMENTS = 2 [(metadata) = { exit_code: 2 }];
-    INVALID_ARGUMENTS = 3 [(metadata) = { exit_code: 2 }];
-  }
-
-  Code code = 1;
-}
diff --git a/atest/bazel/runner/src/main/protobuf/invocation_policy.proto b/atest/bazel/runner/src/main/protobuf/invocation_policy.proto
deleted file mode 100644
index f54a0f5f..00000000
--- a/atest/bazel/runner/src/main/protobuf/invocation_policy.proto
+++ /dev/null
@@ -1,202 +0,0 @@
-// Copyright 2015 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-syntax = "proto2";
-package blaze.invocation_policy;
-
-// option java_api_version = 2;
-option java_package = "com.google.devtools.build.lib.runtime.proto";
-
-// The --invocation_policy flag takes a base64-encoded binary-serialized or text
-// formatted InvocationPolicy message.
-message InvocationPolicy {
-  // Order matters.
-  // After expanding policies on expansion flags or flags with implicit
-  // requirements, only the final policy on a specific flag will be enforced
-  // onto the user's command line.
-  repeated FlagPolicy flag_policies = 1;
-}
-
-// A policy for controlling the value of a flag.
-message FlagPolicy {
-  // The name of the flag to enforce this policy on.
-  //
-  // Note that this should be the full name of the flag, not the abbreviated
-  // name of the flag. If the user specifies the abbreviated name of a flag,
-  // that flag will be matched using its full name.
-  //
-  // The "no" prefix will not be parsed, so for boolean flags, use
-  // the flag's full name and explicitly set it to true or false.
-  optional string flag_name = 1;
-
-  // If set, this flag policy is applied only if one of the given commands or a
-  // command that inherits from one of the given commands is being run. For
-  // instance, if "build" is one of the commands here, then this policy will
-  // apply to any command that inherits from build, such as info, coverage, or
-  // test. If empty, this flag policy is applied for all commands. This allows
-  // the policy setter to add all policies to the proto without having to
-  // determine which Bazel command the user is actually running. Additionally,
-  // Bazel allows multiple flags to be defined by the same name, and the
-  // specific flag definition is determined by the command.
-  repeated string commands = 2;
-
-  oneof operation {
-    SetValue set_value = 3;
-    UseDefault use_default = 4;
-    DisallowValues disallow_values = 5;
-    AllowValues allow_values = 6;
-  }
-}
-
-message SetValue {
-  // Use this value for the specified flag, overriding any default or user-set
-  // value (unless behavior = APPEND for repeatable flags).
-  //
-  // This field is repeated for repeatable flags. It is an error to set
-  // multiple values for a flag that is not actually a repeatable flag.
-  // This requires at least 1 value, if even the empty string.
-  //
-  // If the flag allows multiple values, all of its values are replaced with the
-  // value or values from the policy (i.e., no diffing or merging is performed),
-  // unless behavior = APPEND (see below).
-  //
-  // Note that some flags are tricky. For example, some flags look like boolean
-  // flags, but are actually Void expansion flags that expand into other flags.
-  // The Bazel flag parser will accept "--void_flag=false", but because
-  // the flag is Void, the "=false" is ignored. It can get even trickier, like
-  // "--novoid_flag" which is also an expansion flag with the type Void whose
-  // name is explicitly "novoid_flag" and which expands into other flags that
-  // are the opposite of "--void_flag". For expansion flags, it's best to
-  // explicitly override the flags they expand into.
-  //
-  // Other flags may be differently tricky: A flag could have a converter that
-  // converts some string to a list of values, but that flag may not itself have
-  // allowMultiple set to true.
-  //
-  // An example is "--test_tag_filters": this flag sets its converter to
-  // CommaSeparatedOptionListConverter, but does not set allowMultiple to true.
-  // So "--test_tag_filters=foo,bar" results in ["foo", "bar"], however
-  // "--test_tag_filters=foo --test_tag_filters=bar" results in just ["bar"]
-  // since the 2nd value overrides the 1st.
-  //
-  // Similarly, "--test_tag_filters=foo,bar --test_tag_filters=baz,qux" results
-  // in ["baz", "qux"]. For flags like these, the policy should specify
-  // "foo,bar" instead of separately specifying "foo" and "bar" so that the
-  // converter is appropriately invoked.
-  //
-  // Note that the opposite is not necessarily
-  // true: for a flag that specifies allowMultiple=true, "--flag=foo,bar"
-  // may fail to parse or result in an unexpected value.
-  repeated string flag_value = 1;
-
-  // Obsolete overridable and append fields.
-  reserved 2, 3;
-
-  enum Behavior {
-    UNDEFINED = 0;
-    // Change the flag value but allow it to be overridden by explicit settings
-    // from command line/config expansion/rc files.
-    // Matching old flag values: append = false, overridable = true.
-    ALLOW_OVERRIDES = 1;
-    // Append a new value for a repeatable flag, leave old values and allow
-    // further overrides.
-    // Matching old flag values: append = true, overridable = false.
-    APPEND = 2;
-    // Set a final value of the flag. Any overrides provided by the user for
-    // this flag will be ignored.
-    // Matching old flag values: append = false, overridable = false.
-    FINAL_VALUE_IGNORE_OVERRIDES = 3;
-  }
-
-  // Defines how invocation policy should interact with user settings for the
-  // same flag.
-  optional Behavior behavior = 4;
-}
-
-message UseDefault {
-  // Use the default value of the flag, as defined by Bazel (or equivalently, do
-  // not allow the user to set this flag).
-  //
-  // Note on implementation: UseDefault sets the default by clearing the flag,
-  // so that when the value is requested and no flag is found, the flag parser
-  // returns the default. This is mostly relevant for expansion flags: it will
-  // erase user values in *all* flags that the expansion flag expands to. Only
-  // use this on expansion flags if this is acceptable behavior. Since the last
-  // policy wins, later policies on this same flag will still remove the
-  // expanded UseDefault, so there is a way around, but it's really best not to
-  // use this on expansion flags at all.
-}
-
-message DisallowValues {
-  // Obsolete new_default_value field.
-  reserved 2;
-
-  // It is an error for the user to use any of these values (that is, the Bazel
-  // command will fail), unless new_value or use_default is set.
-  //
-  // For repeatable flags, if any one of the values in the flag matches a value
-  // in the list of disallowed values, an error is thrown.
-  //
-  // Care must be taken for flags with complicated converters. For example,
-  // it's possible for a repeated flag to be of type List<List<T>>, so that
-  // "--foo=a,b --foo=c,d" results in foo=[["a","b"], ["c", "d"]]. In this case,
-  // it is not possible to disallow just "b", nor will ["b", "a"] match, nor
-  // will ["b", "c"] (but ["a", "b"] will still match).
-  repeated string disallowed_values = 1;
-
-  oneof replacement_value {
-    // If set and if the value of the flag is disallowed (including the default
-    // value of the flag if the user doesn't specify a value), use this value as
-    // the value of the flag instead of raising an error. This does not apply to
-    // repeatable flags and is ignored if the flag is a repeatable flag.
-    string new_value = 3;
-
-    // If set and if the value of the flag is disallowed, use the default value
-    // of the flag instead of raising an error. Unlike new_value, this works for
-    // repeatable flags, but note that the default value for repeatable flags is
-    // always empty.
-    //
-    // Note that it is an error to disallow the default value of the flag and
-    // to set use_default, unless the flag is a repeatable flag where the
-    // default value is always the empty list.
-    UseDefault use_default = 4;
-  }
-}
-
-message AllowValues {
-  // Obsolete new_default_value field.
-  reserved 2;
-
-  // It is an error for the user to use any value not in this list, unless
-  // new_value or use_default is set.
-  repeated string allowed_values = 1;
-
-  oneof replacement_value {
-    // If set and if the value of the flag is disallowed (including the default
-    // value of the flag if the user doesn't specify a value), use this value as
-    // the value of the flag instead of raising an error. This does not apply to
-    // repeatable flags and is ignored if the flag is a repeatable flag.
-    string new_value = 3;
-
-    // If set and if the value of the flag is disallowed, use the default value
-    // of the flag instead of raising an error. Unlike new_value, this works for
-    // repeatable flags, but note that the default value for repeatable flags is
-    // always empty.
-    //
-    // Note that it is an error to disallow the default value of the flag and
-    // to set use_default, unless the flag is a repeatable flag where the
-    // default value is always the empty list.
-    UseDefault use_default = 4;
-  }
-}
diff --git a/atest/bazel/runner/src/main/protobuf/option_filters.proto b/atest/bazel/runner/src/main/protobuf/option_filters.proto
deleted file mode 100644
index d931083c..00000000
--- a/atest/bazel/runner/src/main/protobuf/option_filters.proto
+++ /dev/null
@@ -1,59 +0,0 @@
-// Copyright 2017 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-syntax = "proto3";
-
-package options;
-
-// option java_api_version = 2;
-option java_package = "com.google.devtools.common.options.proto";
-
-// IMPORTANT NOTE: These two enums must be kept in sync with their Java
-// equivalents in src/main/java/com/google/devtools/common/options.
-// Changing this proto has specific compatibility requirements, please see the
-// Java documentation for details.
-
-// Docs in java enum.
-enum OptionEffectTag {
-  // This option's effect or intent is unknown.
-  UNKNOWN = 0;
-
-  // This flag has literally no effect.
-  NO_OP = 1;
-
-  LOSES_INCREMENTAL_STATE = 2;
-  CHANGES_INPUTS = 3;
-  AFFECTS_OUTPUTS = 4;
-  BUILD_FILE_SEMANTICS = 5;
-  BAZEL_INTERNAL_CONFIGURATION = 6;
-  LOADING_AND_ANALYSIS = 7;
-  EXECUTION = 8;
-  HOST_MACHINE_RESOURCE_OPTIMIZATIONS = 9;
-  EAGERNESS_TO_EXIT = 10;
-  BAZEL_MONITORING = 11;
-  TERMINAL_OUTPUT = 12;
-  ACTION_COMMAND_LINES = 13;
-  TEST_RUNNER = 14;
-}
-
-// Docs in java enum.
-enum OptionMetadataTag {
-  EXPERIMENTAL = 0;
-  INCOMPATIBLE_CHANGE = 1;
-  DEPRECATED = 2;
-  HIDDEN = 3;
-  INTERNAL = 4;
-  reserved "TRIGGERED_BY_ALL_INCOMPATIBLE_CHANGES";
-  reserved 5;
-  EXPLICIT_IN_OUTPUT_PATH = 6;
-}
diff --git a/atest/bazel/runner/tests/src/com/android/tradefed/testtype/bazel/BazelTestTest.java b/atest/bazel/runner/tests/src/com/android/tradefed/testtype/bazel/BazelTestTest.java
deleted file mode 100644
index ae21d8eb..00000000
--- a/atest/bazel/runner/tests/src/com/android/tradefed/testtype/bazel/BazelTestTest.java
+++ /dev/null
@@ -1,1126 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.tradefed.testtype.bazel;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.anyLong;
-import static org.mockito.Mockito.anyMap;
-import static org.mockito.Mockito.argThat;
-import static org.mockito.Mockito.contains;
-import static org.mockito.Mockito.inOrder;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
-
-import com.android.tradefed.config.ConfigurationException;
-import com.android.tradefed.config.OptionSetter;
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.invoker.InvocationContext;
-import com.android.tradefed.invoker.IInvocationContext;
-import com.android.tradefed.invoker.TestInformation;
-import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.result.FailureDescription;
-import com.android.tradefed.result.ILogSaverListener;
-import com.android.tradefed.result.LogDataType;
-import com.android.tradefed.result.LogFile;
-import com.android.tradefed.result.TestDescription;
-import com.android.tradefed.result.error.ErrorIdentifier;
-import com.android.tradefed.result.error.TestErrorIdentifier;
-import com.android.tradefed.result.proto.FileProtoResultReporter;
-import com.android.tradefed.result.proto.TestRecordProto.FailureStatus;
-import com.android.tradefed.util.ZipUtil;
-
-import com.google.common.base.Splitter;
-import com.google.common.collect.ImmutableMap;
-import com.google.common.io.MoreFiles;
-import com.google.common.util.concurrent.Uninterruptibles;
-import com.google.devtools.build.lib.buildeventstream.BuildEventStreamProtos;
-
-import org.junit.Before;
-import org.junit.Ignore;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.rules.TemporaryFolder;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-import org.mockito.ArgumentMatcher;
-import org.mockito.InOrder;
-
-import java.io.ByteArrayInputStream;
-import java.io.ByteArrayOutputStream;
-import java.io.File;
-import java.io.FileOutputStream;
-import java.io.IOException;
-import java.io.InputStream;
-import java.io.OutputStream;
-import java.nio.file.Files;
-import java.nio.file.Path;
-import java.nio.file.Paths;
-import java.time.Duration;
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.Map.Entry;
-import java.util.Properties;
-import java.util.Random;
-import java.util.concurrent.TimeUnit;
-import java.util.concurrent.atomic.AtomicLong;
-import java.util.function.Function;
-import java.util.stream.Collectors;
-import java.util.stream.Stream;
-
-@RunWith(JUnit4.class)
-public final class BazelTestTest {
-
-    private ILogSaverListener mMockListener;
-    private TestInformation mTestInfo;
-    private Path mBazelTempPath;
-    private Path mWorkspaceArchivePath;
-
-    private static final String BAZEL_TEST_TARGETS_OPTION = "bazel-test-target-patterns";
-    private static final String BEP_FILE_OPTION_NAME = "--build_event_binary_file";
-    private static final String REPORT_CACHED_TEST_RESULTS_OPTION = "report-cached-test-results";
-    private static final String REPORT_CACHED_MODULES_SPARSELY_OPTION =
-            "report-cached-modules-sparsely";
-    private static final String BAZEL_TEST_MODULE_ID = "bazel-test-module-id";
-    private static final String TEST_MODULE_MODULE_ID = "single-tradefed-test-module-id";
-    private static final long RANDOM_SEED = 1234567890L;
-
-    @Rule public final TemporaryFolder tempDir = new TemporaryFolder();
-
-    @Before
-    public void setUp() throws Exception {
-        mMockListener = mock(ILogSaverListener.class);
-        InvocationContext context = new InvocationContext();
-        context.addInvocationAttribute("module-id", BAZEL_TEST_MODULE_ID);
-        context.lockAttributes();
-        mTestInfo = TestInformation.newBuilder().setInvocationContext(context).build();
-        mBazelTempPath =
-                Files.createDirectory(tempDir.getRoot().toPath().resolve("bazel_temp_dir"));
-        Files.createDirectories(
-                tempDir.getRoot()
-                        .toPath()
-                        .resolve("bazel_suite_root/android-bazel-suite/out/atest_bazel_workspace"));
-        mWorkspaceArchivePath = tempDir.getRoot().toPath().resolve("bazel_suite_root");
-    }
-
-    @Test
-    public void runSucceeds_invokesListenerEvents() throws Exception {
-        BazelTest bazelTest = newBazelTest();
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunStarted(eq(BazelTest.class.getName()), eq(0));
-        verify(mMockListener).testRunEnded(anyLong(), anyMap());
-    }
-
-    @Test
-    public void runSucceeds_noFailuresReported() throws Exception {
-        BazelTest bazelTest = newBazelTest();
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener, never()).testRunFailed(any(FailureDescription.class));
-    }
-
-    @Test
-    public void runSucceeds_tempDirEmptied() throws Exception {
-        BazelTest bazelTest = newBazelTest();
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        assertThat(listDirContents(mBazelTempPath)).isEmpty();
-    }
-
-    @Test
-    public void runSucceeds_logsSaved() throws Exception {
-        BazelTest bazelTest = newBazelTest();
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener)
-                .testLog(
-                        contains(String.format("%s-log", BazelTest.QUERY_ALL_TARGETS)),
-                        any(),
-                        any());
-        verify(mMockListener)
-                .testLog(
-                        contains(String.format("%s-log", BazelTest.QUERY_MAP_MODULES_TO_TARGETS)),
-                        any(),
-                        any());
-        verify(mMockListener)
-                .testLog(contains(String.format("%s-log", BazelTest.RUN_TESTS)), any(), any());
-    }
-
-    @Test
-    public void runSucceeds_testLogsReportedUnderModule() throws Exception {
-        BazelTest bazelTest = newBazelTest();
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        InOrder inOrder = inOrder(mMockListener);
-        inOrder.verify(mMockListener).testModuleStarted(any());
-        inOrder.verify(mMockListener)
-                .testLog(eq("tf-test-process-module-log"), eq(LogDataType.TAR_GZ), any());
-        inOrder.verify(mMockListener)
-                .testLog(eq("tf-test-process-invocation-log"), eq(LogDataType.XML), any());
-        inOrder.verify(mMockListener).testModuleEnded();
-    }
-
-    @Test
-    public void traceFileWritten_traceFileReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestOutputs(Path outputsDir, String testName)
-                                throws IOException, ConfigurationException {
-
-                            defaultWriteSingleTestOutputs(outputsDir, testName, true);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener)
-                .testLog(
-                        eq("tf-test-process-fake-invocation-trace.perfetto-trace"),
-                        eq(LogDataType.TEXT),
-                        any());
-    }
-
-    @Test
-    public void malformedProtoResults_runFails() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestOutputs(Path outputsDir, String testName)
-                                throws IOException, ConfigurationException {
-
-                            defaultWriteSingleTestOutputs(outputsDir, testName, false);
-
-                            Path outputFile = outputsDir.resolve("proto-results");
-                            Files.write(outputFile, "Malformed Proto File".getBytes());
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.INFRA_FAILURE));
-    }
-
-    @Test
-    public void malformedBepFile_runFails() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestResultEvent(File outputsZipFile, Path bepFile)
-                                throws IOException {
-
-                            Files.write(bepFile, "Malformed BEP File".getBytes());
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.TEST_FAILURE));
-    }
-
-    @Test
-    public void bepFileMissingLastMessage_runFails() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeLastEvent() throws IOException {
-                            // Do nothing.
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.INFRA_FAILURE));
-    }
-
-    @Test
-    public void targetsNotSet_testsAllTargets() throws Exception {
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_ALL_TARGETS,
-                newPassingProcessWithStdout("//bazel/target:default_target_host"));
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout("default_target //bazel/target:default_target_host"));
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return new FakeBazelTestProcess(builder, mBazelTempPath);
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        assertThat(command).contains("//bazel/target:default_target_host");
-    }
-
-    @Test
-    public void archiveRootPathNotSet_runAborted() throws Exception {
-        Properties properties = bazelTestProperties();
-        properties.remove("BAZEL_SUITE_ROOT");
-        BazelTest bazelTest = newBazelTestWithProperties(properties);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.DEPENDENCY_ISSUE));
-    }
-
-    @Test
-    public void archiveRootPathEmptyString_runAborted() throws Exception {
-        Properties properties = bazelTestProperties();
-        properties.put("BAZEL_SUITE_ROOT", "");
-        BazelTest bazelTest = newBazelTestWithProperties(properties);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.DEPENDENCY_ISSUE));
-    }
-
-    @Test
-    public void bazelQueryAllTargetsFails_runAborted() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(BazelTest.QUERY_ALL_TARGETS, newFailingProcess());
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void bazelQueryMapModuleToTargetsFails_runAborted() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(BazelTest.QUERY_MAP_MODULES_TO_TARGETS, newFailingProcess());
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void bazelReturnsTestFailureCode_noFailureReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public int exitValue() {
-                            return BazelTest.BAZEL_TESTS_FAILED_RETURN_CODE;
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener, never()).testRunFailed(any(FailureDescription.class));
-    }
-
-    @Test
-    @Ignore("b/281805276: Flaky")
-    public void testTimeout_causesTestFailure() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public boolean waitFor(long timeout, TimeUnit unit) {
-                            return false;
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.DEPENDENCY_ISSUE));
-    }
-
-    @Test
-    public void testModuleTimesOut_testReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestResultEvent(File outputsZipFile, Path bepFile)
-                                throws IOException {
-
-                            writeSingleTestResultEvent(
-                                    outputsZipFile,
-                                    bepFile, /* status */
-                                    BuildEventStreamProtos.TestStatus.TIMEOUT);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasFailureStatus(FailureStatus.TIMED_OUT));
-    }
-
-    @Test
-    public void includeTestModule_runsOnlyThatModule() throws Exception {
-        String moduleInclude = "custom_module";
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_ALL_TARGETS,
-                newPassingProcessWithStdout(
-                        "//bazel/target:default_target_host\n//bazel/target:custom_module_host"));
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout(
-                        "default_target //bazel/target:default_target_host\n"
-                                + "custom_module //bazel/target:custom_module_host"));
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return new FakeBazelTestProcess(builder, mBazelTempPath);
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue("include-filter", moduleInclude);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        assertThat(command).contains("//bazel/target:custom_module_host");
-        assertThat(command).doesNotContain("//bazel/target:default_target_host");
-    }
-
-    @Test
-    public void excludeTestModule_doesNotRunTestModule() throws Exception {
-        String moduleExclude = "custom_module";
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_ALL_TARGETS,
-                newPassingProcessWithStdout(
-                        "//bazel/target:default_target_host\n//bazel/target:custom_module_host"));
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout(
-                        "default_target //bazel/target:default_target_host\n"
-                                + "custom_module //bazel/target:custom_module_host"));
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return new FakeBazelTestProcess(builder, mBazelTempPath);
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue("exclude-filter", moduleExclude);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        assertThat(command).doesNotContain("//bazel/target:custom_module_host");
-        assertThat(command).contains("//bazel/target:default_target_host");
-    }
-
-    @Test
-    public void excludeTestFunction_generatesExcludeFilter() throws Exception {
-        String functionExclude = "custom_module custom_module.customClass#customFunction";
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return new FakeBazelTestProcess(builder, mBazelTempPath);
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue("exclude-filter", functionExclude);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        assertThat(command)
-                .contains(
-                        "--test_arg=--global-filters:exclude-filter=custom_module"
-                                + " custom_module.customClass#customFunction");
-    }
-
-    @Test
-    public void excludeAndIncludeFiltersSet_testRunAborted() throws Exception {
-        String moduleExclude = "custom_module";
-        BazelTest bazelTest = newBazelTest();
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue("exclude-filter", moduleExclude);
-        setter.setOptionValue("include-filter", moduleExclude);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void queryMapModulesToTargetsEmpty_abortsRun() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(BazelTest.QUERY_MAP_MODULES_TO_TARGETS, newPassingProcessWithStdout(""));
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void multipleTargetsMappedToSingleModule_abortsRun() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout(
-                        "default_target //bazel/target:default_target_1\n"
-                                + "default_target //bazel/target:default_target_2"));
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void queryMapModulesToTargetsBadOutput_abortsRun() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout(
-                        "default_target //bazel/target:default_target incorrect_field"));
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testRunFailed(hasErrorIdentifier(TestErrorIdentifier.TEST_ABORTED));
-    }
-
-    @Test
-    public void multipleTestsRun_reportsAllResults() throws Exception {
-        int testCount = 3;
-        Duration testDelay = Duration.ofMillis(10);
-        final AtomicLong testTime = new AtomicLong();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        byte[] bytes = logFileContents();
-
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public Path createLogFile(String testName, Path logDir) throws IOException {
-                            Path logFile = logDir.resolve(testName);
-                            Files.write(logFile, bytes);
-                            return logFile;
-                        }
-
-                        @Override
-                        public void runTests() throws IOException, ConfigurationException {
-                            long start = System.nanoTime();
-                            for (int i = 0; i < testCount; i++) {
-                                runSingleTest("test-" + i);
-                            }
-                            testTime.set((System.nanoTime() - start) / 1000000);
-                        }
-
-                        @Override
-                        void singleTestBody() {
-                            Uninterruptibles.sleepUninterruptibly(
-                                    testDelay.toMillis(), TimeUnit.MILLISECONDS);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        long start = System.nanoTime();
-        bazelTest.run(mTestInfo, mMockListener);
-        long totalTime = ((System.nanoTime() - start) / 1000000);
-
-        // TODO(b/267378279): Consider converting this test to a proper benchmark instead of using
-        // logging.
-        CLog.i("Total runtime: " + totalTime + "ms, test time: " + testTime.get() + "ms.");
-
-        verify(mMockListener, times(testCount)).testStarted(any(), anyLong());
-    }
-
-    @Test
-    public void reportCachedTestResultsDisabled_cachedTestResultNotReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestResultEvent(File outputsZipFile, Path bepFile)
-                                throws IOException {
-
-                            writeSingleTestResultEvent(outputsZipFile, bepFile, /* cached */ true);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue(REPORT_CACHED_TEST_RESULTS_OPTION, "false");
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener, never()).testStarted(any(), anyLong());
-    }
-
-    @Test
-    public void bazelQuery_default() throws Exception {
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_ALL_TARGETS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return newPassingProcessWithStdout("unused");
-                });
-
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-        assertThat(command).contains("kind(tradefed_deviceless_test, tests(//...))");
-    }
-
-    @Test
-    public void bazelQuery_optionOverride() throws Exception {
-        List<String> command = new ArrayList<>();
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.QUERY_ALL_TARGETS,
-                builder -> {
-                    command.addAll(builder.command());
-                    return newPassingProcessWithStdout("unused");
-                });
-
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue("bazel-query", "tests(//vendor/...)");
-
-        bazelTest.run(mTestInfo, mMockListener);
-        assertThat(command).contains("tests(//vendor/...)");
-        // Default should be overridden and not appear in command
-        assertThat(command).doesNotContain("kind(tradefed_deviceless_test");
-    }
-
-    @Test
-    public void badLogFilePaths_failureReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestOutputs(Path outputsDir, String testName)
-                                throws IOException, ConfigurationException {
-
-                            defaultWriteSingleTestOutputs(
-                                    outputsDir.resolve(Paths.get("bad-dir")), testName, false);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener)
-                .testRunFailed(hasErrorIdentifier(TestErrorIdentifier.OUTPUT_PARSER_ERROR));
-    }
-
-    @Test
-    public void reportCachedModulesSparsely_reportsOnlyModuleLevelEvents() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestResultEvent(File outputsZipFile, Path bepFile)
-                                throws IOException {
-
-                            writeSingleTestResultEvent(outputsZipFile, bepFile, /* cached */ true);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-        OptionSetter setter = new OptionSetter(bazelTest);
-        setter.setOptionValue(REPORT_CACHED_MODULES_SPARSELY_OPTION, "true");
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        // Verify that the test module calls happened.
-        InOrder inOrder = inOrder(mMockListener);
-        inOrder.verify(mMockListener)
-                .testModuleStarted(
-                        contextHasAttributes(
-                                ImmutableMap.of(
-                                        "module-id",
-                                        TEST_MODULE_MODULE_ID,
-                                        "sparse-module",
-                                        "true")));
-        inOrder.verify(mMockListener).testModuleEnded();
-
-        // Verify that no tests were reported.
-        verify(mMockListener, never()).testStarted(any(), anyLong());
-    }
-
-    @Test
-    public void testModuleCached_cachedPropertyReported() throws Exception {
-        FakeProcessStarter processStarter = newFakeProcessStarter();
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath) {
-                        @Override
-                        public void writeSingleTestResultEvent(File outputsZipFile, Path bepFile)
-                                throws IOException {
-
-                            writeSingleTestResultEvent(outputsZipFile, bepFile, /* cached */ true);
-                        }
-                    };
-                });
-        BazelTest bazelTest = newBazelTestWithProcessStarter(processStarter);
-
-        bazelTest.run(mTestInfo, mMockListener);
-
-        verify(mMockListener).testModuleStarted(hasInvocationAttribute("module-cached", "true"));
-    }
-
-    private static byte[] logFileContents() {
-        // Seed Random to always get the same sequence of values.
-        Random rand = new Random(RANDOM_SEED);
-        byte[] bytes = new byte[1024 * 1024];
-        rand.nextBytes(bytes);
-        return bytes;
-    }
-
-    private static FakeProcess newPassingProcess() {
-        return new FakeProcess() {
-            @Override
-            public int exitValue() {
-                return 0;
-            }
-        };
-    }
-
-    private static FakeProcess newFailingProcess() {
-        return new FakeProcess() {
-            @Override
-            public int exitValue() {
-                return -1;
-            }
-        };
-    }
-
-    private static FakeProcess newPassingProcessWithStdout(String stdOut) {
-        return new FakeProcess() {
-            @Override
-            public int exitValue() {
-                return 0;
-            }
-
-            @Override
-            public InputStream getInputStream() {
-                return new ByteArrayInputStream(stdOut.getBytes());
-            }
-        };
-    }
-
-    private BazelTest newBazelTestWithProperties(Properties properties) throws Exception {
-        return new BazelTest(newFakeProcessStarter(), properties);
-    }
-
-    private BazelTest newBazelTestWithProcessStarter(BazelTest.ProcessStarter starter)
-            throws Exception {
-
-        return new BazelTest(starter, bazelTestProperties());
-    }
-
-    private BazelTest newBazelTest() throws Exception {
-        return newBazelTestWithProcessStarter(newFakeProcessStarter());
-    }
-
-    private Properties bazelTestProperties() {
-        Properties properties = new Properties();
-        properties.put("BAZEL_SUITE_ROOT", mWorkspaceArchivePath.toAbsolutePath().toString());
-        properties.put("java.io.tmpdir", mBazelTempPath.toAbsolutePath().toString());
-
-        return properties;
-    }
-
-    private FakeProcessStarter newFakeProcessStarter() throws IOException {
-        String targetName = "//bazel/target:default_target_host";
-        FakeProcessStarter processStarter = new FakeProcessStarter();
-        processStarter.put(BazelTest.QUERY_ALL_TARGETS, newPassingProcessWithStdout(targetName));
-        processStarter.put(
-                BazelTest.QUERY_MAP_MODULES_TO_TARGETS,
-                newPassingProcessWithStdout("default_target " + targetName));
-        processStarter.put(
-                BazelTest.RUN_TESTS,
-                builder -> {
-                    return new FakeBazelTestProcess(builder, mBazelTempPath);
-                });
-        return processStarter;
-    }
-
-    private static FailureDescription hasErrorIdentifier(ErrorIdentifier error) {
-        return argThat(
-                new ArgumentMatcher<FailureDescription>() {
-                    @Override
-                    public boolean matches(FailureDescription right) {
-                        return right.getErrorIdentifier().equals(error);
-                    }
-
-                    @Override
-                    public String toString() {
-                        return "hasErrorIdentifier(" + error.toString() + ")";
-                    }
-                });
-    }
-
-    private static FailureDescription hasFailureStatus(FailureStatus status) {
-        return argThat(
-                new ArgumentMatcher<FailureDescription>() {
-                    @Override
-                    public boolean matches(FailureDescription right) {
-                        return right.getFailureStatus().equals(status);
-                    }
-
-                    @Override
-                    public String toString() {
-                        return "hasFailureStatus(" + status.toString() + ")";
-                    }
-                });
-    }
-
-    private static IInvocationContext contextHasAttributes(
-            ImmutableMap<String, String> attributes) {
-        return argThat(
-                new ArgumentMatcher<IInvocationContext>() {
-                    @Override
-                    public boolean matches(IInvocationContext right) {
-                        for (Entry<String, String> entry : attributes.entrySet()) {
-                            if (!right.getAttribute(entry.getKey()).equals(entry.getValue())) {
-                                return false;
-                            }
-                        }
-                        return true;
-                    }
-
-                    @Override
-                    public String toString() {
-                        return "contextHasAttributes(" + attributes.toString() + ")";
-                    }
-                });
-    }
-
-    private static IInvocationContext hasInvocationAttribute(String key, String value) {
-        return argThat(
-                new ArgumentMatcher<IInvocationContext>() {
-                    @Override
-                    public boolean matches(IInvocationContext right) {
-                        return right.getAttribute(key).equals(value);
-                    }
-
-                    @Override
-                    public String toString() {
-                        return "hasInvocationAttribute(" + key + ", " + value + ")";
-                    }
-                });
-    }
-
-    private static List<Path> listDirContents(Path dir) throws IOException {
-        try (Stream<Path> fileStream = Files.list(dir)) {
-            return fileStream.collect(Collectors.toList());
-        }
-    }
-
-    private static final class FakeProcessStarter implements BazelTest.ProcessStarter {
-        private final Map<String, Function<ProcessBuilder, FakeProcess>> mTagToProcess =
-                new HashMap<>();
-
-        @Override
-        public Process start(String tag, ProcessBuilder builder) throws IOException {
-            FakeProcess process = mTagToProcess.get(tag).apply(builder);
-            process.start();
-            return process;
-        }
-
-        public void put(String tag, FakeProcess process) {
-            mTagToProcess.put(
-                    tag,
-                    b -> {
-                        return process;
-                    });
-        }
-
-        public void put(String tag, Function<ProcessBuilder, FakeProcess> process) {
-            mTagToProcess.put(tag, process);
-        }
-    }
-
-    private abstract static class FakeProcess extends Process {
-
-        private volatile boolean destroyed;
-
-        @Override
-        public void destroy() {
-            destroyed = true;
-        }
-
-        @Override
-        public int exitValue() {
-            return destroyed ? 42 : 0;
-        }
-
-        @Override
-        public InputStream getErrorStream() {
-            return new ByteArrayInputStream("".getBytes());
-        }
-
-        @Override
-        public InputStream getInputStream() {
-            return new ByteArrayInputStream("".getBytes());
-        }
-
-        @Override
-        public OutputStream getOutputStream() {
-            return new ByteArrayOutputStream(0);
-        }
-
-        @Override
-        public int waitFor() {
-            return exitValue();
-        }
-
-        public void start() throws IOException {
-            return;
-        }
-    }
-
-    private static class FakeBazelTestProcess extends FakeProcess {
-        private final Path mBepFile;
-        private final Path mBazelTempDirectory;
-
-        public FakeBazelTestProcess(ProcessBuilder builder, Path bazelTempDir) {
-            mBepFile =
-                    Paths.get(
-                            builder.command().stream()
-                                    .map(s -> Splitter.on('=').splitToList(s))
-                                    .filter(s -> s.get(0).equals(BEP_FILE_OPTION_NAME))
-                                    .findFirst()
-                                    .get()
-                                    .get(1));
-            mBazelTempDirectory = bazelTempDir;
-        }
-
-        @Override
-        public void start() throws IOException {
-            try {
-                runTests();
-                writeLastEvent();
-            } catch (ConfigurationException e) {
-                throw new RuntimeException(e);
-            }
-        }
-
-        void runTests() throws IOException, ConfigurationException {
-            runSingleTest("test-1");
-        }
-
-        void runSingleTest(String testName) throws IOException, ConfigurationException {
-            Path outputDir = Files.createTempDirectory(mBazelTempDirectory, testName);
-            try {
-                singleTestBody();
-                writeSingleTestOutputs(outputDir, testName);
-                File outputsZipFile = zipSingleTestOutputsDirectory(outputDir);
-                writeSingleTestResultEvent(outputsZipFile, mBepFile);
-            } finally {
-                MoreFiles.deleteRecursively(outputDir);
-            }
-        }
-
-        void singleTestBody() {
-            // Do nothing.
-        }
-
-        void writeSingleTestOutputs(Path outputsDir, String testName)
-                throws IOException, ConfigurationException {
-
-            defaultWriteSingleTestOutputs(outputsDir, testName, false);
-        }
-
-        final void defaultWriteSingleTestOutputs(
-                Path outputsDir, String testName, boolean writeTraceFile)
-                throws IOException, ConfigurationException {
-
-            FileProtoResultReporter reporter = new FileProtoResultReporter();
-            OptionSetter setter = new OptionSetter(reporter);
-            Path outputFile = outputsDir.resolve("proto-results");
-            setter.setOptionValue("proto-output-file", outputFile.toAbsolutePath().toString());
-
-            Path logDir =
-                    Files.createDirectories(
-                            outputsDir
-                                    .resolve(BazelTest.BRANCH_TEST_ARG)
-                                    .resolve(BazelTest.BUILD_TEST_ARG)
-                                    .resolve(BazelTest.TEST_TAG_TEST_ARG));
-            Path isolatedJavaLog = createLogFile("isolated-java-logs.tar.gz", logDir);
-            Path tfConfig = createLogFile("tradefed-expanded-config.xml", logDir);
-            if (writeTraceFile) {
-                createLogFile("fake-invocation-trace.perfetto-trace", logDir);
-            }
-
-            InvocationContext context = new InvocationContext();
-            context.addInvocationAttribute("module-id", TEST_MODULE_MODULE_ID);
-
-            reporter.invocationStarted(context);
-            reporter.testModuleStarted(context);
-            reporter.testRunStarted("test-run", 1);
-            TestDescription testD = new TestDescription("class-name", testName);
-            reporter.testStarted(testD);
-            reporter.testEnded(testD, Collections.emptyMap());
-            reporter.testRunEnded(0, Collections.emptyMap());
-            reporter.logAssociation(
-                    "module-log",
-                    new LogFile(
-                            isolatedJavaLog.toAbsolutePath().toString(), "", LogDataType.TAR_GZ));
-            reporter.testModuleEnded();
-            reporter.logAssociation(
-                    "invocation-log",
-                    new LogFile(tfConfig.toAbsolutePath().toString(), "", LogDataType.XML));
-            reporter.invocationEnded(0);
-        }
-
-        Path createLogFile(String testName, Path logDir) throws IOException {
-            Path logFile = logDir.resolve(testName);
-            Files.write(logFile, testName.getBytes());
-            return logFile;
-        }
-
-        File zipSingleTestOutputsDirectory(Path outputsDir) throws IOException {
-            List<File> files =
-                    listDirContents(outputsDir).stream()
-                            .map(f -> f.toFile())
-                            .collect(Collectors.toList());
-            return ZipUtil.createZip(files);
-        }
-
-        void writeSingleTestResultEvent(File outputsZipFile, Path bepFile) throws IOException {
-            writeSingleTestResultEvent(
-                    outputsZipFile, bepFile, false, BuildEventStreamProtos.TestStatus.PASSED);
-        }
-
-        void writeSingleTestResultEvent(File outputsZipFile, Path bepFile, boolean cached)
-                throws IOException {
-            writeSingleTestResultEvent(
-                    outputsZipFile, bepFile, cached, BuildEventStreamProtos.TestStatus.PASSED);
-        }
-
-        void writeSingleTestResultEvent(
-                File outputsZipFile, Path bepFile, BuildEventStreamProtos.TestStatus status)
-                throws IOException {
-
-            writeSingleTestResultEvent(outputsZipFile, bepFile, false, status);
-        }
-
-        void writeSingleTestResultEvent(
-                File outputsZipFile,
-                Path bepFile,
-                boolean cached,
-                BuildEventStreamProtos.TestStatus status)
-                throws IOException {
-            try (FileOutputStream bepOutputStream = new FileOutputStream(bepFile.toFile(), true)) {
-                BuildEventStreamProtos.BuildEvent.newBuilder()
-                        .setId(
-                                BuildEventStreamProtos.BuildEventId.newBuilder()
-                                        .setTestResult(
-                                                BuildEventStreamProtos.BuildEventId.TestResultId
-                                                        .getDefaultInstance())
-                                        .build())
-                        .setTestResult(
-                                BuildEventStreamProtos.TestResult.newBuilder()
-                                        .addTestActionOutput(
-                                                BuildEventStreamProtos.File.newBuilder()
-                                                        .setName("test.outputs__outputs.zip")
-                                                        .setUri(outputsZipFile.getAbsolutePath())
-                                                        .build())
-                                        .setExecutionInfo(
-                                                BuildEventStreamProtos.TestResult.ExecutionInfo
-                                                        .newBuilder()
-                                                        .setCachedRemotely(cached)
-                                                        .build())
-                                        .setStatus(status)
-                                        .build())
-                        .build()
-                        .writeDelimitedTo(bepOutputStream);
-            }
-        }
-
-        void writeLastEvent() throws IOException {
-            try (FileOutputStream bepOutputStream = new FileOutputStream(mBepFile.toFile(), true)) {
-                BuildEventStreamProtos.BuildEvent.newBuilder()
-                        .setId(BuildEventStreamProtos.BuildEventId.getDefaultInstance())
-                        .setProgress(BuildEventStreamProtos.Progress.getDefaultInstance())
-                        .setLastMessage(true)
-                        .build()
-                        .writeDelimitedTo(bepOutputStream);
-            }
-        }
-    }
-}
diff --git a/atest/bazel/runner/update_bes_protos.sh b/atest/bazel/runner/update_bes_protos.sh
deleted file mode 100755
index d09f84ba..00000000
--- a/atest/bazel/runner/update_bes_protos.sh
+++ /dev/null
@@ -1,22 +0,0 @@
-#!/bin/bash
-# Updater script for Bazel BES protos for BazelTest
-#
-# Usage: update_bes_protos.sh <commit>
-#
-# TODO(b/254334040): Move protos to prebuilts/bazel/common and update alongside
-# bazel.
-
-set -euo pipefail
-
-COMMIT="$1"; shift
-
-SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
-DEST_DIR="${SCRIPT_DIR}/src/main/protobuf"
-
-echo "Updating proto files..."
-wget -P "${DEST_DIR}" https://raw.githubusercontent.com/bazelbuild/bazel/"${COMMIT}"/src/main/java/com/google/devtools/build/lib/buildeventstream/proto/build_event_stream.proto
-wget -P "${DEST_DIR}" https://raw.githubusercontent.com/bazelbuild/bazel/"${COMMIT}"/src/main/protobuf/command_line.proto
-wget -P "${DEST_DIR}" https://raw.githubusercontent.com/bazelbuild/bazel/"${COMMIT}"/src/main/protobuf/failure_details.proto
-wget -P "${DEST_DIR}" https://raw.githubusercontent.com/bazelbuild/bazel/"${COMMIT}"/src/main/protobuf/invocation_policy.proto
-wget -P "${DEST_DIR}" https://raw.githubusercontent.com/bazelbuild/bazel/"${COMMIT}"/src/main/protobuf/option_filters.proto
-echo "Done!"
diff --git a/atest/bazel/scripts/gen_workspace_archive.sh b/atest/bazel/scripts/gen_workspace_archive.sh
deleted file mode 100755
index 027dfbe9..00000000
--- a/atest/bazel/scripts/gen_workspace_archive.sh
+++ /dev/null
@@ -1,124 +0,0 @@
-#!/usr/bin/env bash
-
-# Copyright (C) 2022 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# A script to generate an Atest Bazel workspace for execution on the Android CI.
-
-# Exit immediately on failures and disallow undefined variables.
-set -euo pipefail
-# List commands as they are executed. This helps debug the error
-# if the script exits mid-way through.
-set -x
-
-function check_env_var()
-{
-  if [ ! -n "${!1}" ] ; then
-    echo "Necessary environment variable ${1} missing, exiting."
-    exit 1
-  fi
-}
-
-# Check for necessary environment variables.
-check_env_var "ANDROID_BUILD_TOP"
-check_env_var "TARGET_PRODUCT"
-check_env_var "TARGET_BUILD_VARIANT"
-
-function get_build_var()
-{
-  (${ANDROID_BUILD_TOP}/build/soong/soong_ui.bash --dumpvar-mode --abs $1)
-}
-
-out=$(get_build_var PRODUCT_OUT)
-
-# ANDROID_BUILD_TOP is deprecated, so don't use it throughout the script.
-# But if someone sets it, we'll respect it.
-cd ${ANDROID_BUILD_TOP:-.}
-
-# Use the versioned Python binaries in prebuilts/ for a reproducible
-# build with minimal reliance on host tools.
-export PATH=`pwd`/prebuilts/build-tools/path/linux-x86:${PATH}
-
-export \
-  ANDROID_PRODUCT_OUT=${out} \
-  OUT=${out} \
-  ANDROID_HOST_OUT=$(get_build_var HOST_OUT) \
-  ANDROID_TARGET_OUT_TESTCASES=$(get_build_var TARGET_OUT_TESTCASES)
-
-if [ ! -n "${OUT_DIR:-}" ] ; then
-  OUT_DIR=$(get_build_var "OUT_DIR")
-fi
-
-if [ ! -n "${DIST_DIR:-}" ] ; then
-  echo "dist dir not defined, defaulting to OUT_DIR/dist."
-  export DIST_DIR=${OUT_DIR}/dist
-fi
-
-# Build:
-#  - Atest from source to pick up the latest changes
-#  - Bazel test suite needed by BazelTest
-#  - EXTRA_TARGETS requested on the commandline (used by git_master.gcl)
-targets="atest dist empty-bazel-test-suite ${EXTRA_TARGETS:-}"
-build/soong/soong_ui.bash --make-mode WRAPPER_TOOL=atest $targets
-
-# TODO(b/277656887): Fix the underlying atest issue that causes the workspace to not be
-# regenerated.
-rm -rf ${OUT_DIR}/atest_bazel_workspace
-
-# Generate the initial workspace via Atest Bazel mode.
-${OUT_DIR}/host/linux-x86/bin/atest-dev \
-  --no-metrics \
-  --bazel-mode \
-  --host-unit-test-only \
-  --host \
-  -c \
-  -b # Builds dependencies without running tests.
-
-
-# TODO(b/201242197): Create a stub workspace for the remote_coverage_tools
-# package so that Bazel does not attempt to fetch resources online which is not
-# allowed on build bots.
-mkdir -p ${OUT_DIR}/atest_bazel_workspace/remote_coverage_tools
-touch ${OUT_DIR}/atest_bazel_workspace/remote_coverage_tools/WORKSPACE
-cat << EOF > ${OUT_DIR}/atest_bazel_workspace/remote_coverage_tools/BUILD
-package(default_visibility = ["//visibility:public"])
-
-filegroup(
-    name = "coverage_report_generator",
-    srcs = ["coverage_report_generator.sh"],
-)
-EOF
-
-# Create the workspace archive.
-prebuilts/build-tools/linux-x86/bin/soong_zip \
-  -o ${DIST_DIR}/atest_bazel_workspace.zip \
-  -P android-bazel-suite/ \
-  -D out/atest_bazel_workspace/ \
-  -f "out/atest_bazel_workspace/**/.*" \
-  -symlinks=false  `# Follow symlinks and store the referenced files.` \
-  -sha256  `# Store SHA256 checksum for each file to enable CAS.` \
-  `# Avoid failing for dangling symlinks since these are expected` \
-  `# because we don't build all targets.` \
-  -ignore_missing_files
-
-# Merge the workspace into bazel-test-suite.
-prebuilts/build-tools/linux-x86/bin/merge_zips \
-  ${DIST_DIR}/bazel-test-suite.zip \
-  ${DIST_DIR}/empty-bazel-test-suite.zip \
-  ${DIST_DIR}/atest_bazel_workspace.zip
-
-# Remove the old archives we no longer need
-rm -f \
-  ${DIST_DIR}/atest_bazel_workspace.zip \
-  ${DIST_DIR}/empty-bazel-test-suite.zip
diff --git a/atest/bazel/scripts/gen_workspace_archive_test.sh b/atest/bazel/scripts/gen_workspace_archive_test.sh
deleted file mode 100755
index f230e45f..00000000
--- a/atest/bazel/scripts/gen_workspace_archive_test.sh
+++ /dev/null
@@ -1,68 +0,0 @@
-#!/usr/bin/env bash
-
-# Copyright (C) 2022 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# A simple script for running the Atest workspace generation script in a
-# contained environment.
-
-function check_env_var()
-{
-  if [ ! -n "${!1}" ] ; then
-    echo "Necessary environment variable ${1} missing, did you forget to lunch?"
-    exit 1
-  fi
-}
-
-# Save the location of this script for later.
-SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
-
-# Check for necessary environment variables.
-check_env_var "ANDROID_BUILD_TOP"
-check_env_var "TARGET_PRODUCT"
-check_env_var "TARGET_BUILD_VARIANT"
-
-OUT_DIR=$(mktemp -d)
-trap "rm -rf $OUT_DIR" EXIT
-
-# The dist directory is not usually present on clean local machines so create it
-# here.
-mkdir $OUT_DIR/dist
-
-${ANDROID_BUILD_TOP}/prebuilts/build-tools/linux-x86/bin/nsjail \
-  -H android-build \
-  -E TARGET_PRODUCT=${TARGET_PRODUCT} \
-  -E DIST_DIR=${OUT_DIR}/dist \
-  -E TARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
-  -E OUT_DIR=${OUT_DIR} \
-  -E ANDROID_BUILD_TOP=${ANDROID_BUILD_TOP} \
-  -E HOME=${HOME} \
-  -u nobody \
-  -g $(id -g) \
-  -R / \
-  -B /tmp \
-  -B $OUT_DIR \
-  -B $PWD \
-  --disable_clone_newcgroup \
-  --cwd $ANDROID_BUILD_TOP \
-  -t 0 \
-  --proc_rw \
-  --rlimit_as soft \
-  --rlimit_core soft \
-  --rlimit_cpu soft \
-  --rlimit_fsize soft \
-  --rlimit_nofile soft \
-  -q \
-  -- \
-  ${SCRIPT_DIR}/gen_workspace_archive.sh
diff --git a/atest/bazel_mode.py b/atest/bazel_mode.py
deleted file mode 100644
index 97a4c624..00000000
--- a/atest/bazel_mode.py
+++ /dev/null
@@ -1,2165 +0,0 @@
-# Copyright 2021, The Android Open Source Project
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
-"""Implementation of Atest's Bazel mode.
-
-Bazel mode runs tests using Bazel by generating a synthetic workspace that
-contains test targets. Using Bazel allows Atest to leverage features such as
-sandboxing, caching, and remote execution.
-"""
-# pylint: disable=missing-function-docstring
-# pylint: disable=missing-class-docstring
-# pylint: disable=too-many-lines
-
-from __future__ import annotations
-
-from abc import ABC, abstractmethod
-import argparse
-import atexit
-from collections import OrderedDict, defaultdict, deque
-from collections.abc import Iterable
-import contextlib
-import dataclasses
-import enum
-import functools
-import importlib.resources
-import logging
-import os
-import pathlib
-import re
-import shlex
-import shutil
-import subprocess
-import tempfile
-import time
-from types import MappingProxyType
-from typing import Any, Callable, Dict, IO, List, Set, Tuple
-import warnings
-from xml.etree import ElementTree as ET
-
-from atest import atest_configs
-from atest import atest_utils
-from atest import constants
-from atest import module_info
-from atest.atest_enum import DetectType, ExitCode
-from atest.metrics import metrics
-from atest.proto import file_md5_pb2
-from atest.test_finders import test_finder_base
-from atest.test_finders import test_info
-from atest.test_runners import atest_tf_test_runner as tfr
-from atest.test_runners import test_runner_base as trb
-from google.protobuf.message import DecodeError
-
-
-JDK_PACKAGE_NAME = 'prebuilts/robolectric_jdk'
-JDK_NAME = 'jdk'
-ROBOLECTRIC_CONFIG = 'build/make/core/robolectric_test_config_template.xml'
-
-BAZEL_TEST_LOGS_DIR_NAME = 'bazel-testlogs'
-TEST_OUTPUT_DIR_NAME = 'test.outputs'
-TEST_OUTPUT_ZIP_NAME = 'outputs.zip'
-
-_BAZEL_WORKSPACE_DIR = 'atest_bazel_workspace'
-_SUPPORTED_BAZEL_ARGS = MappingProxyType({
-    # https://docs.bazel.build/versions/main/command-line-reference.html#flag--runs_per_test
-    constants.ITERATIONS: lambda arg_value: [
-        f'--runs_per_test={str(arg_value)}'
-    ],
-    # https://docs.bazel.build/versions/main/command-line-reference.html#flag--flaky_test_attempts
-    constants.RETRY_ANY_FAILURE: lambda arg_value: [
-        f'--flaky_test_attempts={str(arg_value)}'
-    ],
-    # https://docs.bazel.build/versions/main/command-line-reference.html#flag--test_output
-    constants.VERBOSE: (
-        lambda arg_value: ['--test_output=all'] if arg_value else []
-    ),
-    constants.BAZEL_ARG: lambda arg_value: [
-        item for sublist in arg_value for item in sublist
-    ],
-})
-
-# Maps Bazel configuration names to Soong variant names.
-_CONFIG_TO_VARIANT = {
-    'host': 'host',
-    'device': 'target',
-}
-
-
-class AbortRunException(Exception):
-  pass
-
-
-@enum.unique
-class Features(enum.Enum):
-  NULL_FEATURE = ('--null-feature', 'Enables a no-action feature.', True)
-  EXPERIMENTAL_DEVICE_DRIVEN_TEST = (
-      '--experimental-device-driven-test',
-      'Enables running device-driven tests in Bazel mode.',
-      True,
-  )
-  EXPERIMENTAL_REMOTE_AVD = (
-      '--experimental-remote-avd',
-      'Enables running device-driven tests in remote AVD.',
-      False,
-  )
-  EXPERIMENTAL_BES_PUBLISH = (
-      '--experimental-bes-publish',
-      'Upload test results via BES in Bazel mode.',
-      False,
-  )
-  EXPERIMENTAL_JAVA_RUNTIME_DEPENDENCIES = (
-      '--experimental-java-runtime-dependencies',
-      (
-          'Mirrors Soong Java `libs` and `static_libs` as Bazel target '
-          'dependencies in the generated workspace. Tradefed test rules use '
-          'these dependencies to set up the execution environment and ensure '
-          'that all transitive runtime dependencies are present.'
-      ),
-      True,
-  )
-  EXPERIMENTAL_REMOTE = (
-      '--experimental-remote',
-      'Use Bazel remote execution and caching where supported.',
-      False,
-  )
-  EXPERIMENTAL_HOST_DRIVEN_TEST = (
-      '--experimental-host-driven-test',
-      'Enables running host-driven device tests in Bazel mode.',
-      True,
-  )
-  EXPERIMENTAL_ROBOLECTRIC_TEST = (
-      '--experimental-robolectric-test',
-      'Enables running Robolectric tests in Bazel mode.',
-      True,
-  )
-  NO_BAZEL_DETAILED_SUMMARY = (
-      '--no-bazel-detailed-summary',
-      'Disables printing detailed summary of Bazel test results.',
-      False,
-  )
-
-  def __init__(self, arg_flag, description, affects_workspace):
-    self._arg_flag = arg_flag
-    self._description = description
-    self.affects_workspace = affects_workspace
-
-  @property
-  def arg_flag(self):
-    return self._arg_flag
-
-  @property
-  def description(self):
-    return self._description
-
-
-def add_parser_arguments(parser: argparse.ArgumentParser, dest: str):
-  for _, member in Features.__members__.items():
-    parser.add_argument(
-        member.arg_flag,
-        action='append_const',
-        const=member,
-        dest=dest,
-        help=member.description,
-    )
-
-
-def get_bazel_workspace_dir() -> pathlib.Path:
-  return atest_utils.get_build_out_dir(_BAZEL_WORKSPACE_DIR)
-
-
-def generate_bazel_workspace(
-    mod_info: module_info.ModuleInfo, enabled_features: Set[Features] = None
-):
-  """Generate or update the Bazel workspace used for running tests."""
-
-  start = time.time()
-  src_root_path = pathlib.Path(os.environ.get(constants.ANDROID_BUILD_TOP))
-  workspace_path = get_bazel_workspace_dir()
-  resource_manager = ResourceManager(
-      src_root_path=src_root_path,
-      resource_root_path=_get_resource_root(),
-      product_out_path=pathlib.Path(
-          os.environ.get(constants.ANDROID_PRODUCT_OUT)
-      ),
-      md5_checksum_file_path=workspace_path.joinpath('workspace_md5_checksum'),
-  )
-  jdk_path = _read_robolectric_jdk_path(
-      resource_manager.get_src_file_path(ROBOLECTRIC_CONFIG, True)
-  )
-
-  workspace_generator = WorkspaceGenerator(
-      resource_manager=resource_manager,
-      workspace_out_path=workspace_path,
-      host_out_path=pathlib.Path(os.environ.get(constants.ANDROID_HOST_OUT)),
-      build_out_dir=atest_utils.get_build_out_dir(),
-      mod_info=mod_info,
-      jdk_path=jdk_path,
-      enabled_features=enabled_features,
-  )
-  workspace_generator.generate()
-
-  metrics.LocalDetectEvent(
-      detect_type=DetectType.BAZEL_WORKSPACE_GENERATE_TIME,
-      result=int(time.time() - start),
-  )
-
-
-def get_default_build_metadata():
-  return BuildMetadata(
-      atest_utils.get_manifest_branch(), atest_utils.get_build_target()
-  )
-
-
-class ResourceManager:
-  """Class for managing files required to generate a Bazel Workspace."""
-
-  def __init__(
-      self,
-      src_root_path: pathlib.Path,
-      resource_root_path: pathlib.Path,
-      product_out_path: pathlib.Path,
-      md5_checksum_file_path: pathlib.Path,
-  ):
-    self._root_type_to_path = {
-        file_md5_pb2.RootType.SRC_ROOT: src_root_path,
-        file_md5_pb2.RootType.RESOURCE_ROOT: resource_root_path,
-        file_md5_pb2.RootType.ABS_PATH: pathlib.Path(),
-        file_md5_pb2.RootType.PRODUCT_OUT: product_out_path,
-    }
-    self._md5_checksum_file = md5_checksum_file_path
-    self._file_checksum_list = file_md5_pb2.FileChecksumList()
-
-  def get_src_file_path(
-      self, rel_path: pathlib.Path = None, affects_workspace: bool = False
-  ) -> pathlib.Path:
-    """Get the abs file path from the relative path of source_root.
-
-    Args:
-        rel_path: A relative path of the source_root.
-        affects_workspace: A boolean of whether the file affects the workspace.
-
-    Returns:
-        A abs path of the file.
-    """
-    return self._get_file_path(
-        file_md5_pb2.RootType.SRC_ROOT, rel_path, affects_workspace
-    )
-
-  def get_resource_file_path(
-      self,
-      rel_path: pathlib.Path = None,
-      affects_workspace: bool = False,
-  ) -> pathlib.Path:
-    """Get the abs file path from the relative path of resource_root.
-
-    Args:
-        rel_path: A relative path of the resource_root.
-        affects_workspace: A boolean of whether the file affects the workspace.
-
-    Returns:
-        A abs path of the file.
-    """
-    return self._get_file_path(
-        file_md5_pb2.RootType.RESOURCE_ROOT, rel_path, affects_workspace
-    )
-
-  def get_product_out_file_path(
-      self, rel_path: pathlib.Path = None, affects_workspace: bool = False
-  ) -> pathlib.Path:
-    """Get the abs file path from the relative path of product out.
-
-    Args:
-        rel_path: A relative path to the product out.
-        affects_workspace: A boolean of whether the file affects the workspace.
-
-    Returns:
-        An abs path of the file.
-    """
-    return self._get_file_path(
-        file_md5_pb2.RootType.PRODUCT_OUT, rel_path, affects_workspace
-    )
-
-  def _get_file_path(
-      self,
-      root_type: file_md5_pb2.RootType,
-      rel_path: pathlib.Path,
-      affects_workspace: bool = True,
-  ) -> pathlib.Path:
-    abs_path = self._root_type_to_path[root_type].joinpath(
-        rel_path or pathlib.Path()
-    )
-
-    if not affects_workspace:
-      return abs_path
-
-    if abs_path.is_dir():
-      for file in abs_path.glob('**/*'):
-        self._register_file(root_type, file)
-    else:
-      self._register_file(root_type, abs_path)
-    return abs_path
-
-  def _register_file(
-      self, root_type: file_md5_pb2.RootType, abs_path: pathlib.Path
-  ):
-    if not abs_path.is_file():
-      logging.debug(' ignore %s: not a file.', abs_path)
-      return
-
-    rel_path = abs_path
-    if abs_path.is_relative_to(self._root_type_to_path[root_type]):
-      rel_path = abs_path.relative_to(self._root_type_to_path[root_type])
-
-    self._file_checksum_list.file_checksums.append(
-        file_md5_pb2.FileChecksum(
-            root_type=root_type,
-            rel_path=str(rel_path),
-            md5sum=atest_utils.md5sum(abs_path),
-        )
-    )
-
-  def register_file_with_abs_path(self, abs_path: pathlib.Path):
-    """Register a file which affects the workspace.
-
-    Args:
-        abs_path: A abs path of the file.
-    """
-    self._register_file(file_md5_pb2.RootType.ABS_PATH, abs_path)
-
-  def save_affects_files_md5(self):
-    with open(self._md5_checksum_file, 'wb') as f:
-      f.write(self._file_checksum_list.SerializeToString())
-
-  def check_affects_files_md5(self):
-    """Check all affect files are consistent with the actual MD5."""
-    if not self._md5_checksum_file.is_file():
-      return False
-
-    with open(self._md5_checksum_file, 'rb') as f:
-      file_md5_list = file_md5_pb2.FileChecksumList()
-
-      try:
-        file_md5_list.ParseFromString(f.read())
-      except DecodeError:
-        atest_utils.print_and_log_warning(
-            'Failed to parse the workspace md5 checksum file.'
-        )
-        return False
-
-      for file_md5 in file_md5_list.file_checksums:
-        abs_path = pathlib.Path(
-            self._root_type_to_path[file_md5.root_type]
-        ).joinpath(file_md5.rel_path)
-        if not abs_path.is_file():
-          return False
-        if atest_utils.md5sum(abs_path) != file_md5.md5sum:
-          return False
-      return True
-
-
-class WorkspaceGenerator:
-  """Class for generating a Bazel workspace."""
-
-  # pylint: disable=too-many-arguments
-  def __init__(
-      self,
-      resource_manager: ResourceManager,
-      workspace_out_path: pathlib.Path,
-      host_out_path: pathlib.Path,
-      build_out_dir: pathlib.Path,
-      mod_info: module_info.ModuleInfo,
-      jdk_path: pathlib.Path = None,
-      enabled_features: Set[Features] = None,
-  ):
-    """Initializes the generator.
-
-    Args:
-        workspace_out_path: Path where the workspace will be output.
-        host_out_path: Path of the ANDROID_HOST_OUT.
-        build_out_dir: Path of OUT_DIR
-        mod_info: ModuleInfo object.
-        enabled_features: Set of enabled features.
-    """
-    if (
-        enabled_features
-        and Features.EXPERIMENTAL_REMOTE_AVD in enabled_features
-        and Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST not in enabled_features
-    ):
-      raise ValueError(
-          'Cannot run remote device test because '
-          '"--experimental-device-driven-test" flag is'
-          ' not set.'
-      )
-    self.enabled_features = enabled_features or set()
-    self.resource_manager = resource_manager
-    self.workspace_out_path = workspace_out_path
-    self.host_out_path = host_out_path
-    self.build_out_dir = build_out_dir
-    self.mod_info = mod_info
-    self.path_to_package = {}
-    self.jdk_path = jdk_path
-
-  def generate(self):
-    """Generate a Bazel workspace.
-
-    If the workspace md5 checksum file doesn't exist or is stale, a new
-    workspace will be generated. Otherwise, the existing workspace will be
-    reused.
-    """
-    start = time.time()
-    enabled_features_file = self.workspace_out_path.joinpath(
-        'atest_bazel_mode_enabled_features'
-    )
-    enabled_features_file_contents = '\n'.join(
-        sorted(f.name for f in self.enabled_features if f.affects_workspace)
-    )
-
-    if self.workspace_out_path.exists():
-      # Update the file with the set of the currently enabled features to
-      # make sure that changes are detected in the workspace checksum.
-      enabled_features_file.write_text(enabled_features_file_contents)
-      if self.resource_manager.check_affects_files_md5():
-        return
-
-      # We raise an exception if rmtree fails to avoid leaving stale
-      # files in the workspace that could interfere with execution.
-      shutil.rmtree(self.workspace_out_path)
-
-    atest_utils.colorful_print('Generating Bazel workspace.\n', constants.RED)
-
-    self._add_test_module_targets()
-
-    self.workspace_out_path.mkdir(parents=True)
-    self._generate_artifacts()
-
-    # Note that we write the set of enabled features despite having written
-    # it above since the workspace no longer exists at this point.
-    enabled_features_file.write_text(enabled_features_file_contents)
-
-    self.resource_manager.get_product_out_file_path(
-        self.mod_info.mod_info_file_path.relative_to(
-            self.resource_manager.get_product_out_file_path()
-        ),
-        True,
-    )
-    self.resource_manager.register_file_with_abs_path(enabled_features_file)
-    self.resource_manager.save_affects_files_md5()
-    metrics.LocalDetectEvent(
-        detect_type=DetectType.FULL_GENERATE_BAZEL_WORKSPACE_TIME,
-        result=int(time.time() - start),
-    )
-
-  def _add_test_module_targets(self):
-    seen = set()
-
-    for name, info in self.mod_info.name_to_module_info.items():
-      # Ignore modules that have a 'host_cross_' prefix since they are
-      # duplicates of existing modules. For example,
-      # 'host_cross_aapt2_tests' is a duplicate of 'aapt2_tests'. We also
-      # ignore modules with a '_32' suffix since these also are redundant
-      # given that modules have both 32 and 64-bit variants built by
-      # default. See b/77288544#comment6 and b/23566667 for more context.
-      if name.endswith('_32') or name.startswith('host_cross_'):
-        continue
-
-      if (
-          Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST in self.enabled_features
-          and self.mod_info.is_device_driven_test(info)
-      ):
-        self._resolve_dependencies(
-            self._add_device_test_target(info, False), seen
-        )
-
-      if self.mod_info.is_host_unit_test(info):
-        self._resolve_dependencies(self._add_deviceless_test_target(info), seen)
-      elif (
-          Features.EXPERIMENTAL_ROBOLECTRIC_TEST in self.enabled_features
-          and self.mod_info.is_modern_robolectric_test(info)
-      ):
-        self._resolve_dependencies(
-            self._add_tradefed_robolectric_test_target(info), seen
-        )
-      elif (
-          Features.EXPERIMENTAL_HOST_DRIVEN_TEST in self.enabled_features
-          and self.mod_info.is_host_driven_test(info)
-      ):
-        self._resolve_dependencies(
-            self._add_device_test_target(info, True), seen
-        )
-
-  def _resolve_dependencies(self, top_level_target: Target, seen: Set[Target]):
-
-    stack = [deque([top_level_target])]
-
-    while stack:
-      top = stack[-1]
-
-      if not top:
-        stack.pop()
-        continue
-
-      target = top.popleft()
-
-      # Note that we're relying on Python's default identity-based hash
-      # and equality methods. This is fine since we actually DO want
-      # reference-equality semantics for Target objects in this context.
-      if target in seen:
-        continue
-
-      seen.add(target)
-
-      next_top = deque()
-
-      for ref in target.dependencies():
-        info = ref.info or self._get_module_info(ref.name)
-        ref.set(self._add_prebuilt_target(info))
-        next_top.append(ref.target())
-
-      stack.append(next_top)
-
-  def _add_device_test_target(
-      self, info: Dict[str, Any], is_host_driven: bool
-  ) -> Target:
-    package_name = self._get_module_path(info)
-    name_suffix = 'host' if is_host_driven else 'device'
-    name = f'{info[constants.MODULE_INFO_ID]}_{name_suffix}'
-
-    def create():
-      return TestTarget.create_device_test_target(
-          name,
-          package_name,
-          info,
-          is_host_driven,
-      )
-
-    return self._add_target(package_name, name, create)
-
-  def _add_deviceless_test_target(self, info: Dict[str, Any]) -> Target:
-    package_name = self._get_module_path(info)
-    name = f'{info[constants.MODULE_INFO_ID]}_host'
-
-    def create():
-      return TestTarget.create_deviceless_test_target(
-          name,
-          package_name,
-          info,
-      )
-
-    return self._add_target(package_name, name, create)
-
-  def _add_tradefed_robolectric_test_target(
-      self, info: Dict[str, Any]
-  ) -> Target:
-    package_name = self._get_module_path(info)
-    name = f'{info[constants.MODULE_INFO_ID]}_host'
-
-    return self._add_target(
-        package_name,
-        name,
-        lambda: TestTarget.create_tradefed_robolectric_test_target(
-            name, package_name, info, f'//{JDK_PACKAGE_NAME}:{JDK_NAME}'
-        ),
-    )
-
-  def _add_prebuilt_target(self, info: Dict[str, Any]) -> Target:
-    package_name = self._get_module_path(info)
-    name = info[constants.MODULE_INFO_ID]
-
-    def create():
-      return SoongPrebuiltTarget.create(
-          self,
-          info,
-          package_name,
-      )
-
-    return self._add_target(package_name, name, create)
-
-  def _add_target(
-      self, package_path: str, target_name: str, create_fn: Callable
-  ) -> Target:
-
-    package = self.path_to_package.get(package_path)
-
-    if not package:
-      package = Package(package_path)
-      self.path_to_package[package_path] = package
-
-    target = package.get_target(target_name)
-
-    if target:
-      return target
-
-    target = create_fn()
-    package.add_target(target)
-
-    return target
-
-  def _get_module_info(self, module_name: str) -> Dict[str, Any]:
-    info = self.mod_info.get_module_info(module_name)
-
-    if not info:
-      raise LookupError(
-          f'Could not find module `{module_name}` in module_info file'
-      )
-
-    return info
-
-  def _get_module_path(self, info: Dict[str, Any]) -> str:
-    mod_path = info.get(constants.MODULE_PATH)
-
-    if len(mod_path) < 1:
-      module_name = info['module_name']
-      raise ValueError(f'Module `{module_name}` does not have any path')
-
-    if len(mod_path) > 1:
-      module_name = info['module_name']
-      # We usually have a single path but there are a few exceptions for
-      # modules like libLLVM_android and libclang_android.
-      # TODO(yangbill): Raise an exception for multiple paths once
-      # b/233581382 is resolved.
-      warnings.formatwarning = lambda msg, *args, **kwargs: f'{msg}\n'
-      warnings.warn(
-          f'Module `{module_name}` has more than one path: `{mod_path}`'
-      )
-
-    return mod_path[0]
-
-  def _generate_artifacts(self):
-    """Generate workspace files on disk."""
-
-    self._create_base_files()
-
-    self._add_workspace_resource(src='rules', dst='bazel/rules')
-    self._add_workspace_resource(src='configs', dst='bazel/configs')
-
-    if Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST in self.enabled_features:
-      self._add_workspace_resource(src='device_def', dst='device_def')
-
-    self._add_bazel_bootstrap_files()
-
-    # Symlink to package with toolchain definitions.
-    self._symlink(src='prebuilts/build-tools', target='prebuilts/build-tools')
-
-    device_infra_path = 'vendor/google/tools/atest/device_infra'
-    if self.resource_manager.get_src_file_path(device_infra_path).exists():
-      self._symlink(src=device_infra_path, target=device_infra_path)
-
-    self._link_required_src_file_path('external/bazelbuild-rules_python')
-    self._link_required_src_file_path('external/bazelbuild-rules_java')
-
-    self._create_constants_file()
-
-    self._generate_robolectric_resources()
-
-    for package in self.path_to_package.values():
-      package.generate(self.workspace_out_path)
-
-  def _generate_robolectric_resources(self):
-    if not self.jdk_path:
-      return
-
-    self._generate_jdk_resources()
-    self._generate_android_all_resources()
-
-  def _generate_jdk_resources(self):
-    # TODO(b/265596946): Create the JDK toolchain instead of using
-    # a filegroup.
-    return self._add_target(
-        JDK_PACKAGE_NAME,
-        JDK_NAME,
-        lambda: FilegroupTarget(
-            JDK_PACKAGE_NAME,
-            JDK_NAME,
-            self.resource_manager.get_src_file_path(self.jdk_path),
-        ),
-    )
-
-  def _generate_android_all_resources(self):
-    package_name = 'android-all'
-    name = 'android-all'
-
-    return self._add_target(
-        package_name,
-        name,
-        lambda: FilegroupTarget(
-            package_name, name, self.host_out_path.joinpath(f'testcases/{name}')
-        ),
-    )
-
-  def _symlink(self, *, src, target):
-    """Create a symbolic link in workspace pointing to source file/dir.
-
-    Args:
-        src: A string of a relative path to root of Android source tree. This is
-          the source file/dir path for which the symbolic link will be created.
-        target: A string of a relative path to workspace root. This is the
-          target file/dir path where the symbolic link will be created.
-    """
-    symlink = self.workspace_out_path.joinpath(target)
-    symlink.parent.mkdir(parents=True, exist_ok=True)
-    symlink.symlink_to(self.resource_manager.get_src_file_path(src))
-
-  def _create_base_files(self):
-    self._add_workspace_resource(src='WORKSPACE', dst='WORKSPACE')
-    self._add_workspace_resource(src='bazelrc', dst='.bazelrc')
-
-    self.workspace_out_path.joinpath('BUILD.bazel').touch()
-
-  def _add_bazel_bootstrap_files(self):
-    self._add_workspace_resource(src='bazel.sh', dst='bazel.sh')
-    # Restore permissions as execute permissions are not preserved by soong
-    # packaging.
-    os.chmod(self.workspace_out_path.joinpath('bazel.sh'), 0o755)
-    self._symlink(
-        src='prebuilts/jdk/jdk21/BUILD.bazel',
-        target='prebuilts/jdk/jdk21/BUILD.bazel',
-    )
-    self._symlink(
-        src='prebuilts/jdk/jdk21/linux-x86',
-        target='prebuilts/jdk/jdk21/linux-x86',
-    )
-    self._symlink(
-        src='prebuilts/bazel/linux-x86_64/bazel',
-        target='prebuilts/bazel/linux-x86_64/bazel',
-    )
-
-  def _add_workspace_resource(self, src, dst):
-    """Add resource to the given destination in workspace.
-
-    Args:
-        src: A string of a relative path to root of Bazel artifacts. This is the
-          source file/dir path that will be added to workspace.
-        dst: A string of a relative path to workspace root. This is the
-          destination file/dir path where the artifacts will be added.
-    """
-    src = self.resource_manager.get_resource_file_path(src, True)
-    dst = self.workspace_out_path.joinpath(dst)
-    dst.parent.mkdir(parents=True, exist_ok=True)
-
-    if src.is_file():
-      shutil.copy(src, dst)
-    else:
-      shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__init__.py'))
-
-  def _create_constants_file(self):
-    def variable_name(target_name):
-      return re.sub(r'[.-]', '_', target_name) + '_label'
-
-    targets = []
-    seen = set()
-
-    for module_name in TestTarget.DEVICELESS_TEST_PREREQUISITES.union(
-        TestTarget.DEVICE_TEST_PREREQUISITES
-    ):
-      info = self.mod_info.get_module_info(module_name)
-      target = self._add_prebuilt_target(info)
-      self._resolve_dependencies(target, seen)
-      targets.append(target)
-
-    with self.workspace_out_path.joinpath('constants.bzl').open('w') as f:
-      writer = IndentWriter(f)
-      for target in targets:
-        writer.write_line(
-            '%s = "%s"'
-            % (variable_name(target.name()), target.qualified_name())
-        )
-
-  def _link_required_src_file_path(self, path):
-    if not self.resource_manager.get_src_file_path(path).exists():
-      raise RuntimeError(f'Path `{path}` does not exist in source tree.')
-
-    self._symlink(src=path, target=path)
-
-
-@functools.cache
-def _get_resource_root() -> pathlib.Path:
-  tmp_resource_dir = pathlib.Path(tempfile.mkdtemp())
-  atexit.register(lambda: shutil.rmtree(tmp_resource_dir))
-
-  def _extract_resources(
-      resource_path: pathlib.Path,
-      dst: pathlib.Path,
-      ignore_file_names: list[str] = None,
-  ):
-    resource = importlib.resources.files(resource_path.as_posix())
-    dst.mkdir(parents=True, exist_ok=True)
-    for child in resource.iterdir():
-      if child.is_file():
-        if child.name in ignore_file_names:
-          continue
-        with importlib.resources.as_file(child) as child_file:
-          shutil.copy(child_file, dst.joinpath(child.name))
-      elif child.is_dir():
-        _extract_resources(
-            resource_path.joinpath(child.name),
-            dst.joinpath(child.name),
-            ignore_file_names,
-        )
-      else:
-        atest_utils.print_and_log_warning(
-            'Ignoring unknown resource: %s', child
-        )
-
-  try:
-    _extract_resources(
-        pathlib.Path('atest/bazel/resources'),
-        tmp_resource_dir,
-        ignore_file_names=['__init__.py'],
-    )
-  except ModuleNotFoundError as e:
-    logging.debug(
-        'Bazel resource not found from package path, possible due to running'
-        ' atest from source. Returning resource source path instead: %s',
-        e,
-    )
-    return pathlib.Path(os.path.dirname(__file__)).joinpath('bazel/resources')
-
-  return tmp_resource_dir
-
-
-class Package:
-  """Class for generating an entire Package on disk."""
-
-  def __init__(self, path: str):
-    self.path = path
-    self.imports = defaultdict(set)
-    self.name_to_target = OrderedDict()
-
-  def add_target(self, target):
-    target_name = target.name()
-
-    if target_name in self.name_to_target:
-      raise ValueError(
-          f'Cannot add target `{target_name}` which already'
-          f' exists in package `{self.path}`'
-      )
-
-    self.name_to_target[target_name] = target
-
-    for i in target.required_imports():
-      self.imports[i.bzl_package].add(i.symbol)
-
-  def generate(self, workspace_out_path: pathlib.Path):
-    package_dir = workspace_out_path.joinpath(self.path)
-    package_dir.mkdir(parents=True, exist_ok=True)
-
-    self._create_filesystem_layout(package_dir)
-    self._write_build_file(package_dir)
-
-  def _create_filesystem_layout(self, package_dir: pathlib.Path):
-    for target in self.name_to_target.values():
-      target.create_filesystem_layout(package_dir)
-
-  def _write_build_file(self, package_dir: pathlib.Path):
-    with package_dir.joinpath('BUILD.bazel').open('w') as f:
-      f.write('package(default_visibility = ["//visibility:public"])\n')
-      f.write('\n')
-
-      for bzl_package, symbols in sorted(self.imports.items()):
-        symbols_text = ', '.join('"%s"' % s for s in sorted(symbols))
-        f.write(f'load("{bzl_package}", {symbols_text})\n')
-
-      for target in self.name_to_target.values():
-        f.write('\n')
-        target.write_to_build_file(f)
-
-  def get_target(self, target_name: str) -> Target:
-    return self.name_to_target.get(target_name, None)
-
-
-@dataclasses.dataclass(frozen=True)
-class Import:
-  bzl_package: str
-  symbol: str
-
-
-@dataclasses.dataclass(frozen=True)
-class Config:
-  name: str
-  out_path: pathlib.Path
-
-
-class ModuleRef:
-
-  @staticmethod
-  def for_info(info) -> ModuleRef:
-    return ModuleRef(info=info)
-
-  @staticmethod
-  def for_name(name) -> ModuleRef:
-    return ModuleRef(name=name)
-
-  def __init__(self, info=None, name=None):
-    self.info = info
-    self.name = name
-    self._target = None
-
-  def target(self) -> Target:
-    if not self._target:
-      target_name = self.info[constants.MODULE_INFO_ID]
-      raise ValueError(f'Target not set for ref `{target_name}`')
-
-    return self._target
-
-  def set(self, target):
-    self._target = target
-
-
-class Target(ABC):
-  """Abstract class for a Bazel target."""
-
-  @abstractmethod
-  def name(self) -> str:
-    pass
-
-  def package_name(self) -> str:
-    pass
-
-  def qualified_name(self) -> str:
-    return f'//{self.package_name()}:{self.name()}'
-
-  def required_imports(self) -> Set[Import]:
-    return set()
-
-  def supported_configs(self) -> Set[Config]:
-    return set()
-
-  def dependencies(self) -> List[ModuleRef]:
-    return []
-
-  def write_to_build_file(self, f: IO):
-    pass
-
-  def create_filesystem_layout(self, package_dir: pathlib.Path):
-    pass
-
-
-class FilegroupTarget(Target):
-
-  def __init__(
-      self, package_name: str, target_name: str, srcs_root: pathlib.Path
-  ):
-    self._package_name = package_name
-    self._target_name = target_name
-    self._srcs_root = srcs_root
-
-  def name(self) -> str:
-    return self._target_name
-
-  def package_name(self) -> str:
-    return self._package_name
-
-  def write_to_build_file(self, f: IO):
-    writer = IndentWriter(f)
-    build_file_writer = BuildFileWriter(writer)
-
-    writer.write_line('filegroup(')
-
-    with writer.indent():
-      build_file_writer.write_string_attribute('name', self._target_name)
-      build_file_writer.write_glob_attribute(
-          'srcs', [f'{self._target_name}_files/**']
-      )
-
-    writer.write_line(')')
-
-  def create_filesystem_layout(self, package_dir: pathlib.Path):
-    symlink = package_dir.joinpath(f'{self._target_name}_files')
-    symlink.symlink_to(self._srcs_root)
-
-
-class TestTarget(Target):
-  """Class for generating a test target."""
-
-  DEVICELESS_TEST_PREREQUISITES = frozenset({
-      'adb',
-      'atest-tradefed',
-      'atest_script_help.sh',
-      'atest_tradefed.sh',
-      'tradefed',
-      'tradefed-test-framework',
-      'bazel-result-reporter',
-  })
-
-  DEVICE_TEST_PREREQUISITES = frozenset(
-      DEVICELESS_TEST_PREREQUISITES.union(
-          frozenset({
-              'aapt',
-              'aapt2',
-              'compatibility-tradefed',
-              'vts-core-tradefed-harness',
-          })
-      )
-  )
-
-  @staticmethod
-  def create_deviceless_test_target(
-      name: str, package_name: str, info: Dict[str, Any]
-  ):
-    return TestTarget(
-        package_name,
-        'tradefed_deviceless_test',
-        {
-            'name': name,
-            'test': ModuleRef.for_info(info),
-            'module_name': info['module_name'],
-            'tags': info.get(constants.MODULE_TEST_OPTIONS_TAGS, []),
-        },
-        TestTarget.DEVICELESS_TEST_PREREQUISITES,
-    )
-
-  @staticmethod
-  def create_device_test_target(
-      name: str, package_name: str, info: Dict[str, Any], is_host_driven: bool
-  ):
-    rule = (
-        'tradefed_host_driven_device_test'
-        if is_host_driven
-        else 'tradefed_device_driven_test'
-    )
-
-    return TestTarget(
-        package_name,
-        rule,
-        {
-            'name': name,
-            'test': ModuleRef.for_info(info),
-            'module_name': info['module_name'],
-            'suites': set(info.get(constants.MODULE_COMPATIBILITY_SUITES, [])),
-            'tradefed_deps': list(
-                map(
-                    ModuleRef.for_name, info.get(constants.MODULE_HOST_DEPS, [])
-                )
-            ),
-            'tags': info.get(constants.MODULE_TEST_OPTIONS_TAGS, []),
-        },
-        TestTarget.DEVICE_TEST_PREREQUISITES,
-    )
-
-  @staticmethod
-  def create_tradefed_robolectric_test_target(
-      name: str, package_name: str, info: Dict[str, Any], jdk_label: str
-  ):
-    return TestTarget(
-        package_name,
-        'tradefed_robolectric_test',
-        {
-            'name': name,
-            'test': ModuleRef.for_info(info),
-            'module_name': info['module_name'],
-            'tags': info.get(constants.MODULE_TEST_OPTIONS_TAGS, []),
-            'jdk': jdk_label,
-        },
-        TestTarget.DEVICELESS_TEST_PREREQUISITES,
-    )
-
-  def __init__(
-      self,
-      package_name: str,
-      rule_name: str,
-      attributes: Dict[str, Any],
-      prerequisites=frozenset(),
-  ):
-    self._attributes = attributes
-    self._package_name = package_name
-    self._rule_name = rule_name
-    self._prerequisites = prerequisites
-
-  def name(self) -> str:
-    return self._attributes['name']
-
-  def package_name(self) -> str:
-    return self._package_name
-
-  def required_imports(self) -> Set[Import]:
-    return {Import('//bazel/rules:tradefed_test.bzl', self._rule_name)}
-
-  def dependencies(self) -> List[ModuleRef]:
-    prerequisite_refs = map(ModuleRef.for_name, self._prerequisites)
-
-    declared_dep_refs = []
-    for value in self._attributes.values():
-      if isinstance(value, Iterable):
-        declared_dep_refs.extend(
-            [dep for dep in value if isinstance(dep, ModuleRef)]
-        )
-      elif isinstance(value, ModuleRef):
-        declared_dep_refs.append(value)
-
-    return declared_dep_refs + list(prerequisite_refs)
-
-  def write_to_build_file(self, f: IO):
-    prebuilt_target_name = self._attributes['test'].target().qualified_name()
-    writer = IndentWriter(f)
-    build_file_writer = BuildFileWriter(writer)
-
-    writer.write_line(f'{self._rule_name}(')
-
-    with writer.indent():
-      build_file_writer.write_string_attribute('name', self._attributes['name'])
-
-      build_file_writer.write_string_attribute(
-          'module_name', self._attributes['module_name']
-      )
-
-      build_file_writer.write_string_attribute('test', prebuilt_target_name)
-
-      build_file_writer.write_label_list_attribute(
-          'tradefed_deps', self._attributes.get('tradefed_deps')
-      )
-
-      build_file_writer.write_string_list_attribute(
-          'suites', sorted(self._attributes.get('suites', []))
-      )
-
-      build_file_writer.write_string_list_attribute(
-          'tags', sorted(self._attributes.get('tags', []))
-      )
-
-      build_file_writer.write_label_attribute(
-          'jdk', self._attributes.get('jdk', None)
-      )
-
-    writer.write_line(')')
-
-
-def _read_robolectric_jdk_path(
-    test_xml_config_template: pathlib.Path,
-) -> pathlib.Path:
-  if not test_xml_config_template.is_file():
-    return None
-
-  xml_root = ET.parse(test_xml_config_template).getroot()
-  option = xml_root.find(".//option[@name='java-folder']")
-  jdk_path = pathlib.Path(option.get('value', ''))
-
-  if not jdk_path.is_relative_to('prebuilts/jdk'):
-    raise ValueError(
-        f'Failed to get "java-folder" from `{test_xml_config_template}`'
-    )
-
-  return jdk_path
-
-
-class BuildFileWriter:
-  """Class for writing BUILD files."""
-
-  def __init__(self, underlying: IndentWriter):
-    self._underlying = underlying
-
-  def write_string_attribute(self, attribute_name, value):
-    if value is None:
-      return
-
-    self._underlying.write_line(f'{attribute_name} = "{value}",')
-
-  def write_label_attribute(self, attribute_name: str, label_name: str):
-    if label_name is None:
-      return
-
-    self._underlying.write_line(f'{attribute_name} = "{label_name}",')
-
-  def write_string_list_attribute(self, attribute_name, values):
-    if not values:
-      return
-
-    self._underlying.write_line(f'{attribute_name} = [')
-
-    with self._underlying.indent():
-      for value in values:
-        self._underlying.write_line(f'"{value}",')
-
-    self._underlying.write_line('],')
-
-  def write_label_list_attribute(
-      self, attribute_name: str, modules: List[ModuleRef]
-  ):
-    if not modules:
-      return
-
-    self._underlying.write_line(f'{attribute_name} = [')
-
-    with self._underlying.indent():
-      for label in sorted(set(m.target().qualified_name() for m in modules)):
-        self._underlying.write_line(f'"{label}",')
-
-    self._underlying.write_line('],')
-
-  def write_glob_attribute(self, attribute_name: str, patterns: List[str]):
-    self._underlying.write_line(f'{attribute_name} = glob([')
-
-    with self._underlying.indent():
-      for pattern in patterns:
-        self._underlying.write_line(f'"{pattern}",')
-
-    self._underlying.write_line(']),')
-
-
-@dataclasses.dataclass(frozen=True)
-class Dependencies:
-  static_dep_refs: List[ModuleRef]
-  runtime_dep_refs: List[ModuleRef]
-  data_dep_refs: List[ModuleRef]
-  device_data_dep_refs: List[ModuleRef]
-
-
-class SoongPrebuiltTarget(Target):
-  """Class for generating a Soong prebuilt target on disk."""
-
-  @staticmethod
-  def create(
-      gen: WorkspaceGenerator, info: Dict[str, Any], package_name: str = ''
-  ):
-    module_name = info['module_name']
-
-    configs = [
-        Config('host', gen.host_out_path),
-        Config('device', gen.resource_manager.get_product_out_file_path()),
-    ]
-
-    installed_paths = get_module_installed_paths(
-        info, gen.resource_manager.get_src_file_path()
-    )
-    config_files = group_paths_by_config(configs, installed_paths)
-
-    # For test modules, we only create symbolic link to the 'testcases'
-    # directory since the information in module-info is not accurate.
-    if gen.mod_info.is_tradefed_testable_module(info):
-      config_files = {
-          c: [c.out_path.joinpath(f'testcases/{module_name}')]
-          for c in config_files.keys()
-      }
-
-    enabled_features = gen.enabled_features
-
-    return SoongPrebuiltTarget(
-        info,
-        package_name,
-        config_files,
-        Dependencies(
-            static_dep_refs=find_static_dep_refs(
-                gen.mod_info,
-                info,
-                configs,
-                gen.resource_manager.get_src_file_path(),
-                enabled_features,
-            ),
-            runtime_dep_refs=find_runtime_dep_refs(
-                gen.mod_info,
-                info,
-                configs,
-                gen.resource_manager.get_src_file_path(),
-                enabled_features,
-            ),
-            data_dep_refs=find_data_dep_refs(
-                gen.mod_info,
-                info,
-                configs,
-                gen.resource_manager.get_src_file_path(),
-            ),
-            device_data_dep_refs=find_device_data_dep_refs(gen, info),
-        ),
-        [
-            c
-            for c in configs
-            if c.name
-            in map(str.lower, info.get(constants.MODULE_SUPPORTED_VARIANTS, []))
-        ],
-    )
-
-  def __init__(
-      self,
-      info: Dict[str, Any],
-      package_name: str,
-      config_files: Dict[Config, List[pathlib.Path]],
-      deps: Dependencies,
-      supported_configs: List[Config],
-  ):
-    self._target_name = info[constants.MODULE_INFO_ID]
-    self._module_name = info[constants.MODULE_NAME]
-    self._package_name = package_name
-    self.config_files = config_files
-    self.deps = deps
-    self.suites = info.get(constants.MODULE_COMPATIBILITY_SUITES, [])
-    self._supported_configs = supported_configs
-
-  def name(self) -> str:
-    return self._target_name
-
-  def package_name(self) -> str:
-    return self._package_name
-
-  def required_imports(self) -> Set[Import]:
-    return {
-        Import('//bazel/rules:soong_prebuilt.bzl', self._rule_name()),
-    }
-
-  @functools.lru_cache(maxsize=128)
-  def supported_configs(self) -> Set[Config]:
-    # We deduce the supported configs from the installed paths since the
-    # build exports incorrect metadata for some module types such as
-    # Robolectric. The information exported from the build is only used if
-    # the module does not have any installed paths.
-    # TODO(b/232929584): Remove this once all modules correctly export the
-    #  supported variants.
-    supported_configs = set(self.config_files.keys())
-    if supported_configs:
-      return supported_configs
-
-    return self._supported_configs
-
-  def dependencies(self) -> List[ModuleRef]:
-    all_deps = set(self.deps.runtime_dep_refs)
-    all_deps.update(self.deps.data_dep_refs)
-    all_deps.update(self.deps.device_data_dep_refs)
-    all_deps.update(self.deps.static_dep_refs)
-    return list(all_deps)
-
-  def write_to_build_file(self, f: IO):
-    writer = IndentWriter(f)
-    build_file_writer = BuildFileWriter(writer)
-
-    writer.write_line(f'{self._rule_name()}(')
-
-    with writer.indent():
-      writer.write_line(f'name = "{self._target_name}",')
-      writer.write_line(f'module_name = "{self._module_name}",')
-      self._write_files_attribute(writer)
-      self._write_deps_attribute(
-          writer, 'static_deps', self.deps.static_dep_refs
-      )
-      self._write_deps_attribute(
-          writer, 'runtime_deps', self.deps.runtime_dep_refs
-      )
-      self._write_deps_attribute(writer, 'data', self.deps.data_dep_refs)
-
-      build_file_writer.write_label_list_attribute(
-          'device_data', self.deps.device_data_dep_refs
-      )
-      build_file_writer.write_string_list_attribute(
-          'suites', sorted(self.suites)
-      )
-
-    writer.write_line(')')
-
-  def create_filesystem_layout(self, package_dir: pathlib.Path):
-    prebuilts_dir = package_dir.joinpath(self._target_name)
-    prebuilts_dir.mkdir()
-
-    for config, files in self.config_files.items():
-      config_prebuilts_dir = prebuilts_dir.joinpath(config.name)
-      config_prebuilts_dir.mkdir()
-
-      for f in files:
-        rel_path = f.relative_to(config.out_path)
-        symlink = config_prebuilts_dir.joinpath(rel_path)
-        symlink.parent.mkdir(parents=True, exist_ok=True)
-        symlink.symlink_to(f)
-
-  def _rule_name(self):
-    return (
-        'soong_prebuilt' if self.config_files else 'soong_uninstalled_prebuilt'
-    )
-
-  def _write_files_attribute(self, writer: IndentWriter):
-    if not self.config_files:
-      return
-
-    writer.write('files = ')
-    write_config_select(
-        writer,
-        self.config_files,
-        lambda c, _: writer.write(
-            f'glob(["{self._target_name}/{c.name}/**/*"])'
-        ),
-    )
-    writer.write_line(',')
-
-  def _write_deps_attribute(self, writer, attribute_name, module_refs):
-    config_deps = filter_configs(
-        group_targets_by_config(r.target() for r in module_refs),
-        self.supported_configs(),
-    )
-
-    if not config_deps:
-      return
-
-    for config in self.supported_configs():
-      config_deps.setdefault(config, [])
-
-    writer.write(f'{attribute_name} = ')
-    write_config_select(
-        writer,
-        config_deps,
-        lambda _, targets: write_target_list(writer, targets),
-    )
-    writer.write_line(',')
-
-
-def group_paths_by_config(
-    configs: List[Config], paths: List[pathlib.Path]
-) -> Dict[Config, List[pathlib.Path]]:
-
-  config_files = defaultdict(list)
-
-  for f in paths:
-    matching_configs = [c for c in configs if _is_relative_to(f, c.out_path)]
-
-    if not matching_configs:
-      continue
-
-    # The path can only appear in ANDROID_HOST_OUT for host target or
-    # ANDROID_PRODUCT_OUT, but cannot appear in both.
-    if len(matching_configs) > 1:
-      raise ValueError(
-          f'Installed path `{f}` is not in'
-          ' ANDROID_HOST_OUT or ANDROID_PRODUCT_OUT'
-      )
-
-    config_files[matching_configs[0]].append(f)
-
-  return config_files
-
-
-def group_targets_by_config(
-    targets: List[Target],
-) -> Dict[Config, List[Target]]:
-
-  config_to_targets = defaultdict(list)
-
-  for target in targets:
-    for config in target.supported_configs():
-      config_to_targets[config].append(target)
-
-  return config_to_targets
-
-
-def filter_configs(
-    config_dict: Dict[Config, Any],
-    configs: Set[Config],
-) -> Dict[Config, Any]:
-  return {k: v for (k, v) in config_dict.items() if k in configs}
-
-
-def _is_relative_to(path1: pathlib.Path, path2: pathlib.Path) -> bool:
-  """Return True if the path is relative to another path or False."""
-  # Note that this implementation is required because Path.is_relative_to only
-  # exists starting with Python 3.9.
-  try:
-    path1.relative_to(path2)
-    return True
-  except ValueError:
-    return False
-
-
-def get_module_installed_paths(
-    info: Dict[str, Any], src_root_path: pathlib.Path
-) -> List[pathlib.Path]:
-
-  # Install paths in module-info are usually relative to the Android
-  # source root ${ANDROID_BUILD_TOP}. When the output directory is
-  # customized by the user however, the install paths are absolute.
-  def resolve(install_path_string):
-    install_path = pathlib.Path(install_path_string)
-    if not install_path.expanduser().is_absolute():
-      return src_root_path.joinpath(install_path)
-    return install_path
-
-  return map(resolve, info.get(constants.MODULE_INSTALLED, []))
-
-
-def find_runtime_dep_refs(
-    mod_info: module_info.ModuleInfo,
-    info: module_info.Module,
-    configs: List[Config],
-    src_root_path: pathlib.Path,
-    enabled_features: List[Features],
-) -> List[ModuleRef]:
-  """Return module references for runtime dependencies."""
-
-  # We don't use the `dependencies` module-info field for shared libraries
-  # since it's ambiguous and could generate more targets and pull in more
-  # dependencies than necessary. In particular, libraries that support both
-  # static and dynamic linking could end up becoming runtime dependencies
-  # even though the build specifies static linking. For example, if a target
-  # 'T' is statically linked to 'U' which supports both variants, the latter
-  # still appears as a dependency. Since we can't tell, this would result in
-  # the shared library variant of 'U' being added on the library path.
-  libs = set()
-  libs.update(info.get(constants.MODULE_SHARED_LIBS, []))
-  libs.update(info.get(constants.MODULE_RUNTIME_DEPS, []))
-
-  if Features.EXPERIMENTAL_JAVA_RUNTIME_DEPENDENCIES in enabled_features:
-    libs.update(info.get(constants.MODULE_LIBS, []))
-
-  runtime_dep_refs = _find_module_refs(mod_info, configs, src_root_path, libs)
-
-  runtime_library_class = {'RLIB_LIBRARIES', 'DYLIB_LIBRARIES'}
-  # We collect rlibs even though they are technically static libraries since
-  # they could refer to dylibs which are required at runtime. Generating
-  # Bazel targets for these intermediate modules keeps the generator simple
-  # and preserves the shape (isomorphic) of the Soong structure making the
-  # workspace easier to debug.
-  for dep_name in info.get(constants.MODULE_DEPENDENCIES, []):
-    dep_info = mod_info.get_module_info(dep_name)
-    if not dep_info:
-      continue
-    if not runtime_library_class.intersection(
-        dep_info.get(constants.MODULE_CLASS, [])
-    ):
-      continue
-    runtime_dep_refs.append(ModuleRef.for_info(dep_info))
-
-  return runtime_dep_refs
-
-
-def find_data_dep_refs(
-    mod_info: module_info.ModuleInfo,
-    info: module_info.Module,
-    configs: List[Config],
-    src_root_path: pathlib.Path,
-) -> List[ModuleRef]:
-  """Return module references for data dependencies."""
-
-  return _find_module_refs(
-      mod_info, configs, src_root_path, info.get(constants.MODULE_DATA_DEPS, [])
-  )
-
-
-def find_device_data_dep_refs(
-    gen: WorkspaceGenerator,
-    info: module_info.Module,
-) -> List[ModuleRef]:
-  """Return module references for device data dependencies."""
-
-  return _find_module_refs(
-      gen.mod_info,
-      [Config('device', gen.resource_manager.get_product_out_file_path())],
-      gen.resource_manager.get_src_file_path(),
-      info.get(constants.MODULE_TARGET_DEPS, []),
-  )
-
-
-def find_static_dep_refs(
-    mod_info: module_info.ModuleInfo,
-    info: module_info.Module,
-    configs: List[Config],
-    src_root_path: pathlib.Path,
-    enabled_features: List[Features],
-) -> List[ModuleRef]:
-  """Return module references for static libraries."""
-
-  if Features.EXPERIMENTAL_JAVA_RUNTIME_DEPENDENCIES not in enabled_features:
-    return []
-
-  static_libs = set()
-  static_libs.update(info.get(constants.MODULE_STATIC_LIBS, []))
-  static_libs.update(info.get(constants.MODULE_STATIC_DEPS, []))
-
-  return _find_module_refs(mod_info, configs, src_root_path, static_libs)
-
-
-def _find_module_refs(
-    mod_info: module_info.ModuleInfo,
-    configs: List[Config],
-    src_root_path: pathlib.Path,
-    module_names: List[str],
-) -> List[ModuleRef]:
-  """Return module references for modules."""
-
-  module_refs = []
-
-  for name in module_names:
-    info = mod_info.get_module_info(name)
-    if not info:
-      continue
-
-    installed_paths = get_module_installed_paths(info, src_root_path)
-    config_files = group_paths_by_config(configs, installed_paths)
-    if not config_files:
-      continue
-
-    module_refs.append(ModuleRef.for_info(info))
-
-  return module_refs
-
-
-class IndentWriter:
-
-  def __init__(self, f: IO):
-    self._file = f
-    self._indent_level = 0
-    self._indent_string = 4 * ' '
-    self._indent_next = True
-
-  def write_line(self, text: str = ''):
-    if text:
-      self.write(text)
-
-    self._file.write('\n')
-    self._indent_next = True
-
-  def write(self, text):
-    if self._indent_next:
-      self._file.write(self._indent_string * self._indent_level)
-      self._indent_next = False
-
-    self._file.write(text)
-
-  @contextlib.contextmanager
-  def indent(self):
-    self._indent_level += 1
-    yield
-    self._indent_level -= 1
-
-
-def write_config_select(
-    writer: IndentWriter,
-    config_dict: Dict[Config, Any],
-    write_value_fn: Callable,
-):
-  writer.write_line('select({')
-
-  with writer.indent():
-    for config, value in sorted(config_dict.items(), key=lambda c: c[0].name):
-
-      writer.write(f'"//bazel/rules:{config.name}": ')
-      write_value_fn(config, value)
-      writer.write_line(',')
-
-  writer.write('})')
-
-
-def write_target_list(writer: IndentWriter, targets: List[Target]):
-  writer.write_line('[')
-
-  with writer.indent():
-    for label in sorted(set(t.qualified_name() for t in targets)):
-      writer.write_line(f'"{label}",')
-
-  writer.write(']')
-
-
-def _decorate_find_method(mod_info, finder_method_func, host, enabled_features):
-  """A finder_method decorator to override TestInfo properties."""
-
-  def use_bazel_runner(finder_obj, test_id):
-    test_infos = finder_method_func(finder_obj, test_id)
-    if not test_infos:
-      return test_infos
-    for tinfo in test_infos:
-      m_info = mod_info.get_module_info(tinfo.test_name)
-
-      # TODO(b/262200630): Refactor the duplicated logic in
-      # _decorate_find_method() and _add_test_module_targets() to
-      # determine whether a test should run with Atest Bazel Mode.
-
-      # Only enable modern Robolectric tests since those are the only ones
-      # TF currently supports.
-      if mod_info.is_modern_robolectric_test(m_info):
-        if Features.EXPERIMENTAL_ROBOLECTRIC_TEST in enabled_features:
-          tinfo.test_runner = BazelTestRunner.NAME
-        continue
-
-      # Only run device-driven tests in Bazel mode when '--host' is not
-      # specified and the feature is enabled.
-      if not host and mod_info.is_device_driven_test(m_info):
-        if Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST in enabled_features:
-          tinfo.test_runner = BazelTestRunner.NAME
-        continue
-
-      if mod_info.is_suite_in_compatibility_suites(
-          'host-unit-tests', m_info
-      ) or (
-          Features.EXPERIMENTAL_HOST_DRIVEN_TEST in enabled_features
-          and mod_info.is_host_driven_test(m_info)
-      ):
-        tinfo.test_runner = BazelTestRunner.NAME
-    return test_infos
-
-  return use_bazel_runner
-
-
-def create_new_finder(
-    mod_info: module_info.ModuleInfo,
-    finder: test_finder_base.TestFinderBase,
-    host: bool,
-    enabled_features: List[Features] = None,
-):
-  """Create new test_finder_base.Finder with decorated find_method.
-
-  Args:
-    mod_info: ModuleInfo object.
-    finder: Test Finder class.
-    host: Whether to run the host variant.
-    enabled_features: List of enabled features.
-
-  Returns:
-      List of ordered find methods.
-  """
-  return test_finder_base.Finder(
-      finder.test_finder_instance,
-      _decorate_find_method(
-          mod_info, finder.find_method, host, enabled_features or []
-      ),
-      finder.finder_info,
-  )
-
-
-class RunCommandError(subprocess.CalledProcessError):
-  """CalledProcessError but including debug information when it fails."""
-
-  def __str__(self):
-    return f'{super().__str__()}\nstdout={self.stdout}\n\nstderr={self.stderr}'
-
-
-def default_run_command(args: List[str], cwd: pathlib.Path) -> str:
-  result = subprocess.run(
-      args=args,
-      cwd=cwd,
-      text=True,
-      capture_output=True,
-      check=False,
-  )
-  if result.returncode:
-    # Provide a more detailed log message including stdout and stderr.
-    raise RunCommandError(
-        result.returncode, result.args, result.stdout, result.stderr
-    )
-  return result.stdout
-
-
-@dataclasses.dataclass
-class BuildMetadata:
-  build_branch: str
-  build_target: str
-
-
-class BazelTestRunner(trb.TestRunnerBase):
-  """Bazel Test Runner class."""
-
-  NAME = 'BazelTestRunner'
-  EXECUTABLE = 'none'
-
-  # pylint: disable=redefined-outer-name
-  # pylint: disable=too-many-arguments
-  def __init__(
-      self,
-      results_dir,
-      mod_info: module_info.ModuleInfo,
-      extra_args: Dict[str, Any] = None,
-      src_top: pathlib.Path = None,
-      workspace_path: pathlib.Path = None,
-      run_command: Callable = default_run_command,
-      build_metadata: BuildMetadata = None,
-      env: Dict[str, str] = None,
-      generate_workspace_fn: Callable = generate_bazel_workspace,
-      enabled_features: Set[str] = None,
-      **kwargs,
-  ):
-    super().__init__(results_dir, **kwargs)
-    self.mod_info = mod_info
-    self.src_top = src_top or pathlib.Path(
-        os.environ.get(constants.ANDROID_BUILD_TOP)
-    )
-    self.starlark_file = _get_resource_root().joinpath(
-        'format_as_soong_module_name.cquery'
-    )
-
-    self.bazel_workspace = workspace_path or get_bazel_workspace_dir()
-    self.bazel_binary = self.bazel_workspace.joinpath('bazel.sh')
-    self.run_command = run_command
-    self._extra_args = extra_args or {}
-    self.build_metadata = build_metadata or get_default_build_metadata()
-    self.env = env or os.environ
-    self._generate_workspace_fn = generate_workspace_fn
-    self._enabled_features = (
-        enabled_features
-        if enabled_features is not None
-        else atest_configs.GLOBAL_ARGS.bazel_mode_features
-    )
-
-  # pylint: disable=unused-argument
-  def run_tests(self, test_infos, extra_args, reporter):
-    """Run the list of test_infos.
-
-    Args:
-        test_infos: List of TestInfo.
-        extra_args: Dict of extra args to add to test run.
-        reporter: An instance of result_report.ResultReporter.
-    """
-    ret_code = ExitCode.SUCCESS
-
-    try:
-      run_cmds = self.generate_run_commands(test_infos, extra_args)
-    except AbortRunException as e:
-      atest_utils.colorful_print(f'Stop running test(s): {e}', constants.RED)
-      return ExitCode.ERROR
-
-    for run_cmd in run_cmds:
-      subproc = self.run(run_cmd, output_to_stdout=True)
-      ret_code |= self.wait_for_subprocess(subproc)
-
-    self.organize_test_logs(test_infos)
-
-    return ret_code
-
-  def organize_test_logs(self, test_infos: List[test_info.TestInfo]):
-    for t_info in test_infos:
-      test_output_dir, package_name, target_suffix = (
-          self.retrieve_test_output_info(t_info)
-      )
-      if test_output_dir.joinpath(TEST_OUTPUT_ZIP_NAME).exists():
-        # TEST_OUTPUT_ZIP file exist when BES uploading is enabled.
-        # Showing the BES link to users instead of the local log.
-        continue
-
-      # AtestExecutionInfo will find all log files in 'results_dir/log'
-      # directory and generate an HTML file to display to users when
-      # 'results_dir/log' directory exist.
-      log_path = pathlib.Path(self.results_dir).joinpath(
-          'log', f'{package_name}', f'{t_info.test_name}_{target_suffix}'
-      )
-      log_path.parent.mkdir(parents=True, exist_ok=True)
-      if not log_path.is_symlink():
-        log_path.symlink_to(test_output_dir)
-
-  def _get_feature_config_or_warn(self, feature, env_var_name):
-    feature_config = self.env.get(env_var_name)
-    if not feature_config:
-      atest_utils.print_and_log_warning(
-          'Ignoring `%s` because the `%s` environment variable is not set.',
-          # pylint: disable=no-member
-          feature,
-          env_var_name,
-      )
-    return feature_config
-
-  def _get_bes_publish_args(self, feature: Features) -> List[str]:
-    bes_publish_config = self._get_feature_config_or_warn(
-        feature, 'ATEST_BAZEL_BES_PUBLISH_CONFIG'
-    )
-
-    if not bes_publish_config:
-      return []
-
-    branch = self.build_metadata.build_branch
-    target = self.build_metadata.build_target
-
-    return [
-        f'--config={bes_publish_config}',
-        f'--build_metadata=ab_branch={branch}',
-        f'--build_metadata=ab_target={target}',
-    ]
-
-  def _get_remote_args(self, feature):
-    remote_config = self._get_feature_config_or_warn(
-        feature, 'ATEST_BAZEL_REMOTE_CONFIG'
-    )
-    if not remote_config:
-      return []
-    return [f'--config={remote_config}']
-
-  def _get_remote_avd_args(self, feature):
-    remote_avd_config = self._get_feature_config_or_warn(
-        feature, 'ATEST_BAZEL_REMOTE_AVD_CONFIG'
-    )
-    if not remote_avd_config:
-      raise ValueError(
-          'Cannot run remote device test because '
-          'ATEST_BAZEL_REMOTE_AVD_CONFIG '
-          'environment variable is not set.'
-      )
-    return [f'--config={remote_avd_config}']
-
-  def host_env_check(self):
-    """Check that host env has everything we need.
-
-    We actually can assume the host env is fine because we have the same
-    requirements that atest has. Update this to check for android env vars
-    if that changes.
-    """
-
-  def get_test_runner_build_reqs(self, test_infos) -> Set[str]:
-    if not test_infos:
-      return set()
-
-    self._generate_workspace_fn(
-        self.mod_info,
-        self._enabled_features,
-    )
-
-    deps_expression = ' + '.join(
-        sorted(self.test_info_target_label(i) for i in test_infos)
-    )
-
-    with tempfile.NamedTemporaryFile() as query_file:
-      with open(query_file.name, 'w', encoding='utf-8') as _query_file:
-        _query_file.write(f'deps(tests({deps_expression}))')
-
-      query_args = [
-          str(self.bazel_binary),
-          'cquery',
-          f'--query_file={query_file.name}',
-          '--output=starlark',
-          f'--starlark:file={self.starlark_file}',
-      ]
-
-      output = self.run_command(query_args, self.bazel_workspace)
-
-    targets = set()
-    robolectric_tests = set(
-        filter(
-            self._is_robolectric_test_suite,
-            [test.test_name for test in test_infos],
-        )
-    )
-
-    modules_to_variant = _parse_cquery_output(output)
-
-    for module, variants in modules_to_variant.items():
-
-      # Skip specifying the build variant for Robolectric test modules
-      # since they are special. Soong builds them with the `target`
-      # variant although are installed as 'host' modules.
-      if module in robolectric_tests:
-        targets.add(module)
-        continue
-
-      targets.add(_soong_target_for_variants(module, variants))
-
-    return targets
-
-  def _is_robolectric_test_suite(self, module_name: str) -> bool:
-    return self.mod_info.is_robolectric_test_suite(
-        self.mod_info.get_module_info(module_name)
-    )
-
-  def test_info_target_label(self, test: test_info.TestInfo) -> str:
-    module_name = test.test_name
-    info = self.mod_info.get_module_info(module_name)
-    package_name = info.get(constants.MODULE_PATH)[0]
-    target_suffix = self.get_target_suffix(info)
-
-    return f'//{package_name}:{module_name}_{target_suffix}'
-
-  def retrieve_test_output_info(
-      self, test_info: test_info.TestInfo
-  ) -> Tuple[pathlib.Path, str, str]:
-    """Return test output information.
-
-    Args:
-        test_info (test_info.TestInfo): Information about the test.
-
-    Returns:
-        Tuple[pathlib.Path, str, str]: A tuple containing the following
-        elements:
-            - test_output_dir (pathlib.Path): Absolute path of the test output
-                folder.
-            - package_name (str): Name of the package.
-            - target_suffix (str): Target suffix.
-    """
-    module_name = test_info.test_name
-    info = self.mod_info.get_module_info(module_name)
-    package_name = info.get(constants.MODULE_PATH)[0]
-    target_suffix = self.get_target_suffix(info)
-
-    test_output_dir = pathlib.Path(
-        self.bazel_workspace,
-        BAZEL_TEST_LOGS_DIR_NAME,
-        package_name,
-        f'{module_name}_{target_suffix}',
-        TEST_OUTPUT_DIR_NAME,
-    )
-
-    return test_output_dir, package_name, target_suffix
-
-  def get_target_suffix(self, info: Dict[str, Any]) -> str:
-    """Return 'host' or 'device' accordingly to the variant of the test."""
-    if not self._extra_args.get(
-        constants.HOST, False
-    ) and self.mod_info.is_device_driven_test(info):
-      return 'device'
-    return 'host'
-
-  @staticmethod
-  def _get_bazel_feature_args(
-      feature: Features, extra_args: Dict[str, Any], generator: Callable
-  ) -> List[str]:
-    if feature not in extra_args.get('BAZEL_MODE_FEATURES', []):
-      return []
-    return generator(feature)
-
-  # pylint: disable=unused-argument
-  def generate_run_commands(self, test_infos, extra_args, port=None):
-    """Generate a list of run commands from TestInfos.
-
-    Args:
-        test_infos: A set of TestInfo instances.
-        extra_args: A Dict of extra args to append.
-        port: Optional. An int of the port number to send events to.
-
-    Returns:
-        A list of run commands to run the tests.
-    """
-    startup_options = ''
-    bazelrc = self.env.get('ATEST_BAZELRC')
-
-    if bazelrc:
-      startup_options = f'--bazelrc={bazelrc}'
-
-    target_patterns = ' '.join(
-        self.test_info_target_label(i) for i in test_infos
-    )
-
-    bazel_args = parse_args(test_infos, extra_args)
-
-    # If BES is not enabled, use the option of
-    # '--nozip_undeclared_test_outputs' to not compress the test outputs.
-    # And the URL of test outputs will be printed in terminal.
-    bazel_args.extend(
-        self._get_bazel_feature_args(
-            Features.EXPERIMENTAL_BES_PUBLISH,
-            extra_args,
-            self._get_bes_publish_args,
-        )
-        or ['--nozip_undeclared_test_outputs']
-    )
-    bazel_args.extend(
-        self._get_bazel_feature_args(
-            Features.EXPERIMENTAL_REMOTE, extra_args, self._get_remote_args
-        )
-    )
-    bazel_args.extend(
-        self._get_bazel_feature_args(
-            Features.EXPERIMENTAL_REMOTE_AVD,
-            extra_args,
-            self._get_remote_avd_args,
-        )
-    )
-
-    # This is an alternative to shlex.join that doesn't exist in Python
-    # versions < 3.8.
-    bazel_args_str = ' '.join(shlex.quote(arg) for arg in bazel_args)
-
-    # Use 'cd' instead of setting the working directory in the subprocess
-    # call for a working --dry-run command that users can run.
-    return [
-        f'cd {self.bazel_workspace} && '
-        f'{self.bazel_binary} {startup_options} '
-        f'test {target_patterns} {bazel_args_str}'
-    ]
-
-
-def parse_args(
-    test_infos: List[test_info.TestInfo], extra_args: Dict[str, Any]
-) -> Dict[str, Any]:
-  """Parse commandline args and passes supported args to bazel.
-
-  Args:
-      test_infos: A set of TestInfo instances.
-      extra_args: A Dict of extra args to append.
-
-  Returns:
-      A list of args to append to the run command.
-  """
-
-  args_to_append = []
-  # Make a copy of the `extra_args` dict to avoid modifying it for other
-  # Atest runners.
-  extra_args_copy = extra_args.copy()
-
-  # Remove the `--host` flag since we already pass that in the rule's
-  # implementation.
-  extra_args_copy.pop(constants.HOST, None)
-
-  # Remove the serial arg since Bazel mode does not support device tests and
-  # the serial / -s arg conflicts with the TF null device option specified in
-  # the rule implementation (-n).
-  extra_args_copy.pop(constants.SERIAL, None)
-
-  # Map args to their native Bazel counterparts.
-  for arg in _SUPPORTED_BAZEL_ARGS:
-    if arg not in extra_args_copy:
-      continue
-    args_to_append.extend(_map_to_bazel_args(arg, extra_args_copy[arg]))
-    # Remove the argument since we already mapped it to a Bazel option
-    # and no longer need it mapped to a Tradefed argument below.
-    del extra_args_copy[arg]
-
-  # TODO(b/215461642): Store the extra_args in the top-level object so
-  # that we don't have to re-parse the extra args to get BAZEL_ARG again.
-  tf_args, _ = tfr.extra_args_to_tf_args(extra_args_copy)
-
-  # Add ATest include filter argument to allow testcase filtering.
-  tf_args.extend(tfr.get_include_filter(test_infos))
-
-  args_to_append.extend([f'--test_arg={i}' for i in tf_args])
-
-  # Disable test result caching when wait-for-debugger flag is set.
-  if '--wait-for-debugger' in tf_args:
-    # Remove the --cache_test_results flag if it's already set.
-    args_to_append = [
-        arg
-        for arg in args_to_append
-        if not arg.startswith('--cache_test_results')
-    ]
-    args_to_append.append('--cache_test_results=no')
-
-  # Default to --test_output=errors unless specified otherwise
-  if not any(arg.startswith('--test_output=') for arg in args_to_append):
-    args_to_append.append('--test_output=errors')
-
-  # Default to --test_summary=detailed unless specified otherwise, or if the
-  # feature is disabled
-  if not any(arg.startswith('--test_summary=') for arg in args_to_append) and (
-      Features.NO_BAZEL_DETAILED_SUMMARY
-      not in extra_args.get('BAZEL_MODE_FEATURES', [])
-  ):
-    args_to_append.append('--test_summary=detailed')
-
-  return args_to_append
-
-
-def _map_to_bazel_args(arg: str, arg_value: Any) -> List[str]:
-  return (
-      _SUPPORTED_BAZEL_ARGS[arg](arg_value)
-      if arg in _SUPPORTED_BAZEL_ARGS
-      else []
-  )
-
-
-def _parse_cquery_output(output: str) -> Dict[str, Set[str]]:
-  module_to_build_variants = defaultdict(set)
-
-  for line in filter(bool, map(str.strip, output.splitlines())):
-    module_name, build_variant = line.split(':')
-    module_to_build_variants[module_name].add(build_variant)
-
-  return module_to_build_variants
-
-
-def _soong_target_for_variants(
-    module_name: str, build_variants: Set[str]
-) -> str:
-
-  if not build_variants:
-    raise ValueError(
-        f'Missing the build variants for module {module_name} in cquery output!'
-    )
-
-  if len(build_variants) > 1:
-    return module_name
-
-  return f'{module_name}-{_CONFIG_TO_VARIANT[list(build_variants)[0]]}'
diff --git a/atest/cli_translator.py b/atest/cli_translator.py
index e2bf5f3d..fb4035ff 100644
--- a/atest/cli_translator.py
+++ b/atest/cli_translator.py
@@ -33,7 +33,6 @@ from typing import List, Set
 
 from atest import atest_error
 from atest import atest_utils
-from atest import bazel_mode
 from atest import constants
 from atest import rollout_control
 from atest import test_finder_handler
@@ -44,6 +43,7 @@ from atest.metrics import metrics_utils
 from atest.test_finders import module_finder
 from atest.test_finders import test_finder_utils
 from atest.test_finders import test_info
+from atest.test_finders.smart_test_finder import smart_test_finder
 from atest.tools import indexing
 
 FUZZY_FINDER = 'FUZZY'
@@ -86,9 +86,7 @@ class CLITranslator:
       self,
       mod_info=None,
       print_cache_msg=True,
-      bazel_mode_enabled=False,
       host=False,
-      bazel_mode_features: List[bazel_mode.Features] = None,
       indexing_thread: threading.Thread = None,
   ):
     """CLITranslator constructor
@@ -97,18 +95,11 @@ class CLITranslator:
         mod_info: ModuleInfo class that has cached module-info.json.
         print_cache_msg: Boolean whether printing clear cache message or not.
           True will print message while False won't print.
-        bazel_mode_enabled: Boolean of args.bazel_mode.
         host: Boolean of args.host.
-        bazel_mode_features: List of args.bazel_mode_features.
         indexing_thread: Thread of indexing.
     """
     self.mod_info = mod_info
     self.root_dir = os.getenv(constants.ANDROID_BUILD_TOP, os.sep)
-    self._bazel_mode = (
-        bazel_mode_enabled
-        and not rollout_control.deprecate_bazel_mode.is_enabled()
-    )
-    self._bazel_mode_features = bazel_mode_features or []
     self._host = host
     self.enable_file_patterns = False
     self.msg = ''
@@ -166,16 +157,6 @@ class CLITranslator:
     find_methods = test_finder_handler.get_find_methods_for_test(
         self.mod_info, test
     )
-    if self._bazel_mode:
-      find_methods = [
-          bazel_mode.create_new_finder(
-              self.mod_info,
-              f,
-              host=self._host,
-              enabled_features=self._bazel_mode_features,
-          )
-          for f in find_methods
-      ]
 
     for finder in find_methods:
       # Ideally whether a find method requires indexing should be defined within the
@@ -751,14 +732,21 @@ class CLITranslator:
     """
     tests = args.tests
     detect_type = DetectType.TEST_WITH_ARGS
-    # Disable fuzzy searching when running with test mapping related args.
-    if not args.tests or atest_utils.is_test_mapping(args):
+
+    # Disable fuzzy searching when running with test mapping or smart test
+    # selection related args.
+    if any((
+        not args.tests,
+        atest_utils.is_test_mapping(args),
+        args.smart_test_selection,
+    )):
       self.fuzzy_search = False
       detect_type = DetectType.TEST_NULL_ARGS
     start = time.time()
-    # Not including host unit tests if user specify --test-mapping.
+    # Not including host unit tests if user specify --test-mapping or
+    # --smart-test-selection.
     host_unit_tests = []
-    if not any((args.tests, args.test_mapping)):
+    if not any((args.tests, args.test_mapping, args.smart_test_selection)):
       logging.debug('Finding Host Unit Tests...')
       host_unit_tests = test_finder_utils.find_host_unit_tests(
           self.mod_info, str(Path(os.getcwd()).relative_to(self.root_dir))
@@ -774,12 +762,20 @@ class CLITranslator:
       )
     atest_utils.colorful_print('\nFinding Tests...', constants.CYAN)
     logging.debug('Finding Tests: %s', tests)
-    # Clear cache if user pass -c option
-    if args.clear_cache:
-      atest_utils.clean_test_info_caches(tests + host_unit_tests)
     # Process tests which might contain wildcard symbols in advance.
     if atest_utils.has_wildcard(tests):
       tests = self._extract_testable_modules_by_wildcard(tests)
+    if args.smart_test_selection:
+      tests = smart_test_finder.get_smartly_selected_tests(
+          mod_info=self.mod_info, root_dir=self.root_dir
+      )
+      if not tests:
+        metrics.LocalDetectEvent(
+            detect_type=DetectType.STS_SELECT_NO_TEST, result=1
+        )
+    # Clear cache if user pass -c option
+    if args.clear_cache:
+      atest_utils.clean_test_info_caches(tests + host_unit_tests)
     test_infos = self._get_test_infos(tests, test_details_list)
     if host_unit_tests:
       host_unit_test_details = [
@@ -790,7 +786,10 @@ class CLITranslator:
           host_unit_tests, host_unit_test_details
       )
       test_infos.extend(host_unit_test_infos)
-    if atest_utils.has_mixed_type_filters(test_infos):
+    if (
+        atest_utils.has_mixed_type_filters(test_infos)
+        and not args.smart_test_selection
+    ):
       atest_utils.colorful_print(
           'Mixed type filters found. '
           'Please separate tests into different runs.',
diff --git a/atest/cli_translator_unittest.py b/atest/cli_translator_unittest.py
index 9a43cf08..5c5dcdc5 100755
--- a/atest/cli_translator_unittest.py
+++ b/atest/cli_translator_unittest.py
@@ -26,6 +26,7 @@ import tempfile
 import unittest
 from unittest import mock
 from atest import arg_parser
+from atest import atest_enum
 from atest import atest_utils
 from atest import cli_translator as cli_t
 from atest import constants
@@ -38,6 +39,7 @@ from atest.metrics import metrics
 from atest.test_finders import module_finder
 from atest.test_finders import test_finder_base
 from atest.test_finders import test_finder_utils
+from atest.test_finders.smart_test_finder import smart_test_finder
 from pyfakefs import fake_filesystem_unittest
 
 
@@ -568,6 +570,77 @@ class CLITranslatorUnittests(unittest.TestCase):
         ],
     )
 
+  @mock.patch.object(metrics, 'LocalDetectEvent')
+  @mock.patch.object(os, 'getcwd', return_value='/src/build_top/somewhere')
+  @mock.patch.object(
+      smart_test_finder,
+      'get_smartly_selected_tests',
+      return_value=[uc.CLASS_NAME],
+  )
+  @mock.patch.object(
+      cli_t.CLITranslator,
+      '_get_test_infos',
+      side_effect=gettestinfos_side_effect,
+  )
+  def test_translate_tests_returned_from_smart_test_selection(
+      self,
+      _info,
+      _get_smartly_selected_tests,
+      _getcwd,
+      _local_detect_event,
+  ):
+    """Test translate method for smart test selection plus host unit tests."""
+    self.args.tests = []
+    self.args.host = False
+    self.args.host_unit_test_only = False
+    self.args.smart_test_selection = True
+
+    test_infos = self.ctr.translate(self.args)
+
+    unittest_utils.assert_equal_testinfo_lists(
+        self,
+        test_infos,
+        [
+            uc.CLASS_INFO,
+        ],
+    )
+    self.assertNotIn(
+        mock.call(
+            detect_type=atest_enum.DetectType.STS_SELECT_NO_TEST, result=1
+        ),
+        _local_detect_event.mock_calls,
+    )
+
+  @mock.patch.object(metrics, 'LocalDetectEvent')
+  @mock.patch.object(
+      smart_test_finder,
+      'get_smartly_selected_tests',
+      return_value=[],
+  )
+  @mock.patch.object(
+      cli_t.CLITranslator,
+      '_get_test_infos',
+      side_effect=gettestinfos_side_effect,
+  )
+  def test_translate_no_tests_from_smart_test_selection(
+      self,
+      _info,
+      _get_smartly_selected_tests,
+      _local_detect_event,
+  ):
+    """Test translate method for smart test selection when no tests returned."""
+    self.args.tests = []
+    self.args.host = False
+    self.args.host_unit_test_only = False
+    self.args.smart_test_selection = True
+
+    test_infos = self.ctr.translate(self.args)
+
+    self.assertCountEqual(test_infos, [])
+    _local_detect_event.assert_any_call(
+        detect_type=atest_enum.DetectType.STS_SELECT_NO_TEST, result=1
+    )
+
   @mock.patch.object(
       test_finder_utils,
       'find_host_unit_tests',
diff --git a/atest/constants_default.py b/atest/constants_default.py
index 2880c32b..b4e6b9da 100644
--- a/atest/constants_default.py
+++ b/atest/constants_default.py
@@ -52,13 +52,11 @@ TF_DEBUG = 'TF_DEBUG'
 DEFAULT_DEBUG_PORT = '10888'
 COLLECT_TESTS_ONLY = 'COLLECT_TESTS_ONLY'
 TF_TEMPLATE = 'TF_TEMPLATE'
-BAZEL_MODE_FEATURES = 'BAZEL_MODE_FEATURES'
 REQUEST_UPLOAD_RESULT = 'REQUEST_UPLOAD_RESULT'
 DISABLE_UPLOAD_RESULT = 'DISABLE_UPLOAD_RESULT'
 MODULES_IN = 'MODULES-IN-'
 AGGREGATE_METRIC_FILTER_ARG = 'AGGREGATE_METRIC_FILTER'
 ANNOTATION_FILTER = 'ANNOTATION_FILTER'
-BAZEL_ARG = 'BAZEL_ARG'
 COVERAGE = 'COVERAGE'
 TEST_FILTER = 'TEST_FILTER'
 TEST_TIMEOUT = 'TEST_TIMEOUT'
@@ -394,5 +392,15 @@ REQUIRE_DEVICES_MSG = (
 # Default shard num.
 SHARD_NUM = 2
 
+# The keyword for summarizing test results in class granularity
+CLASS_LEVEL_REPORT = 'class_level_report'
+
 # Smart test selection keyword.
 SMART_TEST_SELECTION = 'smart_test_selection'
+
+# Smart test selection X20 root path.
+SMART_TEST_SELECTION_ROOT_PATH = ''
+
+# TODO(b/414460878): Make this time limit an argument, and also pass it to smart
+# test finder as a criteria to select tests.
+SMART_TEST_EXECUTION_TIME_LIMIT_IN_MINUTES = 5
diff --git a/atest/crystalball/OWNERS b/atest/crystalball/OWNERS
new file mode 100644
index 00000000..e2647f02
--- /dev/null
+++ b/atest/crystalball/OWNERS
@@ -0,0 +1 @@
+jinghuanwen@google.com
\ No newline at end of file
diff --git a/atest/crystalball/metric_printer.py b/atest/crystalball/metric_printer.py
new file mode 100644
index 00000000..7c79ea7d
--- /dev/null
+++ b/atest/crystalball/metric_printer.py
@@ -0,0 +1,271 @@
+#!/usr/bin/env python
+#
+# Copyright 2025, The Android Open Source Project
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
+import argparse
+import logging
+import pathlib
+import re
+
+from atest import atest_utils
+from atest import constants
+from atest.test_runners import test_runner_base
+
+PERF_TEST_TEMPLATE = 'template/performance-tests-base'
+PERF_MODULE_ARG_NAME = '--perf'
+
+
+BENCHMARK_ESSENTIAL_KEYS = {
+    'repetition_index',
+    'cpu_time',
+    'name',
+    'repetitions',
+    'run_type',
+    'threads',
+    'time_unit',
+    'iterations',
+    'run_name',
+    'real_time',
+}
+# TODO(b/146875480): handle the optional benchmark events
+BENCHMARK_OPTIONAL_KEYS = {'bytes_per_second', 'label'}
+BENCHMARK_EVENT_KEYS = BENCHMARK_ESSENTIAL_KEYS.union(BENCHMARK_OPTIONAL_KEYS)
+INT_KEYS = {}
+
+
+class PerfInfo:
+  """Class for storing performance test of a test run."""
+
+  def __init__(self):
+    """Initialize a new instance of PerfInfo class."""
+    # perf_info: A list of benchmark_info(dict).
+    self.perf_info = []
+
+  def update_perf_info(self, test):
+    """Update perf_info with the given result of a single test.
+
+    Args:
+        test: A TestResult namedtuple.
+    """
+    all_additional_keys = set(test.additional_info.keys())
+    # Ensure every key is in all_additional_keys.
+    if not BENCHMARK_ESSENTIAL_KEYS.issubset(all_additional_keys):
+      return
+    benchmark_info = {}
+    benchmark_info['test_name'] = test.test_name
+    for key, data in test.additional_info.items():
+      if key in INT_KEYS:
+        data_to_int = data.split('.')[0]
+        benchmark_info[key] = data_to_int
+      elif key in BENCHMARK_EVENT_KEYS:
+        benchmark_info[key] = data
+    if benchmark_info:
+      self.perf_info.append(benchmark_info)
+
+  def print_perf_info(self):
+    """Print summary of a perf_info."""
+    if not self.perf_info:
+      return
+    classify_perf_info, max_len = self._classify_perf_info()
+    separator = '-' * atest_utils.get_terminal_size()[0]
+    print(separator)
+    print(
+        '{:{name}}    {:^{real_time}}    {:^{cpu_time}}    '
+        '{:>{iterations}}'.format(
+            'Benchmark',
+            'Time',
+            'CPU',
+            'Iteration',
+            name=max_len['name'] + 3,
+            real_time=max_len['real_time'] + max_len['time_unit'] + 1,
+            cpu_time=max_len['cpu_time'] + max_len['time_unit'] + 1,
+            iterations=max_len['iterations'],
+        )
+    )
+    print(separator)
+    for module_name, module_perf_info in classify_perf_info.items():
+      print('{}:'.format(module_name))
+      for benchmark_info in module_perf_info:
+        # BpfBenchMark/MapWriteNewEntry/1    1530 ns     1522 ns   460517
+        print(
+            '  #{:{name}}    {:>{real_time}} {:{time_unit}}    '
+            '{:>{cpu_time}} {:{time_unit}}    '
+            '{:>{iterations}}'.format(
+                benchmark_info['name'],
+                benchmark_info['real_time'],
+                benchmark_info['time_unit'],
+                benchmark_info['cpu_time'],
+                benchmark_info['time_unit'],
+                benchmark_info['iterations'],
+                name=max_len['name'],
+                real_time=max_len['real_time'],
+                time_unit=max_len['time_unit'],
+                cpu_time=max_len['cpu_time'],
+                iterations=max_len['iterations'],
+            )
+        )
+
+  def _classify_perf_info(self):
+    """Classify the perf_info by test module name.
+
+    Returns:
+        A tuple of (classified_perf_info, max_len), where
+        classified_perf_info: A dict of perf_info and each perf_info are
+                             belong to different modules.
+            e.g.
+                { module_name_01: [perf_info of module_1],
+                  module_name_02: [perf_info of module_2], ...}
+        max_len: A dict which stores the max length of each event.
+                 It contains the max string length of 'name', real_time',
+                 'time_unit', 'cpu_time', 'iterations'.
+            e.g.
+                {name: 56, real_time: 9, time_unit: 2, cpu_time: 8,
+                 iterations: 12}
+    """
+    module_categories = set()
+    max_len = {}
+    all_name = []
+    all_real_time = []
+    all_time_unit = []
+    all_cpu_time = []
+    all_iterations = ['Iteration']
+    for benchmark_info in self.perf_info:
+      module_categories.add(benchmark_info['test_name'].split('#')[0])
+      all_name.append(benchmark_info['name'])
+      all_real_time.append(benchmark_info['real_time'])
+      all_time_unit.append(benchmark_info['time_unit'])
+      all_cpu_time.append(benchmark_info['cpu_time'])
+      all_iterations.append(benchmark_info['iterations'])
+    classified_perf_info = {}
+    for module_name in module_categories:
+      module_perf_info = []
+      for benchmark_info in self.perf_info:
+        if benchmark_info['test_name'].split('#')[0] == module_name:
+          module_perf_info.append(benchmark_info)
+      classified_perf_info[module_name] = module_perf_info
+    max_len = {
+        'name': len(max(all_name, key=len)),
+        'real_time': len(max(all_real_time, key=len)),
+        'time_unit': len(max(all_time_unit, key=len)),
+        'cpu_time': len(max(all_cpu_time, key=len)),
+        'iterations': len(max(all_iterations, key=len)),
+    }
+    return classified_perf_info, max_len
+
+  @staticmethod
+  def print_banchmark_result(test: test_runner_base.TestResult):
+    for key, data in sorted(test.additional_info.items()):
+      if key not in BENCHMARK_EVENT_KEYS:
+        print(f'\t{atest_utils.mark_blue(key)}: {data}')
+
+  @classmethod
+  def print_perf_test_metrics(cls, test_infos, log_path, args) -> bool:
+    """Print perf test metrics text content to console.
+
+    Returns:
+        True if metric printing is attempted; False if not perf tests.
+    """
+    if not any(
+        'performance-tests' in info.compatibility_suites for info in test_infos
+    ):
+      return False
+
+    if not log_path:
+      return True
+
+    aggregated_metric_files = atest_utils.find_files(
+        log_path, file_name='*_aggregate_test_metrics_*.txt'
+    )
+
+    if args.perf_itr_metrics:
+      individual_metric_files = atest_utils.find_files(
+          log_path, file_name='test_results_*.txt'
+      )
+      print('\n{}'.format(atest_utils.mark_cyan('Individual test metrics')))
+      print(atest_utils.delimiter('-', 7))
+      for metric_file in individual_metric_files:
+        metric_file_path = pathlib.Path(metric_file)
+        # Skip aggregate metrics as we are printing individual metrics here.
+        if '_aggregate_test_metrics_' in metric_file_path.name:
+          continue
+        print('{}:'.format(atest_utils.mark_cyan(metric_file_path.name)))
+        print(
+            ''.join(
+                f'{" "*4}{line}'
+                for line in metric_file_path.read_text(
+                    encoding='utf-8'
+                ).splitlines(keepends=True)
+            )
+        )
+
+    print('\n{}'.format(atest_utils.mark_cyan('Aggregate test metrics')))
+    print(atest_utils.delimiter('-', 7))
+    for metric_file in aggregated_metric_files:
+      cls._print_test_metric(pathlib.Path(metric_file), args)
+
+    return True
+
+  @staticmethod
+  def _print_test_metric(
+      metric_file: pathlib.Path, args: argparse.Namespace
+  ) -> None:
+    """Print the content of the input metric file."""
+    test_metrics_re = re.compile(
+        r'test_results.*\s(.*)_aggregate_test_metrics_.*\.txt'
+    )
+    if not metric_file.is_file():
+      return
+    matches = re.findall(test_metrics_re, metric_file.as_posix())
+    test_name = matches[0] if matches else ''
+    if test_name:
+      print('{}:'.format(atest_utils.mark_cyan(test_name)))
+      with metric_file.open('r', encoding='utf-8') as f:
+        matched = False
+        filter_res = args.aggregate_metric_filter
+        logging.debug('Aggregate metric filters: %s', filter_res)
+        test_methods = []
+        # Collect all test methods
+        if filter_res:
+          test_re = re.compile(r'\n\n(\S+)\n\n', re.MULTILINE)
+          test_methods = re.findall(test_re, f.read())
+          f.seek(0)
+          # The first line of the file is also a test method but could
+          # not parsed by test_re; add the first line manually.
+          first_line = f.readline()
+          test_methods.insert(0, str(first_line).strip())
+          f.seek(0)
+        for line in f.readlines():
+          stripped_line = str(line).strip()
+          if filter_res:
+            if stripped_line in test_methods:
+              print()
+              atest_utils.colorful_print(
+                  ' ' * 4 + stripped_line, constants.MAGENTA
+              )
+            for filter_re in filter_res:
+              if re.match(re.compile(filter_re), line):
+                matched = True
+                print(' ' * 4 + stripped_line)
+          else:
+            matched = True
+            print(' ' * 4 + stripped_line)
+        if not matched:
+          atest_utils.colorful_print(
+              '  Warning: Nothing returned by the pattern: {}'.format(
+                  filter_res
+              ),
+              constants.RED,
+          )
+        print()
diff --git a/atest/crystalball/metric_printer_unittest.py b/atest/crystalball/metric_printer_unittest.py
new file mode 100644
index 00000000..1c10a174
--- /dev/null
+++ b/atest/crystalball/metric_printer_unittest.py
@@ -0,0 +1,300 @@
+#!/usr/bin/env python
+#
+# Copyright 2025, The Android Open Source Project
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
+
+from atest import arg_parser
+from atest import result_reporter
+from atest.crystalball import metric_printer
+from atest.test_finders import test_info
+from atest.test_runners import test_runner_base
+
+
+class TestPerfInfo(unittest.TestCase):
+
+  def setUp(self):
+    self.rr = result_reporter.ResultReporter()
+
+  def test_update_perf_info(self):
+    """Test update_perf_info method."""
+    group = result_reporter.RunStat()
+    # 1. Test PerfInfo after RESULT_PERF01_TEST01
+    # _update_stats() will call _update_perf_info()
+    self.rr._update_stats(RESULT_PERF01_TEST01, group)
+    correct_perf_info = []
+    trim_perf01_test01 = {
+        'repetition_index': '0',
+        'cpu_time': '10001.10001',
+        'name': 'perfName01',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1001',
+        'run_name': 'perfName01',
+        'real_time': '11001.11001',
+        'test_name': 'somePerfClass01#perfName01',
+    }
+    correct_perf_info.append(trim_perf01_test01)
+    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
+    # 2. Test PerfInfo after RESULT_PERF01_TEST01
+    self.rr._update_stats(RESULT_PERF01_TEST02, group)
+    trim_perf01_test02 = {
+        'repetition_index': '0',
+        'cpu_time': '10002.10002',
+        'name': 'perfName02',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1002',
+        'run_name': 'perfName02',
+        'real_time': '11002.11002',
+        'test_name': 'somePerfClass01#perfName02',
+    }
+    correct_perf_info.append(trim_perf01_test02)
+    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
+    # 3. Test PerfInfo after RESULT_PERF02_TEST01
+    self.rr._update_stats(RESULT_PERF02_TEST01, group)
+    trim_perf02_test01 = {
+        'repetition_index': '0',
+        'cpu_time': '20001.20001',
+        'name': 'perfName11',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '2001',
+        'run_name': 'perfName11',
+        'real_time': '21001.21001',
+        'test_name': 'somePerfClass02#perfName11',
+    }
+    correct_perf_info.append(trim_perf02_test01)
+    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
+    # 4. Test PerfInfo after RESULT_PERF01_TEST03_NO_CPU_TIME
+    self.rr._update_stats(RESULT_PERF01_TEST03_NO_CPU_TIME, group)
+    # Nothing added since RESULT_PERF01_TEST03_NO_CPU_TIME lack of cpu_time
+    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
+
+  def test_classify_perf_info(self):
+    """Test _classify_perf_info method."""
+    group = result_reporter.RunStat()
+    self.rr._update_stats(RESULT_PERF01_TEST01, group)
+    self.rr._update_stats(RESULT_PERF01_TEST02, group)
+    self.rr._update_stats(RESULT_PERF02_TEST01, group)
+    # trim the time form 10001.10001 to 10001
+    trim_perf01_test01 = {
+        'repetition_index': '0',
+        'cpu_time': '10001.10001',
+        'name': 'perfName01',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1001',
+        'run_name': 'perfName01',
+        'real_time': '11001.11001',
+        'test_name': 'somePerfClass01#perfName01',
+    }
+    trim_perf01_test02 = {
+        'repetition_index': '0',
+        'cpu_time': '10002.10002',
+        'name': 'perfName02',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1002',
+        'run_name': 'perfName02',
+        'real_time': '11002.11002',
+        'test_name': 'somePerfClass01#perfName02',
+    }
+    trim_perf02_test01 = {
+        'repetition_index': '0',
+        'cpu_time': '20001.20001',
+        'name': 'perfName11',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '2001',
+        'run_name': 'perfName11',
+        'real_time': '21001.21001',
+        'test_name': 'somePerfClass02#perfName11',
+    }
+    correct_classify_perf_info = {
+        'somePerfClass01': [trim_perf01_test01, trim_perf01_test02],
+        'somePerfClass02': [trim_perf02_test01],
+    }
+    classify_perf_info, max_len = (
+        self.rr.run_stats.perf_info._classify_perf_info()
+    )
+    correct_max_len = {
+        'real_time': 11,
+        'cpu_time': 11,
+        'name': 10,
+        'iterations': 9,
+        'time_unit': 2,
+    }
+    self.assertEqual(max_len, correct_max_len)
+    self.assertEqual(classify_perf_info, correct_classify_perf_info)
+
+  def test_print_perf_test_metrics_perf_tests_print_attempted(self):
+    args = arg_parser.parse_args(['--perf', 'MyModule'])
+    test_infos = [
+        test_info.TestInfo(
+            'some_module',
+            'TestRunner',
+            set(),
+            compatibility_suites=['performance-tests'],
+        )
+    ]
+    is_print_attempted = metric_printer.PerfInfo.print_perf_test_metrics(
+        test_infos, 'log_path', args
+    )
+
+    self.assertTrue(is_print_attempted)
+
+  def test_print_perf_test_metrics_not_perf_tests_print__not_attempted(self):
+    args = arg_parser.parse_args(['MyModule'])
+    test_infos = [
+        test_info.TestInfo(
+            'some_module',
+            'TestRunner',
+            set(),
+            compatibility_suites=['not-perf-test'],
+        )
+    ]
+    is_print_attempted = metric_printer.PerfInfo.print_perf_test_metrics(
+        test_infos, 'log_path', args
+    )
+
+    self.assertFalse(is_print_attempted)
+
+
+ADDITIONAL_INFO_PERF01_TEST01 = {
+    'repetition_index': '0',
+    'cpu_time': '10001.10001',
+    'name': 'perfName01',
+    'repetitions': '0',
+    'run_type': 'iteration',
+    'label': '2123',
+    'threads': '1',
+    'time_unit': 'ns',
+    'iterations': '1001',
+    'run_name': 'perfName01',
+    'real_time': '11001.11001',
+}
+
+RESULT_PERF01_TEST01 = test_runner_base.TestResult(
+    runner_name='someTestRunner',
+    group_name='someTestModule',
+    test_name='somePerfClass01#perfName01',
+    status=test_runner_base.PASSED_STATUS,
+    details=None,
+    test_count=1,
+    test_time='(10ms)',
+    runner_total=None,
+    group_total=2,
+    additional_info=ADDITIONAL_INFO_PERF01_TEST01,
+    test_run_name='com.android.UnitTests',
+)
+
+RESULT_PERF01_TEST02 = test_runner_base.TestResult(
+    runner_name='someTestRunner',
+    group_name='someTestModule',
+    test_name='somePerfClass01#perfName02',
+    status=test_runner_base.PASSED_STATUS,
+    details=None,
+    test_count=1,
+    test_time='(10ms)',
+    runner_total=None,
+    group_total=2,
+    additional_info={
+        'repetition_index': '0',
+        'cpu_time': '10002.10002',
+        'name': 'perfName02',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1002',
+        'run_name': 'perfName02',
+        'real_time': '11002.11002',
+    },
+    test_run_name='com.android.UnitTests',
+)
+
+RESULT_PERF01_TEST03_NO_CPU_TIME = test_runner_base.TestResult(
+    runner_name='someTestRunner',
+    group_name='someTestModule',
+    test_name='somePerfClass01#perfName03',
+    status=test_runner_base.PASSED_STATUS,
+    details=None,
+    test_count=1,
+    test_time='(10ms)',
+    runner_total=None,
+    group_total=2,
+    additional_info={
+        'repetition_index': '0',
+        'name': 'perfName03',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '1003',
+        'run_name': 'perfName03',
+        'real_time': '11003.11003',
+    },
+    test_run_name='com.android.UnitTests',
+)
+
+RESULT_PERF02_TEST01 = test_runner_base.TestResult(
+    runner_name='someTestRunner',
+    group_name='someTestModule',
+    test_name='somePerfClass02#perfName11',
+    status=test_runner_base.PASSED_STATUS,
+    details=None,
+    test_count=1,
+    test_time='(10ms)',
+    runner_total=None,
+    group_total=2,
+    additional_info={
+        'repetition_index': '0',
+        'cpu_time': '20001.20001',
+        'name': 'perfName11',
+        'repetitions': '0',
+        'run_type': 'iteration',
+        'label': '2123',
+        'threads': '1',
+        'time_unit': 'ns',
+        'iterations': '2001',
+        'run_name': 'perfName11',
+        'real_time': '21001.21001',
+    },
+    test_run_name='com.android.UnitTests',
+)
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/crystalball/perf_mode.py b/atest/crystalball/perf_mode.py
new file mode 100644
index 00000000..d10fd7d2
--- /dev/null
+++ b/atest/crystalball/perf_mode.py
@@ -0,0 +1,209 @@
+#!/usr/bin/env python
+#
+# Copyright 2025, The Android Open Source Project
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
+import argparse
+import copy
+
+from atest import atest_utils
+from atest.test_finders import test_info
+
+PERF_TEST_TEMPLATE = 'template/performance-tests-base'
+PERF_MODE_ARG_NAME = '--perf'
+
+
+def add_arguments(parser: argparse.ArgumentParser):
+  """Adds perf-related arguments to the argument parser.
+
+  Args:
+    parser: An argparse.ArgumentParser object.
+  """
+  parser.add_argument(
+      '--instr-arg',
+      dest='instrumentation_arg',
+      help=(
+          '(For performance tests) An instrumentation argument to pass to the'
+          ' test. This option is used in'
+          ' com.android.tradefed.testtype.AndroidJUnitTest.'
+      ),
+  )
+
+  parser.add_argument(
+      '--iter',
+      type=int,
+      help=(
+          '(For performance tests) The number of iterations to run the'
+          ' microbenchmark. This option is used in'
+          ' com.android.tradefed.testtype.AndroidJUnitTest to control the'
+          ' microbenchmark iterations.'
+      ),
+  )
+
+  parser.add_argument(
+      '--class',
+      dest='class_name',
+      help=(
+          '(For performance tests) The name of the Microbenchmark or CUJ class'
+          ' to run. This option is used in'
+          ' com.android.tradefed.testtype.AndroidJUnitTest to specify which'
+          ' class will run.'
+      ),
+  )
+
+  parser.add_argument(
+      '--metric-filter',
+      dest='metric_filter',
+      help=(
+          '(For performance tests) Regular expression that will be used for'
+          ' filtering the metrics from individual test metrics and aggregated'
+          ' metrics. This option is equivalent to the option'
+          ' "strict-include-metric-filter" in'
+          ' com.android.tradefed.postprocessor.MetricFilePostProcessor.'
+          ' Right now in the perf test, only the aggregated metrics works well.'
+      ),
+  )
+
+
+def process_parsed_args(args: argparse.Namespace):
+  """Processes perf-related arguments.
+
+  Args:
+    args: The arguments parsed by argparse.
+  """
+  original_args = copy.deepcopy(args)
+
+  if args.instrumentation_arg:
+    module_name = args.tests[0]
+    module_arg = f'{module_name}:{{com.android.tradefed.testtype.AndroidJUnitTest}}instrumentation-arg:{args.instrumentation_arg}'
+    args.custom_args.append('--module-arg')
+    args.custom_args.append(module_arg)
+    print(
+        f'Converting argument "--instr-arg {args.instrumentation_arg}" to'
+        f' "--module-arg {module_arg}"'
+    )
+
+  if args.iter:
+    module_name = args.tests[0]
+    module_arg = f'{module_name}:{{com.android.tradefed.testtype.AndroidJUnitTest}}instrumentation-arg:iterations:={args.iter}'
+    args.custom_args.append('--module-arg')
+    args.custom_args.append(module_arg)
+    print(
+        f'Converting argument "--iter {args.iter}" to "--module-arg'
+        f' {module_arg}"'
+    )
+
+  if args.class_name:
+    module_name = args.tests[0]
+    module_arg = f'{module_name}:{{com.android.tradefed.testtype.AndroidJUnitTest}}class:{args.class_name}'
+    args.custom_args.append('--module-arg')
+    args.custom_args.append(module_arg)
+    print(
+        f'Converting argument "--class {args.class_name}" to "--module-arg'
+        f' {module_arg}"'
+    )
+
+  if args.metric_filter:
+    module_name = args.tests[0]
+    module_arg = f'{module_name}:{{com.android.tradefed.postprocessor.MetricFilePostProcessor}}strict-include-metric-filter:{args.metric_filter}'
+    args.custom_args.append('--module-arg')
+    args.custom_args.append(module_arg)
+    print(
+        f'Converting argument "--metric-filter {args.metric_filter}" to'
+        f' "--module-arg {module_arg}"'
+    )
+
+  if str(original_args) != str(args):
+    print(  # TODO(jinghuanwen): update or remove this message
+        atest_utils.mark_magenta(
+            'Perf arguments simplification experimental feature was triggered.'
+            ' If you like the change please +1 to b/347360193, or leave'
+            ' comments if you have feedbacks.'
+        )
+    )
+
+
+def add_global_arguments(parser: argparse.ArgumentParser):
+  """Adds perf-related arguments to the global argument parser.
+
+  Args:
+    parser: An argparse.ArgumentParser object.
+  """
+
+  parser.add_argument(
+      PERF_MODE_ARG_NAME,
+      action='store_true',
+      help=(
+          '(For performance tests) Enable performance test mode. This option'
+          ' enables some performance-related arguments and logic in atest.'
+      ),
+  )
+
+  parser.add_argument(
+      '--aggregate-metric-filter',
+      action='append',
+      help=(
+          '(For performance tests) Regular expression that will be used for'
+          ' filtering the aggregated metrics.'
+      ),
+  )
+
+  parser.add_argument(
+      '--perf-itr-metrics',
+      action='store_true',
+      help='(For performance tests) Print individual performance metric.',
+  )
+
+
+def is_perf_test(
+    args: argparse.Namespace = None, test_infos: list[test_info.TestInfo] = None
+):
+  """Check if it is a performance test.
+
+  Args:
+    args: The arguments parsed by argparse.
+    test_infos: The list of TestInfo objects.
+
+  Returns:
+    True if it is a performance test, False otherwise or not enough information
+    to determine.
+  """
+  if args and getattr(args, PERF_MODE_ARG_NAME.replace('-', ''), False):
+    return True
+
+  if test_infos:
+    return any(
+        'performance-tests' in info.compatibility_suites for info in test_infos
+    )
+
+  return False
+
+
+def set_default_argument_values(args: argparse.Namespace):
+  """Sets default values for perf-related arguments.
+
+  Args:
+    args: The arguments parsed by argparse.
+  """
+  if not args.disable_upload_result:
+    args.request_upload_result = True
+
+
+def set_invocation_properties(invocation_properties: dict[str, str]):
+  """Sets invocation properties for perf tests.
+
+  Args:
+    invocation_properties: A dictionary to store invocation properties.
+  """
+  invocation_properties['crystalball_ingest'] = 'yes'
diff --git a/atest/crystalball/perf_mode_unittest.py b/atest/crystalball/perf_mode_unittest.py
new file mode 100644
index 00000000..9940d004
--- /dev/null
+++ b/atest/crystalball/perf_mode_unittest.py
@@ -0,0 +1,122 @@
+#!/usr/bin/env python
+#
+# Copyright 2025, The Android Open Source Project
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
+
+from atest import arg_parser
+from atest.crystalball import perf_mode
+from atest.test_finders import test_info
+
+
+class TestPerfModule(unittest.TestCase):
+
+  def test_process_parsed_args_adds_iter_to_custom_args(self):
+    argv = ['--perf', '--iter', '12345', 'MyModule']
+
+    args = arg_parser.parse_args(argv)
+
+    self.assertTrue(any('12345' in arg for arg in args.custom_args))
+
+  def test_parse_args_with_perf_and_iter_sets_iter_attribute(self):
+    argv = ['--perf', '--iter', '10', 'MyModule']
+
+    args = arg_parser.parse_args(argv)
+
+    self.assertTrue(hasattr(args, 'iter'))
+    self.assertEqual(args.iter, 10)
+
+  def test_parse_args_without_perf_does_not_set_iter_attribute(self):
+    argv = ['--iter', '10', 'MyModule']
+
+    args = arg_parser.parse_args(argv)
+
+    self.assertFalse(hasattr(args, 'iter'))
+
+  def test_is_perf_test_with_args_perf_returns_true(self):
+    args = arg_parser.parse_args(['--perf', 'MyModule'])
+
+    res = perf_mode.is_perf_test(args)
+
+    self.assertTrue(res)
+
+  def test_is_perf_test_without_perf_returns_false(self):
+    args = arg_parser.parse_args(['MyModule'])
+
+    res = perf_mode.is_perf_test(args)
+
+    self.assertFalse(res)
+
+  def test_is_perf_test_with_test_infos_perf_suite_returns_true(self):
+    test_infos = [
+        test_info.TestInfo(
+            test_name='MyModule',
+            test_runner='MyRunner',
+            build_targets=[],
+            compatibility_suites=['performance-tests'],
+        )
+    ]
+
+    res = perf_mode.is_perf_test(test_infos=test_infos)
+
+    self.assertTrue(res)
+
+  def test_is_perf_test_with_test_infos_no_perf_suite_returns_false(self):
+    test_infos = [
+        test_info.TestInfo(
+            test_name='MyModule',
+            test_runner='MyRunner',
+            build_targets=[],
+            compatibility_suites=['cts'],
+        )
+    ]
+
+    res = perf_mode.is_perf_test(test_infos=test_infos)
+
+    self.assertFalse(res)
+
+  def test_is_perf_test_with_no_args_and_no_test_infos_returns_false(self):
+    res = perf_mode.is_perf_test()
+
+    self.assertFalse(res)
+
+  def test_set_default_argument_values_sets_request_upload_result_if_not_disabled(
+      self,
+  ):
+    args = arg_parser.parse_args(['MyModule'])
+
+    perf_mode.set_default_argument_values(args)
+
+    self.assertTrue(args.request_upload_result)
+
+  def test_set_default_argument_values_does_not_set_request_upload_result_if_disabled(
+      self,
+  ):
+    args = arg_parser.parse_args(['--disable-upload-result', 'MyModule'])
+
+    perf_mode.set_default_argument_values(args)
+
+    self.assertFalse(args.request_upload_result)
+
+  def test_set_invocation_properties_sets_crystalball_ingest(self):
+    invocation_properties = {}
+
+    perf_mode.set_invocation_properties(invocation_properties)
+
+    self.assertIn('crystalball_ingest', invocation_properties)
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/integration_tests/Android.bp b/atest/integration_tests/Android.bp
index 7ce5b00a..c9f856ac 100644
--- a/atest/integration_tests/Android.bp
+++ b/atest/integration_tests/Android.bp
@@ -26,34 +26,6 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-python_test_host {
-    name: "bazel_mode_test",
-    srcs: [
-        "bazel_mode_test.py",
-    ],
-    test_config_template: "bazel_mode_test.xml",
-    test_suites: [
-        "general-tests",
-    ],
-    test_options: {
-        unit_test: false,
-    },
-}
-
-python_test_host {
-    name: "result_compare_test",
-    srcs: [
-        "result_compare_test.py",
-    ],
-    test_config_template: "bazel_mode_test.xml",
-    test_suites: [
-        "general-tests",
-    ],
-    test_options: {
-        unit_test: false,
-    },
-}
-
 python_library_host {
     name: "asuite_integration_test_lib",
     srcs: [
diff --git a/atest/integration_tests/atest_command_success_tests.py b/atest/integration_tests/atest_command_success_tests.py
index 99e6031f..e1c7af74 100644
--- a/atest/integration_tests/atest_command_success_tests.py
+++ b/atest/integration_tests/atest_command_success_tests.py
@@ -32,13 +32,13 @@ class CommandSuccessTests(atest_integration_test.AtestTestCase):
   def test_csuite_harness_tests(self):
     """Test if csuite-harness-tests command runs successfully."""
     self._verify_atest_command_success(
-        'csuite-harness-tests --no-bazel-mode --host', is_device_required=False
+        'csuite-harness-tests --host', is_device_required=False
     )
 
   def test_csuite_cli_test(self):
     """Test if csuite_cli_test command runs successfully."""
     self._verify_atest_command_success(
-        'csuite_cli_test --no-bazel-mode --host', is_device_required=False
+        'csuite_cli_test --host', is_device_required=False
     )
 
   def _verify_atest_command_success(
diff --git a/atest/integration_tests/atest_command_verification_tests.py b/atest/integration_tests/atest_command_verification_tests.py
index 334609d8..bb974df4 100644
--- a/atest/integration_tests/atest_command_verification_tests.py
+++ b/atest/integration_tests/atest_command_verification_tests.py
@@ -170,7 +170,7 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         'atest_tradefed.sh template/atest_device_test_base --template:map'
         ' test=atest --template:map log_saver=template/log/atest_log_saver'
         ' --no-enable-granular-attempts --include-filter HelloWorldTests'
-        ' --include-filter hallo-welt --skip-loading-config-jar'
+        ' --include-filter hello-world --skip-loading-config-jar'
         ' --log-level-display VERBOSE --log-level VERBOSE'
         ' --no-early-device-release'
     )
@@ -215,7 +215,7 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         ' test=atest --template:map log_saver=template/log/atest_log_saver'
         ' --no-enable-granular-attempts --include-filter'
         ' VtsHalCameraProviderV2_4TargetTest --atest-include-filter'
-        ' VtsHalCameraProviderV2_4TargetTest:PerInstance/CameraHidlTest.configureInjectionStreamsAvailableOutputs/0_internal_0'
+        ' VtsHalCameraProviderV2_4TargetTest:PerInstance/CameraHidlTest#configureInjectionStreamsAvailableOutputs/0_internal_0'
         ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
         ' VERBOSE --no-early-device-release'
     )
diff --git a/atest/integration_tests/atest_test_archetype_integration_tests.py b/atest/integration_tests/atest_test_archetype_integration_tests.py
index 7476f175..bdd2722b 100644
--- a/atest/integration_tests/atest_test_archetype_integration_tests.py
+++ b/atest/integration_tests/atest_test_archetype_integration_tests.py
@@ -28,7 +28,7 @@ class DevicelessJavaTestHostTest(atest_integration_test.AtestTestCase):
   def test_passed_failed_counts(self):
     _run_and_verify(
         self,
-        atest_command=self._TARGET_NAME + ' --no-bazel-mode --host',
+        atest_command=self._TARGET_NAME + ' --host',
         is_device_required=False,
         verifiers=_create_pass_fail_ignore_verifiers(
             expected_passed_count=2,
@@ -45,7 +45,7 @@ class DevicelessPythonTestHostTest(atest_integration_test.AtestTestCase):
   def test_passed_failed_counts(self):
     _run_and_verify(
         self,
-        atest_command=self._TARGET_NAME + ' --no-bazel-mode --host',
+        atest_command=self._TARGET_NAME + ' --host',
         is_device_required=False,
         verifiers=_create_pass_fail_ignore_verifiers(
             expected_passed_count=2,
diff --git a/atest/integration_tests/bazel_mode_test.py b/atest/integration_tests/bazel_mode_test.py
deleted file mode 100755
index 34d62add..00000000
--- a/atest/integration_tests/bazel_mode_test.py
+++ /dev/null
@@ -1,481 +0,0 @@
-#!/usr/bin/env python3
-#
-# Copyright 2022, The Android Open Source Project
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
-"""Integration tests for the Atest Bazel mode feature."""
-
-# pylint: disable=invalid-name
-# pylint: disable=missing-class-docstring
-# pylint: disable=missing-function-docstring
-
-import dataclasses
-import os
-from pathlib import Path
-import shutil
-import subprocess
-import tempfile
-from typing import Any, Dict, List, Tuple
-import unittest
-
-
-_ENV_BUILD_TOP = 'ANDROID_BUILD_TOP'
-_PASSING_CLASS_NAME = 'PassingHostTest'
-_FAILING_CLASS_NAME = 'FailingHostTest'
-_PASSING_METHOD_NAME = 'testPass'
-_FAILING_METHOD_NAME = 'testFAIL'
-
-
-@dataclasses.dataclass(frozen=True)
-class JavaSourceFile:
-  class_name: str
-  src_body: str
-
-
-class BazelModeTest(unittest.TestCase):
-
-  def setUp(self):
-    self.src_root_path = Path(os.environ['ANDROID_BUILD_TOP'])
-    self.test_dir = self.src_root_path.joinpath('atest_bazel_mode_test')
-    if self.test_dir.exists():
-      shutil.rmtree(self.test_dir)
-    self.out_dir_path = Path(tempfile.mkdtemp())
-    self.test_env = self.setup_test_env()
-
-  def tearDown(self):
-    shutil.rmtree(self.test_dir)
-    shutil.rmtree(self.out_dir_path)
-
-  def test_passing_test_returns_zero_exit_code(self):
-    module_name = 'passing_java_host_test'
-    self.add_passing_test(module_name)
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --bazel-mode {module_name}'
-    )
-
-    self.assertEqual(completed_process.returncode, 0)
-
-  def test_failing_test_returns_nonzero_exit_code(self):
-    module_name = 'failing_java_host_test'
-    self.add_failing_test(module_name)
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --bazel-mode {module_name}'
-    )
-
-    self.assertNotEqual(completed_process.returncode, 0)
-
-  def test_passing_test_is_cached_when_rerun(self):
-    module_name = 'passing_java_host_test'
-    self.add_passing_test(module_name)
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --bazel-mode {module_name} && '
-        f'atest --bazel-mode {module_name}'
-    )
-
-    self.assert_in_stdout(
-        f':{module_name}_host (cached) PASSED', completed_process
-    )
-
-  def test_cached_test_reruns_when_modified(self):
-    module_name = 'passing_java_host_test'
-    java_test_file, _ = self.write_java_test_module(
-        module_name, passing_java_test_source()
-    )
-    self.run_shell_command(f'atest -c -m --bazel-mode {module_name}')
-
-    java_test_file.write_text(
-        failing_java_test_source(test_class_name=_PASSING_CLASS_NAME).src_body
-    )
-    completed_process = self.run_shell_command(
-        f'atest --bazel-mode {module_name}'
-    )
-
-    self.assert_in_stdout(f':{module_name}_host FAILED', completed_process)
-
-  def test_only_supported_test_run_with_bazel(self):
-    module_name = 'passing_java_host_test'
-    unsupported_module_name = 'unsupported_passing_java_test'
-    self.add_passing_test(module_name)
-    self.add_unsupported_passing_test(unsupported_module_name)
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --host --bazel-mode {module_name} '
-        f'{unsupported_module_name}'
-    )
-
-    self.assert_in_stdout(f':{module_name}_host PASSED', completed_process)
-    self.assert_in_stdout(
-        f'{_PASSING_CLASS_NAME}#{_PASSING_METHOD_NAME}: PASSED',
-        completed_process,
-    )
-
-  def test_defaults_to_device_variant(self):
-    module_name = 'passing_cc_host_test'
-    self.write_cc_test_module(module_name, passing_cc_test_source())
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --bazel-mode {module_name}'
-    )
-
-    self.assert_in_stdout('AtestTradefedTestRunner:', completed_process)
-
-  def test_runs_host_variant_when_requested(self):
-    module_name = 'passing_cc_host_test'
-    self.write_cc_test_module(module_name, passing_cc_test_source())
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --host --bazel-mode {module_name}'
-    )
-
-    self.assert_in_stdout(f':{module_name}_host   PASSED', completed_process)
-
-  def test_ignores_host_arg_for_device_only_test(self):
-    module_name = 'passing_cc_device_test'
-    self.write_cc_test_module(
-        module_name, passing_cc_test_source(), host_supported=False
-    )
-
-    completed_process = self.run_shell_command(
-        f'atest -c -m --host --bazel-mode {module_name}'
-    )
-
-    self.assert_in_stdout(
-        'Specified --host, but the following tests are device-only',
-        completed_process,
-    )
-
-  def test_supports_extra_tradefed_reporters(self):
-    test_module_name = 'passing_java_host_test'
-    self.add_passing_test(test_module_name)
-
-    reporter_module_name = 'test-result-reporter'
-    reporter_class_name = 'TestResultReporter'
-    expected_output_string = '0xFEEDF00D'
-
-    self.write_java_reporter_module(
-        reporter_module_name,
-        java_reporter_source(reporter_class_name, expected_output_string),
-    )
-
-    self.run_shell_command(f'm {reporter_module_name}', check=True)
-    self.run_shell_command(
-        f'atest -c -m --bazel-mode {test_module_name} --dry-run', check=True
-    )
-    self.run_shell_command(
-        f'cp ${{ANDROID_HOST_OUT}}/framework/{reporter_module_name}.jar '
-        f'{self.out_dir_path}/atest_bazel_workspace/tools/asuite/atest/'
-        'bazel/reporter/bazel-result-reporter/host/framework/.',
-        check=True,
-    )
-
-    completed_process = self.run_shell_command(
-        f'atest --bazel-mode {test_module_name} --bazel-arg='
-        '--//bazel/rules:extra_tradefed_result_reporters=android.'
-        f'{reporter_class_name} --bazel-arg=--test_output=all',
-        check=True,
-    )
-
-    self.assert_in_stdout(expected_output_string, completed_process)
-
-  def setup_test_env(self) -> Dict[str, Any]:
-    test_env = {
-        'PATH': os.environ['PATH'],
-        'HOME': os.environ['HOME'],
-        'OUT_DIR': str(self.out_dir_path),
-    }
-    return test_env
-
-  def run_shell_command(
-      self, shell_command: str, check: bool = False
-  ) -> subprocess.CompletedProcess:
-    return subprocess.run(
-        '. build/envsetup.sh && '
-        'lunch aosp_cf_x86_64_pc-userdebug && '
-        f'{shell_command}',
-        env=self.test_env,
-        cwd=self.src_root_path,
-        shell=True,
-        check=check,
-        stderr=subprocess.STDOUT,
-        stdout=subprocess.PIPE,
-    )
-
-  def add_passing_test(self, module_name: str):
-    self.write_java_test_module(module_name, passing_java_test_source())
-
-  def add_failing_test(self, module_name: str):
-    self.write_java_test_module(module_name, failing_java_test_source())
-
-  def add_unsupported_passing_test(self, module_name: str):
-    self.write_java_test_module(
-        module_name, passing_java_test_source(), unit_test=False
-    )
-
-  def write_java_test_module(
-      self,
-      module_name: str,
-      test_src: JavaSourceFile,
-      unit_test: bool = True,
-  ) -> Tuple[Path, Path]:
-    test_dir = self.test_dir.joinpath(module_name)
-    test_dir.mkdir(parents=True, exist_ok=True)
-
-    src_file_name = f'{test_src.class_name}.java'
-    src_file_path = test_dir.joinpath(f'{src_file_name}')
-    src_file_path.write_text(test_src.src_body, encoding='utf8')
-
-    bp_file_path = test_dir.joinpath('Android.bp')
-    bp_file_path.write_text(
-        android_bp(
-            java_test_host(
-                name=module_name,
-                srcs=[
-                    str(src_file_name),
-                ],
-                unit_test=unit_test,
-            ),
-        ),
-        encoding='utf8',
-    )
-    return (src_file_path, bp_file_path)
-
-  def write_cc_test_module(
-      self,
-      module_name: str,
-      test_src: str,
-      host_supported: bool = True,
-  ) -> Tuple[Path, Path]:
-    test_dir = self.test_dir.joinpath(module_name)
-    test_dir.mkdir(parents=True, exist_ok=True)
-
-    src_file_name = f'{module_name}.cpp'
-    src_file_path = test_dir.joinpath(f'{src_file_name}')
-    src_file_path.write_text(test_src, encoding='utf8')
-
-    bp_file_path = test_dir.joinpath('Android.bp')
-    bp_file_path.write_text(
-        android_bp(
-            cc_test(
-                name=module_name,
-                srcs=[
-                    str(src_file_name),
-                ],
-                host_supported=host_supported,
-            ),
-        ),
-        encoding='utf8',
-    )
-    return (src_file_path, bp_file_path)
-
-  def write_java_reporter_module(
-      self,
-      module_name: str,
-      reporter_src: JavaSourceFile,
-  ) -> Tuple[Path, Path]:
-    test_dir = self.test_dir.joinpath(module_name)
-    test_dir.mkdir(parents=True, exist_ok=True)
-
-    src_file_name = f'{reporter_src.class_name}.java'
-    src_file_path = test_dir.joinpath(f'{src_file_name}')
-    src_file_path.write_text(reporter_src.src_body, encoding='utf8')
-
-    bp_file_path = test_dir.joinpath('Android.bp')
-    bp_file_path.write_text(
-        android_bp(
-            java_library(
-                name=module_name,
-                srcs=[
-                    str(src_file_name),
-                ],
-            ),
-        ),
-        encoding='utf8',
-    )
-    return (src_file_path, bp_file_path)
-
-  def assert_in_stdout(
-      self,
-      message: str,
-      completed_process: subprocess.CompletedProcess,
-  ):
-    self.assertIn(message, completed_process.stdout.decode())
-
-
-def passing_java_test_source() -> JavaSourceFile:
-  return java_test_source(
-      test_class_name=_PASSING_CLASS_NAME,
-      test_method_name=_PASSING_METHOD_NAME,
-      test_method_body='Assert.assertEquals("Pass", "Pass");',
-  )
-
-
-def failing_java_test_source(
-    test_class_name=_FAILING_CLASS_NAME,
-) -> JavaSourceFile:
-  return java_test_source(
-      test_class_name=test_class_name,
-      test_method_name=_FAILING_METHOD_NAME,
-      test_method_body='Assert.assertEquals("Pass", "Fail");',
-  )
-
-
-def java_test_source(
-    test_class_name: str,
-    test_method_name: str,
-    test_method_body: str,
-) -> JavaSourceFile:
-  return JavaSourceFile(
-      test_class_name,
-      f"""\
-package android;
-
-import org.junit.Assert;
-import org.junit.Test;
-import org.junit.runners.JUnit4;
-import org.junit.runner.RunWith;
-
-@RunWith(JUnit4.class)
-public final class {test_class_name} {{
-
-    @Test
-    public void {test_method_name}() {{
-        {test_method_body}
-    }}
-}}
-""",
-  )
-
-
-def java_reporter_source(
-    reporter_class_name: str,
-    output_string: str,
-) -> JavaSourceFile:
-  return JavaSourceFile(
-      reporter_class_name,
-      f"""\
-package android;
-
-import com.android.tradefed.result.ITestInvocationListener;
-
-public final class {reporter_class_name} implements ITestInvocationListener {{
-
-    @Override
-    public void invocationEnded(long elapsedTime) {{
-        System.out.println("{output_string}");
-    }}
-}}
-""",
-  )
-
-
-def passing_cc_test_source() -> str:
-  return cc_test_source(
-      test_suite_name='TestSuite', test_name='PassingTest', test_body=''
-  )
-
-
-def cc_test_source(
-    test_suite_name: str,
-    test_name: str,
-    test_body: str,
-) -> str:
-  return f"""\
-#include <gtest/gtest.h>
-
-TEST({test_suite_name}, {test_name}) {{
-    {test_body}
-}}
-"""
-
-
-def android_bp(
-    modules: str = '',
-) -> str:
-  return f"""\
-package {{
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}}
-
-{modules}
-"""
-
-
-def cc_test(
-    name: str,
-    srcs: List[str],
-    host_supported: bool,
-) -> str:
-  src_files = ',\n'.join([f'"{f}"' for f in srcs])
-
-  return f"""\
-cc_test {{
-    name: "{name}",
-    srcs: [
-        {src_files},
-    ],
-    test_options: {{
-        unit_test: true,
-    }},
-    host_supported: {str(host_supported).lower()},
-}}
-"""
-
-
-def java_test_host(
-    name: str,
-    srcs: List[str],
-    unit_test: bool,
-) -> str:
-  src_files = ',\n'.join([f'"{f}"' for f in srcs])
-
-  return f"""\
-java_test_host {{
-    name: "{name}",
-    srcs: [
-        {src_files},
-    ],
-    test_options: {{
-        unit_test: {str(unit_test).lower()},
-    }},
-    static_libs: [
-        "junit",
-    ],
-}}
-"""
-
-
-def java_library(
-    name: str,
-    srcs: List[str],
-) -> str:
-  src_files = ',\n'.join([f'"{f}"' for f in srcs])
-
-  return f"""\
-java_library_host {{
-    name: "{name}",
-    srcs: [
-        {src_files},
-    ],
-    libs: [
-        "tradefed",
-    ],
-}}
-"""
-
-
-if __name__ == '__main__':
-  unittest.main(verbosity=2)
diff --git a/atest/integration_tests/bazel_mode_test.xml b/atest/integration_tests/bazel_mode_test.xml
deleted file mode 100644
index ea8ef0b4..00000000
--- a/atest/integration_tests/bazel_mode_test.xml
+++ /dev/null
@@ -1,21 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<configuration>
-    <test class="com.android.tradefed.testtype.python.PythonBinaryHostTest" >
-      <option name="par-file-name" value="{MODULE}"/>
-        <option name="test-timeout" value="420m" />
-    </test>
-</configuration>
diff --git a/atest/integration_tests/build_atest_integration_tests.sh b/atest/integration_tests/build_atest_integration_tests.sh
index e1a572cf..b61c094a 100755
--- a/atest/integration_tests/build_atest_integration_tests.sh
+++ b/atest/integration_tests/build_atest_integration_tests.sh
@@ -90,9 +90,8 @@ fi
 export REMOTE_AVD=true
 
 # Use the versioned Python binaries in prebuilts/ for a reproducible
-# build with minimal reliance on host tools. Add build/bazel/bin to PATH since
-# atest needs 'b'
-export PATH=${PWD}/prebuilts/build-tools/path/linux-x86:${PWD}/build/bazel/bin:${PWD}/out/host/linux-x86/bin/:${PATH}
+# build with minimal reliance on host tools.
+export PATH=${PWD}/prebuilts/build-tools/path/linux-x86:${PWD}/out/host/linux-x86/bin/:${PATH}
 
 # Use the versioned Java binaries in prebuilds/ for a reproducible
 # build with minimal reliance on host tools.
diff --git a/atest/integration_tests/result_compare_test.py b/atest/integration_tests/result_compare_test.py
deleted file mode 100755
index a71bce23..00000000
--- a/atest/integration_tests/result_compare_test.py
+++ /dev/null
@@ -1,184 +0,0 @@
-#!/usr/bin/env python3
-#
-# Copyright 2022, The Android Open Source Project
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
-"""Integration tests for the Atest Bazel mode feature."""
-
-# pylint: disable=invalid-name
-# pylint: disable=missing-class-docstring
-# pylint: disable=missing-function-docstring
-
-import json
-import os
-from pathlib import Path
-import re
-import shutil
-import subprocess
-import tempfile
-from typing import Any, Dict
-import unittest
-
-
-class ResultCompareTest(unittest.TestCase):
-
-  def setUp(self):
-    self.src_root_path = Path(os.environ['ANDROID_BUILD_TOP'])
-    self.out_dir_path = Path(tempfile.mkdtemp())
-    self.test_env = self.setup_test_env()
-
-  def tearDown(self):
-    shutil.rmtree(self.out_dir_path)
-
-  def test_standard_mode_and_bazel_mode_result_equal(self):
-    standard_mode_result = self.get_test_result(
-        shell_cmd='atest -c -m --host --host-unit-test-only'
-    )
-
-    bazel_mode_result = self.get_test_result(
-        shell_cmd=(
-            'atest -c --bazel-mode --host --host-unit-test-only '
-            '--bazel-arg=--test_timeout=300'
-        ),
-        is_bazel_mode=True,
-    )
-
-    self.assert_test_result_equal(standard_mode_result, bazel_mode_result)
-
-  def setup_test_env(self) -> Dict[str, Any]:
-    test_env = {
-        'PATH': os.environ['PATH'],
-        'HOME': os.environ['HOME'],
-        'OUT_DIR': str(self.out_dir_path),
-    }
-    return test_env
-
-  def get_test_result(
-      self,
-      shell_cmd: str,
-      is_bazel_mode: bool = False,
-  ) -> Dict[str, str]:
-    result_file_name = 'test_result'
-    if is_bazel_mode:
-      shell_cmd = (
-          f'{shell_cmd} --bazel-arg=--build_event_json_file={result_file_name}'
-      )
-
-    completed_process = self.run_shell_command(shell_cmd)
-    result_file_path = self.get_result_file_path(
-        completed_process, result_file_name, is_bazel_mode
-    )
-
-    if is_bazel_mode:
-      return parse_bazel_result(result_file_path)
-    return parse_standard_result(result_file_path)
-
-  def get_result_file_path(
-      self,
-      completed_process: subprocess.CompletedProcess,
-      result_file_name: str,
-      is_bazel_mode: bool = False,
-  ) -> Path:
-    if is_bazel_mode:
-      return self.out_dir_path.joinpath(
-          'atest_bazel_workspace', result_file_name
-      )
-
-    result_file_path = None
-    log_dir_prefix = 'Atest results and logs directory: '
-    for line in completed_process.stdout.decode().splitlines():
-      if line.startswith(log_dir_prefix):
-        result_file_path = Path(line[len(log_dir_prefix) :]) / result_file_name
-        break
-
-    if not result_file_path:
-      raise Exception('Could not find test result filepath')
-
-    return result_file_path
-
-  def run_shell_command(
-      self,
-      shell_command: str,
-  ) -> subprocess.CompletedProcess:
-    return subprocess.run(
-        '. build/envsetup.sh && '
-        'lunch aosp_cf_x86_64_pc-userdebug && '
-        f'{shell_command}',
-        env=self.test_env,
-        cwd=self.src_root_path,
-        shell=True,
-        check=False,
-        stderr=subprocess.STDOUT,
-        stdout=subprocess.PIPE,
-    )
-
-  def assert_test_result_equal(self, result1, result2):
-    self.assertEqual(set(result1.keys()), set(result2.keys()))
-
-    print(
-        '{0:100}  {1:20}  {2}'.format(
-            'Test', 'Atest Standard Mode', 'Atest Bazel Mode'
-        )
-    )
-    count = 0
-    for k, v in result1.items():
-      if v != result2[k]:
-        count += 1
-        print('{0:100}  {1:20}  {2}'.format(k, v, result2[k]))
-    print(
-        f'Total Number of Host Unit Test: {len(result1)}. {count} tests '
-        'have different results.'
-    )
-
-    self.assertEqual(count, 0)
-
-
-def parse_standard_result(result_file: Path) -> Dict[str, str]:
-  result = {}
-  with result_file.open('r') as f:
-    json_result = json.loads(f.read())
-    for k, v in json_result['test_runner']['AtestTradefedTestRunner'].items():
-      name = k.split()[-1]
-      if name in result:
-        raise Exception(f'Duplicated Test Target: `{name}`')
-
-      # Test passed when there are no failed test cases and no errors.
-      result[name] = (
-          'PASSED'
-          if v['summary']['FAILED'] == 0 and not v.get('ERROR')
-          else 'FAILED'
-      )
-  return result
-
-
-def parse_bazel_result(result_file: Path) -> Dict[str, str]:
-  result = {}
-  with result_file.open('r') as f:
-    content = f.read()
-    events = content.splitlines()
-
-    for e in events:
-      json_event = json.loads(e)
-      if 'testSummary' in json_event['id']:
-        name = (
-            json_event['id']['testSummary']['label']
-            .split(':')[-1]
-            .removesuffix('_host')
-        )
-        result[name] = json_event['testSummary']['overallStatus']
-  return result
-
-
-if __name__ == '__main__':
-  unittest.main(verbosity=2)
diff --git a/atest/logstorage/log_uploader.py b/atest/logstorage/log_uploader.py
index c88f6fa2..1793cb8d 100644
--- a/atest/logstorage/log_uploader.py
+++ b/atest/logstorage/log_uploader.py
@@ -222,9 +222,14 @@ def is_uploading_logs(gcert_checker: Callable[[], bool] = None) -> bool:
       'false',
       '0',
   ]:
+    logging.info(
+        'Log uploading is disabled by the environment variable %s.',
+        _ENABLE_ATEST_LOG_UPLOADING_ENV_KEY,
+    )
     return False
 
   if not logstorage_utils.is_credential_available():
+    logging.info('Log uploading is disabled because gcert is not available.')
     return False
 
   # Checks whether gcert is available and not about to expire.
@@ -243,7 +248,10 @@ def is_uploading_logs(gcert_checker: Callable[[], bool] = None) -> bool:
         ).returncode
         == 0
     )
-  return gcert_checker()
+  gcert_available = gcert_checker()
+  if not gcert_available:
+    logging.info('Log uploading is disabled because gcert is not available.')
+  return gcert_available
 
 
 def upload_logs_detached(logs_dir: pathlib.Path):
diff --git a/atest/module_info.py b/atest/module_info.py
index bee0bd61..e1e2adcf 100644
--- a/atest/module_info.py
+++ b/atest/module_info.py
@@ -772,7 +772,7 @@ class ModuleInfo:
         break
       for name in os.listdir(pth):
         if pth.joinpath(name).is_file():
-          match = re.match('.*AndroidManifest.*\.xml$', name)
+          match = re.match(r'.*AndroidManifest.*\.xml$', name)
           if match:
             xmls.append(os.path.join(pth, name))
     possible_modules = []
@@ -784,7 +784,7 @@ class ModuleInfo:
         if xml_info.get('persistent'):
           logging.debug('%s is a persistent app.', package)
           continue
-        for _m in self.path_to_module_info.get(rel_dir):
+        for _m in self.path_to_module_info.get(rel_dir, []):
           possible_modules.append(_m)
     if possible_modules:
       for mod in possible_modules:
@@ -1551,7 +1551,7 @@ def _filter_modules_by_suite(
 ) -> Set[str]:
   """Return modules of the given suite name."""
   if suite:
-    return suite_to_modules.get(suite)
+    return suite_to_modules.get(suite, set())
 
   return {mod for mod_set in suite_to_modules.values() for mod in mod_set}
 
diff --git a/atest/module_info_unittest.py b/atest/module_info_unittest.py
index 9f872446..e9de22d1 100755
--- a/atest/module_info_unittest.py
+++ b/atest/module_info_unittest.py
@@ -251,6 +251,23 @@ class ModuleInfoUnittests(unittest.TestCase):
     self.assertEqual(actual_test_suite_modules, expected_test_suite_modules)
     self.assertEqual(actual_null_suite_modules, expected_null_suite_modules)
 
+  def test_get_testable_modules_failed_to_find_suite(self):
+    """Test get_testable_modules."""
+    mod_info = create_module_info(
+        modules=[
+            test_module(name='Module1', compatibility_suites=['test-suite']),
+            test_module(name='Module2', compatibility_suites=['test-suite']),
+            test_module(name='Module3'),
+            non_test_module(name='Dep1'),
+        ]
+    )
+
+    actual_all_testable_modules = mod_info.get_testable_modules(
+        'suite-not-exist'
+    )
+
+    self.assertSetEqual(actual_all_testable_modules, set())
+
   @mock.patch.dict(
       'os.environ',
       {
@@ -413,6 +430,25 @@ class ModuleInfoUnittests(unittest.TestCase):
         ),
     )
 
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_BUILD_TOP: uc.TEST_DATA_DIR,
+          constants.ANDROID_PRODUCT_OUT: PRODUCT_OUT_DIR,
+      },
+  )
+  def test_get_target_module_by_pkg_module_not_found(self):
+    mod_info = module_info.load_from_file(module_file=JSON_FILE_PATH)
+    self.assertEqual(
+        '',
+        mod_info.get_target_module_by_pkg(
+            package='module_1',
+            search_from=Path(uc.TEST_DATA_DIR).joinpath(
+                'foo/bar/module_1/test'
+            ),
+        ),
+    )
+
   @mock.patch.dict(
       'os.environ',
       {
@@ -780,33 +816,41 @@ class ModuleInfoUnittests(unittest.TestCase):
     )
 
   def test_get_code_under_test_module_name_is_not_found_in_module_info(self):
-    mod_info = create_module_info([
-        module(
-            name='my_module',
-            code_under_test='code_under_test_module',
-        )
-    ])
+    mod_info = create_module_info(
+        [
+            module(
+                name='my_module',
+                code_under_test='code_under_test_module',
+            )
+        ]
+    )
 
     # module_that_is_not_in_module_info is not found in mod_info.
     self.assertEqual(
-        mod_info.get_code_under_test('module_that_is_not_in_module_info'), [],
+        mod_info.get_code_under_test('module_that_is_not_in_module_info'),
+        [],
     )
 
-  def test_get_code_under_test_code_under_test_is_not_defined_in_module_info(self):
+  def test_get_code_under_test_code_under_test_is_not_defined_in_module_info(
+      self,
+  ):
     mod_info = create_module_info([module(name='my_module')])
 
     # my_module is found in mod_info but code_under_test is not defined.
     self.assertEqual(
-        mod_info.get_code_under_test('my_module'), [],
+        mod_info.get_code_under_test('my_module'),
+        [],
     )
 
   def test_get_code_under_test_code_under_test_is_defined_in_module_info(self):
-    mod_info = create_module_info([
-        module(
-            name='my_module',
-            code_under_test='code_under_test_module',
-        )
-    ])
+    mod_info = create_module_info(
+        [
+            module(
+                name='my_module',
+                code_under_test='code_under_test_module',
+            )
+        ]
+    )
 
     self.assertEqual(
         mod_info.get_code_under_test('my_module'),
diff --git a/atest/proto/decision_graph.proto b/atest/proto/decision_graph.proto
new file mode 100644
index 00000000..4b369a9d
--- /dev/null
+++ b/atest/proto/decision_graph.proto
@@ -0,0 +1,551 @@
+syntax = "proto3";
+
+import "atest/proto/common.proto";
+// DecisionGraphInput is the input to the RunDecisionGraph RPC.
+message DecisionGraphInput {
+  // A client-defined DecisionGraph or pre-defined graph.
+  optional DecisionGraph graph = 1;
+
+  // Optional request-specific context for each stage.
+  // For example, the .context or .change_set fields may be set. If one of these
+  // the StageInput.id field is not set, the non-null fields from that
+  // StageInput is passed to all stages.
+  repeated StageInput input = 2;
+}
+
+// DecisionGraphOutput is the result of running a DecisionGraph.
+// It contains the DecisionGraph which was run, the outputs of the stages,
+// and any other metadata which is useful for observability or debugging.
+message DecisionGraphOutput {
+  optional string id = 1;  // For re-querying stored selections later. Required.
+
+  // The DecisionGraph which ran the run is stored. Required.
+  optional DecisionGraph graph = 2;
+
+  // Children; for querying nested graphs. Optional.
+  repeated DecisionGraphOutput children = 3;
+
+  // Output of the stages. Optional.
+  repeated StageOutput outputs = 5;
+}
+
+// A DecisionGraph is a DAG of StageNodes.
+// A given system such as presubmit or postsubmit may require multiple
+// DecisionGraphs, possibly for different contexts, customer configurations, or
+// parts of the CI workflow.
+//
+// Each major client of the DecisionGraph API would have its own isolation shard
+// to ensure that no badly behaved client can blow up all of Engprod's services.
+message DecisionGraph {
+  optional string name = 1;
+  repeated StageNode stages = 2;
+}
+
+message StageNode {
+  // The identifier and name of the stage. If running more than one stage
+  // of a given type, the identifier does not need to match the name of
+  // the stage.
+  optional Stage stage = 1;
+
+  // Graph structure is expressed here. List of ids of the parent stages.
+  repeated string input_stages = 2;
+
+  // How to call the Stage.
+  optional ExecutionOptions execution_options = 4;
+
+  // Execution options define how to call a Stage.
+  message ExecutionOptions {
+    // How to call the stage.
+    // Test selection can be extended to support additional calling methods
+    // (grpc, in-process classes) by adding additional config fields here.
+    enum Location {
+      LOCATION_UNKNOWN = 0;
+      GSLB = 1;
+      LOCAL = 2;
+    }
+
+    // Implemented in the canonical DecisionGraph stage service.
+    optional Location location = 5;
+
+    // GSLB or other address for the Stage RPC service.
+    optional string address = 6;
+
+    // Whether to call Prepare() on the stage instead of Run().
+    // Useful for slow stages with some precomputation needed before they are
+    // ready, like test relevance.
+    optional bool prepare = 7;
+
+    // Deadline in seconds. Some stages may need more time than others.
+    optional Duration max_duration = 8;
+    optional int32 max_attempts = 9;  // Maximum retries for RPC errors.
+
+    // Whether the plan can continue without this stage. If a blocking stage
+    // fails, execution of downstream stages will not occur. If a nonblocking
+    // satge fails, downstream stages will still execute.
+    // For example, smart test selection is not strictly necessary, and
+    // execution can continue without it.
+    enum Blocking {
+      BLOCKING_UNKNOWN = 0;
+      BLOCKING = 1;
+      NON_BLOCKING = 2;
+    }
+
+    optional Blocking blocking = 10;
+
+    // Experiment options
+    optional Experiment experiment = 11;
+
+    // A/B Experiment options. The stage will be enabled if the md5 hash
+    // of the key mod 100 is less than or equal to the .percentage.
+    message Experiment {
+      optional int32 percentage = 1;
+
+      // The key of StageInput to split on (ex.
+      // changes.leader_changes.0.change_number)
+      repeated string key = 2;
+    }
+  }
+}
+
+// StageInput is passed into the stage:
+//  - The StageOutput of all previous stages
+//  - The config from the DecisionGraph's StageNode.
+//  - The context from the DecisionGraph.RunGraph request
+message StageInput {
+  // The ID and Name of this stage (in the DecisionGraph StageNode).
+  optional Stage stage = 1;
+
+  // The output of the stages which are inputs to this stage.
+  // If this stage depends on the root stage, this will contain a root
+  // StageOutput with the DecisionGraphService.RunDecisionGraph input context.
+  repeated StageOutput input = 3;
+}
+
+message StageOutput {
+  repeated Check checks = 1;
+  optional Stage stage = 2;
+
+  // 'context' contains any DecisionGraph or stage-specific input which is
+  // required to make a decision. For example, Postsubmit selection graphs may
+  // need to process a sequence of changes at various builds. Other graphs or
+  // stages may have other unique contexts.
+  optional Stage.Context context = 3;
+
+  // Private output context, which is not stored in spanner.
+  optional Stage.PrivateContext private_context = 4;
+
+  // Whether this Stage found a critical result which gives a final result
+  // and invalidates the rest of the decision graph. If .terminate is set, then
+  // the DecisionGraph service will stop execution of the garph.
+  optional bool terminate = 5;
+  repeated Error errors = 6;  // Any errors encountered when calling this stage.
+}
+
+message Error {
+  enum Code {
+    // Not an error; returned on success.
+    OK = 0;
+
+    // The operation was cancelled, typically by the caller.
+    CANCELLED = 1;
+
+    // Unknown error.  For example, this error may be returned when
+    // a Status value received from another address space belongs to
+    // an error-space that is not known in this address space.  Also
+    // errors raised by APIs that do not return enough error information
+    // may be converted to this error.
+    UNKNOWN = 2;
+
+    // The client specified an invalid argument.  Note that this differs
+    // from FAILED_PRECONDITION.  INVALID_ARGUMENT indicates arguments
+    // that are problematic regardless of the state of the system
+    // (e.g., a malformed file name).
+    INVALID_ARGUMENT = 3;
+
+    // The deadline expired before the operation could complete. For operations
+    // that change the state of the system, this error may be returned
+    // even if the operation has completed successfully.  For example, a
+    // successful response from a server could have been delayed long
+    // enough for the deadline to expire.
+    DEADLINE_EXCEEDED = 4;
+
+    // Some requested entity (e.g., file or directory) was not found.
+    //
+    // Note to server developers: if a request is denied for an entire class
+    // of users, such as gradual feature rollout or undocumented allowlist,
+    // `NOT_FOUND` may be used. If a request is denied for some users within
+    // a class of users, such as user-based access control, `PERMISSION_DENIED`
+    // must be used.
+    NOT_FOUND = 5;
+
+    // The entity that a client attempted to create (e.g., file or directory)
+    // already exists.
+    ALREADY_EXISTS = 6;
+
+    // The caller does not have permission to execute the specified
+    // operation. `PERMISSION_DENIED` must not be used for rejections
+    // caused by exhausting some resource (use `RESOURCE_EXHAUSTED`
+    // instead for those errors). `PERMISSION_DENIED` must not be
+    // used if the caller can not be identified (use `UNAUTHENTICATED`
+    // instead for those errors). This error code does not imply the
+    // request is valid or the requested entity exists or satisfies
+    // other pre-conditions.
+    PERMISSION_DENIED = 7;
+
+    // The request does not have valid authentication credentials for the
+    // operation.
+    UNAUTHENTICATED = 16;
+
+    // Some resource has been exhausted, perhaps a per-user quota, or
+    // perhaps the entire file system is out of space.
+    RESOURCE_EXHAUSTED = 8;
+
+    // The operation was rejected because the system is not in a state
+    // required for the operation's execution.  For example, the directory
+    // to be deleted is non-empty, an rmdir operation is applied to
+    // a non-directory, etc.
+    //
+    // A litmus test that may help a service implementer in deciding
+    // between FAILED_PRECONDITION, ABORTED, and UNAVAILABLE:
+    //  (a) Use UNAVAILABLE if the client can retry just the failing call.
+    //  (b) Use ABORTED if the client should retry at a higher-level. For
+    //      example, when a client-specified test-and-set fails, indicating the
+    //      client should restart a read-modify-write sequence.
+    //  (c) Use FAILED_PRECONDITION if the client should not retry until
+    //      the system state has been explicitly fixed. For example, if an
+    //      "rmdir" fails because the directory is non-empty,
+    //      FAILED_PRECONDITION should be returned since the client should not
+    //      retry unless the files are deleted from the directory.
+    FAILED_PRECONDITION = 9;
+
+    // The operation was aborted, typically due to a concurrency issue such as
+    // a sequencer check failure or transaction abort.
+    //
+    // See litmus test above for deciding between FAILED_PRECONDITION,
+    // ABORTED, and UNAVAILABLE.
+    ABORTED = 10;
+
+    // The operation was attempted past the valid range.  E.g., seeking or
+    // reading past end-of-file.
+    //
+    // Unlike INVALID_ARGUMENT, this error indicates a problem that may
+    // be fixed if the system state changes. For example, a 32-bit file
+    // system will generate INVALID_ARGUMENT if asked to read at an
+    // offset that is not in the range [0,2^32-1], but it will generate
+    // OUT_OF_RANGE if asked to read from an offset past the current
+    // file size.
+    //
+    // There is a fair bit of overlap between FAILED_PRECONDITION and
+    // OUT_OF_RANGE.  We recommend using OUT_OF_RANGE (the more specific
+    // error) when it applies so that callers who are iterating through
+    // a space can easily look for an OUT_OF_RANGE error to detect when
+    // they are done.
+    OUT_OF_RANGE = 11;
+
+    // The operation is not implemented or is not supported/enabled in this
+    // service.
+    UNIMPLEMENTED = 12;
+
+    // Internal errors.  This means that some invariants expected by the
+    // underlying system have been broken.  This error code is reserved
+    // for serious errors.
+    INTERNAL = 13;
+
+    // The service is currently unavailable.  This is most likely a
+    // transient condition, which can be corrected by retrying with
+    // a backoff. Note that it is not always safe to retry
+    // non-idempotent operations.
+    //
+    // See litmus test above for deciding between FAILED_PRECONDITION,
+    // ABORTED, and UNAVAILABLE.
+    UNAVAILABLE = 14;
+
+    // Unrecoverable data loss or corruption.
+    DATA_LOSS = 15;
+
+    // An extra enum entry to prevent people from writing code that
+    // fails to compile when a new code is added.
+    //
+    // Nobody should ever reference this enumeration entry. In particular,
+    // if you write C++ code that switches on this enumeration, add a default:
+    // case instead of a case that mentions this enumeration entry.
+    //
+    // Nobody should rely on the value (currently 20) listed here.  It
+    // may change in the future.
+    DO_NOT_USE_RESERVED_FOR_FUTURE_EXPANSION_USE_DEFAULT_IN_SWITCH_INSTEAD_ =
+        20;
+  }
+
+  oneof error {
+    Code rpc_error = 1;
+  }
+
+  // A string error message.
+  optional string message = 2;
+}
+
+// -------- RPC message types --------------------------------------------------
+message Stage {
+  optional string id = 1;  // Unique (opaque) ID for this stage.
+
+  // Names are mainly for observability purposes — these are stored
+  // along with the selections (ADD / REMOVE / MODIFY) to enable visibility
+  // into why decisions happened in the test plan.
+  optional string name = 2;
+  // Input stages adjacent to this node in the Stage graph.
+  repeated Stage input_stages = 3;
+
+  // A Stage.Reason is a structured explanation of why the stage made its
+  // decisions.
+  message Reason {}
+
+  optional Reason reason = 4;
+
+  // 'context' contains any DecisionGraph or stage-specific input which is
+  // required to make a decision. For example, Postsubmit selection graphs may
+  // need to process a sequence of changes at various builds. Other graphs or
+  // stages may have other unique contexts.
+  message Context {
+    // The messages to be displayed in the UI.
+    repeated string display_messages = 1;
+  }
+  // Context of the stage, as described above.
+  optional Context context = 5;
+
+  // PrivateContext contains context which is not stored in spanner due to
+  // containing sensitive data which should not be accessible to all googlers.
+  // For example, ChangeInfo for restricted hosts cannot be shared to all
+  // googlers, and should be populated in the PrivateContext instead of Context.
+  message PrivateContext {
+    // The changes which are part of the run.
+    repeated Change changes = 1;
+  }
+}
+
+// The files info that is modified/added/deleted/renamed in the change.
+// For merged changes, it should be the file diffs from the first parent.
+// This is only accessible in the change.list endpoint.
+message FileInfo {
+  // The path of the file.
+  optional string path = 1;
+  // Original path name if the file was renamed or copied.
+  optional string old_path = 2;
+  // Type of change made to the file.
+  enum Status {
+    UNSPECIFIED_STATUS = 0;
+    ADDED = 1;
+    DELETED = 2;
+    MODIFIED = 3;
+    RENAMED = 4;    // old_path is set
+    COPIED = 5;     // old_path is set
+    REWRITTEN = 6;  // similar to MODIFIED
+  }
+  // The status of the file.
+  optional Status status = 3;
+
+  // Number of inserted lines.
+  optional int32 lines_inserted = 4;
+
+  // Number of deleted lines.
+  optional int32 lines_deleted = 5;
+}
+
+// A Gerrit Revision
+message Revision {
+  optional string git_revision = 1;
+  optional int32 patch_set = 2;
+
+  optional User uploader = 7;
+
+  repeated FileInfo file_info = 8;
+}
+
+// A Gerrit Change
+message Change {
+  // Which gerrit instance this change came from
+  optional string host = 1;
+  // Which project
+  optional string project = 2;
+  // Which branch
+  optional string branch = 3;
+
+  repeated Revision revisions = 10;
+
+  optional User owner = 11;
+}
+
+message User {
+  optional string name = 1;
+  optional string email = 2;
+  optional string username = 3;
+  optional int64 account_id = 4;
+}
+
+enum AggregationLevel {
+  AGGREGATION_LEVEL_UNSPECIFIED = 0;
+
+  // All test results for an Invocation.
+  INVOCATION = 1;
+
+  // Test results for a module. This considers the module name and parameters in
+  // the `TestIdentifier` message.
+  MODULE = 2;
+
+  // Test results for a test package. This considers the module and all results
+  // sharing the same package from `test_class` field in the `TestIdentifier`
+  // message. This is the string before the last "." in that field.
+  PACKAGE = 3;
+
+  // Test results for a test class. This considers the module and all results
+  // sharing the same `test_class` in the `TestIdentifier` message.
+  CLASS = 4;
+
+  // Test results for a method. This is currently not being generated.
+  METHOD = 5;
+}
+
+// Describes an Android Build that is being tested.
+//
+// Next ID: 5
+message BuildDescriptor {
+  // The build provider. For example, `androidbuild`.
+  string build_provider = 1;
+
+  // The branch. For example, `git_master`.
+  string branch = 2;
+
+  // The build target. For example, `cf_x86_phone-userdebug`.
+  string build_target = 3;
+
+  // The build ID.
+  string build_id = 4;
+}
+
+message Property {
+  string name = 1;
+  string value = 2;
+}
+
+// A TestDefinition describes how to identify an Invocation.
+//
+// Next ID: 3
+message TestDefinition {
+  // The name used to identify the set of tests being executed.
+  string name = 1;
+
+  // A list of properties the scheduler uses to differentiate between
+  // configurations with the same name. For example 'cluster_id'
+  // and 'run_target' for ATP (http://go/consistent-test-identifiers).
+  repeated Property properties = 2;
+}
+
+// A TestIdentifier describes how to identify a TestResult within an Invocaiton.
+// This includes a hiearchy for where a TestResult is located. Modules are
+// identified by the module name and parameters. Different modules can have the
+// same name but the paramereters must be different.
+//
+// Next ID: 6
+message TestIdentifier {
+  // Name of the module this test belongs to.
+  string module = 1;
+
+  // Parameters for the test module.
+  repeated Property module_parameters = 2;
+
+  // The name for a group of tests that are logically grouped together.
+  // Typically in the format of <package name>.<class name>.
+  string test_class = 3;
+
+  // The name of the test that is the smallest test execution unit.
+  string method = 4;
+}
+
+message AnTSTest {
+  // required, to ensure the nesting levels of selection stages align
+  // together.
+  AggregationLevel aggregation_level = 1;
+  optional BuildDescriptor build_descriptor = 2;
+  optional TestDefinition test_definition = 3;
+  optional TestIdentifier test_identifier = 4;
+  optional string test_identifier_id = 5;
+}
+
+// A Check is a continuous integration entity (ex. build / test) which is
+// acted upon (ADD | REMOVE | MODIFY) by a graph of stages.
+message Check {
+  // A Check.Identifier says what the check is, for example, a build, test or
+  // preflight check.
+  //
+  // For high cardinality identifiers which change rarely, and efficiency is
+  // important, it is more efficient to inline the messages here compared to
+  // using proto Extensions, because those require reflection.
+  //
+  // For low cardinality identifiers such as a Preflight check, we use
+  // proto extensions to enable flexibility on the client side.
+  message Identifier {
+    optional string id = 1;
+    oneof identifier {
+      // An AnTS test identifier, fully spelled out.
+      AnTSTest ants_test = 2;
+    }
+  }
+
+  optional Identifier identifier = 1;
+
+  // Stages can operate on nested structures, like invocation -> module ->
+  // method. That enables composition of granular, method-level stages with
+  // coarse-grain stages.
+  repeated Check children = 2;  // to support hierarchical stages.
+
+  // to support a graph structure (tests -> build) or (build -> build)
+  repeated Check input_checks = 3;
+
+  // Structured selection reason for this test.
+  message Reason {
+    // The reason for the decision to include or exclude this check.
+    oneof reason {
+      // The test is selected or not because of its relevance score.
+      float relevance_score = 1;
+    }
+  }
+
+  optional Reason reason = 7;
+
+  // Additional contextual information, such as the last time the test ran in
+  // postsubmit or the ID of the latest trident build for the target, reference
+  // build IDs, or target dependency info.
+  message Context {
+    // Any stage-specific context.
+    optional Any value = 1;
+
+    // Used by relevance service to identify the worknode and invocation.
+    optional string worknode_id = 2;
+    // Used by relevance service to identify the invocation.
+    optional string invocation_id = 3;
+  }
+
+  repeated Context context = 8;
+
+  // Some checks may evaluate early, such as Preflight checks. These can
+  // populate their results here.
+  message Result {
+    // The status of the check.
+    // TBD definition of a Status proto enum; perhaps reuse AnTS status for
+    // http://go/not-pass-fail reasons?
+    // optional google.internal.android.treehugger.decisiongraph.check.Status
+    //     status = 1;
+
+    // A panic result will stop execution of downstream nodes. This is often
+    // used for Preflight checks.
+    optional bool panic = 2;
+  }
+
+  optional Result result = 9;
+}
+
+message Any {
+  string type_url = 1;
+
+  // Must be a valid serialized protocol buffer of the above specified type.
+  bytes value = 2;
+}
diff --git a/atest/result_reporter.py b/atest/result_reporter.py
index 4e175d3b..6b25e1af 100644
--- a/atest/result_reporter.py
+++ b/atest/result_reporter.py
@@ -60,6 +60,48 @@ HelloWorldTests: Passed: 2, Failed: 0
 WmTests: Passed: 0, Failed: 0 (Completed With ERRORS)
 
 1 test failed
+
+If `class_level_report` is specified, the summary is aggregated by test classes.
+The above example will be like:
+
+Running Tests ...
+
+CtsAnimationTestCases:android.animation.cts.EvaluatorTest.UnitTests
+-------------------------------------------------------------------
+
+android.animation.cts.EvaluatorTest.UnitTests (7 Tests)
+[1/7] android.animation.cts.EvaluatorTest#testRectEvaluator: PASSED (153ms)
+[2/7] android.animation.cts.EvaluatorTest#testIntArrayEvaluator: PASSED (0ms)
+[3/7] android.animation.cts.EvaluatorTest#testIntEvaluator: PASSED (0ms)
+[4/7] android.animation.cts.EvaluatorTest#testFloatArrayEvaluator: PASSED (1ms)
+[5/7] android.animation.cts.EvaluatorTest#testPointFEvaluator: PASSED (1ms)
+[6/7] android.animation.cts.EvaluatorTest#testArgbEvaluator: PASSED (0ms)
+[7/7] android.animation.cts.EvaluatorTest#testFloatEvaluator: PASSED (1ms)
+
+HelloWorldTests:android.test.example.helloworld.UnitTests
+---------------------------------------------------------
+
+android.test.example.helloworld.UnitTests(2 Tests)
+[1/2] android.test.example.helloworld.HelloWorldTest#testHalloWelt: PASSED (0ms)
+[2/2] android.test.example.helloworld.HelloWorldTest#testHelloWorld: PASSED
+(1ms)
+
+WmTests:com.android.tradefed.targetprep.UnitTests
+-------------------------------------------------
+
+com.android.tradefed.targetprep.UnitTests (1 Test)
+RUNNER ERROR: com.android.tradefed.targetprep.TargetSetupError:
+Failed to install WmTests.apk on 127.0.0.1:54373. Reason:
+    error message ...
+
+
+Summary
+-------
+CtsAnimationTestCases:android.animation.cts.EvaluatorTest.UnitTests: Passed: 7,
+Failed: 0
+HelloWorldTests:android.test.example.helloworld.UnitTests: Passed: 2, Failed: 0
+WmTests:com.android.tradefed.targetprep.UnitTests: Passed: 0, Failed: 0
+(Completed With ERRORS)
 """
 
 from __future__ import print_function
@@ -72,153 +114,20 @@ import re
 import zipfile
 
 from atest import atest_configs
+from atest import atest_enum
 from atest import atest_utils as au
 from atest import constants
 from atest.atest_enum import ExitCode
+from atest.crystalball import metric_printer
+from atest.metrics import metrics
 from atest.test_runners import test_runner_base
 
 UNSUPPORTED_FLAG = 'UNSUPPORTED_RUNNER'
 FAILURE_FLAG = 'RUNNER_FAILURE'
-BENCHMARK_ESSENTIAL_KEYS = {
-    'repetition_index',
-    'cpu_time',
-    'name',
-    'repetitions',
-    'run_type',
-    'threads',
-    'time_unit',
-    'iterations',
-    'run_name',
-    'real_time',
-}
-# TODO(b/146875480): handle the optional benchmark events
-BENCHMARK_OPTIONAL_KEYS = {'bytes_per_second', 'label'}
-BENCHMARK_EVENT_KEYS = BENCHMARK_ESSENTIAL_KEYS.union(BENCHMARK_OPTIONAL_KEYS)
-INT_KEYS = {}
 ITER_SUMMARY = {}
 ITER_COUNTS = {}
 
 
-class PerfInfo:
-  """Class for storing performance test of a test run."""
-
-  def __init__(self):
-    """Initialize a new instance of PerfInfo class."""
-    # perf_info: A list of benchmark_info(dict).
-    self.perf_info = []
-
-  def update_perf_info(self, test):
-    """Update perf_info with the given result of a single test.
-
-    Args:
-        test: A TestResult namedtuple.
-    """
-    all_additional_keys = set(test.additional_info.keys())
-    # Ensure every key is in all_additional_keys.
-    if not BENCHMARK_ESSENTIAL_KEYS.issubset(all_additional_keys):
-      return
-    benchmark_info = {}
-    benchmark_info['test_name'] = test.test_name
-    for key, data in test.additional_info.items():
-      if key in INT_KEYS:
-        data_to_int = data.split('.')[0]
-        benchmark_info[key] = data_to_int
-      elif key in BENCHMARK_EVENT_KEYS:
-        benchmark_info[key] = data
-    if benchmark_info:
-      self.perf_info.append(benchmark_info)
-
-  def print_perf_info(self):
-    """Print summary of a perf_info."""
-    if not self.perf_info:
-      return
-    classify_perf_info, max_len = self._classify_perf_info()
-    separator = '-' * au.get_terminal_size()[0]
-    print(separator)
-    print(
-        '{:{name}}    {:^{real_time}}    {:^{cpu_time}}    '
-        '{:>{iterations}}'.format(
-            'Benchmark',
-            'Time',
-            'CPU',
-            'Iteration',
-            name=max_len['name'] + 3,
-            real_time=max_len['real_time'] + max_len['time_unit'] + 1,
-            cpu_time=max_len['cpu_time'] + max_len['time_unit'] + 1,
-            iterations=max_len['iterations'],
-        )
-    )
-    print(separator)
-    for module_name, module_perf_info in classify_perf_info.items():
-      print('{}:'.format(module_name))
-      for benchmark_info in module_perf_info:
-        # BpfBenchMark/MapWriteNewEntry/1    1530 ns     1522 ns   460517
-        print(
-            '  #{:{name}}    {:>{real_time}} {:{time_unit}}    '
-            '{:>{cpu_time}} {:{time_unit}}    '
-            '{:>{iterations}}'.format(
-                benchmark_info['name'],
-                benchmark_info['real_time'],
-                benchmark_info['time_unit'],
-                benchmark_info['cpu_time'],
-                benchmark_info['time_unit'],
-                benchmark_info['iterations'],
-                name=max_len['name'],
-                real_time=max_len['real_time'],
-                time_unit=max_len['time_unit'],
-                cpu_time=max_len['cpu_time'],
-                iterations=max_len['iterations'],
-            )
-        )
-
-  def _classify_perf_info(self):
-    """Classify the perf_info by test module name.
-
-    Returns:
-        A tuple of (classified_perf_info, max_len), where
-        classified_perf_info: A dict of perf_info and each perf_info are
-                             belong to different modules.
-            e.g.
-                { module_name_01: [perf_info of module_1],
-                  module_name_02: [perf_info of module_2], ...}
-        max_len: A dict which stores the max length of each event.
-                 It contains the max string length of 'name', real_time',
-                 'time_unit', 'cpu_time', 'iterations'.
-            e.g.
-                {name: 56, real_time: 9, time_unit: 2, cpu_time: 8,
-                 iterations: 12}
-    """
-    module_categories = set()
-    max_len = {}
-    all_name = []
-    all_real_time = []
-    all_time_unit = []
-    all_cpu_time = []
-    all_iterations = ['Iteration']
-    for benchmark_info in self.perf_info:
-      module_categories.add(benchmark_info['test_name'].split('#')[0])
-      all_name.append(benchmark_info['name'])
-      all_real_time.append(benchmark_info['real_time'])
-      all_time_unit.append(benchmark_info['time_unit'])
-      all_cpu_time.append(benchmark_info['cpu_time'])
-      all_iterations.append(benchmark_info['iterations'])
-    classified_perf_info = {}
-    for module_name in module_categories:
-      module_perf_info = []
-      for benchmark_info in self.perf_info:
-        if benchmark_info['test_name'].split('#')[0] == module_name:
-          module_perf_info.append(benchmark_info)
-      classified_perf_info[module_name] = module_perf_info
-    max_len = {
-        'name': len(max(all_name, key=len)),
-        'real_time': len(max(all_real_time, key=len)),
-        'time_unit': len(max(all_time_unit, key=len)),
-        'cpu_time': len(max(all_cpu_time, key=len)),
-        'iterations': len(max(all_iterations, key=len)),
-    }
-    return classified_perf_info, max_len
-
-
 class RunStat:
   """Class for storing stats of a test run."""
 
@@ -240,7 +149,7 @@ class RunStat:
     self.failed = failed
     self.ignored = ignored
     self.assumption_failed = assumption_failed
-    self.perf_info = PerfInfo()
+    self.perf_info = metric_printer.PerfInfo()
     # Run errors are not for particular tests, they are runner errors.
     self.run_errors = run_errors
 
@@ -298,6 +207,8 @@ class ResultReporter:
       wait_for_debugger=False,
       args=None,
       test_infos=None,
+      class_level_report=False,
+      runner_errors_as_warnings=False,
   ):
     """Init ResultReporter.
 
@@ -313,6 +224,8 @@ class ResultReporter:
     self.silent = silent
     self.rerun_options = ''
     self.collect_only = collect_only
+    self.class_level_report = class_level_report
+    self.runner_errors_as_warnings = runner_errors_as_warnings
     self.test_result_link = None
     self.device_count = 0
     self.wait_for_debugger = wait_for_debugger
@@ -332,10 +245,11 @@ class ResultReporter:
       self.runners[test.runner_name] = OrderedDict()
     assert self.runners[test.runner_name] != FAILURE_FLAG
     self.all_test_results.append(test)
-    if test.group_name not in self.runners[test.runner_name]:
-      self.runners[test.runner_name][test.group_name] = RunStat()
+    group_name = self._get_group_name(test)
+    if group_name not in self.runners[test.runner_name]:
+      self.runners[test.runner_name][group_name] = RunStat()
       self._print_group_title(test)
-    self._update_stats(test, self.runners[test.runner_name][test.group_name])
+    self._update_stats(test, self.runners[test.runner_name][group_name])
     self._print_result(test)
 
   def runner_failure(self, runner_name, failure_msg):
@@ -402,7 +316,9 @@ class ResultReporter:
         name = group_name if group_name else runner_name
         test_run_name = (
             self.all_test_results[-1].test_run_name
-            if self.all_test_results[-1].test_run_name != name
+            # If `name` contains all information in `test_run_name`, do not
+            # attach the test run name.
+            if self.all_test_results[-1].test_run_name not in name
             else None
         )
         summary = self.process_summary(name, stats, test_run_name=test_run_name)
@@ -459,6 +375,7 @@ class ResultReporter:
       print(self.get_iterations_summary())
 
     failed_sum = len(self.failed_tests)
+    run_error_count = 0
     for runner_name, groups in self.runners.items():
       if groups == UNSUPPORTED_FLAG:
         print(
@@ -474,18 +391,34 @@ class ResultReporter:
       for group_name, stats in groups.items():
         name = group_name if group_name else runner_name
         summary = self.process_summary(name, stats)
-        if stats.failed > 0 or stats.run_errors:
+        if stats.failed > 0:
           tests_ret = ExitCode.TEST_FAILURE
-          if stats.run_errors:
+        if stats.run_errors:
+          run_error_count += 1
+          if not self.runner_errors_as_warnings:
+            tests_ret = ExitCode.TEST_FAILURE
             failed_sum += 1 if not stats.failed else 0
         if not ITER_SUMMARY:
           print(summary)
 
+    if run_error_count > 0:
+      metrics.LocalDetectEvent(
+          detect_type=atest_enum.DetectType.RUN_ERROR_COUNT,
+          result=run_error_count,
+      )
+
     self.run_stats.perf_info.print_perf_info()
     print()
     if not UNSUPPORTED_FLAG in self.runners.values():
       if tests_ret == ExitCode.SUCCESS:
-        print(au.mark_green('All tests passed!'))
+        if run_error_count > 0:
+          print(
+              au.mark_yellow(
+                  'All tests passed (With some incomplete tests ignored).'
+              )
+          )
+        else:
+          print(au.mark_green('All tests passed!'))
       else:
         message = '%d %s failed' % (
             failed_sum,
@@ -495,7 +428,9 @@ class ResultReporter:
         print('-' * len(message))
         self.print_failed_tests()
 
-    self._print_perf_test_metrics()
+    metric_printer.PerfInfo.print_perf_test_metrics(
+        self._test_infos, self.log_path, self._args
+    )
     # TODO(b/174535786) Error handling while uploading test results has
     # unexpected exceptions.
     # TODO (b/174627499) Saving this information in atest history.
@@ -503,101 +438,6 @@ class ResultReporter:
       print('Test Result uploaded to %s' % au.mark_green(self.test_result_link))
     return tests_ret
 
-  def _print_perf_test_metrics(self) -> bool:
-    """Print perf test metrics text content to console.
-
-    Returns:
-        True if metric printing is attempted; False if not perf tests.
-    """
-    if not any(
-        'performance-tests' in info.compatibility_suites
-        for info in self._test_infos
-    ):
-      return False
-
-    if not self.log_path:
-      return True
-
-    aggregated_metric_files = au.find_files(
-        self.log_path, file_name='*_aggregate_test_metrics_*.txt'
-    )
-
-    if self._args.perf_itr_metrics:
-      individual_metric_files = au.find_files(
-          self.log_path, file_name='test_results_*.txt'
-      )
-      print('\n{}'.format(au.mark_cyan('Individual test metrics')))
-      print(au.delimiter('-', 7))
-      for metric_file in individual_metric_files:
-        metric_file_path = pathlib.Path(metric_file)
-        # Skip aggregate metrics as we are printing individual metrics here.
-        if '_aggregate_test_metrics_' in metric_file_path.name:
-          continue
-        print('{}:'.format(au.mark_cyan(metric_file_path.name)))
-        print(
-            ''.join(
-                f'{" "*4}{line}'
-                for line in metric_file_path.read_text(
-                    encoding='utf-8'
-                ).splitlines(keepends=True)
-            )
-        )
-
-    print('\n{}'.format(au.mark_cyan('Aggregate test metrics')))
-    print(au.delimiter('-', 7))
-    for metric_file in aggregated_metric_files:
-      self._print_test_metric(pathlib.Path(metric_file))
-
-    return True
-
-  def _print_test_metric(self, metric_file: pathlib.Path) -> None:
-    """Print the content of the input metric file."""
-    test_metrics_re = re.compile(
-        r'test_results.*\s(.*)_aggregate_test_metrics_.*\.txt'
-    )
-    if not metric_file.is_file():
-      return
-    matches = re.findall(test_metrics_re, metric_file.as_posix())
-    test_name = matches[0] if matches else ''
-    if test_name:
-      print('{}:'.format(au.mark_cyan(test_name)))
-      with metric_file.open('r', encoding='utf-8') as f:
-        matched = False
-        filter_res = self._args.aggregate_metric_filter
-        logging.debug('Aggregate metric filters: %s', filter_res)
-        test_methods = []
-        # Collect all test methods
-        if filter_res:
-          test_re = re.compile(r'\n\n(\S+)\n\n', re.MULTILINE)
-          test_methods = re.findall(test_re, f.read())
-          f.seek(0)
-          # The first line of the file is also a test method but could
-          # not parsed by test_re; add the first line manually.
-          first_line = f.readline()
-          test_methods.insert(0, str(first_line).strip())
-          f.seek(0)
-        for line in f.readlines():
-          stripped_line = str(line).strip()
-          if filter_res:
-            if stripped_line in test_methods:
-              print()
-              au.colorful_print(' ' * 4 + stripped_line, constants.MAGENTA)
-            for filter_re in filter_res:
-              if re.match(re.compile(filter_re), line):
-                matched = True
-                print(' ' * 4 + stripped_line)
-          else:
-            matched = True
-            print(' ' * 4 + stripped_line)
-        if not matched:
-          au.colorful_print(
-              '  Warning: Nothing returned by the pattern: {}'.format(
-                  filter_res
-              ),
-              constants.RED,
-          )
-        print()
-
   def print_collect_tests(self):
     """Print summary of collect tests only.
 
@@ -651,7 +491,12 @@ class ResultReporter:
     if stats.failed > 0:
       failed_label = au.mark_red(failed_label)
     if stats.run_errors:
-      error_label = au.mark_red('(Completed With ERRORS)')
+      if self.runner_errors_as_warnings:
+        error_label = au.mark_yellow(
+            '(Incomplete probably due to infra issues)'
+        )
+      else:
+        error_label = au.mark_red('(Completed With ERRORS)')
       # Only extract host_log_content if test name is tradefed
       # Import here to prevent circular-import error.
       from atest.test_runners import atest_tf_test_runner
@@ -747,7 +592,7 @@ class ResultReporter:
     """
     if self.silent:
       return
-    title = test.group_name or test.runner_name
+    title = self._get_group_name(test) or test.runner_name
     underline = '-' * (len(title))
     print('\n%s\n%s' % (title, underline))
 
@@ -803,9 +648,19 @@ class ResultReporter:
       else:
         print(': {} {}'.format(au.colorize(test.status, color), test.test_time))
       if test.status == test_runner_base.PASSED_STATUS:
-        for key, data in sorted(test.additional_info.items()):
-          if key not in BENCHMARK_EVENT_KEYS:
-            print(f'\t{au.mark_blue(key)}: {data}')
+        metric_printer.PerfInfo.print_banchmark_result(test)
       if test.status == test_runner_base.FAILED_STATUS:
         print(f'\nSTACKTRACE:\n{test.details}')
     self.pre_test = test
+
+  def _get_group_name(self, test):
+    """Given a single test result, get its group name to use in the reporter."""
+    if not self.class_level_report:
+      return test.group_name
+    module_name = test.group_name if test.group_name else ''
+    test_class, test_method = (
+        test.test_name.split('#') if test.test_name else ['', '']
+    )
+    if not test_class:
+      return module_name
+    return f'{module_name}:{test_class}'
diff --git a/atest/result_reporter_unittest.py b/atest/result_reporter_unittest.py
index a45e2f07..21682f82 100755
--- a/atest/result_reporter_unittest.py
+++ b/atest/result_reporter_unittest.py
@@ -25,6 +25,7 @@ from unittest.mock import patch
 
 from atest import arg_parser
 from atest import atest_configs
+from atest import atest_enum
 from atest import result_reporter
 from atest.test_finders import test_info
 from atest.test_runners import test_runner_base
@@ -100,6 +101,20 @@ RESULT_RUN_FAILURE = test_runner_base.TestResult(
     test_run_name='com.android.UnitTests',
 )
 
+RESULT_RUN_FAILURE_2 = test_runner_base.TestResult(
+    runner_name='someTestRunner',
+    group_name='someTestModule2',
+    test_name='someClassName2#sostName2',
+    status=test_runner_base.ERROR_STATUS,
+    details='someRunFailureReason',
+    test_count=1,
+    test_time='',
+    runner_total=None,
+    group_total=2,
+    additional_info={},
+    test_run_name='com.android.UnitTests',
+)
+
 RESULT_INVOCATION_FAILURE = test_runner_base.TestResult(
     runner_name='someTestRunner',
     group_name=None,
@@ -142,111 +157,6 @@ RESULT_ASSUMPTION_FAILED_TEST = test_runner_base.TestResult(
     test_run_name='com.android.UnitTests',
 )
 
-ADDITIONAL_INFO_PERF01_TEST01 = {
-    'repetition_index': '0',
-    'cpu_time': '10001.10001',
-    'name': 'perfName01',
-    'repetitions': '0',
-    'run_type': 'iteration',
-    'label': '2123',
-    'threads': '1',
-    'time_unit': 'ns',
-    'iterations': '1001',
-    'run_name': 'perfName01',
-    'real_time': '11001.11001',
-}
-
-RESULT_PERF01_TEST01 = test_runner_base.TestResult(
-    runner_name='someTestRunner',
-    group_name='someTestModule',
-    test_name='somePerfClass01#perfName01',
-    status=test_runner_base.PASSED_STATUS,
-    details=None,
-    test_count=1,
-    test_time='(10ms)',
-    runner_total=None,
-    group_total=2,
-    additional_info=ADDITIONAL_INFO_PERF01_TEST01,
-    test_run_name='com.android.UnitTests',
-)
-
-RESULT_PERF01_TEST02 = test_runner_base.TestResult(
-    runner_name='someTestRunner',
-    group_name='someTestModule',
-    test_name='somePerfClass01#perfName02',
-    status=test_runner_base.PASSED_STATUS,
-    details=None,
-    test_count=1,
-    test_time='(10ms)',
-    runner_total=None,
-    group_total=2,
-    additional_info={
-        'repetition_index': '0',
-        'cpu_time': '10002.10002',
-        'name': 'perfName02',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1002',
-        'run_name': 'perfName02',
-        'real_time': '11002.11002',
-    },
-    test_run_name='com.android.UnitTests',
-)
-
-RESULT_PERF01_TEST03_NO_CPU_TIME = test_runner_base.TestResult(
-    runner_name='someTestRunner',
-    group_name='someTestModule',
-    test_name='somePerfClass01#perfName03',
-    status=test_runner_base.PASSED_STATUS,
-    details=None,
-    test_count=1,
-    test_time='(10ms)',
-    runner_total=None,
-    group_total=2,
-    additional_info={
-        'repetition_index': '0',
-        'name': 'perfName03',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1003',
-        'run_name': 'perfName03',
-        'real_time': '11003.11003',
-    },
-    test_run_name='com.android.UnitTests',
-)
-
-RESULT_PERF02_TEST01 = test_runner_base.TestResult(
-    runner_name='someTestRunner',
-    group_name='someTestModule',
-    test_name='somePerfClass02#perfName11',
-    status=test_runner_base.PASSED_STATUS,
-    details=None,
-    test_count=1,
-    test_time='(10ms)',
-    runner_total=None,
-    group_total=2,
-    additional_info={
-        'repetition_index': '0',
-        'cpu_time': '20001.20001',
-        'name': 'perfName11',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '2001',
-        'run_name': 'perfName11',
-        'real_time': '21001.21001',
-    },
-    test_run_name='com.android.UnitTests',
-)
-
 
 # pylint: disable=protected-access
 # pylint: disable=invalid-name
@@ -290,6 +200,26 @@ class ResultReporterUnittests(unittest.TestCase):
     self.assertTrue('someTestRunner2' in self.rr.runners)
     mock_title.assert_called_with(RESULT_PASSED_TEST_RUNNER_2_NO_MODULE)
 
+  @mock.patch.object(result_reporter.ResultReporter, '_print_group_title')
+  @mock.patch.object(result_reporter.ResultReporter, '_update_stats')
+  @mock.patch.object(result_reporter.ResultReporter, '_print_result')
+  def test_process_test_result_class_level_report(
+      self, mock_print, mock_update, mock_title
+  ):
+    """Test process_test_result method reported by class level."""
+    reporter = result_reporter.ResultReporter(class_level_report=True)
+
+    reporter.process_test_result(RESULT_PASSED_TEST)
+
+    self.assertTrue('someTestRunner' in reporter.runners)
+    group = reporter.runners['someTestRunner'].get(
+        'someTestModule:someClassName'
+    )
+    self.assertIsNotNone(group)
+    mock_title.assert_called_with(RESULT_PASSED_TEST)
+    mock_update.assert_called_with(RESULT_PASSED_TEST, group)
+    mock_print.assert_called_with(RESULT_PASSED_TEST)
+
   def test_print_result_run_name(self):
     """Test print run name function in print_result method."""
     try:
@@ -455,12 +385,13 @@ class ResultReporterUnittests(unittest.TestCase):
     self.rr._update_stats(RESULT_ASSUMPTION_FAILED_TEST, group)
     self.assertEqual(group.assumption_failed, 2)
 
+  @patch('atest.metrics.metrics.LocalDetectEvent')
   @patch.object(
       atest_configs,
       'GLOBAL_ARGS',
       arg_parser.create_atest_arg_parser().parse_args([]),
   )
-  def test_print_summary_ret_val(self):
+  def test_print_summary_ret_val(self, mock_detect_event):
     """Test print_summary method's return value."""
     # PASS Case
     self.rr.process_test_result(RESULT_PASSED_TEST)
@@ -471,6 +402,7 @@ class ResultReporterUnittests(unittest.TestCase):
     # PASS Case + Fail Case + PASS Case
     self.rr.process_test_result(RESULT_PASSED_TEST_MODULE_2)
     self.assertNotEqual(0, self.rr.print_summary())
+    mock_detect_event.assert_not_called()
 
   @patch.object(
       atest_configs,
@@ -489,172 +421,53 @@ class ResultReporterUnittests(unittest.TestCase):
     self.rr.process_test_result(RESULT_PASSED_TEST_MODULE_2)
     self.assertNotEqual(0, self.rr.print_summary())
 
+  @patch('atest.metrics.metrics.LocalDetectEvent')
+  @patch.object(
+      atest_configs,
+      'GLOBAL_ARGS',
+      arg_parser.create_atest_arg_parser().parse_args([]),
+  )
+  def test_print_summary_ret_val_err_stat2(self, mock_detect_event):
+    """Test print_summary method's return value."""
+    # PASS Case
+    self.rr.process_test_result(RESULT_PASSED_TEST)
+    # PASS Case + Run Error Case
+    self.rr.process_test_result(RESULT_RUN_FAILURE)
+    # PASS Case + Run Error Case + PASS Case
+    self.rr.process_test_result(RESULT_PASSED_TEST_MODULE_2)
+    # PASS Case + Run Error Case + PASS Case + Run Error Case
+    self.rr.process_test_result(RESULT_RUN_FAILURE_2)
+
+    self.assertNotEqual(0, self.rr.print_summary())
+    mock_detect_event.assert_called_with(
+        detect_type=atest_enum.DetectType.RUN_ERROR_COUNT,
+        result=2,
+    )
+
+  @patch.object(
+      atest_configs,
+      'GLOBAL_ARGS',
+      arg_parser.create_atest_arg_parser().parse_args([]),
+  )
+  def test_print_summary_ret_val_err_stat_with_run_error_downgraded(self):
+    """Test print_summary method's return value."""
+    reporter = result_reporter.ResultReporter(runner_errors_as_warnings=True)
+    # PASS Case
+    reporter.process_test_result(RESULT_PASSED_TEST)
+    self.assertEqual(0, reporter.print_summary())
+    # PASS Case + Fail Case
+    reporter.process_test_result(RESULT_RUN_FAILURE)
+    self.assertEqual(0, reporter.print_summary())
+    # PASS Case + Fail Case + PASS Case
+    reporter.process_test_result(RESULT_PASSED_TEST_MODULE_2)
+    self.assertEqual(0, reporter.print_summary())
+
   def test_collect_tests_only_no_throw(self):
     rr = result_reporter.ResultReporter(collect_only=True)
     rr.process_test_result(RESULT_PASSED_TEST)
 
     self.assertEqual(0, self.rr.print_collect_tests())
 
-  def test_update_perf_info(self):
-    """Test update_perf_info method."""
-    group = result_reporter.RunStat()
-    # 1. Test PerfInfo after RESULT_PERF01_TEST01
-    # _update_stats() will call _update_perf_info()
-    self.rr._update_stats(RESULT_PERF01_TEST01, group)
-    correct_perf_info = []
-    trim_perf01_test01 = {
-        'repetition_index': '0',
-        'cpu_time': '10001.10001',
-        'name': 'perfName01',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1001',
-        'run_name': 'perfName01',
-        'real_time': '11001.11001',
-        'test_name': 'somePerfClass01#perfName01',
-    }
-    correct_perf_info.append(trim_perf01_test01)
-    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
-    # 2. Test PerfInfo after RESULT_PERF01_TEST01
-    self.rr._update_stats(RESULT_PERF01_TEST02, group)
-    trim_perf01_test02 = {
-        'repetition_index': '0',
-        'cpu_time': '10002.10002',
-        'name': 'perfName02',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1002',
-        'run_name': 'perfName02',
-        'real_time': '11002.11002',
-        'test_name': 'somePerfClass01#perfName02',
-    }
-    correct_perf_info.append(trim_perf01_test02)
-    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
-    # 3. Test PerfInfo after RESULT_PERF02_TEST01
-    self.rr._update_stats(RESULT_PERF02_TEST01, group)
-    trim_perf02_test01 = {
-        'repetition_index': '0',
-        'cpu_time': '20001.20001',
-        'name': 'perfName11',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '2001',
-        'run_name': 'perfName11',
-        'real_time': '21001.21001',
-        'test_name': 'somePerfClass02#perfName11',
-    }
-    correct_perf_info.append(trim_perf02_test01)
-    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
-    # 4. Test PerfInfo after RESULT_PERF01_TEST03_NO_CPU_TIME
-    self.rr._update_stats(RESULT_PERF01_TEST03_NO_CPU_TIME, group)
-    # Nothing added since RESULT_PERF01_TEST03_NO_CPU_TIME lack of cpu_time
-    self.assertEqual(self.rr.run_stats.perf_info.perf_info, correct_perf_info)
-
-  def test_classify_perf_info(self):
-    """Test _classify_perf_info method."""
-    group = result_reporter.RunStat()
-    self.rr._update_stats(RESULT_PERF01_TEST01, group)
-    self.rr._update_stats(RESULT_PERF01_TEST02, group)
-    self.rr._update_stats(RESULT_PERF02_TEST01, group)
-    # trim the time form 10001.10001 to 10001
-    trim_perf01_test01 = {
-        'repetition_index': '0',
-        'cpu_time': '10001.10001',
-        'name': 'perfName01',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1001',
-        'run_name': 'perfName01',
-        'real_time': '11001.11001',
-        'test_name': 'somePerfClass01#perfName01',
-    }
-    trim_perf01_test02 = {
-        'repetition_index': '0',
-        'cpu_time': '10002.10002',
-        'name': 'perfName02',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '1002',
-        'run_name': 'perfName02',
-        'real_time': '11002.11002',
-        'test_name': 'somePerfClass01#perfName02',
-    }
-    trim_perf02_test01 = {
-        'repetition_index': '0',
-        'cpu_time': '20001.20001',
-        'name': 'perfName11',
-        'repetitions': '0',
-        'run_type': 'iteration',
-        'label': '2123',
-        'threads': '1',
-        'time_unit': 'ns',
-        'iterations': '2001',
-        'run_name': 'perfName11',
-        'real_time': '21001.21001',
-        'test_name': 'somePerfClass02#perfName11',
-    }
-    correct_classify_perf_info = {
-        'somePerfClass01': [trim_perf01_test01, trim_perf01_test02],
-        'somePerfClass02': [trim_perf02_test01],
-    }
-    classify_perf_info, max_len = (
-        self.rr.run_stats.perf_info._classify_perf_info()
-    )
-    correct_max_len = {
-        'real_time': 11,
-        'cpu_time': 11,
-        'name': 10,
-        'iterations': 9,
-        'time_unit': 2,
-    }
-    self.assertEqual(max_len, correct_max_len)
-    self.assertEqual(classify_perf_info, correct_classify_perf_info)
-
-  def test_print_perf_test_metrics_perf_tests_print_attempted(self):
-    test_infos = [
-        test_info.TestInfo(
-            'some_module',
-            'TestRunner',
-            set(),
-            compatibility_suites=['performance-tests'],
-        )
-    ]
-    sut = result_reporter.ResultReporter(test_infos=test_infos)
-
-    is_print_attempted = sut._print_perf_test_metrics()
-
-    self.assertTrue(is_print_attempted)
-
-  def test_print_perf_test_metrics_not_perf_tests_print__not_attempted(self):
-    test_infos = [
-        test_info.TestInfo(
-            'some_module',
-            'TestRunner',
-            set(),
-            compatibility_suites=['not-perf-test'],
-        )
-    ]
-    sut = result_reporter.ResultReporter(test_infos=test_infos)
-
-    is_print_attempted = sut._print_perf_test_metrics()
-
-    self.assertFalse(is_print_attempted)
-
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/atest/rollout_control.py b/atest/rollout_control.py
index 34b9cd11..263fd2bf 100644
--- a/atest/rollout_control.py
+++ b/atest/rollout_control.py
@@ -182,13 +182,6 @@ class RolloutControlledFeature:
     return is_enabled
 
 
-deprecate_bazel_mode = RolloutControlledFeature(
-    name='Deprecate Bazel Mode',
-    rollout_percentage=100,
-    env_control_flag='DEPRECATE_BAZEL_MODE',
-    feature_id=1,
-)
-
 rolling_tf_subprocess_output = RolloutControlledFeature(
     name='Rolling TradeFed subprocess output',
     rollout_percentage=100,
@@ -196,7 +189,10 @@ rolling_tf_subprocess_output = RolloutControlledFeature(
     feature_id=2,
     print_message=(
         atest_utils.mark_magenta(
-            'Rolling subprocess output feature is enabled: http://b/380460196.'
+            'Rolling subprocess output feature is enabled.'
+            ' Note that b/407065783 may cause test results to only appear'
+            ' after all tests have finished, and it is unrelated to this'
+            ' feature.'
         )
     ),
 )
@@ -208,10 +204,7 @@ tf_preparer_incremental_setup = RolloutControlledFeature(
     feature_id=3,
     print_message=(
         atest_utils.mark_magenta(
-            'You are one of the first users selected to receive the'
-            ' "Incremental setup for TradeFed preparers" feature. If you are'
-            ' happy with it, please +1 on http://b/381900378. If you'
-            ' experienced any issues, please comment on the same bug.'
+            'Incremental APK installation is enabled (b/381900378).'
         )
     ),
 )
diff --git a/atest/run_bazel_mode_atest_unittest.sh b/atest/run_bazel_mode_atest_unittest.sh
deleted file mode 100755
index 1d37c7af..00000000
--- a/atest/run_bazel_mode_atest_unittest.sh
+++ /dev/null
@@ -1,41 +0,0 @@
-#!/usr/bin/env bash
-
-# Copyright (C) 2021 The Android Open Source Project
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
-ATEST_SRC="${ANDROID_BUILD_TOP}/tools/asuite/atest/atest.py"
-WORKSPACE_ROOT="${ANDROID_BUILD_TOP}/out/atest_bazel_workspace/"
-BAZEL_BINARY="${ANDROID_BUILD_TOP}/prebuilts/bazel/linux-x86_64/bazel"
-
-function create_bazel_workspace(){
-    source "${ANDROID_BUILD_TOP}/build/envsetup.sh"
-    cd ${ANDROID_BUILD_TOP}
-    python ${ATEST_SRC} --bazel-mode atest_unittests --build
-}
-
-function bazel_query(){
-    cd ${WORKSPACE_ROOT}
-    echo "${BAZEL_BINARY} query ${1}"
-    ${BAZEL_BINARY} query ${1}
-}
-
-function bazel_test(){
-    cd ${WORKSPACE_ROOT}
-    echo "${BAZEL_BINARY} test ${1}"
-    ${BAZEL_BINARY} test ${1}
-}
-
-create_bazel_workspace
-bazel_query "deps(//tools/asuite/atest:atest_unittests_host)"
-bazel_test //tools/asuite/atest:atest_unittests_host
diff --git a/atest/test_finder_handler.py b/atest/test_finder_handler.py
index 5a3efc70..6da6cc0a 100644
--- a/atest/test_finder_handler.py
+++ b/atest/test_finder_handler.py
@@ -260,7 +260,11 @@ def _get_test_reference_types(ref):
     if '#' in ref_end:
       ref_end = ref_end.split('#')[0]
     if ref_end in ('java', 'kt', 'bp', 'mk', 'cc', 'cpp'):
-      return [FinderMethod.CACHE, FinderMethod.MODULE_FILE_PATH]
+      return [
+          FinderMethod.CACHE,
+          FinderMethod.MODULE,
+          FinderMethod.MODULE_FILE_PATH,
+      ]
     if ref_end == 'xml':
       return [
           FinderMethod.CACHE,
diff --git a/atest/test_finder_handler_unittest.py b/atest/test_finder_handler_unittest.py
index 48929171..438ba924 100755
--- a/atest/test_finder_handler_unittest.py
+++ b/atest/test_finder_handler_unittest.py
@@ -174,33 +174,37 @@ class TestFinderHandlerUnittests(unittest.TestCase):
             REF_TYPE.SUITE_PLAN_FILE_PATH,
         ],
     )
+    self.assertEqual(
+        test_finder_handler._get_test_reference_types('a.test.module.java'),
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
+    )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('SomeClass.java'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('SomeClass.kt'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('Android.mk'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('Android.bp'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('SomeTest.cc'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('SomeTest.cpp'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('SomeTest.cc#method'),
-        [REF_TYPE.CACHE, REF_TYPE.MODULE_FILE_PATH],
+        [REF_TYPE.CACHE, REF_TYPE.MODULE, REF_TYPE.MODULE_FILE_PATH],
     )
     self.assertEqual(
         test_finder_handler._get_test_reference_types('module:Class'),
diff --git a/atest/test_finders/cache_finder.py b/atest/test_finders/cache_finder.py
index 0495d664..46ec4d51 100644
--- a/atest/test_finders/cache_finder.py
+++ b/atest/test_finders/cache_finder.py
@@ -77,8 +77,6 @@ class CacheFinder(test_finder_base.TestFinderBase):
     if not self._is_latest_testinfos(test_infos):
       return False
     for t_info in test_infos:
-      if t_info.test_runner == 'BazelTestRunner':
-        return False
       if not self._is_test_path_valid(t_info):
         return False
       if not self._is_test_build_target_valid(t_info):
diff --git a/atest/test_finders/module_finder.py b/atest/test_finders/module_finder.py
index bbb0d067..0613e055 100644
--- a/atest/test_finders/module_finder.py
+++ b/atest/test_finders/module_finder.py
@@ -14,11 +14,14 @@
 
 """Module Finder class."""
 
+from collections import Counter
 import logging
 import os
+import shlex
 import time
 from typing import List
 
+from atest import arg_parser
 from atest import atest_configs
 from atest import atest_error
 from atest import atest_utils
@@ -86,6 +89,25 @@ class ModuleFinder(test_finder_base.TestFinderBase):
         testable_modules_only=True,
     )
 
+    # Checking for additional possible module paths
+    additional_paths = []
+    tests_path = os.path.join(module_path, 'tests')
+    if os.path.exists(os.path.join(self.root_dir, tests_path)):
+      additional_paths.append(tests_path)
+    test_path = os.path.join(module_path, 'test')
+    if os.path.exists(os.path.join(self.root_dir, test_path)):
+      additional_paths.append(test_path)
+    if additional_paths:
+      logging.debug(
+          'Adding additional possible module location(s): %s', additional_paths
+      )
+
+    for new_path in additional_paths:
+      modules_to_test |= self.module_info.get_modules_by_path(
+          path=new_path,
+          testable_modules_only=True,
+      )
+
     return test_finder_utils.extract_selected_tests(modules_to_test)
 
   def _is_vts_module(self, module_name):
@@ -350,8 +372,12 @@ class ModuleFinder(test_finder_base.TestFinderBase):
   # pylint: disable=too-many-branches
   # pylint: disable=too-many-locals
   def _get_test_info_filter(
-      self, path, methods, rel_module_dir=None, class_name=None,
-      is_native_test=False
+      self,
+      path,
+      methods,
+      rel_module_dir=None,
+      class_name=None,
+      is_native_test=False,
   ):
     """Get test info filter.
 
@@ -361,8 +387,8 @@ class ModuleFinder(test_finder_base.TestFinderBase):
         rel_module_dir: Optional. A string of the module dir no-absolute to
           root.
         class_name: Optional. A string of the class name.
-        is_native_test: Optional. A boolean variable of whether to search for
-          a native test or not.
+        is_native_test: Optional. A boolean variable of whether to search for a
+          native test or not.
 
     Returns:
         A set of test info filter.
@@ -375,7 +401,8 @@ class ModuleFinder(test_finder_base.TestFinderBase):
           test_info.TestFilter(
               test_filter_utils.get_cc_filter(
                   class_info,
-                  class_name if class_name is not None else '*', methods
+                  class_name if class_name is not None else '*',
+                  methods,
               ),
               frozenset(),
           )
@@ -406,12 +433,11 @@ class ModuleFinder(test_finder_base.TestFinderBase):
       ti_filter = frozenset(cc_filters)
     # If input path is a folder and have class_name information.
     elif not file_name and class_name:
-      ti_filter = frozenset(
-          [test_info.TestFilter(class_name, methods)]
-      )
+      ti_filter = frozenset([test_info.TestFilter(class_name, methods)])
     # Path to non-module dir, treat as package.
     elif not file_name and rel_module_dir != os.path.relpath(
-        path, self.root_dir):
+        path, self.root_dir
+    ):
       dir_items = [os.path.join(path, f) for f in os.listdir(path)]
       for dir_item in dir_items:
         if constants.JAVA_EXT_RE.match(dir_item):
@@ -608,6 +634,79 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     if '/' in search_class_name:
       search_class_name = str(search_class_name).split('/')[-1]
 
+    def remove_duplicated_test(
+        test_paths: List[str] | None,
+    ) -> List[str] | None:
+      """Remove duplicated test paths that generate the same command.
+
+      Check for each TF commands generated with test_path.
+      Only keep the first test_path if the generated command is the same.
+
+      Returns:
+          A subset or the same list of the test paths from test_paths.
+          or None if test_paths is None.
+      """
+      if test_paths is None:
+        return None
+
+      from atest import test_runner_handler
+
+      is_sts_enabled = getattr(
+          atest_configs.GLOBAL_ARGS, 'smart_test_selection', False
+      )
+      # Only do the filtering when sts enabled
+      if is_sts_enabled and module_name and len(test_paths) > 1:
+        # Remove duplicated test paths when they generates same commands:
+        filtered_tests = []
+        known_fingerprints_list = []
+        for test_path in test_paths:
+          test_filter = self._get_test_info_filter(
+              test_path,
+              methods,
+              class_name=class_name,
+              is_native_test=is_native_test,
+          )
+          test_infos = self._get_test_infos(
+              test_path, rel_config_path, module_name, test_filter
+          )
+
+          # A random value for command generation.
+          # GLOBAL_ARGS.device_count_config will be updated to proper value later.
+          atest_configs.GLOBAL_ARGS.device_count_config = 1
+          # try generate the command
+          for (
+              test_runner,
+              tests,
+          ) in test_runner_handler.group_tests_by_test_runners(test_infos):
+            if test_runner.NAME == self._TEST_RUNNER:
+              runner = test_runner(
+                  '/tmp',
+                  mod_info=self.module_info,
+                  extra_args={},
+              )
+              run_cmds = runner.generate_run_commands(tests, {})
+              for run_cmd in run_cmds:
+                current_command_fingerprint = Counter(shlex.split(run_cmd))
+
+                # check if generated command exists, it will be skipped from the result
+                if current_command_fingerprint in known_fingerprints_list:
+                  logging.debug(
+                      'Test [%s] has been filtered out due to same generated'
+                      ' command',
+                      test_path,
+                  )
+                else:
+                  known_fingerprints_list.append(current_command_fingerprint)
+                  filtered_tests.append(test_path)
+                  logging.debug(
+                      'Added generated command [%s] from Test [%s]',
+                      run_cmd,
+                      test_path,
+                  )
+          return filtered_tests if filtered_tests else test_paths
+      # No filtering needed
+      return test_paths
+
     test_paths = []
     # Search using the path where the config file is located.
     if rel_config_path:
@@ -627,7 +726,12 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     # Search from the root dir.
     if not test_paths:
       test_paths = test_finder_utils.find_class_file(
-          self.root_dir, search_class_name, is_native_test, methods
+          self.root_dir,
+          search_class_name,
+          is_native_test,
+          module_name,
+          methods,
+          remove_duplicated_test,
       )
     # If we already have module name, use path in module-info as test_path.
     if not test_paths:
diff --git a/atest/test_finders/module_finder_unittest.py b/atest/test_finders/module_finder_unittest.py
index fc6db565..c377594f 100755
--- a/atest/test_finders/module_finder_unittest.py
+++ b/atest/test_finders/module_finder_unittest.py
@@ -28,6 +28,8 @@ import re
 import tempfile
 import unittest
 from unittest import mock
+from atest import arg_parser
+from atest import atest_configs
 from atest import atest_error
 from atest import atest_utils
 from atest import constants
@@ -409,6 +411,143 @@ class ModuleFinderFindTestByModuleClassName(
           t_infos[0], 'tests.android.multi_module.ClassOneTest'
       )
 
+  @mock.patch.object(test_finder_utils, 'get_multiple_selection_answer')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_module_and_native_class_name_multiple_found(
+      self, find_cmd, mock_selection_answer
+  ):
+    """Testing when multiple cc test_path found and unable to determine module
+
+    sts enabled -- only one test is returned
+    sts not enabled -- two tests are returned
+    """
+    global_args = arg_parser.create_atest_arg_parser().parse_args([])
+    # When sts is enabled
+    global_args.smart_test_selection = True
+    global_args_patcher = mock.patch.object(
+        atest_configs, 'GLOBAL_ARGS', global_args
+    )
+    global_args_patcher.start()
+    # Select all test path if prompted
+    mock_selection_answer.return_value = 'A'
+
+    module_name = 'MyCCTestModule'
+    test_module = module_info_unittest_base.device_driven_test_module(
+        name=module_name, class_type=['NATIVE_TESTS']
+    )
+
+    find_cmd.return_value = [
+        'path/to/testmodule/src/com/android/mycctests/MyCCTestCases.cpp',
+        'path/to/anotherModule/src/com/android/mycctests/MyCCTestCases.cpp',
+    ]
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_module_and_class(
+        'MyCCTestModule:MyCCTestCases'
+    )
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+
+    # When sts is not enabled
+    global_args.smart_test_selection = False
+    t_infos = finder.find_test_by_module_and_class(
+        'MyCCTestModule:MyCCTestCases'
+    )
+    with self.subTest(name='returns_two_test_info'):
+      self.assertEqual(len(t_infos), 2)
+
+    global_args_patcher.stop()
+
+  @mock.patch.object(test_finder_utils, 'get_multiple_selection_answer')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_module_and_java_class_name_multiple_found(
+      self, find_cmd, mock_selection_answer
+  ):
+    """Testing when multiple java test_path found and unable to determine module
+
+    sts enabled -- one test is returned
+    sts not enabled -- two tests are returned
+    """
+    global_args = arg_parser.create_atest_arg_parser().parse_args([])
+    # When sts is enabled
+    global_args.smart_test_selection = True
+    global_args_patcher = mock.patch.object(
+        atest_configs, 'GLOBAL_ARGS', global_args
+    )
+    global_args_patcher.start()
+    # Select all test path if prompted
+    mock_selection_answer.return_value = 'A'
+
+    module_name = 'MyJavaTestModule'
+    test_module = module_info_unittest_base.device_driven_test_module(
+        name=module_name
+    )
+
+    find_cmd.return_value = [
+        'path/to/testmodule/src/com/android/mycctests/MyJavaTestCases.java',
+        'path/to/anotherModule/src/com/android/mycctests/MyJavaTestCases.java',
+    ]
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_module_and_class(
+        'MyJavaTestModule:qualified.domain.MyJavaTestCases'
+    )
+
+    with self.subTest(name='returns_one_test_info'):
+      self.assertEqual(len(t_infos), 1)
+
+    # When sts is not enabled
+    global_args.smart_test_selection = False
+    t_infos = finder.find_test_by_module_and_class(
+        'MyJavaTestModule:MyJavaTestCases'
+    )
+    with self.subTest(name='returns_two_test_info'):
+      self.assertEqual(len(t_infos), 2)
+
+    global_args_patcher.stop()
+
+  @mock.patch.object(atf_tr.AtestTradefedTestRunner, 'generate_run_commands')
+  @mock.patch('subprocess.check_output')
+  def test_find_test_by_module_class_name_multiple_found_with_same_cmd_diff_order(
+      self, find_cmd, generate_run_commands
+  ):
+    """Testing when generated command is same but args in different order.
+
+    The duplicated test will still be filtered out.
+    """
+    global_args = arg_parser.create_atest_arg_parser().parse_args([])
+    # When sts is enabled
+    global_args.smart_test_selection = True
+    global_args_patcher = mock.patch.object(
+        atest_configs, 'GLOBAL_ARGS', global_args
+    )
+    global_args_patcher.start()
+
+    module_name = 'MyJavaTestModule'
+    test_module = module_info_unittest_base.device_driven_test_module(
+        name=module_name
+    )
+
+    find_cmd.return_value = [
+        'path/to/testmodule/src/com/android/mycctests/MyJavaTestCases.java',
+        'path/to/anotherModule/src/com/android/mycctests/MyJavaTestCases.java',
+    ]
+    generate_run_commands.side_effect = [
+        ["atest_tradefed.sh --arg1 'module test' --arg2 222"],
+        ["atest_tradefed.sh --arg2 222 --arg1 'module test'"],
+    ]
+    finder = self.create_finder_with_module(test_module)
+
+    t_infos = finder.find_test_by_module_and_class(
+        'MyJavaTestModule:qualified.domain.MyJavaTestCases'
+    )
+
+    with self.subTest(name='returns_two_test_info'):
+      self.assertEqual(len(t_infos), 1)
+
+    global_args_patcher.stop()
+
   @mock.patch.object(test_finder_utils, 'get_multiple_selection_answer')
   @mock.patch('subprocess.check_output')
   def test_find_test_by_class_multiple_configs_one_test_per_config_found(
@@ -1776,6 +1915,67 @@ class ModuleFinderUnittests(unittest.TestCase):
         self, processed_info, uc.MODULE_INFO_W_DALVIK
     )
 
+  @mock.patch('atest.test_finders.module_finder.os.path.exists')
+  @mock.patch.object(
+      test_finder_utils,
+      'extract_selected_tests',
+      side_effect=lambda x, **kwargs: x,
+  )
+  def test_determine_modules_to_test_with_subdirs(
+      self, mock_extract_selected, mock_os_exists
+  ):
+    """Test _determine_modules_to_test with additional /tests and /test subdirectories."""
+    module_path_base = 'project/module'
+    # Absolute paths for os.path.exists mock
+    path_tests_abs = os.path.join(uc.ROOT, module_path_base, 'tests')
+    # Relative paths for get_modules_by_path mock
+    path_tests_rel = os.path.join(module_path_base, 'tests')
+
+    # Scenario: test_file_path provided, get_modules_by_path_in_srcs returns 1 module (early exit).
+    with self.subTest('test_file_path_srcs_finds_one_module_early_exit'):
+      test_file = 'some/file.java'
+      self.mod_finder.module_info.get_modules_by_path_in_srcs.return_value = {
+          'ModuleFromSrc'
+      }
+      result = self.mod_finder._determine_modules_to_test(
+          module_path_base, test_file_path=test_file
+      )
+      self.assertEqual(result, {'ModuleFromSrc'})
+      self.mod_finder.module_info.get_modules_by_path_in_srcs.assert_called_once_with(
+          path=test_file, testable_modules_only=True
+      )
+      self.mod_finder.module_info.get_modules_by_path.assert_not_called()
+      mock_extract_selected.assert_not_called()
+
+    # Scenario: test_file_path provided, srcs finds 0, then subdirs contribute.
+    with self.subTest('test_file_path_srcs_finds_zero_subdirs_contribute'):
+      test_file = 'some/other/file.java'
+      mock_os_exists.side_effect = (
+          lambda p: p == path_tests_abs
+      )  # Only /tests subdir exists
+      self.mod_finder.module_info.get_modules_by_path_in_srcs.return_value = (
+          set()
+      )
+
+      def get_modules_side_effect(path, testable_modules_only=True):
+        if path == module_path_base:
+          return {'ModuleBase'}
+        if path == path_tests_rel:
+          return {'ModuleFromTests'}  # This will be found
+        return set()
+
+      self.mod_finder.module_info.get_modules_by_path.side_effect = (
+          get_modules_side_effect
+      )
+
+      result = self.mod_finder._determine_modules_to_test(
+          module_path_base, test_file_path=test_file
+      )
+      self.assertEqual(result, {'ModuleBase', 'ModuleFromTests'})
+      mock_extract_selected.assert_called_once_with(
+          {'ModuleBase', 'ModuleFromTests'}
+      )
+
   # pylint: disable=unused-argument
   @mock.patch.object(module_finder.ModuleFinder, '_get_build_targets')
   @mock.patch.object(module_info.ModuleInfo, 'get_instrumentation_target_apps')
diff --git a/atest/test_finders/smart_test_finder/atp_test_selector.py b/atest/test_finders/smart_test_finder/atp_test_selector.py
new file mode 100644
index 00000000..d42e7952
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/atp_test_selector.py
@@ -0,0 +1,296 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Provides utils to select ATP test plans based on local change infos."""
+
+import collections
+import csv
+import dataclasses
+import functools
+import json
+import logging
+import os
+import pathlib
+import re
+import subprocess
+from typing import Dict
+from typing import List
+from atest import atest_utils
+from atest import constants
+from atest.test_finders.smart_test_finder import local_info_collector
+
+
+_DEVICE_PRODUCT_REGEX = re.compile(r'product:(?P<product>[^\s]+)')
+_DEVICE_REGEX = re.compile(r'device:(?P<device>[^\s]+)')
+
+_ENABLED_ATP_TEST_PLANS = [
+    'v2/android-platinum/suite/test-mapping-platinum-presubmit',
+    'v2/android-platinum/suite/test-mapping-platinum-presubmit-sysui-1',
+    'v2/android-platinum/suite/test-mapping-platinum-presubmit-sysui-2',
+    'v2/android-virtual-infra/test_mapping/presubmit-avd',
+    'v2/android-virtual-infra/test_mapping/presubmit-host',
+    'v2/android-virtual-infra/test_mapping/presubmit-large-avd',
+]
+
+
+def _get_constants_path() -> str:
+  """Gets the file path of all constants specific to smart test selection."""
+  return str(
+      pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH) / 'constants.json'
+  )
+
+
+def _get_lookup_table_path() -> str:
+  """Gets the look up table path."""
+  return str(
+      pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+      / 'lookup_tables/project_to_tests.csv'
+  )
+
+
+@functools.cache
+def _get_supported_device_targets() -> List[str]:
+  """Return supported device targets."""
+
+  try:
+    with open(_get_constants_path(), 'r') as file:
+      data = json.load(file)
+      return data['supported_device_target']
+  except (FileNotFoundError, json.JSONDecodeError) as err:
+    atest_utils.print_and_log_warning(
+        'Failed to get supported device targets: %s', err
+    )
+    return []
+
+
+@functools.cache
+def _get_compatible_matrix() -> Dict[str, List[str]]:
+  supported_device_target = _get_supported_device_targets()
+  return {
+      'aosp_cf_x86_64_only_phone-trunk_staging-userdebug': (
+          [
+              'aosp_cf_x86_64_only_phone',
+              'aosp_cf_x86_64_phone',
+              'cf_x86_64_phone',
+          ]
+          + supported_device_target
+      ),
+      'aosp_cf_x86_64_phone-trunk_staging-userdebug': (
+          ['aosp_cf_x86_64_phone', 'cf_x86_64_phone'] + supported_device_target
+      ),
+      'cf_x86_64_phone-trunk_staging-userdebug': (
+          ['cf_x86_64_phone'] + supported_device_target
+      ),
+  }
+
+
+@dataclasses.dataclass(frozen=True)
+class DeviceInfo:
+  """Presents device info: serial, product and device."""
+
+  serial: str
+  product: str
+  device: str
+
+
+# Presents the information of an ATP test.
+AtpTestInfo = collections.namedtuple(
+    'AtpTestInfo', ['name', 'target', 'branch']
+)
+
+
+def _get_filtered_test_names_from_lookup_table(names: str) -> List[str]:
+  """Get filtered test names from lookup table, removing brackets and quotes."""
+  return names.replace('[', '').replace(']', '').replace('"', '').split(',')
+
+
+# TODO(b/405156412): Re-implement this function with Treehugger APIs when they
+# are ready.
+def _get_candidate_atp_tests(
+    change_info: local_info_collector.ChangeInfo,
+) -> set[AtpTestInfo]:
+  """Get the list of ATP tests triggered by Treehugger in presubmit.
+
+  Args:
+    change_info: info of all changed files.
+
+  Returns:
+    ATP test information, including test name, target and branch.
+  """
+  tests = set()
+  if change_info.branch != 'main':
+    atest_utils.print_and_log_warning(
+        'Smart test selection is currently restricted to git_main. Will exit.'
+    )
+    return tests
+
+  with open(_get_lookup_table_path(), 'r', newline='') as csv_file:
+    csv_reader = csv.DictReader(csv_file)
+    for row in csv_reader:
+      if row['project'] == change_info.project and row['branch'] == 'git_main':
+        tests.update([
+            AtpTestInfo(name=name, target=row['target'], branch=row['branch'])
+            for name in _get_filtered_test_names_from_lookup_table(row['names'])
+        ])
+  return tests
+
+
+def _get_all_connected_devices() -> List[DeviceInfo]:
+  """Return all connected devices."""
+  # TODO(b/408251250): Switch to the new method to find connected devices.
+  command = 'adb devices -l'
+  try:
+    command_run_result = subprocess.check_output(
+        command,
+        shell=True,
+    )
+    list_result = command_run_result.strip().decode().splitlines()[1:]
+  except subprocess.CalledProcessError as err:
+    atest_utils.print_and_log_error(
+        'Failed to get connected devices as command %s return error: %s',
+        command,
+        err,
+    )
+    return []
+
+  device_infos = []
+  for line in list_result:
+    attrs = line.split()
+    serial = attrs[0]
+
+    product = ''
+    device_product_match_result = _DEVICE_PRODUCT_REGEX.search(line)
+    if device_product_match_result:
+      product = device_product_match_result.group('product')
+
+    device = ''
+    device_match_result = _DEVICE_REGEX.search(line)
+    if device_match_result:
+      device = device_match_result.group('device')
+    device_infos.append(
+        DeviceInfo(serial=serial, product=product, device=device)
+    )
+  return device_infos
+
+
+def get_matched_device() -> DeviceInfo:
+  """Get the connected device matching the current environment variables.
+
+  If the env var ANDROID_SERIAL is set, then both the match of serial and
+  product is enforced. If ANDROID_SERIAL is not set, then only the match of
+  product is enforced.
+
+  Returns:
+      The name of matched device.
+  """
+  all_devices = _get_all_connected_devices()
+  logging.info('All connected devices: %s', all_devices)
+  if not all_devices:
+    # No device connected
+    return None
+
+  android_serial = os.environ.get(constants.ANDROID_SERIAL)
+  target_product = os.environ.get(constants.ANDROID_TARGET_PRODUCT)
+  if not target_product:
+    atest_utils.print_and_log_warning(
+        'Cannot find target product, have you done lunch?'
+    )
+    return None
+
+  # 'ANDROID_SERIAL' is already set.
+  if android_serial:
+    for device_info in all_devices:
+      if device_info.serial == android_serial:
+        if (
+            device_info.product != target_product
+            and device_info.device != target_product
+        ):
+          atest_utils.print_and_log_warning(
+              f'Device with configured ANDROID_SERIAL {android_serial} is not'
+              ' aligned with the lunch target. lunch target is:'
+              f' {target_product}. Configured device is: {device_info}.'
+          )
+          return None
+        else:
+          return device_info
+    atest_utils.print_and_log_warning(
+        f'ANDROID_SERIAL is set to {android_serial} but can not find the device'
+        ' with that serial.'
+    )
+    return None
+
+  # 'ANDROID_SERIAL' is not set yet.
+  for device_info in all_devices:
+    if (
+        device_info.product == target_product
+        or device_info.device == target_product
+    ):
+      logging.info('Found matched device %s', device_info)
+      logging.info(
+          'ANDROID_SERIAL is not set. Set it to %s', device_info.serial
+      )
+      os.environ[constants.ANDROID_SERIAL] = device_info.serial
+      return device_info
+  atest_utils.print_and_log_warning(
+      f'Can not find a device that matches the lunch target {target_product}.'
+  )
+  atest_utils.colorful_print('Available devices are:', constants.CYAN)
+  for device in all_devices:
+    atest_utils.colorful_print(f'\t{device}', constants.CYAN)
+
+  return None
+
+
+def get_selected_atp_tests(change_info: local_info_collector.ChangeInfo):
+  """Based on changed file details, get selected ATP tests."""
+  candidate_tests = _get_candidate_atp_tests(change_info)
+  logging.info('Candidate ATP tests: %s', candidate_tests)
+  if not candidate_tests:
+    return []
+
+  matched_device = get_matched_device()
+  if not matched_device:
+    atest_utils.print_and_log_warning(
+        'No matched device connected, and no ATP tests are selected.'
+    )
+    return []
+
+  android_serial = matched_device.serial
+  try:
+    logging.debug('Disabling the ADB verification of device %s', android_serial)
+    subprocess.check_output(
+        f'adb -s {android_serial} shell settings put global'
+        ' package_verifier_user_consent -1',
+        shell=True,
+    )
+  except subprocess.CalledProcessError as err:
+    atest_utils.print_and_log_warning(
+        'Failed to disable the ADB verification of devices %s. Error: %s',
+        matched_device,
+        err,
+    )
+
+  selected_atp_tests = []
+  for test in candidate_tests:
+    if (
+        test.name in _ENABLED_ATP_TEST_PLANS
+        and matched_device
+        and matched_device.product
+        in _get_compatible_matrix().get(test.target, [])
+    ):
+      selected_atp_tests.append(test)
+
+  return selected_atp_tests
diff --git a/atest/test_finders/smart_test_finder/atp_test_selector_unittest.py b/atest/test_finders/smart_test_finder/atp_test_selector_unittest.py
new file mode 100644
index 00000000..cc663fbc
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/atp_test_selector_unittest.py
@@ -0,0 +1,349 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Unittests for atp_test_selector."""
+
+# pylint: disable=invalid-name
+
+import os
+import subprocess
+import unittest
+from unittest import mock
+from atest import constants
+from atest.test_finders.smart_test_finder import atp_test_selector
+from atest.test_finders.smart_test_finder import local_info_collector
+from pyfakefs import fake_filesystem_unittest
+
+
+_FAKE_CONSTANTS_CONTENT = """{
+    "supported_device_target": [
+        "device1",
+        "device2"
+    ]
+}"""
+
+_FAKE_ADB_OUTPUT = b"""List of devices attached
+fake.ser.num1        product:device_product_1 model:not_important_model1 device:some_device1 transport_id:1
+fake.ser.num2        device product:device_product_2 model:not_important_model2 device:some_device2 transport_id:2
+matched.ser.num       product:matched_device_product model:not_important_model3 device:matched_device transport_id:3
+aosp.matched.ser.num    product:aosp_cf_x86_64_only_phone model:not_important_model4 device:device2 transport_id:4
+some_serial   device product:aosp_cf_x86_64_phone model:not_important_model5 device:some_device transport_id:5
+"""
+
+_FAKE_ADB_OUTPUT2 = b"""List of devices attached
+matched.ser.num       device product:aosp_cf_x86_64_only_phone model:not_important_model3 device:matched_device transport_id:3
+"""
+
+_FAKE_LOOKUP_TABLE_CONTENT = """project,target,branch,names
+Project/Name1,cf_x86_64_phone-trunk_staging-userdebug,git_main,"[""v2/android-test-harness-team/artifact/artifact_output_validation"",""v2/android-app-compat-engprod/csuite/top_100_app_launch_presubmit_partition_6""]"
+Project/Name1,aosp_cf_x86_64_phone-trunk_staging-userdebug,git_main,"[""v2/android-gki/test_mapping_kernel_presubmit"",""v2/android-virtual-infra/test_mapping/presubmit-avd"",""v2/android-virtual-infra/test_mapping/presubmit-host""]"
+Project/Name2,cf_x86_64_phone-trunk_staging-userdebug,git_main,"[""v2/android-test-harness-team/tradefed/test_mappings_validation_tests_with_device"",""v2/android-virtual-infra/test_mapping/presubmit-cf""]"
+Project/Name2,aosp_cf_x86_64_phone-trunk_staging-userdebug,git_main,"[""v2/android-virtual-infra/test_mapping/presubmit-avd"",""v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation""]"
+Project/Name3,aosp_cf_x86_64_only_phone-trunk_staging-userdebug,git_main,"[""v2/android-virtual-infra/test_mapping/presubmit-large-avd"",""v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation""]"
+Project/Name4,aosp_cf_x86_64_only_phone-trunk_staging-userdebug,aosp-main,"[""v2/android-virtual-infra/test_mapping/presubmit-large-avd"",""v2/android-virtual-infra/test_mapping/presubmit-host""]"
+"""
+
+
+# pylint: disable=protected-access
+class AtpTestSelectorUnittests(unittest.TestCase):
+  """Unit tests for atp_test_selector.py."""
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'matched.ser.num',
+          constants.ANDROID_TARGET_PRODUCT: 'matched_device_product',
+      },
+  )
+  def test_get_matched_device_android_serial_set_and_product_matched(self, _):
+    expected_device_info = atp_test_selector.DeviceInfo(
+        serial='matched.ser.num',
+        product='matched_device_product',
+        device='matched_device',
+    )
+
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertEqual(actual_device_info, expected_device_info)
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'matched.ser.num',
+          constants.ANDROID_TARGET_PRODUCT: 'matched_device',
+      },
+  )
+  def test_get_matched_device_android_serial_set_and_device_matched(self, _):
+    expected_device_info = atp_test_selector.DeviceInfo(
+        serial='matched.ser.num',
+        product='matched_device_product',
+        device='matched_device',
+    )
+
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertEqual(actual_device_info, expected_device_info)
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'matched.ser.num',
+          constants.ANDROID_TARGET_PRODUCT: 'unmatched_device_product',
+      },
+  )
+  def test_get_matched_device_android_serial_set_but_product_unmatched(self, _):
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertIsNone(actual_device_info)
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: '',
+          constants.ANDROID_TARGET_PRODUCT: 'matched_device_product',
+      },
+  )
+  def test_get_matched_device_android_serial_unset_but_product_matched(self, _):
+    expected_device_info = atp_test_selector.DeviceInfo(
+        serial='matched.ser.num',
+        product='matched_device_product',
+        device='matched_device',
+    )
+
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertEqual(actual_device_info, expected_device_info)
+    self.assertEqual(os.environ.get('ANDROID_SERIAL'), 'matched.ser.num')
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: '',
+          constants.ANDROID_TARGET_PRODUCT: 'matched_device',
+      },
+  )
+  def test_get_matched_device_android_serial_unset_but_device_matched(self, _):
+    expected_device_info = atp_test_selector.DeviceInfo(
+        serial='matched.ser.num',
+        product='matched_device_product',
+        device='matched_device',
+    )
+
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertEqual(actual_device_info, expected_device_info)
+    self.assertEqual(os.environ.get('ANDROID_SERIAL'), 'matched.ser.num')
+
+  @mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'matched.ser.num',
+          constants.ANDROID_TARGET_PRODUCT: '',
+      },
+  )
+  def test_get_matched_device_android_serial_set_but_product_unset(self, _):
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertIsNone(actual_device_info)
+
+  @mock.patch(
+      'subprocess.check_output',
+      side_effect=subprocess.CalledProcessError(
+          returncode=1,
+          cmd='adb devices -l',
+      ),
+  )
+  def test_get_matched_device_failed_to_get_connected_devices(self, _):
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertIsNone(actual_device_info)
+
+  @mock.patch(
+      'subprocess.check_output',
+      return_value=b'List of devices attached',
+  )
+  def test_get_matched_device_no_connected_devices(self, _):
+    actual_device_info = atp_test_selector.get_matched_device()
+
+    self.assertIsNone(actual_device_info)
+
+  def test_get_selected_atp_tests_return_empty_list_if_branch_is_not_main(self):
+    input_change_info = local_info_collector.ChangeInfo(
+        project='Project/Name2',
+        branch='not-main',
+        remote_hostname='some_hostname',
+        user_key='some_user',
+        changed_files=set(),
+    )
+
+    actual_selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+        input_change_info
+    )
+
+    self.assertCountEqual(actual_selected_atp_tests, [])
+
+
+# pylint: disable=protected-access
+class AtpTestSelectorFileSystemUnittests(fake_filesystem_unittest.TestCase):
+  """Unit tests for atp_test_selector.py with file access."""
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+
+    self.fake_constants_path = atp_test_selector._get_constants_path()
+    self.fs.create_file(
+        self.fake_constants_path,
+        contents=_FAKE_CONSTANTS_CONTENT,
+    )
+
+    self.fake_lookup_table_path = atp_test_selector._get_lookup_table_path()
+    self.fs.create_file(
+        self.fake_lookup_table_path,
+        contents=_FAKE_LOOKUP_TABLE_CONTENT,
+    )
+
+    self.mock_subprocess_check_output = self.enterContext(
+        mock.patch('subprocess.check_output', return_value=_FAKE_ADB_OUTPUT)
+    )
+
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'some_serial',
+          constants.ANDROID_TARGET_PRODUCT: 'aosp_cf_x86_64_phone',
+      },
+  )
+  def test_get_selected_atp_tests_return_matched_tests_for_virtual_device(self):
+    input_change_info = local_info_collector.ChangeInfo(
+        project='Project/Name2',
+        branch='main',
+        remote_hostname='some_hostname',
+        user_key='some_user',
+        changed_files=set(),
+    )
+    # 'v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation' is
+    # not yet verified to be runnable, so it is not selected.
+    expected_selected_atp_tests = [
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-virtual-infra/test_mapping/presubmit-avd',
+            target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+            branch='git_main',
+        ),
+    ]
+
+    actual_selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+        input_change_info
+    )
+
+    self.assertCountEqual(
+        actual_selected_atp_tests, expected_selected_atp_tests
+    )
+
+  @mock.patch('subprocess.check_output', side_effect=[_FAKE_ADB_OUTPUT2, b''])
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: '',
+          constants.ANDROID_TARGET_PRODUCT: 'aosp_cf_x86_64_only_phone',
+      },
+  )
+  def test_get_selected_atp_tests_return_matched_tests_for_real_device(
+      self, mock_subprocess_check_output
+  ):
+    input_change_info = local_info_collector.ChangeInfo(
+        project='Project/Name3',
+        branch='main',
+        remote_hostname='some_hostname',
+        user_key='some_user',
+        changed_files=set(),
+    )
+    # 'v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation' is
+    # not yet verified to be runnable, so it is not selected.
+    expected_selected_atp_tests = [
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-virtual-infra/test_mapping/presubmit-large-avd',
+            target='aosp_cf_x86_64_only_phone-trunk_staging-userdebug',
+            branch='git_main',
+        ),
+    ]
+
+    actual_selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+        input_change_info
+    )
+
+    self.assertCountEqual(
+        actual_selected_atp_tests, expected_selected_atp_tests
+    )
+    self.assertEqual(
+        os.environ.get(constants.ANDROID_SERIAL), 'matched.ser.num'
+    )
+    mock_subprocess_check_output.assert_called_with(
+        'adb -s matched.ser.num shell settings put global'
+        ' package_verifier_user_consent -1',
+        shell=True,
+    )
+
+  @mock.patch.dict(
+      'os.environ',
+      {
+          constants.ANDROID_SERIAL: 'matched.ser.num',
+          constants.ANDROID_TARGET_PRODUCT: 'unmatched_device_product',
+      },
+  )
+  def test_get_selected_atp_tests_return_empty_list_only_if_no_matched_device(
+      self,
+  ):
+    input_change_info = local_info_collector.ChangeInfo(
+        project='Project/Name1',
+        branch='main',
+        remote_hostname='some_hostname',
+        user_key='some_user',
+        changed_files=set(),
+    )
+
+    actual_selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+        input_change_info
+    )
+
+    self.assertCountEqual(actual_selected_atp_tests, [])
+
+  def test_get_selected_atp_tests_test_plan_not_selected_if_branch_not_git_main(
+      self,
+  ):
+    input_change_info = local_info_collector.ChangeInfo(
+        project='Project/Name4',
+        branch='main',
+        remote_hostname='some_hostname',
+        user_key='some_user',
+        changed_files=set(),
+    )
+
+    actual_selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+        input_change_info
+    )
+
+    self.assertCountEqual(actual_selected_atp_tests, [])
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/test_finders/smart_test_finder/local_info_collector.py b/atest/test_finders/smart_test_finder/local_info_collector.py
new file mode 100644
index 00000000..d185b7f8
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/local_info_collector.py
@@ -0,0 +1,122 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Provides utils to obtain local change infos (project, branch, changed files, etc.)"""
+
+import dataclasses
+import getpass
+import logging
+import re
+import subprocess
+from xml.etree import ElementTree
+from atest import atest_utils
+
+
+_PROJECT_KEY = 'project'
+_BRANCH_KEY = 'branch'
+_REMOTE_HOSTNAME_KEY = 'remote_hostname'
+_MATCH_PROJECT_REGEX = re.compile(rf'^Project: (?P<{_PROJECT_KEY}>[^\s]+)')
+_MATCH_BRANCH_REGEX = re.compile(
+    rf'^Manifest branch: (?P<{_BRANCH_KEY}>[^\s]+)'
+)
+_ANDROID_BUILD_TOP_KEY = 'ANDROID_BUILD_TOP'
+_MATCH_REMOTE_HOSTNAME_REGEX = re.compile(
+    rf'sso://(?P<{_REMOTE_HOSTNAME_KEY}>[^/]+)/'
+)
+
+
+@dataclasses.dataclass(frozen=True)
+class ChangeInfo:
+  """Information of local changes against the remote HEAD.
+
+  The info includes the current project, branch, remote hostname, username, set
+  of changed files.
+  """
+
+  project: str
+  branch: str
+  remote_hostname: str
+  user_key: str
+  changed_files: set[atest_utils.ChangedFileDetails]
+
+
+def get_local_change_info() -> ChangeInfo:
+  """Get the local change info under the current project."""
+  project, branch = _get_project_and_branch()
+  change_info = ChangeInfo(
+      project=project,
+      branch=branch,
+      remote_hostname=_get_remote_hostname(),
+      user_key=getpass.getuser(),
+      changed_files=atest_utils.get_modified_files_with_details(),
+  )
+  return change_info
+
+
+def _get_remote_hostname() -> str:
+  """Get remote hostname.
+
+  Returns:
+      Remote hostnames extracted from the domain name
+      'sso://{remote-hostname}/'.
+  """
+  manifest_default_path = ''
+  try:
+    manifest_default_path = atest_utils.get_build_top(
+        '.repo/manifests/default.xml'
+    )
+    manifest = ElementTree.parse(str(manifest_default_path))
+    root = manifest.getroot()
+    default = root.find('default')
+    if default is not None:
+      for element in root.findall('remote'):
+        if element.attrib['name'] == default.attrib['remote']:
+          match_remote_hostname = _MATCH_REMOTE_HOSTNAME_REGEX.match(
+              element.attrib['review']
+          )
+          if match_remote_hostname:
+            return match_remote_hostname.group(_REMOTE_HOSTNAME_KEY)
+  except (OSError, ElementTree.ParseError):
+    if manifest_default_path:
+      logging.debug(
+          'Failed to parse the XML file for remote hostname: %s',
+          manifest_default_path,
+      )
+    else:
+      logging.debug('Failed to get the build top for remote hostname.')
+  return ''
+
+
+def _get_project_and_branch() -> tuple[str, str]:
+  """Get the project and branch name in the current working directory."""
+  branch = ''
+  project = ''
+  try:
+    repo_output = (
+        subprocess.check_output('repo info .', shell=True).decode().splitlines()
+    )
+    for line in repo_output:
+      match_project = _MATCH_PROJECT_REGEX.match(line)
+      if match_project:
+        project = match_project.group(_PROJECT_KEY)
+        continue
+      match_branch = _MATCH_BRANCH_REGEX.match(line)
+      if match_branch:
+        branch = match_branch.group(_BRANCH_KEY)
+  except subprocess.CalledProcessError as err:
+    logging.debug('Failed to get the repo or the branch: %s', err)
+
+  return (project, branch)
diff --git a/atest/test_finders/smart_test_finder/local_info_collector_unittest.py b/atest/test_finders/smart_test_finder/local_info_collector_unittest.py
new file mode 100644
index 00000000..3e7136a7
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/local_info_collector_unittest.py
@@ -0,0 +1,161 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Unittests for local_info_collector."""
+
+# pylint: disable=invalid-name
+
+import pathlib
+import subprocess
+import tempfile
+import unittest
+from unittest import mock
+from atest import atest_utils
+from atest.test_finders.smart_test_finder import local_info_collector
+from pyfakefs import fake_filesystem_unittest
+
+
+_REPO_INFO_OUTPUT = b"""Manifest branch: fake_branch
+Manifest merge branch: fake_merge_branch
+----------------------------
+Project: fake_project
+"""
+
+_MANIFEST_XML_CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
+    <manifest>
+      <remote  name="remote_symbol"
+               fetch=".."
+               review="sso://stuff-to-be-selected/" />
+      <default revision="main"
+               remote="remote_symbol"
+               sync-j="32"
+        />
+      <remote  name="not_selected_remote_symbol" fetch=".." review="sso://not-selected-stuff/" />
+    </manifest>
+"""
+
+
+_FAKE_CHANGED_FILE_DETAILS = frozenset([
+    atest_utils.ChangedFileDetails(
+        filename='/a/b/c',
+        number_of_lines_inserted=14,
+        number_of_lines_deleted=25,
+    ),
+    atest_utils.ChangedFileDetails(
+        filename='/d/e/f',
+        number_of_lines_inserted=36,
+        number_of_lines_deleted=47,
+    ),
+])
+
+
+# pylint: disable=protected-access
+class LocalInfoCollectorFileSystemUnittests(fake_filesystem_unittest.TestCase):
+  """Unit tests for local_info_collector.py with file access."""
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+    self.mock_getuser = self.enterContext(
+        mock.patch('getpass.getuser', return_value='fake_user')
+    )
+    self.mock_get_modified_files_with_details = self.enterContext(
+        mock.patch.object(
+            atest_utils,
+            'get_modified_files_with_details',
+            return_value=_FAKE_CHANGED_FILE_DETAILS,
+        )
+    )
+
+  @mock.patch('subprocess.check_output', return_value=_REPO_INFO_OUTPUT)
+  def test_get_local_change_info(self, _):
+    fake_temp_file_name = next(tempfile._get_candidate_names())
+    self.fs.create_file(
+        fake_temp_file_name,
+        contents=_MANIFEST_XML_CONTENT,
+    )
+
+    with mock.patch.object(
+        atest_utils,
+        'get_build_top',
+        return_value=pathlib.Path(fake_temp_file_name),
+    ):
+      expected_change_info = local_info_collector.ChangeInfo(
+          project='fake_project',
+          branch='fake_branch',
+          remote_hostname='stuff-to-be-selected',
+          changed_files=_FAKE_CHANGED_FILE_DETAILS,
+          user_key='fake_user',
+      )
+
+      change_info = local_info_collector.get_local_change_info()
+
+      self.assertEqual(change_info, expected_change_info)
+
+  @mock.patch(
+      'subprocess.check_output',
+      side_effect=subprocess.CalledProcessError(
+          returncode=1, cmd='repo info .'
+      ),
+  )
+  def test_get_local_change_info_failed_to_get_repo_info(self, _):
+    fake_temp_file_name = next(tempfile._get_candidate_names())
+    self.fs.create_file(
+        fake_temp_file_name,
+        contents=_MANIFEST_XML_CONTENT,
+    )
+
+    with mock.patch.object(
+        atest_utils,
+        'get_build_top',
+        return_value=pathlib.Path(fake_temp_file_name),
+    ):
+      expected_change_info = local_info_collector.ChangeInfo(
+          project='',
+          branch='',
+          remote_hostname='stuff-to-be-selected',
+          changed_files=_FAKE_CHANGED_FILE_DETAILS,
+          user_key='fake_user',
+      )
+
+      change_info = local_info_collector.get_local_change_info()
+
+      self.assertEqual(change_info, expected_change_info)
+
+  @mock.patch('subprocess.check_output', return_value=_REPO_INFO_OUTPUT)
+  def test_get_local_change_info_failed_to_get_remote_hostname(self, _):
+    fake_temp_file_name = next(tempfile._get_candidate_names())
+
+    with mock.patch.object(
+        atest_utils,
+        'get_build_top',
+        return_value=pathlib.Path(fake_temp_file_name),
+    ):
+      expected_change_info = local_info_collector.ChangeInfo(
+          project='fake_project',
+          branch='fake_branch',
+          remote_hostname='',
+          changed_files=_FAKE_CHANGED_FILE_DETAILS,
+          user_key='fake_user',
+      )
+
+      change_info = local_info_collector.get_local_change_info()
+
+      self.assertEqual(change_info, expected_change_info)
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/test_finders/smart_test_finder/smart_test_filter.py b/atest/test_finders/smart_test_finder/smart_test_filter.py
new file mode 100644
index 00000000..5ba4a8e7
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/smart_test_filter.py
@@ -0,0 +1,148 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Provides utils to filter out some selected test classes."""
+
+import csv
+import dataclasses
+import functools
+import logging
+import pathlib
+from typing import Dict
+from typing import List
+from atest import constants
+
+
+_NUM_MILLISECONDS_IN_MINUTES = 60000
+
+
+@dataclasses.dataclass(frozen=True)
+class TestClassInfo:
+  test_id: str
+  atp_test_name: str = ''
+  branch: str = ''
+  target: str = ''
+  run_time: float = -1
+  pass_rate: float = 0.0
+  module: str = ''
+  test_class: str = ''
+  score: float = 0.0
+
+
+@functools.cache
+def _get_blocked_tests() -> Dict[str, str]:
+  """Get the list of blocked tests from stored file."""
+  results = {}
+  with open(
+      str(
+          pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+          / 'lookup_tables/blocklist.csv'
+      ),
+      'r',
+      newline='',
+  ) as csv_file:
+    csv_reader = csv.DictReader(csv_file)
+    for row in csv_reader:
+      results[row['module']] = row['reason']
+  return results
+
+
+@functools.cache
+def _get_test_class_history() -> Dict[str, TestClassInfo]:
+  """Get the mapping from test ID to test class history."""
+  results = {}
+  with open(
+      str(
+          pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+          / 'lookup_tables/tests_with_runtime_and_pass_rate.csv'
+      ),
+      'r',
+      newline='',
+  ) as csv_file:
+    csv_reader = csv.DictReader(csv_file)
+    for row in csv_reader:
+      test_class_info = TestClassInfo(
+          branch=row['branch'],
+          target=row['target'],
+          atp_test_name=row['test_name'],
+          test_id=row['test_id'],
+          run_time=float(row['test_run_duration_ms_past7days']),
+          pass_rate=float(row['postsubmit_pass_rate']),
+      )
+      results[row['test_id']] = test_class_info
+
+  return results
+
+
+def get_selected_test_classes(
+    candidate_tests: List[TestClassInfo], time_limit_min: float
+) -> List[TestClassInfo]:
+  """Get filtered test classes based on history and time limit to execute."""
+  results = []
+  test_class_history = _get_test_class_history()
+  blocked_test = _get_blocked_tests()
+  total_test_time = 0.0
+
+  # TODO(b/412692700): When test time is stably available by the majority of
+  # tests in the lookup table, we need to switch to a better sorting strategy,
+  # which sorts by non-increasing score, then by non-decreasing run time.
+  # Sort the candidate tests first by non-increasing score, then by
+  # non-decreasing module name, then by non-decreasing test class name.
+  for test in sorted(
+      candidate_tests, key=lambda t: (-t.score, t.module, t.test_class)
+  ):
+    logging.debug(
+        'checking test %s:%s with score: %s',
+        test.module,
+        test.test_class,
+        test.score,
+    )
+    if test.module in blocked_test:
+      logging.debug(
+          'Module %s is currently opted out from smart test selection,'
+          ' skipping',
+          test.module,
+      )
+      continue
+    if test.test_id not in test_class_history:
+      logging.debug('No history of %s found, skipping', test.test_id)
+      continue
+    test_class_info = test_class_history[test.test_id]
+    if not test.module or not test.test_class:
+      logging.debug(
+          'Can not find module/test_class info for Test %s, skipping',
+          test.test_id,
+      )
+      continue
+    if test_class_info.pass_rate < 0.95:
+      logging.debug('Test %s is flaky, skipping', test.test_id)
+      continue
+    if test_class_info.run_time < 0:
+      logging.debug(
+          'Can not determine the test run time for test %s, skipping',
+          test.test_id,
+      )
+      continue
+    if (
+        total_test_time + test_class_info.run_time
+        < time_limit_min * _NUM_MILLISECONDS_IN_MINUTES
+    ):
+      results.append(test)
+      total_test_time += test_class_info.run_time
+    elif results:
+      break
+
+  return results
diff --git a/atest/test_finders/smart_test_finder/smart_test_filter_unittest.py b/atest/test_finders/smart_test_finder/smart_test_filter_unittest.py
new file mode 100644
index 00000000..7ab3a1d3
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/smart_test_filter_unittest.py
@@ -0,0 +1,396 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Unittests for smart_test_filter."""
+
+# pylint: disable=invalid-name
+
+import pathlib
+import unittest
+from atest import constants
+from atest.test_finders.smart_test_finder import smart_test_filter
+from pyfakefs import fake_filesystem_unittest
+
+_FAKE_BLOCKLIST_CONTENT = """module,reason
+BlockedModule, test_reaon"""
+
+_FAKE_LOOKUP_TABLE_CONTENT = """branch,target,test_name,test_id,postsubmit_pass_rate,test_run_duration_ms_past7days
+some_branch,some_target,TestA,a_id,0.99,10000
+some_branch2,some_target2,TestFlakyTest,b_id,0.90,500
+some_branch3,some_target3,TestRunTimeNotFound,c_id,0.99,-1
+some_branch4,some_target4,TestD,d_id,0.99,40000
+some_branch6,some_target6,TestF,f_id,0.99,500
+some_branch7,some_target7,TestG,g_id,0.98,5
+some_branch5,some_target5,TestNotSelectedDueToTimeLimit,e_id,0.99,20000
+some_branch8,some_target8,TestNotSelectedDueToTimeLimit2,h_id,0.98,5
+some_branch2,some_target2,TestWithoutModule,j_id,0.99,500
+some_branch2,some_target2,TestWithoutTestClass,k_id,0.99,500
+some_branch9,some_target9,TestWithOptedOutTests,l_id,1,2"""
+
+
+# pylint: disable=protected-access
+class SmartTestFilterUnittests(fake_filesystem_unittest.TestCase):
+  """Unit tests for smart_test_filter.py."""
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+
+    self.fake_lookup_table_path = str(
+        pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+        / 'lookup_tables/tests_with_runtime_and_pass_rate.csv'
+    )
+    self.fs.create_file(
+        self.fake_lookup_table_path,
+        contents=_FAKE_LOOKUP_TABLE_CONTENT,
+    )
+    self.fake_blocklist_path = str(
+        pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+        / 'lookup_tables/blocklist.csv'
+    )
+    self.fs.create_file(
+        self.fake_blocklist_path,
+        contents=_FAKE_BLOCKLIST_CONTENT,
+    )
+
+  def test_get_selected_test_classes(self):
+    candidate_tests = [
+        # TestA is selected and ranked first, because it has the highest
+        # relevance score.
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass',
+            score=1,
+        ),
+        # This test is not selected because it is blocked.
+        smart_test_filter.TestClassInfo(
+            test_id='blocked_id',
+            atp_test_name='SomeTest',
+            branch='some_branch',
+            target='some_target',
+            module='BlockedModule',
+            test_class='testClass',
+            score=1,
+        ),
+        # This test is not selected because of no history in the lookup table.
+        smart_test_filter.TestClassInfo(
+            test_id='id_not_found',
+            atp_test_name='SomeTest',
+            branch='some_branch',
+            target='some_target',
+            module='SomeTestModule',
+            test_class='testSomeClass',
+            score=0.98,
+        ),
+        # This test is not selected because the module name is missing.
+        smart_test_filter.TestClassInfo(
+            test_id='g_id',
+            atp_test_name='TestWithoutModule',
+            branch='some_branch2',
+            target='some_target2',
+            test_class='testClass',
+            score=1.0,
+        ),
+        # This test is not selected because the test class name is missing.
+        smart_test_filter.TestClassInfo(
+            test_id='h_id',
+            atp_test_name='TestWithoutTestClass',
+            branch='some_branch2',
+            target='some_target2',
+            module='TestWithoutTestClass',
+            score=0.99,
+        ),
+        # This test is not selected because the passing rate of this test class
+        # was only 0.90, less than the threshold 0.95.
+        smart_test_filter.TestClassInfo(
+            test_id='b_id',
+            atp_test_name='TestFlakyTest',
+            branch='some_branch2',
+            target='some_target2',
+            module='SomeTestModule',
+            test_class='testSomeClass',
+            score=0.99,
+        ),
+        # This test is not selected because the execution time history of this
+        # test is missing.
+        smart_test_filter.TestClassInfo(
+            test_id='c_id',
+            atp_test_name='TestRunTimeNotFound',
+            branch='some_branch3',
+            target='some_target3',
+            module='SomeTestModule',
+            test_class='testSomeClass',
+            score=0.995,
+        ),
+        # TestD is selected and ranked right after TestA, because it has the
+        # second highest relevance score.
+        smart_test_filter.TestClassInfo(
+            test_id='d_id',
+            atp_test_name='TestD',
+            branch='some_branch4',
+            target='some_target4',
+            module='TestDModule',
+            test_class='testDClass',
+            score=0.98,
+        ),
+        # After TestA, TestD, TestF and TestG are selected, selecting this test
+        # would result in exceeding the estimated execution time (in this test,
+        # the user specified the time limit to be one minute), so this test is
+        # not selected.
+        smart_test_filter.TestClassInfo(
+            test_id='e_id',
+            atp_test_name='TestNotSelectedDueToTimeLimit',
+            branch='some_branch5',
+            target='some_target5',
+            module='TestEModule',
+            test_class='testEClass',
+            score=0.95,
+        ),
+        # TestF is selected and ranked right after TestG, because it has the
+        # fourth highest relevance score.
+        smart_test_filter.TestClassInfo(
+            test_id='f_id',
+            atp_test_name='TestF',
+            branch='some_branch6',
+            target='some_target6',
+            module='testFModule',
+            test_class='testFClass',
+            score=0.96,
+        ),
+        # TestG is selected and ranked right after TestD, because it has the
+        # third highest relevance score of all valid tests.
+        smart_test_filter.TestClassInfo(
+            test_id='g_id',
+            atp_test_name='TestG',
+            branch='some_branch7',
+            target='some_target7',
+            module='TestGModule',
+            test_class='testGClass',
+            score=0.97,
+        ),
+        # When the decision of not selecting TestNotSelectedDueToTimeLimit was
+        # made, we no longer look into the details of other tests with even
+        # lower relevant scores, so this test is not selected.
+        smart_test_filter.TestClassInfo(
+            test_id='h_id',
+            atp_test_name='TestNotSelectedDueToTimeLimit2',
+            branch='some_branch8',
+            target='some_target8',
+            module='SomeTestModule',
+            test_class='testSomeClass',
+            score=0.949,
+        ),
+    ]
+    expected_selected_tests = [
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='d_id',
+            atp_test_name='TestD',
+            branch='some_branch4',
+            target='some_target4',
+            module='TestDModule',
+            test_class='testDClass',
+            score=0.98,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='g_id',
+            atp_test_name='TestG',
+            branch='some_branch7',
+            target='some_target7',
+            module='TestGModule',
+            test_class='testGClass',
+            score=0.97,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='f_id',
+            atp_test_name='TestF',
+            branch='some_branch6',
+            target='some_target6',
+            module='testFModule',
+            test_class='testFClass',
+            score=0.96,
+        ),
+    ]
+
+    actual_selected_tests = smart_test_filter.get_selected_test_classes(
+        candidate_tests,
+        time_limit_min=1,
+    )
+
+    # Since this function guarantees order, so directly use `assertEqual`
+    # instead of `assertCountEqual`.
+    self.assertEqual(actual_selected_tests, expected_selected_tests)
+
+  def test_get_selected_test_classes_with_very_small_time_limit(self):
+    candidate_tests = [
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='d_id',
+            atp_test_name='TestD',
+            branch='some_branch4',
+            target='some_target4',
+            module='TestDModule',
+            test_class='testDClass',
+            score=0.98,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='e_id',
+            atp_test_name='TestNotSelectedDueToTimeLimit',
+            branch='some_branch5',
+            target='some_target5',
+            module='TestEModule',
+            test_class='testEClass',
+            score=0.95,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='f_id',
+            atp_test_name='TestF',
+            branch='some_branch6',
+            target='some_target6',
+            module='testFModule',
+            test_class='testFClass',
+            score=0.96,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='g_id',
+            atp_test_name='TestG',
+            branch='some_branch7',
+            target='some_target7',
+            module='TestGModule',
+            test_class='testGClass',
+            score=0.97,
+        ),
+    ]
+    expected_selected_tests = [
+        smart_test_filter.TestClassInfo(
+            test_id='g_id',
+            atp_test_name='TestG',
+            branch='some_branch7',
+            target='some_target7',
+            module='TestGModule',
+            test_class='testGClass',
+            score=0.97,
+        ),
+    ]
+
+    actual_selected_tests = smart_test_filter.get_selected_test_classes(
+        candidate_tests,
+        time_limit_min=0.0001,  # 6 ms
+    )
+
+    self.assertEqual(actual_selected_tests, expected_selected_tests)
+
+  def test_get_selected_test_classes_selected_test_is_stable(self):
+    candidate_tests = [
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestBModule',
+            test_class='testAClass0',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass3',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass2',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass1',
+            score=1,
+        ),
+    ]
+    expected_selected_tests = [
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass1',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass2',
+            score=1,
+        ),
+        smart_test_filter.TestClassInfo(
+            test_id='a_id',
+            atp_test_name='TestA',
+            branch='some_branch',
+            target='some_target',
+            module='TestAModule',
+            test_class='testAClass3',
+            score=1,
+        ),
+    ]
+
+    actual_selected_tests = smart_test_filter.get_selected_test_classes(
+        candidate_tests,
+        time_limit_min=0.6,
+    )
+
+    # Since this function guarantees order, so directly use `assertEqual`
+    # instead of `assertCountEqual`.
+    self.assertEqual(actual_selected_tests, expected_selected_tests)
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/test_finders/smart_test_finder/smart_test_finder.py b/atest/test_finders/smart_test_finder/smart_test_finder.py
new file mode 100644
index 00000000..d3101be3
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/smart_test_finder.py
@@ -0,0 +1,226 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""The top-most module to automatically select tests based on local change infos."""
+
+import logging
+import os
+import pathlib
+from typing import List
+from atest import atest_utils
+from atest import constants
+from atest import module_info
+from atest.test_finders import test_finder_utils
+from atest.test_finders import test_info
+from atest.test_finders.smart_test_finder import atp_test_selector
+from atest.test_finders.smart_test_finder import local_info_collector
+from atest.test_finders.smart_test_finder import smart_test_filter
+from atest.test_finders.smart_test_finder import test_relevance_client
+
+
+# TODO(b/412399270): Remove this constant when the issue is fixed.
+# Custom args for smart test selection
+SMART_TEST_SELECTION_CUSTOM_ARGS = [
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:shell-timeout:600000',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:test-timeout:600000',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.FlakyTest',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.support.test.filters.FlakyTest',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.test.FlakyTest',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:androidx.test.filters.FlakyTest',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:org.junit.Ignore',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.support.test.filters.RequiresDevice',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:androidx.test.filters.RequiresDevice',
+    '--test-arg',
+    'com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.RequiresDevice',
+    '--test-arg',
+    'com.android.compatibility.testtype.LibcoreTest:exclude-annotation:android.support.test.filters.RequiresDevice',
+    '--test-arg',
+    'com.android.compatibility.testtype.LibcoreTest:exclude-annotation:androidx.test.filters.RequiresDevice',
+    '--test-arg',
+    'com.android.compatibility.testtype.LibcoreTest:exclude-annotation:android.platform.test.annotations.RequiresDevice',
+    '--test-arg',
+    'com.android.tradefed.testtype.HostTest:exclude-annotation:android.platform.test.annotations.RequiresDevice',
+    '--test-arg',
+    'com.android.compatibility.common.tradefed.testtype.JarHostTest:exclude-annotation:android.platform.test.annotations.RequiresDevice',
+    '--exclude-filter',
+    (
+        "'CtsAppSecurityHostTestCases\\"
+        " android.appsecurity.cts.ExternalStorageHostTest#testMediaLegacy28'"
+    ),
+    '--exclude-filter',
+    (
+        "'CtsQuickAccessWalletTestCases\\"
+        " android.quickaccesswallet.cts.QuickAccessWalletClientTest#testAddListener_sendEvent_success'"
+    ),
+    '--exclude-filter',
+    (
+        "'CtsGraphicsTestCases\\"
+        " android.graphics.cts.FrameRateOverrideTest#testAppBackpressure'"
+    ),
+]
+
+
+def _get_selected_host_unit_tests(
+    mod_info: module_info.ModuleInfo, root_dir: str
+) -> List[str]:
+  """Return host unit tests under the root directory."""
+  if not (mod_info and root_dir):
+    atest_utils.print_and_log_warning(
+        'Missing module info or root directory, skip host unit tests searching.'
+    )
+    return []
+  return test_finder_utils.find_host_unit_tests(
+      mod_info, str(pathlib.Path(os.getcwd()).relative_to(root_dir))
+  )
+
+
+def _get_selected_tests_with_relevance_scores(
+    time_limit_in_minutes: int,
+) -> tuple[List[str], List[float]]:
+  """Gets score based tests with their scores."""
+  local_change_info = local_info_collector.get_local_change_info()
+  logging.info('Local change info: %s', local_change_info)
+  if not local_change_info.changed_files:
+    atest_utils.print_and_log_warning(
+        'No local change detected, skip relevance score based tests searching.'
+    )
+    return ([], [])
+
+  selected_atp_tests = atp_test_selector.get_selected_atp_tests(
+      local_change_info
+  )
+  logging.info('Selected ATP tests: %s', selected_atp_tests)
+  if not selected_atp_tests:
+    atest_utils.print_and_log_warning(
+        'No ATP tests selected, skip relevance score based tests searching.'
+    )
+    return ([], [])
+
+  atest_utils.colorful_print(
+      'Retrieving relevant tests, this may take a few minutes...',
+      constants.MAGENTA,
+  )
+  client = test_relevance_client.TestRelevanceClient()
+  dg_outputs = client.get_tests_with_relevance_score_query_by_query(
+      local_change_info, selected_atp_tests
+  )
+  logging.debug('DG_outputs: %s', dg_outputs)
+
+  if not dg_outputs:
+    atest_utils.print_and_log_warning(
+        'No relevant tests found, skip relevance score based tests searching.'
+    )
+    return ([], [])
+
+  candidate_test_classes = []
+  for dg_output in dg_outputs:
+    test_classes = (
+        test_relevance_client.get_test_class_infos_from_decision_graph_output(
+            dg_output
+        )
+    )
+    candidate_test_classes.extend(test_classes)
+
+  selected_test_classes = smart_test_filter.get_selected_test_classes(
+      candidate_test_classes, time_limit_in_minutes
+  )
+
+  if not selected_test_classes:
+    return ([], [])
+
+  tests = []
+  test_scores = []
+  for selected_test_class in selected_test_classes:
+    # Remove this once b/411508650 is fixed.
+    if selected_test_class.module.startswith('art-run-test'):
+      selected_test_class_str = selected_test_class.module
+    else:
+      # Special handling due to b/414872096
+      split_class_name = selected_test_class.test_class.split('.')
+      if (
+          len(split_class_name) == 2
+          and split_class_name[0] == selected_test_class.module
+      ):
+        selected_test_class_str = (
+            f'{selected_test_class.module}:{split_class_name[1]}'
+        )
+      else:
+        selected_test_class_str = (
+            f'{selected_test_class.module}:{selected_test_class.test_class}'
+        )
+    tests.append(selected_test_class_str)
+    test_scores.append(selected_test_class.score)
+  return (tests, test_scores)
+
+
+def _print_selected_tests(
+    host_unit_tests: List[str],
+    relevance_score_based_tests: List[str],
+    relevance_scores: List[float],
+):
+  """Print selected tests."""
+  atest_utils.colorful_print('\nSelected tests to run:', constants.CYAN)
+  if host_unit_tests:
+    atest_utils.colorful_print('\nHost unit tests:', constants.CYAN)
+    for host_test in host_unit_tests:
+      atest_utils.colorful_print(f'\t{host_test}', constants.CYAN)
+
+  if relevance_score_based_tests:
+    atest_utils.colorful_print(
+        '\nTests based on relevance scores:', constants.CYAN
+    )
+    for test, score in zip(relevance_score_based_tests, relevance_scores):
+      atest_utils.colorful_print(
+          f'\t{test}:{score}',
+          constants.CYAN,
+      )
+
+
+def get_smartly_selected_tests(
+    time_limit_in_minutes: int = constants.SMART_TEST_EXECUTION_TIME_LIMIT_IN_MINUTES,
+    include_host_unit_tests: bool = True,
+    mod_info: module_info.ModuleInfo = None,
+    root_dir: str = None,
+) -> List[test_info.TestInfo]:
+  """Given a time limit, smartly select tests to run."""
+  host_unit_tests = (
+      _get_selected_host_unit_tests(mod_info, root_dir)
+      if include_host_unit_tests
+      else []
+  )
+  score_based_tests_with_scores = _get_selected_tests_with_relevance_scores(
+      time_limit_in_minutes
+  )
+
+  if host_unit_tests or score_based_tests_with_scores[0]:
+    _print_selected_tests(
+        host_unit_tests,
+        score_based_tests_with_scores[0],
+        score_based_tests_with_scores[1],
+    )
+  else:
+    atest_utils.print_and_log_warning('No tests selected, exiting...')
+
+  return host_unit_tests + score_based_tests_with_scores[0]
diff --git a/atest/test_finders/smart_test_finder/smart_test_finder_unittest.py b/atest/test_finders/smart_test_finder/smart_test_finder_unittest.py
new file mode 100644
index 00000000..1da121a1
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/smart_test_finder_unittest.py
@@ -0,0 +1,408 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Unittests for smart_test_finder."""
+
+# pylint: disable=invalid-name
+
+import pathlib
+import unittest
+from unittest import mock
+from atest import atest_utils
+from atest import constants
+from atest import unittest_constants
+from atest.proto import decision_graph_pb2
+from atest.test_finders import test_finder_utils
+from atest.test_finders.smart_test_finder import atp_test_selector
+from atest.test_finders.smart_test_finder import local_info_collector
+from atest.test_finders.smart_test_finder import smart_test_filter
+from atest.test_finders.smart_test_finder import smart_test_finder
+from atest.test_finders.smart_test_finder import test_relevance_client
+from google.protobuf import json_format
+from pyfakefs import fake_filesystem_unittest
+
+_FAKE_BLOCKLIST_CONTENT = """module,reason
+BlockedModule, test_reaon"""
+
+_FAKE_LOOKUP_TABLE_CONTENT = """branch,target,test_name,test_id,postsubmit_pass_rate,test_run_duration_ms_past7days
+some_branch,some_target,TestA,a_id,0.99,10000
+some_branch2,some_target2,TestFlakyTest,b_id,0.90,500
+some_branch3,some_target3,TestRunTimeNotFound,c_id,0.99,-1
+some_branch4,some_target4,TestD,d_id,0.99,40000
+some_branch6,some_target6,TestF,f_id,0.99,500
+some_branch7,some_target7,TestG,g_id,0.98,5
+some_branch5,some_target5,TestNotSelectedDueToTimeLimit,e_id,0.99,20000
+some_branch8,some_target8,TestNotSelectedDueToTimeLimit2,h_id,0.98,5
+some_branch2,some_target2,TestWithoutModule,j_id,0.99,500
+some_branch2,some_target2,TestWithoutTestClass,k_id,0.99,500"""
+
+_FAKE_CHANGED_FILE_DETAILS = frozenset([
+    atest_utils.ChangedFileDetails(
+        filename='/a/b/c',
+        number_of_lines_inserted=14,
+        number_of_lines_deleted=25,
+    ),
+    atest_utils.ChangedFileDetails(
+        filename='/d/e/f',
+        number_of_lines_inserted=36,
+        number_of_lines_deleted=47,
+    ),
+])
+_FAKE_CHANGE_INFO = local_info_collector.ChangeInfo(
+    project='fake_project',
+    branch='fake_branch',
+    remote_hostname='stuff-to-be-selected',
+    changed_files=_FAKE_CHANGED_FILE_DETAILS,
+    user_key='fake_user',
+)
+_FAKE_SELECTED_TESTS = [
+    atp_test_selector.AtpTestInfo(
+        name='v2/android-virtual-infra/test_mapping/presubmit-avd',
+        target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+        branch='some_aosp-branch2',
+    ),
+    atp_test_selector.AtpTestInfo(
+        name='v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation',
+        target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+        branch='some_aosp-branch2',
+    ),
+]
+
+
+def _get_decision_graph_check(
+    info: smart_test_filter.TestClassInfo,
+) -> decision_graph_pb2.Check:
+  ants_test = decision_graph_pb2.AnTSTest(
+      test_identifier=decision_graph_pb2.TestIdentifier(
+          module=info.module,
+          test_class=info.test_class,
+      ),
+      test_identifier_id=info.test_id,
+  )
+  check_reason = decision_graph_pb2.Check.Reason(relevance_score=info.score)
+  return decision_graph_pb2.Check(
+      identifier=decision_graph_pb2.Check.Identifier(
+          ants_test=ants_test,
+      ),
+      reason=check_reason,
+  )
+
+
+# pylint: disable=protected-access
+class SmartTestFinderFilmsystemUnittests(fake_filesystem_unittest.TestCase):
+  """Unit tests for smart_test_finder.py with filesystem access."""
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+
+    self.fake_lookup_table_path = str(
+        pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+        / 'lookup_tables/tests_with_runtime_and_pass_rate.csv'
+    )
+    self.fs.create_file(
+        self.fake_lookup_table_path,
+        contents=_FAKE_LOOKUP_TABLE_CONTENT,
+    )
+    self.fake_blocklist_path = str(
+        pathlib.Path(constants.SMART_TEST_SELECTION_ROOT_PATH)
+        / 'lookup_tables/blocklist.csv'
+    )
+    self.fs.create_file(
+        self.fake_blocklist_path,
+        contents=_FAKE_BLOCKLIST_CONTENT,
+    )
+
+  # TODO(b/410945183): Change this test once the bug is fixed.
+  @mock.patch('uuid.uuid4', side_effect=['001-002-003', '002-003-004'])
+  @mock.patch.object(
+      atp_test_selector,
+      'get_selected_atp_tests',
+      return_value=_FAKE_SELECTED_TESTS,
+  )
+  @mock.patch.object(
+      local_info_collector,
+      'get_local_change_info',
+      return_value=_FAKE_CHANGE_INFO,
+  )
+  @mock.patch.object(test_relevance_client, 'TestRelevanceClient')
+  def test_get_smartly_selected_tests(self, mock_client_class, _, __, ___):
+    checks = [
+        # TestA is selected and ranked first, because it has the highest
+        # relevance score.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='a_id',
+                atp_test_name='TestA',
+                branch='some_branch',
+                target='some_target',
+                module='TestAModule',
+                test_class='testAClass',
+                score=1,
+            )
+        ),
+        # This test is not selected because it is blocked.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='blocked_id',
+                atp_test_name='SomeTest',
+                branch='some_branch',
+                target='some_target',
+                module='BlockedModule',
+                test_class='testClass',
+                score=1,
+            )
+        ),
+        # This test is not selected because of no history in the lookup table.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='id_not_found',
+                atp_test_name='SomeTest',
+                branch='some_branch',
+                target='some_target',
+                module='SomeTestModule',
+                test_class='testSomeClass',
+                score=0.98,
+            )
+        ),
+        # This test is not selected because the module name is missing.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='g_id',
+                atp_test_name='TestWithoutModule',
+                branch='some_branch2',
+                target='some_target2',
+                test_class='testClass',
+                score=1.0,
+            )
+        ),
+        # This test is not selected because the test class name is missing.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='h_id',
+                atp_test_name='TestWithoutTestClass',
+                branch='some_branch2',
+                target='some_target2',
+                module='TestWithoutTestClass',
+                score=0.99,
+            )
+        ),
+        # This test is not selected because the passing rate of this test class
+        # was only 0.90, less than the threshold 0.95.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='b_id',
+                atp_test_name='TestFlakyTest',
+                branch='some_branch2',
+                target='some_target2',
+                module='SomeTestModule',
+                test_class='testSomeClass',
+                score=0.99,
+            )
+        ),
+        # This test is not selected because the execution time history of this
+        # test is missing.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='c_id',
+                atp_test_name='TestRunTimeNotFound',
+                branch='some_branch3',
+                target='some_target3',
+                module='SomeTestModule',
+                test_class='testSomeClass',
+                score=0.995,
+            )
+        ),
+        # TestD is selected and ranked right after TestA, because it has the
+        # second highest relevance score.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='d_id',
+                atp_test_name='TestD',
+                branch='some_branch4',
+                target='some_target4',
+                module='TestDModule',
+                test_class='testDClass',
+                score=0.98,
+            )
+        ),
+        # After TestA, TestD, TestF and TestG are selected, selecting this test
+        # would result in exceeding the estimated execution time (in this test,
+        # the user specified the time limit to be one minute), so this test is
+        # not selected.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='e_id',
+                atp_test_name='TestNotSelectedDueToTimeLimit',
+                branch='some_branch5',
+                target='some_target5',
+                module='TestEModule',
+                test_class='testEClass',
+                score=0.95,
+            )
+        ),
+        # TestF is selected and ranked right after TestG, because it has the
+        # fourth highest relevance score.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='f_id',
+                atp_test_name='TestF',
+                branch='some_branch6',
+                target='some_target6',
+                module='TestFModule',
+                test_class='TestFModule.TestFClass',
+                score=0.96,
+            )
+        ),
+        # TestG is selected and ranked right after TestD, because it has the
+        # third highest relevance score of all valid tests.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='g_id',
+                atp_test_name='TestG',
+                branch='some_branch7',
+                target='some_target7',
+                module='TestGModule',
+                test_class='testGClass',
+                score=0.97,
+            )
+        ),
+        # When the decision of not selecting TestNotSelectedDueToTimeLimit was
+        # made, we no longer look into the details of other tests with even
+        # lower relevant scores, so this test is not selected.
+        _get_decision_graph_check(
+            smart_test_filter.TestClassInfo(
+                test_id='h_id',
+                atp_test_name='TestNotSelectedDueToTimeLimit2',
+                branch='some_branch8',
+                target='some_target8',
+                module='SomeTestModule',
+                test_class='testSomeClass',
+                score=0.949,
+            )
+        ),
+    ]
+    dg_outputs = []
+    for check in checks:
+      dg_output = json_format.MessageToDict(
+          decision_graph_pb2.DecisionGraphOutput(
+              outputs=[decision_graph_pb2.StageOutput(checks=[check])],
+          )
+      )
+      dg_outputs.append(dg_output)
+    mock_client = mock_client_class.return_value
+    mock_client.get_tests_with_relevance_score_query_by_query.return_value = (
+        dg_outputs
+    )
+
+    final_selected_tests = smart_test_finder.get_smartly_selected_tests(
+        time_limit_in_minutes=1,
+    )
+
+    self.assertEqual(
+        final_selected_tests,
+        [
+            'TestAModule:testAClass',
+            'TestDModule:testDClass',
+            'TestGModule:testGClass',
+            'TestFModule:TestFClass',
+        ],
+    )
+
+  @mock.patch.object(atp_test_selector, 'get_selected_atp_tests')
+  @mock.patch.object(local_info_collector, 'get_local_change_info')
+  @mock.patch.object(test_relevance_client, 'TestRelevanceClient')
+  def test_get_smartly_selected_tests_return_no_tests_if_api_broken(
+      self, mock_client_class, _, __
+  ):
+    mock_client = mock_client_class.return_value
+    mock_client.get_tests_with_relevance_score_query_by_query.side_effect = (
+        TimeoutError()
+    )
+    with self.assertRaises(TimeoutError):
+      smart_test_finder.get_smartly_selected_tests()
+
+  @mock.patch.object(local_info_collector, 'get_local_change_info')
+  def test_get_smartly_selected_tests_return_no_tests_with_no_changes(
+      self, mock_local_info_collector
+  ):
+    CHANGE_INFO_WITH_NO_CHANGED_FILES = local_info_collector.ChangeInfo(
+        project='fake_project',
+        branch='fake_branch',
+        remote_hostname='stuff-to-be-selected',
+        changed_files=[],
+        user_key='fake_user',
+    )
+    mock_local_info_collector.return_value = CHANGE_INFO_WITH_NO_CHANGED_FILES
+    results = smart_test_finder.get_smartly_selected_tests()
+    self.assertEqual(results, [])
+
+  @mock.patch.object(
+      test_finder_utils,
+      'find_host_unit_tests',
+      return_value=[
+          unittest_constants.CLASS_NAME,
+          unittest_constants.MODULE2_NAME,
+      ],
+  )
+  @mock.patch('os.getcwd', return_value='/my/main/some/project')
+  @mock.patch.object(local_info_collector, 'get_local_change_info')
+  def test_get_smartly_selected_tests_return_host_unit_tests_but_no_relevance_score_based_tests(
+      self, mock_local_info_collector, _, __
+  ):
+    CHANGE_INFO_WITH_NO_CHANGED_FILES = local_info_collector.ChangeInfo(
+        project='fake_project',
+        branch='fake_branch',
+        remote_hostname='stuff-to-be-selected',
+        changed_files=[],
+        user_key='fake_user',
+    )
+    mock_local_info_collector.return_value = CHANGE_INFO_WITH_NO_CHANGED_FILES
+
+    results = smart_test_finder.get_smartly_selected_tests(
+        mod_info=unittest_constants.MODULE_INFO, root_dir='/my/main'
+    )
+
+    self.assertCountEqual(
+        results,
+        [unittest_constants.CLASS_NAME, unittest_constants.MODULE2_NAME],
+    )
+
+  @mock.patch.object(local_info_collector, 'get_local_change_info')
+  def test_get_smartly_selected_tests_return_no_host_unit_tests_per_user_specification(
+      self,
+      mock_local_info_collector,
+  ):
+    CHANGE_INFO_WITH_NO_CHANGED_FILES = local_info_collector.ChangeInfo(
+        project='fake_project',
+        branch='fake_branch',
+        remote_hostname='stuff-to-be-selected',
+        changed_files=[],
+        user_key='fake_user',
+    )
+    mock_local_info_collector.return_value = CHANGE_INFO_WITH_NO_CHANGED_FILES
+
+    results = smart_test_finder.get_smartly_selected_tests(
+        include_host_unit_tests=False,
+        mod_info=unittest_constants.MODULE_INFO,
+        root_dir='/my/main',
+    )
+
+    self.assertEqual(results, [])
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/test_finders/smart_test_finder/test_relevance_client.py b/atest/test_finders/smart_test_finder/test_relevance_client.py
new file mode 100644
index 00000000..8856175c
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/test_relevance_client.py
@@ -0,0 +1,292 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+"""Provides classes and utils to invoke test relevance API for relevance score calculation."""
+
+import json
+import logging
+import time
+from typing import Any
+from typing import Dict
+from typing import List
+import uuid
+from atest import atest_utils
+from atest.proto import common_pb2
+from atest.proto import decision_graph_pb2
+from atest.test_finders.smart_test_finder import atp_test_selector
+from atest.test_finders.smart_test_finder import local_info_collector
+from atest.test_finders.smart_test_finder import smart_test_filter
+from google.protobuf import json_format
+from googleapiclient.discovery import build
+from googleapiclient.errors import HttpError
+import httplib2
+
+
+_DEFAULT_MAX_TIMEOUT = 300
+_STAGE_ID_FOR_SMART_TEST_SELECTION = 'local_smart_test_selection'
+_STAGE_NAME_FOR_SMART_TEST_SELECTION = (
+    f'{_STAGE_ID_FOR_SMART_TEST_SELECTION}_stage'
+)
+_DISCOVERY_SERVICE_URL = (
+    'https://decisiongraph-pa.googleapis.com/$discovery/rest?version=v1'
+)
+_STAGE_NODE = decision_graph_pb2.StageNode(
+    stage=decision_graph_pb2.Stage(
+        id=_STAGE_ID_FOR_SMART_TEST_SELECTION,
+        name=_STAGE_NAME_FOR_SMART_TEST_SELECTION,
+    ),
+    execution_options=decision_graph_pb2.StageNode.ExecutionOptions(
+        location=1,
+        address='blade:moneyball-test-relevance-prod',
+        prepare=False,
+        max_duration=common_pb2.Duration(seconds=_DEFAULT_MAX_TIMEOUT),
+        blocking=1,
+    ),
+)
+
+
+def _get_decision_graph_checks(
+    tests: List[atp_test_selector.AtpTestInfo],
+) -> List[decision_graph_pb2.Check]:
+  """Get decision graph checks including selected test infos."""
+  checks = []
+  for test in tests:
+    check = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            id=str(uuid.uuid4()),
+            ants_test=decision_graph_pb2.AnTSTest(
+                build_descriptor=decision_graph_pb2.BuildDescriptor(
+                    branch=test.branch, build_target=test.target
+                ),
+                test_definition=decision_graph_pb2.TestDefinition(
+                    name=test.name
+                ),
+            ),
+        )
+    )
+    checks.append(check)
+  return checks
+
+
+def _get_private_context(
+    change_info: local_info_collector.ChangeInfo,
+) -> decision_graph_pb2.Stage.PrivateContext:
+  """Get private context containing local change info."""
+  private_context = decision_graph_pb2.Stage.PrivateContext(
+      changes=[
+          decision_graph_pb2.Change(
+              host=change_info.remote_hostname,
+              project=change_info.project,
+              branch=change_info.branch,
+              owner=decision_graph_pb2.User(
+                  account_id=1, name=change_info.user_key
+              ),
+          )
+      ]
+  )
+
+  revisions = []
+  for file in change_info.changed_files:
+    revision = decision_graph_pb2.Revision(
+        file_info=[
+            decision_graph_pb2.FileInfo(
+                path=file.filename,
+                lines_inserted=file.number_of_lines_inserted,
+                lines_deleted=file.number_of_lines_deleted,
+            )
+        ]
+    )
+    revisions.append(revision)
+  private_context.changes[0].revisions.extend(revisions)
+
+  return private_context
+
+
+def create_query(
+    change_info: local_info_collector.ChangeInfo,
+    tests: List[atp_test_selector.AtpTestInfo],
+):
+  """Create a query for the relevance score between selected tests and local change info."""
+  dg_input = decision_graph_pb2.DecisionGraphInput(
+      input=[
+          decision_graph_pb2.StageInput(
+              stage=decision_graph_pb2.Stage(
+                  id=_STAGE_ID_FOR_SMART_TEST_SELECTION,
+                  name=_STAGE_NAME_FOR_SMART_TEST_SELECTION,
+              ),
+              input=[
+                  decision_graph_pb2.StageOutput(
+                      checks=_get_decision_graph_checks(tests),
+                      private_context=_get_private_context(change_info),
+                  )
+              ],
+          )
+      ]
+  )
+  dg_input.graph.name = 'smart_test_selection_graph'
+  dg_input.graph.stages.extend([_STAGE_NODE])
+
+  json_query = json_format.MessageToJson(dg_input)
+  return json_query
+
+
+# TODO(b/410945183): Remove this function once the bug is fixed.
+def create_queries(
+    change_info: local_info_collector.ChangeInfo,
+    tests: List[atp_test_selector.AtpTestInfo],
+) -> List[str]:
+  """Create queries for the relevance score between selected tests and local change info."""
+  dg_checks = _get_decision_graph_checks(tests)
+  queries = []
+
+  for dg_check in dg_checks:
+    dg_input = decision_graph_pb2.DecisionGraphInput(
+        input=[
+            decision_graph_pb2.StageInput(
+                stage=decision_graph_pb2.Stage(
+                    id=_STAGE_ID_FOR_SMART_TEST_SELECTION,
+                    name=_STAGE_NAME_FOR_SMART_TEST_SELECTION,
+                ),
+                input=[
+                    decision_graph_pb2.StageOutput(
+                        checks=[dg_check],
+                        private_context=_get_private_context(change_info),
+                    )
+                ],
+            )
+        ]
+    )
+    dg_input.graph.name = 'smart_test_selection_graph'
+    dg_input.graph.stages.extend([_STAGE_NODE])
+    queries.append(json_format.MessageToJson(dg_input))
+
+  return queries
+
+
+class TestRelevanceClient:
+  """The client to calculate test relevance scores."""
+
+  def __init__(self, max_retry_count=5):
+    """Init BuildClient class."""
+    self._max_retry_count = max_retry_count
+    try:
+      with open(atp_test_selector._get_constants_path(), 'r') as file:
+        data = json.load(file)
+        developer_key = data['developer_key']
+        http = httplib2.Http(timeout=_DEFAULT_MAX_TIMEOUT)
+        self.client = build(
+            serviceName='decisiongraph-pa',
+            version='v1',
+            cache_discovery=False,
+            discoveryServiceUrl=_DISCOVERY_SERVICE_URL,
+            http=http,
+            developerKey=developer_key,
+        )
+    except (FileNotFoundError, HttpError) as err:
+      atest_utils.print_and_log_error(
+          'Error occurred during smart test selection: %s', err
+      )
+
+  # def get_tests_with_relevance_score(
+  #     self,
+  #     change_info: local_info_collector.ChangeInfo,
+  #     atp_tests: List[atp_test_selector.AtpTestInfo],
+  # ) -> Dict[str, Any]:
+  #   """Get test classes with relevance scores."""
+  #   query = create_query(change_info, atp_tests)
+  #   logging.info(query)
+  #   return self.client.v1().rundecisiongraph(body=json.loads(query)).execute()
+
+  # TODO(b/410945183): Replace this function with the one above once the bug is
+  # fixed.
+  def get_tests_with_relevance_score_query_by_query(
+      self,
+      change_info: local_info_collector.ChangeInfo,
+      atp_tests: List[atp_test_selector.AtpTestInfo],
+  ) -> List[Dict[str, Any]]:
+    """Get test classes with relevance scores query by query."""
+    for try_id in range(self._max_retry_count + 1):
+      try:
+        dg_outputs = []
+        for query in create_queries(change_info, atp_tests):
+          logging.info(query)
+          dg_outputs.append(
+              self.client.v1()
+              .rundecisiongraph(body=json.loads(query))
+              .execute()
+          )
+        return dg_outputs
+      # pylint: disable=broad-exception-caught
+      # `RpcError` is not accessible in Android.
+      except Exception as err:
+        if try_id < self._max_retry_count:
+          seconds_to_be_waited = 2**try_id
+          atest_utils.print_and_log_warning(
+              'Error occurred when querying test relevance API: %s, will retry'
+              ' after %s seconds',
+              err,
+              seconds_to_be_waited,
+          )
+          time.sleep(seconds_to_be_waited)
+        else:
+          atest_utils.print_and_log_warning(
+              'Error occurred when querying test relevance API: %s',
+              err,
+          )
+          return []
+
+
+def get_test_class_infos_from_decision_graph_output(
+    dg_output: Dict[str, Any],
+) -> List[smart_test_filter.TestClassInfo]:
+  """Convert decision graph output to test class infos."""
+  if not dg_output:
+    return []
+
+  test_classes = []
+  for stage_output in dg_output.get('outputs', []):
+    errors = stage_output.get('errors')
+    if errors:
+      atest_utils.print_and_log_warning(
+          'Errors returned from test relevance API output: %s', errors
+      )
+      return []
+    for check in stage_output.get('checks', []):
+      check_identifier = check.get('identifier')
+      if not check_identifier:
+        continue
+      ants_test = check_identifier.get('antsTest')
+      if not ants_test:
+        continue
+      test_id = ants_test.get('testIdentifierId')
+      if not test_id:
+        continue
+
+      test_identifier = ants_test.get('testIdentifier')
+      if not test_identifier:
+        continue
+      module = test_identifier.get('module', '')
+      test_class = test_identifier.get('testClass', '')
+      score = check.get('reason', {}).get('relevanceScore', 0)
+      test_classes.append(
+          smart_test_filter.TestClassInfo(
+              test_id=test_id,
+              module=module,
+              test_class=test_class,
+              score=score,
+          )
+      )
+  return test_classes
diff --git a/atest/test_finders/smart_test_finder/test_relevance_client_unittest.py b/atest/test_finders/smart_test_finder/test_relevance_client_unittest.py
new file mode 100644
index 00000000..4a20d773
--- /dev/null
+++ b/atest/test_finders/smart_test_finder/test_relevance_client_unittest.py
@@ -0,0 +1,562 @@
+#!/usr/bin/env python3
+#
+# Copyright 2025, The Android Open Source Project
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
+#
+"""Unittests for test_relevance_client."""
+
+# pylint: disable=invalid-name
+
+import json
+import unittest
+from unittest import mock
+from atest import atest_utils
+from atest.proto import decision_graph_pb2
+from atest.test_finders.smart_test_finder import atp_test_selector
+from atest.test_finders.smart_test_finder import local_info_collector
+from atest.test_finders.smart_test_finder import smart_test_filter
+from atest.test_finders.smart_test_finder import test_relevance_client
+from google.protobuf import json_format
+
+
+_FAKE_CHANGED_FILE_DETAILS = [
+    atest_utils.ChangedFileDetails(
+        filename='/a/b/c',
+        number_of_lines_inserted=14,
+        number_of_lines_deleted=25,
+    ),
+    atest_utils.ChangedFileDetails(
+        filename='/d/e/f',
+        number_of_lines_inserted=36,
+        number_of_lines_deleted=47,
+    ),
+]
+_EXPECTED_QUERY = """{
+  "graph": {
+    "name": "smart_test_selection_graph",
+    "stages": [
+      {
+        "stage": {
+          "id": "local_smart_test_selection",
+          "name": "local_smart_test_selection_stage"
+        },
+        "executionOptions": {
+          "location": "GSLB",
+          "address": "blade:moneyball-test-relevance-prod",
+          "prepare": false,
+          "maxDuration": {
+            "seconds": "300"
+          },
+          "blocking": "BLOCKING"
+        }
+      }
+    ]
+  },
+  "input": [
+    {
+      "stage": {
+        "id": "local_smart_test_selection",
+        "name": "local_smart_test_selection_stage"
+      },
+      "input": [
+        {
+          "checks": [
+            {
+              "identifier": {
+                "id": "001-002-003",
+                "antsTest": {
+                  "buildDescriptor": {
+                    "branch": "some_aosp-branch2",
+                    "buildTarget": "aosp_cf_x86_64_phone-trunk_staging-userdebug"
+                  },
+                  "testDefinition": {
+                    "name": "v2/android-virtual-infra/test_mapping/presubmit-avd"
+                  }
+                }
+              }
+            },
+            {
+              "identifier": {
+                "id": "002-003-004",
+                "antsTest": {
+                  "buildDescriptor": {
+                    "branch": "some_aosp-branch2",
+                    "buildTarget": "aosp_cf_x86_64_phone-trunk_staging-userdebug"
+                  },
+                  "testDefinition": {
+                    "name": "v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation"
+                  }
+                }
+              }
+            }
+          ],
+          "privateContext": {
+            "changes": [
+              {
+                "host": "stuff-to-be-selected",
+                "project": "fake_project",
+                "branch": "fake_branch",
+                "revisions": [
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/a/b/c",
+                        "linesInserted": 14,
+                        "linesDeleted": 25
+                      }
+                    ]
+                  },
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/d/e/f",
+                        "linesInserted": 36,
+                        "linesDeleted": 47
+                      }
+                    ]
+                  }
+                ],
+                "owner": {
+                  "name": "fake_user",
+                  "accountId": "1"
+                }
+              }
+            ]
+          }
+        }
+      ]
+    }
+  ]
+}"""
+_EXPECTED_QUERY_WITH_SINGLE_CHECK1 = """{
+  "graph": {
+    "name": "smart_test_selection_graph",
+    "stages": [
+      {
+        "stage": {
+          "id": "local_smart_test_selection",
+          "name": "local_smart_test_selection_stage"
+        },
+        "executionOptions": {
+          "location": "GSLB",
+          "address": "blade:moneyball-test-relevance-prod",
+          "prepare": false,
+          "maxDuration": {
+            "seconds": "300"
+          },
+          "blocking": "BLOCKING"
+        }
+      }
+    ]
+  },
+  "input": [
+    {
+      "stage": {
+        "id": "local_smart_test_selection",
+        "name": "local_smart_test_selection_stage"
+      },
+      "input": [
+        {
+          "checks": [
+            {
+              "identifier": {
+                "id": "001-002-003",
+                "antsTest": {
+                  "buildDescriptor": {
+                    "branch": "some_aosp-branch2",
+                    "buildTarget": "aosp_cf_x86_64_phone-trunk_staging-userdebug"
+                  },
+                  "testDefinition": {
+                    "name": "v2/android-virtual-infra/test_mapping/presubmit-avd"
+                  }
+                }
+              }
+            }
+          ],
+          "privateContext": {
+            "changes": [
+              {
+                "host": "stuff-to-be-selected",
+                "project": "fake_project",
+                "branch": "fake_branch",
+                "revisions": [
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/a/b/c",
+                        "linesInserted": 14,
+                        "linesDeleted": 25
+                      }
+                    ]
+                  },
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/d/e/f",
+                        "linesInserted": 36,
+                        "linesDeleted": 47
+                      }
+                    ]
+                  }
+                ],
+                "owner": {
+                  "name": "fake_user",
+                  "accountId": "1"
+                }
+              }
+            ]
+          }
+        }
+      ]
+    }
+  ]
+}"""
+_EXPECTED_QUERY_WITH_SINGLE_CHECK2 = """{
+  "graph": {
+    "name": "smart_test_selection_graph",
+    "stages": [
+      {
+        "stage": {
+          "id": "local_smart_test_selection",
+          "name": "local_smart_test_selection_stage"
+        },
+        "executionOptions": {
+          "location": "GSLB",
+          "address": "blade:moneyball-test-relevance-prod",
+          "prepare": false,
+          "maxDuration": {
+            "seconds": "300"
+          },
+          "blocking": "BLOCKING"
+        }
+      }
+    ]
+  },
+  "input": [
+    {
+      "stage": {
+        "id": "local_smart_test_selection",
+        "name": "local_smart_test_selection_stage"
+      },
+      "input": [
+        {
+          "checks": [
+            {
+              "identifier": {
+                "id": "002-003-004",
+                "antsTest": {
+                  "buildDescriptor": {
+                    "branch": "some_aosp-branch2",
+                    "buildTarget": "aosp_cf_x86_64_phone-trunk_staging-userdebug"
+                  },
+                  "testDefinition": {
+                    "name": "v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation"
+                  }
+                }
+              }
+            }
+          ],
+          "privateContext": {
+            "changes": [
+              {
+                "host": "stuff-to-be-selected",
+                "project": "fake_project",
+                "branch": "fake_branch",
+                "revisions": [
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/a/b/c",
+                        "linesInserted": 14,
+                        "linesDeleted": 25
+                      }
+                    ]
+                  },
+                  {
+                    "fileInfo": [
+                      {
+                        "path": "/d/e/f",
+                        "linesInserted": 36,
+                        "linesDeleted": 47
+                      }
+                    ]
+                  }
+                ],
+                "owner": {
+                  "name": "fake_user",
+                  "accountId": "1"
+                }
+              }
+            ]
+          }
+        }
+      ]
+    }
+  ]
+}"""
+
+
+# pylint: disable=protected-access
+class TestRelevanceClientUnittests(unittest.TestCase):
+  """Unit tests for test_relevance_client.py."""
+
+  @mock.patch('uuid.uuid4', side_effect=['001-002-003', '002-003-004'])
+  def test_create_query(self, _):
+    fake_change_info = local_info_collector.ChangeInfo(
+        project='fake_project',
+        branch='fake_branch',
+        remote_hostname='stuff-to-be-selected',
+        changed_files=_FAKE_CHANGED_FILE_DETAILS,
+        user_key='fake_user',
+    )
+    fake_selected_tests = [
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-virtual-infra/test_mapping/presubmit-avd',
+            target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+            branch='some_aosp-branch2',
+        ),
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation',
+            target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+            branch='some_aosp-branch2',
+        ),
+    ]
+
+    query = test_relevance_client.create_query(
+        fake_change_info, fake_selected_tests
+    )
+
+    self.assertDictEqual(json.loads(query), json.loads(_EXPECTED_QUERY))
+
+  @mock.patch('uuid.uuid4', side_effect=['001-002-003', '002-003-004'])
+  def test_create_queries(self, _):
+    fake_change_info = local_info_collector.ChangeInfo(
+        project='fake_project',
+        branch='fake_branch',
+        remote_hostname='stuff-to-be-selected',
+        changed_files=_FAKE_CHANGED_FILE_DETAILS,
+        user_key='fake_user',
+    )
+    fake_selected_tests = [
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-virtual-infra/test_mapping/presubmit-avd',
+            target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+            branch='some_aosp-branch2',
+        ),
+        atp_test_selector.AtpTestInfo(
+            name='v2/android-test-harness-team/tradefed/host_unit_tests_zip_validation',
+            target='aosp_cf_x86_64_phone-trunk_staging-userdebug',
+            branch='some_aosp-branch2',
+        ),
+    ]
+
+    queries = test_relevance_client.create_queries(
+        fake_change_info, fake_selected_tests
+    )
+
+    self.assertDictEqual(
+        json.loads(queries[0]), json.loads(_EXPECTED_QUERY_WITH_SINGLE_CHECK1)
+    )
+    self.assertDictEqual(
+        json.loads(queries[1]), json.loads(_EXPECTED_QUERY_WITH_SINGLE_CHECK2)
+    )
+
+  def test_get_test_class_infos_from_decision_graph_output(self):
+    ants_test_input = decision_graph_pb2.AnTSTest(
+        aggregation_level=decision_graph_pb2.AggregationLevel.CLASS,
+        build_descriptor=decision_graph_pb2.BuildDescriptor(
+            branch='git_main',
+            build_target='cf-x86-64-some-target',
+        ),
+        test_definition=decision_graph_pb2.TestDefinition(
+            name='v2/some-atp-test/name',
+        ),
+    )
+    check_input = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            ants_test=ants_test_input,
+        ),
+    )
+    ants_test_output1 = decision_graph_pb2.AnTSTest(
+        test_identifier=decision_graph_pb2.TestIdentifier(
+            module='TestAModule',
+            test_class='AClassTest',
+        ),
+        test_identifier_id='id_1',
+    )
+    check_reason1 = decision_graph_pb2.Check.Reason(relevance_score=0.99)
+    check_output1 = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            ants_test=ants_test_output1,
+        ),
+        reason=check_reason1,
+    )
+    ants_test_output2 = decision_graph_pb2.AnTSTest(
+        test_identifier=decision_graph_pb2.TestIdentifier(
+            module='TestBModule',
+            test_class='BClassTest',
+            method='bMethod',
+        ),
+    )
+    check_reason2 = decision_graph_pb2.Check.Reason(relevance_score=0.37)
+    check_output2 = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            ants_test=ants_test_output2,
+        ),
+        reason=check_reason2,
+    )
+    dg_outputs = [
+        json_format.MessageToDict(
+            decision_graph_pb2.DecisionGraphOutput(
+                outputs=[
+                    decision_graph_pb2.StageOutput(
+                        checks=[check_input, check_output1, check_output2]
+                    )
+                ],
+            )
+        ),
+    ]
+    expected_test_class_infos = [
+        smart_test_filter.TestClassInfo(
+            test_id='id_1',
+            module='TestAModule',
+            test_class='AClassTest',
+            score=0.99,
+        ),
+    ]
+
+    test_class_infos = []
+    for dg_output in dg_outputs:
+      test_classes = (
+          test_relevance_client.get_test_class_infos_from_decision_graph_output(
+              dg_output
+          )
+      )
+      test_class_infos.extend(test_classes)
+
+    self.assertEqual(len(test_class_infos), len(expected_test_class_infos))
+    for i in range(len(test_class_infos)):
+      self.assertTestClassInfoAlmostEqual(
+          test_class_infos[i],
+          expected_test_class_infos[i],
+          tolerance=1e-6,
+      )
+
+  def test_get_test_class_infos_from_decision_graph_output_no_test_returned(
+      self,
+  ):
+    check_reason1 = decision_graph_pb2.Check.Reason(relevance_score=0.99)
+    check1 = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            id='id_1',
+        ),
+        reason=check_reason1,
+    )
+    check_reason2 = decision_graph_pb2.Check.Reason(relevance_score=0.37)
+    check2 = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            id='id_2',
+        ),
+        reason=check_reason2,
+    )
+    dg_output = json_format.MessageToDict(
+        decision_graph_pb2.DecisionGraphOutput(
+            outputs=[decision_graph_pb2.StageOutput(checks=[check1, check2])],
+        )
+    )
+
+    test_class_infos = (
+        test_relevance_client.get_test_class_infos_from_decision_graph_output(
+            dg_output
+        )
+    )
+
+    self.assertCountEqual(test_class_infos, [])
+
+  def test_get_test_class_infos_from_decision_graph_output_errors_returned(
+      self,
+  ):
+    check_reason = decision_graph_pb2.Check.Reason(relevance_score=0.99)
+    check = decision_graph_pb2.Check(
+        identifier=decision_graph_pb2.Check.Identifier(
+            id='id_1',
+        ),
+        reason=check_reason,
+    )
+    dg_output = json_format.MessageToDict(
+        decision_graph_pb2.DecisionGraphOutput(
+            outputs=[
+                decision_graph_pb2.StageOutput(
+                    checks=[check],
+                    errors=[
+                        decision_graph_pb2.Error(
+                            message='Query cancelled', rpc_error=1
+                        )
+                    ],
+                )
+            ],
+        )
+    )
+
+    test_class_infos = (
+        test_relevance_client.get_test_class_infos_from_decision_graph_output(
+            dg_output
+        )
+    )
+
+    self.assertCountEqual(test_class_infos, [])
+
+  def assertTestClassInfoAlmostEqual(self, info1, info2, tolerance) -> None:
+    """Assert test class infos equal within tolerance.
+
+    This function asserts the equality of two class infos. This indicates that
+    the relevance scores are within the specified tolerance, while all other
+    fields are equal.
+
+    Args:
+      info1: The first test class info.
+      info2: The second test class info.
+      tolerance: The maximum deviation allowed when comparing two floating-point
+        numbers.
+    """
+    self.assertAlmostEqual(info1.score, info2.score, delta=tolerance)
+
+    info1_without_score = smart_test_filter.TestClassInfo(
+        test_id=info1.test_id,
+        atp_test_name=info1.atp_test_name,
+        branch=info1.branch,
+        target=info1.target,
+        run_time=info1.run_time,
+        pass_rate=info1.pass_rate,
+        module=info1.module,
+        test_class=info1.test_class,
+        score=None,
+    )
+    info2_without_score = smart_test_filter.TestClassInfo(
+        test_id=info2.test_id,
+        atp_test_name=info2.atp_test_name,
+        branch=info2.branch,
+        target=info2.target,
+        run_time=info2.run_time,
+        pass_rate=info2.pass_rate,
+        module=info2.module,
+        test_class=info2.test_class,
+        score=None,
+    )
+
+    self.assertEqual(info1_without_score, info2_without_score)
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/atest/test_finders/test_finder_utils.py b/atest/test_finders/test_finder_utils.py
index 2ffd0134..501a7707 100644
--- a/atest/test_finders/test_finder_utils.py
+++ b/atest/test_finders/test_finder_utils.py
@@ -325,6 +325,7 @@ def extract_selected_tests(tests: Iterable, default_all=False) -> List[str]:
 
   Args:
       tests: A string list which contains multiple test paths.
+      default_all: A bool that indicates whether to select all tests.
 
   Returns:
       A string list of paths.
@@ -417,14 +418,23 @@ def get_selected_indices(string: str, limit: int = None) -> Set[int]:
   return selections
 
 
-def run_find_cmd(ref_type, search_dir, target, methods=None):
+def run_find_cmd(
+    ref_type,
+    search_dir,
+    target,
+    module_name=None,
+    methods=None,
+    filter_func=None,
+):
   """Find a path to a target given a search dir and a target name.
 
   Args:
       ref_type: An Enum of the reference type.
       search_dir: A string of the dirpath to search in.
       target: A string of what you're trying to find.
+      module_name: Optional. A string of the module name.
       methods: A set of method names.
+      filter_func: Optional. A filter logic from calling class.
 
   Return:
       A list of the path to the target.
@@ -466,11 +476,25 @@ def run_find_cmd(ref_type, search_dir, target, methods=None):
     if isinstance(out, bytes):
       out = out.decode()
     logging.debug('%s find cmd out: %s', ref_name, out)
+
+  # Check if module info exist, then do test dedup
+  if module_name and filter_func:
+    logging.debug('Checking duplicate among found tests')
+    out = filter_func(out)  # update out list
+    logging.debug('After test deduplication, Found %s in %s', target, out)
+
   logging.debug('%s find completed in %ss', ref_name, time.time() - start)
   return extract_test_path(out, methods)
 
 
-def find_class_file(search_dir, class_name, is_native_test=False, methods=None):
+def find_class_file(
+    search_dir,
+    class_name,
+    is_native_test=False,
+    module_name=None,
+    methods=None,
+    filter_func=None,
+):
   """Find a path to a class file given a search dir and a class name.
 
   Args:
@@ -478,7 +502,9 @@ def find_class_file(search_dir, class_name, is_native_test=False, methods=None):
       class_name: A string of the class to search for.
       is_native_test: A boolean variable of whether to search for a native test
         or not.
+      module_name: Optional. A string of the module name.
       methods: A set of method names.
+      filter_func: Optional. A filter logic from calling class.
 
   Return:
       A list of the path to the java/cc file.
@@ -489,7 +515,9 @@ def find_class_file(search_dir, class_name, is_native_test=False, methods=None):
     ref_type = TestReferenceType.QUALIFIED_CLASS
   else:
     ref_type = TestReferenceType.CLASS
-  return run_find_cmd(ref_type, search_dir, class_name, methods)
+  return run_find_cmd(
+      ref_type, search_dir, class_name, module_name, methods, filter_func
+  )
 
 
 def is_equal_or_sub_dir(sub_dir, parent_dir):
@@ -629,8 +657,8 @@ def get_targets_from_xml_root(xml_root, module_info):
     - Look for the perf script.
 
   Args:
-      module_info: ModuleInfo class used to verify targets are valid modules.
       xml_root: ElementTree xml_root for us to look through.
+      module_info: ModuleInfo class used to verify targets are valid modules.
 
   Returns:
       A set of build targets based on the signals found in the xml file.
@@ -797,9 +825,9 @@ def get_targets_from_vts_xml(xml_file, rel_out_dir, module_info):
     - apk
 
   Args:
-      module_info: ModuleInfo class used to verify targets are valid modules.
-      rel_out_dir: Abs path to the out dir to help create vts10 build targets.
       xml_file: abs path to xml file.
+      rel_out_dir: Abs path to the out dir to help create vts10 build targets.
+      module_info: ModuleInfo class used to verify targets are valid modules.
 
   Returns:
       A set of build targets based on the signals found in the xml file.
diff --git a/atest/test_runner_handler.py b/atest/test_runner_handler.py
index f368d28d..fd2b577b 100644
--- a/atest/test_runner_handler.py
+++ b/atest/test_runner_handler.py
@@ -22,7 +22,6 @@ import itertools
 from typing import Any, Dict, List
 
 from atest import atest_error
-from atest import bazel_mode
 from atest import module_info
 from atest.test_finders import test_info
 from atest.test_runner_invocation import TestRunnerInvocation
@@ -47,7 +46,6 @@ _TEST_RUNNERS = {
     vts_tf_test_runner.VtsTradefedTestRunner.NAME: (
         vts_tf_test_runner.VtsTradefedTestRunner
     ),
-    bazel_mode.BazelTestRunner.NAME: bazel_mode.BazelTestRunner,
 }
 
 
diff --git a/atest/test_runners/atest_tf_test_runner.py b/atest/test_runners/atest_tf_test_runner.py
index 96dc701d..e86f009b 100644
--- a/atest/test_runners/atest_tf_test_runner.py
+++ b/atest/test_runners/atest_tf_test_runner.py
@@ -44,6 +44,7 @@ from atest import result_reporter
 from atest import rollout_control
 from atest.atest_enum import DetectType, ExitCode
 from atest.coverage import coverage
+from atest.crystalball import perf_mode
 from atest.logstorage import logstorage_utils
 from atest.metrics import metrics
 from atest.test_finders import test_finder_utils
@@ -199,6 +200,10 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     self._smart_test_selection = extra_args.get(
         constants.SMART_TEST_SELECTION, False
     )
+    self._class_level_report = (
+        extra_args.get(constants.CLASS_LEVEL_REPORT, False)
+        or self._smart_test_selection
+    )
 
   def requires_device_update(
       self, test_infos: List[test_info.TestInfo]
@@ -335,14 +340,9 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     upload_start = time.time()
     invocation_properties = {'atest_run_id': metrics.get_run_id()}
 
-    # Set crystalball_ingest property if there are performance tests.
-    is_perf_tests = False
-    for info in test_infos:
-      if 'performance-tests' in info.compatibility_suites:
-        is_perf_tests = True
-        break
-    if is_perf_tests:
-      invocation_properties['crystalball_ingest'] = 'yes'
+    if perf_mode.is_perf_test(args=extra_args, test_infos=test_infos):
+      logging.debug('perf mode is enabled, setting extra invocation properties')
+      perf_mode.set_invocation_properties(invocation_properties)
 
     creds, inv = (
         logstorage_utils.do_upload_flow(extra_args, invocation_properties)
@@ -517,6 +517,8 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
                           collect_only=extra_args.get(
                               constants.COLLECT_TESTS_ONLY
                           ),
+                          class_level_report=self._class_level_report,
+                          runner_errors_as_warnings=self._smart_test_selection,
                       ),
                       self.NAME,
                   ),
@@ -549,6 +551,10 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
                 constants.RED,
                 constants.WHITE,
             )
+            metrics.LocalDetectEvent(
+                detect_type=DetectType.HAS_NO_TEST_RUN_ISSUE,
+                result=1,
+            )
           if not data_map:
             metrics.LocalDetectEvent(
                 detect_type=DetectType.TF_EXIT_CODE,
@@ -910,10 +916,8 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
         A list that contains the string of atest tradefed run command.
         Only one command is returned.
     """
-    if any(
-        'performance-tests' in info.compatibility_suites for info in test_infos
-    ):
-      self.run_cmd_dict['template'] = 'template/performance-tests-base'
+    if perf_mode.is_perf_test(test_infos=test_infos):
+      self.run_cmd_dict['template'] = perf_mode.PERF_TEST_TEMPLATE
     elif extra_args.get(constants.USE_TF_MIN_BASE_TEMPLATE):
       self.run_cmd_dict['template'] = self._TF_LOCAL_MIN
     else:
@@ -1561,6 +1565,8 @@ def extra_args_to_tf_args(
         constants.BUILD_TARGET,
         constants.DRY_RUN,
         constants.DEVICE_ONLY,
+        constants.SMART_TEST_SELECTION,
+        constants.CLASS_LEVEL_REPORT,
     ):
       continue
     unsupported_args.append(arg)
diff --git a/atest/test_runners/atest_tf_test_runner_unittest.py b/atest/test_runners/atest_tf_test_runner_unittest.py
index bf5804c4..eaeae0c0 100755
--- a/atest/test_runners/atest_tf_test_runner_unittest.py
+++ b/atest/test_runners/atest_tf_test_runner_unittest.py
@@ -32,6 +32,7 @@ from unittest import mock
 
 from atest import arg_parser
 from atest import atest_configs
+from atest import atest_enum
 from atest import atest_utils
 from atest import constants
 from atest import module_info
@@ -396,15 +397,17 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     mock_conn1.assert_has_calls([mock.call.close()])
     mock_conn2.assert_has_calls([mock.call.close()])
 
+  @mock.patch('atest.metrics.metrics.LocalDetectEvent')
   @mock.patch.object(atf_tr.AtestTradefedTestRunner, '_process_connection')
   @mock.patch('select.select')
   def test_start_monitor_tf_exit_before_2nd_connection(
-      self, mock_select, mock_process
+      self, mock_select, mock_process, mock_detect_event
   ):
     """Test _start_monitor method."""
     mock_server = mock.Mock()
     mock_subproc = mock.Mock()
     mock_reporter = mock.Mock()
+    mock_reporter.all_test_results = []
     mock_conn1 = mock.Mock()
     mock_conn2 = mock.Mock()
     mock_server.accept.side_effect = [
@@ -424,6 +427,10 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     mock_subproc.poll.side_effect = [None, None, True, True, True, True]
     self.tr._start_monitor(mock_server, mock_subproc, mock_reporter, {})
     self.assertEqual(mock_process.call_count, 4)
+    mock_detect_event.assert_called_once_with(
+        detect_type=atest_enum.DetectType.HAS_NO_TEST_RUN_ISSUE,
+        result=1,
+    )
     calls = [mock.call.accept(), mock.call.close()]
     mock_server.assert_has_calls(calls)
     mock_conn1.assert_has_calls([mock.call.close()])
diff --git a/atest/test_runners/event_handler.py b/atest/test_runners/event_handler.py
index 080568a4..424e86a2 100644
--- a/atest/test_runners/event_handler.py
+++ b/atest/test_runners/event_handler.py
@@ -115,9 +115,12 @@ class EventHandler:
 
   def _test_failed(self, event_data):
     self.state['last_failed'] = {
-        'name': TEST_NAME_TEMPLATE % (
-            event_data['className'],
-            event_data['testName'],
+        'name': (
+            TEST_NAME_TEMPLATE
+            % (
+                event_data['className'],
+                event_data['testName'],
+            )
         ),
         'trace': event_data['trace'],
     }
@@ -180,7 +183,11 @@ class EventHandler:
     # Renew ResultReport if is module level(reporter.silent=False)
     if not self.reporter.silent:
       self.reporter.set_current_iteration_summary(self.run_num)
-      self.reporter = result_reporter.ResultReporter(silent=False)
+      self.reporter = result_reporter.ResultReporter(
+          silent=False,
+          class_level_report=self.reporter.class_level_report,
+          runner_errors_as_warnings=self.reporter.runner_errors_as_warnings,
+      )
 
   def _module_ended(self, event_data):
     pass
diff --git a/atest/tools/indexing.py b/atest/tools/indexing.py
index 7b9c5c5e..2cd8a6c5 100755
--- a/atest/tools/indexing.py
+++ b/atest/tools/indexing.py
@@ -194,7 +194,7 @@ def get_cc_result(indices: Indices):
       indices: an Indices object.
   """
   find_cc_cmd = (
-      f"{LOCATE} -id{indices.locate_db} --regex '/*.test.*\.(cc|cpp)$'"
+      f"{LOCATE} -id{indices.locate_db} --regex '/*.test.*\\.(cc|cpp)$'"
       f"| xargs egrep -sH '{constants.CC_GREP_RE}' 2>/dev/null || true"
   )
   logging.debug('Probing CC classes:\n %s', find_cc_cmd)
@@ -216,7 +216,7 @@ def get_java_result(indices: Indices):
   """
   package_grep_re = r'^\s*package\s+[a-z][[:alnum:]]+[^{]'
   find_java_cmd = (
-      f"{LOCATE} -id{indices.locate_db} --regex '/*.test.*\.(java|kt)$' "
+      f"{LOCATE} -id{indices.locate_db} --regex '/*.test.*\\.(java|kt)$' "
       # (b/204398677) suppress stderr when indexing target terminated.
       f"| xargs egrep -sH '{package_grep_re}' 2>/dev/null|| true"
   )
diff --git a/atest/unittest_data/foo/bar/module_1/AndroidManifest.xml b/atest/unittest_data/foo/bar/module_1/AndroidManifest.xml
new file mode 100644
index 00000000..3373af26
--- /dev/null
+++ b/atest/unittest_data/foo/bar/module_1/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+        xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
+        package="module_1"
+        coreApp="true"
+        android:sharedUserId="android.uid.system">
+    <application>
+        <activity
+            android:name=".wifi.WifiPickerActivity"
+            android:exported="true">
+            <intent-filter android:priority="1">
+                <action android:name="android.net.wifi.PICK_WIFI_NETWORK" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+            <meta-data android:name="com.android.settings.PRIMARY_PROFILE_CONTROLLED"
+                android:value="true" />
+        </activity>
+    </application>
+</manifest>
+
diff --git a/atest/unittest_data/foo/bar/module_1/test/AndroidManifest.xml b/atest/unittest_data/foo/bar/module_1/test/AndroidManifest.xml
new file mode 100644
index 00000000..7fdcf2b8
--- /dev/null
+++ b/atest/unittest_data/foo/bar/module_1/test/AndroidManifest.xml
@@ -0,0 +1,12 @@
+<?xml version="1.0" encoding="utf-8"?>
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.settings.tests.unit">
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="module_1"
+        android:label="Settings Test Cases">
+    </instrumentation>
+
+</manifest>
+
diff --git a/experiments/a/tools/update_aliases.py b/experiments/a/tools/update_aliases.py
index 5e903d84..c4b94c8f 100644
--- a/experiments/a/tools/update_aliases.py
+++ b/experiments/a/tools/update_aliases.py
@@ -258,14 +258,14 @@ alias_definitions = {
     },
     'launcher': {'build': 'NexusLauncherRelease'},
     'launcherd': {
-        'build': 'nexusLauncherDebug',
+        'build': 'NexusLauncherDebug',
         'update': (
             'adb install'
             ' $OUT/anywhere/priv-app/NexusLauncherDebug/NexusLauncherDebug.apk'
         ),
     },
     'launchergo': {
-        'build': 'launcherGoGoogle',
+        'build': 'LauncherGoGoogle',
         'update': 'adb shell am force-stop com.android.launcher3',
     },
     'intentresolver': {
@@ -273,27 +273,27 @@ alias_definitions = {
         'update': 'adb shell am force-stop com.android.intentresolver',
     },
     'sysuig': {
-        'build': 'systemUIGoogle',
+        'build': 'SystemUIGoogle',
         'update': 'adb shell am force-stop com.android.systemui',
     },
     'sysuititan': {
-        'build': 'systemUITitan',
+        'build': 'SystemUITitan',
         'update': 'adb shell am force-stop com.android.systemui',
     },
     'sysuigo': {
-        'build': 'systemUIGo',
+        'build': 'SystemUIGo',
         'update': 'adb shell am force-stop com.android.systemui',
     },
     'flagflipper': {
-        'build': 'theFlippinApp',
+        'build': 'TheFlippinApp',
         'update': 'adb shell am force-stop com.android.theflippinapp',
     },
     'docsui': {
-        'build': 'documentsUI',
+        'build': 'DocumentsUI',
         'update': 'adb shell am force-stop com.android.documentsui',
     },
     'docsuig': {
-        'build': 'documentsUIGoogle',
+        'build': 'DocumentsUIGoogle',
         'update': 'adb shell am force-stop com.google.android.documentsui',
     },
     'settings': {
```

