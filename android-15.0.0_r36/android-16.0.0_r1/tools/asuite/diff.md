```diff
diff --git a/Android.bp b/Android.bp
index 67f75104..9394be41 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,6 +41,20 @@ java_library_host {
     java_version: "11",
 }
 
+java_library_host {
+    name: "asuite_proto_java_lite",
+    srcs: [
+        "atest/proto/*.proto",
+    ],
+    proto: {
+        type: "lite",
+        canonical_path_from_root: false,
+        include_dirs: ["external/protobuf/src"],
+    },
+    // b/267831518: Pin tradefed and dependencies to Java 11.
+    java_version: "11",
+}
+
 python_library_host {
     name: "tradefed-protos-py",
     srcs: [
diff --git a/OWNERS b/OWNERS
index b5f1bfc6..d4bcaede 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,10 +2,8 @@ include /OWNERS_ADTE_TEAM
 
 albaltai@google.com
 dshi@google.com
-hzalek@google.com
 kellyhung@google.com
 kevcheng@google.com
 morrislin@google.com
 patricktu@google.com
-weisu@google.com
 yangbill@google.com
diff --git a/adevice/src/adevice.rs b/adevice/src/adevice.rs
index 4b634cf9..12bda126 100644
--- a/adevice/src/adevice.rs
+++ b/adevice/src/adevice.rs
@@ -673,7 +673,6 @@ fn shadow_apk_check(stdout: &mut impl Write, files: &HashMap<PathBuf, PushState>
 /// Return all path components of file_path up to a passed partition.
 /// Given system/bin/logd and partition "system",
 /// return ["system/bin/logd", "system/bin"], not "system" or ""
-
 fn parents(file_path: &str, partitions: &[PathBuf]) -> Vec<PathBuf> {
     PathBuf::from(file_path)
         .ancestors()
diff --git a/atest/Android.bp b/atest/Android.bp
index c5fda1f8..6753206c 100644
--- a/atest/Android.bp
+++ b/atest/Android.bp
@@ -42,11 +42,6 @@ python_defaults {
         "java_test_filter_generator.py",
         "java_test_filter_generator_test.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 // Attributes common to atest binaries.
diff --git a/atest/arg_parser.py b/atest/arg_parser.py
index 32505253..68c56c11 100644
--- a/atest/arg_parser.py
+++ b/atest/arg_parser.py
@@ -255,6 +255,15 @@ def create_atest_arg_parser():
           ' need to be setup again with "-i".'
       ),
   )
+  parser.add_argument(
+      '--smart-test-selection',
+      default=False,
+      action='store_true',
+      help=(
+          'Automatically select test classes based on correlation with code'
+          ' change, and run them.'
+      ),
+  )
   parser.add_argument(
       '--use-modules-in',
       help=(
diff --git a/atest/atest_enum.py b/atest/atest_enum.py
index d44fdf25..2ac3a352 100644
--- a/atest/atest_enum.py
+++ b/atest/atest_enum.py
@@ -121,6 +121,10 @@ class DetectType(IntEnum):
   # means the feature is enabled, negative value means disabled.
   ROLLOUT_CONTROLLED_FEATURE_ID = 65
   ROLLOUT_CONTROLLED_FEATURE_ID_OVERRIDE = 66
+  # The count of skipped app installation by opting in incremental setup
+  APP_INSTALLATION_SKIPPED_COUNT = 67
+  # The count of not skipped app installation while opting in incremental setup
+  APP_INSTALLATION_NOT_SKIPPED_COUNT = 68
 
 
 @unique
diff --git a/atest/atest_execution_info.py b/atest/atest_execution_info.py
index 064f096a..2e672b08 100644
--- a/atest/atest_execution_info.py
+++ b/atest/atest_execution_info.py
@@ -26,7 +26,7 @@ import pathlib
 import shutil
 import sys
 import time
-from typing import List
+from typing import Callable, List
 
 from atest import atest_enum
 from atest import atest_utils
@@ -56,6 +56,10 @@ _RESULT_LEN = 20
 _RESULT_URL_LEN = 35
 _COMMAND_LEN = 50
 _LOGCAT_FMT = '{}/log/invocation_*/{}*device_logcat_test*'
+_APK_CHANGE_DETECTOR_CLASSNAME = 'ApkChangeDetector'
+_APP_INSTALL_SKIP_KEY = 'Skipping the installation of'
+_APP_INSTALL_KEY = 'Installing apk'
+_HOST_LOG_PREFIX = 'host_log_'
 
 _SUMMARY_MAP_TEMPLATE = {
     _STATUS_PASSED_KEY: 0,
@@ -247,6 +251,53 @@ def has_url_results():
   return False
 
 
+def parse_test_log_and_send_app_installation_stats_metrics(
+    log_path: pathlib.Path,
+) -> None:
+  """Parse log and send app installation statistic metrics."""
+  if not log_path:
+    return
+
+  # Attempt to find all host logs
+  absolute_host_log_paths = glob.glob(
+      str(log_path / f'**/{_HOST_LOG_PREFIX}*'), recursive=True
+  )
+
+  if not absolute_host_log_paths:
+    return
+
+  skipped_count = 0
+  not_skipped_count = 0
+  try:
+    for host_log_path in absolute_host_log_paths:
+      if not os.path.isfile(host_log_path):
+        continue
+
+      # Open the host log and parse app installation skip metric
+      with open(f'{host_log_path}', 'r') as host_log_file:
+        for line in host_log_file:
+          if (
+              _APP_INSTALL_SKIP_KEY in line
+              and _APK_CHANGE_DETECTOR_CLASSNAME in line
+          ):
+            skipped_count += 1
+          elif _APP_INSTALL_KEY in line:
+            # TODO(b/394384055): Check classname for unskipped APKs as well.
+            not_skipped_count += 1
+    logging.debug('%d APK(s) skipped installation.', skipped_count)
+    logging.debug('%d APK(s) did not skip installation.', not_skipped_count)
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.APP_INSTALLATION_SKIPPED_COUNT,
+        result=skipped_count,
+    )
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.APP_INSTALLATION_NOT_SKIPPED_COUNT,
+        result=not_skipped_count,
+    )
+  except Exception as e:
+    logging.debug('An error occurred when accessing certain host logs: %s', e)
+
+
 class AtestExecutionInfo:
   """Class that stores the whole test progress information in JSON format.
 
@@ -291,6 +342,7 @@ class AtestExecutionInfo:
       args: List[str],
       work_dir: str,
       args_ns: argparse.ArgumentParser,
+      get_exit_code_func: Callable[[], int] = None,
       start_time: float = None,
       repo_out_dir: pathlib.Path = None,
   ):
@@ -300,6 +352,7 @@ class AtestExecutionInfo:
         args: Command line parameters.
         work_dir: The directory for saving information.
         args_ns: An argparse.ArgumentParser class instance holding parsed args.
+        get_exit_code_func: A callable that returns the exit_code value.
         start_time: The execution start time. Can be None.
         repo_out_dir: The repo output directory. Can be None.
 
@@ -310,6 +363,7 @@ class AtestExecutionInfo:
     self.work_dir = work_dir
     self.result_file_obj = None
     self.args_ns = args_ns
+    self.get_exit_code_func = get_exit_code_func
     self.test_result = os.path.join(self.work_dir, _TEST_RESULT_NAME)
     self._proc_usb_speed = None
     logging.debug(
@@ -377,22 +431,27 @@ class AtestExecutionInfo:
       atest_utils.prompt_suggestions(self.test_result)
       html_path = atest_utils.generate_result_html(self.test_result)
       symlink_latest_result(self.work_dir)
-    main_module = sys.modules.get(_MAIN_MODULE_KEY)
-    main_exit_code = (
-        value.code
-        if isinstance(value, SystemExit)
-        else (getattr(main_module, _EXIT_CODE_ATTR, ExitCode.ERROR))
-    )
+
+    if self.get_exit_code_func:
+      main_exit_code = self.get_exit_code_func()
+    else:
+      main_module = sys.modules.get(_MAIN_MODULE_KEY)
+      main_exit_code = (
+          value.code
+          if isinstance(value, SystemExit)
+          else (getattr(main_module, _EXIT_CODE_ATTR, ExitCode.ERROR))
+      )
 
     print()
     if log_path:
       print(f'Test logs: {log_path / "log"}')
+      parse_test_log_and_send_app_installation_stats_metrics(log_path)
     log_link = html_path if html_path else log_path
     if log_link:
       print(atest_utils.mark_magenta(f'Log file list: file://{log_link}'))
     bug_report_url = AtestExecutionInfo._create_bug_report_url()
     if bug_report_url:
-      print(atest_utils.mark_magenta(f"Bug report: {bug_report_url}"))
+      print(atest_utils.mark_magenta(f'Report an issue: {bug_report_url}'))
     print()
 
     # Do not send stacktrace with send_exit_event when exit code is not
diff --git a/atest/atest_execution_info_unittest.py b/atest/atest_execution_info_unittest.py
index af614549..75c84013 100755
--- a/atest/atest_execution_info_unittest.py
+++ b/atest/atest_execution_info_unittest.py
@@ -23,6 +23,7 @@ import time
 import unittest
 from unittest.mock import patch
 from atest import arg_parser
+from atest import atest_enum
 from atest import atest_execution_info as aei
 from atest import constants
 from atest import result_reporter
@@ -124,6 +125,97 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     return False
 
 
+class SendIncrementalSetupStatTests(fake_filesystem_unittest.TestCase):
+
+  _HOST_LOG_1_CONTENT = (
+      '[ApkChangeDetector] Skipping the installation of SystemUIApp\nInstalling'
+      ' apk android.CtsApp\n[ApkChangeDetector] Skipping the uninstallation of'
+      ' SystemUIApp'
+  )
+
+  _HOST_LOG_2_CONTENT = (
+      '[ApkChangeDetector] Skipping the installation of SysUIRobolectricApp\n'
+      ' Installing apk a.b.c.d  \n [UnrelatedClass] Skipping the installation'
+      ' of SomeClass'
+  )
+
+  def setUp(self):
+    super().setUp()
+    self.setUpPyfakefs()
+    self.fs.create_dir(constants.ATEST_RESULT_ROOT)
+    self._log_path = pathlib.Path('/tmp')
+
+  def tearDown(self):
+    if os.path.exists(str(self._log_path)):
+      self.fs.remove_object(str(self._log_path))
+    super().tearDown()
+
+  @patch('atest.metrics.metrics.LocalDetectEvent')
+  def test_parse_test_log_and_send_app_installation_stats_metrics_get_stats_successful(
+      self,
+      mock_detect_event,
+  ):
+    host_log_path1 = self._log_path / 'host_log_1.txt'
+    host_log_path2 = self._log_path / 'invocation' / 'host_log_2.txt'
+    self.fs.create_file(
+        host_log_path1,
+        contents=self.__class__._HOST_LOG_1_CONTENT,
+        create_missing_dirs=True,
+    )
+    self.fs.create_file(
+        host_log_path2,
+        contents=self.__class__._HOST_LOG_2_CONTENT,
+        create_missing_dirs=True,
+    )
+    expected_calls = [
+        unittest.mock.call(
+            detect_type=atest_enum.DetectType.APP_INSTALLATION_SKIPPED_COUNT,
+            result=2,
+        ),
+        unittest.mock.call(
+            detect_type=atest_enum.DetectType.APP_INSTALLATION_NOT_SKIPPED_COUNT,
+            result=2,
+        ),
+    ]
+
+    aei.parse_test_log_and_send_app_installation_stats_metrics(self._log_path)
+
+    mock_detect_event.assert_has_calls(expected_calls, any_order=True)
+
+  @patch('atest.metrics.metrics.LocalDetectEvent')
+  def test_parse_test_log_and_send_app_installation_stats_metrics_no_host_log(
+      self,
+      mock_detect_event,
+  ):
+    aei.parse_test_log_and_send_app_installation_stats_metrics(self._log_path)
+
+    mock_detect_event.assert_not_called()
+
+  @patch('atest.metrics.metrics.LocalDetectEvent')
+  def test_parse_test_log_and_send_app_installation_stats_metrics_no_info_in_host_log(
+      self,
+      mock_detect_event,
+  ):
+    host_log_path1 = self._log_path / 'host_log_1.txt'
+    host_log_path2 = self._log_path / 'invocation' / 'host_log_2.txt'
+    self.fs.create_file(host_log_path1, contents='', create_missing_dirs=True)
+    self.fs.create_file(host_log_path2, contents='', create_missing_dirs=True)
+    expected_calls = [
+        unittest.mock.call(
+            detect_type=atest_enum.DetectType.APP_INSTALLATION_SKIPPED_COUNT,
+            result=0,
+        ),
+        unittest.mock.call(
+            detect_type=atest_enum.DetectType.APP_INSTALLATION_NOT_SKIPPED_COUNT,
+            result=0,
+        ),
+    ]
+
+    aei.parse_test_log_and_send_app_installation_stats_metrics(self._log_path)
+
+    mock_detect_event.assert_has_calls(expected_calls, any_order=True)
+
+
 # pylint: disable=protected-access
 class AtestExecutionInfoUnittests(unittest.TestCase):
   """Unit tests for atest_execution_info.py"""
diff --git a/atest/atest_main.py b/atest/atest_main.py
index 590dcade..7ebbcef6 100755
--- a/atest/atest_main.py
+++ b/atest/atest_main.py
@@ -300,7 +300,7 @@ def make_test_run_dir() -> str:
   return test_result_dir
 
 
-def get_extra_args(args):
+def get_extra_args(args) -> Dict[str, str]:
   """Get extra args for test runners.
 
   Args:
@@ -344,6 +344,7 @@ def get_extra_args(args):
       'user_type': constants.USER_TYPE,
       'verbose': constants.VERBOSE,
       'use_tf_min_base_template': constants.USE_TF_MIN_BASE_TEMPLATE,
+      'smart_test_selection': constants.SMART_TEST_SELECTION,
   }
   not_match = [k for k in arg_maps if k not in vars(args)]
   if not_match:
@@ -708,8 +709,12 @@ class _AtestMain:
 
     self._banner_printer = banner.BannerPrinter.create()
 
+    exit_code = ExitCode.ERROR
     with atest_execution_info.AtestExecutionInfo(
-        final_args, self._results_dir, atest_configs.GLOBAL_ARGS
+        final_args,
+        self._results_dir,
+        atest_configs.GLOBAL_ARGS,
+        lambda: exit_code,
     ):
       setup_metrics_tool_name(atest_configs.GLOBAL_ARGS.no_metrics)
 
@@ -1120,6 +1125,8 @@ class _AtestMain:
         Exit code if failed. None otherwise.
     """
     build_targets = self._get_build_targets()
+    if not build_targets:
+      return None
 
     # Add the -jx as a build target if user specify it.
     if self._args.build_j:
diff --git a/atest/atest_main_unittest.py b/atest/atest_main_unittest.py
index 18bc4853..8472a622 100755
--- a/atest/atest_main_unittest.py
+++ b/atest/atest_main_unittest.py
@@ -279,6 +279,14 @@ class AtestMainUnitTests(unittest.TestCase):
 
       self.assertNotEqual(args_original, args)
 
+  @mock.patch.object(
+      atest_main._AtestMain, '_get_build_targets', return_value=None
+  )
+  def test_run_build_step_exits_normally_when_no_build_target(self, _):
+    pseudo_atest_main = atest_main._AtestMain(argv=[])
+
+    self.assertIsNone(pseudo_atest_main._run_build_step())
+
 
 # pylint: disable=missing-function-docstring
 class AtestUnittestFixture(fake_filesystem_unittest.TestCase):
diff --git a/atest/bazel_mode_unittest.py b/atest/bazel_mode_unittest.py
deleted file mode 100755
index a819afa0..00000000
--- a/atest/bazel_mode_unittest.py
+++ /dev/null
@@ -1,2877 +0,0 @@
-#!/usr/bin/env python3
-#
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
-"""Unit tests for bazel_mode."""
-# pylint: disable=invalid-name
-# pylint: disable=missing-function-docstring
-# pylint: disable=too-many-lines
-
-import argparse
-from io import StringIO
-from pathlib import Path
-import re
-import shlex
-import shutil
-import subprocess
-import tempfile
-from typing import List
-import unittest
-from unittest import mock
-from atest import bazel_mode
-from atest import constants
-from atest import module_info
-from atest.test_finders import example_finder, test_finder_base, test_info
-from atest.test_runners import atest_tf_test_runner
-from pyfakefs import fake_filesystem_unittest
-
-
-ATEST_TF_RUNNER = atest_tf_test_runner.AtestTradefedTestRunner.NAME
-BAZEL_RUNNER = bazel_mode.BazelTestRunner.NAME
-MODULE_BUILD_TARGETS = {'foo1', 'foo2', 'foo3'}
-MODULE_NAME = 'foo'
-
-
-class GenerationTestFixture(fake_filesystem_unittest.TestCase):
-  """Fixture for workspace generation tests."""
-
-  def setUp(self):
-    self.setUpPyfakefs()
-
-    self._src_root_path = Path('/src')
-    self.out_dir_path = self._src_root_path.joinpath('out')
-    self.out_dir_path.mkdir(parents=True)
-    self.product_out_path = self.out_dir_path.joinpath('product')
-    self.host_out_path = self.out_dir_path.joinpath('host')
-    self.workspace_out_path = self.out_dir_path.joinpath('workspace')
-
-    self._resource_root = self._src_root_path.joinpath(
-        'tools/asuite/atest/bazel'
-    )
-
-    self.workspace_md5_checksum = self.workspace_out_path.joinpath(
-        'workspace_md5_checksum'
-    )
-    self.resource_manager = bazel_mode.ResourceManager(
-        src_root_path=self._src_root_path,
-        resource_root_path=self._resource_root,
-        product_out_path=self.product_out_path,
-        md5_checksum_file_path=self.workspace_md5_checksum,
-    )
-
-    bazel_rules = self.resource_manager.get_resource_file_path('rules')
-    bazel_rules.mkdir(parents=True)
-    self.rules_bzl_file = bazel_rules.joinpath('rules.bzl')
-    self.rules_bzl_file.touch()
-
-    bazel_configs = self.resource_manager.get_resource_file_path('configs')
-    bazel_configs.mkdir(parents=True)
-    bazel_configs.joinpath('configs.bzl').touch()
-
-    self.resource_manager.get_resource_file_path('WORKSPACE').touch()
-    self.resource_manager.get_resource_file_path('bazelrc').touch()
-    self.resource_manager.get_resource_file_path('bazel.sh').touch()
-
-    rules_python = self.resource_manager.get_src_file_path(
-        'external/bazelbuild-rules_python'
-    )
-    rules_python.mkdir(parents=True)
-    rules_java = self.resource_manager.get_src_file_path(
-        'external/bazelbuild-rules_java'
-    )
-    rules_java.mkdir(parents=True)
-
-  def create_workspace_generator(
-      self,
-      modules=None,
-      enabled_features=None,
-      jdk_path=None,
-  ):
-    mod_info = self.create_module_info(modules)
-
-    generator = bazel_mode.WorkspaceGenerator(
-        resource_manager=self.resource_manager,
-        workspace_out_path=self.workspace_out_path,
-        host_out_path=self.host_out_path,
-        build_out_dir=self.out_dir_path,
-        mod_info=mod_info,
-        jdk_path=jdk_path,
-        enabled_features=enabled_features,
-    )
-
-    return generator
-
-  def run_generator(self, mod_info, enabled_features=None, jdk_path=None):
-    generator = bazel_mode.WorkspaceGenerator(
-        resource_manager=self.resource_manager,
-        workspace_out_path=self.workspace_out_path,
-        host_out_path=self.host_out_path,
-        build_out_dir=self.out_dir_path,
-        mod_info=mod_info,
-        jdk_path=jdk_path,
-        enabled_features=enabled_features,
-    )
-
-    generator.generate()
-
-  # pylint: disable=protected-access
-  def create_empty_module_info(self):
-    fake_temp_file = self.product_out_path.joinpath(
-        next(tempfile._get_candidate_names())
-    )
-    self.fs.create_file(fake_temp_file, contents='{}')
-    return module_info.load_from_file(module_file=fake_temp_file)
-
-  def create_module_info(self, modules=None):
-    mod_info = self.create_empty_module_info()
-    modules = modules or []
-
-    prerequisites = frozenset().union(
-        bazel_mode.TestTarget.DEVICE_TEST_PREREQUISITES,
-        bazel_mode.TestTarget.DEVICELESS_TEST_PREREQUISITES,
-    )
-
-    for module_name in prerequisites:
-      info = host_module(name=module_name, path='prebuilts')
-      info[constants.MODULE_INFO_ID] = module_name
-      mod_info.name_to_module_info[module_name] = info
-
-    for m in modules:
-      m[constants.MODULE_INFO_ID] = m['module_name']
-      mod_info.name_to_module_info[m['module_name']] = m
-      for path in m['path']:
-        if path in mod_info.path_to_module_info:
-          mod_info.path_to_module_info[path].append(m)
-        else:
-          mod_info.path_to_module_info[path] = [m]
-
-    return mod_info
-
-  def assertSymlinkTo(self, symlink_path, target_path):
-    self.assertEqual(symlink_path.resolve(strict=False), target_path)
-
-  def assertTargetInWorkspace(self, name, package=''):
-    build_file = self.workspace_out_path.joinpath(package, 'BUILD.bazel')
-    contents = build_file.read_text(encoding='utf8')
-    occurrences = len(self.find_target_by_name(name, contents))
-
-    if occurrences == 1:
-      return
-
-    cardinality = 'Multiple' if occurrences else 'Zero'
-    self.fail(f"{cardinality} targets named '{name}' found in '{contents}'")
-
-  def assertTargetNotInWorkspace(self, name, package=''):
-    build_file = self.workspace_out_path.joinpath(package, 'BUILD.bazel')
-
-    if not build_file.exists():
-      return
-
-    contents = build_file.read_text(encoding='utf8')
-    matches = self.find_target_by_name(name, contents)
-
-    if not matches:
-      return
-
-    self.fail(f"Unexpectedly found target(s) named '{name}' in '{contents}'")
-
-  def assertInBuildFile(self, substring, package=''):
-    build_file = self.workspace_out_path.joinpath(package, 'BUILD.bazel')
-    self.assertIn(substring, build_file.read_text(encoding='utf8'))
-
-  def assertNotInBuildFile(self, substring, package=''):
-    build_file = self.workspace_out_path.joinpath(package, 'BUILD.bazel')
-    self.assertNotIn(substring, build_file.read_text(encoding='utf8'))
-
-  def assertFileInWorkspace(self, relative_path, package=''):
-    path = self.workspace_out_path.joinpath(package, relative_path)
-    self.assertTrue(path.exists())
-
-  def assertDirInWorkspace(self, relative_path, package=''):
-    path = self.workspace_out_path.joinpath(package, relative_path)
-    self.assertTrue(path.is_dir())
-
-  def assertFileNotInWorkspace(self, relative_path, package=''):
-    path = self.workspace_out_path.joinpath(package, relative_path)
-    self.assertFalse(path.exists())
-
-  def find_target_by_name(self, name: str, contents: str) -> List[str]:
-    return re.findall(rf'\bname\s*=\s*"{name}"', contents)
-
-  def add_device_def_to_filesystem(self):
-    bazel_device_def = self.resource_manager.get_resource_file_path(
-        'device_def'
-    )
-    bazel_device_def.mkdir(parents=True)
-    bazel_device_def.joinpath('device_def.bzl').touch()
-
-
-class BasicWorkspaceGenerationTest(GenerationTestFixture):
-  """Tests for basic workspace generation and update."""
-
-  def test_generate_workspace_when_nonexistent(self):
-    workspace_generator = self.create_workspace_generator()
-    shutil.rmtree(workspace_generator.workspace_out_path, ignore_errors=True)
-
-    workspace_generator.generate()
-
-    self.assertTrue(workspace_generator.workspace_out_path.is_dir())
-
-  def test_regenerate_workspace_when_features_changed(self):
-    workspace_generator = self.create_workspace_generator(
-        enabled_features={bazel_mode.Features.NULL_FEATURE}
-    )
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_when_feature_does_not_affect_workspace(self):
-    workspace_generator = self.create_workspace_generator(
-        enabled_features={bazel_mode.Features.NULL_FEATURE}
-    )
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    parser = argparse.ArgumentParser()
-    bazel_mode.add_parser_arguments(parser, dest='bazel_mode_features')
-    # pylint: disable=no-member
-    args = parser.parse_args([
-        bazel_mode.Features.NULL_FEATURE.arg_flag,
-        '--experimental-bes-publish',
-    ])
-    workspace_generator = self.create_workspace_generator(
-        enabled_features=set(args.bazel_mode_features)
-    )
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_features_unchanged(self):
-    workspace_generator = self.create_workspace_generator(
-        enabled_features={bazel_mode.Features.NULL_FEATURE}
-    )
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    workspace_generator = self.create_workspace_generator(
-        enabled_features={bazel_mode.Features.NULL_FEATURE}
-    )
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_regenerate_workspace_when_module_info_deleted(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    workspace_generator.mod_info.mod_info_file_path.unlink()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_module_info_unchanged(self):
-    workspace_generator1 = self.create_workspace_generator()
-    workspace_generator1.generate()
-    workspace_stat = workspace_generator1.workspace_out_path.stat()
-
-    workspace_generator2 = self.create_workspace_generator()
-    workspace_generator2.generate()
-    new_workspace_stat = workspace_generator2.workspace_out_path.stat()
-
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_module_only_touched(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    Path(workspace_generator.mod_info.mod_info_file_path).touch()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_regenerate_workspace_when_module_info_changed(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    mod_info_file_path = workspace_generator.mod_info.mod_info_file_path
-    with open(mod_info_file_path, 'a', encoding='utf8') as f:
-      f.write(' ')
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_regenerate_workspace_when_md5_file_removed(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.workspace_md5_checksum.unlink()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_regenerate_workspace_when_md5_file_is_broken(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.workspace_md5_checksum.write_text('broken checksum file')
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_workspace_files_unaffected(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_scrub_old_workspace_when_regenerating(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    some_file = workspace_generator.workspace_out_path.joinpath('some_file')
-    some_file.touch()
-    self.assertTrue(some_file.is_file())
-
-    # Remove the module_info file to regenerate the workspace.
-    workspace_generator.mod_info.mod_info_file_path.unlink()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    self.assertFalse(some_file.is_file())
-
-  def test_regenerate_workspace_when_resource_file_changed(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    with open(self.rules_bzl_file, 'a', encoding='utf8') as f:
-      f.write(' ')
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_resource_file_only_touched(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.rules_bzl_file.touch()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-  def test_copy_workspace_resources(self):
-    gen = self.create_workspace_generator()
-
-    gen.generate()
-
-    self.assertFileInWorkspace('WORKSPACE')
-    self.assertFileInWorkspace('.bazelrc')
-    self.assertDirInWorkspace('bazel/rules')
-    self.assertDirInWorkspace('bazel/configs')
-
-  def test_generated_target_name(self):
-    mod_info = self.create_module_info(
-        modules=[host_unit_test_module(name='hello_world_test')]
-    )
-    info = mod_info.get_module_info('hello_world_test')
-    info[constants.MODULE_INFO_ID] = 'new_hello_world_test'
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('new_hello_world_test')
-    self.assertTargetNotInWorkspace('hello_world_test')
-
-  def test_generate_host_unit_test_module_target(self):
-    mod_info = self.create_module_info(
-        modules=[host_unit_test_module(name='hello_world_test')]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('hello_world_test_host')
-
-  def test_not_generate_host_test_module_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_test_module(name='hello_world_test'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetNotInWorkspace('hello_world_test')
-
-  def test_not_generate_test_module_target_with_invalid_installed_path(self):
-    mod_info = self.create_module_info(
-        modules=[
-            test_module(name='hello_world_test', installed='out/invalid/path')
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetNotInWorkspace('hello_world_test_device')
-    self.assertTargetNotInWorkspace('hello_world_test_host')
-
-  def test_generate_variable_file(self):
-    gen = self.create_workspace_generator()
-
-    gen.generate()
-
-    self.assertFileInWorkspace('BUILD.bazel')
-    self.assertFileInWorkspace('constants.bzl')
-
-
-class MultiConfigUnitTestModuleTestTargetGenerationTest(GenerationTestFixture):
-  """Tests for test target generation of test modules with multi-configs."""
-
-  def setUp(self):
-    super().setUp()
-    super().add_device_def_to_filesystem()
-
-  def test_generate_test_rule_imports(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                host_unit_suite(
-                    test_module(name='hello_world_test', path='example/tests')
-                )
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl",'
-        ' "tradefed_device_driven_test", "tradefed_deviceless_test")\n',
-        package='example/tests',
-    )
-
-  def test_not_generate_device_test_import_when_feature_disabled(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                host_unit_suite(
-                    test_module(name='hello_world_test', path='example/tests')
-                )
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl", "tradefed_deviceless_test")\n',
-        package='example/tests',
-    )
-
-  def test_generate_test_targets(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                host_unit_suite(
-                    test_module(name='hello_world_test', path='example/tests')
-                )
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertTargetInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-    self.assertTargetInWorkspace(
-        'hello_world_test_host', package='example/tests'
-    )
-
-  def test_not_generate_device_test_target_when_feature_disabled(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                host_unit_suite(
-                    test_module(name='hello_world_test', path='example/tests')
-                )
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetNotInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-    self.assertTargetInWorkspace(
-        'hello_world_test_host', package='example/tests'
-    )
-
-
-class DeviceTestModuleTestTargetGenerationTest(GenerationTestFixture):
-  """Tests for device test module test target generation."""
-
-  def setUp(self):
-    super().setUp()
-    super().add_device_def_to_filesystem()
-
-  def test_generate_device_driven_test_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(name='hello_world_test', path='example/tests'),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl",'
-        ' "tradefed_device_driven_test")\n',
-        package='example/tests',
-    )
-    self.assertDirInWorkspace('device_def')
-    self.assertTargetInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-
-  def test_generate_target_with_suites(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(
-                name='hello_world_test',
-                path='example/tests',
-                compatibility_suites=['cts', 'mts'],
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        '    suites = [\n        "cts",\n        "mts",\n    ],\n',
-        package='example/tests',
-    )
-
-  def test_generate_target_with_host_dependencies(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(
-                name='hello_world_test',
-                path='example/tests',
-                host_dependencies=['vts_dep', 'cts_dep'],
-            ),
-            host_module(name='vts_dep'),
-            host_module(name='cts_dep'),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        '    tradefed_deps = [\n'
-        '        "//:cts_dep",\n'
-        '        "//:vts_dep",\n'
-        '    ],\n',
-        package='example/tests',
-    )
-
-  def test_generate_target_with_device_dependencies(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_test_module(
-                name='hello_world_test',
-                path='example/tests',
-                target_dependencies=['helper_app'],
-            ),
-            device_module(name='helper_app'),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_HOST_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        '    device_data = [\n        "//:helper_app",\n    ],\n',
-        package='example/tests',
-    )
-
-  def test_generate_target_with_tags(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(
-                name='hello_world_test',
-                path='example/tests',
-                test_options_tags=['no-remote'],
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        '    tags = [\n        "no-remote",\n    ],\n',
-        package='example/tests',
-    )
-
-  def test_generate_host_driven_test_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_test_module(name='hello_world_test', path='example/tests'),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_HOST_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        'tradefed_host_driven_device_test(', package='example/tests'
-    )
-
-  def test_generate_multi_config_device_test_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                test_module(name='hello_world_test', path='example/tests')
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set([
-            bazel_mode.Features.EXPERIMENTAL_HOST_DRIVEN_TEST,
-            bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST,
-        ]),
-    )
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl", '
-        '"tradefed_device_driven_test", '
-        '"tradefed_host_driven_device_test")\n',
-        package='example/tests',
-    )
-    self.assertTargetInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-    self.assertTargetInWorkspace(
-        'hello_world_test_host', package='example/tests'
-    )
-
-  def test_not_generate_host_driven_test_target_when_feature_disabled(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                test_module(name='hello_world_test', path='example/tests')
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-        ),
-    )
-
-    self.assertTargetInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-    self.assertTargetNotInWorkspace(
-        'hello_world_test_host', package='example/tests'
-    )
-
-  def test_raise_when_prerequisite_not_in_module_info(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(),
-        ]
-    )
-    del mod_info.name_to_module_info['aapt']
-
-    with self.assertRaises(Exception) as context:
-      self.run_generator(
-          mod_info,
-          enabled_features=set(
-              [bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST]
-          ),
-      )
-
-    self.assertIn('aapt', str(context.exception))
-
-
-class HostUnitTestModuleTestTargetGenerationTest(GenerationTestFixture):
-  """Tests for host unit test module test target generation."""
-
-  def test_generate_deviceless_test_import(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(name='hello_world_test'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl", "tradefed_deviceless_test")\n'
-    )
-
-  def test_generate_deviceless_test_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(
-                name='hello_world_test', path='example/tests'
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'tradefed_deviceless_test(\n'
-        '    name = "hello_world_test_host",\n'
-        '    module_name = "hello_world_test",\n'
-        '    test = "//example/tests:hello_world_test",\n'
-        ')',
-        package='example/tests',
-    )
-
-  def test_generate_target_with_tags(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(
-                name='hello_world_test',
-                path='example/tests',
-                test_options_tags=['no-remote'],
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    tags = [\n        "no-remote",\n    ],\n',
-        package='example/tests',
-    )
-
-  def test_generate_test_module_prebuilt(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(name='hello_world_test'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('hello_world_test')
-
-  def test_raise_when_prerequisite_not_in_module_info(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(),
-        ]
-    )
-    del mod_info.name_to_module_info['adb']
-
-    with self.assertRaises(Exception) as context:
-      self.run_generator(mod_info)
-
-    self.assertIn('adb', str(context.exception))
-
-  def test_raise_when_prerequisite_module_missing_path(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(),
-        ]
-    )
-    mod_info.name_to_module_info['adb'].get('path').clear()
-
-    with self.assertRaises(Exception) as context:
-      self.run_generator(mod_info)
-
-    self.assertIn('adb', str(context.exception))
-
-  def test_warning_when_prerequisite_module_has_multiple_path(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_unit_test_module(),
-        ]
-    )
-    mod_info.name_to_module_info['adb'].get('path').append('the/2nd/path')
-
-    with self.assertWarns(Warning) as context:
-      self.run_generator(mod_info)
-
-    self.assertIn('adb', str(context.warnings[0].message))
-
-
-class RemoteAvdTestTargetGenerationTest(GenerationTestFixture):
-  """Unit tests for generating Bazel targets on remote AVD."""
-
-  def setUp(self):
-    super().setUp()
-    super().add_device_def_to_filesystem()
-
-  def test_generate_remote_avd_test_target(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(name='hello_world_test', path='example/tests'),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set([
-            bazel_mode.Features.EXPERIMENTAL_REMOTE_AVD,
-            bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST,
-        ]),
-    )
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl",'
-        ' "tradefed_device_driven_test")\n',
-        package='example/tests',
-    )
-    self.assertDirInWorkspace('device_def')
-    self.assertTargetInWorkspace(
-        'hello_world_test_device', package='example/tests'
-    )
-
-  def test_generate_remote_avd_test_target_no_device_test_flag(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_test_module(name='hello_world_test', path='example/tests'),
-        ]
-    )
-
-    with self.assertRaises(Exception) as context:
-      self.run_generator(
-          mod_info,
-          enabled_features=set([bazel_mode.Features.EXPERIMENTAL_REMOTE_AVD]),
-      )
-
-    self.assertIn(
-        '--experimental-device-driven-test" flag is not set',
-        str(context.exception),
-    )
-
-
-class RobolectricTestModuleTestTargetGenerationTest(GenerationTestFixture):
-  """Tests for robolectric test module test target generation."""
-
-  def setUp(self):
-    super().setUp()
-    self.robolectric_template_path = (
-        self.resource_manager.get_resource_file_path(
-            bazel_mode.ROBOLECTRIC_CONFIG, True
-        )
-    )
-    self.fs.create_file(self.robolectric_template_path, contents='')
-    # ResourceManager only calculates md5 when registering files. So, it is
-    # necessary to call get_resource_file_path() again after writing files.
-    self.resource_manager.get_resource_file_path(
-        bazel_mode.ROBOLECTRIC_CONFIG, True
-    )
-
-  def test_generate_robolectric_test_target(self):
-    module_name = 'hello_world_test'
-    mod_info = self.create_module_info(
-        modules=[
-            robolectric_test_module(
-                name=f'{module_name}', compatibility_suites='robolectric-tests'
-            ),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_ROBOLECTRIC_TEST]
-        ),
-    )
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:tradefed_test.bzl",'
-        ' "tradefed_robolectric_test")\n',
-    )
-    self.assertTargetInWorkspace(f'{module_name}_host')
-
-  def test_not_generate_when_feature_disabled(self):
-    module_name = 'hello_world_test'
-    mod_info = self.create_module_info(
-        modules=[
-            robolectric_test_module(
-                name=f'{module_name}', compatibility_suites='robolectric-tests'
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetNotInWorkspace(f'{module_name}_host')
-
-  def test_not_generate_for_legacy_robolectric_test_type(self):
-    module_name = 'hello_world_test'
-    module_path = 'example/tests'
-    mod_info = self.create_module_info(
-        modules=[
-            robolectric_test_module(name=f'{module_name}', path=module_path),
-        ]
-    )
-
-    self.run_generator(
-        mod_info,
-        enabled_features=set(
-            [bazel_mode.Features.EXPERIMENTAL_ROBOLECTRIC_TEST]
-        ),
-    )
-
-    self.assertFileNotInWorkspace('BUILD.bazel', package=f'{module_path}')
-
-  def test_generate_jdk_target(self):
-    gen = self.create_workspace_generator(jdk_path=Path('jdk_src_root'))
-
-    gen.generate()
-
-    self.assertInBuildFile(
-        'filegroup(\n'
-        f'    name = "{bazel_mode.JDK_NAME}",\n'
-        '    srcs = glob([\n'
-        f'        "{bazel_mode.JDK_NAME}_files/**",\n',
-        package=f'{bazel_mode.JDK_PACKAGE_NAME}',
-    )
-
-  def test_not_generate_jdk_target_when_no_jdk_path(self):
-    gen = self.create_workspace_generator(jdk_path=None)
-
-    gen.generate()
-
-    self.assertFileNotInWorkspace(
-        'BUILD.bazel', package=f'{bazel_mode.JDK_PACKAGE_NAME}'
-    )
-
-  def test_create_symlinks_to_jdk(self):
-    jdk_path = Path('jdk_path')
-    gen = self.create_workspace_generator(jdk_path=jdk_path)
-
-    gen.generate()
-
-    self.assertSymlinkTo(
-        self.workspace_out_path.joinpath(
-            f'{bazel_mode.JDK_PACKAGE_NAME}/{bazel_mode.JDK_NAME}_files'
-        ),
-        self.resource_manager.get_src_file_path(f'{jdk_path}'),
-    )
-
-  def test_generate_android_all_target(self):
-    gen = self.create_workspace_generator(jdk_path=Path('jdk_src_root'))
-
-    gen.generate()
-
-    self.assertInBuildFile(
-        'filegroup(\n'
-        '    name = "android-all",\n'
-        '    srcs = glob([\n'
-        '        "android-all_files/**",\n',
-        package='android-all',
-    )
-
-  def test_not_generate_android_all_target_when_no_jdk_path(self):
-    gen = self.create_workspace_generator(jdk_path=None)
-
-    gen.generate()
-
-    self.assertFileNotInWorkspace('BUILD.bazel', package='android-all')
-
-  def test_create_symlinks_to_android_all(self):
-    module_name = 'android-all'
-    gen = self.create_workspace_generator(jdk_path=Path('jdk_src_root'))
-
-    gen.generate()
-
-    self.assertSymlinkTo(
-        self.workspace_out_path.joinpath(f'{module_name}/{module_name}_files'),
-        self.host_out_path.joinpath(f'testcases/{module_name}'),
-    )
-
-  def test_regenerate_workspace_when_robolectric_template_changed(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    with open(self.robolectric_template_path, 'a', encoding='utf8') as f:
-      f.write(' ')
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertNotEqual(workspace_stat, new_workspace_stat)
-
-  def test_not_regenerate_workspace_when_robolectric_template_touched(self):
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-    workspace_stat = workspace_generator.workspace_out_path.stat()
-
-    self.robolectric_template_path.touch()
-    workspace_generator = self.create_workspace_generator()
-    workspace_generator.generate()
-
-    new_workspace_stat = workspace_generator.workspace_out_path.stat()
-    self.assertEqual(workspace_stat, new_workspace_stat)
-
-
-class ModulePrebuiltTargetGenerationTest(GenerationTestFixture):
-  """Tests for module prebuilt target generation."""
-
-  def test_generate_prebuilt_import(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'load("//bazel/rules:soong_prebuilt.bzl", "soong_prebuilt")\n'
-    )
-
-  def test_generate_prebuilt_target_for_multi_config_test_module(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(supported_test_module(name='libhello')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'soong_prebuilt(\n'
-        '    name = "libhello",\n'
-        '    module_name = "libhello",\n'
-        '    files = select({\n'
-        '        "//bazel/rules:device": glob(["libhello/device/**/*"]),\n'
-        '        "//bazel/rules:host": glob(["libhello/host/**/*"]),\n'
-        '    }),\n'
-        '    suites = [\n'
-        '        "host-unit-tests",\n'
-        '    ],\n'
-        ')\n'
-    )
-
-  def test_create_symlinks_to_testcases_for_multi_config_test_module(self):
-    module_name = 'hello_world_test'
-    mod_info = self.create_module_info(
-        modules=[multi_config(supported_test_module(name=module_name))]
-    )
-    module_out_path = self.workspace_out_path.joinpath(module_name)
-
-    self.run_generator(mod_info)
-
-    self.assertSymlinkTo(
-        module_out_path.joinpath(f'host/testcases/{module_name}'),
-        self.host_out_path.joinpath(f'testcases/{module_name}'),
-    )
-    self.assertSymlinkTo(
-        module_out_path.joinpath(f'device/testcases/{module_name}'),
-        self.product_out_path.joinpath(f'testcases/{module_name}'),
-    )
-
-  def test_generate_files_for_host_only_test_module(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_only_config(supported_test_module(name='test1')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    files = select({\n'
-        '        "//bazel/rules:host": glob(["test1/host/**/*"]),\n'
-        '    }),\n'
-    )
-
-  def test_generate_files_for_device_only_test_module(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_only_config(supported_test_module(name='test1')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    files = select({\n'
-        '        "//bazel/rules:device": glob(["test1/device/**/*"]),\n'
-        '    }),\n'
-    )
-
-  def test_not_create_device_symlinks_for_host_only_test_module(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_only_config(supported_test_module(name='test1')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertFileNotInWorkspace('test1/device')
-
-  def test_not_create_host_symlinks_for_device_test_module(self):
-    mod_info = self.create_module_info(
-        modules=[
-            device_only_config(supported_test_module(name='test1')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertFileNotInWorkspace('test1/host')
-
-
-class ModuleSharedLibGenerationTest(GenerationTestFixture):
-  """Tests for module shared libs target generation."""
-
-  def test_not_generate_runtime_deps_when_all_configs_incompatible(self):
-    mod_info = self.create_module_info(
-        modules=[
-            host_only_config(supported_test_module(shared_libs=['libdevice'])),
-            device_only_config(module(name='libdevice')),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('runtime_deps')
-
-  def test_generate_runtime_deps_when_configs_compatible(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(supported_test_module(shared_libs=['libmulti'])),
-            multi_config_module(name='libmulti'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    runtime_deps = select({\n'
-        '        "//bazel/rules:device": [\n'
-        '            "//:libmulti",\n'
-        '        ],\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libmulti",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-
-  def test_generate_runtime_deps_when_configs_partially_compatible(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                supported_test_module(
-                    shared_libs=[
-                        'libhost',
-                    ]
-                )
-            ),
-            host_module(name='libhost'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    runtime_deps = select({\n'
-        '        "//bazel/rules:device": [\n'
-        '        ],\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libhost",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-
-  def test_generate_runtime_deps_with_mixed_compatibility(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                supported_test_module(
-                    shared_libs=['libhost', 'libdevice', 'libmulti']
-                )
-            ),
-            host_module(name='libhost'),
-            device_module(name='libdevice'),
-            multi_config_module(name='libmulti'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    runtime_deps = select({\n'
-        '        "//bazel/rules:device": [\n'
-        '            "//:libdevice",\n'
-        '            "//:libmulti",\n'
-        '        ],\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libhost",\n'
-        '            "//:libmulti",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-
-  def test_generate_runtime_deps_recursively(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                supported_test_module(
-                    shared_libs=[
-                        'libdirect',
-                    ]
-                )
-            ),
-            multi_config_module(
-                name='libdirect',
-                shared_libs=[
-                    'libtransitive',
-                ],
-            ),
-            multi_config_module(name='libtransitive'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('libtransitive')
-
-  def test_generate_shared_runtime_deps_once(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                supported_test_module(
-                    shared_libs=[
-                        'libleft',
-                        'libright',
-                    ]
-                )
-            ),
-            multi_config_module(
-                name='libleft',
-                shared_libs=[
-                    'libshared',
-                ],
-            ),
-            multi_config_module(
-                name='libright',
-                shared_libs=[
-                    'libshared',
-                ],
-            ),
-            multi_config_module(name='libshared'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('libshared')
-
-  def test_generate_runtime_deps_in_order(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello2', 'libhello1']),
-            host_module(name='libhello1'),
-            host_module(name='libhello2'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '            "//:libhello1",\n            "//:libhello2",\n'
-    )
-
-  def test_generate_target_for_shared_lib(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            host_module(name='libhello'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('libhello')
-
-  def test_not_generate_for_missing_shared_lib_module(self):
-    mod_info = self.create_module_info(
-        modules=[supported_test_module(shared_libs=['libhello'])]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('            "//:libhello",\n')
-    self.assertTargetNotInWorkspace('libhello')
-
-  def test_not_generate_when_shared_lib_uninstalled(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            host_module(name='libhello', installed=[]),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('            "//:libhello",\n')
-    self.assertTargetNotInWorkspace('libhello')
-
-  def test_not_generate_when_shared_lib_installed_path_unsupported(self):
-    unsupported_install_path = 'out/other'
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            shared_lib(
-                module('libhello', installed=[unsupported_install_path])
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('"//:libhello",\n')
-    self.assertTargetNotInWorkspace('libhello')
-
-  def test_not_generate_when_shared_lib_install_path_ambiguous(self):
-    ambiguous_install_path = 'out/f1'
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            module(name='libhello', installed=[ambiguous_install_path]),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('"//:libhello",\n')
-    self.assertTargetNotInWorkspace('libhello')
-
-  def test_generate_target_for_rlib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            multi_config(
-                host_unit_suite(
-                    module(
-                        name='hello_world_test',
-                        dependencies=['libhost', 'libdevice'],
-                    )
-                )
-            ),
-            rlib(module(name='libhost', supported_variants=['HOST'])),
-            rlib(module(name='libdevice', supported_variants=['DEVICE'])),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'soong_uninstalled_prebuilt(\n'
-        '    name = "libhost",\n'
-        '    module_name = "libhost",\n'
-        ')\n'
-    )
-    self.assertInBuildFile(
-        'soong_uninstalled_prebuilt(\n'
-        '    name = "libdevice",\n'
-        '    module_name = "libdevice",\n'
-        ')\n'
-    )
-    self.assertInBuildFile(
-        '    runtime_deps = select({\n'
-        '        "//bazel/rules:device": [\n'
-        '            "//:libdevice",\n'
-        '        ],\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libhost",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-
-  def test_generate_target_for_rlib_dylib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(dependencies=['libhello']),
-            rlib(module(name='libhello', dependencies=['libworld'])),
-            host_only_config(dylib(module(name='libworld'))),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetInWorkspace('libworld')
-
-  def test_generate_target_for_dylib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(dependencies=['libhello']),
-            host_only_config(dylib(module(name='libhello'))),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'soong_prebuilt(\n'
-        '    name = "libhello",\n'
-        '    module_name = "libhello",\n'
-    )
-
-  def test_generate_target_for_uninstalled_dylib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(dependencies=['libhello']),
-            dylib(module(name='libhello', installed=[])),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        'soong_uninstalled_prebuilt(\n'
-        '    name = "libhello",\n'
-        '    module_name = "libhello",\n'
-        ')\n'
-    )
-
-  def test_not_generate_target_for_non_runtime_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(dependencies=['libhello']),
-            host_module(name='libhello', classes=['NOT_SUPPORTED']),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertNotInBuildFile('"//:libhello",\n')
-    self.assertTargetNotInWorkspace('libhello')
-
-  def test_generate_target_for_runtime_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(runtime_dependencies=['libhello']),
-            host_only_config(
-                module(name='libhello', classes=['SHARED_LIBRARIES'])
-            ),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    runtime_deps = select({\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libhello",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-
-
-class SharedLibPrebuiltTargetGenerationTest(GenerationTestFixture):
-  """Tests for runtime dependency module prebuilt target generation."""
-
-  def test_create_multi_config_target_symlinks(self):
-    host_file1 = self.host_out_path.joinpath('a/b/f1')
-    host_file2 = self.host_out_path.joinpath('a/c/f2')
-    device_file1 = self.product_out_path.joinpath('a/b/f1')
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            multi_config_module(
-                name='libhello',
-                installed=[str(host_file1), str(host_file2), str(device_file1)],
-            ),
-        ]
-    )
-    package_path = self.workspace_out_path
-
-    self.run_generator(mod_info)
-
-    self.assertSymlinkTo(
-        package_path.joinpath('libhello/host/a/b/f1'), host_file1
-    )
-    self.assertSymlinkTo(
-        package_path.joinpath('libhello/host/a/c/f2'), host_file2
-    )
-    self.assertSymlinkTo(
-        package_path.joinpath('libhello/device/a/b/f1'), device_file1
-    )
-
-  def test_create_symlinks_to_installed_path_for_non_tf_testable_deps(self):
-    host_file = self.host_out_path.joinpath('a/b/f1')
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            host_module(
-                name='libhello',
-                installed=[str(host_file)],
-            ),
-        ]
-    )
-    package_path = self.workspace_out_path
-
-    self.run_generator(mod_info)
-
-    self.assertSymlinkTo(
-        package_path.joinpath('libhello/host/a/b/f1'), host_file
-    )
-
-  def test_create_symlinks_to_installed_path_for_lib_with_test_config(self):
-    host_file = self.host_out_path.joinpath('a/b/f1')
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            host_module(
-                name='libhello', installed=[str(host_file)], path='src/lib'
-            ),
-        ]
-    )
-    self.fs.create_file(Path('src/lib/AndroidTest.xml'), contents='')
-    package_path = self.workspace_out_path
-
-    self.run_generator(mod_info)
-
-    self.assertSymlinkTo(
-        package_path.joinpath('src/lib/libhello/host/a/b/f1'), host_file
-    )
-
-  def test_generate_for_host_only_shared_lib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            host_module(name='libhello'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    files = select({\n'
-        '        "//bazel/rules:host": glob(["libhello/host/**/*"]),\n'
-        '    }),\n'
-    )
-    self.assertFileNotInWorkspace('libhello/device')
-
-  def test_generate_for_device_only_shared_lib_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(shared_libs=['libhello']),
-            device_module(name='libhello'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    files = select({\n'
-        '        "//bazel/rules:device": glob(["libhello/device/**/*"]),\n'
-        '    }),\n'
-    )
-    self.assertFileNotInWorkspace('libhello/host')
-
-
-class DataDependenciesGenerationTest(GenerationTestFixture):
-  """Tests for module data dependencies target generation."""
-
-  def test_generate_target_for_data_dependency(self):
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(data_dependencies=['libdata']),
-            host_module(name='libdata'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertInBuildFile(
-        '    data = select({\n'
-        '        "//bazel/rules:host": [\n'
-        '            "//:libdata",\n'
-        '        ],\n'
-        '    }),\n'
-    )
-    self.assertTargetInWorkspace('libdata')
-
-  def test_not_generate_target_for_data_file(self):
-    # Data files are included in "data", but not in "data_dependencies".
-    mod_info = self.create_module_info(
-        modules=[
-            supported_test_module(data=['libdata']),
-            host_module(name='libdata'),
-        ]
-    )
-
-    self.run_generator(mod_info)
-
-    self.assertTargetNotInWorkspace('libdata')
-
-
-def create_empty_module_info():
-  return module_info.load_from_dict({})
-
-
-def create_module_info(modules=None):
-  mod_info = create_empty_module_info()
-  modules = modules or []
-
-  for m in modules:
-    mod_info.name_to_module_info[m['module_name']] = m
-
-  return mod_info
-
-
-def host_unit_test_module(**kwargs):
-  return host_unit_suite(host_test_module(**kwargs))
-
-
-# We use the below alias in situations where the actual type is irrelevant to
-# the test as long as it is supported in Bazel mode.
-supported_test_module = host_unit_test_module
-
-
-def host_test_module(**kwargs):
-  kwargs.setdefault('name', 'hello_world_test')
-  return host_only_config(test_module(**kwargs))
-
-
-def device_test_module(**kwargs):
-  kwargs.setdefault('name', 'hello_world_test')
-  return device_only_config(test_module(**kwargs))
-
-
-def robolectric_test_module(**kwargs):
-  kwargs.setdefault('name', 'hello_world_test')
-  return host_only_config(robolectric(test_module(**kwargs)))
-
-
-def host_module(**kwargs):
-  m = module(**kwargs)
-
-  if 'installed' in kwargs:
-    return m
-
-  return host_only_config(m)
-
-
-def device_module(**kwargs):
-  m = module(**kwargs)
-
-  if 'installed' in kwargs:
-    return m
-
-  return device_only_config(m)
-
-
-def multi_config_module(**kwargs):
-  m = module(**kwargs)
-
-  if 'installed' in kwargs:
-    return m
-
-  return multi_config(m)
-
-
-def test_module(**kwargs):
-  kwargs.setdefault('name', 'hello_world_test')
-  return test(module(**kwargs))
-
-
-# TODO(b/274822450): Using a builder pattern to reduce the number of parameters
-#  instead of disabling the warning.
-# pylint: disable=too-many-arguments
-# pylint: disable=too-many-locals
-def module(
-    name=None,
-    path=None,
-    installed=None,
-    classes=None,
-    auto_test_config=None,
-    shared_libs=None,
-    dependencies=None,
-    runtime_dependencies=None,
-    data=None,
-    data_dependencies=None,
-    compatibility_suites=None,
-    host_dependencies=None,
-    target_dependencies=None,
-    test_options_tags=None,
-    supported_variants=None,
-):
-  name = name or 'libhello'
-
-  m = {}
-
-  m['module_name'] = name
-  m['class'] = classes or ['']
-  m['path'] = [path or '']
-  m['installed'] = installed or []
-  m['is_unit_test'] = 'false'
-  m['auto_test_config'] = auto_test_config or []
-  m['shared_libs'] = shared_libs or []
-  m['runtime_dependencies'] = runtime_dependencies or []
-  m['dependencies'] = dependencies or []
-  m['data'] = data or []
-  m['data_dependencies'] = data_dependencies or []
-  m['compatibility_suites'] = compatibility_suites or []
-  m['host_dependencies'] = host_dependencies or []
-  m['target_dependencies'] = target_dependencies or []
-  m['test_options_tags'] = test_options_tags or []
-  m['supported_variants'] = supported_variants or []
-  return m
-
-
-def test(info):
-  info['auto_test_config'] = ['true']
-  return info
-
-
-def shared_lib(info):
-  info['class'] = ['SHARED_LIBRARIES']
-  return info
-
-
-def rlib(info):
-  info['class'] = ['RLIB_LIBRARIES']
-  info['installed'] = []
-  return info
-
-
-def dylib(info):
-  info['class'] = ['DYLIB_LIBRARIES']
-  return info
-
-
-def robolectric(info):
-  info['class'] = ['ROBOLECTRIC']
-  return info
-
-
-def host_unit_suite(info):
-  info = test(info)
-  info.setdefault('compatibility_suites', []).append('host-unit-tests')
-  return info
-
-
-def multi_config(info):
-  name = info.get('module_name', 'lib')
-  info['installed'] = [
-      f'out/host/linux-x86/{name}/{name}.jar',
-      f'out/product/vsoc_x86/{name}/{name}.apk',
-  ]
-  info['supported_variants'] = [
-      'DEVICE',
-      'HOST',
-  ]
-  return info
-
-
-def host_only_config(info):
-  name = info.get('module_name', 'lib')
-  info['installed'] = [
-      f'out/host/linux-x86/{name}/{name}.jar',
-  ]
-  info['supported_variants'] = [
-      'HOST',
-  ]
-  return info
-
-
-def device_only_config(info):
-  name = info.get('module_name', 'lib')
-  info['installed'] = [
-      f'out/product/vsoc_x86/{name}/{name}.jar',
-  ]
-  info['supported_variants'] = [
-      'DEVICE',
-  ]
-  return info
-
-
-class PackageTest(fake_filesystem_unittest.TestCase):
-  """Tests for Package."""
-
-  class FakeTarget(bazel_mode.Target):
-    """Fake target used for tests."""
-
-    def __init__(self, name, imports=None):
-      self._name = name
-      self._imports = imports or set()
-
-    def name(self):
-      return self._name
-
-    def required_imports(self):
-      return self._imports
-
-    def write_to_build_file(self, f):
-      f.write(f'{self._name}\n')
-
-  def setUp(self):
-    self.setUpPyfakefs()
-    self.workspace_out_path = Path('/workspace_out_path')
-    self.workspace_out_path.mkdir()
-
-  def test_raise_when_adding_existing_target(self):
-    target_name = '<fake_target>'
-    package = bazel_mode.Package('p')
-    package.add_target(self.FakeTarget(target_name))
-
-    with self.assertRaises(Exception) as context:
-      package.add_target(self.FakeTarget(target_name))
-
-    self.assertIn(target_name, str(context.exception))
-
-  def test_write_build_file_in_package_dir(self):
-    package_path = 'abc/def'
-    package = bazel_mode.Package(package_path)
-    expected_path = self.workspace_out_path.joinpath(
-        package_path, 'BUILD.bazel'
-    )
-
-    package.generate(self.workspace_out_path)
-
-    self.assertTrue(expected_path.exists())
-
-  def test_write_load_statements_in_sorted_order(self):
-    package = bazel_mode.Package('p')
-    target1 = self.FakeTarget(
-        'target1',
-        imports={
-            bazel_mode.Import('z.bzl', 'symbol1'),
-        },
-    )
-    target2 = self.FakeTarget(
-        'target2',
-        imports={
-            bazel_mode.Import('a.bzl', 'symbol2'),
-        },
-    )
-    package.add_target(target1)
-    package.add_target(target2)
-
-    package.generate(self.workspace_out_path)
-
-    self.assertIn(
-        'load("a.bzl", "symbol2")\nload("z.bzl", "symbol1")\n\n',
-        self.package_build_file_text(package),
-    )
-
-  def test_write_load_statements_with_symbols_grouped_by_bzl(self):
-    package = bazel_mode.Package('p')
-    target1 = self.FakeTarget(
-        'target1',
-        imports={
-            bazel_mode.Import('a.bzl', 'symbol1'),
-            bazel_mode.Import('a.bzl', 'symbol3'),
-        },
-    )
-    target2 = self.FakeTarget(
-        'target2',
-        imports={
-            bazel_mode.Import('a.bzl', 'symbol2'),
-        },
-    )
-    package.add_target(target1)
-    package.add_target(target2)
-
-    package.generate(self.workspace_out_path)
-
-    self.assertIn(
-        'load("a.bzl", "symbol1", "symbol2", "symbol3")\n\n',
-        self.package_build_file_text(package),
-    )
-
-  def test_write_targets_in_add_order(self):
-    package = bazel_mode.Package('p')
-    target1 = self.FakeTarget('target1')
-    target2 = self.FakeTarget('target2')
-    package.add_target(target2)  # Added out of order.
-    package.add_target(target1)
-
-    package.generate(self.workspace_out_path)
-
-    self.assertIn('target2\n\ntarget1\n', self.package_build_file_text(package))
-
-  def test_generate_parent_package_when_nested_exists(self):
-    parent_path = Path('parent')
-    parent = bazel_mode.Package(parent_path.name)
-    nested = bazel_mode.Package(parent_path.joinpath('nested'))
-    nested.generate(self.workspace_out_path)
-
-    parent.generate(self.workspace_out_path)
-
-    self.assertTrue(self.workspace_out_path.joinpath(parent_path).is_dir())
-
-  def package_build_file_text(self, package):
-    return self.workspace_out_path.joinpath(
-        package.path, 'BUILD.bazel'
-    ).read_text(encoding='utf8')
-
-
-class DecorateFinderMethodTest(GenerationTestFixture):
-  """Tests for _decorate_find_method()."""
-
-  def test_host_unit_test_with_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[host_unit_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info, original_finder, host=True
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_host_unit_test_without_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[host_unit_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info, original_finder, host=False
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_device_test_with_host_arg_runner_is_preserved(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[device_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info,
-        original_finder,
-        host=True,
-        enabled_features=[bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST],
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, ATEST_TF_RUNNER)
-
-  def test_device_test_without_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[device_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info,
-        original_finder,
-        host=False,
-        enabled_features=[bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST],
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_multi_config_test_with_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[multi_config(supported_test_module(name=MODULE_NAME))]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info,
-        original_finder,
-        host=True,
-        enabled_features=[bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST],
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_multi_config_test_without_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[multi_config(supported_test_module(name=MODULE_NAME))]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info,
-        original_finder,
-        host=False,
-        enabled_features=[bazel_mode.Features.EXPERIMENTAL_DEVICE_DRIVEN_TEST],
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_host_non_unit_test_with_host_arg_runner_is_overridden(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[host_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info,
-        original_finder,
-        host=True,
-        enabled_features=[bazel_mode.Features.EXPERIMENTAL_HOST_DRIVEN_TEST],
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, BAZEL_RUNNER)
-
-  def test_disable_device_driven_test_feature_runner_is_preserved(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[device_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info, original_finder, host=False
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, ATEST_TF_RUNNER)
-
-  def test_disable_host_driven_test_feature_runner_is_preserved(self):
-    def original_find_method(obj, test_id):
-      return self.create_single_test_infos(
-          obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-      )
-
-    mod_info = self.create_module_info(
-        modules=[host_test_module(name=MODULE_NAME)]
-    )
-    original_finder = self.create_finder(mod_info, original_find_method)
-    new_finder = bazel_mode.create_new_finder(
-        mod_info, original_finder, host=True
-    )
-
-    test_infos = new_finder.find_method(
-        new_finder.test_finder_instance, MODULE_NAME
-    )
-
-    self.assertEqual(len(test_infos), 1)
-    self.assertEqual(test_infos[0].test_runner, ATEST_TF_RUNNER)
-
-  # pylint: disable=unused-argument
-  def create_single_test_infos(
-      self, obj, test_id, test_name=MODULE_NAME, runner=ATEST_TF_RUNNER
-  ):
-    """Create list of test_info.TestInfo."""
-    return [test_info.TestInfo(test_name, runner, MODULE_BUILD_TARGETS)]
-
-  def create_finder(self, mod_info, find_method):
-    return test_finder_base.Finder(
-        example_finder.ExampleFinder(mod_info), find_method, 'FINDER_NAME'
-    )
-
-
-class BazelTestRunnerTest(fake_filesystem_unittest.TestCase):
-  """Tests for BazelTestRunner."""
-
-  def test_return_empty_build_reqs_when_no_test_infos(self):
-    run_command = self.mock_run_command(side_effect=Exception(''))
-    runner = self.create_bazel_test_runner(
-        modules=[
-            supported_test_module(name='test1', path='path1'),
-        ],
-        run_command=run_command,
-    )
-
-    reqs = runner.get_test_runner_build_reqs([])
-
-    self.assertFalse(reqs)
-
-  def test_query_bazel_test_targets_deps_with_host_arg(self):
-    query_file_contents = StringIO()
-
-    def get_query_file_content(args: List[str], _) -> str:
-      query_file_contents.write(_get_query_file_content(args))
-      return ''
-
-    runner = self.create_bazel_test_runner(
-        modules=[
-            multi_config(host_unit_test_module(name='test1', path='path1')),
-            multi_config(host_unit_test_module(name='test2', path='path2')),
-            multi_config(test_module(name='test3', path='path3')),
-        ],
-        run_command=get_query_file_content,
-        host=True,
-    )
-
-    runner.get_test_runner_build_reqs([
-        test_info_of('test2'),
-        test_info_of('test1'),  # Intentionally out of order.
-        test_info_of('test3'),
-    ])
-
-    self.assertEqual(
-        'deps(tests(//path1:test1_host + '
-        '//path2:test2_host + '
-        '//path3:test3_host))',
-        query_file_contents.getvalue(),
-    )
-
-  def test_query_bazel_test_targets_deps_without_host_arg(self):
-    query_file_contents = StringIO()
-
-    def get_query_file_content(args: List[str], _) -> str:
-      query_file_contents.write(_get_query_file_content(args))
-      return ''
-
-    runner = self.create_bazel_test_runner(
-        modules=[
-            multi_config(host_unit_test_module(name='test1', path='path1')),
-            host_unit_test_module(name='test2', path='path2'),
-            multi_config(test_module(name='test3', path='path3')),
-        ],
-        run_command=get_query_file_content,
-    )
-
-    runner.get_test_runner_build_reqs([
-        test_info_of('test2'),
-        test_info_of('test1'),
-        test_info_of('test3'),
-    ])
-
-    self.assertEqual(
-        'deps(tests(//path1:test1_device + '
-        '//path2:test2_host + '
-        '//path3:test3_device))',
-        query_file_contents.getvalue(),
-    )
-
-  def test_trim_whitespace_in_bazel_query_output(self):
-    run_command = self.mock_run_command(
-        return_value='\n'.join(['  test1:host  ', 'test2:device  ', '  '])
-    )
-    runner = self.create_bazel_test_runner(
-        modules=[
-            supported_test_module(name='test1', path='path1'),
-        ],
-        run_command=run_command,
-    )
-
-    reqs = runner.get_test_runner_build_reqs([test_info_of('test1')])
-
-    self.assertSetEqual({'test1-host', 'test2-target'}, reqs)
-
-  def test_build_variants_in_bazel_query_output(self):
-    run_command = self.mock_run_command(
-        return_value='\n'.join([
-            'test1:host',
-            'test2:host',
-            'test2:device',
-            'test3:device',
-            'test4:host',
-            'test4:host',
-        ])
-    )
-    runner = self.create_bazel_test_runner(
-        modules=[
-            supported_test_module(name='test1', path='path1'),
-            supported_test_module(name='test2', path='path2'),
-            supported_test_module(name='test3', path='path3'),
-            supported_test_module(name='test4', path='path4'),
-        ],
-        run_command=run_command,
-    )
-
-    reqs = runner.get_test_runner_build_reqs([
-        test_info_of('test1'),
-        test_info_of('test2'),
-        test_info_of('test3'),
-        test_info_of('test4'),
-    ])
-
-    self.assertSetEqual(
-        {'test1-host', 'test2', 'test3-target', 'test4-host'}, reqs
-    )
-
-  def test_generate_single_run_command(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(test_infos, {})
-
-    self.assertEqual(1, len(cmd))
-
-  def test_generate_run_command_containing_targets_with_host_arg(self):
-    test_infos = [
-        test_info_of('test1'),
-        test_info_of('test2'),
-        test_info_of('test3'),
-    ]
-    runner = self.create_bazel_test_runner(
-        [
-            multi_config(host_unit_test_module(name='test1', path='path')),
-            multi_config(host_unit_test_module(name='test2', path='path')),
-            multi_config(test_module(name='test3', path='path')),
-        ],
-        host=True,
-    )
-
-    cmd = runner.generate_run_commands(test_infos, {})
-
-    self.assertTokensIn(
-        ['//path:test1_host', '//path:test2_host', '//path:test3_host'], cmd[0]
-    )
-
-  def test_generate_run_command_containing_targets_without_host_arg(self):
-    test_infos = [test_info_of('test1'), test_info_of('test2')]
-    runner = self.create_bazel_test_runner(
-        [
-            multi_config(host_unit_test_module(name='test1', path='path')),
-            host_unit_test_module(name='test2', path='path'),
-        ],
-    )
-
-    cmd = runner.generate_run_commands(test_infos, {})
-
-    self.assertTokensIn(['//path:test1_device', '//path:test2_host'], cmd[0])
-
-  def test_generate_run_command_with_multi_bazel_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {
-        constants.BAZEL_ARG: [['--option1=value1'], ['--option2=value2']]
-    }
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(['--option1=value1', '--option2=value2'], cmd[0])
-
-  def test_generate_run_command_with_multi_custom_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.CUSTOM_ARGS: ['-hello', '--world=value']}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(
-        ['--test_arg=-hello', '--test_arg=--world=value'], cmd[0]
-    )
-
-  def test_generate_run_command_with_custom_and_bazel_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {
-        constants.CUSTOM_ARGS: ['-hello', '--world=value'],
-        constants.BAZEL_ARG: [['--option1=value1']],
-    }
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(
-        ['--test_arg=-hello', '--test_arg=--world=value', '--option1=value1'],
-        cmd[0],
-    )
-
-  def test_generate_run_command_removes_serial(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.CUSTOM_ARGS: ['--serial=0.0.0.0']}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertNotIn('--test-arg=--serial', shlex.split(cmd[0]))
-    self.assertNotIn('--test-arg=--0.0.0.0', shlex.split(cmd[0]))
-
-  def test_generate_run_command_with_tf_supported_all_abi_arg(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.ALL_ABI: True}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(['--test_arg=--all-abi'], cmd[0])
-
-  def test_generate_run_command_with_iterations_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.ITERATIONS: 2}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(['--runs_per_test=2'], cmd[0])
-    self.assertNotIn('--test_arg=--retry-strategy', shlex.split(cmd[0]))
-
-  def test_generate_run_command_with_testinfo_filter(self):
-    test_filter = test_filter_of('class1', ['method1'])
-    test_infos = [test_info_of('test1', test_filters=[test_filter])]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(test_infos, {})
-
-    self.assertTokensIn(
-        [
-            '--test_arg=--atest-include-filter',
-            '--test_arg=test1:class1#method1',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_bes_publish_enabled(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [
-            bazel_mode.Features.EXPERIMENTAL_BES_PUBLISH
-        ]
-    }
-    build_metadata = bazel_mode.BuildMetadata(
-        'master', 'aosp_cf_x86_64_phone-userdebug'
-    )
-    env = {
-        'ATEST_BAZELRC': '/dir/atest.bazelrc',
-        'ATEST_BAZEL_BES_PUBLISH_CONFIG': 'bes_publish',
-    }
-    runner = self.create_bazel_test_runner_for_tests(
-        test_infos, build_metadata=build_metadata, env=env
-    )
-
-    cmd = runner.generate_run_commands(
-        test_infos,
-        extra_args,
-    )
-
-    self.assertTokensIn(
-        [
-            '--bazelrc=/dir/atest.bazelrc',
-            '--config=bes_publish',
-            '--build_metadata=ab_branch=master',
-            '--build_metadata=ab_target=aosp_cf_x86_64_phone-userdebug',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_no_bazel_detailed_summary(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [
-            bazel_mode.Features.NO_BAZEL_DETAILED_SUMMARY
-        ]
-    }
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensNotIn(
-        [
-            '--test_summary=detailed',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_without_no_bazel_detailed_summary(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {}
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(
-        [
-            '--test_summary=detailed',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_return_until_failure(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {constants.RERUN_UNTIL_FAILURE: 5}
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(
-        [
-            '--test_arg=--retry-strategy',
-            '--test_arg=RERUN_UNTIL_FAILURE',
-            '--test_arg=--max-testcase-run-count',
-            '--test_arg=5',
-        ],
-        cmd[0],
-    )
-
-  def test_not_zip_test_output_files_when_bes_publish_not_enabled(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {}
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    cmd = runner.generate_run_commands(
-        test_infos,
-        extra_args,
-    )
-
-    self.assertTokensIn(
-        [
-            '--nozip_undeclared_test_outputs',
-        ],
-        cmd[0],
-    )
-
-  def test_zip_test_output_files_when_bes_publish_enabled(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [
-            bazel_mode.Features.EXPERIMENTAL_BES_PUBLISH
-        ]
-    }
-    build_metadata = bazel_mode.BuildMetadata(
-        'master', 'aosp_cf_x86_64_phone-userdebug'
-    )
-    env = {
-        'ATEST_BAZELRC': '/dir/atest.bazelrc',
-        'ATEST_BAZEL_BES_PUBLISH_CONFIG': 'bes_publish',
-    }
-    runner = self.create_bazel_test_runner_for_tests(
-        test_infos, build_metadata=build_metadata, env=env
-    )
-
-    cmd = runner.generate_run_commands(
-        test_infos,
-        extra_args,
-    )
-
-    self.assertTokensNotIn(
-        [
-            '--nozip_undeclared_test_outputs',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_remote_enabled(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [bazel_mode.Features.EXPERIMENTAL_REMOTE]
-    }
-    env = {
-        'ATEST_BAZELRC': '/dir/atest.bazelrc',
-        'ATEST_BAZEL_REMOTE_CONFIG': 'remote_deviceless',
-    }
-    runner = self.create_bazel_test_runner_for_tests(test_infos, env=env)
-
-    cmd = runner.generate_run_commands(
-        test_infos,
-        extra_args,
-    )
-
-    self.assertTokensIn(
-        [
-            '--config=remote_deviceless',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_remote_avd_enabled(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [
-            bazel_mode.Features.EXPERIMENTAL_REMOTE_AVD
-        ]
-    }
-    env = {
-        'ATEST_BAZELRC': '/dir/atest.bazelrc',
-        'ATEST_BAZEL_REMOTE_AVD_CONFIG': 'remote_avd',
-    }
-    runner = self.create_bazel_test_runner_for_tests(test_infos, env=env)
-
-    cmd = runner.generate_run_commands(
-        test_infos,
-        extra_args,
-    )
-
-    self.assertTokensIn(
-        [
-            '--config=remote_avd',
-        ],
-        cmd[0],
-    )
-
-  def test_generate_run_command_with_remote_avd_config_not_found(self):
-    test_infos = [test_info_of('test1')]
-    extra_args = {
-        constants.BAZEL_MODE_FEATURES: [
-            bazel_mode.Features.EXPERIMENTAL_REMOTE_AVD
-        ]
-    }
-    env = {
-        'ATEST_BAZELRC': '/dir/atest.bazelrc',
-    }
-    runner = self.create_bazel_test_runner_for_tests(test_infos, env=env)
-
-    with self.assertRaises(Exception) as context:
-      runner.generate_run_commands(
-          test_infos,
-          extra_args,
-      )
-
-    self.assertIn(
-        'ATEST_BAZEL_REMOTE_AVD_CONFIG environment variable is not set.',
-        str(context.exception),
-    )
-
-  def test_generate_run_command_with_verbose_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.VERBOSE: True}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(['--test_output=all'], cmd[0])
-
-  def test_disable_test_result_caching_with_wait_for_debug_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {constants.WAIT_FOR_DEBUGGER: True}
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensIn(
-        ['--test_arg=--wait-for-debugger', '--cache_test_results=no'], cmd[0]
-    )
-
-  def test_cache_test_results_arg_not_used_with_wait_for_debug_args(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    extra_args = {
-        constants.WAIT_FOR_DEBUGGER: True,
-        constants.BAZEL_ARG: [['--cache_test_resultsfoo']],
-    }
-
-    cmd = runner.generate_run_commands(test_infos, extra_args)
-
-    self.assertTokensNotIn(['--cache_test_resultsfoo'], cmd[0])
-
-  def test_retrieve_test_output_info_for_host_test(self):
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    output_file_path, package_name, target_suffix = (
-        runner.retrieve_test_output_info(test_infos[0])
-    )
-
-    self.assertEqual(
-        f'/src/workspace/{bazel_mode.BAZEL_TEST_LOGS_DIR_NAME}'
-        f'/path/test1_host/{bazel_mode.TEST_OUTPUT_DIR_NAME}',
-        str(output_file_path),
-    )
-    self.assertEqual('path', package_name)
-    self.assertEqual('host', target_suffix)
-
-  def test_retrieve_test_output_info_for_device_driven_test(self):
-    runner = self.create_bazel_test_runner(
-        modules=[
-            multi_config(device_test_module(name='test1', path='path1')),
-        ],
-    )
-
-    output_file_path, package_name, target_suffix = (
-        runner.retrieve_test_output_info(test_info_of('test1'))
-    )
-
-    self.assertEqual(
-        f'/src/workspace/{bazel_mode.BAZEL_TEST_LOGS_DIR_NAME}'
-        f'/path1/test1_device/{bazel_mode.TEST_OUTPUT_DIR_NAME}',
-        str(output_file_path),
-    )
-    self.assertEqual('path1', package_name)
-    self.assertEqual('device', target_suffix)
-
-  def test_result_dir_symlink_to_test_output_dir(self):
-    self.setUpPyfakefs()
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    runner.organize_test_logs(test_infos)
-
-    self.assertSymlinkTo(
-        Path('result_dir/log/path/test1_host'),
-        Path(
-            f'/src/workspace/{bazel_mode.BAZEL_TEST_LOGS_DIR_NAME}'
-            f'/path/test1_host/{bazel_mode.TEST_OUTPUT_DIR_NAME}'
-        ),
-    )
-
-  def test_not_create_result_log_dir_when_test_output_zip_exist(self):
-    self.setUpPyfakefs()
-    test_infos = [test_info_of('test1')]
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-    test_output_zip = Path(
-        f'/src/workspace/{bazel_mode.BAZEL_TEST_LOGS_DIR_NAME}'
-        f'/path/test1_host/{bazel_mode.TEST_OUTPUT_DIR_NAME}'
-        f'/{bazel_mode.TEST_OUTPUT_ZIP_NAME}'
-    )
-    self.fs.create_file(test_output_zip, contents='')
-
-    runner.organize_test_logs(test_infos)
-
-    self.assertFalse(Path('result_dir/log/').exists())
-
-  def test_avoid_result_dir_symlink_duplication(self):
-    self.setUpPyfakefs()
-    test_infos = [test_info_of('test1')]
-    old_symlink_to_dir = Path(tempfile.mkdtemp())
-    log_path = Path('result_dir/log/path/test1_host')
-    log_path.parent.mkdir(parents=True, exist_ok=True)
-    log_path.symlink_to(old_symlink_to_dir)
-    runner = self.create_bazel_test_runner_for_tests(test_infos)
-
-    runner.organize_test_logs(test_infos)
-
-    self.assertSymlinkTo(log_path, old_symlink_to_dir)
-
-  def create_bazel_test_runner(
-      self,
-      modules,
-      run_command=None,
-      host=False,
-      build_metadata=None,
-      env=None,
-      enable_features=None,
-  ):
-    return bazel_mode.BazelTestRunner(
-        'result_dir',
-        mod_info=create_module_info(modules),
-        src_top=Path('/src'),
-        workspace_path=Path('/src/workspace'),
-        run_command=run_command or self.mock_run_command(),
-        extra_args={constants.HOST: host},
-        build_metadata=build_metadata,
-        env=env,
-        generate_workspace_fn=lambda *_: None,
-        enabled_features=enable_features or [],
-    )
-
-  def create_bazel_test_runner_for_tests(
-      self, test_infos, build_metadata=None, env=None
-  ):
-    return self.create_bazel_test_runner(
-        modules=[
-            supported_test_module(name=t.test_name, path='path')
-            for t in test_infos
-        ],
-        build_metadata=build_metadata,
-        env=env,
-    )
-
-  def create_completed_process(self, args, returncode, stdout):
-    return subprocess.CompletedProcess(args, returncode, stdout)
-
-  def mock_run_command(self, **kwargs):
-    return mock.create_autospec(bazel_mode.default_run_command, **kwargs)
-
-  def assertTokensIn(self, expected_tokens, s):
-    tokens = shlex.split(s)
-    for token in expected_tokens:
-      self.assertIn(token, tokens)
-
-  def assertTokensNotIn(self, unexpected_tokens, s):
-    tokens = shlex.split(s)
-    for token in unexpected_tokens:
-      self.assertNotIn(token, tokens)
-
-  def assertSymlinkTo(self, symlink_path, target_path):
-    self.assertEqual(symlink_path.resolve(strict=False), target_path)
-
-
-class FeatureParserTest(unittest.TestCase):
-  """Tests for parsing Bazel mode feature flags."""
-
-  def test_parse_args_with_bazel_mode_feature(self):
-    parser = argparse.ArgumentParser()
-    bazel_mode.add_parser_arguments(parser, dest='bazel_mode_features')
-    # pylint: disable=no-member
-    args = parser.parse_args([bazel_mode.Features.NULL_FEATURE.arg_flag])
-
-    self.assertListEqual(
-        [bazel_mode.Features.NULL_FEATURE], args.bazel_mode_features
-    )
-
-  def test_parse_args_without_bazel_mode_feature(self):
-    parser = argparse.ArgumentParser()
-    parser.add_argument('--foo', action='append_const', const='foo', dest='foo')
-    bazel_mode.add_parser_arguments(parser, dest='bazel_mode_features')
-    args = parser.parse_args(['--foo'])
-
-    self.assertIsNone(args.bazel_mode_features)
-
-
-def test_info_of(module_name, test_filters=None):
-  return test_info.TestInfo(
-      module_name,
-      BAZEL_RUNNER,
-      [],
-      data={constants.TI_FILTER: frozenset(test_filters)}
-      if test_filters
-      else None,
-  )
-
-
-def test_filter_of(class_name, methods=None):
-  return test_info.TestFilter(
-      class_name, frozenset(methods) if methods else frozenset()
-  )
-
-
-def _get_query_file_content(args: List[str]) -> str:
-  for arg in args:
-    if arg.startswith('--query_file='):
-      return Path(arg.split('=')[1]).read_text(encoding='utf-8')
-
-  raise FileNotFoundError('Query file not found!')
-
-
-if __name__ == '__main__':
-  unittest.main()
diff --git a/atest/constants_default.py b/atest/constants_default.py
index 693bd984..2880c32b 100644
--- a/atest/constants_default.py
+++ b/atest/constants_default.py
@@ -192,8 +192,10 @@ BOTH_TEST = 'both'
 NO_METRICS_ARG = '--no-metrics'
 EXTERNAL = 'EXTERNAL_RUN'
 INTERNAL = 'INTERNAL_RUN'
+# LINT.IfChange
 INTERNAL_EMAIL = '@google.com'
 INTERNAL_HOSTNAME = ['.google.com', 'c.googlers.com']
+# LINT.ThenChange(/test/robolectric-extensions/clearcut-junit-listener/src/main/java/com/google/asuite/clearcut/junit/listener/EnvironmentInformation.java)
 TOOL_NAME = 'atest'
 SUB_TOOL_NAME = ''
 USER_FROM_TOOL = 'USER_FROM_TOOL'
@@ -391,3 +393,6 @@ REQUIRE_DEVICES_MSG = (
 
 # Default shard num.
 SHARD_NUM = 2
+
+# Smart test selection keyword.
+SMART_TEST_SELECTION = 'smart_test_selection'
diff --git a/atest/coverage/coverage.py b/atest/coverage/coverage.py
index b1c49f0c..c1546369 100644
--- a/atest/coverage/coverage.py
+++ b/atest/coverage/coverage.py
@@ -389,7 +389,7 @@ def _generate_lcov_report(out_dir, reports, root_dir=None):
       # TODO(b/361334044): These errors are ignored to continue to generate a
       # flawed result but ultimately need to be resolved, see bug for details.
       '--ignore-errors',
-      'unmapped,range,empty,corrupt',
+      'unmapped,range,empty,corrupt,missing',
   ]
   if root_dir:
     cmd.extend(['-p', root_dir])
diff --git a/atest/integration_tests/Android.bp b/atest/integration_tests/Android.bp
index dff30d9b..7ce5b00a 100644
--- a/atest/integration_tests/Android.bp
+++ b/atest/integration_tests/Android.bp
@@ -70,11 +70,6 @@ python_defaults {
     libs: [
         "asuite_integration_test_lib",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_suites: [
         "general-tests",
     ],
diff --git a/atest/logstorage/httplib2/Android.bp b/atest/logstorage/httplib2/Android.bp
index 9e48ec61..b028f935 100644
--- a/atest/logstorage/httplib2/Android.bp
+++ b/atest/logstorage/httplib2/Android.bp
@@ -42,11 +42,6 @@ python_test_host {
     test_options: {
         unit_test: true,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
@@ -55,9 +50,5 @@ python_test_host {
     test_options: {
         unit_test: true,
     },
-    version: {
-        py3: {
-            embedded_launcher: false,
-        },
-    },
+    embedded_launcher: false,
 }
diff --git a/atest/rollout_control.py b/atest/rollout_control.py
index 2a89f5bc..34b9cd11 100644
--- a/atest/rollout_control.py
+++ b/atest/rollout_control.py
@@ -184,7 +184,7 @@ class RolloutControlledFeature:
 
 deprecate_bazel_mode = RolloutControlledFeature(
     name='Deprecate Bazel Mode',
-    rollout_percentage=60,
+    rollout_percentage=100,
     env_control_flag='DEPRECATE_BAZEL_MODE',
     feature_id=1,
 )
@@ -195,21 +195,23 @@ rolling_tf_subprocess_output = RolloutControlledFeature(
     env_control_flag='ROLLING_TF_SUBPROCESS_OUTPUT',
     feature_id=2,
     print_message=(
-        'You are one of the first users receiving the "Rolling subprocess'
-        ' output" feature. If you are happy with it, please +1 on'
-        ' http://b/380460196.'
+        atest_utils.mark_magenta(
+            'Rolling subprocess output feature is enabled: http://b/380460196.'
+        )
     ),
 )
 
 tf_preparer_incremental_setup = RolloutControlledFeature(
     name='TradeFed preparer incremental setup',
-    rollout_percentage=0,
+    rollout_percentage=100,
     env_control_flag='TF_PREPARER_INCREMENTAL_SETUP',
     feature_id=3,
     print_message=(
-        'You are one of the first users selected to receive the "Incremental'
-        ' setup for TradeFed preparers" feature. If you are happy with it,'
-        ' please +1 on http://b/381900378. If you experienced any issues,'
-        ' please comment on the same bug.'
+        atest_utils.mark_magenta(
+            'You are one of the first users selected to receive the'
+            ' "Incremental setup for TradeFed preparers" feature. If you are'
+            ' happy with it, please +1 on http://b/381900378. If you'
+            ' experienced any issues, please comment on the same bug.'
+        )
     ),
 )
diff --git a/atest/test_runners/atest_tf_test_runner.py b/atest/test_runners/atest_tf_test_runner.py
index bbd3a238..96dc701d 100644
--- a/atest/test_runners/atest_tf_test_runner.py
+++ b/atest/test_runners/atest_tf_test_runner.py
@@ -196,6 +196,9 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     metrics.LocalDetectEvent(
         detect_type=DetectType.IS_MINIMAL_BUILD, result=int(self._minimal_build)
     )
+    self._smart_test_selection = extra_args.get(
+        constants.SMART_TEST_SELECTION, False
+    )
 
   def requires_device_update(
       self, test_infos: List[test_info.TestInfo]
@@ -225,42 +228,47 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
         A list of TestRunnerInvocation instances.
     """
     invocations = []
-    device_test_infos, deviceless_test_infos = self._partition_tests(test_infos)
-    if deviceless_test_infos:
+    device_test_info_lists, deviceless_test_info_lists = self._partition_tests(
+        test_infos
+    )
+    if deviceless_test_info_lists:
       extra_args_for_deviceless_test = extra_args.copy()
       extra_args_for_deviceless_test.update({constants.HOST: True})
-      invocations.append(
-          TestRunnerInvocation(
-              test_runner=self,
-              extra_args=extra_args_for_deviceless_test,
-              test_infos=deviceless_test_infos,
-          )
-      )
-    if device_test_infos:
+      for temp_test_infos in deviceless_test_info_lists:
+        invocations.append(
+            TestRunnerInvocation(
+                test_runner=self,
+                extra_args=extra_args_for_deviceless_test,
+                test_infos=temp_test_infos,
+            )
+        )
+    if device_test_info_lists:
       extra_args_for_device_test = extra_args.copy()
       if rollout_control.tf_preparer_incremental_setup.is_enabled():
         extra_args_for_device_test.update({_INCREMENTAL_SETUP_KEY: True})
-      invocations.append(
-          TestRunnerInvocation(
-              test_runner=self,
-              extra_args=extra_args_for_device_test,
-              test_infos=device_test_infos,
-          )
-      )
+      for temp_test_infos in device_test_info_lists:
+        invocations.append(
+            TestRunnerInvocation(
+                test_runner=self,
+                extra_args=extra_args_for_device_test,
+                test_infos=temp_test_infos,
+            )
+        )
 
     return invocations
 
   def _partition_tests(
       self,
       test_infos: List[test_info.TestInfo],
-  ) -> (List[test_info.TestInfo], List[test_info.TestInfo]):
+  ) -> (List[List[test_info.TestInfo]], List[List[test_info.TestInfo]]):
     """Partition input tests into two lists based on whether it requires device.
 
     Args:
         test_infos: A list of TestInfos.
 
     Returns:
-        Two lists one contains device tests the other contains deviceless tests.
+        Two lists one contains device test info lists the other contains
+        deviceless test info lists.
     """
     device_test_infos = []
     deviceless_test_infos = []
@@ -272,7 +280,15 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
       else:
         deviceless_test_infos.append(info)
 
-    return device_test_infos, deviceless_test_infos
+    return [
+        [info] for info in device_test_infos
+    ] if self._smart_test_selection or not device_test_infos else [
+        device_test_infos
+    ], [
+        [info] for info in deviceless_test_infos
+    ] if self._smart_test_selection or not deviceless_test_infos else [
+        deviceless_test_infos
+    ]
 
   def _try_set_gts_authentication_key(self):
     """Set GTS authentication key if it is available or exists.
@@ -366,6 +382,13 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
           reporter.test_result_link = (
               constants.RESULT_LINK % inv['invocationId']
           )
+          # TODO(b/400764778): Modify the logic of result_reporter to contain a
+          # mapping of invocations to test result links, and report the mapping
+          # in `ResultReporter.print_summary`.
+          print(
+              'Test Result uploaded to %s'
+              % atest_utils.mark_green(reporter.test_result_link)
+          )
         finally:
           logging.disable(logging.NOTSET)
     return result
diff --git a/atest/test_runners/atest_tf_test_runner_unittest.py b/atest/test_runners/atest_tf_test_runner_unittest.py
index 1b181ab3..bf5804c4 100755
--- a/atest/test_runners/atest_tf_test_runner_unittest.py
+++ b/atest/test_runners/atest_tf_test_runner_unittest.py
@@ -1255,19 +1255,12 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     invocations = self.tr.create_invocations(
         {}, [test_info_deviceless, test_info_device]
     )
-    expected_invocation_deviceless = TestRunnerInvocation(
-        test_runner=self.tr,
-        extra_args={constants.HOST: True},
-        test_infos=[test_info_deviceless],
-    )
-    expected_invocation_device = TestRunnerInvocation(
-        test_runner=self.tr, extra_args={}, test_infos=[test_info_device]
-    )
 
-    self.assertEqual(
-        invocations,
-        [expected_invocation_deviceless, expected_invocation_device],
-    )
+    self.assertEqual(len(invocations), 2)
+    self.assertEqual(invocations[0].test_infos, [test_info_deviceless])
+    self.assertTrue(invocations[0]._extra_args[constants.HOST])
+    self.assertEqual(invocations[1].test_infos, [test_info_device])
+    self.assertFalse(constants.HOST in invocations[1]._extra_args)
 
   def test_create_invocations_returns_invocation_only_for_device_tests(self):
     self.tr.module_info = module_info.ModuleInfo(
@@ -1290,13 +1283,94 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     invocations = self.tr.create_invocations(
         {}, [test_info_device_1, test_info_device_2]
     )
-    expected_invocation = TestRunnerInvocation(
-        test_runner=self.tr,
-        extra_args={},
-        test_infos=[test_info_device_1, test_info_device_2],
+
+    self.assertEqual(len(invocations), 1)
+    self.assertEqual(
+        invocations[0].test_infos, [test_info_device_1, test_info_device_2]
+    )
+    self.assertFalse(constants.HOST in invocations[0]._extra_args)
+
+  def test_create_invocations_with_smart_test_selection_returns_multiple_invocations(
+      self,
+  ):
+    tr = atf_tr.AtestTradefedTestRunner(
+        results_dir=uc.TEST_INFO_DIR,
+        extra_args={
+            constants.HOST: False,
+            constants.SMART_TEST_SELECTION: True,
+        },
+    )
+    tr.module_info = module_info.ModuleInfo(
+        name_to_module_info={
+            'device_test_1': (
+                module_info_unittest_base.device_driven_test_module(
+                    name='device_test_1'
+                )
+            ),
+            'device_test_2': (
+                module_info_unittest_base.host_driven_device_test_module(
+                    name='device_test_2'
+                )
+            ),
+            'deviceless_test_1': (
+                module_info_unittest_base.robolectric_test_module(
+                    name='deviceless_test_1'
+                )
+            ),
+            'deviceless_test_2': (
+                module_info_unittest_base.robolectric_test_module(
+                    name='deviceless_test_2'
+                )
+            ),
+        }
+    )
+    test_info_device_1 = test_info_of('device_test_1')
+    test_info_device_2 = test_info_of('device_test_2')
+    test_info_deviceless_1 = test_info_of('deviceless_test_1')
+    test_info_deviceless_2 = test_info_of('deviceless_test_2')
+
+    invocations = tr.create_invocations(
+        {},
+        [
+            test_info_device_1,
+            test_info_device_2,
+            test_info_deviceless_1,
+            test_info_deviceless_2,
+        ],
+    )
+
+    self.assertEqual(len(invocations), 4)
+
+  def test_create_invocations_returns_invocation_only_for_deviceless_tests(
+      self,
+  ):
+    self.tr.module_info = module_info.ModuleInfo(
+        name_to_module_info={
+            'deviceless_test_1': (
+                module_info_unittest_base.robolectric_test_module(
+                    name='deviceless_test_1'
+                )
+            ),
+            'deviceless_test_2': (
+                module_info_unittest_base.robolectric_test_module(
+                    name='deviceless_test_2'
+                )
+            ),
+        }
+    )
+    test_info_deviceless_1 = test_info_of('deviceless_test_1')
+    test_info_deviceless_2 = test_info_of('deviceless_test_2')
+
+    invocations = self.tr.create_invocations(
+        {}, [test_info_deviceless_1, test_info_deviceless_2]
     )
 
-    self.assertEqual(invocations, [expected_invocation])
+    self.assertEqual(len(invocations), 1)
+    self.assertEqual(
+        invocations[0].test_infos,
+        [test_info_deviceless_1, test_info_deviceless_2],
+    )
+    self.assertTrue(invocations[0]._extra_args[constants.HOST])
 
   def test_create_invocations_returns_invocations_for_device_tests_without_module_info(
       self,
@@ -1306,13 +1380,10 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
     test_info_device = test_info_of('device_test_without_module_info')
 
     invocations = self.tr.create_invocations({}, [test_info_device])
-    expected_invocation = TestRunnerInvocation(
-        test_runner=self.tr,
-        extra_args={},
-        test_infos=[test_info_device],
-    )
 
-    self.assertEqual(invocations, [expected_invocation])
+    self.assertEqual(len(invocations), 1)
+    self.assertEqual(invocations[0].test_infos, [test_info_device])
+    self.assertFalse(constants.HOST in invocations[0]._extra_args)
 
   def assertTokensIn(self, expected_tokens, s):
     tokens = shlex.split(s)
diff --git a/experiments/a/Android.bp b/experiments/a/Android.bp
index 57b8556c..5ad72fac 100644
--- a/experiments/a/Android.bp
+++ b/experiments/a/Android.bp
@@ -20,11 +20,6 @@ python_binary_host {
         "**/*.py",
     ],
     libs: [],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
diff --git a/plugin_lib/OWNERS b/plugin_lib/OWNERS
index 54dab1ec..932c6737 100644
--- a/plugin_lib/OWNERS
+++ b/plugin_lib/OWNERS
@@ -2,6 +2,5 @@ include /OWNERS_ADTE_TEAM
 
 shinwang@google.com
 patricktu@google.com
-bralee@google.com
 albaltai@google.com
 dshi@google.com
```

