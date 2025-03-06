```diff
diff --git a/Android.bp b/Android.bp
index 87859d98..67f75104 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,28 +22,11 @@ python_library_host {
     srcs: [
         "atest/proto/*.proto",
     ],
-    libs: [
-        "asuite_adb_host_proto_py",
-    ],
     proto: {
         canonical_path_from_root: false,
     },
 }
 
-python_library_host {
-    name: "asuite_adb_host_proto_py",
-    srcs: [
-        ":adb_host_proto",
-    ],
-    proto: {
-        type: "full",
-        include_dirs: ["external/protobuf/src"],
-    },
-    visibility: [
-        "//tools/asuite:__subpackages__",
-    ],
-}
-
 java_library_host {
     name: "asuite_proto_java",
     srcs: [
@@ -74,3 +57,11 @@ python_library_host {
         canonical_path_from_root: false,
     },
 }
+
+filegroup {
+    name: "adte-owners-files",
+    srcs: [
+        "OWNERS_ADTE_TEAM",
+        "OWNERS",
+    ],
+}
diff --git a/OWNERS_ADTE_TEAM b/OWNERS_ADTE_TEAM
index f4fee564..12ca6601 100644
--- a/OWNERS_ADTE_TEAM
+++ b/OWNERS_ADTE_TEAM
@@ -1,8 +1,8 @@
 # ADTE team
-agueeva@google.com
 davidjames@google.com
 hwj@google.com
 hzalek@google.com
+ihcinihsdk@google.com
 kevindagostino@google.com
 liuyg@google.com
 lucafarsi@google.com
diff --git a/adevice/src/adevice.rs b/adevice/src/adevice.rs
index 563eb1dd..4b634cf9 100644
--- a/adevice/src/adevice.rs
+++ b/adevice/src/adevice.rs
@@ -291,6 +291,8 @@ pub fn adevice(
         }
     }
     metrics.display_survey();
+    println!("New android update workflow tool available! go/a-update");
+
     Ok(())
 }
 
diff --git a/adevice/src/metrics.rs b/adevice/src/metrics.rs
index a5bd2e87..dd614fde 100644
--- a/adevice/src/metrics.rs
+++ b/adevice/src/metrics.rs
@@ -14,15 +14,14 @@ use std::env;
 use std::fs;
 use std::process::{Command, Stdio};
 use std::time::UNIX_EPOCH;
-use tracing::debug;
+use tracing::info;
 use uuid::Uuid;
 
 const ENV_OUT: &str = "OUT";
 const ENV_USER: &str = "USER";
 const ENV_TARGET: &str = "TARGET_PRODUCT";
 const ENV_SURVEY_BANNER: &str = "ADEVICE_SURVEY_BANNER";
-const METRICS_UPLOADER: &str = "/google/bin/releases/adevice-dev/
-";
+const METRICS_UPLOADER: &str = "/google/bin/releases/adevice-dev/metrics_uploader";
 const ADEVICE_LOG_SOURCE: i32 = 2265;
 
 pub trait MetricSender {
@@ -220,7 +219,7 @@ impl Drop for Metrics {
     fn drop(&mut self) {
         match self.send() {
             Ok(_) => (),
-            Err(e) => debug!("Failed to send metrics: {}", e),
+            Err(e) => info!("Failed to send metrics: {}", e),
         };
     }
 }
diff --git a/atest/Android.bp b/atest/Android.bp
index 7337b1df..c5fda1f8 100644
--- a/atest/Android.bp
+++ b/atest/Android.bp
@@ -68,6 +68,7 @@ python_binary_host {
     defaults: ["atest_binary_defaults"],
     main: "atest_main.py",
     data: [
+        ":adte-owners-files",
         ":atest_flag_list_for_completion",
         ":atest_log_uploader",
     ],
diff --git a/atest/arg_parser.py b/atest/arg_parser.py
index ee9a209d..32505253 100644
--- a/atest/arg_parser.py
+++ b/atest/arg_parser.py
@@ -516,11 +516,17 @@ def create_atest_arg_parser():
       '--aggregate-metric-filter',
       action='append',
       help=(
-          '(For performance testing) Regular expression that will be used for'
+          '(For performance tests) Regular expression that will be used for'
           ' filtering the aggregated metrics.'
       ),
   )
 
+  parser.add_argument(
+      '--perf-itr-metrics',
+      action='store_true',
+      help='(For performance tests) Print individual performance metric.',
+  )
+
   parser.add_argument(
       '--no-checking-device',
       action='store_true',
diff --git a/atest/atest_enum.py b/atest/atest_enum.py
index 33b98613..d44fdf25 100644
--- a/atest/atest_enum.py
+++ b/atest/atest_enum.py
@@ -117,6 +117,10 @@ class DetectType(IntEnum):
   IS_PLOCATEDB_LOCKED = 63
   # Device update duration
   DEVICE_UPDATE_MS = 64
+  # The ID of the feature that is controlled by rollout control. Positive value
+  # means the feature is enabled, negative value means disabled.
+  ROLLOUT_CONTROLLED_FEATURE_ID = 65
+  ROLLOUT_CONTROLLED_FEATURE_ID_OVERRIDE = 66
 
 
 @unique
diff --git a/atest/atest_execution_info.py b/atest/atest_execution_info.py
index 5012c23c..064f096a 100644
--- a/atest/atest_execution_info.py
+++ b/atest/atest_execution_info.py
@@ -311,6 +311,7 @@ class AtestExecutionInfo:
     self.result_file_obj = None
     self.args_ns = args_ns
     self.test_result = os.path.join(self.work_dir, _TEST_RESULT_NAME)
+    self._proc_usb_speed = None
     logging.debug(
         'A %s object is created with args %s, work_dir %s',
         __class__,
@@ -330,26 +331,42 @@ class AtestExecutionInfo:
       self.result_file_obj = open(self.test_result, 'w')
     except IOError:
       atest_utils.print_and_log_error('Cannot open file %s', self.test_result)
+
+    self._proc_usb_speed = atest_utils.run_multi_proc(
+        func=self._send_usb_metrics_and_warning
+    )
+
     return self.result_file_obj
 
   def __exit__(self, exit_type, value, traceback):
     """Write execution information and close information file."""
 
-    # Read the USB speed and send usb metrics.
-    device_proto = usb.get_device_proto_binary()
-    usb.verify_and_print_usb_speed_warning(device_proto)
-    metrics.LocalDetectEvent(
-        detect_type=atest_enum.DetectType.USB_NEGOTIATED_SPEED,
-        result=device_proto.negotiated_speed
-        if device_proto.negotiated_speed
-        else 0,
+    if self._proc_usb_speed:
+      # Usb speed detection is not an obligatory function of atest,
+      # so it can be skipped if the process hasn't finished by the time atest
+      # is ready to exit.
+      if self._proc_usb_speed.is_alive():
+        self._proc_usb_speed.terminate()
+
+    log_path = pathlib.Path(self.work_dir)
+
+    build_log_path = log_path / 'build_logs'
+    build_log_path.mkdir()
+    AtestExecutionInfo._copy_build_artifacts_to_log_dir(
+        self._start_time,
+        time.time(),
+        self._repo_out_dir,
+        build_log_path,
+        'build.trace',
     )
-    metrics.LocalDetectEvent(
-        detect_type=atest_enum.DetectType.USB_MAX_SPEED,
-        result=device_proto.max_speed if device_proto.max_speed else 0,
+    AtestExecutionInfo._copy_build_artifacts_to_log_dir(
+        self._start_time,
+        time.time(),
+        self._repo_out_dir,
+        build_log_path,
+        'verbose.log',
     )
 
-    log_path = pathlib.Path(self.work_dir)
     html_path = None
 
     if self.result_file_obj and not has_non_test_options(self.args_ns):
@@ -368,12 +385,14 @@ class AtestExecutionInfo:
     )
 
     print()
+    if log_path:
+      print(f'Test logs: {log_path / "log"}')
     log_link = html_path if html_path else log_path
     if log_link:
-      print(f'Logs: {atest_utils.mark_magenta(f"file://{log_link}")}')
+      print(atest_utils.mark_magenta(f'Log file list: file://{log_link}'))
     bug_report_url = AtestExecutionInfo._create_bug_report_url()
     if bug_report_url:
-      print(f'Issue report: {bug_report_url}')
+      print(atest_utils.mark_magenta(f"Bug report: {bug_report_url}"))
     print()
 
     # Do not send stacktrace with send_exit_event when exit code is not
@@ -385,12 +404,38 @@ class AtestExecutionInfo:
       logging.debug('handle_exc_and_send_exit_event:%s', main_exit_code)
       metrics_utils.handle_exc_and_send_exit_event(main_exit_code)
 
-    AtestExecutionInfo._copy_build_trace_to_log_dir(
-        self._start_time, time.time(), self._repo_out_dir, log_path
-    )
     if log_uploader.is_uploading_logs():
       log_uploader.upload_logs_detached(log_path)
 
+  def _send_usb_metrics_and_warning(self):
+    # Read the USB speed and send usb metrics.
+    device_ids = usb.get_adb_device_identifiers()
+    if not device_ids:
+      return
+
+    usb_speed_dir_name = usb.get_udc_driver_usb_device_dir_name()
+    if not usb_speed_dir_name:
+      return
+
+    usb_negotiated_speed = usb.get_udc_driver_usb_device_attribute_speed_value(
+        usb_speed_dir_name, usb.UsbAttributeName.NEGOTIATED_SPEED
+    )
+    usb_max_speed = usb.get_udc_driver_usb_device_attribute_speed_value(
+        usb_speed_dir_name, usb.UsbAttributeName.MAXIMUM_SPEED
+    )
+    usb.verify_and_print_usb_speed_warning(
+        device_ids, usb_negotiated_speed, usb_max_speed
+    )
+
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.USB_NEGOTIATED_SPEED,
+        result=usb_negotiated_speed,
+    )
+    metrics.LocalDetectEvent(
+        detect_type=atest_enum.DetectType.USB_MAX_SPEED,
+        result=usb_max_speed,
+    )
+
   @staticmethod
   def _create_bug_report_url() -> str:
     if not metrics.is_internal_user():
@@ -400,20 +445,29 @@ class AtestExecutionInfo:
     return f'http://go/from-atest-runid/{metrics.get_run_id()}'
 
   @staticmethod
-  def _copy_build_trace_to_log_dir(
+  def _copy_build_artifacts_to_log_dir(
       start_time: float,
       end_time: float,
       repo_out_path: pathlib.Path,
       log_path: pathlib.Path,
+      file_name_prefix: str,
   ):
-
+    """Copy build trace files to log directory.
+
+    Params:
+      start_time: The start time of the build.
+      end_time: The end time of the build.
+      repo_out_path: The path to the repo out directory.
+      log_path: The path to the log directory.
+      file_name_prefix: The prefix of the file name.
+    """
     for file in repo_out_path.iterdir():
       if (
           file.is_file()
-          and file.name.startswith('build.trace')
+          and file.name.startswith(file_name_prefix)
           and start_time <= file.stat().st_mtime <= end_time
       ):
-        shutil.copy(file, log_path)
+        shutil.copy(file, log_path / file.name)
 
   @staticmethod
   def _generate_execution_detail(args):
diff --git a/atest/atest_execution_info_unittest.py b/atest/atest_execution_info_unittest.py
index 3c176f31..af614549 100755
--- a/atest/atest_execution_info_unittest.py
+++ b/atest/atest_execution_info_unittest.py
@@ -52,7 +52,7 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     self.setUpPyfakefs()
     self.fs.create_dir(constants.ATEST_RESULT_ROOT)
 
-  def test_copy_build_trace_to_log_dir_new_trace_copy(self):
+  def test_copy_build_artifacts_to_log_dir_new_trace_copy(self):
     start_time = 10
     log_path = pathlib.Path('/logs')
     self.fs.create_dir(log_path)
@@ -63,15 +63,15 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     os.utime(build_trace_path, (20, 20))
     end_time = 30
 
-    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
-        start_time, end_time, out_path, log_path
+    aei.AtestExecutionInfo._copy_build_artifacts_to_log_dir(
+        start_time, end_time, out_path, log_path, 'build.trace'
     )
 
     self.assertTrue(
         self._is_dir_contains_files_with_prefix(log_path, 'build.trace')
     )
 
-  def test_copy_build_trace_to_log_dir_old_trace_does_not_copy(self):
+  def test_copy_build_artifacts_to_log_dir_old_trace_does_not_copy(self):
     start_time = 10
     log_path = pathlib.Path('/logs')
     self.fs.create_dir(log_path)
@@ -82,8 +82,8 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     os.utime(build_trace_path, (5, 5))
     end_time = 30
 
-    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
-        start_time, end_time, out_path, log_path
+    aei.AtestExecutionInfo._copy_build_artifacts_to_log_dir(
+        start_time, end_time, out_path, log_path, 'build.trace'
     )
 
     self.assertFalse(
@@ -95,8 +95,8 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     log_path = pathlib.Path('/logs')
     self.fs.create_dir(log_path)
     out_path = pathlib.Path('/out')
-    build_trace_path1 = out_path / 'build.trace.1'
-    build_trace_path2 = out_path / 'build.trace.2'
+    build_trace_path1 = out_path / 'build.trace.1.gz'
+    build_trace_path2 = out_path / 'build.trace.2.gz'
     self.fs.create_file(build_trace_path1)
     self.fs.create_file(build_trace_path2)
     # Set the trace file's mtime greater than start time
@@ -104,15 +104,15 @@ class CopyBuildTraceToLogsTests(fake_filesystem_unittest.TestCase):
     os.utime(build_trace_path2, (20, 20))
     end_time = 30
 
-    aei.AtestExecutionInfo._copy_build_trace_to_log_dir(
-        start_time, end_time, out_path, log_path
+    aei.AtestExecutionInfo._copy_build_artifacts_to_log_dir(
+        start_time, end_time, out_path, log_path, 'build.trace'
     )
 
     self.assertTrue(
-        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.1')
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.1.gz')
     )
     self.assertTrue(
-        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.2')
+        self._is_dir_contains_files_with_prefix(log_path, 'build.trace.2.gz')
     )
 
   def _is_dir_contains_files_with_prefix(
diff --git a/atest/atest_main.py b/atest/atest_main.py
index d98cda18..590dcade 100755
--- a/atest/atest_main.py
+++ b/atest/atest_main.py
@@ -39,8 +39,9 @@ import platform
 import subprocess
 import sys
 import tempfile
+import threading
 import time
-from typing import Any, Dict, List, Set, Tuple
+from typing import Any, Dict, List, Set
 
 from atest import arg_parser
 from atest import atest_configs
@@ -831,18 +832,15 @@ class _AtestMain:
       return status
     return None
 
-  def _start_indexing_if_required(self) -> None:
+  def _start_indexing_if_required(self) -> threading.Thread:
     """Starts indexing if required.
 
-    The decision flow is as follows: If no build is required, returns False.
-    Otherwise, if some index files are missing, returns True. Otherwise, if
-    some arguments that doesn't require indexing is present, returns False.
-    Otherwise, returns True.
+    Returns:
+        A thread that runs indexing. None if no indexing is required.
     """
-    self._indexing_proc = None
     if not self._steps.build:
       logging.debug("Skip indexing because there's no build required.")
-      return
+      return None
 
     if indexing.Indices().has_all_indices():
       no_indexing_args = (
@@ -853,34 +851,18 @@ class _AtestMain:
         logging.debug(
             'Skip indexing for no_indexing_args=%s.', no_indexing_args
         )
-        return
+        return None
     else:
       logging.debug(
           'Indexing targets is required because some index files do not exist.'
       )
 
     logging.debug('Starting to index targets in a background thread.')
-    self._indexing_proc = atest_utils.start_threading(
+    return atest_utils.start_threading(
         indexing.index_targets,
         daemon=True,
     )
 
-  def _check_indexing_status(self) -> None:
-    """Checks indexing status and wait for it to complete if necessary."""
-    if (
-        not self._indexing_proc
-        or not self._indexing_proc.is_alive()
-        or indexing.Indices().has_all_indices()
-    ):
-      return
-    start_wait_for_indexing = time.time()
-    print('Waiting for the module indexing to complete.')
-    self._indexing_proc.join()
-    metrics.LocalDetectEvent(
-        detect_type=DetectType.WAIT_FOR_INDEXING_MS,
-        result=int(round((time.time() - start_wait_for_indexing) * 1000)),
-    )
-
   @functools.cache
   def _get_device_update_method(self) -> device_update.AdeviceUpdateMethod:
     """Creates a device update method."""
@@ -934,12 +916,6 @@ class _AtestMain:
       logging.debug('"--test" mode detected, will not rebuild module-info.')
       return False
     if self._args.rebuild_module_info:
-      msg = (
-          f'`{constants.REBUILD_MODULE_INFO_FLAG}` is no longer needed '
-          f'since Atest can smartly rebuild {module_info._MODULE_INFO} '
-          r'only when needed.'
-      )
-      atest_utils.colorful_print(msg, constants.YELLOW)
       return True
     logging.debug('Examinating the consistency of build files...')
     if not atest_utils.build_files_integrity_is_ok():
@@ -969,7 +945,8 @@ class _AtestMain:
     Returns:
         Exit code if anything went wrong. None otherwise.
     """
-    self._start_indexing_if_required()
+    indexing_thread = self._start_indexing_if_required()
+
     self._load_module_info()
 
     translator = cli_translator.CLITranslator(
@@ -978,13 +955,16 @@ class _AtestMain:
         bazel_mode_enabled=self._args.bazel_mode,
         host=self._args.host,
         bazel_mode_features=self._args.bazel_mode_features,
+        indexing_thread=indexing_thread,
     )
 
-    self._check_indexing_status()
-
     find_start = time.time()
     self._test_infos = translator.translate(self._args)
 
+    _AtestMain._inject_default_arguments_based_on_test_infos(
+        self._test_infos, self._args
+    )
+
     # Only check for sufficient devices if not dry run.
     self._args.device_count_config = get_device_count_config(
         self._test_infos, self._mod_info
@@ -999,14 +979,24 @@ class _AtestMain:
       return ExitCode.TEST_NOT_FOUND
 
     self._test_execution_plan = _TestExecutionPlan.create(
+        args=self._args,
         test_infos=self._test_infos,
         results_dir=self._results_dir,
         mod_info=self._mod_info,
-        args=self._args,
     )
 
     return None
 
+  @staticmethod
+  def _inject_default_arguments_based_on_test_infos(
+      test_infos: list[test_info.TestInfo], args: argparse.Namespace
+  ) -> None:
+    if any(
+        'performance-tests' in info.compatibility_suites for info in test_infos
+    ):
+      if not args.disable_upload_result:
+        args.request_upload_result = True
+
   def _handle_list_modules(self) -> int:
     """Print the testable modules for a given suite.
 
@@ -1286,19 +1276,18 @@ class _TestExecutionPlan(abc.ABC):
 
   @staticmethod
   def create(
-      *,
+      args: argparse.Namespace,
       test_infos: List[test_info.TestInfo],
       results_dir: str,
       mod_info: module_info.ModuleInfo,
-      args: argparse.Namespace,
   ) -> _TestExecutionPlan:
     """Creates a plan to execute the tests.
 
     Args:
+        args: An argparse.Namespace instance holding parsed args.
         test_infos: A list of instances of TestInfo.
         results_dir: A directory which stores the ATest execution information.
         mod_info: An instance of ModuleInfo.
-        args: An argparse.Namespace instance holding parsed args.
 
     Returns:
         An instance of _TestExecutionPlan.
@@ -1306,25 +1295,28 @@ class _TestExecutionPlan(abc.ABC):
 
     if is_from_test_mapping(test_infos):
       return _TestMappingExecutionPlan.create(
+          args=args,
           test_infos=test_infos,
           results_dir=results_dir,
           mod_info=mod_info,
-          args=args,
       )
 
     return _TestModuleExecutionPlan.create(
+        args=args,
         test_infos=test_infos,
         results_dir=results_dir,
         mod_info=mod_info,
-        args=args,
     )
 
   def __init__(
       self,
-      *,
+      args: argparse.Namespace,
       extra_args: Dict[str, Any],
+      test_infos: List[test_info.TestInfo],
   ):
+    self._args = args
     self._extra_args = extra_args
+    self._test_infos = test_infos
 
   @property
   def extra_args(self) -> Dict[str, Any]:
@@ -1348,28 +1340,28 @@ class _TestMappingExecutionPlan(_TestExecutionPlan):
 
   def __init__(
       self,
-      *,
-      test_type_to_invocations: Dict[str, List[TestRunnerInvocation]],
+      args: argparse.Namespace,
       extra_args: Dict[str, Any],
+      test_infos: List[test_info.TestInfo],
+      test_type_to_invocations: Dict[str, List[TestRunnerInvocation]],
   ):
-    super().__init__(extra_args=extra_args)
+    super().__init__(args, extra_args, test_infos)
     self._test_type_to_invocations = test_type_to_invocations
 
   @staticmethod
   def create(
-      *,
+      args: argparse.Namespace,
       test_infos: List[test_info.TestInfo],
       results_dir: str,
       mod_info: module_info.ModuleInfo,
-      args: argparse.Namespace,
   ) -> _TestMappingExecutionPlan:
     """Creates an instance of _TestMappingExecutionPlan.
 
     Args:
+        args: An argparse.Namespace instance holding parsed args.
         test_infos: A list of instances of TestInfo.
         results_dir: A directory which stores the ATest execution information.
         mod_info: An instance of ModuleInfo.
-        args: An argparse.Namespace instance holding parsed args.
 
     Returns:
         An instance of _TestMappingExecutionPlan.
@@ -1429,8 +1421,10 @@ class _TestMappingExecutionPlan(_TestExecutionPlan):
       )
 
     return _TestMappingExecutionPlan(
-        test_type_to_invocations=test_type_to_invocations,
+        args=args,
         extra_args=extra_args,
+        test_infos=test_infos,
+        test_type_to_invocations=test_type_to_invocations,
     )
 
   def requires_device_update(self) -> bool:
@@ -1471,6 +1465,8 @@ class _TestMappingExecutionPlan(_TestExecutionPlan):
       reporter = result_reporter.ResultReporter(
           collect_only=self._extra_args.get(constants.COLLECT_TESTS_ONLY),
           wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
+          args=self._args,
+          test_infos=self._test_infos,
       )
       reporter.print_starting_text()
 
@@ -1509,28 +1505,28 @@ class _TestModuleExecutionPlan(_TestExecutionPlan):
 
   def __init__(
       self,
-      *,
-      test_runner_invocations: List[TestRunnerInvocation],
+      args: argparse.Namespace,
       extra_args: Dict[str, Any],
+      test_infos: List[test_info.TestInfo],
+      test_runner_invocations: List[TestRunnerInvocation],
   ):
-    super().__init__(extra_args=extra_args)
+    super().__init__(args, extra_args, test_infos)
     self._test_runner_invocations = test_runner_invocations
 
   @staticmethod
   def create(
-      *,
+      args: argparse.Namespace,
       test_infos: List[test_info.TestInfo],
       results_dir: str,
       mod_info: module_info.ModuleInfo,
-      args: argparse.Namespace,
   ) -> _TestModuleExecutionPlan:
     """Creates an instance of _TestModuleExecutionPlan.
 
     Args:
+        args: An argparse.Namespace instance holding parsed args.
         test_infos: A list of instances of TestInfo.
         results_dir: A directory which stores the ATest execution information.
         mod_info: An instance of ModuleInfo.
-        args: An argparse.Namespace instance holding parsed args.
         dry_run: A boolean of whether this invocation is a dry run.
 
     Returns:
@@ -1553,8 +1549,10 @@ class _TestModuleExecutionPlan(_TestExecutionPlan):
     )
 
     return _TestModuleExecutionPlan(
-        test_runner_invocations=invocations,
+        args=args,
         extra_args=extra_args,
+        test_infos=test_infos,
+        test_runner_invocations=invocations,
     )
 
   def requires_device_update(self) -> bool:
@@ -1574,6 +1572,8 @@ class _TestModuleExecutionPlan(_TestExecutionPlan):
     reporter = result_reporter.ResultReporter(
         collect_only=self.extra_args.get(constants.COLLECT_TESTS_ONLY),
         wait_for_debugger=atest_configs.GLOBAL_ARGS.wait_for_debugger,
+        args=self._args,
+        test_infos=self._test_infos,
     )
     reporter.print_starting_text()
 
diff --git a/atest/atest_main_unittest.py b/atest/atest_main_unittest.py
index 611a63ed..18bc4853 100755
--- a/atest/atest_main_unittest.py
+++ b/atest/atest_main_unittest.py
@@ -247,6 +247,39 @@ class AtestUnittests(unittest.TestCase):
     )
 
 
+class AtestMainUnitTests(unittest.TestCase):
+
+  def test_performance_tests_inject_default_args(self):
+    non_perf_test_info = test_info.TestInfo(
+        'some_module',
+        'TestRunner',
+        set(),
+        compatibility_suites=['not-performance'],
+    )
+    perf_test_info = test_info.TestInfo(
+        'some_module',
+        'TestRunner',
+        set(),
+        compatibility_suites=['performance-tests'],
+    )
+    args_original = atest_main._parse_args([])
+    args = atest_main._parse_args([])
+
+    with self.subTest(name='does not inject default args for non-perf tests'):
+      atest_main._AtestMain._inject_default_arguments_based_on_test_infos(
+          [non_perf_test_info], args
+      )
+
+      self.assertEqual(args_original, args)
+
+    with self.subTest(name='injects default args for perf tests'):
+      atest_main._AtestMain._inject_default_arguments_based_on_test_infos(
+          [perf_test_info], args
+      )
+
+      self.assertNotEqual(args_original, args)
+
+
 # pylint: disable=missing-function-docstring
 class AtestUnittestFixture(fake_filesystem_unittest.TestCase):
   """Fixture for ModuleInfo tests."""
diff --git a/atest/atest_utils.py b/atest/atest_utils.py
index 36e7004f..d50e5739 100644
--- a/atest/atest_utils.py
+++ b/atest/atest_utils.py
@@ -20,13 +20,16 @@
 
 from __future__ import print_function
 
+from collections import deque
 from dataclasses import dataclass
 import datetime
 import enum
 import fnmatch
 import hashlib
 import html
-import importlib
+import importlib.resources
+import importlib.util
+import io
 import itertools
 import json
 import logging
@@ -39,9 +42,10 @@ import re
 import shutil
 import subprocess
 import sys
+import threading
 from threading import Thread
 import traceback
-from typing import Any, Dict, List, Set, Tuple
+from typing import Any, Dict, IO, List, Set, Tuple
 import urllib
 import xml.etree.ElementTree as ET
 import zipfile
@@ -53,7 +57,9 @@ from atest.metrics import metrics
 from atest.metrics import metrics_utils
 from atest.tf_proto import test_record_pb2
 
-_BASH_RESET_CODE = '\033[0m\n'
+DEFAULT_OUTPUT_ROLLING_LINES = 6
+_BASH_CLEAR_PREVIOUS_LINE_CODE = '\033[F\033[K'
+_BASH_RESET_CODE = '\033[0m'
 DIST_OUT_DIR = Path(
     os.environ.get(constants.ANDROID_BUILD_TOP, os.getcwd()) + '/out/dist/'
 )
@@ -267,13 +273,126 @@ def _capture_limited_output(full_log):
   return output
 
 
-# TODO: b/187122993 refine subprocess with 'with-statement' in fixit week.
-def run_limited_output(cmd, env_vars=None):
+def stream_io_output(
+    io_input: IO,
+    max_lines=None,
+    full_output_receiver: IO = None,
+    io_output: IO = None,
+    is_io_output_atty=None,
+):
+  """Stream an IO output with max number of rolling lines to display if set.
+
+  Args:
+      input: The file-like object to read the output from.
+      max_lines: The maximum number of rolling lines to display. If None, all
+        lines will be displayed.
+      full_output_receiver: Optional io to receive the full output.
+      io_output: The file-like object to write the output to.
+      is_io_output_atty: Whether the io_output is a TTY.
+  """
+  if io_output is None:
+    io_output = _original_sys_stdout
+  if is_io_output_atty is None:
+    is_io_output_atty = _has_colors(io_output)
+  if not max_lines or not is_io_output_atty:
+    for line in iter(io_input.readline, ''):
+      if not line:
+        break
+      if full_output_receiver is not None:
+        full_output_receiver.write(
+            line if isinstance(line, str) else line.decode('utf-8')
+        )
+      io_output.write(line)
+      io_output.flush()
+    return
+
+  term_width, _ = get_terminal_size()
+  last_lines = deque(maxlen=max_lines)
+  is_rolling = True
+
+  def reset_output():
+    if is_rolling and last_lines:
+      io_output.write(_BASH_CLEAR_PREVIOUS_LINE_CODE * (len(last_lines) + 2))
+
+  def write_output(new_lines: list[str]):
+    if not is_rolling:
+      return
+    last_lines.extend(new_lines)
+    lines = ['========== Rolling subprocess output ==========']
+    lines.extend(last_lines)
+    lines.append('-----------------------------------------------')
+    io_output.write('\n'.join(lines))
+    io_output.write('\n')
+    io_output.flush()
+
+  original_stdout = sys.stdout
+  original_stderr = sys.stderr
+
+  lock = threading.Lock()
+
+  class SafeStdout:
+
+    def __init__(self):
+      self._buffers = []
+
+    def write(self, buf: str) -> None:
+      if len(buf) == 1 and buf[0] == '\n' and self._buffers:
+        with lock:
+          reset_output()
+          original_stdout.write(''.join(self._buffers))
+          original_stdout.write('\n')
+          original_stdout.flush()
+          write_output([])
+          self._buffers.clear()
+      else:
+        self._buffers.append(buf)
+
+    def flush(self) -> None:
+      original_stdout.flush()
+
+  sys.stdout = SafeStdout()
+  sys.stderr = sys.stdout
+
+  for line in iter(io_input.readline, ''):
+    if not line:
+      break
+    line = line.decode('utf-8') if isinstance(line, bytes) else line
+    if full_output_receiver is not None:
+      full_output_receiver.write(line)
+    line = line.rstrip().replace('\t', '  ')
+    # Split the line if it's longer than the terminal width
+    wrapped_lines = (
+        [line]
+        if len(line) <= term_width
+        else [line[i : i + term_width] for i in range(0, len(line), term_width)]
+    )
+    with lock:
+      reset_output()
+      write_output(wrapped_lines)
+
+  with lock:
+    reset_output()
+    is_rolling = False
+    io_output.write(_BASH_RESET_CODE)
+    io_output.flush()
+
+  sys.stdout = original_stdout
+  sys.stderr = original_stderr
+
+  io_input.close()
+
+
+def run_limited_output(
+    cmd, env_vars=None, shell=False, start_new_session=False
+):
   """Runs a given command and streams the output on a single line in stdout.
 
   Args:
       cmd: A list of strings representing the command to run.
       env_vars: Optional arg. Dict of env vars to set during build.
+      shell: Optional arg. Whether to use shell to run the command.
+      start_new_session: Optional arg. Whether to start a new session for the
+        command.
 
   Raises:
       subprocess.CalledProcessError: When the command exits with a non-0
@@ -281,35 +400,26 @@ def run_limited_output(cmd, env_vars=None):
   """
   # Send stderr to stdout so we only have to deal with a single pipe.
   with subprocess.Popen(
-      cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env_vars
+      cmd,
+      stdout=subprocess.PIPE,
+      stderr=subprocess.STDOUT,
+      env=env_vars,
+      shell=shell,
+      start_new_session=start_new_session,
+      text=True,
   ) as proc:
-    sys.stdout.write('\n')
-    term_width, _ = get_terminal_size()
-    white_space = ' ' * int(term_width)
-    full_output = []
-    while proc.poll() is None:
-      line = proc.stdout.readline().decode('utf-8')
-      # Readline will often return empty strings.
-      if not line:
-        continue
-      full_output.append(line)
-      # Trim the line to the width of the terminal.
-      # Note: Does not handle terminal resizing, which is probably not
-      #       worth checking the width every loop.
-      if len(line) >= term_width:
-        line = line[: term_width - 1]
-      # Clear the last line we outputted.
-      sys.stdout.write('\r%s\r' % white_space)
-      sys.stdout.write('%s' % line.strip())
-      sys.stdout.flush()
-    # Reset stdout (on bash) to remove any custom formatting and newline.
-    sys.stdout.write(_BASH_RESET_CODE)
-    sys.stdout.flush()
-    # Wait for the Popen to finish completely before checking the
-    # returncode.
-    proc.wait()
-    if proc.returncode != 0:
-      raise subprocess.CalledProcessError(proc.returncode, cmd, full_output)
+    full_output_receiver = io.StringIO()
+    stream_io_output(
+        proc.stdout,
+        DEFAULT_OUTPUT_ROLLING_LINES,
+        full_output_receiver,
+        _original_sys_stdout,
+    )
+    returncode = proc.wait()
+    if returncode:
+      raise subprocess.CalledProcessError(
+          returncode, cmd, full_output_receiver.getvalue()
+      )
 
 
 def get_build_out_dir(*joinpaths) -> Path:
@@ -501,6 +611,11 @@ def is_test_mapping(args):
   return all((len(args.tests) == 1, args.tests[0][0] == ':'))
 
 
+def is_atty_terminal() -> bool:
+  """Check if the current process is running in a TTY."""
+  return getattr(_original_sys_stdout, 'isatty', lambda: False)()
+
+
 def _has_colors(stream):
   """Check the output stream is colorful.
 
@@ -820,7 +935,7 @@ def update_test_info_cache(test_reference, test_infos, cache_root=None):
   # Save test_info to files.
   try:
     with open(cache_path, 'wb') as test_info_cache_file:
-      logging.debug('Saving cache %s.', cache_path)
+      logging.debug('Saving cache for %s as %s.', test_reference, cache_path)
       pickle.dump(test_infos, test_info_cache_file, protocol=2)
   except (pickle.PicklingError, TypeError, IOError) as err:
     # Won't break anything, just log this error, and collect the exception
@@ -844,7 +959,7 @@ def load_test_info_cache(test_reference, cache_root=None):
 
   cache_file = get_test_info_cache_path(test_reference, cache_root)
   if os.path.isfile(cache_file):
-    logging.debug('Loading cache %s.', cache_file)
+    logging.debug('Loading cache %s from %s.', test_reference, cache_file)
     try:
       with open(cache_file, 'rb') as config_dictionary_file:
         return pickle.load(config_dictionary_file, encoding='utf-8')
@@ -1624,7 +1739,7 @@ def save_build_files_timestamp():
         json.dump(timestamp, _file)
 
 
-def run_multi_proc(func, *args, **kwargs):
+def run_multi_proc(func, *args, **kwargs) -> Process:
   """Start a process with multiprocessing and return Process object.
 
   Args:
@@ -1640,13 +1755,13 @@ def run_multi_proc(func, *args, **kwargs):
   return proc
 
 
-def start_threading(target, *args, **kwargs):
+def start_threading(target, *args, **kwargs) -> Thread:
   """Start a Thread-based parallelism.
 
   Args:
-      func: A string of function name which will be the target name.
+      target: A string of function name which will be the target name.
         args/kwargs: check doc page:
-      https://docs.python.org/3/library/threading.html#threading.Thread
+        https://docs.python.org/3/library/threading.html#threading.Thread
 
   Returns:
       threading.Thread object.
diff --git a/atest/atest_utils_unittest.py b/atest/atest_utils_unittest.py
index 75bc5236..a3eac855 100755
--- a/atest/atest_utils_unittest.py
+++ b/atest/atest_utils_unittest.py
@@ -67,6 +67,109 @@ Manifest groups: all,-notdefault
 """
 
 
+class StreamIoOutputTest(unittest.TestCase):
+  """Class that tests the _stream_io_output function."""
+
+  def test_stream_io_output_no_max_lines_no_clear_line_code(self):
+    """Test when max_lines is None, no clear line code is written to the stream."""
+    io_input = StringIO()
+    io_input.write(f'1\n' * 10)
+    io_input.seek(0)
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=None, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertNotIn(
+        atest_utils._BASH_CLEAR_PREVIOUS_LINE_CODE, io_output.getvalue()
+    )
+
+  @mock.patch.object(atest_utils, 'get_terminal_size', return_value=(5, -1))
+  def test_stream_io_output_wrap_long_lines(self, _):
+    """Test when max_lines is set, long lines will be wrapped."""
+    io_input = StringIO()
+    io_input.write(f'1' * 10)
+    io_input.seek(0)
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=10, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertIn('11111\n11111', io_output.getvalue())
+
+  @mock.patch.object(atest_utils, 'get_terminal_size', return_value=(5, -1))
+  def test_stream_io_output_clear_lines_over_max_lines(self, _):
+    """Test when line exceeds max_lines, the previous lines are cleared."""
+    io_input = StringIO()
+    io_input.write('1\n2\n3\n')
+    io_input.seek(0)
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=2, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertIn(
+        '2\n3\n',
+        io_output.getvalue(),
+    )
+    self.assertNotIn(
+        '1\n2\n3\n',
+        io_output.getvalue(),
+    )
+
+  @mock.patch.object(atest_utils, 'get_terminal_size', return_value=(5, -1))
+  def test_stream_io_output_no_clear_lines_under_max_lines(self, _):
+    """Test when line is under max_lines, the previous lines are not cleared."""
+    io_input = StringIO()
+    io_input.write('1\n2\n3\n')
+    io_input.seek(0)
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=4, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertIn(
+        '1\n2\n3\n',
+        io_output.getvalue(),
+    )
+
+  @mock.patch.object(atest_utils, 'get_terminal_size', return_value=(5, -1))
+  def test_stream_io_output_no_lines_written_no_lines_cleared(self, _):
+    """Test when nothing is written, no lines are cleared."""
+    io_input = StringIO()
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=2, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertNotIn(
+        atest_utils._BASH_CLEAR_PREVIOUS_LINE_CODE,
+        io_output.getvalue(),
+    )
+
+  @mock.patch.object(atest_utils, 'get_terminal_size', return_value=(5, -1))
+  def test_stream_io_output_replace_tab_with_spaces(self, _):
+    """Test when line exceeds max_lines, the previous lines are cleared."""
+    io_input = StringIO()
+    io_input.write('1\t2')
+    io_input.seek(0)
+    io_output = StringIO()
+
+    atest_utils.stream_io_output(
+        io_input, max_lines=2, io_output=io_output, is_io_output_atty=True
+    )
+
+    self.assertNotIn(
+        '\t',
+        io_output.getvalue(),
+    )
+
+
 class ConcatenatePathTest(unittest.TestCase):
   """Class that tests path concatenation."""
 
diff --git a/atest/bazel/resources/rules/tradefed_test.bzl b/atest/bazel/resources/rules/tradefed_test.bzl
index eca0fc13..7fbc750a 100644
--- a/atest/bazel/resources/rules/tradefed_test.bzl
+++ b/atest/bazel/resources/rules/tradefed_test.bzl
@@ -14,10 +14,6 @@
 
 """Rules used to run tests using Tradefed."""
 
-load("//bazel/rules:platform_transitions.bzl", "device_transition", "host_transition")
-load("//bazel/rules:tradefed_test_aspects.bzl", "soong_prebuilt_tradefed_test_aspect")
-load("//bazel/rules:tradefed_test_dependency_info.bzl", "TradefedTestDependencyInfo")
-load("//bazel/rules:common_settings.bzl", "BuildSettingInfo")
 load(
     "//:constants.bzl",
     "aapt2_label",
@@ -32,7 +28,11 @@ load(
     "tradefed_test_framework_label",
     "vts_core_tradefed_harness_label",
 )
+load("//bazel/rules:common_settings.bzl", "BuildSettingInfo")
 load("//bazel/rules:device_test.bzl", "device_test")
+load("//bazel/rules:platform_transitions.bzl", "device_transition", "host_transition")
+load("//bazel/rules:tradefed_test_aspects.bzl", "soong_prebuilt_tradefed_test_aspect")
+load("//bazel/rules:tradefed_test_dependency_info.bzl", "TradefedTestDependencyInfo")
 
 TradefedTestInfo = provider(
     doc = "Info about a Tradefed test module",
@@ -381,7 +381,7 @@ def _get_tradefed_deps(suites, tradefed_deps = []):
     # Since `vts-core-tradefed-harness` includes `compatibility-tradefed`, we
     # will exclude `compatibility-tradefed` if `vts-core-tradefed-harness` exists.
     if vts_core_tradefed_harness_label in all_tradefed_deps:
-        all_tradefed_deps.pop(compatibility_tradefed_label, default = None)
+        all_tradefed_deps.pop(compatibility_tradefed_label)
 
     return all_tradefed_deps.keys()
 
@@ -424,18 +424,16 @@ def _configure_java_toolchain(ctx):
 
 def _configure_python_toolchain(ctx):
     py_toolchain_info = ctx.toolchains[_PY_TOOLCHAIN]
-    py2_interpreter = py_toolchain_info.py2_runtime.interpreter
     py3_interpreter = py_toolchain_info.py3_runtime.interpreter
 
     # Create `python` and `python3` symlinks in the runfiles tree and add them
     # to the executable path. This is required because scripts reference these
     # commands in their shebang line.
     py_runfiles = ctx.runfiles(symlinks = {
-        "/".join([py2_interpreter.dirname, "python"]): py2_interpreter,
+        "/".join([py3_interpreter.dirname, "python"]): py3_interpreter,
         "/".join([py3_interpreter.dirname, "python3"]): py3_interpreter,
     })
     py_paths = [
-        _BAZEL_WORK_DIR + py2_interpreter.dirname,
         _BAZEL_WORK_DIR + py3_interpreter.dirname,
     ]
     return (py_paths, py_runfiles)
diff --git a/atest/cli_translator.py b/atest/cli_translator.py
index 6d7b7b47..e2bf5f3d 100644
--- a/atest/cli_translator.py
+++ b/atest/cli_translator.py
@@ -20,12 +20,14 @@ from __future__ import print_function
 
 from dataclasses import dataclass
 import fnmatch
+import functools
 import json
 import logging
 import os
 from pathlib import Path
 import re
 import sys
+import threading
 import time
 from typing import List, Set
 
@@ -33,6 +35,7 @@ from atest import atest_error
 from atest import atest_utils
 from atest import bazel_mode
 from atest import constants
+from atest import rollout_control
 from atest import test_finder_handler
 from atest import test_mapping
 from atest.atest_enum import DetectType, ExitCode
@@ -41,6 +44,7 @@ from atest.metrics import metrics_utils
 from atest.test_finders import module_finder
 from atest.test_finders import test_finder_utils
 from atest.test_finders import test_info
+from atest.tools import indexing
 
 FUZZY_FINDER = 'FUZZY'
 CACHE_FINDER = 'CACHE'
@@ -85,6 +89,7 @@ class CLITranslator:
       bazel_mode_enabled=False,
       host=False,
       bazel_mode_features: List[bazel_mode.Features] = None,
+      indexing_thread: threading.Thread = None,
   ):
     """CLITranslator constructor
 
@@ -95,10 +100,14 @@ class CLITranslator:
         bazel_mode_enabled: Boolean of args.bazel_mode.
         host: Boolean of args.host.
         bazel_mode_features: List of args.bazel_mode_features.
+        indexing_thread: Thread of indexing.
     """
     self.mod_info = mod_info
     self.root_dir = os.getenv(constants.ANDROID_BUILD_TOP, os.sep)
-    self._bazel_mode = bazel_mode_enabled
+    self._bazel_mode = (
+        bazel_mode_enabled
+        and not rollout_control.deprecate_bazel_mode.is_enabled()
+    )
     self._bazel_mode_features = bazel_mode_features or []
     self._host = host
     self.enable_file_patterns = False
@@ -110,11 +119,31 @@ class CLITranslator:
           'to clean the old cache.)'
       )
     self.fuzzy_search = True
+    self._indexing_thread = indexing_thread
+
+  @functools.cache
+  def _wait_for_index_if_needed(self) -> None:
+    """Checks indexing status and wait for it to complete if necessary."""
+    if (
+        not self._indexing_thread
+        or not self._indexing_thread.is_alive()
+        or indexing.Indices().has_all_indices()
+    ):
+      return
+    start_wait_for_indexing = time.time()
+    print('Waiting for the module indexing to complete.')
+    self._indexing_thread.join()
+    metrics.LocalDetectEvent(
+        detect_type=DetectType.WAIT_FOR_INDEXING_MS,
+        result=int(round((time.time() - start_wait_for_indexing) * 1000)),
+    )
 
   # pylint: disable=too-many-locals
   # pylint: disable=too-many-branches
   # pylint: disable=too-many-statements
-  def _find_test_infos(self, test, tm_test_detail) -> List[test_info.TestInfo]:
+  def _find_test_infos(
+      self, test: str, tm_test_detail: test_mapping.TestDetail
+  ) -> List[test_info.TestInfo]:
     """Return set of TestInfos based on a given test.
 
     Args:
@@ -147,7 +176,23 @@ class CLITranslator:
           )
           for f in find_methods
       ]
+
     for finder in find_methods:
+      # Ideally whether a find method requires indexing should be defined within the
+      # finder class itself. However the current finder class design prevent
+      # us from defining property without a bigger change. Here we use a tuple
+      # to specify the finders that doesn't require indexing and leave the
+      # class redesign work for future work.
+      if finder.finder_info not in (
+          'EXAMPLE',
+          'CACHE',
+          'MODULE',
+          'INTEGRATION',
+          'CONFIG',
+          'SUITE_PLAN',
+      ):
+        self._wait_for_index_if_needed()
+
       # For tests in TEST_MAPPING, find method is only related to
       # test name, so the details can be set after test_info object
       # is created.
diff --git a/atest/coverage/coverage.py b/atest/coverage/coverage.py
index b99cbb4d..b1c49f0c 100644
--- a/atest/coverage/coverage.py
+++ b/atest/coverage/coverage.py
@@ -249,7 +249,7 @@ def _collect_native_report_binaries(code_under_test, mod_info, is_host_enabled):
         continue
       module_dir = soong_intermediates.joinpath(path, module)
       # Check for unstripped binaries to report coverage.
-      report_binaries.update(_find_native_binaries(module_dir))
+      report_binaries.update(module_dir.glob('*cov*/**/unstripped/*'))
 
     # Host tests use the test itself to generate the coverage report.
     info = mod_info.get_module_info(module)
@@ -264,26 +264,21 @@ def _collect_native_report_binaries(code_under_test, mod_info, is_host_enabled):
           str(f) for f in mod_info.get_installed_paths(module)
       )
 
-  return report_binaries
-
-
-def _find_native_binaries(module_dir):
-  files = module_dir.glob('*cov*/**/unstripped/*')
-
-  # Exclude .rsp files. These are files containing the command line used to
-  # generate the unstripped binaries, but are stored in the same directory as
-  # the actual output binary.
-  # Exclude .d and .d.raw files. These are Rust dependency files and are also
-  # stored in the unstripped directory.
-  # Exclude .toc files. These are just a table of conents of a shared library,
-  # but are also stored in the unstripped directory.
-  return [
-      str(file)
-      for file in files
-      if '.rsp' not in file.suffixes
-      and '.d' not in file.suffixes
-      and '.toc' not in file.suffixes
-  ]
+  return _strip_irrelevant_objects(report_binaries)
+
+
+def _strip_irrelevant_objects(files):
+  objects = set()
+  for file in files:
+    cmd = ['llvm-readobj', file]
+    try:
+      subprocess.run(
+          cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
+      )
+      objects.add(file)
+    except subprocess.CalledProcessError:
+      logging.debug(f'{file} is not a valid object file, skipping.')
+  return objects
 
 
 def _get_all_src_paths(modules, mod_info):
diff --git a/atest/coverage/coverage_unittest.py b/atest/coverage/coverage_unittest.py
index 36194ae8..690f9979 100755
--- a/atest/coverage/coverage_unittest.py
+++ b/atest/coverage/coverage_unittest.py
@@ -149,7 +149,14 @@ class CollectNativeReportBinariesUnittests(unittest.TestCase):
       return_value=PosixPath('/out/soong/.intermediates'),
   )
   @mock.patch.object(PosixPath, 'glob')
-  def test_native_binary(self, _glob, _get_build_out_dir):
+  @mock.patch.object(
+      coverage,
+      '_strip_irrelevant_objects',
+      return_value={
+          '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin'
+      },
+  )
+  def test_native_binary(self, _strip_irrelevant_objects, _glob, _get_build_out_dir):
     _glob.return_value = [
         PosixPath(
             '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin'
@@ -175,7 +182,14 @@ class CollectNativeReportBinariesUnittests(unittest.TestCase):
       return_value=PosixPath('/out/soong/.intermediates'),
   )
   @mock.patch.object(PosixPath, 'glob')
-  def test_skip_rsp_and_d_and_toc_files(self, _glob, _get_build_out_dir):
+  @mock.patch.object(
+      coverage,
+      '_strip_irrelevant_objects',
+      return_value={
+          '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin'
+      },
+  )
+  def test_skip_rsp_and_d_and_toc_files(self, _strip_irrelevant_objects, _glob, _get_build_out_dir):
     _glob.return_value = [
         PosixPath(
             '/out/soong/.intermediates/path/to/native_bin/variant-name-cov/unstripped/native_bin'
@@ -204,7 +218,14 @@ class CollectNativeReportBinariesUnittests(unittest.TestCase):
         },
     )
 
-  def test_host_test_includes_installed(self):
+  @mock.patch.object(
+      coverage,
+      '_strip_irrelevant_objects',
+      return_value={
+          '/out/host/nativetests/native_host_test'
+      },
+  )
+  def test_host_test_includes_installed(self, _strip_irrelevant_objects):
     code_under_test = {'native_host_test'}
     mod_info = create_module_info([
         module(
diff --git a/atest/integration_tests/Android.bp b/atest/integration_tests/Android.bp
index 08bf8ceb..dff30d9b 100644
--- a/atest/integration_tests/Android.bp
+++ b/atest/integration_tests/Android.bp
@@ -92,6 +92,7 @@ python_test_host {
         "atest_command_success_tests.py",
         "atest_command_verification_tests.py",
         "atest_test_archetype_integration_tests.py",
+        "atest_dry_run_diff_tests.py",
     ],
     test_config_template: ":atest_integration_test_config_template",
     test_options: {
@@ -172,3 +173,18 @@ python_test_host {
         "atest_integration_test_defaults",
     ],
 }
+
+python_test_host {
+    name: "atest_dry_run_diff_tests",
+    srcs: [
+        "atest_dry_run_diff_tests.py",
+        "atest_command_verification_tests.py",
+    ],
+    test_config_template: ":atest_integration_test_config_template",
+    test_options: {
+        unit_test: false,
+    },
+    defaults: [
+        "atest_integration_test_defaults",
+    ],
+}
diff --git a/atest/integration_tests/atest_command_verification_tests.py b/atest/integration_tests/atest_command_verification_tests.py
index 0cbc9306..334609d8 100644
--- a/atest/integration_tests/atest_command_verification_tests.py
+++ b/atest/integration_tests/atest_command_verification_tests.py
@@ -20,16 +20,6 @@ import os
 from typing import Any, Callable
 import atest_integration_test
 
-# Note: The following constants should ideally be imported from their
-#       corresponding prod source code, but this makes local execution of the
-#       integration test harder due to some special dependencies in the prod
-#       code. Therefore we copy the definition here for now in favor of easier
-#       local integration test execution. If value changes in the source code
-#       breaking the integration test becomes a problem in the future, we can
-#       reconsider importing these constants.
-# Log prefix for dry-run run command. Defined in atest/atest_main.py
-_DRY_RUN_COMMAND_LOG_PREFIX = 'Internal run command from dry-run: '
-
 
 class CommandVerificationTests(atest_integration_test.AtestTestCase):
   """Checks atest tradefed commands."""
@@ -257,47 +247,49 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         expected_cmd=expected_cmd,
     )
 
-  @atest_integration_test.run_in_parallel
-  def test_android_sample_cts_device_report_log_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = 'android.sample.cts.SampleDeviceReportLogTest'
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter'
-        ' CtsSampleDeviceTestCases --atest-include-filter'
-        ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
-        ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
-        ' VERBOSE --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_android_sample_cts_device_report_log_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = 'android.sample.cts.SampleDeviceReportLogTest'
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter'
+  #       ' CtsSampleDeviceTestCases --atest-include-filter'
+  #       ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest'
+  #       ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
+  #       ' VERBOSE --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
 
-  @atest_integration_test.run_in_parallel
-  def test_android_sample_cts_shared_prefs_test(self):
-    """Verify that the test's command runs correctly."""
-    atest_cmd = 'android.sample.cts.SampleDeviceTest#testSharedPreferences'
-    expected_cmd = (
-        'atest_tradefed.sh template/atest_device_test_base --template:map'
-        ' test=atest'
-        ' --template:map log_saver=template/log/atest_log_saver'
-        ' --no-enable-granular-attempts --include-filter'
-        ' CtsSampleDeviceTestCases --atest-include-filter'
-        ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceTest#testSharedPreferences'
-        ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
-        ' VERBOSE --no-early-device-release --test-arg'
-        ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
-    )
-    self._verify_atest_internal_runner_command(
-        atest_cmd,
-        self._assert_equivalent_cmds,
-        expected_cmd=expected_cmd,
-    )
+  # Disabled due to b/358615386
+  # @atest_integration_test.run_in_parallel
+  # def test_android_sample_cts_shared_prefs_test(self):
+  #   """Verify that the test's command runs correctly."""
+  #   atest_cmd = 'android.sample.cts.SampleDeviceTest#testSharedPreferences'
+  #   expected_cmd = (
+  #       'atest_tradefed.sh template/atest_device_test_base --template:map'
+  #       ' test=atest'
+  #       ' --template:map log_saver=template/log/atest_log_saver'
+  #       ' --no-enable-granular-attempts --include-filter'
+  #       ' CtsSampleDeviceTestCases --atest-include-filter'
+  #       ' CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceTest#testSharedPreferences'
+  #       ' --skip-loading-config-jar --log-level-display VERBOSE --log-level'
+  #       ' VERBOSE --no-early-device-release --test-arg'
+  #       ' com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.AppModeInstant'
+  #   )
+  #   self._verify_atest_internal_runner_command(
+  #       atest_cmd,
+  #       self._assert_equivalent_cmds,
+  #       expected_cmd=expected_cmd,
+  #   )
 
   @atest_integration_test.run_in_parallel
   def test_hello_world_test(self):
@@ -638,36 +630,6 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
         print_output=False,
     ).check_returncode()
 
-  def _sanitize_runner_command(self, cmd: str) -> str:
-    """Sanitize an atest runner command by removing non-essential args."""
-    remove_args_starting_with = [
-        '--skip-all-system-status-check',
-        '--atest-log-file-path',
-        'LD_LIBRARY_PATH=',
-        '--proto-output-file=',
-        '--log-root-path',
-    ]
-    remove_args_with_values = ['-s', '--serial']
-    build_command = 'build/soong/soong_ui.bash'
-    original_args = cmd.split()
-    result_args = []
-    for arg in original_args:
-      if arg == build_command:
-        result_args.append(f'./{build_command}')
-        continue
-      if not any(
-          (arg.startswith(prefix) for prefix in remove_args_starting_with)
-      ):
-        result_args.append(arg)
-    for arg in remove_args_with_values:
-      while arg in result_args:
-        idx = result_args.index(arg)
-        # Delete value index first.
-        del result_args[idx + 1]
-        del result_args[idx]
-
-    return ' '.join(result_args)
-
   def _assert_equivalent_cmds(
       self,
       atest_cmd: str,
@@ -685,8 +647,8 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
 
     Returns:
     """
-    actual_cmd = self._sanitize_runner_command(actual_cmd)
-    expected_cmd = self._sanitize_runner_command(expected_cmd)
+    actual_cmd = atest_integration_test.sanitize_runner_command(actual_cmd)
+    expected_cmd = atest_integration_test.sanitize_runner_command(expected_cmd)
 
     self.assertEqual(
         set(actual_cmd.split()),
@@ -721,7 +683,7 @@ class CommandVerificationTests(atest_integration_test.AtestTestCase):
       )
       result.check_returncode()
       runner_cmd = result.get_atest_log_values_from_prefix(
-          _DRY_RUN_COMMAND_LOG_PREFIX
+          atest_integration_test.DRY_RUN_COMMAND_LOG_PREFIX
       )[0]
 
       step_out = self.create_step_output()
diff --git a/atest/integration_tests/atest_dry_run_diff_tests.py b/atest/integration_tests/atest_dry_run_diff_tests.py
new file mode 100644
index 00000000..3bab945d
--- /dev/null
+++ b/atest/integration_tests/atest_dry_run_diff_tests.py
@@ -0,0 +1,294 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024, The Android Open Source Project
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
+"""A collection of integration test cases for atest."""
+
+import concurrent.futures
+import csv
+import dataclasses
+import functools
+import multiprocessing
+import pathlib
+from typing import Any, Optional
+import atest_integration_test
+
+
+@dataclasses.dataclass
+class _AtestCommandUsage:
+  """A class to hold the atest command and its usage frequency."""
+
+  command: str
+  usage_count: int
+  user_count: int
+
+  @staticmethod
+  def to_json(usage: '_AtestCommandUsage') -> dict[str, Any]:
+    """Converts an _AtestCommandUsage object to a JSON dictionary."""
+    return {
+        'command': usage.command,
+        'usage_count': usage.usage_count,
+        'user_count': usage.user_count,
+    }
+
+  @staticmethod
+  def from_json(json_dict: dict[str, Any]) -> '_AtestCommandUsage':
+    """Creates an _AtestCommandUsage object from a JSON dictionary."""
+    return _AtestCommandUsage(
+        json_dict['command'],
+        json_dict['usage_count'],
+        json_dict['user_count'],
+    )
+
+
+class AtestDryRunDiffTests(atest_integration_test.AtestTestCase):
+  """Tests to compare the atest dry run output between atest prod binary and dev binary."""
+
+  def setUp(self):
+    super().setUp()
+    self.maxDiff = None
+
+  def test_dry_run_output_diff(self):
+    """Tests to compare the atest dry run output between atest prod binary and dev binary."""
+    script = self.create_atest_script()
+    script.add_build_step(self._build_step)
+    script.add_test_step(self._test_step)
+    script.run()
+
+  def _get_atest_command_usages(
+      self, repo_root: str, dry_run_diff_test_cmd_input_file: Optional[str]
+  ) -> list[_AtestCommandUsage]:
+    """Returns the atest command usages for the dry run diff test.
+
+    Returns:
+      A list of _AtestCommandUsage objects.
+    """
+    if not dry_run_diff_test_cmd_input_file:
+      return [
+          _AtestCommandUsage(cmd, -1, -1) for cmd in _default_input_commands
+      ]
+    with (
+        pathlib.Path(repo_root)
+        .joinpath(dry_run_diff_test_cmd_input_file)
+        .open()
+    ) as input_file:
+      reader = csv.reader(input_file)
+      return [_AtestCommandUsage(*row) for row in reader if row and row[0]]
+
+  def _build_step(
+      self,
+      step_in: atest_integration_test.StepInput,
+  ) -> atest_integration_test.StepOutput:
+
+    run_command = lambda use_prod, command_usage: self.run_atest_command(
+        '--dry-run -it ' + command_usage.command,
+        step_in,
+        include_device_serial=False,
+        use_prebuilt_atest_binary=use_prod,
+        pipe_to_stdin='n',
+    )
+    get_prod_result = functools.partial(run_command, True)
+    get_dev_result = functools.partial(run_command, False)
+
+    command_usages = self._get_atest_command_usages(
+        step_in.get_repo_root(),
+        step_in.get_config().dry_run_diff_test_cmd_input_file,
+    )
+
+    with concurrent.futures.ThreadPoolExecutor(
+        max_workers=multiprocessing.cpu_count()
+    ) as executor:
+      # Run the version command with -c to clear the cache by the prod binary.
+      self.run_atest_command(
+          '--version -c',
+          step_in,
+          include_device_serial=False,
+          use_prebuilt_atest_binary=True,
+      )
+      cmd_results_prod = list(executor.map(get_prod_result, command_usages))
+      # Run the version command with -c to clear the cache by the dev binary.
+      self.run_atest_command(
+          '--version -c',
+          step_in,
+          include_device_serial=False,
+          use_prebuilt_atest_binary=False,
+      )
+      cmd_results_dev = list(executor.map(get_dev_result, command_usages))
+
+    step_out = self.create_step_output()
+    step_out.set_snapshot_include_paths([])
+    step_out.add_snapshot_obj(
+        'usages', list(map(_AtestCommandUsage.to_json, command_usages))
+    )
+    step_out.add_snapshot_obj(
+        'returncode_prod',
+        list(map(lambda result: result.get_returncode(), cmd_results_prod)),
+    )
+    step_out.add_snapshot_obj(
+        'returncode_dev',
+        list(map(lambda result: result.get_returncode(), cmd_results_dev)),
+    )
+    step_out.add_snapshot_obj(
+        'elapsed_time_prod',
+        list(map(lambda result: result.get_elapsed_time(), cmd_results_prod)),
+    )
+    step_out.add_snapshot_obj(
+        'elapsed_time_dev',
+        list(map(lambda result: result.get_elapsed_time(), cmd_results_dev)),
+    )
+    step_out.add_snapshot_obj(
+        'runner_cmd_prod',
+        list(
+            map(
+                lambda result: result.get_atest_log_values_from_prefix(
+                    atest_integration_test.DRY_RUN_COMMAND_LOG_PREFIX
+                ),
+                cmd_results_prod,
+            )
+        ),
+    )
+    step_out.add_snapshot_obj(
+        'runner_cmd_dev',
+        list(
+            map(
+                lambda result: result.get_atest_log_values_from_prefix(
+                    atest_integration_test.DRY_RUN_COMMAND_LOG_PREFIX
+                ),
+                cmd_results_dev,
+            )
+        ),
+    )
+
+    return step_out
+
+  def _test_step(self, step_in: atest_integration_test.StepInput) -> None:
+    usages = list(map(_AtestCommandUsage.from_json, step_in.get_obj('usages')))
+    returncode_prod = step_in.get_obj('returncode_prod')
+    returncode_dev = step_in.get_obj('returncode_dev')
+    elapsed_time_prod = step_in.get_obj('elapsed_time_prod')
+    elapsed_time_dev = step_in.get_obj('elapsed_time_dev')
+    runner_cmd_prod = step_in.get_obj('runner_cmd_prod')
+    runner_cmd_dev = step_in.get_obj('runner_cmd_dev')
+
+    for idx in range(len(usages)):
+      impact_str = (
+          'Potential'
+          f' impacted number of users: {usages[idx].user_count}, number of'
+          f' invocations: {usages[idx].usage_count}.'
+      )
+      with self.subTest(name=f'{usages[idx].command}_returncode'):
+        self.assertEqual(
+            returncode_prod[idx],
+            returncode_dev[idx],
+            f'Return code mismatch for command: {usages[idx].command}. Prod:'
+            f' {returncode_prod[idx]} Dev: {returncode_dev[idx]}. {impact_str}',
+        )
+      with self.subTest(name=f'{usages[idx].command}_elapsed_time'):
+        self.assertAlmostEqual(
+            elapsed_time_prod[idx],
+            elapsed_time_dev[idx],
+            delta=12,
+            msg=(
+                f'Elapsed time mismatch for command: {usages[idx].command}.'
+                f' Prod: {elapsed_time_prod[idx]} Dev:'
+                f' {elapsed_time_dev[idx]} {impact_str}'
+            ),
+        )
+      with self.subTest(
+          name=f'{usages[idx].command}_runner_cmd_has_same_elements'
+      ):
+        self.assertEqual(
+            len(runner_cmd_prod[idx]),
+            len(runner_cmd_dev[idx]),
+            'Nummber of runner commands mismatch for command:'
+            ' {usages[idx].command}.',
+        )
+
+        for cmd_idx in range(len(runner_cmd_prod[idx])):
+          sanitized_runner_cmd_prod = (
+              atest_integration_test.sanitize_runner_command(runner_cmd_prod[idx][cmd_idx])
+          )
+          sanitized_runner_cmd_dev = (
+              atest_integration_test.sanitize_runner_command(runner_cmd_dev[idx][cmd_idx])
+          )
+          self.assertEqual(
+              set(sanitized_runner_cmd_prod.split(' ')),
+              set(sanitized_runner_cmd_dev.split(' ')),
+              'Runner command mismatch for command:'
+              f' {usages[idx].command}.\nProd:\n'
+              f' {sanitized_runner_cmd_prod}\nDev:\n{sanitized_runner_cmd_dev}\n'
+              f' {impact_str}',
+          )
+
+
+# A copy of the list of atest commands tested in the command verification tests.
+_default_input_commands = [
+    'AnimatorTest',
+    'CtsAnimationTestCases:AnimatorTest',
+    'CtsSampleDeviceTestCases:android.sample.cts',
+    'CtsAnimationTestCases CtsSampleDeviceTestCases',
+    'HelloWorldTests',
+    'android.animation.cts',
+    'android.sample.cts.SampleDeviceReportLogTest',
+    'android.sample.cts.SampleDeviceTest#testSharedPreferences',
+    'hello_world_test',
+    'native-benchmark',
+    'platform_testing/tests/example/native',
+    'platform_testing/tests/example/native/Android.bp',
+    'tools/tradefederation/core/res/config/native-benchmark.xml',
+    'QuickAccessWalletRoboTests',
+    'QuickAccessWalletRoboTests --host',
+    'CtsWifiAwareTestCases',
+    'pts-bot:PAN/GN/MISC/UUID/BV-01-C',
+    'TeeUIUtilsTest',
+    'android.security.cts.PermissionMemoryFootprintTest',
+    'CtsSampleDeviceTestCases:SampleDeviceTest#testSharedPreferences',
+    'CtsSampleDeviceTestCases:android.sample.cts.SampleDeviceReportLogTest',
+    (
+        'PerInstance/CameraHidlTest#'
+        'configureInjectionStreamsAvailableOutputs/0_internal_0'
+    ),
+    (
+        'VtsHalCameraProviderV2_4TargetTest:PerInstance/'
+        'CameraHidlTest#configureInjectionStreamsAvailableOutputs/'
+        '0_internal_0'
+    ),
+    (
+        'TeeUIUtilsTest#intersectTest,ConvexObjectConstruction,'
+        'ConvexObjectLineIntersection'
+    ),
+    (
+        'CtsSecurityTestCases:android.security.cts.'
+        'ActivityManagerTest#testActivityManager_'
+        'registerUidChangeObserver_allPermission'
+    ),
+    (
+        'cts/tests/tests/security/src/android/security/cts/'
+        'ActivityManagerTest.java#testActivityManager_'
+        'registerUidChangeObserver_allPermission'
+    ),
+    (
+        'cts/tests/tests/security/src/android/security/cts/'
+        'PermissionMemoryFootprintTest.kt#'
+        'checkAppsCantIncreasePermissionSizeAfterCreating'
+    ),
+    (
+        'android.security.cts.PermissionMemoryFootprintTest#'
+        'checkAppsCantIncreasePermissionSizeAfterCreating'
+    ),
+]
+
+if __name__ == '__main__':
+  atest_integration_test.main()
diff --git a/atest/integration_tests/atest_integration_test.py b/atest/integration_tests/atest_integration_test.py
index 971b77ec..c8416d6f 100644
--- a/atest/integration_tests/atest_integration_test.py
+++ b/atest/integration_tests/atest_integration_test.py
@@ -46,7 +46,8 @@ setup_parallel_in_build_env = (
 #       breaking the integration test becomes a problem in the future, we can
 #       reconsider importing these constants.
 # Stdout print prefix for results directory. Defined in atest/atest_main.py
-_RESULTS_DIR_PRINT_PREFIX = 'Atest results and logs directory: '
+RESULTS_DIR_PRINT_PREFIX = 'Atest results and logs directory: '
+DRY_RUN_COMMAND_LOG_PREFIX = 'Internal run command from dry-run: '
 
 
 class LogEntry:
@@ -156,8 +157,8 @@ class AtestRunResult:
     """
     results_dir = None
     for line in self.get_stdout().splitlines(keepends=False):
-      if line.startswith(_RESULTS_DIR_PRINT_PREFIX):
-        results_dir = pathlib.Path(line[len(_RESULTS_DIR_PRINT_PREFIX) :])
+      if line.startswith(RESULTS_DIR_PRINT_PREFIX):
+        results_dir = pathlib.Path(line[len(RESULTS_DIR_PRINT_PREFIX) :])
     if not results_dir:
       raise RuntimeError('Failed to parse the result directory from stdout.')
 
@@ -343,6 +344,7 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
       include_device_serial: bool,
       print_output: bool = True,
       use_prebuilt_atest_binary=None,
+      pipe_to_stdin: str = None,
   ) -> AtestRunResult:
     """Run either `atest-dev` or `atest` command through subprocess.
 
@@ -358,6 +360,8 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
           is running.
         use_prebuilt_atest_binary: Whether to run the command using the prebuilt
           atest binary instead of the atest-dev binary.
+        pipe_to_stdin: A string value to pipe continuously to the stdin of the
+          command subprocess.
 
     Returns:
         An AtestRunResult object containing the run information.
@@ -386,6 +390,7 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
         env=step_in.get_env(),
         cwd=step_in.get_repo_root(),
         print_output=print_output,
+        pipe_to_stdin=pipe_to_stdin,
     )
     elapsed_time = time.time() - start_time
     result = AtestRunResult(
@@ -418,39 +423,53 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
       env: dict[str, str],
       cwd: str,
       print_output: bool = True,
+      pipe_to_stdin: str = None,
   ) -> subprocess.CompletedProcess[str]:
     """Execute shell command with real time output printing and capture."""
 
-    def read_output(read_src, print_dst, capture_dst):
+    def read_output(process, read_src, print_dst, capture_dst):
       while (output := read_src.readline()) or process.poll() is None:
         if output:
           if print_output:
             print(output, end='', file=print_dst)
           capture_dst.append(output)
 
-    with subprocess.Popen(
-        cmd,
-        stdout=subprocess.PIPE,
-        stderr=subprocess.PIPE,
-        text=True,
-        env=env,
-        cwd=cwd,
-    ) as process:
-      stdout = []
-      stderr = []
-      with concurrent.futures.ThreadPoolExecutor() as executor:
-        stdout_future = executor.submit(
-            read_output, process.stdout, sys.stdout, stdout
+    # Disable log uploading when running locally.
+    env['ENABLE_ATEST_LOG_UPLOADING'] = 'false'
+
+    def run_popen(stdin=None):
+      with subprocess.Popen(
+          cmd,
+          stdout=subprocess.PIPE,
+          stderr=subprocess.PIPE,
+          stdin=stdin,
+          text=True,
+          env=env,
+          cwd=cwd,
+      ) as process:
+        stdout = []
+        stderr = []
+        with concurrent.futures.ThreadPoolExecutor() as executor:
+          stdout_future = executor.submit(
+              read_output, process, process.stdout, sys.stdout, stdout
+          )
+          stderr_future = executor.submit(
+              read_output, process, process.stderr, sys.stderr, stderr
+          )
+        stdout_future.result()
+        stderr_future.result()
+
+        return subprocess.CompletedProcess(
+            cmd, process.poll(), ''.join(stdout), ''.join(stderr)
         )
-        stderr_future = executor.submit(
-            read_output, process.stderr, sys.stderr, stderr
-        )
-      stdout_future.result()
-      stderr_future.result()
 
-      return subprocess.CompletedProcess(
-          cmd, process.poll(), ''.join(stdout), ''.join(stderr)
-      )
+    if pipe_to_stdin:
+      with subprocess.Popen(
+          ['yes', pipe_to_stdin], stdout=subprocess.PIPE
+      ) as yes_process:
+        return run_popen(yes_process.stdout)
+
+    return run_popen()
 
   @staticmethod
   def _get_jdk_path_list() -> str:
@@ -470,26 +489,61 @@ class AtestTestCase(split_build_test_script.SplitBuildTestTestCase):
     return [absolute_path.relative_to(repo_root).as_posix()]
 
 
-def main():
-  """Main method to run the integration tests."""
+def sanitize_runner_command(cmd: str) -> str:
+  """Sanitize an atest runner command by removing non-essential args."""
+  remove_args_starting_with = [
+      '--skip-all-system-status-check',
+      '--atest-log-file-path',
+      'LD_LIBRARY_PATH=',
+      '--proto-output-file=',
+      '--log-root-path',
+  ]
+  remove_args_with_values = ['-s', '--serial']
+  build_command = 'build/soong/soong_ui.bash'
+  original_args = cmd.split()
+  result_args = []
+  for arg in original_args:
+    if arg == build_command:
+      result_args.append(f'./{build_command}')
+      continue
+    if not any(
+        (arg.startswith(prefix) for prefix in remove_args_starting_with)
+    ):
+      result_args.append(arg)
+  for arg in remove_args_with_values:
+    while arg in result_args:
+      idx = result_args.index(arg)
+      # Delete value index first.
+      del result_args[idx + 1]
+      del result_args[idx]
+
+  return ' '.join(result_args)
 
-  def argparser_update_func(parser):
-    parser.add_argument(
-        '--use-prebuilt-atest-binary',
-        action='store_true',
-        default=False,
-        help=(
-            'Set the default atest binary to the prebuilt `atest` instead'
-            ' of `atest-dev`.'
-        ),
-    )
-
-  def config_update_function(config, args):
-    config.use_prebuilt_atest_binary = args.use_prebuilt_atest_binary
 
+def main():
+  """Main method to run the integration tests."""
+  additional_args = [
+      split_build_test_script.AddArgument(
+          'use_prebuilt_atest_binary',
+          '--use-prebuilt-atest-binary',
+          action='store_true',
+          default=False,
+          help=(
+              'Set the default atest binary to the prebuilt `atest` instead'
+              ' of `atest-dev`.'
+          ),
+      ),
+      split_build_test_script.AddArgument(
+          'dry_run_diff_test_cmd_input_file',
+          '--dry-run-diff-test-cmd-input-file',
+          help=(
+              'The path of file containing the list of atest commands to test'
+              ' in the dry run diff tests relative to the repo root.'
+          ),
+      ),
+  ]
   split_build_test_script.main(
       argv=sys.argv,
       make_before_build=['atest'],
-      argparser_update_func=argparser_update_func,
-      config_update_function=config_update_function,
+      additional_args=additional_args,
   )
diff --git a/atest/integration_tests/split_build_test_script.py b/atest/integration_tests/split_build_test_script.py
index c308c881..4d512059 100644
--- a/atest/integration_tests/split_build_test_script.py
+++ b/atest/integration_tests/split_build_test_script.py
@@ -25,6 +25,7 @@ import argparse
 import atexit
 import concurrent.futures
 import copy
+import dataclasses
 import datetime
 import functools
 import itertools
@@ -675,9 +676,32 @@ def _configure_logging(verbose: bool, log_file_dir_path: pathlib.Path):
   logging.getLogger('').addHandler(console)
 
 
+@dataclasses.dataclass
+class AddArgument:
+  """A class to add an argument to the argparse parser and copy to test config."""
+
+  dest: str
+  args: tuple[Any, ...]
+  kwargs: dict[str, Any]
+
+  def __init__(self, dest: str, *args: Any, **kwargs: Any) -> None:
+    """Initializes the AddArgument class.
+
+    Params:
+        dest: Specify the attribute name used in the result namespace. This is
+          required here for adding the parsed value to test config object.
+        *args: Any arguments used to call argparse.add_argument.
+        **kwargs: Any keyword arguments used to call argparse.add_argument.
+    """
+    self.dest = dest
+    self.args = args
+    self.kwargs = kwargs
+    self.kwargs['dest'] = dest
+
+
 def _parse_known_args(
     argv: list[str],
-    argparser_update_func: Callable[argparse.ArgumentParser, None] = None,
+    additional_args: list[AddArgument],
 ) -> tuple[argparse.Namespace, list[str]]:
   """Parse command line args and check required args being provided."""
 
@@ -750,8 +774,8 @@ Usage examples:
       ),
   )
 
-  if argparser_update_func:
-    argparser_update_func(parser)
+  for additional_arg in additional_args:
+    parser.add_argument(*additional_arg.args, **additional_arg.kwargs)
 
   return parser.parse_known_args(argv)
 
@@ -864,21 +888,15 @@ def _run_test(
 def main(
     argv: list[str] = None,
     make_before_build: list[str] = None,
-    argparser_update_func: Callable[argparse.ArgumentParser, None] = None,
-    config_update_function: Callable[
-        [IntegrationTestConfiguration, argparse.Namespace], None
-    ] = None,
+    additional_args: list[AddArgument] = None,
 ) -> None:
   """Main method to start the integration tests.
 
   Args:
       argv: A list of arguments to parse.
       make_before_build: A list of targets to make before running build steps.
-      argparser_update_func: A function that takes an ArgumentParser object and
-        updates it.
-      config_update_function: A function that takes a
-        IntegrationTestConfiguration config and the parsed args to updates the
-        config.
+      additional_args: A list of additional arguments to be injected to the
+        argparser and test config.
 
   Raises:
       EnvironmentError: When some environment variables are missing.
@@ -887,8 +905,10 @@ def main(
     argv = sys.argv
   if make_before_build is None:
     make_before_build = []
+  if additional_args is None:
+    additional_args = []
 
-  args, unittest_argv = _parse_known_args(argv, argparser_update_func)
+  args, unittest_argv = _parse_known_args(argv, additional_args)
 
   snapshot_storage_dir_name = 'snapshot_storage'
   snapshot_storage_tar_name = 'snapshot.tar'
@@ -926,9 +946,8 @@ def main(
   config.snapshot_storage_tar_path = snapshot_storage_tar_path
   config.workspace_path = integration_test_out_path.joinpath('workspace')
   config.is_tar_snapshot = args.tar_snapshot
-
-  if config_update_function:
-    config_update_function(config, args)
+  for additional_arg in additional_args:
+    setattr(config, additional_arg.dest, getattr(args, additional_arg.dest))
 
   if config.is_build_env:
     if ANDROID_BUILD_TOP_KEY not in os.environ:
diff --git a/atest/java/res/config/template/performance-tests-base.xml b/atest/java/res/config/template/performance-tests-base.xml
new file mode 100644
index 00000000..e3af1c6b
--- /dev/null
+++ b/atest/java/res/config/template/performance-tests-base.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<!-- Common configuration for atest's local runs for device tests. -->
+<configuration description="Top level configuration for performance tests (device tests)">
+  <include name="template/atest_device_test_base" />
+
+  <option name="enable-module-dynamic-download" value="true" />
+</configuration>
\ No newline at end of file
diff --git a/atest/logstorage/atest_gcp_utils.py b/atest/logstorage/atest_gcp_utils.py
index 9e151016..1285046a 100644
--- a/atest/logstorage/atest_gcp_utils.py
+++ b/atest/logstorage/atest_gcp_utils.py
@@ -202,7 +202,7 @@ class GCPHelper:
 def do_upload_flow(
     extra_args: dict[str, str],
     build_client_creator: Callable,
-    atest_run_id: str = None,
+    invocation_properties: dict[str, str] = None,
 ) -> tuple:
   """Run upload flow.
 
@@ -212,11 +212,13 @@ def do_upload_flow(
       extra_args: Dict of extra args to add to test run.
       build_client_creator: A function that takes a credential and returns a
         BuildClient object.
-      atest_run_id: The atest run ID to write into the invocation.
+      invocation_properties: Additional invocation properties to write into the
+        invocation.
 
   Return:
       A tuple of credential object and invocation information dict.
   """
+  invocation_properties = invocation_properties or {}
   fetch_cred_start = time.time()
   creds = fetch_credential()
   metrics.LocalDetectEvent(
@@ -227,7 +229,7 @@ def do_upload_flow(
     prepare_upload_start = time.time()
     build_client = build_client_creator(creds)
     inv, workunit, local_build_id, build_target = _prepare_data(
-        build_client, atest_run_id or metrics.get_run_id()
+        build_client, invocation_properties
     )
     metrics.LocalDetectEvent(
         detect_type=DetectType.UPLOAD_PREPARE_MS,
@@ -260,12 +262,13 @@ def fetch_credential():
   ).get_credential_with_auth_flow(creds_path)
 
 
-def _prepare_data(client, atest_run_id: str):
+def _prepare_data(client, invocation_properties: dict[str, str]):
   """Prepare data for build api using.
 
   Args:
       build_client: The logstorage_utils.BuildClient object.
-      atest_run_id: The atest run ID to write into the invocation.
+      invocation_properties: Additional invocation properties to write into the
+        invocation.
 
   Return:
       invocation and workunit object.
@@ -278,7 +281,7 @@ def _prepare_data(client, atest_run_id: str):
     target = _get_target(branch, client)
     build_record = client.insert_local_build(external_id, target, branch)
     client.insert_build_attempts(build_record)
-    invocation = client.insert_invocation(build_record, atest_run_id)
+    invocation = client.insert_invocation(build_record, invocation_properties)
     workunit = client.insert_work_unit(invocation)
     return invocation, workunit, build_record['buildId'], target
   finally:
diff --git a/atest/logstorage/log_uploader.py b/atest/logstorage/log_uploader.py
index 599f081d..c88f6fa2 100644
--- a/atest/logstorage/log_uploader.py
+++ b/atest/logstorage/log_uploader.py
@@ -51,7 +51,7 @@ class _SimpleUploadingClient:
     """Initialize internal build clients and get invocation ID from AnTS."""
     configuration = {}
     creds, self._invocation_data = logstorage_utils.do_upload_flow(
-        configuration, self._atest_run_id
+        configuration, {'atest_run_id': self._atest_run_id}
     )
 
     self._client = logstorage_utils.BuildClient(creds)
diff --git a/atest/logstorage/logstorage_utils.py b/atest/logstorage/logstorage_utils.py
index c64611c0..57890fb8 100644
--- a/atest/logstorage/logstorage_utils.py
+++ b/atest/logstorage/logstorage_utils.py
@@ -88,7 +88,7 @@ def is_upload_enabled(args: dict[str, str]) -> bool:
 
 
 def do_upload_flow(
-    extra_args: dict[str, str], atest_run_id: str = None
+    extra_args: dict[str, str], invocation_properties: dict[str, str] = None
 ) -> tuple:
   """Run upload flow.
 
@@ -96,13 +96,15 @@ def do_upload_flow(
 
   Args:
       extra_args: Dict of extra args to add to test run.
-      atest_run_id: The atest run ID to write into the invocation.
+      invocation_properties: Additional invocation properties to write into the
+        invocation.
 
   Return:
       A tuple of credential object and invocation information dict.
   """
+  invocation_properties = invocation_properties or {}
   return atest_gcp_utils.do_upload_flow(
-      extra_args, lambda cred: BuildClient(cred), atest_run_id
+      extra_args, lambda cred: BuildClient(cred), invocation_properties
   )
 
 
@@ -191,12 +193,15 @@ class BuildClient:
         .execute()
     )
 
-  def insert_invocation(self, build_record, atest_run_id: str):
+  def insert_invocation(
+      self, build_record: dict[str, str], invocation_properties: dict[str, str]
+  ):
     """Insert a build invocation record.
 
     Args:
         build_record: build record.
-        atest_run_id: The atest run ID to write into the invocation.
+        invocation_properties: Additional invocation properties to write into
+          the invocation.
 
     Returns:
         A build invocation object.
@@ -222,7 +227,9 @@ class BuildClient:
                 'name': 'test_uri',
                 'value': f'{constants.STORAGE2_TEST_URI}{sponge_invocation_id}',
             },
-            {'name': 'atest_run_id', 'value': atest_run_id},
+        ] + [
+            {'name': key, 'value': value}
+            for key, value in invocation_properties.items()
         ],
     }
     return self.client.invocation().insert(body=invocation).execute()
diff --git a/atest/result_reporter.py b/atest/result_reporter.py
index 56ef7ee4..4e175d3b 100644
--- a/atest/result_reporter.py
+++ b/atest/result_reporter.py
@@ -67,6 +67,7 @@ from __future__ import print_function
 from collections import OrderedDict
 import logging
 import os
+import pathlib
 import re
 import zipfile
 
@@ -290,7 +291,14 @@ class ResultReporter:
             'VtsTradefedTestRunner': {'Module1': RunStat(passed:4, failed:0)}}
   """
 
-  def __init__(self, silent=False, collect_only=False, wait_for_debugger=False):
+  def __init__(
+      self,
+      silent=False,
+      collect_only=False,
+      wait_for_debugger=False,
+      args=None,
+      test_infos=None,
+  ):
     """Init ResultReporter.
 
     Args:
@@ -308,6 +316,8 @@ class ResultReporter:
     self.test_result_link = None
     self.device_count = 0
     self.wait_for_debugger = wait_for_debugger
+    self._args = args
+    self._test_infos = test_infos or []
 
   def get_test_results_by_runner(self, runner_name):
     return [t for t in self.all_test_results if t.runner_name == runner_name]
@@ -390,7 +400,12 @@ class ResultReporter:
     for runner_name, groups in self.runners.items():
       for group_name, stats in groups.items():
         name = group_name if group_name else runner_name
-        summary = self.process_summary(name, stats)
+        test_run_name = (
+            self.all_test_results[-1].test_run_name
+            if self.all_test_results[-1].test_run_name != name
+            else None
+        )
+        summary = self.process_summary(name, stats, test_run_name=test_run_name)
         run_summary.append(summary)
     summary_list = ITER_SUMMARY.get(iteration_num, [])
     summary_list.extend(run_summary)
@@ -479,9 +494,8 @@ class ResultReporter:
         print(au.mark_red(message))
         print('-' * len(message))
         self.print_failed_tests()
-    if self.log_path:
-      # Print aggregate result if any.
-      self._print_aggregate_test_metrics()
+
+    self._print_perf_test_metrics()
     # TODO(b/174535786) Error handling while uploading test results has
     # unexpected exceptions.
     # TODO (b/174627499) Saving this information in atest history.
@@ -489,32 +503,67 @@ class ResultReporter:
       print('Test Result uploaded to %s' % au.mark_green(self.test_result_link))
     return tests_ret
 
-  def _print_aggregate_test_metrics(self):
-    """Print aggregate test metrics text content if metric files exist."""
-    metric_files = au.find_files(
+  def _print_perf_test_metrics(self) -> bool:
+    """Print perf test metrics text content to console.
+
+    Returns:
+        True if metric printing is attempted; False if not perf tests.
+    """
+    if not any(
+        'performance-tests' in info.compatibility_suites
+        for info in self._test_infos
+    ):
+      return False
+
+    if not self.log_path:
+      return True
+
+    aggregated_metric_files = au.find_files(
         self.log_path, file_name='*_aggregate_test_metrics_*.txt'
     )
 
-    if metric_files:
-      print('\n{}'.format(au.mark_cyan('Aggregate test metrics')))
+    if self._args.perf_itr_metrics:
+      individual_metric_files = au.find_files(
+          self.log_path, file_name='test_results_*.txt'
+      )
+      print('\n{}'.format(au.mark_cyan('Individual test metrics')))
       print(au.delimiter('-', 7))
-      for metric_file in metric_files:
-        self._print_test_metric(metric_file)
+      for metric_file in individual_metric_files:
+        metric_file_path = pathlib.Path(metric_file)
+        # Skip aggregate metrics as we are printing individual metrics here.
+        if '_aggregate_test_metrics_' in metric_file_path.name:
+          continue
+        print('{}:'.format(au.mark_cyan(metric_file_path.name)))
+        print(
+            ''.join(
+                f'{" "*4}{line}'
+                for line in metric_file_path.read_text(
+                    encoding='utf-8'
+                ).splitlines(keepends=True)
+            )
+        )
+
+    print('\n{}'.format(au.mark_cyan('Aggregate test metrics')))
+    print(au.delimiter('-', 7))
+    for metric_file in aggregated_metric_files:
+      self._print_test_metric(pathlib.Path(metric_file))
+
+    return True
 
-  def _print_test_metric(self, metric_file):
+  def _print_test_metric(self, metric_file: pathlib.Path) -> None:
     """Print the content of the input metric file."""
     test_metrics_re = re.compile(
         r'test_results.*\s(.*)_aggregate_test_metrics_.*\.txt'
     )
-    if not os.path.isfile(metric_file):
+    if not metric_file.is_file():
       return
-    matches = re.findall(test_metrics_re, metric_file)
+    matches = re.findall(test_metrics_re, metric_file.as_posix())
     test_name = matches[0] if matches else ''
     if test_name:
       print('{}:'.format(au.mark_cyan(test_name)))
-      with open(metric_file, 'r', encoding='utf-8') as f:
+      with metric_file.open('r', encoding='utf-8') as f:
         matched = False
-        filter_res = atest_configs.GLOBAL_ARGS.aggregate_metric_filter
+        filter_res = self._args.aggregate_metric_filter
         logging.debug('Aggregate metric filters: %s', filter_res)
         test_methods = []
         # Collect all test methods
@@ -572,7 +621,7 @@ class ResultReporter:
       for test_name in self.failed_tests:
         print(test_name)
 
-  def process_summary(self, name, stats):
+  def process_summary(self, name, stats, test_run_name=None):
     """Process the summary line.
 
     Strategy:
@@ -588,6 +637,7 @@ class ResultReporter:
     Args:
         name: A string of test name.
         stats: A RunStat instance for a test group.
+        test_run_name: A string of test run name (optional)
 
     Returns:
         A summary of the test result.
@@ -643,8 +693,9 @@ class ResultReporter:
     )
     ITER_COUNTS[name] = temp
 
+    summary_name = f'{name}:{test_run_name}' if test_run_name else name
     summary = '%s: %s: %s, %s: %s, %s: %s, %s: %s %s %s' % (
-        name,
+        summary_name,
         passed_label,
         stats.passed,
         failed_label,
diff --git a/atest/result_reporter_unittest.py b/atest/result_reporter_unittest.py
index 7281b827..a45e2f07 100755
--- a/atest/result_reporter_unittest.py
+++ b/atest/result_reporter_unittest.py
@@ -26,6 +26,7 @@ from unittest.mock import patch
 from atest import arg_parser
 from atest import atest_configs
 from atest import result_reporter
+from atest.test_finders import test_info
 from atest.test_runners import test_runner_base
 
 
@@ -624,6 +625,36 @@ class ResultReporterUnittests(unittest.TestCase):
     self.assertEqual(max_len, correct_max_len)
     self.assertEqual(classify_perf_info, correct_classify_perf_info)
 
+  def test_print_perf_test_metrics_perf_tests_print_attempted(self):
+    test_infos = [
+        test_info.TestInfo(
+            'some_module',
+            'TestRunner',
+            set(),
+            compatibility_suites=['performance-tests'],
+        )
+    ]
+    sut = result_reporter.ResultReporter(test_infos=test_infos)
+
+    is_print_attempted = sut._print_perf_test_metrics()
+
+    self.assertTrue(is_print_attempted)
+
+  def test_print_perf_test_metrics_not_perf_tests_print__not_attempted(self):
+    test_infos = [
+        test_info.TestInfo(
+            'some_module',
+            'TestRunner',
+            set(),
+            compatibility_suites=['not-perf-test'],
+        )
+    ]
+    sut = result_reporter.ResultReporter(test_infos=test_infos)
+
+    is_print_attempted = sut._print_perf_test_metrics()
+
+    self.assertFalse(is_print_attempted)
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/atest/rollout_control.py b/atest/rollout_control.py
new file mode 100644
index 00000000..2a89f5bc
--- /dev/null
+++ b/atest/rollout_control.py
@@ -0,0 +1,215 @@
+#!/usr/bin/env python3
+# Copyright 2024, The Android Open Source Project
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
+"""Rollout control for Atest features."""
+
+import functools
+import getpass
+import hashlib
+import importlib.resources
+import logging
+import os
+from atest import atest_enum
+from atest import atest_utils
+from atest.metrics import metrics
+
+
+@functools.cache
+def _get_project_owners() -> list[str]:
+  """Returns the owners of the feature."""
+  owners = []
+  try:
+    with importlib.resources.as_file(
+        importlib.resources.files('atest').joinpath('OWNERS')
+    ) as version_file_path:
+      owners.extend(version_file_path.read_text(encoding='utf-8').splitlines())
+  except (ModuleNotFoundError, FileNotFoundError) as e:
+    logging.error(e)
+  try:
+    with importlib.resources.as_file(
+        importlib.resources.files('atest').joinpath('OWNERS_ADTE_TEAM')
+    ) as version_file_path:
+      owners.extend(version_file_path.read_text(encoding='utf-8').splitlines())
+  except (ModuleNotFoundError, FileNotFoundError) as e:
+    logging.error(e)
+  return [line.split('@')[0] for line in owners if '@google.com' in line]
+
+
+class RolloutControlledFeature:
+  """Base class for Atest features under rollout control."""
+
+  def __init__(
+      self,
+      name: str,
+      rollout_percentage: float,
+      env_control_flag: str,
+      feature_id: int = None,
+      owners: list[str] | None = None,
+      print_message: str | None = None,
+  ):
+    """Initializes the object.
+
+    Args:
+        name: The name of the feature.
+        rollout_percentage: The percentage of users to enable the feature for.
+          The value should be in [0, 100].
+        env_control_flag: The environment variable name to override the feature
+          enablement. When set, 'true' or '1' means enable, other values means
+          disable.
+        feature_id: The ID of the feature that is controlled by rollout control
+          for metric collection purpose. Must be a positive integer.
+        owners: The owners of the feature. If not provided, the owners of the
+          feature will be read from OWNERS file.
+        print_message: The message to print to the console when the feature is
+          enabled for the user.
+    """
+    if rollout_percentage < 0 or rollout_percentage > 100:
+      raise ValueError(
+          'Rollout percentage must be in [0, 100]. Got %s instead.'
+          % rollout_percentage
+      )
+    if feature_id is not None and feature_id <= 0:
+      raise ValueError(
+          'Feature ID must be a positive integer. Got %s instead.' % feature_id
+      )
+    if owners is None:
+      owners = _get_project_owners()
+    self._name = name
+    self._rollout_percentage = rollout_percentage
+    self._env_control_flag = env_control_flag
+    self._feature_id = feature_id
+    self._owners = owners
+    self._print_message = print_message
+
+  def _check_env_control_flag(self) -> bool | None:
+    """Checks the environment variable to override the feature enablement.
+
+    Returns:
+        True if the feature is enabled, False if disabled, None if not set.
+    """
+    if self._env_control_flag not in os.environ:
+      return None
+    return os.environ[self._env_control_flag] in ('TRUE', 'True', 'true', '1')
+
+  def _is_enabled_for_user(self, username: str | None) -> bool:
+    """Checks whether the feature is enabled for the user.
+
+    Args:
+        username: The username to check the feature enablement for. If not
+          provided, the current user's username will be used.
+
+    Returns:
+        True if the feature is enabled for the user, False otherwise.
+    """
+    if self._rollout_percentage == 100:
+      return True
+
+    if username is None:
+      username = getpass.getuser()
+
+    if not username:
+      logging.debug(
+          'Unable to determine the username. Disabling the feature %s.',
+          self._name,
+      )
+      return False
+
+    if username in self._owners:
+      return True
+
+    hash_object = hashlib.sha256()
+    hash_object.update((username + ' ' + self._name).encode('utf-8'))
+    return int(hash_object.hexdigest(), 16) % 100 < self._rollout_percentage
+
+  @functools.cache
+  def is_enabled(self, username: str | None = None) -> bool:
+    """Checks whether the current feature is enabled for the user.
+
+    Args:
+        username: The username to check the feature enablement for. If not
+          provided, the current user's username will be used.
+
+    Returns:
+        True if the feature is enabled for the user, False otherwise.
+    """
+    override_flag_value = self._check_env_control_flag()
+    if override_flag_value is not None:
+      logging.debug(
+          'Feature %s is %s by env variable %s.',
+          self._name,
+          'enabled' if override_flag_value else 'disabled',
+          self._env_control_flag,
+      )
+      if self._feature_id:
+        metrics.LocalDetectEvent(
+            detect_type=atest_enum.DetectType.ROLLOUT_CONTROLLED_FEATURE_ID_OVERRIDE,
+            result=self._feature_id
+            if override_flag_value
+            else -self._feature_id,
+        )
+      return override_flag_value
+
+    is_enabled = self._is_enabled_for_user(username)
+
+    logging.debug(
+        'Feature %s is %s for user %s.',
+        self._name,
+        'enabled' if is_enabled else 'disabled',
+        username,
+    )
+
+    if self._feature_id:
+      metrics.LocalDetectEvent(
+          detect_type=atest_enum.DetectType.ROLLOUT_CONTROLLED_FEATURE_ID,
+          result=self._feature_id if is_enabled else -self._feature_id,
+      )
+
+    if is_enabled and self._print_message:
+      print(atest_utils.mark_magenta(self._print_message))
+
+    return is_enabled
+
+
+deprecate_bazel_mode = RolloutControlledFeature(
+    name='Deprecate Bazel Mode',
+    rollout_percentage=60,
+    env_control_flag='DEPRECATE_BAZEL_MODE',
+    feature_id=1,
+)
+
+rolling_tf_subprocess_output = RolloutControlledFeature(
+    name='Rolling TradeFed subprocess output',
+    rollout_percentage=100,
+    env_control_flag='ROLLING_TF_SUBPROCESS_OUTPUT',
+    feature_id=2,
+    print_message=(
+        'You are one of the first users receiving the "Rolling subprocess'
+        ' output" feature. If you are happy with it, please +1 on'
+        ' http://b/380460196.'
+    ),
+)
+
+tf_preparer_incremental_setup = RolloutControlledFeature(
+    name='TradeFed preparer incremental setup',
+    rollout_percentage=0,
+    env_control_flag='TF_PREPARER_INCREMENTAL_SETUP',
+    feature_id=3,
+    print_message=(
+        'You are one of the first users selected to receive the "Incremental'
+        ' setup for TradeFed preparers" feature. If you are happy with it,'
+        ' please +1 on http://b/381900378. If you experienced any issues,'
+        ' please comment on the same bug.'
+    ),
+)
diff --git a/atest/rollout_control_unittest.py b/atest/rollout_control_unittest.py
new file mode 100644
index 00000000..ca000d07
--- /dev/null
+++ b/atest/rollout_control_unittest.py
@@ -0,0 +1,104 @@
+#!/usr/bin/env python3
+# Copyright 2024, The Android Open Source Project
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
+from atest import rollout_control
+
+
+class RolloutControlledFeatureUnittests(unittest.TestCase):
+
+  def test_is_enabled_username_hash_is_greater_than_rollout_percentage_returns_false(
+      self,
+  ):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=66,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    self.assertFalse(sut.is_enabled('username'))
+
+  def test_is_enabled_username_hash_is_equal_to_rollout_percentage_returns_false(
+      self,
+  ):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=67,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    self.assertFalse(sut.is_enabled('username'))
+
+  def test_is_enabled_username_hash_is_less_or_equal_than_rollout_percentage_returns_true(
+      self,
+  ):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=68,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    self.assertTrue(sut.is_enabled('username'))
+
+  def test_is_enabled_username_undetermined_returns_false(self):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=99,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    self.assertFalse(sut.is_enabled(''))
+
+  def test_is_enabled_flag_set_to_true_returns_true(self):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=0,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    with mock.patch.dict('os.environ', {'TEST_FEATURE': 'true'}):
+      self.assertTrue(sut.is_enabled())
+
+  def test_is_enabled_flag_set_to_1_returns_true(self):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=0,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    with mock.patch.dict('os.environ', {'TEST_FEATURE': '1'}):
+      self.assertTrue(sut.is_enabled())
+
+  def test_is_enabled_flag_set_to_false_returns_false(self):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=100,
+        env_control_flag='TEST_FEATURE',
+    )
+
+    with mock.patch.dict('os.environ', {'TEST_FEATURE': 'false'}):
+      self.assertFalse(sut.is_enabled())
+
+  def test_is_enabled_is_owner_returns_true(self):
+    sut = rollout_control.RolloutControlledFeature(
+        name='test_feature',
+        rollout_percentage=0,
+        env_control_flag='TEST_FEATURE',
+        owners=['owner_name'],
+    )
+
+    self.assertFalse(sut.is_enabled('name'))
+    self.assertTrue(sut.is_enabled('owner_name'))
diff --git a/atest/test_finders/module_finder.py b/atest/test_finders/module_finder.py
index 77756687..bbb0d067 100644
--- a/atest/test_finders/module_finder.py
+++ b/atest/test_finders/module_finder.py
@@ -107,7 +107,7 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     Args:
         test: TestInfo to update with vts10 specific details.
 
-    Return:
+    Returns:
         TestInfo that is ready for the vts10 test runner.
     """
     test.test_runner = self._VTS_TEST_RUNNER
@@ -197,7 +197,7 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     Args:
         test: TestInfo that has been filled out by a find method.
 
-    Return:
+    Returns:
         TestInfo that has been modified as needed and return None if
         this module can't be found in the module_info.
     """
@@ -237,7 +237,9 @@ class ModuleFinder(test_finder_base.TestFinderBase):
       logging.debug(
           'Add %s to build targets...', ', '.join(artifact_map.keys())
       )
-      test.artifacts = [apk for p in artifact_map.values() for apk in p]
+      test.artifacts = []
+      for p in artifact_map.values():
+        test.artifacts += p
       logging.debug('Will install target APK: %s\n', test.artifacts)
       metrics.LocalDetectEvent(
           detect_type=DetectType.FOUND_TARGET_ARTIFACTS,
@@ -292,11 +294,6 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     for module_path in self.module_info.get_paths(module_name):
       mod_dir = module_path.replace('/', '-')
       targets.add(constants.MODULES_IN + mod_dir)
-    # (b/156457698) Force add vts_kernel_ltp_tests as build target if our
-    # test belongs to REQUIRED_LTP_TEST_MODULES due to required_module
-    # option not working for sh_test in soong.
-    if module_name in constants.REQUIRED_LTP_TEST_MODULES:
-      targets.add('vts_kernel_ltp_tests')
     # (b/184567849) Force adding module_name as a build_target. This will
     # allow excluding MODULES-IN-* and prevent from missing build targets.
     if module_name and self.module_info.is_module(module_name):
@@ -345,14 +342,17 @@ class ModuleFinder(test_finder_base.TestFinderBase):
       # Double check if below section is needed.
       if (
           not self.module_info.is_auto_gen_test_config(module_name)
-          and len(test_configs) > 0
+          and test_configs
       ):
         return test_configs
     return [rel_config] if rel_config else []
 
   # pylint: disable=too-many-branches
   # pylint: disable=too-many-locals
-  def _get_test_info_filter(self, path, methods, **kwargs):
+  def _get_test_info_filter(
+      self, path, methods, rel_module_dir=None, class_name=None,
+      is_native_test=False
+  ):
     """Get test info filter.
 
     Args:
@@ -361,20 +361,21 @@ class ModuleFinder(test_finder_base.TestFinderBase):
         rel_module_dir: Optional. A string of the module dir no-absolute to
           root.
         class_name: Optional. A string of the class name.
-        is_native_test: Optional. A boolean variable of whether to search for a
-          native test or not.
+        is_native_test: Optional. A boolean variable of whether to search for
+          a native test or not.
 
     Returns:
         A set of test info filter.
     """
     _, file_name = test_finder_utils.get_dir_path_and_filename(path)
     ti_filter = frozenset()
-    if os.path.isfile(path) and kwargs.get('is_native_test', None):
+    if os.path.isfile(path) and is_native_test:
       class_info = test_finder_utils.get_cc_class_info(path)
       ti_filter = frozenset([
           test_info.TestFilter(
               test_filter_utils.get_cc_filter(
-                  class_info, kwargs.get('class_name', '*'), methods
+                  class_info,
+                  class_name if class_name is not None else '*', methods
               ),
               frozenset(),
           )
@@ -404,14 +405,13 @@ class ModuleFinder(test_finder_base.TestFinderBase):
         )
       ti_filter = frozenset(cc_filters)
     # If input path is a folder and have class_name information.
-    elif not file_name and kwargs.get('class_name', None):
+    elif not file_name and class_name:
       ti_filter = frozenset(
-          [test_info.TestFilter(kwargs.get('class_name', None), methods)]
+          [test_info.TestFilter(class_name, methods)]
       )
     # Path to non-module dir, treat as package.
-    elif not file_name and kwargs.get(
-        'rel_module_dir', None
-    ) != os.path.relpath(path, self.root_dir):
+    elif not file_name and rel_module_dir != os.path.relpath(
+        path, self.root_dir):
       dir_items = [os.path.join(path, f) for f in os.listdir(path)]
       for dir_item in dir_items:
         if constants.JAVA_EXT_RE.match(dir_item):
@@ -784,7 +784,7 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     Args:
         package: A string of the package name.
         module_name: Optional. A string of the module name.
-        ref_config: Optional. A string of rel path of config.
+        rel_config: Optional. A string of rel path of config.
 
     Returns:
         A list of populated TestInfo namedtuple if found, else None.
@@ -868,7 +868,6 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     """
     logging.debug('Finding test by path: %s', rel_path)
     path, methods = test_filter_utils.split_methods(rel_path)
-    # TODO: See if this can be generalized and shared with methods above
     # create absolute path from cwd and remove symbolic links
     path = os.path.realpath(path)
     if not os.path.exists(path):
@@ -1026,16 +1025,16 @@ class ModuleFinder(test_finder_base.TestFinderBase):
     Args:
         user_input: the target module name for fuzzy searching.
 
-    Return:
+    Returns:
         A list of guessed modules.
     """
     modules_with_ld = self.get_testable_modules_with_ld(
         user_input, ld_range=constants.LD_RANGE
     )
     guessed_modules = []
-    for _distance, _module in modules_with_ld:
-      if _distance <= abs(constants.LD_RANGE):
-        guessed_modules.append(_module)
+    for distance_, module_ in modules_with_ld:
+      if distance_ <= abs(constants.LD_RANGE):
+        guessed_modules.append(module_)
     return guessed_modules
 
   def find_test_by_config_name(self, config_name):
diff --git a/atest/test_runners/atest_tf_test_runner.py b/atest/test_runners/atest_tf_test_runner.py
index cd15f293..bbd3a238 100644
--- a/atest/test_runners/atest_tf_test_runner.py
+++ b/atest/test_runners/atest_tf_test_runner.py
@@ -31,6 +31,7 @@ import re
 import select
 import shutil
 import socket
+import threading
 import time
 from typing import Any, Dict, List, Set, Tuple
 
@@ -40,6 +41,7 @@ from atest import atest_utils
 from atest import constants
 from atest import module_info
 from atest import result_reporter
+from atest import rollout_control
 from atest.atest_enum import DetectType, ExitCode
 from atest.coverage import coverage
 from atest.logstorage import logstorage_utils
@@ -57,6 +59,9 @@ SOCKET_QUEUE_MAX = 1
 SOCKET_BUFFER = 4096
 SELECT_TIMEOUT = 0.5
 
+# Env key for rolling subprocess output window height.
+_ROLLING_OUTPUT_WINDOW_HEIGHT_ENV_KEY = 'ATEST_ROLLING_OUTPUT_WINDOW_HEIGHT'
+
 # Socket Events of form FIRST_EVENT {JSON_DATA}\nSECOND_EVENT {JSON_DATA}
 # EVENT_RE has groups for the name and the data. "." does not match \n.
 EVENT_RE = re.compile(
@@ -86,6 +91,9 @@ _TF_EXIT_CODE = [
     'WRONG_JAVA_VERSION',
 ]
 
+# The environment variable for TF preparer incremental setup.
+_INCREMENTAL_SETUP_KEY = 'TF_PREPARER_INCREMENTAL_SETUP'
+
 
 class Error(Exception):
   """Module-level error."""
@@ -229,10 +237,13 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
           )
       )
     if device_test_infos:
+      extra_args_for_device_test = extra_args.copy()
+      if rollout_control.tf_preparer_incremental_setup.is_enabled():
+        extra_args_for_device_test.update({_INCREMENTAL_SETUP_KEY: True})
       invocations.append(
           TestRunnerInvocation(
               test_runner=self,
-              extra_args=extra_args,
+              extra_args=extra_args_for_device_test,
               test_infos=device_test_infos,
           )
       )
@@ -306,8 +317,19 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     self._try_set_gts_authentication_key()
     result = 0
     upload_start = time.time()
+    invocation_properties = {'atest_run_id': metrics.get_run_id()}
+
+    # Set crystalball_ingest property if there are performance tests.
+    is_perf_tests = False
+    for info in test_infos:
+      if 'performance-tests' in info.compatibility_suites:
+        is_perf_tests = True
+        break
+    if is_perf_tests:
+      invocation_properties['crystalball_ingest'] = 'yes'
+
     creds, inv = (
-        logstorage_utils.do_upload_flow(extra_args)
+        logstorage_utils.do_upload_flow(extra_args, invocation_properties)
         if logstorage_utils.is_upload_enabled(extra_args)
         else (None, None)
     )
@@ -388,12 +410,37 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
     run_cmds = self.generate_run_commands(
         test_infos, extra_args, server.getsockname()[1]
     )
+    is_rolling_output = (
+        not extra_args.get(constants.VERBOSE, False)
+        and atest_utils.is_atty_terminal()
+        and rollout_control.rolling_tf_subprocess_output.is_enabled()
+    )
+
     logging.debug('Running test: %s', run_cmds[0])
     subproc = self.run(
         run_cmds[0],
         output_to_stdout=extra_args.get(constants.VERBOSE, False),
         env_vars=self.generate_env_vars(extra_args),
+        rolling_output_lines=is_rolling_output,
     )
+
+    if is_rolling_output:
+      height = os.environ.get(_ROLLING_OUTPUT_WINDOW_HEIGHT_ENV_KEY, None)
+      if height:
+        try:
+          height = int(height)
+        except ValueError:
+          atest_utils.print_and_log_warning(
+              'Invalid rolling output window height: %s', height
+          )
+      threading.Thread(
+          target=atest_utils.stream_io_output,
+          args=(
+              subproc.stdout,
+              height if height else atest_utils.DEFAULT_OUTPUT_ROLLING_LINES,
+          ),
+      ).start()
+
     self.handle_subprocess(
         subproc,
         partial(self._start_monitor, server, subproc, reporter, extra_args),
@@ -840,7 +887,11 @@ class AtestTradefedTestRunner(trb.TestRunnerBase):
         A list that contains the string of atest tradefed run command.
         Only one command is returned.
     """
-    if extra_args.get(constants.USE_TF_MIN_BASE_TEMPLATE):
+    if any(
+        'performance-tests' in info.compatibility_suites for info in test_infos
+    ):
+      self.run_cmd_dict['template'] = 'template/performance-tests-base'
+    elif extra_args.get(constants.USE_TF_MIN_BASE_TEMPLATE):
       self.run_cmd_dict['template'] = self._TF_LOCAL_MIN
     else:
       self.run_cmd_dict['template'] = (
@@ -1467,6 +1518,7 @@ def extra_args_to_tf_args(
           ),
       ],
       constants.COVERAGE: lambda _: coverage.tf_args(mod_info),
+      _INCREMENTAL_SETUP_KEY: constant_list('--incremental-setup=YES'),
   })
 
   for arg in extra_args:
diff --git a/atest/test_runners/atest_tf_test_runner_unittest.py b/atest/test_runners/atest_tf_test_runner_unittest.py
index f44b079e..1b181ab3 100755
--- a/atest/test_runners/atest_tf_test_runner_unittest.py
+++ b/atest/test_runners/atest_tf_test_runner_unittest.py
@@ -871,6 +871,35 @@ class AtestTradefedTestRunnerUnittests(unittest.TestCase):
         ],
     )
 
+  @mock.patch.object(
+      atf_tr.AtestTradefedTestRunner,
+      '_is_all_tests_parameter_auto_enabled',
+      return_value=False,
+  )
+  @mock.patch('os.environ.get', return_value=None)
+  @mock.patch('atest.atest_utils.get_result_server_args')
+  def test_generate_run_commands_incremental_setup(
+      self, mock_resultargs, _, _mock_is_all
+  ):
+    """Test generate_run_command method with incremental setup."""
+    mock_resultargs.return_value = []
+    extra_args = {atf_tr._INCREMENTAL_SETUP_KEY: True}
+
+    run_commands = self.tr.generate_run_commands([], extra_args)
+
+    unittest_utils.assert_strict_equal(
+        self,
+        run_commands,
+        [
+            RUN_CMD.format(
+                serial=' --incremental-setup=YES',
+                template=self.tr._TF_DEVICE_TEST_TEMPLATE,
+                tf_customize_template='',
+                device_early_release=' --no-early-device-release',
+            )
+        ],
+    )
+
   @mock.patch.object(
       atf_tr.AtestTradefedTestRunner,
       '_is_all_tests_parameter_auto_enabled',
diff --git a/atest/test_runners/test_runner_base.py b/atest/test_runners/test_runner_base.py
index 499cb1fa..927960a9 100644
--- a/atest/test_runners/test_runner_base.py
+++ b/atest/test_runners/test_runner_base.py
@@ -79,6 +79,7 @@ class TestRunnerBase:
     """Init stuff for base class."""
     self.results_dir = results_dir
     self.test_log_file = None
+    self._subprocess_stdout = None
     if not self.NAME:
       raise atest_error.NoTestRunnerName('Class var NAME is not defined.')
     if not self.EXECUTABLE:
@@ -116,7 +117,13 @@ class TestRunnerBase:
     """Checks whether this runner requires device update."""
     return False
 
-  def run(self, cmd, output_to_stdout=False, env_vars=None):
+  def run(
+      self,
+      cmd,
+      output_to_stdout=False,
+      env_vars=None,
+      rolling_output_lines=False,
+  ):
     """Shell out and execute command.
 
     Args:
@@ -127,20 +134,34 @@ class TestRunnerBase:
           reporter to print the test results.  Set to True to see the output of
           the cmd. This would be appropriate for verbose runs.
         env_vars: Environment variables passed to the subprocess.
+        rolling_output_lines: If True, the subprocess output will be streamed
+          with rolling lines when output_to_stdout is False.
     """
-    if not output_to_stdout:
-      self.test_log_file = tempfile.NamedTemporaryFile(
-          mode='w', dir=self.results_dir, delete=True
-      )
     logging.debug('Executing command: %s', cmd)
-    return subprocess.Popen(
-        cmd,
-        start_new_session=True,
-        shell=True,
-        stderr=subprocess.STDOUT,
-        stdout=self.test_log_file,
-        env=env_vars,
-    )
+    if rolling_output_lines:
+      proc = subprocess.Popen(
+          cmd,
+          start_new_session=True,
+          shell=True,
+          stderr=subprocess.STDOUT,
+          stdout=None if output_to_stdout else subprocess.PIPE,
+          env=env_vars,
+      )
+      self._subprocess_stdout = proc.stdout
+      return proc
+    else:
+      if not output_to_stdout:
+        self.test_log_file = tempfile.NamedTemporaryFile(
+            mode='w', dir=self.results_dir, delete=True
+        )
+      return subprocess.Popen(
+          cmd,
+          start_new_session=True,
+          shell=True,
+          stderr=subprocess.STDOUT,
+          stdout=self.test_log_file,
+          env=env_vars,
+      )
 
   # pylint: disable=broad-except
   def handle_subprocess(self, subproc, func):
@@ -165,11 +186,15 @@ class TestRunnerBase:
         # we have to save it above.
         logging.debug('Subproc already terminated, skipping')
       finally:
-        if self.test_log_file:
+        full_output = ''
+        if self._subprocess_stdout:
+          full_output = self._subprocess_stdout.read()
+        elif self.test_log_file:
           with open(self.test_log_file.name, 'r') as f:
-            intro_msg = 'Unexpected Issue. Raw Output:'
-            print(atest_utils.mark_red(intro_msg))
-            print(f.read())
+            full_output = f.read()
+        if full_output:
+          print(atest_utils.mark_red('Unexpected Issue. Raw Output:'))
+          print(full_output)
         # Ignore socket.recv() raising due to ctrl-c
         if not error.args or error.args[0] != errno.EINTR:
           raise error
diff --git a/atest/usb_speed_detect.py b/atest/usb_speed_detect.py
index 4db5b7ab..af1ca643 100644
--- a/atest/usb_speed_detect.py
+++ b/atest/usb_speed_detect.py
@@ -14,58 +14,70 @@
 
 """Module that detects device attributes and USB speed using adb commands."""
 
+import enum
 import logging
 import subprocess
+from typing import NamedTuple
 from atest import atest_utils
 from atest import constants
-from packages.modules.adb.proto import adb_host_pb2
 
 
-def verify_and_print_usb_speed_warning(device: adb_host_pb2.Device) -> bool:
+@enum.unique
+class UsbAttributeName(enum.Enum):
+  NEGOTIATED_SPEED = 'current_speed'
+  MAXIMUM_SPEED = 'maximum_speed'
+
+
+class DeviceIds(NamedTuple):
+  manufacturer: str
+  model: str
+  name: str
+  serial: str
+  address: str
+
+
+def verify_and_print_usb_speed_warning(
+    device_ids: DeviceIds, negotiated_speed: int, max_speed: int
+) -> bool:
   """Checks whether the connection speed is optimal for the given device.
 
   Args:
-      device: The proto representation of a device.
+      device_ids: Identifiers allowing a user to recognize the device the usb
+        speed warning is related to.
+      negotiated_speed: The current speed of the device.
+      max_speed: The maximum speed that the given device is capable of.
 
   Returns:
       True if the warning was printed, False otherwise.
   """
-  if (
-      device.connection_type != adb_host_pb2.ConnectionType.USB
-      or device.state != adb_host_pb2.ConnectionState.DEVICE
-  ):
-    return False
-
   # If a USB-2 is used with a USB-3 capable device, the speed will be
   # downgraded to 480 Mbps and never 12 Mbps, so this is the only case we
   # check.
-  if (
-      device.negotiated_speed == 480
-      and device.negotiated_speed < device.max_speed
-  ):
-    _print_usb_speed_warning(
-        device.serial, device.negotiated_speed, device.max_speed
-    )
+  if negotiated_speed == 480 and negotiated_speed < max_speed:
+    _print_usb_speed_warning(device_ids, negotiated_speed, max_speed)
     return True
   return False
 
 
 def _print_usb_speed_warning(
-    serial: str, negotiated_speed: int, max_speed: int
+    device_ids: DeviceIds, negotiated_speed: int, max_speed: int
 ):
   """Prints a warning about the device's operating speed if it's suboptimal.
 
   Args:
-    serial: The serial number of the device.
+    device_ids: Identifiers allowing a user to recognize the device the usb
+      speed warning is related to.
     negotiated_speed: The negotiated speed (in Mbits per seconds) the device is
       operating at.
     max_speed: The maximum speed (in Mbits per seconds) of which the device is
       capable.
   """
   atest_utils.colorful_print(
-      f'Warning: The device with serial {serial} is using'
-      f' {_speed_to_string(negotiated_speed)} while'
-      f' {_speed_to_string(max_speed)} capable. Check the USB cables/hubs.',
+      f'Warning: The {device_ids.manufacturer} {device_ids.model} device ('
+      f'{device_ids.name}) with address {device_ids.address} and serial '
+      f'{device_ids.serial} is using '
+      f'{_speed_to_string(negotiated_speed)} while '
+      f'{_speed_to_string(max_speed)} capable. Check the USB cables/hubs.',
       constants.MAGENTA,
   )
 
@@ -81,33 +93,117 @@ def _speed_to_string(speed: int) -> str:
   }.get(speed, f'{speed:,} Mbps')
 
 
-def get_device_proto_binary() -> adb_host_pb2.Device:
-  """Run `adb track-devices --proto-binary` to fetch the device info.
+def _string_to_speed(speed_str: str) -> int:
+  return {
+      'UNKNOWN': 0,
+      'high-speed': 480,
+      'super-speed': 5000,
+      'super-speed-plus': 10000,
+  }.get(speed_str, 0)
+
+
+def get_udc_driver_usb_device_dir_name() -> str:
+  """Reads the directory where the usb devices attributes are stored.
 
   Returns:
-     A Device object with the attributes of the given device.
+      A string corresponding to the directory name.
   """
-  if not atest_utils.has_command('adb'):
-    return adb_host_pb2.Device()
-  proc = subprocess.Popen(
-      ['adb', 'track-devices', '--proto-binary'],
-      stdin=subprocess.PIPE,
-      stdout=subprocess.PIPE,
+  return _adb_read_file('/config/usb_gadget/g1/UDC')
+
+
+def get_udc_driver_usb_device_attribute_speed_value(
+    speed_dir_name: str,
+    attr_name: UsbAttributeName,
+) -> int:
+  """Reads the usb speed string from the device and returns the numeric speed.
+
+  Args:
+      speed_dir_name: name of the directory where the usb driver attributes are
+        located.
+      attr_name: The attribute to read from the device.
+
+  Returns:
+      An int corresponding to the numeric speed value converted from the udc
+      driver attribute value. 0 is returned if adb is unable to read the value.
+  """
+  speed_reading = _adb_read_file(
+      '/sys/class/udc/' + speed_dir_name + '/' + attr_name.value
   )
-  devices = None
+  return _string_to_speed(speed_reading)
+
+
+def _adb_read_file(file_path: str) -> str:
+  cmd = [
+      'adb',
+      'shell',
+      'su',
+      '0',
+      f'cat {file_path}',
+  ]
   try:
-    devices = adb_host_pb2.Devices.FromString(
-        proc.stdout.read(int(proc.stdout.read(4).decode('utf-8'), 16))
+    logging.debug('Running command: %s', cmd)
+    result = subprocess.check_output(
+        cmd,
+        encoding='utf-8',
+        stderr=subprocess.STDOUT,
     )
-  except ValueError as ve:
+    return result.strip()
+  except subprocess.CalledProcessError as cpe:
     logging.debug(
-        'Exception raised while running `adb track-devices`. USB speed will'
-        ' not be read. Error: %s',
-        ve,
+        f'Cannot read directory; USB speed will not be read. Error: %s', cpe
     )
-  # Make sure the process is terminated even though an exception is thrown.
-  proc.terminate()
-  # When multiple devices are available, only one will be used.
-  return (
-      devices.device[0] if devices and devices.device else adb_host_pb2.Device()
+  except OSError as ose:
+    logging.debug(f'Cannot read usb speed from the device. Error: %s', ose)
+  return ''
+
+
+def get_adb_device_identifiers() -> DeviceIds | None:
+  """Fetch the user-facing device identifiers."""
+  if not atest_utils.has_command('adb'):
+    return None
+
+  device_serial = _adb_run_cmd(['adb', 'shell', 'getprop', 'ro.serialno'])
+  if not device_serial:
+    return None
+
+  device_address_resp = _adb_run_cmd(['adb', 'devices'])
+  try:
+    device_addresses = device_address_resp.splitlines()
+    for line in device_addresses:
+      if 'device' in line:
+        device_address = line.split()[0].strip()
+  except IndexError:
+    logging.debug('No devices are connected. USB speed will not be read.')
+    return None
+
+  device_manufacturer = _adb_run_cmd(
+      ['adb', 'shell', 'getprop', 'ro.product.manufacturer']
   )
+  device_model = _adb_run_cmd(['adb', 'shell', 'getprop', 'ro.product.model'])
+  device_name = _adb_run_cmd(['adb', 'shell', 'getprop', 'ro.product.name'])
+
+  return DeviceIds(
+      manufacturer=device_manufacturer,
+      model=device_model,
+      name=device_name,
+      serial=device_serial,
+      address=device_address,
+  )
+
+
+def _adb_run_cmd(cmd: list[str]) -> str:
+  try:
+    logging.debug(f'Running command: %s.', cmd)
+    result = subprocess.check_output(
+        cmd,
+        encoding='utf-8',
+        stderr=subprocess.STDOUT,
+    )
+    return result.strip() if result else ''
+  except subprocess.CalledProcessError:
+    logging.debug(
+        'Exception raised while running `%s`. USB speed will not be read.', cmd
+    )
+  except OSError:
+    logging.debug('Could not find adb. USB speed will not be read.')
+  return ''
diff --git a/atest/usb_speed_detect_unittest.py b/atest/usb_speed_detect_unittest.py
index db1eda82..bb31c15b 100644
--- a/atest/usb_speed_detect_unittest.py
+++ b/atest/usb_speed_detect_unittest.py
@@ -12,47 +12,172 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+import subprocess
 import unittest
-from atest import usb_speed_detect
-from packages.modules.adb.proto import adb_host_pb2
+from unittest import mock
 
+from atest import atest_utils
+from atest import usb_speed_detect as usb
 
-class UsbSpeedDetectTest(unittest.TestCase):
 
-  def test_non_usb_device_doesnt_print(self):
-    device = adb_host_pb2.Device()
-    device.connection_type = adb_host_pb2.ConnectionType.SOCKET
-    device.state = adb_host_pb2.ConnectionState.DEVICE
+class UsbIgnoredSpeedPatterns(unittest.TestCase):
 
-    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+  def _usb_speed_assert_no_warning(self, negotiated_speed, max_speed):
+    """Parametrized test to verify whether a usb speed warning is printed."""
+    warning = usb.verify_and_print_usb_speed_warning(
+        device_ids=usb.DeviceIds('', '', '', '', ''),
+        negotiated_speed=negotiated_speed,
+        max_speed=max_speed,
+    )
 
     self.assertFalse(warning)
 
-  def test_usb_device_expected_speed_doesnt_print(self):
-    device = adb_host_pb2.Device()
-    device.connection_type = adb_host_pb2.ConnectionType.USB
-    device.state = adb_host_pb2.ConnectionState.DEVICE
-    device.negotiated_speed = 5000
-    device.max_speed = 5000
+  def test_verify_print_speed_unknown_speed_doesnt_print(self):
+    self._usb_speed_assert_no_warning(0, 0)
 
-    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+  def test_verify_print_speed_low_speed_doesnt_print(self):
+    self._usb_speed_assert_no_warning(480, 480)
+
+  def test_verify_print_speed_expected_speed_doesnt_print(self):
+    self._usb_speed_assert_no_warning(5000, 5000)
+
+  def test_verify_print_speed_high_speed_doesnt_print(self):
+    self._usb_speed_assert_no_warning(5000, 10000)
 
-    self.assertFalse(warning)
 
-  def test_usb_device_slow_speed_prints_warning(self):
-    device = adb_host_pb2.Device()
-    device.connection_type = adb_host_pb2.ConnectionType.USB
-    device.state = adb_host_pb2.ConnectionState.DEVICE
-    device.negotiated_speed = 480
-    device.max_speed = 5000
+class UsbSpeedDetectTest(unittest.TestCase):
 
-    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+  def test_verify_print_speed_slow_speed_prints_warning(self):
+    warning = usb.verify_and_print_usb_speed_warning(
+        device_ids=usb.DeviceIds('', '', '', '', ''),
+        negotiated_speed=480,
+        max_speed=10000,
+    )
 
     self.assertTrue(warning)
 
-  def test_adb_unavailable_doesnt_print(self):
-    device = adb_host_pb2.Device()
 
-    warning = usb_speed_detect.verify_and_print_usb_speed_warning(device)
+class UdcDriverPatterns(unittest.TestCase):
 
-    self.assertFalse(warning)
+  def _udc_driver_response(
+      self, attr_name: usb.UsbAttributeName, expected_response: int
+  ):
+    """Parametrized test for handling the responses from the usb driver."""
+
+    speed = usb.get_udc_driver_usb_device_attribute_speed_value('', attr_name)
+
+    self.assertEqual(speed, expected_response)
+
+  @mock.patch('subprocess.check_output', return_value='not found')
+  def test_udc_driver_unexpected_subprocess_response_returns_0(
+      self, mock_output
+  ):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 0)
+
+  @mock.patch('subprocess.check_output', return_value='UNKNOWN')
+  def test_udc_driver_unknown_speed_returns_0(self, mock_output):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 0)
+
+  @mock.patch('subprocess.check_output', return_value='wireless')
+  def test_udc_driver_irrelevant_speed_returns_0(self, mock_output):
+    self._udc_driver_response(usb.UsbAttributeName.NEGOTIATED_SPEED, 0)
+
+  @mock.patch('subprocess.check_output', return_value='high-speed')
+  def test_udc_driver_high_speed_returns_numeric_speed(self, mock_output):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 480)
+
+  @mock.patch('subprocess.check_output', return_value='high-speed\n')
+  def test_udc_driver_high_speed_output_has_newline_returns_numeric_speed(
+      self, mock_output
+  ):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 480)
+
+  @mock.patch('subprocess.check_output', return_value='super-speed')
+  def test_udc_driver_super_speed_returns_numeric_speed(self, mock_output):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 5000)
+
+  @mock.patch('subprocess.check_output', return_value='super-speed-plus')
+  def test_udc_driver_super_speed_plus_returns_numeric_speed(self, mock_output):
+    self._udc_driver_response(usb.UsbAttributeName.MAXIMUM_SPEED, 10000)
+
+
+class DeviceIdentifierPatterns(unittest.TestCase):
+
+  @mock.patch.object(atest_utils, 'has_command', return_value=True)
+  @mock.patch.object(subprocess, 'check_output')
+  def test_get_adb_device_identifiers_port_fwd_device_returns_address(
+      self, mock_output, mock_utils
+  ):
+    def check_output_side_effect_port_fwd_device(*args, **kwargs):
+      for arg in args:
+        if 'ro.serialno' in arg:
+          return 'SERIAL'
+        if all(cmd_arg in ['adb', 'devices'] for cmd_arg in arg):
+          return 'List of devices\nlocalhost:27030     device'
+        if any(
+            cmd_arg
+            in {
+                'ro.product.manufacturer',
+                'ro.product.model',
+                'ro.product.name',
+            }
+            for cmd_arg in arg
+        ):
+          return ''
+
+    mock_output.side_effect = check_output_side_effect_port_fwd_device
+
+    device_ids = usb.get_adb_device_identifiers()
+
+    self.assertEqual(device_ids.address, 'localhost:27030')
+
+  @mock.patch.object(atest_utils, 'has_command', return_value=True)
+  @mock.patch.object(subprocess, 'check_output')
+  def test_get_adb_device_identifiers_tcp_device_returns_address(
+      self, mock_output, mock_utils
+  ):
+    def check_output_side_effect_tcp_device(*args, **kwargs):
+      for arg in args:
+        if 'ro.serialno' in arg:
+          return 'SERIAL'
+        if all(cmd_arg in ['adb', 'devices'] for cmd_arg in arg):
+          return (
+              '* daemon not running; starting now at tcp:1111\n * daemon '
+              'started successfully\n List of devices\n33a832a820  device'
+          )
+        if any(
+            # If check_output is called with any of ('model', 'name',
+            # 'manufacturer', return an empty placeholder value.
+            cmd_arg
+            in {
+                'ro.product.manufacturer',
+                'ro.product.model',
+                'ro.product.name',
+            }
+            for cmd_arg in arg
+        ):
+          return ''
+
+    mock_output.side_effect = check_output_side_effect_tcp_device
+
+    device_ids = usb.get_adb_device_identifiers()
+
+    self.assertEqual(device_ids.address, '33a832a820')
+
+  @mock.patch.object(atest_utils, 'has_command', return_value=True)
+  @mock.patch.object(subprocess, 'check_output')
+  def test_get_adb_device_identifiers_multiple_devices_returns_none(
+      self, mock_output, mock_utils
+  ):
+    def check_output_side_effect_multiple_devices(*args, **kwargs):
+      for arg in args:
+        # When multiple devices are connected, ADB will display an error "adb:
+        # more than one device/emulator" and no serial will be returned.
+        if 'ro.serialno' in arg:
+          return None
+
+    mock_output.side_effect = check_output_side_effect_multiple_devices
+
+    device_ids = usb.get_adb_device_identifiers()
+
+    self.assertIsNone(device_ids)
diff --git a/experiments/a/README.md b/experiments/a/README.md
index e94742ad..116e8724 100644
--- a/experiments/a/README.md
+++ b/experiments/a/README.md
@@ -5,6 +5,32 @@ go/a-tool-design-doc
 
 Contributions welcome!
 
+### A and Autocomplete aliases
+Add the following to your  ~/.bashrc for autocompletions
+```
+# Alias for local workflow "a update" tool
+a() {
+    python3 "$ANDROID_BUILD_TOP/tools/asuite/experiments/a/a.py" "$@"
+}
+_a_completion() {
+  local cur prev opts
+  COMPREPLY=()
+  cur="${COMP_WORDS[COMP_CWORD]}"
+  prev="${COMP_WORDS[COMP_CWORD-1]}"
+
+  if [[ ${prev} == "a" ]] ; then
+    COMPREPLY=( $(compgen -W "update" -- ${cur}) )
+    return 0
+  fi
+
+  if [[ ${prev} == "update" ]] ; then
+    COMPREPLY=( $(compgen -W "$(a update --list-aliases)" -- ${cur}) )
+    return 0
+  fi
+}
+complete -F _a_completion a
+```
+
 ### To Run
 ```a {config_name}```
 or
diff --git a/experiments/a/a.py b/experiments/a/a.py
index 6069062f..dfa14a67 100644
--- a/experiments/a/a.py
+++ b/experiments/a/a.py
@@ -35,26 +35,23 @@ tools_map = {
 def run():
   """Entry point for tool."""
   parser = argparse.ArgumentParser(
-      description='Run workflows to build update and test modules',
+      description='A runs tools and workflows for local Android development',
       formatter_class=argparse.RawDescriptionHelpFormatter,
   )
-  parser.add_argument(
-      '-q',
-      '--quiet',
-      action='store_true',
-      help='Do not display progress updates',
-  )
-  subparsers = parser.add_subparsers(dest='name')
-  for name in tools_map:
-    tools_map[name].add_parser(subparsers)
+  subparsers = parser.add_subparsers(dest='tool')
+  for _, tool_class in tools_map.items():
+    tool_class.add_parser(subparsers)
 
   args = parser.parse_args()
-  name = args.name.lower()
 
-  # Tools
-  if name in tools_map:
-    tool = tools_map[name]()
-    return tool.main(args)
+  # Tool
+  if not args.tool:
+    print('Error: Please specify a tool (eg. update)')
+    parser.print_help()
+    return 1
+  tool_name = args.tool.lower()
+  tool = tools_map[tool_name](args)
+  return tool.main()
 
 
 if __name__ == '__main__':
diff --git a/experiments/a/core/task_runner.py b/experiments/a/core/task_runner.py
index 1b0eb2d3..965547cc 100644
--- a/experiments/a/core/task_runner.py
+++ b/experiments/a/core/task_runner.py
@@ -17,14 +17,21 @@
 
 """Classes to help coordinate running tasks and displaying progress."""
 
-import os
 import subprocess
+import sys
 import threading
-import time
 
 from .errors import TaskError
 
 
+class Task:
+  """Defines a task to be run by the task_runner."""
+
+  def __init__(self, cmd, fall_back_tasks=None):
+    self.cmd = cmd
+    self.fall_back_tasks = fall_back_tasks
+
+
 class TaskResult:
   """Holds result and status code of a task."""
 
@@ -39,7 +46,6 @@ class TaskRunner:
   def __init__(self):
     self.tasks = {}
     self.task_queue = []
-    self.fall_back_tasks = []
 
     self.running = False
 
@@ -47,10 +53,12 @@ class TaskRunner:
     self.quiet = False
     self.output = ''
     self.running_indicator_thread = None
-    self.running_indicator_chars = ['◢', '◣', '◤', '◥']
+    self.running_indicator_chars = ['→']
+    # self.running_indicator_chars = ['◢', '◣', '◤', '◥']
     self.running_indicator_index = 0
+    self.stop_event = threading.Event()
 
-  def add_task(self, name, function, *args, **kwargs):
+  def add_task(self, name, function, *args, fall_back_tasks=None, **kwargs):
     """Adds a task to the queue."""
     self.tasks[name] = {
         'status': 'pending',
@@ -58,18 +66,20 @@ class TaskRunner:
         'output': '',
         'args': args,
         'kwargs': kwargs,
+        'fall_back_tasks': fall_back_tasks,
     }
     self.task_queue.append(name)
 
   def start(self):
     """Starts running all the tasks in the queue."""
+    print('Running Plan:')
     self.running = True
     self._run_next_task()
-    self.start_running_indicator()
 
   def run_task(self, name):
     """Run this task in the queue."""
     task = self.tasks[name]
+    self.render_output()
     try:
       for line in task['function'](*task['args'], **task['kwargs']):
         if isinstance(line, TaskResult):
@@ -78,25 +88,23 @@ class TaskRunner:
             raise TaskError(f'status_code: {result.status_code}')
         else:
           self.tasks[name]['output'] += line
-        if self.running:
-          self.render_output()
       self.tasks[name]['status'] = 'completed'
       if self.running:
         self._run_next_task()
     except TaskError as e:
       self.tasks[name]['status'] = 'failed'
       self.tasks[name]['output'] += f'Error: {e}\n'
+      self.render_output()
 
-      if self.fall_back_tasks:
+      fall_back_tasks = self.tasks[name].get('fall_back_tasks', [])
+      if fall_back_tasks:
         self.task_queue = []
-        for t in self.fall_back_tasks:
+        for t in fall_back_tasks:
           if isinstance(t, str):
-            self.add_shell_command_task(t)
-        self.fall_back_tasks = []
+            self.add_shell_command_task([t])
         self._run_next_task()
       else:
         if self.running:
-          self.render_output()
           self.running = False
 
   def _run_next_task(self):
@@ -112,50 +120,26 @@ class TaskRunner:
       if self.quiet:
         return
 
-      print('')
-      print(
-          'Add workflows/tools: go/atool Join http://g/atool-discuss to discuss'
-          ' and stay up to date'
-      )
       print('')
       print('Run Completed Successfully!')
+      print('')
 
-  def add_shell_command_task(self, command):
+  def add_shell_command_task(self, command, fall_back_tasks=None):
     """Adds a shell command to the task queue."""
-    self.add_task(command, run_shell_command, command)
-
-  def start_running_indicator(self):
-    """Starts the progress indicator thread."""
-    if (
-        self.running_indicator_thread is None
-        or not self.running_indicator_thread.is_alive()
-    ):
-      self.running_indicator_thread = threading.Thread(
-          target=self._update_running_indicator
-      )
-      self.running_indicator_thread.start()
-
-  def _update_running_indicator(self):
-    """Updates the progress indicator thread."""
-    while self.running:
-      self.running_indicator_index = (self.running_indicator_index + 1) % len(
-          self.running_indicator_chars
-      )
-      self.render_output()
-      time.sleep(0.15)
+    self.add_task(
+        command, run_shell_command, command, fall_back_tasks=fall_back_tasks
+    )
 
   def render_output(self):
     """Prints the output of the tasks as well as a table showing the progres on the task queue."""
     if self.quiet:
       return
 
-    os.system('cls' if os.name == 'nt' else 'clear')
+    # os.system('cls' if os.name == 'nt' else 'clear')
     print(f'{self.output}', end='')
     for name, command_data in self.tasks.items():
       print(f"{command_data['output']}", end='')
 
-    print('')
-    print('-' * 20)
     for name, command_data in self.tasks.items():
       status_icon = '.'
       status_color = '\033[94m'  # Blue
@@ -168,28 +152,37 @@ class TaskRunner:
       elif command_data['status'] == 'failed':
         status_icon = '✗'
         status_color = '\033[91m'  # Red
-      print(f'{status_color}{status_icon}\033[0m {status_color}{name}\033[0m')
+      print(f'{status_color}{status_icon}\033[0m {name}\033[0m')
     print('-' * 20)
 
 
-def run_shell_command(command):
+def run_shell_command(command, use_stdout=True):
   """Run a shell command and yield output."""
   last_line = ''
-  with subprocess.Popen(
-      command,
-      shell=True,
-      stdout=subprocess.PIPE,
-      stderr=subprocess.STDOUT,
-      text=True,
-  ) as process:
-    yield f'Running: {command}\n'
-    for line in iter(process.stdout.readline, ''):
-      if line.strip() == last_line:
-        continue
-      last_line = line.strip()
-      yield line
-    process.stdout.flush()
-    process.stdout.close()
+
+  if use_stdout:
+    with subprocess.Popen(
+        command,
+        shell=True,
+        stdout=sys.stdout,
+        stderr=sys.stderr,
+        text=True,
+    ) as process:
+      status_code = process.wait()
+      yield TaskResult(status_code=status_code)
+  else:
+    with subprocess.Popen(
+        command,
+        shell=True,
+        text=True,
+    ) as process:
+      status_code = process.wait()
+      for line in iter(process.stdout.readline, ''):
+        if line.strip() == last_line:
+          continue
+        last_line = line.strip()
+        yield line
+      process.stdout.flush()
+      process.stdout.close()
     status_code = process.wait()
-    yield f'Command finished with exit code: {status_code}\n'
     yield TaskResult(status_code=status_code)
diff --git a/experiments/a/tools/update.py b/experiments/a/tools/update.py
index 62542602..39acf87d 100644
--- a/experiments/a/tools/update.py
+++ b/experiments/a/tools/update.py
@@ -17,217 +17,118 @@
 
 """Update Tool."""
 
-import inspect
-import os
-import sys
+import argparse
 
 from core.errors import WorkflowError
+from core.task_runner import Task
 from core.task_runner import TaskRunner
+from tools.update_aliases import get_aliases
+from tools.update_utils import combine_build_commands
+from tools.update_utils import combine_update_commands
 
 
 class Update:
   """Updates a device."""
 
+  def __init__(self, args):
+    self.args = args
+
   @classmethod
   def add_parser(cls, subparsers):
-    """Parse update alias/arguments."""
-    parser = subparsers.add_parser('update', help='Updates a device')
+    """Parse command line update arguments."""
+
+    aliases = get_aliases()
+    epilog = 'Aliases:\n'
+    for alias in get_aliases().keys():
+      name = alias
+      build_commands = (';').join(aliases[name].build())
+      update_commands = (';').join(aliases[name].update())
+      epilog += f'  {name}:\n\t{build_commands}\n\t{update_commands}\n'
+
+    parser = subparsers.add_parser(
+        'update', epilog=epilog, formatter_class=argparse.RawTextHelpFormatter
+    )
+
+    parser.add_argument('alias', nargs='*', default=[], type=str)
     parser.add_argument(
-        'alias', nargs='?', default='default', type=str, help='alias'
+        '--build-only',
+        action='store_true',
+        help='only build the specified targets, do not update the device.',
+    )
+    parser.add_argument(
+        '--update-only',
+        action='store_true',
+        help=(
+            'only update the device with prebuilt targets, do not build'
+            ' targets.'
+        ),
+    )
+    parser.add_argument(
+        '--list-aliases',
+        action='store_true',
+        help='list aliases; used for autocomplete',
     )
 
-  def main(self, args):
+  def main(self):
     """Main entrypoint for Update."""
-    alias = args.alias
-    tasks, fall_back_tasks = self.gather_tasks(alias)
-    self.run_tasks(tasks, fall_back_tasks)
 
-  def gather_tasks(self, alias):
+    if self.args.list_aliases:
+      print(' '.join(get_aliases().keys()))
+      return
+
+    tasks = self.gather_tasks()
+    self.run_tasks(tasks)
+
+  def gather_tasks(self):
     """Gathers tasks to run based on alias."""
     tasks = []
-    fall_back_tasks = []
+    build_tasks = []
+    update_tasks = []
 
+    requested_aliases = self.args.alias
     aliases = get_aliases()
-    if alias in aliases:
-      config = aliases[alias]()
-      tasks += config.build()
-      tasks += config.update()
+    for a in requested_aliases:
+      if a not in aliases:
+        raise WorkflowError(f'unknown alias: {a}')
+      config = aliases[a]
+      build_tasks += config.build()
+      update_tasks += config.update()
+
+    # combine build tasks
+    build_tasks = combine_build_commands(build_tasks)
+    # combine update tasks
+    update_tasks = combine_update_commands(update_tasks)
+
+    if self.args.build_only:
+      tasks = build_tasks
+    elif self.args.update_only:
+      tasks = update_tasks
     else:
-      # default
+      tasks = build_tasks + update_tasks
+
+    if not tasks:
+      # If no tasks run adevice update with a fall back to a full flash.
       tasks = [
           'm sync',
-          'adevice update',
-      ]
-      fall_back_tasks = [
-          'm droid',
-          'flashall',
+          Task(
+              cmd='adevice update',
+              fall_back_tasks=[
+                  'm droid',
+                  'flashall',
+              ],
+          ),
       ]
-    return (tasks, fall_back_tasks)
+    return tasks
 
-  def run_tasks(self, tasks, fall_back_tasks):
+  def run_tasks(self, tasks):
     """Runs tasks."""
     task_runner = TaskRunner()
     task_runner.quiet = False
     for task in tasks:
       if isinstance(task, str):
         task_runner.add_shell_command_task(task)
+      elif isinstance(task, Task):
+        task_runner.add_shell_command_task(task.cmd, task.fall_back_tasks)
       else:
         task_runner.add_task(task)
-    task_runner.fall_back_tasks = fall_back_tasks
     task_runner.start()
-
-
-class Alias:
-  """Base class for defining an alias."""
-
-  def build(self):
-    return []
-
-  def update(self):
-    return []
-
-
-class Core(Alias):
-  """Alias for Core."""
-
-  def build(self):
-    return ['m framework framework-minus-apex']
-
-  def update(self):
-    return [
-        'adevice update',
-    ]
-
-
-class SystemServer(Alias):
-  """Alias for SystemServer."""
-
-  def update(self):
-    return [
-        'adevice update --restart=none',
-        'adb kill systemserver',
-    ]
-
-
-class SysUI(Alias):
-  """Alias for SystemUI."""
-
-  def build(self):
-    if is_nexus():
-      raise WorkflowError(
-          "Target 'sysui' is not allowed on Nexus Experience devices.\n"
-          'Try sysuig (with g at the end) or sysuititan'
-      )
-    return ['m framework framework-minus-apex SystemUI']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-class SysUIG(Alias):
-  """Alias for SystemUI for Google Devices."""
-
-  def build(self):
-    if not is_nexus():
-      raise WorkflowError(
-          "Target 'sysuig' is only allowed on Nexus Experience devices.\n"
-          'Try sysui (no g at the end)'
-      )
-    return ['m framework framework-minus-apex SystemUIGoogle']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-class SysUITitan(Alias):
-  """Alias for SystemUI Titan devices."""
-
-  def build(self):
-    if not is_nexus():
-      raise WorkflowError(
-          "Target 'sysuititan' is only allowed on Nexus Experience devices.\n"
-          'Try sysui (no g at the end)'
-      )
-    return ['m framework framework-minus-apex SystemUITitan']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-class SysUIGo(Alias):
-  """Alias for SystemUI."""
-
-  def build(self):
-    if not is_nexus():
-      raise WorkflowError(
-          "Target 'sysuigo' is only allowed on Nexus Experience devices.\n"
-          'Try sysui (no go at the end)'
-      )
-    return ['m framework framework-minus-apex SystemUIGo']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-class CarSysUI(Alias):
-  """Alias for CarSystemUI."""
-
-  def build(self):
-    return ['m framework framework-minus-apex CarSystemUI']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-class CarSysUIG(Alias):
-  """Alias for CarSystemUI."""
-
-  def build(self):
-    return ['m framework framework-minus-apex AAECarSystemUI']
-
-  def update(self):
-    target = 'com.android.systemui'
-    return [
-        'adevice update --restart=none',
-        f'adb shell am force-stop {target}',
-    ]
-
-
-# Utilities to get type of target
-def is_nexus():
-  target_product = os.getenv('TARGET_PRODUCT')
-  return (
-      target_product.startswith('.aosp')
-      or 'wembley' in target_product
-      or 'gms_humuhumu' in target_product
-  )
-
-
-def get_aliases():
-  return {
-      name.lower(): cls
-      for name, cls in inspect.getmembers(
-          sys.modules[__name__], inspect.isclass
-      )
-      if issubclass(cls, Alias) and cls != Alias
-  }
diff --git a/experiments/a/tools/update_aliases.py b/experiments/a/tools/update_aliases.py
new file mode 100644
index 00000000..5e903d84
--- /dev/null
+++ b/experiments/a/tools/update_aliases.py
@@ -0,0 +1,458 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
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
+
+"""Update Aliases."""
+
+import inspect
+import os
+import sys
+from core.errors import WorkflowError
+
+
+class Alias:
+  """Base class for defining an alias."""
+
+  def build(self):
+    return []
+
+  def update(self):
+    return []
+
+
+class Core(Alias):
+  """Alias for Core."""
+
+  def build(self):
+    return ['m framework framework-minus-apex']
+
+  def update(self):
+    return [
+        'adevice update',
+    ]
+
+
+class SystemServer(Alias):
+  """Alias for SystemServer."""
+
+  def update(self):
+    return [
+        'adevice update --restart=none',
+        'adb kill systemserver',
+    ]
+
+
+class SysUI(Alias):
+  """Alias for SystemUI."""
+
+  def build(self):
+    if is_nexus():
+      raise WorkflowError(
+          "Target 'sysui' is not allowed on Nexus Experience devices.\n"
+          'Try sysuig (with g at the end) or sysuititan'
+      )
+    return ['m framework framework-minus-apex SystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell "am force-stop {target}"',
+    ]
+
+
+class SysUIG(Alias):
+  """Alias for SystemUI for Google Devices."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuig' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no g at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUIGoogle']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class SysUITitan(Alias):
+  """Alias for SystemUI Titan devices."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuititan' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no g at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUITitan']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class SysUIGo(Alias):
+  """Alias for SystemUI."""
+
+  def build(self):
+    if not is_nexus():
+      raise WorkflowError(
+          "Target 'sysuigo' is only allowed on Nexus Experience devices.\n"
+          'Try sysui (no go at the end)'
+      )
+    return ['m framework framework-minus-apex SystemUIGo']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class CarSysUI(Alias):
+  """Alias for CarSystemUI."""
+
+  def build(self):
+    return ['m framework framework-minus-apex CarSystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class CarSysUIG(Alias):
+  """Alias for CarSystemUI."""
+
+  def build(self):
+    return ['m framework framework-minus-apex AAECarSystemUI']
+
+  def update(self):
+    target = 'com.android.systemui'
+    return [
+        'adevice update --restart=none',
+        f'adb shell am force-stop {target}',
+    ]
+
+
+class Droid(Alias):
+  """Alias for Droid."""
+
+  def build(self):
+    return ['m droid']
+
+  def update(self):
+    return ['flashall']
+
+
+class Snod(Alias):
+  """Alias for Snod."""
+
+  def build(self):
+    return ['m snod']
+
+  def update(self):
+    return ['flashall']
+
+
+# These definitions are imported from makepush
+# https://team.git.corp.google.com/android-framework/toolbox/+/refs/heads/main/makepush/makepush.sh
+alias_definitions = {
+    'core_jni': {'build': 'libandroid_runtime'},
+    'res_jni': {'build': 'libandroidfw libidmap2'},
+    'idmap2': {'build': 'idmap2 idmap2d'},
+    'sf': {'build': 'surfaceflinger'},
+    'res': {'build': 'framework-res'},
+    'services': {'build': 'services protolog.conf.json.gz'},
+    'inputflinger': {'build': 'libinputflinger'},
+    'carsysui': {
+        'build': 'carSystemUI',
+        'update': 'adb shell am force-stop com.android.systemui',
+    },
+    'carsysuig': {
+        'build': 'AAECarSystemUI',
+        'update': 'adb shell am force-stop com.android.systemui',
+    },
+    'car-mainline': {
+        'build': 'com.android.car.framework',
+        'update': (
+            'adb install -r --staged --enable-rollback'
+            ' $OUT/system/apex/com.android.car.framework.apex'
+        ),
+    },
+    'carfwk': {'build': 'carfwk car-frameworks-service'},
+    'carfwk-module': {'build': 'car-frameworks-service-module'},
+    'carsettings': {
+        'build': 'carSettings',
+        'update': 'adb shell am force-stop com.android.car.settings',
+    },
+    'carks': {
+        'build': 'EmbeddedKitchenSinkApp',
+        'update': 'adb shell am force-stop com.google.android.car.kitchensink',
+    },
+    'carlauncher': {
+        'build': 'carLauncher',
+        'update': 'adb shell am force-stop com.android.car.carlauncher',
+    },
+    'carlauncherg': {
+        'build': 'GASCarLauncher',
+        'update': 'adb shell am force-stop com.android.car.carlauncher',
+    },
+    'car-md-launcher': {
+        'build': 'MultiDisplaySecondaryHomeTestLauncher',
+        'update': (
+            'adb install'
+            ' $OUT/system/priv-app/MultiDisplaySecondaryHomeTestLauncher/MultiDisplaySecondaryHomeTestLauncher.apk'
+        ),
+    },
+    'carsuw': {
+        'build': 'carProvision',
+        'update': 'adb shell am force-stop com.android.car.provision',
+    },
+    'car': {'build': 'android.car'},
+    'car-builtin': {'build': 'android.car.builtin'},
+    'vhal-legacy': {
+        'build': 'android.hardware.automotive.vehicle@2.0-service',
+        'update': (
+            'adb shell am force-stop'
+            ' android.hardware.automotive.vehicle@2.0-service'
+        ),
+    },
+    'vhal': {
+        'build': 'android.hardware.automotive.vehicle@V1-default-service',
+        'update': (
+            'adb shell am force-stop'
+            ' android.hardware.automotive.vehicle@V1-default-service'
+        ),
+    },
+    'vhal-pasa': {
+        'build': 'android.hardware.automotive.vehicle@V1-pasa-service',
+        'update': (
+            'adb shell am force-stop'
+            ' android.hardware.automotive.vehicle@V1-pasa-service'
+        ),
+    },
+    'launcher': {'build': 'NexusLauncherRelease'},
+    'launcherd': {
+        'build': 'nexusLauncherDebug',
+        'update': (
+            'adb install'
+            ' $OUT/anywhere/priv-app/NexusLauncherDebug/NexusLauncherDebug.apk'
+        ),
+    },
+    'launchergo': {
+        'build': 'launcherGoGoogle',
+        'update': 'adb shell am force-stop com.android.launcher3',
+    },
+    'intentresolver': {
+        'build': 'intentResolver',
+        'update': 'adb shell am force-stop com.android.intentresolver',
+    },
+    'sysuig': {
+        'build': 'systemUIGoogle',
+        'update': 'adb shell am force-stop com.android.systemui',
+    },
+    'sysuititan': {
+        'build': 'systemUITitan',
+        'update': 'adb shell am force-stop com.android.systemui',
+    },
+    'sysuigo': {
+        'build': 'systemUIGo',
+        'update': 'adb shell am force-stop com.android.systemui',
+    },
+    'flagflipper': {
+        'build': 'theFlippinApp',
+        'update': 'adb shell am force-stop com.android.theflippinapp',
+    },
+    'docsui': {
+        'build': 'documentsUI',
+        'update': 'adb shell am force-stop com.android.documentsui',
+    },
+    'docsuig': {
+        'build': 'documentsUIGoogle',
+        'update': 'adb shell am force-stop com.google.android.documentsui',
+    },
+    'settings': {
+        'build': 'settings',
+        'update': 'adb shell am force-stop com.android.settings',
+    },
+    'settingsg': {
+        'build': 'SettingsGoogle',
+        'update': 'adb shell am force-stop com.google.android.settings',
+    },
+    'settingsgf': {
+        'build': 'SettingsGoogleFutureFaceEnroll',
+        'update': (
+            'adb shell am force-stop'
+            ' com.google.android.settings.future.biometrics.faceenroll'
+        ),
+    },
+    'settings_provider': {'build': 'SettingsProvider'},
+    'apidemos': {
+        'build': 'ApiDemos',
+        'update': (
+            'adb install'
+            ' $OUT/testcases/ApiDemos/$var_cache_TARGET_ARCH/ApiDemos.apk'
+        ),
+    },
+    'teleservice': {
+        'build': 'TeleService',
+        'update': 'adb shell am force-stop com.android.phone',
+    },
+    'managed_provisioning': {
+        'build': 'ManagedProvisioning',
+        'update': 'adb shell am force-stop com.android.managedprovisioning',
+    },
+    'car_managed_provisioning': {
+        'build': 'carManagedProvisioning',
+        'update': (
+            'adb install'
+            ' $OUT/anywhere/priv-app/CarManagedProvisioning/CarManagedProvisioning.apk'
+        ),
+    },
+    'ctsv': {
+        'build': 'ctsVerifier',
+        'update': (
+            'adb install'
+            ' $OUT/testcases/CtsVerifier/$var_cache_TARGET_ARCH/CtsVerifier.apk'
+        ),
+    },
+    'gtsv': {
+        'build': 'gtsVerifier',
+        'update': (
+            'adb install'
+            ' $OUT/testcases/GtsVerifier/$var_cache_TARGET_ARCH/GtsVerifier.apk'
+        ),
+    },
+    'suw': {
+        'build': 'Provision',
+        'update': 'adb shell am force-stop com.android.provision',
+    },
+    'pkg_installer': {
+        'build': 'PackageInstaller',
+        'update': 'adb shell am force-stop com.android.packageinstaller',
+    },
+    'pkg_installer_g': {
+        'build': 'GooglePackageInstaller',
+        'update': 'adb shell am force-stop com.google.android.packageinstaller',
+    },
+    'perm_controller': {
+        'build': 'PermissionController',
+        'update': (
+            'adb install'
+            ' $OUT/apex/com.android.permission/priv-app/PermissionController/PermissionController.apk'
+        ),
+    },
+    'perm_controller_g': {
+        'build': 'GooglePermissionController',
+        'update': (
+            'adb install -r'
+            ' $OUT/apex/com.google.android.permission/priv-app/GooglePermissionController/GooglePermissionController.apk'
+        ),
+    },
+    'wifi': {
+        'build': 'com.android.wifi',
+        'update': (
+            'adb install -r --staged --enable-rollback'
+            ' $OUT/system/apex/com.android.wifi && adb shell am force-stop'
+            ' com.android.wifi'
+        ),
+    },
+    'vold': {'build': 'vold', 'update': 'adb shell am force-stop vold'},
+    'multidisplay': {
+        'build': 'multiDisplayProvider',
+        'update': 'adb shell am force-stop com.android.emulator.multidisplay',
+    },
+    'wm_ext': {
+        'build': 'androidx.window.extensions',
+    },
+    'rb': {
+        'build': 'adServicesApk',
+        'update': (
+            'adb install'
+            ' $OUT/apex/com.android.adservices/priv-app/AdServices/AdServices.apk'
+        ),
+    },
+    'rb_g': {
+        'build': 'adServicesApkGoogle',
+        'update': (
+            'adb install'
+            ' $OUT/apex/com.google.android.adservices/priv-app/AdServicesApkGoogle@MASTER/AdServicesApkGoogle.apk'
+        ),
+    },
+    'sdk_sandbox': {
+        'build': 'sdkSandbox',
+        'update': (
+            'adb install'
+            ' $OUT/apex/com.google.android.adservices/app/SdkSandboxGoogle@MASTER/SdkSandboxGoogle.apk'
+        ),
+    },
+}
+
+
+# Utilities to get type of target
+def is_nexus():
+  target_product = os.getenv('TARGET_PRODUCT')
+  return (
+      target_product.startswith('.aosp')
+      or 'wembley' in target_product
+      or 'gms_humuhumu' in target_product
+  )
+
+
+def create_alias_from_config(config):
+  """Generates a Alias class from json."""
+  alias = Alias()
+  build = config.get('build', None)
+  if build:
+    alias.build = lambda: [f'm {build}']
+
+  update = config.get('update', None)
+  if update:
+    alias.update = lambda: [
+        'adevice update --restart=none',
+        update,
+    ]
+  else:
+    alias.update = lambda: ['adevice update']
+  return alias
+
+
+def get_aliases():
+  """Dynamically find all aliases."""
+  # definitions that subclass the Alias class
+  aliases = {
+      name.lower(): cls()
+      for name, cls in inspect.getmembers(
+          sys.modules[__name__], inspect.isclass
+      )
+      if issubclass(cls, Alias) and cls != Alias
+  }
+  # definitions that are defined in alias_definitions
+  for name, config in alias_definitions.items():
+    aliases[name.lower()] = create_alias_from_config(config)
+  return aliases
diff --git a/experiments/a/tools/update_test.py b/experiments/a/tools/update_test.py
index e56a4dfb..acc0d969 100644
--- a/experiments/a/tools/update_test.py
+++ b/experiments/a/tools/update_test.py
@@ -14,39 +14,135 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
+import argparse
 import unittest
-from .update import Core
-from .update import get_aliases
-from .update import SystemServer
-from .update import SysUI
 from .update import Update
+from .update_aliases import Core
+from .update_aliases import get_aliases
+from .update_aliases import SystemServer
+from .update_aliases import SysUI
+from .update_utils import combine_build_commands
+from .update_utils import combine_update_commands
+from .update_utils import remove_commands_that_starts_with
+from .update_utils import remove_duplicates_maintain_order
 
 
 class UpdateTest(unittest.TestCase):
 
+  def setUp(self):
+    super().setUp()
+    args = argparse.Namespace()
+    args.build_only = False
+    args.update_only = False
+    args.alias = []
+    self.args = args
+
   def test_get_aliases(self):
     aliases = get_aliases()
     self.assertIn('core', aliases)
     self.assertIn('systemserver', aliases)
     self.assertIn('sysui', aliases)
 
-    self.assertIs(aliases['core'], Core)
-    self.assertIs(aliases['systemserver'], SystemServer)
-    self.assertIs(aliases['sysui'], SysUI)
+    self.assertIs(aliases['core'].__class__, Core)
+    self.assertIs(aliases['systemserver'].__class__, SystemServer)
+    self.assertIs(aliases['sysui'].__class__, SysUI)
+
+    # Test that definitions from json are found
+    self.assertIn('wifi', aliases)
+    self.assertIn('sdk_sandbox', aliases)
 
   def test_gather_tasks_default(self):
-    update = Update()
-    tasks, fall_back_tasks = update.gather_tasks('')
-    self.assertEqual(tasks, ['m sync', 'adevice update'])
-    self.assertEqual(fall_back_tasks, ['m droid', 'flashall'])
+    update = Update(self.args)
+    tasks = update.gather_tasks()
+    self.assertEqual(tasks[0], 'm sync')
+    self.assertEqual(tasks[1].cmd, 'adevice update')
+    self.assertEqual(tasks[1].fall_back_tasks, ['m droid', 'flashall'])
 
   def test_gather_tasks_alias(self):
-    update = Update()
-    tasks, fall_back_tasks = update.gather_tasks('core')
+    self.args.alias = ['core']
+    update = Update(self.args)
+    tasks = update.gather_tasks()
     self.assertEqual(
         tasks, ['m framework framework-minus-apex', 'adevice update']
     )
-    self.assertEqual(fall_back_tasks, [])
+
+  def test_gather_tasks_build_only(self):
+    self.args.alias = ['core']
+    self.args.build_only = True
+
+    update = Update(self.args)
+    tasks = update.gather_tasks()
+    self.assertEqual(tasks, ['m framework framework-minus-apex'])
+
+  def test_gather_tasks_update_only(self):
+    self.args.alias = ['core']
+    self.args.update_only = True
+
+    update = Update(self.args)
+    tasks = update.gather_tasks()
+    self.assertEqual(tasks, ['adevice update'])
+
+  def test_gather_tasks_multiple_alias(self):
+    self.args.alias = ['sf', 'res']
+    update = Update(self.args)
+    tasks = update.gather_tasks()
+    self.assertEqual(
+        tasks, ['m surfaceflinger framework-res', 'adevice update']
+    )
+
+
+class UpdateUtilsTest(unittest.TestCase):
+
+  def test_remove_duplicates_maintain_order(self):
+    self.assertEqual(
+        remove_duplicates_maintain_order(['1', '2', '1', '3']), ['1', '2', '3']
+    )
+
+  def test_remove_commands_that_starts_with_no_match(self):
+    self.assertEqual(
+        remove_commands_that_starts_with(
+            commands=[
+                'keep a',
+                'keep b',
+                'remove a',
+                'remove b',
+            ],
+            cmd_to_remove='remove',
+        ),
+        ['keep a', 'keep b'],
+    )
+
+  def test_combine_build_cmd(self):
+    self.assertEqual(combine_build_commands(['m foo', 'm bar']), ['m foo bar'])
+
+  def test_combine_update_cmds_adevice_update(self):
+    # adevice update restarts so remove unneeded force-stops
+    self.assertEqual(
+        combine_update_commands([
+            'adevice update',
+            'adb shell "am force-stop foo"',
+            'adevice update',
+            'adb shell "am force-stop bar"',
+            'adevice update restart=none',
+        ]),
+        ['adevice update'],
+    )
+
+  def test_combine_update_cmds_adevice_update_no_restart(self):
+    # adevice update will not restart so keep force-stops
+    self.assertEqual(
+        combine_update_commands([
+            'adevice update --restart=none',
+            'adb shell "am force-stop foo"',
+            'adevice update --restart=none',
+            'adb shell "am force-stop bar"',
+        ]),
+        [
+            'adevice update --restart=none',
+            'adb shell "am force-stop foo"',
+            'adb shell "am force-stop bar"',
+        ],
+    )
 
 
 if __name__ == '__main__':
diff --git a/experiments/a/tools/update_utils.py b/experiments/a/tools/update_utils.py
new file mode 100644
index 00000000..7ae90c15
--- /dev/null
+++ b/experiments/a/tools/update_utils.py
@@ -0,0 +1,66 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024 - The Android Open Source Project
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
+"""Update Utils."""
+
+
+def combine_build_commands(commands):
+  """Combines build commands so that m is called once."""
+  m_command = ''
+  result = []
+  for cmd in commands:
+    if cmd.startswith('m '):
+      m_command += cmd[2:] + ' '
+    else:
+      result.append(cmd)
+  if m_command:
+    result.insert(0, 'm ' + m_command.strip())
+  return result
+
+
+def combine_update_commands(commands):
+  """Combines update tasks so that a reboot/adevice update is called only once."""
+  commands = remove_duplicates_maintain_order(commands)
+
+  # if any command calls for a restart; just do that
+  # deduplicate and remove
+  if 'adevice update' in commands:
+    commands = remove_commands_that_starts_with(commands, 'adevice update')
+    commands = remove_commands_that_starts_with(
+        commands, 'adb shell "am force-stop'
+    )
+    commands = ['adevice update'] + commands
+  return commands
+
+
+def remove_duplicates_maintain_order(commands):
+  """Removes duplicates while maintaining order."""
+  seen = set()
+  result = []
+  for item in commands:
+    if item not in seen:
+      seen.add(item)
+      result.append(item)
+  return result
+
+
+def remove_commands_that_starts_with(commands, cmd_to_remove):
+  """Removes commands that start with a command."""
+  result = []
+  for cmd in commands:
+    if not cmd.startswith(cmd_to_remove):
+      result.append(cmd)
+  return result
diff --git a/team_build_scripts/Android.bp b/team_build_scripts/Android.bp
deleted file mode 100644
index 1a32e94e..00000000
--- a/team_build_scripts/Android.bp
+++ /dev/null
@@ -1,30 +0,0 @@
-// Copyright (C) 2024 The Android Open Source Project
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
-python_binary_host {
-    name: "filter_teams",
-    srcs: [
-        "filter_teams.py",
-    ],
-    libs: [
-        "teams-proto-py",
-        "code-metadata-proto-py",
-        "test-spec-proto-py",
-    ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
-}
diff --git a/team_build_scripts/OWNERS b/team_build_scripts/OWNERS
deleted file mode 100644
index c0d88476..00000000
--- a/team_build_scripts/OWNERS
+++ /dev/null
@@ -1,2 +0,0 @@
-# parent owners +
-ronish@google.com
diff --git a/team_build_scripts/filter_teams.py b/team_build_scripts/filter_teams.py
deleted file mode 100644
index 53d5cf66..00000000
--- a/team_build_scripts/filter_teams.py
+++ /dev/null
@@ -1,159 +0,0 @@
-#!/usr/bin/env python3
-
-# Copyright 2024, The Android Open Source Project
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
-#
-"""
-Combines out/soong/ownership_teams with module-info.json to create a
-a new proto that only lists 'test' modules (and their teams).
-Uses heuristcis on module-info.json to decide if a module is a test.
-   i.e. tests have at least one these:
-           test_config property
-           NATIVE_TESTS class
-           tests tag
-           compatibility_suite
-
-   This implicitly covers these soong module types:
-        android_test
-        art_cc_test
-        cc_test
-        cc_test_host
-        csuite_test
-        java_test
-        java_test_host
-        python_test
-        python_test_host
-        rust_test
-        rust_test_host
-        sh_test
-        sh_test_host
-        android_robolectric_test
-        cc_benchmark
-   (not bootclasspath_fragment_test or cc_fuzz)
-
-Writes output back to out/soong/ownership_teams/all_test_specs.pb file.
-Requires: 'm all_teams' already ran and also module-info.json was created.
-          env variables ANDROID_BUILD_TOP, ANDROID_PRODUCT_OUT set.
-Also converts between identical serialized proto formats. teams -> test_spec
-"""
-# pylint: disable=import-error
-# pylint: disable=missing-function-docstring
-# pylint: disable=line-too-long
-
-import argparse
-import json
-import os
-import sys
-
-from teams import team_pb2
-from test_spec import test_spec_pb2
-
-# Parse arg and return Namespace
-def parse_args(argv) -> argparse.Namespace:
-    parser = argparse.ArgumentParser(description='Filter teams proto file to only test modules')
-    parser.add_argument(
-        '--filter_teams', action='store_true',
-        help='combine all_teams.bp with module-info for a smaller teams file filtered to tests')
-    # parser.add_argument(
-    # '--add_files',
-    # help='combines all_teams.bp with jdeps and ccdeps to write files owned by each module')
-    return parser.parse_args(argv)
-
-#
-def main(argv):
-    args = parse_args(argv)
-
-    all_modules_proto_file = "%s/out/soong/ownership/all_teams.pb" % os.environ['ANDROID_BUILD_TOP']
-    all_teams = read_team_proto_file(all_modules_proto_file)
-
-    if args.filter_teams:
-        test_modules = read_module_info("%s/module-info.json" % os.environ['ANDROID_PRODUCT_OUT'])
-        filtered_teams = filter_teams(all_teams, test_modules)
-
-        out_file = "%s/out/soong/ownership/all_test_specs.pb" % os.environ['ANDROID_BUILD_TOP']
-        with open(out_file, "wb") as f:
-            f.write(filtered_teams.SerializeToString())
-#
-def read_team_proto_file(proto_file_path) -> team_pb2.AllTeams:
-    all_teams = team_pb2.AllTeams()
-    try:
-        # TODO(rbraunstein): Try parsing as textproto if binary fails (for udc-mainline-prod)
-        with open(proto_file_path, "rb") as f:
-            all_teams.ParseFromString(f.read())
-    except IOError:
-        print(proto_file_path + ": Could not open file")
-        sys.exit(2)
-
-    return all_teams
-
-# Given a proto file that lists the team for _all_modules and a set of test_modules,
-# Return a filtered proto (as test_spec proto) that only contains modules that are tests.
-# test_modules: dictionary of module names
-def filter_teams(all_teams: team_pb2.AllTeams, test_modules: dict[str, int]):
-    filtered_teams = test_spec_pb2.TestSpec()
-
-    for team in all_teams.teams:
-        if test_modules.get(team.target_name):
-            # Only keep module if it has trendy_team_id.
-            if team.HasField('trendy_team_id'):
-                owner = test_spec_pb2.TestSpec.OwnershipMetadata()
-                owner.target_name = team.target_name
-                owner.path = team.path
-                owner.trendy_team_id = team.trendy_team_id
-                filtered_teams.ownership_metadata_list.append(owner)
-
-    return filtered_teams
-
-
-# Read module-info.json and return a dict of module names that are tests.
-def read_module_info(path) -> dict[str, int]:
-    test_modules = {}
-    with open(path, 'r', encoding="utf-8") as f:
-        for mod_name, mod_value in json.load(f).items():
-            # Skip android_test_helper_app
-            # They don't seem to have test_config and use installed: .apk, not .jar?
-            # Fixes .32 problem for CC tests too. (FuseUtilsTest)
-            if mod_value.get("test_config", []) or mod_value.get("auto_test_config", []):
-                test_modules[mod_name] = 1
-                continue
-
-            tags = mod_value.get("tags")
-            if tags and  "tests" in tags:
-                test_modules[mod_name] = 1
-                continue
-
-            clazz = mod_value.get("class", [])
-            if "NATIVE_TESTS" in clazz:
-                # Fixup names liks net_test_bta_32  back to net_test_bta
-                # Is this bad for some modules, only do for NATIVE_TESTS?
-                # mod_name = mod_value.get("module_name")
-                test_modules[mod_name] = 1
-                continue
-            # Android_robolectric_test creates an extra runner module that has this class.
-            # Technically, it isn't a test and thing it runs is the test and that thing
-            # will have a test_config and probably auto_test_config
-            # See EmergencyInfoRoboTests in module-info.json
-            if "ROBOLECTRIC" in clazz:
-                test_modules[mod_name] = 1
-                continue
-
-            if mod_value.get("compatibility_suites"):
-                test_modules[mod_name] = 1
-                continue
-
-    return test_modules
-
-
-if __name__ == "__main__":
-    main(sys.argv[1:])
```

