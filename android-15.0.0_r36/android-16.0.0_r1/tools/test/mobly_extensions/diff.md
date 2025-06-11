```diff
diff --git a/Android.bp b/Android.bp
index 9aaf7f0..dbdd8ff 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,3 +37,40 @@ python_test_host {
         "mobly_device_flags",
     ],
 }
+
+python_library_host {
+    name: "mobly_coverage_device_utils",
+    srcs: ["coverage/device_utils.py"],
+    libs: [
+        "mobly",
+    ],
+    pkg_path: "mobly",
+}
+
+python_test_host {
+    name: "mobly_coverage_device_utils_test",
+    srcs: ["coverage/device_utils_test.py"],
+    main: "coverage/device_utils_test.py",
+    libs: [
+        "mobly",
+        "mobly_coverage_device_utils",
+    ],
+}
+
+python_library_host {
+    name: "mobly_coverage_options",
+    srcs: ["coverage/coverage_options.py"],
+    libs: [
+        "mobly",
+    ],
+    pkg_path: "mobly",
+}
+
+python_library_host {
+    name: "mobly_java_coverage",
+    srcs: ["coverage/java_coverage.py"],
+    libs: [
+        "mobly",
+    ],
+    pkg_path: "mobly",
+}
diff --git a/OWNERS b/OWNERS
index 84b0bbb..3e77dd6 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@
 angli@google.com
 kolinlu@google.com
 xianyuanjia@google.com
+nkprasad@google.com
diff --git a/coverage/coverage_options.py b/coverage/coverage_options.py
new file mode 100644
index 0000000..94d184d
--- /dev/null
+++ b/coverage/coverage_options.py
@@ -0,0 +1,48 @@
+#!/usr/bin/env python3
+
+# Copyright (C) 2024 The Android Open Source Project
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
+"""Options for controlling code coverage."""
+
+from collections.abc import Sequence
+import dataclasses
+
+
+@dataclasses.dataclass
+class CoverageOptions:
+  """Options to control code coverage.
+
+  Mirrors
+  https://cs.android.com/android/platform/superproject/main/+/main:tools/tradefederation/core/src/com/android/tradefed/testtype/coverage/CoverageOptions.java
+  """
+
+  coverage: bool = False
+  # TODO(b/383557170): Handle remaining options if requested.
+  coverage_flush: bool = False
+  coverage_processes: Sequence[str] = dataclasses.field(
+      default_factory=lambda: []
+  )
+  merge_coverage: bool = False
+  reset_coverage_before_test: bool = True
+  llvm_profdata_path: str | None = None
+  profraw_filter: str = ".*\\.profraw"
+  pull_timeout: int = 20 * 60 * 1000
+  jacocoagent_path: str | None = None
+  device_coverage_paths: Sequence[str] = dataclasses.field(
+      default_factory=lambda: [
+          "/data/misc/trace",
+          "/data/local/tmp",
+      ]
+  )
diff --git a/coverage/device_utils.py b/coverage/device_utils.py
new file mode 100644
index 0000000..24d01cb
--- /dev/null
+++ b/coverage/device_utils.py
@@ -0,0 +1,76 @@
+#!/usr/bin/env python3
+
+# Copyright (C) 2024 The Android Open Source Project
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
+"""Helper utilities for coverage."""
+
+from collections.abc import Sequence
+import dataclasses
+import re
+
+from mobly.controllers import android_device
+
+
+# Sample output:
+# ```
+# USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME
+# root             1     0   10929596   4324 0                   0 S init
+# ```
+_PS_PATTERN = re.compile(
+    r"^\s*(\S+)\s+(\d+)\s+(?:\d+)\s+(?:\d+)\s+(?:\d+)\s+(?:\d+)\s+(?:\d+)\s+(?:\S+)\s+(\S+)\s*$"
+)
+_PM_PACKAGE_PREFIX = "package:"
+
+
+@dataclasses.dataclass
+class ProcessInfo:
+  """Information about a running process."""
+
+  user: str
+  name: str
+  pid: int
+
+
+def get_running_processes(
+    device: android_device.AndroidDevice,
+) -> Sequence[ProcessInfo]:
+  """Returns information about all running processes on the device."""
+  processes = []
+  raw_output = device.adb.shell("ps -e")
+  ps_lines = raw_output.decode().split("\n")
+  for line in ps_lines:
+    match = _PS_PATTERN.match(line)
+    if not match:
+      continue
+    processes.append(
+        ProcessInfo(
+            user=match.group(1), pid=int(match.group(2)), name=match.group(3)
+        )
+    )
+  return processes
+
+
+def get_all_packages(device: android_device.AndroidDevice) -> Sequence[str]:
+  """Retrieves the names of all installed packages on the device."""
+  packages = []
+  raw_output = device.adb.shell(["pm", "list", "packages", "-a"])
+  output_lines = raw_output.decode().split("\n")
+  for line in output_lines:
+    line = line.strip()
+    if not line:
+      continue
+    if line.startswith(_PM_PACKAGE_PREFIX):
+      packages.append(line[len(_PM_PACKAGE_PREFIX) :])
+  return packages
diff --git a/coverage/device_utils_test.py b/coverage/device_utils_test.py
new file mode 100644
index 0000000..e758eef
--- /dev/null
+++ b/coverage/device_utils_test.py
@@ -0,0 +1,75 @@
+#!/usr/bin/env python3
+
+# Copyright (C) 2024 The Android Open Source Project
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
+import unittest
+from unittest import mock
+
+from mobly.controllers import android_device
+
+from mobly.coverage import device_utils
+
+
+_PS_E_OUTPUT = """USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME
+root             1     0   10929596   4136 0                   0 S init
+root             2     0          0      0 0                   0 S [kthreadd]
+root             3     2          0      0 0                   0 I [rcu_gp]
+"""
+
+_LIST_PACKAGES_OUTPUT = """package:com.android.systemui.auto_generated_rro_vendor__
+package:com.google.android.retaildemo
+package:com.clozemaster.v2
+package:com.google.android.overlay.googlewebview
+"""
+
+
+def _create_mock_android_device(shell_output: str):
+  device = mock.create_autospec(
+      android_device.AndroidDevice, instance=True, spec_set=False
+  )
+  mock_adb = mock.Mock()
+  device.adb = mock_adb
+  mock_adb.shell.return_value = shell_output.encode("utf-8")
+  return device
+
+
+class DeviceUtilsTest(unittest.TestCase):
+
+  def test_get_all_packages(self):
+    device = _create_mock_android_device(_LIST_PACKAGES_OUTPUT)
+    self.assertEqual(
+        device_utils.get_all_packages(device),
+        [
+            "com.android.systemui.auto_generated_rro_vendor__",
+            "com.google.android.retaildemo",
+            "com.clozemaster.v2",
+            "com.google.android.overlay.googlewebview",
+        ],
+    )
+
+  def test_get_running_processes(self):
+    device = _create_mock_android_device(_PS_E_OUTPUT)
+    self.assertEqual(
+        device_utils.get_running_processes(device),
+        [
+            device_utils.ProcessInfo("root", "init", 1),
+            device_utils.ProcessInfo("root", "[kthreadd]", 2),
+            device_utils.ProcessInfo("root", "[rcu_gp]", 3),
+        ],
+    )
+
+
+if __name__ == "__main__":
+  unittest.main()
diff --git a/coverage/java_coverage.py b/coverage/java_coverage.py
new file mode 100644
index 0000000..8152090
--- /dev/null
+++ b/coverage/java_coverage.py
@@ -0,0 +1,99 @@
+#!/usr/bin/env python3
+
+# Copyright (C) 2024 The Android Open Source Project
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
+import glob
+import os
+import shutil
+import subprocess
+import tarfile
+import tempfile
+
+from mobly.controllers import android_device
+from mobly.coverage import coverage_options
+from mobly.coverage import device_utils
+
+
+_COVERAGE_DIRECTORY = "/data/misc/trace"
+_FIND_COVERAGE_FILES = f"find {_COVERAGE_DIRECTORY} -name '*.ec'"
+_COMPRESS_COVERAGE_FILES = (
+    f"{_FIND_COVERAGE_FILES} | tar -czf - -T - 2>/dev/null"
+)
+
+
+def collect_coverage(
+    device: android_device.AndroidDevice,
+    options: coverage_options.CoverageOptions,
+    output_path: str,
+) -> None:
+  """Collects Java code coverage from the device.
+
+  Args:
+    device: The device to collect coverage from.
+    options: The coverage options to use.
+    output_path: The path to save the coverage data to.
+  """
+  try:
+    _collect_coverage(device, options, output_path)
+  finally:
+    _clean_up_device_coverage_files(device)
+
+
+def _collect_coverage(
+    device: android_device.AndroidDevice,
+    options: coverage_options.CoverageOptions,
+    output_path: str,
+) -> None:
+  """Collects Java code coverage for a test."""
+  if not options.coverage:
+    return
+  # TODO(b/383557170): Handle merged merged and flushed coverage if requested.
+  device.adb.root()
+  with tempfile.TemporaryDirectory() as temp_dir:
+    coverage_tar_gz = os.path.join(temp_dir, "java_coverage.tar.gz")
+    with open(coverage_tar_gz, "wb") as f:
+      command = f'adb -s {device.serial} shell "{_COMPRESS_COVERAGE_FILES}"'
+      subprocess.run(command, shell=True, stdout=f, timeout=1200, check=True)
+    coverage_dir = os.path.join(temp_dir, "java_coverage")
+    tarfile.open(coverage_tar_gz, "r:gz").extractall(coverage_dir)
+    for filename in glob.glob(f"{coverage_dir}/**/*.ec", recursive=True):
+      if not filename.endswith(".ec"):
+        continue
+      _save_coverage_measurement(filename, output_path)
+
+
+def _save_coverage_measurement(coverage_file: str, output_path: str) -> None:
+  """Saves Java coverage file data."""
+  shutil.move(coverage_file, output_path)
+  # TODO(b/383557170): Handle merged coverage if requested.
+
+
+def _clean_up_device_coverage_files(
+    device: android_device.AndroidDevice,
+) -> None:
+  """Cleans up coverage files on the device."""
+  processes = device_utils.get_running_processes(device)
+  active_pids = [process.pid for process in processes]
+  coverage_output = device.adb.shell(_FIND_COVERAGE_FILES).decode()
+  for coverage_output_line in coverage_output.split("\n"):
+    line = coverage_output_line.strip()
+    if not line:
+      continue
+    if not line.endswith(".mm.ec"):
+      device.adb.shell(f"rm {line}", shell=True)
+      continue
+    pid = int(line[line.index("-") + 1 : line.index(".")])
+    if pid not in active_pids:
+      device.adb.shell(f"rm {line}", shell=True)
diff --git a/tools/results_uploader/CHANGELOG.md b/tools/results_uploader/CHANGELOG.md
index c68243f..562e6a0 100644
--- a/tools/results_uploader/CHANGELOG.md
+++ b/tools/results_uploader/CHANGELOG.md
@@ -1,5 +1,15 @@
 # Mobly Results Uploader release history
 
+## 0.7.2 (2024-12-13)
+
+### New
+* Enable the option to directly upload results already in the Resultstore format,
+  skipping the conversion step.
+
+### Fixes
+* Stream verbose debug logs to a dedicated file.
+
+
 ## 0.7.1 (2024-12-06)
 
 ### Fixes
diff --git a/tools/results_uploader/pyproject.toml b/tools/results_uploader/pyproject.toml
index 6dcb6bb..15c2d47 100644
--- a/tools/results_uploader/pyproject.toml
+++ b/tools/results_uploader/pyproject.toml
@@ -4,7 +4,7 @@ build-backend = "setuptools.build_meta"
 
 [project]
 name = "results_uploader"
-version = "0.7.1"
+version = "0.7.2"
 description = "Tool for uploading Mobly test results to Resultstore web UI."
 readme = "README.md"
 requires-python = ">=3.11"
diff --git a/tools/results_uploader/src/results_uploader.py b/tools/results_uploader/src/results_uploader.py
index 788b555..eff6e85 100644
--- a/tools/results_uploader/src/results_uploader.py
+++ b/tools/results_uploader/src/results_uploader.py
@@ -44,8 +44,6 @@ with warnings.catch_warnings():
     warnings.simplefilter('ignore')
     from google.cloud.storage import transfer_manager
 
-logging.getLogger('googleapiclient').setLevel(logging.WARNING)
-logging.getLogger('google.auth').setLevel(logging.ERROR)
 
 _RESULTSTORE_SERVICE_NAME = 'resultstore'
 _API_VERSION = 'v2'
@@ -83,6 +81,29 @@ class _TestResultInfo:
     target_id: str | None = None
 
 
+def _setup_logging(verbose: bool) -> None:
+    """Configures the logging for this module."""
+    debug_log_path = tempfile.mkstemp('_upload_log.txt')[1]
+    file_handler = logging.FileHandler(debug_log_path)
+    file_handler.setLevel(logging.DEBUG)
+    file_handler.setFormatter(logging.Formatter(
+        '%(asctime)s %(levelname)s [%(module)s.%(funcName)s] %(message)s'
+    ))
+    stream_handler = logging.StreamHandler()
+    stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
+    stream_handler.setFormatter(
+        logging.Formatter('%(levelname)s: %(message)s'))
+    logging.basicConfig(
+        level=logging.DEBUG,
+        handlers=(file_handler, stream_handler)
+    )
+
+    logging.getLogger('googleapiclient').setLevel(logging.WARNING)
+    logging.getLogger('google.auth').setLevel(logging.ERROR)
+    logging.info('Debug logs are saved to %s', debug_log_path)
+    print('-' * 50)
+
+
 def _gcloud_login_and_set_project() -> None:
     """Get gcloud application default creds and set the desired GCP project."""
     logging.info('No credentials found. Performing initial setup.')
@@ -98,7 +119,7 @@ def _gcloud_login_and_set_project() -> None:
         logging.exception(
             'Failed to run `gcloud` commands. Please install the `gcloud` CLI!')
     logging.info('Initial setup complete!')
-    print('-' * 20)
+    print('-' * 50)
 
 
 def _get_project_number(project_id: str) -> str:
@@ -398,7 +419,7 @@ def main():
     parser.add_argument(
         '--gcs_dir',
         help=(
-            'Directory to save test artifacts in GCS. If unspecified or empty,'
+            'Directory to save test artifacts in GCS. If unspecified or empty, '
             'use the current timestamp as the GCS directory name.'
         ),
     )
@@ -420,11 +441,17 @@ def main():
         help='Label to attach to the uploaded result. Can be repeated for '
              'multiple labels.'
     )
-    args = parser.parse_args()
-    logging.basicConfig(
-        format='%(levelname)s: %(message)s',
-        level=(logging.DEBUG if args.verbose else logging.INFO)
+    parser.add_argument(
+        '--no_convert_result',
+        action='store_true',
+        help=(
+            'Upload the files as is, without first converting Mobly results to '
+            'Resultstore\'s format. The source directory must contain at least '
+            'a `test.xml` file, and an `undeclared_outputs` zip or '
+            'subdirectory.')
     )
+    args = parser.parse_args()
+    _setup_logging(args.verbose)
     try:
         _, project_id = google.auth.default()
     except google.auth.exceptions.DefaultCredentialsError:
@@ -446,21 +473,32 @@ def main():
         else args.gcs_dir
     )
     mobly_dir = pathlib.Path(args.mobly_dir).absolute().expanduser()
-    # Generate and upload test.xml and test.log
-    with tempfile.TemporaryDirectory() as tmp:
-        converted_dir = pathlib.Path(tmp).joinpath(gcs_base_dir)
-        converted_dir.mkdir(parents=True)
-        test_result_info = _convert_results(mobly_dir, converted_dir)
+
+    if args.no_convert_result:
+        # Determine the final status based on the test.xml
+        test_xml = ElementTree.parse(mobly_dir.joinpath(_TEST_XML))
+        test_result_info = _get_test_result_info_from_test_xml(test_xml)
+        # Upload the contents of mobly_dir directly
         gcs_files = _upload_dir_to_gcs(
-            converted_dir, gcs_bucket, gcs_base_dir.as_posix(),
+            mobly_dir, gcs_bucket, gcs_base_dir.as_posix(),
+            args.gcs_upload_timeout
+        )
+    else:
+        # Generate and upload test.xml and test.log
+        with tempfile.TemporaryDirectory() as tmp:
+            converted_dir = pathlib.Path(tmp).joinpath(gcs_base_dir)
+            converted_dir.mkdir(parents=True)
+            test_result_info = _convert_results(mobly_dir, converted_dir)
+            gcs_files = _upload_dir_to_gcs(
+                converted_dir, gcs_bucket, gcs_base_dir.as_posix(),
+                args.gcs_upload_timeout
+            )
+        # Upload raw Mobly logs to undeclared_outputs/ subdirectory
+        gcs_files += _upload_dir_to_gcs(
+            mobly_dir, gcs_bucket,
+            gcs_base_dir.joinpath(_UNDECLARED_OUTPUTS).as_posix(),
             args.gcs_upload_timeout
         )
-    # Upload raw Mobly logs to undeclared_outputs/ subdirectory
-    gcs_files += _upload_dir_to_gcs(
-        mobly_dir, gcs_bucket,
-        gcs_base_dir.joinpath(_UNDECLARED_OUTPUTS).as_posix(),
-        args.gcs_upload_timeout
-    )
     _upload_to_resultstore(
         api_key,
         gcs_bucket,
diff --git a/tools/results_uploader/src/resultstore_client.py b/tools/results_uploader/src/resultstore_client.py
index d92b7da..67f47b1 100644
--- a/tools/results_uploader/src/resultstore_client.py
+++ b/tools/results_uploader/src/resultstore_client.py
@@ -396,7 +396,7 @@ class ResultstoreClient:
         )
         res = request.execute(http=self._http)
         logging.debug('invocations.finalize: %s', res)
-        print('-' * 20)
+        print('-' * 50)
         # Make the URL show test cases regardless of status by default.
         show_statuses = (
             'showStatuses='
```

