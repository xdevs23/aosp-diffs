```diff
diff --git a/scripts/local_mobly_runner.py b/scripts/local_mobly_runner.py
index 6681962..bb2808f 100755
--- a/scripts/local_mobly_runner.py
+++ b/scripts/local_mobly_runner.py
@@ -14,22 +14,25 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""Script for running Android Gerrit-based Mobly tests locally.
+"""Script for running git-based Mobly tests locally.
 
 Example:
-    - Run a test module.
+    - Run an Android platform test module.
     local_mobly_runner.py -m my_test_module
 
-    - Run a test module. Build the module and install test APKs before running
-      the test.
+    - Run an Android platform test module. Build the module and install test
+      APKs before running the test.
     local_mobly_runner.py -m my_test_module -b -i
 
-    - Run a test module with specific Android devices.
+    - Run an Android platform test module with specific Android devices.
     local_mobly_runner.py -m my_test_module -s DEV00001,DEV00002
 
-    - Run a list of zipped Mobly packages (built from `python_test_host`)
+    - Run a list of zipped executable Mobly packages
     local_mobly_runner.py -p test_pkg1,test_pkg2,test_pkg3
 
+    - Install and run a test binary from a Python wheel
+    local_mobly_runner.py -w my-test-0.1-py3-none-any.whl --bin test_suite_a
+
 Please run `local_mobly_runner.py -h` for a full list of options.
 """
 
@@ -67,11 +70,24 @@ def _parse_args() -> argparse.Namespace:
         description=__doc__)
     group1 = parser.add_mutually_exclusive_group(required=True)
     group1.add_argument(
-        '-m', '--module', help='The Android build module of the test to run.'
+        '-m', '--module',
+        help='The Android platform build module of the test to run.'
     )
     group1.add_argument(
         '-p', '--packages',
-        help='A comma-delimited list of test packages to run.'
+        help=(
+            'A comma-delimited list of test packages to run. The packages '
+            'should be directly executable by the Python interpreter. If '
+            'the package includes a requirements.txt file, deps will '
+            'automatically be installed.'
+        )
+    )
+    group1.add_argument(
+        '-w', '--wheel',
+        help=(
+            'A Python wheel (.whl) containing one or more Mobly test scripts. '
+            'Does not support the --novenv option.'
+        )
     )
     group1.add_argument(
         '-t',
@@ -81,19 +97,7 @@ def _parse_args() -> argparse.Namespace:
             'the --novenv option.'
         ),
     )
-    parser.add_argument(
-        '--tests',
-        nargs='+',
-        type=str,
-        metavar='TEST_CLASS[.TEST_CASE]',
-        help=(
-            'A list of test classes and optional tests to execute within the '
-            'package or file. E.g. `--tests TestClassA TestClassB.test_b` '
-            'would run all of test class TestClassA, but only test_b in '
-            'TestClassB. This option cannot be used if multiple packages/test '
-            'paths are specified.'
-        ),
-    )
+
     parser.add_argument(
         '-b',
         '--build',
@@ -106,7 +110,7 @@ def _parse_args() -> argparse.Namespace:
         action='store_true',
         help=(
             'Install all APKs associated with the module to all specified'
-            ' devices. Requires the -m or -p options.'
+            ' devices. Does not support the -t option.'
         ),
     )
     parser.add_argument(
@@ -128,6 +132,27 @@ def _parse_args() -> argparse.Namespace:
                              'selected by default.')
     parser.add_argument('-lp', '--log_path',
                         help='Specify a path to store logs.')
+
+    parser.add_argument(
+        '--tests',
+        nargs='+',
+        type=str,
+        metavar='TEST_CLASS[.TEST_CASE]',
+        help=(
+            'A list of test classes and optional tests to execute within the '
+            'package or file. E.g. `--tests TestClassA TestClassB.test_b` '
+            'would run all of test class TestClassA, but only test_b in '
+            'TestClassB. This option cannot be used if multiple packages/test '
+            'paths are specified.'
+        ),
+    )
+    parser.add_argument(
+        '--bin',
+        help=(
+            'Name of the binary to run in the installed wheel. Must be '
+            'specified alongside the --wheel option.'
+        ),
+    )
     parser.add_argument(
         '--novenv',
         action='store_true',
@@ -139,8 +164,16 @@ def _parse_args() -> argparse.Namespace:
     args = parser.parse_args()
     if args.build and not args.module:
         parser.error('Option --build requires --module to be specified.')
-    if args.install_apks and not (args.module or args.packages):
-        parser.error('Option --install_apks requires --module or --packages.')
+    if args.wheel:
+        if args.novenv:
+            parser.error('Option --novenv cannot be used with --wheel.')
+        if not args.bin:
+            parser.error('Option --wheel requires --bin to be specified.')
+    if args.bin:
+        if not args.wheel:
+            parser.error('Option --bin requires --wheel to be specified.')
+    if args.install_apks and args.test_paths:
+        parser.error('Option --install_apks cannot be used with --test_paths.')
     if args.tests is not None:
         multiple_packages = (args.packages is not None
                              and len(args.packages.split(',')) > 1)
@@ -209,10 +242,10 @@ def _get_module_artifacts(module: str) -> List[str]:
     return outmod_paths
 
 
-def _resolve_test_resources(
+def _extract_test_resources(
         args: argparse.Namespace,
 ) -> Tuple[List[str], List[str], List[str]]:
-    """Resolve test resources from the given test module or package.
+    """Extract test resources from the given test module or package.
 
     Args:
       args: Parsed command-line args.
@@ -235,39 +268,45 @@ def _resolve_test_resources(
                 requirements_files.append(path)
             if path.endswith('.apk'):
                 test_apks.append(path)
-    elif args.packages:
+    elif args.packages or args.wheel:
+        packages = args.packages.split(',') if args.packages else [args.wheel]
         unzip_root = tempfile.mkdtemp(prefix='mobly_unzip_')
         _tempdirs.append(unzip_root)
-        for package in args.packages.split(','):
+        for package in packages:
             mobly_bins.append(os.path.abspath(package))
             unzip_dir = os.path.join(unzip_root, os.path.basename(package))
             print(f'Unzipping test package {package} to {unzip_dir}.')
             os.makedirs(unzip_dir)
             with zipfile.ZipFile(package) as zf:
                 zf.extractall(unzip_dir)
-            for path in os.listdir(unzip_dir):
-                path = os.path.join(unzip_dir, path)
-                if path.endswith('requirements.txt'):
-                    requirements_files.append(path)
-                if path.endswith('.apk'):
-                    test_apks.append(path)
+            for root, _, files in os.walk(unzip_dir):
+                for file_name in files:
+                    path = os.path.join(root, file_name)
+                    if path.endswith('requirements.txt'):
+                        requirements_files.append(path)
+                    if path.endswith('.apk'):
+                        test_apks.append(path)
     else:
         print('No tests specified. Aborting.')
         exit(1)
     return mobly_bins, requirements_files, test_apks
 
 
-def _setup_virtualenv(requirements_files: List[str]) -> str:
+def _setup_virtualenv(
+        requirements_files: List[str],
+        wheel_file: Optional[str]
+) -> str:
     """Creates a virtualenv and install dependencies into it.
 
     Args:
       requirements_files: List of paths of requirements.txt files.
+      wheel_file: A Mobly test package as an installable Python wheel.
 
     Returns:
       Path to the virtualenv's Python interpreter.
     """
     venv_dir = tempfile.mkdtemp(prefix='venv_')
-    _padded_print(f'Creating virtualenv at {venv_dir}.')
+    _padded_print(f'Setting up virtualenv at {venv_dir}.')
     subprocess.check_call([sys.executable, '-m', 'venv', venv_dir])
     _tempdirs.append(venv_dir)
     if platform.system() == 'Windows':
@@ -277,10 +316,17 @@ def _setup_virtualenv(requirements_files: List[str]) -> str:
 
     # Install requirements
     for requirements_file in requirements_files:
-        print(f'Installing dependencies from {requirements_file}.')
+        print(f'Installing dependencies from {requirements_file}.\n')
         subprocess.check_call(
             [venv_executable, '-m', 'pip', 'install', '-r', requirements_file]
         )
+
+    # Install wheel
+    if wheel_file is not None:
+        print(f'Installing test wheel package {wheel_file}.\n')
+        subprocess.check_call(
+            [venv_executable, '-m', 'pip', 'install', wheel_file]
+        )
     return venv_executable
 
 
@@ -408,8 +454,8 @@ def main() -> None:
 
     serials = args.serials.split(',') if args.serials else None
 
-    # Resolve test resources
-    mobly_bins, requirements_files, test_apks = _resolve_test_resources(args)
+    # Extract test resources
+    mobly_bins, requirements_files, test_apks = _extract_test_resources(args)
 
     # Install test APKs, if necessary
     if args.install_apks:
@@ -421,7 +467,13 @@ def main() -> None:
         if args.test_paths is not None:
             python_executable = sys.executable
     else:
-        python_executable = _setup_virtualenv(requirements_files)
+        python_executable = _setup_virtualenv(requirements_files, args.wheel)
+
+    if args.wheel:
+        mobly_bins = [
+            os.path.join(os.path.dirname(python_executable), args.bin)
+        ]
+        python_executable = None
 
     # Generate the Mobly config, if necessary
     config = args.config or _generate_mobly_config(serials)
diff --git a/tools/device_flags.py b/tools/device_flags.py
index 22ba87d..226fd95 100644
--- a/tools/device_flags.py
+++ b/tools/device_flags.py
@@ -21,6 +21,7 @@ import tempfile
 from typing import Any
 
 from mobly.controllers import android_device
+from mobly.controllers.android_device_lib import adb
 from protos import aconfig_pb2
 
 _ACONFIG_PARTITIONS = ('product', 'system', 'system_ext', 'vendor')
@@ -120,7 +121,14 @@ class DeviceFlags:
                     '/', partition, 'etc', _ACONFIG_PB_FILE)
                 host_path = os.path.join(
                     tmp_dir, f'{partition}_{_ACONFIG_PB_FILE}')
-                self._ad.adb.pull([device_path, host_path])
+                try:
+                    self._ad.adb.pull([device_path, host_path])
+                except adb.AdbError as e:
+                    self._ad.log.warning(
+                        'Failed to pull aconfig file %s from device: %s',
+                        device_path, e
+                    )
+                    continue
                 with open(host_path, 'rb') as f:
                     parsed_flags = aconfig_pb2.parsed_flags.FromString(f.read())
                 for flag in parsed_flags.parsed_flag:
diff --git a/tools/results_uploader/CHANGELOG.md b/tools/results_uploader/CHANGELOG.md
index a48a3ec..c584339 100644
--- a/tools/results_uploader/CHANGELOG.md
+++ b/tools/results_uploader/CHANGELOG.md
@@ -1,5 +1,50 @@
 # Mobly Results Uploader release history
 
+## 0.6.1 (2024-08-21)
+
+### Fixes
+* The Resultstore service now requires API keys for its Upload API. This must
+  be provided by the client.
+  * Automatically fetch and use the `resultstore` API key from the user's Google
+    Cloud project, if it exists.
+  * Otherwise, the tool will show an error message for the missing key.
+
+
+## 0.6 (2024-07-19)
+
+### New
+* Display newly uploaded results in the BTX invocation search page
+  (https://btx.cloud.google.com/invocations).
+* Support tagging uploaded results with `--label`.
+  * Labels will be visible in the invocation search page.
+  * Filters can be applied in the search page (`label:...`) to search
+    for results with matching labels.
+* Support specifying multilevel paths in `--gcs_dir`.
+* Remove support for empty string `--gcs_dir`. Uploads to the root directory
+  of a GCS bucket are no longer allowed.
+* Add the uploader tool version to the result metadata.
+
+### Fixes
+* Mobly log files are no longer locally copied to a second temp location prior
+  to upload.
+* Remove manual GCS upload fallback (introduced in v0.3).
+
+
+## 0.5.1 (2024-06-28)
+
+### Fixes
+* Extend the default timeout for GCS uploads and support custom timeout values.
+* Enable automatic retry of GCS uploads following connection errors.
+
+
+## 0.5 (2024-06-25)
+
+### New
+* Use `pathlib` for all file operations.
+  * Support specifying relative paths.
+  * Support specifying paths with backslash separators in Windows.
+
+
 ## 0.4 (2024-05-16)
 
 ### New
@@ -35,7 +80,6 @@
 ## 0.1 (2024-01-05)
 
 ### New
-
 * Add the `results_uploader` tool for uploading Mobly test results to the
   Resultstore service.
   * Uploads local test logs to a user-provided Google Cloud Storage location.
diff --git a/tools/results_uploader/README.md b/tools/results_uploader/README.md
index 4e2c3f1..bba1f51 100644
--- a/tools/results_uploader/README.md
+++ b/tools/results_uploader/README.md
@@ -73,3 +73,7 @@ Google Cloud Storage bucket:
 4. If successful, at the end of the upload process you will get a link beginning
    with http://btx.cloud.google.com. Simply share this link to others who
    wish to view your test results.
+
+## Additional reference
+
+To see a list of supported options, please consult `results_uploader --help`.
diff --git a/tools/results_uploader/pyproject.toml b/tools/results_uploader/pyproject.toml
index 3f5bbff..50e2a02 100644
--- a/tools/results_uploader/pyproject.toml
+++ b/tools/results_uploader/pyproject.toml
@@ -4,7 +4,7 @@ build-backend = "setuptools.build_meta"
 
 [project]
 name = "results_uploader"
-version = "0.4"
+version = "0.6.1"
 description = "Tool for uploading Mobly test results to Resultstore web UI."
 readme = "README.md"
 requires-python = ">=3.11"
@@ -13,6 +13,8 @@ dependencies = [
   "google-auth",
   "google-auth-httplib2",
   "google-cloud",
+  "google-cloud-api-keys",
+  "google-cloud-resource-manager",
   "google-cloud-storage",
   "httplib2",
   "mobly",
diff --git a/tools/results_uploader/src/data/mime.types b/tools/results_uploader/src/data/mime.types
index 7a29e33..fd027d8 100644
--- a/tools/results_uploader/src/data/mime.types
+++ b/tools/results_uploader/src/data/mime.types
@@ -1,3 +1,3 @@
 # Configure the desired MIME types for Mobly log files in GCS
-text/plain      info debug
+text/plain      info debug log
 text/x-yaml     yaml yml
diff --git a/tools/results_uploader/src/results_uploader.py b/tools/results_uploader/src/results_uploader.py
index 6a949c9..92a8376 100644
--- a/tools/results_uploader/src/results_uploader.py
+++ b/tools/results_uploader/src/results_uploader.py
@@ -30,6 +30,8 @@ import warnings
 from xml.etree import ElementTree
 
 import google.auth
+from google.cloud import api_keys_v2
+from google.cloud import resourcemanager_v3
 from google.cloud import storage
 from googleapiclient import discovery
 
@@ -44,12 +46,14 @@ logging.getLogger('googleapiclient').setLevel(logging.WARNING)
 
 _RESULTSTORE_SERVICE_NAME = 'resultstore'
 _API_VERSION = 'v2'
+_API_KEY_DISPLAY_NAME = 'resultstore'
 _DISCOVERY_SERVICE_URL = (
     'https://{api}.googleapis.com/$discovery/rest?version={apiVersion}'
 )
+
 _TEST_XML = 'test.xml'
-_TEST_LOGS = 'test.log'
-_UNDECLARED_OUTPUTS = 'undeclared_outputs/'
+_TEST_LOG = 'test.log'
+_UNDECLARED_OUTPUTS = 'undeclared_outputs'
 
 _TEST_SUMMARY_YAML = 'test_summary.yaml'
 _TEST_LOG_INFO = 'test_log.INFO'
@@ -58,14 +62,7 @@ _SUITE_NAME = 'suite_name'
 _RUN_IDENTIFIER = 'run_identifier'
 
 _GCS_BASE_LINK = 'https://console.cloud.google.com/storage/browser'
-
-_GCS_UPLOAD_INSTRUCTIONS = (
-    '\nAutomatic upload to GCS failed.\n'
-    'Please follow the steps below to manually upload files:\n'
-    f'\t1. Follow the link {_GCS_BASE_LINK}/%s.\n'
-    '\t2. Click "UPLOAD FOLDER".\n'
-    '\t3. Select the directory "%s" to upload.'
-)
+_GCS_DEFAULT_TIMEOUT_SECS = 300
 
 _ResultstoreTreeTags = mobly_result_converter.ResultstoreTreeTags
 _ResultstoreTreeAttributes = mobly_result_converter.ResultstoreTreeAttributes
@@ -85,7 +82,7 @@ class _TestResultInfo:
 
 def _convert_results(
         mobly_dir: pathlib.Path, dest_dir: pathlib.Path) -> _TestResultInfo:
-    """Converts Mobly test results into Resultstore artifacts."""
+    """Converts Mobly test results into Resultstore test.xml and test.log."""
     test_result_info = _TestResultInfo()
     logging.info('Converting raw Mobly logs into Resultstore artifacts...')
     # Generate the test.xml
@@ -103,14 +100,8 @@ def _convert_results(
     # Copy test_log.INFO to test.log
     test_log_info = mobly_dir.joinpath(_TEST_LOG_INFO)
     if test_log_info.is_file():
-        shutil.copyfile(test_log_info, dest_dir.joinpath(_TEST_LOGS))
+        shutil.copyfile(test_log_info, dest_dir.joinpath(_TEST_LOG))
 
-    # Copy directory to undeclared_outputs/
-    shutil.copytree(
-        mobly_dir,
-        dest_dir.joinpath(_UNDECLARED_OUTPUTS),
-        dirs_exist_ok=True,
-    )
     return test_result_info
 
 
@@ -184,7 +175,7 @@ def _get_test_result_info_from_test_xml(
 
 
 def _upload_dir_to_gcs(
-        src_dir: pathlib.Path, gcs_bucket: str, gcs_dir: str
+        src_dir: pathlib.Path, gcs_bucket: str, gcs_dir: str, timeout: int
 ) -> list[str]:
     """Uploads the given directory to a GCS bucket."""
     # Set correct MIME types for certain text-format files.
@@ -224,58 +215,66 @@ def _upload_dir_to_gcs(
         file_paths,
         source_directory=str(src_dir),
         blob_name_prefix=blob_name_prefix,
+        skip_if_exists=True,
         worker_type=worker_type,
+        upload_kwargs={'timeout': timeout},
     )
 
     success_paths = []
-    for file_name, result in zip(file_paths, results):
+    for file_path, result in zip(file_paths, results):
         if isinstance(result, Exception):
-            logging.warning('Failed to upload %s. Error: %s', file_name, result)
+            logging.warning('Failed to upload %s. Error: %s', file_path, result)
         else:
-            logging.debug('Uploaded %s.', file_name)
-            success_paths.append(file_name)
+            logging.debug('Uploaded %s.', file_path)
+            success_paths.append(file_path)
+
+    return [f'{gcs_dir}/{path}' for path in success_paths]
 
-    # If all files fail to upload, something wrong happened with the GCS client.
-    # Prompt the user to manually upload the files instead.
-    if file_paths and not success_paths:
-        _prompt_user_upload(src_dir, gcs_bucket)
-        success_paths = file_paths
 
-    return success_paths
+def _get_project_number(project_id: str) -> str:
+    """Get the project number associated with a GCP project ID."""
+    client = resourcemanager_v3.ProjectsClient()
+    response = client.get_project(name=f'projects/{project_id}')
+    return response.name.split('/', 1)[1]
 
 
-def _prompt_user_upload(src_dir: pathlib.Path, gcs_bucket: str) -> None:
-    """Prompts the user to manually upload files to GCS."""
-    print(_GCS_UPLOAD_INSTRUCTIONS % (gcs_bucket, src_dir))
-    while True:
-        resp = input(
-            'Once you see the message "# files successfully uploaded", '
-            'enter "Y" or "yes" to continue:')
-        if resp.lower() in ('y', 'yes'):
-            break
+def _retrieve_api_key(project_id: str) -> str | None:
+    """Downloads the Resultstore API key for the given Google Cloud project."""
+    project_number = _get_project_number(project_id)
+    client = api_keys_v2.ApiKeysClient()
+    keys = client.list_keys(
+        parent=f'projects/{project_number}/locations/global'
+    ).keys
+    for key in keys:
+        if key.display_name == _API_KEY_DISPLAY_NAME:
+            return client.get_key_string(name=key.name).key_string
+    return None
 
 
 def _upload_to_resultstore(
+        api_key: str,
         gcs_bucket: str,
-        gcs_dir: str,
+        gcs_base_dir: str,
         file_paths: list[str],
         status: _Status,
         target_id: str | None,
+        labels: list[str],
 ) -> None:
     """Uploads test results to Resultstore."""
     logging.info('Generating Resultstore link...')
+    creds, project_id = google.auth.default()
     service = discovery.build(
         _RESULTSTORE_SERVICE_NAME,
         _API_VERSION,
         discoveryServiceUrl=_DISCOVERY_SERVICE_URL,
+        developerKey=api_key,
     )
-    creds, project_id = google.auth.default()
     client = resultstore_client.ResultstoreClient(service, creds, project_id)
-    client.create_invocation()
+    client.create_invocation(labels)
     client.create_default_configuration()
     client.create_target(target_id)
     client.create_configured_target()
-    client.create_action(f'gs://{gcs_bucket}/{gcs_dir}', file_paths)
+    client.create_action(gcs_bucket, gcs_base_dir, file_paths)
     client.set_status(status)
     client.merge_configured_target()
     client.finalize_configured_target()
@@ -302,41 +301,72 @@ def main():
     parser.add_argument(
         '--gcs_dir',
         help=(
-            'Directory to save test artifacts in GCS. Specify empty string to '
-            'store the files in the bucket root. If unspecified, use the '
-            'current timestamp as the GCS directory name.'
+            'Directory to save test artifacts in GCS. If unspecified or empty,'
+            'use the current timestamp as the GCS directory name.'
         ),
     )
+    parser.add_argument(
+        '--gcs_upload_timeout',
+        type=int,
+        default=_GCS_DEFAULT_TIMEOUT_SECS,
+        help=(
+            'Timeout (in seconds) to upload each file to GCS. '
+            f'Default: {_GCS_DEFAULT_TIMEOUT_SECS} seconds.'),
+    )
     parser.add_argument(
         '--test_title',
         help='Custom test title to display in the result UI.'
     )
-
+    parser.add_argument(
+        '--label',
+        action='append',
+        help='Label to attach to the uploaded result. Can be repeated for '
+             'multiple labels.'
+    )
     args = parser.parse_args()
     logging.basicConfig(
         format='%(levelname)s: %(message)s',
         level=(logging.DEBUG if args.verbose else logging.INFO)
     )
     _, project_id = google.auth.default()
+    api_key = _retrieve_api_key(project_id)
+    if api_key is None:
+        logging.error(
+            'No API key with name [%s] found for project [%s]. Contact the '
+            'project owner to create the required key.',
+            _API_KEY_DISPLAY_NAME, project_id
+        )
+        return
     gcs_bucket = project_id if args.gcs_bucket is None else args.gcs_bucket
-    gcs_dir = (
+    gcs_base_dir = pathlib.PurePath(
         datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
-        if args.gcs_dir is None
+        if not args.gcs_dir
         else args.gcs_dir
     )
+    mobly_dir = pathlib.Path(args.mobly_dir).absolute().expanduser()
+    # Generate and upload test.xml and test.log
     with tempfile.TemporaryDirectory() as tmp:
-        converted_dir = pathlib.Path(tmp).joinpath(gcs_dir)
-        converted_dir.mkdir()
-        mobly_dir = pathlib.Path(args.mobly_dir).absolute().expanduser()
+        converted_dir = pathlib.Path(tmp).joinpath(gcs_base_dir)
+        converted_dir.mkdir(parents=True)
         test_result_info = _convert_results(mobly_dir, converted_dir)
         gcs_files = _upload_dir_to_gcs(
-            converted_dir, gcs_bucket, gcs_dir)
+            converted_dir, gcs_bucket, gcs_base_dir.as_posix(),
+            args.gcs_upload_timeout
+        )
+    # Upload raw Mobly logs to undeclared_outputs/ subdirectory
+    gcs_files += _upload_dir_to_gcs(
+        mobly_dir, gcs_bucket,
+        gcs_base_dir.joinpath(_UNDECLARED_OUTPUTS).as_posix(),
+        args.gcs_upload_timeout
+    )
     _upload_to_resultstore(
+        api_key,
         gcs_bucket,
-        gcs_dir,
+        gcs_base_dir.as_posix(),
         gcs_files,
         test_result_info.status,
         args.test_title or test_result_info.target_id,
+        args.label
     )
 
 
diff --git a/tools/results_uploader/src/resultstore_client.py b/tools/results_uploader/src/resultstore_client.py
index 2fd2f30..b5fcd42 100644
--- a/tools/results_uploader/src/resultstore_client.py
+++ b/tools/results_uploader/src/resultstore_client.py
@@ -18,8 +18,9 @@
 
 import datetime
 import enum
+import importlib.metadata
 import logging
-import posixpath
+import pathlib
 import urllib.parse
 import uuid
 
@@ -31,6 +32,8 @@ import httplib2
 _DEFAULT_CONFIGURATION = 'default'
 _RESULTSTORE_BASE_LINK = 'https://btx.cloud.google.com'
 
+_PACKAGE_NAME = 'results_uploader'
+
 
 class Status(enum.Enum):
     """Aggregate status of the Resultstore invocation and target."""
@@ -107,9 +110,13 @@ class ResultstoreClient:
         """Sets the overall test run status."""
         self._status = status
 
-    def create_invocation(self) -> str:
+    def create_invocation(self, labels: list[str]) -> str:
         """Creates an invocation.
 
+        Args:
+            labels: A list of labels to attach to the invocation, as
+              `invocation.invocationAttributes.labels`.
+
         Returns:
           The invocation ID.
         """
@@ -122,8 +129,18 @@ class ResultstoreClient:
             return None
         invocation = {
             'timing': {
-                'startTime': datetime.datetime.utcnow().isoformat() + 'Z'},
-            'invocationAttributes': {'projectId': self._project_id},
+                'startTime': datetime.datetime.utcnow().isoformat() + 'Z'
+            },
+            'invocationAttributes': {
+                'projectId': self._project_id,
+                'labels': labels,
+            },
+            'properties': [
+                {
+                    'key': _PACKAGE_NAME,
+                    'value': importlib.metadata.version(_PACKAGE_NAME)
+                }
+            ]
         }
         self._request_id = str(uuid.uuid4())
         self._invocation_id = str(uuid.uuid4())
@@ -184,6 +201,7 @@ class ResultstoreClient:
                 'targetId': self._target_id,
             },
             'targetAttributes': {'type': 'TEST', 'language': 'PY'},
+            'visible': True,
         }
         request = (
             self._service.invocations()
@@ -223,22 +241,28 @@ class ResultstoreClient:
         res = request.execute(http=self._http)
         logging.debug('invocations.targets.configuredTargets.create: %s', res)
 
-    def create_action(self, gcs_path: str, artifacts: list[str]) -> str:
+    def create_action(
+            self, gcs_bucket: str, gcs_base_dir: str, artifacts: list[str]
+    ) -> str:
         """Creates an action.
 
         Args:
-          gcs_path: The directory in GCS where artifacts are stored.
-          artifacts: List of paths (relative to gcs_path) to the test artifacts.
+          gcs_bucket: The bucket in GCS where artifacts are stored.
+          gcs_base_dir: Base directory of the artifacts in the GCS bucket.
+          artifacts: List of paths (relative to gcs_bucket) to the test
+            artifacts.
 
         Returns:
           The action ID.
         """
         logging.debug('creating action in %s...', self._configured_target_name)
         action_id = str(uuid.uuid4())
-        files = [
-            {'uid': path, 'uri': posixpath.join(gcs_path, path)}
-            for path in artifacts
-        ]
+
+        files = []
+        for path in artifacts:
+            uid = str(pathlib.PurePosixPath(path).relative_to(gcs_base_dir))
+            uri = f'gs://{gcs_bucket}/{path}'
+            files.append({'uid': uid, 'uri': uri})
         action = {
             'id': {
                 'invocationId': self._invocation_id,
```

