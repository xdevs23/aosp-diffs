```diff
diff --git a/tools/results_uploader/CHANGELOG.md b/tools/results_uploader/CHANGELOG.md
index c584339..c68243f 100644
--- a/tools/results_uploader/CHANGELOG.md
+++ b/tools/results_uploader/CHANGELOG.md
@@ -1,5 +1,21 @@
 # Mobly Results Uploader release history
 
+## 0.7.1 (2024-12-06)
+
+### Fixes
+* If a target contains any flaky test nodes, but not failing ones, set the target
+  status to FLAKY instead of FAILED.
+  * FLAKY targets will appear with a yellow banner in the BTX page.
+
+
+## 0.7 (2024-10-29)
+
+### New
+* Automatically prompt the user for GCP login if missing stored credentials.
+  * The user is no longer required to separately run login commands before using
+    the uploader for the first time.
+
+
 ## 0.6.1 (2024-08-21)
 
 ### Fixes
diff --git a/tools/results_uploader/pyproject.toml b/tools/results_uploader/pyproject.toml
index 50e2a02..6dcb6bb 100644
--- a/tools/results_uploader/pyproject.toml
+++ b/tools/results_uploader/pyproject.toml
@@ -4,7 +4,7 @@ build-backend = "setuptools.build_meta"
 
 [project]
 name = "results_uploader"
-version = "0.6.1"
+version = "0.7.1"
 description = "Tool for uploading Mobly test results to Resultstore web UI."
 readme = "README.md"
 requires-python = ">=3.11"
diff --git a/tools/results_uploader/src/results_uploader.py b/tools/results_uploader/src/results_uploader.py
index 92a8376..788b555 100644
--- a/tools/results_uploader/src/results_uploader.py
+++ b/tools/results_uploader/src/results_uploader.py
@@ -17,6 +17,7 @@
 """CLI uploader for Mobly test results to Resultstore."""
 
 import argparse
+import collections
 import dataclasses
 import datetime
 from importlib import resources
@@ -25,6 +26,7 @@ import mimetypes
 import pathlib
 import platform
 import shutil
+import subprocess
 import tempfile
 import warnings
 from xml.etree import ElementTree
@@ -43,6 +45,7 @@ with warnings.catch_warnings():
     from google.cloud.storage import transfer_manager
 
 logging.getLogger('googleapiclient').setLevel(logging.WARNING)
+logging.getLogger('google.auth').setLevel(logging.ERROR)
 
 _RESULTSTORE_SERVICE_NAME = 'resultstore'
 _API_VERSION = 'v2'
@@ -80,6 +83,44 @@ class _TestResultInfo:
     target_id: str | None = None
 
 
+def _gcloud_login_and_set_project() -> None:
+    """Get gcloud application default creds and set the desired GCP project."""
+    logging.info('No credentials found. Performing initial setup.')
+    project_id = ''
+    while not project_id:
+        project_id = input('Enter your GCP project ID: ')
+    try:
+        subprocess.run(['gcloud', 'auth', 'application-default', 'login',
+                        '--no-launch-browser'])
+        subprocess.run(['gcloud', 'auth', 'application-default',
+                        'set-quota-project', project_id])
+    except FileNotFoundError:
+        logging.exception(
+            'Failed to run `gcloud` commands. Please install the `gcloud` CLI!')
+    logging.info('Initial setup complete!')
+    print('-' * 20)
+
+
+def _get_project_number(project_id: str) -> str:
+    """Get the project number associated with a GCP project ID."""
+    client = resourcemanager_v3.ProjectsClient()
+    response = client.get_project(name=f'projects/{project_id}')
+    return response.name.split('/', 1)[1]
+
+
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
+
+
 def _convert_results(
         mobly_dir: pathlib.Path, dest_dir: pathlib.Path) -> _TestResultInfo:
     """Converts Mobly test results into Resultstore test.xml and test.log."""
@@ -105,6 +146,97 @@ def _convert_results(
     return test_result_info
 
 
+def _aggregate_testcase_iteration_results(
+        iteration_results: list[str]):
+    """Determines the aggregate result from a list of test case iterations.
+
+    This is only applicable to test cases with repeat/retry.
+    """
+    iterations_failed = [
+        result == _Status.FAILED for result in iteration_results
+        if result != _Status.SKIPPED
+    ]
+    # Skip if all iterations skipped
+    if not iterations_failed:
+        return _Status.SKIPPED
+    # Fail if all iterations failed
+    if all(iterations_failed):
+        return _Status.FAILED
+    # Flaky if some iterations failed
+    if any(iterations_failed):
+        return _Status.FLAKY
+    # Pass otherwise
+    return _Status.PASSED
+
+
+def _aggregate_subtest_results(subtest_results: list[str]):
+    """Determines the aggregate result from a list of subtest nodes.
+
+    This is used to provide a test class result based on the test cases, or
+    a test suite result based on the test classes.
+    """
+    # Skip if all subtests skipped
+    if all([result == _Status.SKIPPED for result in subtest_results]):
+        return _Status.SKIPPED
+
+    any_flaky = False
+    for result in subtest_results:
+        # Fail if any subtest failed
+        if result == _Status.FAILED:
+            return _Status.FAILED
+        # Record flaky subtest
+        if result == _Status.FLAKY:
+            any_flaky = True
+    # Flaky if any subtest is flaky, pass otherwise
+    return _Status.FLAKY if any_flaky else _Status.PASSED
+
+
+def _get_test_status_from_xml(mobly_suite_element: ElementTree.Element):
+    """Gets the overall status from the test XML."""
+    test_class_elements = mobly_suite_element.findall(
+        f'./{_ResultstoreTreeTags.TESTSUITE.value}')
+    test_class_results = []
+    for test_class_element in test_class_elements:
+        test_case_results = []
+        test_case_iteration_results = collections.defaultdict(list)
+        test_case_elements = test_class_element.findall(
+            f'./{_ResultstoreTreeTags.TESTCASE.value}')
+        for test_case_element in test_case_elements:
+            result = _Status.PASSED
+            if test_case_element.get(
+                    _ResultstoreTreeAttributes.RESULT.value) == 'skipped':
+                result = _Status.SKIPPED
+            if (
+                    test_case_element.find(
+                        f'./{_ResultstoreTreeTags.FAILURE.value}') is not None
+                    or test_case_element.find(
+                        f'./{_ResultstoreTreeTags.ERROR.value}') is not None
+            ):
+                result = _Status.FAILED
+            # Add to iteration results if run as part of a repeat/retry
+            # Otherwise, add to test case results directly
+            if (
+                    test_case_element.get(
+                        _ResultstoreTreeAttributes.RETRY_NUMBER.value) or
+                    test_case_element.get(
+                        _ResultstoreTreeAttributes.REPEAT_NUMBER.value)
+            ):
+                test_case_iteration_results[
+                    test_case_element.get(_ResultstoreTreeAttributes.NAME.value)
+                ].append(result)
+            else:
+                test_case_results.append(result)
+
+        for iteration_result_list in test_case_iteration_results.values():
+            test_case_results.append(
+                _aggregate_testcase_iteration_results(iteration_result_list)
+            )
+        test_class_results.append(
+            _aggregate_subtest_results(test_case_results)
+        )
+    return _aggregate_subtest_results(test_class_results)
+
+
 def _get_test_result_info_from_test_xml(
         test_xml: ElementTree.ElementTree,
 ) -> _TestResultInfo:
@@ -116,24 +248,7 @@ def _get_test_result_info_from_test_xml(
     if mobly_suite_element is None:
         return test_result_info
     # Set aggregate test status
-    test_result_info.status = _Status.PASSED
-    test_class_elements = mobly_suite_element.findall(
-        f'./{_ResultstoreTreeTags.TESTSUITE.value}')
-    failures = int(
-        mobly_suite_element.get(_ResultstoreTreeAttributes.FAILURES.value)
-    )
-    errors = int(
-        mobly_suite_element.get(_ResultstoreTreeAttributes.ERRORS.value))
-    if failures or errors:
-        test_result_info.status = _Status.FAILED
-    else:
-        all_skipped = all([test_case_element.get(
-            _ResultstoreTreeAttributes.RESULT.value) == 'skipped' for
-                           test_class_element in test_class_elements for
-                           test_case_element in test_class_element.findall(
-                f'./{_ResultstoreTreeTags.TESTCASE.value}')])
-        if all_skipped:
-            test_result_info.status = _Status.SKIPPED
+    test_result_info.status = _get_test_status_from_xml(mobly_suite_element)
 
     # Set target ID based on test class names, suite name, and custom run
     # identifier.
@@ -162,6 +277,8 @@ def _get_test_result_info_from_test_xml(
     if suite_name_value:
         target_id = suite_name_value
     else:
+        test_class_elements = mobly_suite_element.findall(
+            f'./{_ResultstoreTreeTags.TESTSUITE.value}')
         test_class_names = [
             test_class_element.get(_ResultstoreTreeAttributes.NAME.value)
             for test_class_element in test_class_elements
@@ -231,26 +348,6 @@ def _upload_dir_to_gcs(
     return [f'{gcs_dir}/{path}' for path in success_paths]
 
 
-def _get_project_number(project_id: str) -> str:
-    """Get the project number associated with a GCP project ID."""
-    client = resourcemanager_v3.ProjectsClient()
-    response = client.get_project(name=f'projects/{project_id}')
-    return response.name.split('/', 1)[1]
-
-
-def _retrieve_api_key(project_id: str) -> str | None:
-    """Downloads the Resultstore API key for the given Google Cloud project."""
-    project_number = _get_project_number(project_id)
-    client = api_keys_v2.ApiKeysClient()
-    keys = client.list_keys(
-        parent=f'projects/{project_number}/locations/global'
-    ).keys
-    for key in keys:
-        if key.display_name == _API_KEY_DISPLAY_NAME:
-            return client.get_key_string(name=key.name).key_string
-    return None
-
-
 def _upload_to_resultstore(
         api_key: str,
         gcs_bucket: str,
@@ -328,7 +425,12 @@ def main():
         format='%(levelname)s: %(message)s',
         level=(logging.DEBUG if args.verbose else logging.INFO)
     )
-    _, project_id = google.auth.default()
+    try:
+        _, project_id = google.auth.default()
+    except google.auth.exceptions.DefaultCredentialsError:
+        _gcloud_login_and_set_project()
+        _, project_id = google.auth.default()
+    logging.info('Current GCP project ID: %s', project_id)
     api_key = _retrieve_api_key(project_id)
     if api_key is None:
         logging.error(
diff --git a/tools/results_uploader/src/resultstore_client.py b/tools/results_uploader/src/resultstore_client.py
index b5fcd42..d92b7da 100644
--- a/tools/results_uploader/src/resultstore_client.py
+++ b/tools/results_uploader/src/resultstore_client.py
@@ -40,6 +40,7 @@ class Status(enum.Enum):
     PASSED = 'PASSED'
     FAILED = 'FAILED'
     SKIPPED = 'SKIPPED'
+    FLAKY = 'FLAKY'
     UNKNOWN = 'UNKNOWN'
 
 
@@ -395,7 +396,7 @@ class ResultstoreClient:
         )
         res = request.execute(http=self._http)
         logging.debug('invocations.finalize: %s', res)
-        print('---------------------')
+        print('-' * 20)
         # Make the URL show test cases regardless of status by default.
         show_statuses = (
             'showStatuses='
```

