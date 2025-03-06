```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 31de3b0..4cedfd1 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -9,8 +9,10 @@ utils_unittest  = ./rh/utils_unittest.py
 android_test_mapping_format_unittest = ./tools/android_test_mapping_format_unittest.py
 clang-format unittest = ./tools/clang-format_unittest.py
 config_test = ./rh/config_test.py --check-env --commit-id ${PREUPLOAD_COMMIT} --commit-msg ${PREUPLOAD_COMMIT_MESSAGE} --repo-root ${REPO_ROOT} -- ${PREUPLOAD_FILES}
+check_aosp_license_unittest = ./tools/check_aosp_license_unittest.py
 
 [Builtin Hooks]
+aosp_license = true
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
 commit_msg_test_field = true
diff --git a/README.md b/README.md
index c1ac4fc..664394b 100644
--- a/README.md
+++ b/README.md
@@ -178,6 +178,7 @@ This section allows for turning on common/builtin hooks.  There are a bunch of
 canned hooks already included geared towards AOSP style guidelines.
 
 * `aidl_format`: Run AIDL files (.aidl) through `aidl-format`.
+* `aosp_license`: Check if all new-added file have valid AOSP license headers.
 * `android_test_mapping_format`: Validate TEST_MAPPING files in Android source
   code. Refer to go/test-mapping for more details.
 * `bpfmt`: Run Blueprint files (.bp) through `bpfmt`.
@@ -331,7 +332,6 @@ without a bypass being required.
   their own list of files like `.cc` and `.py` and `.xml`.
 * Add more checkers.
   * `clang-check`: Runs static analyzers against code.
-  * License checking (like require AOSP header).
   * Whitespace checking (trailing/tab mixing/etc...).
   * Long line checking.
   * Commit message checks (correct format/BUG/TEST/SOB tags/etc...).
diff --git a/pre-upload.py b/pre-upload.py
index 18bf11f..892389d 100755
--- a/pre-upload.py
+++ b/pre-upload.py
@@ -361,9 +361,11 @@ def _run_project_hooks_in_cwd(
         output.error('Loading config files', str(e))
         return ret._replace(internal_failure=True)
 
+    builtin_hooks = list(config.callable_builtin_hooks())
+    custom_hooks = list(config.callable_custom_hooks())
+
     # If the repo has no pre-upload hooks enabled, then just return.
-    hooks = list(config.callable_hooks())
-    if not hooks:
+    if not builtin_hooks and not custom_hooks:
         return ret
 
     # Set up the environment like repo would with the forall command.
@@ -379,8 +381,10 @@ def _run_project_hooks_in_cwd(
     rel_proj_dir = os.path.relpath(proj_dir, rh.git.find_repo_root())
 
     # Filter out the hooks to process.
-    hooks = [x for x in hooks if rel_proj_dir not in x.scope]
-    if not hooks:
+    builtin_hooks = [x for x in builtin_hooks if rel_proj_dir not in x.scope]
+    custom_hooks = [x for x in custom_hooks if rel_proj_dir not in x.scope]
+
+    if not builtin_hooks and not custom_hooks:
         return ret
 
     os.environ.update({
@@ -413,24 +417,28 @@ def _run_project_hooks_in_cwd(
             os.environ['PREUPLOAD_COMMIT_MESSAGE'] = desc
 
             commit_summary = desc.split('\n', 1)[0]
-            output.commit_start(hooks, commit, commit_summary)
-
-            futures = (
-                executor.submit(_run_hook, hook, project, commit, desc, diff)
-                for hook in hooks
-            )
-            future_results = (
-                x.result() for x in concurrent.futures.as_completed(futures)
-            )
-            for hook, hook_results, error, warning, duration in future_results:
-                ret.add_results(hook_results)
-                if error is not None or warning is not None:
-                    if warning is not None:
-                        output.hook_warning(hook, warning)
-                    if error is not None:
-                        output.hook_error(hook, error)
-                        output.hook_fixups(ret, hook_results)
-                output.hook_finish(hook, duration)
+            output.commit_start(builtin_hooks + custom_hooks, commit, commit_summary)
+
+            def run_hooks(hooks):
+                futures = (
+                    executor.submit(_run_hook, hook, project, commit, desc, diff)
+                    for hook in hooks
+                )
+                future_results = (
+                    x.result() for x in concurrent.futures.as_completed(futures)
+                )
+                for hook, hook_results, error, warning, duration in future_results:
+                    ret.add_results(hook_results)
+                    if error is not None or warning is not None:
+                        if warning is not None:
+                            output.hook_warning(hook, warning)
+                        if error is not None:
+                            output.hook_error(hook, error)
+                            output.hook_fixups(ret, hook_results)
+                    output.hook_finish(hook, duration)
+
+            run_hooks(builtin_hooks)
+            run_hooks(custom_hooks)
 
     return ret
 
diff --git a/rh/config.py b/rh/config.py
index 6cd218b..3671a3f 100644
--- a/rh/config.py
+++ b/rh/config.py
@@ -141,7 +141,7 @@ class PreUploadConfig(object):
         """List of all tool paths."""
         return dict(self.config.items(self.TOOL_PATHS_SECTION, ()))
 
-    def callable_hooks(self):
+    def callable_custom_hooks(self):
         """Yield a CallableHook for each hook to be executed."""
         scope = rh.hooks.ExclusionScope([])
         for hook in self.custom_hooks:
@@ -151,6 +151,9 @@ class PreUploadConfig(object):
             func = functools.partial(rh.hooks.check_custom, options=options)
             yield rh.hooks.CallableHook(hook, func, scope)
 
+    def callable_builtin_hooks(self):
+        """Yield a CallableHook for each hook to be executed."""
+        scope = rh.hooks.ExclusionScope([])
         for hook in self.builtin_hooks:
             options = rh.hooks.HookOptions(hook,
                                            self.builtin_hook_option(hook),
diff --git a/rh/hooks.py b/rh/hooks.py
index ae0ea51..d07e0f9 100644
--- a/rh/hooks.py
+++ b/rh/hooks.py
@@ -343,6 +343,46 @@ def check_custom(project, commit, _desc, diff, options=None, **kwargs):
                       **kwargs)
 
 
+def check_aosp_license(project, commit, _desc, diff, options=None):
+    """Checks that if all new added files has AOSP licenses"""
+
+    exclude_dir_args = [x for x in options.args()
+                        if x.startswith('--exclude-dirs=')]
+    exclude_dirs = [x[len('--exclude-dirs='):].split(',')
+                    for x in exclude_dir_args]
+    exclude_list = [fr'^{x}/.*$' for dir_list in exclude_dirs for x in dir_list]
+
+    # Filter diff based on extension.
+    include_list = [
+        # Coding languages and scripts.
+        r".*\.c$",
+        r".*\.cc$",
+        r".*\.cpp$",
+        r".*\.h$",
+        r".*\.java$",
+        r".*\.kt$",
+        r".*\.rs$",
+        r".*\.py$",
+        r".*\.sh$",
+
+        # Build and config files.
+        r".*\.bp$",
+        r".*\.mk$",
+        r".*\.xml$",
+    ]
+    diff = _filter_diff(diff, include_list, exclude_list)
+
+    # Only check the new-added files.
+    diff = [d for d in diff if d.status == 'A']
+
+    if not diff:
+        return None
+
+    cmd = [get_helper_path('check_aosp_license.py'), '--commit_hash', commit]
+    cmd += HookOptions.expand_vars(('${PREUPLOAD_FILES}',), diff)
+    return _check_cmd('aosp_license', project, commit, cmd)
+
+
 def check_bpfmt(project, commit, _desc, diff, options=None):
     """Checks that Blueprint files are formatted with bpfmt."""
     filtered = _filter_diff(diff, [r'\.bp$'])
@@ -458,13 +498,12 @@ def check_ktfmt(project, commit, _desc, diff, options=None):
 
 
 def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
-    """Check the commit message for a 'Bug:' line."""
-    field = 'Bug'
-    regex = fr'^{field}: (None|[0-9]+(, [0-9]+)*)$'
+    """Check the commit message for a 'Bug:' or 'Fix:' line."""
+    regex = r'^(Bug|Fix): (None|[0-9]+(, [0-9]+)*)$'
     check_re = re.compile(regex)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError('commit msg Bug check takes no options')
 
     found = []
     for line in desc.splitlines():
@@ -473,13 +512,13 @@ def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
 
     if not found:
         error = (
-            f'Commit message is missing a "{field}:" line.  It must match the\n'
+            'Commit message is missing a "Bug:" line.  It must match the\n'
             f'following case-sensitive regex:\n\n    {regex}'
         )
     else:
         return None
 
-    return [rh.results.HookResult(f'commit msg: "{field}:" check',
+    return [rh.results.HookResult('commit msg: "Bug:" check',
                                   project, commit, error=error)]
 
 
@@ -1061,6 +1100,7 @@ def check_aidl_format(project, commit, _desc, diff, options=None):
 BUILTIN_HOOKS = {
     'aidl_format': check_aidl_format,
     'android_test_mapping_format': check_android_test_mapping,
+    'aosp_license': check_aosp_license,
     'bpfmt': check_bpfmt,
     'checkpatch': check_checkpatch,
     'clang_format': check_clang_format,
diff --git a/rh/hooks_unittest.py b/rh/hooks_unittest.py
index 389fe07..a54e24f 100755
--- a/rh/hooks_unittest.py
+++ b/rh/hooks_unittest.py
@@ -370,6 +370,51 @@ class BuiltinHooksTests(unittest.TestCase):
             self.assertIn(f'test_{hook}', dir(self),
                           msg=f'Missing unittest for builtin hook {hook}')
 
+    def test_aosp_license(self, mock_check, _mock_run):
+        """Verify the aosp_license builtin hook."""
+        # First call should do nothing as there are no files to check.
+        diff = [
+            rh.git.RawDiffEntry(file='d.bp', status='D'),
+            rh.git.RawDiffEntry(file='m.bp', status='M'),
+            rh.git.RawDiffEntry(file='non-interested', status='A'),
+        ]
+        ret = rh.hooks.check_aosp_license(
+            self.project, 'commit', 'desc', diff, options=self.options)
+        self.assertIsNone(ret)
+        self.assertFalse(mock_check.called)
+
+        # Second call will have some results.
+        diff = [
+            rh.git.RawDiffEntry(file='a.bp', status='A'),
+        ]
+        ret = rh.hooks.check_aosp_license(
+            self.project, 'commit', 'desc', diff, options=self.options)
+        self.assertIsNotNone(ret)
+
+        # No result since all paths are excluded.
+        diff = [
+            rh.git.RawDiffEntry(file='a/a.bp', status='A'),
+            rh.git.RawDiffEntry(file='b/a.bp', status='A'),
+            rh.git.RawDiffEntry(file='c/d/a.bp', status='A'),
+        ]
+        ret = rh.hooks.check_aosp_license(
+            self.project, 'commit', 'desc', diff,
+            options=rh.hooks.HookOptions('hook name',
+                ['--exclude-dirs=a,b', '--exclude-dirs=c/d'], {})
+        )
+        self.assertIsNone(ret)
+
+        # Make sure that `--exclude-dir` doesn't match the path in the middle.
+        diff = [
+            rh.git.RawDiffEntry(file='a/b/c.bp', status='A'),
+        ]
+        ret = rh.hooks.check_aosp_license(
+            self.project, 'commit', 'desc', diff,
+            options=rh.hooks.HookOptions('hook name', ['--exclude-dirs=b'], {})
+        )
+        self.assertIsNotNone(ret)
+
+
     def test_bpfmt(self, mock_check, _mock_run):
         """Verify the bpfmt builtin hook."""
         # First call should do nothing as there are no files to check.
@@ -428,6 +473,7 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_bug_field, True, (
                 'subj\n\nBug: 1234\n',
                 'subj\n\nBug: 1234\nChange-Id: blah\n',
+                'subj\n\nFix: 1234\n',
             ))
 
         # Check some bad messages.
@@ -438,6 +484,7 @@ class BuiltinHooksTests(unittest.TestCase):
                 'subj\n\nBUG: 1234\n',
                 'subj\n\nBug: N/A\n',
                 'subj\n\nBug:\n',
+                'subj\n\nFIX=1234\n',
             ))
 
     def test_commit_msg_changeid_field(self, _mock_check, _mock_run):
diff --git a/rh/utils.py b/rh/utils.py
index 4f1a063..d4001d6 100644
--- a/rh/utils.py
+++ b/rh/utils.py
@@ -426,7 +426,11 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
         if e.errno == errno.EACCES:
             estr += '; does the program need `chmod a+x`?'
         if not check:
-            result = CompletedProcess(args=cmd, stderr=estr, returncode=255)
+            result = CompletedProcess(args=cmd, returncode=255)
+            if combine_stdout_stderr:
+                result.stdout = estr
+            else:
+                result.stderr = estr
         else:
             raise CalledProcessError(
                 result.returncode, result.cmd, msg=estr,
diff --git a/tools/check_aosp_license.py b/tools/check_aosp_license.py
new file mode 100755
index 0000000..39896e7
--- /dev/null
+++ b/tools/check_aosp_license.py
@@ -0,0 +1,113 @@
+#!/usr/bin/env python3
+#
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
+"""Check if the given files in a given commit has an AOSP license."""
+
+import argparse
+import os
+import re
+import sys
+
+_path = os.path.realpath(__file__ + '/../..')
+if sys.path[0] != _path:
+    sys.path.insert(0, _path)
+del _path
+
+# We have to import our local modules after the sys.path tweak.  We can't use
+# relative imports because this is an executable program, not a module.
+# pylint: disable=import-error,wrong-import-position
+import rh.git
+
+
+# AOSP uses the Apache2 License: https://source.android.com/source/licenses.html
+# Spaces and comment identifiers in different languages are allowed at the
+# beginning of each line.
+AOSP_LICENSE_HEADER = (
+    r"""[ #/\*]*Copyright \(C\) 20\d\d The Android Open Source Project
+[ #/\*]*\n?[ #/\*]*Licensed under the Apache License, Version 2.0 """
+    r"""\(the "License"\);
+[ #/\*]*you may not use this file except in compliance with the License\.
+[ #/\*]*You may obtain a copy of the License at
+[ #/\*]*
+[ #/\*]*http://www\.apache\.org/licenses/LICENSE-2\.0
+[ #/\*]*
+[ #/\*]*Unless required by applicable law or agreed to in writing, software
+[ #/\*]*distributed under the License is distributed on an "AS IS" BASIS,
+[ #/\*]*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or """
+    r"""implied\.
+[ #/\*]*See the License for the specific language governing permissions and
+[ #/\*]*limitations under the License\.
+"""
+)
+
+
+license_re = re.compile(AOSP_LICENSE_HEADER, re.MULTILINE)
+
+
+AOSP_LICENSE_SUBSTR = 'Licensed under the Apache License'
+
+
+def check_license(contents: str) -> bool:
+    """Verifies the AOSP license/copyright header."""
+    return license_re.search(contents) is not None
+
+
+def get_parser() -> argparse.ArgumentParser:
+    parser = argparse.ArgumentParser(
+        description=(
+            'Check if the given files in a given commit has an AOSP license.'
+        )
+    )
+    parser.add_argument(
+        'file_paths',
+        nargs='+',
+        help='The file paths to check.',
+    )
+    parser.add_argument(
+        '--commit_hash',
+        '-c',
+        help='The commit hash to check.',
+        # TODO(b/370907797): Read the contents on the file system by default
+        # instead.
+        default='HEAD',
+    )
+    return parser
+
+
+def main(argv: list[str]):
+    """The main entry."""
+    parser = get_parser()
+    args = parser.parse_args(argv)
+    commit_hash = args.commit_hash
+    file_paths = args.file_paths
+
+    all_passed = True
+    for file_path in file_paths:
+        contents = rh.git.get_file_content(commit_hash, file_path)
+        if not check_license(contents):
+            has_pattern = contents.find(AOSP_LICENSE_SUBSTR) != -1
+            if has_pattern:
+                print(f'Malformed AOSP license in {file_path}')
+            else:
+                print(f'Missing AOSP license in {file_path}')
+            all_passed = False
+    if not all_passed:
+        return 1
+    return 0
+
+
+if __name__ == '__main__':
+    sys.exit(main(sys.argv[1:]))
diff --git a/tools/check_aosp_license_unittest.py b/tools/check_aosp_license_unittest.py
new file mode 100755
index 0000000..bcd98f8
--- /dev/null
+++ b/tools/check_aosp_license_unittest.py
@@ -0,0 +1,159 @@
+#!/usr/bin/env python3
+#
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
+
+import check_aosp_license
+
+
+class CheckAospLicenseTests(unittest.TestCase):
+    """Unittest for check_aosp_license module."""
+
+    def test_valid_header(self):
+        # The standard one on
+        # https://source.android.com/docs/setup/contribute/licenses
+        valid_header = """
+Copyright (C) 2024 The Android Open Source Project
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+"""
+        self.assertTrue(check_aosp_license.check_license(valid_header))
+
+    def test_valid_header_with_additional_empty_line(self):
+        # With additional empty line after the first line and additional white
+        # spaces before the URL. This is more common in the current code base.
+        valid_header = """
+Copyright (C) 2024 The Android Open Source Project
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+/"""
+        self.assertTrue(check_aosp_license.check_license(valid_header))
+
+    def test_valid_header_c(self):
+        # C-style comment.
+        valid_header = """/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */"""
+        self.assertTrue(check_aosp_license.check_license(valid_header))
+
+    def test_valid_header_cc(self):
+        # C++-style comment.
+        valid_header = """
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
+"""
+        self.assertTrue(check_aosp_license.check_license(valid_header))
+
+    def test_valid_header_xml(self):
+        # XML-style comment.
+        valid_header = """
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
+"""
+        self.assertTrue(check_aosp_license.check_license(valid_header))
+
+    def test_invalid_header_missing_year(self):
+        invalid_header = """
+Copyright (C) The Android Open Source Project
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+/"""
+        self.assertFalse(check_aosp_license.check_license(invalid_header))
+
+    def test_invalid_header_missing_line_in_middle(self):
+        invalid_header = """
+Copyright (C) The Android Open Source Project
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+     http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+See the License for the specific language governing permissions and
+limitations under the License.
+/"""
+        self.assertFalse(check_aosp_license.check_license(invalid_header))
+
+
+if __name__ == '__main__':
+    unittest.main()
```

