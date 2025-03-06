```diff
diff --git a/Android.bp b/Android.bp
index d447d15..90181cb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,7 @@ python_library_host {
     srcs: [
         "archive_utils.py",
         "base_updater.py",
+        "color.py",
         "crates_updater.py",
         "fileutils.py",
         "git_updater.py",
diff --git a/README.md b/README.md
index 9d0fb68..a610294 100644
--- a/README.md
+++ b/README.md
@@ -38,6 +38,12 @@ Update a library without committing and uploading to Gerrit:
 tools/external_updater/updater.sh update --no-upload $PROJECT_PATH
 ```
 
+Update a library to a specific version:
+
+```shell
+tools/external_updater/updater.sh update --custom-version $VERSION $PROJECT_PATH
+```
+
 Update a library on top of the local changes in the current branch, commit, and upload the change to Gerrit:
 
 ```shell
diff --git a/base_updater.py b/base_updater.py
index 106f125..ed97b56 100644
--- a/base_updater.py
+++ b/base_updater.py
@@ -119,3 +119,12 @@ class Updater:
     def set_new_version(self, version: str) -> None:
         """Uses the passed version as the latest to upgrade project."""
         self._new_identifier.version = version
+
+    def set_custom_version(self, custom_version: str) -> None:
+        """Uses the passed version as the latest to upgrade project if the
+        passed version is not older than the current version."""
+        if git_utils.is_ancestor(self._proj_path, self._old_identifier.version, custom_version):
+            self._new_identifier.version = custom_version
+        else:
+            raise RuntimeError(
+                f"Can not upgrade to {custom_version}. The current version is newer than {custom_version}.")
diff --git a/color.py b/color.py
new file mode 100644
index 0000000..1a1a250
--- /dev/null
+++ b/color.py
@@ -0,0 +1,37 @@
+#
+# Copyright (C) 2018 The Android Open Source Project
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
+import enum
+import sys
+
+USE_COLOR = sys.stdout.isatty()
+
+
+@enum.unique
+class Color(enum.Enum):
+    """Colors for output to console."""
+    FRESH = '\x1b[32m'
+    STALE = '\x1b[31;1m'
+    ERROR = '\x1b[31m'
+
+
+END_COLOR = '\033[0m'
+
+
+def color_string(string: str, color: Color) -> str:
+    """Changes the color of a string when print to terminal."""
+    if not USE_COLOR:
+        return string
+    return color.value + string + END_COLOR
diff --git a/external_updater.py b/external_updater.py
index 6e8a304..ff03c31 100644
--- a/external_updater.py
+++ b/external_updater.py
@@ -22,18 +22,17 @@ updater.sh update --refresh --keep_date rust/crates/libc
 
 import argparse
 from collections.abc import Iterable
-import enum
 import json
 import logging
 import os
 import subprocess
-import sys
 import textwrap
 import time
 from typing import Dict, Iterator, List, Union, Tuple, Type
 from pathlib import Path
 
 from base_updater import Updater
+from color import Color, color_string
 from crates_updater import CratesUpdater
 from git_updater import GitUpdater
 from github_archive_updater import GithubArchiveUpdater
@@ -50,25 +49,6 @@ UPDATERS: List[Type[Updater]] = [
 ]
 
 TMP_BRANCH_NAME = 'tmp_auto_upgrade'
-USE_COLOR = sys.stdout.isatty()
-
-
-@enum.unique
-class Color(enum.Enum):
-    """Colors for output to console."""
-    FRESH = '\x1b[32m'
-    STALE = '\x1b[31;1m'
-    ERROR = '\x1b[31m'
-
-
-END_COLOR = '\033[0m'
-
-
-def color_string(string: str, color: Color) -> str:
-    """Changes the color of a string when print to terminal."""
-    if not USE_COLOR:
-        return string
-    return color.value + string + END_COLOR
 
 
 def build_updater(proj_path: Path) -> Tuple[Updater, metadata_pb2.MetaData]:
@@ -156,7 +136,7 @@ def _do_update(args: argparse.Namespace, updater: Updater,
 
 def has_new_version(updater: Updater) -> bool:
     """Checks if a newer version of the project is available."""
-    if updater.current_version != updater.latest_version:
+    if updater.latest_version is not None and updater.current_version != updater.latest_version:
         return True
     return False
 
@@ -169,7 +149,11 @@ def print_project_status(updater: Updater) -> None:
     alternative_latest_version = updater.alternative_latest_version
 
     print(f'Current version: {current_version}')
-    print(f'Latest version: {latest_version}')
+    print('Latest version: ', end='')
+    if not latest_version:
+        print(color_string('Not available', Color.STALE))
+    else:
+        print(latest_version)
     if alternative_latest_version is not None:
         print(f'Alternative latest version: {alternative_latest_version}')
     if has_new_version(updater):
@@ -201,21 +185,26 @@ def use_alternative_version(updater: Updater) -> bool:
     recom_message = color_string(f'We recommend upgrading to {alternative_ver_type} {alternative_version} instead. ', Color.FRESH)
     not_recom_message = color_string(f'We DO NOT recommend upgrading to {alternative_ver_type} {alternative_version}. ', Color.STALE)
 
-    # If alternative_version is not None, there are ONLY three possible
+    # If alternative_version is not None, there are four possible
     # scenarios:
     # Scenario 1, out of date, we recommend switching to tag:
     # Current version: sha1
     # Latest version: sha2
     # Alternative latest version: tag
 
-    # Scenario 2, out of date, we DO NOT recommend switching to sha.
+    # Scenario 2, up to date, we DO NOT recommend switching to sha.
     # Current version: tag1
-    # Latest version: tag2
+    # Latest version: tag1
     # Alternative latest version: sha
 
-    # Scenario 3, up to date, we DO NOT recommend switching to sha.
+    # Scenario 3, out of date, we DO NOT recommend switching to sha.
     # Current version: tag1
-    # Latest version: tag1
+    # Latest version: tag2
+    # Alternative latest version: sha
+
+    # Scenario 4, out of date, no recommendations at all
+    # Current version: sha1
+    # Latest version: No tag found or a tag that doesn't belong to any branch
     # Alternative latest version: sha
 
     if alternative_ver_type == 'tag':
@@ -224,7 +213,10 @@ def use_alternative_version(updater: Updater) -> bool:
         if not new_version_available:
             warning = up_to_date_question + not_recom_message
         else:
-            warning = out_of_date_question + not_recom_message
+            if not latest_version:
+                warning = up_to_date_question
+            else:
+                warning = out_of_date_question + not_recom_message
 
     answer = input(warning)
     if "yes".startswith(answer.lower()):
@@ -236,7 +228,6 @@ def use_alternative_version(updater: Updater) -> bool:
         raise ValueError(f"Invalid input: {answer}")
 
 
-
 def check_and_update(args: argparse.Namespace,
                      proj_path: Path,
                      update_lib=False) -> Union[Updater, str]:
@@ -254,23 +245,24 @@ def check_and_update(args: argparse.Namespace,
         updater, metadata = build_updater(proj_path)
         updater.check()
 
-        alternative_version = updater.alternative_latest_version
         new_version_available = has_new_version(updater)
         print_project_status(updater)
 
         if update_lib:
-            if args.refresh:
-                print('Refreshing the current version')
+            if args.custom_version is not None:
+                updater.set_custom_version(args.custom_version)
+                print(f"Upgrading to custom version {args.custom_version}")
+            elif args.refresh:
                 updater.refresh_without_upgrading()
-
-            answer = False
-            if alternative_version is not None:
-                answer = use_alternative_version(updater)
-                if answer:
-                    updater.set_new_version(alternative_version)
-            if new_version_available or args.force or args.refresh or answer:
-                _do_update(args, updater, metadata)
+            elif new_version_available:
+                if updater.alternative_latest_version is not None:
+                    if use_alternative_version(updater):
+                        updater.set_new_version(updater.alternative_latest_version)
+            else:
+                return updater
+            _do_update(args, updater, metadata)
         return updater
+
     # pylint: disable=broad-except
     except Exception as err:
         logging.exception("Failed to check or update %s", proj_path)
@@ -394,10 +386,6 @@ def parse_args() -> argparse.Namespace:
         'Relative paths will be resolved from external/.')
     update_parser.add_argument('--json-output',
                                help='Path of a json file to write result to.')
-    update_parser.add_argument(
-        '--force',
-        help='Run update even if there\'s no new version.',
-        action='store_true')
     update_parser.add_argument(
         '--refresh',
         help='Run update and refresh to the current version.',
@@ -425,6 +413,9 @@ def parse_args() -> argparse.Namespace:
     update_parser.add_argument('--bug',
                                type=int,
                                help='Bug number for this update')
+    update_parser.add_argument('--custom-version',
+                               type=str,
+                               help='Custom version we want to upgrade to.')
     update_parser.add_argument('--remote-name',
                                default='aosp',
                                required=False,
diff --git a/fileutils.py b/fileutils.py
index 0ff8b05..c015488 100644
--- a/fileutils.py
+++ b/fileutils.py
@@ -179,6 +179,7 @@ def read_metadata(proj_path: Path) -> metadata_pb2.MetaData:
         metadata = metadata_file.read()
         return text_format.Parse(metadata, metadata_pb2.MetaData())
 
+
 def convert_url_to_identifier(metadata: metadata_pb2.MetaData) -> metadata_pb2.MetaData:
     """Converts the old style METADATA to the new style"""
     for url in metadata.third_party.url:
diff --git a/git_updater.py b/git_updater.py
index f32e735..023b006 100644
--- a/git_updater.py
+++ b/git_updater.py
@@ -18,7 +18,9 @@ import fileutils
 import git_utils
 import updater_utils
 # pylint: disable=import-error
+from color import Color, color_string
 from manifest import Manifest
+import metadata_pb2  # type: ignore
 
 
 class GitUpdater(base_updater.Updater):
@@ -45,36 +47,45 @@ class GitUpdater(base_updater.Updater):
 
         git_utils.fetch(self._proj_path, self.UPSTREAM_REMOTE_NAME)
 
+    def set_custom_version(self, custom_version: str) -> None:
+        super().set_custom_version(custom_version)
+        if not git_utils.list_branches_with_commit(self._proj_path, custom_version, self.UPSTREAM_REMOTE_NAME):
+            raise RuntimeError(
+                f"Can not upgrade to {custom_version}. This version does not belong to any branches.")
+
+    def set_new_versions_for_commit(self, latest_sha: str, latest_tag: str | None = None) -> None:
+        self._new_identifier.version = latest_sha
+        if latest_tag is not None and git_utils.is_ancestor(
+            self._proj_path, self._old_identifier.version, latest_tag):
+            self._alternative_new_ver = latest_tag
+
+    def set_new_versions_for_tag(self, latest_sha: str, latest_tag: str | None = None) -> None:
+        if latest_tag is None:
+            project = fileutils.canonicalize_project_path(self.project_path)
+            print(color_string(
+                f"{project} is currently tracking upstream tags but either no "
+                "tags were found in the upstream repository or the tag does not "
+                "belong to any branch. No latest tag available", Color.STALE
+            ))
+            self._new_identifier.ClearField("version")
+            self._alternative_new_ver = latest_sha
+            return
+        self._new_identifier.version = latest_tag
+        if git_utils.is_ancestor(
+            self._proj_path, self._old_identifier.version, latest_sha):
+            self._alternative_new_ver = latest_sha
+
     def check(self) -> None:
         """Checks upstream and returns whether a new version is available."""
         self.setup_remote()
-        possible_alternative_new_ver: str | None = None
+
+        latest_sha = self.current_head_of_upstream_default_branch()
+        latest_tag = self.latest_tag_of_upstream()
+
         if git_utils.is_commit(self._old_identifier.version):
-            # Update to remote head.
-            self._new_identifier.version = self.current_head_of_upstream_default_branch()
-            # Some libraries don't have a tag. We only populate
-            # _alternative_new_ver if there is a tag newer than _old_ver.
-            # Checks if there is a tag newer than AOSP's SHA
-            if (tag := self.latest_tag_of_upstream()) is not None:
-                possible_alternative_new_ver = tag
+            self.set_new_versions_for_commit(latest_sha, latest_tag)
         else:
-            # Update to the latest version tag.
-            tag = self.latest_tag_of_upstream()
-            if tag is None:
-                project = fileutils.canonicalize_project_path(self.project_path)
-                raise RuntimeError(
-                    f"{project} is currently tracking upstream tags but no tags were "
-                    "found in the upstream repository"
-                )
-            self._new_identifier.version = tag
-            # Checks if there is a SHA newer than AOSP's tag
-            possible_alternative_new_ver = self.current_head_of_upstream_default_branch()
-        if possible_alternative_new_ver is not None and git_utils.is_ancestor(
-            self._proj_path,
-            self._old_identifier.version,
-            possible_alternative_new_ver
-        ):
-            self._alternative_new_ver = possible_alternative_new_ver
+            self.set_new_versions_for_tag(latest_sha, latest_tag)
 
     def latest_tag_of_upstream(self) -> str | None:
         tags = git_utils.list_remote_tags(self._proj_path, self.UPSTREAM_REMOTE_NAME)
@@ -83,6 +94,9 @@ class GitUpdater(base_updater.Updater):
 
         parsed_tags = [updater_utils.parse_remote_tag(tag) for tag in tags]
         tag = updater_utils.get_latest_stable_release_tag(self._old_identifier.version, parsed_tags)
+        if not git_utils.list_branches_with_commit(self._proj_path, tag, self.UPSTREAM_REMOTE_NAME):
+            return None
+
         return tag
 
     def current_head_of_upstream_default_branch(self) -> str:
diff --git a/git_utils.py b/git_utils.py
index 584ba11..6682904 100644
--- a/git_utils.py
+++ b/git_utils.py
@@ -291,3 +291,13 @@ def is_ancestor(proj_path: Path, ancestor: str, child: str) -> bool:
         if ex.returncode == 1:
             return False
         raise
+
+
+def list_branches_with_commit(proj_path: Path, commit: str, remote_name: str) -> list[str]:
+    """Lists upstream branches which contain the specified commit"""
+    cmd = ['git', 'branch', '-r', '--contains', commit]
+    out = subprocess.run(cmd, capture_output=True, cwd=proj_path, check=True,
+                         text=True).stdout
+    lines = out.splitlines()
+    remote_branches = [line for line in lines if remote_name in line]
+    return remote_branches
diff --git a/github_archive_updater.py b/github_archive_updater.py
index 6e00cb9..2bf7f59 100644
--- a/github_archive_updater.py
+++ b/github_archive_updater.py
@@ -119,6 +119,16 @@ class GithubArchiveUpdater(Updater):
 
         git_utils.fetch(self._proj_path, self.UPSTREAM_REMOTE_NAME)
 
+    def create_tar_gz_url(self) -> str:
+        url = f'https://github.com/{self.owner}/{self.repo}/archive/' \
+              f'{self._new_identifier.version}.tar.gz'
+        return url
+
+    def create_zip_url(self) -> str:
+        url = f'https://github.com/{self.owner}/{self.repo}/archive/' \
+              f'{self._new_identifier.version}.zip'
+        return url
+
     def _fetch_latest_tag(self) -> Tuple[str, List[str]]:
         """We want to avoid hitting GitHub API rate limit by using alternative solutions."""
         tags = git_utils.list_remote_tags(self._proj_path, self.UPSTREAM_REMOTE_NAME)
@@ -126,16 +136,14 @@ class GithubArchiveUpdater(Updater):
         tag = updater_utils.get_latest_stable_release_tag(self._old_identifier.version, parsed_tags)
         return tag, []
 
-    def _fetch_latest_version(self) -> None:
+    def _fetch_latest_tag_or_release(self) -> None:
         """Checks upstream and gets the latest release tag."""
         self._new_identifier.version, urls = (self._fetch_latest_release()
                                or self._fetch_latest_tag())
 
         # Adds source code urls.
-        urls.append(f'https://github.com/{self.owner}/{self.repo}/archive/'
-                    f'{self._new_identifier.version}.tar.gz')
-        urls.append(f'https://github.com/{self.owner}/{self.repo}/archive/'
-                    f'{self._new_identifier.version}.zip')
+        urls.append(self.create_tar_gz_url())
+        urls.append(self.create_zip_url())
 
         self._new_identifier.value = choose_best_url(urls, self._old_identifier.value)
 
@@ -152,16 +160,23 @@ class GithubArchiveUpdater(Updater):
             f'https://github.com/{self.owner}/{self.repo}/archive/{self._new_identifier.version}.zip'
         )
 
+    def set_custom_version(self, custom_version: str) -> None:
+        super().set_custom_version(custom_version)
+        tar_gz_url = self.create_tar_gz_url()
+        zip_url = self.create_zip_url()
+        self._new_identifier.value = choose_best_url([tar_gz_url, zip_url], self._old_identifier.value)
+
     def check(self) -> None:
         """Checks update for package.
 
         Returns True if a new version is available.
         """
         self.setup_remote()
+
         if git_utils.is_commit(self._old_identifier.version):
             self._fetch_latest_commit()
         else:
-            self._fetch_latest_version()
+            self._fetch_latest_tag_or_release()
 
     def update(self) -> None:
         """Updates the package.
diff --git a/metadata.proto b/metadata.proto
index 47d0b16..09f7f8f 100644
--- a/metadata.proto
+++ b/metadata.proto
@@ -43,6 +43,7 @@ enum LicenseType {
 
 enum DirectoryType {
   PACKAGE = 1;
+  GROUP = 2;
   GOOGLE_INTERNAL = 4;
 }
 
@@ -79,6 +80,7 @@ message URL {
 
 message Identifier {
   optional string type = 1;
+  optional string omission_reason = 2;
   optional string value = 3;
   optional string version = 4;
   optional bool primary_source = 6;
diff --git a/tests/endtoend/test_check.py b/tests/endtoend/test_check.py
index bec6918..f561f16 100644
--- a/tests/endtoend/test_check.py
+++ b/tests/endtoend/test_check.py
@@ -88,3 +88,23 @@ class TestCheck:
             f"Latest version: {latest_version}\n"
             "Out of date!\n"
         )
+
+    def test_not_suggest_tag_that_is_not_on_any_branch(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that out-of-date projects are identified."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("v1.0.0")
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        a.upstream.switch_to_new_branch("new_branch")
+        a.upstream.commit("Third commit.", allow_empty=True)
+        a.upstream.tag("v2.0.0")
+        a.upstream.checkout("main")
+        a.upstream.delete_branch("new_branch")
+        output = self.check(updater_cmd, [a.local.path])
+        assert "Latest version: Not available" in output
diff --git a/tests/endtoend/test_update.py b/tests/endtoend/test_update.py
index 2730490..b1ad441 100644
--- a/tests/endtoend/test_update.py
+++ b/tests/endtoend/test_update.py
@@ -22,7 +22,12 @@ from .treebuilder import TreeBuilder
 
 class TestUpdate:
 
-    def update(self, updater_cmd: list[str], paths: list[Path], args: list[str] | None = None, bug_number: str | None = None) -> str:
+    def update(
+        self,
+        updater_cmd: list[str],
+        paths: list[Path],
+        args: list[str] | None = None,
+    ) -> str:
         """Runs `external_updater update` with the given arguments.
 
         Returns:
@@ -31,7 +36,6 @@ class TestUpdate:
         return subprocess.run(
             updater_cmd + ["update"] +
             (args if args is not None else []) +
-            (["--bug", bug_number] if bug_number is not None else []) +
             [str(p) for p in paths],
             check=True,
             capture_output=True,
@@ -48,7 +52,80 @@ class TestUpdate:
         a.initial_import()
         tree.init_and_sync()
         bug_number = "12345"
-        self.update(updater_cmd, [a.local.path], args=['--refresh'], bug_number=bug_number)
+        self.update(updater_cmd, [a.local.path], args=['--refresh', '--bug', bug_number])
         latest_sha = a.local.head()
         latest_commit_message = a.local.commit_message_at_revision(latest_sha)
         assert f"Bug: {bug_number}" in latest_commit_message
+
+    def test_custom_update_to_tag_successful(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that upgrade to a specific tag is successful."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("v1.0.0")
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        a.upstream.tag("v2.0.0")
+        a.upstream.commit("Third commit.", allow_empty=True)
+        a.upstream.tag("v3.0.0")
+        self.update(updater_cmd, [a.local.path], args=['--custom-version', "v2.0.0"])
+        latest_sha = a.local.head()
+        latest_commit_message = a.local.commit_message_at_revision(latest_sha)
+        assert "Upgrade test to v2.0.0" in latest_commit_message
+
+    def test_custom_downgrade_to_tag_unsuccessful(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that downgrade to a specific tag is unsuccessful."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("v1.0.0")
+        a.upstream.commit("Second commit.", allow_empty=True)
+        a.upstream.tag("v2.0.0")
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+        self.update(updater_cmd, [a.local.path], args=['--custom-version', "v1.0.0"])
+        latest_sha = a.local.head()
+        latest_commit_message = a.local.commit_message_at_revision(latest_sha)
+        assert "Add metadata files." in latest_commit_message
+
+    def test_custom_update_to_sha_successful(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that upgrade to a specific sha is successful."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        custom_sha = a.upstream.head()
+        a.upstream.commit("Third commit.", allow_empty=True)
+        self.update(updater_cmd, [a.local.path], args=['--custom-version', custom_sha])
+        latest_sha = a.local.head()
+        latest_commit_message = a.local.commit_message_at_revision(latest_sha)
+        assert f"Upgrade test to {custom_sha}" in latest_commit_message
+
+    def test_custom_downgrade_to_sha_unsuccessful(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that downgrade to a specific sha is unsuccessful."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        custom_sha = a.upstream.head()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        self.update(updater_cmd, [a.local.path], args=['--custom-version', custom_sha])
+        latest_sha = a.local.head()
+        latest_commit_message = a.local.commit_message_at_revision(latest_sha)
+        assert "Add metadata files." in latest_commit_message
diff --git a/tests/endtoend/treebuilder/fakeproject.py b/tests/endtoend/treebuilder/fakeproject.py
index a87d58d..77ca8d7 100644
--- a/tests/endtoend/treebuilder/fakeproject.py
+++ b/tests/endtoend/treebuilder/fakeproject.py
@@ -46,7 +46,7 @@ class FakeProject:  # pylint: disable=too-few-public-methods
         repo.init(branch_name="main")
         repo.commit("Initial commit.", allow_empty=True)
 
-    def initial_import(self) -> None:
+    def initial_import(self, upstream_is_tag: bool = False) -> None:
         """Perform the initial import of the upstream repo into the mirror repo.
 
         These are an approximation of the steps that would be taken for the initial
@@ -61,7 +61,9 @@ class FakeProject:  # pylint: disable=too-few-public-methods
         self.android_mirror.init()
         self.android_mirror.commit("Initial commit.", allow_empty=True)
 
-        upstream_sha = self.upstream.head()
+        upstream_version = self.upstream.head()
+        if upstream_is_tag:
+            upstream_version = self.upstream.describe(upstream_version)
         self.android_mirror.fetch(self.upstream)
         self.android_mirror.merge(
             "FETCH_HEAD", allow_fast_forward=False, allow_unrelated_histories=True
@@ -83,9 +85,9 @@ class FakeProject:  # pylint: disable=too-few-public-methods
                         day: 1
                       }}
                       identifier {{
-                        type: "GIT"
+                        type: "Git"
                         value: "{self.upstream.path.as_uri()}"
-                        version: "{upstream_sha}"
+                        version: "{upstream_version}"
                       }}
                     }}
                     """
diff --git a/tests/gitrepo.py b/tests/gitrepo.py
index e51bba0..5dd304d 100644
--- a/tests/gitrepo.py
+++ b/tests/gitrepo.py
@@ -114,6 +114,16 @@ class GitRepo:
             args.append(start_point)
         self.run(args)
 
+    def checkout(self, branch: str) -> None:
+        """Checks out a branch."""
+        args = ["checkout", branch]
+        self.run(args)
+
+    def delete_branch(self, name: str) -> None:
+        """Deletes a branch"""
+        args = ["branch", "-D", name]
+        self.run(args)
+
     def tag(self, name: str, ref: str | None = None) -> None:
         """Creates a tag at the given ref, or HEAD if not provided."""
         args = ["tag", name]
@@ -134,3 +144,8 @@ class GitRepo:
         # %B is the raw commit body
         # %- eats the separator newline
         return self.run(["show", "--format=%B%-", f"{revision}:{path}"])
+
+    def describe(self, sha: str) -> str:
+        """Returns the nearest tag to a given commit."""
+        cmd = ["describe", "--contains", sha]
+        return self.run(cmd).strip()
```

