```diff
diff --git a/README.md b/README.md
index 20a83de..1d9623c 100644
--- a/README.md
+++ b/README.md
@@ -11,13 +11,12 @@ In each of the examples below, `$PROJECT_PATH` is the path to the project to
 operate on. If more than one path is given, external_updater will operate on
 each in turn.
 
-Make sure you have initialized AOSP main source code. The default remote for
-external updater is AOSP.
+Make sure you have initialized Android main source code:
 
-If you are trying to upgrade a project in other remotes, you can pass
-`--remote-name $REMOTE` to the `update` parser. We strongly recommend updating
-projects in AOSP and allowing automerger to merge the upgrade CL with other
-branches.
+```shell
+repo init -u URL [options]
+repo sync
+```
 
 To use this tool, a METADATA file must present at the root of the
 repository. The full definition can be found in
@@ -61,7 +60,6 @@ The following options can be passed to `update` parser:
 --skip-post-update                Skip post_update script if post_update script exists
 --keep-local-changes              Updates the current branch instead of creating a new branch
 --no-verify                       Pass --no-verify to git commit
---remote-name REMOTE_NAME        Remote repository name, the default is set to aosp
 --exclude$EXCLUDE                Names of projects to exclude. These are just the final part of the path with no directories.
 --refresh                         Run update and refresh to the current version.
 --keep-date                       Run update and do not change date in METADATA.
diff --git a/archive_utils.py b/archive_utils.py
index fd3cb65..cd5ed0e 100644
--- a/archive_utils.py
+++ b/archive_utils.py
@@ -14,8 +14,8 @@
 """Functions to process archive files."""
 
 import os
-import tempfile
 import tarfile
+import tempfile
 import urllib.parse
 import zipfile
 
@@ -26,7 +26,7 @@ class ZipFileWithPermission(zipfile.ZipFile):
     See https://bugs.python.org/issue15795
     """
     def _extract_member(self, member, targetpath, pwd):
-        ret_val = super()._extract_member(member, targetpath, pwd)
+        ret_val = super().extract(member, targetpath, pwd)
 
         if not isinstance(member, zipfile.ZipInfo):
             member = self.getinfo(member)
diff --git a/base_updater.py b/base_updater.py
index 4c958b0..e85e4c1 100644
--- a/base_updater.py
+++ b/base_updater.py
@@ -13,13 +13,37 @@
 # limitations under the License.
 """Base class for all updaters."""
 
+import re
 from pathlib import Path
 
-import git_utils
-import fileutils
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
 
+import fileutils
+import git_utils
+from color import Color, color_string
+
+VERSION_MATCH_PATTERN = r"^[^\d]*([\d].*)$"
+VERSION_WITH_UNDERSCORES_PATTERN = r"^[^\d]*([\d+_]+[\d])$"
+VERSION_WITH_DASHES_PATTERN = r"^[^\d]*([\d+-]+[\d])$"
+
+
+def _sanitize_version_for_cpe(version: str) -> str:
+    """Sanitizes a version in SemVer format by removing the prefix before the first digit.
+
+    This is necessary to match the CPE (go/metadata-cpe) version attribute
+    against the one in the National Vulnerability Database (NVD)."""
+    version_match = re.match(VERSION_MATCH_PATTERN, version)
+    version_with_underscore_match = re.match(VERSION_WITH_UNDERSCORES_PATTERN, version)
+    version_with_dashes_match = re.match(VERSION_WITH_DASHES_PATTERN, version)
+    if version_with_underscore_match is not None:
+        return version_with_underscore_match.group(1).replace("_", ".")
+    if version_with_dashes_match is not None:
+        return version_with_dashes_match.group(1).replace("-", ".")
+    if version_match is not None:
+        return version_match.group(1)
+    return version
+
 
 class Updater:
     """Base Updater that defines methods common for all updaters."""
@@ -43,10 +67,11 @@ class Updater:
     def setup_remote(self) -> None:
         raise NotImplementedError()
 
-    def validate(self) -> str:
-        """Checks whether aosp version is what it claims to be."""
+    def validate(self) -> None:
+        """Checks whether Android version is what it claims to be."""
         self.setup_remote()
-        return git_utils.diff_stat(self._proj_path, 'a', self._old_identifier.version)
+        diff = git_utils.diff_stat(self._proj_path, 'a', self._old_identifier.version)
+        print("No diff" if len(diff) == 0 else color_string(diff, Color.STALE))
 
     def check(self) -> None:
         """Checks whether a new version is available."""
@@ -75,6 +100,33 @@ class Updater:
         for identifier in updated_metadata.third_party.identifier:
             if identifier == self.current_identifier:
                 identifier.CopyFrom(self.latest_identifier)
+
+        version_is_sha= git_utils.is_commit(self.latest_version)
+        # TODO: b/412615684 - Implement a way to track the closest version
+        # associated with a package that uses a commit hash as the version. For
+        # example, in a "Git" Identifier that tracks the version as a git
+        # commit, the closest version would be the git tag. This would allow CPE
+        # tags to be updated with the closest version if the version is a commit
+        # hash.
+
+        # Update CPE tags with the latest version (go/metadata-cpe).
+        if updated_metadata.third_party.HasField("security") and not version_is_sha:
+            copy_of_security = metadata_pb2.Security()
+            copy_of_security.CopyFrom(updated_metadata.third_party.security)
+            for tag in copy_of_security.tag:
+                old_tag = tag
+                updated_version = _sanitize_version_for_cpe(self.latest_version)
+                if tag.startswith("NVD-CPE2.3"):
+                    cpe_parts = tag.split(":")
+                    if len(cpe_parts) > 5:
+                        new_tag = cpe_parts[:5] + [updated_version] + cpe_parts[6:]
+                    elif len(cpe_parts) == 5:
+                        new_tag = cpe_parts + [updated_version]
+                    else:
+                        continue
+                    new_tag = ":".join(new_tag)
+                    updated_metadata.third_party.security.tag.remove(old_tag)
+                    updated_metadata.third_party.security.tag.append(new_tag)
         return updated_metadata
 
     @property
diff --git a/crates_updater.py b/crates_updater.py
index a350384..0027789 100644
--- a/crates_updater.py
+++ b/crates_updater.py
@@ -15,19 +15,20 @@
 
 import json
 import os
-from pathlib import Path
 import re
 import shutil
 import tempfile
 import urllib.request
+from pathlib import Path
 from typing import IO
 
-import archive_utils
-from base_updater import Updater
-import git_utils
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
+
+import archive_utils
+import git_utils
 import updater_utils
+from base_updater import Updater
 
 LIBRARY_NAME_PATTERN: str = r"([-\w]+)"
 
@@ -98,7 +99,7 @@ class CratesUpdater(Updater):
                 int(match.group(2)),
                 int(match.group(3)),
             )
-        return (0, 0, 0)
+        return 0, 0, 0
 
     def _is_newer_version(self, prev_version: str, prev_id: int,
                           check_version: str, check_id: int):
diff --git a/external_updater.py b/external_updater.py
index 2a3ac07..fda75e8 100644
--- a/external_updater.py
+++ b/external_updater.py
@@ -21,27 +21,27 @@ updater.sh update --refresh --keep_date rust/crates/libc
 """
 
 import argparse
-from collections.abc import Iterable
 import json
 import logging
 import os
-import shutil
 import subprocess
 import textwrap
 import time
-from typing import Dict, Iterator, List, Union, Tuple, Type
+from collections.abc import Iterable
 from pathlib import Path
+from typing import Dict, Iterator, List, Tuple, Type, Union
+
+# pylint: disable=import-error
+import metadata_pb2  # type: ignore
 
+import fileutils
+import git_utils
+import updater_utils
 from base_updater import Updater
 from color import Color, color_string
 from crates_updater import CratesUpdater
 from git_updater import GitUpdater
 from github_archive_updater import GithubArchiveUpdater
-import fileutils
-import git_utils
-# pylint: disable=import-error
-import metadata_pb2  # type: ignore
-import updater_utils
 
 UPDATERS: List[Type[Updater]] = [
     CratesUpdater,
@@ -77,10 +77,8 @@ def commit_message_generator(project_name: str, version: str, path: str, bug: in
     This project was upgraded with external_updater.
     Usage: tools/external_updater/updater.sh update external/{path}
     For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md\n\n""")
-    if bug is None:
-        footer = "Test: TreeHugger"
-    else:
-        footer = f"Bug: {bug}\nTest: TreeHugger"
+    bug_number = "None" if bug is None else bug
+    footer = f"Bug: {bug_number}\nTest: TreeHugger"
     return header + body + footer
 
 
@@ -134,12 +132,20 @@ def _do_update(args: argparse.Namespace, updater: Updater,
         raise err
 
     if not args.no_upload:
-        git_utils.push(full_path, args.remote_name, updater.has_errors)
+        git_utils.push(full_path, updater.has_errors)
 
 
 def has_new_version(updater: Updater) -> bool:
     """Checks if a newer version of the project is available."""
-    if updater.latest_version is not None and updater.current_version != updater.latest_version:
+    if updater.latest_version is not None:
+        if updater.current_version != updater.latest_version or updater.alternative_latest_version is not None:
+            return True
+    return False
+
+
+def check_if_on_latest_tag_but_newer_sha_available(updater: Updater) -> bool:
+    """This is an edge case where METADATA is on the latest tag but there is a newer SHA available."""
+    if updater.current_version == updater.latest_version and updater.alternative_latest_version is not None:
         return True
     return False
 
@@ -160,7 +166,10 @@ def print_project_status(updater: Updater) -> None:
     if alternative_latest_version is not None:
         print(f'Alternative latest version: {alternative_latest_version}')
     if has_new_version(updater):
-        print(color_string('Out of date!', Color.STALE))
+        if check_if_on_latest_tag_but_newer_sha_available(updater):
+            print(color_string('Up to date.', Color.FRESH))
+        else:
+            print(color_string('Out of date!', Color.STALE))
     else:
         print(color_string('Up to date.', Color.FRESH))
 
@@ -188,28 +197,6 @@ def use_alternative_version(updater: Updater) -> bool:
     recom_message = color_string(f'We recommend upgrading to {alternative_ver_type} {alternative_version} instead. ', Color.FRESH)
     not_recom_message = color_string(f'We DO NOT recommend upgrading to {alternative_ver_type} {alternative_version}. ', Color.STALE)
 
-    # If alternative_version is not None, there are four possible
-    # scenarios:
-    # Scenario 1, out of date, we recommend switching to tag:
-    # Current version: sha1
-    # Latest version: sha2
-    # Alternative latest version: tag
-
-    # Scenario 2, up to date, we DO NOT recommend switching to sha.
-    # Current version: tag1
-    # Latest version: tag1
-    # Alternative latest version: sha
-
-    # Scenario 3, out of date, we DO NOT recommend switching to sha.
-    # Current version: tag1
-    # Latest version: tag2
-    # Alternative latest version: sha
-
-    # Scenario 4, out of date, no recommendations at all
-    # Current version: sha1
-    # Latest version: No tag found or a tag that doesn't belong to any branch
-    # Alternative latest version: sha
-
     if alternative_ver_type == 'tag':
         warning = out_of_date_question + recom_message
     else:
@@ -218,6 +205,8 @@ def use_alternative_version(updater: Updater) -> bool:
         else:
             if not latest_version:
                 warning = up_to_date_question
+            elif check_if_on_latest_tag_but_newer_sha_available(updater):
+                warning = up_to_date_question + not_recom_message
             else:
                 warning = out_of_date_question + not_recom_message
 
@@ -309,9 +298,10 @@ def validate(args: argparse.Namespace) -> None:
     paths = fileutils.resolve_command_line_paths(args.paths)
     try:
         canonical_path = fileutils.canonicalize_project_path(paths[0])
-        print(f'Validating {canonical_path}')
+        print(f'Validating {canonical_path}...')
         updater, _ = build_updater(paths[0])
-        print(updater.validate())
+        print('Difference with upstream:')
+        updater.validate()
     except Exception:  # pylint: disable=broad-exception-caught
         logging.exception("Failed to check or update %s", paths)
 
@@ -411,11 +401,6 @@ def parse_args() -> argparse.Namespace:
         '--no-verify',
         action='store_true',
         help='Pass --no-verify to git commit')
-    update_parser.add_argument(
-        '--remote-name',
-        default='aosp',
-        required=False,
-        help='Remote repository name, the default is set to aosp')
     update_parser.add_argument(
         '--exclude',
         action='append',
@@ -437,7 +422,7 @@ def parse_args() -> argparse.Namespace:
 
     diff_parser = subparsers.add_parser(
         'validate',
-        help='Check if aosp version is what it claims to be.')
+        help='Check if Android version is what it claims to be.')
     diff_parser.add_argument(
         'paths',
         nargs='*',
diff --git a/external_updater_reviewers_test.py b/external_updater_reviewers_test.py
index a1e5cf5..3c6a86e 100644
--- a/external_updater_reviewers_test.py
+++ b/external_updater_reviewers_test.py
@@ -13,8 +13,8 @@
 # limitations under the License.
 """Unit tests for external updater reviewers."""
 
-from typing import List, Mapping, Set
 import unittest
+from typing import List, Mapping, Set
 
 import reviewers
 
diff --git a/fileutils.py b/fileutils.py
index c7bcb59..4c212ed 100644
--- a/fileutils.py
+++ b/fileutils.py
@@ -18,14 +18,13 @@ import enum
 import os
 import shutil
 import subprocess
-from pathlib import Path
 import textwrap
-
-# pylint: disable=import-error
-from google.protobuf import text_format  # type: ignore
+from pathlib import Path
 
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
+# pylint: disable=import-error
+from google.protobuf import text_format  # type: ignore
 
 import git_utils
 
@@ -52,7 +51,7 @@ def find_tree_containing(project: Path) -> Path:
     finding this directory won't necessarily work:
 
     * Using ANDROID_BUILD_TOP might find the wrong tree (if external_updater
-    is used to manage a project that is not in AOSP, as it does for CMake,
+    is used to manage a project that is not in Android, as it does for CMake,
     rr, and a few others), since ANDROID_BUILD_TOP will be the one that built
     external_updater rather than the given project.
     * Paths relative to __file__ are no good because we'll run from a "built"
@@ -281,4 +280,4 @@ def bpfmt(proj_path: Path, bp_files: list[str]) -> bool:
             return True
     except subprocess.CalledProcessError as ex:
         print(f"bpfmt failed: {ex}")
-        return False
+    return False
diff --git a/git_updater.py b/git_updater.py
index 023b006..208abdd 100644
--- a/git_updater.py
+++ b/git_updater.py
@@ -13,6 +13,11 @@
 # limitations under the License.
 """Module to check updates from Git upstream."""
 
+from pathlib import Path
+from string import Template
+
+import metadata_pb2  # type: ignore
+
 import base_updater
 import fileutils
 import git_utils
@@ -20,13 +25,34 @@ import updater_utils
 # pylint: disable=import-error
 from color import Color, color_string
 from manifest import Manifest
-import metadata_pb2  # type: ignore
+
+BUGANIZER_LINK = "go/android-external-updater-bug"
+ARCHIVE_WARNING = f"This is most likely an Archive, not Git. Please consider " \
+                  f"editing the METADATA file or filing a bug {BUGANIZER_LINK}."
+
+ACCURATE_VERSION_IN_METADATA = "The version in METADATA file is accurate."
+
+INACCURATE_VERSION_IN_METADATA = f"The version in the METADATA file is not " \
+                                 f"correct. We suspect that it should be " \
+                                 f"$real_version. Please consider editing the" \
+                                 f" METADATA file or filing a bug" \
+                                 f"{BUGANIZER_LINK}."
 
 
 class GitUpdater(base_updater.Updater):
     """Updater for Git upstream."""
     UPSTREAM_REMOTE_NAME: str = "update_origin"
 
+    def __init__(self, proj_path: Path, old_identifier: metadata_pb2.Identifier,
+        old_ver: str) -> None:
+        non_default_branch = git_utils.find_non_default_branch(old_identifier.value)
+        if non_default_branch is not None:
+            self.upstream_branch = non_default_branch
+            old_identifier.value = old_identifier.value.strip(f'tree/{self.upstream_branch}')
+        else:
+            self.upstream_branch = git_utils.detect_default_branch(proj_path, self.UPSTREAM_REMOTE_NAME)
+        super().__init__(proj_path, old_identifier, old_ver)
+
     def is_supported_url(self) -> bool:
         return git_utils.is_valid_url(self._proj_path, self._old_identifier.value)
 
@@ -79,7 +105,8 @@ class GitUpdater(base_updater.Updater):
         """Checks upstream and returns whether a new version is available."""
         self.setup_remote()
 
-        latest_sha = self.current_head_of_upstream_default_branch()
+        latest_sha = git_utils.get_sha_for_revision(
+            self._proj_path, self.UPSTREAM_REMOTE_NAME + '/' + self.upstream_branch)
         latest_tag = self.latest_tag_of_upstream()
 
         if git_utils.is_commit(self._old_identifier.version):
@@ -102,16 +129,58 @@ class GitUpdater(base_updater.Updater):
     def current_head_of_upstream_default_branch(self) -> str:
         branch = git_utils.detect_default_branch(self._proj_path,
                                                  self.UPSTREAM_REMOTE_NAME)
-        return git_utils.get_sha_for_branch(
+        return git_utils.get_sha_for_revision(
             self._proj_path, self.UPSTREAM_REMOTE_NAME + '/' + branch)
 
     def update(self) -> None:
         """Updates the package.
         Has to call check() before this function.
         """
-        print(f"Running `git merge {self._new_identifier.version}`...")
+        print(f"Running 'git merge {self._new_identifier.version}'...")
         git_utils.merge(self._proj_path, self._new_identifier.version)
 
+    def is_metadata_accurate(self, common_ancestor: str) -> bool:
+        sha_of_claimed_version = git_utils.get_sha_for_revision(self._proj_path, self._old_identifier.version)
+        if sha_of_claimed_version == common_ancestor:
+            return True
+        return False
+
+    def find_real_version(self, common_ancestor: str) -> str:
+        read_version = f"SHA {common_ancestor}"
+        tag = git_utils.get_tag_for_revision(self._proj_path, common_ancestor)
+        if tag is not None:
+            read_version = f"tag {tag} or SHA {common_ancestor}"
+        return read_version
+
+    def find_common_ancestor(self) -> str | None:
+        """Finds the most recent common ancestor of Android's main branch and upstream's default branch."""
+        upstream_default_branch = git_utils.detect_default_branch(self._proj_path, self.UPSTREAM_REMOTE_NAME)
+        local_remote_name = git_utils.determine_remote_name(self._proj_path)
+        local_default_branch = git_utils.detect_default_branch(self._proj_path, local_remote_name)
+        android_default_branch = local_remote_name + "/" + local_default_branch
+        upstream_default_branch = self.UPSTREAM_REMOTE_NAME + "/" + upstream_default_branch
+        common_ancestor = git_utils.merge_base(self._proj_path, android_default_branch, upstream_default_branch)
+        return common_ancestor
+
+    def validate(self) -> None:
+        """Checks whether Android version is what it claims to be."""
+        super().validate()
+
+        common_ancestor = self.find_common_ancestor()
+
+        if common_ancestor is None:
+            print(ARCHIVE_WARNING)
+            return
+
+        is_metadata_accurate = self.is_metadata_accurate(common_ancestor)
+        if is_metadata_accurate:
+            print(color_string(ACCURATE_VERSION_IN_METADATA, Color.FRESH))
+            return
+        real_version = self.find_real_version(common_ancestor)
+        template = Template(INACCURATE_VERSION_IN_METADATA)
+        print(template.substitute(real_version=real_version))
+        return
+
     def _determine_android_fetch_ref(self) -> str:
         """Returns the ref that should be fetched from the android remote."""
         # It isn't particularly efficient to reparse the tree for every
diff --git a/git_utils.py b/git_utils.py
index 4a5f549..2b6bba0 100644
--- a/git_utils.py
+++ b/git_utils.py
@@ -17,12 +17,21 @@ import datetime
 import re
 import subprocess
 from pathlib import Path
+from urllib.parse import urlparse
 
+import fileutils
 import hashtags
 import reviewers
+from manifest import Manifest
 
 UNWANTED_TAGS = ["*alpha*", "*Alpha*", "*beta*", "*Beta*", "*rc*", "*RC*", "*test*"]
 
+COMMIT_PATTERN = r'^[a-f0-9]{40}$'
+COMMIT_RE = re.compile(COMMIT_PATTERN)
+
+GITHUB_NETLOC = 'github.com'
+GITHUB_BRANCH_DIVIDER = '/tree/'
+
 
 def fetch(proj_path: Path, remote_name: str, branch: str | None = None) -> None:
     """Runs git fetch.
@@ -87,11 +96,14 @@ def detect_default_branch(proj_path: Path, remote_name: str) -> str:
     )
 
 
-def get_sha_for_branch(proj_path: Path, branch: str):
-    """Gets the hash SHA for a branch."""
-    cmd = ['git', 'rev-parse', branch]
-    return subprocess.run(cmd, capture_output=True, cwd=proj_path, check=True,
-                          text=True).stdout.strip()
+def get_sha_for_revision(proj_path: Path, revision: str) -> str:
+    """Gets the hash SHA for a revision, whether it's a tag or a hash SHA"""
+    cmd = ['git', 'rev-parse', revision]
+    try:
+        return subprocess.run(cmd, capture_output=True, cwd=proj_path,
+                              check=True, text=True).stdout.strip()
+    except subprocess.CalledProcessError as ex:
+        return ex.stderr
 
 
 def get_most_recent_tag(proj_path: Path, branch: str) -> str | None:
@@ -140,10 +152,6 @@ def list_local_branches(proj_path: Path) -> list[str]:
     return lines
 
 
-COMMIT_PATTERN = r'^[a-f0-9]{40}$'
-COMMIT_RE = re.compile(COMMIT_PATTERN)
-
-
 # pylint: disable=redefined-outer-name
 def is_commit(commit: str) -> bool:
     """Whether a string looks like a SHA1 hash."""
@@ -224,8 +232,9 @@ def detach_to_android_head(proj_path: Path) -> None:
     subprocess.run(['repo', 'sync', '-l', '-d', proj_path], cwd=proj_path, check=True)
 
 
-def push(proj_path: Path, remote_name: str, has_errors: bool) -> None:
+def push(proj_path: Path, has_errors: bool) -> None:
     """Pushes change to remote."""
+    remote_name = determine_remote_name(proj_path)
     cmd = ['git', 'push', remote_name, 'HEAD:refs/for/main', '-o', 'banned-words~skip']
     if revs := reviewers.find_reviewers(str(proj_path)):
         cmd.extend(['-o', revs])
@@ -290,7 +299,7 @@ def is_ancestor(proj_path: Path, ancestor: str, child: str) -> bool:
     # Exit status of 0 means yes, 1 means no, and all others mean an error occurred.
     # Although a commit is an ancestor of itself, we don't want to return True
     # if ancestor points to the same commit as child.
-    if get_sha_for_branch(proj_path, ancestor) == child:
+    if get_sha_for_revision(proj_path, ancestor) == child:
         return False
     try:
         subprocess.run(
@@ -316,3 +325,42 @@ def list_branches_with_commit(proj_path: Path, commit: str, remote_name: str) ->
     lines = out.splitlines()
     remote_branches = [line for line in lines if remote_name in line]
     return remote_branches
+
+
+def merge_base(proj_path: Path, branch1: str, branch2: str) -> str | None:
+    """Finds as good common ancestors as possible between branch1 and branch2"""
+    try:
+        cmd = ['git', 'merge-base', branch1, branch2]
+        out = subprocess.run(cmd, capture_output=True, cwd=proj_path,
+                             check=True, text=True).stdout.strip()
+        return out
+    except:
+        return None
+
+
+def get_tag_for_revision(proj_path: Path, sha: str) -> str | None:
+    """Give an object a human-readable name based on an available ref.
+    using --tags to find any tag found in refs/tags namespace.
+    """
+    try:
+        cmd = ['git', 'describe', '--exact-match', '--tags', sha]
+        out = subprocess.run(cmd, capture_output=True, cwd=proj_path,
+                             check=True, text=True).stdout.strip()
+        return out
+    except:
+        return None
+
+
+def determine_remote_name(proj_path: Path) -> str:
+    """Returns the remote name in the manifest."""
+    root = fileutils.find_tree_containing(proj_path)
+    manifest = Manifest.for_tree(root)
+    return manifest.remote
+
+
+def find_non_default_branch(identifier_value: str) -> str | None:
+    parsed_url = urlparse(identifier_value)
+    _, divider, branch = parsed_url.path.partition(GITHUB_BRANCH_DIVIDER)
+    if parsed_url.netloc == GITHUB_NETLOC and divider == GITHUB_BRANCH_DIVIDER:
+        return branch
+    return None
diff --git a/github_archive_updater.py b/github_archive_updater.py
index 72fc8ef..3c70fa1 100644
--- a/github_archive_updater.py
+++ b/github_archive_updater.py
@@ -16,16 +16,17 @@
 import json
 import os
 import re
-import urllib.request
 import urllib.error
+import urllib.request
 from pathlib import Path
 from typing import List, Optional, Tuple
 
 import archive_utils
-from base_updater import Updater
 import git_utils
 # pylint: disable=import-error
 import updater_utils
+from base_updater import Updater
+
 GITHUB_URL_PATTERN: str = (r'^https:\/\/github.com\/([-\w]+)\/([-\w]+)\/' +
                            r'(releases\/download\/|archive\/)')
 GITHUB_URL_RE: re.Pattern = re.compile(GITHUB_URL_PATTERN)
@@ -155,7 +156,7 @@ class GithubArchiveUpdater(Updater):
         # pylint: disable=line-too-long
         branch = git_utils.detect_default_branch(self._proj_path,
                                                  self.UPSTREAM_REMOTE_NAME)
-        self._new_identifier.version = git_utils.get_sha_for_branch(
+        self._new_identifier.version = git_utils.get_sha_for_revision(
             self._proj_path, self.UPSTREAM_REMOTE_NAME + '/' + branch)
         self._new_identifier.value = (
             # pylint: disable=line-too-long
diff --git a/hashtags.py b/hashtags.py
index 9b043dd..8d3d2af 100644
--- a/hashtags.py
+++ b/hashtags.py
@@ -15,6 +15,7 @@
 
 from pathlib import Path
 
+
 def find_hashtag(proj_path: Path) -> str:
     """Returns an empty string or a hashtag for git push."""
     if str(proj_path).find('/external/rust/') != -1:
diff --git a/manifest.py b/manifest.py
index 3fd68c1..2c42153 100644
--- a/manifest.py
+++ b/manifest.py
@@ -88,6 +88,7 @@ class ManifestParser:  # pylint: disable=too-few-public-methods
 
         return Manifest(
             self.xml_path,
+            default_remote,
             [
                 Project.from_xml_node(p, default_remote, default_revision)
                 for p in root.findall("./project")
@@ -101,8 +102,9 @@ class Manifest:
     https://gerrit.googlesource.com/git-repo/+/master/docs/manifest-format.md
     """
 
-    def __init__(self, path: Path, projects: list[Project]) -> None:
+    def __init__(self, path: Path, remote: str, projects: list[Project]) -> None:
         self.path = path
+        self.remote = remote
         self.projects_by_path = {p.path: p for p in projects}
 
     @staticmethod
diff --git a/notifier.py b/notifier.py
index 6f302f6..371f9f0 100644
--- a/notifier.py
+++ b/notifier.py
@@ -21,13 +21,13 @@ external_updater_notifier \
     googletest
 """
 
-from datetime import timedelta, datetime
 import argparse
 import json
 import os
 import re
 import subprocess
 import time
+from datetime import datetime, timedelta
 
 # pylint: disable=invalid-name
 
diff --git a/reviewers.py b/reviewers.py
index c20c7ac..83d180f 100644
--- a/reviewers.py
+++ b/reviewers.py
@@ -13,9 +13,9 @@
 # limitations under the License.
 """Find main reviewers for git push commands."""
 
-from collections.abc import MutableMapping
 import math
 import random
+from collections.abc import MutableMapping
 from typing import List, Set, Union
 
 # To randomly pick one of multiple reviewers, we put them in a List[str]
diff --git a/test_base_updater.py b/test_base_updater.py
index e930a35..756e1ba 100644
--- a/test_base_updater.py
+++ b/test_base_updater.py
@@ -18,9 +18,11 @@
 import unittest
 from pathlib import Path
 
-import base_updater
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
+
+import base_updater
+
 # pylint: enable=import-error
 
 
@@ -51,6 +53,181 @@ class UpdaterTest(unittest.TestCase):
         )
         self.assertEqual(updater.current_version, "old version")
 
+    def test_update_metadata_with_cpe_tag(self) -> None:
+        """Tests that Updater.update_metadata returns the updated metadata with updated version in CPE tags."""
+        updater = base_updater.Updater(
+            # This is absolute so we get the fast path out of the path canonicalization
+            # that would otherwise require us to define ANDROID_BUILD_TOP or run from a
+            # temp repo tree.
+            Path("/"),
+            metadata_pb2.Identifier(),
+            "1.0.0",
+        )
+        metadata = metadata_pb2.MetaData()
+        third_party = metadata_pb2.ThirdPartyMetaData()
+        security = metadata_pb2.Security()
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*"
+        )
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product"
+        )
+        third_party.security.CopyFrom(security)
+        metadata.third_party.CopyFrom(third_party)
+        updater.set_new_version("v2.0.1")
+
+        updated_metadata = updater.update_metadata(metadata)
+
+        self.assertEqual(updater.latest_version, "v2.0.1")
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[0],
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:2.0.1:*:*:*:*:*:*:*",
+        )
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[1],
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product:2.0.1",
+        )
+
+    def test_update_metadata_with_cpe_tags_and_version_with_non_numeric_prefix(self) -> None:
+        """Tests that Updater.update_metadata returns the updated metadata with updated sanitized version in CPE tags."""
+        updater = base_updater.Updater(
+            # This is absolute so we get the fast path out of the path canonicalization
+            # that would otherwise require us to define ANDROID_BUILD_TOP or run from a
+            # temp repo tree.
+            Path("/"),
+            metadata_pb2.Identifier(),
+            "1.0.0",
+        )
+        metadata = metadata_pb2.MetaData()
+        third_party = metadata_pb2.ThirdPartyMetaData()
+        security = metadata_pb2.Security()
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*"
+        )
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product"
+        )
+        third_party.security.CopyFrom(security)
+        metadata.third_party.CopyFrom(third_party)
+        updater.set_new_version("test-2.0.1")
+
+        updated_metadata = updater.update_metadata(metadata)
+
+        self.assertEqual(updater.latest_version, "test-2.0.1")
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[0],
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:2.0.1:*:*:*:*:*:*:*",
+        )
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[1],
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product:2.0.1",
+        )
+
+    def test_update_metadata_with_cpe_tags_and_sha_version(self) -> None:
+        """Tests that Updater.update_metadata returns the updated metadata and does not update CPE tags with SHA version."""
+        updater = base_updater.Updater(
+            # This is absolute so we get the fast path out of the path canonicalization
+            # that would otherwise require us to define ANDROID_BUILD_TOP or run from a
+            # temp repo tree.
+            Path("/"),
+            metadata_pb2.Identifier(),
+            "1.0.0",
+        )
+        metadata = metadata_pb2.MetaData()
+        third_party = metadata_pb2.ThirdPartyMetaData()
+        security = metadata_pb2.Security()
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*"
+        )
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product"
+        )
+        third_party.security.CopyFrom(security)
+        metadata.third_party.CopyFrom(third_party)
+        updater.set_new_version("e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")
+
+        updated_metadata = updater.update_metadata(metadata)
+
+        self.assertEqual(updater.latest_version, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e")
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[0],
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*",
+        )
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[1],
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product",
+        )
+
+    def test_update_metadata_with_cpe_tags_and_version_with_underscores(self) -> None:
+        """Tests that Updater.update_metadata returns the updated metadata with updated sanitized version in CPE tags."""
+        updater = base_updater.Updater(
+            # This is absolute so we get the fast path out of the path canonicalization
+            # that would otherwise require us to define ANDROID_BUILD_TOP or run from a
+            # temp repo tree.
+            Path("/"),
+            metadata_pb2.Identifier(),
+            "1.0.0",
+        )
+        metadata = metadata_pb2.MetaData()
+        third_party = metadata_pb2.ThirdPartyMetaData()
+        security = metadata_pb2.Security()
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*"
+        )
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product"
+        )
+        third_party.security.CopyFrom(security)
+        metadata.third_party.CopyFrom(third_party)
+        updater.set_new_version("test-2_0_1")
+
+        updated_metadata = updater.update_metadata(metadata)
+
+        self.assertEqual(updater.latest_version, "test-2_0_1")
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[0],
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:2.0.1:*:*:*:*:*:*:*",
+        )
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[1],
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product:2.0.1",
+        )
+
+    def test_update_metadata_with_cpe_tags_and_version_with_dashes(self) -> None:
+        """Tests that Updater.update_metadata returns the updated metadata with updated sanitized version in CPE tags."""
+        updater = base_updater.Updater(
+            # This is absolute so we get the fast path out of the path canonicalization
+            # that would otherwise require us to define ANDROID_BUILD_TOP or run from a
+            # temp repo tree.
+            Path("/"),
+            metadata_pb2.Identifier(),
+            "1.0.0",
+        )
+        metadata = metadata_pb2.MetaData()
+        third_party = metadata_pb2.ThirdPartyMetaData()
+        security = metadata_pb2.Security()
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:1.0.0:*:*:*:*:*:*:*"
+        )
+        security.tag.append(
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product"
+        )
+        third_party.security.CopyFrom(security)
+        metadata.third_party.CopyFrom(third_party)
+        updater.set_new_version("test-2-0-1")
+
+        updated_metadata = updater.update_metadata(metadata)
+
+        self.assertEqual(updater.latest_version, "test-2-0-1")
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[0],
+            "NVD-CPE2.3:cpe:/a:test1_vendor:test1_product:2.0.1:*:*:*:*:*:*:*",
+        )
+        self.assertEqual(
+            updated_metadata.third_party.security.tag[1],
+            "NVD-CPE2.3:cpe:/a:test2_vendor:test2_product:2.0.1",
+        )
+
 
 if __name__ == "__main__":
     unittest.main(verbosity=2)
diff --git a/test_manifest.py b/test_manifest.py
index 2e9c8b9..e3fb377 100644
--- a/test_manifest.py
+++ b/test_manifest.py
@@ -42,7 +42,7 @@ class TestFindManifestXmlForTree:
 class TestManifestParser:
     """Tests for ManifestParser."""
 
-    def test_default_missing(self, tmp_path: Path) -> None:
+    def test_manifest_default_missing(self, tmp_path: Path) -> None:
         """Tests that an error is raised when the default node is missing."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -58,7 +58,7 @@ class TestManifestParser:
         with pytest.raises(RuntimeError):
             ManifestParser(manifest_path).parse()
 
-    def test_name_missing(self, tmp_path: Path) -> None:
+    def test_project_name_missing(self, tmp_path: Path) -> None:
         """Tests that an error is raised when neither name nor path is defined for a project."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -66,7 +66,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project />
                 </manifest>
@@ -76,8 +76,7 @@ class TestManifestParser:
         with pytest.raises(RuntimeError):
             ManifestParser(manifest_path).parse()
 
-
-    def test_multiple_default(self, tmp_path: Path) -> None:
+    def test_multiple_manifest_default(self, tmp_path: Path) -> None:
         """Tests that an error is raised when there is more than one default node."""
         manifest = tmp_path / "manifest.xml"
         manifest.write_text(
@@ -85,8 +84,8 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
+                    <default revision="main" remote="testremote" />
 
                     <project path="external/project" revision="master" />
                 </manifest>
@@ -96,7 +95,26 @@ class TestManifestParser:
         with pytest.raises(RuntimeError):
             ManifestParser(manifest).parse()
 
-    def test_remote_default(self, tmp_path: Path) -> None:
+    def test_manifest_remote(self, tmp_path: Path) -> None:
+        """Tests that the correct remote name of the manifest is found."""
+        manifest_path = tmp_path / "manifest.xml"
+        manifest_path.write_text(
+            textwrap.dedent(
+                """\
+                <?xml version="1.0" encoding="UTF-8"?>
+                <manifest>
+                    <remote name="testremote" />
+                    <default revision="main" remote="testremote" />
+
+                    <project path="external/project" remote="origin" />
+                </manifest>
+                """
+            )
+        )
+        manifest = ManifestParser(manifest_path).parse()
+        assert manifest.remote == "testremote"
+
+    def test_project_remote_default(self, tmp_path: Path) -> None:
         """Tests that the default remote is used when not defined by the project."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -104,8 +122,8 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <remote name="aosp" />
-                    <default revision="main" remote="aosp" />
+                    <remote name="testremote" />
+                    <default revision="main" remote="testremote" />
 
                     <project path="external/project" />
                 </manifest>
@@ -113,9 +131,9 @@ class TestManifestParser:
             )
         )
         manifest = ManifestParser(manifest_path).parse()
-        assert manifest.project_with_path("external/project").remote == "aosp"
+        assert manifest.project_with_path("external/project").remote == "testremote"
 
-    def test_revision_default(self, tmp_path: Path) -> None:
+    def test_project_revision_default(self, tmp_path: Path) -> None:
         """Tests that the default revision is used when not defined by the project."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -123,7 +141,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project path="external/project" />
                 </manifest>
@@ -133,7 +151,7 @@ class TestManifestParser:
         manifest = ManifestParser(manifest_path).parse()
         assert manifest.project_with_path("external/project").revision == "main"
 
-    def test_path_default(self, tmp_path: Path) -> None:
+    def test_project_path_default(self, tmp_path: Path) -> None:
         """Tests that the default path is used when not defined by the project."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -141,7 +159,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project name="external/project" />
                 </manifest>
@@ -151,7 +169,7 @@ class TestManifestParser:
         manifest = ManifestParser(manifest_path).parse()
         assert manifest.project_with_path("external/project") is not None
 
-    def test_remote_explicit(self, tmp_path: Path) -> None:
+    def test_project_remote_explicit(self, tmp_path: Path) -> None:
         """Tests that the project remote is used when defined."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -159,7 +177,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project path="external/project" remote="origin" />
                 </manifest>
@@ -169,7 +187,7 @@ class TestManifestParser:
         manifest = ManifestParser(manifest_path).parse()
         assert manifest.project_with_path("external/project").remote == "origin"
 
-    def test_revision_explicit(self, tmp_path: Path) -> None:
+    def test_project_revision_explicit(self, tmp_path: Path) -> None:
         """Tests that the project revision is used when defined."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -177,7 +195,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project path="external/project" revision="master" />
                 </manifest>
@@ -187,7 +205,7 @@ class TestManifestParser:
         manifest = ManifestParser(manifest_path).parse()
         assert manifest.project_with_path("external/project").revision == "master"
 
-    def test_path_explicit(self, tmp_path: Path) -> None:
+    def test_project_path_explicit(self, tmp_path: Path) -> None:
         """Tests that the project path is used when defined."""
         manifest_path = tmp_path / "manifest.xml"
         manifest_path.write_text(
@@ -195,7 +213,7 @@ class TestManifestParser:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default revision="main" remote="aosp" />
+                    <default revision="main" remote="testremote" />
 
                     <project name="external/project" path="other/path" />
                 </manifest>
@@ -205,6 +223,7 @@ class TestManifestParser:
         manifest = ManifestParser(manifest_path).parse()
         assert manifest.project_with_path("other/path") is not None
 
+
 class TestManifest:
     """Tests for Manifest."""
 
@@ -217,7 +236,7 @@ class TestManifest:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default remote="aosp" revision="main" />
+                    <default remote="testremote" revision="main" />
 
                     <project path="external/a" />
                     <project path="external/b" />
@@ -238,7 +257,7 @@ class TestManifest:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default remote="aosp" revision="main" />
+                    <default remote="testremote" revision="main" />
 
                     <project path="external/a" />
                     <project path="external/b" />
@@ -259,7 +278,7 @@ class TestManifest:
                 """\
                 <?xml version="1.0" encoding="UTF-8"?>
                 <manifest>
-                    <default remote="aosp" revision="main" />
+                    <default remote="testremote" revision="main" />
 
                     <project path="external/a" />
                     <project path="external/b" />
diff --git a/tests/endtoend/test_check.py b/tests/endtoend/test_check.py
index f561f16..f2c5fae 100644
--- a/tests/endtoend/test_check.py
+++ b/tests/endtoend/test_check.py
@@ -53,12 +53,13 @@ class TestCheck:
         tree.init_and_sync()
         output = self.check(updater_cmd, [a.local.path])
         current_version = a.upstream.head()
-        assert output == (
+        expected_output = (
             f"Checking {a.local.path}...\n"
             f"Current version: {current_version}\n"
             f"Latest version: {current_version}\n"
             "Up to date.\n"
         )
+        assert expected_output in output
 
     def test_git_out_of_date(
         self, tree_builder: TreeBuilder, updater_cmd: list[str]
@@ -82,12 +83,13 @@ class TestCheck:
         )
         output = self.check(updater_cmd, [a.local.path])
         latest_version = a.upstream.head()
-        assert output == (
+        expected_output = (
             f"Checking {a.local.path}...\n"
             f"Current version: {current_version}\n"
             f"Latest version: {latest_version}\n"
             "Out of date!\n"
         )
+        assert expected_output in output
 
     def test_not_suggest_tag_that_is_not_on_any_branch(
         self, tree_builder: TreeBuilder, updater_cmd: list[str]
diff --git a/tests/endtoend/test_update.py b/tests/endtoend/test_update.py
index 2021086..238ea3a 100644
--- a/tests/endtoend/test_update.py
+++ b/tests/endtoend/test_update.py
@@ -17,7 +17,6 @@
 import subprocess
 from pathlib import Path
 
-import git_utils
 from .treebuilder import TreeBuilder
 
 UNFORMATTED_BP_FILE = """\
@@ -54,6 +53,7 @@ class TestUpdate:
         updater_cmd: list[str],
         paths: list[Path],
         args: list[str] | None = None,
+        input: str | None = None,
     ) -> str:
         """Runs `external_updater update` with the given arguments.
 
@@ -67,6 +67,7 @@ class TestUpdate:
             check=True,
             capture_output=True,
             text=True,
+            input=input
         ).stdout
 
     def test_bug_number(
@@ -84,6 +85,20 @@ class TestUpdate:
         latest_commit_message = a.local.commit_message_at_revision(latest_sha)
         assert f"Bug: {bug_number}" in latest_commit_message
 
+    def test_no_bug_number(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that bug: None is added to the commit message."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        self.update(updater_cmd, [a.local.path], args=['--refresh'])
+        latest_sha = a.local.head()
+        latest_commit_message = a.local.commit_message_at_revision(latest_sha)
+        assert "Bug: None" in latest_commit_message
+
     def test_custom_update_to_tag_successful(
         self, tree_builder: TreeBuilder, updater_cmd: list[str]
     ) -> None:
@@ -218,3 +233,204 @@ class TestUpdate:
             f"Latest version: {commit_two}\n"
             "Up to date.\n"
         )
+
+    def test_on_latest_sha(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA has an up to date SHA.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        commit_one = a.upstream.head()
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+
+        output = self.update(updater_cmd, [a.local.path])
+        assert output == (
+            f"repo sync has finished successfully.\n"
+            f"Checking {a.local.path}...\n"
+            f"Current version: {commit_one}\n"
+            f"Latest version: {commit_one}\n"
+            "Up to date.\n"
+        )
+
+    def test_on_sha_latest_equal_sha_and_tag_available(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA has an out of date SHA.
+        Upstream's latest SHA is tagged.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        commit_one = a.upstream.head()
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+
+        a.upstream.commit("Second commit.", allow_empty=True)
+        commit_two = a.upstream.head()
+        a.upstream.tag("tag1")
+
+        output = self.update(updater_cmd, [a.local.path], input='yes')
+        expected_output = (
+            f"Current version: {commit_one}\n"
+            f"Latest version: {commit_two}\n"
+            f"Alternative latest version: tag1\n"
+            "Out of date!\n"
+            f"Would you like to upgrade to tag tag1 instead of sha {commit_two}? (yes/no)\n"
+            "We recommend upgrading to tag tag1 instead."
+        )
+        assert expected_output in output
+
+    def test_on_sha_new_tag_newer_sha_available(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA has an out of date SHA.
+        Upstream has a new tag and a newer SHA.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        commit_one = a.upstream.head()
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+
+        a.upstream.commit("Second commit.", allow_empty=True)
+        a.upstream.tag("tag1")
+
+        a.upstream.commit("Third commit.", allow_empty=True)
+        commit_three = a.upstream.head()
+
+        output = self.update(updater_cmd, [a.local.path], input='yes')
+        expected_output = (
+            f"Current version: {commit_one}\n"
+            f"Latest version: {commit_three}\n"
+            f"Alternative latest version: tag1\n"
+            "Out of date!\n"
+            f"Would you like to upgrade to tag tag1 instead of sha {commit_three}? (yes/no)\n"
+            "We recommend upgrading to tag tag1 instead."
+        )
+        assert expected_output in output
+
+    def test_on_tag_latest_equal_sha_and_tag_available(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA has an out of date tag.
+        Upstream's latest SHA is tagged.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("tag1")
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+
+        a.upstream.commit("Second commit.", allow_empty=True)
+        commit_two = a.upstream.head()
+        a.upstream.tag("tag2")
+
+        output = self.update(updater_cmd, [a.local.path], input='no')
+        expected_output = (
+            f"Current version: tag1\n"
+            f"Latest version: tag2\n"
+            f"Alternative latest version: {commit_two}\n"
+            "Out of date!\n"
+            f"Would you like to upgrade to sha {commit_two} instead of tag tag2? (yes/no)\n"
+            f"We DO NOT recommend upgrading to sha {commit_two}."
+        )
+        assert expected_output in output
+
+    def test_on_tag_equal_to_latest_sha_and_tag(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA is on the latest tag.
+        Upstream's latest SHA is tagged.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("tag1")
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+
+        output = self.update(updater_cmd, [a.local.path])
+        expected_output = (
+            "Current version: tag1\n"
+            "Latest version: tag1\n"
+            "Up to date.\n"
+        )
+        assert expected_output in output
+
+    def test_on_tag_new_tag_newer_sha_available(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA has an out of date tag.
+        Upstream has a new tag and a newer SHA.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("tag1")
+
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+
+        a.upstream.commit("Second commit.", allow_empty=True)
+        a.upstream.tag("tag2")
+
+        a.upstream.commit("Third commit.", allow_empty=True)
+        commit_three = a.upstream.head()
+
+        output = self.update(updater_cmd, [a.local.path], input='yes')
+        expected_output = (
+            f"Current version: tag1\n"
+            f"Latest version: tag2\n"
+            f"Alternative latest version: {commit_three}\n"
+            "Out of date!\n"
+            f"Would you like to upgrade to sha {commit_three} instead of tag tag2? (yes/no)\n"
+            f"We DO NOT recommend upgrading to sha {commit_three}."
+        )
+        assert expected_output in output
+
+    def test_on_latest_tag_but_newer_sha_available(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """
+        METADATA is on the latest tag.
+        Upstream has a newer SHA.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        a.upstream.tag("tag1")
+
+        tree.create_manifest_repo()
+        a.initial_import(True)
+        tree.init_and_sync()
+
+        a.upstream.commit("Second commit.", allow_empty=True)
+        commit_two = a.upstream.head()
+
+        output = self.update(updater_cmd, [a.local.path], input='yes')
+        expected_output = (
+            f"Current version: tag1\n"
+            f"Latest version: tag1\n"
+            f"Alternative latest version: {commit_two}\n"
+            "Up to date.\n"
+            f"Would you like to upgrade to sha {commit_two}? (yes/no)\n"
+            f"We DO NOT recommend upgrading to sha {commit_two}."
+        )
+        assert expected_output in output
diff --git a/tests/endtoend/test_validate.py b/tests/endtoend/test_validate.py
new file mode 100644
index 0000000..1c4e39a
--- /dev/null
+++ b/tests/endtoend/test_validate.py
@@ -0,0 +1,98 @@
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
+#
+"""End-to-end tests for external_updater."""
+import subprocess
+from pathlib import Path
+from string import Template
+
+from .treebuilder import TreeBuilder
+
+WRONG_METADATA_FILE = """\
+name: "test"
+description: "It's a test."
+third_party {
+  license_type: UNENCUMBERED
+  last_upgrade_date {
+    year: 2023
+    month: 12
+    day: 1
+  }
+  identifier {
+    type: "Git"
+    value: "$upstream_uri"
+    version: "$upstream_version"
+  }
+}
+"""
+
+
+class TestValidate:
+    def validate(
+        self,
+        updater_cmd: list[str],
+        paths: list[Path],
+        args: list[str] | None = None,
+        input: str | None = None,
+    ) -> str:
+        """Runs `external_updater validate` with the given arguments.
+
+        Returns:
+        The output of the command.
+        """
+        return subprocess.run(
+            updater_cmd + ["validate"] +
+            (args if args is not None else []) +
+            [str(p) for p in paths],
+            check=True,
+            capture_output=True,
+            text=True,
+            input=input
+        ).stdout
+
+    def test_metadata_version_accurate(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that bug number is added to the commit message."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        output = self.validate(updater_cmd, [a.local.path])
+        assert "The version in METADATA file is accurate." in output
+
+    def test_metadata_version_not_accurate(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that bug number is added to the commit message."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        commit_one = a.upstream.head()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        commit_two = a.upstream.head()
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        upstream_url = a.upstream.path.as_uri()
+        template = Template(WRONG_METADATA_FILE)
+        new_metadata = template.substitute(upstream_uri=upstream_url, upstream_version=commit_one)
+        a.android_mirror.commit("Changing METADATA version to commit_one",
+                       update_files={"METADATA": new_metadata})
+        output = self.validate(updater_cmd, [a.local.path])
+        expected_output = f"We suspect that it should be SHA {commit_two}"
+        assert expected_output in output
diff --git a/tests/test_git_utils.py b/tests/test_git_utils.py
index 8963148..320577a 100644
--- a/tests/test_git_utils.py
+++ b/tests/test_git_utils.py
@@ -150,5 +150,89 @@ class DiffTest(GitRepoTestCase):
         assert diff == 'METADATA\nOWNERS\n'
 
 
+class GetShaForRevisionTest(GitRepoTestCase):
+    """Tests for git_utils.get_sha_for_revision."""
+
+    def test_get_sha_for_existing_tag(self) -> None:
+        """Tests if it can find the SHA of an existing tag"""
+        self.repo.init("main")
+        self.repo.commit("Initial commit.", allow_empty=True)
+        first_commit = self.repo.head()
+        self.repo.tag("tag1")
+        out = git_utils.get_sha_for_revision(self.repo.path, "tag1")
+        assert first_commit == out
+
+    def test_get_sha_for_existing_sha(self) -> None:
+        """Tests if the same SHA is returned."""
+        self.repo.init("main")
+        self.repo.commit("Initial commit.", allow_empty=True)
+        first_commit = self.repo.head()
+        out = git_utils.get_sha_for_revision(self.repo.path, first_commit)
+        assert first_commit == out
+
+    def test_get_sha_for_non_existent_tag(self) -> None:
+        """Tests if it prints error message if the tag doesn't exist."""
+        self.repo.init("main")
+        self.repo.commit("Initial commit.", allow_empty=True)
+        out = git_utils.get_sha_for_revision(self.repo.path, "tag1")
+        assert "fatal: ambiguous argument" in out
+
+
+class GetTagForRevisionTest(GitRepoTestCase):
+    """Tests for git_utils.get_tag_for_revision."""
+
+    def test_describe_a_tagged_sha(self) -> None:
+        """Tests if it finds the tag of a SHA."""
+        self.repo.init("main")
+        self.repo.commit("Initial commit.", allow_empty=True)
+        self.repo.tag("tag1")
+        first_commit = self.repo.head()
+        out = git_utils.get_tag_for_revision(self.repo.path, first_commit)
+        assert out == "tag1"
+
+    def test_describe_a_non_tagged_sha(self) -> None:
+        """Tests if None is returned if no tag is associated with a SHA."""
+        self.repo.init("main")
+        self.repo.commit("Initial commit.", allow_empty=True)
+        first_commit = self.repo.head()
+        out = git_utils.get_tag_for_revision(self.repo.path, first_commit)
+        assert out is None
+
+
+class MergeBaseTest(GitRepoTestCase):
+    """Tests for git_utils.merge_base."""
+
+    def test_merge_base_with_common_ancestor(self) -> None:
+        """Tests if it finds the common ancestor of two branches."""
+        self.repo.init("main")
+        self.repo.commit("Initial commit on main branch.", allow_empty=True)
+        first_commit = self.repo.head()
+        self.repo.switch_to_new_branch("dev")
+        self.repo.commit("Second commit on dev", allow_empty=True)
+        out = git_utils.merge_base(self.repo.path, "main", "dev")
+        assert first_commit == out
+
+
+class FindNonDefaultBranchTest(unittest.TestCase):
+    """Tests for git_utils.find_non_default_branch"""
+    def test_branch_in_github_url(self) -> None:
+        """Tests if the branch attached to the url is found."""
+        url = 'https://github.com/robolectric/robolectric/tree/google'
+        non_default_branch = git_utils.find_non_default_branch(url)
+        self.assertEqual(non_default_branch, "google")
+
+    def test_no_branch_in_url(self) -> None:
+        """Tests if None is returned when the url doesn't have a branch."""
+        url = 'https://github.com/GNOME/libxml2/'
+        non_default_branch = git_utils.find_non_default_branch(url)
+        self.assertIsNone(non_default_branch)
+
+    def test_branch_in_gitlab_url(self) -> None:
+        """Tests if None is returned when the url is non-GitHub git."""
+        url = 'https://gitlab.xiph.org/xiph/opus/-/tree/whitespace'
+        non_default_branch = git_utils.find_non_default_branch(url)
+        self.assertIsNone(non_default_branch)
+
+
 if __name__ == "__main__":
     unittest.main(verbosity=2)
diff --git a/updater_utils.py b/updater_utils.py
index 497d399..357d18b 100644
--- a/updater_utils.py
+++ b/updater_utils.py
@@ -13,19 +13,20 @@
 # limitations under the License.
 """Helper functions for updaters."""
 
-from collections.abc import Sequence
 import os
 import re
 import subprocess
 import sys
+from collections.abc import Sequence
 from pathlib import Path
 from typing import List, Tuple, Type
 
-from base_updater import Updater
-import fileutils
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
 
+import fileutils
+from base_updater import Updater
+
 
 def create_updater(metadata: metadata_pb2.MetaData, proj_path: Path,
                    updaters: List[Type[Updater]]) -> Updater:
```

