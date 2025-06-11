```diff
diff --git a/Android.bp b/Android.bp
index 90181cb..293fd15 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,11 +24,7 @@ python_binary_host {
     libs: ["external_updater_lib"],
     required: ["cargo_embargo"],
     data: [":bpfmt"],
-    version: {
-        py3: {
-            embedded_launcher: false,
-        },
-    },
+    embedded_launcher: false,
 }
 
 python_binary_host {
@@ -68,11 +64,6 @@ python_library_host {
 
 python_defaults {
     name: "external_updater_test_defaults",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_library_host {
diff --git a/README.md b/README.md
index a610294..20a83de 100644
--- a/README.md
+++ b/README.md
@@ -11,76 +11,78 @@ In each of the examples below, `$PROJECT_PATH` is the path to the project to
 operate on. If more than one path is given, external_updater will operate on
 each in turn.
 
-Note: Older versions of external_updater used a different path resolution
-method. Relative paths were resolved relative to `//external` rather than the
-CWD, which meant tab-completed paths would only work if the CWD was
-`//external`, and that wildcards had to be escaped for processing by
-external_updater rather than the shell (e.g.
-`updater.sh 'check rust/crates/*'`). That behavior was removed to support CWD
-relative paths. If you want the old behavior back, leave a comment on
-http://b/243685332 or https://r.android.com/2855445.
+Make sure you have initialized AOSP main source code. The default remote for
+external updater is AOSP.
 
-Check updates for a library or verify METADATA is valid:
-
-```shell
-tools/external_updater/updater.sh check $PROJECT_PATH
-```
+If you are trying to upgrade a project in other remotes, you can pass
+`--remote-name $REMOTE` to the `update` parser. We strongly recommend updating
+projects in AOSP and allowing automerger to merge the upgrade CL with other
+branches.
 
-Update a library, commit, and upload the change to Gerrit:
-
-```shell
-tools/external_updater/updater.sh update $PROJECT_PATH
-```
+To use this tool, a METADATA file must present at the root of the
+repository. The full definition can be found in
+[metadata.proto](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/metadata.proto).
+Or
+[external/toybox/METADATA](https://android.googlesource.com/platform/external/toybox/+/refs/heads/main/METADATA)
+is a concrete example.
 
-Update a library without committing and uploading to Gerrit:
+From within your working directory, source the `envsetup.sh` script to set up
+your build environment and pick a target to build with the `lunch` command. You
+can pass any target that you want. After upgrading a project, external_updater
+starts building for the selected lunch target:
 
 ```shell
-tools/external_updater/updater.sh update --no-upload $PROJECT_PATH
+source build/envsetup.sh
+lunch aosp_cf_x86_64_phone-trunk_staging-eng
 ```
 
-Update a library to a specific version:
+Check updates for a library or verify METADATA is valid:
 
 ```shell
-tools/external_updater/updater.sh update --custom-version $VERSION $PROJECT_PATH
+tools/external_updater/updater.sh check PROJECT_PATH
 ```
 
-Update a library on top of the local changes in the current branch, commit, and upload the change to Gerrit:
+Update a library, commit, and upload the change to Gerrit:
 
 ```shell
-tools/external_updater/updater.sh update --keep-local-changes $PROJECT_PATH
+tools/external_updater/updater.sh update PROJECT_PATH
 ```
 
-Update a library without building:
+PROJECT_PATH can be the path to a library under external/, e.g.
+external/kotlinc, or external/python/cpython3. You can press Tab to complete the
+path.
 
+The following options can be passed to `update` parser:
 ```shell
-tools/external_updater/updater.sh update --no-build $PROJECT_PATH
+--no-build                        Skip building
+--no-upload                       Does not upload to Gerrit after upgrade
+--bug BUG                        Bug number for this update
+--custom-version CUSTOM_VERSION  Custom version we want to upgrade to.
+--skip-post-update                Skip post_update script if post_update script exists
+--keep-local-changes              Updates the current branch instead of creating a new branch
+--no-verify                       Pass --no-verify to git commit
+--remote-name REMOTE_NAME        Remote repository name, the default is set to aosp
+--exclude$EXCLUDE                Names of projects to exclude. These are just the final part of the path with no directories.
+--refresh                         Run update and refresh to the current version.
+--keep-date                       Run update and do not change date in METADATA.
+--json-output JSON_OUTPUT        Path of a json file to write result to.
 ```
 
-Update a library and add bug number to the commit message:
+For example:
 
 ```shell
-tools/external_updater/updater.sh update --bug $BUG_NUMBER $PROJECT_PATH
+tools/external_updater/updater.sh update --custom-version $VERSION $PROJECT_PATH
 ```
 
-PROJECT_PATH can be the path to a library under external/, e.g.
-external/kotlinc, or external/python/cpython3.
-
 ## Configure
 
-To use this tool, a METADATA file must present at the root of the
-repository. The full definition can be found in
-[metadata.proto](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/metadata.proto).
-Or
-[external/toybox/METADATA](https://android.googlesource.com/platform/external/toybox/+/refs/heads/main/METADATA)
-is a concrete example.
-
 The most important part in the file is a list of urls.
 `external_updater` will go through all urls and uses the first
 supported url.
 
 ### Git upstream
 
-If type of a URL is set to GIT, the URL must be a git upstream
+If the url type is `Git`, the URL must be a git upstream
 (the one you can use with `git clone`). And the version field must
 be either a version tag, or SHA. The tool will find the latest
 version tag or sha based on it.
@@ -119,8 +121,8 @@ be done easily in Gerrit, by comparing parent2 and the patchset.
 
 ### GitHub archive
 
-If the url type is ARCHIVE, and the url is from GitHub, `external_updater`
-can upgrade a library based on GitHub releases.
+If the url type is `Archive`, and the url is from GitHub, `external_updater`
+will upgrade a library based on GitHub tags/releases.
 
 If you have the choice between archives and git tags, choose tags.
 Because that makes it easier to manage local changes.
diff --git a/base_updater.py b/base_updater.py
index ed97b56..4c958b0 100644
--- a/base_updater.py
+++ b/base_updater.py
@@ -46,16 +46,17 @@ class Updater:
     def validate(self) -> str:
         """Checks whether aosp version is what it claims to be."""
         self.setup_remote()
-        return git_utils.diff(self._proj_path, 'a', self._old_identifier.version)
+        return git_utils.diff_stat(self._proj_path, 'a', self._old_identifier.version)
 
     def check(self) -> None:
         """Checks whether a new version is available."""
         raise NotImplementedError()
 
-    def update(self) -> None:
+    def update(self) -> Path | None:
         """Updates the package.
 
-        Has to call check() before this function.
+        Has to call check() before this function. Returns either the temporary
+        dir it stored the old version in after upgrading or None.
         """
         raise NotImplementedError()
 
@@ -127,4 +128,6 @@ class Updater:
             self._new_identifier.version = custom_version
         else:
             raise RuntimeError(
-                f"Can not upgrade to {custom_version}. The current version is newer than {custom_version}.")
+                f"Cannot upgrade to {custom_version}. "
+                f"Either the current version is newer than {custom_version} "
+                f"or the current version in the METADATA file is not correct.")
diff --git a/external_updater.py b/external_updater.py
index ff03c31..2a3ac07 100644
--- a/external_updater.py
+++ b/external_updater.py
@@ -25,6 +25,7 @@ from collections.abc import Iterable
 import json
 import logging
 import os
+import shutil
 import subprocess
 import textwrap
 import time
@@ -62,7 +63,7 @@ def build_updater(proj_path: Path) -> Tuple[Updater, metadata_pb2.MetaData]:
     Returns:
       The updater object built. None if there's any error.
     """
-
+    git_utils.repo_sync(proj_path)
     proj_path = fileutils.get_absolute_project_path(proj_path)
     metadata = fileutils.read_metadata(proj_path)
     metadata = fileutils.convert_url_to_identifier(metadata)
@@ -94,20 +95,19 @@ def _do_update(args: argparse.Namespace, updater: Updater,
             git_utils.reset_hard(full_path)
             git_utils.clean(full_path)
         git_utils.start_branch(full_path, TMP_BRANCH_NAME)
-
     try:
-        updater.update()
-
+        tmp_dir_of_old_version = updater.update()
+        bp_files = fileutils.find_local_bp_files(full_path, updater.latest_version)
+        fileutils.bpfmt(full_path, bp_files)
         updated_metadata = updater.update_metadata(metadata)
         fileutils.write_metadata(full_path, updated_metadata, args.keep_date)
-        git_utils.add_file(full_path, 'METADATA')
 
         try:
             rel_proj_path = str(fileutils.get_relative_project_path(full_path))
         except ValueError:
-            # Absolute paths to other trees will not be relative to our tree. There are
-            # not portable instructions for upgrading that project, since the path will
-            # differ between machines (or checkouts).
+            # Absolute paths to other trees will not be relative to our tree.
+            # There are no portable instructions for upgrading that project,
+            # since the path will differ between machines (or checkouts).
             rel_proj_path = "<absolute path to project>"
         commit_message = commit_message_generator(metadata.name, updater.latest_version, rel_proj_path, args.bug)
         git_utils.remove_gitmodules(full_path)
@@ -115,7 +115,10 @@ def _do_update(args: argparse.Namespace, updater: Updater,
         git_utils.commit(full_path, commit_message, args.no_verify)
 
         if not args.skip_post_update:
-            updater_utils.run_post_update(full_path, full_path)
+            if tmp_dir_of_old_version:
+                updater_utils.run_post_update(full_path, tmp_dir_of_old_version)
+            else:
+                updater_utils.run_post_update(full_path)
             git_utils.add_file(full_path, '*')
             git_utils.commit_amend(full_path)
 
@@ -343,29 +346,23 @@ def parse_args() -> argparse.Namespace:
     """Parses commandline arguments."""
 
     parser = argparse.ArgumentParser(
+        prog='tools/external_updater/updater.sh',
         description='Check updates for third party projects in external/.')
     subparsers = parser.add_subparsers(dest='cmd')
     subparsers.required = True
 
-    diff_parser = subparsers.add_parser('validate',
-                                        help='Check if aosp version is what it claims to be.')
-    diff_parser.add_argument(
-        'paths',
-        nargs='*',
-        help='Paths of the project. '
-             'Relative paths will be resolved from external/.')
-    diff_parser.set_defaults(func=validate)
-
     # Creates parser for check command.
-    check_parser = subparsers.add_parser('check',
-                                         help='Check update for one project.')
+    check_parser = subparsers.add_parser(
+        'check',
+        help='Check update for one project.')
     check_parser.add_argument(
         'paths',
         nargs='*',
         help='Paths of the project. '
-        'Relative paths will be resolved from external/.')
-    check_parser.add_argument('--json-output',
-                              help='Path of a json file to write result to.')
+             'Relative paths will be resolved from external/.')
+    check_parser.add_argument(
+        '--json-output',
+        help='Path of a json file to write result to.')
     check_parser.add_argument(
         '--all',
         action='store_true',
@@ -378,14 +375,53 @@ def parse_args() -> argparse.Namespace:
     check_parser.set_defaults(func=check)
 
     # Creates parser for update command.
-    update_parser = subparsers.add_parser('update', help='Update one project.')
+    update_parser = subparsers.add_parser(
+        'update',
+        help='Update one project.')
     update_parser.add_argument(
         'paths',
         nargs='*',
-        help='Paths of the project as globs. '
-        'Relative paths will be resolved from external/.')
-    update_parser.add_argument('--json-output',
-                               help='Path of a json file to write result to.')
+        help='Paths of the project as globs.')
+    update_parser.add_argument(
+        '--no-build',
+        action='store_false',
+        dest='build',
+        help='Skip building')
+    update_parser.add_argument(
+        '--no-upload',
+        action='store_true',
+        help='Does not upload to Gerrit after upgrade')
+    update_parser.add_argument(
+        '--bug',
+        type=int,
+        help='Bug number for this update')
+    update_parser.add_argument(
+        '--custom-version',
+        type=str,
+        help='Custom version we want to upgrade to.')
+    update_parser.add_argument(
+        '--skip-post-update',
+        action='store_true',
+        help='Skip post_update script if post_update script exists')
+    update_parser.add_argument(
+        '--keep-local-changes',
+        action='store_true',
+        help='Updates the current branch instead of creating a new branch')
+    update_parser.add_argument(
+        '--no-verify',
+        action='store_true',
+        help='Pass --no-verify to git commit')
+    update_parser.add_argument(
+        '--remote-name',
+        default='aosp',
+        required=False,
+        help='Remote repository name, the default is set to aosp')
+    update_parser.add_argument(
+        '--exclude',
+        action='append',
+        help='Names of projects to exclude. '
+             'These are just the final part of the path '
+             'with no directories.')
     update_parser.add_argument(
         '--refresh',
         help='Run update and refresh to the current version.',
@@ -394,39 +430,21 @@ def parse_args() -> argparse.Namespace:
         '--keep-date',
         help='Run update and do not change date in METADATA.',
         action='store_true')
-    update_parser.add_argument('--no-upload',
-                               action='store_true',
-                               help='Does not upload to Gerrit after upgrade')
-    update_parser.add_argument('--keep-local-changes',
-                               action='store_true',
-                               help='Updates the current branch')
-    update_parser.add_argument('--skip-post-update',
-                               action='store_true',
-                               help='Skip post_update script')
-    update_parser.add_argument('--no-build',
-                               action='store_false',
-                               dest='build',
-                               help='Skip building')
-    update_parser.add_argument('--no-verify',
-                               action='store_true',
-                               help='Pass --no-verify to git commit')
-    update_parser.add_argument('--bug',
-                               type=int,
-                               help='Bug number for this update')
-    update_parser.add_argument('--custom-version',
-                               type=str,
-                               help='Custom version we want to upgrade to.')
-    update_parser.add_argument('--remote-name',
-                               default='aosp',
-                               required=False,
-                               help='Upstream remote name.')
-    update_parser.add_argument('--exclude',
-                               action='append',
-                               help='Names of projects to exclude. '
-                               'These are just the final part of the path '
-                               'with no directories.')
+    update_parser.add_argument(
+        '--json-output',
+        help='Path of a json file to write result to.')
     update_parser.set_defaults(func=update)
 
+    diff_parser = subparsers.add_parser(
+        'validate',
+        help='Check if aosp version is what it claims to be.')
+    diff_parser.add_argument(
+        'paths',
+        nargs='*',
+        help='Paths of the project.'
+             'Relative paths will be resolved from external/.')
+    diff_parser.set_defaults(func=validate)
+
     return parser.parse_args()
 
 
diff --git a/fileutils.py b/fileutils.py
index c015488..c7bcb59 100644
--- a/fileutils.py
+++ b/fileutils.py
@@ -16,6 +16,8 @@
 import datetime
 import enum
 import os
+import shutil
+import subprocess
 from pathlib import Path
 import textwrap
 
@@ -25,8 +27,10 @@ from google.protobuf import text_format  # type: ignore
 # pylint: disable=import-error
 import metadata_pb2  # type: ignore
 
+import git_utils
 
 METADATA_FILENAME = 'METADATA'
+ANDROID_BP_FILENAME = 'Android.bp'
 
 
 @enum.unique
@@ -237,3 +241,44 @@ def write_metadata(proj_path: Path, metadata: metadata_pb2.MetaData, keep_date:
 
             """))
         metadata_file.write(text_metadata)
+
+
+def find_local_bp_files(proj_path: Path, latest_version: str) -> list[str]:
+    """Finds the bp files that are in the local project but not upstream.
+
+    Args:
+        proj_path: Path to the project.
+        latest_version: To compare upstream's latest_version to current working dir
+    """
+    added_files = git_utils.diff_name_only(proj_path, 'A', latest_version).splitlines()
+    bp_files = [file for file in added_files if ANDROID_BP_FILENAME in file]
+    return bp_files
+
+
+def bpfmt(proj_path: Path, bp_files: list[str]) -> bool:
+    """Runs bpfmt.
+
+    It only runs bpfmt on Android.bp files that are not in upstream to prevent
+    merge conflicts.
+
+    Args:
+        proj_path: Path to the project.
+        bp_files: List of bp files to run bpfmt on
+    """
+    cmd = ['bpfmt', '-w']
+
+    if shutil.which("bpfmt") is None:
+        print("bpfmt is not in your PATH. You may need to run lunch, or run 'm bpfmt' first.")
+        return False
+
+    if not bp_files:
+        print("Did not find any Android.bp files to format")
+        return False
+
+    try:
+        for file in bp_files:
+            subprocess.run(cmd + [file], capture_output=True, cwd=proj_path, check=True)
+            return True
+    except subprocess.CalledProcessError as ex:
+        print(f"bpfmt failed: {ex}")
+        return False
diff --git a/git_utils.py b/git_utils.py
index 6682904..4a5f549 100644
--- a/git_utils.py
+++ b/git_utils.py
@@ -193,6 +193,11 @@ def start_branch(proj_path: Path, branch_name: str) -> None:
     subprocess.run(['repo', 'start', branch_name], cwd=proj_path, check=True)
 
 
+def repo_sync(proj_path: Path,) -> None:
+    """Downloads new changes and updates the working files in the local environment."""
+    subprocess.run(['repo', 'sync', '.'], cwd=proj_path, check=True)
+
+
 def commit(proj_path: Path, message: str, no_verify: bool) -> None:
     """Commits changes."""
     cmd = ['git', 'commit', '-m', message] + (['--no-verify'] if no_verify is True else [])
@@ -259,7 +264,7 @@ def list_remote_tags(proj_path: Path, remote_name: str) -> list[str]:
     return lines
 
 
-def diff(proj_path: Path, diff_filter: str, revision: str) -> str:
+def diff_stat(proj_path: Path, diff_filter: str, revision: str) -> str:
     try:
         cmd = ['git', 'diff', revision, '--stat', f'--diff-filter={diff_filter}']
         out = subprocess.run(cmd, capture_output=True, cwd=proj_path,
@@ -269,6 +274,16 @@ def diff(proj_path: Path, diff_filter: str, revision: str) -> str:
         return f"Could not calculate the diff: {err}"
 
 
+def diff_name_only(proj_path: Path, diff_filter: str, revision: str) -> str:
+    try:
+        cmd = ['git', 'diff', revision, '--name-only', f'--diff-filter={diff_filter}']
+        out = subprocess.run(cmd, capture_output=True, cwd=proj_path,
+                             check=True, text=True).stdout
+        return out
+    except subprocess.CalledProcessError as err:
+        return f"Could not calculate the diff: {err}"
+
+
 def is_ancestor(proj_path: Path, ancestor: str, child: str) -> bool:
     cmd = ['git', 'merge-base', '--is-ancestor', ancestor, child]
     # https://git-scm.com/docs/git-merge-base#Documentation/git-merge-base.txt---is-ancestor
diff --git a/github_archive_updater.py b/github_archive_updater.py
index 2bf7f59..72fc8ef 100644
--- a/github_archive_updater.py
+++ b/github_archive_updater.py
@@ -14,9 +14,11 @@
 """Module to update packages from GitHub archive."""
 
 import json
+import os
 import re
 import urllib.request
 import urllib.error
+from pathlib import Path
 from typing import List, Optional, Tuple
 
 import archive_utils
@@ -178,7 +180,7 @@ class GithubArchiveUpdater(Updater):
         else:
             self._fetch_latest_tag_or_release()
 
-    def update(self) -> None:
+    def update(self) -> Path:
         """Updates the package.
 
         Has to call check() before this function.
@@ -189,6 +191,9 @@ class GithubArchiveUpdater(Updater):
                 self._new_identifier.value)
             package_dir = archive_utils.find_archive_root(temporary_dir)
             updater_utils.replace_package(package_dir, self._proj_path)
+            # package_dir contains the old version of the project. This is
+            # returned in case a project needs a post_update.sh script.
+            return os.path.normpath(package_dir)
         finally:
             # Don't remove the temporary directory, or it'll be impossible
             # to debug the failure...
diff --git a/test_fileutils.py b/test_fileutils.py
index 6056a48..f48f0f1 100644
--- a/test_fileutils.py
+++ b/test_fileutils.py
@@ -22,6 +22,32 @@ from tempfile import TemporaryDirectory
 
 import fileutils
 
+UNFORMATTED_BP_FILE = """\
+cc_library_shared {
+    name: "test",
+    srcs: [
+        "source2.c",
+        "source1.c",
+    ],
+    cflags: ["-Wno-error=ignored-attributes", "-Wall", "-Werror"],
+}
+"""
+
+FORMATTED_BP_FILE = """\
+cc_library_shared {
+    name: "test",
+    srcs: [
+        "source2.c",
+        "source1.c",
+    ],
+    cflags: [
+        "-Wno-error=ignored-attributes",
+        "-Wall",
+        "-Werror",
+    ],
+}
+"""
+
 
 class ResolveCommandLinePathsTest(unittest.TestCase):
     """Unit tests for resolve_command_line_paths."""
@@ -119,5 +145,24 @@ class FindTreeContainingTest(unittest.TestCase):
             fileutils.find_tree_containing(self.temp_dir)
 
 
+class BpfmtTest(unittest.TestCase):
+    """Unit tests for bpfmt."""
+
+    def setUp(self) -> None:
+        self._temp_dir = TemporaryDirectory()
+        self.temp_dir = Path(self._temp_dir.name)
+        (self.temp_dir / "Android.bp").write_text(UNFORMATTED_BP_FILE)
+
+    def tearDown(self) -> None:
+        self._temp_dir.cleanup()
+
+    def test_unformatted_bpfmt(self) -> None:
+        """Tests that bpfmt formats the bp file."""
+        results = fileutils.bpfmt(self.temp_dir, ['Android.bp'])
+        content = (self.temp_dir / "Android.bp").read_text()
+        if results:
+            self.assertEqual(content, FORMATTED_BP_FILE)
+
+
 if __name__ == "__main__":
     unittest.main(verbosity=2)
diff --git a/tests/endtoend/test_update.py b/tests/endtoend/test_update.py
index b1ad441..2021086 100644
--- a/tests/endtoend/test_update.py
+++ b/tests/endtoend/test_update.py
@@ -17,8 +17,35 @@
 import subprocess
 from pathlib import Path
 
+import git_utils
 from .treebuilder import TreeBuilder
 
+UNFORMATTED_BP_FILE = """\
+cc_library_shared {
+    name: "test",
+    srcs: [
+        "source2.c",
+        "source1.c",
+    ],
+    cflags: ["-Wno-error=ignored-attributes", "-Wall", "-Werror"],
+}
+"""
+
+FORMATTED_BP_FILE = """\
+cc_library_shared {
+    name: "test",
+    srcs: [
+        "source2.c",
+        "source1.c",
+    ],
+    cflags: [
+        "-Wno-error=ignored-attributes",
+        "-Wall",
+        "-Werror",
+    ],
+}
+"""
+
 
 class TestUpdate:
 
@@ -129,3 +156,65 @@ class TestUpdate:
         latest_sha = a.local.head()
         latest_commit_message = a.local.commit_message_at_revision(latest_sha)
         assert "Add metadata files." in latest_commit_message
+
+    def test_bpfmt_one_local_bp_file_no_upstream_bp_file(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that bpfmt formats the only local bp file."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        tree.create_manifest_repo()
+        a.initial_import()
+        a.android_mirror.commit("Add Android.bp file", update_files={"Android.bp": UNFORMATTED_BP_FILE})
+        tree.init_and_sync()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        self.update(updater_cmd, [a.local.path])
+        latest_sha = a.local.head()
+        bp_content = a.local.file_contents_at_revision(latest_sha, 'Android.bp')
+        assert bp_content == FORMATTED_BP_FILE
+
+    def test_bpfmt_one_local_bp_file_one_upstream_bp_file(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests that bpfmt doesn't format the bp file because it's an upstream file."""
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit and adding bp file", update_files={"Android.bp": UNFORMATTED_BP_FILE})
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        self.update(updater_cmd, [a.local.path])
+        latest_sha = a.local.head()
+        bp_content = a.local.file_contents_at_revision(latest_sha, 'Android.bp')
+        assert bp_content == UNFORMATTED_BP_FILE
+
+    def test_repo_sync(
+        self, tree_builder: TreeBuilder, updater_cmd: list[str]
+    ) -> None:
+        """Tests if updater is fooled by checking out an older commit.
+
+        We want to see if we checkout an older update commit, external_updater
+        knows we are up to date and it is not fooled by the fake out of date
+        state.
+        """
+        tree = tree_builder.repo_tree("tree")
+        a = tree.project("platform/external/foo", "external/foo")
+        a.upstream.commit("Initial commit.", allow_empty=True)
+        tree.create_manifest_repo()
+        a.initial_import()
+        tree.init_and_sync()
+        head_after_import = a.android_mirror.head()
+        a.upstream.commit("Second commit.", allow_empty=True)
+        commit_two = a.upstream.head()
+        self.update(updater_cmd, [a.local.path])
+        a.android_mirror.checkout(head_after_import)
+        output = self.update(updater_cmd, [a.local.path])
+        assert output == (
+            f"repo sync has finished successfully.\n"
+            f"Checking {a.local.path}...\n"
+            f"Current version: {commit_two}\n"
+            f"Latest version: {commit_two}\n"
+            "Up to date.\n"
+        )
diff --git a/tests/endtoend/treebuilder/test_fakeproject.py b/tests/endtoend/treebuilder/test_fakeproject.py
index 09aadb2..612c5cc 100644
--- a/tests/endtoend/treebuilder/test_fakeproject.py
+++ b/tests/endtoend/treebuilder/test_fakeproject.py
@@ -56,6 +56,6 @@ class TestFakeProject:
             == "Add metadata files.\n"
         )
         metadata = project.android_mirror.file_contents_at_revision("HEAD", "METADATA")
-        assert 'type: "GIT"' in metadata
+        assert 'type: "Git"' in metadata
         assert f'value: "{project.upstream.path.as_uri()}"' in metadata
         assert f'version: "{upstream_sha}"' in metadata
diff --git a/tests/gitrepo.py b/tests/gitrepo.py
index 5dd304d..c67024a 100644
--- a/tests/gitrepo.py
+++ b/tests/gitrepo.py
@@ -114,9 +114,9 @@ class GitRepo:
             args.append(start_point)
         self.run(args)
 
-    def checkout(self, branch: str) -> None:
-        """Checks out a branch."""
-        args = ["checkout", branch]
+    def checkout(self, revision_or_branch: str) -> None:
+        """Checks out a revision or a branch."""
+        args = ["checkout", revision_or_branch]
         self.run(args)
 
     def delete_branch(self, name: str) -> None:
diff --git a/tests/test_git_utils.py b/tests/test_git_utils.py
index 3c24302..8963148 100644
--- a/tests/test_git_utils.py
+++ b/tests/test_git_utils.py
@@ -53,6 +53,7 @@ class GitRepoTestCase(unittest.TestCase):
         os.environ.clear()
         os.environ.update(self._original_env)
 
+
 class IsAncestorTest(GitRepoTestCase):
     """Tests for git_utils.is_ancestor."""
 
@@ -120,18 +121,33 @@ class GetMostRecentTagTest(GitRepoTestCase):
 
 
 class DiffTest(GitRepoTestCase):
-    """Tests for git_utils.diff."""
-    def test_git_diff_added_filter(self) -> None:
+    def test_diff_stat_A_filter(self) -> None:
+        """Tests for git_utils.diff_stat."""
+        self.repo.init("main")
+        self.repo.commit(
+            "Add README.md", update_files={"README.md": "Hello, world!"}
+        )
+        first_commit = self.repo.head()
+        self.repo.commit(
+            "Add OWNERS and METADATA",
+            update_files={"OWNERS": "nobody"}
+        )
+        diff = git_utils.diff_stat(self.repo.path, 'A', first_commit)
+        assert 'OWNERS | 1 +' in diff
+
+    def test_diff_name_only_A_filter(self) -> None:
+        """Tests for git_utils.diff_name_only."""
         self.repo.init("main")
         self.repo.commit(
             "Add README.md", update_files={"README.md": "Hello, world!"}
         )
         first_commit = self.repo.head()
         self.repo.commit(
-            "Add OWNERS", update_files={"OWNERS": "nobody"}
+            "Add OWNERS and METADATA",
+            update_files={"OWNERS": "nobody", "METADATA": "name: 'foo'"}
         )
-        diff = git_utils.diff(self.repo.path, 'A', first_commit)
-        self.assertIn('OWNERS', diff)
+        diff = git_utils.diff_name_only(self.repo.path, 'A', first_commit)
+        assert diff == 'METADATA\nOWNERS\n'
 
 
 if __name__ == "__main__":
diff --git a/updater_utils.py b/updater_utils.py
index 5f2829e..497d399 100644
--- a/updater_utils.py
+++ b/updater_utils.py
@@ -66,16 +66,23 @@ def replace_package(source_dir, target_dir, temp_file=None) -> None:
                            "" if temp_file is None else temp_file])
 
 
-def run_post_update(source_dir: Path, target_dir: Path) -> None:
-    """
-      source_dir: Path to the new downloaded and extracted package.
-      target_dir: The path to the project in Android source tree.
+def run_post_update(proj_path: Path, old_project_path: Path | None = None) -> None:
+    """ Runs the post_update.sh script if exists.
+
+    Args:
+      proj_path: The path to the project in Android source tree. Note that this
+      project is now updated.
+      old_project_path: Temp dir to where it stored the old version after
+      upgrading the project.
     """
-    post_update_path = os.path.join(source_dir, 'post_update.sh')
+    post_update_path = os.path.join(proj_path, 'post_update.sh')
     if os.path.isfile(post_update_path):
-        print("Running post update script")
-        cmd: Sequence[str | Path] = ['bash', post_update_path, source_dir, target_dir]
-        print(f'Running {post_update_path}')
+        print(f"Running post update script {post_update_path}")
+        cmd: Sequence[str | Path]
+        if old_project_path:
+            cmd = ['bash', post_update_path, proj_path, old_project_path]
+        else:
+            cmd = ['bash', post_update_path, proj_path]
         subprocess.check_call(cmd)
 
 
@@ -145,7 +152,7 @@ def build(proj_path: Path) -> None:
     cmd = [
         str(tree / 'build/soong/soong_ui.bash'),
         "--build-mode",
-        "--modules-in-a-dir-no-deps",
+        "--modules-in-a-dir",
         f"--dir={str(proj_path)}",
     ]
     print('Building...')
```

