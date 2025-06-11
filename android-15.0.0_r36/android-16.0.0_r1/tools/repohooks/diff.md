```diff
diff --git a/OWNERS b/OWNERS
index 8e52c19..4cc9976 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,10 @@
+# keep-sorted start
+lovisolo@google.com
 rrangel@google.com
 saklein@google.com
-sfrolov@google.com
 tbain@google.com
 vapier@google.com
 zland@google.com
+# keep-sorted end
 
 samccone@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 664394b..ec3c22e 100644
--- a/README.md
+++ b/README.md
@@ -1,6 +1,6 @@
 # AOSP Preupload Hooks
 
-This repo holds hooks that get run by repo during the upload phase.  They
+This repo holds hooks that get run by [repo] during the upload phase.  They
 perform various checks automatically such as running linters on your code.
 
 Note: Currently all hooks are disabled by default.  Each repo must explicitly
@@ -20,9 +20,8 @@ See its help for more info.
 Sometimes you might want to bypass the upload checks.  While this is **strongly
 discouraged** (often failures you add will affect others and block them too),
 sometimes there are valid reasons for this.  You can simply use the option
-`--no-verify` when running `repo upload` to skip all upload checks.  This will
-skip **all** checks and not just specific ones.  It should be used only after
-having run & evaluated the upload output previously.
+`--ignore-hooks` when running `repo upload` to ignore all hook errors.
+This will ignore **all** hook errors and not just specific ones.
 
 # Config Files
 
@@ -134,11 +133,12 @@ lister = ls ${PREUPLOAD_FILES}
 checker prefix = check --file=${PREUPLOAD_FILES_PREFIXED}
 checker flag = check --file ${PREUPLOAD_FILES_PREFIXED}
 ```
+
 With a commit that changes `path1/file1` and `path2/file2`, then this will run
 programs with the arguments:
-* ['ls', 'path1/file1', 'path2/file2']
-* ['check', '--file=path1/file1', '--file=path2/file2']
-* ['check', '--file', 'path1/file1', '--file', 'path2/file2']
+* `['ls', 'path1/file1', 'path2/file2']`
+* `['check', '--file=path1/file1', '--file=path2/file2']`
+* `['check', '--file', 'path1/file1', '--file', 'path2/file2']`
 
 ## [Options]
 
@@ -207,7 +207,7 @@ canned hooks already included geared towards AOSP style guidelines.
   --include-dirs, which if specified will limit enforcement to only files under
   the specified directories.
 * `pylint`: Alias of `pylint3`.
-* `pylint2`: Run Python code through `pylint` using Python 2.
+* `pylint2`: Ignored for compatibility with old configs.
 * `pylint3`: Run Python code through `pylint` using Python 3.
 * `rustfmt`: Run Rust code through `rustfmt`.
 * `xmllint`: Run XML code through `xmllint`.
@@ -245,7 +245,7 @@ cpplint = --filter=-x ${PREUPLOAD_FILES}
 
 *** note
 This section can only be added to the repo project-wide settings
-[GLOBAL-PREUPLOAD.cfg].
+[GLOBAL-PREUPLOAD.cfg](#GLOBAL_PREUPLOAD_cfg).
 ***
 
 Used to explicitly exclude some projects when processing a hook. With this
@@ -311,6 +311,14 @@ These are notes for people updating the `pre-upload.py` hook itself:
   and exec-ed in its own context.  The only entry-point that matters is `main`.
 * New hooks can be added in `rh/hooks.py`.  Be sure to keep the list up-to-date
   with the documentation in this file.
+* Python versions
+  * Code loaded & run by end users (i.e. during `repo upload`) should stick to
+    older versions of Python.  We expect users to run on a variety of platforms
+    where Python is not the latest (e.g. Ubuntu LTS that is years behind).  We
+    currently require **Python 3.6**.  This aligns with [repo's supported Python
+    versions](https://gerrit.googlesource.com/git-repo/+/HEAD/docs/python-support.md).
+  * Code only run by repohooks developers may use much newer versions of Python
+    to keep things simple, especially as we don't readily test older versions.
 
 ## Warnings
 
@@ -337,3 +345,5 @@ without a bypass being required.
   * Commit message checks (correct format/BUG/TEST/SOB tags/etc...).
   * Markdown (gitiles) validator.
   * Spell checker.
+
+[repo]: https://gerrit.googlesource.com/git-repo/
diff --git a/pre-upload.py b/pre-upload.py
index 892389d..c852c29 100755
--- a/pre-upload.py
+++ b/pre-upload.py
@@ -29,6 +29,7 @@ from typing import List, Optional
 
 
 # Assert some minimum Python versions as we don't test or support any others.
+# See README.md for what version we may require.
 if sys.version_info < (3, 6):
     print('repohooks: error: Python-3.6+ is required', file=sys.stderr)
     sys.exit(1)
diff --git a/rh/hooks.py b/rh/hooks.py
index d07e0f9..6bdf344 100644
--- a/rh/hooks.py
+++ b/rh/hooks.py
@@ -353,24 +353,24 @@ def check_aosp_license(project, commit, _desc, diff, options=None):
     exclude_list = [fr'^{x}/.*$' for dir_list in exclude_dirs for x in dir_list]
 
     # Filter diff based on extension.
-    include_list = [
+    extensions = frozenset((
         # Coding languages and scripts.
-        r".*\.c$",
-        r".*\.cc$",
-        r".*\.cpp$",
-        r".*\.h$",
-        r".*\.java$",
-        r".*\.kt$",
-        r".*\.rs$",
-        r".*\.py$",
-        r".*\.sh$",
+        'c',
+        'cc',
+        'cpp',
+        'h',
+        'java',
+        'kt',
+        'rs',
+        'py',
+        'sh',
 
         # Build and config files.
-        r".*\.bp$",
-        r".*\.mk$",
-        r".*\.xml$",
-    ]
-    diff = _filter_diff(diff, include_list, exclude_list)
+        'bp',
+        'mk',
+        'xml',
+    ))
+    diff = _filter_diff(diff, [r'\.(' + '|'.join(extensions) + r')$'], exclude_list)
 
     # Only check the new-added files.
     diff = [d for d in diff if d.status == 'A']
@@ -378,7 +378,7 @@ def check_aosp_license(project, commit, _desc, diff, options=None):
     if not diff:
         return None
 
-    cmd = [get_helper_path('check_aosp_license.py'), '--commit_hash', commit]
+    cmd = [get_helper_path('check_aosp_license.py'), '--commit-hash', commit]
     cmd += HookOptions.expand_vars(('${PREUPLOAD_FILES}',), diff)
     return _check_cmd('aosp_license', project, commit, cmd)
 
@@ -499,11 +499,12 @@ def check_ktfmt(project, commit, _desc, diff, options=None):
 
 def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
     """Check the commit message for a 'Bug:' or 'Fix:' line."""
+    field = 'Bug'
     regex = r'^(Bug|Fix): (None|[0-9]+(, [0-9]+)*)$'
     check_re = re.compile(regex)
 
     if options.args():
-        raise ValueError('commit msg Bug check takes no options')
+        raise ValueError(f'commit msg {field} check takes no options')
 
     found = []
     for line in desc.splitlines():
@@ -512,13 +513,13 @@ def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
 
     if not found:
         error = (
-            'Commit message is missing a "Bug:" line.  It must match the\n'
+            f'Commit message is missing a "{field}:" line.  It must match the\n'
             f'following case-sensitive regex:\n\n    {regex}'
         )
     else:
         return None
 
-    return [rh.results.HookResult('commit msg: "Bug:" check',
+    return [rh.results.HookResult(f'commit msg: "{field}:" check',
                                   project, commit, error=error)]
 
 
@@ -975,15 +976,22 @@ def _check_pylint(project, commit, _desc, diff, extra_args=None, options=None):
 
 
 def check_pylint2(project, commit, desc, diff, options=None):
-    """Run pylint through Python 2."""
-    return _check_pylint(project, commit, desc, diff, options=options)
+    """Run pylint through Python 2.
+
+    This hook is not supported anymore, but we keep it registered to avoid
+    breaking in older branches with old configs that still have it.
+    """
+    del desc, diff, options
+    return [rh.results.HookResult(
+        'pylint2', project, commit,
+        ('The pylint2 check is no longer supported.  '
+         'Please delete from PREUPLOAD.cfg.'),
+        warning=True)]
 
 
 def check_pylint3(project, commit, desc, diff, options=None):
     """Run pylint through Python 3."""
-    return _check_pylint(project, commit, desc, diff,
-                         extra_args=['--py3'],
-                         options=options)
+    return _check_pylint(project, commit, desc, diff, options=options)
 
 
 def check_rustfmt(project, commit, _desc, diff, options=None):
diff --git a/rh/hooks_unittest.py b/rh/hooks_unittest.py
index a54e24f..bed3745 100755
--- a/rh/hooks_unittest.py
+++ b/rh/hooks_unittest.py
@@ -911,13 +911,15 @@ class BuiltinHooksTests(unittest.TestCase):
 
     def test_pylint(self, mock_check, _mock_run):
         """Verify the pylint builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_pylint2,
+        self._test_file_filter(mock_check, rh.hooks.check_pylint3,
                                ('foo.py',))
 
     def test_pylint2(self, mock_check, _mock_run):
         """Verify the pylint2 builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_pylint2,
-                               ('foo.py',))
+        ret = rh.hooks.check_pylint2(
+            self.project, 'commit', 'desc', (), options=self.options)
+        self.assertEqual(len(ret), 1)
+        self.assertTrue(ret[0].is_warning())
 
     def test_pylint3(self, mock_check, _mock_run):
         """Verify the pylint3 builtin hook."""
diff --git a/rh/results.py b/rh/results.py
index 65e0052..236387e 100644
--- a/rh/results.py
+++ b/rh/results.py
@@ -27,8 +27,16 @@ del _path
 class HookResult(object):
     """A single hook result."""
 
-    def __init__(self, hook, project, commit, error, files=(),
-                 fixup_cmd: Optional[List[str]] = None):
+    def __init__(
+        self,
+        hook,
+        project,
+        commit,
+        error,
+        warning: bool = False,
+        files=(),
+        fixup_cmd: Optional[List[str]] = None,
+    ):
         """Initialize.
 
         Args:
@@ -37,6 +45,7 @@ class HookResult(object):
           commit: The git commit sha.
           error: A string representation of the hook's result.  Empty on
               success.
+          warning: Whether this result is a warning, not an error.
           files: The list of files that were involved in the hook execution.
           fixup_cmd: A command that can automatically fix errors found in the
               hook's execution.  Can be None if the hook does not support
@@ -46,16 +55,17 @@ class HookResult(object):
         self.project = project
         self.commit = commit
         self.error = error
+        self._warning = warning
         self.files = files
         self.fixup_cmd = fixup_cmd
 
     def __bool__(self):
         """Whether this result is an error."""
-        return bool(self.error)
+        return bool(self.error) and not self._warning
 
     def is_warning(self):
         """Whether this result is a non-fatal warning."""
-        return False
+        return self._warning
 
 
 class HookCommandResult(HookResult):
diff --git a/tools/check_aosp_license.py b/tools/check_aosp_license.py
index 39896e7..ffeed21 100755
--- a/tools/check_aosp_license.py
+++ b/tools/check_aosp_license.py
@@ -20,6 +20,7 @@ import argparse
 import os
 import re
 import sys
+from typing import List
 
 _path = os.path.realpath(__file__ + '/../..')
 if sys.path[0] != _path:
@@ -54,7 +55,7 @@ AOSP_LICENSE_HEADER = (
 )
 
 
-license_re = re.compile(AOSP_LICENSE_HEADER, re.MULTILINE)
+LICENSE_RE = re.compile(AOSP_LICENSE_HEADER, re.MULTILINE)
 
 
 AOSP_LICENSE_SUBSTR = 'Licensed under the Apache License'
@@ -62,22 +63,19 @@ AOSP_LICENSE_SUBSTR = 'Licensed under the Apache License'
 
 def check_license(contents: str) -> bool:
     """Verifies the AOSP license/copyright header."""
-    return license_re.search(contents) is not None
+    return LICENSE_RE.search(contents) is not None
 
 
 def get_parser() -> argparse.ArgumentParser:
-    parser = argparse.ArgumentParser(
-        description=(
-            'Check if the given files in a given commit has an AOSP license.'
-        )
-    )
+    """Returns a command line parser."""
+    parser = argparse.ArgumentParser(description=__doc__)
     parser.add_argument(
-        'file_paths',
+        'files',
         nargs='+',
         help='The file paths to check.',
     )
     parser.add_argument(
-        '--commit_hash',
+        '--commit-hash',
         '-c',
         help='The commit hash to check.',
         # TODO(b/370907797): Read the contents on the file system by default
@@ -87,26 +85,23 @@ def get_parser() -> argparse.ArgumentParser:
     return parser
 
 
-def main(argv: list[str]):
+def main(argv: List[str]) -> int:
     """The main entry."""
     parser = get_parser()
-    args = parser.parse_args(argv)
-    commit_hash = args.commit_hash
-    file_paths = args.file_paths
+    opts = parser.parse_args(argv)
+    commit_hash = opts.commit_hash
+    file_paths = opts.files
 
     all_passed = True
     for file_path in file_paths:
         contents = rh.git.get_file_content(commit_hash, file_path)
         if not check_license(contents):
-            has_pattern = contents.find(AOSP_LICENSE_SUBSTR) != -1
-            if has_pattern:
-                print(f'Malformed AOSP license in {file_path}')
+            if AOSP_LICENSE_SUBSTR in contents:
+                print(f'{file_path}: Malformed AOSP license', file=sys.stderr)
             else:
-                print(f'Missing AOSP license in {file_path}')
+                print(f'{file_path}: Missing AOSP license', file=sys.stderr)
             all_passed = False
-    if not all_passed:
-        return 1
-    return 0
+    return 0 if all_passed else 1
 
 
 if __name__ == '__main__':
diff --git a/tools/cpplint.py b/tools/cpplint.py
index c5db879..4605300 100755
--- a/tools/cpplint.py
+++ b/tools/cpplint.py
@@ -43,6 +43,7 @@ same line, but it is far from perfect (in either direction).
 """
 
 import codecs
+import collections
 import copy
 import getopt
 import glob
@@ -50,7 +51,6 @@ import itertools
 import math  # for log
 import os
 import re
-import sre_compile
 import string
 import sys
 import sysconfig
@@ -60,14 +60,7 @@ import xml.etree.ElementTree
 # if empty, use defaults
 _valid_extensions = set([])
 
-__VERSION__ = '1.5.5'
-
-try:
-  xrange          # Python 2
-except NameError:
-  #  -- pylint: disable=redefined-builtin
-  xrange = range  # Python 3
-
+__VERSION__ = '2.0.0'
 
 _USAGE = """
 Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
@@ -79,6 +72,7 @@ Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
                    [--exclude=path]
                    [--extensions=hpp,cpp,...]
                    [--includeorder=default|standardcfirst]
+                   [--config=filename]
                    [--quiet]
                    [--version]
         <file> [file] ...
@@ -93,9 +87,14 @@ Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
   certain of the problem, and 1 meaning it could be a legitimate construct.
   This will miss some errors, and is not a substitute for a code review.
 
-  To suppress false-positive errors of a certain category, add a
-  'NOLINT(category)' comment to the line.  NOLINT or NOLINT(*)
-  suppresses errors of all categories on that line.
+  To suppress false-positive errors of certain categories, add a
+  'NOLINT(category[, category...])' comment to the line.  NOLINT or NOLINT(*)
+  suppresses errors of all categories on that line. To suppress categories
+  on the next line use NOLINTNEXTLINE instead of NOLINT. To suppress errors in
+  a block of code 'NOLINTBEGIN(category[, category...])' comment to a line at
+  the start of the block and to end the block add a comment with 'NOLINTEND'.
+  NOLINT blocks are inclusive so any statements on the same line as a BEGIN
+  or END will have the error suppression applied.
 
   The files passed in will be linted; at least one file must be provided.
   Default linted extensions are %s.
@@ -138,12 +137,20 @@ Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
       To see a list of all the categories used in cpplint, pass no arg:
          --filter=
 
+      Filters can directly be limited to files and also line numbers. The
+      syntax is category:file:line , where line is optional. The filter limitation
+      works for both + and - and can be combined with ordinary filters:
+
+      Examples: --filter=-whitespace:foo.h,+whitespace/braces:foo.h
+                --filter=-whitespace,-runtime/printf:foo.h:14,+runtime/printf_format:foo.h
+                --filter=-,+build/include_what_you_use:foo.h:321
+
     counting=total|toplevel|detailed
       The total number of errors found is always printed. If
       'toplevel' is provided, then the count of errors in each of
       the top-level categories like 'build' and 'whitespace' will
       also be printed. If 'detailed' is provided, then a count
-      is provided for each category like 'build/class'.
+      is provided for each category like 'legal/copyright'.
 
     repository=path
       The top level directory of the repository, used to derive the header
@@ -225,6 +232,9 @@ Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
       treat all others as separate group of "other system headers". The C headers
       included are those of the C-standard lib and closely related ones.
 
+    config=filename
+      Search for config files with the specified name instead of CPPLINT.cfg
+
     headers=x,y,...
       The header extensions that cpplint will treat as .h in checks. Values are
       automatically added to --extensions list.
@@ -284,10 +294,8 @@ Syntax: cpplint.py [--verbose=#] [--output=emacs|eclipse|vs7|junit|sed|gsed]
 # If you add a new error message with a new category, add it to the list
 # here!  cpplint_unittest.py should tell you if you forget to do this.
 _ERROR_CATEGORIES = [
-    'build/class',
     'build/c++11',
-    'build/c++14',
-    'build/c++tr1',
+    'build/c++17',
     'build/deprecated',
     'build/endif_comment',
     'build/explicit_make_pair',
@@ -327,7 +335,6 @@ _ERROR_CATEGORIES = [
     'runtime/invalid_increment',
     'runtime/member_string_references',
     'runtime/memset',
-    'runtime/indentation_namespace',
     'runtime/operator',
     'runtime/printf',
     'runtime/printf_format',
@@ -346,6 +353,7 @@ _ERROR_CATEGORIES = [
     'whitespace/ending_newline',
     'whitespace/forcolon',
     'whitespace/indent',
+    'whitespace/indent_namespace',
     'whitespace/line_length',
     'whitespace/newline',
     'whitespace/operators',
@@ -365,15 +373,49 @@ _MACHINE_OUTPUTS = [
 # These error categories are no longer enforced by cpplint, but for backwards-
 # compatibility they may still appear in NOLINT comments.
 _LEGACY_ERROR_CATEGORIES = [
+    'build/class',
     'readability/streams',
     'readability/function',
     ]
 
+# These prefixes for categories should be ignored since they relate to other
+# tools which also use the NOLINT syntax, e.g. clang-tidy.
+_OTHER_NOLINT_CATEGORY_PREFIXES = [
+    'clang-analyzer-',
+    'abseil-',
+    'altera-',
+    'android-',
+    'boost-',
+    'bugprone-',
+    'cert-',
+    'concurrency-',
+    'cppcoreguidelines-',
+    'darwin-',
+    'fuchsia-',
+    'google-',
+    'hicpp-',
+    'linuxkernel-',
+    'llvm-',
+    'llvmlibc-',
+    'misc-',
+    'modernize-',
+    'mpi-',
+    'objc-',
+    'openmp-',
+    'performance-',
+    'portability-',
+    'readability-',
+    'zircon-',
+    ]
+
 # The default state of the category filter. This is overridden by the --filter=
 # flag. By default all errors are on, so only add here categories that should be
 # off by default (i.e., categories that must be enabled by the --filter= flags).
 # All entries here should start with a '-' or '+', as in the --filter= flag.
-_DEFAULT_FILTERS = ['-build/include_alpha']
+_DEFAULT_FILTERS = [
+    '-build/include_alpha',
+    '-readability/fn_size',
+    ]
 
 # The default list of categories suppressed for C (not C++) files.
 _DEFAULT_C_SUPPRESSED_CATEGORIES = [
@@ -397,7 +439,7 @@ _CPP_HEADERS = frozenset([
     'alloc.h',
     'builtinbuf.h',
     'bvector.h',
-    'complex.h',
+    # 'complex.h', collides with System C header "complex.h" since C11
     'defalloc.h',
     'deque.h',
     'editbuf.h',
@@ -443,7 +485,7 @@ _CPP_HEADERS = frozenset([
     'tree.h',
     'type_traits.h',
     'vector.h',
-    # 17.6.1.2 C++ library headers
+    # C++ library headers
     'algorithm',
     'array',
     'atomic',
@@ -497,9 +539,9 @@ _CPP_HEADERS = frozenset([
     'utility',
     'valarray',
     'vector',
-    # 17.6.1.2 C++14 headers
+    # C++14 headers
     'shared_mutex',
-    # 17.6.1.2 C++17 headers
+    # C++17 headers
     'any',
     'charconv',
     'codecvt',
@@ -509,7 +551,33 @@ _CPP_HEADERS = frozenset([
     'optional',
     'string_view',
     'variant',
-    # 17.6.1.2 C++ headers for C library facilities
+    # C++20 headers
+    'barrier',
+    'bit',
+    'compare',
+    'concepts',
+    'coroutine',
+    'format',
+    'latch'
+    'numbers',
+    'ranges',
+    'semaphore',
+    'source_location',
+    'span',
+    'stop_token',
+    'syncstream',
+    'version',
+    # C++23 headers
+    'expected',
+    'flat_map',
+    'flat_set',
+    'generator',
+    'mdspan',
+    'print',
+    'spanstream',
+    'stacktrace',
+    'stdfloat',
+    # C++ headers for C library facilities
     'cassert',
     'ccomplex',
     'cctype',
@@ -570,6 +638,9 @@ _C_HEADERS = frozenset([
     'uchar.h',
     'wchar.h',
     'wctype.h',
+    # C23 headers
+    'stdbit.h',
+    'stdckdint.h',
     # additional POSIX C headers
     'aio.h',
     'arpa/inet.h',
@@ -761,16 +832,16 @@ _CHECK_REPLACEMENT = dict([(macro_var, {}) for macro_var in _CHECK_MACROS])
 for op, replacement in [('==', 'EQ'), ('!=', 'NE'),
                         ('>=', 'GE'), ('>', 'GT'),
                         ('<=', 'LE'), ('<', 'LT')]:
-  _CHECK_REPLACEMENT['DCHECK'][op] = 'DCHECK_%s' % replacement
-  _CHECK_REPLACEMENT['CHECK'][op] = 'CHECK_%s' % replacement
-  _CHECK_REPLACEMENT['EXPECT_TRUE'][op] = 'EXPECT_%s' % replacement
-  _CHECK_REPLACEMENT['ASSERT_TRUE'][op] = 'ASSERT_%s' % replacement
+  _CHECK_REPLACEMENT['DCHECK'][op] = f'DCHECK_{replacement}'
+  _CHECK_REPLACEMENT['CHECK'][op] = f'CHECK_{replacement}'
+  _CHECK_REPLACEMENT['EXPECT_TRUE'][op] = f'EXPECT_{replacement}'
+  _CHECK_REPLACEMENT['ASSERT_TRUE'][op] = f'ASSERT_{replacement}'
 
 for op, inv_replacement in [('==', 'NE'), ('!=', 'EQ'),
                             ('>=', 'LT'), ('>', 'LE'),
                             ('<=', 'GT'), ('<', 'GE')]:
-  _CHECK_REPLACEMENT['EXPECT_FALSE'][op] = 'EXPECT_%s' % inv_replacement
-  _CHECK_REPLACEMENT['ASSERT_FALSE'][op] = 'ASSERT_%s' % inv_replacement
+  _CHECK_REPLACEMENT['EXPECT_FALSE'][op] = f'EXPECT_{inv_replacement}'
+  _CHECK_REPLACEMENT['ASSERT_FALSE'][op] = f'ASSERT_{inv_replacement}'
 
 # Alternative tokens and their replacements.  For full list, see section 2.5
 # Alternative tokens [lex.digraph] in the C++ standard.
@@ -797,7 +868,7 @@ _ALT_TOKEN_REPLACEMENT = {
 # False positives include C-style multi-line comments and multi-line strings
 # but those have always been troublesome for cpplint.
 _ALT_TOKEN_REPLACEMENT_PATTERN = re.compile(
-    r'[ =()](' + ('|'.join(_ALT_TOKEN_REPLACEMENT.keys())) + r')(?=[ (]|$)')
+    r'([ =()])(' + ('|'.join(_ALT_TOKEN_REPLACEMENT.keys())) + r')([ (]|$)')
 
 
 # These constants define types of headers for use with
@@ -843,8 +914,6 @@ _SED_FIXUPS = {
   'Missing space after ,': r's/,\([^ ]\)/, \1/g',
 }
 
-_regexp_compile_cache = {}
-
 # {str, set(int)}: a map from error categories to sets of linenumbers
 # on which those errors are expected and should be suppressed.
 _error_suppressions = {}
@@ -862,7 +931,7 @@ _repository = None
 # Files to exclude from linting. This is set by the --exclude flag.
 _excludes = None
 
-# Whether to supress all PrintInfo messages, UNRELATED to --quiet flag
+# Whether to suppress all PrintInfo messages, UNRELATED to --quiet flag
 _quiet = False
 
 # The allowed line length of files.
@@ -872,41 +941,79 @@ _line_length = 80
 # This allows to use different include order rule than default
 _include_order = "default"
 
-try:
-  unicode
-except NameError:
-  #  -- pylint: disable=redefined-builtin
-  basestring = unicode = str
-
-try:
-  long
-except NameError:
-  #  -- pylint: disable=redefined-builtin
-  long = int
-
-if sys.version_info < (3,):
-  #  -- pylint: disable=no-member
-  # BINARY_TYPE = str
-  itervalues = dict.itervalues
-  iteritems = dict.iteritems
-else:
-  # BINARY_TYPE = bytes
-  itervalues = dict.values
-  iteritems = dict.items
-
-def unicode_escape_decode(x):
-  if sys.version_info < (3,):
-    return codecs.unicode_escape_decode(x)[0]
-  else:
-    return x
+# This allows different config files to be used
+_config_filename = "CPPLINT.cfg"
 
 # Treat all headers starting with 'h' equally: .h, .hpp, .hxx etc.
 # This is set by --headers flag.
 _hpp_headers = set([])
 
-# {str, bool}: a map from error categories to booleans which indicate if the
-# category should be suppressed for every line.
-_global_error_suppressions = {}
+class ErrorSuppressions:
+  """Class to track all error suppressions for cpplint"""
+
+  class LineRange:
+    """Class to represent a range of line numbers for which an error is suppressed"""
+    def __init__(self, begin, end):
+      self.begin = begin
+      self.end = end
+
+    def __str__(self):
+      return f'[{self.begin}-{self.end}]'
+
+    def __contains__(self, obj):
+      return self.begin <= obj <= self.end
+
+    def ContainsRange(self, other):
+      return self.begin <= other.begin and self.end >= other.end
+
+  def __init__(self):
+    self._suppressions = collections.defaultdict(list)
+    self._open_block_suppression = None
+
+  def _AddSuppression(self, category, line_range):
+    suppressed = self._suppressions[category]
+    if not (suppressed and suppressed[-1].ContainsRange(line_range)):
+      suppressed.append(line_range)
+
+  def GetOpenBlockStart(self):
+    """:return: The start of the current open block or `-1` if there is not an open block"""
+    return self._open_block_suppression.begin if self._open_block_suppression else -1
+
+  def AddGlobalSuppression(self, category):
+    """Add a suppression for `category` which is suppressed for the whole file"""
+    self._AddSuppression(category, self.LineRange(0, math.inf))
+
+  def AddLineSuppression(self, category, linenum):
+    """Add a suppression for `category` which is suppressed only on `linenum`"""
+    self._AddSuppression(category, self.LineRange(linenum, linenum))
+
+  def StartBlockSuppression(self, category, linenum):
+    """Start a suppression block for `category` on `linenum`. inclusive"""
+    if self._open_block_suppression is None:
+      self._open_block_suppression = self.LineRange(linenum, math.inf)
+    self._AddSuppression(category, self._open_block_suppression)
+
+  def EndBlockSuppression(self, linenum):
+    """End the current block suppression on `linenum`. inclusive"""
+    if self._open_block_suppression:
+      self._open_block_suppression.end = linenum
+      self._open_block_suppression = None
+
+  def IsSuppressed(self, category, linenum):
+    """:return: `True` if `category` is suppressed for `linenum`"""
+    suppressed = self._suppressions[category] + self._suppressions[None]
+    return any(linenum in lr for lr in suppressed)
+
+  def HasOpenBlock(self):
+    """:return: `True` if a block suppression was started but not ended"""
+    return self._open_block_suppression is not None
+
+  def Clear(self):
+    """Clear all current error suppressions"""
+    self._suppressions.clear()
+    self._open_block_suppression = None
+
+_error_suppressions = ErrorSuppressions()
 
 def ProcessHppHeadersOption(val):
   global _hpp_headers
@@ -948,7 +1055,7 @@ def ProcessExtensionsOption(val):
   except ValueError:
     PrintUsage('Extensions should be a comma-separated list of values;'
                'for example: extensions=hpp,cpp\n'
-               'This could not be parsed: "%s"' % (val,))
+              f'This could not be parsed: "{val}"')
 
 def GetNonHeaderExtensions():
   return GetAllExtensions().difference(GetHeaderExtensions())
@@ -966,26 +1073,50 @@ def ParseNolintSuppressions(filename, raw_line, linenum, error):
     linenum: int, the number of the current line.
     error: function, an error handler.
   """
-  matched = Search(r'\bNOLINT(NEXTLINE)?\b(\([^)]+\))?', raw_line)
+  matched = re.search(r'\bNOLINT(NEXTLINE|BEGIN|END)?\b(\([^)]+\))?', raw_line)
   if matched:
-    if matched.group(1):
-      suppressed_line = linenum + 1
-    else:
-      suppressed_line = linenum
-    category = matched.group(2)
-    if category in (None, '(*)'):  # => "suppress all"
-      _error_suppressions.setdefault(None, set()).add(suppressed_line)
+    no_lint_type = matched.group(1)
+    if no_lint_type == 'NEXTLINE':
+      def ProcessCategory(category):
+        _error_suppressions.AddLineSuppression(category, linenum + 1)
+    elif no_lint_type == 'BEGIN':
+      if _error_suppressions.HasOpenBlock():
+        error(filename, linenum, 'readability/nolint', 5,
+              f'NONLINT block already defined on line {_error_suppressions.GetOpenBlockStart()}')
+
+      def ProcessCategory(category):
+        _error_suppressions.StartBlockSuppression(category, linenum)
+    elif no_lint_type == 'END':
+      if not _error_suppressions.HasOpenBlock():
+        error(filename, linenum, 'readability/nolint', 5, 'Not in a NOLINT block')
+
+      def ProcessCategory(category):
+        if category is not None:
+          error(filename, linenum, 'readability/nolint', 5,
+                f'NOLINT categories not supported in block END: {category}')
+        _error_suppressions.EndBlockSuppression(linenum)
     else:
-      if category.startswith('(') and category.endswith(')'):
-        category = category[1:-1]
+      def ProcessCategory(category):
+        _error_suppressions.AddLineSuppression(category, linenum)
+    categories = matched.group(2)
+    if categories in (None, '(*)'):  # => "suppress all"
+      ProcessCategory(None)
+    elif categories.startswith('(') and categories.endswith(')'):
+      for category in set(map(lambda c: c.strip(), categories[1:-1].split(','))):
         if category in _ERROR_CATEGORIES:
-          _error_suppressions.setdefault(category, set()).add(suppressed_line)
+          ProcessCategory(category)
+        elif any(c for c in _OTHER_NOLINT_CATEGORY_PREFIXES if category.startswith(c)):
+          # Ignore any categories from other tools.
+          pass
         elif category not in _LEGACY_ERROR_CATEGORIES:
           error(filename, linenum, 'readability/nolint', 5,
-                'Unknown NOLINT error category: %s' % category)
-
+                f'Unknown NOLINT error category: {category}')
 
 def ProcessGlobalSuppresions(lines):
+  """Deprecated; use ProcessGlobalSuppressions."""
+  ProcessGlobalSuppressions(lines)
+
+def ProcessGlobalSuppressions(lines):
   """Updates the list of global error suppressions.
 
   Parses any lint directives in the file that have global effect.
@@ -997,69 +1128,31 @@ def ProcessGlobalSuppresions(lines):
   for line in lines:
     if _SEARCH_C_FILE.search(line):
       for category in _DEFAULT_C_SUPPRESSED_CATEGORIES:
-        _global_error_suppressions[category] = True
+        _error_suppressions.AddGlobalSuppression(category)
     if _SEARCH_KERNEL_FILE.search(line):
       for category in _DEFAULT_KERNEL_SUPPRESSED_CATEGORIES:
-        _global_error_suppressions[category] = True
+        _error_suppressions.AddGlobalSuppression(category)
 
 
 def ResetNolintSuppressions():
   """Resets the set of NOLINT suppressions to empty."""
-  _error_suppressions.clear()
-  _global_error_suppressions.clear()
+  _error_suppressions.Clear()
 
 
 def IsErrorSuppressedByNolint(category, linenum):
   """Returns true if the specified error category is suppressed on this line.
 
   Consults the global error_suppressions map populated by
-  ParseNolintSuppressions/ProcessGlobalSuppresions/ResetNolintSuppressions.
+  ParseNolintSuppressions/ProcessGlobalSuppressions/ResetNolintSuppressions.
 
   Args:
     category: str, the category of the error.
     linenum: int, the current line number.
   Returns:
-    bool, True iff the error should be suppressed due to a NOLINT comment or
-    global suppression.
-  """
-  return (_global_error_suppressions.get(category, False) or
-          linenum in _error_suppressions.get(category, set()) or
-          linenum in _error_suppressions.get(None, set()))
-
-
-def Match(pattern, s):
-  """Matches the string with the pattern, caching the compiled regexp."""
-  # The regexp compilation caching is inlined in both Match and Search for
-  # performance reasons; factoring it out into a separate function turns out
-  # to be noticeably expensive.
-  if pattern not in _regexp_compile_cache:
-    _regexp_compile_cache[pattern] = sre_compile.compile(pattern)
-  return _regexp_compile_cache[pattern].match(s)
-
-
-def ReplaceAll(pattern, rep, s):
-  """Replaces instances of pattern in a string with a replacement.
-
-  The compiled regex is kept in a cache shared by Match and Search.
-
-  Args:
-    pattern: regex pattern
-    rep: replacement text
-    s: search string
-
-  Returns:
-    string with replacements made (or original string if no replacements)
+    bool, True iff the error should be suppressed due to a NOLINT comment,
+    block suppression or global suppression.
   """
-  if pattern not in _regexp_compile_cache:
-    _regexp_compile_cache[pattern] = sre_compile.compile(pattern)
-  return _regexp_compile_cache[pattern].sub(rep, s)
-
-
-def Search(pattern, s):
-  """Searches the string for the pattern, caching the compiled regexp."""
-  if pattern not in _regexp_compile_cache:
-    _regexp_compile_cache[pattern] = sre_compile.compile(pattern)
-  return _regexp_compile_cache[pattern].search(s)
+  return _error_suppressions.IsSuppressed(category, linenum)
 
 
 def _IsSourceExtension(s):
@@ -1179,7 +1272,7 @@ class _IncludeState(object):
     # If previous line was a blank line, assume that the headers are
     # intentionally sorted the way they are.
     if (self._last_header > header_path and
-        Match(r'^\s*#\s*include\b', clean_lines.elided[linenum - 1])):
+        re.match(r'^\s*#\s*include\b', clean_lines.elided[linenum - 1])):
       return False
     return True
 
@@ -1197,9 +1290,8 @@ class _IncludeState(object):
       error message describing what's wrong.
 
     """
-    error_message = ('Found %s after %s' %
-                     (self._TYPE_NAMES[header_type],
-                      self._SECTION_NAMES[self._section]))
+    error_message = (f'Found {self._TYPE_NAMES[header_type]}'
+                     f' after {self._SECTION_NAMES[self._section]}')
 
     last_section = self._section
 
@@ -1255,7 +1347,7 @@ class _CppLintState(object):
     self._filters_backup = self.filters[:]
     self.counting = 'total'  # In what way are we counting errors?
     self.errors_by_category = {}  # string to int dict storing error counts
-    self.quiet = False  # Suppress non-error messagess?
+    self.quiet = False  # Suppress non-error messages?
 
     # output format:
     # "emacs" - format that emacs can parse (default)
@@ -1318,7 +1410,7 @@ class _CppLintState(object):
     for filt in self.filters:
       if not (filt.startswith('+') or filt.startswith('-')):
         raise ValueError('Every filter in --filters must start with + or -'
-                         ' (%s does not)' % filt)
+                        f' ({filt} does not)')
 
   def BackupFilters(self):
     """ Saves the current filter list to backup storage."""
@@ -1345,11 +1437,10 @@ class _CppLintState(object):
 
   def PrintErrorCounts(self):
     """Print a summary of errors by category, and the total."""
-    for category, count in sorted(iteritems(self.errors_by_category)):
-      self.PrintInfo('Category \'%s\' errors found: %d\n' %
-                       (category, count))
+    for category, count in sorted(dict.items(self.errors_by_category)):
+      self.PrintInfo(f'Category \'{category}\' errors found: {count}\n')
     if self.error_count > 0:
-      self.PrintInfo('Total errors found: %d\n' % self.error_count)
+      self.PrintInfo(f'Total errors found: {self.error_count}\n')
 
   def PrintInfo(self, message):
     # _quiet does not represent --quiet flag.
@@ -1521,7 +1612,7 @@ class _FunctionState(object):
     if not self.in_a_function:
       return
 
-    if Match(r'T(EST|est)', self.current_function):
+    if re.match(r'T(EST|est)', self.current_function):
       base_trigger = self._TEST_TRIGGER
     else:
       base_trigger = self._NORMAL_TRIGGER
@@ -1534,9 +1625,8 @@ class _FunctionState(object):
         error_level = 5
       error(filename, linenum, 'readability/fn_size', error_level,
             'Small and focused functions are preferred:'
-            ' %s has %d non-comment lines'
-            ' (error triggered by exceeding %d lines).'  % (
-                self.current_function, self.lines_in_function, trigger))
+            f' {self.current_function} has {self.lines_in_function} non-comment lines'
+            f' (error triggered by exceeding {trigger} lines).')
 
   def End(self):
     """Stop analyzing function body."""
@@ -1611,6 +1701,7 @@ class FileInfo(object):
             os.path.exists(os.path.join(current_dir, ".hg")) or
             os.path.exists(os.path.join(current_dir, ".svn"))):
           root_dir = current_dir
+          break
         current_dir = os.path.dirname(current_dir)
 
       if (os.path.exists(os.path.join(root_dir, ".git")) or
@@ -1653,7 +1744,7 @@ class FileInfo(object):
     return _IsSourceExtension(self.Extension()[1:])
 
 
-def _ShouldPrintError(category, confidence, linenum):
+def _ShouldPrintError(category, confidence, filename, linenum):
   """If confidence >= verbose, category passes filter and is not suppressed."""
 
   # There are three ways we might decide not to print an error message:
@@ -1667,11 +1758,16 @@ def _ShouldPrintError(category, confidence, linenum):
 
   is_filtered = False
   for one_filter in _Filters():
+    filter_cat, filter_file, filter_line = _ParseFilterSelector(one_filter[1:])
+    category_match = category.startswith(filter_cat)
+    file_match = filter_file == "" or filter_file == filename
+    line_match = filter_line == linenum or filter_line == -1
+
     if one_filter.startswith('-'):
-      if category.startswith(one_filter[1:]):
+      if category_match and file_match and line_match:
         is_filtered = True
     elif one_filter.startswith('+'):
-      if category.startswith(one_filter[1:]):
+      if category_match and file_match and line_match:
         is_filtered = False
     else:
       assert False  # should have been checked for in SetFilter.
@@ -1688,9 +1784,9 @@ def Error(filename, linenum, category, confidence, message):
   that is, how certain we are this is a legitimate style regression, and
   not a misidentification or a use that's sometimes justified.
 
-  False positives can be suppressed by the use of
-  "cpplint(category)"  comments on the offending line.  These are
-  parsed into _error_suppressions.
+  False positives can be suppressed by the use of "NOLINT(category)"
+  comments, NOLINTNEXTLINE or in blocks started by NOLINTBEGIN.  These
+  are parsed into _error_suppressions.
 
   Args:
     filename: The name of the file containing the error.
@@ -1703,29 +1799,30 @@ def Error(filename, linenum, category, confidence, message):
       and 1 meaning that it could be a legitimate construct.
     message: The error message.
   """
-  if _ShouldPrintError(category, confidence, linenum):
+  if _ShouldPrintError(category, confidence, filename, linenum):
     _cpplint_state.IncrementErrorCount(category)
     if _cpplint_state.output_format == 'vs7':
-      _cpplint_state.PrintError('%s(%s): error cpplint: [%s] %s [%d]\n' % (
-          filename, linenum, category, message, confidence))
+      _cpplint_state.PrintError(f'{filename}({linenum}): error cpplint:'
+                                f' [{category}] {message} [{confidence}]\n')
     elif _cpplint_state.output_format == 'eclipse':
-      sys.stderr.write('%s:%s: warning: %s  [%s] [%d]\n' % (
-          filename, linenum, message, category, confidence))
+      sys.stderr.write(f'{filename}:{linenum}: warning:'
+                       f' {message}  [{category}] [{confidence}]\n')
     elif _cpplint_state.output_format == 'junit':
-      _cpplint_state.AddJUnitFailure(filename, linenum, message, category,
-          confidence)
+      _cpplint_state.AddJUnitFailure(filename, linenum, message, category, confidence)
     elif _cpplint_state.output_format in ['sed', 'gsed']:
       if message in _SED_FIXUPS:
-        sys.stdout.write(_cpplint_state.output_format + " -i '%s%s' %s # %s  [%s] [%d]\n" % (
-            linenum, _SED_FIXUPS[message], filename, message, category, confidence))
+        sys.stdout.write(f"{_cpplint_state.output_format} -i"
+                         f" '{linenum}{_SED_FIXUPS[message]}' {filename}"
+                         f" # {message}  [{category}] [{confidence}]\n")
       else:
-        sys.stderr.write('# %s:%s:  "%s"  [%s] [%d]\n' % (
-            filename, linenum, message, category, confidence))
+        sys.stderr.write(f'# {filename}:{linenum}: '
+                         f' "{message}"  [{category}] [{confidence}]\n')
     else:
-      final_message = '%s:%s:  %s  [%s] [%d]\n' % (
-          filename, linenum, message, category, confidence)
+      final_message = (f'{filename}:{linenum}: '
+                       f' {message}  [{category}] [{confidence}]\n')
       sys.stderr.write(final_message)
 
+
 # Matches standard C++ escape sequences per 2.13.2.3 of the C++ standard.
 _RE_PATTERN_CLEANSE_LINE_ESCAPES = re.compile(
     r'\\([abfnrtv?"\\\']|\d+|x[0-9a-fA-F]+)')
@@ -1793,7 +1890,7 @@ def CleanseRawStrings(raw_lines):
         # Found the end of the string, match leading space for this
         # line and resume copying the original lines, and also insert
         # a "" on the last line.
-        leading_space = Match(r'^(\s*)\S', line)
+        leading_space = re.match(r'^(\s*)\S', line)
         line = leading_space.group(1) + '""' + line[end + len(delimiter):]
         delimiter = None
       else:
@@ -1814,9 +1911,9 @@ def CleanseRawStrings(raw_lines):
       # before removing raw strings.  This is because there are some
       # cpplint checks that requires the comments to be preserved, but
       # we don't want to check comments that are inside raw strings.
-      matched = Match(r'^(.*?)\b(?:R|u8R|uR|UR|LR)"([^\s\\()]*)\((.*)$', line)
+      matched = re.match(r'^(.*?)\b(?:R|u8R|uR|UR|LR)"([^\s\\()]*)\((.*)$', line)
       if (matched and
-          not Match(r'^([^\'"]|\'(\\.|[^\'])*\'|"(\\.|[^"])*")*//',
+          not re.match(r'^([^\'"]|\'(\\.|[^\'])*\'|"(\\.|[^"])*")*//',
                     matched.group(1))):
         delimiter = ')' + matched.group(2) + '"'
 
@@ -1899,6 +1996,28 @@ def CleanseComments(line):
   return _RE_PATTERN_CLEANSE_LINE_C_COMMENTS.sub('', line)
 
 
+def ReplaceAlternateTokens(line):
+  """Replace any alternate token by its original counterpart.
+
+  In order to comply with the google rule stating that unary operators should
+  never be followed by a space, an exception is made for the 'not' and 'compl'
+  alternate tokens. For these, any trailing space is removed during the
+  conversion.
+
+  Args:
+    line: The line being processed.
+
+  Returns:
+    The line with alternate tokens replaced.
+  """
+  for match in _ALT_TOKEN_REPLACEMENT_PATTERN.finditer(line):
+    token = _ALT_TOKEN_REPLACEMENT[match.group(2)]
+    tail = '' if match.group(2) in ['not', 'compl'] and match.group(3) == ' ' \
+           else r'\3'
+    line = re.sub(match.re, rf'\1{token}{tail}', line, count=1)
+  return line
+
+
 class CleansedLines(object):
   """Holds 4 copies of all lines with different preprocessing applied to them.
 
@@ -1911,15 +2030,17 @@ class CleansedLines(object):
   """
 
   def __init__(self, lines):
+    if '-readability/alt_tokens' in _cpplint_state.filters:
+      for i, line in enumerate(lines):
+        lines[i] = ReplaceAlternateTokens(line)
     self.elided = []
     self.lines = []
     self.raw_lines = lines
     self.num_lines = len(lines)
     self.lines_without_raw_strings = CleanseRawStrings(lines)
-    for linenum in range(len(self.lines_without_raw_strings)):
-      self.lines.append(CleanseComments(
-          self.lines_without_raw_strings[linenum]))
-      elided = self._CollapseStrings(self.lines_without_raw_strings[linenum])
+    for line in self.lines_without_raw_strings:
+      self.lines.append(CleanseComments(line))
+      elided = self._CollapseStrings(line)
       self.elided.append(CleanseComments(elided))
 
   def NumLines(self):
@@ -1952,7 +2073,7 @@ class CleansedLines(object):
     collapsed = ''
     while True:
       # Find the first quote character
-      match = Match(r'^([^\'"]*)([\'"])(.*)$', elided)
+      match = re.match(r'^([^\'"]*)([\'"])(.*)$', elided)
       if not match:
         collapsed += elided
         break
@@ -1977,8 +2098,8 @@ class CleansedLines(object):
         # correctly as long as there are digits on both sides of the
         # separator.  So we are fine as long as we don't see something
         # like "0.'3" (gcc 4.9.0 will not allow this literal).
-        if Search(r'\b(?:0[bBxX]?|[1-9])[0-9a-fA-F]*$', head):
-          match_literal = Match(r'^((?:\'?[0-9a-zA-Z_])*)(.*)$', "'" + tail)
+        if re.search(r'\b(?:0[bBxX]?|[1-9])[0-9a-fA-F]*$', head):
+          match_literal = re.match(r'^((?:\'?[0-9a-zA-Z_])*)(.*)$', "'" + tail)
           collapsed += head + match_literal.group(1).replace("'", '')
           elided = match_literal.group(2)
         else:
@@ -2007,7 +2128,7 @@ def FindEndOfExpressionInLine(line, startpos, stack):
     On finding an unclosed expression: (-1, None)
     Otherwise: (-1, new stack at end of this line)
   """
-  for i in xrange(startpos, len(line)):
+  for i in range(startpos, len(line)):
     char = line[i]
     if char in '([{':
       # Found start of parenthesized expression, push to expression stack
@@ -2020,7 +2141,7 @@ def FindEndOfExpressionInLine(line, startpos, stack):
           stack.pop()
           if not stack:
             return (-1, None)
-      elif i > 0 and Search(r'\boperator\s*$', line[0:i]):
+      elif i > 0 and re.search(r'\boperator\s*$', line[0:i]):
         # operator<, don't add to stack
         continue
       else:
@@ -2049,7 +2170,7 @@ def FindEndOfExpressionInLine(line, startpos, stack):
 
       # Ignore "->" and operator functions
       if (i > 0 and
-          (line[i - 1] == '-' or Search(r'\boperator\s*$', line[0:i - 1]))):
+          (line[i - 1] == '-' or re.search(r'\boperator\s*$', line[0:i - 1]))):
         continue
 
       # Pop the stack if there is a matching '<'.  Otherwise, ignore
@@ -2096,7 +2217,7 @@ def CloseExpression(clean_lines, linenum, pos):
   """
 
   line = clean_lines.elided[linenum]
-  if (line[pos] not in '({[<') or Match(r'<[<=]', line[pos:]):
+  if (line[pos] not in '({[<') or re.match(r'<[<=]', line[pos:]):
     return (line, clean_lines.NumLines(), -1)
 
   # Check first line
@@ -2144,8 +2265,8 @@ def FindStartOfExpressionInLine(line, endpos, stack):
       # Ignore it if it's a "->" or ">=" or "operator>"
       if (i > 0 and
           (line[i - 1] == '-' or
-           Match(r'\s>=\s', line[i - 1:]) or
-           Search(r'\boperator\s*$', line[0:i]))):
+           re.match(r'\s>=\s', line[i - 1:]) or
+           re.search(r'\boperator\s*$', line[0:i]))):
         i -= 1
       else:
         stack.append('>')
@@ -2236,7 +2357,7 @@ def CheckForCopyright(filename, lines, error):
 
   # We'll say it should occur by line 10. Don't forget there's a
   # placeholder line at the front.
-  for line in xrange(1, min(len(lines), 11)):
+  for line in range(1, min(len(lines), 11)):
     if re.search(r'Copyright', lines[line], re.I): break
   else:                       # means no copyright line was found
     error(filename, 0, 'legal/copyright', 5,
@@ -2253,7 +2374,7 @@ def GetIndentLevel(line):
   Returns:
     An integer count of leading spaces, possibly zero.
   """
-  indent = Match(r'^( *)\S', line)
+  indent = re.match(r'^( *)\S', line)
   if indent:
     return len(indent.group(1))
   else:
@@ -2308,8 +2429,8 @@ def GetHeaderGuardCPPVariable(filename):
 
   def FixupPathFromRoot():
     if _root_debug:
-      sys.stderr.write("\n_root fixup, _root = '%s', repository name = '%s'\n"
-          % (_root, fileinfo.RepositoryName()))
+      sys.stderr.write(f"\n_root fixup, _root = '{_root}',"
+                       f" repository name = '{fileinfo.RepositoryName()}'\n")
 
     # Process the file path with the --root flag if it was set.
     if not _root:
@@ -2352,7 +2473,7 @@ def GetHeaderGuardCPPVariable(filename):
       return os.path.join(*maybe_path)
 
     if _root_debug:
-      sys.stderr.write("_root ignore, returning %s\n" % (file_path_from_root))
+      sys.stderr.write(f"_root ignore, returning {file_path_from_root}\n")
 
     #   --root=FAKE_DIR is ignored
     return file_path_from_root
@@ -2361,7 +2482,7 @@ def GetHeaderGuardCPPVariable(filename):
   return re.sub(r'[^a-zA-Z0-9]', '_', file_path_from_root).upper() + '_'
 
 
-def CheckForHeaderGuard(filename, clean_lines, error):
+def CheckForHeaderGuard(filename, clean_lines, error, cppvar):
   """Checks that the file contains a header guard.
 
   Logs an error if no #ifndef header guard is present.  For other
@@ -2381,16 +2502,14 @@ def CheckForHeaderGuard(filename, clean_lines, error):
   # and not the general NOLINT or NOLINT(*) syntax.
   raw_lines = clean_lines.lines_without_raw_strings
   for i in raw_lines:
-    if Search(r'//\s*NOLINT\(build/header_guard\)', i):
+    if re.search(r'//\s*NOLINT\(build/header_guard\)', i):
       return
 
   # Allow pragma once instead of header guards
   for i in raw_lines:
-    if Search(r'^\s*#pragma\s+once', i):
+    if re.search(r'^\s*#pragma\s+once', i):
       return
 
-  cppvar = GetHeaderGuardCPPVariable(filename)
-
   ifndef = ''
   ifndef_linenum = 0
   define = ''
@@ -2413,8 +2532,7 @@ def CheckForHeaderGuard(filename, clean_lines, error):
 
   if not ifndef or not define or ifndef != define:
     error(filename, 0, 'build/header_guard', 5,
-          'No #ifndef header guard found, suggested CPP variable is: %s' %
-          cppvar)
+          f'No #ifndef header guard found, suggested CPP variable is: {cppvar}')
     return
 
   # The guard should be PATH_FILE_H_, but we also allow PATH_FILE_H__
@@ -2427,41 +2545,41 @@ def CheckForHeaderGuard(filename, clean_lines, error):
     ParseNolintSuppressions(filename, raw_lines[ifndef_linenum], ifndef_linenum,
                             error)
     error(filename, ifndef_linenum, 'build/header_guard', error_level,
-          '#ifndef header guard has wrong style, please use: %s' % cppvar)
+          f'#ifndef header guard has wrong style, please use: {cppvar}')
 
   # Check for "//" comments on endif line.
   ParseNolintSuppressions(filename, raw_lines[endif_linenum], endif_linenum,
                           error)
-  match = Match(r'#endif\s*//\s*' + cppvar + r'(_)?\b', endif)
+  match = re.match(r'#endif\s*//\s*' + cppvar + r'(_)?\b', endif)
   if match:
     if match.group(1) == '_':
       # Issue low severity warning for deprecated double trailing underscore
       error(filename, endif_linenum, 'build/header_guard', 0,
-            '#endif line should be "#endif  // %s"' % cppvar)
+            f'#endif line should be "#endif  // {cppvar}"')
     return
 
   # Didn't find the corresponding "//" comment.  If this file does not
   # contain any "//" comments at all, it could be that the compiler
   # only wants "/**/" comments, look for those instead.
   no_single_line_comments = True
-  for i in xrange(1, len(raw_lines) - 1):
+  for i in range(1, len(raw_lines) - 1):
     line = raw_lines[i]
-    if Match(r'^(?:(?:\'(?:\.|[^\'])*\')|(?:"(?:\.|[^"])*")|[^\'"])*//', line):
+    if re.match(r'^(?:(?:\'(?:\.|[^\'])*\')|(?:"(?:\.|[^"])*")|[^\'"])*//', line):
       no_single_line_comments = False
       break
 
   if no_single_line_comments:
-    match = Match(r'#endif\s*/\*\s*' + cppvar + r'(_)?\s*\*/', endif)
+    match = re.match(r'#endif\s*/\*\s*' + cppvar + r'(_)?\s*\*/', endif)
     if match:
       if match.group(1) == '_':
         # Low severity warning for double trailing underscore
         error(filename, endif_linenum, 'build/header_guard', 0,
-              '#endif line should be "#endif  /* %s */"' % cppvar)
+              f'#endif line should be "#endif  /* {cppvar} */"')
       return
 
   # Didn't find anything
   error(filename, endif_linenum, 'build/header_guard', 5,
-        '#endif line should be "#endif  // %s"' % cppvar)
+        f'#endif line should be "#endif  // {cppvar}"')
 
 
 def CheckHeaderFileIncluded(filename, include_state, error):
@@ -2469,16 +2587,16 @@ def CheckHeaderFileIncluded(filename, include_state, error):
 
   # Do not check test files
   fileinfo = FileInfo(filename)
-  if Search(_TEST_FILE_SUFFIX, fileinfo.BaseName()):
+  if re.search(_TEST_FILE_SUFFIX, fileinfo.BaseName()):
     return
 
+  first_include = message = None
+  basefilename = filename[0:len(filename) - len(fileinfo.Extension())]
   for ext in GetHeaderExtensions():
-    basefilename = filename[0:len(filename) - len(fileinfo.Extension())]
     headerfile = basefilename + '.' + ext
     if not os.path.exists(headerfile):
       continue
     headername = FileInfo(headerfile).RepositoryName()
-    first_include = None
     include_uses_unix_dir_aliases = False
     for section_list in include_state.include_list:
       for f in section_list:
@@ -2490,10 +2608,11 @@ def CheckHeaderFileIncluded(filename, include_state, error):
         if not first_include:
           first_include = f[1]
 
-    message = '%s should include its header file %s' % (fileinfo.RepositoryName(), headername)
+    message = f'{fileinfo.RepositoryName()} should include its header file {headername}'
     if include_uses_unix_dir_aliases:
       message += ". Relative paths like . and .. are not allowed."
 
+  if message:
     error(filename, first_include, 'build/include', 5, message)
 
 
@@ -2515,7 +2634,7 @@ def CheckForBadCharacters(filename, lines, error):
     error: The function to call with any errors found.
   """
   for linenum, line in enumerate(lines):
-    if unicode_escape_decode('\ufffd') in line:
+    if '\ufffd' in line:
       error(filename, linenum, 'readability/utf8', 5,
             'Line contains invalid UTF-8 (or Unicode replacement character).')
     if '\0' in line:
@@ -2627,7 +2746,7 @@ def CheckPosixThreading(filename, clean_lines, linenum, error):
   for single_thread_func, multithread_safe_func, pattern in _THREADING_LIST:
     # Additional pattern matching check to confirm that this is the
     # function we are looking for
-    if Search(pattern, line):
+    if re.search(pattern, line):
       error(filename, linenum, 'runtime/threadsafe_fn', 2,
             'Consider using ' + multithread_safe_func +
             '...) instead of ' + single_thread_func +
@@ -2647,7 +2766,7 @@ def CheckVlogArguments(filename, clean_lines, linenum, error):
     error: The function to call with any errors found.
   """
   line = clean_lines.elided[linenum]
-  if Search(r'\bVLOG\((INFO|ERROR|WARNING|DFATAL|FATAL)\)', line):
+  if re.search(r'\bVLOG\((INFO|ERROR|WARNING|DFATAL|FATAL)\)', line):
     error(filename, linenum, 'runtime/vlog', 5,
           'VLOG() should be used with numeric verbosity level.  '
           'Use LOG() if you want symbolic severity levels.')
@@ -2681,17 +2800,17 @@ def CheckInvalidIncrement(filename, clean_lines, linenum, error):
 
 
 def IsMacroDefinition(clean_lines, linenum):
-  if Search(r'^#define', clean_lines[linenum]):
+  if re.search(r'^#define', clean_lines[linenum]):
     return True
 
-  if linenum > 0 and Search(r'\\$', clean_lines[linenum - 1]):
+  if linenum > 0 and re.search(r'\\$', clean_lines[linenum - 1]):
     return True
 
   return False
 
 
 def IsForwardClassDeclaration(clean_lines, linenum):
-  return Match(r'^\s*(\btemplate\b)*.*class\s+\w+;\s*$', clean_lines[linenum])
+  return re.match(r'^\s*(\btemplate\b)*.*class\s+\w+;\s*$', clean_lines[linenum])
 
 
 class _BlockInfo(object):
@@ -2786,15 +2905,15 @@ class _ClassInfo(_BlockInfo):
 
   def CheckBegin(self, filename, clean_lines, linenum, error):
     # Look for a bare ':'
-    if Search('(^|[^:]):($|[^:])', clean_lines.elided[linenum]):
+    if re.search('(^|[^:]):($|[^:])', clean_lines.elided[linenum]):
       self.is_derived = True
 
   def CheckEnd(self, filename, clean_lines, linenum, error):
     # If there is a DISALLOW macro, it should appear near the end of
     # the class.
     seen_last_thing_in_class = False
-    for i in xrange(linenum - 1, self.starting_linenum, -1):
-      match = Search(
+    for i in range(linenum - 1, self.starting_linenum, -1):
+      match = re.search(
           r'\b(DISALLOW_COPY_AND_ASSIGN|DISALLOW_IMPLICIT_CONSTRUCTORS)\(' +
           self.name + r'\)',
           clean_lines.elided[i])
@@ -2804,20 +2923,20 @@ class _ClassInfo(_BlockInfo):
                 match.group(1) + ' should be the last thing in the class')
         break
 
-      if not Match(r'^\s*$', clean_lines.elided[i]):
+      if not re.match(r'^\s*$', clean_lines.elided[i]):
         seen_last_thing_in_class = True
 
     # Check that closing brace is aligned with beginning of the class.
     # Only do this if the closing brace is indented by only whitespaces.
     # This means we will not check single-line class definitions.
-    indent = Match(r'^( *)\}', clean_lines.elided[linenum])
+    indent = re.match(r'^( *)\}', clean_lines.elided[linenum])
     if indent and len(indent.group(1)) != self.class_indent:
       if self.is_struct:
         parent = 'struct ' + self.name
       else:
         parent = 'class ' + self.name
       error(filename, linenum, 'whitespace/indent', 3,
-            'Closing brace should be aligned with beginning of %s' % parent)
+            f'Closing brace should be aligned with beginning of {parent}')
 
 
 class _NamespaceInfo(_BlockInfo):
@@ -2844,7 +2963,7 @@ class _NamespaceInfo(_BlockInfo):
     # deciding what these nontrivial things are, so this check is
     # triggered by namespace size only, which works most of the time.
     if (linenum - self.starting_linenum < 10
-        and not Match(r'^\s*};*\s*(//|/\*).*\bnamespace\b', line)):
+        and not re.match(r'^\s*};*\s*(//|/\*).*\bnamespace\b', line)):
       return
 
     # Look for matching comment at end of namespace.
@@ -2861,18 +2980,17 @@ class _NamespaceInfo(_BlockInfo):
     # expected namespace.
     if self.name:
       # Named namespace
-      if not Match((r'^\s*};*\s*(//|/\*).*\bnamespace\s+' +
+      if not re.match((r'^\s*};*\s*(//|/\*).*\bnamespace\s+' +
                     re.escape(self.name) + r'[\*/\.\\\s]*$'),
                    line):
         error(filename, linenum, 'readability/namespace', 5,
-              'Namespace should be terminated with "// namespace %s"' %
-              self.name)
+              f'Namespace should be terminated with "// namespace {self.name}"')
     else:
       # Anonymous namespace
-      if not Match(r'^\s*};*\s*(//|/\*).*\bnamespace[\*/\.\\\s]*$', line):
+      if not re.match(r'^\s*};*\s*(//|/\*).*\bnamespace[\*/\.\\\s]*$', line):
         # If "// namespace anonymous" or "// anonymous namespace (more text)",
         # mention "// anonymous namespace" as an acceptable form
-        if Match(r'^\s*}.*\b(namespace anonymous|anonymous namespace)\b', line):
+        if re.match(r'^\s*}.*\b(namespace anonymous|anonymous namespace)\b', line):
           error(filename, linenum, 'readability/namespace', 5,
                 'Anonymous namespace should be terminated with "// namespace"'
                 ' or "// anonymous namespace"')
@@ -2975,7 +3093,7 @@ class NestingState(object):
     while linenum < clean_lines.NumLines():
       # Find the earliest character that might indicate a template argument
       line = clean_lines.elided[linenum]
-      match = Match(r'^[^{};=\[\]\.<>]*(.)', line[pos:])
+      match = re.match(r'^[^{};=\[\]\.<>]*(.)', line[pos:])
       if not match:
         linenum += 1
         pos = 0
@@ -3035,11 +3153,11 @@ class NestingState(object):
     Args:
       line: current line to check.
     """
-    if Match(r'^\s*#\s*(if|ifdef|ifndef)\b', line):
+    if re.match(r'^\s*#\s*(if|ifdef|ifndef)\b', line):
       # Beginning of #if block, save the nesting stack here.  The saved
       # stack will allow us to restore the parsing state in the #else case.
       self.pp_stack.append(_PreprocessorInfo(copy.deepcopy(self.stack)))
-    elif Match(r'^\s*#\s*(else|elif)\b', line):
+    elif re.match(r'^\s*#\s*(else|elif)\b', line):
       # Beginning of #else block
       if self.pp_stack:
         if not self.pp_stack[-1].seen_else:
@@ -3054,7 +3172,7 @@ class NestingState(object):
       else:
         # TODO(unknown): unexpected #else, issue warning?
         pass
-    elif Match(r'^\s*#\s*endif\b', line):
+    elif re.match(r'^\s*#\s*endif\b', line):
       # End of #if or #else blocks.
       if self.pp_stack:
         # If we saw an #else, we will need to restore the nesting
@@ -3126,7 +3244,7 @@ class NestingState(object):
       # declarations even if it weren't followed by a whitespace, this
       # is so that we don't confuse our namespace checker.  The
       # missing spaces will be flagged by CheckSpacing.
-      namespace_decl_match = Match(r'^\s*namespace\b\s*([:\w]+)?(.*)$', line)
+      namespace_decl_match = re.match(r'^\s*namespace\b\s*([:\w]+)?(.*)$', line)
       if not namespace_decl_match:
         break
 
@@ -3143,7 +3261,7 @@ class NestingState(object):
     # such as in:
     #   class LOCKABLE API Object {
     #   };
-    class_decl_match = Match(
+    class_decl_match = re.match(
         r'^(\s*(?:template\s*<[\w\s<>,:=]*>\s*)?'
         r'(class|struct)\s+(?:[a-zA-Z0-9_]+\s+)*(\w+(?:::\w+)*))'
         r'(.*)$', line)
@@ -3173,7 +3291,7 @@ class NestingState(object):
     # Update access control if we are inside a class/struct
     if self.stack and isinstance(self.stack[-1], _ClassInfo):
       classinfo = self.stack[-1]
-      access_match = Match(
+      access_match = re.match(
           r'^(.*)\b(public|private|protected|signals)(\s+(?:slots\s*)?)?'
           r':(?:[^:]|$)',
           line)
@@ -3184,7 +3302,7 @@ class NestingState(object):
         # check if the keywords are not preceded by whitespaces.
         indent = access_match.group(1)
         if (len(indent) != classinfo.class_indent + 1 and
-            Match(r'^\s*$', indent)):
+            re.match(r'^\s*$', indent)):
           if classinfo.is_struct:
             parent = 'struct ' + classinfo.name
           else:
@@ -3193,13 +3311,13 @@ class NestingState(object):
           if access_match.group(3):
             slots = access_match.group(3)
           error(filename, linenum, 'whitespace/indent', 3,
-                '%s%s: should be indented +1 space inside %s' % (
-                    access_match.group(2), slots, parent))
+                f'{access_match.group(2)}{slots}:'
+                f' should be indented +1 space inside {parent}')
 
     # Consume braces or semicolons from what's left of the line
     while True:
       # Match first brace, semicolon, or closed parenthesis.
-      matched = Match(r'^[^{;)}]*([{;)}])(.*)$', line)
+      matched = re.match(r'^[^{;)}]*([{;)}])(.*)$', line)
       if not matched:
         break
 
@@ -3210,7 +3328,7 @@ class NestingState(object):
         # stack otherwise.
         if not self.SeenOpenBrace():
           self.stack[-1].seen_open_brace = True
-        elif Match(r'^extern\s*"[^"]*"\s*\{', line):
+        elif re.match(r'^extern\s*"[^"]*"\s*\{', line):
           self.stack.append(_ExternCInfo(linenum))
         else:
           self.stack.append(_BlockInfo(linenum, True))
@@ -3247,28 +3365,6 @@ class NestingState(object):
         return classinfo
     return None
 
-  def CheckCompletedBlocks(self, filename, error):
-    """Checks that all classes and namespaces have been completely parsed.
-
-    Call this when all lines in a file have been processed.
-    Args:
-      filename: The name of the current file.
-      error: The function to call with any errors found.
-    """
-    # Note: This test can result in false positives if #ifdef constructs
-    # get in the way of brace matching. See the testBuildClass test in
-    # cpplint_unittest.py for an example of this.
-    for obj in self.stack:
-      if isinstance(obj, _ClassInfo):
-        error(filename, obj.starting_linenum, 'build/class', 5,
-              'Failed to find complete declaration of class %s' %
-              obj.name)
-      elif isinstance(obj, _NamespaceInfo):
-        error(filename, obj.starting_linenum, 'build/namespaces', 5,
-              'Failed to find complete declaration of namespace %s' %
-              obj.name)
-
-
 def CheckForNonStandardConstructs(filename, clean_lines, linenum,
                                   nesting_state, error):
   r"""Logs an error if we see certain non-ANSI constructs ignored by gcc-2.
@@ -3301,47 +3397,47 @@ def CheckForNonStandardConstructs(filename, clean_lines, linenum,
   # Remove comments from the line, but leave in strings for now.
   line = clean_lines.lines[linenum]
 
-  if Search(r'printf\s*\(.*".*%[-+ ]?\d*q', line):
+  if re.search(r'printf\s*\(.*".*%[-+ ]?\d*q', line):
     error(filename, linenum, 'runtime/printf_format', 3,
           '%q in format strings is deprecated.  Use %ll instead.')
 
-  if Search(r'printf\s*\(.*".*%\d+\$', line):
+  if re.search(r'printf\s*\(.*".*%\d+\$', line):
     error(filename, linenum, 'runtime/printf_format', 2,
           '%N$ formats are unconventional.  Try rewriting to avoid them.')
 
   # Remove escaped backslashes before looking for undefined escapes.
   line = line.replace('\\\\', '')
 
-  if Search(r'("|\').*\\(%|\[|\(|{)', line):
+  if re.search(r'("|\').*\\(%|\[|\(|{)', line):
     error(filename, linenum, 'build/printf_format', 3,
           '%, [, (, and { are undefined character escapes.  Unescape them.')
 
   # For the rest, work with both comments and strings removed.
   line = clean_lines.elided[linenum]
 
-  if Search(r'\b(const|volatile|void|char|short|int|long'
+  if re.search(r'\b(const|volatile|void|char|short|int|long'
             r'|float|double|signed|unsigned'
-            r'|schar|u?int8|u?int16|u?int32|u?int64)'
+            r'|schar|u?int8_t|u?int16_t|u?int32_t|u?int64_t)'
             r'\s+(register|static|extern|typedef)\b',
             line):
     error(filename, linenum, 'build/storage_class', 5,
           'Storage-class specifier (static, extern, typedef, etc) should be '
           'at the beginning of the declaration.')
 
-  if Match(r'\s*#\s*endif\s*[^/\s]+', line):
+  if re.match(r'\s*#\s*endif\s*[^/\s]+', line):
     error(filename, linenum, 'build/endif_comment', 5,
           'Uncommented text after #endif is non-standard.  Use a comment.')
 
-  if Match(r'\s*class\s+(\w+\s*::\s*)+\w+\s*;', line):
+  if re.match(r'\s*class\s+(\w+\s*::\s*)+\w+\s*;', line):
     error(filename, linenum, 'build/forward_decl', 5,
           'Inner-style forward declarations are invalid.  Remove this line.')
 
-  if Search(r'(\w+|[+-]?\d+(\.\d*)?)\s*(<|>)\?=?\s*(\w+|[+-]?\d+)(\.\d*)?',
+  if re.search(r'(\w+|[+-]?\d+(\.\d*)?)\s*(<|>)\?=?\s*(\w+|[+-]?\d+)(\.\d*)?',
             line):
     error(filename, linenum, 'build/deprecated', 3,
           '>? and <? (max and min) operators are non-standard and deprecated.')
 
-  if Search(r'^\s*const\s*string\s*&\s*\w+\s*;', line):
+  if re.search(r'^\s*const\s*string\s*&\s*\w+\s*;', line):
     # TODO(unknown): Could it be expanded safely to arbitrary references,
     # without triggering too many false positives? The first
     # attempt triggered 5 warnings for mostly benign code in the regtest, hence
@@ -3366,12 +3462,10 @@ def CheckForNonStandardConstructs(filename, clean_lines, linenum,
 
   # Look for single-argument constructors that aren't marked explicit.
   # Technically a valid construct, but against style.
-  explicit_constructor_match = Match(
+  explicit_constructor_match = re.match(
       r'\s+(?:(?:inline|constexpr)\s+)*(explicit\s+)?'
-      r'(?:(?:inline|constexpr)\s+)*%s\s*'
-      r'\(((?:[^()]|\([^()]*\))*)\)'
-      % re.escape(base_classname),
-      line)
+      rf'(?:(?:inline|constexpr)\s+)*{re.escape(base_classname)}\s*'
+      r'\(((?:[^()]|\([^()]*\))*)\)', line)
 
   if explicit_constructor_match:
     is_marked_explicit = explicit_constructor_match.group(1)
@@ -3410,28 +3504,25 @@ def CheckForNonStandardConstructs(filename, clean_lines, linenum,
                            len(variadic_args) >= 1))
     initializer_list_constructor = bool(
         onearg_constructor and
-        Search(r'\bstd\s*::\s*initializer_list\b', constructor_args[0]))
+        re.search(r'\bstd\s*::\s*initializer_list\b', constructor_args[0]))
     copy_constructor = bool(
         onearg_constructor and
-        Match(r'((const\s+(volatile\s+)?)?|(volatile\s+(const\s+)?))?'
-              r'%s(\s*<[^>]*>)?(\s+const)?\s*(?:<\w+>\s*)?&'
-              % re.escape(base_classname), constructor_args[0].strip()))
+        re.match(r'((const\s+(volatile\s+)?)?|(volatile\s+(const\s+)?))?'
+                rf'{re.escape(base_classname)}(\s*<[^>]*>)?(\s+const)?\s*(?:<\w+>\s*)?&',
+                constructor_args[0].strip())
+    )
 
     if (not is_marked_explicit and
         onearg_constructor and
         not initializer_list_constructor and
         not copy_constructor):
       if defaulted_args or variadic_args:
-        error(filename, linenum, 'runtime/explicit', 5,
+        error(filename, linenum, 'runtime/explicit', 4,
               'Constructors callable with one argument '
               'should be marked explicit.')
       else:
-        error(filename, linenum, 'runtime/explicit', 5,
+        error(filename, linenum, 'runtime/explicit', 4,
               'Single-parameter constructors should be marked explicit.')
-    elif is_marked_explicit and not onearg_constructor:
-      if noarg_constructor:
-        error(filename, linenum, 'runtime/explicit', 5,
-              'Zero-parameter constructors should not be marked explicit.')
 
 
 def CheckSpacingForFunctionCall(filename, clean_lines, linenum, error):
@@ -3454,7 +3545,7 @@ def CheckSpacingForFunctionCall(filename, clean_lines, linenum, error):
                   r'\bfor\s*\((.*)\)\s*{',
                   r'\bwhile\s*\((.*)\)\s*[{;]',
                   r'\bswitch\s*\((.*)\)\s*{'):
-    match = Search(pattern, line)
+    match = re.search(pattern, line)
     if match:
       fncall = match.group(1)    # look inside the parens for function calls
       break
@@ -3473,26 +3564,26 @@ def CheckSpacingForFunctionCall(filename, clean_lines, linenum, error):
   # Note that we assume the contents of [] to be short enough that
   # they'll never need to wrap.
   if (  # Ignore control structures.
-      not Search(r'\b(if|elif|for|while|switch|return|new|delete|catch|sizeof)\b',
+      not re.search(r'\b(if|elif|for|while|switch|return|new|delete|catch|sizeof)\b',
                  fncall) and
       # Ignore pointers/references to functions.
-      not Search(r' \([^)]+\)\([^)]*(\)|,$)', fncall) and
+      not re.search(r' \([^)]+\)\([^)]*(\)|,$)', fncall) and
       # Ignore pointers/references to arrays.
-      not Search(r' \([^)]+\)\[[^\]]+\]', fncall)):
-    if Search(r'\w\s*\(\s(?!\s*\\$)', fncall):      # a ( used for a fn call
+      not re.search(r' \([^)]+\)\[[^\]]+\]', fncall)):
+    if re.search(r'\w\s*\(\s(?!\s*\\$)', fncall):      # a ( used for a fn call
       error(filename, linenum, 'whitespace/parens', 4,
             'Extra space after ( in function call')
-    elif Search(r'\(\s+(?!(\s*\\)|\()', fncall):
+    elif re.search(r'\(\s+(?!(\s*\\)|\()', fncall):
       error(filename, linenum, 'whitespace/parens', 2,
             'Extra space after (')
-    if (Search(r'\w\s+\(', fncall) and
-        not Search(r'_{0,2}asm_{0,2}\s+_{0,2}volatile_{0,2}\s+\(', fncall) and
-        not Search(r'#\s*define|typedef|using\s+\w+\s*=', fncall) and
-        not Search(r'\w\s+\((\w+::)*\*\w+\)\(', fncall) and
-        not Search(r'\bcase\s+\(', fncall)):
+    if (re.search(r'\w\s+\(', fncall) and
+        not re.search(r'_{0,2}asm_{0,2}\s+_{0,2}volatile_{0,2}\s+\(', fncall) and
+        not re.search(r'#\s*define|typedef|using\s+\w+\s*=', fncall) and
+        not re.search(r'\w\s+\((\w+::)*\*\w+\)\(', fncall) and
+        not re.search(r'\bcase\s+\(', fncall)):
       # TODO(unknown): Space after an operator function seem to be a common
       # error, silence those for now by restricting them to highest verbosity.
-      if Search(r'\boperator_*\b', line):
+      if re.search(r'\boperator_*\b', line):
         error(filename, linenum, 'whitespace/parens', 0,
               'Extra space before ( in function call')
       else:
@@ -3500,10 +3591,10 @@ def CheckSpacingForFunctionCall(filename, clean_lines, linenum, error):
               'Extra space before ( in function call')
     # If the ) is followed only by a newline or a { + newline, assume it's
     # part of a control statement (if/while/etc), and don't complain
-    if Search(r'[^)]\s+\)\s*[^{\s]', fncall):
+    if re.search(r'[^)]\s+\)\s*[^{\s]', fncall):
       # If the closing parenthesis is preceded by only whitespaces,
       # try to give a more descriptive error message.
-      if Search(r'^\s+\)', fncall):
+      if re.search(r'^\s+\)', fncall):
         error(filename, linenum, 'whitespace/parens', 2,
               'Closing ) should be moved to the previous line')
       else:
@@ -3529,10 +3620,10 @@ def IsBlankLine(line):
 def CheckForNamespaceIndentation(filename, nesting_state, clean_lines, line,
                                  error):
   is_namespace_indent_item = (
-      len(nesting_state.stack) > 1 and
-      nesting_state.stack[-1].check_namespace_indentation and
-      isinstance(nesting_state.previous_stack_top, _NamespaceInfo) and
-      nesting_state.previous_stack_top == nesting_state.stack[-2])
+      len(nesting_state.stack) >= 1 and
+      (isinstance(nesting_state.stack[-1], _NamespaceInfo) or
+      (isinstance(nesting_state.previous_stack_top, _NamespaceInfo)))
+      )
 
   if ShouldCheckNamespaceIndentation(nesting_state, is_namespace_indent_item,
                                      clean_lines.elided, line):
@@ -3569,28 +3660,28 @@ def CheckForFunctionLengths(filename, clean_lines, linenum,
 
   starting_func = False
   regexp = r'(\w(\w|::|\*|\&|\s)*)\('  # decls * & space::name( ...
-  match_result = Match(regexp, line)
+  match_result = re.match(regexp, line)
   if match_result:
     # If the name is all caps and underscores, figure it's a macro and
     # ignore it, unless it's TEST or TEST_F.
     function_name = match_result.group(1).split()[-1]
     if function_name == 'TEST' or function_name == 'TEST_F' or (
-        not Match(r'[A-Z_]+$', function_name)):
+        not re.match(r'[A-Z_]+$', function_name)):
       starting_func = True
 
   if starting_func:
     body_found = False
-    for start_linenum in xrange(linenum, clean_lines.NumLines()):
+    for start_linenum in range(linenum, clean_lines.NumLines()):
       start_line = lines[start_linenum]
       joined_line += ' ' + start_line.lstrip()
-      if Search(r'(;|})', start_line):  # Declarations and trivial functions
+      if re.search(r'(;|})', start_line):  # Declarations and trivial functions
         body_found = True
         break                              # ... ignore
-      if Search(r'{', start_line):
+      if re.search(r'{', start_line):
         body_found = True
-        function = Search(r'((\w|:)*)\(', line).group(1)
-        if Match(r'TEST', function):    # Handle TEST... macros
-          parameter_regexp = Search(r'(\(.*\))', joined_line)
+        function = re.search(r'((\w|:)*)\(', line).group(1)
+        if re.match(r'TEST', function):    # Handle TEST... macros
+          parameter_regexp = re.search(r'(\(.*\))', joined_line)
           if parameter_regexp:             # Ignore bad syntax
             function += parameter_regexp.group(1)
         else:
@@ -3601,10 +3692,10 @@ def CheckForFunctionLengths(filename, clean_lines, linenum,
       # No body for the function (or evidence of a non-function) was found.
       error(filename, linenum, 'readability/fn_size', 5,
             'Lint failed to find start of function body.')
-  elif Match(r'^\}\s*$', line):  # function end
+  elif re.match(r'^\}\s*$', line):  # function end
     function_state.Check(error, filename, linenum)
     function_state.End()
-  elif not Match(r'^\s*$', line):
+  elif not re.match(r'^\s*$', line):
     function_state.Count()  # Count non-blank/non-comment lines.
 
 
@@ -3626,7 +3717,7 @@ def CheckComment(line, filename, linenum, next_line_start, error):
     # Check if the // may be in quotes.  If so, ignore it
     if re.sub(r'\\.', '', line[0:commentpos]).count('"') % 2 == 0:
       # Allow one space for new scopes, two spaces otherwise:
-      if (not (Match(r'^.*{ *//', line) and next_line_start == commentpos) and
+      if (not (re.match(r'^.*{ *//', line) and next_line_start == commentpos) and
           ((commentpos >= 1 and
             line[commentpos-1] not in string.whitespace) or
            (commentpos >= 2 and
@@ -3651,7 +3742,8 @@ def CheckComment(line, filename, linenum, next_line_start, error):
                 '"// TODO(my_username): Stuff."')
 
         middle_whitespace = match.group(3)
-        # Comparisons made explicit for correctness -- pylint: disable=g-explicit-bool-comparison
+        # Comparisons made explicit for correctness
+        #  -- pylint: disable=g-explicit-bool-comparison
         if middle_whitespace != ' ' and middle_whitespace != '':
           error(filename, linenum, 'whitespace/todo', 2,
                 'TODO(my_username) should be followed by a space')
@@ -3659,8 +3751,8 @@ def CheckComment(line, filename, linenum, next_line_start, error):
       # If the comment contains an alphanumeric character, there
       # should be a space somewhere between it and the // unless
       # it's a /// or //! Doxygen comment.
-      if (Match(r'//[^ ]*\w', comment) and
-          not Match(r'(///|//\!)(\s+|$)', comment)):
+      if (re.match(r'//[^ ]*\w', comment) and
+          not re.match(r'(///|//\!)(\s+|$)', comment)):
         error(filename, linenum, 'whitespace/comments', 4,
               'Should have a space between // and comment')
 
@@ -3723,12 +3815,12 @@ def CheckSpacing(filename, clean_lines, linenum, nesting_state, error):
       # the previous line is indented 6 spaces, which may happen when the
       # initializers of a constructor do not fit into a 80 column line.
       exception = False
-      if Match(r' {6}\w', prev_line):  # Initializer list?
+      if re.match(r' {6}\w', prev_line):  # Initializer list?
         # We are looking for the opening column of initializer list, which
         # should be indented 4 spaces to cause 6 space indentation afterwards.
         search_position = linenum-2
         while (search_position >= 0
-               and Match(r' {6}\w', elided[search_position])):
+               and re.match(r' {6}\w', elided[search_position])):
           search_position -= 1
         exception = (search_position >= 0
                      and elided[search_position][:5] == '    :')
@@ -3739,9 +3831,9 @@ def CheckSpacing(filename, clean_lines, linenum, nesting_state, error):
         # or colon (for initializer lists) we assume that it is the last line of
         # a function header.  If we have a colon indented 4 spaces, it is an
         # initializer list.
-        exception = (Match(r' {4}\w[^\(]*\)\s*(const\s*)?(\{\s*$|:)',
+        exception = (re.match(r' {4}\w[^\(]*\)\s*(const\s*)?(\{\s*$|:)',
                            prev_line)
-                     or Match(r' {4}:', prev_line))
+                     or re.match(r' {4}:', prev_line))
 
       if not exception:
         error(filename, linenum, 'whitespace/blank_line', 2,
@@ -3758,16 +3850,16 @@ def CheckSpacing(filename, clean_lines, linenum, nesting_state, error):
     if linenum + 1 < clean_lines.NumLines():
       next_line = raw[linenum + 1]
       if (next_line
-          and Match(r'\s*}', next_line)
+          and re.match(r'\s*}', next_line)
           and next_line.find('} else ') == -1):
         error(filename, linenum, 'whitespace/blank_line', 3,
               'Redundant blank line at the end of a code block '
               'should be deleted.')
 
-    matched = Match(r'\s*(public|protected|private):', prev_line)
+    matched = re.match(r'\s*(public|protected|private):', prev_line)
     if matched:
       error(filename, linenum, 'whitespace/blank_line', 3,
-            'Do not leave a blank line after "%s:"' % matched.group(1))
+            f'Do not leave a blank line after "{matched.group(1)}:"')
 
   # Next, check comments
   next_line_start = 0
@@ -3781,15 +3873,15 @@ def CheckSpacing(filename, clean_lines, linenum, nesting_state, error):
 
   # You shouldn't have spaces before your brackets, except for C++11 attributes
   # or maybe after 'delete []', 'return []() {};', or 'auto [abc, ...] = ...;'.
-  if (Search(r'\w\s+\[(?!\[)', line) and
-      not Search(r'(?:auto&?|delete|return)\s+\[', line)):
+  if (re.search(r'\w\s+\[(?!\[)', line) and
+      not re.search(r'(?:auto&?|delete|return)\s+\[', line)):
     error(filename, linenum, 'whitespace/braces', 5,
           'Extra space before [')
 
   # In range-based for, we wanted spaces before and after the colon, but
   # not around "::" tokens that might appear.
-  if (Search(r'for *\(.*[^:]:[^: ]', line) or
-      Search(r'for *\(.*[^: ]:[^:]', line)):
+  if (re.search(r'for *\(.*[^:]:[^: ]', line) or
+      re.search(r'for *\(.*[^: ]:[^:]', line)):
     error(filename, linenum, 'whitespace/forcolon', 2,
           'Missing space around colon in range-based for loop')
 
@@ -3812,7 +3904,7 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
   # The replacement is done repeatedly to avoid false positives from
   # operators that call operators.
   while True:
-    match = Match(r'^(.*\boperator\b)(\S+)(\s*\(.*)$', line)
+    match = re.match(r'^(.*\boperator\b)(\S+)(\s*\(.*)$', line)
     if match:
       line = match.group(1) + ('_' * len(match.group(2))) + match.group(3)
     else:
@@ -3822,12 +3914,12 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
   # Otherwise not.  Note we only check for non-spaces on *both* sides;
   # sometimes people put non-spaces on one side when aligning ='s among
   # many lines (not that this is behavior that I approve of...)
-  if ((Search(r'[\w.]=', line) or
-       Search(r'=[\w.]', line))
-      and not Search(r'\b(if|while|for) ', line)
+  if ((re.search(r'[\w.]=', line) or
+       re.search(r'=[\w.]', line))
+      and not re.search(r'\b(if|while|for) ', line)
       # Operators taken from [lex.operators] in C++11 standard.
-      and not Search(r'(>=|<=|==|!=|&=|\^=|\|=|\+=|\*=|\/=|\%=)', line)
-      and not Search(r'operator=', line)):
+      and not re.search(r'(>=|<=|==|!=|&=|\^=|\|=|\+=|\*=|\/=|\%=)', line)
+      and not re.search(r'operator=', line)):
     error(filename, linenum, 'whitespace/operators', 4,
           'Missing spaces around =')
 
@@ -3846,16 +3938,17 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
   #
   # Note that && is not included here.  This is because there are too
   # many false positives due to RValue references.
-  match = Search(r'[^<>=!\s](==|!=|<=|>=|\|\|)[^<>=!\s,;\)]', line)
+  match = re.search(r'[^<>=!\s](==|!=|<=|>=|\|\|)[^<>=!\s,;\)]', line)
   if match:
+    # TODO: support alternate operators
     error(filename, linenum, 'whitespace/operators', 3,
-          'Missing spaces around %s' % match.group(1))
-  elif not Match(r'#.*include', line):
+          f'Missing spaces around {match.group(1)}')
+  elif not re.match(r'#.*include', line):
     # Look for < that is not surrounded by spaces.  This is only
     # triggered if both sides are missing spaces, even though
     # technically should should flag if at least one side is missing a
     # space.  This is done to avoid some false positives with shifts.
-    match = Match(r'^(.*[^\s<])<[^\s=<,]', line)
+    match = re.match(r'^(.*[^\s<])<[^\s=<,]', line)
     if match:
       (_, _, end_pos) = CloseExpression(
           clean_lines, linenum, len(match.group(1)))
@@ -3866,7 +3959,7 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
     # Look for > that is not surrounded by spaces.  Similar to the
     # above, we only trigger if both sides are missing spaces to avoid
     # false positives with shifts.
-    match = Match(r'^(.*[^-\s>])>[^\s=>,]', line)
+    match = re.match(r'^(.*[^-\s>])>[^\s=>,]', line)
     if match:
       (_, _, start_pos) = ReverseCloseExpression(
           clean_lines, linenum, len(match.group(1)))
@@ -3879,7 +3972,7 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
   #
   # We also allow operators following an opening parenthesis, since
   # those tend to be macros that deal with operators.
-  match = Search(r'(operator|[^\s(<])(?:L|UL|LL|ULL|l|ul|ll|ull)?<<([^\s,=<])', line)
+  match = re.search(r'(operator|[^\s(<])(?:L|UL|LL|ULL|l|ul|ll|ull)?<<([^\s,=<])', line)
   if (match and not (match.group(1).isdigit() and match.group(2).isdigit()) and
       not (match.group(1) == 'operator' and match.group(2) == ';')):
     error(filename, linenum, 'whitespace/operators', 3,
@@ -3897,16 +3990,16 @@ def CheckOperatorSpacing(filename, clean_lines, linenum, error):
   # follows would be part of an identifier, and there should still be
   # a space separating the template type and the identifier.
   #   type<type<type>> alpha
-  match = Search(r'>>[a-zA-Z_]', line)
+  match = re.search(r'>>[a-zA-Z_]', line)
   if match:
     error(filename, linenum, 'whitespace/operators', 3,
           'Missing spaces around >>')
 
   # There shouldn't be space around unary operators
-  match = Search(r'(!\s|~\s|[\s]--[\s;]|[\s]\+\+[\s;])', line)
+  match = re.search(r'(!\s|~\s|[\s]--[\s;]|[\s]\+\+[\s;])', line)
   if match:
     error(filename, linenum, 'whitespace/operators', 4,
-          'Extra space for operator %s' % match.group(1))
+          f'Extra space for operator {match.group(1)}')
 
 
 def CheckParenthesisSpacing(filename, clean_lines, linenum, error):
@@ -3921,30 +4014,29 @@ def CheckParenthesisSpacing(filename, clean_lines, linenum, error):
   line = clean_lines.elided[linenum]
 
   # No spaces after an if, while, switch, or for
-  match = Search(r' (if\(|for\(|while\(|switch\()', line)
+  match = re.search(r' (if\(|for\(|while\(|switch\()', line)
   if match:
     error(filename, linenum, 'whitespace/parens', 5,
-          'Missing space before ( in %s' % match.group(1))
+          f'Missing space before ( in {match.group(1)}')
 
   # For if/for/while/switch, the left and right parens should be
   # consistent about how many spaces are inside the parens, and
   # there should either be zero or one spaces inside the parens.
   # We don't want: "if ( foo)" or "if ( foo   )".
   # Exception: "for ( ; foo; bar)" and "for (foo; bar; )" are allowed.
-  match = Search(r'\b(if|for|while|switch)\s*'
+  match = re.search(r'\b(if|for|while|switch)\s*'
                  r'\(([ ]*)(.).*[^ ]+([ ]*)\)\s*{\s*$',
                  line)
   if match:
     if len(match.group(2)) != len(match.group(4)):
       if not (match.group(3) == ';' and
               len(match.group(2)) == 1 + len(match.group(4)) or
-              not match.group(2) and Search(r'\bfor\s*\(.*; \)', line)):
+              not match.group(2) and re.search(r'\bfor\s*\(.*; \)', line)):
         error(filename, linenum, 'whitespace/parens', 5,
-              'Mismatching spaces inside () in %s' % match.group(1))
+              f'Mismatching spaces inside () in {match.group(1)}')
     if len(match.group(2)) not in [0, 1]:
       error(filename, linenum, 'whitespace/parens', 5,
-            'Should have zero or one spaces inside ( and ) in %s' %
-            match.group(1))
+            f'Should have zero or one spaces inside ( and ) in {match.group(1)}')
 
 
 def CheckCommaSpacing(filename, clean_lines, linenum, error):
@@ -3969,8 +4061,9 @@ def CheckCommaSpacing(filename, clean_lines, linenum, error):
   # verify that lines contain missing whitespaces, second pass on raw
   # lines to confirm that those missing whitespaces are not due to
   # elided comments.
-  if (Search(r',[^,\s]', ReplaceAll(r'\boperator\s*,\s*\(', 'F(', line)) and
-      Search(r',[^,\s]', raw[linenum])):
+  match = re.search(r',[^,\s]', re.sub(r'\b__VA_OPT__\s*\(,\)', '',
+                                       re.sub(r'\boperator\s*,\s*\(', 'F(', line)))
+  if (match and re.search(r',[^,\s]', raw[linenum])):
     error(filename, linenum, 'whitespace/comma', 3,
           'Missing space after ,')
 
@@ -3978,7 +4071,7 @@ def CheckCommaSpacing(filename, clean_lines, linenum, error):
   # except for few corner cases
   # TODO(unknown): clarify if 'if (1) { return 1;}' is requires one more
   # space after ;
-  if Search(r';[^\s};\\)/]', line):
+  if re.search(r';[^\s};\\)/]', line):
     error(filename, linenum, 'whitespace/semicolon', 3,
           'Missing space after ;')
 
@@ -3995,7 +4088,7 @@ def _IsType(clean_lines, nesting_state, expr):
     True, if token looks like a type.
   """
   # Keep only the last token in the expression
-  last_word = Match(r'^.*(\b\S+)$', expr)
+  last_word = re.match(r'^.*(\b\S+)$', expr)
   if last_word:
     token = last_word.group(1)
   else:
@@ -4038,8 +4131,8 @@ def _IsType(clean_lines, nesting_state, expr):
       continue
 
     # Look for typename in the specified range
-    for i in xrange(first_line, last_line + 1, 1):
-      if Search(typename_pattern, clean_lines.elided[i]):
+    for i in range(first_line, last_line + 1, 1):
+      if re.search(typename_pattern, clean_lines.elided[i]):
         return True
     block_index -= 1
 
@@ -4065,7 +4158,7 @@ def CheckBracesSpacing(filename, clean_lines, linenum, nesting_state, error):
   # And since you should never have braces at the beginning of a line,
   # this is an easy test.  Except that braces used for initialization don't
   # follow the same rule; we often don't want spaces before those.
-  match = Match(r'^(.*[^ ({>]){', line)
+  match = re.match(r'^(.*[^ ({>]){', line)
 
   if match:
     # Try a bit harder to check for brace initialization.  This
@@ -4102,34 +4195,34 @@ def CheckBracesSpacing(filename, clean_lines, linenum, nesting_state, error):
     trailing_text = ''
     if endpos > -1:
       trailing_text = endline[endpos:]
-    for offset in xrange(endlinenum + 1,
+    for offset in range(endlinenum + 1,
                          min(endlinenum + 3, clean_lines.NumLines() - 1)):
       trailing_text += clean_lines.elided[offset]
     # We also suppress warnings for `uint64_t{expression}` etc., as the style
     # guide recommends brace initialization for integral types to avoid
     # overflow/truncation.
-    if (not Match(r'^[\s}]*[{.;,)<>\]:]', trailing_text)
+    if (not re.match(r'^[\s}]*[{.;,)<>\]:]', trailing_text)
         and not _IsType(clean_lines, nesting_state, leading_text)):
       error(filename, linenum, 'whitespace/braces', 5,
             'Missing space before {')
 
   # Make sure '} else {' has spaces.
-  if Search(r'}else', line):
+  if re.search(r'}else', line):
     error(filename, linenum, 'whitespace/braces', 5,
           'Missing space before else')
 
   # You shouldn't have a space before a semicolon at the end of the line.
   # There's a special case for "for" since the style guide allows space before
   # the semicolon there.
-  if Search(r':\s*;\s*$', line):
+  if re.search(r':\s*;\s*$', line):
     error(filename, linenum, 'whitespace/semicolon', 5,
           'Semicolon defining empty statement. Use {} instead.')
-  elif Search(r'^\s*;\s*$', line):
+  elif re.search(r'^\s*;\s*$', line):
     error(filename, linenum, 'whitespace/semicolon', 5,
           'Line contains only semicolon. If this should be an empty statement, '
           'use {} instead.')
-  elif (Search(r'\s+;\s*$', line) and
-        not Search(r'\bfor\b', line)):
+  elif (re.search(r'\s+;\s*$', line) and
+        not re.search(r'\bfor\b', line)):
     error(filename, linenum, 'whitespace/semicolon', 5,
           'Extra space before last semicolon. If this should be an empty '
           'statement, use {} instead.')
@@ -4148,7 +4241,7 @@ def IsDecltype(clean_lines, linenum, column):
   (text, _, start_col) = ReverseCloseExpression(clean_lines, linenum, column)
   if start_col < 0:
     return False
-  if Search(r'\bdecltype\s*$', text[0:start_col]):
+  if re.search(r'\bdecltype\s*$', text[0:start_col]):
     return True
   return False
 
@@ -4179,7 +4272,7 @@ def CheckSectionSpacing(filename, clean_lines, class_info, linenum, error):
       linenum <= class_info.starting_linenum):
     return
 
-  matched = Match(r'\s*(public|protected|private):', clean_lines.lines[linenum])
+  matched = re.match(r'\s*(public|protected|private):', clean_lines.lines[linenum])
   if matched:
     # Issue warning if the line before public/protected/private was
     # not a blank line, but don't do this if the previous line contains
@@ -4191,20 +4284,20 @@ def CheckSectionSpacing(filename, clean_lines, class_info, linenum, error):
     # common when defining classes in C macros.
     prev_line = clean_lines.lines[linenum - 1]
     if (not IsBlankLine(prev_line) and
-        not Search(r'\b(class|struct)\b', prev_line) and
-        not Search(r'\\$', prev_line)):
+        not re.search(r'\b(class|struct)\b', prev_line) and
+        not re.search(r'\\$', prev_line)):
       # Try a bit harder to find the beginning of the class.  This is to
       # account for multi-line base-specifier lists, e.g.:
       #   class Derived
       #       : public Base {
       end_class_head = class_info.starting_linenum
       for i in range(class_info.starting_linenum, linenum):
-        if Search(r'\{\s*$', clean_lines.lines[i]):
+        if re.search(r'\{\s*$', clean_lines.lines[i]):
           end_class_head = i
           break
       if end_class_head < linenum - 1:
         error(filename, linenum, 'whitespace/blank_line', 3,
-              '"%s:" should be preceded by a blank line' % matched.group(1))
+              f'"{matched.group(1)}:" should be preceded by a blank line')
 
 
 def GetPreviousNonBlankLine(clean_lines, linenum):
@@ -4242,7 +4335,7 @@ def CheckBraces(filename, clean_lines, linenum, error):
 
   line = clean_lines.elided[linenum]        # get rid of comments and strings
 
-  if Match(r'\s*{\s*$', line):
+  if re.match(r'\s*{\s*$', line):
     # We allow an open brace to start a line in the case where someone is using
     # braces in a block to explicitly create a new scope, which is commonly used
     # to control the lifetime of stack-allocated variables.  Braces are also
@@ -4253,23 +4346,25 @@ def CheckBraces(filename, clean_lines, linenum, error):
     # following line if it is part of an array initialization and would not fit
     # within the 80 character limit of the preceding line.
     prevline = GetPreviousNonBlankLine(clean_lines, linenum)[0]
-    if (not Search(r'[,;:}{(]\s*$', prevline) and
-        not Match(r'\s*#', prevline) and
+    if (not re.search(r'[,;:}{(]\s*$', prevline) and
+        not re.match(r'\s*#', prevline) and
         not (GetLineWidth(prevline) > _line_length - 2 and '[]' in prevline)):
       error(filename, linenum, 'whitespace/braces', 4,
             '{ should almost always be at the end of the previous line')
 
   # An else clause should be on the same line as the preceding closing brace.
-  if Match(r'\s*else\b\s*(?:if\b|\{|$)', line):
+  if last_wrong := re.match(r'\s*else\b\s*(?:if\b|\{|$)', line):
     prevline = GetPreviousNonBlankLine(clean_lines, linenum)[0]
-    if Match(r'\s*}\s*$', prevline):
+    if re.match(r'\s*}\s*$', prevline):
       error(filename, linenum, 'whitespace/newline', 4,
             'An else should appear on the same line as the preceding }')
+    else:
+      last_wrong = False
 
   # If braces come on one side of an else, they should be on both.
   # However, we have to worry about "else if" that spans multiple lines!
-  if Search(r'else if\s*\(', line):       # could be multi-line if
-    brace_on_left = bool(Search(r'}\s*else if\s*\(', line))
+  if re.search(r'else if\s*\(', line):       # could be multi-line if
+    brace_on_left = bool(re.search(r'}\s*else if\s*\(', line))
     # find the ( after the if
     pos = line.find('else if')
     pos = line.find('(', pos)
@@ -4279,19 +4374,29 @@ def CheckBraces(filename, clean_lines, linenum, error):
       if brace_on_left != brace_on_right:    # must be brace after if
         error(filename, linenum, 'readability/braces', 5,
               'If an else has a brace on one side, it should have it on both')
-  elif Search(r'}\s*else[^{]*$', line) or Match(r'[^}]*else\s*{', line):
+  # Prevent detection if statement has { and we detected an improper newline after }
+  elif re.search(r'}\s*else[^{]*$', line) or (re.match(r'[^}]*else\s*{', line) and not last_wrong):
     error(filename, linenum, 'readability/braces', 5,
           'If an else has a brace on one side, it should have it on both')
 
-  # Likewise, an else should never have the else clause on the same line
-  if Search(r'\belse [^\s{]', line) and not Search(r'\belse if\b', line):
-    error(filename, linenum, 'whitespace/newline', 4,
-          'Else clause should never be on same line as else (use 2 lines)')
-
-  # In the same way, a do/while should never be on one line
-  if Match(r'\s*do [^\s{]', line):
-    error(filename, linenum, 'whitespace/newline', 4,
-          'do/while clauses should not be on a single line')
+  # No control clauses with braces should have its contents on the same line
+  # Exclude } which will be covered by empty-block detect
+  # Exclude ; which may be used by while in a do-while
+  if keyword := re.search(
+      r'\b(else if|if|while|for|switch)'  # These have parens
+      r'\s*\(.*\)\s*(?:\[\[(?:un)?likely\]\]\s*)?{\s*[^\s\\};]', line):
+    error(filename, linenum, 'whitespace/newline', 5,
+          f'Controlled statements inside brackets of {keyword.group(1)} clause'
+          ' should be on a separate line')
+  elif keyword := re.search(
+      r'\b(else|do|try)'  # These don't have parens
+      r'\s*(?:\[\[(?:un)?likely\]\]\s*)?{\s*[^\s\\}]', line):
+    error(filename, linenum, 'whitespace/newline', 5,
+          f'Controlled statements inside brackets of {keyword.group(1)} clause'
+          ' should be on a separate line')
+
+  # TODO: Err on if...else and do...while statements without braces;
+  # style guide has changed since the below comment was written
 
   # Check single-line if/else bodies. The style guide says 'curly braces are not
   # required for single-line statements'. We additionally allow multi-line,
@@ -4300,21 +4405,21 @@ def CheckBraces(filename, clean_lines, linenum, error):
   # its line, and the line after that should have an indent level equal to or
   # lower than the if. We also check for ambiguous if/else nesting without
   # braces.
-  if_else_match = Search(r'\b(if\s*(|constexpr)\s*\(|else\b)', line)
-  if if_else_match and not Match(r'\s*#', line):
+  if_else_match = re.search(r'\b(if\s*(|constexpr)\s*\(|else\b)', line)
+  if if_else_match and not re.match(r'\s*#', line):
     if_indent = GetIndentLevel(line)
     endline, endlinenum, endpos = line, linenum, if_else_match.end()
-    if_match = Search(r'\bif\s*(|constexpr)\s*\(', line)
+    if_match = re.search(r'\bif\s*(|constexpr)\s*\(', line)
     if if_match:
       # This could be a multiline if condition, so find the end first.
       pos = if_match.end() - 1
       (endline, endlinenum, endpos) = CloseExpression(clean_lines, linenum, pos)
     # Check for an opening brace, either directly after the if or on the next
     # line. If found, this isn't a single-statement conditional.
-    if (not Match(r'\s*{', endline[endpos:])
-        and not (Match(r'\s*$', endline[endpos:])
+    if (not re.match(r'\s*(?:\[\[(?:un)?likely\]\]\s*)?{', endline[endpos:])
+        and not (re.match(r'\s*$', endline[endpos:])
                  and endlinenum < (len(clean_lines.elided) - 1)
-                 and Match(r'\s*{', clean_lines.elided[endlinenum + 1]))):
+                 and re.match(r'\s*{', clean_lines.elided[endlinenum + 1]))):
       while (endlinenum < len(clean_lines.elided)
              and ';' not in clean_lines.elided[endlinenum][endpos:]):
         endlinenum += 1
@@ -4324,11 +4429,11 @@ def CheckBraces(filename, clean_lines, linenum, error):
         # We allow a mix of whitespace and closing braces (e.g. for one-liner
         # methods) and a single \ after the semicolon (for macros)
         endpos = endline.find(';')
-        if not Match(r';[\s}]*(\\?)$', endline[endpos:]):
+        if not re.match(r';[\s}]*(\\?)$', endline[endpos:]):
           # Semicolon isn't the last character, there's something trailing.
           # Output a warning if the semicolon is not contained inside
           # a lambda expression.
-          if not Match(r'^[^{};]*\[[^\[\]]*\][^{}]*\{[^{}]*\}\s*\)*[;,]\s*$',
+          if not re.match(r'^[^{};]*\[[^\[\]]*\][^{}]*\{[^{}]*\}\s*\)*[;,]\s*$',
                        endline):
             error(filename, linenum, 'readability/braces', 4,
                   'If/else bodies with multiple statements require braces')
@@ -4339,7 +4444,7 @@ def CheckBraces(filename, clean_lines, linenum, error):
           # With ambiguous nested if statements, this will error out on the
           # if that *doesn't* match the else, regardless of whether it's the
           # inner one or outer one.
-          if (if_match and Match(r'\s*else\b', next_line)
+          if (if_match and re.match(r'\s*else\b', next_line)
               and next_indent != if_indent):
             error(filename, linenum, 'readability/braces', 4,
                   'Else clause should be indented at the same level as if. '
@@ -4405,7 +4510,7 @@ def CheckTrailingSemicolon(filename, clean_lines, linenum, error):
   #    to namespaces.  For now we do not warn for this case.
   #
   # Try matching case 1 first.
-  match = Match(r'^(.*\)\s*)\{', line)
+  match = re.match(r'^(.*\)\s*)\{', line)
   if match:
     # Matched closing parenthesis (case 1).  Check the token before the
     # matching opening parenthesis, and don't warn if it looks like a
@@ -4433,32 +4538,34 @@ def CheckTrailingSemicolon(filename, clean_lines, linenum, error):
     #  - Lambdas
     #  - alignas specifier with anonymous structs
     #  - decltype
+    #  - concepts (requires expression)
     closing_brace_pos = match.group(1).rfind(')')
     opening_parenthesis = ReverseCloseExpression(
         clean_lines, linenum, closing_brace_pos)
     if opening_parenthesis[2] > -1:
       line_prefix = opening_parenthesis[0][0:opening_parenthesis[2]]
-      macro = Search(r'\b([A-Z_][A-Z0-9_]*)\s*$', line_prefix)
-      func = Match(r'^(.*\])\s*$', line_prefix)
+      macro = re.search(r'\b([A-Z_][A-Z0-9_]*)\s*$', line_prefix)
+      func = re.match(r'^(.*\])\s*$', line_prefix)
       if ((macro and
            macro.group(1) not in (
                'TEST', 'TEST_F', 'MATCHER', 'MATCHER_P', 'TYPED_TEST',
                'EXCLUSIVE_LOCKS_REQUIRED', 'SHARED_LOCKS_REQUIRED',
                'LOCKS_EXCLUDED', 'INTERFACE_DEF')) or
-          (func and not Search(r'\boperator\s*\[\s*\]', func.group(1))) or
-          Search(r'\b(?:struct|union)\s+alignas\s*$', line_prefix) or
-          Search(r'\bdecltype$', line_prefix) or
-          Search(r'\s+=\s*$', line_prefix)):
+          (func and not re.search(r'\boperator\s*\[\s*\]', func.group(1))) or
+          re.search(r'\b(?:struct|union)\s+alignas\s*$', line_prefix) or
+          re.search(r'\bdecltype$', line_prefix) or
+          re.search(r'\brequires.*$', line_prefix) or
+          re.search(r'\s+=\s*$', line_prefix)):
         match = None
     if (match and
         opening_parenthesis[1] > 1 and
-        Search(r'\]\s*$', clean_lines.elided[opening_parenthesis[1] - 1])):
+        re.search(r'\]\s*$', clean_lines.elided[opening_parenthesis[1] - 1])):
       # Multi-line lambda-expression
       match = None
 
   else:
     # Try matching cases 2-3.
-    match = Match(r'^(.*(?:else|\)\s*const)\s*)\{', line)
+    match = re.match(r'^(.*(?:else|\)\s*const)\s*)\{', line)
     if not match:
       # Try matching cases 4-6.  These are always matched on separate lines.
       #
@@ -4469,14 +4576,14 @@ def CheckTrailingSemicolon(filename, clean_lines, linenum, error):
       #     // blank line
       #   }
       prevline = GetPreviousNonBlankLine(clean_lines, linenum)[0]
-      if prevline and Search(r'[;{}]\s*$', prevline):
-        match = Match(r'^(\s*)\{', line)
+      if prevline and re.search(r'[;{}]\s*$', prevline):
+        match = re.match(r'^(\s*)\{', line)
 
   # Check matching closing brace
   if match:
     (endline, endlinenum, endpos) = CloseExpression(
         clean_lines, linenum, len(match.group(1)))
-    if endpos > -1 and Match(r'^\s*;', endline[endpos:]):
+    if endpos > -1 and re.match(r'^\s*;', endline[endpos:]):
       # Current {} pair is eligible for semicolon check, and we have found
       # the redundant semicolon, output warning here.
       #
@@ -4513,7 +4620,7 @@ def CheckEmptyBlockBody(filename, clean_lines, linenum, error):
   # We also check "if" blocks here, since an empty conditional block
   # is likely an error.
   line = clean_lines.elided[linenum]
-  matched = Match(r'\s*(for|while|if)\s*\(', line)
+  matched = re.match(r'\s*(for|while|if)\s*\(', line)
   if matched:
     # Find the end of the conditional expression.
     (end_line, end_linenum, end_pos) = CloseExpression(
@@ -4522,7 +4629,7 @@ def CheckEmptyBlockBody(filename, clean_lines, linenum, error):
     # Output warning if what follows the condition expression is a semicolon.
     # No warning for all other cases, including whitespace or newline, since we
     # have a separate check for semicolons preceded by whitespace.
-    if end_pos >= 0 and Match(r';', end_line[end_pos:]):
+    if end_pos >= 0 and re.match(r';', end_line[end_pos:]):
       if matched.group(1) == 'if':
         error(filename, end_linenum, 'whitespace/empty_conditional_body', 5,
               'Empty conditional bodies should use {}')
@@ -4538,8 +4645,8 @@ def CheckEmptyBlockBody(filename, clean_lines, linenum, error):
       opening_linenum = end_linenum
       opening_line_fragment = end_line[end_pos:]
       # Loop until EOF or find anything that's not whitespace or opening {.
-      while not Search(r'^\s*\{', opening_line_fragment):
-        if Search(r'^(?!\s*$)', opening_line_fragment):
+      while not re.search(r'^\s*\{', opening_line_fragment):
+        if re.search(r'^(?!\s*$)', opening_line_fragment):
           # Conditional has no brackets.
           return
         opening_linenum += 1
@@ -4586,8 +4693,8 @@ def CheckEmptyBlockBody(filename, clean_lines, linenum, error):
       current_linenum = closing_linenum
       current_line_fragment = closing_line[closing_pos:]
       # Loop until EOF or find anything that's not whitespace or else clause.
-      while Search(r'^\s*$|^(?=\s*else)', current_line_fragment):
-        if Search(r'^(?=\s*else)', current_line_fragment):
+      while re.search(r'^\s*$|^(?=\s*else)', current_line_fragment):
+        if re.search(r'^(?=\s*else)', current_line_fragment):
           # Found an else clause, so don't log an error.
           return
         current_linenum += 1
@@ -4616,7 +4723,7 @@ def FindCheckMacro(line):
       # to make sure that we are matching the expected CHECK macro, as
       # opposed to some other macro that happens to contain the CHECK
       # substring.
-      matched = Match(r'^(.*\b' + macro + r'\s*)\(', line)
+      matched = re.match(r'^(.*\b' + macro + r'\s*)\(', line)
       if not matched:
         continue
       return (macro, len(matched.group(1)))
@@ -4648,14 +4755,14 @@ def CheckCheck(filename, clean_lines, linenum, error):
   # If the check macro is followed by something other than a
   # semicolon, assume users will log their own custom error messages
   # and don't suggest any replacements.
-  if not Match(r'\s*;', last_line[end_pos:]):
+  if not re.match(r'\s*;', last_line[end_pos:]):
     return
 
   if linenum == end_line:
     expression = lines[linenum][start_pos + 1:end_pos - 1]
   else:
     expression = lines[linenum][start_pos + 1:]
-    for i in xrange(linenum + 1, end_line):
+    for i in range(linenum + 1, end_line):
       expression += lines[i]
     expression += last_line[0:end_pos - 1]
 
@@ -4666,7 +4773,7 @@ def CheckCheck(filename, clean_lines, linenum, error):
   rhs = ''
   operator = None
   while expression:
-    matched = Match(r'^\s*(<<|<<=|>>|>>=|->\*|->|&&|\|\||'
+    matched = re.match(r'^\s*(<<|<<=|>>|>>=|->\*|->|&&|\|\||'
                     r'==|!=|>=|>|<=|<|\()(.*)$', expression)
     if matched:
       token = matched.group(1)
@@ -4700,9 +4807,9 @@ def CheckCheck(filename, clean_lines, linenum, error):
       # characters at once if possible.  Trivial benchmark shows that this
       # is more efficient when the operands are longer than a single
       # character, which is generally the case.
-      matched = Match(r'^([^-=!<>()&|]+)(.*)$', expression)
+      matched = re.match(r'^([^-=!<>()&|]+)(.*)$', expression)
       if not matched:
-        matched = Match(r'^(\s*\S)(.*)$', expression)
+        matched = re.match(r'^(\s*\S)(.*)$', expression)
         if not matched:
           break
       lhs += matched.group(1)
@@ -4726,7 +4833,7 @@ def CheckCheck(filename, clean_lines, linenum, error):
   lhs = lhs.strip()
   rhs = rhs.strip()
   match_constant = r'^([-+]?(\d+|0[xX][0-9a-fA-F]+)[lLuU]{0,3}|".*"|\'.*\')$'
-  if Match(match_constant, lhs) or Match(match_constant, rhs):
+  if re.match(match_constant, lhs) or re.match(match_constant, rhs):
     # Note: since we know both lhs and rhs, we can provide a more
     # descriptive error message like:
     #   Consider using CHECK_EQ(x, 42) instead of CHECK(x == 42)
@@ -4736,9 +4843,8 @@ def CheckCheck(filename, clean_lines, linenum, error):
     # We are still keeping the less descriptive message because if lhs
     # or rhs gets long, the error message might become unreadable.
     error(filename, linenum, 'readability/check', 2,
-          'Consider using %s instead of %s(a %s b)' % (
-              _CHECK_REPLACEMENT[check_macro][operator],
-              check_macro, operator))
+          f'Consider using {_CHECK_REPLACEMENT[check_macro][operator]}'
+          f' instead of {check_macro}(a {operator} b)')
 
 
 def CheckAltTokens(filename, clean_lines, linenum, error):
@@ -4753,7 +4859,7 @@ def CheckAltTokens(filename, clean_lines, linenum, error):
   line = clean_lines.elided[linenum]
 
   # Avoid preprocessor lines
-  if Match(r'^\s*#', line):
+  if re.match(r'^\s*#', line):
     return
 
   # Last ditch effort to avoid multi-line comments.  This will not help
@@ -4769,8 +4875,8 @@ def CheckAltTokens(filename, clean_lines, linenum, error):
 
   for match in _ALT_TOKEN_REPLACEMENT_PATTERN.finditer(line):
     error(filename, linenum, 'readability/alt_tokens', 2,
-          'Use operator %s instead of %s' % (
-              _ALT_TOKEN_REPLACEMENT[match.group(1)], match.group(1)))
+          f'Use operator {_ALT_TOKEN_REPLACEMENT[match.group(2)]}'
+          f' instead of {match.group(2)}')
 
 
 def GetLineWidth(line):
@@ -4783,7 +4889,7 @@ def GetLineWidth(line):
     The width of the line in column positions, accounting for Unicode
     combining characters and wide characters.
   """
-  if isinstance(line, unicode):
+  if isinstance(line, str):
     width = 0
     for uc in unicodedata.normalize('NFC', line):
       if unicodedata.east_asian_width(uc) in ('W', 'F'):
@@ -4806,7 +4912,7 @@ def GetLineWidth(line):
 
 
 def CheckStyle(filename, clean_lines, linenum, file_extension, nesting_state,
-               error):
+               error, cppvar=None):
   """Checks rules from the 'C++ style rules' section of cppguide.html.
 
   Most of these rules are hard to test (naming, comment style), but we
@@ -4821,6 +4927,7 @@ def CheckStyle(filename, clean_lines, linenum, file_extension, nesting_state,
     nesting_state: A NestingState instance which maintains information about
                    the current stack of nested blocks being parsed.
     error: The function to call with any errors found.
+    cppvar: The header guard variable returned by GetHeaderGuardCPPVar.
   """
 
   # Don't use "elided" lines here, otherwise we can't check commented lines.
@@ -4857,11 +4964,11 @@ def CheckStyle(filename, clean_lines, linenum, file_extension, nesting_state,
   # We also don't check for lines that look like continuation lines
   # (of lines ending in double quotes, commas, equals, or angle brackets)
   # because the rules for how to indent those are non-trivial.
-  if (not Search(r'[",=><] *$', prev) and
+  if (not re.search(r'[",=><] *$', prev) and
       (initial_spaces == 1 or initial_spaces == 3) and
-      not Match(scope_or_label_pattern, cleansed_line) and
+      not re.match(scope_or_label_pattern, cleansed_line) and
       not (clean_lines.raw_lines[linenum] != line and
-           Match(r'^\s*""', line))):
+           re.match(r'^\s*""', line))):
     error(filename, linenum, 'whitespace/indent', 3,
           'Weird number of spaces at line-start.  '
           'Are you using a 2-space indent?')
@@ -4873,10 +4980,9 @@ def CheckStyle(filename, clean_lines, linenum, file_extension, nesting_state,
   # Check if the line is a header guard.
   is_header_guard = False
   if IsHeaderExtension(file_extension):
-    cppvar = GetHeaderGuardCPPVariable(filename)
-    if (line.startswith('#ifndef %s' % cppvar) or
-        line.startswith('#define %s' % cppvar) or
-        line.startswith('#endif  // %s' % cppvar)):
+    if (line.startswith(f'#ifndef {cppvar}') or
+        line.startswith(f'#define {cppvar}') or
+        line.startswith(f'#endif  // {cppvar}')):
       is_header_guard = True
   # #include lines and header guards can be long, since there's no clean way to
   # split them.
@@ -4890,18 +4996,18 @@ def CheckStyle(filename, clean_lines, linenum, file_extension, nesting_state,
   # Doxygen documentation copying can get pretty long when using an overloaded
   # function declaration
   if (not line.startswith('#include') and not is_header_guard and
-      not Match(r'^\s*//.*http(s?)://\S*$', line) and
-      not Match(r'^\s*//\s*[^\s]*$', line) and
-      not Match(r'^// \$Id:.*#[0-9]+ \$$', line) and
-      not Match(r'^\s*/// [@\\](copydoc|copydetails|copybrief) .*$', line)):
+      not re.match(r'^\s*//.*http(s?)://\S*$', line) and
+      not re.match(r'^\s*//\s*[^\s]*$', line) and
+      not re.match(r'^// \$Id:.*#[0-9]+ \$$', line) and
+      not re.match(r'^\s*/// [@\\](copydoc|copydetails|copybrief) .*$', line)):
     line_width = GetLineWidth(line)
     if line_width > _line_length:
       error(filename, linenum, 'whitespace/line_length', 2,
-            'Lines should be <= %i characters long' % _line_length)
+            f'Lines should be <= {_line_length} characters long')
 
   if (cleansed_line.count(';') > 1 and
       # allow simple single line lambdas
-      not Match(r'^[^{};]*\[[^\[\]]*\][^{}]*\{[^{}\n\r]*\}',
+      not re.match(r'^[^{};]*\[[^\[\]]*\][^{}]*\{[^{}\n\r]*\}',
                 line) and
       # for loops are allowed two ;'s (and may run over two lines).
       cleansed_line.find('for') == -1 and
@@ -4960,9 +5066,9 @@ def _DropCommonSuffixes(filename):
     The filename with the common suffix removed.
   """
   for suffix in itertools.chain(
-      ('%s.%s' % (test_suffix.lstrip('_'), ext)
+      (f"{test_suffix.lstrip('_')}.{ext}"
        for test_suffix, ext in itertools.product(_test_suffixes, GetNonHeaderExtensions())),
-      ('%s.%s' % (suffix, ext)
+      (f'{suffix}.{ext}'
        for suffix, ext in itertools.product(['inl', 'imp', 'internal'], GetHeaderExtensions()))):
     if (filename.endswith(suffix) and len(filename) > len(suffix) and
         filename[-len(suffix) - 1] in ('-', '_')):
@@ -5004,10 +5110,11 @@ def _ClassifyInclude(fileinfo, include, used_angle_brackets, include_order="defa
   # Mark include as C header if in list or in a known folder for standard-ish C headers.
   is_std_c_header = (include_order == "default") or (include in _C_HEADERS
             # additional linux glibc header folders
-            or Search(r'(?:%s)\/.*\.h' % "|".join(C_STANDARD_HEADER_FOLDERS), include))
+            or re.search(rf'(?:{"|".join(C_STANDARD_HEADER_FOLDERS)})\/.*\.h', include))
 
   # Headers with C++ extensions shouldn't be considered C system headers
-  is_system = used_angle_brackets and not os.path.splitext(include)[1] in ['.hpp', '.hxx', '.h++']
+  include_ext = os.path.splitext(include)[1]
+  is_system = used_angle_brackets and include_ext not in ['.hh', '.hpp', '.hxx', '.h++']
 
   if is_system:
     if is_cpp_header:
@@ -5069,10 +5176,12 @@ def CheckIncludeLine(filename, clean_lines, linenum, include_state, error):
   #
   # We also make an exception for Lua headers, which follow google
   # naming convention but not the include convention.
-  match = Match(r'#include\s*"([^/]+\.h)"', line)
-  if match and not _THIRD_PARTY_HEADERS_PATTERN.match(match.group(1)):
-    error(filename, linenum, 'build/include_subdir', 4,
-          'Include the directory when naming .h files')
+  match = re.match(r'#include\s*"([^/]+\.(.*))"', line)
+  if match:
+    if (IsHeaderExtension(match.group(2)) and
+        not _THIRD_PARTY_HEADERS_PATTERN.match(match.group(1))):
+      error(filename, linenum, 'build/include_subdir', 4,
+            'Include the directory when naming header files')
 
   # we shouldn't include a file more than once. actually, there are a
   # handful of instances where doing so is okay, but in general it's
@@ -5080,12 +5189,11 @@ def CheckIncludeLine(filename, clean_lines, linenum, include_state, error):
   match = _RE_PATTERN_INCLUDE.search(line)
   if match:
     include = match.group(2)
-    used_angle_brackets = (match.group(1) == '<')
+    used_angle_brackets = match.group(1) == '<'
     duplicate_line = include_state.FindHeader(include)
     if duplicate_line >= 0:
       error(filename, linenum, 'build/include', 4,
-            '"%s" already included at %s:%s' %
-            (include, filename, duplicate_line))
+            f'"{include}" already included at {filename}:{duplicate_line}')
       return
 
     for extension in GetNonHeaderExtensions():
@@ -5125,13 +5233,13 @@ def CheckIncludeLine(filename, clean_lines, linenum, include_state, error):
           _ClassifyInclude(fileinfo, include, used_angle_brackets, _include_order))
       if error_message:
         error(filename, linenum, 'build/include_order', 4,
-              '%s. Should be: %s.h, c system, c++ system, other.' %
-              (error_message, fileinfo.BaseName()))
+              f'{error_message}. Should be: {fileinfo.BaseName()}.h, c system,'
+              ' c++ system, other.')
       canonical_include = include_state.CanonicalizeAlphabeticalOrder(include)
       if not include_state.IsInAlphabeticalOrder(
           clean_lines, linenum, canonical_include):
         error(filename, linenum, 'build/include_alpha', 4,
-              'Include "%s" not in alphabetical order' % include)
+              f'Include "{include}" not in alphabetical order')
       include_state.SetLastHeader(canonical_include)
 
 
@@ -5161,7 +5269,7 @@ def _GetTextInside(text, start_pattern):
 
   # Give opening punctuations to get the matching close-punctuations.
   matching_punctuation = {'(': ')', '{': '}', '[': ']'}
-  closing_punctuation = set(itervalues(matching_punctuation))
+  closing_punctuation = set(dict.values(matching_punctuation))
 
   # Find the position to start extracting text.
   match = re.search(start_pattern, text, re.M)
@@ -5226,7 +5334,7 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
   """Checks rules from the 'C++ language rules' section of cppguide.html.
 
   Some of these rules are hard to test (function overloading, using
-  uint32 inappropriately), but we do the best we can.
+  uint32_t inappropriately), but we do the best we can.
 
   Args:
     filename: The name of the current file.
@@ -5251,7 +5359,7 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
 
   # Reset include state across preprocessor directives.  This is meant
   # to silence warnings for conditional includes.
-  match = Match(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b', line)
+  match = re.match(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b', line)
   if match:
     include_state.ResetSection(match.group(1))
 
@@ -5271,15 +5379,15 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
 
   # Check if people are using the verboten C basic types.  The only exception
   # we regularly allow is "unsigned short port" for port.
-  if Search(r'\bshort port\b', line):
-    if not Search(r'\bunsigned short port\b', line):
+  if re.search(r'\bshort port\b', line):
+    if not re.search(r'\bunsigned short port\b', line):
       error(filename, linenum, 'runtime/int', 4,
             'Use "unsigned short" for ports, not "short"')
   else:
-    match = Search(r'\b(short|long(?! +double)|long long)\b', line)
+    match = re.search(r'\b(short|long(?! +double)|long long)\b', line)
     if match:
       error(filename, linenum, 'runtime/int', 4,
-            'Use int16/int64/etc, rather than the C type %s' % match.group(1))
+            f'Use int16_t/int64_t/etc, rather than the C type {match.group(1)}')
 
   # Check if some verboten operator overloading is going on
   # TODO(unknown): catch out-of-line unary operator&:
@@ -5287,13 +5395,13 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
   #   int operator&(const X& x) { return 42; }  // unary operator&
   # The trick is it's hard to tell apart from binary operator&:
   #   class Y { int operator&(const Y& x) { return 23; } }; // binary operator&
-  if Search(r'\boperator\s*&\s*\(\s*\)', line):
+  if re.search(r'\boperator\s*&\s*\(\s*\)', line):
     error(filename, linenum, 'runtime/operator', 4,
           'Unary operator& is dangerous.  Do not use it.')
 
   # Check for suspicious usage of "if" like
   # } if (a == b) {
-  if Search(r'\}\s*if\s*\(', line):
+  if re.search(r'\}\s*if\s*\(', line):
     error(filename, linenum, 'readability/braces', 4,
           'Did you mean "else if"? If not, start a new line for "if".')
 
@@ -5306,23 +5414,22 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
   #       boy_this_is_a_really_long_variable_that_cannot_fit_on_the_prev_line);
   printf_args = _GetTextInside(line, r'(?i)\b(string)?printf\s*\(')
   if printf_args:
-    match = Match(r'([\w.\->()]+)$', printf_args)
+    match = re.match(r'([\w.\->()]+)$', printf_args)
     if match and match.group(1) != '__VA_ARGS__':
       function_name = re.search(r'\b((?:string)?printf)\s*\(',
                                 line, re.I).group(1)
       error(filename, linenum, 'runtime/printf', 4,
-            'Potential format string bug. Do %s("%%s", %s) instead.'
-            % (function_name, match.group(1)))
+            'Potential format string bug. Do'
+            f' {function_name}("%s", {match.group(1)}) instead.')
 
   # Check for potential memset bugs like memset(buf, sizeof(buf), 0).
-  match = Search(r'memset\s*\(([^,]*),\s*([^,]*),\s*0\s*\)', line)
-  if match and not Match(r"^''|-?[0-9]+|0x[0-9A-Fa-f]$", match.group(2)):
+  match = re.search(r'memset\s*\(([^,]*),\s*([^,]*),\s*0\s*\)', line)
+  if match and not re.match(r"^''|-?[0-9]+|0x[0-9A-Fa-f]$", match.group(2)):
     error(filename, linenum, 'runtime/memset', 4,
-          'Did you mean "memset(%s, 0, %s)"?'
-          % (match.group(1), match.group(2)))
+          f'Did you mean "memset({match.group(1)}, 0, {match.group(2)})"?')
 
-  if Search(r'\busing namespace\b', line):
-    if Search(r'\bliterals\b', line):
+  if re.search(r'\busing namespace\b', line):
+    if re.search(r'\bliterals\b', line):
       error(filename, linenum, 'build/namespaces_literals', 5,
             'Do not use namespace using-directives.  '
             'Use using-declarations instead.')
@@ -5332,7 +5439,7 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
             'Use using-declarations instead.')
 
   # Detect variable-length arrays.
-  match = Match(r'\s*(.+::)?(\w+) [a-z]\w*\[(.+)];', line)
+  match = re.match(r'\s*(.+::)?(\w+) [a-z]\w*\[(.+)];', line)
   if (match and match.group(2) != 'return' and match.group(2) != 'delete' and
       match.group(3).find(']') == -1):
     # Split the size using space and arithmetic operators as delimiters.
@@ -5346,17 +5453,17 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
         skip_next = False
         continue
 
-      if Search(r'sizeof\(.+\)', tok): continue
-      if Search(r'arraysize\(\w+\)', tok): continue
+      if re.search(r'sizeof\(.+\)', tok): continue
+      if re.search(r'arraysize\(\w+\)', tok): continue
 
       tok = tok.lstrip('(')
       tok = tok.rstrip(')')
       if not tok: continue
-      if Match(r'\d+', tok): continue
-      if Match(r'0[xX][0-9a-fA-F]+', tok): continue
-      if Match(r'k[A-Z0-9]\w*', tok): continue
-      if Match(r'(.+::)?k[A-Z0-9]\w*', tok): continue
-      if Match(r'(.+::)?[A-Z][A-Z0-9_]*', tok): continue
+      if re.match(r'\d+', tok): continue
+      if re.match(r'0[xX][0-9a-fA-F]+', tok): continue
+      if re.match(r'k[A-Z0-9]\w*', tok): continue
+      if re.match(r'(.+::)?k[A-Z0-9]\w*', tok): continue
+      if re.match(r'(.+::)?[A-Z][A-Z0-9_]*', tok): continue
       # A catch all for tricky sizeof cases, including 'sizeof expression',
       # 'sizeof(*type)', 'sizeof(const type)', 'sizeof(struct StructName)'
       # requires skipping the next token because we split on ' ' and '*'.
@@ -5374,7 +5481,7 @@ def CheckLanguage(filename, clean_lines, linenum, file_extension,
   # macros are typically OK, so we allow use of "namespace {" on lines
   # that end with backslashes.
   if (IsHeaderExtension(file_extension)
-      and Search(r'\bnamespace\s*{', line)
+      and re.search(r'\bnamespace\s*{', line)
       and line[-1] != '\\'):
     error(filename, linenum, 'build/namespaces_headers', 4,
           'Do not use unnamed namespaces in header files.  See '
@@ -5394,7 +5501,7 @@ def CheckGlobalStatic(filename, clean_lines, linenum, error):
   line = clean_lines.elided[linenum]
 
   # Match two lines at a time to support multiline declarations
-  if linenum + 1 < clean_lines.NumLines() and not Search(r'[;({]', line):
+  if linenum + 1 < clean_lines.NumLines() and not re.search(r'[;({]', line):
     line += clean_lines.elided[linenum + 1].strip()
 
   # Check for people declaring static/global STL strings at the top level.
@@ -5403,7 +5510,7 @@ def CheckGlobalStatic(filename, clean_lines, linenum, error):
   # also because globals can be destroyed when some threads are still running.
   # TODO(unknown): Generalize this to also find static unique_ptr instances.
   # TODO(unknown): File bugs for clang-tidy to find these.
-  match = Match(
+  match = re.match(
       r'((?:|static +)(?:|const +))(?::*std::)?string( +const)? +'
       r'([a-zA-Z0-9_:]+)\b(.*)',
       line)
@@ -5425,20 +5532,19 @@ def CheckGlobalStatic(filename, clean_lines, linenum, error):
   #   matching identifiers.
   #    string Class::operator*()
   if (match and
-      not Search(r'\bstring\b(\s+const)?\s*[\*\&]\s*(const\s+)?\w', line) and
-      not Search(r'\boperator\W', line) and
-      not Match(r'\s*(<.*>)?(::[a-zA-Z0-9_]+)*\s*\(([^"]|$)', match.group(4))):
-    if Search(r'\bconst\b', line):
+      not re.search(r'\bstring\b(\s+const)?\s*[\*\&]\s*(const\s+)?\w', line) and
+      not re.search(r'\boperator\W', line) and
+      not re.match(r'\s*(<.*>)?(::[a-zA-Z0-9_]+)*\s*\(([^"]|$)', match.group(4))):
+    if re.search(r'\bconst\b', line):
       error(filename, linenum, 'runtime/string', 4,
-            'For a static/global string constant, use a C style string '
-            'instead: "%schar%s %s[]".' %
-            (match.group(1), match.group(2) or '', match.group(3)))
+            'For a static/global string constant, use a C style string instead:'
+            f' "{match.group(1)}char{match.group(2) or ""} {match.group(3)}[]".')
     else:
       error(filename, linenum, 'runtime/string', 4,
             'Static/global string variables are not permitted.')
 
-  if (Search(r'\b([A-Za-z0-9_]*_)\(\1\)', line) or
-      Search(r'\b([A-Za-z0-9_]*_)\(CHECK_NOTNULL\(\1\)\)', line)):
+  if (re.search(r'\b([A-Za-z0-9_]*_)\(\1\)', line) or
+      re.search(r'\b([A-Za-z0-9_]*_)\(CHECK_NOTNULL\(\1\)\)', line)):
     error(filename, linenum, 'runtime/init', 4,
           'You seem to be initializing a member variable with itself.')
 
@@ -5455,21 +5561,21 @@ def CheckPrintf(filename, clean_lines, linenum, error):
   line = clean_lines.elided[linenum]
 
   # When snprintf is used, the second argument shouldn't be a literal.
-  match = Search(r'snprintf\s*\(([^,]*),\s*([0-9]*)\s*,', line)
+  match = re.search(r'snprintf\s*\(([^,]*),\s*([0-9]*)\s*,', line)
   if match and match.group(2) != '0':
     # If 2nd arg is zero, snprintf is used to calculate size.
-    error(filename, linenum, 'runtime/printf', 3,
-          'If you can, use sizeof(%s) instead of %s as the 2nd arg '
-          'to snprintf.' % (match.group(1), match.group(2)))
+    error(filename, linenum, 'runtime/printf', 3, 'If you can, use'
+          f' sizeof({match.group(1)}) instead of {match.group(2)}'
+          ' as the 2nd arg to snprintf.')
 
   # Check if some verboten C functions are being used.
-  if Search(r'\bsprintf\s*\(', line):
+  if re.search(r'\bsprintf\s*\(', line):
     error(filename, linenum, 'runtime/printf', 5,
           'Never use sprintf. Use snprintf instead.')
-  match = Search(r'\b(strcpy|strcat)\s*\(', line)
+  match = re.search(r'\b(strcpy|strcat)\s*\(', line)
   if match:
     error(filename, linenum, 'runtime/printf', 4,
-          'Almost always, snprintf is better than %s' % match.group(1))
+          f'Almost always, snprintf is better than {match.group(1)}')
 
 
 def IsDerivedFunction(clean_lines, linenum):
@@ -5483,14 +5589,14 @@ def IsDerivedFunction(clean_lines, linenum):
     virt-specifier.
   """
   # Scan back a few lines for start of current function
-  for i in xrange(linenum, max(-1, linenum - 10), -1):
-    match = Match(r'^([^()]*\w+)\(', clean_lines.elided[i])
+  for i in range(linenum, max(-1, linenum - 10), -1):
+    match = re.match(r'^([^()]*\w+)\(', clean_lines.elided[i])
     if match:
       # Look for "override" after the matching closing parenthesis
       line, _, closing_paren = CloseExpression(
           clean_lines, i, len(match.group(1)))
       return (closing_paren >= 0 and
-              Search(r'\boverride\b', line[closing_paren:]))
+              re.search(r'\boverride\b', line[closing_paren:]))
   return False
 
 
@@ -5504,9 +5610,9 @@ def IsOutOfLineMethodDefinition(clean_lines, linenum):
     True if current line contains an out-of-line method definition.
   """
   # Scan back a few lines for start of current function
-  for i in xrange(linenum, max(-1, linenum - 10), -1):
-    if Match(r'^([^()]*\w+)\(', clean_lines.elided[i]):
-      return Match(r'^[^()]*\w+::\w+\(', clean_lines.elided[i]) is not None
+  for i in range(linenum, max(-1, linenum - 10), -1):
+    if re.match(r'^([^()]*\w+)\(', clean_lines.elided[i]):
+      return re.match(r'^[^()]*\w+::\w+\(', clean_lines.elided[i]) is not None
   return False
 
 
@@ -5520,24 +5626,24 @@ def IsInitializerList(clean_lines, linenum):
     True if current line appears to be inside constructor initializer
     list, False otherwise.
   """
-  for i in xrange(linenum, 1, -1):
+  for i in range(linenum, 1, -1):
     line = clean_lines.elided[i]
     if i == linenum:
-      remove_function_body = Match(r'^(.*)\{\s*$', line)
+      remove_function_body = re.match(r'^(.*)\{\s*$', line)
       if remove_function_body:
         line = remove_function_body.group(1)
 
-    if Search(r'\s:\s*\w+[({]', line):
+    if re.search(r'\s:\s*\w+[({]', line):
       # A lone colon tend to indicate the start of a constructor
       # initializer list.  It could also be a ternary operator, which
       # also tend to appear in constructor initializer lists as
       # opposed to parameter lists.
       return True
-    if Search(r'\}\s*,\s*$', line):
+    if re.search(r'\}\s*,\s*$', line):
       # A closing brace followed by a comma is probably the end of a
       # brace-initialized member in constructor initializer list.
       return True
-    if Search(r'[{};]\s*$', line):
+    if re.search(r'[{};]\s*$', line):
       # Found one of the following:
       # - A closing brace or semicolon, probably the end of the previous
       #   function.
@@ -5601,13 +5707,13 @@ def CheckForNonConstReference(filename, clean_lines, linenum,
   # that spans more than 2 lines, please use a typedef.
   if linenum > 1:
     previous = None
-    if Match(r'\s*::(?:[\w<>]|::)+\s*&\s*\S', line):
+    if re.match(r'\s*::(?:[\w<>]|::)+\s*&\s*\S', line):
       # previous_line\n + ::current_line
-      previous = Search(r'\b((?:const\s*)?(?:[\w<>]|::)+[\w<>])\s*$',
+      previous = re.search(r'\b((?:const\s*)?(?:[\w<>]|::)+[\w<>])\s*$',
                         clean_lines.elided[linenum - 1])
-    elif Match(r'\s*[a-zA-Z_]([\w<>]|::)+\s*&\s*\S', line):
+    elif re.match(r'\s*[a-zA-Z_]([\w<>]|::)+\s*&\s*\S', line):
       # previous_line::\n + current_line
-      previous = Search(r'\b((?:const\s*)?(?:[\w<>]|::)+::)\s*$',
+      previous = re.search(r'\b((?:const\s*)?(?:[\w<>]|::)+::)\s*$',
                         clean_lines.elided[linenum - 1])
     if previous:
       line = previous.group(1) + line.lstrip()
@@ -5621,7 +5727,7 @@ def CheckForNonConstReference(filename, clean_lines, linenum,
           # Found the matching < on an earlier line, collect all
           # pieces up to current line.
           line = ''
-          for i in xrange(startline, linenum + 1):
+          for i in range(startline, linenum + 1):
             line += clean_lines.elided[i].strip()
 
   # Check for non-const references in function parameters.  A single '&' may
@@ -5645,15 +5751,15 @@ def CheckForNonConstReference(filename, clean_lines, linenum,
   # appear inside the second set of parentheses on the current line as
   # opposed to the first set.
   if linenum > 0:
-    for i in xrange(linenum - 1, max(0, linenum - 10), -1):
+    for i in range(linenum - 1, max(0, linenum - 10), -1):
       previous_line = clean_lines.elided[i]
-      if not Search(r'[),]\s*$', previous_line):
+      if not re.search(r'[),]\s*$', previous_line):
         break
-      if Match(r'^\s*:\s+\S', previous_line):
+      if re.match(r'^\s*:\s+\S', previous_line):
         return
 
   # Avoid preprocessors
-  if Search(r'\\\s*$', line):
+  if re.search(r'\\\s*$', line):
     return
 
   # Avoid constructor initializer lists
@@ -5670,25 +5776,25 @@ def CheckForNonConstReference(filename, clean_lines, linenum,
                            r'operator\s*[<>][<>]|'
                            r'static_assert|COMPILE_ASSERT'
                            r')\s*\(')
-  if Search(allowed_functions, line):
+  if re.search(allowed_functions, line):
     return
-  elif not Search(r'\S+\([^)]*$', line):
+  elif not re.search(r'\S+\([^)]*$', line):
     # Don't see an allowed function on this line.  Actually we
     # didn't see any function name on this line, so this is likely a
     # multi-line parameter list.  Try a bit harder to catch this case.
-    for i in xrange(2):
+    for i in range(2):
       if (linenum > i and
-          Search(allowed_functions, clean_lines.elided[linenum - i - 1])):
+          re.search(allowed_functions, clean_lines.elided[linenum - i - 1])):
         return
 
-  decls = ReplaceAll(r'{[^}]*}', ' ', line)  # exclude function body
+  decls = re.sub(r'{[^}]*}', ' ', line)  # exclude function body
   for parameter in re.findall(_RE_PATTERN_REF_PARAM, decls):
-    if (not Match(_RE_PATTERN_CONST_REF_PARAM, parameter) and
-        not Match(_RE_PATTERN_REF_STREAM_PARAM, parameter)):
+    if (not re.match(_RE_PATTERN_CONST_REF_PARAM, parameter) and
+        not re.match(_RE_PATTERN_REF_STREAM_PARAM, parameter)):
       error(filename, linenum, 'runtime/references', 2,
             'Is this a non-const reference? '
             'If so, make const or use a pointer: ' +
-            ReplaceAll(' *<', '<', parameter))
+            re.sub(' *<', '<', parameter))
 
 
 def CheckCasts(filename, clean_lines, linenum, error):
@@ -5706,9 +5812,9 @@ def CheckCasts(filename, clean_lines, linenum, error):
   # I just try to capture the most common basic types, though there are more.
   # Parameterless conversion functions, such as bool(), are allowed as they are
   # probably a member operator declaration or default constructor.
-  match = Search(
+  match = re.search(
       r'(\bnew\s+(?:const\s+)?|\S<\s*(?:const\s+)?)?\b'
-      r'(int|float|double|bool|char|int32|uint32|int64|uint64)'
+      r'(int|float|double|bool|char|int16_t|uint16_t|int32_t|uint32_t|int64_t|uint64_t)'
       r'(\([^)].*)', line)
   expecting_function = ExpectingFunctionArgs(clean_lines, linenum)
   if match and not expecting_function:
@@ -5730,7 +5836,7 @@ def CheckCasts(filename, clean_lines, linenum, error):
 
     # Avoid arrays by looking for brackets that come after the closing
     # parenthesis.
-    if Match(r'\([^()]+\)\s*\[', match.group(3)):
+    if re.match(r'\([^()]+\)\s*\[', match.group(3)):
       return
 
     # Other things to ignore:
@@ -5741,19 +5847,18 @@ def CheckCasts(filename, clean_lines, linenum, error):
     matched_funcptr = match.group(3)
     if (matched_new_or_template is None and
         not (matched_funcptr and
-             (Match(r'\((?:[^() ]+::\s*\*\s*)?[^() ]+\)\s*\(',
+             (re.match(r'\((?:[^() ]+::\s*\*\s*)?[^() ]+\)\s*\(',
                     matched_funcptr) or
               matched_funcptr.startswith('(*)'))) and
-        not Match(r'\s*using\s+\S+\s*=\s*' + matched_type, line) and
-        not Search(r'new\(\S+\)\s*' + matched_type, line)):
+        not re.match(r'\s*using\s+\S+\s*=\s*' + matched_type, line) and
+        not re.search(r'new\(\S+\)\s*' + matched_type, line)):
       error(filename, linenum, 'readability/casting', 4,
             'Using deprecated casting style.  '
-            'Use static_cast<%s>(...) instead' %
-            matched_type)
+            f'Use static_cast<{matched_type}>(...) instead')
 
   if not expecting_function:
     CheckCStyleCast(filename, clean_lines, linenum, 'static_cast',
-                    r'\((int|float|double|bool|char|u?int(16|32|64)|size_t)\)', error)
+                    r'\((int|float|double|bool|char|u?int(16|32|64)_t|size_t)\)', error)
 
   # This doesn't catch all cases. Consider (const char * const)"hello".
   #
@@ -5778,7 +5883,7 @@ def CheckCasts(filename, clean_lines, linenum, error):
   #
   # This is not a cast:
   #   reference_type&(int* function_param);
-  match = Search(
+  match = re.search(
       r'(?:[^\w]&\(([^)*][^)]*)\)[\w(])|'
       r'(?:[^\w]&(static|dynamic|down|reinterpret)_cast\b)', line)
   if match:
@@ -5786,7 +5891,7 @@ def CheckCasts(filename, clean_lines, linenum, error):
     # dereferenced by the casted pointer, as opposed to the casted
     # pointer itself.
     parenthesis_error = False
-    match = Match(r'^(.*&(?:static|dynamic|down|reinterpret)_cast\b)<', line)
+    match = re.match(r'^(.*&(?:static|dynamic|down|reinterpret)_cast\b)<', line)
     if match:
       _, y1, x1 = CloseExpression(clean_lines, linenum, len(match.group(1)))
       if x1 >= 0 and clean_lines.elided[y1][x1] == '(':
@@ -5795,7 +5900,7 @@ def CheckCasts(filename, clean_lines, linenum, error):
           extended_line = clean_lines.elided[y2][x2:]
           if y2 < clean_lines.NumLines() - 1:
             extended_line += clean_lines.elided[y2 + 1]
-          if Match(r'\s*(?:->|\[)', extended_line):
+          if re.match(r'\s*(?:->|\[)', extended_line):
             parenthesis_error = True
 
     if parenthesis_error:
@@ -5827,38 +5932,38 @@ def CheckCStyleCast(filename, clean_lines, linenum, cast_type, pattern, error):
     False otherwise.
   """
   line = clean_lines.elided[linenum]
-  match = Search(pattern, line)
+  match = re.search(pattern, line)
   if not match:
     return False
 
   # Exclude lines with keywords that tend to look like casts
   context = line[0:match.start(1) - 1]
-  if Match(r'.*\b(?:sizeof|alignof|alignas|[_A-Z][_A-Z0-9]*)\s*$', context):
+  if re.match(r'.*\b(?:sizeof|alignof|alignas|[_A-Z][_A-Z0-9]*)\s*$', context):
     return False
 
   # Try expanding current context to see if we one level of
   # parentheses inside a macro.
   if linenum > 0:
-    for i in xrange(linenum - 1, max(0, linenum - 5), -1):
+    for i in range(linenum - 1, max(0, linenum - 5), -1):
       context = clean_lines.elided[i] + context
-  if Match(r'.*\b[_A-Z][_A-Z0-9]*\s*\((?:\([^()]*\)|[^()])*$', context):
+  if re.match(r'.*\b[_A-Z][_A-Z0-9]*\s*\((?:\([^()]*\)|[^()])*$', context):
     return False
 
   # operator++(int) and operator--(int)
-  if context.endswith(' operator++') or context.endswith(' operator--'):
+  if (context.endswith(' operator++') or context.endswith(' operator--') or
+      context.endswith('::operator++') or context.endswith('::operator--')):
     return False
 
   # A single unnamed argument for a function tends to look like old style cast.
   # If we see those, don't issue warnings for deprecated casts.
   remainder = line[match.end(0):]
-  if Match(r'^\s*(?:;|const\b|throw\b|final\b|override\b|[=>{),]|->)',
+  if re.match(r'^\s*(?:;|const\b|throw\b|final\b|override\b|[=>{),]|->)',
            remainder):
     return False
 
   # At this point, all that should be left is actual casts.
   error(filename, linenum, 'readability/casting', 4,
-        'Using C-style cast.  Use %s<%s>(...) instead' %
-        (cast_type, match.group(1)))
+        f'Using C-style cast.  Use {cast_type}<{match.group(1)}>(...) instead')
 
   return True
 
@@ -5875,13 +5980,13 @@ def ExpectingFunctionArgs(clean_lines, linenum):
     of function types.
   """
   line = clean_lines.elided[linenum]
-  return (Match(r'^\s*MOCK_(CONST_)?METHOD\d+(_T)?\(', line) or
+  return (re.match(r'^\s*MOCK_(CONST_)?METHOD\d+(_T)?\(', line) or
           (linenum >= 2 and
-           (Match(r'^\s*MOCK_(?:CONST_)?METHOD\d+(?:_T)?\((?:\S+,)?\s*$',
+           (re.match(r'^\s*MOCK_(?:CONST_)?METHOD\d+(?:_T)?\((?:\S+,)?\s*$',
                   clean_lines.elided[linenum - 1]) or
-            Match(r'^\s*MOCK_(?:CONST_)?METHOD\d+(?:_T)?\(\s*$',
+            re.match(r'^\s*MOCK_(?:CONST_)?METHOD\d+(?:_T)?\(\s*$',
                   clean_lines.elided[linenum - 2]) or
-            Search(r'\bstd::m?function\s*\<\s*$',
+            re.search(r'\bstd::m?function\s*\<\s*$',
                    clean_lines.elided[linenum - 1]))))
 
 
@@ -5910,7 +6015,7 @@ _HEADERS_CONTAINING_TEMPLATES = (
     ('<memory>', ('allocator', 'make_shared', 'make_unique', 'shared_ptr',
                   'unique_ptr', 'weak_ptr')),
     ('<queue>', ('queue', 'priority_queue',)),
-    ('<set>', ('multiset',)),
+    ('<set>', ('set', 'multiset',)),
     ('<stack>', ('stack',)),
     ('<string>', ('char_traits', 'basic_string',)),
     ('<tuple>', ('tuple',)),
@@ -5933,7 +6038,26 @@ _HEADERS_MAYBE_TEMPLATES = (
     ('<utility>', ('forward', 'make_pair', 'move', 'swap')),
     )
 
-_RE_PATTERN_STRING = re.compile(r'\bstring\b')
+# Non templated types or global objects
+_HEADERS_TYPES_OR_OBJS = (
+    # String and others are special -- it is a non-templatized type in STL.
+    ('<string>', ('string',)),
+    ('<iostream>', ('cin', 'cout', 'cerr', 'clog', 'wcin', 'wcout',
+                    'wcerr', 'wclog')),
+    ('<cstdio>', ('FILE', 'fpos_t')))
+
+# Non templated functions
+_HEADERS_FUNCTIONS = (
+    ('<cstdio>', ('fopen', 'freopen',
+                  'fclose', 'fflush', 'setbuf', 'setvbuf', 'fread',
+                  'fwrite', 'fgetc', 'getc', 'fgets', 'fputc', 'putc',
+                  'fputs', 'getchar', 'gets', 'putchar', 'puts', 'ungetc',
+                  'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf',
+                  'vsscanf', 'printf', 'fprintf', 'sprintf', 'snprintf',
+                  'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
+                  'ftell', 'fgetpos', 'fseek', 'fsetpos',
+                  'clearerr', 'feof', 'ferror', 'perror',
+                  'tmpfile', 'tmpnam'),),)
 
 _re_pattern_headers_maybe_templates = []
 for _header, _templates in _HEADERS_MAYBE_TEMPLATES:
@@ -5941,15 +6065,12 @@ for _header, _templates in _HEADERS_MAYBE_TEMPLATES:
     # Match max<type>(..., ...), max(..., ...), but not foo->max, foo.max or
     # 'type::max()'.
     _re_pattern_headers_maybe_templates.append(
-        (re.compile(r'[^>.]\b' + _template + r'(<.*?>)?\([^\)]'),
+        (re.compile(r'((\bstd::)|[^>.:])\b' + _template + r'(<.*?>)?\([^\)]'),
             _template,
             _header))
-# Match set<type>, but not foo->set<type>, foo.set<type>
-_re_pattern_headers_maybe_templates.append(
-    (re.compile(r'[^>.]\bset\s*\<'),
-        'set<>',
-        '<set>'))
-# Match 'map<type> var' and 'std::map<type>(...)', but not 'map<type>(...)''
+
+# Map is often overloaded. Only check, if it is fully qualified.
+# Match 'std::map<type>(...)', but not 'map<type>(...)''
 _re_pattern_headers_maybe_templates.append(
     (re.compile(r'(std\b::\bmap\s*\<)|(^(std\b::\b)map\b\(\s*\<)'),
         'map<>',
@@ -5960,10 +6081,27 @@ _re_pattern_templates = []
 for _header, _templates in _HEADERS_CONTAINING_TEMPLATES:
   for _template in _templates:
     _re_pattern_templates.append(
-        (re.compile(r'(\<|\b)' + _template + r'\s*\<'),
+        (re.compile(r'((^|(^|\s|((^|\W)::))std::)|[^>.:]\b)' + _template + r'\s*\<'),
          _template + '<>',
          _header))
 
+_re_pattern_types_or_objs = []
+for _header, _types_or_objs in _HEADERS_TYPES_OR_OBJS:
+  for _type_or_obj in _types_or_objs:
+    _re_pattern_types_or_objs.append(
+        (re.compile(r'\b' + _type_or_obj + r'\b'),
+            _type_or_obj,
+            _header))
+
+_re_pattern_functions = []
+for _header, _functions in _HEADERS_FUNCTIONS:
+  for _function in _functions:
+    # Match printf(..., ...), but not foo->printf, foo.printf or
+    # 'type::printf()'.
+    _re_pattern_functions.append(
+        (re.compile(r'([^>.]|^)\b' + _function + r'\([^\)]'),
+            _function,
+            _header))
 
 def FilesBelongToSameModule(filename_cc, filename_h):
   """Check if these two filenames belong to the same module.
@@ -5995,7 +6133,7 @@ def FilesBelongToSameModule(filename_cc, filename_h):
     string: the additional prefix needed to open the header file.
   """
   fileinfo_cc = FileInfo(filename_cc)
-  if not fileinfo_cc.Extension().lstrip('.') in GetNonHeaderExtensions():
+  if fileinfo_cc.Extension().lstrip('.') not in GetNonHeaderExtensions():
     return (False, '')
 
   fileinfo_h = FileInfo(filename_h)
@@ -6003,7 +6141,7 @@ def FilesBelongToSameModule(filename_cc, filename_h):
     return (False, '')
 
   filename_cc = filename_cc[:-(len(fileinfo_cc.Extension()))]
-  matched_test_suffix = Search(_TEST_FILE_SUFFIX, fileinfo_cc.BaseName())
+  matched_test_suffix = re.search(_TEST_FILE_SUFFIX, fileinfo_cc.BaseName())
   if matched_test_suffix:
     filename_cc = filename_cc[:-len(matched_test_suffix.group(1))]
 
@@ -6023,34 +6161,6 @@ def FilesBelongToSameModule(filename_cc, filename_h):
   return files_belong_to_same_module, common_path
 
 
-def UpdateIncludeState(filename, include_dict, io=codecs):
-  """Fill up the include_dict with new includes found from the file.
-
-  Args:
-    filename: the name of the header to read.
-    include_dict: a dictionary in which the headers are inserted.
-    io: The io factory to use to read the file. Provided for testability.
-
-  Returns:
-    True if a header was successfully added. False otherwise.
-  """
-  headerfile = None
-  try:
-    with io.open(filename, 'r', 'utf8', 'replace') as headerfile:
-      linenum = 0
-      for line in headerfile:
-        linenum += 1
-        clean_line = CleanseComments(line)
-        match = _RE_PATTERN_INCLUDE.search(clean_line)
-        if match:
-          include = match.group(2)
-          include_dict.setdefault(include, linenum)
-    return True
-  except IOError:
-    return False
-
-
-
 def CheckForIncludeWhatYouUse(filename, clean_lines, include_state, error,
                               io=codecs):
   """Reports for missing stl includes.
@@ -6072,26 +6182,29 @@ def CheckForIncludeWhatYouUse(filename, clean_lines, include_state, error,
   required = {}  # A map of header name to linenumber and the template entity.
                  # Example of required: { '<functional>': (1219, 'less<>') }
 
-  for linenum in xrange(clean_lines.NumLines()):
+  for linenum in range(clean_lines.NumLines()):
     line = clean_lines.elided[linenum]
     if not line or line[0] == '#':
       continue
 
-    # String is special -- it is a non-templatized type in STL.
-    matched = _RE_PATTERN_STRING.search(line)
-    if matched:
-      # Don't warn about strings in non-STL namespaces:
-      # (We check only the first match per line; good enough.)
-      prefix = line[:matched.start()]
-      if prefix.endswith('std::') or not prefix.endswith('::'):
-        required['<string>'] = (linenum, 'string')
+    _re_patterns = []
+    _re_patterns.extend(_re_pattern_types_or_objs)
+    _re_patterns.extend(_re_pattern_functions)
+    for pattern, item, header in _re_patterns:
+      matched = pattern.search(line)
+      if matched:
+        # Don't warn about strings in non-STL namespaces:
+        # (We check only the first match per line; good enough.)
+        prefix = line[:matched.start()]
+        if prefix.endswith('std::') or not prefix.endswith('::'):
+          required[header] = (linenum, item)
 
     for pattern, template, header in _re_pattern_headers_maybe_templates:
       if pattern.search(line):
         required[header] = (linenum, template)
 
     # The following function is just a speed up, no semantics are changed.
-    if not '<' in line:  # Reduces the cpu time usage by skipping lines.
+    if '<' not in line:  # Reduces the cpu time usage by skipping lines.
       continue
 
     for pattern, template, header in _re_pattern_templates:
@@ -6103,46 +6216,10 @@ def CheckForIncludeWhatYouUse(filename, clean_lines, include_state, error,
         if prefix.endswith('std::') or not prefix.endswith('::'):
           required[header] = (linenum, template)
 
-  # The policy is that if you #include something in foo.h you don't need to
-  # include it again in foo.cc. Here, we will look at possible includes.
   # Let's flatten the include_state include_list and copy it into a dictionary.
   include_dict = dict([item for sublist in include_state.include_list
                        for item in sublist])
 
-  # Did we find the header for this file (if any) and successfully load it?
-  header_found = False
-
-  # Use the absolute path so that matching works properly.
-  abs_filename = FileInfo(filename).FullName()
-
-  # For Emacs's flymake.
-  # If cpplint is invoked from Emacs's flymake, a temporary file is generated
-  # by flymake and that file name might end with '_flymake.cc'. In that case,
-  # restore original file name here so that the corresponding header file can be
-  # found.
-  # e.g. If the file name is 'foo_flymake.cc', we should search for 'foo.h'
-  # instead of 'foo_flymake.h'
-  abs_filename = re.sub(r'_flymake\.cc$', '.cc', abs_filename)
-
-  # include_dict is modified during iteration, so we iterate over a copy of
-  # the keys.
-  header_keys = list(include_dict.keys())
-  for header in header_keys:
-    (same_module, common_path) = FilesBelongToSameModule(abs_filename, header)
-    fullpath = common_path + header
-    if same_module and UpdateIncludeState(fullpath, include_dict, io):
-      header_found = True
-
-  # If we can't find the header file for a .cc, assume it's because we don't
-  # know where to look. In that case we'll give up as we're not sure they
-  # didn't include it in the .h file.
-  # TODO(unknown): Do a better job of finding .h files so we are confident that
-  # not having the .h file means there isn't one.
-  if not header_found:
-    for extension in GetNonHeaderExtensions():
-      if filename.endswith('.' + extension):
-        return
-
   # All the lines have been processed, report the errors found.
   for required_header_unstripped in sorted(required, key=required.__getitem__):
     template = required[required_header_unstripped][1]
@@ -6187,20 +6264,20 @@ def CheckRedundantVirtual(filename, clean_lines, linenum, error):
   """
   # Look for "virtual" on current line.
   line = clean_lines.elided[linenum]
-  virtual = Match(r'^(.*)(\bvirtual\b)(.*)$', line)
+  virtual = re.match(r'^(.*)(\bvirtual\b)(.*)$', line)
   if not virtual: return
 
   # Ignore "virtual" keywords that are near access-specifiers.  These
   # are only used in class base-specifier and do not apply to member
   # functions.
-  if (Search(r'\b(public|protected|private)\s+$', virtual.group(1)) or
-      Match(r'^\s+(public|protected|private)\b', virtual.group(3))):
+  if (re.search(r'\b(public|protected|private)\s+$', virtual.group(1)) or
+      re.match(r'^\s+(public|protected|private)\b', virtual.group(3))):
     return
 
   # Ignore the "virtual" keyword from virtual base classes.  Usually
   # there is a column on the same line in these cases (virtual base
   # classes are rare in google3 because multiple inheritance is rare).
-  if Match(r'^.*[^:]:[^:].*$', line): return
+  if re.match(r'^.*[^:]:[^:].*$', line): return
 
   # Look for the next opening parenthesis.  This is the start of the
   # parameter list (possibly on the next line shortly after virtual).
@@ -6210,9 +6287,9 @@ def CheckRedundantVirtual(filename, clean_lines, linenum, error):
   end_col = -1
   end_line = -1
   start_col = len(virtual.group(2))
-  for start_line in xrange(linenum, min(linenum + 3, clean_lines.NumLines())):
+  for start_line in range(linenum, min(linenum + 3, clean_lines.NumLines())):
     line = clean_lines.elided[start_line][start_col:]
-    parameter_list = Match(r'^([^(]*)\(', line)
+    parameter_list = re.match(r'^([^(]*)\(', line)
     if parameter_list:
       # Match parentheses to find the end of the parameter list
       (_, end_line, end_col) = CloseExpression(
@@ -6225,18 +6302,18 @@ def CheckRedundantVirtual(filename, clean_lines, linenum, error):
 
   # Look for "override" or "final" after the parameter list
   # (possibly on the next few lines).
-  for i in xrange(end_line, min(end_line + 3, clean_lines.NumLines())):
+  for i in range(end_line, min(end_line + 3, clean_lines.NumLines())):
     line = clean_lines.elided[i][end_col:]
-    match = Search(r'\b(override|final)\b', line)
+    match = re.search(r'\b(override|final)\b', line)
     if match:
       error(filename, linenum, 'readability/inheritance', 4,
             ('"virtual" is redundant since function is '
-             'already declared as "%s"' % match.group(1)))
+            f'already declared as "{match.group(1)}"'))
 
     # Set end_col to check whole lines after we are done with the
     # first line.
     end_col = 0
-    if Search(r'[^\w]\s*$', line):
+    if re.search(r'[^\w]\s*$', line):
       break
 
 
@@ -6263,7 +6340,7 @@ def CheckRedundantOverrideOrFinal(filename, clean_lines, linenum, error):
       return
 
   # Check that at most one of "override" or "final" is present, not both
-  if Search(r'\boverride\b', fragment) and Search(r'\bfinal\b', fragment):
+  if re.search(r'\boverride\b', fragment) and re.search(r'\bfinal\b', fragment):
     error(filename, linenum, 'readability/inheritance', 4,
           ('"override" is redundant since function is '
            'already declared as "final"'))
@@ -6286,10 +6363,14 @@ def IsBlockInNameSpace(nesting_state, is_forward_declaration):
     return len(nesting_state.stack) >= 1 and (
       isinstance(nesting_state.stack[-1], _NamespaceInfo))
 
-
-  return (len(nesting_state.stack) > 1 and
-          nesting_state.stack[-1].check_namespace_indentation and
-          isinstance(nesting_state.stack[-2], _NamespaceInfo))
+  if len(nesting_state.stack) >= 1:
+    if isinstance(nesting_state.stack[-1], _NamespaceInfo):
+      return True
+    elif (len(nesting_state.stack) > 1 and
+          isinstance(nesting_state.previous_stack_top, _NamespaceInfo) and
+          isinstance(nesting_state.stack[-2], _NamespaceInfo)):
+      return True
+  return False
 
 
 def ShouldCheckNamespaceIndentation(nesting_state, is_namespace_indent_item,
@@ -6328,14 +6409,14 @@ def ShouldCheckNamespaceIndentation(nesting_state, is_namespace_indent_item,
 def CheckItemIndentationInNamespace(filename, raw_lines_no_comments, linenum,
                                     error):
   line = raw_lines_no_comments[linenum]
-  if Match(r'^\s+', line):
-    error(filename, linenum, 'runtime/indentation_namespace', 4,
-          'Do not indent within a namespace')
+  if re.match(r'^\s+', line):
+    error(filename, linenum, 'whitespace/indent_namespace', 4,
+          'Do not indent within a namespace.')
 
 
 def ProcessLine(filename, file_extension, clean_lines, line,
                 include_state, function_state, nesting_state, error,
-                extra_check_functions=None):
+                extra_check_functions=None, cppvar=None):
   """Processes a single line in the file.
 
   Args:
@@ -6353,6 +6434,7 @@ def ProcessLine(filename, file_extension, clean_lines, line,
     extra_check_functions: An array of additional check functions that will be
                            run on each source line. Each function takes 4
                            arguments: filename, clean_lines, line, error
+    cppvar: The header guard variable returned by GetHeaderGuardCPPVar.
   """
   raw_lines = clean_lines.raw_lines
   ParseNolintSuppressions(filename, raw_lines[line], line, error)
@@ -6362,7 +6444,7 @@ def ProcessLine(filename, file_extension, clean_lines, line,
   if nesting_state.InAsmBlock(): return
   CheckForFunctionLengths(filename, clean_lines, line, function_state, error)
   CheckForMultilineCommentsAndStrings(filename, clean_lines, line, error)
-  CheckStyle(filename, clean_lines, line, file_extension, nesting_state, error)
+  CheckStyle(filename, clean_lines, line, file_extension, nesting_state, error, cppvar)
   CheckLanguage(filename, clean_lines, line, file_extension, include_state,
                 nesting_state, error)
   CheckForNonConstReference(filename, clean_lines, line, nesting_state, error)
@@ -6378,8 +6460,9 @@ def ProcessLine(filename, file_extension, clean_lines, line,
     for check_fn in extra_check_functions:
       check_fn(filename, clean_lines, line, error)
 
-def FlagCxx11Features(filename, clean_lines, linenum, error):
-  """Flag those c++11 features that we only allow in certain places.
+
+def FlagCxxHeaders(filename, clean_lines, linenum, error):
+  """Flag C++ headers that the styleguide restricts.
 
   Args:
     filename: The name of the current file.
@@ -6389,64 +6472,20 @@ def FlagCxx11Features(filename, clean_lines, linenum, error):
   """
   line = clean_lines.elided[linenum]
 
-  include = Match(r'\s*#\s*include\s+[<"]([^<"]+)[">]', line)
-
-  # Flag unapproved C++ TR1 headers.
-  if include and include.group(1).startswith('tr1/'):
-    error(filename, linenum, 'build/c++tr1', 5,
-          ('C++ TR1 headers such as <%s> are unapproved.') % include.group(1))
+  include = re.match(r'\s*#\s*include\s+[<"]([^<"]+)[">]', line)
 
   # Flag unapproved C++11 headers.
   if include and include.group(1) in ('cfenv',
-                                      'condition_variable',
                                       'fenv.h',
-                                      'future',
-                                      'mutex',
-                                      'thread',
-                                      'chrono',
                                       'ratio',
-                                      'regex',
-                                      'system_error',
                                      ):
     error(filename, linenum, 'build/c++11', 5,
-          ('<%s> is an unapproved C++11 header.') % include.group(1))
-
-  # The only place where we need to worry about C++11 keywords and library
-  # features in preprocessor directives is in macro definitions.
-  if Match(r'\s*#', line) and not Match(r'\s*#\s*define\b', line): return
-
-  # These are classes and free functions.  The classes are always
-  # mentioned as std::*, but we only catch the free functions if
-  # they're not found by ADL.  They're alphabetical by header.
-  for top_name in (
-      # type_traits
-      'alignment_of',
-      'aligned_union',
-      ):
-    if Search(r'\bstd::%s\b' % top_name, line):
-      error(filename, linenum, 'build/c++11', 5,
-            ('std::%s is an unapproved C++11 class or function.  Send c-style '
-             'an example of where it would make your code more readable, and '
-             'they may let you use it.') % top_name)
-
-
-def FlagCxx14Features(filename, clean_lines, linenum, error):
-  """Flag those C++14 features that we restrict.
-
-  Args:
-    filename: The name of the current file.
-    clean_lines: A CleansedLines instance containing the file.
-    linenum: The number of the line to check.
-    error: The function to call with any errors found.
-  """
-  line = clean_lines.elided[linenum]
-
-  include = Match(r'\s*#\s*include\s+[<"]([^<"]+)[">]', line)
+          f"<{include.group(1)}> is an unapproved C++11 header.")
 
-  # Flag unapproved C++14 headers.
-  if include and include.group(1) in ('scoped_allocator', 'shared_mutex'):
-    error(filename, linenum, 'build/c++14', 5,
-          ('<%s> is an unapproved C++14 header.') % include.group(1))
+  # filesystem is the only unapproved C++17 header
+  if include and include.group(1) == 'filesystem':
+    error(filename, linenum, 'build/c++17', 5,
+          "<filesystem> is an unapproved C++17 header.")
 
 
 def ProcessFileData(filename, file_extension, lines, error,
@@ -6474,19 +6513,23 @@ def ProcessFileData(filename, file_extension, lines, error,
   ResetNolintSuppressions()
 
   CheckForCopyright(filename, lines, error)
-  ProcessGlobalSuppresions(lines)
+  ProcessGlobalSuppressions(lines)
   RemoveMultiLineComments(filename, lines, error)
   clean_lines = CleansedLines(lines)
 
+  cppvar = None
   if IsHeaderExtension(file_extension):
-    CheckForHeaderGuard(filename, clean_lines, error)
+    cppvar = GetHeaderGuardCPPVariable(filename)
+    CheckForHeaderGuard(filename, clean_lines, error, cppvar)
 
-  for line in xrange(clean_lines.NumLines()):
+  for line in range(clean_lines.NumLines()):
     ProcessLine(filename, file_extension, clean_lines, line,
                 include_state, function_state, nesting_state, error,
-                extra_check_functions)
-    FlagCxx11Features(filename, clean_lines, line, error)
-  nesting_state.CheckCompletedBlocks(filename, error)
+                extra_check_functions, cppvar)
+    FlagCxxHeaders(filename, clean_lines, line, error)
+  if _error_suppressions.HasOpenBlock():
+    error(filename, _error_suppressions.GetOpenBlockStart(), 'readability/nolint', 5,
+          'NONLINT block never ended')
 
   CheckForIncludeWhatYouUse(filename, clean_lines, include_state, error)
 
@@ -6518,13 +6561,13 @@ def ProcessConfigOverrides(filename):
     if not base_name:
       break  # Reached the root directory.
 
-    cfg_file = os.path.join(abs_path, "CPPLINT.cfg")
+    cfg_file = os.path.join(abs_path, _config_filename)
     abs_filename = abs_path
     if not os.path.isfile(cfg_file):
       continue
 
     try:
-      with open(cfg_file) as file_handle:
+      with codecs.open(cfg_file, 'r', 'utf8', 'replace') as file_handle:
         for line in file_handle:
           line, _, _ = line.partition('#')  # Remove comments.
           if not line.strip():
@@ -6550,10 +6593,10 @@ def ProcessConfigOverrides(filename):
                 if _cpplint_state.quiet:
                   # Suppress "Ignoring file" warning when using --quiet.
                   return False
-                _cpplint_state.PrintInfo('Ignoring "%s": file excluded by "%s". '
+                _cpplint_state.PrintInfo(f'Ignoring "{filename}": file excluded by "{cfg_file}". '
                                  'File path component "%s" matches '
                                  'pattern "%s"\n' %
-                                 (filename, cfg_file, base_name, val))
+                                 (base_name, val))
                 return False
           elif name == 'linelength':
             global _line_length
@@ -6573,12 +6616,11 @@ def ProcessConfigOverrides(filename):
             ProcessIncludeOrderOption(val)
           else:
             _cpplint_state.PrintError(
-                'Invalid configuration option (%s) in file %s\n' %
-                (name, cfg_file))
+                f'Invalid configuration option ({name}) in file {cfg_file}\n')
 
     except IOError:
       _cpplint_state.PrintError(
-          "Skipping config file '%s': Can't open for reading\n" % cfg_file)
+          f"Skipping config file '{cfg_file}': Can't open for reading\n")
       keep_looking = False
 
   # Apply all the accumulated filters in reverse order (top-level directory
@@ -6622,10 +6664,7 @@ def ProcessFile(filename, vlevel, extra_check_functions=None):
     # If after the split a trailing '\r' is present, it is removed
     # below.
     if filename == '-':
-      lines = codecs.StreamReaderWriter(sys.stdin,
-                                        codecs.getreader('utf8'),
-                                        codecs.getwriter('utf8'),
-                                        'replace').read().split('\n')
+      lines = sys.stdin.read().split('\n')
     else:
       with codecs.open(filename, 'r', 'utf8', 'replace') as target_file:
         lines = target_file.read().split('\n')
@@ -6640,8 +6679,9 @@ def ProcessFile(filename, vlevel, extra_check_functions=None):
         lf_lines.append(linenum + 1)
 
   except IOError:
+    # TODO: Maybe make this have an exit code of 2 after all is done
     _cpplint_state.PrintError(
-        "Skipping input '%s': Can't open for reading\n" % filename)
+        f"Skipping input '{filename}': Can't open for reading\n")
     _RestoreFilters()
     return
 
@@ -6651,8 +6691,8 @@ def ProcessFile(filename, vlevel, extra_check_functions=None):
   # When reading from stdin, the extension is unknown, so no cpplint tests
   # should rely on the extension.
   if filename != '-' and file_extension not in GetAllExtensions():
-    _cpplint_state.PrintError('Ignoring %s; not a valid file name '
-                     '(%s)\n' % (filename, ', '.join(GetAllExtensions())))
+    _cpplint_state.PrintError(f'Ignoring {filename}; not a valid file name'
+                              f' ({(", ".join(GetAllExtensions()))})\n')
   else:
     ProcessFileData(filename, file_extension, lines, Error,
                     extra_check_functions)
@@ -6678,7 +6718,7 @@ def ProcessFile(filename, vlevel, extra_check_functions=None):
   # Suppress printing anything if --quiet was passed unless the error
   # count has increased after processing this file.
   if not _cpplint_state.quiet or old_errors != _cpplint_state.error_count:
-    _cpplint_state.PrintInfo('Done processing %s\n' % filename)
+    _cpplint_state.PrintInfo(f'Done processing {filename}\n')
   _RestoreFilters()
 
 
@@ -6709,7 +6749,7 @@ def PrintCategories():
 
   These are the categories used to filter messages via --filter.
   """
-  sys.stderr.write(''.join('  %s\n' % cat for cat in _ERROR_CATEGORIES))
+  sys.stderr.write(''.join(f'  {cat}\n' for cat in _ERROR_CATEGORIES))
   sys.exit(0)
 
 
@@ -6738,6 +6778,7 @@ def ParseArguments(args):
                                                  'recursive',
                                                  'headers=',
                                                  'includeorder=',
+                                                 'config=',
                                                  'quiet'])
   except getopt.GetoptError:
     PrintUsage('Invalid arguments.')
@@ -6796,6 +6837,11 @@ def ParseArguments(args):
       recursive = True
     elif opt == '--includeorder':
       ProcessIncludeOrderOption(val)
+    elif opt == '--config':
+      global _config_filename
+      _config_filename = val
+      if os.path.basename(_config_filename) != _config_filename:
+        PrintUsage('Config file name must not include directory components.')
 
   if not filenames:
     PrintUsage('No files were specified.')
@@ -6815,6 +6861,32 @@ def ParseArguments(args):
   filenames.sort()
   return filenames
 
+def _ParseFilterSelector(parameter):
+  """Parses the given command line parameter for file- and line-specific
+  exclusions.
+  readability/casting:file.cpp
+  readability/casting:file.cpp:43
+
+  Args:
+    parameter: The parameter value of --filter
+
+  Returns:
+    [category, filename, line].
+    Category is always given.
+    Filename is either a filename or empty if all files are meant.
+    Line is either a line in filename or -1 if all lines are meant.
+  """
+  colon_pos = parameter.find(":")
+  if colon_pos == -1:
+    return parameter, "", -1
+  category = parameter[:colon_pos]
+  second_colon_pos = parameter.find(":", colon_pos + 1)
+  if second_colon_pos == -1:
+    return category, parameter[colon_pos + 1:], -1
+  else:
+    return category, parameter[colon_pos + 1: second_colon_pos], \
+      int(parameter[second_colon_pos + 1:])
+
 def _ExpandDirectories(filenames):
   """Searches a list of filenames and replaces directories in the list with
   all files descending from those directories. Files with extensions not in
diff --git a/tools/cpplint.py-update b/tools/cpplint.py-update
index 3d32330..40d047a 100755
--- a/tools/cpplint.py-update
+++ b/tools/cpplint.py-update
@@ -1,4 +1,4 @@
-#!/bin/bash
+#!/usr/bin/env python3
 # Copyright 2016 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -13,48 +13,103 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-set -eu
-
-# The outdated Google version that only supports Python 2.
-GITHUB_URL="https://github.com/google/styleguide/raw/gh-pages/cpplint"
-# The forked version with Python 3 support.
-GITHUB_URL="https://github.com/cpplint/cpplint/raw/develop"
-SCRIPT_DIR="$(dirname "$(readlink -f -- "$0")")"
-
-usage() {
-  cat <<EOF
-Usage: $0
-
-Helper script to quickly update the bundled cpplint.py script.
-
-EOF
-
-  if [[ $# -ne 0 ]]; then
-    echo "ERROR: $*" 2>&1
-    exit 1
-  else
-    exit 0
-  fi
-}
-
-main() {
-  while [[ $# -gt 0 ]]; do
-    case $1 in
-    -h|--help) usage;;
-    -x) set -x;;
-    *) usage "Unknown option: $1";;
-    esac
-    shift
-  done
-
-  # Download cpplint.py from upstream.
-  local cpplint_py="${SCRIPT_DIR}/cpplint.py"
-  wget "${GITHUB_URL}/cpplint.py" -O "${cpplint_py}"
-  sed -i \
-    -e '1s|python$|python3|' \
-    -e '2i# pylint: skip-file' \
-    "${cpplint_py}"
-  chmod +x "${cpplint_py}"
-}
-
-main "$@"
+"""Helper script to quickly update the bundled cpplint.py script."""
+
+import argparse
+import json
+from pathlib import Path
+import re
+import sys
+import urllib.request
+
+
+# Since this is manually run by repohooks developers, we can safely require more
+# recent versions of Python.
+assert sys.version_info >= (3, 9), f"Python 3.9+ required; found {sys.version}"
+
+
+THIS_FILE = Path(__file__).resolve()
+SCRIPT_NAME = THIS_FILE.name
+THIS_DIR = THIS_FILE.parent
+CPPLINT_PY = THIS_DIR / "cpplint.py"
+
+
+# The cpplint project.
+GITHUB_URL = "https://github.com/cpplint/cpplint/raw"
+
+
+def find_latest_tag() -> str:
+    """Figure out the latest tag/release and return its commit."""
+    url = "https://api.github.com/repos/cpplint/cpplint/tags"
+    with urllib.request.urlopen(url, timeout=60) as fp:
+        data = fp.read()
+
+    # This will have the format:
+    # [
+    #   {"name": "0.0.7", "commit": {"sha": "<sha1>", ...}, ...},
+    #   {"name": "0.0.6", "commit": {"sha": "<sha1>", ...}, ...},
+    #   ...
+    # ]
+    resp = json.loads(data)
+    # Filter out random named tags.
+    tags = [x for x in resp if re.match(r"^[0-9.]+$", x["name"])]
+    tags = sorted(
+        tags,
+        key=lambda x: tuple(int(v) for v in x["name"].split(".")),
+        reverse=True,
+    )
+    latest = tags[0]
+    print(f"{SCRIPT_NAME}: found latest tag {latest['name']}")
+    return latest["commit"]["sha"]
+
+
+def download(commit: str) -> str:
+    """Download latest cpplint version."""
+    url = f"{GITHUB_URL}/{commit}/cpplint.py"
+    with urllib.request.urlopen(url, timeout=60) as fp:
+        return fp.read()
+
+
+def munge_content(data: str) -> str:
+    """Make changes to |data| for local script usage."""
+    lines = data.splitlines()
+    if lines[0].endswith(b"python"):
+        lines[0] += b"3"
+    lines.insert(1, b"# pylint: skip-file")
+    return b"\n".join(lines).rstrip() + b"\n"
+
+
+def update_script(data: str) -> None:
+    """Update the cpplint script."""
+    CPPLINT_PY.write_bytes(data)
+    CPPLINT_PY.chmod(0o755)
+
+
+def get_parser() -> argparse.ArgumentParser:
+    """Return a command line parser."""
+    parser = argparse.ArgumentParser(description=__doc__)
+    parser.add_argument(
+        "--rev",
+        help="What git commit or ref to fetch (default: latest)",
+    )
+    return parser
+
+
+def main(argv: list[str]) -> int:
+    parser = get_parser()
+    opts = parser.parse_args(argv)
+
+    ret = 0
+
+    commit = opts.rev
+    if not commit:
+        commit = find_latest_tag()
+    data = download(commit)
+    data = munge_content(data)
+    update_script(data)
+
+    return ret
+
+
+if __name__ == "__main__":
+    sys.exit(main(sys.argv[1:]))
diff --git a/tools/pylint.py b/tools/pylint.py
index d692d83..8b27da8 100755
--- a/tools/pylint.py
+++ b/tools/pylint.py
@@ -18,12 +18,13 @@
 import argparse
 import errno
 import os
-import shutil
 import sys
 import subprocess
 from typing import Dict, List, Optional, Set
 
 
+# This script is run by repohooks users.
+# See README.md for what version we may require.
 assert (sys.version_info.major, sys.version_info.minor) >= (3, 6), (
     f'Python 3.6 or newer is required; found {sys.version}')
 
@@ -32,37 +33,6 @@ DEFAULT_PYLINTRC_PATH = os.path.join(
     os.path.dirname(os.path.realpath(__file__)), 'pylintrc')
 
 
-def is_pylint3(pylint):
-    """See whether |pylint| supports Python 3."""
-    # Make sure pylint is using Python 3.
-    result = subprocess.run([pylint, '--version'], stdout=subprocess.PIPE,
-                            check=True)
-    if b'Python 3' not in result.stdout:
-        print(f'{__file__}: unable to locate a Python 3 version of pylint; '
-              'Python 3 support cannot be guaranteed', file=sys.stderr)
-        return False
-
-    return True
-
-
-def find_pylint3():
-    """Figure out the name of the pylint tool for Python 3.
-
-    It keeps changing with Python 2->3 migrations.  Fun.
-    """
-    # Prefer pylint3 as that's what we want.
-    if shutil.which('pylint3'):
-        return 'pylint3'
-
-    # If there's no pylint, give up.
-    if not shutil.which('pylint'):
-        print(f'{__file__}: unable to locate pylint; please install:\n'
-              'sudo apt-get install pylint', file=sys.stderr)
-        sys.exit(1)
-
-    return 'pylint'
-
-
 def run_lint(pylint: str, unknown: Optional[List[str]],
              files: Optional[List[str]], init_hook: str,
              pylintrc: Optional[str] = None) -> bool:
@@ -181,9 +151,7 @@ def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
     parser.add_argument('--init-hook', help='Init hook commands to run.')
-    parser.add_argument('--py3', action='store_true',
-                        help='Force Python 3 mode')
-    parser.add_argument('--executable-path',
+    parser.add_argument('--executable-path', default='pylint',
                         help='The path of the pylint executable.')
     parser.add_argument('--no-rcfile', dest='use_default_conf',
                         help='Specify to use the executable\'s default '
@@ -200,16 +168,6 @@ def main(argv):
     ret = 0
 
     pylint = opts.executable_path
-    if pylint is None:
-        if opts.py3:
-            pylint = find_pylint3()
-        else:
-            pylint = 'pylint'
-
-    # Make sure pylint is using Python 3.
-    if opts.py3:
-        is_pylint3(pylint)
-
     if not opts.use_default_conf:
         pylintrc_map = map_pyfiles_to_pylintrc(opts.files)
         first = True
diff --git a/tools/pylintrc b/tools/pylintrc
index 3abe640..3a40922 100644
--- a/tools/pylintrc
+++ b/tools/pylintrc
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-[MASTER]
+[MAIN]
 
 # Specify a configuration file.
 #rcfile=
@@ -21,9 +21,6 @@
 # pygtk.require().
 #init-hook=
 
-# Profiled execution.
-profile=no
-
 # Add files or directories to the blacklist. They should be base names, not
 # paths.
 ignore=CVS,.svn,.git
@@ -37,7 +34,6 @@ load-plugins=
     pylint.extensions.bad_builtin,
     pylint.extensions.check_elif,
     pylint.extensions.docstyle,
-    pylint.extensions.emptystring,
     pylint.extensions.overlapping_exceptions,
     pylint.extensions.redefined_variable_type,
 
@@ -49,19 +45,6 @@ jobs=0
 # active Python interpreter and may run arbitrary code.
 unsafe-load-any-extension=no
 
-# A comma-separated list of package or module names from where C extensions may
-# be loaded. Extensions are loading into the active Python interpreter and may
-# run arbitrary code
-extension-pkg-whitelist=
-
-# Allow optimization of some AST trees. This will activate a peephole AST
-# optimizer, which will apply various small optimizations. For instance, it can
-# be used to obtain the result of joining multiple strings with the addition
-# operator. Joining a lot of strings can lead to a maximum recursion error in
-# Pylint and this flag can prevent that. It has one side effect, the resulting
-# AST will be different than the one from reality.
-optimize-ast=no
-
 
 [MESSAGES CONTROL]
 
@@ -110,33 +93,12 @@ disable=
 
 [REPORTS]
 
-# Set the output format. Available formats are text, parseable, colorized, msvs
-# (visual studio) and html. You can also give a reporter class, eg
-# mypackage.mymodule.MyReporterClass.
-output-format=text
-
-# Put messages in a separate file for each module / package specified on the
-# command line instead of printing them on stdout. Reports (if any) will be
-# written in a file name "pylint_global.[txt|html]".
-files-output=no
-
 # Tells whether to display a full report or only the messages
 reports=no
 
 # Activate the evaluation score.
 score=no
 
-# Python expression which should return a note less than 10 (10 is the highest
-# note). You have access to the variables errors warning, statement which
-# respectively contain the number of errors / warnings messages and the total
-# number of statements analyzed. This is used by the global evaluation report
-# (RP0004).
-#evaluation=10.0 - ((float(5 * error + warning + refactor + convention) / statement) * 10)
-
-# Template used to display messages. This is a python new-style format string
-# used to format the message information. See doc for all details
-#msg-template=
-
 
 [SIMILARITIES]
 
@@ -230,12 +192,6 @@ ignore-long-lines=^\s*(# )?<?https?://\S+>?$
 # else.
 single-line-if-stmt=no
 
-# List of optional constructs for which whitespace checking is disabled. `dict-
-# separator` is used to allow tabulation in dicts, etc.: {1  : 1,\n222: 2}.
-# `trailing-comma` allows a space between comma and closing bracket: (a, ).
-# `empty-line` allows space-only lines.
-no-space-check=trailing-comma,dict-separator
-
 # Maximum number of lines in a module
 max-module-lines=1000
 
@@ -267,77 +223,6 @@ good-names=i,j,k,ex,x,_
 # Bad variable names which should always be refused, separated by a comma
 bad-names=foo,bar,baz,toto,tutu,tata
 
-# Colon-delimited sets of names that determine each other's naming style when
-# the name regexes allow several styles.
-name-group=
-
-# Include a hint for the correct naming format with invalid-name
-include-naming-hint=no
-
-# Regular expression matching correct function names
-function-rgx=[a-z_][a-z0-9_]{2,30}$
-
-# Naming hint for function names
-function-name-hint=[a-z_][a-z0-9_]{2,30}$
-
-# Regular expression matching correct variable names
-variable-rgx=[a-z_][a-z0-9_]{2,30}$
-
-# Naming hint for variable names
-variable-name-hint=[a-z_][a-z0-9_]{2,30}$
-
-# Regular expression matching correct constant names
-const-rgx=(([A-Z_][A-Z0-9_]*)|(__.*__))$
-
-# Naming hint for constant names
-const-name-hint=(([A-Z_][A-Z0-9_]*)|(__.*__))$
-
-# Regular expression matching correct attribute names
-attr-rgx=[a-z_][a-z0-9_]{2,30}$
-
-# Naming hint for attribute names
-attr-name-hint=[a-z_][a-z0-9_]{2,30}$
-
-# Regular expression matching correct argument names
-argument-rgx=[a-z_][a-z0-9_]{2,30}$
-
-# Naming hint for argument names
-argument-name-hint=[a-z_][a-z0-9_]{2,30}$
-
-# Regular expression matching correct class attribute names
-class-attribute-rgx=([A-Za-z_][A-Za-z0-9_]{2,30}|(__.*__))$
-
-# Naming hint for class attribute names
-class-attribute-name-hint=([A-Za-z_][A-Za-z0-9_]{2,30}|(__.*__))$
-
-# Regular expression matching correct inline iteration names
-inlinevar-rgx=[A-Za-z_][A-Za-z0-9_]*$
-
-# Naming hint for inline iteration names
-inlinevar-name-hint=[A-Za-z_][A-Za-z0-9_]*$
-
-# Regular expression matching correct class names
-class-rgx=[A-Z_][a-zA-Z0-9]+$
-
-# Naming hint for class names
-class-name-hint=[A-Z_][a-zA-Z0-9]+$
-
-# Regular expression matching correct module names
-module-rgx=(([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+))$
-
-# Naming hint for module names
-module-name-hint=(([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+))$
-
-# Regular expression which should only match correct method names
-method-rgx=[a-z_][a-z0-9_]{2,30}$
-
-# Naming hint for method names
-method-name-hint=[a-z_][a-z0-9_]{2,30}$
-
-# Regular expression which should only match function or class names that do
-# not require a docstring.
-no-docstring-rgx=^_
-
 # Minimum line length for functions/classes that require docstrings, shorter
 # ones are exempt.
 docstring-min-length=10
@@ -406,22 +291,3 @@ exclude-protected=_asdict,_fields,_replace,_source,_make
 
 # Deprecated modules which should not be used, separated by a comma
 deprecated-modules=regsub,TERMIOS,Bastion,rexec,optparse
-
-# Create a graph of every (i.e. internal and external) dependencies in the
-# given file (report RP0402 must not be disabled)
-import-graph=
-
-# Create a graph of external dependencies in the given file (report RP0402 must
-# not be disabled)
-ext-import-graph=
-
-# Create a graph of internal dependencies in the given file (report RP0402 must
-# not be disabled)
-int-import-graph=
-
-
-[EXCEPTIONS]
-
-# Exceptions that will emit a warning when being caught. Defaults to
-# "Exception"
-overgeneral-exceptions=Exception
```

