```diff
diff --git a/OWNERS b/OWNERS
index 0280764..8e52c19 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,8 @@
+rrangel@google.com
+saklein@google.com
+sfrolov@google.com
+tbain@google.com
 vapier@google.com
-samccone@google.com
+zland@google.com
+
+samccone@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 9b855ec..c1ac4fc 100644
--- a/README.md
+++ b/README.md
@@ -205,7 +205,7 @@ canned hooks already included geared towards AOSP style guidelines.
 * `ktfmt`: Run Kotlin code through `ktfmt`. Supports an additional option
   --include-dirs, which if specified will limit enforcement to only files under
   the specified directories.
-* `pylint`: Alias of `pylint2`.  Will change to `pylint3` by end of 2019.
+* `pylint`: Alias of `pylint3`.
 * `pylint2`: Run Python code through `pylint` using Python 2.
 * `pylint3`: Run Python code through `pylint` using Python 3.
 * `rustfmt`: Run Rust code through `rustfmt`.
@@ -319,7 +319,6 @@ without a bypass being required.
 
 # TODO/Limitations
 
-* `pylint` should support per-directory pylintrc files.
 * Some checkers operate on the files as they exist in the filesystem.  This is
   not easy to fix because the linters require not just the modified file but the
   entire repo in order to perform full checks.  e.g. `pylint` needs to know what
diff --git a/rh/hooks.py b/rh/hooks.py
index 453f74e..ae0ea51 100644
--- a/rh/hooks.py
+++ b/rh/hooks.py
@@ -1076,7 +1076,7 @@ BUILTIN_HOOKS = {
     'google_java_format': check_google_java_format,
     'jsonlint': check_json,
     'ktfmt': check_ktfmt,
-    'pylint': check_pylint2,
+    'pylint': check_pylint3,
     'pylint2': check_pylint2,
     'pylint3': check_pylint3,
     'rustfmt': check_rustfmt,
diff --git a/tools/google-java-format.py b/tools/google-java-format.py
index 88ffed8..ebb9475 100755
--- a/tools/google-java-format.py
+++ b/tools/google-java-format.py
@@ -44,9 +44,6 @@ def get_parser():
                         help='Fix any formatting errors automatically.')
     parser.add_argument('--commit', type=str, default='HEAD',
                         help='Specify the commit to validate.')
-    # TODO: b/344615661 — Remove argument when all usage has been updated
-    parser.add_argument('--sort-imports', action='store_true',
-                        help='Deprecated, do nothing')
     parser.add_argument('--skip-sorting-imports', action='store_true',
                         help='If true, imports will not be sorted.')
     parser.add_argument('files', nargs='*',
diff --git a/tools/pylint.py b/tools/pylint.py
index 3fbb148..d692d83 100755
--- a/tools/pylint.py
+++ b/tools/pylint.py
@@ -21,6 +21,7 @@ import os
 import shutil
 import sys
 import subprocess
+from typing import Dict, List, Optional, Set
 
 
 assert (sys.version_info.major, sys.version_info.minor) >= (3, 6), (
@@ -62,6 +63,120 @@ def find_pylint3():
     return 'pylint'
 
 
+def run_lint(pylint: str, unknown: Optional[List[str]],
+             files: Optional[List[str]], init_hook: str,
+             pylintrc: Optional[str] = None) -> bool:
+    """Run lint command.
+
+    Upon error the stdout from pylint will be dumped to stdout and
+    False will be returned.
+    """
+    cmd = [pylint]
+
+    if not files:
+        # No files to analyze for this pylintrc file.
+        return True
+
+    if pylintrc:
+        cmd += ['--rcfile', pylintrc]
+
+    files.sort()
+    cmd += unknown + files
+
+    if init_hook:
+        cmd += ['--init-hook', init_hook]
+
+    try:
+        result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True,
+                                check=False)
+    except OSError as e:
+        if e.errno == errno.ENOENT:
+            print(f'{__file__}: unable to run `{cmd[0]}`: {e}',
+                  file=sys.stderr)
+            print(f'{__file__}: Try installing pylint: sudo apt-get install '
+                  f'{os.path.basename(cmd[0])}', file=sys.stderr)
+            return False
+
+        raise
+
+    if result.returncode:
+        print(f'{__file__}: Using pylintrc: {pylintrc}')
+        print(result.stdout)
+        return False
+
+    return True
+
+
+def find_parent_dirs_with_pylintrc(leafdir: str,
+                                   pylintrc_map: Dict[str, Set[str]]) -> None:
+    """Find all dirs containing a pylintrc between root dir and leafdir."""
+
+    # Find all pylintrc files, store the path. The path must end with '/'
+    # to make sure that string compare can be used to compare with full
+    # path to python files later.
+
+    rootdir = os.path.abspath(".") + os.sep
+    key = os.path.abspath(leafdir) + os.sep
+
+    if not key.startswith(rootdir):
+        sys.exit(f'{__file__}: The search directory {key} is outside the '
+                 f'repo dir {rootdir}')
+
+    while rootdir != key:
+        # This subdirectory has already been handled, skip it.
+        if key in pylintrc_map:
+            break
+
+        if os.path.exists(os.path.join(key, 'pylintrc')):
+            pylintrc_map.setdefault(key, set())
+            break
+
+        # Go up one directory.
+        key = os.path.abspath(os.path.join(key, os.pardir)) + os.sep
+
+
+def map_pyfiles_to_pylintrc(files: List[str]) -> Dict[str, Set[str]]:
+    """ Map all python files to a pylintrc file.
+
+    Generate dictionary with pylintrc-file dirnames (including trailing /)
+    as key containing sets with corresponding python files.
+    """
+
+    pylintrc_map = {}
+    # We assume pylint is running in the top directory of the project,
+    # so load the pylintrc file from there if it is available.
+    pylintrc = os.path.abspath('pylintrc')
+    if not os.path.exists(pylintrc):
+        pylintrc = DEFAULT_PYLINTRC_PATH
+        # If we pass a non-existent rcfile to pylint, it'll happily ignore
+        # it.
+        assert os.path.exists(pylintrc), f'Could not find {pylintrc}'
+    # Always add top directory, either there is a pylintrc or fallback to
+    # default.
+    key = os.path.abspath('.') + os.sep
+    pylintrc_map[key] = set()
+
+    search_dirs = {os.path.dirname(x) for x in files}
+    for search_dir in search_dirs:
+        find_parent_dirs_with_pylintrc(search_dir, pylintrc_map)
+
+    # List of directories where pylintrc files are stored, most
+    # specific path first.
+    rc_dir_names = sorted(pylintrc_map, reverse=True)
+    # Map all python files to a pylintrc file.
+    for f in files:
+        f_full = os.path.abspath(f)
+        for rc_dir in rc_dir_names:
+            # The pylintrc map keys always have trailing /.
+            if f_full.startswith(rc_dir):
+                pylintrc_map[rc_dir].add(f)
+                break
+        else:
+            sys.exit(f'{__file__}: Failed to map file {f} to a pylintrc file.')
+
+    return pylintrc_map
+
+
 def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
@@ -70,7 +185,7 @@ def get_parser():
                         help='Force Python 3 mode')
     parser.add_argument('--executable-path',
                         help='The path of the pylint executable.')
-    parser.add_argument('--no-rcfile',
+    parser.add_argument('--no-rcfile', dest='use_default_conf',
                         help='Specify to use the executable\'s default '
                         'configuration.',
                         action='store_true')
@@ -82,6 +197,7 @@ def main(argv):
     """The main entry."""
     parser = get_parser()
     opts, unknown = parser.parse_known_args(argv)
+    ret = 0
 
     pylint = opts.executable_path
     if pylint is None:
@@ -94,35 +210,25 @@ def main(argv):
     if opts.py3:
         is_pylint3(pylint)
 
-    cmd = [pylint]
-    if not opts.no_rcfile:
-        # We assume pylint is running in the top directory of the project,
-        # so load the pylintrc file from there if it's available.
-        pylintrc = os.path.abspath('pylintrc')
-        if not os.path.exists(pylintrc):
-            pylintrc = DEFAULT_PYLINTRC_PATH
-            # If we pass a non-existent rcfile to pylint, it'll happily ignore
-            # it.
-            assert os.path.exists(pylintrc), f'Could not find {pylintrc}'
-        cmd += ['--rcfile', pylintrc]
-
-    cmd += unknown + opts.files
-
-    if opts.init_hook:
-        cmd += ['--init-hook', opts.init_hook]
-
-    try:
-        os.execvp(cmd[0], cmd)
-        return 0
-    except OSError as e:
-        if e.errno == errno.ENOENT:
-            print(f'{__file__}: unable to run `{cmd[0]}`: {e}',
-                  file=sys.stderr)
-            print(f'{__file__}: Try installing pylint: sudo apt-get install '
-                  f'{os.path.basename(cmd[0])}', file=sys.stderr)
-            return 1
-
-        raise
+    if not opts.use_default_conf:
+        pylintrc_map = map_pyfiles_to_pylintrc(opts.files)
+        first = True
+        for rc_dir, files in sorted(pylintrc_map.items()):
+            pylintrc = os.path.join(rc_dir, 'pylintrc')
+            if first:
+                first = False
+                assert os.path.abspath(rc_dir) == os.path.abspath('.'), (
+                    f'{__file__}: pylintrc in top dir not first in list')
+                if not os.path.exists(pylintrc):
+                    pylintrc = DEFAULT_PYLINTRC_PATH
+            if not run_lint(pylint, unknown, sorted(files),
+                            opts.init_hook, pylintrc):
+                ret = 1
+    # Not using rc files, pylint default behaviour.
+    elif not run_lint(pylint, unknown, sorted(opts.files), opts.init_hook):
+        ret = 1
+
+    return ret
 
 
 if __name__ == '__main__':
```

