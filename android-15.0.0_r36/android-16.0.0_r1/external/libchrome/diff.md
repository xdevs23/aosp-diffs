```diff
diff --git a/Android.bp b/Android.bp
index abea2b570..240810e09 100644
--- a/Android.bp
+++ b/Android.bp
@@ -878,10 +878,11 @@ cc_library {
     },
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
     min_sdk_version: "30",
     visibility: [
+        "//build/make/tools/otatools_package",
         "//device/google/bertha:__subpackages__",
         "//device/google/cheets2/camera/v3",
         "//external/avb",
diff --git a/OWNERS b/OWNERS
index 179a7a7dd..23d8dc69f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ jorgelo@google.com
 
 # For Mojo changes.
 hidehiko@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/build/android/gyp/util/build_utils.py b/build/android/gyp/util/build_utils.py
index f41a43a87..3724587af 100644
--- a/build/android/gyp/util/build_utils.py
+++ b/build/android/gyp/util/build_utils.py
@@ -10,7 +10,6 @@ import filecmp
 import fnmatch
 import json
 import os
-import pipes
 import re
 import shutil
 import stat
@@ -168,9 +167,14 @@ class CalledProcessError(Exception):
 
   def __str__(self):
     # A user should be able to simply copy and paste the command that failed
-    # into their shell.
+    # into their shell (unless it is more than 200 chars).
+    # User can set PRINT_FULL_COMMAND=1 to always print the full command.
+    print_full = os.environ.get('PRINT_FULL_COMMAND', '0') != '0'
+    full_cmd = shlex.join(self.args)
+    short_cmd = textwrap.shorten(full_cmd, width=200)
+    printed_cmd = full_cmd if print_full else short_cmd
     copyable_command = '( cd {}; {} )'.format(os.path.abspath(self.cwd),
-        ' '.join(map(pipes.quote, self.args)))
+                                              printed_cmd)
     return 'Command failed: {}\n{}'.format(copyable_command, self.output)
 
 
diff --git a/mojo/public/tools/bindings/pylib/mojom/parse/lexer.py b/mojo/public/tools/bindings/pylib/mojom/parse/lexer.py
index 06354b1d8..7a1da9dea 100644
--- a/mojo/public/tools/bindings/pylib/mojom/parse/lexer.py
+++ b/mojo/public/tools/bindings/pylib/mojom/parse/lexer.py
@@ -2,7 +2,6 @@
 # Use of this source code is governed by a BSD-style license that can be
 # found in the LICENSE file.
 
-import imp
 import os.path
 import sys
 
@@ -16,10 +15,6 @@ def _GetDirAbove(dirname):
     if tail == dirname:
       return path
 
-try:
-  imp.find_module("ply")
-except ImportError:
-  sys.path.append(os.path.join(_GetDirAbove("mojo"), "third_party"))
 from ply.lex import TOKEN
 
 from ..error import Error
```

