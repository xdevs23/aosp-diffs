```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 90cb945..9954a68 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -8,5 +8,10 @@
     {
       "name": "gtest_isolated_tests"
     }
+  ],
+  "postsubmit": [
+    {
+      "name": "gtestifier_test"
+    }
   ]
 }
diff --git a/gtest_isolated/IsolateMain.cpp b/gtest_isolated/IsolateMain.cpp
index 0d214f9..4cadc34 100644
--- a/gtest_isolated/IsolateMain.cpp
+++ b/gtest_isolated/IsolateMain.cpp
@@ -120,7 +120,7 @@ static bool RunInIsolationMode(std::vector<const char*>& args) {
                                                   "riscv64-lldb-server",
                                                   "x86-lldb-server",
                                                   "x86_64-lldb-server"};
-      return debuggers.find(basename(buf)) == debuggers.end();
+      return !debuggers.contains(basename(buf));
     }
     // If we can't figure out what our parent was just assume we are fine to isolate.
   }
diff --git a/gtestifier/Android.bp b/gtestifier/Android.bp
new file mode 100644
index 0000000..b23ae2e
--- /dev/null
+++ b/gtestifier/Android.bp
@@ -0,0 +1,44 @@
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
+
+package {
+    default_team: "trendy_team_native_tools_libraries",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+python_binary_host {
+    name: "gtestifier",
+    srcs: ["gtestifier.py"],
+}
+
+cc_library_static {
+    name: "libgtestifier",
+    host_supported: true,
+    native_bridge_supported: true,
+    srcs: ["gtestifier.cpp"],
+    shared_libs: ["libbase"],
+    static_libs: ["libgtest"],
+    export_include_dirs: ["."],
+}
+
+cc_test {
+    name: "gtestifier_test",
+    host_supported: true,
+    srcs: [
+        "gtestifier_c_test.c",
+        "gtestifier_cpp_test.cpp",
+    ],
+    static_libs: ["libgtestifier"],
+    test_suites: ["general-tests"],
+}
diff --git a/gtestifier/OWNERS b/gtestifier/OWNERS
new file mode 100644
index 0000000..5080d69
--- /dev/null
+++ b/gtestifier/OWNERS
@@ -0,0 +1,2 @@
+ccross@android.com
+cferris@google.com
diff --git a/gtestifier/gtestifier.cpp b/gtestifier/gtestifier.cpp
new file mode 100644
index 0000000..aa86ae1
--- /dev/null
+++ b/gtestifier/gtestifier.cpp
@@ -0,0 +1,42 @@
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
+
+#include <gtest/gtest.h>
+
+class GTestifierTest : public testing::Test {
+ public:
+  GTestifierTest(std::function<int()> func, std::function<bool(int)> predicate,
+                 std::string test_name)
+      : child_test_(func), predicate_(predicate), test_name_(test_name) {}
+  void TestBody() {
+    int result = child_test_();
+    bool pass = predicate_ ? predicate_(result) : result == 0;
+    if (!pass) {
+      FAIL() << "Test " << test_name_ << " failed, result " << result;
+    }
+  }
+
+ private:
+  std::function<int()> child_test_;
+  std::function<bool(int)> predicate_;
+  std::string test_name_;
+};
+
+extern "C" void registerGTestifierTest(const char* test_suite_name, const char* test_name,
+                                       const char* file, int line, int (*func)(),
+                                       bool (*predicate)(int)) {
+  testing::RegisterTest(
+      test_suite_name, test_name, nullptr, nullptr, file, line,
+      [=]() -> GTestifierTest* { return new GTestifierTest(func, predicate, test_name); });
+}
diff --git a/gtestifier/gtestifier.h b/gtestifier/gtestifier.h
new file mode 100644
index 0000000..ed1395a
--- /dev/null
+++ b/gtestifier/gtestifier.h
@@ -0,0 +1,65 @@
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
+
+// This file is included when gtestifier.py rewrites a source file for a standalone test that is
+// normally run as main() to turn it into a gtest.
+
+#pragma once
+
+#include <stdbool.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/cdefs.h>
+
+#define GTESTIFIER_STRINGIFY(x) GTESTIFIER_STRINGIFY2(x)
+#define GTESTIFIER_STRINGIFY2(x) #x
+
+#define GTESTIFIER_CONCAT(x, y) GTESTIFIER_CONCAT2(x, y)
+#define GTESTIFIER_CONCAT2(x, y) x##y
+
+// Create unique names for main() and gtestifierWrapper() so that multiple standalone tests
+// can be linked together.
+#define main GTESTIFIER_CONCAT(GTESTIFIER_TEST, _main)
+#define gtestifierWrapper GTESTIFIER_CONCAT(GTESTIFIER_TEST, _wrapper)
+
+__BEGIN_DECLS
+void registerGTestifierTest(const char* test_suite_name, const char* test_name, const char* file,
+                            int line, int (*func)(), bool (*predicate)(int));
+
+// The signature of main() needs to match the definition used in the standalone test.  If
+// the standalone test uses main() with no arguments then the code will need to be compiled
+// with -DGTESTIFIER_MAIN_NO_ARGUMENTS.
+#if GTESTIFIER_MAIN_NO_ARGUMENTS
+int main(void);
+#else
+int main(int argc, char** argv);
+#endif
+__END_DECLS
+
+// gtestifierWrapper wraps the standalone main() function.
+static int gtestifierWrapper(void) {
+#if GTESTIFIER_MAIN_NO_ARGUMENTS
+  return main();
+#else
+  char* argv[] = {strdup(GTESTIFIER_STRINGIFY(GTESTIFIER_TEST)), NULL};
+  return main(1, argv);
+#endif
+}
+
+// Use a static constructor to register this wrapped test as a gtest.
+__attribute__((constructor)) static void registerGTestifier() {
+  registerGTestifierTest(GTESTIFIER_STRINGIFY(GTESTIFIER_SUITE),
+                         GTESTIFIER_STRINGIFY(GTESTIFIER_TEST), __FILE__, __LINE__,
+                         gtestifierWrapper, GTESTIFIER_PREDICATE);
+};
diff --git a/gtestifier/gtestifier.py b/gtestifier/gtestifier.py
new file mode 100644
index 0000000..6c6d1b4
--- /dev/null
+++ b/gtestifier/gtestifier.py
@@ -0,0 +1,74 @@
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
+#
+""" A tool to rewrite source files to turn individual tests that run in main()
+into gtests"""
+
+import argparse
+import os
+from pathlib import Path
+
+def parse_args() -> argparse.Namespace:
+  """Parse commandline arguments."""
+
+  parser = argparse.ArgumentParser()
+  parser.add_argument('--suite', help='specify test suite name')
+  parser.add_argument('--test_name_prefix', help='specify test name prefix')
+  parser.add_argument('--main_no_arguments', action='store_true',
+                      help='standalone test main function is declared with no arguments')
+  parser.add_argument('--predicate', default='NULL',
+                      help='name of function that converts return value of main to boolean pass signal')
+  parser.add_argument('--in', required=True, dest='in_path', type=Path,
+                      help='specify the input file')
+  parser.add_argument('--out', required=True, dest='out_path', type=Path,
+                      help='specify the output file')
+  return parser.parse_args()
+
+
+def rewrite_test_src(in_path: Path, out_path: Path, suite_name: str,
+                     test_name: str, main_no_arguments: bool, predicate: str):
+  with open(out_path, 'w', encoding='utf8') as out_file:
+    with open(in_path, encoding='utf8') as in_file:
+      out_file.write('// Automatically inserted by gtestifier\n')
+      out_file.write('#ifndef GTESTIFIER_TEST\n')
+      if suite_name:
+        out_file.write(f'#define GTESTIFIER_SUITE {suite_name}\n')
+        out_file.write(f'#define GTESTIFIER_TEST {test_name}\n')
+        out_file.write(f'#define GTESTIFIER_MAIN_NO_ARGUMENTS {int(main_no_arguments)}\n')
+        out_file.write(f'#define GTESTIFIER_PREDICATE {predicate}\n')
+        out_file.write('#include <gtestifier.h>\n')
+        out_file.write('#endif\n')
+        out_file.write('// End automatically inserted by gtestifier\n')
+        out_file.write('\n')
+        out_file.write(in_file.read())
+
+
+def path_to_test_name(in_path: Path, test_name_prefix: str):
+  name = ''.join([c for c in in_path.stem if c == '_' or str.isalnum(c)])
+  return test_name_prefix + name
+
+
+def main():
+  """Program entry point."""
+  args = parse_args()
+
+  rewrite_test_src(args.in_path, args.out_path, args.suite,
+                   path_to_test_name(args.in_path, args.test_name_prefix),
+                   args.main_no_arguments, args.predicate)
+
+
+if __name__ == '__main__':
+  main()
diff --git a/gtestifier/gtestifier_c_test.c b/gtestifier/gtestifier_c_test.c
new file mode 100644
index 0000000..c9630f2
--- /dev/null
+++ b/gtestifier/gtestifier_c_test.c
@@ -0,0 +1,24 @@
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
+
+#define GTESTIFIER_SUITE gtestifier
+#define GTESTIFIER_TEST gtestifier_c_test
+#define GTESTIFIER_MAIN_NO_ARGUMENTS 0
+#define GTESTIFIER_PREDICATE NULL
+
+#include <gtestifier.h>
+
+int main(int argc __attribute__((unused)), char** argv __attribute((unused))) {
+  return 0;
+}
diff --git a/gtestifier/gtestifier_cpp_test.cpp b/gtestifier/gtestifier_cpp_test.cpp
new file mode 100644
index 0000000..9c3262a
--- /dev/null
+++ b/gtestifier/gtestifier_cpp_test.cpp
@@ -0,0 +1,24 @@
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
+
+#define GTESTIFIER_SUITE gtestifier
+#define GTESTIFIER_TEST gtestifier_cpp_test
+#define GTESTIFIER_MAIN_NO_ARGUMENTS 0
+#define GTESTIFIER_PREDICATE NULL
+
+#include <gtestifier.h>
+
+int main(int argc [[maybe_unused]], char** argv [[maybe_unused]]) {
+  return 0;
+}
```

