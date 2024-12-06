```diff
diff --git a/.github/workflows/gtest-ci.yml b/.github/workflows/gtest-ci.yml
deleted file mode 100644
index 03a8cc5e..00000000
--- a/.github/workflows/gtest-ci.yml
+++ /dev/null
@@ -1,43 +0,0 @@
-name: ci
-
-on:
-  push:
-  pull_request:
-
-env:
-  BAZEL_CXXOPTS: -std=c++14
-
-jobs:
-  Linux:
-    runs-on: ubuntu-latest
-    steps:
-
-    - uses: actions/checkout@v3
-      with:
-        fetch-depth: 0
-
-    - name: Tests
-      run: bazel test --cxxopt=-std=c++14 --features=external_include_paths --test_output=errors ...
-
-  macOS:
-    runs-on: macos-latest
-    steps:
-
-    - uses: actions/checkout@v3
-      with:
-        fetch-depth: 0
-
-    - name: Tests
-      run:  bazel test --cxxopt=-std=c++14 --features=external_include_paths --test_output=errors ...
-
-
-  Windows:
-    runs-on: windows-latest
-    steps:
-
-    - uses: actions/checkout@v3
-      with:
-        fetch-depth: 0
-
-    - name: Tests
-      run: bazel test --cxxopt=/std:c++14 --features=external_include_paths --test_output=errors ...
diff --git a/.gitignore b/.gitignore
index fede02f6..f0df39db 100644
--- a/.gitignore
+++ b/.gitignore
@@ -8,6 +8,7 @@ bazel-genfiles
 bazel-googletest
 bazel-out
 bazel-testlogs
+MODULE.bazel.lock
 # python
 *.pyc
 
diff --git a/Android.bp b/Android.bp
index 8ecadf4c..2e77afda 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,3 +42,9 @@ license {
         "LICENSE",
     ],
 }
+
+// Phony library to mark CMakeLists.txt available for cc_cmake_snapshot
+cc_library_host_static {
+    name: "googletest_cmake",
+    cmake_snapshot_supported: true,
+}
diff --git a/BUILD.bazel b/BUILD.bazel
index b1e3b7fb..0306468e 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -56,6 +56,12 @@ config_setting(
     constraint_values = ["@platforms//os:openbsd"],
 )
 
+# NOTE: Fuchsia is not an officially supported platform.
+config_setting(
+    name = "fuchsia",
+    constraint_values = ["@platforms//os:fuchsia"],
+)
+
 config_setting(
     name = "msvc_compiler",
     flag_values = {
@@ -132,19 +138,30 @@ cc_library(
     }),
     deps = select({
         ":has_absl": [
-            "@com_google_absl//absl/container:flat_hash_set",
-            "@com_google_absl//absl/debugging:failure_signal_handler",
-            "@com_google_absl//absl/debugging:stacktrace",
-            "@com_google_absl//absl/debugging:symbolize",
-            "@com_google_absl//absl/flags:flag",
-            "@com_google_absl//absl/flags:parse",
-            "@com_google_absl//absl/flags:reflection",
-            "@com_google_absl//absl/flags:usage",
-            "@com_google_absl//absl/strings",
-            "@com_google_absl//absl/types:any",
-            "@com_google_absl//absl/types:optional",
-            "@com_google_absl//absl/types:variant",
-            "@com_googlesource_code_re2//:re2",
+            "@abseil-cpp//absl/container:flat_hash_set",
+            "@abseil-cpp//absl/debugging:failure_signal_handler",
+            "@abseil-cpp//absl/debugging:stacktrace",
+            "@abseil-cpp//absl/debugging:symbolize",
+            "@abseil-cpp//absl/flags:flag",
+            "@abseil-cpp//absl/flags:parse",
+            "@abseil-cpp//absl/flags:reflection",
+            "@abseil-cpp//absl/flags:usage",
+            "@abseil-cpp//absl/strings",
+            "@abseil-cpp//absl/types:any",
+            "@abseil-cpp//absl/types:optional",
+            "@abseil-cpp//absl/types:variant",
+            "@re2//:re2",
+        ],
+        "//conditions:default": [],
+    }) + select({
+        # `gtest-death-test.cc` has `EXPECT_DEATH` that spawns a process,
+        # expects it to crash and inspects its logs with the given matcher,
+        # so that's why these libraries are needed.
+        # Otherwise, builds targeting Fuchsia would fail to compile.
+        ":fuchsia": [
+            "@fuchsia_sdk//pkg/fdio",
+            "@fuchsia_sdk//pkg/syslog",
+            "@fuchsia_sdk//pkg/zx",
         ],
         "//conditions:default": [],
     }),
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 9e6d6440..512e5c3d 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -4,7 +4,7 @@
 cmake_minimum_required(VERSION 3.13)
 
 project(googletest-distribution)
-set(GOOGLETEST_VERSION 1.14.0)
+set(GOOGLETEST_VERSION 1.15.2)
 
 if(NOT CYGWIN AND NOT MSYS AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL QNX)
   set(CMAKE_CXX_EXTENSIONS OFF)
diff --git a/CONTRIBUTORS b/CONTRIBUTORS
index 77397a5b..ccea41ea 100644
--- a/CONTRIBUTORS
+++ b/CONTRIBUTORS
@@ -55,6 +55,7 @@ Russ Cox <rsc@google.com>
 Russ Rufer <russ@pentad.com>
 Sean Mcafee <eefacm@gmail.com>
 Sigurður Ásgeirsson <siggi@google.com>
+Soyeon Kim <sxshx818@naver.com>
 Sverre Sundsdal <sundsdal@gmail.com>
 Szymon Sobik <sobik.szymon@gmail.com>
 Takeshi Yoshino <tyoshino@google.com>
diff --git a/METADATA b/METADATA
index 7c59c9de..a7caf810 100644
--- a/METADATA
+++ b/METADATA
@@ -1,5 +1,5 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update googletest
+# Usage: tools/external_updater/updater.sh update external/<absolute path to project>
 # For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
 
 name: "googletest"
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 1
-    day: 23
+    month: 8
+    day: 1
   }
   homepage: "https://github.com/google/googletest"
   identifier {
     type: "Git"
     value: "https://github.com/google/googletest.git"
-    version: "563ebf1769af08d448765c31064260e1a16fcced"
+    version: "ff233bdd4cac0a0bf6e5cd45bda3406814cb2796"
   }
 }
diff --git a/MODULE.bazel b/MODULE.bazel
new file mode 100644
index 00000000..c9a52e05
--- /dev/null
+++ b/MODULE.bazel
@@ -0,0 +1,67 @@
+# Copyright 2024 Google Inc.
+# All Rights Reserved.
+#
+#
+# Redistribution and use in source and binary forms, with or without
+# modification, are permitted provided that the following conditions are
+# met:
+#
+#     * Redistributions of source code must retain the above copyright
+# notice, this list of conditions and the following disclaimer.
+#     * Redistributions in binary form must reproduce the above
+# copyright notice, this list of conditions and the following disclaimer
+# in the documentation and/or other materials provided with the
+# distribution.
+#     * Neither the name of Google Inc. nor the names of its
+# contributors may be used to endorse or promote products derived from
+# this software without specific prior written permission.
+#
+# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+
+# https://bazel.build/external/overview#bzlmod
+
+module(
+    name = "googletest",
+    version = "head",
+    compatibility_level = 1,
+)
+
+# Only direct dependencies need to be listed below.
+# Please keep the versions in sync with the versions in the WORKSPACE file.
+
+bazel_dep(name = "abseil-cpp",
+          version = "20240116.2")
+
+bazel_dep(name = "platforms",
+          version = "0.0.10")
+
+bazel_dep(name = "re2",
+          version = "2024-07-02")
+
+bazel_dep(name = "rules_python",
+          version = "0.34.0",
+          dev_dependency = True)
+
+# https://rules-python.readthedocs.io/en/stable/toolchains.html#library-modules-with-dev-only-python-usage
+python = use_extension(
+    "@rules_python//python/extensions:python.bzl",
+    "python",
+    dev_dependency = True
+)
+
+python.toolchain(python_version = "3.12",
+                 is_default = True,
+                 ignore_root_user_error = True)
+
+fake_fuchsia_sdk = use_repo_rule("//:fake_fuchsia_sdk.bzl", "fake_fuchsia_sdk")
+fake_fuchsia_sdk(name = "fuchsia_sdk")
diff --git a/README.md b/README.md
index c1c14465..03c70a1e 100644
--- a/README.md
+++ b/README.md
@@ -9,7 +9,7 @@ GoogleTest now follows the
 We recommend
 [updating to the latest commit in the `main` branch as often as possible](https://github.com/abseil/abseil-cpp/blob/master/FAQ.md#what-is-live-at-head-and-how-do-i-do-it).
 We do publish occasional semantic versions, tagged with
-`v${major}.${minor}.${patch}` (e.g. `v1.14.0`).
+`v${major}.${minor}.${patch}` (e.g. `v1.15.2`).
 
 #### Documentation Updates
 
@@ -17,25 +17,21 @@ Our documentation is now live on GitHub Pages at
 https://google.github.io/googletest/. We recommend browsing the documentation on
 GitHub Pages rather than directly in the repository.
 
-#### Release 1.14.0
+#### Release 1.15.2
 
-[Release 1.14.0](https://github.com/google/googletest/releases/tag/v1.14.0) is
+[Release 1.15.2](https://github.com/google/googletest/releases/tag/v1.15.2) is
 now available.
 
-The 1.14.x branch requires at least C++14.
+The 1.15.x branch requires at least C++14.
 
 #### Continuous Integration
 
-We use Google's internal systems for continuous integration. \
-GitHub Actions were added for the convenience of open-source contributors. They
-are exclusively maintained by the open-source community and not used by the
-GoogleTest team.
+We use Google's internal systems for continuous integration.
 
 #### Coming Soon
 
 *   We are planning to take a dependency on
     [Abseil](https://github.com/abseil/abseil-cpp).
-*   More documentation improvements are planned.
 
 ## Welcome to **GoogleTest**, Google's C++ test framework!
 
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 32e6a971..a3653235 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -3,10 +3,6 @@
     {
       "name": "gtest_isolated_tests"
     },
-    {
-      // Confirm GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST behavior
-      "name": "VtsHalBluetoothA2dpV1_0TargetTest"
-    },
     {
       // Confirm VTS test can pass
       "name": "VtsHalPowerStatsV1_0TargetTest"
@@ -17,8 +13,34 @@
       "name": "gtest_isolated_tests"
     },
     {
-      // Confirm GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST behavior
-      "name": "VtsHalBluetoothA2dpV1_0TargetTest"
+      "name": "gtest_tests"
+    },
+    {
+      "name": "gtest_tests_no_main"
+    },
+    {
+      "name": "googletest-param-test-test"
+    },
+    {
+      "name": "gtest-typed-test_test"
+    },
+    {
+      "name": "gtest_prod_test"
+    },
+    {
+      "name": "gtest_ndk_tests"
+    },
+    {
+      "name": "gtest_ndk_tests_no_main"
+    },
+    {
+      "name": "googletest-param-test-test_ndk"
+    },
+    {
+      "name": "gtest-typed-test_test_ndk"
+    },
+    {
+      "name": "gtest_prod_test_ndk"
     },
     {
       // Confirm VTS test can pass
diff --git a/WORKSPACE b/WORKSPACE
index f819ffe6..63f76813 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -1,4 +1,34 @@
-workspace(name = "com_google_googletest")
+# Copyright 2024 Google Inc.
+# All Rights Reserved.
+#
+#
+# Redistribution and use in source and binary forms, with or without
+# modification, are permitted provided that the following conditions are
+# met:
+#
+#     * Redistributions of source code must retain the above copyright
+# notice, this list of conditions and the following disclaimer.
+#     * Redistributions in binary form must reproduce the above
+# copyright notice, this list of conditions and the following disclaimer
+# in the documentation and/or other materials provided with the
+# distribution.
+#     * Neither the name of Google Inc. nor the names of its
+# contributors may be used to endorse or promote products derived from
+# this software without specific prior written permission.
+#
+# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+
+workspace(name = "googletest")
 
 load("//:googletest_deps.bzl", "googletest_deps")
 googletest_deps()
@@ -6,22 +36,27 @@ googletest_deps()
 load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 
 http_archive(
-  name = "rules_python",  # 2023-07-31T20:39:27Z
-  sha256 = "1250b59a33c591a1c4ba68c62e95fc88a84c334ec35a2e23f46cbc1b9a5a8b55",
-  strip_prefix = "rules_python-e355becc30275939d87116a4ec83dad4bb50d9e1",
-  urls = ["https://github.com/bazelbuild/rules_python/archive/e355becc30275939d87116a4ec83dad4bb50d9e1.zip"],
+  name = "rules_python",
+  sha256 = "d71d2c67e0bce986e1c5a7731b4693226867c45bfe0b7c5e0067228a536fc580",
+  strip_prefix = "rules_python-0.29.0",
+  urls = ["https://github.com/bazelbuild/rules_python/releases/download/0.29.0/rules_python-0.29.0.tar.gz"],
 )
 
+# https://github.com/bazelbuild/rules_python/releases/tag/0.29.0
+load("@rules_python//python:repositories.bzl", "py_repositories")
+py_repositories()
+
 http_archive(
-  name = "bazel_skylib",  # 2023-05-31T19:24:07Z
-  sha256 = "08c0386f45821ce246bbbf77503c973246ed6ee5c3463e41efc197fa9bc3a7f4",
-  strip_prefix = "bazel-skylib-288731ef9f7f688932bd50e704a91a45ec185f9b",
-  urls = ["https://github.com/bazelbuild/bazel-skylib/archive/288731ef9f7f688932bd50e704a91a45ec185f9b.zip"],
+  name = "bazel_skylib",
+  sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
+  urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz"],
 )
 
 http_archive(
-  name = "platforms",  # 2023-07-28T19:44:27Z
-  sha256 = "40eb313613ff00a5c03eed20aba58890046f4d38dec7344f00bb9a8867853526",
-  strip_prefix = "platforms-4ad40ef271da8176d4fc0194d2089b8a76e19d7b",
-  urls = ["https://github.com/bazelbuild/platforms/archive/4ad40ef271da8176d4fc0194d2089b8a76e19d7b.zip"],
+    name = "platforms",
+    urls = [
+        "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
+        "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
+    ],
+    sha256 = "218efe8ee736d26a3572663b374a253c012b716d8af0c07e842e82f238a0a7ee",
 )
diff --git a/WORKSPACE.bzlmod b/WORKSPACE.bzlmod
new file mode 100644
index 00000000..381432c5
--- /dev/null
+++ b/WORKSPACE.bzlmod
@@ -0,0 +1,35 @@
+# Copyright 2024 Google Inc.
+# All Rights Reserved.
+#
+#
+# Redistribution and use in source and binary forms, with or without
+# modification, are permitted provided that the following conditions are
+# met:
+#
+#     * Redistributions of source code must retain the above copyright
+# notice, this list of conditions and the following disclaimer.
+#     * Redistributions in binary form must reproduce the above
+# copyright notice, this list of conditions and the following disclaimer
+# in the documentation and/or other materials provided with the
+# distribution.
+#     * Neither the name of Google Inc. nor the names of its
+# contributors may be used to endorse or promote products derived from
+# this software without specific prior written permission.
+#
+# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
+# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
+# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
+# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
+# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
+# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
+# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+
+# https://bazel.build/external/migration#workspace.bzlmod
+#
+# This file is intentionally empty. When bzlmod is enabled and this
+# file exists, the content of WORKSPACE is ignored. This prevents
+# bzlmod builds from unintentionally depending on the WORKSPACE file.
diff --git a/ci/linux-presubmit.sh b/ci/linux-presubmit.sh
index 1e05998e..6d2b3fb5 100644
--- a/ci/linux-presubmit.sh
+++ b/ci/linux-presubmit.sh
@@ -31,7 +31,7 @@
 
 set -euox pipefail
 
-readonly LINUX_LATEST_CONTAINER="gcr.io/google.com/absl-177019/linux_hybrid-latest:20231218"
+readonly LINUX_LATEST_CONTAINER="gcr.io/google.com/absl-177019/linux_hybrid-latest:20240523"
 readonly LINUX_GCC_FLOOR_CONTAINER="gcr.io/google.com/absl-177019/linux_gcc-floor:20230120"
 
 if [[ -z ${GTEST_ROOT:-} ]]; then
@@ -67,6 +67,9 @@ for cc in /usr/local/bin/gcc /opt/llvm/clang/bin/clang; do
 done
 
 # Do one test with an older version of GCC
+# TODO(googletest-team): This currently uses Bazel 5. When upgrading to a
+# version of Bazel that supports Bzlmod, add --enable_bzlmod=false to keep test
+# coverage for the old WORKSPACE dependency management.
 time docker run \
   --volume="${GTEST_ROOT}:/src:ro" \
   --workdir="/src" \
@@ -101,7 +104,7 @@ for std in ${STD}; do
         --copt="-Wuninitialized" \
         --copt="-Wundef" \
         --define="absl=${absl}" \
-        --enable_bzlmod=false \
+        --enable_bzlmod=true \
         --features=external_include_paths \
         --keep_going \
         --show_timestamps \
@@ -126,7 +129,7 @@ for std in ${STD}; do
         --copt="-Wuninitialized" \
         --copt="-Wundef" \
         --define="absl=${absl}" \
-        --enable_bzlmod=false \
+        --enable_bzlmod=true \
         --features=external_include_paths \
         --keep_going \
         --linkopt="--gcc-toolchain=/usr/local" \
diff --git a/ci/macos-presubmit.sh b/ci/macos-presubmit.sh
index 1033282e..70eaa74f 100644
--- a/ci/macos-presubmit.sh
+++ b/ci/macos-presubmit.sh
@@ -69,6 +69,7 @@ for absl in 0 1; do
     --copt="-Wundef" \
     --cxxopt="-std=c++14" \
     --define="absl=${absl}" \
+    --enable_bzlmod=true \
     --features=external_include_paths \
     --keep_going \
     --show_timestamps \
diff --git a/ci/windows-presubmit.bat b/ci/windows-presubmit.bat
index 38565fbf..1adc1a16 100644
--- a/ci/windows-presubmit.bat
+++ b/ci/windows-presubmit.bat
@@ -46,11 +46,17 @@ RMDIR /S /Q cmake_msvc2022
 :: ----------------------------------------------------------------------------
 :: Bazel
 
+:: The default home directory on Kokoro is a long path which causes errors
+:: because of Windows limitations on path length.
+:: --output_user_root=C:\tmp causes Bazel to use a shorter path.
 SET BAZEL_VS=C:\Program Files\Microsoft Visual Studio\2022\Community
-%BAZEL_EXE% test ... ^
+%BAZEL_EXE% ^
+  --output_user_root=C:\tmp ^
+  test ... ^
   --compilation_mode=dbg ^
   --copt=/std:c++14 ^
   --copt=/WX ^
+  --enable_bzlmod=true ^
   --keep_going ^
   --test_output=errors ^
   --test_tag_filters=-no_test_msvc2017
diff --git a/docs/advanced.md b/docs/advanced.md
index 0e1f812b..240588a8 100644
--- a/docs/advanced.md
+++ b/docs/advanced.md
@@ -1004,11 +1004,21 @@ calling the `::testing::AddGlobalTestEnvironment()` function:
 Environment* AddGlobalTestEnvironment(Environment* env);
 ```
 
-Now, when `RUN_ALL_TESTS()` is called, it first calls the `SetUp()` method of
-each environment object, then runs the tests if none of the environments
-reported fatal failures and `GTEST_SKIP()` was not called. `RUN_ALL_TESTS()`
-always calls `TearDown()` with each environment object, regardless of whether or
-not the tests were run.
+Now, when `RUN_ALL_TESTS()` is invoked, it first calls the `SetUp()` method. The
+tests are then executed, provided that none of the environments have reported
+fatal failures and `GTEST_SKIP()` has not been invoked. Finally, `TearDown()` is
+called.
+
+Note that `SetUp()` and `TearDown()` are only invoked if there is at least one
+test to be performed. Importantly, `TearDown()` is executed even if the test is
+not run due to a fatal failure or `GTEST_SKIP()`.
+
+Calling `SetUp()` and `TearDown()` for each iteration depends on the flag
+`gtest_recreate_environments_when_repeating`. `SetUp()` and `TearDown()` are
+called for each environment object when the object is recreated for each
+iteration. However, if test environments are not recreated for each iteration,
+`SetUp()` is called only on the first iteration, and `TearDown()` is called only
+on the last iteration.
 
 It's OK to register multiple environment objects. In this suite, their `SetUp()`
 will be called in the order they are registered, and their `TearDown()` will be
@@ -1804,7 +1814,7 @@ and/or command line flags. For the flags to work, your programs must call
 `::testing::InitGoogleTest()` before calling `RUN_ALL_TESTS()`.
 
 To see a list of supported flags and their usage, please run your test program
-with the `--help` flag. You can also use `-h`, `-?`, or `/?` for short.
+with the `--help` flag.
 
 If an option is specified both by an environment variable and by a flag, the
 latter takes precedence.
diff --git a/docs/gmock_cook_book.md b/docs/gmock_cook_book.md
index 5e9b6647..f1b10b47 100644
--- a/docs/gmock_cook_book.md
+++ b/docs/gmock_cook_book.md
@@ -3312,7 +3312,7 @@ For convenience, we allow the description string to be empty (`""`), in which
 case gMock will use the sequence of words in the matcher name as the
 description.
 
-For example:
+#### Basic Example
 
 ```cpp
 MATCHER(IsDivisibleBy7, "") { return (arg % 7) == 0; }
@@ -3350,6 +3350,8 @@ If the above assertions fail, they will print something like:
 where the descriptions `"is divisible by 7"` and `"not (is divisible by 7)"` are
 automatically calculated from the matcher name `IsDivisibleBy7`.
 
+#### Adding Custom Failure Messages
+
 As you may have noticed, the auto-generated descriptions (especially those for
 the negation) may not be so great. You can always override them with a `string`
 expression of your own:
@@ -3383,14 +3385,41 @@ With this definition, the above assertion will give a better message:
     Actual: 27 (the remainder is 6)
 ```
 
+#### Using EXPECT_ Statements in Matchers
+
+You can also use `EXPECT_...` (and `ASSERT_...`) statements inside custom
+matcher definitions. In many cases, this allows you to write your matcher more
+concisely while still providing an informative error message. For example:
+
+```cpp
+MATCHER(IsDivisibleBy7, "") {
+  const auto remainder = arg % 7;
+  EXPECT_EQ(remainder, 0);
+  return true;
+}
+```
+
+If you write a test that includes the line `EXPECT_THAT(27, IsDivisibleBy7());`,
+you will get an error something like the following:
+
+```shell
+Expected equality of these values:
+  remainder
+    Which is: 6
+  0
+```
+
+#### `MatchAndExplain`
+
 You should let `MatchAndExplain()` print *any additional information* that can
 help a user understand the match result. Note that it should explain why the
 match succeeds in case of a success (unless it's obvious) - this is useful when
 the matcher is used inside `Not()`. There is no need to print the argument value
 itself, as gMock already prints it for you.
 
-{: .callout .note}
-NOTE: The type of the value being matched (`arg_type`) is determined by the
+#### Argument Types
+
+The type of the value being matched (`arg_type`) is determined by the
 context in which you use the matcher and is supplied to you by the compiler, so
 you don't need to worry about declaring it (nor can you). This allows the
 matcher to be polymorphic. For example, `IsDivisibleBy7()` can be used to match
diff --git a/docs/gmock_for_dummies.md b/docs/gmock_for_dummies.md
index 9f24dcae..ed2297c2 100644
--- a/docs/gmock_for_dummies.md
+++ b/docs/gmock_for_dummies.md
@@ -261,6 +261,8 @@ happen. Therefore it's a good idea to turn on the heap checker in your tests
 when you allocate mocks on the heap. You get that automatically if you use the
 `gtest_main` library already.
 
+###### Expectation Ordering
+
 **Important note:** gMock requires expectations to be set **before** the mock
 functions are called, otherwise the behavior is **undefined**. Do not alternate
 between calls to `EXPECT_CALL()` and calls to the mock functions, and do not set
diff --git a/docs/primer.md b/docs/primer.md
index 0f90c039..61806be6 100644
--- a/docs/primer.md
+++ b/docs/primer.md
@@ -273,14 +273,14 @@ First, define a fixture class. By convention, you should give it the name
 ```c++
 class QueueTest : public testing::Test {
  protected:
-  void SetUp() override {
+  QueueTest() {
      // q0_ remains empty
      q1_.Enqueue(1);
      q2_.Enqueue(2);
      q2_.Enqueue(3);
   }
 
-  // void TearDown() override {}
+  // ~QueueTest() override = default;
 
   Queue<int> q0_;
   Queue<int> q1_;
@@ -288,8 +288,9 @@ class QueueTest : public testing::Test {
 };
 ```
 
-In this case, `TearDown()` is not needed since we don't have to clean up after
-each test, other than what's already done by the destructor.
+In this case, we don't need to define a destructor or a `TearDown()` method,
+because the implicit destructor generated by the compiler will perform all of
+the necessary cleanup.
 
 Now we'll write tests using `TEST_F()` and this fixture.
 
@@ -326,11 +327,9 @@ would lead to a segfault when `n` is `NULL`.
 When these tests run, the following happens:
 
 1.  GoogleTest constructs a `QueueTest` object (let's call it `t1`).
-2.  `t1.SetUp()` initializes `t1`.
-3.  The first test (`IsEmptyInitially`) runs on `t1`.
-4.  `t1.TearDown()` cleans up after the test finishes.
-5.  `t1` is destructed.
-6.  The above steps are repeated on another `QueueTest` object, this time
+2.  The first test (`IsEmptyInitially`) runs on `t1`.
+3.  `t1` is destructed.
+4.  The above steps are repeated on another `QueueTest` object, this time
     running the `DequeueWorks` test.
 
 **Availability**: Linux, Windows, Mac.
diff --git a/docs/quickstart-bazel.md b/docs/quickstart-bazel.md
index 4f693dbe..5750f026 100644
--- a/docs/quickstart-bazel.md
+++ b/docs/quickstart-bazel.md
@@ -10,8 +10,8 @@ To complete this tutorial, you'll need:
 
 *   A compatible operating system (e.g. Linux, macOS, Windows).
 *   A compatible C++ compiler that supports at least C++14.
-*   [Bazel](https://bazel.build/), the preferred build system used by the
-    GoogleTest team.
+*   [Bazel](https://bazel.build/) 7.0 or higher, the preferred build system used
+    by the GoogleTest team.
 
 See [Supported Platforms](platforms.md) for more information about platforms
 compatible with GoogleTest.
@@ -28,7 +28,7 @@ A
 [Bazel workspace](https://docs.bazel.build/versions/main/build-ref.html#workspace)
 is a directory on your filesystem that you use to manage source files for the
 software you want to build. Each workspace directory has a text file named
-`WORKSPACE` which may be empty, or may contain references to external
+`MODULE.bazel` which may be empty, or may contain references to external
 dependencies required to build the outputs.
 
 First, create a directory for your workspace:
@@ -37,30 +37,20 @@ First, create a directory for your workspace:
 $ mkdir my_workspace && cd my_workspace
 ```
 
-Next, you’ll create the `WORKSPACE` file to specify dependencies. A common and
-recommended way to depend on GoogleTest is to use a
-[Bazel external dependency](https://docs.bazel.build/versions/main/external.html)
-via the
-[`http_archive` rule](https://docs.bazel.build/versions/main/repo/http.html#http_archive).
-To do this, in the root directory of your workspace (`my_workspace/`), create a
-file named `WORKSPACE` with the following contents:
+Next, you’ll create the `MODULE.bazel` file to specify dependencies. As of Bazel
+7.0, the recommended way to consume GoogleTest is through the
+[Bazel Central Registry](https://registry.bazel.build/modules/googletest). To do
+this, create a `MODULE.bazel` file in the root directory of your Bazel workspace
+with the following content:
 
 ```
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+# MODULE.bazel
 
-http_archive(
-  name = "com_google_googletest",
-  urls = ["https://github.com/google/googletest/archive/5ab508a01f9eb089207ee87fd547d290da39d015.zip"],
-  strip_prefix = "googletest-5ab508a01f9eb089207ee87fd547d290da39d015",
-)
+# Choose the most recent version available at
+# https://registry.bazel.build/modules/googletest
+bazel_dep(name = "googletest", version = "1.15.2")
 ```
 
-The above configuration declares a dependency on GoogleTest which is downloaded
-as a ZIP archive from GitHub. In the above example,
-`5ab508a01f9eb089207ee87fd547d290da39d015` is the Git commit hash of the
-GoogleTest version to use; we recommend updating the hash often to point to the
-latest version. Use a recent hash on the `main` branch.
-
 Now you're ready to build C++ code that uses GoogleTest.
 
 ## Create and run a binary
@@ -92,17 +82,20 @@ following contents:
 
 ```
 cc_test(
-  name = "hello_test",
-  size = "small",
-  srcs = ["hello_test.cc"],
-  deps = ["@com_google_googletest//:gtest_main"],
+    name = "hello_test",
+    size = "small",
+    srcs = ["hello_test.cc"],
+    deps = [
+        "@googletest//:gtest",
+        "@googletest//:gtest_main",
+    ],
 )
 ```
 
 This `cc_test` rule declares the C++ test binary you want to build, and links to
-GoogleTest (`//:gtest_main`) using the prefix you specified in the `WORKSPACE`
-file (`@com_google_googletest`). For more information about Bazel `BUILD` files,
-see the
+the GoogleTest library (`@googletest//:gtest"`) and the GoogleTest `main()`
+function (`@googletest//:gtest_main`). For more information about Bazel `BUILD`
+files, see the
 [Bazel C++ Tutorial](https://docs.bazel.build/versions/main/tutorial/cpp.html).
 
 {: .callout .note}
@@ -115,7 +108,7 @@ on supported language versions.
 Now you can build and run your test:
 
 <pre>
-<strong>my_workspace$ bazel test --cxxopt=-std=c++14 --test_output=all //:hello_test</strong>
+<strong>$ bazel test --cxxopt=-std=c++14 --test_output=all //:hello_test</strong>
 INFO: Analyzed target //:hello_test (26 packages loaded, 362 targets configured).
 INFO: Found 1 test target...
 INFO: From Testing //:hello_test:
diff --git a/docs/reference/mocking.md b/docs/reference/mocking.md
index 3ad49527..ab37ebf3 100644
--- a/docs/reference/mocking.md
+++ b/docs/reference/mocking.md
@@ -81,8 +81,8 @@ EXPECT_CALL(mock_object, method_name(matchers...))
     .Times(cardinality)            // Can be used at most once
     .InSequence(sequences...)      // Can be used any number of times
     .After(expectations...)        // Can be used any number of times
-    .WillRepeatedly(action)        // Can be used any number of times
-    .WillOnce(action)              // Can be used at most once
+    .WillOnce(action)              // Can be used any number of times
+    .WillRepeatedly(action)        // Can be used at most once
     .RetiresOnSaturation();        // Can be used at most once
 ```
 
diff --git a/docs/reference/testing.md b/docs/reference/testing.md
index 81640fd4..3ed52111 100644
--- a/docs/reference/testing.md
+++ b/docs/reference/testing.md
@@ -94,7 +94,8 @@ Instantiates the value-parameterized test suite *`TestSuiteName`* (defined with
 The argument *`InstantiationName`* is a unique name for the instantiation of the
 test suite, to distinguish between multiple instantiations. In test output, the
 instantiation name is added as a prefix to the test suite name
-*`TestSuiteName`*.
+*`TestSuiteName`*. If *`InstantiationName`* is empty
+(`INSTANTIATE_TEST_SUITE_P(, ...)`), no prefix is added.
 
 The argument *`param_generator`* is one of the following GoogleTest-provided
 functions that generate the test parameters, all defined in the `::testing`
@@ -139,6 +140,7 @@ See also
 ### TYPED_TEST_SUITE {#TYPED_TEST_SUITE}
 
 `TYPED_TEST_SUITE(`*`TestFixtureName`*`,`*`Types`*`)`
+`TYPED_TEST_SUITE(`*`TestFixtureName`*`,`*`Types`*`,`*`NameGenerator`*`)`
 
 Defines a typed test suite based on the test fixture *`TestFixtureName`*. The
 test suite name is *`TestFixtureName`*.
@@ -168,6 +170,22 @@ TYPED_TEST_SUITE(MyFixture, MyTypes);
 The type alias (`using` or `typedef`) is necessary for the `TYPED_TEST_SUITE`
 macro to parse correctly.
 
+The optional third argument *`NameGenerator`* allows specifying a class that
+exposes a templated static function `GetName(int)`. For example:
+
+```cpp
+class NameGenerator {
+ public:
+  template <typename T>
+  static std::string GetName(int) {
+    if constexpr (std::is_same_v<T, char>) return "char";
+    if constexpr (std::is_same_v<T, int>) return "int";
+    if constexpr (std::is_same_v<T, unsigned int>) return "unsignedInt";
+  }
+};
+TYPED_TEST_SUITE(MyFixture, MyTypes, NameGenerator);
+```
+
 See also [`TYPED_TEST`](#TYPED_TEST) and
 [Typed Tests](../advanced.md#typed-tests) for more information.
 
@@ -277,7 +295,8 @@ must be registered with
 The argument *`InstantiationName`* is a unique name for the instantiation of the
 test suite, to distinguish between multiple instantiations. In test output, the
 instantiation name is added as a prefix to the test suite name
-*`TestSuiteName`*.
+*`TestSuiteName`*. If *`InstantiationName`* is empty
+(`INSTANTIATE_TYPED_TEST_SUITE_P(, ...)`), no prefix is added.
 
 The argument *`Types`* is a [`Types`](#Types) object representing the list of
 types to run the tests on, for example:
diff --git a/fake_fuchsia_sdk.bzl b/fake_fuchsia_sdk.bzl
new file mode 100644
index 00000000..2024dc6c
--- /dev/null
+++ b/fake_fuchsia_sdk.bzl
@@ -0,0 +1,33 @@
+"""Provides a fake @fuchsia_sdk implementation that's used when the real one isn't available.
+
+This is needed since bazel queries on targets that depend on //:gtest (eg:
+`bazel query "deps(set(//googletest/test:gtest_all_test))"`) will fail if @fuchsia_sdk is not
+defined when bazel is evaluating the transitive closure of the query target.
+
+See https://github.com/google/googletest/issues/4472.
+"""
+
+def _fake_fuchsia_sdk_impl(repo_ctx):
+    for stub_target in repo_ctx.attr._stub_build_targets:
+        stub_package = stub_target
+        stub_target_name = stub_target.split("/")[-1]
+        repo_ctx.file("%s/BUILD.bazel" % stub_package, """
+filegroup(
+    name = "%s",
+)
+""" % stub_target_name)
+
+fake_fuchsia_sdk = repository_rule(
+    doc = "Used to create a fake @fuchsia_sdk repository with stub build targets.",
+    implementation = _fake_fuchsia_sdk_impl,
+    attrs = {
+        "_stub_build_targets": attr.string_list(
+            doc = "The stub build targets to initialize.",
+            default = [
+                "pkg/fdio",
+                "pkg/syslog",
+                "pkg/zx",
+            ],
+        ),
+    },
+)
diff --git a/googlemock/Android.bp b/googlemock/Android.bp
index 4cc979d2..916466fe 100644
--- a/googlemock/Android.bp
+++ b/googlemock/Android.bp
@@ -92,6 +92,7 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     native_bridge_supported: true,
+    cmake_snapshot_supported: true,
 }
 
 cc_library_static {
@@ -105,6 +106,7 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     native_bridge_supported: true,
+    cmake_snapshot_supported: true,
 }
 
 // Deprecated: use libgmock instead
diff --git a/googlemock/CMakeLists.txt b/googlemock/CMakeLists.txt
index 428bd9f8..99b2411f 100644
--- a/googlemock/CMakeLists.txt
+++ b/googlemock/CMakeLists.txt
@@ -65,12 +65,13 @@ endif()
 config_compiler_and_linker() # from ${gtest_dir}/cmake/internal_utils.cmake
 
 # Adds Google Mock's and Google Test's header directories to the search path.
+# Get Google Test's include dirs from the target, gtest_SOURCE_DIR is broken
+# when using fetch-content with the name "GTest".
+get_target_property(gtest_include_dirs gtest INCLUDE_DIRECTORIES)
 set(gmock_build_include_dirs
   "${gmock_SOURCE_DIR}/include"
   "${gmock_SOURCE_DIR}"
-  "${gtest_SOURCE_DIR}/include"
-  # This directory is needed to build directly from Google Test sources.
-  "${gtest_SOURCE_DIR}")
+  "${gtest_include_dirs}")
 include_directories(${gmock_build_include_dirs})
 
 ########################################################################
diff --git a/googlemock/include/gmock/gmock-actions.h b/googlemock/include/gmock/gmock-actions.h
index fab99933..aa470799 100644
--- a/googlemock/include/gmock/gmock-actions.h
+++ b/googlemock/include/gmock/gmock-actions.h
@@ -1493,6 +1493,7 @@ class DoAllAction<FinalAction> {
   // providing a call operator because even with a particular set of arguments
   // they don't have a fixed return type.
 
+  // We support conversion to OnceAction whenever the sub-action does.
   template <typename R, typename... Args,
             typename std::enable_if<
                 std::is_convertible<FinalAction, OnceAction<R(Args...)>>::value,
@@ -1501,6 +1502,21 @@ class DoAllAction<FinalAction> {
     return std::move(final_action_);
   }
 
+  // We also support conversion to OnceAction whenever the sub-action supports
+  // conversion to Action (since any Action can also be a OnceAction).
+  template <
+      typename R, typename... Args,
+      typename std::enable_if<
+          conjunction<
+              negation<
+                  std::is_convertible<FinalAction, OnceAction<R(Args...)>>>,
+              std::is_convertible<FinalAction, Action<R(Args...)>>>::value,
+          int>::type = 0>
+  operator OnceAction<R(Args...)>() && {  // NOLINT
+    return Action<R(Args...)>(std::move(final_action_));
+  }
+
+  // We support conversion to Action whenever the sub-action does.
   template <
       typename R, typename... Args,
       typename std::enable_if<
@@ -1580,16 +1596,16 @@ class DoAllAction<InitialAction, OtherActions...>
       : Base({}, std::forward<U>(other_actions)...),
         initial_action_(std::forward<T>(initial_action)) {}
 
-  template <typename R, typename... Args,
-            typename std::enable_if<
-                conjunction<
-                    // Both the initial action and the rest must support
-                    // conversion to OnceAction.
-                    std::is_convertible<
-                        InitialAction,
-                        OnceAction<void(InitialActionArgType<Args>...)>>,
-                    std::is_convertible<Base, OnceAction<R(Args...)>>>::value,
-                int>::type = 0>
+  // We support conversion to OnceAction whenever both the initial action and
+  // the rest support conversion to OnceAction.
+  template <
+      typename R, typename... Args,
+      typename std::enable_if<
+          conjunction<std::is_convertible<
+                          InitialAction,
+                          OnceAction<void(InitialActionArgType<Args>...)>>,
+                      std::is_convertible<Base, OnceAction<R(Args...)>>>::value,
+          int>::type = 0>
   operator OnceAction<R(Args...)>() && {  // NOLINT
     // Return an action that first calls the initial action with arguments
     // filtered through InitialActionArgType, then forwards arguments directly
@@ -1612,12 +1628,34 @@ class DoAllAction<InitialAction, OtherActions...>
     };
   }
 
+  // We also support conversion to OnceAction whenever the initial action
+  // supports conversion to Action (since any Action can also be a OnceAction).
+  //
+  // The remaining sub-actions must also be compatible, but we don't need to
+  // special case them because the base class deals with them.
+  template <
+      typename R, typename... Args,
+      typename std::enable_if<
+          conjunction<
+              negation<std::is_convertible<
+                  InitialAction,
+                  OnceAction<void(InitialActionArgType<Args>...)>>>,
+              std::is_convertible<InitialAction,
+                                  Action<void(InitialActionArgType<Args>...)>>,
+              std::is_convertible<Base, OnceAction<R(Args...)>>>::value,
+          int>::type = 0>
+  operator OnceAction<R(Args...)>() && {  // NOLINT
+    return DoAll(
+        Action<void(InitialActionArgType<Args>...)>(std::move(initial_action_)),
+        std::move(static_cast<Base&>(*this)));
+  }
+
+  // We support conversion to Action whenever both the initial action and the
+  // rest support conversion to Action.
   template <
       typename R, typename... Args,
       typename std::enable_if<
           conjunction<
-              // Both the initial action and the rest must support conversion to
-              // Action.
               std::is_convertible<const InitialAction&,
                                   Action<void(InitialActionArgType<Args>...)>>,
               std::is_convertible<const Base&, Action<R(Args...)>>>::value,
@@ -1665,8 +1703,9 @@ template <size_t k>
 struct ReturnArgAction {
   template <typename... Args,
             typename = typename std::enable_if<(k < sizeof...(Args))>::type>
-  auto operator()(Args&&... args) const -> decltype(std::get<k>(
-      std::forward_as_tuple(std::forward<Args>(args)...))) {
+  auto operator()(Args&&... args) const
+      -> decltype(std::get<k>(
+          std::forward_as_tuple(std::forward<Args>(args)...))) {
     return std::get<k>(std::forward_as_tuple(std::forward<Args>(args)...));
   }
 };
@@ -2135,13 +2174,13 @@ struct ActionImpl<R(Args...), Impl> : ImplBase<Impl>::type {
   R operator()(Args&&... arg) const {
     static constexpr size_t kMaxArgs =
         sizeof...(Args) <= 10 ? sizeof...(Args) : 10;
-    return Apply(MakeIndexSequence<kMaxArgs>{},
-                 MakeIndexSequence<10 - kMaxArgs>{},
+    return Apply(std::make_index_sequence<kMaxArgs>{},
+                 std::make_index_sequence<10 - kMaxArgs>{},
                  args_type{std::forward<Args>(arg)...});
   }
 
   template <std::size_t... arg_id, std::size_t... excess_id>
-  R Apply(IndexSequence<arg_id...>, IndexSequence<excess_id...>,
+  R Apply(std::index_sequence<arg_id...>, std::index_sequence<excess_id...>,
           const args_type& args) const {
     // Impl need not be specific to the signature of action being implemented;
     // only the implementing function body needs to have all of the specific
@@ -2174,9 +2213,9 @@ template <typename F, typename Impl>
 }
 
 #define GMOCK_INTERNAL_ARG_UNUSED(i, data, el) \
-  , const arg##i##_type& arg##i GTEST_ATTRIBUTE_UNUSED_
-#define GMOCK_ACTION_ARG_TYPES_AND_NAMES_UNUSED_                 \
-  const args_type& args GTEST_ATTRIBUTE_UNUSED_ GMOCK_PP_REPEAT( \
+  , GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED const arg##i##_type& arg##i
+#define GMOCK_ACTION_ARG_TYPES_AND_NAMES_UNUSED_                               \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED const args_type& args GMOCK_PP_REPEAT( \
       GMOCK_INTERNAL_ARG_UNUSED, , 10)
 
 #define GMOCK_INTERNAL_ARG(i, data, el) , const arg##i##_type& arg##i
diff --git a/googlemock/include/gmock/gmock-matchers.h b/googlemock/include/gmock/gmock-matchers.h
index 9167ac25..0bd6f4df 100644
--- a/googlemock/include/gmock/gmock-matchers.h
+++ b/googlemock/include/gmock/gmock-matchers.h
@@ -492,12 +492,12 @@ class MatcherBaseImpl<Derived<Ts...>> {
 
   template <typename F>
   operator ::testing::Matcher<F>() const {  // NOLINT(runtime/explicit)
-    return Apply<F>(MakeIndexSequence<sizeof...(Ts)>{});
+    return Apply<F>(std::make_index_sequence<sizeof...(Ts)>{});
   }
 
  private:
   template <typename F, std::size_t... tuple_ids>
-  ::testing::Matcher<F> Apply(IndexSequence<tuple_ids...>) const {
+  ::testing::Matcher<F> Apply(std::index_sequence<tuple_ids...>) const {
     return ::testing::Matcher<F>(
         new typename Derived<Ts...>::template gmock_Impl<F>(
             std::get<tuple_ids>(params_)...));
@@ -1302,34 +1302,48 @@ class AllOfMatcherImpl : public MatcherInterface<const T&> {
 
   bool MatchAndExplain(const T& x,
                        MatchResultListener* listener) const override {
-    // If either matcher1_ or matcher2_ doesn't match x, we only need
-    // to explain why one of them fails.
+    // This method uses matcher's explanation when explaining the result.
+    // However, if matcher doesn't provide one, this method uses matcher's
+    // description.
     std::string all_match_result;
-
-    for (size_t i = 0; i < matchers_.size(); ++i) {
+    for (const Matcher<T>& matcher : matchers_) {
       StringMatchResultListener slistener;
-      if (matchers_[i].MatchAndExplain(x, &slistener)) {
-        if (all_match_result.empty()) {
-          all_match_result = slistener.str();
+      // Return explanation for first failed matcher.
+      if (!matcher.MatchAndExplain(x, &slistener)) {
+        const std::string explanation = slistener.str();
+        if (!explanation.empty()) {
+          *listener << explanation;
         } else {
-          std::string result = slistener.str();
-          if (!result.empty()) {
-            all_match_result += ", and ";
-            all_match_result += result;
-          }
+          *listener << "which doesn't match (" << Describe(matcher) << ")";
         }
-      } else {
-        *listener << slistener.str();
         return false;
       }
+      // Keep track of explanations in case all matchers succeed.
+      std::string explanation = slistener.str();
+      if (explanation.empty()) {
+        explanation = Describe(matcher);
+      }
+      if (all_match_result.empty()) {
+        all_match_result = explanation;
+      } else {
+        if (!explanation.empty()) {
+          all_match_result += ", and ";
+          all_match_result += explanation;
+        }
+      }
     }
 
-    // Otherwise we need to explain why *both* of them match.
     *listener << all_match_result;
     return true;
   }
 
  private:
+  // Returns matcher description as a string.
+  std::string Describe(const Matcher<T>& matcher) const {
+    StringMatchResultListener listener;
+    matcher.DescribeTo(listener.stream());
+    return listener.str();
+  }
   const std::vector<Matcher<T>> matchers_;
 };
 
@@ -2922,26 +2936,27 @@ class EachMatcher {
   const M inner_matcher_;
 };
 
-struct Rank1 {};
-struct Rank0 : Rank1 {};
+// Use go/ranked-overloads for dispatching.
+struct Rank0 {};
+struct Rank1 : Rank0 {};
 
 namespace pair_getters {
 using std::get;
 template <typename T>
-auto First(T& x, Rank1) -> decltype(get<0>(x)) {  // NOLINT
+auto First(T& x, Rank0) -> decltype(get<0>(x)) {  // NOLINT
   return get<0>(x);
 }
 template <typename T>
-auto First(T& x, Rank0) -> decltype((x.first)) {  // NOLINT
+auto First(T& x, Rank1) -> decltype((x.first)) {  // NOLINT
   return x.first;
 }
 
 template <typename T>
-auto Second(T& x, Rank1) -> decltype(get<1>(x)) {  // NOLINT
+auto Second(T& x, Rank0) -> decltype(get<1>(x)) {  // NOLINT
   return get<1>(x);
 }
 template <typename T>
-auto Second(T& x, Rank0) -> decltype((x.second)) {  // NOLINT
+auto Second(T& x, Rank1) -> decltype((x.second)) {  // NOLINT
   return x.second;
 }
 }  // namespace pair_getters
@@ -2967,7 +2982,7 @@ class KeyMatcherImpl : public MatcherInterface<PairType> {
                        MatchResultListener* listener) const override {
     StringMatchResultListener inner_listener;
     const bool match = inner_matcher_.MatchAndExplain(
-        pair_getters::First(key_value, Rank0()), &inner_listener);
+        pair_getters::First(key_value, Rank1()), &inner_listener);
     const std::string explanation = inner_listener.str();
     if (!explanation.empty()) {
       *listener << "whose first field is a value " << explanation;
@@ -3089,18 +3104,18 @@ class PairMatcherImpl : public MatcherInterface<PairType> {
     if (!listener->IsInterested()) {
       // If the listener is not interested, we don't need to construct the
       // explanation.
-      return first_matcher_.Matches(pair_getters::First(a_pair, Rank0())) &&
-             second_matcher_.Matches(pair_getters::Second(a_pair, Rank0()));
+      return first_matcher_.Matches(pair_getters::First(a_pair, Rank1())) &&
+             second_matcher_.Matches(pair_getters::Second(a_pair, Rank1()));
     }
     StringMatchResultListener first_inner_listener;
-    if (!first_matcher_.MatchAndExplain(pair_getters::First(a_pair, Rank0()),
+    if (!first_matcher_.MatchAndExplain(pair_getters::First(a_pair, Rank1()),
                                         &first_inner_listener)) {
       *listener << "whose first field does not match";
       PrintIfNotEmpty(first_inner_listener.str(), listener->stream());
       return false;
     }
     StringMatchResultListener second_inner_listener;
-    if (!second_matcher_.MatchAndExplain(pair_getters::Second(a_pair, Rank0()),
+    if (!second_matcher_.MatchAndExplain(pair_getters::Second(a_pair, Rank1()),
                                          &second_inner_listener)) {
       *listener << "whose second field does not match";
       PrintIfNotEmpty(second_inner_listener.str(), listener->stream());
@@ -3153,8 +3168,8 @@ class PairMatcher {
 };
 
 template <typename T, size_t... I>
-auto UnpackStructImpl(const T& t, IndexSequence<I...>, int)
-    -> decltype(std::tie(get<I>(t)...)) {
+auto UnpackStructImpl(const T& t, std::index_sequence<I...>,
+                      int) -> decltype(std::tie(get<I>(t)...)) {
   static_assert(std::tuple_size<T>::value == sizeof...(I),
                 "Number of arguments doesn't match the number of fields.");
   return std::tie(get<I>(t)...);
@@ -3162,97 +3177,97 @@ auto UnpackStructImpl(const T& t, IndexSequence<I...>, int)
 
 #if defined(__cpp_structured_bindings) && __cpp_structured_bindings >= 201606
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<1>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<1>, char) {
   const auto& [a] = t;
   return std::tie(a);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<2>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<2>, char) {
   const auto& [a, b] = t;
   return std::tie(a, b);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<3>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<3>, char) {
   const auto& [a, b, c] = t;
   return std::tie(a, b, c);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<4>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<4>, char) {
   const auto& [a, b, c, d] = t;
   return std::tie(a, b, c, d);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<5>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<5>, char) {
   const auto& [a, b, c, d, e] = t;
   return std::tie(a, b, c, d, e);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<6>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<6>, char) {
   const auto& [a, b, c, d, e, f] = t;
   return std::tie(a, b, c, d, e, f);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<7>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<7>, char) {
   const auto& [a, b, c, d, e, f, g] = t;
   return std::tie(a, b, c, d, e, f, g);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<8>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<8>, char) {
   const auto& [a, b, c, d, e, f, g, h] = t;
   return std::tie(a, b, c, d, e, f, g, h);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<9>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<9>, char) {
   const auto& [a, b, c, d, e, f, g, h, i] = t;
   return std::tie(a, b, c, d, e, f, g, h, i);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<10>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<10>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<11>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<11>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<12>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<12>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<13>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<13>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<14>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<14>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<15>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<15>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<16>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<16>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<17>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<17>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<18>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<18>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r);
 }
 template <typename T>
-auto UnpackStructImpl(const T& t, MakeIndexSequence<19>, char) {
+auto UnpackStructImpl(const T& t, std::make_index_sequence<19>, char) {
   const auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s] = t;
   return std::tie(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s);
 }
@@ -3260,8 +3275,8 @@ auto UnpackStructImpl(const T& t, MakeIndexSequence<19>, char) {
 
 template <size_t I, typename T>
 auto UnpackStruct(const T& t)
-    -> decltype((UnpackStructImpl)(t, MakeIndexSequence<I>{}, 0)) {
-  return (UnpackStructImpl)(t, MakeIndexSequence<I>{}, 0);
+    -> decltype((UnpackStructImpl)(t, std::make_index_sequence<I>{}, 0)) {
+  return (UnpackStructImpl)(t, std::make_index_sequence<I>{}, 0);
 }
 
 // Helper function to do comma folding in C++11.
@@ -3274,7 +3289,7 @@ template <typename Struct, typename StructSize>
 class FieldsAreMatcherImpl;
 
 template <typename Struct, size_t... I>
-class FieldsAreMatcherImpl<Struct, IndexSequence<I...>>
+class FieldsAreMatcherImpl<Struct, std::index_sequence<I...>>
     : public MatcherInterface<Struct> {
   using UnpackedType =
       decltype(UnpackStruct<sizeof...(I)>(std::declval<const Struct&>()));
@@ -3356,8 +3371,8 @@ class FieldsAreMatcher {
   template <typename Struct>
   operator Matcher<Struct>() const {  // NOLINT
     return Matcher<Struct>(
-        new FieldsAreMatcherImpl<const Struct&, IndexSequenceFor<Inner...>>(
-            matchers_));
+        new FieldsAreMatcherImpl<const Struct&,
+                                 std::index_sequence_for<Inner...>>(matchers_));
   }
 
  private:
@@ -5446,47 +5461,47 @@ PolymorphicMatcher<internal::ExceptionMatcherImpl<Err>> ThrowsMessage(
       ::testing::internal::MakePredicateFormatterFromMatcher(matcher), value)
 
 // MATCHER* macros itself are listed below.
-#define MATCHER(name, description)                                             \
-  class name##Matcher                                                          \
-      : public ::testing::internal::MatcherBaseImpl<name##Matcher> {           \
-   public:                                                                     \
-    template <typename arg_type>                                               \
-    class gmock_Impl : public ::testing::MatcherInterface<const arg_type&> {   \
-     public:                                                                   \
-      gmock_Impl() {}                                                          \
-      bool MatchAndExplain(                                                    \
-          const arg_type& arg,                                                 \
-          ::testing::MatchResultListener* result_listener) const override;     \
-      void DescribeTo(::std::ostream* gmock_os) const override {               \
-        *gmock_os << FormatDescription(false);                                 \
-      }                                                                        \
-      void DescribeNegationTo(::std::ostream* gmock_os) const override {       \
-        *gmock_os << FormatDescription(true);                                  \
-      }                                                                        \
-                                                                               \
-     private:                                                                  \
-      ::std::string FormatDescription(bool negation) const {                   \
-        /* NOLINTNEXTLINE readability-redundant-string-init */                 \
-        ::std::string gmock_description = (description);                       \
-        if (!gmock_description.empty()) {                                      \
-          return gmock_description;                                            \
-        }                                                                      \
-        return ::testing::internal::FormatMatcherDescription(negation, #name,  \
-                                                             {}, {});          \
-      }                                                                        \
-    };                                                                         \
-  };                                                                           \
-  inline name##Matcher GMOCK_INTERNAL_WARNING_PUSH()                           \
-      GMOCK_INTERNAL_WARNING_CLANG(ignored, "-Wunused-function")               \
-          GMOCK_INTERNAL_WARNING_CLANG(ignored, "-Wunused-member-function")    \
-              name GMOCK_INTERNAL_WARNING_POP()() {                            \
-    return {};                                                                 \
-  }                                                                            \
-  template <typename arg_type>                                                 \
-  bool name##Matcher::gmock_Impl<arg_type>::MatchAndExplain(                   \
-      const arg_type& arg,                                                     \
-      ::testing::MatchResultListener* result_listener GTEST_ATTRIBUTE_UNUSED_) \
-      const
+#define MATCHER(name, description)                                            \
+  class name##Matcher                                                         \
+      : public ::testing::internal::MatcherBaseImpl<name##Matcher> {          \
+   public:                                                                    \
+    template <typename arg_type>                                              \
+    class gmock_Impl : public ::testing::MatcherInterface<const arg_type&> {  \
+     public:                                                                  \
+      gmock_Impl() {}                                                         \
+      bool MatchAndExplain(                                                   \
+          const arg_type& arg,                                                \
+          ::testing::MatchResultListener* result_listener) const override;    \
+      void DescribeTo(::std::ostream* gmock_os) const override {              \
+        *gmock_os << FormatDescription(false);                                \
+      }                                                                       \
+      void DescribeNegationTo(::std::ostream* gmock_os) const override {      \
+        *gmock_os << FormatDescription(true);                                 \
+      }                                                                       \
+                                                                              \
+     private:                                                                 \
+      ::std::string FormatDescription(bool negation) const {                  \
+        /* NOLINTNEXTLINE readability-redundant-string-init */                \
+        ::std::string gmock_description = (description);                      \
+        if (!gmock_description.empty()) {                                     \
+          return gmock_description;                                           \
+        }                                                                     \
+        return ::testing::internal::FormatMatcherDescription(negation, #name, \
+                                                             {}, {});         \
+      }                                                                       \
+    };                                                                        \
+  };                                                                          \
+  inline name##Matcher GMOCK_INTERNAL_WARNING_PUSH()                          \
+      GMOCK_INTERNAL_WARNING_CLANG(ignored, "-Wunused-function")              \
+          GMOCK_INTERNAL_WARNING_CLANG(ignored, "-Wunused-member-function")   \
+              name GMOCK_INTERNAL_WARNING_POP()() {                           \
+    return {};                                                                \
+  }                                                                           \
+  template <typename arg_type>                                                \
+  bool name##Matcher::gmock_Impl<arg_type>::MatchAndExplain(                  \
+      const arg_type& arg,                                                    \
+      GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED ::testing::MatchResultListener*   \
+          result_listener) const
 
 #define MATCHER_P(name, p0, description) \
   GMOCK_INTERNAL_MATCHER(name, name##MatcherP, description, (#p0), (p0))
@@ -5568,11 +5583,11 @@ PolymorphicMatcher<internal::ExceptionMatcherImpl<Err>> ThrowsMessage(
   }                                                                            \
   template <GMOCK_INTERNAL_MATCHER_TEMPLATE_PARAMS(args)>                      \
   template <typename arg_type>                                                 \
-  bool full_name<GMOCK_INTERNAL_MATCHER_TYPE_PARAMS(args)>::gmock_Impl<        \
-      arg_type>::MatchAndExplain(const arg_type& arg,                          \
-                                 ::testing::MatchResultListener*               \
-                                     result_listener GTEST_ATTRIBUTE_UNUSED_)  \
-      const
+  bool full_name<GMOCK_INTERNAL_MATCHER_TYPE_PARAMS(args)>::                   \
+      gmock_Impl<arg_type>::MatchAndExplain(                                   \
+          const arg_type& arg,                                                 \
+          GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED ::testing::                    \
+              MatchResultListener* result_listener) const
 
 #define GMOCK_INTERNAL_MATCHER_TEMPLATE_PARAMS(args) \
   GMOCK_PP_TAIL(                                     \
@@ -5607,8 +5622,8 @@ PolymorphicMatcher<internal::ExceptionMatcherImpl<Err>> ThrowsMessage(
 
 #define GMOCK_INTERNAL_MATCHER_ARGS_USAGE(args) \
   GMOCK_PP_TAIL(GMOCK_PP_FOR_EACH(GMOCK_INTERNAL_MATCHER_ARG_USAGE, , args))
-#define GMOCK_INTERNAL_MATCHER_ARG_USAGE(i, data_unused, arg_unused) \
-  , gmock_p##i
+#define GMOCK_INTERNAL_MATCHER_ARG_USAGE(i, data_unused, arg) \
+  , ::std::forward<arg##_type>(gmock_p##i)
 
 // To prevent ADL on certain functions we put them on a separate namespace.
 using namespace no_adl;  // NOLINT
diff --git a/googlemock/include/gmock/gmock-more-actions.h b/googlemock/include/gmock/gmock-more-actions.h
index dd90e31f..55294dbd 100644
--- a/googlemock/include/gmock/gmock-more-actions.h
+++ b/googlemock/include/gmock/gmock-more-actions.h
@@ -592,17 +592,19 @@ namespace internal {
 // Overloads for other custom-callables are provided in the
 // internal/custom/gmock-generated-actions.h header.
 template <typename F, typename... Args>
-auto InvokeArgument(F f, Args... args) -> decltype(f(args...)) {
-  return f(args...);
+auto InvokeArgument(F &&f,
+                    Args... args) -> decltype(std::forward<F>(f)(args...)) {
+  return std::forward<F>(f)(args...);
 }
 
 template <std::size_t index, typename... Params>
 struct InvokeArgumentAction {
   template <typename... Args,
             typename = typename std::enable_if<(index < sizeof...(Args))>::type>
-  auto operator()(Args &&...args) const -> decltype(internal::InvokeArgument(
-      std::get<index>(std::forward_as_tuple(std::forward<Args>(args)...)),
-      std::declval<const Params &>()...)) {
+  auto operator()(Args &&...args) const
+      -> decltype(internal::InvokeArgument(
+          std::get<index>(std::forward_as_tuple(std::forward<Args>(args)...)),
+          std::declval<const Params &>()...)) {
     internal::FlatTuple<Args &&...> args_tuple(FlatTupleConstructTag{},
                                                std::forward<Args>(args)...);
     return params.Apply([&](const Params &...unpacked_params) {
diff --git a/googlemock/include/gmock/gmock-spec-builders.h b/googlemock/include/gmock/gmock-spec-builders.h
index 78ca15d0..c4c42b7c 100644
--- a/googlemock/include/gmock/gmock-spec-builders.h
+++ b/googlemock/include/gmock/gmock-spec-builders.h
@@ -868,7 +868,7 @@ class GTEST_API_ ExpectationBase {
   Clause last_clause_;
   mutable bool action_count_checked_;  // Under mutex_.
   mutable Mutex mutex_;                // Protects action_count_checked_.
-};                                     // class ExpectationBase
+};  // class ExpectationBase
 
 template <typename F>
 class TypedExpectation;
@@ -1838,9 +1838,8 @@ R FunctionMocker<R(Args...)>::InvokeWith(ArgumentTuple&& args)
     // Doing so slows down compilation dramatically because the *constructor* of
     // std::function<T> is re-instantiated with different template
     // parameters each time.
-    const UninterestingCallCleanupHandler report_uninteresting_call = {
-        reaction, ss
-    };
+    const UninterestingCallCleanupHandler report_uninteresting_call = {reaction,
+                                                                       ss};
 
     return PerformActionAndPrintResult(nullptr, std::move(args), ss.str(), ss);
   }
@@ -1890,8 +1889,7 @@ R FunctionMocker<R(Args...)>::InvokeWith(ArgumentTuple&& args)
   // std::function<T> is re-instantiated with different template
   // parameters each time.
   const FailureCleanupHandler handle_failures = {
-      ss, why, loc, untyped_expectation, found, is_excessive
-  };
+      ss, why, loc, untyped_expectation, found, is_excessive};
 
   return PerformActionAndPrintResult(untyped_action, std::move(args), ss.str(),
                                      ss);
diff --git a/googlemock/include/gmock/internal/gmock-internal-utils.h b/googlemock/include/gmock/internal/gmock-internal-utils.h
index ead6d7c8..b7685f57 100644
--- a/googlemock/include/gmock/internal/gmock-internal-utils.h
+++ b/googlemock/include/gmock/internal/gmock-internal-utils.h
@@ -44,6 +44,7 @@
 #include <ostream>  // NOLINT
 #include <string>
 #include <type_traits>
+#include <utility>
 #include <vector>
 
 #include "gmock/internal/gmock-port.h"
@@ -420,7 +421,7 @@ struct RemoveConstFromKey<std::pair<const K, V> > {
 GTEST_API_ void IllegalDoDefault(const char* file, int line);
 
 template <typename F, typename Tuple, size_t... Idx>
-auto ApplyImpl(F&& f, Tuple&& args, IndexSequence<Idx...>)
+auto ApplyImpl(F&& f, Tuple&& args, std::index_sequence<Idx...>)
     -> decltype(std::forward<F>(f)(
         std::get<Idx>(std::forward<Tuple>(args))...)) {
   return std::forward<F>(f)(std::get<Idx>(std::forward<Tuple>(args))...);
@@ -428,12 +429,13 @@ auto ApplyImpl(F&& f, Tuple&& args, IndexSequence<Idx...>)
 
 // Apply the function to a tuple of arguments.
 template <typename F, typename Tuple>
-auto Apply(F&& f, Tuple&& args) -> decltype(ApplyImpl(
-    std::forward<F>(f), std::forward<Tuple>(args),
-    MakeIndexSequence<std::tuple_size<
-        typename std::remove_reference<Tuple>::type>::value>())) {
+auto Apply(F&& f, Tuple&& args)
+    -> decltype(ApplyImpl(
+        std::forward<F>(f), std::forward<Tuple>(args),
+        std::make_index_sequence<std::tuple_size<
+            typename std::remove_reference<Tuple>::type>::value>())) {
   return ApplyImpl(std::forward<F>(f), std::forward<Tuple>(args),
-                   MakeIndexSequence<std::tuple_size<
+                   std::make_index_sequence<std::tuple_size<
                        typename std::remove_reference<Tuple>::type>::value>());
 }
 
diff --git a/googlemock/include/gmock/internal/gmock-port.h b/googlemock/include/gmock/internal/gmock-port.h
index 55ddfb6c..42d36d2f 100644
--- a/googlemock/include/gmock/internal/gmock-port.h
+++ b/googlemock/include/gmock/internal/gmock-port.h
@@ -42,6 +42,7 @@
 
 #include <assert.h>
 #include <stdlib.h>
+
 #include <cstdint>
 #include <iostream>
 
@@ -56,7 +57,7 @@
 #include "gmock/internal/custom/gmock-port.h"
 #include "gtest/internal/gtest-port.h"
 
-#ifdef GTEST_HAS_ABSL
+#if defined(GTEST_HAS_ABSL) && !defined(GTEST_NO_ABSL_FLAGS)
 #include "absl/flags/declare.h"
 #include "absl/flags/flag.h"
 #endif
@@ -73,7 +74,7 @@
 #define GMOCK_FLAG(name) FLAGS_gmock_##name
 
 // Pick a command line flags implementation.
-#ifdef GTEST_HAS_ABSL
+#if defined(GTEST_HAS_ABSL) && !defined(GTEST_NO_ABSL_FLAGS)
 
 // Macros for defining flags.
 #define GMOCK_DEFINE_bool_(name, default_val, doc) \
@@ -95,7 +96,7 @@
 #define GMOCK_FLAG_SET(name, value) \
   (void)(::absl::SetFlag(&GMOCK_FLAG(name), value))
 
-#else  // GTEST_HAS_ABSL
+#else  // defined(GTEST_HAS_ABSL) && !defined(GTEST_NO_ABSL_FLAGS)
 
 // Macros for defining flags.
 #define GMOCK_DEFINE_bool_(name, default_val, doc)  \
@@ -134,6 +135,6 @@
 #define GMOCK_FLAG_GET(name) ::testing::GMOCK_FLAG(name)
 #define GMOCK_FLAG_SET(name, value) (void)(::testing::GMOCK_FLAG(name) = value)
 
-#endif  // GTEST_HAS_ABSL
+#endif  // defined(GTEST_HAS_ABSL) && !defined(GTEST_NO_ABSL_FLAGS)
 
 #endif  // GOOGLEMOCK_INCLUDE_GMOCK_INTERNAL_GMOCK_PORT_H_
diff --git a/googlemock/src/gmock-cardinalities.cc b/googlemock/src/gmock-cardinalities.cc
index 92cde348..a7283aaf 100644
--- a/googlemock/src/gmock-cardinalities.cc
+++ b/googlemock/src/gmock-cardinalities.cc
@@ -53,12 +53,12 @@ class BetweenCardinalityImpl : public CardinalityInterface {
       : min_(min >= 0 ? min : 0), max_(max >= min_ ? max : min_) {
     std::stringstream ss;
     if (min < 0) {
-      ss << "The invocation lower bound must be >= 0, "
-         << "but is actually " << min << ".";
+      ss << "The invocation lower bound must be >= 0, " << "but is actually "
+         << min << ".";
       internal::Expect(false, __FILE__, __LINE__, ss.str());
     } else if (max < 0) {
-      ss << "The invocation upper bound must be >= 0, "
-         << "but is actually " << max << ".";
+      ss << "The invocation upper bound must be >= 0, " << "but is actually "
+         << max << ".";
       internal::Expect(false, __FILE__, __LINE__, ss.str());
     } else if (min > max) {
       ss << "The invocation upper bound (" << max
diff --git a/googlemock/src/gmock-internal-utils.cc b/googlemock/src/gmock-internal-utils.cc
index 5c2ce0d5..96c7e306 100644
--- a/googlemock/src/gmock-internal-utils.cc
+++ b/googlemock/src/gmock-internal-utils.cc
@@ -44,6 +44,7 @@
 #include <iostream>
 #include <ostream>  // NOLINT
 #include <string>
+#include <utility>
 #include <vector>
 
 #include "gmock/gmock.h"
@@ -211,14 +212,14 @@ constexpr char UnBase64Impl(char c, const char* const base64, char carry) {
 }
 
 template <size_t... I>
-constexpr std::array<char, 256> UnBase64Impl(IndexSequence<I...>,
+constexpr std::array<char, 256> UnBase64Impl(std::index_sequence<I...>,
                                              const char* const base64) {
   return {
       {UnBase64Impl(UndoWebSafeEncoding(static_cast<char>(I)), base64, 0)...}};
 }
 
 constexpr std::array<char, 256> UnBase64(const char* const base64) {
-  return UnBase64Impl(MakeIndexSequence<256>{}, base64);
+  return UnBase64Impl(std::make_index_sequence<256>{}, base64);
 }
 
 static constexpr char kBase64[] =
diff --git a/googlemock/src/gmock-matchers.cc b/googlemock/src/gmock-matchers.cc
index 81a5b7ea..277add6b 100644
--- a/googlemock/src/gmock-matchers.cc
+++ b/googlemock/src/gmock-matchers.cc
@@ -236,9 +236,8 @@ static void LogElementMatcherPairVec(const ElementMatcherPairs& pairs,
   os << "{";
   const char* sep = "";
   for (Iter it = pairs.begin(); it != pairs.end(); ++it) {
-    os << sep << "\n  ("
-       << "element #" << it->first << ", "
-       << "matcher #" << it->second << ")";
+    os << sep << "\n  (" << "element #" << it->first << ", " << "matcher #"
+       << it->second << ")";
     sep = ",";
   }
   os << "\n}";
@@ -374,20 +373,20 @@ bool UnorderedElementsAreMatcherImplBase::VerifyMatchMatrix(
     return true;
   }
 
-  if (match_flags() == UnorderedMatcherRequire::ExactMatch) {
-    if (matrix.LhsSize() != matrix.RhsSize()) {
-      // The element count doesn't match.  If the container is empty,
-      // there's no need to explain anything as Google Mock already
-      // prints the empty container. Otherwise we just need to show
-      // how many elements there actually are.
-      if (matrix.LhsSize() != 0 && listener->IsInterested()) {
-        *listener << "which has " << Elements(matrix.LhsSize());
-      }
-      return false;
+  const bool is_exact_match_with_size_discrepency =
+      match_flags() == UnorderedMatcherRequire::ExactMatch &&
+      matrix.LhsSize() != matrix.RhsSize();
+  if (is_exact_match_with_size_discrepency) {
+    // The element count doesn't match.  If the container is empty,
+    // there's no need to explain anything as Google Mock already
+    // prints the empty container. Otherwise we just need to show
+    // how many elements there actually are.
+    if (matrix.LhsSize() != 0 && listener->IsInterested()) {
+      *listener << "which has " << Elements(matrix.LhsSize()) << "\n";
     }
   }
 
-  bool result = true;
+  bool result = !is_exact_match_with_size_discrepency;
   ::std::vector<char> element_matched(matrix.LhsSize(), 0);
   ::std::vector<char> matcher_matched(matrix.RhsSize(), 0);
 
diff --git a/googlemock/src/gmock-spec-builders.cc b/googlemock/src/gmock-spec-builders.cc
index fb67ab09..ffdf03dd 100644
--- a/googlemock/src/gmock-spec-builders.cc
+++ b/googlemock/src/gmock-spec-builders.cc
@@ -531,7 +531,7 @@ class MockObjectRegistry {
 #ifdef GTEST_OS_QURT
       qurt_exception_raise_fatal();
 #else
-      _exit(1);  // We cannot call exit() as it is not reentrant and
+      _Exit(1);  // We cannot call exit() as it is not reentrant and
                  // may already have been called.
 #endif
     }
diff --git a/googlemock/test/Android.bp b/googlemock/test/Android.bp
index 19463a36..bb1b89f6 100644
--- a/googlemock/test/Android.bp
+++ b/googlemock/test/Android.bp
@@ -45,39 +45,22 @@ cc_defaults {
 }
 
 cc_test {
-    name: "gmock_tests",
+    name: "gmock_all_test",
     defaults: ["gmock_test_defaults"],
-    test_per_src: true,
-    srcs: [
-        "gmock-actions_test.cc",
-        "gmock-cardinalities_test.cc",
-
-        // Test is disabled because Android doesn't build gmock with exceptions.
-        //"gmock_ex_test.cc",
-
-        "gmock-function-mocker_test.cc",
-        "gmock-internal-utils_test.cc",
-        "gmock-matchers-arithmetic_test.cc",
-        "gmock-matchers-comparisons_test.cc",
-        "gmock-matchers-containers_test.cc",
-        "gmock-matchers-misc_test.cc",
-        "gmock-more-actions_test.cc",
-        "gmock-nice-strict_test.cc",
-        "gmock-port_test.cc",
-        "gmock-pp_test.cc",
-        "gmock-pp-string_test.cc",
-        "gmock-spec-builders_test.cc",
-        "gmock_test.cc",
-    ],
+    srcs: ["gmock-*.cc"],
 }
 
 cc_test {
     name: "gmock_link_test",
     defaults: ["gmock_test_defaults"],
-    relative_install_path: "gmock_tests",
-    no_named_install_directory: true,
     srcs: [
         "gmock_link_test.cc",
         "gmock_link2_test.cc",
     ],
 }
+
+cc_test {
+    name: "gmock_test",
+    defaults: ["gmock_test_defaults"],
+    srcs: ["gmock_test.cc"],
+}
diff --git a/googlemock/test/gmock-actions_test.cc b/googlemock/test/gmock-actions_test.cc
index da1675c5..82c22c31 100644
--- a/googlemock/test/gmock-actions_test.cc
+++ b/googlemock/test/gmock-actions_test.cc
@@ -441,8 +441,8 @@ TEST(DefaultValueDeathTest, GetReturnsBuiltInDefaultValueWhenUnset) {
 
   EXPECT_EQ(0, DefaultValue<int>::Get());
 
-  EXPECT_DEATH_IF_SUPPORTED({ DefaultValue<MyNonDefaultConstructible>::Get(); },
-                            "");
+  EXPECT_DEATH_IF_SUPPORTED(
+      { DefaultValue<MyNonDefaultConstructible>::Get(); }, "");
 }
 
 TEST(DefaultValueTest, GetWorksForMoveOnlyIfSet) {
@@ -505,8 +505,8 @@ TEST(DefaultValueOfReferenceDeathTest, GetReturnsBuiltInDefaultValueWhenUnset) {
   EXPECT_FALSE(DefaultValue<MyNonDefaultConstructible&>::IsSet());
 
   EXPECT_DEATH_IF_SUPPORTED({ DefaultValue<int&>::Get(); }, "");
-  EXPECT_DEATH_IF_SUPPORTED({ DefaultValue<MyNonDefaultConstructible>::Get(); },
-                            "");
+  EXPECT_DEATH_IF_SUPPORTED(
+      { DefaultValue<MyNonDefaultConstructible>::Get(); }, "");
 }
 
 // Tests that ActionInterface can be implemented by defining the
@@ -1477,6 +1477,54 @@ TEST(DoAll, SupportsTypeErasedActions) {
   }
 }
 
+// A DoAll action should be convertible to a OnceAction, even when its component
+// sub-actions are user-provided types that define only an Action conversion
+// operator. If they supposed being called more than once then they also support
+// being called at most once.
+TEST(DoAll, ConvertibleToOnceActionWithUserProvidedActionConversion) {
+  // Simplest case: only one sub-action.
+  struct CustomFinal final {
+    operator Action<int()>() {  // NOLINT
+      return Return(17);
+    }
+
+    operator Action<int(int, char)>() {  // NOLINT
+      return Return(19);
+    }
+  };
+
+  {
+    OnceAction<int()> action = DoAll(CustomFinal{});
+    EXPECT_EQ(17, std::move(action).Call());
+  }
+
+  {
+    OnceAction<int(int, char)> action = DoAll(CustomFinal{});
+    EXPECT_EQ(19, std::move(action).Call(0, 0));
+  }
+
+  // It should also work with multiple sub-actions.
+  struct CustomInitial final {
+    operator Action<void()>() {  // NOLINT
+      return [] {};
+    }
+
+    operator Action<void(int, char)>() {  // NOLINT
+      return [] {};
+    }
+  };
+
+  {
+    OnceAction<int()> action = DoAll(CustomInitial{}, CustomFinal{});
+    EXPECT_EQ(17, std::move(action).Call());
+  }
+
+  {
+    OnceAction<int(int, char)> action = DoAll(CustomInitial{}, CustomFinal{});
+    EXPECT_EQ(19, std::move(action).Call(0, 0));
+  }
+}
+
 // Tests using WithArgs and with an action that takes 1 argument.
 TEST(WithArgsTest, OneArg) {
   Action<bool(double x, int n)> a = WithArgs<1>(Invoke(Unary));  // NOLINT
diff --git a/googlemock/test/gmock-matchers-arithmetic_test.cc b/googlemock/test/gmock-matchers-arithmetic_test.cc
index f1769628..6968f55b 100644
--- a/googlemock/test/gmock-matchers-arithmetic_test.cc
+++ b/googlemock/test/gmock-matchers-arithmetic_test.cc
@@ -36,7 +36,9 @@
 #include <memory>
 #include <string>
 
+#include "gmock/gmock.h"
 #include "test/gmock-matchers_test.h"
+#include "gtest/gtest.h"
 
 // Silence warning C4244: 'initializing': conversion from 'int' to 'short',
 // possible loss of data and C4100, unreferenced local parameter
@@ -559,10 +561,9 @@ TEST_P(AllOfTestP, ExplainsResult) {
   Matcher<int> m;
 
   // Successful match.  Both matchers need to explain.  The second
-  // matcher doesn't give an explanation, so only the first matcher's
-  // explanation is printed.
+  // matcher doesn't give an explanation, so the matcher description is used.
   m = AllOf(GreaterThan(10), Lt(30));
-  EXPECT_EQ("which is 15 more than 10", Explain(m, 25));
+  EXPECT_EQ("which is 15 more than 10, and is < 30", Explain(m, 25));
 
   // Successful match.  Both matchers need to explain.
   m = AllOf(GreaterThan(10), GreaterThan(20));
@@ -572,8 +573,9 @@ TEST_P(AllOfTestP, ExplainsResult) {
   // Successful match.  All matchers need to explain.  The second
   // matcher doesn't given an explanation.
   m = AllOf(GreaterThan(10), Lt(30), GreaterThan(20));
-  EXPECT_EQ("which is 15 more than 10, and which is 5 more than 20",
-            Explain(m, 25));
+  EXPECT_EQ(
+      "which is 15 more than 10, and is < 30, and which is 5 more than 20",
+      Explain(m, 25));
 
   // Successful match.  All matchers need to explain.
   m = AllOf(GreaterThan(10), GreaterThan(20), GreaterThan(30));
@@ -588,10 +590,10 @@ TEST_P(AllOfTestP, ExplainsResult) {
   EXPECT_EQ("which is 5 less than 10", Explain(m, 5));
 
   // Failed match.  The second matcher, which failed, needs to
-  // explain.  Since it doesn't given an explanation, nothing is
+  // explain.  Since it doesn't given an explanation, the matcher text is
   // printed.
   m = AllOf(GreaterThan(10), Lt(30));
-  EXPECT_EQ("", Explain(m, 40));
+  EXPECT_EQ("which doesn't match (is < 30)", Explain(m, 40));
 
   // Failed match.  The second matcher, which failed, needs to
   // explain.
diff --git a/googlemock/test/gmock-matchers-comparisons_test.cc b/googlemock/test/gmock-matchers-comparisons_test.cc
index 5b75b457..a324c4c7 100644
--- a/googlemock/test/gmock-matchers-comparisons_test.cc
+++ b/googlemock/test/gmock-matchers-comparisons_test.cc
@@ -37,13 +37,14 @@
 #include <tuple>
 #include <vector>
 
+#include "gmock/gmock.h"
 #include "test/gmock-matchers_test.h"
+#include "gtest/gtest.h"
 
 // Silence warning C4244: 'initializing': conversion from 'int' to 'short',
 // possible loss of data and C4100, unreferenced local parameter
 GTEST_DISABLE_MSC_WARNINGS_PUSH_(4244 4100)
 
-
 namespace testing {
 namespace gmock_matchers_test {
 namespace {
@@ -2334,9 +2335,11 @@ TEST(ExplainMatchResultTest, AllOf_True_True) {
   EXPECT_EQ("which is 0 modulo 2, and which is 0 modulo 3", Explain(m, 6));
 }
 
+// Tests that when AllOf() succeeds, but matchers have no explanation,
+// the matcher description is used.
 TEST(ExplainMatchResultTest, AllOf_True_True_2) {
   const Matcher<int> m = AllOf(Ge(2), Le(3));
-  EXPECT_EQ("", Explain(m, 2));
+  EXPECT_EQ("is >= 2, and is <= 3", Explain(m, 2));
 }
 
 INSTANTIATE_GTEST_MATCHER_TEST_P(ExplainmatcherResultTest);
diff --git a/googlemock/test/gmock-matchers-containers_test.cc b/googlemock/test/gmock-matchers-containers_test.cc
index 38fd9a5d..52b52d5d 100644
--- a/googlemock/test/gmock-matchers-containers_test.cc
+++ b/googlemock/test/gmock-matchers-containers_test.cc
@@ -43,14 +43,14 @@
 #include <tuple>
 #include <vector>
 
+#include "gmock/gmock.h"
+#include "test/gmock-matchers_test.h"
 #include "gtest/gtest.h"
 
 // Silence warning C4244: 'initializing': conversion from 'int' to 'short',
 // possible loss of data and C4100, unreferenced local parameter
 GTEST_DISABLE_MSC_WARNINGS_PUSH_(4244 4100)
 
-#include "test/gmock-matchers_test.h"
-
 namespace testing {
 namespace gmock_matchers_test {
 namespace {
@@ -2014,7 +2014,14 @@ TEST_F(UnorderedElementsAreTest, FailMessageCountWrong) {
   StringMatchResultListener listener;
   EXPECT_FALSE(ExplainMatchResult(UnorderedElementsAre(1, 2, 3), v, &listener))
       << listener.str();
-  EXPECT_THAT(listener.str(), Eq("which has 1 element"));
+  EXPECT_THAT(listener.str(),
+              Eq("which has 1 element\n"
+                 "where the following matchers don't match any elements:\n"
+                 "matcher #0: is equal to 1,\n"
+                 "matcher #1: is equal to 2,\n"
+                 "matcher #2: is equal to 3\n"
+                 "and where the following elements don't match any matchers:\n"
+                 "element #0: 4"));
 }
 
 TEST_F(UnorderedElementsAreTest, FailMessageCountWrongZero) {
@@ -2022,7 +2029,11 @@ TEST_F(UnorderedElementsAreTest, FailMessageCountWrongZero) {
   StringMatchResultListener listener;
   EXPECT_FALSE(ExplainMatchResult(UnorderedElementsAre(1, 2, 3), v, &listener))
       << listener.str();
-  EXPECT_THAT(listener.str(), Eq(""));
+  EXPECT_THAT(listener.str(),
+              Eq("where the following matchers don't match any elements:\n"
+                 "matcher #0: is equal to 1,\n"
+                 "matcher #1: is equal to 2,\n"
+                 "matcher #2: is equal to 3"));
 }
 
 TEST_F(UnorderedElementsAreTest, FailMessageUnmatchedMatchers) {
@@ -2438,7 +2449,7 @@ TEST(UnorderedPointwiseTest, RejectsWrongSize) {
   const double lhs[2] = {1, 2};
   const int rhs[1] = {0};
   EXPECT_THAT(lhs, Not(UnorderedPointwise(Gt(), rhs)));
-  EXPECT_EQ("which has 2 elements",
+  EXPECT_EQ("which has 2 elements\n",
             Explain(UnorderedPointwise(Gt(), rhs), lhs));
 
   const int rhs2[3] = {0, 1, 2};
diff --git a/googlemock/test/gmock-matchers-misc_test.cc b/googlemock/test/gmock-matchers-misc_test.cc
index b8f64587..2bb4cdbe 100644
--- a/googlemock/test/gmock-matchers-misc_test.cc
+++ b/googlemock/test/gmock-matchers-misc_test.cc
@@ -39,14 +39,14 @@
 #include <utility>
 #include <vector>
 
+#include "gmock/gmock.h"
+#include "test/gmock-matchers_test.h"
 #include "gtest/gtest.h"
 
 // Silence warning C4244: 'initializing': conversion from 'int' to 'short',
 // possible loss of data and C4100, unreferenced local parameter
 GTEST_DISABLE_MSC_WARNINGS_PUSH_(4244 4100)
 
-#include "test/gmock-matchers_test.h"
-
 namespace testing {
 namespace gmock_matchers_test {
 namespace {
diff --git a/googlemock/test/gmock-more-actions_test.cc b/googlemock/test/gmock-more-actions_test.cc
index 16af6892..354a79b1 100644
--- a/googlemock/test/gmock-more-actions_test.cc
+++ b/googlemock/test/gmock-more-actions_test.cc
@@ -91,6 +91,10 @@ struct UnaryMoveOnlyFunctor : UnaryFunctor {
   UnaryMoveOnlyFunctor(UnaryMoveOnlyFunctor&&) = default;
 };
 
+struct OneShotUnaryFunctor {
+  int operator()(bool x) && { return x ? 1 : -1; }
+};
+
 const char* Binary(const char* input, short n) { return input + n; }  // NOLINT
 
 int Ternary(int x, char y, short z) { return x + y + z; }  // NOLINT
@@ -716,6 +720,12 @@ TEST(InvokeArgumentTest, Functor1MoveOnly) {
   EXPECT_EQ(1, a.Perform(std::make_tuple(UnaryMoveOnlyFunctor())));
 }
 
+// Tests using InvokeArgument with a one-shot unary functor.
+TEST(InvokeArgumentTest, OneShotFunctor1) {
+  Action<int(OneShotUnaryFunctor)> a = InvokeArgument<0>(true);  // NOLINT
+  EXPECT_EQ(1, a.Perform(std::make_tuple(OneShotUnaryFunctor())));
+}
+
 // Tests using InvokeArgument with a 5-ary function.
 TEST(InvokeArgumentTest, Function5) {
   Action<int(int (*)(int, int, int, int, int))> a =  // NOLINT
@@ -818,6 +828,22 @@ TEST(InvokeArgumentTest, ByExplicitConstReferenceFunction) {
   EXPECT_FALSE(a.Perform(std::make_tuple(&ReferencesGlobalDouble)));
 }
 
+TEST(InvokeArgumentTest, MoveOnlyType) {
+  struct Marker {};
+  struct {
+    // Method takes a unique_ptr (to a type we don't care about), and an
+    // invocable type.
+    MOCK_METHOD(bool, MockMethod,
+                (std::unique_ptr<Marker>, std::function<int()>), ());
+  } mock;
+
+  ON_CALL(mock, MockMethod(_, _)).WillByDefault(InvokeArgument<1>());
+
+  // This compiles, but is a little opaque as a workaround:
+  ON_CALL(mock, MockMethod(_, _))
+      .WillByDefault(WithArg<1>(InvokeArgument<0>()));
+}
+
 // Tests DoAll(a1, a2).
 TEST(DoAllTest, TwoActions) {
   int n = 0;
diff --git a/googlemock/test/gmock_link_test.h b/googlemock/test/gmock_link_test.h
index cf0a985b..cb5179b2 100644
--- a/googlemock/test/gmock_link_test.h
+++ b/googlemock/test/gmock_link_test.h
@@ -186,8 +186,8 @@ using testing::SetErrnoAndReturn;
 #endif
 
 #if GTEST_HAS_EXCEPTIONS
-using testing::Throw;
 using testing::Rethrow;
+using testing::Throw;
 #endif
 
 using testing::ContainsRegex;
diff --git a/googletest/Android.bp b/googletest/Android.bp
index 4abe7ea5..23de168f 100644
--- a/googletest/Android.bp
+++ b/googletest/Android.bp
@@ -68,6 +68,7 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     native_bridge_supported: true,
+    cmake_snapshot_supported: true,
     srcs: ["src/gtest-all.cc"],
     rtti: true,
 }
@@ -79,6 +80,7 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     native_bridge_supported: true,
+    cmake_snapshot_supported: true,
     srcs: ["src/gtest_main.cc"],
 }
 
diff --git a/googletest/README.md b/googletest/README.md
index 44fd69b4..7c351747 100644
--- a/googletest/README.md
+++ b/googletest/README.md
@@ -25,7 +25,7 @@ When building GoogleTest as a standalone project, the typical workflow starts
 with
 
 ```
-git clone https://github.com/google/googletest.git -b v1.14.0
+git clone https://github.com/google/googletest.git -b v1.15.2
 cd googletest        # Main directory of the cloned repository.
 mkdir build          # Create a directory to hold the build output.
 cd build
diff --git a/googletest/include/gtest/gtest-assertion-result.h b/googletest/include/gtest/gtest-assertion-result.h
index 56fe128f..74eb2b1f 100644
--- a/googletest/include/gtest/gtest-assertion-result.h
+++ b/googletest/include/gtest/gtest-assertion-result.h
@@ -129,7 +129,7 @@ namespace testing {
 //
 //   Expected: Foo() is even
 //     Actual: it's 5
-//
+
 class GTEST_API_ AssertionResult {
  public:
   // Copy constructor.
diff --git a/googletest/include/gtest/gtest-death-test.h b/googletest/include/gtest/gtest-death-test.h
index 08fef8c7..3c619097 100644
--- a/googletest/include/gtest/gtest-death-test.h
+++ b/googletest/include/gtest/gtest-death-test.h
@@ -293,8 +293,8 @@ class GTEST_API_ KilledBySignal {
 //                statement is compiled but not executed, to ensure that
 //                EXPECT_DEATH_IF_SUPPORTED compiles with a certain
 //                parameter if and only if EXPECT_DEATH compiles with it.
-//   regex     -  A regex that a macro such as EXPECT_DEATH would use to test
-//                the output of statement.  This parameter has to be
+//   regex_or_matcher -  A regex that a macro such as EXPECT_DEATH would use
+//                to test the output of statement.  This parameter has to be
 //                compiled but not evaluated by this macro, to ensure that
 //                this macro only accepts expressions that a macro such as
 //                EXPECT_DEATH would accept.
@@ -311,13 +311,13 @@ class GTEST_API_ KilledBySignal {
 //  statement unconditionally returns or throws. The Message constructor at
 //  the end allows the syntax of streaming additional messages into the
 //  macro, for compilational compatibility with EXPECT_DEATH/ASSERT_DEATH.
-#define GTEST_UNSUPPORTED_DEATH_TEST(statement, regex, terminator)             \
+#define GTEST_UNSUPPORTED_DEATH_TEST(statement, regex_or_matcher, terminator)  \
   GTEST_AMBIGUOUS_ELSE_BLOCKER_                                                \
   if (::testing::internal::AlwaysTrue()) {                                     \
     GTEST_LOG_(WARNING) << "Death tests are not supported on this platform.\n" \
                         << "Statement '" #statement "' cannot be verified.";   \
   } else if (::testing::internal::AlwaysFalse()) {                             \
-    ::testing::internal::RE::PartialMatch(".*", (regex));                      \
+    ::testing::internal::MakeDeathTestMatcher(regex_or_matcher);               \
     GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_(statement);                 \
     terminator;                                                                \
   } else                                                                       \
diff --git a/googletest/include/gtest/gtest-param-test.h b/googletest/include/gtest/gtest-param-test.h
index 49a47ead..55ee088b 100644
--- a/googletest/include/gtest/gtest-param-test.h
+++ b/googletest/include/gtest/gtest-param-test.h
@@ -178,7 +178,7 @@ TEST_P(DerivedTest, DoesBlah) {
 #include <utility>
 
 #include "gtest/internal/gtest-internal.h"
-#include "gtest/internal/gtest-param-util.h"
+#include "gtest/internal/gtest-param-util.h"  // IWYU pragma: export
 #include "gtest/internal/gtest-port.h"
 
 namespace testing {
@@ -469,7 +469,7 @@ internal::ParamConverterGenerator<T> ConvertGenerator(
               ::testing::internal::CodeLocation(__FILE__, __LINE__));          \
       return 0;                                                                \
     }                                                                          \
-    static int gtest_registering_dummy_ GTEST_ATTRIBUTE_UNUSED_;               \
+    GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static int gtest_registering_dummy_; \
   };                                                                           \
   int GTEST_TEST_CLASS_NAME_(test_suite_name,                                  \
                              test_name)::gtest_registering_dummy_ =            \
@@ -514,8 +514,8 @@ internal::ParamConverterGenerator<T> ConvertGenerator(
         ::testing::internal::DefaultParamName<test_suite_name::ParamType>,   \
         DUMMY_PARAM_))))(info);                                              \
   }                                                                          \
-  static int gtest_##prefix##test_suite_name##_dummy_                        \
-      GTEST_ATTRIBUTE_UNUSED_ =                                              \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static int                           \
+      gtest_##prefix##test_suite_name##_dummy_ =                             \
           ::testing::UnitTest::GetInstance()                                 \
               ->parameterized_test_registry()                                \
               .GetTestSuitePatternHolder<test_suite_name>(                   \
diff --git a/googletest/include/gtest/gtest-typed-test.h b/googletest/include/gtest/gtest-typed-test.h
index 72de536b..305b0b50 100644
--- a/googletest/include/gtest/gtest-typed-test.h
+++ b/googletest/include/gtest/gtest-typed-test.h
@@ -194,33 +194,34 @@ INSTANTIATE_TYPED_TEST_SUITE_P(My, FooTest, MyTypes);
   typedef ::testing::internal::NameGeneratorSelector<__VA_ARGS__>::type \
   GTEST_NAME_GENERATOR_(CaseName)
 
-#define TYPED_TEST(CaseName, TestName)                                        \
-  static_assert(sizeof(GTEST_STRINGIFY_(TestName)) > 1,                       \
-                "test-name must not be empty");                               \
-  template <typename gtest_TypeParam_>                                        \
-  class GTEST_TEST_CLASS_NAME_(CaseName, TestName)                            \
-      : public CaseName<gtest_TypeParam_> {                                   \
-   private:                                                                   \
-    typedef CaseName<gtest_TypeParam_> TestFixture;                           \
-    typedef gtest_TypeParam_ TypeParam;                                       \
-    void TestBody() override;                                                 \
-  };                                                                          \
-  static bool gtest_##CaseName##_##TestName##_registered_                     \
-      GTEST_ATTRIBUTE_UNUSED_ = ::testing::internal::TypeParameterizedTest<   \
-          CaseName,                                                           \
-          ::testing::internal::TemplateSel<GTEST_TEST_CLASS_NAME_(CaseName,   \
-                                                                  TestName)>, \
-          GTEST_TYPE_PARAMS_(                                                 \
-              CaseName)>::Register("",                                        \
-                                   ::testing::internal::CodeLocation(         \
-                                       __FILE__, __LINE__),                   \
-                                   GTEST_STRINGIFY_(CaseName),                \
-                                   GTEST_STRINGIFY_(TestName), 0,             \
-                                   ::testing::internal::GenerateNames<        \
-                                       GTEST_NAME_GENERATOR_(CaseName),       \
-                                       GTEST_TYPE_PARAMS_(CaseName)>());      \
-  template <typename gtest_TypeParam_>                                        \
-  void GTEST_TEST_CLASS_NAME_(CaseName,                                       \
+#define TYPED_TEST(CaseName, TestName)                                       \
+  static_assert(sizeof(GTEST_STRINGIFY_(TestName)) > 1,                      \
+                "test-name must not be empty");                              \
+  template <typename gtest_TypeParam_>                                       \
+  class GTEST_TEST_CLASS_NAME_(CaseName, TestName)                           \
+      : public CaseName<gtest_TypeParam_> {                                  \
+   private:                                                                  \
+    typedef CaseName<gtest_TypeParam_> TestFixture;                          \
+    typedef gtest_TypeParam_ TypeParam;                                      \
+    void TestBody() override;                                                \
+  };                                                                         \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static bool                          \
+      gtest_##CaseName##_##TestName##_registered_ =                          \
+          ::testing::internal::TypeParameterizedTest<                        \
+              CaseName,                                                      \
+              ::testing::internal::TemplateSel<GTEST_TEST_CLASS_NAME_(       \
+                  CaseName, TestName)>,                                      \
+              GTEST_TYPE_PARAMS_(                                            \
+                  CaseName)>::Register("",                                   \
+                                       ::testing::internal::CodeLocation(    \
+                                           __FILE__, __LINE__),              \
+                                       GTEST_STRINGIFY_(CaseName),           \
+                                       GTEST_STRINGIFY_(TestName), 0,        \
+                                       ::testing::internal::GenerateNames<   \
+                                           GTEST_NAME_GENERATOR_(CaseName),  \
+                                           GTEST_TYPE_PARAMS_(CaseName)>()); \
+  template <typename gtest_TypeParam_>                                       \
+  void GTEST_TEST_CLASS_NAME_(CaseName,                                      \
                               TestName)<gtest_TypeParam_>::TestBody()
 
 // Legacy API is deprecated but still available
@@ -267,22 +268,23 @@ INSTANTIATE_TYPED_TEST_SUITE_P(My, FooTest, MyTypes);
   TYPED_TEST_SUITE_P
 #endif  // GTEST_REMOVE_LEGACY_TEST_CASEAPI_
 
-#define TYPED_TEST_P(SuiteName, TestName)                           \
-  namespace GTEST_SUITE_NAMESPACE_(SuiteName) {                     \
-  template <typename gtest_TypeParam_>                              \
-  class TestName : public SuiteName<gtest_TypeParam_> {             \
-   private:                                                         \
-    typedef SuiteName<gtest_TypeParam_> TestFixture;                \
-    typedef gtest_TypeParam_ TypeParam;                             \
-    void TestBody() override;                                       \
-  };                                                                \
-  static bool gtest_##TestName##_defined_ GTEST_ATTRIBUTE_UNUSED_ = \
-      GTEST_TYPED_TEST_SUITE_P_STATE_(SuiteName).AddTestName(       \
-          __FILE__, __LINE__, GTEST_STRINGIFY_(SuiteName),          \
-          GTEST_STRINGIFY_(TestName));                              \
-  }                                                                 \
-  template <typename gtest_TypeParam_>                              \
-  void GTEST_SUITE_NAMESPACE_(                                      \
+#define TYPED_TEST_P(SuiteName, TestName)                         \
+  namespace GTEST_SUITE_NAMESPACE_(SuiteName) {                   \
+  template <typename gtest_TypeParam_>                            \
+  class TestName : public SuiteName<gtest_TypeParam_> {           \
+   private:                                                       \
+    typedef SuiteName<gtest_TypeParam_> TestFixture;              \
+    typedef gtest_TypeParam_ TypeParam;                           \
+    void TestBody() override;                                     \
+  };                                                              \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static bool               \
+      gtest_##TestName##_defined_ =                               \
+          GTEST_TYPED_TEST_SUITE_P_STATE_(SuiteName).AddTestName( \
+              __FILE__, __LINE__, GTEST_STRINGIFY_(SuiteName),    \
+              GTEST_STRINGIFY_(TestName));                        \
+  }                                                               \
+  template <typename gtest_TypeParam_>                            \
+  void GTEST_SUITE_NAMESPACE_(                                    \
       SuiteName)::TestName<gtest_TypeParam_>::TestBody()
 
 // Note: this won't work correctly if the trailing arguments are macros.
@@ -290,8 +292,8 @@ INSTANTIATE_TYPED_TEST_SUITE_P(My, FooTest, MyTypes);
   namespace GTEST_SUITE_NAMESPACE_(SuiteName) {                             \
   typedef ::testing::internal::Templates<__VA_ARGS__> gtest_AllTests_;      \
   }                                                                         \
-  static const char* const GTEST_REGISTERED_TEST_NAMES_(                    \
-      SuiteName) GTEST_ATTRIBUTE_UNUSED_ =                                  \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static const char* const            \
+  GTEST_REGISTERED_TEST_NAMES_(SuiteName) =                                 \
       GTEST_TYPED_TEST_SUITE_P_STATE_(SuiteName).VerifyRegisteredTestNames( \
           GTEST_STRINGIFY_(SuiteName), __FILE__, __LINE__, #__VA_ARGS__)
 
@@ -303,22 +305,24 @@ INSTANTIATE_TYPED_TEST_SUITE_P(My, FooTest, MyTypes);
   REGISTER_TYPED_TEST_SUITE_P
 #endif  // GTEST_REMOVE_LEGACY_TEST_CASEAPI_
 
-#define INSTANTIATE_TYPED_TEST_SUITE_P(Prefix, SuiteName, Types, ...)     \
-  static_assert(sizeof(GTEST_STRINGIFY_(Prefix)) > 1,                     \
-                "test-suit-prefix must not be empty");                    \
-  static bool gtest_##Prefix##_##SuiteName GTEST_ATTRIBUTE_UNUSED_ =      \
-      ::testing::internal::TypeParameterizedTestSuite<                    \
-          SuiteName, GTEST_SUITE_NAMESPACE_(SuiteName)::gtest_AllTests_,  \
-          ::testing::internal::GenerateTypeList<Types>::type>::           \
-          Register(GTEST_STRINGIFY_(Prefix),                              \
-                   ::testing::internal::CodeLocation(__FILE__, __LINE__), \
-                   &GTEST_TYPED_TEST_SUITE_P_STATE_(SuiteName),           \
-                   GTEST_STRINGIFY_(SuiteName),                           \
-                   GTEST_REGISTERED_TEST_NAMES_(SuiteName),               \
-                   ::testing::internal::GenerateNames<                    \
-                       ::testing::internal::NameGeneratorSelector<        \
-                           __VA_ARGS__>::type,                            \
-                       ::testing::internal::GenerateTypeList<Types>::type>())
+#define INSTANTIATE_TYPED_TEST_SUITE_P(Prefix, SuiteName, Types, ...)        \
+  static_assert(sizeof(GTEST_STRINGIFY_(Prefix)) > 1,                        \
+                "test-suit-prefix must not be empty");                       \
+  GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static bool                          \
+      gtest_##Prefix##_##SuiteName =                                         \
+          ::testing::internal::TypeParameterizedTestSuite<                   \
+              SuiteName, GTEST_SUITE_NAMESPACE_(SuiteName)::gtest_AllTests_, \
+              ::testing::internal::GenerateTypeList<Types>::type>::          \
+              Register(                                                      \
+                  GTEST_STRINGIFY_(Prefix),                                  \
+                  ::testing::internal::CodeLocation(__FILE__, __LINE__),     \
+                  &GTEST_TYPED_TEST_SUITE_P_STATE_(SuiteName),               \
+                  GTEST_STRINGIFY_(SuiteName),                               \
+                  GTEST_REGISTERED_TEST_NAMES_(SuiteName),                   \
+                  ::testing::internal::GenerateNames<                        \
+                      ::testing::internal::NameGeneratorSelector<            \
+                          __VA_ARGS__>::type,                                \
+                      ::testing::internal::GenerateTypeList<Types>::type>())
 
 // Legacy API is deprecated but still available
 #ifndef GTEST_REMOVE_LEGACY_TEST_CASEAPI_
diff --git a/googletest/include/gtest/gtest.h b/googletest/include/gtest/gtest.h
index 45400fd0..c8996695 100644
--- a/googletest/include/gtest/gtest.h
+++ b/googletest/include/gtest/gtest.h
@@ -60,16 +60,16 @@
 #include <type_traits>
 #include <vector>
 
-#include "gtest/gtest-assertion-result.h"
-#include "gtest/gtest-death-test.h"
-#include "gtest/gtest-matchers.h"
-#include "gtest/gtest-message.h"
-#include "gtest/gtest-param-test.h"
-#include "gtest/gtest-printers.h"
-#include "gtest/gtest-test-part.h"
-#include "gtest/gtest-typed-test.h"
-#include "gtest/gtest_pred_impl.h"
-#include "gtest/gtest_prod.h"
+#include "gtest/gtest-assertion-result.h"  // IWYU pragma: export
+#include "gtest/gtest-death-test.h"  // IWYU pragma: export
+#include "gtest/gtest-matchers.h"  // IWYU pragma: export
+#include "gtest/gtest-message.h"  // IWYU pragma: export
+#include "gtest/gtest-param-test.h"  // IWYU pragma: export
+#include "gtest/gtest-printers.h"  // IWYU pragma: export
+#include "gtest/gtest-test-part.h"  // IWYU pragma: export
+#include "gtest/gtest-typed-test.h"  // IWYU pragma: export
+#include "gtest/gtest_pred_impl.h"  // IWYU pragma: export
+#include "gtest/gtest_prod.h"  // IWYU pragma: export
 #include "gtest/internal/gtest-internal.h"
 #include "gtest/internal/gtest-string.h"
 
@@ -607,7 +607,7 @@ class GTEST_API_ TestInfo {
   friend class internal::UnitTestImpl;
   friend class internal::StreamingListenerTest;
   friend TestInfo* internal::MakeAndRegisterTestInfo(
-      const char* test_suite_name, const char* name, const char* type_param,
+      std::string test_suite_name, const char* name, const char* type_param,
       const char* value_param, internal::CodeLocation code_location,
       internal::TypeId fixture_class_id, internal::SetUpTestSuiteFunc set_up_tc,
       internal::TearDownTestSuiteFunc tear_down_tc,
@@ -615,7 +615,7 @@ class GTEST_API_ TestInfo {
 
   // Constructs a TestInfo object. The newly constructed instance assumes
   // ownership of the factory object.
-  TestInfo(const std::string& test_suite_name, const std::string& name,
+  TestInfo(std::string test_suite_name, std::string name,
            const char* a_type_param,   // NULL if not a type-parameterized test
            const char* a_value_param,  // NULL if not a value-parameterized test
            internal::CodeLocation a_code_location,
@@ -683,7 +683,7 @@ class GTEST_API_ TestSuite {
   //                 this is not a type-parameterized test.
   //   set_up_tc:    pointer to the function that sets up the test suite
   //   tear_down_tc: pointer to the function that tears down the test suite
-  TestSuite(const char* name, const char* a_type_param,
+  TestSuite(const std::string& name, const char* a_type_param,
             internal::SetUpTestSuiteFunc set_up_tc,
             internal::TearDownTestSuiteFunc tear_down_tc);
 
@@ -1262,6 +1262,20 @@ class GTEST_API_ UnitTest {
   // total_test_suite_count() - 1. If i is not in that range, returns NULL.
   TestSuite* GetMutableTestSuite(int i);
 
+  // Invokes OsStackTrackGetterInterface::UponLeavingGTest. UponLeavingGTest()
+  // should be called immediately before Google Test calls user code. It saves
+  // some information about the current stack that CurrentStackTrace() will use
+  // to find and hide Google Test stack frames.
+  void UponLeavingGTest();
+
+  // Sets the TestSuite object for the test that's currently running.
+  void set_current_test_suite(TestSuite* a_current_test_suite)
+      GTEST_LOCK_EXCLUDED_(mutex_);
+
+  // Sets the TestInfo object for the test that's currently running.
+  void set_current_test_info(TestInfo* a_current_test_info)
+      GTEST_LOCK_EXCLUDED_(mutex_);
+
   // Accessors for the implementation object.
   internal::UnitTestImpl* impl() { return impl_; }
   const internal::UnitTestImpl* impl() const { return impl_; }
@@ -1270,6 +1284,8 @@ class GTEST_API_ UnitTest {
   // members of UnitTest.
   friend class ScopedTrace;
   friend class Test;
+  friend class TestInfo;
+  friend class TestSuite;
   friend class internal::AssertHelper;
   friend class internal::StreamingListenerTest;
   friend class internal::UnitTestRecordPropertyTestHelper;
@@ -2308,7 +2324,8 @@ TestInfo* RegisterTest(const char* test_suite_name, const char* test_name,
 // tests are successful, or 1 otherwise.
 //
 // RUN_ALL_TESTS() should be invoked after the command line has been
-// parsed by InitGoogleTest().
+// parsed by InitGoogleTest(). RUN_ALL_TESTS will tear down and delete any
+// installed environments and should only be called once per binary.
 //
 // This function was formerly a macro; thus, it is in the global
 // namespace and has an all-caps name.
diff --git a/googletest/include/gtest/internal/custom/gtest.h b/googletest/include/gtest/internal/custom/gtest.h
index 67ce67f1..afaaf17b 100644
--- a/googletest/include/gtest/internal/custom/gtest.h
+++ b/googletest/include/gtest/internal/custom/gtest.h
@@ -34,26 +34,4 @@
 #ifndef GOOGLETEST_INCLUDE_GTEST_INTERNAL_CUSTOM_GTEST_H_
 #define GOOGLETEST_INCLUDE_GTEST_INTERNAL_CUSTOM_GTEST_H_
 
-#if GTEST_OS_LINUX_ANDROID
-# define GTEST_CUSTOM_TEMPDIR_FUNCTION_ GetAndroidTempDir
-# include <unistd.h>
-static inline std::string GetAndroidTempDir() {
-  // Android doesn't have /tmp, and /sdcard is no longer accessible from
-  // an app context starting from Android O. On Android, /data/local/tmp
-  // is usually used as the temporary directory, so try that first...
-  if (access("/data/local/tmp", R_OK | W_OK | X_OK) == 0) return "/data/local/tmp/";
-
-  // Processes running in an app context can't write to /data/local/tmp,
-  // so fall back to the current directory...
-  std::string result = "./";
-  char* cwd = getcwd(NULL, 0);
-  if (cwd != NULL) {
-    result = cwd;
-    result += "/";
-    free(cwd);
-  }
-  return result;
-}
-#endif //GTEST_OS_LINUX_ANDROID
-
 #endif  // GOOGLETEST_INCLUDE_GTEST_INTERNAL_CUSTOM_GTEST_H_
diff --git a/googletest/include/gtest/internal/gtest-death-test-internal.h b/googletest/include/gtest/internal/gtest-death-test-internal.h
index 61536d65..b363259e 100644
--- a/googletest/include/gtest/internal/gtest-death-test-internal.h
+++ b/googletest/include/gtest/internal/gtest-death-test-internal.h
@@ -46,6 +46,7 @@
 
 #include "gtest/gtest-matchers.h"
 #include "gtest/internal/gtest-internal.h"
+#include "gtest/internal/gtest-port.h"
 
 GTEST_DECLARE_string_(internal_run_death_test);
 
@@ -55,6 +56,28 @@ namespace internal {
 // Name of the flag (needed for parsing Google Test flag).
 const char kInternalRunDeathTestFlag[] = "internal_run_death_test";
 
+// A string passed to EXPECT_DEATH (etc.) is caught by one of these overloads
+// and interpreted as a regex (rather than an Eq matcher) for legacy
+// compatibility.
+inline Matcher<const ::std::string&> MakeDeathTestMatcher(
+    ::testing::internal::RE regex) {
+  return ContainsRegex(regex.pattern());
+}
+inline Matcher<const ::std::string&> MakeDeathTestMatcher(const char* regex) {
+  return ContainsRegex(regex);
+}
+inline Matcher<const ::std::string&> MakeDeathTestMatcher(
+    const ::std::string& regex) {
+  return ContainsRegex(regex);
+}
+
+// If a Matcher<const ::std::string&> is passed to EXPECT_DEATH (etc.), it's
+// used directly.
+inline Matcher<const ::std::string&> MakeDeathTestMatcher(
+    Matcher<const ::std::string&> matcher) {
+  return matcher;
+}
+
 #ifdef GTEST_HAS_DEATH_TEST
 
 GTEST_DISABLE_MSC_WARNINGS_PUSH_(4251 \
@@ -71,7 +94,7 @@ GTEST_DISABLE_MSC_WARNINGS_PUSH_(4251 \
 //
 // exit status:  The integer exit information in the format specified
 //               by wait(2)
-// exit code:    The integer code passed to exit(3), _exit(2), or
+// exit code:    The integer code passed to exit(3), _Exit(2), or
 //               returned from main()
 class GTEST_API_ DeathTest {
  public:
@@ -168,28 +191,6 @@ class DefaultDeathTestFactory : public DeathTestFactory {
 // by a signal, or exited normally with a nonzero exit code.
 GTEST_API_ bool ExitedUnsuccessfully(int exit_status);
 
-// A string passed to EXPECT_DEATH (etc.) is caught by one of these overloads
-// and interpreted as a regex (rather than an Eq matcher) for legacy
-// compatibility.
-inline Matcher<const ::std::string&> MakeDeathTestMatcher(
-    ::testing::internal::RE regex) {
-  return ContainsRegex(regex.pattern());
-}
-inline Matcher<const ::std::string&> MakeDeathTestMatcher(const char* regex) {
-  return ContainsRegex(regex);
-}
-inline Matcher<const ::std::string&> MakeDeathTestMatcher(
-    const ::std::string& regex) {
-  return ContainsRegex(regex);
-}
-
-// If a Matcher<const ::std::string&> is passed to EXPECT_DEATH (etc.), it's
-// used directly.
-inline Matcher<const ::std::string&> MakeDeathTestMatcher(
-    Matcher<const ::std::string&> matcher) {
-  return matcher;
-}
-
 // Traps C++ exceptions escaping statement and reports them as test
 // failures. Note that trapping SEH exceptions is not implemented here.
 #if GTEST_HAS_EXCEPTIONS
diff --git a/googletest/include/gtest/internal/gtest-filepath.h b/googletest/include/gtest/internal/gtest-filepath.h
index 5189c81d..6dc47be5 100644
--- a/googletest/include/gtest/internal/gtest-filepath.h
+++ b/googletest/include/gtest/internal/gtest-filepath.h
@@ -43,6 +43,7 @@
 #define GOOGLETEST_INCLUDE_GTEST_INTERNAL_GTEST_FILEPATH_H_
 
 #include <string>
+#include <utility>
 
 #include "gtest/internal/gtest-port.h"
 #include "gtest/internal/gtest-string.h"
@@ -70,8 +71,9 @@ class GTEST_API_ FilePath {
  public:
   FilePath() : pathname_("") {}
   FilePath(const FilePath& rhs) : pathname_(rhs.pathname_) {}
+  FilePath(FilePath&& rhs) noexcept : pathname_(std::move(rhs.pathname_)) {}
 
-  explicit FilePath(const std::string& pathname) : pathname_(pathname) {
+  explicit FilePath(std::string pathname) : pathname_(std::move(pathname)) {
     Normalize();
   }
 
@@ -79,6 +81,10 @@ class GTEST_API_ FilePath {
     Set(rhs);
     return *this;
   }
+  FilePath& operator=(FilePath&& rhs) noexcept {
+    pathname_ = std::move(rhs.pathname_);
+    return *this;
+  }
 
   void Set(const FilePath& rhs) { pathname_ = rhs.pathname_; }
 
diff --git a/googletest/include/gtest/internal/gtest-internal.h b/googletest/include/gtest/internal/gtest-internal.h
index 806b0862..7e55dc60 100644
--- a/googletest/include/gtest/internal/gtest-internal.h
+++ b/googletest/include/gtest/internal/gtest-internal.h
@@ -474,8 +474,8 @@ using SetUpTestSuiteFunc = void (*)();
 using TearDownTestSuiteFunc = void (*)();
 
 struct CodeLocation {
-  CodeLocation(const std::string& a_file, int a_line)
-      : file(a_file), line(a_line) {}
+  CodeLocation(std::string a_file, int a_line)
+      : file(std::move(a_file)), line(a_line) {}
 
   std::string file;
   int line;
@@ -564,7 +564,7 @@ struct SuiteApiResolver : T {
 //                     The newly created TestInfo instance will assume
 //                     ownership of the factory object.
 GTEST_API_ TestInfo* MakeAndRegisterTestInfo(
-    const char* test_suite_name, const char* name, const char* type_param,
+    std::string test_suite_name, const char* name, const char* type_param,
     const char* value_param, CodeLocation code_location,
     TypeId fixture_class_id, SetUpTestSuiteFunc set_up_tc,
     TearDownTestSuiteFunc tear_down_tc, TestFactoryBase* factory);
@@ -595,8 +595,7 @@ class GTEST_API_ TypedTestSuitePState {
       fflush(stderr);
       posix::Abort();
     }
-    registered_tests_.insert(
-        ::std::make_pair(test_name, CodeLocation(file, line)));
+    registered_tests_.emplace(test_name, CodeLocation(file, line));
     return true;
   }
 
@@ -700,7 +699,7 @@ class TypeParameterizedTest {
   // specified in INSTANTIATE_TYPED_TEST_SUITE_P(Prefix, TestSuite,
   // Types).  Valid values for 'index' are [0, N - 1] where N is the
   // length of Types.
-  static bool Register(const char* prefix, const CodeLocation& code_location,
+  static bool Register(const char* prefix, CodeLocation code_location,
                        const char* case_name, const char* test_names, int index,
                        const std::vector<std::string>& type_names =
                            GenerateNames<DefaultNameGenerator, Types>()) {
@@ -712,8 +711,7 @@ class TypeParameterizedTest {
     // list.
     MakeAndRegisterTestInfo(
         (std::string(prefix) + (prefix[0] == '\0' ? "" : "/") + case_name +
-         "/" + type_names[static_cast<size_t>(index)])
-            .c_str(),
+         "/" + type_names[static_cast<size_t>(index)]),
         StripTrailingSpaces(GetPrefixUntilComma(test_names)).c_str(),
         GetTypeName<Type>().c_str(),
         nullptr,  // No value parameter.
@@ -725,13 +723,9 @@ class TypeParameterizedTest {
         new TestFactoryImpl<TestClass>);
 
     // Next, recurses (at compile time) with the tail of the type list.
-    return TypeParameterizedTest<Fixture, TestSel,
-                                 typename Types::Tail>::Register(prefix,
-                                                                 code_location,
-                                                                 case_name,
-                                                                 test_names,
-                                                                 index + 1,
-                                                                 type_names);
+    return TypeParameterizedTest<Fixture, TestSel, typename Types::Tail>::
+        Register(prefix, std::move(code_location), case_name, test_names,
+                 index + 1, type_names);
   }
 };
 
@@ -739,7 +733,7 @@ class TypeParameterizedTest {
 template <GTEST_TEMPLATE_ Fixture, class TestSel>
 class TypeParameterizedTest<Fixture, TestSel, internal::None> {
  public:
-  static bool Register(const char* /*prefix*/, const CodeLocation&,
+  static bool Register(const char* /*prefix*/, CodeLocation,
                        const char* /*case_name*/, const char* /*test_names*/,
                        int /*index*/,
                        const std::vector<std::string>& =
@@ -786,7 +780,8 @@ class TypeParameterizedTestSuite {
 
     // Next, recurses (at compile time) with the tail of the test list.
     return TypeParameterizedTestSuite<Fixture, typename Tests::Tail,
-                                      Types>::Register(prefix, code_location,
+                                      Types>::Register(prefix,
+                                                       std::move(code_location),
                                                        state, case_name,
                                                        SkipComma(test_names),
                                                        type_names);
@@ -1142,40 +1137,6 @@ class NativeArray {
   void (NativeArray::*clone_)(const Element*, size_t);
 };
 
-// Backport of std::index_sequence.
-template <size_t... Is>
-struct IndexSequence {
-  using type = IndexSequence;
-};
-
-// Double the IndexSequence, and one if plus_one is true.
-template <bool plus_one, typename T, size_t sizeofT>
-struct DoubleSequence;
-template <size_t... I, size_t sizeofT>
-struct DoubleSequence<true, IndexSequence<I...>, sizeofT> {
-  using type = IndexSequence<I..., (sizeofT + I)..., 2 * sizeofT>;
-};
-template <size_t... I, size_t sizeofT>
-struct DoubleSequence<false, IndexSequence<I...>, sizeofT> {
-  using type = IndexSequence<I..., (sizeofT + I)...>;
-};
-
-// Backport of std::make_index_sequence.
-// It uses O(ln(N)) instantiation depth.
-template <size_t N>
-struct MakeIndexSequenceImpl
-    : DoubleSequence<N % 2 == 1, typename MakeIndexSequenceImpl<N / 2>::type,
-                     N / 2>::type {};
-
-template <>
-struct MakeIndexSequenceImpl<0> : IndexSequence<> {};
-
-template <size_t N>
-using MakeIndexSequence = typename MakeIndexSequenceImpl<N>::type;
-
-template <typename... T>
-using IndexSequenceFor = typename MakeIndexSequence<sizeof...(T)>::type;
-
 template <size_t>
 struct Ignore {
   Ignore(...);  // NOLINT
@@ -1184,7 +1145,7 @@ struct Ignore {
 template <typename>
 struct ElemFromListImpl;
 template <size_t... I>
-struct ElemFromListImpl<IndexSequence<I...>> {
+struct ElemFromListImpl<std::index_sequence<I...>> {
   // We make Ignore a template to solve a problem with MSVC.
   // A non-template Ignore would work fine with `decltype(Ignore(I))...`, but
   // MSVC doesn't understand how to deal with that pack expansion.
@@ -1195,9 +1156,8 @@ struct ElemFromListImpl<IndexSequence<I...>> {
 
 template <size_t N, typename... T>
 struct ElemFromList {
-  using type =
-      decltype(ElemFromListImpl<typename MakeIndexSequence<N>::type>::Apply(
-          static_cast<T (*)()>(nullptr)...));
+  using type = decltype(ElemFromListImpl<std::make_index_sequence<N>>::Apply(
+      static_cast<T (*)()>(nullptr)...));
 };
 
 struct FlatTupleConstructTag {};
@@ -1222,9 +1182,9 @@ template <typename Derived, typename Idx>
 struct FlatTupleBase;
 
 template <size_t... Idx, typename... T>
-struct FlatTupleBase<FlatTuple<T...>, IndexSequence<Idx...>>
+struct FlatTupleBase<FlatTuple<T...>, std::index_sequence<Idx...>>
     : FlatTupleElemBase<FlatTuple<T...>, Idx>... {
-  using Indices = IndexSequence<Idx...>;
+  using Indices = std::index_sequence<Idx...>;
   FlatTupleBase() = default;
   template <typename... Args>
   explicit FlatTupleBase(FlatTupleConstructTag, Args&&... args)
@@ -1259,14 +1219,15 @@ struct FlatTupleBase<FlatTuple<T...>, IndexSequence<Idx...>>
 // implementations.
 // FlatTuple and ElemFromList are not recursive and have a fixed depth
 // regardless of T...
-// MakeIndexSequence, on the other hand, it is recursive but with an
+// std::make_index_sequence, on the other hand, it is recursive but with an
 // instantiation depth of O(ln(N)).
 template <typename... T>
 class FlatTuple
     : private FlatTupleBase<FlatTuple<T...>,
-                            typename MakeIndexSequence<sizeof...(T)>::type> {
-  using Indices = typename FlatTupleBase<
-      FlatTuple<T...>, typename MakeIndexSequence<sizeof...(T)>::type>::Indices;
+                            std::make_index_sequence<sizeof...(T)>> {
+  using Indices =
+      typename FlatTupleBase<FlatTuple<T...>,
+                             std::make_index_sequence<sizeof...(T)>>::Indices;
 
  public:
   FlatTuple() = default;
@@ -1540,7 +1501,8 @@ class NeverThrown {
                                                                                \
    private:                                                                    \
     void TestBody() override;                                                  \
-    static ::testing::TestInfo* const test_info_ GTEST_ATTRIBUTE_UNUSED_;      \
+    GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static ::testing::TestInfo* const    \
+        test_info_;                                                            \
   };                                                                           \
                                                                                \
   ::testing::TestInfo* const GTEST_TEST_CLASS_NAME_(test_suite_name,           \
diff --git a/googletest/include/gtest/internal/gtest-param-util.h b/googletest/include/gtest/internal/gtest-param-util.h
index b04f7020..cc7ea531 100644
--- a/googletest/include/gtest/internal/gtest-param-util.h
+++ b/googletest/include/gtest/internal/gtest-param-util.h
@@ -47,6 +47,7 @@
 #include <string>
 #include <tuple>
 #include <type_traits>
+#include <unordered_map>
 #include <utility>
 #include <vector>
 
@@ -85,7 +86,7 @@ namespace internal {
 // TEST_P macro is used to define two tests with the same name
 // but in different namespaces.
 GTEST_API_ void ReportInvalidTestSuiteType(const char* test_suite_name,
-                                           CodeLocation code_location);
+                                           const CodeLocation& code_location);
 
 template <typename>
 class ParamGeneratorInterface;
@@ -379,9 +380,7 @@ class ValuesInIteratorRangeGenerator : public ParamGeneratorInterface<T> {
 // integer test parameter index.
 template <class ParamType>
 std::string DefaultParamName(const TestParamInfo<ParamType>& info) {
-  Message name_stream;
-  name_stream << info.index;
-  return name_stream.GetString();
+  return std::to_string(info.index);
 }
 
 template <typename T = int>
@@ -513,9 +512,10 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
   typedef ParamGenerator<ParamType>(GeneratorCreationFunc)();
   using ParamNameGeneratorFunc = std::string(const TestParamInfo<ParamType>&);
 
-  explicit ParameterizedTestSuiteInfo(const char* name,
+  explicit ParameterizedTestSuiteInfo(std::string name,
                                       CodeLocation code_location)
-      : test_suite_name_(name), code_location_(code_location) {}
+      : test_suite_name_(std::move(name)),
+        code_location_(std::move(code_location)) {}
 
   // Test suite base name for display purposes.
   const std::string& GetTestSuiteName() const override {
@@ -529,20 +529,21 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
   // prefix). test_base_name is the name of an individual test without
   // parameter index. For the test SequenceA/FooTest.DoBar/1 FooTest is
   // test suite base name and DoBar is test base name.
-  void AddTestPattern(const char* test_suite_name, const char* test_base_name,
+  void AddTestPattern(const char*,
+                      const char* test_base_name,
                       TestMetaFactoryBase<ParamType>* meta_factory,
                       CodeLocation code_location) {
-    tests_.push_back(std::shared_ptr<TestInfo>(new TestInfo(
-        test_suite_name, test_base_name, meta_factory, code_location)));
+    tests_.emplace_back(
+        new TestInfo(test_base_name, meta_factory, std::move(code_location)));
   }
   // INSTANTIATE_TEST_SUITE_P macro uses AddGenerator() to record information
   // about a generator.
-  int AddTestSuiteInstantiation(const std::string& instantiation_name,
+  int AddTestSuiteInstantiation(std::string instantiation_name,
                                 GeneratorCreationFunc* func,
                                 ParamNameGeneratorFunc* name_func,
                                 const char* file, int line) {
-    instantiations_.push_back(
-        InstantiationInfo(instantiation_name, func, name_func, file, line));
+    instantiations_.emplace_back(std::move(instantiation_name), func, name_func,
+                                 file, line);
     return 0;  // Return value used only to run this method in namespace scope.
   }
   // UnitTest class invokes this method to register tests in this test suite
@@ -553,34 +554,31 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
   void RegisterTests() override {
     bool generated_instantiations = false;
 
-    for (typename TestInfoContainer::iterator test_it = tests_.begin();
-         test_it != tests_.end(); ++test_it) {
-      std::shared_ptr<TestInfo> test_info = *test_it;
-      for (typename InstantiationContainer::iterator gen_it =
-               instantiations_.begin();
-           gen_it != instantiations_.end(); ++gen_it) {
-        const std::string& instantiation_name = gen_it->name;
-        ParamGenerator<ParamType> generator((*gen_it->generator)());
-        ParamNameGeneratorFunc* name_func = gen_it->name_func;
-        const char* file = gen_it->file;
-        int line = gen_it->line;
-
-        std::string test_suite_name;
+    std::string test_suite_name;
+    std::string test_name;
+    for (const std::shared_ptr<TestInfo>& test_info : tests_) {
+      for (const InstantiationInfo& instantiation : instantiations_) {
+        const std::string& instantiation_name = instantiation.name;
+        ParamGenerator<ParamType> generator((*instantiation.generator)());
+        ParamNameGeneratorFunc* name_func = instantiation.name_func;
+        const char* file = instantiation.file;
+        int line = instantiation.line;
+
         if (!instantiation_name.empty())
           test_suite_name = instantiation_name + "/";
-        test_suite_name += test_info->test_suite_base_name;
+        else
+          test_suite_name.clear();
+        test_suite_name += test_suite_name_;
 
         size_t i = 0;
         std::set<std::string> test_param_names;
-        for (typename ParamGenerator<ParamType>::iterator param_it =
-                 generator.begin();
-             param_it != generator.end(); ++param_it, ++i) {
+        for (const auto& param : generator) {
           generated_instantiations = true;
 
-          Message test_name_stream;
+          test_name.clear();
 
           std::string param_name =
-              name_func(TestParamInfo<ParamType>(*param_it, i));
+              name_func(TestParamInfo<ParamType>(param, i));
 
           GTEST_CHECK_(IsValidParamName(param_name))
               << "Parameterized test name '" << param_name
@@ -592,23 +590,25 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
               << "Duplicate parameterized test name '" << param_name << "', in "
               << file << " line " << line << std::endl;
 
-          test_param_names.insert(param_name);
-
           if (!test_info->test_base_name.empty()) {
-            test_name_stream << test_info->test_base_name << "/";
+            test_name.append(test_info->test_base_name).append("/");
           }
-          test_name_stream << param_name;
+          test_name += param_name;
+
+          test_param_names.insert(std::move(param_name));
+
           MakeAndRegisterTestInfo(
-              test_suite_name.c_str(), test_name_stream.GetString().c_str(),
+              test_suite_name, test_name.c_str(),
               nullptr,  // No type parameter.
-              PrintToString(*param_it).c_str(), test_info->code_location,
+              PrintToString(param).c_str(), test_info->code_location,
               GetTestSuiteTypeId(),
               SuiteApiResolver<TestSuite>::GetSetUpCaseOrSuite(file, line),
               SuiteApiResolver<TestSuite>::GetTearDownCaseOrSuite(file, line),
-              test_info->test_meta_factory->CreateTestFactory(*param_it));
-        }  // for param_it
-      }    // for gen_it
-    }      // for test_it
+              test_info->test_meta_factory->CreateTestFactory(param));
+          ++i;
+        }  // for param
+      }  // for instantiation
+    }  // for test_info
 
     if (!generated_instantiations) {
       // There are no generaotrs, or they all generate nothing ...
@@ -621,15 +621,13 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
   // LocalTestInfo structure keeps information about a single test registered
   // with TEST_P macro.
   struct TestInfo {
-    TestInfo(const char* a_test_suite_base_name, const char* a_test_base_name,
+    TestInfo(const char* a_test_base_name,
              TestMetaFactoryBase<ParamType>* a_test_meta_factory,
              CodeLocation a_code_location)
-        : test_suite_base_name(a_test_suite_base_name),
-          test_base_name(a_test_base_name),
+        : test_base_name(a_test_base_name),
           test_meta_factory(a_test_meta_factory),
-          code_location(a_code_location) {}
+          code_location(std::move(a_code_location)) {}
 
-    const std::string test_suite_base_name;
     const std::string test_base_name;
     const std::unique_ptr<TestMetaFactoryBase<ParamType>> test_meta_factory;
     const CodeLocation code_location;
@@ -639,11 +637,10 @@ class ParameterizedTestSuiteInfo : public ParameterizedTestSuiteInfoBase {
   //  <Instantiation name, Sequence generator creation function,
   //     Name generator function, Source file, Source line>
   struct InstantiationInfo {
-    InstantiationInfo(const std::string& name_in,
-                      GeneratorCreationFunc* generator_in,
+    InstantiationInfo(std::string name_in, GeneratorCreationFunc* generator_in,
                       ParamNameGeneratorFunc* name_func_in, const char* file_in,
                       int line_in)
-        : name(name_in),
+        : name(std::move(name_in)),
           generator(generator_in),
           name_func(name_func_in),
           file(file_in),
@@ -704,29 +701,32 @@ class ParameterizedTestSuiteRegistry {
   // tests and instantiations of a particular test suite.
   template <class TestSuite>
   ParameterizedTestSuiteInfo<TestSuite>* GetTestSuitePatternHolder(
-      const char* test_suite_name, CodeLocation code_location) {
+      std::string test_suite_name, CodeLocation code_location) {
     ParameterizedTestSuiteInfo<TestSuite>* typed_test_info = nullptr;
-    for (auto& test_suite_info : test_suite_infos_) {
-      if (test_suite_info->GetTestSuiteName() == test_suite_name) {
-        if (test_suite_info->GetTestSuiteTypeId() != GetTypeId<TestSuite>()) {
-          // Complain about incorrect usage of Google Test facilities
-          // and terminate the program since we cannot guaranty correct
-          // test suite setup and tear-down in this case.
-          ReportInvalidTestSuiteType(test_suite_name, code_location);
-          posix::Abort();
-        } else {
-          // At this point we are sure that the object we found is of the same
-          // type we are looking for, so we downcast it to that type
-          // without further checks.
-          typed_test_info = CheckedDowncastToActualType<
-              ParameterizedTestSuiteInfo<TestSuite>>(test_suite_info);
-        }
-        break;
+
+    auto item_it = suite_name_to_info_index_.find(test_suite_name);
+    if (item_it != suite_name_to_info_index_.end()) {
+      auto* test_suite_info = test_suite_infos_[item_it->second];
+      if (test_suite_info->GetTestSuiteTypeId() != GetTypeId<TestSuite>()) {
+        // Complain about incorrect usage of Google Test facilities
+        // and terminate the program since we cannot guaranty correct
+        // test suite setup and tear-down in this case.
+        ReportInvalidTestSuiteType(test_suite_name.c_str(), code_location);
+        posix::Abort();
+      } else {
+        // At this point we are sure that the object we found is of the same
+        // type we are looking for, so we downcast it to that type
+        // without further checks.
+        typed_test_info =
+            CheckedDowncastToActualType<ParameterizedTestSuiteInfo<TestSuite>>(
+                test_suite_info);
       }
     }
     if (typed_test_info == nullptr) {
       typed_test_info = new ParameterizedTestSuiteInfo<TestSuite>(
-          test_suite_name, code_location);
+          test_suite_name, std::move(code_location));
+      suite_name_to_info_index_.emplace(std::move(test_suite_name),
+                                        test_suite_infos_.size());
       test_suite_infos_.push_back(typed_test_info);
     }
     return typed_test_info;
@@ -740,8 +740,9 @@ class ParameterizedTestSuiteRegistry {
 #ifndef GTEST_REMOVE_LEGACY_TEST_CASEAPI_
   template <class TestCase>
   ParameterizedTestCaseInfo<TestCase>* GetTestCasePatternHolder(
-      const char* test_case_name, CodeLocation code_location) {
-    return GetTestSuitePatternHolder<TestCase>(test_case_name, code_location);
+      std::string test_case_name, CodeLocation code_location) {
+    return GetTestSuitePatternHolder<TestCase>(std::move(test_case_name),
+                                               std::move(code_location));
   }
 
 #endif  //  GTEST_REMOVE_LEGACY_TEST_CASEAPI_
@@ -750,6 +751,7 @@ class ParameterizedTestSuiteRegistry {
   using TestSuiteInfoContainer = ::std::vector<ParameterizedTestSuiteInfoBase*>;
 
   TestSuiteInfoContainer test_suite_infos_;
+  ::std::unordered_map<std::string, size_t> suite_name_to_info_index_;
 
   ParameterizedTestSuiteRegistry(const ParameterizedTestSuiteRegistry&) =
       delete;
@@ -776,7 +778,7 @@ class TypeParameterizedTestSuiteRegistry {
  private:
   struct TypeParameterizedTestSuiteInfo {
     explicit TypeParameterizedTestSuiteInfo(CodeLocation c)
-        : code_location(c), instantiated(false) {}
+        : code_location(std::move(c)), instantiated(false) {}
 
     CodeLocation code_location;
     bool instantiated;
@@ -805,12 +807,12 @@ class ValueArray {
 
   template <typename T>
   operator ParamGenerator<T>() const {  // NOLINT
-    return ValuesIn(MakeVector<T>(MakeIndexSequence<sizeof...(Ts)>()));
+    return ValuesIn(MakeVector<T>(std::make_index_sequence<sizeof...(Ts)>()));
   }
 
  private:
   template <typename T, size_t... I>
-  std::vector<T> MakeVector(IndexSequence<I...>) const {
+  std::vector<T> MakeVector(std::index_sequence<I...>) const {
     return std::vector<T>{static_cast<T>(v_.template Get<I>())...};
   }
 
@@ -840,7 +842,7 @@ class CartesianProductGenerator
   template <class I>
   class IteratorImpl;
   template <size_t... I>
-  class IteratorImpl<IndexSequence<I...>>
+  class IteratorImpl<std::index_sequence<I...>>
       : public ParamIteratorInterface<ParamType> {
    public:
     IteratorImpl(const ParamGeneratorInterface<ParamType>* base,
@@ -931,7 +933,7 @@ class CartesianProductGenerator
     std::shared_ptr<ParamType> current_value_;
   };
 
-  using Iterator = IteratorImpl<typename MakeIndexSequence<sizeof...(T)>::type>;
+  using Iterator = IteratorImpl<std::make_index_sequence<sizeof...(T)>>;
 
   std::tuple<ParamGenerator<T>...> generators_;
 };
diff --git a/googletest/include/gtest/internal/gtest-port-arch.h b/googletest/include/gtest/internal/gtest-port-arch.h
index 3162f2b1..7ec968f3 100644
--- a/googletest/include/gtest/internal/gtest-port-arch.h
+++ b/googletest/include/gtest/internal/gtest-port-arch.h
@@ -56,6 +56,8 @@
 #elif WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_TV_TITLE)
 #define GTEST_OS_WINDOWS_PHONE 1
 #define GTEST_OS_WINDOWS_TV_TITLE 1
+#elif WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_GAMES)
+#define GTEST_OS_WINDOWS_GAMES 1
 #else
 // WINAPI_FAMILY defined but no known partition matched.
 // Default to desktop.
diff --git a/googletest/include/gtest/internal/gtest-port.h b/googletest/include/gtest/internal/gtest-port.h
index 2adf0627..d4990f3f 100644
--- a/googletest/include/gtest/internal/gtest-port.h
+++ b/googletest/include/gtest/internal/gtest-port.h
@@ -194,8 +194,6 @@
 //
 // Macros for basic C++ coding:
 //   GTEST_AMBIGUOUS_ELSE_BLOCKER_ - for disabling a gcc warning.
-//   GTEST_ATTRIBUTE_UNUSED_  - declares that a class' instances or a
-//                              variable don't have to be used.
 //   GTEST_MUST_USE_RESULT_   - declares that a function's result must be used.
 //   GTEST_INTENTIONAL_CONST_COND_PUSH_ - start code section where MSVC C4127 is
 //                                        suppressed (constant conditional).
@@ -340,8 +338,8 @@
 
 #if defined(GTEST_HAS_ABSL) && !defined(GTEST_NO_ABSL_FLAGS)
 #define GTEST_INTERNAL_HAS_ABSL_FLAGS  // Used only in this file.
-#include "absl/flags/flag.h"
 #include "absl/flags/declare.h"
+#include "absl/flags/flag.h"
 #include "absl/flags/reflection.h"
 #endif
 
@@ -609,7 +607,8 @@ typedef struct _RTL_CRITICAL_SECTION GTEST_CRITICAL_SECTION;
      defined(GTEST_OS_NETBSD) || defined(GTEST_OS_FUCHSIA) ||         \
      defined(GTEST_OS_DRAGONFLY) || defined(GTEST_OS_GNU_KFREEBSD) || \
      defined(GTEST_OS_OPENBSD) || defined(GTEST_OS_HAIKU) ||          \
-     defined(GTEST_OS_GNU_HURD))
+     defined(GTEST_OS_GNU_HURD) || defined(GTEST_OS_SOLARIS) ||       \
+     defined(GTEST_OS_AIX) || defined(GTEST_OS_ZOS))
 #define GTEST_HAS_PTHREAD 1
 #else
 #define GTEST_HAS_PTHREAD 0
@@ -659,9 +658,9 @@ typedef struct _RTL_CRITICAL_SECTION GTEST_CRITICAL_SECTION;
 // platforms except known mobile / embedded ones. Also, if the port doesn't have
 // a file system, stream redirection is not supported.
 #if defined(GTEST_OS_WINDOWS_MOBILE) || defined(GTEST_OS_WINDOWS_PHONE) || \
-    defined(GTEST_OS_WINDOWS_RT) || defined(GTEST_OS_ESP8266) ||           \
-    defined(GTEST_OS_XTENSA) || defined(GTEST_OS_QURT) ||                  \
-    !GTEST_HAS_FILE_SYSTEM
+    defined(GTEST_OS_WINDOWS_RT) || defined(GTEST_OS_WINDOWS_GAMES) ||     \
+    defined(GTEST_OS_ESP8266) || defined(GTEST_OS_XTENSA) ||               \
+    defined(GTEST_OS_QURT) || !GTEST_HAS_FILE_SYSTEM
 #define GTEST_HAS_STREAM_REDIRECTION 0
 #else
 #define GTEST_HAS_STREAM_REDIRECTION 1
@@ -671,7 +670,7 @@ typedef struct _RTL_CRITICAL_SECTION GTEST_CRITICAL_SECTION;
 // Determines whether to support death tests.
 // pops up a dialog window that cannot be suppressed programmatically.
 #if (defined(GTEST_OS_LINUX) || defined(GTEST_OS_CYGWIN) ||           \
-     defined(GTEST_OS_SOLARIS) ||                                     \
+     defined(GTEST_OS_SOLARIS) || defined(GTEST_OS_ZOS) ||            \
      (defined(GTEST_OS_MAC) && !defined(GTEST_OS_IOS)) ||             \
      (defined(GTEST_OS_WINDOWS_DESKTOP) && _MSC_VER) ||               \
      defined(GTEST_OS_WINDOWS_MINGW) || defined(GTEST_OS_AIX) ||      \
@@ -751,6 +750,20 @@ typedef struct _RTL_CRITICAL_SECTION GTEST_CRITICAL_SECTION;
 #define GTEST_HAVE_ATTRIBUTE_(x) 0
 #endif
 
+// GTEST_INTERNAL_HAVE_CPP_ATTRIBUTE
+//
+// A function-like feature checking macro that accepts C++11 style attributes.
+// It's a wrapper around `__has_cpp_attribute`, defined by ISO C++ SD-6
+// (https://en.cppreference.com/w/cpp/experimental/feature_test). If we don't
+// find `__has_cpp_attribute`, will evaluate to 0.
+#if defined(__has_cpp_attribute)
+// NOTE: requiring __cplusplus above should not be necessary, but
+// works around https://bugs.llvm.org/show_bug.cgi?id=23435.
+#define GTEST_INTERNAL_HAVE_CPP_ATTRIBUTE(x) __has_cpp_attribute(x)
+#else
+#define GTEST_INTERNAL_HAVE_CPP_ATTRIBUTE(x) 0
+#endif
+
 // GTEST_HAVE_FEATURE_
 //
 // A function-like feature checking macro that is a wrapper around
@@ -762,14 +775,22 @@ typedef struct _RTL_CRITICAL_SECTION GTEST_CRITICAL_SECTION;
 #endif
 
 // Use this annotation after a variable or parameter declaration to tell the
-// compiler the variable/parameter does not have to be used.
+// compiler the variable/parameter may be used.
 // Example:
 //
-//   GTEST_ATTRIBUTE_UNUSED_ int foo = bar();
-#if GTEST_HAVE_ATTRIBUTE_(unused)
-#define GTEST_ATTRIBUTE_UNUSED_ __attribute__((unused))
+//   GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED int foo = bar();
+//
+// This can be removed once we only support only C++17 or newer and
+// [[maybe_unused]] is available on all supported platforms.
+#if GTEST_INTERNAL_HAVE_CPP_ATTRIBUTE(maybe_unused)
+#define GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED [[maybe_unused]]
+#elif GTEST_HAVE_ATTRIBUTE_(unused)
+// This is inferior to [[maybe_unused]] as it can produce a
+// -Wused-but-marked-unused warning on optionally used symbols, but it is all we
+// have.
+#define GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED __attribute__((__unused__))
 #else
-#define GTEST_ATTRIBUTE_UNUSED_
+#define GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED
 #endif
 
 // Use this annotation before a function that takes a printf format string.
@@ -2120,8 +2141,9 @@ GTEST_DISABLE_MSC_DEPRECATED_PUSH_()
 // defined there.
 #if GTEST_HAS_FILE_SYSTEM
 #if !defined(GTEST_OS_WINDOWS_MOBILE) && !defined(GTEST_OS_WINDOWS_PHONE) && \
-    !defined(GTEST_OS_WINDOWS_RT) && !defined(GTEST_OS_ESP8266) &&           \
-    !defined(GTEST_OS_XTENSA) && !defined(GTEST_OS_QURT)
+    !defined(GTEST_OS_WINDOWS_RT) && !defined(GTEST_OS_WINDOWS_GAMES) &&     \
+    !defined(GTEST_OS_ESP8266) && !defined(GTEST_OS_XTENSA) &&               \
+    !defined(GTEST_OS_QURT)
 inline int ChDir(const char* dir) { return chdir(dir); }
 #endif
 inline FILE* FOpen(const char* path, const char* mode) {
diff --git a/googletest/include/gtest/internal/gtest-type-util.h b/googletest/include/gtest/internal/gtest-type-util.h
index f94cf614..78da0531 100644
--- a/googletest/include/gtest/internal/gtest-type-util.h
+++ b/googletest/include/gtest/internal/gtest-type-util.h
@@ -71,7 +71,7 @@ inline std::string CanonicalizeForStdLibVersioning(std::string s) {
   // Strip redundant spaces in typename to match MSVC
   // For example, std::pair<int, bool> -> std::pair<int,bool>
   static const char to_search[] = ", ";
-  static const char replace_str[] = ",";
+  const char replace_char = ',';
   size_t pos = 0;
   while (true) {
     // Get the next occurrence from the current position
@@ -80,8 +80,8 @@ inline std::string CanonicalizeForStdLibVersioning(std::string s) {
       break;
     }
     // Replace this occurrence of substring
-    s.replace(pos, strlen(to_search), replace_str);
-    pos += strlen(replace_str);
+    s.replace(pos, strlen(to_search), 1, replace_char);
+    ++pos;
   }
   return s;
 }
diff --git a/googletest/src/gtest-death-test.cc b/googletest/src/gtest-death-test.cc
index 8417a300..15472f1a 100644
--- a/googletest/src/gtest-death-test.cc
+++ b/googletest/src/gtest-death-test.cc
@@ -32,6 +32,8 @@
 
 #include "gtest/gtest-death-test.h"
 
+#include <stdlib.h>
+
 #include <functional>
 #include <memory>
 #include <sstream>
@@ -115,7 +117,7 @@ GTEST_DEFINE_string_(
 GTEST_DEFINE_bool_(
     death_test_use_fork,
     testing::internal::BoolFromGTestEnv("death_test_use_fork", false),
-    "Instructs to use fork()/_exit() instead of clone() in death tests. "
+    "Instructs to use fork()/_Exit() instead of clone() in death tests. "
     "Ignored and always uses fork() on POSIX systems where clone() is not "
     "implemented. Useful when running under valgrind or similar tools if "
     "those do not support clone(). Valgrind 3.3.1 will just fail if "
@@ -299,7 +301,7 @@ enum DeathTestOutcome { IN_PROGRESS, DIED, LIVED, RETURNED, THREW };
     fputc(kDeathTestInternalError, parent);
     fprintf(parent, "%s", message.c_str());
     fflush(parent);
-    _exit(1);
+    _Exit(1);
   } else {
     fprintf(stderr, "%s", message.c_str());
     fflush(stderr);
@@ -511,7 +513,7 @@ std::string DeathTestImpl::GetErrorLogs() { return GetCapturedStderr(); }
 // Signals that the death test code which should have exited, didn't.
 // Should be called only in a death test child process.
 // Writes a status byte to the child's status file descriptor, then
-// calls _exit(1).
+// calls _Exit(1).
 void DeathTestImpl::Abort(AbortReason reason) {
   // The parent process considers the death test to be a failure if
   // it finds any data in our pipe.  So, here we write a single flag byte
@@ -523,13 +525,13 @@ void DeathTestImpl::Abort(AbortReason reason) {
   GTEST_DEATH_TEST_CHECK_SYSCALL_(posix::Write(write_fd(), &status_ch, 1));
   // We are leaking the descriptor here because on some platforms (i.e.,
   // when built as Windows DLL), destructors of global objects will still
-  // run after calling _exit(). On such systems, write_fd_ will be
+  // run after calling _Exit(). On such systems, write_fd_ will be
   // indirectly closed from the destructor of UnitTestImpl, causing double
   // close if it is also closed here. On debug configurations, double close
   // may assert. As there are no in-process buffers to flush here, we are
   // relying on the OS to close the descriptor after the process terminates
   // when the destructors are not run.
-  _exit(1);  // Exits w/o any normal exit hooks (we were supposed to crash)
+  _Exit(1);  // Exits w/o any normal exit hooks (we were supposed to crash)
 }
 
 // Returns an indented copy of stderr output for a death test.
@@ -628,13 +630,13 @@ bool DeathTestImpl::Passed(bool status_ok) {
 #ifndef GTEST_OS_WINDOWS
 // Note: The return value points into args, so the return value's lifetime is
 // bound to that of args.
-static std::unique_ptr<char*[]> CreateArgvFromArgs(
-    std::vector<std::string>& args) {
-  auto result = std::make_unique<char*[]>(args.size() + 1);
-  for (size_t i = 0; i < args.size(); ++i) {
-    result[i] = &args[i][0];
+static std::vector<char*> CreateArgvFromArgs(std::vector<std::string>& args) {
+  std::vector<char*> result;
+  result.reserve(args.size() + 1);
+  for (auto& arg : args) {
+    result.push_back(&arg[0]);
   }
-  result[args.size()] = nullptr;  // extra null terminator
+  result.push_back(nullptr);  // Extra null terminator.
   return result;
 }
 #endif
@@ -1034,8 +1036,8 @@ DeathTest::TestRole FuchsiaDeathTest::AssumeRole() {
   // "Fuchsia Test Component" which contains a "Fuchsia Component Manifest")
   // Launching processes is a privileged operation in Fuchsia, and the
   // declaration indicates that the ability is required for the component.
-  std::unique_ptr<char*[]> argv = CreateArgvFromArgs(args);
-  status = fdio_spawn_etc(child_job, FDIO_SPAWN_CLONE_ALL, argv[0], argv.get(),
+  std::vector<char*> argv = CreateArgvFromArgs(args);
+  status = fdio_spawn_etc(child_job, FDIO_SPAWN_CLONE_ALL, argv[0], argv.data(),
                           nullptr, 2, spawn_actions,
                           child_process_.reset_and_get_address(), nullptr);
   GTEST_DEATH_TEST_CHECK_(status == ZX_OK);
@@ -1333,7 +1335,7 @@ static pid_t ExecDeathTestSpawnChild(char* const* argv, int close_fd) {
 #endif  // GTEST_HAS_CLONE
 
   if (use_fork && (child_pid = fork()) == 0) {
-    _exit(ExecDeathTestChildMain(&args));
+    _Exit(ExecDeathTestChildMain(&args));
   }
 #endif  // GTEST_OS_QNX
 #ifdef GTEST_OS_LINUX
@@ -1386,8 +1388,8 @@ DeathTest::TestRole ExecDeathTest::AssumeRole() {
   // is necessary.
   FlushInfoLog();
 
-  std::unique_ptr<char*[]> argv = CreateArgvFromArgs(args);
-  const pid_t child_pid = ExecDeathTestSpawnChild(argv.get(), pipe_fd[0]);
+  std::vector<char*> argv = CreateArgvFromArgs(args);
+  const pid_t child_pid = ExecDeathTestSpawnChild(argv.data(), pipe_fd[0]);
   GTEST_DEATH_TEST_CHECK_SYSCALL_(close(pipe_fd[1]));
   set_child_pid(child_pid);
   set_read_fd(pipe_fd[0]);
diff --git a/googletest/src/gtest-internal-inl.h b/googletest/src/gtest-internal-inl.h
index 4799a1e7..cc6f0048 100644
--- a/googletest/src/gtest-internal-inl.h
+++ b/googletest/src/gtest-internal-inl.h
@@ -46,6 +46,7 @@
 #include <memory>
 #include <set>
 #include <string>
+#include <unordered_map>
 #include <vector>
 
 #include "gtest/internal/gtest-port.h"
@@ -649,13 +650,15 @@ class GTEST_API_ UnitTestImpl {
   //                    this is not a typed or a type-parameterized test.
   //   set_up_tc:       pointer to the function that sets up the test suite
   //   tear_down_tc:    pointer to the function that tears down the test suite
-  TestSuite* GetTestSuite(const char* test_suite_name, const char* type_param,
+  TestSuite* GetTestSuite(const std::string& test_suite_name,
+                          const char* type_param,
                           internal::SetUpTestSuiteFunc set_up_tc,
                           internal::TearDownTestSuiteFunc tear_down_tc);
 
 //  Legacy API is deprecated but still available
 #ifndef GTEST_REMOVE_LEGACY_TEST_CASEAPI_
-  TestCase* GetTestCase(const char* test_case_name, const char* type_param,
+  TestCase* GetTestCase(const std::string& test_case_name,
+                        const char* type_param,
                         internal::SetUpTestSuiteFunc set_up_tc,
                         internal::TearDownTestSuiteFunc tear_down_tc) {
     return GetTestSuite(test_case_name, type_param, set_up_tc, tear_down_tc);
@@ -681,13 +684,13 @@ class GTEST_API_ UnitTestImpl {
     // AddTestInfo(), which is called to register a TEST or TEST_F
     // before main() is reached.
     if (original_working_dir_.IsEmpty()) {
-      original_working_dir_.Set(FilePath::GetCurrentDir());
+      original_working_dir_ = FilePath::GetCurrentDir();
       GTEST_CHECK_(!original_working_dir_.IsEmpty())
           << "Failed to get the current working directory.";
     }
 #endif  // GTEST_HAS_FILE_SYSTEM
 
-    GetTestSuite(test_info->test_suite_name(), test_info->type_param(),
+    GetTestSuite(test_info->test_suite_name_, test_info->type_param(),
                  set_up_tc, tear_down_tc)
         ->AddTestInfo(test_info);
   }
@@ -709,18 +712,6 @@ class GTEST_API_ UnitTestImpl {
     return type_parameterized_test_registry_;
   }
 
-  // Sets the TestSuite object for the test that's currently running.
-  void set_current_test_suite(TestSuite* a_current_test_suite) {
-    current_test_suite_ = a_current_test_suite;
-  }
-
-  // Sets the TestInfo object for the test that's currently running.  If
-  // current_test_info is NULL, the assertion results will be stored in
-  // ad_hoc_test_result_.
-  void set_current_test_info(TestInfo* a_current_test_info) {
-    current_test_info_ = a_current_test_info;
-  }
-
   // Registers all parameterized tests defined using TEST_P and
   // INSTANTIATE_TEST_SUITE_P, creating regular tests for each test/parameter
   // combination. This method can be called more then once; it has guards
@@ -835,12 +826,30 @@ class GTEST_API_ UnitTestImpl {
   bool catch_exceptions() const { return catch_exceptions_; }
 
  private:
+  struct CompareTestSuitesByPointer {
+    bool operator()(const TestSuite* lhs, const TestSuite* rhs) const {
+      return lhs->name_ < rhs->name_;
+    }
+  };
+
   friend class ::testing::UnitTest;
 
   // Used by UnitTest::Run() to capture the state of
   // GTEST_FLAG(catch_exceptions) at the moment it starts.
   void set_catch_exceptions(bool value) { catch_exceptions_ = value; }
 
+  // Sets the TestSuite object for the test that's currently running.
+  void set_current_test_suite(TestSuite* a_current_test_suite) {
+    current_test_suite_ = a_current_test_suite;
+  }
+
+  // Sets the TestInfo object for the test that's currently running.  If
+  // current_test_info is NULL, the assertion results will be stored in
+  // ad_hoc_test_result_.
+  void set_current_test_info(TestInfo* a_current_test_info) {
+    current_test_info_ = a_current_test_info;
+  }
+
   // The UnitTest object that owns this implementation object.
   UnitTest* const parent_;
 
@@ -873,6 +882,9 @@ class GTEST_API_ UnitTestImpl {
   // elements in the vector.
   std::vector<TestSuite*> test_suites_;
 
+  // The set of TestSuites by name.
+  std::unordered_map<std::string, TestSuite*> test_suites_by_name_;
+
   // Provides a level of indirection for the test suite list to allow
   // easy shuffling and restoring the test suite order.  The i-th
   // element of this vector is the index of the i-th test suite in the
diff --git a/googletest/src/gtest-port.cc b/googletest/src/gtest-port.cc
index 3bb7dd45..1038ad7b 100644
--- a/googletest/src/gtest-port.cc
+++ b/googletest/src/gtest-port.cc
@@ -587,9 +587,11 @@ class ThreadLocalRegistryImpl {
   // thread's ID.
   typedef std::map<DWORD, ThreadLocalValues> ThreadIdToThreadLocals;
 
-  // Holds the thread id and thread handle that we pass from
-  // StartWatcherThreadFor to WatcherThreadFunc.
-  typedef std::pair<DWORD, HANDLE> ThreadIdAndHandle;
+  struct WatcherThreadParams {
+    DWORD thread_id;
+    HANDLE handle;
+    Notification has_initialized;
+  };
 
   static void StartWatcherThreadFor(DWORD thread_id) {
     // The returned handle will be kept in thread_map and closed by
@@ -597,15 +599,20 @@ class ThreadLocalRegistryImpl {
     HANDLE thread =
         ::OpenThread(SYNCHRONIZE | THREAD_QUERY_INFORMATION, FALSE, thread_id);
     GTEST_CHECK_(thread != nullptr);
+
+    WatcherThreadParams* watcher_thread_params = new WatcherThreadParams;
+    watcher_thread_params->thread_id = thread_id;
+    watcher_thread_params->handle = thread;
+
     // We need to pass a valid thread ID pointer into CreateThread for it
     // to work correctly under Win98.
     DWORD watcher_thread_id;
-    HANDLE watcher_thread = ::CreateThread(
-        nullptr,  // Default security.
-        0,        // Default stack size
-        &ThreadLocalRegistryImpl::WatcherThreadFunc,
-        reinterpret_cast<LPVOID>(new ThreadIdAndHandle(thread_id, thread)),
-        CREATE_SUSPENDED, &watcher_thread_id);
+    HANDLE watcher_thread =
+        ::CreateThread(nullptr,  // Default security.
+                       0,        // Default stack size
+                       &ThreadLocalRegistryImpl::WatcherThreadFunc,
+                       reinterpret_cast<LPVOID>(watcher_thread_params),
+                       CREATE_SUSPENDED, &watcher_thread_id);
     GTEST_CHECK_(watcher_thread != nullptr)
         << "CreateThread failed with error " << ::GetLastError() << ".";
     // Give the watcher thread the same priority as ours to avoid being
@@ -614,17 +621,25 @@ class ThreadLocalRegistryImpl {
                         ::GetThreadPriority(::GetCurrentThread()));
     ::ResumeThread(watcher_thread);
     ::CloseHandle(watcher_thread);
+
+    // Wait for the watcher thread to start to avoid race conditions.
+    // One specific race condition that can happen is that we have returned
+    // from main and have started to tear down, the newly spawned watcher
+    // thread may access already-freed variables, like global shared_ptrs.
+    watcher_thread_params->has_initialized.WaitForNotification();
   }
 
   // Monitors exit from a given thread and notifies those
   // ThreadIdToThreadLocals about thread termination.
   static DWORD WINAPI WatcherThreadFunc(LPVOID param) {
-    const ThreadIdAndHandle* tah =
-        reinterpret_cast<const ThreadIdAndHandle*>(param);
-    GTEST_CHECK_(::WaitForSingleObject(tah->second, INFINITE) == WAIT_OBJECT_0);
-    OnThreadExit(tah->first);
-    ::CloseHandle(tah->second);
-    delete tah;
+    WatcherThreadParams* watcher_thread_params =
+        reinterpret_cast<WatcherThreadParams*>(param);
+    watcher_thread_params->has_initialized.Notify();
+    GTEST_CHECK_(::WaitForSingleObject(watcher_thread_params->handle,
+                                       INFINITE) == WAIT_OBJECT_0);
+    OnThreadExit(watcher_thread_params->thread_id);
+    ::CloseHandle(watcher_thread_params->handle);
+    delete watcher_thread_params;
     return 0;
   }
 
@@ -1033,12 +1048,12 @@ GTestLog::~GTestLog() {
   }
 }
 
+#if GTEST_HAS_STREAM_REDIRECTION
+
 // Disable Microsoft deprecation warnings for POSIX functions called from
 // this class (creat, dup, dup2, and close)
 GTEST_DISABLE_MSC_DEPRECATED_PUSH_()
 
-#if GTEST_HAS_STREAM_REDIRECTION
-
 namespace {
 
 #if defined(GTEST_OS_LINUX_ANDROID) || defined(GTEST_OS_IOS)
@@ -1333,8 +1348,8 @@ bool ParseInt32(const Message& src_text, const char* str, int32_t* value) {
   ) {
     Message msg;
     msg << "WARNING: " << src_text
-        << " is expected to be a 32-bit integer, but actually"
-        << " has value " << str << ", which overflows.\n";
+        << " is expected to be a 32-bit integer, but actually" << " has value "
+        << str << ", which overflows.\n";
     printf("%s", msg.GetString().c_str());
     fflush(stdout);
     return false;
diff --git a/googletest/src/gtest.cc b/googletest/src/gtest.cc
index 34d3e301..d25e39a4 100644
--- a/googletest/src/gtest.cc
+++ b/googletest/src/gtest.cc
@@ -379,7 +379,7 @@ GTEST_DEFINE_string_(
     testing::internal::StringFromGTestEnv("stream_result_to", ""),
     "This flag specifies the host name and the port number on which to stream "
     "test results. Example: \"localhost:555\". The flag is effective only on "
-    "Linux.");
+    "Linux and macOS.");
 
 GTEST_DEFINE_bool_(
     throw_on_failure,
@@ -451,6 +451,19 @@ static bool ShouldRunTestSuite(const TestSuite* test_suite) {
   return test_suite->should_run();
 }
 
+namespace {
+
+// Returns true if test part results of type `type` should include a stack
+// trace.
+bool ShouldEmitStackTraceForResultType(TestPartResult::Type type) {
+  // Suppress emission of the stack trace for SUCCEED() since it likely never
+  // requires investigation, and GTEST_SKIP() since skipping is an intentional
+  // act by the developer rather than a failure requiring investigation.
+  return type != TestPartResult::kSuccess && type != TestPartResult::kSkip;
+}
+
+}  // namespace
+
 // AssertHelper constructor.
 AssertHelper::AssertHelper(TestPartResult::Type type, const char* file,
                            int line, const char* message)
@@ -463,10 +476,7 @@ void AssertHelper::operator=(const Message& message) const {
   UnitTest::GetInstance()->AddTestPartResult(
       data_->type, data_->file, data_->line,
       AppendUserMessage(data_->message, message),
-      // Suppress emission of the stack trace for GTEST_SKIP() since skipping is
-      // an intentional act by the developer rather than a failure requiring
-      // investigation.
-      data_->type != TestPartResult::kSkip
+      ShouldEmitStackTraceForResultType(data_->type)
           ? UnitTest::GetInstance()->impl()->CurrentOsStackTraceExceptTop(1)
           : ""
       // Skips the stack frame for this function itself.
@@ -526,7 +536,8 @@ void InsertSyntheticTestCase(const std::string& name, CodeLocation location,
   if (ignored.find(name) != ignored.end()) return;
 
   const char kMissingInstantiation[] =  //
-      " is defined via TEST_P, but never instantiated. None of the test cases "
+      " is defined via TEST_P, but never instantiated. None of the test "
+      "cases "
       "will run. Either no INSTANTIATE_TEST_SUITE_P is provided or the only "
       "ones provided expand to nothing."
       "\n\n"
@@ -567,7 +578,7 @@ void InsertSyntheticTestCase(const std::string& name, CodeLocation location,
 void RegisterTypeParameterizedTestSuite(const char* test_suite_name,
                                         CodeLocation code_location) {
   GetUnitTestImpl()->type_parameterized_test_registry().RegisterTestSuite(
-      test_suite_name, code_location);
+      test_suite_name, std::move(code_location));
 }
 
 void RegisterTypeParameterizedTestSuiteInstantiation(const char* case_name) {
@@ -578,7 +589,7 @@ void RegisterTypeParameterizedTestSuiteInstantiation(const char* case_name) {
 void TypeParameterizedTestSuiteRegistry::RegisterTestSuite(
     const char* test_suite_name, CodeLocation code_location) {
   suites_.emplace(std::string(test_suite_name),
-                  TypeParameterizedTestSuiteInfo(code_location));
+                  TypeParameterizedTestSuiteInfo(std::move(code_location)));
 }
 
 void TypeParameterizedTestSuiteRegistry::RegisterInstantiation(
@@ -605,10 +616,12 @@ void TypeParameterizedTestSuiteRegistry::CheckForInstantiations() {
         "\n\n"
         "Ideally, TYPED_TEST_P definitions should only ever be included as "
         "part of binaries that intend to use them. (As opposed to, for "
-        "example, being placed in a library that may be linked in to get other "
+        "example, being placed in a library that may be linked in to get "
+        "other "
         "utilities.)"
         "\n\n"
-        "To suppress this error for this test suite, insert the following line "
+        "To suppress this error for this test suite, insert the following "
+        "line "
         "(in a non-header) in the namespace it is defined in:"
         "\n\n"
         "GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(" +
@@ -648,11 +661,14 @@ static ::std::vector<std::string> g_argvs;
 FilePath GetCurrentExecutableName() {
   FilePath result;
 
+  auto args = GetArgvs();
+  if (!args.empty()) {
 #if defined(GTEST_OS_WINDOWS) || defined(GTEST_OS_OS2)
-  result.Set(FilePath(GetArgvs()[0]).RemoveExtension("exe"));
+    result.Set(FilePath(args[0]).RemoveExtension("exe"));
 #else
-  result.Set(FilePath(GetArgvs()[0]));
+    result.Set(FilePath(args[0]));
 #endif  // GTEST_OS_WINDOWS
+  }
 
   return result.RemoveDirectoryName();
 }
@@ -788,7 +804,7 @@ class UnitTestFilter {
   // Returns true if and only if name matches at least one of the patterns in
   // the filter.
   bool MatchesName(const std::string& name) const {
-    return exact_match_patterns_.count(name) > 0 ||
+    return exact_match_patterns_.find(name) != exact_match_patterns_.end() ||
            std::any_of(glob_patterns_.begin(), glob_patterns_.end(),
                        [&name](const std::string& pattern) {
                          return PatternMatchesString(
@@ -2327,7 +2343,7 @@ static const char* const kReservedTestCaseAttributes[] = {
     "type_param", "value_param", "file",   "line"};
 
 // Use a slightly different set for allowed output to ensure existing tests can
-// still RecordProperty("result") or "RecordProperty(timestamp")
+// still RecordProperty("result") or RecordProperty("timestamp")
 static const char* const kReservedOutputTestCaseAttributes[] = {
     "classname",   "name", "status", "time",   "type_param",
     "value_param", "file", "line",   "result", "timestamp"};
@@ -2727,18 +2743,16 @@ bool Test::IsSkipped() {
 
 // Constructs a TestInfo object. It assumes ownership of the test factory
 // object.
-TestInfo::TestInfo(const std::string& a_test_suite_name,
-                   const std::string& a_name, const char* a_type_param,
-                   const char* a_value_param,
+TestInfo::TestInfo(std::string a_test_suite_name, std::string a_name,
+                   const char* a_type_param, const char* a_value_param,
                    internal::CodeLocation a_code_location,
                    internal::TypeId fixture_class_id,
                    internal::TestFactoryBase* factory)
-    : test_suite_name_(a_test_suite_name),
-      // begin()/end() is MSVC 17.3.3 ASAN crash workaround (GitHub issue #3997)
-      name_(a_name.begin(), a_name.end()),
+    : test_suite_name_(std::move(a_test_suite_name)),
+      name_(std::move(a_name)),
       type_param_(a_type_param ? new std::string(a_type_param) : nullptr),
       value_param_(a_value_param ? new std::string(a_value_param) : nullptr),
-      location_(a_code_location),
+      location_(std::move(a_code_location)),
       fixture_class_id_(fixture_class_id),
       should_run_(false),
       is_disabled_(false),
@@ -2771,19 +2785,19 @@ namespace internal {
 //                     The newly created TestInfo instance will assume
 //                     ownership of the factory object.
 TestInfo* MakeAndRegisterTestInfo(
-    const char* test_suite_name, const char* name, const char* type_param,
+    std::string test_suite_name, const char* name, const char* type_param,
     const char* value_param, CodeLocation code_location,
     TypeId fixture_class_id, SetUpTestSuiteFunc set_up_tc,
     TearDownTestSuiteFunc tear_down_tc, TestFactoryBase* factory) {
   TestInfo* const test_info =
-      new TestInfo(test_suite_name, name, type_param, value_param,
-                   code_location, fixture_class_id, factory);
+      new TestInfo(std::move(test_suite_name), name, type_param, value_param,
+                   std::move(code_location), fixture_class_id, factory);
   GetUnitTestImpl()->AddTestInfo(set_up_tc, tear_down_tc, test_info);
   return test_info;
 }
 
 void ReportInvalidTestSuiteType(const char* test_suite_name,
-                                CodeLocation code_location) {
+                                const CodeLocation& code_location) {
   Message errors;
   errors
       << "Attempted redefinition of test suite " << test_suite_name << ".\n"
@@ -2823,14 +2837,13 @@ void TestInfo::Run() {
   }
 
   // Tells UnitTest where to store test result.
-  internal::UnitTestImpl* const impl = internal::GetUnitTestImpl();
-  impl->set_current_test_info(this);
+  UnitTest::GetInstance()->set_current_test_info(this);
 
   // Notifies the unit test event listeners that a test is about to start.
   repeater->OnTestStart(*this);
   result_.set_start_timestamp(internal::GetTimeInMillis());
   internal::Timer timer;
-  impl->os_stack_trace_getter()->UponLeavingGTest();
+  UnitTest::GetInstance()->UponLeavingGTest();
 
   // Creates the test object.
   Test* const test = internal::HandleExceptionsInMethodIfSupported(
@@ -2848,7 +2861,7 @@ void TestInfo::Run() {
 
   if (test != nullptr) {
     // Deletes the test object.
-    impl->os_stack_trace_getter()->UponLeavingGTest();
+    UnitTest::GetInstance()->UponLeavingGTest();
     internal::HandleExceptionsInMethodIfSupported(
         test, &Test::DeleteSelf_, "the test fixture's destructor");
   }
@@ -2860,15 +2873,14 @@ void TestInfo::Run() {
 
   // Tells UnitTest to stop associating assertion results to this
   // test.
-  impl->set_current_test_info(nullptr);
+  UnitTest::GetInstance()->set_current_test_info(nullptr);
 }
 
 // Skip and records a skipped test result for this object.
 void TestInfo::Skip() {
   if (!should_run_) return;
 
-  internal::UnitTestImpl* const impl = internal::GetUnitTestImpl();
-  impl->set_current_test_info(this);
+  UnitTest::GetInstance()->set_current_test_info(this);
 
   TestEventListener* repeater = UnitTest::GetInstance()->listeners().repeater();
 
@@ -2877,12 +2889,13 @@ void TestInfo::Skip() {
 
   const TestPartResult test_part_result =
       TestPartResult(TestPartResult::kSkip, this->file(), this->line(), "");
-  impl->GetTestPartResultReporterForCurrentThread()->ReportTestPartResult(
-      test_part_result);
+  internal::GetUnitTestImpl()
+      ->GetTestPartResultReporterForCurrentThread()
+      ->ReportTestPartResult(test_part_result);
 
   // Notifies the unit test event listener that a test has just finished.
   repeater->OnTestEnd(*this);
-  impl->set_current_test_info(nullptr);
+  UnitTest::GetInstance()->set_current_test_info(nullptr);
 }
 
 // class TestSuite
@@ -2936,7 +2949,7 @@ int TestSuite::total_test_count() const {
 //                 this is not a typed or a type-parameterized test suite.
 //   set_up_tc:    pointer to the function that sets up the test suite
 //   tear_down_tc: pointer to the function that tears down the test suite
-TestSuite::TestSuite(const char* a_name, const char* a_type_param,
+TestSuite::TestSuite(const std::string& a_name, const char* a_type_param,
                      internal::SetUpTestSuiteFunc set_up_tc,
                      internal::TearDownTestSuiteFunc tear_down_tc)
     : name_(a_name),
@@ -2978,8 +2991,7 @@ void TestSuite::AddTestInfo(TestInfo* test_info) {
 void TestSuite::Run() {
   if (!should_run_) return;
 
-  internal::UnitTestImpl* const impl = internal::GetUnitTestImpl();
-  impl->set_current_test_suite(this);
+  UnitTest::GetInstance()->set_current_test_suite(this);
 
   TestEventListener* repeater = UnitTest::GetInstance()->listeners().repeater();
 
@@ -3009,7 +3021,7 @@ void TestSuite::Run() {
   repeater->OnTestCaseStart(*this);
 #endif  //  GTEST_REMOVE_LEGACY_TEST_CASEAPI_
 
-  impl->os_stack_trace_getter()->UponLeavingGTest();
+  UnitTest::GetInstance()->UponLeavingGTest();
   internal::HandleExceptionsInMethodIfSupported(
       this, &TestSuite::RunSetUpTestSuite, "SetUpTestSuite()");
 
@@ -3034,7 +3046,7 @@ void TestSuite::Run() {
   }
   elapsed_time_ = timer.Elapsed();
 
-  impl->os_stack_trace_getter()->UponLeavingGTest();
+  UnitTest::GetInstance()->UponLeavingGTest();
   internal::HandleExceptionsInMethodIfSupported(
       this, &TestSuite::RunTearDownTestSuite, "TearDownTestSuite()");
 
@@ -3045,15 +3057,14 @@ void TestSuite::Run() {
   repeater->OnTestCaseEnd(*this);
 #endif  //  GTEST_REMOVE_LEGACY_TEST_CASEAPI_
 
-  impl->set_current_test_suite(nullptr);
+  UnitTest::GetInstance()->set_current_test_suite(nullptr);
 }
 
 // Skips all tests under this TestSuite.
 void TestSuite::Skip() {
   if (!should_run_) return;
 
-  internal::UnitTestImpl* const impl = internal::GetUnitTestImpl();
-  impl->set_current_test_suite(this);
+  UnitTest::GetInstance()->set_current_test_suite(this);
 
   TestEventListener* repeater = UnitTest::GetInstance()->listeners().repeater();
 
@@ -3075,7 +3086,7 @@ void TestSuite::Skip() {
   repeater->OnTestCaseEnd(*this);
 #endif  //  GTEST_REMOVE_LEGACY_TEST_CASEAPI_
 
-  impl->set_current_test_suite(nullptr);
+  UnitTest::GetInstance()->set_current_test_suite(nullptr);
 }
 
 // Clears the results of all tests in this test suite.
@@ -3176,9 +3187,9 @@ static void PrintTestPartResult(const TestPartResult& test_part_result) {
 }
 
 // class PrettyUnitTestResultPrinter
-#if defined(GTEST_OS_WINDOWS) && !defined(GTEST_OS_WINDOWS_MOBILE) &&    \
-    !defined(GTEST_OS_WINDOWS_PHONE) && !defined(GTEST_OS_WINDOWS_RT) && \
-    !defined(GTEST_OS_WINDOWS_MINGW)
+#if defined(GTEST_OS_WINDOWS) && !defined(GTEST_OS_WINDOWS_MOBILE) &&       \
+    !defined(GTEST_OS_WINDOWS_GAMES) && !defined(GTEST_OS_WINDOWS_PHONE) && \
+    !defined(GTEST_OS_WINDOWS_RT) && !defined(GTEST_OS_WINDOWS_MINGW)
 
 // Returns the character attribute for the given color.
 static WORD GetColorAttribute(GTestColor color) {
@@ -3262,6 +3273,7 @@ bool ShouldUseColor(bool stdout_is_tty) {
         term != nullptr && (String::CStringEquals(term, "xterm") ||
                             String::CStringEquals(term, "xterm-color") ||
                             String::CStringEquals(term, "xterm-kitty") ||
+                            String::CStringEquals(term, "alacritty") ||
                             String::CStringEquals(term, "screen") ||
                             String::CStringEquals(term, "tmux") ||
                             String::CStringEquals(term, "rxvt-unicode") ||
@@ -3304,9 +3316,9 @@ static void ColoredPrintf(GTestColor color, const char* fmt, ...) {
     return;
   }
 
-#if defined(GTEST_OS_WINDOWS) && !defined(GTEST_OS_WINDOWS_MOBILE) &&    \
-    !defined(GTEST_OS_WINDOWS_PHONE) && !defined(GTEST_OS_WINDOWS_RT) && \
-    !defined(GTEST_OS_WINDOWS_MINGW)
+#if defined(GTEST_OS_WINDOWS) && !defined(GTEST_OS_WINDOWS_MOBILE) &&       \
+    !defined(GTEST_OS_WINDOWS_GAMES) && !defined(GTEST_OS_WINDOWS_PHONE) && \
+    !defined(GTEST_OS_WINDOWS_RT) && !defined(GTEST_OS_WINDOWS_MINGW)
   const HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
 
   // Gets the current text color.
@@ -4429,8 +4441,8 @@ std::string XmlUnitTestResultPrinter::TestPropertiesAsXmlAttributes(
   Message attributes;
   for (int i = 0; i < result.test_property_count(); ++i) {
     const TestProperty& property = result.GetTestProperty(i);
-    attributes << " " << property.key() << "="
-               << "\"" << EscapeXmlAttribute(property.value()) << "\"";
+    attributes << " " << property.key() << "=" << "\""
+               << EscapeXmlAttribute(property.value()) << "\"";
   }
   return attributes.GetString();
 }
@@ -4734,28 +4746,53 @@ void JsonUnitTestResultPrinter::OutputJsonTestResult(::std::ostream* stream,
                                                      const TestResult& result) {
   const std::string kIndent = Indent(10);
 
-  int failures = 0;
-  for (int i = 0; i < result.total_part_count(); ++i) {
-    const TestPartResult& part = result.GetTestPartResult(i);
-    if (part.failed()) {
-      *stream << ",\n";
-      if (++failures == 1) {
-        *stream << kIndent << "\""
-                << "failures"
-                << "\": [\n";
+  {
+    int failures = 0;
+    for (int i = 0; i < result.total_part_count(); ++i) {
+      const TestPartResult& part = result.GetTestPartResult(i);
+      if (part.failed()) {
+        *stream << ",\n";
+        if (++failures == 1) {
+          *stream << kIndent << "\"" << "failures" << "\": [\n";
+        }
+        const std::string location =
+            internal::FormatCompilerIndependentFileLocation(part.file_name(),
+                                                            part.line_number());
+        const std::string message =
+            EscapeJson(location + "\n" + part.message());
+        *stream << kIndent << "  {\n"
+                << kIndent << "    \"failure\": \"" << message << "\",\n"
+                << kIndent << "    \"type\": \"\"\n"
+                << kIndent << "  }";
+      }
+    }
+
+    if (failures > 0) *stream << "\n" << kIndent << "]";
+  }
+
+  {
+    int skipped = 0;
+    for (int i = 0; i < result.total_part_count(); ++i) {
+      const TestPartResult& part = result.GetTestPartResult(i);
+      if (part.skipped()) {
+        *stream << ",\n";
+        if (++skipped == 1) {
+          *stream << kIndent << "\"" << "skipped" << "\": [\n";
+        }
+        const std::string location =
+            internal::FormatCompilerIndependentFileLocation(part.file_name(),
+                                                            part.line_number());
+        const std::string message =
+            EscapeJson(location + "\n" + part.message());
+        *stream << kIndent << "  {\n"
+                << kIndent << "    \"message\": \"" << message << "\"\n"
+                << kIndent << "  }";
       }
-      const std::string location =
-          internal::FormatCompilerIndependentFileLocation(part.file_name(),
-                                                          part.line_number());
-      const std::string message = EscapeJson(location + "\n" + part.message());
-      *stream << kIndent << "  {\n"
-              << kIndent << "    \"failure\": \"" << message << "\",\n"
-              << kIndent << "    \"type\": \"\"\n"
-              << kIndent << "  }";
     }
+
+    if (skipped > 0) *stream << "\n" << kIndent << "]";
   }
 
-  if (failures > 0) *stream << "\n" << kIndent << "]";
   *stream << "\n" << Indent(8) << "}";
 }
 
@@ -4892,8 +4929,8 @@ std::string JsonUnitTestResultPrinter::TestPropertiesAsJson(
   for (int i = 0; i < result.test_property_count(); ++i) {
     const TestProperty& property = result.GetTestProperty(i);
     attributes << ",\n"
-               << indent << "\"" << property.key() << "\": "
-               << "\"" << EscapeJson(property.value()) << "\"";
+               << indent << "\"" << property.key() << "\": " << "\""
+               << EscapeJson(property.value()) << "\"";
   }
   return attributes.GetString();
 }
@@ -5291,6 +5328,22 @@ TestSuite* UnitTest::GetMutableTestSuite(int i) {
   return impl()->GetMutableSuiteCase(i);
 }
 
+void UnitTest::UponLeavingGTest() {
+  impl()->os_stack_trace_getter()->UponLeavingGTest();
+}
+
+// Sets the TestSuite object for the test that's currently running.
+void UnitTest::set_current_test_suite(TestSuite* a_current_test_suite) {
+  internal::MutexLock lock(&mutex_);
+  impl_->set_current_test_suite(a_current_test_suite);
+}
+
+// Sets the TestInfo object for the test that's currently running.
+void UnitTest::set_current_test_info(TestInfo* a_current_test_info) {
+  internal::MutexLock lock(&mutex_);
+  impl_->set_current_test_info(a_current_test_info);
+}
+
 // Returns the list of event listeners that can be used to track events
 // inside Google Test.
 TestEventListeners& UnitTest::listeners() { return *impl()->listeners(); }
@@ -5451,7 +5504,7 @@ int UnitTest::Run() {
   // about crashes - they are expected.
   if (impl()->catch_exceptions() || in_death_test_child_process) {
 #if !defined(GTEST_OS_WINDOWS_MOBILE) && !defined(GTEST_OS_WINDOWS_PHONE) && \
-    !defined(GTEST_OS_WINDOWS_RT)
+    !defined(GTEST_OS_WINDOWS_RT) && !defined(GTEST_OS_WINDOWS_GAMES)
     // SetErrorMode doesn't exist on CE.
     SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT |
                  SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
@@ -5721,29 +5774,6 @@ void UnitTestImpl::PostFlagParsingInit() {
   }
 }
 
-// A predicate that checks the name of a TestSuite against a known
-// value.
-//
-// This is used for implementation of the UnitTest class only.  We put
-// it in the anonymous namespace to prevent polluting the outer
-// namespace.
-//
-// TestSuiteNameIs is copyable.
-class TestSuiteNameIs {
- public:
-  // Constructor.
-  explicit TestSuiteNameIs(const std::string& name) : name_(name) {}
-
-  // Returns true if and only if the name of test_suite matches name_.
-  bool operator()(const TestSuite* test_suite) const {
-    return test_suite != nullptr &&
-           strcmp(test_suite->name(), name_.c_str()) == 0;
-  }
-
- private:
-  std::string name_;
-};
-
 // Finds and returns a TestSuite with the given name.  If one doesn't
 // exist, creates one and returns it.  It's the CALLER'S
 // RESPONSIBILITY to ensure that this function is only called WHEN THE
@@ -5757,19 +5787,27 @@ class TestSuiteNameIs {
 //   set_up_tc:       pointer to the function that sets up the test suite
 //   tear_down_tc:    pointer to the function that tears down the test suite
 TestSuite* UnitTestImpl::GetTestSuite(
-    const char* test_suite_name, const char* type_param,
+    const std::string& test_suite_name, const char* type_param,
     internal::SetUpTestSuiteFunc set_up_tc,
     internal::TearDownTestSuiteFunc tear_down_tc) {
-  // Can we find a TestSuite with the given name?
-  const auto test_suite =
-      std::find_if(test_suites_.rbegin(), test_suites_.rend(),
-                   TestSuiteNameIs(test_suite_name));
+  // During initialization, all TestInfos for a given suite are added in
+  // sequence. To optimize this case, see if the most recently added suite is
+  // the one being requested now.
+  if (!test_suites_.empty() &&
+      (*test_suites_.rbegin())->name_ == test_suite_name) {
+    return *test_suites_.rbegin();
+  }
 
-  if (test_suite != test_suites_.rend()) return *test_suite;
+  // Fall back to searching the collection.
+  auto item_it = test_suites_by_name_.find(test_suite_name);
+  if (item_it != test_suites_by_name_.end()) {
+    return item_it->second;
+  }
 
-  // No.  Let's create one.
+  // Not found. Create a new instance.
   auto* const new_test_suite =
       new TestSuite(test_suite_name, type_param, set_up_tc, tear_down_tc);
+  test_suites_by_name_.emplace(test_suite_name, new_test_suite);
 
   const UnitTestFilter death_test_suite_filter(kDeathTestSuiteFilter);
   // Is this a death test suite?
@@ -5982,6 +6020,12 @@ bool UnitTestImpl::RunAllTests() {
   }
 
   repeater->OnTestProgramEnd(*parent_);
+  // Destroy environments in normal code, not in static teardown.
+  bool delete_environment_on_teardown = true;
+  if (delete_environment_on_teardown) {
+    ForEach(environments_, internal::Delete<Environment>);
+    environments_.clear();
+  }
 
   if (!gtest_is_initialized_before_run_all_tests) {
     ColoredPrintf(
@@ -6115,12 +6159,11 @@ int UnitTestImpl::FilterTests(ReactionToSharding shard_tests) {
   int num_runnable_tests = 0;
   int num_selected_tests = 0;
   for (auto* test_suite : test_suites_) {
-    const std::string& test_suite_name = test_suite->name();
+    const std::string& test_suite_name = test_suite->name_;
     test_suite->set_should_run(false);
 
-    for (size_t j = 0; j < test_suite->test_info_list().size(); j++) {
-      TestInfo* const test_info = test_suite->test_info_list()[j];
-      const std::string test_name(test_info->name());
+    for (TestInfo* test_info : test_suite->test_info_list()) {
+      const std::string& test_name = test_info->name_;
       // A test is disabled if test suite name or test name matches
       // kDisableTestFilter.
       const bool is_disabled =
@@ -6661,17 +6704,17 @@ void ParseGoogleTestFlagsOnlyImpl(int* argc, CharType** argv) {
     }
 
     if (remove_flag) {
-      // Shift the remainder of the argv list left by one.  Note
-      // that argv has (*argc + 1) elements, the last one always being
-      // NULL.  The following loop moves the trailing NULL element as
-      // well.
-      for (int j = i; j != *argc; j++) {
-        argv[j] = argv[j + 1];
+      // Shift the remainder of the argv list left by one.
+      for (int j = i + 1; j < *argc; ++j) {
+        argv[j - 1] = argv[j];
       }
 
       // Decrements the argument count.
       (*argc)--;
 
+      // Terminate the array with nullptr.
+      argv[*argc] = nullptr;
+
       // We also need to decrement the iterator as we just removed
       // an element.
       i--;
diff --git a/googletest/test/Android.bp b/googletest/test/Android.bp
index 4b000128..7edb3216 100644
--- a/googletest/test/Android.bp
+++ b/googletest/test/Android.bp
@@ -36,7 +36,6 @@ cc_defaults {
     include_dirs: ["external/googletest/googletest"],
     static_libs: ["libgtest"],
     relative_install_path: "gtest_tests",
-    no_named_install_directory: true,
 }
 
 cc_defaults {
@@ -57,44 +56,104 @@ cc_defaults {
     stl: "c++_static",
 }
 
-cc_test {
-    name: "gtest_tests",
-    defaults: ["gtest_test_defaults"],
-    test_per_src: true,
+cc_defaults {
+    name: "gtest_all_test_defaults",
     srcs: [
-        "googletest-death-test-test.cc",
-        "googletest-filepath-test.cc",
+        "gtest-*.cc",
+        "googletest-*.cc",
+    ],
+    exclude_srcs: [
+        "gtest-unittest-api_test.cc",
+        "googletest/src/gtest-all.cc",
+        "gtest_all_test.cc",
+        "gtest-death-test_ex_test.cc",
+        "gtest-listener_test.cc",
+        "gtest-unittest-api_test.cc",
+        "googletest-param-test-test.cc",
+        "googletest-param-test2-test.cc",
+        "googletest-catch-exceptions-test_.cc",
+        "googletest-color-test_.cc",
+        "googletest-env-var-test_.cc",
+        "googletest-failfast-unittest_.cc",
+        "googletest-filter-unittest_.cc",
+        "googletest-global-environment-unittest_.cc",
+        "googletest-break-on-failure-unittest_.cc",
         "googletest-listener-test.cc",
         "googletest-message-test.cc",
-        "googletest-options-test.cc",
-        "googletest-port-test.cc",
-        "googletest-printers-test.cc",
-        "googletest-test-part-test.cc",
-        "gtest-unittest-api_test.cc",
-        "gtest_main_unittest.cc",
-        "gtest_pred_impl_unittest.cc",
-        "gtest_skip_test.cc",
-        "gtest_sole_header_test.cc",
-        "gtest_unittest.cc",
+        "googletest-output-test_.cc",
+        "googletest-list-tests-unittest_.cc",
+        "googletest-shuffle-test_.cc",
+        "googletest-setuptestsuite-test_.cc",
+        "googletest-uninitialized-test_.cc",
+        "googletest-death-test_ex_test.cc",
+        "googletest-param-test-test",
+        "googletest-throw-on-failure-test_.cc",
+        "googletest-param-test-invalid-name1-test_.cc",
+        "googletest-param-test-invalid-name2-test_.cc",
+    ],
+    cflags: ["-DGTEST_USE_OWN_TR1_TUPLE=1"],
+}
+
+cc_test {
+    name: "gtest_all_test",
+    defaults: [
+        "gtest_test_defaults",
+        "gtest_all_test_defaults",
     ],
     static_libs: ["libgtest_main"],
 }
 
 cc_test {
-    name: "gtest_tests_no_main",
-    defaults: ["gtest_test_defaults"],
-    test_per_src: true,
-    srcs: [
-        "gtest_environment_test.cc",
-        "gtest_no_test_unittest.cc",
-        "gtest_premature_exit_test.cc",
-        "gtest_repeat_test.cc",
-        "gtest_stress_test.cc",
-
-        // Tests are disabled because Android doesn't build gtest with exceptions
-        // "gtest_throw_on_failure_ex_test.cc",
-        // "gtest_assert_by_exception_test.cc",
+    name: "gtest_all_test_ndk",
+    defaults: [
+        "gtest_ndk_test_defaults",
+        "gtest_all_test_defaults",
     ],
+    static_libs: ["libgtest_main_ndk_c++"],
+}
+
+// Tests death tests.
+cc_test {
+    name: "googletest-death-test-test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["googletest-death-test-test.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_test_macro_stack_footprint_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_test_macro_stack_footprint_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+//These googletest tests have their own main()
+cc_test {
+    name: "googletest-listener-test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["googletest-listener-test.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "googletest-listener-test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["googletest-listener-test.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest-unittest-api_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest-unittest-api_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "gtest-unittest-api_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest-unittest-api_test.cc"],
+    static_libs: ["libgtest_ndk_c++"],
 }
 
 cc_test {
@@ -104,6 +163,30 @@ cc_test {
         "googletest-param-test-test.cc",
         "googletest-param-test2-test.cc",
     ],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "googletest-param-test-test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: [
+        "googletest-param-test-test.cc",
+        "googletest-param-test2-test.cc",
+    ],
+}
+
+cc_test {
+    name: "gtest_unittest",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_unittest.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_unittest_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_unittest.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
 }
 
 cc_test {
@@ -116,6 +199,16 @@ cc_test {
     static_libs: ["libgtest_main"],
 }
 
+cc_test {
+    name: "gtest-typed-test_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: [
+        "gtest-typed-test_test.cc",
+        "gtest-typed-test2_test.cc",
+    ],
+    static_libs: ["libgtest_main_ndk_c++"],
+}
+
 cc_test {
     name: "gtest_prod_test",
     defaults: ["gtest_test_defaults"],
@@ -127,70 +220,151 @@ cc_test {
 }
 
 cc_test {
-    name: "gtest_ndk_tests",
+    name: "gtest_prod_test_ndk",
     defaults: ["gtest_ndk_test_defaults"],
-    test_per_src: true,
     srcs: [
-        "googletest-death-test-test.cc",
-        "googletest-filepath-test.cc",
-        "googletest-listener-test.cc",
-        "googletest-message-test.cc",
-        "googletest-options-test.cc",
-        "googletest-port-test.cc",
-        "googletest-printers-test.cc",
-        "googletest-test-part-test.cc",
-        "gtest-unittest-api_test.cc",
-        "gtest_main_unittest.cc",
-        "gtest_pred_impl_unittest.cc",
-        "gtest_skip_test.cc",
-        "gtest_sole_header_test.cc",
-        "gtest_unittest.cc",
+        "gtest_prod_test.cc",
+        "production.cc",
     ],
     static_libs: ["libgtest_main_ndk_c++"],
 }
 
 cc_test {
-    name: "gtest_ndk_tests_no_main",
+    name: "gtest_skip_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_skip_test.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_skip_test_ndk",
     defaults: ["gtest_ndk_test_defaults"],
-    test_per_src: true,
-    srcs: [
-        "gtest_environment_test.cc",
-        "gtest_no_test_unittest.cc",
-        "gtest_premature_exit_test.cc",
-        "gtest_repeat_test.cc",
-        "gtest_stress_test.cc",
-
-        // Tests are disabled because Android doesn't build gtest with exceptions
-        // "gtest_throw_on_failure_ex_test.cc",
-        // "gtest_assert_by_exception_test.cc",
-    ],
+    srcs: ["gtest_skip_test.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
 }
 
 cc_test {
-    name: "googletest-param-test-test_ndk",
+    name: "gtest_skip_in_environment_setup_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_skip_in_environment_setup_test.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_skip_in_environment_setup_test_ndk",
     defaults: ["gtest_ndk_test_defaults"],
-    srcs: [
-        "googletest-param-test-test.cc",
-        "googletest-param-test2-test.cc",
-    ],
+    srcs: ["gtest_skip_in_environment_setup_test.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
 }
 
 cc_test {
-    name: "gtest-typed-test_test_ndk",
+    name: "gtest_no_test_unittest",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_no_test_unittest.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_no_test_unittest_ndk",
     defaults: ["gtest_ndk_test_defaults"],
-    srcs: [
-        "gtest-typed-test_test.cc",
-        "gtest-typed-test2_test.cc",
-    ],
+    srcs: ["gtest_no_test_unittest.cc"],
     static_libs: ["libgtest_main_ndk_c++"],
 }
 
 cc_test {
-    name: "gtest_prod_test_ndk",
+    name: "gtest_environment_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_environment_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "gtest_environment_test_ndk",
     defaults: ["gtest_ndk_test_defaults"],
-    srcs: [
-        "gtest_prod_test.cc",
-        "production.cc",
-    ],
+    srcs: ["gtest_environment_test.cc"],
+    static_libs: ["libgtest_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_premature_exit_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_premature_exit_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "gtest_premature_exit_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_premature_exit_test.cc"],
+    static_libs: ["libgtest_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_repeat_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_repeat_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "gtest_repeat_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_repeat_test.cc"],
+    static_libs: ["libgtest_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_stress_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_stress_test.cc"],
+    static_libs: ["libgtest"],
+}
+
+cc_test {
+    name: "gtest_stress_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_stress_test.cc"],
+    static_libs: ["libgtest_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_main_unittest",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_main_unittest.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_main_unittest_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_main_unittest.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_pred_impl_unittest",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_pred_impl_unittest.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_pred_impl_unittest_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_pred_impl_unittest.cc"],
+    static_libs: ["libgtest_main_ndk_c++"],
+}
+
+cc_test {
+    name: "gtest_sole_header_test",
+    defaults: ["gtest_test_defaults"],
+    srcs: ["gtest_sole_header_test.cc"],
+    static_libs: ["libgtest_main"],
+}
+
+cc_test {
+    name: "gtest_sole_header_test_ndk",
+    defaults: ["gtest_ndk_test_defaults"],
+    srcs: ["gtest_sole_header_test.cc"],
     static_libs: ["libgtest_main_ndk_c++"],
 }
diff --git a/googletest/test/googletest-color-test.py b/googletest/test/googletest-color-test.py
index 8926a481..8968cf1f 100755
--- a/googletest/test/googletest-color-test.py
+++ b/googletest/test/googletest-color-test.py
@@ -80,6 +80,7 @@ class GTestColorTest(gtest_test_utils.TestCase):
     self.assertTrue(UsesColor('xterm', None, None))
     self.assertTrue(UsesColor('xterm-color', None, None))
     self.assertTrue(UsesColor('xterm-kitty', None, None))
+    self.assertTrue(UsesColor('alacritty', None, None))
     self.assertTrue(UsesColor('xterm-256color', None, None))
 
   def testFlagOnly(self):
diff --git a/googletest/test/googletest-death-test-test.cc b/googletest/test/googletest-death-test-test.cc
index 4cc81b72..44b80464 100644
--- a/googletest/test/googletest-death-test-test.cc
+++ b/googletest/test/googletest-death-test-test.cc
@@ -30,6 +30,8 @@
 //
 // Tests for death tests.
 
+#include <stdlib.h>
+
 #include "gtest/gtest-death-test.h"
 #include "gtest/gtest.h"
 #include "gtest/internal/gtest-filepath.h"
@@ -111,15 +113,15 @@ void DieWithMessage(const ::std::string& message) {
   fprintf(stderr, "%s", message.c_str());
   fflush(stderr);  // Make sure the text is printed before the process exits.
 
-  // We call _exit() instead of exit(), as the former is a direct
+  // We call _Exit() instead of exit(), as the former is a direct
   // system call and thus safer in the presence of threads.  exit()
   // will invoke user-defined exit-hooks, which may do dangerous
   // things that conflict with death tests.
   //
-  // Some compilers can recognize that _exit() never returns and issue the
+  // Some compilers can recognize that _Exit() never returns and issue the
   // 'unreachable code' warning for code following this function, unless
   // fooled by a fake condition.
-  if (AlwaysTrue()) _exit(1);
+  if (AlwaysTrue()) _Exit(1);
 }
 
 void DieInside(const ::std::string& function) {
@@ -238,13 +240,13 @@ TEST(ExitStatusPredicateTest, ExitedWithCode) {
 
 #else
 
-// Returns the exit status of a process that calls _exit(2) with a
+// Returns the exit status of a process that calls _Exit(2) with a
 // given exit code.  This is a helper function for the
 // ExitStatusPredicateTest test suite.
 static int NormalExitStatus(int exit_code) {
   pid_t child_pid = fork();
   if (child_pid == 0) {
-    _exit(exit_code);
+    _Exit(exit_code);
   }
   int status;
   waitpid(child_pid, &status, 0);
@@ -260,7 +262,7 @@ static int KilledExitStatus(int signum) {
   pid_t child_pid = fork();
   if (child_pid == 0) {
     raise(signum);
-    _exit(1);
+    _Exit(1);
   }
   int status;
   waitpid(child_pid, &status, 0);
@@ -289,7 +291,9 @@ TEST(ExitStatusPredicateTest, KilledBySignal) {
   const int status_kill = KilledExitStatus(SIGKILL);
   const testing::KilledBySignal pred_segv(SIGSEGV);
   const testing::KilledBySignal pred_kill(SIGKILL);
+#if !(defined(GTEST_OS_LINUX_ANDROID) && __ANDROID_API__ <= 21)
   EXPECT_PRED1(pred_segv, status_segv);
+#endif
   EXPECT_PRED1(pred_kill, status_kill);
   EXPECT_FALSE(pred_segv(status_kill));
   EXPECT_FALSE(pred_kill(status_segv));
@@ -313,7 +317,7 @@ TEST_F(TestForDeathTest, SingleStatement) {
     ASSERT_DEATH(return, "");
 
   if (AlwaysTrue())
-    EXPECT_DEATH(_exit(1), "");
+    EXPECT_DEATH(_Exit(1), "");
   else
     // This empty "else" branch is meant to ensure that EXPECT_DEATH
     // doesn't expand into an "if" statement without an "else"
@@ -324,7 +328,7 @@ TEST_F(TestForDeathTest, SingleStatement) {
   if (AlwaysFalse())
     ;
   else
-    EXPECT_DEATH(_exit(1), "") << 1 << 2 << 3;
+    EXPECT_DEATH(_Exit(1), "") << 1 << 2 << 3;
 }
 #ifdef __GNUC__
 #pragma GCC diagnostic pop
@@ -339,11 +343,11 @@ TEST_F(TestForDeathTest, SwitchStatement) {
 
   switch (0)
   default:
-    ASSERT_DEATH(_exit(1), "") << "exit in default switch handler";
+    ASSERT_DEATH(_Exit(1), "") << "exit in default switch handler";
 
   switch (0)
   case 0:
-    EXPECT_DEATH(_exit(1), "") << "exit in switch case";
+    EXPECT_DEATH(_Exit(1), "") << "exit in switch case";
 
   GTEST_DISABLE_MSC_WARNINGS_POP_()
 }
@@ -371,10 +375,10 @@ TEST_F(TestForDeathTest, FastDeathTestInChangedDir) {
   GTEST_FLAG_SET(death_test_style, "fast");
 
   ChangeToRootDir();
-  EXPECT_EXIT(_exit(1), testing::ExitedWithCode(1), "");
+  EXPECT_EXIT(_Exit(1), testing::ExitedWithCode(1), "");
 
   ChangeToRootDir();
-  ASSERT_DEATH(_exit(1), "");
+  ASSERT_DEATH(_Exit(1), "");
 }
 
 #ifdef GTEST_OS_LINUX
@@ -416,7 +420,7 @@ void DisableSigprofActionAndTimer(struct sigaction* old_signal_action) {
 TEST_F(TestForDeathTest, FastSigprofActionSet) {
   GTEST_FLAG_SET(death_test_style, "fast");
   SetSigprofActionAndTimer();
-  EXPECT_DEATH(_exit(1), "");
+  EXPECT_DEATH(_Exit(1), "");
   struct sigaction old_signal_action;
   DisableSigprofActionAndTimer(&old_signal_action);
   EXPECT_TRUE(old_signal_action.sa_sigaction == SigprofAction);
@@ -425,7 +429,7 @@ TEST_F(TestForDeathTest, FastSigprofActionSet) {
 TEST_F(TestForDeathTest, ThreadSafeSigprofActionSet) {
   GTEST_FLAG_SET(death_test_style, "threadsafe");
   SetSigprofActionAndTimer();
-  EXPECT_DEATH(_exit(1), "");
+  EXPECT_DEATH(_Exit(1), "");
   struct sigaction old_signal_action;
   DisableSigprofActionAndTimer(&old_signal_action);
   EXPECT_TRUE(old_signal_action.sa_sigaction == SigprofAction);
@@ -449,24 +453,24 @@ TEST_F(TestForDeathTest, ThreadsafeDeathTestInLoop) {
   GTEST_FLAG_SET(death_test_style, "threadsafe");
 
   for (int i = 0; i < 3; ++i)
-    EXPECT_EXIT(_exit(i), testing::ExitedWithCode(i), "") << ": i = " << i;
+    EXPECT_EXIT(_Exit(i), testing::ExitedWithCode(i), "") << ": i = " << i;
 }
 
 TEST_F(TestForDeathTest, ThreadsafeDeathTestInChangedDir) {
   GTEST_FLAG_SET(death_test_style, "threadsafe");
 
   ChangeToRootDir();
-  EXPECT_EXIT(_exit(1), testing::ExitedWithCode(1), "");
+  EXPECT_EXIT(_Exit(1), testing::ExitedWithCode(1), "");
 
   ChangeToRootDir();
-  ASSERT_DEATH(_exit(1), "");
+  ASSERT_DEATH(_Exit(1), "");
 }
 
 TEST_F(TestForDeathTest, MixedStyles) {
   GTEST_FLAG_SET(death_test_style, "threadsafe");
-  EXPECT_DEATH(_exit(1), "");
+  EXPECT_DEATH(_Exit(1), "");
   GTEST_FLAG_SET(death_test_style, "fast");
-  EXPECT_DEATH(_exit(1), "");
+  EXPECT_DEATH(_Exit(1), "");
 }
 
 #if GTEST_HAS_CLONE && GTEST_HAS_PTHREAD
@@ -480,7 +484,7 @@ TEST_F(TestForDeathTest, DoesNotExecuteAtforkHooks) {
     GTEST_FLAG_SET(death_test_style, "threadsafe");
     pthread_flag = false;
     ASSERT_EQ(0, pthread_atfork(&SetPthreadFlag, nullptr, nullptr));
-    ASSERT_DEATH(_exit(1), "");
+    ASSERT_DEATH(_Exit(1), "");
     ASSERT_FALSE(pthread_flag);
   }
 }
@@ -805,8 +809,8 @@ TEST_F(TestForDeathTest, AssertDebugDeathAborts10) {
 
 // Tests the *_EXIT family of macros, using a variety of predicates.
 static void TestExitMacros() {
-  EXPECT_EXIT(_exit(1), testing::ExitedWithCode(1), "");
-  ASSERT_EXIT(_exit(42), testing::ExitedWithCode(42), "");
+  EXPECT_EXIT(_Exit(1), testing::ExitedWithCode(1), "");
+  ASSERT_EXIT(_Exit(42), testing::ExitedWithCode(42), "");
 
 #ifdef GTEST_OS_WINDOWS
 
@@ -823,7 +827,7 @@ static void TestExitMacros() {
 
   EXPECT_FATAL_FAILURE(
       {  // NOLINT
-        ASSERT_EXIT(_exit(0), testing::KilledBySignal(SIGSEGV), "")
+        ASSERT_EXIT(_Exit(0), testing::KilledBySignal(SIGSEGV), "")
             << "This failure is expected, too.";
       },
       "This failure is expected, too.");
@@ -849,7 +853,7 @@ TEST_F(TestForDeathTest, InvalidStyle) {
   GTEST_FLAG_SET(death_test_style, "rococo");
   EXPECT_NONFATAL_FAILURE(
       {  // NOLINT
-        EXPECT_DEATH(_exit(0), "") << "This failure is expected.";
+        EXPECT_DEATH(_Exit(0), "") << "This failure is expected.";
       },
       "This failure is expected.");
 }
@@ -1140,7 +1144,7 @@ TEST_F(MacroLogicDeathTest, ChildDoesNotDie) {
   // This time there are two calls to Abort: one since the test didn't
   // die, and another from the ReturnSentinel when it's destroyed.  The
   // sentinel normally isn't destroyed if a test doesn't die, since
-  // _exit(2) is called in that case by ForkingDeathTest, but not by
+  // _Exit(2) is called in that case by ForkingDeathTest, but not by
   // our MockDeathTest.
   ASSERT_EQ(2U, factory_->AbortCalls());
   EXPECT_EQ(DeathTest::TEST_DID_NOT_DIE, factory_->AbortArgument(0));
@@ -1152,21 +1156,21 @@ TEST_F(MacroLogicDeathTest, ChildDoesNotDie) {
 // Tests that a successful death test does not register a successful
 // test part.
 TEST(SuccessRegistrationDeathTest, NoSuccessPart) {
-  EXPECT_DEATH(_exit(1), "");
+  EXPECT_DEATH(_Exit(1), "");
   EXPECT_EQ(0, GetUnitTestImpl()->current_test_result()->total_part_count());
 }
 
 TEST(StreamingAssertionsDeathTest, DeathTest) {
-  EXPECT_DEATH(_exit(1), "") << "unexpected failure";
-  ASSERT_DEATH(_exit(1), "") << "unexpected failure";
+  EXPECT_DEATH(_Exit(1), "") << "unexpected failure";
+  ASSERT_DEATH(_Exit(1), "") << "unexpected failure";
   EXPECT_NONFATAL_FAILURE(
       {  // NOLINT
-        EXPECT_DEATH(_exit(0), "") << "expected failure";
+        EXPECT_DEATH(_Exit(0), "") << "expected failure";
       },
       "expected failure");
   EXPECT_FATAL_FAILURE(
       {  // NOLINT
-        ASSERT_DEATH(_exit(0), "") << "expected failure";
+        ASSERT_DEATH(_Exit(0), "") << "expected failure";
       },
       "expected failure");
 }
@@ -1330,7 +1334,7 @@ TEST(InDeathTestChildDeathTest, ReportsDeathTestCorrectlyInFastStyle) {
       {
         fprintf(stderr, InDeathTestChild() ? "Inside" : "Outside");
         fflush(stderr);
-        _exit(1);
+        _Exit(1);
       },
       "Inside");
 }
@@ -1342,7 +1346,7 @@ TEST(InDeathTestChildDeathTest, ReportsDeathTestCorrectlyInThreadSafeStyle) {
       {
         fprintf(stderr, InDeathTestChild() ? "Inside" : "Outside");
         fflush(stderr);
-        _exit(1);
+        _Exit(1);
       },
       "Inside");
 }
@@ -1350,7 +1354,7 @@ TEST(InDeathTestChildDeathTest, ReportsDeathTestCorrectlyInThreadSafeStyle) {
 void DieWithMessage(const char* message) {
   fputs(message, stderr);
   fflush(stderr);  // Make sure the text is printed before the process exits.
-  _exit(1);
+  _Exit(1);
 }
 
 TEST(MatcherDeathTest, DoesNotBreakBareRegexMatching) {
@@ -1466,7 +1470,7 @@ TEST(ConditionalDeathMacrosSyntaxDeathTest, SingleStatement) {
     ASSERT_DEATH_IF_SUPPORTED(return, "");
 
   if (AlwaysTrue())
-    EXPECT_DEATH_IF_SUPPORTED(_exit(1), "");
+    EXPECT_DEATH_IF_SUPPORTED(_Exit(1), "");
   else
     // This empty "else" branch is meant to ensure that EXPECT_DEATH
     // doesn't expand into an "if" statement without an "else"
@@ -1477,7 +1481,7 @@ TEST(ConditionalDeathMacrosSyntaxDeathTest, SingleStatement) {
   if (AlwaysFalse())
     ;  // NOLINT
   else
-    EXPECT_DEATH_IF_SUPPORTED(_exit(1), "") << 1 << 2 << 3;
+    EXPECT_DEATH_IF_SUPPORTED(_Exit(1), "") << 1 << 2 << 3;
 }
 #ifdef __GNUC__
 #pragma GCC diagnostic pop
@@ -1492,11 +1496,11 @@ TEST(ConditionalDeathMacrosSyntaxDeathTest, SwitchStatement) {
 
   switch (0)
   default:
-    ASSERT_DEATH_IF_SUPPORTED(_exit(1), "") << "exit in default switch handler";
+    ASSERT_DEATH_IF_SUPPORTED(_Exit(1), "") << "exit in default switch handler";
 
   switch (0)
   case 0:
-    EXPECT_DEATH_IF_SUPPORTED(_exit(1), "") << "exit in switch case";
+    EXPECT_DEATH_IF_SUPPORTED(_Exit(1), "") << "exit in switch case";
 
   GTEST_DISABLE_MSC_WARNINGS_POP_()
 }
diff --git a/googletest/test/googletest-json-output-unittest.py b/googletest/test/googletest-json-output-unittest.py
index cb976945..d3338e3d 100644
--- a/googletest/test/googletest-json-output-unittest.py
+++ b/googletest/test/googletest-json-output-unittest.py
@@ -150,6 +150,9 @@ EXPECTED_NON_EMPTY = {
                     'time': '*',
                     'timestamp': '*',
                     'classname': 'SkippedTest',
+                    'skipped': [
+                        {'message': 'gtest_xml_output_unittest_.cc:*\n\n'}
+                    ],
                 },
                 {
                     'name': 'SkippedWithMessage',
@@ -160,6 +163,12 @@ EXPECTED_NON_EMPTY = {
                     'time': '*',
                     'timestamp': '*',
                     'classname': 'SkippedTest',
+                    'skipped': [{
+                        'message': (
+                            'gtest_xml_output_unittest_.cc:*\n'
+                            'It is good practice to tell why you skip a test.\n'
+                        )
+                    }],
                 },
                 {
                     'name': 'SkippedAfterFailure',
@@ -179,6 +188,12 @@ EXPECTED_NON_EMPTY = {
                         ),
                         'type': '',
                     }],
+                    'skipped': [{
+                        'message': (
+                            'gtest_xml_output_unittest_.cc:*\n'
+                            'It is good practice to tell why you skip a test.\n'
+                        )
+                    }],
                 },
             ],
         },
diff --git a/googletest/test/googletest-options-test.cc b/googletest/test/googletest-options-test.cc
index 722c5b55..640082d2 100644
--- a/googletest/test/googletest-options-test.cc
+++ b/googletest/test/googletest-options-test.cc
@@ -115,16 +115,14 @@ TEST(OutputFileHelpersTest, GetCurrentExecutableName) {
       strcasecmp("gtest_dll_test", exe_str.c_str()) == 0;
 #elif defined(GTEST_OS_FUCHSIA)
   const bool success = exe_str == "app";
+#elif defined(__EMSCRIPTEN__)
+  const bool success = exe_str == "patched_googletest-options-test.js";
 #else
   const bool success =
-      exe_str == "googletest-options-test" ||
-      exe_str == "gtest_all_test" ||
-      exe_str == "lt-gtest_all_test" ||
-      exe_str == "gtest_dll_test"
+      exe_str == "googletest-options-test" || exe_str == "gtest_all_test" ||
+      exe_str == "lt-gtest_all_test" || exe_str == "gtest_dll_test"
 #ifdef __ANDROID__
-      || exe_str == "gtest-options_test_ndk_c++" ||
-      exe_str == "gtest-options_test_ndk_gnustl" ||
-      exe_str == "gtest-options_test_ndk_stlport"
+      || exe_str == "gtest_all_test_ndk"
 #endif
       ;
 #endif  // GTEST_OS_WINDOWS
diff --git a/googletest/test/googletest-output-test-golden-lin.txt b/googletest/test/googletest-output-test-golden-lin.txt
index e06856a2..533eb8c6 100644
--- a/googletest/test/googletest-output-test-golden-lin.txt
+++ b/googletest/test/googletest-output-test-golden-lin.txt
@@ -696,7 +696,6 @@ Expected: 1 fatal failure
   Actual:
 googletest-output-test_.cc:#: Success:
 Succeeded
-Stack trace: (omitted)
 
 
 Stack trace: (omitted)
@@ -733,7 +732,6 @@ Expected: 1 non-fatal failure
   Actual:
 googletest-output-test_.cc:#: Success:
 Succeeded
-Stack trace: (omitted)
 
 
 Stack trace: (omitted)
@@ -770,7 +768,6 @@ Expected: 1 fatal failure
   Actual:
 googletest-output-test_.cc:#: Success:
 Succeeded
-Stack trace: (omitted)
 
 
 Stack trace: (omitted)
@@ -807,7 +804,6 @@ Expected: 1 non-fatal failure
   Actual:
 googletest-output-test_.cc:#: Success:
 Succeeded
-Stack trace: (omitted)
 
 
 Stack trace: (omitted)
diff --git a/googletest/test/gtest_environment_test.cc b/googletest/test/gtest_environment_test.cc
index 122eaf3c..03657c7d 100644
--- a/googletest/test/gtest_environment_test.cc
+++ b/googletest/test/gtest_environment_test.cc
@@ -40,16 +40,21 @@ namespace {
 
 enum FailureType { NO_FAILURE, NON_FATAL_FAILURE, FATAL_FAILURE };
 
+// Was SetUp run?
+bool set_up_was_run;
+// Was TearDown run?
+bool tear_down_was_run;
+// Was the TEST run?
+bool test_was_run;
+
 // For testing using global test environments.
 class MyEnvironment : public testing::Environment {
  public:
-  MyEnvironment() { Reset(); }
-
   // Depending on the value of failure_in_set_up_, SetUp() will
   // generate a non-fatal failure, generate a fatal failure, or
   // succeed.
   void SetUp() override {
-    set_up_was_run_ = true;
+    set_up_was_run = true;
 
     switch (failure_in_set_up_) {
       case NON_FATAL_FAILURE:
@@ -65,36 +70,18 @@ class MyEnvironment : public testing::Environment {
 
   // Generates a non-fatal failure.
   void TearDown() override {
-    tear_down_was_run_ = true;
+    tear_down_was_run = true;
     ADD_FAILURE() << "Expected non-fatal failure in global tear-down.";
   }
 
-  // Resets the state of the environment s.t. it can be reused.
-  void Reset() {
-    failure_in_set_up_ = NO_FAILURE;
-    set_up_was_run_ = false;
-    tear_down_was_run_ = false;
-  }
-
   // We call this function to set the type of failure SetUp() should
   // generate.
   void set_failure_in_set_up(FailureType type) { failure_in_set_up_ = type; }
 
-  // Was SetUp() run?
-  bool set_up_was_run() const { return set_up_was_run_; }
-
-  // Was TearDown() run?
-  bool tear_down_was_run() const { return tear_down_was_run_; }
-
  private:
   FailureType failure_in_set_up_;
-  bool set_up_was_run_;
-  bool tear_down_was_run_;
 };
 
-// Was the TEST run?
-bool test_was_run;
-
 // The sole purpose of this TEST is to enable us to check whether it
 // was run.
 TEST(FooTest, Bar) { test_was_run = true; }
@@ -112,67 +99,88 @@ void Check(bool condition, const char* msg) {
 // The 'failure' parameter specifies the type of failure that should
 // be generated by the global set-up.
 int RunAllTests(MyEnvironment* env, FailureType failure) {
-  env->Reset();
-  env->set_failure_in_set_up(failure);
+  set_up_was_run = false;
+  tear_down_was_run = false;
   test_was_run = false;
+  env->set_failure_in_set_up(failure);
   testing::internal::GetUnitTestImpl()->ClearAdHocTestResult();
   return RUN_ALL_TESTS();
 }
 
-}  // namespace
-
-int main(int argc, char** argv) {
-  testing::InitGoogleTest(&argc, argv);
-
-  // Registers a global test environment, and verifies that the
-  // registration function returns its argument.
+// Registers a global test environment, and verifies that the
+// registration function returns its argument.
+MyEnvironment* RegisterTestEnv() {
   MyEnvironment* const env = new MyEnvironment;
   Check(testing::AddGlobalTestEnvironment(env) == env,
         "AddGlobalTestEnvironment() should return its argument.");
+  return env;
+}
 
-  // Verifies that RUN_ALL_TESTS() runs the tests when the global
-  // set-up is successful.
+// Verifies that RUN_ALL_TESTS() runs the tests when the global
+// set-up is successful.
+void TestGlobalSetUp() {
+  MyEnvironment* const env = RegisterTestEnv();
   Check(RunAllTests(env, NO_FAILURE) != 0,
         "RUN_ALL_TESTS() should return non-zero, as the global tear-down "
         "should generate a failure.");
   Check(test_was_run,
         "The tests should run, as the global set-up should generate no "
         "failure");
-  Check(env->tear_down_was_run(),
+  Check(tear_down_was_run,
         "The global tear-down should run, as the global set-up was run.");
+}
 
-  // Verifies that RUN_ALL_TESTS() runs the tests when the global
-  // set-up generates no fatal failure.
+// Verifies that RUN_ALL_TESTS() runs the tests when the global
+// set-up generates no fatal failure.
+void TestTestsRun() {
+  MyEnvironment* const env = RegisterTestEnv();
   Check(RunAllTests(env, NON_FATAL_FAILURE) != 0,
         "RUN_ALL_TESTS() should return non-zero, as both the global set-up "
         "and the global tear-down should generate a non-fatal failure.");
   Check(test_was_run,
         "The tests should run, as the global set-up should generate no "
         "fatal failure.");
-  Check(env->tear_down_was_run(),
+  Check(tear_down_was_run,
         "The global tear-down should run, as the global set-up was run.");
+}
 
-  // Verifies that RUN_ALL_TESTS() runs no test when the global set-up
-  // generates a fatal failure.
+// Verifies that RUN_ALL_TESTS() runs no test when the global set-up
+// generates a fatal failure.
+void TestNoTestsRunSetUpFailure() {
+  MyEnvironment* const env = RegisterTestEnv();
   Check(RunAllTests(env, FATAL_FAILURE) != 0,
         "RUN_ALL_TESTS() should return non-zero, as the global set-up "
         "should generate a fatal failure.");
   Check(!test_was_run,
         "The tests should not run, as the global set-up should generate "
         "a fatal failure.");
-  Check(env->tear_down_was_run(),
+  Check(tear_down_was_run,
         "The global tear-down should run, as the global set-up was run.");
+}
 
-  // Verifies that RUN_ALL_TESTS() doesn't do global set-up or
-  // tear-down when there is no test to run.
+// Verifies that RUN_ALL_TESTS() doesn't do global set-up or
+// tear-down when there is no test to run.
+void TestNoTestsSkipsSetUp() {
+  MyEnvironment* const env = RegisterTestEnv();
   GTEST_FLAG_SET(filter, "-*");
   Check(RunAllTests(env, NO_FAILURE) == 0,
         "RUN_ALL_TESTS() should return zero, as there is no test to run.");
-  Check(!env->set_up_was_run(),
+  Check(!set_up_was_run,
         "The global set-up should not run, as there is no test to run.");
-  Check(!env->tear_down_was_run(),
+  Check(!tear_down_was_run,
         "The global tear-down should not run, "
         "as the global set-up was not run.");
+}
+
+}  // namespace
+
+int main(int argc, char** argv) {
+  testing::InitGoogleTest(&argc, argv);
+
+  TestGlobalSetUp();
+  TestTestsRun();
+  TestNoTestsRunSetUpFailure();
+  TestNoTestsSkipsSetUp();
 
   printf("PASS\n");
   return 0;
diff --git a/googletest/test/gtest_json_test_utils.py b/googletest/test/gtest_json_test_utils.py
index 86a5925b..694a7a60 100644
--- a/googletest/test/gtest_json_test_utils.py
+++ b/googletest/test/gtest_json_test_utils.py
@@ -51,6 +51,9 @@ def normalize(obj):
     elif key == 'failure':
       value = re.sub(r'^.*[/\\](.*:)\d+\n', '\\1*\n', value)
       return re.sub(r'Stack trace:\n(.|\n)*', 'Stack trace:\n*', value)
+    elif key == 'message':
+      value = re.sub(r'^.*[/\\](.*:)\d+\n', '\\1*\n', value)
+      return re.sub(r'Stack trace:\n(.|\n)*', 'Stack trace:\n*', value)
     elif key == 'file':
       return re.sub(r'^.*[/\\](.*)', '\\1', value)
     else:
diff --git a/googletest/test/gtest_repeat_test.cc b/googletest/test/gtest_repeat_test.cc
index f67b7886..55103d0e 100644
--- a/googletest/test/gtest_repeat_test.cc
+++ b/googletest/test/gtest_repeat_test.cc
@@ -61,7 +61,6 @@ int g_environment_tear_down_count = 0;
 
 class MyEnvironment : public testing::Environment {
  public:
-  MyEnvironment() = default;
   void SetUp() override { g_environment_set_up_count++; }
   void TearDown() override { g_environment_tear_down_count++; }
 };
@@ -117,6 +116,7 @@ void ResetCounts() {
   g_should_pass_count = 0;
   g_death_test_count = 0;
   g_param_test_count = 0;
+  testing::AddGlobalTestEnvironment(new MyEnvironment);
 }
 
 // Checks that the count for each test is expected.
@@ -197,8 +197,6 @@ void TestRepeatWithFilterForFailedTests(int repeat) {
 int main(int argc, char **argv) {
   testing::InitGoogleTest(&argc, argv);
 
-  testing::AddGlobalTestEnvironment(new MyEnvironment);
-
   TestRepeatUnspecified();
   TestRepeat(0);
   TestRepeat(1);
diff --git a/googletest/test/gtest_unittest.cc b/googletest/test/gtest_unittest.cc
index 67d776ed..5ded8650 100644
--- a/googletest/test/gtest_unittest.cc
+++ b/googletest/test/gtest_unittest.cc
@@ -422,11 +422,14 @@ TEST(FormatTimeInMillisAsSecondsTest, FormatsNegativeNumber) {
   EXPECT_EQ("-1234567.89", FormatTimeInMillisAsSeconds(-1234567890));
 }
 
+// TODO: b/287046337 - In emscripten, local time zone modification is not
+// supported.
+#if !defined(__EMSCRIPTEN__)
 // Tests FormatEpochTimeInMillisAsIso8601().  The correctness of conversion
 // for particular dates below was verified in Python using
 // datetime.datetime.fromutctimestamp(<timestamp>/1000).
 
-// FormatEpochTimeInMillisAsIso8601 depends on the current timezone, so we
+// FormatEpochTimeInMillisAsIso8601 depends on the local timezone, so we
 // have to set up a particular timezone to obtain predictable results.
 class FormatEpochTimeInMillisAsIso8601Test : public Test {
  public:
@@ -445,9 +448,8 @@ class FormatEpochTimeInMillisAsIso8601Test : public Test {
     }
     GTEST_DISABLE_MSC_DEPRECATED_POP_()
 
-    // Set up the time zone for FormatEpochTimeInMillisAsIso8601 to use.  We
-    // cannot use the local time zone because the function's output depends
-    // on the time zone.
+    // Set the local time zone for FormatEpochTimeInMillisAsIso8601 to be
+    // a fixed time zone for reproducibility purposes.
     SetTimeZone("UTC+00");
   }
 
@@ -514,6 +516,8 @@ TEST_F(FormatEpochTimeInMillisAsIso8601Test, PrintsEpochStart) {
   EXPECT_EQ("1970-01-01T00:00:00.000", FormatEpochTimeInMillisAsIso8601(0));
 }
 
+#endif  // __EMSCRIPTEN__
+
 #ifdef __BORLANDC__
 // Silences warnings: "Condition is always true", "Unreachable code"
 #pragma option push -w-ccc -w-rch
@@ -2159,7 +2163,7 @@ class UnitTestRecordPropertyTestEnvironment : public Environment {
 };
 
 // This will test property recording outside of any test or test case.
-static Environment* record_property_env GTEST_ATTRIBUTE_UNUSED_ =
+GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static Environment* record_property_env =
     AddGlobalTestEnvironment(new UnitTestRecordPropertyTestEnvironment);
 
 // This group of tests is for predicate assertions (ASSERT_PRED*, etc)
@@ -4168,8 +4172,8 @@ TEST(AssertionSyntaxTest, ExceptionAssertionsBehavesLikeSingleStatement) {
 #endif
 TEST(AssertionSyntaxTest, NoFatalFailureAssertionsBehavesLikeSingleStatement) {
   if (AlwaysFalse())
-    EXPECT_NO_FATAL_FAILURE(FAIL()) << "This should never be executed. "
-                                    << "It's a compilation test only.";
+    EXPECT_NO_FATAL_FAILURE(FAIL())
+        << "This should never be executed. " << "It's a compilation test only.";
   else
     ;  // NOLINT
 
@@ -6667,6 +6671,9 @@ TEST(ColoredOutputTest, UsesColorsWhenTermSupportsColors) {
   SetEnv("TERM", "xterm-kitty");      // TERM supports colors.
   EXPECT_TRUE(ShouldUseColor(true));  // Stdout is a TTY.
 
+  SetEnv("TERM", "alacritty");        // TERM supports colors.
+  EXPECT_TRUE(ShouldUseColor(true));  // Stdout is a TTY.
+
   SetEnv("TERM", "xterm-256color");   // TERM supports colors.
   EXPECT_TRUE(ShouldUseColor(true));  // Stdout is a TTY.
 
@@ -6691,15 +6698,16 @@ TEST(ColoredOutputTest, UsesColorsWhenTermSupportsColors) {
   SetEnv("TERM", "linux");            // TERM supports colors.
   EXPECT_TRUE(ShouldUseColor(true));  // Stdout is a TTY.
 
-  SetEnv("TERM", "cygwin");  // TERM supports colors.
+  SetEnv("TERM", "cygwin");           // TERM supports colors.
   EXPECT_TRUE(ShouldUseColor(true));  // Stdout is a TTY.
 #endif  // GTEST_OS_WINDOWS
 }
 
 // Verifies that StaticAssertTypeEq works in a namespace scope.
 
-static bool dummy1 GTEST_ATTRIBUTE_UNUSED_ = StaticAssertTypeEq<bool, bool>();
-static bool dummy2 GTEST_ATTRIBUTE_UNUSED_ =
+GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static bool dummy1 =
+    StaticAssertTypeEq<bool, bool>();
+GTEST_INTERNAL_ATTRIBUTE_MAYBE_UNUSED static bool dummy2 =
     StaticAssertTypeEq<const int, const int>();
 
 // Verifies that StaticAssertTypeEq works in a class.
@@ -7475,22 +7483,6 @@ TEST(NativeArrayTest, WorksForTwoDimensionalArray) {
   EXPECT_EQ(a, na.begin());
 }
 
-// IndexSequence
-TEST(IndexSequence, MakeIndexSequence) {
-  using testing::internal::IndexSequence;
-  using testing::internal::MakeIndexSequence;
-  EXPECT_TRUE(
-      (std::is_same<IndexSequence<>, MakeIndexSequence<0>::type>::value));
-  EXPECT_TRUE(
-      (std::is_same<IndexSequence<0>, MakeIndexSequence<1>::type>::value));
-  EXPECT_TRUE(
-      (std::is_same<IndexSequence<0, 1>, MakeIndexSequence<2>::type>::value));
-  EXPECT_TRUE((
-      std::is_same<IndexSequence<0, 1, 2>, MakeIndexSequence<3>::type>::value));
-  EXPECT_TRUE(
-      (std::is_base_of<IndexSequence<0, 1, 2>, MakeIndexSequence<3>>::value));
-}
-
 // ElemFromList
 TEST(ElemFromList, Basic) {
   using testing::internal::ElemFromList;
diff --git a/googletest_deps.bzl b/googletest_deps.bzl
index 8f19cbed..281af5c0 100644
--- a/googletest_deps.bzl
+++ b/googletest_deps.bzl
@@ -1,22 +1,28 @@
 """Load dependencies needed to use the googletest library as a 3rd-party consumer."""
 
 load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+load("//:fake_fuchsia_sdk.bzl", "fake_fuchsia_sdk")
 
 def googletest_deps():
     """Loads common dependencies needed to use the googletest library."""
 
-    if not native.existing_rule("com_googlesource_code_re2"):
+    if not native.existing_rule("re2"):
         http_archive(
-            name = "com_googlesource_code_re2",  # 2023-03-17T11:36:51Z
-            sha256 = "cb8b5312a65f2598954545a76e8bce913f35fbb3a21a5c88797a4448e9f9b9d9",
-            strip_prefix = "re2-578843a516fd1da7084ae46209a75f3613b6065e",
-            urls = ["https://github.com/google/re2/archive/578843a516fd1da7084ae46209a75f3613b6065e.zip"],
+            name = "re2",
+            sha256 = "eb2df807c781601c14a260a507a5bb4509be1ee626024cb45acbd57cb9d4032b",
+            strip_prefix = "re2-2024-07-02",
+            urls = ["https://github.com/google/re2/releases/download/2024-07-02/re2-2024-07-02.tar.gz"],
         )
 
-    if not native.existing_rule("com_google_absl"):
+    if not native.existing_rule("abseil-cpp"):
         http_archive(
-            name = "com_google_absl",  # 2023-09-13T14:58:42Z
-            sha256 = "7766815ef6293dc7bca58fef59a96d7d3230874412dcd36dafb0e313ed1356f2",
-            strip_prefix = "abseil-cpp-9e1789ffea47fdeb3133aa42aa9592f3673fb6ed",
-            urls = ["https://github.com/abseil/abseil-cpp/archive/9e1789ffea47fdeb3133aa42aa9592f3673fb6ed.zip"],
+            name = "abseil-cpp",
+            sha256 = "733726b8c3a6d39a4120d7e45ea8b41a434cdacde401cba500f14236c49b39dc",
+            strip_prefix = "abseil-cpp-20240116.2",
+            urls = ["https://github.com/abseil/abseil-cpp/releases/download/20240116.2/abseil-cpp-20240116.2.tar.gz"],
+        )
+
+    if not native.existing_rule("fuchsia_sdk"):
+        fake_fuchsia_sdk(
+            name = "fuchsia_sdk",
         )
```

