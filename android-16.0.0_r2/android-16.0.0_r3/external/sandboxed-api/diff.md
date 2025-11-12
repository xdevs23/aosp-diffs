```diff
diff --git a/.bazelci/presubmit.yml b/.bazelci/presubmit.yml
index 2d82098..ca84dea 100644
--- a/.bazelci/presubmit.yml
+++ b/.bazelci/presubmit.yml
@@ -1,7 +1,7 @@
 ---
 tasks:
-  debian10:
+  debian12:
     shell_commands:
-    - "sudo apt -y update && sudo apt -y install llvm-11-dev libclang-11-dev libncurses-dev python3-clang-11"
+    - "sudo apt -y update && sudo apt -y install llvm-19-dev libclang-19-dev libncurses-dev python3-clang-19"
     build_targets:
     - "..."
diff --git a/.bazelrc b/.bazelrc
index 5c57d3f..36cdcc7 100644
--- a/.bazelrc
+++ b/.bazelrc
@@ -1,5 +1,4 @@
-# Enable Bazel modules by default. Projects using Sandboxed API may still use
-# a regular WORKSPACE ("Hybrid Mode").
+# Enable Bazel modules
 common --enable_bzlmod
 
 # Build in C++17 mode without a custom CROSSTOOL
diff --git a/.github/workflows/fedora-cmake.yml b/.github/workflows/fedora-cmake.yml
index a933168..66b4101 100644
--- a/.github/workflows/fedora-cmake.yml
+++ b/.github/workflows/fedora-cmake.yml
@@ -23,11 +23,15 @@ jobs:
     continue-on-error: ${{ matrix.ignore-errors }}
 
     env:
-      RUN_CMD: docker exec --tty ${{matrix.compiler}}-build-container
+      RUN_CMD: docker exec --privileged --tty ${{matrix.compiler}}-build-container
 
     steps:
     - uses: actions/checkout@v3
 
+    - name: Set up environment
+      run: |
+        echo "RUN_USER_CMD=docker exec --privileged --user=$(id -u):$(id -g) --tty ${{matrix.compiler}}-build-container" >> $GITHUB_ENV
+
     - name: Cache dependencies
       uses: actions/cache@v3
       with:
@@ -58,15 +62,15 @@ jobs:
           git make automake diffutils file patch glibc-static \
           libstdc++-static cmake ninja-build python3 python3-pip \
           python3-clang clang-devel libcap-devel
+        $RUN_CMD pip3 install --progress-bar=off absl-py
 
     - name: Create Build Environment
       run: |
-        $RUN_CMD pip3 install --progress-bar=off absl-py
-        $RUN_CMD cmake -E make_directory $GITHUB_WORKSPACE/build
+        $RUN_USER_CMD cmake -E make_directory $GITHUB_WORKSPACE/build
 
     - name: Configure CMake
       run: |
-        $RUN_CMD cmake \
+        $RUN_USER_CMD cmake \
           -S $GITHUB_WORKSPACE \
           -B $GITHUB_WORKSPACE/build \
           -G Ninja \
@@ -74,13 +78,13 @@ jobs:
 
     - name: Build
       run: |
-        $RUN_CMD cmake \
+        $RUN_USER_CMD cmake \
           --build $GITHUB_WORKSPACE/build \
           --config $BUILD_TYPE
 
     - name: Test
       run: |
-        $RUN_CMD ctest \
+        $RUN_USER_CMD ctest \
           --test-dir $GITHUB_WORKSPACE/build \
           -C $BUILD_TYPE \
           --output-on-failure \
diff --git a/.github/workflows/generator-tool.yml b/.github/workflows/generator-tool.yml
index 3e9d7bb..ccbb1ec 100644
--- a/.github/workflows/generator-tool.yml
+++ b/.github/workflows/generator-tool.yml
@@ -1,5 +1,8 @@
 name: generator-tool
-on: push
+on:
+  push:
+    branches:
+      - 'main'
 jobs:
   build:
     runs-on: ubuntu-latest
@@ -10,7 +13,7 @@ jobs:
     - name: Cache dependencies
       uses: actions/cache@v3
       with:
-        key: debian-10.13-clang16
+        key: debian-10.13-clang20
         path: |
           ${{github.workspace}}/build/_deps
 
@@ -33,7 +36,7 @@ jobs:
             wget
         wget https://apt.llvm.org/llvm.sh
         chmod +x llvm.sh
-        ./llvm.sh 16 all
+        ./llvm.sh 20 all
 
     - name: Configure CMake
       run: |
@@ -59,13 +62,15 @@ jobs:
         )
 
     - name: Upload Build Artifact
-      uses: actions/upload-artifact@v3.1.2
+      uses: actions/upload-artifact@v4
       with:
         name: sapi_generator_tool-linux
         path: ${{github.workspace}}/build/sapi_generator_tool-linux-x86_64
 
   prerelease:
     needs: build
+    permissions:
+      contents: write
     runs-on: ubuntu-latest
     env:
       ARTIFACT_NAME: sapi_generator_tool-linux
@@ -84,7 +89,7 @@ jobs:
           let allArtifacts = await github.rest.actions.listWorkflowRunArtifacts({
             owner: context.repo.owner,
             repo: context.repo.repo,
-            run_id: context.payload.workflow_run.id,
+            run_id: ${{github.run_id}},
           });
           let matchArtifact = allArtifacts.data.artifacts.filter((artifact) => {
             return artifact.name == artifactName
@@ -97,7 +102,7 @@ jobs:
           });
           let fs = require('fs');
           fs.writeFileSync(
-            `${process.env.GITHUB_WORKSPACE}/build/${artifactName}.zip`,
+            `${{github.workspace}}/build/${artifactName}.zip`,
             Buffer.from(download.data)
           );
 
diff --git a/.github/workflows/ubuntu-cmake-contrib.yml b/.github/workflows/ubuntu-cmake-contrib.yml
index 7775a80..cf0c5ec 100644
--- a/.github/workflows/ubuntu-cmake-contrib.yml
+++ b/.github/workflows/ubuntu-cmake-contrib.yml
@@ -10,26 +10,24 @@ jobs:
     strategy:
       fail-fast: false
       matrix:
-        os: [ubuntu-22.04]
+        os: [ubuntu-24.04]
         contrib:
           - brotli
           - c-blosc
           - jsonnet
           - libidn2
           - libraw
-          - libtiff
           - libxls
-          - libzip
           - lodepng
           - pffft
         ignore-errors: [true]
         include:
           - compiler: clang
-            compiler-version: 11
-            libclang-version: 11
+            compiler-version: 14
+            libclang-version: 18
           - compiler: gcc
             compiler-version: 10
-            libclang-version: 11
+            libclang-version: 18
     runs-on: ${{ matrix.os }}
     continue-on-error: ${{ matrix.ignore-errors }}
 
diff --git a/.github/workflows/ubuntu-cmake.yml b/.github/workflows/ubuntu-cmake.yml
index 9800cfa..b2aa4a3 100644
--- a/.github/workflows/ubuntu-cmake.yml
+++ b/.github/workflows/ubuntu-cmake.yml
@@ -11,48 +11,42 @@ jobs:
       fail-fast: false
       matrix:
         include:
-          # Ubuntu 22.04: Use preinstalled Clang 12.0.1, 13.0.1 and 14.0.0
-          - os: ubuntu-22.04
+          # Ubuntu 24.04: Use preinstalled Clang 18, 17, 16
+          - os: ubuntu-24.04
             compiler: clang
-            compiler-version: 14
-            libclang-version: 14
+            compiler-version: 18
+            libclang-version: 18
             ignore-errors: false
-          - os: ubuntu-22.04
+          - os: ubuntu-24.04
             compiler: clang
-            compiler-version: 13
-            libclang-version: 13
+            compiler-version: 17
+            libclang-version: 18
             ignore-errors: false
-          - os: ubuntu-22.04
+          - os: ubuntu-24.04
             compiler: clang
-            compiler-version: 12
-            libclang-version: 12
+            compiler-version: 16
+            libclang-version: 18
             ignore-errors: false
-          # Ubuntu 22.04: Use preinstalled GCC 9.5.0, 10.4.0, 11.3.0, 12.1.0
-          - os: ubuntu-22.04
+          # Ubuntu 24.04: Use preinstalled GCC 9.5.0, 10.4.0, 11.3.0, 12.1.0
+          - os: ubuntu-24.04
             compiler: gcc
             compiler-version: 12
-            libclang-version: 14
+            libclang-version: 18
             ignore-errors: false
-          - os: ubuntu-22.04
+          - os: ubuntu-24.04
             compiler: gcc
             compiler-version: 11
-            libclang-version: 14
+            libclang-version: 18
             ignore-errors: false
-          - os: ubuntu-22.04
+          - os: ubuntu-24.04
             compiler: gcc
             compiler-version: 10
-            libclang-version: 14
+            libclang-version: 18
             ignore-errors: false
-          - os: ubuntu-22.04
+          - os: ubuntu-24.04
             compiler: gcc
             compiler-version: 9
-            libclang-version: 14
-            ignore-errors: false
-          # Ubuntu 20.04
-          - os: ubuntu-20.04
-            compiler: gcc
-            compiler-version: 8
-            libclang-version: 12
+            libclang-version: 18
             ignore-errors: false
     runs-on: ${{ matrix.os }}
     continue-on-error: ${{ matrix.ignore-errors }}
diff --git a/Android.bp b/Android.bp
index f86bcaa..ec2c375 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,7 +16,7 @@
 // Usage is only approved for sandboxing host-side Cuttlefish tools to run them
 // in Google's internal production environment.
 package {
-    default_visibility: [":__subpackages__"]
+    default_visibility: [":__subpackages__"],
 }
 
 cc_defaults {
@@ -47,7 +47,20 @@ cc_library {
 cc_defaults {
     name: "sandboxed_api_cc_defaults",
     static_libs: [
-        "libabsl_host",
+        "absl_cleanup",
+        "absl_log",
+        "absl_log_check",
+        "absl_log_die_if_null",
+        "absl_memory",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_strings",
+        "absl_strings_string_view",
+        "absl_time",
+        "absl_container_flat_hash_map",
+        "absl_container_flat_hash_set",
+        "absl_container_btree",
+        "absl_flags_flag",
         "libcap",
         "libprotobuf-cpp-full",
         "sandboxed_api_proto",
@@ -176,12 +189,12 @@ cc_genrule {
         },
     },
     cmd: "$(location sandboxed_api_filewrapper) " +
-         "'' " +
-         "forkserver_bin_embed " +
-         "'' " +
-         "$(genDir)/forkserver_bin_embed.h " +
-         "$(genDir)/forkserver_bin_embed.cc " +
-         "$(in)",
+        "'' " +
+        "forkserver_bin_embed " +
+        "'' " +
+        "$(genDir)/forkserver_bin_embed.h " +
+        "$(genDir)/forkserver_bin_embed.cc " +
+        "$(in)",
     device_supported: false,
     host_supported: true,
     out: ["forkserver_bin_embed.cc"],
@@ -210,14 +223,14 @@ cc_genrule {
         },
     },
     cmd: "mkdir -p $(genDir)/sandboxed_api/sandbox2/ && " +
-         "$(location sandboxed_api_filewrapper) " +
-         "'' " +
-         "forkserver_bin_embed " +
-         "'' " +
-         "$(genDir)/forkserver_bin_embed.h " +
-         "$(genDir)/forkserver_bin_embed.cc " +
-         "$(in) && " +
-         "cp $(genDir)/forkserver_bin_embed.h $(genDir)/sandboxed_api/sandbox2/",
+        "$(location sandboxed_api_filewrapper) " +
+        "'' " +
+        "forkserver_bin_embed " +
+        "'' " +
+        "$(genDir)/forkserver_bin_embed.h " +
+        "$(genDir)/forkserver_bin_embed.cc " +
+        "$(in) && " +
+        "cp $(genDir)/forkserver_bin_embed.h $(genDir)/sandboxed_api/sandbox2/",
     device_supported: false,
     host_supported: true,
     out: [
@@ -246,6 +259,7 @@ cc_library {
         "sandboxed_api/sandbox2/stack_trace.cc",
         "sandboxed_api/sandbox2/network_proxy/filtering.cc",
         "sandboxed_api/sandbox2/network_proxy/server.cc",
+        "sandboxed_api/sandbox2/util/seccomp_unotify.cc",
     ],
     visibility: ["//device/google/cuttlefish:__subpackages__"],
     whole_static_libs: [
@@ -255,4 +269,3 @@ cc_library {
     ],
     defaults: ["sandboxed_api_cc_defaults"],
 }
-
diff --git a/METADATA b/METADATA
index e72f718..f4f43ee 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "sandboxed-api"
-description:
-    "Generate sandboxes for C/C++ libraries automatically"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/sandboxed-api
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "sandboxed-api"
+description: "Generate sandboxes for C/C++ libraries automatically"
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/google/sandboxed-api"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 5
+    day: 27
   }
-  url {
-    type: GIT
+  homepage: "https://github.com/google/sandboxed-api"
+  identifier {
+    type: "Git"
     value: "https://github.com/google/sandboxed-api"
+    version: "08f4d5d09d1a232888ee683be4da13177b02c0d9"
   }
-  version: "4ba75ea0a29b55874f08ee10cc8878f5ad847cd1"
-  last_upgrade_date { year: 2023 month: 7 day: 17 }
-  license_type: NOTICE
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index 48bdff7..d0020e9 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -13,36 +13,60 @@
 # limitations under the License.
 
 module(
-    name = "com_google_sandboxed_api",
+    name = "sandboxed_api",
     version = "20241101.0",
     bazel_compatibility = [">=7.1.1"],
 )
 
-bazel_dep(
-    name = "abseil-cpp",
-    version = "20240722.0",
-    repo_name = "com_google_absl",
-)
-bazel_dep(
-    name = "abseil-py",
-    version = "2.1.0",
-    repo_name = "com_google_absl_py",
-)
+# Load additional repo rules.
+http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+
+# Bazel Central Registry (BCR) Modules:
+bazel_dep(name = "abseil-cpp", version = "20240722.0")
+bazel_dep(name = "abseil-py", version = "2.1.0")
 bazel_dep(name = "bazel_skylib", version = "1.7.1")
-bazel_dep(
-    name = "google_benchmark",
-    version = "1.8.5",
-    repo_name = "com_google_benchmark",
-)
-bazel_dep(
-    name = "googletest",
-    version = "1.15.2",
-    repo_name = "com_google_googletest",
-)
-bazel_dep(
-    name = "protobuf",
-    version = "28.2",
-    repo_name = "com_google_protobuf",
-)
+bazel_dep(name = "google_benchmark", version = "1.8.5")
+bazel_dep(name = "googletest", version = "1.15.2")
+bazel_dep(name = "protobuf", version = "28.2", repo_name = "com_google_protobuf")
 bazel_dep(name = "rules_proto", version = "6.0.2")
 bazel_dep(name = "rules_python", version = "0.37.2")
+bazel_dep(name = "rules_cc", version = "0.1.1")
+bazel_dep(name = "libunwind", version = "1.8.1")
+bazel_dep(name = "libffi", version = "3.4.7")
+
+# Non-Modularized Dependencies:
+
+# llvm-project
+llvm = use_extension("//sandboxed_api/bazel:llvm_config.bzl", "llvm")
+llvm.disable_llvm_zlib()
+llvm.disable_llvm_terminfo()
+use_repo(llvm, "llvm-project")
+
+# libcap
+http_archive(
+    name = "org_kernel_libcap",
+    build_file = "//sandboxed_api:bazel/external/libcap.BUILD",
+    sha256 = "260b549c154b07c3cdc16b9ccc93c04633c39f4fb6a4a3b8d1fa5b8a9c3f5fe8",  # 2019-04-16
+    strip_prefix = "libcap-2.27",
+    urls = ["https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.27.tar.gz"],
+)
+
+# zlib, only needed for examples
+http_archive(
+    name = "net_zlib",
+    build_file = "//sandboxed_api:bazel/external/zlib.BUILD",
+    patch_args = ["-p1"],
+    # This is a patch that removes the "OF" macro that is used in zlib function
+    # definitions. It is necessary, because libclang, the library used by the
+    # interface generator to parse C/C++ files contains a bug that manifests
+    # itself with macros like this.
+    # We are investigating better ways to avoid this issue. For most "normal"
+    # C and C++ headers, parsing just works.
+    patches = ["//sandboxed_api:bazel/external/zlib.patch"],
+    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",  # 2020-04-23
+    strip_prefix = "zlib-1.2.11",
+    urls = [
+        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
+        "https://www.zlib.net/zlib-1.2.11.tar.gz",
+    ],
+)
diff --git a/README.md b/README.md
index 7e5ea54..e56b981 100644
--- a/README.md
+++ b/README.md
@@ -1,31 +1,104 @@
-![Sandbox](sandboxed_api/docs/images/sapi-lockup-vertical.png)
+<p align="left">
+  <img src="https://badge.buildkite.com/2f662d7bddfd1c07d25bf92d243538c8344bc6fbf38fe187f8.svg" alt="Bazel build status" href="https://buildkite.com/bazel/sandboxed-api">
+  <img src="https://github.com/google/sandboxed-api/workflows/ubuntu-cmake/badge.svg" alt="CMake build status" href="https://github.com/google/sandboxed-api/actions/workflows/ubuntu-cmake.yml">
+</p>
+<p align="center">
+  <img src="docs/images/sapi-lockup-vertical.png" alt="Sandboxed API" width="400">
+</p>
 
-Copyright 2019-2023 Google LLC
+Copyright 2019-2025 Google LLC
 
-[![Bazel build status](https://badge.buildkite.com/2f662d7bddfd1c07d25bf92d243538c8344bc6fbf38fe187f8.svg)](https://buildkite.com/bazel/sandboxed-api)
-[![CMake build status](https://github.com/google/sandboxed-api/workflows/CMake/badge.svg)](https://github.com/google/sandboxed-api/actions?query=workflow%3ACMake)
+### Introduction
 
-## What is Sandboxed API?
+The open-source Sandboxed API (SAPI) project builds on top of Google's
+[Sandbox2](https://developers.google.com/code-sandboxing/sandbox2) and
+aims to make sandboxing of C/C++ libraries less burdensome.
 
-The Sandboxed API project (**SAPI**) makes sandboxing of C/C++ libraries less
-burdensome: after initial setup of security policies and generation of library
-interfaces, a stub API is generated, transparently forwarding calls using a
-custom RPC layer to the real library running inside a sandboxed environment.
+Sandboxed API provides three main benefits:
 
-Additionally, each SAPI library utilizes a tightly defined security policy, in
-contrast to the typical sandboxed project, where security policies must cover
-the total syscall/resource footprint of all its libraries.
+*   Instead of sandboxing entire programs or having to change source code to be
+    able to sandbox a part of a program as with Sandbox2, individual C/C++
+    libraries can be sandboxed with SAPI. As a result, the main program is
+    isolated from code execution vulnerabilities in the C/C++ library.
 
-## Documentation
+*   Our working motto is: Sandbox once, use anywhere. Libraries sandboxed with
+    Sandboxed API can be reused easily, which removes the burden for future
+    projects. Before Sandboxed API, sandboxes available for use at Google
+    required additional implementation work with each new instance of a project
+    which was intended to be sandboxed, even if it reused the same software
+    library. Sandbox2 policies and other restrictions applied to the sandboxed
+    process had to be reimplemented each time, and data exchange mechanisms
+    between trusted and untrusted parts of the code had to be designed from
+    scratch.
 
-Developer documentation is available on the Google Developers site for
-[Sandboxed API](https://developers.google.com/code-sandboxing/sandboxed-api).
+*   Each SAPI library utilizes a tightly defined security policy, in contrast
+    to the typical sandboxed project, where security policies must cover the
+    total syscall/resource footprint of all utilized libraries.
 
-There is also a
-[Getting Started](https://developers.google.com/code-sandboxing/sandboxed-api/getting-started)
-guide.
+Sandboxed API (SAPI) has been designed, developed, and is maintained by members
+of the Google Sandbox Team. It also uses our field-tested Sandbox2. Currently,
+many internal projects are using SAPI to isolate their production workloads.
 
-## Getting Involved
+Sandbox2 is also open-sourced as part of the SAPI project and can be used
+independently.
+
+### Documentation
+
+Developer documentation is available at [Sandboxed API](https://developers.google.com/code-sandboxing/sandboxed-api)
+and [Sandbox2](https://developers.google.com/code-sandboxing/sandbox2).
+
+We recommend reading [SAPI Getting Started](https://developers.google.com/code-sandboxing/sandboxed-api/getting-started)
+guide, or [Sandbox2 Getting Started](https://developers.google.com/code-sandboxing/sandbox2/full-getting-started)
+respectively.
+
+If you are interested in a general overview of sandboxing technologies, see
+https://developers.google.com/code-sandboxing.
+
+### Dependencies
+
+SAPI and Sandbox2 both support Bazel and CMake build systems. The following
+dependencies are required on Debian 10 Buster:
+
+```
+sudo apt-get update
+sudo apt-get install -qy
+  bazel \
+  build-essential \
+  ccache \
+  cmake \
+  g++-12 \
+  gcc-12 \
+  git \
+  gnupg \
+  libcap-dev \
+  libclang-18-dev \
+  libffi-dev \
+  libncurses-dev \
+  linux-libc-dev \
+  llvm-18-dev \
+  libzstd-dev \
+  ninja-build \
+  pkg-config \
+  python3 \
+  python3-absl \
+  python3-clang-16 \
+  python3-pip \
+  unzip \
+  wget \
+  zip \
+  zlib1g-dev
+```
+
+#### LLVM
+
+SAPI offers two header generators, based on
+[Python](tools/python_generator/BUILD) and
+[LLVM Libtooling](tools/clang_generator/BUILD).
+
+We aim to provide support for at least the latest three LLVM release and
+cross-check with Debian stable.
+
+### Getting Involved
 
 If you want to contribute, please read [CONTRIBUTING.md](CONTRIBUTING.md) and
 send us pull requests. You can also report bugs or file feature requests.
diff --git a/WORKSPACE b/WORKSPACE
deleted file mode 100644
index b223f19..0000000
--- a/WORKSPACE
+++ /dev/null
@@ -1,73 +0,0 @@
-# Copyright 2019 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# Workspace definition used when Bzlmod is disabled
-workspace(name = "com_google_sandboxed_api")
-
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
-load("//sandboxed_api/bazel:sapi_deps.bzl", "sapi_deps")
-
-# Load Sandboxed API dependencies
-sapi_deps()
-
-load("@bazel_skylib//lib:versions.bzl", "versions")
-
-versions.check(minimum_bazel_version = "5.1.0")
-
-load("@rules_python//python:repositories.bzl", "py_repositories")
-
-py_repositories()
-
-load("@rules_python//python:pip.bzl", "pip_parse")
-
-pip_parse(
-    name = "pypi",
-    requirements_lock = "//sandboxed_api/tools/python_generator:requirements_lock.txt",
-)
-
-load("@pypi//:requirements.bzl", "install_deps")
-
-# Initialize repositories for all packages in requirements_lock.txt.
-install_deps()
-
-load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
-
-protobuf_deps()
-
-load(
-    "//sandboxed_api/bazel:llvm_config.bzl",
-    "llvm_disable_optional_support_deps",
-)
-
-llvm_disable_optional_support_deps()
-
-# zlib, only needed for examples
-http_archive(
-    name = "net_zlib",
-    build_file = "//sandboxed_api:bazel/external/zlib.BUILD",
-    patch_args = ["-p1"],
-    # This is a patch that removes the "OF" macro that is used in zlib function
-    # definitions. It is necessary, because libclang, the library used by the
-    # interface generator to parse C/C++ files contains a bug that manifests
-    # itself with macros like this.
-    # We are investigating better ways to avoid this issue. For most "normal"
-    # C and C++ headers, parsing just works.
-    patches = ["//sandboxed_api:bazel/external/zlib.patch"],
-    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",  # 2020-04-23
-    strip_prefix = "zlib-1.2.11",
-    urls = [
-        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
-        "https://www.zlib.net/zlib-1.2.11.tar.gz",
-    ],
-)
diff --git a/WORKSPACE.bzlmod b/WORKSPACE.bzlmod
index 103c166..74d5de5 100644
--- a/WORKSPACE.bzlmod
+++ b/WORKSPACE.bzlmod
@@ -12,40 +12,5 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# Workspace definition used when Bzlmod is enabled
-workspace(name = "com_google_sandboxed_api")
-
-load("@bazel_skylib//lib:versions.bzl", "versions")
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
-load("//sandboxed_api/bazel:sapi_deps.bzl", "sapi_non_module_deps")
-
-versions.check(minimum_bazel_version = "7.1.1")
-
-sapi_non_module_deps()
-
-load(
-    "//sandboxed_api/bazel:llvm_config.bzl",
-    "llvm_disable_optional_support_deps",
-)
-
-llvm_disable_optional_support_deps()
-
-# zlib, only needed for examples
-http_archive(
-    name = "net_zlib",
-    build_file = "//sandboxed_api:bazel/external/zlib.BUILD",
-    patch_args = ["-p1"],
-    # This is a patch that removes the "OF" macro that is used in zlib function
-    # definitions. It is necessary, because libclang, the library used by the
-    # interface generator to parse C/C++ files contains a bug that manifests
-    # itself with macros like this.
-    # We are investigating better ways to avoid this issue. For most "normal"
-    # C and C++ headers, parsing just works.
-    patches = ["//sandboxed_api:bazel/external/zlib.patch"],
-    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",  # 2020-04-23
-    strip_prefix = "zlib-1.2.11",
-    urls = [
-        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
-        "https://www.zlib.net/zlib-1.2.11.tar.gz",
-    ],
-)
+# This file marks the root of the Bazel workspace.
+# See MODULE.bazel for external dependencies setup.
diff --git a/contrib/brotli/sandboxed.h b/contrib/brotli/sandboxed.h
index e5588c0..1c0a44d 100644
--- a/contrib/brotli/sandboxed.h
+++ b/contrib/brotli/sandboxed.h
@@ -21,13 +21,14 @@
 #include <memory>
 
 #include "sapi_brotli.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class BrotliSapiSandbox : public BrotliSandbox {
  public:
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowWrite()
         .AllowSystemMalloc()
diff --git a/contrib/c-blosc/CMakeLists.txt b/contrib/c-blosc/CMakeLists.txt
index c66cbb9..cd6dc6f 100644
--- a/contrib/c-blosc/CMakeLists.txt
+++ b/contrib/c-blosc/CMakeLists.txt
@@ -30,7 +30,7 @@ endif()
 
 FetchContent_Declare(libblosc
   GIT_REPOSITORY https://github.com/Blosc/c-blosc.git
-  GIT_TAG        ad6361f0151f830efb5ae113211c3559ab969886 # 2022-05-31
+  GIT_TAG        051b9d2cb9437e375dead8574f66d80ebce47bee # 2025-03-28
 )
 set(HIDE_SYMBOLS OFF CACHE BOOL "" FORCE)
 set(BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
diff --git a/contrib/libraw/sandboxed.h b/contrib/libraw/sandboxed.h
index 808b185..c56e8e9 100644
--- a/contrib/libraw/sandboxed.h
+++ b/contrib/libraw/sandboxed.h
@@ -22,6 +22,7 @@
 #include <string>
 
 #include "sapi_libraw.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class LibRawSapiSandbox : public LibRawSandbox {
  public:
@@ -32,7 +33,7 @@ class LibRawSapiSandbox : public LibRawSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowOpen()
         .AllowRead()
         .AllowWrite()
diff --git a/contrib/libxls/sandboxed.h b/contrib/libxls/sandboxed.h
index 0fcc894..ac2973a 100644
--- a/contrib/libxls/sandboxed.h
+++ b/contrib/libxls/sandboxed.h
@@ -21,6 +21,7 @@
 #include <memory>
 
 #include "sapi_libxls.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class LibxlsSapiSandbox : public LibxlsSandbox {
  public:
@@ -30,7 +31,7 @@ class LibxlsSapiSandbox : public LibxlsSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowOpen()
         .AllowRead()
         .AllowWrite()
diff --git a/contrib/libzip/sandboxed.h b/contrib/libzip/sandboxed.h
index 7aa7aac..6319e03 100644
--- a/contrib/libzip/sandboxed.h
+++ b/contrib/libzip/sandboxed.h
@@ -26,13 +26,14 @@
 #include <zipconf.h>  // NOLINT(build/include_order)
 
 #include "sapi_zip.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class ZipSapiSandbox : public ZipSandbox {
  public:
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowWrite()
         .AllowSystemMalloc()
diff --git a/contrib/uriparser/sandboxed.h b/contrib/uriparser/sandboxed.h
index b340ec2..51f94da 100644
--- a/contrib/uriparser/sandboxed.h
+++ b/contrib/uriparser/sandboxed.h
@@ -21,13 +21,14 @@
 #include <memory>
 
 #include "sapi_uriparser.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class UriparserSapiSandbox : public UriparserSandbox {
  public:
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowWrite()
         .AllowSystemMalloc()
diff --git a/contrib/woff2/woff2_sapi.h b/contrib/woff2/woff2_sapi.h
index 263f978..492adea 100644
--- a/contrib/woff2/woff2_sapi.h
+++ b/contrib/woff2/woff2_sapi.h
@@ -19,6 +19,7 @@
 
 #include <cstdlib>
 
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "woff2_sapi.sapi.h"  // NOLINT(build/include)
 
 namespace sapi_woff2 {
@@ -28,7 +29,7 @@ class Woff2SapiSandbox : public WOFF2Sandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowSystemMalloc()
         .AllowRead()
         .AllowStat()
diff --git a/contrib/zopfli/sandboxed.h b/contrib/zopfli/sandboxed.h
index 7f25069..6983216 100644
--- a/contrib/zopfli/sandboxed.h
+++ b/contrib/zopfli/sandboxed.h
@@ -22,13 +22,14 @@
 #include <memory>
 
 #include "sapi_zopfli.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class ZopfliSapiSandbox : public ZopfliSandbox {
  public:
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder *) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowWrite()
         .AllowExit()
         .AllowMmapWithoutExec()
diff --git a/contrib/zstd/sandboxed.h b/contrib/zstd/sandboxed.h
index b06b898..32ba30e 100644
--- a/contrib/zstd/sandboxed.h
+++ b/contrib/zstd/sandboxed.h
@@ -21,13 +21,14 @@
 #include <memory>
 
 #include "sapi_zstd.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 class ZstdSapiSandbox : public ZstdSandbox {
  public:
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowWrite()
         .AllowSystemMalloc()
diff --git a/oss-internship-2020/curl/sandbox.h b/oss-internship-2020/curl/sandbox.h
index b39f28b..3515f1f 100644
--- a/oss-internship-2020/curl/sandbox.h
+++ b/oss-internship-2020/curl/sandbox.h
@@ -22,6 +22,7 @@
 #include <cstdlib>
 
 #include "curl_sapi.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/sandbox2/util/allow_unrestricted_networking.h"
 #include "sandboxed_api/sandbox2/util/bpf_helper.h"
 
@@ -33,7 +34,7 @@ class CurlSapiSandbox : public curl::CurlSandbox {
       sandbox2::PolicyBuilder*) override {
     // Return a new policy
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFork()
         .AllowFutexOp(FUTEX_WAIT_PRIVATE)
diff --git a/oss-internship-2020/gdal/raster.cc b/oss-internship-2020/gdal/raster.cc
index bbe4096..ce69fc1 100644
--- a/oss-internship-2020/gdal/raster.cc
+++ b/oss-internship-2020/gdal/raster.cc
@@ -20,6 +20,7 @@
 
 #include "gdal_sapi.sapi.h"  // NOLINT(build/include)
 #include "absl/log/log.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/fileops.h"
 
 class GdalSapiSandbox : public GDALSandbox {
@@ -30,7 +31,7 @@ class GdalSapiSandbox : public GDALSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowSystemMalloc()
         .AllowWrite()
diff --git a/oss-internship-2020/gdal/raster_to_gtiff/gdal_sandbox.h b/oss-internship-2020/gdal/raster_to_gtiff/gdal_sandbox.h
index 2d4e1e2..a7312b8 100644
--- a/oss-internship-2020/gdal/raster_to_gtiff/gdal_sandbox.h
+++ b/oss-internship-2020/gdal/raster_to_gtiff/gdal_sandbox.h
@@ -20,6 +20,7 @@
 #include <string>
 
 #include "gdal_sapi.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 
 namespace gdal::sandbox {
 
@@ -36,7 +37,7 @@ class GdalSapiSandbox : public GdalSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowRead()
         .AllowSystemMalloc()
         .AllowWrite()
diff --git a/oss-internship-2020/libuv/examples/helloworld.cc b/oss-internship-2020/libuv/examples/helloworld.cc
index a42e6d3..b1de962 100644
--- a/oss-internship-2020/libuv/examples/helloworld.cc
+++ b/oss-internship-2020/libuv/examples/helloworld.cc
@@ -19,6 +19,7 @@
 #include <iostream>
 
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
 namespace {
@@ -28,7 +29,7 @@ class UVSapiHelloworldSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowSyscalls({__NR_epoll_create1, __NR_eventfd2, __NR_pipe2})
diff --git a/oss-internship-2020/libuv/examples/idle-basic.cc b/oss-internship-2020/libuv/examples/idle-basic.cc
index 8b758cd..d52f989 100644
--- a/oss-internship-2020/libuv/examples/idle-basic.cc
+++ b/oss-internship-2020/libuv/examples/idle-basic.cc
@@ -20,6 +20,7 @@
 
 #include "absl/flags/flag.h"
 #include "absl/log/initialize.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
 namespace {
@@ -29,7 +30,7 @@ class UVSapiIdleBasicSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowEpoll()
diff --git a/oss-internship-2020/libuv/examples/uvcat.cc b/oss-internship-2020/libuv/examples/uvcat.cc
index cc930fa..61e338c 100644
--- a/oss-internship-2020/libuv/examples/uvcat.cc
+++ b/oss-internship-2020/libuv/examples/uvcat.cc
@@ -19,6 +19,7 @@
 #include <iostream>
 
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
 namespace {
@@ -32,7 +33,7 @@ class UVSapiUVCatSandbox : public uv::UVSandbox {
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
         .AddFile(filename)
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFork()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
diff --git a/oss-internship-2020/libuv/tests/test_array.cc b/oss-internship-2020/libuv/tests/test_array.cc
index d96bbe4..641c950 100644
--- a/oss-internship-2020/libuv/tests/test_array.cc
+++ b/oss-internship-2020/libuv/tests/test_array.cc
@@ -18,6 +18,7 @@
 
 #include "gtest/gtest.h"
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/status_matchers.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
@@ -28,7 +29,7 @@ class UVTestArraySapiSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowOpen()
diff --git a/oss-internship-2020/libuv/tests/test_callback.cc b/oss-internship-2020/libuv/tests/test_callback.cc
index de37e73..f411437 100644
--- a/oss-internship-2020/libuv/tests/test_callback.cc
+++ b/oss-internship-2020/libuv/tests/test_callback.cc
@@ -18,6 +18,7 @@
 
 #include "gtest/gtest.h"
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/status_matchers.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
@@ -28,7 +29,7 @@ class UVTestCallbackSapiSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowSyscalls({__NR_epoll_create1, __NR_eventfd2, __NR_pipe2})
diff --git a/oss-internship-2020/libuv/tests/test_error.cc b/oss-internship-2020/libuv/tests/test_error.cc
index 5caffa0..a0c775d 100644
--- a/oss-internship-2020/libuv/tests/test_error.cc
+++ b/oss-internship-2020/libuv/tests/test_error.cc
@@ -17,6 +17,7 @@
 
 #include "gtest/gtest.h"
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/status_matchers.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
@@ -27,7 +28,7 @@ class UVTestErrorSapiSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowWrite()
diff --git a/oss-internship-2020/libuv/tests/test_loop.cc b/oss-internship-2020/libuv/tests/test_loop.cc
index 646503f..6643cbd 100644
--- a/oss-internship-2020/libuv/tests/test_loop.cc
+++ b/oss-internship-2020/libuv/tests/test_loop.cc
@@ -18,6 +18,7 @@
 
 #include "gtest/gtest.h"
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/status_matchers.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
@@ -28,7 +29,7 @@ class UVTestLoopSapiSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowSyscalls({__NR_epoll_create1, __NR_eventfd2, __NR_pipe2})
diff --git a/oss-internship-2020/libuv/tests/test_os.cc b/oss-internship-2020/libuv/tests/test_os.cc
index 732ec3d..320d4d8 100644
--- a/oss-internship-2020/libuv/tests/test_os.cc
+++ b/oss-internship-2020/libuv/tests/test_os.cc
@@ -18,6 +18,7 @@
 
 #include "gtest/gtest.h"
 #include "absl/flags/flag.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/util/status_matchers.h"
 #include "uv_sapi.sapi.h"  // NOLINT(build/include)
 
@@ -28,7 +29,7 @@ class UVTestOSSapiSandbox : public uv::UVSandbox {
   std::unique_ptr<sandbox2::Policy> ModifyPolicy(
       sandbox2::PolicyBuilder*) override {
     return sandbox2::PolicyBuilder()
-        .AllowDynamicStartup()
+        .AllowDynamicStartup(sandbox2::MapExec())
         .AllowExit()
         .AllowFutexOp(FUTEX_WAKE_PRIVATE)
         .AllowGetIDs()
diff --git a/sandboxed_api/BUILD b/sandboxed_api/BUILD
index 7a76c66..1ac27cd 100644
--- a/sandboxed_api/BUILD
+++ b/sandboxed_api/BUILD
@@ -12,9 +12,9 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
-package(default_visibility = ["@com_google_sandboxed_api//sandboxed_api:__subpackages__"])
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
 
 licenses(["notice"])
 
@@ -26,7 +26,7 @@ cc_library(
     hdrs = ["config.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:config",
+        "@abseil-cpp//absl/base:config",
     ],
 )
 
@@ -40,13 +40,13 @@ cc_library(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/synchronization",
     ],
 )
 
@@ -56,9 +56,9 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":embed_file",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -84,28 +84,28 @@ cc_library(
         ":embed_file",
         ":var_type",
         ":vars",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:dynamic_annotations",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:runfiles",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:dynamic_annotations",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -158,21 +158,21 @@ cc_library(
         ":call",
         ":lenval_core",
         ":var_type",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/types:span",
-        "@com_google_absl//absl/utility",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:proto_helper",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/types:span",
+        "@abseil-cpp//absl/utility",
         "@com_google_protobuf//:protobuf_lite",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:proto_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
     ],
 )
 
@@ -186,22 +186,22 @@ cc_library(
         ":call",
         ":lenval_core",
         ":var_type",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:dynamic_annotations",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:flags",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:forkingclient",
+        "//sandboxed_api/sandbox2:logsink",
+        "//sandboxed_api/util:proto_arg_cc_proto",
+        "//sandboxed_api/util:proto_helper",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:dynamic_annotations",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:flags",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
         "@com_google_protobuf//:protobuf",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:forkingclient",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:logsink",
-        "@com_google_sandboxed_api//sandboxed_api/util:proto_arg_cc_proto",
-        "@com_google_sandboxed_api//sandboxed_api/util:proto_helper",
-        "@org_sourceware_libffi//:libffi",
+        "@libffi",
     ],
 )
 
@@ -214,21 +214,21 @@ cc_test(
         ":sapi",
         ":testing",
         ":vars",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_absl//absl/types:span",
-        "@com_google_benchmark//:benchmark",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/examples/stringop:stringop-sapi",
-        "@com_google_sandboxed_api//sandboxed_api/examples/stringop:stringop_params_cc_proto",
-        "@com_google_sandboxed_api//sandboxed_api/examples/sum:sum-sapi",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:result",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/examples/stringop:stringop-sapi",
+        "//sandboxed_api/examples/stringop:stringop_params_cc_proto",
+        "//sandboxed_api/examples/sum:sum-sapi",
+        "//sandboxed_api/sandbox2:result",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
+        "@abseil-cpp//absl/types:span",
+        "@google_benchmark//:benchmark",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -242,9 +242,10 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":config",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:policybuilder",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
+        "//sandboxed_api/sandbox2:policybuilder",
+        "//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
+        "//sandboxed_api/util:file_base",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest",
     ],
 )
diff --git a/sandboxed_api/CMakeLists.txt b/sandboxed_api/CMakeLists.txt
index 1ebb55d..95233f5 100644
--- a/sandboxed_api/CMakeLists.txt
+++ b/sandboxed_api/CMakeLists.txt
@@ -202,7 +202,8 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
    PRIVATE absl::strings
            sapi::file_base
            sapi::base
-   PUBLIC sapi::config
+   PUBLIC gtest
+          sapi::config
           sandbox2::allowlists_all_syscalls
           sandbox2::policybuilder
   )
@@ -231,7 +232,7 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING AND NOT CMAKE_CROSSCOMPILING)
 endif()
 
 # Install headers and libraries, excluding tools, tests and examples
-foreach(_dir IN ITEMS . sandbox2 sandbox2/network_proxy sandbox2/util util)
+foreach(_dir IN ITEMS . sandbox2 sandbox2/allowlists sandbox2/network_proxy sandbox2/unwind sandbox2/util util)
   get_property(_sapi_targets DIRECTORY ${_dir} PROPERTY BUILDSYSTEM_TARGETS)
   list(FILTER _sapi_targets INCLUDE REGEX ^\(sapi|sandbox2\).*)
   list(FILTER _sapi_targets EXCLUDE REGEX _test)
diff --git a/sandboxed_api/bazel/BUILD b/sandboxed_api/bazel/BUILD
index 0889433..1413f11 100644
--- a/sandboxed_api/bazel/BUILD
+++ b/sandboxed_api/bazel/BUILD
@@ -49,12 +49,6 @@ bzl_library(
     visibility = ["//visibility:private"],
 )
 
-bzl_library(
-    name = "sapi_deps_bzl",
-    srcs = ["sapi_deps.bzl"],
-    visibility = ["//visibility:private"],
-)
-
 bzl_library(
     name = "sapi",
     srcs = ["sapi.bzl"],
diff --git a/sandboxed_api/bazel/embed_data.bzl b/sandboxed_api/bazel/embed_data.bzl
index 3e18af8..d281312 100644
--- a/sandboxed_api/bazel/embed_data.bzl
+++ b/sandboxed_api/bazel/embed_data.bzl
@@ -90,8 +90,8 @@ def sapi_cc_embed_data(name, srcs = [], namespace = "", **kwargs):
         hdrs = [":%s.h" % name],
         srcs = [":%s.cc" % name],
         deps = [
-            "@com_google_absl//absl/base:core_headers",
-            "@com_google_absl//absl/strings",
+            "@abseil-cpp//absl/base:core_headers",
+            "@abseil-cpp//absl/strings",
         ],
         **kwargs
     )
diff --git a/sandboxed_api/bazel/external/zlib.BUILD b/sandboxed_api/bazel/external/zlib.BUILD
index 830db0a..aa7bb53 100644
--- a/sandboxed_api/bazel/external/zlib.BUILD
+++ b/sandboxed_api/bazel/external/zlib.BUILD
@@ -40,6 +40,7 @@ cc_library(
     copts = [
         "-w",
         "-Dverbose=-1",
+        "-DZ_HAVE_UNISTD_H",
     ],
     includes = ["."],
     textual_hdrs = [
diff --git a/sandboxed_api/bazel/llvm_config.bzl b/sandboxed_api/bazel/llvm_config.bzl
index 54090c0..bb032df 100644
--- a/sandboxed_api/bazel/llvm_config.bzl
+++ b/sandboxed_api/bazel/llvm_config.bzl
@@ -16,7 +16,7 @@
 
 load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
 
-SYSTEM_LLVM_BAZEL_TEMPLATE = """package(default_visibility = ["//visibility:public"])
+_SYSTEM_LLVM_BAZEL_TEMPLATE = """package(default_visibility = ["//visibility:public"])
 # Create one hidden library with all LLVM headers that depends on all its
 # static library archives. This will be used to provide individual library
 # targets named the same as the upstream Bazel files.
@@ -31,14 +31,14 @@ cc_library(
         "llvm-project-include/llvm/**/*.def",
         "llvm-project-include/llvm/**/*.h",
         "llvm-project-include/llvm/**/*.inc",
-    ]),
+    ], allow_empty = True),
     includes = ["llvm-project-include"],
     linkopts = [
         "-lncurses",
-        %{llvm_system_libs}
-        %{llvm_lib_dir}
+        {llvm_system_libs}
+        {llvm_lib_dir}
         "-Wl,--start-group",
-        %{llvm_libs}
+        {llvm_libs}
         "-Wl,--end-group",
     ],
     visibility = ["@llvm-project//clang:__pkg__"],
@@ -48,7 +48,7 @@ cc_library(name = "Support", deps = ["@llvm-project//llvm:llvm"])
 cc_library(name = "config", deps = ["@llvm-project//llvm:llvm"])
 """
 
-SYSTEM_CLANG_BAZEL = """package(default_visibility = ["//visibility:public"])
+_SYSTEM_CLANG_BAZEL = """package(default_visibility = ["//visibility:public"])
 # Fake libraries that just depend on a big library with all files.
 cc_library(name = "ast", deps = ["@llvm-project//llvm:llvm"])
 cc_library(name = "basic", deps = ["@llvm-project//llvm:llvm"])
@@ -61,18 +61,44 @@ cc_library(name = "tooling", deps = ["@llvm-project//llvm:llvm"])
 cc_library(name = "tooling_core", deps = ["@llvm-project//llvm:llvm"])
 """
 
-def _use_system_llvm(ctx):
-    # Look for LLVM in known places
-    llvm_config_tool = ctx.execute(
+def _locate_llvm_config_tool(repository_ctx):
+    """Searches for the llvm-config tool on the system.
+
+    It will try to find llvm-config starting with `version` (which can be configured) and going down
+    to 10 and lastly trying to find llvm-config (without version number). This assures that we find
+    the latest version of llvm-config.
+
+    Returns:
+        The path to the llvm-config tool.
+    """
+    max_version = 20
+    min_version = 18
+
+    llvm_config_tool = repository_ctx.execute(
         ["which"] +  # Prints all arguments it finds in the system PATH
-        ["llvm-config-{}".format(ver) for ver in range(20, 10, -1)] +
+        ["llvm-config-{}".format(ver) for ver in range(max_version, min_version, -1)] +
         ["llvm-config"],
-    ).stdout.splitlines()
-    if not llvm_config_tool:
-        return False
+    )
+    if not llvm_config_tool.stdout:
+        fail("Local llvm-config lookup failed")
+    return llvm_config_tool.stdout.splitlines()[0]
+
+def _get_llvm_config_output(repository_ctx, llvm_config_tool):
+    """Runs llvm-config and returns the output.
+
+    Returns:
+        A dict with the following keys:
+            include_dir: The path to the include directory.
+            system_libs: The list of system libraries.
+            lib_dir: The path to the library directory.
 
-    llvm_config = ctx.execute([
-        llvm_config_tool[0],
+    Args:
+        repository_ctx: The context.
+        llvm_config_tool: The path to the llvm-config tool.
+    """
+
+    llvm_config = repository_ctx.execute([
+        llvm_config_tool,
         "--link-static",
         "--includedir",  # Output line 0
         "--libdir",  # Output line 1
@@ -80,162 +106,157 @@ def _use_system_llvm(ctx):
         "--system-libs",  # Output line 3
         "engine",
         "option",
-    ]).stdout.splitlines()
-    if not llvm_config:
-        return False
+    ])
+    if llvm_config.return_code != 0:
+        fail("llvm-config failed: {}".format(llvm_config.stderr))
+    output = llvm_config.stdout.splitlines()
+
+    return {
+        "include_dir": output[0],
+        "system_libs": output[3].split(" "),
+        "lib_dir": output[1].split(" ")[0],
+    }
+
+def _create_llvm_build_files(repository_ctx, llvm_config):
+    """Creates the BUILD.bazel files for LLVM and Clang.
 
-    include_dir = llvm_config[0]
+    Args:
+        repository_ctx: The context.
+        llvm_config: The output dict of _get_llvm_config_output.
+    """
+
+    include_dir = llvm_config["include_dir"]
     for suffix in ["llvm", "llvm-c", "clang", "clang-c"]:
-        ctx.symlink(
+        repository_ctx.symlink(
             include_dir + "/" + suffix,
             "llvm/llvm-project-include/" + suffix,
         )
 
-    system_libs = llvm_config[3].split(" ")
-    lib_dir = llvm_config[1].split(" ")[0]
+    system_libs = llvm_config["system_libs"]
+    lib_dir = llvm_config["lib_dir"]
 
     # Sadly there's no easy way to get to the Clang library archives
-    archives = ctx.execute(
+    archives = repository_ctx.execute(
         ["find", ".", "-maxdepth", "1"] +
         ["(", "-name", "libLLVM*.a", "-o", "-name", "libclang*.a", ")"],
         working_directory = lib_dir,
     ).stdout.splitlines()
-    lib_strs = sorted(["\"-l{}\",".format(a[5:-2]) for a in archives])
+    lib_strs = sorted(['"-l{}",'.format(a[5:-2]) for a in archives])
 
-    ctx.file(
+    paddeed_newline = "\n" + " " * 8
+    repository_ctx.file(
         "llvm/BUILD.bazel",
-        SYSTEM_LLVM_BAZEL_TEMPLATE.replace(
-            "%{llvm_system_libs}",
-            "\n".join(["\"{}\",".format(s) for s in system_libs]),
-        ).replace(
-            "%{llvm_lib_dir}",
-            "\"-L{}\",".format(lib_dir),
-        ).replace(
-            "%{llvm_libs}",
-            "\n".join(lib_strs),
+        _SYSTEM_LLVM_BAZEL_TEMPLATE.format(
+            llvm_system_libs = paddeed_newline.join(['"{}",'.format(s) for s in system_libs]),
+            llvm_lib_dir = '"-L{}",'.format(lib_dir),
+            llvm_libs = paddeed_newline.join(lib_strs),
         ),
     )
-    ctx.file("clang/BUILD.bazel", SYSTEM_CLANG_BAZEL)
-    return True
 
-def _overlay_directories(ctx, src_path, target_path):
-    bazel_path = src_path.get_child("utils").get_child("bazel")
-    overlay_path = bazel_path.get_child("llvm-project-overlay")
-    script_path = bazel_path.get_child("overlay_directories.py")
-
-    python_bin = ctx.which("python3")
-    if not python_bin:
-        python_bin = ctx.which("python")
-
-    if not python_bin:
-        fail("Failed to find python3 binary")
-
-    cmd = [
-        python_bin,
-        script_path,
-        "--src",
-        src_path,
-        "--overlay",
-        overlay_path,
-        "--target",
-        target_path,
-    ]
-    exec_result = ctx.execute(cmd, timeout = 20)
-
-    if exec_result.return_code != 0:
-        fail(("Failed to execute overlay script: '{cmd}'\n" +
-              "Exited with code {return_code}\n" +
-              "stdout:\n{stdout}\n" +
-              "stderr:\n{stderr}\n").format(
-            cmd = " ".join([str(arg) for arg in cmd]),
-            return_code = exec_result.return_code,
-            stdout = exec_result.stdout,
-            stderr = exec_result.stderr,
-        ))
-
-DEFAULT_LLVM_COMMIT = "2c494f094123562275ae688bd9e946ae2a0b4f8b"  # 2022-03-31
-DEFAULT_LLVM_SHA256 = "59b9431ae22f0ea5f2ce880925c0242b32a9e4f1ae8147deb2bb0fc19b53fa0d"
+def _create_clang_build_files(repository_ctx):
+    """Creates the BUILD.bazel files for Clang."""
+    repository_ctx.file("clang/BUILD.bazel", _SYSTEM_CLANG_BAZEL)
 
-def _llvm_configure_impl(ctx):
-    commit = ctx.attr.commit
-    sha256 = ctx.attr.sha256
-
-    if ctx.attr.system_libraries:
-        if _use_system_llvm(ctx):
-            return
-        if not commit:
-            fail((
-                "Failed to find LLVM and clang system libraries\n\n" +
-                "Note: You may have to install llvm-13-dev and libclang-13-dev\n" +
-                "      packages (or later versions) first.\n"
+def _verify_llvm_dev_headers_are_installed(repository_ctx, llvm_config_tool):
+    """Verifies that the LLVM dev headers are installed."""
+
+    llvm_major_version = repository_ctx.execute([
+        llvm_config_tool,
+        "--version",
+    ])
+    if llvm_major_version.return_code != 0:
+        fail("llvm-config --version failed:\n{}\n".format(llvm_major_version.stderr))
+
+    major_version = llvm_major_version.stdout.split(".")[0]
+    for lib in ["llvm", "clang"]:
+        llvm_dev_headers = repository_ctx.execute(
+            ["stat"] +
+            ["/usr/lib/llvm-{}/include/{}".format(major_version, lib)],
+        )
+        if llvm_dev_headers.return_code != 0:
+            fail("Locating {} headers failed. You may have to install libclang-{}-dev\n{}\n".format(
+                lib,
+                major_version,
+                llvm_dev_headers.stderr,
             ))
 
-    if not commit:
-        commit = DEFAULT_LLVM_COMMIT
-        sha256 = DEFAULT_LLVM_SHA256
+def _use_system_llvm(repository_ctx):
+    """Looks for local LLVM and then prepares BUILD files.
 
-    ctx.download_and_extract(
-        ["https://github.com/llvm/llvm-project/archive/{commit}.tar.gz".format(commit = commit)],
-        "llvm-raw",
-        sha256,
-        "",
-        "llvm-project-" + commit,
-    )
+    Returns:
+        True if LLVM was found, or otherwise Fails.
+    """
+    llvm_config_tool = _locate_llvm_config_tool(repository_ctx)
+    llvm_config = _get_llvm_config_output(repository_ctx, llvm_config_tool)
+    _verify_llvm_dev_headers_are_installed(repository_ctx, llvm_config_tool)
+    _create_llvm_build_files(repository_ctx, llvm_config)
+    _create_clang_build_files(repository_ctx)
+    return True
 
-    target_path = ctx.path("llvm-raw").dirname
-    src_path = target_path.get_child("llvm-raw")
-    _overlay_directories(ctx, src_path, target_path)
+def _llvm_configure_impl(ctx):
+    """Implementation of the `llvm_configure` rule."""
+
+    if _use_system_llvm(ctx):
+        return
+    fail((
+        "Failed to find LLVM and clang system libraries\n\n" +
+        "Note: You may have to install llvm-13-dev and libclang-13-dev\n" +
+        "      packages (or later versions) first.\n"
+    ))
 
-    # Create a starlark file with the requested LLVM targets
+def _llvm_zlib_disable_impl(ctx):
     ctx.file(
-        "llvm/targets.bzl",
-        "llvm_targets = " + str(ctx.attr.targets),
+        "BUILD.bazel",
+        """cc_library(name = "zlib", visibility = ["//visibility:public"])""",
         executable = False,
     )
 
-    # Set up C++ toolchain options. LLVM requires at least C++ 14.
+def _llvm_terminfo_disable_impl(ctx):
     ctx.file(
-        ".bazelrc",
-        "build --cxxopt=-std=c++17 --host_cxxopt=-std=c++17",
+        "BUILD.bazel",
+        """cc_library(name = "terminfo", visibility = ["//visibility:public"])""",
         executable = False,
     )
 
-DEFAULT_TARGETS = ["AArch64", "ARM", "PowerPC", "X86"]
+# We use this `module_extension` directly in MODULE.bazel, configure it with the values and
+# then use `use_repo` to add it to the workspace.
+llvm = module_extension(
+    tag_classes = {
+        "disable_llvm_zlib": tag_class(),
+        "disable_llvm_terminfo": tag_class(),
+    },
+    implementation = lambda ctx: _llvm_module_implementation(ctx),
+)
+
+def _llvm_module_implementation(module_ctx):
+    """Implementation of the `llvm_configure` module_extension."""
+    if len(module_ctx.modules) != 1:
+        fail("llvm_configure module_extension must be used with exactly one module")
+
+    llvm_configure(
+        name = "llvm-project",
+    )
+
+    for _ in module_ctx.modules[0].tags.disable_llvm_zlib:
+        maybe(llvm_zlib_disable, name = "llvm_zlib")
+    for _ in module_ctx.modules[0].tags.disable_llvm_terminfo:
+        maybe(llvm_terminfo_disable, name = "llvm_terminfo")
 
+# DON'T USE THIS RULE DIRECTLY.
 llvm_configure = repository_rule(
     implementation = _llvm_configure_impl,
     local = True,
     configure = True,
-    attrs = {
-        "system_libraries": attr.bool(default = True),
-        "commit": attr.string(),
-        "sha256": attr.string(),
-        "targets": attr.string_list(default = DEFAULT_TARGETS),
-    },
 )
 
-def _llvm_zlib_disable_impl(ctx):
-    ctx.file(
-        "BUILD.bazel",
-        """cc_library(name = "zlib", visibility = ["//visibility:public"])""",
-        executable = False,
-    )
-
+# DO NOT USE THIS RULE DIRECTLY.
 llvm_zlib_disable = repository_rule(
     implementation = _llvm_zlib_disable_impl,
+    local = True,
 )
 
-def _llvm_terminfo_disable(ctx):
-    ctx.file(
-        "BUILD.bazel",
-        """cc_library(name = "terminfo", visibility = ["//visibility:public"])""",
-        executable = False,
-    )
-
+# DO NOT USE THIS RULE DIRECTLY.
 llvm_terminfo_disable = repository_rule(
-    implementation = _llvm_terminfo_disable,
+    implementation = _llvm_terminfo_disable_impl,
+    local = True,
 )
-
-def llvm_disable_optional_support_deps():
-    maybe(llvm_zlib_disable, name = "llvm_zlib")
-    maybe(llvm_terminfo_disable, name = "llvm_terminfo")
diff --git a/sandboxed_api/bazel/sapi.bzl b/sandboxed_api/bazel/sapi.bzl
index 6c54127..ba40278 100644
--- a/sandboxed_api/bazel/sapi.bzl
+++ b/sandboxed_api/bazel/sapi.bzl
@@ -14,10 +14,10 @@
 
 """Starlark rules for projects using Sandboxed API."""
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
 load(
-    "@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl",
+    "//sandboxed_api/bazel:proto.bzl",
     _sapi_proto_library = "sapi_proto_library",
 )
 load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
@@ -117,7 +117,6 @@ def _sapi_interface_impl(ctx):
         extra_flags += ["--extra-arg=-D{}".format(d) for d in cc_ctx.defines.to_list()]
         extra_flags += ["--extra-arg=-isystem{}".format(i) for i in cc_ctx.system_includes.to_list()]
         extra_flags += ["--extra-arg=-iquote{}".format(i) for i in cc_ctx.quote_includes.to_list()]
-        extra_flags += ["--extra-arg=-isystem{}".format(d) for d in cpp_toolchain.built_in_include_directories]
         extra_flags += ["--extra-arg=-I{}".format(d) for d in cc_ctx.includes.to_list()]
     else:
         append_all(extra_flags, "-D", cc_ctx.defines.to_list())
@@ -192,7 +191,7 @@ sapi_interface = rule(
         ),
         "_generator_v2": make_exec_label(
             # TODO(cblichmann): Add prebuilt version of Clang based generator
-            "@com_google_sandboxed_api//sandboxed_api/tools/clang_generator:generator_tool",
+            "//sandboxed_api/tools/clang_generator:generator_tool",
         ),
     },
     toolchains = use_cpp_toolchain(),
@@ -291,7 +290,7 @@ def sapi_library(
     else:
         lib_hdrs += [generated_header]
 
-    default_deps = ["@com_google_sandboxed_api//sandboxed_api/sandbox2"]
+    default_deps = ["//sandboxed_api/sandbox2"]
 
     # Library that contains generated interface and sandboxed binary as a data
     # dependency. Add this as a dependency instead of original library.
@@ -304,12 +303,12 @@ def sapi_library(
         defines = defines,
         deps = sort_deps(
             [
-                "@com_google_absl//absl/base:core_headers",
-                "@com_google_absl//absl/status",
-                "@com_google_absl//absl/status:statusor",
-                "@com_google_sandboxed_api//sandboxed_api:sapi",
-                "@com_google_sandboxed_api//sandboxed_api/util:status",
-                "@com_google_sandboxed_api//sandboxed_api:vars",
+                "@abseil-cpp//absl/base:core_headers",
+                "@abseil-cpp//absl/status",
+                "@abseil-cpp//absl/status:statusor",
+                "//sandboxed_api:sapi",
+                "//sandboxed_api/util:status",
+                "//sandboxed_api:vars",
             ] + deps +
             ([":" + name + "_embed"] if embed else []) +
             (default_deps if add_default_deps else []),
@@ -327,7 +326,7 @@ def sapi_library(
         malloc = malloc,
         deps = [
             ":" + name + ".lib",
-            "@com_google_sandboxed_api//sandboxed_api:client",
+            "//sandboxed_api:client",
         ],
         copts = default_copts,
         **common
diff --git a/sandboxed_api/bazel/sapi_deps.bzl b/sandboxed_api/bazel/sapi_deps.bzl
deleted file mode 100644
index 9d3f5ec..0000000
--- a/sandboxed_api/bazel/sapi_deps.bzl
+++ /dev/null
@@ -1,143 +0,0 @@
-# Copyright 2019 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Loads dependencies needed to compile Sandboxed API for 3rd-party consumers."""
-
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
-load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
-load("//sandboxed_api/bazel:llvm_config.bzl", "llvm_configure")
-load("//sandboxed_api/bazel:repositories.bzl", "autotools_repository")
-
-def sapi_non_module_deps():
-    """Loads non-modularized dependencies."""
-
-    # libcap
-    http_archive(
-        name = "org_kernel_libcap",
-        build_file = "@com_google_sandboxed_api//sandboxed_api:bazel/external/libcap.BUILD",
-        sha256 = "260b549c154b07c3cdc16b9ccc93c04633c39f4fb6a4a3b8d1fa5b8a9c3f5fe8",  # 2019-04-16
-        strip_prefix = "libcap-2.27",
-        urls = ["https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.27.tar.gz"],
-    )
-
-    # libffi
-    autotools_repository(
-        name = "org_sourceware_libffi",
-        build_file = "@com_google_sandboxed_api//sandboxed_api:bazel/external/libffi.BUILD",
-        sha256 = "653ffdfc67fbb865f39c7e5df2a071c0beb17206ebfb0a9ecb18a18f63f6b263",  # 2019-11-02
-        strip_prefix = "libffi-3.3-rc2",
-        urls = ["https://github.com/libffi/libffi/releases/download/v3.3-rc2/libffi-3.3-rc2.tar.gz"],
-    )
-
-    # libunwind
-    autotools_repository(
-        name = "org_gnu_libunwind",
-        build_file = "@com_google_sandboxed_api//sandboxed_api:bazel/external/libunwind.BUILD",
-        configure_args = [
-            "--disable-documentation",
-            "--disable-minidebuginfo",
-            "--disable-shared",
-            "--enable-ptrace",
-        ],
-        sha256 = "4a6aec666991fb45d0889c44aede8ad6eb108071c3554fcdff671f9c94794976",  # 2021-12-01
-        strip_prefix = "libunwind-1.6.2",
-        urls = ["https://github.com/libunwind/libunwind/releases/download/v1.6.2/libunwind-1.6.2.tar.gz"],
-    )
-
-    # LLVM/libclang
-    maybe(
-        llvm_configure,
-        name = "llvm-project",
-        commit = "2c494f094123562275ae688bd9e946ae2a0b4f8b",  # 2022-03-31
-        sha256 = "59b9431ae22f0ea5f2ce880925c0242b32a9e4f1ae8147deb2bb0fc19b53fa0d",
-        system_libraries = True,  # Prefer system libraries
-    )
-
-def sapi_deps():
-    """Loads common dependencies needed to compile Sandboxed API."""
-
-    # Bazel rules_python
-    maybe(
-        http_archive,
-        name = "rules_python",
-        sha256 = "c6fb25d0ba0246f6d5bd820dd0b2e66b339ccc510242fd4956b9a639b548d113",  # 2024-10-27
-        strip_prefix = "rules_python-0.37.2",
-        urls = ["https://github.com/bazelbuild/rules_python/releases/download/0.37.2/rules_python-0.37.2.tar.gz"],
-    )
-
-    # Bazel Skylib
-    maybe(
-        http_archive,
-        name = "bazel_skylib",
-        sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",  # 2024-06-03
-        urls = [
-            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
-            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
-        ],
-    )
-
-    # Abseil
-    maybe(
-        http_archive,
-        name = "com_google_absl",
-        sha256 = "571549a0fa17ebf46f517541bb8d66fe369493963d463409fe61f2b8a44eb2dc",  # 2024-04-05
-        strip_prefix = "abseil-cpp-fa588813c4b2d931737bbe7c4b4f7fa6ed7509db",
-        urls = ["https://github.com/abseil/abseil-cpp/archive/fa588813c4b2d931737bbe7c4b4f7fa6ed7509db.zip"],
-    )
-    maybe(
-        http_archive,
-        name = "com_google_absl_py",
-        sha256 = "8a3d0830e4eb4f66c4fa907c06edf6ce1c719ced811a12e26d9d3162f8471758",  # 2024-01-16
-        strip_prefix = "abseil-py-2.1.0",
-        urls = ["https://github.com/abseil/abseil-py/archive/refs/tags/v2.1.0.tar.gz"],
-    )
-
-    # Abseil-py dependency for Python 2/3 compatiblity
-    maybe(
-        http_archive,
-        name = "six_archive",
-        build_file = "@com_google_sandboxed_api//sandboxed_api:bazel/external/six.BUILD",
-        sha256 = "30639c035cdb23534cd4aa2dd52c3bf48f06e5f4a941509c8bafd8ce11080259",  # 2020-05-21
-        strip_prefix = "six-1.15.0",
-        urls = ["https://pypi.python.org/packages/source/s/six/six-1.15.0.tar.gz"],
-    )
-
-    # Protobuf
-    maybe(
-        http_archive,
-        name = "com_google_protobuf",
-        sha256 = "b2340aa47faf7ef10a0328190319d3f3bee1b24f426d4ce8f4253b6f27ce16db",  # 2024-09-18
-        strip_prefix = "protobuf-28.2",
-        urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v28.2/protobuf-28.2.tar.gz"],
-    )
-
-    # GoogleTest/GoogleMock
-    maybe(
-        http_archive,
-        name = "com_google_googletest",
-        sha256 = "a217118c2c36a3632b594af7ff98111a65bb2b980b726a7fa62305e02a998440",  # 2023-06-06
-        strip_prefix = "googletest-334704df263b480a3e9e7441ed3292a5e30a37ec",
-        urls = ["https://github.com/google/googletest/archive/334704df263b480a3e9e7441ed3292a5e30a37ec.zip"],
-    )
-
-    # Google Benchmark
-    maybe(
-        http_archive,
-        name = "com_google_benchmark",
-        sha256 = "342705876335bf894147e052d0dac141fe15962034b41bef5aa59c4b279ca89c",  # 2023-05-30
-        strip_prefix = "benchmark-604f6fd3f4b34a84ec4eb4db81d842fa4db829cd",
-        urls = ["https://github.com/google/benchmark/archive/604f6fd3f4b34a84ec4eb4db81d842fa4db829cd.zip"],
-    )
-
-    sapi_non_module_deps()
diff --git a/sandboxed_api/config.h b/sandboxed_api/config.h
index 7bf2904..4e2faf2 100644
--- a/sandboxed_api/config.h
+++ b/sandboxed_api/config.h
@@ -165,9 +165,20 @@ constexpr bool IsLSan() {
 #endif
 }
 
+constexpr bool IsCfiDiag() {
+// Note, Only diagnostic mode of needs exceptions, CONTROL_FLOW_INTEGRITY is
+// intended for use in production, and doesn't need any sandbox exceptions.
+#ifdef CONTROL_FLOW_INTEGRITY_DIAGNOSTICS
+  return true;
+#else
+  return false;
+#endif
+}
+
 // Returns whether any of the sanitizers is enabled.
 constexpr bool IsAny() {
-  return IsMSan() || IsTSan() || IsASan() || IsHwASan() || IsLSan();
+  return IsMSan() || IsTSan() || IsASan() || IsHwASan() || IsLSan() ||
+         IsCfiDiag();
 }
 
 }  // namespace sanitizers
diff --git a/sandboxed_api/examples/hello_sapi/BUILD b/sandboxed_api/examples/hello_sapi/BUILD
index 20358ad..0cbfb90 100644
--- a/sandboxed_api/examples/hello_sapi/BUILD
+++ b/sandboxed_api/examples/hello_sapi/BUILD
@@ -12,10 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load(
-    "@com_google_sandboxed_api//sandboxed_api/bazel:sapi.bzl",
-    "sapi_library",
-)
+load("//sandboxed_api/bazel:sapi.bzl", "sapi_library")
+
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
+
+licenses(["notice"])
 
 # Library with code that should be sandboxed
 cc_library(
@@ -30,7 +31,7 @@ sapi_library(
     functions = [
         "AddTwoIntegers",
     ],
-    generator_version = 1,
+    generator_version = 2,
     input_files = ["hello_lib.cc"],
     lib = ":hello_lib",
     lib_name = "Hello",
@@ -52,8 +53,10 @@ cc_binary(
     srcs = ["hello_transacted.cc"],
     deps = [
         ":hello_sapi",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:sapi",
+        "//sandboxed_api/sandbox2:policy",
+        "//sandboxed_api/sandbox2:policybuilder",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/status",
     ],
 )
diff --git a/sandboxed_api/examples/hello_sapi/CMakeLists.txt b/sandboxed_api/examples/hello_sapi/CMakeLists.txt
index a058b15..4506b42 100644
--- a/sandboxed_api/examples/hello_sapi/CMakeLists.txt
+++ b/sandboxed_api/examples/hello_sapi/CMakeLists.txt
@@ -79,4 +79,8 @@ target_link_libraries(hello_transacted PRIVATE
   hello::base
   hello::sapi
   sapi::sapi
+  sandbox2::policy
+  sandbox2::policybuilder
+  sandbox2::util
+  absl::status
 )
diff --git a/sandboxed_api/examples/hello_sapi/hello_main.cc b/sandboxed_api/examples/hello_sapi/hello_main.cc
index 7081bcc..6154284 100644
--- a/sandboxed_api/examples/hello_sapi/hello_main.cc
+++ b/sandboxed_api/examples/hello_sapi/hello_main.cc
@@ -23,7 +23,7 @@
 #include <iostream>
 
 // Generated header
-#include "hello_sapi.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/examples/hello_sapi/hello_sapi.sapi.h"
 
 int main() {
   std::cout << "Calling into a sandboxee to add two numbers...\n";
diff --git a/sandboxed_api/examples/hello_sapi/hello_transacted.cc b/sandboxed_api/examples/hello_sapi/hello_transacted.cc
index 5a75f61..d324fa0 100644
--- a/sandboxed_api/examples/hello_sapi/hello_transacted.cc
+++ b/sandboxed_api/examples/hello_sapi/hello_transacted.cc
@@ -19,11 +19,10 @@
 #include <iostream>
 #include <memory>
 
-#include "absl/memory/memory.h"
 #include "absl/status/status.h"
-
 // Generated header
-#include "hello_sapi.sapi.h"  // NOLINT(build/include)
+#include "sandboxed_api/examples/hello_sapi/hello_sapi.sapi.h"
+#include "sandboxed_api/sandbox.h"
 #include "sandboxed_api/sandbox2/policy.h"
 #include "sandboxed_api/sandbox2/policybuilder.h"
 #include "sandboxed_api/transaction.h"
diff --git a/sandboxed_api/examples/stringop/BUILD b/sandboxed_api/examples/stringop/BUILD
index bbef83c..d5fd5cc 100644
--- a/sandboxed_api/examples/stringop/BUILD
+++ b/sandboxed_api/examples/stringop/BUILD
@@ -14,11 +14,11 @@
 
 # Description: Example using dynamic length structures for Sandboxed API
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:sapi.bzl", "sapi_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
+load("//sandboxed_api/bazel:sapi.bzl", "sapi_library")
 
-package(default_visibility = ["@com_google_sandboxed_api//sandboxed_api:__subpackages__"])
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
 
 licenses(["notice"])
 
@@ -36,8 +36,8 @@ cc_library(
     linkstatic = True,
     deps = [
         ":stringop_params_cc_proto",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_sandboxed_api//sandboxed_api:lenval_core",
+        "//sandboxed_api:lenval_core",
+        "@abseil-cpp//absl/base:core_headers",
     ],
     alwayslink = True,
 )
@@ -55,7 +55,7 @@ STRINGOP_FUNCTIONS = [
 sapi_library(
     name = "stringop-sapi",
     functions = STRINGOP_FUNCTIONS,
-    generator_version = 1,
+    generator_version = 2,
     input_files = ["stringop.cc"],
     lib = ":stringop",
     lib_name = "Stringop",
@@ -71,15 +71,15 @@ cc_test(
     deps = [
         ":stringop-sapi",
         ":stringop_params_cc_proto",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:sapi",
-        "@com_google_sandboxed_api//sandboxed_api:vars",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:sapi",
+        "//sandboxed_api:vars",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:string_view",
+        "@googletest//:gtest_main",
     ],
 )
diff --git a/sandboxed_api/examples/sum/BUILD b/sandboxed_api/examples/sum/BUILD
index 2ff4110..3a6605a 100644
--- a/sandboxed_api/examples/sum/BUILD
+++ b/sandboxed_api/examples/sum/BUILD
@@ -12,11 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:sapi.bzl", "sapi_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
+load("//sandboxed_api/bazel:sapi.bzl", "sapi_library")
 
-package(default_visibility = ["@com_google_sandboxed_api//sandboxed_api:__subpackages__"])
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
 
 licenses(["notice"])
 
@@ -37,7 +37,7 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":sum_params_cc_proto",
-        "@com_google_absl//absl/log",
+        "@abseil-cpp//absl/log",
     ],
     alwayslink = 1,  # All functions are linked into depending binaries
 )
@@ -60,7 +60,7 @@ sapi_library(
         "sleep_for_sec",
         "sumproto",
     ],
-    generator_version = 1,
+    generator_version = 2,
     input_files = [
         "sum.c",
         "sum_cpp.cc",
@@ -80,18 +80,19 @@ cc_binary(
     deps = [
         ":sum-sapi",
         ":sum_params_cc_proto",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:sapi",
-        "@com_google_sandboxed_api//sandboxed_api:vars",
+        "//sandboxed_api:sapi",
+        "//sandboxed_api:vars",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
diff --git a/sandboxed_api/examples/sum/main_sum.cc b/sandboxed_api/examples/sum/main_sum.cc
index 19a2043..c0e389e 100644
--- a/sandboxed_api/examples/sum/main_sum.cc
+++ b/sandboxed_api/examples/sum/main_sum.cc
@@ -32,7 +32,9 @@
 #include "absl/strings/str_cat.h"
 #include "sandboxed_api/examples/sum/sum-sapi.sapi.h"
 #include "sandboxed_api/examples/sum/sum_params.pb.h"
+#include "sandboxed_api/sandbox.h"
 #include "sandboxed_api/transaction.h"
+#include "sandboxed_api/util/status_macros.h"
 #include "sandboxed_api/vars.h"
 
 namespace {
@@ -120,7 +122,6 @@ absl::Status SumTransaction::Main() {
   long double c = 1.1001L;
   SAPI_ASSIGN_OR_RETURN(long double r, f.addf(a, b, c));
   LOG(INFO) << "Addf(" << a << ", " << b << ", " << c << ") = " << r;
-  // TODO(szwl): floating point comparison.
 
   // Prints "Hello World!!!" via puts()
   const char hwstr[] = "Hello World!!!";
diff --git a/sandboxed_api/examples/zlib/BUILD b/sandboxed_api/examples/zlib/BUILD
index cfd6623..7381b74 100644
--- a/sandboxed_api/examples/zlib/BUILD
+++ b/sandboxed_api/examples/zlib/BUILD
@@ -14,10 +14,10 @@
 
 # Description: Sandboxed API reimplementation of zlib's zpipe.c example.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:sapi.bzl", "sapi_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:sapi.bzl", "sapi_library")
 
-package(default_visibility = ["@com_google_sandboxed_api//sandboxed_api:__subpackages__"])
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
 
 licenses(["notice"])
 
@@ -42,15 +42,15 @@ cc_binary(
     copts = sapi_platform_copts(),
     deps = [
         ":zlib-sapi",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_sandboxed_api//sandboxed_api:vars",
+        "//sandboxed_api:vars",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/BUILD b/sandboxed_api/sandbox2/BUILD
index 6a406bc..66665c4 100644
--- a/sandboxed_api/sandbox2/BUILD
+++ b/sandboxed_api/sandbox2/BUILD
@@ -14,11 +14,11 @@
 
 # Description: sandbox2 is a C++ sandbox technology for Linux.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
+load("//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
 
-package(default_visibility = ["@com_google_sandboxed_api//sandboxed_api:__subpackages__"])
+package(default_visibility = ["//sandboxed_api:__subpackages__"])
 
 licenses(["notice"])
 
@@ -29,8 +29,8 @@ cc_library(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/types:span",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -41,11 +41,11 @@ cc_library(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -56,10 +56,10 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":syscall",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:config",
+        "//sandboxed_api:config",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -73,11 +73,11 @@ cc_test(
         ":sanitizer",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/log:check",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log:check",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -95,14 +95,14 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":util",
-        "@com_google_absl//absl/algorithm:container",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/algorithm:container",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -113,9 +113,9 @@ cc_test(
     tags = ["no_qemu_user_mode"],
     deps = [
         ":syscall",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:config",
+        "//sandboxed_api:config",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -128,9 +128,9 @@ cc_library(
         ":regs",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:config",
+        "//sandboxed_api:config",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -147,8 +147,8 @@ cc_library(
     deps = [
         ":comms",
         ":logserver_cc_proto",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/log",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/log",
     ],
 )
 
@@ -161,13 +161,13 @@ cc_library(
     deps = [
         ":comms",
         ":logserver_cc_proto",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/log:log_entry",
-        "@com_google_absl//absl/log:log_sink",
-        "@com_google_absl//absl/log:log_sink_registry",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/synchronization",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/log:log_entry",
+        "@abseil-cpp//absl/log:log_sink",
+        "@abseil-cpp//absl/log:log_sink_registry",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/synchronization",
     ],
 )
 
@@ -180,10 +180,10 @@ cc_library(
         ":comms",
         ":logserver",
         ":logsink",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -197,12 +197,13 @@ cc_library(
         ":namespace",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:filtering",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/network_proxy:filtering",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/sandbox2/util:seccomp_unotify",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/strings:string_view",
     ],
 )
 
@@ -216,9 +217,9 @@ cc_library(
         ":result",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/strings:str_format",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/strings:str_format",
     ],
 )
 
@@ -227,8 +228,8 @@ cc_library(
     hdrs = ["limits.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/time",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -242,11 +243,11 @@ cc_binary(
         ":comms",
         ":forkserver",
         ":sanitizer",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/status",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/unwind",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2/unwind",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/status",
     ],
 )
 
@@ -267,19 +268,19 @@ cc_library(
         ":forkserver_bin_embed",
         ":forkserver_cc_proto",
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api:embed_file",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api:embed_file",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/synchronization",
     ],
 )
 
@@ -293,7 +294,7 @@ cc_library(
     deps = [
         ":fork_client",
         ":global_forkserver",
-        "@com_google_absl//absl/base:core_headers",
+        "@abseil-cpp//absl/base:core_headers",
     ],
 )
 
@@ -310,15 +311,15 @@ cc_library(
         ":limits",
         ":namespace",
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api:config",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -326,9 +327,7 @@ cc_library(
 # sandbox2::Client objects
 cc_library(
     name = "sandbox2",
-    srcs = [
-        "sandbox2.cc",
-    ],
+    srcs = ["sandbox2.cc"],
     hdrs = [
         "client.h",
         "executor.h",
@@ -365,24 +364,25 @@ cc_library(
         ":stack_trace",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/base",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/time",
-        "@com_google_absl//absl/types:optional",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:map_exec",  # TODO b/371179394 - Remove this after migrating to Allow(MapExec).
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:filtering",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/allowlists:map_exec",  # TODO: b/371179394 - Remove this after migrating to Allow(MapExec).
+        "//sandboxed_api/sandbox2/network_proxy:client",
+        "//sandboxed_api/sandbox2/network_proxy:filtering",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/base",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:die_if_null",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/time",
+        "@abseil-cpp//absl/types:optional",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -401,19 +401,19 @@ cc_library(
         ":policybuilder",
         ":regs",
         ":result",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/unwind:unwind_cc_proto",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2/unwind:unwind_cc_proto",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -434,24 +434,24 @@ cc_library(
         ":sanitizer",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:vlog_is_on",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:pid_waiter",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/util:pid_waiter",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:vlog_is_on",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -469,20 +469,21 @@ cc_library(
         ":notify",
         ":policy",
         ":result",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        ":util",
+        "//sandboxed_api/sandbox2/util:seccomp_unotify",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -508,24 +509,24 @@ cc_library(
         ":stack_trace",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/base",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:vlog_is_on",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:server",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:strerror",
-        "@com_google_sandboxed_api//sandboxed_api/util:temp_file",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/sandbox2/network_proxy:client",
+        "//sandboxed_api/sandbox2/network_proxy:server",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:strerror",
+        "//sandboxed_api/util:temp_file",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:vlog_is_on",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -540,28 +541,28 @@ cc_library(
         ":namespace",
         ":policy",
         ":syscall",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/types:optional",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:map_exec",  # TODO b/371179394 - Remove this after migrating to Allow(MapExec).
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:namespaces",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:seccomp_speculation",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:trace_all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:filtering",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/allowlists:all_syscalls",
+        "//sandboxed_api/sandbox2/allowlists:map_exec",  # TODO: b/371179394 - Remove this after migrating to Allow(MapExec).
+        "//sandboxed_api/sandbox2/allowlists:namespaces",
+        "//sandboxed_api/sandbox2/allowlists:seccomp_speculation",
+        "//sandboxed_api/sandbox2/allowlists:trace_all_syscalls",
+        "//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
+        "//sandboxed_api/sandbox2/network_proxy:filtering",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/types:optional",
+        "@abseil-cpp//absl/types:span",
     ],
 )
 
@@ -579,13 +580,13 @@ cc_library(
         ":policy",
         ":sanitizer",
         ":syscall",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2/network_proxy:client",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -597,13 +598,13 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":util",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -622,17 +623,17 @@ cc_library(
         ":sanitizer",
         ":syscall",
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:strerror",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:strerror",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
         "@org_kernel_libcap//:libcap",
     ],
 )
@@ -646,11 +647,11 @@ cc_library(
     deps = [
         ":comms",
         ":forkserver_cc_proto",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/synchronization",
     ],
 )
 
@@ -661,16 +662,16 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":mount_tree_cc_proto",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:minielf",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2/util:minielf",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -678,17 +679,17 @@ cc_test(
     name = "mounts_test",
     srcs = ["mounts_test.cc"],
     copts = sapi_platform_copts(),
-    data = ["@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal_dynamic"],
+    data = ["//sandboxed_api/sandbox2/testcases:minimal_dynamic"],
     deps = [
         ":mount_tree_cc_proto",
         ":mounts",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
-        "@com_google_sandboxed_api//sandboxed_api/util:temp_file",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:temp_file",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -700,10 +701,10 @@ cc_library(
     deps = [
         ":forkserver_cc_proto",
         ":mounts",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -712,7 +713,7 @@ cc_test(
     srcs = ["namespace_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:namespace",
+        "//sandboxed_api/sandbox2/testcases:namespace",
     ],
     tags = [
         "requires-net:external",
@@ -720,18 +721,18 @@ cc_test(
     deps = [
         ":namespace",
         ":sandbox2",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:namespaces",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:testonly_unrestricted_networking",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
-        "@com_google_sandboxed_api//sandboxed_api/util:temp_file",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2/allowlists:namespaces",
+        "//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
+        "//sandboxed_api/sandbox2/allowlists:testonly_unrestricted_networking",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:temp_file",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -746,8 +747,8 @@ cc_library(
         ":comms",
         ":forkserver",
         ":sanitizer",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
     ],
 )
 
@@ -755,25 +756,37 @@ cc_library(
     name = "util",
     srcs = ["util.cc"],
     hdrs = ["util.h"],
-    # The default is 16384, however we need to do a clone with a
-    # stack-allocated buffer -- and PTHREAD_STACK_MIN also happens to be 16384.
-    # Thus the slight increase.
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/algorithm:container",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/types:span",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/algorithm:container",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/types:span",
+    ],
+)
+
+# Library for C-wrappers of util.h.
+cc_library(
+    name = "util_c",
+    srcs = ["util_c.cc"],
+    hdrs = ["util_c.h"],
+    copts = sapi_platform_copts(),
+    visibility = ["//visibility:public"],
+    deps = [
+        ":util",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
@@ -785,9 +798,11 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":util",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
@@ -795,14 +810,15 @@ cc_test(
     name = "buffer_test",
     srcs = ["buffer_test.cc"],
     copts = sapi_platform_copts(),
-    data = ["@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:buffer"],
+    data = ["//sandboxed_api/sandbox2/testcases:buffer"],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":buffer",
         ":sandbox2",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status_matchers",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -825,17 +841,17 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":util",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:dynamic_annotations",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:status_cc_proto",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:dynamic_annotations",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
         "@com_google_protobuf//:protobuf",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_cc_proto",
     ],
 )
 
@@ -851,14 +867,14 @@ cc_test(
     deps = [
         ":comms",
         ":comms_test_cc_proto",
-        "@com_google_absl//absl/container:fixed_array",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/container:fixed_array",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -866,18 +882,18 @@ cc_test(
     name = "forkserver_test",
     srcs = ["forkserver_test.cc"],
     copts = sapi_platform_copts(),
-    data = ["@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal"],
+    data = ["//sandboxed_api/sandbox2/testcases:minimal"],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":forkserver",
         ":forkserver_cc_proto",
         ":global_forkserver",
         ":sandbox2",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
+        "//sandboxed_api:testing",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -886,15 +902,15 @@ cc_test(
     srcs = ["limits_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:limits",
+        "//sandboxed_api/sandbox2/testcases:limits",
     ],
     deps = [
         ":limits",
         ":sandbox2",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:config",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:status_matchers",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -903,21 +919,21 @@ cc_test(
     srcs = ["notify_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:personality",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:pidcomms",
+        "//sandboxed_api/sandbox2/testcases:minimal",
+        "//sandboxed_api/sandbox2/testcases:personality",
+        "//sandboxed_api/sandbox2/testcases:pidcomms",
     ],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":comms",
         ":sandbox2",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:trace_all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2/allowlists:trace_all_syscalls",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -926,23 +942,28 @@ cc_test(
     srcs = ["policy_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:add_policy_on_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:malloc_system",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal_dynamic",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:policy",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:posix_timers",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:sandbox_detection",
+        "//sandboxed_api/sandbox2/testcases:add_policy_on_syscalls",
+        "//sandboxed_api/sandbox2/testcases:execveat",
+        "//sandboxed_api/sandbox2/testcases:malloc_system",
+        "//sandboxed_api/sandbox2/testcases:minimal",
+        "//sandboxed_api/sandbox2/testcases:minimal_dynamic",
+        "//sandboxed_api/sandbox2/testcases:policy",
+        "//sandboxed_api/sandbox2/testcases:posix_timers",
+        "//sandboxed_api/sandbox2/testcases:sandbox_detection",
     ],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":sandbox2",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:config",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2/allowlists:seccomp_speculation",
+        "//sandboxed_api/sandbox2/allowlists:testonly_map_exec",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -951,12 +972,12 @@ cc_test(
     srcs = ["sandbox2_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:abort",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:custom_fork",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:minimal",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:sleep",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:starve",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:tsync",
+        "//sandboxed_api/sandbox2/testcases:abort",
+        "//sandboxed_api/sandbox2/testcases:custom_fork",
+        "//sandboxed_api/sandbox2/testcases:minimal",
+        "//sandboxed_api/sandbox2/testcases:sleep",
+        "//sandboxed_api/sandbox2/testcases:starve",
+        "//sandboxed_api/sandbox2/testcases:tsync",
     ],
     tags = [
         "local",
@@ -965,16 +986,16 @@ cc_test(
     deps = [
         ":fork_client",
         ":sandbox2",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api:config",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -983,8 +1004,8 @@ cc_test(
     srcs = ["sanitizer_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:close_fds",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:sanitizer",
+        "//sandboxed_api/sandbox2/testcases:close_fds",
+        "//sandboxed_api/sandbox2/testcases:sanitizer",
     ],
     tags = ["no_qemu_user_mode"],
     deps = [
@@ -992,12 +1013,12 @@ cc_test(
         ":sandbox2",
         ":sanitizer",
         ":util",
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1006,19 +1027,19 @@ cc_test(
     srcs = ["util_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:util_communicate",
+        "//sandboxed_api/sandbox2/testcases:util_communicate",
     ],
     deps = [
         ":util",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/types:span",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/types:span",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1028,23 +1049,23 @@ cc_test(
         "stack_trace_test.cc",
     ],
     copts = sapi_platform_copts(),
-    data = ["@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:symbolize"],
+    data = ["//sandboxed_api/sandbox2/testcases:symbolize"],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":global_forkserver",
         ":sandbox2",
         ":stack_trace",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:scoped_mock_log",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/time",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:testonly_namespaces",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2/allowlists:testonly_all_syscalls",
+        "//sandboxed_api/sandbox2/allowlists:testonly_namespaces",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:scoped_mock_log",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/time",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1052,14 +1073,14 @@ cc_test(
     name = "ipc_test",
     srcs = ["ipc_test.cc"],
     copts = sapi_platform_copts(),
-    data = ["@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:ipc"],
+    data = ["//sandboxed_api/sandbox2/testcases:ipc"],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":comms",
         ":sandbox2",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:status_matchers",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1069,7 +1090,7 @@ cc_library(
     hdrs = ["testing.h"],
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
-    deps = ["@com_google_sandboxed_api//sandboxed_api:testing"],
+    deps = ["//sandboxed_api:testing"],
 )
 
 cc_test(
@@ -1079,14 +1100,14 @@ cc_test(
     deps = [
         ":policy",
         ":policybuilder",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1096,8 +1117,8 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":bpfdisassembler",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1107,10 +1128,10 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":bpf_evaluator",
-        "@com_google_absl//absl/status",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/status",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -1119,16 +1140,17 @@ cc_test(
     srcs = ["network_proxy_test.cc"],
     copts = sapi_platform_copts(),
     data = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/testcases:network_proxy",
+        "//sandboxed_api/sandbox2/testcases:network_proxy",
     ],
     tags = ["no_qemu_user_mode"],
     deps = [
         ":sandbox2",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/time",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2/allowlists:testonly_map_exec",
+        "//sandboxed_api/sandbox2/network_proxy:testing",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/time",
+        "@googletest//:gtest_main",
     ],
 )
diff --git a/sandboxed_api/sandbox2/CMakeLists.txt b/sandboxed_api/sandbox2/CMakeLists.txt
index c6d0047..2cc24af 100644
--- a/sandboxed_api/sandbox2/CMakeLists.txt
+++ b/sandboxed_api/sandbox2/CMakeLists.txt
@@ -18,42 +18,6 @@ add_subdirectory(unwind)
 add_subdirectory(util)
 add_subdirectory(network_proxy)
 
-# sandboxed_api/sandbox2:allow_all_syscalls
-add_library(sandbox2_allow_all_syscalls ${SAPI_LIB_TYPE}
-  allow_all_syscalls.h
-)
-add_library(sandbox2::allow_all_syscalls ALIAS sandbox2_allow_all_syscalls)
-target_link_libraries(sandbox2_allow_all_syscalls PRIVATE
-  sapi::base
-)
-
-# sandboxed_api/sandbox2:allow_map_exec
-add_library(sandbox2_allow_map_exec ${SAPI_LIB_TYPE}
-  allow_map_exec.h
-)
-add_library(sandbox2::allow_allow_map_exec ALIAS sandbox2_allow_map_exec)
-target_link_libraries(sandbox2_allow_map_exec PRIVATE
-  sapi::base
-)
-
-# sandboxed_api/sandbox2:allow_seccomp_speculation
-add_library(sandbox2_allow_seccomp_speculation ${SAPI_LIB_TYPE}
-  allow_seccomp_speculation.h
-)
-add_library(sandbox2::allow_seccomp_speculation ALIAS sandbox2_allow_seccomp_speculation)
-target_link_libraries(sandbox2_allow_seccomp_speculation PRIVATE
-  sapi::base
-)
-
-# sandboxed_api/sandbox2:allow_unrestricted_networking
-add_library(sandbox2_allow_unrestricted_networking ${SAPI_LIB_TYPE}
-  allow_unrestricted_networking.h
-)
-add_library(sandbox2::allow_unrestricted_networking ALIAS sandbox2_allow_unrestricted_networking)
-target_link_libraries(sandbox2_allow_unrestricted_networking PRIVATE
-  sapi::base
-)
-
 # sandboxed_api/sandbox2:bpfdisassembler
 add_library(sandbox2_bpfdisassembler ${SAPI_LIB_TYPE}
   bpfdisassembler.cc
@@ -206,6 +170,7 @@ target_link_libraries(sandbox2_policy
          sandbox2::bpf_helper
          sandbox2::bpfdisassembler
          sandbox2::regs
+         sandbox2::seccomp_unotify
          sandbox2::syscall
          sapi::base
          sapi::config
@@ -349,7 +314,9 @@ add_library(sandbox2_sandbox2 ${SAPI_LIB_TYPE}
 add_library(sandbox2::sandbox2 ALIAS sandbox2_sandbox2)
 target_link_libraries(sandbox2_sandbox2
   PRIVATE absl::core_headers
+          absl::check
           absl::flat_hash_set
+          absl::log
           absl::memory
           absl::optional
           absl::str_format
@@ -358,34 +325,35 @@ target_link_libraries(sandbox2_sandbox2
           sandbox2::monitor_ptrace
           sandbox2::monitor_unotify
           sapi::base
-  PUBLIC  absl::flat_hash_map
-          absl::status
-          absl::statusor
-          absl::time
-          sapi::config
-          sapi::fileops
-          sapi::temp_file
-          sandbox2::client
-          sandbox2::comms
-          sandbox2::executor
-          sandbox2::fork_client
-          sandbox2::global_forkserver
-          sandbox2::ipc
-          sandbox2::limits
-          sandbox2::logsink
-          sandbox2::monitor_base
-          sandbox2::mounts
-          sandbox2::mount_tree_proto
-          sandbox2::namespace
-          sandbox2::network_proxy_client
-          sandbox2::network_proxy_server
-          sandbox2::notify
-          sandbox2::policy
-          sandbox2::policybuilder
-          sandbox2::regs
-          sandbox2::result
-          sandbox2::syscall
-          sandbox2::util
+  PUBLIC absl::die_if_null
+         absl::flat_hash_map
+         absl::status
+         absl::statusor
+         absl::time
+         sapi::config
+         sapi::fileops
+         sapi::temp_file
+         sandbox2::client
+         sandbox2::comms
+         sandbox2::executor
+         sandbox2::fork_client
+         sandbox2::global_forkserver
+         sandbox2::ipc
+         sandbox2::limits
+         sandbox2::logsink
+         sandbox2::monitor_base
+         sandbox2::mounts
+         sandbox2::mount_tree_proto
+         sandbox2::namespace
+         sandbox2::network_proxy_client
+         sandbox2::network_proxy_server
+         sandbox2::notify
+         sandbox2::policy
+         sandbox2::policybuilder
+         sandbox2::regs
+         sandbox2::result
+         sandbox2::syscall
+         sandbox2::util
 )
 
 
@@ -523,7 +491,8 @@ target_link_libraries(sandbox2_monitor_unotify
           sandbox2::bpf_evaluator
           sandbox2::client
           sandbox2::forkserver_proto
-          sapi::config
+          sandbox2::seccomp_unotify
+          sandbox2::util
           sapi::status
   PUBLIC sandbox2::executor
          sandbox2::monitor_base
@@ -733,7 +702,8 @@ target_link_libraries(sandbox2_util
           sapi::base
           sapi::raw_logging
           sapi::status
-  PUBLIC absl::span
+  PUBLIC absl::log
+         absl::span
          absl::status
          absl::statusor
 )
@@ -744,6 +714,19 @@ target_compile_options(sandbox2_util PRIVATE
   -Wframe-larger-than=17000
 )
 
+# sandboxed_api/sandbox2:util_c
+add_library(sandbox2_util_c ${SAPI_LIB_TYPE}
+  util_c.cc
+  util_c.h
+)
+add_library(sandbox2::util_c ALIAS sandbox2_util_c)
+target_link_libraries(sandbox2_util_c
+  PRIVATE absl::statusor
+          absl::log
+          sandbox2::util
+          sapi::base
+)
+
 # sandboxed_api/sandbox2:buffer
 add_library(sandbox2_buffer ${SAPI_LIB_TYPE}
   buffer.cc
@@ -751,15 +734,13 @@ add_library(sandbox2_buffer ${SAPI_LIB_TYPE}
 )
 add_library(sandbox2::buffer ALIAS sandbox2_buffer)
 target_link_libraries(sandbox2_buffer
-  PRIVATE absl::core_headers
-          absl::memory
+  PRIVATE absl::memory
           absl::status
-          absl::strings
-          sapi::strerror
-          sandbox2::util
           sapi::base
-          sapi::status
-  PUBLIC absl::statusor
+          sandbox2::util
+  PUBLIC absl::core_headers
+         absl::statusor
+         sapi::fileops
 )
 
 # sandboxed_api/sandbox2:forkserver_proto
@@ -1048,6 +1029,7 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING)
   )
   add_dependencies(sandbox2_policy_test
     sandbox2::testcase_add_policy_on_syscalls
+    sandbox2::testcase_execveat
     sandbox2::testcase_malloc_system
     sandbox2::testcase_minimal
     sandbox2::testcase_minimal_dynamic
@@ -1056,6 +1038,7 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING)
   )
   target_link_libraries(sandbox2_policy_test PRIVATE
     absl::strings
+    sandbox2::allowlists_seccomp_speculation
     sandbox2::bpf_helper
     sapi::config
     sandbox2::sandbox2
diff --git a/sandboxed_api/sandbox2/allowlists/BUILD b/sandboxed_api/sandbox2/allowlists/BUILD
index 670d305..c8b1a3a 100644
--- a/sandboxed_api/sandbox2/allowlists/BUILD
+++ b/sandboxed_api/sandbox2/allowlists/BUILD
@@ -19,7 +19,7 @@
 # default visibility in a target (currently //visibility:public) with the
 # appropriate visibility list for your targets.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 licenses(["notice"])
 
diff --git a/sandboxed_api/sandbox2/buffer.cc b/sandboxed_api/sandbox2/buffer.cc
index 5f20709..c19d429 100644
--- a/sandboxed_api/sandbox2/buffer.cc
+++ b/sandboxed_api/sandbox2/buffer.cc
@@ -28,52 +28,52 @@
 #include "absl/status/status.h"
 #include "absl/status/statusor.h"
 #include "sandboxed_api/sandbox2/util.h"
+#include "sandboxed_api/util/fileops.h"
 
 namespace sandbox2 {
 
-// Creates a new Buffer that is backed by the specified file descriptor.
-absl::StatusOr<std::unique_ptr<Buffer>> Buffer::CreateFromFd(int fd) {
-  // Using `new` to access a non-public constructor.
-  auto buffer = absl::WrapUnique(new Buffer());
+using ::sapi::file_util::fileops::FDCloser;
 
+// Creates a new Buffer that is backed by the specified file descriptor.
+absl::StatusOr<std::unique_ptr<Buffer>> Buffer::CreateFromFd(FDCloser fd) {
   struct stat stat_buf;
-  if (fstat(fd, &stat_buf) != 0) {
+  if (fstat(fd.get(), &stat_buf) != 0) {
     return absl::ErrnoToStatus(errno, "Could not stat buffer fd");
   }
-  size_t size = stat_buf.st_size;
+  return CreateFromFd(std::move(fd), stat_buf.st_size);
+}
+
+absl::StatusOr<std::unique_ptr<Buffer>> Buffer::CreateFromFd(FDCloser fd,
+                                                             size_t size) {
   int prot = PROT_READ | PROT_WRITE;
   int flags = MAP_SHARED;
   off_t offset = 0;
-  buffer->buf_ =
-      reinterpret_cast<uint8_t*>(mmap(nullptr, size, prot, flags, fd, offset));
-  if (buffer->buf_ == MAP_FAILED) {
+  uint8_t* buf = reinterpret_cast<uint8_t*>(
+      mmap(nullptr, size, prot, flags, fd.get(), offset));
+  if (buf == MAP_FAILED) {
     return absl::ErrnoToStatus(errno, "Could not map buffer fd");
   }
-  buffer->fd_ = fd;
-  buffer->size_ = size;
-  return std::move(buffer);  // GCC 7 needs the move (C++ DR #1579)
+  // Using `new` to access a non-public constructor.
+  return absl::WrapUnique(new Buffer(std::move(fd), buf, size));
 }
 
 // Creates a new Buffer of the specified size, backed by a temporary file that
 // will be immediately deleted.
 absl::StatusOr<std::unique_ptr<Buffer>> Buffer::CreateWithSize(size_t size) {
-  int fd;
-  if (!util::CreateMemFd(&fd)) {
-    return absl::InternalError("Could not create buffer temp file");
+  absl::StatusOr<FDCloser> fd = util::CreateMemFd();
+  if (!fd.ok()) {
+    return fd.status();
   }
-  if (ftruncate(fd, size) != 0) {
+  if (ftruncate(fd->get(), size) != 0) {
     return absl::ErrnoToStatus(errno, "Could not extend buffer fd");
   }
-  return CreateFromFd(fd);
+  return CreateFromFd(*std::move(fd), size);
 }
 
 Buffer::~Buffer() {
   if (buf_ != nullptr) {
     munmap(buf_, size_);
   }
-  if (fd_ != -1) {
-    close(fd_);
-  }
 }
 
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/buffer.h b/sandboxed_api/sandbox2/buffer.h
index d2c15e9..a67e053 100644
--- a/sandboxed_api/sandbox2/buffer.h
+++ b/sandboxed_api/sandbox2/buffer.h
@@ -18,8 +18,11 @@
 #include <cstddef>
 #include <cstdint>
 #include <memory>
+#include <utility>
 
+#include "absl/base/macros.h"
 #include "absl/status/statusor.h"
+#include "sandboxed_api/util/fileops.h"
 
 namespace sandbox2 {
 
@@ -34,10 +37,18 @@ class Buffer final {
   Buffer(const Buffer&) = delete;
   Buffer& operator=(const Buffer&) = delete;
 
-  // Creates a new Buffer that is backed by the specified file descriptor.
-  // The Buffer takes ownership of the descriptor and will close it when
-  // destroyed.
-  static absl::StatusOr<std::unique_ptr<Buffer>> CreateFromFd(int fd);
+  // Creates a new Buffer that is backed by the specified file descriptor, size
+  // is determined by the size of the file.
+  static absl::StatusOr<std::unique_ptr<Buffer>> CreateFromFd(
+      sapi::file_util::fileops::FDCloser fd);
+  // Creates a new Buffer that is backed by the specified file descriptor with
+  // given size.
+  static absl::StatusOr<std::unique_ptr<Buffer>> CreateFromFd(
+      sapi::file_util::fileops::FDCloser fd, size_t size);
+  ABSL_DEPRECATE_AND_INLINE()
+  static absl::StatusOr<std::unique_ptr<Buffer>> CreateFromFd(int fd) {
+    return CreateFromFd(sapi::file_util::fileops::FDCloser(fd));
+  }
 
   // Creates a new Buffer of the specified size, backed by a temporary file that
   // will be immediately deleted.
@@ -50,13 +61,14 @@ class Buffer final {
   size_t size() const { return size_; }
 
   // Gets the file descriptor backing the buffer.
-  int fd() const { return fd_; }
+  int fd() const { return fd_.get(); }
 
  private:
-  Buffer() = default;
+  Buffer(sapi::file_util::fileops::FDCloser fd, uint8_t* buf, size_t size)
+      : buf_(buf), fd_(std::move(fd)), size_(size) {}
 
   uint8_t* buf_ = nullptr;
-  int fd_ = -1;
+  sapi::file_util::fileops::FDCloser fd_;
   size_t size_ = 0;
 };
 
diff --git a/sandboxed_api/sandbox2/buffer_test.cc b/sandboxed_api/sandbox2/buffer_test.cc
index 82e4c9d..8fff384 100644
--- a/sandboxed_api/sandbox2/buffer_test.cc
+++ b/sandboxed_api/sandbox2/buffer_test.cc
@@ -31,6 +31,7 @@
 #include "sandboxed_api/sandbox2/result.h"
 #include "sandboxed_api/sandbox2/sandbox2.h"
 #include "sandboxed_api/testing.h"
+#include "sandboxed_api/util/fileops.h"
 #include "sandboxed_api/util/status_matchers.h"
 
 namespace sandbox2 {
@@ -38,6 +39,7 @@ namespace {
 
 using ::sapi::CreateDefaultPermissiveTestPolicy;
 using ::sapi::GetTestSourcePath;
+using ::sapi::file_util::fileops::FDCloser;
 using ::testing::Eq;
 using ::testing::Ne;
 
@@ -50,7 +52,10 @@ TEST(BufferTest, TestImplementation) {
   for (int i = 0; i < kSize; i++) {
     raw_buf[i] = 'X';
   }
-  SAPI_ASSERT_OK_AND_ASSIGN(auto buffer2, Buffer::CreateFromFd(buffer->fd()));
+  int duped = dup(buffer->fd());
+  ASSERT_THAT(duped, Ne(-1));
+  SAPI_ASSERT_OK_AND_ASSIGN(auto buffer2,
+                            Buffer::CreateFromFd(FDCloser(duped)));
   uint8_t* raw_buf2 = buffer2->data();
   for (int i = 0; i < kSize; i++) {
     EXPECT_THAT(raw_buf2[i], Eq('X'));
@@ -74,7 +79,7 @@ TEST(BufferTest, TestWithSandboxeeMapFd) {
 
   // Map buffer as fd 3, but careful because MapFd closes the buffer fd and
   // we need to keep it since buffer uses it for mmap, so we must dup.
-  executor->ipc()->MapFd(dup(buffer->fd()), 3);
+  executor->ipc()->MapDupedFd(buffer->fd(), 3);
 
   Sandbox2 s2(std::move(executor), std::move(policy));
   auto result = s2.Run();
diff --git a/sandboxed_api/sandbox2/client.cc b/sandboxed_api/sandbox2/client.cc
index da4ab7e..2b4cb61 100644
--- a/sandboxed_api/sandbox2/client.cc
+++ b/sandboxed_api/sandbox2/client.cc
@@ -70,7 +70,7 @@ void InitSeccompUnotify(sock_fprog prog, Comms* comms,
   std::atomic<int> fd(-1);
   std::atomic<int> tid(-1);
 
-  std::thread th([comms, &fd, &tid]() {
+  std::thread th([comms, seccomp_extra_flags, &fd, &tid]() {
     int notify_fd = -1;
     while (notify_fd == -1) {
       notify_fd = fd.load(std::memory_order_seq_cst);
@@ -82,14 +82,15 @@ void InitSeccompUnotify(sock_fprog prog, Comms* comms,
         .len = 1,
         .filter = &filter,
     };
-    int result = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0,
-                         reinterpret_cast<uintptr_t>(&allow_prog));
+    int result =
+        syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, seccomp_extra_flags,
+                reinterpret_cast<uintptr_t>(&allow_prog));
     SAPI_RAW_PCHECK(result != -1, "setting seccomp filter");
     tid.store(syscall(__NR_gettid), std::memory_order_seq_cst);
   });
   th.detach();
   int result = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
-                       SECCOMP_FILTER_FLAG_NEW_LISTENER,
+                       SECCOMP_FILTER_FLAG_NEW_LISTENER | seccomp_extra_flags,
                        reinterpret_cast<uintptr_t>(&prog));
   SAPI_RAW_PCHECK(result != -1, "setting seccomp filter");
   fd.store(result, std::memory_order_seq_cst);
@@ -329,12 +330,14 @@ void Client::ApplyPolicyAndBecomeTracee() {
   uint32_t message;  // wait for confirmation
   SAPI_RAW_CHECK(comms_->RecvUint32(&message),
                  "receving confirmation from executor");
+  bool allow_speculation = message & kAllowSpeculationBit;
   uint32_t seccomp_extra_flags =
-      allow_speculation_ ? SECCOMP_FILTER_FLAG_SPEC_ALLOW : 0;
-  if (message == kSandbox2ClientUnotify) {
+      allow_speculation ? SECCOMP_FILTER_FLAG_SPEC_ALLOW : 0;
+  uint32_t monitor_type = message & kMonitorTypeMask;
+  if (monitor_type == kSandbox2ClientUnotify) {
     InitSeccompUnotify(prog, comms_, seccomp_extra_flags);
   } else {
-    SAPI_RAW_CHECK(message == kSandbox2ClientDone,
+    SAPI_RAW_CHECK(monitor_type == kSandbox2ClientPtrace,
                    "invalid confirmation from executor");
     InitSeccompRegular(prog, seccomp_extra_flags);
   }
diff --git a/sandboxed_api/sandbox2/client.h b/sandboxed_api/sandbox2/client.h
index 36168c4..4d08e4e 100644
--- a/sandboxed_api/sandbox2/client.h
+++ b/sandboxed_api/sandbox2/client.h
@@ -36,12 +36,19 @@ class Client {
   // Client is ready to be sandboxed.
   static constexpr uint32_t kClient2SandboxReady = 0x0A0B0C01;
 
-  // Sandbox is ready to monitor the sandboxee.
-  static constexpr uint32_t kSandbox2ClientDone = 0x0A0B0C02;
+  // Sandbox is ready to monitor the sandboxee. Used with PtraceMonitor.
+  static constexpr uint32_t kSandbox2ClientPtrace = 0x0A0B0C02;
 
-  // Sandboxee should setup seccomp_unotify and send back the FD.
+  // Sandboxee should setup seccomp_unotify and send back the FD. Used with
+  // UnotifyMonitor.
   static constexpr uint32_t kSandbox2ClientUnotify = 0x0A0B0C03;
 
+  // Allow speculation in the seccomp policy.
+  static constexpr uint32_t kAllowSpeculationBit = 0x10000000;
+
+  // Mask for the monitor type in the message.
+  static constexpr uint32_t kMonitorTypeMask = 0x0FFFFFFF;
+
   explicit Client(Comms* comms);
   virtual ~Client() = default;
 
@@ -112,8 +119,6 @@ class Client {
 
   void PrepareEnvironment(int* preserved_fd = nullptr);
   void EnableSandbox();
-
-  bool allow_speculation_ = false;
 };
 
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/comms.cc b/sandboxed_api/sandbox2/comms.cc
index efa809c..8bc05b9 100644
--- a/sandboxed_api/sandbox2/comms.cc
+++ b/sandboxed_api/sandbox2/comms.cc
@@ -204,7 +204,6 @@ void Comms::Terminate() {
   state_ = State::kTerminated;
 
   raw_comms_ = std::unique_ptr<RawComms>();
-  listening_comms_.reset();
 }
 
 bool Comms::SendTLV(uint32_t tag, size_t length, const void* value) {
@@ -253,6 +252,9 @@ bool Comms::SendTLV(uint32_t tag, size_t length, const void* value) {
 bool Comms::RecvString(std::string* v) {
   uint32_t tag;
   if (!RecvTLV(&tag, v)) {
+    if (IsConnected()) {
+      SAPI_RAW_LOG(ERROR, "RecvString failed for (%s)", name_.c_str());
+    }
     return false;
   }
 
@@ -272,6 +274,9 @@ bool Comms::SendString(const std::string& v) {
 bool Comms::RecvBytes(std::vector<uint8_t>* buffer) {
   uint32_t tag;
   if (!RecvTLV(&tag, buffer)) {
+    if (IsConnected()) {
+      SAPI_RAW_LOG(ERROR, "RecvBytes failed for (%s)", name_.c_str());
+    }
     return false;
   }
   if (tag != kTagBytes) {
@@ -338,10 +343,12 @@ bool Comms::RecvFD(int* fd) {
 
   ssize_t len = GetRawComms()->RawRecvMsg(&msg);
   if (len < 0) {
-    if (IsFatalError(errno)) {
+    bool fatal = IsFatalError(errno);
+    SAPI_RAW_PLOG(ERROR, "recvmsg(SCM_RIGHTS): %s error",
+                  fatal ? "fatal" : "normal");
+    if (fatal) {
       Terminate();
     }
-    SAPI_RAW_PLOG(ERROR, "recvmsg(SCM_RIGHTS)");
     return false;
   }
   if (len == 0) {
@@ -424,10 +431,12 @@ bool Comms::SendFD(int fd) {
     return false;
   }
   if (len < 0) {
-    if (IsFatalError(errno)) {
+    bool fatal = IsFatalError(errno);
+    SAPI_RAW_PLOG(ERROR, "sendmsg(SCM_RIGHTS): %s error",
+                  fatal ? "fatal" : "normal");
+    if (fatal) {
       Terminate();
     }
-    SAPI_RAW_PLOG(ERROR, "sendmsg(SCM_RIGHTS)");
     return false;
   }
   if (len != sizeof(tlv)) {
@@ -443,10 +452,7 @@ bool Comms::RecvProtoBuf(google::protobuf::MessageLite* message) {
   std::vector<uint8_t> bytes;
   if (!RecvTLV(&tag, &bytes)) {
     if (IsConnected()) {
-      SAPI_RAW_PLOG(ERROR, "RecvProtoBuf failed for (%s)", name_);
-    } else {
-      Terminate();
-      SAPI_RAW_VLOG(2, "Connection terminated (%s)", name_.c_str());
+      SAPI_RAW_LOG(ERROR, "RecvProtoBuf failed for (%s)", name_.c_str());
     }
     return false;
   }
@@ -526,8 +532,9 @@ bool Comms::Send(const void* data, size_t len) {
       return false;
     }
     if (s == -1) {
-      SAPI_RAW_PLOG(ERROR, "write");
-      if (IsFatalError(errno)) {
+      bool fatal = IsFatalError(errno);
+      SAPI_RAW_PLOG(ERROR, "write: %s error", fatal ? "fatal" : "normal");
+      if (fatal) {
         Terminate();
       }
       return false;
@@ -554,8 +561,9 @@ bool Comms::Recv(void* data, size_t len) {
   while (total_recv < len) {
     ssize_t s = GetRawComms()->RawRecv(&bytes[total_recv], len - total_recv);
     if (s == -1) {
-      SAPI_RAW_PLOG(ERROR, "read");
-      if (IsFatalError(errno)) {
+      bool fatal = IsFatalError(errno);
+      SAPI_RAW_PLOG(ERROR, "read: %s error", fatal ? "fatal" : "normal");
+      if (fatal) {
         Terminate();
       }
       return false;
diff --git a/sandboxed_api/sandbox2/comms.h b/sandboxed_api/sandbox2/comms.h
index b933737..0b344f1 100644
--- a/sandboxed_api/sandbox2/comms.h
+++ b/sandboxed_api/sandbox2/comms.h
@@ -50,7 +50,6 @@ class Message;
 namespace sandbox2 {
 
 class Client;
-class ListeningComms;
 
 class Comms {
  public:
@@ -69,6 +68,7 @@ class Comms {
   static constexpr uint32_t kTagString = 0x80000100;
   static constexpr uint32_t kTagBytes = 0x80000101;
   static constexpr uint32_t kTagProto2 = 0x80000102;
+  static constexpr uint32_t kTagBarrier = 0x80000103;
   static constexpr uint32_t kTagFd = 0X80000201;
 
   // Any payload size above this limit will LOG(WARNING).
@@ -169,6 +169,12 @@ class Comms {
   bool SendBool(bool v) { return SendGeneric(v, kTagBool); }
   bool RecvString(std::string* v);
   bool SendString(const std::string& v);
+  bool RecvBarrier() {
+    uint32_t tag;
+    size_t length;
+    return RecvTLV(&tag, &length, nullptr, 0, kTagBarrier);
+  }
+  bool SendBarrier() { return SendTLV(kTagBarrier, 0, nullptr); }
 
   bool RecvBytes(std::vector<uint8_t>* buffer);
   bool SendBytes(const uint8_t* v, size_t len);
@@ -198,7 +204,6 @@ class Comms {
     swap(abstract_uds_, other.abstract_uds_);
     swap(raw_comms_, other.raw_comms_);
     swap(state_, other.state_);
-    swap(listening_comms_, other.listening_comms_);
   }
 
   friend void swap(Comms& x, Comms& y) { return x.Swap(y); }
@@ -244,8 +249,6 @@ class Comms {
   bool abstract_uds_ = true;
   std::variant<std::unique_ptr<RawComms>, RawCommsFdImpl> raw_comms_;
 
-  std::unique_ptr<ListeningComms> listening_comms_;
-
   // State of the channel (enum), socket will have to be connected later on.
   State state_ = State::kUnconnected;
 
diff --git a/sandboxed_api/sandbox2/comms_test.cc b/sandboxed_api/sandbox2/comms_test.cc
index 557946c..b54532a 100644
--- a/sandboxed_api/sandbox2/comms_test.cc
+++ b/sandboxed_api/sandbox2/comms_test.cc
@@ -262,6 +262,20 @@ TEST(CommsTest, TestSendRecvEmptyTLV2) {
   HandleCommunication(a, b);
 }
 
+TEST(CommsTest, TestSendRecvBarrier) {
+  auto a = [](Comms* comms) {
+    // Waits for a barrier, and then sends one.
+    ASSERT_THAT(comms->RecvBarrier(), IsTrue());
+    ASSERT_THAT(comms->SendBarrier(), IsTrue());
+  };
+  auto b = [](Comms* comms) {
+    // Sends a barrier, and then waits for one.
+    ASSERT_THAT(comms->SendBarrier(), IsTrue());
+    ASSERT_THAT(comms->RecvBarrier(), IsTrue());
+  };
+  HandleCommunication(a, b);
+}
+
 TEST(CommsTest, TestSendRecvProto) {
   auto a = [](Comms* comms) {
     // Receive a ProtoBuf.
diff --git a/sandboxed_api/sandbox2/examples/crc4/BUILD b/sandboxed_api/sandbox2/examples/crc4/BUILD
index c7de51b..898200e 100644
--- a/sandboxed_api/sandbox2/examples/crc4/BUILD
+++ b/sandboxed_api/sandbox2/examples/crc4/BUILD
@@ -19,10 +19,10 @@
 # - Using sandbox2::Comms for data exchange (IPC)
 # - Test to ensure sandbox executor runs sandboxee without issue
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -34,18 +34,18 @@ cc_binary(
     copts = sapi_platform_copts(),
     data = [":crc4bin"],
     deps = [
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:namespaces",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/allowlists:namespaces",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -55,12 +55,12 @@ cc_binary(
     srcs = ["crc4bin.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:util",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/strings:string_view",
     ],
 )
 
@@ -74,10 +74,10 @@ cc_test(
         "no_qemu_user_mode",
     ],
     deps = [
-        "@com_google_absl//absl/log",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log",
+        "@googletest//:gtest_main",
     ],
 )
diff --git a/sandboxed_api/sandbox2/examples/custom_fork/BUILD b/sandboxed_api/sandbox2/examples/custom_fork/BUILD
index abc6a8a..7f9b204 100644
--- a/sandboxed_api/sandbox2/examples/custom_fork/BUILD
+++ b/sandboxed_api/sandbox2/examples/custom_fork/BUILD
@@ -16,10 +16,10 @@
 # - create a custom fork-server, which will prepare and fork a sandboxee
 #   from the current process
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -31,17 +31,17 @@ cc_binary(
     copts = sapi_platform_copts(),
     data = [":custom_fork_bin"],
     deps = [
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:fork_client",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:fork_client",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -51,13 +51,13 @@ cc_binary(
     srcs = ["custom_fork_bin.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:forkingclient",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:forkingclient",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/examples/network/BUILD b/sandboxed_api/sandbox2/examples/network/BUILD
index 75cb8c8..3046812 100644
--- a/sandboxed_api/sandbox2/examples/network/BUILD
+++ b/sandboxed_api/sandbox2/examples/network/BUILD
@@ -18,10 +18,10 @@
 # - strict syscall policy
 # - sandbox2::Comms for data exchange (IPC)
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -33,19 +33,19 @@ cc_binary(
     copts = sapi_platform_copts(),
     data = [":network_bin"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/network_proxy:testing",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -55,10 +55,10 @@ cc_binary(
     srcs = ["network_bin.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/strings:str_format",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/examples/network_proxy/BUILD b/sandboxed_api/sandbox2/examples/network_proxy/BUILD
index 929c059..a8e5993 100644
--- a/sandboxed_api/sandbox2/examples/network_proxy/BUILD
+++ b/sandboxed_api/sandbox2/examples/network_proxy/BUILD
@@ -14,10 +14,10 @@
 
 # The 'network proxy' example demonstrates how to use network proxy server.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -29,20 +29,20 @@ cc_binary(
     copts = sapi_platform_copts(),
     data = [":networkproxy_bin"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/network_proxy:testing",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -52,21 +52,21 @@ cc_binary(
     srcs = ["networkproxy_bin.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:client",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/network_proxy:client",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/strings:string_view",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/examples/static/BUILD b/sandboxed_api/sandbox2/examples/static/BUILD
index 2805feb..9a6f3e7 100644
--- a/sandboxed_api/sandbox2/examples/static/BUILD
+++ b/sandboxed_api/sandbox2/examples/static/BUILD
@@ -19,10 +19,10 @@
 # - communication with file descriptors and MapFd
 # - test to ensure sandbox executor runs sandboxee without issue
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -35,17 +35,17 @@ cc_binary(
     data = [":static_bin"],
     tags = ["no_qemu_user_mode"],
     deps = [
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/examples/tool/BUILD b/sandboxed_api/sandbox2/examples/tool/BUILD
index 7988299..80d3601 100644
--- a/sandboxed_api/sandbox2/examples/tool/BUILD
+++ b/sandboxed_api/sandbox2/examples/tool/BUILD
@@ -20,10 +20,10 @@
 # - set limits, wall time, filesystem checks, asynchronous run
 # - test to ensure sandbox executor runs sandboxee without issue
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -34,23 +34,23 @@ cc_binary(
     srcs = ["sandbox2tool.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/flags:usage",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:all_syscalls",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/sandbox2/allowlists:all_syscalls",
+        "//sandboxed_api/sandbox2/allowlists:unrestricted_networking",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/flags:usage",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/time",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/examples/zlib/BUILD b/sandboxed_api/sandbox2/examples/zlib/BUILD
index 72ce31b..e4800ce 100644
--- a/sandboxed_api/sandbox2/examples/zlib/BUILD
+++ b/sandboxed_api/sandbox2/examples/zlib/BUILD
@@ -12,10 +12,10 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -27,17 +27,17 @@ cc_binary(
     copts = sapi_platform_copts(),
     data = [":zpipe"],
     deps = [
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:bpf_helper",
-        "@com_google_sandboxed_api//sandboxed_api/util:runfiles",
+        "//sandboxed_api/sandbox2",
+        "//sandboxed_api/sandbox2/util:bpf_helper",
+        "//sandboxed_api/util:runfiles",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/executor.cc b/sandboxed_api/sandbox2/executor.cc
index 8bbe651..ee19e8e 100644
--- a/sandboxed_api/sandbox2/executor.cc
+++ b/sandboxed_api/sandbox2/executor.cc
@@ -177,6 +177,7 @@ std::unique_ptr<ForkClient> Executor::StartForkServer() {
   set_enable_sandbox_before_exec(false);
   absl::StatusOr<SandboxeeProcess> process = StartSubProcess(0);
   if (!process.ok()) {
+    LOG(ERROR) << "Failed to start fork server: " << process.status();
     return nullptr;
   }
   return std::make_unique<ForkClient>(process->main_pid, ipc_.comms());
diff --git a/sandboxed_api/sandbox2/executor.h b/sandboxed_api/sandbox2/executor.h
index fd33311..631a7c6 100644
--- a/sandboxed_api/sandbox2/executor.h
+++ b/sandboxed_api/sandbox2/executor.h
@@ -37,6 +37,10 @@
 
 namespace sandbox2 {
 
+// Forward declarations for friend declarations.
+class MonitorBase;
+class StackTracePeer;
+
 // The sandbox2::Executor class is responsible for both creating and executing
 // new processes which will be sandboxed.
 class Executor final {
@@ -102,7 +106,6 @@ class Executor final {
 
  private:
   friend class MonitorBase;
-  friend class PtraceMonitor;
   friend class StackTracePeer;
 
   // Internal constructor for executing libunwind on the given pid
diff --git a/sandboxed_api/sandbox2/forkserver.cc b/sandboxed_api/sandbox2/forkserver.cc
index 6ee13b0..8bcd00d 100644
--- a/sandboxed_api/sandbox2/forkserver.cc
+++ b/sandboxed_api/sandbox2/forkserver.cc
@@ -18,6 +18,7 @@
 
 #include <fcntl.h>
 #include <linux/filter.h>
+#include <linux/prctl.h>
 #include <linux/seccomp.h>
 #include <sched.h>
 #include <sys/prctl.h>
@@ -124,7 +125,8 @@ Pipe CreatePipe() {
   return {FDCloser(pfds[0]), FDCloser(pfds[1])};
 }
 
-ABSL_ATTRIBUTE_NORETURN void RunInitProcess(pid_t main_pid, FDCloser pipe_fd) {
+ABSL_ATTRIBUTE_NORETURN void RunInitProcess(pid_t main_pid, FDCloser pipe_fd,
+                                            bool allow_speculation) {
   if (prctl(PR_SET_NAME, "S2-INIT-PROC", 0, 0, 0) != 0) {
     SAPI_RAW_PLOG(WARNING, "prctl(PR_SET_NAME, 'S2-INIT-PROC')");
   }
@@ -157,13 +159,17 @@ ABSL_ATTRIBUTE_NORETURN void RunInitProcess(pid_t main_pid, FDCloser pipe_fd) {
       .filter = code.data(),
   };
 
+  uint32_t seccomp_extra_flags = 0;
+  if (allow_speculation) {
+    seccomp_extra_flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
+  }
   SAPI_RAW_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
                  "Denying new privs");
   SAPI_RAW_CHECK(prctl(PR_SET_KEEPCAPS, 0) == 0, "Dropping caps");
-  SAPI_RAW_CHECK(
-      syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
-              reinterpret_cast<uintptr_t>(&prog)) == 0,
-      "Enabling seccomp filter");
+  SAPI_RAW_CHECK(syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
+                         SECCOMP_FILTER_FLAG_TSYNC | seccomp_extra_flags,
+                         reinterpret_cast<uintptr_t>(&prog)) == 0,
+                 "Enabling seccomp filter");
 
   siginfo_t info;
   // Reap children.
@@ -324,7 +330,7 @@ void ForkServer::LaunchChild(const ForkRequest& request, int execve_fd,
       for (const auto& fd : *open_fds) {
         close(fd);
       }
-      RunInitProcess(child, std::move(status_fd));
+      RunInitProcess(child, std::move(status_fd), request.allow_speculation());
     }
     // Send sandboxee pid
     auto status = SendPid(signaling_fd.get());
@@ -335,7 +341,6 @@ void ForkServer::LaunchChild(const ForkRequest& request, int execve_fd,
   status_fd.Close();
 
   Client client(comms_);
-  client.allow_speculation_ = request.allow_speculation();
 
   // Prepare the arguments before sandboxing (if needed), as doing it after
   // sandoxing can cause syscall violations (e.g. related to memory management).
diff --git a/sandboxed_api/sandbox2/monitor_base.cc b/sandboxed_api/sandbox2/monitor_base.cc
index a9d82b9..fdb7e4c 100644
--- a/sandboxed_api/sandbox2/monitor_base.cc
+++ b/sandboxed_api/sandbox2/monitor_base.cc
@@ -128,12 +128,13 @@ void LogContainer(const std::vector<std::string>& container) {
 
 MonitorBase::MonitorBase(Executor* executor, Policy* policy, Notify* notify)
     : executor_(executor),
-      notify_(notify),
       policy_(policy),
+      notify_(notify),
       // NOLINTNEXTLINE clang-diagnostic-deprecated-declarations
       comms_(executor_->ipc()->comms()),
       ipc_(executor_->ipc()),
       uses_custom_forkserver_(executor_->fork_client_ != nullptr) {
+  wait_for_execveat_ = executor->enable_sandboxing_pre_execve_;
   // It's a pre-connected Comms channel, no need to accept new connection.
   CHECK(comms_->IsConnected());
   std::string path =
@@ -277,9 +278,18 @@ absl::Status MonitorBase::SendPolicy(const std::vector<sock_filter>& policy) {
   return absl::OkStatus();
 }
 
+bool MonitorBase::SendMonitorReadyMessageAndFlags(uint32_t monitor_type) {
+  uint32_t message = monitor_type;
+  if (policy_->allow_speculation_) {
+    message |= Client::kAllowSpeculationBit;
+  }
+  return comms_->SendUint32(message);
+}
+
 bool MonitorBase::InitSendPolicy() {
   bool user_notif = type_ == FORKSERVER_MONITOR_UNOTIFY;
-  auto policy = policy_->GetPolicy(user_notif);
+  auto policy =
+      policy_->GetPolicy(user_notif, executor_->enable_sandboxing_pre_execve_);
   absl::Status status = SendPolicy(std::move(policy));
   if (!status.ok()) {
     LOG(ERROR) << "Couldn't send policy: " << status;
diff --git a/sandboxed_api/sandbox2/monitor_base.h b/sandboxed_api/sandbox2/monitor_base.h
index 73e68b3..2bcd631 100644
--- a/sandboxed_api/sandbox2/monitor_base.h
+++ b/sandboxed_api/sandbox2/monitor_base.h
@@ -80,10 +80,27 @@ class MonitorBase {
   virtual void SetWallTimeLimit(absl::Duration limit) = 0;
 
  protected:
+  // Sends the policy to the client.
+  // Can be overridden by subclasses to save/modify policy before sending.
+  // Returns success/failure status.
+  virtual absl::Status SendPolicy(const std::vector<sock_filter>& policy);
+
+  bool wait_for_execveat() const { return wait_for_execveat_; }
+  void set_wait_for_execveat(bool wait_for_execve) {
+    wait_for_execveat_ = wait_for_execve;
+  }
+
   void OnDone();
+
+  // Sends a message to the client that we're ready to monitor it.
+  // The message contains the monitor type and final sandboxee mode flags
+  // (currently only flag to allow speculation for the seccomped process).
+  bool SendMonitorReadyMessageAndFlags(uint32_t monitor_type);
+
   // Sets basic info status and reason code in the result object.
   void SetExitStatusCode(Result::StatusEnum final_status,
                          uintptr_t reason_code);
+
   // Logs a SANDBOX VIOLATION message based on the registers and additional
   // explanation for the reason of the violation.
   void LogSyscallViolation(const Syscall& syscall) const;
@@ -103,8 +120,9 @@ class MonitorBase {
 
   // Internal objects, owned by the Sandbox2 object.
   Executor* executor_;
-  Notify* notify_;
   Policy* policy_;
+  Notify* notify_;
+
   // The sandboxee process.
   SandboxeeProcess process_;
   Result result_;
@@ -119,12 +137,6 @@ class MonitorBase {
   // Monitor type
   MonitorType type_ = FORKSERVER_MONITOR_PTRACE;
 
- protected:
-  // Sends Policy to the Client.
-  // Can be overridden by subclasses to save/modify policy before sending.
-  // Returns success/failure status.
-  virtual absl::Status SendPolicy(const std::vector<sock_filter>& policy);
-
  private:
   // Instantiates and sends Policy to the Client.
   // Returns success/failure status.
@@ -168,6 +180,9 @@ class MonitorBase {
 
   // Is the sandboxee forked from a custom forkserver?
   bool uses_custom_forkserver_;
+
+  // Are we waiting for the first execveat syscall?
+  bool wait_for_execveat_ = false;
 };
 
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/monitor_ptrace.cc b/sandboxed_api/sandbox2/monitor_ptrace.cc
index bda5c3a..500d227 100644
--- a/sandboxed_api/sandbox2/monitor_ptrace.cc
+++ b/sandboxed_api/sandbox2/monitor_ptrace.cc
@@ -138,8 +138,7 @@ void CompleteSyscall(pid_t pid, int signo) {
 }  // namespace
 
 PtraceMonitor::PtraceMonitor(Executor* executor, Policy* policy, Notify* notify)
-    : MonitorBase(executor, policy, notify),
-      wait_for_execve_(executor->enable_sandboxing_pre_execve_) {
+    : MonitorBase(executor, policy, notify) {
   if (executor_->limits()->wall_time_limit() != absl::ZeroDuration()) {
     auto deadline = absl::Now() + executor_->limits()->wall_time_limit();
     deadline_millis_.store(absl::ToUnixMillis(deadline),
@@ -151,13 +150,6 @@ PtraceMonitor::PtraceMonitor(Executor* executor, Policy* policy, Notify* notify)
       absl::GetFlag(FLAGS_sandbox2_monitor_ptrace_use_deadline_manager);
 }
 
-bool PtraceMonitor::IsActivelyMonitoring() {
-  // If we're still waiting for execve(), then we allow all syscalls.
-  return !wait_for_execve_;
-}
-
-void PtraceMonitor::SetActivelyMonitoring() { wait_for_execve_ = false; }
-
 void PtraceMonitor::SetAdditionalResultInfo(std::unique_ptr<Regs> regs) {
   pid_t pid = regs->pid();
   result_.SetRegs(std::move(regs));
@@ -346,7 +338,7 @@ void PtraceMonitor::Run() {
       // all remaining processes (if there are any) because of the
       // PTRACE_O_EXITKILL ptrace() flag.
       if (ret == process_.main_pid) {
-        if (IsActivelyMonitoring()) {
+        if (!wait_for_execveat()) {
           SetExitStatusCode(Result::OK, WEXITSTATUS(status));
         } else {
           SetExitStatusCode(Result::SETUP_ERROR, Result::FAILED_MONITOR);
@@ -623,8 +615,8 @@ bool PtraceMonitor::InitPtraceAttach() {
   // no matter what is the current state of the sandboxee, and it will allow for
   // our process to continue and unlock the sandboxee with the proper ptrace
   // event handling.
-  if (!comms_->SendUint32(Client::kSandbox2ClientDone)) {
-    LOG(ERROR) << "Couldn't send Client::kSandbox2ClientDone message";
+  if (!SendMonitorReadyMessageAndFlags(Client::kSandbox2ClientPtrace)) {
+    LOG(ERROR) << "Couldn't send Client::kSandbox2ClientPtrace message";
     return false;
   }
   return true;
@@ -632,7 +624,7 @@ bool PtraceMonitor::InitPtraceAttach() {
 
 void PtraceMonitor::ActionProcessSyscall(Regs* regs, const Syscall& syscall) {
   // If the sandboxing is not enabled yet, allow the first __NR_execveat.
-  if (syscall.nr() == __NR_execveat && !IsActivelyMonitoring()) {
+  if (syscall.nr() == __NR_execveat && wait_for_execveat()) {
     VLOG(1) << "[PERMITTED/BEFORE_EXECVEAT]: " << "SYSCALL ::: PID: "
             << regs->pid() << ", PROG: '" << util::GetProgName(regs->pid())
             << "' : " << syscall.GetDescription();
@@ -783,10 +775,10 @@ void PtraceMonitor::EventPtraceNewProcess(pid_t pid, int event_msg) {
 }
 
 void PtraceMonitor::EventPtraceExec(pid_t pid, int event_msg) {
-  if (!IsActivelyMonitoring()) {
+  if (wait_for_execveat()) {
     VLOG(1) << "PTRACE_EVENT_EXEC seen from PID: " << event_msg
             << ". SANDBOX ENABLED!";
-    SetActivelyMonitoring();
+    set_wait_for_execveat(false);
   } else {
     // ptrace doesn't issue syscall-exit-stops for successful execve/execveat
     // system calls. Check if the monitor wanted to inspect the syscall's return
@@ -920,7 +912,6 @@ void PtraceMonitor::StateProcessStopped(pid_t pid, int status) {
   }
 
   if (ABSL_PREDICT_FALSE(pid == process_.main_pid && should_dump_stack_ &&
-                         executor_->libunwind_sbox_for_pid_ == 0 &&
                          policy_->GetNamespace())) {
     auto stack_trace = [this,
                         pid]() -> absl::StatusOr<std::vector<std::string>> {
diff --git a/sandboxed_api/sandbox2/monitor_ptrace.h b/sandboxed_api/sandbox2/monitor_ptrace.h
index 25abecd..92110fc 100644
--- a/sandboxed_api/sandbox2/monitor_ptrace.h
+++ b/sandboxed_api/sandbox2/monitor_ptrace.h
@@ -155,8 +155,6 @@ class PtraceMonitor : public MonitorBase {
   bool timed_out_ = false;
   // Should we dump the main sandboxed PID's stack?
   bool should_dump_stack_ = false;
-  // Is the sandboxee actively monitored, or maybe we're waiting for execve()?
-  bool wait_for_execve_;
   // Syscalls that are running, whose result values we want to inspect.
   absl::flat_hash_map<pid_t, Syscall> syscalls_in_progress_;
   sigset_t sset_;
diff --git a/sandboxed_api/sandbox2/monitor_unotify.cc b/sandboxed_api/sandbox2/monitor_unotify.cc
index 4b25fc0..03ee044 100644
--- a/sandboxed_api/sandbox2/monitor_unotify.cc
+++ b/sandboxed_api/sandbox2/monitor_unotify.cc
@@ -1,10 +1,8 @@
 #include "sandboxed_api/sandbox2/monitor_unotify.h"
 
-#include <linux/audit.h>
 #include <linux/seccomp.h>
 #include <poll.h>
 #include <sys/eventfd.h>
-#include <sys/ioctl.h>
 #include <sys/ptrace.h>
 #include <sys/resource.h>
 #include <sys/sysinfo.h>
@@ -17,8 +15,6 @@
 #include <atomic>
 #include <cerrno>
 #include <cstdint>
-#include <cstdlib>
-#include <cstring>
 #include <memory>
 #include <string>
 #include <utility>
@@ -36,7 +32,6 @@
 #include "absl/time/clock.h"
 #include "absl/time/time.h"
 #include "absl/types/span.h"
-#include "sandboxed_api/config.h"
 #include "sandboxed_api/sandbox2/bpf_evaluator.h"
 #include "sandboxed_api/sandbox2/client.h"
 #include "sandboxed_api/sandbox2/executor.h"
@@ -45,69 +40,20 @@
 #include "sandboxed_api/sandbox2/notify.h"
 #include "sandboxed_api/sandbox2/policy.h"
 #include "sandboxed_api/sandbox2/result.h"
+#include "sandboxed_api/sandbox2/util.h"
+#include "sandboxed_api/sandbox2/util/seccomp_unotify.h"
 #include "sandboxed_api/util/fileops.h"
 #include "sandboxed_api/util/status_macros.h"
 #include "sandboxed_api/util/thread.h"
 
-#ifndef SECCOMP_RET_USER_NOTIF
-#define SECCOMP_RET_USER_NOTIF 0x7fc00000U /* notifies userspace */
-#endif
-
-#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
-#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1
-#endif
-
 #define DO_USER_NOTIF BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF)
 
-#ifndef SECCOMP_GET_NOTIF_SIZES
-#define SECCOMP_GET_NOTIF_SIZES 3
-
-struct seccomp_notif_sizes {
-  __u16 seccomp_notif;
-  __u16 seccomp_notif_resp;
-  __u16 seccomp_data;
-};
-#endif
-
-#ifndef SECCOMP_IOCTL_NOTIF_RECV
-#ifndef SECCOMP_IOWR
-#define SECCOMP_IOC_MAGIC '!'
-#define SECCOMP_IO(nr) _IO(SECCOMP_IOC_MAGIC, nr)
-#define SECCOMP_IOWR(nr, type) _IOWR(SECCOMP_IOC_MAGIC, nr, type)
-#endif
-
-// Flags for seccomp notification fd ioctl.
-#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
-#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
-#endif
-
 namespace sandbox2 {
 
 namespace {
 
 using ::sapi::file_util::fileops::FDCloser;
 
-int seccomp(unsigned int operation, unsigned int flags, void* args) {
-  return syscall(SYS_seccomp, operation, flags, args);
-}
-
-sapi::cpu::Architecture AuditArchToCPUArch(uint32_t arch) {
-  switch (arch) {
-    case AUDIT_ARCH_AARCH64:
-      return sapi::cpu::Architecture::kArm64;
-    case AUDIT_ARCH_ARM:
-      return sapi::cpu::Architecture::kArm;
-    case AUDIT_ARCH_X86_64:
-      return sapi::cpu::Architecture::kX8664;
-    case AUDIT_ARCH_I386:
-      return sapi::cpu::Architecture::kX86;
-    case AUDIT_ARCH_PPC64LE:
-      return sapi::cpu::Architecture::kPPC64LE;
-    default:
-      return sapi::cpu::Architecture::kUnknown;
-  }
-}
-
 absl::Status WaitForFdReadable(int fd, absl::Time deadline) {
   pollfd pfds[] = {
       {.fd = fd, .events = POLLIN},
@@ -202,53 +148,57 @@ void UnotifyMonitor::HandleViolation(const Syscall& syscall) {
                                      : ViolationType::kArchitectureSwitch;
   LogSyscallViolation(syscall);
   notify_->EventSyscallViolation(syscall, violation_type);
-  MaybeGetStackTrace(req_->pid, Result::VIOLATION);
+  MaybeGetStackTrace(syscall.pid(), Result::VIOLATION);
   SetExitStatusCode(Result::VIOLATION, syscall.nr());
   notify_->EventSyscallViolation(syscall, violation_type);
   result_.SetSyscall(std::make_unique<Syscall>(syscall));
   KillSandboxee();
 }
 
-void UnotifyMonitor::AllowSyscallViaUnotify() {
-  memset(resp_.get(), 0, resp_size_);
-  resp_->id = req_->id;
-  resp_->val = 0;
-  resp_->error = 0;
-  resp_->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
-  if (ioctl(seccomp_notify_fd_.get(), SECCOMP_IOCTL_NOTIF_SEND, resp_.get()) !=
-      0) {
-    if (errno == ENOENT) {
+void UnotifyMonitor::AllowSyscallViaUnotify(seccomp_notif req) {
+  if (!util::SeccompUnotify::IsContinueSupported()) {
+    LOG(ERROR)
+        << "SECCOMP_USER_NOTIF_FLAG_CONTINUE not supported by the kernel.";
+    SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_NOTIFY);
+    return;
+  }
+  if (absl::Status status = seccomp_unotify_.RespondContinue(req);
+      !status.ok()) {
+    if (absl::IsNotFound(status)) {
       VLOG(1) << "Unotify send failed with ENOENT";
     } else {
-      LOG_IF(ERROR, errno == EINVAL)
-          << "Unotify send failed with EINVAL. Likely "
-             "SECCOMP_USER_NOTIF_FLAG_CONTINUE unsupported by the kernel.";
       SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_NOTIFY);
     }
   }
 }
 
 void UnotifyMonitor::HandleUnotify() {
-  memset(req_.get(), 0, req_size_);
-  if (ioctl(seccomp_notify_fd_.get(), SECCOMP_IOCTL_NOTIF_RECV, req_.get()) !=
-      0) {
-    if (errno == ENOENT) {
+  absl::StatusOr<seccomp_notif> req_data = seccomp_unotify_.Receive();
+  if (!req_data.ok()) {
+    if (absl::IsNotFound(req_data.status())) {
       VLOG(1) << "Unotify recv failed with ENOENT";
     } else {
       SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_NOTIFY);
+      return;
     }
+  }
+  Syscall syscall(req_data->pid, req_data->data);
+  if (wait_for_execveat() && syscall.nr() == __NR_execveat &&
+      util::SeccompUnotify::IsContinueSupported()) {
+    VLOG(1) << "[PERMITTED/BEFORE_EXECVEAT]: " << "SYSCALL ::: PID: "
+            << syscall.pid() << ", PROG: '" << util::GetProgName(syscall.pid())
+            << "' : " << syscall.GetDescription();
+    set_wait_for_execveat(false);
+    AllowSyscallViaUnotify(*req_data);
     return;
   }
-  Syscall syscall(AuditArchToCPUArch(req_->data.arch), req_->data.nr,
-                  {req_->data.args[0], req_->data.args[1], req_->data.args[2],
-                   req_->data.args[3], req_->data.args[4], req_->data.args[5]},
-                  req_->pid, 0, req_->data.instruction_pointer);
   absl::StatusOr<uint32_t> policy_ret =
-      bpf::Evaluate(original_policy_, req_->data);
+      bpf::Evaluate(original_policy_, req_data->data);
   if (!policy_ret.ok()) {
     LOG(ERROR) << "Failed to evaluate policy: " << policy_ret.status();
     SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_NOTIFY);
   }
+
   const sock_filter trace_action = SANDBOX2_TRACE;
   bool should_trace = *policy_ret == trace_action.k;
   Notify::TraceAction trace_response = Notify::TraceAction::kDeny;
@@ -257,7 +207,7 @@ void UnotifyMonitor::HandleUnotify() {
   }
   switch (trace_response) {
     case Notify::TraceAction::kAllow:
-      AllowSyscallViaUnotify();
+      AllowSyscallViaUnotify(*req_data);
       return;
     case Notify::TraceAction::kDeny:
       HandleViolation(syscall);
@@ -290,7 +240,7 @@ void UnotifyMonitor::Run() {
 
   pollfd pfds[] = {
       {.fd = process_.status_fd.get(), .events = POLLIN},
-      {.fd = seccomp_notify_fd_.get(), .events = POLLIN},
+      {.fd = seccomp_unotify_.GetFd(), .events = POLLIN},
       {.fd = monitor_notify_fd_.get(), .events = POLLIN},
   };
   while (result_.final_status() == Result::UNSET) {
@@ -348,6 +298,7 @@ void UnotifyMonitor::Run() {
       break;
     }
     if (pfds[0].revents & POLLHUP) {
+      LOG(ERROR) << "Status pipe hangup";
       SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_MONITOR);
       break;
     }
@@ -391,12 +342,13 @@ void UnotifyMonitor::SetExitStatusFromStatusPipe() {
       SetExitStatusCode(Result::SIGNALED, status);
     }
   } else {
+    LOG(ERROR) << "Unexpected exit code: " << code;
     SetExitStatusCode(Result::INTERNAL_ERROR, Result::FAILED_MONITOR);
   }
 }
 
 bool UnotifyMonitor::InitSetupUnotify() {
-  if (!comms_->SendUint32(Client::kSandbox2ClientUnotify)) {
+  if (!SendMonitorReadyMessageAndFlags(Client::kSandbox2ClientUnotify)) {
     LOG(ERROR) << "Couldn't send Client::kSandbox2ClientUnotify message";
     return false;
   }
@@ -405,16 +357,10 @@ bool UnotifyMonitor::InitSetupUnotify() {
     LOG(ERROR) << "Couldn't recv unotify fd";
     return false;
   }
-  seccomp_notify_fd_ = FDCloser(fd);
-  struct seccomp_notif_sizes sizes = {};
-  if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
-    LOG(ERROR) << "Couldn't get seccomp_notif_sizes";
+  if (absl::Status status = seccomp_unotify_.Init(FDCloser(fd)); !status.ok()) {
+    LOG(ERROR) << "Could not init seccomp_unotify: " << status;
     return false;
   }
-  req_size_ = sizes.seccomp_notif;
-  req_.reset(static_cast<seccomp_notif*>(malloc(req_size_)));
-  resp_size_ = sizes.seccomp_notif_resp;
-  resp_.reset(static_cast<seccomp_notif_resp*>(malloc(resp_size_)));
   return true;
 }
 
diff --git a/sandboxed_api/sandbox2/monitor_unotify.h b/sandboxed_api/sandbox2/monitor_unotify.h
index 20b19b5..e90b5ad 100644
--- a/sandboxed_api/sandbox2/monitor_unotify.h
+++ b/sandboxed_api/sandbox2/monitor_unotify.h
@@ -10,7 +10,6 @@
 #include <atomic>
 #include <cstdint>
 #include <cstdlib>
-#include <memory>
 #include <string>
 #include <vector>
 
@@ -25,27 +24,12 @@
 #include "sandboxed_api/sandbox2/notify.h"
 #include "sandboxed_api/sandbox2/policy.h"
 #include "sandboxed_api/sandbox2/result.h"
+#include "sandboxed_api/sandbox2/util/seccomp_unotify.h"
 #include "sandboxed_api/util/fileops.h"
 #include "sandboxed_api/util/thread.h"
 
 namespace sandbox2 {
 
-#ifndef SECCOMP_IOCTL_NOTIF_RECV
-struct seccomp_notif {
-  __u64 id;
-  __u32 pid;
-  __u32 flags;
-  struct seccomp_data data;
-};
-
-struct seccomp_notif_resp {
-  __u64 id;
-  __s64 val;
-  __s32 error;
-  __u32 flags;
-};
-#endif
-
 class UnotifyMonitor : public MonitorBase {
  public:
   UnotifyMonitor(Executor* executor, Policy* policy, Notify* notify);
@@ -96,7 +80,7 @@ class UnotifyMonitor : public MonitorBase {
   bool KillSandboxee();
   void KillInit();
 
-  void AllowSyscallViaUnotify();
+  void AllowSyscallViaUnotify(seccomp_notif req);
   void HandleViolation(const Syscall& syscall);
   void HandleUnotify();
   void SetExitStatusFromStatusPipe();
@@ -108,7 +92,6 @@ class UnotifyMonitor : public MonitorBase {
   void NotifyMonitor();
 
   absl::Notification setup_notification_;
-  sapi::file_util::fileops::FDCloser seccomp_notify_fd_;
   sapi::file_util::fileops::FDCloser monitor_notify_fd_;
   // Original policy as configured by the user.
   std::vector<sock_filter> original_policy_;
@@ -132,10 +115,7 @@ class UnotifyMonitor : public MonitorBase {
   // Synchronizes monitor thread deletion and notifying the monitor.
   absl::Mutex notify_mutex_;
 
-  size_t req_size_;
-  std::unique_ptr<seccomp_notif, StdFreeDeleter> req_;
-  size_t resp_size_;
-  std::unique_ptr<seccomp_notif_resp, StdFreeDeleter> resp_;
+  util::SeccompUnotify seccomp_unotify_;
 };
 
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/network_proxy/BUILD b/sandboxed_api/sandbox2/network_proxy/BUILD
index aa0c59c..de4405f 100644
--- a/sandboxed_api/sandbox2/network_proxy/BUILD
+++ b/sandboxed_api/sandbox2/network_proxy/BUILD
@@ -12,10 +12,10 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -27,12 +27,12 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":filtering",
-        "@com_google_absl//absl/functional:any_invocable",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/functional:any_invocable",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
@@ -43,15 +43,15 @@ cc_library(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:syscall_trap",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/util:syscall_trap",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/synchronization",
     ],
 )
 
@@ -61,12 +61,12 @@ cc_library(
     hdrs = ["filtering.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -76,9 +76,9 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":filtering",
-        "@com_google_absl//absl/log:check",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/log:check",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -88,14 +88,14 @@ cc_library(
     hdrs = ["testing.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
diff --git a/sandboxed_api/sandbox2/network_proxy_test.cc b/sandboxed_api/sandbox2/network_proxy_test.cc
index a888998..84fcf12 100644
--- a/sandboxed_api/sandbox2/network_proxy_test.cc
+++ b/sandboxed_api/sandbox2/network_proxy_test.cc
@@ -25,6 +25,7 @@
 #include "gtest/gtest.h"
 #include "absl/status/status.h"
 #include "absl/time/time.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/sandbox2/executor.h"
 #include "sandboxed_api/sandbox2/network_proxy/testing.h"
 #include "sandboxed_api/sandbox2/policybuilder.h"
@@ -95,7 +96,7 @@ TEST_P(NetworkProxyTest, ProxyWithHandlerAllowed) {
   executor->limits()->set_walltime_limit(absl::Seconds(3));
 
   PolicyBuilder builder;
-  builder.AllowDynamicStartup()
+  builder.AllowDynamicStartup(sandbox2::MapExec())
       .AllowWrite()
       .AllowRead()
       .AllowExit()
@@ -143,7 +144,7 @@ TEST_P(NetworkProxyTest, ProxyWithHandlerNotAllowed) {
   executor->limits()->set_walltime_limit(absl::Seconds(3));
 
   PolicyBuilder builder;
-  builder.AllowDynamicStartup()
+  builder.AllowDynamicStartup(sandbox2::MapExec())
       .AllowWrite()
       .AllowRead()
       .AllowExit()
@@ -184,7 +185,7 @@ TEST_P(NetworkProxyTest, ProxyWithoutHandlerAllowed) {
   executor->limits()->set_walltime_limit(absl::Seconds(3));
 
   PolicyBuilder builder;
-  builder.AllowDynamicStartup()
+  builder.AllowDynamicStartup(sandbox2::MapExec())
       .AllowExit()
       .AllowWrite()
       .AllowRead()
@@ -228,7 +229,7 @@ TEST(NetworkProxyTest, ProxyNonExistantAddress) {
   executor->limits()->set_walltime_limit(absl::Seconds(3));
 
   PolicyBuilder builder;
-  builder.AllowDynamicStartup()
+  builder.AllowDynamicStartup(sandbox2::MapExec())
       .AllowExit()
       .AllowWrite()
       .AllowRead()
diff --git a/sandboxed_api/sandbox2/policy.cc b/sandboxed_api/sandbox2/policy.cc
index 0a5cac0..5142dd7 100644
--- a/sandboxed_api/sandbox2/policy.cc
+++ b/sandboxed_api/sandbox2/policy.cc
@@ -40,11 +40,31 @@
 #include "sandboxed_api/sandbox2/syscall.h"
 #include "sandboxed_api/sandbox2/util.h"
 #include "sandboxed_api/sandbox2/util/bpf_helper.h"
+#include "sandboxed_api/sandbox2/util/seccomp_unotify.h"
 
 #ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
 #define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
 #endif
 
+#ifndef BPF_MAP_LOOKUP_ELEM
+#define BPF_MAP_LOOKUP_ELEM 1
+#endif
+#ifndef BPF_OBJ_GET
+#define BPF_OBJ_GET 7
+#endif
+#ifndef BPF_MAP_GET_NEXT_KEY
+#define BPF_MAP_GET_NEXT_KEY 4
+#endif
+#ifndef BPF_MAP_GET_NEXT_ID
+#define BPF_MAP_GET_NEXT_ID 12
+#endif
+#ifndef BPF_MAP_GET_FD_BY_ID
+#define BPF_MAP_GET_FD_BY_ID 14
+#endif
+#ifndef BPF_OBJ_GET_INFO_BY_FD
+#define BPF_OBJ_GET_INFO_BY_FD 15
+#endif
+
 ABSL_FLAG(bool, sandbox2_danger_danger_permit_all, false,
           "Allow all syscalls, useful for testing");
 ABSL_FLAG(std::string, sandbox2_danger_danger_permit_all_and_log, "",
@@ -56,7 +76,8 @@ namespace sandbox2 {
 //   1. default policy (GetDefaultPolicy, private),
 //   2. user policy (user_policy_, public),
 //   3. default KILL action (avoid failing open if user policy did not do it).
-std::vector<sock_filter> Policy::GetPolicy(bool user_notif) const {
+std::vector<sock_filter> Policy::GetPolicy(
+    bool user_notif, bool enable_sandboxing_pre_execve) const {
   if (absl::GetFlag(FLAGS_sandbox2_danger_danger_permit_all) ||
       !absl::GetFlag(FLAGS_sandbox2_danger_danger_permit_all_and_log).empty()) {
     return GetTrackingPolicy();
@@ -64,7 +85,7 @@ std::vector<sock_filter> Policy::GetPolicy(bool user_notif) const {
 
   // Now we can start building the policy.
   // 1. Start with the default policy (e.g. syscall architecture checks).
-  auto policy = GetDefaultPolicy(user_notif);
+  auto policy = GetDefaultPolicy(user_notif, enable_sandboxing_pre_execve);
   VLOG(3) << "Default policy:\n" << bpf::Disasm(policy);
 
   // 2. Append user policy.
@@ -86,11 +107,16 @@ std::vector<sock_filter> Policy::GetPolicy(bool user_notif) const {
 // Produces a policy which returns SECCOMP_RET_TRACE instead of SECCOMP_RET_KILL
 // for the __NR_execve syscall, so the tracer can make a decision to allow or
 // disallow it depending on which occurrence of __NR_execve it was.
-std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
+std::vector<sock_filter> Policy::GetDefaultPolicy(
+    bool user_notif, bool enable_sandboxing_pre_execve) const {
   bpf_labels l = {0};
 
   std::vector<sock_filter> policy;
   if (user_notif) {
+    sock_filter execve_action = ALLOW;
+    if (util::SeccompUnotify::IsContinueSupported()) {
+      execve_action = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF);
+    }
     policy = {
         // If compiled arch is different from the runtime one, inform the
         // Monitor.
@@ -103,16 +129,21 @@ std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
         ALLOW,
         LABEL(&l, past_seccomp_l),
         LOAD_SYSCALL_NR,
-        JNE32(__NR_execveat, JUMP(&l, past_execveat_l)),
-        ARG_32(4),
-        JNE32(AT_EMPTY_PATH, JUMP(&l, past_execveat_l)),
-        ARG_32(5),
-        JNE32(internal::kExecveMagic, JUMP(&l, past_execveat_l)),
-        ALLOW,
-        LABEL(&l, past_execveat_l),
-
-        LOAD_SYSCALL_NR,
     };
+    if (enable_sandboxing_pre_execve) {
+      policy.insert(
+          policy.end(),
+          {
+              JNE32(__NR_execveat, JUMP(&l, past_execveat_l)),
+              ARG_32(4),
+              JNE32(AT_EMPTY_PATH, JUMP(&l, past_execveat_l)),
+              ARG_32(5),
+              JNE32(internal::kExecveMagic, JUMP(&l, past_execveat_l)),
+              execve_action,
+              LABEL(&l, past_execveat_l),
+              LOAD_SYSCALL_NR,
+          });
+    }
   } else {
     policy = {
         // If compiled arch is different from the runtime one, inform the
@@ -125,23 +156,28 @@ std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
         TRACE(sapi::cpu::kUnknown),
         LABEL(&l, past_arch_check_l),
 
-        // After the policy is uploaded, forkserver will execve the sandboxee.
-        // We need to allow this execve but not others. Since BPF does not have
-        // state, we need to inform the Monitor to decide, and for that we use a
-        // magic value in syscall args 5. Note that this value is not supposed
-        // to be secret, but just an optimization so that the monitor is not
-        // triggered on every call to execveat.
-        LOAD_SYSCALL_NR,
-        JNE32(__NR_execveat, JUMP(&l, past_execveat_l)),
-        ARG_32(4),
-        JNE32(AT_EMPTY_PATH, JUMP(&l, past_execveat_l)),
-        ARG_32(5),
-        JNE32(internal::kExecveMagic, JUMP(&l, past_execveat_l)),
-        SANDBOX2_TRACE,
-        LABEL(&l, past_execveat_l),
-
         LOAD_SYSCALL_NR,
     };
+    if (enable_sandboxing_pre_execve) {
+      // After the policy is uploaded, forkserver will execve the sandboxee.
+      // We need to allow this execve but not others. Since BPF does not have
+      // state, we need to inform the Monitor to decide, and for that we use a
+      // magic value in syscall args 5. Note that this value is not supposed
+      // to be secret, but just an optimization so that the monitor is not
+      // triggered on every call to execveat.
+      policy.insert(
+          policy.end(),
+          {
+              JNE32(__NR_execveat, JUMP(&l, past_execveat_l)),
+              ARG_32(4),
+              JNE32(AT_EMPTY_PATH, JUMP(&l, past_execveat_l)),
+              ARG_32(5),
+              JNE32(internal::kExecveMagic, JUMP(&l, past_execveat_l)),
+              SANDBOX2_TRACE,
+              LABEL(&l, past_execveat_l),
+              LOAD_SYSCALL_NR,
+          });
+    }
   }
 
   // Insert a custom syscall to signal the sandboxee it's running inside a
@@ -159,11 +195,26 @@ std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
     policy.insert(policy.end(), {JEQ32(__NR_ptrace, DENY)});
   }
 
-  // If user policy doesn't mention it, then forbid bpf because it's unsafe or
-  // too risky. This uses LOAD_SYSCALL_NR from above.
-  if (!user_policy_handles_bpf_) {
-    policy.insert(policy.end(), {JEQ32(__NR_bpf, DENY)});
-  }
+  // If user policy doesn't mention it, forbid bpf() because it's unsafe or too
+  // risky. Users can still allow safe invocations of this syscall by using
+  // PolicyBuilder::AllowSafeBpf(). This uses LOAD_SYSCALL_NR from above.
+    if (allow_safe_bpf_) {
+      policy.insert(policy.end(), {
+                                      JNE32(__NR_bpf, JUMP(&l, past_bpf_l)),
+                                      ARG_32(0),
+                                      JEQ32(BPF_MAP_LOOKUP_ELEM, ALLOW),
+                                      JEQ32(BPF_OBJ_GET, ALLOW),
+                                      JEQ32(BPF_MAP_GET_NEXT_KEY, ALLOW),
+                                      JEQ32(BPF_MAP_GET_NEXT_ID, ALLOW),
+                                      JEQ32(BPF_MAP_GET_FD_BY_ID, ALLOW),
+                                      JEQ32(BPF_OBJ_GET_INFO_BY_FD, ALLOW),
+                                      LABEL(&l, past_bpf_l),
+                                      LOAD_SYSCALL_NR,
+                                  });
+    }
+    if (!user_policy_handles_bpf_) {
+      policy.insert(policy.end(), {JEQ32(__NR_bpf, DENY)});
+    }
 
   if (!allow_map_exec_) {
     policy.insert(
@@ -197,8 +248,12 @@ std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
       CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWUTS |
       CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWPID;
   static_assert(kNewNamespacesFlags <= std::numeric_limits<uint32_t>::max());
-  constexpr uintptr_t kUnsafeCloneFlags = kNewNamespacesFlags | CLONE_UNTRACED;
-  static_assert(kUnsafeCloneFlags <= std::numeric_limits<uint32_t>::max());
+
+  static_assert(CLONE_UNTRACED <= std::numeric_limits<uint32_t>::max());
+  // For unotify monitor tracing is not used for policy enforcement, thus it's
+  // fine to allow CLONE_UNTRACED.
+  const uint32_t unsafe_clone_flags =
+      kNewNamespacesFlags | (user_notif ? 0 : CLONE_UNTRACED);
   policy.insert(policy.end(),
                 {
 #ifdef __NR_clone3
@@ -212,7 +267,7 @@ std::vector<sock_filter> Policy::GetDefaultPolicy(bool user_notif) const {
                     // Regardless of arch, we only care about the lower 32-bits
                     // of the flags.
                     ARG_32(0),
-                    JA32(kUnsafeCloneFlags, DENY),
+                    JA32(unsafe_clone_flags, DENY),
                     LABEL(&l, past_clone_unsafe_l),
                     // Disallow unshare with unsafe flags.
                     LOAD_SYSCALL_NR,
diff --git a/sandboxed_api/sandbox2/policy.h b/sandboxed_api/sandbox2/policy.h
index 99500a3..3a2380a 100644
--- a/sandboxed_api/sandbox2/policy.h
+++ b/sandboxed_api/sandbox2/policy.h
@@ -56,7 +56,8 @@ class Policy final {
 
   // Returns the policy, but modifies it according to FLAGS and internal
   // requirements (message passing via Comms, Executor::WaitForExecve etc.).
-  std::vector<sock_filter> GetPolicy(bool user_notif) const;
+  std::vector<sock_filter> GetPolicy(bool user_notif,
+                                     bool enable_sandboxing_pre_execve) const;
 
   const std::optional<Namespace>& GetNamespace() const { return namespace_; }
   const Namespace* GetNamespaceOrNull() const {
@@ -65,7 +66,8 @@ class Policy final {
 
   // Returns the default policy, which blocks certain dangerous syscalls and
   // mismatched syscall tables.
-  std::vector<sock_filter> GetDefaultPolicy(bool user_notif) const;
+  std::vector<sock_filter> GetDefaultPolicy(
+      bool user_notif, bool enable_sandboxing_pre_execve) const;
   // Returns a policy allowing the Monitor module to track all syscalls.
   std::vector<sock_filter> GetTrackingPolicy() const;
 
@@ -96,6 +98,7 @@ class Policy final {
   bool collect_stacktrace_on_exit_ = false;
 
   bool allow_map_exec_ = false;
+  bool allow_safe_bpf_ = false;
   bool allow_speculation_ = false;
 
   // The policy set by the user.
diff --git a/sandboxed_api/sandbox2/policy_test.cc b/sandboxed_api/sandbox2/policy_test.cc
index b4d5d0c..8695554 100644
--- a/sandboxed_api/sandbox2/policy_test.cc
+++ b/sandboxed_api/sandbox2/policy_test.cc
@@ -25,14 +25,19 @@
 
 #include "gmock/gmock.h"
 #include "gtest/gtest.h"
+#include "absl/log/check.h"
+#include "absl/strings/match.h"
 #include "absl/strings/string_view.h"
 #include "sandboxed_api/config.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
+#include "sandboxed_api/sandbox2/allowlists/seccomp_speculation.h"
 #include "sandboxed_api/sandbox2/executor.h"
 #include "sandboxed_api/sandbox2/policybuilder.h"
 #include "sandboxed_api/sandbox2/result.h"
 #include "sandboxed_api/sandbox2/sandbox2.h"
 #include "sandboxed_api/sandbox2/util/bpf_helper.h"
 #include "sandboxed_api/testing.h"
+#include "sandboxed_api/util/path.h"
 #include "sandboxed_api/util/status_matchers.h"
 
 namespace sandbox2 {
@@ -42,18 +47,45 @@ using ::sapi::CreateDefaultPermissiveTestPolicy;
 using ::sapi::GetTestSourcePath;
 using ::testing::Eq;
 
-#ifdef SAPI_X86_64
+std::string GetBinaryFromArgs(const std::vector<std::string>& args) {
+  return !absl::StrContains(args[0], "/")
+             ? GetTestSourcePath(
+                   sapi::file::JoinPath("sandbox2/testcases", args[0]))
+             : args[0];
+}
 
-// Test that 32-bit syscalls from 64-bit are disallowed.
-TEST(PolicyTest, AMD64Syscall32PolicyAllowed) {
-  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
+class PolicyTest : public ::testing::TestWithParam<bool> {
+ public:
+  std::unique_ptr<Sandbox2> CreateTestSandbox(
+      const std::vector<std::string>& args, PolicyBuilder builder,
+      bool sandbox_pre_execve = true) {
+    CHECK(!args.empty());
+    if (GetParam()) {
+      builder.CollectStacktracesOnSignal(false);
+    }
+    auto executor = std::make_unique<Executor>(GetBinaryFromArgs(args), args);
+    executor->set_enable_sandbox_before_exec(sandbox_pre_execve);
+    auto sandbox =
+        std::make_unique<Sandbox2>(std::move(executor), builder.BuildOrDie());
+    if (GetParam()) {
+      CHECK_OK(sandbox->EnableUnotifyMonitor());
+    }
+    return sandbox;
+  }
 
-  std::vector<std::string> args = {path, "1"};
+  std::unique_ptr<Sandbox2> CreatePermissiveTestSandbox(
+      std::vector<std::string> args, bool sandbox_pre_execve = true) {
+    return CreateTestSandbox(
+        args, CreateDefaultPermissiveTestPolicy(GetBinaryFromArgs(args)),
+        sandbox_pre_execve);
+  }
+};
+
+#ifdef SAPI_X86_64
 
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+// Test that 32-bit syscalls from 64-bit are disallowed.
+TEST_P(PolicyTest, AMD64Syscall32PolicyAllowed) {
+  Result result = CreatePermissiveTestSandbox({"policy", "1"})->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
   EXPECT_THAT(result.reason_code(), Eq(1));  // __NR_exit in 32-bit
@@ -61,101 +93,129 @@ TEST(PolicyTest, AMD64Syscall32PolicyAllowed) {
 }
 
 // Test that 32-bit syscalls from 64-bit for FS checks are disallowed.
-TEST(PolicyTest, AMD64Syscall32FsAllowed) {
-  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "2"};
-
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+TEST_P(PolicyTest, AMD64Syscall32FsAllowed) {
+  Result result = CreatePermissiveTestSandbox({"policy", "2"})->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
   EXPECT_THAT(result.reason_code(),
               Eq(33));  // __NR_access in 32-bit
   EXPECT_THAT(result.GetSyscallArch(), Eq(sapi::cpu::kX86));
 }
-#endif
 
-// Test that ptrace(2) is disallowed.
-TEST(PolicyTest, PtraceDisallowed) {
-  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "3"};
+#endif  // SAPI_X86_64
 
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+// Test that ptrace(2) is disallowed.
+TEST_P(PolicyTest, PtraceDisallowed) {
+  Result result = CreatePermissiveTestSandbox({"policy", "3"})->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
   EXPECT_THAT(result.reason_code(), Eq(__NR_ptrace));
 }
 
-// Test that clone(2) with flag CLONE_UNTRACED is disallowed.
-TEST(PolicyTest, CloneUntracedDisallowed) {
-  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "4"};
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+// Test that clone(2) with flag CLONE_UNTRACED is disallowed with PtraceMonitor.
+TEST_P(PolicyTest, CloneUntrace) {
+  Result result = CreatePermissiveTestSandbox({"policy", "4"})->Run();
 
-  ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
-  EXPECT_THAT(result.reason_code(), Eq(__NR_clone));
+  if (GetParam()) {
+    ASSERT_THAT(result.final_status(), Eq(Result::OK));
+    EXPECT_THAT(result.reason_code(), Eq(EXIT_FAILURE));
+  } else {
+    ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
+    EXPECT_THAT(result.reason_code(), Eq(__NR_clone));
+  }
 }
 
 // Test that bpf(2) is disallowed.
-TEST(PolicyTest, BpfDisallowed) {
-  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "5"};
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+TEST_P(PolicyTest, BpfDisallowed) {
+  Result result = CreatePermissiveTestSandbox({"policy", "5"})->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
   EXPECT_THAT(result.reason_code(), Eq(__NR_bpf));
 }
 
 // Test that ptrace/bpf can return EPERM.
-TEST(PolicyTest, BpfPtracePermissionDenied) {
+TEST_P(PolicyTest, BpfPtracePermissionDenied) {
   const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "7"};
-
-  SAPI_ASSERT_OK_AND_ASSIGN(
-      auto policy, CreateDefaultPermissiveTestPolicy(path)
-                       .BlockSyscallsWithErrno({__NR_ptrace, __NR_bpf}, EPERM)
-                       .TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {"policy", "7"},
+      CreateDefaultPermissiveTestPolicy(path).BlockSyscallsWithErrno(
+          {__NR_ptrace, __NR_bpf}, EPERM));
+  Result result = s2->Run();
 
-  // ptrace/bpf is not a violation due to explicit policy.  EPERM is expected.
+  // ptrace/bpf is not a violation due to explicit policy. EPERM is expected.
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
   EXPECT_THAT(result.reason_code(), Eq(0));
 }
 
-TEST(PolicyTest, IsattyAllowed) {
-  SKIP_SANITIZERS;
-  PolicyBuilder builder;
-  builder.AllowStaticStartup()
-      .AllowExit()
-      .AllowRead()
-      .AllowWrite()
-      .AllowTCGETS()
-      .AllowLlvmCoverage();
+// Test that we can allow safe uses of bpf().
+TEST_P(PolicyTest, BpfAllowSafe) {
   const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
-  std::vector<std::string> args = {path, "6"};
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy, builder.TryBuild());
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+  {
+    std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+        {"policy", "9"},  // Calls TestSafeBpf()
+        CreateDefaultPermissiveTestPolicy(path).AllowSafeBpf());
+    Result result = s2->Run();
+
+    ASSERT_THAT(result.final_status(), Eq(Result::OK));
+    EXPECT_THAT(result.reason_code(), Eq(0));
+  }
+  {
+    std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+        {"policy", "5"},  // Calls TestBpf()
+        CreateDefaultPermissiveTestPolicy(path).AllowSafeBpf());
+    Result result = s2->Run();
+
+    ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
+    EXPECT_THAT(result.reason_code(), Eq(__NR_bpf));
+  }
+}
+
+// Test that bpf can return EPERM even after AllowSafeBpf() is called.
+TEST_P(PolicyTest, BpfAllowSafeButBlock) {
+  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
+  {
+    std::unique_ptr<Sandbox2> s2 =
+        CreateTestSandbox({"policy", "8"},  // Calls TestBpfBlocked()
+                          CreateDefaultPermissiveTestPolicy(path)
+                              .AllowSafeBpf()
+                              .BlockSyscallWithErrno(__NR_bpf, EPERM));
+    Result result = s2->Run();
+
+    ASSERT_THAT(result.final_status(), Eq(Result::OK));
+    EXPECT_THAT(result.reason_code(), Eq(0));
+  }
+  {
+    std::unique_ptr<Sandbox2> s2 =
+        CreateTestSandbox({"policy", "9"},  // Calls TestSafeBpf()
+                          CreateDefaultPermissiveTestPolicy(path)
+                              .AllowSafeBpf()
+                              .BlockSyscallWithErrno(__NR_bpf, EPERM));
+    Result result = s2->Run();
+
+    ASSERT_THAT(result.final_status(), Eq(Result::OK));
+    EXPECT_THAT(result.reason_code(), Eq(0));
+  }
+}
+
+TEST_P(PolicyTest, IsattyAllowed) {
+  SKIP_SANITIZERS;
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({"policy", "6"}, PolicyBuilder()
+                                             .AllowStaticStartup()
+                                             .AllowExit()
+                                             .AllowRead()
+                                             .AllowWrite()
+                                             .AllowTCGETS()
+                                             .AllowLlvmCoverage());
+  Result result = s2->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
 }
 
-PolicyBuilder PosixTimersPolicyBuilder(absl::string_view path) {
+PolicyBuilder PosixTimersPolicyBuilder() {
   return PolicyBuilder()
       // Required by google infra / logging.
-      .AllowDynamicStartup()
+      .AllowDynamicStartup(sandbox2::MapExec())
       .AllowWrite()
       .AllowSyscall(__NR_getcwd)
       .AllowMmap()
@@ -175,114 +235,87 @@ PolicyBuilder PosixTimersPolicyBuilder(absl::string_view path) {
       .AllowPosixTimers();
 }
 
-TEST(PolicyTest, PosixTimersWorkIfAllowed) {
+TEST_P(PolicyTest, PosixTimersWorkIfAllowed) {
   SKIP_SANITIZERS;
-  const std::string path = GetTestSourcePath("sandbox2/testcases/posix_timers");
   for (absl::string_view kind : {"SIGEV_NONE", "SIGEV_SIGNAL",
                                  "SIGEV_THREAD_ID", "syscall(SIGEV_THREAD)"}) {
-    std::vector<std::string> args = {path, "--sigev_notify_kind",
-                                     std::string(kind)};
-
-    SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                              PosixTimersPolicyBuilder(path).TryBuild());
-    auto executor = std::make_unique<Executor>(path, args);
-    Sandbox2 sandbox(std::move(executor), std::move(policy));
-    Result result = sandbox.Run();
+    std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+        {"posix_timers", "--sigev_notify_kind", std::string(kind)},
+        PosixTimersPolicyBuilder());
+    Result result = s2->Run();
     EXPECT_EQ(result.final_status(), Result::OK) << kind;
   }
 }
 
-TEST(PolicyTest, PosixTimersCannotCreateThreadsIfThreadsAreProhibited) {
+TEST_P(PolicyTest, PosixTimersCannotCreateThreadsIfThreadsAreProhibited) {
   SKIP_SANITIZERS;
-  const std::string path = GetTestSourcePath("sandbox2/testcases/posix_timers");
-  std::vector<std::string> args = {
-      path,
-      // SIGEV_THREAD creates a thread as an implementation detail.
-      "--sigev_notify_kind=SIGEV_THREAD",
-  };
-
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            PosixTimersPolicyBuilder(path).TryBuild());
-  auto executor = std::make_unique<Executor>(path, args);
-  Sandbox2 sandbox(std::move(executor), std::move(policy));
-  Result result = sandbox.Run();
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {"posix_timers",
+       // SIGEV_THREAD creates a thread as an implementation detail.
+       "--sigev_notify_kind=SIGEV_THREAD"},
+      PosixTimersPolicyBuilder());
+  Result result = s2->Run();
   EXPECT_EQ(result.final_status(), Result::VIOLATION);
 }
 
-TEST(PolicyTest, PosixTimersCanCreateThreadsIfThreadsAreAllowed) {
+TEST_P(PolicyTest, PosixTimersCanCreateThreadsIfThreadsAreAllowed) {
   SKIP_SANITIZERS;
-  const std::string path = GetTestSourcePath("sandbox2/testcases/posix_timers");
-  std::vector<std::string> args = {path, "--sigev_notify_kind=SIGEV_THREAD"};
-
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy, PosixTimersPolicyBuilder(path)
-                                             .AllowFork()
-                                             // For Arm.
-                                             .AllowSyscall(__NR_madvise)
-                                             .TryBuild());
-  auto executor = std::make_unique<Executor>(path, args);
-  Sandbox2 sandbox(std::move(executor), std::move(policy));
-  Result result = sandbox.Run();
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({"posix_timers", "--sigev_notify_kind=SIGEV_THREAD"},
+                        PosixTimersPolicyBuilder()
+                            .AllowFork()
+                            // For Arm.
+                            .AllowSyscall(__NR_madvise));
+  Result result = s2->Run();
   EXPECT_EQ(result.final_status(), Result::OK);
 }
 
-std::unique_ptr<Policy> MinimalTestcasePolicy(absl::string_view path = "") {
-  PolicyBuilder builder;
-  builder.AllowStaticStartup().AllowExit().AllowLlvmCoverage();
-  return builder.BuildOrDie();
+PolicyBuilder MinimalTestcasePolicyBuilder() {
+  return PolicyBuilder().AllowStaticStartup().AllowExit().AllowLlvmCoverage();
 }
 
 // Test that we can sandbox a minimal static binary returning 0.
 // If this starts failing, it means something changed, maybe in the way we
 // compile static binaries, and we need to update the policy just above.
-TEST(MinimalTest, MinimalBinaryWorks) {
+TEST_P(PolicyTest, MinimalBinaryWorks) {
   SKIP_SANITIZERS;
-  const std::string path = GetTestSourcePath("sandbox2/testcases/minimal");
-  std::vector<std::string> args = {path};
-  Sandbox2 s2(std::make_unique<Executor>(path, args),
-              MinimalTestcasePolicy(path));
-  auto result = s2.Run();
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({"minimal"}, MinimalTestcasePolicyBuilder());
+  Result result = s2->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
   EXPECT_THAT(result.reason_code(), Eq(EXIT_SUCCESS));
 }
 
 // Test that we can sandbox a minimal non-static binary returning 0.
-TEST(MinimalTest, MinimalSharedBinaryWorks) {
+TEST_P(PolicyTest, MinimalSharedBinaryWorks) {
   SKIP_SANITIZERS;
   const std::string path =
       GetTestSourcePath("sandbox2/testcases/minimal_dynamic");
-  std::vector<std::string> args = {path};
-
-  PolicyBuilder builder;
-  builder.AddLibrariesForBinary(path)
-      .AllowDynamicStartup()
-      .AllowExit()
-      .AllowLlvmCoverage();
-  auto policy = builder.BuildOrDie();
-
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({path}, PolicyBuilder()
+                                    .AddLibrariesForBinary(path)
+                                    .AllowDynamicStartup(sandbox2::MapExec())
+                                    .AllowExit()
+                                    .AllowLlvmCoverage());
+  Result result = s2->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
   EXPECT_THAT(result.reason_code(), Eq(EXIT_SUCCESS));
 }
 
 // Test that the AllowSystemMalloc helper works as expected.
-TEST(MallocTest, SystemMallocWorks) {
+TEST_P(PolicyTest, SystemMallocWorks) {
   SKIP_SANITIZERS;
   const std::string path =
       GetTestSourcePath("sandbox2/testcases/malloc_system");
-  std::vector<std::string> args = {path};
-
-  PolicyBuilder builder;
-  builder.AllowStaticStartup()
-      .AllowSystemMalloc()
-      .AllowExit()
-      .AllowLlvmCoverage();
-  auto policy = builder.BuildOrDie();
-
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({path}, PolicyBuilder()
+                                    .AllowStaticStartup()
+                                    .AllowSystemMalloc()
+                                    .AllowExit()
+                                    .AllowLlvmCoverage());
+  Result result = s2->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
   EXPECT_THAT(result.reason_code(), Eq(EXIT_SUCCESS));
@@ -293,76 +326,126 @@ TEST(MallocTest, SystemMallocWorks) {
 // almost correct, but that the jump targets were off slightly. This uses the
 // AddPolicyOnSyscall multiple times in a row to make any miscalculation
 // unlikely to pass this check.
-TEST(MultipleSyscalls, AddPolicyOnSyscallsWorks) {
+TEST_P(PolicyTest, AddPolicyOnSyscallsWorks) {
   SKIP_SANITIZERS_AND_COVERAGE;
   const std::string path =
       GetTestSourcePath("sandbox2/testcases/add_policy_on_syscalls");
-  std::vector<std::string> args = {path};
-
-  PolicyBuilder builder;
-  builder.AllowStaticStartup()
-      .AllowTcMalloc()
-      .AllowExit()
-      .AddPolicyOnSyscalls(
-          {
-              __NR_getuid,
-              __NR_getgid,
-              __NR_geteuid,
-              __NR_getegid,
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {path}, PolicyBuilder()
+                  .AllowStaticStartup()
+                  .AllowTcMalloc()
+                  .AllowExit()
+                  .AddPolicyOnSyscalls(
+                      {
+                          __NR_getuid,
+                          __NR_getgid,
+                          __NR_geteuid,
+                          __NR_getegid,
 #ifdef __NR_getuid32
-              __NR_getuid32,
+                          __NR_getuid32,
 #endif
 #ifdef __NR_getgid32
-              __NR_getgid32,
+                          __NR_getgid32,
 #endif
 #ifdef __NR_geteuid32
-              __NR_geteuid32,
+                          __NR_geteuid32,
 #endif
 #ifdef __NR_getegid32
-              __NR_getegid32,
+                          __NR_getegid32,
 #endif
-          },
-          {ALLOW})
-      .AddPolicyOnSyscalls(
-          {
-              __NR_getresuid,
-              __NR_getresgid,
+                      },
+                      {ALLOW})
+                  .AddPolicyOnSyscalls(
+                      {
+                          __NR_getresuid,
+                          __NR_getresgid,
 #ifdef __NR_getresuid32
-              __NR_getresuid32,
+                          __NR_getresuid32,
 #endif
 #ifdef __NR_getresgid32
-              __NR_getresgid32,
+                          __NR_getresgid32,
 #endif
-          },
-          {ERRNO(42)})
-      .AddPolicyOnSyscalls({__NR_write}, {ERRNO(43)})
-      .AddPolicyOnSyscall(__NR_umask, {DENY});
-  auto policy = builder.BuildOrDie();
-
-  Sandbox2 s2(std::make_unique<Executor>(path, args), std::move(policy));
-  auto result = s2.Run();
+                      },
+                      {ERRNO(42)})
+                  .AddPolicyOnSyscalls({__NR_write}, {ERRNO(43)})
+                  .AddPolicyOnSyscall(__NR_umask, {DENY}));
+  Result result = s2->Run();
 
   ASSERT_THAT(result.final_status(), Eq(Result::VIOLATION));
   EXPECT_THAT(result.reason_code(), Eq(__NR_umask));
 }
 
 // Test that util::kMagicSyscallNo is returns ENOSYS or util::kMagicSyscallErr.
-TEST(PolicyTest, DetectSandboxSyscall) {
+TEST_P(PolicyTest, DetectSandboxSyscall) {
   const std::string path =
       GetTestSourcePath("sandbox2/testcases/sandbox_detection");
-  std::vector<std::string> args = {path};
+  std::unique_ptr<Sandbox2> s2 =
+      CreatePermissiveTestSandbox({path}, /*sandbox_pre_execve=*/false);
+  Result result = s2->Run();
+
+  // The test binary should exit with success.
+  ASSERT_THAT(result.final_status(), Eq(Result::OK));
+  EXPECT_THAT(result.reason_code(), Eq(0));
+}
+
+TEST_P(PolicyTest, ExecveatNotAllowedByDefault) {
+  const std::string path = GetTestSourcePath("sandbox2/testcases/execveat");
+
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {path, "1"},
+      CreateDefaultPermissiveTestPolicy(path).BlockSyscallWithErrno(
+          __NR_execveat, EPERM),
+      /*sandbox_pre_execve=*/false);
+  Result result = s2->Run();
+
+  // The test binary should exit with success.
+  ASSERT_THAT(result.final_status(), Eq(Result::OK));
+  EXPECT_THAT(result.reason_code(), Eq(0));
+}
+
+TEST_P(PolicyTest, SecondExecveatNotAllowedByDefault) {
+  const std::string path = GetTestSourcePath("sandbox2/testcases/execveat");
 
-  SAPI_ASSERT_OK_AND_ASSIGN(auto policy,
-                            CreateDefaultPermissiveTestPolicy(path).TryBuild());
-  auto executor = std::make_unique<Executor>(path, args);
-  executor->set_enable_sandbox_before_exec(false);
-  Sandbox2 s2(std::move(executor), std::move(policy));
-  auto result = s2.Run();
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {path, "2"},
+      CreateDefaultPermissiveTestPolicy(path).BlockSyscallWithErrno(
+          __NR_execveat, EPERM));
+  Result result = s2->Run();
 
   // The test binary should exit with success.
   ASSERT_THAT(result.final_status(), Eq(Result::OK));
   EXPECT_THAT(result.reason_code(), Eq(0));
 }
 
+#ifdef SAPI_X86_64
+TEST_P(PolicyTest, SpeculationAllowed) {
+  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
+  std::unique_ptr<Sandbox2> s2 = CreateTestSandbox(
+      {"policy", "11"},  // Calls TestSpeculationAllowed()
+      CreateDefaultPermissiveTestPolicy(path).Allow(SeccompSpeculation()));
+  Result result = s2->Run();
+
+  ASSERT_THAT(result.final_status(), Eq(Result::OK));
+  EXPECT_THAT(result.reason_code(), Eq(0));
+}
+
+TEST_P(PolicyTest, SpeculationBlockedByDefault) {
+  const std::string path = GetTestSourcePath("sandbox2/testcases/policy");
+  std::unique_ptr<Sandbox2> s2 =
+      CreateTestSandbox({"policy", "12"},  // Calls TestSpeculationBlocked()
+                        CreateDefaultPermissiveTestPolicy(path));
+  Result result = s2->Run();
+
+  ASSERT_THAT(result.final_status(), Eq(Result::OK));
+  EXPECT_THAT(result.reason_code(), Eq(0));
+}
+#endif  // SAPI_X86_64
+
+INSTANTIATE_TEST_SUITE_P(Sandbox2, PolicyTest, ::testing::Values(false, true),
+                         [](const ::testing::TestParamInfo<bool>& info) {
+                           return info.param ? "UnotifyMonitor"
+                                             : "PtraceMonitor";
+                         });
+
 }  // namespace
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/policybuilder.cc b/sandboxed_api/sandbox2/policybuilder.cc
index cdc9dd7..e282d8d 100644
--- a/sandboxed_api/sandbox2/policybuilder.cc
+++ b/sandboxed_api/sandbox2/policybuilder.cc
@@ -42,7 +42,6 @@
 #include <memory>
 #include <optional>
 #include <string>
-#include <type_traits>
 #include <utility>
 #include <vector>
 
@@ -57,6 +56,7 @@
 #include "absl/types/span.h"
 #include "sandboxed_api/config.h"
 #include "sandboxed_api/sandbox2/allowlists/all_syscalls.h"
+#include "sandboxed_api/sandbox2/allowlists/map_exec.h"
 #include "sandboxed_api/sandbox2/allowlists/namespaces.h"
 #include "sandboxed_api/sandbox2/allowlists/seccomp_speculation.h"
 #include "sandboxed_api/sandbox2/allowlists/trace_all_syscalls.h"
@@ -76,34 +76,17 @@
 #include <asm/termbits.h>  // On PPC, TCGETS macro needs termios
 #endif
 
-#ifndef BPF_MAP_LOOKUP_ELEM
-#define BPF_MAP_LOOKUP_ELEM 1
-#endif
-#ifndef BPF_OBJ_GET
-#define BPF_OBJ_GET 7
-#endif
-#ifndef BPF_MAP_GET_NEXT_KEY
-#define BPF_MAP_GET_NEXT_KEY 4
-#endif
-#ifndef BPF_MAP_GET_NEXT_ID
-#define BPF_MAP_GET_NEXT_ID 12
-#endif
-#ifndef BPF_MAP_GET_FD_BY_ID
-#define BPF_MAP_GET_FD_BY_ID 14
-#endif
-#ifndef BPF_OBJ_GET_INFO_BY_FD
-#define BPF_OBJ_GET_INFO_BY_FD 15
-#endif
-
 #ifndef MAP_FIXED_NOREPLACE
-#define MAP_FIXED_NOREPLACE 0x100000
+#define MAP_FIXED_NOREPLACE 0x100000  // Linux 4.17+
 #endif
+
 #ifndef MADV_POPULATE_READ
 #define MADV_POPULATE_READ 22  // Linux 5.14+
 #endif
 #ifndef MADV_POPULATE_WRITE  // Linux 5.14+
 #define MADV_POPULATE_WRITE 23
 #endif
+
 #ifndef PR_SET_VMA
 #define PR_SET_VMA 0x53564d41
 #endif
@@ -256,11 +239,13 @@ PolicyBuilder& PolicyBuilder::BlockSyscallWithErrno(uint32_t num, int error) {
   if (handled_syscalls_.insert(num).second &&
       blocked_syscalls_.insert(num).second) {
     user_policy_.insert(user_policy_.end(), {SYSCALL(num, ERRNO(error))});
-    if (num == __NR_bpf) {
-      user_policy_handles_bpf_ = true;
-    }
-    if (num == __NR_ptrace) {
-      user_policy_handles_ptrace_ = true;
+    switch (num) {
+      case __NR_bpf:
+        user_policy_handles_bpf_ = true;
+        break;
+      case __NR_ptrace:
+        user_policy_handles_ptrace_ = true;
+        break;
     }
   }
   return *this;
@@ -493,7 +478,7 @@ PolicyBuilder& PolicyBuilder::AllowLlvmSanitizers() {
   AllowSyscall(__NR_sched_getaffinity);
   // https://github.com/llvm/llvm-project/blob/3cabbf60393cc8d55fe635e35e89e5973162de33/compiler-rt/lib/interception/interception.h#L352
 #ifdef __ELF__
-  AllowDynamicStartup();
+  AllowDynamicStartup(MapExec());
 #endif
   // https://github.com/llvm/llvm-project/blob/02c2b472b510ff55679844c087b66e7837e13dc2/compiler-rt/lib/sanitizer_common/sanitizer_linux.cpp#L434
 #ifdef __NR_readlink
@@ -557,14 +542,16 @@ PolicyBuilder& PolicyBuilder::AllowLimitedMadvise() {
     return *this;
   }
   allowed_complex_.limited_madvise = true;
-  return AddPolicyOnSyscall(__NR_madvise, {
-                                              ARG_32(2),
-                                              JEQ32(MADV_SEQUENTIAL, ALLOW),
-                                              JEQ32(MADV_DONTNEED, ALLOW),
-                                              JEQ32(MADV_REMOVE, ALLOW),
-                                              JEQ32(MADV_HUGEPAGE, ALLOW),
-                                              JEQ32(MADV_NOHUGEPAGE, ALLOW),
-                                          });
+  return AddPolicyOnSyscall(
+      __NR_madvise, {
+                        ARG_32(2),
+                        JEQ32(MADV_SEQUENTIAL, ALLOW),
+                        JEQ32(MADV_DONTNEED, ALLOW),
+                        JEQ32(MADV_REMOVE, ALLOW),
+                        JEQ32(MADV_HUGEPAGE, ALLOW),
+                        JEQ32(MADV_NOHUGEPAGE, ALLOW),
+                        JEQ32(MADV_DONTDUMP, ALLOW),
+                    });
 }
 
 PolicyBuilder& PolicyBuilder::AllowMadvisePopulate() {
@@ -604,9 +591,14 @@ PolicyBuilder& PolicyBuilder::AllowMprotectWithoutExec() {
                      });
 }
 
-std::enable_if_t<builder_internal::is_type_complete_v<MapExec>, PolicyBuilder&>
-PolicyBuilder::AllowMmap() {
-  return AllowSyscalls(kMmapSyscalls);
+PolicyBuilder& PolicyBuilder::AllowMprotect(MapExec) {
+  return Allow(MapExec()).AllowSyscall(__NR_mprotect);
+}
+
+PolicyBuilder& PolicyBuilder::AllowMmap() { return AllowMmap(MapExec()); }
+
+PolicyBuilder& PolicyBuilder::AllowMmap(MapExec) {
+  return Allow(MapExec()).AllowSyscalls(kMmapSyscalls);
 }
 
 PolicyBuilder& PolicyBuilder::AllowMlock() {
@@ -832,20 +824,8 @@ PolicyBuilder& PolicyBuilder::AllowUtime() {
 }
 
 PolicyBuilder& PolicyBuilder::AllowSafeBpf() {
-  if (allowed_complex_.safe_bpf) {
-    return *this;
-  }
-  allowed_complex_.safe_bpf = true;
-  user_policy_handles_bpf_ = true;
-  return AddPolicyOnSyscall(__NR_bpf, {
-                                          ARG_32(1),
-                                          JEQ32(BPF_MAP_LOOKUP_ELEM, ALLOW),
-                                          JEQ32(BPF_OBJ_GET, ALLOW),
-                                          JEQ32(BPF_MAP_GET_NEXT_KEY, ALLOW),
-                                          JEQ32(BPF_MAP_GET_NEXT_ID, ALLOW),
-                                          JEQ32(BPF_MAP_GET_FD_BY_ID, ALLOW),
-                                          JEQ32(BPF_OBJ_GET_INFO_BY_FD, ALLOW),
-                                      });
+  allow_safe_bpf_ = true;
+  return *this;
 }
 
 PolicyBuilder& PolicyBuilder::AllowSafeFcntl() {
@@ -1284,13 +1264,12 @@ PolicyBuilder& PolicyBuilder::AllowStaticStartup() {
   return *this;
 }
 
-std::enable_if_t<builder_internal::is_type_complete_v<MapExec>, PolicyBuilder&>
-PolicyBuilder::AllowDynamicStartup() {
-  if (!allow_map_exec_) {
-    SetError(absl::FailedPreconditionError(
-        "Allowing dynamic startup requires Allow(MapExec)."));
-    return *this;
-  }
+PolicyBuilder& PolicyBuilder::AllowDynamicStartup() {
+  return AllowDynamicStartup(MapExec());
+}
+
+PolicyBuilder& PolicyBuilder::AllowDynamicStartup(MapExec) {
+  Allow(MapExec());
   if (allowed_complex_.dynamic_startup) {
     return *this;
   }
@@ -1477,13 +1456,13 @@ absl::StatusOr<std::unique_ptr<Policy>> PolicyBuilder::TryBuild() {
                      " > ", kMaxUserPolicyLength, ")."));
   }
 
-  // Using `new` to access a non-public constructor.
-  auto policy = absl::WrapUnique(new Policy());
-
   if (already_built_) {
     return absl::FailedPreconditionError("Can only build policy once.");
   }
 
+  // Using `new` to access a non-public constructor.
+  auto policy = absl::WrapUnique(new Policy());
+
   if (use_namespaces_) {
     // If no specific netns mode is set, default to per-sandboxee.
     if (netns_mode_ == NETNS_MODE_UNSPECIFIED) {
@@ -1498,6 +1477,7 @@ absl::StatusOr<std::unique_ptr<Policy>> PolicyBuilder::TryBuild() {
   }
 
   policy->allow_map_exec_ = allow_map_exec_;
+  policy->allow_safe_bpf_ = allow_safe_bpf_;
   policy->allow_speculation_ = allow_speculation_;
   policy->collect_stacktrace_on_signal_ = collect_stacktrace_on_signal_;
   policy->collect_stacktrace_on_violation_ = collect_stacktrace_on_violation_;
diff --git a/sandboxed_api/sandbox2/policybuilder.h b/sandboxed_api/sandbox2/policybuilder.h
index a5827b4..c4bf24d 100644
--- a/sandboxed_api/sandbox2/policybuilder.h
+++ b/sandboxed_api/sandbox2/policybuilder.h
@@ -21,8 +21,8 @@
 #include <cstdint>
 #include <functional>
 #include <memory>
+#include <optional>
 #include <string>
-#include <type_traits>
 #include <utility>
 #include <vector>
 
@@ -49,20 +49,11 @@ class AllowAllSyscalls;
 class NamespacesToken;
 class LoadUserBpfCodeFromFile;
 class MapExec;
+class UnsafeCoreDumpPtrace;
 class SeccompSpeculation;
 class TraceAllSyscalls;
 class UnrestrictedNetworking;
 
-namespace builder_internal {
-
-template <typename, typename = void>
-constexpr bool is_type_complete_v = false;
-
-template <typename T>
-constexpr bool is_type_complete_v<T, std::void_t<decltype(sizeof(T))>> = true;
-
-}  // namespace builder_internal
-
 // PolicyBuilder is a helper class to simplify creation of policies. The builder
 // uses fluent interface for convenience and increased readability of policies.
 //
@@ -334,18 +325,19 @@ class PolicyBuilder final {
   // Appends code to unconditionally allow mmap. Specifically this allows mmap
   // and mmap2 syscall on architectures where these syscalls exist.
   //
-  // This function requires that targets :map_exec library to be linked
-  // against. Otherwise, the PolicyBuilder will fail to build the policy.
-  //
   // Prefer using `AllowMmapWithoutExec()` as allowing mapping executable pages
   // makes exploitation easier.
-  std::enable_if_t<builder_internal::is_type_complete_v<MapExec>,
-                   PolicyBuilder&>
-  AllowMmap();
+  PolicyBuilder& AllowMmap(MapExec);
+
+  ABSL_DEPRECATED("Use AllowMmap(MapExec) or AllowMmapWithoutExec() instead.")
+  PolicyBuilder& AllowMmap();
 
   // Appends code to allow mmap calls that don't specify PROT_EXEC.
   PolicyBuilder& AllowMmapWithoutExec();
 
+  // Appends code to allow mprotect (also with PROT_EXEC).
+  PolicyBuilder& AllowMprotect(MapExec);
+
   // Appends code to allow mprotect calls that don't specify PROT_EXEC.
   PolicyBuilder& AllowMprotectWithoutExec();
 
@@ -706,9 +698,10 @@ class PolicyBuilder final {
   //
   // In addition to syscalls allowed by `AllowStaticStartup`, also allow
   // reading, seeking, mmap()-ing and closing files.
-  std::enable_if_t<builder_internal::is_type_complete_v<MapExec>,
-                   PolicyBuilder&>
-  AllowDynamicStartup();
+  PolicyBuilder& AllowDynamicStartup(MapExec);
+
+  ABSL_DEPRECATED("Use AllowDynamicStartup(MapExec) instead.")
+  PolicyBuilder& AllowDynamicStartup();
 
   // Appends a policy, which will be run on the specified syscall.
   //
@@ -779,7 +772,11 @@ class PolicyBuilder final {
   //
   // NOTE: This function will abort if an error happened in any of the
   // PolicyBuilder methods. This should only be called once.
-  std::unique_ptr<Policy> BuildOrDie() { return TryBuild().value(); }
+  std::unique_ptr<Policy> BuildOrDie() {
+    absl::StatusOr<std::unique_ptr<Policy>> policy = TryBuild();
+    CHECK_OK(policy);
+    return *std::move(policy);
+  }
 
   // Adds a bind-mount for a file from outside the namespace to inside.
   //
@@ -1017,6 +1014,7 @@ class PolicyBuilder final {
   bool requires_namespaces_ = false;
   NetNsMode netns_mode_ = NETNS_MODE_UNSPECIFIED;
   bool allow_map_exec_ = true;  //  Temporary default while we migrate users.
+  bool allow_safe_bpf_ = false;
   bool allow_speculation_ = false;
   bool allow_mount_propagation_ = false;
   std::string hostname_ = std::string(kDefaultHostname);
@@ -1055,7 +1053,6 @@ class PolicyBuilder final {
     bool madvise_populate = false;
     bool mmap_without_exec = false;
     bool mprotect_without_exec = false;
-    bool safe_bpf = false;
     bool safe_fcntl = false;
     bool tcgets = false;
     bool slow_fences = false;
diff --git a/sandboxed_api/sandbox2/policybuilder_test.cc b/sandboxed_api/sandbox2/policybuilder_test.cc
index bf25dd2..c9bee48 100644
--- a/sandboxed_api/sandbox2/policybuilder_test.cc
+++ b/sandboxed_api/sandbox2/policybuilder_test.cc
@@ -247,6 +247,12 @@ TEST(PolicyBuilderTest, CannotBypassBpf) {
   EXPECT_THAT(builder.TryBuild(), Not(IsOk()));
 }
 
+TEST(PolicyBuilderTest, AllowSafeBpf) {
+  PolicyBuilder builder;
+  builder.AllowSafeBpf();
+  EXPECT_THAT(builder.TryBuild(), IsOk());
+}
+
 TEST(PolicyBuilderTest, CannotBypassAfterAllowSafeBpf) {
   PolicyBuilder builder;
   builder.AllowSafeBpf().AddPolicyOnSyscall(__NR_bpf, {ALLOW});
@@ -290,5 +296,6 @@ TEST(PolicyBuilderTest, TestAllowLlvmCoverageWithoutCoverageDir) {
   EXPECT_THAT(builder.TryBuild(), IsOk());
   ASSERT_THAT(unsetenv("COVERAGE"), Eq(0));
 }
+
 }  // namespace
 }  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/sandbox2.cc b/sandboxed_api/sandbox2/sandbox2.cc
index 13fa1bc..2351ea8 100644
--- a/sandboxed_api/sandbox2/sandbox2.cc
+++ b/sandboxed_api/sandbox2/sandbox2.cc
@@ -46,6 +46,9 @@ class Sandbox2Peer : public internal::SandboxPeer {
   Sandbox2Peer(std::unique_ptr<Executor> executor,
                std::unique_ptr<Policy> policy)
       : sandbox_(std::move(executor), std::move(policy)) {
+    if (absl::Status status = sandbox_.EnableUnotifyMonitor(); !status.ok()) {
+      LOG(WARNING) << "Failed to enable unotify monitor: " << status;
+    }
     sandbox_.RunAsync();
   }
 
diff --git a/sandboxed_api/sandbox2/sandbox2.h b/sandboxed_api/sandbox2/sandbox2.h
index 11e1ed4..892fb07 100644
--- a/sandboxed_api/sandbox2/sandbox2.h
+++ b/sandboxed_api/sandbox2/sandbox2.h
@@ -18,13 +18,11 @@
 #ifndef SANDBOXED_API_SANDBOX2_SANDBOX2_H_
 #define SANDBOXED_API_SANDBOX2_SANDBOX2_H_
 
-#include <ctime>
 #include <memory>
 #include <utility>
 
 #include "absl/base/attributes.h"
-#include "absl/base/macros.h"
-#include "absl/log/check.h"
+#include "absl/log/die_if_null.h"
 #include "absl/status/status.h"
 #include "absl/status/statusor.h"
 #include "absl/time/time.h"
@@ -45,12 +43,9 @@ class Sandbox2 final {
 
   Sandbox2(std::unique_ptr<Executor> executor, std::unique_ptr<Policy> policy,
            std::unique_ptr<Notify> notify)
-      : executor_(std::move(executor)),
-        policy_(std::move(policy)),
-        notify_(std::move(notify)) {
-    CHECK(executor_ != nullptr);
-    CHECK(policy_ != nullptr);
-  }
+      : executor_(std::move(ABSL_DIE_IF_NULL(executor))),
+        policy_(std::move(ABSL_DIE_IF_NULL(policy))),
+        notify_(std::move(notify)) {}
 
   Sandbox2(const Sandbox2&) = delete;
   Sandbox2& operator=(const Sandbox2&) = delete;
@@ -66,6 +61,7 @@ class Sandbox2 final {
   // Even if set-up fails AwaitResult can still used to get a more specific
   // failure reason.
   bool RunAsync();
+
   // Waits for sandbox execution to finish and returns the execution result.
   ABSL_MUST_USE_RESULT Result AwaitResult();
 
@@ -75,8 +71,8 @@ class Sandbox2 final {
   absl::StatusOr<Result> AwaitResultWithTimeout(absl::Duration timeout);
 
   // Requests termination of the sandboxee.
-  // Sandbox should still waited with AwaitResult(), as it may finish for other
-  // reason before the request is handled.
+  // The sandbox should still waited on using AwaitResult(), as it may finish
+  // for other reasons before the request is handled.
   void Kill();
 
   // Dumps the main sandboxed process's stack trace to log.
@@ -85,7 +81,7 @@ class Sandbox2 final {
   // Returns whether sandboxing task has ended.
   bool IsTerminated() const;
 
-  // Sets a wall time limit on a running sandboxee, absl::ZeroDuration() to
+  // Sets a wall time limit on a running sandboxee. Use absl::ZeroDuration() to
   // disarm. This can be useful in a persistent sandbox scenario, to impose a
   // deadline for responses after each request and reset the deadline in
   // between. Sandboxed API can be used to implement persistent sandboxes.
@@ -94,7 +90,7 @@ class Sandbox2 final {
   // Returns the process id inside the executor.
   pid_t pid() const { return monitor_ != nullptr ? monitor_->pid() : -1; }
 
-  // Gets the comms inside the executor.
+  // Returns the comms object from the executor.
   Comms* comms() {
     return executor_ != nullptr ? executor_->ipc()->comms() : nullptr;
   }
@@ -107,16 +103,9 @@ class Sandbox2 final {
 
   std::unique_ptr<MonitorBase> CreateMonitor();
 
-  // Executor set by user - owned by Sandbox2.
   std::unique_ptr<Executor> executor_;
-
-  // Seccomp policy set by the user - owned by Sandbox2.
-  std::unique_ptr<Policy> policy_;
-
-  // Notify object - owned by Sandbox2.
+  std::unique_ptr<Policy> policy_;  // Seccomp user policy
   std::unique_ptr<Notify> notify_;
-
-  // Monitor object - owned by Sandbox2.
   std::unique_ptr<MonitorBase> monitor_;
 
   bool use_unotify_monitor_ = false;
diff --git a/sandboxed_api/sandbox2/stack_trace.cc b/sandboxed_api/sandbox2/stack_trace.cc
index 30837c6..8bace2a 100644
--- a/sandboxed_api/sandbox2/stack_trace.cc
+++ b/sandboxed_api/sandbox2/stack_trace.cc
@@ -173,6 +173,9 @@ absl::StatusOr<std::unique_ptr<Policy>> StackTracePeer::GetPolicy(
       .AllowLlvmCoverage()
       .AllowLlvmSanitizers();
 
+  // Disable stack trace collection on signals, so we can use unotify monitor.
+  builder.CollectStacktracesOnSignal(false);
+
   return builder.TryBuild();
 }
 
@@ -203,12 +206,11 @@ absl::StatusOr<std::vector<std::string>> StackTracePeer::LaunchLibunwindSandbox(
     return absl::InternalError(
         "Could not create temporary directory for unwinding");
   }
-  struct UnwindTempDirectoryCleanup {
-    ~UnwindTempDirectoryCleanup() {
-      file_util::fileops::DeleteRecursively(capture);
+  absl::Cleanup delete_unwind_temp_directory = [&unwind_temp_directory] {
+    if (!file_util::fileops::DeleteRecursively(unwind_temp_directory)) {
+      LOG(ERROR) << "Failed to delete " << unwind_temp_directory;
     }
-    char* capture;
-  } cleanup{unwind_temp_directory};
+  };
 
   // Copy over important files from the /proc directory as we can't mount them.
   const std::string unwind_temp_maps_path =
diff --git a/sandboxed_api/sandbox2/stack_trace_test.cc b/sandboxed_api/sandbox2/stack_trace_test.cc
index 281d12e..7edb09f 100644
--- a/sandboxed_api/sandbox2/stack_trace_test.cc
+++ b/sandboxed_api/sandbox2/stack_trace_test.cc
@@ -53,7 +53,7 @@ class StackTraceTestPeer {
   std::unique_ptr<internal::SandboxPeer> SpawnFn(
       std::unique_ptr<Executor> executor, std::unique_ptr<Policy> policy) {
     if (crash_unwind_) {
-      policy = PolicyBuilder().BuildOrDie();
+      policy = PolicyBuilder().CollectStacktracesOnSignal(false).BuildOrDie();
       crash_unwind_ = false;
     }
     return old_spawn_fn_(std::move(executor), std::move(policy));
@@ -270,6 +270,14 @@ TEST(StackTraceTest, RecursiveStackTrace) {
   EXPECT_THAT(result.final_status(), Eq(Result::SIGNALED));
 }
 
+TEST(StackTraceTest, SymbolizationEnablesMonitor) {
+  absl::ScopedMockLog log;
+  EXPECT_CALL(log, Log(_, _, StartsWith("Failed to enable unotify monitor")))
+      .Times(0);
+  log.StartCapturingLogs();
+  SymbolizationWorksCommon({});
+}
+
 INSTANTIATE_TEST_SUITE_P(
     Instantiation, StackTraceTest,
     ::testing::Values(
diff --git a/sandboxed_api/sandbox2/syscall.cc b/sandboxed_api/sandbox2/syscall.cc
index bd42f64..54062bf 100644
--- a/sandboxed_api/sandbox2/syscall.cc
+++ b/sandboxed_api/sandbox2/syscall.cc
@@ -15,6 +15,7 @@
 #include "sandboxed_api/sandbox2/syscall.h"
 
 #include <linux/audit.h>
+#include <linux/seccomp.h>
 
 #include <cstdint>
 #include <string>
@@ -31,6 +32,34 @@
 #endif
 
 namespace sandbox2 {
+namespace {
+
+sapi::cpu::Architecture AuditArchToCPUArch(uint32_t arch) {
+  switch (arch) {
+    case AUDIT_ARCH_AARCH64:
+      return sapi::cpu::Architecture::kArm64;
+    case AUDIT_ARCH_ARM:
+      return sapi::cpu::Architecture::kArm;
+    case AUDIT_ARCH_X86_64:
+      return sapi::cpu::Architecture::kX8664;
+    case AUDIT_ARCH_I386:
+      return sapi::cpu::Architecture::kX86;
+    case AUDIT_ARCH_PPC64LE:
+      return sapi::cpu::Architecture::kPPC64LE;
+    default:
+      return sapi::cpu::Architecture::kUnknown;
+  }
+}
+}  // namespace
+
+Syscall::Syscall(pid_t pid, const seccomp_data& data)
+    : arch_(AuditArchToCPUArch(data.arch)),
+      nr_(data.nr),
+      args_({data.args[0], data.args[1], data.args[2], data.args[3],
+             data.args[4], data.args[5]}),
+      pid_(pid),
+      sp_(0),
+      ip_(data.instruction_pointer) {}
 
 std::string Syscall::GetArchDescription(sapi::cpu::Architecture arch) {
   switch (arch) {
diff --git a/sandboxed_api/sandbox2/syscall.h b/sandboxed_api/sandbox2/syscall.h
index 23d2015..10754b8 100644
--- a/sandboxed_api/sandbox2/syscall.h
+++ b/sandboxed_api/sandbox2/syscall.h
@@ -18,6 +18,7 @@
 #ifndef SANDBOXED_API_SANDBOX2_SYSCALL_H__
 #define SANDBOXED_API_SANDBOX2_SYSCALL_H__
 
+#include <linux/seccomp.h>
 #include <sys/types.h>
 
 #include <array>
@@ -30,6 +31,10 @@
 #include "sandboxed_api/sandbox2/syscall_defs.h"
 
 namespace sandbox2 {
+class Regs;
+namespace util {
+class SeccompUnotify;
+}
 
 class Syscall {
  public:
@@ -49,6 +54,7 @@ class Syscall {
   static std::string GetArchDescription(sapi::cpu::Architecture arch);
 
   Syscall() = default;
+  Syscall(pid_t pid, const seccomp_data& data);
   Syscall(sapi::cpu::Architecture arch, uint64_t nr, Args args = {})
       : arch_(arch), nr_(nr), args_(args) {}
 
@@ -66,7 +72,6 @@ class Syscall {
 
  private:
   friend class Regs;
-  friend class UnotifyMonitor;
 
   explicit Syscall(pid_t pid) : pid_(pid) {}
   Syscall(sapi::cpu::Architecture arch, uint64_t nr, Args args, pid_t pid,
diff --git a/sandboxed_api/sandbox2/testcases/BUILD b/sandboxed_api/sandbox2/testcases/BUILD
index f49485c..187ed8d 100644
--- a/sandboxed_api/sandbox2/testcases/BUILD
+++ b/sandboxed_api/sandbox2/testcases/BUILD
@@ -27,10 +27,10 @@
 # any networking and none of the functionality from cstdio/stdio.h (due to
 # auto-loading of locale-specific shared objecs).
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -41,7 +41,7 @@ cc_binary(
     srcs = ["abort.cc"],
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
-    deps = ["@com_google_sandboxed_api//sandboxed_api/util:raw_logging"],
+    deps = ["//sandboxed_api/util:raw_logging"],
 )
 
 cc_binary(
@@ -59,7 +59,7 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:buffer",
+        "//sandboxed_api/sandbox2:buffer",
     ],
 )
 
@@ -70,10 +70,10 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -115,9 +115,9 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/util:raw_logging",
     ],
 )
 
@@ -128,8 +128,8 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_sandboxed_api//sandboxed_api:config",
+        "//sandboxed_api:config",
+        "@abseil-cpp//absl/base:core_headers",
     ],
 )
 
@@ -140,10 +140,10 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:util",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
@@ -161,11 +161,11 @@ cc_binary(
     srcs = ["close_fds.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:sanitizer",
+        "//sandboxed_api/sandbox2:sanitizer",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -189,7 +189,7 @@ cc_library(
     ]),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_absl//absl/base:core_headers",
+        "@abseil-cpp//absl/base:core_headers",
     ],
 )
 
@@ -201,9 +201,9 @@ cc_binary(
     features = ["fully_static_link"],
     deps = [
         ":symbolize_lib",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:raw_logging",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -214,8 +214,8 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
     ],
 )
 
@@ -242,12 +242,12 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -257,22 +257,22 @@ cc_binary(
     srcs = ["network_proxy.cc"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:client",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/network_proxy:client",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/network_proxy:client",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/strings:string_view",
     ],
 )
 
@@ -283,9 +283,9 @@ cc_binary(
     copts = sapi_platform_copts(),
     features = ["fully_static_link"],
     deps = [
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:forkingclient",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:forkingclient",
+        "//sandboxed_api/util:raw_logging",
     ],
 )
 
@@ -304,14 +304,27 @@ cc_binary(
     features = ["fully_static_link"],
     linkopts = ["-lrt"],
     deps = [
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/flags:parse",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/log:globals",
-        "@com_google_absl//absl/log:initialize",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/time",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/flags:parse",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/log:globals",
+        "@abseil-cpp//absl/log:initialize",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/time",
+    ],
+)
+
+cc_binary(
+    name = "execveat",
+    testonly = True,
+    srcs = ["execveat.cc"],
+    copts = sapi_platform_copts(),
+    features = ["fully_static_link"],
+    deps = [
+        "//sandboxed_api/sandbox2:client",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2:util",
     ],
 )
diff --git a/sandboxed_api/sandbox2/testcases/CMakeLists.txt b/sandboxed_api/sandbox2/testcases/CMakeLists.txt
index 0ba0dd6..aeb22fa 100644
--- a/sandboxed_api/sandbox2/testcases/CMakeLists.txt
+++ b/sandboxed_api/sandbox2/testcases/CMakeLists.txt
@@ -151,9 +151,6 @@ set_target_properties(sandbox2_testcase_policy PROPERTIES
 target_link_libraries(sandbox2_testcase_policy PRIVATE
   -static
   absl::core_headers
-  sandbox2::client
-  sandbox2::comms
-  sandbox2::util
   sapi::base
 )
 
@@ -390,3 +387,19 @@ target_link_libraries(sandbox2_testcase_posix_timers PRIVATE
   absl::time
   sapi::base
 )
+
+# sandboxed_api/sandbox2/testcases:execveat
+add_executable(sandbox2_testcase_execveat
+  execveat.cc
+)
+add_executable(sandbox2::testcase_execveat ALIAS sandbox2_testcase_execveat)
+set_target_properties(sandbox2_testcase_execveat PROPERTIES
+  OUTPUT_NAME execveat
+)
+target_link_libraries(sandbox2_testcase_execveat PRIVATE
+  -static
+  sapi::base
+  sandbox2::client
+  sandbox2::comms
+  sandbox2::util
+)
diff --git a/sandboxed_api/sandbox2/testcases/buffer.cc b/sandboxed_api/sandbox2/testcases/buffer.cc
index c25b030..2d4d411 100644
--- a/sandboxed_api/sandbox2/testcases/buffer.cc
+++ b/sandboxed_api/sandbox2/testcases/buffer.cc
@@ -21,7 +21,8 @@
 #include <utility>
 
 int main(int argc, char* argv[]) {
-  auto buffer_or = sandbox2::Buffer::CreateFromFd(3);
+  auto buffer_or =
+      sandbox2::Buffer::CreateFromFd(sapi::file_util::fileops::FDCloser(3));
   if (!buffer_or.ok()) {
     return EXIT_FAILURE;
   }
diff --git a/sandboxed_api/sandbox2/testcases/execveat.cc b/sandboxed_api/sandbox2/testcases/execveat.cc
new file mode 100644
index 0000000..3a19d71
--- /dev/null
+++ b/sandboxed_api/sandbox2/testcases/execveat.cc
@@ -0,0 +1,40 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <fcntl.h>
+#include <syscall.h>
+
+#include <cerrno>
+#include <cstdio>
+#include <cstdlib>
+
+#include "sandboxed_api/sandbox2/client.h"
+#include "sandboxed_api/sandbox2/comms.h"
+#include "sandboxed_api/sandbox2/util.h"
+
+int main(int argc, char** argv) {
+  int testno = atoi(argv[1]);  // NOLINT
+  if (testno == 1) {
+    sandbox2::Comms comms(sandbox2::Comms::kSandbox2ClientCommsFD);
+    sandbox2::Client client(&comms);
+    client.SandboxMeHere();
+  }
+  int result =
+      sandbox2::util::Syscall(__NR_execveat, AT_EMPTY_PATH, 0, 0, 0, 0);
+  if (result != -1 || errno != EPERM) {
+    printf("System call should have been blocked\n");
+    return EXIT_FAILURE;
+  }
+  return EXIT_SUCCESS;
+}
diff --git a/sandboxed_api/sandbox2/testcases/policy.cc b/sandboxed_api/sandbox2/testcases/policy.cc
index fb56a4d..2af83b8 100644
--- a/sandboxed_api/sandbox2/testcases/policy.cc
+++ b/sandboxed_api/sandbox2/testcases/policy.cc
@@ -14,7 +14,9 @@
 
 // A binary that tries x86_64 compat syscalls, ptrace and clone untraced.
 
+#include <linux/prctl.h>
 #include <sched.h>
+#include <sys/prctl.h>
 #include <sys/ptrace.h>
 #include <syscall.h>
 #include <unistd.h>
@@ -99,8 +101,82 @@ void TestBpf() {
   exit(EXIT_FAILURE);
 }
 
+void TestSafeBpf() {
+#define BPF_MAP_LOOKUP_ELEM 1
+  // This call (if allowed) will return an error. We not interested in that
+  // here, we just want to check whether this call is allowed.
+  errno = 0;
+  syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, nullptr, 0);
+  if (errno == EPERM) {
+    printf("System call should not have been blocked\n");
+    exit(EXIT_FAILURE);
+  }
+}
+
 void TestIsatty() { isatty(0); }
 
+#ifdef SAPI_X86_64
+void TestSpeculationAllowed() {
+  int res = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
+  if (res == -1) {
+    printf("prctl(R_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS) failed: %d\n",
+           errno);
+  } else if (res == PR_SPEC_NOT_AFFECTED) {
+    printf("CPU not affected for PR_SPEC_STORE_BYPASS");
+  } else if ((res & ~(PR_SPEC_PRCTL)) != PR_SPEC_ENABLE) {
+    printf(
+        "PR_SPEC_STORE_BYPASS speculation disabled when it should not have "
+        "been: %d\n",
+        res);
+    exit(EXIT_FAILURE);
+  }
+  res = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0);
+  if (res == -1) {
+    printf(
+        "prctl(R_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH) failed: %d\n",
+        errno);
+  } else if (res == PR_SPEC_NOT_AFFECTED) {
+    printf("CPU not affected for PR_SPEC_INDIRECT_BRANCH");
+  } else if ((res & ~(PR_SPEC_PRCTL)) != PR_SPEC_ENABLE) {
+    printf(
+        "PR_SPEC_INDIRECT_BRANCH speculation disabled when it should not have "
+        "been: %d\n",
+        res);
+    exit(EXIT_FAILURE);
+  }
+}
+
+void TestSpeculationBlocked() {
+  int res = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
+  if (res == -1) {
+    printf("prctl(R_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS) failed: %d\n",
+           errno);
+  } else if (res == PR_SPEC_NOT_AFFECTED) {
+    printf("CPU not affected for PR_SPEC_STORE_BYPASS");
+  } else if ((res & ~(PR_SPEC_PRCTL)) != PR_SPEC_FORCE_DISABLE) {
+    printf(
+        "PR_SPEC_STORE_BYPASS speculation enabled when it should not have "
+        "been: %d\n",
+        res);
+    exit(EXIT_FAILURE);
+  }
+  res = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, 0, 0, 0);
+  if (res == -1) {
+    printf(
+        "prctl(R_GET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH) failed: %d\n",
+        errno);
+  } else if (res == PR_SPEC_NOT_AFFECTED) {
+    printf("CPU not affected for PR_SPEC_INDIRECT_BRANCH");
+  } else if ((res & ~(PR_SPEC_PRCTL)) != PR_SPEC_FORCE_DISABLE) {
+    printf(
+        "PR_SPEC_INDIRECT_BRANCH speculation enabled when it should not have "
+        "been: %d\n",
+        res);
+    exit(EXIT_FAILURE);
+  }
+}
+#endif  // SAPI_X86_64
+
 int main(int argc, char* argv[]) {
   // Disable buffering.
   setbuf(stdin, nullptr);
@@ -140,6 +216,17 @@ int main(int argc, char* argv[]) {
     case 8:
       TestBpfBlocked();
       break;
+    case 9:
+      TestSafeBpf();
+      break;
+#ifdef SAPI_X86_64
+    case 11:
+      TestSpeculationAllowed();
+      break;
+    case 12:
+      TestSpeculationBlocked();
+      break;
+#endif  // SAPI_X86_64
     default:
       printf("Unknown test: %d\n", testno);
       return EXIT_FAILURE;
diff --git a/sandboxed_api/sandbox2/unwind/BUILD b/sandboxed_api/sandbox2/unwind/BUILD
index 4de6b34..a952d79 100644
--- a/sandboxed_api/sandbox2/unwind/BUILD
+++ b/sandboxed_api/sandbox2/unwind/BUILD
@@ -12,11 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api/sandbox2:__subpackages__",
+    "//sandboxed_api/sandbox2:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -27,8 +27,8 @@ cc_library(
     hdrs = ["ptrace_hook.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:syscall_trap",
+        "//sandboxed_api/sandbox2/util:syscall_trap",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -41,18 +41,18 @@ cc_library(
     deps = [
         ":ptrace_hook",
         ":unwind_cc_proto",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:comms",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:maps_parser",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2/util:minielf",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
-        "@org_gnu_libunwind//:unwind-ptrace",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2:comms",
+        "//sandboxed_api/sandbox2/util:maps_parser",
+        "//sandboxed_api/sandbox2/util:minielf",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@libunwind//:libunwind_ptrace",
     ],
 )
 
diff --git a/sandboxed_api/sandbox2/util.cc b/sandboxed_api/sandbox2/util.cc
index 0925c9f..f18f7f8 100644
--- a/sandboxed_api/sandbox2/util.cc
+++ b/sandboxed_api/sandbox2/util.cc
@@ -63,7 +63,7 @@ namespace sandbox2 {
 namespace util {
 
 namespace file = ::sapi::file;
-namespace file_util = ::sapi::file_util;
+using ::sapi::file_util::fileops::FDCloser;
 
 namespace {
 
@@ -142,7 +142,8 @@ std::string GetProgName(pid_t pid) {
   // Use ReadLink instead of RealPath, as for fd-based executables (e.g. created
   // via memfd_create()) the RealPath will not work, as the destination file
   // doesn't exist on the local file-system.
-  return file_util::fileops::Basename(file_util::fileops::ReadLink(fname));
+  return sapi::file_util::fileops::Basename(
+      sapi::file_util::fileops::ReadLink(fname));
 }
 
 absl::StatusOr<std::string> GetResolvedFdLink(pid_t pid, uint32_t fd) {
@@ -253,7 +254,7 @@ pid_t ForkWithFlags(int flags) {
   return 0;
 }
 
-bool CreateMemFd(int* fd, const char* name) {
+absl::StatusOr<FDCloser> CreateMemFd(const char* name) {
   // Usually defined in linux/memfd.h. Define it here to avoid dependency on
   // UAPI headers.
   constexpr uintptr_t kMfdCloseOnExec = 0x0001;
@@ -262,16 +263,14 @@ bool CreateMemFd(int* fd, const char* name) {
                        kMfdCloseOnExec | kMfdAllowSealing);
   if (tmp_fd < 0) {
     if (errno == ENOSYS) {
-      SAPI_RAW_LOG(ERROR,
-                   "This system does not seem to support the memfd_create()"
-                   " syscall. Try running on a newer kernel.");
-    } else {
-      SAPI_RAW_PLOG(ERROR, "Could not create tmp file '%s'", name);
+      return absl::InternalError(
+          "This system does not seem to support the memfd_create()"
+          " syscall. Try running on a newer kernel.");
     }
-    return false;
+    return absl::ErrnoToStatus(
+        errno, absl::StrFormat("Could not create tmp file '%s'", name));
   }
-  *fd = tmp_fd;
-  return true;
+  return FDCloser(tmp_fd);
 }
 
 absl::StatusOr<int> Communicate(const std::vector<std::string>& argv,
@@ -283,7 +282,7 @@ absl::StatusOr<int> Communicate(const std::vector<std::string>& argv,
   if (pipe(cout_pipe) == -1) {
     return absl::ErrnoToStatus(errno, "creating pipe");
   }
-  file_util::fileops::FDCloser cout_closer{cout_pipe[1]};
+  FDCloser cout_closer{cout_pipe[1]};
 
   posix_spawn_file_actions_init(&action);
   struct ActionCleanup {
@@ -505,11 +504,9 @@ absl::StatusOr<size_t> ProcessVmReadInSplitChunks(pid_t pid, uintptr_t ptr,
 }
 
 // Open /proc/pid/mem file descriptor.
-absl::StatusOr<file_util::fileops::FDCloser> OpenProcMem(pid_t pid,
-                                                         bool is_read) {
+absl::StatusOr<FDCloser> OpenProcMem(pid_t pid, bool is_read) {
   auto path = absl::StrFormat("/proc/%d/mem", pid);
-  auto closer = file_util::fileops::FDCloser(
-      open(path.c_str(), is_read ? O_RDONLY : O_WRONLY));
+  auto closer = FDCloser(open(path.c_str(), is_read ? O_RDONLY : O_WRONLY));
   if (closer.get() == -1) {
     return absl::ErrnoToStatus(
         errno, absl::StrFormat("open() failed for PID: %d", pid));
@@ -523,8 +520,7 @@ absl::StatusOr<size_t> ProcMemTransfer(bool is_read, pid_t pid, uintptr_t ptr,
     return 0;
   }
 
-  SAPI_ASSIGN_OR_RETURN(file_util::fileops::FDCloser fd_closer,
-                        OpenProcMem(pid, is_read));
+  SAPI_ASSIGN_OR_RETURN(FDCloser fd_closer, OpenProcMem(pid, is_read));
   size_t total_bytes_transferred = 0;
   while (!data.empty()) {
     ssize_t bytes_transfered =
diff --git a/sandboxed_api/sandbox2/util.h b/sandboxed_api/sandbox2/util.h
index 9cda752..5a8e11b 100644
--- a/sandboxed_api/sandbox2/util.h
+++ b/sandboxed_api/sandbox2/util.h
@@ -25,9 +25,12 @@
 #include <string>
 #include <vector>
 
+#include "absl/base/attributes.h"
 #include "absl/base/macros.h"
+#include "absl/log/log.h"
 #include "absl/status/statusor.h"
 #include "absl/types/span.h"
+#include "sandboxed_api/util/fileops.h"
 
 namespace sandbox2 {
 
@@ -99,7 +102,20 @@ long Syscall(long sys_no,  // NOLINT
 pid_t ForkWithFlags(int flags);
 
 // Creates a new memfd.
-bool CreateMemFd(int* fd, const char* name = "buffer_file");
+absl::StatusOr<sapi::file_util::fileops::FDCloser> CreateMemFd(
+    const char* name = "buffer_file");
+
+ABSL_DEPRECATED("Use absl::StausOr<FDCloser> version instead.")
+inline bool CreateMemFd(int* fd, const char* name = "buffer_file") {
+  absl::StatusOr<sapi::file_util::fileops::FDCloser> fd_closer =
+      CreateMemFd(name);
+  if (!fd_closer.ok()) {
+    LOG(ERROR) << "Could not create memfd: " << fd_closer.status();
+    return false;
+  }
+  *fd = fd_closer->Release();
+  return true;
+}
 
 // Executes a the program given by argv and the specified environment and
 // captures any output to stdout/stderr.
diff --git a/sandboxed_api/sandbox2/util/BUILD b/sandboxed_api/sandbox2/util/BUILD
index c003e71..451247e 100644
--- a/sandboxed_api/sandbox2/util/BUILD
+++ b/sandboxed_api/sandbox2/util/BUILD
@@ -12,10 +12,10 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 DEFAULT_VISIBILITY = [
-    "@com_google_sandboxed_api//sandboxed_api:__subpackages__",
+    "//sandboxed_api:__subpackages__",
 ]
 
 package(default_visibility = DEFAULT_VISIBILITY)
@@ -36,8 +36,8 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":bpf_helper",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -48,14 +48,14 @@ cc_library(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/base:endian",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_sandboxed_api//sandboxed_api:config",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:config",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:endian",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -71,12 +71,12 @@ cc_test(
     deps = [
         ":maps_parser",
         ":minielf",
-        "@com_google_absl//absl/algorithm:container",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/algorithm:container",
+        "@abseil-cpp//absl/status:statusor",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -86,8 +86,8 @@ cc_library(
     hdrs = ["syscall_trap.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/log:check",
-        "@com_google_sandboxed_api//sandboxed_api:config",
+        "//sandboxed_api:config",
+        "@abseil-cpp//absl/log:check",
     ],
 )
 
@@ -97,20 +97,20 @@ cc_library(
     hdrs = ["deadline_manager.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:no_destructor",
-        "@com_google_absl//absl/container:btree",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/functional:function_ref",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
-        "@com_google_sandboxed_api//sandboxed_api/sandbox2:util",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/base",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:no_destructor",
+        "@abseil-cpp//absl/container:btree",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/functional:function_ref",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -120,11 +120,11 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":deadline_manager",
-        "@com_google_absl//absl/flags:flag",
-        "@com_google_absl//absl/log:check",
-        "@com_google_absl//absl/time",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/flags:flag",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/time",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -134,9 +134,9 @@ cc_library(
     hdrs = ["maps_parser.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -146,9 +146,9 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":maps_parser",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/status:statusor",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -159,10 +159,10 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":deadline_manager",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/cleanup",
-        "@com_google_absl//absl/synchronization",
-        "@com_google_absl//absl/time",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/synchronization",
+        "@abseil-cpp//absl/time",
     ],
 )
 
@@ -172,8 +172,41 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":pid_waiter",
-        "@com_google_absl//absl/time",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:thread",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/time",
+        "@googletest//:gtest_main",
+    ],
+)
+
+cc_library(
+    name = "seccomp_unotify",
+    srcs = ["seccomp_unotify.cc"],
+    hdrs = ["seccomp_unotify.h"],
+    copts = sapi_platform_copts(),
+    deps = [
+        ":bpf_helper",
+        "//sandboxed_api/sandbox2:syscall",
+        "//sandboxed_api/sandbox2:util",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:strerror",
+        "//sandboxed_api/util:thread",
+        "@abseil-cpp//absl/cleanup",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/synchronization",
+    ],
+)
+
+cc_test(
+    name = "seccomp_unotify_test",
+    srcs = ["seccomp_unotify_test.cc"],
+    copts = sapi_platform_copts(),
+    deps = [
+        ":seccomp_unotify",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/status:statusor",
+        "@googletest//:gtest_main",
     ],
 )
diff --git a/sandboxed_api/sandbox2/util/CMakeLists.txt b/sandboxed_api/sandbox2/util/CMakeLists.txt
index 93d7b4b..c0d2f6d 100644
--- a/sandboxed_api/sandbox2/util/CMakeLists.txt
+++ b/sandboxed_api/sandbox2/util/CMakeLists.txt
@@ -101,6 +101,28 @@ target_link_libraries(sandbox2_util_deadline_manager
           sapi::base
 )
 
+# sandboxed_api/sandbox2/util:seccomp_unotify
+add_library(sandbox2_util_seccomp_unotify ${SAPI_LIB_TYPE}
+  seccomp_unotify.cc
+  seccomp_unotify.h
+)
+add_library(sandbox2::seccomp_unotify ALIAS sandbox2_util_seccomp_unotify)
+target_link_libraries(sandbox2_util_seccomp_unotify
+  PUBLIC absl::status
+         absl::statusor
+         sandbox2::syscall
+         sapi::fileops
+  PRIVATE absl::cleanup
+          absl::log
+          absl::strings
+          absl::synchronization
+          sandbox2::bpf_helper
+          sandbox2::util
+          sapi::base
+          sapi::strerror
+          sapi::thread
+)
+
 if(BUILD_TESTING AND SAPI_BUILD_TESTING)
   # sandboxed_api/sandbox2/util:minielf_test
   add_executable(sandbox2_minielf_test
@@ -188,4 +210,20 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING)
     sapi::thread
   )
   gtest_discover_tests_xcompile(sandbox2_deadline_manager_test)
+
+  # sandboxed_api/sandbox2/util:seccomp_unotify_test
+  add_executable(sandbox2_seccomp_unotify_test
+    seccomp_unotify_test.cc
+  )
+  set_target_properties(sandbox2_seccomp_unotify_test PROPERTIES
+    OUTPUT_NAME seccomp_unotify_test
+  )
+  target_link_libraries(sandbox2_seccomp_unotify_test PRIVATE
+    sandbox2::seccomp_unotify
+    absl::statusor
+    sapi::fileops
+    sapi::status_matchers
+    sapi::test_main
+  )
+  gtest_discover_tests_xcompile(sandbox2_seccomp_unotify_test)
 endif()
diff --git a/sandboxed_api/sandbox2/util/minielf.cc b/sandboxed_api/sandbox2/util/minielf.cc
index ecda878..89a8d86 100644
--- a/sandboxed_api/sandbox2/util/minielf.cc
+++ b/sandboxed_api/sandbox2/util/minielf.cc
@@ -27,6 +27,8 @@
 #include <utility>
 #include <vector>
 
+// TODO: internal/endian.h will become private with abseil-cpp LTS 202507.
+// Switch to absl::byteswap.
 #include "absl/base/internal/endian.h"
 #include "absl/status/status.h"
 #include "absl/status/statusor.h"
diff --git a/sandboxed_api/sandbox2/util/seccomp_unotify.cc b/sandboxed_api/sandbox2/util/seccomp_unotify.cc
new file mode 100644
index 0000000..d52e073
--- /dev/null
+++ b/sandboxed_api/sandbox2/util/seccomp_unotify.cc
@@ -0,0 +1,215 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "sandboxed_api/sandbox2/util/seccomp_unotify.h"
+
+#include <linux/audit.h>
+#include <linux/filter.h>
+#include <linux/seccomp.h>
+#include <sys/ioctl.h>
+#include <sys/prctl.h>
+#include <syscall.h>
+
+#include <array>
+#include <cerrno>
+#include <cstdint>
+#include <cstdlib>
+#include <cstring>
+#include <memory>
+#include <utility>
+
+#include "absl/cleanup/cleanup.h"
+#include "absl/log/log.h"
+#include "absl/status/status.h"
+#include "absl/synchronization/notification.h"
+#include "sandboxed_api/sandbox2/syscall.h"
+#include "sandboxed_api/sandbox2/util.h"
+#include "sandboxed_api/sandbox2/util/bpf_helper.h"
+#include "sandboxed_api/util/fileops.h"
+#include "sandboxed_api/util/strerror.h"
+#include "sandboxed_api/util/thread.h"
+
+#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
+#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1
+#endif
+
+#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
+#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
+#endif
+
+#ifndef SECCOMP_GET_NOTIF_SIZES
+#define SECCOMP_GET_NOTIF_SIZES 3
+#endif
+
+#ifndef SECCOMP_IOCTL_NOTIF_RECV
+#ifndef SECCOMP_IOWR
+#define SECCOMP_IOC_MAGIC '!'
+#define SECCOMP_IO(nr) _IO(SECCOMP_IOC_MAGIC, nr)
+#define SECCOMP_IOWR(nr, type) _IOWR(SECCOMP_IOC_MAGIC, nr, type)
+#endif
+
+// Flags for seccomp notification fd ioctl.
+#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
+#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
+#endif
+
+namespace sandbox2 {
+namespace util {
+namespace {
+using ::sapi::file_util::fileops::FDCloser;
+
+int seccomp(unsigned int operation, unsigned int flags, void* args) {
+  return Syscall(SYS_seccomp, operation, flags,
+                 reinterpret_cast<uintptr_t>(args));
+}
+
+class OsSeccompUnotify : public SeccompUnotify::SeccompUnotifyInterface {
+ public:
+  int GetSizes(seccomp_notif_sizes* sizes) override {
+    return seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes);
+  }
+  int ReceiveNotification(int fd, seccomp_notif* req) override {
+    return ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV,
+                 reinterpret_cast<uintptr_t>(req));
+  }
+  int SendResponse(int fd, const seccomp_notif_resp& resp) override {
+    return ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND,
+                 reinterpret_cast<uintptr_t>(&resp));
+  }
+};
+
+bool TestUserNotifFlagContinueSupport() {
+  constexpr int kSpecialSyscall = 0x12345;
+  std::array<sock_filter, 4> code = {{
+      LOAD_SYSCALL_NR,
+      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, kSpecialSyscall, 0, 1),
+      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
+      ALLOW,
+  }};
+  sock_fprog prog = {
+      .len = code.size(),
+      .filter = code.data(),
+  };
+  absl::Notification setup_done;
+  FDCloser notify_fd;
+  sapi::Thread th([&notify_fd, &setup_done, &prog]() {
+    absl::Cleanup cleanup = [&setup_done] { setup_done.Notify(); };
+    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
+      VLOG(3) << "Failed to set PR_SET_NO_NEW_PRIVS" << sapi::StrError(errno);
+      return;
+    }
+    int ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
+                      SECCOMP_FILTER_FLAG_NEW_LISTENER,
+                      reinterpret_cast<uintptr_t>(&prog));
+    if (ret == -1) {
+      VLOG(3) << "Failed seccomp" << sapi::StrError(errno);
+      return;
+    }
+    notify_fd = FDCloser(ret);
+    std::move(cleanup).Invoke();
+    util::Syscall(kSpecialSyscall);
+  });
+  absl::Cleanup join_thread = [&th] { th.Join(); };
+  setup_done.WaitForNotification();
+  if (notify_fd.get() == -1) {
+    VLOG(3) << "Failed to setup notify_fd";
+    return false;
+  }
+  SeccompUnotify unotify;
+  if (absl::Status status = unotify.Init(std::move(notify_fd)); !status.ok()) {
+    VLOG(3) << "Failed to init unotify: " << status;
+    return false;
+  }
+  absl::StatusOr<seccomp_notif> req = unotify.Receive();
+  if (!req.ok()) {
+    VLOG(3) << "Failed to receive unotify: " << req.status();
+    return false;
+  }
+
+  if (absl::Status status = unotify.RespondContinue(*req); !status.ok()) {
+    VLOG(3) << "Failed to respond continue: " << status;
+    return false;
+  }
+  return true;
+}
+}  // namespace
+
+bool SeccompUnotify::IsContinueSupported() {
+  static bool supported = []() { return TestUserNotifFlagContinueSupport(); }();
+  return supported;
+}
+
+SeccompUnotify::SeccompUnotify()
+    : SeccompUnotify(std::make_unique<OsSeccompUnotify>()) {}
+
+absl::Status SeccompUnotify::Init(FDCloser seccomp_notify_fd) {
+  if (seccomp_notify_fd_.get() > 0) {
+    return absl::FailedPreconditionError("Init() must be called only once");
+  }
+  struct seccomp_notif_sizes sizes = {};
+  if (seccomp_unotify_iface_->GetSizes(&sizes) == -1) {
+    return absl::InternalError("Couldn't get seccomp_notif_sizes");
+  }
+  req_size_ = sizes.seccomp_notif;
+  req_.reset(static_cast<seccomp_notif*>(malloc(req_size_)));
+  resp_size_ = sizes.seccomp_notif_resp;
+  resp_.reset(static_cast<seccomp_notif_resp*>(malloc(resp_size_)));
+  seccomp_notify_fd_ = std::move(seccomp_notify_fd);
+  return absl::OkStatus();
+}
+
+absl::StatusOr<seccomp_notif> SeccompUnotify::Receive() {
+  if (seccomp_notify_fd_.get() < 0) {
+    return absl::FailedPreconditionError("Init() must be called first");
+  }
+  memset(req_.get(), 0, req_size_);
+  if (seccomp_unotify_iface_->ReceiveNotification(seccomp_notify_fd_.get(),
+                                                  req_.get()) != 0) {
+    if (errno == ENOENT) {
+      return absl::NotFoundError("Failed to receive notification");
+    }
+    return absl::ErrnoToStatus(errno, "Failed to receive notification");
+  }
+  return *req_;
+}
+
+absl::Status SeccompUnotify::Respond(const seccomp_notif& req) {
+  resp_->id = req.id;
+  if (seccomp_unotify_iface_->SendResponse(seccomp_notify_fd_.get(), *resp_) !=
+      0) {
+    return absl::ErrnoToStatus(errno, "Failed to send notification");
+  }
+  return absl::OkStatus();
+}
+
+absl::Status SeccompUnotify::RespondErrno(const seccomp_notif& req, int error) {
+  if (!resp_) {
+    return absl::FailedPreconditionError("Init() must be called first");
+  }
+  memset(resp_.get(), 0, resp_size_);
+  resp_->error = error;
+  return Respond(req);
+}
+
+absl::Status SeccompUnotify::RespondContinue(const seccomp_notif& req) {
+  if (!resp_) {
+    return absl::FailedPreconditionError("Init() must be called first");
+  }
+  memset(resp_.get(), 0, resp_size_);
+  resp_->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
+  return Respond(req);
+}
+
+}  // namespace util
+}  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/util/seccomp_unotify.h b/sandboxed_api/sandbox2/util/seccomp_unotify.h
new file mode 100644
index 0000000..f9e48f0
--- /dev/null
+++ b/sandboxed_api/sandbox2/util/seccomp_unotify.h
@@ -0,0 +1,109 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SANDBOXED_API_SANDBOX2_UTIL_SECCOMP_UNOTIFY_H_
+#define SANDBOXED_API_SANDBOX2_UTIL_SECCOMP_UNOTIFY_H_
+
+#include <linux/seccomp.h>
+
+#include <cstddef>
+#include <cstdlib>
+#include <memory>
+#include <utility>
+
+#include "absl/status/status.h"
+#include "absl/status/statusor.h"
+#include "sandboxed_api/sandbox2/syscall.h"
+#include "sandboxed_api/util/fileops.h"
+
+#ifndef SECCOMP_RET_USER_NOTIF
+#define SECCOMP_RET_USER_NOTIF 0x7fc00000U /* notifies userspace */
+#endif
+
+#ifndef SECCOMP_IOCTL_NOTIF_RECV
+struct seccomp_notif {
+  __u64 id;
+  __u32 pid;
+  __u32 flags;
+  struct seccomp_data data;
+};
+
+struct seccomp_notif_resp {
+  __u64 id;
+  __s64 val;
+  __s32 error;
+  __u32 flags;
+};
+
+struct seccomp_notif_sizes {
+  __u16 seccomp_notif;
+  __u16 seccomp_notif_resp;
+  __u16 seccomp_data;
+};
+#endif
+
+namespace sandbox2 {
+namespace util {
+
+class SeccompUnotify {
+ public:
+  // Interface for seccomp_unotify to allow mocking it in tests.
+  class SeccompUnotifyInterface {
+   public:
+    virtual int GetSizes(seccomp_notif_sizes* sizes) = 0;
+    virtual int ReceiveNotification(int fd, seccomp_notif* req) = 0;
+    virtual int SendResponse(int fd, const seccomp_notif_resp& resp) = 0;
+    virtual ~SeccompUnotifyInterface() = default;
+  };
+
+  explicit SeccompUnotify();
+  explicit SeccompUnotify(
+      std::unique_ptr<SeccompUnotifyInterface> seccomp_unotify_iface)
+      : seccomp_unotify_iface_(std::move(seccomp_unotify_iface)) {}
+  ~SeccompUnotify() = default;
+
+  static bool IsContinueSupported();
+
+  // Initializes the object. Must be called before any other method.
+  absl::Status Init(sapi::file_util::fileops::FDCloser seccomp_notify_fd);
+  // Receives a notification from the sandboxee.
+  absl::StatusOr<seccomp_notif> Receive();
+  // Responds to the sandboxee with an errno, syscall is not executed.
+  absl::Status RespondErrno(const seccomp_notif& req, int error);
+  // Allows the sandboxee to continue execution of the syscall.
+  absl::Status RespondContinue(const seccomp_notif& req);
+  // Returns the file descriptor of the seccomp notify socket.
+  int GetFd() const { return seccomp_notify_fd_.get(); }
+
+ private:
+  // Custom deleter for req_ and resp_ members which need to allocate space
+  // using malloc.
+  struct StdFreeDeleter {
+    void operator()(void* p) { std::free(p); }
+  };
+
+  absl::Status Respond(const seccomp_notif& req);
+
+  std::unique_ptr<SeccompUnotifyInterface> seccomp_unotify_iface_;
+  sapi::file_util::fileops::FDCloser seccomp_notify_fd_;
+  size_t req_size_ = 0;
+  std::unique_ptr<seccomp_notif, StdFreeDeleter> req_;
+  size_t resp_size_ = 0;
+  std::unique_ptr<seccomp_notif_resp, StdFreeDeleter> resp_;
+};
+
+}  // namespace util
+}  // namespace sandbox2
+
+#endif  // SANDBOXED_API_SANDBOX2_UTIL_SECCOMP_UNOTIFY_H_
diff --git a/sandboxed_api/sandbox2/util/seccomp_unotify_test.cc b/sandboxed_api/sandbox2/util/seccomp_unotify_test.cc
new file mode 100644
index 0000000..4aec896
--- /dev/null
+++ b/sandboxed_api/sandbox2/util/seccomp_unotify_test.cc
@@ -0,0 +1,100 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "sandboxed_api/sandbox2/util/seccomp_unotify.h"
+
+#include <linux/seccomp.h>
+
+#include <cerrno>
+#include <memory>
+#include <utility>
+
+#include "gmock/gmock.h"
+#include "gtest/gtest.h"
+#include "absl/status/statusor.h"
+#include "sandboxed_api/util/fileops.h"
+#include "sandboxed_api/util/status_matchers.h"
+
+namespace sandbox2 {
+namespace util {
+namespace {
+
+using ::sapi::IsOk;
+using ::sapi::file_util::fileops::FDCloser;
+using ::testing::_;
+using ::testing::DoAll;
+using ::testing::Not;
+using ::testing::Return;
+using ::testing::SetArgPointee;
+
+class MockSeccompUnotify : public SeccompUnotify::SeccompUnotifyInterface {
+ public:
+  MOCK_METHOD(int, GetSizes, (seccomp_notif_sizes*), (override));
+  MOCK_METHOD(int, ReceiveNotification, (int, seccomp_notif*), (override));
+  MOCK_METHOD(int, SendResponse, (int, const seccomp_notif_resp&), (override));
+};
+
+TEST(SeccompUnotifyTest, ReceiveRespondFailWithoutInit) {
+  SeccompUnotify unotify(std::make_unique<MockSeccompUnotify>());
+  EXPECT_THAT(unotify.Receive(), Not(IsOk()));
+  seccomp_notif req = {};
+  EXPECT_THAT(unotify.RespondErrno(req, EINVAL), Not(IsOk()));
+  EXPECT_THAT(unotify.RespondContinue(req), Not(IsOk()));
+}
+
+TEST(SeccompUnotifyTest, Normal) {
+  seccomp_notif_sizes sizes = {
+      .seccomp_notif = sizeof(seccomp_notif) + 100,
+      .seccomp_notif_resp = sizeof(seccomp_notif_resp) + 100,
+  };
+  auto mock_seccomp_unotify = std::make_unique<MockSeccompUnotify>();
+  EXPECT_CALL(*mock_seccomp_unotify, GetSizes(_))
+      .WillOnce(DoAll(SetArgPointee<0>(sizes), Return(0)));
+  EXPECT_CALL(*mock_seccomp_unotify, ReceiveNotification(1, _))
+      .WillOnce([&sizes](int fd, seccomp_notif* req) {
+        for (int i = sizeof(seccomp_notif); i < sizes.seccomp_notif; ++i) {
+          EXPECT_EQ(reinterpret_cast<const char*>(req)[i], 0) << i;
+        }
+        req->id = 1;
+        return 0;
+      });
+  EXPECT_CALL(*mock_seccomp_unotify, SendResponse(1, _))
+      .WillOnce([&sizes](int fd, const seccomp_notif_resp& resp) {
+        for (int i = sizeof(seccomp_notif_resp); i < sizes.seccomp_notif_resp;
+             ++i) {
+          EXPECT_EQ(reinterpret_cast<const char*>(&resp)[i], 0);
+        }
+        EXPECT_EQ(resp.id, 1);
+        EXPECT_EQ(resp.error, EINVAL);
+        EXPECT_EQ(resp.flags, 0);
+        EXPECT_EQ(resp.val, 0);
+        return 0;
+      });
+
+  SeccompUnotify unotify(std::move(mock_seccomp_unotify));
+  ASSERT_THAT(unotify.Init(FDCloser(1)), IsOk());
+  absl::StatusOr<seccomp_notif> req = unotify.Receive();
+  ASSERT_THAT(req.status(), IsOk());
+  EXPECT_THAT(unotify.RespondErrno(*req, EINVAL), IsOk());
+}
+
+// sapi::google3-begin(unotify continue)
+TEST(SeccompUnotifyTest, Continue) {
+  EXPECT_TRUE(SeccompUnotify::IsContinueSupported());
+}
+// sapi::google3-end
+
+}  // namespace
+}  // namespace util
+}  // namespace sandbox2
diff --git a/sandboxed_api/sandbox2/util_c.cc b/sandboxed_api/sandbox2/util_c.cc
new file mode 100644
index 0000000..6e3ff7c
--- /dev/null
+++ b/sandboxed_api/sandbox2/util_c.cc
@@ -0,0 +1,29 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "sandboxed_api/sandbox2/util_c.h"
+
+#include "absl/log/log.h"
+#include "absl/status/statusor.h"
+#include "sandboxed_api/sandbox2/util.h"
+
+// Returns true if the current process is running inside Sandbox2.
+bool IsRunningInSandbox2() {
+  absl::StatusOr<bool> result = sandbox2::util::IsRunningInSandbox2();
+  if (!result.ok()) {
+    LOG(ERROR) << result.status();
+    return false;
+  }
+  return *result;
+}
diff --git a/sandboxed_api/sandbox2/util_c.h b/sandboxed_api/sandbox2/util_c.h
new file mode 100644
index 0000000..f3054b3
--- /dev/null
+++ b/sandboxed_api/sandbox2/util_c.h
@@ -0,0 +1,34 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// This header provides a C-wrapper for sandbox2::util functions that may be
+// useful in C hostcode.
+
+#ifndef SANDBOXED_API_SANDBOX2_UTIL_C_H_
+#define SANDBOXED_API_SANDBOX2_UTIL_C_H_
+
+#include <stdbool.h>
+
+#if defined(__cplusplus)
+extern "C" {
+#endif
+
+// Returns true if the current process is running inside Sandbox2.
+bool IsRunningInSandbox2();
+
+#if defined(__cplusplus)
+}  // extern "C"
+#endif
+
+#endif  // SANDBOXED_API_SANDBOX2_UTIL_C_H_
diff --git a/sandboxed_api/testing.cc b/sandboxed_api/testing.cc
index 06ddbfd..0fcac83 100644
--- a/sandboxed_api/testing.cc
+++ b/sandboxed_api/testing.cc
@@ -26,7 +26,7 @@
 namespace sapi {
 
 sandbox2::PolicyBuilder CreateDefaultPermissiveTestPolicy(
-    absl::string_view bin_path) {
+    absl::string_view binary_path) {
   sandbox2::PolicyBuilder builder;
   // Don't restrict the syscalls at all.
   builder.DefaultAction(sandbox2::AllowAllSyscalls());
@@ -35,7 +35,7 @@ sandbox2::PolicyBuilder CreateDefaultPermissiveTestPolicy(
                          /*is_ro=*/false);
   }
   if constexpr (sapi::sanitizers::IsAny()) {
-    builder.AddLibrariesForBinary(bin_path);
+    builder.AddLibrariesForBinary(binary_path);
   }
   if constexpr (sapi::sanitizers::IsAny()) {
     builder.AddDirectory("/proc");
diff --git a/sandboxed_api/testing.h b/sandboxed_api/testing.h
index c0ea984..13f7343 100644
--- a/sandboxed_api/testing.h
+++ b/sandboxed_api/testing.h
@@ -17,6 +17,7 @@
 
 #include <string>
 
+#include "gtest/gtest.h"
 #include "absl/strings/string_view.h"
 #include "sandboxed_api/config.h"  // IWYU pragma: export
 #include "sandboxed_api/sandbox2/policybuilder.h"
@@ -45,21 +46,21 @@
 #define SKIP_SANITIZERS_AND_COVERAGE                          \
   do {                                                        \
     if (sapi::sanitizers::IsAny() || sapi::IsCoverageRun()) { \
-      return;                                                 \
+      GTEST_SKIP();                                           \
     }                                                         \
   } while (0)
 
 #define SKIP_SANITIZERS              \
   do {                               \
     if (sapi::sanitizers::IsAny()) { \
-      return;                        \
+      GTEST_SKIP();                  \
     }                                \
   } while (0)
 
 namespace sapi {
 
 sandbox2::PolicyBuilder CreateDefaultPermissiveTestPolicy(
-    absl::string_view bin_path);
+    absl::string_view binary_path);
 
 // Returns a writable path usable in tests. If the name argument is specified,
 // returns a name under that path. This can then be used for creating temporary
diff --git a/sandboxed_api/tools/clang_generator/BUILD b/sandboxed_api/tools/clang_generator/BUILD
index cc94354..7ab1727 100644
--- a/sandboxed_api/tools/clang_generator/BUILD
+++ b/sandboxed_api/tools/clang_generator/BUILD
@@ -12,10 +12,15 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
 
 licenses(["notice"])
 
+filegroup(
+    name = "testdata",
+    srcs = glob(["testdata/*"]),
+)
+
 cc_library(
     name = "generator",
     srcs = [
@@ -30,22 +35,25 @@ cc_library(
         "emitter.h",
         "emitter_base.h",
         "generator.h",
+        "includes.h",
         "types.h",
     ],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/container:flat_hash_set",
-        "@com_google_absl//absl/container:node_hash_set",
-        "@com_google_absl//absl/log",
-        "@com_google_absl//absl/random",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:cord",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_absl//absl/types:optional",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/container:btree",
+        "@abseil-cpp//absl/container:flat_hash_set",
+        "@abseil-cpp//absl/container:node_hash_set",
+        "@abseil-cpp//absl/log",
+        "@abseil-cpp//absl/random",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:cord",
+        "@abseil-cpp//absl/strings:str_format",
+        "@abseil-cpp//absl/types:optional",
         "@llvm-project//clang:ast",
         "@llvm-project//clang:basic",
         "@llvm-project//clang:format",
@@ -67,15 +75,22 @@ cc_test(
         "frontend_action_test_util.h",
     ],
     copts = sapi_platform_copts(),
+    data = [
+        ":testdata",
+    ],
     deps = [
         ":generator",
-        "@com_google_absl//absl/container:flat_hash_map",
-        "@com_google_absl//absl/memory",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:status_matchers",
+        "@abseil-cpp//absl/container:flat_hash_map",
+        "@abseil-cpp//absl/log:check",
+        "@abseil-cpp//absl/memory",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
         "@llvm-project//clang:basic",
         "@llvm-project//clang:frontend",
         "@llvm-project//clang:tooling",
@@ -96,15 +111,15 @@ cc_binary(
     visibility = ["//visibility:public"],
     deps = [
         ":generator",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:no_destructor",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_base",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api/util:file_base",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:no_destructor",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
         "@llvm-project//clang:driver",
         "@llvm-project//clang:tooling",
         "@llvm-project//llvm:Support",
diff --git a/sandboxed_api/tools/clang_generator/CMakeLists.txt b/sandboxed_api/tools/clang_generator/CMakeLists.txt
index 31b1446..18b8ab1 100644
--- a/sandboxed_api/tools/clang_generator/CMakeLists.txt
+++ b/sandboxed_api/tools/clang_generator/CMakeLists.txt
@@ -12,11 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# Minimum supported: LLVM 11.0.0
+# Minimum supported: LLVM 18.0.0
 find_package(LLVM REQUIRED)
 find_package(Clang REQUIRED)
-if(LLVM_VERSION VERSION_LESS "11.0.0")
-  message(FATAL_ERROR "SAPI header generator needs LLVM 11 or newer")
+if(LLVM_VERSION VERSION_LESS "18.0.0")
+  message(FATAL_ERROR "SAPI header generator needs LLVM 18 or newer")
 endif()
 
 add_library(sapi_generator
@@ -28,6 +28,7 @@ add_library(sapi_generator
   emitter_base.cc
   generator.h
   generator.cc
+  includes.h
   types.h
   types.cc
 )
@@ -54,11 +55,9 @@ list(APPEND _sapi_generator_llvm_comp
   BinaryFormat
   Demangle
 )
-if(LLVM_VERSION VERSION_GREATER_EQUAL "15.0.0")
-  list(APPEND _sapi_generator_llvm_comp
-    WindowsDriver # Always needed
-  )
-endif()
+list(APPEND _sapi_generator_llvm_comp
+  WindowsDriver # Always needed
+)
 llvm_map_components_to_libnames(_sapi_generator_llvm_libs
   ${_sapi_generator_llvm_comp}
 )
@@ -148,15 +147,20 @@ if(BUILD_TESTING AND SAPI_BUILD_TESTING)
     emitter_test.cc
   )
   target_link_libraries(sapi_generator_test PRIVATE
+    absl::check
     absl::flat_hash_map
     absl::memory
     absl::statusor
     benchmark
+    sapi::file_base
+    sapi::file_helpers
+    sapi::runfiles
     sapi::sapi
     sapi::generator
     sapi::status
     sapi::status_matchers
     sapi::test_main
   )
-  gtest_discover_tests_xcompile(sapi_generator_test)
+  gtest_discover_tests_xcompile(sapi_generator_test
+    ENVIRONMENT "TEST_DATA_DIR=${PROJECT_SOURCE_DIR}/testdata")
 endif()
diff --git a/sandboxed_api/tools/clang_generator/emitter.cc b/sandboxed_api/tools/clang_generator/emitter.cc
index 6e6086c..6fc9cae 100644
--- a/sandboxed_api/tools/clang_generator/emitter.cc
+++ b/sandboxed_api/tools/clang_generator/emitter.cc
@@ -18,6 +18,7 @@
 #include <utility>
 #include <vector>
 
+#include "absl/container/btree_set.h"
 #include "absl/container/flat_hash_set.h"
 #include "absl/log/log.h"
 #include "absl/status/status.h"
@@ -54,9 +55,6 @@ constexpr absl::string_view kHeaderDescription =
 //   1. Header guard
 constexpr absl::string_view kHeaderIncludes =
     R"(
-#include <cstdint>
-#include <type_traits>
-
 #include "absl/base/macros.h"
 #include "absl/status/status.h"
 #include "absl/status/statusor.h"
@@ -240,6 +238,7 @@ absl::StatusOr<std::string> EmitFunction(const clang::FunctionDecl* decl) {
 absl::StatusOr<std::string> EmitHeader(
     const std::vector<std::string>& function_definitions,
     const std::vector<const RenderedType*>& rendered_types,
+    const absl::btree_set<std::string>& rendered_includes,
     const GeneratorOptions& options) {
   // Log a warning message if the number of requested functions is not equal to
   // the number of functions generated.
@@ -257,6 +256,11 @@ absl::StatusOr<std::string> EmitHeader(
   const std::string include_guard = GetIncludeGuard(options.out_file);
   absl::StrAppend(&out, kHeaderDescription);
   absl::StrAppendFormat(&out, kHeaderProlog, include_guard);
+
+  // Emit the collected includes.
+  absl::StrAppend(&out, absl::StrJoin(rendered_includes, "\n"));
+
+  // Emit the common includes.
   absl::StrAppend(&out, kHeaderIncludes);
 
   // When embedding the sandboxee, add embed header include
@@ -333,9 +337,10 @@ absl::Status Emitter::AddFunction(clang::FunctionDecl* decl) {
 
 absl::StatusOr<std::string> Emitter::EmitHeader(
     const GeneratorOptions& options) {
-  SAPI_ASSIGN_OR_RETURN(const std::string header,
-                        ::sapi::EmitHeader(rendered_functions_ordered_,
-                                           rendered_types_ordered_, options));
+  SAPI_ASSIGN_OR_RETURN(
+      const std::string header,
+      ::sapi::EmitHeader(rendered_functions_ordered_, rendered_types_ordered_,
+                         rendered_includes_ordered_, options));
   return internal::ReformatGoogleStyle(options.out_file, header);
 }
 
diff --git a/sandboxed_api/tools/clang_generator/emitter_base.cc b/sandboxed_api/tools/clang_generator/emitter_base.cc
index 91a3b1c..7d194ee 100644
--- a/sandboxed_api/tools/clang_generator/emitter_base.cc
+++ b/sandboxed_api/tools/clang_generator/emitter_base.cc
@@ -39,6 +39,7 @@
 #include "llvm/Support/Error.h"
 #include "llvm/Support/raw_ostream.h"
 #include "sandboxed_api/tools/clang_generator/generator.h"
+#include "sandboxed_api/tools/clang_generator/includes.h"
 
 namespace sapi {
 
@@ -301,4 +302,26 @@ void EmitterBase::AddTypeDeclarations(
   }
 }
 
+std::string EmitInclude(const IncludeInfo& info) {
+  std::string out;
+  if (!info.is_system_header) {
+    return out;
+  }
+
+  if (info.is_angled) {
+    absl::StrAppend(&out, "#include <", info.include, ">");
+    return out;
+  }
+
+  absl::StrAppend(&out, "#include ", info.include, "");
+  return out;
+}
+
+void EmitterBase::AddIncludes(IncludeInfo* include) {
+  std::string include_str = EmitInclude(*include);
+  if (!include_str.empty()) {
+    rendered_includes_ordered_.insert(include_str);
+  }
+}
+
 }  // namespace sapi
diff --git a/sandboxed_api/tools/clang_generator/emitter_base.h b/sandboxed_api/tools/clang_generator/emitter_base.h
index de16c85..c6da66c 100644
--- a/sandboxed_api/tools/clang_generator/emitter_base.h
+++ b/sandboxed_api/tools/clang_generator/emitter_base.h
@@ -19,6 +19,8 @@
 #include <utility>
 #include <vector>
 
+#include "absl/container/btree_map.h"
+#include "absl/container/btree_set.h"
 #include "absl/container/flat_hash_set.h"
 #include "absl/container/node_hash_set.h"
 #include "absl/status/status.h"
@@ -26,6 +28,7 @@
 #include "absl/strings/string_view.h"
 #include "clang/AST/Decl.h"
 #include "clang/AST/Type.h"
+#include "sandboxed_api/tools/clang_generator/includes.h"
 
 namespace sapi {
 // TODO b/347118045 - Refactor the naming of internal namespaces across the
@@ -104,6 +107,9 @@ class EmitterBase {
   // Adds the declarations of previously collected functions to the emitter.
   virtual absl::Status AddFunction(clang::FunctionDecl* decl) = 0;
 
+  // Adds an include to the list of includes to be rendered.
+  void AddIncludes(IncludeInfo* include);
+
   // Stores namespaces and a list of spellings for types. Keeps track of types
   // that have been rendered so far. Using a node_hash_set for pointer
   // stability.
@@ -116,6 +122,17 @@ class EmitterBase {
   // functions that have been rendered so far.
   absl::flat_hash_set<std::string> rendered_functions_;
 
+  // A map of collected includes, keyed by the parse context (i.e. the input
+  // file).
+  absl::btree_map<std::string, std::vector<IncludeInfo>> collected_includes_;
+
+  // A set of the actual include directives to be rendered. It is initialized
+  // with standard includes that are commonly used in generated code.
+  absl::btree_set<std::string> rendered_includes_ordered_ = {
+      "#include <cstdint>",
+      "#include <type_traits>",
+  };
+
  private:
   void EmitType(clang::TypeDecl* type_decl);
 };
diff --git a/sandboxed_api/tools/clang_generator/emitter_test.cc b/sandboxed_api/tools/clang_generator/emitter_test.cc
index 781ddf7..a81123f 100644
--- a/sandboxed_api/tools/clang_generator/emitter_test.cc
+++ b/sandboxed_api/tools/clang_generator/emitter_test.cc
@@ -21,6 +21,7 @@
 
 #include "gmock/gmock.h"
 #include "gtest/gtest.h"
+#include "absl/log/check.h"
 #include "absl/status/statusor.h"
 #include "absl/strings/str_cat.h"
 #include "absl/strings/string_view.h"
@@ -33,6 +34,7 @@ namespace sapi {
 namespace {
 
 using ::testing::ElementsAre;
+using ::testing::HasSubstr;
 using ::testing::IsEmpty;
 using ::testing::MatchesRegex;
 using ::testing::SizeIs;
@@ -41,6 +43,8 @@ using ::testing::StrNe;
 
 class EmitterForTesting : public Emitter {
  public:
+  // Returns the spellings of all rendered_types_ordered_ that have the given
+  // namespace name.
   std::vector<std::string> SpellingsForNS(const std::string& ns_name) {
     std::vector<std::string> result;
     for (const RenderedType* rt : rendered_types_ordered_) {
@@ -58,20 +62,101 @@ class EmitterForTesting : public Emitter {
 
 class EmitterTest : public FrontendActionTest {};
 
-TEST_F(EmitterTest, BasicFunctionality) {
+// Tests that the generator only emits the requested function and ignores the
+// others.
+TEST_F(EmitterTest, SpecificFunctionRequested) {
   GeneratorOptions options;
   options.set_function_names<std::initializer_list<std::string>>(
       {"ExposedFunction"});
 
+  EmitterForTesting emitter;
+  ASSERT_THAT(RunFrontendActionOnFile(
+                  "simple_functions.cc",
+                  std::make_unique<GeneratorAction>(emitter, options)),
+              IsOk());
+  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(1));
+
+  absl::StatusOr<std::string> header = emitter.EmitHeader(options);
+  ASSERT_THAT(header, IsOk());
+  EXPECT_THAT(*header, HasSubstr("ExposedFunction"));
+}
+
+// Tests that the generator emits all functions if no specific functions are
+// requested.
+TEST_F(EmitterTest, AllFunctionsSuccess) {
+  constexpr absl::string_view input_file = "simple_functions.cc";
+  GeneratorOptions options;
+  options.set_function_names<std::initializer_list<std::string>>({});
+  options.in_files = {"simple_functions.cc"};
+
   EmitterForTesting emitter;
   ASSERT_THAT(
-      RunFrontendAction(R"(extern "C" void ExposedFunction() {})",
-                        std::make_unique<GeneratorAction>(emitter, options)),
+      RunFrontendActionOnFile(
+          input_file, std::make_unique<GeneratorAction>(emitter, options)),
       IsOk());
-  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(1));
+  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(2));
+
+  absl::StatusOr<std::string> header = emitter.EmitHeader(options);
+  ASSERT_THAT(header, IsOk());
+  EXPECT_THAT(*header, HasSubstr("ExposedFunction"));
+  EXPECT_THAT(*header, HasSubstr("OtherFunction"));
+}
+
+// Tests that the generator emits all functions if no specific functions are
+// requested, and the input file is not provided.
+TEST_F(EmitterTest, AllFunctionsNoInputFiles) {
+  GeneratorOptions options;
+  options.set_function_names<std::initializer_list<std::string>>({});
+
+  EmitterForTesting emitter;
+  ASSERT_THAT(RunFrontendActionOnFile(
+                  "simple_functions.cc",
+                  std::make_unique<GeneratorAction>(emitter, options)),
+              IsOk());
+  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(2));
 
   absl::StatusOr<std::string> header = emitter.EmitHeader(options);
-  EXPECT_THAT(header, IsOk());
+  ASSERT_THAT(header, IsOk());
+  EXPECT_THAT(*header, HasSubstr("ExposedFunction"));
+  EXPECT_THAT(*header, HasSubstr("OtherFunction"));
+}
+
+// Tests that the generator emits all functions if no specific functions are
+// requested, the input file is provided, and the limit scan depth is enabled.
+TEST_F(EmitterTest, AllFunctionsLimitScanDepthSuccess) {
+  constexpr absl::string_view input_file = "simple_functions.cc";
+  GeneratorOptions options;
+  options.set_function_names<std::initializer_list<std::string>>({});
+  options.limit_scan_depth = true;
+  options.in_files.emplace(input_file);
+
+  EmitterForTesting emitter;
+  ASSERT_THAT(
+      RunFrontendActionOnFile(
+          input_file, std::make_unique<GeneratorAction>(emitter, options)),
+      IsOk());
+  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(2));
+
+  absl::StatusOr<std::string> header = emitter.EmitHeader(options);
+  ASSERT_THAT(header, IsOk());
+  EXPECT_THAT(*header, HasSubstr("ExposedFunction"));
+  EXPECT_THAT(*header, HasSubstr("OtherFunction"));
+}
+
+// Tests that the generator fails to emit all functions if no specific functions
+// are requested, the input file is not provided, and the limit scan depth is
+// enabled.
+TEST_F(EmitterTest, AllFunctionsLimitScanDepthFailure) {
+  GeneratorOptions options;
+  options.set_function_names<std::initializer_list<std::string>>({});
+  options.limit_scan_depth = true;
+
+  EmitterForTesting emitter;
+  ASSERT_THAT(RunFrontendActionOnFile(
+                  "simple_functions.cc",
+                  std::make_unique<GeneratorAction>(emitter, options)),
+              IsOk());
+  EXPECT_THAT(emitter.GetRenderedFunctions(), IsEmpty());
 }
 
 TEST_F(EmitterTest, RelatedTypes) {
@@ -412,6 +497,28 @@ TEST_F(EmitterTest, SkipAbseilInternals) {
   EXPECT_THAT(UglifyAll(emitter.SpellingsForNS("")), IsEmpty());
 }
 
+TEST_F(EmitterTest, SkipProtobufMessagesInternals) {
+  EmitterForTesting emitter;
+  EXPECT_THAT(
+      RunFrontendAction(
+          R"(namespace google::protobuf {
+               class Message {};
+             }
+             class MySpecialType {
+               int x;
+             };
+             class MyMessage : public google::protobuf::Message {
+               MySpecialType member;
+             };
+             extern "C" void TakesAMessage(MyMessage*);)",
+          std::make_unique<GeneratorAction>(emitter, GeneratorOptions())),
+      IsOk());
+  EXPECT_THAT(emitter.GetRenderedFunctions(), SizeIs(1));
+
+  EXPECT_THAT(UglifyAll(emitter.SpellingsForNS("")),
+              ElementsAre("class MyMessage"));
+}
+
 TEST(IncludeGuard, CreatesRandomizedGuardForEmptyFilename) {
   // Copybara will transform the string. This is intentional.
   constexpr absl::string_view kGeneratedHeaderPrefix =
diff --git a/sandboxed_api/tools/clang_generator/frontend_action_test_util.cc b/sandboxed_api/tools/clang_generator/frontend_action_test_util.cc
index 5573b26..4abcfae 100644
--- a/sandboxed_api/tools/clang_generator/frontend_action_test_util.cc
+++ b/sandboxed_api/tools/clang_generator/frontend_action_test_util.cc
@@ -22,6 +22,7 @@
 #include <vector>
 
 #include "absl/container/flat_hash_map.h"
+#include "absl/log/check.h"
 #include "absl/status/status.h"
 #include "absl/strings/ascii.h"
 #include "absl/strings/str_cat.h"
@@ -36,10 +37,21 @@
 #include "llvm/Config/llvm-config.h"
 #include "llvm/Support/MemoryBuffer.h"
 #include "llvm/Support/VirtualFileSystem.h"
+#include "sandboxed_api/testing.h"
+#include "sandboxed_api/util/file_helpers.h"
+#include "sandboxed_api/util/path.h"
 
 namespace sapi {
 namespace internal {
 
+std::string GetTestFileContents(absl::string_view file) {
+  std::string contents;
+  CHECK_OK(file::GetContents(GetTestSourcePath(file::JoinPath(
+                                 "tools/clang_generator/testdata/", file)),
+                             &contents, file::Defaults()));
+  return contents;
+}
+
 absl::Status RunClangTool(
     const std::vector<std::string>& command_line,
     const absl::flat_hash_map<std::string, std::string>& file_contents,
@@ -58,13 +70,8 @@ absl::Status RunClangTool(
     }
   }
 
-#if LLVM_VERSION_MAJOR >= 10
   clang::tooling::ToolInvocation invocation(command_line, std::move(action),
                                             files.get());
-#else
-  clang::tooling::ToolInvocation invocation(command_line, action.get(),
-                                            files.get());
-#endif
   if (!invocation.run()) {
     return absl::UnknownError("Tool invocation failed");
   }
@@ -79,6 +86,7 @@ std::vector<std::string> FrontendActionTest::GetCommandLineFlagsForTesting(
           "-I.",  "-Wno-error",    std::string(input_file)};
 }
 
+// Replaces all newlines with spaces and removes consecutive runs of whitespace.
 std::string Uglify(absl::string_view code) {
   std::string result = absl::StrReplaceAll(code, {{"\n", " "}});
   absl::RemoveExtraAsciiWhitespace(&result);
diff --git a/sandboxed_api/tools/clang_generator/frontend_action_test_util.h b/sandboxed_api/tools/clang_generator/frontend_action_test_util.h
index 2dcbb35..0b773eb 100644
--- a/sandboxed_api/tools/clang_generator/frontend_action_test_util.h
+++ b/sandboxed_api/tools/clang_generator/frontend_action_test_util.h
@@ -31,6 +31,11 @@
 namespace sapi {
 namespace internal {
 
+// Returns the contents of the file.
+std::string GetTestFileContents(absl::string_view file);
+
+// Sets up a virtual filesystem, adds code files to it, and runs a clang tool
+// on it.
 absl::Status RunClangTool(
     const std::vector<std::string>& command_line,
     const absl::flat_hash_map<std::string, std::string>& file_contents,
@@ -51,9 +56,19 @@ class FrontendActionTest : public ::testing::Test {
     input_file_ = std::string(value);
   }
 
+  // Returns the command line flags for the specified input file.
   virtual std::vector<std::string> GetCommandLineFlagsForTesting(
       absl::string_view input_file);
 
+  // Runs the specified frontend action on file loaded in-memory.
+  absl::Status RunFrontendActionOnFile(
+      absl::string_view input_file,
+      std::unique_ptr<clang::FrontendAction> action) {
+    set_input_file(input_file);
+    std::string code = internal::GetTestFileContents(input_file);
+    return RunFrontendAction(code, std::move(action));
+  }
+
   // Runs the specified frontend action on in-memory source code.
   absl::Status RunFrontendAction(
       absl::string_view code, std::unique_ptr<clang::FrontendAction> action) {
@@ -64,24 +79,15 @@ class FrontendActionTest : public ::testing::Test {
                                   std::move(action));
   }
 
-  // Runs the specified frontend action. Provided for compatibility with LLVM <
-  // 10. Takes ownership.
-  absl::Status RunFrontendAction(absl::string_view code,
-                                 clang::FrontendAction* action) {
-    return RunFrontendAction(code, absl::WrapUnique(action));
-  }
-
  private:
   std::string input_file_ = "input.cc";
   absl::flat_hash_map<std::string, std::string> file_contents_;
 };
 
-// Flattens a piece of C++ code into one line and removes consecutive runs of
-// whitespace. This makes it easier to compare code snippets for testing.
-// Note: This is not syntax-aware and will replace characters within strings as
-// well.
-std::string Uglify(absl::string_view code);
-
+// Flattens a vector of C++ code snippets into one line and removes consecutive
+// runs of whitespace. This makes it easier to compare code snippets for
+// testing. Note: This is not syntax-aware and will replace characters within
+// strings as well.
 std::vector<std::string> UglifyAll(const std::vector<std::string>& snippets);
 
 }  // namespace sapi
diff --git a/sandboxed_api/tools/clang_generator/generator.cc b/sandboxed_api/tools/clang_generator/generator.cc
index a4e13f3..3f33a2a 100644
--- a/sandboxed_api/tools/clang_generator/generator.cc
+++ b/sandboxed_api/tools/clang_generator/generator.cc
@@ -20,6 +20,7 @@
 #include <utility>
 #include <vector>
 
+#include "absl/container/btree_map.h"
 #include "absl/container/flat_hash_set.h"
 #include "absl/status/status.h"
 #include "absl/strings/match.h"
@@ -29,15 +30,22 @@
 #include "clang/AST/ASTContext.h"
 #include "clang/AST/Decl.h"
 #include "clang/AST/Type.h"
+#include "clang/AST/TypeLoc.h"
 #include "clang/Basic/Diagnostic.h"
+#include "clang/Basic/FileEntry.h"
+#include "clang/Basic/LLVM.h"
 #include "clang/Basic/SourceLocation.h"
 #include "clang/Basic/SourceManager.h"
 #include "clang/Frontend/CompilerInvocation.h"
+#include "clang/Lex/Lexer.h"
+#include "clang/Lex/PPCallbacks.h"
 #include "clang/Lex/PreprocessorOptions.h"
 #include "clang/Serialization/PCHContainerOperations.h"
 #include "clang/Tooling/Tooling.h"
+#include "llvm/Config/llvm-config.h"
 #include "sandboxed_api/tools/clang_generator/diagnostics.h"
 #include "sandboxed_api/tools/clang_generator/emitter_base.h"
+#include "sandboxed_api/tools/clang_generator/includes.h"
 
 namespace sapi {
 namespace {
@@ -55,12 +63,81 @@ std::string ReplaceFileExtension(absl::string_view path,
 
 }  // namespace
 
+// IncludeRecorder is a clang preprocessor callback that records includes from
+// the input files.
+class IncludeRecorder : public clang::PPCallbacks {
+ public:
+  IncludeRecorder(std::string current_file,
+                  clang::SourceManager& source_manager,
+                  absl::btree_map<std::string, std::vector<IncludeInfo>>&
+                      collected_includes)
+      : current_file_(std::move(current_file)),
+        source_manager_(source_manager),
+        collected_includes_(collected_includes) {}
+
+  // Will only record direct includes from the input file.
+  void InclusionDirective(
+      clang::SourceLocation hash_loc, const clang::Token& include_tok,
+      clang::StringRef filename, bool is_angled,
+      clang::CharSourceRange filename_range, clang::OptionalFileEntryRef file,
+      clang::StringRef search_path, clang::StringRef relative_path,
+#if LLVM_VERSION_MAJOR >= 19
+      const clang::Module* suggested_module, bool module_imported,
+#else
+      const clang::Module* imported,
+#endif
+      clang::SrcMgr::CharacteristicKind file_type) override;
+
+ private:
+  // The input file which is currently being processed.
+  std::string current_file_;
+
+  // The source manager for the current file.
+  clang::SourceManager& source_manager_;
+
+  // Reference to the map of collected includes, owned by the BaseEmitter.
+  absl::btree_map<std::string, std::vector<IncludeInfo>>& collected_includes_;
+};
+
+void IncludeRecorder::InclusionDirective(
+    clang::SourceLocation hash_loc, const clang::Token& include_tok,
+    clang::StringRef filename, bool is_angled,
+    clang::CharSourceRange filename_range, clang::OptionalFileEntryRef file,
+    clang::StringRef search_path, clang::StringRef relative_path,
+#if LLVM_VERSION_MAJOR >= 19
+    const clang::Module* suggested_module, bool module_imported,
+#else
+    const clang::Module* imported,
+#endif
+    clang::SrcMgr::CharacteristicKind file_type) {
+
+  // Filter out includes which are not directly included from the input files
+  // and remove includes which have a path component (e.g. <foo/bar>).
+  // TODO b/402670257 - Handle cases where a path component is present.
+  if (current_file_ ==
+          RemoveHashLocationMarker(hash_loc.printToString(source_manager_)) &&
+      !relative_path.contains("/")) {
+    // file is of type OptionalFileEntryRef, ensure it has a value, otherwise
+    // skip the include.
+    if (!file.has_value()) {
+      return;
+    }
+    collected_includes_[current_file_].push_back({
+        .include = filename.str(),
+        .file = *file,
+        .is_angled = is_angled,
+        .is_system_header = (file_type == clang::SrcMgr::C_System),
+    });
+  }
+}
+
 std::string GetOutputFilename(absl::string_view source_file) {
   return ReplaceFileExtension(source_file, ".sapi.h");
 }
 
+// Called during HandleTranslationUnit
 bool GeneratorASTVisitor::VisitTypeDecl(clang::TypeDecl* decl) {
-  collector_.RecordOrderedDecl(decl);
+  type_collector_.RecordOrderedTypeDeclarations(decl);
   return true;
 }
 
@@ -73,15 +150,15 @@ bool GeneratorASTVisitor::VisitFunctionDecl(clang::FunctionDecl* decl) {
   }
 
   // Process either all function or just the requested ones
-  bool all_functions = options_.function_names.empty();
-  if (!all_functions &&
+  bool sandbox_all_functions = options_.function_names.empty();
+  if (!sandbox_all_functions &&
       !options_.function_names.contains(ToStringView(decl->getName()))) {
     return true;
   }
 
   // Skip Abseil internal functions when all functions are requested. This still
   // allows them to be specified explicitly.
-  if (all_functions &&
+  if (sandbox_all_functions &&
       absl::StartsWith(decl->getQualifiedNameAsString(), "AbslInternal")) {
     return true;
   }
@@ -92,11 +169,11 @@ bool GeneratorASTVisitor::VisitFunctionDecl(clang::FunctionDecl* decl) {
 
   // Skip functions from system headers when all functions are requested. Like
   // above, they can still explicitly be specified.
-  if (all_functions && source_manager.isInSystemHeader(decl_start)) {
+  if (sandbox_all_functions && source_manager.isInSystemHeader(decl_start)) {
     return true;
   }
 
-  if (all_functions) {
+  if (sandbox_all_functions) {
     const std::string filename(absl::StripPrefix(
         ToStringView(source_manager.getFilename(decl_start)), "./"));
     if (options_.limit_scan_depth && !options_.in_files.contains(filename)) {
@@ -106,9 +183,11 @@ bool GeneratorASTVisitor::VisitFunctionDecl(clang::FunctionDecl* decl) {
 
   functions_.push_back(decl);
 
-  collector_.CollectRelatedTypes(decl->getDeclaredReturnType());
+  // Store the return type and parameters for type collection.
+  type_collector_.CollectRelatedTypes(decl->getDeclaredReturnType());
+
   for (const clang::ParmVarDecl* param : decl->parameters()) {
-    collector_.CollectRelatedTypes(param->getType());
+    type_collector_.CollectRelatedTypes(param->getType());
   }
 
   return true;
@@ -122,7 +201,14 @@ void GeneratorASTConsumer::HandleTranslationUnit(clang::ASTContext& context) {
     return;
   }
 
-  emitter_.AddTypeDeclarations(visitor_.collector().GetTypeDeclarations());
+  for (auto& [parse_ctx, includes] : emitter_.collected_includes_) {
+    for (auto& include : includes) {
+      emitter_.AddIncludes(&include);
+    }
+  }
+
+  emitter_.AddTypeDeclarations(visitor_.type_collector().GetTypeDeclarations());
+
   for (clang::FunctionDecl* func : visitor_.functions()) {
     absl::Status status = emitter_.AddFunction(func);
     if (!status.ok()) {
@@ -138,6 +224,18 @@ void GeneratorASTConsumer::HandleTranslationUnit(clang::ASTContext& context) {
   }
 }
 
+// Called at the start of processing an input file, before
+// HandleTranslationUnit.
+bool GeneratorAction::BeginSourceFileAction(clang::CompilerInstance& ci) {
+  ci.getPreprocessor().addPPCallbacks(std::make_unique<IncludeRecorder>(
+      ci.getSourceManager()
+          .getFileEntryRefForID(ci.getSourceManager().getMainFileID())
+          ->getName()
+          .str(),
+      ci.getSourceManager(), emitter_.collected_includes_));
+  return true;
+}
+
 bool GeneratorFactory::runInvocation(
     std::shared_ptr<clang::CompilerInvocation> invocation,
     clang::FileManager* files,
@@ -319,6 +417,24 @@ bool GeneratorFactory::runInvocation(
            "__builtin_ia32_vpopcntw_128=",
            "__builtin_ia32_vpopcntw_256=",
            "__builtin_ia32_vpopcntw_512=",
+           "__builtin_ia32_vcvttpd2dqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m128i {return __m128i();}",
+           "__builtin_ia32_vcvttpd2udqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m128i {return __m128i();}",
+           "__builtin_ia32_vcvttpd2qqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttpd2uqqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttps2dqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttps2udqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttps2qqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttps2uqqs256_round_mask=[](auto, auto, auto, "
+           "auto)->__m256i {return __m256i();}",
+           "__builtin_ia32_vcvttps2uqqs512_round_mask=[](auto, auto, auto, "
+           "auto)->__m512i {return __m512i();}",
        }) {
     options.addMacroDef(def);
     // To avoid code to include header with compiler intrinsics, undefine a few
diff --git a/sandboxed_api/tools/clang_generator/generator.h b/sandboxed_api/tools/clang_generator/generator.h
index 3431d86..f5fa1c9 100644
--- a/sandboxed_api/tools/clang_generator/generator.h
+++ b/sandboxed_api/tools/clang_generator/generator.h
@@ -85,14 +85,14 @@ class GeneratorASTVisitor
   bool VisitTypeDecl(clang::TypeDecl* decl);
   bool VisitFunctionDecl(clang::FunctionDecl* decl);
 
-  TypeCollector& collector() { return collector_; }
+  TypeCollector& type_collector() { return type_collector_; }
 
   const std::vector<clang::FunctionDecl*>& functions() const {
     return functions_;
   }
 
  private:
-  TypeCollector collector_;
+  TypeCollector type_collector_;
   std::vector<clang::FunctionDecl*> functions_;
   const GeneratorOptions& options_;
 };
@@ -123,10 +123,7 @@ class GeneratorAction : public clang::ASTFrontendAction {
                                                   emitter_, options_);
   }
 
-  bool BeginSourceFileAction(clang::CompilerInstance& ci) override {
-    ci.getPreprocessor().enableIncrementalProcessing();
-    return true;
-  }
+  bool BeginSourceFileAction(clang::CompilerInstance& ci);
 
   bool hasCodeCompletionSupport() const override { return false; }
 
@@ -141,15 +138,9 @@ class GeneratorFactory : public clang::tooling::FrontendActionFactory {
       : emitter_(emitter), options_(options) {}
 
  private:
-#if LLVM_VERSION_MAJOR >= 10
   std::unique_ptr<clang::FrontendAction> create() override {
     return std::make_unique<GeneratorAction>(emitter_, options_);
   }
-#else
-  clang::FrontendAction* create() override {
-    return new GeneratorAction(emitter_, options_);
-  }
-#endif
 
   bool runInvocation(
       std::shared_ptr<clang::CompilerInvocation> invocation,
diff --git a/sandboxed_api/tools/clang_generator/includes.h b/sandboxed_api/tools/clang_generator/includes.h
new file mode 100644
index 0000000..eecae4e
--- /dev/null
+++ b/sandboxed_api/tools/clang_generator/includes.h
@@ -0,0 +1,51 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef SANDBOXED_API_TOOLS_CLANG_GENERATOR_INCLUDES_H_
+#define SANDBOXED_API_TOOLS_CLANG_GENERATOR_INCLUDES_H_
+
+#include <string>
+
+#include "absl/strings/string_view.h"
+#include "clang/Basic/FileEntry.h"
+
+namespace sapi {
+
+// Struct to store the information about an include directive.
+struct IncludeInfo {
+  // The string of the include directive.
+  std::string include;
+  // The file entry of the included file.
+  const clang::FileEntryRef file;
+  // True, if the include is an angled include, false otherwise.
+  bool is_angled;
+  // True, if the include is a system header, false otherwise.
+  bool is_system_header;
+};
+
+// Removes the hash location marker from the hash location string.
+// Example:
+//   "[...]clang_generator/test/test_include.h:33:9" changes to
+//   "[...]clang_generator/test/test_include.h"
+inline std::string RemoveHashLocationMarker(absl::string_view hash_loc) {
+  const auto first_colon_pos = hash_loc.find(':');
+  if (first_colon_pos == absl::string_view::npos) {
+    return std::string(hash_loc);
+  }
+  return std::string(hash_loc.substr(0, first_colon_pos));
+}
+
+}  // namespace sapi
+
+#endif  // SANDBOXED_API_TOOLS_CLANG_GENERATOR_INCLUDES_H_
diff --git a/sandboxed_api/tools/clang_generator/testdata/simple_functions.cc b/sandboxed_api/tools/clang_generator/testdata/simple_functions.cc
new file mode 100644
index 0000000..2f5b8af
--- /dev/null
+++ b/sandboxed_api/tools/clang_generator/testdata/simple_functions.cc
@@ -0,0 +1,22 @@
+// Copyright 2025 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// This file is used to test the generator's handling of simple functions.
+//
+// We expect that the generator will emit either the specifically requested
+// function, or all functions otherwise.
+
+extern "C" void ExposedFunction() {}
+
+extern "C" void OtherFunction() {}
diff --git a/sandboxed_api/tools/clang_generator/types.cc b/sandboxed_api/tools/clang_generator/types.cc
index e5132b9..35bb274 100644
--- a/sandboxed_api/tools/clang_generator/types.cc
+++ b/sandboxed_api/tools/clang_generator/types.cc
@@ -22,26 +22,34 @@
 #include "absl/strings/str_cat.h"
 #include "clang/AST/ASTContext.h"
 #include "clang/AST/Decl.h"
+#include "clang/AST/DeclCXX.h"
 #include "clang/AST/QualTypeNames.h"
 #include "clang/AST/Type.h"
-#include "llvm/Config/llvm-config.h"
 #include "llvm/Support/Casting.h"
 
 namespace sapi {
 namespace {
 
-bool IsFunctionReferenceType(clang::QualType qual) {
-#if LLVM_VERSION_MAJOR >= 9
-  return qual->isFunctionReferenceType();
-#else
-  const auto* ref = qual->getAs<clang::ReferenceType>();
-  return ref && ref->getPointeeType()->isFunctionType();
-#endif
+bool IsProtoBuf(const clang::RecordDecl* decl) {
+  const auto* cxxdecl = llvm::dyn_cast<const clang::CXXRecordDecl>(decl);
+  if (cxxdecl == nullptr) {
+    return false;
+  }
+  if (!cxxdecl->hasDefinition()) {
+    return false;
+  }
+  for (const clang::CXXBaseSpecifier& base : cxxdecl->bases()) {
+    if (base.getType()->getAsCXXRecordDecl()->getQualifiedNameAsString() ==
+        "google::protobuf::Message") {
+      return true;
+    }
+  }
+  return false;
 }
 
 }  // namespace
 
-void TypeCollector::RecordOrderedDecl(clang::TypeDecl* type_decl) {
+void TypeCollector::RecordOrderedTypeDeclarations(clang::TypeDecl* type_decl) {
   // This implicitly assigns a number (its source order) to each declaration.
   ordered_decls_.push_back(type_decl);
 }
@@ -53,8 +61,11 @@ void TypeCollector::CollectRelatedTypes(clang::QualType qual) {
 
   if (const auto* record_type = qual->getAs<clang::RecordType>()) {
     const clang::RecordDecl* decl = record_type->getDecl();
-    for (const clang::FieldDecl* field : decl->fields()) {
-      CollectRelatedTypes(field->getType());
+    // Do not collect internals of a protobuf message.
+    if (!IsProtoBuf(decl)) {
+      for (const clang::FieldDecl* field : decl->fields()) {
+        CollectRelatedTypes(field->getType());
+      }
     }
     // Do not collect structs/unions if they are declared within another
     // record. The enclosing type is enough to reconstruct the AST when
@@ -75,7 +86,7 @@ void TypeCollector::CollectRelatedTypes(clang::QualType qual) {
     return;
   }
 
-  if (qual->isFunctionPointerType() || IsFunctionReferenceType(qual) ||
+  if (qual->isFunctionPointerType() || qual->isFunctionReferenceType() ||
       qual->isMemberFunctionPointerType()) {
     if (const auto* function_type = qual->getPointeeOrArrayElementType()
                                         ->getAs<clang::FunctionProtoType>()) {
@@ -122,7 +133,7 @@ std::string GetQualTypeName(const clang::ASTContext& context,
   clang::QualType unqual = qual.getLocalUnqualifiedType();
 
   // This is to get to the actual name of function pointers.
-  if (unqual->isFunctionPointerType() || IsFunctionReferenceType(unqual) ||
+  if (unqual->isFunctionPointerType() || unqual->isFunctionReferenceType() ||
       unqual->isMemberFunctionPointerType()) {
     unqual = unqual->getPointeeType();
   }
@@ -198,13 +209,7 @@ namespace {
 // type. Keeps top-level typedef types intact.
 clang::QualType MaybeRemoveConst(const clang::ASTContext& context,
                                  clang::QualType qual) {
-  if (
-#if LLVM_VERSION_MAJOR < 13
-      qual->getAs<clang::TypedefType>() == nullptr
-#else
-      !qual->isTypedefNameType()
-#endif
-      && IsPointerOrReference(qual)) {
+  if (!qual->isTypedefNameType() && IsPointerOrReference(qual)) {
     clang::QualType pointee_qual = qual->getPointeeType();
     pointee_qual.removeLocalConst();
     qual = context.getPointerType(pointee_qual);
diff --git a/sandboxed_api/tools/clang_generator/types.h b/sandboxed_api/tools/clang_generator/types.h
index 403fb29..1eab7bf 100644
--- a/sandboxed_api/tools/clang_generator/types.h
+++ b/sandboxed_api/tools/clang_generator/types.h
@@ -47,7 +47,7 @@ class TypeCollector {
   // This is different from collecting related types, as the emitter also needs
   // to know in which order to emit typedefs vs forward decls, etc. and
   // QualTypes only refer to complete definitions.
-  void RecordOrderedDecl(clang::TypeDecl* type_decl);
+  void RecordOrderedTypeDeclarations(clang::TypeDecl* type_decl);
 
   // Computes the transitive closure of all types that a type depends on. Those
   // are types that need to be declared before a declaration of the type denoted
diff --git a/sandboxed_api/tools/filewrapper/BUILD b/sandboxed_api/tools/filewrapper/BUILD
index 2ab971d..51a181d 100644
--- a/sandboxed_api/tools/filewrapper/BUILD
+++ b/sandboxed_api/tools/filewrapper/BUILD
@@ -12,8 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:embed_data.bzl", "sapi_cc_embed_data")
 
 licenses(["notice"])
 
@@ -25,11 +25,11 @@ cc_binary(
     copts = sapi_platform_copts(),
     visibility = ["//visibility:public"],
     deps = [
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_sandboxed_api//sandboxed_api/util:fileops",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
-        "@com_google_sandboxed_api//sandboxed_api/util:strerror",
+        "//sandboxed_api/util:fileops",
+        "//sandboxed_api/util:raw_logging",
+        "//sandboxed_api/util:strerror",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
     ],
 )
 
@@ -45,9 +45,9 @@ cc_test(
     data = ["testdata/filewrapper_embedded.bin"],
     deps = [
         ":filewrapper_embedded",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
-        "@com_google_sandboxed_api//sandboxed_api/util:file_helpers",
-        "@com_google_sandboxed_api//sandboxed_api/util:status_matchers",
+        "//sandboxed_api:testing",
+        "//sandboxed_api/util:file_helpers",
+        "//sandboxed_api/util:status_matchers",
+        "@googletest//:gtest_main",
     ],
 )
diff --git a/sandboxed_api/tools/python_generator/BUILD b/sandboxed_api/tools/python_generator/BUILD
index 7601eb3..c061e1b 100644
--- a/sandboxed_api/tools/python_generator/BUILD
+++ b/sandboxed_api/tools/python_generator/BUILD
@@ -12,8 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:sapi.bzl", "sapi_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:sapi.bzl", "sapi_library")
 
 licenses(["notice"])
 
@@ -31,8 +31,8 @@ py_test(
     ],
     deps = [
         ":code",
-        "@com_google_absl_py//absl/testing:absltest",
-        "@com_google_absl_py//absl/testing:parameterized",
+        "@abseil-py//absl/testing:absltest",
+        "@abseil-py//absl/testing:parameterized",
     ],
 )
 
@@ -42,9 +42,9 @@ py_binary(
     visibility = ["//visibility:public"],
     deps = [
         ":code",
-        "@com_google_absl_py//absl:app",
-        "@com_google_absl_py//absl/flags",
-        "@com_google_absl_py//absl/logging",
+        "@abseil-py//absl:app",
+        "@abseil-py//absl/flags",
+        "@abseil-py//absl/logging",
     ],
 )
 
@@ -82,11 +82,11 @@ cc_binary(
     copts = sapi_platform_copts(),
     deps = [
         ":tests_sapi_generator",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_sandboxed_api//sandboxed_api:sapi",
-        "@com_google_sandboxed_api//sandboxed_api:vars",
-        "@com_google_sandboxed_api//sandboxed_api/util:status",
+        "//sandboxed_api:sapi",
+        "//sandboxed_api:vars",
+        "//sandboxed_api/util:status",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
     ],
 )
 
diff --git a/sandboxed_api/tools/python_generator/code.py b/sandboxed_api/tools/python_generator/code.py
index 4c62168..541fb48 100644
--- a/sandboxed_api/tools/python_generator/code.py
+++ b/sandboxed_api/tools/python_generator/code.py
@@ -26,6 +26,7 @@ from typing import (
     Text,
     List,
     Optional,
+    FrozenSet,
     Set,
     Dict,
     Callable,
@@ -73,13 +74,22 @@ def get_header_guard(path):
   return path + '_'
 
 
-def _stringify_tokens(tokens, separator='\n'):
-  # type: (Sequence[cindex.Token], Text) -> Text
+def _stringify_tokens(tokens, separator='\n', continued_lines=frozenset()):
+  # type: (Sequence[cindex.Token], Text, Set[int]) -> Text
   """Converts tokens to text respecting line position (disrespecting column)."""
   previous = OutputLine(0, [])  # not used in output
   lines = []  # type: List[OutputLine]
 
-  for _, group in itertools.groupby(tokens, lambda t: t.location.line):
+  # Group all tokens from a same line together. If a line is terminated by
+  # a backslash (line continuation), merge tokens from the next line too.
+  # This is needed because clang doesn't output backslash-newlines as tokens.
+  def get_token_line(t: cindex.Token):
+    line = t.location.line
+    while (line - 1) in continued_lines:
+      line -= 1
+    return line
+
+  for _, group in itertools.groupby(tokens, get_token_line):
     group_list = list(group)
     line = OutputLine(previous.next_tab, group_list)
 
@@ -364,7 +374,12 @@ class Type(object):
         if x.kind is not cindex.TokenKind.COMMENT
     ]
 
-    return _stringify_tokens(tokens)
+    return _stringify_tokens(
+        tokens,
+        continued_lines=self._tu.get_continued_lines(
+            tokens[0].location.file.name
+        ),
+    )
 
 
 class OutputLine(object):
@@ -581,8 +596,15 @@ class Function(object):
 class _TranslationUnit(object):
   """Class wrapping clang's _TranslationUnit. Provides extra utilities."""
 
-  def __init__(self, path, tu, limit_scan_depth=False, func_names=None):
-    # type: (Text, cindex.TranslationUnit, bool, Optional[List[Text]]) -> None
+  def __init__(
+      self,
+      path,
+      tu,
+      limit_scan_depth=False,
+      func_names=None,
+      unsaved_files=None,
+  ):
+    # type: (Text, cindex.TranslationUnit, bool, Optional[List[Text]], Optional[List]) -> None  # pylint:disable=line-too-long
     """Initializes the translation unit.
 
     Args:
@@ -591,6 +613,7 @@ class _TranslationUnit(object):
       limit_scan_depth: whether scan should be limited to single file
       func_names: list of function names to take into consideration, empty means
         all functions.
+      unsaved_files: [(path: str, content: str)] in-memory contents for files
     """
     self.path = path
     self.limit_scan_depth = limit_scan_depth
@@ -603,6 +626,12 @@ class _TranslationUnit(object):
     self.required_defines = set()
     self.types_to_skip = set()
     self.func_names = func_names or []
+    # Record line numbers of lines that end in line-continuation backslashes.
+    # Clang tokenizer doesn't output them as tokens, but they are needed when
+    # reconstructing preprocessor commands.
+    self._continued_lines = dict()
+    for path, content in unsaved_files or []:
+      self._continued_lines[path] = self._find_continued_lines(content)
 
   def _process(self):
     # type: () -> None
@@ -666,6 +695,24 @@ class _TranslationUnit(object):
     except ValueError:
       return
 
+  def _find_continued_lines(self, content):
+    # type: (Text) -> FrozenSet[int]
+    result = set()
+    for line_num, line in enumerate(content.splitlines(), start=1):
+      if line.rstrip().endswith('\\'):
+        result.add(line_num)
+    return frozenset(result)
+
+  def get_continued_lines(self, path):
+    # type: (Text) -> FrozenSet[int]
+    """Returns numbers of lines with continuation backslashes from the file."""
+    if path not in self._continued_lines:
+      with open(path, 'rt') as source_f:
+        self._continued_lines[path] = self._find_continued_lines(
+            source_f.read()
+        )
+    return self._continued_lines[path]
+
 
 class Analyzer(object):
   """Class responsible for analysis."""
@@ -720,6 +767,7 @@ class Analyzer(object):
         ),
         limit_scan_depth=limit_scan_depth,
         func_names=func_names,
+        unsaved_files=unsaved_files,
     )
 
 
diff --git a/sandboxed_api/tools/python_generator/code_test.py b/sandboxed_api/tools/python_generator/code_test.py
index 2f6ec3f..7387045 100644
--- a/sandboxed_api/tools/python_generator/code_test.py
+++ b/sandboxed_api/tools/python_generator/code_test.py
@@ -626,7 +626,7 @@ class CodeAnalysisTest(parameterized.TestCase):
     self.assertLen(functions, 1)
 
   def testTypeToString(self):
-    body = """
+    body = r"""
       #define SIZE 1024
       typedef unsigned int uint;
 
@@ -706,7 +706,7 @@ class CodeAnalysisTest(parameterized.TestCase):
     generator.generate('Test', 'sapi::Tests', None, None)
 
   def testYaraCase(self):
-    body = """
+    body = r"""
       #define YR_ALIGN(n) __attribute__((aligned(n)))
       #define DECLARE_REFERENCE(type, name) union {    \
         type name;            \
@@ -756,7 +756,7 @@ class CodeAnalysisTest(parameterized.TestCase):
     generator.generate('Test', 'sapi::Tests', None, None)
 
   def testDefineStructBody(self):
-    body = """
+    body = r"""
       #define STRUCT_BODY \
       int a;  \
       char b; \
diff --git a/sandboxed_api/util/BUILD b/sandboxed_api/util/BUILD
index e37b8b1..185a711 100644
--- a/sandboxed_api/util/BUILD
+++ b/sandboxed_api/util/BUILD
@@ -12,11 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@com_google_sandboxed_api//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
-load("@com_google_sandboxed_api//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
+load("//sandboxed_api/bazel:build_defs.bzl", "sapi_platform_copts")
+load("//sandboxed_api/bazel:proto.bzl", "sapi_proto_library")
 
 package(default_visibility = [
-    "@com_google_sandboxed_api//sandboxed_api:__subpackages__",
+    "//sandboxed_api:__subpackages__",
 ])
 
 licenses(["notice"])
@@ -27,7 +27,7 @@ cc_library(
     srcs = ["path.cc"],
     hdrs = ["path.h"],
     copts = sapi_platform_copts(),
-    deps = ["@com_google_absl//absl/strings"],
+    deps = ["@abseil-cpp//absl/strings"],
 )
 
 cc_test(
@@ -37,8 +37,8 @@ cc_test(
     copts = sapi_platform_copts(),
     deps = [
         ":file_base",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -49,8 +49,8 @@ cc_library(
     hdrs = ["file_helpers.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -62,7 +62,7 @@ cc_test(
     deps = [
         ":file_helpers",
         ":status_matchers",
-        "@com_google_googletest//:gtest_main",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -72,9 +72,10 @@ cc_library(
     srcs = ["fileops.cc"],
     hdrs = ["fileops.h"],
     copts = sapi_platform_copts(),
+    visibility = ["//visibility:public"],
     deps = [
         ":strerror",
-        "@com_google_absl//absl/strings",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -87,9 +88,9 @@ cc_test(
         ":file_helpers",
         ":fileops",
         ":status_matchers",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
+        "//sandboxed_api:testing",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -107,8 +108,8 @@ cc_library(
     deps = [
         ":proto_arg_cc_proto",
         ":status",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
         "@com_google_protobuf//:protobuf_lite",
     ],
 )
@@ -122,11 +123,11 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":strerror",
-        "@com_google_absl//absl/base:config",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/base:log_severity",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
+        "@abseil-cpp//absl/base:config",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/base:log_severity",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
     ],
 )
 
@@ -138,10 +139,10 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":file_base",
+        ":raw_logging",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:str_format",
         "@bazel_tools//tools/cpp/runfiles",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:str_format",
-        "@com_google_sandboxed_api//sandboxed_api/util:raw_logging",
     ],
 )
 
@@ -162,10 +163,10 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":status_cc_proto",
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings",
-        "@com_google_absl//absl/strings:cord",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings",
+        "@abseil-cpp//absl/strings:cord",
     ],
 )
 
@@ -179,11 +180,11 @@ cc_library(
     visibility = ["//visibility:public"],
     deps = [
         ":status",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_absl//absl/types:optional",
-        "@com_google_googletest//:gtest",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings:string_view",
+        "@abseil-cpp//absl/types:optional",
+        "@googletest//:gtest",
     ],
 )
 
@@ -195,9 +196,9 @@ cc_test(
     deps = [
         ":status",
         ":status_cc_proto",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/strings:string_view",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/strings:string_view",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -209,10 +210,10 @@ cc_test(
     deps = [
         ":status",
         ":status_matchers",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -224,8 +225,8 @@ cc_library(
     hdrs = ["strerror.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/base:core_headers",
-        "@com_google_absl//absl/strings:str_format",
+        "@abseil-cpp//absl/base:core_headers",
+        "@abseil-cpp//absl/strings:str_format",
     ],
 )
 
@@ -236,8 +237,8 @@ cc_test(
     deps = [
         ":strerror",
         ":thread",
-        "@com_google_absl//absl/strings",
-        "@com_google_googletest//:gtest_main",
+        "@abseil-cpp//absl/strings",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -248,9 +249,9 @@ cc_library(
     copts = sapi_platform_copts(),
     deps = [
         ":status",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_absl//absl/strings",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@abseil-cpp//absl/strings",
     ],
 )
 
@@ -263,10 +264,10 @@ cc_test(
         ":fileops",
         ":status_matchers",
         ":temp_file",
-        "@com_google_absl//absl/status",
-        "@com_google_absl//absl/status:statusor",
-        "@com_google_googletest//:gtest_main",
-        "@com_google_sandboxed_api//sandboxed_api:testing",
+        "//sandboxed_api:testing",
+        "@abseil-cpp//absl/status",
+        "@abseil-cpp//absl/status:statusor",
+        "@googletest//:gtest_main",
     ],
 )
 
@@ -275,7 +276,7 @@ cc_library(
     hdrs = ["thread.h"],
     copts = sapi_platform_copts(),
     deps = [
-        "@com_google_absl//absl/functional:any_invocable",
-        "@com_google_absl//absl/strings:string_view",
+        "@abseil-cpp//absl/functional:any_invocable",
+        "@abseil-cpp//absl/strings:string_view",
     ],
 )
diff --git a/sandboxed_api/var_ptr.h b/sandboxed_api/var_ptr.h
index 774e48e..8ff69ac 100644
--- a/sandboxed_api/var_ptr.h
+++ b/sandboxed_api/var_ptr.h
@@ -22,7 +22,6 @@
 
 #include "absl/base/attributes.h"
 #include "absl/base/macros.h"
-#include "absl/log/log.h"
 #include "absl/strings/str_format.h"
 #include "sandboxed_api/var_abstract.h"
 #include "sandboxed_api/var_reg.h"
@@ -99,9 +98,7 @@ class RemotePtr : public Ptr {
     pointed_obj_.SetRemote(remote_addr);
   }
 
-  void SetRemote(void* /* remote */) override {
-    LOG(FATAL) << "SetRemote not supported on RemotePtr";
-  }
+  void SetRemote(void* remote_addr) { pointed_obj_.SetRemote(remote_addr); }
 
  private:
   Reg<void*> pointed_obj_;
```

