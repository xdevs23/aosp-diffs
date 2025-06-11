```diff
diff --git a/.bazelci/presubmit.yml b/.bazelci/presubmit.yml
index 8d7899d..5d8f4a4 100644
--- a/.bazelci/presubmit.yml
+++ b/.bazelci/presubmit.yml
@@ -1,53 +1,135 @@
 ---
-x_defaults:
-  # YAML has a feature for "repeated nodes", BazelCI is fine with extra nodes
-  # it doesn't know about; so that is used to avoid repeating common subparts.
-  common: &common
-    # We have to list every package because even with exclusion notation -//foo
-    # Bazel will load the excluded package and it will be an error because at
-    # release Bazel the cc_libraries do not have all the attributes.
-    build_targets:
-    - "//:all"
-    - "//cc:all"
-    - "//cc/private/rules_impl:all"
-    - "//cc/private/toolchain:all"
-    - "//cc/runfiles:all"
-    - "//examples:all"
-    - "//examples/my_c_archive:all"
-    - "//examples/my_c_compile:all"
-    - "//examples/write_cc_toolchain_cpu:all"
-    - "//tools/migration:all"
-    - "//tests/..."
-    test_flags:
-    - "--test_timeout=120"
-    test_targets:
-    - "//:all"
-    - "//cc:all"
-    - "//cc/private/rules_impl:all"
-    - "//cc/private/toolchain:all"
-    - "//examples:all"
-    - "//examples/my_c_archive:all"
-    - "//examples/my_c_compile:all"
-    - "//examples/write_cc_toolchain_cpu:all"
-    - "//tools/migration:all"
-    - "//tests/..."
+build_targets: &build_targets
+  - "//:all"
+  - "//cc/..."
+  - "//examples/..."
+  - "//tests/..."
+  - "-//examples/custom_toolchain:legacy_selector" # Example only works on Linux
+  - "-//tests/rule_based_toolchain/tool_map:_duplicate_action_test_subject" # Intentionally broken rule.
+test_targets: &test_targets
+  - "//:all"
+  - "//cc/..."
+  - "//examples/..."
+  - "//tests/..."
+  - "-//examples/custom_toolchain:legacy_selector" # Example only works on Linux
+  - "-//tests/rule_based_toolchain/tool_map:_duplicate_action_test_subject" # Intentionally broken rule.
+
+build_targets_bazel_6: &build_targets_bazel_6
+  - "//:all"
+  - "//cc:all"
+  - "//examples/..."
+  - "//tests/..."
+  - "-//examples/custom_toolchain:legacy_selector" # Example only works on Linux
+  - "-//tests/rule_based_toolchain/..." # proto.encode_text doesn't support None
+  - "-//cc:optional_current_cc_toolchain" # Not supported in Bazel 6
+  - "-//tests/rule_based_toolchain/tool_map:_duplicate_action_test_subject" # Intentionally broken rule.
+test_targets_bazel_6: &test_targets_bazel_6
+  - "//:all"
+  - "//cc:all"
+  - "//examples/..."
+  - "//tests/..."
+  - "-//examples/custom_toolchain:legacy_selector" # Example only works on Linux
+  - "-//tests/rule_based_toolchain/..." # proto.encode_text doesn't support None
+  - "-//cc:optional_current_cc_toolchain" # Not supported in Bazel 6
+  - "-//tests/rule_based_toolchain/tool_map:_duplicate_action_test_subject" # Intentionally broken rule.
 
 buildifier:
   version: latest
   warnings: "all"
 
 tasks:
-  ubuntu1804:
-    <<: *common
+  ubuntu2004:
+    name: Docs
+    test_targets:
+      - "//docs/..."
+      - "-//docs:toolchain_api_diff_test" # Bazel adds loads statements in examples
+
+# Bazel LTS
+  ubuntu2004:
+    name: Ubuntu 20.04 (Bazel LTS)
+    build_targets: *build_targets
+    test_targets: *test_targets
   macos:
-    <<: *common
+    name: MacOS (Bazel LTS)
+    build_targets: *build_targets
+    test_targets: *test_targets
   windows:
-    <<: *common
+    name: Windows (Bazel LTS)
+    build_targets: *build_targets
+    test_targets: *test_targets
   ubuntu_bzlmod:
-    name: Bzlmod
-    platform: ubuntu1804
+    name: Ubuntu 20.04 (Bazel LTS, bzlmod)
+    platform: ubuntu2004
     build_flags:
       - "--enable_bzlmod"
       - "--ignore_dev_dependency"
-    build_targets:
+
+# Bazel@HEAD
+  ubuntu2004_head:
+    name: Ubuntu 20.04 (Bazel HEAD)
+    bazel: last_green
+    platform: ubuntu2004
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets
+    test_targets:
+      - "//:all"
       - "//cc/..."
+      - "//examples/..."
+      - "//tests/..."
+      - "-//examples/custom_toolchain:legacy_selector" # Example only works on Linux
+      - "-//tests/system_library:system_library_test" # Fails because of repo setup
+      - "-//tests/rule_based_toolchain/tool_map:_duplicate_action_test_subject" # Intentionally broken rule.
+  macos_head:
+    name: MacOS (Bazel HEAD)
+    bazel: last_green
+    platform: macos
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets
+    test_targets: *test_targets
+  windows_head:
+    name: Windows (Bazel HEAD)
+    bazel: last_green
+    platform: macos
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets
+    test_targets: *test_targets
+
+# Bazel 6
+  ubuntu2004_bazel_6:
+    name: Ubuntu 20.04 (Bazel 6)
+    bazel: 6.3.0
+    platform: ubuntu2004
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets_bazel_6
+    test_targets: *test_targets_bazel_6
+  macos_bazel_6:
+    name: MacOS (Bazel 6)
+    bazel: 6.3.0
+    platform: macos
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets_bazel_6
+    test_targets: *test_targets_bazel_6
+  windows_bazel_6:
+    name: Windows (Bazel 6)
+    bazel: 6.3.0
+    platform: macos
+    environment:
+      EXP_USE_CQUERY: 1 # Don't build incompatible targets
+    build_targets: *build_targets_bazel_6
+    test_targets: *test_targets_bazel_6
+
+  ubuntu_rule_based_toolchains:
+    name: Ubuntu rule-based toolchains
+    platform: ubuntu1804
+    working_directory: examples/rule_based_toolchain
+    build_flags:
+      - "--enable_bzlmod"
+    build_targets:
+      - "//..."
+    test_targets:
+      - "//..."
diff --git a/.bazelignore b/.bazelignore
new file mode 100644
index 0000000..ff5e9ce
--- /dev/null
+++ b/.bazelignore
@@ -0,0 +1 @@
+examples/rule_based_toolchain
diff --git a/.bcr/metadata.template.json b/.bcr/metadata.template.json
index 9f0e465..8cf8ee2 100644
--- a/.bcr/metadata.template.json
+++ b/.bcr/metadata.template.json
@@ -1,6 +1,12 @@
 {
   "homepage": "https://github.com/bazelbuild/rules_cc",
-  "maintainers": [],
+  "maintainers": [
+    {
+      "email": "ilist@google.com",
+      "github": "comius",
+      "name": "Ivo Ristovski List"
+    }
+  ],
   "versions": [],
   "yanked_versions": {}
 }
diff --git a/.bcr/presubmit.yml b/.bcr/presubmit.yml
index 52869b1..902c89c 100644
--- a/.bcr/presubmit.yml
+++ b/.bcr/presubmit.yml
@@ -1,8 +1,12 @@
 matrix:
   platform: ["centos7", "debian10", "macos", "ubuntu2004", "windows"]
+  bazel:
+  - 6.x
+  - 7.x
 tasks:
   verify_targets:
     name: "Verify build targets"
     platform: ${{ platform }}
+    bazel: ${{ bazel }}
     build_targets:
       - "@rules_cc//cc/..."
diff --git a/.bcr/source.template.json b/.bcr/source.template.json
index 4f14819..53c3bbe 100644
--- a/.bcr/source.template.json
+++ b/.bcr/source.template.json
@@ -1,5 +1,5 @@
 {
   "integrity": "",
   "strip_prefix": "{REPO}-{VERSION}",
-  "url": "https://github.com/{OWNER}/{REPO}/archive/refs/tags/{TAG}.tar.gz"
+  "url": "https://github.com/{OWNER}/{REPO}/releases/download/{TAG}/rules_cc-{TAG}.tar.gz"
 }
diff --git a/.github/workflows/ci.bazelrc b/.github/workflows/ci.bazelrc
new file mode 100644
index 0000000..2a5a8a3
--- /dev/null
+++ b/.github/workflows/ci.bazelrc
@@ -0,0 +1,15 @@
+# This file contains Bazel settings to apply on CI only.
+# It is referenced with a --bazelrc option in the call to bazel in ci.yaml
+
+# Debug where options came from
+build --announce_rc
+# This directory is configured in GitHub actions to be persisted between runs.
+# We do not enable the repository cache to cache downloaded external artifacts
+# as these are generally faster to download again than to fetch them from the
+# GitHub actions cache.
+build --disk_cache=~/.cache/bazel
+# Don't rely on test logs being easily accessible from the test runner,
+# though it makes the log noisier.
+test --test_output=errors
+# Allows tests to run bazelisk-in-bazel, since this is the cache folder used
+test --test_env=XDG_CACHE_HOME
\ No newline at end of file
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..31edb4d
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,18 @@
+# Automatically perform a release whenever a new "release-like" tag is pushed to the repo.
+name: Release
+
+on:
+  push:
+    tags:
+      # Detect tags that look like a release.
+      # Note that we don't use a "v" prefix to help anchor this pattern.
+      # This is purely a matter of preference.
+      - "*.*.*"
+
+jobs:
+  release:
+    # Re-use https://github.com/bazel-contrib/.github/blob/v7/.github/workflows/release_ruleset.yaml
+    uses: bazel-contrib/.github/.github/workflows/release_ruleset.yaml@v7
+    with:
+      prerelease: false
+      release_files: rules_cc-*.tar.gz
\ No newline at end of file
diff --git a/.github/workflows/release_prep.sh b/.github/workflows/release_prep.sh
new file mode 100644
index 0000000..749e34f
--- /dev/null
+++ b/.github/workflows/release_prep.sh
@@ -0,0 +1,44 @@
+#!/usr/bin/env bash
+
+set -o errexit -o nounset -o pipefail
+
+# Set by GH actions, see
+# https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
+readonly TAG=${GITHUB_REF_NAME}
+# The prefix is chosen to match what GitHub generates for source archives.
+# This guarantees that users can easily switch from a released artifact to a source archive
+# with minimal differences in their code (e.g. strip_prefix remains the same)
+readonly PREFIX="rules_cc-${TAG}"
+readonly ARCHIVE="${PREFIX}.tar.gz"
+
+# NB: configuration for 'git archive' is in /.gitattributes
+git archive --format=tar --prefix=${PREFIX}/ ${TAG} | gzip > $ARCHIVE
+SHA=$(shasum -a 256 $ARCHIVE | awk '{print $1}')
+
+# The stdout of this program will be used as the top of the release notes for this release.
+cat << EOF
+## Using bzlmod with Bazel 6 or later:
+
+1. [Bazel 6] Add \`common --enable_bzlmod\` to \`.bazelrc\`.
+
+2. Add to your \`MODULE.bazel\` file:
+
+\`\`\`starlark
+bazel_dep(name = "rules_cc", version = "${TAG}")
+\`\`\`
+
+## Using WORKSPACE:
+
+\`\`\`starlark
+
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+
+http_archive(
+    name = "rules_cc",
+    sha256 = "${SHA}",
+    strip_prefix = "${PREFIX}",
+    url = "https://github.com/bazelbuild/rules_cc/releases/download/${TAG}/${ARCHIVE}",
+)
+
+\`\`\`
+EOF
\ No newline at end of file
diff --git a/.gitignore b/.gitignore
index 65e8edc..0d4fed2 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1 +1,2 @@
-/bazel-*
\ No newline at end of file
+bazel-*
+MODULE.bazel.lock
diff --git a/BUILD b/BUILD
index 1ed7987..fc7b2da 100644
--- a/BUILD
+++ b/BUILD
@@ -1,4 +1,4 @@
-load("//cc:defs.bzl", "cc_library")
+load("//cc:cc_library.bzl", "cc_library")
 
 package(default_visibility = ["//visibility:public"])
 
diff --git a/CODEOWNERS b/CODEOWNERS
index 85a388b..dd7518c 100644
--- a/CODEOWNERS
+++ b/CODEOWNERS
@@ -1 +1 @@
-* @oquenchil @c-mita @comius @buildbreaker2021
+* @trybka @matts1 @armandomontanez @pzembrod @comius @c-mita @hvadehra
diff --git a/METADATA b/METADATA
index 8d58189..30c498e 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/bazelbuild-rules_cc
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "bazelbuild-rules_cc"
 description: "A repository of Starlark implementation of C++ rules in Bazel"
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 5
-    day: 9
+    year: 2025
+    month: 1
+    day: 23
   }
   identifier {
     type: "Git"
     value: "https://github.com/bazelbuild/rules_cc"
-    version: "f88663dc502aacb6a6f377030d0652309412c8a9"
+    version: "0.0.16"
   }
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index ee4789b..5c3383c 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,15 +1,20 @@
 module(
     name = "rules_cc",
-    version = "0.0.4",
+    version = "0.0.0",
     compatibility_level = 1,
 )
 
-bazel_dep(name = "bazel_skylib", version = "1.3.0")
-bazel_dep(name = "platforms", version = "0.0.7")
+bazel_dep(name = "bazel_features", version = "1.19.0")
+bazel_dep(name = "bazel_skylib", version = "1.7.1")
+bazel_dep(name = "platforms", version = "0.0.10")
+# ANDROID: Drop protobuf dependency to avoid being fetched from the Internet
+# bazel_dep(name = "protobuf", version = "27.0", repo_name = "com_google_protobuf")
 
-cc_configure = use_extension("@bazel_tools//tools/cpp:cc_configure.bzl", "cc_configure_extension")
-use_repo(cc_configure, "local_config_cc_toolchains")
+cc_configure = use_extension("//cc:extensions.bzl", "cc_configure_extension")
+use_repo(cc_configure, "local_config_cc", "local_config_cc_toolchains")
 
 register_toolchains("@local_config_cc_toolchains//:all")
 
+bazel_dep(name = "rules_shell", version = "0.2.0", dev_dependency = True)
 bazel_dep(name = "rules_testing", version = "0.6.0", dev_dependency = True)
+bazel_dep(name = "stardoc", version = "0.7.0", dev_dependency = True)
diff --git a/OWNERS b/OWNERS
index 926ae1e..a18cfbe 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include kernel/build:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 16245ef..1b3fb27 100644
--- a/README.md
+++ b/README.md
@@ -42,8 +42,8 @@ This is non-hermetic, and may have varying behaviors depending on the versions o
 
 There are third-party contributed hermetic toolchains you may want to investigate:
 
-- LLVM: <https://github.com/grailbio/bazel-toolchain>
-- GCC (Linux only): <https://github.com/aspect-build/gcc-toolchain>
+- LLVM: <https://github.com/bazel-contrib/toolchains_llvm>
+- GCC (Linux only): <https://github.com/f0rmiga/gcc-toolchain>
 - zig cc: <https://github.com/uber/hermetic_cc_toolchain>
 
 If you'd like to use the cc toolchain defined in this repo, add this to
diff --git a/WORKSPACE b/WORKSPACE
index 875888e..ce5112f 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -4,74 +4,19 @@ load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 
 http_archive(
     name = "bazel_skylib",
-    sha256 = "b8a1527901774180afc798aeb28c4634bdccf19c4d98e7bdd1ce79d1fe9aaad7",
+    sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
-        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.1/bazel-skylib-1.4.1.tar.gz",
-    ],
-)
-
-http_archive(
-    name = "com_google_googletest",
-    sha256 = "81964fe578e9bd7c94dfdb09c8e4d6e6759e19967e397dbea48d1c10e45d0df2",
-    strip_prefix = "googletest-release-1.12.1",
-    urls = [
-        "https://mirror.bazel.build/github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
-        "https://github.com/google/googletest/archive/refs/tags/release-1.12.1.tar.gz",
-    ],
-)
-
-http_archive(
-    name = "io_abseil_py",
-    sha256 = "0fb3a4916a157eb48124ef309231cecdfdd96ff54adf1660b39c0d4a9790a2c0",
-    strip_prefix = "abseil-py-1.4.0",
-    urls = [
-        "https://github.com/abseil/abseil-py/archive/refs/tags/v1.4.0.tar.gz",
-    ],
-)
-
-http_archive(
-    name = "io_bazel_rules_go",
-    sha256 = "91585017debb61982f7054c9688857a2ad1fd823fc3f9cb05048b0025c47d023",
-    urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
-        "https://github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
+        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
+        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
     ],
 )
 
 http_archive(
     name = "platforms",
-    sha256 = "3a561c99e7bdbe9173aa653fd579fe849f1d8d67395780ab4770b1f381431d51",
+    sha256 = "218efe8ee736d26a3572663b374a253c012b716d8af0c07e842e82f238a0a7ee",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.7/platforms-0.0.7.tar.gz",
-        "https://github.com/bazelbuild/platforms/releases/download/0.0.7/platforms-0.0.7.tar.gz",
-    ],
-)
-
-http_archive(
-    name = "py_mock",
-    patch_cmds = [
-        "mkdir -p py/mock",
-        "mv mock.py py/mock/__init__.py",
-        """echo 'licenses(["notice"])' > BUILD""",
-        "touch py/BUILD",
-        """echo 'py_library(name = "mock", srcs = ["__init__.py"], visibility = ["//visibility:public"],)' > py/mock/BUILD""",
-    ],
-    sha256 = "b839dd2d9c117c701430c149956918a423a9863b48b09c90e30a6013e7d2f44f",
-    strip_prefix = "mock-1.0.1",
-    urls = [
-        "https://mirror.bazel.build/pypi.python.org/packages/source/m/mock/mock-1.0.1.tar.gz",
-        "https://pypi.python.org/packages/source/m/mock/mock-1.0.1.tar.gz",
-    ],
-)
-
-http_archive(
-    name = "rules_proto",
-    sha256 = "9a0503631679e9ab4e27d891ea60fee3e86a85654ea2048cae25516171dd260e",
-    strip_prefix = "rules_proto-e51f588e5932966ab9e63e0b0f6de6f740cf04c4",
-    urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/e51f588e5932966ab9e63e0b0f6de6f740cf04c4.tar.gz",
-        "https://github.com/bazelbuild/rules_proto/archive/e51f588e5932966ab9e63e0b0f6de6f740cf04c4.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
+        "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
     ],
 )
 
@@ -79,17 +24,18 @@ load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
 
 bazel_skylib_workspace()
 
-load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
-
-go_rules_dependencies()
-
-go_register_toolchains(version = "1.20.5")
+http_archive(
+    name = "rules_shell",
+    sha256 = "410e8ff32e018b9efd2743507e7595c26e2628567c42224411ff533b57d27c28",
+    strip_prefix = "rules_shell-0.2.0",
+    url = "https://github.com/bazelbuild/rules_shell/releases/download/v0.2.0/rules_shell-v0.2.0.tar.gz",
+)
 
-load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
+load("@rules_shell//shell:repositories.bzl", "rules_shell_dependencies", "rules_shell_toolchains")
 
-rules_proto_dependencies()
+rules_shell_dependencies()
 
-rules_proto_toolchains()
+rules_shell_toolchains()
 
 http_archive(
     name = "rules_testing",
@@ -97,3 +43,10 @@ http_archive(
     strip_prefix = "rules_testing-0.6.0",
     url = "https://github.com/bazelbuild/rules_testing/releases/download/v0.6.0/rules_testing-v0.6.0.tar.gz",
 )
+
+http_archive(
+    name = "com_google_protobuf",
+    sha256 = "da288bf1daa6c04d03a9051781caa52aceb9163586bff9aa6cfb12f69b9395aa",
+    strip_prefix = "protobuf-27.0",
+    url = "https://github.com/protocolbuffers/protobuf/releases/download/v27.0/protobuf-27.0.tar.gz",
+)
diff --git a/WORKSPACE.bzlmod b/WORKSPACE.bzlmod
new file mode 100644
index 0000000..0947211
--- /dev/null
+++ b/WORKSPACE.bzlmod
@@ -0,0 +1,2 @@
+# A completely empty WORKSPACE file to replace the original WORKSPACE content when enabling Bzlmod.
+# No WORKSPACE prefix or suffix are added for this file.
\ No newline at end of file
diff --git a/cc/BUILD b/cc/BUILD
index aeb5beb..020abb8 100644
--- a/cc/BUILD
+++ b/cc/BUILD
@@ -12,6 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
 package(default_visibility = ["//visibility:public"])
 
 licenses(["notice"])  # Apache 2.0
@@ -80,6 +82,30 @@ filegroup(
     ],
 )
 
+bzl_library(
+    name = "find_cc_toolchain_bzl",
+    srcs = ["find_cc_toolchain.bzl"],
+    visibility = ["//visibility:public"],
+)
+
+bzl_library(
+    name = "action_names_bzl",
+    srcs = ["action_names.bzl"],
+    visibility = ["//visibility:public"],
+)
+
+bzl_library(
+    name = "cc_toolchain_config_lib_bzl",
+    srcs = ["cc_toolchain_config_lib.bzl"],
+    visibility = ["//cc/toolchains:__subpackages__"],
+)
+
 cc_toolchain_alias(name = "current_cc_toolchain")
 
+# Use alias, because it doesn't build on Bazel 6.
+alias(
+    name = "optional_current_cc_toolchain",
+    actual = "//cc/private/bazel7:optional_current_cc_toolchain",
+)
+
 cc_libc_top_alias(name = "current_libc_top")
diff --git a/cc/action_names.bzl b/cc/action_names.bzl
index 3df7cfa..31a5967 100644
--- a/cc/action_names.bzl
+++ b/cc/action_names.bzl
@@ -33,6 +33,13 @@ CPP_MODULE_CODEGEN_ACTION_NAME = "c++-module-codegen"
 # Name of the C++ header parsing action.
 CPP_HEADER_PARSING_ACTION_NAME = "c++-header-parsing"
 
+# Name of the C++ deps scanning action.
+CPP_MODULE_DEPS_SCANNING_ACTION_NAME = "c++-module-deps-scanning"
+
+# Name of the C++ module compile action.
+CPP20_MODULE_COMPILE_ACTION_NAME = "c++20-module-compile"
+CPP20_MODULE_CODEGEN_ACTION_NAME = "c++20-module-codegen"
+
 # Name of the C++ module compile action.
 CPP_MODULE_COMPILE_ACTION_NAME = "c++-module-compile"
 
@@ -42,6 +49,8 @@ ASSEMBLE_ACTION_NAME = "assemble"
 # Name of the assembly preprocessing action.
 PREPROCESS_ASSEMBLE_ACTION_NAME = "preprocess-assemble"
 
+LLVM_COV = "llvm-cov"
+
 # Name of the action producing ThinLto index.
 LTO_INDEXING_ACTION_NAME = "lto-indexing"
 
@@ -85,9 +94,15 @@ OBJC_EXECUTABLE_ACTION_NAME = "objc-executable"
 # A string constant for the objc fully-link link action.
 OBJC_FULLY_LINK_ACTION_NAME = "objc-fully-link"
 
-# A string constant for the clif action.
+# A string constant for the clif actions.
 CLIF_MATCH_ACTION_NAME = "clif-match"
 
+# A string constant for the obj copy actions.
+OBJ_COPY_ACTION_NAME = "objcopy_embed_data"
+
+# A string constant for the validation action for cc_static_library.
+VALIDATE_STATIC_LIBRARY = "validate-static-library"
+
 ACTION_NAMES = struct(
     c_compile = C_COMPILE_ACTION_NAME,
     cpp_compile = CPP_COMPILE_ACTION_NAME,
@@ -95,9 +110,13 @@ ACTION_NAMES = struct(
     cc_flags_make_variable = CC_FLAGS_MAKE_VARIABLE_ACTION_NAME,
     cpp_module_codegen = CPP_MODULE_CODEGEN_ACTION_NAME,
     cpp_header_parsing = CPP_HEADER_PARSING_ACTION_NAME,
+    cpp_module_deps_scanning = CPP_MODULE_DEPS_SCANNING_ACTION_NAME,
+    cpp20_module_compile = CPP20_MODULE_COMPILE_ACTION_NAME,
+    cpp20_module_codegen = CPP20_MODULE_CODEGEN_ACTION_NAME,
     cpp_module_compile = CPP_MODULE_COMPILE_ACTION_NAME,
     assemble = ASSEMBLE_ACTION_NAME,
     preprocess_assemble = PREPROCESS_ASSEMBLE_ACTION_NAME,
+    llvm_cov = LLVM_COV,
     lto_indexing = LTO_INDEXING_ACTION_NAME,
     lto_backend = LTO_BACKEND_ACTION_NAME,
     lto_index_for_executable = LTO_INDEX_FOR_EXECUTABLE_ACTION_NAME,
@@ -113,6 +132,8 @@ ACTION_NAMES = struct(
     objc_fully_link = OBJC_FULLY_LINK_ACTION_NAME,
     objcpp_compile = OBJCPP_COMPILE_ACTION_NAME,
     clif_match = CLIF_MATCH_ACTION_NAME,
+    objcopy_embed_data = OBJ_COPY_ACTION_NAME,
+    validate_static_library = VALIDATE_STATIC_LIBRARY,
 )
 
 # Names of actions that parse or compile C++ code.
diff --git a/cc/cc_binary.bzl b/cc/cc_binary.bzl
new file mode 100644
index 0000000..f36e431
--- /dev/null
+++ b/cc/cc_binary.bzl
@@ -0,0 +1,43 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""cc_binary rule"""
+
+# TODO(bazel-team): To avoid breaking changes, if the below are no longer
+# forwarding to native rules, flag @bazel_tools@bazel_tools//tools/cpp:link_extra_libs
+# should either: (a) alias the flag @rules_cc//:link_extra_libs, or (b) be
+# added as a dependency to @rules_cc//:link_extra_lib. The intermediate library
+# @bazel_tools@bazel_tools//tools/cpp:link_extra_lib should either be added as a dependency
+# to @rules_cc//:link_extra_lib, or removed entirely (if possible).
+_LINK_EXTRA_LIB = Label("//:link_extra_lib")
+
+def cc_binary(**attrs):
+    """Bazel cc_binary rule.
+
+    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_binary
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    is_library = "linkshared" in attrs and attrs["linkshared"]
+
+    # Executable builds also include the "link_extra_lib" library.
+    if not is_library:
+        if "deps" in attrs and attrs["deps"] != None:
+            attrs["deps"] = attrs["deps"] + [_LINK_EXTRA_LIB]
+        else:
+            attrs["deps"] = [_LINK_EXTRA_LIB]
+
+    # buildifier: disable=native-cc
+    native.cc_binary(**attrs)
diff --git a/cc/cc_import.bzl b/cc/cc_import.bzl
new file mode 100644
index 0000000..130805c
--- /dev/null
+++ b/cc/cc_import.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""cc_import rule"""
+
+def cc_import(**kwargs):
+    native.cc_import(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/cc_library.bzl b/cc/cc_library.bzl
new file mode 100644
index 0000000..9ce181f
--- /dev/null
+++ b/cc/cc_library.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""cc_library rule"""
+
+def cc_library(**kwargs):
+    native.cc_library(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/cc_shared_library.bzl b/cc/cc_shared_library.bzl
new file mode 100644
index 0000000..fb6be5a
--- /dev/null
+++ b/cc/cc_shared_library.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""cc_library rule"""
+
+def cc_shared_library(**kwargs):
+    native.cc_shared_library(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/cc_test.bzl b/cc/cc_test.bzl
new file mode 100644
index 0000000..387fd18
--- /dev/null
+++ b/cc/cc_test.bzl
@@ -0,0 +1,44 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""cc_test rule"""
+
+# TODO(bazel-team): To avoid breaking changes, if the below are no longer
+# forwarding to native rules, flag @bazel_tools@bazel_tools//tools/cpp:link_extra_libs
+# should either: (a) alias the flag @rules_cc//:link_extra_libs, or (b) be
+# added as a dependency to @rules_cc//:link_extra_lib. The intermediate library
+# @bazel_tools@bazel_tools//tools/cpp:link_extra_lib should either be added as a dependency
+# to @rules_cc//:link_extra_lib, or removed entirely (if possible).
+_LINK_EXTRA_LIB = Label("//:link_extra_lib")
+
+def cc_test(**attrs):
+    """Bazel cc_test rule.
+
+    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_test
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    is_library = "linkshared" in attrs and attrs["linkshared"]
+
+    # Executable builds also include the "link_extra_lib" library.
+    if not is_library:
+        if "deps" in attrs and attrs["deps"] != None:
+            attrs["deps"] = attrs["deps"] + [_LINK_EXTRA_LIB]
+        else:
+            attrs["deps"] = [_LINK_EXTRA_LIB]
+
+    # buildifier: disable=native-cc
+    native.cc_test(**attrs)
diff --git a/cc/common/BUILD b/cc/common/BUILD
new file mode 100644
index 0000000..fdb3921
--- /dev/null
+++ b/cc/common/BUILD
@@ -0,0 +1,55 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+bzl_library(
+    name = "common",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//visibility:public"],
+    deps = ["//cc/private/rules_impl:native_bzl"],
+)
+
+bzl_library(
+    name = "cc_helper_bzl",
+    srcs = ["cc_helper.bzl"],
+    visibility = ["//visibility:public"],
+    deps = [":visibility_bzl"],
+)
+
+bzl_library(
+    name = "cc_debug_helper_bzl",
+    srcs = ["cc_debug_helper.bzl"],
+    visibility = ["//visibility:public"],
+    deps = [
+        ":cc_helper_bzl",
+        ":visibility_bzl",
+        "//cc:find_cc_toolchain_bzl",
+    ],
+)
+
+bzl_library(
+    name = "visibility_bzl",
+    srcs = ["visibility.bzl"],
+    visibility = ["//visibility:private"],
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob([
+        "**/*.bzl",
+        "**/BUILD",
+    ]),
+    visibility = ["//visibility:public"],
+)
diff --git a/cc/common/cc_common.bzl b/cc/common/cc_common.bzl
new file mode 100644
index 0000000..e2eb502
--- /dev/null
+++ b/cc/common/cc_common.bzl
@@ -0,0 +1,19 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""cc_common module"""
+
+load("//cc/private/rules_impl:native.bzl", "native_cc_common")
+
+cc_common = native_cc_common
diff --git a/cc/common/cc_debug_helper.bzl b/cc/common/cc_debug_helper.bzl
new file mode 100644
index 0000000..d16e925
--- /dev/null
+++ b/cc/common/cc_debug_helper.bzl
@@ -0,0 +1,181 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Utilities for creating cc debug package information outputs"""
+
+load("//cc:find_cc_toolchain.bzl", "CC_TOOLCHAIN_TYPE")
+load(":cc_helper.bzl", "linker_mode")
+load(":visibility.bzl", "INTERNAL_VISIBILITY")
+
+visibility(INTERNAL_VISIBILITY)
+
+def create_debug_packager_actions(
+        ctx,
+        cc_toolchain,
+        dwp_output,
+        *,
+        cc_compilation_outputs,
+        cc_debug_context,
+        linking_mode,
+        use_pic = True,
+        lto_artifacts = []):
+    """Creates intermediate and final dwp creation action(s)
+
+    Args:
+        ctx: (RuleContext) the rule context
+        cc_toolchain: (CcToolchainInfo) the cc toolchain
+        dwp_output: (File) the output of the final dwp action
+        cc_compilation_outputs: (CcCompilationOutputs)
+        cc_debug_context: (DebugContext)
+        linking_mode: (str) See cc_helper.bzl%linker_mode
+        use_pic: (bool)
+        lto_artifacts: ([CcLtoBackendArtifacts])
+    """
+    dwo_files = _collect_transitive_dwo_artifacts(
+        cc_compilation_outputs,
+        cc_debug_context,
+        linking_mode,
+        use_pic,
+        lto_artifacts,
+    )
+
+    # No inputs? Just generate a trivially empty .dwp.
+    #
+    # Note this condition automatically triggers for any build where fission is disabled.
+    # Because rules referencing .dwp targets may be invoked with or without fission, we need
+    # to support .dwp generation even when fission is disabled. Since no actual functionality
+    # is expected then, an empty file is appropriate.
+    dwo_files_list = dwo_files.to_list()
+    if len(dwo_files_list) == 0:
+        ctx.actions.write(dwp_output, "", False)
+        return
+
+    # We apply a hierarchical action structure to limit the maximum number of inputs to any
+    # single action.
+    #
+    # While the dwp tool consumes .dwo files, it can also consume intermediate .dwp files,
+    # allowing us to split a large input set into smaller batches of arbitrary size and order.
+    # Aside from the parallelism performance benefits this offers, this also reduces input
+    # size requirements: if a.dwo, b.dwo, c.dwo, and e.dwo are each 1 KB files, we can apply
+    # two intermediate actions DWP(a.dwo, b.dwo) --> i1.dwp and DWP(c.dwo, e.dwo) --> i2.dwp.
+    # When we then apply the final action DWP(i1.dwp, i2.dwp) --> finalOutput.dwp, the inputs
+    # to this action will usually total far less than 4 KB.
+    #
+    # The actions form an n-ary tree with n == MAX_INPUTS_PER_DWP_ACTION. The tree is fuller
+    # at the leaves than the root, but that both increases parallelism and reduces the final
+    # action's input size.
+    packager = _create_intermediate_dwp_packagers(ctx, dwp_output, cc_toolchain, cc_toolchain._dwp_files, dwo_files_list, 1)
+    packager["outputs"].append(dwp_output)
+    packager["arguments"].add("-o", dwp_output)
+    ctx.actions.run(
+        mnemonic = "CcGenerateDwp",
+        tools = packager["tools"],
+        executable = packager["executable"],
+        toolchain = CC_TOOLCHAIN_TYPE,
+        arguments = [packager["arguments"]],
+        inputs = packager["inputs"],
+        outputs = packager["outputs"],
+    )
+
+def _collect_transitive_dwo_artifacts(cc_compilation_outputs, cc_debug_context, linking_mode, use_pic, lto_backend_artifacts):
+    dwo_files = []
+    transitive_dwo_files = depset()
+    if use_pic:
+        dwo_files.extend(cc_compilation_outputs.pic_dwo_files())
+    else:
+        dwo_files.extend(cc_compilation_outputs.dwo_files())
+
+    if lto_backend_artifacts != None:
+        for lto_backend_artifact in lto_backend_artifacts:
+            if lto_backend_artifact.dwo_file() != None:
+                dwo_files.append(lto_backend_artifact.dwo_file())
+
+    if linking_mode != linker_mode.LINKING_DYNAMIC:
+        if use_pic:
+            transitive_dwo_files = cc_debug_context.pic_files
+        else:
+            transitive_dwo_files = cc_debug_context.files
+    return depset(dwo_files, transitive = [transitive_dwo_files])
+
+def _get_intermediate_dwp_file(ctx, dwp_output, order_number):
+    output_path = dwp_output.short_path
+
+    # Since it is a dwp_output we can assume that it always
+    # ends with .dwp suffix, because it is declared so in outputs
+    # attribute.
+    extension_stripped_output_path = output_path[0:len(output_path) - 4]
+    intermediate_path = extension_stripped_output_path + "-" + str(order_number) + ".dwp"
+
+    return ctx.actions.declare_file("_dwps/" + intermediate_path)
+
+def _create_intermediate_dwp_packagers(ctx, dwp_output, cc_toolchain, dwp_files, dwo_files, intermediate_dwp_count):
+    intermediate_outputs = dwo_files
+
+    # This long loop is a substitution for recursion, which is not currently supported in Starlark.
+    for _ in range(2147483647):
+        packagers = []
+        current_packager = _new_dwp_action(ctx, cc_toolchain, dwp_files)
+        inputs_for_current_packager = 0
+
+        # Step 1: generate our batches. We currently break into arbitrary batches of fixed maximum
+        # input counts, but we can always apply more intelligent heuristics if the need arises.
+        for dwo_file in intermediate_outputs:
+            if inputs_for_current_packager == 100:
+                packagers.append(current_packager)
+                current_packager = _new_dwp_action(ctx, cc_toolchain, dwp_files)
+                inputs_for_current_packager = 0
+            current_packager["inputs"].append(dwo_file)
+
+            # add_all expands all directories to their contained files, see
+            # https://bazel.build/rules/lib/builtins/Args#add_all. add doesn't
+            # do that, so using add_all on the one-item list here allows us to
+            # find dwo files in directories.
+            current_packager["arguments"].add_all([dwo_file])
+            inputs_for_current_packager += 1
+
+        packagers.append(current_packager)
+
+        # Step 2: given the batches, create the actions.
+        if len(packagers) > 1:
+            # If we have multiple batches, make them all intermediate actions, then pipe their outputs
+            # into an additional level.
+            intermediate_outputs = []
+            for packager in packagers:
+                intermediate_output = _get_intermediate_dwp_file(ctx, dwp_output, intermediate_dwp_count)
+                intermediate_dwp_count += 1
+                packager["outputs"].append(intermediate_output)
+                packager["arguments"].add("-o", intermediate_output)
+                ctx.actions.run(
+                    mnemonic = "CcGenerateIntermediateDwp",
+                    tools = packager["tools"],
+                    executable = packager["executable"],
+                    toolchain = CC_TOOLCHAIN_TYPE,
+                    arguments = [packager["arguments"]],
+                    inputs = packager["inputs"],
+                    outputs = packager["outputs"],
+                )
+                intermediate_outputs.append(intermediate_output)
+        else:
+            return packagers[0]
+
+    # This is to fix buildifier errors, even though we should never reach this part of the code.
+    return None
+
+def _new_dwp_action(ctx, cc_toolchain, dwp_tools):
+    return {
+        "arguments": ctx.actions.args(),
+        "executable": cc_toolchain._tool_paths.get("dwp", None),
+        "inputs": [],
+        "outputs": [],
+        "tools": dwp_tools,
+    }
diff --git a/cc/common/cc_helper.bzl b/cc/common/cc_helper.bzl
new file mode 100644
index 0000000..35f6812
--- /dev/null
+++ b/cc/common/cc_helper.bzl
@@ -0,0 +1,295 @@
+# Copyright 2020 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Utility functions for C++ rules."""
+
+load("//cc:find_cc_toolchain.bzl", "CC_TOOLCHAIN_TYPE")
+load(":cc_common.bzl", "cc_common")
+load(":visibility.bzl", "INTERNAL_VISIBILITY")
+
+visibility(INTERNAL_VISIBILITY)
+
+# LINT.IfChange(linker_mode)
+linker_mode = struct(
+    LINKING_DYNAMIC = "dynamic_linking_mode",
+    LINKING_STATIC = "static_linking_mode",
+)
+# LINT.ThenChange(https://github.com/bazelbuild/bazel/blob/master/src/main/starlark/builtins_bzl/common/cc/cc_helper.bzl:linker_mode)
+
+# LINT.IfChange(forked_exports)
+def _get_static_mode_params_for_dynamic_library_libraries(libs):
+    linker_inputs = []
+    for lib in libs.to_list():
+        if lib.pic_static_library:
+            linker_inputs.append(lib.pic_static_library)
+        elif lib.static_library:
+            linker_inputs.append(lib.static_library)
+        elif lib.interface_library:
+            linker_inputs.append(lib.interface_library)
+        else:
+            linker_inputs.append(lib.dynamic_library)
+    return linker_inputs
+
+def _create_strip_action(ctx, cc_toolchain, cpp_config, input, output, feature_configuration):
+    if cc_common.is_enabled(feature_configuration = feature_configuration, feature_name = "no_stripping"):
+        ctx.actions.symlink(
+            output = output,
+            target_file = input,
+            progress_message = "Symlinking original binary as stripped binary",
+        )
+        return
+
+    if not cc_common.action_is_enabled(feature_configuration = feature_configuration, action_name = "strip"):
+        fail("Expected action_config for 'strip' to be configured.")
+
+    variables = cc_common.create_compile_variables(
+        cc_toolchain = cc_toolchain,
+        feature_configuration = feature_configuration,
+        output_file = output.path,
+        input_file = input.path,
+        strip_opts = cpp_config.strip_opts(),
+    )
+    command_line = cc_common.get_memory_inefficient_command_line(
+        feature_configuration = feature_configuration,
+        action_name = "strip",
+        variables = variables,
+    )
+    env = cc_common.get_environment_variables(
+        feature_configuration = feature_configuration,
+        action_name = "strip",
+        variables = variables,
+    )
+    execution_info = {}
+    for execution_requirement in cc_common.get_tool_requirement_for_action(feature_configuration = feature_configuration, action_name = "strip"):
+        execution_info[execution_requirement] = ""
+    ctx.actions.run(
+        inputs = depset(
+            direct = [input],
+            transitive = [cc_toolchain._strip_files],
+        ),
+        outputs = [output],
+        use_default_shell_env = True,
+        env = env,
+        executable = cc_common.get_tool_for_action(feature_configuration = feature_configuration, action_name = "strip"),
+        toolchain = CC_TOOLCHAIN_TYPE,
+        execution_requirements = execution_info,
+        progress_message = "Stripping {} for {}".format(output.short_path, ctx.label),
+        mnemonic = "CcStrip",
+        arguments = command_line,
+    )
+
+def _lookup_var(ctx, additional_vars, var):
+    expanded_make_var_ctx = ctx.var.get(var)
+    expanded_make_var_additional = additional_vars.get(var)
+    if expanded_make_var_additional != None:
+        return expanded_make_var_additional
+    if expanded_make_var_ctx != None:
+        return expanded_make_var_ctx
+    fail("{}: {} not defined".format(ctx.label, "$(" + var + ")"))
+
+def _expand_nested_variable(ctx, additional_vars, exp, execpath = True, targets = []):
+    # If make variable is predefined path variable(like $(location ...))
+    # we will expand it first.
+    if exp.find(" ") != -1:
+        if not execpath:
+            if exp.startswith("location"):
+                exp = exp.replace("location", "rootpath", 1)
+        data_targets = []
+        if ctx.attr.data != None:
+            data_targets = ctx.attr.data
+
+        # Make sure we do not duplicate targets.
+        unified_targets_set = {}
+        for data_target in data_targets:
+            unified_targets_set[data_target] = True
+        for target in targets:
+            unified_targets_set[target] = True
+        return ctx.expand_location("$({})".format(exp), targets = unified_targets_set.keys())
+
+    # Recursively expand nested make variables, but since there is no recursion
+    # in Starlark we will do it via for loop.
+    unbounded_recursion = True
+
+    # The only way to check if the unbounded recursion is happening or not
+    # is to have a look at the depth of the recursion.
+    # 10 seems to be a reasonable number, since it is highly unexpected
+    # to have nested make variables which are expanding more than 10 times.
+    for _ in range(10):
+        exp = _lookup_var(ctx, additional_vars, exp)
+        if len(exp) >= 3 and exp[0] == "$" and exp[1] == "(" and exp[len(exp) - 1] == ")":
+            # Try to expand once more.
+            exp = exp[2:len(exp) - 1]
+            continue
+        unbounded_recursion = False
+        break
+
+    if unbounded_recursion:
+        fail("potentially unbounded recursion during expansion of {}".format(exp))
+    return exp
+
+def _expand(ctx, expression, additional_make_variable_substitutions, execpath = True, targets = []):
+    idx = 0
+    last_make_var_end = 0
+    result = []
+    n = len(expression)
+    for _ in range(n):
+        if idx >= n:
+            break
+        if expression[idx] != "$":
+            idx += 1
+            continue
+
+        idx += 1
+
+        # We've met $$ pattern, so $ is escaped.
+        if idx < n and expression[idx] == "$":
+            idx += 1
+            result.append(expression[last_make_var_end:idx - 1])
+            last_make_var_end = idx
+            # We might have found a potential start for Make Variable.
+
+        elif idx < n and expression[idx] == "(":
+            # Try to find the closing parentheses.
+            make_var_start = idx
+            make_var_end = make_var_start
+            for j in range(idx + 1, n):
+                if expression[j] == ")":
+                    make_var_end = j
+                    break
+
+            # Note we cannot go out of string's bounds here,
+            # because of this check.
+            # If start of the variable is different from the end,
+            # we found a make variable.
+            if make_var_start != make_var_end:
+                # Some clarifications:
+                # *****$(MAKE_VAR_1)*******$(MAKE_VAR_2)*****
+                #                   ^       ^          ^
+                #                   |       |          |
+                #   last_make_var_end  make_var_start make_var_end
+                result.append(expression[last_make_var_end:make_var_start - 1])
+                make_var = expression[make_var_start + 1:make_var_end]
+                exp = _expand_nested_variable(ctx, additional_make_variable_substitutions, make_var, execpath, targets)
+                result.append(exp)
+
+                # Update indexes.
+                idx = make_var_end + 1
+                last_make_var_end = idx
+
+    # Add the last substring which would be skipped by for loop.
+    if last_make_var_end < n:
+        result.append(expression[last_make_var_end:n])
+
+    return "".join(result)
+
+def _get_expanded_env(ctx, additional_make_variable_substitutions):
+    if not hasattr(ctx.attr, "env"):
+        fail("could not find rule attribute named: 'env'")
+    expanded_env = {}
+    for k in ctx.attr.env:
+        expanded_env[k] = _expand(
+            ctx,
+            ctx.attr.env[k],
+            additional_make_variable_substitutions,
+            # By default, Starlark `ctx.expand_location` has `execpath` semantics.
+            # For legacy attributes, e.g. `env`, we want `rootpath` semantics instead.
+            execpath = False,
+        )
+    return expanded_env
+
+# Implementation of Bourne shell tokenization.
+# Tokenizes str and appends result to the options list.
+def _tokenize(options, options_string):
+    token = []
+    force_token = False
+    quotation = "\0"
+    length = len(options_string)
+
+    # Since it is impossible to modify loop variable inside loop
+    # in Starlark, and also there is no while loop, I have to
+    # use this ugly hack.
+    i = -1
+    for _ in range(length):
+        i += 1
+        if i >= length:
+            break
+        c = options_string[i]
+        if quotation != "\0":
+            # In quotation.
+            if c == quotation:
+                # End quotation.
+                quotation = "\0"
+            elif c == "\\" and quotation == "\"":
+                i += 1
+                if i == length:
+                    fail("backslash at the end of the string: {}".format(options_string))
+                c = options_string[i]
+                if c != "\\" and c != "\"":
+                    token.append("\\")
+                token.append(c)
+            else:
+                # Regular char, in quotation.
+                token.append(c)
+        else:
+            # Not in quotation.
+            if c == "'" or c == "\"":
+                # Begin single double quotation.
+                quotation = c
+                force_token = True
+            elif c == " " or c == "\t":
+                # Space not quoted.
+                if force_token or len(token) > 0:
+                    options.append("".join(token))
+                    token = []
+                    force_token = False
+            elif c == "\\":
+                # Backslash not quoted.
+                i += 1
+                if i == length:
+                    fail("backslash at the end of the string: {}".format(options_string))
+                token.append(options_string[i])
+            else:
+                # Regular char, not quoted.
+                token.append(c)
+    if quotation != "\0":
+        fail("unterminated quotation at the end of the string: {}".format(options_string))
+
+    if force_token or len(token) > 0:
+        options.append("".join(token))
+
+def _should_use_pic(ctx, cc_toolchain, feature_configuration):
+    """Whether to use pic files
+
+    Args:
+        ctx: (RuleContext)
+        cc_toolchain: (CcToolchainInfo)
+        feature_configuration: (FeatureConfiguration)
+
+    Returns:
+        (bool)
+    """
+    return ctx.fragments.cpp.force_pic() or (
+        cc_toolchain.needs_pic_for_dynamic_libraries(feature_configuration = feature_configuration) and (
+            ctx.var["COMPILATION_MODE"] != "opt" or
+            cc_common.is_enabled(feature_configuration = feature_configuration, feature_name = "prefer_pic_for_opt_binaries")
+        )
+    )
+
+cc_helper = struct(
+    create_strip_action = _create_strip_action,
+    get_expanded_env = _get_expanded_env,
+    get_static_mode_params_for_dynamic_library_libraries = _get_static_mode_params_for_dynamic_library_libraries,
+    should_use_pic = _should_use_pic,
+    tokenize = _tokenize,
+)
+# LINT.ThenChange(https://github.com/bazelbuild/bazel/blob/master/src/main/starlark/builtins_bzl/common/cc/cc_helper.bzl:forked_exports)
diff --git a/cc/common/cc_info.bzl b/cc/common/cc_info.bzl
new file mode 100644
index 0000000..91f4517
--- /dev/null
+++ b/cc/common/cc_info.bzl
@@ -0,0 +1,19 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""CcInfo"""
+
+load("//cc/private/rules_impl:native.bzl", "NativeCcInfo")
+
+CcInfo = NativeCcInfo
diff --git a/cc/common/cc_shared_library_hint_info.bzl b/cc/common/cc_shared_library_hint_info.bzl
new file mode 100644
index 0000000..133990b
--- /dev/null
+++ b/cc/common/cc_shared_library_hint_info.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""CcSharedLibraryInfo"""
+
+# Backward compatibility with Bazel 6
+CcSharedLibraryHintInfo = getattr(cc_common, "CcSharedLibraryHintInfo", provider("CcSharedLibraryHintInfo", fields = ["attributes", "owners"]))
diff --git a/cc/common/cc_shared_library_info.bzl b/cc/common/cc_shared_library_info.bzl
new file mode 100644
index 0000000..04c4363
--- /dev/null
+++ b/cc/common/cc_shared_library_info.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""CcSharedLibraryInfo"""
+
+load("//cc/private/rules_impl:native.bzl", "NativeCcSharedLibraryInfo")
+
+CcSharedLibraryInfo = NativeCcSharedLibraryInfo
diff --git a/cc/common/debug_package_info.bzl b/cc/common/debug_package_info.bzl
new file mode 100644
index 0000000..8087840
--- /dev/null
+++ b/cc/common/debug_package_info.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""DebugPackageInfo"""
+
+load("//cc/private/rules_impl:native.bzl", "NativeDebugPackageInfo")
+
+DebugPackageInfo = NativeDebugPackageInfo
diff --git a/cc/common/visibility.bzl b/cc/common/visibility.bzl
new file mode 100644
index 0000000..981ce86
--- /dev/null
+++ b/cc/common/visibility.bzl
@@ -0,0 +1,3 @@
+"""Bzl load visibility package specs"""
+
+INTERNAL_VISIBILITY = ["public"]
diff --git a/cc/compiler/BUILD b/cc/compiler/BUILD
index 41f00e4..2f81d74 100644
--- a/cc/compiler/BUILD
+++ b/cc/compiler/BUILD
@@ -29,9 +29,9 @@ Example:
     name = "foo",
     srcs = ["foo.cc"],
     copts = select({
-        "@rules_cc//cc/compiler:gcc": [...],
-        "@rules_cc//cc/compiler:clang": [...],
-        "@rules_cc//cc/compiler:msvc-cl": [...],
+        "//cc/compiler:gcc": [...],
+        "//cc/compiler:clang": [...],
+        "//cc/compiler:msvc-cl": [...],
         # Fallback case for an undetected compiler.
         "//conditions:default": [...],
     }),
@@ -47,25 +47,30 @@ licenses(["notice"])
 
 config_setting(
     name = "clang",
-    flag_values = {"@bazel_tools//tools/cpp:compiler": "clang"},
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "clang"},
 )
 
 config_setting(
     name = "clang-cl",
-    flag_values = {"@bazel_tools//tools/cpp:compiler": "clang-cl"},
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "clang-cl"},
 )
 
 config_setting(
     name = "gcc",
-    flag_values = {"@bazel_tools//tools/cpp:compiler": "gcc"},
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "gcc"},
 )
 
 config_setting(
     name = "mingw-gcc",
-    flag_values = {"@bazel_tools//tools/cpp:compiler": "mingw-gcc"},
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "mingw-gcc"},
 )
 
 config_setting(
     name = "msvc-cl",
-    flag_values = {"@bazel_tools//tools/cpp:compiler": "msvc-cl"},
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "msvc-cl"},
+)
+
+config_setting(
+    name = "emscripten",
+    flag_values = {"@rules_cc//cc/private/toolchain:compiler": "emscripten"},
 )
diff --git a/cc/defs.bzl b/cc/defs.bzl
index 11be6fd..afcdba8 100644
--- a/cc/defs.bzl
+++ b/cc/defs.bzl
@@ -11,193 +11,55 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-
 """Starlark rules for building C++ projects."""
 
-load("//cc/private/rules_impl:cc_flags_supplier.bzl", _cc_flags_supplier = "cc_flags_supplier")
-load("//cc/private/rules_impl:compiler_flag.bzl", _compiler_flag = "compiler_flag")
-load("//cc/private/rules_impl:native.bzl", "NativeCcInfo", "NativeCcToolchainConfigInfo", "NativeDebugPackageInfo", "native_cc_common")
-
-_MIGRATION_TAG = "__CC_RULES_MIGRATION_DO_NOT_USE_WILL_BREAK__"
-
-# TODO(bazel-team): To avoid breaking changes, if the below are no longer
-# forwarding to native rules, flag @bazel_tools@bazel_tools//tools/cpp:link_extra_libs
-# should either: (a) alias the flag @rules_cc//:link_extra_libs, or (b) be
-# added as a dependency to @rules_cc//:link_extra_lib. The intermediate library
-# @bazel_tools@bazel_tools//tools/cpp:link_extra_lib should either be added as a dependency
-# to @rules_cc//:link_extra_lib, or removed entirely (if possible).
-_LINK_EXTRA_LIB = "@rules_cc//:link_extra_lib"  # copybara-use-repo-external-label
-
-def _add_tags(attrs, is_binary = False):
-    if "tags" in attrs and attrs["tags"] != None:
-        attrs["tags"] = attrs["tags"] + [_MIGRATION_TAG]
-    else:
-        attrs["tags"] = [_MIGRATION_TAG]
-
-    if is_binary:
-        is_library = "linkshared" in attrs and attrs["linkshared"]
-
-        # Executable builds also include the "link_extra_lib" library.
-        if not is_library:
-            if "deps" in attrs and attrs["deps"] != None:
-                attrs["deps"] = attrs["deps"] + [_LINK_EXTRA_LIB]
-            else:
-                attrs["deps"] = [_LINK_EXTRA_LIB]
-
-    return attrs
-
-def cc_binary(**attrs):
-    """Bazel cc_binary rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_binary
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_binary(**_add_tags(attrs, True))
-
-def cc_test(**attrs):
-    """Bazel cc_test rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_test
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_test(**_add_tags(attrs, True))
-
-def cc_library(**attrs):
-    """Bazel cc_library rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_library(**_add_tags(attrs))
-
-def cc_import(**attrs):
-    """Bazel cc_import rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_import
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_import(**_add_tags(attrs))
-
-def cc_proto_library(**attrs):
-    """Bazel cc_proto_library rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_proto_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc-proto
-    native.cc_proto_library(**_add_tags(attrs))
-
-def fdo_prefetch_hints(**attrs):
-    """Bazel fdo_prefetch_hints rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#fdo_prefetch_hints
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.fdo_prefetch_hints(**_add_tags(attrs))
-
-def fdo_profile(**attrs):
-    """Bazel fdo_profile rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#fdo_profile
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.fdo_profile(**_add_tags(attrs))
-
-def cc_toolchain(**attrs):
-    """Bazel cc_toolchain rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_toolchain
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_toolchain(**_add_tags(attrs))
-
-def cc_toolchain_suite(**attrs):
-    """Bazel cc_toolchain_suite rule.
-
-    https://docs.bazel.build/versions/main/be/c-cpp.html#cc_toolchain_suite
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.cc_toolchain_suite(**_add_tags(attrs))
-
-def objc_library(**attrs):
-    """Bazel objc_library rule.
-
-    https://docs.bazel.build/versions/main/be/objective-c.html#objc_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.objc_library(**_add_tags(attrs))
-
-def objc_import(**attrs):
-    """Bazel objc_import rule.
-
-    https://docs.bazel.build/versions/main/be/objective-c.html#objc_import
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-cc
-    native.objc_import(**_add_tags(attrs))
-
-def cc_flags_supplier(**attrs):
-    """Bazel cc_flags_supplier rule.
-
-    Args:
-      **attrs: Rule attributes
-    """
-    _cc_flags_supplier(**_add_tags(attrs))
-
-def compiler_flag(**attrs):
-    """Bazel compiler_flag rule.
-
-    Args:
-      **attrs: Rule attributes
-    """
-    _compiler_flag(**_add_tags(attrs))
-
-cc_common = native_cc_common
-
-CcInfo = NativeCcInfo
-
-CcToolchainConfigInfo = NativeCcToolchainConfigInfo
-
-DebugPackageInfo = NativeDebugPackageInfo
+load("//cc:cc_binary.bzl", _cc_binary = "cc_binary")
+load("//cc:cc_import.bzl", _cc_import = "cc_import")
+load("//cc:cc_library.bzl", _cc_library = "cc_library")
+load("//cc:cc_shared_library.bzl", _cc_shared_library = "cc_shared_library")
+load("//cc:cc_test.bzl", _cc_test = "cc_test")
+load("//cc:objc_import.bzl", _objc_import = "objc_import")
+load("//cc:objc_library.bzl", _objc_library = "objc_library")
+load("//cc/common:cc_common.bzl", _cc_common = "cc_common")
+load("//cc/common:cc_info.bzl", _CcInfo = "CcInfo")
+load("//cc/common:debug_package_info.bzl", _DebugPackageInfo = "DebugPackageInfo")
+load("//cc/toolchains:cc_flags_supplier.bzl", _cc_flags_supplier = "cc_flags_supplier")
+load("//cc/toolchains:cc_toolchain.bzl", _cc_toolchain = "cc_toolchain")
+load("//cc/toolchains:cc_toolchain_config_info.bzl", _CcToolchainConfigInfo = "CcToolchainConfigInfo")
+load("//cc/toolchains:cc_toolchain_suite.bzl", _cc_toolchain_suite = "cc_toolchain_suite")
+load("//cc/toolchains:compiler_flag.bzl", _compiler_flag = "compiler_flag")
+load("//cc/toolchains:fdo_prefetch_hints.bzl", _fdo_prefetch_hints = "fdo_prefetch_hints")
+load("//cc/toolchains:fdo_profile.bzl", _fdo_profile = "fdo_profile")
+
+# Rules
+
+cc_library = _cc_library
+cc_binary = _cc_binary
+cc_test = _cc_test
+cc_import = _cc_import
+cc_shared_library = _cc_shared_library
+
+objc_library = _objc_library
+objc_import = _objc_import
+
+# ANDROID: Drop protobuf dependency to avoid being fetched from the Internet
+def cc_proto_library(**kwargs):
+    fail("{}: Use cc_proto_library from com_google_protobuf".format(
+        native.package_relative_label(kwargs.get("name")),
+    ))
+
+# Toolchain rules
+
+cc_toolchain = _cc_toolchain
+fdo_profile = _fdo_profile
+fdo_prefetch_hints = _fdo_prefetch_hints
+cc_toolchain_suite = _cc_toolchain_suite
+compiler_flag = _compiler_flag
+cc_flags_supplier = _cc_flags_supplier
+
+# Modules and providers
+
+cc_common = _cc_common
+CcInfo = _CcInfo
+DebugPackageInfo = _DebugPackageInfo
+CcToolchainConfigInfo = _CcToolchainConfigInfo
diff --git a/cc/extensions.bzl b/cc/extensions.bzl
index 72b2dca..0d73141 100644
--- a/cc/extensions.bzl
+++ b/cc/extensions.bzl
@@ -13,12 +13,15 @@
 # limitations under the License.
 """Module extension for cc auto configuration."""
 
-load("@bazel_tools//tools/osx:xcode_configure.bzl", "xcode_configure")
+load("@bazel_features//:features.bzl", "bazel_features")
 load("//cc/private/toolchain:cc_configure.bzl", "cc_autoconf", "cc_autoconf_toolchains")
 
-def _cc_configure_impl(_):
+def _cc_configure_extension_impl(ctx):
     cc_autoconf_toolchains(name = "local_config_cc_toolchains")
     cc_autoconf(name = "local_config_cc")
-    xcode_configure("@bazel_tools//tools/osx:xcode_locator.m")
+    if bazel_features.external_deps.extension_metadata_has_reproducible:
+        return ctx.extension_metadata(reproducible = True)
+    else:
+        return None
 
-cc_configure = module_extension(implementation = _cc_configure_impl)
+cc_configure_extension = module_extension(implementation = _cc_configure_extension_impl)
diff --git a/cc/find_cc_toolchain.bzl b/cc/find_cc_toolchain.bzl
index d2f2d9f..c3e9ed4 100644
--- a/cc/find_cc_toolchain.bzl
+++ b/cc/find_cc_toolchain.bzl
@@ -29,7 +29,7 @@ to depend on and find a cc toolchain.
         attrs = {
             "_cc_toolchain": attr.label(
                 default = Label(
-                    "@rules_cc//cc:current_cc_toolchain", # copybara-use-repo-external-label
+                    "@rules_cc//cc:current_cc_toolchain",
                 ),
             ),
         },
@@ -53,17 +53,20 @@ https://github.com/bazelbuild/bazel/issues/7260 is flipped (and support for old
 Bazel version is not needed), it's enough to only keep the toolchain type.
 """
 
-CC_TOOLCHAIN_TYPE = "@bazel_tools//tools/cpp:toolchain_type"  # copybara-use-repo-external-label
+CC_TOOLCHAIN_TYPE = Label("@bazel_tools//tools/cpp:toolchain_type")
 
-def find_cc_toolchain(ctx):
+def find_cc_toolchain(ctx, *, mandatory = True):
     """
 Returns the current `CcToolchainInfo`.
 
     Args:
       ctx: The rule context for which to find a toolchain.
+      mandatory: (bool) If this is set to False, this function will return None
+        rather than fail if no toolchain is found.
 
     Returns:
-      A CcToolchainInfo.
+      A CcToolchainInfo or None if the c++ toolchain is declared as
+      optional, mandatory is False and no toolchain has been found.
     """
 
     # Check the incompatible flag for toolchain resolution.
@@ -72,6 +75,9 @@ Returns the current `CcToolchainInfo`.
             fail("In order to use find_cc_toolchain, your rule has to depend on C++ toolchain. See find_cc_toolchain.bzl docs for details.")
         toolchain_info = ctx.toolchains[CC_TOOLCHAIN_TYPE]
         if toolchain_info == None:
+            if not mandatory:
+                return None
+
             # No cpp toolchain was found, so report an error.
             fail("Unable to find a CC toolchain using toolchain resolution. Target: %s, Platform: %s, Exec platform: %s" %
                  (ctx.label, ctx.fragments.platform.platform, ctx.fragments.platform.host_platform))
@@ -84,6 +90,8 @@ Returns the current `CcToolchainInfo`.
         return ctx.attr._cc_toolchain[cc_common.CcToolchainInfo]
 
     # We didn't find anything.
+    if not mandatory:
+        return None
     fail("In order to use find_cc_toolchain, your rule has to depend on C++ toolchain. See find_cc_toolchain.bzl docs for details.")
 
 def find_cpp_toolchain(ctx):
diff --git a/cc/objc_import.bzl b/cc/objc_import.bzl
new file mode 100644
index 0000000..723f4c7
--- /dev/null
+++ b/cc/objc_import.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""objc_import rule"""
+
+def objc_import(**kwargs):
+    native.objc_import(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/objc_library.bzl b/cc/objc_library.bzl
new file mode 100644
index 0000000..5292be3
--- /dev/null
+++ b/cc/objc_library.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""objc_library rule"""
+
+def objc_library(**kwargs):
+    native.objc_library(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/private/BUILD b/cc/private/BUILD
new file mode 100644
index 0000000..15361bb
--- /dev/null
+++ b/cc/private/BUILD
@@ -0,0 +1,24 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+filegroup(
+    name = "srcs",
+    srcs = glob([
+        "**/BUILD",
+    ]) + [
+        "//cc/private/rules_impl:srcs",
+        "//cc/private/toolchain:srcs",
+    ],
+    visibility = ["//visibility:public"],
+)
diff --git a/cc/private/bazel7/BUILD b/cc/private/bazel7/BUILD
new file mode 100644
index 0000000..ebf88d4
--- /dev/null
+++ b/cc/private/bazel7/BUILD
@@ -0,0 +1,24 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+package(default_visibility = ["//visibility:public"])
+
+licenses(["notice"])  # Apache 2.0
+
+# The target is here, because it's doesn't build on Bazel 6.
+# Unfortunately, rules_cc doesn't have a WORKSPACE setup and thus can't use bazel_features check.
+cc_toolchain_alias(
+    name = "optional_current_cc_toolchain",
+    mandatory = False,
+)
diff --git a/cc/private/rules_impl/BUILD b/cc/private/rules_impl/BUILD
index dc74dfe..88d9537 100644
--- a/cc/private/rules_impl/BUILD
+++ b/cc/private/rules_impl/BUILD
@@ -1,3 +1,5 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
 package(default_visibility = ["//visibility:public"])
 
 licenses(["notice"])  # Apache 2.0
@@ -16,3 +18,15 @@ filegroup(
         "**/BUILD",
     ]),
 )
+
+bzl_library(
+    name = "cc_flags_supplier_lib_bzl",
+    srcs = ["cc_flags_supplier_lib.bzl"],
+    visibility = ["//cc:__subpackages__"],
+)
+
+bzl_library(
+    name = "native_bzl",
+    srcs = ["native.bzl"],
+    visibility = ["//cc:__subpackages__"],
+)
diff --git a/cc/private/rules_impl/native.bzl b/cc/private/rules_impl/native.bzl
index cce8c7f..e5fabd3 100644
--- a/cc/private/rules_impl/native.bzl
+++ b/cc/private/rules_impl/native.bzl
@@ -32,3 +32,6 @@ NativeCcToolchainConfigInfo = CcToolchainConfigInfo
 
 # buildifier: disable=native-cc
 native_cc_common = cc_common
+
+# buildifier: disable=native-cc
+NativeCcSharedLibraryInfo = CcSharedLibraryInfo
diff --git a/cc/private/toolchain/BUILD b/cc/private/toolchain/BUILD
index 557a6a7..5c30925 100644
--- a/cc/private/toolchain/BUILD
+++ b/cc/private/toolchain/BUILD
@@ -1,5 +1,3 @@
-load("//cc:defs.bzl", "cc_flags_supplier", "cc_library", "compiler_flag")
-
 # Copyright 2018 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -14,6 +12,11 @@ load("//cc:defs.bzl", "cc_flags_supplier", "cc_library", "compiler_flag")
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
+
+load("//cc:cc_library.bzl", "cc_library")
+load("//cc/toolchains:cc_flags_supplier.bzl", "cc_flags_supplier")
+load("//cc/toolchains:compiler_flag.bzl", "compiler_flag")
+
 package(default_visibility = ["//visibility:public"])
 
 licenses(["notice"])  # Apache 2.0
diff --git a/cc/private/toolchain/BUILD.empty b/cc/private/toolchain/BUILD.empty.tpl
similarity index 80%
rename from cc/private/toolchain/BUILD.empty
rename to cc/private/toolchain/BUILD.empty.tpl
index a873d0c..3ae6387 100644
--- a/cc/private/toolchain/BUILD.empty
+++ b/cc/private/toolchain/BUILD.empty.tpl
@@ -12,11 +12,16 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@rules_cc//cc:defs.bzl", "cc_library", "cc_toolchain", "cc_toolchain_suite")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")
+load("@rules_cc//cc/toolchains:cc_toolchain_suite.bzl", "cc_toolchain_suite")
+load(":cc_toolchain_config.bzl", "cc_toolchain_config")
 
 package(default_visibility = ["//visibility:public"])
 
-load(":cc_toolchain_config.bzl", "cc_toolchain_config")
+cc_library(
+    name = "link_extra_lib",
+)
 
 cc_library(
     name = "malloc",
@@ -30,8 +35,8 @@ filegroup(
 cc_toolchain_suite(
     name = "toolchain",
     toolchains = {
-        "local": ":local",
-        "local|local": ":local",
+        "%{cpu}|local": ":local",
+        "%{cpu}": ":local",
     },
 )
 
diff --git a/cc/private/toolchain/BUILD.static.freebsd b/cc/private/toolchain/BUILD.static.bsd
similarity index 60%
rename from cc/private/toolchain/BUILD.static.freebsd
rename to cc/private/toolchain/BUILD.static.bsd
index d8a7b2d..30d57c2 100644
--- a/cc/private/toolchain/BUILD.static.freebsd
+++ b/cc/private/toolchain/BUILD.static.bsd
@@ -12,12 +12,32 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# This becomes the BUILD file for @local_config_cc// under FreeBSD.
+# This becomes the BUILD file for @local_config_cc// under FreeBSD and OpenBSD.
+
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")
+load("@rules_cc//cc/toolchains:cc_toolchain_suite.bzl", "cc_toolchain_suite")
+load(":cc_toolchain_config.bzl", "cc_toolchain_config")
 
 package(default_visibility = ["//visibility:public"])
 
-load("@rules_cc//cc:defs.bzl", "cc_library", "cc_toolchain", "cc_toolchain_suite")
-load(":cc_toolchain_config.bzl", "cc_toolchain_config")
+cc_library(name = "empty_lib")
+
+# Label flag for extra libraries to be linked into every binary.
+# TODO(bazel-team): Support passing flag multiple times to build a list.
+label_flag(
+    name = "link_extra_libs",
+    build_setting_default = ":empty_lib",
+)
+
+# The final extra library to be linked into every binary target. This collects
+# the above flag, but may also include more libraries depending on config.
+cc_library(
+    name = "link_extra_lib",
+    deps = [
+        ":link_extra_libs",
+    ],
+)
 
 cc_library(
     name = "malloc",
@@ -32,10 +52,12 @@ filegroup(
 cc_toolchain_suite(
     name = "toolchain",
     toolchains = {
-        "armeabi-v7a": ":cc-compiler-armeabi-v7a",
         "armeabi-v7a|compiler": ":cc-compiler-armeabi-v7a",
-        "freebsd": ":cc-compiler-freebsd",
         "freebsd|compiler": ":cc-compiler-freebsd",
+        "openbsd|compiler": ":cc-compiler-openbsd",
+        "armeabi-v7a": ":cc-compiler-armeabi-v7a",
+        "freebsd": ":cc-compiler-freebsd",
+        "openbsd": ":cc-compiler-openbsd",
     },
 )
 
@@ -70,7 +92,41 @@ toolchain(
         "@platforms//os:freebsd",
     ],
     toolchain = ":cc-compiler-freebsd",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-openbsd",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":empty",
+    compiler_files = ":empty",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 0,
+    toolchain_config = ":local_openbsd",
+    toolchain_identifier = "local_openbsd",
+)
+
+cc_toolchain_config(
+    name = "local_openbsd",
+    cpu = "openbsd",
+)
+
+toolchain(
+    name = "cc-toolchain-openbsd",
+    exec_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:openbsd",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:openbsd",
+    ],
+    toolchain = ":cc-compiler-openbsd",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 cc_toolchain(
@@ -99,11 +155,11 @@ toolchain(
         "@platforms//cpu:arm",
     ],
     target_compatible_with = [
-        "@platforms//cpu:arm",
+        "@platforms//cpu:armv7",
         "@platforms//os:android",
     ],
     toolchain = ":cc-compiler-armeabi-v7a",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 filegroup(
diff --git a/cc/private/toolchain/BUILD.toolchains.tpl b/cc/private/toolchain/BUILD.toolchains.tpl
index 3fee112..7d3d6d6 100644
--- a/cc/private/toolchain/BUILD.toolchains.tpl
+++ b/cc/private/toolchain/BUILD.toolchains.tpl
@@ -5,16 +5,16 @@ toolchain(
     exec_compatible_with = HOST_CONSTRAINTS,
     target_compatible_with = HOST_CONSTRAINTS,
     toolchain = "@local_config_cc//:cc-compiler-%{name}",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 toolchain(
     name = "cc-toolchain-armeabi-v7a",
     exec_compatible_with = HOST_CONSTRAINTS,
     target_compatible_with = [
-        "@platforms//cpu:arm",
+        "@platforms//cpu:armv7",
         "@platforms//os:android",
     ],
     toolchain = "@local_config_cc//:cc-compiler-armeabi-v7a",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
diff --git a/cc/private/toolchain/BUILD.tpl b/cc/private/toolchain/BUILD.tpl
index 9241326..522d67e 100644
--- a/cc/private/toolchain/BUILD.tpl
+++ b/cc/private/toolchain/BUILD.tpl
@@ -12,16 +12,35 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# This becomes the BUILD file for @local_config_cc// under non-FreeBSD unixes.
-
-package(default_visibility = ["//visibility:public"])
+# This becomes the BUILD file for @local_config_cc// under non-BSD unixes.
 
 load(":cc_toolchain_config.bzl", "cc_toolchain_config")
 load(":armeabi_cc_toolchain_config.bzl", "armeabi_cc_toolchain_config")
-load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")
+load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")
+load("@rules_cc//cc/toolchains:cc_toolchain_suite.bzl", "cc_toolchain_suite")
+
+package(default_visibility = ["//visibility:public"])
 
 licenses(["notice"])  # Apache 2.0
 
+cc_library(name = "empty_lib")
+
+# Label flag for extra libraries to be linked into every binary.
+# TODO(bazel-team): Support passing flag multiple times to build a list.
+label_flag(
+    name = "link_extra_libs",
+    build_setting_default = ":empty_lib",
+)
+
+# The final extra library to be linked into every binary target. This collects
+# the above flag, but may also include more libraries depending on config.
+cc_library(
+    name = "link_extra_lib",
+    deps = [
+        ":link_extra_libs",
+    ],
+)
+
 cc_library(
     name = "malloc",
 )
@@ -36,6 +55,15 @@ filegroup(
     srcs = ["cc_wrapper.sh"],
 )
 
+filegroup(
+    name = "validate_static_library",
+    srcs = ["validate_static_library.sh"],
+)
+
+filegroup(
+    name = "deps_scanner_wrapper",
+    srcs = ["deps_scanner_wrapper.sh"],
+)
 filegroup(
     name = "compiler_deps",
     srcs = glob(["extra_tools/**"], allow_empty = True) + [%{cc_compiler_deps}],
@@ -66,7 +94,9 @@ cc_toolchain(
     linker_files = ":compiler_deps",
     objcopy_files = ":empty",
     strip_files = ":empty",
-    supports_param_files = %{supports_param_files},
+    supports_header_parsing = 1,
+    supports_param_files = 1,
+    module_map = %{modulemap},
 )
 
 cc_toolchain_config(
@@ -84,6 +114,7 @@ cc_toolchain_config(
     compile_flags = [%{compile_flags}],
     opt_compile_flags = [%{opt_compile_flags}],
     dbg_compile_flags = [%{dbg_compile_flags}],
+    conly_flags = [%{conly_flags}],
     cxx_flags = [%{cxx_flags}],
     link_flags = [%{link_flags}],
     link_libs = [%{link_libs}],
@@ -92,6 +123,7 @@ cc_toolchain_config(
     coverage_compile_flags = [%{coverage_compile_flags}],
     coverage_link_flags = [%{coverage_link_flags}],
     supports_start_end_lib = %{supports_start_end_lib},
+    extra_flags_per_feature = %{extra_flags_per_feature},
 )
 
 # Android tooling requires a default toolchain for the armeabi-v7a cpu.
diff --git a/cc/private/toolchain/BUILD.windows.tpl b/cc/private/toolchain/BUILD.windows.tpl
index 66dbafd..75fbd0a 100644
--- a/cc/private/toolchain/BUILD.windows.tpl
+++ b/cc/private/toolchain/BUILD.windows.tpl
@@ -14,11 +14,32 @@
 
 # This becomes the BUILD file for @local_config_cc// under Windows.
 
-package(default_visibility = ["//visibility:public"])
-
-load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite", "cc_library")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")
+load("@rules_cc//cc/toolchains:cc_toolchain_suite.bzl", "cc_toolchain_suite")
 load(":windows_cc_toolchain_config.bzl", "cc_toolchain_config")
 load(":armeabi_cc_toolchain_config.bzl", "armeabi_cc_toolchain_config")
+
+package(default_visibility = ["//visibility:public"])
+
+cc_library(name = "empty_lib")
+
+# Label flag for extra libraries to be linked into every binary.
+# TODO(bazel-team): Support passing flag multiple times to build a list.
+label_flag(
+    name = "link_extra_libs",
+    build_setting_default = ":empty_lib",
+)
+
+# The final extra library to be linked into every binary target. This collects
+# the above flag, but may also include more libraries depending on config.
+cc_library(
+    name = "link_extra_lib",
+    deps = [
+        ":link_extra_libs",
+    ],
+)
+
 cc_library(
     name = "malloc",
 )
@@ -40,7 +61,13 @@ filegroup(
 
 filegroup(
     name = "msvc_compiler_files",
-    srcs = [":builtin_include_directory_paths_msvc"]
+    srcs = [
+        ":builtin_include_directory_paths_msvc",
+        "%{msvc_deps_scanner_wrapper_path_x86}",
+        "%{msvc_deps_scanner_wrapper_path_x64}",
+        "%{msvc_deps_scanner_wrapper_path_arm}",
+        "%{msvc_deps_scanner_wrapper_path_arm64}",
+    ]
 )
 
 # Hardcoded toolchain, legacy behaviour.
@@ -49,11 +76,23 @@ cc_toolchain_suite(
     toolchains = {
         "armeabi-v7a|compiler": ":cc-compiler-armeabi-v7a",
         "x64_windows|msvc-cl": ":cc-compiler-x64_windows",
+        "x64_x86_windows|msvc-cl": ":cc-compiler-x64_x86_windows",
+        "x64_arm_windows|msvc-cl": ":cc-compiler-x64_arm_windows",
+        "x64_arm64_windows|msvc-cl": ":cc-compiler-arm64_windows",
+        "arm64_windows|msvc-cl": ":cc-compiler-arm64_windows",
         "x64_windows|msys-gcc": ":cc-compiler-x64_windows_msys",
+        "x64_x86_windows|msys-gcc": ":cc-compiler-x64_x86_windows_msys",
         "x64_windows|mingw-gcc": ":cc-compiler-x64_windows_mingw",
+        "x64_x86_windows|mingw-gcc": ":cc-compiler-x64_x86_windows_mingw",
         "x64_windows|clang-cl": ":cc-compiler-x64_windows-clang-cl",
         "x64_windows_msys": ":cc-compiler-x64_windows_msys",
         "x64_windows": ":cc-compiler-x64_windows",
+        "x64_x86_windows": ":cc-compiler-x64_x86_windows",
+        "x64_arm_windows": ":cc-compiler-x64_arm_windows",
+        "x64_arm64_windows": ":cc-compiler-arm64_windows",
+        "arm64_windows": ":cc-compiler-arm64_windows",
+        "x64_arm64_windows|clang-cl": ":cc-compiler-arm64_windows-clang-cl",
+        "arm64_windows|clang-cl": ":cc-compiler-arm64_windows-clang-cl",
         "armeabi-v7a": ":cc-compiler-armeabi-v7a",
     },
 )
@@ -85,8 +124,6 @@ cc_toolchain_config(
     cxx_builtin_include_directories = [%{cxx_builtin_include_directories}],
     tool_paths = {%{tool_paths}},
     tool_bin_path = "%{tool_bin_path}",
-    dbg_mode_debug_flag = "%{dbg_mode_debug_flag}",
-    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag}",
 )
 
 toolchain(
@@ -101,7 +138,53 @@ toolchain(
         "@platforms//os:windows",
     ],
     toolchain = ":cc-compiler-x64_windows_msys",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-x64_x86_windows_msys",
+    toolchain_identifier = "msys_x64_x86",
+    toolchain_config = ":msys_x64_x86",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":mingw_compiler_files",
+    compiler_files = ":mingw_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 1,
+)
+
+cc_toolchain_config(
+    name = "msys_x64_x86",
+    cpu = "x64_x86_windows",
+    compiler = "msys-gcc",
+    host_system_name = "local",
+    target_system_name = "local",
+    target_libc = "msys",
+    abi_version = "local",
+    abi_libc_version = "local",
+    cxx_builtin_include_directories = [%{cxx_builtin_include_directories}],
+    tool_paths = {%{tool_paths}},
+    tool_bin_path = "%{tool_bin_path}",
+    default_compile_flags = ["-m32"],
+    default_link_flags = ["-m32"],
+)
+
+toolchain(
+    name = "cc-toolchain-x64_x86_windows_msys",
+    exec_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:windows",
+        "@rules_cc//cc/private/toolchain:msys",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:x86_32",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-x64_x86_windows_msys",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 cc_toolchain(
@@ -131,8 +214,6 @@ cc_toolchain_config(
     tool_bin_path = "%{mingw_tool_bin_path}",
     cxx_builtin_include_directories = [%{mingw_cxx_builtin_include_directories}],
     tool_paths = {%{mingw_tool_paths}},
-    dbg_mode_debug_flag = "%{dbg_mode_debug_flag}",
-    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag}",
 )
 
 toolchain(
@@ -147,7 +228,53 @@ toolchain(
         "@platforms//os:windows",
     ],
     toolchain = ":cc-compiler-x64_windows_mingw",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-x64_x86_windows_mingw",
+    toolchain_identifier = "msys_x64_x86_mingw",
+    toolchain_config = ":msys_x64_x86_mingw",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":mingw_compiler_files",
+    compiler_files = ":mingw_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 0,
+)
+
+cc_toolchain_config(
+    name = "msys_x64_x86_mingw",
+    cpu = "x64_x86_windows",
+    compiler = "mingw-gcc",
+    host_system_name = "local",
+    target_system_name = "local",
+    target_libc = "mingw",
+    abi_version = "local",
+    abi_libc_version = "local",
+    tool_bin_path = "%{mingw_tool_bin_path}",
+    cxx_builtin_include_directories = [%{mingw_cxx_builtin_include_directories}],
+    tool_paths = {%{mingw_tool_paths}},
+    default_compile_flags = ["-m32"],
+    default_link_flags = ["-m32"],
+)
+
+toolchain(
+    name = "cc-toolchain-x64_x86_windows_mingw",
+    exec_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:windows",
+        "@rules_cc//cc/private/toolchain:mingw",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:x86_32",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-x64_x86_windows_mingw",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 cc_toolchain(
@@ -175,30 +302,34 @@ cc_toolchain_config(
     abi_version = "local",
     abi_libc_version = "local",
     toolchain_identifier = "msvc_x64",
-    msvc_env_tmp = "%{msvc_env_tmp}",
-    msvc_env_path = "%{msvc_env_path}",
-    msvc_env_include = "%{msvc_env_include}",
-    msvc_env_lib = "%{msvc_env_lib}",
-    msvc_cl_path = "%{msvc_cl_path}",
-    msvc_ml_path = "%{msvc_ml_path}",
-    msvc_link_path = "%{msvc_link_path}",
-    msvc_lib_path = "%{msvc_lib_path}",
-    cxx_builtin_include_directories = [%{msvc_cxx_builtin_include_directories}],
+    msvc_env_tmp = "%{msvc_env_tmp_x64}",
+    msvc_env_path = "%{msvc_env_path_x64}",
+    msvc_env_include = "%{msvc_env_include_x64}",
+    msvc_env_lib = "%{msvc_env_lib_x64}",
+    msvc_cl_path = "%{msvc_cl_path_x64}",
+    msvc_ml_path = "%{msvc_ml_path_x64}",
+    msvc_link_path = "%{msvc_link_path_x64}",
+    msvc_lib_path = "%{msvc_lib_path_x64}",
+    cxx_builtin_include_directories = [%{msvc_cxx_builtin_include_directories_x64}],
     tool_paths = {
-        "ar": "%{msvc_lib_path}",
-        "ml": "%{msvc_ml_path}",
-        "cpp": "%{msvc_cl_path}",
-        "gcc": "%{msvc_cl_path}",
+        "ar": "%{msvc_lib_path_x64}",
+        "ml": "%{msvc_ml_path_x64}",
+        "cpp": "%{msvc_cl_path_x64}",
+        "gcc": "%{msvc_cl_path_x64}",
         "gcov": "wrapper/bin/msvc_nop.bat",
-        "ld": "%{msvc_link_path}",
+        "ld": "%{msvc_link_path_x64}",
         "nm": "wrapper/bin/msvc_nop.bat",
         "objcopy": "wrapper/bin/msvc_nop.bat",
         "objdump": "wrapper/bin/msvc_nop.bat",
         "strip": "wrapper/bin/msvc_nop.bat",
+        "dumpbin": "%{msvc_dumpbin_path_x64}",
+        "cpp-module-deps-scanner": "%{msvc_deps_scanner_wrapper_path_x64}",
     },
+    archiver_flags = ["/MACHINE:X64"],
     default_link_flags = ["/MACHINE:X64"],
-    dbg_mode_debug_flag = "%{dbg_mode_debug_flag}",
-    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag}",
+    dbg_mode_debug_flag = "%{dbg_mode_debug_flag_x64}",
+    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag_x64}",
+    supports_parse_showincludes = %{msvc_parse_showincludes_x64},
 )
 
 toolchain(
@@ -212,9 +343,216 @@ toolchain(
         "@platforms//os:windows",
     ],
     toolchain = ":cc-compiler-x64_windows",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-x64_x86_windows",
+    toolchain_identifier = "msvc_x64_x86",
+    toolchain_config = ":msvc_x64_x86",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":msvc_compiler_files",
+    compiler_files = ":msvc_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 1,
+)
+
+cc_toolchain_config(
+    name = "msvc_x64_x86",
+    cpu = "x64_windows",
+    compiler = "msvc-cl",
+    host_system_name = "local",
+    target_system_name = "local",
+    target_libc = "msvcrt",
+    abi_version = "local",
+    abi_libc_version = "local",
+    toolchain_identifier = "msvc_x64_x86",
+    msvc_env_tmp = "%{msvc_env_tmp_x86}",
+    msvc_env_path = "%{msvc_env_path_x86}",
+    msvc_env_include = "%{msvc_env_include_x86}",
+    msvc_env_lib = "%{msvc_env_lib_x86}",
+    msvc_cl_path = "%{msvc_cl_path_x86}",
+    msvc_ml_path = "%{msvc_ml_path_x86}",
+    msvc_link_path = "%{msvc_link_path_x86}",
+    msvc_lib_path = "%{msvc_lib_path_x86}",
+    cxx_builtin_include_directories = [%{msvc_cxx_builtin_include_directories_x86}],
+    tool_paths = {
+        "ar": "%{msvc_lib_path_x86}",
+        "ml": "%{msvc_ml_path_x86}",
+        "cpp": "%{msvc_cl_path_x86}",
+        "gcc": "%{msvc_cl_path_x86}",
+        "gcov": "wrapper/bin/msvc_nop.bat",
+        "ld": "%{msvc_link_path_x86}",
+        "nm": "wrapper/bin/msvc_nop.bat",
+        "objcopy": "wrapper/bin/msvc_nop.bat",
+        "objdump": "wrapper/bin/msvc_nop.bat",
+        "strip": "wrapper/bin/msvc_nop.bat",
+        "dumpbin": "%{msvc_dumpbin_path_x86}",
+        "cpp-module-deps-scanner": "%{msvc_deps_scanner_wrapper_path_x86}",
+    },
+    archiver_flags = ["/MACHINE:X86"],
+    default_link_flags = ["/MACHINE:X86"],
+    dbg_mode_debug_flag = "%{dbg_mode_debug_flag_x86}",
+    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag_x86}",
+    supports_parse_showincludes = %{msvc_parse_showincludes_x86},
+)
+
+toolchain(
+    name = "cc-toolchain-x64_x86_windows",
+    exec_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:windows",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:x86_32",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-x64_x86_windows",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
+cc_toolchain(
+    name = "cc-compiler-x64_arm_windows",
+    toolchain_identifier = "msvc_x64_arm",
+    toolchain_config = ":msvc_x64_arm",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":msvc_compiler_files",
+    compiler_files = ":msvc_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 1,
+)
+
+cc_toolchain_config(
+    name = "msvc_x64_arm",
+    cpu = "x64_windows",
+    compiler = "msvc-cl",
+    host_system_name = "local",
+    target_system_name = "local",
+    target_libc = "msvcrt",
+    abi_version = "local",
+    abi_libc_version = "local",
+    toolchain_identifier = "msvc_x64_arm",
+    msvc_env_tmp = "%{msvc_env_tmp_arm}",
+    msvc_env_path = "%{msvc_env_path_arm}",
+    msvc_env_include = "%{msvc_env_include_arm}",
+    msvc_env_lib = "%{msvc_env_lib_arm}",
+    msvc_cl_path = "%{msvc_cl_path_arm}",
+    msvc_ml_path = "%{msvc_ml_path_arm}",
+    msvc_link_path = "%{msvc_link_path_arm}",
+    msvc_lib_path = "%{msvc_lib_path_arm}",
+    cxx_builtin_include_directories = [%{msvc_cxx_builtin_include_directories_arm}],
+    tool_paths = {
+        "ar": "%{msvc_lib_path_arm}",
+        "ml": "%{msvc_ml_path_arm}",
+        "cpp": "%{msvc_cl_path_arm}",
+        "gcc": "%{msvc_cl_path_arm}",
+        "gcov": "wrapper/bin/msvc_nop.bat",
+        "ld": "%{msvc_link_path_arm}",
+        "nm": "wrapper/bin/msvc_nop.bat",
+        "objcopy": "wrapper/bin/msvc_nop.bat",
+        "objdump": "wrapper/bin/msvc_nop.bat",
+        "strip": "wrapper/bin/msvc_nop.bat",
+        "dumpbin": "%{msvc_dumpbin_path_arm}",
+        "cpp-module-deps-scanner": "%{msvc_deps_scanner_wrapper_path_arm}",
+    },
+    archiver_flags = ["/MACHINE:ARM"],
+    default_link_flags = ["/MACHINE:ARM"],
+    dbg_mode_debug_flag = "%{dbg_mode_debug_flag_arm}",
+    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag_arm}",
+    supports_parse_showincludes = %{msvc_parse_showincludes_arm},
+)
+
+toolchain(
+    name = "cc-toolchain-x64_arm_windows",
+    exec_compatible_with = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:windows",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:arm",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-x64_arm_windows",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-arm64_windows",
+    toolchain_identifier = "msvc_arm64",
+    toolchain_config = ":msvc_arm64",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":msvc_compiler_files",
+    compiler_files = ":msvc_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 1,
+)
+
+cc_toolchain_config(
+    name = "msvc_arm64",
+    cpu = "x64_windows",
+    compiler = "msvc-cl",
+    host_system_name = "local",
+    target_system_name = "local",
+    target_libc = "msvcrt",
+    abi_version = "local",
+    abi_libc_version = "local",
+    toolchain_identifier = "msvc_arm64",
+    msvc_env_tmp = "%{msvc_env_tmp_arm64}",
+    msvc_env_path = "%{msvc_env_path_arm64}",
+    msvc_env_include = "%{msvc_env_include_arm64}",
+    msvc_env_lib = "%{msvc_env_lib_arm64}",
+    msvc_cl_path = "%{msvc_cl_path_arm64}",
+    msvc_ml_path = "%{msvc_ml_path_arm64}",
+    msvc_link_path = "%{msvc_link_path_arm64}",
+    msvc_lib_path = "%{msvc_lib_path_arm64}",
+    cxx_builtin_include_directories = [%{msvc_cxx_builtin_include_directories_arm64}],
+    tool_paths = {
+        "ar": "%{msvc_lib_path_arm64}",
+        "ml": "%{msvc_ml_path_arm64}",
+        "cpp": "%{msvc_cl_path_arm64}",
+        "gcc": "%{msvc_cl_path_arm64}",
+        "gcov": "wrapper/bin/msvc_nop.bat",
+        "ld": "%{msvc_link_path_arm64}",
+        "nm": "wrapper/bin/msvc_nop.bat",
+        "objcopy": "wrapper/bin/msvc_nop.bat",
+        "objdump": "wrapper/bin/msvc_nop.bat",
+        "strip": "wrapper/bin/msvc_nop.bat",
+        "dumpbin": "%{msvc_dumpbin_path_arm64}",
+        "cpp-module-deps-scanner": "%{msvc_deps_scanner_wrapper_path_arm64}",
+    },
+    archiver_flags = ["/MACHINE:ARM64"],
+    default_link_flags = ["/MACHINE:ARM64"],
+    dbg_mode_debug_flag = "%{dbg_mode_debug_flag_arm64}",
+    fastbuild_mode_debug_flag = "%{fastbuild_mode_debug_flag_arm64}",
+    supports_parse_showincludes = %{msvc_parse_showincludes_arm64},
+)
+
+toolchain(
+    name = "cc-toolchain-arm64_windows",
+    exec_compatible_with = [
+        "@platforms//os:windows",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:arm64",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-arm64_windows",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+
 cc_toolchain(
     name = "cc-compiler-x64_windows-clang-cl",
     toolchain_identifier = "clang_cl_x64",
@@ -240,30 +578,32 @@ cc_toolchain_config(
     abi_version = "local",
     abi_libc_version = "local",
     toolchain_identifier = "clang_cl_x64",
-    msvc_env_tmp = "%{clang_cl_env_tmp}",
-    msvc_env_path = "%{clang_cl_env_path}",
-    msvc_env_include = "%{clang_cl_env_include}",
-    msvc_env_lib = "%{clang_cl_env_lib}",
-    msvc_cl_path = "%{clang_cl_cl_path}",
-    msvc_ml_path = "%{clang_cl_ml_path}",
-    msvc_link_path = "%{clang_cl_link_path}",
-    msvc_lib_path = "%{clang_cl_lib_path}",
-    cxx_builtin_include_directories = [%{clang_cl_cxx_builtin_include_directories}],
+    msvc_env_tmp = "%{clang_cl_env_tmp_x64}",
+    msvc_env_path = "%{clang_cl_env_path_x64}",
+    msvc_env_include = "%{clang_cl_env_include_x64}",
+    msvc_env_lib = "%{clang_cl_env_lib_x64}",
+    msvc_cl_path = "%{clang_cl_cl_path_x64}",
+    msvc_ml_path = "%{clang_cl_ml_path_x64}",
+    msvc_link_path = "%{clang_cl_link_path_x64}",
+    msvc_lib_path = "%{clang_cl_lib_path_x64}",
+    cxx_builtin_include_directories = [%{clang_cl_cxx_builtin_include_directories_x64}],
     tool_paths = {
-        "ar": "%{clang_cl_lib_path}",
-        "ml": "%{clang_cl_ml_path}",
-        "cpp": "%{clang_cl_cl_path}",
-        "gcc": "%{clang_cl_cl_path}",
+        "ar": "%{clang_cl_lib_path_x64}",
+        "ml": "%{clang_cl_ml_path_x64}",
+        "cpp": "%{clang_cl_cl_path_x64}",
+        "gcc": "%{clang_cl_cl_path_x64}",
         "gcov": "wrapper/bin/msvc_nop.bat",
-        "ld": "%{clang_cl_link_path}",
+        "ld": "%{clang_cl_link_path_x64}",
         "nm": "wrapper/bin/msvc_nop.bat",
         "objcopy": "wrapper/bin/msvc_nop.bat",
         "objdump": "wrapper/bin/msvc_nop.bat",
         "strip": "wrapper/bin/msvc_nop.bat",
     },
-    default_link_flags = ["/MACHINE:X64", "/DEFAULTLIB:clang_rt.builtins-x86_64.lib"],
-    dbg_mode_debug_flag = "%{clang_cl_dbg_mode_debug_flag}",
-    fastbuild_mode_debug_flag = "%{clang_cl_fastbuild_mode_debug_flag}",
+    archiver_flags = ["/MACHINE:X64"],
+    default_link_flags = ["/MACHINE:X64"],
+    dbg_mode_debug_flag = "%{clang_cl_dbg_mode_debug_flag_x64}",
+    fastbuild_mode_debug_flag = "%{clang_cl_fastbuild_mode_debug_flag_x64}",
+    supports_parse_showincludes = %{clang_cl_parse_showincludes_x64},
 )
 
 toolchain(
@@ -278,7 +618,74 @@ toolchain(
         "@platforms//os:windows",
     ],
     toolchain = ":cc-compiler-x64_windows-clang-cl",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
+
+cc_toolchain(
+    name = "cc-compiler-arm64_windows-clang-cl",
+    toolchain_identifier = "clang_cl_arm64",
+    toolchain_config = ":clang_cl_arm64",
+    all_files = ":empty",
+    ar_files = ":empty",
+    as_files = ":clangcl_compiler_files",
+    compiler_files = ":clangcl_compiler_files",
+    dwp_files = ":empty",
+    linker_files = ":empty",
+    objcopy_files = ":empty",
+    strip_files = ":empty",
+    supports_param_files = 1,
+)
+
+cc_toolchain_config(
+    name = "clang_cl_arm64",
+    cpu = "arm64_windows",
+    compiler = "clang-cl",
+    host_system_name = "local",
+    target_system_name = "aarch64-pc-windows-msvc",
+    target_libc = "msvcrt",
+    abi_version = "local",
+    abi_libc_version = "local",
+    toolchain_identifier = "clang_cl_arm64",
+    msvc_env_tmp = "%{clang_cl_env_tmp_arm64}",
+    msvc_env_path = "%{clang_cl_env_path_arm64}",
+    msvc_env_include = "%{clang_cl_env_include_arm64}",
+    msvc_env_lib = "%{clang_cl_env_lib_arm64}",
+    msvc_cl_path = "%{clang_cl_cl_path_arm64}",
+    msvc_ml_path = "%{clang_cl_ml_path_arm64}",
+    msvc_link_path = "%{clang_cl_link_path_arm64}",
+    msvc_lib_path = "%{clang_cl_lib_path_arm64}",
+    cxx_builtin_include_directories = [%{clang_cl_cxx_builtin_include_directories_arm64}],
+    tool_paths = {
+        "ar": "%{clang_cl_lib_path_arm64}",
+        "ml": "%{clang_cl_ml_path_arm64}",
+        "cpp": "%{clang_cl_cl_path_arm64}",
+        "gcc": "%{clang_cl_cl_path_arm64}",
+        "gcov": "wrapper/bin/msvc_nop.bat",
+        "ld": "%{clang_cl_link_path_arm64}",
+        "nm": "wrapper/bin/msvc_nop.bat",
+        "objcopy": "wrapper/bin/msvc_nop.bat",
+        "objdump": "wrapper/bin/msvc_nop.bat",
+        "strip": "wrapper/bin/msvc_nop.bat",
+    },
+    archiver_flags = ["/MACHINE:ARM64"],
+    default_link_flags = ["/MACHINE:ARM64"],
+    dbg_mode_debug_flag = "%{clang_cl_dbg_mode_debug_flag_arm64}",
+    fastbuild_mode_debug_flag = "%{clang_cl_fastbuild_mode_debug_flag_arm64}",
+    supports_parse_showincludes = %{clang_cl_parse_showincludes_arm64},
+)
+
+toolchain(
+    name = "cc-toolchain-arm64_windows-clang-cl",
+    exec_compatible_with = [
+        "@platforms//os:windows",
+        "@rules_cc//cc/private/toolchain:clang-cl",
+    ],
+    target_compatible_with = [
+        "@platforms//cpu:arm64",
+        "@platforms//os:windows",
+    ],
+    toolchain = ":cc-compiler-arm64_windows-clang-cl",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
 
 cc_toolchain(
@@ -303,14 +710,9 @@ toolchain(
     exec_compatible_with = [
     ],
     target_compatible_with = [
-        "@platforms//cpu:arm",
+        "@platforms//cpu:armv7",
         "@platforms//os:android",
     ],
     toolchain = ":cc-compiler-armeabi-v7a",
-    toolchain_type = "@rules_cc//cc:toolchain_type",
-)
-
-filegroup(
-    name = "link_dynamic_library",
-    srcs = ["link_dynamic_library.sh"],
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
 )
diff --git a/cc/private/toolchain/armeabi_cc_toolchain_config.bzl b/cc/private/toolchain/armeabi_cc_toolchain_config.bzl
index 66c5752..7d4baad 100644
--- a/cc/private/toolchain/armeabi_cc_toolchain_config.bzl
+++ b/cc/private/toolchain/armeabi_cc_toolchain_config.bzl
@@ -49,6 +49,7 @@ def _impl(ctx):
         tool_path(name = "gcc", path = "/bin/false"),
         tool_path(name = "gcov", path = "/bin/false"),
         tool_path(name = "ld", path = "/bin/false"),
+        tool_path(name = "llvm-profdata", path = "/bin/false"),
         tool_path(name = "nm", path = "/bin/false"),
         tool_path(name = "objcopy", path = "/bin/false"),
         tool_path(name = "objdump", path = "/bin/false"),
diff --git a/cc/private/toolchain/freebsd_cc_toolchain_config.bzl b/cc/private/toolchain/bsd_cc_toolchain_config.bzl
similarity index 93%
rename from cc/private/toolchain/freebsd_cc_toolchain_config.bzl
rename to cc/private/toolchain/bsd_cc_toolchain_config.bzl
index 3521d92..3ad8d1f 100644
--- a/cc/private/toolchain/freebsd_cc_toolchain_config.bzl
+++ b/cc/private/toolchain/bsd_cc_toolchain_config.bzl
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""A Starlark cc_toolchain configuration rule for freebsd."""
+"""A Starlark cc_toolchain configuration rule for FreeBSD and OpenBSD."""
 
 load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
 load(
@@ -24,7 +24,7 @@ load(
     "tool",
     "tool_path",
     "with_feature_set",
-)
+)  # buildifier: disable=deprecated-function
 
 all_compile_actions = [
     ACTION_NAMES.c_compile,
@@ -56,13 +56,14 @@ all_link_actions = [
 
 def _impl(ctx):
     cpu = ctx.attr.cpu
+    is_bsd = cpu == "freebsd" or cpu == "openbsd"
     compiler = "compiler"
-    toolchain_identifier = "local_freebsd" if cpu == "freebsd" else "stub_armeabi-v7a"
-    host_system_name = "local" if cpu == "freebsd" else "armeabi-v7a"
-    target_system_name = "local" if cpu == "freebsd" else "armeabi-v7a"
-    target_libc = "local" if cpu == "freebsd" else "armeabi-v7a"
-    abi_version = "local" if cpu == "freebsd" else "armeabi-v7a"
-    abi_libc_version = "local" if cpu == "freebsd" else "armeabi-v7a"
+    toolchain_identifier = "local_{}".format(cpu) if is_bsd else "stub_armeabi-v7a"
+    host_system_name = "local" if is_bsd else "armeabi-v7a"
+    target_system_name = "local" if is_bsd else "armeabi-v7a"
+    target_libc = "local" if is_bsd else "armeabi-v7a"
+    abi_version = "local" if is_bsd else "armeabi-v7a"
+    abi_libc_version = "local" if is_bsd else "armeabi-v7a"
 
     objcopy_embed_data_action = action_config(
         action_name = "objcopy_embed_data",
@@ -70,7 +71,7 @@ def _impl(ctx):
         tools = [tool(path = "/usr/bin/objcopy")],
     )
 
-    action_configs = [objcopy_embed_data_action] if cpu == "freebsd" else []
+    action_configs = [objcopy_embed_data_action] if is_bsd else []
 
     default_link_flags_feature = feature(
         name = "default_link_flags",
@@ -159,7 +160,7 @@ def _impl(ctx):
             ),
             flag_set(
                 actions = all_cpp_compile_actions + [ACTION_NAMES.lto_backend],
-                flag_groups = [flag_group(flags = ["-std=c++0x"])],
+                flag_groups = [flag_group(flags = ["-std=c++17"])],
             ),
         ],
     )
@@ -224,7 +225,7 @@ def _impl(ctx):
         ],
     )
 
-    if cpu == "freebsd":
+    if is_bsd:
         features = [
             default_compile_flags_feature,
             default_link_flags_feature,
@@ -240,12 +241,12 @@ def _impl(ctx):
     else:
         features = [supports_dynamic_linker_feature, supports_pic_feature]
 
-    if (cpu == "freebsd"):
+    if (is_bsd):
         cxx_builtin_include_directories = ["/usr/lib/clang", "/usr/local/include", "/usr/include"]
     else:
         cxx_builtin_include_directories = []
 
-    if cpu == "freebsd":
+    if is_bsd:
         tool_paths = [
             tool_path(name = "ar", path = "/usr/bin/ar"),
             tool_path(name = "compat-ld", path = "/usr/bin/ld"),
diff --git a/cc/private/toolchain/cc_configure.bzl b/cc/private/toolchain/cc_configure.bzl
index c7b19de..ce0dac5 100644
--- a/cc/private/toolchain/cc_configure.bzl
+++ b/cc/private/toolchain/cc_configure.bzl
@@ -46,7 +46,6 @@ def cc_autoconf_toolchains_impl(repository_ctx):
 
 cc_autoconf_toolchains = repository_rule(
     environ = [
-        "BAZEL_USE_CPP_ONLY_TOOLCHAIN",
         "BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN",
     ],
     implementation = cc_autoconf_toolchains_impl,
@@ -65,24 +64,26 @@ def cc_autoconf_impl(repository_ctx, overriden_tools = dict()):
     cpu_value = get_cpu_value(repository_ctx)
     if "BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN" in env and env["BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN"] == "1":
         paths = resolve_labels(repository_ctx, [
-            "@rules_cc//cc/private/toolchain:BUILD.empty",
+            "@rules_cc//cc/private/toolchain:BUILD.empty.tpl",
             "@rules_cc//cc/private/toolchain:empty_cc_toolchain_config.bzl",
         ])
         repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:empty_cc_toolchain_config.bzl"], "cc_toolchain_config.bzl")
-        repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:BUILD.empty"], "BUILD")
-    elif cpu_value == "freebsd":
+        repository_ctx.template("BUILD", paths["@rules_cc//cc/private/toolchain:BUILD.empty.tpl"], {
+            "%{cpu}": get_cpu_value(repository_ctx),
+        })
+    elif cpu_value == "freebsd" or cpu_value == "openbsd":
         paths = resolve_labels(repository_ctx, [
-            "@rules_cc//cc/private/toolchain:BUILD.static.freebsd",
-            "@rules_cc//cc/private/toolchain:freebsd_cc_toolchain_config.bzl",
+            "@rules_cc//cc/private/toolchain:BUILD.static.bsd",
+            "@rules_cc//cc/private/toolchain:bsd_cc_toolchain_config.bzl",
         ])
 
-        # This is defaulting to a static crosstool, we should eventually
-        # autoconfigure this platform too.  Theorically, FreeBSD should be
-        # straightforward to add but we cannot run it in a docker container so
-        # skipping until we have proper tests for FreeBSD.
-        repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:freebsd_cc_toolchain_config.bzl"], "cc_toolchain_config.bzl")
-        repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:BUILD.static.freebsd"], "BUILD")
-    elif cpu_value == "x64_windows":
+        # This is defaulting to a static crosstool. We should eventually
+        # autoconfigure this platform too. Theoretically, FreeBSD and OpenBSD
+        # should be straightforward to add but we cannot run them in a Docker
+        # container so skipping until we have proper tests for these platforms.
+        repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:bsd_cc_toolchain_config.bzl"], "cc_toolchain_config.bzl")
+        repository_ctx.symlink(paths["@rules_cc//cc/private/toolchain:BUILD.static.bsd"], "BUILD")
+    elif cpu_value in ["x64_windows", "arm64_windows"]:
         # TODO(ibiryukov): overriden_tools are only supported in configure_unix_toolchain.
         # We might want to add that to Windows too(at least for msys toolchain).
         configure_windows_toolchain(repository_ctx)
@@ -111,16 +112,17 @@ cc_autoconf = repository_rule(
         "ABI_VERSION",
         "BAZEL_COMPILER",
         "BAZEL_HOST_SYSTEM",
+        "BAZEL_CONLYOPTS",
         "BAZEL_CXXOPTS",
         "BAZEL_LINKOPTS",
         "BAZEL_LINKLIBS",
+        "BAZEL_LLVM_COV",
+        "BAZEL_LLVM_PROFDATA",
         "BAZEL_PYTHON",
         "BAZEL_SH",
         "BAZEL_TARGET_CPU",
         "BAZEL_TARGET_LIBC",
         "BAZEL_TARGET_SYSTEM",
-        "BAZEL_USE_CPP_ONLY_TOOLCHAIN",
-        "BAZEL_USE_XCODE_TOOLCHAIN",
         "BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN",
         "BAZEL_USE_LLVM_NATIVE_COVERAGE",
         "BAZEL_LLVM",
@@ -130,9 +132,12 @@ cc_autoconf = repository_rule(
         "CC_CONFIGURE_DEBUG",
         "CC_TOOLCHAIN_NAME",
         "CPLUS_INCLUDE_PATH",
+        "DEVELOPER_DIR",
         "GCOV",
+        "LIBTOOL",
         "HOMEBREW_RUBY_PATH",
         "SYSTEMROOT",
+        "USER",
     ] + MSVC_ENVVARS,
     implementation = cc_autoconf_impl,
     configure = True,
diff --git a/cc/private/toolchain/clang_deps_scanner_wrapper.sh.tpl b/cc/private/toolchain/clang_deps_scanner_wrapper.sh.tpl
new file mode 100644
index 0000000..0bff014
--- /dev/null
+++ b/cc/private/toolchain/clang_deps_scanner_wrapper.sh.tpl
@@ -0,0 +1,11 @@
+#!/usr/bin/env bash
+#
+# Ship the environment to the C++ action
+#
+set -eu
+
+# Set-up the environment
+%{env}
+
+# Call the C++ compiler
+%{deps_scanner} -format=p1689 -- %{cc} "$@" >"$DEPS_SCANNER_OUTPUT_FILE"
diff --git a/cc/private/toolchain/clang_installation_error.bat.tpl b/cc/private/toolchain/clang_installation_error.bat.tpl
index e3a61a4..13668ae 100644
--- a/cc/private/toolchain/clang_installation_error.bat.tpl
+++ b/cc/private/toolchain/clang_installation_error.bat.tpl
@@ -18,7 +18,7 @@ echo. 1>&2
 echo The target you are compiling requires the Clang compiler. 1>&2
 echo Bazel couldn't find a valid Clang installation on your machine. 1>&2
 %{clang_error_message}
-echo Please check your installation following https://docs.bazel.build/versions/main/windows.html#using 1>&2
+echo Please check your installation following https://bazel.build/docs/windows#using 1>&2
 echo. 1>&2
 
 exit /b 1
diff --git a/cc/private/toolchain/gcc_deps_scanner_wrapper.sh.tpl b/cc/private/toolchain/gcc_deps_scanner_wrapper.sh.tpl
new file mode 100644
index 0000000..9436493
--- /dev/null
+++ b/cc/private/toolchain/gcc_deps_scanner_wrapper.sh.tpl
@@ -0,0 +1,12 @@
+#!/bin/bash
+#
+# Ship the environment to the C++ action
+#
+set -eu
+
+# Set-up the environment
+%{env}
+
+# Call the C++ compiler
+
+%{cc} -E -x c++ -fmodules-ts -fdeps-file=out.tmp -fdeps-format=p1689r5 "$@" >"$DEPS_SCANNER_OUTPUT_FILE"
diff --git a/cc/private/toolchain/generate_system_module_map.sh b/cc/private/toolchain/generate_system_module_map.sh
new file mode 100755
index 0000000..deb52c2
--- /dev/null
+++ b/cc/private/toolchain/generate_system_module_map.sh
@@ -0,0 +1,35 @@
+#!/bin/bash
+# Copyright 2020 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+set -eu
+
+echo 'module "crosstool" [system] {'
+
+if [[ "$OSTYPE" == darwin* ]]; then
+  for dir in $@; do
+    find "$dir" -type f \( -name "*.h" -o -name "*.def" -o -path "*/c++/*" \) \
+      | LANG=C sort -u | while read -r header; do
+        echo "  textual header \"${header}\""
+      done
+  done
+else
+  for dir in $@; do
+    find -L "${dir}" -type f 2>/dev/null | LANG=C sort -u | while read -r header; do
+      echo "  textual header \"${header}\""
+    done
+  done
+fi
+
+echo "}"
diff --git a/cc/private/toolchain/lib_cc_configure.bzl b/cc/private/toolchain/lib_cc_configure.bzl
index bcd9013..975dd44 100644
--- a/cc/private/toolchain/lib_cc_configure.bzl
+++ b/cc/private/toolchain/lib_cc_configure.bzl
@@ -51,7 +51,7 @@ def split_escaped(string, delimiter):
       Basic usage:
         split_escaped("a:b:c", ":") -> [ "a", "b", "c" ]
 
-      Delimeter that is not supposed to be splitten on has to be %-escaped:
+      Delimiter that is not supposed to be splitten on has to be %-escaped:
         split_escaped("a%:b", ":") -> [ "a:b" ]
 
       Literal % can be represented by escaping it as %%:
@@ -137,7 +137,8 @@ def get_env_var(repository_ctx, name, default = None, enable_warning = True):
         if enable_warning:
             auto_configure_warning("'%s' environment variable is not set, using '%s' as default" % (name, default))
         return default
-    return auto_configure_fail("'%s' environment variable is not set" % name)
+    auto_configure_fail("'%s' environment variable is not set" % name)
+    return None
 
 def which(repository_ctx, cmd, default = None):
     """A wrapper around repository_ctx.which() to provide a fallback value. Doesn't %-escape the value!
@@ -176,7 +177,8 @@ def execute(
         repository_ctx,
         command,
         environment = None,
-        expect_failure = False):
+        expect_failure = False,
+        expect_empty_output = False):
     """Execute a command, return stdout if succeed and throw an error if it fails. Doesn't %-escape the result!
 
     Args:
@@ -184,6 +186,7 @@ def execute(
       command: command to execute.
       environment: dictionary with environment variables to set for the command.
       expect_failure: True if the command is expected to fail.
+      expect_empty_output: True if the command is expected to produce no output.
     Returns:
       stdout of the executed command.
     """
@@ -208,10 +211,15 @@ def execute(
                 ),
             )
     stripped_stdout = result.stdout.strip()
-    if not stripped_stdout:
-        auto_configure_fail(
-            "empty output from command %s, stderr: (%s)" % (command, result.stderr),
-        )
+    if expect_empty_output != (not stripped_stdout):
+        if expect_empty_output:
+            auto_configure_fail(
+                "non-empty output from command %s, stdout: (%s), stderr: (%s)" % (command, result.stdout, result.stderr),
+            )
+        else:
+            auto_configure_fail(
+                "empty output from command %s, stderr: (%s)" % (command, result.stderr),
+            )
     return stripped_stdout
 
 def get_cpu_value(repository_ctx):
@@ -222,25 +230,34 @@ def get_cpu_value(repository_ctx):
     Returns:
       One of (darwin, freebsd, x64_windows, ppc, s390x, arm, aarch64, k8, piii)
     """
-    os_name = repository_ctx.os.name.lower()
+    os_name = repository_ctx.os.name
+    arch = repository_ctx.os.arch
     if os_name.startswith("mac os"):
-        return "darwin"
+        # Check if we are on x86_64 or arm64 and return the corresponding cpu value.
+        return "darwin_" + ("arm64" if arch == "aarch64" else "x86_64")
     if os_name.find("freebsd") != -1:
         return "freebsd"
+    if os_name.find("openbsd") != -1:
+        return "openbsd"
     if os_name.find("windows") != -1:
-        return "x64_windows"
+        if arch == "aarch64":
+            return "arm64_windows"
+        else:
+            return "x64_windows"
 
-    # Use uname to figure out whether we are on x86_32 or x86_64
-    result = repository_ctx.execute(["uname", "-m"])
-    if result.stdout.strip() in ["power", "ppc64le", "ppc", "ppc64"]:
+    if arch in ["power", "ppc64le", "ppc", "ppc64"]:
         return "ppc"
-    if result.stdout.strip() in ["s390x"]:
+    if arch in ["s390x"]:
         return "s390x"
-    if result.stdout.strip() in ["arm", "armv7l"]:
+    if arch in ["mips64"]:
+        return "mips64"
+    if arch in ["riscv64"]:
+        return "riscv64"
+    if arch in ["arm", "armv7l"]:
         return "arm"
-    if result.stdout.strip() in ["aarch64"]:
+    if arch in ["aarch64"]:
         return "aarch64"
-    return "k8" if result.stdout.strip() in ["amd64", "x86_64", "x64"] else "piii"
+    return "k8" if arch in ["amd64", "x86_64", "x64"] else "piii"
 
 def is_cc_configure_debug(repository_ctx):
     """Returns True if CC_CONFIGURE_DEBUG is set to 1."""
diff --git a/cc/private/toolchain/linux_cc_wrapper.sh.tpl b/cc/private/toolchain/linux_cc_wrapper.sh.tpl
index a83be50..629741e 100644
--- a/cc/private/toolchain/linux_cc_wrapper.sh.tpl
+++ b/cc/private/toolchain/linux_cc_wrapper.sh.tpl
@@ -18,8 +18,37 @@
 #
 set -eu
 
+OUTPUT=
+
+function parse_option() {
+    local -r opt="$1"
+    if [[ "${OUTPUT}" = "1" ]]; then
+        OUTPUT=$opt
+    elif [[ "$opt" = "-o" ]]; then
+        # output is coming
+        OUTPUT=1
+    fi
+}
+
+# let parse the option list
+for i in "$@"; do
+    if [[ "$i" = @* && -r "${i:1}" ]]; then
+        while IFS= read -r opt
+        do
+            parse_option "$opt"
+        done < "${i:1}" || exit 1
+    else
+        parse_option "$i"
+    fi
+done
+
 # Set-up the environment
 %{env}
 
 # Call the C++ compiler
 %{cc} "$@"
+
+# Generate an empty file if header processing succeeded.
+if [[ "${OUTPUT}" == *.h.processed ]]; then
+  echo -n > "${OUTPUT}"
+fi
diff --git a/cc/private/toolchain/msvc_deps_scanner_wrapper.bat.tpl b/cc/private/toolchain/msvc_deps_scanner_wrapper.bat.tpl
new file mode 100644
index 0000000..2c6200f
--- /dev/null
+++ b/cc/private/toolchain/msvc_deps_scanner_wrapper.bat.tpl
@@ -0,0 +1,16 @@
+:: Copyright 2024 The Bazel Authors. All rights reserved.
+::
+:: Licensed under the Apache License, Version 2.0 (the "License");
+:: you may not use this file except in compliance with the License.
+:: You may obtain a copy of the License at
+::
+::    http://www.apache.org/licenses/LICENSE-2.0
+::
+:: Unless required by applicable law or agreed to in writing, software
+:: distributed under the License is distributed on an "AS IS" BASIS,
+:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+:: See the License for the specific language governing permissions and
+:: limitations under the License.
+
+@echo OFF
+"%{cc}" /scanDependencies- /TP %* >%DEPS_SCANNER_OUTPUT_FILE%
diff --git a/cc/private/toolchain/osx_cc_wrapper.sh.tpl b/cc/private/toolchain/osx_cc_wrapper.sh.tpl
index 28bd47b..e40a98b 100644
--- a/cc/private/toolchain/osx_cc_wrapper.sh.tpl
+++ b/cc/private/toolchain/osx_cc_wrapper.sh.tpl
@@ -27,9 +27,8 @@
 #
 set -eu
 
-INSTALL_NAME_TOOL="/usr/bin/install_name_tool"
-
 LIBS=
+LIB_PATHS=
 LIB_DIRS=
 RPATHS=
 OUTPUT=
@@ -40,9 +39,13 @@ function parse_option() {
         OUTPUT=$opt
     elif [[ "$opt" =~ ^-l(.*)$ ]]; then
         LIBS="${BASH_REMATCH[1]} $LIBS"
+    elif [[ "$opt" =~ ^(.*)\.so$ ]]; then
+        LIB_PATHS="${opt} $LIB_PATHS"
+    elif [[ "$opt" =~ ^(.*)\.dylib$ ]]; then
+        LIB_PATHS="${opt} $LIB_PATHS"
     elif [[ "$opt" =~ ^-L(.*)$ ]]; then
         LIB_DIRS="${BASH_REMATCH[1]} $LIB_DIRS"
-    elif [[ "$opt" =~ ^-Wl,-rpath,\@loader_path/(.*)$ ]]; then
+    elif [[ "$opt" =~ ^\@loader_path/(.*)$ ]]; then
         RPATHS="${BASH_REMATCH[1]} ${RPATHS}"
     elif [[ "$opt" = "-o" ]]; then
         # output is coming
@@ -52,7 +55,7 @@ function parse_option() {
 
 # let parse the option list
 for i in "$@"; do
-    if [[ "$i" = @* ]]; then
+    if [[ "$i" = @* && -r "${i:1}" ]]; then
         while IFS= read -r opt
         do
             parse_option "$opt"
@@ -68,6 +71,11 @@ done
 # Call the C++ compiler
 %{cc} "$@"
 
+# Generate an empty file if header processing succeeded.
+if [[ "${OUTPUT}" == *.h.processed ]]; then
+  echo -n > "${OUTPUT}"
+fi
+
 function get_library_path() {
     for libdir in ${LIB_DIRS}; do
         if [ -f ${libdir}/lib$1.so ]; then
@@ -96,6 +104,11 @@ function get_otool_path() {
     get_realpath $1 | sed 's|^.*/bazel-out/|bazel-out/|'
 }
 
+function call_install_name() {
+    /usr/bin/xcrun install_name_tool -change $(get_otool_path "$1") \
+        "@loader_path/$2/$3" "${OUTPUT}"
+}
+
 # Do replacements in the output
 for rpath in ${RPATHS}; do
     for lib in ${LIBS}; do
@@ -110,10 +123,16 @@ for rpath in ${RPATHS}; do
         if [[ -n "${libname-}" ]]; then
             libpath=$(get_library_path ${lib})
             if [ -n "${libpath}" ]; then
-                ${INSTALL_NAME_TOOL} -change $(get_otool_path "${libpath}") \
-                    "@loader_path/${rpath}/${libname}" "${OUTPUT}"
+                call_install_name "${libpath}" "${rpath}" "${libname}"
+            fi
+        fi
+    done
+    for libpath in ${LIB_PATHS}; do
+        if [ -f "$libpath" ]; then
+            libname=$(basename "$libpath")
+            if [ -f "$(dirname ${OUTPUT})/${rpath}/${libname}" ]; then
+                call_install_name "${libpath}" "${rpath}" "${libname}"
             fi
         fi
     done
 done
-
diff --git a/cc/private/toolchain/unix_cc_configure.bzl b/cc/private/toolchain/unix_cc_configure.bzl
index 0c936de..6a6f38a 100644
--- a/cc/private/toolchain/unix_cc_configure.bzl
+++ b/cc/private/toolchain/unix_cc_configure.bzl
@@ -20,6 +20,7 @@ load(
     "auto_configure_warning",
     "auto_configure_warning_maybe",
     "escape_string",
+    "execute",
     "get_env_var",
     "get_starlark_list",
     "resolve_labels",
@@ -34,16 +35,19 @@ def _uniq(iterable):
     unique_elements = {element: None for element in iterable}
     return unique_elements.keys()
 
+def _generate_system_module_map(repository_ctx, dirs, script_path):
+    return execute(repository_ctx, [script_path] + dirs)
+
 def _prepare_include_path(repo_ctx, path):
-    """Resolve and sanitize include path before outputting it into the crosstool.
+    """Resolve include path before outputting it into the crosstool.
 
     Args:
       repo_ctx: repository_ctx object.
-      path: an include path to be sanitized.
+      path: an include path to be resolved.
 
     Returns:
-      Sanitized include path that can be written to the crosstoot. Resulting path
-      is absolute if it is outside the repository and relative otherwise.
+      Resolved include path. Resulting path is absolute if it is outside the
+      repository and relative otherwise.
     """
 
     repo_root = str(repo_ctx.path("."))
@@ -52,22 +56,24 @@ def _prepare_include_path(repo_ctx, path):
     repo_root += "/"
     path = str(repo_ctx.path(path))
     if path.startswith(repo_root):
-        return escape_string(path[len(repo_root):])
-    return escape_string(path)
+        return path[len(repo_root):]
+    return path
 
-def _find_tool(repository_ctx, tool, overriden_tools):
-    """Find a tool for repository, taking overriden tools into account."""
-    if tool in overriden_tools:
-        return overriden_tools[tool]
+def _find_tool(repository_ctx, tool, overridden_tools):
+    """Find a tool for repository, taking overridden tools into account."""
+    if tool in overridden_tools:
+        return overridden_tools[tool]
     return which(repository_ctx, tool, "/usr/bin/" + tool)
 
-def _get_tool_paths(repository_ctx, overriden_tools):
+def _get_tool_paths(repository_ctx, overridden_tools):
     """Compute the %-escaped path to the various tools"""
     return dict({
-        k: escape_string(_find_tool(repository_ctx, k, overriden_tools))
+        k: escape_string(_find_tool(repository_ctx, k, overridden_tools))
         for k in [
             "ar",
             "ld",
+            "llvm-cov",
+            "llvm-profdata",
             "cpp",
             "gcc",
             "dwp",
@@ -76,6 +82,7 @@ def _get_tool_paths(repository_ctx, overriden_tools):
             "objcopy",
             "objdump",
             "strip",
+            "c++filt",
         ]
     }.items())
 
@@ -103,17 +110,8 @@ def _cxx_inc_convert(path):
         path = path[:-_OSX_FRAMEWORK_SUFFIX_LEN].strip()
     return path
 
-def get_escaped_cxx_inc_directories(repository_ctx, cc, lang_flag, additional_flags = []):
-    """Compute the list of default %-escaped C++ include directories.
-
-    Args:
-      repository_ctx: The repository context.
-      cc: path to the C compiler.
-      lang_flag: value for the language flag (c, c++).
-      additional_flags: additional flags to pass to cc.
-    Returns:
-      a list of escaped system include directories.
-    """
+def _get_cxx_include_directories(repository_ctx, print_resource_dir_supported, cc, lang_flag, additional_flags = []):
+    """Compute the list of C++ include directories."""
     result = repository_ctx.execute([cc, "-E", lang_flag, "-", "-v"] + additional_flags)
     index1 = result.stderr.find(_INC_DIR_MARKER_BEGIN)
     if index1 == -1:
@@ -135,9 +133,9 @@ def get_escaped_cxx_inc_directories(repository_ctx, cc, lang_flag, additional_fl
         for p in inc_dirs.split("\n")
     ]
 
-    if _is_compiler_option_supported(repository_ctx, cc, "-print-resource-dir"):
+    if print_resource_dir_supported:
         resource_dir = repository_ctx.execute(
-            [cc, "-print-resource-dir"],
+            [cc, "-print-resource-dir"] + additional_flags,
         ).stdout.strip() + "/share"
         inc_directories.append(_prepare_include_path(repository_ctx, resource_dir))
 
@@ -155,10 +153,9 @@ def _is_compiler_option_supported(repository_ctx, cc, option):
     ])
     return result.stderr.find(option) == -1
 
-def _is_linker_option_supported(repository_ctx, cc, option, pattern):
+def _is_linker_option_supported(repository_ctx, cc, force_linker_flags, option, pattern):
     """Checks that `option` is supported by the C linker. Doesn't %-escape the option."""
-    result = repository_ctx.execute([
-        cc,
+    result = repository_ctx.execute([cc] + force_linker_flags + [
         option,
         "-o",
         "/dev/null",
@@ -166,63 +163,50 @@ def _is_linker_option_supported(repository_ctx, cc, option, pattern):
     ])
     return result.stderr.find(pattern) == -1
 
-def _find_gold_linker_path(repository_ctx, cc):
-    """Checks if `gold` is supported by the C compiler.
+def _find_linker_path(repository_ctx, cc, linker, is_clang):
+    """Checks if a given linker is supported by the C compiler.
 
     Args:
       repository_ctx: repository_ctx.
       cc: path to the C compiler.
+      linker: linker to find
+      is_clang: whether the compiler is known to be clang
 
     Returns:
-      String to put as value to -fuse-ld= flag, or None if gold couldn't be found.
+      String to put as value to -fuse-ld= flag, or None if linker couldn't be found.
     """
     result = repository_ctx.execute([
         cc,
         str(repository_ctx.path("tools/cpp/empty.cc")),
         "-o",
         "/dev/null",
-        # Some macos clang versions don't fail when setting -fuse-ld=gold, adding
+        # Some macOS clang versions don't fail when setting -fuse-ld=gold, adding
         # these lines to force it to. This also means that we will not detect
         # gold when only a very old (year 2010 and older) is present.
         "-Wl,--start-lib",
         "-Wl,--end-lib",
-        "-fuse-ld=gold",
+        "-fuse-ld=" + linker,
         "-v",
     ])
     if result.return_code != 0:
         return None
 
-    for line in result.stderr.splitlines():
-        if line.find("gold") == -1:
-            continue
-        for flag in line.split(" "):
-            if flag.find("gold") == -1:
-                continue
-            if flag.find("--enable-gold") > -1 or flag.find("--with-plugin-ld") > -1:
-                # skip build configuration options of gcc itself
-                # TODO(hlopko): Add redhat-like worker on the CI (#9392)
-                continue
-
-            # flag is '-fuse-ld=gold' for GCC or "/usr/lib/ld.gold" for Clang
-            # strip space, single quote, and double quotes
-            flag = flag.strip(" \"'")
-
-            # remove -fuse-ld= from GCC output so we have only the flag value part
-            flag = flag.replace("-fuse-ld=", "")
-            return flag
-    auto_configure_warning(
-        "CC with -fuse-ld=gold returned 0, but its -v output " +
-        "didn't contain 'gold', falling back to the default linker.",
-    )
-    return None
+    if not is_clang:
+        return linker
+
+    # Extract linker path from:
+    # /usr/bin/clang ...
+    # "/usr/bin/ld.lld" -pie -z ...
+    linker_command = result.stderr.splitlines()[-1]
+    return linker_command.strip().split(" ")[0].strip("\"'")
 
 def _add_compiler_option_if_supported(repository_ctx, cc, option):
     """Returns `[option]` if supported, `[]` otherwise. Doesn't %-escape the option."""
     return [option] if _is_compiler_option_supported(repository_ctx, cc, option) else []
 
-def _add_linker_option_if_supported(repository_ctx, cc, option, pattern):
+def _add_linker_option_if_supported(repository_ctx, cc, force_linker_flags, option, pattern):
     """Returns `[option]` if supported, `[]` otherwise. Doesn't %-escape the option."""
-    return [option] if _is_linker_option_supported(repository_ctx, cc, option, pattern) else []
+    return [option] if _is_linker_option_supported(repository_ctx, cc, force_linker_flags, option, pattern) else []
 
 def _get_no_canonical_prefixes_opt(repository_ctx, cc):
     # If the compiler sometimes rewrites paths in the .d files without symlinks
@@ -280,11 +264,27 @@ def _coverage_flags(repository_ctx, darwin):
         link_flags = '"--coverage"'
     return compile_flags, link_flags
 
-def _find_generic(repository_ctx, name, env_name, overriden_tools, warn = False, silent = False):
+def _is_clang(repository_ctx, cc):
+    return "clang" in repository_ctx.execute([cc, "-v"]).stderr
+
+def _is_gcc(repository_ctx, cc):
+    # GCC's version output uses the basename of argv[0] as the program name:
+    # https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=gcc/gcc.cc;h=158461167951c1b9540322fb19be6a89d6da07fc;hb=HEAD#l8728
+    cc_stdout = repository_ctx.execute([cc, "--version"]).stdout
+    return cc_stdout.startswith("gcc ") or cc_stdout.startswith("gcc-")
+
+def _get_compiler_name(repository_ctx, cc):
+    if _is_clang(repository_ctx, cc):
+        return "clang"
+    if _is_gcc(repository_ctx, cc):
+        return "gcc"
+    return "compiler"
+
+def _find_generic(repository_ctx, name, env_name, overridden_tools, warn = False, silent = False):
     """Find a generic C++ toolchain tool. Doesn't %-escape the result."""
 
-    if name in overriden_tools:
-        return overriden_tools[name]
+    if name in overridden_tools:
+        return overridden_tools[name]
 
     result = name
     env_value = repository_ctx.os.environ.get(env_name)
@@ -295,7 +295,7 @@ def _find_generic(repository_ctx, name, env_name, overriden_tools, warn = False,
             result = env_value
             env_value_with_paren = " (%s)" % env_value
     if result.startswith("/"):
-        # Absolute path, maybe we should make this suported by our which function.
+        # Absolute path, maybe we should make this supported by our which function.
         return result
     result = repository_ctx.which(result)
     if result == None:
@@ -308,23 +308,44 @@ def _find_generic(repository_ctx, name, env_name, overriden_tools, warn = False,
             auto_configure_fail(msg)
     return result
 
-def find_cc(repository_ctx, overriden_tools):
-    return _find_generic(repository_ctx, "gcc", "CC", overriden_tools)
+def find_cc(repository_ctx, overridden_tools):
+    """Find the C compiler (gcc or clang) for the repository, considering overridden tools.
+
+    Args:
+      repository_ctx: The repository context.
+      overridden_tools: A dictionary of overridden tools.
 
-def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
+    Returns:
+      The path to the C compiler.
+    """
+    cc = _find_generic(repository_ctx, "gcc", "CC", overridden_tools)
+    if _is_clang(repository_ctx, cc):
+        # If clang is run through a symlink with -no-canonical-prefixes, it does
+        # not find its own include directory, which includes the headers for
+        # libc++. Resolving the potential symlink here prevents this.
+        result = repository_ctx.execute(["readlink", "-f", cc])
+        if result.return_code == 0:
+            return result.stdout.strip()
+    return cc
+
+def configure_unix_toolchain(repository_ctx, cpu_value, overridden_tools):
     """Configure C++ toolchain on Unix platforms.
 
     Args:
-      repository_ctx: The repository context.
-      cpu_value: current cpu name.
-      overriden_tools: overriden tools.
+        repository_ctx: The repository context.
+        cpu_value: The CPU value.
+        overridden_tools: A dictionary of overridden tools.
     """
     paths = resolve_labels(repository_ctx, [
         "@rules_cc//cc/private/toolchain:BUILD.tpl",
+        "@rules_cc//cc/private/toolchain:generate_system_module_map.sh",
         "@rules_cc//cc/private/toolchain:armeabi_cc_toolchain_config.bzl",
         "@rules_cc//cc/private/toolchain:unix_cc_toolchain_config.bzl",
         "@rules_cc//cc/private/toolchain:linux_cc_wrapper.sh.tpl",
+        "@rules_cc//cc/private/toolchain:validate_static_library.sh.tpl",
         "@rules_cc//cc/private/toolchain:osx_cc_wrapper.sh.tpl",
+        "@rules_cc//cc/private/toolchain:clang_deps_scanner_wrapper.sh.tpl",
+        "@rules_cc//cc/private/toolchain:gcc_deps_scanner_wrapper.sh.tpl",
     ])
 
     repository_ctx.symlink(
@@ -338,24 +359,56 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
     )
 
     repository_ctx.file("tools/cpp/empty.cc", "int main() {}")
-    darwin = cpu_value == "darwin"
-
-    cc = _find_generic(repository_ctx, "gcc", "CC", overriden_tools)
-    overriden_tools = dict(overriden_tools)
-    overriden_tools["gcc"] = cc
-    overriden_tools["gcov"] = _find_generic(
+    darwin = cpu_value.startswith("darwin")
+    bsd = cpu_value == "freebsd" or cpu_value == "openbsd"
+
+    cc = find_cc(repository_ctx, overridden_tools)
+    is_clang = _is_clang(repository_ctx, cc)
+    overridden_tools = dict(overridden_tools)
+    overridden_tools["gcc"] = cc
+    overridden_tools["gcov"] = _find_generic(
         repository_ctx,
         "gcov",
         "GCOV",
-        overriden_tools,
+        overridden_tools,
+        warn = True,
+        silent = True,
+    )
+    overridden_tools["llvm-cov"] = _find_generic(
+        repository_ctx,
+        "llvm-cov",
+        "BAZEL_LLVM_COV",
+        overridden_tools,
+        warn = True,
+        silent = True,
+    )
+    overridden_tools["llvm-profdata"] = _find_generic(
+        repository_ctx,
+        "llvm-profdata",
+        "BAZEL_LLVM_PROFDATA",
+        overridden_tools,
+        warn = True,
+        silent = True,
+    )
+    overridden_tools["ar"] = _find_generic(
+        repository_ctx,
+        "ar",
+        "AR",
+        overridden_tools,
         warn = True,
         silent = True,
     )
     if darwin:
-        overriden_tools["gcc"] = "cc_wrapper.sh"
-        overriden_tools["ar"] = "/usr/bin/libtool"
+        overridden_tools["gcc"] = "cc_wrapper.sh"
+        overridden_tools["ar"] = _find_generic(repository_ctx, "libtool", "LIBTOOL", overridden_tools)
+
     auto_configure_warning_maybe(repository_ctx, "CC used: " + str(cc))
-    tool_paths = _get_tool_paths(repository_ctx, overriden_tools)
+    tool_paths = _get_tool_paths(repository_ctx, overridden_tools)
+    tool_paths["cpp-module-deps-scanner"] = "deps_scanner_wrapper.sh"
+
+    # The parse_header tool needs to be a wrapper around the compiler as it has
+    # to touch the output file.
+    tool_paths["parse_headers"] = "cc_wrapper.sh"
     cc_toolchain_identifier = escape_string(get_env_var(
         repository_ctx,
         "CC_TOOLCHAIN_NAME",
@@ -363,6 +416,19 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
         False,
     ))
 
+    if "nm" in tool_paths and "c++filt" in tool_paths:
+        repository_ctx.template(
+            "validate_static_library.sh",
+            paths["@rules_cc//cc/private/toolchain:validate_static_library.sh.tpl"],
+            {
+                "%{c++filt}": escape_string(str(repository_ctx.path(tool_paths["c++filt"]))),
+                # Certain weak symbols are otherwise listed with type T in the output of nm on macOS.
+                "%{nm_extra_args}": "--no-weak" if darwin else "",
+                "%{nm}": escape_string(str(repository_ctx.path(tool_paths["nm"]))),
+            },
+        )
+        tool_paths["validate_static_library"] = "validate_static_library.sh"
+
     cc_wrapper_src = (
         "@rules_cc//cc/private/toolchain:osx_cc_wrapper.sh.tpl" if darwin else "@rules_cc//cc/private/toolchain:linux_cc_wrapper.sh.tpl"
     )
@@ -374,16 +440,94 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
             "%{env}": escape_string(get_env(repository_ctx)),
         },
     )
+    deps_scanner_wrapper_src = (
+        "@rules_cc//cc/private/toolchain:clang_deps_scanner_wrapper.sh.tpl" if is_clang else "@rules_cc//cc/private/toolchain:gcc_deps_scanner_wrapper.sh.tpl"
+    )
+    deps_scanner = "cpp-module-deps-scanner_not_found"
+    if is_clang:
+        cc_str = str(cc)
+        path_arr = cc_str.split("/")[:-1]
+        path_arr.append("clang-scan-deps")
+        deps_scanner = "/".join(path_arr)
+    repository_ctx.template(
+        "deps_scanner_wrapper.sh",
+        paths[deps_scanner_wrapper_src],
+        {
+            "%{cc}": escape_string(str(cc)),
+            "%{deps_scanner}": escape_string(deps_scanner),
+            "%{env}": escape_string(get_env(repository_ctx)),
+        },
+    )
+
+    conly_opts = split_escaped(get_env_var(
+        repository_ctx,
+        "BAZEL_CONLYOPTS",
+        "",
+        False,
+    ), ":")
 
     cxx_opts = split_escaped(get_env_var(
         repository_ctx,
         "BAZEL_CXXOPTS",
-        "-std=c++0x",
+        "-std=c++17",
         False,
     ), ":")
 
-    bazel_linklibs = "-lstdc++:-lm"
+    gold_or_lld_linker_path = (
+        _find_linker_path(repository_ctx, cc, "lld", is_clang) or
+        _find_linker_path(repository_ctx, cc, "gold", is_clang)
+    )
+    cc_path = repository_ctx.path(cc)
+    if not str(cc_path).startswith(str(repository_ctx.path(".")) + "/"):
+        # cc is outside the repository, set -B
+        bin_search_flags = ["-B" + escape_string(str(cc_path.dirname))]
+    else:
+        # cc is inside the repository, don't set -B.
+        bin_search_flags = []
+    if not gold_or_lld_linker_path:
+        ld_path = repository_ctx.path(tool_paths["ld"])
+        if ld_path.dirname != cc_path.dirname:
+            bin_search_flags.append("-B" + str(ld_path.dirname))
+    force_linker_flags = []
+    if gold_or_lld_linker_path:
+        force_linker_flags.append("-fuse-ld=" + gold_or_lld_linker_path)
+
+    # TODO: It's unclear why these flags aren't added on macOS.
+    if bin_search_flags and not darwin:
+        force_linker_flags.extend(bin_search_flags)
+    use_libcpp = darwin or bsd
+    is_as_needed_supported = _is_linker_option_supported(
+        repository_ctx,
+        cc,
+        force_linker_flags,
+        "-Wl,-no-as-needed",
+        "-no-as-needed",
+    )
+    is_push_state_supported = _is_linker_option_supported(
+        repository_ctx,
+        cc,
+        force_linker_flags,
+        "-Wl,--push-state",
+        "--push-state",
+    )
+    if use_libcpp:
+        bazel_default_libs = ["-lc++", "-lm"]
+    else:
+        bazel_default_libs = ["-lstdc++", "-lm"]
+    if is_as_needed_supported and is_push_state_supported:
+        # Do not link against C++ standard libraries unless they are actually
+        # used.
+        # We assume that --push-state support implies --pop-state support.
+        bazel_linklibs_elements = [
+            arg
+            for lib in bazel_default_libs
+            for arg in ["-Wl,--push-state,-as-needed", lib, "-Wl,--pop-state"]
+        ]
+    else:
+        bazel_linklibs_elements = bazel_default_libs
+    bazel_linklibs = ":".join(bazel_linklibs_elements)
     bazel_linkopts = ""
+
     link_opts = split_escaped(get_env_var(
         repository_ctx,
         "BAZEL_LINKOPTS",
@@ -396,37 +540,78 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
         bazel_linklibs,
         False,
     ), ":")
-    gold_linker_path = _find_gold_linker_path(repository_ctx, cc)
-    cc_path = repository_ctx.path(cc)
-    if not str(cc_path).startswith(str(repository_ctx.path(".")) + "/"):
-        # cc is outside the repository, set -B
-        bin_search_flag = ["-B" + escape_string(str(cc_path.dirname))]
-    else:
-        # cc is inside the repository, don't set -B.
-        bin_search_flag = []
-
     coverage_compile_flags, coverage_link_flags = _coverage_flags(repository_ctx, darwin)
+    print_resource_dir_supported = _is_compiler_option_supported(
+        repository_ctx,
+        cc,
+        "-print-resource-dir",
+    )
+    no_canonical_prefixes_opt = _get_no_canonical_prefixes_opt(repository_ctx, cc)
     builtin_include_directories = _uniq(
-        get_escaped_cxx_inc_directories(repository_ctx, cc, "-xc") +
-        get_escaped_cxx_inc_directories(repository_ctx, cc, "-xc++", cxx_opts) +
-        get_escaped_cxx_inc_directories(
+        _get_cxx_include_directories(repository_ctx, print_resource_dir_supported, cc, "-xc", conly_opts) +
+        _get_cxx_include_directories(repository_ctx, print_resource_dir_supported, cc, "-xc++", cxx_opts) +
+        _get_cxx_include_directories(
             repository_ctx,
+            print_resource_dir_supported,
+            cc,
+            "-xc++",
+            cxx_opts + ["-stdlib=libc++"],
+        ) +
+        _get_cxx_include_directories(
+            repository_ctx,
+            print_resource_dir_supported,
             cc,
             "-xc",
-            _get_no_canonical_prefixes_opt(repository_ctx, cc),
+            no_canonical_prefixes_opt,
+        ) +
+        _get_cxx_include_directories(
+            repository_ctx,
+            print_resource_dir_supported,
+            cc,
+            "-xc++",
+            cxx_opts + no_canonical_prefixes_opt,
         ) +
-        get_escaped_cxx_inc_directories(
+        _get_cxx_include_directories(
             repository_ctx,
+            print_resource_dir_supported,
             cc,
             "-xc++",
-            cxx_opts + _get_no_canonical_prefixes_opt(repository_ctx, cc),
-        ),
+            cxx_opts + no_canonical_prefixes_opt + ["-stdlib=libc++"],
+        ) +
+        # Always included in case the user has Xcode + the CLT installed, both
+        # paths can be used interchangeably
+        ["/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"],
     )
 
+    generate_modulemap = is_clang
+    if generate_modulemap:
+        repository_ctx.file("module.modulemap", _generate_system_module_map(
+            repository_ctx,
+            builtin_include_directories,
+            paths["@rules_cc//cc/private/toolchain:generate_system_module_map.sh"],
+        ))
+    extra_flags_per_feature = {}
+    if is_clang:
+        # Only supported by LLVM 14 and later, but required with C++20 and
+        # layering_check as C++ modules are the default.
+        # https://github.com/llvm/llvm-project/commit/0556138624edf48621dd49a463dbe12e7101f17d
+        result = repository_ctx.execute([
+            cc,
+            "-Xclang",
+            "-fno-cxx-modules",
+            "-o",
+            "/dev/null",
+            "-c",
+            str(repository_ctx.path("tools/cpp/empty.cc")),
+        ])
+        if "-fno-cxx-modules" not in result.stderr:
+            extra_flags_per_feature["use_module_maps"] = ["-Xclang", "-fno-cxx-modules"]
+
     write_builtin_include_directory_paths(repository_ctx, cc, builtin_include_directories)
     repository_ctx.template(
         "BUILD",
         paths["@rules_cc//cc/private/toolchain:BUILD.tpl"],
+        # @unsorted-dict-items
         {
             "%{abi_libc_version}": escape_string(get_env_var(
                 repository_ctx,
@@ -440,23 +625,24 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
                 "local",
                 False,
             )),
-            "%{cc_compiler_deps}": get_starlark_list([":builtin_include_directory_paths"] + (
-                [":cc_wrapper"] if darwin else []
+            "%{cc_compiler_deps}": get_starlark_list([
+                ":builtin_include_directory_paths",
+                ":cc_wrapper",
+                ":deps_scanner_wrapper",
+            ] + (
+                [":validate_static_library"] if "validate_static_library" in tool_paths else []
             )),
             "%{cc_toolchain_identifier}": cc_toolchain_identifier,
             "%{compile_flags}": get_starlark_list(
                 [
-                    # Security hardening requires optimization.
-                    # We need to undef it as some distributions now have it enabled by default.
-                    "-U_FORTIFY_SOURCE",
                     "-fstack-protector",
-                    # All warnings are enabled. Maybe enable -Werror as well?
+                    # All warnings are enabled.
                     "-Wall",
                     # Enable a few more warnings that aren't part of -Wall.
-                ] + (
+                ] + ((
                     _add_compiler_option_if_supported(repository_ctx, cc, "-Wthread-safety") +
                     _add_compiler_option_if_supported(repository_ctx, cc, "-Wself-assign")
-                ) + (
+                )) + (
                     # Disable problematic warnings.
                     _add_compiler_option_if_supported(repository_ctx, cc, "-Wunused-but-set-parameter") +
                     # has false positives
@@ -472,38 +658,34 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
             "%{compiler}": escape_string(get_env_var(
                 repository_ctx,
                 "BAZEL_COMPILER",
-                "compiler",
+                _get_compiler_name(repository_ctx, cc),
                 False,
             )),
+            "%{conly_flags}": get_starlark_list(conly_opts),
             "%{coverage_compile_flags}": coverage_compile_flags,
             "%{coverage_link_flags}": coverage_link_flags,
             "%{cxx_builtin_include_directories}": get_starlark_list(builtin_include_directories),
             "%{cxx_flags}": get_starlark_list(cxx_opts + _escaped_cplus_include_paths(repository_ctx)),
             "%{dbg_compile_flags}": get_starlark_list(["-g"]),
+            "%{extra_flags_per_feature}": repr(extra_flags_per_feature),
             "%{host_system_name}": escape_string(get_env_var(
                 repository_ctx,
                 "BAZEL_HOST_SYSTEM",
                 "local",
                 False,
             )),
-            "%{link_flags}": get_starlark_list((
-                ["-fuse-ld=" + gold_linker_path] if gold_linker_path else []
-            ) + _add_linker_option_if_supported(
-                repository_ctx,
-                cc,
-                "-Wl,-no-as-needed",
-                "-no-as-needed",
+            "%{link_flags}": get_starlark_list(force_linker_flags + (
+                ["-Wl,-no-as-needed"] if is_as_needed_supported else []
             ) + _add_linker_option_if_supported(
                 repository_ctx,
                 cc,
+                force_linker_flags,
                 "-Wl,-z,relro,-z,now",
                 "-z",
             ) + (
                 [
-                    "-undefined",
-                    "dynamic_lookup",
                     "-headerpad_max_install_names",
-                ] if darwin else bin_search_flag + [
+                ] if darwin else [
                     # Gold linker only? Can we enable this by default?
                     # "-Wl,--warn-execstack",
                     # "-Wl,--detect-odr-violations"
@@ -515,6 +697,7 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
                 )
             ) + link_opts),
             "%{link_libs}": get_starlark_list(link_libs),
+            "%{modulemap}": ("\":module.modulemap\"" if generate_modulemap else "None"),
             "%{name}": cpu_value,
             "%{opt_compile_flags}": get_starlark_list(
                 [
@@ -543,15 +726,15 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
                 ],
             ),
             "%{opt_link_flags}": get_starlark_list(
-                [] if darwin else _add_linker_option_if_supported(
+                ["-Wl,-dead_strip"] if darwin else _add_linker_option_if_supported(
                     repository_ctx,
                     cc,
+                    force_linker_flags,
                     "-Wl,--gc-sections",
                     "-gc-sections",
                 ),
             ),
-            "%{supports_param_files}": "0" if darwin else "1",
-            "%{supports_start_end_lib}": "True" if gold_linker_path else "False",
+            "%{supports_start_end_lib}": "True" if gold_or_lld_linker_path else "False",
             "%{target_cpu}": escape_string(get_env_var(
                 repository_ctx,
                 "BAZEL_TARGET_CPU",
@@ -571,7 +754,7 @@ def configure_unix_toolchain(repository_ctx, cpu_value, overriden_tools):
                 False,
             )),
             "%{tool_paths}": ",\n        ".join(
-                ['"%s": "%s"' % (k, v) for k, v in tool_paths.items()],
+                ['"%s": "%s"' % (k, v) for k, v in tool_paths.items() if v != None],
             ),
             "%{unfiltered_compile_flags}": get_starlark_list(
                 _get_no_canonical_prefixes_opt(repository_ctx, cc) + [
diff --git a/cc/private/toolchain/unix_cc_toolchain_config.bzl b/cc/private/toolchain/unix_cc_toolchain_config.bzl
index 4325a68..e500999 100644
--- a/cc/private/toolchain/unix_cc_toolchain_config.bzl
+++ b/cc/private/toolchain/unix_cc_toolchain_config.bzl
@@ -17,15 +17,137 @@
 load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
 load(
     "@rules_cc//cc:cc_toolchain_config_lib.bzl",
+    "action_config",
+    "artifact_name_pattern",
+    "env_entry",
+    "env_set",
     "feature",
     "feature_set",
     "flag_group",
     "flag_set",
+    "tool",
     "tool_path",
     "variable_with_value",
     "with_feature_set",
 )
 
+def _target_os_version(ctx):
+    platform_type = ctx.fragments.apple.single_arch_platform.platform_type
+    xcode_config = ctx.attr._xcode_config[apple_common.XcodeVersionConfig]
+    return xcode_config.minimum_os_for_platform_type(platform_type)
+
+def layering_check_features(compiler, extra_flags_per_feature, is_macos):
+    if compiler != "clang":
+        return []
+    return [
+        feature(
+            name = "use_module_maps",
+            requires = [feature_set(features = ["module_maps"])],
+            flag_sets = [
+                flag_set(
+                    actions = [
+                        ACTION_NAMES.c_compile,
+                        ACTION_NAMES.cpp_compile,
+                        ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_compile,
+                    ],
+                    flag_groups = [
+                        flag_group(
+                            # macOS requires -Xclang because of a bug in Apple Clang
+                            flags = (["-Xclang"] if is_macos else []) + [
+                                "-fmodule-name=%{module_name}",
+                            ] + (["-Xclang"] if is_macos else []) + [
+                                "-fmodule-map-file=%{module_map_file}",
+                            ] + extra_flags_per_feature.get("use_module_maps", []),
+                        ),
+                    ],
+                ),
+            ],
+        ),
+
+        # Tell blaze we support module maps in general, so they will be generated
+        # for all c/c++ rules.
+        # Note: not all C++ rules support module maps; thus, do not imply this
+        # feature from other features - instead, require it.
+        feature(name = "module_maps", enabled = True),
+        feature(
+            name = "layering_check",
+            implies = ["use_module_maps"],
+            flag_sets = [
+                flag_set(
+                    actions = [
+                        ACTION_NAMES.c_compile,
+                        ACTION_NAMES.cpp_compile,
+                        ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_compile,
+                    ],
+                    flag_groups = [
+                        flag_group(flags = [
+                            "-fmodules-strict-decluse",
+                            "-Wprivate-header",
+                        ]),
+                        flag_group(
+                            iterate_over = "dependent_module_map_files",
+                            flags = (["-Xclang"] if is_macos else []) + [
+                                "-fmodule-map-file=%{dependent_module_map_files}",
+                            ],
+                        ),
+                    ],
+                ),
+            ],
+        ),
+    ]
+
+def parse_headers_support(parse_headers_tool_path):
+    """
+    Returns action configurations and features for parsing headers.
+
+    Args:
+        parse_headers_tool_path: The path to the tool used for parsing headers.
+
+    Returns:
+        A tuple containing a list of action configurations and a list of features.
+    """
+    if not parse_headers_tool_path:
+        return [], []
+    action_configs = [
+        action_config(
+            action_name = ACTION_NAMES.cpp_header_parsing,
+            tools = [
+                tool(path = parse_headers_tool_path),
+            ],
+            flag_sets = [
+                flag_set(
+                    flag_groups = [
+                        flag_group(
+                            flags = [
+                                # Note: This treats all headers as C++ headers, which may lead to
+                                # parsing failures for C headers that are not valid C++.
+                                # For such headers, use features = ["-parse_headers"] to selectively
+                                # disable parsing.
+                                "-xc++-header",
+                                "-fsyntax-only",
+                            ],
+                        ),
+                    ],
+                ),
+            ],
+            implies = [
+                # Copied from the legacy feature definition in CppActionConfigs.java.
+                "legacy_compile_flags",
+                "user_compile_flags",
+                "sysroot",
+                "unfiltered_compile_flags",
+                "compiler_input_flags",
+                "compiler_output_flags",
+            ],
+        ),
+    ]
+    features = [
+        feature(name = "parse_headers"),
+    ]
+    return action_configs, features
+
 all_compile_actions = [
     ACTION_NAMES.c_compile,
     ACTION_NAMES.cpp_compile,
@@ -35,6 +157,9 @@ all_compile_actions = [
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.clif_match,
     ACTION_NAMES.lto_backend,
 ]
@@ -45,6 +170,9 @@ all_cpp_compile_actions = [
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.clif_match,
 ]
 
@@ -55,6 +183,8 @@ preprocessor_compile_actions = [
     ACTION_NAMES.preprocess_assemble,
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
     ACTION_NAMES.clif_match,
 ]
 
@@ -65,6 +195,7 @@ codegen_compile_actions = [
     ACTION_NAMES.assemble,
     ACTION_NAMES.preprocess_assemble,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.lto_backend,
 ]
 
@@ -80,13 +211,138 @@ lto_index_actions = [
     ACTION_NAMES.lto_index_for_nodeps_dynamic_library,
 ]
 
+def _sanitizer_feature(name = "", specific_compile_flags = [], specific_link_flags = []):
+    return feature(
+        name = name,
+        flag_sets = [
+            flag_set(
+                actions = all_compile_actions,
+                flag_groups = [
+                    flag_group(flags = [
+                        "-fno-omit-frame-pointer",
+                        "-fno-sanitize-recover=all",
+                    ] + specific_compile_flags),
+                ],
+            ),
+            flag_set(
+                actions = all_link_actions,
+                flag_groups = [
+                    flag_group(flags = specific_link_flags),
+                ],
+            ),
+        ],
+    )
+
 def _impl(ctx):
+    is_linux = ctx.attr.target_libc != "macosx"
+
     tool_paths = [
         tool_path(name = name, path = path)
         for name, path in ctx.attr.tool_paths.items()
     ]
     action_configs = []
 
+    llvm_cov = ctx.attr.tool_paths.get("llvm-cov")
+    if llvm_cov:
+        llvm_cov_action = action_config(
+            action_name = ACTION_NAMES.llvm_cov,
+            tools = [
+                tool(
+                    path = llvm_cov,
+                ),
+            ],
+        )
+        action_configs.append(llvm_cov_action)
+
+    objcopy = ctx.attr.tool_paths.get("objcopy")
+    if objcopy:
+        objcopy_action = action_config(
+            action_name = ACTION_NAMES.objcopy_embed_data,
+            tools = [
+                tool(
+                    path = objcopy,
+                ),
+            ],
+        )
+        action_configs.append(objcopy_action)
+
+    validate_static_library = ctx.attr.tool_paths.get("validate_static_library")
+    if validate_static_library:
+        validate_static_library_action = action_config(
+            action_name = ACTION_NAMES.validate_static_library,
+            tools = [
+                tool(
+                    path = validate_static_library,
+                ),
+            ],
+        )
+        action_configs.append(validate_static_library_action)
+
+        symbol_check = feature(
+            name = "symbol_check",
+            implies = [ACTION_NAMES.validate_static_library],
+        )
+    else:
+        symbol_check = None
+
+    deps_scanner = "cpp-module-deps-scanner_not_found"
+    if "cpp-module-deps-scanner" in ctx.attr.tool_paths:
+        deps_scanner = ctx.attr.tool_paths["cpp-module-deps-scanner"]
+    cc = ctx.attr.tool_paths.get("gcc")
+    compile_implies = [
+        # keep same with c++-compile
+        "legacy_compile_flags",
+        "user_compile_flags",
+        "sysroot",
+        "unfiltered_compile_flags",
+        "compiler_input_flags",
+        "compiler_output_flags",
+    ]
+    cpp_module_scan_deps = action_config(
+        action_name = ACTION_NAMES.cpp_module_deps_scanning,
+        tools = [
+            tool(
+                path = deps_scanner,
+            ),
+        ],
+        implies = compile_implies,
+    )
+    action_configs.append(cpp_module_scan_deps)
+
+    cpp20_module_compile = action_config(
+        action_name = ACTION_NAMES.cpp20_module_compile,
+        tools = [
+            tool(
+                path = cc,
+            ),
+        ],
+        flag_sets = [
+            flag_set(
+                flag_groups = [
+                    flag_group(
+                        flags = [
+                            "-x",
+                            "c++-module" if ctx.attr.compiler == "clang" else "c++",
+                        ],
+                    ),
+                ],
+            ),
+        ],
+        implies = compile_implies,
+    )
+    action_configs.append(cpp20_module_compile)
+
+    cpp20_module_codegen = action_config(
+        action_name = ACTION_NAMES.cpp20_module_codegen,
+        tools = [
+            tool(
+                path = cc,
+            ),
+        ],
+        implies = compile_implies,
+    )
+    action_configs.append(cpp20_module_codegen)
+
     supports_pic_feature = feature(
         name = "supports_pic",
         enabled = True,
@@ -96,10 +352,35 @@ def _impl(ctx):
         enabled = True,
     )
 
+    gcc_quoting_for_param_files_feature = feature(
+        name = "gcc_quoting_for_param_files",
+        enabled = True,
+    )
+
+    static_link_cpp_runtimes_feature = feature(
+        name = "static_link_cpp_runtimes",
+        enabled = False,
+    )
+
     default_compile_flags_feature = feature(
         name = "default_compile_flags",
         enabled = True,
         flag_sets = [
+            flag_set(
+                actions = all_compile_actions,
+                flag_groups = [
+                    flag_group(
+                        # Security hardening requires optimization.
+                        # We need to undef it as some distributions now have it enabled by default.
+                        flags = ["-U_FORTIFY_SOURCE"],
+                    ),
+                ],
+                with_features = [
+                    with_feature_set(
+                        not_features = ["thin_lto"],
+                    ),
+                ],
+            ),
             flag_set(
                 actions = all_compile_actions,
                 flag_groups = ([
@@ -126,6 +407,14 @@ def _impl(ctx):
                 ] if ctx.attr.opt_compile_flags else []),
                 with_features = [with_feature_set(features = ["opt"])],
             ),
+            flag_set(
+                actions = [ACTION_NAMES.c_compile],
+                flag_groups = ([
+                    flag_group(
+                        flags = ctx.attr.conly_flags,
+                    ),
+                ] if ctx.attr.conly_flags else []),
+            ),
             flag_set(
                 actions = all_cpp_compile_actions + [ACTION_NAMES.lto_backend],
                 flag_groups = ([
@@ -159,6 +448,18 @@ def _impl(ctx):
                 with_features = [with_feature_set(features = ["opt"])],
             ),
         ],
+        env_sets = [
+            env_set(
+                actions = all_link_actions + lto_index_actions + [ACTION_NAMES.cpp_link_static_library],
+                env_entries = ([
+                    env_entry(
+                        # Required for hermetic links on macOS
+                        key = "ZERO_AR_DATE",
+                        value = "1",
+                    ),
+                ]),
+            ),
+        ],
     )
 
     dbg_feature = feature(name = "dbg")
@@ -178,6 +479,9 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_header_parsing,
                     ACTION_NAMES.cpp_module_compile,
                     ACTION_NAMES.cpp_module_codegen,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
                     ACTION_NAMES.lto_backend,
                     ACTION_NAMES.clif_match,
                 ] + all_link_actions + lto_index_actions,
@@ -191,6 +495,76 @@ def _impl(ctx):
         ],
     )
 
+    compiler_input_flags_feature = feature(
+        name = "compiler_input_flags",
+        enabled = True,
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.assemble,
+                    ACTION_NAMES.preprocess_assemble,
+                    ACTION_NAMES.linkstamp_compile,
+                    ACTION_NAMES.c_compile,
+                    ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp_header_parsing,
+                    ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_codegen,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
+                    ACTION_NAMES.objc_compile,
+                    ACTION_NAMES.objcpp_compile,
+                    ACTION_NAMES.lto_backend,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["-c", "%{source_file}"],
+                        expand_if_available = "source_file",
+                    ),
+                ],
+            ),
+        ],
+    )
+
+    compiler_output_flags_feature = feature(
+        name = "compiler_output_flags",
+        enabled = True,
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.assemble,
+                    ACTION_NAMES.preprocess_assemble,
+                    ACTION_NAMES.linkstamp_compile,
+                    ACTION_NAMES.c_compile,
+                    ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp_header_parsing,
+                    ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_codegen,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
+                    ACTION_NAMES.objc_compile,
+                    ACTION_NAMES.objcpp_compile,
+                    ACTION_NAMES.lto_backend,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["-S"],
+                        expand_if_available = "output_assembly_file",
+                    ),
+                    flag_group(
+                        flags = ["-E"],
+                        expand_if_available = "output_preprocess_file",
+                    ),
+                    flag_group(
+                        flags = ["-o", "%{output_file}"],
+                        expand_if_available = "output_file",
+                    ),
+                ],
+            ),
+        ],
+    )
+
     fdo_optimize_feature = feature(
         name = "fdo_optimize",
         flag_sets = [
@@ -292,6 +666,8 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_module_codegen,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
                 ],
                 flag_groups = [
                     flag_group(flags = ["-fPIC"], expand_if_available = "pic"),
@@ -302,6 +678,7 @@ def _impl(ctx):
 
     per_object_debug_info_feature = feature(
         name = "per_object_debug_info",
+        enabled = True,
         flag_sets = [
             flag_set(
                 actions = [
@@ -310,6 +687,7 @@ def _impl(ctx):
                     ACTION_NAMES.c_compile,
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_module_codegen,
+                    ACTION_NAMES.cpp20_module_codegen,
                 ],
                 flag_groups = [
                     flag_group(
@@ -333,6 +711,9 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_header_parsing,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
                     ACTION_NAMES.clif_match,
                 ],
                 flag_groups = [
@@ -385,60 +766,134 @@ def _impl(ctx):
         provides = ["profile"],
     )
 
-    runtime_library_search_directories_feature = feature(
-        name = "runtime_library_search_directories",
-        flag_sets = [
-            flag_set(
-                actions = all_link_actions + lto_index_actions,
-                flag_groups = [
-                    flag_group(
-                        iterate_over = "runtime_library_search_directories",
-                        flag_groups = [
-                            flag_group(
-                                flags = [
-                                    "-Wl,-rpath,$EXEC_ORIGIN/%{runtime_library_search_directories}",
-                                ],
-                                expand_if_true = "is_cc_test",
-                            ),
-                            flag_group(
-                                flags = [
-                                    "-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}",
-                                ],
-                                expand_if_false = "is_cc_test",
-                            ),
-                        ],
-                        expand_if_available =
-                            "runtime_library_search_directories",
-                    ),
-                ],
-                with_features = [
-                    with_feature_set(features = ["static_link_cpp_runtimes"]),
-                ],
-            ),
-            flag_set(
-                actions = all_link_actions + lto_index_actions,
-                flag_groups = [
-                    flag_group(
-                        iterate_over = "runtime_library_search_directories",
-                        flag_groups = [
-                            flag_group(
-                                flags = [
-                                    "-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}",
-                                ],
-                            ),
-                        ],
-                        expand_if_available =
-                            "runtime_library_search_directories",
-                    ),
-                ],
-                with_features = [
-                    with_feature_set(
-                        not_features = ["static_link_cpp_runtimes"],
-                    ),
-                ],
-            ),
-        ],
-    )
+    if is_linux:
+        runtime_library_search_directories_feature = feature(
+            name = "runtime_library_search_directories",
+            flag_sets = [
+                flag_set(
+                    actions = all_link_actions + lto_index_actions,
+                    flag_groups = [
+                        flag_group(
+                            iterate_over = "runtime_library_search_directories",
+                            flag_groups = [
+                                flag_group(
+                                    flags = [
+                                        "-Xlinker",
+                                        "-rpath",
+                                        "-Xlinker",
+                                        "$EXEC_ORIGIN/%{runtime_library_search_directories}",
+                                    ],
+                                    expand_if_true = "is_cc_test",
+                                ),
+                                flag_group(
+                                    flags = [
+                                        "-Xlinker",
+                                        "-rpath",
+                                        "-Xlinker",
+                                        "$ORIGIN/%{runtime_library_search_directories}",
+                                    ],
+                                    expand_if_false = "is_cc_test",
+                                ),
+                            ],
+                            expand_if_available =
+                                "runtime_library_search_directories",
+                        ),
+                    ],
+                    with_features = [
+                        with_feature_set(features = ["static_link_cpp_runtimes"]),
+                    ],
+                ),
+                flag_set(
+                    actions = all_link_actions + lto_index_actions,
+                    flag_groups = [
+                        flag_group(
+                            iterate_over = "runtime_library_search_directories",
+                            flag_groups = [
+                                flag_group(
+                                    flags = [
+                                        "-Xlinker",
+                                        "-rpath",
+                                        "-Xlinker",
+                                        "$ORIGIN/%{runtime_library_search_directories}",
+                                    ],
+                                ),
+                            ],
+                            expand_if_available =
+                                "runtime_library_search_directories",
+                        ),
+                    ],
+                    with_features = [
+                        with_feature_set(
+                            not_features = ["static_link_cpp_runtimes"],
+                        ),
+                    ],
+                ),
+            ],
+        )
+        set_install_name_feature = feature(
+            name = "set_soname",
+            flag_sets = [
+                flag_set(
+                    actions = [
+                        ACTION_NAMES.cpp_link_dynamic_library,
+                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
+                    ],
+                    flag_groups = [
+                        flag_group(
+                            flags = [
+                                "-Wl,-soname,%{runtime_solib_name}",
+                            ],
+                            expand_if_available = "runtime_solib_name",
+                        ),
+                    ],
+                ),
+            ],
+        )
+    else:
+        runtime_library_search_directories_feature = feature(
+            name = "runtime_library_search_directories",
+            flag_sets = [
+                flag_set(
+                    actions = all_link_actions + lto_index_actions,
+                    flag_groups = [
+                        flag_group(
+                            iterate_over = "runtime_library_search_directories",
+                            flag_groups = [
+                                flag_group(
+                                    flags = [
+                                        "-Xlinker",
+                                        "-rpath",
+                                        "-Xlinker",
+                                        "@loader_path/%{runtime_library_search_directories}",
+                                    ],
+                                ),
+                            ],
+                            expand_if_available = "runtime_library_search_directories",
+                        ),
+                    ],
+                ),
+            ],
+        )
+        set_install_name_feature = feature(
+            name = "set_install_name",
+            enabled = ctx.fragments.cpp.do_not_use_macos_set_install_name,
+            flag_sets = [
+                flag_set(
+                    actions = [
+                        ACTION_NAMES.cpp_link_dynamic_library,
+                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
+                    ],
+                    flag_groups = [
+                        flag_group(
+                            flags = [
+                                "-Wl,-install_name,@rpath/%{runtime_solib_name}",
+                            ],
+                            expand_if_available = "runtime_solib_name",
+                        ),
+                    ],
+                ),
+            ],
+        )
 
     fission_support_feature = feature(
         name = "fission_support",
@@ -480,6 +935,9 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_module_codegen,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
                 ],
                 flag_groups = [
                     flag_group(
@@ -503,6 +961,8 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_header_parsing,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
                     ACTION_NAMES.clif_match,
                     ACTION_NAMES.objc_compile,
                     ACTION_NAMES.objcpp_compile,
@@ -574,6 +1034,8 @@ def _impl(ctx):
                     ACTION_NAMES.cpp_compile,
                     ACTION_NAMES.cpp_header_parsing,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
                     ACTION_NAMES.clif_match,
                     ACTION_NAMES.objc_compile,
                     ACTION_NAMES.objcpp_compile,
@@ -596,56 +1058,33 @@ def _impl(ctx):
         ],
     )
 
-    symbol_counts_feature = feature(
-        name = "symbol_counts",
-        flag_sets = [
-            flag_set(
-                actions = all_link_actions + lto_index_actions,
-                flag_groups = [
-                    flag_group(
-                        flags = [
-                            "-Wl,--print-symbol-counts=%{symbol_counts_output}",
-                        ],
-                        expand_if_available = "symbol_counts_output",
-                    ),
-                ],
-            ),
-        ],
-    )
-
-    llvm_coverage_map_format_feature = feature(
-        name = "llvm_coverage_map_format",
+    external_include_paths_feature = feature(
+        name = "external_include_paths",
         flag_sets = [
             flag_set(
                 actions = [
                     ACTION_NAMES.preprocess_assemble,
+                    ACTION_NAMES.linkstamp_compile,
                     ACTION_NAMES.c_compile,
                     ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp_header_parsing,
                     ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
+                    ACTION_NAMES.clif_match,
                     ACTION_NAMES.objc_compile,
                     ACTION_NAMES.objcpp_compile,
                 ],
                 flag_groups = [
                     flag_group(
-                        flags = [
-                            "-fprofile-instr-generate",
-                            "-fcoverage-mapping",
-                        ],
+                        flags = ["-isystem", "%{external_include_paths}"],
+                        iterate_over = "external_include_paths",
+                        expand_if_available = "external_include_paths",
                     ),
                 ],
             ),
-            flag_set(
-                actions = all_link_actions + lto_index_actions + [
-                    "objc-executable",
-                    "objc++-executable",
-                ],
-                flag_groups = [
-                    flag_group(flags = ["-fprofile-instr-generate"]),
-                ],
-            ),
         ],
-        requires = [feature_set(features = ["coverage"])],
-        provides = ["profile"],
     )
 
     strip_debug_symbols_feature = feature(
@@ -693,11 +1132,77 @@ def _impl(ctx):
         ],
     )
 
+    libraries_to_link_common_flag_groups = [
+        flag_group(
+            flags = ["-Wl,-whole-archive"],
+            expand_if_true =
+                "libraries_to_link.is_whole_archive",
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "static_library",
+            ),
+        ),
+        flag_group(
+            flags = ["%{libraries_to_link.object_files}"],
+            iterate_over = "libraries_to_link.object_files",
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "object_file_group",
+            ),
+        ),
+        flag_group(
+            flags = ["%{libraries_to_link.name}"],
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "object_file",
+            ),
+        ),
+        flag_group(
+            flags = ["%{libraries_to_link.name}"],
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "interface_library",
+            ),
+        ),
+        flag_group(
+            flags = ["%{libraries_to_link.name}"],
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "static_library",
+            ),
+        ),
+        flag_group(
+            flags = ["-l%{libraries_to_link.name}"],
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "dynamic_library",
+            ),
+        ),
+        flag_group(
+            flags = ["-l:%{libraries_to_link.name}"],
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "versioned_dynamic_library",
+            ),
+        ),
+        flag_group(
+            flags = ["-Wl,-no-whole-archive"],
+            expand_if_true = "libraries_to_link.is_whole_archive",
+            expand_if_equal = variable_with_value(
+                name = "libraries_to_link.type",
+                value = "static_library",
+            ),
+        ),
+    ]
+
     libraries_to_link_feature = feature(
         name = "libraries_to_link",
         flag_sets = [
             flag_set(
-                actions = all_link_actions + lto_index_actions,
+                actions = [
+                    ACTION_NAMES.cpp_link_executable,
+                    ACTION_NAMES.cpp_link_dynamic_library,
+                ] + lto_index_actions,
                 flag_groups = [
                     flag_group(
                         iterate_over = "libraries_to_link",
@@ -709,58 +1214,7 @@ def _impl(ctx):
                                     value = "object_file_group",
                                 ),
                             ),
-                            flag_group(
-                                flags = ["-Wl,-whole-archive"],
-                                expand_if_true =
-                                    "libraries_to_link.is_whole_archive",
-                            ),
-                            flag_group(
-                                flags = ["%{libraries_to_link.object_files}"],
-                                iterate_over = "libraries_to_link.object_files",
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "object_file_group",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["%{libraries_to_link.name}"],
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "object_file",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["%{libraries_to_link.name}"],
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "interface_library",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["%{libraries_to_link.name}"],
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "static_library",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["-l%{libraries_to_link.name}"],
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "dynamic_library",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["-l:%{libraries_to_link.name}"],
-                                expand_if_equal = variable_with_value(
-                                    name = "libraries_to_link.type",
-                                    value = "versioned_dynamic_library",
-                                ),
-                            ),
-                            flag_group(
-                                flags = ["-Wl,-no-whole-archive"],
-                                expand_if_true = "libraries_to_link.is_whole_archive",
-                            ),
+                        ] + libraries_to_link_common_flag_groups + [
                             flag_group(
                                 flags = ["-Wl,--end-lib"],
                                 expand_if_equal = variable_with_value(
@@ -777,6 +1231,22 @@ def _impl(ctx):
                     ),
                 ],
             ),
+            # Object file groups may contain symbols that aren't referenced in the same target that
+            # produces the object files and must thus not be wrapped in --start-lib/--end-lib when
+            # linking a nodeps dynamic library.
+            flag_set(
+                actions = [ACTION_NAMES.cpp_link_nodeps_dynamic_library],
+                flag_groups = [
+                    flag_group(
+                        iterate_over = "libraries_to_link",
+                        flag_groups = libraries_to_link_common_flag_groups,
+                    ),
+                    flag_group(
+                        flags = ["-Wl,@%{thinlto_param_file}"],
+                        expand_if_true = "thinlto_param_file",
+                    ),
+                ],
+            ),
         ],
     )
 
@@ -791,7 +1261,18 @@ def _impl(ctx):
                         iterate_over = "user_link_flags",
                         expand_if_available = "user_link_flags",
                     ),
-                ] + ([flag_group(flags = ctx.attr.link_libs)] if ctx.attr.link_libs else []),
+                ],
+            ),
+        ],
+    )
+
+    default_link_libs_feature = feature(
+        name = "default_link_libs",
+        enabled = True,
+        flag_sets = [
+            flag_set(
+                actions = all_link_actions + lto_index_actions,
+                flag_groups = [flag_group(flags = ctx.attr.link_libs)] if ctx.attr.link_libs else [],
             ),
         ],
     )
@@ -834,48 +1315,48 @@ def _impl(ctx):
         ],
     )
 
-    gcc_coverage_map_format_feature = feature(
-        name = "gcc_coverage_map_format",
+    libtool_feature = feature(
+        name = "libtool",
+        enabled = not is_linux,
+    )
+
+    archiver_flags_feature = feature(
+        name = "archiver_flags",
         flag_sets = [
             flag_set(
-                actions = [
-                    ACTION_NAMES.preprocess_assemble,
-                    ACTION_NAMES.c_compile,
-                    ACTION_NAMES.cpp_compile,
-                    ACTION_NAMES.cpp_module_compile,
-                    ACTION_NAMES.objc_compile,
-                    ACTION_NAMES.objcpp_compile,
-                    "objc-executable",
-                    "objc++-executable",
-                ],
+                actions = [ACTION_NAMES.cpp_link_static_library],
                 flag_groups = [
                     flag_group(
-                        flags = ["-fprofile-arcs", "-ftest-coverage"],
-                        expand_if_available = "gcov_gcno_file",
+                        flags = [
+                            "rcsD" if is_linux else "rcs",
+                            "%{output_execpath}",
+                        ],
+                        expand_if_available = "output_execpath",
+                    ),
+                ],
+                with_features = [
+                    with_feature_set(
+                        not_features = ["libtool"],
                     ),
                 ],
             ),
-            flag_set(
-                actions = all_link_actions + lto_index_actions,
-                flag_groups = [flag_group(flags = ["--coverage"])],
-            ),
-        ],
-        requires = [feature_set(features = ["coverage"])],
-        provides = ["profile"],
-    )
-
-    archiver_flags_feature = feature(
-        name = "archiver_flags",
-        flag_sets = [
             flag_set(
                 actions = [ACTION_NAMES.cpp_link_static_library],
                 flag_groups = [
-                    flag_group(flags = ["rcsD"]),
                     flag_group(
-                        flags = ["%{output_execpath}"],
+                        flags = [
+                            "-static",
+                            "-o",
+                            "%{output_execpath}",
+                        ],
                         expand_if_available = "output_execpath",
                     ),
                 ],
+                with_features = [
+                    with_feature_set(
+                        features = ["libtool"],
+                    ),
+                ],
             ),
             flag_set(
                 actions = [ACTION_NAMES.cpp_link_static_library],
@@ -903,6 +1384,24 @@ def _impl(ctx):
                     ),
                 ],
             ),
+            flag_set(
+                actions = [ACTION_NAMES.cpp_link_static_library],
+                flag_groups = ([
+                    flag_group(
+                        flags = ctx.attr.archive_flags,
+                    ),
+                ] if ctx.attr.archive_flags else []),
+            ),
+            flag_set(
+                actions = [ACTION_NAMES.cpp_link_static_library],
+                flag_groups = [
+                    flag_group(
+                        flags = ["%{user_archiver_flags}"],
+                        iterate_over = "user_archiver_flags",
+                        expand_if_available = "user_archiver_flags",
+                    ),
+                ],
+            ),
         ],
     )
 
@@ -938,6 +1437,8 @@ def _impl(ctx):
                     ACTION_NAMES.objc_compile,
                     ACTION_NAMES.objcpp_compile,
                     ACTION_NAMES.cpp_header_parsing,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.cpp20_module_compile,
                     ACTION_NAMES.clif_match,
                 ],
                 flag_groups = [
@@ -950,6 +1451,32 @@ def _impl(ctx):
         ],
     )
 
+    serialized_diagnostics_file_feature = feature(
+        name = "serialized_diagnostics_file",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.assemble,
+                    ACTION_NAMES.preprocess_assemble,
+                    ACTION_NAMES.c_compile,
+                    ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp_module_compile,
+                    ACTION_NAMES.objc_compile,
+                    ACTION_NAMES.objcpp_compile,
+                    ACTION_NAMES.cpp_header_parsing,
+                    ACTION_NAMES.cpp_module_deps_scanning,
+                    ACTION_NAMES.clif_match,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["--serialize-diagnostics", "%{serialized_diagnostics_file}"],
+                        expand_if_available = "serialized_diagnostics_file",
+                    ),
+                ],
+            ),
+        ],
+    )
+
     dynamic_library_linker_tool_feature = feature(
         name = "dynamic_library_linker_tool",
         flag_sets = [
@@ -975,6 +1502,25 @@ def _impl(ctx):
         ],
     )
 
+    generate_linkmap_feature = feature(
+        name = "generate_linkmap",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.cpp_link_executable,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = [
+                            "-Wl,-Map=%{output_execpath}.map" if is_linux else "-Wl,-map,%{output_execpath}.map",
+                        ],
+                        expand_if_available = "output_execpath",
+                    ),
+                ],
+            ),
+        ],
+    )
+
     output_execpath_flags_feature = feature(
         name = "output_execpath_flags",
         flag_sets = [
@@ -1081,18 +1627,156 @@ def _impl(ctx):
         ],
     )
 
-    is_linux = ctx.attr.target_libc != "macosx"
+    treat_warnings_as_errors_feature = feature(
+        name = "treat_warnings_as_errors",
+        flag_sets = [
+            flag_set(
+                actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                flag_groups = [flag_group(flags = ["-Werror"])],
+            ),
+            flag_set(
+                actions = all_link_actions,
+                flag_groups = [flag_group(
+                    flags = ["-Wl,-fatal-warnings"] if is_linux else ["-Wl,-fatal_warnings"],
+                )],
+            ),
+        ],
+    )
+
+    archive_param_file_feature = feature(
+        name = "archive_param_file",
+        enabled = True,
+    )
+
+    asan_feature = _sanitizer_feature(
+        name = "asan",
+        specific_compile_flags = [
+            "-fsanitize=address",
+            "-fno-common",
+        ],
+        specific_link_flags = [
+            "-fsanitize=address",
+        ],
+    )
+
+    tsan_feature = _sanitizer_feature(
+        name = "tsan",
+        specific_compile_flags = [
+            "-fsanitize=thread",
+        ],
+        specific_link_flags = [
+            "-fsanitize=thread",
+        ],
+    )
+
+    ubsan_feature = _sanitizer_feature(
+        name = "ubsan",
+        specific_compile_flags = [
+            "-fsanitize=undefined",
+        ],
+        specific_link_flags = [
+            "-fsanitize=undefined",
+        ],
+    )
+
+    # If you have Xcode + the CLT installed the version defaults can be
+    # too old for some standard C apis such as thread locals
+    macos_minimum_os_feature = feature(
+        name = "macos_minimum_os",
+        enabled = True,
+        flag_sets = [
+            flag_set(
+                actions = all_compile_actions + all_link_actions,
+                flag_groups = [flag_group(flags = ["-mmacosx-version-min={}".format(_target_os_version(ctx))])],
+            ),
+        ],
+    )
+
+    # Kept for backwards compatibility with the crosstool that moved. Without
+    # linking the objc runtime binaries don't link CoreFoundation for free,
+    # which breaks abseil.
+    macos_default_link_flags_feature = feature(
+        name = "macos_default_link_flags",
+        enabled = True,
+        flag_sets = [
+            flag_set(
+                actions = all_link_actions,
+                flag_groups = [flag_group(flags = [
+                    "-no-canonical-prefixes",
+                    "-fobjc-link-runtime",
+                ])],
+            ),
+        ],
+    )
+
+    # Tell bazel we support C++ modules now
+    cpp_modules_feature = feature(
+        name = "cpp_modules",
+        # set default value to False
+        # to enable the feature
+        # use --features=cpp_modules
+        # or add cpp_modules to features attr
+        enabled = False,
+    )
+
+    cpp_module_modmap_file_feature = feature(
+        name = "cpp_module_modmap_file",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["@%{cpp_module_modmap_file}" if ctx.attr.compiler == "clang" else "-fmodule-mapper=%{cpp_module_modmap_file}"],
+                        expand_if_available = "cpp_module_modmap_file",
+                    ),
+                ],
+            ),
+        ],
+        enabled = True,
+    )
+    if ctx.attr.compiler == "clang":
+        flag_groups = [
+            flag_group(
+                flags = ["-fmodule-output=%{cpp_module_output_file}"],
+                expand_if_available = "cpp_module_output_file",
+            ),
+        ]
+    else:
+        flag_groups = []
+    cpp20_module_compile_flags_feature = feature(
+        name = "cpp20_module_compile_flags",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.cpp20_module_compile,
+                ],
+                flag_groups = flag_groups,
+            ),
+        ],
+        enabled = True,
+    )
 
     # TODO(#8303): Mac crosstool should also declare every feature.
     if is_linux:
+        # Linux artifact name patterns are the default.
+        artifact_name_patterns = []
         features = [
+            cpp_modules_feature,
+            cpp_module_modmap_file_feature,
+            cpp20_module_compile_flags_feature,
             dependency_file_feature,
+            serialized_diagnostics_file_feature,
             random_seed_feature,
             pic_feature,
             per_object_debug_info_feature,
             preprocessor_defines_feature,
             includes_feature,
             include_paths_feature,
+            external_include_paths_feature,
             fdo_instrument_feature,
             cs_fdo_instrument_feature,
             cs_fdo_optimize_feature,
@@ -1101,20 +1785,24 @@ def _impl(ctx):
             autofdo_feature,
             build_interface_libraries_feature,
             dynamic_library_linker_tool_feature,
-            symbol_counts_feature,
+            generate_linkmap_feature,
             shared_flag_feature,
             linkstamps_feature,
             output_execpath_flags_feature,
             runtime_library_search_directories_feature,
             library_search_directories_feature,
+            libtool_feature,
             archiver_flags_feature,
             force_pic_flags_feature,
             fission_support_feature,
             strip_debug_symbols_feature,
             coverage_feature,
             supports_pic_feature,
-            gcc_coverage_map_format_feature,
-            llvm_coverage_map_format_feature,
+            asan_feature,
+            tsan_feature,
+            ubsan_feature,
+            gcc_quoting_for_param_files_feature,
+            static_link_cpp_runtimes_feature,
         ] + (
             [
                 supports_start_end_lib_feature,
@@ -1124,6 +1812,7 @@ def _impl(ctx):
             default_link_flags_feature,
             libraries_to_link_feature,
             user_link_flags_feature,
+            default_link_libs_feature,
             static_libgcc_feature,
             fdo_optimize_feature,
             supports_dynamic_linker_feature,
@@ -1131,11 +1820,39 @@ def _impl(ctx):
             opt_feature,
             user_compile_flags_feature,
             sysroot_feature,
+            compiler_input_flags_feature,
+            compiler_output_flags_feature,
             unfiltered_compile_flags_feature,
-        ]
+            treat_warnings_as_errors_feature,
+            archive_param_file_feature,
+            set_install_name_feature,
+        ] + layering_check_features(ctx.attr.compiler, ctx.attr.extra_flags_per_feature, is_macos = False)
     else:
+        # macOS artifact name patterns differ from the defaults only for dynamic
+        # libraries.
+        artifact_name_patterns = [
+            artifact_name_pattern(
+                category_name = "dynamic_library",
+                prefix = "lib",
+                extension = ".dylib",
+            ),
+        ]
         features = [
-            supports_pic_feature,
+            cpp_modules_feature,
+            cpp_module_modmap_file_feature,
+            cpp20_module_compile_flags_feature,
+            macos_minimum_os_feature,
+            macos_default_link_flags_feature,
+            dependency_file_feature,
+            runtime_library_search_directories_feature,
+            set_install_name_feature,
+            libtool_feature,
+            archiver_flags_feature,
+            asan_feature,
+            tsan_feature,
+            ubsan_feature,
+            gcc_quoting_for_param_files_feature,
+            static_link_cpp_runtimes_feature,
         ] + (
             [
                 supports_start_end_lib_feature,
@@ -1144,21 +1861,36 @@ def _impl(ctx):
             coverage_feature,
             default_compile_flags_feature,
             default_link_flags_feature,
+            user_link_flags_feature,
+            default_link_libs_feature,
+            external_include_paths_feature,
             fdo_optimize_feature,
-            supports_dynamic_linker_feature,
             dbg_feature,
             opt_feature,
             user_compile_flags_feature,
             sysroot_feature,
+            compiler_input_flags_feature,
+            compiler_output_flags_feature,
             unfiltered_compile_flags_feature,
-            gcc_coverage_map_format_feature,
-            llvm_coverage_map_format_feature,
-        ]
+            treat_warnings_as_errors_feature,
+            archive_param_file_feature,
+            generate_linkmap_feature,
+        ] + layering_check_features(ctx.attr.compiler, ctx.attr.extra_flags_per_feature, is_macos = True)
+
+    parse_headers_action_configs, parse_headers_features = parse_headers_support(
+        parse_headers_tool_path = ctx.attr.tool_paths.get("parse_headers"),
+    )
+    action_configs += parse_headers_action_configs
+    features += parse_headers_features
+
+    if symbol_check:
+        features.append(symbol_check)
 
     return cc_common.create_cc_toolchain_config_info(
         ctx = ctx,
         features = features,
         action_configs = action_configs,
+        artifact_name_patterns = artifact_name_patterns,
         cxx_builtin_include_directories = ctx.attr.cxx_builtin_include_directories,
         toolchain_identifier = ctx.attr.toolchain_identifier,
         host_system_name = ctx.attr.host_system_name,
@@ -1169,6 +1901,7 @@ def _impl(ctx):
         abi_version = ctx.attr.abi_version,
         abi_libc_version = ctx.attr.abi_libc_version,
         tool_paths = tool_paths,
+        builtin_sysroot = ctx.attr.builtin_sysroot,
     )
 
 cc_toolchain_config = rule(
@@ -1176,14 +1909,18 @@ cc_toolchain_config = rule(
     attrs = {
         "abi_libc_version": attr.string(mandatory = True),
         "abi_version": attr.string(mandatory = True),
+        "archive_flags": attr.string_list(),
+        "builtin_sysroot": attr.string(),
         "compile_flags": attr.string_list(),
         "compiler": attr.string(mandatory = True),
+        "conly_flags": attr.string_list(),
         "coverage_compile_flags": attr.string_list(),
         "coverage_link_flags": attr.string_list(),
         "cpu": attr.string(mandatory = True),
         "cxx_builtin_include_directories": attr.string_list(),
         "cxx_flags": attr.string_list(),
         "dbg_compile_flags": attr.string_list(),
+        "extra_flags_per_feature": attr.string_list_dict(),
         "host_system_name": attr.string(mandatory = True),
         "link_flags": attr.string_list(),
         "link_libs": attr.string_list(),
@@ -1195,6 +1932,11 @@ cc_toolchain_config = rule(
         "tool_paths": attr.string_dict(),
         "toolchain_identifier": attr.string(mandatory = True),
         "unfiltered_compile_flags": attr.string_list(),
+        "_xcode_config": attr.label(default = configuration_field(
+            fragment = "apple",
+            name = "xcode_config_label",
+        )),
     },
+    fragments = ["apple", "cpp"],
     provides = [CcToolchainConfigInfo],
 )
diff --git a/cc/private/toolchain/validate_static_library.sh.tpl b/cc/private/toolchain/validate_static_library.sh.tpl
new file mode 100755
index 0000000..d769408
--- /dev/null
+++ b/cc/private/toolchain/validate_static_library.sh.tpl
@@ -0,0 +1,44 @@
+#!/usr/bin/env bash
+#
+# Copyright 2023 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+set -euo pipefail
+
+# Find all duplicate symbols in the given static library:
+# 1. Use nm to list all global symbols in the library in POSIX format:
+#    libstatic.a[my_object.o]: my_function T 1234 abcd
+# 2. Use sed to transform the output to a format that can be sorted by symbol
+#    name and is readable by humans:
+#    my_object.o: T my_function
+#    By using the `t` and `d` commands, lines for symbols of type U (undefined)
+#    as well as V and W (weak) and their local lowercase variants are removed.
+# 3. Use sort to sort the lines by symbol name.
+# 4. Use uniq to only keep the lines corresponding to duplicate symbols.
+# 5. Use c++filt to demangle the symbol names.
+#    c++filt is applied to the duplicated symbols instead of using the -C flag
+#    of nm because it is not in POSIX and demangled names may not be unique
+#    (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=35201).
+DUPLICATE_SYMBOLS=$(
+  "%{nm}" -A -g -P %{nm_extra_args} "$1" |
+  sed -E -e 's/.*\[([^][]+)\]: (.+) ([A-TX-Z]) [a-f0-9]+ [a-f0-9]+/\1: \3 \2/g' -e t -e d |
+  LC_ALL=C sort -k 3 |
+  LC_ALL=C uniq -D -f 2 |
+  "%{c++filt}")
+if [[ -n "$DUPLICATE_SYMBOLS" ]]; then
+  >&2 echo "Duplicate symbols found in $1:"
+  >&2 echo "$DUPLICATE_SYMBOLS"
+  exit 1
+else
+  touch "$2"
+fi
diff --git a/cc/private/toolchain/vc_installation_error.bat.tpl b/cc/private/toolchain/vc_installation_error.bat.tpl
index 9cdd658..2285422 100644
--- a/cc/private/toolchain/vc_installation_error.bat.tpl
+++ b/cc/private/toolchain/vc_installation_error.bat.tpl
@@ -18,7 +18,7 @@ echo. 1>&2
 echo The target you are compiling requires Visual C++ build tools. 1>&2
 echo Bazel couldn't find a valid Visual C++ build tools installation on your machine. 1>&2
 %{vc_error_message}
-echo Please check your installation following https://docs.bazel.build/versions/main/windows.html#using 1>&2
+echo Please check your installation following https://bazel.build/docs/windows#using 1>&2
 echo. 1>&2
 
 exit /b 1
diff --git a/cc/private/toolchain/windows_cc_configure.bzl b/cc/private/toolchain/windows_cc_configure.bzl
index 598d4b2..bd87d41 100644
--- a/cc/private/toolchain/windows_cc_configure.bzl
+++ b/cc/private/toolchain/windows_cc_configure.bzl
@@ -25,12 +25,35 @@ load(
     "write_builtin_include_directory_paths",
 )
 
+_targets_archs = {"arm": "amd64_arm", "arm64": "amd64_arm64", "x64": "amd64", "x86": "amd64_x86"}
+_targets_lib_folder = {"arm": "arm", "arm64": "arm64", "x86": ""}
+
+def _lookup_env_var(env, name, default = None):
+    """Lookup environment variable case-insensitve.
+
+    If a matching (case-insensitive) entry is found in the env dict both
+    the key and the value are returned. The returned key might differ from
+    name in casing.
+
+    If a matching key was found its value is returned otherwise
+    the default is returned.
+
+    Return a (key, value) tuple"""
+    for key, value in env.items():
+        if name.lower() == key.lower():
+            return (key, value)
+    return (name, default)
+
+def _get_env_var(repository_ctx, name, default = None):
+    """Returns a value from an environment variable."""
+    return _lookup_env_var(repository_ctx.os.environ, name, default)[1]
+
 def _get_path_env_var(repository_ctx, name):
     """Returns a path from an environment variable.
 
     Removes quotes, replaces '/' with '\', and strips trailing '\'s."""
-    if name in repository_ctx.os.environ:
-        value = repository_ctx.os.environ[name]
+    value = _get_env_var(repository_ctx, name)
+    if value != None:
         if value[0] == "\"":
             if len(value) == 1 or value[-1] != "\"":
                 auto_configure_fail("'%s' environment variable has no trailing quote" % name)
@@ -39,9 +62,7 @@ def _get_path_env_var(repository_ctx, name):
             value = value.replace("/", "\\")
         if value[-1] == "\\":
             value = value.rstrip("\\")
-        return value
-    else:
-        return None
+    return value
 
 def _get_temp_env(repository_ctx):
     """Returns the value of TMP, or TEMP, or if both undefined then C:\\Windows."""
@@ -72,7 +93,7 @@ def _get_escaped_windows_msys_starlark_content(repository_ctx, use_mingw = False
     tool_bin_path = tool_path_prefix + "/bin"
     tool_path = {}
 
-    for tool in ["ar", "compat-ld", "cpp", "dwp", "gcc", "gcov", "ld", "nm", "objcopy", "objdump", "strip"]:
+    for tool in ["ar", "cpp", "dwp", "gcc", "gcov", "ld", "nm", "objcopy", "objdump", "strip"]:
         if msys_root:
             tool_path[tool] = tool_bin_path + "/" + tool
         else:
@@ -94,13 +115,19 @@ def _get_system_root(repository_ctx):
 
 def _add_system_root(repository_ctx, env):
     """Running VCVARSALL.BAT and VCVARSQUERYREGISTRY.BAT need %SYSTEMROOT%\\\\system32 in PATH."""
-    if "PATH" not in env:
-        env["PATH"] = ""
-    env["PATH"] = env["PATH"] + ";" + _get_system_root(repository_ctx) + "\\system32"
+    env_key, env_value = _lookup_env_var(env, "PATH", default = "")
+    env[env_key] = env_value + ";" + _get_system_root(repository_ctx) + "\\system32"
     return env
 
-def _find_vc_path(repository_ctx):
-    """Find Visual C++ build tools install path. Doesn't %-escape the result."""
+def find_vc_path(repository_ctx):
+    """Find Visual C++ build tools install path. Doesn't %-escape the result.
+
+    Args:
+        repository_ctx: The repository context.
+
+    Returns:
+        The path to the Visual C++ build tools installation.
+    """
 
     # 1. Check if BAZEL_VC or BAZEL_VS is already set by user.
     bazel_vc = _get_path_env_var(repository_ctx, "BAZEL_VC")
@@ -136,7 +163,27 @@ def _find_vc_path(repository_ctx):
         " installed.",
     )
 
-    # 2. Check if VS%VS_VERSION%COMNTOOLS is set, if true then try to find and use
+    # 2. Use vswhere to locate all Visual Studio installations
+    program_files_dir = _get_path_env_var(repository_ctx, "PROGRAMFILES(X86)")
+    if not program_files_dir:
+        program_files_dir = "C:\\Program Files (x86)"
+        auto_configure_warning_maybe(
+            repository_ctx,
+            "'PROGRAMFILES(X86)' environment variable is not set, using '%s' as default" % program_files_dir,
+        )
+
+    vswhere_binary = program_files_dir + "\\Microsoft Visual Studio\\Installer\\vswhere.exe"
+    if repository_ctx.path(vswhere_binary).exists:
+        result = repository_ctx.execute([vswhere_binary, "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath", "-latest"])
+        auto_configure_warning_maybe(repository_ctx, "vswhere query result:\n\nSTDOUT(start)\n%s\nSTDOUT(end)\nSTDERR(start):\n%s\nSTDERR(end)\n" %
+                                                     (result.stdout, result.stderr))
+        installation_path = result.stdout.strip()
+        if not result.stderr and installation_path:
+            vc_dir = installation_path + "\\VC"
+            auto_configure_warning_maybe(repository_ctx, "Visual C++ build tools found at %s" % vc_dir)
+            return vc_dir
+
+    # 3. Check if VS%VS_VERSION%COMNTOOLS is set, if true then try to find and use
     # vcvarsqueryregistry.bat / VsDevCmd.bat to detect VC++.
     auto_configure_warning_maybe(repository_ctx, "Looking for VS%VERSION%COMNTOOLS environment variables, " +
                                                  "eg. VS140COMNTOOLS")
@@ -149,15 +196,16 @@ def _find_vc_path(repository_ctx):
         ("VS100COMNTOOLS", "vcvarsqueryregistry.bat"),
         ("VS90COMNTOOLS", "vcvarsqueryregistry.bat"),
     ]:
-        if vscommontools_env not in repository_ctx.os.environ:
+        path = _get_path_env_var(repository_ctx, vscommontools_env)
+        if path == None:
             continue
-        script = _get_path_env_var(repository_ctx, vscommontools_env) + "\\" + script
+        script = path + "\\" + script
         if not repository_ctx.path(script).exists:
             continue
         repository_ctx.file(
             "get_vc_dir.bat",
             "@echo off\n" +
-            "call \"" + script + "\"\n" +
+            "call \"" + script + "\" > NUL\n" +
             "echo %VCINSTALLDIR%",
             True,
         )
@@ -167,9 +215,8 @@ def _find_vc_path(repository_ctx):
         auto_configure_warning_maybe(repository_ctx, "Visual C++ build tools found at %s" % vc_dir)
         return vc_dir
 
-    # 3. User might have purged all environment variables. If so, look for Visual C++ in registry.
+    # 4. User might have purged all environment variables. If so, look for Visual C++ in registry.
     # Works for Visual Studio 2017 and older. (Does not work for Visual Studio 2019 Preview.)
-    # TODO(laszlocsomor): check if "16.0" also has this registry key, after VS 2019 is released.
     auto_configure_warning_maybe(repository_ctx, "Looking for Visual C++ through registry")
     reg_binary = _get_system_root(repository_ctx) + "\\system32\\reg.exe"
     vc_dir = None
@@ -189,25 +236,13 @@ def _find_vc_path(repository_ctx):
         auto_configure_warning_maybe(repository_ctx, "Visual C++ build tools found at %s" % vc_dir)
         return vc_dir
 
-    # 4. Check default directories for VC installation
+    # 5. Check default directories for VC installation
     auto_configure_warning_maybe(repository_ctx, "Looking for default Visual C++ installation directory")
-    program_files_dir = _get_path_env_var(repository_ctx, "PROGRAMFILES(X86)")
-    if not program_files_dir:
-        program_files_dir = "C:\\Program Files (x86)"
-        auto_configure_warning_maybe(
-            repository_ctx,
-            "'PROGRAMFILES(X86)' environment variable is not set, using '%s' as default" % program_files_dir,
-        )
     for path in [
-        "Microsoft Visual Studio\\2019\\Preview\\VC",
-        "Microsoft Visual Studio\\2019\\BuildTools\\VC",
-        "Microsoft Visual Studio\\2019\\Community\\VC",
-        "Microsoft Visual Studio\\2019\\Professional\\VC",
-        "Microsoft Visual Studio\\2019\\Enterprise\\VC",
-        "Microsoft Visual Studio\\2017\\BuildTools\\VC",
-        "Microsoft Visual Studio\\2017\\Community\\VC",
-        "Microsoft Visual Studio\\2017\\Professional\\VC",
-        "Microsoft Visual Studio\\2017\\Enterprise\\VC",
+        "Microsoft Visual Studio\\%s\\%s\\VC" % (year, edition)
+        for year in (2022, 2019, 2017)
+        for edition in ("Preview", "BuildTools", "Community", "Professional", "Enterprise")
+    ] + [
         "Microsoft Visual Studio 14.0\\VC",
     ]:
         path = program_files_dir + "\\" + path
@@ -221,18 +256,22 @@ def _find_vc_path(repository_ctx):
     auto_configure_warning_maybe(repository_ctx, "Visual C++ build tools found at %s" % vc_dir)
     return vc_dir
 
-def _is_vs_2017_or_2019(vc_path):
-    """Check if the installed VS version is Visual Studio 2017."""
+def _is_vs_2017_or_newer(repository_ctx, vc_path):
+    """Check if the installed VS version is Visual Studio 2017 or newer."""
+
+    # For VS 2017 and later, a `Tools` directory should exist under `BAZEL_VC`
+    return repository_ctx.path(vc_path).get_child("Tools").exists
+
+def _is_msbuildtools(vc_path):
+    """Check if the installed VC version is from MSBuildTools."""
 
-    # In VS 2017 and 2019, the location of VC is like:
-    # C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\
-    # In VS 2015 or older version, it is like:
-    # C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\
-    return vc_path.find("2017") != -1 or vc_path.find("2019") != -1
+    # In MSBuildTools (usually container setup), the location of VC is like:
+    # C:\BuildTools\MSBuild\Microsoft\VC
+    return vc_path.find("BuildTools") != -1 and vc_path.find("MSBuild") != -1
 
 def _find_vcvars_bat_script(repository_ctx, vc_path):
     """Find batch script to set up environment variables for VC. Doesn't %-escape the result."""
-    if _is_vs_2017_or_2019(vc_path):
+    if _is_vs_2017_or_newer(repository_ctx, vc_path):
         vcvars_script = vc_path + "\\Auxiliary\\Build\\VCVARSALL.BAT"
     else:
         vcvars_script = vc_path + "\\VCVARSALL.BAT"
@@ -250,17 +289,49 @@ def _is_support_vcvars_ver(vc_full_version):
 
 def _is_support_winsdk_selection(repository_ctx, vc_path):
     """Windows SDK selection is supported with VC 2017 / 2019 or with full VS 2015 installation."""
-    if _is_vs_2017_or_2019(vc_path):
+    if _is_vs_2017_or_newer(repository_ctx, vc_path):
         return True
 
     # By checking the source code of VCVARSALL.BAT in VC 2015, we know that
     # when devenv.exe or wdexpress.exe exists, VCVARSALL.BAT supports Windows SDK selection.
-    vc_common_ide = repository_ctx.path(vc_path).dirname.get_child("Common7").get_child("IDE")
+    vc_common_ide = repository_ctx.path(vc_path).dirname.get_child("Common7", "IDE")
     for tool in ["devenv.exe", "wdexpress.exe"]:
         if vc_common_ide.get_child(tool).exists:
             return True
     return False
 
+def _get_vc_env_vars(repository_ctx, vc_path, msvc_vars_x64, target_arch):
+    """Derive the environment variables set of a given target architecture from the environment variables of the x64 target.
+
+       This is done to avoid running VCVARSALL.BAT script for every target architecture.
+
+    Args:
+        repository_ctx: the repository_ctx object
+        vc_path: Visual C++ root directory
+        msvc_vars_x64: values of MSVC toolchain including the environment variables for x64 target architecture
+        target_arch: the target architecture to get its environment variables
+
+    Returns:
+        dictionary of envvars
+    """
+    env = {}
+    if _is_vs_2017_or_newer(repository_ctx, vc_path):
+        lib = msvc_vars_x64["%{msvc_env_lib_x64}"]
+        full_version = _get_vc_full_version(repository_ctx, vc_path)
+        tools_path = "%s\\Tools\\MSVC\\%s\\bin\\HostX64\\%s" % (vc_path, full_version, target_arch)
+
+        # For native windows(10) on arm64 builds host toolchain runs in an emulated x86 environment
+        if not repository_ctx.path(tools_path).exists:
+            tools_path = "%s\\Tools\\MSVC\\%s\\bin\\HostX86\\%s" % (vc_path, full_version, target_arch)
+    else:
+        lib = msvc_vars_x64["%{msvc_env_lib_x64}"].replace("amd64", _targets_lib_folder[target_arch])
+        tools_path = vc_path + "\\bin\\" + _targets_archs[target_arch]
+
+    env["INCLUDE"] = msvc_vars_x64["%{msvc_env_include_x64}"]
+    env["LIB"] = lib.replace("x64", target_arch)
+    env["PATH"] = escape_string(tools_path.replace("\\", "\\\\")) + ";" + msvc_vars_x64["%{msvc_env_path_x64}"]
+    return env
+
 def setup_vc_env_vars(repository_ctx, vc_path, envvars = [], allow_empty = False, escape = True):
     """Get environment variables set by VCVARSALL.BAT script. Doesn't %-escape the result!
 
@@ -292,7 +363,7 @@ def setup_vc_env_vars(repository_ctx, vc_path, envvars = [], allow_empty = False
 
     # Get VC version set by user. Only supports VC 2017 & 2019.
     vcvars_ver = ""
-    if _is_vs_2017_or_2019(vc_path):
+    if _is_vs_2017_or_newer(repository_ctx, vc_path):
         full_version = _get_vc_full_version(repository_ctx, vc_path)
 
         # Because VCVARSALL.BAT is from the latest VC installed, so we check if the latest
@@ -314,6 +385,7 @@ def setup_vc_env_vars(repository_ctx, vc_path, envvars = [], allow_empty = False
     for env in envs:
         key, value = env.split("=", 1)
         env_map[key] = escape_string(value.replace("\\", "\\\\")) if escape else value
+
     if not allow_empty:
         _check_env_vars(env_map, cmd, expected = envvars)
     return env_map
@@ -347,48 +419,84 @@ def _get_latest_subversion(repository_ctx, vc_path):
     version_list = sorted(version_list)
     latest_version = version_list[-1][1]
 
-    auto_configure_warning_maybe(repository_ctx, "Found the following VC verisons:\n%s\n\nChoosing the latest version = %s" % ("\n".join(versions), latest_version))
+    auto_configure_warning_maybe(repository_ctx, "Found the following VC versions:\n%s\n\nChoosing the latest version = %s" % ("\n".join(versions), latest_version))
     return latest_version
 
 def _get_vc_full_version(repository_ctx, vc_path):
     """Return the value of BAZEL_VC_FULL_VERSION if defined, otherwise the latest version."""
-    if "BAZEL_VC_FULL_VERSION" in repository_ctx.os.environ:
-        return repository_ctx.os.environ["BAZEL_VC_FULL_VERSION"]
+    version = _get_env_var(repository_ctx, "BAZEL_VC_FULL_VERSION")
+    if version != None:
+        return version
     return _get_latest_subversion(repository_ctx, vc_path)
 
 def _get_winsdk_full_version(repository_ctx):
     """Return the value of BAZEL_WINSDK_FULL_VERSION if defined, otherwise an empty string."""
-    return repository_ctx.os.environ.get("BAZEL_WINSDK_FULL_VERSION", default = "")
+    return _get_env_var(repository_ctx, "BAZEL_WINSDK_FULL_VERSION", default = "")
 
-def _find_msvc_tool(repository_ctx, vc_path, tool):
-    """Find the exact path of a specific build tool in MSVC. Doesn't %-escape the result."""
+def _find_msvc_tools(repository_ctx, vc_path, target_arch = "x64"):
+    """Find the exact paths of the build tools in MSVC for the given target. Doesn't %-escape the result."""
+    build_tools_paths = {}
+    tools = _get_target_tools(target_arch)
+    for tool_name in tools:
+        build_tools_paths[tool_name] = find_msvc_tool(repository_ctx, vc_path, tools[tool_name], target_arch)
+    return build_tools_paths
+
+def find_msvc_tool(repository_ctx, vc_path, tool, target_arch = "x64"):
+    """Find the exact path of a specific build tool in MSVC. Doesn't %-escape the result.
+
+    Args:
+        repository_ctx: The repository context.
+        vc_path: Visual C++ root directory.
+        tool: The name of the tool to find.
+        target_arch: The target architecture (default is "x64").
+
+    Returns:
+        The exact path of the specified build tool in MSVC, or None if not found.
+    """
     tool_path = None
-    if _is_vs_2017_or_2019(vc_path):
+    if _is_vs_2017_or_newer(repository_ctx, vc_path) or _is_msbuildtools(vc_path):
         full_version = _get_vc_full_version(repository_ctx, vc_path)
         if full_version:
-            tool_path = "%s\\Tools\\MSVC\\%s\\bin\\HostX64\\x64\\%s" % (vc_path, full_version, tool)
+            tool_path = "%s\\Tools\\MSVC\\%s\\bin\\HostX64\\%s\\%s" % (vc_path, full_version, target_arch, tool)
+
+            # For native windows(10) on arm64 builds host toolchain runs in an emulated x86 environment
+            if not repository_ctx.path(tool_path).exists:
+                tool_path = "%s\\Tools\\MSVC\\%s\\bin\\HostX86\\%s\\%s" % (vc_path, full_version, target_arch, tool)
     else:
         # For VS 2015 and older version, the tools are under:
         # C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\amd64
-        tool_path = vc_path + "\\bin\\amd64\\" + tool
+        tool_path = vc_path + "\\bin\\" + _targets_archs[target_arch] + "\\" + tool
 
     if not tool_path or not repository_ctx.path(tool_path).exists:
         return None
 
     return tool_path.replace("\\", "/")
 
-def _find_missing_vc_tools(repository_ctx, vc_path):
-    """Check if any required tool is missing under given VC path."""
+def _find_missing_vc_tools(repository_ctx, vc_path, target_arch = "x64"):
+    """Check if any required tool for the given target architecture is missing under given VC path."""
     missing_tools = []
     if not _find_vcvars_bat_script(repository_ctx, vc_path):
         missing_tools.append("VCVARSALL.BAT")
 
-    for tool in ["cl.exe", "link.exe", "lib.exe", "ml64.exe"]:
-        if not _find_msvc_tool(repository_ctx, vc_path, tool):
-            missing_tools.append(tool)
-
+    tools = _get_target_tools(target_arch)
+    for tool_name in tools:
+        if not find_msvc_tool(repository_ctx, vc_path, tools[tool_name], target_arch):
+            missing_tools.append(tools[tool_name])
     return missing_tools
 
+def _get_target_tools(target):
+    """Return a list of required tools names and their filenames for a certain target."""
+    tools = {
+        "arm": {"CL": "cl.exe", "DUMPBIN": "dumpbin.exe", "LIB": "lib.exe", "LINK": "link.exe"},
+        "arm64": {"CL": "cl.exe", "DUMPBIN": "dumpbin.exe", "LIB": "lib.exe", "LINK": "link.exe"},
+        "x64": {"CL": "cl.exe", "DUMPBIN": "dumpbin.exe", "LIB": "lib.exe", "LINK": "link.exe", "ML": "ml64.exe"},
+        "x86": {"CL": "cl.exe", "DUMPBIN": "dumpbin.exe", "LIB": "lib.exe", "LINK": "link.exe", "ML": "ml.exe"},
+    }
+    if tools.get(target) == None:
+        auto_configure_fail("Target architecture %s is not recognized" % target)
+
+    return tools.get(target)
+
 def _is_support_debug_fastlink(repository_ctx, linker):
     """Run linker alone to see if it supports /DEBUG:FASTLINK."""
     if _use_clang_cl(repository_ctx):
@@ -397,8 +505,37 @@ def _is_support_debug_fastlink(repository_ctx, linker):
     result = execute(repository_ctx, [linker], expect_failure = True)
     return result.find("/DEBUG[:{FASTLINK|FULL|NONE}]") != -1
 
-def _find_llvm_path(repository_ctx):
-    """Find LLVM install path."""
+def _is_support_parse_showincludes(repository_ctx, cl, env):
+    repository_ctx.file(
+        "main.cpp",
+        "#include \"bazel_showincludes.h\"\nint main(){}\n",
+    )
+    repository_ctx.file(
+        "bazel_showincludes.h",
+        "\n",
+    )
+    result = execute(
+        repository_ctx,
+        [cl, "/nologo", "/showIncludes", "/c", "main.cpp", "/out", "main.exe", "/Fo", "main.obj"],
+        # Attempt to force English language. This may fail if the language pack isn't installed.
+        environment = env | {"VSLANG": "1033"},
+    )
+    for file in ["main.cpp", "bazel_showincludes.h", "main.exe", "main.obj"]:
+        execute(repository_ctx, ["cmd", "/C", "del", file], expect_empty_output = True)
+    return any([
+        line.startswith("Note: including file:") and line.endswith("bazel_showincludes.h")
+        for line in result.split("\n")
+    ])
+
+def find_llvm_path(repository_ctx):
+    """Find LLVM install path.
+
+    Args:
+        repository_ctx: The repository context.
+
+    Returns:
+        The path to the LLVM installation, or None if not found.
+    """
 
     # 1. Check if BAZEL_LLVM is already set by user.
     bazel_llvm = _get_path_env_var(repository_ctx, "BAZEL_LLVM")
@@ -443,8 +580,17 @@ def _find_llvm_path(repository_ctx):
     auto_configure_warning_maybe(repository_ctx, "LLVM installation found at %s" % llvm_dir)
     return llvm_dir
 
-def _find_llvm_tool(repository_ctx, llvm_path, tool):
-    """Find the exact path of a specific build tool in LLVM. Doesn't %-escape the result."""
+def find_llvm_tool(repository_ctx, llvm_path, tool):
+    """Find the exact path of a specific build tool in LLVM. Doesn't %-escape the result.
+
+    Args:
+        repository_ctx: The repository context.
+        llvm_path: The path to the LLVM installation.
+        tool: The name of the tool to find.
+
+    Returns:
+        The exact path of the specified build tool in LLVM, or None if not found.
+    """
     tool_path = llvm_path + "\\bin\\" + tool
 
     if not repository_ctx.path(tool_path).exists:
@@ -454,24 +600,37 @@ def _find_llvm_tool(repository_ctx, llvm_path, tool):
 
 def _use_clang_cl(repository_ctx):
     """Returns True if USE_CLANG_CL is set to 1."""
-    return repository_ctx.os.environ.get("USE_CLANG_CL", default = "0") == "1"
+    return _get_env_var(repository_ctx, "USE_CLANG_CL", default = "0") == "1"
 
 def _find_missing_llvm_tools(repository_ctx, llvm_path):
     """Check if any required tool is missing under given LLVM path."""
     missing_tools = []
     for tool in ["clang-cl.exe", "lld-link.exe", "llvm-lib.exe"]:
-        if not _find_llvm_tool(repository_ctx, llvm_path, tool):
+        if not find_llvm_tool(repository_ctx, llvm_path, tool):
             missing_tools.append(tool)
 
     return missing_tools
 
 def _get_clang_version(repository_ctx, clang_cl):
     result = repository_ctx.execute([clang_cl, "-v"])
-    if result.return_code != 0:
+    first_line = result.stderr.strip().splitlines()[0].strip()
+
+    # The first line of stderr should look like "[vendor ]clang version X.X.X"
+    if result.return_code != 0 or first_line.find("clang version ") == -1:
         auto_configure_fail("Failed to get clang version by running \"%s -v\"" % clang_cl)
+    return first_line.split(" ")[-1]
+
+def _get_clang_dir(repository_ctx, llvm_path, clang_version):
+    """Get the clang installation directory."""
+
+    # The clang_version string format is "X.X.X"
+    clang_dir = llvm_path + "\\lib\\clang\\" + clang_version
+    if repository_ctx.path(clang_dir).exists:
+        return clang_dir
 
-    # Stderr should look like "clang version X.X.X ..."
-    return result.stderr.splitlines()[0].split(" ")[2]
+    # Clang 16 changed the install path to use just the major number.
+    clang_major_version = clang_version.split(".")[0]
+    return llvm_path + "\\lib\\clang\\" + clang_major_version
 
 def _get_msys_mingw_vars(repository_ctx):
     """Get the variables we need to populate the msys/mingw toolchains."""
@@ -488,29 +647,31 @@ def _get_msys_mingw_vars(repository_ctx):
     }
     return msys_mingw_vars
 
-def _get_msvc_vars(repository_ctx, paths):
+def _get_msvc_vars(repository_ctx, paths, target_arch = "x64", msvc_vars_x64 = None):
     """Get the variables we need to populate the MSVC toolchains."""
     msvc_vars = dict()
-    vc_path = _find_vc_path(repository_ctx)
+    vc_path = find_vc_path(repository_ctx)
     missing_tools = None
+
     if not vc_path:
         repository_ctx.template(
-            "vc_installation_error.bat",
+            "vc_installation_error_" + target_arch + ".bat",
             paths["@rules_cc//cc/private/toolchain:vc_installation_error.bat.tpl"],
             {"%{vc_error_message}": ""},
         )
     else:
-        missing_tools = _find_missing_vc_tools(repository_ctx, vc_path)
+        missing_tools = _find_missing_vc_tools(repository_ctx, vc_path, target_arch)
         if missing_tools:
             message = "\r\n".join([
                 "echo. 1>&2",
                 "echo Visual C++ build tools seems to be installed at %s 1>&2" % vc_path,
                 "echo But Bazel can't find the following tools: 1>&2",
                 "echo     %s 1>&2" % ", ".join(missing_tools),
+                "echo for %s target architecture 1>&2" % target_arch,
                 "echo. 1>&2",
             ])
             repository_ctx.template(
-                "vc_installation_error.bat",
+                "vc_installation_error_" + target_arch + ".bat",
                 paths["@rules_cc//cc/private/toolchain:vc_installation_error.bat.tpl"],
                 {"%{vc_error_message}": message},
             )
@@ -518,82 +679,92 @@ def _get_msvc_vars(repository_ctx, paths):
     if not vc_path or missing_tools:
         write_builtin_include_directory_paths(repository_ctx, "msvc", [], file_suffix = "_msvc")
         msvc_vars = {
-            "%{dbg_mode_debug_flag}": "/DEBUG",
-            "%{fastbuild_mode_debug_flag}": "/DEBUG",
-            "%{msvc_cl_path}": "vc_installation_error.bat",
-            "%{msvc_cxx_builtin_include_directories}": "",
-            "%{msvc_env_include}": "msvc_not_found",
-            "%{msvc_env_lib}": "msvc_not_found",
-            "%{msvc_env_path}": "msvc_not_found",
-            "%{msvc_env_tmp}": "msvc_not_found",
-            "%{msvc_lib_path}": "vc_installation_error.bat",
-            "%{msvc_link_path}": "vc_installation_error.bat",
-            "%{msvc_ml_path}": "vc_installation_error.bat",
+            "%{msvc_env_tmp_" + target_arch + "}": "msvc_not_found",
+            "%{msvc_env_include_" + target_arch + "}": "msvc_not_found",
+            "%{msvc_cxx_builtin_include_directories_" + target_arch + "}": "",
+            "%{msvc_env_path_" + target_arch + "}": "msvc_not_found",
+            "%{msvc_env_lib_" + target_arch + "}": "msvc_not_found",
+            "%{msvc_cl_path_" + target_arch + "}": "vc_installation_error_" + target_arch + ".bat",
+            "%{msvc_ml_path_" + target_arch + "}": "vc_installation_error_" + target_arch + ".bat",
+            "%{msvc_link_path_" + target_arch + "}": "vc_installation_error_" + target_arch + ".bat",
+            "%{msvc_lib_path_" + target_arch + "}": "vc_installation_error_" + target_arch + ".bat",
+            "%{dbg_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+            "%{fastbuild_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+            "%{msvc_parse_showincludes_" + target_arch + "}": repr(False),
         }
         return msvc_vars
 
-    env = setup_vc_env_vars(repository_ctx, vc_path)
-    escaped_paths = escape_string(env["PATH"])
-    escaped_include_paths = escape_string(env["INCLUDE"])
-    escaped_lib_paths = escape_string(env["LIB"])
+    if msvc_vars_x64:
+        env = _get_vc_env_vars(repository_ctx, vc_path, msvc_vars_x64, target_arch)
+    else:
+        env = setup_vc_env_vars(repository_ctx, vc_path)
     escaped_tmp_dir = escape_string(_get_temp_env(repository_ctx).replace("\\", "\\\\"))
+    escaped_include_paths = escape_string(env["INCLUDE"])
 
+    build_tools = {}
     llvm_path = ""
     if _use_clang_cl(repository_ctx):
-        llvm_path = _find_llvm_path(repository_ctx)
+        llvm_path = find_llvm_path(repository_ctx)
         if not llvm_path:
             auto_configure_fail("\nUSE_CLANG_CL is set to 1, but Bazel cannot find Clang installation on your system.\n" +
                                 "Please install Clang via http://releases.llvm.org/download.html\n")
-        cl_path = _find_llvm_tool(repository_ctx, llvm_path, "clang-cl.exe")
-        link_path = _find_llvm_tool(repository_ctx, llvm_path, "lld-link.exe")
-        if not link_path:
-            link_path = _find_msvc_tool(repository_ctx, vc_path, "link.exe")
-        lib_path = _find_llvm_tool(repository_ctx, llvm_path, "llvm-lib.exe")
-        if not lib_path:
-            lib_path = _find_msvc_tool(repository_ctx, vc_path, "lib.exe")
+
+        build_tools["CL"] = find_llvm_tool(repository_ctx, llvm_path, "clang-cl.exe")
+        build_tools["ML"] = find_msvc_tool(repository_ctx, vc_path, "ml64.exe", "x64")
+        build_tools["LINK"] = find_llvm_tool(repository_ctx, llvm_path, "lld-link.exe")
+        if not build_tools["LINK"]:
+            build_tools["LINK"] = find_msvc_tool(repository_ctx, vc_path, "link.exe", "x64")
+        build_tools["LIB"] = find_llvm_tool(repository_ctx, llvm_path, "llvm-lib.exe")
+        if not build_tools["LIB"]:
+            build_tools["LIB"] = find_msvc_tool(repository_ctx, vc_path, "lib.exe", "x64")
     else:
-        cl_path = _find_msvc_tool(repository_ctx, vc_path, "cl.exe")
-        link_path = _find_msvc_tool(repository_ctx, vc_path, "link.exe")
-        lib_path = _find_msvc_tool(repository_ctx, vc_path, "lib.exe")
+        build_tools = _find_msvc_tools(repository_ctx, vc_path, target_arch)
 
-    msvc_ml_path = _find_msvc_tool(repository_ctx, vc_path, "ml64.exe")
     escaped_cxx_include_directories = []
-
     for path in escaped_include_paths.split(";"):
         if path:
             escaped_cxx_include_directories.append("\"%s\"" % path)
     if llvm_path:
-        clang_version = _get_clang_version(repository_ctx, cl_path)
-        clang_dir = llvm_path + "\\lib\\clang\\" + clang_version
+        clang_version = _get_clang_version(repository_ctx, build_tools["CL"])
+        clang_dir = _get_clang_dir(repository_ctx, llvm_path, clang_version)
         clang_include_path = (clang_dir + "\\include").replace("\\", "\\\\")
         escaped_cxx_include_directories.append("\"%s\"" % clang_include_path)
         clang_lib_path = (clang_dir + "\\lib\\windows").replace("\\", "\\\\")
-        escaped_lib_paths = escaped_lib_paths + ";" + clang_lib_path
-
-    support_debug_fastlink = _is_support_debug_fastlink(repository_ctx, link_path)
+        env["LIB"] = escape_string(env["LIB"]) + ";" + clang_lib_path
 
+    support_debug_fastlink = _is_support_debug_fastlink(repository_ctx, build_tools["LINK"])
     write_builtin_include_directory_paths(repository_ctx, "msvc", escaped_cxx_include_directories, file_suffix = "_msvc")
+
+    support_parse_showincludes = _is_support_parse_showincludes(repository_ctx, build_tools["CL"], env)
+    if not support_parse_showincludes:
+        auto_configure_warning("""
+Header pruning has been disabled since Bazel failed to recognize the output of /showIncludes.
+This can result in unnecessary recompilation.
+Fix this by installing the English language pack for the Visual Studio installation at {} and run 'bazel sync --configure'.""".format(vc_path))
+
     msvc_vars = {
-        "%{dbg_mode_debug_flag}": "/DEBUG:FULL" if support_debug_fastlink else "/DEBUG",
-        "%{fastbuild_mode_debug_flag}": "/DEBUG:FASTLINK" if support_debug_fastlink else "/DEBUG",
-        "%{msvc_cl_path}": cl_path,
-        "%{msvc_cxx_builtin_include_directories}": "        " + ",\n        ".join(escaped_cxx_include_directories),
-        "%{msvc_env_include}": escaped_include_paths,
-        "%{msvc_env_lib}": escaped_lib_paths,
-        "%{msvc_env_path}": escaped_paths,
-        "%{msvc_env_tmp}": escaped_tmp_dir,
-        "%{msvc_lib_path}": lib_path,
-        "%{msvc_link_path}": link_path,
-        "%{msvc_ml_path}": msvc_ml_path,
+        "%{msvc_env_tmp_" + target_arch + "}": escaped_tmp_dir,
+        "%{msvc_env_include_" + target_arch + "}": escaped_include_paths,
+        "%{msvc_cxx_builtin_include_directories_" + target_arch + "}": "        " + ",\n        ".join(escaped_cxx_include_directories),
+        "%{msvc_env_path_" + target_arch + "}": escape_string(env["PATH"]),
+        "%{msvc_env_lib_" + target_arch + "}": escape_string(env["LIB"]),
+        "%{msvc_cl_path_" + target_arch + "}": build_tools["CL"],
+        "%{msvc_ml_path_" + target_arch + "}": build_tools.get("ML", "msvc_arm_toolchain_does_not_support_ml"),
+        "%{msvc_link_path_" + target_arch + "}": build_tools["LINK"],
+        "%{msvc_lib_path_" + target_arch + "}": build_tools["LIB"],
+        "%{msvc_dumpbin_path_" + target_arch + "}": build_tools["DUMPBIN"],
+        "%{msvc_parse_showincludes_" + target_arch + "}": repr(support_parse_showincludes),
+        "%{dbg_mode_debug_flag_" + target_arch + "}": "/DEBUG:FULL" if support_debug_fastlink else "/DEBUG",
+        "%{fastbuild_mode_debug_flag_" + target_arch + "}": "/DEBUG:FASTLINK" if support_debug_fastlink else "/DEBUG",
     }
     return msvc_vars
 
-def _get_clang_cl_vars(repository_ctx, paths, msvc_vars):
+def _get_clang_cl_vars(repository_ctx, paths, msvc_vars, target_arch):
     """Get the variables we need to populate the clang-cl toolchains."""
-    llvm_path = _find_llvm_path(repository_ctx)
+    llvm_path = find_llvm_path(repository_ctx)
     error_script = None
-    if msvc_vars["%{msvc_cl_path}"] == "vc_installation_error.bat":
-        error_script = "vc_installation_error.bat"
+    if msvc_vars["%{msvc_cl_path_" + target_arch + "}"] == "vc_installation_error_{}.bat".format(target_arch):
+        error_script = "vc_installation_error_{}.bat".format(target_arch)
     elif not llvm_path:
         repository_ctx.template(
             "clang_installation_error.bat",
@@ -621,52 +792,69 @@ def _get_clang_cl_vars(repository_ctx, paths, msvc_vars):
     if error_script:
         write_builtin_include_directory_paths(repository_ctx, "clang-cl", [], file_suffix = "_clangcl")
         clang_cl_vars = {
-            "%{clang_cl_cl_path}": error_script,
-            "%{clang_cl_cxx_builtin_include_directories}": "",
-            "%{clang_cl_dbg_mode_debug_flag}": "/DEBUG",
-            "%{clang_cl_env_include}": "clang_cl_not_found",
-            "%{clang_cl_env_lib}": "clang_cl_not_found",
-            "%{clang_cl_env_path}": "clang_cl_not_found",
-            "%{clang_cl_env_tmp}": "clang_cl_not_found",
-            "%{clang_cl_fastbuild_mode_debug_flag}": "/DEBUG",
-            "%{clang_cl_lib_path}": error_script,
-            "%{clang_cl_link_path}": error_script,
-            "%{clang_cl_ml_path}": error_script,
+            "%{clang_cl_env_tmp_" + target_arch + "}": "clang_cl_not_found",
+            "%{clang_cl_env_path_" + target_arch + "}": "clang_cl_not_found",
+            "%{clang_cl_env_include_" + target_arch + "}": "clang_cl_not_found",
+            "%{clang_cl_env_lib_" + target_arch + "}": "clang_cl_not_found",
+            "%{clang_cl_cl_path_" + target_arch + "}": error_script,
+            "%{clang_cl_link_path_" + target_arch + "}": error_script,
+            "%{clang_cl_lib_path_" + target_arch + "}": error_script,
+            "%{clang_cl_ml_path_" + target_arch + "}": error_script,
+            "%{clang_cl_dbg_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+            "%{clang_cl_fastbuild_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+            "%{clang_cl_cxx_builtin_include_directories_" + target_arch + "}": "",
+            "%{clang_cl_parse_showincludes_" + target_arch + "}": repr(False),
         }
         return clang_cl_vars
 
-    clang_cl_path = _find_llvm_tool(repository_ctx, llvm_path, "clang-cl.exe")
-    lld_link_path = _find_llvm_tool(repository_ctx, llvm_path, "lld-link.exe")
-    llvm_lib_path = _find_llvm_tool(repository_ctx, llvm_path, "llvm-lib.exe")
+    clang_cl_path = find_llvm_tool(repository_ctx, llvm_path, "clang-cl.exe")
+    lld_link_path = find_llvm_tool(repository_ctx, llvm_path, "lld-link.exe")
+    llvm_lib_path = find_llvm_tool(repository_ctx, llvm_path, "llvm-lib.exe")
 
     clang_version = _get_clang_version(repository_ctx, clang_cl_path)
-    clang_dir = llvm_path + "\\lib\\clang\\" + clang_version
+    clang_dir = _get_clang_dir(repository_ctx, llvm_path, clang_version)
     clang_include_path = (clang_dir + "\\include").replace("\\", "\\\\")
     clang_lib_path = (clang_dir + "\\lib\\windows").replace("\\", "\\\\")
 
-    clang_cl_include_directories = msvc_vars["%{msvc_cxx_builtin_include_directories}"] + (",\n        \"%s\"" % clang_include_path)
+    clang_cl_include_directories = msvc_vars["%{msvc_cxx_builtin_include_directories_" + target_arch + "}"] + (",\n        \"%s\"" % clang_include_path)
     write_builtin_include_directory_paths(repository_ctx, "clang-cl", [clang_cl_include_directories], file_suffix = "_clangcl")
     clang_cl_vars = {
-        "%{clang_cl_cl_path}": clang_cl_path,
-        "%{clang_cl_cxx_builtin_include_directories}": clang_cl_include_directories,
+        "%{clang_cl_env_tmp_" + target_arch + "}": msvc_vars["%{msvc_env_tmp_" + target_arch + "}"],
+        "%{clang_cl_env_path_" + target_arch + "}": msvc_vars["%{msvc_env_path_" + target_arch + "}"],
+        "%{clang_cl_env_include_" + target_arch + "}": msvc_vars["%{msvc_env_include_" + target_arch + "}"] + ";" + clang_include_path,
+        "%{clang_cl_env_lib_" + target_arch + "}": msvc_vars["%{msvc_env_lib_" + target_arch + "}"] + ";" + clang_lib_path,
+        "%{clang_cl_cxx_builtin_include_directories_" + target_arch + "}": clang_cl_include_directories,
+        "%{clang_cl_cl_path_" + target_arch + "}": clang_cl_path,
+        "%{clang_cl_link_path_" + target_arch + "}": lld_link_path,
+        "%{clang_cl_lib_path_" + target_arch + "}": llvm_lib_path,
+        # clang-cl does not support assembly files as input.
+        "%{clang_cl_ml_path_" + target_arch + "}": msvc_vars["%{msvc_ml_path_" + target_arch + "}"],
         # LLVM's lld-link.exe doesn't support /DEBUG:FASTLINK.
-        "%{clang_cl_dbg_mode_debug_flag}": "/DEBUG",
-        "%{clang_cl_env_include}": msvc_vars["%{msvc_env_include}"] + ";" + clang_include_path,
-        "%{clang_cl_env_lib}": msvc_vars["%{msvc_env_lib}"] + ";" + clang_lib_path,
-        "%{clang_cl_env_path}": msvc_vars["%{msvc_env_path}"],
-        "%{clang_cl_env_tmp}": msvc_vars["%{msvc_env_tmp}"],
-        "%{clang_cl_fastbuild_mode_debug_flag}": "/DEBUG",
-        "%{clang_cl_lib_path}": llvm_lib_path,
-        "%{clang_cl_link_path}": lld_link_path,
-        "%{clang_cl_ml_path}": msvc_vars["%{msvc_ml_path}"],
+        "%{clang_cl_dbg_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+        "%{clang_cl_fastbuild_mode_debug_flag_" + target_arch + "}": "/DEBUG",
+        # clang-cl always emits the English language version of the /showIncludes prefix.
+        "%{clang_cl_parse_showincludes_" + target_arch + "}": repr(True),
     }
     return clang_cl_vars
 
+def _get_msvc_deps_scanner_vars(repository_ctx, paths, template_vars, target_arch = "x64"):
+    repository_ctx.template(
+        "msvc_deps_scanner_wrapper_" + target_arch + ".bat",
+        paths["@rules_cc//cc/private/toolchain:msvc_deps_scanner_wrapper.bat.tpl"],
+        {
+            "%{cc}": template_vars["%{msvc_cl_path_" + target_arch + "}"],
+        },
+    )
+
+    return {
+        "%{msvc_deps_scanner_wrapper_path_" + target_arch + "}": "msvc_deps_scanner_wrapper_" + target_arch + ".bat",
+    }
+
 def configure_windows_toolchain(repository_ctx):
     """Configure C++ toolchain on Windows.
 
     Args:
-      repository_ctx: The repository context.
+        repository_ctx: The repository context.
     """
     paths = resolve_labels(repository_ctx, [
         "@rules_cc//cc/private/toolchain:BUILD.windows.tpl",
@@ -675,6 +863,7 @@ def configure_windows_toolchain(repository_ctx):
         "@rules_cc//cc/private/toolchain:vc_installation_error.bat.tpl",
         "@rules_cc//cc/private/toolchain:msys_gcc_installation_error.bat",
         "@rules_cc//cc/private/toolchain:clang_installation_error.bat.tpl",
+        "@rules_cc//cc/private/toolchain:msvc_deps_scanner_wrapper.bat.tpl",
     ])
 
     repository_ctx.symlink(
@@ -691,11 +880,20 @@ def configure_windows_toolchain(repository_ctx):
     )
 
     template_vars = dict()
-    msvc_vars = _get_msvc_vars(repository_ctx, paths)
-    template_vars.update(msvc_vars)
-    template_vars.update(_get_clang_cl_vars(repository_ctx, paths, msvc_vars))
+    msvc_vars_x64 = _get_msvc_vars(repository_ctx, paths, "x64")
+    template_vars.update(msvc_vars_x64)
+    template_vars.update(_get_clang_cl_vars(repository_ctx, paths, msvc_vars_x64, "x64"))
     template_vars.update(_get_msys_mingw_vars(repository_ctx))
-
+    template_vars.update(_get_msvc_vars(repository_ctx, paths, "x86", msvc_vars_x64))
+    template_vars.update(_get_msvc_vars(repository_ctx, paths, "arm", msvc_vars_x64))
+    msvc_vars_arm64 = _get_msvc_vars(repository_ctx, paths, "arm64", msvc_vars_x64)
+    template_vars.update(msvc_vars_arm64)
+    template_vars.update(_get_clang_cl_vars(repository_ctx, paths, msvc_vars_arm64, "arm64"))
+
+    template_vars.update(_get_msvc_deps_scanner_vars(repository_ctx, paths, template_vars, "x64"))
+    template_vars.update(_get_msvc_deps_scanner_vars(repository_ctx, paths, template_vars, "x86"))
+    template_vars.update(_get_msvc_deps_scanner_vars(repository_ctx, paths, template_vars, "arm"))
+    template_vars.update(_get_msvc_deps_scanner_vars(repository_ctx, paths, template_vars, "arm64"))
     repository_ctx.template(
         "BUILD",
         paths["@rules_cc//cc/private/toolchain:BUILD.windows.tpl"],
diff --git a/cc/private/toolchain/windows_cc_toolchain_config.bzl b/cc/private/toolchain/windows_cc_toolchain_config.bzl
index 7fa2978..76cd586 100644
--- a/cc/private/toolchain/windows_cc_toolchain_config.bzl
+++ b/cc/private/toolchain/windows_cc_toolchain_config.bzl
@@ -22,9 +22,9 @@ load(
     "env_entry",
     "env_set",
     "feature",
-    "feature_set",
     "flag_group",
     "flag_set",
+    "make_variable",
     "tool",
     "tool_path",
     "variable_with_value",
@@ -40,6 +40,9 @@ all_compile_actions = [
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.clif_match,
     ACTION_NAMES.lto_backend,
 ]
@@ -50,6 +53,9 @@ all_cpp_compile_actions = [
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.clif_match,
 ]
 
@@ -60,6 +66,8 @@ preprocessor_compile_actions = [
     ACTION_NAMES.preprocess_assemble,
     ACTION_NAMES.cpp_header_parsing,
     ACTION_NAMES.cpp_module_compile,
+    ACTION_NAMES.cpp_module_deps_scanning,
+    ACTION_NAMES.cpp20_module_compile,
     ACTION_NAMES.clif_match,
 ]
 
@@ -70,6 +78,7 @@ codegen_compile_actions = [
     ACTION_NAMES.assemble,
     ACTION_NAMES.preprocess_assemble,
     ACTION_NAMES.cpp_module_codegen,
+    ACTION_NAMES.cpp20_module_codegen,
     ACTION_NAMES.lto_backend,
 ]
 
@@ -80,7 +89,7 @@ all_link_actions = [
 ]
 
 def _use_msvc_toolchain(ctx):
-    return ctx.attr.cpu == "x64_windows" and (ctx.attr.compiler == "msvc-cl" or ctx.attr.compiler == "clang-cl")
+    return ctx.attr.cpu in ["x64_windows", "arm64_windows"] and (ctx.attr.compiler == "msvc-cl" or ctx.attr.compiler == "clang-cl")
 
 def _impl(ctx):
     if _use_msvc_toolchain(ctx):
@@ -135,7 +144,6 @@ def _impl(ctx):
                 "output_execpath_flags",
                 "input_param_flags",
                 "user_link_flags",
-                "default_link_flags",
                 "linker_subsystem_flag",
                 "linker_param_file",
                 "msvc_env",
@@ -184,13 +192,25 @@ def _impl(ctx):
 
         c_compile_action = action_config(
             action_name = ACTION_NAMES.c_compile,
+            implies = [
+                "compiler_input_flags",
+                "compiler_output_flags",
+                "nologo",
+                "msvc_env",
+                "user_compile_flags",
+                "sysroot",
+            ],
+            tools = [tool(path = ctx.attr.msvc_cl_path)],
+        )
+
+        linkstamp_compile_action = action_config(
+            action_name = ACTION_NAMES.linkstamp_compile,
             implies = [
                 "compiler_input_flags",
                 "compiler_output_flags",
                 "default_compile_flags",
                 "nologo",
                 "msvc_env",
-                "parse_showincludes",
                 "user_compile_flags",
                 "sysroot",
                 "unfiltered_compile_flags",
@@ -203,13 +223,10 @@ def _impl(ctx):
             implies = [
                 "compiler_input_flags",
                 "compiler_output_flags",
-                "default_compile_flags",
                 "nologo",
                 "msvc_env",
-                "parse_showincludes",
                 "user_compile_flags",
                 "sysroot",
-                "unfiltered_compile_flags",
             ],
             tools = [tool(path = ctx.attr.msvc_cl_path)],
         )
@@ -222,7 +239,6 @@ def _impl(ctx):
                 "output_execpath_flags",
                 "input_param_flags",
                 "user_link_flags",
-                "default_link_flags",
                 "linker_subsystem_flag",
                 "linker_param_file",
                 "msvc_env",
@@ -240,7 +256,6 @@ def _impl(ctx):
                 "output_execpath_flags",
                 "input_param_flags",
                 "user_link_flags",
-                "default_link_flags",
                 "linker_subsystem_flag",
                 "linker_param_file",
                 "msvc_env",
@@ -251,15 +266,84 @@ def _impl(ctx):
             tools = [tool(path = ctx.attr.msvc_link_path)],
         )
 
+        deps_scanner = "cpp-module-deps-scanner_not_found"
+        if "cpp-module-deps-scanner" in ctx.attr.tool_paths:
+            deps_scanner = ctx.attr.tool_paths["cpp-module-deps-scanner"]
+        cpp_module_scan_deps = action_config(
+            action_name = ACTION_NAMES.cpp_module_deps_scanning,
+            tools = [
+                tool(
+                    path = deps_scanner,
+                ),
+            ],
+            implies = [
+                "compiler_input_flags",
+                "compiler_output_flags",
+                "nologo",
+                "msvc_env",
+                "user_compile_flags",
+                "sysroot",
+            ],
+        )
+
+        cpp20_module_compile = action_config(
+            action_name = ACTION_NAMES.cpp20_module_compile,
+            tools = [
+                tool(
+                    path = ctx.attr.msvc_cl_path,
+                ),
+            ],
+            flag_sets = [
+                flag_set(
+                    flag_groups = [
+                        flag_group(
+                            flags = [
+                                "/TP",
+                                "/interface",
+                            ],
+                        ),
+                    ],
+                ),
+            ],
+            implies = [
+                "compiler_input_flags",
+                "compiler_output_flags",
+                "nologo",
+                "msvc_env",
+                "user_compile_flags",
+                "sysroot",
+            ],
+        )
+
+        cpp20_module_codegen = action_config(
+            action_name = ACTION_NAMES.cpp20_module_codegen,
+            tools = [
+                tool(
+                    path = ctx.attr.msvc_cl_path,
+                ),
+            ],
+            implies = [
+                "compiler_input_flags",
+                "compiler_output_flags",
+                "nologo",
+                "msvc_env",
+                "user_compile_flags",
+                "sysroot",
+            ],
+        )
         action_configs = [
             assemble_action,
             preprocess_assemble_action,
             c_compile_action,
+            linkstamp_compile_action,
             cpp_compile_action,
             cpp_link_executable_action,
             cpp_link_dynamic_library_action,
             cpp_link_nodeps_dynamic_library_action,
             cpp_link_static_library_action,
+            cpp_module_scan_deps,
+            cpp20_module_compile,
+            cpp20_module_codegen,
         ]
     else:
         action_configs = []
@@ -317,10 +401,14 @@ def _impl(ctx):
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.cpp_link_executable,
                         ACTION_NAMES.cpp_link_dynamic_library,
                         ACTION_NAMES.cpp_link_nodeps_dynamic_library,
@@ -338,15 +426,20 @@ def _impl(ctx):
 
         unfiltered_compile_flags_feature = feature(
             name = "unfiltered_compile_flags",
+            enabled = True,
             flag_sets = [
                 flag_set(
                     actions = [
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                     ],
                     flag_groups = [
                         flag_group(
@@ -359,8 +452,14 @@ def _impl(ctx):
             ],
         )
 
+        archive_param_file_feature = feature(
+            name = "archive_param_file",
+            enabled = True,
+        )
+
         compiler_param_file_feature = feature(
             name = "compiler_param_file",
+            enabled = True,
         )
 
         copy_dynamic_libraries_to_binary_feature = feature(
@@ -471,10 +570,14 @@ def _impl(ctx):
                     actions = [
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                     ],
                     flag_groups = [
                         flag_group(
@@ -498,7 +601,12 @@ def _impl(ctx):
                             expand_if_available = "output_execpath",
                         ),
                         flag_group(
-                            flags = ["/MACHINE:X64"],
+                            flags = ["%{user_archiver_flags}"],
+                            iterate_over = "user_archiver_flags",
+                            expand_if_available = "user_archiver_flags",
+                        ),
+                        flag_group(
+                            flags = ctx.attr.archiver_flags,
                         ),
                     ],
                 ),
@@ -516,21 +624,57 @@ def _impl(ctx):
             ],
         )
 
-        static_link_msvcrt_feature = feature(name = "static_link_msvcrt")
+        static_link_msvcrt_feature = feature(
+            name = "static_link_msvcrt",
+            flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = ["/MT"])],
+                    with_features = [with_feature_set(not_features = ["dbg"])],
+                ),
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = ["/MTd"])],
+                    with_features = [with_feature_set(features = ["dbg"])],
+                ),
+                flag_set(
+                    actions = all_link_actions,
+                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:libcmt.lib"])],
+                    with_features = [with_feature_set(not_features = ["dbg"])],
+                ),
+                flag_set(
+                    actions = all_link_actions,
+                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:libcmtd.lib"])],
+                    with_features = [with_feature_set(features = ["dbg"])],
+                ),
+            ],
+        )
 
-        dynamic_link_msvcrt_debug_feature = feature(
-            name = "dynamic_link_msvcrt_debug",
+        dynamic_link_msvcrt_feature = feature(
+            name = "dynamic_link_msvcrt",
+            enabled = True,
             flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = ["/MD"])],
+                    with_features = [with_feature_set(not_features = ["dbg", "static_link_msvcrt"])],
+                ),
                 flag_set(
                     actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
                     flag_groups = [flag_group(flags = ["/MDd"])],
+                    with_features = [with_feature_set(features = ["dbg"], not_features = ["static_link_msvcrt"])],
+                ),
+                flag_set(
+                    actions = all_link_actions,
+                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:msvcrt.lib"])],
+                    with_features = [with_feature_set(not_features = ["dbg", "static_link_msvcrt"])],
                 ),
                 flag_set(
                     actions = all_link_actions,
                     flag_groups = [flag_group(flags = ["/DEFAULTLIB:msvcrtd.lib"])],
+                    with_features = [with_feature_set(features = ["dbg"], not_features = ["static_link_msvcrt"])],
                 ),
             ],
-            requires = [feature_set(features = ["dbg"])],
         )
 
         dbg_feature = feature(
@@ -598,6 +742,9 @@ def _impl(ctx):
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.lto_backend,
                         ACTION_NAMES.clif_match,
                     ],
@@ -629,10 +776,14 @@ def _impl(ctx):
                 env_set(
                     actions = [
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
                         ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                     ],
@@ -650,9 +801,12 @@ def _impl(ctx):
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
                     ],
                     flag_groups = [
                         flag_group(
@@ -668,14 +822,18 @@ def _impl(ctx):
             name = "generate_pdb_file",
         )
 
-        output_execpath_flags_feature = feature(
-            name = "output_execpath_flags",
+        generate_linkmap_feature = feature(
+            name = "generate_linkmap",
             flag_sets = [
                 flag_set(
-                    actions = all_link_actions,
+                    actions = [
+                        ACTION_NAMES.cpp_link_executable,
+                    ],
                     flag_groups = [
                         flag_group(
-                            flags = ["/OUT:%{output_execpath}"],
+                            flags = [
+                                "/MAP:%{output_execpath}.map",
+                            ],
                             expand_if_available = "output_execpath",
                         ),
                     ],
@@ -683,22 +841,19 @@ def _impl(ctx):
             ],
         )
 
-        dynamic_link_msvcrt_no_debug_feature = feature(
-            name = "dynamic_link_msvcrt_no_debug",
+        output_execpath_flags_feature = feature(
+            name = "output_execpath_flags",
             flag_sets = [
-                flag_set(
-                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
-                    flag_groups = [flag_group(flags = ["/MD"])],
-                ),
                 flag_set(
                     actions = all_link_actions,
-                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:msvcrt.lib"])],
+                    flag_groups = [
+                        flag_group(
+                            flags = ["/OUT:%{output_execpath}"],
+                            expand_if_available = "output_execpath",
+                        ),
+                    ],
                 ),
             ],
-            requires = [
-                feature_set(features = ["fastbuild"]),
-                feature_set(features = ["opt"]),
-            ],
         )
 
         disable_assertions_feature = feature(
@@ -750,43 +905,50 @@ def _impl(ctx):
 
         parse_showincludes_feature = feature(
             name = "parse_showincludes",
+            enabled = ctx.attr.supports_parse_showincludes,
             flag_sets = [
                 flag_set(
                     actions = [
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
                     ],
                     flag_groups = [flag_group(flags = ["/showIncludes"])],
                 ),
             ],
-        )
-
-        static_link_msvcrt_no_debug_feature = feature(
-            name = "static_link_msvcrt_no_debug",
-            flag_sets = [
-                flag_set(
-                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
-                    flag_groups = [flag_group(flags = ["/MT"])],
-                ),
-                flag_set(
-                    actions = all_link_actions,
-                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:libcmt.lib"])],
+            env_sets = [
+                env_set(
+                    actions = [
+                        ACTION_NAMES.preprocess_assemble,
+                        ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
+                        ACTION_NAMES.cpp_compile,
+                        ACTION_NAMES.cpp_module_compile,
+                        ACTION_NAMES.cpp_header_parsing,
+                    ],
+                    # Force English (and thus a consistent locale) output so that Bazel can parse
+                    # the /showIncludes output without having to guess the encoding.
+                    env_entries = [env_entry(key = "VSLANG", value = "1033")],
                 ),
             ],
-            requires = [
-                feature_set(features = ["fastbuild"]),
-                feature_set(features = ["opt"]),
-            ],
+        )
+
+        # MSVC does not emit .d files.
+        no_dotd_file_feature = feature(
+            name = "no_dotd_file",
+            enabled = True,
         )
 
         treat_warnings_as_errors_feature = feature(
             name = "treat_warnings_as_errors",
             flag_sets = [
                 flag_set(
-                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile] + all_link_actions,
                     flag_groups = [flag_group(flags = ["/WX"])],
                 ),
             ],
@@ -805,6 +967,7 @@ def _impl(ctx):
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
@@ -827,6 +990,34 @@ def _impl(ctx):
             ],
         )
 
+        external_include_paths_feature = feature(
+            name = "external_include_paths",
+            flag_sets = [
+                flag_set(
+                    actions = [
+                        ACTION_NAMES.preprocess_assemble,
+                        ACTION_NAMES.linkstamp_compile,
+                        ACTION_NAMES.c_compile,
+                        ACTION_NAMES.cpp_compile,
+                        ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_compile,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.clif_match,
+                        ACTION_NAMES.objc_compile,
+                        ACTION_NAMES.objcpp_compile,
+                    ],
+                    flag_groups = [
+                        flag_group(
+                            flags = ["/external:I%{external_include_paths}"],
+                            iterate_over = "external_include_paths",
+                            expand_if_available = "external_include_paths",
+                        ),
+                    ],
+                ),
+            ],
+        )
+
         linkstamps_feature = feature(
             name = "linkstamps",
             flag_sets = [
@@ -859,21 +1050,6 @@ def _impl(ctx):
             ],
         )
 
-        static_link_msvcrt_debug_feature = feature(
-            name = "static_link_msvcrt_debug",
-            flag_sets = [
-                flag_set(
-                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
-                    flag_groups = [flag_group(flags = ["/MTd"])],
-                ),
-                flag_set(
-                    actions = all_link_actions,
-                    flag_groups = [flag_group(flags = ["/DEFAULTLIB:libcmtd.lib"])],
-                ),
-            ],
-            requires = [feature_set(features = ["dbg"])],
-        )
-
         frame_pointer_feature = feature(
             name = "frame_pointer",
             flag_sets = [
@@ -906,10 +1082,14 @@ def _impl(ctx):
                     actions = [
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                     ],
                     flag_groups = [
                         flag_group(
@@ -951,10 +1131,14 @@ def _impl(ctx):
                 flag_set(
                     actions = [
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
                         ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.cpp_link_executable,
@@ -984,6 +1168,17 @@ def _impl(ctx):
             ],
         )
 
+        remove_unreferenced_code_feature = feature(
+            name = "remove_unreferenced_code",
+            enabled = True,
+            flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = ["/Zc:inline"])],
+                ),
+            ],
+        )
+
         compiler_input_flags_feature = feature(
             name = "compiler_input_flags",
             flag_sets = [
@@ -992,10 +1187,14 @@ def _impl(ctx):
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                     ],
                     flag_groups = [
                         flag_group(
@@ -1028,10 +1227,14 @@ def _impl(ctx):
                 env_set(
                     actions = [
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
                         ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.cpp_link_executable,
@@ -1048,6 +1251,17 @@ def _impl(ctx):
             ],
             implies = ["msvc_compile_env", "msvc_link_env"],
         )
+
+        symbol_check_feature = feature(
+            name = "symbol_check",
+            flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.cpp_link_static_library],
+                    flag_groups = [flag_group(flags = ["/WX:4006"])],
+                ),
+            ],
+        )
+
         features = [
             no_legacy_features_feature,
             nologo_feature,
@@ -1060,9 +1274,12 @@ def _impl(ctx):
             msvc_compile_env_feature,
             msvc_link_env_feature,
             include_paths_feature,
+            external_include_paths_feature,
             preprocessor_defines_feature,
             parse_showincludes_feature,
+            no_dotd_file_feature,
             generate_pdb_file_feature,
+            generate_linkmap_feature,
             shared_flag_feature,
             linkstamps_feature,
             output_execpath_flags_feature,
@@ -1073,10 +1290,7 @@ def _impl(ctx):
             default_link_flags_feature,
             linker_param_file_feature,
             static_link_msvcrt_feature,
-            static_link_msvcrt_no_debug_feature,
-            dynamic_link_msvcrt_no_debug_feature,
-            static_link_msvcrt_debug_feature,
-            dynamic_link_msvcrt_debug_feature,
+            dynamic_link_msvcrt_feature,
             dbg_feature,
             fastbuild_feature,
             opt_feature,
@@ -1085,10 +1299,12 @@ def _impl(ctx):
             determinism_feature,
             treat_warnings_as_errors_feature,
             smaller_binary_feature,
+            remove_unreferenced_code_feature,
             ignore_noisy_warnings_feature,
             user_compile_flags_feature,
             sysroot_feature,
             unfiltered_compile_flags_feature,
+            archive_param_file_feature,
             compiler_param_file_feature,
             compiler_output_flags_feature,
             compiler_input_flags_feature,
@@ -1097,6 +1313,7 @@ def _impl(ctx):
             no_windows_export_all_symbols_feature,
             supports_dynamic_linker_feature,
             supports_interface_shared_libraries_feature,
+            symbol_check_feature,
         ]
     else:
         targets_windows_feature = feature(
@@ -1114,10 +1331,14 @@ def _impl(ctx):
                 env_set(
                     actions = [
                         ACTION_NAMES.c_compile,
+                        ACTION_NAMES.linkstamp_compile,
                         ACTION_NAMES.cpp_compile,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
                         ACTION_NAMES.cpp_header_parsing,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.assemble,
                         ACTION_NAMES.preprocess_assemble,
                         ACTION_NAMES.cpp_link_executable,
@@ -1143,10 +1364,13 @@ def _impl(ctx):
                         ACTION_NAMES.cpp_header_parsing,
                         ACTION_NAMES.cpp_module_compile,
                         ACTION_NAMES.cpp_module_codegen,
+                        ACTION_NAMES.cpp_module_deps_scanning,
+                        ACTION_NAMES.cpp20_module_compile,
+                        ACTION_NAMES.cpp20_module_codegen,
                         ACTION_NAMES.lto_backend,
                         ACTION_NAMES.clif_match,
                     ],
-                    flag_groups = [flag_group(flags = ["-std=gnu++0x"])],
+                    flag_groups = [flag_group(flags = ["-std=gnu++14"] + ctx.attr.default_compile_flags)],
                 ),
             ],
         )
@@ -1157,7 +1381,7 @@ def _impl(ctx):
             flag_sets = [
                 flag_set(
                     actions = all_link_actions,
-                    flag_groups = [flag_group(flags = ["-lstdc++"])],
+                    flag_groups = [flag_group(flags = ["-lstdc++"] + ctx.attr.default_link_flags)],
                 ),
             ],
         )
@@ -1167,7 +1391,42 @@ def _impl(ctx):
             enabled = True,
         )
 
+        dbg_feature = feature(
+            name = "dbg",
+            flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = ["-g", "-Og"])],
+                ),
+            ],
+        )
+
+        opt_feature = feature(
+            name = "opt",
+            flag_sets = [
+                flag_set(
+                    actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                    flag_groups = [flag_group(flags = [
+                        "-g0",
+                        "-O3",
+                        "-DNDEBUG",
+                        "-ffunction-sections",
+                        "-fdata-sections",
+                    ])],
+                ),
+                flag_set(
+                    actions = all_link_actions,
+                    flag_groups = [flag_group(flags = ["-Wl,--gc-sections"])],
+                ),
+            ],
+        )
+
         if ctx.attr.cpu == "x64_windows" and ctx.attr.compiler == "mingw-gcc":
+            archive_param_file_feature = feature(
+                name = "archive_param_file",
+                enabled = True,
+            )
+
             compiler_param_file_feature = feature(
                 name = "compiler_param_file",
             )
@@ -1177,23 +1436,18 @@ def _impl(ctx):
                 copy_dynamic_libraries_to_binary_feature,
                 gcc_env_feature,
                 default_compile_flags_feature,
+                archive_param_file_feature,
                 compiler_param_file_feature,
                 default_link_flags_feature,
                 supports_dynamic_linker_feature,
+                dbg_feature,
+                opt_feature,
             ]
         else:
             supports_pic_feature = feature(
                 name = "supports_pic",
                 enabled = True,
             )
-            supports_start_end_lib_feature = feature(
-                name = "supports_start_end_lib",
-                enabled = True,
-            )
-
-            dbg_feature = feature(name = "dbg")
-
-            opt_feature = feature(name = "opt")
 
             sysroot_feature = feature(
                 name = "sysroot",
@@ -1208,6 +1462,9 @@ def _impl(ctx):
                             ACTION_NAMES.cpp_header_parsing,
                             ACTION_NAMES.cpp_module_compile,
                             ACTION_NAMES.cpp_module_codegen,
+                            ACTION_NAMES.cpp_module_deps_scanning,
+                            ACTION_NAMES.cpp20_module_compile,
+                            ACTION_NAMES.cpp20_module_codegen,
                             ACTION_NAMES.lto_backend,
                             ACTION_NAMES.clif_match,
                             ACTION_NAMES.cpp_link_executable,
@@ -1243,6 +1500,20 @@ def _impl(ctx):
                 provides = ["profile"],
             )
 
+            treat_warnings_as_errors_feature = feature(
+                name = "treat_warnings_as_errors",
+                flag_sets = [
+                    flag_set(
+                        actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
+                        flag_groups = [flag_group(flags = ["-Werror"])],
+                    ),
+                    flag_set(
+                        actions = all_link_actions,
+                        flag_groups = [flag_group(flags = ["-Wl,-fatal-warnings"])],
+                    ),
+                ],
+            )
+
             user_compile_flags_feature = feature(
                 name = "user_compile_flags",
                 enabled = True,
@@ -1257,6 +1528,9 @@ def _impl(ctx):
                             ACTION_NAMES.cpp_header_parsing,
                             ACTION_NAMES.cpp_module_compile,
                             ACTION_NAMES.cpp_module_codegen,
+                            ACTION_NAMES.cpp_module_deps_scanning,
+                            ACTION_NAMES.cpp20_module_compile,
+                            ACTION_NAMES.cpp20_module_codegen,
                             ACTION_NAMES.lto_backend,
                             ACTION_NAMES.clif_match,
                         ],
@@ -1276,7 +1550,6 @@ def _impl(ctx):
                 copy_dynamic_libraries_to_binary_feature,
                 gcc_env_feature,
                 supports_pic_feature,
-                supports_start_end_lib_feature,
                 default_compile_flags_feature,
                 default_link_flags_feature,
                 fdo_optimize_feature,
@@ -1284,6 +1557,7 @@ def _impl(ctx):
                 dbg_feature,
                 opt_feature,
                 user_compile_flags_feature,
+                treat_warnings_as_errors_feature,
                 sysroot_feature,
             ]
 
@@ -1292,9 +1566,61 @@ def _impl(ctx):
         for name, path in ctx.attr.tool_paths.items()
     ]
 
+    make_variables = []
+
+    # dumpbin.exe is not available in MSYS toolchain
+    if "dumpbin" in ctx.attr.tool_paths:
+        make_variables.append(make_variable(name = "DUMPBIN", value = ctx.attr.tool_paths["dumpbin"]))
+
+    # Tell bazel we support C++ modules now
+    cpp_modules_feature = feature(
+        name = "cpp_modules",
+        # set default value to False
+        # to enable the feature
+        # use --features=cpp_modules
+        # or add cpp_modules to features attr
+        enabled = False,
+    )
+
+    cpp_module_modmap_file_feature = feature(
+        name = "cpp_module_modmap_file",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.cpp_compile,
+                    ACTION_NAMES.cpp20_module_compile,
+                    ACTION_NAMES.cpp20_module_codegen,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["@%{cpp_module_modmap_file}"],
+                        expand_if_available = "cpp_module_modmap_file",
+                    ),
+                ],
+            ),
+        ],
+        enabled = True,
+    )
+    cpp20_module_compile_flags_feature = feature(
+        name = "cpp20_module_compile_flags",
+        flag_sets = [
+            flag_set(
+                actions = [
+                    ACTION_NAMES.cpp20_module_compile,
+                ],
+                flag_groups = [
+                    flag_group(
+                        flags = ["/ifcOutput%{cpp_module_output_file}"],
+                        expand_if_available = "cpp_module_output_file",
+                    ),
+                ],
+            ),
+        ],
+        enabled = True,
+    )
     return cc_common.create_cc_toolchain_config_info(
         ctx = ctx,
-        features = features,
+        features = features + [cpp_modules_feature, cpp_module_modmap_file_feature, cpp20_module_compile_flags_feature],
         action_configs = action_configs,
         artifact_name_patterns = artifact_name_patterns,
         cxx_builtin_include_directories = ctx.attr.cxx_builtin_include_directories,
@@ -1307,6 +1633,7 @@ def _impl(ctx):
         abi_version = ctx.attr.abi_version,
         abi_libc_version = ctx.attr.abi_libc_version,
         tool_paths = tool_paths,
+        make_variables = make_variables,
     )
 
 cc_toolchain_config = rule(
@@ -1314,12 +1641,14 @@ cc_toolchain_config = rule(
     attrs = {
         "abi_libc_version": attr.string(),
         "abi_version": attr.string(),
+        "archiver_flags": attr.string_list(default = []),
         "compiler": attr.string(),
         "cpu": attr.string(mandatory = True),
         "cxx_builtin_include_directories": attr.string_list(),
-        "dbg_mode_debug_flag": attr.string(),
+        "dbg_mode_debug_flag": attr.string(default = ""),
+        "default_compile_flags": attr.string_list(default = []),
         "default_link_flags": attr.string_list(default = []),
-        "fastbuild_mode_debug_flag": attr.string(),
+        "fastbuild_mode_debug_flag": attr.string(default = ""),
         "host_system_name": attr.string(),
         "msvc_cl_path": attr.string(default = "vc_installation_error.bat"),
         "msvc_env_include": attr.string(default = "msvc_not_found"),
@@ -1329,6 +1658,7 @@ cc_toolchain_config = rule(
         "msvc_lib_path": attr.string(default = "vc_installation_error.bat"),
         "msvc_link_path": attr.string(default = "vc_installation_error.bat"),
         "msvc_ml_path": attr.string(default = "vc_installation_error.bat"),
+        "supports_parse_showincludes": attr.bool(),
         "target_libc": attr.string(),
         "target_system_name": attr.string(),
         "tool_bin_path": attr.string(default = "not_found"),
diff --git a/cc/toolchains/BUILD b/cc/toolchains/BUILD
index cde0cb5..aac254d 100644
--- a/cc/toolchains/BUILD
+++ b/cc/toolchains/BUILD
@@ -12,10 +12,28 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
 
-bool_flag(
-    name = "experimental_enable_rule_based_toolchains",
-    build_setting_default = False,
+bzl_library(
+    name = "toolchain_rules",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//visibility:public"],
+    deps = [
+        "//cc:action_names_bzl",
+        "//cc:cc_toolchain_config_lib_bzl",
+        "//cc:find_cc_toolchain_bzl",
+        "//cc/private/rules_impl:cc_flags_supplier_lib_bzl",
+        "//cc/private/rules_impl:native_bzl",
+        "//cc/toolchains/impl:toolchain_impl_rules",
+        "@bazel_skylib//rules/directory:glob",
+    ],
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob([
+        "**/*.bzl",
+        "**/BUILD",
+    ]),
     visibility = ["//visibility:public"],
 )
diff --git a/cc/toolchains/README.md b/cc/toolchains/README.md
index 42266b7..fc8f1ed 100644
--- a/cc/toolchains/README.md
+++ b/cc/toolchains/README.md
@@ -1,333 +1,7 @@
-# Writing a custom rule_based C++ toolchain with rule-based definition.
+# Toolchain rules
+This directory contains a suite of rules for defining C/C++ toolchain
+configurations.
 
-Work in progress!
-
-This document serves two purposes:
-* Until complete, this serves as an agreement for the final user-facing API. 
-* Once complete, this will serve as onboarding documentation.
-
-This section will be removed once complete.
-
-## Step 1: Define tools
-A tool is simply a binary. Just like any other bazel binary, a tool can specify
-additional files required to run.
-
-We can use any bazel binary as an input to anything that requires tools. In the
-example below, you could use both clang and ld as tools.
-
-```
-# @sysroot//:BUILD
-cc_tool(
-    name = "clang",
-    exe = ":bin/clang",
-    execution_requirements = ["requires-mem:24g"],
-    data = [...],
-)
-
-sh_binary(
-    name = "ld",
-    srcs = ["ld_wrapper.sh"],
-    data = [":bin/ld"],
-)
-    
-```
-
-## Step 2: Generate action configs from those tools
-An action config is a mapping from action to:
-
-* A list of tools, (the first one matching the execution requirements is used).
-* A list of args and features that are always enabled for the action
-* A set of additional files required for the action
-
-Each action can only be specified once in the toolchain. Specifying multiple
-actions in a single `cc_action_type_config` is just a shorthand for specifying the
-same config for every one of those actions.
-
-If you're already familiar with how to define toolchains, the additional files
-is a replacement for `compile_files`, `link_files`, etc.
-
-Additionally, to replace `all_files`, we add `cc_additional_files_for_actions`.
-This allows you to specify that particular files are required for particular
-actions.
-
-We provide `additional_files` on the `cc_action_type_config` as a shorthand for 
-specifying `cc_additional_files_for_actions`
-
-Warning: Implying a feature that is not listed directly in the toolchain will throw
-an error. This is to ensure you don't accidentally add a feature to the
-toolchain.
-
-```
-cc_action_type_config(
-    name  = "c_compile",
-    actions = ["@rules_cc//actions:all_c_compile"],
-    tools = ["@sysroot//:clang"],
-    args = [":my_args"],
-    implies = [":my_feature"],
-    additional_files = ["@sysroot//:all_header_files"],
-)
-
-cc_additional_files_for_actions(
-    name = "all_action_files",
-    actions = ["@rules_cc//actions:all_actions"],
-    additional_files = ["@sysroot//:always_needed_files"]
-)
-```
-
-## Step 3: Define some arguments
-Arguments are our replacement for `flag_set` and `env_set`. To add arguments to
-our tools, we take heavy inspiration from bazel's
-[`Args`](https://bazel.build/rules/lib/builtins/Args) type. We provide the same
-API, with the following caveats:
-* `actions` specifies which actions the arguments apply to (same as `flag_set`).
-* `requires_any_of` is equivalent to `with_features` on the `flag_set`.
-* `args` may be used instead of `add` if your command-line is only strings.
-* `env` may be used to add environment variables to the arguments. Environment
-  variables set by later args take priority.
-* By default, all inputs are automatically added to the corresponding actions.
-  `additional_files` specifies files that are required for an action when using
-  that argument.
-
-```
-cc_args(
-    name = "inline",
-    actions = ["@rules_cc//actions:all_cpp_compile_actions"],
-    args = ["--foo"],
-    requires_any_of = [":feature"]
-    env = {"FOO": "bar"},
-    additional_files = [":file"],
-)
-```
-
-For more complex use cases, we use the same API as `Args`. Values are either:
-* A list of files (or a single file for `cc_add_args`).
-* Something returning `CcVariableInfo`, which is equivalent to a list of strings.
-
-```
-cc_variable(
-  name = "bar_baz",
-  values = ["bar", "baz"],
-)
-
-# Expands to CcVariableInfo(values = ["x86_64-unknown-linux-gnu"])
-custom_variable_rule(
-  name = "triple",
-  ...
-)
-
-# Taken from https://bazel.build/rules/lib/builtins/Args#add
-cc_add_args(
-    name = "single",
-    arg_name = "--platform",
-    value = ":triple", # Either a single file or a cc_variable
-    format = "%s",
-)
-
-# Taken from https://bazel.build/rules/lib/builtins/Args#add_all
-cc_add_args_all(
-    name = "multiple",
-    arg_name = "--foo",
-    values = [":file", ":file_set"], # Either files or cc_variable.
-    # map_each not supported. Write a custom rule if you want that.
-    format_each = "%s",
-    before_each = "--foo",
-    omit_if_empty = True,
-    uniquify = False,
-    # Expand_directories not yet supported.
-    terminate_with = "foo",
-)
-
-# Taken from https://bazel.build/rules/lib/builtins/Args#add_joined
-cc_add_args_joined(
-    name = "joined",
-    arg_name = "--foo",
-    values = [":file", ":file_set"], # Either files or cc_variable.
-    join_with = ",",
-    # map_each not supported. Write a custom rule if you want that.
-    format_each = "%s",
-    format_joined = "--foo=%s",
-    omit_if_empty = True,
-    uniquify = False,
-    # Expand_directories not yet supported.
-)
-
-cc_args(
-    name = "complex",
-    actions = ["@rules_cc//actions:c_compile"],
-    add = [":single", ":multiple", ":joined"],
-)
-
-cc_args_list(
-    name = "all_flags",
-    args = [":inline", ":complex"],
-)
-```
-
-## Step 4: Define some features
-A feature is a set of args and configurations that can be enabled or disabled.
-
-Although the existing toolchain recommends using features to avoid duplication
-of definitions, we recommend avoiding using features unless you want the user to
-be able to enable / disable the feature themselves. This is because we provide
-alternatives such as `cc_args_list` to allow combining arguments and
-specifying them on each action in the action config.
-
-```
-cc_feature(
-    name = "my_feature",
-    feature_name = "my_feature",
-    args = [":all_args"],
-    implies = [":other_feature"],
-)
-```
-
-## Step 5: Generate the toolchain
-The `cc_toolchain` macro:
-
-* Performs validation on the inputs (eg. no two action configs for a single
-  action)
-* Converts the type-safe providers to the unsafe ones in
-  `cc_toolchain_config_lib.bzl`
-* Generates a set of providers for each of the filegroups respectively
-* Generates the appropriate `native.cc_toolchain` invocation.
-
-```
-cc_toolchain(
-    name = "toolchain",
-    features = [":my_feature"]
-    unconditional_args = [":all_warnings"],
-    action_type_configs = [":c_compile"],
-    additional_files = [":all_action_files"],
-)
-```
-
-# Ancillary components for type-safe toolchains.
-## Well-known features
-Well-known features will be defined in `@rules_cc//features/well_known:*`.
-Any feature with `feature_name` in the well known features will have to specify
-overrides.
-
-`cc_toolchain` is aware of the builtin / well-known features. In order to
-ensure that a user understands that this overrides the builtin opt feature (I
-originally thought that it added extra flags to opt, but you still got the
-default ones, so that can definitely happen), and to ensure that they don't
-accidentally do so, we will force them to explicitly specify that it overrides
-the builtin one. This is essentially just an acknowledgement of "I know what
-I'm doing".
-
-Warning: Specifying two features with the same name is an error, unless one
-overrides the other. 
-
-```
-cc_feature(
-    name = "opt",
-    ...,
-    overrides = "@rules_cc//features/well_known:opt",
-)
-```
-
-In addition to well-known features, we could also consider in future iterations
-to also use known features for partial migrations, where you still imply a
-feature that's still defined by the legacy API:
-
-```
-# Implementation
-def cc_legacy_features(name, features):
-  for feature in features:
-    cc_known_feature(name = name + "_" + feature.name)
-  cc_legacy_features(name = name, features = FEATURES)
-
-
-# Build file
-FOO = feature(name = "foo", args=[arg_group(...)])
-FEATURES = [FOO]
-cc_legacy_features(name = "legacy_features", features = FEATURES)
-
-cc_feature(name = "bar", implies = [":legacy_features_foo"])
-
-cc_toolchain(
-  name = "toolchain",
-  legacy_features = ":legacy_features",
-  features = [":bar"],
-)
-```
-
-## Mutual exclusion
-Features can be mutually exclusive.
-
-We allow two approaches to mutual exclusion - via features or via categories.
-
-The existing toolchain uses `provides` for both of these. We rename it so that
-it makes more sense semantically.
-
-```
-cc_feature(
-   name = "incompatible_with_my_feature",
-   feature_name = "bar",
-   mutually_exclusive = [":my_feature"],
-)
-
-
-# This is an example of how we would define compilation mode.
-# Since it already exists, this wouldn't work.
-cc_mutual_exclusion_category(
-    name = "compilation_mode",
-)
-
-cc_feature(
-    name = "opt",
-    ...
-    mutually_exclusive = [":compilation_mode"],
-)
-cc_feature(
-    name = "dbg",
-    ...
-    mutually_exclusive = [":compilation_mode"],
-)
-```
-
-## Feature requirements
-Feature requirements can come in two formats.
-
-For example:
-
-* Features can require some subset of features to be enabled.
-* Arguments can require some subset of features to be enabled, but others to be
-  disabled.
-
-This is very confusing for toolchain authors, so we will simplify things with
-the use of providers:
-
-* `cc_feature` will provide `feature`, `feature_set`, and `with_feature`
-* `cc_feature_set` will provide `feature_set` and `with_feature`.
-* `cc_feature_constraint` will provide `with_features` only.
-
-We will rename all `with_features` and `requires` to `requires_any_of`, to make
-it very clear that only one of the requirements needs to be met.
-
-```
-cc_feature_set(
-    name = "my_feature_set",
-    all_of = [":my_feature"],
-)
-
-cc_feature_constraint(
-    name = "my_feature_constraint",
-    all_of = [":my_feature"],
-    none_of = [":my_other_feature"],
-)
-
-cc_args(
-   name = "foo",
-   # All of these provide with_feature.
-   requires_any_of = [":my_feature", ":my_feature_set", ":my_feature_constraint"]
-)
-
-# my_feature_constraint would be an error here.
-cc_feature(
-   name = "foo",
-   # Both of these provide feature_set.
-   requires_any_of = [":my_feature", ":my_feature_set"]
-   implies = [":my_other_feature", :my_other_feature_set"],
-)
-```
+For a living example, see
+[`//examples/rule_based_toolchain`](https://github.com/bazelbuild/rules_cc/tree/main/examples/rule_based_toolchain/).
+For the full API, see [`//third_party/bazel_rules/docs:toolchain_api.md`](https://github.com/bazelbuild/rules_cc/tree/main/docs/toolchain_api.md).
diff --git a/cc/toolchains/action_type_config.bzl b/cc/toolchains/action_type_config.bzl
deleted file mode 100644
index 4d5a8cd..0000000
--- a/cc/toolchains/action_type_config.bzl
+++ /dev/null
@@ -1,137 +0,0 @@
-# Copyright 2024 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Implementation of cc_action_type_config."""
-
-load("//cc/toolchains/impl:args_utils.bzl", "get_action_type")
-load(
-    "//cc/toolchains/impl:collect.bzl",
-    "collect_action_types",
-    "collect_args_lists",
-    "collect_features",
-    "collect_files",
-    "collect_tools",
-)
-load(
-    ":cc_toolchain_info.bzl",
-    "ActionTypeConfigInfo",
-    "ActionTypeConfigSetInfo",
-    "ActionTypeSetInfo",
-    "ArgsListInfo",
-    "FeatureSetInfo",
-)
-
-def _cc_action_type_config_impl(ctx):
-    if not ctx.attr.action_types:
-        fail("At least one action type is required for cc_action_type_config")
-    if not ctx.attr.tools:
-        fail("At least one tool is required for cc_action_type_config")
-
-    tools = tuple(collect_tools(ctx, ctx.attr.tools))
-    implies = collect_features(ctx.attr.implies)
-    args_list = collect_args_lists(ctx.attr.args, ctx.label)
-    files = collect_files(ctx.attr.data)
-
-    configs = {}
-    for action_type in collect_action_types(ctx.attr.action_types).to_list():
-        for_action = get_action_type(args_list, action_type)
-        configs[action_type] = ActionTypeConfigInfo(
-            label = ctx.label,
-            action_type = action_type,
-            tools = tools,
-            args = for_action.args,
-            implies = implies,
-            files = ctx.runfiles(
-                transitive_files = depset(transitive = [files, for_action.files]),
-            ).merge_all([tool.runfiles for tool in tools]),
-        )
-
-    return [ActionTypeConfigSetInfo(label = ctx.label, configs = configs)]
-
-cc_action_type_config = rule(
-    implementation = _cc_action_type_config_impl,
-    # @unsorted-dict-items
-    attrs = {
-        "action_types": attr.label_list(
-            providers = [ActionTypeSetInfo],
-            mandatory = True,
-            doc = """A list of action names to apply this action to.
-
-See @toolchain//actions:all for valid options.
-""",
-        ),
-        "tools": attr.label_list(
-            mandatory = True,
-            cfg = "exec",
-            allow_files = True,
-            doc = """The tool to use for the specified actions.
-
-A tool can be a `cc_tool`, or a binary.
-
-If multiple tools are specified, the first tool that has `with_features` that
-satisfy the currently enabled feature set is used.
-""",
-        ),
-        "args": attr.label_list(
-            providers = [ArgsListInfo],
-            doc = """Labels that point to `cc_arg`s / `cc_arg_list`s that are
-unconditionally bound to the specified actions.
-""",
-        ),
-        "implies": attr.label_list(
-            providers = [FeatureSetInfo],
-            doc = "Features that should be enabled when this action is used.",
-        ),
-        "data": attr.label_list(
-            allow_files = True,
-            doc = """Files required for this action type.
-
-For example, the c-compile action type might add the C standard library header
-files from the sysroot.
-""",
-        ),
-    },
-    provides = [ActionTypeConfigSetInfo],
-    doc = """Declares the configuration and selection of `cc_tool` rules.
-
-Action configs are bound to a toolchain through `action_configs`, and are the
-driving mechanism for controlling toolchain tool invocation/behavior.
-
-Action configs define three key things:
-
-* Which tools to invoke for a given type of action.
-* Tool features and compatibility.
-* `cc_args`s that are unconditionally bound to a tool invocation.
-
-Examples:
-
-    cc_action_config(
-        name = "ar",
-        action_types = ["@toolchain//actions:all_ar_actions"],
-        implies = [
-            "@toolchain//features/legacy:archiver_flags",
-            "@toolchain//features/legacy:linker_param_file",
-        ],
-        tools = [":ar_tool"],
-    )
-
-    cc_action_config(
-        name = "clang",
-        action_types = [
-            "@toolchain//actions:all_asm_actions",
-            "@toolchain//actions:all_c_compiler_actions",
-        ],
-        tools = [":clang_tool"],
-    )
-""",
-)
diff --git a/cc/toolchains/actions.bzl b/cc/toolchains/actions.bzl
index fc91787..84dc837 100644
--- a/cc/toolchains/actions.bzl
+++ b/cc/toolchains/actions.bzl
@@ -37,14 +37,26 @@ cc_action_type = rule(
     },
     doc = """A type of action (eg. c_compile, assemble, strip).
 
-Example:
+`cc_action_type` rules are used to associate arguments and tools together to
+perform a specific action. Bazel prescribes a set of known action types that are used to drive
+typical C/C++/ObjC actions like compiling, linking, and archiving. The set of well-known action
+types can be found in [@rules_cc//cc/toolchains/actions:BUILD](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/actions/BUILD).
+
+It's possible to create project-specific action types for use in toolchains. Be careful when
+doing this, because every toolchain that encounters the action will need to be configured to
+support the custom action type. If your project is a library, avoid creating new action types as
+it will reduce compatibility with existing toolchains and increase setup complexity for users.
 
-load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
+Example:
+```
+load("//cc:action_names.bzl", "ACTION_NAMES")
+load("//cc/toolchains:actions.bzl", "cc_action_type")
 
 cc_action_type(
-  name = "cpp_compile",
-  action_name =  = ACTION_NAMES.cpp_compile,
+    name = "cpp_compile",
+    action_name =  = ACTION_NAMES.cpp_compile,
 )
+```
 """,
     provides = [ActionTypeInfo, ActionTypeSetInfo],
 )
@@ -60,15 +72,21 @@ def _cc_action_type_set_impl(ctx):
 cc_action_type_set = rule(
     doc = """Represents a set of actions.
 
+This is a convenience rule to allow for more compact representation of a group of action types.
+Use this anywhere a `cc_action_type` is accepted.
+
 Example:
+```
+load("//cc/toolchains:actions.bzl", "cc_action_type_set")
 
 cc_action_type_set(
     name = "link_executable_actions",
     actions = [
-        ":cpp_link_executable",
-        ":lto_index_for_executable",
+        "//cc/toolchains/actions:cpp_link_executable",
+        "//cc/toolchains/actions:lto_index_for_executable",
     ],
 )
+```
 """,
     implementation = _cc_action_type_set_impl,
     attrs = {
diff --git a/cc/toolchains/actions/BUILD b/cc/toolchains/actions/BUILD
index e122f5c..9eb0ce7 100644
--- a/cc/toolchains/actions/BUILD
+++ b/cc/toolchains/actions/BUILD
@@ -53,6 +53,21 @@ cc_action_type(
     action_name = ACTION_NAMES.cpp_header_parsing,
 )
 
+cc_action_type(
+    name = "cpp_module_deps_scanning",
+    action_name = ACTION_NAMES.cpp_module_deps_scanning,
+)
+
+cc_action_type(
+    name = "cpp20_module_compile",
+    action_name = ACTION_NAMES.cpp20_module_compile,
+)
+
+cc_action_type(
+    name = "cpp20_module_codegen",
+    action_name = ACTION_NAMES.cpp20_module_codegen,
+)
+
 cc_action_type(
     name = "cpp_module_compile",
     action_name = ACTION_NAMES.cpp_module_compile,
@@ -68,6 +83,11 @@ cc_action_type(
     action_name = ACTION_NAMES.preprocess_assemble,
 )
 
+cc_action_type(
+    name = "llvm_cov",
+    action_name = ACTION_NAMES.llvm_cov,
+)
+
 cc_action_type(
     name = "lto_indexing",
     action_name = ACTION_NAMES.lto_indexing,
@@ -120,7 +140,12 @@ cc_action_type(
 
 cc_action_type(
     name = "objcopy_embed_data",
-    action_name = "objcopy_embed_data",
+    action_name = ACTION_NAMES.objcopy_embed_data,
+)
+
+cc_action_type(
+    name = "validate_static_library",
+    action_name = ACTION_NAMES.validate_static_library,
 )
 
 # ld_embed_data is only available within google.
@@ -184,6 +209,13 @@ cc_action_type_set(
     ],
 )
 
+cc_action_type_set(
+    name = "c_compile_actions",
+    actions = [
+        ":c_compile",
+    ],
+)
+
 cc_action_type_set(
     name = "cpp_compile_actions",
     actions = [
@@ -201,8 +233,10 @@ cc_action_type_set(
     name = "compile_actions",
     actions = [
         ":cpp_compile_actions",
-        ":c_compile",
+        ":c_compile_actions",
         ":assembly_actions",
+        ":objc_compile",
+        ":objcpp_compile",
     ],
 )
 
@@ -259,9 +293,13 @@ cc_action_type_set(
         ":cpp_module_codegen",
         ":cpp_header_analysis",
         ":cpp_header_parsing",
+        ":cpp_module_deps_scanning",
+        ":cpp20_module_compile",
+        ":cpp20_module_codegen",
         ":cpp_module_compile",
         ":assemble",
         ":preprocess_assemble",
+        ":llvm_cov",
         ":lto_indexing",
         ":lto_backend",
         ":lto_index_for_executable",
@@ -280,5 +318,6 @@ cc_action_type_set(
         ":objcpp_compile",
         ":objcpp_executable",
         ":clif_match",
+        ":validate_static_library",
     ],
 )
diff --git a/cc/toolchains/args.bzl b/cc/toolchains/args.bzl
index 1df3333..78d551c 100644
--- a/cc/toolchains/args.bzl
+++ b/cc/toolchains/args.bzl
@@ -13,6 +13,7 @@
 # limitations under the License.
 """All providers for rule-based bazel toolchain config."""
 
+load("@bazel_skylib//rules/directory:providers.bzl", "DirectoryInfo")
 load("//cc/toolchains/impl:args_utils.bzl", "validate_nested_args")
 load(
     "//cc/toolchains/impl:collect.bzl",
@@ -23,7 +24,6 @@ load(
 load(
     "//cc/toolchains/impl:nested_args.bzl",
     "NESTED_ARGS_ATTRS",
-    "args_wrapper_macro",
     "nested_args_provider_from_ctx",
 )
 load(
@@ -40,9 +40,6 @@ visibility("public")
 def _cc_args_impl(ctx):
     actions = collect_action_types(ctx.attr.actions)
 
-    if not ctx.attr.args and not ctx.attr.nested and not ctx.attr.env:
-        fail("cc_args requires at least one of args, nested, and env")
-
     nested = None
     if ctx.attr.args or ctx.attr.nested:
         nested = nested_args_provider_from_ctx(ctx)
@@ -54,7 +51,7 @@ def _cc_args_impl(ctx):
         )
         files = nested.files
     else:
-        files = collect_files(ctx.attr.data)
+        files = collect_files(ctx.attr.data + ctx.attr.allowlist_include_directories)
 
     requires = collect_provider(ctx.attr.requires_any_of, FeatureConstraintInfo)
 
@@ -65,6 +62,9 @@ def _cc_args_impl(ctx):
         nested = nested,
         env = ctx.attr.env,
         files = files,
+        allowlist_include_directories = depset(
+            direct = [d[DirectoryInfo] for d in ctx.attr.allowlist_include_directories],
+        ),
     )
     return [
         args,
@@ -76,6 +76,7 @@ def _cc_args_impl(ctx):
                 struct(action = action, args = tuple([args]), files = files)
                 for action in actions.to_list()
             ]),
+            allowlist_include_directories = args.allowlist_include_directories,
         ),
     ]
 
@@ -85,20 +86,18 @@ _cc_args = rule(
         "actions": attr.label_list(
             providers = [ActionTypeSetInfo],
             mandatory = True,
-            doc = """A list of action types that this flag set applies to.
-
-See @rules_cc//cc/toolchains/actions:all for valid options.
-""",
+            doc = """See documentation for cc_args macro wrapper.""",
+        ),
+        "allowlist_include_directories": attr.label_list(
+            providers = [DirectoryInfo],
+            doc = """See documentation for cc_args macro wrapper.""",
         ),
         "env": attr.string_dict(
-            doc = "Environment variables to be added to the command-line.",
+            doc = """See documentation for cc_args macro wrapper.""",
         ),
         "requires_any_of": attr.label_list(
             providers = [FeatureConstraintInfo],
-            doc = """This will be enabled when any of the constraints are met.
-
-If omitted, this flag set will be enabled unconditionally.
-""",
+            doc = """See documentation for cc_args macro wrapper.""",
         ),
         "_variables": attr.label(
             default = "//cc/toolchains/variables:variables",
@@ -117,4 +116,175 @@ Examples:
 """,
 )
 
-cc_args = lambda **kwargs: args_wrapper_macro(rule = _cc_args, **kwargs)
+def cc_args(
+        *,
+        name,
+        actions = None,
+        allowlist_include_directories = None,
+        args = None,
+        data = None,
+        env = None,
+        format = {},
+        iterate_over = None,
+        nested = None,
+        requires_not_none = None,
+        requires_none = None,
+        requires_true = None,
+        requires_false = None,
+        requires_equal = None,
+        requires_equal_value = None,
+        requires_any_of = None,
+        **kwargs):
+    """Action-specific arguments for use with a `cc_toolchain`.
+
+    This rule is the fundamental building building block for every toolchain tool invocation. Each
+    argument expressed in a toolchain tool invocation (e.g. `gcc`, `llvm-ar`) is declared in a
+    `cc_args` rule that applies an ordered list of arguments to a set of toolchain
+    actions. `cc_args` rules can be added unconditionally to a
+    `cc_toolchain`, conditionally via `select()` statements, or dynamically via an
+    intermediate `cc_feature`.
+
+    Conceptually, this is similar to the old `CFLAGS`, `CPPFLAGS`, etc. environment variables that
+    many build systems use to determine which flags to use for a given action. The significant
+    difference is that `cc_args` rules are declared in a structured way that allows for
+    significantly more powerful and sharable toolchain configurations. Also, due to Bazel's more
+    granular action types, it's possible to bind flags to very specific actions (e.g. LTO indexing
+    for an executable vs a dynamic library) multiple different actions (e.g. C++ compile and link
+    simultaneously).
+
+    Example usage:
+    ```
+    load("//cc/toolchains:args.bzl", "cc_args")
+
+    # Basic usage: a trivial flag.
+    #
+    # An example of expressing `-Werror` as a `cc_args` rule.
+    cc_args(
+        name = "warnings_as_errors",
+        actions = [
+            # Applies to all C/C++ compile actions.
+            "//cc/toolchains/actions:compile_actions",
+        ],
+        args = ["-Werror"],
+    )
+
+    # Basic usage: ordered flags.
+    #
+    # An example of linking against libc++, which uses two flags that must be applied in order.
+    cc_args(
+        name = "link_libcxx",
+        actions = [
+            # Applies to all link actions.
+            "//cc/toolchains/actions:link_actions",
+        ],
+        # On tool invocation, this appears as `-Xlinker -lc++`. Nothing will ever end up between
+        # the two flags.
+        args = [
+            "-Xlinker",
+            "-lc++",
+        ],
+    )
+
+    # Advanced usage: built-in variable expansions.
+    #
+    # Expands to `-L/path/to/search_dir` for each directory in the built-in variable
+    # `library_search_directories`. This variable is managed internally by Bazel through inherent
+    # behaviors of Bazel and the interactions between various C/C++ build rules.
+    cc_args(
+        name = "library_search_directories",
+        actions = [
+            "//cc/toolchains/actions:link_actions",
+        ],
+        args = ["-L{search_dir}"],
+        iterate_over = "//cc/toolchains/variables:library_search_directories",
+        requires_not_none = "//cc/toolchains/variables:library_search_directories",
+        format = {
+            "search_dir": "//cc/toolchains/variables:library_search_directories",
+        },
+    )
+    ```
+
+    For more extensive examples, see the usages here:
+        https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args
+
+    Args:
+        name: (str) The name of the target.
+        actions: (List[Label]) A list of labels of `cc_action_type` or
+            `cc_action_type_set` rules that dictate which actions these
+            arguments should be applied to.
+        allowlist_include_directories: (List[Label]) A list of include paths that are implied by
+            using this rule. These must point to a skylib
+            [directory](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/directory_doc.md#directory)
+            or [subdirectory](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/directory_subdirectory_doc.md#subdirectory) rule.
+            Some flags (e.g. --sysroot) imply certain include paths are available despite
+            not explicitly specifying a normal include path flag (`-I`, `-isystem`, etc.).
+            Bazel checks that all included headers are properly provided by a dependency or
+            allowlisted through this mechanism.
+
+            As a rule of thumb, only use this if Bazel is complaining about absolute paths in
+            your toolchain and you've ensured that the toolchain is compiling with the
+            `-no-canonical-prefixes` and/or `-fno-canonical-system-headers` arguments.
+
+            This can help work around errors like:
+            `the source file 'main.c' includes the following non-builtin files with absolute paths
+            (if these are builtin files, make sure these paths are in your toolchain)`.
+        args: (List[str]) The command-line arguments that are applied by using this rule. This is
+            mutually exclusive with [nested](#cc_args-nested).
+        data: (List[Label]) A list of runtime data dependencies that are required for these
+            arguments to work as intended.
+        env: (Dict[str, str]) Environment variables that should be set when the tool is invoked.
+        format: (Dict[str, Label]) A mapping of format strings to the label of the corresponding
+            `cc_variable` that the value should be pulled from. All instances of
+            `{variable_name}` will be replaced with the expanded value of `variable_name` in this
+            dictionary. The complete list of possible variables can be found in
+            https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD.
+            It is not possible to declare custom variables--these are inherent to Bazel itself.
+        iterate_over: (Label) The label of a `cc_variable` that should be iterated over. This is
+            intended for use with built-in variables that are lists.
+        nested: (List[Label]) A list of `cc_nested_args` rules that should be
+            expanded to command-line arguments when this rule is used. This is mutually exclusive
+            with [args](#cc_args-args).
+        requires_not_none: (Label) The label of a `cc_variable` that should be checked
+            for existence before expanding this rule. If the variable is None, this rule will be
+            ignored.
+        requires_none: (Label) The label of a `cc_variable` that should be checked for
+            non-existence before expanding this rule. If the variable is not None, this rule will be
+            ignored.
+        requires_true: (Label) The label of a `cc_variable` that should be checked for
+            truthiness before expanding this rule. If the variable is false, this rule will be
+            ignored.
+        requires_false: (Label) The label of a `cc_variable` that should be checked
+            for falsiness before expanding this rule. If the variable is true, this rule will be
+            ignored.
+        requires_equal: (Label) The label of a `cc_variable` that should be checked
+            for equality before expanding this rule. If the variable is not equal to
+            (requires_equal_value)[#cc_args-requires_equal_value], this rule will be ignored.
+        requires_equal_value: (str) The value to compare (requires_equal)[#cc_args-requires_equal]
+            against.
+        requires_any_of: (List[Label]) These arguments will be used
+            in a tool invocation when at least one of the [cc_feature_constraint](#cc_feature_constraint)
+            entries in this list are satisfied. If omitted, this flag set will be enabled
+            unconditionally.
+        **kwargs: [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.
+    """
+    return _cc_args(
+        name = name,
+        actions = actions,
+        allowlist_include_directories = allowlist_include_directories,
+        args = args,
+        data = data,
+        env = env,
+        # We flip the key/value pairs in the dictionary here because Bazel doesn't have a
+        # string-keyed label dict attribute type.
+        format = {k: v for v, k in format.items()},
+        iterate_over = iterate_over,
+        nested = nested,
+        requires_not_none = requires_not_none,
+        requires_none = requires_none,
+        requires_true = requires_true,
+        requires_false = requires_false,
+        requires_equal = requires_equal,
+        requires_equal_value = requires_equal_value,
+        requires_any_of = requires_any_of,
+        **kwargs
+    )
diff --git a/cc/toolchains/args/BUILD b/cc/toolchains/args/BUILD
new file mode 100644
index 0000000..6545890
--- /dev/null
+++ b/cc/toolchains/args/BUILD
@@ -0,0 +1,42 @@
+load("//cc/toolchains:feature.bzl", "cc_feature")
+
+package(default_visibility = ["//visibility:public"])
+
+# All of these arguments originate from the legacy features defined in Bazel's Java code:
+#     https://github.com/bazelbuild/bazel/blob/master/src/main/java/com/google/devtools/build/lib/rules/cpp/CppActionConfigs.java
+
+# This feature replaces the need for action configs to list legacy features
+# in `implies` to produce a working toolchain. The full list is the set of
+# features that are implied (enabled) by built-in action  config definitions.
+# Note that some other legacy features are still hidden and enabled by default,
+# and others exist that are NOT enabled at all by default. As args are built
+# out, the `implies` entry should be removed and then moved into `args`.
+cc_feature(
+    name = "experimental_replace_legacy_action_config_features",
+    args = [
+        "//cc/toolchains/args/archiver_flags",
+        "//cc/toolchains/args/force_pic_flags",
+        "//cc/toolchains/args/libraries_to_link",
+        "//cc/toolchains/args/linker_param_file",
+        "//cc/toolchains/args/runtime_library_search_directories",
+        "//cc/toolchains/args/shared_flag",
+    ],
+    feature_name = "experimental_replace_legacy_action_config_features",
+    # TODO: Convert remaining items in this list into their actual args.
+    implies = [
+        "//cc/toolchains/features/legacy:build_interface_libraries",
+        "//cc/toolchains/features/legacy:compiler_input_flags",
+        "//cc/toolchains/features/legacy:compiler_output_flags",
+        "//cc/toolchains/features/legacy:dynamic_library_linker_tool",
+        "//cc/toolchains/features/legacy:fission_support",
+        "//cc/toolchains/features/legacy:legacy_compile_flags",
+        "//cc/toolchains/features/legacy:legacy_link_flags",
+        "//cc/toolchains/features/legacy:library_search_directories",
+        "//cc/toolchains/features/legacy:linkstamps",
+        "//cc/toolchains/features/legacy:output_execpath_flags",
+        "//cc/toolchains/features/legacy:strip_debug_symbols",
+        "//cc/toolchains/features/legacy:unfiltered_compile_flags",
+        "//cc/toolchains/features/legacy:user_compile_flags",
+        "//cc/toolchains/features/legacy:user_link_flags",
+    ],
+)
diff --git a/cc/toolchains/args/archiver_flags/BUILD b/cc/toolchains/args/archiver_flags/BUILD
new file mode 100644
index 0000000..4e3c97f
--- /dev/null
+++ b/cc/toolchains/args/archiver_flags/BUILD
@@ -0,0 +1,68 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+load("//cc/toolchains:args_list.bzl", "cc_args_list")
+load("//cc/toolchains:nested_args.bzl", "cc_nested_args")
+
+package(default_visibility = ["//visibility:private"])
+
+cc_args_list(
+    name = "archiver_flags",
+    args = [
+        ":create_static_archive",
+        ":output_execpath",
+        ":libraries_to_link",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+cc_args(
+    name = "create_static_archive",
+    actions = ["//cc/toolchains/actions:ar_actions"],
+    args = select({
+        "@platforms//os:macos": ["-static"],
+        "//conditions:default": ["rcsD"],
+    }),
+)
+
+cc_args(
+    name = "output_execpath",
+    actions = ["//cc/toolchains/actions:ar_actions"],
+    args = select({
+        "@platforms//os:macos": ["-o"],
+        "//conditions:default": [],
+    }) + ["{output_execpath}"],
+    format = {"output_execpath": "//cc/toolchains/variables:output_execpath"},
+    requires_not_none = "//cc/toolchains/variables:output_execpath",
+)
+
+cc_args(
+    name = "libraries_to_link",
+    actions = ["//cc/toolchains/actions:ar_actions"],
+    nested = ["libraries_to_link_expansion"],
+    requires_not_none = "//cc/toolchains/variables:libraries_to_link",
+)
+
+cc_nested_args(
+    name = "libraries_to_link_expansion",
+    iterate_over = "//cc/toolchains/variables:libraries_to_link",
+    nested = [
+        ":link_obj_file",
+        ":link_object_file_group",
+    ],
+)
+
+cc_nested_args(
+    name = "link_obj_file",
+    args = ["{object_file}"],
+    format = {"object_file": "//cc/toolchains/variables:libraries_to_link.name"},
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "object_file",
+)
+
+cc_nested_args(
+    name = "link_object_file_group",
+    args = ["{object_files}"],
+    format = {"object_files": "//cc/toolchains/variables:libraries_to_link.object_files"},
+    iterate_over = "//cc/toolchains/variables:libraries_to_link.object_files",
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "object_file_group",
+)
diff --git a/cc/toolchains/args/force_pic_flags/BUILD b/cc/toolchains/args/force_pic_flags/BUILD
new file mode 100644
index 0000000..3eaae56
--- /dev/null
+++ b/cc/toolchains/args/force_pic_flags/BUILD
@@ -0,0 +1,14 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+
+package(default_visibility = ["//visibility:private"])
+
+cc_args(
+    name = "force_pic_flags",
+    actions = ["//cc/toolchains/actions:link_executable_actions"],
+    args = select({
+        "@platforms//os:macos": ["-Wl,-pie"],
+        "//conditions:default": ["-pie"],
+    }),
+    requires_not_none = "//cc/toolchains/variables:force_pic",
+    visibility = ["//visibility:public"],
+)
diff --git a/cc/toolchains/args/libraries_to_link/BUILD b/cc/toolchains/args/libraries_to_link/BUILD
new file mode 100644
index 0000000..c338c1c
--- /dev/null
+++ b/cc/toolchains/args/libraries_to_link/BUILD
@@ -0,0 +1,168 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+load("//cc/toolchains:nested_args.bzl", "cc_nested_args")
+load("//cc/toolchains/args/libraries_to_link/private:library_link_args.bzl", "library_link_args")
+
+package(default_visibility = ["//visibility:private"])
+
+cc_args(
+    name = "libraries_to_link",
+    actions = ["//cc/toolchains/actions:link_actions"],
+    nested = [
+        ":thinlto_param_file",
+        ":libraries_to_link_args",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+cc_nested_args(
+    name = "thinlto_param_file",
+    args = ["-Wl,@{param_file}"],
+    format = {
+        "param_file": "//cc/toolchains/variables:thinlto_param_file",
+    },
+    requires_not_none = "//cc/toolchains/variables:thinlto_param_file",
+)
+
+cc_nested_args(
+    name = "libraries_to_link_args",
+    nested = [":iterate_over_libraries_to_link"],
+    requires_not_none = "//cc/toolchains/variables:libraries_to_link",
+)
+
+cc_nested_args(
+    name = "iterate_over_libraries_to_link",
+    iterate_over = "//cc/toolchains/variables:libraries_to_link",
+    nested = [
+        ":optional_object_file_group_start",
+        ":single_library_args",
+        ":optional_object_file_group_end",
+    ],
+)
+
+cc_nested_args(
+    name = "optional_object_file_group_start",
+    nested = [":start_lib_arg"],
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "object_file_group",
+)
+
+cc_nested_args(
+    name = "start_lib_arg",
+    args = ["-Wl,--start-lib"],
+    requires_false = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+)
+
+cc_nested_args(
+    name = "optional_object_file_group_end",
+    nested = [":end_lib_arg"],
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "object_file_group",
+)
+
+cc_nested_args(
+    name = "end_lib_arg",
+    args = ["-Wl,--end-lib"],
+    requires_false = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+)
+
+cc_nested_args(
+    name = "single_library_args",
+    nested = select({
+        "@platforms//os:macos": [],
+        "//conditions:default": [":optional_whole_archive_start"],
+    }) + [
+        ":optional_object_file_group",
+        ":optional_object_file",
+        ":optional_interface_library",
+        ":optional_static_library",
+        ":optional_dynamic_library",
+    ] + select({
+        # maOS has a minor nuance where it uses the path to the library instead of `-l:{library_name}`.
+        "@platforms//os:macos": [":macos_optional_versioned_dynamic_library"],
+        "//conditions:default": [":generic_optional_versioned_dynamic_library"],
+    }) + select({
+        "@platforms//os:macos": [],
+        "//conditions:default": [":optional_whole_archive_end"],
+    }),
+)
+
+cc_nested_args(
+    name = "optional_whole_archive_start",
+    nested = [":whole_archive_start_arg"],
+    requires_true = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+)
+
+cc_nested_args(
+    name = "whole_archive_start_arg",
+    args = ["-Wl,-whole-archive"],
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "static_library",
+)
+
+cc_nested_args(
+    name = "optional_whole_archive_end",
+    nested = [":whole_archive_end_arg"],
+    requires_true = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+)
+
+cc_nested_args(
+    name = "whole_archive_end_arg",
+    args = ["-Wl,-no-whole-archive"],
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "static_library",
+)
+
+library_link_args(
+    name = "optional_object_file_group",
+    from_variable = "//cc/toolchains/variables:libraries_to_link.object_files",
+    iterate_over_variable = True,
+    library_type = "object_file_group",
+)
+
+library_link_args(
+    name = "optional_object_file",
+    from_variable = "//cc/toolchains/variables:libraries_to_link.name",
+    library_type = "object_file",
+)
+
+library_link_args(
+    name = "optional_interface_library",
+    from_variable = "//cc/toolchains/variables:libraries_to_link.name",
+    library_type = "interface_library",
+)
+
+library_link_args(
+    name = "optional_static_library",
+    from_variable = "//cc/toolchains/variables:libraries_to_link.name",
+    library_type = "static_library",
+)
+
+cc_nested_args(
+    name = "optional_dynamic_library",
+    args = ["-l{library}"],
+    format = {
+        "library": "//cc/toolchains/variables:libraries_to_link.name",
+    },
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "dynamic_library",
+)
+
+cc_nested_args(
+    name = "generic_optional_versioned_dynamic_library",
+    args = ["-l:{library_name}"],
+    format = {
+        "library_name": "//cc/toolchains/variables:libraries_to_link.name",
+    },
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "versioned_dynamic_library",
+)
+
+cc_nested_args(
+    name = "macos_optional_versioned_dynamic_library",
+    args = ["{library_path}"],
+    format = {
+        "library_path": "//cc/toolchains/variables:libraries_to_link.path",
+    },
+    requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+    requires_equal_value = "versioned_dynamic_library",
+)
diff --git a/cc/toolchains/args/libraries_to_link/private/BUILD b/cc/toolchains/args/libraries_to_link/private/BUILD
new file mode 100644
index 0000000..ecb36c3
--- /dev/null
+++ b/cc/toolchains/args/libraries_to_link/private/BUILD
@@ -0,0 +1 @@
+package(default_visibility = ["//visibility:private"])
diff --git a/cc/toolchains/args/libraries_to_link/private/library_link_args.bzl b/cc/toolchains/args/libraries_to_link/private/library_link_args.bzl
new file mode 100644
index 0000000..8b0e409
--- /dev/null
+++ b/cc/toolchains/args/libraries_to_link/private/library_link_args.bzl
@@ -0,0 +1,104 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Helper macros for declaring library link arguments."""
+
+load("//cc/toolchains:nested_args.bzl", "cc_nested_args")
+
+def macos_force_load_library_args(name, variable):
+    """A helper for declaring -force_load argument expansion for a library.
+
+    This creates an argument expansion that will expand to -Wl,-force_load,<library>
+    if the library should be linked as a whole archive.
+
+    Args:
+      name: The name of the rule.
+      variable: The variable to expand.
+    """
+    cc_nested_args(
+        name = name,
+        nested = [
+            ":{}_force_load_library".format(name),
+            ":{}_no_force_load_library".format(name),
+        ],
+    )
+    cc_nested_args(
+        name = name + "_no_force_load_library",
+        requires_false = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+        args = ["{library}"],
+        format = {
+            "library": variable,
+        },
+    )
+    cc_nested_args(
+        name = name + "_force_load_library",
+        requires_true = "//cc/toolchains/variables:libraries_to_link.is_whole_archive",
+        args = ["-Wl,-force_load,{library}"],
+        format = {
+            "library": variable,
+        },
+    )
+
+def library_link_args(name, library_type, from_variable, iterate_over_variable = False):
+    """A helper for declaring a library to link.
+
+    For most platforms, this expands something akin to the following:
+
+        cc_nested_args(
+            name = "foo",
+            requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+            requires_equal_value = "interface_library",
+            iterate_over = None,
+            args = ["{library}"],
+            format = {
+                "library": //cc/toolchains/variables:libraries_to_link.name,
+            },
+        )
+
+    For macos, this expands to a more complex cc_nested_args structure that
+    handles the -force_load flag.
+
+    Args:
+      name: The name of the rule.
+      library_type: The type of the library.
+      from_variable: The variable to expand.
+      iterate_over_variable: Whether to iterate over the variable.
+    """
+    native.alias(
+        name = name,
+        actual = select({
+            "@platforms//os:macos": ":macos_{}".format(name),
+            "//conditions:default": ":generic_{}".format(name),
+        }),
+    )
+    cc_nested_args(
+        name = "generic_{}".format(name),
+        requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+        requires_equal_value = library_type,
+        iterate_over = from_variable if iterate_over_variable else None,
+        args = ["{library}"],
+        format = {
+            "library": from_variable,
+        },
+    )
+    cc_nested_args(
+        name = "macos_{}".format(name),
+        requires_equal = "//cc/toolchains/variables:libraries_to_link.type",
+        requires_equal_value = library_type,
+        iterate_over = from_variable if iterate_over_variable else None,
+        nested = [":{}_maybe_force_load".format(name)],
+    )
+    macos_force_load_library_args(
+        name = "{}_maybe_force_load".format(name),
+        variable = from_variable,
+    )
diff --git a/cc/toolchains/args/linker_param_file/BUILD b/cc/toolchains/args/linker_param_file/BUILD
new file mode 100644
index 0000000..6d1b4b2
--- /dev/null
+++ b/cc/toolchains/args/linker_param_file/BUILD
@@ -0,0 +1,21 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+load("//cc/toolchains:args_list.bzl", "cc_args_list")
+
+package(default_visibility = ["//visibility:private"])
+
+cc_args_list(
+    name = "linker_param_file",
+    args = [":use_param_file"],
+    visibility = ["//visibility:public"],
+)
+
+cc_args(
+    name = "use_param_file",
+    actions = [
+        "//cc/toolchains/actions:link_actions",
+        "//cc/toolchains/actions:ar_actions",
+    ],
+    args = ["@{param_file}"],
+    format = {"param_file": "//cc/toolchains/variables:linker_param_file"},
+    requires_not_none = "//cc/toolchains/variables:linker_param_file",
+)
diff --git a/cc/toolchains/args/runtime_library_search_directories/BUILD b/cc/toolchains/args/runtime_library_search_directories/BUILD
new file mode 100644
index 0000000..50bdb43
--- /dev/null
+++ b/cc/toolchains/args/runtime_library_search_directories/BUILD
@@ -0,0 +1,108 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+load("//cc/toolchains:args_list.bzl", "cc_args_list")
+load("//cc/toolchains:feature_constraint.bzl", "cc_feature_constraint")
+load("//cc/toolchains:nested_args.bzl", "cc_nested_args")
+
+package(default_visibility = ["//visibility:private"])
+
+# TODO: b/27153401 - The implementation of this is particularly complex because
+# of what appears to be a workaround where macOS cc_test targets with
+# static_link_cpp_runtimes enabled utilize a $EXEC_ORIGIN/ prefix. This can be
+# paired down significantly after it is clear this workaround is no longer
+# required.
+
+cc_feature_constraint(
+    name = "static_link_cpp_runtimes_enabled",
+    all_of = ["//cc/toolchains/features:static_link_cpp_runtimes"],
+)
+
+cc_feature_constraint(
+    name = "static_link_cpp_runtimes_disabled",
+    none_of = ["//cc/toolchains/features:static_link_cpp_runtimes"],
+)
+
+cc_args_list(
+    name = "runtime_library_search_directories",
+    args = [
+        ":runtime_library_search_directories_static_runtimes_args",
+        ":runtime_library_search_directories_args",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+cc_args(
+    name = "runtime_library_search_directories_static_runtimes_args",
+    actions = ["//cc/toolchains/actions:link_actions"],
+    nested = [":iterate_over_search_dirs"],
+    requires_any_of = [":static_link_cpp_runtimes_enabled"],
+    requires_not_none = "//cc/toolchains/variables:runtime_library_search_directories",
+)
+
+cc_nested_args(
+    name = "iterate_over_search_dirs",
+    iterate_over = "//cc/toolchains/variables:runtime_library_search_directories",
+    nested = [
+        ":unit_test_static_runtime_search_dir_args",
+        ":static_runtime_search_dir_args",
+    ],
+)
+
+cc_nested_args(
+    name = "unit_test_static_runtime_search_dir_args",
+    args = [
+        "-Xlinker",
+        "-rpath",
+        "-Xlinker",
+        # TODO(b/27153401): This should probably be @loader_path on osx.
+        "$EXEC_ORIGIN/{search_path}",
+    ],
+    format = {
+        "search_path": "//cc/toolchains/variables:runtime_library_search_directories",
+    },
+    requires_true = "//cc/toolchains/variables:is_cc_test",
+)
+
+cc_nested_args(
+    name = "static_runtime_search_dir_args",
+    args = [
+        "-Xlinker",
+        "-rpath",
+        "-Xlinker",
+    ] + select({
+        "@platforms//os:macos": ["@loader_path/{search_path}"],
+        "//conditions:default": ["$ORIGIN/{search_path}"],
+    }),
+    format = {
+        "search_path": "//cc/toolchains/variables:runtime_library_search_directories",
+    },
+    requires_false = "//cc/toolchains/variables:is_cc_test",
+)
+
+# TODO: b/27153401 - runtime_library_search_directories_args and
+# search_dir_args are all we need to keep if the workaround is no
+# longer required.
+cc_args(
+    name = "runtime_library_search_directories_args",
+    actions = ["//cc/toolchains/actions:link_actions"],
+    nested = [":search_dir_args"],
+    # Remove the requires_any_of here if the workaround for b/27153401 is no
+    # longer required.
+    requires_any_of = [":static_link_cpp_runtimes_disabled"],
+    requires_not_none = "//cc/toolchains/variables:runtime_library_search_directories",
+)
+
+cc_nested_args(
+    name = "search_dir_args",
+    args = [
+        "-Xlinker",
+        "-rpath",
+        "-Xlinker",
+    ] + select({
+        "@platforms//os:macos": ["@loader_path/{search_path}"],
+        "//conditions:default": ["$ORIGIN/{search_path}"],
+    }),
+    format = {
+        "search_path": "//cc/toolchains/variables:runtime_library_search_directories",
+    },
+    iterate_over = "//cc/toolchains/variables:runtime_library_search_directories",
+)
diff --git a/cc/toolchains/args/shared_flag/BUILD b/cc/toolchains/args/shared_flag/BUILD
new file mode 100644
index 0000000..0c4f1e9
--- /dev/null
+++ b/cc/toolchains/args/shared_flag/BUILD
@@ -0,0 +1,10 @@
+load("//cc/toolchains:args.bzl", "cc_args")
+
+package(default_visibility = ["//visibility:private"])
+
+cc_args(
+    name = "shared_flag",
+    actions = ["//cc/toolchains/actions:dynamic_library_link_actions"],
+    args = ["-shared"],
+    visibility = ["//visibility:public"],
+)
diff --git a/cc/toolchains/args/sysroot.bzl b/cc/toolchains/args/sysroot.bzl
new file mode 100644
index 0000000..6898535
--- /dev/null
+++ b/cc/toolchains/args/sysroot.bzl
@@ -0,0 +1,43 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Implementation of the cc_sysroot macro."""
+
+load("//cc/toolchains:args.bzl", "cc_args")
+
+visibility("public")
+
+_DEFAULT_SYSROOT_ACTIONS = [
+    Label("//cc/toolchains/actions:cpp_compile_actions"),
+    Label("//cc/toolchains/actions:c_compile"),
+    Label("//cc/toolchains/actions:link_actions"),
+]
+
+def cc_sysroot(*, name, sysroot, actions = _DEFAULT_SYSROOT_ACTIONS, args = [], **kwargs):
+    """Creates args for a sysroot.
+
+    Args:
+      name: (str) The name of the target
+      sysroot: (bazel_skylib's directory rule) The directory that should be the
+        sysroot.
+      actions: (List[Label]) Actions the `--sysroot` flag should be applied to.
+      args: (List[str]) Extra command-line args to add.
+      **kwargs: kwargs to pass to cc_args.
+    """
+    cc_args(
+        name = name,
+        actions = actions,
+        args = ["--sysroot={sysroot}"] + args,
+        format = {"sysroot": sysroot},
+        **kwargs
+    )
diff --git a/cc/toolchains/args_list.bzl b/cc/toolchains/args_list.bzl
index fbbaad5..0747acb 100644
--- a/cc/toolchains/args_list.bzl
+++ b/cc/toolchains/args_list.bzl
@@ -24,11 +24,49 @@ def _cc_args_list_impl(ctx):
 
 cc_args_list = rule(
     implementation = _cc_args_list_impl,
-    doc = "A list of cc_args",
+    doc = """An ordered list of cc_args.
+
+    This is a convenience rule to allow you to group a set of multiple `cc_args` into a
+    single list. This particularly useful for toolchain behaviors that require different flags for
+    different actions.
+
+    Note: The order of the arguments in `args` is preserved to support order-sensitive flags.
+
+    Example usage:
+    ```
+    load("//cc/toolchains:cc_args.bzl", "cc_args")
+    load("//cc/toolchains:args_list.bzl", "cc_args_list")
+
+    cc_args(
+        name = "gc_sections",
+        actions = [
+            "//cc/toolchains/actions:link_actions",
+        ],
+        args = ["-Wl,--gc-sections"],
+    )
+
+    cc_args(
+        name = "function_sections",
+        actions = [
+            "//cc/toolchains/actions:compile_actions",
+            "//cc/toolchains/actions:link_actions",
+        ],
+        args = ["-ffunction-sections"],
+    )
+
+    cc_args_list(
+        name = "gc_functions",
+        args = [
+            ":function_sections",
+            ":gc_sections",
+        ],
+    )
+    ```
+    """,
     attrs = {
         "args": attr.label_list(
             providers = [ArgsListInfo],
-            doc = "The cc_args to include",
+            doc = "(ordered) cc_args to include in this list.",
         ),
     },
     provides = [ArgsListInfo],
diff --git a/cc/toolchains/capabilities/BUILD b/cc/toolchains/capabilities/BUILD
new file mode 100644
index 0000000..8c55804
--- /dev/null
+++ b/cc/toolchains/capabilities/BUILD
@@ -0,0 +1,19 @@
+load("//cc/toolchains:tool_capability.bzl", "cc_tool_capability")
+
+package(default_visibility = ["//visibility:public"])
+
+cc_tool_capability(
+    name = "supports_start_end_lib",
+)
+
+cc_tool_capability(
+    name = "supports_interface_shared_libraries",
+)
+
+cc_tool_capability(
+    name = "supports_dynamic_linker",
+)
+
+cc_tool_capability(
+    name = "supports_pic",
+)
diff --git a/cc/private/rules_impl/cc_flags_supplier.bzl b/cc/toolchains/cc_flags_supplier.bzl
similarity index 83%
rename from cc/private/rules_impl/cc_flags_supplier.bzl
rename to cc/toolchains/cc_flags_supplier.bzl
index 474c7ce..17adbad 100644
--- a/cc/private/rules_impl/cc_flags_supplier.bzl
+++ b/cc/toolchains/cc_flags_supplier.bzl
@@ -13,8 +13,8 @@
 # limitations under the License.
 """Rule that provides the CC_FLAGS Make variable."""
 
-load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
 load("//cc:action_names.bzl", "CC_FLAGS_MAKE_VARIABLE_ACTION_NAME")
+load("//cc:find_cc_toolchain.bzl", "find_cpp_toolchain", "use_cc_toolchain")
 load("//cc/private/rules_impl:cc_flags_supplier_lib.bzl", "build_cc_flags")
 
 def _cc_flags_supplier_impl(ctx):
@@ -28,8 +28,8 @@ def _cc_flags_supplier_impl(ctx):
 cc_flags_supplier = rule(
     implementation = _cc_flags_supplier_impl,
     attrs = {
-        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
+        "_cc_toolchain": attr.label(default = Label("@rules_cc//cc:current_cc_toolchain")),
     },
-    toolchains = use_cpp_toolchain(),
+    toolchains = use_cc_toolchain(),
     fragments = ["cpp"],
 )
diff --git a/cc/toolchains/cc_toolchain.bzl b/cc/toolchains/cc_toolchain.bzl
new file mode 100644
index 0000000..0272b12
--- /dev/null
+++ b/cc/toolchains/cc_toolchain.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""cc_toolchain rule"""
+
+def cc_toolchain(**kwargs):
+    native.cc_toolchain(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/toolchains/cc_toolchain_config_info.bzl b/cc/toolchains/cc_toolchain_config_info.bzl
new file mode 100644
index 0000000..cc310ab
--- /dev/null
+++ b/cc/toolchains/cc_toolchain_config_info.bzl
@@ -0,0 +1,19 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""CcToolchainConfigInfo"""
+
+load("//cc/private/rules_impl:native.bzl", "NativeCcToolchainConfigInfo")
+
+CcToolchainConfigInfo = NativeCcToolchainConfigInfo
diff --git a/cc/toolchains/cc_toolchain_info.bzl b/cc/toolchains/cc_toolchain_info.bzl
index 3a499f6..17881a8 100644
--- a/cc/toolchains/cc_toolchain_info.bzl
+++ b/cc/toolchains/cc_toolchain_info.bzl
@@ -87,6 +87,7 @@ ArgsInfo = provider(
         "nested": "(Optional[NestedArgsInfo]) The args expand. Equivalent to a flag group.",
         "files": "(depset[File]) Files required for the args",
         "env": "(dict[str, str]) Environment variables to apply",
+        "allowlist_include_directories": "(depset[DirectoryInfo]) Include directories implied by these arguments that should be allowlisted in Bazel's include checker",
     },
 )
 ArgsListInfo = provider(
@@ -97,6 +98,7 @@ ArgsListInfo = provider(
         "args": "(Sequence[ArgsInfo]) The flag sets contained within",
         "files": "(depset[File]) The files required for all of the arguments",
         "by_action": "(Sequence[struct(action=ActionTypeInfo, args=List[ArgsInfo], files=depset[Files])]) Relevant information about the args keyed by the action type.",
+        "allowlist_include_directories": "(depset[DirectoryInfo]) Include directories implied by these arguments that should be allowlisted in Bazel's include checker",
     },
 )
 
@@ -114,6 +116,7 @@ FeatureInfo = provider(
         "external": "(bool) Whether a feature is defined elsewhere.",
         "overridable": "(bool) Whether the feature is an overridable feature.",
         "overrides": "(Optional[FeatureInfo]) The feature that this overrides. Must be a known feature",
+        "allowlist_include_directories": "(depset[DirectoryInfo]) Include directories implied by this feature that should be allowlisted in Bazel's include checker",
     },
 )
 FeatureSetInfo = provider(
@@ -150,31 +153,28 @@ ToolInfo = provider(
     fields = {
         "label": "(Label) The label defining this provider. Place in error messages to simplify debugging",
         "exe": "(File) The file corresponding to the tool",
-        "runfiles": "(depset[File]) The files required to run the tool",
-        "requires_any_of": "(Sequence[FeatureConstraintInfo]) A set of constraints, one of which is required to enable the tool. Equivalent to with_features",
+        "runfiles": "(runfiles) The files required to run the tool",
         "execution_requirements": "(Sequence[str]) A set of execution requirements of the tool",
+        "allowlist_include_directories": "(depset[DirectoryInfo]) Built-in include directories implied by this tool that should be allowlisted in Bazel's include checker",
+        "capabilities": "(Sequence[ToolCapabilityInfo]) Capabilities supported by the tool.",
     },
 )
 
-ActionTypeConfigInfo = provider(
-    doc = "Configuration of a Bazel action.",
+ToolCapabilityInfo = provider(
+    doc = "A capability associated with a tool (eg. supports_pic).",
     # @unsorted-dict-items
     fields = {
         "label": "(Label) The label defining this provider. Place in error messages to simplify debugging",
-        "action_type": "(ActionTypeInfo) The type of the action",
-        "tools": "(Sequence[ToolInfo]) The tool applied to the action will be the first tool in the sequence with a feature set that matches the feature configuration",
-        "args": "(Sequence[ArgsInfo]) Set of flag sets the action sets",
-        "implies": "(depset[FeatureInfo]) Set of features implied by this action config",
-        "files": "(runfiles) The files required to run these actions",
+        "feature": "(FeatureInfo) The feature this capability defines",
     },
 )
 
-ActionTypeConfigSetInfo = provider(
-    doc = "A set of action configs",
+ToolConfigInfo = provider(
+    doc = "A mapping from action to tool",
     # @unsorted-dict-items
     fields = {
         "label": "(Label) The label defining this provider. Place in error messages to simplify debugging",
-        "configs": "(dict[ActionTypeInfo, ActionTypeConfigInfo]) A set of action configs",
+        "configs": "(dict[ActionTypeInfo, ToolInfo]) A mapping from action to tool.",
     },
 )
 
@@ -184,8 +184,10 @@ ToolchainConfigInfo = provider(
     fields = {
         "label": "(Label) The label defining this provider. Place in error messages to simplify debugging",
         "features": "(Sequence[FeatureInfo]) The features available for this toolchain",
-        "action_type_configs": "(dict[ActionTypeInfo, ActionTypeConfigInfo]) The configuration of action configs for the toolchain.",
+        "enabled_features": "(Sequence[FeatureInfo]) The features That are enabled by default for this toolchain",
+        "tool_map": "(ToolConfigInfo) A provider mapping toolchain action types to tools.",
         "args": "(Sequence[ArgsInfo]) A list of arguments to be unconditionally applied to the toolchain.",
         "files": "(dict[ActionTypeInfo, depset[File]]) Files required for the toolchain, keyed by the action type.",
+        "allowlist_include_directories": "(depset[DirectoryInfo]) Built-in include directories implied by this toolchain's args and tools that should be allowlisted in Bazel's include checker",
     },
 )
diff --git a/cc/toolchains/cc_toolchain_suite.bzl b/cc/toolchains/cc_toolchain_suite.bzl
new file mode 100644
index 0000000..66c42b2
--- /dev/null
+++ b/cc/toolchains/cc_toolchain_suite.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""cc_toolchain_suite rule"""
+
+def cc_toolchain_suite(**kwargs):
+    native.cc_toolchain_suite(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/private/rules_impl/compiler_flag.bzl b/cc/toolchains/compiler_flag.bzl
similarity index 79%
rename from cc/private/rules_impl/compiler_flag.bzl
rename to cc/toolchains/compiler_flag.bzl
index ebbac94..502efe7 100644
--- a/cc/private/rules_impl/compiler_flag.bzl
+++ b/cc/toolchains/compiler_flag.bzl
@@ -14,7 +14,7 @@
 
 """Rule that allows select() to differentiate between compilers."""
 
-load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
+load("//cc:find_cc_toolchain.bzl", "find_cpp_toolchain", "use_cc_toolchain")
 
 def _compiler_flag_impl(ctx):
     toolchain = find_cpp_toolchain(ctx)
@@ -23,7 +23,7 @@ def _compiler_flag_impl(ctx):
 compiler_flag = rule(
     implementation = _compiler_flag_impl,
     attrs = {
-        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
+        "_cc_toolchain": attr.label(default = Label("@rules_cc//cc:current_cc_toolchain")),
     },
-    toolchains = use_cpp_toolchain(),
+    toolchains = use_cc_toolchain(),
 )
diff --git a/cc/toolchains/directory_tool.bzl b/cc/toolchains/directory_tool.bzl
new file mode 100644
index 0000000..b4572e7
--- /dev/null
+++ b/cc/toolchains/directory_tool.bzl
@@ -0,0 +1,49 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Macro to extract tools from a directory."""
+
+load("@bazel_skylib//rules/directory:glob.bzl", "directory_glob")
+load(":tool.bzl", "cc_tool")
+
+def cc_directory_tool(name, directory, executable, data = [], exclude = [], allow_empty = False, **kwargs):
+    """A tool extracted from a directory.
+
+    Args:
+        name: (str) The name of the generated target
+        directory: (Label) The directory to extract from
+        executable: (str) The relative path from the directory to the
+            executable.
+        data: (List[str]) A list of globs to runfiles for the executable,
+          relative to the directory.
+        exclude: (List[str]) A list of globs to exclude from data.
+        allow_empty: (bool) If false, any glob that fails to match anything will
+          result in a failure.
+        **kwargs: Kwargs to be passed through to cc_tool.
+    """
+    files_name = "_%s_files" % name
+    directory_glob(
+        name = files_name,
+        directory = directory,
+        srcs = [executable],
+        data = data,
+        exclude = exclude,
+        allow_empty = allow_empty,
+        visibility = ["//visibility:private"],
+    )
+
+    cc_tool(
+        name = name,
+        src = files_name,
+        **kwargs
+    )
diff --git a/cc/toolchains/fdo_prefetch_hints.bzl b/cc/toolchains/fdo_prefetch_hints.bzl
new file mode 100644
index 0000000..3215856
--- /dev/null
+++ b/cc/toolchains/fdo_prefetch_hints.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""fdo_prefetch_hints rule"""
+
+def fdo_prefetch_hints(**kwargs):
+    native.fdo_prefetch_hints(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/toolchains/fdo_profile.bzl b/cc/toolchains/fdo_profile.bzl
new file mode 100644
index 0000000..9450455
--- /dev/null
+++ b/cc/toolchains/fdo_profile.bzl
@@ -0,0 +1,18 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""fdo_profile rule"""
+
+def fdo_profile(**kwargs):
+    native.fdo_profile(**kwargs)  # buildifier: disable=native-cc
diff --git a/cc/toolchains/feature.bzl b/cc/toolchains/feature.bzl
index c81a756..f0acbfe 100644
--- a/cc/toolchains/feature.bzl
+++ b/cc/toolchains/feature.bzl
@@ -62,11 +62,14 @@ def _cc_feature_impl(ctx):
     if name.startswith("implied_by_"):
         fail("Feature names starting with 'implied_by' are reserved")
 
+    args = collect_args_lists(ctx.attr.args, ctx.label)
     feature = FeatureInfo(
         label = ctx.label,
         name = name,
-        enabled = ctx.attr.enabled,
-        args = collect_args_lists(ctx.attr.args, ctx.label),
+        # Unused field, but leave it just in case we want to reuse it in the
+        # future.
+        enabled = False,
+        args = args,
         implies = collect_features(ctx.attr.implies),
         requires_any_of = tuple(collect_provider(
             ctx.attr.requires_any_of,
@@ -79,6 +82,7 @@ def _cc_feature_impl(ctx):
         external = False,
         overridable = False,
         overrides = overrides,
+        allowlist_include_directories = args.allowlist_include_directories,
     )
 
     return [
@@ -106,27 +110,23 @@ While two features with the same `feature_name` may not be bound to the same
 toolchain, they can happily live alongside each other in the same BUILD file.
 
 Example:
+```
+cc_feature(
+    name = "sysroot_macos",
+    feature_name = "sysroot",
+    ...
+)
 
-    cc_feature(
-        name = "sysroot_macos",
-        feature_name = "sysroot",
-        ...
-    )
-
-    cc_feature(
-        name = "sysroot_linux",
-        feature_name = "sysroot",
-        ...
-    )
+cc_feature(
+    name = "sysroot_linux",
+    feature_name = "sysroot",
+    ...
+)
+```
 """,
         ),
-        "enabled": attr.bool(
-            mandatory = True,
-            doc = """Whether or not this feature is enabled by default.""",
-        ),
         "args": attr.label_list(
-            mandatory = True,
-            doc = """Args that, when expanded, implement this feature.""",
+            doc = """A list of `cc_args` or `cc_args_list` labels that are expanded when this feature is enabled.""",
             providers = [ArgsListInfo],
         ),
         "requires_any_of": attr.label_list(
@@ -138,7 +138,8 @@ deemed compatible and may be enabled.
 
 Note: Even if `cc_feature.requires_any_of` is satisfied, a feature is not
 enabled unless another mechanism (e.g. command-line flags, `cc_feature.implies`,
-`cc_feature.enabled`) signals that the feature should actually be enabled.
+`cc_toolchain_config.enabled_features`) signals that the feature should actually
+be enabled.
 """,
             providers = [FeatureSetInfo],
         ),
@@ -152,7 +153,7 @@ silently disabled.
         ),
         "mutually_exclusive": attr.label_list(
             providers = [MutuallyExclusiveCategoryInfo],
-            doc = """A list of things that this is mutually exclusive with.
+            doc = """A list of things that this feature is mutually exclusive with.
 
 It can be either:
 * A feature, in which case the two features are mutually exclusive.
@@ -160,8 +161,7 @@ It can be either:
     `mutually_exclusive = [":category"]` are mutually exclusive with each other.
 
 If this feature has a side-effect of implementing another feature, it can be
-useful to list that feature here to ensure they aren't enabled at the
-same time.
+useful to list that feature here to ensure they aren't enabled at the same time.
 """,
         ),
         "overrides": attr.label(
@@ -172,14 +172,16 @@ In the example below, if you missed the "overrides" attribute, it would complain
 that the feature "opt" was defined twice.
 
 Example:
-
-    cc_feature(
-      name = "opt",
-      feature_name = "opt",
-      ...
-      overrides = "@toolchain//features/well_known:opt",
-    )
-
+```
+load("//cc/toolchains:feature.bzl", "cc_feature")
+
+cc_feature(
+    name = "opt",
+    feature_name = "opt",
+    args = [":size_optimized"],
+    overrides = "//cc/toolchains/features:opt",
+)
+```
 """,
         ),
     },
@@ -189,55 +191,58 @@ Example:
         FeatureConstraintInfo,
         MutuallyExclusiveCategoryInfo,
     ],
-    doc = """Defines the implemented behavior of a C/C++ toolchain feature.
+    doc = """A dynamic set of toolchain flags that create a singular [feature](https://bazel.build/docs/cc-toolchain-config-reference#features) definition.
 
-A feature is basically a toggleable list of args. There are a variety of
-dependencies and compatibility requirements that must be satisfied for the
-listed args to be applied.
+A feature is basically a dynamically toggleable `cc_args_list`. There are a variety of
+dependencies and compatibility requirements that must be satisfied to enable a
+`cc_feature`. Once those conditions are met, the arguments in [`cc_feature.args`](#cc_feature-args)
+are expanded and added to the command-line.
 
 A feature may be enabled or disabled through the following mechanisms:
-* Via command-line flags, or a `.bazelrc`.
-* Through inter-feature relationships (enabling one feature may implicitly
-  enable another).
-* Individual rules may elect to manually enable or disable features through the
-  builtin `features` attribute.
-
-Because of the toggleable nature of toolchain features, it's generally best to
-avoid defining features as part of your toolchain with the following exceptions:
-* You want build files to be able to configure compiler flags. For example, a
+* Via command-line flags, or a `.bazelrc` file via the
+  [`--features` flag](https://bazel.build/reference/command-line-reference#flag--features)
+* Through inter-feature relationships (via [`cc_feature.implies`](#cc_feature-implies)) where one
+  feature may implicitly enable another.
+* Individual rules (e.g. `cc_library`) or `package` definitions may elect to manually enable or
+  disable features through the
+  [`features` attribute](https://bazel.build/reference/be/common-definitions#common.features).
+
+Note that a feature may alternate between enabled and disabled dynamically over the course of a
+build. Because of their toggleable nature, it's generally best to avoid adding arguments to a
+`cc_toolchain` as a `cc_feature` unless strictly necessary. Instead, prefer to express arguments
+via [`cc_toolchain.args`](#cc_toolchain-args) whenever possible.
+
+You should use a `cc_feature` when any of the following apply:
+* You need the flags to be dynamically toggled over the course of a build.
+* You want build files to be able to configure the flags in question. For example, a
   binary might specify `features = ["optimize_for_size"]` to create a small
   binary instead of optimizing for performance.
 * You need to carry forward Starlark toolchain behaviors. If you're migrating a
   complex Starlark-based toolchain definition to these rules, many of the
-  workflows and flags were likely based on features. This rule exists to support
-  those existing structures.
+  workflows and flags were likely based on features.
 
-If you want to be able to configure flags via the bazel command-line, instead
-consider making a bool_flag, and then making your `cc_args` `select` on those
-flags.
+If you only need to configure flags via the Bazel command-line, instead
+consider adding a
+[`bool_flag`](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/common_settings_doc.md#bool_flag)
+paired with a [`config_setting`](https://bazel.build/reference/be/general#config_setting)
+and then make your `cc_args` rule `select` on the `config_setting`.
 
 For more details about how Bazel handles features, see the official Bazel
 documentation at
 https://bazel.build/docs/cc-toolchain-config-reference#features.
 
-Examples:
-
-    # A feature that can be easily toggled to optimize for size
-    cc_feature(
-        name = "optimize_for_size",
-        enabled = False,
-        feature_name = "optimize_for_size",
-        args = [":optimize_for_size_args"],
-    )
-
-    # This feature signals a capability, and doesn't have associated flags.
-    #
-    # For a list of well-known features, see:
-    #    https://bazel.build/docs/cc-toolchain-config-reference#wellknown-features
-    cc_feature(
-        name = "supports_pic",
-        enabled = True,
-        overrides = "//cc/toolchains/features:supports_pic
-    )
+Example:
+```
+load("//cc/toolchains:feature.bzl", "cc_feature")
+
+# A feature that enables LTO, which may be incompatible when doing interop with various
+# languages (e.g. rust, go), or may need to be disabled for particular `cc_binary` rules
+# for various reasons.
+cc_feature(
+    name = "lto",
+    feature_name = "lto",
+    args = [":lto_args"],
+)
+```
 """,
 )
diff --git a/cc/toolchains/feature_constraint.bzl b/cc/toolchains/feature_constraint.bzl
index c6ae44a..8a3d60f 100644
--- a/cc/toolchains/feature_constraint.bzl
+++ b/cc/toolchains/feature_constraint.bzl
@@ -47,8 +47,26 @@ cc_feature_constraint = rule(
         ),
     },
     provides = [FeatureConstraintInfo],
-    doc = """Defines a constraint on features.
+    doc = """Defines a compound relationship between features.
 
-Can be used with require_any_of to specify that something is only enabled when
-a constraint is met.""",
+This rule can be used with [`cc_args.require_any_of`](#cc_args-require_any_of) to specify that a set
+of arguments are only enabled when a constraint is met. Both `all_of` and `none_of` must be
+satisfied simultaneously.
+
+This is basically a `cc_feature_set` that supports `none_of` expressions. This extra flexibility
+is why this rule may only be used by [`cc_args.require_any_of`](#cc_args-require_any_of).
+
+Example:
+```
+load("//cc/toolchains:feature_constraint.bzl", "cc_feature_constraint")
+
+# A constraint that requires a `linker_supports_thinlto` feature to be enabled,
+# AND a `no_optimization` to be disabled.
+cc_feature_constraint(
+    name = "thinlto_constraint",
+    all_of = [":linker_supports_thinlto"],
+    none_of = [":no_optimization"],
+)
+```
+""",
 )
diff --git a/cc/toolchains/feature_set.bzl b/cc/toolchains/feature_set.bzl
index 07af6d1..c4a0756 100644
--- a/cc/toolchains/feature_set.bzl
+++ b/cc/toolchains/feature_set.bzl
@@ -44,14 +44,20 @@ cc_feature_set = rule(
     provides = [FeatureSetInfo],
     doc = """Defines a set of features.
 
+This may be used by both `cc_feature` and `cc_args` rules, and is effectively a way to express
+a logical `AND` operation across multiple required features.
+
 Example:
+```
+load("//cc/toolchains:feature_set.bzl", "cc_feature_set")
 
-    cc_feature_set(
-        name = "thin_lto_requirements",
-        all_of = [
-            ":thin_lto",
-            ":opt",
-        ],
-    )
+cc_feature_set(
+    name = "thin_lto_requirements",
+    all_of = [
+        ":thin_lto",
+        ":opt",
+    ],
+)
+```
 """,
 )
diff --git a/cc/toolchains/features/BUILD b/cc/toolchains/features/BUILD
index 6c6088b..22c3519 100644
--- a/cc/toolchains/features/BUILD
+++ b/cc/toolchains/features/BUILD
@@ -41,36 +41,12 @@ cc_external_feature(
     overridable = True,
 )
 
-cc_external_feature(
-    name = "supports_start_end_lib",
-    feature_name = "supports_start_end_lib",
-    overridable = True,
-)
-
-cc_external_feature(
-    name = "supports_interface_shared_libraries",
-    feature_name = "supports_interface_shared_libraries",
-    overridable = True,
-)
-
-cc_external_feature(
-    name = "supports_dynamic_linker",
-    feature_name = "supports_dynamic_linker",
-    overridable = True,
-)
-
 cc_external_feature(
     name = "static_link_cpp_runtimes",
     feature_name = "static_link_cpp_runtimes",
     overridable = True,
 )
 
-cc_external_feature(
-    name = "supports_pic",
-    feature_name = "supports_pic",
-    overridable = True,
-)
-
 cc_feature_set(
     name = "all_non_legacy_builtin_features",
     all_of = [
@@ -80,11 +56,7 @@ cc_feature_set(
         ":static_linking_mode",
         ":dynamic_linking_mode",
         ":per_object_debug_info",
-        ":supports_start_end_lib",
-        ":supports_interface_shared_libraries",
-        ":supports_dynamic_linker",
         ":static_link_cpp_runtimes",
-        ":supports_pic",
     ],
     visibility = ["//visibility:private"],
 )
diff --git a/cc/toolchains/features/legacy/BUILD b/cc/toolchains/features/legacy/BUILD
index c7953a0..af68df4 100644
--- a/cc/toolchains/features/legacy/BUILD
+++ b/cc/toolchains/features/legacy/BUILD
@@ -97,6 +97,7 @@ cc_external_feature(
 
 cc_external_feature(
     name = "shared_flag",
+    deprecation = "Use //cc/toolchains/args/shared_flag instead",
     feature_name = "shared_flag",
     overridable = True,
 )
@@ -115,6 +116,7 @@ cc_external_feature(
 
 cc_external_feature(
     name = "runtime_library_search_directories",
+    deprecation = "Use //cc/toolchains/args/runtime_library_search_directories instead",
     feature_name = "runtime_library_search_directories",
     overridable = True,
 )
@@ -127,18 +129,21 @@ cc_external_feature(
 
 cc_external_feature(
     name = "archiver_flags",
+    deprecation = "Use //cc/toolchains/args/archiver_flags instead",
     feature_name = "archiver_flags",
     overridable = True,
 )
 
 cc_external_feature(
     name = "libraries_to_link",
+    deprecation = "Use //cc/toolchains/args/libraries_to_link instead",
     feature_name = "libraries_to_link",
     overridable = True,
 )
 
 cc_external_feature(
     name = "force_pic_flags",
+    deprecation = "Use //cc/toolchains/args/force_pic_flags instead",
     feature_name = "force_pic_flags",
     overridable = True,
 )
@@ -203,11 +208,8 @@ cc_external_feature(
     overridable = True,
 )
 
-cc_external_feature(
-    name = "sysroot",
-    feature_name = "sysroot",
-    overridable = True,
-)
+# Instead of the "sysroot" legacy flag, use the cc_sysroot macro in
+# //cc/toolchains/args:sysroot.bzl
 
 cc_external_feature(
     name = "unfiltered_compile_flags",
@@ -217,6 +219,7 @@ cc_external_feature(
 
 cc_external_feature(
     name = "linker_param_file",
+    deprecation = "Use //cc/toolchains/args/linker_param_file instead",
     feature_name = "linker_param_file",
     overridable = True,
 )
@@ -269,7 +272,6 @@ cc_feature_set(
         ":gcc_coverage_map_format",
         ":fully_static_link",
         ":user_compile_flags",
-        ":sysroot",
         ":unfiltered_compile_flags",
         ":linker_param_file",
         ":compiler_input_flags",
diff --git a/cc/toolchains/impl/BUILD b/cc/toolchains/impl/BUILD
index 8484e1c..f621832 100644
--- a/cc/toolchains/impl/BUILD
+++ b/cc/toolchains/impl/BUILD
@@ -4,3 +4,16 @@
 
 # I wanted to call it private / internal, but then buildifier complains about
 # referencing it from the tests directory.
+
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+exports_files(
+    ["documented_api.bzl"],
+    visibility = ["//docs:__pkg__"],
+)
+
+bzl_library(
+    name = "toolchain_impl_rules",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//cc/toolchains:__subpackages__"],
+)
diff --git a/cc/toolchains/impl/collect.bzl b/cc/toolchains/impl/collect.bzl
index 3fab3e6..e242d91 100644
--- a/cc/toolchains/impl/collect.bzl
+++ b/cc/toolchains/impl/collect.bzl
@@ -15,7 +15,6 @@
 
 load(
     "//cc/toolchains:cc_toolchain_info.bzl",
-    "ActionTypeConfigSetInfo",
     "ActionTypeSetInfo",
     "ArgsListInfo",
     "FeatureSetInfo",
@@ -106,8 +105,9 @@ def collect_tools(ctx, targets, fail = fail):
                 label = target.label,
                 exe = info.files_to_run.executable,
                 runfiles = collect_data(ctx, [target]),
-                requires_any_of = tuple(),
                 execution_requirements = tuple(),
+                allowlist_include_directories = depset(),
+                capabilities = tuple(),
             ))
         else:
             fail("Expected %s to be a cc_tool or a binary rule" % target.label)
@@ -143,6 +143,9 @@ def collect_args_lists(targets, label):
         label = label,
         args = tuple(args),
         files = depset(transitive = transitive_files),
+        allowlist_include_directories = depset(
+            transitive = [a.allowlist_include_directories for a in args],
+        ),
         by_action = tuple([
             struct(
                 action = k,
@@ -152,22 +155,3 @@ def collect_args_lists(targets, label):
             for k, v in by_action.items()
         ]),
     )
-
-def collect_action_type_config_sets(targets, label, fail = fail):
-    """Collects several `cc_action_type_config` labels together.
-
-    Args:
-        targets: (List[Target]) A list of targets providing ActionTypeConfigSetInfo
-        label: The label to apply to the resulting config.
-        fail: (function) The fail function. Should only be used in tests.
-    Returns:
-        A combined ActionTypeConfigSetInfo representing a variety of action
-        types.
-    """
-    configs = {}
-    for atcs in collect_provider(targets, ActionTypeConfigSetInfo):
-        for action_type, config in atcs.configs.items():
-            if action_type in configs:
-                fail("The action type %s is configured by both %s and %s. Each action type may only be configured once." % (action_type.label, config.label, configs[action_type].label))
-            configs[action_type] = config
-    return ActionTypeConfigSetInfo(label = label, configs = configs)
diff --git a/cc/toolchains/impl/documented_api.bzl b/cc/toolchains/impl/documented_api.bzl
new file mode 100644
index 0000000..e6cfa99
--- /dev/null
+++ b/cc/toolchains/impl/documented_api.bzl
@@ -0,0 +1,66 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""This is a list of rules/macros that should be exported as documentation."""
+
+load("//cc/toolchains:actions.bzl", _cc_action_type = "cc_action_type", _cc_action_type_set = "cc_action_type_set")
+load("//cc/toolchains:args.bzl", _cc_args = "cc_args")
+load("//cc/toolchains:args_list.bzl", _cc_args_list = "cc_args_list")
+load("//cc/toolchains:feature.bzl", _cc_feature = "cc_feature")
+load("//cc/toolchains:feature_constraint.bzl", _cc_feature_constraint = "cc_feature_constraint")
+load("//cc/toolchains:feature_set.bzl", _cc_feature_set = "cc_feature_set")
+load("//cc/toolchains:mutually_exclusive_category.bzl", _cc_mutually_exclusive_category = "cc_mutually_exclusive_category")
+load("//cc/toolchains:nested_args.bzl", _cc_nested_args = "cc_nested_args")
+load("//cc/toolchains:tool.bzl", _cc_tool = "cc_tool")
+load("//cc/toolchains:tool_capability.bzl", _cc_tool_capability = "cc_tool_capability")
+load("//cc/toolchains:tool_map.bzl", _cc_tool_map = "cc_tool_map")
+load("//cc/toolchains:toolchain.bzl", _cc_toolchain = "cc_toolchain")
+load("//cc/toolchains/impl:external_feature.bzl", _cc_external_feature = "cc_external_feature")
+load("//cc/toolchains/impl:variables.bzl", _cc_variable = "cc_variable")
+
+cc_tool_map = _cc_tool_map
+cc_tool = _cc_tool
+cc_tool_capability = _cc_tool_capability
+cc_args = _cc_args
+cc_nested_args = _cc_nested_args
+cc_args_list = _cc_args_list
+cc_action_type = _cc_action_type
+cc_action_type_set = _cc_action_type_set
+cc_variable = _cc_variable
+cc_feature = _cc_feature
+cc_feature_constraint = _cc_feature_constraint
+cc_feature_set = _cc_feature_set
+cc_mutually_exclusive_category = _cc_mutually_exclusive_category
+cc_external_feature = _cc_external_feature
+cc_toolchain = _cc_toolchain
+
+# This list is used to automatically remap instances of `foo` to [`foo`](#foo)
+# links in the generated documentation so that maintainers don't need to manually
+# ensure every reference to a rule is properly linked.
+DOCUMENTED_TOOLCHAIN_RULES = [
+    "cc_tool_map",
+    "cc_tool",
+    "cc_tool_capability",
+    "cc_args",
+    "cc_nested_args",
+    "cc_args_list",
+    "cc_action_type",
+    "cc_action_type_set",
+    "cc_variable",
+    "cc_feature",
+    "cc_feature_constraint",
+    "cc_feature_set",
+    "cc_mutually_exclusive_category",
+    "cc_external_feature",
+    "cc_toolchain",
+]
diff --git a/cc/toolchains/impl/external_feature.bzl b/cc/toolchains/impl/external_feature.bzl
index 0853b32..027738f 100644
--- a/cc/toolchains/impl/external_feature.bzl
+++ b/cc/toolchains/impl/external_feature.bzl
@@ -43,6 +43,7 @@ def _cc_external_feature_impl(ctx):
         external = True,
         overridable = ctx.attr.overridable,
         overrides = None,
+        allowlist_include_directories = depset(),
     )
     providers = [
         feature,
@@ -68,5 +69,26 @@ cc_external_feature = rule(
         ),
     },
     provides = [FeatureInfo, FeatureSetInfo, FeatureConstraintInfo],
-    doc = "A declaration that a feature with this name is defined elsewhere.",
+    doc = """A declaration that a [feature](https://bazel.build/docs/cc-toolchain-config-reference#features) with this name is defined elsewhere.
+
+This rule communicates that a feature has been defined externally to make it possible to reference
+features that live outside the rule-based cc toolchain ecosystem. This allows various toolchain
+rules to reference the external feature without accidentally re-defining said feature.
+
+This rule is currently considered a private API of the toolchain rules to encourage the Bazel
+ecosystem to migrate to properly defining their features as rules.
+
+Example:
+```
+load("//cc/toolchains:external_feature.bzl", "cc_external_feature")
+
+# rules_rust defines a feature that is disabled whenever rust artifacts are being linked using
+# the cc toolchain to signal that incompatible flags should be disabled as well.
+cc_external_feature(
+    name = "rules_rust_unsupported_feature",
+    feature_name = "rules_rust_unsupported_feature",
+    overridable = False,
+)
+```
+""",
 )
diff --git a/cc/toolchains/impl/legacy_converter.bzl b/cc/toolchains/impl/legacy_converter.bzl
index 9f9d2a9..6eafc4f 100644
--- a/cc/toolchains/impl/legacy_converter.bzl
+++ b/cc/toolchains/impl/legacy_converter.bzl
@@ -24,11 +24,6 @@ load(
     legacy_tool = "tool",
     legacy_with_feature_set = "with_feature_set",
 )
-load(
-    "//cc/toolchains:cc_toolchain_info.bzl",
-    "ArgsListInfo",
-    "FeatureInfo",
-)
 
 visibility([
     "//cc/toolchains/...",
@@ -49,11 +44,12 @@ def convert_feature_constraint(constraint):
         not_features = sorted([ft.name for ft in constraint.none_of.to_list()]),
     )
 
-def convert_args(args):
+def convert_args(args, strip_actions = False):
     """Converts an ArgsInfo to flag_sets and env_sets.
 
     Args:
         args: (ArgsInfo) The args to convert
+        strip_actions: (bool) Whether to strip the actions from the resulting flag_set.
     Returns:
         struct(flag_sets = List[flag_set], env_sets = List[env_sets])
     """
@@ -66,7 +62,7 @@ def convert_args(args):
     flag_sets = []
     if args.nested != None:
         flag_sets.append(legacy_flag_set(
-            actions = actions,
+            actions = [] if strip_actions else actions,
             with_features = with_features,
             flag_groups = [args.nested.legacy_flag_group],
         ))
@@ -89,17 +85,17 @@ def convert_args(args):
         env_sets = env_sets,
     )
 
-def _convert_args_sequence(args_sequence):
+def _convert_args_sequence(args_sequence, strip_actions = False):
     flag_sets = []
     env_sets = []
     for args in args_sequence:
-        legacy_args = convert_args(args)
+        legacy_args = convert_args(args, strip_actions)
         flag_sets.extend(legacy_args.flag_sets)
         env_sets.extend(legacy_args.env_sets)
 
     return struct(flag_sets = flag_sets, env_sets = env_sets)
 
-def convert_feature(feature):
+def convert_feature(feature, enabled = False):
     if feature.external:
         return None
 
@@ -107,7 +103,7 @@ def convert_feature(feature):
 
     return legacy_feature(
         name = feature.name,
-        enabled = feature.enabled,
+        enabled = enabled or feature.enabled,
         flag_sets = args.flag_sets,
         env_sets = args.env_sets,
         implies = sorted([ft.name for ft in feature.implies.to_list()]),
@@ -128,63 +124,85 @@ def convert_tool(tool):
     return legacy_tool(
         tool = tool.exe,
         execution_requirements = list(tool.execution_requirements),
-        with_features = [
-            convert_feature_constraint(fc)
-            for fc in tool.requires_any_of
-        ],
+        with_features = [],
     )
 
-def _convert_action_type_config(atc):
-    implies = sorted([ft.name for ft in atc.implies.to_list()])
-    if atc.args:
-        implies.append("implied_by_%s" % atc.action_type.name)
-
-    return legacy_action_config(
-        action_name = atc.action_type.name,
-        enabled = True,
-        tools = [convert_tool(tool) for tool in atc.tools],
-        implies = implies,
+def convert_capability(capability):
+    return legacy_feature(
+        name = capability.name,
+        enabled = False,
     )
 
+def _convert_tool_map(tool_map, args_by_action):
+    action_configs = []
+    caps = {}
+    for action_type, tool in tool_map.configs.items():
+        action_args = args_by_action.get(action_type.name, default = None)
+        flag_sets = action_args.flag_sets if action_args != None else []
+        action_configs.append(legacy_action_config(
+            action_name = action_type.name,
+            enabled = True,
+            flag_sets = flag_sets,
+            tools = [convert_tool(tool)],
+            implies = [cap.feature.name for cap in tool.capabilities],
+        ))
+        for cap in tool.capabilities:
+            caps[cap] = None
+
+    cap_features = [
+        legacy_feature(name = cap.feature.name, enabled = False)
+        for cap in caps
+    ]
+    return action_configs, cap_features
+
 def convert_toolchain(toolchain):
     """Converts a rule-based toolchain into the legacy providers.
 
     Args:
-        toolchain: CcToolchainConfigInfo: The toolchain config to convert.
+        toolchain: (ToolchainConfigInfo) The toolchain config to convert.
     Returns:
         A struct containing parameters suitable to pass to
           cc_common.create_cc_toolchain_config_info.
     """
-    features = [convert_feature(feature) for feature in toolchain.features]
-    features.append(convert_feature(FeatureInfo(
+
+    # Ordering of arguments is important! Intended argument ordering is:
+    #   1. Arguments listed in `args`.
+    #   2. Legacy/built-in features.
+    #   3. User-defined features.
+    # While we could just attach arguments to a feature, legacy/built-in features will appear
+    # before the user-defined features if we do not bind args directly to the action configs.
+    # For that reason, there's additional logic in this function to ensure that the args are
+    # attached to the action configs directly, as that is the only way to ensure the correct
+    # ordering.
+    args_by_action = {}
+    for a in toolchain.args.by_action:
+        args = args_by_action.setdefault(a.action.name, struct(flag_sets = [], env_sets = []))
+        new_args = _convert_args_sequence(a.args, strip_actions = True)
+        args.flag_sets.extend(new_args.flag_sets)
+        args.env_sets.extend(new_args.env_sets)
+
+    action_configs, cap_features = _convert_tool_map(toolchain.tool_map, args_by_action)
+    features = [
+        convert_feature(feature, enabled = feature in toolchain.enabled_features)
+        for feature in toolchain.features
+    ]
+    features.extend(cap_features)
+
+    features.append(legacy_feature(
         # We reserve names starting with implied_by. This ensures we don't
         # conflict with the name of a feature the user creates.
-        name = "implied_by_always_enabled",
+        name = "implied_by_always_enabled_env_sets",
         enabled = True,
-        args = ArgsListInfo(args = toolchain.args),
-        implies = depset([]),
-        requires_any_of = [],
-        mutually_exclusive = [],
-        external = False,
-    )))
-    action_configs = []
-    for atc in toolchain.action_type_configs.values():
-        # Action configs don't take in an env like they do a flag set.
-        # In order to support them, we create a feature with the env that the action
-        # config will enable, and imply it in the action config.
-        if atc.args:
-            features.append(convert_feature(FeatureInfo(
-                name = "implied_by_%s" % atc.action_type.name,
-                enabled = False,
-                args = ArgsListInfo(args = atc.args),
-                implies = depset([]),
-                requires_any_of = [],
-                mutually_exclusive = [],
-                external = False,
-            )))
-        action_configs.append(_convert_action_type_config(atc))
+        env_sets = _convert_args_sequence(toolchain.args.args).env_sets,
+    ))
+
+    cxx_builtin_include_directories = [
+        d.path
+        for d in toolchain.allowlist_include_directories.to_list()
+    ]
 
     return struct(
-        features = sorted([ft for ft in features if ft != None], key = lambda ft: ft.name),
+        features = [ft for ft in features if ft != None],
         action_configs = sorted(action_configs, key = lambda ac: ac.action_name),
+        cxx_builtin_include_directories = cxx_builtin_include_directories,
     )
diff --git a/cc/toolchains/impl/markdown_helpers.bzl b/cc/toolchains/impl/markdown_helpers.bzl
new file mode 100644
index 0000000..1ae401f
--- /dev/null
+++ b/cc/toolchains/impl/markdown_helpers.bzl
@@ -0,0 +1,53 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""A few small helpers for working with Markdown."""
+
+def markdown_link(link_text, href):
+    """Creates a markdown link.
+
+    Args:
+      link_text: The text to display for the link.
+      href: The href for the link.
+
+    Returns:
+      A markdown link.
+    """
+    return "[" + link_text + "](" + href + ")"
+
+def xref_substitutions(match_text_patterns):
+    """Creates a dictionary of substitutions for use for linkification of text.
+
+    Example:
+    ```
+    # Produces a dictionary containing:
+    #   {
+    #     "foo": "[foo](http://foo.com)"
+    #     "bar": "[bar](http://bar.com)"
+    #   }
+    substitutions = xref_substitutions({
+        "foo": "http://foo.com",
+        "bar": "http://bar.com",
+    })
+    ```
+
+    Args:
+      match_text_patterns: A dictionary mapping string literals to the links they should point to.
+
+    Returns:
+      A dictionary of string literals mapped to their linkified substitutions.
+    """
+    return {
+        match_text: markdown_link(match_text, href)
+        for match_text, href in match_text_patterns.items()
+    }
diff --git a/cc/toolchains/impl/nested_args.bzl b/cc/toolchains/impl/nested_args.bzl
index ed83cf1..17ebb77 100644
--- a/cc/toolchains/impl/nested_args.bzl
+++ b/cc/toolchains/impl/nested_args.bzl
@@ -13,7 +13,7 @@
 # limitations under the License.
 """Helper functions for working with args."""
 
-load("@bazel_skylib//lib:structs.bzl", "structs")
+load("@bazel_skylib//rules/directory:providers.bzl", "DirectoryInfo")
 load("//cc:cc_toolchain_config_lib.bzl", "flag_group", "variable_with_value")
 load("//cc/toolchains:cc_toolchain_info.bzl", "NestedArgsInfo", "VariableInfo")
 load(":collect.bzl", "collect_files", "collect_provider")
@@ -30,25 +30,7 @@ REQUIRES_TRUE_ERR = "requires_true only works on bools"
 REQUIRES_FALSE_ERR = "requires_false only works on bools"
 REQUIRES_EQUAL_ERR = "requires_equal only works on strings"
 REQUIRES_EQUAL_VALUE_ERR = "When requires_equal is provided, you must also provide requires_equal_value to specify what it should be equal to"
-FORMAT_ARGS_ERR = "format_args can only format strings, files, or directories"
-
-_NOT_ESCAPED_FMT = "%% should always either of the form %%s, or escaped with %%%%. Instead, got %r"
-
-_EXAMPLE = """
-
-cc_args(
-    ...,
-    args = [format_arg("--foo=%s", "//cc/toolchains/variables:foo")]
-)
-
-or
-
-cc_args(
-    ...,
-    # If foo_list contains ["a", "b"], then this expands to ["--foo", "+a", "--foo", "+b"].
-    args = ["--foo", format_arg("+%s")],
-    iterate_over = "//toolchains/variables:foo_list",
-"""
+FORMAT_ARGS_ERR = "format only works on string, file, or directory type variables"
 
 # @unsorted-dict-items.
 NESTED_ARGS_ATTRS = {
@@ -58,7 +40,10 @@ NESTED_ARGS_ATTRS = {
 Usage:
 cc_args(
     ...,
-    args = ["--foo", format_arg("%s", "//cc/toolchains/variables:foo")]
+    args = ["--foo={foo}"],
+    format = {
+        "//cc/toolchains/variables:foo": "foo"
+    },
 )
 
 This is equivalent to flag_group(flags = ["--foo", "%{foo}"])
@@ -80,8 +65,7 @@ For example, a flag that sets the header directory might add the headers in that
 directory as additional files.
 """,
     ),
-    "variables": attr.label_list(
-        providers = [VariableInfo],
+    "format": attr.label_keyed_string_dict(
         doc = "Variables to be used in substitutions",
     ),
     "iterate_over": attr.label(providers = [VariableInfo], doc = "Replacement for flag_group.iterate_over"),
@@ -93,45 +77,6 @@ directory as additional files.
     "requires_equal_value": attr.string(),
 }
 
-def args_wrapper_macro(*, name, rule, args = [], **kwargs):
-    """Invokes a rule by converting args to attributes.
-
-    Args:
-        name: (str) The name of the target.
-        rule: (rule) The rule to invoke. Either cc_args or cc_nested_args.
-        args: (List[str|Formatted]) A list of either strings, or function calls
-          from format.bzl. For example:
-            ["--foo", format_arg("--sysroot=%s", "//cc/toolchains/variables:sysroot")]
-        **kwargs: kwargs to pass through into the rule invocation.
-    """
-    out_args = []
-    vars = []
-    if type(args) != "list":
-        fail("Args must be a list in %s" % native.package_relative_label(name))
-    for arg in args:
-        if type(arg) == "string":
-            out_args.append(raw_string(arg))
-        elif getattr(arg, "format_type") == "format_arg":
-            arg = structs.to_dict(arg)
-            if arg["value"] == None:
-                out_args.append(arg)
-            else:
-                var = arg.pop("value")
-
-                # Swap the variable from a label to an index. This allows us to
-                # actually get the providers in a rule.
-                out_args.append(struct(value = len(vars), **arg))
-                vars.append(var)
-        else:
-            fail("Invalid type of args in %s. Expected either a string or format_args(format_string, variable_label), got value %r" % (native.package_relative_label(name), arg))
-
-    rule(
-        name = name,
-        args = [json.encode(arg) for arg in out_args],
-        variables = vars,
-        **kwargs
-    )
-
 def _var(target):
     if target == None:
         return None
@@ -147,21 +92,13 @@ def nested_args_provider_from_ctx(ctx):
     Returns:
         NestedArgsInfo
     """
-    variables = collect_provider(ctx.attr.variables, VariableInfo)
-    args = []
-    for arg in ctx.attr.args:
-        arg = json.decode(arg)
-        if "value" in arg:
-            if arg["value"] != None:
-                arg["value"] = variables[arg["value"]]
-        args.append(struct(**arg))
-
     return nested_args_provider(
         label = ctx.label,
-        args = args,
+        args = ctx.attr.args,
+        format = ctx.attr.format,
         nested = collect_provider(ctx.attr.nested, NestedArgsInfo),
-        files = collect_files(ctx.attr.data),
-        iterate_over = _var(ctx.attr.iterate_over),
+        files = collect_files(ctx.attr.data + getattr(ctx.attr, "allowlist_include_directories", [])),
+        iterate_over = ctx.attr.iterate_over,
         requires_not_none = _var(ctx.attr.requires_not_none),
         requires_none = _var(ctx.attr.requires_none),
         requires_true = _var(ctx.attr.requires_true),
@@ -170,85 +107,12 @@ def nested_args_provider_from_ctx(ctx):
         requires_equal_value = ctx.attr.requires_equal_value,
     )
 
-def raw_string(s):
-    """Constructs metadata for creating a raw string.
-
-    Args:
-      s: (str) The string to input.
-    Returns:
-      Metadata suitable for format_variable.
-    """
-    return struct(format_type = "raw", format = s)
-
-def format_string_indexes(s, fail = fail):
-    """Gets the index of a '%s' in a string.
-
-    Args:
-      s: (str) The string
-      fail: The fail function. Used for tests
-
-    Returns:
-      List[int] The indexes of the '%s' in the string
-    """
-    indexes = []
-    escaped = False
-    for i in range(len(s)):
-        if not escaped and s[i] == "%":
-            escaped = True
-        elif escaped:
-            if s[i] == "{":
-                fail('Using the old mechanism for variables, %%{variable}, but we instead use format_arg("--foo=%%s", "//cc/toolchains/variables:<variable>"). Got %r' % s)
-            elif s[i] == "s":
-                indexes.append(i - 1)
-            elif s[i] != "%":
-                fail(_NOT_ESCAPED_FMT % s)
-            escaped = False
-    if escaped:
-        return fail(_NOT_ESCAPED_FMT % s)
-    return indexes
-
-def format_variable(arg, iterate_over, fail = fail):
-    """Lists all of the variables referenced by an argument.
-
-    Eg: referenced_variables([
-        format_arg("--foo", None),
-        format_arg("--bar=%s", ":bar")
-    ]) => ["--foo", "--bar=%{bar}"]
-
-    Args:
-      arg: [Formatted] The command-line arguments, as created by the format_arg function.
-      iterate_over: (Optional[str]) The name of the variable we're iterating over.
-      fail: The fail function. Used for tests
-
-    Returns:
-      A string defined to be compatible with flag groups.
-    """
-    indexes = format_string_indexes(arg.format, fail = fail)
-    if arg.format_type == "raw":
-        if indexes:
-            return fail("Can't use %s with a raw string. Either escape it with %%s or use format_arg, like the following examples:" + _EXAMPLE)
-        return arg.format
-    else:
-        if len(indexes) == 0:
-            return fail('format_arg requires a "%%s" in the format string, but got %r' % arg.format)
-        elif len(indexes) > 1:
-            return fail("Only one %%s can be used in a format string, but got %r" % arg.format)
-
-        if arg.value == None:
-            if iterate_over == None:
-                return fail("format_arg requires either a variable to format, or iterate_over must be provided. For example:" + _EXAMPLE)
-            var = iterate_over
-        else:
-            var = arg.value.name
-
-        index = indexes[0]
-        return arg.format[:index] + "%{" + var + "}" + arg.format[index + 2:]
-
 def nested_args_provider(
         *,
         label,
         args = [],
         nested = [],
+        format = {},
         files = depset([]),
         iterate_over = None,
         requires_not_none = None,
@@ -269,8 +133,9 @@ def nested_args_provider(
           error messages.
         args: (List[str]) The command-line arguments to add.
         nested: (List[NestedArgsInfo]) command-line arguments to expand.
+        format: (dict[Target, str]) A mapping from target to format string name
         files: (depset[File]) Files required for this set of command-line args.
-        iterate_over: (Optional[str]) Variable to iterate over
+        iterate_over: (Optional[Target]) Target for the variable to iterate over
         requires_not_none: (Optional[str]) If provided, this NestedArgsInfo will
           be ignored if the variable is None
         requires_none: (Optional[str]) If provided, this NestedArgsInfo will
@@ -287,8 +152,38 @@ def nested_args_provider(
     Returns:
         NestedArgsInfo
     """
-    if bool(args) == bool(nested):
-        fail("Exactly one of args and nested must be provided")
+    if bool(args) and bool(nested):
+        fail("Args and nested are mutually exclusive")
+
+    replacements = {}
+    if iterate_over:
+        # Since the user didn't assign a name to iterate_over, allow them to
+        # reference it as "--foo={}"
+        replacements[""] = iterate_over
+
+    # Intentionally ensure that {} clashes between an explicit user format
+    # string "" and the implicit one provided by iterate_over.
+    for target, name in format.items():
+        if name in replacements:
+            fail("Both %s and %s have the format string name %r" % (
+                target.label,
+                replacements[name].label,
+                name,
+            ))
+        replacements[name] = target
+
+    # Intentionally ensure that we do not have to use the variable provided by
+    # iterate_over in the format string.
+    # For example, a valid use case is:
+    # cc_args(
+    #     nested = ":nested",
+    #     iterate_over = "//cc/toolchains/variables:libraries_to_link",
+    # )
+    # cc_nested_args(
+    #     args = ["{}"],
+    #     iterate_over = "//cc/toolchains/variables:libraries_to_link.object_files",
+    # )
+    args = format_args(args, replacements, must_use = format.values(), fail = fail)
 
     transitive_files = [ea.files for ea in nested]
     transitive_files.append(files)
@@ -307,6 +202,10 @@ def nested_args_provider(
         fail(REQUIRES_MUTUALLY_EXCLUSIVE_ERR)
 
     kwargs = {}
+
+    if args:
+        kwargs["flags"] = args
+
     requires_types = {}
     if nested:
         kwargs["flag_groups"] = [ea.legacy_flag_group for ea in nested]
@@ -314,7 +213,7 @@ def nested_args_provider(
     unwrap_options = []
 
     if iterate_over:
-        kwargs["iterate_over"] = iterate_over
+        kwargs["iterate_over"] = _var(iterate_over)
 
     if requires_not_none:
         kwargs["expand_if_available"] = requires_not_none
@@ -361,27 +260,98 @@ def nested_args_provider(
             after_option_unwrap = True,
         ))
 
-    for arg in args:
-        if arg.format_type != "raw":
-            var_name = arg.value.name if arg.value != None else iterate_over
-            requires_types.setdefault(var_name, []).append(struct(
+    for arg in format:
+        if VariableInfo in arg:
+            requires_types.setdefault(arg[VariableInfo].name, []).append(struct(
                 msg = FORMAT_ARGS_ERR,
                 valid_types = ["string", "file", "directory"],
                 after_option_unwrap = True,
             ))
 
-    if args:
-        kwargs["flags"] = [
-            format_variable(arg, iterate_over = iterate_over, fail = fail)
-            for arg in args
-        ]
-
     return NestedArgsInfo(
         label = label,
         nested = nested,
         files = depset(transitive = transitive_files),
-        iterate_over = iterate_over,
+        iterate_over = _var(iterate_over),
         unwrap_options = unwrap_options,
         requires_types = requires_types,
         legacy_flag_group = flag_group(**kwargs),
     )
+
+def _escape(s):
+    return s.replace("%", "%%")
+
+def _format_target(target, fail = fail):
+    if VariableInfo in target:
+        return "%%{%s}" % target[VariableInfo].name
+    elif DirectoryInfo in target:
+        return _escape(target[DirectoryInfo].path)
+
+    files = target[DefaultInfo].files.to_list()
+    if len(files) == 1:
+        return _escape(files[0].path)
+
+    fail("%s should be either a variable, a directory, or a single file." % target.label)
+
+def format_args(args, format, must_use = [], fail = fail):
+    """Lists all of the variables referenced by an argument.
+
+    Eg: format_args(["--foo", "--bar={bar}"], {"bar": VariableInfo(name="bar")})
+      => ["--foo", "--bar=%{bar}"]
+
+    Args:
+      args: (List[str]) The command-line arguments.
+      format: (Dict[str, Target]) A mapping of substitutions from key to target.
+      must_use: (List[str]) A list of substitutions that must be used.
+      fail: The fail function. Used for tests
+
+    Returns:
+      A string defined to be compatible with flag groups.
+    """
+    formatted = []
+    used_vars = {}
+
+    for arg in args:
+        upto = 0
+        out = []
+        has_format = False
+
+        # This should be "while true". I used this number because it's an upper
+        # bound of the number of iterations.
+        for _ in range(len(arg)):
+            if upto >= len(arg):
+                break
+
+            # Escaping via "{{" and "}}"
+            if arg[upto] in "{}" and upto + 1 < len(arg) and arg[upto + 1] == arg[upto]:
+                out.append(arg[upto])
+                upto += 2
+            elif arg[upto] == "{":
+                chunks = arg[upto + 1:].split("}", 1)
+                if len(chunks) != 2:
+                    fail("Unmatched { in %r" % arg)
+                variable = chunks[0]
+
+                if variable not in format:
+                    fail('Unknown variable %r in format string %r. Try using cc_args(..., format = {"//path/to:variable": %r})' % (variable, arg, variable))
+                elif has_format:
+                    fail("The format string %r contained multiple variables, which is unsupported." % arg)
+                else:
+                    used_vars[variable] = None
+                    has_format = True
+                    out.append(_format_target(format[variable], fail = fail))
+                    upto += len(variable) + 2
+
+            elif arg[upto] == "}":
+                fail("Unexpected } in %r" % arg)
+            else:
+                out.append(_escape(arg[upto]))
+                upto += 1
+
+        formatted.append("".join(out))
+
+    unused_vars = [var for var in must_use if var not in used_vars]
+    if unused_vars:
+        fail("The variable %r was not used in the format string." % unused_vars[0])
+
+    return formatted
diff --git a/cc/toolchains/impl/toolchain_config.bzl b/cc/toolchains/impl/toolchain_config.bzl
index dde94f2..da2a873 100644
--- a/cc/toolchains/impl/toolchain_config.bzl
+++ b/cc/toolchains/impl/toolchain_config.bzl
@@ -13,13 +13,12 @@
 # limitations under the License.
 """Implementation of the cc_toolchain rule."""
 
-load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
 load(
     "//cc/toolchains:cc_toolchain_info.bzl",
-    "ActionTypeConfigSetInfo",
     "ActionTypeSetInfo",
     "ArgsListInfo",
     "FeatureSetInfo",
+    "ToolConfigInfo",
     "ToolchainConfigInfo",
 )
 load(":collect.bzl", "collect_action_types")
@@ -50,15 +49,13 @@ cc_legacy_file_group = rule(
 
 def _cc_toolchain_config_impl(ctx):
     if ctx.attr.features:
-        fail("Features is a reserved attribute in bazel. Did you mean 'toolchain_features'")
-
-    if not ctx.attr._enabled[BuildSettingInfo].value and not ctx.attr.skip_experimental_flag_validation_for_test:
-        fail("Rule based toolchains are experimental. To use it, please add --@rules_cc//cc/toolchains:experimental_enable_rule_based_toolchains to your bazelrc")
+        fail("Features is a reserved attribute in bazel. Did you mean 'known_features' or 'enabled_features'?")
 
     toolchain_config = toolchain_config_info(
         label = ctx.label,
-        features = ctx.attr.toolchain_features + [ctx.attr._builtin_features],
-        action_type_configs = ctx.attr.action_type_configs,
+        known_features = ctx.attr.known_features + [ctx.attr._builtin_features],
+        enabled_features = ctx.attr.enabled_features,
+        tool_map = ctx.attr.tool_map,
         args = ctx.attr.args,
     )
 
@@ -70,22 +67,22 @@ def _cc_toolchain_config_impl(ctx):
             ctx = ctx,
             action_configs = legacy.action_configs,
             features = legacy.features,
-            cxx_builtin_include_directories = ctx.attr.cxx_builtin_include_directories,
+            cxx_builtin_include_directories = legacy.cxx_builtin_include_directories,
             # toolchain_identifier is deprecated, but setting it to None results
             # in an error that it expected a string, and for safety's sake, I'd
             # prefer to provide something unique.
             toolchain_identifier = str(ctx.label),
-            target_system_name = ctx.attr.target_system_name,
-            target_cpu = ctx.attr.target_cpu,
-            target_libc = ctx.attr.target_libc,
-            compiler = ctx.attr.compiler,
-            abi_version = ctx.attr.abi_version,
-            abi_libc_version = ctx.attr.abi_libc_version,
-            builtin_sysroot = ctx.attr.sysroot or None,
+            # These fields are only relevant for legacy toolchain resolution.
+            target_system_name = "",
+            target_cpu = "",
+            target_libc = "",
+            compiler = "",
+            abi_version = "",
+            abi_libc_version = "",
         ),
         # This allows us to support all_files.
         # If all_files was simply an alias to
-        # ///cc/toolchains/actions:all_actions,
+        # //cc/toolchains/actions:all_actions,
         # then if a toolchain introduced a new type of action, it wouldn't get
         # put in all_files.
         DefaultInfo(files = depset(transitive = toolchain_config.files.values())),
@@ -96,28 +93,11 @@ cc_toolchain_config = rule(
     # @unsorted-dict-items
     attrs = {
         # Attributes new to this rule.
-        "action_type_configs": attr.label_list(providers = [ActionTypeConfigSetInfo]),
+        "tool_map": attr.label(providers = [ToolConfigInfo], mandatory = True),
         "args": attr.label_list(providers = [ArgsListInfo]),
-        "toolchain_features": attr.label_list(providers = [FeatureSetInfo]),
-        "skip_experimental_flag_validation_for_test": attr.bool(default = False),
+        "known_features": attr.label_list(providers = [FeatureSetInfo]),
+        "enabled_features": attr.label_list(providers = [FeatureSetInfo]),
         "_builtin_features": attr.label(default = "//cc/toolchains/features:all_builtin_features"),
-        "_enabled": attr.label(default = "//cc/toolchains:experimental_enable_rule_based_toolchains"),
-
-        # Attributes from create_cc_toolchain_config_info.
-        # artifact_name_patterns is currently unused. Consider adding it later.
-        # TODO: Consider making this into a label_list that takes a
-        #  cc_directory_marker rule as input.
-        "cxx_builtin_include_directories": attr.string_list(),
-        "target_system_name": attr.string(mandatory = True),
-        "target_cpu": attr.string(mandatory = True),
-        "target_libc": attr.string(mandatory = True),
-        "compiler": attr.string(mandatory = True),
-        "abi_version": attr.string(),
-        "abi_libc_version": attr.string(),
-        # tool_paths currently unused.
-        # TODO: Consider making this into a label that takes a
-        #  cc_directory_marker rule as an input.
-        "sysroot": attr.string(),
     },
     provides = [ToolchainConfigInfo],
 )
diff --git a/cc/toolchains/impl/toolchain_config_info.bzl b/cc/toolchains/impl/toolchain_config_info.bzl
index e2a8b37..3c8c65c 100644
--- a/cc/toolchains/impl/toolchain_config_info.bzl
+++ b/cc/toolchains/impl/toolchain_config_info.bzl
@@ -13,9 +13,9 @@
 # limitations under the License.
 """Helper functions to create and validate a ToolchainConfigInfo."""
 
-load("//cc/toolchains:cc_toolchain_info.bzl", "ToolchainConfigInfo")
+load("//cc/toolchains:cc_toolchain_info.bzl", "ToolConfigInfo", "ToolchainConfigInfo")
 load(":args_utils.bzl", "get_action_type")
-load(":collect.bzl", "collect_action_type_config_sets", "collect_args_lists", "collect_features")
+load(":collect.bzl", "collect_args_lists", "collect_features")
 
 visibility([
     "//cc/toolchains/...",
@@ -54,9 +54,9 @@ def _feature_key(feature):
     # This should be sufficiently unique.
     return (feature.label, feature.name)
 
-def _get_known_features(features, fail):
+def _get_known_features(features, capability_features, fail):
     feature_names = {}
-    for ft in features:
+    for ft in capability_features + features:
         if ft.name in feature_names:
             other = feature_names[ft.name]
             if other.overrides != ft and ft.overrides != other:
@@ -85,14 +85,6 @@ def _validate_requires_any_of(fn, self, known_features, fail):
     if self.requires_any_of and not valid:
         fail(_INVALID_CONSTRAINT_ERR.format(provider = self.label))
 
-def _validate_requires_any_of_constraint(self, known_features, fail):
-    return _validate_requires_any_of(
-        lambda constraint: constraint.all_of.to_list(),
-        self,
-        known_features,
-        fail,
-    )
-
 def _validate_requires_any_of_feature_set(self, known_features, fail):
     return _validate_requires_any_of(
         lambda feature_set: feature_set.features.to_list(),
@@ -107,17 +99,12 @@ def _validate_implies(self, known_features, fail = fail):
             fail(_UNKNOWN_FEATURE_ERR.format(self = self.label, ft = ft.label))
 
 def _validate_args(self, known_features, fail):
-    _validate_requires_any_of_constraint(self, known_features, fail = fail)
-
-def _validate_tool(self, known_features, fail):
-    _validate_requires_any_of_constraint(self, known_features, fail = fail)
-
-def _validate_action_config(self, known_features, fail):
-    _validate_implies(self, known_features, fail = fail)
-    for tool in self.tools:
-        _validate_tool(tool, known_features, fail = fail)
-    for args in self.args:
-        _validate_args(args, known_features, fail = fail)
+    return _validate_requires_any_of(
+        lambda constraint: constraint.all_of.to_list(),
+        self,
+        known_features,
+        fail,
+    )
 
 def _validate_feature(self, known_features, fail):
     _validate_requires_any_of_feature_set(self, known_features, fail = fail)
@@ -126,53 +113,72 @@ def _validate_feature(self, known_features, fail):
     _validate_implies(self, known_features, fail = fail)
 
 def _validate_toolchain(self, fail = fail):
-    known_features = _get_known_features(self.features, fail = fail)
+    capabilities = []
+    for tool in self.tool_map.configs.values():
+        capabilities.extend([cap.feature for cap in tool.capabilities])
+    known_features = _get_known_features(self.features, capabilities, fail = fail)
 
     for feature in self.features:
         _validate_feature(feature, known_features, fail = fail)
-    for atc in self.action_type_configs.values():
-        _validate_action_config(atc, known_features, fail = fail)
-    for args in self.args:
+    for args in self.args.args:
         _validate_args(args, known_features, fail = fail)
 
-def _collect_files_for_action_type(atc, features, args):
-    transitive_files = [atc.files.files, get_action_type(args, atc.action_type).files]
+def _collect_files_for_action_type(action_type, tool_map, features, args):
+    transitive_files = [tool_map[action_type].runfiles.files, get_action_type(args, action_type).files]
     for ft in features:
-        transitive_files.append(get_action_type(ft.args, atc.action_type).files)
+        transitive_files.append(get_action_type(ft.args, action_type).files)
 
     return depset(transitive = transitive_files)
 
-def toolchain_config_info(label, features = [], args = [], action_type_configs = [], fail = fail):
+def toolchain_config_info(label, known_features = [], enabled_features = [], args = [], tool_map = None, fail = fail):
     """Generates and validates a ToolchainConfigInfo from lists of labels.
 
     Args:
         label: (Label) The label to apply to the ToolchainConfigInfo
-        features: (List[Target]) A list of targets providing FeatureSetInfo
+        known_features: (List[Target]) A list of features that can be enabled.
+        enabled_features: (List[Target]) A list of features that are enabled by
+          default. Every enabled feature is implicitly also a known feature.
         args: (List[Target]) A list of targets providing ArgsListInfo
-        action_type_configs: (List[Target]) A list of targets providing
-          ActionTypeConfigSetInfo
+        tool_map: (Target) A target providing ToolMapInfo.
         fail: A fail function. Use only during tests.
     Returns:
         A validated ToolchainConfigInfo
     """
-    features = collect_features(features).to_list()
+
+    # Later features will come after earlier features on the command-line, and
+    # thus override them. Because of this, we ensure that known_features comes
+    # *after* enabled_features, so that if we do enable them, they override the
+    # default feature flags.
+    features = collect_features(enabled_features + known_features).to_list()
+    enabled_features = collect_features(enabled_features).to_list()
+
+    if tool_map == None:
+        fail("tool_map is required")
+
+        # The `return` here is to support testing, since injecting `fail()` has a
+        # side-effect of allowing code to continue.
+        return None  # buildifier: disable=unreachable
+
     args = collect_args_lists(args, label = label)
-    action_type_configs = collect_action_type_config_sets(
-        action_type_configs,
-        label = label,
-        fail = fail,
-    ).configs
+    tools = tool_map[ToolConfigInfo].configs
     files = {
-        atc.action_type: _collect_files_for_action_type(atc, features, args)
-        for atc in action_type_configs.values()
+        action_type: _collect_files_for_action_type(action_type, tools, features, args)
+        for action_type in tools.keys()
     }
-
+    allowlist_include_directories = depset(
+        transitive = [
+            src.allowlist_include_directories
+            for src in features + tools.values()
+        ] + [args.allowlist_include_directories],
+    )
     toolchain_config = ToolchainConfigInfo(
         label = label,
         features = features,
-        action_type_configs = action_type_configs,
-        args = args.args,
+        enabled_features = enabled_features,
+        tool_map = tool_map[ToolConfigInfo],
+        args = args,
         files = files,
+        allowlist_include_directories = allowlist_include_directories,
     )
     _validate_toolchain(toolchain_config, fail = fail)
     return toolchain_config
diff --git a/cc/toolchains/impl/variables.bzl b/cc/toolchains/impl/variables.bzl
index c2820f3..aab365d 100644
--- a/cc/toolchains/impl/variables.bzl
+++ b/cc/toolchains/impl/variables.bzl
@@ -67,19 +67,32 @@ _cc_variable = rule(
 )
 
 def cc_variable(name, type, **kwargs):
-    """Defines a variable for both the specified variable, and all nested ones.
+    """Exposes a toolchain variable to use in toolchain argument expansions.
 
-    Eg. cc_variable(
-      name = "foo",
-      type = types.list(types.struct(bar = types.string))
-    )
+    This internal rule exposes [toolchain variables](https://bazel.build/docs/cc-toolchain-config-reference#cctoolchainconfiginfo-build-variables)
+    that may be expanded in `cc_args` or `cc_nested_args`
+    rules. Because these varaibles merely expose variables inherrent to Bazel,
+    it's not possible to declare custom variables.
+
+    For a full list of available variables, see
+    [@rules_cc//cc/toolchains/varaibles:BUILD](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD).
 
-    would define two targets, ":foo" and ":foo.bar"
+    Example:
+    ```
+    load("//cc/toolchains/impl:variables.bzl", "cc_variable")
+
+    # Defines two targets, ":foo" and ":foo.bar"
+    cc_variable(
+        name = "foo",
+        type = types.list(types.struct(bar = types.string)),
+    )
+    ```
 
     Args:
         name: (str) The name of the outer variable, and the rule.
-        type: The type of the variable, constructed using types above.
-        **kwargs: kwargs to pass to _cc_variable.
+        type: The type of the variable, constructed using `types` factory in
+            [@rules_cc//cc/toolchains/impl:variables.bzl](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/impl/variables.bzl).
+        **kwargs: [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.
     """
     _cc_variable(name = name, type = json.encode(type), **kwargs)
 
diff --git a/cc/toolchains/memprof_profile.bzl b/cc/toolchains/memprof_profile.bzl
new file mode 100644
index 0000000..28bb5b3
--- /dev/null
+++ b/cc/toolchains/memprof_profile.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""memprof_profile rule"""
+
+memprof_profile = native.memprof_profile
diff --git a/cc/toolchains/mutually_exclusive_category.bzl b/cc/toolchains/mutually_exclusive_category.bzl
index 9920290..f83b554 100644
--- a/cc/toolchains/mutually_exclusive_category.bzl
+++ b/cc/toolchains/mutually_exclusive_category.bzl
@@ -23,7 +23,40 @@ def _cc_mutually_exclusive_category_impl(ctx):
 
 cc_mutually_exclusive_category = rule(
     implementation = _cc_mutually_exclusive_category_impl,
-    doc = "A category of features, for which only one can be enabled",
+    doc = """A rule used to categorize `cc_feature` definitions for which only one can be enabled.
+
+This is used by [`cc_feature.mutually_exclusive`](#cc_feature-mutually_exclusive) to express groups
+of `cc_feature` definitions that are inherently incompatible with each other and must be treated as
+mutually exclusive.
+
+Warning: These groups are keyed by name, so two `cc_mutually_exclusive_category` definitions of the
+same name in different packages will resolve to the same logical group.
+
+Example:
+```
+load("//cc/toolchains:feature.bzl", "cc_feature")
+load("//cc/toolchains:mutually_exclusive_category.bzl", "cc_mutually_exclusive_category")
+
+cc_mutually_exclusive_category(
+    name = "opt_level",
+)
+
+cc_feature(
+    name = "speed_optimized",
+    mutually_exclusive = [":opt_level"],
+)
+
+cc_feature(
+    name = "size_optimized",
+    mutually_exclusive = [":opt_level"],
+)
+
+cc_feature(
+    name = "unoptimized",
+    mutually_exclusive = [":opt_level"],
+)
+```
+""",
     attrs = {},
     provides = [MutuallyExclusiveCategoryInfo],
 )
diff --git a/cc/toolchains/nested_args.bzl b/cc/toolchains/nested_args.bzl
index e4e3d53..d81dd99 100644
--- a/cc/toolchains/nested_args.bzl
+++ b/cc/toolchains/nested_args.bzl
@@ -16,7 +16,6 @@
 load(
     "//cc/toolchains/impl:nested_args.bzl",
     "NESTED_ARGS_ATTRS",
-    "args_wrapper_macro",
     "nested_args_provider_from_ctx",
 )
 load(
@@ -42,4 +41,88 @@ Examples:
 """,
 )
 
-cc_nested_args = lambda **kwargs: args_wrapper_macro(rule = _cc_nested_args, **kwargs)
+def cc_nested_args(
+        *,
+        name,
+        args = None,
+        data = None,
+        format = {},
+        iterate_over = None,
+        nested = None,
+        requires_not_none = None,
+        requires_none = None,
+        requires_true = None,
+        requires_false = None,
+        requires_equal = None,
+        requires_equal_value = None,
+        **kwargs):
+    """Nested arguments for use in more complex `cc_args` expansions.
+
+    While this rule is very similar in shape to `cc_args`, it is intended to be used as a
+    dependency of `cc_args` to provide additional arguments that should be applied to the
+    same actions as defined by the parent `cc_args` rule. The key motivation for this rule
+    is to allow for more complex variable-based argument expensions.
+
+    Prefer expressing collections of arguments as `cc_args` and
+    `cc_args_list` rules when possible.
+
+    For living examples of how this rule is used, see the usages here:
+        https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args/runtime_library_search_directories/BUILD
+        https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args/libraries_to_link/BUILD
+
+    Note: These examples are non-trivial, but they illustrate when it is absolutely necessary to
+    use this rule.
+
+    Args:
+        name: (str) The name of the target.
+        args: (List[str]) The command-line arguments that are applied by using this rule. This is
+            mutually exclusive with [nested](#cc_nested_args-nested).
+        data: (List[Label]) A list of runtime data dependencies that are required for these
+            arguments to work as intended.
+        format: (Dict[str, Label]) A mapping of format strings to the label of the corresponding
+            `cc_variable` that the value should be pulled from. All instances of
+            `{variable_name}` will be replaced with the expanded value of `variable_name` in this
+            dictionary. The complete list of possible variables can be found in
+            https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD.
+            It is not possible to declare custom variables--these are inherent to Bazel itself.
+        iterate_over: (Label) The label of a `cc_variable` that should be iterated
+            over. This is intended for use with built-in variables that are lists.
+        nested: (List[Label]) A list of `cc_nested_args` rules that should be
+            expanded to command-line arguments when this rule is used. This is mutually exclusive
+            with [args](#cc_nested_args-args).
+        requires_not_none: (Label) The label of a `cc_variable` that should be checked
+            for existence before expanding this rule. If the variable is None, this rule will be
+            ignored.
+        requires_none: (Label) The label of a `cc_variable` that should be checked for
+            non-existence before expanding this rule. If the variable is not None, this rule will be
+            ignored.
+        requires_true: (Label) The label of a `cc_variable` that should be checked for
+            truthiness before expanding this rule. If the variable is false, this rule will be
+            ignored.
+        requires_false: (Label) The label of a `cc_variable` that should be checked
+            for falsiness before expanding this rule. If the variable is true, this rule will be
+            ignored.
+        requires_equal: (Label) The label of a `cc_variable` that should be checked
+            for equality before expanding this rule. If the variable is not equal to
+            (requires_equal_value)[#cc_nested_args-requires_equal_value], this rule will be ignored.
+        requires_equal_value: (str) The value to compare
+            (requires_equal)[#cc_nested_args-requires_equal] against.
+        **kwargs: [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.
+    """
+    return _cc_nested_args(
+        name = name,
+        args = args,
+        data = data,
+        # We flip the key/value pairs in the dictionary here because Bazel doesn't have a
+        # string-keyed label dict attribute type.
+        format = {k: v for v, k in format.items()},
+        iterate_over = iterate_over,
+        nested = nested,
+        requires_not_none = requires_not_none,
+        requires_none = requires_none,
+        requires_true = requires_true,
+        requires_false = requires_false,
+        requires_equal = requires_equal,
+        requires_equal_value = requires_equal_value,
+        **kwargs
+    )
diff --git a/cc/toolchains/propeller_optimize.bzl b/cc/toolchains/propeller_optimize.bzl
new file mode 100644
index 0000000..0883cd7
--- /dev/null
+++ b/cc/toolchains/propeller_optimize.bzl
@@ -0,0 +1,17 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""propeller_optimize rule"""
+
+propeller_optimize = native.propeller_optimize
diff --git a/cc/toolchains/tool.bzl b/cc/toolchains/tool.bzl
index fb552ca..a60d458 100644
--- a/cc/toolchains/tool.bzl
+++ b/cc/toolchains/tool.bzl
@@ -13,10 +13,11 @@
 # limitations under the License.
 """Implementation of cc_tool"""
 
+load("@bazel_skylib//rules/directory:providers.bzl", "DirectoryInfo")
 load("//cc/toolchains/impl:collect.bzl", "collect_data", "collect_provider")
 load(
     ":cc_toolchain_info.bzl",
-    "FeatureConstraintInfo",
+    "ToolCapabilityInfo",
     "ToolInfo",
 )
 
@@ -29,16 +30,16 @@ def _cc_tool_impl(ctx):
     else:
         fail("Expected cc_tool's src attribute to be either an executable or a single file")
 
-    runfiles = collect_data(ctx, ctx.attr.data + [ctx.attr.src])
+    runfiles = collect_data(ctx, ctx.attr.data + [ctx.attr.src] + ctx.attr.allowlist_include_directories)
     tool = ToolInfo(
         label = ctx.label,
         exe = exe,
         runfiles = runfiles,
-        requires_any_of = tuple(collect_provider(
-            ctx.attr.requires_any_of,
-            FeatureConstraintInfo,
-        )),
-        execution_requirements = tuple(ctx.attr.execution_requirements),
+        execution_requirements = tuple(ctx.attr.tags),
+        allowlist_include_directories = depset(
+            direct = [d[DirectoryInfo] for d in ctx.attr.allowlist_include_directories],
+        ),
+        capabilities = tuple(collect_provider(ctx.attr.capabilities, ToolCapabilityInfo)),
     )
 
     link = ctx.actions.declare_file(ctx.label.name)
@@ -67,38 +68,68 @@ cc_tool = rule(
             cfg = "exec",
             doc = """The underlying binary that this tool represents.
 
-Usually just a single prebuilt (eg. @sysroot//:bin/clang), but may be any
+Usually just a single prebuilt (eg. @toolchain//:bin/clang), but may be any
 executable label.
 """,
         ),
         "data": attr.label_list(
             allow_files = True,
-            doc = "Additional files that are required for this tool to run.",
+            doc = """Additional files that are required for this tool to run.
+
+Frequently, clang and gcc require additional files to execute as they often shell out to
+other binaries (e.g. `cc1`).
+""",
         ),
-        "execution_requirements": attr.string_list(
-            doc = "A list of strings that provide hints for execution environment compatibility (e.g. `requires-network`).",
+        "allowlist_include_directories": attr.label_list(
+            providers = [DirectoryInfo],
+            doc = """Include paths implied by using this tool.
+
+Compilers may include a set of built-in headers that are implicitly available
+unless flags like `-nostdinc` are provided. Bazel checks that all included
+headers are properly provided by a dependency or allowlisted through this
+mechanism.
+
+As a rule of thumb, only use this if Bazel is complaining about absolute paths in your
+toolchain and you've ensured that the toolchain is compiling with the `-no-canonical-prefixes`
+and/or `-fno-canonical-system-headers` arguments.
+
+This can help work around errors like:
+`the source file 'main.c' includes the following non-builtin files with absolute paths
+(if these are builtin files, make sure these paths are in your toolchain)`.
+""",
         ),
-        "requires_any_of": attr.label_list(
-            providers = [FeatureConstraintInfo],
-            doc = """This will be enabled when any of the constraints are met.
+        "capabilities": attr.label_list(
+            providers = [ToolCapabilityInfo],
+            doc = """Declares that a tool is capable of doing something.
 
-If omitted, this tool will be enabled unconditionally.
+For example, `@rules_cc//cc/toolchains/capabilities:supports_pic`.
 """,
         ),
     },
     provides = [ToolInfo],
-    doc = """Declares a tool that can be bound to action configs.
+    doc = """Declares a tool for use by toolchain actions.
 
-A tool is a binary with extra metadata for the action config rule to consume
-(eg. execution_requirements).
+`cc_tool` rules are used in a `cc_tool_map` rule to ensure all files and
+metadata required to run a tool are available when constructing a `cc_toolchain`.
+
+In general, include all files that are always required to run a tool (e.g. libexec/** and
+cross-referenced tools in bin/*) in the [data](#cc_tool-data) attribute. If some files are only
+required when certain flags are passed to the tool, consider using a `cc_args` rule to
+bind the files to the flags that require them. This reduces the overhead required to properly
+enumerate a sandbox with all the files required to run a tool, and ensures that there isn't
+unintentional leakage across configurations and actions.
 
 Example:
 ```
+load("//cc/toolchains:tool.bzl", "cc_tool")
+
 cc_tool(
     name = "clang_tool",
     executable = "@llvm_toolchain//:bin/clang",
     # Suppose clang needs libc to run.
     data = ["@llvm_toolchain//:lib/x86_64-linux-gnu/libc.so.6"]
+    tags = ["requires-network"],
+    capabilities = ["//cc/toolchains/capabilities:supports_pic"],
 )
 ```
 """,
diff --git a/cc/toolchains/tool_capability.bzl b/cc/toolchains/tool_capability.bzl
new file mode 100644
index 0000000..60b0f59
--- /dev/null
+++ b/cc/toolchains/tool_capability.bzl
@@ -0,0 +1,85 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Implementation of the cc_tool_capability rule."""
+
+load(
+    ":cc_toolchain_info.bzl",
+    "ArgsListInfo",
+    "FeatureConstraintInfo",
+    "FeatureInfo",
+    "ToolCapabilityInfo",
+)
+
+def _cc_tool_capability_impl(ctx):
+    ft = FeatureInfo(
+        name = ctx.attr.feature_name or ctx.label.name,
+        label = ctx.label,
+        enabled = False,
+        args = ArgsListInfo(
+            label = ctx.label,
+            args = (),
+            files = depset(),
+            by_action = (),
+            allowlist_include_directories = depset(),
+        ),
+        implies = depset(),
+        requires_any_of = (),
+        mutually_exclusive = (),
+        # Mark it as external so that it doesn't complain if we say
+        # "requires" on a constraint that was never referenced elsewhere
+        # in the toolchain.
+        external = True,
+        overridable = True,
+        overrides = None,
+        allowlist_include_directories = depset(),
+    )
+    return [
+        ToolCapabilityInfo(label = ctx.label, feature = ft),
+        # Only give it a feature constraint info and not a feature info.
+        # This way you can't imply it - you can only require it.
+        FeatureConstraintInfo(label = ctx.label, all_of = depset([ft])),
+    ]
+
+cc_tool_capability = rule(
+    implementation = _cc_tool_capability_impl,
+    provides = [ToolCapabilityInfo, FeatureConstraintInfo],
+    doc = """A capability is an optional feature that a tool supports.
+
+For example, not all compilers support PIC, so to handle this, we write:
+
+```
+cc_tool(
+    name = "clang",
+    src = "@host_tools/bin/clang",
+    capabilities = [
+        "//cc/toolchains/capabilities:supports_pic",
+    ],
+)
+
+cc_args(
+    name = "pic",
+    requires = [
+        "//cc/toolchains/capabilities:supports_pic"
+    ],
+    args = ["-fPIC"],
+)
+```
+
+This ensures that `-fPIC` is added to the command-line only when we are using a
+tool that supports PIC.
+""",
+    attrs = {
+        "feature_name": attr.string(doc = "The name of the feature to generate for this capability"),
+    },
+)
diff --git a/cc/toolchains/tool_map.bzl b/cc/toolchains/tool_map.bzl
new file mode 100644
index 0000000..9a5d592
--- /dev/null
+++ b/cc/toolchains/tool_map.bzl
@@ -0,0 +1,130 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Implementation of cc_tool_map."""
+
+load(
+    "//cc/toolchains/impl:collect.bzl",
+    "collect_provider",
+    "collect_tools",
+)
+load(
+    ":cc_toolchain_info.bzl",
+    "ActionTypeSetInfo",
+    "ToolConfigInfo",
+)
+
+def _cc_tool_map_impl(ctx):
+    tools = collect_tools(ctx, ctx.attr.tools)
+    action_sets = collect_provider(ctx.attr.actions, ActionTypeSetInfo)
+
+    action_to_tool = {}
+    action_to_as = {}
+    for i in range(len(action_sets)):
+        action_set = action_sets[i]
+        tool = tools[ctx.attr.tool_index_for_action[i]]
+
+        for action in action_set.actions.to_list():
+            if action in action_to_as:
+                fail("The action %s appears multiple times in your tool_map (as %s and %s)" % (action.label, action_set.label, action_to_as[action].label))
+            action_to_as[action] = action_set
+            action_to_tool[action] = tool
+
+    return [ToolConfigInfo(label = ctx.label, configs = action_to_tool)]
+
+_cc_tool_map = rule(
+    implementation = _cc_tool_map_impl,
+    # @unsorted-dict-items
+    attrs = {
+        "actions": attr.label_list(
+            providers = [ActionTypeSetInfo],
+            mandatory = True,
+            doc = """A list of action names to apply this action to.
+
+See //cc/toolchains/actions:BUILD for valid options.
+""",
+        ),
+        "tools": attr.label_list(
+            mandatory = True,
+            cfg = "exec",
+            allow_files = True,
+            doc = """The tool to use for the specified actions.
+
+The tool may be a `cc_tool` or other executable rule.
+""",
+        ),
+        "tool_index_for_action": attr.int_list(
+            mandatory = True,
+            doc = """The index of the tool in `tools` for the action in `actions`.""",
+        ),
+    },
+    provides = [ToolConfigInfo],
+)
+
+def cc_tool_map(name, tools, **kwargs):
+    """A toolchain configuration rule that maps toolchain actions to tools.
+
+    A `cc_tool_map` aggregates all the tools that may be used for a given toolchain
+    and maps them to their corresponding actions. Conceptually, this is similar to the
+    `CXX=/path/to/clang++` environment variables that most build systems use to determine which
+    tools to use for a given action. To simplify usage, some actions have been grouped together (for
+    example,
+    [@rules_cc//cc/toolchains/actions:cpp_compile_actions](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/actions/BUILD)) to
+    logically express "all the C++ compile actions".
+
+    In Bazel, there is a little more granularity to the mapping, so the mapping doesn't follow the
+    traditional `CXX`, `AR`, etc. naming scheme. For a comprehensive list of all the well-known
+    actions, see //cc/toolchains/actions:BUILD.
+
+    Example usage:
+    ```
+    load("//cc/toolchains:tool_map.bzl", "cc_tool_map")
+
+    cc_tool_map(
+        name = "all_tools",
+        tools = {
+            "//cc/toolchains/actions:assembly_actions": ":asm",
+            "//cc/toolchains/actions:c_compile": ":clang",
+            "//cc/toolchains/actions:cpp_compile_actions": ":clang++",
+            "//cc/toolchains/actions:link_actions": ":lld",
+            "//cc/toolchains/actions:objcopy_embed_data": ":llvm-objcopy",
+            "//cc/toolchains/actions:strip": ":llvm-strip",
+            "//cc/toolchains/actions:ar_actions": ":llvm-ar",
+        },
+    )
+    ```
+
+    Args:
+        name: (str) The name of the target.
+        tools: (Dict[Label, Label]) A mapping between
+            `cc_action_type`/`cc_action_type_set` targets
+            and the `cc_tool` or executable target that implements that action.
+        **kwargs: [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.
+    """
+    actions = []
+    tool_index_for_action = []
+    deduplicated_tools = {}
+    for action, tool in tools.items():
+        actions.append(action)
+        label = native.package_relative_label(tool)
+        if label not in deduplicated_tools:
+            deduplicated_tools[label] = len(deduplicated_tools)
+        tool_index_for_action.append(deduplicated_tools[label])
+
+    _cc_tool_map(
+        name = name,
+        actions = actions,
+        tools = deduplicated_tools.keys(),
+        tool_index_for_action = tool_index_for_action,
+        **kwargs
+    )
diff --git a/cc/toolchains/toolchain.bzl b/cc/toolchains/toolchain.bzl
index 0ce1abf..432ef71 100644
--- a/cc/toolchains/toolchain.bzl
+++ b/cc/toolchains/toolchain.bzl
@@ -13,7 +13,7 @@
 # limitations under the License.
 """Implementation of the cc_toolchain rule."""
 
-load("//cc:defs.bzl", _cc_toolchain = "cc_toolchain")
+load("//cc/toolchains:cc_toolchain.bzl", _cc_toolchain = "cc_toolchain")
 load(
     "//cc/toolchains/impl:toolchain_config.bzl",
     "cc_legacy_file_group",
@@ -27,47 +27,75 @@ visibility("public")
 #  work out what actions correspond to what file groups.
 _LEGACY_FILE_GROUPS = {
     "ar_files": [
-        "@rules_cc//cc/toolchains/actions:ar_actions",  # copybara-use-repo-external-label
+        Label("//cc/toolchains/actions:ar_actions"),
     ],
     "as_files": [
-        "@rules_cc//cc/toolchains/actions:assembly_actions",  # copybara-use-repo-external-label
+        Label("//cc/toolchains/actions:assembly_actions"),
     ],
     "compiler_files": [
-        "@rules_cc//cc/toolchains/actions:cc_flags_make_variable",  # copybara-use-repo-external-label
-        "@rules_cc//cc/toolchains/actions:c_compile",  # copybara-use-repo-external-label
-        "@rules_cc//cc/toolchains/actions:cpp_compile",  # copybara-use-repo-external-label
-        "@rules_cc//cc/toolchains/actions:cpp_header_parsing",  # copybara-use-repo-external-label
+        Label("//cc/toolchains/actions:cc_flags_make_variable"),
+        Label("//cc/toolchains/actions:c_compile"),
+        Label("//cc/toolchains/actions:cpp_compile"),
+        Label("//cc/toolchains/actions:cpp_header_parsing"),
     ],
     # There are no actions listed for coverage, dwp, and objcopy in action_names.bzl.
     "coverage_files": [],
     "dwp_files": [],
     "linker_files": [
-        "@rules_cc//cc/toolchains/actions:cpp_link_dynamic_library",  # copybara-use-repo-external-label
-        "@rules_cc//cc/toolchains/actions:cpp_link_nodeps_dynamic_library",  # copybara-use-repo-external-label
-        "@rules_cc//cc/toolchains/actions:cpp_link_executable",  # copybara-use-repo-external-label
+        Label("//cc/toolchains/actions:cpp_link_dynamic_library"),
+        Label("//cc/toolchains/actions:cpp_link_nodeps_dynamic_library"),
+        Label("//cc/toolchains/actions:cpp_link_executable"),
     ],
     "objcopy_files": [],
     "strip_files": [
-        "@rules_cc//cc/toolchains/actions:strip",  # copybara-use-repo-external-label
+        Label("//cc/toolchains/actions:strip"),
     ],
 }
 
 def cc_toolchain(
+        *,
         name,
-        dynamic_runtime_lib = None,
+        tool_map = None,
+        args = [],
+        known_features = [],
+        enabled_features = [],
         libc_top = None,
         module_map = None,
-        output_licenses = [],
+        dynamic_runtime_lib = None,
         static_runtime_lib = None,
         supports_header_parsing = False,
-        supports_param_files = True,
-        target_compatible_with = None,
-        exec_compatible_with = None,
-        compatible_with = None,
-        tags = [],
-        visibility = None,
+        supports_param_files = False,
         **kwargs):
-    """A macro that invokes native.cc_toolchain under the hood.
+    """A C/C++ toolchain configuration.
+
+    This rule is the core declaration of a complete C/C++ toolchain. It collects together
+    tool configuration, which arguments to pass to each tool, and how
+    [features](https://bazel.build/docs/cc-toolchain-config-reference#features)
+    (dynamically-toggleable argument lists) interact.
+
+    A single `cc_toolchain` may support a wide variety of platforms and configurations through
+    [configurable build attributes](https://bazel.build/docs/configurable-attributes) and
+    [feature relationships](https://bazel.build/docs/cc-toolchain-config-reference#feature-relationships).
+
+    Arguments are applied to commandline invocation of tools in the following order:
+
+    1. Arguments in the order they are listed in listed in [`args`](#cc_toolchain-args).
+    2. Any legacy/built-in features that have been implicitly or explicitly enabled.
+    3. User-defined features in the order they are listed in
+       [`known_features`](#cc_toolchain-known_features).
+
+    When building a `cc_toolchain` configuration, it's important to understand how `select`
+    statements will be evaluated:
+
+    * Most attributes and dependencies of a `cc_toolchain` are evaluated under the target platform.
+      This means that a `@platforms//os:linux` constraint will be satisfied when
+      the final compiled binaries are intended to be ran from a Linux machine. This means that
+      a different operating system (e.g. Windows) may be cross-compiling to linux.
+    * The `cc_tool_map` rule performs a transition to the exec platform when evaluating tools. This
+      means that a if a `@platforms//os:linux` constraint is satisfied in a
+      `select` statement on a `cc_tool`, that means the machine that will run the tool is a Linux
+      machine. This means that a Linux machine may be cross-compiling to a different OS
+      like Windows.
 
     Generated rules:
         {name}: A `cc_toolchain` for this toolchain.
@@ -78,38 +106,65 @@ def cc_toolchain(
             normally enumerated as part of the `cc_toolchain` rule.
 
     Args:
-        name: str: The name of the label for the toolchain.
-        dynamic_runtime_lib: See cc_toolchain.dynamic_runtime_lib
-        libc_top: See cc_toolchain.libc_top
-        module_map: See cc_toolchain.module_map
-        output_licenses: See cc_toolchain.output_licenses
-        static_runtime_lib: See cc_toolchain.static_runtime_lib
-        supports_header_parsing: See cc_toolchain.supports_header_parsing
-        supports_param_files: See cc_toolchain.supports_param_files
-        target_compatible_with: target_compatible_with to apply to all generated
-          rules
-        exec_compatible_with: exec_compatible_with to apply to all generated
-          rules
-        compatible_with: compatible_with to apply to all generated rules
-        tags: Tags to apply to all generated rules
-        visibility: Visibility of toolchain rule
-        **kwargs: Args to be passed through to cc_toolchain_config.
+        name: (str) The name of the label for the toolchain.
+        tool_map: (Label) The `cc_tool_map` that specifies the tools to use for various toolchain
+            actions.
+        args: (List[Label]) A list of `cc_args` and `cc_arg_list` to apply across this toolchain.
+        known_features: (List[Label]) A list of `cc_feature` rules that this toolchain supports.
+            Whether or not these
+            [features](https://bazel.build/docs/cc-toolchain-config-reference#features)
+            are enabled may change over the course of a build. See the documentation for
+            `cc_feature` for more information.
+        enabled_features: (List[Label]) A list of `cc_feature` rules whose initial state should
+            be `enabled`. Note that it is still possible for these
+            [features](https://bazel.build/docs/cc-toolchain-config-reference#features)
+            to be disabled over the course of a build through other mechanisms. See the
+            documentation for `cc_feature` for more information.
+        libc_top: (Label) A collection of artifacts for libc passed as inputs to compile/linking
+            actions. See
+            [`cc_toolchain.libc_top`](https://bazel.build/reference/be/c-cpp#cc_toolchain.libc_top)
+            for more information.
+        module_map: (Label) Module map artifact to be used for modular builds. See
+            [`cc_toolchain.module_map`](https://bazel.build/reference/be/c-cpp#cc_toolchain.module_map)
+            for more information.
+        dynamic_runtime_lib: (Label) Dynamic library to link when the `static_link_cpp_runtimes`
+            and `dynamic_linking_mode`
+            [features](https://bazel.build/docs/cc-toolchain-config-reference#features) are both
+            enabled. See
+            [`cc_toolchain.dynamic_runtime_lib`](https://bazel.build/reference/be/c-cpp#cc_toolchain.dynamic_runtime_lib)
+            for more information.
+        static_runtime_lib: (Label) Static library to link when the `static_link_cpp_runtimes`
+            and `static_linking_mode`
+            [features](https://bazel.build/docs/cc-toolchain-config-reference#features) are both
+            enabled. See
+            [`cc_toolchain.dynamic_runtime_lib`](https://bazel.build/reference/be/c-cpp#cc_toolchain.dynamic_runtime_lib)
+            for more information.
+        supports_header_parsing: (bool) Whether or not this toolchain supports header parsing
+            actions. See
+            [`cc_toolchain.supports_header_parsing`](https://bazel.build/reference/be/c-cpp#cc_toolchain.supports_header_parsing)
+            for more information.
+        supports_param_files: (bool) Whether or not this toolchain supports linking via param files.
+            See
+            [`cc_toolchain.supports_param_files`](https://bazel.build/reference/be/c-cpp#cc_toolchain.supports_param_files)
+            for more information.
+        **kwargs: [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes)
+            that should be applied to all rules created by this macro.
     """
-    all_kwargs = {
-        "compatible_with": compatible_with,
-        "exec_compatible_with": exec_compatible_with,
-        "tags": tags,
-        "target_compatible_with": target_compatible_with,
-    }
+    cc_toolchain_visibility = kwargs.pop("visibility", default = None)
+
     for group in _LEGACY_FILE_GROUPS:
         if group in kwargs:
-            fail("Don't use legacy file groups such as %s. Instead, associate files with tools, actions, and args." % group)
+            fail("Don't use legacy file groups such as %s. Instead, associate files with `cc_tool` or `cc_args` rules." % group)
 
     config_name = "_{}_config".format(name)
     cc_toolchain_config(
         name = config_name,
+        tool_map = tool_map,
+        args = args,
+        known_features = known_features,
+        enabled_features = enabled_features,
         visibility = ["//visibility:private"],
-        **(all_kwargs | kwargs)
+        **kwargs
     )
 
     # Provides ar_files, compiler_files, linker_files, ...
@@ -121,13 +176,10 @@ def cc_toolchain(
             config = config_name,
             actions = actions,
             visibility = ["//visibility:private"],
-            **all_kwargs
+            **kwargs
         )
         legacy_file_groups[group] = group_name
 
-    if visibility != None:
-        all_kwargs["visibility"] = visibility
-
     _cc_toolchain(
         name = name,
         toolchain_config = config_name,
@@ -135,9 +187,11 @@ def cc_toolchain(
         dynamic_runtime_lib = dynamic_runtime_lib,
         libc_top = libc_top,
         module_map = module_map,
-        output_licenses = output_licenses,
         static_runtime_lib = static_runtime_lib,
         supports_header_parsing = supports_header_parsing,
         supports_param_files = supports_param_files,
-        **(all_kwargs | legacy_file_groups)
+        # This is required for Bazel versions <= 7.x.x. It is ignored in later versions.
+        exec_transition_for_inputs = False,
+        visibility = cc_toolchain_visibility,
+        **(kwargs | legacy_file_groups)
     )
diff --git a/cc/toolchains/toolchain_config_utils.bzl b/cc/toolchains/toolchain_config_utils.bzl
new file mode 100644
index 0000000..48e52ec
--- /dev/null
+++ b/cc/toolchains/toolchain_config_utils.bzl
@@ -0,0 +1,24 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Exposing some helper functions for configure cc toolchains."""
+
+load("//cc/private/toolchain:cc_configure.bzl", _MSVC_ENVVARS = "MSVC_ENVVARS")
+load("//cc/private/toolchain:lib_cc_configure.bzl", _escape_string = "escape_string")
+load("//cc/private/toolchain:windows_cc_configure.bzl", _find_vc_path = "find_vc_path", _setup_vc_env_vars = "setup_vc_env_vars")
+
+MSVC_ENVVARS = _MSVC_ENVVARS
+
+find_vc_path = _find_vc_path
+setup_vc_env_vars = _setup_vc_env_vars
+escape_string = _escape_string
diff --git a/cc/toolchains/variables/BUILD b/cc/toolchains/variables/BUILD
index ec07287..d650708 100644
--- a/cc/toolchains/variables/BUILD
+++ b/cc/toolchains/variables/BUILD
@@ -156,8 +156,15 @@ cc_variable(
 
 cc_variable(
     name = "libraries_to_link",
-    actions = ["//cc/toolchains/actions:link_actions"],
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
     type = types.option(types.list(types.struct(
+        name = types.string,
+        is_whole_archive = types.bool,
+        object_files = types.list(types.file),
+        path = types.string,
         shared_libraries = types.list(types.struct(
             name = types.string,
             is_whole_archive = types.bool,
@@ -165,9 +172,56 @@ cc_variable(
             path = types.file,
             type = types.string,
         )),
+        type = types.string,
     ))),
 )
 
+cc_variable(
+    name = "libraries_to_link.type",
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
+    # See :libraries_to_link.
+    type = types.string,
+)
+
+cc_variable(
+    name = "libraries_to_link.name",
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
+    # See :libraries_to_link.
+    type = types.string,
+)
+
+cc_variable(
+    name = "libraries_to_link.path",
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
+    # See :libraries_to_link.
+    type = types.string,
+)
+
+cc_variable(
+    name = "libraries_to_link.object_files",
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
+    # See :libraries_to_link.
+    type = types.list(types.file),
+)
+
+cc_variable(
+    name = "libraries_to_link.is_whole_archive",
+    actions = ["//cc/toolchains/actions:link_actions"],
+    type = types.bool,
+)
+
 cc_variable(
     name = "libraries_to_link.shared_libraries",
     actions = ["//cc/toolchains/actions:link_actions"],
@@ -213,8 +267,11 @@ cc_variable(
 
 cc_variable(
     name = "linker_param_file",
-    actions = ["//cc/toolchains/actions:link_actions"],
-    type = types.file,
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
+    type = types.option(types.file),
 )
 
 cc_variable(
@@ -255,13 +312,19 @@ cc_variable(
 
 cc_variable(
     name = "output_execpath",
-    actions = ["//cc/toolchains/actions:link_actions"],
+    actions = [
+        "//cc/toolchains/actions:cpp_link_static_library",
+        "//cc/toolchains/actions:link_actions",
+    ],
     type = types.option(types.directory),
 )
 
 cc_variable(
     name = "output_file",
-    actions = ["//cc/toolchains/actions:compile_actions"],
+    actions = [
+        "//cc/toolchains/actions:compile_actions",
+        "//cc/toolchains/actions:strip",
+    ],
     type = types.file,
 )
 
@@ -337,10 +400,8 @@ cc_variable(
     type = types.list(types.string),
 )
 
-cc_variable(
-    name = "sysroot",
-    type = types.directory,
-)
+# Instead of the "sysroot" variable, use the cc_sysroot macro in
+# //cc/toolchains/args:sysroot.bzl
 
 cc_variable(
     name = "system_include_paths",
@@ -463,7 +524,6 @@ cc_builtin_variables(
         ":source_file",
         ":strip_debug_symbols",
         ":stripopts",
-        ":sysroot",
         ":system_include_paths",
         ":thinlto_index",
         ":thinlto_indexing_param_file",
diff --git a/docs/BUILD b/docs/BUILD
new file mode 100644
index 0000000..3680fb6
--- /dev/null
+++ b/docs/BUILD
@@ -0,0 +1,60 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@bazel_skylib//rules:diff_test.bzl", "diff_test")
+load("@bazel_skylib//rules:expand_template.bzl", "expand_template")
+load("@stardoc//stardoc:stardoc.bzl", "stardoc")
+load("//cc/toolchains/impl:documented_api.bzl", "DOCUMENTED_TOOLCHAIN_RULES")
+load("//cc/toolchains/impl:markdown_helpers.bzl", "xref_substitutions")
+
+filegroup(
+    name = "srcs",
+    srcs = glob([
+        "**/*.bzl",
+        "**/BUILD",
+    ]),
+    visibility = ["//visibility:public"],
+)
+
+stardoc(
+    name = "toolchain_api",
+    out = "raw_generated_toolchain_api.md",
+    input = "//cc/toolchains/impl:documented_api.bzl",
+    deps = ["//cc/toolchains:toolchain_rules"],
+)
+
+expand_template(
+    name = "toolchain_api_md",
+    out = "generated_toolchain_api.md",
+    # Dictionary order 100% matters here!
+    # buildifier: disable=unsorted-dict-items
+    substitutions = {
+        # Strip @rules_cc to prevent instances of @rules_cc@rules_cc//cc.
+        "@rules_cc//cc": "//cc",
+        # In GitHub, we prefer to clarify all the labels that come from
+        # rules_cc.
+        "//cc": "@rules_cc//cc",
+    } | xref_substitutions({
+        "`{}`".format(rule_name): "#{}".format(rule_name)
+        for rule_name in DOCUMENTED_TOOLCHAIN_RULES
+    }),
+    # buildifier: enable=unsorted-dict-items
+    template = ":raw_generated_toolchain_api.md",
+)
+
+diff_test(
+    name = "toolchain_api_diff_test",
+    file1 = ":generated_toolchain_api.md",
+    file2 = ":toolchain_api.md",
+)
diff --git a/docs/toolchain_api.md b/docs/toolchain_api.md
new file mode 100644
index 0000000..b51e378
--- /dev/null
+++ b/docs/toolchain_api.md
@@ -0,0 +1,779 @@
+<!-- Generated with Stardoc: http://skydoc.bazel.build -->
+
+This is a list of rules/macros that should be exported as documentation.
+
+<a id="cc_action_type"></a>
+
+## cc_action_type
+
+<pre>
+cc_action_type(<a href="#cc_action_type-name">name</a>, <a href="#cc_action_type-action_name">action_name</a>)
+</pre>
+
+A type of action (eg. c_compile, assemble, strip).
+
+[`cc_action_type`](#cc_action_type) rules are used to associate arguments and tools together to
+perform a specific action. Bazel prescribes a set of known action types that are used to drive
+typical C/C++/ObjC actions like compiling, linking, and archiving. The set of well-known action
+types can be found in [@rules_cc//cc/toolchains/actions:BUILD](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/actions/BUILD).
+
+It's possible to create project-specific action types for use in toolchains. Be careful when
+doing this, because every toolchain that encounters the action will need to be configured to
+support the custom action type. If your project is a library, avoid creating new action types as
+it will reduce compatibility with existing toolchains and increase setup complexity for users.
+
+Example:
+```
+load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
+load("@rules_cc//cc/toolchains:actions.bzl", "cc_action_type")
+
+cc_action_type(
+    name = "cpp_compile",
+    action_name =  = ACTION_NAMES.cpp_compile,
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_action_type-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_action_type-action_name"></a>action_name |  -   | String | required |  |
+
+
+<a id="cc_action_type_set"></a>
+
+## cc_action_type_set
+
+<pre>
+cc_action_type_set(<a href="#cc_action_type_set-name">name</a>, <a href="#cc_action_type_set-actions">actions</a>, <a href="#cc_action_type_set-allow_empty">allow_empty</a>)
+</pre>
+
+Represents a set of actions.
+
+This is a convenience rule to allow for more compact representation of a group of action types.
+Use this anywhere a [`cc_action_type`](#cc_action_type) is accepted.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:actions.bzl", "cc_action_type_set")
+
+cc_action_type_set(
+    name = "link_executable_actions",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:cpp_link_executable",
+        "@rules_cc//cc/toolchains/actions:lto_index_for_executable",
+    ],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_action_type_set-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_action_type_set-actions"></a>actions |  A list of cc_action_type or cc_action_type_set   | <a href="https://bazel.build/concepts/labels">List of labels</a> | required |  |
+| <a id="cc_action_type_set-allow_empty"></a>allow_empty |  -   | Boolean | optional |  `False`  |
+
+
+<a id="cc_args_list"></a>
+
+## cc_args_list
+
+<pre>
+cc_args_list(<a href="#cc_args_list-name">name</a>, <a href="#cc_args_list-args">args</a>)
+</pre>
+
+An ordered list of cc_args.
+
+This is a convenience rule to allow you to group a set of multiple [`cc_args`](#cc_args) into a
+single list. This particularly useful for toolchain behaviors that require different flags for
+different actions.
+
+Note: The order of the arguments in `args` is preserved to support order-sensitive flags.
+
+Example usage:
+```
+load("@rules_cc//cc/toolchains:cc_args.bzl", "cc_args")
+load("@rules_cc//cc/toolchains:args_list.bzl", "cc_args_list")
+
+cc_args(
+    name = "gc_sections",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:link_actions",
+    ],
+    args = ["-Wl,--gc-sections"],
+)
+
+cc_args(
+    name = "function_sections",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:compile_actions",
+        "@rules_cc//cc/toolchains/actions:link_actions",
+    ],
+    args = ["-ffunction-sections"],
+)
+
+cc_args_list(
+    name = "gc_functions",
+    args = [
+        ":function_sections",
+        ":gc_sections",
+    ],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_args_list-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_args_list-args"></a>args |  (ordered) cc_args to include in this list.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="cc_external_feature"></a>
+
+## cc_external_feature
+
+<pre>
+cc_external_feature(<a href="#cc_external_feature-name">name</a>, <a href="#cc_external_feature-feature_name">feature_name</a>, <a href="#cc_external_feature-overridable">overridable</a>)
+</pre>
+
+A declaration that a [feature](https://bazel.build/docs/cc-toolchain-config-reference#features) with this name is defined elsewhere.
+
+This rule communicates that a feature has been defined externally to make it possible to reference
+features that live outside the rule-based cc toolchain ecosystem. This allows various toolchain
+rules to reference the external feature without accidentally re-defining said feature.
+
+This rule is currently considered a private API of the toolchain rules to encourage the Bazel
+ecosystem to migrate to properly defining their features as rules.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:external_feature.bzl", "cc_external_feature")
+
+# rules_rust defines a feature that is disabled whenever rust artifacts are being linked using
+# the cc toolchain to signal that incompatible flags should be disabled as well.
+cc_external_feature(
+    name = "rules_rust_unsupported_feature",
+    feature_name = "rules_rust_unsupported_feature",
+    overridable = False,
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_external_feature-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_external_feature-feature_name"></a>feature_name |  The name of the feature   | String | required |  |
+| <a id="cc_external_feature-overridable"></a>overridable |  Whether the feature can be overridden   | Boolean | required |  |
+
+
+<a id="cc_feature"></a>
+
+## cc_feature
+
+<pre>
+cc_feature(<a href="#cc_feature-name">name</a>, <a href="#cc_feature-args">args</a>, <a href="#cc_feature-feature_name">feature_name</a>, <a href="#cc_feature-implies">implies</a>, <a href="#cc_feature-mutually_exclusive">mutually_exclusive</a>, <a href="#cc_feature-overrides">overrides</a>, <a href="#cc_feature-requires_any_of">requires_any_of</a>)
+</pre>
+
+A dynamic set of toolchain flags that create a singular [feature](https://bazel.build/docs/cc-toolchain-config-reference#features) definition.
+
+A feature is basically a dynamically toggleable [`cc_args_list`](#cc_args_list). There are a variety of
+dependencies and compatibility requirements that must be satisfied to enable a
+[`cc_feature`](#cc_feature). Once those conditions are met, the arguments in [`cc_feature.args`](#cc_feature-args)
+are expanded and added to the command-line.
+
+A feature may be enabled or disabled through the following mechanisms:
+* Via command-line flags, or a `.bazelrc` file via the
+  [`--features` flag](https://bazel.build/reference/command-line-reference#flag--features)
+* Through inter-feature relationships (via [`cc_feature.implies`](#cc_feature-implies)) where one
+  feature may implicitly enable another.
+* Individual rules (e.g. `cc_library`) or `package` definitions may elect to manually enable or
+  disable features through the
+  [`features` attribute](https://bazel.build/reference/be/common-definitions#common.features).
+
+Note that a feature may alternate between enabled and disabled dynamically over the course of a
+build. Because of their toggleable nature, it's generally best to avoid adding arguments to a
+[`cc_toolchain`](#cc_toolchain) as a [`cc_feature`](#cc_feature) unless strictly necessary. Instead, prefer to express arguments
+via [`cc_toolchain.args`](#cc_toolchain-args) whenever possible.
+
+You should use a [`cc_feature`](#cc_feature) when any of the following apply:
+* You need the flags to be dynamically toggled over the course of a build.
+* You want build files to be able to configure the flags in question. For example, a
+  binary might specify `features = ["optimize_for_size"]` to create a small
+  binary instead of optimizing for performance.
+* You need to carry forward Starlark toolchain behaviors. If you're migrating a
+  complex Starlark-based toolchain definition to these rules, many of the
+  workflows and flags were likely based on features.
+
+If you only need to configure flags via the Bazel command-line, instead
+consider adding a
+[`bool_flag`](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/common_settings_doc.md#bool_flag)
+paired with a [`config_setting`](https://bazel.build/reference/be/general#config_setting)
+and then make your [`cc_args`](#cc_args) rule `select` on the `config_setting`.
+
+For more details about how Bazel handles features, see the official Bazel
+documentation at
+https://bazel.build/docs/cc-toolchain-config-reference#features.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:feature.bzl", "cc_feature")
+
+# A feature that enables LTO, which may be incompatible when doing interop with various
+# languages (e.g. rust, go), or may need to be disabled for particular `cc_binary` rules
+# for various reasons.
+cc_feature(
+    name = "lto",
+    feature_name = "lto",
+    args = [":lto_args"],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_feature-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_feature-args"></a>args |  A list of [`cc_args`](#cc_args) or [`cc_args_list`](#cc_args_list) labels that are expanded when this feature is enabled.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_feature-feature_name"></a>feature_name |  The name of the feature that this rule implements.<br><br>The feature name is a string that will be used in the `features` attribute of rules to enable them (eg. `cc_binary(..., features = ["opt"])`.<br><br>While two features with the same `feature_name` may not be bound to the same toolchain, they can happily live alongside each other in the same BUILD file.<br><br>Example: <pre><code>cc_feature(&#10;    name = "sysroot_macos",&#10;    feature_name = "sysroot",&#10;    ...&#10;)&#10;&#10;cc_feature(&#10;    name = "sysroot_linux",&#10;    feature_name = "sysroot",&#10;    ...&#10;)</code></pre>   | String | optional |  `""`  |
+| <a id="cc_feature-implies"></a>implies |  List of features enabled along with this feature.<br><br>Warning: If any of the features cannot be enabled, this feature is silently disabled.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_feature-mutually_exclusive"></a>mutually_exclusive |  A list of things that this feature is mutually exclusive with.<br><br>It can be either: * A feature, in which case the two features are mutually exclusive. * A [`cc_mutually_exclusive_category`](#cc_mutually_exclusive_category), in which case all features that write     `mutually_exclusive = [":category"]` are mutually exclusive with each other.<br><br>If this feature has a side-effect of implementing another feature, it can be useful to list that feature here to ensure they aren't enabled at the same time.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_feature-overrides"></a>overrides |  A declaration that this feature overrides a known feature.<br><br>In the example below, if you missed the "overrides" attribute, it would complain that the feature "opt" was defined twice.<br><br>Example: <pre><code>load("@rules_cc//cc/toolchains:feature.bzl", "cc_feature")&#10;&#10;cc_feature(&#10;    name = "opt",&#10;    feature_name = "opt",&#10;    args = [":size_optimized"],&#10;    overrides = "@rules_cc//cc/toolchains/features:opt",&#10;)</code></pre>   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="cc_feature-requires_any_of"></a>requires_any_of |  A list of feature sets that define toolchain compatibility.<br><br>If *at least one* of the listed [`cc_feature_set`](#cc_feature_set)s are fully satisfied (all features exist in the toolchain AND are currently enabled), this feature is deemed compatible and may be enabled.<br><br>Note: Even if `cc_feature.requires_any_of` is satisfied, a feature is not enabled unless another mechanism (e.g. command-line flags, `cc_feature.implies`, `cc_toolchain_config.enabled_features`) signals that the feature should actually be enabled.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="cc_feature_constraint"></a>
+
+## cc_feature_constraint
+
+<pre>
+cc_feature_constraint(<a href="#cc_feature_constraint-name">name</a>, <a href="#cc_feature_constraint-all_of">all_of</a>, <a href="#cc_feature_constraint-none_of">none_of</a>)
+</pre>
+
+Defines a compound relationship between features.
+
+This rule can be used with [`cc_args.require_any_of`](#cc_args-require_any_of) to specify that a set
+of arguments are only enabled when a constraint is met. Both `all_of` and `none_of` must be
+satisfied simultaneously.
+
+This is basically a [`cc_feature_set`](#cc_feature_set) that supports `none_of` expressions. This extra flexibility
+is why this rule may only be used by [`cc_args.require_any_of`](#cc_args-require_any_of).
+
+Example:
+```
+load("@rules_cc//cc/toolchains:feature_constraint.bzl", "cc_feature_constraint")
+
+# A constraint that requires a `linker_supports_thinlto` feature to be enabled,
+# AND a `no_optimization` to be disabled.
+cc_feature_constraint(
+    name = "thinlto_constraint",
+    all_of = [":linker_supports_thinlto"],
+    none_of = [":no_optimization"],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_feature_constraint-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_feature_constraint-all_of"></a>all_of |  -   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_feature_constraint-none_of"></a>none_of |  -   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="cc_feature_set"></a>
+
+## cc_feature_set
+
+<pre>
+cc_feature_set(<a href="#cc_feature_set-name">name</a>, <a href="#cc_feature_set-all_of">all_of</a>)
+</pre>
+
+Defines a set of features.
+
+This may be used by both [`cc_feature`](#cc_feature) and [`cc_args`](#cc_args) rules, and is effectively a way to express
+a logical `AND` operation across multiple required features.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:feature_set.bzl", "cc_feature_set")
+
+cc_feature_set(
+    name = "thin_lto_requirements",
+    all_of = [
+        ":thin_lto",
+        ":opt",
+    ],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_feature_set-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_feature_set-all_of"></a>all_of |  A set of features   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="cc_mutually_exclusive_category"></a>
+
+## cc_mutually_exclusive_category
+
+<pre>
+cc_mutually_exclusive_category(<a href="#cc_mutually_exclusive_category-name">name</a>)
+</pre>
+
+A rule used to categorize [`cc_feature`](#cc_feature) definitions for which only one can be enabled.
+
+This is used by [`cc_feature.mutually_exclusive`](#cc_feature-mutually_exclusive) to express groups
+of [`cc_feature`](#cc_feature) definitions that are inherently incompatible with each other and must be treated as
+mutually exclusive.
+
+Warning: These groups are keyed by name, so two [`cc_mutually_exclusive_category`](#cc_mutually_exclusive_category) definitions of the
+same name in different packages will resolve to the same logical group.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:feature.bzl", "cc_feature")
+load("@rules_cc//cc/toolchains:mutually_exclusive_category.bzl", "cc_mutually_exclusive_category")
+
+cc_mutually_exclusive_category(
+    name = "opt_level",
+)
+
+cc_feature(
+    name = "speed_optimized",
+    mutually_exclusive = [":opt_level"],
+)
+
+cc_feature(
+    name = "size_optimized",
+    mutually_exclusive = [":opt_level"],
+)
+
+cc_feature(
+    name = "unoptimized",
+    mutually_exclusive = [":opt_level"],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_mutually_exclusive_category-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+
+
+<a id="cc_tool"></a>
+
+## cc_tool
+
+<pre>
+cc_tool(<a href="#cc_tool-name">name</a>, <a href="#cc_tool-src">src</a>, <a href="#cc_tool-data">data</a>, <a href="#cc_tool-allowlist_include_directories">allowlist_include_directories</a>, <a href="#cc_tool-capabilities">capabilities</a>)
+</pre>
+
+Declares a tool for use by toolchain actions.
+
+[`cc_tool`](#cc_tool) rules are used in a [`cc_tool_map`](#cc_tool_map) rule to ensure all files and
+metadata required to run a tool are available when constructing a [`cc_toolchain`](#cc_toolchain).
+
+In general, include all files that are always required to run a tool (e.g. libexec/** and
+cross-referenced tools in bin/*) in the [data](#cc_tool-data) attribute. If some files are only
+required when certain flags are passed to the tool, consider using a [`cc_args`](#cc_args) rule to
+bind the files to the flags that require them. This reduces the overhead required to properly
+enumerate a sandbox with all the files required to run a tool, and ensures that there isn't
+unintentional leakage across configurations and actions.
+
+Example:
+```
+load("@rules_cc//cc/toolchains:tool.bzl", "cc_tool")
+
+cc_tool(
+    name = "clang_tool",
+    executable = "@llvm_toolchain//:bin/clang",
+    # Suppose clang needs libc to run.
+    data = ["@llvm_toolchain//:lib/x86_64-linux-gnu/libc.so.6"]
+    tags = ["requires-network"],
+    capabilities = ["@rules_cc//cc/toolchains/capabilities:supports_pic"],
+)
+```
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_tool-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_tool-src"></a>src |  The underlying binary that this tool represents.<br><br>Usually just a single prebuilt (eg. @toolchain//:bin/clang), but may be any executable label.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="cc_tool-data"></a>data |  Additional files that are required for this tool to run.<br><br>Frequently, clang and gcc require additional files to execute as they often shell out to other binaries (e.g. `cc1`).   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_tool-allowlist_include_directories"></a>allowlist_include_directories |  Include paths implied by using this tool.<br><br>Compilers may include a set of built-in headers that are implicitly available unless flags like `-nostdinc` are provided. Bazel checks that all included headers are properly provided by a dependency or allowlisted through this mechanism.<br><br>As a rule of thumb, only use this if Bazel is complaining about absolute paths in your toolchain and you've ensured that the toolchain is compiling with the `-no-canonical-prefixes` and/or `-fno-canonical-system-headers` arguments.<br><br>This can help work around errors like: `the source file 'main.c' includes the following non-builtin files with absolute paths (if these are builtin files, make sure these paths are in your toolchain)`.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="cc_tool-capabilities"></a>capabilities |  Declares that a tool is capable of doing something.<br><br>For example, `@rules_cc//cc/toolchains/capabilities:supports_pic`.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="cc_tool_capability"></a>
+
+## cc_tool_capability
+
+<pre>
+cc_tool_capability(<a href="#cc_tool_capability-name">name</a>, <a href="#cc_tool_capability-feature_name">feature_name</a>)
+</pre>
+
+A capability is an optional feature that a tool supports.
+
+For example, not all compilers support PIC, so to handle this, we write:
+
+```
+cc_tool(
+    name = "clang",
+    src = "@host_tools/bin/clang",
+    capabilities = [
+        "@rules_cc//cc/toolchains/capabilities:supports_pic",
+    ],
+)
+
+cc_args(
+    name = "pic",
+    requires = [
+        "@rules_cc//cc/toolchains/capabilities:supports_pic"
+    ],
+    args = ["-fPIC"],
+)
+```
+
+This ensures that `-fPIC` is added to the command-line only when we are using a
+tool that supports PIC.
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="cc_tool_capability-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="cc_tool_capability-feature_name"></a>feature_name |  The name of the feature to generate for this capability   | String | optional |  `""`  |
+
+
+<a id="cc_args"></a>
+
+## cc_args
+
+<pre>
+cc_args(<a href="#cc_args-name">name</a>, <a href="#cc_args-actions">actions</a>, <a href="#cc_args-allowlist_include_directories">allowlist_include_directories</a>, <a href="#cc_args-args">args</a>, <a href="#cc_args-data">data</a>, <a href="#cc_args-env">env</a>, <a href="#cc_args-format">format</a>, <a href="#cc_args-iterate_over">iterate_over</a>, <a href="#cc_args-nested">nested</a>,
+        <a href="#cc_args-requires_not_none">requires_not_none</a>, <a href="#cc_args-requires_none">requires_none</a>, <a href="#cc_args-requires_true">requires_true</a>, <a href="#cc_args-requires_false">requires_false</a>, <a href="#cc_args-requires_equal">requires_equal</a>,
+        <a href="#cc_args-requires_equal_value">requires_equal_value</a>, <a href="#cc_args-requires_any_of">requires_any_of</a>, <a href="#cc_args-kwargs">kwargs</a>)
+</pre>
+
+Action-specific arguments for use with a [`cc_toolchain`](#cc_toolchain).
+
+This rule is the fundamental building building block for every toolchain tool invocation. Each
+argument expressed in a toolchain tool invocation (e.g. `gcc`, `llvm-ar`) is declared in a
+[`cc_args`](#cc_args) rule that applies an ordered list of arguments to a set of toolchain
+actions. [`cc_args`](#cc_args) rules can be added unconditionally to a
+[`cc_toolchain`](#cc_toolchain), conditionally via `select()` statements, or dynamically via an
+intermediate [`cc_feature`](#cc_feature).
+
+Conceptually, this is similar to the old `CFLAGS`, `CPPFLAGS`, etc. environment variables that
+many build systems use to determine which flags to use for a given action. The significant
+difference is that [`cc_args`](#cc_args) rules are declared in a structured way that allows for
+significantly more powerful and sharable toolchain configurations. Also, due to Bazel's more
+granular action types, it's possible to bind flags to very specific actions (e.g. LTO indexing
+for an executable vs a dynamic library) multiple different actions (e.g. C++ compile and link
+simultaneously).
+
+Example usage:
+```
+load("@rules_cc//cc/toolchains:args.bzl", "cc_args")
+
+# Basic usage: a trivial flag.
+#
+# An example of expressing `-Werror` as a [`cc_args`](#cc_args) rule.
+cc_args(
+    name = "warnings_as_errors",
+    actions = [
+        # Applies to all C/C++ compile actions.
+        "@rules_cc//cc/toolchains/actions:compile_actions",
+    ],
+    args = ["-Werror"],
+)
+
+# Basic usage: ordered flags.
+#
+# An example of linking against libc++, which uses two flags that must be applied in order.
+cc_args(
+    name = "link_libcxx",
+    actions = [
+        # Applies to all link actions.
+        "@rules_cc//cc/toolchains/actions:link_actions",
+    ],
+    # On tool invocation, this appears as `-Xlinker -lc++`. Nothing will ever end up between
+    # the two flags.
+    args = [
+        "-Xlinker",
+        "-lc++",
+    ],
+)
+
+# Advanced usage: built-in variable expansions.
+#
+# Expands to `-L/path/to/search_dir` for each directory in the built-in variable
+# `library_search_directories`. This variable is managed internally by Bazel through inherent
+# behaviors of Bazel and the interactions between various C/C++ build rules.
+cc_args(
+    name = "library_search_directories",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:link_actions",
+    ],
+    args = ["-L{search_dir}"],
+    iterate_over = "@rules_cc//cc/toolchains/variables:library_search_directories",
+    requires_not_none = "@rules_cc//cc/toolchains/variables:library_search_directories",
+    format = {
+        "search_dir": "@rules_cc//cc/toolchains/variables:library_search_directories",
+    },
+)
+```
+
+For more extensive examples, see the usages here:
+    https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args
+
+
+**PARAMETERS**
+
+
+| Name  | Description | Default Value |
+| :------------- | :------------- | :------------- |
+| <a id="cc_args-name"></a>name |  (str) The name of the target.   |  none |
+| <a id="cc_args-actions"></a>actions |  (List[Label]) A list of labels of [`cc_action_type`](#cc_action_type) or [`cc_action_type_set`](#cc_action_type_set) rules that dictate which actions these arguments should be applied to.   |  `None` |
+| <a id="cc_args-allowlist_include_directories"></a>allowlist_include_directories |  (List[Label]) A list of include paths that are implied by using this rule. These must point to a skylib [directory](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/directory_doc.md#directory) or [subdirectory](https://github.com/bazelbuild/bazel-skylib/tree/main/doc/directory_subdirectory_doc.md#subdirectory) rule. Some flags (e.g. --sysroot) imply certain include paths are available despite not explicitly specifying a normal include path flag (`-I`, `-isystem`, etc.). Bazel checks that all included headers are properly provided by a dependency or allowlisted through this mechanism.<br><br>As a rule of thumb, only use this if Bazel is complaining about absolute paths in your toolchain and you've ensured that the toolchain is compiling with the `-no-canonical-prefixes` and/or `-fno-canonical-system-headers` arguments.<br><br>This can help work around errors like: `the source file 'main.c' includes the following non-builtin files with absolute paths (if these are builtin files, make sure these paths are in your toolchain)`.   |  `None` |
+| <a id="cc_args-args"></a>args |  (List[str]) The command-line arguments that are applied by using this rule. This is mutually exclusive with [nested](#cc_args-nested).   |  `None` |
+| <a id="cc_args-data"></a>data |  (List[Label]) A list of runtime data dependencies that are required for these arguments to work as intended.   |  `None` |
+| <a id="cc_args-env"></a>env |  (Dict[str, str]) Environment variables that should be set when the tool is invoked.   |  `None` |
+| <a id="cc_args-format"></a>format |  (Dict[str, Label]) A mapping of format strings to the label of the corresponding [`cc_variable`](#cc_variable) that the value should be pulled from. All instances of `{variable_name}` will be replaced with the expanded value of `variable_name` in this dictionary. The complete list of possible variables can be found in https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD. It is not possible to declare custom variables--these are inherent to Bazel itself.   |  `{}` |
+| <a id="cc_args-iterate_over"></a>iterate_over |  (Label) The label of a [`cc_variable`](#cc_variable) that should be iterated over. This is intended for use with built-in variables that are lists.   |  `None` |
+| <a id="cc_args-nested"></a>nested |  (List[Label]) A list of [`cc_nested_args`](#cc_nested_args) rules that should be expanded to command-line arguments when this rule is used. This is mutually exclusive with [args](#cc_args-args).   |  `None` |
+| <a id="cc_args-requires_not_none"></a>requires_not_none |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for existence before expanding this rule. If the variable is None, this rule will be ignored.   |  `None` |
+| <a id="cc_args-requires_none"></a>requires_none |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for non-existence before expanding this rule. If the variable is not None, this rule will be ignored.   |  `None` |
+| <a id="cc_args-requires_true"></a>requires_true |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for truthiness before expanding this rule. If the variable is false, this rule will be ignored.   |  `None` |
+| <a id="cc_args-requires_false"></a>requires_false |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for falsiness before expanding this rule. If the variable is true, this rule will be ignored.   |  `None` |
+| <a id="cc_args-requires_equal"></a>requires_equal |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for equality before expanding this rule. If the variable is not equal to (requires_equal_value)[#cc_args-requires_equal_value], this rule will be ignored.   |  `None` |
+| <a id="cc_args-requires_equal_value"></a>requires_equal_value |  (str) The value to compare (requires_equal)[#cc_args-requires_equal] against.   |  `None` |
+| <a id="cc_args-requires_any_of"></a>requires_any_of |  (List[Label]) These arguments will be used in a tool invocation when at least one of the [cc_feature_constraint](#cc_feature_constraint) entries in this list are satisfied. If omitted, this flag set will be enabled unconditionally.   |  `None` |
+| <a id="cc_args-kwargs"></a>kwargs |  [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.   |  none |
+
+
+<a id="cc_nested_args"></a>
+
+## cc_nested_args
+
+<pre>
+cc_nested_args(<a href="#cc_nested_args-name">name</a>, <a href="#cc_nested_args-args">args</a>, <a href="#cc_nested_args-data">data</a>, <a href="#cc_nested_args-format">format</a>, <a href="#cc_nested_args-iterate_over">iterate_over</a>, <a href="#cc_nested_args-nested">nested</a>, <a href="#cc_nested_args-requires_not_none">requires_not_none</a>, <a href="#cc_nested_args-requires_none">requires_none</a>,
+               <a href="#cc_nested_args-requires_true">requires_true</a>, <a href="#cc_nested_args-requires_false">requires_false</a>, <a href="#cc_nested_args-requires_equal">requires_equal</a>, <a href="#cc_nested_args-requires_equal_value">requires_equal_value</a>, <a href="#cc_nested_args-kwargs">kwargs</a>)
+</pre>
+
+Nested arguments for use in more complex [`cc_args`](#cc_args) expansions.
+
+While this rule is very similar in shape to [`cc_args`](#cc_args), it is intended to be used as a
+dependency of [`cc_args`](#cc_args) to provide additional arguments that should be applied to the
+same actions as defined by the parent [`cc_args`](#cc_args) rule. The key motivation for this rule
+is to allow for more complex variable-based argument expensions.
+
+Prefer expressing collections of arguments as [`cc_args`](#cc_args) and
+[`cc_args_list`](#cc_args_list) rules when possible.
+
+For living examples of how this rule is used, see the usages here:
+    https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args/runtime_library_search_directories/BUILD
+    https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/args/libraries_to_link/BUILD
+
+Note: These examples are non-trivial, but they illustrate when it is absolutely necessary to
+use this rule.
+
+
+**PARAMETERS**
+
+
+| Name  | Description | Default Value |
+| :------------- | :------------- | :------------- |
+| <a id="cc_nested_args-name"></a>name |  (str) The name of the target.   |  none |
+| <a id="cc_nested_args-args"></a>args |  (List[str]) The command-line arguments that are applied by using this rule. This is mutually exclusive with [nested](#cc_nested_args-nested).   |  `None` |
+| <a id="cc_nested_args-data"></a>data |  (List[Label]) A list of runtime data dependencies that are required for these arguments to work as intended.   |  `None` |
+| <a id="cc_nested_args-format"></a>format |  (Dict[str, Label]) A mapping of format strings to the label of the corresponding [`cc_variable`](#cc_variable) that the value should be pulled from. All instances of `{variable_name}` will be replaced with the expanded value of `variable_name` in this dictionary. The complete list of possible variables can be found in https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD. It is not possible to declare custom variables--these are inherent to Bazel itself.   |  `{}` |
+| <a id="cc_nested_args-iterate_over"></a>iterate_over |  (Label) The label of a [`cc_variable`](#cc_variable) that should be iterated over. This is intended for use with built-in variables that are lists.   |  `None` |
+| <a id="cc_nested_args-nested"></a>nested |  (List[Label]) A list of [`cc_nested_args`](#cc_nested_args) rules that should be expanded to command-line arguments when this rule is used. This is mutually exclusive with [args](#cc_nested_args-args).   |  `None` |
+| <a id="cc_nested_args-requires_not_none"></a>requires_not_none |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for existence before expanding this rule. If the variable is None, this rule will be ignored.   |  `None` |
+| <a id="cc_nested_args-requires_none"></a>requires_none |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for non-existence before expanding this rule. If the variable is not None, this rule will be ignored.   |  `None` |
+| <a id="cc_nested_args-requires_true"></a>requires_true |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for truthiness before expanding this rule. If the variable is false, this rule will be ignored.   |  `None` |
+| <a id="cc_nested_args-requires_false"></a>requires_false |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for falsiness before expanding this rule. If the variable is true, this rule will be ignored.   |  `None` |
+| <a id="cc_nested_args-requires_equal"></a>requires_equal |  (Label) The label of a [`cc_variable`](#cc_variable) that should be checked for equality before expanding this rule. If the variable is not equal to (requires_equal_value)[#cc_nested_args-requires_equal_value], this rule will be ignored.   |  `None` |
+| <a id="cc_nested_args-requires_equal_value"></a>requires_equal_value |  (str) The value to compare (requires_equal)[#cc_nested_args-requires_equal] against.   |  `None` |
+| <a id="cc_nested_args-kwargs"></a>kwargs |  [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.   |  none |
+
+
+<a id="cc_tool_map"></a>
+
+## cc_tool_map
+
+<pre>
+cc_tool_map(<a href="#cc_tool_map-name">name</a>, <a href="#cc_tool_map-tools">tools</a>, <a href="#cc_tool_map-kwargs">kwargs</a>)
+</pre>
+
+A toolchain configuration rule that maps toolchain actions to tools.
+
+A [`cc_tool_map`](#cc_tool_map) aggregates all the tools that may be used for a given toolchain
+and maps them to their corresponding actions. Conceptually, this is similar to the
+`CXX=/path/to/clang++` environment variables that most build systems use to determine which
+tools to use for a given action. To simplify usage, some actions have been grouped together (for
+example,
+[@rules_cc//cc/toolchains/actions:cpp_compile_actions](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/actions/BUILD)) to
+logically express "all the C++ compile actions".
+
+In Bazel, there is a little more granularity to the mapping, so the mapping doesn't follow the
+traditional `CXX`, `AR`, etc. naming scheme. For a comprehensive list of all the well-known
+actions, see @rules_cc//cc/toolchains/actions:BUILD.
+
+Example usage:
+```
+load("@rules_cc//cc/toolchains:tool_map.bzl", "cc_tool_map")
+
+cc_tool_map(
+    name = "all_tools",
+    tools = {
+        "@rules_cc//cc/toolchains/actions:assembly_actions": ":asm",
+        "@rules_cc//cc/toolchains/actions:c_compile": ":clang",
+        "@rules_cc//cc/toolchains/actions:cpp_compile_actions": ":clang++",
+        "@rules_cc//cc/toolchains/actions:link_actions": ":lld",
+        "@rules_cc//cc/toolchains/actions:objcopy_embed_data": ":llvm-objcopy",
+        "@rules_cc//cc/toolchains/actions:strip": ":llvm-strip",
+        "@rules_cc//cc/toolchains/actions:ar_actions": ":llvm-ar",
+    },
+)
+```
+
+
+**PARAMETERS**
+
+
+| Name  | Description | Default Value |
+| :------------- | :------------- | :------------- |
+| <a id="cc_tool_map-name"></a>name |  (str) The name of the target.   |  none |
+| <a id="cc_tool_map-tools"></a>tools |  (Dict[Label, Label]) A mapping between [`cc_action_type`](#cc_action_type)/[`cc_action_type_set`](#cc_action_type_set) targets and the [`cc_tool`](#cc_tool) or executable target that implements that action.   |  none |
+| <a id="cc_tool_map-kwargs"></a>kwargs |  [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.   |  none |
+
+
+<a id="cc_toolchain"></a>
+
+## cc_toolchain
+
+<pre>
+cc_toolchain(<a href="#cc_toolchain-name">name</a>, <a href="#cc_toolchain-tool_map">tool_map</a>, <a href="#cc_toolchain-args">args</a>, <a href="#cc_toolchain-known_features">known_features</a>, <a href="#cc_toolchain-enabled_features">enabled_features</a>, <a href="#cc_toolchain-libc_top">libc_top</a>, <a href="#cc_toolchain-module_map">module_map</a>,
+             <a href="#cc_toolchain-dynamic_runtime_lib">dynamic_runtime_lib</a>, <a href="#cc_toolchain-static_runtime_lib">static_runtime_lib</a>, <a href="#cc_toolchain-supports_header_parsing">supports_header_parsing</a>, <a href="#cc_toolchain-supports_param_files">supports_param_files</a>,
+             <a href="#cc_toolchain-kwargs">kwargs</a>)
+</pre>
+
+A C/C++ toolchain configuration.
+
+This rule is the core declaration of a complete C/C++ toolchain. It collects together
+tool configuration, which arguments to pass to each tool, and how
+[features](https://bazel.build/docs/cc-toolchain-config-reference#features)
+(dynamically-toggleable argument lists) interact.
+
+A single [`cc_toolchain`](#cc_toolchain) may support a wide variety of platforms and configurations through
+[configurable build attributes](https://bazel.build/docs/configurable-attributes) and
+[feature relationships](https://bazel.build/docs/cc-toolchain-config-reference#feature-relationships).
+
+Arguments are applied to commandline invocation of tools in the following order:
+
+1. Arguments in the order they are listed in listed in [`args`](#cc_toolchain-args).
+2. Any legacy/built-in features that have been implicitly or explicitly enabled.
+3. User-defined features in the order they are listed in
+   [`known_features`](#cc_toolchain-known_features).
+
+When building a [`cc_toolchain`](#cc_toolchain) configuration, it's important to understand how `select`
+statements will be evaluated:
+
+* Most attributes and dependencies of a [`cc_toolchain`](#cc_toolchain) are evaluated under the target platform.
+  This means that a `@platforms//os:linux` constraint will be satisfied when
+  the final compiled binaries are intended to be ran from a Linux machine. This means that
+  a different operating system (e.g. Windows) may be cross-compiling to linux.
+* The [`cc_tool_map`](#cc_tool_map) rule performs a transition to the exec platform when evaluating tools. This
+  means that a if a `@platforms//os:linux` constraint is satisfied in a
+  `select` statement on a [`cc_tool`](#cc_tool), that means the machine that will run the tool is a Linux
+  machine. This means that a Linux machine may be cross-compiling to a different OS
+  like Windows.
+
+Generated rules:
+    {name}: A [`cc_toolchain`](#cc_toolchain) for this toolchain.
+    _{name}_config: A `cc_toolchain_config` for this toolchain.
+    _{name}_*_files: Generated rules that group together files for
+        "ar_files", "as_files", "compiler_files", "coverage_files",
+        "dwp_files", "linker_files", "objcopy_files", and "strip_files"
+        normally enumerated as part of the [`cc_toolchain`](#cc_toolchain) rule.
+
+
+**PARAMETERS**
+
+
+| Name  | Description | Default Value |
+| :------------- | :------------- | :------------- |
+| <a id="cc_toolchain-name"></a>name |  (str) The name of the label for the toolchain.   |  none |
+| <a id="cc_toolchain-tool_map"></a>tool_map |  (Label) The [`cc_tool_map`](#cc_tool_map) that specifies the tools to use for various toolchain actions.   |  `None` |
+| <a id="cc_toolchain-args"></a>args |  (List[Label]) A list of [`cc_args`](#cc_args) and `cc_arg_list` to apply across this toolchain.   |  `[]` |
+| <a id="cc_toolchain-known_features"></a>known_features |  (List[Label]) A list of [`cc_feature`](#cc_feature) rules that this toolchain supports. Whether or not these [features](https://bazel.build/docs/cc-toolchain-config-reference#features) are enabled may change over the course of a build. See the documentation for [`cc_feature`](#cc_feature) for more information.   |  `[]` |
+| <a id="cc_toolchain-enabled_features"></a>enabled_features |  (List[Label]) A list of [`cc_feature`](#cc_feature) rules whose initial state should be `enabled`. Note that it is still possible for these [features](https://bazel.build/docs/cc-toolchain-config-reference#features) to be disabled over the course of a build through other mechanisms. See the documentation for [`cc_feature`](#cc_feature) for more information.   |  `[]` |
+| <a id="cc_toolchain-libc_top"></a>libc_top |  (Label) A collection of artifacts for libc passed as inputs to compile/linking actions. See [`cc_toolchain.libc_top`](https://bazel.build/reference/be/c-cpp#cc_toolchain.libc_top) for more information.   |  `None` |
+| <a id="cc_toolchain-module_map"></a>module_map |  (Label) Module map artifact to be used for modular builds. See [`cc_toolchain.module_map`](https://bazel.build/reference/be/c-cpp#cc_toolchain.module_map) for more information.   |  `None` |
+| <a id="cc_toolchain-dynamic_runtime_lib"></a>dynamic_runtime_lib |  (Label) Dynamic library to link when the `static_link_cpp_runtimes` and `dynamic_linking_mode` [features](https://bazel.build/docs/cc-toolchain-config-reference#features) are both enabled. See [`cc_toolchain.dynamic_runtime_lib`](https://bazel.build/reference/be/c-cpp#cc_toolchain.dynamic_runtime_lib) for more information.   |  `None` |
+| <a id="cc_toolchain-static_runtime_lib"></a>static_runtime_lib |  (Label) Static library to link when the `static_link_cpp_runtimes` and `static_linking_mode` [features](https://bazel.build/docs/cc-toolchain-config-reference#features) are both enabled. See [`cc_toolchain.dynamic_runtime_lib`](https://bazel.build/reference/be/c-cpp#cc_toolchain.dynamic_runtime_lib) for more information.   |  `None` |
+| <a id="cc_toolchain-supports_header_parsing"></a>supports_header_parsing |  (bool) Whether or not this toolchain supports header parsing actions. See [`cc_toolchain.supports_header_parsing`](https://bazel.build/reference/be/c-cpp#cc_toolchain.supports_header_parsing) for more information.   |  `False` |
+| <a id="cc_toolchain-supports_param_files"></a>supports_param_files |  (bool) Whether or not this toolchain supports linking via param files. See [`cc_toolchain.supports_param_files`](https://bazel.build/reference/be/c-cpp#cc_toolchain.supports_param_files) for more information.   |  `False` |
+| <a id="cc_toolchain-kwargs"></a>kwargs |  [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to all rules created by this macro.   |  none |
+
+
+<a id="cc_variable"></a>
+
+## cc_variable
+
+<pre>
+cc_variable(<a href="#cc_variable-name">name</a>, <a href="#cc_variable-type">type</a>, <a href="#cc_variable-kwargs">kwargs</a>)
+</pre>
+
+Exposes a toolchain variable to use in toolchain argument expansions.
+
+This internal rule exposes [toolchain variables](https://bazel.build/docs/cc-toolchain-config-reference#cctoolchainconfiginfo-build-variables)
+that may be expanded in [`cc_args`](#cc_args) or [`cc_nested_args`](#cc_nested_args)
+rules. Because these varaibles merely expose variables inherrent to Bazel,
+it's not possible to declare custom variables.
+
+For a full list of available variables, see
+[@rules_cc//cc/toolchains/varaibles:BUILD](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/variables/BUILD).
+
+Example:
+```
+load("@rules_cc//cc/toolchains/impl:variables.bzl", "cc_variable")
+
+# Defines two targets, ":foo" and ":foo.bar"
+cc_variable(
+    name = "foo",
+    type = types.list(types.struct(bar = types.string)),
+)
+```
+
+
+**PARAMETERS**
+
+
+| Name  | Description | Default Value |
+| :------------- | :------------- | :------------- |
+| <a id="cc_variable-name"></a>name |  (str) The name of the outer variable, and the rule.   |  none |
+| <a id="cc_variable-type"></a>type |  The type of the variable, constructed using `types` factory in [@rules_cc//cc/toolchains/impl:variables.bzl](https://github.com/bazelbuild/rules_cc/tree/main/cc/toolchains/impl/variables.bzl).   |  none |
+| <a id="cc_variable-kwargs"></a>kwargs |  [common attributes](https://bazel.build/reference/be/common-definitions#common-attributes) that should be applied to this rule.   |  none |
+
+
diff --git a/examples/custom_toolchain/BUILD b/examples/custom_toolchain/BUILD
index 371fdfd..0631d7d 100644
--- a/examples/custom_toolchain/BUILD
+++ b/examples/custom_toolchain/BUILD
@@ -29,7 +29,9 @@
 #
 # This example demonstrates both approaches.
 
-load("@rules_cc//cc:defs.bzl", "cc_library", "cc_toolchain", "cc_toolchain_suite")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")
+load("@rules_cc//cc/toolchains:cc_toolchain_suite.bzl", "cc_toolchain_suite")
 
 # Load the Starlark logic defining the toolchain's behavior. For example: what
 # program runs to compile a source file and how its command line is
@@ -81,7 +83,7 @@ filegroup(
 cc_toolchain_suite(
     name = "legacy_selector",
     toolchains = {
-        "x86": ":my_custom_toolchain",
+        "k8": ":my_custom_toolchain",
     },
 )
 
diff --git a/examples/custom_toolchain/toolchain_config.bzl b/examples/custom_toolchain/toolchain_config.bzl
index e83162b..74b2280 100644
--- a/examples/custom_toolchain/toolchain_config.bzl
+++ b/examples/custom_toolchain/toolchain_config.bzl
@@ -12,7 +12,7 @@ https://docs.bazel.build/versions/main/tutorial/cc-toolchain-config.html for
 advanced usage.
 """
 
-load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl", "tool_path")
+load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "tool_path")  # buildifier: disable=deprecated-function
 
 def _impl(ctx):
     tool_paths = [
diff --git a/examples/my_c_archive/BUILD b/examples/my_c_archive/BUILD
index 4484684..d800738 100644
--- a/examples/my_c_archive/BUILD
+++ b/examples/my_c_archive/BUILD
@@ -15,7 +15,8 @@
 # Example showing how to create a custom Starlark rule that rules_cc can depend on
 
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
+load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
 load("//examples/my_c_archive:my_c_archive.bzl", "my_c_archive")
 load("//examples/my_c_compile:my_c_compile.bzl", "my_c_compile")
 
diff --git a/examples/my_c_archive/my_c_archive.bzl b/examples/my_c_archive/my_c_archive.bzl
index 314564f..84b34e5 100644
--- a/examples/my_c_archive/my_c_archive.bzl
+++ b/examples/my_c_archive/my_c_archive.bzl
@@ -14,8 +14,8 @@
 
 """Example showing how to create a rule that rules_cc can depend on."""
 
-load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
 load("@rules_cc//cc:action_names.bzl", "CPP_LINK_STATIC_LIBRARY_ACTION_NAME")
+load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cpp_toolchain", "use_cc_toolchain")
 load("//examples/my_c_compile:my_c_compile.bzl", "MyCCompileInfo")
 
 def _my_c_archive_impl(ctx):
@@ -92,8 +92,8 @@ my_c_archive = rule(
     attrs = {
         "deps": attr.label_list(providers = [CcInfo]),
         "object": attr.label(mandatory = True, providers = [MyCCompileInfo]),
-        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
+        "_cc_toolchain": attr.label(default = Label("@rules_cc//cc:current_cc_toolchain")),
     },
     fragments = ["cpp"],
-    toolchains = use_cpp_toolchain(),
+    toolchains = use_cc_toolchain(),
 )
diff --git a/examples/my_c_compile/my_c_compile.bzl b/examples/my_c_compile/my_c_compile.bzl
index d232f91..ac4fea9 100644
--- a/examples/my_c_compile/my_c_compile.bzl
+++ b/examples/my_c_compile/my_c_compile.bzl
@@ -14,8 +14,8 @@
 
 """Example showing how to create a rule that just compiles C sources."""
 
-load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
 load("@rules_cc//cc:action_names.bzl", "C_COMPILE_ACTION_NAME")
+load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cpp_toolchain", "use_cc_toolchain")
 
 MyCCompileInfo = provider(doc = "", fields = ["object"])
 
@@ -74,8 +74,8 @@ my_c_compile = rule(
     implementation = _my_c_compile_impl,
     attrs = {
         "src": attr.label(mandatory = True, allow_single_file = True),
-        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
+        "_cc_toolchain": attr.label(default = Label("@rules_cc//cc:current_cc_toolchain")),
     },
-    toolchains = use_cpp_toolchain(),
+    toolchains = use_cc_toolchain(),
     fragments = ["cpp"],
 )
diff --git a/examples/rule_based_toolchain/.bazelrc b/examples/rule_based_toolchain/.bazelrc
new file mode 100644
index 0000000..ac2fe2f
--- /dev/null
+++ b/examples/rule_based_toolchain/.bazelrc
@@ -0,0 +1,2 @@
+# Do not use the default toolchain.
+build --repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=0
diff --git a/examples/rule_based_toolchain/.bazelversion b/examples/rule_based_toolchain/.bazelversion
new file mode 100644
index 0000000..b26a34e
--- /dev/null
+++ b/examples/rule_based_toolchain/.bazelversion
@@ -0,0 +1 @@
+7.2.1
diff --git a/examples/rule_based_toolchain/BUILD.bazel b/examples/rule_based_toolchain/BUILD.bazel
new file mode 100644
index 0000000..bc09fb2
--- /dev/null
+++ b/examples/rule_based_toolchain/BUILD.bazel
@@ -0,0 +1,28 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@rules_cc//cc:cc_test.bzl", "cc_test")
+
+licenses(["notice"])
+
+cc_test(
+    name = "quick_test",
+    srcs = ["quick_test.cc"],
+    deps = [
+        "//dynamic_answer",
+        "//static_answer",
+        "@googletest//:gtest",
+        "@googletest//:gtest_main",
+    ],
+)
diff --git a/examples/rule_based_toolchain/MODULE.bazel b/examples/rule_based_toolchain/MODULE.bazel
new file mode 100644
index 0000000..88b5227
--- /dev/null
+++ b/examples/rule_based_toolchain/MODULE.bazel
@@ -0,0 +1,44 @@
+module(
+    name = "rule_based_toolchain",
+    version = "0.0.1",
+)
+
+bazel_dep(name = "platforms", version = "0.0.10")
+bazel_dep(name = "googletest", version = "1.15.2")
+bazel_dep(name = "bazel_skylib", version = "1.7.1")
+bazel_dep(name = "rules_cc")
+local_path_override(
+    module_name = "rules_cc",
+    path = "../..",
+)
+
+http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+
+http_archive(
+    name = "clang-linux-x86_64",
+    build_file = "//toolchain:clang.BUILD",
+    sha256 = "9042f89df9c13a2bf28e16ce34dfe22934b59b5d8390e94b030bb378bdb3c898",
+    type = "zip",
+    url = "https://chrome-infra-packages.appspot.com/dl/fuchsia/third_party/clang/linux-amd64/+/git_revision:0cfd03ac0d3f9713090a581bda07584754c73a49",
+)
+
+http_archive(
+    name = "clang-linux-aarch64",
+    build_file = "//toolchain:clang.BUILD",
+    sha256 = "61abb915821190baddafa973c69a9db9acda5a16ed3a89489ea2b3b030a2330b",
+    type = "zip",
+    url = "https://chrome-infra-packages.appspot.com/dl/fuchsia/third_party/clang/linux-arm64/+/git_revision:0cfd03ac0d3f9713090a581bda07584754c73a49",
+)
+
+http_archive(
+    name = "linux_sysroot",
+    build_file = "//toolchain:linux_sysroot.BUILD",
+    sha256 = "f45ca0d8b46810b94d2a7dbc65f9092337d6a9568b260b51173a5ab9314da25e",
+    type = "zip",
+    url = "https://chrome-infra-packages.appspot.com/dl/fuchsia/third_party/sysroot/bionic/+/git_revision:702eb9654703a7cec1cadf93a7e3aa269d053943",
+)
+
+register_toolchains(
+    "//toolchain:host_cc_toolchain",
+    dev_dependency = True,
+)
diff --git a/examples/rule_based_toolchain/README.md b/examples/rule_based_toolchain/README.md
new file mode 100644
index 0000000..9d370a5
--- /dev/null
+++ b/examples/rule_based_toolchain/README.md
@@ -0,0 +1,15 @@
+# Rule-based toolchains
+This example showcases a fully working rule-based toolchain for Linux. This also
+serves as an integration test to ensure rule-based toolchains continue to work
+as intended.
+
+The complete toolchain configuration lives [here](https://github.com/bazelbuild/rules_cc/tree/main/examples/rule_based_toolchain/toolchain).
+
+# Trying the example
+From this directory, you can run example tests that build using this toolchain
+with the following command:
+```
+$ bazel test //...
+```
+
+This example currently only supports Linux.
diff --git a/examples/rule_based_toolchain/constraint/BUILD.bazel b/examples/rule_based_toolchain/constraint/BUILD.bazel
new file mode 100644
index 0000000..062b033
--- /dev/null
+++ b/examples/rule_based_toolchain/constraint/BUILD.bazel
@@ -0,0 +1,65 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@bazel_skylib//lib:selects.bzl", "selects")
+
+licenses(["notice"])
+
+selects.config_setting_group(
+    name = "linux_x86_64",
+    match_all = [
+        "@platforms//os:linux",
+        "@platforms//cpu:x86_64",
+    ],
+)
+
+selects.config_setting_group(
+    name = "linux_aarch64",
+    match_all = [
+        "@platforms//os:linux",
+        "@platforms//cpu:aarch64",
+    ],
+)
+
+selects.config_setting_group(
+    name = "macos_x86_64",
+    match_all = [
+        "@platforms//os:macos",
+        "@platforms//cpu:x86_64",
+    ],
+)
+
+selects.config_setting_group(
+    name = "macos_aarch64",
+    match_all = [
+        "@platforms//os:macos",
+        "@platforms//cpu:aarch64",
+    ],
+)
+
+selects.config_setting_group(
+    name = "windows_x86_64",
+    match_all = [
+        "@platforms//os:windows",
+        "@platforms//cpu:x86_64",
+    ],
+)
+
+selects.config_setting_group(
+    name = "windows_aarch64",
+    match_all = [
+        "@platforms//os:windows",
+        "@platforms//cpu:aarch64",
+    ],
+)
diff --git a/examples/rule_based_toolchain/dynamic_answer/BUILD.bazel b/examples/rule_based_toolchain/dynamic_answer/BUILD.bazel
new file mode 100644
index 0000000..3085cdf
--- /dev/null
+++ b/examples/rule_based_toolchain/dynamic_answer/BUILD.bazel
@@ -0,0 +1,46 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_cc//cc:cc_shared_library.bzl", "cc_shared_library")
+
+licenses(["notice"])
+
+cc_library(
+    name = "headers",
+    hdrs = ["public/dynamic_answer.h"],
+    includes = ["public"],
+    visibility = ["//visibility:private"],
+)
+
+cc_library(
+    name = "answer",
+    srcs = ["dynamic_answer.c"],
+    visibility = ["//visibility:private"],
+    deps = [":headers"],
+)
+
+cc_shared_library(
+    name = "shared_library",
+    visibility = ["//visibility:private"],
+    deps = [":answer"],
+)
+
+# Forces linkage as a shared library.
+cc_library(
+    name = "dynamic_answer",
+    srcs = [":shared_library"],
+    visibility = ["//visibility:public"],
+    deps = [":headers"],
+)
diff --git a/examples/rule_based_toolchain/dynamic_answer/dynamic_answer.c b/examples/rule_based_toolchain/dynamic_answer/dynamic_answer.c
new file mode 100644
index 0000000..247526b
--- /dev/null
+++ b/examples/rule_based_toolchain/dynamic_answer/dynamic_answer.c
@@ -0,0 +1,19 @@
+// Copyright 2024 The Bazel Authors. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "dynamic_answer.h"
+
+int dynamic_answer(void) {
+    return 24;
+}
diff --git a/examples/rule_based_toolchain/dynamic_answer/public/dynamic_answer.h b/examples/rule_based_toolchain/dynamic_answer/public/dynamic_answer.h
new file mode 100644
index 0000000..c354758
--- /dev/null
+++ b/examples/rule_based_toolchain/dynamic_answer/public/dynamic_answer.h
@@ -0,0 +1,28 @@
+// Copyright 2024 The Bazel Authors. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef DYNAMIC_ANSWER_PUBLIC_DYNAMIC_ANSWER_H_
+#define DYNAMIC_ANSWER_PUBLIC_DYNAMIC_ANSWER_H_
+
+#ifdef __cplusplus
+extern "C" {
+#endif  // __cplusplus
+
+int dynamic_answer(void);
+
+#ifdef __cplusplus
+}  // extern "C"
+#endif  // __cplusplus
+
+#endif  // DYNAMIC_ANSWER_PUBLIC_DYNAMIC_ANSWER_H_
diff --git a/examples/rule_based_toolchain/quick_test.cc b/examples/rule_based_toolchain/quick_test.cc
new file mode 100644
index 0000000..80737dd
--- /dev/null
+++ b/examples/rule_based_toolchain/quick_test.cc
@@ -0,0 +1,26 @@
+// Copyright 2024 The Bazel Authors. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <gtest/gtest.h>
+
+#include "dynamic_answer.h"
+#include "static_answer.h"
+
+TEST(Static, ProperlyLinked) {
+  EXPECT_EQ(static_answer(), 42);
+}
+
+TEST(Dynamic, ProperlyLinked) {
+  EXPECT_EQ(dynamic_answer(), 24);
+}
diff --git a/cc/toolchains/format.bzl b/examples/rule_based_toolchain/static_answer/BUILD.bazel
similarity index 55%
rename from cc/toolchains/format.bzl
rename to examples/rule_based_toolchain/static_answer/BUILD.bazel
index bdbb0c8..3c89a50 100644
--- a/cc/toolchains/format.bzl
+++ b/examples/rule_based_toolchain/static_answer/BUILD.bazel
@@ -11,16 +11,23 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-"""Functions to format arguments for the cc toolchain"""
 
-def format_arg(format, value = None):
-    """Generate metadata to format a variable with a given value.
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
 
-    Args:
-      format: (str) The format string
-      value: (Optional[Label]) The variable to format. Any is used because it can
-        be any representation of a variable.
-    Returns:
-      A struct corresponding to the formatted variable.
-    """
-    return struct(format_type = "format_arg", format = format, value = value)
+licenses(["notice"])
+
+cc_library(
+    name = "answer",
+    srcs = ["static_answer.cc"],
+    hdrs = ["public/static_answer.h"],
+    includes = ["public"],
+    linkstatic = True,
+    visibility = ["//visibility:private"],
+)
+
+# TODO: This should be a cc_static_library when that's supported.
+alias(
+    name = "static_answer",
+    actual = ":answer",
+    visibility = ["//visibility:public"],
+)
diff --git a/examples/rule_based_toolchain/static_answer/public/static_answer.h b/examples/rule_based_toolchain/static_answer/public/static_answer.h
new file mode 100644
index 0000000..a77c8e5
--- /dev/null
+++ b/examples/rule_based_toolchain/static_answer/public/static_answer.h
@@ -0,0 +1,28 @@
+// Copyright 2024 The Bazel Authors. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#ifndef STATIC_ANSWER_PUBLIC_STATIC_ANSWER_H_
+#define STATIC_ANSWER_PUBLIC_STATIC_ANSWER_H_
+
+#ifdef __cplusplus
+extern "C" {
+#endif  // __cplusplus
+
+int static_answer(void);
+
+#ifdef __cplusplus
+}  // extern "C"
+#endif  // __cplusplus
+
+#endif  // STATIC_ANSWER_PUBLIC_STATIC_ANSWER_H_
diff --git a/examples/rule_based_toolchain/static_answer/static_answer.cc b/examples/rule_based_toolchain/static_answer/static_answer.cc
new file mode 100644
index 0000000..4f8a06f
--- /dev/null
+++ b/examples/rule_based_toolchain/static_answer/static_answer.cc
@@ -0,0 +1,19 @@
+// Copyright 2024 The Bazel Authors. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "static_answer.h"
+
+extern "C" int static_answer() {
+    return 42;
+}
diff --git a/examples/rule_based_toolchain/toolchain/BUILD.bazel b/examples/rule_based_toolchain/toolchain/BUILD.bazel
new file mode 100644
index 0000000..58e3540
--- /dev/null
+++ b/examples/rule_based_toolchain/toolchain/BUILD.bazel
@@ -0,0 +1,39 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@rules_cc//cc/toolchains:toolchain.bzl", "cc_toolchain")
+
+licenses(["notice"])
+
+cc_toolchain(
+    name = "host_clang",
+    args = select({
+        "@platforms//os:linux": [
+            "//toolchain/args:linux_sysroot",
+        ],
+        "//conditions:default": [],
+    }) + [
+        "//toolchain/args:no_canonical_prefixes",
+        "//toolchain/args:warnings",
+    ],
+    enabled_features = ["@rules_cc//cc/toolchains/args:experimental_replace_legacy_action_config_features"],
+    known_features = ["@rules_cc//cc/toolchains/args:experimental_replace_legacy_action_config_features"],
+    tool_map = "//toolchain/tools:all_tools",
+)
+
+toolchain(
+    name = "host_cc_toolchain",
+    toolchain = ":host_clang",
+    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
+)
diff --git a/examples/rule_based_toolchain/toolchain/args/BUILD.bazel b/examples/rule_based_toolchain/toolchain/args/BUILD.bazel
new file mode 100644
index 0000000..537c6b2
--- /dev/null
+++ b/examples/rule_based_toolchain/toolchain/args/BUILD.bazel
@@ -0,0 +1,52 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@rules_cc//cc/toolchains:args.bzl", "cc_args")
+load("@rules_cc//cc/toolchains/args:sysroot.bzl", "cc_sysroot")
+
+cc_sysroot(
+    name = "linux_sysroot",
+    data = [
+        "@linux_sysroot//:root",
+        "@linux_sysroot//:usr-include",
+        "@linux_sysroot//:usr-include-x86_64-linux-gnu",
+    ],
+    sysroot = "@linux_sysroot//:root",
+    visibility = ["//visibility:public"],
+)
+
+cc_args(
+    name = "warnings",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:c_compile",
+        "@rules_cc//cc/toolchains/actions:cpp_compile_actions",
+    ],
+    args = [
+        "-Werror",
+        "-Wall",
+        "-Wextra",
+        "-Wpedantic",
+    ],
+    visibility = ["//visibility:public"],
+)
+
+cc_args(
+    name = "no_canonical_prefixes",
+    actions = [
+        "@rules_cc//cc/toolchains/actions:c_compile",
+        "@rules_cc//cc/toolchains/actions:cpp_compile_actions",
+    ],
+    args = ["-no-canonical-prefixes"],
+    visibility = ["//visibility:public"],
+)
diff --git a/examples/rule_based_toolchain/toolchain/clang.BUILD b/examples/rule_based_toolchain/toolchain/clang.BUILD
new file mode 100644
index 0000000..24842da
--- /dev/null
+++ b/examples/rule_based_toolchain/toolchain/clang.BUILD
@@ -0,0 +1,85 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@bazel_skylib//rules/directory:directory.bzl", "directory")
+load("@bazel_skylib//rules/directory:subdirectory.bzl", "subdirectory")
+
+package(default_visibility = ["//visibility:public"])
+
+licenses(["notice"])
+
+exports_files(glob(["bin/**"]))
+
+# Directory-based rules in this toolchain only referece things in
+# lib/ or include/ subdirectories.
+directory(
+    name = "toolchain_root",
+    srcs = glob([
+        "lib/**",
+        "include/**",
+    ]),
+)
+
+subdirectory(
+    name = "include-c++-v1",
+    parent = ":toolchain_root",
+    path = "include/c++/v1",
+)
+
+subdirectory(
+    name = "lib-clang-include",
+    parent = ":toolchain_root",
+    path = "lib/clang/19/include",
+)
+
+subdirectory(
+    name = "include-x86_64-unknown-linux-gnu-c++-v1",
+    parent = ":toolchain_root",
+    path = "include/x86_64-unknown-linux-gnu/c++/v1",
+)
+
+filegroup(
+    name = "builtin_headers",
+    srcs = [
+        ":include-c++-v1",
+        ":include-x86_64-unknown-linux-gnu-c++-v1",
+        ":lib-clang-include",
+    ],
+)
+
+# Various supporting files needed to run the linker.
+filegroup(
+    name = "linker_builtins",
+    data = glob([
+        "bin/lld*",
+        "bin/ld*",
+        "lib/**/*.a",
+        "lib/**/*.so*",
+        "lib/**/*.o",
+    ]) + [
+        ":multicall_support_files",
+    ],
+)
+
+# Some toolchain distributions use busybox-style handling of tools, so things
+# like `clang++` just redirect to a `llvm` binary. This glob catches this
+# binary if it's included in the distribution, and is a no-op if the multicall
+# binary doesn't exist.
+filegroup(
+    name = "multicall_support_files",
+    srcs = glob(
+        ["bin/llvm"],
+        allow_empty = True,
+    ),
+)
diff --git a/examples/rule_based_toolchain/toolchain/linux_sysroot.BUILD b/examples/rule_based_toolchain/toolchain/linux_sysroot.BUILD
new file mode 100644
index 0000000..66ebca7
--- /dev/null
+++ b/examples/rule_based_toolchain/toolchain/linux_sysroot.BUILD
@@ -0,0 +1,37 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@bazel_skylib//rules/directory:directory.bzl", "directory")
+load("@bazel_skylib//rules/directory:subdirectory.bzl", "subdirectory")
+
+package(default_visibility = ["//visibility:public"])
+
+licenses(["notice"])
+
+directory(
+    name = "root",
+    srcs = glob(["**/*"]),
+)
+
+subdirectory(
+    name = "usr-include-x86_64-linux-gnu",
+    parent = ":root",
+    path = "usr/include/x86_64-linux-gnu",
+)
+
+subdirectory(
+    name = "usr-include",
+    parent = ":root",
+    path = "usr/include",
+)
diff --git a/examples/rule_based_toolchain/toolchain/tools/BUILD.bazel b/examples/rule_based_toolchain/toolchain/tools/BUILD.bazel
new file mode 100644
index 0000000..ccd0060
--- /dev/null
+++ b/examples/rule_based_toolchain/toolchain/tools/BUILD.bazel
@@ -0,0 +1,193 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+load("@rules_cc//cc/toolchains:tool.bzl", "cc_tool")
+load("@rules_cc//cc/toolchains:tool_map.bzl", "cc_tool_map")
+
+licenses(["notice"])
+
+# This `select` happens under the target configuration. For macOS,
+# llvm-libtool-darwin should be used when creating static libraries even if the
+# exec platform is linux.
+alias(
+    name = "all_tools",
+    actual = select({
+        "@platforms//os:macos": ":macos_tools",
+        "//conditions:default": ":default_tools",
+    }),
+    visibility = ["//visibility:public"],
+)
+
+COMMON_TOOLS = {
+    "@rules_cc//cc/toolchains/actions:assembly_actions": ":clang",
+    "@rules_cc//cc/toolchains/actions:c_compile": ":clang",
+    "@rules_cc//cc/toolchains/actions:cpp_compile_actions": ":clang++",
+    "@rules_cc//cc/toolchains/actions:link_actions": ":lld",
+    "@rules_cc//cc/toolchains/actions:objcopy_embed_data": ":llvm-objcopy",
+    "@rules_cc//cc/toolchains/actions:strip": ":llvm-strip",
+}
+
+cc_tool_map(
+    name = "default_tools",
+    tools = COMMON_TOOLS | {
+        "@rules_cc//cc/toolchains/actions:ar_actions": ":llvm-ar",
+    },
+    visibility = ["//visibility:private"],
+)
+
+cc_tool_map(
+    name = "macos_tools",
+    tools = COMMON_TOOLS | {
+        "@rules_cc//cc/toolchains/actions:ar_actions": ":llvm-libtool-darwin",
+    },
+    visibility = ["//visibility:private"],
+)
+
+cc_tool(
+    name = "clang",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/clang",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/clang",
+    }),
+    data = [
+        ":exec_platform_builtin_headers",
+        ":exec_platform_multicall_support_files",
+    ],
+)
+
+cc_tool(
+    name = "clang++",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/clang++",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/clang++",
+    }),
+    data = [
+        ":exec_platform_builtin_headers",
+        ":exec_platform_multicall_support_files",
+    ],
+)
+
+cc_tool(
+    name = "lld",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/clang++",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/clang++",
+    }),
+    data = [
+        ":exec_platform_builtin_headers",
+        ":exec_platform_linker_builtins",
+        ":exec_platform_multicall_support_files",
+    ],
+)
+
+cc_tool(
+    name = "llvm-ar",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-ar",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-ar",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "llvm-libtool-darwin",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-libtool-darwin",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-libtool-darwin",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "llvm-objcopy",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-objcopy",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-objcopy",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "llvm-objdump",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-objdump",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-objdump",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "llvm-cov",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-cov",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-cov",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "llvm-strip",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/llvm-strip",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/llvm-strip",
+    }),
+    data = [":exec_platform_multicall_support_files"],
+)
+
+cc_tool(
+    name = "clang-tidy",
+    src = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:bin/clang-tidy",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:bin/clang-tidy",
+    }),
+    data = [
+        ":exec_platform_builtin_headers",
+        ":exec_platform_multicall_support_files",
+    ],
+)
+
+#################################
+#   Platform-specific aliases   #
+#################################
+
+# These aliases are used to reduce duplication of `select` statements throughout
+# this build file. The select statements in these aliases are evaluated under
+# the exec configuration.
+
+alias(
+    name = "exec_platform_builtin_headers",
+    actual = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:builtin_headers",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:builtin_headers",
+    }),
+    visibility = ["//visibility:private"],
+)
+
+alias(
+    name = "exec_platform_multicall_support_files",
+    actual = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:multicall_support_files",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:multicall_support_files",
+    }),
+    visibility = ["//visibility:private"],
+)
+
+alias(
+    name = "exec_platform_linker_builtins",
+    actual = select({
+        "//constraint:linux_aarch64": "@clang-linux-aarch64//:linker_builtins",
+        "//constraint:linux_x86_64": "@clang-linux-x86_64//:linker_builtins",
+    }),
+    visibility = ["//visibility:private"],
+)
diff --git a/examples/write_cc_toolchain_cpu/write_cc_toolchain_cpu.bzl b/examples/write_cc_toolchain_cpu/write_cc_toolchain_cpu.bzl
index 3e93b42..a3015c4 100644
--- a/examples/write_cc_toolchain_cpu/write_cc_toolchain_cpu.bzl
+++ b/examples/write_cc_toolchain_cpu/write_cc_toolchain_cpu.bzl
@@ -14,7 +14,7 @@
 
 """Example showing how to get CcToolchainInfo in a custom rule."""
 
-load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
+load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cpp_toolchain", "use_cc_toolchain")
 
 def _write_cc_toolchain_cpu_impl(ctx):
     cc_toolchain = find_cpp_toolchain(ctx)
@@ -26,7 +26,7 @@ def _write_cc_toolchain_cpu_impl(ctx):
 write_cc_toolchain_cpu = rule(
     implementation = _write_cc_toolchain_cpu_impl,
     attrs = {
-        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
+        "_cc_toolchain": attr.label(default = Label("@rules_cc//cc:current_cc_toolchain")),
     },
-    toolchains = use_cpp_toolchain(),
+    toolchains = use_cc_toolchain(),
 )
diff --git a/tests/compiler_settings/BUILD b/tests/compiler_settings/BUILD
index a377a51..7c6db4a 100644
--- a/tests/compiler_settings/BUILD
+++ b/tests/compiler_settings/BUILD
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("//cc:defs.bzl", "cc_binary")
+load("//cc:cc_binary.bzl", "cc_binary")
 
 licenses(["notice"])
 
diff --git a/tests/load_from_macro/BUILD b/tests/load_from_macro/BUILD
index 93b902a..132703a 100644
--- a/tests/load_from_macro/BUILD
+++ b/tests/load_from_macro/BUILD
@@ -13,7 +13,7 @@
 # limitations under the License.
 
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-load("//cc:defs.bzl", "cc_library")
+load("//cc:cc_library.bzl", "cc_library")
 load(":tags.bzl", "TAGS")
 
 licenses(["notice"])
diff --git a/tests/rule_based_toolchain/action_type_config/BUILD b/tests/rule_based_toolchain/action_type_config/BUILD
deleted file mode 100644
index e7b9194..0000000
--- a/tests/rule_based_toolchain/action_type_config/BUILD
+++ /dev/null
@@ -1,42 +0,0 @@
-load("@rules_testing//lib:util.bzl", "util")
-load("//cc/toolchains:action_type_config.bzl", "cc_action_type_config")
-load("//tests/rule_based_toolchain:analysis_test_suite.bzl", "analysis_test_suite")
-load(":action_type_config_test.bzl", "TARGETS", "TESTS")
-
-util.helper_target(
-    cc_action_type_config,
-    name = "file_map",
-    action_types = ["//tests/rule_based_toolchain/actions:all_compile"],
-    args = ["//tests/rule_based_toolchain/args_list"],
-    data = [
-        "//tests/rule_based_toolchain/testdata:multiple2",
-    ],
-    tools = [
-        "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
-        "//tests/rule_based_toolchain/tool:wrapped_tool",
-    ],
-)
-
-util.helper_target(
-    cc_action_type_config,
-    name = "c_compile_config",
-    action_types = ["//tests/rule_based_toolchain/actions:c_compile"],
-    tools = [
-        "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
-    ],
-)
-
-util.helper_target(
-    cc_action_type_config,
-    name = "cpp_compile_config",
-    action_types = ["//tests/rule_based_toolchain/actions:cpp_compile"],
-    tools = [
-        "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
-    ],
-)
-
-analysis_test_suite(
-    name = "test_suite",
-    targets = TARGETS,
-    tests = TESTS,
-)
diff --git a/tests/rule_based_toolchain/action_type_config/action_type_config_test.bzl b/tests/rule_based_toolchain/action_type_config/action_type_config_test.bzl
deleted file mode 100644
index 7ee85e6..0000000
--- a/tests/rule_based_toolchain/action_type_config/action_type_config_test.bzl
+++ /dev/null
@@ -1,108 +0,0 @@
-# Copyright 2024 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Tests for the action_type_config rule."""
-
-load(
-    "//cc/toolchains:cc_toolchain_info.bzl",
-    "ActionTypeConfigSetInfo",
-    "ActionTypeInfo",
-)
-load("//cc/toolchains/impl:collect.bzl", _collect_action_type_configs = "collect_action_type_config_sets")
-load("//tests/rule_based_toolchain:subjects.bzl", "result_fn_wrapper", "subjects")
-
-visibility("private")
-
-_TOOL_FILES = [
-    "tests/rule_based_toolchain/testdata/bin",
-    "tests/rule_based_toolchain/testdata/bin_wrapper",
-    "tests/rule_based_toolchain/testdata/bin_wrapper.sh",
-]
-_ADDITIONAL_FILES = [
-    "tests/rule_based_toolchain/testdata/multiple2",
-]
-_C_COMPILE_FILES = [
-    "tests/rule_based_toolchain/testdata/file1",
-    "tests/rule_based_toolchain/testdata/multiple1",
-]
-_CPP_COMPILE_FILES = [
-    "tests/rule_based_toolchain/testdata/file2",
-    "tests/rule_based_toolchain/testdata/multiple1",
-]
-
-collect_action_type_configs = result_fn_wrapper(_collect_action_type_configs)
-
-def _files_taken_test(env, targets):
-    configs = env.expect.that_target(targets.file_map).provider(ActionTypeConfigSetInfo).configs()
-    c_compile = configs.get(targets.c_compile[ActionTypeInfo])
-    c_compile.files().contains_exactly(
-        _C_COMPILE_FILES + _TOOL_FILES + _ADDITIONAL_FILES,
-    )
-    c_compile.args().contains_exactly([
-        targets.c_compile_args.label,
-        targets.all_compile_args.label,
-    ])
-
-    cpp_compile = configs.get(targets.cpp_compile[ActionTypeInfo])
-    cpp_compile.files().contains_exactly(
-        _CPP_COMPILE_FILES + _TOOL_FILES + _ADDITIONAL_FILES,
-    )
-    cpp_compile.args().contains_exactly([
-        targets.cpp_compile_args.label,
-        targets.all_compile_args.label,
-    ])
-
-def _merge_distinct_configs_succeeds_test(env, targets):
-    configs = env.expect.that_value(
-        collect_action_type_configs(
-            targets = [targets.c_compile_config, targets.cpp_compile_config],
-            label = env.ctx.label,
-        ),
-        factory = subjects.result(subjects.ActionTypeConfigSetInfo),
-    ).ok().configs()
-    configs.get(targets.c_compile[ActionTypeInfo]).label().equals(
-        targets.c_compile_config.label,
-    )
-    configs.get(targets.cpp_compile[ActionTypeInfo]).label().equals(
-        targets.cpp_compile_config.label,
-    )
-
-def _merge_overlapping_configs_fails_test(env, targets):
-    err = env.expect.that_value(
-        collect_action_type_configs(
-            targets = [targets.file_map, targets.c_compile_config],
-            label = env.ctx.label,
-        ),
-        factory = subjects.result(subjects.ActionTypeConfigSetInfo),
-    ).err()
-    err.contains("//tests/rule_based_toolchain/actions:c_compile is configured by both")
-    err.contains("//tests/rule_based_toolchain/action_type_config:c_compile_config")
-    err.contains("//tests/rule_based_toolchain/action_type_config:file_map")
-
-TARGETS = [
-    ":file_map",
-    ":c_compile_config",
-    ":cpp_compile_config",
-    "//tests/rule_based_toolchain/actions:c_compile",
-    "//tests/rule_based_toolchain/actions:cpp_compile",
-    "//tests/rule_based_toolchain/args_list:c_compile_args",
-    "//tests/rule_based_toolchain/args_list:cpp_compile_args",
-    "//tests/rule_based_toolchain/args_list:all_compile_args",
-    "//tests/rule_based_toolchain/args_list:args_list",
-]
-
-TESTS = {
-    "files_taken_test": _files_taken_test,
-    "merge_distinct_configs_succeeds_test": _merge_distinct_configs_succeeds_test,
-    "merge_overlapping_configs_fails_test": _merge_overlapping_configs_fails_test,
-}
diff --git a/tests/rule_based_toolchain/args/BUILD b/tests/rule_based_toolchain/args/BUILD
index 585ec91..3b8e1ab 100644
--- a/tests/rule_based_toolchain/args/BUILD
+++ b/tests/rule_based_toolchain/args/BUILD
@@ -29,6 +29,14 @@ util.helper_target(
     env = {"BAR": "bar"},
 )
 
+util.helper_target(
+    cc_args,
+    name = "with_dir",
+    actions = ["//tests/rule_based_toolchain/actions:all_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:directory"],
+    args = ["--secret-builtin-include-dir"],
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/rule_based_toolchain/args/args_test.bzl b/tests/rule_based_toolchain/args/args_test.bzl
index fbd4ce9..46ab7f9 100644
--- a/tests/rule_based_toolchain/args/args_test.bzl
+++ b/tests/rule_based_toolchain/args/args_test.bzl
@@ -39,6 +39,7 @@ _SIMPLE_FILES = [
     "tests/rule_based_toolchain/testdata/multiple1",
     "tests/rule_based_toolchain/testdata/multiple2",
 ]
+_TOOL_DIRECTORY = "tests/rule_based_toolchain/testdata"
 
 _CONVERTED_ARGS = subjects.struct(
     flag_sets = subjects.collection,
@@ -99,9 +100,20 @@ def _env_only_test(env, targets):
 
     converted.flag_sets().contains_exactly([])
 
+def _with_dir_test(env, targets):
+    with_dir = env.expect.that_target(targets.with_dir).provider(ArgsInfo)
+    with_dir.allowlist_include_directories().contains_exactly([_TOOL_DIRECTORY])
+    with_dir.files().contains_at_least(_SIMPLE_FILES)
+
+    c_compile = env.expect.that_target(targets.with_dir).provider(ArgsListInfo).by_action().get(
+        targets.c_compile[ActionTypeInfo],
+    )
+    c_compile.files().contains_at_least(_SIMPLE_FILES)
+
 TARGETS = [
     ":simple",
     ":env_only",
+    ":with_dir",
     "//tests/rule_based_toolchain/actions:c_compile",
     "//tests/rule_based_toolchain/actions:cpp_compile",
 ]
@@ -109,5 +121,6 @@ TARGETS = [
 # @unsorted-dict-items
 TESTS = {
     "simple_test": _simple_test,
-    "env_only_test_test": _env_only_test,
+    "env_only_test": _env_only_test,
+    "with_dir_test": _with_dir_test,
 }
diff --git a/tests/rule_based_toolchain/args_list/BUILD b/tests/rule_based_toolchain/args_list/BUILD
index 9fc9f88..64f0fbb 100644
--- a/tests/rule_based_toolchain/args_list/BUILD
+++ b/tests/rule_based_toolchain/args_list/BUILD
@@ -42,6 +42,34 @@ util.helper_target(
     visibility = ["//tests/rule_based_toolchain:__subpackages__"],
 )
 
+util.helper_target(
+    cc_args,
+    name = "args_with_dir_1",
+    actions = ["//tests/rule_based_toolchain/actions:c_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_1"],
+    args = ["dir1"],
+    visibility = ["//tests/rule_based_toolchain:__subpackages__"],
+)
+
+util.helper_target(
+    cc_args,
+    name = "args_with_dir_2",
+    actions = ["//tests/rule_based_toolchain/actions:cpp_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_2"],
+    args = ["dir2"],
+    visibility = ["//tests/rule_based_toolchain:__subpackages__"],
+)
+
+util.helper_target(
+    cc_args_list,
+    name = "args_list_with_dir",
+    args = [
+        ":args_with_dir_1",
+        ":args_with_dir_2",
+    ],
+    visibility = ["//tests/rule_based_toolchain:__subpackages__"],
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/rule_based_toolchain/args_list/args_list_test.bzl b/tests/rule_based_toolchain/args_list/args_list_test.bzl
index 1d37145..c811673 100644
--- a/tests/rule_based_toolchain/args_list/args_list_test.bzl
+++ b/tests/rule_based_toolchain/args_list/args_list_test.bzl
@@ -26,6 +26,20 @@ _C_COMPILE_FILE = "tests/rule_based_toolchain/testdata/file1"
 _CPP_COMPILE_FILE = "tests/rule_based_toolchain/testdata/file2"
 _BOTH_FILE = "tests/rule_based_toolchain/testdata/multiple1"
 
+_TEST_DIR_1 = "tests/rule_based_toolchain/testdata/subdir1"
+_TEST_DIR_2 = "tests/rule_based_toolchain/testdata/subdir2"
+_ALL_TEST_DIRS = [
+    _TEST_DIR_1,
+    _TEST_DIR_2,
+]
+_TEST_DIR_1_FILES = [
+    "tests/rule_based_toolchain/testdata/subdir1/file_foo",
+]
+_TEST_DIR_2_FILES = [
+    "tests/rule_based_toolchain/testdata/subdir2/file_bar",
+]
+_ALL_TEST_DIRS_FILES = _TEST_DIR_1_FILES + _TEST_DIR_2_FILES
+
 def _collect_args_lists_test(env, targets):
     args = env.expect.that_target(targets.args_list).provider(ArgsListInfo)
     args.args().contains_exactly([
@@ -53,15 +67,34 @@ def _collect_args_lists_test(env, targets):
         targets.all_compile_args[ArgsInfo],
     ])
 
+def _collect_args_list_dirs_test(env, targets):
+    args = env.expect.that_target(targets.args_list_with_dir).provider(ArgsListInfo)
+    args.allowlist_include_directories().contains_exactly(_ALL_TEST_DIRS)
+    args.files().contains_exactly(_ALL_TEST_DIRS_FILES)
+
+    c_compile = env.expect.that_target(targets.args_list_with_dir).provider(ArgsListInfo).by_action().get(
+        targets.c_compile[ActionTypeInfo],
+    )
+    c_compile.files().contains_exactly(_TEST_DIR_1_FILES)
+
+    cpp_compile = env.expect.that_target(targets.args_list_with_dir).provider(ArgsListInfo).by_action().get(
+        targets.cpp_compile[ActionTypeInfo],
+    )
+    cpp_compile.files().contains_exactly(_TEST_DIR_2_FILES)
+
 TARGETS = [
     ":c_compile_args",
     ":cpp_compile_args",
     ":all_compile_args",
     ":args_list",
+    ":args_with_dir_1",
+    ":args_with_dir_2",
+    ":args_list_with_dir",
     "//tests/rule_based_toolchain/actions:c_compile",
     "//tests/rule_based_toolchain/actions:cpp_compile",
 ]
 
 TESTS = {
+    "collect_args_list_dirs_test": _collect_args_list_dirs_test,
     "collect_args_lists_test": _collect_args_lists_test,
 }
diff --git a/tests/rule_based_toolchain/features/BUILD b/tests/rule_based_toolchain/features/BUILD
index cc3c0c7..c982318 100644
--- a/tests/rule_based_toolchain/features/BUILD
+++ b/tests/rule_based_toolchain/features/BUILD
@@ -10,7 +10,7 @@ load(":features_test.bzl", "TARGETS", "TESTS")
 
 util.helper_target(
     cc_args,
-    name = "c_compile",
+    name = "c_compile_args",
     actions = ["//tests/rule_based_toolchain/actions:c_compile"],
     args = ["c"],
     data = ["//tests/rule_based_toolchain/testdata:file1"],
@@ -19,8 +19,7 @@ util.helper_target(
 util.helper_target(
     cc_feature,
     name = "simple",
-    args = [":c_compile"],
-    enabled = False,
+    args = [":c_compile_args"],
     feature_name = "feature_name",
     visibility = ["//tests/rule_based_toolchain:__subpackages__"],
 )
@@ -28,8 +27,7 @@ util.helper_target(
 util.helper_target(
     cc_feature,
     name = "simple2",
-    args = [":c_compile"],
-    enabled = False,
+    args = [":c_compile_args"],
     feature_name = "simple2",
 )
 
@@ -45,8 +43,7 @@ util.helper_target(
 util.helper_target(
     cc_feature,
     name = "requires",
-    args = [":c_compile"],
-    enabled = True,
+    args = [":c_compile_args"],
     feature_name = "requires",
     requires_any_of = [":feature_set"],
 )
@@ -54,8 +51,7 @@ util.helper_target(
 util.helper_target(
     cc_feature,
     name = "implies",
-    args = [":c_compile"],
-    enabled = True,
+    args = [":c_compile_args"],
     feature_name = "implies",
     implies = [":simple"],
 )
@@ -67,8 +63,7 @@ cc_mutually_exclusive_category(
 util.helper_target(
     cc_feature,
     name = "mutual_exclusion_feature",
-    args = [":c_compile"],
-    enabled = True,
+    args = [":c_compile_args"],
     feature_name = "mutual_exclusion",
     mutually_exclusive = [
         ":simple",
@@ -104,11 +99,31 @@ util.helper_target(
 util.helper_target(
     cc_feature,
     name = "overrides",
-    args = [":c_compile"],
-    enabled = True,
+    args = [":c_compile_args"],
     overrides = ":builtin_feature",
 )
 
+util.helper_target(
+    cc_feature,
+    name = "sentinel_feature",
+    feature_name = "sentinel_feature_name",
+)
+
+util.helper_target(
+    cc_args,
+    name = "args_with_dir",
+    actions = ["//tests/rule_based_toolchain/actions:c_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_1"],
+    args = ["--include-builtin-dirs"],
+)
+
+util.helper_target(
+    cc_feature,
+    name = "feature_with_dir",
+    args = [":args_with_dir"],
+    feature_name = "feature_with_dir",
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/rule_based_toolchain/features/features_test.bzl b/tests/rule_based_toolchain/features/features_test.bzl
index 2345cd7..a0d479a 100644
--- a/tests/rule_based_toolchain/features/features_test.bzl
+++ b/tests/rule_based_toolchain/features/features_test.bzl
@@ -21,6 +21,7 @@ load(
 )
 load(
     "//cc/toolchains:cc_toolchain_info.bzl",
+    "ActionTypeInfo",
     "ArgsInfo",
     "FeatureConstraintInfo",
     "FeatureInfo",
@@ -36,21 +37,28 @@ load(
 visibility("private")
 
 _C_COMPILE_FILE = "tests/rule_based_toolchain/testdata/file1"
+_SUBDIR1 = "tests/rule_based_toolchain/testdata/subdir1"
+_SUBDIR1_FILES = ["tests/rule_based_toolchain/testdata/subdir1/file_foo"]
+
+def _sentinel_feature_test(env, targets):
+    sentinel_feature = env.expect.that_target(targets.sentinel_feature).provider(FeatureInfo)
+    sentinel_feature.name().equals("sentinel_feature_name")
+    sentinel_feature.args().args().contains_exactly([])
 
 def _simple_feature_test(env, targets):
     simple = env.expect.that_target(targets.simple).provider(FeatureInfo)
     simple.name().equals("feature_name")
-    simple.args().args().contains_exactly([targets.c_compile.label])
+    simple.args().args().contains_exactly([targets.c_compile_args.label])
     simple.enabled().equals(False)
     simple.overrides().is_none()
     simple.overridable().equals(False)
 
     simple.args().files().contains_exactly([_C_COMPILE_FILE])
     c_compile_action = simple.args().by_action().get(
-        targets.c_compile[ArgsInfo].actions.to_list()[0],
+        targets.c_compile_args[ArgsInfo].actions.to_list()[0],
     )
     c_compile_action.files().contains_exactly([_C_COMPILE_FILE])
-    c_compile_action.args().contains_exactly([targets.c_compile[ArgsInfo]])
+    c_compile_action.args().contains_exactly([targets.c_compile_args[ArgsInfo]])
 
     legacy = convert_feature(simple.actual)
     env.expect.that_str(legacy.name).equals("feature_name")
@@ -144,23 +152,37 @@ def _feature_can_be_overridden_test(env, targets):
     overrides.name().equals("builtin_feature")
     overrides.overrides().some().label().equals(targets.builtin_feature.label)
 
+def _feature_with_directory_test(env, targets):
+    with_dir = env.expect.that_target(targets.feature_with_dir).provider(FeatureInfo)
+    with_dir.allowlist_include_directories().contains_exactly([_SUBDIR1])
+
+    c_compile = env.expect.that_target(targets.feature_with_dir).provider(FeatureInfo).args().by_action().get(
+        targets.c_compile[ActionTypeInfo],
+    )
+    c_compile.files().contains_at_least(_SUBDIR1_FILES)
+
 TARGETS = [
+    ":args_with_dir",
     ":builtin_feature",
-    ":c_compile",
+    ":c_compile_args",
     ":category",
     ":direct_constraint",
     ":feature_set",
+    ":feature_with_dir",
     ":implies",
     ":mutual_exclusion_feature",
     ":overrides",
     ":requires",
+    ":sentinel_feature",
     ":simple",
     ":simple2",
     ":transitive_constraint",
+    "//tests/rule_based_toolchain/actions:c_compile",
 ]
 
 # @unsorted-dict-items
 TESTS = {
+    "sentinel_feature_test": _sentinel_feature_test,
     "simple_feature_test": _simple_feature_test,
     "feature_collects_requirements_test": _feature_collects_requirements_test,
     "feature_collects_implies_test": _feature_collects_implies_test,
@@ -170,4 +192,5 @@ TESTS = {
     "feature_constraint_collects_transitive_features_test": _feature_constraint_collects_transitive_features_test,
     "external_feature_is_a_feature_test": _external_feature_is_a_feature_test,
     "feature_can_be_overridden_test": _feature_can_be_overridden_test,
+    "feature_with_directory_test": _feature_with_directory_test,
 }
diff --git a/tests/rule_based_toolchain/generate_factory.bzl b/tests/rule_based_toolchain/generate_factory.bzl
index c58bb51..ea9dc58 100644
--- a/tests/rule_based_toolchain/generate_factory.bzl
+++ b/tests/rule_based_toolchain/generate_factory.bzl
@@ -67,7 +67,7 @@ def generate_factory(type, name, attrs):
             meta.add_failure("Wanted a %s but got" % name, value)
         got_keys = sorted(structs.to_dict(value).keys())
         subjects.collection(got_keys, meta = meta.derive(details = [
-            "Value was not a %s - it has a different set of fields" % name,
+            "Value %r was not a %s - it has a different set of fields" % (value, name),
         ])).contains_exactly(want_keys).in_order()
 
     def type_factory(value, *, meta):
diff --git a/tests/rule_based_toolchain/generics.bzl b/tests/rule_based_toolchain/generics.bzl
index 17bd3a6..505b09e 100644
--- a/tests/rule_based_toolchain/generics.bzl
+++ b/tests/rule_based_toolchain/generics.bzl
@@ -136,4 +136,6 @@ dict_key_subject = lambda factory: lambda value, *, meta: struct(
         value[key],
         meta = meta.derive("get({})".format(key)),
     ),
+    keys = lambda: subjects.collection(value.keys(), meta = meta.derive("keys()")),
+    contains = lambda key: subjects.bool(key in value, meta = meta.derive("contains({})".format(key))),
 )
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/BUILD b/tests/rule_based_toolchain/legacy_features_as_args/BUILD
new file mode 100644
index 0000000..1083f7a
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/BUILD
@@ -0,0 +1,58 @@
+load(":compare_feature.bzl", "compare_feature_implementation")
+
+# These tests validate that the produced legacy feature implementations
+# properly reflect the implementations housed in the Java source of truth at
+# https://github.com/bazelbuild/bazel/blob/master/src/main/java/com/google/devtools/build/lib/rules/cpp/CppActionConfigs.java.
+#
+# Note: the golden textprotos are not a 1:1 match of the textprotos inlined in
+# the Java files. These aim to have identical behavior, but with allowance
+# for slight differences in structure due to implementation details. This also
+# makes it easier to review the final results.
+
+compare_feature_implementation(
+    name = "archiver_flags_test",
+    actual_implementation = "//cc/toolchains/args/archiver_flags",
+    expected = select({
+        "@platforms//os:macos": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/macos/archiver_flags.textproto",
+        "//conditions:default": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/archiver_flags.textproto",
+    }),
+)
+
+compare_feature_implementation(
+    name = "force_pic_flags_test",
+    actual_implementation = "//cc/toolchains/args/force_pic_flags",
+    expected = select({
+        "@platforms//os:macos": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/macos/force_pic_flags.textproto",
+        "//conditions:default": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/force_pic_flags.textproto",
+    }),
+)
+
+compare_feature_implementation(
+    name = "libraries_to_link_test",
+    actual_implementation = "//cc/toolchains/args/libraries_to_link",
+    expected = select({
+        "@platforms//os:macos": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/macos/libraries_to_link.textproto",
+        "//conditions:default": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/libraries_to_link.textproto",
+    }),
+)
+
+compare_feature_implementation(
+    name = "linker_param_file_test",
+    actual_implementation = "//cc/toolchains/args/linker_param_file",
+    expected = "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/linker_param_file.textproto",
+)
+
+compare_feature_implementation(
+    name = "runtime_library_search_directories_test",
+    actual_implementation = "//cc/toolchains/args/runtime_library_search_directories",
+    expected = select({
+        "@platforms//os:macos": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/macos/runtime_library_search_directories.textproto",
+        "//conditions:default": "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/runtime_library_search_directories.textproto",
+    }),
+)
+
+compare_feature_implementation(
+    name = "shared_flag_test",
+    actual_implementation = "//cc/toolchains/args/shared_flag",
+    expected = "//tests/rule_based_toolchain/legacy_features_as_args:goldens/unix/shared_flag.textproto",
+)
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/compare_feature.bzl b/tests/rule_based_toolchain/legacy_features_as_args/compare_feature.bzl
new file mode 100644
index 0000000..10e63a8
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/compare_feature.bzl
@@ -0,0 +1,61 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#    http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Test helper for cc_arg_list validation."""
+
+load("@bazel_skylib//rules:diff_test.bzl", "diff_test")
+load("//cc:cc_toolchain_config_lib.bzl", "feature")
+load("//cc/toolchains:cc_toolchain_info.bzl", "ArgsListInfo")
+load("//cc/toolchains/impl:legacy_converter.bzl", "convert_args")
+
+def _generate_textproto_for_args_impl(ctx):
+    out = ctx.actions.declare_file(ctx.attr.output.name)
+    converted_args = [convert_args(arg) for arg in ctx.attr.actual_implementation[ArgsListInfo].args]
+    feature_impl = feature(
+        name = ctx.attr.feature_name,
+        flag_sets = [fs for one_arg in converted_args for fs in one_arg.flag_sets],
+        env_sets = [es for one_arg in converted_args for es in one_arg.env_sets],
+    )
+    strip_types = [line for line in proto.encode_text(feature_impl).splitlines() if "type_name:" not in line]
+
+    # Ensure trailing newline.
+    strip_types.append("")
+    ctx.actions.write(out, "\n".join(strip_types))
+    return DefaultInfo(files = depset([out]))
+
+_generate_textproto_for_args = rule(
+    implementation = _generate_textproto_for_args_impl,
+    attrs = {
+        "actual_implementation": attr.label(
+            mandatory = True,
+            providers = [ArgsListInfo],
+        ),
+        "feature_name": attr.string(mandatory = True),
+        "output": attr.output(mandatory = True),
+    },
+)
+
+def compare_feature_implementation(name, actual_implementation, expected):
+    output_filename = name + ".actual.textproto"
+    _generate_textproto_for_args(
+        name = name + "_implementation",
+        actual_implementation = actual_implementation,
+        feature_name = name,
+        output = output_filename,
+        testonly = True,
+    )
+    diff_test(
+        name = name,
+        file1 = expected,
+        file2 = output_filename,
+    )
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/archiver_flags.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/archiver_flags.textproto
new file mode 100644
index 0000000..b783c56
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/archiver_flags.textproto
@@ -0,0 +1,40 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    flags: "-static"
+  }
+}
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    expand_if_available: "output_execpath"
+    flags: "-o"
+    flags: "%{output_execpath}"
+  }
+}
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    expand_if_available: "libraries_to_link"
+    flag_groups {
+      flag_groups {
+        expand_if_equal {
+          name: "libraries_to_link.type"
+          value: "object_file"
+        }
+        flags: "%{libraries_to_link.name}"
+      }
+      flag_groups {
+        expand_if_equal {
+          name: "libraries_to_link.type"
+          value: "object_file_group"
+        }
+        flags: "%{libraries_to_link.object_files}"
+        iterate_over: "libraries_to_link.object_files"
+      }
+      iterate_over: "libraries_to_link"
+    }
+  }
+}
+name: "archiver_flags_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/force_pic_flags.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/force_pic_flags.textproto
new file mode 100644
index 0000000..c18413b
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/force_pic_flags.textproto
@@ -0,0 +1,10 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-executable"
+  actions: "lto-index-for-executable"
+  flag_groups {
+    expand_if_available: "force_pic"
+    flags: "-Wl,-pie"
+  }
+}
+name: "force_pic_flags_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/libraries_to_link.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/libraries_to_link.textproto
new file mode 100644
index 0000000..7144d7f
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/libraries_to_link.textproto
@@ -0,0 +1,123 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    flag_groups {
+      expand_if_available: "thinlto_param_file"
+      flags: "-Wl,@%{thinlto_param_file}"
+    }
+    flag_groups {
+      expand_if_available: "libraries_to_link"
+      flag_groups {
+        flag_groups {
+          expand_if_equal {
+            name: "libraries_to_link.type"
+            value: "object_file_group"
+          }
+          flag_groups {
+            expand_if_false: "libraries_to_link.is_whole_archive"
+            flags: "-Wl,--start-lib"
+          }
+        }
+        flag_groups {
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "object_file_group"
+            }
+            flag_groups {
+              flag_groups {
+                expand_if_true: "libraries_to_link.is_whole_archive"
+                flags: "-Wl,-force_load,%{libraries_to_link.object_files}"
+              }
+              flag_groups {
+                expand_if_false: "libraries_to_link.is_whole_archive"
+                flags: "%{libraries_to_link.object_files}"
+              }
+            }
+            iterate_over: "libraries_to_link.object_files"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "object_file"
+            }
+            flag_groups {
+              flag_groups {
+                expand_if_true: "libraries_to_link.is_whole_archive"
+                flags: "-Wl,-force_load,%{libraries_to_link.name}"
+              }
+              flag_groups {
+                expand_if_false: "libraries_to_link.is_whole_archive"
+                flags: "%{libraries_to_link.name}"
+              }
+            }
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "interface_library"
+            }
+            flag_groups {
+              flag_groups {
+                expand_if_true: "libraries_to_link.is_whole_archive"
+                flags: "-Wl,-force_load,%{libraries_to_link.name}"
+              }
+              flag_groups {
+                expand_if_false: "libraries_to_link.is_whole_archive"
+                flags: "%{libraries_to_link.name}"
+              }
+            }
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "static_library"
+            }
+            flag_groups {
+              flag_groups {
+                expand_if_true: "libraries_to_link.is_whole_archive"
+                flags: "-Wl,-force_load,%{libraries_to_link.name}"
+              }
+              flag_groups {
+                expand_if_false: "libraries_to_link.is_whole_archive"
+                flags: "%{libraries_to_link.name}"
+              }
+            }
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "dynamic_library"
+            }
+            flags: "-l%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "versioned_dynamic_library"
+            }
+            flags: "%{libraries_to_link.path}"
+          }
+        }
+        flag_groups {
+          expand_if_equal {
+            name: "libraries_to_link.type"
+            value: "object_file_group"
+          }
+          flag_groups {
+            expand_if_false: "libraries_to_link.is_whole_archive"
+            flags: "-Wl,--end-lib"
+          }
+        }
+        iterate_over: "libraries_to_link"
+      }
+    }
+  }
+}
+name: "libraries_to_link_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/runtime_library_search_directories.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/runtime_library_search_directories.textproto
new file mode 100644
index 0000000..520de8e
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/macos/runtime_library_search_directories.textproto
@@ -0,0 +1,54 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    expand_if_available: "runtime_library_search_directories"
+    flag_groups {
+      flag_groups {
+        expand_if_true: "is_cc_test"
+        flags: "-Xlinker"
+        flags: "-rpath"
+        flags: "-Xlinker"
+        flags: "$EXEC_ORIGIN/%{runtime_library_search_directories}"
+      }
+      flag_groups {
+        expand_if_false: "is_cc_test"
+        flags: "-Xlinker"
+        flags: "-rpath"
+        flags: "-Xlinker"
+        flags: "@loader_path/%{runtime_library_search_directories}"
+      }
+      iterate_over: "runtime_library_search_directories"
+    }
+  }
+  with_features {
+    features: "static_link_cpp_runtimes"
+  }
+}
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    expand_if_available: "runtime_library_search_directories"
+    flag_groups {
+      flags: "-Xlinker"
+      flags: "-rpath"
+      flags: "-Xlinker"
+      flags: "@loader_path/%{runtime_library_search_directories}"
+      iterate_over: "runtime_library_search_directories"
+    }
+  }
+  with_features {
+    not_features: "static_link_cpp_runtimes"
+  }
+}
+name: "runtime_library_search_directories_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/archiver_flags.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/archiver_flags.textproto
new file mode 100644
index 0000000..a1944bb
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/archiver_flags.textproto
@@ -0,0 +1,39 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    flags: "rcsD"
+  }
+}
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    expand_if_available: "output_execpath"
+    flags: "%{output_execpath}"
+  }
+}
+flag_sets {
+  actions: "c++-link-static-library"
+  flag_groups {
+    expand_if_available: "libraries_to_link"
+    flag_groups {
+      flag_groups {
+        expand_if_equal {
+          name: "libraries_to_link.type"
+          value: "object_file"
+        }
+        flags: "%{libraries_to_link.name}"
+      }
+      flag_groups {
+        expand_if_equal {
+          name: "libraries_to_link.type"
+          value: "object_file_group"
+        }
+        flags: "%{libraries_to_link.object_files}"
+        iterate_over: "libraries_to_link.object_files"
+      }
+      iterate_over: "libraries_to_link"
+    }
+  }
+}
+name: "archiver_flags_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/force_pic_flags.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/force_pic_flags.textproto
new file mode 100644
index 0000000..d8e2ebf
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/force_pic_flags.textproto
@@ -0,0 +1,10 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-executable"
+  actions: "lto-index-for-executable"
+  flag_groups {
+    expand_if_available: "force_pic"
+    flags: "-pie"
+  }
+}
+name: "force_pic_flags_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/libraries_to_link.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/libraries_to_link.textproto
new file mode 100644
index 0000000..80f0562
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/libraries_to_link.textproto
@@ -0,0 +1,107 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    flag_groups {
+      expand_if_available: "thinlto_param_file"
+      flags: "-Wl,@%{thinlto_param_file}"
+    }
+    flag_groups {
+      expand_if_available: "libraries_to_link"
+      flag_groups {
+        flag_groups {
+          expand_if_equal {
+            name: "libraries_to_link.type"
+            value: "object_file_group"
+          }
+          flag_groups {
+            expand_if_false: "libraries_to_link.is_whole_archive"
+            flags: "-Wl,--start-lib"
+          }
+        }
+        flag_groups {
+          flag_groups {
+            expand_if_true: "libraries_to_link.is_whole_archive"
+            flag_groups {
+              expand_if_equal {
+                name: "libraries_to_link.type"
+                value: "static_library"
+              }
+              flags: "-Wl,-whole-archive"
+            }
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "object_file_group"
+            }
+            flags: "%{libraries_to_link.object_files}"
+            iterate_over: "libraries_to_link.object_files"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "object_file"
+            }
+            flags: "%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "interface_library"
+            }
+            flags: "%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "static_library"
+            }
+            flags: "%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "dynamic_library"
+            }
+            flags: "-l%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_equal {
+              name: "libraries_to_link.type"
+              value: "versioned_dynamic_library"
+            }
+            flags: "-l:%{libraries_to_link.name}"
+          }
+          flag_groups {
+            expand_if_true: "libraries_to_link.is_whole_archive"
+            flag_groups {
+              expand_if_equal {
+                name: "libraries_to_link.type"
+                value: "static_library"
+              }
+              flags: "-Wl,-no-whole-archive"
+            }
+          }
+        }
+        flag_groups {
+          expand_if_equal {
+            name: "libraries_to_link.type"
+            value: "object_file_group"
+          }
+          flag_groups {
+            expand_if_false: "libraries_to_link.is_whole_archive"
+            flags: "-Wl,--end-lib"
+          }
+        }
+        iterate_over: "libraries_to_link"
+      }
+    }
+  }
+}
+name: "libraries_to_link_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/linker_param_file.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/linker_param_file.textproto
new file mode 100644
index 0000000..d20b60b
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/linker_param_file.textproto
@@ -0,0 +1,15 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "c++-link-static-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    expand_if_available: "linker_param_file"
+    flags: "@%{linker_param_file}"
+  }
+}
+name: "linker_param_file_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/runtime_library_search_directories.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/runtime_library_search_directories.textproto
new file mode 100644
index 0000000..8618b47
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/runtime_library_search_directories.textproto
@@ -0,0 +1,54 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    expand_if_available: "runtime_library_search_directories"
+    flag_groups {
+      flag_groups {
+        expand_if_true: "is_cc_test"
+        flags: "-Xlinker"
+        flags: "-rpath"
+        flags: "-Xlinker"
+        flags: "$EXEC_ORIGIN/%{runtime_library_search_directories}"
+      }
+      flag_groups {
+        expand_if_false: "is_cc_test"
+        flags: "-Xlinker"
+        flags: "-rpath"
+        flags: "-Xlinker"
+        flags: "$ORIGIN/%{runtime_library_search_directories}"
+      }
+      iterate_over: "runtime_library_search_directories"
+    }
+  }
+  with_features {
+    features: "static_link_cpp_runtimes"
+  }
+}
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-executable"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-executable"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    expand_if_available: "runtime_library_search_directories"
+    flag_groups {
+      flags: "-Xlinker"
+      flags: "-rpath"
+      flags: "-Xlinker"
+      flags: "$ORIGIN/%{runtime_library_search_directories}"
+      iterate_over: "runtime_library_search_directories"
+    }
+  }
+  with_features {
+    not_features: "static_link_cpp_runtimes"
+  }
+}
+name: "runtime_library_search_directories_test"
diff --git a/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/shared_flag.textproto b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/shared_flag.textproto
new file mode 100644
index 0000000..51b6868
--- /dev/null
+++ b/tests/rule_based_toolchain/legacy_features_as_args/goldens/unix/shared_flag.textproto
@@ -0,0 +1,11 @@
+enabled: false
+flag_sets {
+  actions: "c++-link-dynamic-library"
+  actions: "c++-link-nodeps-dynamic-library"
+  actions: "lto-index-for-dynamic-library"
+  actions: "lto-index-for-nodeps-dynamic-library"
+  flag_groups {
+    flags: "-shared"
+  }
+}
+name: "shared_flag_test"
diff --git a/tests/rule_based_toolchain/nested_args/BUILD b/tests/rule_based_toolchain/nested_args/BUILD
index 30e75ed..491ed0b 100644
--- a/tests/rule_based_toolchain/nested_args/BUILD
+++ b/tests/rule_based_toolchain/nested_args/BUILD
@@ -7,6 +7,11 @@ cc_variable(
     type = types.string,
 )
 
+cc_variable(
+    name = "my_list",
+    type = types.list(types.string),
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/rule_based_toolchain/nested_args/nested_args_test.bzl b/tests/rule_based_toolchain/nested_args/nested_args_test.bzl
index 96a361c..bcb30dc 100644
--- a/tests/rule_based_toolchain/nested_args/nested_args_test.bzl
+++ b/tests/rule_based_toolchain/nested_args/nested_args_test.bzl
@@ -13,19 +13,16 @@
 # limitations under the License.
 """Tests for the cc_args rule."""
 
+load("@bazel_skylib//rules/directory:providers.bzl", "DirectoryInfo")
 load("//cc:cc_toolchain_config_lib.bzl", "flag_group", "variable_with_value")
-load("//cc/toolchains:cc_toolchain_info.bzl", "VariableInfo")
-load("//cc/toolchains:format.bzl", "format_arg")
 load(
     "//cc/toolchains/impl:nested_args.bzl",
     "FORMAT_ARGS_ERR",
     "REQUIRES_EQUAL_ERR",
     "REQUIRES_MUTUALLY_EXCLUSIVE_ERR",
     "REQUIRES_NONE_ERR",
-    "format_string_indexes",
-    "format_variable",
+    "format_args",
     "nested_args_provider",
-    "raw_string",
 )
 load("//tests/rule_based_toolchain:subjects.bzl", "result_fn_wrapper", "subjects")
 
@@ -41,83 +38,101 @@ def _expect_that_nested(env, expr = None, **kwargs):
         factory = subjects.result(subjects.NestedArgsInfo),
     )
 
-def _expect_that_formatted(env, var, iterate_over = None, expr = None):
+def _expect_that_formatted(env, args, format, must_use = [], expr = None):
     return env.expect.that_value(
-        result_fn_wrapper(format_variable)(var, iterate_over),
-        factory = subjects.result(subjects.str),
-        expr = expr or "format_variable(var=%r, iterate_over=%r" % (var, iterate_over),
-    )
-
-def _expect_that_format_string_indexes(env, var, expr = None):
-    return env.expect.that_value(
-        result_fn_wrapper(format_string_indexes)(var),
+        result_fn_wrapper(format_args)(args, format, must_use = must_use),
         factory = subjects.result(subjects.collection),
-        expr = expr or "format_string_indexes(%r)" % var,
+        expr = expr or "format_args(%r, %r)" % (args, format),
     )
 
-def _format_string_indexes_test(env, _):
-    _expect_that_format_string_indexes(env, "foo").ok().contains_exactly([])
-    _expect_that_format_string_indexes(env, "%%").ok().contains_exactly([])
-    _expect_that_format_string_indexes(env, "%").err().equals(
-        '% should always either of the form %s, or escaped with %%. Instead, got "%"',
-    )
-    _expect_that_format_string_indexes(env, "%a").err().equals(
-        '% should always either of the form %s, or escaped with %%. Instead, got "%a"',
-    )
-    _expect_that_format_string_indexes(env, "%s").ok().contains_exactly([0])
-    _expect_that_format_string_indexes(env, "%%%s%s").ok().contains_exactly([2, 4])
-    _expect_that_format_string_indexes(env, "%%{").ok().contains_exactly([])
-    _expect_that_format_string_indexes(env, "%%s").ok().contains_exactly([])
-    _expect_that_format_string_indexes(env, "%{foo}").err().equals(
-        'Using the old mechanism for variables, %{variable}, but we instead use format_arg("--foo=%s", "//cc/toolchains/variables:<variable>"). Got "%{foo}"',
-    )
+def _format_args_test(env, targets):
+    _expect_that_formatted(
+        env,
+        [
+            "a % b",
+            "a {{",
+            "}} b",
+            "a {{ b }}",
+        ],
+        {},
+    ).ok().contains_exactly([
+        "a %% b",
+        "a {",
+        "} b",
+        "a { b }",
+    ]).in_order()
 
-def _formats_raw_strings_test(env, _):
     _expect_that_formatted(
         env,
-        raw_string("foo"),
-    ).ok().equals("foo")
+        ["{foo"],
+        {},
+    ).err().equals('Unmatched { in "{foo"')
+
     _expect_that_formatted(
         env,
-        raw_string("%s"),
-    ).err().contains("Can't use %s with a raw string. Either escape it with %%s or use format_arg")
+        ["foo}"],
+        {},
+    ).err().equals('Unexpected } in "foo}"')
+    _expect_that_formatted(
+        env,
+        ["{foo}"],
+        {},
+    ).err().contains('Unknown variable "foo" in format string "{foo}"')
 
-def _formats_variables_test(env, targets):
     _expect_that_formatted(
         env,
-        format_arg("ab %s cd", targets.foo[VariableInfo]),
-    ).ok().equals("ab %{foo} cd")
+        [
+            "a {var}",
+            "b {directory}",
+            "c {file}",
+        ],
+        {
+            "directory": targets.directory,
+            "file": targets.bin_wrapper,
+            "var": targets.foo,
+        },
+    ).ok().contains_exactly([
+        "a %{foo}",
+        "b " + targets.directory[DirectoryInfo].path,
+        "c " + targets.bin_wrapper[DefaultInfo].files.to_list()[0].path,
+    ]).in_order()
 
     _expect_that_formatted(
         env,
-        format_arg("foo", targets.foo[VariableInfo]),
-    ).err().equals('format_arg requires a "%s" in the format string, but got "foo"')
+        ["{var}", "{var}"],
+        {"var": targets.foo},
+    ).ok().contains_exactly(["%{foo}", "%{foo}"])
+
     _expect_that_formatted(
         env,
-        format_arg("%s%s", targets.foo[VariableInfo]),
-    ).err().equals('Only one %s can be used in a format string, but got "%s%s"')
+        [],
+        {"var": targets.foo},
+        must_use = ["var"],
+    ).err().contains('"var" was not used')
 
     _expect_that_formatted(
         env,
-        format_arg("%s"),
-        iterate_over = "foo",
-    ).ok().equals("%{foo}")
+        ["{var} {var}"],
+        {"var": targets.foo},
+    ).err().contains('"{var} {var}" contained multiple variables')
+
     _expect_that_formatted(
         env,
-        format_arg("%s"),
-    ).err().contains("format_arg requires either a variable to format, or iterate_over must be provided")
+        ["{foo} {bar}"],
+        {"bar": targets.foo, "foo": targets.foo},
+    ).err().contains('"{foo} {bar}" contained multiple variables')
 
-def _iterate_over_test(env, _):
+def _iterate_over_test(env, targets):
     inner = _expect_that_nested(
         env,
-        args = [raw_string("--foo")],
+        args = ["--foo"],
     ).ok().actual
     env.expect.that_str(inner.legacy_flag_group).equals(flag_group(flags = ["--foo"]))
 
     nested = _expect_that_nested(
         env,
         nested = [inner],
-        iterate_over = "my_list",
+        iterate_over = targets.my_list,
     ).ok()
     nested.iterate_over().some().equals("my_list")
     nested.legacy_flag_group().equals(flag_group(
@@ -131,14 +146,14 @@ def _requires_types_test(env, targets):
         env,
         requires_not_none = "abc",
         requires_none = "def",
-        args = [raw_string("--foo")],
+        args = ["--foo"],
         expr = "mutually_exclusive",
     ).err().equals(REQUIRES_MUTUALLY_EXCLUSIVE_ERR)
 
     _expect_that_nested(
         env,
         requires_none = "var",
-        args = [raw_string("--foo")],
+        args = ["--foo"],
         expr = "requires_none",
     ).ok().requires_types().contains_exactly(
         {"var": [struct(
@@ -150,13 +165,8 @@ def _requires_types_test(env, targets):
 
     _expect_that_nested(
         env,
-        args = [raw_string("foo %s baz")],
-        expr = "no_variable",
-    ).err().contains("Can't use %s with a raw string")
-
-    _expect_that_nested(
-        env,
-        args = [format_arg("foo %s baz", targets.foo[VariableInfo])],
+        args = ["foo {foo} baz"],
+        format = {targets.foo: "foo"},
         expr = "type_validation",
     ).ok().requires_types().contains_exactly(
         {"foo": [struct(
@@ -170,7 +180,8 @@ def _requires_types_test(env, targets):
         env,
         requires_equal = "foo",
         requires_equal_value = "value",
-        args = [format_arg("--foo=%s", targets.foo[VariableInfo])],
+        args = ["--foo={foo}"],
+        format = {targets.foo: "foo"},
         expr = "type_and_requires_equal_validation",
     ).ok()
     nested.requires_types().contains_exactly(
@@ -194,12 +205,13 @@ def _requires_types_test(env, targets):
 
 TARGETS = [
     ":foo",
+    ":my_list",
+    "//tests/rule_based_toolchain/testdata:directory",
+    "//tests/rule_based_toolchain/testdata:bin_wrapper",
 ]
 
 TESTS = {
-    "format_string_indexes_test": _format_string_indexes_test,
-    "formats_raw_strings_test": _formats_raw_strings_test,
-    "formats_variables_test": _formats_variables_test,
+    "format_args_test": _format_args_test,
     "iterate_over_test": _iterate_over_test,
     "requires_types_test": _requires_types_test,
 }
diff --git a/tests/rule_based_toolchain/subjects.bzl b/tests/rule_based_toolchain/subjects.bzl
index f42d5d7..be36b1c 100644
--- a/tests/rule_based_toolchain/subjects.bzl
+++ b/tests/rule_based_toolchain/subjects.bzl
@@ -17,8 +17,6 @@ load("@bazel_skylib//lib:structs.bzl", "structs")
 load("@rules_testing//lib:truth.bzl", _subjects = "subjects")
 load(
     "//cc/toolchains:cc_toolchain_info.bzl",
-    "ActionTypeConfigInfo",
-    "ActionTypeConfigSetInfo",
     "ActionTypeInfo",
     "ActionTypeSetInfo",
     "ArgsInfo",
@@ -28,6 +26,8 @@ load(
     "FeatureSetInfo",
     "MutuallyExclusiveCategoryInfo",
     "NestedArgsInfo",
+    "ToolCapabilityInfo",
+    "ToolConfigInfo",
     "ToolInfo",
     "ToolchainConfigInfo",
 )
@@ -44,6 +44,10 @@ runfiles_subject = lambda value, meta: _subjects.depset_file(value.files, meta =
 # type.
 unknown_subject = _subjects.str
 
+# Directory depsets are quite complex, so just simplify them as a list of paths.
+# buildifier: disable=name-conventions
+_FakeDirectoryDepset = lambda value, *, meta: _subjects.collection([v.path for v in value.to_list()], meta = meta)
+
 # buildifier: disable=name-conventions
 _ActionTypeFactory = generate_factory(
     ActionTypeInfo,
@@ -79,6 +83,7 @@ _FEATURE_FLAGS = dict(
     overridable = _subjects.bool,
     external = _subjects.bool,
     overrides = None,
+    allowlist_include_directories = _FakeDirectoryDepset,
 )
 
 # Break the dependency loop.
@@ -142,6 +147,7 @@ _ArgsFactory = generate_factory(
         # Use .factory so it's not inlined.
         nested = optional_subject(_NestedArgsFactory.factory),
         requires_any_of = ProviderSequence(_FeatureConstraintFactory),
+        allowlist_include_directories = _FakeDirectoryDepset,
     ),
 )
 
@@ -156,6 +162,7 @@ _ArgsListFactory = generate_factory(
             files = _subjects.depset_file,
         ))({value.action: value for value in values}, meta = meta),
         files = _subjects.depset_file,
+        allowlist_include_directories = _FakeDirectoryDepset,
     ),
 )
 
@@ -172,6 +179,15 @@ _FeatureFactory = generate_factory(
     ),
 )
 
+# buildifier: disable=name-conventions
+_ToolCapabilityFactory = generate_factory(
+    ToolCapabilityInfo,
+    "ToolCapabilityInfo",
+    dict(
+        name = _subjects.str,
+    ),
+)
+
 # buildifier: disable=name-conventions
 _ToolFactory = generate_factory(
     ToolInfo,
@@ -179,30 +195,18 @@ _ToolFactory = generate_factory(
     dict(
         exe = _subjects.file,
         runfiles = runfiles_subject,
-        requires_any_of = ProviderSequence(_FeatureConstraintFactory),
         execution_requirements = _subjects.collection,
+        allowlist_include_directories = _FakeDirectoryDepset,
+        capabilities = ProviderSequence(_ToolCapabilityFactory),
     ),
 )
 
 # buildifier: disable=name-conventions
-_ActionTypeConfigFactory = generate_factory(
-    ActionTypeConfigInfo,
-    "ActionTypeConfigInfo",
-    dict(
-        action_type = _ActionTypeFactory,
-        tools = ProviderSequence(_ToolFactory),
-        args = ProviderSequence(_ArgsFactory),
-        implies = ProviderDepset(_FeatureFactory),
-        files = runfiles_subject,
-    ),
-)
-
-# buildifier: disable=name-conventions
-_ActionTypeConfigSetFactory = generate_factory(
-    ActionTypeConfigSetInfo,
-    "ActionTypeConfigSetInfo",
+_ToolConfigFactory = generate_factory(
+    ToolConfigInfo,
+    "ToolConfigInfo",
     dict(
-        configs = dict_key_subject(_ActionTypeConfigFactory.factory),
+        configs = dict_key_subject(_ToolFactory.factory),
     ),
 )
 
@@ -212,9 +216,11 @@ _ToolchainConfigFactory = generate_factory(
     "ToolchainConfigInfo",
     dict(
         features = ProviderDepset(_FeatureFactory),
-        action_type_configs = dict_key_subject(_ActionTypeConfigFactory.factory),
+        enabled_features = _subjects.collection,
+        tool_map = optional_subject(_ToolConfigFactory.factory),
         args = ProviderSequence(_ArgsFactory),
         files = dict_key_subject(_subjects.depset_file),
+        allowlist_include_directories = _FakeDirectoryDepset,
     ),
 )
 
@@ -229,7 +235,7 @@ FACTORIES = [
     _FeatureConstraintFactory,
     _FeatureSetFactory,
     _ToolFactory,
-    _ActionTypeConfigSetFactory,
+    _ToolConfigFactory,
     _ToolchainConfigFactory,
 ]
 
diff --git a/tests/rule_based_toolchain/testdata/BUILD b/tests/rule_based_toolchain/testdata/BUILD
index 4bfb3e6..876834a 100644
--- a/tests/rule_based_toolchain/testdata/BUILD
+++ b/tests/rule_based_toolchain/testdata/BUILD
@@ -1,7 +1,35 @@
 load("@bazel_skylib//rules:native_binary.bzl", "native_binary")
+load("@bazel_skylib//rules/directory:directory.bzl", "directory")
+load("@bazel_skylib//rules/directory:subdirectory.bzl", "subdirectory")
 
 package(default_visibility = ["//tests/rule_based_toolchain:__subpackages__"])
 
+directory(
+    name = "directory",
+    srcs = glob(
+        ["**"],
+        exclude = ["BUILD"],
+    ),
+)
+
+subdirectory(
+    name = "subdirectory_1",
+    parent = ":directory",
+    path = "subdir1",
+)
+
+subdirectory(
+    name = "subdirectory_2",
+    parent = ":directory",
+    path = "subdir2",
+)
+
+subdirectory(
+    name = "subdirectory_3",
+    parent = ":directory",
+    path = "subdir3",
+)
+
 exports_files(
     glob(
         ["*"],
@@ -30,3 +58,10 @@ filegroup(
     name = "bin_filegroup",
     srcs = ["bin"],
 )
+
+# Analysis_test is unable to depend on source files directly, but it can depend
+# on a filegroup containing a single file.
+filegroup(
+    name = "bin_wrapper_filegroup",
+    srcs = ["bin_wrapper.sh"],
+)
diff --git a/tests/rule_based_toolchain/testdata/subdir1/file_foo b/tests/rule_based_toolchain/testdata/subdir1/file_foo
new file mode 100644
index 0000000..e69de29
diff --git a/tests/rule_based_toolchain/testdata/subdir2/file_bar b/tests/rule_based_toolchain/testdata/subdir2/file_bar
new file mode 100644
index 0000000..e69de29
diff --git a/tests/rule_based_toolchain/testdata/subdir3/file_baz b/tests/rule_based_toolchain/testdata/subdir3/file_baz
new file mode 100644
index 0000000..e69de29
diff --git a/tests/rule_based_toolchain/testing_rules.bzl b/tests/rule_based_toolchain/testing_rules.bzl
new file mode 100644
index 0000000..0e0968f
--- /dev/null
+++ b/tests/rule_based_toolchain/testing_rules.bzl
@@ -0,0 +1,48 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Helpers for creating tests for the rule based toolchain."""
+
+load("@rules_testing//lib:analysis_test.bzl", _analysis_test = "analysis_test")
+load("@rules_testing//lib:truth.bzl", "matching")
+load("@rules_testing//lib:util.bzl", "util")
+load(":subjects.bzl", "FACTORIES")
+
+visibility("//tests/rule_based_toolchain/...")
+
+helper_target = util.helper_target
+
+def analysis_test(*, name, **kwargs):
+    """An analysis test for the toolchain rules.
+
+    Args:
+      name: (str) The name of the test suite.
+      **kwargs: Kwargs to be passed to rules_testing's analysis_test.
+    """
+
+    _analysis_test(
+        name = name,
+        provider_subject_factories = FACTORIES,
+        **kwargs
+    )
+
+def expect_failure_test(*, name, target, failure_message):
+    def _impl(env, target):
+        env.expect.that_target(target).failures().contains_predicate(matching.contains(failure_message))
+
+    _analysis_test(
+        name = name,
+        expect_failure = True,
+        impl = _impl,
+        target = target,
+    )
diff --git a/tests/rule_based_toolchain/tool/BUILD b/tests/rule_based_toolchain/tool/BUILD
index d16ded6..daa617a 100644
--- a/tests/rule_based_toolchain/tool/BUILD
+++ b/tests/rule_based_toolchain/tool/BUILD
@@ -1,24 +1,37 @@
-load("@rules_testing//lib:util.bzl", "util")
+load("//cc/toolchains:directory_tool.bzl", "cc_directory_tool")
 load("//cc/toolchains:tool.bzl", "cc_tool")
 load("//tests/rule_based_toolchain:analysis_test_suite.bzl", "analysis_test_suite")
 load(":tool_test.bzl", "TARGETS", "TESTS")
 
-util.helper_target(
-    cc_tool,
+cc_tool(
     name = "tool",
     src = "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
+    capabilities = ["//cc/toolchains/capabilities:supports_pic"],
     data = ["//tests/rule_based_toolchain/testdata:bin"],
-    execution_requirements = ["requires-network"],
-    requires_any_of = ["//tests/rule_based_toolchain/features:direct_constraint"],
+    tags = ["requires-network"],
 )
 
-util.helper_target(
-    cc_tool,
+cc_tool(
     name = "wrapped_tool",
     src = "//tests/rule_based_toolchain/testdata:bin_wrapper",
     visibility = ["//tests/rule_based_toolchain:__subpackages__"],
 )
 
+cc_tool(
+    name = "tool_with_allowlist_include_directories",
+    src = "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:directory"],
+    visibility = ["//tests/rule_based_toolchain:__subpackages__"],
+)
+
+cc_directory_tool(
+    name = "directory_tool",
+    data = ["bin"],
+    directory = "//tests/rule_based_toolchain/testdata:directory",
+    executable = "bin_wrapper.sh",
+    tags = ["requires-network"],
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/rule_based_toolchain/tool/tool_test.bzl b/tests/rule_based_toolchain/tool/tool_test.bzl
index 8e9b68a..ebc5164 100644
--- a/tests/rule_based_toolchain/tool/tool_test.bzl
+++ b/tests/rule_based_toolchain/tool/tool_test.bzl
@@ -13,10 +13,6 @@
 # limitations under the License.
 """Tests for the cc_args rule."""
 
-load(
-    "//cc:cc_toolchain_config_lib.bzl",
-    legacy_with_feature_set = "with_feature_set",
-)
 load("//cc/toolchains:cc_toolchain_info.bzl", "ToolInfo")
 load("//cc/toolchains/impl:collect.bzl", _collect_tools = "collect_tools")
 load("//cc/toolchains/impl:legacy_converter.bzl", "convert_tool")
@@ -36,26 +32,22 @@ tool_result = subjects.result(subjects.ToolInfo)
 _BIN_WRAPPER_SYMLINK = "tests/rule_based_toolchain/testdata/bin_wrapper"
 _BIN_WRAPPER = "tests/rule_based_toolchain/testdata/bin_wrapper.sh"
 _BIN = "tests/rule_based_toolchain/testdata/bin"
+_FILE1 = "tests/rule_based_toolchain/testdata/file1"
+_TOOL_DIRECTORY = "tests/rule_based_toolchain/testdata"
 
-def _tool_test(env, targets):
-    tool = env.expect.that_target(targets.tool).provider(ToolInfo)
+def _tool_test(env, target):
+    tool = env.expect.that_target(target).provider(ToolInfo)
     tool.exe().short_path_equals(_BIN_WRAPPER)
     tool.execution_requirements().contains_exactly(["requires-network"])
     tool.runfiles().contains_exactly([
         _BIN_WRAPPER,
         _BIN,
     ])
-    tool.requires_any_of().contains_exactly([targets.direct_constraint.label])
 
     legacy = convert_tool(tool.actual)
     env.expect.that_file(legacy.tool).equals(tool.actual.exe)
     env.expect.that_collection(legacy.execution_requirements).contains_exactly(["requires-network"])
-    env.expect.that_collection(legacy.with_features).contains_exactly([
-        legacy_with_feature_set(
-            features = ["feature_name"],
-            not_features = ["simple2"],
-        ),
-    ])
+    env.expect.that_collection(legacy.with_features).contains_exactly([])
 
 def _wrapped_tool_includes_runfiles_test(env, targets):
     tool = env.expect.that_target(targets.wrapped_tool).provider(ToolInfo)
@@ -65,6 +57,14 @@ def _wrapped_tool_includes_runfiles_test(env, targets):
         _BIN,
     ])
 
+def _tool_with_allowlist_include_directories_test(env, targets):
+    tool = env.expect.that_target(targets.tool_with_allowlist_include_directories).provider(ToolInfo)
+    tool.allowlist_include_directories().contains_exactly([_TOOL_DIRECTORY])
+    tool.runfiles().contains_at_least([
+        _BIN,
+        _FILE1,
+    ])
+
 def _collect_tools_collects_tools_test(env, targets):
     env.expect.that_value(
         value = collect_tools(env.ctx, [targets.tool, targets.wrapped_tool]),
@@ -106,17 +106,22 @@ TARGETS = [
     "//tests/rule_based_toolchain/features:direct_constraint",
     "//tests/rule_based_toolchain/tool:tool",
     "//tests/rule_based_toolchain/tool:wrapped_tool",
+    "//tests/rule_based_toolchain/tool:directory_tool",
+    "//tests/rule_based_toolchain/tool:tool_with_allowlist_include_directories",
     "//tests/rule_based_toolchain/testdata:bin_wrapper",
     "//tests/rule_based_toolchain/testdata:multiple",
     "//tests/rule_based_toolchain/testdata:bin_filegroup",
+    "//tests/rule_based_toolchain/testdata:bin_wrapper_filegroup",
 ]
 
 # @unsorted-dict-items
 TESTS = {
-    "tool_test": _tool_test,
+    "tool_test": lambda env, targets: _tool_test(env, targets.tool),
+    "directory_tool_test": lambda env, targets: _tool_test(env, targets.directory_tool),
     "wrapped_tool_includes_runfiles_test": _wrapped_tool_includes_runfiles_test,
     "collect_tools_collects_tools_test": _collect_tools_collects_tools_test,
     "collect_tools_collects_binaries_test": _collect_tools_collects_binaries_test,
     "collect_tools_collects_single_files_test": _collect_tools_collects_single_files_test,
     "collect_tools_fails_on_non_binary_test": _collect_tools_fails_on_non_binary_test,
+    "tool_with_allowlist_include_directories_test": _tool_with_allowlist_include_directories_test,
 }
diff --git a/tests/rule_based_toolchain/tool_map/BUILD b/tests/rule_based_toolchain/tool_map/BUILD
new file mode 100644
index 0000000..9be1aeb
--- /dev/null
+++ b/tests/rule_based_toolchain/tool_map/BUILD
@@ -0,0 +1,9 @@
+load(
+    ":tool_map_test.bzl",
+    "duplicate_action_test",
+    "valid_config_test",
+)
+
+duplicate_action_test(name = "duplicate_action_test")
+
+valid_config_test(name = "valid_config_test")
diff --git a/tests/rule_based_toolchain/tool_map/tool_map_test.bzl b/tests/rule_based_toolchain/tool_map/tool_map_test.bzl
new file mode 100644
index 0000000..f4073c3
--- /dev/null
+++ b/tests/rule_based_toolchain/tool_map/tool_map_test.bzl
@@ -0,0 +1,76 @@
+# Copyright 2024 The Bazel Authors. All rights reserved.
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Tests for the cc_tool_map rule."""
+
+load("//cc/toolchains:cc_toolchain_info.bzl", "ActionTypeInfo", "ToolConfigInfo")
+load("//cc/toolchains:tool_map.bzl", "cc_tool_map")
+load("//tests/rule_based_toolchain:subjects.bzl", "subjects")
+load("//tests/rule_based_toolchain:testing_rules.bzl", "analysis_test", "expect_failure_test", "helper_target")
+
+_ALL_ACTIONS = "//cc/toolchains/actions:all_actions"
+_C_COMPILE = "//cc/toolchains/actions:c_compile"
+_CPP_COMPILE = "//cc/toolchains/actions:cpp_compile"
+_ALL_CPP_COMPILE = "//cc/toolchains/actions:cpp_compile_actions"
+_STRIP = "//cc/toolchains/actions:strip"
+_LINK_DYNAMIC_LIBRARY = "//cc/toolchains/actions:cpp_link_executable"
+_BIN = "//tests/rule_based_toolchain/testdata:bin"
+_BIN_WRAPPER = "//tests/rule_based_toolchain/testdata:bin_wrapper"
+
+def valid_config_test(name):
+    subject_name = "_%s_subject" % name
+    cc_tool_map(
+        name = subject_name,
+        tools = {
+            _LINK_DYNAMIC_LIBRARY: _BIN,
+            _C_COMPILE: _BIN_WRAPPER,
+            _ALL_CPP_COMPILE: _BIN,
+        },
+    )
+
+    analysis_test(
+        name = name,
+        impl = _valid_config_test_impl,
+        targets = {
+            "c_compile": _C_COMPILE,
+            "cpp_compile": _CPP_COMPILE,
+            "link_dynamic_library": _LINK_DYNAMIC_LIBRARY,
+            "strip": _STRIP,
+            "subject": subject_name,
+        },
+    )
+
+def _valid_config_test_impl(env, targets):
+    configs = env.expect.that_target(targets.subject).provider(ToolConfigInfo).configs()
+
+    configs.contains(targets.strip[ActionTypeInfo]).equals(False)
+    configs.get(targets.c_compile[ActionTypeInfo]).exe().path().split("/").offset(-1, subjects.str).equals("bin_wrapper")
+    configs.get(targets.cpp_compile[ActionTypeInfo]).exe().path().split("/").offset(-1, subjects.str).equals("bin")
+    configs.get(targets.link_dynamic_library[ActionTypeInfo]).exe().path().split("/").offset(-1, subjects.str).equals("bin")
+
+def duplicate_action_test(name):
+    subject_name = "_%s_subject" % name
+    helper_target(
+        cc_tool_map,
+        name = subject_name,
+        tools = {
+            _C_COMPILE: _BIN_WRAPPER,
+            _ALL_ACTIONS: _BIN,
+        },
+    )
+
+    expect_failure_test(
+        name = name,
+        target = subject_name,
+        failure_message = "appears multiple times in your tool_map",
+    )
diff --git a/tests/rule_based_toolchain/toolchain_config/BUILD b/tests/rule_based_toolchain/toolchain_config/BUILD
index 0068963..08b5f83 100644
--- a/tests/rule_based_toolchain/toolchain_config/BUILD
+++ b/tests/rule_based_toolchain/toolchain_config/BUILD
@@ -1,9 +1,10 @@
 load("@rules_testing//lib:util.bzl", "util")
-load("//cc/toolchains:action_type_config.bzl", "cc_action_type_config")
 load("//cc/toolchains:args.bzl", "cc_args")
 load("//cc/toolchains:feature.bzl", "cc_feature")
 load("//cc/toolchains:feature_set.bzl", "cc_feature_set")
 load("//cc/toolchains:tool.bzl", "cc_tool")
+load("//cc/toolchains:tool_map.bzl", "cc_tool_map")
+load("//cc/toolchains/args:sysroot.bzl", "cc_sysroot")
 load("//cc/toolchains/impl:external_feature.bzl", "cc_external_feature")
 load("//cc/toolchains/impl:toolchain_config.bzl", "cc_legacy_file_group", "cc_toolchain_config")
 load("//tests/rule_based_toolchain:analysis_test_suite.bzl", "analysis_test_suite")
@@ -29,6 +30,7 @@ util.helper_target(
     cc_args,
     name = "c_compile_args",
     actions = ["//tests/rule_based_toolchain/actions:c_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_1"],
     args = ["c_compile_args"],
     data = ["//tests/rule_based_toolchain/testdata:file1"],
 )
@@ -41,17 +43,35 @@ util.helper_target(
     env = {"CPP_COMPILE": "1"},
 )
 
+cc_tool(
+    name = "c_compile_tool",
+    src = "//tests/rule_based_toolchain/testdata:bin_wrapper",
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_3"],
+    capabilities = ["//cc/toolchains/capabilities:supports_pic"],
+)
+
+cc_sysroot(
+    name = "sysroot",
+    actions = [
+        "//cc/toolchains/actions:cpp_compile_actions",
+        "//cc/toolchains/actions:c_compile",
+        "//cc/toolchains/actions:link_actions",
+        "//tests/rule_based_toolchain/actions:c_compile",
+        "//tests/rule_based_toolchain/actions:cpp_compile",
+    ],
+    sysroot = "//tests/rule_based_toolchain/testdata:directory",
+)
+
 util.helper_target(
     cc_toolchain_config,
     name = "collects_files_toolchain_config",
-    action_type_configs = [":compile_config"],
-    args = [":c_compile_args"],
-    compiler = "gcc-4.1.1",
-    skip_experimental_flag_validation_for_test = True,
-    target_cpu = "k8",
-    target_libc = "glibc-2.2.2",
-    target_system_name = "local",
-    toolchain_features = [":compile_feature"],
+    args = [
+        ":sysroot",
+        ":c_compile_args",
+    ],
+    enabled_features = [":simple_feature"],
+    known_features = [":compile_feature"],
+    tool_map = ":compile_tool_map",
 )
 
 util.helper_target(
@@ -72,43 +92,45 @@ util.helper_target(
     cc_args,
     name = "compile_args",
     actions = ["//tests/rule_based_toolchain/actions:all_compile"],
+    allowlist_include_directories = ["//tests/rule_based_toolchain/testdata:subdirectory_2"],
     args = ["compile_args"],
     data = ["//tests/rule_based_toolchain/testdata:file2"],
 )
 
 util.helper_target(
-    cc_action_type_config,
-    name = "compile_config",
-    action_types = ["//tests/rule_based_toolchain/actions:all_compile"],
-    args = [":cpp_compile_args"],
-    tools = [
-        "//tests/rule_based_toolchain/tool:wrapped_tool",
-    ],
+    cc_tool_map,
+    name = "compile_tool_map",
+    tools = {
+        "//tests/rule_based_toolchain/actions:c_compile": ":c_compile_tool",
+        "//tests/rule_based_toolchain/actions:cpp_compile": "//tests/rule_based_toolchain/tool:wrapped_tool",
+    },
 )
 
 util.helper_target(
     cc_feature,
     name = "compile_feature",
     args = [":compile_args"],
-    enabled = True,
     feature_name = "compile_feature",
 )
 
 util.helper_target(
-    cc_action_type_config,
-    name = "c_compile_config",
-    action_types = ["//tests/rule_based_toolchain/actions:c_compile"],
-    implies = [":simple_feature"],
-    tools = [
-        "//tests/rule_based_toolchain/tool:wrapped_tool",
-    ],
+    cc_tool_map,
+    name = "c_compile_tool_map",
+    tools = {
+        "//tests/rule_based_toolchain/actions:c_compile": "//tests/rule_based_toolchain/tool:wrapped_tool",
+    },
+)
+
+util.helper_target(
+    cc_tool_map,
+    name = "empty_tool_map",
+    tools = {},
 )
 
 util.helper_target(
     cc_feature,
     name = "implies_simple_feature",
     args = [":c_compile_args"],
-    enabled = True,
     feature_name = "implies",
     implies = [":simple_feature"],
 )
@@ -117,7 +139,6 @@ util.helper_target(
     cc_feature,
     name = "overrides_feature",
     args = [":c_compile_args"],
-    enabled = True,
     overrides = ":builtin_feature",
 )
 
@@ -133,30 +154,14 @@ util.helper_target(
     cc_feature,
     name = "requires_all_simple_feature",
     args = [":c_compile_args"],
-    enabled = True,
     feature_name = "requires_any_simple",
     requires_any_of = [":all_simple_features"],
 )
 
-util.helper_target(
-    cc_tool,
-    name = "requires_all_simple_tool",
-    src = "//tests/rule_based_toolchain/testdata:bin_wrapper.sh",
-    requires_any_of = [":all_simple_features"],
-)
-
-util.helper_target(
-    cc_action_type_config,
-    name = "requires_all_simple_action_type_config",
-    action_types = ["//tests/rule_based_toolchain/actions:c_compile"],
-    tools = [":requires_all_simple_tool"],
-)
-
 util.helper_target(
     cc_feature,
     name = "requires_any_simple_feature",
     args = [":c_compile_args"],
-    enabled = True,
     feature_name = "requires_any_simple",
     requires_any_of = [
         ":simple_feature",
@@ -168,7 +173,6 @@ util.helper_target(
     cc_feature,
     name = "same_feature_name",
     args = [":c_compile_args"],
-    enabled = False,
     feature_name = "simple_feature",
     visibility = ["//tests/rule_based_toolchain:__subpackages__"],
 )
@@ -177,7 +181,6 @@ util.helper_target(
     cc_feature,
     name = "simple_feature",
     args = [":c_compile_args"],
-    enabled = False,
     feature_name = "simple_feature",
 )
 
@@ -185,7 +188,6 @@ util.helper_target(
     cc_feature,
     name = "simple_feature2",
     args = [":c_compile_args"],
-    enabled = False,
     feature_name = "simple_feature2",
     visibility = ["//tests/rule_based_toolchain:__subpackages__"],
 )
diff --git a/tests/rule_based_toolchain/toolchain_config/toolchain_config_test.bzl b/tests/rule_based_toolchain/toolchain_config/toolchain_config_test.bzl
index e188772..1047203 100644
--- a/tests/rule_based_toolchain/toolchain_config/toolchain_config_test.bzl
+++ b/tests/rule_based_toolchain/toolchain_config/toolchain_config_test.bzl
@@ -16,8 +16,6 @@
 load(
     "//cc:cc_toolchain_config_lib.bzl",
     legacy_action_config = "action_config",
-    legacy_env_entry = "env_entry",
-    legacy_env_set = "env_set",
     legacy_feature = "feature",
     legacy_flag_group = "flag_group",
     legacy_flag_set = "flag_set",
@@ -38,11 +36,17 @@ _COLLECTED_CPP_COMPILE_FILES = [
     "tests/rule_based_toolchain/testdata/bin_wrapper",
     # From :compile_feature's args
     "tests/rule_based_toolchain/testdata/file2",
+    # From :compile_feature's args' allowlist_include_directories
+    "tests/rule_based_toolchain/testdata/subdir2/file_bar",
 ]
 
 _COLLECTED_C_COMPILE_FILES = _COLLECTED_CPP_COMPILE_FILES + [
     # From :c_compile_args
     "tests/rule_based_toolchain/testdata/file1",
+    # From :c_compile_args's allowlist_include_directories
+    "tests/rule_based_toolchain/testdata/subdir1/file_foo",
+    # From :c_compile_tool's allowlist_include_directories
+    "tests/rule_based_toolchain/testdata/subdir3/file_baz",
 ]
 
 def _expect_that_toolchain(env, expr = None, **kwargs):
@@ -52,13 +56,26 @@ def _expect_that_toolchain(env, expr = None, **kwargs):
         factory = subjects.result(subjects.ToolchainConfigInfo),
     )
 
-def _empty_toolchain_valid_test(env, _targets):
-    _expect_that_toolchain(env).ok()
+def _missing_tool_map_invalid_test(env, _targets):
+    _expect_that_toolchain(
+        env,
+        tool_map = None,
+        expr = "missing_tool_map",
+    ).err().contains(
+        "tool_map is required",
+    )
+
+def _empty_toolchain_valid_test(env, targets):
+    _expect_that_toolchain(
+        env,
+        tool_map = targets.empty_tool_map,  # tool_map is always required.
+    ).ok()
 
 def _duplicate_feature_names_invalid_test(env, targets):
     _expect_that_toolchain(
         env,
-        features = [targets.simple_feature, targets.same_feature_name],
+        known_features = [targets.simple_feature, targets.same_feature_name],
+        tool_map = targets.empty_tool_map,
         expr = "duplicate_feature_name",
     ).err().contains_all_of([
         "The feature name simple_feature was defined by",
@@ -69,48 +86,23 @@ def _duplicate_feature_names_invalid_test(env, targets):
     # Overriding a feature gives it the same name. Ensure this isn't blocked.
     _expect_that_toolchain(
         env,
-        features = [targets.builtin_feature, targets.overrides_feature],
+        known_features = [targets.builtin_feature, targets.overrides_feature],
+        tool_map = targets.empty_tool_map,
         expr = "override_feature",
     ).ok()
 
-def _duplicate_action_type_invalid_test(env, targets):
-    _expect_that_toolchain(
-        env,
-        features = [targets.simple_feature],
-        action_type_configs = [targets.compile_config, targets.c_compile_config],
-    ).err().contains_all_of([
-        "The action type %s is configured by" % targets.c_compile.label,
-        targets.compile_config.label,
-        targets.c_compile_config.label,
-    ])
-
-def _action_config_implies_missing_feature_invalid_test(env, targets):
-    _expect_that_toolchain(
-        env,
-        features = [targets.simple_feature],
-        action_type_configs = [targets.c_compile_config],
-        expr = "action_type_config_with_implies",
-    ).ok()
-
-    _expect_that_toolchain(
-        env,
-        features = [],
-        action_type_configs = [targets.c_compile_config],
-        expr = "action_type_config_missing_implies",
-    ).err().contains(
-        "%s implies the feature %s" % (targets.c_compile_config.label, targets.simple_feature.label),
-    )
-
 def _feature_config_implies_missing_feature_invalid_test(env, targets):
     _expect_that_toolchain(
         env,
         expr = "feature_with_implies",
-        features = [targets.simple_feature, targets.implies_simple_feature],
+        known_features = [targets.simple_feature, targets.implies_simple_feature],
+        tool_map = targets.empty_tool_map,
     ).ok()
 
     _expect_that_toolchain(
         env,
-        features = [targets.implies_simple_feature],
+        known_features = [targets.implies_simple_feature],
+        tool_map = targets.empty_tool_map,
         expr = "feature_missing_implies",
     ).err().contains(
         "%s implies the feature %s" % (targets.implies_simple_feature.label, targets.simple_feature.label),
@@ -119,17 +111,20 @@ def _feature_config_implies_missing_feature_invalid_test(env, targets):
 def _feature_missing_requirements_invalid_test(env, targets):
     _expect_that_toolchain(
         env,
-        features = [targets.requires_any_simple_feature, targets.simple_feature],
+        known_features = [targets.requires_any_simple_feature, targets.simple_feature],
+        tool_map = targets.empty_tool_map,
         expr = "requires_any_simple_has_simple",
     ).ok()
     _expect_that_toolchain(
         env,
-        features = [targets.requires_any_simple_feature, targets.simple_feature2],
+        known_features = [targets.requires_any_simple_feature, targets.simple_feature2],
+        tool_map = targets.empty_tool_map,
         expr = "requires_any_simple_has_simple2",
     ).ok()
     _expect_that_toolchain(
         env,
-        features = [targets.requires_any_simple_feature],
+        known_features = [targets.requires_any_simple_feature],
+        tool_map = targets.empty_tool_map,
         expr = "requires_any_simple_has_none",
     ).err().contains(
         "It is impossible to enable %s" % targets.requires_any_simple_feature.label,
@@ -137,19 +132,22 @@ def _feature_missing_requirements_invalid_test(env, targets):
 
     _expect_that_toolchain(
         env,
-        features = [targets.requires_all_simple_feature, targets.simple_feature, targets.simple_feature2],
+        known_features = [targets.requires_all_simple_feature, targets.simple_feature, targets.simple_feature2],
+        tool_map = targets.empty_tool_map,
         expr = "requires_all_simple_has_both",
     ).ok()
     _expect_that_toolchain(
         env,
-        features = [targets.requires_all_simple_feature, targets.simple_feature],
+        known_features = [targets.requires_all_simple_feature, targets.simple_feature],
+        tool_map = targets.empty_tool_map,
         expr = "requires_all_simple_has_simple",
     ).err().contains(
         "It is impossible to enable %s" % targets.requires_all_simple_feature.label,
     )
     _expect_that_toolchain(
         env,
-        features = [targets.requires_all_simple_feature, targets.simple_feature2],
+        known_features = [targets.requires_all_simple_feature, targets.simple_feature2],
+        tool_map = targets.empty_tool_map,
         expr = "requires_all_simple_has_simple2",
     ).err().contains(
         "It is impossible to enable %s" % targets.requires_all_simple_feature.label,
@@ -159,34 +157,20 @@ def _args_missing_requirements_invalid_test(env, targets):
     _expect_that_toolchain(
         env,
         args = [targets.requires_all_simple_args],
-        features = [targets.simple_feature, targets.simple_feature2],
+        known_features = [targets.simple_feature, targets.simple_feature2],
+        tool_map = targets.empty_tool_map,
         expr = "has_both",
     ).ok()
     _expect_that_toolchain(
         env,
         args = [targets.requires_all_simple_args],
-        features = [targets.simple_feature],
+        known_features = [targets.simple_feature],
+        tool_map = targets.empty_tool_map,
         expr = "has_only_one",
     ).err().contains(
         "It is impossible to enable %s" % targets.requires_all_simple_args.label,
     )
 
-def _tool_missing_requirements_invalid_test(env, targets):
-    _expect_that_toolchain(
-        env,
-        action_type_configs = [targets.requires_all_simple_action_type_config],
-        features = [targets.simple_feature, targets.simple_feature2],
-        expr = "has_both",
-    ).ok()
-    _expect_that_toolchain(
-        env,
-        action_type_configs = [targets.requires_all_simple_action_type_config],
-        features = [targets.simple_feature],
-        expr = "has_only_one",
-    ).err().contains(
-        "It is impossible to enable %s" % targets.requires_all_simple_tool.label,
-    )
-
 def _toolchain_collects_files_test(env, targets):
     tc = env.expect.that_target(
         targets.collects_files_toolchain_config,
@@ -204,17 +188,7 @@ def _toolchain_collects_files_test(env, targets):
     legacy = convert_toolchain(tc.actual)
     env.expect.that_collection(legacy.features).contains_exactly([
         legacy_feature(
-            name = "compile_feature",
-            enabled = True,
-            flag_sets = [legacy_flag_set(
-                actions = ["c_compile", "cpp_compile"],
-                flag_groups = [
-                    legacy_flag_group(flags = ["compile_args"]),
-                ],
-            )],
-        ),
-        legacy_feature(
-            name = "implied_by_always_enabled",
+            name = "simple_feature",
             enabled = True,
             flag_sets = [legacy_flag_set(
                 actions = ["c_compile"],
@@ -224,35 +198,63 @@ def _toolchain_collects_files_test(env, targets):
             )],
         ),
         legacy_feature(
-            name = "implied_by_cpp_compile",
+            name = "compile_feature",
             enabled = False,
             flag_sets = [legacy_flag_set(
-                actions = ["cpp_compile"],
+                actions = ["c_compile", "cpp_compile"],
                 flag_groups = [
-                    legacy_flag_group(flags = ["cpp_compile_args"]),
+                    legacy_flag_group(flags = ["compile_args"]),
                 ],
             )],
-            env_sets = [legacy_env_set(
-                actions = ["cpp_compile"],
-                env_entries = [legacy_env_entry(key = "CPP_COMPILE", value = "1")],
-            )],
+        ),
+        legacy_feature(
+            name = "supports_pic",
+            enabled = False,
+        ),
+        legacy_feature(
+            name = "implied_by_always_enabled_env_sets",
+            enabled = True,
         ),
     ]).in_order()
 
-    exe = tc.action_type_configs().get(
+    exe = tc.tool_map().some().configs().get(
         targets.c_compile[ActionTypeInfo],
-    ).actual.tools[0].exe
+    ).actual.exe
     env.expect.that_collection(legacy.action_configs).contains_exactly([
         legacy_action_config(
             action_name = "c_compile",
             enabled = True,
             tools = [legacy_tool(tool = exe)],
+            implies = ["supports_pic"],
+            flag_sets = [
+                legacy_flag_set(
+                    flag_groups = [
+                        legacy_flag_group(flags = [
+                            "--sysroot=tests/rule_based_toolchain/testdata",
+                        ]),
+                    ],
+                ),
+                legacy_flag_set(
+                    flag_groups = [
+                        legacy_flag_group(flags = ["c_compile_args"]),
+                    ],
+                ),
+            ],
         ),
         legacy_action_config(
             action_name = "cpp_compile",
             enabled = True,
             tools = [legacy_tool(tool = exe)],
-            implies = ["implied_by_cpp_compile"],
+            implies = [],
+            flag_sets = [
+                legacy_flag_set(
+                    flag_groups = [
+                        legacy_flag_group(flags = [
+                            "--sysroot=tests/rule_based_toolchain/testdata",
+                        ]),
+                    ],
+                ),
+            ],
         ),
     ]).in_order()
 
@@ -260,20 +262,19 @@ TARGETS = [
     "//tests/rule_based_toolchain/actions:c_compile",
     "//tests/rule_based_toolchain/actions:cpp_compile",
     ":builtin_feature",
-    ":compile_config",
+    ":compile_tool_map",
     ":collects_files_c_compile",
     ":collects_files_cpp_compile",
     ":collects_files_toolchain_config",
     ":compile_feature",
     ":c_compile_args",
-    ":c_compile_config",
+    ":c_compile_tool_map",
+    ":empty_tool_map",
     ":implies_simple_feature",
     ":overrides_feature",
     ":requires_any_simple_feature",
     ":requires_all_simple_feature",
     ":requires_all_simple_args",
-    ":requires_all_simple_action_type_config",
-    ":requires_all_simple_tool",
     ":simple_feature",
     ":simple_feature2",
     ":same_feature_name",
@@ -282,12 +283,10 @@ TARGETS = [
 # @unsorted-dict-items
 TESTS = {
     "empty_toolchain_valid_test": _empty_toolchain_valid_test,
+    "missing_tool_map_invalid_test": _missing_tool_map_invalid_test,
     "duplicate_feature_names_fail_validation_test": _duplicate_feature_names_invalid_test,
-    "duplicate_action_type_invalid_test": _duplicate_action_type_invalid_test,
-    "action_config_implies_missing_feature_invalid_test": _action_config_implies_missing_feature_invalid_test,
     "feature_config_implies_missing_feature_invalid_test": _feature_config_implies_missing_feature_invalid_test,
     "feature_missing_requirements_invalid_test": _feature_missing_requirements_invalid_test,
     "args_missing_requirements_invalid_test": _args_missing_requirements_invalid_test,
-    "tool_missing_requirements_invalid_test": _tool_missing_requirements_invalid_test,
     "toolchain_collects_files_test": _toolchain_collects_files_test,
 }
diff --git a/tests/rule_based_toolchain/variables/BUILD b/tests/rule_based_toolchain/variables/BUILD
index 5f7a5a6..2e9d480 100644
--- a/tests/rule_based_toolchain/variables/BUILD
+++ b/tests/rule_based_toolchain/variables/BUILD
@@ -1,4 +1,3 @@
-load("//cc/toolchains:format.bzl", "format_arg")
 load("//cc/toolchains:nested_args.bzl", "cc_nested_args")
 load("//cc/toolchains/impl:variables.bzl", "cc_builtin_variables", "cc_variable", "types")
 load("//tests/rule_based_toolchain:analysis_test_suite.bzl", "analysis_test_suite")
@@ -56,17 +55,19 @@ alias(
 
 cc_nested_args(
     name = "simple_str",
-    args = [format_arg("%s", ":str")],
+    args = ["{str}"],
+    format = {"str": ":str"},
 )
 
 cc_nested_args(
     name = "list_not_allowed",
-    args = [format_arg("%s", ":str_list")],
+    args = ["{s}"],
+    format = {"s": ":str_list"},
 )
 
 cc_nested_args(
     name = "iterate_over_list",
-    args = [format_arg("%s")],
+    args = ["{}"],
     iterate_over = ":str_list",
 )
 
@@ -91,7 +92,7 @@ cc_nested_args(
 
 cc_nested_args(
     name = "inner_iter",
-    args = [format_arg("%s")],
+    args = ["{}"],
     iterate_over = ":struct_list.nested_str_list",
 )
 
@@ -103,7 +104,8 @@ cc_nested_args(
 
 cc_nested_args(
     name = "bad_inner_iter",
-    args = [format_arg("%s", ":struct_list.nested_str_list")],
+    args = ["{s}"],
+    format = {"s": ":struct_list.nested_str_list"},
 )
 
 cc_nested_args(
@@ -114,12 +116,14 @@ cc_nested_args(
 
 cc_nested_args(
     name = "bad_nested_optional",
-    args = [format_arg("%s", ":str_option")],
+    args = ["{s}"],
+    format = {"s": ":str_option"},
 )
 
 cc_nested_args(
     name = "good_nested_optional",
-    args = [format_arg("%s", ":str_option")],
+    args = ["{s}"],
+    format = {"s": ":str_option"},
     requires_not_none = ":str_option",
 )
 
@@ -141,6 +145,13 @@ cc_builtin_variables(
     ],
 )
 
+cc_builtin_variables(
+    name = "nested_variables",
+    srcs = [
+        ":struct_list.nested_str_list",
+    ],
+)
+
 analysis_test_suite(
     name = "test_suite",
     targets = TARGETS,
diff --git a/tests/simple_binary/BUILD b/tests/simple_binary/BUILD
index c8d78a6..259e5a5 100644
--- a/tests/simple_binary/BUILD
+++ b/tests/simple_binary/BUILD
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-load("//cc:defs.bzl", "cc_binary")
+load("//cc:cc_binary.bzl", "cc_binary")
 
 licenses(["notice"])
 
diff --git a/tests/system_library/BUILD b/tests/system_library/BUILD
index 3c8d577..215ba2c 100644
--- a/tests/system_library/BUILD
+++ b/tests/system_library/BUILD
@@ -12,6 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@rules_shell//shell:sh_test.bzl", "sh_test")
+
 sh_test(
     name = "system_library_test",
     size = "small",
diff --git a/third_party/BUILD b/third_party/BUILD
deleted file mode 100644
index 0c41157..0000000
--- a/third_party/BUILD
+++ /dev/null
@@ -1 +0,0 @@
-# Intentionally empty, only there to make //third_party a package.
diff --git a/third_party/com/github/bazelbuild/bazel/src/main/protobuf/BUILD b/third_party/com/github/bazelbuild/bazel/src/main/protobuf/BUILD
deleted file mode 100644
index c08e13b..0000000
--- a/third_party/com/github/bazelbuild/bazel/src/main/protobuf/BUILD
+++ /dev/null
@@ -1,30 +0,0 @@
-load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")
-load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
-load("@rules_proto//proto:defs.bzl", "proto_library")
-
-licenses(["notice"])  # Apache 2.0
-
-py_proto_library(
-    name = "crosstool_config_py_pb2",
-    srcs = ["crosstool_config.proto"],
-    visibility = [
-        "//tools/migration:__pkg__",
-    ],
-)
-
-proto_library(
-    name = "crosstool_config_pb2",
-    srcs = ["crosstool_config.proto"],
-    visibility = [
-        "//tools/migration:__pkg__",
-    ],
-)
-
-go_proto_library(
-    name = "crosstool_config_go_proto",
-    importpath = "third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config_go_proto",
-    proto = ":crosstool_config_pb2",
-    visibility = [
-        "//tools/migration:__pkg__",
-    ],
-)
diff --git a/third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config.proto b/third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config.proto
deleted file mode 100644
index 45ad1e5..0000000
--- a/third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config.proto
+++ /dev/null
@@ -1,548 +0,0 @@
-// Copyright 2014 The Bazel Authors. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-// File format for Blaze to configure Crosstool releases.
-
-syntax = "proto2";
-
-package com.google.devtools.build.lib.view.config.crosstool;
-
-// option java_api_version = 2;  // copybara-comment-this-out-please
-option java_package = "com.google.devtools.build.lib.view.config.crosstool";
-
-// A description of a toolchain, which includes all the tools generally expected
-// to be available for building C/C++ targets, based on the GNU C compiler.
-//
-// System and cpu names are two overlapping concepts, which need to be both
-// supported at this time. The cpu name is the blaze command-line name for the
-// target system. The most common values are 'k8' and 'piii'. The system name is
-// a more generic identification of the executable system, based on the names
-// used by the GNU C compiler.
-//
-// Typically, the system name contains an identifier for the cpu (e.g. x86_64 or
-// alpha), an identifier for the machine (e.g. pc, or unknown), and an
-// identifier for the operating system (e.g. cygwin or linux-gnu). Typical
-// examples are 'x86_64-unknown-linux-gnu' and 'i686-unknown-cygwin'.
-//
-// The system name is used to determine if a given machine can execute a given
-// executable. In particular, it is used to check if the compilation products of
-// a toolchain can run on the host machine.
-message CToolchain {
-  // A group of correlated flags. Supports parametrization via variable
-  // expansion.
-  //
-  // To expand a variable of list type, flag_group has to be annotated with
-  // `iterate_over` message. Then all nested flags or flag_groups will be
-  // expanded repeatedly for each element of the list.
-  //
-  // For example:
-  // flag_group {
-  //   iterate_over: 'include_path'
-  //   flag: '-I'
-  //   flag: '%{include_path}'
-  // }
-  // ... will get expanded to -I /to/path1 -I /to/path2 ... for each
-  // include_path /to/pathN.
-  //
-  // To expand a variable of structure type, use dot-notation, e.g.:
-  //    flag_group {
-  //      iterate_over: "libraries_to_link"
-  //      flag_group {
-  //        iterate_over: "libraries_to_link.libraries"
-  //        flag: "-L%{libraries_to_link.libraries.directory}"
-  //      }
-  //    }
-  //
-  // Flag groups can be nested; if they are, the flag group must only contain
-  // other flag groups (no flags) so the order is unambiguously specified.
-  // In order to expand a variable of nested lists, 'iterate_over' can be used.
-  //
-  // For example:
-  // flag_group {
-  //   iterate_over: 'object_files'
-  //   flag_group { flag: '--start-lib' }
-  //   flag_group {
-  //     iterate_over: 'object_files'
-  //     flag: '%{object_files}'
-  //   }
-  //   flag_group { flag: '--end-lib' }
-  // }
-  // ... will get expanded to
-  //   --start-lib a1.o a2.o ... --end-lib --start-lib b1.o b2.o .. --end-lib
-  //   with %{object_files} being a variable of nested list type
-  //   [['a1.o', 'a2.o', ...], ['b1.o', 'b2.o', ...], ...].
-  //
-  // TODO(bazel-team): Write more elaborate documentation and add a link to it.
-  message FlagGroup {
-    repeated string flag = 1;
-
-    repeated FlagGroup flag_group = 2;
-
-    optional string iterate_over = 3;
-
-    repeated string expand_if_all_available = 4;
-
-    repeated string expand_if_none_available = 5;
-
-    optional string expand_if_true = 6;
-
-    optional string expand_if_false = 7;
-
-    optional VariableWithValue expand_if_equal = 8;
-  }
-
-  message VariableWithValue {
-    required string variable = 1;
-
-    required string value = 2;
-  }
-
-  // A key/value pair to be added as an environment variable. The value of
-  // this pair is expanded in the same way as is described in FlagGroup.
-  // The key remains an unexpanded string literal.
-  message EnvEntry {
-    required string key = 1;
-    required string value = 2;
-    repeated string expand_if_all_available = 3;
-  }
-
-  // A set of features; used to support logical 'and' when specifying feature
-  // requirements in Feature.
-  message FeatureSet {
-    repeated string feature = 1;
-  }
-
-  // A set of positive and negative features. This stanza will
-  // evaluate to true when every 'feature' is enabled, and every
-  // 'not_feature' is not enabled.
-  message WithFeatureSet {
-    repeated string feature = 1;
-    repeated string not_feature = 2;
-  }
-
-  // A set of flags that are expanded in the command line for specific actions.
-  message FlagSet {
-    // The actions this flag set applies to; each flag set must specify at
-    // least one action.
-    repeated string action = 1;
-
-    // The flags applied via this flag set.
-    repeated FlagGroup flag_group = 2;
-
-    // A list of feature sets defining when this flag set gets applied.  The
-    // flag set will be applied when any one of the feature sets evaluate to
-    // true. (That is, when when every 'feature' is enabled, and every
-    // 'not_feature' is not enabled.)
-    //
-    // If 'with_feature' is omitted, the flag set will be applied
-    // unconditionally for every action specified.
-    repeated WithFeatureSet with_feature = 3;
-
-    // Deprecated (https://github.com/bazelbuild/bazel/issues/7008) - use
-    // expand_if_all_available in flag_group
-    //
-    // A list of build variables that this feature set needs, but which are
-    // allowed to not be set. If any of the build variables listed is not
-    // set, the feature set will not be expanded.
-    //
-    // NOTE: Consider alternatives before using this; usually tools should
-    // consistently create the same set of files, even if empty; use this
-    // only for backwards compatibility with already existing behavior in tools
-    // that are currently not worth changing.
-    repeated string expand_if_all_available = 4;
-  }
-
-  // A set of environment variables that are expanded in the command line for
-  // specific actions.
-  message EnvSet {
-    // The actions this env set applies to; each env set must specify at
-    // least one action.
-    repeated string action = 1;
-
-    // The environment variables applied via this env set.
-    repeated EnvEntry env_entry = 2;
-
-    // A list of feature sets defining when this env set gets applied.  The
-    // env set will be applied when any one of the feature sets evaluate to
-    // true. (That is, when when every 'feature' is enabled, and every
-    // 'not_feature' is not enabled.)
-    //
-    // If 'with_feature' is omitted, the env set will be applied
-    // unconditionally for every action specified.
-    repeated WithFeatureSet with_feature = 3;
-  }
-
-  // Contains all flag specifications for one feature.
-  // Next ID: 8
-  message Feature {
-    // The feature's name. Feature names are generally defined by Bazel; it is
-    // possible to introduce a feature without a change to Bazel by adding a
-    // 'feature' section to the toolchain and adding the corresponding string as
-    // feature in the BUILD file.
-    optional string name = 1;
-
-    // If 'true', this feature is enabled unless a rule type explicitly marks it
-    // as unsupported. Such features cannot be turned off from within a BUILD
-    // file or the command line.
-    optional bool enabled = 7;
-
-    // If the given feature is enabled, the flag sets will be applied for the
-    // actions in the modes that they are specified for.
-    repeated FlagSet flag_set = 2;
-
-    // If the given feature is enabled, the env sets will be applied for the
-    // actions in the modes that they are specified for.
-    repeated EnvSet env_set = 6;
-
-    // A list of feature sets defining when this feature is supported by the
-    // toolchain. The feature is supported if any of the feature sets fully
-    // apply, that is, when all features of a feature set are enabled.
-    //
-    // If 'requires' is omitted, the feature is supported independently of which
-    // other features are enabled.
-    //
-    // Use this for example to filter flags depending on the build mode
-    // enabled (opt / fastbuild / dbg).
-    repeated FeatureSet requires = 3;
-
-    // A list of features or action configs that are automatically enabled when
-    // this feature is enabled. If any of the implied features or action configs
-    // cannot be enabled, this feature will (silently) not be enabled either.
-    repeated string implies = 4;
-
-    // A list of names this feature conflicts with.
-    // A feature cannot be enabled if:
-    // - 'provides' contains the name of a different feature or action config
-    //  that we want to enable.
-    // - 'provides' contains the same value as a 'provides' in a different
-    //   feature or action config that we want to enable.
-    //
-    // Use this in order to ensure that incompatible features cannot be
-    // accidentally activated at the same time, leading to hard to diagnose
-    // compiler errors.
-    repeated string provides = 5;
-  }
-
-  // Describes a tool associated with a crosstool action config.
-  message Tool {
-    // Describes the origin of a path.
-    enum PathOrigin {
-      // Indicates that `tool_path` is relative to the location of the
-      // crosstool. For legacy reasons, absolute paths are als0 allowed here.
-      CROSSTOOL_PACKAGE = 0;
-
-      // Indicates that `tool_path` is an absolute path.
-      // This is enforced by Bazel.
-      FILESYSTEM_ROOT = 1;
-
-      // Indicates that `tool_path` is relative to the current workspace's
-      // exec root.
-      WORKSPACE_ROOT = 2;
-    }
-
-    // Path to the tool, relative to the location of the crosstool.
-    required string tool_path = 1;
-
-    // Origin of `tool_path`.
-    // Optional only for legacy reasons. New crosstools should set this value!
-    optional PathOrigin tool_path_origin = 4 [default = CROSSTOOL_PACKAGE];
-
-    // A list of feature sets defining when this tool is applicable.  The tool
-    // will used when any one of the feature sets evaluate to true. (That is,
-    // when when every 'feature' is enabled, and every 'not_feature' is not
-    // enabled.)
-    //
-    // If 'with_feature' is omitted, the tool will apply for any feature
-    // configuration.
-    repeated WithFeatureSet with_feature = 2;
-
-    // Requirements on the execution environment for the execution of this tool,
-    // to be passed as out-of-band "hints" to the execution backend.
-    // Ex. "requires-darwin"
-    repeated string execution_requirement = 3;
-  }
-
-  // The name for an artifact of a given category of input or output artifacts
-  // to an action.
-  message ArtifactNamePattern {
-    // The category of artifacts that this selection applies to.  This field
-    // is compared against a list of categories defined in bazel. Example
-    // categories include "linked_output" or "debug_symbols". An error is thrown
-    // if no category is matched.
-    required string category_name = 1;
-    // The prefix and extension for creating the artifact for this selection.
-    // They are used to create an artifact name based on the target name.
-    required string prefix = 2;
-    required string extension = 3;
-  }
-
-  // An action config corresponds to a blaze action, and allows selection of
-  // a tool based on activated features.  Action configs come in two varieties:
-  // automatic (the blaze action will exist whether or not the action config
-  // is activated) and attachable (the blaze action will be added to the
-  // action graph only if the action config is activated).
-  //
-  // Action config activation occurs by the same semantics as features: a
-  // feature can 'require' or 'imply' an action config in the same way that it
-  // would another feature.
-  // Next ID: 9
-  message ActionConfig {
-    // The name other features will use to activate this action config.  Can
-    // be the same as action_name.
-    required string config_name = 1;
-
-    // The name of the blaze action that this config applies to, ex. 'c-compile'
-    // or 'c-module-compile'.
-    required string action_name = 2;
-
-    // If 'true', this feature is enabled unless a rule type explicitly marks it
-    // as unsupported.  Such action_configs cannot be turned off from within a
-    // BUILD file or the command line.
-    optional bool enabled = 8;
-
-    // The tool applied to the action will be the first Tool with a feature
-    // set that matches the feature configuration.  An error will be thrown
-    // if no tool matches a provided feature configuration - for that reason,
-    // it's a good idea to provide a default tool with an empty feature set.
-    repeated Tool tool = 3;
-
-    // If the given action config is enabled, the flag sets will be applied
-    // to the corresponding action.
-    repeated FlagSet flag_set = 4;
-
-    // If the given action config is enabled, the env sets will be applied
-    // to the corresponding action.
-    repeated EnvSet env_set = 5;
-
-    // A list of feature sets defining when this action config
-    // is supported by the toolchain. The action config is supported if any of
-    // the feature sets fully apply, that is, when all features of a
-    // feature set are enabled.
-    //
-    // If 'requires' is omitted, the action config is supported independently
-    // of which other features are enabled.
-    //
-    // Use this for example to filter actions depending on the build
-    // mode enabled (opt / fastbuild / dbg).
-    repeated FeatureSet requires = 6;
-
-    // A list of features or action configs that are automatically enabled when
-    // this action config is enabled. If any of the implied features or action
-    // configs cannot be enabled, this action config will (silently)
-    // not be enabled either.
-    repeated string implies = 7;
-  }
-
-  repeated Feature feature = 50;
-  repeated ActionConfig action_config = 53;
-  repeated ArtifactNamePattern artifact_name_pattern = 54;
-
-  // The unique identifier of the toolchain within the crosstool release. It
-  // must be possible to use this as a directory name in a path.
-  // It has to match the following regex: [a-zA-Z_][\.\- \w]*
-  required string toolchain_identifier = 1;
-
-  // A basic toolchain description.
-  required string host_system_name = 2;
-  required string target_system_name = 3;
-  required string target_cpu = 4;
-  required string target_libc = 5;
-  required string compiler = 6;
-
-  required string abi_version = 7;
-  required string abi_libc_version = 8;
-
-  // Tool locations. Relative paths are resolved relative to the configuration
-  // file directory.
-  // NOTE: DEPRECATED. Prefer specifying an ActionConfig for the action that
-  // needs the tool.
-  // TODO(b/27903698) migrate to ActionConfig.
-  repeated ToolPath tool_path = 9;
-
-  // Feature flags.
-  // TODO(bazel-team): Sink those into 'Feature' instances.
-  // Legacy field, ignored by Bazel.
-  optional bool supports_gold_linker = 10 [default = false];
-  // Legacy field, ignored by Bazel.
-  optional bool supports_thin_archives = 11 [default = false];
-  // Legacy field, use 'supports_start_end_lib' feature instead.
-  optional bool supports_start_end_lib = 28 [default = false];
-  // Legacy field, use 'supports_interface_shared_libraries' instead.
-  optional bool supports_interface_shared_objects = 32 [default = false];
-  // Legacy field, use 'static_link_cpp_runtimes' feature instead.
-  optional bool supports_embedded_runtimes = 40 [default = false];
-  // If specified, Blaze finds statically linked / dynamically linked runtime
-  // libraries in the declared crosstool filegroup. Otherwise, Blaze
-  // looks in "[static|dynamic]-runtime-libs-$TARGET_CPU".
-  // Deprecated, see https://github.com/bazelbuild/bazel/issues/6942
-  optional string static_runtimes_filegroup = 45;
-  // Deprecated, see https://github.com/bazelbuild/bazel/issues/6942
-  optional string dynamic_runtimes_filegroup = 46;
-  // Legacy field, ignored by Bazel.
-  optional bool supports_incremental_linker = 41 [default = false];
-  // Legacy field, ignored by Bazel.
-  optional bool supports_normalizing_ar = 26 [default = false];
-  // Legacy field, use 'per_object_debug_info' feature instead.
-  optional bool supports_fission = 43 [default = false];
-  // Legacy field, ignored by Bazel.
-  optional bool supports_dsym = 51 [default = false];
-  // Legacy field, use 'supports_pic' feature instead
-  optional bool needsPic = 12 [default = false];
-
-  // Compiler flags for C/C++/Asm compilation.
-  repeated string compiler_flag = 13;
-  // Additional compiler flags for C++ compilation.
-  repeated string cxx_flag = 14;
-  // Additional unfiltered compiler flags for C/C++/Asm compilation.
-  // These are not subject to nocopt filtering in cc_* rules.
-  // Note: These flags are *not* applied to objc/objc++ compiles.
-  repeated string unfiltered_cxx_flag = 25;
-  // Linker flags.
-  repeated string linker_flag = 15;
-  // Additional linker flags when linking dynamic libraries.
-  repeated string dynamic_library_linker_flag = 27;
-  // Additional test-only linker flags.
-  repeated string test_only_linker_flag = 49;
-  // Objcopy flags for embedding files into binaries.
-  repeated string objcopy_embed_flag = 16;
-  // Ld flags for embedding files into binaries. This is used by filewrapper
-  // since it calls ld directly and needs to know what -m flag to pass.
-  repeated string ld_embed_flag = 23;
-  // Ar flags for combining object files into archives. If this is not set, it
-  // defaults to "rcsD".
-  // TODO(b/37271982): Remove after blaze with ar action_config release
-  repeated string ar_flag = 47;
-  // Legacy field, ignored by Bazel.
-  repeated string ar_thin_archives_flag = 48;
-  // Legacy field, ignored by Bazel.
-  repeated string gcc_plugin_compiler_flag = 34;
-
-  // Additional compiler and linker flags depending on the compilation mode.
-  repeated CompilationModeFlags compilation_mode_flags = 17;
-
-  // Additional linker flags depending on the linking mode.
-  repeated LinkingModeFlags linking_mode_flags = 18;
-
-  // Legacy field, ignored by Bazel.
-  repeated string gcc_plugin_header_directory = 19;
-  // Legacy field, ignored by Bazel.
-  repeated string mao_plugin_header_directory = 20;
-
-  // Make variables that are made accessible to rules.
-  repeated MakeVariable make_variable = 21;
-
-  // Built-in include directories for C++ compilation. These should be the exact
-  // paths used by the compiler, and are generally relative to the exec root.
-  // The paths used by the compiler can be determined by 'gcc -Wp,-v some.c'.
-  // We currently use the C++ paths also for C compilation, which is safe as
-  // long as there are no name clashes between C++ and C header files.
-  //
-  // Relative paths are resolved relative to the configuration file directory.
-  //
-  // If the compiler has --sysroot support, then these paths should use
-  // %sysroot% rather than the include path, and specify the sysroot attribute
-  // in order to give blaze the information necessary to make the correct
-  // replacements.
-  repeated string cxx_builtin_include_directory = 22;
-
-  // The built-in sysroot. If this attribute is not present, blaze does not
-  // allow using a different sysroot, i.e. through the --grte_top option. Also
-  // see the documentation above.
-  optional string builtin_sysroot = 24;
-
-  // Legacy field, ignored by Bazel.
-  optional string default_python_top = 29;
-  // Legacy field, ignored by Bazel.
-  optional string default_python_version = 30;
-  // Legacy field, ignored by Bazel.
-  optional bool python_preload_swigdeps = 42;
-
-  // The default GRTE to use. This should be a label, and gets the same
-  // treatment from Blaze as the --grte_top option. This setting is only used in
-  // the absence of an explicit --grte_top option. If unset, Blaze will not pass
-  // -sysroot by default. The local part must be 'everything', i.e.,
-  // '//some/label:everything'. There can only be one GRTE library per package,
-  // because the compiler expects the directory as a parameter of the -sysroot
-  // option.
-  // This may only be set to a non-empty value if builtin_sysroot is also set!
-  optional string default_grte_top = 31;
-
-  // Legacy field, ignored by Bazel.
-  repeated string debian_extra_requires = 33;
-
-  // Legacy field, ignored by Bazel. Only there for compatibility with
-  // things internal to Google.
-  optional string cc_target_os = 55;
-
-  // Next free id: 56
-}
-
-message ToolPath {
-  required string name = 1;
-  required string path = 2;
-}
-
-enum CompilationMode {
-  FASTBUILD = 1;
-  DBG = 2;
-  OPT = 3;
-  // This value is ignored and should not be used in new files.
-  COVERAGE = 4;
-}
-
-message CompilationModeFlags {
-  required CompilationMode mode = 1;
-  repeated string compiler_flag = 2;
-  repeated string cxx_flag = 3;
-  // Linker flags that are added when compiling in a certain mode.
-  repeated string linker_flag = 4;
-}
-
-enum LinkingMode {
-  FULLY_STATIC = 1;
-  MOSTLY_STATIC = 2;
-  DYNAMIC = 3;
-  MOSTLY_STATIC_LIBRARIES = 4;
-}
-
-message LinkingModeFlags {
-  required LinkingMode mode = 1;
-  repeated string linker_flag = 2;
-}
-
-message MakeVariable {
-  required string name = 1;
-  required string value = 2;
-}
-
-message DefaultCpuToolchain {
-  required string cpu = 1;
-  required string toolchain_identifier = 2;
-}
-
-// An entire crosstool release, containing the version number, and a set of
-// toolchains.
-message CrosstoolRelease {
-  // The major and minor version of the crosstool release.
-  required string major_version = 1;
-  required string minor_version = 2;
-
-  // Legacy field, ignored by Bazel.
-  optional string default_target_cpu = 3;
-  // Legacy field, ignored by Bazel.
-  repeated DefaultCpuToolchain default_toolchain = 4;
-
-  // All the toolchains in this release.
-  repeated CToolchain toolchain = 5;
-}
diff --git a/third_party/six.BUILD b/third_party/six.BUILD
deleted file mode 100644
index 19433c2..0000000
--- a/third_party/six.BUILD
+++ /dev/null
@@ -1,16 +0,0 @@
-# Description:
-#   Six provides simple utilities for wrapping over differences between Python 2
-#   and Python 3.
-
-load("@rules_python//python:defs.bzl", "py_library")
-
-licenses(["notice"])  # MIT
-
-exports_files(["LICENSE"])
-
-py_library(
-    name = "six",
-    srcs = ["six.py"],
-    srcs_version = "PY2AND3",
-    visibility = ["//visibility:public"],
-)
diff --git a/tools/migration/BUILD b/tools/migration/BUILD
deleted file mode 100644
index 1550c15..0000000
--- a/tools/migration/BUILD
+++ /dev/null
@@ -1,144 +0,0 @@
-# Copyright 2018 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")
-load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")
-
-package(default_visibility = ["//visibility:public"])
-
-licenses(["notice"])
-
-py_binary(
-    name = "legacy_fields_migrator",
-    srcs = ["legacy_fields_migrator.py"],
-    python_version = "PY3",
-    deps = [
-        ":legacy_fields_migration_lib",
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-        "@io_abseil_py//absl:app",
-        "@io_abseil_py//absl/flags",
-        #internal proto upb dep,
-    ],
-)
-
-py_library(
-    name = "legacy_fields_migration_lib",
-    srcs = ["legacy_fields_migration_lib.py"],
-    deps = [
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-    ],
-)
-
-py_test(
-    name = "legacy_fields_migration_lib_test",
-    srcs = ["legacy_fields_migration_lib_test.py"],
-    python_version = "PY3",
-    deps = [
-        ":legacy_fields_migration_lib",
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-    ],
-)
-
-py_binary(
-    name = "crosstool_query",
-    srcs = ["crosstool_query.py"],
-    python_version = "PY3",
-    deps = [
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-        "@io_abseil_py//absl:app",
-        "@io_abseil_py//absl/flags",
-        #internal proto upb dep,
-    ],
-)
-
-py_binary(
-    name = "ctoolchain_comparator",
-    srcs = ["ctoolchain_comparator.py"],
-    python_version = "PY3",
-    deps = [
-        ":ctoolchain_comparator_lib",
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-        "@io_abseil_py//absl:app",
-        "@io_abseil_py//absl/flags",
-        #internal proto upb dep,
-    ],
-)
-
-py_library(
-    name = "ctoolchain_comparator_lib",
-    srcs = ["ctoolchain_comparator_lib.py"],
-    deps = [
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-    ],
-)
-
-py_test(
-    name = "ctoolchain_comparator_lib_test",
-    srcs = ["ctoolchain_comparator_lib_test.py"],
-    python_version = "PY3",
-    deps = [
-        ":ctoolchain_comparator_lib",
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_py_pb2",
-        "@py_mock//py/mock",
-    ],
-)
-
-go_binary(
-    name = "convert_crosstool_to_starlark",
-    srcs = ["convert_crosstool_to_starlark.go"],
-    deps = [
-        ":crosstooltostarlarklib",
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_go_proto",
-        "@com_github_golang_protobuf//proto:go_default_library",
-    ],
-)
-
-go_library(
-    name = "crosstooltostarlarklib",
-    srcs = ["crosstool_to_starlark_lib.go"],
-    importpath = "tools/migration/crosstooltostarlarklib",
-    deps = ["//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_go_proto"],
-)
-
-go_test(
-    name = "crosstooltostarlarklib_test",
-    size = "small",
-    srcs = ["crosstool_to_starlark_lib_test.go"],
-    embed = [":crosstooltostarlarklib"],
-    deps = [
-        "//third_party/com/github/bazelbuild/bazel/src/main/protobuf:crosstool_config_go_proto",
-        "@com_github_golang_protobuf//proto:go_default_library",
-    ],
-)
-
-filegroup(
-    name = "bazel_osx_p4deps",
-    srcs = [
-        "BUILD",
-        "ctoolchain_compare.bzl",
-    ],
-)
-
-bzl_library(
-    name = "ctoolchain_compare_bzl",
-    srcs = ["ctoolchain_compare.bzl"],
-    visibility = ["//visibility:private"],
-)
-
-bzl_library(
-    name = "cc_toolchain_config_comparator_bzl",
-    srcs = ["cc_toolchain_config_comparator.bzl"],
-    visibility = ["//visibility:private"],
-)
diff --git a/tools/migration/cc_toolchain_config_comparator.bzl b/tools/migration/cc_toolchain_config_comparator.bzl
deleted file mode 100644
index 66746b3..0000000
--- a/tools/migration/cc_toolchain_config_comparator.bzl
+++ /dev/null
@@ -1,53 +0,0 @@
-"""A test rule that compares two C++ toolchain configuration rules in proto format."""
-
-def _impl(ctx):
-    first_toolchain_config_proto = ctx.actions.declare_file(
-        ctx.label.name + "_first_toolchain_config.proto",
-    )
-    ctx.actions.write(
-        first_toolchain_config_proto,
-        ctx.attr.first[CcToolchainConfigInfo].proto,
-    )
-
-    second_toolchain_config_proto = ctx.actions.declare_file(
-        ctx.label.name + "_second_toolchain_config.proto",
-    )
-    ctx.actions.write(
-        second_toolchain_config_proto,
-        ctx.attr.second[CcToolchainConfigInfo].proto,
-    )
-
-    script = ("%s --before='%s' --after='%s'" % (
-        ctx.executable._comparator.short_path,
-        first_toolchain_config_proto.short_path,
-        second_toolchain_config_proto.short_path,
-    ))
-    test_executable = ctx.actions.declare_file(ctx.label.name)
-    ctx.actions.write(test_executable, script, is_executable = True)
-
-    runfiles = ctx.runfiles(files = [first_toolchain_config_proto, second_toolchain_config_proto])
-    runfiles = runfiles.merge(ctx.attr._comparator[DefaultInfo].default_runfiles)
-
-    return DefaultInfo(runfiles = runfiles, executable = test_executable)
-
-cc_toolchain_config_compare_test = rule(
-    implementation = _impl,
-    attrs = {
-        "first": attr.label(
-            mandatory = True,
-            providers = [CcToolchainConfigInfo],
-            doc = "A C++ toolchain config rule",
-        ),
-        "second": attr.label(
-            mandatory = True,
-            providers = [CcToolchainConfigInfo],
-            doc = "A C++ toolchain config rule",
-        ),
-        "_comparator": attr.label(
-            default = ":ctoolchain_comparator",
-            executable = True,
-            cfg = "exec",
-        ),
-    },
-    test = True,
-)
diff --git a/tools/migration/convert_crosstool_to_starlark.go b/tools/migration/convert_crosstool_to_starlark.go
deleted file mode 100644
index 2c31456..0000000
--- a/tools/migration/convert_crosstool_to_starlark.go
+++ /dev/null
@@ -1,101 +0,0 @@
-/*
-The convert_crosstool_to_starlark script takes in a CROSSTOOL file and
-generates a Starlark rule.
-
-See https://github.com/bazelbuild/bazel/issues/5380
-
-Example usage:
-bazel run \
-@rules_cc//tools/migration:convert_crosstool_to_starlark -- \
---crosstool=/path/to/CROSSTOOL \
---output_location=/path/to/cc_config.bzl
-*/
-package main
-
-import (
-	"flag"
-	"fmt"
-	"io/ioutil"
-	"os"
-	"os/user"
-	"path"
-	"strings"
-
-	// Google internal base/go package, commented out by copybara
-	"log"
-	crosstoolpb "third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config_go_proto"
-	"github.com/golang/protobuf/proto"
-
-	"tools/migration/crosstooltostarlarklib"
-)
-
-var (
-	crosstoolLocation = flag.String(
-		"crosstool", "", "Location of the CROSSTOOL file")
-	outputLocation = flag.String(
-		"output_location", "", "Location of the output .bzl file")
-)
-
-func toAbsolutePath(pathString string) (string, error) {
-	usr, err := user.Current()
-	if err != nil {
-		return "", err
-	}
-	homeDir := usr.HomeDir
-
-	if strings.HasPrefix(pathString, "~") {
-		return path.Join(homeDir, pathString[1:]), nil
-	}
-
-	if path.IsAbs(pathString) {
-		return pathString, nil
-	}
-
-	workingDirectory := os.Getenv("BUILD_WORKING_DIRECTORY")
-	return path.Join(workingDirectory, pathString), nil
-}
-
-func main() {
-	flag.Parse()
-
-	if *crosstoolLocation == "" {
-		log.Fatalf("Missing mandatory argument 'crosstool'")
-	}
-	crosstoolPath, err := toAbsolutePath(*crosstoolLocation)
-	if err != nil {
-		log.Fatalf("Error while resolving CROSSTOOL location:", err)
-	}
-
-	if *outputLocation == "" {
-		log.Fatalf("Missing mandatory argument 'output_location'")
-	}
-	outputPath, err := toAbsolutePath(*outputLocation)
-	if err != nil {
-		log.Fatalf("Error resolving output location:", err)
-	}
-
-	in, err := ioutil.ReadFile(crosstoolPath)
-	if err != nil {
-		log.Fatalf("Error reading CROSSTOOL file:", err)
-	}
-	crosstool := &crosstoolpb.CrosstoolRelease{}
-	if err := proto.UnmarshalText(string(in), crosstool); err != nil {
-		log.Fatalf("Failed to parse CROSSTOOL:", err)
-	}
-
-	file, err := os.Create(outputPath)
-	if err != nil {
-		log.Fatalf("Error creating output file:", err)
-	}
-	defer file.Close()
-
-	rule, err := crosstooltostarlarklib.Transform(crosstool)
-	if err != nil {
-		log.Fatalf("Error converting CROSSTOOL to a Starlark rule:", err)
-	}
-
-	if _, err := file.WriteString(rule); err != nil {
-		log.Fatalf("Error converting CROSSTOOL to a Starlark rule:", err)
-	}
-	fmt.Println("Success!")
-}
diff --git a/tools/migration/crosstool_query.py b/tools/migration/crosstool_query.py
deleted file mode 100644
index af3f7fa..0000000
--- a/tools/migration/crosstool_query.py
+++ /dev/null
@@ -1,53 +0,0 @@
-"""Script to make automated CROSSTOOL refactorings easier.
-
-This script reads the CROSSTOOL file and allows for querying of its fields.
-"""
-
-from absl import app
-from absl import flags
-from google.protobuf import text_format
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-
-flags.DEFINE_string("crosstool", None, "CROSSTOOL file path to be queried")
-flags.DEFINE_string("identifier", None,
-                    "Toolchain identifier to specify toolchain.")
-flags.DEFINE_string("print_field", None, "Field to be printed to stdout.")
-
-
-def main(unused_argv):
-  crosstool = crosstool_config_pb2.CrosstoolRelease()
-
-  crosstool_filename = flags.FLAGS.crosstool
-  identifier = flags.FLAGS.identifier
-  print_field = flags.FLAGS.print_field
-
-  if not crosstool_filename:
-    raise app.UsageError("ERROR crosstool unspecified")
-  if not identifier:
-    raise app.UsageError("ERROR identifier unspecified")
-
-  if not print_field:
-    raise app.UsageError("ERROR print_field unspecified")
-
-  with open(crosstool_filename, "r") as f:
-    text = f.read()
-    text_format.Merge(text, crosstool)
-
-  toolchain_found = False
-  for toolchain in crosstool.toolchain:
-    if toolchain.toolchain_identifier == identifier:
-      toolchain_found = True
-      if not print_field:
-        continue
-      for field, value in toolchain.ListFields():
-        if print_field == field.name:
-          print value
-
-  if not toolchain_found:
-    print "toolchain_identifier %s not found, valid values are:" % identifier
-    for toolchain in crosstool.toolchain:
-      print "  " + toolchain.toolchain_identifier
-
-
-if __name__ == "__main__":
-  app.run(main)
diff --git a/tools/migration/crosstool_to_starlark_lib.go b/tools/migration/crosstool_to_starlark_lib.go
deleted file mode 100644
index 4403a4b..0000000
--- a/tools/migration/crosstool_to_starlark_lib.go
+++ /dev/null
@@ -1,1419 +0,0 @@
-/*
-Package crosstooltostarlarklib provides the Transform method
-for conversion of a CROSSTOOL file to a Starlark rule.
-
-https://github.com/bazelbuild/bazel/issues/5380
-*/
-package crosstooltostarlarklib
-
-import (
-	"bytes"
-	"errors"
-	"fmt"
-	"sort"
-	"strings"
-
-	crosstoolpb "third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config_go_proto"
-)
-
-// CToolchainIdentifier is what we'll use to differ between CToolchains
-// If a CToolchain can be distinguished from the other CToolchains
-// by only one of the fields (eg if cpu is different for each CToolchain
-// then only that field will be set.
-type CToolchainIdentifier struct {
-	cpu      string
-	compiler string
-}
-
-// Writes the load statement for the cc_toolchain_config_lib
-func getCcToolchainConfigHeader() string {
-	return `load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
-    "action_config",
-    "artifact_name_pattern",
-    "env_entry",
-    "env_set",
-    "feature",
-    "feature_set",
-    "flag_group",
-    "flag_set",
-    "make_variable",
-    "tool",
-    "tool_path",
-    "variable_with_value",
-    "with_feature_set",
-)
-`
-}
-
-var allCompileActions = []string{
-	"c-compile",
-	"c++-compile",
-	"linkstamp-compile",
-	"assemble",
-	"preprocess-assemble",
-	"c++-header-parsing",
-	"c++-module-compile",
-	"c++-module-codegen",
-	"clif-match",
-	"lto-backend",
-}
-
-var allCppCompileActions = []string{
-	"c++-compile",
-	"linkstamp-compile",
-	"c++-header-parsing",
-	"c++-module-compile",
-	"c++-module-codegen",
-	"clif-match",
-}
-
-var preprocessorCompileActions = []string{
-	"c-compile",
-	"c++-compile",
-	"linkstamp-compile",
-	"preprocess-assemble",
-	"c++-header-parsing",
-	"c++-module-compile",
-	"clif-match",
-}
-
-var codegenCompileActions = []string{
-	"c-compile",
-	"c++-compile",
-	"linkstamp-compile",
-	"assemble",
-	"preprocess-assemble",
-	"c++-module-codegen",
-	"lto-backend",
-}
-
-var allLinkActions = []string{
-	"c++-link-executable",
-	"c++-link-dynamic-library",
-	"c++-link-nodeps-dynamic-library",
-}
-
-var actionNames = map[string]string{
-	"c-compile":                       "ACTION_NAMES.c_compile",
-	"c++-compile":                     "ACTION_NAMES.cpp_compile",
-	"linkstamp-compile":               "ACTION_NAMES.linkstamp_compile",
-	"cc-flags-make-variable":          "ACTION_NAMES.cc_flags_make_variable",
-	"c++-module-codegen":              "ACTION_NAMES.cpp_module_codegen",
-	"c++-header-parsing":              "ACTION_NAMES.cpp_header_parsing",
-	"c++-module-compile":              "ACTION_NAMES.cpp_module_compile",
-	"assemble":                        "ACTION_NAMES.assemble",
-	"preprocess-assemble":             "ACTION_NAMES.preprocess_assemble",
-	"lto-indexing":                    "ACTION_NAMES.lto_indexing",
-	"lto-backend":                     "ACTION_NAMES.lto_backend",
-	"c++-link-executable":             "ACTION_NAMES.cpp_link_executable",
-	"c++-link-dynamic-library":        "ACTION_NAMES.cpp_link_dynamic_library",
-	"c++-link-nodeps-dynamic-library": "ACTION_NAMES.cpp_link_nodeps_dynamic_library",
-	"c++-link-static-library":         "ACTION_NAMES.cpp_link_static_library",
-	"strip":                           "ACTION_NAMES.strip",
-	"objc-compile":                    "ACTION_NAMES.objc_compile",
-	"objc++-compile":                  "ACTION_NAMES.objcpp_compile",
-	"clif-match":                      "ACTION_NAMES.clif_match",
-// 	"objcopy_embed_data":              "ACTION_NAMES.objcopy_embed_data", // copybara-comment-this-out-please
-// 	"ld_embed_data":                   "ACTION_NAMES.ld_embed_data",      // copybara-comment-this-out-please
-}
-
-func getLoadActionsStmt() string {
-	return "load(\"@bazel_tools//tools/build_defs/cc:action_names.bzl\", \"ACTION_NAMES\")\n\n"
-}
-
-// Returns a map {toolchain_identifier : CToolchainIdentifier}
-func toolchainToCToolchainIdentifier(
-	crosstool *crosstoolpb.CrosstoolRelease) map[string]CToolchainIdentifier {
-	cpuToCompiler := make(map[string][]string)
-	compilerToCPU := make(map[string][]string)
-	var cpus []string
-	var compilers []string
-	var identifiers []string
-	res := make(map[string]CToolchainIdentifier)
-	for _, cToolchain := range crosstool.GetToolchain() {
-		cpu := cToolchain.GetTargetCpu()
-		compiler := cToolchain.GetCompiler()
-
-		cpuToCompiler[cpu] = append(cpuToCompiler[cpu], compiler)
-		compilerToCPU[compiler] = append(compilerToCPU[compiler], cpu)
-
-		cpus = append(cpus, cToolchain.GetTargetCpu())
-		compilers = append(compilers, cToolchain.GetCompiler())
-		identifiers = append(identifiers, cToolchain.GetToolchainIdentifier())
-	}
-
-	for i := range cpus {
-		if len(cpuToCompiler[cpus[i]]) == 1 {
-			// if cpu is unique among CToolchains, we don't need the compiler field
-			res[identifiers[i]] = CToolchainIdentifier{cpu: cpus[i], compiler: ""}
-		} else {
-			res[identifiers[i]] = CToolchainIdentifier{
-				cpu:      cpus[i],
-				compiler: compilers[i],
-			}
-		}
-	}
-	return res
-}
-
-func getConditionStatementForCToolchainIdentifier(identifier CToolchainIdentifier) string {
-	if identifier.compiler != "" {
-		return fmt.Sprintf(
-			"ctx.attr.cpu == \"%s\" and ctx.attr.compiler == \"%s\"",
-			identifier.cpu,
-			identifier.compiler)
-	}
-	return fmt.Sprintf("ctx.attr.cpu == \"%s\"", identifier.cpu)
-}
-
-func isArrayPrefix(prefix []string, arr []string) bool {
-	if len(prefix) > len(arr) {
-		return false
-	}
-	for i := 0; i < len(prefix); i++ {
-		if arr[i] != prefix[i] {
-			return false
-		}
-	}
-	return true
-}
-
-func isAllCompileActions(actions []string) (bool, []string) {
-	if isArrayPrefix(allCompileActions, actions) {
-		return true, actions[len(allCompileActions):]
-	}
-	return false, actions
-}
-
-func isAllCppCompileActions(actions []string) (bool, []string) {
-	if isArrayPrefix(allCppCompileActions, actions) {
-		return true, actions[len(allCppCompileActions):]
-	}
-	return false, actions
-}
-
-func isPreprocessorCompileActions(actions []string) (bool, []string) {
-	if isArrayPrefix(preprocessorCompileActions, actions) {
-		return true, actions[len(preprocessorCompileActions):]
-	}
-	return false, actions
-}
-
-func isCodegenCompileActions(actions []string) (bool, []string) {
-	if isArrayPrefix(codegenCompileActions, actions) {
-		return true, actions[len(codegenCompileActions):]
-	}
-	return false, actions
-}
-
-func isAllLinkActions(actions []string) (bool, []string) {
-	if isArrayPrefix(allLinkActions, actions) {
-		return true, actions[len(allLinkActions):]
-	}
-	return false, actions
-}
-
-func getActionNames(actions []string) []string {
-	var res []string
-	for _, el := range actions {
-		if name, ok := actionNames[el]; ok {
-			res = append(res, name)
-		} else {
-			res = append(res, "\""+el+"\"")
-		}
-	}
-	return res
-}
-
-func getListOfActions(name string, depth int) string {
-	var res []string
-	if name == "all_compile_actions" {
-		res = getActionNames(allCompileActions)
-	} else if name == "all_cpp_compile_actions" {
-		res = getActionNames(allCppCompileActions)
-	} else if name == "preprocessor_compile_actions" {
-		res = getActionNames(preprocessorCompileActions)
-	} else if name == "codegen_compile_actions" {
-		res = getActionNames(codegenCompileActions)
-	} else if name == "all_link_actions" {
-		res = getActionNames(allLinkActions)
-	}
-	stmt := fmt.Sprintf("%s%s = %s\n\n", getTabs(depth),
-		name, makeStringArr(res, depth /* isPlainString= */, false))
-	return stmt
-}
-
-func processActions(actions []string, depth int) []string {
-	var res []string
-	var ok bool
-	initLen := len(actions)
-	if ok, actions = isAllCompileActions(actions); ok {
-		res = append(res, "all_compile_actions")
-	}
-	if ok, actions = isAllCppCompileActions(actions); ok {
-		res = append(res, "all_cpp_compile_actions")
-	}
-	if ok, actions = isPreprocessorCompileActions(actions); ok {
-		res = append(res, "preprocessor_compile_actions")
-	}
-	if ok, actions = isCodegenCompileActions(actions); ok {
-		res = append(res, "codegen_actions")
-	}
-	if ok, actions = isAllLinkActions(actions); ok {
-		res = append(res, "all_link_actions")
-	}
-	if len(actions) != 0 {
-		actions = getActionNames(actions)
-		newDepth := depth + 1
-		if len(actions) != initLen {
-			newDepth++
-		}
-		res = append(res, makeStringArr(actions, newDepth /* isPlainString= */, false))
-	}
-	return res
-}
-
-func getUniqueValues(arr []string) []string {
-	valuesSet := make(map[string]bool)
-	for _, val := range arr {
-		valuesSet[val] = true
-	}
-	var uniques []string
-	for val, _ := range valuesSet {
-		uniques = append(uniques, val)
-	}
-	sort.Strings(uniques)
-	return uniques
-}
-
-func getRule(cToolchainIdentifiers map[string]CToolchainIdentifier,
-	allowedCompilers []string) string {
-	cpus := make(map[string]bool)
-	shouldUseCompilerAttribute := false
-	for _, val := range cToolchainIdentifiers {
-		cpus[val.cpu] = true
-		if val.compiler != "" {
-			shouldUseCompilerAttribute = true
-		}
-	}
-
-	var cpuValues []string
-	for cpu := range cpus {
-		cpuValues = append(cpuValues, cpu)
-	}
-
-	var args []string
-	sort.Strings(cpuValues)
-	args = append(args,
-		fmt.Sprintf(
-			`"cpu": attr.string(mandatory=True, values=["%s"]),`,
-			strings.Join(cpuValues, "\", \"")))
-	if shouldUseCompilerAttribute {
-		// If there are two CToolchains that share the cpu we need the compiler attribute
-		// for our cc_toolchain_config rule.
-		allowedCompilers = getUniqueValues(allowedCompilers)
-		args = append(args,
-			fmt.Sprintf(`"compiler": attr.string(mandatory=True, values=["%s"]),`,
-				strings.Join(allowedCompilers, "\", \"")))
-	}
-	return fmt.Sprintf(`cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        %s
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`, strings.Join(args, "\n        "))
-}
-
-func getImplHeader() string {
-	return "def _impl(ctx):\n"
-}
-
-func getStringStatement(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, field string,
-	depth int) string {
-
-	identifiers := getToolchainIdentifiers(crosstool)
-	var fieldValues []string
-	if field == "toolchain_identifier" {
-		fieldValues = getToolchainIdentifiers(crosstool)
-	} else if field == "host_system_name" {
-		fieldValues = getHostSystemNames(crosstool)
-	} else if field == "target_system_name" {
-		fieldValues = getTargetSystemNames(crosstool)
-	} else if field == "target_cpu" {
-		fieldValues = getTargetCpus(crosstool)
-	} else if field == "target_libc" {
-		fieldValues = getTargetLibcs(crosstool)
-	} else if field == "compiler" {
-		fieldValues = getCompilers(crosstool)
-	} else if field == "abi_version" {
-		fieldValues = getAbiVersions(crosstool)
-	} else if field == "abi_libc_version" {
-		fieldValues = getAbiLibcVersions(crosstool)
-	} else if field == "cc_target_os" {
-		fieldValues = getCcTargetOss(crosstool)
-	} else if field == "builtin_sysroot" {
-		fieldValues = getBuiltinSysroots(crosstool)
-	}
-
-	mappedValuesToIds := getMappedStringValuesToIdentifiers(identifiers, fieldValues)
-	return getAssignmentStatement(field, mappedValuesToIds, crosstool,
-		cToolchainIdentifiers, depth /* isPlainString= */, true /* shouldFail= */, true)
-}
-
-func getFeatures(crosstool *crosstoolpb.CrosstoolRelease) (
-	map[string][]string, map[string]map[string][]string, error) {
-	featureNameToFeature := make(map[string]map[string][]string)
-	toolchainToFeatures := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		id := toolchain.GetToolchainIdentifier()
-		if len(toolchain.GetFeature()) == 0 {
-			toolchainToFeatures[id] = []string{}
-		}
-		for _, feature := range toolchain.GetFeature() {
-			featureName := strings.ToLower(feature.GetName()) + "_feature"
-			featureName = strings.Replace(featureName, "+", "p", -1)
-			featureName = strings.Replace(featureName, ".", "_", -1)
-			featureName = strings.Replace(featureName, "-", "_", -1)
-			stringFeature, err := parseFeature(feature, 1)
-			if err != nil {
-				return nil, nil, fmt.Errorf(
-					"Error in feature '%s': %v", feature.GetName(), err)
-			}
-			if _, ok := featureNameToFeature[featureName]; !ok {
-				featureNameToFeature[featureName] = make(map[string][]string)
-			}
-			featureNameToFeature[featureName][stringFeature] = append(
-				featureNameToFeature[featureName][stringFeature], id)
-			toolchainToFeatures[id] = append(toolchainToFeatures[id], featureName)
-		}
-	}
-	return toolchainToFeatures, featureNameToFeature, nil
-}
-
-func getFeaturesDeclaration(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier,
-	featureNameToFeature map[string]map[string][]string, depth int) string {
-	var res []string
-	for featureName, featureStringToID := range featureNameToFeature {
-		res = append(res,
-			getAssignmentStatement(
-				featureName,
-				featureStringToID,
-				crosstool,
-				cToolchainIdentifiers,
-				depth,
-				/* isPlainString= */ false,
-				/* shouldFail= */ false))
-	}
-	return strings.Join(res, "")
-}
-
-func getFeaturesStmt(cToolchainIdentifiers map[string]CToolchainIdentifier,
-	toolchainToFeatures map[string][]string, depth int) string {
-	var res []string
-	arrToIdentifier := make(map[string][]string)
-	for id, features := range toolchainToFeatures {
-		arrayString := strings.Join(features, "{arrayFieldDelimiter}")
-		arrToIdentifier[arrayString] = append(arrToIdentifier[arrayString], id)
-	}
-	res = append(res,
-		getStringArrStatement(
-			"features",
-			arrToIdentifier,
-			cToolchainIdentifiers,
-			depth,
-			/* isPlainString= */ false))
-	return strings.Join(res, "\n")
-}
-
-func getActions(crosstool *crosstoolpb.CrosstoolRelease) (
-	map[string][]string, map[string]map[string][]string, error) {
-	actionNameToAction := make(map[string]map[string][]string)
-	toolchainToActions := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		id := toolchain.GetToolchainIdentifier()
-		var actionName string
-		if len(toolchain.GetActionConfig()) == 0 {
-			toolchainToActions[id] = []string{}
-		}
-		for _, action := range toolchain.GetActionConfig() {
-			if aName, ok := actionNames[action.GetActionName()]; ok {
-				actionName = aName
-			} else {
-				actionName = strings.ToLower(action.GetActionName())
-				actionName = strings.Replace(actionName, "+", "p", -1)
-				actionName = strings.Replace(actionName, ".", "_", -1)
-				actionName = strings.Replace(actionName, "-", "_", -1)
-			}
-			stringAction, err := parseAction(action, 1)
-			if err != nil {
-				return nil, nil, fmt.Errorf(
-					"Error in action_config '%s': %v", action.GetActionName(), err)
-			}
-			if _, ok := actionNameToAction[actionName]; !ok {
-				actionNameToAction[actionName] = make(map[string][]string)
-			}
-			actionNameToAction[actionName][stringAction] = append(
-				actionNameToAction[actionName][stringAction], id)
-			toolchainToActions[id] = append(
-				toolchainToActions[id],
-				strings.TrimPrefix(strings.ToLower(actionName), "action_names.")+"_action")
-		}
-	}
-	return toolchainToActions, actionNameToAction, nil
-}
-
-func getActionConfigsDeclaration(
-	crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier,
-	actionNameToAction map[string]map[string][]string, depth int) string {
-	var res []string
-	for actionName, actionStringToID := range actionNameToAction {
-		variableName := strings.TrimPrefix(strings.ToLower(actionName), "action_names.") + "_action"
-		res = append(res,
-			getAssignmentStatement(
-				variableName,
-				actionStringToID,
-				crosstool,
-				cToolchainIdentifiers,
-				depth,
-				/* isPlainString= */ false,
-				/* shouldFail= */ false))
-	}
-	return strings.Join(res, "")
-}
-
-func getActionConfigsStmt(
-	cToolchainIdentifiers map[string]CToolchainIdentifier,
-	toolchainToActions map[string][]string, depth int) string {
-	var res []string
-	arrToIdentifier := make(map[string][]string)
-	for id, actions := range toolchainToActions {
-		var arrayString string
-		arrayString = strings.Join(actions, "{arrayFieldDelimiter}")
-		arrToIdentifier[arrayString] = append(arrToIdentifier[arrayString], id)
-	}
-	res = append(res,
-		getStringArrStatement(
-			"action_configs",
-			arrToIdentifier,
-			cToolchainIdentifiers,
-			depth,
-			/* isPlainString= */ false))
-	return strings.Join(res, "\n")
-}
-
-func parseAction(action *crosstoolpb.CToolchain_ActionConfig, depth int) (string, error) {
-	actionName := action.GetActionName()
-	aName := ""
-	if val, ok := actionNames[actionName]; ok {
-		aName = val
-	} else {
-		aName = "\"" + action.GetActionName() + "\""
-	}
-	name := fmt.Sprintf("action_name = %s", aName)
-	fields := []string{name}
-	if action.GetEnabled() {
-		fields = append(fields, "enabled = True")
-	}
-	if len(action.GetFlagSet()) != 0 {
-		flagSets, err := parseFlagSets(action.GetFlagSet(), depth+1)
-		if err != nil {
-			return "", err
-		}
-		fields = append(fields, "flag_sets = "+flagSets)
-	}
-	if len(action.GetImplies()) != 0 {
-		implies := "implies = " +
-			makeStringArr(action.GetImplies(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, implies)
-	}
-	if len(action.GetTool()) != 0 {
-		tools := "tools = " + parseTools(action.GetTool(), depth+1)
-		fields = append(fields, tools)
-	}
-	return createObject("action_config", fields, depth), nil
-}
-
-func getStringArrStatement(attr string, arrValToIds map[string][]string,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, depth int, plainString bool) string {
-	var b bytes.Buffer
-	if len(arrValToIds) == 0 {
-		b.WriteString(fmt.Sprintf("%s%s = []\n", getTabs(depth), attr))
-	} else if len(arrValToIds) == 1 {
-		for value := range arrValToIds {
-			var arr []string
-			if value == "" {
-				arr = []string{}
-			} else if value == "None" {
-				b.WriteString(fmt.Sprintf("%s%s = None\n", getTabs(depth), attr))
-				break
-			} else {
-				arr = strings.Split(value, "{arrayFieldDelimiter}")
-			}
-			b.WriteString(
-				fmt.Sprintf(
-					"%s%s = %s\n",
-					getTabs(depth),
-					attr,
-					makeStringArr(arr, depth+1, plainString)))
-			break
-		}
-	} else {
-		first := true
-		var keys []string
-		for k := range arrValToIds {
-			keys = append(keys, k)
-		}
-		sort.Strings(keys)
-		for _, value := range keys {
-			ids := arrValToIds[value]
-			branch := "elif"
-			if first {
-				branch = "if"
-			}
-			first = false
-			var arr []string
-			if value == "" {
-				arr = []string{}
-			} else if value == "None" {
-				b.WriteString(
-					getIfStatement(
-						branch, ids, attr, "None", cToolchainIdentifiers,
-						depth /* isPlainString= */, true))
-				continue
-			} else {
-				arr = strings.Split(value, "{arrayFieldDelimiter}")
-			}
-			b.WriteString(
-				getIfStatement(branch, ids, attr,
-					makeStringArr(arr, depth+1, plainString),
-					cToolchainIdentifiers, depth /* isPlainString= */, false))
-		}
-		b.WriteString(fmt.Sprintf("%selse:\n%sfail(\"Unreachable\")\n", getTabs(depth), getTabs(depth+1)))
-	}
-	b.WriteString("\n")
-	return b.String()
-}
-
-func getStringArr(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, attr string, depth int) string {
-	var res []string
-	arrToIdentifier := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		id := toolchain.GetToolchainIdentifier()
-		arrayString := strings.Join(getArrField(attr, toolchain), "{arrayFieldDelimiter}")
-		arrToIdentifier[arrayString] = append(arrToIdentifier[arrayString], id)
-	}
-	statement := getStringArrStatement(attr, arrToIdentifier, cToolchainIdentifiers, depth /* isPlainString= */, true)
-	res = append(res, statement)
-	return strings.Join(res, "\n")
-}
-
-func getArrField(attr string, toolchain *crosstoolpb.CToolchain) []string {
-	var arr []string
-	if attr == "cxx_builtin_include_directories" {
-		arr = toolchain.GetCxxBuiltinIncludeDirectory()
-	}
-	return arr
-}
-
-func getTabs(depth int) string {
-	var res string
-	for i := 0; i < depth; i++ {
-		res = res + "    "
-	}
-	return res
-}
-
-func createObject(objtype string, fields []string, depth int) string {
-	if len(fields) == 0 {
-		return objtype + "()"
-	}
-	singleLine := objtype + "(" + strings.Join(fields, ", ") + ")"
-	if len(singleLine) < 60 {
-		return singleLine
-	}
-	return objtype +
-		"(\n" +
-		getTabs(depth+1) +
-		strings.Join(fields, ",\n"+getTabs(depth+1)) +
-		",\n" + getTabs(depth) +
-		")"
-}
-
-func getArtifactNamePatterns(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, depth int) string {
-	var res []string
-	artifactToIds := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		artifactNamePatterns := parseArtifactNamePatterns(
-			toolchain.GetArtifactNamePattern(),
-			depth)
-		artifactToIds[artifactNamePatterns] = append(
-			artifactToIds[artifactNamePatterns],
-			toolchain.GetToolchainIdentifier())
-	}
-	res = append(res,
-		getAssignmentStatement(
-			"artifact_name_patterns",
-			artifactToIds,
-			crosstool,
-			cToolchainIdentifiers,
-			depth,
-			/* isPlainString= */ false,
-			/* shouldFail= */ true))
-	return strings.Join(res, "\n")
-}
-
-func parseArtifactNamePatterns(
-	artifactNamePatterns []*crosstoolpb.CToolchain_ArtifactNamePattern, depth int) string {
-	var res []string
-	for _, pattern := range artifactNamePatterns {
-		res = append(res, parseArtifactNamePattern(pattern, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseArtifactNamePattern(
-	artifactNamePattern *crosstoolpb.CToolchain_ArtifactNamePattern, depth int) string {
-	categoryName := fmt.Sprintf("category_name = \"%s\"", artifactNamePattern.GetCategoryName())
-	prefix := fmt.Sprintf("prefix = \"%s\"", artifactNamePattern.GetPrefix())
-	extension := fmt.Sprintf("extension = \"%s\"", artifactNamePattern.GetExtension())
-	fields := []string{categoryName, prefix, extension}
-	return createObject("artifact_name_pattern", fields, depth)
-}
-
-func parseFeature(feature *crosstoolpb.CToolchain_Feature, depth int) (string, error) {
-	name := fmt.Sprintf("name = \"%s\"", feature.GetName())
-
-	fields := []string{name}
-	if feature.GetEnabled() {
-		fields = append(fields, "enabled = True")
-	}
-
-	if len(feature.GetFlagSet()) > 0 {
-		flagSets, err := parseFlagSets(feature.GetFlagSet(), depth+1)
-		if err != nil {
-			return "", err
-		}
-		fields = append(fields, "flag_sets = "+flagSets)
-	}
-	if len(feature.GetEnvSet()) > 0 {
-		envSets := "env_sets = " + parseEnvSets(feature.GetEnvSet(), depth+1)
-		fields = append(fields, envSets)
-	}
-	if len(feature.GetRequires()) > 0 {
-		requires := "requires = " + parseFeatureSets(feature.GetRequires(), depth+1)
-		fields = append(fields, requires)
-	}
-	if len(feature.GetImplies()) > 0 {
-		implies := "implies = " +
-			makeStringArr(feature.GetImplies(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, implies)
-	}
-	if len(feature.GetProvides()) > 0 {
-		provides := "provides = " +
-			makeStringArr(feature.GetProvides(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, provides)
-	}
-	return createObject("feature", fields, depth), nil
-}
-
-func parseFlagSets(flagSets []*crosstoolpb.CToolchain_FlagSet, depth int) (string, error) {
-	var res []string
-	for _, flagSet := range flagSets {
-		parsedFlagset, err := parseFlagSet(flagSet, depth+1)
-		if err != nil {
-			return "", err
-		}
-		res = append(res, parsedFlagset)
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false), nil
-}
-
-func parseFlagSet(flagSet *crosstoolpb.CToolchain_FlagSet, depth int) (string, error) {
-	var fields []string
-	if len(flagSet.GetAction()) > 0 {
-		actionArr := processActions(flagSet.GetAction(), depth)
-		actions := "actions = " + strings.Join(actionArr, " +\n"+getTabs(depth+2))
-		fields = append(fields, actions)
-	}
-	if len(flagSet.GetFlagGroup()) > 0 {
-		flagGroups, err := parseFlagGroups(flagSet.GetFlagGroup(), depth+1)
-		if err != nil {
-			return "", err
-		}
-		fields = append(fields, "flag_groups = "+flagGroups)
-	}
-	if len(flagSet.GetWithFeature()) > 0 {
-		withFeatures := "with_features = " +
-			parseWithFeatureSets(flagSet.GetWithFeature(), depth+1)
-		fields = append(fields, withFeatures)
-	}
-	return createObject("flag_set", fields, depth), nil
-}
-
-func parseFlagGroups(flagGroups []*crosstoolpb.CToolchain_FlagGroup, depth int) (string, error) {
-	var res []string
-	for _, flagGroup := range flagGroups {
-		flagGroupString, err := parseFlagGroup(flagGroup, depth+1)
-		if err != nil {
-			return "", err
-		}
-		res = append(res, flagGroupString)
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false), nil
-}
-
-func parseFlagGroup(flagGroup *crosstoolpb.CToolchain_FlagGroup, depth int) (string, error) {
-	var res []string
-	if len(flagGroup.GetFlag()) != 0 {
-		res = append(res, "flags = "+makeStringArr(flagGroup.GetFlag(), depth+1, true))
-	}
-	if flagGroup.GetIterateOver() != "" {
-		res = append(res, fmt.Sprintf("iterate_over = \"%s\"", flagGroup.GetIterateOver()))
-	}
-	if len(flagGroup.GetFlagGroup()) != 0 {
-		flagGroupString, err := parseFlagGroups(flagGroup.GetFlagGroup(), depth+1)
-		if err != nil {
-			return "", err
-		}
-		res = append(res, "flag_groups = "+flagGroupString)
-	}
-	if len(flagGroup.GetExpandIfAllAvailable()) > 1 {
-		return "", errors.New("Flag group must not have more than one 'expand_if_all_available' field")
-	}
-	if len(flagGroup.GetExpandIfAllAvailable()) != 0 {
-		res = append(res,
-			fmt.Sprintf(
-				"expand_if_available = \"%s\"",
-				flagGroup.GetExpandIfAllAvailable()[0]))
-	}
-	if len(flagGroup.GetExpandIfNoneAvailable()) > 1 {
-		return "", errors.New("Flag group must not have more than one 'expand_if_none_available' field")
-	}
-	if len(flagGroup.GetExpandIfNoneAvailable()) != 0 {
-		res = append(res,
-			fmt.Sprintf(
-				"expand_if_not_available = \"%s\"",
-				flagGroup.GetExpandIfNoneAvailable()[0]))
-	}
-	if flagGroup.GetExpandIfTrue() != "" {
-		res = append(res, fmt.Sprintf("expand_if_true = \"%s\"",
-			flagGroup.GetExpandIfTrue()))
-	}
-	if flagGroup.GetExpandIfFalse() != "" {
-		res = append(res, fmt.Sprintf("expand_if_false = \"%s\"",
-			flagGroup.GetExpandIfFalse()))
-	}
-	if flagGroup.GetExpandIfEqual() != nil {
-		res = append(res,
-			"expand_if_equal = "+parseVariableWithValue(
-				flagGroup.GetExpandIfEqual(), depth+1))
-	}
-	return createObject("flag_group", res, depth), nil
-}
-
-func parseVariableWithValue(variable *crosstoolpb.CToolchain_VariableWithValue, depth int) string {
-	variableName := fmt.Sprintf("name = \"%s\"", variable.GetVariable())
-	value := fmt.Sprintf("value = \"%s\"", variable.GetValue())
-	return createObject("variable_with_value", []string{variableName, value}, depth)
-}
-
-func getToolPaths(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, depth int) string {
-	var res []string
-	toolPathsToIds := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		toolPaths := parseToolPaths(toolchain.GetToolPath(), depth)
-		toolPathsToIds[toolPaths] = append(
-			toolPathsToIds[toolPaths],
-			toolchain.GetToolchainIdentifier())
-	}
-	res = append(res,
-		getAssignmentStatement(
-			"tool_paths",
-			toolPathsToIds,
-			crosstool,
-			cToolchainIdentifiers,
-			depth,
-			/* isPlainString= */ false,
-			/* shouldFail= */ true))
-	return strings.Join(res, "\n")
-}
-
-func parseToolPaths(toolPaths []*crosstoolpb.ToolPath, depth int) string {
-	var res []string
-	for _, toolPath := range toolPaths {
-		res = append(res, parseToolPath(toolPath, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseToolPath(toolPath *crosstoolpb.ToolPath, depth int) string {
-	name := fmt.Sprintf("name = \"%s\"", toolPath.GetName())
-	path := toolPath.GetPath()
-	if path == "" {
-		path = "NOT_USED"
-	}
-	path = fmt.Sprintf("path = \"%s\"", path)
-	return createObject("tool_path", []string{name, path}, depth)
-}
-
-func getMakeVariables(crosstool *crosstoolpb.CrosstoolRelease,
-	cToolchainIdentifiers map[string]CToolchainIdentifier, depth int) string {
-	var res []string
-	makeVariablesToIds := make(map[string][]string)
-	for _, toolchain := range crosstool.GetToolchain() {
-		makeVariables := parseMakeVariables(toolchain.GetMakeVariable(), depth)
-		makeVariablesToIds[makeVariables] = append(
-			makeVariablesToIds[makeVariables],
-			toolchain.GetToolchainIdentifier())
-	}
-	res = append(res,
-		getAssignmentStatement(
-			"make_variables",
-			makeVariablesToIds,
-			crosstool,
-			cToolchainIdentifiers,
-			depth,
-			/* isPlainString= */ false,
-			/* shouldFail= */ true))
-	return strings.Join(res, "\n")
-}
-
-func parseMakeVariables(makeVariables []*crosstoolpb.MakeVariable, depth int) string {
-	var res []string
-	for _, makeVariable := range makeVariables {
-		res = append(res, parseMakeVariable(makeVariable, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseMakeVariable(makeVariable *crosstoolpb.MakeVariable, depth int) string {
-	name := fmt.Sprintf("name = \"%s\"", makeVariable.GetName())
-	value := fmt.Sprintf("value = \"%s\"", makeVariable.GetValue())
-	return createObject("make_variable", []string{name, value}, depth)
-}
-
-func parseTools(tools []*crosstoolpb.CToolchain_Tool, depth int) string {
-	var res []string
-	for _, tool := range tools {
-		res = append(res, parseTool(tool, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseTool(tool *crosstoolpb.CToolchain_Tool, depth int) string {
-	toolPath := "path = \"NOT_USED\""
-	if tool.GetToolPath() != "" {
-		toolPath = fmt.Sprintf("path = \"%s\"", tool.GetToolPath())
-	}
-	fields := []string{toolPath}
-	if len(tool.GetWithFeature()) != 0 {
-		withFeatures := "with_features = " + parseWithFeatureSets(tool.GetWithFeature(), depth+1)
-		fields = append(fields, withFeatures)
-	}
-	if len(tool.GetExecutionRequirement()) != 0 {
-		executionRequirements := "execution_requirements = " +
-			makeStringArr(tool.GetExecutionRequirement(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, executionRequirements)
-	}
-	return createObject("tool", fields, depth)
-}
-
-func parseEnvEntries(envEntries []*crosstoolpb.CToolchain_EnvEntry, depth int) string {
-	var res []string
-	for _, envEntry := range envEntries {
-		res = append(res, parseEnvEntry(envEntry, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseEnvEntry(envEntry *crosstoolpb.CToolchain_EnvEntry, depth int) string {
-	key := fmt.Sprintf("key = \"%s\"", envEntry.GetKey())
-	value := fmt.Sprintf("value = \"%s\"", envEntry.GetValue())
-	return createObject("env_entry", []string{key, value}, depth)
-}
-
-func parseWithFeatureSets(withFeatureSets []*crosstoolpb.CToolchain_WithFeatureSet,
-	depth int) string {
-	var res []string
-	for _, withFeature := range withFeatureSets {
-		res = append(res, parseWithFeatureSet(withFeature, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseWithFeatureSet(withFeature *crosstoolpb.CToolchain_WithFeatureSet,
-	depth int) string {
-	var fields []string
-	if len(withFeature.GetFeature()) != 0 {
-		features := "features = " +
-			makeStringArr(withFeature.GetFeature(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, features)
-	}
-	if len(withFeature.GetNotFeature()) != 0 {
-		notFeatures := "not_features = " +
-			makeStringArr(withFeature.GetNotFeature(), depth+1 /* isPlainString= */, true)
-		fields = append(fields, notFeatures)
-	}
-	return createObject("with_feature_set", fields, depth)
-}
-
-func parseEnvSets(envSets []*crosstoolpb.CToolchain_EnvSet, depth int) string {
-	var res []string
-	for _, envSet := range envSets {
-		envSetString := parseEnvSet(envSet, depth+1)
-		res = append(res, envSetString)
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseEnvSet(envSet *crosstoolpb.CToolchain_EnvSet, depth int) string {
-	actionsStatement := processActions(envSet.GetAction(), depth)
-	actions := "actions = " + strings.Join(actionsStatement, " +\n"+getTabs(depth+2))
-	fields := []string{actions}
-	if len(envSet.GetEnvEntry()) != 0 {
-		envEntries := "env_entries = " + parseEnvEntries(envSet.GetEnvEntry(), depth+1)
-		fields = append(fields, envEntries)
-	}
-	if len(envSet.GetWithFeature()) != 0 {
-		withFeatures := "with_features = " + parseWithFeatureSets(envSet.GetWithFeature(), depth+1)
-		fields = append(fields, withFeatures)
-	}
-	return createObject("env_set", fields, depth)
-}
-
-func parseFeatureSets(featureSets []*crosstoolpb.CToolchain_FeatureSet, depth int) string {
-	var res []string
-	for _, featureSet := range featureSets {
-		res = append(res, parseFeatureSet(featureSet, depth+1))
-	}
-	return makeStringArr(res, depth /* isPlainString= */, false)
-}
-
-func parseFeatureSet(featureSet *crosstoolpb.CToolchain_FeatureSet, depth int) string {
-	features := "features = " +
-		makeStringArr(featureSet.GetFeature(), depth+1 /* isPlainString= */, true)
-	return createObject("feature_set", []string{features}, depth)
-}
-
-// Takes in a list of string elements and returns a string that represents
-// an array :
-//     [
-//         "element1",
-//         "element2",
-//     ]
-// The isPlainString argument tells us whether the input elements should be
-// treated as string (eg, flags), or not (eg, variable names)
-func makeStringArr(arr []string, depth int, isPlainString bool) string {
-	if len(arr) == 0 {
-		return "[]"
-	}
-	var escapedArr []string
-	for _, el := range arr {
-		if isPlainString {
-			escapedArr = append(escapedArr, strings.Replace(el, "\"", "\\\"", -1))
-		} else {
-			escapedArr = append(escapedArr, el)
-		}
-	}
-	addQuote := ""
-	if isPlainString {
-		addQuote = "\""
-	}
-	singleLine := "[" + addQuote + strings.Join(escapedArr, addQuote+", "+addQuote) + addQuote + "]"
-	if len(singleLine) < 60 {
-		return singleLine
-	}
-	return "[\n" +
-		getTabs(depth+1) +
-		addQuote +
-		strings.Join(escapedArr, addQuote+",\n"+getTabs(depth+1)+addQuote) +
-		addQuote +
-		",\n" +
-		getTabs(depth) +
-		"]"
-}
-
-// Returns a string that represents a value assignment
-// (eg if ctx.attr.cpu == "linux":
-//         compiler = "llvm"
-//     elif ctx.attr.cpu == "windows":
-//         compiler = "mingw"
-//     else:
-//         fail("Unreachable")
-func getAssignmentStatement(field string, valToIds map[string][]string,
-	crosstool *crosstoolpb.CrosstoolRelease,
-	toCToolchainIdentifier map[string]CToolchainIdentifier,
-	depth int, isPlainString, shouldFail bool) string {
-	var b bytes.Buffer
-	if len(valToIds) <= 1 {
-		// if there is only one possible value for this field, we don't need if statements
-		for val := range valToIds {
-			if val != "None" && isPlainString {
-				val = "\"" + val + "\""
-			}
-			b.WriteString(fmt.Sprintf("%s%s = %s\n", getTabs(depth), field, val))
-			break
-		}
-	} else {
-		first := true
-		var keys []string
-		for k := range valToIds {
-			keys = append(keys, k)
-		}
-		sort.Strings(keys)
-		for _, value := range keys {
-			ids := valToIds[value]
-			branch := "elif"
-			if first {
-				branch = "if"
-			}
-			b.WriteString(
-				getIfStatement(branch, ids, field, value,
-					toCToolchainIdentifier, depth, isPlainString))
-			first = false
-		}
-		if shouldFail {
-			b.WriteString(
-				fmt.Sprintf(
-					"%selse:\n%sfail(\"Unreachable\")\n",
-					getTabs(depth), getTabs(depth+1)))
-		} else {
-			b.WriteString(
-				fmt.Sprintf(
-					"%selse:\n%s%s = None\n",
-					getTabs(depth), getTabs(depth+1), field))
-		}
-	}
-	b.WriteString("\n")
-	return b.String()
-}
-
-func getCPUToCompilers(identifiers []CToolchainIdentifier) map[string][]string {
-	res := make(map[string][]string)
-	for _, identifier := range identifiers {
-		if identifier.compiler != "" {
-			res[identifier.cpu] = append(res[identifier.cpu], identifier.compiler)
-		}
-	}
-	return res
-}
-
-func getIfStatement(ifOrElseIf string, identifiers []string, field, val string,
-	toCToolchainIdentifier map[string]CToolchainIdentifier, depth int,
-	isPlainString bool) string {
-	usedStmts := make(map[string]bool)
-	if val != "None" && isPlainString {
-		val = "\"" + val + "\""
-	}
-	var cToolchainIdentifiers []CToolchainIdentifier
-	for _, value := range toCToolchainIdentifier {
-		cToolchainIdentifiers = append(cToolchainIdentifiers, value)
-	}
-	cpuToCompilers := getCPUToCompilers(cToolchainIdentifiers)
-	countCpus := make(map[string]int)
-	var conditions []string
-	for _, id := range identifiers {
-		identifier := toCToolchainIdentifier[id]
-		stmt := getConditionStatementForCToolchainIdentifier(identifier)
-		if _, ok := usedStmts[stmt]; !ok {
-			conditions = append(conditions, stmt)
-			usedStmts[stmt] = true
-			if identifier.compiler != "" {
-				countCpus[identifier.cpu]++
-			}
-		}
-	}
-
-	var compressedConditions []string
-	usedStmtsOptimized := make(map[string]bool)
-	for _, id := range identifiers {
-		identifier := toCToolchainIdentifier[id]
-		var stmt string
-		if _, ok := countCpus[identifier.cpu]; ok {
-			if countCpus[identifier.cpu] == len(cpuToCompilers[identifier.cpu]) {
-				stmt = getConditionStatementForCToolchainIdentifier(
-					CToolchainIdentifier{cpu: identifier.cpu, compiler: ""})
-			} else {
-				stmt = getConditionStatementForCToolchainIdentifier(identifier)
-			}
-		} else {
-			stmt = getConditionStatementForCToolchainIdentifier(identifier)
-		}
-		if _, ok := usedStmtsOptimized[stmt]; !ok {
-			compressedConditions = append(compressedConditions, stmt)
-			usedStmtsOptimized[stmt] = true
-		}
-	}
-
-	sort.Strings(compressedConditions)
-	val = strings.Join(strings.Split(val, "\n"+getTabs(depth)), "\n"+getTabs(depth+1))
-	return fmt.Sprintf(`%s%s %s:
-%s%s = %s
-`, getTabs(depth),
-		ifOrElseIf,
-		"("+strings.Join(compressedConditions, "\n"+getTabs(depth+1)+"or ")+")",
-		getTabs(depth+1),
-		field,
-		val)
-}
-
-func getToolchainIdentifiers(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetToolchainIdentifier())
-	}
-	return res
-}
-
-func getHostSystemNames(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetHostSystemName())
-	}
-	return res
-}
-
-func getTargetSystemNames(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetTargetSystemName())
-	}
-	return res
-}
-
-func getTargetCpus(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetTargetCpu())
-	}
-	return res
-}
-
-func getTargetLibcs(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetTargetLibc())
-	}
-	return res
-}
-
-func getCompilers(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetCompiler())
-	}
-	return res
-}
-
-func getAbiVersions(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetAbiVersion())
-	}
-	return res
-}
-
-func getAbiLibcVersions(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		res = append(res, toolchain.GetAbiLibcVersion())
-	}
-	return res
-}
-
-func getCcTargetOss(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		targetOS := "None"
-		if toolchain.GetCcTargetOs() != "" {
-			targetOS = toolchain.GetCcTargetOs()
-		}
-		res = append(res, targetOS)
-	}
-	return res
-}
-
-func getBuiltinSysroots(crosstool *crosstoolpb.CrosstoolRelease) []string {
-	var res []string
-	for _, toolchain := range crosstool.GetToolchain() {
-		sysroot := "None"
-		if toolchain.GetBuiltinSysroot() != "" {
-			sysroot = toolchain.GetBuiltinSysroot()
-		}
-		res = append(res, sysroot)
-	}
-	return res
-}
-
-func getMappedStringValuesToIdentifiers(identifiers, fields []string) map[string][]string {
-	res := make(map[string][]string)
-	for i := range identifiers {
-		res[fields[i]] = append(res[fields[i]], identifiers[i])
-	}
-	return res
-}
-
-func getReturnStatement() string {
-	return `
-    out = ctx.actions.declare_file(ctx.label.name)
-    ctx.actions.write(out, "Fake executable")
-    return [
-        cc_common.create_cc_toolchain_config_info(
-            ctx = ctx,
-            features = features,
-            action_configs = action_configs,
-            artifact_name_patterns = artifact_name_patterns,
-            cxx_builtin_include_directories = cxx_builtin_include_directories,
-            toolchain_identifier = toolchain_identifier,
-            host_system_name = host_system_name,
-            target_system_name = target_system_name,
-            target_cpu = target_cpu,
-            target_libc = target_libc,
-            compiler = compiler,
-            abi_version = abi_version,
-            abi_libc_version = abi_libc_version,
-            tool_paths = tool_paths,
-            make_variables = make_variables,
-            builtin_sysroot = builtin_sysroot,
-            cc_target_os = cc_target_os
-        ),
-        DefaultInfo(
-            executable = out,
-        ),
-    ]
-`
-}
-
-// Transform writes a cc_toolchain_config rule functionally equivalent to the
-// CROSSTOOL file.
-func Transform(crosstool *crosstoolpb.CrosstoolRelease) (string, error) {
-	var b bytes.Buffer
-
-	cToolchainIdentifiers := toolchainToCToolchainIdentifier(crosstool)
-
-	toolchainToFeatures, featureNameToFeature, err := getFeatures(crosstool)
-	if err != nil {
-		return "", err
-	}
-
-	toolchainToActions, actionNameToAction, err := getActions(crosstool)
-	if err != nil {
-		return "", err
-	}
-
-	header := getCcToolchainConfigHeader()
-	if _, err := b.WriteString(header); err != nil {
-		return "", err
-	}
-
-	loadActionsStmt := getLoadActionsStmt()
-	if _, err := b.WriteString(loadActionsStmt); err != nil {
-		return "", err
-	}
-
-	implHeader := getImplHeader()
-	if _, err := b.WriteString(implHeader); err != nil {
-		return "", err
-	}
-
-	stringFields := []string{
-		"toolchain_identifier",
-		"host_system_name",
-		"target_system_name",
-		"target_cpu",
-		"target_libc",
-		"compiler",
-		"abi_version",
-		"abi_libc_version",
-		"cc_target_os",
-		"builtin_sysroot",
-	}
-
-	for _, stringField := range stringFields {
-		stmt := getStringStatement(crosstool, cToolchainIdentifiers, stringField, 1)
-		if _, err := b.WriteString(stmt); err != nil {
-			return "", err
-		}
-	}
-
-	listsOfActions := []string{
-		"all_compile_actions",
-		"all_cpp_compile_actions",
-		"preprocessor_compile_actions",
-		"codegen_compile_actions",
-		"all_link_actions",
-	}
-
-	for _, listOfActions := range listsOfActions {
-		actions := getListOfActions(listOfActions, 1)
-		if _, err := b.WriteString(actions); err != nil {
-			return "", err
-		}
-	}
-
-	actionConfigDeclaration := getActionConfigsDeclaration(
-		crosstool, cToolchainIdentifiers, actionNameToAction, 1)
-	if _, err := b.WriteString(actionConfigDeclaration); err != nil {
-		return "", err
-	}
-
-	actionConfigStatement := getActionConfigsStmt(
-		cToolchainIdentifiers, toolchainToActions, 1)
-	if _, err := b.WriteString(actionConfigStatement); err != nil {
-		return "", err
-	}
-
-	featureDeclaration := getFeaturesDeclaration(
-		crosstool, cToolchainIdentifiers, featureNameToFeature, 1)
-	if _, err := b.WriteString(featureDeclaration); err != nil {
-		return "", err
-	}
-
-	featuresStatement := getFeaturesStmt(
-		cToolchainIdentifiers, toolchainToFeatures, 1)
-	if _, err := b.WriteString(featuresStatement); err != nil {
-		return "", err
-	}
-
-	includeDirectories := getStringArr(
-		crosstool, cToolchainIdentifiers, "cxx_builtin_include_directories", 1)
-	if _, err := b.WriteString(includeDirectories); err != nil {
-		return "", err
-	}
-
-	artifactNamePatterns := getArtifactNamePatterns(
-		crosstool, cToolchainIdentifiers, 1)
-	if _, err := b.WriteString(artifactNamePatterns); err != nil {
-		return "", err
-	}
-
-	makeVariables := getMakeVariables(crosstool, cToolchainIdentifiers, 1)
-	if _, err := b.WriteString(makeVariables); err != nil {
-		return "", err
-	}
-
-	toolPaths := getToolPaths(crosstool, cToolchainIdentifiers, 1)
-	if _, err := b.WriteString(toolPaths); err != nil {
-		return "", err
-	}
-
-	if _, err := b.WriteString(getReturnStatement()); err != nil {
-		return "", err
-	}
-
-	rule := getRule(cToolchainIdentifiers, getCompilers(crosstool))
-	if _, err := b.WriteString(rule); err != nil {
-		return "", err
-	}
-
-	return b.String(), nil
-}
diff --git a/tools/migration/crosstool_to_starlark_lib_test.go b/tools/migration/crosstool_to_starlark_lib_test.go
deleted file mode 100644
index a5db02f..0000000
--- a/tools/migration/crosstool_to_starlark_lib_test.go
+++ /dev/null
@@ -1,1756 +0,0 @@
-package crosstooltostarlarklib
-
-import (
-	"fmt"
-	"strings"
-	"testing"
-
-	"log"
-	crosstoolpb "third_party/com/github/bazelbuild/bazel/src/main/protobuf/crosstool_config_go_proto"
-	"github.com/golang/protobuf/proto"
-)
-
-func makeCToolchainString(lines []string) string {
-	return fmt.Sprintf(`toolchain {
-  %s
-}`, strings.Join(lines, "\n  "))
-}
-
-func makeCrosstool(CToolchains []string) *crosstoolpb.CrosstoolRelease {
-	crosstool := &crosstoolpb.CrosstoolRelease{}
-	requiredFields := []string{
-		"major_version: '0'",
-		"minor_version: '0'",
-		"default_target_cpu: 'cpu'",
-	}
-	CToolchains = append(CToolchains, requiredFields...)
-	if err := proto.UnmarshalText(strings.Join(CToolchains, "\n"), crosstool); err != nil {
-		log.Fatalf("Failed to parse CROSSTOOL:", err)
-	}
-	return crosstool
-}
-
-func getSimpleCToolchain(id string) string {
-	lines := []string{
-		"toolchain_identifier: 'id-" + id + "'",
-		"host_system_name: 'host-" + id + "'",
-		"target_system_name: 'target-" + id + "'",
-		"target_cpu: 'cpu-" + id + "'",
-		"compiler: 'compiler-" + id + "'",
-		"target_libc: 'libc-" + id + "'",
-		"abi_version: 'version-" + id + "'",
-		"abi_libc_version: 'libc_version-" + id + "'",
-	}
-	return makeCToolchainString(lines)
-}
-
-func getCToolchain(id, cpu, compiler string, extraLines []string) string {
-	lines := []string{
-		"toolchain_identifier: '" + id + "'",
-		"host_system_name: 'host'",
-		"target_system_name: 'target'",
-		"target_cpu: '" + cpu + "'",
-		"compiler: '" + compiler + "'",
-		"target_libc: 'libc'",
-		"abi_version: 'version'",
-		"abi_libc_version: 'libc_version'",
-	}
-	lines = append(lines, extraLines...)
-	return makeCToolchainString(lines)
-}
-
-func TestStringFieldsConditionStatement(t *testing.T) {
-	toolchain1 := getSimpleCToolchain("1")
-	toolchain2 := getSimpleCToolchain("2")
-	toolchains := []string{toolchain1, toolchain2}
-	crosstool := makeCrosstool(toolchains)
-
-	testCases := []struct {
-		field        string
-		expectedText string
-	}{
-		{field: "toolchain_identifier",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        toolchain_identifier = "id-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        toolchain_identifier = "id-2"
-    else:
-        fail("Unreachable")`},
-		{field: "host_system_name",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        host_system_name = "host-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        host_system_name = "host-2"
-    else:
-        fail("Unreachable")`},
-		{field: "target_system_name",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        target_system_name = "target-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        target_system_name = "target-2"
-    else:
-        fail("Unreachable")`},
-		{field: "target_cpu",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        target_cpu = "cpu-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        target_cpu = "cpu-2"
-    else:
-        fail("Unreachable")`},
-		{field: "target_libc",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        target_libc = "libc-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        target_libc = "libc-2"
-    else:
-        fail("Unreachable")`},
-		{field: "compiler",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        compiler = "compiler-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        compiler = "compiler-2"
-    else:
-        fail("Unreachable")`},
-		{field: "abi_version",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        abi_version = "version-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        abi_version = "version-2"
-    else:
-        fail("Unreachable")`},
-		{field: "abi_libc_version",
-			expectedText: `
-    if (ctx.attr.cpu == "cpu-1"):
-        abi_libc_version = "libc_version-1"
-    elif (ctx.attr.cpu == "cpu-2"):
-        abi_libc_version = "libc_version-2"
-    else:
-        fail("Unreachable")`}}
-
-	got, err := Transform(crosstool)
-	if err != nil {
-		t.Fatalf("CROSSTOOL conversion failed: %v", err)
-	}
-
-	failed := false
-	for _, tc := range testCases {
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			failed = true
-		}
-	}
-	if failed {
-		t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-			strings.Join(toolchains, "\n"), got)
-	}
-}
-
-func TestConditionsSameCpu(t *testing.T) {
-	toolchainAA := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainAB := getCToolchain("2", "cpuA", "compilerB", []string{})
-	toolchains := []string{toolchainAA, toolchainAB}
-	crosstool := makeCrosstool(toolchains)
-
-	testCases := []struct {
-		field        string
-		expectedText string
-	}{
-		{field: "toolchain_identifier",
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerA"):
-        toolchain_identifier = "1"
-    elif (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerB"):
-        toolchain_identifier = "2"
-    else:
-        fail("Unreachable")`},
-		{field: "host_system_name",
-			expectedText: `
-    host_system_name = "host"`},
-		{field: "target_system_name",
-			expectedText: `
-    target_system_name = "target"`},
-		{field: "target_cpu",
-			expectedText: `
-    target_cpu = "cpuA"`},
-		{field: "target_libc",
-			expectedText: `
-    target_libc = "libc"`},
-		{field: "compiler",
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerA"):
-        compiler = "compilerA"
-    elif (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerB"):
-        compiler = "compilerB"
-    else:
-        fail("Unreachable")`},
-		{field: "abi_version",
-			expectedText: `
-    abi_version = "version"`},
-		{field: "abi_libc_version",
-			expectedText: `
-    abi_libc_version = "libc_version"`}}
-
-	got, err := Transform(crosstool)
-	if err != nil {
-		t.Fatalf("CROSSTOOL conversion failed: %v", err)
-	}
-
-	failed := false
-	for _, tc := range testCases {
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			failed = true
-		}
-	}
-	if failed {
-		t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-			strings.Join(toolchains, "\n"), got)
-	}
-}
-
-func TestConditionsSameCompiler(t *testing.T) {
-	toolchainAA := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainBA := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchains := []string{toolchainAA, toolchainBA}
-	crosstool := makeCrosstool(toolchains)
-
-	testCases := []struct {
-		field        string
-		expectedText string
-	}{
-		{field: "toolchain_identifier",
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        toolchain_identifier = "1"
-    elif (ctx.attr.cpu == "cpuB"):
-        toolchain_identifier = "2"
-    else:
-        fail("Unreachable")`},
-		{field: "target_cpu",
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        target_cpu = "cpuA"
-    elif (ctx.attr.cpu == "cpuB"):
-        target_cpu = "cpuB"
-    else:
-        fail("Unreachable")`},
-		{field: "compiler",
-			expectedText: `
-    compiler = "compilerA"`}}
-
-	got, err := Transform(crosstool)
-	if err != nil {
-		t.Fatalf("CROSSTOOL conversion failed: %v", err)
-	}
-
-	failed := false
-	for _, tc := range testCases {
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			failed = true
-		}
-	}
-	if failed {
-		t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-			strings.Join(toolchains, "\n"), got)
-	}
-}
-
-func TestNonMandatoryStrings(t *testing.T) {
-	toolchainAA := getCToolchain("1", "cpuA", "compilerA", []string{"cc_target_os: 'osA'"})
-	toolchainBB := getCToolchain("2", "cpuB", "compilerB", []string{})
-	toolchains := []string{toolchainAA, toolchainBB}
-	crosstool := makeCrosstool(toolchains)
-
-	testCases := []struct {
-		field        string
-		expectedText string
-	}{
-		{field: "cc_target_os",
-			expectedText: `
-    if (ctx.attr.cpu == "cpuB"):
-        cc_target_os = None
-    elif (ctx.attr.cpu == "cpuA"):
-        cc_target_os = "osA"
-    else:
-        fail("Unreachable")`},
-		{field: "builtin_sysroot",
-			expectedText: `
-    builtin_sysroot = None`}}
-
-	got, err := Transform(crosstool)
-	if err != nil {
-		t.Fatalf("CROSSTOOL conversion failed: %v", err)
-	}
-
-	failed := false
-	for _, tc := range testCases {
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			failed = true
-		}
-	}
-	if failed {
-		t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-			strings.Join(toolchains, "\n"), got)
-	}
-}
-
-func TestBuiltinIncludeDirectories(t *testing.T) {
-	toolchainAA := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainBA := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainCA := getCToolchain("3", "cpuC", "compilerA",
-		[]string{"cxx_builtin_include_directory: 'dirC'"})
-	toolchainCB := getCToolchain("4", "cpuC", "compilerB",
-		[]string{"cxx_builtin_include_directory: 'dirC'",
-			"cxx_builtin_include_directory: 'dirB'"})
-	toolchainDA := getCToolchain("5", "cpuD", "compilerA",
-		[]string{"cxx_builtin_include_directory: 'dirC'"})
-
-	toolchainsEmpty := []string{toolchainAA, toolchainBA}
-
-	toolchainsOneNonempty := []string{toolchainAA, toolchainBA, toolchainCA}
-
-	toolchainsSameNonempty := []string{toolchainCA, toolchainDA}
-
-	allToolchains := []string{toolchainAA, toolchainBA, toolchainCA, toolchainCB, toolchainDA}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "cxx_builtin_include_directories",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    cxx_builtin_include_directories = []`},
-		{field: "cxx_builtin_include_directories",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        cxx_builtin_include_directories = []
-    elif (ctx.attr.cpu == "cpuC"):
-        cxx_builtin_include_directories = ["dirC"]
-    else:
-        fail("Unreachable")`},
-		{field: "cxx_builtin_include_directories",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    cxx_builtin_include_directories = ["dirC"]`},
-		{field: "cxx_builtin_include_directories",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        cxx_builtin_include_directories = []
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuD"):
-        cxx_builtin_include_directories = ["dirC"]
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        cxx_builtin_include_directories = ["dirC", "dirB"]`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestMakeVariables(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainA1 := getCToolchain("3", "cpuC", "compilerA",
-		[]string{"make_variable {name: 'A', value: 'a/b/c'}"})
-	toolchainA2 := getCToolchain("4", "cpuC", "compilerB",
-		[]string{"make_variable {name: 'A', value: 'a/b/c'}"})
-	toolchainAB := getCToolchain("5", "cpuC", "compilerC",
-		[]string{"make_variable {name: 'A', value: 'a/b/c'}",
-			"make_variable {name: 'B', value: 'a/b/c'}"})
-	toolchainBA := getCToolchain("6", "cpuD", "compilerA",
-		[]string{"make_variable {name: 'B', value: 'a/b/c'}",
-			"make_variable {name: 'A', value: 'a b c'}"})
-
-	toolchainsEmpty := []string{toolchainEmpty1, toolchainEmpty2}
-
-	toolchainsOneNonempty := []string{toolchainEmpty1, toolchainA1}
-
-	toolchainsSameNonempty := []string{toolchainA1, toolchainA2}
-
-	toolchainsDifferentOrder := []string{toolchainAB, toolchainBA}
-
-	allToolchains := []string{
-		toolchainEmpty1,
-		toolchainEmpty2,
-		toolchainA1,
-		toolchainA2,
-		toolchainAB,
-		toolchainBA,
-	}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "make_variables",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    make_variables = []`},
-		{field: "make_variables",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        make_variables = []
-    elif (ctx.attr.cpu == "cpuC"):
-        make_variables = [make_variable(name = "A", value = "a/b/c")]
-    else:
-        fail("Unreachable")`},
-		{field: "make_variables",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    make_variables = [make_variable(name = "A", value = "a/b/c")]`},
-		{field: "make_variables",
-			toolchains: toolchainsDifferentOrder,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        make_variables = [
-            make_variable(name = "A", value = "a/b/c"),
-            make_variable(name = "B", value = "a/b/c"),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        make_variables = [
-            make_variable(name = "B", value = "a/b/c"),
-            make_variable(name = "A", value = "a b c"),
-        ]
-    else:
-        fail("Unreachable")`},
-		{field: "make_variables",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerC"):
-        make_variables = [
-            make_variable(name = "A", value = "a/b/c"),
-            make_variable(name = "B", value = "a/b/c"),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        make_variables = [
-            make_variable(name = "B", value = "a/b/c"),
-            make_variable(name = "A", value = "a b c"),
-        ]
-    elif (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        make_variables = []
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        make_variables = [make_variable(name = "A", value = "a/b/c")]
-    else:
-        fail("Unreachable")`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestToolPaths(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainA1 := getCToolchain("3", "cpuC", "compilerA",
-		[]string{"tool_path {name: 'A', path: 'a/b/c'}"})
-	toolchainA2 := getCToolchain("4", "cpuC", "compilerB",
-		[]string{"tool_path {name: 'A', path: 'a/b/c'}"})
-	toolchainAB := getCToolchain("5", "cpuC", "compilerC",
-		[]string{"tool_path {name: 'A', path: 'a/b/c'}",
-			"tool_path {name: 'B', path: 'a/b/c'}"})
-	toolchainBA := getCToolchain("6", "cpuD", "compilerA",
-		[]string{"tool_path {name: 'B', path: 'a/b/c'}",
-			"tool_path {name: 'A', path: 'a/b/c'}"})
-
-	toolchainsEmpty := []string{toolchainEmpty1, toolchainEmpty2}
-
-	toolchainsOneNonempty := []string{toolchainEmpty1, toolchainA1}
-
-	toolchainsSameNonempty := []string{toolchainA1, toolchainA2}
-
-	toolchainsDifferentOrder := []string{toolchainAB, toolchainBA}
-
-	allToolchains := []string{
-		toolchainEmpty1,
-		toolchainEmpty2,
-		toolchainA1,
-		toolchainA2,
-		toolchainAB,
-		toolchainBA,
-	}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "tool_paths",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    tool_paths = []`},
-		{field: "tool_paths",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        tool_paths = []
-    elif (ctx.attr.cpu == "cpuC"):
-        tool_paths = [tool_path(name = "A", path = "a/b/c")]
-    else:
-        fail("Unreachable")`},
-		{field: "tool_paths",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    tool_paths = [tool_path(name = "A", path = "a/b/c")]`},
-		{field: "tool_paths",
-			toolchains: toolchainsDifferentOrder,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        tool_paths = [
-            tool_path(name = "A", path = "a/b/c"),
-            tool_path(name = "B", path = "a/b/c"),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        tool_paths = [
-            tool_path(name = "B", path = "a/b/c"),
-            tool_path(name = "A", path = "a/b/c"),
-        ]
-    else:
-        fail("Unreachable")`},
-		{field: "tool_paths",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerC"):
-        tool_paths = [
-            tool_path(name = "A", path = "a/b/c"),
-            tool_path(name = "B", path = "a/b/c"),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        tool_paths = [
-            tool_path(name = "B", path = "a/b/c"),
-            tool_path(name = "A", path = "a/b/c"),
-        ]
-    elif (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        tool_paths = []
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        tool_paths = [tool_path(name = "A", path = "a/b/c")]
-    else:
-        fail("Unreachable")`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func getArtifactNamePattern(lines []string) string {
-	return fmt.Sprintf(`artifact_name_pattern {
-  %s
-}`, strings.Join(lines, "\n  "))
-}
-
-func TestArtifactNamePatterns(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainA1 := getCToolchain("3", "cpuC", "compilerA",
-		[]string{
-			getArtifactNamePattern([]string{
-				"category_name: 'A'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-		},
-	)
-	toolchainA2 := getCToolchain("4", "cpuC", "compilerB",
-		[]string{
-			getArtifactNamePattern([]string{
-				"category_name: 'A'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-		},
-	)
-	toolchainAB := getCToolchain("5", "cpuC", "compilerC",
-		[]string{
-			getArtifactNamePattern([]string{
-				"category_name: 'A'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-			getArtifactNamePattern([]string{
-				"category_name: 'B'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-		},
-	)
-	toolchainBA := getCToolchain("6", "cpuD", "compilerA",
-		[]string{
-			getArtifactNamePattern([]string{
-				"category_name: 'B'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-			getArtifactNamePattern([]string{
-				"category_name: 'A'",
-				"prefix: 'p'",
-				"extension: '.exe'"}),
-		},
-	)
-	toolchainsEmpty := []string{toolchainEmpty1, toolchainEmpty2}
-
-	toolchainsOneNonempty := []string{toolchainEmpty1, toolchainA1}
-
-	toolchainsSameNonempty := []string{toolchainA1, toolchainA2}
-
-	toolchainsDifferentOrder := []string{toolchainAB, toolchainBA}
-
-	allToolchains := []string{
-		toolchainEmpty1,
-		toolchainEmpty2,
-		toolchainA1,
-		toolchainA2,
-		toolchainAB,
-		toolchainBA,
-	}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "artifact_name_patterns",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    artifact_name_patterns = []`},
-		{field: "artifact_name_patterns",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    elif (ctx.attr.cpu == "cpuA"):
-        artifact_name_patterns = []
-    else:
-        fail("Unreachable")`},
-		{field: "artifact_name_patterns",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    artifact_name_patterns = [
-        artifact_name_pattern(
-            category_name = "A",
-            prefix = "p",
-            extension = ".exe",
-        ),
-    ]`},
-		{field: "artifact_name_patterns",
-			toolchains: toolchainsDifferentOrder,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-            artifact_name_pattern(
-                category_name = "B",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "B",
-                prefix = "p",
-                extension = ".exe",
-            ),
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    else:
-        fail("Unreachable")`},
-		{field: "artifact_name_patterns",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerC"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-            artifact_name_pattern(
-                category_name = "B",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    elif (ctx.attr.cpu == "cpuD"):
-        artifact_name_patterns = [
-            artifact_name_pattern(
-                category_name = "B",
-                prefix = "p",
-                extension = ".exe",
-            ),
-            artifact_name_pattern(
-                category_name = "A",
-                prefix = "p",
-                extension = ".exe",
-            ),
-        ]
-    elif (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        artifact_name_patterns = []
-    else:
-        fail("Unreachable")`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func getFeature(lines []string) string {
-	return fmt.Sprintf(`feature {
-  %s
-}`, strings.Join(lines, "\n  "))
-}
-
-func TestFeatureListAssignment(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainA1 := getCToolchain("3", "cpuC", "compilerA",
-		[]string{getFeature([]string{"name: 'A'"})},
-	)
-	toolchainA2 := getCToolchain("4", "cpuC", "compilerB",
-		[]string{getFeature([]string{"name: 'A'"})},
-	)
-	toolchainAB := getCToolchain("5", "cpuC", "compilerC",
-		[]string{
-			getFeature([]string{"name: 'A'"}),
-			getFeature([]string{"name: 'B'"}),
-		},
-	)
-	toolchainBA := getCToolchain("6", "cpuD", "compilerA",
-		[]string{
-			getFeature([]string{"name: 'B'"}),
-			getFeature([]string{"name: 'A'"}),
-		},
-	)
-	toolchainsEmpty := []string{toolchainEmpty1, toolchainEmpty2}
-
-	toolchainsOneNonempty := []string{toolchainEmpty1, toolchainA1}
-
-	toolchainsSameNonempty := []string{toolchainA1, toolchainA2}
-
-	toolchainsDifferentOrder := []string{toolchainAB, toolchainBA}
-
-	allToolchains := []string{
-		toolchainEmpty1,
-		toolchainEmpty2,
-		toolchainA1,
-		toolchainA2,
-		toolchainAB,
-		toolchainBA,
-	}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "features",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    features = []`},
-		{field: "features",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        features = []
-    elif (ctx.attr.cpu == "cpuC"):
-        features = [a_feature]
-    else:
-        fail("Unreachable")`},
-		{field: "features",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    features = [a_feature]`},
-		{field: "features",
-			toolchains: toolchainsDifferentOrder,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        features = [a_feature, b_feature]
-    elif (ctx.attr.cpu == "cpuD"):
-        features = [b_feature, a_feature]
-    else:
-        fail("Unreachable")`},
-		{field: "features",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        features = []
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        features = [a_feature]
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerC"):
-        features = [a_feature, b_feature]
-    elif (ctx.attr.cpu == "cpuD"):
-        features = [b_feature, a_feature]
-    else:
-        fail("Unreachable")`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func getActionConfig(lines []string) string {
-	return fmt.Sprintf(`action_config {
-  %s
-}`, strings.Join(lines, "\n  "))
-}
-
-func TestActionConfigListAssignment(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainA1 := getCToolchain("3", "cpuC", "compilerA",
-		[]string{
-			getActionConfig([]string{"action_name: 'A'", "config_name: 'A'"}),
-		},
-	)
-	toolchainA2 := getCToolchain("4", "cpuC", "compilerB",
-		[]string{
-			getActionConfig([]string{"action_name: 'A'", "config_name: 'A'"}),
-		},
-	)
-	toolchainAB := getCToolchain("5", "cpuC", "compilerC",
-		[]string{
-			getActionConfig([]string{"action_name: 'A'", "config_name: 'A'"}),
-			getActionConfig([]string{"action_name: 'B'", "config_name: 'B'"}),
-		},
-	)
-	toolchainBA := getCToolchain("6", "cpuD", "compilerA",
-		[]string{
-			getActionConfig([]string{"action_name: 'B'", "config_name: 'B'"}),
-			getActionConfig([]string{"action_name: 'A'", "config_name: 'A'"}),
-		},
-	)
-	toolchainsEmpty := []string{toolchainEmpty1, toolchainEmpty2}
-
-	toolchainsOneNonempty := []string{toolchainEmpty1, toolchainA1}
-
-	toolchainsSameNonempty := []string{toolchainA1, toolchainA2}
-
-	toolchainsDifferentOrder := []string{toolchainAB, toolchainBA}
-
-	allToolchains := []string{
-		toolchainEmpty1,
-		toolchainEmpty2,
-		toolchainA1,
-		toolchainA2,
-		toolchainAB,
-		toolchainBA,
-	}
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "action_configs",
-			toolchains: toolchainsEmpty,
-			expectedText: `
-    action_configs = []`},
-		{field: "action_configs",
-			toolchains: toolchainsOneNonempty,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"):
-        action_configs = []
-    elif (ctx.attr.cpu == "cpuC"):
-        action_configs = [a_action]
-    else:
-        fail("Unreachable")`},
-		{field: "action_configs",
-			toolchains: toolchainsSameNonempty,
-			expectedText: `
-    action_configs = [a_action]`},
-		{field: "action_configs",
-			toolchains: toolchainsDifferentOrder,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        action_configs = [a_action, b_action]
-    elif (ctx.attr.cpu == "cpuD"):
-        action_configs = [b_action, a_action]
-    else:
-        fail("Unreachable")`},
-		{field: "action_configs",
-			toolchains: allToolchains,
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA"
-        or ctx.attr.cpu == "cpuB"):
-        action_configs = []
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"
-        or ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        action_configs = [a_action]
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerC"):
-        action_configs = [a_action, b_action]
-    elif (ctx.attr.cpu == "cpuD"):
-        action_configs = [b_action, a_action]
-    else:
-        fail("Unreachable")`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestAllAndNoneAvailableErrorsWhenMoreThanOneElement(t *testing.T) {
-	toolchainFeatureAllAvailable := getCToolchain("1", "cpu", "compiler",
-		[]string{getFeature([]string{
-			"name: 'A'",
-			"flag_set {",
-			"  action: 'A'",
-			"  flag_group {",
-			"    flag: 'f'",
-			"    expand_if_all_available: 'e1'",
-			"    expand_if_all_available: 'e2'",
-			"  }",
-			"}",
-		})},
-	)
-	toolchainFeatureNoneAvailable := getCToolchain("1", "cpu", "compiler",
-		[]string{getFeature([]string{
-			"name: 'A'",
-			"flag_set {",
-			"  action: 'A'",
-			"  flag_group {",
-			"    flag: 'f'",
-			"    expand_if_none_available: 'e1'",
-			"    expand_if_none_available: 'e2'",
-			"  }",
-			"}",
-		})},
-	)
-	toolchainActionConfigAllAvailable := getCToolchain("1", "cpu", "compiler",
-		[]string{getActionConfig([]string{
-			"config_name: 'A'",
-			"action_name: 'A'",
-			"flag_set {",
-			"  action: 'A'",
-			"  flag_group {",
-			"    flag: 'f'",
-			"    expand_if_all_available: 'e1'",
-			"    expand_if_all_available: 'e2'",
-			"  }",
-			"}",
-		})},
-	)
-	toolchainActionConfigNoneAvailable := getCToolchain("1", "cpu", "compiler",
-		[]string{getActionConfig([]string{
-			"config_name: 'A'",
-			"action_name: 'A'",
-			"flag_set {",
-			"  action: 'A'",
-			"  flag_group {",
-			"    flag: 'f'",
-			"    expand_if_none_available: 'e1'",
-			"    expand_if_none_available: 'e2'",
-			"  }",
-			"}",
-		})},
-	)
-
-	testCases := []struct {
-		field        string
-		toolchain    string
-		expectedText string
-	}{
-		{field: "features",
-			toolchain: toolchainFeatureAllAvailable,
-			expectedText: "Error in feature 'A': Flag group must not have more " +
-				"than one 'expand_if_all_available' field"},
-		{field: "features",
-			toolchain: toolchainFeatureNoneAvailable,
-			expectedText: "Error in feature 'A': Flag group must not have more " +
-				"than one 'expand_if_none_available' field"},
-		{field: "action_configs",
-			toolchain: toolchainActionConfigAllAvailable,
-			expectedText: "Error in action_config 'A': Flag group must not have more " +
-				"than one 'expand_if_all_available' field"},
-		{field: "action_configs",
-			toolchain: toolchainActionConfigNoneAvailable,
-			expectedText: "Error in action_config 'A': Flag group must not have more " +
-				"than one 'expand_if_none_available' field"},
-	}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool([]string{tc.toolchain})
-		_, err := Transform(crosstool)
-		if err == nil || !strings.Contains(err.Error(), tc.expectedText) {
-			t.Errorf("Expected error: %s, got: %v", tc.expectedText, err)
-		}
-	}
-}
-
-func TestFeaturesAndActionConfigsSetToNoneWhenAllOptionsAreExausted(t *testing.T) {
-	toolchainFeatureAEnabled := getCToolchain("1", "cpuA", "compilerA",
-		[]string{getFeature([]string{"name: 'A'", "enabled: true"})},
-	)
-	toolchainFeatureADisabled := getCToolchain("2", "cpuA", "compilerB",
-		[]string{getFeature([]string{"name: 'A'", "enabled: false"})},
-	)
-
-	toolchainWithoutFeatureA := getCToolchain("3", "cpuA", "compilerC", []string{})
-
-	toolchainActionConfigAEnabled := getCToolchain("4", "cpuA", "compilerD",
-		[]string{getActionConfig([]string{
-			"config_name: 'A'",
-			"action_name: 'A'",
-			"enabled: true",
-		})})
-
-	toolchainActionConfigADisabled := getCToolchain("5", "cpuA", "compilerE",
-		[]string{getActionConfig([]string{
-			"config_name: 'A'",
-			"action_name: 'A'",
-		})})
-
-	toolchainWithoutActionConfigA := getCToolchain("6", "cpuA", "compilerF", []string{})
-
-	testCases := []struct {
-		field        string
-		toolchains   []string
-		expectedText string
-	}{
-		{field: "features",
-			toolchains: []string{
-				toolchainFeatureAEnabled, toolchainFeatureADisabled, toolchainWithoutFeatureA},
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerB"):
-        a_feature = feature(name = "A")
-    elif (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerA"):
-        a_feature = feature(name = "A", enabled = True)
-    else:
-        a_feature = None
-`},
-		{field: "action_config",
-			toolchains: []string{
-				toolchainActionConfigAEnabled, toolchainActionConfigADisabled, toolchainWithoutActionConfigA},
-			expectedText: `
-    if (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerE"):
-        a_action = action_config(action_name = "A")
-    elif (ctx.attr.cpu == "cpuA" and ctx.attr.compiler == "compilerD"):
-        a_action = action_config(action_name = "A", enabled = True)
-    else:
-        a_action = None
-`},
-	}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly convert '%s' field, expected to contain:\n%v\n",
-				tc.field, tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestActionConfigDeclaration(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-
-	toolchainNameNotInDict := getCToolchain("3", "cpBC", "compilerB",
-		[]string{
-			getActionConfig([]string{"action_name: 'A-B.C'", "config_name: 'A-B.C'"}),
-		},
-	)
-	toolchainNameInDictA := getCToolchain("4", "cpuC", "compilerA",
-		[]string{
-			getActionConfig([]string{"action_name: 'c++-compile'", "config_name: 'c++-compile'"}),
-		},
-	)
-	toolchainNameInDictB := getCToolchain("5", "cpuC", "compilerB",
-		[]string{
-			getActionConfig([]string{
-				"action_name: 'c++-compile'",
-				"config_name: 'c++-compile'",
-				"tool {",
-				"  tool_path: '/a/b/c'",
-				"}",
-			}),
-		},
-	)
-	toolchainComplexActionConfig := getCToolchain("6", "cpuC", "compilerC",
-		[]string{
-			getActionConfig([]string{
-				"action_name: 'action-complex'",
-				"config_name: 'action-complex'",
-				"enabled: true",
-				"tool {",
-				"  tool_path: '/a/b/c'",
-				"  with_feature {",
-				"    feature: 'a'",
-				"    feature: 'b'",
-				"    not_feature: 'c'",
-				"    not_feature: 'd'",
-				"  }",
-				"  with_feature{",
-				"    feature: 'e'",
-				"  }",
-				"  execution_requirement: 'a'",
-				"}",
-				"tool {",
-				"  tool_path: ''",
-				"}",
-				"flag_set {",
-				"  flag_group {",
-				"    flag: 'a'",
-				"    flag: '%b'",
-				"    iterate_over: 'c'",
-				"    expand_if_all_available: 'd'",
-				"    expand_if_none_available: 'e'",
-				"    expand_if_true: 'f'",
-				"    expand_if_false: 'g'",
-				"    expand_if_equal {",
-				"      variable: 'var'",
-				"      value: 'val'",
-				"    }",
-				"  }",
-				"  flag_group {",
-				"    flag_group {",
-				"      flag: 'a'",
-				"    }",
-				"  }",
-				"}",
-				"flag_set {",
-				"  with_feature {",
-				"    feature: 'a'",
-				"    feature: 'b'",
-				"    not_feature: 'c'",
-				"    not_feature: 'd'",
-				"  }",
-				"}",
-				"env_set {",
-				"  action: 'a'",
-				"  env_entry {",
-				"    key: 'k'",
-				"    value: 'v'",
-				"  }",
-				"  with_feature {",
-				"    feature: 'a'",
-				"  }",
-				"}",
-				"requires {",
-				"  feature: 'a'",
-				"  feature: 'b'",
-				"}",
-				"implies: 'a'",
-				"implies: 'b'",
-			}),
-		},
-	)
-
-	testCases := []struct {
-		toolchains   []string
-		expectedText string
-	}{
-		{
-			toolchains: []string{toolchainEmpty1, toolchainEmpty2},
-			expectedText: `
-    action_configs = []`},
-		{
-			toolchains: []string{toolchainEmpty1, toolchainNameNotInDict},
-			expectedText: `
-    a_b_c_action = action_config(action_name = "A-B.C")`},
-		{
-			toolchains: []string{toolchainNameInDictA, toolchainNameInDictB},
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerB"):
-        cpp_compile_action = action_config(
-            action_name = ACTION_NAMES.cpp_compile,
-            tools = [tool(path = "/a/b/c")],
-        )
-    elif (ctx.attr.cpu == "cpuC" and ctx.attr.compiler == "compilerA"):
-        cpp_compile_action = action_config(action_name = ACTION_NAMES.cpp_compile)`},
-		{
-			toolchains: []string{toolchainComplexActionConfig},
-			expectedText: `
-    action_complex_action = action_config(
-        action_name = "action-complex",
-        enabled = True,
-        flag_sets = [
-            flag_set(
-                flag_groups = [
-                    flag_group(
-                        flags = ["a", "%b"],
-                        iterate_over = "c",
-                        expand_if_available = "d",
-                        expand_if_not_available = "e",
-                        expand_if_true = "f",
-                        expand_if_false = "g",
-                        expand_if_equal = variable_with_value(name = "var", value = "val"),
-                    ),
-                    flag_group(flag_groups = [flag_group(flags = ["a"])]),
-                ],
-            ),
-            flag_set(
-                with_features = [
-                    with_feature_set(
-                        features = ["a", "b"],
-                        not_features = ["c", "d"],
-                    ),
-                ],
-            ),
-        ],
-        implies = ["a", "b"],
-        tools = [
-            tool(
-                path = "/a/b/c",
-                with_features = [
-                    with_feature_set(
-                        features = ["a", "b"],
-                        not_features = ["c", "d"],
-                    ),
-                    with_feature_set(features = ["e"]),
-                ],
-                execution_requirements = ["a"],
-            ),
-            tool(path = "NOT_USED"),
-        ],
-    )`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly declare an action_config, expected to contain:\n%v\n",
-				tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestFeatureDeclaration(t *testing.T) {
-	toolchainEmpty1 := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainEmpty2 := getCToolchain("2", "cpuB", "compilerA", []string{})
-
-	toolchainSimpleFeatureA1 := getCToolchain("3", "cpuB", "compilerB",
-		[]string{
-			getFeature([]string{"name: 'Feature-c++.a'", "enabled: true"}),
-		},
-	)
-	toolchainSimpleFeatureA2 := getCToolchain("4", "cpuC", "compilerA",
-		[]string{
-			getFeature([]string{"name: 'Feature-c++.a'"}),
-		},
-	)
-	toolchainComplexFeature := getCToolchain("5", "cpuC", "compilerC",
-		[]string{
-			getFeature([]string{
-				"name: 'complex-feature'",
-				"enabled: true",
-				"flag_set {",
-				"  action: 'c++-compile'",    // in ACTION_NAMES
-				"  action: 'something-else'", // not in ACTION_NAMES
-				"  flag_group {",
-				"    flag: 'a'",
-				"    flag: '%b'",
-				"    iterate_over: 'c'",
-				"    expand_if_all_available: 'd'",
-				"    expand_if_none_available: 'e'",
-				"    expand_if_true: 'f'",
-				"    expand_if_false: 'g'",
-				"    expand_if_equal {",
-				"      variable: 'var'",
-				"      value: 'val'",
-				"    }",
-				"  }",
-				"  flag_group {",
-				"    flag_group {",
-				"      flag: 'a'",
-				"    }",
-				"  }",
-				"}",
-				"flag_set {", // all_compile_actions
-				"  action: 'c-compile'",
-				"  action: 'c++-compile'",
-				"  action: 'linkstamp-compile'",
-				"  action: 'assemble'",
-				"  action: 'preprocess-assemble'",
-				"  action: 'c++-header-parsing'",
-				"  action: 'c++-module-compile'",
-				"  action: 'c++-module-codegen'",
-				"  action: 'clif-match'",
-				"  action: 'lto-backend'",
-				"}",
-				"flag_set {", // all_cpp_compile_actions
-				"  action: 'c++-compile'",
-				"  action: 'linkstamp-compile'",
-				"  action: 'c++-header-parsing'",
-				"  action: 'c++-module-compile'",
-				"  action: 'c++-module-codegen'",
-				"  action: 'clif-match'",
-				"}",
-				"flag_set {", // all_link_actions
-				"  action: 'c++-link-executable'",
-				"  action: 'c++-link-dynamic-library'",
-				"  action: 'c++-link-nodeps-dynamic-library'",
-				"}",
-				"flag_set {", // all_cpp_compile_actions + all_link_actions
-				"  action: 'c++-compile'",
-				"  action: 'linkstamp-compile'",
-				"  action: 'c++-header-parsing'",
-				"  action: 'c++-module-compile'",
-				"  action: 'c++-module-codegen'",
-				"  action: 'clif-match'",
-				"  action: 'c++-link-executable'",
-				"  action: 'c++-link-dynamic-library'",
-				"  action: 'c++-link-nodeps-dynamic-library'",
-				"}",
-				"flag_set {", // all_link_actions + something else
-				"  action: 'c++-link-executable'",
-				"  action: 'c++-link-dynamic-library'",
-				"  action: 'c++-link-nodeps-dynamic-library'",
-				"  action: 'some.unknown-c++.action'",
-				"}",
-				"env_set {",
-				"  action: 'a'",
-				"  env_entry {",
-				"    key: 'k'",
-				"    value: 'v'",
-				"  }",
-				"  with_feature {",
-				"    feature: 'a'",
-				"  }",
-				"}",
-				"env_set {",
-				"  action: 'c-compile'",
-				"}",
-				"env_set {", // all_compile_actions
-				"  action: 'c-compile'",
-				"  action: 'c++-compile'",
-				"  action: 'linkstamp-compile'",
-				"  action: 'assemble'",
-				"  action: 'preprocess-assemble'",
-				"  action: 'c++-header-parsing'",
-				"  action: 'c++-module-compile'",
-				"  action: 'c++-module-codegen'",
-				"  action: 'clif-match'",
-				"  action: 'lto-backend'",
-				"}",
-				"requires {",
-				"  feature: 'a'",
-				"  feature: 'b'",
-				"}",
-				"implies: 'a'",
-				"implies: 'b'",
-				"provides: 'c'",
-				"provides: 'd'",
-			}),
-		},
-	)
-
-	testCases := []struct {
-		toolchains   []string
-		expectedText string
-	}{
-		{
-			toolchains: []string{toolchainEmpty1, toolchainEmpty2},
-			expectedText: `
-    features = []
-`},
-		{
-			toolchains: []string{toolchainEmpty1, toolchainSimpleFeatureA1},
-			expectedText: `
-    feature_cpp_a_feature = feature(name = "Feature-c++.a", enabled = True)`},
-		{
-			toolchains: []string{toolchainSimpleFeatureA1, toolchainSimpleFeatureA2},
-			expectedText: `
-    if (ctx.attr.cpu == "cpuC"):
-        feature_cpp_a_feature = feature(name = "Feature-c++.a")
-    elif (ctx.attr.cpu == "cpuB"):
-        feature_cpp_a_feature = feature(name = "Feature-c++.a", enabled = True)`},
-		{
-			toolchains: []string{toolchainComplexFeature},
-			expectedText: `
-    complex_feature_feature = feature(
-        name = "complex-feature",
-        enabled = True,
-        flag_sets = [
-            flag_set(
-                actions = [ACTION_NAMES.cpp_compile, "something-else"],
-                flag_groups = [
-                    flag_group(
-                        flags = ["a", "%b"],
-                        iterate_over = "c",
-                        expand_if_available = "d",
-                        expand_if_not_available = "e",
-                        expand_if_true = "f",
-                        expand_if_false = "g",
-                        expand_if_equal = variable_with_value(name = "var", value = "val"),
-                    ),
-                    flag_group(flag_groups = [flag_group(flags = ["a"])]),
-                ],
-            ),
-            flag_set(actions = all_compile_actions),
-            flag_set(actions = all_cpp_compile_actions),
-            flag_set(actions = all_link_actions),
-            flag_set(
-                actions = all_cpp_compile_actions +
-                    all_link_actions,
-            ),
-            flag_set(
-                actions = all_link_actions +
-                    ["some.unknown-c++.action"],
-            ),
-        ],
-        env_sets = [
-            env_set(
-                actions = ["a"],
-                env_entries = [env_entry(key = "k", value = "v")],
-                with_features = [with_feature_set(features = ["a"])],
-            ),
-            env_set(actions = [ACTION_NAMES.c_compile]),
-            env_set(actions = all_compile_actions),
-        ],
-        requires = [feature_set(features = ["a", "b"])],
-        implies = ["a", "b"],
-        provides = ["c", "d"],
-    )`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly declare a feature, expected to contain:\n%v\n",
-				tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
-
-func TestRule(t *testing.T) {
-	simpleToolchain := getSimpleCToolchain("simple")
-	expected := `load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
-    "action_config",
-    "artifact_name_pattern",
-    "env_entry",
-    "env_set",
-    "feature",
-    "feature_set",
-    "flag_group",
-    "flag_set",
-    "make_variable",
-    "tool",
-    "tool_path",
-    "variable_with_value",
-    "with_feature_set",
-)
-load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
-
-def _impl(ctx):
-    toolchain_identifier = "id-simple"
-
-    host_system_name = "host-simple"
-
-    target_system_name = "target-simple"
-
-    target_cpu = "cpu-simple"
-
-    target_libc = "libc-simple"
-
-    compiler = "compiler-simple"
-
-    abi_version = "version-simple"
-
-    abi_libc_version = "libc_version-simple"
-
-    cc_target_os = None
-
-    builtin_sysroot = None
-
-    all_compile_actions = [
-        ACTION_NAMES.c_compile,
-        ACTION_NAMES.cpp_compile,
-        ACTION_NAMES.linkstamp_compile,
-        ACTION_NAMES.assemble,
-        ACTION_NAMES.preprocess_assemble,
-        ACTION_NAMES.cpp_header_parsing,
-        ACTION_NAMES.cpp_module_compile,
-        ACTION_NAMES.cpp_module_codegen,
-        ACTION_NAMES.clif_match,
-        ACTION_NAMES.lto_backend,
-    ]
-
-    all_cpp_compile_actions = [
-        ACTION_NAMES.cpp_compile,
-        ACTION_NAMES.linkstamp_compile,
-        ACTION_NAMES.cpp_header_parsing,
-        ACTION_NAMES.cpp_module_compile,
-        ACTION_NAMES.cpp_module_codegen,
-        ACTION_NAMES.clif_match,
-    ]
-
-    preprocessor_compile_actions = [
-        ACTION_NAMES.c_compile,
-        ACTION_NAMES.cpp_compile,
-        ACTION_NAMES.linkstamp_compile,
-        ACTION_NAMES.preprocess_assemble,
-        ACTION_NAMES.cpp_header_parsing,
-        ACTION_NAMES.cpp_module_compile,
-        ACTION_NAMES.clif_match,
-    ]
-
-    codegen_compile_actions = [
-        ACTION_NAMES.c_compile,
-        ACTION_NAMES.cpp_compile,
-        ACTION_NAMES.linkstamp_compile,
-        ACTION_NAMES.assemble,
-        ACTION_NAMES.preprocess_assemble,
-        ACTION_NAMES.cpp_module_codegen,
-        ACTION_NAMES.lto_backend,
-    ]
-
-    all_link_actions = [
-        ACTION_NAMES.cpp_link_executable,
-        ACTION_NAMES.cpp_link_dynamic_library,
-        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
-    ]
-
-    action_configs = []
-
-    features = []
-
-    cxx_builtin_include_directories = []
-
-    artifact_name_patterns = []
-
-    make_variables = []
-
-    tool_paths = []
-
-
-    out = ctx.actions.declare_file(ctx.label.name)
-    ctx.actions.write(out, "Fake executable")
-    return [
-        cc_common.create_cc_toolchain_config_info(
-            ctx = ctx,
-            features = features,
-            action_configs = action_configs,
-            artifact_name_patterns = artifact_name_patterns,
-            cxx_builtin_include_directories = cxx_builtin_include_directories,
-            toolchain_identifier = toolchain_identifier,
-            host_system_name = host_system_name,
-            target_system_name = target_system_name,
-            target_cpu = target_cpu,
-            target_libc = target_libc,
-            compiler = compiler,
-            abi_version = abi_version,
-            abi_libc_version = abi_libc_version,
-            tool_paths = tool_paths,
-            make_variables = make_variables,
-            builtin_sysroot = builtin_sysroot,
-            cc_target_os = cc_target_os
-        ),
-        DefaultInfo(
-            executable = out,
-        ),
-    ]
-cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        "cpu": attr.string(mandatory=True, values=["cpu-simple"]),
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`
-	crosstool := makeCrosstool([]string{simpleToolchain})
-	got, err := Transform(crosstool)
-	if err != nil {
-		t.Fatalf("CROSSTOOL conversion failed: %v", err)
-	}
-	if got != expected {
-		t.Fatalf("Expected:\n%v\nGot:\n%v\nTested CROSSTOOL:\n%v",
-			expected, got, simpleToolchain)
-	}
-}
-
-func TestAllowedCompilerValues(t *testing.T) {
-	toolchainAA := getCToolchain("1", "cpuA", "compilerA", []string{})
-	toolchainBA := getCToolchain("2", "cpuB", "compilerA", []string{})
-	toolchainBB := getCToolchain("3", "cpuB", "compilerB", []string{})
-	toolchainCC := getCToolchain("4", "cpuC", "compilerC", []string{})
-
-	testCases := []struct {
-		toolchains   []string
-		expectedText string
-	}{
-		{
-			toolchains: []string{toolchainAA, toolchainBA},
-			expectedText: `
-cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        "cpu": attr.string(mandatory=True, values=["cpuA", "cpuB"]),
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`},
-		{
-			toolchains: []string{toolchainBA, toolchainBB},
-			expectedText: `
-cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        "cpu": attr.string(mandatory=True, values=["cpuB"]),
-        "compiler": attr.string(mandatory=True, values=["compilerA", "compilerB"]),
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`},
-		{
-			toolchains: []string{toolchainAA, toolchainBA, toolchainBB},
-			expectedText: `
-cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        "cpu": attr.string(mandatory=True, values=["cpuA", "cpuB"]),
-        "compiler": attr.string(mandatory=True, values=["compilerA", "compilerB"]),
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`},
-		{
-			toolchains: []string{toolchainAA, toolchainBA, toolchainBB, toolchainCC},
-			expectedText: `
-cc_toolchain_config =  rule(
-    implementation = _impl,
-    attrs = {
-        "cpu": attr.string(mandatory=True, values=["cpuA", "cpuB", "cpuC"]),
-        "compiler": attr.string(mandatory=True, values=["compilerA", "compilerB", "compilerC"]),
-    },
-    provides = [CcToolchainConfigInfo],
-    executable = True,
-)
-`}}
-
-	for _, tc := range testCases {
-		crosstool := makeCrosstool(tc.toolchains)
-		got, err := Transform(crosstool)
-		if err != nil {
-			t.Fatalf("CROSSTOOL conversion failed: %v", err)
-		}
-		if !strings.Contains(got, tc.expectedText) {
-			t.Errorf("Failed to correctly declare the rule, expected to contain:\n%v\n",
-				tc.expectedText)
-			t.Fatalf("Tested CROSSTOOL:\n%v\n\nGenerated rule:\n%v\n",
-				strings.Join(tc.toolchains, "\n"), got)
-		}
-	}
-}
diff --git a/tools/migration/ctoolchain_comparator.py b/tools/migration/ctoolchain_comparator.py
deleted file mode 100644
index 5143e02..0000000
--- a/tools/migration/ctoolchain_comparator.py
+++ /dev/null
@@ -1,127 +0,0 @@
-# Copyright 2018 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-r"""A script that compares 2 CToolchains from proto format.
-
-This script accepts two files in either a CROSSTOOL proto text format or a
-CToolchain proto text format. It then locates the CToolchains with the given
-toolchain_identifier and checks if the resulting CToolchain objects in Java
-are the same.
-
-Example usage:
-
-bazel run \
-@rules_cc//tools/migration:ctoolchain_comparator -- \
---before=/path/to/CROSSTOOL1 \
---after=/path/to/CROSSTOOL2 \
---toolchain_identifier=id
-"""
-
-import os
-from absl import app
-from absl import flags
-from google.protobuf import text_format
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-from tools.migration.ctoolchain_comparator_lib import compare_ctoolchains
-
-flags.DEFINE_string(
-    "before", None,
-    ("A text proto file containing the relevant CTooclchain before the change, "
-     "either a CROSSTOOL file or a single CToolchain proto text"))
-flags.DEFINE_string(
-    "after", None,
-    ("A text proto file containing the relevant CToolchain after the change, "
-     "either a CROSSTOOL file or a single CToolchain proto text"))
-flags.DEFINE_string("toolchain_identifier", None,
-                    "The identifier of the CToolchain that is being compared.")
-flags.mark_flag_as_required("before")
-flags.mark_flag_as_required("after")
-
-
-def _to_absolute_path(path):
-  path = os.path.expanduser(path)
-  if os.path.isabs(path):
-    return path
-  else:
-    if "BUILD_WORKING_DIRECTORY" in os.environ:
-      return os.path.join(os.environ["BUILD_WORKING_DIRECTORY"], path)
-    else:
-      return path
-
-
-def _find_toolchain(crosstool, toolchain_identifier):
-  for toolchain in crosstool.toolchain:
-    if toolchain.toolchain_identifier == toolchain_identifier:
-      return toolchain
-  return None
-
-
-def _read_crosstool_or_ctoolchain_proto(input_file, toolchain_identifier=None):
-  """Reads a proto file and finds the CToolchain with the given identifier."""
-  with open(input_file, "r") as f:
-    text = f.read()
-  crosstool_release = crosstool_config_pb2.CrosstoolRelease()
-  c_toolchain = crosstool_config_pb2.CToolchain()
-  try:
-    text_format.Merge(text, crosstool_release)
-    if toolchain_identifier is None:
-      print("CROSSTOOL proto needs a 'toolchain_identifier' specified in "
-            "order to be able to select the right toolchain for comparison.")
-      return None
-    toolchain = _find_toolchain(crosstool_release, toolchain_identifier)
-    if toolchain is None:
-      print(("Cannot find a CToolchain with an identifier '%s' in CROSSTOOL "
-             "file") % toolchain_identifier)
-      return None
-    return toolchain
-  except text_format.ParseError as crosstool_error:
-    try:
-      text_format.Merge(text, c_toolchain)
-      if (toolchain_identifier is not None and
-          c_toolchain.toolchain_identifier != toolchain_identifier):
-        print(("Expected CToolchain with identifier '%s', got CToolchain with "
-               "identifier '%s'" % (toolchain_identifier,
-                                    c_toolchain.toolchain_identifier)))
-        return None
-      return c_toolchain
-    except text_format.ParseError as toolchain_error:
-      print(("Error parsing file '%s':" % input_file))  # pylint: disable=superfluous-parens
-      print("Attempt to parse it as a CROSSTOOL proto:")  # pylint: disable=superfluous-parens
-      print(crosstool_error)  # pylint: disable=superfluous-parens
-      print("Attempt to parse it as a CToolchain proto:")  # pylint: disable=superfluous-parens
-      print(toolchain_error)  # pylint: disable=superfluous-parens
-      return None
-
-
-def main(unused_argv):
-
-  before_file = _to_absolute_path(flags.FLAGS.before)
-  after_file = _to_absolute_path(flags.FLAGS.after)
-  toolchain_identifier = flags.FLAGS.toolchain_identifier
-
-  toolchain_before = _read_crosstool_or_ctoolchain_proto(
-      before_file, toolchain_identifier)
-  toolchain_after = _read_crosstool_or_ctoolchain_proto(after_file,
-                                                        toolchain_identifier)
-
-  if not toolchain_before or not toolchain_after:
-    print("There was an error getting the required toolchains.")
-    exit(1)
-
-  found_difference = compare_ctoolchains(toolchain_before, toolchain_after)
-  if found_difference:
-    exit(1)
-
-
-if __name__ == "__main__":
-  app.run(main)
diff --git a/tools/migration/ctoolchain_comparator_lib.py b/tools/migration/ctoolchain_comparator_lib.py
deleted file mode 100644
index eb47305..0000000
--- a/tools/migration/ctoolchain_comparator_lib.py
+++ /dev/null
@@ -1,523 +0,0 @@
-# Copyright 2018 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""Module providing compare_ctoolchains function.
-
-compare_ctoolchains takes in two parsed CToolchains and compares them
-"""
-
-
-def _print_difference(field_name, before_value, after_value):
-  if not before_value and after_value:
-    print(("Difference in '%s' field:\nValue before change is not set\n"
-           "Value after change is set to '%s'") % (field_name, after_value))
-  elif before_value and not after_value:
-    print(("Difference in '%s' field:\nValue before change is set to '%s'\n"
-           "Value after change is not set") % (field_name, before_value))
-  else:
-    print(("Difference in '%s' field:\nValue before change:\t'%s'\n"
-           "Value after change:\t'%s'\n") % (field_name, before_value,
-                                             after_value))
-
-
-def _array_to_string(arr, ordered=False):
-  if not arr:
-    return "[]"
-  elif len(arr) == 1:
-    return "[" + list(arr)[0] + "]"
-  if not ordered:
-    return "[\n\t%s\n]" % "\n\t".join(arr)
-  else:
-    return "[\n\t%s\n]" % "\n\t".join(sorted(list(arr)))
-
-
-def _check_with_feature_set_equivalence(before, after):
-  before_set = set()
-  after_set = set()
-  for el in before:
-    before_set.add((str(set(el.feature)), str(set(el.not_feature))))
-  for el in after:
-    after_set.add((str(set(el.feature)), str(set(el.not_feature))))
-  return before_set == after_set
-
-
-def _check_tool_equivalence(before, after):
-  """Compares two "CToolchain.Tool"s."""
-  if before.tool_path == "NOT_USED":
-    before.tool_path = ""
-  if after.tool_path == "NOT_USED":
-    after.tool_path = ""
-  if before.tool_path != after.tool_path:
-    return False
-  if set(before.execution_requirement) != set(after.execution_requirement):
-    return False
-  if not _check_with_feature_set_equivalence(before.with_feature,
-                                             after.with_feature):
-    return False
-  return True
-
-
-def _check_flag_group_equivalence(before, after):
-  """Compares two "CToolchain.FlagGroup"s."""
-  if before.flag != after.flag:
-    return False
-  if before.expand_if_true != after.expand_if_true:
-    return False
-  if before.expand_if_false != after.expand_if_false:
-    return False
-  if set(before.expand_if_all_available) != set(after.expand_if_all_available):
-    return False
-  if set(before.expand_if_none_available) != set(
-      after.expand_if_none_available):
-    return False
-  if before.iterate_over != after.iterate_over:
-    return False
-  if before.expand_if_equal != after.expand_if_equal:
-    return False
-  if len(before.flag_group) != len(after.flag_group):
-    return False
-  for (flag_group_before, flag_group_after) in zip(before.flag_group,
-                                                   after.flag_group):
-    if not _check_flag_group_equivalence(flag_group_before, flag_group_after):
-      return False
-  return True
-
-
-def _check_flag_set_equivalence(before, after, in_action_config=False):
-  """Compares two "CToolchain.FlagSet"s."""
-  # ActionConfigs in proto format do not have a 'FlagSet.action' field set.
-  # Instead, when construction the Java ActionConfig object, we set the
-  # flag_set.action field to the action name. This currently causes the
-  # CcToolchainConfigInfo.proto to generate a CToolchain.ActionConfig that still
-  # has the action name in the FlagSet.action field, therefore we don't compare
-  # the FlagSet.action field when comparing flag_sets that belong to an
-  # ActionConfig.
-  if not in_action_config and set(before.action) != set(after.action):
-    return False
-  if not _check_with_feature_set_equivalence(before.with_feature,
-                                             after.with_feature):
-    return False
-  if len(before.flag_group) != len(after.flag_group):
-    return False
-  for (flag_group_before, flag_group_after) in zip(before.flag_group,
-                                                   after.flag_group):
-    if not _check_flag_group_equivalence(flag_group_before, flag_group_after):
-      return False
-  return True
-
-
-def _check_action_config_equivalence(before, after):
-  """Compares two "CToolchain.ActionConfig"s."""
-  if before.config_name != after.config_name:
-    return False
-  if before.action_name != after.action_name:
-    return False
-  if before.enabled != after.enabled:
-    return False
-  if len(before.tool) != len(after.tool):
-    return False
-  for (tool_before, tool_after) in zip(before.tool, after.tool):
-    if not _check_tool_equivalence(tool_before, tool_after):
-      return False
-  if before.implies != after.implies:
-    return False
-  if len(before.flag_set) != len(after.flag_set):
-    return False
-  for (flag_set_before, flag_set_after) in zip(before.flag_set, after.flag_set):
-    if not _check_flag_set_equivalence(flag_set_before, flag_set_after, True):
-      return False
-  return True
-
-
-def _check_env_set_equivalence(before, after):
-  """Compares two "CToolchain.EnvSet"s."""
-  if set(before.action) != set(after.action):
-    return False
-  if not _check_with_feature_set_equivalence(before.with_feature,
-                                             after.with_feature):
-    return False
-  if before.env_entry != after.env_entry:
-    return False
-  return True
-
-
-def _check_feature_equivalence(before, after):
-  """Compares two "CToolchain.Feature"s."""
-  if before.name != after.name:
-    return False
-  if before.enabled != after.enabled:
-    return False
-  if len(before.flag_set) != len(after.flag_set):
-    return False
-  for (flag_set_before, flag_set_after) in zip(before.flag_set, after.flag_set):
-    if not _check_flag_set_equivalence(flag_set_before, flag_set_after):
-      return False
-  if len(before.env_set) != len(after.env_set):
-    return False
-  for (env_set_before, env_set_after) in zip(before.env_set, after.env_set):
-    if not _check_env_set_equivalence(env_set_before, env_set_after):
-      return False
-  if len(before.requires) != len(after.requires):
-    return False
-  for (requires_before, requires_after) in zip(before.requires, after.requires):
-    if set(requires_before.feature) != set(requires_after.feature):
-      return False
-  if before.implies != after.implies:
-    return False
-  if before.provides != after.provides:
-    return False
-  return True
-
-
-def _compare_features(features_before, features_after):
-  """Compares two "CToolchain.FlagFeature" lists."""
-  feature_name_to_feature_before = {}
-  feature_name_to_feature_after = {}
-  for feature in features_before:
-    feature_name_to_feature_before[feature.name] = feature
-  for feature in features_after:
-    feature_name_to_feature_after[feature.name] = feature
-
-  feature_names_before = set(feature_name_to_feature_before.keys())
-  feature_names_after = set(feature_name_to_feature_after.keys())
-
-  before_after_diff = feature_names_before - feature_names_after
-  after_before_diff = feature_names_after - feature_names_before
-
-  diff_string = "Difference in 'feature' field:"
-  found_difference = False
-  if before_after_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List before change contains entries for the following features "
-           "that the list after the change doesn't:\n%s") % _array_to_string(
-               before_after_diff, ordered=True))
-  if after_before_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List after change contains entries for the following features "
-           "that the list before the change doesn't:\n%s") % _array_to_string(
-               after_before_diff, ordered=True))
-
-  names_before = [feature.name for feature in features_before]
-  names_after = [feature.name for feature in features_after]
-  if names_before != names_after:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("Features not in right order:\n"
-           "* List of features before change:\t%s"
-           "* List of features before change:\t%s") %
-          (_array_to_string(names_before), _array_to_string(names_after)))
-  for name in feature_name_to_feature_before:
-    feature_before = feature_name_to_feature_before[name]
-    feature_after = feature_name_to_feature_after.get(name, None)
-    if feature_after and not _check_feature_equivalence(feature_before,
-                                                        feature_after):
-      if not found_difference:
-        print(diff_string)  # pylint: disable=superfluous-parens
-        found_difference = True
-      print(("* Feature '%s' differs before and after the change:\n"
-             "Value before change:\n%s\n"
-             "Value after change:\n%s") % (name, str(feature_before),
-                                           str(feature_after)))
-  if found_difference:
-    print("")  # pylint: disable=superfluous-parens
-  return found_difference
-
-
-def _compare_action_configs(action_configs_before, action_configs_after):
-  """Compares two "CToolchain.ActionConfig" lists."""
-  action_name_to_action_before = {}
-  action_name_to_action_after = {}
-  for action_config in action_configs_before:
-    action_name_to_action_before[action_config.config_name] = action_config
-  for action_config in action_configs_after:
-    action_name_to_action_after[action_config.config_name] = action_config
-
-  config_names_before = set(action_name_to_action_before.keys())
-  config_names_after = set(action_name_to_action_after.keys())
-
-  before_after_diff = config_names_before - config_names_after
-  after_before_diff = config_names_after - config_names_before
-
-  diff_string = "Difference in 'action_config' field:"
-  found_difference = False
-  if before_after_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List before change contains entries for the following "
-           "action_configs that the list after the change doesn't:\n%s") %
-          _array_to_string(before_after_diff, ordered=True))
-  if after_before_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List after change contains entries for the following "
-           "action_configs that the list before the change doesn't:\n%s") %
-          _array_to_string(after_before_diff, ordered=True))
-
-  names_before = [config.config_name for config in action_configs_before]
-  names_after = [config.config_name for config in action_configs_after]
-  if names_before != names_after:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("Action configs not in right order:\n"
-           "* List of action configs before change:\t%s"
-           "* List of action_configs before change:\t%s") %
-          (_array_to_string(names_before), _array_to_string(names_after)))
-  for name in config_names_before:
-    action_config_before = action_name_to_action_before[name]
-    action_config_after = action_name_to_action_after.get(name, None)
-    if action_config_after and not _check_action_config_equivalence(
-        action_config_before, action_config_after):
-      if not found_difference:
-        print(diff_string)  # pylint: disable=superfluous-parens
-        found_difference = True
-      print(("* Action config '%s' differs before and after the change:\n"
-             "Value before change:\n%s\n"
-             "Value after change:\n%s") % (name, str(action_config_before),
-                                           str(action_config_after)))
-  if found_difference:
-    print("")  # pylint: disable=superfluous-parens
-  return found_difference
-
-
-def _compare_tool_paths(tool_paths_before, tool_paths_after):
-  """Compares two "CToolchain.ToolPath" lists."""
-  tool_to_path_before = {}
-  tool_to_path_after = {}
-  for tool_path in tool_paths_before:
-    tool_to_path_before[tool_path.name] = (
-        tool_path.path if tool_path.path != "NOT_USED" else "")
-  for tool_path in tool_paths_after:
-    tool_to_path_after[tool_path.name] = (
-        tool_path.path if tool_path.path != "NOT_USED" else "")
-
-  tool_names_before = set(tool_to_path_before.keys())
-  tool_names_after = set(tool_to_path_after.keys())
-
-  before_after_diff = tool_names_before - tool_names_after
-  after_before_diff = tool_names_after - tool_names_before
-
-  diff_string = "Difference in 'tool_path' field:"
-  found_difference = False
-  if before_after_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List before change contains entries for the following tools "
-           "that the list after the change doesn't:\n%s") % _array_to_string(
-               before_after_diff, ordered=True))
-  if after_before_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List after change contains entries for the following tools that "
-           "the list before the change doesn't:\n%s") % _array_to_string(
-               after_before_diff, ordered=True))
-
-  for tool in tool_to_path_before:
-    path_before = tool_to_path_before[tool]
-    path_after = tool_to_path_after.get(tool, None)
-    if path_after and path_after != path_before:
-      if not found_difference:
-        print(diff_string)  # pylint: disable=superfluous-parens
-        found_difference = True
-      print(("* Path for tool '%s' differs before and after the change:\n"
-             "Value before change:\t'%s'\n"
-             "Value after change:\t'%s'") % (tool, path_before, path_after))
-  if found_difference:
-    print("")  # pylint: disable=superfluous-parens
-  return found_difference
-
-
-def _compare_make_variables(make_variables_before, make_variables_after):
-  """Compares two "CToolchain.MakeVariable" lists."""
-  name_to_variable_before = {}
-  name_to_variable_after = {}
-  for variable in make_variables_before:
-    name_to_variable_before[variable.name] = variable.value
-  for variable in make_variables_after:
-    name_to_variable_after[variable.name] = variable.value
-
-  variable_names_before = set(name_to_variable_before.keys())
-  variable_names_after = set(name_to_variable_after.keys())
-
-  before_after_diff = variable_names_before - variable_names_after
-  after_before_diff = variable_names_after - variable_names_before
-
-  diff_string = "Difference in 'make_variable' field:"
-  found_difference = False
-  if before_after_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List before change contains entries for the following variables "
-           "that the list after the change doesn't:\n%s") % _array_to_string(
-               before_after_diff, ordered=True))
-  if after_before_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List after change contains entries for the following variables "
-           "that the list before the change doesn't:\n%s") % _array_to_string(
-               after_before_diff, ordered=True))
-
-  for variable in name_to_variable_before:
-    value_before = name_to_variable_before[variable]
-    value_after = name_to_variable_after.get(variable, None)
-    if value_after and value_after != value_before:
-      if not found_difference:
-        print(diff_string)  # pylint: disable=superfluous-parens
-        found_difference = True
-      print(
-          ("* Value for variable '%s' differs before and after the change:\n"
-           "Value before change:\t'%s'\n"
-           "Value after change:\t'%s'") % (variable, value_before, value_after))
-  if found_difference:
-    print("")  # pylint: disable=superfluous-parens
-  return found_difference
-
-
-def _compare_cxx_builtin_include_directories(directories_before,
-                                             directories_after):
-  if directories_before != directories_after:
-    print(("Difference in 'cxx_builtin_include_directory' field:\n"
-           "List of elements before change:\n%s\n"
-           "List of elements after change:\n%s\n") %
-          (_array_to_string(directories_before),
-           _array_to_string(directories_after)))
-    return True
-  return False
-
-
-def _compare_artifact_name_patterns(artifact_name_patterns_before,
-                                    artifact_name_patterns_after):
-  """Compares two "CToolchain.ArtifactNamePattern" lists."""
-  category_to_values_before = {}
-  category_to_values_after = {}
-  for name_pattern in artifact_name_patterns_before:
-    category_to_values_before[name_pattern.category_name] = (
-        name_pattern.prefix, name_pattern.extension)
-  for name_pattern in artifact_name_patterns_after:
-    category_to_values_after[name_pattern.category_name] = (
-        name_pattern.prefix, name_pattern.extension)
-
-  category_names_before = set(category_to_values_before.keys())
-  category_names_after = set(category_to_values_after.keys())
-
-  before_after_diff = category_names_before - category_names_after
-  after_before_diff = category_names_after - category_names_before
-
-  diff_string = "Difference in 'artifact_name_pattern' field:"
-  found_difference = False
-  if before_after_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List before change contains entries for the following categories "
-           "that the list after the change doesn't:\n%s") % _array_to_string(
-               before_after_diff, ordered=True))
-  if after_before_diff:
-    if not found_difference:
-      print(diff_string)  # pylint: disable=superfluous-parens
-      found_difference = True
-    print(("* List after change contains entries for the following categories "
-           "that the list before the change doesn't:\n%s") % _array_to_string(
-               after_before_diff, ordered=True))
-
-  for category in category_to_values_before:
-    value_before = category_to_values_before[category]
-    value_after = category_to_values_after.get(category, None)
-    if value_after and value_after != value_before:
-      if not found_difference:
-        print(diff_string)  # pylint: disable=superfluous-parens
-        found_difference = True
-      print(("* Value for category '%s' differs before and after the change:\n"
-             "Value before change:\tprefix:'%s'\textension:'%s'\n"
-             "Value after change:\tprefix:'%s'\textension:'%s'") %
-            (category, value_before[0], value_before[1], value_after[0],
-             value_after[1]))
-  if found_difference:
-    print("")  # pylint: disable=superfluous-parens
-  return found_difference
-
-
-def compare_ctoolchains(toolchain_before, toolchain_after):
-  """Compares two CToolchains."""
-  found_difference = False
-  if (toolchain_before.toolchain_identifier !=
-      toolchain_after.toolchain_identifier):
-    _print_difference("toolchain_identifier",
-                      toolchain_before.toolchain_identifier,
-                      toolchain_after.toolchain_identifier)
-  if toolchain_before.host_system_name != toolchain_after.host_system_name:
-    _print_difference("host_system_name", toolchain_before.host_system_name,
-                      toolchain_after.host_system_name)
-    found_difference = True
-  if toolchain_before.target_system_name != toolchain_after.target_system_name:
-    _print_difference("target_system_name", toolchain_before.target_system_name,
-                      toolchain_after.target_system_name)
-    found_difference = True
-  if toolchain_before.target_cpu != toolchain_after.target_cpu:
-    _print_difference("target_cpu", toolchain_before.target_cpu,
-                      toolchain_after.target_cpu)
-    found_difference = True
-  if toolchain_before.target_libc != toolchain_after.target_libc:
-    _print_difference("target_libc", toolchain_before.target_libc,
-                      toolchain_after.target_libc)
-    found_difference = True
-  if toolchain_before.compiler != toolchain_after.compiler:
-    _print_difference("compiler", toolchain_before.compiler,
-                      toolchain_after.compiler)
-    found_difference = True
-  if toolchain_before.abi_version != toolchain_after.abi_version:
-    _print_difference("abi_version", toolchain_before.abi_version,
-                      toolchain_after.abi_version)
-    found_difference = True
-  if toolchain_before.abi_libc_version != toolchain_after.abi_libc_version:
-    _print_difference("abi_libc_version", toolchain_before.abi_libc_version,
-                      toolchain_after.abi_libc_version)
-    found_difference = True
-  if toolchain_before.cc_target_os != toolchain_after.cc_target_os:
-    _print_difference("cc_target_os", toolchain_before.cc_target_os,
-                      toolchain_after.cc_target_os)
-    found_difference = True
-  if toolchain_before.builtin_sysroot != toolchain_after.builtin_sysroot:
-    _print_difference("builtin_sysroot", toolchain_before.builtin_sysroot,
-                      toolchain_after.builtin_sysroot)
-    found_difference = True
-  found_difference = _compare_features(
-      toolchain_before.feature, toolchain_after.feature) or found_difference
-  found_difference = _compare_action_configs(
-      toolchain_before.action_config,
-      toolchain_after.action_config) or found_difference
-  found_difference = _compare_tool_paths(
-      toolchain_before.tool_path, toolchain_after.tool_path) or found_difference
-  found_difference = _compare_cxx_builtin_include_directories(
-      toolchain_before.cxx_builtin_include_directory,
-      toolchain_after.cxx_builtin_include_directory) or found_difference
-  found_difference = _compare_make_variables(
-      toolchain_before.make_variable,
-      toolchain_after.make_variable) or found_difference
-  found_difference = _compare_artifact_name_patterns(
-      toolchain_before.artifact_name_pattern,
-      toolchain_after.artifact_name_pattern) or found_difference
-  if not found_difference:
-    print("No difference")  # pylint: disable=superfluous-parens
-  return found_difference
diff --git a/tools/migration/ctoolchain_comparator_lib_test.py b/tools/migration/ctoolchain_comparator_lib_test.py
deleted file mode 100644
index 1a3a270..0000000
--- a/tools/migration/ctoolchain_comparator_lib_test.py
+++ /dev/null
@@ -1,1821 +0,0 @@
-# Copyright 2018 The Bazel Authors. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-import unittest
-
-from py import mock
-
-from google.protobuf import text_format
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-from tools.migration.ctoolchain_comparator_lib import compare_ctoolchains
-
-try:
-  # Python 2
-  from cStringIO import StringIO
-except ImportError:
-  # Python 3
-  from io import StringIO
-
-
-def make_toolchain(toolchain_proto):
-  toolchain = crosstool_config_pb2.CToolchain()
-  text_format.Merge(toolchain_proto, toolchain)
-  return toolchain
-
-
-class CtoolchainComparatorLibTest(unittest.TestCase):
-
-  def test_string_fields(self):
-    first = make_toolchain("""
-          toolchain_identifier: "first-id"
-          host_system_name: "first-host"
-          target_system_name: "first-target"
-          target_cpu: "first-cpu"
-          target_libc: "first-libc"
-          compiler: "first-compiler"
-          abi_version: "first-abi"
-          abi_libc_version: "first-abi-libc"
-          builtin_sysroot: "sysroot"
-        """)
-    second = make_toolchain("""
-          toolchain_identifier: "second-id"
-          host_system_name: "second-host"
-          target_system_name: "second-target"
-          target_cpu: "second-cpu"
-          target_libc: "second-libc"
-          compiler: "second-compiler"
-          abi_version: "second-abi"
-          abi_libc_version: "second-abi-libc"
-          cc_target_os: "os"
-        """)
-    error_toolchain_identifier = (
-        "Difference in 'toolchain_identifier' field:\n"
-        "Value before change:\t'first-id'\n"
-        "Value after change:\t'second-id'\n"
-    )
-    error_host_system_name = (
-        "Difference in 'host_system_name' field:\n"
-        "Value before change:\t'first-host'\n"
-        "Value after change:\t'second-host'\n"
-    )
-    error_target_system_name = (
-        "Difference in 'target_system_name' field:\n"
-        "Value before change:\t'first-target'\n"
-        "Value after change:\t'second-target'\n"
-    )
-    error_target_cpu = (
-        "Difference in 'target_cpu' field:\n"
-        "Value before change:\t'first-cpu'\n"
-        "Value after change:\t'second-cpu'\n"
-    )
-    error_target_libc = (
-        "Difference in 'target_libc' field:\n"
-        "Value before change:\t'first-libc'\n"
-        "Value after change:\t'second-libc'\n"
-    )
-    error_compiler = (
-        "Difference in 'compiler' field:\n"
-        "Value before change:\t'first-compiler'\n"
-        "Value after change:\t'second-compiler'\n"
-    )
-    error_abi_version = (
-        "Difference in 'abi_version' field:\n"
-        "Value before change:\t'first-abi'\n"
-        "Value after change:\t'second-abi'\n"
-    )
-    error_abi_libc_version = (
-        "Difference in 'abi_libc_version' field:\n"
-        "Value before change:\t'first-abi-libc'\n"
-        "Value after change:\t'second-abi-libc'\n"
-    )
-    error_builtin_sysroot = (
-        "Difference in 'builtin_sysroot' field:\n"
-        "Value before change is set to 'sysroot'\n"
-        "Value after change is not set\n"
-    )
-    error_cc_target_os = (
-        "Difference in 'cc_target_os' field:\n"
-        "Value before change is not set\n"
-        "Value after change is set to 'os'\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_toolchain_identifier, mock_stdout.getvalue())
-      self.assertIn(error_host_system_name, mock_stdout.getvalue())
-      self.assertIn(error_target_system_name, mock_stdout.getvalue())
-      self.assertIn(error_target_cpu, mock_stdout.getvalue())
-      self.assertIn(error_target_libc, mock_stdout.getvalue())
-      self.assertIn(error_compiler, mock_stdout.getvalue())
-      self.assertIn(error_abi_version, mock_stdout.getvalue())
-      self.assertIn(error_abi_libc_version, mock_stdout.getvalue())
-      self.assertIn(error_builtin_sysroot, mock_stdout.getvalue())
-      self.assertIn(error_cc_target_os, mock_stdout.getvalue())
-
-  def test_tool_path(self):
-    first = make_toolchain("""
-        tool_path {
-          name: "only_first"
-          path: "/a/b/c"
-        }
-        tool_path {
-          name: "paths_differ"
-          path: "/path/first"
-        }
-    """)
-    second = make_toolchain("""
-        tool_path {
-          name: "paths_differ"
-          path: "/path/second"
-        }
-        tool_path {
-          name: "only_second_1"
-          path: "/a/b/c"
-        }
-        tool_path {
-          name: "only_second_2"
-          path: "/a/b/c"
-        }
-    """)
-    error_only_first = (
-        "* List before change contains entries for the "
-        "following tools that the list after the change "
-        "doesn't:\n[only_first]\n"
-    )
-    error_only_second = (
-        "* List after change contains entries for the "
-        "following tools that the list before the change "
-        "doesn't:\n"
-        "[\n"
-        "\tonly_second_1\n"
-        "\tonly_second_2\n"
-        "]\n"
-    )
-    error_paths_differ = (
-        "* Path for tool 'paths_differ' differs before and "
-        "after the change:\n"
-        "Value before change:\t'/path/first'\n"
-        "Value after change:\t'/path/second'\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_only_first, mock_stdout.getvalue())
-      self.assertIn(error_only_second, mock_stdout.getvalue())
-      self.assertIn(error_paths_differ, mock_stdout.getvalue())
-
-  def test_make_variable(self):
-    first = make_toolchain("""
-        make_variable {
-          name: "only_first"
-          value: "val"
-        }
-        make_variable {
-          name: "value_differs"
-          value: "first_value"
-        }
-    """)
-    second = make_toolchain("""
-        make_variable {
-          name: "value_differs"
-          value: "second_value"
-        }
-        make_variable {
-          name: "only_second_1"
-          value: "val"
-        }
-        make_variable {
-          name: "only_second_2"
-          value: "val"
-        }
-    """)
-    error_only_first = (
-        "* List before change contains entries for the "
-        "following variables that the list after the "
-        "change doesn't:\n[only_first]\n"
-    )
-    error_only_second = (
-        "* List after change contains entries for the "
-        "following variables that the list before the "
-        "change doesn't:\n"
-        "[\n"
-        "\tonly_second_1\n"
-        "\tonly_second_2\n"
-        "]\n"
-    )
-    error_value_differs = (
-        "* Value for variable 'value_differs' differs before"
-        " and after the change:\n"
-        "Value before change:\t'first_value'\n"
-        "Value after change:\t'second_value'\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_only_first, mock_stdout.getvalue())
-      self.assertIn(error_only_second, mock_stdout.getvalue())
-      self.assertIn(error_value_differs, mock_stdout.getvalue())
-
-  def test_cxx_builtin_include_directories(self):
-    first = make_toolchain("""
-        cxx_builtin_include_directory: "a/b/c"
-        cxx_builtin_include_directory: "d/e/f"
-    """)
-    second = make_toolchain("""
-        cxx_builtin_include_directory: "d/e/f"
-        cxx_builtin_include_directory: "a/b/c"
-    """)
-    expect_error = (
-        "Difference in 'cxx_builtin_include_directory' field:\n"
-        "List of elements before change:\n"
-        "[\n"
-        "\ta/b/c\n"
-        "\td/e/f\n"
-        "]\n"
-        "List of elements after change:\n"
-        "[\n"
-        "\td/e/f\n"
-        "\ta/b/c\n"
-        "]\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(expect_error, mock_stdout.getvalue())
-
-  def test_artifact_name_pattern(self):
-    first = make_toolchain("""
-        artifact_name_pattern {
-          category_name: 'object_file'
-          prefix: ''
-          extension: '.obj1'
-        }
-        artifact_name_pattern {
-          category_name: 'executable'
-          prefix: 'first'
-          extension: '.exe'
-        }
-        artifact_name_pattern {
-          category_name: 'dynamic_library'
-          prefix: ''
-          extension: '.dll'
-        }
-    """)
-    second = make_toolchain("""
-        artifact_name_pattern {
-          category_name: 'object_file'
-          prefix: ''
-          extension: '.obj2'
-        }
-        artifact_name_pattern {
-          category_name: 'static_library'
-          prefix: ''
-          extension: '.lib'
-        }
-        artifact_name_pattern {
-          category_name: 'executable'
-          prefix: 'second'
-          extension: '.exe'
-        }
-        artifact_name_pattern {
-          category_name: 'interface_library'
-          prefix: ''
-          extension: '.if.lib'
-        }
-    """)
-    error_only_first = (
-        "* List before change contains entries for the "
-        "following categories that the list after the "
-        "change doesn't:\n[dynamic_library]\n"
-    )
-    error_only_second = (
-        "* List after change contains entries for the "
-        "following categories that the list before the "
-        "change doesn't:\n"
-        "[\n"
-        "\tinterface_library\n"
-        "\tstatic_library\n"
-        "]\n"
-    )
-    error_extension_differs = (
-        "* Value for category 'object_file' differs "
-        "before and after the change:\n"
-        "Value before change:"
-        "\tprefix:''"
-        "\textension:'.obj1'\n"
-        "Value after change:"
-        "\tprefix:''"
-        "\textension:'.obj2'\n"
-    )
-    error_prefix_differs = (
-        "* Value for category 'executable' differs "
-        "before and after the change:\n"
-        "Value before change:"
-        "\tprefix:'first'"
-        "\textension:'.exe'\n"
-        "Value after change:"
-        "\tprefix:'second'"
-        "\textension:'.exe'\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_only_first, mock_stdout.getvalue())
-      self.assertIn(error_only_second, mock_stdout.getvalue())
-      self.assertIn(error_extension_differs, mock_stdout.getvalue())
-      self.assertIn(error_prefix_differs, mock_stdout.getvalue())
-
-  def test_features_not_ordered(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature1'
-        }
-        feature {
-          name: 'feature2'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature2'
-        }
-        feature {
-          name: 'feature1'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("Features not in right order", mock_stdout.getvalue())
-
-  def test_features_missing(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature1'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature2'
-        }
-    """)
-    error_only_first = (
-        "* List before change contains entries for the "
-        "following features that the list after the "
-        "change doesn't:\n[feature1]\n"
-    )
-    error_only_second = (
-        "* List after change contains entries for the "
-        "following features that the list before the "
-        "change doesn't:\n[feature2]\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_only_first, mock_stdout.getvalue())
-      self.assertIn(error_only_second, mock_stdout.getvalue())
-
-  def test_feature_enabled(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          enabled: true
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          enabled: false
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-
-  def test_feature_provides(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          provides: 'a'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          provides: 'b'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_provides_preserves_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          provides: 'a'
-          provides: 'b'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          provides: 'b'
-          provides: 'a'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_implies(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          implies: 'a'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_implies_preserves_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          implies: 'a'
-          implies: 'b'
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          implies: 'b'
-          implies: 'a'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_requires_preserves_list_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature1'
-          }
-          requires: {
-            feature: 'feature2'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature2'
-          }
-          requires: {
-            feature: 'feature1'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_requires_ignores_required_features_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature1'
-            feature: 'feature2'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature2'
-            feature: 'feature1'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_feature_requires_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          requires: {
-            feature: 'feature2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_ignores_requires(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          requires: {
-            feature: 'feature1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          requires: {
-            feature: 'feature2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_env_set_actions_differ(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            action: 'a1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set: {
-            action: 'a1'
-            action: 'a2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_env_set_ignores_actions_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            action: 'a2'
-            action: 'a1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set: {
-            action: 'a1'
-            action: 'a2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_env_set_env_entries_not_ordered(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'k1'
-              value: 'v1'
-            }
-            env_entry {
-              key: 'k2'
-              value: 'v2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'k2'
-              value: 'v2'
-            }
-            env_entry {
-              key: 'k1'
-              value: 'v1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_env_set_env_entries_differ(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'k1'
-              value: 'value_first'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'k1'
-              value: 'value_second'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_feature_preserves_env_set_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'first'
-              value: 'first'
-            }
-          }
-          env_set {
-            env_entry {
-              key: 'second'
-              value: 'second'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            env_entry {
-              key: 'second'
-              value: 'second'
-            }
-          }
-          env_set {
-            env_entry {
-              key: 'first'
-              value: 'first'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after the change:",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_ignores_env_set(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          env_set {
-            env_entry {
-              key: 'k1'
-              value: 'value_first'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          env_set {
-            env_entry {
-              key: 'k1'
-              value: 'value_second'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_env_set_ignores_with_feature_set_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set{
-            with_feature {
-              feature: 'feature1'
-            }
-            with_feature {
-              not_feature: 'feature2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set {
-            with_feature {
-              not_feature: 'feature2'
-            }
-            with_feature {
-              feature: 'feature1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_env_set_ignores_with_feature_set_lists_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set{
-            with_feature {
-              feature: 'feature1'
-              feature: 'feature2'
-              not_feature: 'not_feature1'
-              not_feature: 'not_feature2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          env_set{
-            with_feature {
-              feature: 'feature2'
-              feature: 'feature1'
-              not_feature: 'not_feature2'
-              not_feature: 'not_feature1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_set_ignores_actions_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set {
-             action: 'a1'
-             action: 'a2'
-          }
-        }
-    """)
-    second = make_toolchain("""
-       feature {
-          name: 'feature'
-          flag_set {
-             action: 'a2'
-             action: 'a1'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_action_config_flag_set_actions_ignored(self):
-    first = make_toolchain("""
-      action_config {
-          config_name: 'config'
-          flag_set {
-            action: 'a1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-      action_config {
-          config_name: 'config'
-          flag_set {
-            action: 'a2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_set_ignores_with_feature_set_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set {
-            with_feature {
-              feature: 'feature1'
-            }
-            with_feature {
-              not_feature: 'feature2'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set {
-            with_feature {
-              feature: 'feature1'
-            }
-            with_feature {
-              not_feature: 'feature2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set {
-            with_feature {
-              not_feature: 'feature2'
-            }
-            with_feature {
-              feature: 'feature1'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set {
-            with_feature {
-              not_feature: 'feature2'
-            }
-            with_feature {
-              feature: 'feature1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_set_ignores_with_feature_set_lists_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            with_feature {
-              feature: 'feature1'
-              feature: 'feature2'
-              not_feature: 'not_feature1'
-              not_feature: 'not_feature2'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            with_feature {
-              feature: 'feature1'
-              feature: 'feature2'
-              not_feature: 'not_feature1'
-              not_feature: 'not_feature2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            with_feature {
-              feature: 'feature2'
-              feature: 'feature1'
-              not_feature: 'not_feature2'
-              not_feature: 'not_feature1'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            with_feature {
-              feature: 'feature2'
-              feature: 'feature1'
-              not_feature: 'not_feature2'
-              not_feature: 'not_feature1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_set_preserves_flag_group_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set {
-            flag_group {
-              flag: 'a'
-            }
-            flag_group {
-              flag: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set {
-             flag_group {
-               flag: 'a'
-             }
-             flag_group {
-               flag: 'b'
-             }
-          }
-        }
-    """)
-    second = make_toolchain("""
-       feature {
-          name: 'feature'
-          flag_set {
-            flag_group {
-              flag: 'b'
-            }
-            flag_group {
-              flag: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set {
-            flag_group {
-              flag: 'b'
-            }
-            flag_group {
-              flag: 'a'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_preserves_flags_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              flag: 'flag1'
-              flag: 'flag2'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              flag: 'flag1'
-              flag: 'flag2'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              flag: 'flag2'
-              flag: 'flag1'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              flag: 'flag2'
-              flag: 'flag1'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_iterate_over_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              iterate_over: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              iterate_over: 'a'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              iterate_over: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              iterate_over: 'b'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_expand_if_true_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_true: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_true: 'a'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_true: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_true: 'b'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_expand_if_false_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_false: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_false: 'a'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_false: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_false: 'b'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_expand_if_all_available_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'a'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'b'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_expand_if_none_available_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'a'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'b'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_expand_if_all_available_ignores_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'a'
-              expand_if_all_available: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'a'
-              expand_if_all_available: 'b'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'b'
-              expand_if_all_available: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_all_available: 'b'
-              expand_if_all_available: 'a'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_group_expand_if_none_available_ignores_order(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'a'
-              expand_if_none_available: 'b'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'a'
-              expand_if_none_available: 'b'
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'b'
-              expand_if_none_available: 'a'
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_none_available: 'b'
-              expand_if_none_available: 'a'
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_flag_group_expand_if_equal_differs(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_equal {
-                variable: 'first'
-                value: 'val'
-              }
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_equal {
-                variable: 'first'
-                value: 'val'
-              }
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              expand_if_equal {
-                variable: 'second'
-                value: 'val'
-              }
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              expand_if_equal {
-                variable: 'second'
-                value: 'val'
-              }
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_flag_group_flag_groups_differ(self):
-    first = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              flag_group {
-                flag: 'a'
-                flag: 'b'
-              }
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              flag_group {
-                flag: 'a'
-                flag: 'b'
-              }
-            }
-          }
-        }
-    """)
-    second = make_toolchain("""
-        feature {
-          name: 'feature'
-          flag_set{
-            flag_group {
-              flag_group {
-                flag: 'b'
-                flag: 'a'
-              }
-            }
-          }
-        }
-        action_config {
-          config_name: 'config'
-          flag_set{
-            flag_group {
-              flag_group {
-                flag: 'b'
-                flag: 'a'
-              }
-            }
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Feature 'feature' differs before and after", mock_stdout.getvalue()
-      )
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_configs_not_ordered(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'action1'
-        }
-        action_config {
-          config_name: 'action2'
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'action2'
-        }
-        action_config {
-          config_name: 'action1'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("Action configs not in right order", mock_stdout.getvalue())
-
-  def test_action_configs_missing(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'action1'
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'action2'
-        }
-    """)
-    error_only_first = (
-        "* List before change contains entries for the "
-        "following action_configs that the list after the "
-        "change doesn't:\n[action1]\n"
-    )
-    error_only_second = (
-        "* List after change contains entries for the "
-        "following action_configs that the list before the "
-        "change doesn't:\n[action2]\n"
-    )
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(error_only_first, mock_stdout.getvalue())
-      self.assertIn(error_only_second, mock_stdout.getvalue())
-
-  def test_action_config_enabled(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          enabled: true
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          enabled: false
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_action_name(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          action_name: 'config1'
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          action_name: 'config2'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_tool_tool_path_differs(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            tool_path: 'path1'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            tool_path: 'path2'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_tool_execution_requirements_differ(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            execution_requirement: 'a'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            execution_requirement: 'b'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_tool_execution_requirements_ignores_order(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            execution_requirement: 'a'
-            execution_requirement: 'b'
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            execution_requirement: 'b'
-            execution_requirement: 'a'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_action_config_implies_differs(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          implies: 'a'
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          implies: 'b'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_action_config_implies_preserves_order(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          implies: 'a'
-          implies: 'b'
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          implies: 'b'
-          implies: 'a'
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn(
-          "* Action config 'config' differs before and after",
-          mock_stdout.getvalue(),
-      )
-
-  def test_unused_tool_path(self):
-    first = make_toolchain("""
-        tool_path {
-          name: "empty"
-          path: ""
-        }
-    """)
-    second = make_toolchain("""
-        tool_path {
-          name: "empty"
-          path: "NOT_USED"
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-  def test_unused_tool_path_in_tool(self):
-    first = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            tool_path: ''
-          }
-        }
-    """)
-    second = make_toolchain("""
-        action_config {
-          config_name: 'config'
-          tool {
-            tool_path: 'NOT_USED'
-          }
-        }
-    """)
-    mock_stdout = StringIO()
-    with mock.patch("sys.stdout", mock_stdout):
-      compare_ctoolchains(first, second)
-      self.assertIn("No difference", mock_stdout.getvalue())
-
-
-if __name__ == "__main__":
-  unittest.main()
diff --git a/tools/migration/ctoolchain_compare.bzl b/tools/migration/ctoolchain_compare.bzl
deleted file mode 100644
index a9632af..0000000
--- a/tools/migration/ctoolchain_compare.bzl
+++ /dev/null
@@ -1,49 +0,0 @@
-"""A test rule that compares two CToolchains in proto format."""
-
-def _impl(ctx):
-    toolchain_config_proto = ctx.actions.declare_file(ctx.label.name + "_toolchain_config.proto")
-    ctx.actions.write(
-        toolchain_config_proto,
-        ctx.attr.toolchain_config[CcToolchainConfigInfo].proto,
-    )
-
-    script = ("%s --before='%s' --after='%s' --toolchain_identifier='%s'" % (
-        ctx.executable._comparator.short_path,
-        ctx.file.crosstool.short_path,
-        toolchain_config_proto.short_path,
-        ctx.attr.toolchain_identifier,
-    ))
-    test_executable = ctx.actions.declare_file(ctx.label.name)
-    ctx.actions.write(test_executable, script, is_executable = True)
-
-    runfiles = ctx.runfiles(files = [toolchain_config_proto, ctx.file.crosstool])
-    runfiles = runfiles.merge(ctx.attr._comparator[DefaultInfo].default_runfiles)
-
-    return DefaultInfo(runfiles = runfiles, executable = test_executable)
-
-cc_toolchains_compare_test = rule(
-    implementation = _impl,
-    attrs = {
-        "crosstool": attr.label(
-            mandatory = True,
-            allow_single_file = True,
-            doc = "Location of the CROSSTOOL file",
-        ),
-        "toolchain_config": attr.label(
-            mandatory = True,
-            providers = [CcToolchainConfigInfo],
-            doc = ("Starlark rule that replaces the CROSSTOOL file functionality " +
-                   "for the CToolchain with the given identifier"),
-        ),
-        "toolchain_identifier": attr.string(
-            mandatory = True,
-            doc = "identifier of the CToolchain that is being compared",
-        ),
-        "_comparator": attr.label(
-            default = ":ctoolchain_comparator",
-            executable = True,
-            cfg = "exec",
-        ),
-    },
-    test = True,
-)
diff --git a/tools/migration/legacy_fields_migration_lib.py b/tools/migration/legacy_fields_migration_lib.py
deleted file mode 100644
index 6107f92..0000000
--- a/tools/migration/legacy_fields_migration_lib.py
+++ /dev/null
@@ -1,564 +0,0 @@
-"""Module providing migrate_legacy_fields function.
-
-migrate_legacy_fields takes parsed CROSSTOOL proto and migrates it (inplace) to
-use only the features.
-
-Tracking issue: https://github.com/bazelbuild/bazel/issues/5187
-
-Since C++ rules team is working on migrating CROSSTOOL from text proto into
-Starlark, we advise CROSSTOOL owners to wait for the CROSSTOOL -> Starlark
-migrator before they invest too much time into fixing their pipeline. Tracking
-issue for the Starlark effort is
-https://github.com/bazelbuild/bazel/issues/5380.
-"""
-
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-
-ALL_CC_COMPILE_ACTIONS = [
-    "assemble", "preprocess-assemble", "linkstamp-compile", "c-compile",
-    "c++-compile", "c++-header-parsing", "c++-module-compile",
-    "c++-module-codegen", "lto-backend", "clif-match"
-]
-
-ALL_OBJC_COMPILE_ACTIONS = [
-    "objc-compile", "objc++-compile"
-]
-
-ALL_CXX_COMPILE_ACTIONS = [
-    action for action in ALL_CC_COMPILE_ACTIONS
-    if action not in ["c-compile", "preprocess-assemble", "assemble"]
-]
-
-ALL_CC_LINK_ACTIONS = [
-    "c++-link-executable", "c++-link-dynamic-library",
-    "c++-link-nodeps-dynamic-library"
-]
-
-ALL_OBJC_LINK_ACTIONS = [
-    "objc-executable", "objc++-executable",
-]
-
-DYNAMIC_LIBRARY_LINK_ACTIONS = [
-    "c++-link-dynamic-library", "c++-link-nodeps-dynamic-library"
-]
-
-NODEPS_DYNAMIC_LIBRARY_LINK_ACTIONS = ["c++-link-nodeps-dynamic-library"]
-
-TRANSITIVE_DYNAMIC_LIBRARY_LINK_ACTIONS = ["c++-link-dynamic-library"]
-
-TRANSITIVE_LINK_ACTIONS = ["c++-link-executable", "c++-link-dynamic-library"]
-
-CC_LINK_EXECUTABLE = ["c++-link-executable"]
-
-
-def compile_actions(toolchain):
-  """Returns compile actions for cc or objc rules."""
-  if _is_objc_toolchain(toolchain):
-    return ALL_CC_COMPILE_ACTIONS + ALL_OBJC_COMPILE_ACTIONS
-  else:
-    return ALL_CC_COMPILE_ACTIONS
-
-def link_actions(toolchain):
-  """Returns link actions for cc or objc rules."""
-  if _is_objc_toolchain(toolchain):
-    return ALL_CC_LINK_ACTIONS + ALL_OBJC_LINK_ACTIONS
-  else:
-    return ALL_CC_LINK_ACTIONS
-
-
-def executable_link_actions(toolchain):
-  """Returns transitive link actions for cc or objc rules."""
-  if _is_objc_toolchain(toolchain):
-    return CC_LINK_EXECUTABLE + ALL_OBJC_LINK_ACTIONS
-  else:
-    return CC_LINK_EXECUTABLE
-
-
-def _is_objc_toolchain(toolchain):
-  return any(ac.action_name == "objc-compile" for ac in toolchain.action_config)
-
-# Map converting from LinkingMode to corresponding feature name
-LINKING_MODE_TO_FEATURE_NAME = {
-    "FULLY_STATIC": "fully_static_link",
-    "MOSTLY_STATIC": "static_linking_mode",
-    "DYNAMIC": "dynamic_linking_mode",
-    "MOSTLY_STATIC_LIBRARIES": "static_linking_mode_nodeps_library",
-}
-
-def migrate_legacy_fields(crosstool):
-  """Migrates parsed crosstool (inplace) to not use legacy fields."""
-  crosstool.ClearField("default_toolchain")
-  for toolchain in crosstool.toolchain:
-    _ = [_migrate_expand_if_all_available(f) for f in toolchain.feature]
-    _ = [_migrate_expand_if_all_available(ac) for ac in toolchain.action_config]
-    _ = [_migrate_repeated_expands(f) for f in toolchain.feature]
-    _ = [_migrate_repeated_expands(ac) for ac in toolchain.action_config]
-
-    if (toolchain.dynamic_library_linker_flag or
-        _contains_dynamic_flags(toolchain)) and not _get_feature(
-            toolchain, "supports_dynamic_linker"):
-      feature = toolchain.feature.add()
-      feature.name = "supports_dynamic_linker"
-      feature.enabled = True
-
-    if toolchain.supports_start_end_lib and not _get_feature(
-        toolchain, "supports_start_end_lib"):
-      feature = toolchain.feature.add()
-      feature.name = "supports_start_end_lib"
-      feature.enabled = True
-
-    if toolchain.supports_interface_shared_objects and not _get_feature(
-        toolchain, "supports_interface_shared_libraries"):
-      feature = toolchain.feature.add()
-      feature.name = "supports_interface_shared_libraries"
-      feature.enabled = True
-
-    if toolchain.supports_embedded_runtimes and not _get_feature(
-        toolchain, "static_link_cpp_runtimes"):
-      feature = toolchain.feature.add()
-      feature.name = "static_link_cpp_runtimes"
-      feature.enabled = True
-
-    if toolchain.needsPic and not _get_feature(toolchain, "supports_pic"):
-      feature = toolchain.feature.add()
-      feature.name = "supports_pic"
-      feature.enabled = True
-
-    if toolchain.supports_fission and not _get_feature(
-        toolchain, "per_object_debug_info"):
-      # feature {
-      #   name: "per_object_debug_info"
-      #   enabled: true
-      #   flag_set {
-      #     action: "assemble"
-      #     action: "preprocess-assemble"
-      #     action: "c-compile"
-      #     action: "c++-compile"
-      #     action: "c++-module-codegen"
-      #     action: "lto-backend"
-      #     flag_group {
-      #       expand_if_all_available: 'is_using_fission'",
-      #       flag: "-gsplit-dwarf"
-      #     }
-      #   }
-      # }
-      feature = toolchain.feature.add()
-      feature.name = "per_object_debug_info"
-      feature.enabled = True
-      flag_set = feature.flag_set.add()
-      flag_set.action[:] = [
-          "c-compile", "c++-compile", "c++-module-codegen", "assemble",
-          "preprocess-assemble", "lto-backend"
-      ]
-      flag_group = flag_set.flag_group.add()
-      flag_group.expand_if_all_available[:] = ["is_using_fission"]
-      flag_group.flag[:] = ["-gsplit-dwarf"]
-
-    if toolchain.objcopy_embed_flag and not _get_feature(
-        toolchain, "objcopy_embed_flags"):
-      feature = toolchain.feature.add()
-      feature.name = "objcopy_embed_flags"
-      feature.enabled = True
-      flag_set = feature.flag_set.add()
-      flag_set.action[:] = ["objcopy_embed_data"]
-      flag_group = flag_set.flag_group.add()
-      flag_group.flag[:] = toolchain.objcopy_embed_flag
-
-      action_config = toolchain.action_config.add()
-      action_config.action_name = "objcopy_embed_data"
-      action_config.config_name = "objcopy_embed_data"
-      action_config.enabled = True
-      tool = action_config.tool.add()
-      tool.tool_path = _find_tool_path(toolchain, "objcopy")
-
-    if toolchain.ld_embed_flag and not _get_feature(
-        toolchain, "ld_embed_flags"):
-      feature = toolchain.feature.add()
-      feature.name = "ld_embed_flags"
-      feature.enabled = True
-      flag_set = feature.flag_set.add()
-      flag_set.action[:] = ["ld_embed_data"]
-      flag_group = flag_set.flag_group.add()
-      flag_group.flag[:] = toolchain.ld_embed_flag
-
-      action_config = toolchain.action_config.add()
-      action_config.action_name = "ld_embed_data"
-      action_config.config_name = "ld_embed_data"
-      action_config.enabled = True
-      tool = action_config.tool.add()
-      tool.tool_path = _find_tool_path(toolchain, "ld")
-
-
-    # Create default_link_flags feature for linker_flag
-    flag_sets = _extract_legacy_link_flag_sets_for(toolchain)
-    if flag_sets:
-      if _get_feature(toolchain, "default_link_flags"):
-        continue
-      if _get_feature(toolchain, "legacy_link_flags"):
-        for f in toolchain.feature:
-          if f.name == "legacy_link_flags":
-            f.ClearField("flag_set")
-            feature = f
-            _rename_feature_in_toolchain(toolchain, "legacy_link_flags",
-                                         "default_link_flags")
-            break
-      else:
-        feature = _prepend_feature(toolchain)
-      feature.name = "default_link_flags"
-      feature.enabled = True
-      _add_flag_sets(feature, flag_sets)
-
-    # Create default_compile_flags feature for compiler_flag, cxx_flag
-    flag_sets = _extract_legacy_compile_flag_sets_for(toolchain)
-    if flag_sets and not _get_feature(toolchain, "default_compile_flags"):
-      if _get_feature(toolchain, "legacy_compile_flags"):
-        for f in toolchain.feature:
-          if f.name == "legacy_compile_flags":
-            f.ClearField("flag_set")
-            feature = f
-            _rename_feature_in_toolchain(toolchain, "legacy_compile_flags",
-                                         "default_compile_flags")
-            break
-      else:
-        feature = _prepend_feature(toolchain)
-      feature.enabled = True
-      feature.name = "default_compile_flags"
-      _add_flag_sets(feature, flag_sets)
-
-    # Unfiltered cxx flags have to have their own special feature.
-    # "unfiltered_compile_flags" is a well-known (by Bazel) feature name that is
-    # excluded from nocopts filtering.
-    if toolchain.unfiltered_cxx_flag:
-      # If there already is a feature named unfiltered_compile_flags, the
-      # crosstool is already migrated for unfiltered_compile_flags
-      if _get_feature(toolchain, "unfiltered_compile_flags"):
-        for f in toolchain.feature:
-          if f.name == "unfiltered_compile_flags":
-            for flag_set in f.flag_set:
-              for flag_group in flag_set.flag_group:
-                if flag_group.iterate_over == "unfiltered_compile_flags":
-                  flag_group.ClearField("iterate_over")
-                  flag_group.ClearField("expand_if_all_available")
-                  flag_group.ClearField("flag")
-                  flag_group.flag[:] = toolchain.unfiltered_cxx_flag
-      else:
-        if not _get_feature(toolchain, "user_compile_flags"):
-          feature = toolchain.feature.add()
-          feature.name = "user_compile_flags"
-          feature.enabled = True
-          flag_set = feature.flag_set.add()
-          flag_set.action[:] = compile_actions(toolchain)
-          flag_group = flag_set.flag_group.add()
-          flag_group.expand_if_all_available[:] = ["user_compile_flags"]
-          flag_group.iterate_over = "user_compile_flags"
-          flag_group.flag[:] = ["%{user_compile_flags}"]
-
-        if not _get_feature(toolchain, "sysroot"):
-          sysroot_actions = compile_actions(toolchain) + link_actions(toolchain)
-          sysroot_actions.remove("assemble")
-          feature = toolchain.feature.add()
-          feature.name = "sysroot"
-          feature.enabled = True
-          flag_set = feature.flag_set.add()
-          flag_set.action[:] = sysroot_actions
-          flag_group = flag_set.flag_group.add()
-          flag_group.expand_if_all_available[:] = ["sysroot"]
-          flag_group.flag[:] = ["--sysroot=%{sysroot}"]
-
-        feature = toolchain.feature.add()
-        feature.name = "unfiltered_compile_flags"
-        feature.enabled = True
-        flag_set = feature.flag_set.add()
-        flag_set.action[:] = compile_actions(toolchain)
-        flag_group = flag_set.flag_group.add()
-        flag_group.flag[:] = toolchain.unfiltered_cxx_flag
-
-    # clear fields
-    toolchain.ClearField("debian_extra_requires")
-    toolchain.ClearField("gcc_plugin_compiler_flag")
-    toolchain.ClearField("ar_flag")
-    toolchain.ClearField("ar_thin_archives_flag")
-    toolchain.ClearField("gcc_plugin_header_directory")
-    toolchain.ClearField("mao_plugin_header_directory")
-    toolchain.ClearField("supports_normalizing_ar")
-    toolchain.ClearField("supports_thin_archives")
-    toolchain.ClearField("supports_incremental_linker")
-    toolchain.ClearField("supports_dsym")
-    toolchain.ClearField("supports_gold_linker")
-    toolchain.ClearField("default_python_top")
-    toolchain.ClearField("default_python_version")
-    toolchain.ClearField("python_preload_swigdeps")
-    toolchain.ClearField("needsPic")
-    toolchain.ClearField("compilation_mode_flags")
-    toolchain.ClearField("linking_mode_flags")
-    toolchain.ClearField("unfiltered_cxx_flag")
-    toolchain.ClearField("ld_embed_flag")
-    toolchain.ClearField("objcopy_embed_flag")
-    toolchain.ClearField("supports_start_end_lib")
-    toolchain.ClearField("supports_interface_shared_objects")
-    toolchain.ClearField("supports_fission")
-    toolchain.ClearField("supports_embedded_runtimes")
-    toolchain.ClearField("compiler_flag")
-    toolchain.ClearField("cxx_flag")
-    toolchain.ClearField("linker_flag")
-    toolchain.ClearField("dynamic_library_linker_flag")
-    toolchain.ClearField("static_runtimes_filegroup")
-    toolchain.ClearField("dynamic_runtimes_filegroup")
-
-    # Enable features that were previously enabled by Bazel
-    default_features = [
-        "dependency_file", "random_seed", "module_maps", "module_map_home_cwd",
-        "header_module_compile", "include_paths", "pic", "preprocessor_define"
-    ]
-    for feature_name in default_features:
-      feature = _get_feature(toolchain, feature_name)
-      if feature:
-        feature.enabled = True
-
-
-def _find_tool_path(toolchain, tool_name):
-  """Returns the tool path of the tool with the given name."""
-  for tool in toolchain.tool_path:
-    if tool.name == tool_name:
-      return tool.path
-  return None
-
-
-def _add_flag_sets(feature, flag_sets):
-  """Add flag sets into a feature."""
-  for flag_set in flag_sets:
-    with_feature = flag_set[0]
-    actions = flag_set[1]
-    flags = flag_set[2]
-    expand_if_all_available = flag_set[3]
-    not_feature = None
-    if len(flag_set) >= 5:
-      not_feature = flag_set[4]
-    flag_set = feature.flag_set.add()
-    if with_feature is not None:
-      flag_set.with_feature.add().feature[:] = [with_feature]
-    if not_feature is not None:
-      flag_set.with_feature.add().not_feature[:] = [not_feature]
-    flag_set.action[:] = actions
-    flag_group = flag_set.flag_group.add()
-    flag_group.expand_if_all_available[:] = expand_if_all_available
-    flag_group.flag[:] = flags
-  return feature
-
-
-def _extract_legacy_compile_flag_sets_for(toolchain):
-  """Get flag sets for default_compile_flags feature."""
-  result = []
-  if toolchain.compiler_flag:
-    result.append(
-        [None, compile_actions(toolchain), toolchain.compiler_flag, []])
-
-  # Migrate compiler_flag from compilation_mode_flags
-  for cmf in toolchain.compilation_mode_flags:
-    mode = crosstool_config_pb2.CompilationMode.Name(cmf.mode).lower()
-    # coverage mode has been a noop since a while
-    if mode == "coverage":
-      continue
-
-    if (cmf.compiler_flag or
-        cmf.cxx_flag) and not _get_feature(toolchain, mode):
-      feature = toolchain.feature.add()
-      feature.name = mode
-
-    if cmf.compiler_flag:
-      result.append([mode, compile_actions(toolchain), cmf.compiler_flag, []])
-
-  if toolchain.cxx_flag:
-    result.append([None, ALL_CXX_COMPILE_ACTIONS, toolchain.cxx_flag, []])
-
-  # Migrate compiler_flag/cxx_flag from compilation_mode_flags
-  for cmf in toolchain.compilation_mode_flags:
-    mode = crosstool_config_pb2.CompilationMode.Name(cmf.mode).lower()
-    # coverage mode has been a noop since a while
-    if mode == "coverage":
-      continue
-
-    if cmf.cxx_flag:
-      result.append([mode, ALL_CXX_COMPILE_ACTIONS, cmf.cxx_flag, []])
-
-  return result
-
-
-def _extract_legacy_link_flag_sets_for(toolchain):
-  """Get flag sets for default_link_flags feature."""
-  result = []
-
-  # Migrate linker_flag
-  if toolchain.linker_flag:
-    result.append([None, link_actions(toolchain), toolchain.linker_flag, []])
-
-  # Migrate linker_flags from compilation_mode_flags
-  for cmf in toolchain.compilation_mode_flags:
-    mode = crosstool_config_pb2.CompilationMode.Name(cmf.mode).lower()
-    # coverage mode has beed a noop since a while
-    if mode == "coverage":
-      continue
-
-    if cmf.linker_flag and not _get_feature(toolchain, mode):
-      feature = toolchain.feature.add()
-      feature.name = mode
-
-    if cmf.linker_flag:
-      result.append([mode, link_actions(toolchain), cmf.linker_flag, []])
-
-  # Migrate linker_flags from linking_mode_flags
-  for lmf in toolchain.linking_mode_flags:
-    mode = crosstool_config_pb2.LinkingMode.Name(lmf.mode)
-    feature_name = LINKING_MODE_TO_FEATURE_NAME.get(mode)
-    # if the feature is already there, we don't migrate, lmf is not used
-    if _get_feature(toolchain, feature_name):
-      continue
-
-    if lmf.linker_flag:
-      feature = toolchain.feature.add()
-      feature.name = feature_name
-      if mode == "DYNAMIC":
-        result.append(
-            [None, NODEPS_DYNAMIC_LIBRARY_LINK_ACTIONS, lmf.linker_flag, []])
-        result.append([
-            None,
-            TRANSITIVE_DYNAMIC_LIBRARY_LINK_ACTIONS,
-            lmf.linker_flag,
-            [],
-            "static_link_cpp_runtimes",
-        ])
-        result.append([
-            feature_name,
-            executable_link_actions(toolchain), lmf.linker_flag, []
-        ])
-      elif mode == "MOSTLY_STATIC":
-        result.append(
-            [feature_name,
-             CC_LINK_EXECUTABLE, lmf.linker_flag, []])
-      else:
-        result.append(
-           [feature_name,
-            link_actions(toolchain), lmf.linker_flag, []])
-
-  if toolchain.dynamic_library_linker_flag:
-    result.append([
-        None, DYNAMIC_LIBRARY_LINK_ACTIONS,
-        toolchain.dynamic_library_linker_flag, []
-    ])
-
-  if toolchain.test_only_linker_flag:
-    result.append([
-        None,
-        link_actions(toolchain), toolchain.test_only_linker_flag,
-        ["is_cc_test"]
-    ])
-
-  return result
-
-
-def _prepend_feature(toolchain):
-  """Create a new feature and make it be the first in the toolchain."""
-  features = toolchain.feature
-  toolchain.ClearField("feature")
-  new_feature = toolchain.feature.add()
-  toolchain.feature.extend(features)
-  return new_feature
-
-
-def _get_feature(toolchain, name):
-  """Returns feature with a given name or None."""
-  for feature in toolchain.feature:
-    if feature.name == name:
-      return feature
-  return None
-
-
-def _migrate_expand_if_all_available(message):
-  """Move expand_if_all_available field to flag_groups."""
-  for flag_set in message.flag_set:
-    if flag_set.expand_if_all_available:
-      for flag_group in flag_set.flag_group:
-        new_vars = (
-            flag_group.expand_if_all_available[:] +
-            flag_set.expand_if_all_available[:])
-        flag_group.expand_if_all_available[:] = new_vars
-      flag_set.ClearField("expand_if_all_available")
-
-
-def _migrate_repeated_expands(message):
-  """Replace repeated legacy fields with nesting."""
-  todo_queue = []
-  for flag_set in message.flag_set:
-    todo_queue.extend(flag_set.flag_group)
-  while todo_queue:
-    flag_group = todo_queue.pop()
-    todo_queue.extend(flag_group.flag_group)
-    if len(flag_group.expand_if_all_available) <= 1 and len(
-        flag_group.expand_if_none_available) <= 1:
-      continue
-
-    current_children = flag_group.flag_group
-    current_flags = flag_group.flag
-    flag_group.ClearField("flag_group")
-    flag_group.ClearField("flag")
-
-    new_flag_group = flag_group.flag_group.add()
-    new_flag_group.flag_group.extend(current_children)
-    new_flag_group.flag.extend(current_flags)
-
-    if len(flag_group.expand_if_all_available) > 1:
-      expands_to_move = flag_group.expand_if_all_available[1:]
-      flag_group.expand_if_all_available[:] = [
-          flag_group.expand_if_all_available[0]
-      ]
-      new_flag_group.expand_if_all_available.extend(expands_to_move)
-
-    if len(flag_group.expand_if_none_available) > 1:
-      expands_to_move = flag_group.expand_if_none_available[1:]
-      flag_group.expand_if_none_available[:] = [
-          flag_group.expand_if_none_available[0]
-      ]
-      new_flag_group.expand_if_none_available.extend(expands_to_move)
-
-    todo_queue.append(new_flag_group)
-    todo_queue.append(flag_group)
-
-
-def _contains_dynamic_flags(toolchain):
-  for lmf in toolchain.linking_mode_flags:
-    mode = crosstool_config_pb2.LinkingMode.Name(lmf.mode)
-    if mode == "DYNAMIC":
-      return True
-  return False
-
-
-def _rename_feature_in_toolchain(toolchain, from_name, to_name):
-  for f in toolchain.feature:
-    _rename_feature_in(f, from_name, to_name)
-  for a in toolchain.action_config:
-    _rename_feature_in(a, from_name, to_name)
-
-
-def _rename_feature_in(msg, from_name, to_name):
-  if from_name in msg.implies:
-    msg.implies.remove(from_name)
-  for requires in msg.requires:
-    if from_name in requires.feature:
-      requires.feature.remove(from_name)
-      requires.feature.extend([to_name])
-    for flag_set in msg.flag_set:
-      for with_feature in flag_set.with_feature:
-        if from_name in with_feature.feature:
-          with_feature.feature.remove(from_name)
-          with_feature.feature.extend([to_name])
-        if from_name in with_feature.not_feature:
-          with_feature.not_feature.remove(from_name)
-          with_feature.not_feature.extend([to_name])
-    for env_set in msg.env_set:
-      for with_feature in env_set.with_feature:
-        if from_name in with_feature.feature:
-          with_feature.feature.remove(from_name)
-          with_feature.feature.extend([to_name])
-        if from_name in with_feature.not_feature:
-          with_feature.not_feature.remove(from_name)
-          with_feature.not_feature.extend([to_name])
diff --git a/tools/migration/legacy_fields_migration_lib_test.py b/tools/migration/legacy_fields_migration_lib_test.py
deleted file mode 100644
index 93972cc..0000000
--- a/tools/migration/legacy_fields_migration_lib_test.py
+++ /dev/null
@@ -1,1240 +0,0 @@
-import unittest
-from google.protobuf import text_format
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-from tools.migration.legacy_fields_migration_lib import ALL_CC_COMPILE_ACTIONS
-from tools.migration.legacy_fields_migration_lib import ALL_OBJC_COMPILE_ACTIONS
-from tools.migration.legacy_fields_migration_lib import ALL_CXX_COMPILE_ACTIONS
-from tools.migration.legacy_fields_migration_lib import ALL_CC_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import ALL_OBJC_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import DYNAMIC_LIBRARY_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import NODEPS_DYNAMIC_LIBRARY_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import TRANSITIVE_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import TRANSITIVE_DYNAMIC_LIBRARY_LINK_ACTIONS
-from tools.migration.legacy_fields_migration_lib import CC_LINK_EXECUTABLE
-from tools.migration.legacy_fields_migration_lib import migrate_legacy_fields
-
-
-def assert_has_feature(self, toolchain, name):
-  self.assertTrue(any(feature.name == name for feature in toolchain.feature))
-
-
-def make_crosstool(string):
-  crosstool = crosstool_config_pb2.CrosstoolRelease()
-  text_format.Merge("major_version: '123' minor_version: '456'", crosstool)
-  toolchain = crosstool.toolchain.add()
-  text_format.Merge(string, toolchain)
-  return crosstool
-
-
-def migrate_to_string(crosstool):
-  migrate_legacy_fields(crosstool)
-  return to_string(crosstool)
-
-
-def to_string(crosstool):
-  return text_format.MessageToString(crosstool)
-
-
-class LegacyFieldsMigrationLibTest(unittest.TestCase):
-
-  def test_deletes_fields(self):
-    crosstool = make_crosstool("""
-          debian_extra_requires: 'debian-1'
-          gcc_plugin_compiler_flag: 'gcc_plugin_compiler_flag-1'
-          ar_flag: 'ar_flag-1'
-          ar_thin_archives_flag: 'ar_thin_archives_flag-1'
-          gcc_plugin_header_directory: 'gcc_plugin_header_directory-1'
-          mao_plugin_header_directory: 'mao_plugin_header_directory-1'
-          default_python_top: 'default_python_top-1'
-          default_python_version: 'default_python_version-1'
-          python_preload_swigdeps: false
-          supports_normalizing_ar: false
-          supports_thin_archives: false
-          supports_incremental_linker: false
-          supports_dsym: false
-          supports_gold_linker: false
-          needsPic: false
-          supports_start_end_lib: false
-          supports_interface_shared_objects: false
-          supports_fission: false
-          supports_embedded_runtimes: false
-          static_runtimes_filegroup: 'yolo'
-          dynamic_runtimes_filegroup: 'yolo'
-      """)
-    output = migrate_to_string(crosstool)
-    self.assertNotIn("debian_extra_requires", output)
-    self.assertNotIn("gcc_plugin_compiler_flag", output)
-    self.assertNotIn("ar_flag", output)
-    self.assertNotIn("ar_thin_archives_flag", output)
-    self.assertNotIn("gcc_plugin_header_directory", output)
-    self.assertNotIn("mao_plugin_header_directory", output)
-    self.assertNotIn("supports_normalizing_ar", output)
-    self.assertNotIn("supports_thin_archives", output)
-    self.assertNotIn("supports_incremental_linker", output)
-    self.assertNotIn("supports_dsym", output)
-    self.assertNotIn("default_python_top", output)
-    self.assertNotIn("default_python_version", output)
-    self.assertNotIn("python_preload_swigdeps", output)
-    self.assertNotIn("supports_gold_linker", output)
-    self.assertNotIn("needsPic", output)
-    self.assertNotIn("supports_start_end_lib", output)
-    self.assertNotIn("supports_interface_shared_objects", output)
-    self.assertNotIn("supports_fission", output)
-    self.assertNotIn("supports_embedded_runtimes", output)
-    self.assertNotIn("static_runtimes_filegroup", output)
-    self.assertNotIn("dynamic_runtimes_filegroup", output)
-
-  def test_deletes_default_toolchains(self):
-    crosstool = make_crosstool("")
-    crosstool.default_toolchain.add()
-    self.assertEqual(len(crosstool.default_toolchain), 1)
-    migrate_legacy_fields(crosstool)
-    self.assertEqual(len(crosstool.default_toolchain), 0)
-
-  def test_replace_legacy_compile_flags(self):
-    crosstool = make_crosstool("""
-        feature { name: 'foo' }
-        feature { name: 'legacy_compile_flags' }
-        compiler_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compiler_flag), 0)
-    self.assertEqual(output.feature[0].name, "foo")
-    self.assertEqual(output.feature[1].name, "default_compile_flags")
-    self.assertEqual(output.feature[1].flag_set[0].action,
-                     ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[1].flag_set[0].flag_group[0].flag,
-                     ["clang-flag-1"])
-
-  def test_replace_legacy_compile_flags_in_action_configs(self):
-    crosstool = make_crosstool("""
-        feature {
-          name: 'foo'
-          implies: 'legacy_compile_flags'
-          requires: { feature: 'legacy_compile_flags' }
-          flag_set {
-            with_feature { feature: 'legacy_compile_flags' }
-            with_feature { not_feature: 'legacy_compile_flags' }
-          }
-          env_set {
-            with_feature { feature: 'legacy_compile_flags' }
-            with_feature { not_feature: 'legacy_compile_flags' }
-          }
-        }
-        feature { name: 'legacy_compile_flags' }
-        action_config {
-          action_name: 'foo'
-          config_name: 'foo'
-          implies: 'legacy_compile_flags'
-          requires: { feature: 'legacy_compile_flags' }
-          flag_set {
-            with_feature { feature: 'legacy_compile_flags' }
-            with_feature { not_feature: 'legacy_compile_flags' }
-          }
-          env_set {
-            with_feature { feature: 'legacy_compile_flags' }
-            with_feature { not_feature: 'legacy_compile_flags' }
-          }
-        }
-        compiler_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.action_config[0].action_name, "foo")
-    self.assertEqual(output.action_config[0].implies, [])
-    self.assertEqual(output.action_config[0].requires[0].feature,
-                     ["default_compile_flags"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].with_feature[0].feature,
-        ["default_compile_flags"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].with_feature[1].not_feature,
-        ["default_compile_flags"])
-    self.assertEqual(output.action_config[0].env_set[0].with_feature[0].feature,
-                     ["default_compile_flags"])
-    self.assertEqual(
-        output.action_config[0].env_set[0].with_feature[1].not_feature,
-        ["default_compile_flags"])
-    self.assertEqual(output.feature[0].name, "foo")
-    self.assertEqual(output.feature[0].implies, [])
-    self.assertEqual(output.feature[0].requires[0].feature,
-                     ["default_compile_flags"])
-    self.assertEqual(output.feature[0].flag_set[0].with_feature[0].feature,
-                     ["default_compile_flags"])
-    self.assertEqual(output.feature[0].flag_set[0].with_feature[1].not_feature,
-                     ["default_compile_flags"])
-    self.assertEqual(output.feature[0].env_set[0].with_feature[0].feature,
-                     ["default_compile_flags"])
-    self.assertEqual(output.feature[0].env_set[0].with_feature[1].not_feature,
-                     ["default_compile_flags"])
-
-  def test_replace_legacy_link_flags(self):
-    crosstool = make_crosstool("""
-        feature { name: 'foo' }
-        feature { name: 'legacy_link_flags' }
-        linker_flag: 'ld-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compiler_flag), 0)
-    self.assertEqual(output.feature[0].name, "foo")
-    self.assertEqual(output.feature[1].name, "default_link_flags")
-    self.assertEqual(output.feature[1].flag_set[0].action, ALL_CC_LINK_ACTIONS)
-    self.assertEqual(output.feature[1].flag_set[0].flag_group[0].flag,
-                     ["ld-flag-1"])
-
-  def test_replace_legacy_link_flags_in_action_configs(self):
-    crosstool = make_crosstool("""
-        feature {
-          name: 'foo'
-          implies: 'legacy_link_flags'
-          requires: { feature: 'legacy_link_flags' }
-          flag_set {
-            with_feature { feature: 'legacy_link_flags' }
-            with_feature { not_feature: 'legacy_link_flags' }
-          }
-          env_set {
-            with_feature { feature: 'legacy_link_flags' }
-            with_feature { not_feature: 'legacy_link_flags' }
-          }
-        }
-        feature { name: 'legacy_link_flags' }
-        action_config {
-          action_name: 'foo'
-          config_name: 'foo'
-          implies: 'legacy_link_flags'
-          requires: { feature: 'legacy_link_flags' }
-          flag_set {
-            with_feature { feature: 'legacy_link_flags' }
-            with_feature { not_feature: 'legacy_link_flags' }
-          }
-          env_set {
-            with_feature { feature: 'legacy_link_flags' }
-            with_feature { not_feature: 'legacy_link_flags' }
-          }
-        }
-        linker_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.action_config[0].action_name, "foo")
-    self.assertEqual(output.action_config[0].implies, [])
-    self.assertEqual(output.action_config[0].requires[0].feature,
-                     ["default_link_flags"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].with_feature[0].feature,
-        ["default_link_flags"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].with_feature[1].not_feature,
-        ["default_link_flags"])
-    self.assertEqual(output.action_config[0].env_set[0].with_feature[0].feature,
-                     ["default_link_flags"])
-    self.assertEqual(
-        output.action_config[0].env_set[0].with_feature[1].not_feature,
-        ["default_link_flags"])
-    self.assertEqual(output.feature[0].name, "foo")
-    self.assertEqual(output.feature[0].implies, [])
-    self.assertEqual(output.feature[0].requires[0].feature,
-                     ["default_link_flags"])
-    self.assertEqual(output.feature[0].flag_set[0].with_feature[0].feature,
-                     ["default_link_flags"])
-    self.assertEqual(output.feature[0].flag_set[0].with_feature[1].not_feature,
-                     ["default_link_flags"])
-    self.assertEqual(output.feature[0].env_set[0].with_feature[0].feature,
-                     ["default_link_flags"])
-    self.assertEqual(output.feature[0].env_set[0].with_feature[1].not_feature,
-                     ["default_link_flags"])
-
-
-  def test_migrate_compiler_flags(self):
-    crosstool = make_crosstool("""
-        compiler_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compiler_flag), 0)
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action, ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["clang-flag-1"])
-
-  def test_migrate_compiler_flags_for_objc(self):
-    crosstool = make_crosstool("""
-        action_config { action_name: "objc-compile" }
-        compiler_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compiler_flag), 0)
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action, ALL_CC_COMPILE_ACTIONS + ALL_OBJC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["clang-flag-1"])
-
-  def test_migrate_cxx_flags(self):
-    crosstool = make_crosstool("""
-        cxx_flag: 'clang-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.cxx_flag), 0)
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action,
-                     ALL_CXX_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["clang-flag-1"])
-
-  def test_compiler_flag_come_before_cxx_flags(self):
-    crosstool = make_crosstool("""
-        compiler_flag: 'clang-flag-1'
-        cxx_flag: 'clang-flag-2'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action, ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[1].action,
-                     ALL_CXX_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["clang-flag-1"])
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[0].flag,
-                     ["clang-flag-2"])
-
-  def test_migrate_linker_flags(self):
-    crosstool = make_crosstool("""
-        linker_flag: 'linker-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.linker_flag), 0)
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action, ALL_CC_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["linker-flag-1"])
-
-  def test_migrate_dynamic_library_linker_flags(self):
-    crosstool = make_crosstool("""
-        dynamic_library_linker_flag: 'linker-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.dynamic_library_linker_flag), 0)
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action,
-                     DYNAMIC_LIBRARY_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["linker-flag-1"])
-
-  def test_compilation_mode_flags(self):
-    crosstool = make_crosstool("""
-        compiler_flag: "compile-flag-1"
-        cxx_flag: "cxx-flag-1"
-        linker_flag: "linker-flag-1"
-        compilation_mode_flags {
-          mode: OPT
-          compiler_flag: "opt-flag-1"
-          cxx_flag: "opt-flag-2"
-          linker_flag: "opt-flag-3"
-        }
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compilation_mode_flags), 0)
-    assert_has_feature(self, output, "opt")
-
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[1].name, "default_link_flags")
-
-    # flag set for compiler_flag fields
-    self.assertEqual(len(output.feature[0].flag_set[0].with_feature), 0)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["compile-flag-1"])
-
-    # flag set for compiler_flag from compilation_mode_flags
-    self.assertEqual(len(output.feature[0].flag_set[1].with_feature), 1)
-    self.assertEqual(output.feature[0].flag_set[1].with_feature[0].feature[0],
-                     "opt")
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[0].flag,
-                     ["opt-flag-1"])
-
-    # flag set for cxx_flag fields
-    self.assertEqual(len(output.feature[0].flag_set[2].with_feature), 0)
-    self.assertEqual(output.feature[0].flag_set[2].flag_group[0].flag,
-                     ["cxx-flag-1"])
-
-    # flag set for cxx_flag from compilation_mode_flags
-    self.assertEqual(len(output.feature[0].flag_set[3].with_feature), 1)
-    self.assertEqual(output.feature[0].flag_set[3].with_feature[0].feature[0],
-                     "opt")
-    self.assertEqual(output.feature[0].flag_set[3].flag_group[0].flag,
-                     ["opt-flag-2"])
-
-    # default_link_flags, flag set for linker_flag
-    self.assertEqual(len(output.feature[1].flag_set[0].with_feature), 0)
-    self.assertEqual(output.feature[1].flag_set[0].flag_group[0].flag,
-                     ["linker-flag-1"])
-
-    # default_link_flags, flag set for linker_flag from
-    # compilation_mode_flags
-    self.assertEqual(len(output.feature[1].flag_set[1].with_feature), 1)
-    self.assertEqual(output.feature[1].flag_set[1].with_feature[0].feature[0],
-                     "opt")
-    self.assertEqual(output.feature[1].flag_set[1].flag_group[0].flag,
-                     ["opt-flag-3"])
-
-  def test_linking_mode_flags(self):
-    crosstool = make_crosstool("""
-        linker_flag: "linker-flag-1"
-        compilation_mode_flags {
-          mode: DBG
-          linker_flag: "dbg-flag-1"
-        }
-        linking_mode_flags {
-          mode: MOSTLY_STATIC
-          linker_flag: "mostly-static-flag-1"
-        }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.compilation_mode_flags), 0)
-    self.assertEqual(len(output.linking_mode_flags), 0)
-
-    # flag set for linker_flag
-    self.assertEqual(len(output.feature[0].flag_set[0].with_feature), 0)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["linker-flag-1"])
-
-    # flag set for compilation_mode_flags
-    self.assertEqual(len(output.feature[0].flag_set[1].with_feature), 1)
-    self.assertEqual(output.feature[0].flag_set[1].with_feature[0].feature[0],
-                     "dbg")
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[0].flag,
-                     ["dbg-flag-1"])
-
-    # flag set for linking_mode_flags
-    self.assertEqual(len(output.feature[0].flag_set[2].with_feature), 1)
-    self.assertEqual(output.feature[0].flag_set[2].action, CC_LINK_EXECUTABLE)
-    self.assertEqual(output.feature[0].flag_set[2].with_feature[0].feature[0],
-                     "static_linking_mode")
-    self.assertEqual(output.feature[0].flag_set[2].flag_group[0].flag,
-                     ["mostly-static-flag-1"])
-
-  def test_coverage_compilation_mode_ignored(self):
-    crosstool = make_crosstool("""
-    compilation_mode_flags {
-      mode: COVERAGE
-      compiler_flag: "coverage-flag-1"
-      cxx_flag: "coverage-flag-2"
-      linker_flag: "coverage-flag-3"
-    }
-    """)
-    output = migrate_to_string(crosstool)
-    self.assertNotIn("compilation_mode_flags", output)
-    self.assertNotIn("coverage-flag-1", output)
-    self.assertNotIn("coverage-flag-2", output)
-    self.assertNotIn("coverage-flag-3", output)
-    self.assertNotIn("COVERAGE", output)
-
-  def test_supports_dynamic_linker_when_dynamic_library_linker_flag_is_used(
-      self):
-    crosstool = make_crosstool("""
-        dynamic_library_linker_flag: "foo"
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[1].name, "supports_dynamic_linker")
-    self.assertEqual(output.feature[1].enabled, True)
-
-  def test_supports_dynamic_linker_is_added_when_DYNAMIC_present(self):
-    crosstool = make_crosstool("""
-    linking_mode_flags {
-      mode: DYNAMIC
-    }
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_dynamic_linker")
-    self.assertEqual(output.feature[0].enabled, True)
-
-  def test_supports_dynamic_linker_is_not_added_when_present(self):
-    crosstool = make_crosstool("""
-    feature { name: "supports_dynamic_linker" enabled: false }
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_dynamic_linker")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_all_linker_flag_ordering(self):
-    crosstool = make_crosstool("""
-    linker_flag: 'linker-flag-1'
-    compilation_mode_flags {
-        mode: OPT
-        linker_flag: 'cmf-flag-2'
-    }
-    linking_mode_flags {
-      mode: MOSTLY_STATIC
-      linker_flag: 'lmf-flag-3'
-    }
-    linking_mode_flags {
-      mode: DYNAMIC
-      linker_flag: 'lmf-dynamic-flag-4'
-    }
-    dynamic_library_linker_flag: 'dl-flag-5'
-    test_only_linker_flag: 'to-flag-6'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].action[:], ALL_CC_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag[:],
-                     ["linker-flag-1"])
-
-    self.assertEqual(output.feature[0].flag_set[1].action[:], ALL_CC_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[1].with_feature[0].feature[0],
-                     "opt")
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[0].flag,
-                     ["cmf-flag-2"])
-
-    self.assertEqual(output.feature[0].flag_set[2].action, CC_LINK_EXECUTABLE)
-    self.assertEqual(output.feature[0].flag_set[2].with_feature[0].feature[0],
-                     "static_linking_mode")
-    self.assertEqual(output.feature[0].flag_set[2].flag_group[0].flag,
-                     ["lmf-flag-3"])
-
-    self.assertEqual(len(output.feature[0].flag_set[3].with_feature), 0)
-    self.assertEqual(output.feature[0].flag_set[3].flag_group[0].flag,
-                     ["lmf-dynamic-flag-4"])
-    self.assertEqual(output.feature[0].flag_set[3].action,
-                     NODEPS_DYNAMIC_LIBRARY_LINK_ACTIONS)
-
-    self.assertEqual(
-        output.feature[0].flag_set[4].with_feature[0].not_feature[0],
-        "static_link_cpp_runtimes")
-    self.assertEqual(output.feature[0].flag_set[4].flag_group[0].flag,
-                     ["lmf-dynamic-flag-4"])
-    self.assertEqual(output.feature[0].flag_set[4].action,
-                     TRANSITIVE_DYNAMIC_LIBRARY_LINK_ACTIONS)
-
-    self.assertEqual(output.feature[0].flag_set[5].with_feature[0].feature[0],
-                     "dynamic_linking_mode")
-    self.assertEqual(output.feature[0].flag_set[5].flag_group[0].flag,
-                     ["lmf-dynamic-flag-4"])
-    self.assertEqual(output.feature[0].flag_set[5].action,
-                     CC_LINK_EXECUTABLE)
-
-    self.assertEqual(output.feature[0].flag_set[6].flag_group[0].flag,
-                     ["dl-flag-5"])
-    self.assertEqual(output.feature[0].flag_set[6].action,
-                     DYNAMIC_LIBRARY_LINK_ACTIONS)
-
-    self.assertEqual(output.feature[0].flag_set[7].flag_group[0].flag,
-                     ["to-flag-6"])
-    self.assertEqual(output.feature[0].flag_set[7].action, ALL_CC_LINK_ACTIONS)
-    self.assertEqual(
-        output.feature[0].flag_set[7].flag_group[0].expand_if_all_available,
-        ["is_cc_test"])
-
-  def test_all_linker_flag_objc_actions(self):
-    crosstool = make_crosstool("""
-    action_config { action_name: "objc-compile" }
-    linker_flag: 'linker-flag-1'
-    compilation_mode_flags {
-        mode: OPT
-        linker_flag: 'cmf-flag-2'
-    }
-    linking_mode_flags {
-      mode: MOSTLY_STATIC
-      linker_flag: 'lmf-flag-3'
-    }
-    dynamic_library_linker_flag: 'dl-flag-5'
-    test_only_linker_flag: 'to-flag-6'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action[:],
-                     ALL_CC_LINK_ACTIONS + ALL_OBJC_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[1].action[:],
-                     ALL_CC_LINK_ACTIONS + ALL_OBJC_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[2].action[:],
-                     CC_LINK_EXECUTABLE)
-    self.assertEqual(output.feature[0].flag_set[3].action[:],
-                     DYNAMIC_LIBRARY_LINK_ACTIONS)
-    self.assertEqual(output.feature[0].flag_set[4].action[:],
-                     ALL_CC_LINK_ACTIONS + ALL_OBJC_LINK_ACTIONS)
-
-  def test_linking_mode_features_are_not_added_when_present(self):
-    crosstool = make_crosstool("""
-    linking_mode_flags {
-      mode: DYNAMIC
-      linker_flag: 'dynamic-flag'
-    }
-    linking_mode_flags {
-      mode: FULLY_STATIC
-      linker_flag: 'fully-static-flag'
-    }
-    linking_mode_flags {
-      mode: MOSTLY_STATIC
-      linker_flag: 'mostly-static-flag'
-    }
-    linking_mode_flags {
-      mode: MOSTLY_STATIC_LIBRARIES
-      linker_flag: 'mostly-static-libraries-flag'
-    }
-    feature { name: "static_linking_mode" }
-    feature { name: "dynamic_linking_mode" }
-    feature { name: "static_linking_mode_nodeps_library" }
-    feature { name: "fully_static_link" }
-    """)
-    output = migrate_to_string(crosstool)
-    self.assertNotIn("linking_mode_flags", output)
-    self.assertNotIn("DYNAMIC", output)
-    self.assertNotIn("MOSTLY_STATIC", output)
-    self.assertNotIn("MOSTLY_STATIC_LIBRARIES", output)
-    self.assertNotIn("MOSTLY_STATIC_LIBRARIES", output)
-    self.assertNotIn("dynamic-flag", output)
-    self.assertNotIn("fully-static-flag", output)
-    self.assertNotIn("mostly-static-flag", output)
-    self.assertNotIn("mostly-static-libraries-flag", output)
-
-  def test_unfiltered_require_user_compile_flags_and_sysroot(self):
-    crosstool = make_crosstool("""
-      feature { name: 'preexisting_feature' }
-      unfiltered_cxx_flag: 'unfiltered-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    # all these features are added after features that are already present in
-    # the crosstool
-    self.assertEqual(output.feature[0].name, "preexisting_feature")
-    self.assertEqual(output.feature[1].name, "user_compile_flags")
-    self.assertEqual(output.feature[2].name, "sysroot")
-    self.assertEqual(output.feature[3].name, "unfiltered_compile_flags")
-
-  def test_user_compile_flags_not_migrated_when_present(self):
-    crosstool = make_crosstool("""
-      unfiltered_cxx_flag: 'unfiltered-flag-1'
-      feature { name: 'user_compile_flags' }
-      feature { name: 'preexisting_feature' }
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "user_compile_flags")
-    self.assertEqual(output.feature[1].name, "preexisting_feature")
-    self.assertEqual(output.feature[2].name, "sysroot")
-    self.assertEqual(output.feature[3].name, "unfiltered_compile_flags")
-
-  def test_sysroot_not_migrated_when_present(self):
-    crosstool = make_crosstool("""
-      unfiltered_cxx_flag: 'unfiltered-flag-1'
-      feature { name: 'sysroot' }
-      feature { name: 'preexisting_feature' }
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "sysroot")
-    self.assertEqual(output.feature[1].name, "preexisting_feature")
-    self.assertEqual(output.feature[2].name, "user_compile_flags")
-    self.assertEqual(output.feature[3].name, "unfiltered_compile_flags")
-
-  def test_user_compile_flags(self):
-    crosstool = make_crosstool("""
-      unfiltered_cxx_flag: 'unfiltered-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "user_compile_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].action,
-                     ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].expand_if_all_available,
-        ["user_compile_flags"])
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].iterate_over,
-                     "user_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["%{user_compile_flags}"])
-
-  def test_sysroot(self):
-    sysroot_actions = ALL_CC_COMPILE_ACTIONS + ALL_CC_LINK_ACTIONS
-    sysroot_actions.remove("assemble")
-    self.assertTrue("assemble" not in sysroot_actions)
-    crosstool = make_crosstool("""
-      unfiltered_cxx_flag: 'unfiltered-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[1].name, "sysroot")
-    self.assertEqual(output.feature[1].enabled, True)
-    self.assertEqual(output.feature[1].flag_set[0].action, sysroot_actions)
-    self.assertEqual(
-        output.feature[1].flag_set[0].flag_group[0].expand_if_all_available,
-        ["sysroot"])
-    self.assertEqual(output.feature[1].flag_set[0].flag_group[0].flag,
-                     ["--sysroot=%{sysroot}"])
-
-  def test_unfiltered_compile_flags_is_not_added_when_already_present(self):
-    crosstool = make_crosstool("""
-            unfiltered_cxx_flag: 'unfiltered-flag-1'
-            feature { name: 'something_else' }
-            feature { name: 'unfiltered_compile_flags' }
-            feature { name: 'something_else_2' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(output.feature[1].name, "unfiltered_compile_flags")
-    self.assertEqual(len(output.feature[1].flag_set), 0)
-    self.assertEqual(output.feature[2].name, "something_else_2")
-
-  def test_unfiltered_compile_flags_is_not_edited_if_old_variant_present(self):
-    crosstool = make_crosstool("""
-            unfiltered_cxx_flag: 'unfiltered-flag-1'
-            feature {
-              name: 'unfiltered_compile_flags'
-              flag_set {
-                action: 'c-compile'
-                flag_group {
-                  flag: 'foo-flag-1'
-                }
-              }
-            }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "unfiltered_compile_flags")
-    self.assertEqual(len(output.feature[0].flag_set), 1)
-    self.assertEqual(output.feature[0].flag_set[0].action, ["c-compile"])
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["foo-flag-1"])
-
-  def test_use_of_unfiltered_compile_flags_var_is_removed_and_replaced(self):
-    crosstool = make_crosstool("""
-            unfiltered_cxx_flag: 'unfiltered-flag-1'
-            feature {
-              name: 'unfiltered_compile_flags'
-              flag_set {
-                action: 'c-compile'
-                flag_group {
-                  flag: 'foo-flag-1'
-                }
-              }
-              flag_set {
-                action: 'c++-compile'
-                flag_group {
-                  flag: 'bar-flag-1'
-                }
-                flag_group {
-                  expand_if_all_available: 'unfiltered_compile_flags'
-                  iterate_over: 'unfiltered_compile_flags'
-                  flag: '%{unfiltered_compile_flags}'
-                }
-                flag_group {
-                  flag: 'bar-flag-2'
-                }
-              }
-              flag_set {
-                action: 'c-compile'
-                flag_group {
-                  flag: 'foo-flag-2'
-                }
-              }
-            }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "unfiltered_compile_flags")
-    self.assertEqual(output.feature[0].flag_set[0].action, ["c-compile"])
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["foo-flag-1"])
-    self.assertEqual(output.feature[0].flag_set[1].action, ["c++-compile"])
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[0].flag,
-                     ["bar-flag-1"])
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[1].flag,
-                     ["unfiltered-flag-1"])
-    self.assertEqual(output.feature[0].flag_set[1].flag_group[2].flag,
-                     ["bar-flag-2"])
-    self.assertEqual(output.feature[0].flag_set[2].action, ["c-compile"])
-    self.assertEqual(output.feature[0].flag_set[2].flag_group[0].flag,
-                     ["foo-flag-2"])
-
-  def test_unfiltered_compile_flags_is_added_at_the_end(self):
-    crosstool = make_crosstool("""
-            feature { name: 'something_else' }
-            unfiltered_cxx_flag: 'unfiltered-flag-1'
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(output.feature[1].name, "user_compile_flags")
-    self.assertEqual(output.feature[2].name, "sysroot")
-    self.assertEqual(output.feature[3].name, "unfiltered_compile_flags")
-    self.assertEqual(output.feature[3].flag_set[0].action,
-                     ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[3].flag_set[0].flag_group[0].flag,
-                     ["unfiltered-flag-1"])
-
-  def test_unfiltered_compile_flags_are_not_added_for_objc(self):
-    crosstool = make_crosstool("""
-        action_config { action_name: "obc-compile" }
-        feature { name: 'something_else' }
-        unfiltered_cxx_flag: 'unfiltered-flag-1'
-    """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[3].name, "unfiltered_compile_flags")
-    self.assertEqual(output.feature[3].flag_set[0].action,
-                     ALL_CC_COMPILE_ACTIONS)
-    self.assertEqual(output.feature[3].flag_set[0].flag_group[0].flag,
-                     ["unfiltered-flag-1"])
-
-  def test_default_link_flags_is_added_first(self):
-    crosstool = make_crosstool("""
-          linker_flag: 'linker-flag-1'
-          feature { name: 'something_else' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_link_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["linker-flag-1"])
-
-  def test_default_link_flags_is_not_added_when_already_present(self):
-    crosstool = make_crosstool("""
-            linker_flag: 'linker-flag-1'
-            feature { name: 'something_else' }
-            feature { name: 'default_link_flags' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(output.feature[1].name, "default_link_flags")
-
-  def test_default_compile_flags_is_not_added_when_no_reason_to(self):
-    crosstool = make_crosstool("""
-          feature { name: 'something_else' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(len(output.feature), 1)
-
-  def test_default_compile_flags_is_first(self):
-    crosstool = make_crosstool("""
-          compiler_flag: 'compiler-flag-1'
-          feature { name: 'something_else' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "default_compile_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag,
-                     ["compiler-flag-1"])
-
-  def test_default_compile_flags_not_added_when_present(self):
-    crosstool = make_crosstool("""
-          compiler_flag: 'compiler-flag-1'
-          feature { name: 'something_else' }
-          feature { name: 'default_compile_flags' }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(output.feature[1].name, "default_compile_flags")
-    self.assertEqual(len(output.feature[1].flag_set), 0)
-
-  def test_supports_start_end_lib_migrated(self):
-    crosstool = make_crosstool("supports_start_end_lib: true")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_start_end_lib")
-    self.assertEqual(output.feature[0].enabled, True)
-
-  def test_supports_start_end_lib_not_migrated_on_false(self):
-    crosstool = make_crosstool("supports_start_end_lib: false")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.feature), 0)
-
-  def test_supports_start_end_lib_not_migrated_when_already_present(self):
-    crosstool = make_crosstool("""
-            supports_start_end_lib: true
-            feature { name: "supports_start_end_lib" enabled: false }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_start_end_lib")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_supports_interface_shared_libraries_migrated(self):
-    crosstool = make_crosstool("supports_interface_shared_objects: true")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name,
-                     "supports_interface_shared_libraries")
-    self.assertEqual(output.feature[0].enabled, True)
-
-  def test_supports_interface_shared_libraries_not_migrated_on_false(self):
-    crosstool = make_crosstool("supports_interface_shared_objects: false")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.feature), 0)
-
-  def test_supports_interface_shared_libraries_not_migrated_when_present(self):
-    crosstool = make_crosstool("""
-            supports_interface_shared_objects: true
-            feature {
-              name: "supports_interface_shared_libraries"
-              enabled: false }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name,
-                     "supports_interface_shared_libraries")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_supports_embedded_runtimes_migrated(self):
-    crosstool = make_crosstool("supports_embedded_runtimes: true")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "static_link_cpp_runtimes")
-    self.assertEqual(output.feature[0].enabled, True)
-
-  def test_supports_embedded_runtimes_not_migrated_on_false(self):
-    crosstool = make_crosstool("supports_embedded_runtimes: false")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.feature), 0)
-
-  def test_supports_embedded_runtimes_not_migrated_when_already_present(self):
-    crosstool = make_crosstool("""
-            supports_embedded_runtimes: true
-            feature { name: "static_link_cpp_runtimes" enabled: false }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "static_link_cpp_runtimes")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_needs_pic_migrated(self):
-    crosstool = make_crosstool("needsPic: true")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_pic")
-    self.assertEqual(output.feature[0].enabled, True)
-
-  def test_needs_pic_not_migrated_on_false(self):
-    crosstool = make_crosstool("needsPic: false")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.feature), 0)
-
-  def test_needs_pic_not_migrated_when_already_present(self):
-    crosstool = make_crosstool("""
-            needsPic: true
-            feature { name: "supports_pic" enabled: false }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "supports_pic")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_supports_fission_migrated(self):
-    crosstool = make_crosstool("supports_fission: true")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "per_object_debug_info")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].expand_if_all_available,
-        ["is_using_fission"])
-
-  def test_supports_fission_not_migrated_on_false(self):
-    crosstool = make_crosstool("supports_fission: false")
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(len(output.feature), 0)
-
-  def test_supports_fission_not_migrated_when_already_present(self):
-    crosstool = make_crosstool("""
-            supports_fission: true
-            feature { name: "per_object_debug_info" enabled: false }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "per_object_debug_info")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_migrating_objcopy_embed_flag(self):
-    crosstool = make_crosstool("""
-            tool_path { name: "objcopy" path: "foo/objcopy" }
-            objcopy_embed_flag: "a"
-            objcopy_embed_flag: "b"
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "objcopy_embed_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].action[:],
-                     ["objcopy_embed_data"])
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag[:],
-                     ["a", "b"])
-    self.assertEqual(len(output.objcopy_embed_flag), 0)
-    self.assertEqual(output.action_config[0].action_name, "objcopy_embed_data")
-    self.assertEqual(output.action_config[0].tool[0].tool_path, "foo/objcopy")
-
-  def test_not_migrating_objcopy_embed_flag_when_feature_present(self):
-    crosstool = make_crosstool("""
-            objcopy_embed_flag: "a"
-            objcopy_embed_flag: "b"
-            feature { name: "objcopy_embed_flags" }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "objcopy_embed_flags")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_migrating_ld_embed_flag(self):
-    crosstool = make_crosstool("""
-            tool_path { name: "ld" path: "foo/ld" }
-            ld_embed_flag: "a"
-            ld_embed_flag: "b"
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "ld_embed_flags")
-    self.assertEqual(output.feature[0].enabled, True)
-    self.assertEqual(output.feature[0].flag_set[0].action[:], ["ld_embed_data"])
-    self.assertEqual(output.feature[0].flag_set[0].flag_group[0].flag[:],
-                     ["a", "b"])
-    self.assertEqual(len(output.ld_embed_flag), 0)
-    self.assertEqual(output.action_config[0].action_name, "ld_embed_data")
-    self.assertEqual(output.action_config[0].tool[0].tool_path, "foo/ld")
-
-  def test_not_migrating_objcopy_embed_flag_when_feature_present(self):
-    crosstool = make_crosstool("""
-            objcopy_embed_flag: "a"
-            objcopy_embed_flag: "b"
-            feature { name: "objcopy_embed_flags" }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.feature[0].name, "objcopy_embed_flags")
-    self.assertEqual(output.feature[0].enabled, False)
-
-  def test_migrate_expand_if_all_available_from_flag_sets(self):
-    crosstool = make_crosstool("""
-        action_config {
-          action_name: 'something'
-          config_name: 'something'
-          flag_set {
-            expand_if_all_available: 'foo'
-            flag_group {
-              flag: '%{foo}'
-            }
-            flag_group {
-              flag: 'bar'
-            }
-          }
-        }
-        feature {
-          name: 'something_else'
-          flag_set {
-            action: 'c-compile'
-            expand_if_all_available: 'foo'
-            flag_group {
-              flag: '%{foo}'
-            }
-            flag_group {
-              flag: 'bar'
-            }
-          }
-        }
-        """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.action_config[0].action_name, "something")
-    self.assertEqual(len(output.action_config[0].flag_set), 1)
-    self.assertEqual(
-        len(output.action_config[0].flag_set[0].expand_if_all_available), 0)
-    self.assertEqual(len(output.action_config[0].flag_set[0].flag_group), 2)
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[0]
-        .expand_if_all_available, ["foo"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[1]
-        .expand_if_all_available, ["foo"])
-
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(len(output.feature[0].flag_set), 1)
-    self.assertEqual(
-        len(output.feature[0].flag_set[0].expand_if_all_available), 0)
-    self.assertEqual(len(output.feature[0].flag_set[0].flag_group), 2)
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].expand_if_all_available,
-        ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].expand_if_all_available,
-        ["foo"])
-
-  def test_enable_previously_default_features(self):
-    default_features = [
-        "dependency_file", "random_seed", "module_maps", "module_map_home_cwd",
-        "header_module_compile", "include_paths", "pic", "preprocessor_define"
-    ]
-    crosstool = make_crosstool("""
-          feature { name: "dependency_file" }
-          feature { name: "random_seed" }
-          feature { name: "module_maps" }
-          feature { name: "module_map_home_cwd" }
-          feature { name: "header_module_compile" }
-          feature { name: "include_paths" }
-          feature { name: "pic" }
-          feature { name: "preprocessor_define" }
-          """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    for i in range(0, 8):
-      self.assertEqual(output.feature[i].name, default_features[i])
-      self.assertTrue(output.feature[i].enabled)
-
-  def test_migrate_repeated_expand_if_all_available_from_flag_groups(self):
-    crosstool = make_crosstool("""
-          action_config {
-            action_name: 'something'
-            config_name: 'something'
-            flag_set {
-              flag_group {
-                expand_if_all_available: 'foo'
-                expand_if_all_available: 'bar'
-                flag: '%{foo}'
-              }
-              flag_group {
-                expand_if_none_available: 'foo'
-                expand_if_none_available: 'bar'
-                flag: 'bar'
-              }
-            }
-          }
-          feature {
-            name: 'something_else'
-            flag_set {
-              action: 'c-compile'
-              flag_group {
-                expand_if_all_available: 'foo'
-                expand_if_all_available: 'bar'
-                flag: '%{foo}'
-              }
-              flag_group {
-                expand_if_none_available: 'foo'
-                expand_if_none_available: 'bar'
-                flag: 'bar'
-              }
-            }
-          }
-          """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-    self.assertEqual(output.action_config[0].action_name, "something")
-    self.assertEqual(len(output.action_config[0].flag_set), 1)
-    self.assertEqual(
-        len(output.action_config[0].flag_set[0].expand_if_all_available), 0)
-    self.assertEqual(len(output.action_config[0].flag_set[0].flag_group), 2)
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[0]
-        .expand_if_all_available, ["foo"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[0].flag_group[0]
-        .expand_if_all_available, ["bar"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[1]
-        .expand_if_none_available, ["foo"])
-    self.assertEqual(
-        output.action_config[0].flag_set[0].flag_group[1].flag_group[0]
-        .expand_if_none_available, ["bar"])
-
-    self.assertEqual(output.feature[0].name, "something_else")
-    self.assertEqual(len(output.feature[0].flag_set), 1)
-    self.assertEqual(
-        len(output.feature[0].flag_set[0].expand_if_all_available), 0)
-    self.assertEqual(len(output.feature[0].flag_set[0].flag_group), 2)
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].expand_if_all_available,
-        ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].flag_group[0]
-        .expand_if_all_available, ["bar"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].expand_if_none_available,
-        ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0]
-        .expand_if_none_available, ["bar"])
-
-  def test_migrate_repeated_expands_from_nested_flag_groups(self):
-    crosstool = make_crosstool("""
-          feature {
-            name: 'something'
-            flag_set {
-              action: 'c-compile'
-              flag_group {
-                flag_group {
-                  expand_if_all_available: 'foo'
-                  expand_if_all_available: 'bar'
-                  flag: '%{foo}'
-                }
-              }
-              flag_group {
-                flag_group {
-                  expand_if_all_available: 'foo'
-                  expand_if_all_available: 'bar'
-                  expand_if_none_available: 'foo'
-                  expand_if_none_available: 'bar'
-                  flag: '%{foo}'
-                }
-              }
-            }
-          }
-          """)
-    migrate_legacy_fields(crosstool)
-    output = crosstool.toolchain[0]
-
-    self.assertEqual(output.feature[0].name, "something")
-    self.assertEqual(len(output.feature[0].flag_set[0].flag_group), 2)
-    self.assertEqual(
-        len(output.feature[0].flag_set[0].flag_group[0].expand_if_all_available
-           ), 0)
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].flag_group[0]
-        .expand_if_all_available, ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].flag_group[0].flag_group[0]
-        .expand_if_all_available, ["bar"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[0].flag_group[0].flag_group[0]
-        .flag, ["%{foo}"])
-
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0]
-        .expand_if_all_available, ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0]
-        .expand_if_none_available, ["foo"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0].flag_group[0]
-        .expand_if_none_available, ["bar"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0].flag_group[0]
-        .expand_if_all_available, ["bar"])
-    self.assertEqual(
-        output.feature[0].flag_set[0].flag_group[1].flag_group[0].flag_group[0]
-        .flag, ["%{foo}"])
-
-
-if __name__ == "__main__":
-  unittest.main()
diff --git a/tools/migration/legacy_fields_migrator.py b/tools/migration/legacy_fields_migrator.py
deleted file mode 100644
index cc1bb41..0000000
--- a/tools/migration/legacy_fields_migrator.py
+++ /dev/null
@@ -1,69 +0,0 @@
-"""Script migrating legacy CROSSTOOL fields into features.
-
-This script migrates the CROSSTOOL to use only the features to describe C++
-command lines. It is intended to be added as a last step of CROSSTOOL generation
-pipeline. Since it doesn't retain comments, we assume CROSSTOOL owners will want
-to migrate their pipeline manually.
-"""
-
-# Tracking issue: https://github.com/bazelbuild/bazel/issues/5187
-#
-# Since C++ rules team is working on migrating CROSSTOOL from text proto into
-# Starlark, we advise CROSSTOOL owners to wait for the CROSSTOOL -> Starlark
-# migrator before they invest too much time into fixing their pipeline. Tracking
-# issue for the Starlark effort is
-# https://github.com/bazelbuild/bazel/issues/5380.
-
-from absl import app
-from absl import flags
-from google.protobuf import text_format
-from third_party.com.github.bazelbuild.bazel.src.main.protobuf import crosstool_config_pb2
-from tools.migration.legacy_fields_migration_lib import migrate_legacy_fields
-import os
-
-flags.DEFINE_string("input", None, "Input CROSSTOOL file to be migrated")
-flags.DEFINE_string("output", None,
-                    "Output path where to write migrated CROSSTOOL.")
-flags.DEFINE_boolean("inline", None, "Overwrite --input file")
-
-
-def main(unused_argv):
-  crosstool = crosstool_config_pb2.CrosstoolRelease()
-
-  input_filename = flags.FLAGS.input
-  output_filename = flags.FLAGS.output
-  inline = flags.FLAGS.inline
-
-  if not input_filename:
-    raise app.UsageError("ERROR --input unspecified")
-  if not output_filename and not inline:
-    raise app.UsageError("ERROR --output unspecified and --inline not passed")
-  if output_filename and inline:
-    raise app.UsageError("ERROR both --output and --inline passed")
-
-  with open(to_absolute_path(input_filename), "r") as f:
-    input_text = f.read()
-
-  text_format.Merge(input_text, crosstool)
-
-  migrate_legacy_fields(crosstool)
-  output_text = text_format.MessageToString(crosstool)
-
-  resolved_output_filename = to_absolute_path(
-      input_filename if inline else output_filename)
-  with open(resolved_output_filename, "w") as f:
-    f.write(output_text)
-
-def to_absolute_path(path):
-  path = os.path.expanduser(path)
-  if os.path.isabs(path):
-    return path
-  else:
-    if "BUILD_WORKING_DIRECTORY" in os.environ:
-      return os.path.join(os.environ["BUILD_WORKING_DIRECTORY"], path)
-    else:
-      return path
-
-
-if __name__ == "__main__":
-  app.run(main)
```

