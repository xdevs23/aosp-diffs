```diff
diff --git a/.bazel_checkout/__README b/.bazel_checkout/__README
new file mode 100644
index 0000000..6de50f3
--- /dev/null
+++ b/.bazel_checkout/__README
@@ -0,0 +1,4 @@
+This directory exists just so we can clone Bazel sources and run tests on presubmit
+
+At some point, we should migrate the tests we care about, out of Bazel and into
+rules_java.
\ No newline at end of file
diff --git a/.bazel_checkout/setup.sh b/.bazel_checkout/setup.sh
new file mode 100644
index 0000000..f1981a6
--- /dev/null
+++ b/.bazel_checkout/setup.sh
@@ -0,0 +1,51 @@
+#!/usr/bin/env bash
+set -e
+set -x
+
+FAKE_BCR_ROOT=$(mktemp -d --tmpdir fake-bcr.XXX)
+FAKE_RULES_JAVA_ROOT=${FAKE_BCR_ROOT}/modules/rules_java
+FAKE_MODULE_VERSION=9999
+FAKE_MODULE_ROOT=${FAKE_RULES_JAVA_ROOT}/${FAKE_MODULE_VERSION}
+FAKE_ARCHIVE=${FAKE_MODULE_ROOT}/rules_java.tar.gz
+mkdir -p ${FAKE_MODULE_ROOT}
+
+# relying on the line number is not great, but :shrugs:
+sed -e "3 c version = \"${FAKE_MODULE_VERSION}\"," ../MODULE.bazel > ${FAKE_MODULE_ROOT}/MODULE.bazel
+
+tar zcf ${FAKE_ARCHIVE} ../
+RULES_JAVA_INTEGRITY_SHA256=`cat ${FAKE_ARCHIVE} | openssl dgst -sha256 -binary | base64`
+cat << EOF > ${FAKE_MODULE_ROOT}/source.json
+{
+    "integrity": "sha256-${RULES_JAVA_INTEGRITY_SHA256}",
+    "strip_prefix": "",
+    "url": "file://${FAKE_ARCHIVE}"
+}
+EOF
+
+# fetch and setup bazel sources
+git init
+git remote add origin https://github.com/bazelbuild/bazel.git
+git pull origin master
+sed -i.bak -e 's/^# android_sdk_repository/android_sdk_repository/' \
+  -e 's/^#  android_ndk_repository/android_ndk_repository/' \
+  WORKSPACE.bzlmod
+rm -f WORKSPACE.bzlmod.bak
+rm -rf $HOME/bazeltest
+mkdir $HOME/bazeltest
+
+echo "common --registry=https://bcr.bazel.build" >> .bazelrc
+echo "common --registry=file://${FAKE_BCR_ROOT}" >> .bazelrc
+echo "add_to_bazelrc \"common --registry=https://bcr.bazel.build\"" >> src/test/shell/testenv.sh.tmpl
+echo "add_to_bazelrc \"common --registry=file://${FAKE_BCR_ROOT}\"" >> src/test/shell/testenv.sh.tmpl
+
+SED_CMD="s/bazel_dep(name = \"rules_java\".*/bazel_dep(name = \"rules_java\", version = \"${FAKE_MODULE_VERSION}\")/"
+sed -i "${SED_CMD}" MODULE.bazel
+sed -i "${SED_CMD}" src/MODULE.tools
+
+BAZEL_QUIET_MODE_ARGS="--ui_event_filters=error,fail"
+
+bazel run ${BAZEL_QUIET_MODE_ARGS} //src/test/tools/bzlmod:update_default_lock_file -- \
+  --registry="https://bcr.bazel.build" --registry="file://${FAKE_BCR_ROOT}" ${BAZEL_QUIET_MODE_ARGS}
+bazel mod deps --lockfile_mode=update
+# populate repo cache so tests don't need to access network
+bazel fetch --config=ci-linux --all ${BAZEL_QUIET_MODE_ARGS}
diff --git a/.bazelci/presubmit.yml b/.bazelci/presubmit.yml
index cd90651..f66eb71 100644
--- a/.bazelci/presubmit.yml
+++ b/.bazelci/presubmit.yml
@@ -13,9 +13,8 @@ build_targets_bzlmod: &build_targets_bzlmod
   # Enable once the issue is fixed.
   - "-//distro/..."
 
-buildifier:
-  version: latest
-  warnings: "all"
+buildifier: latest
+
 tasks:
   ubuntu2004:
     build_targets: *build_targets
@@ -36,20 +35,17 @@ tasks:
     platform: windows
     build_targets: *build_targets
   ubuntu2004_bzlmod:
-    bazel: last_green
     platform: ubuntu2004
     build_flags:
       - "--config=bzlmod"
     build_targets: *build_targets_bzlmod
   macos_bzlmod:
-    bazel: last_green
     platform: macos
     build_flags:
       - "--config=bzlmod"
     build_targets: *build_targets_bzlmod
   windows_bzlmod:
-    bazel: last_green
     platform: windows
     build_flags:
       - "--config=bzlmod"
-    build_targets: *build_targets_bzlmod
+    build_targets: *build_targets_bzlmod
\ No newline at end of file
diff --git a/.bazelrc b/.bazelrc
index 4fadfce..5d84eb8 100644
--- a/.bazelrc
+++ b/.bazelrc
@@ -1 +1,3 @@
 build:bzlmod --experimental_enable_bzlmod
+
+common --incompatible_disallow_empty_glob
\ No newline at end of file
diff --git a/.bazelversion b/.bazelversion
new file mode 100644
index 0000000..66ce77b
--- /dev/null
+++ b/.bazelversion
@@ -0,0 +1 @@
+7.0.0
diff --git a/.bcr/metadata.template.json b/.bcr/metadata.template.json
index 41ba4c2..9d09144 100644
--- a/.bcr/metadata.template.json
+++ b/.bcr/metadata.template.json
@@ -1,6 +1,12 @@
 {
   "homepage": "https://github.com/bazelbuild/rules_java",
-  "maintainers": [],
+  "maintainers": [
+    {
+      "email": "hvd@google.com",
+      "github": "hvadehra",
+      "name": "Hemanshu Vadehra"
+    }
+  ],
   "versions": [],
   "yanked_versions": {},
   "repository": [
diff --git a/.bcr/presubmit.yml b/.bcr/presubmit.yml
index 52f713e..a994334 100644
--- a/.bcr/presubmit.yml
+++ b/.bcr/presubmit.yml
@@ -1,8 +1,16 @@
 matrix:
-  platform: ["centos7", "debian10", "macos", "ubuntu2004", "windows"]
+  platform:
+  - centos7
+  - debian10
+  - macos
+  - ubuntu2004
+  - windows
+  bazel:
+  - 7.x
 tasks:
   verify_build_targets:
     name: "Verify build targets"
     platform: ${{ platform }}
+    bazel: ${{ bazel }}
     build_targets:
-      - "@rules_java//java/..."
+    - "@rules_java//java/..."
diff --git a/.github/ISSUE_TEMPLATE/release.md b/.github/ISSUE_TEMPLATE/release.md
new file mode 100644
index 0000000..088ed07
--- /dev/null
+++ b/.github/ISSUE_TEMPLATE/release.md
@@ -0,0 +1,18 @@
+---
+name: 'Release tracker'
+about: Use this template to request for a new rules_java release
+title: 'Release: rules_java X.Y.Z'
+labels: ['release','P1']
+assignees:
+  - iancha1992
+  - sgowroji
+---
+
+**Link to relevant issue and/or commit:**
+
+**Other details:**
+<!-- Does this need to be updated in Bazel? -->
+<!-- Does this need to be cherry-picked into a Bazel release? -->
+<!-- Any constraints to note? -->
+
+cc @bazelbuild/triage
diff --git a/BUILD b/BUILD
index 9840747..c138b7f 100644
--- a/BUILD
+++ b/BUILD
@@ -12,8 +12,9 @@ filegroup(
         "BUILD",
         "LICENSE",
         "MODULE.bazel",
+        "WORKSPACE",
         "//java:srcs",
         "//toolchains:srcs",
     ],
-    visibility = ["//distro:__pkg__"],
+    visibility = ["//visibility:public"],
 )
diff --git a/METADATA b/METADATA
index 7414aa4..e54ab2a 100644
--- a/METADATA
+++ b/METADATA
@@ -1,13 +1,19 @@
-name: "rules_java"
-description:
-    "Bazel rules for building java code"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/bazelbuild-rules_java
+# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
 
+name: "rules_java"
+description: "Bazel rules for building java code"
 third_party {
-  url {
-    type: GIT
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 6
+    day: 5
+  }
+  identifier {
+    type: "Git"
     value: "https://github.com/bazelbuild/rules_java"
+    version: "7.6.1"
   }
-  version: "6.1.1"
-  last_upgrade_date { year: 2023 month: 6 day: 23 }
-  license_type: NOTICE
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index ebf3c8c..1be58b8 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,12 +1,15 @@
 module(
     name = "rules_java",
-    version = "6.1.1",
+    version = "7.6.1",
+    # Requires @bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type.
+    bazel_compatibility = [">=7.0.0"],
     compatibility_level = 1,
 )
 
 bazel_dep(name = "platforms", version = "0.0.4")
 bazel_dep(name = "rules_cc", version = "0.0.2")
-bazel_dep(name = "bazel_skylib", version = "1.2.0")
+bazel_dep(name = "bazel_features", version = "1.11.0")
+bazel_dep(name = "bazel_skylib", version = "1.6.1")
 
 # Required by @remote_java_tools, which is loaded via module extension.
 bazel_dep(name = "rules_proto", version = "4.0.0")
@@ -26,10 +29,22 @@ use_repo(toolchains, "remote_java_tools_darwin_arm64")
 # Declare local jdk repo
 use_repo(toolchains, "local_jdk")
 
-register_toolchains("@local_jdk//:runtime_toolchain_definition")
+register_toolchains(
+    "@local_jdk//:runtime_toolchain_definition",
+    "@local_jdk//:bootstrap_runtime_toolchain_definition",
+)
 
 # Declare all remote jdk toolchain config repos
 JDKS = {
+    # Must match JDK repos defined in remote_jdk8_repos()
+    "8": [
+        "linux",
+        "linux_aarch64",
+        "linux_s390x",
+        "macos",
+        "macos_aarch64",
+        "windows",
+    ],
     # Must match JDK repos defined in remote_jdk11_repos()
     "11": [
         "linux",
@@ -52,24 +67,33 @@ JDKS = {
         "win",
         "win_arm64",
     ],
-    # Must match JDK repos defined in remote_jdk20_repos()
-    "20": [
+    # Must match JDK repos defined in remote_jdk21_repos()
+    "21": [
         "linux",
         "linux_aarch64",
+        "linux_ppc64le",
+        "linux_s390x",
         "macos",
         "macos_aarch64",
         "win",
+        "win_arm64",
     ],
 }
 
-REMOTE_JDK_REPOS = [("remotejdk" + version + "_" + platform) for version in JDKS for platform in JDKS[version]]
+REMOTE_JDK_REPOS = [(("remote_jdk" if version == "8" else "remotejdk") + version + "_" + platform) for version in JDKS for platform in JDKS[version]]
 
 [use_repo(
     toolchains,
     repo + "_toolchain_config_repo",
 ) for repo in REMOTE_JDK_REPOS]
 
-[register_toolchains("@" + name + "_toolchain_config_repo//:toolchain") for name in REMOTE_JDK_REPOS]
+[register_toolchains("@" + name + "_toolchain_config_repo//:all") for name in REMOTE_JDK_REPOS]
 
 # Dev dependencies
-bazel_dep(name = "rules_pkg", version = "0.5.1", dev_dependency = True)
+bazel_dep(name = "rules_pkg", version = "0.9.1", dev_dependency = True)
+
+# Override rules_python version to deal with #161 and https://github.com/bazelbuild/bazel/issues/20458
+single_version_override(
+    module_name = "rules_python",
+    version = "0.24.0",
+)
diff --git a/OWNERS b/OWNERS
index f0f1277..d856ca7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 include platform/build/bazel:/OWNERS
-jobredeaux@google.com
-agespino@google.com
+include kernel/build:/OWNERS
diff --git a/WORKSPACE b/WORKSPACE
index 059716f..6e4b3c0 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -4,10 +4,10 @@ load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 
 http_archive(
     name = "bazel_skylib",
-    sha256 = "af87959afe497dc8dfd4c6cb66e1279cb98ccc84284619ebfec27d9c09a903de",
+    sha256 = "9f38886a40548c6e96c106b752f242130ee11aaa068a56ba7e56f4511f33e4f2",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.0/bazel-skylib-1.2.0.tar.gz",
-        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.0/bazel-skylib-1.2.0.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.6.1/bazel-skylib-1.6.1.tar.gz",
+        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.6.1/bazel-skylib-1.6.1.tar.gz",
     ],
 )
 
@@ -17,10 +17,10 @@ bazel_skylib_workspace()
 
 http_archive(
     name = "rules_pkg",
-    sha256 = "a89e203d3cf264e564fcb96b6e06dd70bc0557356eb48400ce4b5d97c2c3720d",
+    sha256 = "8f9ee2dc10c1ae514ee599a8b42ed99fa262b757058f65ad3c384289ff70c4b8",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.5.1/rules_pkg-0.5.1.tar.gz",
-        "https://github.com/bazelbuild/rules_pkg/releases/download/0.5.1/rules_pkg-0.5.1.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
+        "https://github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
     ],
 )
 
diff --git a/distro/BUILD.bazel b/distro/BUILD.bazel
index d136ca1..0fa843f 100644
--- a/distro/BUILD.bazel
+++ b/distro/BUILD.bazel
@@ -1,14 +1,11 @@
-load("@rules_pkg//:pkg.bzl", "pkg_tar")
-load("@rules_pkg//releasing:defs.bzl", "print_rel_notes")
-load("//java:defs.bzl", "version")
+load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
+load("@rules_pkg//pkg/releasing:defs.bzl", "print_rel_notes")
 
-package(
-    default_visibility = ["//visibility:private"],
-)
+package(default_visibility = ["//visibility:private"])
 
 # Build the artifact to put on the github release page.
 pkg_tar(
-    name = "rules_java-%s" % version,
+    name = "rules_java-%s" % module_version(),
     srcs = ["//:distribution"],
     extension = "tar.gz",
     # It is all source code, so make it read-only.
@@ -26,5 +23,5 @@ print_rel_notes(
     repo = "rules_java",
     setup_file = "java:repositories.bzl",
     toolchains_method = "rules_java_toolchains",
-    version = version,
+    version = module_version(),
 )
diff --git a/distro/README.md b/distro/README.md
index eb57af3..7cac892 100644
--- a/distro/README.md
+++ b/distro/README.md
@@ -1,9 +1,21 @@
 # Releasing rules_java
 
-1. Update version in [java/defs.bzl](/java/defs.bzl),
-   [MODULE.bazel](/MODULE.bazel) and merge it
+1. Update version in [MODULE.bazel](/MODULE.bazel) and merge it
 2. Build the release running `bazel build //distro:rules_java-{version}`
 3. Prepare release notes running `bazel build //distro:relnotes`
 4. Create a new release on GitHub
 5. Copy/paste the produced `relnotes.txt` into the notes. Adjust as needed.
 6. Upload the produced tar.gz file as an artifact.
+
+------
+
+**Note:** Steps 2-6 have been automated. Trigger a new build of the [rules_java release pipeline](https://buildkite.com/bazel-trusted/rules-java-release/). Set the message to "rules_java [version]" (or anything else), and leave the commit and branch fields as is.
+
+A new release will be created [here](https://github.com/bazelbuild/rules_java/releases) -- edit the description as needed. A PR will be submitted against the [bazel-central-registry](https://github.com/bazelbuild/bazel-central-registry) repo.
+
+rules_java 6.5.0 example:
+
+- Build: https://buildkite.com/bazel-trusted/rules-java-release/builds/1
+- Release: https://github.com/bazelbuild/rules_java/releases/tag/6.5.0
+- BCR PR: bazelbuild/bazel-central-registry#818
+
diff --git a/java/BUILD b/java/BUILD
index 8e07ca3..8b7465e 100644
--- a/java/BUILD
+++ b/java/BUILD
@@ -6,7 +6,12 @@ licenses(["notice"])
 
 filegroup(
     name = "srcs",
-    srcs = glob(["**"]) + ["//java/private:srcs"],
+    srcs = glob(["**"]) + [
+        "//java/common:srcs",
+        "//java/private:srcs",
+        "//java/proto:srcs",
+        "//java/toolchains:srcs",
+    ],
     visibility = ["//:__pkg__"],
 )
 
@@ -14,5 +19,53 @@ bzl_library(
     name = "rules",
     srcs = ["defs.bzl"],
     visibility = ["//visibility:public"],
-    deps = ["//java/private"],
+    deps = [
+        ":core_rules",
+        "//java/common",
+        "//java/toolchains:toolchain_rules",
+    ],
+)
+
+bzl_library(
+    name = "core_rules",
+    srcs = [
+        "java_binary.bzl",
+        "java_import.bzl",
+        "java_library.bzl",
+        "java_plugin.bzl",
+        "java_single_jar.bzl",
+        "java_test.bzl",
+    ],
+    visibility = ["//visibility:public"],
+    deps = [
+        "//java/common",
+        "//java/private",
+    ],
+)
+
+bzl_library(
+    name = "utils",
+    srcs = ["java_utils.bzl"],
+    visibility = ["//visibility:public"],
+)
+
+bzl_library(
+    name = "java_single_jar",
+    srcs = ["java_single_jar.bzl"],
+    visibility = ["//visibility:public"],
+    deps = ["//java/common"],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD",
+        ":core_rules",
+        ":java_single_jar",
+        ":rules",
+        "//java/common:for_bazel_tests",
+        "//java/private:for_bazel_tests",
+    ],
+    visibility = ["//visibility:public"],
 )
diff --git a/java/common/BUILD b/java/common/BUILD
new file mode 100644
index 0000000..e9d0165
--- /dev/null
+++ b/java/common/BUILD
@@ -0,0 +1,28 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+package(default_visibility = ["//visibility:public"])
+
+licenses(["notice"])
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
+
+bzl_library(
+    name = "common",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//visibility:public"],
+    deps = ["//java/private"],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD",
+        ":common",
+    ],
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/common/java_common.bzl b/java/common/java_common.bzl
new file mode 100644
index 0000000..201beba
--- /dev/null
+++ b/java/common/java_common.bzl
@@ -0,0 +1,18 @@
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
+"""java_common module"""
+
+load("//java/private:native.bzl", "native_java_common")
+
+java_common = native_java_common
diff --git a/java/common/java_info.bzl b/java/common/java_info.bzl
new file mode 100644
index 0000000..e22fb3d
--- /dev/null
+++ b/java/common/java_info.bzl
@@ -0,0 +1,18 @@
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
+"""JavaInfo provider"""
+
+load("//java/private:native.bzl", "NativeJavaInfo")
+
+JavaInfo = NativeJavaInfo
diff --git a/java/common/java_plugin_info.bzl b/java/common/java_plugin_info.bzl
new file mode 100644
index 0000000..36d84f9
--- /dev/null
+++ b/java/common/java_plugin_info.bzl
@@ -0,0 +1,18 @@
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
+"""JavaPluginInfo provider"""
+
+load("//java/private:native.bzl", "NativeJavaPluginInfo")
+
+JavaPluginInfo = NativeJavaPluginInfo
diff --git a/java/defs.bzl b/java/defs.bzl
index bbfc55f..64de71a 100644
--- a/java/defs.bzl
+++ b/java/defs.bzl
@@ -13,142 +13,39 @@
 # limitations under the License.
 """Starlark rules for building Java projects."""
 
-load("//java/private:native.bzl", "NativeJavaInfo", "NativeJavaPluginInfo", "native_java_common")
-
-# Do not touch: This line marks the end of loads; needed for PR importing.
-
-_MIGRATION_TAG = "__JAVA_RULES_MIGRATION_DO_NOT_USE_WILL_BREAK__"
-version = "6.1.1"
-
-def _add_tags(attrs):
-    if "tags" in attrs and attrs["tags"] != None:
-        attrs["tags"] = attrs["tags"] + [_MIGRATION_TAG]
-    else:
-        attrs["tags"] = [_MIGRATION_TAG]
-    return attrs
-
-def java_binary(**attrs):
-    """Bazel java_binary rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_binary
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_binary(**_add_tags(attrs))
-
-def java_import(**attrs):
-    """Bazel java_import rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_import
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_import(**_add_tags(attrs))
-
-def java_library(**attrs):
-    """Bazel java_library rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_library(**_add_tags(attrs))
-
-def java_lite_proto_library(**attrs):
-    """Bazel java_lite_proto_library rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_lite_proto_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_lite_proto_library(**_add_tags(attrs))
-
-def java_proto_library(**attrs):
-    """Bazel java_proto_library rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_proto_library
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_proto_library(**_add_tags(attrs))
-
-def java_test(**attrs):
-    """Bazel java_test rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_test
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_test(**_add_tags(attrs))
-
-def java_package_configuration(**attrs):
-    """Bazel java_package_configuration rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_package_configuration
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_package_configuration(**_add_tags(attrs))
-
-def java_plugin(**attrs):
-    """Bazel java_plugin rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_plugin
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_plugin(**_add_tags(attrs))
-
-def java_runtime(**attrs):
-    """Bazel java_runtime rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_runtime
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_runtime(**_add_tags(attrs))
-
-def java_toolchain(**attrs):
-    """Bazel java_toolchain rule.
-
-    https://docs.bazel.build/versions/master/be/java.html#java_toolchain
-
-    Args:
-      **attrs: Rule attributes
-    """
-
-    # buildifier: disable=native-java
-    native.java_toolchain(**_add_tags(attrs))
-
-java_common = native_java_common
-
-JavaInfo = NativeJavaInfo
-
-JavaPluginInfo = NativeJavaPluginInfo
+load("//java:java_binary.bzl", _java_binary = "java_binary")
+load("//java:java_import.bzl", _java_import = "java_import")
+load("//java:java_library.bzl", _java_library = "java_library")
+load("//java:java_plugin.bzl", _java_plugin = "java_plugin")
+load("//java:java_test.bzl", _java_test = "java_test")
+load("//java/common:java_common.bzl", _java_common = "java_common")
+load("//java/common:java_info.bzl", _JavaInfo = "JavaInfo")
+load("//java/common:java_plugin_info.bzl", _JavaPluginInfo = "JavaPluginInfo")
+load("//java/toolchains:java_package_configuration.bzl", _java_package_configuration = "java_package_configuration")
+load("//java/toolchains:java_runtime.bzl", _java_runtime = "java_runtime")
+load("//java/toolchains:java_toolchain.bzl", _java_toolchain = "java_toolchain")
+
+# Language rules
+
+java_binary = _java_binary
+java_test = _java_test
+java_library = _java_library
+java_plugin = _java_plugin
+java_import = _java_import
+
+# Toolchain rules
+
+java_runtime = _java_runtime
+java_toolchain = _java_toolchain
+java_package_configuration = _java_package_configuration
+
+# Proto rules
+# Deprecated: don't use java proto libraries from here
+java_proto_library = native.java_proto_library
+java_lite_proto_library = native.java_lite_proto_library
+
+# Modules and providers
+
+JavaInfo = _JavaInfo
+JavaPluginInfo = _JavaPluginInfo
+java_common = _java_common
diff --git a/java/extensions.bzl b/java/extensions.bzl
index 5e456ed..f456f3f 100644
--- a/java/extensions.bzl
+++ b/java/extensions.bzl
@@ -13,13 +13,28 @@
 # limitations under the License.
 """Module extensions for rules_java."""
 
-load("//java:repositories.bzl", "java_tools_repos", "local_jdk_repo", "remote_jdk11_repos", "remote_jdk17_repos", "remote_jdk20_repos")
+load("@bazel_features//:features.bzl", "bazel_features")
+load(
+    "//java:repositories.bzl",
+    "java_tools_repos",
+    "local_jdk_repo",
+    "remote_jdk11_repos",
+    "remote_jdk17_repos",
+    "remote_jdk21_repos",
+    "remote_jdk8_repos",
+)
 
-def _toolchains_impl(_ctx):
+def _toolchains_impl(module_ctx):
     java_tools_repos()
     local_jdk_repo()
+    remote_jdk8_repos()
     remote_jdk11_repos()
     remote_jdk17_repos()
-    remote_jdk20_repos()
+    remote_jdk21_repos()
 
-toolchains = module_extension(implementation = _toolchains_impl)
+    if bazel_features.external_deps.extension_metadata_has_reproducible:
+        return module_ctx.extension_metadata(reproducible = True)
+    else:
+        return None
+
+toolchains = module_extension(_toolchains_impl)
diff --git a/java/java_binary.bzl b/java/java_binary.bzl
new file mode 100644
index 0000000..b35064c
--- /dev/null
+++ b/java/java_binary.bzl
@@ -0,0 +1,28 @@
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
+"""java_binary rule"""
+
+# Do not touch: This line marks the end of loads; needed for PR importing.
+
+def java_binary(**attrs):
+    """Bazel java_binary rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_binary
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_binary(**attrs)
diff --git a/java/java_import.bzl b/java/java_import.bzl
new file mode 100644
index 0000000..24a52af
--- /dev/null
+++ b/java/java_import.bzl
@@ -0,0 +1,26 @@
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
+"""java_import rule"""
+
+def java_import(**attrs):
+    """Bazel java_import rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_import
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_import(**attrs)
diff --git a/java/java_library.bzl b/java/java_library.bzl
new file mode 100644
index 0000000..2dff6d6
--- /dev/null
+++ b/java/java_library.bzl
@@ -0,0 +1,28 @@
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
+"""java_library rule"""
+
+# Do not touch: This line marks the end of loads; needed for PR importing.
+
+def java_library(**attrs):
+    """Bazel java_library rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_library
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_library(**attrs)
diff --git a/java/java_plugin.bzl b/java/java_plugin.bzl
new file mode 100644
index 0000000..e26ae04
--- /dev/null
+++ b/java/java_plugin.bzl
@@ -0,0 +1,26 @@
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
+"""java_plugin rule"""
+
+def java_plugin(**attrs):
+    """Bazel java_plugin rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_plugin
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_plugin(**attrs)
diff --git a/java/java_single_jar.bzl b/java/java_single_jar.bzl
new file mode 100644
index 0000000..6e85bde
--- /dev/null
+++ b/java/java_single_jar.bzl
@@ -0,0 +1,143 @@
+""" Definition of _java_single_jar. """
+
+load("//java/common:java_common.bzl", "java_common")
+load("//java/common:java_info.bzl", "JavaInfo")
+
+def _java_single_jar(ctx):
+    transitive_inputs = []
+    for dep in ctx.attr.deps:
+        if JavaInfo in dep:
+            info = dep[JavaInfo]
+            transitive_inputs.append(info.transitive_runtime_jars)
+            if hasattr(info, "compilation_info"):
+                compilation_info = info.compilation_info
+                if hasattr(compilation_info, "runtime_classpath"):
+                    transitive_inputs.append(compilation_info.runtime_classpath)
+        else:
+            files = []
+            for f in dep[DefaultInfo].files.to_list():
+                if not f.extension == "jar":
+                    fail("unexpected file type in java_single_jar.deps: %s" % f.path)
+                files.append(f)
+            transitive_inputs.append(depset(files))
+    inputs = depset(transitive = transitive_inputs)
+
+    if hasattr(java_common, "JavaRuntimeClasspathInfo"):
+        deploy_env_jars = depset(transitive = [
+            dep[java_common.JavaRuntimeClasspathInfo].runtime_classpath
+            for dep in ctx.attr.deploy_env
+        ])
+        excluded_jars = {jar: None for jar in deploy_env_jars.to_list()}
+        if excluded_jars:
+            inputs = depset([jar for jar in inputs.to_list() if jar not in excluded_jars])
+
+    args = ctx.actions.args()
+    args.add_all("--sources", inputs)
+    args.use_param_file("@%s")
+    args.set_param_file_format("multiline")
+    args.add_all("--deploy_manifest_lines", ctx.attr.deploy_manifest_lines)
+    args.add("--output", ctx.outputs.jar)
+    args.add("--normalize")
+
+    # Deal with limitation of singlejar flags: tool's default behavior is
+    # "no", but you get that behavior only by absence of compression flags.
+    if ctx.attr.compress == "preserve":
+        args.add("--dont_change_compression")
+    elif ctx.attr.compress == "yes":
+        args.add("--compression")
+    elif ctx.attr.compress == "no":
+        pass
+    else:
+        fail("\"compress\" attribute (%s) must be: yes, no, preserve." % ctx.attr.compress)
+
+    if ctx.attr.exclude_build_data:
+        args.add("--exclude_build_data")
+    if ctx.attr.multi_release:
+        args.add("--multi_release")
+
+    ctx.actions.run(
+        inputs = inputs,
+        outputs = [ctx.outputs.jar],
+        arguments = [args],
+        progress_message = "Merging into %s" % ctx.outputs.jar.short_path,
+        mnemonic = "JavaSingleJar",
+        executable = ctx.executable._singlejar,
+    )
+
+    files = depset([ctx.outputs.jar])
+    providers = [DefaultInfo(
+        files = files,
+        runfiles = ctx.runfiles(transitive_files = files),
+    )]
+    if hasattr(java_common, "JavaRuntimeClasspathInfo"):
+        providers.append(java_common.JavaRuntimeClasspathInfo(runtime_classpath = inputs))
+    return providers
+
+java_single_jar = rule(
+    attrs = {
+        "deps": attr.label_list(
+            allow_files = True,
+            doc = """
+                The Java targets (including java_import and java_library) to collect
+                transitive dependencies from. Runtime dependencies are collected via
+                deps, exports, and runtime_deps. Resources are also collected.
+                Native cc_library or java_wrap_cc dependencies are not.""",
+        ),
+        "deploy_manifest_lines": attr.string_list(doc = """
+          A list of lines to add to the <code>META-INF/manifest.mf</code> file."""),
+        "deploy_env": attr.label_list(
+            providers = [java_common.JavaRuntimeClasspathInfo] if hasattr(java_common, "JavaRuntimeClasspathInfo") else [],
+            allow_files = False,
+            doc = """
+            A list of `java_binary` or `java_single_jar` targets which represent
+            the deployment environment for this binary.
+
+            Set this attribute when building a plugin which will be loaded by another
+            `java_binary`.
+
+            `deploy_env` dependencies are excluded from the jar built by this rule.""",
+        ),
+        "compress": attr.string(default = "preserve", doc = """
+            Whether to always deflate ("yes"), always store ("no"), or pass
+            through unmodified ("preserve"). The default is "preserve", and is the
+            most efficient option -- no extra work is done to inflate or deflate."""),
+        "exclude_build_data": attr.bool(default = True, doc = """
+            Whether to omit the build-data.properties file generated
+            by default."""),
+        "multi_release": attr.bool(default = True, doc = """Whether to enable Multi-Release output jars."""),
+        "_singlejar": attr.label(
+            default = Label("//toolchains:singlejar"),
+            cfg = "exec",
+            allow_single_file = True,
+            executable = True,
+        ),
+    },
+    outputs = {
+        "jar": "%{name}.jar",
+    },
+    implementation = _java_single_jar,
+    doc = """
+Collects Java dependencies and jar files into a single jar
+
+`java_single_jar` collects Java dependencies and jar files into a single jar.
+This is similar to java_binary with everything related to executables disabled,
+and provides an alternative to the java_binary "deploy jar hack".
+
+## Example
+
+```skylark
+load("//tools/build_defs/java_single_jar:java_single_jar.bzl", "java_single_jar")
+
+java_single_jar(
+    name = "my_single_jar",
+    deps = [
+        "//java/com/google/foo",
+        "//java/com/google/bar",
+    ],
+)
+```
+
+Outputs:
+  {name}.jar: A single jar containing all of the inputs.
+""",
+)
diff --git a/java/java_test.bzl b/java/java_test.bzl
new file mode 100644
index 0000000..7064b5b
--- /dev/null
+++ b/java/java_test.bzl
@@ -0,0 +1,28 @@
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
+"""java_test rule"""
+
+# Do not touch: This line marks the end of loads; needed for PR importing.
+
+def java_test(**attrs):
+    """Bazel java_test rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_test
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_test(**attrs)
diff --git a/java/java_utils.bzl b/java/java_utils.bzl
new file mode 100644
index 0000000..a90a001
--- /dev/null
+++ b/java/java_utils.bzl
@@ -0,0 +1,25 @@
+"""Utility methods for interacting with the java rules"""
+
+def _tokenize_javacopts(ctx, opts):
+    """Tokenizes a list or depset of options to a list.
+
+    Iff opts is a depset, we reverse the flattened list to ensure right-most
+    duplicates are preserved in their correct position.
+
+    Args:
+        ctx: (RuleContext) the rule context
+        opts: (depset[str]|[str]) the javac options to tokenize
+    Returns:
+        [str] list of tokenized options
+    """
+    if hasattr(opts, "to_list"):
+        opts = reversed(opts.to_list())
+    return [
+        token
+        for opt in opts
+        for token in ctx.tokenize(opt)
+    ]
+
+utils = struct(
+    tokenize_javacopts = _tokenize_javacopts,
+)
diff --git a/java/private/BUILD b/java/private/BUILD
index 9f50995..6948199 100644
--- a/java/private/BUILD
+++ b/java/private/BUILD
@@ -4,8 +4,10 @@ licenses(["notice"])
 
 bzl_library(
     name = "private",
-    srcs = ["native.bzl"],
-    visibility = ["//java:__pkg__"],
+    srcs = [
+        "native.bzl",
+    ],
+    visibility = ["//java:__subpackages__"],
 )
 
 filegroup(
@@ -13,3 +15,13 @@ filegroup(
     srcs = glob(["**"]),
     visibility = ["//java:__pkg__"],
 )
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD",
+        ":private",
+    ],
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/proto/BUILD b/java/proto/BUILD
new file mode 100644
index 0000000..209a5f5
--- /dev/null
+++ b/java/proto/BUILD
@@ -0,0 +1,13 @@
+package(default_visibility = ["//visibility:public"])
+
+# Toolchain type provided by proto_lang_toolchain rule and used by java_proto_library
+toolchain_type(name = "toolchain_type")
+
+# Toolchain type provided by proto_lang_toolchain rule and used by java_lite_proto_library
+toolchain_type(name = "lite_toolchain_type")
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/repositories.bzl b/java/repositories.bzl
index eaef6d7..f9c396a 100644
--- a/java/repositories.bzl
+++ b/java/repositories.bzl
@@ -20,57 +20,50 @@ load("//toolchains:jdk_build_file.bzl", "JDK_BUILD_TEMPLATE")
 load("//toolchains:local_java_repository.bzl", "local_java_repository")
 load("//toolchains:remote_java_repository.bzl", "remote_java_repository")
 
+_JAVA_TOOLS_CONFIG = {
+    "version": "v13.6.0",
+    "release": "true",
+    "artifacts": {
+        "java_tools_linux": {
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_linux-v13.6.0.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_linux-v13.6.0.zip",
+            "sha": "0d3fcae7ae40d0a25f17c3adc30a3674f526953c55871189e2efe3463fce3496",
+        },
+        "java_tools_windows": {
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_windows-v13.6.0.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_windows-v13.6.0.zip",
+            "sha": "5a7d00e42c0b35f08eb5c8577eb115f8f57dd36ef8b6940c2190bd0d0e4ddcf0",
+        },
+        "java_tools_darwin_x86_64": {
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_darwin_x86_64-v13.6.0.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_darwin_x86_64-v13.6.0.zip",
+            "sha": "465dcb1da77a0c83c49f178c11bad29b3d703df1756722ec42fe5afd7c8129f8",
+        },
+        "java_tools_darwin_arm64": {
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_darwin_arm64-v13.6.0.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_darwin_arm64-v13.6.0.zip",
+            "sha": "eb54c4e5fa23d6e9e9fc14c106a682dbefc54659d8e389a2f3c0d61d51cae274",
+        },
+        "java_tools": {
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools-v13.6.0.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools-v13.6.0.zip",
+            "sha": "74c978eab040ad4ec38ce0d0970ac813cc2c6f4f6f4f121c0414719487edc991",
+        },
+    },
+}
+
 def java_tools_repos():
     """ Declares the remote java_tools repositories """
-    maybe(
-        http_archive,
-        name = "remote_java_tools",
-        sha256 = "cbb62ecfef61568ded46260a8e8e8430755db7ec9638c0c7ff668a656f6c042f",
-        urls = [
-            "https://mirror.bazel.build/bazel_java_tools/releases/java/v12.3/java_tools-v12.3.zip",
-            "https://github.com/bazelbuild/java_tools/releases/download/java_v12.3/java_tools-v12.3.zip",
-        ],
-    )
-
-    maybe(
-        http_archive,
-        name = "remote_java_tools_linux",
-        sha256 = "32157b5218b151009f5b99bf5e2f65e28823d269dfbba8cd57e7da5e7cdd291d",
-        urls = [
-            "https://mirror.bazel.build/bazel_java_tools/releases/java/v12.3/java_tools_linux-v12.3.zip",
-            "https://github.com/bazelbuild/java_tools/releases/download/java_v12.3/java_tools_linux-v12.3.zip",
-        ],
-    )
-
-    maybe(
-        http_archive,
-        name = "remote_java_tools_windows",
-        sha256 = "ec6f91387d2353eacb0ca0492f35f68c5c7b0e7a80acd1fb825088b4b069fab1",
-        urls = [
-            "https://mirror.bazel.build/bazel_java_tools/releases/java/v12.3/java_tools_windows-v12.3.zip",
-            "https://github.com/bazelbuild/java_tools/releases/download/java_v12.3/java_tools_windows-v12.3.zip",
-        ],
-    )
-
-    maybe(
-        http_archive,
-        name = "remote_java_tools_darwin_x86_64",
-        sha256 = "3c3fb1967a0f35c73ff509505de53ca4611518922a6b7c8c22a468aa7503132c",
-        urls = [
-            "https://mirror.bazel.build/bazel_java_tools/releases/java/v12.3/java_tools_darwin_x86_64-v12.3.zip",
-            "https://github.com/bazelbuild/java_tools/releases/download/java_v12.3/java_tools_darwin_x86_64-v12.3.zip",
-        ],
-    )
-
-    maybe(
-        http_archive,
-        name = "remote_java_tools_darwin_arm64",
-        sha256 = "29aa0c2de4e3cf45bc55d2995ba803ecbd1173a8d363860abbc309551db7931b",
-        urls = [
-            "https://mirror.bazel.build/bazel_java_tools/releases/java/v12.3/java_tools_darwin_arm64-v12.3.zip",
-            "https://github.com/bazelbuild/java_tools/releases/download/java_v12.3/java_tools_darwin_arm64-v12.3.zip",
-        ],
-    )
+    for name, config in _JAVA_TOOLS_CONFIG["artifacts"].items():
+        maybe(
+            http_archive,
+            name = "remote_" + name,
+            sha256 = config["sha"],
+            urls = [
+                config["mirror_url"],
+                config["github_url"],
+            ],
+        )
 
 def local_jdk_repo():
     maybe(
@@ -139,6 +132,7 @@ def remote_jdk8_repos(name = ""):
         sha256 = "e5c84a46bbd985c3a53358db9c97a6fd4930f92b833c3163a0d1e47dab59768c",
         strip_prefix = "zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64",
         urls = [
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64.tar.gz",
             "https://cdn.azul.com/zulu/bin/zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64.tar.gz",
         ],
         version = "8",
@@ -173,16 +167,6 @@ def remote_jdk8_repos(name = ""):
         ],
         version = "8",
     )
-    REMOTE_JDK8_REPOS = [
-        "remote_jdk8_linux_aarch64",
-        "remote_jdk8_linux_s390x",
-        "remote_jdk8_linux",
-        "remote_jdk8_macos_aarch64",
-        "remote_jdk8_macos",
-        "remote_jdk8_windows",
-    ]
-    for name in REMOTE_JDK8_REPOS:
-        native.register_toolchains("@" + name + "_toolchain_config_repo//:toolchain")
 
 def remote_jdk11_repos():
     """Imports OpenJDK 11 repositories."""
@@ -193,11 +177,11 @@ def remote_jdk11_repos():
             "@platforms//os:linux",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "e064b61d93304012351242bf0823c6a2e41d9e28add7ea7f05378b7243d34247",
-        strip_prefix = "zulu11.56.19-ca-jdk11.0.15-linux_x64",
+        sha256 = "a34b404f87a08a61148b38e1416d837189e1df7a040d949e743633daf4695a3c",
+        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-linux_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-linux_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_x64.tar.gz",
         ],
         version = "11",
     )
@@ -209,11 +193,11 @@ def remote_jdk11_repos():
             "@platforms//os:linux",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "fc7c41a0005180d4ca471c90d01e049469e0614cf774566d4cf383caa29d1a97",
-        strip_prefix = "zulu11.56.19-ca-jdk11.0.15-linux_aarch64",
+        sha256 = "54174439f2b3fddd11f1048c397fe7bb45d4c9d66d452d6889b013d04d21c4de",
+        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-linux_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu-embedded/bin/zulu11.56.19-ca-jdk11.0.15-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu-embedded/bin/zulu11.56.19-ca-jdk11.0.15-linux_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_aarch64.tar.gz",
         ],
         version = "11",
     )
@@ -257,11 +241,11 @@ def remote_jdk11_repos():
             "@platforms//os:macos",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "2614e5c5de8e989d4d81759de4c333aa5b867b17ab9ee78754309ba65c7f6f55",
-        strip_prefix = "zulu11.56.19-ca-jdk11.0.15-macosx_x64",
+        sha256 = "bcaab11cfe586fae7583c6d9d311c64384354fb2638eb9a012eca4c3f1a1d9fd",
+        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-macosx_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-macosx_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_x64.tar.gz",
         ],
         version = "11",
     )
@@ -273,11 +257,11 @@ def remote_jdk11_repos():
             "@platforms//os:macos",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "6bb0d2c6e8a29dcd9c577bbb2986352ba12481a9549ac2c0bcfd00ed60e538d2",
-        strip_prefix = "zulu11.56.19-ca-jdk11.0.15-macosx_aarch64",
+        sha256 = "7632bc29f8a4b7d492b93f3bc75a7b61630894db85d136456035ab2a24d38885",
+        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-macosx_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-macosx_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_aarch64.tar.gz",
         ],
         version = "11",
     )
@@ -289,11 +273,11 @@ def remote_jdk11_repos():
             "@platforms//os:windows",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "a106c77389a63b6bd963a087d5f01171bd32aa3ee7377ecef87531390dcb9050",
-        strip_prefix = "zulu11.56.19-ca-jdk11.0.15-win_x64",
+        sha256 = "43408193ce2fa0862819495b5ae8541085b95660153f2adcf91a52d3a1710e83",
+        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-win_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu11.56.19-ca-jdk11.0.15-win_x64.zip",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-win_x64.zip",
+            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-win_x64.zip",
         ],
         version = "11",
     )
@@ -322,11 +306,11 @@ def remote_jdk17_repos():
             "@platforms//os:linux",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "20c91a922eec795f3181eaa70def8b99d8eac56047c9a14bfb257c85b991df1b",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-linux_x64",
+        sha256 = "b9482f2304a1a68a614dfacddcf29569a72f0fac32e6c74f83dc1b9a157b8340",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-linux_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-linux_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_x64.tar.gz",
         ],
         version = "17",
     )
@@ -338,11 +322,11 @@ def remote_jdk17_repos():
             "@platforms//os:linux",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "dbc6ae9163e7ff469a9ab1f342cd1bc1f4c1fb78afc3c4f2228ee3b32c4f3e43",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-linux_aarch64",
+        sha256 = "6531cef61e416d5a7b691555c8cf2bdff689201b8a001ff45ab6740062b44313",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-linux_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64.tar.gz",
         ],
         version = "17",
     )
@@ -354,11 +338,11 @@ def remote_jdk17_repos():
             "@platforms//os:linux",
             "@platforms//cpu:s390x",
         ],
-        sha256 = "fdc82f4b06c880762503b0cb40e25f46cf8190d06011b3b768f4091d3334ef7f",
-        strip_prefix = "jdk-17.0.4.1+1",
+        sha256 = "ffacba69c6843d7ca70d572489d6cc7ab7ae52c60f0852cedf4cf0d248b6fc37",
+        strip_prefix = "jdk-17.0.8.1+1",
         urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.4.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.4.1_1.tar.gz",
-            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.4.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.4.1_1.tar.gz",
+            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz",
+            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz",
         ],
         version = "17",
     )
@@ -370,11 +354,11 @@ def remote_jdk17_repos():
             "@platforms//os:linux",
             "@platforms//cpu:ppc",
         ],
-        sha256 = "cbedd0a1428b3058d156e99e8e9bc8769e0d633736d6776a4c4d9136648f2fd1",
-        strip_prefix = "jdk-17.0.4.1+1",
+        sha256 = "00a4c07603d0218cd678461b5b3b7e25b3253102da4022d31fc35907f21a2efd",
+        strip_prefix = "jdk-17.0.8.1+1",
         urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.4.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.4.1_1.tar.gz",
-            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.4.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.4.1_1.tar.gz",
+            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz",
+            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz",
         ],
         version = "17",
     )
@@ -386,11 +370,11 @@ def remote_jdk17_repos():
             "@platforms//os:macos",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "e6317cee4d40995f0da5b702af3f04a6af2bbd55febf67927696987d11113b53",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-macosx_x64",
+        sha256 = "640453e8afe8ffe0fb4dceb4535fb50db9c283c64665eebb0ba68b19e65f4b1f",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-macosx_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-macosx_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_x64.tar.gz",
         ],
         version = "17",
     )
@@ -402,11 +386,11 @@ def remote_jdk17_repos():
             "@platforms//os:macos",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "515dd56ec99bb5ae8966621a2088aadfbe72631818ffbba6e4387b7ee292ab09",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-macosx_aarch64",
+        sha256 = "314b04568ec0ae9b36ba03c9cbd42adc9e1265f74678923b19297d66eb84dcca",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-macosx_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64.tar.gz",
         ],
         version = "17",
     )
@@ -417,11 +401,11 @@ def remote_jdk17_repos():
             "@platforms//os:windows",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "9972c5b62a61b45785d3d956c559e079d9e91f144ec46225f5deeda214d48f27",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-win_x64",
+        sha256 = "192f2afca57701de6ec496234f7e45d971bf623ff66b8ee4a5c81582054e5637",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-win_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-win_x64.zip",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_x64.zip",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_x64.zip",
         ],
         version = "17",
     )
@@ -432,94 +416,137 @@ def remote_jdk17_repos():
             "@platforms//os:windows",
             "@platforms//cpu:arm64",
         ],
-        sha256 = "bc3476f2161bf99bc9a243ff535b8fc033b34ce9a2fa4b62fb8d79b6bfdc427f",
-        strip_prefix = "zulu17.38.21-ca-jdk17.0.5-win_aarch64",
+        sha256 = "6802c99eae0d788e21f52d03cab2e2b3bf42bc334ca03cbf19f71eb70ee19f85",
+        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-win_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-win_aarch64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu17.38.21-ca-jdk17.0.5-win_aarch64.zip",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_aarch64.zip",
+            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_aarch64.zip",
         ],
         version = "17",
     )
 
-def remote_jdk20_repos():
-    """Imports OpenJDK 20 repositories."""
+def remote_jdk21_repos():
+    """Imports OpenJDK 21 repositories."""
     maybe(
         remote_java_repository,
-        name = "remotejdk20_linux",
+        name = "remotejdk21_linux",
         target_compatible_with = [
             "@platforms//os:linux",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "0386418db7f23ae677d05045d30224094fc13423593ce9cd087d455069893bac",
-        strip_prefix = "zulu20.28.85-ca-jdk20.0.0-linux_x64",
+        sha256 = "5ad730fbee6bb49bfff10bf39e84392e728d89103d3474a7e5def0fd134b300a",
+        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-linux_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-linux_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_x64.tar.gz",
         ],
-        version = "20",
+        version = "21",
     )
-
     maybe(
         remote_java_repository,
-        name = "remotejdk20_linux_aarch64",
+        name = "remotejdk21_linux_aarch64",
         target_compatible_with = [
             "@platforms//os:linux",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "47ce58ead9a05d5d53b96706ff6fa0eb2e46755ee67e2b416925e28f5b55038a",
-        strip_prefix = "zulu20.28.85-ca-jdk20.0.0-linux_aarch64",
+        sha256 = "ce7df1af5d44a9f455617c4b8891443fbe3e4b269c777d8b82ed66f77167cfe0",
+        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-linux_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-linux_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_aarch64.tar.gz",
         ],
-        version = "20",
+        version = "21",
     )
-
     maybe(
         remote_java_repository,
-        name = "remotejdk20_macos",
+        name = "remotejdk21_linux_ppc64le",
+        target_compatible_with = [
+            "@platforms//os:linux",
+            "@platforms//cpu:ppc",
+        ],
+        sha256 = "d08de863499d8851811c893e8915828f2cd8eb67ed9e29432a6b4e222d80a12f",
+        strip_prefix = "jdk-21.0.2+13",
+        urls = [
+            "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.2_13.tar.gz",
+            "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.2_13.tar.gz",
+        ],
+        version = "21",
+    )
+    maybe(
+        remote_java_repository,
+        name = "remotejdk21_linux_s390x",
+        target_compatible_with = [
+            "@platforms//os:linux",
+            "@platforms//cpu:s390x",
+        ],
+        sha256 = "0d5676c50821e0d0b951bf3ffd717e7a13be2a89d8848a5c13b4aedc6f982c78",
+        strip_prefix = "jdk-21.0.2+13",
+        urls = [
+            "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.2_13.tar.gz",
+            "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.2_13.tar.gz",
+        ],
+        version = "21",
+    )
+    maybe(
+        remote_java_repository,
+        name = "remotejdk21_macos",
         target_compatible_with = [
             "@platforms//os:macos",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "fde6cc17a194ea0d9b0c6c0cb6178199d8edfc282d649eec2c86a9796e843f86",
-        strip_prefix = "zulu20.28.85-ca-jdk20.0.0-macosx_x64",
+        sha256 = "3ad8fe288eb57d975c2786ae453a036aa46e47ab2ac3d81538ebae2a54d3c025",
+        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-macosx_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-macosx_x64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_x64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_x64.tar.gz",
         ],
-        version = "20",
+        version = "21",
     )
 
     maybe(
         remote_java_repository,
-        name = "remotejdk20_macos_aarch64",
+        name = "remotejdk21_macos_aarch64",
         target_compatible_with = [
             "@platforms//os:macos",
             "@platforms//cpu:aarch64",
         ],
-        sha256 = "a2eff6a940c2df3a2352278027e83f5959f34dcfc8663034fe92be0f1b91ce6f",
-        strip_prefix = "zulu20.28.85-ca-jdk20.0.0-macosx_aarch64",
+        sha256 = "e8260516de8b60661422a725f1df2c36ef888f6fb35393566b00e7325db3d04e",
+        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-macosx_aarch64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-macosx_aarch64.tar.gz",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_aarch64.tar.gz",
+            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_aarch64.tar.gz",
         ],
-        version = "20",
+        version = "21",
     )
     maybe(
         remote_java_repository,
-        name = "remotejdk20_win",
+        name = "remotejdk21_win",
         target_compatible_with = [
             "@platforms//os:windows",
             "@platforms//cpu:x86_64",
         ],
-        sha256 = "ac5f6a7d84dbbb0bb4d376feb331cc4c49a9920562f2a5e85b7a6b4863b10e1e",
-        strip_prefix = "zulu20.28.85-ca-jdk20.0.0-win_x64",
+        sha256 = "f7cc15ca17295e69c907402dfe8db240db446e75d3b150da7bf67243cded93de",
+        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-win_x64",
         urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu20.28.85-ca-jdk20.0.0-win_x64.zip",
+            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-win_x64.zip",
+            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-win_x64.zip",
         ],
-        version = "20",
+        version = "21",
+    )
+    maybe(
+        remote_java_repository,
+        name = "remotejdk21_win_arm64",
+        target_compatible_with = [
+            "@platforms//os:windows",
+            "@platforms//cpu:arm64",
+        ],
+        sha256 = "975603e684f2ec5a525b3b5336d6aa0b09b5b7d2d0d9e271bd6a9892ad550181",
+        strip_prefix = "jdk-21+35",
+        urls = [
+            "https://mirror.bazel.build/aka.ms/download-jdk/microsoft-jdk-21.0.0-windows-aarch64.zip",
+            "https://aka.ms/download-jdk/microsoft-jdk-21.0.0-windows-aarch64.zip",
+        ],
+        version = "21",
     )
 
 def rules_java_dependencies():
@@ -529,9 +556,10 @@ def rules_java_dependencies():
     """
 
     local_jdk_repo()
+    remote_jdk8_repos()
     remote_jdk11_repos()
     remote_jdk17_repos()
-    remote_jdk20_repos()
+    remote_jdk21_repos()
     java_tools_repos()
 
 def rules_java_toolchains(name = "toolchains"):
@@ -541,17 +569,25 @@ def rules_java_toolchains(name = "toolchains"):
         name: The name of this macro (not used)
     """
     JDKS = {
+        # Must match JDK repos defined in remote_jdk8_repos()
+        "8": ["linux", "linux_aarch64", "linux_s390x", "macos", "macos_aarch64", "windows"],
         # Must match JDK repos defined in remote_jdk11_repos()
         "11": ["linux", "linux_aarch64", "linux_ppc64le", "linux_s390x", "macos", "macos_aarch64", "win", "win_arm64"],
         # Must match JDK repos defined in remote_jdk17_repos()
         "17": ["linux", "linux_aarch64", "linux_ppc64le", "linux_s390x", "macos", "macos_aarch64", "win", "win_arm64"],
-        # Must match JDK repos defined in remote_jdk20_repos()
-        "20": ["linux", "linux_aarch64", "macos", "macos_aarch64", "win"],
+        # Must match JDK repos defined in remote_jdk21_repos()
+        "21": ["linux", "linux_aarch64", "macos", "macos_aarch64", "win"],
     }
 
-    REMOTE_JDK_REPOS = [("remotejdk" + version + "_" + platform) for version in JDKS for platform in JDKS[version]]
+    REMOTE_JDK_REPOS = [(("remote_jdk" if version == "8" else "remotejdk") + version + "_" + platform) for version in JDKS for platform in JDKS[version]]
 
-    native.register_toolchains("//toolchains:all")
-    native.register_toolchains("@local_jdk//:runtime_toolchain_definition")
+    native.register_toolchains(
+        "//toolchains:all",
+        "@local_jdk//:runtime_toolchain_definition",
+        "@local_jdk//:bootstrap_runtime_toolchain_definition",
+    )
     for name in REMOTE_JDK_REPOS:
-        native.register_toolchains("@" + name + "_toolchain_config_repo//:toolchain")
+        native.register_toolchains(
+            "@" + name + "_toolchain_config_repo//:toolchain",
+            "@" + name + "_toolchain_config_repo//:bootstrap_runtime_toolchain",
+        )
diff --git a/java/toolchains/BUILD b/java/toolchains/BUILD
new file mode 100644
index 0000000..894cf44
--- /dev/null
+++ b/java/toolchains/BUILD
@@ -0,0 +1,26 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+package(default_visibility = ["//visibility:public"])
+
+licenses(["notice"])
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
+
+bzl_library(
+    name = "toolchain_rules",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//visibility:public"],
+    deps = ["//java/private"],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    srcs = [
+        "BUILD",
+        "java_toolchain.bzl",
+    ],
+)
diff --git a/java/toolchains/java_package_configuration.bzl b/java/toolchains/java_package_configuration.bzl
new file mode 100644
index 0000000..09d8e1e
--- /dev/null
+++ b/java/toolchains/java_package_configuration.bzl
@@ -0,0 +1,26 @@
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
+"""java_package_configuration rule"""
+
+def java_package_configuration(**attrs):
+    """Bazel java_package_configuration rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_package_configuration
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_package_configuration(**attrs)
diff --git a/java/toolchains/java_runtime.bzl b/java/toolchains/java_runtime.bzl
new file mode 100644
index 0000000..3657a88
--- /dev/null
+++ b/java/toolchains/java_runtime.bzl
@@ -0,0 +1,26 @@
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
+"""java_runtime rule"""
+
+def java_runtime(**attrs):
+    """Bazel java_runtime rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_runtime
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_runtime(**attrs)
diff --git a/java/toolchains/java_toolchain.bzl b/java/toolchains/java_toolchain.bzl
new file mode 100644
index 0000000..5b07292
--- /dev/null
+++ b/java/toolchains/java_toolchain.bzl
@@ -0,0 +1,26 @@
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
+"""java_toolchain rule"""
+
+def java_toolchain(**attrs):
+    """Bazel java_toolchain rule.
+
+    https://docs.bazel.build/versions/master/be/java.html#java_toolchain
+
+    Args:
+      **attrs: Rule attributes
+    """
+
+    # buildifier: disable=native-java
+    native.java_toolchain(**attrs)
diff --git a/toolchains/BUILD b/toolchains/BUILD
index b8cb35d..81126c2 100644
--- a/toolchains/BUILD
+++ b/toolchains/BUILD
@@ -1,3 +1,4 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
 load("@rules_cc//cc:defs.bzl", "cc_library")
 load(
     ":default_java_toolchain.bzl",
@@ -29,14 +30,45 @@ filegroup(
     srcs = glob(["*.bzl"]),
 )
 
-# Used to distinguish toolchains used for Java development, ie the JavaToolchainProvider.
+# A single binary distribution of a JDK (e.g., OpenJDK 17 for Windows arm64) provides three
+# different types of toolchains from the perspective of Bazel:
+
+# The compilation toolchain, which provides the Java runtime used to execute the Java compiler, as
+# well as various helper tools and settings.
+#
+# Toolchains of this type typically have constraints on the execution platform so that their Java
+# runtime can run the compiler, but not on the target platform as Java compilation outputs are
+# platform independent.
+#
+# Obtain the associated JavaToolchainInfo via:
+#   ctx.toolchains["@bazel_tools//tools/jdk:toolchain_type"].java
 # TODO: migrate away from using @bazel_tools//tools/jdk:toolchain_type ?
 # toolchain_type(name = "toolchain_type")
 
-# Used to distinguish toolchains used for Java execution, ie the JavaRuntimeInfo.
+# The Java runtime that executable Java compilation outputs (e.g., java_binary with
+# create_executable = True) will run on.
+#
+# Toolchains of this type typically have constraints on the target platform so that the runtime's
+# native 'java' binary can be run there, but not on the execution platform as building an executable
+# Java target only requires copying or symlinking the runtime, which can be done on any platform.
+#
+# Obtain the associated JavaRuntimeInfo via:
+#   ctx.toolchains["@bazel_tools//tools/jdk:runtime_toolchain_type"].java_runtime
 # TODO: migrate away from using @bazel_tools//tools/jdk:runtime_toolchain_type ?
 # toolchain_type(name = "runtime_toolchain_type")
 
+# The Java runtime to extract the bootclasspath from that is then used to compile Java sources.
+#
+# As the bootclasspath is platform independent, toolchains of this type may have no constraints.
+# Purely as an optimization to prevent unnecessary fetches of remote runtimes for other
+# architectures, toolchains of this type may have constraints on the execution platform that match
+# those on the corresponding compilation toolchain.
+#
+# Toolchains of this type are only consumed internally by the bootclasspath rule and should not be
+# accessed from Starlark.
+# TODO: migrate away from using @bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type ?
+# toolchain_type(name = "bootstrap_runtime_toolchain_type")
+
 # Points to toolchain[":runtime_toolchain_type"] (was :legacy_current_java_runtime)
 java_runtime_alias(name = "current_java_runtime")
 
@@ -128,6 +160,10 @@ cc_library(
             actual = "@remote_java_tools_%s//:prebuilt_singlejar" % OS,
             visibility = ["//visibility:private"],
         ),
+        alias(
+            name = "turbine_direct_graal_%s" % OS,
+            actual = "@remote_java_tools_%s//:turbine_direct_graal" % OS,
+        ),
     )
     for OS in [
         "linux",
@@ -137,9 +173,6 @@ cc_library(
     ]
 ]
 
-# On Windows, executables end in ".exe", but the label we reach it through
-# must be platform-independent. Thus, we create a little filegroup that
-# contains the appropriate platform-dependent file.
 alias(
     name = "ijar",
     actual = ":ijar_prebuilt_binary_or_cc_binary",
@@ -166,12 +199,6 @@ alias(
     }),
 )
 
-# On Windows, Java implementation of singlejar is used. We create a little
-# filegroup that contains the appropriate platform-dependent file.
-# Once https://github.com/bazelbuild/bazel/issues/2241 is fixed (that is,
-# the native singlejar is used on windows), this file group can be reused since
-# on Windows, executables end in ".exe", but the label we reach it through
-# must be platform-independent.
 alias(
     name = "singlejar",
     actual = ":singlejar_prebuilt_or_cc_binary",
@@ -198,11 +225,36 @@ alias(
     }),
 )
 
+alias(
+    name = "turbine_direct",
+    actual = ":turbine_direct_graal_or_java",
+)
+
+alias(
+    name = "turbine_direct_graal_or_java",
+    actual = select({
+        "@bazel_tools//src/conditions:darwin_arm64": ":turbine_direct_graal_darwin_arm64",
+        "@bazel_tools//src/conditions:darwin_x86_64": ":turbine_direct_graal_darwin_x86_64",
+        "@bazel_tools//src/conditions:linux_x86_64": ":turbine_direct_graal_linux",
+        "@bazel_tools//src/conditions:windows": ":turbine_direct_graal_windows",
+        "//conditions:default": "@remote_java_tools//:TurbineDirect",
+    }),
+)
+
+alias(
+    name = "turbine_direct_graal",
+    actual = select({
+        "@bazel_tools//src/conditions:darwin_arm64": ":turbine_direct_graal_darwin_arm64",
+        "@bazel_tools//src/conditions:darwin_x86_64": ":turbine_direct_graal_darwin_x86_64",
+        "@bazel_tools//src/conditions:linux_x86_64": ":turbine_direct_graal_linux",
+        "@bazel_tools//src/conditions:windows": ":turbine_direct_graal_windows",
+    }),
+)
+
 bootclasspath(
     name = "platformclasspath",
     src = "DumpPlatformClassPath.java",
-    host_javabase = ":current_java_runtime",
-    target_javabase = ":current_java_runtime",
+    java_runtime_alias = ":current_java_runtime",
 )
 
 default_java_toolchain(
@@ -216,11 +268,11 @@ alias(
     actual = ":toolchain",
 )
 
-RELEASES = (8, 9, 10, 11)
+RELEASES = (8, 9, 10, 11, 17, 21)
 
 [
     default_java_toolchain(
-        name = "toolchain_java%d" % release,
+        name = ("toolchain_java%d" if release <= 11 else "toolchain_jdk_%d") % release,
         configuration = DEFAULT_TOOLCHAIN_CONFIGURATION,
         source_version = "%s" % release,
         target_version = "%s" % release,
@@ -228,51 +280,6 @@ RELEASES = (8, 9, 10, 11)
     for release in RELEASES
 ]
 
-# A toolchain that targets java 14.
-default_java_toolchain(
-    name = "toolchain_jdk_14",
-    configuration = dict(),
-    java_runtime = "//toolchains:remotejdk_14",
-    source_version = "14",
-    target_version = "14",
-)
-
-# A toolchain that targets java 15.
-default_java_toolchain(
-    name = "toolchain_jdk_15",
-    configuration = dict(),
-    java_runtime = "//toolchains:remotejdk_15",
-    source_version = "15",
-    target_version = "15",
-)
-
-# A toolchain that targets java 16.
-default_java_toolchain(
-    name = "toolchain_jdk_16",
-    configuration = dict(),
-    java_runtime = "//toolchains:remotejdk_16",
-    source_version = "16",
-    target_version = "16",
-)
-
-# A toolchain that targets java 17.
-default_java_toolchain(
-    name = "toolchain_jdk_17",
-    configuration = dict(),
-    java_runtime = "//toolchains:remotejdk_17",
-    source_version = "17",
-    target_version = "17",
-)
-
-# A toolchain that targets java 20.
-default_java_toolchain(
-    name = "toolchain_jdk_20",
-    configuration = dict(),
-    java_runtime = "//toolchains:remotejdk_20",
-    source_version = "20",
-    target_version = "20",
-)
-
 default_java_toolchain(
     name = "prebuilt_toolchain",
     configuration = PREBUILT_TOOLCHAIN_CONFIGURATION,
@@ -305,8 +312,8 @@ java_runtime_version_alias(
 )
 
 java_runtime_version_alias(
-    name = "remotejdk_20",
-    runtime_version = "remotejdk_20",
+    name = "remotejdk_21",
+    runtime_version = "remotejdk_21",
     visibility = ["//visibility:public"],
 )
 
@@ -315,3 +322,10 @@ java_runtime_version_alias(
     runtime_version = "8",
     visibility = ["//visibility:public"],
 )
+
+bzl_library(
+    name = "toolchain_utils",
+    srcs = ["toolchain_utils.bzl"],
+    visibility = ["//visibility:public"],
+    deps = ["//java/common"],
+)
diff --git a/toolchains/DumpPlatformClassPath.java b/toolchains/DumpPlatformClassPath.java
index 0832853..17b014a 100644
--- a/toolchains/DumpPlatformClassPath.java
+++ b/toolchains/DumpPlatformClassPath.java
@@ -12,8 +12,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-import com.sun.tools.javac.api.JavacTool;
-import com.sun.tools.javac.util.Context;
 import java.io.BufferedOutputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
@@ -21,13 +19,19 @@ import java.io.InputStream;
 import java.io.OutputStream;
 import java.io.UncheckedIOException;
 import java.lang.reflect.Method;
+import java.net.URI;
+import java.nio.file.DirectoryStream;
+import java.nio.file.FileSystem;
+import java.nio.file.FileSystems;
+import java.nio.file.FileVisitResult;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.nio.file.SimpleFileVisitor;
+import java.nio.file.attribute.BasicFileAttributes;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
-import java.util.EnumSet;
 import java.util.GregorianCalendar;
 import java.util.List;
 import java.util.Map;
@@ -38,16 +42,11 @@ import java.util.jar.JarFile;
 import java.util.jar.JarOutputStream;
 import java.util.zip.CRC32;
 import java.util.zip.ZipEntry;
-import javax.tools.JavaFileManager;
-import javax.tools.JavaFileObject;
-import javax.tools.JavaFileObject.Kind;
-import javax.tools.StandardJavaFileManager;
-import javax.tools.StandardLocation;
 
 /**
  * Output a jar file containing all classes on the platform classpath of the given JDK release.
  *
- * <p>usage: DumpPlatformClassPath <release version> <output jar> <path to target JDK>?
+ * <p>usage: {@code DumpPlatformClassPath <output jar> <path to target JDK>}
  */
 public class DumpPlatformClassPath {
 
@@ -90,7 +89,7 @@ public class DumpPlatformClassPath {
     // * --release takes a language level (e.g. '9') and uses the API information baked in to
     //     the host JDK (in lib/ct.sym).
 
-    // Since --system only supports JDK >= 9, first check of the target JDK defines a JDK 8
+    // Since --system only supports JDK >= 9, first check if the target JDK defines a JDK 8
     // bootclasspath.
     List<Path> bootClassPathJars = getBootClassPathJars(targetJavabase);
     if (!bootClassPathJars.isEmpty()) {
@@ -98,50 +97,35 @@ public class DumpPlatformClassPath {
       return true;
     }
 
-    // Initialize a FileManager to process the --system argument, and then read the
-    // initialized bootclasspath data back out.
-
-    Context context = new Context();
-    try {
-      JavacTool.create()
-          .getTask(
-              /* out = */ null,
-              /* fileManager = */ null,
-              /* diagnosticListener = */ null,
-              /* options = */ Arrays.asList("--system", String.valueOf(targetJavabase)),
-              /* classes = */ null,
-              /* compilationUnits = */ null,
-              context);
-    } catch (IllegalArgumentException e) {
-      throw new IllegalArgumentException(
-          String.format(
-              "Failed to collect system class path. Please ensure that the configured Java runtime"
-                  + " ('%s') is a complete JDK. There are known issues with Homebrew versions of"
-                  + " the Java runtime.",
-              targetJavabase.toRealPath()),
-          e);
-    }
-    StandardJavaFileManager fileManager =
-        (StandardJavaFileManager) context.get(JavaFileManager.class);
-
-    SortedMap<String, InputStream> entries = new TreeMap<>();
-    for (JavaFileObject fileObject :
-        fileManager.list(
-            StandardLocation.PLATFORM_CLASS_PATH,
-            "",
-            EnumSet.of(Kind.CLASS),
-            /* recurse= */ true)) {
-      String binaryName =
-          fileManager.inferBinaryName(StandardLocation.PLATFORM_CLASS_PATH, fileObject);
-      entries.put(binaryName.replace('.', '/') + ".class", fileObject.openInputStream());
+    // Read the bootclasspath data using the JRT filesystem
+    Map<String, byte[]> entries = new TreeMap<>();
+    Map<String, String> env = new TreeMap<>();
+    env.put("java.home", String.valueOf(targetJavabase));
+    try (FileSystem fileSystem = FileSystems.newFileSystem(URI.create("jrt:/"), env)) {
+      Path modules = fileSystem.getPath("/modules");
+      try (DirectoryStream<Path> ms = Files.newDirectoryStream(modules)) {
+        for (Path m : ms) {
+          Files.walkFileTree(
+              m,
+              new SimpleFileVisitor<Path>() {
+                @Override
+                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
+                    throws IOException {
+                  if (file.getFileName().toString().endsWith(".class")) {
+                    entries.put(m.relativize(file).toString(), Files.readAllBytes(file));
+                  }
+                  return super.visitFile(file, attrs);
+                }
+              });
+        }
+      }
+      writeEntries(output, entries);
     }
-    writeEntries(output, entries);
     return true;
   }
 
   /** Writes the given entry names and data to a jar archive at the given path. */
-  private static void writeEntries(Path output, Map<String, InputStream> entries)
-      throws IOException {
+  private static void writeEntries(Path output, Map<String, byte[]> entries) throws IOException {
     if (!entries.containsKey("java/lang/Object.class")) {
       throw new AssertionError(
           "\nCould not find java.lang.Object on bootclasspath; something has gone terribly wrong.\n"
@@ -168,14 +152,14 @@ public class DumpPlatformClassPath {
     for (Path path : paths) {
       jars.add(new JarFile(path.toFile()));
     }
-    SortedMap<String, InputStream> entries = new TreeMap<>();
+    SortedMap<String, byte[]> entries = new TreeMap<>();
     for (JarFile jar : jars) {
       jar.stream()
           .filter(p -> p.getName().endsWith(".class"))
           .forEachOrdered(
               entry -> {
                 try {
-                  entries.put(entry.getName(), jar.getInputStream(entry));
+                  entries.put(entry.getName(), toByteArray(jar.getInputStream(entry)));
                 } catch (IOException e) {
                   throw new UncheckedIOException(e);
                 }
@@ -203,6 +187,10 @@ public class DumpPlatformClassPath {
         jars.add(path);
       }
     }
+    Path toolsJar = javaHome.resolve("lib/tools.jar");
+    if (Files.exists(toolsJar)) {
+      jars.add(toolsJar);
+    }
     return jars;
   }
 
@@ -214,12 +202,10 @@ public class DumpPlatformClassPath {
    * Add a jar entry to the given {@link JarOutputStream}, normalizing the entry timestamps to
    * ensure deterministic build output.
    */
-  private static void addEntry(JarOutputStream jos, String name, InputStream input)
-      throws IOException {
+  private static void addEntry(JarOutputStream jos, String name, byte[] bytes) throws IOException {
     JarEntry je = new JarEntry(name);
     je.setTime(FIXED_TIMESTAMP);
     je.setMethod(ZipEntry.STORED);
-    byte[] bytes = toByteArray(input);
     // When targeting JDK >= 10, patch the major version so it will be accepted by javac 9
     // TODO(cushon): remove this after updating javac
     if (bytes[7] > 53) {
@@ -266,4 +252,4 @@ public class DumpPlatformClassPath {
     throw new IllegalStateException(
         "Unknown Java version: " + System.getProperty("java.specification.version"));
   }
-}
+}
\ No newline at end of file
diff --git a/toolchains/default_java_toolchain.bzl b/toolchains/default_java_toolchain.bzl
index 9442c5e..020b101 100644
--- a/toolchains/default_java_toolchain.bzl
+++ b/toolchains/default_java_toolchain.bzl
@@ -15,6 +15,7 @@
 """Rules for defining default_java_toolchain"""
 
 load("//java:defs.bzl", "java_toolchain")
+load("//java/common:java_common.bzl", "java_common")
 
 # JVM options, without patching java.compiler and jdk.compiler modules.
 BASE_JDK9_JVM_OPTS = [
@@ -64,6 +65,7 @@ DEFAULT_JAVACOPTS = [
     "-Xep:EmptyTopLevelDeclaration:OFF",
     "-Xep:LenientFormatStringValidation:OFF",
     "-Xep:ReturnMissingNullable:OFF",
+    "-Xep:UseCorrectAssertInTests:OFF",
 ]
 
 # Default java_toolchain parameters
@@ -71,7 +73,7 @@ _BASE_TOOLCHAIN_CONFIGURATION = dict(
     forcibly_disable_header_compilation = False,
     genclass = [Label("@remote_java_tools//:GenClass")],
     header_compiler = [Label("@remote_java_tools//:TurbineDirect")],
-    header_compiler_direct = [Label("@remote_java_tools//:TurbineDirect")],
+    header_compiler_direct = [Label("//toolchains:turbine_direct")],
     ijar = [Label("//toolchains:ijar")],
     javabuilder = [Label("@remote_java_tools//:JavaBuilder")],
     javac_supports_workers = True,
@@ -91,7 +93,7 @@ _BASE_TOOLCHAIN_CONFIGURATION = dict(
     reduced_classpath_incompatible_processors = [
         "dagger.hilt.processor.internal.root.RootProcessor",  # see b/21307381
     ],
-    java_runtime = Label("//toolchains:remotejdk_17"),
+    java_runtime = Label("//toolchains:remotejdk_21"),
 )
 
 DEFAULT_TOOLCHAIN_CONFIGURATION = _BASE_TOOLCHAIN_CONFIGURATION
@@ -129,8 +131,11 @@ PREBUILT_TOOLCHAIN_CONFIGURATION = dict(
 NONPREBUILT_TOOLCHAIN_CONFIGURATION = dict(
     ijar = [Label("@remote_java_tools//:ijar_cc_binary")],
     singlejar = [Label("@remote_java_tools//:singlejar_cc_bin")],
+    header_compiler_direct = [Label("@remote_java_tools//:TurbineDirect")],
 )
 
+# If this is changed, the docs for "{,tool_}java_language_version" also
+# need to be updated in the Bazel user manual
 _DEFAULT_SOURCE_VERSION = "8"
 
 def default_java_toolchain(name, configuration = DEFAULT_TOOLCHAIN_CONFIGURATION, toolchain_definition = True, exec_compatible_with = [], target_compatible_with = [], **kwargs):
@@ -203,8 +208,14 @@ def java_runtime_files(name, srcs):
             tags = ["manual"],
         )
 
+_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE = Label("@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type")
+
+# Opt the Java bootstrap actions into path mapping:
+# https://github.com/bazelbuild/bazel/commit/a239ea84832f18ee8706682145e9595e71b39680
+_SUPPORTS_PATH_MAPPING = {"supports-path-mapping": "1"}
+
 def _bootclasspath_impl(ctx):
-    host_javabase = ctx.attr.host_javabase[java_common.JavaRuntimeInfo]
+    exec_javabase = ctx.attr.java_runtime_alias[java_common.JavaRuntimeInfo]
 
     class_dir = ctx.actions.declare_directory("%s_classes" % ctx.label.name)
 
@@ -214,24 +225,25 @@ def _bootclasspath_impl(ctx):
     args.add("-target")
     args.add("8")
     args.add("-Xlint:-options")
+    args.add("-J-XX:-UsePerfData")
     args.add("-d")
     args.add_all([class_dir], expand_directories = False)
     args.add(ctx.file.src)
 
     ctx.actions.run(
-        executable = "%s/bin/javac" % host_javabase.java_home,
+        executable = "%s/bin/javac" % exec_javabase.java_home,
         mnemonic = "JavaToolchainCompileClasses",
-        inputs = [ctx.file.src] + ctx.files.host_javabase,
+        inputs = [ctx.file.src] + ctx.files.java_runtime_alias,
         outputs = [class_dir],
         arguments = [args],
+        execution_requirements = _SUPPORTS_PATH_MAPPING,
     )
 
     bootclasspath = ctx.outputs.output_jar
 
-    inputs = [class_dir] + ctx.files.host_javabase
-
     args = ctx.actions.args()
     args.add("-XX:+IgnoreUnrecognizedVMOptions")
+    args.add("-XX:-UsePerfData")
     args.add("--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED")
     args.add("--add-exports=jdk.compiler/com.sun.tools.javac.platform=ALL-UNNAMED")
     args.add("--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED")
@@ -239,20 +251,22 @@ def _bootclasspath_impl(ctx):
     args.add("DumpPlatformClassPath")
     args.add(bootclasspath)
 
+    any_javabase = ctx.toolchains[_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE].java_runtime
+    args.add(any_javabase.java_home)
+
     system_files = ("release", "modules", "jrt-fs.jar")
-    system = [f for f in ctx.files.target_javabase if f.basename in system_files]
+    system = [f for f in any_javabase.files.to_list() if f.basename in system_files]
     if len(system) != len(system_files):
         system = None
-    if ctx.attr.target_javabase:
-        inputs.extend(ctx.files.target_javabase)
-        args.add(ctx.attr.target_javabase[java_common.JavaRuntimeInfo].java_home)
 
+    inputs = depset([class_dir] + ctx.files.java_runtime_alias, transitive = [any_javabase.files])
     ctx.actions.run(
-        executable = str(host_javabase.java_executable_exec_path),
+        executable = str(exec_javabase.java_executable_exec_path),
         mnemonic = "JavaToolchainCompileBootClasspath",
         inputs = inputs,
         outputs = [bootclasspath],
         arguments = [args],
+        execution_requirements = _SUPPORTS_PATH_MAPPING,
     )
     return [
         DefaultInfo(files = depset([bootclasspath])),
@@ -266,7 +280,7 @@ def _bootclasspath_impl(ctx):
 _bootclasspath = rule(
     implementation = _bootclasspath_impl,
     attrs = {
-        "host_javabase": attr.label(
+        "java_runtime_alias": attr.label(
             cfg = "exec",
             providers = [java_common.JavaRuntimeInfo],
         ),
@@ -275,10 +289,8 @@ _bootclasspath = rule(
             cfg = "exec",
             allow_single_file = True,
         ),
-        "target_javabase": attr.label(
-            providers = [java_common.JavaRuntimeInfo],
-        ),
     },
+    toolchains = [_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE],
 )
 
 def bootclasspath(name, **kwargs):
diff --git a/toolchains/java_toolchain_alias.bzl b/toolchains/java_toolchain_alias.bzl
index 21fae7e..8d8a7e4 100644
--- a/toolchains/java_toolchain_alias.bzl
+++ b/toolchains/java_toolchain_alias.bzl
@@ -14,6 +14,8 @@
 
 """Experimental re-implementations of Java toolchain aliases using toolchain resolution."""
 
+load("//java/common:java_common.bzl", "java_common")
+
 def _java_runtime_alias(ctx):
     """An experimental implementation of java_runtime_alias using toolchain resolution."""
     toolchain_info = ctx.toolchains["@bazel_tools//tools/jdk:runtime_toolchain_type"]
@@ -35,7 +37,6 @@ def _java_runtime_alias(ctx):
 java_runtime_alias = rule(
     implementation = _java_runtime_alias,
     toolchains = ["@bazel_tools//tools/jdk:runtime_toolchain_type"],
-    incompatible_use_toolchain_transition = True,
 )
 
 def _java_host_runtime_alias(ctx):
@@ -82,12 +83,8 @@ _java_runtime_transition = transition(
 java_runtime_version_alias = rule(
     implementation = _java_runtime_alias,
     toolchains = ["@bazel_tools//tools/jdk:runtime_toolchain_type"],
-    incompatible_use_toolchain_transition = True,
     attrs = {
         "runtime_version": attr.string(mandatory = True),
-        "_allowlist_function_transition": attr.label(
-            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
-        ),
     },
     cfg = _java_runtime_transition,
 )
@@ -97,18 +94,12 @@ def _java_toolchain_alias(ctx):
     toolchain_info = ctx.toolchains["@bazel_tools//tools/jdk:toolchain_type"]
     toolchain = toolchain_info.java
 
-    # buildifier: disable=rule-impl-return
-    return struct(
-        providers = [
-            toolchain_info,
-            toolchain,
-        ],
-        # Use the legacy provider syntax for compatibility with the native rules.
-        java_toolchain = toolchain,
-    )
+    return [
+        toolchain_info,
+        toolchain,
+    ]
 
 java_toolchain_alias = rule(
     implementation = _java_toolchain_alias,
     toolchains = ["@bazel_tools//tools/jdk:toolchain_type"],
-    incompatible_use_toolchain_transition = True,
 )
diff --git a/toolchains/jdk_build_file.bzl b/toolchains/jdk_build_file.bzl
index 71b615a..1e08f37 100644
--- a/toolchains/jdk_build_file.bzl
+++ b/toolchains/jdk_build_file.bzl
@@ -83,6 +83,35 @@ java_runtime(
         ":jdk-lib",
         ":jre",
     ],
+    # Provide the 'java` binary explicitly so that the correct path is used by
+    # Bazel even when the host platform differs from the execution platform.
+    # Exactly one of the two globs will be empty depending on the host platform.
+    # When --incompatible_disallow_empty_glob is enabled, each individual empty
+    # glob will fail without allow_empty = True, even if the overall result is
+    # non-empty.
+    java = glob(["bin/java.exe", "bin/java"], allow_empty = True)[0],
+    version = {RUNTIME_VERSION},
+)
+
+filegroup(
+    name = "jdk-jmods",
+    srcs = glob(
+        ["jmods/**"],
+        allow_empty = True,
+    ),
+)
+
+java_runtime(
+    name = "jdk-with-jmods",
+    srcs = [
+        ":jdk-bin",
+        ":jdk-conf",
+        ":jdk-include",
+        ":jdk-lib",
+        ":jdk-jmods",
+        ":jre",
+    ],
+    java = glob(["bin/java.exe", "bin/java"], allow_empty = True)[0],
     version = {RUNTIME_VERSION},
 )
 """
diff --git a/toolchains/local_java_repository.bzl b/toolchains/local_java_repository.bzl
index ab25f0d..3f28baa 100644
--- a/toolchains/local_java_repository.bzl
+++ b/toolchains/local_java_repository.bzl
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""Rules for importing and registering a local JDK."""
+"""Rules for importing a local JDK."""
 
 load("//java:defs.bzl", "java_runtime")
 load(":default_java_toolchain.bzl", "default_java_toolchain")
@@ -57,9 +57,13 @@ def local_java_runtime(name, java_home, version, runtime_name = None, visibility
       runtime_name: name of java_runtime target if it already exists.
       visibility: Visibility that will be applied to the java runtime target
       exec_compatible_with: A list of constraint values that must be
-                            satisfied for the exec platform.
+                            satisfied by the exec platform for the Java compile
+                            toolchain to be selected. They must be satisfied by
+                            the target platform for the Java runtime toolchain
+                            to be selected.
       target_compatible_with: A list of constraint values that must be
-                              satisfied for the target platform.
+                              satisfied by the target platform for the Java
+                              compile toolchain to be selected.
     """
 
     if runtime_name == None:
@@ -97,10 +101,18 @@ def local_java_runtime(name, java_home, version, runtime_name = None, visibility
     )
     native.toolchain(
         name = "runtime_toolchain_definition",
+        # A JDK can be used as a runtime *for* the platforms it can be used to compile *on*.
+        target_compatible_with = exec_compatible_with,
         target_settings = [":%s_settings_alias" % name],
         toolchain_type = Label("@bazel_tools//tools/jdk:runtime_toolchain_type"),
         toolchain = runtime_name,
     )
+    native.toolchain(
+        name = "bootstrap_runtime_toolchain_definition",
+        target_settings = [":%s_settings_alias" % name],
+        toolchain_type = Label("@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type"),
+        toolchain = runtime_name,
+    )
 
     if type(version) == type("") and version.isdigit() and int(version) > 8:
         for version in range(8, int(version) + 1):
@@ -179,19 +191,28 @@ def _local_java_repository_impl(repository_ctx):
 
     if not java_bin.exists:
         # Java binary does not exist
-        repository_ctx.file(
-            "BUILD.bazel",
-            _NOJDK_BUILD_TPL.format(
-                local_jdk = local_java_runtime_name,
-                java_binary = _with_os_extension(repository_ctx, "bin/java"),
-                java_home = java_home,
-            ),
-            False,
+        _create_auto_config_error_build_file(
+            repository_ctx,
+            local_java_runtime_name = local_java_runtime_name,
+            java_home = java_home,
+            message = "Cannot find Java binary {java_binary} in {java_home}; " +
+                      "either correct your JAVA_HOME, PATH or specify Java from " +
+                      "remote repository (e.g. --java_runtime_version=remotejdk_11)",
         )
         return
 
     # Detect version
     version = repository_ctx.attr.version if repository_ctx.attr.version != "" else _detect_java_version(repository_ctx, java_bin)
+    if version == None:
+        # Java version could not be detected
+        _create_auto_config_error_build_file(
+            repository_ctx,
+            local_java_runtime_name = local_java_runtime_name,
+            java_home = java_home,
+            message = "Cannot detect Java version of {java_binary} in {java_home}; " +
+                      "make sure it points to a valid Java executable",
+        )
+        return
 
     # Prepare BUILD file using "local_java_runtime" macro
     if repository_ctx.attr.build_file_content and repository_ctx.attr.build_file:
@@ -211,12 +232,14 @@ local_java_runtime(
     runtime_name = %s,
     java_home = "%s",
     version = "%s",
+    exec_compatible_with = HOST_CONSTRAINTS,
 )
 """ % (local_java_runtime_name, runtime_name, java_home, version)
 
     repository_ctx.file(
         "BUILD.bazel",
         'load("@rules_java//toolchains:local_java_repository.bzl", "local_java_runtime")\n' +
+        'load("@local_config_platform//:constraints.bzl", "HOST_CONSTRAINTS")\n' +
         build_file +
         local_java_runtime_macro,
     )
@@ -225,14 +248,12 @@ local_java_runtime(
     for file in repository_ctx.path(java_home).readdir():
         repository_ctx.symlink(file, file.basename)
 
-# Build file template, when JDK does not exist
-_NOJDK_BUILD_TPL = '''load("@rules_java//toolchains:fail_rule.bzl", "fail_rule")
+# Build file template, when JDK could not be detected
+_AUTO_CONFIG_ERROR_BUILD_TPL = '''load("@rules_java//toolchains:fail_rule.bzl", "fail_rule")
 fail_rule(
    name = "jdk",
    header = "Auto-Configuration Error:",
-   message = ("Cannot find Java binary {java_binary} in {java_home}; either correct your JAVA_HOME, " +
-          "PATH or specify Java from remote repository (e.g. " +
-          "--java_runtime_version=remotejdk_11)")
+   message = {message},
 )
 config_setting(
    name = "localjdk_setting",
@@ -245,8 +266,27 @@ toolchain(
    toolchain_type = "@bazel_tools//tools/jdk:runtime_toolchain_type",
    toolchain = ":jdk",
 )
+toolchain(
+   name = "bootstrap_runtime_toolchain_definition",
+   target_settings = [":localjdk_setting"],
+   toolchain_type = "@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type",
+   toolchain = ":jdk",
+)
 '''
 
+def _create_auto_config_error_build_file(repository_ctx, *, local_java_runtime_name, java_home, message):
+    repository_ctx.file(
+        "BUILD.bazel",
+        _AUTO_CONFIG_ERROR_BUILD_TPL.format(
+            local_jdk = local_java_runtime_name,
+            message = repr(message.format(
+                java_binary = _with_os_extension(repository_ctx, "bin/java"),
+                java_home = java_home,
+            )),
+        ),
+        False,
+    )
+
 _local_java_repository_rule = repository_rule(
     implementation = _local_java_repository_impl,
     local = True,
@@ -261,7 +301,19 @@ _local_java_repository_rule = repository_rule(
 )
 
 def local_java_repository(name, java_home = "", version = "", build_file = None, build_file_content = None, **kwargs):
-    """Registers a runtime toolchain for local JDK and creates an unregistered compile toolchain.
+    """Defines runtime and compile toolchains for a local JDK.
+
+    Register the toolchains defined by this macro as follows (where `<name>` is the value of the
+    `name` parameter):
+    * Runtime toolchains only (recommended)
+      ```
+      register_toolchains("@<name>//:runtime_toolchain_definition")
+      register_toolchains("@<name>//:bootstrap_runtime_toolchain_definition")
+      ```
+    * Runtime and compilation toolchains:
+      ```
+      register_toolchains("@<name>//:all")
+      ```
 
     Toolchain resolution is constrained with --java_runtime_version flag
     having value of the "name" or "version" parameter.
diff --git a/toolchains/remote_java_repository.bzl b/toolchains/remote_java_repository.bzl
index cbd8b13..65bbe48 100644
--- a/toolchains/remote_java_repository.bzl
+++ b/toolchains/remote_java_repository.bzl
@@ -12,9 +12,9 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""Rules for importing and registering JDKs from http archive.
+"""Rules for importing JDKs from http archive.
 
-Rule remote_java_repository imports and registers JDK with the toolchain resolution.
+Rule remote_java_repository imports a JDK and creates toolchain definitions for it.
 """
 
 load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
@@ -33,7 +33,10 @@ _toolchain_config = repository_rule(
 )
 
 def remote_java_repository(name, version, target_compatible_with = None, prefix = "remotejdk", **kwargs):
-    """Imports and registers a JDK from a http archive.
+    """Imports a JDK from a http archive and creates runtime toolchain definitions for it.
+
+    Register the toolchains defined by this macro via `register_toolchains("@<name>//:all")`, where
+    `<name>` is the value of the `name` parameter.
 
     Toolchain resolution is determined with target_compatible_with
     parameter and constrained with --java_runtime_version flag either having value
@@ -79,6 +82,16 @@ toolchain(
     toolchain_type = "@bazel_tools//tools/jdk:runtime_toolchain_type",
     toolchain = "{toolchain}",
 )
+toolchain(
+    name = "bootstrap_runtime_toolchain",
+    # These constraints are not required for correctness, but prevent fetches of remote JDK for
+    # different architectures. As every Java compilation toolchain depends on a bootstrap runtime in
+    # the same configuration, this constraint will not result in toolchain resolution failures.
+    exec_compatible_with = {target_compatible_with},
+    target_settings = [":version_or_prefix_version_setting"],
+    toolchain_type = "@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type",
+    toolchain = "{toolchain}",
+)
 """.format(
             prefix = prefix,
             version = version,
diff --git a/toolchains/toolchain_utils.bzl b/toolchains/toolchain_utils.bzl
index 7177092..8a33293 100644
--- a/toolchains/toolchain_utils.bzl
+++ b/toolchains/toolchain_utils.bzl
@@ -19,6 +19,8 @@ Returns the toolchain if enabled, and falls back to a toolchain constructed from
 legacy toolchain selection.
 """
 
+load("//java/common:java_common.bzl", "java_common")
+
 def find_java_toolchain(ctx, target):
     """
     Finds the Java toolchain.
```

