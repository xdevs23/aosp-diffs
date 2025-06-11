```diff
diff --git a/.bazelci/presubmit.yml b/.bazelci/presubmit.yml
index f66eb71..d61be6c 100644
--- a/.bazelci/presubmit.yml
+++ b/.bazelci/presubmit.yml
@@ -2,50 +2,136 @@
 build_targets: &build_targets
   - "//..."
   - "@remote_java_tools//java_tools/..."
-  # TODO: Look into broken targets in //toolchains
+  # can't build @remote_java_tools_X repos for other platforms
   - "-//toolchains/..."
+  # TODO: re-enable docs after moving them out of https://bazel.build/reference/be/java
+  - "-//java/docs/..."
+  - "-//test:docs_up_to_date_test"
 
-build_targets_bzlmod: &build_targets_bzlmod
-  - "//..."
+build_targets_bazel6: &build_targets_bazel6
+  - "//:all"
   - "@remote_java_tools//java_tools/..."
-  - "-//toolchains/..."
-  # TODO(pcloudy): pkg_tar doesn't work with Bzlmod due to https://github.com/bazelbuild/bazel/issues/14259
-  # Enable once the issue is fixed.
-  - "-//distro/..."
+  - "//examples/..."
+
+build_targets_integration: &build_targets_integration
+  - "//..."
+  - "//:bin_deploy.jar"
+
+test_targets: &test_targets
+  - "//test/..."
+  - "//java/test/..."
+  # TODO: re-enable docs after moving them out of https://bazel.build/reference/be/java
+  - "-//test:docs_up_to_date_test"
+
+test_targets_bazel6: &test_targets_bazel6
+  - "//java/test/..."
+
+test_target_integration: &test_target_integration
+  - "//:MyTest"
+
+flags_workspace_integration: &flags_workspace_integration
+  - "--noenable_bzlmod"
+  - "--enable_workspace"
 
 buildifier: latest
 
 tasks:
+# TODO: add config for 8.0.0 once released
+# Bazel 7.x
   ubuntu2004:
+    name: "Bazel 7.x"
+    bazel: "7.4.0"
     build_targets: *build_targets
+    test_targets: *test_targets
+  ubuntu2004_integration:
+    name: "Bazel 7.x Integration"
+    bazel: "7.4.0"
+    platform: ubuntu2004
+    working_directory: "test/repo"
+    shell_commands:
+      - sh setup.sh
+    build_targets: *build_targets_integration
+    test_targets: *test_target_integration
+  ubuntu2004_integration_workspace:
+    name: "Bazel 7.x Integration (WORKSPACE)"
+    bazel: "7.4.0"
+    platform: ubuntu2004
+    working_directory: "test/repo"
+    shell_commands:
+      - sh setup.sh
+    build_targets: *build_targets_integration
+    build_flags: *flags_workspace_integration
+    test_targets: *test_target_integration
+    test_flags: *flags_workspace_integration
   macos:
+    name: "Bazel 7.x"
+    bazel: "7.4.0"
     build_targets: *build_targets
   windows:
+    name: "Bazel 7.x"
+    bazel: "7.4.0"
     build_targets: *build_targets
+# Bazel@HEAD
   ubuntu2004_head:
+    name: "Bazel@HEAD"
     bazel: last_green
     platform: ubuntu2004
     build_targets: *build_targets
+    test_targets: *test_targets
+  ubuntu2004_integration_head:
+    name: "Bazel@HEAD Integration"
+    bazel: last_green
+    platform: ubuntu2004
+    working_directory: "test/repo"
+    shell_commands:
+      - sh setup.sh
+    build_targets: *build_targets_integration
+    test_targets: *test_target_integration
+  ubuntu2004_integration_head_workspace:
+    name: "Bazel@HEAD Integration (WORKSPACE)"
+    bazel: "last_green"
+    platform: ubuntu2004
+    working_directory: "test/repo"
+    shell_commands:
+      - sh setup.sh
+    build_targets: *build_targets_integration
+    build_flags: *flags_workspace_integration
+    test_targets: *test_target_integration
+    test_flags: *flags_workspace_integration
   macos_head:
+    name: "Bazel@HEAD"
     bazel: last_green
     platform: macos
     build_targets: *build_targets
   windows_head:
+    name: "Bazel@HEAD"
     bazel: last_green
     platform: windows
     build_targets: *build_targets
-  ubuntu2004_bzlmod:
+
+# Bazel 6.x
+  ubuntu2004_bazel6:
+    name: "Bazel 6.x"
+    bazel: 6.4.0
+    platform: ubuntu2004
+    build_targets: *build_targets_bazel6
+    test_targets: *test_targets_bazel6
+  ubuntu2004_integration_bazel6:
+    name: "Bazel 6.x Integration"
+    bazel: 6.4.0
     platform: ubuntu2004
-    build_flags:
-      - "--config=bzlmod"
-    build_targets: *build_targets_bzlmod
-  macos_bzlmod:
+    working_directory: "test/repo"
+    shell_commands:
+    - sh setup.sh
+    build_targets: *build_targets_integration
+    test_targets: *test_target_integration
+  macos_bazel6:
+    name: "Bazel 6.x"
+    bazel: 6.4.0
     platform: macos
-    build_flags:
-      - "--config=bzlmod"
-    build_targets: *build_targets_bzlmod
-  windows_bzlmod:
+    build_targets: *build_targets_bazel6
+  windows_bazel6:
+    name: "Bazel 6.x"
+    bazel: 6.4.0
     platform: windows
-    build_flags:
-      - "--config=bzlmod"
-    build_targets: *build_targets_bzlmod
\ No newline at end of file
+    build_targets: *build_targets_bazel6
diff --git a/.bazelignore b/.bazelignore
new file mode 100644
index 0000000..457eb2a
--- /dev/null
+++ b/.bazelignore
@@ -0,0 +1 @@
+test/repo
diff --git a/.bazelrc b/.bazelrc
index 5d84eb8..526b36d 100644
--- a/.bazelrc
+++ b/.bazelrc
@@ -1,3 +1,10 @@
-build:bzlmod --experimental_enable_bzlmod
+common --incompatible_disallow_empty_glob
 
-common --incompatible_disallow_empty_glob
\ No newline at end of file
+# Use hermetic JDKs for testing and ensure compatibliity with Java 8.
+common --java_language_version=8
+common --java_runtime_version=remotejdk_8
+common --tool_java_language_version=8
+common --tool_java_runtime_version=remotejdk_8
+
+# Hide Java 8 deprecation warnings.
+common --javacopt=-Xlint:-options
diff --git a/.bazelversion b/.bazelversion
deleted file mode 100644
index 66ce77b..0000000
--- a/.bazelversion
+++ /dev/null
@@ -1 +0,0 @@
-7.0.0
diff --git a/.gitignore b/.gitignore
index ef43625..86e15ab 100644
--- a/.gitignore
+++ b/.gitignore
@@ -17,3 +17,5 @@
 # Ignore jekyll build output.
 /production
 /.sass-cache
+# Ignore MODULE.bazel.lock as this is a library project.
+MODULE.bazel.lock
diff --git a/METADATA b/METADATA
index e54ab2a..62c9db3 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/bazelbuild-rules_java
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "rules_java"
 description: "Bazel rules for building java code"
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 5
+    month: 12
+    day: 6
   }
   identifier {
     type: "Git"
     value: "https://github.com/bazelbuild/rules_java"
-    version: "7.6.1"
+    version: "8.6.2"
   }
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index 1be58b8..0476b99 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,19 +1,19 @@
 module(
     name = "rules_java",
-    version = "7.6.1",
-    # Requires @bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type.
-    bazel_compatibility = [">=7.0.0"],
+    version = "8.6.2",
+    bazel_compatibility = [">=6.4.0"],
     compatibility_level = 1,
 )
 
 bazel_dep(name = "platforms", version = "0.0.4")
-bazel_dep(name = "rules_cc", version = "0.0.2")
+bazel_dep(name = "rules_cc", version = "0.0.15")
 bazel_dep(name = "bazel_features", version = "1.11.0")
 bazel_dep(name = "bazel_skylib", version = "1.6.1")
+bazel_dep(name = "protobuf", version = "27.0", repo_name = "com_google_protobuf")
 
 # Required by @remote_java_tools, which is loaded via module extension.
-bazel_dep(name = "rules_proto", version = "4.0.0")
 bazel_dep(name = "rules_license", version = "0.0.3")
+bazel_dep(name = "abseil-cpp", version = "20230802.1", repo_name = "com_google_absl")
 
 register_toolchains("//toolchains:all")
 
@@ -89,11 +89,15 @@ REMOTE_JDK_REPOS = [(("remote_jdk" if version == "8" else "remotejdk") + version
 
 [register_toolchains("@" + name + "_toolchain_config_repo//:all") for name in REMOTE_JDK_REPOS]
 
+# Compatibility layer
+compat = use_extension("//java:rules_java_deps.bzl", "compatibility_proxy")
+use_repo(compat, "compatibility_proxy")
+
 # Dev dependencies
 bazel_dep(name = "rules_pkg", version = "0.9.1", dev_dependency = True)
+bazel_dep(name = "stardoc", version = "0.7.1", dev_dependency = True)
+bazel_dep(name = "rules_shell", version = "0.2.0", dev_dependency = True)
+bazel_dep(name = "rules_testing", version = "0.7.0", dev_dependency = True)
 
-# Override rules_python version to deal with #161 and https://github.com/bazelbuild/bazel/issues/20458
-single_version_override(
-    module_name = "rules_python",
-    version = "0.24.0",
-)
+test_repositories = use_extension("//test:repositories.bzl", "test_repositories_ext", dev_dependency = True)
+use_repo(test_repositories, "guava", "truth")
diff --git a/OWNERS b/OWNERS
index d856ca7..8509568 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 include platform/build/bazel:/OWNERS
 include kernel/build:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 8c946de..e4cfeb0 100644
--- a/README.md
+++ b/README.md
@@ -4,3 +4,22 @@
 * Postsubmit + Current Bazel Incompatible Flags [![Build status](https://badge.buildkite.com/ef265d270238c02aff65106a0b861abb9265efacdf4af399c3.svg?branch=master)](https://buildkite.com/bazel/rules-java-plus-bazelisk-migrate)
 
 Java Rules for Bazel https://bazel.build.
+
+**Documentation**
+
+For a quickstart tutorial, see https://bazel.build/start/java
+
+For slightly more advanced usage, like setting up toolchains
+or writing your own java-like rules,
+see https://bazel.build/docs/bazel-and-java
+
+
+***Core Java rules***
+
+Add a load like:
+```build
+load("@rules_java//java:java_library.bzl", "java_library")
+```
+to your `BUILD` / `BUILD.bazel` / bzl` files
+
+For detailed docs on the core rules, see https://bazel.build/reference/be/java
diff --git a/WORKSPACE b/WORKSPACE
index 6e4b3c0..161fa9c 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -4,10 +4,10 @@ load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 
 http_archive(
     name = "bazel_skylib",
-    sha256 = "9f38886a40548c6e96c106b752f242130ee11aaa068a56ba7e56f4511f33e4f2",
+    sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.6.1/bazel-skylib-1.6.1.tar.gz",
-        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.6.1/bazel-skylib-1.6.1.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
+        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
     ],
 )
 
@@ -27,3 +27,39 @@ http_archive(
 load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
 
 rules_pkg_dependencies()
+
+http_archive(
+    name = "stardoc",
+    sha256 = "62bd2e60216b7a6fec3ac79341aa201e0956477e7c8f6ccc286f279ad1d96432",
+    urls = [
+        "https://mirror.bazel.build/github.com/bazelbuild/stardoc/releases/download/0.6.2/stardoc-0.6.2.tar.gz",
+        "https://github.com/bazelbuild/stardoc/releases/download/0.6.2/stardoc-0.6.2.tar.gz",
+    ],
+)
+
+load("//java:rules_java_deps.bzl", "rules_java_dependencies")
+
+rules_java_dependencies()
+
+load("@com_google_protobuf//bazel/private:proto_bazel_features.bzl", "proto_bazel_features")  # buildifier: disable=bzl-visibility
+
+proto_bazel_features(name = "proto_bazel_features")
+
+load("//java:repositories.bzl", "rules_java_toolchains")
+
+rules_java_toolchains()
+
+load("@stardoc//:setup.bzl", "stardoc_repositories")
+
+stardoc_repositories()
+
+http_archive(
+    name = "rules_testing",
+    sha256 = "28c2d174471b587bf0df1fd3a10313f22c8906caf4050f8b46ec4648a79f90c3",
+    strip_prefix = "rules_testing-0.7.0",
+    url = "https://github.com/bazelbuild/rules_testing/releases/download/v0.7.0/rules_testing-v0.7.0.tar.gz",
+)
+
+load("//test:repositories.bzl", "test_repositories")
+
+test_repositories()
diff --git a/distro/BUILD.bazel b/distro/BUILD.bazel
index 0fa843f..d8722d4 100644
--- a/distro/BUILD.bazel
+++ b/distro/BUILD.bazel
@@ -1,5 +1,5 @@
 load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
-load("@rules_pkg//pkg/releasing:defs.bzl", "print_rel_notes")
+load(":relnotes.bzl", "print_rel_notes")
 
 package(default_visibility = ["//visibility:private"])
 
@@ -18,10 +18,6 @@ pkg_tar(
 
 print_rel_notes(
     name = "relnotes",
-    outs = ["relnotes.txt"],
-    deps_method = "rules_java_dependencies",
-    repo = "rules_java",
-    setup_file = "java:repositories.bzl",
-    toolchains_method = "rules_java_toolchains",
+    archive = ":rules_java-%s" % module_version(),
     version = module_version(),
 )
diff --git a/distro/relnotes.bzl b/distro/relnotes.bzl
new file mode 100644
index 0000000..ba12883
--- /dev/null
+++ b/distro/relnotes.bzl
@@ -0,0 +1,51 @@
+"""Release notes generator"""
+
+def print_rel_notes(*, name, version, archive):
+    native.genrule(
+        name = name,
+        outs = [name + ".txt"],
+        cmd = """
+              last_rel=$$(curl -s https://api.github.com/repos/bazelbuild/rules_java/releases/latest  | grep 'tag_name' | cut -d: -f2 | tr -cd '[:alnum:].')
+              changelog=$$(/usr/bin/git log tags/$$last_rel..origin/master --format=oneline --)
+              sha=$$(/usr/bin/sha256sum $(SRCS) | cut -d ' '  -f1)
+              cat > $@ <<EOF
+**Changes since $$last_rel**
+$$changelog
+
+**MODULE.bazel setup**
+~~~
+bazel_dep(name = "rules_java", version = "{VERSION}")
+~~~
+
+**WORKSPACE setup**
+~~~
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+http_archive(
+    name = "rules_java",
+    urls = [
+        "https://github.com/bazelbuild/rules_java/releases/download/{VERSION}/rules_java-{VERSION}.tar.gz",
+    ],
+    sha256 = "$$sha",
+)
+
+load("@rules_java//java:rules_java_deps.bzl", "rules_java_dependencies")
+rules_java_dependencies()
+
+# note that the following line is what is minimally required from protobuf for the java rules
+# consider using the protobuf_deps() public API from @com_google_protobuf//:protobuf_deps.bzl
+load("@com_google_protobuf//bazel/private:proto_bazel_features.bzl", "proto_bazel_features")  # buildifier: disable=bzl-visibility
+proto_bazel_features(name = "proto_bazel_features")
+
+# register toolchains
+load("@rules_java//java:repositories.bzl", "rules_java_toolchains")
+rules_java_toolchains()
+~~~
+
+**Using the rules**
+See [the source](https://github.com/bazelbuild/rules_java/tree/{VERSION}).
+
+EOF
+              """.format(ARCHIVE = archive, VERSION = version),
+        srcs = [archive],
+        tags = ["local", "manual"],
+    )
diff --git a/java/BUILD b/java/BUILD
index 8b7465e..a436327 100644
--- a/java/BUILD
+++ b/java/BUILD
@@ -7,9 +7,13 @@ licenses(["notice"])
 filegroup(
     name = "srcs",
     srcs = glob(["**"]) + [
+        "//java/bazel:srcs",
+        "//java/bazel/common:srcs",
+        "//java/bazel/rules:srcs",
         "//java/common:srcs",
         "//java/private:srcs",
         "//java/proto:srcs",
+        "//java/runfiles:srcs",
         "//java/toolchains:srcs",
     ],
     visibility = ["//:__pkg__"],
@@ -23,6 +27,8 @@ bzl_library(
         ":core_rules",
         "//java/common",
         "//java/toolchains:toolchain_rules",
+        "@com_google_protobuf//bazel:java_lite_proto_library_bzl",
+        "@com_google_protobuf//bazel:java_proto_library_bzl",
     ],
 )
 
@@ -38,8 +44,11 @@ bzl_library(
     ],
     visibility = ["//visibility:public"],
     deps = [
+        "//java/bazel/common",  # copybara-use-repo-external-label
+        "//java/bazel/rules",  # copybara-use-repo-external-label
         "//java/common",
-        "//java/private",
+        "//java/common/rules:core_rules",
+        "//java/private:native_bzl",
     ],
 )
 
@@ -56,6 +65,13 @@ bzl_library(
     deps = ["//java/common"],
 )
 
+bzl_library(
+    name = "http_jar_bzl",
+    srcs = ["http_jar.bzl"],
+    visibility = ["//visibility:public"],
+    deps = ["@compatibility_proxy//:proxy_bzl"],
+)
+
 filegroup(
     name = "for_bazel_tests",
     testonly = 1,
@@ -64,8 +80,12 @@ filegroup(
         ":core_rules",
         ":java_single_jar",
         ":rules",
+        "//java/bazel:for_bazel_tests",  # copybara-use-repo-external-label
+        "//java/bazel/rules:for_bazel_tests",  # copybara-use-repo-external-label
         "//java/common:for_bazel_tests",
         "//java/private:for_bazel_tests",
+        "//java/toolchains:for_bazel_tests",
+        "@bazel_skylib//lib:test_deps",
     ],
     visibility = ["//visibility:public"],
 )
diff --git a/java/bazel/BUILD.bazel b/java/bazel/BUILD.bazel
new file mode 100644
index 0000000..2c26d11
--- /dev/null
+++ b/java/bazel/BUILD.bazel
@@ -0,0 +1,76 @@
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
+load(":repositories_util.bzl", "FLAT_CONFIGS")
+
+# build this to generate _REMOTE_JDK_CONFIGS_LIST in repositories.bzl
+# this downloads all the jdks and computes their sha256 sum, so can take a while
+# TODO(hvd): make this a sh_binary to update the configs in place
+genrule(
+    name = "dump_remote_jdk_configs",
+    outs = ["remote_jdks_config.out"],
+    cmd = """
+echo > $@
+while read -r config; do
+    TMP_FILE=$$(mktemp -q /tmp/remotejdk.XXXXXX)
+    IFS=\\| read -r name version urls strip_prefix target_compatible_with primary_url <<< "$$config"
+    echo "fetching: $$primary_url to $$TMP_FILE" > /dev/stderr
+    curl --silent -o $$TMP_FILE -L "$$primary_url" > /dev/stderr
+    sha256=`sha256sum $$TMP_FILE | cut -d' ' -f1`
+    echo "struct("
+    echo "  name = \\"$$name\\","
+    echo "  target_compatible_with = $$target_compatible_with,"
+    echo "  sha256 = \\"$$sha256\\","
+    echo "  strip_prefix = \\"$$strip_prefix\\","
+    echo "  urls = $$urls,"
+    echo "  version = \\"$$version\\","
+    echo "),"
+done <<< '{configs}' >> $@
+    """.format(configs = "\n".join([
+        "|".join([
+            config.name,
+            config.version,
+            json.encode(config.urls),
+            config.strip_prefix,
+            json.encode(config.target_compatible_with),
+            config.urls[0],
+        ])
+        for config in FLAT_CONFIGS
+    ])),
+    tags = [
+        "local",
+        "manual",
+    ],
+    visibility = ["//visibility:private"],
+)
+
+bzl_library(
+    name = "http_jar_bzl",
+    srcs = ["http_jar.bzl"],
+    visibility = ["@compatibility_proxy//:__pkg__"],
+    deps = ["@bazel_tools//tools:bzl_srcs"],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    visibility = ["//java:__pkg__"],
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/bazel/common/BUILD.bazel b/java/bazel/common/BUILD.bazel
new file mode 100644
index 0000000..dd3bc06
--- /dev/null
+++ b/java/bazel/common/BUILD.bazel
@@ -0,0 +1,13 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+bzl_library(
+    name = "common",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//java:__pkg__"],
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/bazel/common/empty.bzl b/java/bazel/common/empty.bzl
new file mode 100644
index 0000000..c40e750
--- /dev/null
+++ b/java/bazel/common/empty.bzl
@@ -0,0 +1 @@
+"""Placeholder for glob"""
diff --git a/java/bazel/http_jar.bzl b/java/bazel/http_jar.bzl
new file mode 100644
index 0000000..6ba729c
--- /dev/null
+++ b/java/bazel/http_jar.bzl
@@ -0,0 +1,178 @@
+"""The http_jar repo rule, for downloading jars over HTTP."""
+
+load("@bazel_tools//tools/build_defs/repo:cache.bzl", "CANONICAL_ID_DOC", "DEFAULT_CANONICAL_ID_ENV", "get_default_canonical_id")
+load("@bazel_tools//tools/build_defs/repo:utils.bzl", "get_auth", "update_attrs")
+
+_URL_DOC = """A URL to the jar that will be made available to Bazel.
+
+This must be a file, http or https URL. Redirections are followed.
+Authentication is not supported.
+
+More flexibility can be achieved by the urls parameter that allows
+to specify alternative URLs to fetch from."""
+
+_URLS_DOC = """A list of URLs to the jar that will be made available to Bazel.
+
+Each entry must be a file, http or https URL. Redirections are followed.
+Authentication is not supported.
+
+URLs are tried in order until one succeeds, so you should list local mirrors first.
+If all downloads fail, the rule will fail."""
+
+_AUTH_PATTERN_DOC = """An optional dict mapping host names to custom authorization patterns.
+
+If a URL's host name is present in this dict the value will be used as a pattern when
+generating the authorization header for the http request. This enables the use of custom
+authorization schemes used in a lot of common cloud storage providers.
+
+The pattern currently supports 2 tokens: <code>&lt;login&gt;</code> and
+<code>&lt;password&gt;</code>, which are replaced with their equivalent value
+in the netrc file for the same host name. After formatting, the result is set
+as the value for the <code>Authorization</code> field of the HTTP request.
+
+Example attribute and netrc for a http download to an oauth2 enabled API using a bearer token:
+
+<pre>
+auth_patterns = {
+    "storage.cloudprovider.com": "Bearer &lt;password&gt;"
+}
+</pre>
+
+netrc:
+
+<pre>
+machine storage.cloudprovider.com
+        password RANDOM-TOKEN
+</pre>
+
+The final HTTP request would have the following header:
+
+<pre>
+Authorization: Bearer RANDOM-TOKEN
+</pre>
+"""
+
+def _get_source_urls(ctx):
+    """Returns source urls provided via the url, urls attributes.
+
+    Also checks that at least one url is provided."""
+    if not ctx.attr.url and not ctx.attr.urls:
+        fail("At least one of url and urls must be provided")
+
+    source_urls = []
+    if ctx.attr.urls:
+        source_urls = ctx.attr.urls
+    if ctx.attr.url:
+        source_urls = [ctx.attr.url] + source_urls
+    return source_urls
+
+def _update_integrity_attr(ctx, attrs, download_info):
+    # We don't need to override the integrity attribute if sha256 is already specified.
+    integrity_override = {} if ctx.attr.sha256 else {"integrity": download_info.integrity}
+    return update_attrs(ctx.attr, attrs.keys(), integrity_override)
+
+_HTTP_JAR_BUILD = """\
+load("{java_import_bzl}", "java_import")
+
+java_import(
+  name = 'jar',
+  jars = ["{file_name}"],
+  visibility = ['//visibility:public'],
+)
+
+filegroup(
+  name = 'file',
+  srcs = ["{file_name}"],
+  visibility = ['//visibility:public'],
+)
+
+"""
+
+def _http_jar_impl(ctx):
+    """Implementation of the http_jar rule."""
+    source_urls = _get_source_urls(ctx)
+    downloaded_file_name = ctx.attr.downloaded_file_name
+    download_info = ctx.download(
+        source_urls,
+        "jar/" + downloaded_file_name,
+        ctx.attr.sha256,
+        canonical_id = ctx.attr.canonical_id or get_default_canonical_id(ctx, source_urls),
+        auth = get_auth(ctx, source_urls),
+        integrity = ctx.attr.integrity,
+    )
+    ctx.file("jar/BUILD", _HTTP_JAR_BUILD.format(
+        java_import_bzl = str(Label("//java:java_import.bzl")),
+        file_name = downloaded_file_name,
+    ))
+
+    return _update_integrity_attr(ctx, _http_jar_attrs, download_info)
+
+_http_jar_attrs = {
+    "sha256": attr.string(
+        doc = """The expected SHA-256 of the jar downloaded.
+
+This must match the SHA-256 of the jar downloaded. _It is a security risk
+to omit the SHA-256 as remote files can change._ At best omitting this
+field will make your build non-hermetic. It is optional to make development
+easier but either this attribute or `integrity` should be set before shipping.""",
+    ),
+    "integrity": attr.string(
+        doc = """Expected checksum in Subresource Integrity format of the jar downloaded.
+
+This must match the checksum of the file downloaded. _It is a security risk
+to omit the checksum as remote files can change._ At best omitting this
+field will make your build non-hermetic. It is optional to make development
+easier but either this attribute or `sha256` should be set before shipping.""",
+    ),
+    "canonical_id": attr.string(
+        doc = CANONICAL_ID_DOC,
+    ),
+    "url": attr.string(doc = _URL_DOC + "\n\nThe URL must end in `.jar`."),
+    "urls": attr.string_list(doc = _URLS_DOC + "\n\nAll URLs must end in `.jar`."),
+    "netrc": attr.string(
+        doc = "Location of the .netrc file to use for authentication",
+    ),
+    "auth_patterns": attr.string_dict(
+        doc = _AUTH_PATTERN_DOC,
+    ),
+    "downloaded_file_name": attr.string(
+        default = "downloaded.jar",
+        doc = "Filename assigned to the jar downloaded",
+    ),
+}
+
+http_jar = repository_rule(
+    implementation = _http_jar_impl,
+    attrs = _http_jar_attrs,
+    environ = [DEFAULT_CANONICAL_ID_ENV],
+    doc =
+        """Downloads a jar from a URL and makes it available as java_import
+
+Downloaded files must have a .jar extension.
+
+Examples:
+  Suppose the current repository contains the source code for a chat program, rooted at the
+  directory `~/chat-app`. It needs to depend on an SSL library which is available from
+  `http://example.com/openssl-0.2.jar`.
+
+  Targets in the `~/chat-app` repository can depend on this target if the following lines are
+  added to `~/chat-app/MODULE.bazel`:
+
+  ```python
+  http_jar = use_repo_rule("@rules_java//java:http_jar.bzl", "http_jar")
+
+  http_jar(
+      name = "my_ssl",
+      url = "http://example.com/openssl-0.2.jar",
+      sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
+  )
+  ```
+
+  Targets would specify `@my_ssl//jar` as a dependency to depend on this jar.
+
+  You may also reference files on the current system (localhost) by using "file:///path/to/file"
+  if you are on Unix-based systems. If you're on Windows, use "file:///c:/path/to/file". In both
+  examples, note the three slashes (`/`) -- the first two slashes belong to `file://` and the third
+  one belongs to the absolute path to the file.
+""",
+)
diff --git a/java/bazel/repositories_util.bzl b/java/bazel/repositories_util.bzl
new file mode 100644
index 0000000..7e9efbd
--- /dev/null
+++ b/java/bazel/repositories_util.bzl
@@ -0,0 +1,187 @@
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
+"""Helper functions to register remote jdk repos"""
+
+visibility(["//test"])
+
+_RELEASE_CONFIGS = {
+    "8": {
+        "zulu": {
+            "release": "8.78.0.19-ca-jdk8.0.412",
+            "platforms": {
+                "linux": ["aarch64", "x86_64"],
+                "macos": ["aarch64", "x86_64"],
+                "windows": ["x86_64"],
+            },
+        },
+        "adoptopenjdk": {
+            "release": "8u292-b10",
+            "platforms": {
+                "linux": ["s390x"],
+            },
+        },
+    },
+    "11": {
+        "zulu": {
+            "release": "11.72.19-ca-jdk11.0.23",
+            "platforms": {
+                "linux": ["aarch64", "x86_64"],
+                "macos": ["aarch64", "x86_64"],
+                "windows": ["x86_64"],
+            },
+        },
+        "adoptium": {
+            "release": "11.0.15+10",
+            "platforms": {
+                "linux": ["ppc", "s390x"],
+            },
+        },
+        "microsoft": {
+            "release": "11.0.13.8.1",
+            "platforms": {
+                "windows": ["arm64"],
+            },
+        },
+    },
+    "17": {
+        "zulu": {
+            "release": "17.50.19-ca-jdk17.0.11",
+            "platforms": {
+                "linux": ["aarch64", "x86_64"],
+                "macos": ["aarch64", "x86_64"],
+                "windows": ["arm64", "x86_64"],
+            },
+        },
+        "adoptium": {
+            "release": "17.0.8.1+1",
+            "platforms": {
+                "linux": ["ppc", "s390x"],
+            },
+        },
+    },
+    "21": {
+        "zulu": {
+            "release": "21.36.17-ca-jdk21.0.4",
+            "platforms": {
+                "linux": ["aarch64", "x86_64"],
+                "macos": ["aarch64", "x86_64"],
+                "windows": ["arm64", "x86_64"],
+            },
+        },
+        "adoptium": {
+            "release": "21.0.4+7",
+            "platforms": {
+                "linux": ["ppc", "s390x"],
+            },
+        },
+    },
+}
+
+_STRIP_PREFIX_OVERRIDES = {
+    "remotejdk11_win_arm64": "jdk-11.0.13+8",
+}
+
+def _name_for_remote_jdk(version, os, cpu):
+    prefix = "remote_jdk" if version == "8" else "remotejdk"
+    os_part = "win" if (os == "windows" and version != "8") else os
+    if cpu == "x86_64":
+        suffix = ""
+    elif cpu == "ppc":
+        suffix = "_ppc64le"
+    else:
+        suffix = "_" + cpu
+    return prefix + version + "_" + os_part + suffix
+
+def _zulu_remote_jdk_repo(os, cpu, release):
+    arch = cpu
+    if cpu == "x86_64":
+        arch = "x64"
+    platform = os
+    ext = ".tar.gz"
+    if os == "macos":
+        platform = "macosx"
+    elif os == "windows":
+        ext = ".zip"
+        platform = "win"
+        arch = "aarch64" if arch == "arm64" else arch
+    archive_name = "zulu" + release + "-" + platform + "_" + arch
+    primary_url = "cdn.azul.com/zulu/bin/" + archive_name + ext
+    urls = [
+        "https://" + primary_url,
+        "https://mirror.bazel.build/" + primary_url,
+    ]
+    return urls, archive_name
+
+def _adoptium_linux_remote_jdk_repo(version, cpu, release):
+    os = "linux"
+    arch = cpu
+    if cpu == "ppc":
+        arch = "ppc64le"
+    archive_name = "OpenJDK" + version + "U-jdk_" + arch + "_" + os + "_hotspot_" + release.replace("+", "_") + ".tar.gz"
+    primary_url = "github.com/adoptium/temurin" + version + "-binaries/releases/download/jdk-" + release + "/" + archive_name
+    urls = [
+        "https://" + primary_url,
+        "https://mirror.bazel.build/" + primary_url,
+    ]
+    return urls, "jdk-" + release
+
+def _microsoft_windows_arm64_remote_jdk_repo(release):
+    primary_url = "aka.ms/download-jdk/microsoft-jdk-" + release + "-windows-aarch64.zip"
+    urls = [
+        "https://" + primary_url,
+        "https://mirror.bazel.build/" + primary_url,
+    ]
+    return urls, ""
+
+def _adoptopenjdk_remote_jdk_repo(version, os, cpu, release):
+    archive = "OpenJDK" + version + "U-jdk_" + cpu + "_" + os + "_hotspot_" + release.replace("-", "") + ".tar.gz"
+    primary_url = "github.com/AdoptOpenJDK/openjdk" + version + "-binaries/releases/download/jdk" + release + "/" + archive
+    urls = [
+        "https://" + primary_url,
+        "https://mirror.bazel.build/" + primary_url,
+    ]
+    return urls, "jdk" + release
+
+def _flatten_configs():
+    result = []
+    for version, all_for_version in _RELEASE_CONFIGS.items():
+        for distrib, distrib_cfg in all_for_version.items():
+            release = distrib_cfg["release"]
+            for os, cpus in distrib_cfg["platforms"].items():
+                for cpu in cpus:
+                    name = _name_for_remote_jdk(version, os, cpu)
+                    if distrib == "zulu":
+                        urls, strip_prefix = _zulu_remote_jdk_repo(os, cpu, release)
+                    elif distrib == "adoptium":
+                        if os != "linux":
+                            fail("adoptium jdk configured but not linux")
+                        urls, strip_prefix = _adoptium_linux_remote_jdk_repo(version, cpu, release)
+                    elif distrib == "microsoft":
+                        if os != "windows" or cpu != "arm64":
+                            fail("only windows_arm64 config for microsoft is expected")
+                        urls, strip_prefix = _microsoft_windows_arm64_remote_jdk_repo(release)
+                    elif distrib == "adoptopenjdk":
+                        urls, strip_prefix = _adoptopenjdk_remote_jdk_repo(version, os, cpu, release)
+                    else:
+                        fail("unexpected distribution:", distrib)
+                    result.append(struct(
+                        name = name,
+                        version = version,
+                        urls = urls,
+                        strip_prefix = _STRIP_PREFIX_OVERRIDES.get(name, strip_prefix),
+                        target_compatible_with = ["@platforms//os:" + os, "@platforms//cpu:" + cpu],
+                    ))
+    return result
+
+FLAT_CONFIGS = _flatten_configs()
diff --git a/java/bazel/rules/BUILD.bazel b/java/bazel/rules/BUILD.bazel
new file mode 100644
index 0000000..0ffa9d4
--- /dev/null
+++ b/java/bazel/rules/BUILD.bazel
@@ -0,0 +1,45 @@
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
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java:__pkg__"],
+)
+
+bzl_library(
+    name = "rules",
+    srcs = glob(["*.bzl"]),
+    visibility = ["//visibility:public"],  # for Bazel docgen
+    deps = [
+        "//java/common:semantics_bzl",
+        "//java/common/rules:core_rules",
+        "//java/common/rules/impl",
+        "//java/private:internals",
+        "@bazel_skylib//lib:paths",
+        "@rules_cc//cc:find_cc_toolchain_bzl",
+        "@rules_cc//cc/common",
+    ],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD.bazel",
+        ":rules",
+    ],
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/bazel/rules/bazel_java_binary.bzl b/java/bazel/rules/bazel_java_binary.bzl
new file mode 100644
index 0000000..06e8421
--- /dev/null
+++ b/java/bazel/rules/bazel_java_binary.bzl
@@ -0,0 +1,456 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Bazel java_binary rule"""
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("@rules_cc//cc:find_cc_toolchain.bzl", "use_cc_toolchain")
+load("//java/common:java_semantics.bzl", "semantics")
+load(
+    "//java/common/rules:android_lint.bzl",
+    "android_lint_subrule",
+)
+load("//java/common/rules:java_binary.bzl", "BASIC_JAVA_BINARY_ATTRIBUTES")
+load("//java/common/rules:rule_util.bzl", "merge_attrs")
+load("//java/common/rules/impl:java_binary_deploy_jar.bzl", "create_deploy_archives")
+load("//java/common/rules/impl:java_binary_impl.bzl", "basic_java_binary")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load("//java/private:java_info.bzl", "JavaInfo")
+
+def _bazel_java_binary_impl(ctx):
+    return bazel_base_binary_impl(ctx, is_test_rule_class = False) + helper.executable_providers(ctx)
+
+def bazel_base_binary_impl(ctx, is_test_rule_class):
+    """Common implementation for binaries and tests
+
+    Args:
+        ctx: (RuleContext)
+        is_test_rule_class: (bool)
+
+    Returns:
+        [Provider]
+    """
+    deps = _collect_all_targets_as_deps(ctx, classpath_type = "compile_only")
+    runtime_deps = _collect_all_targets_as_deps(ctx)
+
+    main_class = _check_and_get_main_class(ctx)
+    coverage_main_class = main_class
+    coverage_config = helper.get_coverage_config(ctx, _get_coverage_runner(ctx))
+    if coverage_config:
+        main_class = coverage_config.main_class
+
+    launcher_info = _get_launcher_info(ctx)
+
+    executable = _get_executable(ctx)
+
+    feature_config = helper.get_feature_config(ctx)
+    if feature_config:
+        strip_as_default = helper.should_strip_as_default(ctx, feature_config)
+    else:
+        # No C++ toolchain available.
+        strip_as_default = False
+
+    providers, default_info, jvm_flags = basic_java_binary(
+        ctx,
+        deps,
+        runtime_deps,
+        ctx.files.resources,
+        main_class,
+        coverage_main_class,
+        coverage_config,
+        launcher_info,
+        executable,
+        strip_as_default,
+        is_test_rule_class = is_test_rule_class,
+    )
+
+    if ctx.attr.use_testrunner:
+        if semantics.find_java_runtime_toolchain(ctx).version >= 17:
+            jvm_flags.append("-Djava.security.manager=allow")
+        test_class = ctx.attr.test_class if hasattr(ctx.attr, "test_class") else ""
+        if test_class == "":
+            test_class = helper.primary_class(ctx)
+        if test_class == None:
+            fail("cannot determine test class. You might want to rename the " +
+                 " rule or add a 'test_class' attribute.")
+        jvm_flags.extend([
+            "-ea",
+            "-Dbazel.test_suite=" + helper.shell_escape(test_class),
+        ])
+
+    java_attrs = providers["InternalDeployJarInfo"].java_attrs
+
+    if executable:
+        _create_stub(ctx, java_attrs, launcher_info.launcher, executable, jvm_flags, main_class, coverage_main_class)
+
+    runfiles = default_info.runfiles
+
+    if executable:
+        runtime_toolchain = semantics.find_java_runtime_toolchain(ctx)
+        runfiles = runfiles.merge(ctx.runfiles(transitive_files = runtime_toolchain.files))
+
+    test_support = helper.get_test_support(ctx)
+    if test_support:
+        runfiles = runfiles.merge(test_support[DefaultInfo].default_runfiles)
+
+    providers["DefaultInfo"] = DefaultInfo(
+        files = default_info.files,
+        runfiles = runfiles,
+        executable = default_info.executable,
+    )
+
+    info = providers.pop("InternalDeployJarInfo")
+    create_deploy_archives(
+        ctx,
+        info.java_attrs,
+        launcher_info,
+        main_class,
+        coverage_main_class,
+        info.strip_as_default,
+        add_exports = info.add_exports,
+        add_opens = info.add_opens,
+    )
+
+    return providers.values()
+
+def _get_coverage_runner(ctx):
+    if ctx.configuration.coverage_enabled and ctx.attr.create_executable:
+        toolchain = semantics.find_java_toolchain(ctx)
+        runner = toolchain.jacocorunner
+        if not runner:
+            fail("jacocorunner not set in java_toolchain: %s" % toolchain.label)
+        runner_jar = runner.executable
+
+        # wrap the jar in JavaInfo so we can add it to deps for java_common.compile()
+        return JavaInfo(output_jar = runner_jar, compile_jar = runner_jar)
+
+    return None
+
+def _collect_all_targets_as_deps(ctx, classpath_type = "all"):
+    deps = helper.collect_all_targets_as_deps(ctx, classpath_type = classpath_type)
+
+    if classpath_type == "compile_only" and ctx.fragments.java.enforce_explicit_java_test_deps():
+        return deps
+
+    test_support = helper.get_test_support(ctx)
+    if test_support:
+        deps.append(test_support)
+    return deps
+
+def _check_and_get_main_class(ctx):
+    create_executable = ctx.attr.create_executable
+    main_class = _get_main_class(ctx)
+
+    if not create_executable and main_class:
+        fail("main class must not be specified when executable is not created")
+    if create_executable and not main_class:
+        if not ctx.attr.srcs:
+            fail("need at least one of 'main_class' or Java source files")
+        main_class = helper.primary_class(ctx)
+        if main_class == None:
+            fail("main_class was not provided and cannot be inferred: " +
+                 "source path doesn't include a known root (java, javatests, src, testsrc)")
+
+    return _get_main_class(ctx)
+
+def _get_main_class(ctx):
+    if not ctx.attr.create_executable:
+        return None
+
+    main_class = _get_main_class_from_rule(ctx)
+
+    if main_class == "":
+        main_class = helper.primary_class(ctx)
+    return main_class
+
+def _get_main_class_from_rule(ctx):
+    main_class = ctx.attr.main_class
+    if main_class:
+        return main_class
+    if ctx.attr.use_testrunner:
+        return "com.google.testing.junit.runner.BazelTestRunner"
+    return main_class
+
+def _get_launcher_info(ctx):
+    launcher = helper.launcher_artifact_for_target(ctx)
+    return struct(
+        launcher = launcher,
+        unstripped_launcher = launcher,
+        runfiles = [],
+        runtime_jars = [],
+        jvm_flags = [],
+        classpath_resources = [],
+    )
+
+def _get_executable(ctx):
+    if not ctx.attr.create_executable:
+        return None
+    executable_name = ctx.label.name
+    if helper.is_target_platform_windows(ctx):
+        executable_name = executable_name + ".exe"
+
+    return ctx.actions.declare_file(executable_name)
+
+def _create_stub(ctx, java_attrs, launcher, executable, jvm_flags, main_class, coverage_main_class):
+    java_runtime_toolchain = semantics.find_java_runtime_toolchain(ctx)
+    java_executable = helper.get_java_executable(ctx, java_runtime_toolchain, launcher)
+    workspace_name = ctx.workspace_name
+    workspace_prefix = workspace_name + ("/" if workspace_name else "")
+    runfiles_enabled = helper.runfiles_enabled(ctx)
+    coverage_enabled = ctx.configuration.coverage_enabled
+
+    test_support = helper.get_test_support(ctx)
+    test_support_jars = test_support[JavaInfo].transitive_runtime_jars if test_support else depset()
+    classpath = depset(
+        transitive = [
+            java_attrs.runtime_classpath,
+            test_support_jars if ctx.fragments.java.enforce_explicit_java_test_deps() else depset(),
+        ],
+    )
+
+    if helper.is_target_platform_windows(ctx):
+        jvm_flags_for_launcher = []
+        for flag in jvm_flags:
+            jvm_flags_for_launcher.extend(ctx.tokenize(flag))
+        return _create_windows_exe_launcher(ctx, java_executable, classpath, main_class, jvm_flags_for_launcher, runfiles_enabled, executable)
+
+    if runfiles_enabled:
+        prefix = "" if helper.is_absolute_target_platform_path(ctx, java_executable) else "${JAVA_RUNFILES}/"
+        java_bin = "JAVABIN=${JAVABIN:-" + prefix + java_executable + "}"
+    else:
+        java_bin = "JAVABIN=${JAVABIN:-$(rlocation " + java_executable + ")}"
+
+    td = ctx.actions.template_dict()
+    td.add_joined(
+        "%classpath%",
+        classpath,
+        map_each = lambda file: _format_classpath_entry(runfiles_enabled, workspace_prefix, file),
+        join_with = ctx.configuration.host_path_separator,
+        format_joined = "\"%s\"",
+        allow_closure = True,
+    )
+
+    ctx.actions.expand_template(
+        template = ctx.file._stub_template,
+        output = executable,
+        substitutions = {
+            "%runfiles_manifest_only%": "" if runfiles_enabled else "1",
+            "%workspace_prefix%": workspace_prefix,
+            "%javabin%": java_bin,
+            "%needs_runfiles%": "0" if helper.is_absolute_target_platform_path(ctx, java_runtime_toolchain.java_executable_exec_path) else "1",
+            "%set_jacoco_metadata%": "",
+            "%set_jacoco_main_class%": "export JACOCO_MAIN_CLASS=" + coverage_main_class if coverage_enabled else "",
+            "%set_jacoco_java_runfiles_root%": "export JACOCO_JAVA_RUNFILES_ROOT=${JAVA_RUNFILES}/" + workspace_prefix if coverage_enabled else "",
+            "%java_start_class%": helper.shell_escape(main_class),
+            "%jvm_flags%": " ".join(jvm_flags),
+        },
+        computed_substitutions = td,
+        is_executable = True,
+    )
+    return executable
+
+def _format_classpath_entry(runfiles_enabled, workspace_prefix, file):
+    if runfiles_enabled:
+        return "${RUNPATH}" + file.short_path
+
+    return "$(rlocation " + paths.normalize(workspace_prefix + file.short_path) + ")"
+
+def _create_windows_exe_launcher(ctx, java_executable, classpath, main_class, jvm_flags_for_launcher, runfiles_enabled, executable):
+    launch_info = ctx.actions.args().use_param_file("%s", use_always = True).set_param_file_format("multiline")
+    launch_info.add("binary_type=Java")
+    launch_info.add(ctx.workspace_name, format = "workspace_name=%s")
+    launch_info.add("1" if runfiles_enabled else "0", format = "symlink_runfiles_enabled=%s")
+    launch_info.add(java_executable, format = "java_bin_path=%s")
+    launch_info.add(main_class, format = "java_start_class=%s")
+    launch_info.add_joined(classpath, map_each = _short_path, join_with = ";", format_joined = "classpath=%s", omit_if_empty = False)
+    launch_info.add_joined(jvm_flags_for_launcher, join_with = "\t", format_joined = "jvm_flags=%s", omit_if_empty = False)
+    launch_info.add(semantics.find_java_runtime_toolchain(ctx).java_home_runfiles_path, format = "jar_bin_path=%s/bin/jar.exe")
+
+    # TODO(b/295221112): Change to use the "launcher" attribute (only windows use a fixed _launcher attribute)
+    launcher_artifact = ctx.executable._launcher
+    ctx.actions.run(
+        executable = ctx.executable._windows_launcher_maker,
+        inputs = [launcher_artifact],
+        outputs = [executable],
+        arguments = [launcher_artifact.path, launch_info, executable.path],
+        use_default_shell_env = True,
+    )
+    return executable
+
+def _short_path(file):
+    return file.short_path
+
+def _compute_test_support(use_testrunner):
+    return Label(semantics.JAVA_TEST_RUNNER_LABEL) if use_testrunner else None
+
+def make_binary_rule(implementation, *, doc, attrs, executable = False, test = False, initializer = None):
+    return rule(
+        implementation = implementation,
+        initializer = initializer,
+        doc = doc,
+        attrs = attrs,
+        executable = executable,
+        test = test,
+        fragments = ["cpp", "java"],
+        provides = [JavaInfo],
+        toolchains = [semantics.JAVA_TOOLCHAIN] + use_cc_toolchain() + (
+            [semantics.JAVA_RUNTIME_TOOLCHAIN] if executable or test else []
+        ),
+        # TODO(hvd): replace with filegroups?
+        outputs = {
+            "classjar": "%{name}.jar",
+            "sourcejar": "%{name}-src.jar",
+            "deploysrcjar": "%{name}_deploy-src.jar",
+            "deployjar": "%{name}_deploy.jar",
+            "unstrippeddeployjar": "%{name}_deploy.jar.unstripped",
+        },
+        exec_groups = {
+            "cpp_link": exec_group(toolchains = use_cc_toolchain()),
+        },
+        subrules = [android_lint_subrule],
+    )
+
+BASE_BINARY_ATTRS = merge_attrs(
+    BASIC_JAVA_BINARY_ATTRIBUTES,
+    {
+        "resource_strip_prefix": attr.string(
+            doc = """
+The path prefix to strip from Java resources.
+<p>
+If specified, this path prefix is stripped from every file in the <code>resources</code>
+attribute. It is an error for a resource file not to be under this directory. If not
+specified (the default), the path of resource file is determined according to the same
+logic as the Java package of source files. For example, a source file at
+<code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>.
+</p>
+            """,
+        ),
+        "_test_support": attr.label(default = _compute_test_support),
+        "_launcher": attr.label(
+            cfg = "exec",
+            executable = True,
+            default = "@bazel_tools//tools/launcher:launcher",
+        ),
+        "_windows_launcher_maker": attr.label(
+            default = "@bazel_tools//tools/launcher:launcher_maker",
+            cfg = "exec",
+            executable = True,
+        ),
+    },
+)
+
+def make_java_binary(executable):
+    return make_binary_rule(
+        _bazel_java_binary_impl,
+        doc = """
+<p>
+  Builds a Java archive ("jar file"), plus a wrapper shell script with the same name as the rule.
+  The wrapper shell script uses a classpath that includes, among other things, a jar file for each
+  library on which the binary depends. When running the wrapper shell script, any nonempty
+  <code>JAVABIN</code> environment variable will take precedence over the version specified via
+  Bazel's <code>--java_runtime_version</code> flag.
+</p>
+<p>
+  The wrapper script accepts several unique flags. Refer to
+  <code>//src/main/java/com/google/devtools/build/lib/bazel/rules/java/java_stub_template.txt</code>
+  for a list of configurable flags and environment variables accepted by the wrapper.
+</p>
+
+<h4 id="java_binary_implicit_outputs">Implicit output targets</h4>
+<ul>
+  <li><code><var>name</var>.jar</code>: A Java archive, containing the class files and other
+    resources corresponding to the binary's direct dependencies.</li>
+  <li><code><var>name</var>-src.jar</code>: An archive containing the sources ("source
+    jar").</li>
+  <li><code><var>name</var>_deploy.jar</code>: A Java archive suitable for deployment (only
+    built if explicitly requested).
+    <p>
+      Building the <code>&lt;<var>name</var>&gt;_deploy.jar</code> target for your rule
+      creates a self-contained jar file with a manifest that allows it to be run with the
+      <code>java -jar</code> command or with the wrapper script's <code>--singlejar</code>
+      option. Using the wrapper script is preferred to <code>java -jar</code> because it
+      also passes the <a href="#java_binary-jvm_flags">JVM flags</a> and the options
+      to load native libraries.
+    </p>
+    <p>
+      The deploy jar contains all the classes that would be found by a classloader that
+      searched the classpath from the binary's wrapper script from beginning to end. It also
+      contains the native libraries needed for dependencies. These are automatically loaded
+      into the JVM at runtime.
+    </p>
+    <p>If your target specifies a <a href="#java_binary.launcher">launcher</a>
+      attribute, then instead of being a normal JAR file, the _deploy.jar will be a
+      native binary. This will contain the launcher plus any native (C++) dependencies of
+      your rule, all linked into a static binary. The actual jar file's bytes will be
+      appended to that native binary, creating a single binary blob containing both the
+      executable and the Java code. You can execute the resulting jar file directly
+      like you would execute any native binary.</p>
+  </li>
+  <li><code><var>name</var>_deploy-src.jar</code>: An archive containing the sources
+    collected from the transitive closure of the target. These will match the classes in the
+    <code>deploy.jar</code> except where jars have no matching source jar.</li>
+</ul>
+
+<p>
+It is good practice to use the name of the source file that is the main entry point of the
+application (minus the extension). For example, if your entry point is called
+<code>Main.java</code>, then your name could be <code>Main</code>.
+</p>
+
+<p>
+  A <code>deps</code> attribute is not allowed in a <code>java_binary</code> rule without
+  <a href="#java_binary-srcs"><code>srcs</code></a>; such a rule requires a
+  <a href="#java_binary-main_class"><code>main_class</code></a> provided by
+  <a href="#java_binary-runtime_deps"><code>runtime_deps</code></a>.
+</p>
+
+<p>The following code snippet illustrates a common mistake:</p>
+
+<pre class="code">
+<code class="lang-starlark">
+java_binary(
+    name = "DontDoThis",
+    srcs = [
+        <var>...</var>,
+        <code class="deprecated">"GeneratedJavaFile.java"</code>,  # a generated .java file
+    ],
+    deps = [<code class="deprecated">":generating_rule",</code>],  # rule that generates that file
+)
+</code>
+</pre>
+
+<p>Do this instead:</p>
+
+<pre class="code">
+<code class="lang-starlark">
+java_binary(
+    name = "DoThisInstead",
+    srcs = [
+        <var>...</var>,
+        ":generating_rule",
+    ],
+)
+</code>
+</pre>
+        """,
+        attrs = merge_attrs(
+            BASE_BINARY_ATTRS,
+            ({} if executable else {
+                "args": attr.string_list(),
+                "output_licenses": attr.string_list(),
+            }),
+        ),
+        executable = executable,
+    )
+
+java_binary = make_java_binary(executable = True)
diff --git a/java/bazel/rules/bazel_java_binary_nonexec.bzl b/java/bazel/rules/bazel_java_binary_nonexec.bzl
new file mode 100644
index 0000000..a59030e
--- /dev/null
+++ b/java/bazel/rules/bazel_java_binary_nonexec.bzl
@@ -0,0 +1,25 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Defines a java_binary rule class that is non-executable.
+
+There are two physical rule classes for java_binary and we want both of them
+to have a name string of "java_binary" because various tooling expects that.
+"""
+
+load(":bazel_java_binary.bzl", "make_java_binary")
+
+visibility("private")
+
+java_binary = make_java_binary(executable = False)
diff --git a/java/bazel/rules/bazel_java_binary_wrapper.bzl b/java/bazel/rules/bazel_java_binary_wrapper.bzl
new file mode 100644
index 0000000..517dcd6
--- /dev/null
+++ b/java/bazel/rules/bazel_java_binary_wrapper.bzl
@@ -0,0 +1,43 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Macro encapsulating the java_binary implementation
+
+This is needed since the `executable` nature of the target must be computed from
+the supplied value of the `create_executable` attribute.
+"""
+
+load(
+    "//java/common/rules:java_binary_wrapper.bzl",
+    "register_java_binary_rules",
+    "register_legacy_java_binary_rules",
+)
+load("//java/private:native.bzl", "get_internal_java_common")
+load(":bazel_java_binary.bzl", java_bin_exec = "java_binary")
+load(":bazel_java_binary_nonexec.bzl", java_bin_nonexec = "java_binary")
+
+# copybara: default visibility
+
+def java_binary(**kwargs):
+    if get_internal_java_common().incompatible_disable_non_executable_java_binary():
+        register_java_binary_rules(
+            java_bin_exec,
+            **kwargs
+        )
+    else:
+        register_legacy_java_binary_rules(
+            java_bin_exec,
+            java_bin_nonexec,
+            **kwargs
+        )
diff --git a/java/bazel/rules/bazel_java_import.bzl b/java/bazel/rules/bazel_java_import.bzl
new file mode 100644
index 0000000..855420f
--- /dev/null
+++ b/java/bazel/rules/bazel_java_import.bzl
@@ -0,0 +1,66 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_import rule.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:java_import.bzl", "JAVA_IMPORT_ATTRS")
+load("//java/common/rules/impl:bazel_java_import_impl.bzl", "bazel_java_import_rule")
+load("//java/private:java_info.bzl", "JavaInfo")
+
+def _proxy(ctx):
+    return bazel_java_import_rule(
+        ctx,
+        ctx.attr.jars,
+        ctx.file.srcjar,
+        ctx.attr.deps,
+        ctx.attr.runtime_deps,
+        ctx.attr.exports,
+        ctx.attr.neverlink,
+        ctx.files.proguard_specs,
+        ctx.attr.add_exports,
+        ctx.attr.add_opens,
+    ).values()
+
+java_import = rule(
+    _proxy,
+    doc = """
+<p>
+  This rule allows the use of precompiled <code>.jar</code> files as
+  libraries for <code><a href="#java_library">java_library</a></code> and
+  <code>java_binary</code> rules.
+</p>
+
+<h4 id="java_import_examples">Examples</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+    java_import(
+        name = "maven_model",
+        jars = [
+            "maven_model/maven-aether-provider-3.2.3.jar",
+            "maven_model/maven-model-3.2.3.jar",
+            "maven_model/maven-model-builder-3.2.3.jar",
+        ],
+    )
+</code>
+</pre>
+    """,
+    attrs = JAVA_IMPORT_ATTRS,
+    provides = [JavaInfo],
+    fragments = ["java", "cpp"],
+    toolchains = [semantics.JAVA_TOOLCHAIN],
+)
diff --git a/java/bazel/rules/bazel_java_library.bzl b/java/bazel/rules/bazel_java_library.bzl
new file mode 100644
index 0000000..2c92394
--- /dev/null
+++ b/java/bazel/rules/bazel_java_library.bzl
@@ -0,0 +1,65 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_library rule.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:android_lint.bzl", "android_lint_subrule")
+load("//java/common/rules:java_library.bzl", "JAVA_LIBRARY_ATTRS")
+load("//java/common/rules/impl:bazel_java_library_impl.bzl", "bazel_java_library_rule")
+load("//java/private:java_info.bzl", "JavaInfo")
+
+def _proxy(ctx):
+    return bazel_java_library_rule(
+        ctx,
+        ctx.files.srcs,
+        ctx.attr.deps,
+        ctx.attr.runtime_deps,
+        ctx.attr.plugins,
+        ctx.attr.exports,
+        ctx.attr.exported_plugins,
+        ctx.files.resources,
+        ctx.attr.javacopts,
+        ctx.attr.neverlink,
+        ctx.files.proguard_specs,
+        ctx.attr.add_exports,
+        ctx.attr.add_opens,
+        ctx.attr.bootclasspath,
+        ctx.attr.javabuilder_jvm_flags,
+    ).values()
+
+java_library = rule(
+    _proxy,
+    doc = """
+<p>This rule compiles and links sources into a <code>.jar</code> file.</p>
+
+<h4>Implicit outputs</h4>
+<ul>
+  <li><code>lib<var>name</var>.jar</code>: A Java archive containing the class files.</li>
+  <li><code>lib<var>name</var>-src.jar</code>: An archive containing the sources ("source
+    jar").</li>
+</ul>
+    """,
+    attrs = JAVA_LIBRARY_ATTRS,
+    provides = [JavaInfo],
+    outputs = {
+        "classjar": "lib%{name}.jar",
+        "sourcejar": "lib%{name}-src.jar",
+    },
+    fragments = ["java", "cpp"],
+    toolchains = [semantics.JAVA_TOOLCHAIN],
+    subrules = [android_lint_subrule],
+)
diff --git a/java/bazel/rules/bazel_java_plugin.bzl b/java/bazel/rules/bazel_java_plugin.bzl
new file mode 100644
index 0000000..f2619ed
--- /dev/null
+++ b/java/bazel/rules/bazel_java_plugin.bzl
@@ -0,0 +1,154 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_plugin rule.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:android_lint.bzl", "android_lint_subrule")
+load("//java/common/rules:java_library.bzl", "JAVA_LIBRARY_IMPLICIT_ATTRS")
+load("//java/common/rules:java_plugin.bzl", "JAVA_PLUGIN_ATTRS")
+load("//java/common/rules:rule_util.bzl", "merge_attrs")
+load("//java/common/rules/impl:basic_java_library_impl.bzl", "basic_java_library", "construct_defaultinfo")
+load("//java/private:java_info.bzl", "JavaPluginInfo")
+
+def bazel_java_plugin_rule(
+        ctx,
+        srcs = [],
+        data = [],
+        generates_api = False,
+        processor_class = "",
+        deps = [],
+        plugins = [],
+        resources = [],
+        javacopts = [],
+        neverlink = False,
+        proguard_specs = [],
+        add_exports = [],
+        add_opens = []):
+    """Implements java_plugin rule.
+
+    Use this call when you need to produce a fully fledged java_plugin from
+    another rule's implementation.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      srcs: (list[File]) The list of source files that are processed to create the target.
+      data: (list[File]) The list of files needed by this plugin at runtime.
+      generates_api: (bool) This attribute marks annotation processors that generate API code.
+      processor_class: (str) The processor class is the fully qualified type of
+        the class that the Java compiler should use as entry point to the annotation processor.
+      deps: (list[Target]) The list of other libraries to be linked in to the target.
+      plugins: (list[Target]) Java compiler plugins to run at compile-time.
+      resources: (list[File]) A list of data files to include in a Java jar.
+      javacopts: (list[str]) Extra compiler options for this library.
+      neverlink: (bool) Whether this library should only be used for compilation and not at runtime.
+      proguard_specs: (list[File]) Files to be used as Proguard specification.
+      add_exports: (list[str]) Allow this library to access the given <module>/<package>.
+      add_opens: (list[str]) Allow this library to reflectively access the given <module>/<package>.
+    Returns:
+      (list[provider]) A list containing DefaultInfo, JavaInfo,
+        InstrumentedFilesInfo, OutputGroupsInfo, ProguardSpecProvider providers.
+    """
+    target, base_info = basic_java_library(
+        ctx,
+        srcs,
+        deps,
+        [],  # runtime_deps
+        plugins,
+        [],  # exports
+        [],  # exported_plugins
+        resources,
+        [],  # resource_jars
+        [],  # classpath_resources
+        javacopts,
+        neverlink,
+        proguard_specs = proguard_specs,
+        add_exports = add_exports,
+        add_opens = add_opens,
+    )
+    java_info = target.pop("JavaInfo")
+
+    # Replace JavaInfo with JavaPluginInfo
+    target["JavaPluginInfo"] = JavaPluginInfo(
+        runtime_deps = [java_info],
+        processor_class = processor_class if processor_class else None,  # ignore empty string (default)
+        data = data,
+        generates_api = generates_api,
+    )
+    target["DefaultInfo"] = construct_defaultinfo(
+        ctx,
+        base_info.files_to_build,
+        base_info.runfiles,
+        neverlink,
+    )
+    target["OutputGroupInfo"] = OutputGroupInfo(**base_info.output_groups)
+
+    return target
+
+def _proxy(ctx):
+    return bazel_java_plugin_rule(
+        ctx,
+        ctx.files.srcs,
+        ctx.files.data,
+        ctx.attr.generates_api,
+        ctx.attr.processor_class,
+        ctx.attr.deps,
+        ctx.attr.plugins,
+        ctx.files.resources,
+        ctx.attr.javacopts,
+        ctx.attr.neverlink,
+        ctx.files.proguard_specs,
+        ctx.attr.add_exports,
+        ctx.attr.add_opens,
+    ).values()
+
+_JAVA_PLUGIN_IMPLICIT_ATTRS = JAVA_LIBRARY_IMPLICIT_ATTRS
+
+java_plugin = rule(
+    _proxy,
+    doc = """
+<p>
+  <code>java_plugin</code> defines plugins for the Java compiler run by Bazel. The
+  only supported kind of plugins are annotation processors. A <code>java_library</code> or
+  <code>java_binary</code> rule can run plugins by depending on them via the <code>plugins</code>
+  attribute. A <code>java_library</code> can also automatically export plugins to libraries that
+  directly depend on it using
+  <code><a href="#java_library-exported_plugins">exported_plugins</a></code>.
+</p>
+
+<h4 id="java_plugin_implicit_outputs">Implicit output targets</h4>
+    <ul>
+      <li><code><var>libname</var>.jar</code>: A Java archive.</li>
+    </ul>
+
+<p>
+  Arguments are identical to <a href="#java_library"><code>java_library</code></a>, except
+  for the addition of the <code>processor_class</code> argument.
+</p>
+    """,
+    attrs = merge_attrs(
+        JAVA_PLUGIN_ATTRS,
+        _JAVA_PLUGIN_IMPLICIT_ATTRS,
+    ),
+    provides = [JavaPluginInfo],
+    outputs = {
+        "classjar": "lib%{name}.jar",
+        "sourcejar": "lib%{name}-src.jar",
+    },
+    fragments = ["java", "cpp"],
+    toolchains = [semantics.JAVA_TOOLCHAIN],
+    subrules = [android_lint_subrule],
+)
diff --git a/java/bazel/rules/bazel_java_test.bzl b/java/bazel/rules/bazel_java_test.bzl
new file mode 100644
index 0000000..7dec849
--- /dev/null
+++ b/java/bazel/rules/bazel_java_test.bzl
@@ -0,0 +1,148 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Bazel java_test rule"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:java_binary.bzl", "BASE_TEST_ATTRIBUTES")
+load("//java/common/rules:rule_util.bzl", "merge_attrs")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load(":bazel_java_binary.bzl", "BASE_BINARY_ATTRS", "bazel_base_binary_impl", "make_binary_rule")
+
+def _bazel_java_test_impl(ctx):
+    return bazel_base_binary_impl(ctx, is_test_rule_class = True) + helper.test_providers(ctx)
+
+def _java_test_initializer(**kwargs):
+    if "stamp" in kwargs and type(kwargs["stamp"]) == type(True):
+        kwargs["stamp"] = 1 if kwargs["stamp"] else 0
+    if "use_launcher" in kwargs and not kwargs["use_launcher"]:
+        kwargs["launcher"] = None
+    else:
+        # If launcher is not set or None, set it to config flag
+        if "launcher" not in kwargs or not kwargs["launcher"]:
+            kwargs["launcher"] = semantics.LAUNCHER_FLAG_LABEL
+    return kwargs
+
+java_test = make_binary_rule(
+    _bazel_java_test_impl,
+    doc = """
+<p>
+A <code>java_test()</code> rule compiles a Java test. A test is a binary wrapper around your
+test code. The test runner's main method is invoked instead of the main class being compiled.
+</p>
+
+<h4 id="java_test_implicit_outputs">Implicit output targets</h4>
+<ul>
+  <li><code><var>name</var>.jar</code>: A Java archive.</li>
+  <li><code><var>name</var>_deploy.jar</code>: A Java archive suitable
+    for deployment. (Only built if explicitly requested.) See the description of the
+    <code><var>name</var>_deploy.jar</code> output from
+    <a href="#java_binary">java_binary</a> for more details.</li>
+</ul>
+
+<p>
+See the section on <code>java_binary()</code> arguments. This rule also
+supports all <a href="https://bazel.build/reference/be/common-definitions#common-attributes-tests">attributes common
+to all test rules (*_test)</a>.
+</p>
+
+<h4 id="java_test_examples">Examples</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_library(
+    name = "tests",
+    srcs = glob(["*.java"]),
+    deps = [
+        "//java/com/foo/base:testResources",
+        "//java/com/foo/testing/util",
+    ],
+)
+
+java_test(
+    name = "AllTests",
+    size = "small",
+    runtime_deps = [
+        ":tests",
+        "//util/mysql",
+    ],
+)
+</code>
+</pre>
+    """,
+    attrs = merge_attrs(
+        BASE_TEST_ATTRIBUTES,
+        BASE_BINARY_ATTRS,
+        {
+            "_lcov_merger": attr.label(
+                cfg = "exec",
+                default = configuration_field(
+                    fragment = "coverage",
+                    name = "output_generator",
+                ),
+            ),
+            "_collect_cc_coverage": attr.label(
+                cfg = "exec",
+                allow_single_file = True,
+                default = "@bazel_tools//tools/test:collect_cc_coverage",
+            ),
+        },
+        override_attrs = {
+            "use_testrunner": attr.bool(
+                default = True,
+                doc = semantics.DOCS.for_attribute("use_testrunner") + """
+<br/>
+You can use this to override the default
+behavior, which is to use test runner for
+<code>java_test</code> rules,
+and not use it for <code>java_binary</code> rules.  It is unlikely
+you will want to do this.  One use is for <code>AllTest</code>
+rules that are invoked by another rule (to set up a database
+before running the tests, for example).  The <code>AllTest</code>
+rule must be declared as a <code>java_binary</code>, but should
+still use the test runner as its main entry point.
+
+The name of a test runner class can be overridden with <code>main_class</code> attribute.
+                """,
+            ),
+            "stamp": attr.int(
+                default = 0,
+                values = [-1, 0, 1],
+                doc = """
+Whether to encode build information into the binary. Possible values:
+<ul>
+<li>
+  <code>stamp = 1</code>: Always stamp the build information into the binary, even in
+  <a href="https://bazel.build/docs/user-manual#stamp"><code>--nostamp</code></a> builds. <b>This
+  setting should be avoided</b>, since it potentially kills remote caching for the
+  binary and any downstream actions that depend on it.
+</li>
+<li>
+  <code>stamp = 0</code>: Always replace build information by constant values. This
+  gives good build result caching.
+</li>
+<li>
+  <code>stamp = -1</code>: Embedding of build information is controlled by the
+  <a href="https://bazel.build/docs/user-manual#stamp"><code>--[no]stamp</code></a> flag.
+</li>
+</ul>
+<p>Stamped binaries are <em>not</em> rebuilt unless their dependencies change.</p>
+                """,
+            ),
+        },
+        remove_attrs = ["deploy_env"],
+    ),
+    test = True,
+    initializer = _java_test_initializer,
+)
diff --git a/java/common/BUILD b/java/common/BUILD
index e9d0165..a06a2f3 100644
--- a/java/common/BUILD
+++ b/java/common/BUILD
@@ -6,15 +6,42 @@ licenses(["notice"])
 
 filegroup(
     name = "srcs",
-    srcs = glob(["**"]),
+    srcs = glob(["**"]) + [
+        "//java/common/rules:srcs",
+    ],
     visibility = ["//java:__pkg__"],
 )
 
 bzl_library(
     name = "common",
-    srcs = glob(["*.bzl"]),
+    srcs = glob(
+        ["*.bzl"],
+        exclude = [
+            "java_semantics.bzl",
+            "proguard_spec_info.bzl",
+        ],
+    ),
+    visibility = ["//visibility:public"],
+    deps = [
+        ":proguard_spec_info_bzl",
+        ":semantics_bzl",
+        "@compatibility_proxy//:proxy_bzl",
+    ],
+)
+
+bzl_library(
+    name = "semantics_bzl",
+    srcs = ["java_semantics.bzl"],
+    visibility = ["//visibility:public"],
+    deps = [
+        "@rules_cc//cc/common",
+    ],
+)
+
+bzl_library(
+    name = "proguard_spec_info_bzl",
+    srcs = ["proguard_spec_info.bzl"],
     visibility = ["//visibility:public"],
-    deps = ["//java/private"],
 )
 
 filegroup(
@@ -23,6 +50,7 @@ filegroup(
     srcs = [
         "BUILD",
         ":common",
+        "//java/common/rules:for_bazel_tests",
     ],
     visibility = ["//java:__pkg__"],
 )
diff --git a/java/common/java_common.bzl b/java/common/java_common.bzl
index 201beba..ed55bdb 100644
--- a/java/common/java_common.bzl
+++ b/java/common/java_common.bzl
@@ -13,6 +13,6 @@
 # limitations under the License.
 """java_common module"""
 
-load("//java/private:native.bzl", "native_java_common")
+load("@compatibility_proxy//:proxy.bzl", _java_common = "java_common")
 
-java_common = native_java_common
+java_common = _java_common
diff --git a/java/common/java_info.bzl b/java/common/java_info.bzl
index e22fb3d..2748f6d 100644
--- a/java/common/java_info.bzl
+++ b/java/common/java_info.bzl
@@ -13,6 +13,6 @@
 # limitations under the License.
 """JavaInfo provider"""
 
-load("//java/private:native.bzl", "NativeJavaInfo")
+load("@compatibility_proxy//:proxy.bzl", _JavaInfo = "JavaInfo")
 
-JavaInfo = NativeJavaInfo
+JavaInfo = _JavaInfo
diff --git a/java/common/java_plugin_info.bzl b/java/common/java_plugin_info.bzl
index 36d84f9..b43dfd5 100644
--- a/java/common/java_plugin_info.bzl
+++ b/java/common/java_plugin_info.bzl
@@ -13,6 +13,6 @@
 # limitations under the License.
 """JavaPluginInfo provider"""
 
-load("//java/private:native.bzl", "NativeJavaPluginInfo")
+load("@compatibility_proxy//:proxy.bzl", _JavaPluginInfo = "JavaPluginInfo")
 
-JavaPluginInfo = NativeJavaPluginInfo
+JavaPluginInfo = _JavaPluginInfo
diff --git a/java/common/java_semantics.bzl b/java/common/java_semantics.bzl
new file mode 100644
index 0000000..a08717b
--- /dev/null
+++ b/java/common/java_semantics.bzl
@@ -0,0 +1,109 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""Bazel Java Semantics"""
+
+load("@rules_cc//cc/common:cc_helper.bzl", "cc_helper")
+
+# copybara: default visibility
+
+def _find_java_toolchain(ctx):
+    return ctx.toolchains["@bazel_tools//tools/jdk:toolchain_type"].java
+
+def _find_java_runtime_toolchain(ctx):
+    return ctx.toolchains["@bazel_tools//tools/jdk:runtime_toolchain_type"].java_runtime
+
+def _get_default_resource_path(path, segment_extractor):
+    # Look for src/.../resources to match Maven repository structure.
+    segments = path.split("/")
+    for idx in range(0, len(segments) - 2):
+        if segments[idx] == "src" and segments[idx + 2] == "resources":
+            return "/".join(segments[idx + 3:])
+    java_segments = segment_extractor(path)
+    return "/".join(java_segments) if java_segments != None else path
+
+def _compatible_javac_options(*_args):
+    return depset()
+
+def _check_java_info_opens_exports():
+    pass
+
+def _minimize_cc_info(cc_info):
+    return cc_info
+
+_DOCS = struct(
+    ATTRS = {
+        "resources": """
+<p>
+If resources are specified, they will be bundled in the jar along with the usual
+<code>.class</code> files produced by compilation. The location of the resources inside
+of the jar file is determined by the project structure. Bazel first looks for Maven's
+<a href="https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html">standard directory layout</a>,
+(a "src" directory followed by a "resources" directory grandchild). If that is not
+found, Bazel then looks for the topmost directory named "java" or "javatests" (so, for
+example, if a resource is at <code>&lt;workspace root&gt;/x/java/y/java/z</code>, the
+path of the resource will be <code>y/java/z</code>. This heuristic cannot be overridden,
+however, the <code>resource_strip_prefix</code> attribute can be used to specify a
+specific alternative directory for resource files.
+        """,
+        "use_testrunner": """
+Use the test runner (by default
+<code>com.google.testing.junit.runner.BazelTestRunner</code>) class as the
+main entry point for a Java program, and provide the test class
+to the test runner as a value of <code>bazel.test_suite</code>
+system property.
+        """,
+    },
+)
+
+semantics = struct(
+    JAVA_TOOLCHAIN_LABEL = "@bazel_tools//tools/jdk:current_java_toolchain",
+    JAVA_TOOLCHAIN_TYPE = "@bazel_tools//tools/jdk:toolchain_type",
+    JAVA_TOOLCHAIN = config_common.toolchain_type("@bazel_tools//tools/jdk:toolchain_type", mandatory = True),
+    find_java_toolchain = _find_java_toolchain,
+    JAVA_RUNTIME_TOOLCHAIN_TYPE = "@bazel_tools//tools/jdk:runtime_toolchain_type",
+    JAVA_RUNTIME_TOOLCHAIN = config_common.toolchain_type("@bazel_tools//tools/jdk:runtime_toolchain_type", mandatory = True),
+    find_java_runtime_toolchain = _find_java_runtime_toolchain,
+    JAVA_PLUGINS_FLAG_ALIAS_LABEL = "@bazel_tools//tools/jdk:java_plugins_flag_alias",
+    EXTRA_SRCS_TYPES = [],
+    ALLOWED_RULES_IN_DEPS = [
+        "cc_binary",  # NB: linkshared=1
+        "cc_library",
+        "genrule",
+        "genproto",  # TODO(bazel-team): we should filter using providers instead (starlark rule).
+        "java_import",
+        "java_library",
+        "java_proto_library",
+        "java_lite_proto_library",
+        "proto_library",
+        "sh_binary",
+        "sh_library",
+    ],
+    ALLOWED_RULES_IN_DEPS_WITH_WARNING = [],
+    LINT_PROGRESS_MESSAGE = "Running Android Lint for: %{label}",
+    JAVA_STUB_TEMPLATE_LABEL = "@bazel_tools//tools/jdk:java_stub_template.txt",
+    BUILD_INFO_TRANSLATOR_LABEL = "@bazel_tools//tools/build_defs/build_info:java_build_info",
+    JAVA_TEST_RUNNER_LABEL = "@bazel_tools//tools/jdk:TestRunner",
+    IS_BAZEL = True,
+    get_default_resource_path = _get_default_resource_path,
+    compatible_javac_options = _compatible_javac_options,
+    LAUNCHER_FLAG_LABEL = Label("@bazel_tools//tools/jdk:launcher_flag_alias"),
+    PROGUARD_ALLOWLISTER_LABEL = "@bazel_tools//tools/jdk:proguard_whitelister",
+    check_java_info_opens_exports = _check_java_info_opens_exports,
+    DOCS = struct(
+        for_attribute = lambda name: _DOCS.ATTRS.get(name, ""),
+    ),
+    minimize_cc_info = _minimize_cc_info,
+    tokenize_javacopts = cc_helper.tokenize,
+    PLATFORMS_ROOT = "@platforms//",
+)
diff --git a/java/common/proguard_spec_info.bzl b/java/common/proguard_spec_info.bzl
new file mode 100644
index 0000000..b2a591a
--- /dev/null
+++ b/java/common/proguard_spec_info.bzl
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
+"""ProguardSpecInfo provider"""
+
+def _proguard_spec_info_init(specs):
+    # The constructor supports positional parameter, i.e ProguardSpecInfo([file])
+    return {"specs": specs}
+
+ProguardSpecInfo, _ = provider(
+    doc = "Information about proguard specs for Android binaries.",
+    fields = {
+        "specs": "A list of proguard specs files",
+    },
+    init = _proguard_spec_info_init,
+)
diff --git a/java/common/rules/BUILD b/java/common/rules/BUILD
new file mode 100644
index 0000000..9d0678c
--- /dev/null
+++ b/java/common/rules/BUILD
@@ -0,0 +1,71 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+package(default_visibility = ["//visibility:public"])
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]) + [
+        "//java/common/rules/impl:srcs",
+    ],
+    visibility = ["//java/common:__pkg__"],
+)
+
+bzl_library(
+    name = "android_lint_bzl",
+    srcs = ["android_lint.bzl"],
+    visibility = ["//visibility:private"],
+)
+
+bzl_library(
+    name = "rule_util_bzl",
+    srcs = ["rule_util.bzl"],
+    visibility = ["//visibility:private"],
+)
+
+bzl_library(
+    name = "core_rules",
+    srcs = [
+        "basic_java_library.bzl",
+        "java_binary.bzl",
+        "java_binary_wrapper.bzl",
+        "java_import.bzl",
+        "java_library.bzl",
+        "java_plugin.bzl",
+    ],
+    visibility = [
+        "//java:__subpackages__",
+    ],
+    deps = [
+        ":android_lint_bzl",
+        ":rule_util_bzl",
+        "//java/private:internals",
+        "@bazel_skylib//lib:paths",
+        "@rules_cc//cc/common",
+    ],
+)
+
+bzl_library(
+    name = "toolchain_rules",
+    srcs = [
+        "java_package_configuration.bzl",
+        "java_runtime.bzl",
+        "java_toolchain.bzl",
+    ],
+    visibility = [
+        "//java:__subpackages__",
+        "@compatibility_proxy//:__pkg__",
+    ],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD",
+        ":core_rules",
+        ":toolchain_rules",
+        "//java/common/rules/impl:for_bazel_tests",
+        "@rules_cc//cc/private/rules_impl:srcs",
+    ],
+    visibility = ["//java/common:__pkg__"],
+)
diff --git a/java/common/rules/android_lint.bzl b/java/common/rules/android_lint.bzl
new file mode 100644
index 0000000..5275ec2
--- /dev/null
+++ b/java/common/rules/android_lint.bzl
@@ -0,0 +1,145 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""Creates the android lint action for java rules"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+
+# copybara: default visibility
+
+def _tokenize_opts(opts_depset):
+    opts = reversed(opts_depset.to_list())
+    return semantics.tokenize_javacopts(opts)
+
+def _android_lint_action(ctx, source_files, source_jars, compilation_info):
+    """
+    Creates an action that runs Android lint against Java source files.
+
+    You need to add `ANDROID_LINT_IMPLICIT_ATTRS` to any rule or aspect using this call.
+
+    To lint generated source jars (java_info.java_outputs.gen_source_jar)
+    add them to the `source_jar` parameter.
+
+    `compilation_info` parameter should supply the classpath and Javac options
+    that were used during Java compilation.
+
+    The Android lint tool is obtained from Java toolchain.
+
+    Args:
+      ctx: (RuleContext) Used to register the action.
+      source_files: (list[File]) A list of .java source files
+      source_jars: (list[File])  A list of .jar or .srcjar files containing
+        source files. It should also include generated source jars.
+      compilation_info: (struct) Information about compilation.
+
+    Returns:
+      (None|File) The Android lint output file or None if no source files were
+      present.
+    """
+
+    # assuming that linting is enabled for all java rules i.e.
+    # --experimental_limit_android_lint_to_android_constrained_java=false
+
+    # --experimental_run_android_lint_on_java_rules= is checked in basic_java_library.bzl
+
+    if not (source_files or source_jars):
+        return None
+
+    toolchain = semantics.find_java_toolchain(ctx)
+    java_runtime = toolchain.java_runtime
+    linter = toolchain._android_linter
+    if not linter:
+        # TODO(hvd): enable after enabling in tests
+        # fail("android linter not set in java_toolchain")
+        return None
+
+    args = ctx.actions.args()
+
+    executable = linter.tool.executable
+    transitive_inputs = []
+    if executable.extension != "jar":
+        tools = [linter.tool]
+        transitive_inputs.append(linter.data)
+        args_list = [args]
+    else:
+        jvm_args = ctx.actions.args()
+        jvm_args.add_all(toolchain.jvm_opt)
+        jvm_args.add_all(linter.jvm_opts)
+        jvm_args.add("-jar", executable)
+        executable = java_runtime.java_executable_exec_path
+        tools = [java_runtime.files, linter.tool.executable]
+        transitive_inputs.append(linter.data)
+        args_list = [jvm_args, args]
+
+    classpath = compilation_info.compilation_classpath
+
+    # TODO(hvd): get from toolchain if we need this - probably android only
+    bootclasspath_aux = []
+    if bootclasspath_aux:
+        classpath = depset(transitive = [classpath, bootclasspath_aux])
+    transitive_inputs.append(classpath)
+
+    bootclasspath = toolchain.bootclasspath
+    transitive_inputs.append(bootclasspath)
+
+    transitive_inputs.append(compilation_info.plugins.processor_jars)
+    transitive_inputs.append(compilation_info.plugins.processor_data)
+    args.add_all("--sources", source_files)
+    args.add_all("--source_jars", source_jars)
+    args.add_all("--bootclasspath", bootclasspath)
+    args.add_all("--classpath", classpath)
+    args.add_all("--lint_rules", compilation_info.plugins.processor_jars)
+    args.add("--target_label", ctx.label)
+
+    javac_opts = compilation_info.javac_options
+    if javac_opts:
+        # wrap in a list so that map_each passes the depset to _tokenize_opts
+        args.add_all("--javacopts", [javac_opts], map_each = _tokenize_opts)
+        args.add("--")
+
+    args.add("--lintopts")
+    args.add_all(linter.lint_opts)
+
+    for package_config in linter.package_config:
+        if package_config.matches(package_config.package_specs, ctx.label):
+            # wrap in a list so that map_each passes the depset to _tokenize_opts
+            package_opts = [package_config.javac_opts]
+            args.add_all(package_opts, map_each = _tokenize_opts)
+            transitive_inputs.append(package_config.data)
+
+    android_lint_out = ctx.actions.declare_file("%s_android_lint_output.xml" % ctx.label.name)
+    args.add("--xml", android_lint_out)
+
+    args.set_param_file_format(format = "multiline")
+    args.use_param_file(param_file_arg = "@%s", use_always = True)
+    ctx.actions.run(
+        mnemonic = "AndroidLint",
+        progress_message = semantics.LINT_PROGRESS_MESSAGE,
+        executable = executable,
+        inputs = depset(
+            # TODO(b/213551463) benchmark using a transitive depset instead
+            source_files + source_jars,
+            transitive = transitive_inputs,
+        ),
+        outputs = [android_lint_out],
+        tools = tools,
+        arguments = args_list,
+        execution_requirements = {"supports-workers": "1"},
+    )
+    return android_lint_out
+
+android_lint_subrule = subrule(
+    implementation = _android_lint_action,
+    toolchains = [semantics.JAVA_TOOLCHAIN_TYPE],
+)
diff --git a/java/common/rules/basic_java_library.bzl b/java/common/rules/basic_java_library.bzl
new file mode 100644
index 0000000..74b4376
--- /dev/null
+++ b/java/common/rules/basic_java_library.bzl
@@ -0,0 +1,39 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Common code for reuse across java_* rules
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/private:java_common.bzl", "java_common")
+load("//java/private:java_info.bzl", "JavaPluginInfo")
+load(":rule_util.bzl", "merge_attrs")
+
+# copybara: default multiline visibility
+
+BASIC_JAVA_LIBRARY_IMPLICIT_ATTRS = merge_attrs(
+    {
+        "_java_plugins": attr.label(
+            default = semantics.JAVA_PLUGINS_FLAG_ALIAS_LABEL,
+            providers = [JavaPluginInfo],
+        ),
+        # TODO(b/245144242): Used by IDE integration, remove when toolchains are used
+        "_java_toolchain": attr.label(
+            default = semantics.JAVA_TOOLCHAIN_LABEL,
+            providers = [java_common.JavaToolchainInfo],
+        ),
+        "_use_auto_exec_groups": attr.bool(default = True),
+    },
+)
diff --git a/java/common/rules/impl/BUILD b/java/common/rules/impl/BUILD
new file mode 100644
index 0000000..f50862c
--- /dev/null
+++ b/java/common/rules/impl/BUILD
@@ -0,0 +1,39 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+
+package(default_visibility = ["//visibility:public"])
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java/common/rules:__pkg__"],
+)
+
+bzl_library(
+    name = "impl",
+    srcs = glob(
+        ["*.bzl"],
+        exclude = ["java_helper.bzl"],
+    ),
+    visibility = ["//java:__subpackages__"],
+    deps = [
+        ":java_helper_bzl",
+        "//java/common:proguard_spec_info_bzl",
+        "@com_google_protobuf//bazel/common:proto_info_bzl",
+    ],
+)
+
+bzl_library(
+    name = "java_helper_bzl",
+    srcs = ["java_helper.bzl"],
+    visibility = ["//java:__subpackages__"],
+)
+
+filegroup(
+    name = "for_bazel_tests",
+    testonly = 1,
+    srcs = [
+        "BUILD",
+        ":impl",
+    ],
+    visibility = ["//java/common/rules:__pkg__"],
+)
diff --git a/java/common/rules/impl/basic_java_library_impl.bzl b/java/common/rules/impl/basic_java_library_impl.bzl
new file mode 100644
index 0000000..35b1edd
--- /dev/null
+++ b/java/common/rules/impl/basic_java_library_impl.bzl
@@ -0,0 +1,259 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Common code for reuse across java_* rules
+"""
+
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common/rules:android_lint.bzl", "android_lint_subrule")
+load("//java/private:boot_class_path_info.bzl", "BootClassPathInfo")
+load("//java/private:java_common_internal.bzl", "target_kind")
+load("//java/private:java_info.bzl", "JavaInfo", "JavaPluginInfo")
+load(":compile_action.bzl", "compile_action")
+load(":proguard_validation.bzl", "validate_proguard_specs")
+
+# copybara: default multiline visibility
+
+def _filter_srcs(srcs, ext):
+    return [f for f in srcs if f.extension == ext]
+
+def _filter_provider(provider, *attrs):
+    return [dep[provider] for attr in attrs for dep in attr if provider in dep]
+
+# TODO(b/11285003): disallow jar files in deps, require java_import instead
+def _filter_javainfo_and_legacy_jars(attr):
+    dep_list = []
+
+    # Native code collected data into a NestedSet, using add for legacy jars and
+    # addTransitive for JavaInfo. This resulted in legacy jars being first in the list.
+    for dep in attr:
+        kind = target_kind(dep)
+        if not JavaInfo in dep or kind == "java_binary" or kind == "java_test":
+            for file in dep[DefaultInfo].files.to_list():
+                if file.extension == "jar":
+                    # Native doesn't construct JavaInfo
+                    java_info = JavaInfo(output_jar = file, compile_jar = file)
+                    dep_list.append(java_info)
+
+    for dep in attr:
+        if JavaInfo in dep:
+            dep_list.append(dep[JavaInfo])
+    return dep_list
+
+def basic_java_library(
+        ctx,
+        srcs,
+        deps = [],
+        runtime_deps = [],
+        plugins = [],
+        exports = [],
+        exported_plugins = [],
+        resources = [],
+        resource_jars = [],
+        classpath_resources = [],
+        javacopts = [],
+        neverlink = False,
+        enable_compile_jar_action = True,
+        coverage_config = None,
+        proguard_specs = None,
+        add_exports = [],
+        add_opens = [],
+        bootclasspath = None,
+        javabuilder_jvm_flags = None):
+    """
+    Creates actions that compile and lint Java sources, sets up coverage and returns JavaInfo, InstrumentedFilesInfo and output groups.
+
+    The call creates actions and providers needed and shared by `java_library`,
+    `java_plugin`,`java_binary`, and `java_test` rules and it is primarily
+    intended to be used in those rules.
+
+    Before compilation coverage.runner is added to the dependencies and if
+    present plugins are extended with the value of `--plugin` flag.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      srcs: (list[File]) The list of source files that are processed to create the target.
+      deps: (list[Target]) The list of other libraries to be linked in to the target.
+      runtime_deps: (list[Target]) Libraries to make available to the final binary or test at runtime only.
+      plugins: (list[Target]) Java compiler plugins to run at compile-time.
+      exports: (list[Target]) Exported libraries.
+      exported_plugins: (list[Target]) The list of `java_plugin`s (e.g. annotation
+        processors) to export to libraries that directly depend on this library.
+      resources: (list[File]) A list of data files to include in a Java jar.
+      resource_jars: (list[File]) A list of jar files to unpack and include in a
+        Java jar.
+      classpath_resources: (list[File])
+      javacopts: (list[str])
+      neverlink: (bool) Whether this library should only be used for compilation and not at runtime.
+      enable_compile_jar_action: (bool) Enables header compilation or ijar creation.
+      coverage_config: (struct{runner:JavaInfo, support_files:list[File]|depset[File], env:dict[str,str]})
+        Coverage configuration. `runner` is added to dependencies during
+        compilation, `support_files` and `env` is returned in InstrumentedFilesInfo.
+      proguard_specs: (list[File]) Files to be used as Proguard specification.
+        Proguard validation is done only when the parameter is set.
+      add_exports: (list[str]) Allow this library to access the given <module>/<package>.
+      add_opens: (list[str]) Allow this library to reflectively access the given <module>/<package>.
+      bootclasspath: (Target) The JDK APIs to compile this library against.
+      javabuilder_jvm_flags: (list[str]) Additional JVM flags to pass to JavaBuilder.
+    Returns:
+      (dict[str, Provider],
+        {files_to_build: list[File],
+         runfiles: list[File],
+         output_groups: dict[str,list[File]]})
+    """
+    source_files = _filter_srcs(srcs, "java")
+    source_jars = _filter_srcs(srcs, "srcjar")
+
+    plugins_javaplugininfo = _collect_plugins(plugins)
+    plugins_javaplugininfo.append(ctx.attr._java_plugins[JavaPluginInfo])
+
+    properties = _filter_srcs(srcs, "properties")
+    if properties:
+        resources = list(resources)
+        resources.extend(properties)
+
+    java_info, compilation_info = compile_action(
+        ctx,
+        ctx.outputs.classjar,
+        ctx.outputs.sourcejar,
+        source_files,
+        source_jars,
+        collect_deps(deps) + ([coverage_config.runner] if coverage_config and coverage_config.runner else []),
+        collect_deps(runtime_deps),
+        plugins_javaplugininfo,
+        collect_deps(exports),
+        _collect_plugins(exported_plugins),
+        resources,
+        resource_jars,
+        classpath_resources,
+        _collect_native_libraries(deps, runtime_deps, exports),
+        javacopts,
+        neverlink,
+        ctx.fragments.java.strict_java_deps,
+        enable_compile_jar_action,
+        add_exports = add_exports,
+        add_opens = add_opens,
+        bootclasspath = bootclasspath[BootClassPathInfo] if bootclasspath else None,
+        javabuilder_jvm_flags = javabuilder_jvm_flags,
+    )
+    target = {"JavaInfo": java_info}
+
+    output_groups = dict(
+        compilation_outputs = compilation_info.files_to_build,
+        _source_jars = java_info.transitive_source_jars,
+        _direct_source_jars = java_info.source_jars,
+    )
+
+    if ctx.fragments.java.run_android_lint:
+        generated_source_jars = [
+            output.generated_source_jar
+            for output in java_info.java_outputs
+            if output.generated_source_jar != None
+        ]
+        lint_output = android_lint_subrule(
+            source_files,
+            source_jars + generated_source_jars,
+            compilation_info,
+        )
+        if lint_output:
+            output_groups["_validation"] = [lint_output]
+
+    target["InstrumentedFilesInfo"] = coverage_common.instrumented_files_info(
+        ctx,
+        source_attributes = ["srcs"],
+        dependency_attributes = ["deps", "data", "resources", "resource_jars", "exports", "runtime_deps", "jars"],
+        coverage_support_files = coverage_config.support_files if coverage_config else depset(),
+        coverage_environment = coverage_config.env if coverage_config else {},
+    )
+
+    if proguard_specs != None:
+        target["ProguardSpecProvider"] = validate_proguard_specs(
+            ctx,
+            proguard_specs,
+            [deps, runtime_deps, exports],
+        )
+        output_groups["_hidden_top_level_INTERNAL_"] = target["ProguardSpecProvider"].specs
+
+    return target, struct(
+        files_to_build = compilation_info.files_to_build,
+        runfiles = compilation_info.runfiles,
+        output_groups = output_groups,
+    )
+
+def _collect_plugins(plugins):
+    """Collects plugins from an attribute.
+
+    Use this call to collect plugins from `plugins` or `exported_plugins` attribute.
+
+    The call simply extracts JavaPluginInfo provider.
+
+    Args:
+      plugins: (list[Target]) Attribute to collect plugins from.
+    Returns:
+      (list[JavaPluginInfo]) The plugins.
+    """
+    return _filter_provider(JavaPluginInfo, plugins)
+
+def collect_deps(deps):
+    """Collects dependencies from an attribute.
+
+    Use this call to collect plugins from `deps`, `runtime_deps`, or `exports` attribute.
+
+    The call extracts JavaInfo and additionaly also "legacy jars". "legacy jars"
+    are wrapped into a JavaInfo.
+
+    Args:
+      deps: (list[Target]) Attribute to collect dependencies from.
+    Returns:
+      (list[JavaInfo]) The dependencies.
+    """
+    return _filter_javainfo_and_legacy_jars(deps)
+
+def _collect_native_libraries(*attrs):
+    """Collects native libraries from a list of attributes.
+
+    Use this call to collect native libraries from `deps`, `runtime_deps`, or `exports` attributes.
+
+    The call simply extracts CcInfo provider.
+    Args:
+      *attrs: (*list[Target]) Attribute to collect native libraries from.
+    Returns:
+      (list[CcInfo]) The native library dependencies.
+    """
+    return _filter_provider(CcInfo, *attrs)
+
+def construct_defaultinfo(ctx, files_to_build, files, neverlink, *extra_attrs):
+    """Constructs DefaultInfo for Java library like rule.
+
+    Args:
+      ctx: (RuleContext) Used to construct the runfiles.
+      files_to_build: (list[File]) List of the files built by the rule.
+      files: (list[File]) List of the files include in runfiles.
+      neverlink: (bool) When true empty runfiles are constructed.
+      *extra_attrs: (list[Target]) Extra attributes to merge runfiles from.
+
+    Returns:
+      (DefaultInfo) DefaultInfo provider.
+    """
+    if neverlink:
+        runfiles = None
+    else:
+        runfiles = ctx.runfiles(files = files, collect_default = True)
+        runfiles = runfiles.merge_all([dep[DefaultInfo].default_runfiles for attr in extra_attrs for dep in attr])
+    default_info = DefaultInfo(
+        files = depset(files_to_build),
+        runfiles = runfiles,
+    )
+    return default_info
diff --git a/java/common/rules/impl/bazel_java_import_impl.bzl b/java/common/rules/impl/bazel_java_import_impl.bzl
new file mode 100644
index 0000000..4df2ab8
--- /dev/null
+++ b/java/common/rules/impl/bazel_java_import_impl.bzl
@@ -0,0 +1,205 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_import rule.
+"""
+
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules/impl:basic_java_library_impl.bzl", "construct_defaultinfo")
+load("//java/common/rules/impl:import_deps_check.bzl", "import_deps_check")
+load("//java/private:java_common.bzl", "java_common")
+load("//java/private:java_common_internal.bzl", _run_ijar_private_for_builtins = "run_ijar")
+load("//java/private:java_info.bzl", "JavaInfo")
+load(":proguard_validation.bzl", "validate_proguard_specs")
+
+# copybara: default visibility
+
+def _filter_provider(provider, *attrs):
+    return [dep[provider] for attr in attrs for dep in attr if provider in dep]
+
+def _collect_jars(ctx, jars):
+    jars_dict = {}
+    for info in jars:
+        if JavaInfo in info:
+            fail("'jars' attribute cannot contain labels of Java targets")
+        for jar in info.files.to_list():
+            jar_path = jar.dirname + jar.basename
+            if jars_dict.get(jar_path) != None:
+                fail("in jars attribute of java_import rule //" + ctx.label.package + ":" + ctx.attr.name + ": " + jar.basename + " is a duplicate")
+            jars_dict[jar_path] = jar
+    return [jar_tuple[1] for jar_tuple in jars_dict.items()] if len(jars_dict.items()) > 0 else []
+
+def _process_with_ijars_if_needed(jars, ctx):
+    file_dict = {}
+    use_ijars = ctx.fragments.java.use_ijars()
+    for jar in jars:
+        interface_jar = jar
+        if use_ijars:
+            ijar_basename = jar.short_path.removeprefix("../").removesuffix("." + jar.extension) + "-ijar.jar"
+            interface_jar_directory = "_ijar/" + ctx.label.name + "/" + ijar_basename
+
+            interface_jar = ctx.actions.declare_file(interface_jar_directory)
+            _run_ijar_private_for_builtins(
+                ctx.actions,
+                target_label = ctx.label,
+                jar = jar,
+                output = interface_jar,
+                java_toolchain = semantics.find_java_toolchain(ctx),
+            )
+        file_dict[jar] = interface_jar
+
+    return file_dict
+
+def _check_export_error(ctx, exports):
+    not_in_allowlist = hasattr(ctx.attr, "_allowlist_java_import_exports") and not getattr(ctx.attr, "_allowlist_java_import_exports")[PackageSpecificationInfo].contains(ctx.label)
+    disallow_java_import_exports = ctx.fragments.java.disallow_java_import_exports()
+
+    if len(exports) != 0 and (disallow_java_import_exports or not_in_allowlist):
+        fail("java_import.exports is no longer supported; use java_import.deps instead")
+
+def _check_empty_jars_error(ctx, jars):
+    # TODO(kotlaja): Remove temporary incompatible flag [disallow_java_import_empty_jars] once migration is done.
+    not_in_allowlist = hasattr(ctx.attr, "_allowlist_java_import_empty_jars") and not getattr(ctx.attr, "_allowlist_java_import_empty_jars")[PackageSpecificationInfo].contains(ctx.label)
+    disallow_java_import_empty_jars = ctx.fragments.java.disallow_java_import_empty_jars()
+
+    if len(jars) == 0 and disallow_java_import_empty_jars and not_in_allowlist:
+        fail("empty java_import.jars is no longer supported " + ctx.label.package)
+
+def _create_java_info_with_dummy_output_file(ctx, srcjar, all_deps, exports, runtime_deps_list, neverlink, cc_info_list, add_exports, add_opens):
+    dummy_jar = ctx.actions.declare_file(ctx.label.name + "_dummy.jar")
+    dummy_src_jar = srcjar
+    if dummy_src_jar == None:
+        dummy_src_jar = ctx.actions.declare_file(ctx.label.name + "_src_dummy.java")
+        ctx.actions.write(dummy_src_jar, "")
+    return java_common.compile(
+        ctx,
+        output = dummy_jar,
+        java_toolchain = semantics.find_java_toolchain(ctx),
+        source_files = [dummy_src_jar],
+        deps = all_deps,
+        runtime_deps = runtime_deps_list,
+        neverlink = neverlink,
+        exports = [export[JavaInfo] for export in exports if JavaInfo in export],  # Watchout, maybe you need to add them there manually.
+        native_libraries = cc_info_list,
+        add_exports = add_exports,
+        add_opens = add_opens,
+    )
+
+def bazel_java_import_rule(
+        ctx,
+        jars = [],
+        srcjar = None,
+        deps = [],
+        runtime_deps = [],
+        exports = [],
+        neverlink = False,
+        proguard_specs = [],
+        add_exports = [],
+        add_opens = []):
+    """Implements java_import.
+
+    This rule allows the use of precompiled .jar files as libraries in other Java rules.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      jars: (list[Artifact]) List of output jars.
+      srcjar: (Artifact) The jar containing the sources.
+      deps: (list[Target]) The list of dependent libraries.
+      runtime_deps: (list[Target]) Runtime dependencies to attach to the rule.
+      exports: (list[Target])  The list of exported libraries.
+      neverlink: (bool) Whether this rule should only be used for compilation and not at runtime.
+      proguard_specs: (list[File]) Files to be used as Proguard specification.
+      add_exports: (list[str]) Allow this library to access the given <module>/<package>.
+      add_opens: (list[str]) Allow this library to reflectively access the given <module>/<package>.
+
+    Returns:
+      (list[provider]) A list containing DefaultInfo, JavaInfo,
+      OutputGroupsInfo, ProguardSpecProvider providers.
+    """
+
+    _check_empty_jars_error(ctx, jars)
+    _check_export_error(ctx, exports)
+
+    collected_jars = _collect_jars(ctx, jars)
+    all_deps = _filter_provider(JavaInfo, deps, exports)
+
+    jdeps_artifact = None
+    merged_java_info = java_common.merge(all_deps)
+    not_in_allowlist = hasattr(ctx.attr, "_allowlist_java_import_deps_checking") and not ctx.attr._allowlist_java_import_deps_checking[PackageSpecificationInfo].contains(ctx.label)
+    if len(collected_jars) > 0 and not_in_allowlist and "incomplete-deps" not in ctx.attr.tags:
+        jdeps_artifact = import_deps_check(
+            ctx,
+            collected_jars,
+            merged_java_info.compile_jars,
+            merged_java_info.transitive_compile_time_jars,
+            "java_import",
+        )
+
+    compilation_to_runtime_jar_map = _process_with_ijars_if_needed(collected_jars, ctx)
+    runtime_deps_list = [runtime_dep[JavaInfo] for runtime_dep in runtime_deps if JavaInfo in runtime_dep]
+    cc_info_list = [dep[CcInfo] for dep in deps if CcInfo in dep]
+    java_info = None
+    if len(collected_jars) > 0:
+        java_infos = []
+        for jar in collected_jars:
+            java_infos.append(JavaInfo(
+                output_jar = jar,
+                compile_jar = compilation_to_runtime_jar_map[jar],
+                deps = all_deps,
+                runtime_deps = runtime_deps_list,
+                neverlink = neverlink,
+                source_jar = srcjar,
+                exports = [export[JavaInfo] for export in exports if JavaInfo in export],  # Watchout, maybe you need to add them there manually.
+                native_libraries = cc_info_list,
+                add_exports = add_exports,
+                add_opens = add_opens,
+            ))
+        java_info = java_common.merge(java_infos)
+    else:
+        # TODO(kotlaja): Remove next line once all java_import targets with empty jars attribute are cleaned from depot (b/246559727).
+        java_info = _create_java_info_with_dummy_output_file(ctx, srcjar, all_deps, exports, runtime_deps_list, neverlink, cc_info_list, add_exports, add_opens)
+
+    target = {"JavaInfo": java_info}
+
+    target["ProguardSpecProvider"] = validate_proguard_specs(
+        ctx,
+        proguard_specs,
+        [deps, runtime_deps, exports],
+    )
+
+    # TODO(kotlaja): Revise if collected_runtimes can be added into construct_defaultinfo directly.
+    collected_runtimes = []
+    for runtime_dep in ctx.attr.runtime_deps:
+        collected_runtimes.extend(runtime_dep.files.to_list())
+
+    target["DefaultInfo"] = construct_defaultinfo(
+        ctx,
+        collected_jars,
+        collected_jars + collected_runtimes,
+        neverlink,
+        exports,
+    )
+
+    output_group_src_jars = depset() if srcjar == None else depset([srcjar])
+    target["OutputGroupInfo"] = OutputGroupInfo(
+        **{
+            "_source_jars": output_group_src_jars,
+            "_direct_source_jars": output_group_src_jars,
+            "_validation": depset() if jdeps_artifact == None else depset([jdeps_artifact]),
+            "_hidden_top_level_INTERNAL_": target["ProguardSpecProvider"].specs,
+        }
+    )
+    return target
diff --git a/java/common/rules/impl/bazel_java_library_impl.bzl b/java/common/rules/impl/bazel_java_library_impl.bzl
new file mode 100644
index 0000000..04a020e
--- /dev/null
+++ b/java/common/rules/impl/bazel_java_library_impl.bzl
@@ -0,0 +1,98 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_library rule.
+"""
+
+load("//java/common/rules/impl:basic_java_library_impl.bzl", "basic_java_library", "construct_defaultinfo")
+
+# copybara: default visibility
+
+def bazel_java_library_rule(
+        ctx,
+        srcs = [],
+        deps = [],
+        runtime_deps = [],
+        plugins = [],
+        exports = [],
+        exported_plugins = [],
+        resources = [],
+        javacopts = [],
+        neverlink = False,
+        proguard_specs = [],
+        add_exports = [],
+        add_opens = [],
+        bootclasspath = None,
+        javabuilder_jvm_flags = None):
+    """Implements java_library.
+
+    Use this call when you need to produce a fully fledged java_library from
+    another rule's implementation.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      srcs: (list[File]) The list of source files that are processed to create the target.
+      deps: (list[Target]) The list of other libraries to be linked in to the target.
+      runtime_deps: (list[Target]) Libraries to make available to the final binary or test at runtime only.
+      plugins: (list[Target]) Java compiler plugins to run at compile-time.
+      exports: (list[Target]) Exported libraries.
+      exported_plugins: (list[Target]) The list of `java_plugin`s (e.g. annotation
+        processors) to export to libraries that directly depend on this library.
+      resources: (list[File]) A list of data files to include in a Java jar.
+      javacopts: (list[str]) Extra compiler options for this library.
+      neverlink: (bool) Whether this library should only be used for compilation and not at runtime.
+      proguard_specs: (list[File]) Files to be used as Proguard specification.
+      add_exports: (list[str]) Allow this library to access the given <module>/<package>.
+      add_opens: (list[str]) Allow this library to reflectively access the given <module>/<package>.
+      bootclasspath: (Target) The JDK APIs to compile this library against.
+      javabuilder_jvm_flags: (list[str]) Additional JVM flags to pass to JavaBuilder.
+    Returns:
+      (dict[str, provider]) A list containing DefaultInfo, JavaInfo,
+        InstrumentedFilesInfo, OutputGroupsInfo, ProguardSpecProvider providers.
+    """
+    if not srcs and deps:
+        fail("deps not allowed without srcs; move to runtime_deps?")
+
+    target, base_info = basic_java_library(
+        ctx,
+        srcs,
+        deps,
+        runtime_deps,
+        plugins,
+        exports,
+        exported_plugins,
+        resources,
+        [],  # resource_jars
+        [],  # class_pathresources
+        javacopts,
+        neverlink,
+        proguard_specs = proguard_specs,
+        add_exports = add_exports,
+        add_opens = add_opens,
+        bootclasspath = bootclasspath,
+        javabuilder_jvm_flags = javabuilder_jvm_flags,
+    )
+
+    target["DefaultInfo"] = construct_defaultinfo(
+        ctx,
+        base_info.files_to_build,
+        base_info.runfiles,
+        neverlink,
+        exports,
+        runtime_deps,
+    )
+    target["OutputGroupInfo"] = OutputGroupInfo(**base_info.output_groups)
+
+    return target
diff --git a/java/common/rules/impl/compile_action.bzl b/java/common/rules/impl/compile_action.bzl
new file mode 100644
index 0000000..bf5b935
--- /dev/null
+++ b/java/common/rules/impl/compile_action.bzl
@@ -0,0 +1,174 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Java compile action
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/private:java_common_internal.bzl", _compile_private_for_builtins = "compile")
+
+visibility("private")
+
+def _filter_strict_deps(mode):
+    return "error" if mode in ["strict", "default"] else mode
+
+def _collect_plugins(deps, plugins):
+    transitive_processor_jars = []
+    transitive_processor_data = []
+    for plugin in plugins:
+        transitive_processor_jars.append(plugin.plugins.processor_jars)
+        transitive_processor_data.append(plugin.plugins.processor_data)
+    for dep in deps:
+        transitive_processor_jars.append(dep.plugins.processor_jars)
+        transitive_processor_data.append(dep.plugins.processor_data)
+    return struct(
+        processor_jars = depset(transitive = transitive_processor_jars),
+        processor_data = depset(transitive = transitive_processor_data),
+    )
+
+def compile_action(
+        ctx,
+        output_class_jar,
+        output_source_jar,
+        source_files = [],
+        source_jars = [],
+        deps = [],
+        runtime_deps = [],
+        plugins = [],
+        exports = [],
+        exported_plugins = [],
+        resources = [],
+        resource_jars = [],
+        classpath_resources = [],
+        native_libraries = [],
+        javacopts = [],
+        neverlink = False,
+        strict_deps = "ERROR",
+        enable_compile_jar_action = True,
+        add_exports = [],
+        add_opens = [],
+        bootclasspath = None,
+        javabuilder_jvm_flags = None):
+    """
+    Creates actions that compile Java sources, produce source jar, and produce header jar and returns JavaInfo.
+
+    Use this call when you need the most basic and consistent Java compilation.
+
+    Most parameters correspond to attributes on a java_library (srcs, deps,
+    plugins, resources ...) except they are more strict, for example:
+
+    - Where java_library's srcs attribute allows mixing of .java, .srcjar, and
+     .properties files the arguments accepted by this call should be strictly
+     separated into source_files, source_jars, and resources parameter.
+    - deps parameter accepts only JavaInfo providers and plugins parameter only
+     JavaPluginInfo
+
+    The call creates following actions and files:
+    - compiling Java sources to a class jar (output_class_jar parameter)
+    - a source jar (output_source_jar parameter)
+    - optionally a jar containing plugin generated classes when plugins are present
+    - optionally a jar containing plugin generated sources
+    - jdeps file containing dependencies used during compilation
+    - other files used to speed up incremental builds:
+         - a header jar - a jar containing only method signatures without implementation
+         - compile jdeps - dependencies used during header compilation
+
+    The returned JavaInfo provider may be used as a "fully-qualified" dependency
+    to a java_library.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      output_class_jar: (File) Output class .jar file. The file needs to be declared.
+      output_source_jar: (File) Output source .jar file. The file needs to be declared.
+      source_files: (list[File]) A list of .java source files to compile.
+        At least one of source_files or source_jars parameter must be specified.
+      source_jars: (list[File]) A list of .jar or .srcjar files containing
+        source files to compile.
+        At least one of source_files or source_jars parameter must be specified.
+      deps: (list[JavaInfo]) A list of dependencies.
+      runtime_deps: (list[JavaInfo]) A list of runtime dependencies.
+      plugins: (list[JavaPluginInfo]) A list of plugins.
+      exports: (list[JavaInfo]) A list of exports.
+      exported_plugins: (list[JavaInfo]) A list of exported plugins.
+      resources: (list[File]) A list of resources.
+      resource_jars: (list[File]) A list of jars to unpack.
+      classpath_resources: (list[File]) A list of classpath resources.
+      native_libraries: (list[CcInfo]) C++ native library dependencies that are
+        needed for this library.
+      javacopts: (list[str]) A list of the desired javac options. The options
+        may contain `$(location ..)` templates that will be expanded.
+      neverlink: (bool) Whether or not this library should be used only for
+        compilation and not at runtime.
+      strict_deps: (str) A string that specifies how to handle strict deps.
+        Possible values: 'OFF', 'ERROR', 'WARN' and 'DEFAULT'. For more details
+        see https://bazel.build/docs/user-manual#strict-java-deps.
+        By default 'ERROR'.
+      enable_compile_jar_action: (bool) Enables header compilation or ijar
+        creation. If set to False, it forces use of the full class jar in the
+        compilation classpaths of any dependants. Doing so is intended for use
+        by non-library targets such as binaries that do not have dependants.
+      add_exports: (list[str]) Allow this library to access the given <module>/<package>.
+      add_opens: (list[str]) Allow this library to reflectively access the given <module>/<package>.
+      bootclasspath: (BootClassPathInfo) The set of JDK APIs to compile this library against.
+      javabuilder_jvm_flags: (list[str]) Additional JVM flags to pass to JavaBuilder.
+
+    Returns:
+      ((JavaInfo, {files_to_build: list[File],
+                   runfiles: list[File],
+                   compilation_classpath: list[File],
+                   plugins: {processor_jars,
+                             processor_data: depset[File]}}))
+      A tuple with JavaInfo provider and additional compilation info.
+
+      Files_to_build may include an empty .jar file when there are no sources
+      or resources present, whereas runfiles in this case are empty.
+    """
+
+    java_info = _compile_private_for_builtins(
+        ctx,
+        output = output_class_jar,
+        java_toolchain = semantics.find_java_toolchain(ctx),
+        source_files = source_files,
+        source_jars = source_jars,
+        resources = resources,
+        resource_jars = resource_jars,
+        classpath_resources = classpath_resources,
+        plugins = plugins,
+        deps = deps,
+        native_libraries = native_libraries,
+        runtime_deps = runtime_deps,
+        exports = exports,
+        exported_plugins = exported_plugins,
+        javac_opts = [ctx.expand_location(opt) for opt in javacopts],
+        neverlink = neverlink,
+        output_source_jar = output_source_jar,
+        strict_deps = _filter_strict_deps(strict_deps),
+        enable_compile_jar_action = enable_compile_jar_action,
+        add_exports = add_exports,
+        add_opens = add_opens,
+        bootclasspath = bootclasspath,
+        javabuilder_jvm_flags = javabuilder_jvm_flags,
+    )
+
+    compilation_info = struct(
+        files_to_build = [output_class_jar],
+        runfiles = [output_class_jar] if source_files or source_jars or resources else [],
+        # TODO(ilist): collect compile_jars from JavaInfo in deps & exports
+        compilation_classpath = java_info.compilation_info.compilation_classpath,
+        javac_options = java_info.compilation_info.javac_options,
+        plugins = _collect_plugins(deps, plugins),
+    )
+
+    return java_info, compilation_info
diff --git a/java/common/rules/impl/import_deps_check.bzl b/java/common/rules/impl/import_deps_check.bzl
new file mode 100644
index 0000000..306a40c
--- /dev/null
+++ b/java/common/rules/impl/import_deps_check.bzl
@@ -0,0 +1,81 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Creates the import deps checker for java rules"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+
+visibility(["//java/common/rules/..."])
+
+def import_deps_check(
+        ctx,
+        jars_to_check,
+        declared_deps,
+        transitive_deps,
+        rule_class):
+    """
+    Creates actions that checks import deps for java rules.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      jars_to_check: (list[File])  A list of jars files to check.
+      declared_deps: (list[File]) A list of direct dependencies.
+      transitive_deps: (list[File]) A list of transitive dependencies.
+      rule_class: (String) Rule class.
+
+    Returns:
+      (File) Output file of the created action.
+    """
+    java_toolchain = semantics.find_java_toolchain(ctx)
+    deps_checker = java_toolchain._deps_checker
+    if deps_checker == None:
+        return None
+
+    jdeps_output = ctx.actions.declare_file("_%s/%s/jdeps.proto" % (rule_class, ctx.label.name))
+
+    args = ctx.actions.args()
+    args.add("-jar", deps_checker)
+    args.add_all(jars_to_check, before_each = "--input")
+    args.add_all(declared_deps, before_each = "--directdep")
+    args.add_all(
+        depset(order = "preorder", transitive = [declared_deps, transitive_deps]),
+        before_each = "--classpath_entry",
+    )
+    args.add_all(java_toolchain.bootclasspath, before_each = "--bootclasspath_entry")
+    args.add("--checking_mode=error")
+    args.add("--jdeps_output", jdeps_output)
+    args.add("--rule_label", ctx.label)
+
+    inputs = depset(
+        jars_to_check,
+        transitive = [
+            declared_deps,
+            transitive_deps,
+            java_toolchain.bootclasspath,
+        ],
+    )
+    tools = [deps_checker, java_toolchain.java_runtime.files]
+
+    ctx.actions.run(
+        mnemonic = "ImportDepsChecker",
+        progress_message = "Checking the completeness of the deps for %s" % jars_to_check,
+        executable = java_toolchain.java_runtime.java_executable_exec_path,
+        arguments = [args],
+        inputs = inputs,
+        outputs = [jdeps_output],
+        tools = tools,
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+    )
+
+    return jdeps_output
diff --git a/java/common/rules/impl/java_binary_deploy_jar.bzl b/java/common/rules/impl/java_binary_deploy_jar.bzl
new file mode 100644
index 0000000..8755d95
--- /dev/null
+++ b/java/common/rules/impl/java_binary_deploy_jar.bzl
@@ -0,0 +1,240 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Auxiliary rule to create the deploy archives for java_binary"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load(":java_helper.bzl", "helper")
+
+# copybara: default visibility
+
+def _get_build_info(ctx, stamp):
+    if helper.is_stamping_enabled(ctx, stamp):
+        # Makes the target depend on BUILD_INFO_KEY, which helps to discover stamped targets
+        # See b/326620485 for more details.
+        ctx.version_file  # buildifier: disable=no-effect
+        return ctx.attr._build_info_translator[OutputGroupInfo].non_redacted_build_info_files.to_list()
+    else:
+        return ctx.attr._build_info_translator[OutputGroupInfo].redacted_build_info_files.to_list()
+
+def create_deploy_archives(
+        ctx,
+        java_attrs,
+        launcher_info,
+        main_class,
+        coverage_main_class,
+        strip_as_default,
+        hermetic = False,
+        add_exports = depset(),
+        add_opens = depset(),
+        one_version_level = "OFF",
+        one_version_allowlist = None,
+        extra_args = [],
+        extra_manifest_lines = []):
+    """ Registers actions for _deploy.jar and _deploy.jar.unstripped
+
+    Args:
+        ctx: (RuleContext) The rule context
+        java_attrs: (Struct) Struct of (classpath_resources, runtime_jars, runtime_classpath_for_archive, resources)
+        launcher_info: (Struct) Struct of (runtime_jars, launcher, unstripped_launcher)
+        main_class: (String) FQN of the entry point for execution
+        coverage_main_class: (String) FQN of the entry point for coverage collection
+        strip_as_default: (bool) Whether to create unstripped deploy jar
+        hermetic: (bool)
+        add_exports: (depset)
+        add_opens: (depset)
+        one_version_level: (String) Optional one version check level, default OFF
+        one_version_allowlist: (File) Optional allowlist for one version check
+        extra_args: (list[Args]) Optional arguments for the deploy jar action
+        extra_manifest_lines: (list[String]) Optional lines added to the jar manifest
+    """
+    classpath_resources = java_attrs.classpath_resources
+
+    runtime_classpath = depset(
+        direct = launcher_info.runtime_jars,
+        transitive = [
+            java_attrs.runtime_jars,
+            java_attrs.runtime_classpath_for_archive,
+        ],
+        order = "preorder",
+    )
+    multi_release = ctx.fragments.java.multi_release_deploy_jars
+    build_info_files = _get_build_info(ctx, ctx.attr.stamp)
+    build_target = str(ctx.label)
+    manifest_lines = ctx.attr.deploy_manifest_lines + extra_manifest_lines
+    create_deploy_archive(
+        ctx,
+        launcher_info.launcher,
+        main_class,
+        coverage_main_class,
+        java_attrs.resources,
+        classpath_resources,
+        runtime_classpath,
+        manifest_lines,
+        build_info_files,
+        build_target,
+        output = ctx.outputs.deployjar,
+        one_version_level = one_version_level,
+        one_version_allowlist = one_version_allowlist,
+        multi_release = multi_release,
+        hermetic = hermetic,
+        add_exports = add_exports,
+        add_opens = add_opens,
+        extra_args = extra_args,
+    )
+
+    if strip_as_default:
+        create_deploy_archive(
+            ctx,
+            launcher_info.unstripped_launcher,
+            main_class,
+            coverage_main_class,
+            java_attrs.resources,
+            classpath_resources,
+            runtime_classpath,
+            manifest_lines,
+            build_info_files,
+            build_target,
+            output = ctx.outputs.unstrippeddeployjar,
+            multi_release = multi_release,
+            hermetic = hermetic,
+            add_exports = add_exports,
+            add_opens = add_opens,
+            extra_args = extra_args,
+        )
+    else:
+        ctx.actions.write(ctx.outputs.unstrippeddeployjar, "")
+
+def create_deploy_archive(
+        ctx,
+        launcher,
+        main_class,
+        coverage_main_class,
+        resources,
+        classpath_resources,
+        runtime_classpath,
+        manifest_lines,
+        build_info_files,
+        build_target,
+        output,
+        one_version_level = "OFF",
+        one_version_allowlist = None,
+        multi_release = False,
+        hermetic = False,
+        add_exports = [],
+        add_opens = [],
+        extra_args = []):
+    """ Creates a deploy jar
+
+    Requires a Java runtime toolchain if and only if hermetic is True.
+
+    Args:
+        ctx: (RuleContext) The rule context
+        launcher: (File) the launcher artifact
+        main_class: (String) FQN of the entry point for execution
+        coverage_main_class: (String) FQN of the entry point for coverage collection
+        resources: (Depset) resource inputs
+        classpath_resources: (Depset) classpath resource inputs
+        runtime_classpath: (Depset) source files to add to the jar
+        build_target: (String) Name of the build target for stamping
+        manifest_lines: (list[String]) Optional lines added to the jar manifest
+        build_info_files: (list[File]) build info files for stamping
+        build_target: (String) the owner build target label name string
+        output: (File) the output jar artifact
+        one_version_level: (String) Optional one version check level, default OFF
+        one_version_allowlist: (File) Optional allowlist for one version check
+        multi_release: (bool)
+        hermetic: (bool)
+        add_exports: (depset)
+        add_opens: (depset)
+        extra_args: (list[Args]) Optional arguments for the deploy jar action
+    """
+    input_files = []
+    input_files.extend(build_info_files)
+
+    transitive_input_files = [
+        resources,
+        classpath_resources,
+        runtime_classpath,
+    ]
+
+    single_jar = semantics.find_java_toolchain(ctx).single_jar
+
+    manifest_lines = list(manifest_lines)
+    if ctx.configuration.coverage_enabled:
+        manifest_lines.append("Coverage-Main-Class: %s" % coverage_main_class)
+
+    args = ctx.actions.args()
+    args.set_param_file_format("shell").use_param_file("@%s", use_always = True)
+
+    args.add("--output", output)
+    args.add("--build_target", build_target)
+    args.add("--normalize")
+    args.add("--compression")
+    if main_class:
+        args.add("--main_class", main_class)
+    args.add_all("--deploy_manifest_lines", manifest_lines)
+    args.add_all(build_info_files, before_each = "--build_info_file")
+    if launcher:
+        input_files.append(launcher)
+        args.add("--java_launcher", launcher)
+    args.add_all("--classpath_resources", classpath_resources)
+    args.add_all(
+        "--sources",
+        runtime_classpath,
+        map_each = helper.jar_and_target_arg_mapper,
+    )
+
+    if one_version_level != "OFF" and one_version_allowlist:
+        input_files.append(one_version_allowlist)
+        args.add("--enforce_one_version")
+        args.add("--one_version_allowlist", one_version_allowlist)
+        if one_version_level == "WARNING":
+            args.add("--succeed_on_found_violations")
+
+    if multi_release:
+        args.add("--multi_release")
+
+    if hermetic:
+        runtime = ctx.toolchains["@//tools/jdk/hermetic:hermetic_runtime_toolchain_type"].java_runtime
+        if runtime.lib_modules != None:
+            java_home = runtime.java_home
+            lib_modules = runtime.lib_modules
+            hermetic_files = runtime.hermetic_files
+            default_cds = runtime.default_cds
+            args.add("--hermetic_java_home", java_home)
+            args.add("--jdk_lib_modules", lib_modules)
+            args.add_all("--resources", hermetic_files)
+            input_files.append(lib_modules)
+            transitive_input_files.append(hermetic_files)
+            if default_cds:
+                input_files.append(default_cds)
+                args.add("--cds_archive", default_cds)
+
+    args.add_all("--add_exports", add_exports)
+    args.add_all("--add_opens", add_opens)
+
+    inputs = depset(input_files, transitive = transitive_input_files)
+
+    ctx.actions.run(
+        mnemonic = "JavaDeployJar",
+        progress_message = "Building deploy jar %s" % output.short_path,
+        executable = single_jar,
+        inputs = inputs,
+        tools = [single_jar],
+        outputs = [output],
+        arguments = [args] + extra_args,
+        use_default_shell_env = True,
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+    )
diff --git a/java/common/rules/impl/java_binary_impl.bzl b/java/common/rules/impl/java_binary_impl.bzl
new file mode 100644
index 0000000..7de9d30
--- /dev/null
+++ b/java/common/rules/impl/java_binary_impl.bzl
@@ -0,0 +1,460 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+""" Implementation of java_binary for bazel """
+
+load("@com_google_protobuf//bazel/common:proto_info.bzl", "ProtoInfo")
+load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules/impl:basic_java_library_impl.bzl", "basic_java_library", "collect_deps")
+load("//java/private:java_common.bzl", "java_common")
+load(
+    "//java/private:java_common_internal.bzl",
+    "collect_native_deps_dirs",
+    "get_runtime_classpath_for_archive",
+)
+load("//java/private:java_info.bzl", "JavaCompilationInfo", "JavaInfo", "to_java_binary_info")
+load(":java_binary_deploy_jar.bzl", "create_deploy_archive")
+load(":java_helper.bzl", "helper")
+
+# copybara: default visibility
+
+InternalDeployJarInfo = provider(
+    "Provider for passing info to deploy jar rule",
+    fields = [
+        "java_attrs",
+        "strip_as_default",
+        "add_exports",
+        "add_opens",
+    ],
+)
+
+def basic_java_binary(
+        ctx,
+        deps,
+        runtime_deps,
+        resources,
+        main_class,
+        coverage_main_class,
+        coverage_config,
+        launcher_info,
+        executable,
+        strip_as_default,
+        extra_java_info = None,
+        is_test_rule_class = False):
+    """Creates actions for compiling and linting java sources, coverage support, and sources jar (_deploy-src.jar).
+
+    Args:
+        ctx: (RuleContext) The rule context
+        deps: (list[Target]) The list of other targets to be compiled with
+        runtime_deps: (list[Target]) The list of other targets to be linked in
+        resources: (list[File]) The list of data files to be included in the class jar
+        main_class: (String) FQN of the java main class
+        coverage_main_class: (String) FQN of the actual main class if coverage is enabled
+        coverage_config: (Struct|None) If coverage is enabled, a struct with fields (runner, manifest, env, support_files), None otherwise
+        launcher_info: (Struct) Structure with fields (launcher, unstripped_launcher, runfiles, runtime_jars, jvm_flags, classpath_resources)
+        executable: (File) The executable output of the rule
+        strip_as_default: (bool) Whether this target outputs a stripped launcher and deploy jar
+        extra_java_info: (JavaInfo) additional outputs to merge
+        is_test_rule_class: (bool) Whether this rule is a test rule
+
+    Returns:
+        Tuple(
+            dict[str, Provider],    // providers
+            Struct(                 // default info
+                files_to_build: depset(File),
+                runfiles: Runfiles,
+                executable: File
+            ),
+            list[String]            // jvm flags
+          )
+
+    """
+    if not ctx.attr.create_executable and (ctx.attr.launcher and cc_common.launcher_provider in ctx.attr.launcher):
+        fail("launcher specified but create_executable is false")
+    if not ctx.attr.use_launcher and (ctx.attr.launcher and ctx.attr.launcher.label != semantics.LAUNCHER_FLAG_LABEL):
+        fail("launcher specified but use_launcher is false")
+
+    if not ctx.attr.srcs and ctx.attr.deps:
+        fail("deps not allowed without srcs; move to runtime_deps?")
+
+    module_flags = [dep[JavaInfo].module_flags_info for dep in runtime_deps if JavaInfo in dep]
+    add_exports = depset(ctx.attr.add_exports, transitive = [m.add_exports for m in module_flags])
+    add_opens = depset(ctx.attr.add_opens, transitive = [m.add_opens for m in module_flags])
+
+    classpath_resources = []
+    classpath_resources.extend(launcher_info.classpath_resources)
+    if hasattr(ctx.files, "classpath_resources"):
+        classpath_resources.extend(ctx.files.classpath_resources)
+
+    toolchain = semantics.find_java_toolchain(ctx)
+    timezone_data = [toolchain._timezone_data] if toolchain._timezone_data else []
+    target, common_info = basic_java_library(
+        ctx,
+        srcs = ctx.files.srcs,
+        deps = deps,
+        runtime_deps = runtime_deps,
+        plugins = ctx.attr.plugins,
+        resources = resources,
+        resource_jars = timezone_data,
+        classpath_resources = classpath_resources,
+        javacopts = ctx.attr.javacopts,
+        neverlink = ctx.attr.neverlink,
+        enable_compile_jar_action = False,
+        coverage_config = coverage_config,
+        add_exports = ctx.attr.add_exports,
+        add_opens = ctx.attr.add_opens,
+        bootclasspath = ctx.attr.bootclasspath,
+    )
+    java_info = target["JavaInfo"]
+    compilation_info = java_info.compilation_info
+    runtime_classpath = depset(
+        order = "preorder",
+        transitive = [
+            java_info.transitive_runtime_jars
+            for java_info in (
+                collect_deps(ctx.attr.runtime_deps + deps) +
+                ([coverage_config.runner] if coverage_config and coverage_config.runner else [])
+            )
+        ],
+    )
+    if extra_java_info:
+        runtime_classpath = depset(order = "preorder", transitive = [
+            extra_java_info.transitive_runtime_jars,
+            runtime_classpath,
+        ])
+        java_info = java_common.merge([java_info, extra_java_info])
+        compilation_info = JavaCompilationInfo(
+            compilation_classpath = compilation_info.compilation_classpath,
+            runtime_classpath = runtime_classpath,
+            boot_classpath = compilation_info.boot_classpath,
+            javac_options = compilation_info.javac_options,
+        )
+
+    java_attrs = _collect_attrs(ctx, runtime_classpath, classpath_resources)
+
+    jvm_flags = []
+
+    jvm_flags.extend(launcher_info.jvm_flags)
+
+    native_libs_depsets = []
+    for dep in runtime_deps:
+        if JavaInfo in dep:
+            native_libs_depsets.append(dep[JavaInfo].transitive_native_libraries)
+        if CcInfo in dep:
+            native_libs_depsets.append(dep[CcInfo].transitive_native_libraries())
+    native_libs_dirs = collect_native_deps_dirs(depset(transitive = native_libs_depsets))
+    if native_libs_dirs:
+        prefix = "${JAVA_RUNFILES}/" + ctx.workspace_name + "/"
+        jvm_flags.append("-Djava.library.path=%s" % (
+            ":".join([prefix + d for d in native_libs_dirs])
+        ))
+
+    jvm_flags.extend(ctx.fragments.java.default_jvm_opts)
+    jvm_flags.extend([ctx.expand_make_variables(
+        "jvm_flags",
+        ctx.expand_location(flag, ctx.attr.data, short_paths = True),
+        {},
+    ) for flag in ctx.attr.jvm_flags])
+
+    # TODO(cushon): make string formatting lazier once extend_template support is added
+    # https://github.com/bazelbuild/proposals#:~:text=2022%2D04%2D25,Starlark
+    jvm_flags.extend(["--add-exports=%s=ALL-UNNAMED" % x for x in add_exports.to_list()])
+    jvm_flags.extend(["--add-opens=%s=ALL-UNNAMED" % x for x in add_opens.to_list()])
+
+    files_to_build = []
+
+    if executable:
+        files_to_build.append(executable)
+
+    output_groups = common_info.output_groups
+
+    if coverage_config:
+        _generate_coverage_manifest(ctx, coverage_config.manifest, java_attrs.runtime_classpath)
+        files_to_build.append(coverage_config.manifest)
+
+    if extra_java_info:
+        files_to_build.extend(extra_java_info.runtime_output_jars)
+        output_groups["_direct_source_jars"] = (
+            output_groups["_direct_source_jars"] + extra_java_info.source_jars
+        )
+        output_groups["_source_jars"] = depset(
+            direct = extra_java_info.source_jars,
+            transitive = [output_groups["_source_jars"]],
+        )
+
+    if (ctx.fragments.java.one_version_enforcement_on_java_tests or not is_test_rule_class):
+        one_version_output = _create_one_version_check(ctx, java_attrs.runtime_classpath, is_test_rule_class)
+    else:
+        one_version_output = None
+
+    validation_outputs = [one_version_output] if one_version_output else []
+
+    _create_deploy_sources_jar(ctx, output_groups["_source_jars"])
+
+    files = depset(files_to_build + common_info.files_to_build)
+
+    transitive_runfiles_artifacts = depset(transitive = [
+        files,
+        java_attrs.runtime_classpath,
+        depset(transitive = launcher_info.runfiles),
+    ])
+
+    runfiles = ctx.runfiles(
+        transitive_files = transitive_runfiles_artifacts,
+        collect_default = True,
+    )
+
+    if launcher_info.launcher:
+        default_launcher = helper.filter_launcher_for_target(ctx)
+        default_launcher_artifact = helper.launcher_artifact_for_target(ctx)
+        default_launcher_runfiles = default_launcher[DefaultInfo].default_runfiles
+        if default_launcher_artifact == launcher_info.launcher:
+            runfiles = runfiles.merge(default_launcher_runfiles)
+        else:
+            # N.B. The "default launcher" referred to here is the launcher target specified through
+            # an attribute or flag. We wish to retain the runfiles of the default launcher, *except*
+            # for the original cc_binary artifact, because we've swapped it out with our custom
+            # launcher. Hence, instead of calling builder.addTarget(), or adding an odd method
+            # to Runfiles.Builder, we "unravel" the call and manually add things to the builder.
+            # Because the NestedSet representing each target's launcher runfiles is re-built here,
+            # we may see increased memory consumption for representing the target's runfiles.
+            runfiles = runfiles.merge(
+                ctx.runfiles(
+                    files = [launcher_info.launcher],
+                    transitive_files = depset([
+                        file
+                        for file in default_launcher_runfiles.files.to_list()
+                        if file != default_launcher_artifact
+                    ]),
+                    symlinks = default_launcher_runfiles.symlinks,
+                    root_symlinks = default_launcher_runfiles.root_symlinks,
+                ),
+            )
+
+    runfiles = runfiles.merge_all([
+        dep[DefaultInfo].default_runfiles
+        for dep in ctx.attr.runtime_deps
+        if DefaultInfo in dep
+    ])
+
+    if validation_outputs:
+        output_groups["_validation"] = output_groups.get("_validation", []) + validation_outputs
+
+    _filter_validation_output_group(ctx, output_groups)
+
+    java_binary_info = to_java_binary_info(java_info, compilation_info)
+
+    internal_deploy_jar_info = InternalDeployJarInfo(
+        java_attrs = java_attrs,
+        strip_as_default = strip_as_default,
+        add_exports = add_exports,
+        add_opens = add_opens,
+    )
+
+    # "temporary" workaround for https://github.com/bazelbuild/intellij/issues/5845
+    extra_files = []
+    if is_test_rule_class and ctx.fragments.java.auto_create_java_test_deploy_jars():
+        extra_files.append(_auto_create_deploy_jar(ctx, internal_deploy_jar_info, launcher_info, main_class, coverage_main_class))
+
+    default_info = struct(
+        files = depset(extra_files, transitive = [files]),
+        runfiles = runfiles,
+        executable = executable,
+    )
+
+    return {
+        "OutputGroupInfo": OutputGroupInfo(**output_groups),
+        "JavaInfo": java_binary_info,
+        "InstrumentedFilesInfo": target["InstrumentedFilesInfo"],
+        "JavaRuntimeClasspathInfo": java_common.JavaRuntimeClasspathInfo(runtime_classpath = java_info.transitive_runtime_jars),
+        "InternalDeployJarInfo": internal_deploy_jar_info,
+    }, default_info, jvm_flags
+
+def _collect_attrs(ctx, runtime_classpath, classpath_resources):
+    deploy_env_jars = depset(transitive = [
+        dep[java_common.JavaRuntimeClasspathInfo].runtime_classpath
+        for dep in ctx.attr.deploy_env
+    ]) if hasattr(ctx.attr, "deploy_env") else depset()
+
+    runtime_classpath_for_archive = get_runtime_classpath_for_archive(runtime_classpath, deploy_env_jars)
+    runtime_jars = [ctx.outputs.classjar]
+
+    resources = [p for p in ctx.files.srcs if p.extension == "properties"]
+    transitive_resources = []
+    for r in ctx.attr.resources:
+        transitive_resources.append(
+            r[ProtoInfo].transitive_sources if ProtoInfo in r else r.files,
+        )
+
+    resource_names = dict()
+    for r in classpath_resources:
+        if r.basename in resource_names:
+            fail("entries must have different file names (duplicate: %s)" % r.basename)
+        resource_names[r.basename] = None
+
+    return struct(
+        runtime_jars = depset(runtime_jars),
+        runtime_classpath_for_archive = runtime_classpath_for_archive,
+        classpath_resources = depset(classpath_resources),
+        runtime_classpath = depset(order = "preorder", direct = runtime_jars, transitive = [runtime_classpath]),
+        resources = depset(resources, transitive = transitive_resources),
+    )
+
+def _generate_coverage_manifest(ctx, output, runtime_classpath):
+    ctx.actions.write(
+        output = output,
+        content = "\n".join([file.short_path for file in runtime_classpath.to_list()]),
+    )
+
+def _create_one_version_check(ctx, inputs, is_test_rule_class):
+    one_version_level = ctx.fragments.java.one_version_enforcement_level
+    if one_version_level == "OFF":
+        return None
+    tool = helper.check_and_get_one_version_attribute(ctx, "_one_version_tool")
+
+    if is_test_rule_class:
+        toolchain = semantics.find_java_toolchain(ctx)
+        allowlist = toolchain._one_version_allowlist_for_tests
+    else:
+        allowlist = helper.check_and_get_one_version_attribute(ctx, "_one_version_allowlist")
+
+    if not tool:  # On Mac oneversion tool is not available
+        return None
+
+    output = ctx.actions.declare_file("%s-one-version.txt" % ctx.label.name)
+
+    args = ctx.actions.args()
+    args.set_param_file_format("shell").use_param_file("@%s", use_always = True)
+
+    one_version_inputs = []
+    args.add("--output", output)
+    if allowlist:
+        args.add("--allowlist", allowlist)
+        one_version_inputs.append(allowlist)
+    if one_version_level == "WARNING":
+        args.add("--succeed_on_found_violations")
+    args.add_all(
+        "--inputs",
+        inputs,
+        map_each = helper.jar_and_target_arg_mapper,
+    )
+
+    ctx.actions.run(
+        mnemonic = "JavaOneVersion",
+        progress_message = "Checking for one-version violations in %{label}",
+        executable = tool,
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+        inputs = depset(one_version_inputs, transitive = [inputs]),
+        tools = [tool],
+        outputs = [output],
+        arguments = [args],
+    )
+
+    return output
+
+def _create_deploy_sources_jar(ctx, sources):
+    helper.create_single_jar(
+        ctx.actions,
+        toolchain = semantics.find_java_toolchain(ctx),
+        output = ctx.outputs.deploysrcjar,
+        sources = sources,
+    )
+
+def _filter_validation_output_group(ctx, output_group):
+    to_exclude = depset(transitive = [
+        dep[OutputGroupInfo]._validation
+        for dep in ctx.attr.deploy_env
+        if OutputGroupInfo in dep and hasattr(dep[OutputGroupInfo], "_validation")
+    ]) if hasattr(ctx.attr, "deploy_env") else depset()
+    if to_exclude:
+        transitive_validations = depset(transitive = [
+            _get_validations_from_attr(ctx, attr_name)
+            for attr_name in dir(ctx.attr)
+            # we also exclude implicit, cfg=host/exec and tool attributes
+            if not attr_name.startswith("_") and
+               attr_name not in [
+                   "deploy_env",
+                   "applicable_licenses",
+                   "package_metadata",
+                   "plugins",
+                   "translations",
+                   # special ignored attributes
+                   "compatible_with",
+                   "restricted_to",
+                   "exec_compatible_with",
+                   "target_compatible_with",
+               ]
+        ])
+        if not ctx.attr.create_executable:
+            excluded_set = {x: None for x in to_exclude.to_list()}
+            transitive_validations = [
+                x
+                for x in transitive_validations.to_list()
+                if x not in excluded_set
+            ]
+        output_group["_validation_transitive"] = transitive_validations
+
+def _get_validations_from_attr(ctx, attr_name):
+    attr = getattr(ctx.attr, attr_name)
+    if type(attr) == "list":
+        return depset(transitive = [_get_validations_from_target(t) for t in attr])
+    else:
+        return _get_validations_from_target(attr)
+
+def _get_validations_from_target(target):
+    if (
+        type(target) == "Target" and
+        OutputGroupInfo in target and
+        hasattr(target[OutputGroupInfo], "_validation")
+    ):
+        return target[OutputGroupInfo]._validation
+    else:
+        return depset()
+
+# TODO: bazelbuild/intellij/issues/5845 - remove this once no longer required
+# this need not be completely identical to the regular deploy jar since we only
+# care about packaging the classpath
+def _auto_create_deploy_jar(ctx, info, launcher_info, main_class, coverage_main_class):
+    output = ctx.actions.declare_file(ctx.label.name + "_auto_deploy.jar")
+    java_attrs = info.java_attrs
+    runtime_classpath = depset(
+        direct = launcher_info.runtime_jars,
+        transitive = [
+            java_attrs.runtime_jars,
+            java_attrs.runtime_classpath_for_archive,
+        ],
+        order = "preorder",
+    )
+    create_deploy_archive(
+        ctx,
+        launcher = launcher_info.launcher,
+        main_class = main_class,
+        coverage_main_class = coverage_main_class,
+        resources = java_attrs.resources,
+        classpath_resources = java_attrs.classpath_resources,
+        runtime_classpath = runtime_classpath,
+        manifest_lines = [],
+        build_info_files = [],
+        build_target = str(ctx.label),
+        output = output,
+        one_version_level = ctx.fragments.java.one_version_enforcement_level,
+        one_version_allowlist = helper.check_and_get_one_version_attribute(ctx, "_one_version_allowlist"),
+        multi_release = ctx.fragments.java.multi_release_deploy_jars,
+        hermetic = hasattr(ctx.attr, "hermetic") and ctx.attr.hermetic,
+        add_exports = info.add_exports,
+        add_opens = info.add_opens,
+    )
+    return output
diff --git a/java/common/rules/impl/java_helper.bzl b/java/common/rules/impl/java_helper.bzl
new file mode 100644
index 0000000..fa82898
--- /dev/null
+++ b/java/common/rules/impl/java_helper.bzl
@@ -0,0 +1,510 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Common util functions for java_* rules"""
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain")
+load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
+load("@rules_cc//cc/common:cc_helper.bzl", "cc_helper")
+load("//java/common:java_semantics.bzl", "semantics")
+
+# copybara: default visibility
+
+def _collect_all_targets_as_deps(ctx, classpath_type = "all"):
+    deps = []
+    if not classpath_type == "compile_only":
+        if hasattr(ctx.attr, "runtime_deps"):
+            deps.extend(ctx.attr.runtime_deps)
+        if hasattr(ctx.attr, "exports"):
+            deps.extend(ctx.attr.exports)
+
+    deps.extend(ctx.attr.deps or [])
+
+    launcher = _filter_launcher_for_target(ctx)
+    if launcher:
+        deps.append(launcher)
+
+    return deps
+
+def _filter_launcher_for_target(ctx):
+    # create_executable=0 disables the launcher
+    if hasattr(ctx.attr, "create_executable") and not ctx.attr.create_executable:
+        return None
+
+    # use_launcher=False disables the launcher
+    if hasattr(ctx.attr, "use_launcher") and not ctx.attr.use_launcher:
+        return None
+
+    # BUILD rule "launcher" attribute
+    if ctx.attr.launcher and cc_common.launcher_provider in ctx.attr.launcher:
+        return ctx.attr.launcher
+
+    return None
+
+def _launcher_artifact_for_target(ctx):
+    launcher = _filter_launcher_for_target(ctx)
+    if not launcher:
+        return None
+    files = launcher[DefaultInfo].files.to_list()
+    if len(files) != 1:
+        fail("%s expected a single artifact in %s" % (ctx.label, launcher))
+    return files[0]
+
+def _check_and_get_main_class(ctx):
+    create_executable = ctx.attr.create_executable
+    use_testrunner = ctx.attr.use_testrunner
+    main_class = ctx.attr.main_class
+
+    if not create_executable and use_testrunner:
+        fail("cannot have use_testrunner without creating an executable")
+    if not create_executable and main_class:
+        fail("main class must not be specified when executable is not created")
+    if create_executable and not use_testrunner:
+        if not main_class:
+            if not ctx.attr.srcs:
+                fail("need at least one of 'main_class', 'use_testrunner' or Java source files")
+            main_class = _primary_class(ctx)
+            if main_class == None:
+                fail("main_class was not provided and cannot be inferred: " +
+                     "source path doesn't include a known root (java, javatests, src, testsrc)")
+    if not create_executable:
+        return None
+    if not main_class:
+        if use_testrunner:
+            main_class = "com.google.testing.junit.runner.GoogleTestRunner"
+        else:
+            main_class = _primary_class(ctx)
+    return main_class
+
+def _primary_class(ctx):
+    if ctx.attr.srcs:
+        main = ctx.label.name + ".java"
+        for src in ctx.files.srcs:
+            if src.basename == main:
+                return _full_classname(_strip_extension(src))
+    return _full_classname(_get_relative(ctx.label.package, ctx.label.name))
+
+def _strip_extension(file):
+    return file.dirname + "/" + (
+        file.basename[:-(1 + len(file.extension))] if file.extension else file.basename
+    )
+
+# TODO(b/193629418): once out of builtins, create a canonical implementation and remove duplicates in depot
+def _full_classname(path):
+    java_segments = _java_segments(path)
+    return ".".join(java_segments) if java_segments != None else None
+
+def _java_segments(path):
+    if path.startswith("/"):
+        fail("path must not be absolute: '%s'" % path)
+    segments = path.split("/")
+    root_idx = -1
+    for idx, segment in enumerate(segments):
+        if segment in ["java", "javatests", "src", "testsrc"]:
+            root_idx = idx
+            break
+    if root_idx < 0:
+        return None
+    is_src = "src" == segments[root_idx]
+    check_mvn_idx = root_idx if is_src else -1
+    if (root_idx == 0 or is_src):
+        for i in range(root_idx + 1, len(segments) - 1):
+            segment = segments[i]
+            if "src" == segment or (is_src and (segment in ["java", "javatests"])):
+                next = segments[i + 1]
+                if next in ["com", "org", "net"]:
+                    root_idx = i
+                elif "src" == segment:
+                    check_mvn_idx = i
+                break
+
+    if check_mvn_idx >= 0 and check_mvn_idx < len(segments) - 2:
+        next = segments[check_mvn_idx + 1]
+        if next in ["main", "test"]:
+            next = segments[check_mvn_idx + 2]
+            if next in ["java", "resources"]:
+                root_idx = check_mvn_idx + 2
+    return segments[(root_idx + 1):]
+
+def _concat(*lists):
+    result = []
+    for list in lists:
+        result.extend(list)
+    return result
+
+def _get_shared_native_deps_path(
+        linker_inputs,
+        link_opts,
+        linkstamps,
+        build_info_artifacts,
+        features,
+        is_test_target_partially_disabled_thin_lto):
+    """
+    Returns the path of the shared native library.
+
+    The name must be generated based on the rule-specific inputs to the link actions. At this point
+    this includes order-sensitive list of linker inputs and options collected from the transitive
+    closure and linkstamp-related artifacts that are compiled during linking. All those inputs can
+    be affected by modifying target attributes (srcs/deps/stamp/etc). However, target build
+    configuration can be ignored since it will either change output directory (in case of different
+    configuration instances) or will not affect anything (if two targets use same configuration).
+    Final goal is for all native libraries that use identical linker command to use same output
+    name.
+
+    <p>TODO(bazel-team): (2010) Currently process of identifying parameters that can affect native
+    library name is manual and should be kept in sync with the code in the
+    CppLinkAction.Builder/CppLinkAction/Link classes which are responsible for generating linker
+    command line. Ideally we should reuse generated command line for both purposes - selecting a
+    name of the native library and using it as link action payload. For now, correctness of the
+    method below is only ensured by validations in the CppLinkAction.Builder.build() method.
+    """
+
+    fp = ""
+    for artifact in linker_inputs:
+        fp += artifact.short_path
+    fp += str(len(link_opts))
+    for opt in link_opts:
+        fp += opt
+    for artifact in linkstamps:
+        fp += artifact.short_path
+    for artifact in build_info_artifacts:
+        fp += artifact.short_path
+    for feature in features:
+        fp += feature
+
+    # Sharing of native dependencies may cause an ActionConflictException when ThinLTO is
+    # disabled for test and test-only targets that are statically linked, but enabled for other
+    # statically linked targets. This happens in case the artifacts for the shared native
+    # dependency are output by actions owned by the non-test and test targets both. To fix
+    # this, we allow creation of multiple artifacts for the shared native library - one shared
+    # among the test and test-only targets where ThinLTO is disabled, and the other shared among
+    # other targets where ThinLTO is enabled.
+    fp += "1" if is_test_target_partially_disabled_thin_lto else "0"
+
+    fingerprint = "%x" % hash(fp)
+    return "_nativedeps/" + fingerprint
+
+def _check_and_get_one_version_attribute(ctx, attr):
+    value = getattr(semantics.find_java_toolchain(ctx), attr)
+    return value
+
+def _jar_and_target_arg_mapper(jar):
+    # Emit pretty labels for targets in the main repository.
+    label = str(jar.owner)
+    if label.startswith("@@//"):
+        label = label.lstrip("@")
+    return jar.path + "," + label
+
+def _get_feature_config(ctx):
+    cc_toolchain = find_cc_toolchain(ctx, mandatory = False)
+    if not cc_toolchain:
+        return None
+    feature_config = cc_common.configure_features(
+        ctx = ctx,
+        cc_toolchain = cc_toolchain,
+        requested_features = ctx.features + ["java_launcher_link", "static_linking_mode"],
+        unsupported_features = ctx.disabled_features,
+    )
+    return feature_config
+
+def _should_strip_as_default(ctx, feature_config):
+    fission_is_active = ctx.fragments.cpp.fission_active_for_current_compilation_mode()
+    create_per_obj_debug_info = fission_is_active and cc_common.is_enabled(
+        feature_name = "per_object_debug_info",
+        feature_configuration = feature_config,
+    )
+    compilation_mode = ctx.var["COMPILATION_MODE"]
+    strip_as_default = create_per_obj_debug_info and compilation_mode == "opt"
+
+    return strip_as_default
+
+def _get_coverage_config(ctx, runner):
+    toolchain = semantics.find_java_toolchain(ctx)
+    if not ctx.configuration.coverage_enabled:
+        return None
+    runner = runner if ctx.attr.create_executable else None
+    manifest = ctx.actions.declare_file("runtime_classpath_for_coverage/%s/runtime_classpath.txt" % ctx.label.name)
+    singlejar = toolchain.single_jar
+    return struct(
+        runner = runner,
+        main_class = "com.google.testing.coverage.JacocoCoverageRunner",
+        manifest = manifest,
+        env = {
+            "JAVA_RUNTIME_CLASSPATH_FOR_COVERAGE": manifest.path,
+            "SINGLE_JAR_TOOL": singlejar.executable.path,
+        },
+        support_files = [manifest, singlejar.executable],
+    )
+
+def _get_java_executable(ctx, java_runtime_toolchain, launcher):
+    java_executable = launcher.short_path if launcher else java_runtime_toolchain.java_executable_runfiles_path
+    if not _is_absolute_target_platform_path(ctx, java_executable):
+        java_executable = ctx.workspace_name + "/" + java_executable
+    return paths.normalize(java_executable)
+
+def _has_target_constraints(ctx, constraints):
+    # Constraints is a label_list.
+    for constraint in constraints:
+        constraint_value = constraint[platform_common.ConstraintValueInfo]
+        if ctx.target_platform_has_constraint(constraint_value):
+            return True
+    return False
+
+def _is_target_platform_windows(ctx):
+    return _has_target_constraints(ctx, ctx.attr._windows_constraints)
+
+def _is_absolute_target_platform_path(ctx, path):
+    if _is_target_platform_windows(ctx):
+        return len(path) > 2 and path[1] == ":"
+    return path.startswith("/")
+
+def _runfiles_enabled(ctx):
+    return ctx.configuration.runfiles_enabled()
+
+def _get_test_support(ctx):
+    if ctx.attr.create_executable and ctx.attr.use_testrunner:
+        return ctx.attr._test_support
+    return None
+
+def _test_providers(ctx):
+    test_providers = []
+    if _has_target_constraints(ctx, ctx.attr._apple_constraints):
+        test_providers.append(testing.ExecutionInfo({"requires-darwin": ""}))
+
+    test_env = {}
+    test_env.update(cc_helper.get_expanded_env(ctx, {}))
+
+    coverage_config = _get_coverage_config(
+        ctx,
+        runner = None,  # we only need the environment
+    )
+    if coverage_config:
+        test_env.update(coverage_config.env)
+    test_providers.append(testing.TestEnvironment(
+        environment = test_env,
+        inherited_environment = ctx.attr.env_inherit,
+    ))
+
+    return test_providers
+
+def _executable_providers(ctx):
+    if ctx.attr.create_executable:
+        return [RunEnvironmentInfo(cc_helper.get_expanded_env(ctx, {}))]
+    return []
+
+def _resource_mapper(file):
+    root_relative_path = paths.relativize(
+        path = file.path,
+        start = paths.join(file.root.path, file.owner.workspace_root),
+    )
+    return "%s:%s" % (
+        file.path,
+        semantics.get_default_resource_path(root_relative_path, segment_extractor = _java_segments),
+    )
+
+def _create_single_jar(
+        actions,
+        toolchain,
+        output,
+        sources = depset(),
+        resources = depset(),
+        mnemonic = "JavaSingleJar",
+        progress_message = "Building singlejar jar %{output}",
+        build_target = None,
+        output_creator = None):
+    """Register singlejar action for the output jar.
+
+    Args:
+      actions: (actions) ctx.actions
+      toolchain: (JavaToolchainInfo) The java toolchain
+      output: (File) Output file of the action.
+      sources: (depset[File]) The jar files to merge into the output jar.
+      resources: (depset[File]) The files to add to the output jar.
+      mnemonic: (str) The action identifier
+      progress_message: (str) The action progress message
+      build_target: (Label) The target label to stamp in the manifest. Optional.
+      output_creator: (str) The name of the tool to stamp in the manifest. Optional,
+          defaults to 'singlejar'
+    Returns:
+      (File) Output file which was used for registering the action.
+    """
+    args = actions.args()
+    args.set_param_file_format("shell").use_param_file("@%s", use_always = True)
+    args.add("--output", output)
+    args.add_all(
+        [
+            "--compression",
+            "--normalize",
+            "--exclude_build_data",
+            "--warn_duplicate_resources",
+        ],
+    )
+    args.add_all("--sources", sources)
+    args.add_all("--resources", resources, map_each = _resource_mapper)
+
+    args.add("--build_target", build_target)
+    args.add("--output_jar_creator", output_creator)
+
+    actions.run(
+        mnemonic = mnemonic,
+        progress_message = progress_message,
+        executable = toolchain.single_jar,
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+        inputs = depset(transitive = [resources, sources]),
+        tools = [toolchain.single_jar],
+        outputs = [output],
+        arguments = [args],
+    )
+    return output
+
+# TODO(hvd): use skylib shell.quote()
+def _shell_escape(s):
+    """Shell-escape a string
+
+    Quotes a word so that it can be used, without further quoting, as an argument
+    (or part of an argument) in a shell command.
+
+    Args:
+        s: (str) the string to escape
+
+    Returns:
+        (str) the shell-escaped string
+    """
+    if not s:
+        # Empty string is a special case: needs to be quoted to ensure that it
+        # gets treated as a separate argument.
+        return "''"
+    for c in s.elems():
+        # We do this positively so as to be sure we don't inadvertently forget
+        # any unsafe characters.
+        if not c.isalnum() and c not in "@%-_+:,./":
+            return "'" + s.replace("'", "'\\''") + "'"
+    return s
+
+def _detokenize_javacopts(opts):
+    """Detokenizes a list of options to a depset.
+
+    Args:
+        opts: ([str]) the javac options to detokenize
+
+    Returns:
+        (depset[str]) depset of detokenized options
+    """
+    return depset(
+        [" ".join([_shell_escape(opt) for opt in opts])],
+        order = "preorder",
+    )
+
+def _derive_output_file(ctx, base_file, *, name_suffix = "", extension = None, extension_suffix = ""):
+    """Declares a new file whose name is derived from the given file
+
+    This method allows appending a suffix to the name (before extension), changing
+    the extension or appending a suffix after the extension. The new file is declared
+    as a sibling of the given base file. At least one of the three options must be
+    specified. It is an error to specify both `extension` and `extension_suffix`.
+
+    Args:
+        ctx: (RuleContext) the rule context.
+        base_file: (File) the file from which to derive the resultant file.
+        name_suffix: (str) Optional. The suffix to append to the name before the
+        extension.
+        extension: (str) Optional. The new extension to use (without '.'). By default,
+        the base_file's extension is used.
+        extension_suffix: (str) Optional. The suffix to append to the base_file's extension
+
+    Returns:
+        (File) the derived file
+    """
+    if not name_suffix and not extension_suffix and not extension:
+        fail("At least one of name_suffix, extension or extension_suffix is required")
+    if extension and extension_suffix:
+        fail("only one of extension or extension_suffix can be specified")
+    if extension == None:
+        extension = base_file.extension
+    new_basename = paths.replace_extension(base_file.basename, name_suffix + "." + extension + extension_suffix)
+    return ctx.actions.declare_file(new_basename, sibling = base_file)
+
+def _is_stamping_enabled(ctx, stamp):
+    if ctx.configuration.is_tool_configuration():
+        return 0
+    if stamp == 1 or stamp == 0:
+        return stamp
+
+    # stamp == -1 / auto
+    return int(ctx.configuration.stamp_binaries())
+
+def _get_relative(path_a, path_b):
+    if paths.is_absolute(path_b):
+        return path_b
+    return paths.normalize(paths.join(path_a, path_b))
+
+def _tokenize_javacopts(ctx = None, opts = []):
+    """Tokenizes a list or depset of options to a list.
+
+    Iff opts is a depset, we reverse the flattened list to ensure right-most
+    duplicates are preserved in their correct position.
+
+    If the ctx parameter is omitted, a slow, but pure Starlark, implementation
+    of shell tokenization is used. Otherwise, tokenization is performed using
+    ctx.tokenize() which has significantly better performance (up to 100x for
+    large options lists).
+
+    Args:
+        ctx: (RuleContext|None) the rule context
+        opts: (depset[str]|[str]) the javac options to tokenize
+    Returns:
+        [str] list of tokenized options
+    """
+    if hasattr(opts, "to_list"):
+        opts = reversed(opts.to_list())
+    if ctx:
+        return [
+            token
+            for opt in opts
+            for token in ctx.tokenize(opt)
+        ]
+    else:
+        # TODO: optimize and use the pure Starlark implementation in cc_helper
+        return semantics.tokenize_javacopts(opts)
+
+helper = struct(
+    collect_all_targets_as_deps = _collect_all_targets_as_deps,
+    filter_launcher_for_target = _filter_launcher_for_target,
+    launcher_artifact_for_target = _launcher_artifact_for_target,
+    check_and_get_main_class = _check_and_get_main_class,
+    primary_class = _primary_class,
+    strip_extension = _strip_extension,
+    concat = _concat,
+    get_shared_native_deps_path = _get_shared_native_deps_path,
+    check_and_get_one_version_attribute = _check_and_get_one_version_attribute,
+    jar_and_target_arg_mapper = _jar_and_target_arg_mapper,
+    get_feature_config = _get_feature_config,
+    should_strip_as_default = _should_strip_as_default,
+    get_coverage_config = _get_coverage_config,
+    get_java_executable = _get_java_executable,
+    is_absolute_target_platform_path = _is_absolute_target_platform_path,
+    is_target_platform_windows = _is_target_platform_windows,
+    runfiles_enabled = _runfiles_enabled,
+    get_test_support = _get_test_support,
+    test_providers = _test_providers,
+    executable_providers = _executable_providers,
+    create_single_jar = _create_single_jar,
+    shell_escape = _shell_escape,
+    detokenize_javacopts = _detokenize_javacopts,
+    tokenize_javacopts = _tokenize_javacopts,
+    derive_output_file = _derive_output_file,
+    is_stamping_enabled = _is_stamping_enabled,
+    get_relative = _get_relative,
+)
diff --git a/java/common/rules/impl/proguard_validation.bzl b/java/common/rules/impl/proguard_validation.bzl
new file mode 100644
index 0000000..18142b3
--- /dev/null
+++ b/java/common/rules/impl/proguard_validation.bzl
@@ -0,0 +1,71 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Proguard
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common:proguard_spec_info.bzl", "ProguardSpecInfo")
+
+visibility("private")
+
+def _filter_provider(provider, *attrs):
+    return [dep[provider] for attr in attrs for dep in attr if provider in dep]
+
+def _validate_spec(ctx, spec_file):
+    validated_proguard_spec = ctx.actions.declare_file(
+        "validated_proguard/%s/%s_valid" % (ctx.label.name, spec_file.path),
+    )
+
+    toolchain = semantics.find_java_toolchain(ctx)
+
+    args = ctx.actions.args()
+    args.add("--path", spec_file)
+    args.add("--output", validated_proguard_spec)
+
+    ctx.actions.run(
+        mnemonic = "ValidateProguard",
+        progress_message = "Validating proguard configuration %{input}",
+        executable = toolchain.proguard_allowlister,
+        arguments = [args],
+        inputs = [spec_file],
+        outputs = [validated_proguard_spec],
+        toolchain = Label(semantics.JAVA_TOOLCHAIN_TYPE),
+    )
+
+    return validated_proguard_spec
+
+def validate_proguard_specs(ctx, proguard_specs = [], transitive_attrs = []):
+    """
+    Creates actions that validate Proguard specification and returns ProguardSpecProvider.
+
+    Use transtive_attrs parameter to collect Proguard validations from `deps`,
+    `runtime_deps`, `exports`, `plugins`, and `exported_plugins` attributes.
+
+    Args:
+      ctx: (RuleContext) Used to register the actions.
+      proguard_specs: (list[File]) List of Proguard specs files.
+      transitive_attrs: (list[list[Target]])  Attributes to collect transitive
+        proguard validations from.
+    Returns:
+      (ProguardSpecProvider) A ProguardSpecProvider.
+    """
+    proguard_validations = _filter_provider(ProguardSpecInfo, *transitive_attrs)
+    return ProguardSpecInfo(
+        depset(
+            [_validate_spec(ctx, spec_file) for spec_file in proguard_specs],
+            transitive = [validation.specs for validation in proguard_validations],
+        ),
+    )
diff --git a/java/common/rules/java_binary.bzl b/java/common/rules/java_binary.bzl
new file mode 100644
index 0000000..09b6b12
--- /dev/null
+++ b/java/common/rules/java_binary.bzl
@@ -0,0 +1,377 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+""" Implementation of java_binary for bazel """
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/private:java_common.bzl", "java_common")
+load("//java/private:java_info.bzl", "JavaInfo", "JavaPluginInfo")
+load("//java/private:native.bzl", "get_internal_java_common")
+load(":basic_java_library.bzl", "BASIC_JAVA_LIBRARY_IMPLICIT_ATTRS")
+load(":rule_util.bzl", "merge_attrs")
+
+# copybara: default visibility
+
+BootClassPathInfo = java_common.BootClassPathInfo
+_PLATFORMS_ROOT = semantics.PLATFORMS_ROOT
+
+BASIC_JAVA_BINARY_ATTRIBUTES = merge_attrs(
+    BASIC_JAVA_LIBRARY_IMPLICIT_ATTRS,
+    # buildifier: disable=attr-licenses
+    {
+        "srcs": attr.label_list(
+            allow_files = [".java", ".srcjar", ".properties"] + semantics.EXTRA_SRCS_TYPES,
+            flags = ["DIRECT_COMPILE_TIME_INPUT", "ORDER_INDEPENDENT"],
+            doc = """
+The list of source files that are processed to create the target.
+This attribute is almost always required; see exceptions below.
+<p>
+Source files of type <code>.java</code> are compiled. In case of generated
+<code>.java</code> files it is generally advisable to put the generating rule's name
+here instead of the name of the file itself. This not only improves readability but
+makes the rule more resilient to future changes: if the generating rule generates
+different files in the future, you only need to fix one place: the <code>outs</code> of
+the generating rule. You should not list the generating rule in <code>deps</code>
+because it is a no-op.
+</p>
+<p>
+Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if
+you need to generate a set of <code>.java</code> files with a genrule.)
+</p>
+<p>
+Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates
+any of the files listed above, they will be used the same way as described for source
+files.
+</p>
+
+<p>
+This argument is almost always required, except if a
+<a href="#java_binary.main_class"><code>main_class</code></a> attribute specifies a
+class on the runtime classpath or you specify the <code>runtime_deps</code> argument.
+</p>
+            """,
+        ),
+        "deps": attr.label_list(
+            allow_files = [".jar"],
+            allow_rules = semantics.ALLOWED_RULES_IN_DEPS + semantics.ALLOWED_RULES_IN_DEPS_WITH_WARNING,
+            providers = [
+                [CcInfo],
+                [JavaInfo],
+            ],
+            flags = ["SKIP_ANALYSIS_TIME_FILETYPE_CHECK"],
+            doc = """
+The list of other libraries to be linked in to the target.
+See general comments about <code>deps</code> at
+<a href="common-definitions.html#typical-attributes">Typical attributes defined by
+most build rules</a>.
+            """,
+        ),
+        "resources": attr.label_list(
+            allow_files = True,
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE", "ORDER_INDEPENDENT"],
+            doc = """
+A list of data files to include in a Java jar.
+
+<p>
+Resources may be source files or generated files.
+</p>
+            """ + semantics.DOCS.for_attribute("resources"),
+        ),
+        "runtime_deps": attr.label_list(
+            allow_files = [".jar"],
+            allow_rules = semantics.ALLOWED_RULES_IN_DEPS,
+            providers = [[CcInfo], [JavaInfo]],
+            flags = ["SKIP_ANALYSIS_TIME_FILETYPE_CHECK"],
+            doc = """
+Libraries to make available to the final binary or test at runtime only.
+Like ordinary <code>deps</code>, these will appear on the runtime classpath, but unlike
+them, not on the compile-time classpath. Dependencies needed only at runtime should be
+listed here. Dependency-analysis tools should ignore targets that appear in both
+<code>runtime_deps</code> and <code>deps</code>.
+            """,
+        ),
+        "data": attr.label_list(
+            allow_files = True,
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE"],
+            doc = """
+The list of files needed by this library at runtime.
+See general comments about <code>data</code>
+at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by
+most build rules</a>.
+            """ + semantics.DOCS.for_attribute("data"),
+        ),
+        "plugins": attr.label_list(
+            providers = [JavaPluginInfo],
+            allow_files = True,
+            cfg = "exec",
+            doc = """
+Java compiler plugins to run at compile-time.
+Every <code>java_plugin</code> specified in this attribute will be run whenever this rule
+is built. A library may also inherit plugins from dependencies that use
+<code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources
+generated by the plugin will be included in the resulting jar of this rule.
+            """,
+        ),
+        "deploy_env": attr.label_list(
+            providers = [java_common.JavaRuntimeClasspathInfo],
+            allow_files = False,
+            doc = """
+A list of other <code>java_binary</code> targets which represent the deployment
+environment for this binary.
+Set this attribute when building a plugin which will be loaded by another
+<code>java_binary</code>.<br/> Setting this attribute excludes all dependencies from
+the runtime classpath (and the deploy jar) of this binary that are shared between this
+binary and the targets specified in <code>deploy_env</code>.
+            """,
+        ),
+        "launcher": attr.label(
+            # TODO(b/295221112): add back CcLauncherInfo
+            allow_files = False,
+            doc = """
+Specify a binary that will be used to run your Java program instead of the
+normal <code>bin/java</code> program included with the JDK.
+The target must be a <code>cc_binary</code>. Any <code>cc_binary</code> that
+implements the
+<a href="http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html">
+Java Invocation API</a> can be specified as a value for this attribute.
+
+<p>By default, Bazel will use the normal JDK launcher (bin/java or java.exe).</p>
+
+<p>The related <a href="${link user-manual#flag--java_launcher}"><code>
+--java_launcher</code></a> Bazel flag affects only those
+<code>java_binary</code> and <code>java_test</code> targets that have
+<i>not</i> specified a <code>launcher</code> attribute.</p>
+
+<p>Note that your native (C++, SWIG, JNI) dependencies will be built differently
+depending on whether you are using the JDK launcher or another launcher:</p>
+
+<ul>
+<li>If you are using the normal JDK launcher (the default), native dependencies are
+built as a shared library named <code>{name}_nativedeps.so</code>, where
+<code>{name}</code> is the <code>name</code> attribute of this java_binary rule.
+Unused code is <em>not</em> removed by the linker in this configuration.</li>
+
+<li>If you are using any other launcher, native (C++) dependencies are statically
+linked into a binary named <code>{name}_nativedeps</code>, where <code>{name}</code>
+is the <code>name</code> attribute of this java_binary rule. In this case,
+the linker will remove any code it thinks is unused from the resulting binary,
+which means any C++ code accessed only via JNI may not be linked in unless
+that <code>cc_library</code> target specifies <code>alwayslink = True</code>.</li>
+</ul>
+
+<p>When using any launcher other than the default JDK launcher, the format
+of the <code>*_deploy.jar</code> output changes. See the main
+<a href="#java_binary">java_binary</a> docs for details.</p>
+            """,
+        ),
+        "bootclasspath": attr.label(
+            providers = [BootClassPathInfo],
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE"],
+            doc = "Restricted API, do not use!",
+        ),
+        "neverlink": attr.bool(),
+        "javacopts": attr.string_list(
+            doc = """
+Extra compiler options for this binary.
+Subject to <a href="make-variables.html">"Make variable"</a> substitution and
+<a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>.
+<p>These compiler options are passed to javac after the global compiler options.</p>
+            """,
+        ),
+        "add_exports": attr.string_list(
+            doc = """
+Allow this library to access the given <code>module</code> or <code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-exports= flags.
+            """,
+        ),
+        "add_opens": attr.string_list(
+            doc = """
+Allow this library to reflectively access the given <code>module</code> or
+<code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-opens= flags.
+            """,
+        ),
+        "main_class": attr.string(
+            doc = """
+Name of class with <code>main()</code> method to use as entry point.
+If a rule uses this option, it does not need a <code>srcs=[...]</code> list.
+Thus, with this attribute one can make an executable from a Java library that already
+contains one or more <code>main()</code> methods.
+<p>
+The value of this attribute is a class name, not a source file. The class must be
+available at runtime: it may be compiled by this rule (from <code>srcs</code>) or
+provided by direct or transitive dependencies (through <code>runtime_deps</code> or
+<code>deps</code>). If the class is unavailable, the binary will fail at runtime; there
+is no build-time check.
+</p>
+            """,
+        ),
+        "jvm_flags": attr.string_list(
+            doc = """
+A list of flags to embed in the wrapper script generated for running this binary.
+Subject to <a href="${link make-variables#location}">$(location)</a> and
+<a href="make-variables.html">"Make variable"</a> substitution, and
+<a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>.
+
+<p>The wrapper script for a Java binary includes a CLASSPATH definition
+(to find all the dependent jars) and invokes the right Java interpreter.
+The command line generated by the wrapper script includes the name of
+the main class followed by a <code>"$@"</code> so you can pass along other
+arguments after the classname.  However, arguments intended for parsing
+by the JVM must be specified <i>before</i> the classname on the command
+line.  The contents of <code>jvm_flags</code> are added to the wrapper
+script before the classname is listed.</p>
+
+<p>Note that this attribute has <em>no effect</em> on <code>*_deploy.jar</code>
+outputs.</p>
+            """,
+        ),
+        "deploy_manifest_lines": attr.string_list(
+            doc = """
+A list of lines to add to the <code>META-INF/manifest.mf</code> file generated for the
+<code>*_deploy.jar</code> target. The contents of this attribute are <em>not</em> subject
+to <a href="make-variables.html">"Make variable"</a> substitution.
+            """,
+        ),
+        "stamp": attr.int(
+            default = -1,
+            values = [-1, 0, 1],
+            doc = """
+Whether to encode build information into the binary. Possible values:
+<ul>
+<li>
+  <code>stamp = 1</code>: Always stamp the build information into the binary, even in
+  <a href="${link user-manual#flag--stamp}"><code>--nostamp</code></a> builds. <b>This
+  setting should be avoided</b>, since it potentially kills remote caching for the
+  binary and any downstream actions that depend on it.
+</li>
+<li>
+  <code>stamp = 0</code>: Always replace build information by constant values. This
+  gives good build result caching.
+</li>
+<li>
+  <code>stamp = -1</code>: Embedding of build information is controlled by the
+  <a href="${link user-manual#flag--stamp}"><code>--[no]stamp</code></a> flag.
+</li>
+</ul>
+<p>Stamped binaries are <em>not</em> rebuilt unless their dependencies change.</p>
+            """,
+        ),
+        "use_testrunner": attr.bool(
+            default = False,
+            doc = semantics.DOCS.for_attribute("use_testrunner") + """
+<br/>
+You can use this to override the default
+behavior, which is to use test runner for
+<code>java_test</code> rules,
+and not use it for <code>java_binary</code> rules.  It is unlikely
+you will want to do this.  One use is for <code>AllTest</code>
+rules that are invoked by another rule (to set up a database
+before running the tests, for example).  The <code>AllTest</code>
+rule must be declared as a <code>java_binary</code>, but should
+still use the test runner as its main entry point.
+
+The name of a test runner class can be overridden with <code>main_class</code> attribute.
+            """,
+        ),
+        "use_launcher": attr.bool(
+            default = True,
+            doc = """
+Whether the binary should use a custom launcher.
+
+<p>If this attribute is set to false, the
+<a href="${link java_binary.launcher}">launcher</a> attribute  and the related
+<a href="${link user-manual#flag--java_launcher}"><code>--java_launcher</code></a> flag
+will be ignored for this target.
+            """,
+        ),
+        "env": attr.string_dict(),
+        "classpath_resources": attr.label_list(
+            allow_files = True,
+            doc = """
+<em class="harmful">DO NOT USE THIS OPTION UNLESS THERE IS NO OTHER WAY)</em>
+<p>
+A list of resources that must be located at the root of the java tree. This attribute's
+only purpose is to support third-party libraries that require that their resources be
+found on the classpath as exactly <code>"myconfig.xml"</code>. It is only allowed on
+binaries and not libraries, due to the danger of namespace conflicts.
+</p>
+            """,
+        ),
+        "licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+        "_stub_template": attr.label(
+            default = semantics.JAVA_STUB_TEMPLATE_LABEL,
+            allow_single_file = True,
+        ),
+        "_java_toolchain_type": attr.label(default = semantics.JAVA_TOOLCHAIN_TYPE),
+        "_windows_constraints": attr.label_list(
+            default = [paths.join(_PLATFORMS_ROOT, "os:windows")],
+        ),
+        "_build_info_translator": attr.label(default = semantics.BUILD_INFO_TRANSLATOR_LABEL),
+    } | ({} if get_internal_java_common().incompatible_disable_non_executable_java_binary() else {"create_executable": attr.bool(default = True, doc = "Deprecated, use <code>java_single_jar</code> instead.")}),
+)
+
+BASE_TEST_ATTRIBUTES = {
+    "test_class": attr.string(
+        doc = """
+The Java class to be loaded by the test runner.<br/>
+<p>
+  By default, if this argument is not defined then the legacy mode is used and the
+  test arguments are used instead. Set the <code>--nolegacy_bazel_java_test</code> flag
+  to not fallback on the first argument.
+</p>
+<p>
+  This attribute specifies the name of a Java class to be run by
+  this test. It is rare to need to set this. If this argument is omitted,
+  it will be inferred using the target's <code>name</code> and its
+  source-root-relative path. If the test is located outside a known
+  source root, Bazel will report an error if <code>test_class</code>
+  is unset.
+</p>
+<p>
+  For JUnit3, the test class needs to either be a subclass of
+  <code>junit.framework.TestCase</code> or it needs to have a public
+  static <code>suite()</code> method that returns a
+  <code>junit.framework.Test</code> (or a subclass of <code>Test</code>).
+  For JUnit4, the class needs to be annotated with
+  <code>org.junit.runner.RunWith</code>.
+</p>
+<p>
+  This attribute allows several <code>java_test</code> rules to
+  share the same <code>Test</code>
+  (<code>TestCase</code>, <code>TestSuite</code>, ...).  Typically
+  additional information is passed to it
+  (e.g. via <code>jvm_flags=['-Dkey=value']</code>) so that its
+  behavior differs in each case, such as running a different
+  subset of the tests.  This attribute also enables the use of
+  Java tests outside the <code>javatests</code> tree.
+</p>
+        """,
+    ),
+    "env_inherit": attr.string_list(),
+    "_apple_constraints": attr.label_list(
+        default = [
+            paths.join(_PLATFORMS_ROOT, "os:ios"),
+            paths.join(_PLATFORMS_ROOT, "os:macos"),
+            paths.join(_PLATFORMS_ROOT, "os:tvos"),
+            paths.join(_PLATFORMS_ROOT, "os:visionos"),
+            paths.join(_PLATFORMS_ROOT, "os:watchos"),
+        ],
+    ),
+    "_legacy_any_type_attrs": attr.string_list(default = ["stamp"]),
+}
diff --git a/java/common/rules/java_binary_wrapper.bzl b/java/common/rules/java_binary_wrapper.bzl
new file mode 100644
index 0000000..89b423b
--- /dev/null
+++ b/java/common/rules/java_binary_wrapper.bzl
@@ -0,0 +1,73 @@
+# Copyright 2022 The Bazel Authors. All rights reserved.
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
+"""Macro encapsulating the java_binary implementation
+
+This is needed since the `executable` nature of the target must be computed from
+the supplied value of the `create_executable` attribute.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+
+# copybara: default visibility
+
+def register_legacy_java_binary_rules(
+        rule_exec,
+        rule_nonexec,
+        **kwargs):
+    """Registers the correct java_binary rule and deploy jar rule
+
+    Args:
+        rule_exec: (Rule) The executable java_binary rule
+        rule_nonexec: (Rule) The non-executable java_binary rule
+        **kwargs: Actual args to instantiate the rule
+    """
+
+    create_executable = "create_executable" not in kwargs or kwargs["create_executable"]
+
+    # TODO(hvd): migrate depot to integers / maybe use decompose_select_list()
+    if "stamp" in kwargs and type(kwargs["stamp"]) == type(True):
+        kwargs["stamp"] = 1 if kwargs["stamp"] else 0
+    if not create_executable:
+        rule_nonexec(**kwargs)
+    else:
+        if "use_launcher" in kwargs and not kwargs["use_launcher"]:
+            kwargs["launcher"] = None
+        else:
+            # If launcher is not set or None, set it to config flag
+            if "launcher" not in kwargs or not kwargs["launcher"]:
+                kwargs["launcher"] = semantics.LAUNCHER_FLAG_LABEL
+        rule_exec(**kwargs)
+
+def register_java_binary_rules(
+        java_binary,
+        **kwargs):
+    """Creates a java_binary rule and a deploy jar rule
+
+    Args:
+        java_binary: (Rule) The executable java_binary rule
+        **kwargs: Actual args to instantiate the rule
+    """
+
+    # TODO(hvd): migrate depot to integers / maybe use decompose_select_list()
+    if "stamp" in kwargs and type(kwargs["stamp"]) == type(True):
+        kwargs["stamp"] = 1 if kwargs["stamp"] else 0
+
+    if "use_launcher" in kwargs and not kwargs["use_launcher"]:
+        kwargs["launcher"] = None
+    else:
+        # If launcher is not set or None, set it to config flag
+        if "launcher" not in kwargs or not kwargs["launcher"]:
+            kwargs["launcher"] = semantics.LAUNCHER_FLAG_LABEL
+    java_binary(**kwargs)
diff --git a/java/common/rules/java_import.bzl b/java/common/rules/java_import.bzl
new file mode 100644
index 0000000..4a22b2a
--- /dev/null
+++ b/java/common/rules/java_import.bzl
@@ -0,0 +1,127 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_import rule.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/private:java_info.bzl", "JavaInfo")
+
+# copybara: default visibility
+
+_ALLOWED_RULES_IN_DEPS_FOR_JAVA_IMPORT = [
+    "java_library",
+    "java_import",
+    "cc_library",
+    "cc_binary",
+]
+
+# buildifier: disable=attr-licenses
+JAVA_IMPORT_ATTRS = {
+    "data": attr.label_list(
+        allow_files = True,
+        flags = ["SKIP_CONSTRAINTS_OVERRIDE"],
+        doc = """
+The list of files needed by this rule at runtime.
+        """,
+    ),
+    "deps": attr.label_list(
+        providers = [JavaInfo],
+        allow_rules = _ALLOWED_RULES_IN_DEPS_FOR_JAVA_IMPORT,
+        doc = """
+The list of other libraries to be linked in to the target.
+See <a href="${link java_library.deps}">java_library.deps</a>.
+        """,
+    ),
+    "exports": attr.label_list(
+        providers = [JavaInfo],
+        allow_rules = _ALLOWED_RULES_IN_DEPS_FOR_JAVA_IMPORT,
+        doc = """
+Targets to make available to users of this rule.
+See <a href="${link java_library.exports}">java_library.exports</a>.
+        """,
+    ),
+    "runtime_deps": attr.label_list(
+        allow_files = [".jar"],
+        allow_rules = _ALLOWED_RULES_IN_DEPS_FOR_JAVA_IMPORT,
+        providers = [[CcInfo], [JavaInfo]],
+        flags = ["SKIP_ANALYSIS_TIME_FILETYPE_CHECK"],
+        doc = """
+Libraries to make available to the final binary or test at runtime only.
+See <a href="${link java_library.runtime_deps}">java_library.runtime_deps</a>.
+        """,
+    ),
+    # JavaImportBazeRule attr
+    "jars": attr.label_list(
+        allow_files = [".jar"],
+        mandatory = True,
+        doc = """
+The list of JAR files provided to Java targets that depend on this target.
+        """,
+    ),
+    "srcjar": attr.label(
+        allow_single_file = [".srcjar", ".jar"],
+        flags = ["DIRECT_COMPILE_TIME_INPUT"],
+        doc = """
+A JAR file that contains source code for the compiled JAR files.
+        """,
+    ),
+    "neverlink": attr.bool(
+        default = False,
+        doc = """
+Only use this library for compilation and not at runtime.
+Useful if the library will be provided by the runtime environment
+during execution. Examples of libraries like this are IDE APIs
+for IDE plug-ins or <code>tools.jar</code> for anything running on
+a standard JDK.
+        """,
+    ),
+    "constraints": attr.string_list(
+        doc = """
+Extra constraints imposed on this rule as a Java library.
+        """,
+    ),
+    # ProguardLibraryRule attr
+    "proguard_specs": attr.label_list(
+        allow_files = True,
+        doc = """
+Files to be used as Proguard specification.
+These will describe the set of specifications to be used by Proguard. If specified,
+they will be added to any <code>android_binary</code> target depending on this library.
+
+The files included here must only have idempotent rules, namely -dontnote, -dontwarn,
+assumenosideeffects, and rules that start with -keep. Other options can only appear in
+<code>android_binary</code>'s proguard_specs, to ensure non-tautological merges.
+        """,
+    ),
+    # Additional attrs
+    "add_exports": attr.string_list(
+        doc = """
+Allow this library to access the given <code>module</code> or <code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-exports= flags.
+        """,
+    ),
+    "add_opens": attr.string_list(
+        doc = """
+Allow this library to reflectively access the given <code>module</code> or
+<code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-opens= flags.
+        """,
+    ),
+    "licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+    "_java_toolchain_type": attr.label(default = semantics.JAVA_TOOLCHAIN_TYPE),
+}
diff --git a/java/common/rules/java_library.bzl b/java/common/rules/java_library.bzl
new file mode 100644
index 0000000..77861ac
--- /dev/null
+++ b/java/common/rules/java_library.bzl
@@ -0,0 +1,272 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_library rule.
+"""
+
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/private:java_common.bzl", "java_common")
+load("//java/private:java_info.bzl", "JavaInfo", "JavaPluginInfo")
+load(":basic_java_library.bzl", "BASIC_JAVA_LIBRARY_IMPLICIT_ATTRS")
+load(":rule_util.bzl", "merge_attrs")
+
+# copybara: default visibility
+
+BootClassPathInfo = java_common.BootClassPathInfo
+
+JAVA_LIBRARY_IMPLICIT_ATTRS = BASIC_JAVA_LIBRARY_IMPLICIT_ATTRS
+
+JAVA_LIBRARY_ATTRS = merge_attrs(
+    JAVA_LIBRARY_IMPLICIT_ATTRS,
+    # buildifier: disable=attr-licenses
+    {
+        "srcs": attr.label_list(
+            allow_files = [".java", ".srcjar", ".properties"] + semantics.EXTRA_SRCS_TYPES,
+            flags = ["DIRECT_COMPILE_TIME_INPUT", "ORDER_INDEPENDENT"],
+            doc = """
+The list of source files that are processed to create the target.
+This attribute is almost always required; see exceptions below.
+<p>
+Source files of type <code>.java</code> are compiled. In case of generated
+<code>.java</code> files it is generally advisable to put the generating rule's name
+here instead of the name of the file itself. This not only improves readability but
+makes the rule more resilient to future changes: if the generating rule generates
+different files in the future, you only need to fix one place: the <code>outs</code> of
+the generating rule. You should not list the generating rule in <code>deps</code>
+because it is a no-op.
+</p>
+<p>
+Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if
+you need to generate a set of <code>.java</code> files with a genrule.)
+</p>
+<p>
+Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates
+any of the files listed above, they will be used the same way as described for source
+files.
+</p>
+<p>
+Source files of type <code>.properties</code> are treated as resources.
+</p>
+
+<p>All other files are ignored, as long as there is at least one file of a
+file type described above. Otherwise an error is raised.</p>
+
+<p>
+This argument is almost always required, except if you specify the <code>runtime_deps</code> argument.
+</p>
+            """,
+        ),
+        "data": attr.label_list(
+            allow_files = True,
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE"],
+            doc = """
+The list of files needed by this library at runtime.
+See general comments about <code>data</code> at
+<a href="${link common-definitions#typical-attributes}">Typical attributes defined by
+most build rules</a>.
+<p>
+  When building a <code>java_library</code>, Bazel doesn't put these files anywhere; if the
+  <code>data</code> files are generated files then Bazel generates them. When building a
+  test that depends on this <code>java_library</code> Bazel copies or links the
+  <code>data</code> files into the runfiles area.
+</p>
+            """ + semantics.DOCS.for_attribute("data"),
+        ),
+        "resources": attr.label_list(
+            allow_files = True,
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE", "ORDER_INDEPENDENT"],
+            doc = """
+A list of data files to include in a Java jar.
+<p>
+Resources may be source files or generated files.
+</p>
+            """ + semantics.DOCS.for_attribute("resources"),
+        ),
+        "plugins": attr.label_list(
+            providers = [JavaPluginInfo],
+            allow_files = True,
+            cfg = "exec",
+            doc = """
+Java compiler plugins to run at compile-time.
+Every <code>java_plugin</code> specified in this attribute will be run whenever this rule
+is built. A library may also inherit plugins from dependencies that use
+<code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources
+generated by the plugin will be included in the resulting jar of this rule.
+            """,
+        ),
+        "deps": attr.label_list(
+            allow_files = [".jar"],
+            allow_rules = semantics.ALLOWED_RULES_IN_DEPS + semantics.ALLOWED_RULES_IN_DEPS_WITH_WARNING,
+            providers = [
+                [CcInfo],
+                [JavaInfo],
+            ],
+            flags = ["SKIP_ANALYSIS_TIME_FILETYPE_CHECK"],
+            doc = """
+The list of libraries to link into this library.
+See general comments about <code>deps</code> at
+<a href="${link common-definitions#typical-attributes}">Typical attributes defined by
+most build rules</a>.
+<p>
+  The jars built by <code>java_library</code> rules listed in <code>deps</code> will be on
+  the compile-time classpath of this rule. Furthermore the transitive closure of their
+  <code>deps</code>, <code>runtime_deps</code> and <code>exports</code> will be on the
+  runtime classpath.
+</p>
+<p>
+  By contrast, targets in the <code>data</code> attribute are included in the runfiles but
+  on neither the compile-time nor runtime classpath.
+</p>
+            """,
+        ),
+        "runtime_deps": attr.label_list(
+            allow_files = [".jar"],
+            allow_rules = semantics.ALLOWED_RULES_IN_DEPS,
+            providers = [[CcInfo], [JavaInfo]],
+            flags = ["SKIP_ANALYSIS_TIME_FILETYPE_CHECK"],
+            doc = """
+Libraries to make available to the final binary or test at runtime only.
+Like ordinary <code>deps</code>, these will appear on the runtime classpath, but unlike
+them, not on the compile-time classpath. Dependencies needed only at runtime should be
+listed here. Dependency-analysis tools should ignore targets that appear in both
+<code>runtime_deps</code> and <code>deps</code>.
+            """,
+        ),
+        "exports": attr.label_list(
+            allow_rules = semantics.ALLOWED_RULES_IN_DEPS,
+            providers = [[JavaInfo], [CcInfo]],
+            doc = """
+Exported libraries.
+<p>
+  Listing rules here will make them available to parent rules, as if the parents explicitly
+  depended on these rules. This is not true for regular (non-exported) <code>deps</code>.
+</p>
+<p>
+  Summary: a rule <i>X</i> can access the code in <i>Y</i> if there exists a dependency
+  path between them that begins with a <code>deps</code> edge followed by zero or more
+  <code>exports</code> edges. Let's see some examples to illustrate this.
+</p>
+<p>
+  Assume <i>A</i> depends on <i>B</i> and <i>B</i> depends on <i>C</i>. In this case
+  C is a <em>transitive</em> dependency of A, so changing C's sources and rebuilding A will
+  correctly rebuild everything. However A will not be able to use classes in C. To allow
+  that, either A has to declare C in its <code>deps</code>, or B can make it easier for A
+  (and anything that may depend on A) by declaring C in its (B's) <code>exports</code>
+  attribute.
+</p>
+<p>
+  The closure of exported libraries is available to all direct parent rules. Take a slightly
+  different example: A depends on B, B depends on C and D, and also exports C but not D.
+  Now A has access to C but not to D. Now, if C and D exported some libraries, C' and D'
+  respectively, A could only access C' but not D'.
+</p>
+<p>
+  Important: an exported rule is not a regular dependency. Sticking to the previous example,
+  if B exports C and wants to also use C, it has to also list it in its own
+  <code>deps</code>.
+</p>
+            """,
+        ),
+        "exported_plugins": attr.label_list(
+            providers = [JavaPluginInfo],
+            cfg = "exec",
+            doc = """
+The list of <code><a href="#${link java_plugin}">java_plugin</a></code>s (e.g. annotation
+processors) to export to libraries that directly depend on this library.
+<p>
+  The specified list of <code>java_plugin</code>s will be applied to any library which
+  directly depends on this library, just as if that library had explicitly declared these
+  labels in <code><a href="${link java_library.plugins}">plugins</a></code>.
+</p>
+            """,
+        ),
+        "bootclasspath": attr.label(
+            providers = [BootClassPathInfo],
+            flags = ["SKIP_CONSTRAINTS_OVERRIDE"],
+            doc = """Restricted API, do not use!""",
+        ),
+        "javabuilder_jvm_flags": attr.string_list(doc = """Restricted API, do not use!"""),
+        "javacopts": attr.string_list(
+            doc = """
+Extra compiler options for this library.
+Subject to <a href="make-variables.html">"Make variable"</a> substitution and
+<a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>.
+<p>These compiler options are passed to javac after the global compiler options.</p>
+            """,
+        ),
+        "neverlink": attr.bool(
+            doc = """
+Whether this library should only be used for compilation and not at runtime.
+Useful if the library will be provided by the runtime environment during execution. Examples
+of such libraries are the IDE APIs for IDE plug-ins or <code>tools.jar</code> for anything
+running on a standard JDK.
+<p>
+  Note that <code>neverlink = True</code> does not prevent the compiler from inlining material
+  from this library into compilation targets that depend on it, as permitted by the Java
+  Language Specification (e.g., <code>static final</code> constants of <code>String</code>
+  or of primitive types). The preferred use case is therefore when the runtime library is
+  identical to the compilation library.
+</p>
+<p>
+  If the runtime library differs from the compilation library then you must ensure that it
+  differs only in places that the JLS forbids compilers to inline (and that must hold for
+  all future versions of the JLS).
+</p>
+            """,
+        ),
+        "resource_strip_prefix": attr.string(
+            doc = """
+The path prefix to strip from Java resources.
+<p>
+If specified, this path prefix is stripped from every file in the <code>resources</code>
+attribute. It is an error for a resource file not to be under this directory. If not
+specified (the default), the path of resource file is determined according to the same
+logic as the Java package of source files. For example, a source file at
+<code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>.
+</p>
+            """,
+        ),
+        "proguard_specs": attr.label_list(
+            allow_files = True,
+            doc = """
+Files to be used as Proguard specification.
+These will describe the set of specifications to be used by Proguard. If specified,
+they will be added to any <code>android_binary</code> target depending on this library.
+
+The files included here must only have idempotent rules, namely -dontnote, -dontwarn,
+assumenosideeffects, and rules that start with -keep. Other options can only appear in
+<code>android_binary</code>'s proguard_specs, to ensure non-tautological merges.
+            """,
+        ),
+        "add_exports": attr.string_list(
+            doc = """
+Allow this library to access the given <code>module</code> or <code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-exports= flags.
+            """,
+        ),
+        "add_opens": attr.string_list(
+            doc = """
+Allow this library to reflectively access the given <code>module</code> or
+<code>package</code>.
+<p>
+This corresponds to the javac and JVM --add-opens= flags.
+            """,
+        ),
+        "licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+        "_java_toolchain_type": attr.label(default = semantics.JAVA_TOOLCHAIN_TYPE),
+    },
+)
diff --git a/java/common/rules/java_package_configuration.bzl b/java/common/rules/java_package_configuration.bzl
new file mode 100644
index 0000000..0752e41
--- /dev/null
+++ b/java/common/rules/java_package_configuration.bzl
@@ -0,0 +1,124 @@
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
+
+"""Implementation for the java_package_configuration rule"""
+
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load("//java/private:boot_class_path_info.bzl", "BootClassPathInfo")
+load("//java/private:native.bzl", "get_internal_java_common")
+
+# copybara: default visibility
+
+JavaPackageConfigurationInfo = provider(
+    "A provider for Java per-package configuration",
+    fields = [
+        "data",
+        "javac_opts",
+        "matches",
+        "package_specs",
+        "system",
+    ],
+)
+
+def _matches(package_specs, label):
+    for spec in package_specs:
+        if spec.contains(label):
+            return True
+    return False
+
+def _rule_impl(ctx):
+    javacopts = get_internal_java_common().expand_java_opts(ctx, "javacopts", tokenize = True)
+    javacopts_depset = helper.detokenize_javacopts(javacopts)
+    package_specs = [package[PackageSpecificationInfo] for package in ctx.attr.packages]
+    system = ctx.attr.system[BootClassPathInfo] if ctx.attr.system else None
+    return [
+        DefaultInfo(),
+        JavaPackageConfigurationInfo(
+            data = depset(ctx.files.data),
+            javac_opts = javacopts_depset,
+            matches = _matches,
+            package_specs = package_specs,
+            system = system,
+        ),
+    ]
+
+java_package_configuration = rule(
+    implementation = _rule_impl,
+    doc = """
+<p>
+Configuration to apply to a set of packages.
+Configurations can be added to
+<code><a href="${link java_toolchain.javacopts}">java_toolchain.javacopts</a></code>s.
+</p>
+
+<h4 id="java_package_configuration_example">Example:</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_package_configuration(
+    name = "my_configuration",
+    packages = [":my_packages"],
+    javacopts = ["-Werror"],
+)
+
+package_group(
+    name = "my_packages",
+    packages = [
+        "//com/my/project/...",
+        "-//com/my/project/testing/...",
+    ],
+)
+
+java_toolchain(
+    ...,
+    package_configuration = [
+        ":my_configuration",
+    ]
+)
+
+</code>
+</pre>
+    """,
+    attrs = {
+        "packages": attr.label_list(
+            cfg = "exec",
+            providers = [PackageSpecificationInfo],
+            doc = """
+The set of <code><a href="${link package_group}">package_group</a></code>s
+the configuration should be applied to.
+            """,
+        ),
+        "javacopts": attr.string_list(
+            doc = """
+Java compiler flags.
+            """,
+        ),
+        "data": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """
+The list of files needed by this configuration at runtime.
+            """,
+        ),
+        "system": attr.label(
+            providers = [BootClassPathInfo],
+            doc = """
+Corresponds to javac's --system flag.
+""",
+        ),
+        # buildifier: disable=attr-licenses
+        "output_licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+    },
+)
diff --git a/java/common/rules/java_plugin.bzl b/java/common/rules/java_plugin.bzl
new file mode 100644
index 0000000..5b2cc93
--- /dev/null
+++ b/java/common/rules/java_plugin.bzl
@@ -0,0 +1,52 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""
+Definition of java_plugin rule.
+"""
+
+load(":java_library.bzl", "JAVA_LIBRARY_ATTRS")
+load(":rule_util.bzl", "merge_attrs")
+
+# copybara: default visibility
+
+JAVA_PLUGIN_ATTRS = merge_attrs(
+    JAVA_LIBRARY_ATTRS,
+    {
+        "generates_api": attr.bool(doc = """
+This attribute marks annotation processors that generate API code.
+<p>If a rule uses an API-generating annotation processor, other rules
+depending on it can refer to the generated code only if their
+compilation actions are scheduled after the generating rule. This
+attribute instructs Bazel to introduce scheduling constraints when
+--java_header_compilation is enabled.
+<p><em class="harmful">WARNING: This attribute affects build
+performance, use it only if necessary.</em></p>
+        """),
+        "processor_class": attr.string(doc = """
+The processor class is the fully qualified type of the class that the Java compiler should
+use as entry point to the annotation processor. If not specified, this rule will not
+contribute an annotation processor to the Java compiler's annotation processing, but its
+runtime classpath will still be included on the compiler's annotation processor path. (This
+is primarily intended for use by
+<a href="https://errorprone.info/docs/plugins">Error Prone plugins</a>, which are loaded
+from the annotation processor path using
+<a href="https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html">
+java.util.ServiceLoader</a>.)
+       """),
+        # buildifier: disable=attr-licenses
+        "output_licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+    },
+    remove_attrs = ["runtime_deps", "exports", "exported_plugins"],
+)
diff --git a/java/common/rules/java_runtime.bzl b/java/common/rules/java_runtime.bzl
new file mode 100644
index 0000000..52b1301
--- /dev/null
+++ b/java/common/rules/java_runtime.bzl
@@ -0,0 +1,258 @@
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
+
+"""
+Definition of java_runtime rule and JavaRuntimeInfo provider.
+"""
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+
+# copybara: default visibility
+
+ToolchainInfo = platform_common.ToolchainInfo
+
+def _init_java_runtime_info(**_kwargs):
+    fail("instantiating JavaRuntimeInfo is a private API")
+
+JavaRuntimeInfo, _new_javaruntimeinfo = provider(
+    doc = "Information about the Java runtime used by the java rules.",
+    fields = {
+        "default_cds": "Returns the JDK default CDS archive.",
+        "files": "Returns the files in the Java runtime.",
+        "hermetic_files": "Returns the files in the Java runtime needed for hermetic deployments.",
+        "hermetic_static_libs": "Returns the JDK static libraries.",
+        "java_executable_exec_path": "Returns the execpath of the Java executable.",
+        "java_executable_runfiles_path": """Returns the path of the Java executable in
+                runfiles trees. This should only be used when one needs to access the
+                JVM during the execution of a binary or a test built by Bazel. In particular,
+                when one needs to invoke the JVM during an action, java_executable_exec_path
+                should be used instead.""",
+        "java_home": "Returns the execpath of the root of the Java installation.",
+        "java_home_runfiles_path": """Returns the path of the Java installation in runfiles trees.
+                This should only be used when one needs to access the JDK during the execution
+                of a binary or a test built by Bazel. In particular, when one needs the JDK
+                during an action, java_home should be used instead.""",
+        "lib_ct_sym": "Returns the lib/ct.sym file.",
+        "lib_modules": "Returns the lib/modules file.",
+        "version": "The Java feature version of the runtime. This is 0 if the version is unknown.",
+    },
+    init = _init_java_runtime_info,
+)
+
+def _is_main_repo(label):
+    return label.workspace_name == ""
+
+def _default_java_home(label):
+    if _is_main_repo(label):
+        return label.package
+    else:
+        return helper.get_relative(label.workspace_root, label.package)
+
+def _get_bin_java(ctx):
+    is_windows = helper.is_target_platform_windows(ctx)
+    return "bin/java.exe" if is_windows else "bin/java"
+
+def _get_runfiles_java_executable(ctx, java_home, label):
+    if paths.is_absolute(java_home) or _is_main_repo(label):
+        return helper.get_relative(java_home, _get_bin_java(ctx))
+    else:
+        repo_runfiles_path = "" if _is_main_repo(label) else helper.get_relative("..", label.workspace_name)
+        return helper.get_relative(repo_runfiles_path, _get_bin_java(ctx))
+
+def _is_java_binary(path):
+    return path.endswith("bin/java") or path.endswith("bin/java.exe")
+
+def _get_lib_ct_sym(srcs, explicit_lib_ct_sym):
+    if explicit_lib_ct_sym:
+        return explicit_lib_ct_sym
+    candidates = [src for src in srcs if src.path.endswith("/lib/ct.sym")]
+    if len(candidates) == 1:
+        return candidates[0]
+    else:
+        return None
+
+def _java_runtime_rule_impl(ctx):
+    all_files = []  # [depset[File]]
+    all_files.append(depset(ctx.files.srcs))
+
+    java_home = _default_java_home(ctx.label)
+    if ctx.attr.java_home:
+        java_home_attr = ctx.expand_make_variables("java_home", ctx.attr.java_home, {})
+        if ctx.files.srcs and paths.is_absolute(java_home_attr):
+            fail("'java_home' with an absolute path requires 'srcs' to be empty.")
+        java_home = helper.get_relative(java_home, java_home_attr)
+
+    java_binary_exec_path = helper.get_relative(java_home, _get_bin_java(ctx))
+    java_binary_runfiles_path = _get_runfiles_java_executable(ctx, java_home, ctx.label)
+
+    java = ctx.file.java
+    if java:
+        if paths.is_absolute(java_home):
+            fail("'java_home' with an absolute path requires 'java' to be empty.")
+        java_binary_exec_path = java.path
+        java_binary_runfiles_path = java.short_path
+        if not _is_java_binary(java_binary_exec_path):
+            fail("the path to 'java' must end in 'bin/java'.")
+        java_home = paths.dirname(paths.dirname(java_binary_exec_path))
+        all_files.append(depset([java]))
+
+    java_home_runfiles_path = paths.dirname(paths.dirname(java_binary_runfiles_path))
+
+    hermetic_inputs = depset(ctx.files.hermetic_srcs)
+    all_files.append(hermetic_inputs)
+
+    lib_ct_sym = _get_lib_ct_sym(ctx.files.srcs, ctx.file.lib_ct_sym)
+    lib_modules = ctx.file.lib_modules
+    hermetic_static_libs = [dep[CcInfo] for dep in ctx.attr.hermetic_static_libs]
+
+    # If a runtime does not set default_cds in hermetic mode, it is not fatal.
+    # We can skip the default CDS in the check below.
+    default_cds = ctx.file.default_cds
+
+    if (hermetic_inputs or lib_modules or hermetic_static_libs) and (
+        not hermetic_inputs or not lib_modules or not hermetic_static_libs
+    ):
+        fail("hermetic specified, all of java_runtime.lib_modules, java_runtime.hermetic_srcs and java_runtime.hermetic_static_libs must be specified")
+
+    files = depset(transitive = all_files)
+
+    java_runtime_info = _new_javaruntimeinfo(
+        default_cds = default_cds,
+        files = files,
+        hermetic_files = hermetic_inputs,
+        hermetic_static_libs = hermetic_static_libs,
+        java_executable_exec_path = java_binary_exec_path,
+        java_executable_runfiles_path = java_binary_runfiles_path,
+        java_home = java_home,
+        java_home_runfiles_path = java_home_runfiles_path,
+        lib_ct_sym = lib_ct_sym,
+        lib_modules = lib_modules,
+        version = ctx.attr.version,
+    )
+    return [
+        DefaultInfo(
+            files = files,
+            runfiles = ctx.runfiles(transitive_files = files),
+        ),
+        java_runtime_info,
+        platform_common.TemplateVariableInfo({
+            "JAVA": java_binary_exec_path,
+            "JAVABASE": java_home,
+        }),
+        ToolchainInfo(java_runtime = java_runtime_info),
+    ]
+
+java_runtime = rule(
+    implementation = _java_runtime_rule_impl,
+    doc = """
+<p>
+Specifies the configuration for a Java runtime.
+</p>
+
+<h4 id="java_runtime_example">Example:</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_runtime(
+    name = "jdk-9-ea+153",
+    srcs = glob(["jdk9-ea+153/**"]),
+    java_home = "jdk9-ea+153",
+)
+
+</code>
+</pre>
+    """,
+    attrs = {
+        "default_cds": attr.label(
+            allow_single_file = True,
+            executable = True,
+            cfg = "target",
+            doc = """
+Default CDS archive for hermetic <code>java_runtime</code>. When hermetic
+is enabled for a <code>java_binary</code> target the <code>java_runtime</code>
+default CDS is packaged in the hermetic deploy JAR.
+            """,
+        ),
+        "hermetic_srcs": attr.label_list(
+            allow_files = True,
+            doc = """
+Files in the runtime needed for hermetic deployments.
+            """,
+        ),
+        "hermetic_static_libs": attr.label_list(
+            providers = [CcInfo],
+            doc = """
+The libraries that are statically linked with the launcher for hermetic deployments
+            """,
+        ),
+        "java": attr.label(
+            allow_single_file = True,
+            executable = True,
+            cfg = "target",
+            doc = """
+The path to the java executable.
+            """,
+        ),
+        "java_home": attr.string(
+            doc = """
+The path to the root of the runtime.
+Subject to <a href="${link make-variables}">"Make" variable</a> substitution.
+If this path is absolute, the rule denotes a non-hermetic Java runtime with a well-known
+path. In that case, the <code>srcs</code> and <code>java</code> attributes must be empty.
+            """,
+        ),
+        "lib_ct_sym": attr.label(
+            allow_single_file = True,
+            doc = """
+The lib/ct.sym file needed for compilation with <code>--release</code>. If not specified and
+there is exactly one file in <code>srcs</code> whose path ends with
+<code>/lib/ct.sym</code>, that file is used.
+            """,
+        ),
+        "lib_modules": attr.label(
+            allow_single_file = True,
+            executable = True,
+            cfg = "target",
+            doc = """
+The lib/modules file needed for hermetic deployments.
+            """,
+        ),
+        "srcs": attr.label_list(
+            allow_files = True,
+            doc = """
+All files in the runtime.
+            """,
+        ),
+        "version": attr.int(
+            doc = """
+The feature version of the Java runtime. I.e., the integer returned by
+<code>Runtime.version().feature()</code>.
+            """,
+        ),
+        # buildifier: disable=attr-licenses
+        "output_licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+        "_windows_constraints": attr.label_list(
+            default = [paths.join(semantics.PLATFORMS_ROOT, "os:windows")],
+        ),
+    },
+    fragments = ["java"],
+    provides = [
+        JavaRuntimeInfo,
+        platform_common.TemplateVariableInfo,
+    ],
+)
diff --git a/java/common/rules/java_toolchain.bzl b/java/common/rules/java_toolchain.bzl
new file mode 100644
index 0000000..2e4fc67
--- /dev/null
+++ b/java/common/rules/java_toolchain.bzl
@@ -0,0 +1,611 @@
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
+
+"""
+Definition of java_toolchain rule and JavaToolchainInfo provider.
+"""
+
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load("//java/private:boot_class_path_info.bzl", "BootClassPathInfo")
+load("//java/private:java_info.bzl", "JavaPluginDataInfo")
+load("//java/private:native.bzl", "get_internal_java_common")
+load(":java_package_configuration.bzl", "JavaPackageConfigurationInfo")
+load(":java_runtime.bzl", "JavaRuntimeInfo")
+
+# copybara: default visibility
+
+ToolchainInfo = platform_common.ToolchainInfo
+
+def _java_toolchain_info_init(**_kwargs):
+    fail("JavaToolchainInfo instantiation is a private API")
+
+_PRIVATE_API_DOC_STRING = "internal API, DO NOT USE!"
+
+JavaToolchainInfo, _new_javatoolchaininfo = provider(
+    doc = "Information about the JDK used by the <code>java_*</code> rules.",
+    fields = {
+        "bootclasspath": "(depset[File]) The Java target bootclasspath entries. Corresponds to javac's -bootclasspath flag.",
+        "ijar": "(FilesToRunProvider) The ijar executable.",
+        "jacocorunner": "(FilesToRunProvider) The jacocorunner used by the toolchain.",
+        "java_runtime": "(JavaRuntimeInfo) The java runtime information.",
+        "jvm_opt": "(depset[str]) The default options for the JVM running the java compiler and associated tools.",
+        "label": "(label) The toolchain label.",
+        "proguard_allowlister": "(FilesToRunProvider) The binary to validate proguard configuration.",
+        "single_jar": "(FilesToRunProvider) The SingleJar deploy jar.",
+        "source_version": "(str) The java source version.",
+        "target_version": "(str) The java target version.",
+        "tools": "(depset[File]) The compilation tools.",
+        # private
+        "_android_linter": _PRIVATE_API_DOC_STRING,
+        "_bootclasspath_info": _PRIVATE_API_DOC_STRING,
+        "_bytecode_optimizer": _PRIVATE_API_DOC_STRING,
+        "_compatible_javacopts": _PRIVATE_API_DOC_STRING,
+        "_deps_checker": _PRIVATE_API_DOC_STRING,
+        "_forcibly_disable_header_compilation": _PRIVATE_API_DOC_STRING,
+        "_gen_class": _PRIVATE_API_DOC_STRING,
+        "_header_compiler": _PRIVATE_API_DOC_STRING,
+        "_header_compiler_builtin_processors": _PRIVATE_API_DOC_STRING,
+        "_header_compiler_direct": _PRIVATE_API_DOC_STRING,
+        "_javabuilder": _PRIVATE_API_DOC_STRING,
+        "_javacopts": _PRIVATE_API_DOC_STRING,
+        "_javacopts_list": _PRIVATE_API_DOC_STRING,
+        "_javac_supports_workers": _PRIVATE_API_DOC_STRING,
+        "_javac_supports_multiplex_workers": _PRIVATE_API_DOC_STRING,
+        "_javac_supports_worker_cancellation": _PRIVATE_API_DOC_STRING,
+        "_javac_supports_worker_multiplex_sandboxing": _PRIVATE_API_DOC_STRING,
+        "_jspecify_info": _PRIVATE_API_DOC_STRING,
+        "_local_java_optimization_config": _PRIVATE_API_DOC_STRING,
+        "_one_version_tool": _PRIVATE_API_DOC_STRING,
+        "_one_version_allowlist": _PRIVATE_API_DOC_STRING,
+        "_one_version_allowlist_for_tests": _PRIVATE_API_DOC_STRING,
+        "_package_configuration": _PRIVATE_API_DOC_STRING,
+        "_reduced_classpath_incompatible_processors": _PRIVATE_API_DOC_STRING,
+        "_timezone_data": _PRIVATE_API_DOC_STRING,
+    },
+    init = _java_toolchain_info_init,
+)
+
+def _java_toolchain_impl(ctx):
+    javac_opts_list = _get_javac_opts(ctx)
+    bootclasspath_info = _get_bootclasspath_info(ctx)
+    java_runtime = _get_java_runtime(ctx)
+    if java_runtime and java_runtime.lib_ct_sym:
+        header_compiler_direct_data = [java_runtime.lib_ct_sym]
+        header_compiler_direct_jvm_opts = ["-Dturbine.ctSymPath=" + java_runtime.lib_ct_sym.path]
+    elif java_runtime and java_runtime.java_home:
+        # Turbine finds ct.sym relative to java.home.
+        header_compiler_direct_data = []
+        header_compiler_direct_jvm_opts = ["-Djava.home=" + java_runtime.java_home]
+    else:
+        header_compiler_direct_data = []
+        header_compiler_direct_jvm_opts = []
+    if ctx.attr.oneversion_allowlist and ctx.attr.oneversion_whitelist:
+        fail("oneversion_allowlist and oneversion_whitelist are mutually exclusive")
+    oneversion_allowlist = ctx.file.oneversion_allowlist if ctx.file.oneversion_allowlist else ctx.file.oneversion_whitelist
+    java_toolchain_info = _new_javatoolchaininfo(
+        bootclasspath = bootclasspath_info.bootclasspath,
+        ijar = ctx.attr.ijar.files_to_run if ctx.attr.ijar else None,
+        jacocorunner = ctx.attr.jacocorunner.files_to_run if ctx.attr.jacocorunner else None,
+        java_runtime = java_runtime,
+        jvm_opt = depset(get_internal_java_common().expand_java_opts(ctx, "jvm_opts", tokenize = False, exec_paths = True)),
+        label = ctx.label,
+        proguard_allowlister = ctx.attr.proguard_allowlister.files_to_run if ctx.attr.proguard_allowlister else None,
+        single_jar = ctx.attr.singlejar.files_to_run,
+        source_version = ctx.attr.source_version,
+        target_version = ctx.attr.target_version,
+        tools = depset(ctx.files.tools),
+        # private
+        _android_linter = _get_android_lint_tool(ctx),
+        _bootclasspath_info = bootclasspath_info,
+        _bytecode_optimizer = _get_tool_from_executable(ctx, "_bytecode_optimizer"),
+        _compatible_javacopts = _get_compatible_javacopts(ctx),
+        _deps_checker = ctx.file.deps_checker,
+        _forcibly_disable_header_compilation = ctx.attr.forcibly_disable_header_compilation,
+        _gen_class = ctx.file.genclass,
+        _header_compiler = _get_tool_from_ctx(ctx, "header_compiler", "turbine_data", "turbine_jvm_opts"),
+        _header_compiler_builtin_processors = depset(ctx.attr.header_compiler_builtin_processors),
+        _header_compiler_direct = _get_tool_from_executable(
+            ctx,
+            "header_compiler_direct",
+            data = header_compiler_direct_data,
+            jvm_opts = header_compiler_direct_jvm_opts,
+        ),
+        _javabuilder = _get_tool_from_ctx(ctx, "javabuilder", "javabuilder_data", "javabuilder_jvm_opts"),
+        _javacopts = helper.detokenize_javacopts(javac_opts_list),
+        _javacopts_list = javac_opts_list,
+        _javac_supports_workers = ctx.attr.javac_supports_workers,
+        _javac_supports_multiplex_workers = ctx.attr.javac_supports_multiplex_workers,
+        _javac_supports_worker_cancellation = ctx.attr.javac_supports_worker_cancellation,
+        _javac_supports_worker_multiplex_sandboxing = ctx.attr.javac_supports_worker_multiplex_sandboxing,
+        _jspecify_info = _get_jspecify_info(ctx),
+        _local_java_optimization_config = ctx.files._local_java_optimization_configuration,
+        _one_version_tool = ctx.attr.oneversion.files_to_run if ctx.attr.oneversion else None,
+        _one_version_allowlist = oneversion_allowlist,
+        _one_version_allowlist_for_tests = ctx.file.oneversion_allowlist_for_tests,
+        _package_configuration = [dep[JavaPackageConfigurationInfo] for dep in ctx.attr.package_configuration],
+        _reduced_classpath_incompatible_processors = depset(ctx.attr.reduced_classpath_incompatible_processors, order = "preorder"),
+        _timezone_data = ctx.file.timezone_data,
+    )
+    toolchain_info = ToolchainInfo(java = java_toolchain_info)
+    return [java_toolchain_info, toolchain_info, DefaultInfo()]
+
+def _get_bootclasspath_info(ctx):
+    bootclasspath_infos = [dep[BootClassPathInfo] for dep in ctx.attr.bootclasspath if BootClassPathInfo in dep]
+    if bootclasspath_infos:
+        if len(bootclasspath_infos) != 1:
+            fail("in attribute 'bootclasspath': expected exactly one entry with a BootClassPathInfo provider")
+        else:
+            return bootclasspath_infos[0]
+    else:
+        return BootClassPathInfo(bootclasspath = ctx.files.bootclasspath)
+
+def _get_java_runtime(ctx):
+    if not ctx.attr.java_runtime:
+        return None
+    return ctx.attr.java_runtime[ToolchainInfo].java_runtime
+
+def _get_javac_opts(ctx):
+    opts = []
+    if ctx.attr.source_version:
+        opts.extend(["-source", ctx.attr.source_version])
+    if ctx.attr.target_version:
+        opts.extend(["-target", ctx.attr.target_version])
+    if ctx.attr.xlint:
+        opts.append("-Xlint:" + ",".join(ctx.attr.xlint))
+    opts.extend(get_internal_java_common().expand_java_opts(ctx, "misc", tokenize = True))
+    opts.extend(get_internal_java_common().expand_java_opts(ctx, "javacopts", tokenize = True))
+    return opts
+
+def _get_android_lint_tool(ctx):
+    if not ctx.attr.android_lint_runner:
+        return None
+    files_to_run = ctx.attr.android_lint_runner.files_to_run
+    if not files_to_run or not files_to_run.executable:
+        fail(ctx.attr.android_lint_runner.label, "does not refer to a valid executable target")
+    return struct(
+        tool = files_to_run,
+        data = depset(ctx.files.android_lint_data),
+        jvm_opts = depset([ctx.expand_location(opt, ctx.attr.android_lint_data) for opt in ctx.attr.android_lint_jvm_opts]),
+        lint_opts = [ctx.expand_location(opt, ctx.attr.android_lint_data) for opt in ctx.attr.android_lint_opts],
+        package_config = [dep[JavaPackageConfigurationInfo] for dep in ctx.attr.android_lint_package_configuration],
+    )
+
+def _get_tool_from_ctx(ctx, tool_attr, data_attr, opts_attr):
+    dep = getattr(ctx.attr, tool_attr)
+    if not dep:
+        return None
+    files_to_run = dep.files_to_run
+    if not files_to_run or not files_to_run.executable:
+        fail(dep.label, "does not refer to a valid executable target")
+    data = getattr(ctx.attr, data_attr)
+    return struct(
+        tool = files_to_run,
+        data = depset(getattr(ctx.files, data_attr)),
+        jvm_opts = depset([ctx.expand_location(opt, data) for opt in getattr(ctx.attr, opts_attr)]),
+    )
+
+def _get_tool_from_executable(ctx, attr_name, data = [], jvm_opts = []):
+    dep = getattr(ctx.attr, attr_name)
+    if not dep:
+        return None
+    files_to_run = dep.files_to_run
+    if not files_to_run or not files_to_run.executable:
+        fail(dep.label, "does not refer to a valid executable target")
+    return struct(tool = files_to_run, data = depset(data), jvm_opts = depset(jvm_opts))
+
+def _get_compatible_javacopts(ctx):
+    result = {}
+    for key, opt_list in ctx.attr.compatible_javacopts.items():
+        result[key] = helper.detokenize_javacopts([token for opt in opt_list for token in ctx.tokenize(opt)])
+    return result
+
+def _get_jspecify_info(ctx):
+    if not ctx.attr.jspecify_processor_class:
+        return None
+    stubs = ctx.files.jspecify_stubs
+    javacopts = []
+    javacopts.extend(ctx.attr.jspecify_javacopts)
+    if stubs:
+        javacopts.append("-Astubs=" + ":".join([file.path for file in stubs]))
+    return struct(
+        processor = JavaPluginDataInfo(
+            processor_classes = depset([ctx.attr.jspecify_processor_class]),
+            processor_jars = depset([ctx.file.jspecify_processor]),
+            processor_data = depset(stubs),
+        ),
+        implicit_deps = depset([ctx.file.jspecify_implicit_deps]),
+        javacopts = javacopts,
+        packages = [target[PackageSpecificationInfo] for target in ctx.attr.jspecify_packages],
+    )
+
+def _extract_singleton_list_value(dict, key):
+    if key in dict and type(dict[key]) == type([]):
+        list = dict[key]
+        if len(list) > 1:
+            fail("expected a single value for:", key, "got: ", list)
+        elif len(list) == 1:
+            dict[key] = dict[key][0]
+        else:
+            dict[key] = None
+
+_LEGACY_ANY_TYPE_ATTRS = [
+    "genclass",
+    "deps_checker",
+    "header_compiler",
+    "header_compiler_direct",
+    "ijar",
+    "javabuilder",
+    "singlejar",
+]
+
+def _java_toolchain_initializer(**kwargs):
+    # these attributes are defined as executable `label_list`s in native but are
+    # expected to be singleton values. Since this is not supported in Starlark,
+    # we just inline the value from the list (if present) before invoking the
+    # rule.
+    for attr in _LEGACY_ANY_TYPE_ATTRS:
+        _extract_singleton_list_value(kwargs, attr)
+
+    return kwargs
+
+java_toolchain = rule(
+    implementation = _java_toolchain_impl,
+    initializer = _java_toolchain_initializer,
+    doc = """
+<p>
+Specifies the configuration for the Java compiler. Which toolchain to be used can be changed through
+the --java_toolchain argument. Normally you should not write those kind of rules unless you want to
+tune your Java compiler.
+</p>
+
+<h4>Examples</h4>
+
+<p>A simple example would be:
+</p>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_toolchain(
+    name = "toolchain",
+    source_version = "7",
+    target_version = "7",
+    bootclasspath = ["//tools/jdk:bootclasspath"],
+    xlint = [ "classfile", "divzero", "empty", "options", "path" ],
+    javacopts = [ "-g" ],
+    javabuilder = ":JavaBuilder_deploy.jar",
+)
+</code>
+</pre>
+    """,
+    # buildifier: disable=attr-licenses
+    attrs = {
+        "android_lint_data": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """
+Labels of tools available for label-expansion in android_lint_jvm_opts.
+            """,
+        ),
+        "android_lint_opts": attr.string_list(
+            default = [],
+            doc = """
+The list of Android Lint arguments.
+            """,
+        ),
+        "android_lint_jvm_opts": attr.string_list(
+            default = [],
+            doc = """
+The list of arguments for the JVM when invoking Android Lint.
+            """,
+        ),
+        "android_lint_package_configuration": attr.label_list(
+            cfg = "exec",
+            providers = [JavaPackageConfigurationInfo],
+            allow_files = True,
+            doc = """
+Android Lint Configuration that should be applied to the specified package groups.
+            """,
+        ),
+        "android_lint_runner": attr.label(
+            cfg = "exec",
+            executable = True,
+            allow_single_file = True,
+            doc = """
+Label of the Android Lint runner, if any.
+            """,
+        ),
+        "bootclasspath": attr.label_list(
+            default = [],
+            allow_files = True,
+            doc = """
+The Java target bootclasspath entries. Corresponds to javac's -bootclasspath flag.
+            """,
+        ),
+        "compatible_javacopts": attr.string_list_dict(
+            doc = """Internal API, do not use!""",
+        ),
+        "deps_checker": attr.label(
+            allow_single_file = True,
+            cfg = "exec",
+            executable = True,
+            doc = """
+Label of the ImportDepsChecker deploy jar.
+            """,
+        ),
+        "forcibly_disable_header_compilation": attr.bool(
+            default = False,
+            doc = """
+Overrides --java_header_compilation to disable header compilation on platforms that do not
+support it, e.g. JDK 7 Bazel.
+            """,
+        ),
+        "genclass": attr.label(
+            allow_single_file = True,
+            cfg = "exec",
+            executable = True,
+            doc = """
+Label of the GenClass deploy jar.
+            """,
+        ),
+        "header_compiler": attr.label(
+            allow_single_file = True,
+            cfg = "exec",
+            executable = True,
+            doc = """
+Label of the header compiler. Required if --java_header_compilation is enabled.
+            """,
+        ),
+        "header_compiler_direct": attr.label(
+            allow_single_file = True,
+            cfg = "exec",
+            executable = True,
+            doc = """
+Optional label of the header compiler to use for direct classpath actions that do not
+include any API-generating annotation processors.
+
+<p>This tool does not support annotation processing.
+            """,
+        ),
+        "header_compiler_builtin_processors": attr.string_list(
+            doc = """Internal API, do not use!""",
+        ),
+        "ijar": attr.label(
+            cfg = "exec",
+            allow_files = True,
+            executable = True,
+            doc = """
+Label of the ijar executable.
+            """,
+        ),
+        "jacocorunner": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+            executable = True,
+            doc = """
+Label of the JacocoCoverageRunner deploy jar.
+            """,
+        ),
+        "javabuilder": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+            executable = True,
+            doc = """
+Label of the JavaBuilder deploy jar.
+            """,
+        ),
+        "javabuilder_data": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """
+Labels of data available for label-expansion in javabuilder_jvm_opts.
+            """,
+        ),
+        "javabuilder_jvm_opts": attr.string_list(
+            doc = """
+The list of arguments for the JVM when invoking JavaBuilder.
+            """,
+        ),
+        "java_runtime": attr.label(
+            cfg = "exec",
+            providers = [JavaRuntimeInfo],
+            doc = """
+The java_runtime to use with this toolchain. It defaults to java_runtime
+in execution configuration.
+            """,
+        ),
+        "javac_supports_workers": attr.bool(
+            default = True,
+            doc = """
+True if JavaBuilder supports running as a persistent worker, false if it doesn't.
+            """,
+        ),
+        "javac_supports_multiplex_workers": attr.bool(
+            default = True,
+            doc = """
+True if JavaBuilder supports running as a multiplex persistent worker, false if it doesn't.
+            """,
+        ),
+        "javac_supports_worker_cancellation": attr.bool(
+            default = True,
+            doc = """
+True if JavaBuilder supports cancellation of persistent workers, false if it doesn't.
+            """,
+        ),
+        "javac_supports_worker_multiplex_sandboxing": attr.bool(
+            default = False,
+            doc = """
+True if JavaBuilder supports running as a multiplex persistent worker with sandboxing, false if it doesn't.
+            """,
+        ),
+        "javacopts": attr.string_list(
+            default = [],
+            doc = """
+The list of extra arguments for the Java compiler. Please refer to the Java compiler
+documentation for the extensive list of possible Java compiler flags.
+            """,
+        ),
+        "jspecify_implicit_deps": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+            executable = True,
+            doc = """Experimental, do not use!""",
+        ),
+        "jspecify_javacopts": attr.string_list(
+            doc = """Experimental, do not use!""",
+        ),
+        "jspecify_packages": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            providers = [PackageSpecificationInfo],
+            doc = """Experimental, do not use!""",
+        ),
+        "jspecify_processor": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+            executable = True,
+            doc = """Experimental, do not use!""",
+        ),
+        "jspecify_processor_class": attr.string(
+            doc = """Experimental, do not use!""",
+        ),
+        "jspecify_stubs": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """Experimental, do not use!""",
+        ),
+        "jvm_opts": attr.string_list(
+            default = [],
+            doc = """
+The list of arguments for the JVM when invoking the Java compiler. Please refer to the Java
+virtual machine documentation for the extensive list of possible flags for this option.
+            """,
+        ),
+        "misc": attr.string_list(
+            default = [],
+            doc = """Deprecated: use javacopts instead""",
+        ),
+        "oneversion": attr.label(
+            cfg = "exec",
+            allow_files = True,
+            executable = True,
+            doc = """
+Label of the one-version enforcement binary.
+            """,
+        ),
+        "oneversion_whitelist": attr.label(
+            allow_single_file = True,
+            doc = """Deprecated: use oneversion_allowlist instead""",
+        ),
+        "oneversion_allowlist": attr.label(
+            allow_single_file = True,
+            doc = """
+Label of the one-version allowlist.
+            """,
+        ),
+        "oneversion_allowlist_for_tests": attr.label(
+            allow_single_file = True,
+            doc = """
+Label of the one-version allowlist for tests.
+            """,
+        ),
+        "package_configuration": attr.label_list(
+            cfg = "target",
+            providers = [JavaPackageConfigurationInfo],
+            doc = """
+Configuration that should be applied to the specified package groups.
+            """,
+        ),
+        "proguard_allowlister": attr.label(
+            cfg = "exec",
+            executable = True,
+            allow_files = True,
+            default = semantics.PROGUARD_ALLOWLISTER_LABEL,
+            doc = """
+Label of the Proguard allowlister.
+            """,
+        ),
+        "reduced_classpath_incompatible_processors": attr.string_list(
+            doc = """Internal API, do not use!""",
+        ),
+        "singlejar": attr.label(
+            cfg = "exec",
+            allow_files = True,
+            executable = True,
+            doc = """
+Label of the SingleJar deploy jar.
+            """,
+        ),
+        "source_version": attr.string(
+            doc = """
+The Java source version (e.g., '6' or '7'). It specifies which set of code structures
+are allowed in the Java source code.
+            """,
+        ),
+        "target_version": attr.string(
+            doc = """
+The Java target version (e.g., '6' or '7'). It specifies for which Java runtime the class
+should be build.
+            """,
+        ),
+        "timezone_data": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+            doc = """
+Label of a resource jar containing timezone data. If set, the timezone data is added as an
+implicitly runtime dependency of all java_binary rules.
+            """,
+        ),
+        "tools": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """
+Labels of tools available for label-expansion in jvm_opts.
+            """,
+        ),
+        "turbine_data": attr.label_list(
+            cfg = "exec",
+            allow_files = True,
+            doc = """
+Labels of data available for label-expansion in turbine_jvm_opts.
+            """,
+        ),
+        "turbine_jvm_opts": attr.string_list(
+            doc = """
+The list of arguments for the JVM when invoking turbine.
+            """,
+        ),
+        "xlint": attr.string_list(
+            default = [],
+            doc = """
+The list of warning to add or removes from default list. Precedes it with a dash to
+removes it. Please see the Javac documentation on the -Xlint options for more information.
+            """,
+        ),
+        "licenses": attr.license() if hasattr(attr, "license") else attr.string_list(),
+        "_bytecode_optimizer": attr.label(
+            cfg = "exec",
+            executable = True,
+            default = configuration_field(fragment = "java", name = "java_toolchain_bytecode_optimizer"),
+        ),
+        "_local_java_optimization_configuration": attr.label(
+            cfg = "exec",
+            default = configuration_field(fragment = "java", name = "local_java_optimization_configuration"),
+            allow_files = True,
+        ),
+        "_legacy_any_type_attrs": attr.string_list(default = _LEGACY_ANY_TYPE_ATTRS),
+    },
+    fragments = ["java"],
+)
diff --git a/java/common/rules/rule_util.bzl b/java/common/rules/rule_util.bzl
new file mode 100644
index 0000000..dc62252
--- /dev/null
+++ b/java/common/rules/rule_util.bzl
@@ -0,0 +1,50 @@
+# Copyright 2021 The Bazel Authors. All rights reserved.
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
+"""Defines rule utilities."""
+
+# copybara: default visibility
+
+def merge_attrs(*attribute_dicts, override_attrs = {}, remove_attrs = []):
+    """Merges attributes together.
+
+    Attributes are first merged, then overridden and removed.
+
+    If there are duplicate definitions of an attribute, the last one is used.
+    (Current API doesn't let us compare)
+
+    Overridden and removed attributes need to be present.
+
+    Args:
+      *attribute_dicts: (*dict[str,Attribute]) A list of attribute dictionaries
+        to merge together.
+      override_attrs: (dict[str,Attribute]) A dictionary of attributes to override
+      remove_attrs: (list[str]) A list of attributes to remove.
+    Returns:
+      (dict[str,Attribute]) The merged attributes dictionary.
+    """
+    all_attributes = {}
+    for attribute_dict in attribute_dicts:
+        for key, attr in attribute_dict.items():
+            all_attributes.setdefault(key, attr)
+    for key, attr in override_attrs.items():
+        if all_attributes.get(key) == None:
+            fail("Trying to override attribute %s where there is none." % key)
+        all_attributes[key] = attr
+    for key in remove_attrs:
+        if key in override_attrs:
+            fail("Trying to remove overridden attribute %s." % key)
+        if key not in all_attributes:
+            fail("Trying to remove non-existent attribute %s." % key)
+        all_attributes.pop(key)
+    return all_attributes
diff --git a/java/defs.bzl b/java/defs.bzl
index 64de71a..da1d6af 100644
--- a/java/defs.bzl
+++ b/java/defs.bzl
@@ -13,6 +13,8 @@
 # limitations under the License.
 """Starlark rules for building Java projects."""
 
+load("@com_google_protobuf//bazel:java_lite_proto_library.bzl", _java_lite_proto_library = "java_lite_proto_library")
+load("@com_google_protobuf//bazel:java_proto_library.bzl", _java_proto_library = "java_proto_library")
 load("//java:java_binary.bzl", _java_binary = "java_binary")
 load("//java:java_import.bzl", _java_import = "java_import")
 load("//java:java_library.bzl", _java_library = "java_library")
@@ -41,8 +43,17 @@ java_package_configuration = _java_package_configuration
 
 # Proto rules
 # Deprecated: don't use java proto libraries from here
-java_proto_library = native.java_proto_library
-java_lite_proto_library = native.java_lite_proto_library
+def java_proto_library(**kwargs):
+    if "deprecation" not in kwargs:
+        _java_proto_library(deprecation = "Use java_proto_library from com_google_protobuf", **kwargs)
+    else:
+        _java_proto_library(**kwargs)
+
+def java_lite_proto_library(**kwargs):
+    if "deprecation" not in kwargs:
+        _java_lite_proto_library(deprecation = "Use java_lite_proto_library from com_google_protobuf", **kwargs)
+    else:
+        _java_lite_proto_library(**kwargs)
 
 # Modules and providers
 
diff --git a/java/docs/BUILD.bazel b/java/docs/BUILD.bazel
new file mode 100644
index 0000000..599e4e0
--- /dev/null
+++ b/java/docs/BUILD.bazel
@@ -0,0 +1,39 @@
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+load("@stardoc//stardoc:stardoc.bzl", "stardoc")
+
+exports_files(
+    ["rules.md"],
+    visibility = ["//test:__pkg__"],
+)
+
+bzl_library(
+    name = "rules_bzl",
+    srcs = ["rules.bzl"],
+    deps = [
+        "//java/bazel/rules",
+        "//java/common/rules:toolchain_rules",
+    ],
+)
+
+stardoc(
+    name = "rules_docs",
+    out = "rules_docs.out",
+    input = "rules.bzl",
+    rule_template = ":rule.vm",
+    symbol_names = [
+        # core rules
+        "java_binary",
+        "java_import",
+        "java_library",
+        "java_plugin",
+        "java_test",
+
+        # toolchain rules
+        "java_package_configuration",
+        "java_runtime",
+        "java_toolchain",
+    ],
+    table_of_contents_template = "@stardoc//stardoc:templates/markdown_tables/table_of_contents.vm",
+    visibility = ["//test:__pkg__"],
+    deps = [":rules_bzl"],
+)
diff --git a/java/docs/rule.vm b/java/docs/rule.vm
new file mode 100644
index 0000000..dd89fdf
--- /dev/null
+++ b/java/docs/rule.vm
@@ -0,0 +1,20 @@
+<a id="${ruleName}"></a>
+
+#[[##]]# ${ruleName}
+
+<pre>
+${util.ruleSummary($ruleName, $ruleInfo)}
+</pre>
+
+${ruleInfo.docString}
+
+**ATTRIBUTES**
+
+#if (!$ruleInfo.getAttributeList().isEmpty())
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+#foreach ($attribute in $ruleInfo.getAttributeList())
+| <a id="${ruleName}-${attribute.name}"></a>$attribute.name | #if(!$attribute.docString.isEmpty()) ${util.markdownCellFormat($attribute.docString)} #else - #end  | ${util.attributeTypeString($attribute)} | ${util.mandatoryString($attribute)} | #if(!$attribute.defaultValue.isEmpty()) ${util.markdownCodeSpan($attribute.defaultValue)} #end |
+#end
+#end
\ No newline at end of file
diff --git a/java/docs/rules.bzl b/java/docs/rules.bzl
new file mode 100644
index 0000000..fa6c3dd
--- /dev/null
+++ b/java/docs/rules.bzl
@@ -0,0 +1,22 @@
+"""Java rules"""
+
+load("//java/bazel/rules:bazel_java_binary.bzl", _java_binary = "java_binary")
+load("//java/bazel/rules:bazel_java_import.bzl", _java_import = "java_import")
+load("//java/bazel/rules:bazel_java_library.bzl", _java_library = "java_library")
+load("//java/bazel/rules:bazel_java_plugin.bzl", _java_plugin = "java_plugin")
+load("//java/bazel/rules:bazel_java_test.bzl", _java_test = "java_test")
+load("//java/common/rules:java_package_configuration.bzl", _java_package_configuration = "java_package_configuration")
+load("//java/common/rules:java_runtime.bzl", _java_runtime = "java_runtime")
+load("//java/common/rules:java_toolchain.bzl", _java_toolchain = "java_toolchain")
+
+visibility("private")
+
+java_binary = _java_binary
+java_import = _java_import
+java_library = _java_library
+java_plugin = _java_plugin
+java_test = _java_test
+
+java_package_configuration = _java_package_configuration
+java_runtime = _java_runtime
+java_toolchain = _java_toolchain
diff --git a/java/docs/rules.md b/java/docs/rules.md
new file mode 100644
index 0000000..b6dd015
--- /dev/null
+++ b/java/docs/rules.md
@@ -0,0 +1,590 @@
+<!-- Generated with Stardoc: http://skydoc.bazel.build -->
+
+Java rules
+
+
+## Rules
+
+- [java_binary](#java_binary)
+- [java_import](#java_import)
+- [java_library](#java_library)
+- [java_package_configuration](#java_package_configuration)
+- [java_plugin](#java_plugin)
+- [java_runtime](#java_runtime)
+- [java_test](#java_test)
+- [java_toolchain](#java_toolchain)
+
+
+<a id="java_binary"></a>
+
+## java_binary
+
+<pre>
+java_binary(<a href="#java_binary-name">name</a>, <a href="#java_binary-deps">deps</a>, <a href="#java_binary-srcs">srcs</a>, <a href="#java_binary-data">data</a>, <a href="#java_binary-resources">resources</a>, <a href="#java_binary-add_exports">add_exports</a>, <a href="#java_binary-add_opens">add_opens</a>, <a href="#java_binary-bootclasspath">bootclasspath</a>,
+            <a href="#java_binary-classpath_resources">classpath_resources</a>, <a href="#java_binary-create_executable">create_executable</a>, <a href="#java_binary-deploy_env">deploy_env</a>, <a href="#java_binary-deploy_manifest_lines">deploy_manifest_lines</a>, <a href="#java_binary-env">env</a>, <a href="#java_binary-javacopts">javacopts</a>,
+            <a href="#java_binary-jvm_flags">jvm_flags</a>, <a href="#java_binary-launcher">launcher</a>, <a href="#java_binary-licenses">licenses</a>, <a href="#java_binary-main_class">main_class</a>, <a href="#java_binary-neverlink">neverlink</a>, <a href="#java_binary-plugins">plugins</a>, <a href="#java_binary-resource_strip_prefix">resource_strip_prefix</a>,
+            <a href="#java_binary-runtime_deps">runtime_deps</a>, <a href="#java_binary-stamp">stamp</a>, <a href="#java_binary-use_launcher">use_launcher</a>, <a href="#java_binary-use_testrunner">use_testrunner</a>)
+</pre>
+
+<p>
+  Builds a Java archive ("jar file"), plus a wrapper shell script with the same name as the rule.
+  The wrapper shell script uses a classpath that includes, among other things, a jar file for each
+  library on which the binary depends. When running the wrapper shell script, any nonempty
+  <code>JAVABIN</code> environment variable will take precedence over the version specified via
+  Bazel's <code>--java_runtime_version</code> flag.
+</p>
+<p>
+  The wrapper script accepts several unique flags. Refer to
+  <code>//src/main/java/com/google/devtools/build/lib/bazel/rules/java/java_stub_template.txt</code>
+  for a list of configurable flags and environment variables accepted by the wrapper.
+</p>
+
+<h4 id="java_binary_implicit_outputs">Implicit output targets</h4>
+<ul>
+  <li><code><var>name</var>.jar</code>: A Java archive, containing the class files and other
+    resources corresponding to the binary's direct dependencies.</li>
+  <li><code><var>name</var>-src.jar</code>: An archive containing the sources ("source
+    jar").</li>
+  <li><code><var>name</var>_deploy.jar</code>: A Java archive suitable for deployment (only
+    built if explicitly requested).
+    <p>
+      Building the <code>&lt;<var>name</var>&gt;_deploy.jar</code> target for your rule
+      creates a self-contained jar file with a manifest that allows it to be run with the
+      <code>java -jar</code> command or with the wrapper script's <code>--singlejar</code>
+      option. Using the wrapper script is preferred to <code>java -jar</code> because it
+      also passes the <a href="#java_binary-jvm_flags">JVM flags</a> and the options
+      to load native libraries.
+    </p>
+    <p>
+      The deploy jar contains all the classes that would be found by a classloader that
+      searched the classpath from the binary's wrapper script from beginning to end. It also
+      contains the native libraries needed for dependencies. These are automatically loaded
+      into the JVM at runtime.
+    </p>
+    <p>If your target specifies a <a href="#java_binary.launcher">launcher</a>
+      attribute, then instead of being a normal JAR file, the _deploy.jar will be a
+      native binary. This will contain the launcher plus any native (C++) dependencies of
+      your rule, all linked into a static binary. The actual jar file's bytes will be
+      appended to that native binary, creating a single binary blob containing both the
+      executable and the Java code. You can execute the resulting jar file directly
+      like you would execute any native binary.</p>
+  </li>
+  <li><code><var>name</var>_deploy-src.jar</code>: An archive containing the sources
+    collected from the transitive closure of the target. These will match the classes in the
+    <code>deploy.jar</code> except where jars have no matching source jar.</li>
+</ul>
+
+<p>
+It is good practice to use the name of the source file that is the main entry point of the
+application (minus the extension). For example, if your entry point is called
+<code>Main.java</code>, then your name could be <code>Main</code>.
+</p>
+
+<p>
+  A <code>deps</code> attribute is not allowed in a <code>java_binary</code> rule without
+  <a href="#java_binary-srcs"><code>srcs</code></a>; such a rule requires a
+  <a href="#java_binary-main_class"><code>main_class</code></a> provided by
+  <a href="#java_binary-runtime_deps"><code>runtime_deps</code></a>.
+</p>
+
+<p>The following code snippet illustrates a common mistake:</p>
+
+<pre class="code">
+<code class="lang-starlark">
+java_binary(
+    name = "DontDoThis",
+    srcs = [
+        <var>...</var>,
+        <code class="deprecated">"GeneratedJavaFile.java"</code>,  # a generated .java file
+    ],
+    deps = [<code class="deprecated">":generating_rule",</code>],  # rule that generates that file
+)
+</code>
+</pre>
+
+<p>Do this instead:</p>
+
+<pre class="code">
+<code class="lang-starlark">
+java_binary(
+    name = "DoThisInstead",
+    srcs = [
+        <var>...</var>,
+        ":generating_rule",
+    ],
+)
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_binary-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_binary-deps"></a>deps |  The list of other libraries to be linked in to the target. See general comments about <code>deps</code> at <a href="common-definitions.html#typical-attributes">Typical attributes defined by most build rules</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-srcs"></a>srcs |  The list of source files that are processed to create the target. This attribute is almost always required; see exceptions below. <p> Source files of type <code>.java</code> are compiled. In case of generated <code>.java</code> files it is generally advisable to put the generating rule's name here instead of the name of the file itself. This not only improves readability but makes the rule more resilient to future changes: if the generating rule generates different files in the future, you only need to fix one place: the <code>outs</code> of the generating rule. You should not list the generating rule in <code>deps</code> because it is a no-op. </p> <p> Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if you need to generate a set of <code>.java</code> files with a genrule.) </p> <p> Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates any of the files listed above, they will be used the same way as described for source files. </p><br><br><p> This argument is almost always required, except if a <a href="#java_binary.main_class"><code>main_class</code></a> attribute specifies a class on the runtime classpath or you specify the <code>runtime_deps</code> argument. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-data"></a>data |  The list of files needed by this library at runtime. See general comments about <code>data</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-resources"></a>resources |  A list of data files to include in a Java jar.<br><br><p> Resources may be source files or generated files. </p><br><br><p> If resources are specified, they will be bundled in the jar along with the usual <code>.class</code> files produced by compilation. The location of the resources inside of the jar file is determined by the project structure. Bazel first looks for Maven's <a href="https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html">standard directory layout</a>, (a "src" directory followed by a "resources" directory grandchild). If that is not found, Bazel then looks for the topmost directory named "java" or "javatests" (so, for example, if a resource is at <code>&lt;workspace root&gt;/x/java/y/java/z</code>, the path of the resource will be <code>y/java/z</code>. This heuristic cannot be overridden, however, the <code>resource_strip_prefix</code> attribute can be used to specify a specific alternative directory for resource files.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-add_exports"></a>add_exports |  Allow this library to access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-exports= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_binary-add_opens"></a>add_opens |  Allow this library to reflectively access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-opens= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_binary-bootclasspath"></a>bootclasspath |  Restricted API, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_binary-classpath_resources"></a>classpath_resources |  <em class="harmful">DO NOT USE THIS OPTION UNLESS THERE IS NO OTHER WAY)</em> <p> A list of resources that must be located at the root of the java tree. This attribute's only purpose is to support third-party libraries that require that their resources be found on the classpath as exactly <code>"myconfig.xml"</code>. It is only allowed on binaries and not libraries, due to the danger of namespace conflicts. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-create_executable"></a>create_executable |  Deprecated, use <code>java_single_jar</code> instead.   | Boolean | optional |  `True`  |
+| <a id="java_binary-deploy_env"></a>deploy_env |  A list of other <code>java_binary</code> targets which represent the deployment environment for this binary. Set this attribute when building a plugin which will be loaded by another <code>java_binary</code>.<br/> Setting this attribute excludes all dependencies from the runtime classpath (and the deploy jar) of this binary that are shared between this binary and the targets specified in <code>deploy_env</code>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-deploy_manifest_lines"></a>deploy_manifest_lines |  A list of lines to add to the <code>META-INF/manifest.mf</code> file generated for the <code>*_deploy.jar</code> target. The contents of this attribute are <em>not</em> subject to <a href="make-variables.html">"Make variable"</a> substitution.   | List of strings | optional |  `[]`  |
+| <a id="java_binary-env"></a>env |  -   | <a href="https://bazel.build/rules/lib/dict">Dictionary: String -> String</a> | optional |  `{}`  |
+| <a id="java_binary-javacopts"></a>javacopts |  Extra compiler options for this binary. Subject to <a href="make-variables.html">"Make variable"</a> substitution and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>. <p>These compiler options are passed to javac after the global compiler options.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_binary-jvm_flags"></a>jvm_flags |  A list of flags to embed in the wrapper script generated for running this binary. Subject to <a href="${link make-variables#location}">$(location)</a> and <a href="make-variables.html">"Make variable"</a> substitution, and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>.<br><br><p>The wrapper script for a Java binary includes a CLASSPATH definition (to find all the dependent jars) and invokes the right Java interpreter. The command line generated by the wrapper script includes the name of the main class followed by a <code>"$@"</code> so you can pass along other arguments after the classname.  However, arguments intended for parsing by the JVM must be specified <i>before</i> the classname on the command line.  The contents of <code>jvm_flags</code> are added to the wrapper script before the classname is listed.</p><br><br><p>Note that this attribute has <em>no effect</em> on <code>*_deploy.jar</code> outputs.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_binary-launcher"></a>launcher |  Specify a binary that will be used to run your Java program instead of the normal <code>bin/java</code> program included with the JDK. The target must be a <code>cc_binary</code>. Any <code>cc_binary</code> that implements the <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html"> Java Invocation API</a> can be specified as a value for this attribute.<br><br><p>By default, Bazel will use the normal JDK launcher (bin/java or java.exe).</p><br><br><p>The related <a href="${link user-manual#flag--java_launcher}"><code> --java_launcher</code></a> Bazel flag affects only those <code>java_binary</code> and <code>java_test</code> targets that have <i>not</i> specified a <code>launcher</code> attribute.</p><br><br><p>Note that your native (C++, SWIG, JNI) dependencies will be built differently depending on whether you are using the JDK launcher or another launcher:</p><br><br><ul> <li>If you are using the normal JDK launcher (the default), native dependencies are built as a shared library named <code>{name}_nativedeps.so</code>, where <code>{name}</code> is the <code>name</code> attribute of this java_binary rule. Unused code is <em>not</em> removed by the linker in this configuration.</li><br><br><li>If you are using any other launcher, native (C++) dependencies are statically linked into a binary named <code>{name}_nativedeps</code>, where <code>{name}</code> is the <code>name</code> attribute of this java_binary rule. In this case, the linker will remove any code it thinks is unused from the resulting binary, which means any C++ code accessed only via JNI may not be linked in unless that <code>cc_library</code> target specifies <code>alwayslink = True</code>.</li> </ul><br><br><p>When using any launcher other than the default JDK launcher, the format of the <code>*_deploy.jar</code> output changes. See the main <a href="#java_binary">java_binary</a> docs for details.</p>   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_binary-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_binary-main_class"></a>main_class |  Name of class with <code>main()</code> method to use as entry point. If a rule uses this option, it does not need a <code>srcs=[...]</code> list. Thus, with this attribute one can make an executable from a Java library that already contains one or more <code>main()</code> methods. <p> The value of this attribute is a class name, not a source file. The class must be available at runtime: it may be compiled by this rule (from <code>srcs</code>) or provided by direct or transitive dependencies (through <code>runtime_deps</code> or <code>deps</code>). If the class is unavailable, the binary will fail at runtime; there is no build-time check. </p>   | String | optional |  `""`  |
+| <a id="java_binary-neverlink"></a>neverlink |  -   | Boolean | optional |  `False`  |
+| <a id="java_binary-plugins"></a>plugins |  Java compiler plugins to run at compile-time. Every <code>java_plugin</code> specified in this attribute will be run whenever this rule is built. A library may also inherit plugins from dependencies that use <code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources generated by the plugin will be included in the resulting jar of this rule.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-resource_strip_prefix"></a>resource_strip_prefix |  The path prefix to strip from Java resources. <p> If specified, this path prefix is stripped from every file in the <code>resources</code> attribute. It is an error for a resource file not to be under this directory. If not specified (the default), the path of resource file is determined according to the same logic as the Java package of source files. For example, a source file at <code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>. </p>   | String | optional |  `""`  |
+| <a id="java_binary-runtime_deps"></a>runtime_deps |  Libraries to make available to the final binary or test at runtime only. Like ordinary <code>deps</code>, these will appear on the runtime classpath, but unlike them, not on the compile-time classpath. Dependencies needed only at runtime should be listed here. Dependency-analysis tools should ignore targets that appear in both <code>runtime_deps</code> and <code>deps</code>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_binary-stamp"></a>stamp |  Whether to encode build information into the binary. Possible values: <ul> <li>   <code>stamp = 1</code>: Always stamp the build information into the binary, even in   <a href="${link user-manual#flag--stamp}"><code>--nostamp</code></a> builds. <b>This   setting should be avoided</b>, since it potentially kills remote caching for the   binary and any downstream actions that depend on it. </li> <li>   <code>stamp = 0</code>: Always replace build information by constant values. This   gives good build result caching. </li> <li>   <code>stamp = -1</code>: Embedding of build information is controlled by the   <a href="${link user-manual#flag--stamp}"><code>--[no]stamp</code></a> flag. </li> </ul> <p>Stamped binaries are <em>not</em> rebuilt unless their dependencies change.</p>   | Integer | optional |  `-1`  |
+| <a id="java_binary-use_launcher"></a>use_launcher |  Whether the binary should use a custom launcher.<br><br><p>If this attribute is set to false, the <a href="${link java_binary.launcher}">launcher</a> attribute  and the related <a href="${link user-manual#flag--java_launcher}"><code>--java_launcher</code></a> flag will be ignored for this target.   | Boolean | optional |  `True`  |
+| <a id="java_binary-use_testrunner"></a>use_testrunner |  Use the test runner (by default <code>com.google.testing.junit.runner.BazelTestRunner</code>) class as the main entry point for a Java program, and provide the test class to the test runner as a value of <code>bazel.test_suite</code> system property.<br><br><br/> You can use this to override the default behavior, which is to use test runner for <code>java_test</code> rules, and not use it for <code>java_binary</code> rules.  It is unlikely you will want to do this.  One use is for <code>AllTest</code> rules that are invoked by another rule (to set up a database before running the tests, for example).  The <code>AllTest</code> rule must be declared as a <code>java_binary</code>, but should still use the test runner as its main entry point.<br><br>The name of a test runner class can be overridden with <code>main_class</code> attribute.   | Boolean | optional |  `False`  |
+
+
+<a id="java_import"></a>
+
+## java_import
+
+<pre>
+java_import(<a href="#java_import-name">name</a>, <a href="#java_import-deps">deps</a>, <a href="#java_import-data">data</a>, <a href="#java_import-add_exports">add_exports</a>, <a href="#java_import-add_opens">add_opens</a>, <a href="#java_import-constraints">constraints</a>, <a href="#java_import-exports">exports</a>, <a href="#java_import-jars">jars</a>, <a href="#java_import-licenses">licenses</a>,
+            <a href="#java_import-neverlink">neverlink</a>, <a href="#java_import-proguard_specs">proguard_specs</a>, <a href="#java_import-runtime_deps">runtime_deps</a>, <a href="#java_import-srcjar">srcjar</a>)
+</pre>
+
+<p>
+  This rule allows the use of precompiled <code>.jar</code> files as
+  libraries for <code><a href="#java_library">java_library</a></code> and
+  <code>java_binary</code> rules.
+</p>
+
+<h4 id="java_import_examples">Examples</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+    java_import(
+        name = "maven_model",
+        jars = [
+            "maven_model/maven-aether-provider-3.2.3.jar",
+            "maven_model/maven-model-3.2.3.jar",
+            "maven_model/maven-model-builder-3.2.3.jar",
+        ],
+    )
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_import-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_import-deps"></a>deps |  The list of other libraries to be linked in to the target. See <a href="${link java_library.deps}">java_library.deps</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_import-data"></a>data |  The list of files needed by this rule at runtime.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_import-add_exports"></a>add_exports |  Allow this library to access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-exports= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_import-add_opens"></a>add_opens |  Allow this library to reflectively access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-opens= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_import-constraints"></a>constraints |  Extra constraints imposed on this rule as a Java library.   | List of strings | optional |  `[]`  |
+| <a id="java_import-exports"></a>exports |  Targets to make available to users of this rule. See <a href="${link java_library.exports}">java_library.exports</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_import-jars"></a>jars |  The list of JAR files provided to Java targets that depend on this target.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | required |  |
+| <a id="java_import-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_import-neverlink"></a>neverlink |  Only use this library for compilation and not at runtime. Useful if the library will be provided by the runtime environment during execution. Examples of libraries like this are IDE APIs for IDE plug-ins or <code>tools.jar</code> for anything running on a standard JDK.   | Boolean | optional |  `False`  |
+| <a id="java_import-proguard_specs"></a>proguard_specs |  Files to be used as Proguard specification. These will describe the set of specifications to be used by Proguard. If specified, they will be added to any <code>android_binary</code> target depending on this library.<br><br>The files included here must only have idempotent rules, namely -dontnote, -dontwarn, assumenosideeffects, and rules that start with -keep. Other options can only appear in <code>android_binary</code>'s proguard_specs, to ensure non-tautological merges.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_import-runtime_deps"></a>runtime_deps |  Libraries to make available to the final binary or test at runtime only. See <a href="${link java_library.runtime_deps}">java_library.runtime_deps</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_import-srcjar"></a>srcjar |  A JAR file that contains source code for the compiled JAR files.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+
+
+<a id="java_library"></a>
+
+## java_library
+
+<pre>
+java_library(<a href="#java_library-name">name</a>, <a href="#java_library-deps">deps</a>, <a href="#java_library-srcs">srcs</a>, <a href="#java_library-data">data</a>, <a href="#java_library-resources">resources</a>, <a href="#java_library-add_exports">add_exports</a>, <a href="#java_library-add_opens">add_opens</a>, <a href="#java_library-bootclasspath">bootclasspath</a>,
+             <a href="#java_library-exported_plugins">exported_plugins</a>, <a href="#java_library-exports">exports</a>, <a href="#java_library-javabuilder_jvm_flags">javabuilder_jvm_flags</a>, <a href="#java_library-javacopts">javacopts</a>, <a href="#java_library-licenses">licenses</a>, <a href="#java_library-neverlink">neverlink</a>,
+             <a href="#java_library-plugins">plugins</a>, <a href="#java_library-proguard_specs">proguard_specs</a>, <a href="#java_library-resource_strip_prefix">resource_strip_prefix</a>, <a href="#java_library-runtime_deps">runtime_deps</a>)
+</pre>
+
+<p>This rule compiles and links sources into a <code>.jar</code> file.</p>
+
+<h4>Implicit outputs</h4>
+<ul>
+  <li><code>lib<var>name</var>.jar</code>: A Java archive containing the class files.</li>
+  <li><code>lib<var>name</var>-src.jar</code>: An archive containing the sources ("source
+    jar").</li>
+</ul>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_library-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_library-deps"></a>deps |  The list of libraries to link into this library. See general comments about <code>deps</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>. <p>   The jars built by <code>java_library</code> rules listed in <code>deps</code> will be on   the compile-time classpath of this rule. Furthermore the transitive closure of their   <code>deps</code>, <code>runtime_deps</code> and <code>exports</code> will be on the   runtime classpath. </p> <p>   By contrast, targets in the <code>data</code> attribute are included in the runfiles but   on neither the compile-time nor runtime classpath. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-srcs"></a>srcs |  The list of source files that are processed to create the target. This attribute is almost always required; see exceptions below. <p> Source files of type <code>.java</code> are compiled. In case of generated <code>.java</code> files it is generally advisable to put the generating rule's name here instead of the name of the file itself. This not only improves readability but makes the rule more resilient to future changes: if the generating rule generates different files in the future, you only need to fix one place: the <code>outs</code> of the generating rule. You should not list the generating rule in <code>deps</code> because it is a no-op. </p> <p> Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if you need to generate a set of <code>.java</code> files with a genrule.) </p> <p> Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates any of the files listed above, they will be used the same way as described for source files. </p> <p> Source files of type <code>.properties</code> are treated as resources. </p><br><br><p>All other files are ignored, as long as there is at least one file of a file type described above. Otherwise an error is raised.</p><br><br><p> This argument is almost always required, except if you specify the <code>runtime_deps</code> argument. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-data"></a>data |  The list of files needed by this library at runtime. See general comments about <code>data</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>. <p>   When building a <code>java_library</code>, Bazel doesn't put these files anywhere; if the   <code>data</code> files are generated files then Bazel generates them. When building a   test that depends on this <code>java_library</code> Bazel copies or links the   <code>data</code> files into the runfiles area. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-resources"></a>resources |  A list of data files to include in a Java jar. <p> Resources may be source files or generated files. </p><br><br><p> If resources are specified, they will be bundled in the jar along with the usual <code>.class</code> files produced by compilation. The location of the resources inside of the jar file is determined by the project structure. Bazel first looks for Maven's <a href="https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html">standard directory layout</a>, (a "src" directory followed by a "resources" directory grandchild). If that is not found, Bazel then looks for the topmost directory named "java" or "javatests" (so, for example, if a resource is at <code>&lt;workspace root&gt;/x/java/y/java/z</code>, the path of the resource will be <code>y/java/z</code>. This heuristic cannot be overridden, however, the <code>resource_strip_prefix</code> attribute can be used to specify a specific alternative directory for resource files.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-add_exports"></a>add_exports |  Allow this library to access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-exports= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_library-add_opens"></a>add_opens |  Allow this library to reflectively access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-opens= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_library-bootclasspath"></a>bootclasspath |  Restricted API, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_library-exported_plugins"></a>exported_plugins |  The list of <code><a href="#${link java_plugin}">java_plugin</a></code>s (e.g. annotation processors) to export to libraries that directly depend on this library. <p>   The specified list of <code>java_plugin</code>s will be applied to any library which   directly depends on this library, just as if that library had explicitly declared these   labels in <code><a href="${link java_library.plugins}">plugins</a></code>. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-exports"></a>exports |  Exported libraries. <p>   Listing rules here will make them available to parent rules, as if the parents explicitly   depended on these rules. This is not true for regular (non-exported) <code>deps</code>. </p> <p>   Summary: a rule <i>X</i> can access the code in <i>Y</i> if there exists a dependency   path between them that begins with a <code>deps</code> edge followed by zero or more   <code>exports</code> edges. Let's see some examples to illustrate this. </p> <p>   Assume <i>A</i> depends on <i>B</i> and <i>B</i> depends on <i>C</i>. In this case   C is a <em>transitive</em> dependency of A, so changing C's sources and rebuilding A will   correctly rebuild everything. However A will not be able to use classes in C. To allow   that, either A has to declare C in its <code>deps</code>, or B can make it easier for A   (and anything that may depend on A) by declaring C in its (B's) <code>exports</code>   attribute. </p> <p>   The closure of exported libraries is available to all direct parent rules. Take a slightly   different example: A depends on B, B depends on C and D, and also exports C but not D.   Now A has access to C but not to D. Now, if C and D exported some libraries, C' and D'   respectively, A could only access C' but not D'. </p> <p>   Important: an exported rule is not a regular dependency. Sticking to the previous example,   if B exports C and wants to also use C, it has to also list it in its own   <code>deps</code>. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-javabuilder_jvm_flags"></a>javabuilder_jvm_flags |  Restricted API, do not use!   | List of strings | optional |  `[]`  |
+| <a id="java_library-javacopts"></a>javacopts |  Extra compiler options for this library. Subject to <a href="make-variables.html">"Make variable"</a> substitution and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>. <p>These compiler options are passed to javac after the global compiler options.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_library-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_library-neverlink"></a>neverlink |  Whether this library should only be used for compilation and not at runtime. Useful if the library will be provided by the runtime environment during execution. Examples of such libraries are the IDE APIs for IDE plug-ins or <code>tools.jar</code> for anything running on a standard JDK. <p>   Note that <code>neverlink = True</code> does not prevent the compiler from inlining material   from this library into compilation targets that depend on it, as permitted by the Java   Language Specification (e.g., <code>static final</code> constants of <code>String</code>   or of primitive types). The preferred use case is therefore when the runtime library is   identical to the compilation library. </p> <p>   If the runtime library differs from the compilation library then you must ensure that it   differs only in places that the JLS forbids compilers to inline (and that must hold for   all future versions of the JLS). </p>   | Boolean | optional |  `False`  |
+| <a id="java_library-plugins"></a>plugins |  Java compiler plugins to run at compile-time. Every <code>java_plugin</code> specified in this attribute will be run whenever this rule is built. A library may also inherit plugins from dependencies that use <code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources generated by the plugin will be included in the resulting jar of this rule.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-proguard_specs"></a>proguard_specs |  Files to be used as Proguard specification. These will describe the set of specifications to be used by Proguard. If specified, they will be added to any <code>android_binary</code> target depending on this library.<br><br>The files included here must only have idempotent rules, namely -dontnote, -dontwarn, assumenosideeffects, and rules that start with -keep. Other options can only appear in <code>android_binary</code>'s proguard_specs, to ensure non-tautological merges.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_library-resource_strip_prefix"></a>resource_strip_prefix |  The path prefix to strip from Java resources. <p> If specified, this path prefix is stripped from every file in the <code>resources</code> attribute. It is an error for a resource file not to be under this directory. If not specified (the default), the path of resource file is determined according to the same logic as the Java package of source files. For example, a source file at <code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>. </p>   | String | optional |  `""`  |
+| <a id="java_library-runtime_deps"></a>runtime_deps |  Libraries to make available to the final binary or test at runtime only. Like ordinary <code>deps</code>, these will appear on the runtime classpath, but unlike them, not on the compile-time classpath. Dependencies needed only at runtime should be listed here. Dependency-analysis tools should ignore targets that appear in both <code>runtime_deps</code> and <code>deps</code>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+
+
+<a id="java_package_configuration"></a>
+
+## java_package_configuration
+
+<pre>
+java_package_configuration(<a href="#java_package_configuration-name">name</a>, <a href="#java_package_configuration-data">data</a>, <a href="#java_package_configuration-javacopts">javacopts</a>, <a href="#java_package_configuration-output_licenses">output_licenses</a>, <a href="#java_package_configuration-packages">packages</a>, <a href="#java_package_configuration-system">system</a>)
+</pre>
+
+<p>
+Configuration to apply to a set of packages.
+Configurations can be added to
+<code><a href="${link java_toolchain.javacopts}">java_toolchain.javacopts</a></code>s.
+</p>
+
+<h4 id="java_package_configuration_example">Example:</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_package_configuration(
+    name = "my_configuration",
+    packages = [":my_packages"],
+    javacopts = ["-Werror"],
+)
+
+package_group(
+    name = "my_packages",
+    packages = [
+        "//com/my/project/...",
+        "-//com/my/project/testing/...",
+    ],
+)
+
+java_toolchain(
+    ...,
+    package_configuration = [
+        ":my_configuration",
+    ]
+)
+
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_package_configuration-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_package_configuration-data"></a>data |  The list of files needed by this configuration at runtime.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_package_configuration-javacopts"></a>javacopts |  Java compiler flags.   | List of strings | optional |  `[]`  |
+| <a id="java_package_configuration-output_licenses"></a>output_licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_package_configuration-packages"></a>packages |  The set of <code><a href="${link package_group}">package_group</a></code>s the configuration should be applied to.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_package_configuration-system"></a>system |  Corresponds to javac's --system flag.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+
+
+<a id="java_plugin"></a>
+
+## java_plugin
+
+<pre>
+java_plugin(<a href="#java_plugin-name">name</a>, <a href="#java_plugin-deps">deps</a>, <a href="#java_plugin-srcs">srcs</a>, <a href="#java_plugin-data">data</a>, <a href="#java_plugin-resources">resources</a>, <a href="#java_plugin-add_exports">add_exports</a>, <a href="#java_plugin-add_opens">add_opens</a>, <a href="#java_plugin-bootclasspath">bootclasspath</a>, <a href="#java_plugin-generates_api">generates_api</a>,
+            <a href="#java_plugin-javabuilder_jvm_flags">javabuilder_jvm_flags</a>, <a href="#java_plugin-javacopts">javacopts</a>, <a href="#java_plugin-licenses">licenses</a>, <a href="#java_plugin-neverlink">neverlink</a>, <a href="#java_plugin-output_licenses">output_licenses</a>, <a href="#java_plugin-plugins">plugins</a>,
+            <a href="#java_plugin-processor_class">processor_class</a>, <a href="#java_plugin-proguard_specs">proguard_specs</a>, <a href="#java_plugin-resource_strip_prefix">resource_strip_prefix</a>)
+</pre>
+
+<p>
+  <code>java_plugin</code> defines plugins for the Java compiler run by Bazel. The
+  only supported kind of plugins are annotation processors. A <code>java_library</code> or
+  <code>java_binary</code> rule can run plugins by depending on them via the <code>plugins</code>
+  attribute. A <code>java_library</code> can also automatically export plugins to libraries that
+  directly depend on it using
+  <code><a href="#java_library-exported_plugins">exported_plugins</a></code>.
+</p>
+
+<h4 id="java_plugin_implicit_outputs">Implicit output targets</h4>
+    <ul>
+      <li><code><var>libname</var>.jar</code>: A Java archive.</li>
+    </ul>
+
+<p>
+  Arguments are identical to <a href="#java_library"><code>java_library</code></a>, except
+  for the addition of the <code>processor_class</code> argument.
+</p>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_plugin-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_plugin-deps"></a>deps |  The list of libraries to link into this library. See general comments about <code>deps</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>. <p>   The jars built by <code>java_library</code> rules listed in <code>deps</code> will be on   the compile-time classpath of this rule. Furthermore the transitive closure of their   <code>deps</code>, <code>runtime_deps</code> and <code>exports</code> will be on the   runtime classpath. </p> <p>   By contrast, targets in the <code>data</code> attribute are included in the runfiles but   on neither the compile-time nor runtime classpath. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-srcs"></a>srcs |  The list of source files that are processed to create the target. This attribute is almost always required; see exceptions below. <p> Source files of type <code>.java</code> are compiled. In case of generated <code>.java</code> files it is generally advisable to put the generating rule's name here instead of the name of the file itself. This not only improves readability but makes the rule more resilient to future changes: if the generating rule generates different files in the future, you only need to fix one place: the <code>outs</code> of the generating rule. You should not list the generating rule in <code>deps</code> because it is a no-op. </p> <p> Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if you need to generate a set of <code>.java</code> files with a genrule.) </p> <p> Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates any of the files listed above, they will be used the same way as described for source files. </p> <p> Source files of type <code>.properties</code> are treated as resources. </p><br><br><p>All other files are ignored, as long as there is at least one file of a file type described above. Otherwise an error is raised.</p><br><br><p> This argument is almost always required, except if you specify the <code>runtime_deps</code> argument. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-data"></a>data |  The list of files needed by this library at runtime. See general comments about <code>data</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>. <p>   When building a <code>java_library</code>, Bazel doesn't put these files anywhere; if the   <code>data</code> files are generated files then Bazel generates them. When building a   test that depends on this <code>java_library</code> Bazel copies or links the   <code>data</code> files into the runfiles area. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-resources"></a>resources |  A list of data files to include in a Java jar. <p> Resources may be source files or generated files. </p><br><br><p> If resources are specified, they will be bundled in the jar along with the usual <code>.class</code> files produced by compilation. The location of the resources inside of the jar file is determined by the project structure. Bazel first looks for Maven's <a href="https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html">standard directory layout</a>, (a "src" directory followed by a "resources" directory grandchild). If that is not found, Bazel then looks for the topmost directory named "java" or "javatests" (so, for example, if a resource is at <code>&lt;workspace root&gt;/x/java/y/java/z</code>, the path of the resource will be <code>y/java/z</code>. This heuristic cannot be overridden, however, the <code>resource_strip_prefix</code> attribute can be used to specify a specific alternative directory for resource files.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-add_exports"></a>add_exports |  Allow this library to access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-exports= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-add_opens"></a>add_opens |  Allow this library to reflectively access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-opens= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-bootclasspath"></a>bootclasspath |  Restricted API, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_plugin-generates_api"></a>generates_api |  This attribute marks annotation processors that generate API code. <p>If a rule uses an API-generating annotation processor, other rules depending on it can refer to the generated code only if their compilation actions are scheduled after the generating rule. This attribute instructs Bazel to introduce scheduling constraints when --java_header_compilation is enabled. <p><em class="harmful">WARNING: This attribute affects build performance, use it only if necessary.</em></p>   | Boolean | optional |  `False`  |
+| <a id="java_plugin-javabuilder_jvm_flags"></a>javabuilder_jvm_flags |  Restricted API, do not use!   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-javacopts"></a>javacopts |  Extra compiler options for this library. Subject to <a href="make-variables.html">"Make variable"</a> substitution and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>. <p>These compiler options are passed to javac after the global compiler options.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-neverlink"></a>neverlink |  Whether this library should only be used for compilation and not at runtime. Useful if the library will be provided by the runtime environment during execution. Examples of such libraries are the IDE APIs for IDE plug-ins or <code>tools.jar</code> for anything running on a standard JDK. <p>   Note that <code>neverlink = True</code> does not prevent the compiler from inlining material   from this library into compilation targets that depend on it, as permitted by the Java   Language Specification (e.g., <code>static final</code> constants of <code>String</code>   or of primitive types). The preferred use case is therefore when the runtime library is   identical to the compilation library. </p> <p>   If the runtime library differs from the compilation library then you must ensure that it   differs only in places that the JLS forbids compilers to inline (and that must hold for   all future versions of the JLS). </p>   | Boolean | optional |  `False`  |
+| <a id="java_plugin-output_licenses"></a>output_licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_plugin-plugins"></a>plugins |  Java compiler plugins to run at compile-time. Every <code>java_plugin</code> specified in this attribute will be run whenever this rule is built. A library may also inherit plugins from dependencies that use <code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources generated by the plugin will be included in the resulting jar of this rule.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-processor_class"></a>processor_class |  The processor class is the fully qualified type of the class that the Java compiler should use as entry point to the annotation processor. If not specified, this rule will not contribute an annotation processor to the Java compiler's annotation processing, but its runtime classpath will still be included on the compiler's annotation processor path. (This is primarily intended for use by <a href="https://errorprone.info/docs/plugins">Error Prone plugins</a>, which are loaded from the annotation processor path using <a href="https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html"> java.util.ServiceLoader</a>.)   | String | optional |  `""`  |
+| <a id="java_plugin-proguard_specs"></a>proguard_specs |  Files to be used as Proguard specification. These will describe the set of specifications to be used by Proguard. If specified, they will be added to any <code>android_binary</code> target depending on this library.<br><br>The files included here must only have idempotent rules, namely -dontnote, -dontwarn, assumenosideeffects, and rules that start with -keep. Other options can only appear in <code>android_binary</code>'s proguard_specs, to ensure non-tautological merges.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_plugin-resource_strip_prefix"></a>resource_strip_prefix |  The path prefix to strip from Java resources. <p> If specified, this path prefix is stripped from every file in the <code>resources</code> attribute. It is an error for a resource file not to be under this directory. If not specified (the default), the path of resource file is determined according to the same logic as the Java package of source files. For example, a source file at <code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>. </p>   | String | optional |  `""`  |
+
+
+<a id="java_runtime"></a>
+
+## java_runtime
+
+<pre>
+java_runtime(<a href="#java_runtime-name">name</a>, <a href="#java_runtime-srcs">srcs</a>, <a href="#java_runtime-default_cds">default_cds</a>, <a href="#java_runtime-hermetic_srcs">hermetic_srcs</a>, <a href="#java_runtime-hermetic_static_libs">hermetic_static_libs</a>, <a href="#java_runtime-java">java</a>, <a href="#java_runtime-java_home">java_home</a>,
+             <a href="#java_runtime-lib_ct_sym">lib_ct_sym</a>, <a href="#java_runtime-lib_modules">lib_modules</a>, <a href="#java_runtime-output_licenses">output_licenses</a>, <a href="#java_runtime-version">version</a>)
+</pre>
+
+<p>
+Specifies the configuration for a Java runtime.
+</p>
+
+<h4 id="java_runtime_example">Example:</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_runtime(
+    name = "jdk-9-ea+153",
+    srcs = glob(["jdk9-ea+153/**"]),
+    java_home = "jdk9-ea+153",
+)
+
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_runtime-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_runtime-srcs"></a>srcs |  All files in the runtime.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_runtime-default_cds"></a>default_cds |  Default CDS archive for hermetic <code>java_runtime</code>. When hermetic is enabled for a <code>java_binary</code> target and if the target does not provide its own CDS archive by specifying the <a href="${link java_binary.classlist}"><code>classlist</code></a> attribute, the <code>java_runtime</code> default CDS is packaged in the hermetic deploy JAR.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_runtime-hermetic_srcs"></a>hermetic_srcs |  Files in the runtime needed for hermetic deployments.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_runtime-hermetic_static_libs"></a>hermetic_static_libs |  The libraries that are statically linked with the launcher for hermetic deployments   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_runtime-java"></a>java |  The path to the java executable.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_runtime-java_home"></a>java_home |  The path to the root of the runtime. Subject to <a href="${link make-variables}">"Make" variable</a> substitution. If this path is absolute, the rule denotes a non-hermetic Java runtime with a well-known path. In that case, the <code>srcs</code> and <code>java</code> attributes must be empty.   | String | optional |  `""`  |
+| <a id="java_runtime-lib_ct_sym"></a>lib_ct_sym |  The lib/ct.sym file needed for compilation with <code>--release</code>. If not specified and there is exactly one file in <code>srcs</code> whose path ends with <code>/lib/ct.sym</code>, that file is used.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_runtime-lib_modules"></a>lib_modules |  The lib/modules file needed for hermetic deployments.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_runtime-output_licenses"></a>output_licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_runtime-version"></a>version |  The feature version of the Java runtime. I.e., the integer returned by <code>Runtime.version().feature()</code>.   | Integer | optional |  `0`  |
+
+
+<a id="java_test"></a>
+
+## java_test
+
+<pre>
+java_test(<a href="#java_test-name">name</a>, <a href="#java_test-deps">deps</a>, <a href="#java_test-srcs">srcs</a>, <a href="#java_test-data">data</a>, <a href="#java_test-resources">resources</a>, <a href="#java_test-add_exports">add_exports</a>, <a href="#java_test-add_opens">add_opens</a>, <a href="#java_test-bootclasspath">bootclasspath</a>,
+          <a href="#java_test-classpath_resources">classpath_resources</a>, <a href="#java_test-create_executable">create_executable</a>, <a href="#java_test-deploy_manifest_lines">deploy_manifest_lines</a>, <a href="#java_test-env">env</a>, <a href="#java_test-env_inherit">env_inherit</a>, <a href="#java_test-javacopts">javacopts</a>,
+          <a href="#java_test-jvm_flags">jvm_flags</a>, <a href="#java_test-launcher">launcher</a>, <a href="#java_test-licenses">licenses</a>, <a href="#java_test-main_class">main_class</a>, <a href="#java_test-neverlink">neverlink</a>, <a href="#java_test-plugins">plugins</a>, <a href="#java_test-resource_strip_prefix">resource_strip_prefix</a>,
+          <a href="#java_test-runtime_deps">runtime_deps</a>, <a href="#java_test-stamp">stamp</a>, <a href="#java_test-test_class">test_class</a>, <a href="#java_test-use_launcher">use_launcher</a>, <a href="#java_test-use_testrunner">use_testrunner</a>)
+</pre>
+
+<p>
+A <code>java_test()</code> rule compiles a Java test. A test is a binary wrapper around your
+test code. The test runner's main method is invoked instead of the main class being compiled.
+</p>
+
+<h4 id="java_test_implicit_outputs">Implicit output targets</h4>
+<ul>
+  <li><code><var>name</var>.jar</code>: A Java archive.</li>
+  <li><code><var>name</var>_deploy.jar</code>: A Java archive suitable
+    for deployment. (Only built if explicitly requested.) See the description of the
+    <code><var>name</var>_deploy.jar</code> output from
+    <a href="#java_binary">java_binary</a> for more details.</li>
+</ul>
+
+<p>
+See the section on <code>java_binary()</code> arguments. This rule also
+supports all <a href="https://bazel.build/reference/be/common-definitions#common-attributes-tests">attributes common
+to all test rules (*_test)</a>.
+</p>
+
+<h4 id="java_test_examples">Examples</h4>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_library(
+    name = "tests",
+    srcs = glob(["*.java"]),
+    deps = [
+        "//java/com/foo/base:testResources",
+        "//java/com/foo/testing/util",
+    ],
+)
+
+java_test(
+    name = "AllTests",
+    size = "small",
+    runtime_deps = [
+        ":tests",
+        "//util/mysql",
+    ],
+)
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_test-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_test-deps"></a>deps |  The list of other libraries to be linked in to the target. See general comments about <code>deps</code> at <a href="common-definitions.html#typical-attributes">Typical attributes defined by most build rules</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-srcs"></a>srcs |  The list of source files that are processed to create the target. This attribute is almost always required; see exceptions below. <p> Source files of type <code>.java</code> are compiled. In case of generated <code>.java</code> files it is generally advisable to put the generating rule's name here instead of the name of the file itself. This not only improves readability but makes the rule more resilient to future changes: if the generating rule generates different files in the future, you only need to fix one place: the <code>outs</code> of the generating rule. You should not list the generating rule in <code>deps</code> because it is a no-op. </p> <p> Source files of type <code>.srcjar</code> are unpacked and compiled. (This is useful if you need to generate a set of <code>.java</code> files with a genrule.) </p> <p> Rules: if the rule (typically <code>genrule</code> or <code>filegroup</code>) generates any of the files listed above, they will be used the same way as described for source files. </p><br><br><p> This argument is almost always required, except if a <a href="#java_binary.main_class"><code>main_class</code></a> attribute specifies a class on the runtime classpath or you specify the <code>runtime_deps</code> argument. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-data"></a>data |  The list of files needed by this library at runtime. See general comments about <code>data</code> at <a href="${link common-definitions#typical-attributes}">Typical attributes defined by most build rules</a>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-resources"></a>resources |  A list of data files to include in a Java jar.<br><br><p> Resources may be source files or generated files. </p><br><br><p> If resources are specified, they will be bundled in the jar along with the usual <code>.class</code> files produced by compilation. The location of the resources inside of the jar file is determined by the project structure. Bazel first looks for Maven's <a href="https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html">standard directory layout</a>, (a "src" directory followed by a "resources" directory grandchild). If that is not found, Bazel then looks for the topmost directory named "java" or "javatests" (so, for example, if a resource is at <code>&lt;workspace root&gt;/x/java/y/java/z</code>, the path of the resource will be <code>y/java/z</code>. This heuristic cannot be overridden, however, the <code>resource_strip_prefix</code> attribute can be used to specify a specific alternative directory for resource files.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-add_exports"></a>add_exports |  Allow this library to access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-exports= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_test-add_opens"></a>add_opens |  Allow this library to reflectively access the given <code>module</code> or <code>package</code>. <p> This corresponds to the javac and JVM --add-opens= flags.   | List of strings | optional |  `[]`  |
+| <a id="java_test-bootclasspath"></a>bootclasspath |  Restricted API, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_test-classpath_resources"></a>classpath_resources |  <em class="harmful">DO NOT USE THIS OPTION UNLESS THERE IS NO OTHER WAY)</em> <p> A list of resources that must be located at the root of the java tree. This attribute's only purpose is to support third-party libraries that require that their resources be found on the classpath as exactly <code>"myconfig.xml"</code>. It is only allowed on binaries and not libraries, due to the danger of namespace conflicts. </p>   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-create_executable"></a>create_executable |  Deprecated, use <code>java_single_jar</code> instead.   | Boolean | optional |  `True`  |
+| <a id="java_test-deploy_manifest_lines"></a>deploy_manifest_lines |  A list of lines to add to the <code>META-INF/manifest.mf</code> file generated for the <code>*_deploy.jar</code> target. The contents of this attribute are <em>not</em> subject to <a href="make-variables.html">"Make variable"</a> substitution.   | List of strings | optional |  `[]`  |
+| <a id="java_test-env"></a>env |  -   | <a href="https://bazel.build/rules/lib/dict">Dictionary: String -> String</a> | optional |  `{}`  |
+| <a id="java_test-env_inherit"></a>env_inherit |  -   | List of strings | optional |  `[]`  |
+| <a id="java_test-javacopts"></a>javacopts |  Extra compiler options for this binary. Subject to <a href="make-variables.html">"Make variable"</a> substitution and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>. <p>These compiler options are passed to javac after the global compiler options.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_test-jvm_flags"></a>jvm_flags |  A list of flags to embed in the wrapper script generated for running this binary. Subject to <a href="${link make-variables#location}">$(location)</a> and <a href="make-variables.html">"Make variable"</a> substitution, and <a href="common-definitions.html#sh-tokenization">Bourne shell tokenization</a>.<br><br><p>The wrapper script for a Java binary includes a CLASSPATH definition (to find all the dependent jars) and invokes the right Java interpreter. The command line generated by the wrapper script includes the name of the main class followed by a <code>"$@"</code> so you can pass along other arguments after the classname.  However, arguments intended for parsing by the JVM must be specified <i>before</i> the classname on the command line.  The contents of <code>jvm_flags</code> are added to the wrapper script before the classname is listed.</p><br><br><p>Note that this attribute has <em>no effect</em> on <code>*_deploy.jar</code> outputs.</p>   | List of strings | optional |  `[]`  |
+| <a id="java_test-launcher"></a>launcher |  Specify a binary that will be used to run your Java program instead of the normal <code>bin/java</code> program included with the JDK. The target must be a <code>cc_binary</code>. Any <code>cc_binary</code> that implements the <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html"> Java Invocation API</a> can be specified as a value for this attribute.<br><br><p>By default, Bazel will use the normal JDK launcher (bin/java or java.exe).</p><br><br><p>The related <a href="${link user-manual#flag--java_launcher}"><code> --java_launcher</code></a> Bazel flag affects only those <code>java_binary</code> and <code>java_test</code> targets that have <i>not</i> specified a <code>launcher</code> attribute.</p><br><br><p>Note that your native (C++, SWIG, JNI) dependencies will be built differently depending on whether you are using the JDK launcher or another launcher:</p><br><br><ul> <li>If you are using the normal JDK launcher (the default), native dependencies are built as a shared library named <code>{name}_nativedeps.so</code>, where <code>{name}</code> is the <code>name</code> attribute of this java_binary rule. Unused code is <em>not</em> removed by the linker in this configuration.</li><br><br><li>If you are using any other launcher, native (C++) dependencies are statically linked into a binary named <code>{name}_nativedeps</code>, where <code>{name}</code> is the <code>name</code> attribute of this java_binary rule. In this case, the linker will remove any code it thinks is unused from the resulting binary, which means any C++ code accessed only via JNI may not be linked in unless that <code>cc_library</code> target specifies <code>alwayslink = True</code>.</li> </ul><br><br><p>When using any launcher other than the default JDK launcher, the format of the <code>*_deploy.jar</code> output changes. See the main <a href="#java_binary">java_binary</a> docs for details.</p>   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_test-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_test-main_class"></a>main_class |  Name of class with <code>main()</code> method to use as entry point. If a rule uses this option, it does not need a <code>srcs=[...]</code> list. Thus, with this attribute one can make an executable from a Java library that already contains one or more <code>main()</code> methods. <p> The value of this attribute is a class name, not a source file. The class must be available at runtime: it may be compiled by this rule (from <code>srcs</code>) or provided by direct or transitive dependencies (through <code>runtime_deps</code> or <code>deps</code>). If the class is unavailable, the binary will fail at runtime; there is no build-time check. </p>   | String | optional |  `""`  |
+| <a id="java_test-neverlink"></a>neverlink |  -   | Boolean | optional |  `False`  |
+| <a id="java_test-plugins"></a>plugins |  Java compiler plugins to run at compile-time. Every <code>java_plugin</code> specified in this attribute will be run whenever this rule is built. A library may also inherit plugins from dependencies that use <code><a href="#java_library.exported_plugins">exported_plugins</a></code>. Resources generated by the plugin will be included in the resulting jar of this rule.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-resource_strip_prefix"></a>resource_strip_prefix |  The path prefix to strip from Java resources. <p> If specified, this path prefix is stripped from every file in the <code>resources</code> attribute. It is an error for a resource file not to be under this directory. If not specified (the default), the path of resource file is determined according to the same logic as the Java package of source files. For example, a source file at <code>stuff/java/foo/bar/a.txt</code> will be located at <code>foo/bar/a.txt</code>. </p>   | String | optional |  `""`  |
+| <a id="java_test-runtime_deps"></a>runtime_deps |  Libraries to make available to the final binary or test at runtime only. Like ordinary <code>deps</code>, these will appear on the runtime classpath, but unlike them, not on the compile-time classpath. Dependencies needed only at runtime should be listed here. Dependency-analysis tools should ignore targets that appear in both <code>runtime_deps</code> and <code>deps</code>.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_test-stamp"></a>stamp |  Whether to encode build information into the binary. Possible values: <ul> <li>   <code>stamp = 1</code>: Always stamp the build information into the binary, even in   <a href="https://bazel.build/docs/user-manual#stamp"><code>--nostamp</code></a> builds. <b>This   setting should be avoided</b>, since it potentially kills remote caching for the   binary and any downstream actions that depend on it. </li> <li>   <code>stamp = 0</code>: Always replace build information by constant values. This   gives good build result caching. </li> <li>   <code>stamp = -1</code>: Embedding of build information is controlled by the   <a href="https://bazel.build/docs/user-manual#stamp"><code>--[no]stamp</code></a> flag. </li> </ul> <p>Stamped binaries are <em>not</em> rebuilt unless their dependencies change.</p>   | Integer | optional |  `0`  |
+| <a id="java_test-test_class"></a>test_class |  The Java class to be loaded by the test runner.<br/> <p>   By default, if this argument is not defined then the legacy mode is used and the   test arguments are used instead. Set the <code>--nolegacy_bazel_java_test</code> flag   to not fallback on the first argument. </p> <p>   This attribute specifies the name of a Java class to be run by   this test. It is rare to need to set this. If this argument is omitted,   it will be inferred using the target's <code>name</code> and its   source-root-relative path. If the test is located outside a known   source root, Bazel will report an error if <code>test_class</code>   is unset. </p> <p>   For JUnit3, the test class needs to either be a subclass of   <code>junit.framework.TestCase</code> or it needs to have a public   static <code>suite()</code> method that returns a   <code>junit.framework.Test</code> (or a subclass of <code>Test</code>).   For JUnit4, the class needs to be annotated with   <code>org.junit.runner.RunWith</code>. </p> <p>   This attribute allows several <code>java_test</code> rules to   share the same <code>Test</code>   (<code>TestCase</code>, <code>TestSuite</code>, ...).  Typically   additional information is passed to it   (e.g. via <code>jvm_flags=['-Dkey=value']</code>) so that its   behavior differs in each case, such as running a different   subset of the tests.  This attribute also enables the use of   Java tests outside the <code>javatests</code> tree. </p>   | String | optional |  `""`  |
+| <a id="java_test-use_launcher"></a>use_launcher |  Whether the binary should use a custom launcher.<br><br><p>If this attribute is set to false, the <a href="${link java_binary.launcher}">launcher</a> attribute  and the related <a href="${link user-manual#flag--java_launcher}"><code>--java_launcher</code></a> flag will be ignored for this target.   | Boolean | optional |  `True`  |
+| <a id="java_test-use_testrunner"></a>use_testrunner |  Use the test runner (by default <code>com.google.testing.junit.runner.BazelTestRunner</code>) class as the main entry point for a Java program, and provide the test class to the test runner as a value of <code>bazel.test_suite</code> system property.<br><br><br/> You can use this to override the default behavior, which is to use test runner for <code>java_test</code> rules, and not use it for <code>java_binary</code> rules.  It is unlikely you will want to do this.  One use is for <code>AllTest</code> rules that are invoked by another rule (to set up a database before running the tests, for example).  The <code>AllTest</code> rule must be declared as a <code>java_binary</code>, but should still use the test runner as its main entry point.<br><br>The name of a test runner class can be overridden with <code>main_class</code> attribute.   | Boolean | optional |  `True`  |
+
+
+<a id="java_toolchain"></a>
+
+## java_toolchain
+
+<pre>
+java_toolchain(<a href="#java_toolchain-name">name</a>, <a href="#java_toolchain-android_lint_data">android_lint_data</a>, <a href="#java_toolchain-android_lint_jvm_opts">android_lint_jvm_opts</a>, <a href="#java_toolchain-android_lint_opts">android_lint_opts</a>,
+               <a href="#java_toolchain-android_lint_package_configuration">android_lint_package_configuration</a>, <a href="#java_toolchain-android_lint_runner">android_lint_runner</a>, <a href="#java_toolchain-bootclasspath">bootclasspath</a>,
+               <a href="#java_toolchain-compatible_javacopts">compatible_javacopts</a>, <a href="#java_toolchain-deps_checker">deps_checker</a>, <a href="#java_toolchain-forcibly_disable_header_compilation">forcibly_disable_header_compilation</a>, <a href="#java_toolchain-genclass">genclass</a>,
+               <a href="#java_toolchain-header_compiler">header_compiler</a>, <a href="#java_toolchain-header_compiler_builtin_processors">header_compiler_builtin_processors</a>, <a href="#java_toolchain-header_compiler_direct">header_compiler_direct</a>, <a href="#java_toolchain-ijar">ijar</a>,
+               <a href="#java_toolchain-jacocorunner">jacocorunner</a>, <a href="#java_toolchain-java_runtime">java_runtime</a>, <a href="#java_toolchain-javabuilder">javabuilder</a>, <a href="#java_toolchain-javabuilder_data">javabuilder_data</a>, <a href="#java_toolchain-javabuilder_jvm_opts">javabuilder_jvm_opts</a>,
+               <a href="#java_toolchain-javac_supports_multiplex_workers">javac_supports_multiplex_workers</a>, <a href="#java_toolchain-javac_supports_worker_cancellation">javac_supports_worker_cancellation</a>,
+               <a href="#java_toolchain-javac_supports_worker_multiplex_sandboxing">javac_supports_worker_multiplex_sandboxing</a>, <a href="#java_toolchain-javac_supports_workers">javac_supports_workers</a>, <a href="#java_toolchain-javacopts">javacopts</a>,
+               <a href="#java_toolchain-jspecify_implicit_deps">jspecify_implicit_deps</a>, <a href="#java_toolchain-jspecify_javacopts">jspecify_javacopts</a>, <a href="#java_toolchain-jspecify_packages">jspecify_packages</a>, <a href="#java_toolchain-jspecify_processor">jspecify_processor</a>,
+               <a href="#java_toolchain-jspecify_processor_class">jspecify_processor_class</a>, <a href="#java_toolchain-jspecify_stubs">jspecify_stubs</a>, <a href="#java_toolchain-jvm_opts">jvm_opts</a>, <a href="#java_toolchain-licenses">licenses</a>, <a href="#java_toolchain-misc">misc</a>, <a href="#java_toolchain-oneversion">oneversion</a>,
+               <a href="#java_toolchain-oneversion_allowlist">oneversion_allowlist</a>, <a href="#java_toolchain-oneversion_allowlist_for_tests">oneversion_allowlist_for_tests</a>, <a href="#java_toolchain-oneversion_whitelist">oneversion_whitelist</a>,
+               <a href="#java_toolchain-package_configuration">package_configuration</a>, <a href="#java_toolchain-proguard_allowlister">proguard_allowlister</a>, <a href="#java_toolchain-reduced_classpath_incompatible_processors">reduced_classpath_incompatible_processors</a>,
+               <a href="#java_toolchain-singlejar">singlejar</a>, <a href="#java_toolchain-source_version">source_version</a>, <a href="#java_toolchain-target_version">target_version</a>, <a href="#java_toolchain-timezone_data">timezone_data</a>, <a href="#java_toolchain-tools">tools</a>, <a href="#java_toolchain-turbine_data">turbine_data</a>,
+               <a href="#java_toolchain-turbine_jvm_opts">turbine_jvm_opts</a>, <a href="#java_toolchain-xlint">xlint</a>)
+</pre>
+
+<p>
+Specifies the configuration for the Java compiler. Which toolchain to be used can be changed through
+the --java_toolchain argument. Normally you should not write those kind of rules unless you want to
+tune your Java compiler.
+</p>
+
+<h4>Examples</h4>
+
+<p>A simple example would be:
+</p>
+
+<pre class="code">
+<code class="lang-starlark">
+
+java_toolchain(
+    name = "toolchain",
+    source_version = "7",
+    target_version = "7",
+    bootclasspath = ["//tools/jdk:bootclasspath"],
+    xlint = [ "classfile", "divzero", "empty", "options", "path" ],
+    javacopts = [ "-g" ],
+    javabuilder = ":JavaBuilder_deploy.jar",
+)
+</code>
+</pre>
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="java_toolchain-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+| <a id="java_toolchain-android_lint_data"></a>android_lint_data |  Labels of tools available for label-expansion in android_lint_jvm_opts.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-android_lint_jvm_opts"></a>android_lint_jvm_opts |  The list of arguments for the JVM when invoking Android Lint.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-android_lint_opts"></a>android_lint_opts |  The list of Android Lint arguments.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-android_lint_package_configuration"></a>android_lint_package_configuration |  Android Lint Configuration that should be applied to the specified package groups.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-android_lint_runner"></a>android_lint_runner |  Label of the Android Lint runner, if any.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-bootclasspath"></a>bootclasspath |  The Java target bootclasspath entries. Corresponds to javac's -bootclasspath flag.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-compatible_javacopts"></a>compatible_javacopts |  Internal API, do not use!   | <a href="https://bazel.build/rules/lib/dict">Dictionary: String -> List of strings</a> | optional |  `{}`  |
+| <a id="java_toolchain-deps_checker"></a>deps_checker |  Label of the ImportDepsChecker deploy jar.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-forcibly_disable_header_compilation"></a>forcibly_disable_header_compilation |  Overrides --java_header_compilation to disable header compilation on platforms that do not support it, e.g. JDK 7 Bazel.   | Boolean | optional |  `False`  |
+| <a id="java_toolchain-genclass"></a>genclass |  Label of the GenClass deploy jar.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-header_compiler"></a>header_compiler |  Label of the header compiler. Required if --java_header_compilation is enabled.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-header_compiler_builtin_processors"></a>header_compiler_builtin_processors |  Internal API, do not use!   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-header_compiler_direct"></a>header_compiler_direct |  Optional label of the header compiler to use for direct classpath actions that do not include any API-generating annotation processors.<br><br><p>This tool does not support annotation processing.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-ijar"></a>ijar |  Label of the ijar executable.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-jacocorunner"></a>jacocorunner |  Label of the JacocoCoverageRunner deploy jar.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-java_runtime"></a>java_runtime |  The java_runtime to use with this toolchain. It defaults to java_runtime in execution configuration.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-javabuilder"></a>javabuilder |  Label of the JavaBuilder deploy jar.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-javabuilder_data"></a>javabuilder_data |  Labels of data available for label-expansion in javabuilder_jvm_opts.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-javabuilder_jvm_opts"></a>javabuilder_jvm_opts |  The list of arguments for the JVM when invoking JavaBuilder.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-javac_supports_multiplex_workers"></a>javac_supports_multiplex_workers |  True if JavaBuilder supports running as a multiplex persistent worker, false if it doesn't.   | Boolean | optional |  `True`  |
+| <a id="java_toolchain-javac_supports_worker_cancellation"></a>javac_supports_worker_cancellation |  True if JavaBuilder supports cancellation of persistent workers, false if it doesn't.   | Boolean | optional |  `True`  |
+| <a id="java_toolchain-javac_supports_worker_multiplex_sandboxing"></a>javac_supports_worker_multiplex_sandboxing |  True if JavaBuilder supports running as a multiplex persistent worker with sandboxing, false if it doesn't.   | Boolean | optional |  `False`  |
+| <a id="java_toolchain-javac_supports_workers"></a>javac_supports_workers |  True if JavaBuilder supports running as a persistent worker, false if it doesn't.   | Boolean | optional |  `True`  |
+| <a id="java_toolchain-javacopts"></a>javacopts |  The list of extra arguments for the Java compiler. Please refer to the Java compiler documentation for the extensive list of possible Java compiler flags.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-jspecify_implicit_deps"></a>jspecify_implicit_deps |  Experimental, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-jspecify_javacopts"></a>jspecify_javacopts |  Experimental, do not use!   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-jspecify_packages"></a>jspecify_packages |  Experimental, do not use!   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-jspecify_processor"></a>jspecify_processor |  Experimental, do not use!   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-jspecify_processor_class"></a>jspecify_processor_class |  Experimental, do not use!   | String | optional |  `""`  |
+| <a id="java_toolchain-jspecify_stubs"></a>jspecify_stubs |  Experimental, do not use!   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-jvm_opts"></a>jvm_opts |  The list of arguments for the JVM when invoking the Java compiler. Please refer to the Java virtual machine documentation for the extensive list of possible flags for this option.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-licenses"></a>licenses |  -   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-misc"></a>misc |  Deprecated: use javacopts instead   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-oneversion"></a>oneversion |  Label of the one-version enforcement binary.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-oneversion_allowlist"></a>oneversion_allowlist |  Label of the one-version allowlist.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-oneversion_allowlist_for_tests"></a>oneversion_allowlist_for_tests |  Label of the one-version allowlist for tests.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-oneversion_whitelist"></a>oneversion_whitelist |  Deprecated: use oneversion_allowlist instead   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-package_configuration"></a>package_configuration |  Configuration that should be applied to the specified package groups.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-proguard_allowlister"></a>proguard_allowlister |  Label of the Proguard allowlister.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `"@bazel_tools//tools/jdk:proguard_whitelister"`  |
+| <a id="java_toolchain-reduced_classpath_incompatible_processors"></a>reduced_classpath_incompatible_processors |  Internal API, do not use!   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-singlejar"></a>singlejar |  Label of the SingleJar deploy jar.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-source_version"></a>source_version |  The Java source version (e.g., '6' or '7'). It specifies which set of code structures are allowed in the Java source code.   | String | optional |  `""`  |
+| <a id="java_toolchain-target_version"></a>target_version |  The Java target version (e.g., '6' or '7'). It specifies for which Java runtime the class should be build.   | String | optional |  `""`  |
+| <a id="java_toolchain-timezone_data"></a>timezone_data |  Label of a resource jar containing timezone data. If set, the timezone data is added as an implicitly runtime dependency of all java_binary rules.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional |  `None`  |
+| <a id="java_toolchain-tools"></a>tools |  Labels of tools available for label-expansion in jvm_opts.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-turbine_data"></a>turbine_data |  Labels of data available for label-expansion in turbine_jvm_opts.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional |  `[]`  |
+| <a id="java_toolchain-turbine_jvm_opts"></a>turbine_jvm_opts |  The list of arguments for the JVM when invoking turbine.   | List of strings | optional |  `[]`  |
+| <a id="java_toolchain-xlint"></a>xlint |  The list of warning to add or removes from default list. Precedes it with a dash to removes it. Please see the Javac documentation on the -Xlint options for more information.   | List of strings | optional |  `[]`  |
+
+
diff --git a/java/http_jar.bzl b/java/http_jar.bzl
new file mode 100644
index 0000000..ed3c331
--- /dev/null
+++ b/java/http_jar.bzl
@@ -0,0 +1,27 @@
+"""The http_jar repo rule, for downloading jars over HTTP.
+
+### Setup
+
+To use this rule in a module extension, load it in your .bzl file and then call it from your
+extension's implementation function. For example:
+
+```python
+load("@rules_java//java:http_jar.bzl", "http_jar")
+
+def _my_extension_impl(mctx):
+  http_jar(name = "foo", urls = [...])
+
+my_extension = module_extension(implementation = _my_extension_impl)
+```
+
+Alternatively, you can directly call it your MODULE.bazel file with `use_repo_rule`:
+
+```python
+http_jar = use_repo_rule("@rules_java//java:http_jar.bzl", "http_jar")
+http_jar(name = "foo", urls = [...])
+```
+"""
+
+load("@compatibility_proxy//:proxy.bzl", _http_jar = "http_jar")
+
+http_jar = _http_jar
diff --git a/java/java_binary.bzl b/java/java_binary.bzl
index b35064c..3c86ed2 100644
--- a/java/java_binary.bzl
+++ b/java/java_binary.bzl
@@ -1,4 +1,4 @@
-# Copyright 2023 The Bazel Authors. All rights reserved.
+# Copyright 2024 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,7 +13,7 @@
 # limitations under the License.
 """java_binary rule"""
 
-# Do not touch: This line marks the end of loads; needed for PR importing.
+load("@compatibility_proxy//:proxy.bzl", _java_binary = "java_binary")
 
 def java_binary(**attrs):
     """Bazel java_binary rule.
@@ -24,5 +24,4 @@ def java_binary(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_binary(**attrs)
+    _java_binary(**attrs)
diff --git a/java/java_import.bzl b/java/java_import.bzl
index 24a52af..7dfef83 100644
--- a/java/java_import.bzl
+++ b/java/java_import.bzl
@@ -1,4 +1,4 @@
-# Copyright 2023 The Bazel Authors. All rights reserved.
+# Copyright 2024 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,6 +13,8 @@
 # limitations under the License.
 """java_import rule"""
 
+load("@compatibility_proxy//:proxy.bzl", _java_import = "java_import")
+
 def java_import(**attrs):
     """Bazel java_import rule.
 
@@ -22,5 +24,4 @@ def java_import(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_import(**attrs)
+    _java_import(**attrs)
diff --git a/java/java_library.bzl b/java/java_library.bzl
index 2dff6d6..81e0ba1 100644
--- a/java/java_library.bzl
+++ b/java/java_library.bzl
@@ -1,4 +1,4 @@
-# Copyright 2023 The Bazel Authors. All rights reserved.
+# Copyright 2024 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,7 +13,7 @@
 # limitations under the License.
 """java_library rule"""
 
-# Do not touch: This line marks the end of loads; needed for PR importing.
+load("@compatibility_proxy//:proxy.bzl", _java_library = "java_library")
 
 def java_library(**attrs):
     """Bazel java_library rule.
@@ -24,5 +24,4 @@ def java_library(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_library(**attrs)
+    _java_library(**attrs)
diff --git a/java/java_plugin.bzl b/java/java_plugin.bzl
index e26ae04..e73843a 100644
--- a/java/java_plugin.bzl
+++ b/java/java_plugin.bzl
@@ -1,4 +1,4 @@
-# Copyright 2023 The Bazel Authors. All rights reserved.
+# Copyright 2024 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,6 +13,8 @@
 # limitations under the License.
 """java_plugin rule"""
 
+load("@compatibility_proxy//:proxy.bzl", _java_plugin = "java_plugin")
+
 def java_plugin(**attrs):
     """Bazel java_plugin rule.
 
@@ -22,5 +24,4 @@ def java_plugin(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_plugin(**attrs)
+    _java_plugin(**attrs)
diff --git a/java/java_test.bzl b/java/java_test.bzl
index 7064b5b..d11f10b 100644
--- a/java/java_test.bzl
+++ b/java/java_test.bzl
@@ -1,4 +1,4 @@
-# Copyright 2023 The Bazel Authors. All rights reserved.
+# Copyright 2024 The Bazel Authors. All rights reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,7 +13,7 @@
 # limitations under the License.
 """java_test rule"""
 
-# Do not touch: This line marks the end of loads; needed for PR importing.
+load("@compatibility_proxy//:proxy.bzl", _java_test = "java_test")
 
 def java_test(**attrs):
     """Bazel java_test rule.
@@ -24,5 +24,4 @@ def java_test(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_test(**attrs)
+    _java_test(**attrs)
diff --git a/java/private/BUILD b/java/private/BUILD
index 6948199..94bae8d 100644
--- a/java/private/BUILD
+++ b/java/private/BUILD
@@ -3,11 +3,45 @@ load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
 licenses(["notice"])
 
 bzl_library(
-    name = "private",
+    name = "native_bzl",
     srcs = [
         "native.bzl",
     ],
-    visibility = ["//java:__subpackages__"],
+    visibility = [
+        "//java:__subpackages__",
+        "@compatibility_proxy//:__pkg__",
+    ],
+)
+
+bzl_library(
+    name = "internals",
+    srcs = [
+        "boot_class_path_info.bzl",
+        "java_common.bzl",
+        "java_common_internal.bzl",
+        "java_info.bzl",
+        "message_bundle_info.bzl",
+    ],
+    visibility = [
+        "//java:__subpackages__",
+        "@compatibility_proxy//:__pkg__",
+    ],
+    deps = [
+        ":native_bzl",
+        "//java/common/rules:toolchain_rules",
+        "//java/common/rules/impl:java_helper_bzl",
+        "@bazel_skylib//lib:paths",
+        "@rules_cc//cc:find_cc_toolchain_bzl",
+        "@rules_cc//cc/common",
+    ],
+)
+
+# Exposed for use by the protobuf.
+bzl_library(
+    name = "proto_support",
+    srcs = ["proto_support.bzl"],
+    visibility = ["//visibility:public"],
+    deps = ["@compatibility_proxy//:proxy_bzl"],
 )
 
 filegroup(
@@ -21,7 +55,9 @@ filegroup(
     testonly = 1,
     srcs = [
         "BUILD",
-        ":private",
+        ":internals",
+        ":native_bzl",
+        ":proto_support",
     ],
     visibility = ["//java:__pkg__"],
 )
diff --git a/java/private/boot_class_path_info.bzl b/java/private/boot_class_path_info.bzl
new file mode 100644
index 0000000..f742e8f
--- /dev/null
+++ b/java/private/boot_class_path_info.bzl
@@ -0,0 +1,67 @@
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
+
+"""
+Definition of the BootClassPathInfo provider.
+"""
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+
+visibility(
+    ["//java/..."],
+)
+
+def _init(bootclasspath = [], auxiliary = [], system = None):
+    """The <code>BootClassPathInfo</code> constructor.
+
+    Args:
+        bootclasspath: ([File])
+        auxiliary: ([File])
+        system: ([File]|File|None)
+    """
+    if not system:  # None or []
+        system_inputs = depset()
+        system_path = None
+    elif type(system) == "File":
+        system_inputs = depset([system])
+        if not system.is_directory:
+            fail("for system,", system, "is not a directory")
+        system_path = system.path
+    elif type(system) == type([]):
+        system_inputs = depset(system)
+        system_paths = [input.path for input in system if input.basename == "release"]
+        if not system_paths:
+            fail("for system, expected inputs to contain 'release'")
+        system_path = paths.dirname(system_paths[0])
+    else:
+        fail("for system, got", type(system), ", want File, sequence, or None")
+
+    return {
+        "bootclasspath": depset(bootclasspath),
+        "_auxiliary": depset(auxiliary),
+        "_system_inputs": system_inputs,
+        "_system_path": system_path,
+    }
+
+BootClassPathInfo, _new_bootclasspathinfo = provider(
+    doc = "Information about the system APIs for a Java compilation.",
+    fields = [
+        "bootclasspath",
+        # private
+        "_auxiliary",
+        "_system_inputs",
+        "_system_path",
+    ],
+    init = _init,
+)
diff --git a/java/private/java_common.bzl b/java/private/java_common.bzl
new file mode 100644
index 0000000..ebaa35d
--- /dev/null
+++ b/java/private/java_common.bzl
@@ -0,0 +1,323 @@
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
+
+""" Utilities for Java compilation support in Starlark. """
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:java_runtime.bzl", "JavaRuntimeInfo")
+load("//java/common/rules:java_toolchain.bzl", "JavaToolchainInfo")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load(":boot_class_path_info.bzl", "BootClassPathInfo")
+load(
+    ":java_common_internal.bzl",
+    _compile_internal = "compile",
+    _run_ijar_internal = "run_ijar",
+)
+load(
+    ":java_info.bzl",
+    "JavaInfo",
+    "JavaPluginInfo",
+    _java_info_add_constraints = "add_constraints",
+    _java_info_make_non_strict = "make_non_strict",
+    _java_info_merge = "merge",
+    _java_info_set_annotation_processing = "set_annotation_processing",
+)
+load(":message_bundle_info.bzl", "MessageBundleInfo")
+load(":native.bzl", "get_internal_java_common")
+
+# copybara: default visibility
+
+JavaRuntimeClasspathInfo = provider(
+    "Provider for the runtime classpath contributions of a Java binary.",
+    fields = ["runtime_classpath"],
+)
+
+def _compile(
+        ctx,
+        output,
+        java_toolchain,
+        source_jars = [],
+        source_files = [],
+        output_source_jar = None,
+        javac_opts = [],
+        deps = [],
+        runtime_deps = [],
+        exports = [],
+        plugins = [],
+        exported_plugins = [],
+        native_libraries = [],
+        annotation_processor_additional_inputs = [],
+        annotation_processor_additional_outputs = [],
+        strict_deps = "ERROR",
+        bootclasspath = None,
+        sourcepath = [],
+        resources = [],
+        neverlink = False,
+        enable_annotation_processing = True,
+        add_exports = [],
+        add_opens = []):
+    return _compile_internal(
+        ctx,
+        output,
+        java_toolchain,
+        source_jars = source_jars,
+        source_files = source_files,
+        output_source_jar = output_source_jar,
+        javac_opts = javac_opts,
+        deps = deps,
+        runtime_deps = runtime_deps,
+        exports = exports,
+        plugins = plugins,
+        exported_plugins = exported_plugins,
+        native_libraries = native_libraries,
+        annotation_processor_additional_inputs = annotation_processor_additional_inputs,
+        annotation_processor_additional_outputs = annotation_processor_additional_outputs,
+        strict_deps = strict_deps,
+        bootclasspath = bootclasspath,
+        sourcepath = sourcepath,
+        resources = resources,
+        neverlink = neverlink,
+        enable_annotation_processing = enable_annotation_processing,
+        add_exports = add_exports,
+        add_opens = add_opens,
+    )
+
+def _run_ijar(actions, jar, java_toolchain, target_label = None):
+    get_internal_java_common().check_java_toolchain_is_declared_on_rule(actions)
+    return _run_ijar_internal(
+        actions = actions,
+        jar = jar,
+        java_toolchain = java_toolchain,
+        target_label = target_label,
+    )
+
+def _stamp_jar(actions, jar, java_toolchain, target_label):
+    """Stamps a jar with a target label for <code>add_dep</code> support.
+
+    The return value is typically passed to `JavaInfo.compile_jar`. Prefer to use `run_ijar` when
+    possible.
+
+    Args:
+        actions: (actions) ctx.actions
+        jar: (File) The jar to run stamp_jar on.
+        java_toolchain: (JavaToolchainInfo) The toolchain to used to find the stamp_jar tool.
+        target_label: (Label) A target label to stamp the jar with. Used for `add_dep` support.
+            Typically, you would pass `ctx.label` to stamp the jar with the current rule's label.
+
+    Returns:
+        (File) The output artifact
+
+    """
+    get_internal_java_common().check_java_toolchain_is_declared_on_rule(actions)
+    output = actions.declare_file(paths.replace_extension(jar.basename, "-stamped.jar"), sibling = jar)
+    args = actions.args()
+    args.add(jar)
+    args.add(output)
+    args.add("--nostrip_jar")
+    args.add("--target_label", target_label)
+    actions.run(
+        mnemonic = "JavaIjar",
+        inputs = [jar],
+        outputs = [output],
+        executable = java_toolchain.ijar,  # ijar doubles as a stamping tool
+        arguments = [args],
+        progress_message = "Stamping target label into jar %{input}",
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+        use_default_shell_env = True,
+    )
+    return output
+
+def _pack_sources(
+        actions,
+        java_toolchain,
+        output_source_jar,
+        sources = [],
+        source_jars = []):
+    """Packs sources and source jars into a single source jar file.
+
+    The return value is typically passed to `JavaInfo.source_jar`.
+
+    Args:
+        actions: (actions) ctx.actions
+        java_toolchain: (JavaToolchainInfo) The toolchain used to find the ijar tool.
+        output_source_jar: (File) The output source jar.
+        sources: ([File]) A list of Java source files to be packed into the source jar.
+        source_jars: ([File]) A list of source jars to be packed into the source jar.
+
+    Returns:
+        (File) The output artifact
+    """
+    get_internal_java_common().check_java_toolchain_is_declared_on_rule(actions)
+    return helper.create_single_jar(
+        actions,
+        toolchain = java_toolchain,
+        output = output_source_jar,
+        sources = depset(source_jars),
+        resources = depset(sources),
+        progress_message = "Building source jar %{output}",
+        mnemonic = "JavaSourceJar",
+    )
+
+# TODO: b/78512644 - migrate callers to passing explicit javacopts or using custom toolchains, and delete
+def _default_javac_opts(java_toolchain):
+    """Experimental! Get default javacopts from a java toolchain
+
+    Args:
+        java_toolchain: (JavaToolchainInfo) the toolchain from which to get the javac options.
+
+    Returns:
+        ([str]) A list of javac options
+    """
+    return java_toolchain._javacopts_list
+
+# temporary for migration
+def _default_javac_opts_depset(java_toolchain):
+    """Experimental! Get default javacopts from a java toolchain
+
+    Args:
+        java_toolchain: (JavaToolchainInfo) the toolchain from which to get the javac options.
+
+    Returns:
+        (depset[str]) A depset of javac options that should be tokenized before passing to javac
+    """
+    return java_toolchain._javacopts
+
+def _merge(providers):
+    """Merges the given providers into a single JavaInfo.
+
+    Args:
+        providers: ([JavaInfo]) The list of providers to merge.
+
+    Returns:
+        (JavaInfo) The merged JavaInfo
+    """
+    return _java_info_merge(providers)
+
+def _make_non_strict(java_info):
+    """Returns a new JavaInfo instance whose direct-jars part is the union of both the direct and indirect jars of the given Java provider.
+
+    Args:
+        java_info: (JavaInfo) The java info to make non-strict.
+
+    Returns:
+        (JavaInfo)
+    """
+    return _java_info_make_non_strict(java_info)
+
+def _get_message_bundle_info():
+    return None if semantics.IS_BAZEL else MessageBundleInfo
+
+def _add_constraints(java_info, constraints = []):
+    """Returns a copy of the given JavaInfo with the given constraints added.
+
+    Args:
+        java_info: (JavaInfo) The JavaInfo to enhance
+        constraints: ([str]) Constraints to add
+
+    Returns:
+        (JavaInfo)
+    """
+    if semantics.IS_BAZEL:
+        return java_info
+
+    return _java_info_add_constraints(java_info, constraints = constraints)
+
+def _get_constraints(java_info):
+    """Returns a set of constraints added.
+
+    Args:
+        java_info: (JavaInfo) The JavaInfo to get constraints from.
+
+    Returns:
+        ([str]) The constraints set on the supplied JavaInfo
+    """
+    return [] if semantics.IS_BAZEL else java_info._constraints
+
+def _set_annotation_processing(
+        java_info,
+        enabled = False,
+        processor_classnames = [],
+        processor_classpath = None,
+        class_jar = None,
+        source_jar = None):
+    """Returns a copy of the given JavaInfo with the given annotation_processing info.
+
+    Args:
+        java_info: (JavaInfo) The JavaInfo to enhance.
+        enabled: (bool) Whether the rule uses annotation processing.
+        processor_classnames: ([str]) Class names of annotation processors applied.
+        processor_classpath: (depset[File]) Class names of annotation processors applied.
+        class_jar: (File) Optional. Jar that is the result of annotation processing.
+        source_jar: (File) Optional. Source archive resulting from annotation processing.
+
+    Returns:
+        (JavaInfo)
+    """
+    if semantics.IS_BAZEL:
+        return None
+
+    return _java_info_set_annotation_processing(
+        java_info,
+        enabled = enabled,
+        processor_classnames = processor_classnames,
+        processor_classpath = processor_classpath,
+        class_jar = class_jar,
+        source_jar = source_jar,
+    )
+
+def _java_toolchain_label(java_toolchain):
+    """Returns the toolchain's label.
+
+    Args:
+        java_toolchain: (JavaToolchainInfo) The toolchain.
+    Returns:
+        (Label)
+    """
+    if semantics.IS_BAZEL:
+        # No implementation in Bazel. This method is not callable in Starlark except through
+        # (discouraged) use of --experimental_google_legacy_api.
+        return None
+
+    get_internal_java_common().check_provider_instances([java_toolchain], "java_toolchain", JavaToolchainInfo)
+    return java_toolchain.label
+
+def _make_java_common():
+    methods = {
+        "provider": JavaInfo,
+        "compile": _compile,
+        "run_ijar": _run_ijar,
+        "stamp_jar": _stamp_jar,
+        "pack_sources": _pack_sources,
+        "default_javac_opts": _default_javac_opts,
+        "default_javac_opts_depset": _default_javac_opts_depset,
+        "merge": _merge,
+        "make_non_strict": _make_non_strict,
+        "JavaPluginInfo": JavaPluginInfo,
+        "JavaToolchainInfo": JavaToolchainInfo,
+        "JavaRuntimeInfo": JavaRuntimeInfo,
+        "BootClassPathInfo": BootClassPathInfo,
+        "JavaRuntimeClasspathInfo": JavaRuntimeClasspathInfo,
+    }
+    if get_internal_java_common().google_legacy_api_enabled():
+        methods.update(
+            MessageBundleInfo = _get_message_bundle_info(),  # struct field that is None in bazel
+            add_constraints = _add_constraints,
+            get_constraints = _get_constraints,
+            set_annotation_processing = _set_annotation_processing,
+            java_toolchain_label = _java_toolchain_label,
+        )
+    return struct(**methods)
+
+java_common = _make_java_common()
diff --git a/java/private/java_common_internal.bzl b/java/private/java_common_internal.bzl
new file mode 100644
index 0000000..d740255
--- /dev/null
+++ b/java/private/java_common_internal.bzl
@@ -0,0 +1,433 @@
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
+
+""" Private utilities for Java compilation support in Starlark. """
+
+load("@bazel_skylib//lib:paths.bzl", "paths")
+load("//java/common:java_semantics.bzl", "semantics")
+load("//java/common/rules:java_toolchain.bzl", "JavaToolchainInfo")
+load("//java/common/rules/impl:java_helper.bzl", "helper")
+load(
+    ":java_info.bzl",
+    "JavaPluginInfo",
+    "disable_plugin_info_annotation_processing",
+    "java_info_for_compilation",
+    "merge_plugin_info_without_outputs",
+)
+load(":native.bzl", "get_internal_java_common")
+
+# copybara: default multiline visibility
+
+def compile(
+        ctx,
+        output,
+        java_toolchain,
+        source_jars = [],
+        source_files = [],
+        output_source_jar = None,
+        javac_opts = [],
+        deps = [],
+        runtime_deps = [],
+        exports = [],
+        plugins = [],
+        exported_plugins = [],
+        native_libraries = [],
+        annotation_processor_additional_inputs = [],
+        annotation_processor_additional_outputs = [],
+        strict_deps = "ERROR",
+        bootclasspath = None,
+        javabuilder_jvm_flags = None,
+        sourcepath = [],
+        resources = [],
+        add_exports = [],
+        add_opens = [],
+        neverlink = False,
+        enable_annotation_processing = True,
+        # private to @_builtins:
+        enable_compile_jar_action = True,
+        enable_jspecify = True,
+        include_compilation_info = True,
+        classpath_resources = [],
+        resource_jars = [],
+        injecting_rule_kind = None):
+    """Compiles Java source files/jars from the implementation of a Starlark rule
+
+    The result is a provider that represents the results of the compilation and can be added to the
+    set of providers emitted by this rule.
+
+    Args:
+        ctx: (RuleContext) The rule context
+        output: (File) The output of compilation
+        java_toolchain: (JavaToolchainInfo) Toolchain to be used for this compilation. Mandatory.
+        source_jars: ([File]) A list of the jars to be compiled. At least one of source_jars or
+            source_files should be specified.
+        source_files: ([File]) A list of the Java source files to be compiled. At least one of
+            source_jars or source_files should be specified.
+        output_source_jar: (File) The output source jar. Optional. Defaults to
+            `{output_jar}-src.jar` if unset.
+        javac_opts: ([str]|depset[str]) A list of the desired javac options. Optional.
+        deps: ([JavaInfo]) A list of dependencies. Optional.
+        runtime_deps: ([JavaInfo]) A list of runtime dependencies. Optional.
+        exports: ([JavaInfo]) A list of exports. Optional.
+        plugins: ([JavaPluginInfo|JavaInfo]) A list of plugins. Optional.
+        exported_plugins: ([JavaPluginInfo|JavaInfo]) A list of exported plugins. Optional.
+        native_libraries: ([CcInfo]) CC library dependencies that are needed for this library.
+        annotation_processor_additional_inputs: ([File]) A list of inputs that the Java compilation
+            action will take in addition to the Java sources for annotation processing.
+        annotation_processor_additional_outputs: ([File]) A list of outputs that the Java
+            compilation action will output in addition to the class jar from annotation processing.
+        strict_deps: (str) A string that specifies how to handle strict deps. Possible values:
+            'OFF', 'ERROR', 'WARN' and 'DEFAULT'.
+        bootclasspath: (BootClassPathInfo) If present, overrides the bootclasspath associated with
+            the provided java_toolchain. Optional.
+        javabuilder_jvm_flags: (list[str]) Additional JVM flags to pass to JavaBuilder.
+        sourcepath: ([File])
+        resources: ([File])
+        resource_jars: ([File])
+        classpath_resources: ([File])
+        neverlink: (bool)
+        enable_annotation_processing: (bool) Disables annotation processing in this compilation,
+            causing any annotation processors provided in plugins or in exported_plugins of deps to
+            be ignored.
+        enable_compile_jar_action: (bool) Enables header compilation or ijar creation. If set to
+            False, it forces use of the full class jar in the compilation classpaths of any
+            dependants. Doing so is intended for use by non-library targets such as binaries that
+            do not have dependants.
+        enable_jspecify: (bool)
+        include_compilation_info: (bool)
+        injecting_rule_kind: (str|None)
+        add_exports: ([str]) Allow this library to access the given <module>/<package>. Optional.
+        add_opens: ([str]) Allow this library to reflectively access the given <module>/<package>.
+             Optional.
+
+    Returns:
+        (JavaInfo)
+    """
+    get_internal_java_common().check_provider_instances([java_toolchain], "java_toolchain", JavaToolchainInfo)
+    get_internal_java_common().check_provider_instances(plugins, "plugins", JavaPluginInfo)
+
+    plugin_info = merge_plugin_info_without_outputs(plugins + deps)
+
+    all_javac_opts = []  # [depset[str]]
+    all_javac_opts.append(java_toolchain._javacopts)
+
+    all_javac_opts.append(ctx.fragments.java.default_javac_flags_depset)
+    all_javac_opts.append(semantics.compatible_javac_options(ctx, java_toolchain))
+
+    if ("com.google.devtools.build.runfiles.AutoBazelRepositoryProcessor" in
+        plugin_info.plugins.processor_classes.to_list()):
+        all_javac_opts.append(depset(
+            ["-Abazel.repository=" + ctx.label.workspace_name],
+            order = "preorder",
+        ))
+    system_bootclasspath = None
+    for package_config in java_toolchain._package_configuration:
+        if package_config.matches(package_config.package_specs, ctx.label):
+            all_javac_opts.append(package_config.javac_opts)
+            if package_config.system:
+                if system_bootclasspath:
+                    fail("Multiple system package configurations found for %s" % ctx.label)
+                system_bootclasspath = package_config.system
+    if not bootclasspath:
+        bootclasspath = system_bootclasspath
+
+    all_javac_opts.append(depset(
+        ["--add-exports=%s=ALL-UNNAMED" % x for x in add_exports],
+        order = "preorder",
+    ))
+
+    if type(javac_opts) == type([]):
+        # detokenize target's javacopts, it will be tokenized before compilation
+        all_javac_opts.append(helper.detokenize_javacopts(helper.tokenize_javacopts(ctx, javac_opts)))
+    elif type(javac_opts) == type(depset()):
+        all_javac_opts.append(javac_opts)
+    else:
+        fail("Expected javac_opts to be a list or depset, got:", type(javac_opts))
+
+    # we reverse the list of javacopts depsets, so that we keep the right-most set
+    # in case it's deduped. When this depset is flattened, we will reverse again,
+    # and then tokenize before passing to javac. This way, right-most javacopts will
+    # be retained and "win out".
+    all_javac_opts = depset(order = "preorder", transitive = reversed(all_javac_opts))
+
+    # Optimization: skip this if there are no annotation processors, to avoid unnecessarily
+    # disabling the direct classpath optimization if `enable_annotation_processor = False`
+    # but there aren't any annotation processors.
+    enable_direct_classpath = True
+    if not enable_annotation_processing and plugin_info.plugins.processor_classes:
+        plugin_info = disable_plugin_info_annotation_processing(plugin_info)
+        enable_direct_classpath = False
+
+    all_javac_opts_list = helper.tokenize_javacopts(ctx, all_javac_opts)
+    uses_annotation_processing = False
+    if "-processor" in all_javac_opts_list or plugin_info.plugins.processor_classes:
+        uses_annotation_processing = True
+
+    has_sources = source_files or source_jars
+    has_resources = resources or resource_jars
+
+    is_strict_mode = strict_deps != "OFF"
+    classpath_mode = ctx.fragments.java.reduce_java_classpath()
+
+    direct_jars = depset()
+    if is_strict_mode:
+        direct_jars = depset(order = "preorder", transitive = [dep.compile_jars for dep in deps])
+    compilation_classpath = depset(
+        order = "preorder",
+        transitive = [direct_jars] + [dep.transitive_compile_time_jars for dep in deps],
+    )
+    compile_time_java_deps = depset()
+    if is_strict_mode and classpath_mode != "OFF":
+        compile_time_java_deps = depset(transitive = [dep._compile_time_java_dependencies for dep in deps])
+
+    # create compile time jar action
+    if not has_sources:
+        compile_jar = None
+        compile_deps_proto = None
+    elif not enable_compile_jar_action:
+        compile_jar = output
+        compile_deps_proto = None
+    elif _should_use_header_compilation(ctx, java_toolchain):
+        compile_jar = helper.derive_output_file(ctx, output, name_suffix = "-hjar", extension = "jar")
+        compile_deps_proto = helper.derive_output_file(ctx, output, name_suffix = "-hjar", extension = "jdeps")
+        get_internal_java_common().create_header_compilation_action(
+            ctx,
+            java_toolchain,
+            compile_jar,
+            compile_deps_proto,
+            plugin_info,
+            depset(source_files),
+            source_jars,
+            compilation_classpath,
+            direct_jars,
+            bootclasspath,
+            compile_time_java_deps,
+            all_javac_opts,
+            strict_deps,
+            ctx.label,
+            injecting_rule_kind,
+            enable_direct_classpath,
+            annotation_processor_additional_inputs,
+        )
+    elif ctx.fragments.java.use_ijars():
+        compile_jar = run_ijar(
+            ctx.actions,
+            output,
+            java_toolchain,
+            target_label = ctx.label,
+            injecting_rule_kind = injecting_rule_kind,
+        )
+        compile_deps_proto = None
+    else:
+        compile_jar = output
+        compile_deps_proto = None
+
+    native_headers_jar = helper.derive_output_file(ctx, output, name_suffix = "-native-header")
+    manifest_proto = helper.derive_output_file(ctx, output, extension_suffix = "_manifest_proto")
+    deps_proto = None
+    if ctx.fragments.java.generate_java_deps() and has_sources:
+        deps_proto = helper.derive_output_file(ctx, output, extension = "jdeps")
+    generated_class_jar = None
+    generated_source_jar = None
+    if uses_annotation_processing:
+        generated_class_jar = helper.derive_output_file(ctx, output, name_suffix = "-gen")
+        generated_source_jar = helper.derive_output_file(ctx, output, name_suffix = "-gensrc")
+    get_internal_java_common().create_compilation_action(
+        ctx,
+        java_toolchain,
+        output,
+        manifest_proto,
+        plugin_info,
+        compilation_classpath,
+        direct_jars,
+        bootclasspath,
+        depset(javabuilder_jvm_flags),
+        compile_time_java_deps,
+        all_javac_opts,
+        strict_deps,
+        ctx.label,
+        deps_proto,
+        generated_class_jar,
+        generated_source_jar,
+        native_headers_jar,
+        depset(source_files),
+        source_jars,
+        resources,
+        depset(resource_jars),
+        classpath_resources,
+        sourcepath,
+        injecting_rule_kind,
+        enable_jspecify,
+        enable_direct_classpath,
+        annotation_processor_additional_inputs,
+        annotation_processor_additional_outputs,
+    )
+
+    create_output_source_jar = len(source_files) > 0 or source_jars != [output_source_jar]
+    if not output_source_jar:
+        output_source_jar = helper.derive_output_file(ctx, output, name_suffix = "-src", extension = "jar")
+    if create_output_source_jar:
+        helper.create_single_jar(
+            ctx.actions,
+            toolchain = java_toolchain,
+            output = output_source_jar,
+            sources = depset(source_jars + ([generated_source_jar] if generated_source_jar else [])),
+            resources = depset(source_files),
+            progress_message = "Building source jar %{output}",
+            mnemonic = "JavaSourceJar",
+        )
+
+    if has_sources or has_resources:
+        direct_runtime_jars = [output]
+    else:
+        direct_runtime_jars = []
+
+    compilation_info = struct(
+        javac_options = all_javac_opts,
+        # needs to be flattened because the public API is a list
+        boot_classpath = (bootclasspath.bootclasspath if bootclasspath else java_toolchain.bootclasspath).to_list(),
+        # we only add compile time jars from deps, and not exports
+        compilation_classpath = compilation_classpath,
+        runtime_classpath = depset(
+            order = "preorder",
+            direct = direct_runtime_jars,
+            transitive = [dep.transitive_runtime_jars for dep in runtime_deps + deps],
+        ),
+        uses_annotation_processing = uses_annotation_processing,
+    ) if include_compilation_info else None
+
+    return java_info_for_compilation(
+        output_jar = output,
+        compile_jar = compile_jar,
+        source_jar = output_source_jar,
+        generated_class_jar = generated_class_jar,
+        generated_source_jar = generated_source_jar,
+        plugin_info = plugin_info,
+        deps = deps,
+        runtime_deps = runtime_deps,
+        exports = exports,
+        exported_plugins = exported_plugins,
+        compile_jdeps = compile_deps_proto if compile_deps_proto else deps_proto,
+        jdeps = deps_proto if include_compilation_info else None,
+        native_headers_jar = native_headers_jar,
+        manifest_proto = manifest_proto,
+        native_libraries = native_libraries,
+        neverlink = neverlink,
+        add_exports = add_exports,
+        add_opens = add_opens,
+        direct_runtime_jars = direct_runtime_jars,
+        compilation_info = compilation_info,
+    )
+
+def _should_use_header_compilation(ctx, toolchain):
+    if not ctx.fragments.java.use_header_compilation():
+        return False
+    if toolchain._forcibly_disable_header_compilation:
+        return False
+    if not toolchain._header_compiler:
+        fail(
+            "header compilation was requested but it is not supported by the " +
+            "current Java toolchain '" + str(toolchain.label) +
+            "'; see the java_toolchain.header_compiler attribute",
+        )
+    if not toolchain._header_compiler_direct:
+        fail(
+            "header compilation was requested but it is not supported by the " +
+            "current Java toolchain '" + str(toolchain.label) +
+            "'; see the java_toolchain.header_compiler_direct attribute",
+        )
+    return True
+
+def run_ijar(
+        actions,
+        jar,
+        java_toolchain,
+        target_label = None,
+        # private to @_builtins:
+        output = None,
+        injecting_rule_kind = None):
+    """Runs ijar on a jar, stripping it of its method bodies.
+
+    This helps reduce rebuilding of dependent jars during any recompiles consisting only of simple
+    changes to method implementations. The return value is typically passed to JavaInfo.compile_jar
+
+    Args:
+        actions: (actions) ctx.actions
+        jar: (File) The jar to run ijar on.
+        java_toolchain: (JavaToolchainInfo) The toolchain to used to find the ijar tool.
+        target_label: (Label|None) A target label to stamp the jar with. Used for `add_dep` support.
+            Typically, you would pass `ctx.label` to stamp the jar with the current rule's label.
+        output: (File) Optional.
+        injecting_rule_kind: (str) the rule class of the current target
+    Returns:
+        (File) The output artifact
+    """
+    if not output:
+        output = actions.declare_file(paths.replace_extension(jar.basename, "-ijar.jar"), sibling = jar)
+    args = actions.args()
+    args.add(jar)
+    args.add(output)
+    if target_label != None:
+        args.add("--target_label", target_label)
+    if injecting_rule_kind != None:
+        args.add("--injecting_rule_kind", injecting_rule_kind)
+
+    actions.run(
+        mnemonic = "JavaIjar",
+        inputs = [jar],
+        outputs = [output],
+        executable = java_toolchain.ijar,
+        arguments = [args],
+        progress_message = "Extracting interface for jar %{input}",
+        toolchain = semantics.JAVA_TOOLCHAIN_TYPE,
+        use_default_shell_env = True,
+    )
+    return output
+
+def target_kind(target):
+    """Get the rule class string for a target
+
+    Args:
+        target: (Target)
+
+    Returns:
+        (str) The rule class string of the target
+    """
+    return get_internal_java_common().target_kind(target)
+
+def collect_native_deps_dirs(libraries):
+    """Collect the set of root-relative paths containing native libraries
+
+    Args:
+        libraries: (depset[LibraryToLink]) set of native libraries
+
+    Returns:
+        ([String]) A set of root-relative paths as a list
+    """
+    return get_internal_java_common().collect_native_deps_dirs(libraries)
+
+def get_runtime_classpath_for_archive(jars, excluded_jars):
+    """Filters a classpath to remove certain entries
+
+    Args
+        jars: (depset[File]) The classpath to filter
+        excluded_jars: (depset[File]) The files to remove
+
+    Returns:
+        (depset[File]) The filtered classpath
+    """
+    return get_internal_java_common().get_runtime_classpath_for_archive(
+        jars,
+        excluded_jars,
+    )
diff --git a/java/private/java_info.bzl b/java/private/java_info.bzl
new file mode 100644
index 0000000..8ba655e
--- /dev/null
+++ b/java/private/java_info.bzl
@@ -0,0 +1,969 @@
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
+
+"""
+Definition of JavaInfo and JavaPluginInfo provider.
+"""
+
+load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
+load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
+load("//java/common:java_semantics.bzl", "semantics")
+load(":native.bzl", "get_internal_java_common")
+
+# copybara: default visibility
+
+_JavaOutputInfo = provider(
+    doc = "The outputs of Java compilation.",
+    fields = {
+        "class_jar": "(File) A classes jar file.",
+        "compile_jar": "(File) An interface jar file.",
+        "ijar": "Deprecated: Please use compile_jar.",
+        "compile_jdeps": "(File) Compile time dependencies information (deps.proto file).",
+        "generated_class_jar": "(File) A jar containing classes generated via annotation processing.",
+        "generated_source_jar": "(File) The source jar created as a result of annotation processing.",
+        "native_headers_jar": "(File) A jar of CC header files supporting native method implementation.",
+        "manifest_proto": "(File) The manifest protobuf file of the manifest generated from JavaBuilder.",
+        "jdeps": "(File) The jdeps protobuf file of the manifest generated from JavaBuilder.",
+        "source_jars": "(depset[File]) A depset of sources archive files.",
+        "source_jar": "Deprecated: Please use source_jars instead.",
+    },
+)
+_ModuleFlagsInfo = provider(
+    doc = "Provider for the runtime classpath contributions of a Java binary.",
+    fields = {
+        "add_exports": "(depset[str]) Add-Exports configuration.",
+        "add_opens": "(depset[str]) Add-Opens configuration.",
+    },
+)
+_EMPTY_MODULE_FLAGS_INFO = _ModuleFlagsInfo(add_exports = depset(), add_opens = depset())
+
+def _create_module_flags_info(*, add_exports, add_opens):
+    if add_exports or add_opens:
+        return _ModuleFlagsInfo(add_exports = add_exports, add_opens = add_opens)
+    return _EMPTY_MODULE_FLAGS_INFO
+
+_JavaRuleOutputJarsInfo = provider(
+    doc = "Deprecated: use java_info.java_outputs. Information about outputs of a Java rule.",
+    fields = {
+        "jdeps": "Deprecated: Use java_info.java_outputs.",
+        "native_headers": "Deprecated: Use java_info.java_outputs[i].jdeps.",
+        "jars": "Deprecated: Use java_info.java_outputs[i].native_headers_jar.",
+    },
+)
+_JavaGenJarsInfo = provider(
+    doc = "Deprecated: Information about jars that are a result of annotation processing for a Java rule.",
+    fields = {
+        "enabled": "Deprecated. Returns true if annotation processing was applied on this target.",
+        "class_jar": "Deprecated: Please use JavaInfo.java_outputs.generated_class_jar instead.",
+        "source_jar": "Deprecated: Please use JavaInfo.java_outputs.generated_source_jar instead.",
+        "transitive_class_jars": "Deprecated. A transitive set of class file jars from annotation " +
+                                 "processing of this rule and its dependencies.",
+        "transitive_source_jars": "Deprecated. A transitive set of source archives from annotation " +
+                                  "processing of this rule and its dependencies.",
+        "processor_classpath": "Deprecated: Please use JavaInfo.plugins instead.",
+        "processor_classnames": "Deprecated: Please use JavaInfo.plugins instead.",
+    },
+)
+
+JavaCompilationInfo = provider(
+    doc = "Compilation information in Java rules, for perusal of aspects and tools.",
+    fields = {
+        "boot_classpath": "Boot classpath for this Java target.",
+        "javac_options": """Depset of options to the java compiler. To get the
+            exact list of options passed to javac in the correct order, use the
+            tokenize_javacopts utility in rules_java""",
+        "compilation_classpath": "Compilation classpath for this Java target.",
+        "runtime_classpath": "Run-time classpath for this Java target.",
+    },
+)
+
+def merge(
+        providers,
+        # private to @_builtins:
+        merge_java_outputs = True,
+        merge_source_jars = True):
+    """Merges the given providers into a single JavaInfo.
+
+    Args:
+        providers: ([JavaInfo]) The list of providers to merge.
+        merge_java_outputs: (bool)
+        merge_source_jars: (bool)
+
+    Returns:
+        (JavaInfo) The merged JavaInfo
+    """
+    _validate_provider_list(providers, "providers", JavaInfo)
+
+    plugin_info = merge_plugin_info_without_outputs(providers)
+
+    source_jars = []  # [File]
+    transitive_source_jars = []  # [depset[File]]
+    java_outputs = []  # [_JavaOutputInfo]
+    runtime_output_jars = []  # [File]
+    transitive_runtime_jars = []  # [depset[File]]
+    transitive_compile_time_jars = []  # [depset[File]]
+    compile_jars = []  # [depset[File]]
+    full_compile_jars = []  # [depset[File]]
+    _transitive_full_compile_time_jars = []  # [depset[File]]
+    _compile_time_java_dependencies = []  # [depset[File]]
+    add_exports = []  # [depset[str]]
+    add_opens = []  # [depset[str]]
+    _neverlink = False
+    _constraints = []  # [str]
+    for p in providers:
+        if merge_source_jars:
+            source_jars.extend(p.source_jars)
+            transitive_source_jars.append(p.transitive_source_jars)
+        if merge_java_outputs:
+            java_outputs.extend(p.java_outputs)
+            runtime_output_jars.extend(p.runtime_output_jars)
+        transitive_runtime_jars.append(p.transitive_runtime_jars)
+        transitive_compile_time_jars.append(p.transitive_compile_time_jars)
+        compile_jars.append(p.compile_jars)
+        full_compile_jars.append(p.full_compile_jars)
+        _transitive_full_compile_time_jars.append(p._transitive_full_compile_time_jars)
+        _compile_time_java_dependencies.append(p._compile_time_java_dependencies)
+        add_exports.append(p.module_flags_info.add_exports)
+        add_opens.append(p.module_flags_info.add_opens)
+        _neverlink = _neverlink or p._neverlink
+        _constraints.extend(p._constraints)
+
+    transitive_runtime_jars = depset(order = "preorder", transitive = transitive_runtime_jars)
+    transitive_compile_time_jars = depset(order = "preorder", transitive = transitive_compile_time_jars)
+
+    # java_outputs is a list so we uniquify to avoid https://github.com/bazelbuild/bazel/issues/17170
+    java_outputs = depset(java_outputs).to_list()
+    result = {
+        "transitive_runtime_jars": transitive_runtime_jars,
+        "transitive_compile_time_jars": transitive_compile_time_jars,
+        "compile_jars": depset(order = "preorder", transitive = compile_jars),
+        "full_compile_jars": depset(order = "preorder", transitive = full_compile_jars),
+        "_transitive_full_compile_time_jars": depset(order = "preorder", transitive = _transitive_full_compile_time_jars),
+        "_compile_time_java_dependencies": depset(order = "preorder", transitive = _compile_time_java_dependencies),
+        # runtime_output_jars is a list so we uniquify to avoid https://github.com/bazelbuild/bazel/issues/17170
+        "runtime_output_jars": depset(runtime_output_jars).to_list(),
+        # source_jars is a list so we uniquify to avoid https://github.com/bazelbuild/bazel/issues/17170
+        "source_jars": depset(source_jars).to_list(),
+        "transitive_source_jars": depset(transitive = transitive_source_jars),
+        "java_outputs": java_outputs,
+        "outputs": _JavaRuleOutputJarsInfo(jars = java_outputs, jdeps = None, native_headers = None),
+        "module_flags_info": _create_module_flags_info(
+            add_exports = depset(transitive = add_exports),
+            add_opens = depset(transitive = add_opens),
+        ),
+        "plugins": plugin_info.plugins,
+        "api_generating_plugins": plugin_info.api_generating_plugins,
+        "_neverlink": bool(_neverlink),
+        "_constraints": depset(_constraints).to_list(),
+        "annotation_processing": None,
+        "compilation_info": None,
+    }
+
+    if get_internal_java_common().google_legacy_api_enabled():
+        cc_info = semantics.minimize_cc_info(cc_common.merge_cc_infos(cc_infos = [p.cc_link_params_info for p in providers]))
+        result.update(
+            cc_link_params_info = cc_info,
+            transitive_native_libraries = cc_info.transitive_native_libraries(),
+        )
+    else:
+        result.update(
+            transitive_native_libraries = depset(
+                order = "topological",
+                transitive = [p.transitive_native_libraries for p in providers],
+            ),
+        )
+    return get_internal_java_common().wrap_java_info(_new_javainfo(**result))
+
+def to_java_binary_info(java_info, compilation_info):
+    """Get a copy of the given JavaInfo with minimal info returned by a java_binary
+
+    Args:
+        java_info: (JavaInfo) A JavaInfo provider instance
+        compilation_info: (JavaCompilationInfo)
+    Returns:
+        (JavaInfo) A JavaInfo instance representing a java_binary target
+    """
+    result = {
+        "transitive_runtime_jars": depset(),
+        "transitive_compile_time_jars": depset(),
+        "compile_jars": depset(),
+        "full_compile_jars": depset(),
+        "_transitive_full_compile_time_jars": depset(),
+        "_compile_time_java_dependencies": depset(),
+        "runtime_output_jars": [],
+        "plugins": _EMPTY_PLUGIN_DATA,
+        "api_generating_plugins": _EMPTY_PLUGIN_DATA,
+        "module_flags_info": _EMPTY_MODULE_FLAGS_INFO,
+        "_neverlink": False,
+        "_constraints": [],
+        "annotation_processing": java_info.annotation_processing,
+        "transitive_native_libraries": java_info.transitive_native_libraries,
+        "source_jars": java_info.source_jars,
+        "transitive_source_jars": java_info.transitive_source_jars,
+    }
+    if hasattr(java_info, "cc_link_params_info"):
+        result.update(cc_link_params_info = java_info.cc_link_params_info)
+
+    result["compilation_info"] = compilation_info
+
+    java_outputs = [
+        _JavaOutputInfo(
+            compile_jar = None,
+            ijar = None,  # deprecated
+            compile_jdeps = None,
+            class_jar = output.class_jar,
+            generated_class_jar = output.generated_class_jar,
+            generated_source_jar = output.generated_source_jar,
+            native_headers_jar = output.native_headers_jar,
+            manifest_proto = output.manifest_proto,
+            jdeps = output.jdeps,
+            source_jars = output.source_jars,
+            source_jar = output.source_jar,  # deprecated
+        )
+        for output in java_info.java_outputs
+    ]
+    all_jdeps = [output.jdeps for output in java_info.java_outputs if output.jdeps]
+    all_native_headers = [output.native_headers_jar for output in java_info.java_outputs if output.native_headers_jar]
+    result.update(
+        java_outputs = java_outputs,
+        outputs = _JavaRuleOutputJarsInfo(
+            jars = java_outputs,
+            jdeps = all_jdeps[0] if len(all_jdeps) == 1 else None,
+            native_headers = all_native_headers[0] if len(all_native_headers) == 1 else None,
+        ),
+    )
+
+    # so that translation into native JavaInfo does not add JavaCompilationArgsProvider
+    result.update(_is_binary = True)
+    return _new_javainfo(**result)
+
+def _to_mutable_dict(java_info):
+    return {
+        key: getattr(java_info, key)
+        for key in dir(java_info)
+        if key not in ["to_json", "to_proto"]
+    }
+
+def add_constraints(java_info, constraints = []):
+    """Returns a copy of the given JavaInfo with the given constraints added.
+
+    Args:
+        java_info: (JavaInfo) The JavaInfo to enhance
+        constraints: ([str]) Constraints to add
+
+    Returns:
+        (JavaInfo)
+    """
+    result = _to_mutable_dict(java_info)
+    old_constraints = java_info._constraints if java_info._constraints else []
+    result.update(
+        _constraints = depset(constraints + old_constraints).to_list(),
+    )
+    return _new_javainfo(**result)
+
+def make_non_strict(java_info):
+    """Returns a new JavaInfo instance whose direct-jars part is the union of both the direct and indirect jars of the given Java provider.
+
+    Args:
+        java_info: (JavaInfo) The java info to make non-strict.
+
+    Returns:
+        (JavaInfo)
+    """
+    result = _to_mutable_dict(java_info)
+    result.update(
+        compile_jars = java_info.transitive_compile_time_jars,
+        full_compile_jars = java_info._transitive_full_compile_time_jars,
+    )
+
+    # Omit jdeps, which aren't available transitively and aren't useful for reduced classpath
+    # pruning for non-strict targets: the direct classpath and transitive classpath are the same,
+    # so there's nothing to prune, and reading jdeps at compile-time isn't free.
+    result.update(
+        _compile_time_java_dependencies = depset(),
+    )
+    return _new_javainfo(**result)
+
+def add_module_flags(java_info, add_exports = [], add_opens = []):
+    """Returns a new JavaInfo instance with the additional add_exports/add_opens
+
+    Args:
+        java_info: (JavaInfo) The java info to enhance.
+        add_exports: ([str]) The <module>/<package>s given access to.
+        add_opens: ([str]) The <module>/<package>s given reflective access to.
+    Returns:
+        (JavaInfo)
+    """
+    if not add_exports and not add_opens:
+        return java_info
+
+    result = _to_mutable_dict(java_info)
+    result.update(
+        module_flags_info = _create_module_flags_info(
+            add_exports = depset(add_exports, transitive = [java_info.module_flags_info.add_exports]),
+            add_opens = depset(add_opens, transitive = [java_info.module_flags_info.add_opens]),
+        ),
+    )
+    return _new_javainfo(**result)
+
+def set_annotation_processing(
+        java_info,
+        enabled = False,
+        processor_classnames = [],
+        processor_classpath = None,
+        class_jar = None,
+        source_jar = None):
+    """Returns a copy of the given JavaInfo with the given annotation_processing info.
+
+    Args:
+        java_info: (JavaInfo) The JavaInfo to enhance.
+        enabled: (bool) Whether the rule uses annotation processing.
+        processor_classnames: ([str]) Class names of annotation processors applied.
+        processor_classpath: (depset[File]) Class names of annotation processors applied.
+        class_jar: (File) Optional. Jar that is the result of annotation processing.
+        source_jar: (File) Optional. Source archive resulting from annotation processing.
+
+    Returns:
+        (JavaInfo)
+    """
+    gen_jars_info = java_info.annotation_processing
+    if gen_jars_info:
+        # Existing Jars would be a problem b/c we can't remove them from transitiveXxx sets
+        if gen_jars_info.class_jar and gen_jars_info.class_jar != class_jar:
+            fail("Existing gen_class_jar:", gen_jars_info.class_jar)
+        if gen_jars_info.source_jar and gen_jars_info.source_jar != source_jar:
+            fail("Existing gen_source_jar:", gen_jars_info.class_jar)
+        transitive_class_jars = depset([class_jar] if class_jar else [], transitive = [gen_jars_info.transitive_class_jars])
+        transitive_source_jars = depset([source_jar] if source_jar else [], transitive = [gen_jars_info.transitive_source_jars])
+    else:
+        transitive_class_jars = depset([class_jar] if class_jar else [])
+        transitive_source_jars = depset([source_jar] if source_jar else [])
+
+    result = _to_mutable_dict(java_info)
+    result.update(
+        annotation_processing = _JavaGenJarsInfo(
+            enabled = enabled,
+            class_jar = class_jar,
+            source_jar = source_jar,
+            processor_classnames = processor_classnames,
+            processor_classpath = processor_classpath if processor_classpath else depset(),
+            transitive_class_jars = transitive_class_jars,
+            transitive_source_jars = transitive_source_jars,
+        ),
+    )
+    return _new_javainfo(**result)
+
+def java_info_for_compilation(
+        output_jar,
+        compile_jar,
+        source_jar,
+        generated_class_jar,
+        generated_source_jar,
+        plugin_info,
+        deps,
+        runtime_deps,
+        exports,
+        exported_plugins,
+        compile_jdeps,
+        jdeps,
+        native_headers_jar,
+        manifest_proto,
+        native_libraries,
+        neverlink,
+        add_exports,
+        add_opens,
+        direct_runtime_jars,
+        compilation_info):
+    """Creates a JavaInfo instance represiting the result of java compilation.
+
+    Args:
+        output_jar: (File) The jar that was created as a result of a compilation.
+        compile_jar: (File) A jar that is the compile-time dependency in lieu of `output_jar`.
+        source_jar: (File) The source jar that was used to create the output jar.
+        generated_class_jar: (File) A jar file containing class files compiled from sources
+            generated during annotation processing.
+        generated_source_jar: (File) The source jar that was created as a result of annotation
+            processing.
+        plugin_info: (JavaPluginInfo) Information about annotation processing.
+        deps: ([JavaInfo]) Compile time dependencies that were used to create the output jar.
+        runtime_deps: ([JavaInfo]) Runtime dependencies that are needed for this library.
+        exports: ([JavaInfo]) Libraries to make available for users of this library.
+        exported_plugins: ([JavaPluginInfo]) A list of exported plugins.
+        compile_jdeps: (File) jdeps information about compile time dependencies to be consumed by
+            JavaCompileAction. This should be a binary proto encoded using the deps.proto protobuf
+            included with Bazel. If available this file is typically produced by a header compiler.
+        jdeps: (File) jdeps information for the rule output (if available). This should be a binary
+            proto encoded using the deps.proto protobuf included with Bazel. If available this file
+            is typically produced by a compiler. IDEs and other tools can use this information for
+            more efficient processing.
+        native_headers_jar: (File) A jar containing CC header files supporting native method
+            implementation (typically output of javac -h).
+        manifest_proto: (File) Manifest information for the rule output (if available). This should
+            be a binary proto encoded using the manifest.proto protobuf included with Bazel. IDEs
+            and other tools can use this information for more efficient processing.
+        native_libraries: ([CcInfo]) Native library dependencies that are needed for this library.
+        neverlink: (bool) If true, only use this library for compilation and not at runtime.
+        add_exports: ([str]) The <module>/<package>s this library was given access to.
+        add_opens: ([str]) The <module>/<package>s this library was given reflective access to.
+        direct_runtime_jars: ([File]) The class jars needed directly by this library at runtime.
+            This is usually just the output_jar or empty if there were no sources/resources.
+        compilation_info: (struct) Information for IDE/tools
+
+    Returns:
+        (JavaInfo) the JavaInfo instance
+    """
+    result, concatenated_deps = _javainfo_init_base(
+        output_jar,
+        compile_jar,
+        source_jar,
+        deps,
+        runtime_deps,
+        exports,
+        exported_plugins,
+        jdeps,
+        compile_jdeps,
+        native_headers_jar,
+        manifest_proto,
+        generated_class_jar,
+        generated_source_jar,
+        native_libraries,
+        neverlink,
+    )
+
+    # this differs ever so slightly from the usual JavaInfo in that direct_runtime_jars
+    # does not contain the output_jar is there were no sources/resources
+    transitive_runtime_jars = depset() if neverlink else depset(
+        order = "preorder",
+        direct = direct_runtime_jars,
+        transitive = [dep.transitive_runtime_jars for dep in concatenated_deps.exports_deps + runtime_deps],
+    )
+    result.update(
+        runtime_output_jars = direct_runtime_jars,
+        transitive_runtime_jars = transitive_runtime_jars,
+        transitive_source_jars = depset(
+            direct = [source_jar],
+            # only differs from the usual java_info.transitive_source_jars in the order of deps
+            transitive = [dep.transitive_source_jars for dep in concatenated_deps.runtimedeps_exports_deps],
+        ),
+        # the JavaInfo constructor does not add flags from runtime_deps
+        module_flags_info = _create_module_flags_info(
+            add_exports = depset(add_exports, transitive = [
+                dep.module_flags_info.add_exports
+                for dep in concatenated_deps.runtimedeps_exports_deps
+            ]),
+            add_opens = depset(add_opens, transitive = [
+                dep.module_flags_info.add_opens
+                for dep in concatenated_deps.runtimedeps_exports_deps
+            ]),
+        ),
+    )
+    if compilation_info:
+        result.update(
+            compilation_info = JavaCompilationInfo(
+                javac_options = compilation_info.javac_options,
+                boot_classpath = compilation_info.boot_classpath,
+                compilation_classpath = compilation_info.compilation_classpath,
+                runtime_classpath = compilation_info.runtime_classpath,
+            ),
+            annotation_processing = _JavaGenJarsInfo(
+                enabled = compilation_info.uses_annotation_processing,
+                class_jar = result["annotation_processing"].class_jar,
+                source_jar = result["annotation_processing"].source_jar,
+                processor_classnames = plugin_info.plugins.processor_classes.to_list(),
+                processor_classpath = plugin_info.plugins.processor_jars,
+                transitive_class_jars = result["annotation_processing"].transitive_class_jars,
+                transitive_source_jars = result["annotation_processing"].transitive_source_jars,
+            ),
+        )
+    else:
+        result.update(
+            compilation_info = None,
+            annotation_processing = None,
+        )
+    return get_internal_java_common().wrap_java_info(_new_javainfo(**result))
+
+def _validate_provider_list(provider_list, what, expected_provider_type):
+    get_internal_java_common().check_provider_instances(provider_list, what, expected_provider_type)
+
+def _compute_concatenated_deps(deps, runtime_deps, exports):
+    deps_exports = []
+    deps_exports.extend(deps)
+    deps_exports.extend(exports)
+
+    exports_deps = []
+    exports_deps.extend(exports)
+    exports_deps.extend(deps)
+
+    runtimedeps_exports_deps = []
+    runtimedeps_exports_deps.extend(runtime_deps)
+    runtimedeps_exports_deps.extend(exports_deps)
+
+    return struct(
+        deps_exports = deps_exports,
+        exports_deps = exports_deps,
+        runtimedeps_exports_deps = runtimedeps_exports_deps,
+    )
+
+def _javainfo_init_base(
+        output_jar,
+        compile_jar,
+        source_jar,
+        deps,
+        runtime_deps,
+        exports,
+        exported_plugins,
+        jdeps,
+        compile_jdeps,
+        native_headers_jar,
+        manifest_proto,
+        generated_class_jar,
+        generated_source_jar,
+        native_libraries,
+        neverlink):
+    _validate_provider_list(deps, "deps", JavaInfo)
+    _validate_provider_list(runtime_deps, "runtime_deps", JavaInfo)
+    _validate_provider_list(exports, "exports", JavaInfo)
+    _validate_provider_list(native_libraries, "native_libraries", CcInfo)
+
+    concatenated_deps = _compute_concatenated_deps(deps, runtime_deps, exports)
+
+    source_jars = [source_jar] if source_jar else []
+    plugin_info = merge_plugin_info_without_outputs(exported_plugins + exports)
+    transitive_compile_time_jars = depset(
+        order = "preorder",
+        direct = [compile_jar] if compile_jar else [],
+        transitive = [dep.transitive_compile_time_jars for dep in concatenated_deps.exports_deps],
+    )
+    java_outputs = [_JavaOutputInfo(
+        class_jar = output_jar,
+        compile_jar = compile_jar,
+        ijar = compile_jar,  # deprecated
+        compile_jdeps = compile_jdeps,
+        generated_class_jar = generated_class_jar,
+        generated_source_jar = generated_source_jar,
+        native_headers_jar = native_headers_jar,
+        manifest_proto = manifest_proto,
+        jdeps = jdeps,
+        source_jars = depset(source_jars),
+        source_jar = source_jar,  # deprecated
+    )]
+    result = {
+        "transitive_compile_time_jars": transitive_compile_time_jars,
+        "compile_jars": depset(
+            order = "preorder",
+            direct = [compile_jar] if compile_jar else [],
+            transitive = [dep.compile_jars for dep in exports],
+        ),
+        "full_compile_jars": depset(
+            order = "preorder",
+            direct = [output_jar],
+            transitive = [
+                dep.full_compile_jars
+                for dep in exports
+            ],
+        ),
+        "source_jars": source_jars,
+        "runtime_output_jars": [output_jar],
+        "plugins": plugin_info.plugins,
+        "api_generating_plugins": plugin_info.api_generating_plugins,
+        "java_outputs": java_outputs,
+        # deprecated
+        "outputs": _JavaRuleOutputJarsInfo(
+            jars = java_outputs,
+            jdeps = jdeps,
+            native_headers = native_headers_jar,
+        ),
+        "annotation_processing": _JavaGenJarsInfo(
+            enabled = False,
+            class_jar = generated_class_jar,
+            source_jar = generated_source_jar,
+            transitive_class_jars = depset(
+                direct = [generated_class_jar] if generated_class_jar else [],
+                transitive = [
+                    dep.annotation_processing.transitive_class_jars
+                    for dep in concatenated_deps.deps_exports
+                    if dep.annotation_processing
+                ],
+            ),
+            transitive_source_jars = depset(
+                direct = [generated_source_jar] if generated_source_jar else [],
+                transitive = [
+                    dep.annotation_processing.transitive_source_jars
+                    for dep in concatenated_deps.deps_exports
+                    if dep.annotation_processing
+                ],
+            ),
+            processor_classnames = [],
+            processor_classpath = depset(),
+        ),
+        "_transitive_full_compile_time_jars": depset(
+            order = "preorder",
+            direct = [output_jar],
+            transitive = [dep._transitive_full_compile_time_jars for dep in concatenated_deps.exports_deps],
+        ),
+        "_compile_time_java_dependencies": depset(
+            order = "preorder",
+            transitive = [dep._compile_time_java_dependencies for dep in exports] +
+                         ([depset([compile_jdeps])] if compile_jdeps else []),
+        ),
+        "_neverlink": bool(neverlink),
+        "compilation_info": None,
+        "_constraints": [],
+    }
+
+    if get_internal_java_common().google_legacy_api_enabled():
+        transitive_cc_infos = [dep.cc_link_params_info for dep in concatenated_deps.runtimedeps_exports_deps]
+        transitive_cc_infos.extend(native_libraries)
+        cc_info = semantics.minimize_cc_info(cc_common.merge_cc_infos(cc_infos = transitive_cc_infos))
+        result.update(
+            cc_link_params_info = cc_info,
+            transitive_native_libraries = cc_info.transitive_native_libraries(),
+        )
+    else:
+        result.update(
+            transitive_native_libraries = depset(
+                order = "topological",
+                transitive = [dep.transitive_native_libraries for dep in concatenated_deps.runtimedeps_exports_deps] +
+                             ([cc_common.merge_cc_infos(cc_infos = native_libraries).transitive_native_libraries()] if native_libraries else []),
+            ),
+        )
+    return result, concatenated_deps
+
+def _javainfo_init(
+        output_jar,
+        compile_jar,
+        source_jar = None,
+        compile_jdeps = None,
+        generated_class_jar = None,
+        generated_source_jar = None,
+        native_headers_jar = None,
+        manifest_proto = None,
+        neverlink = False,
+        deps = [],
+        runtime_deps = [],
+        exports = [],
+        exported_plugins = [],
+        jdeps = None,
+        native_libraries = [],
+        add_exports = [],
+        add_opens = []):
+    """The JavaInfo constructor
+
+    Args:
+        output_jar: (File) The jar that was created as a result of a compilation.
+        compile_jar: (File) A jar that is the compile-time dependency in lieu of `output_jar`.
+        source_jar: (File) The source jar that was used to create the output jar. Optional.
+        compile_jdeps: (File) jdeps information about compile time dependencies to be consumed by
+            JavaCompileAction. This should be a binary proto encoded using the deps.proto protobuf
+            included with Bazel. If available this file is typically produced by a header compiler.
+            Optional.
+        generated_class_jar: (File) A jar file containing class files compiled from sources
+            generated during annotation processing. Optional.
+        generated_source_jar: (File) The source jar that was created as a result of annotation
+            processing. Optional.
+        native_headers_jar: (File) A jar containing CC header files supporting native method
+            implementation (typically output of javac -h). Optional.
+        manifest_proto: (File) Manifest information for the rule output (if available). This should
+            be a binary proto encoded using the manifest.proto protobuf included with Bazel. IDEs
+            and other tools can use this information for more efficient processing. Optional.
+        neverlink: (bool) If true, only use this library for compilation and not at runtime.
+        deps: ([JavaInfo]) Compile time dependencies that were used to create the output jar.
+        runtime_deps: ([JavaInfo]) Runtime dependencies that are needed for this library.
+        exports: ([JavaInfo]) Libraries to make available for users of this library.
+        exported_plugins: ([JavaPluginInfo]) Optional. A list of exported plugins.
+        jdeps: (File) jdeps information for the rule output (if available). This should be a binary
+            proto encoded using the deps.proto protobuf included with Bazel. If available this file
+            is typically produced by a compiler. IDEs and other tools can use this information for
+            more efficient processing. Optional.
+        native_libraries: ([CcInfo]) Native library dependencies that are needed for this library.
+        add_exports: ([str]) The <module>/<package>s this library was given access to.
+        add_opens: ([str]) The <module>/<package>s this library was given reflective access to.
+
+    Returns:
+        (dict) arguments to the JavaInfo provider constructor
+    """
+    if add_exports or add_opens:
+        semantics.check_java_info_opens_exports()
+
+    result, concatenated_deps = _javainfo_init_base(
+        output_jar,
+        compile_jar,
+        source_jar,
+        deps,
+        runtime_deps,
+        exports,
+        exported_plugins,
+        jdeps,
+        compile_jdeps,
+        native_headers_jar,
+        manifest_proto,
+        generated_class_jar,
+        generated_source_jar,
+        native_libraries,
+        neverlink,
+    )
+
+    if neverlink:
+        transitive_runtime_jars = depset()
+    else:
+        transitive_runtime_jars = depset(
+            order = "preorder",
+            direct = [output_jar],
+            transitive = [dep.transitive_runtime_jars for dep in concatenated_deps.exports_deps + runtime_deps],
+        )
+
+    # For backward compatibility, we use deps_exports for add_exports/add_opens
+    # for the JavaInfo constructor rather than runtimedeps_exports_deps (used
+    # by java_info_for_compilation). However, runtimedeps_exports_deps makes
+    # more sense, since add_exports/add_opens from runtime_deps are needed at
+    # runtime anyway.
+    #
+    # TODO: When this flag is removed, move this logic into _javainfo_init_base
+    #  and remove the special case from java_info_for_compilation.
+    module_flags_deps = concatenated_deps.deps_exports
+    if get_internal_java_common().incompatible_java_info_merge_runtime_module_flags():
+        module_flags_deps = concatenated_deps.runtimedeps_exports_deps
+
+    result.update(
+        transitive_runtime_jars = transitive_runtime_jars,
+        transitive_source_jars = depset(
+            direct = [source_jar] if source_jar else [],
+            # TODO(hvd): native also adds source jars from deps, but this should be unnecessary
+            transitive = [
+                dep.transitive_source_jars
+                for dep in deps + runtime_deps + exports
+            ],
+        ),
+        module_flags_info = _create_module_flags_info(
+            add_exports = depset(add_exports, transitive = [
+                dep.module_flags_info.add_exports
+                for dep in module_flags_deps
+            ]),
+            add_opens = depset(add_opens, transitive = [
+                dep.module_flags_info.add_opens
+                for dep in module_flags_deps
+            ]),
+        ),
+    )
+    return result
+
+JavaInfo, _new_javainfo = provider(
+    doc = "Info object encapsulating all information by java rules.",
+    fields = {
+        "transitive_runtime_jars": """(depset[File]) A transitive set of jars required on the
+        runtime classpath.
+        <p/>Note: for binary targets (such as java_binary and java_test), this is empty, since such
+        targets are not intended to be dependencies of other Java targets.
+        """,
+        "transitive_compile_time_jars": """(depset[File]) The transitive set of jars required to
+        build the target.
+        <p/>Note: for binary targets (such as java_binary and java_test), this is empty, since such
+        targets are not intended to be dependencies of other Java targets.
+        """,
+        "compile_jars": """(depset[File]) The jars required directly at compile time. They can be interface jars
+                (ijar or hjar), regular jars or both, depending on whether rule
+                implementations chose to create interface jars or not.""",
+        "full_compile_jars": """(depset[File]) The regular, full compile time Jars required by this target directly.
+                They can be:
+                 - the corresponding regular Jars of the interface Jars returned by JavaInfo.compile_jars
+                 - the regular (full) Jars returned by JavaInfo.compile_jars
+
+                Note: JavaInfo.compile_jars can return a mix of interface Jars and
+                regular Jars.<p>Only use this method if interface Jars don't work with
+                your rule set(s) (e.g. some Scala targets) If you're working with
+                Java-only targets it's preferable to use interface Jars via
+                JavaInfo.compile_jars""",
+        "source_jars": """([File]) A list of Jars with all the source files (including those generated by
+                annotations) of the target itself, i.e. NOT including the sources of the
+                transitive dependencies.""",
+        "outputs": "Deprecated: use java_outputs.",
+        "annotation_processing": "Deprecated: Please use plugins instead.",
+        "runtime_output_jars": "([File]) A list of runtime Jars created by this Java/Java-like target.",
+        "transitive_source_jars": "(depset[File]) The Jars of all source files in the transitive closure.",
+        "transitive_native_libraries": """(depset[LibraryToLink]) The transitive set of CC native
+                libraries required by the target.""",
+        "cc_link_params_info": "Deprecated. Do not use. C++ libraries to be linked into Java targets.",
+        "module_flags_info": "(_ModuleFlagsInfo) The Java module flag configuration.",
+        "plugins": """(_JavaPluginDataInfo) Data about all plugins that a consuming target should
+               apply.
+               This is typically either a `java_plugin` itself or a `java_library` exporting
+               one or more plugins.
+               A `java_library` runs annotation processing with all plugins from this field
+               appearing in <code>deps</code> and `plugins` attributes.""",
+        "api_generating_plugins": """"(_JavaPluginDataInfo) Data about API generating plugins
+               defined or exported by this target.
+               Those annotation processors are applied to a Java target before
+               producing its header jars (which contain method signatures). When
+               no API plugins are present, header jars are generated from the
+               sources, reducing critical path.
+               The `api_generating_plugins` is a subset of `plugins`.""",
+        "java_outputs": "(_JavaOutputInfo) Information about outputs of this Java/Java-like target.",
+        "compilation_info": """(java_compilation_info) Compilation information for this
+               Java/Java-like target.""",
+        "_transitive_full_compile_time_jars": "internal API, do not use",
+        "_compile_time_java_dependencies": "internal API, do not use",
+        "_neverlink": "internal API, do not use",
+        "_constraints": "internal API, do not use",
+        "_is_binary": "internal API, do not use",
+    },
+    init = _javainfo_init,
+)
+
+JavaPluginDataInfo = provider(
+    doc = "Provider encapsulating information about a Java compatible plugin.",
+    fields = {
+        "processor_classes": "depset(str) The fully qualified classnames of entry points for the compiler",
+        "processor_jars": "depset(file) Deps containing an annotation processor",
+        "processor_data": "depset(file) Files needed during execution",
+    },
+)
+
+_EMPTY_PLUGIN_DATA = JavaPluginDataInfo(
+    processor_classes = depset(),
+    processor_jars = depset(),
+    processor_data = depset(),
+)
+
+def _create_plugin_data_info(*, processor_classes, processor_jars, processor_data):
+    if processor_classes or processor_jars or processor_data:
+        return JavaPluginDataInfo(
+            processor_classes = processor_classes,
+            processor_jars = processor_jars,
+            processor_data = processor_data,
+        )
+    else:
+        return _EMPTY_PLUGIN_DATA
+
+def disable_plugin_info_annotation_processing(plugin_info):
+    """Returns a copy of the provided JavaPluginInfo without annotation processing info
+
+    Args:
+        plugin_info: (JavaPluginInfo) the instance to transform
+
+    Returns:
+        (JavaPluginInfo) a new, transformed instance.
+     """
+    return _new_javaplugininfo(
+        plugins = _create_plugin_data_info(
+            processor_classes = depset(order = "preorder"),
+            # Preserve the processor path, since it may contain Error Prone plugins
+            # which will be service-loaded by JavaBuilder.
+            processor_jars = plugin_info.plugins.processor_jars,
+            # Preserve data, which may be used by Error Prone plugins.
+            processor_data = plugin_info.plugins.processor_data,
+        ),
+        api_generating_plugins = _EMPTY_PLUGIN_DATA,
+        java_outputs = plugin_info.java_outputs,
+    )
+
+def merge_plugin_info_without_outputs(infos):
+    """ Merge plugin information from a list of JavaPluginInfo or JavaInfo
+
+    Args:
+        infos: ([JavaPluginInfo|JavaInfo]) list of providers to merge
+
+    Returns:
+        (JavaPluginInfo)
+    """
+    plugins = []
+    api_generating_plugins = []
+    for info in infos:
+        if _has_plugin_data(info.plugins):
+            plugins.append(info.plugins)
+        if _has_plugin_data(info.api_generating_plugins):
+            api_generating_plugins.append(info.api_generating_plugins)
+    return _new_javaplugininfo(
+        plugins = _merge_plugin_data(plugins),
+        api_generating_plugins = _merge_plugin_data(api_generating_plugins),
+        java_outputs = [],
+    )
+
+def _has_plugin_data(plugin_data):
+    return plugin_data and (
+        plugin_data.processor_classes or
+        plugin_data.processor_jars or
+        plugin_data.processor_data
+    )
+
+def _merge_plugin_data(datas):
+    return _create_plugin_data_info(
+        processor_classes = depset(transitive = [p.processor_classes for p in datas]),
+        processor_jars = depset(transitive = [p.processor_jars for p in datas]),
+        processor_data = depset(transitive = [p.processor_data for p in datas]),
+    )
+
+def _javaplugininfo_init(
+        runtime_deps,
+        processor_class,
+        data = [],
+        generates_api = False):
+    """ Constructs JavaPluginInfo
+
+    Args:
+        runtime_deps: ([JavaInfo]) list of deps containing an annotation
+             processor.
+        processor_class: (String) The fully qualified class name that the Java
+             compiler uses as an entry point to the annotation processor.
+        data: (depset[File]) The files needed by this annotation
+             processor during execution.
+        generates_api: (boolean) Set to true when this annotation processor
+            generates API code. Such an annotation processor is applied to a
+            Java target before producing its header jars (which contains method
+            signatures). When no API plugins are present, header jars are
+            generated from the sources, reducing the critical path.
+            WARNING: This parameter affects build performance, use it only if
+            necessary.
+
+    Returns:
+        (JavaPluginInfo)
+    """
+
+    java_infos = merge(runtime_deps)
+    processor_data = data if type(data) == "depset" else depset(data)
+    plugins = _create_plugin_data_info(
+        processor_classes = depset([processor_class]) if processor_class else depset(),
+        processor_jars = java_infos.transitive_runtime_jars,
+        processor_data = processor_data,
+    )
+    return {
+        "plugins": plugins,
+        "api_generating_plugins": plugins if generates_api else _EMPTY_PLUGIN_DATA,
+        "java_outputs": java_infos.java_outputs,
+    }
+
+JavaPluginInfo, _new_javaplugininfo = provider(
+    doc = "Provider encapsulating information about Java plugins.",
+    fields = {
+        "plugins": """
+            Returns data about all plugins that a consuming target should apply.
+            This is typically either a <code>java_plugin</code> itself or a
+            <code>java_library</code> exporting one or more plugins.
+            A <code>java_library</code> runs annotation processing with all
+            plugins from this field appearing in <code>deps</code> and
+            <code>plugins</code> attributes.""",
+        "api_generating_plugins": """
+            Returns data about API generating plugins defined or exported by
+            this target.
+            Those annotation processors are applied to a Java target before
+            producing its header jars (which contain method signatures). When
+            no API plugins are present, header jars are generated from the
+            sources, reducing critical path.
+            The <code>api_generating_plugins</code> is a subset of
+            <code>plugins</code>.""",
+        "java_outputs": """
+            Returns information about outputs of this Java/Java-like target.
+        """,
+    },
+    init = _javaplugininfo_init,
+)
diff --git a/java/private/message_bundle_info.bzl b/java/private/message_bundle_info.bzl
new file mode 100644
index 0000000..df77fce
--- /dev/null
+++ b/java/private/message_bundle_info.bzl
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
+
+"""
+Definition of MessageBundleInfo provider.
+"""
+
+visibility("private")
+
+MessageBundleInfo = provider(
+    doc = "Marks configured targets that are able to supply message bundles to their dependents.",
+    fields = {
+        "messages": "Sequence of message bundles",
+    },
+)
diff --git a/java/private/native.bzl b/java/private/native.bzl
index 64a4d5a..22f84ff 100644
--- a/java/private/native.bzl
+++ b/java/private/native.bzl
@@ -21,6 +21,8 @@
 
 """Lovely workaround to be able to expose native constants pretending to be Starlark."""
 
+# Unused with Bazel@HEAD, used by the compatibility layer for older Bazel versions
+
 # buildifier: disable=native-java
 native_java_common = java_common
 
@@ -29,3 +31,10 @@ NativeJavaInfo = JavaInfo
 
 # buildifier: disable=native-java
 NativeJavaPluginInfo = JavaPluginInfo
+
+# Used for some private native APIs that we can't replicate just yet in Starlark
+# getattr() for loading this file with Bazel 6, where we won't use this
+def get_internal_java_common():
+    if hasattr(native_java_common, "internal_DO_NOT_USE"):
+        return native_java_common.internal_DO_NOT_USE()
+    return None
diff --git a/java/private/proto_support.bzl b/java/private/proto_support.bzl
new file mode 100644
index 0000000..957dc31
--- /dev/null
+++ b/java/private/proto_support.bzl
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
+"""Support for Java compilation of protocol buffer generated code."""
+
+load("@compatibility_proxy//:proxy.bzl", "java_common", "java_common_internal_compile", "java_info_internal_merge")
+
+def compile(*, injecting_rule_kind, enable_jspecify, include_compilation_info, **kwargs):
+    if java_common_internal_compile:
+        return java_common_internal_compile(
+            injecting_rule_kind = injecting_rule_kind,
+            enable_jspecify = enable_jspecify,
+            include_compilation_info = include_compilation_info,
+            **kwargs
+        )
+    else:
+        return java_common.compile(**kwargs)
+
+def merge(providers, *, merge_java_outputs = True, merge_source_jars = True):
+    if java_info_internal_merge:
+        return java_info_internal_merge(
+            providers,
+            merge_java_outputs = merge_java_outputs,
+            merge_source_jars = merge_source_jars,
+        )
+    else:
+        return java_common.merge(providers)
diff --git a/java/repositories.bzl b/java/repositories.bzl
index f9c396a..f02b0f6 100644
--- a/java/repositories.bzl
+++ b/java/repositories.bzl
@@ -20,41 +20,43 @@ load("//toolchains:jdk_build_file.bzl", "JDK_BUILD_TEMPLATE")
 load("//toolchains:local_java_repository.bzl", "local_java_repository")
 load("//toolchains:remote_java_repository.bzl", "remote_java_repository")
 
-_JAVA_TOOLS_CONFIG = {
-    "version": "v13.6.0",
+# visible for tests
+JAVA_TOOLS_CONFIG = {
+    "version": "v13.13",
     "release": "true",
     "artifacts": {
         "java_tools_linux": {
-            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_linux-v13.6.0.zip",
-            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_linux-v13.6.0.zip",
-            "sha": "0d3fcae7ae40d0a25f17c3adc30a3674f526953c55871189e2efe3463fce3496",
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.13/java_tools_linux-v13.13.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.13/java_tools_linux-v13.13.zip",
+            "sha": "60c10e91f5900801423f9c5b020cc0c7da16dbaeee9c22891b38e7017306a8e7",
         },
         "java_tools_windows": {
-            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_windows-v13.6.0.zip",
-            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_windows-v13.6.0.zip",
-            "sha": "5a7d00e42c0b35f08eb5c8577eb115f8f57dd36ef8b6940c2190bd0d0e4ddcf0",
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.13/java_tools_windows-v13.13.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.13/java_tools_windows-v13.13.zip",
+            "sha": "f5de3f2afc49d1a457efa63926bcc0ca4cdb5fc4887160bf9163e49f059dd12c",
         },
         "java_tools_darwin_x86_64": {
-            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_darwin_x86_64-v13.6.0.zip",
-            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_darwin_x86_64-v13.6.0.zip",
-            "sha": "465dcb1da77a0c83c49f178c11bad29b3d703df1756722ec42fe5afd7c8129f8",
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.13/java_tools_darwin_x86_64-v13.13.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.13/java_tools_darwin_x86_64-v13.13.zip",
+            "sha": "d002ff57bd5e36d6d69a1c282fa571841816a1ccc5d28060cf7fe4c7257e376a",
         },
         "java_tools_darwin_arm64": {
-            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools_darwin_arm64-v13.6.0.zip",
-            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools_darwin_arm64-v13.6.0.zip",
-            "sha": "eb54c4e5fa23d6e9e9fc14c106a682dbefc54659d8e389a2f3c0d61d51cae274",
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.13/java_tools_darwin_arm64-v13.13.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.13/java_tools_darwin_arm64-v13.13.zip",
+            "sha": "6d4b4e3a12cc5fd9f600b383465d0860afd5c11ba7c7386867bb621a55fa8452",
         },
         "java_tools": {
-            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.6.0/java_tools-v13.6.0.zip",
-            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.6.0/java_tools-v13.6.0.zip",
-            "sha": "74c978eab040ad4ec38ce0d0970ac813cc2c6f4f6f4f121c0414719487edc991",
+            "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/v13.13/java_tools-v13.13.zip",
+            "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_v13.13/java_tools-v13.13.zip",
+            "sha": "df895d5067f2dad4524109ebfddac442d2514d0e2f95f6abc098cfae98b9bbb5",
+            "build_file": "@rules_java//toolchains:BUILD.java_tools",
         },
     },
 }
 
 def java_tools_repos():
     """ Declares the remote java_tools repositories """
-    for name, config in _JAVA_TOOLS_CONFIG["artifacts"].items():
+    for name, config in JAVA_TOOLS_CONFIG["artifacts"].items():
         maybe(
             http_archive,
             name = "remote_" + name,
@@ -63,6 +65,7 @@ def java_tools_repos():
                 config["mirror_url"],
                 config["github_url"],
             ],
+            build_file = config.get("build_file"),
         )
 
 def local_jdk_repo():
@@ -72,495 +75,296 @@ def local_jdk_repo():
         build_file_content = JDK_BUILD_TEMPLATE,
     )
 
-def remote_jdk8_repos(name = ""):
-    """Imports OpenJDK 8 repositories.
-
-    Args:
-        name: The name of this macro (not used)
-    """
-    maybe(
-        remote_java_repository,
+# DO NOT MANUALLY UPDATE! Update java/bazel/repositories_util.bzl instead and
+# build the java/bazel:dump_remote_jdk_configs target to generate this list
+_REMOTE_JDK_CONFIGS_LIST = [
+    struct(
         name = "remote_jdk8_linux_aarch64",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "f4072e82faa5a09fab2accf2892d4684324fc999d614583c3ff785e87c03963f",
-        strip_prefix = "zulu8.50.51.263-ca-jdk8.0.275-linux_aarch64",
-        urls = [
-            "https://mirror.bazel.build/openjdk/azul-zulu-8.50.0.51-ca-jdk8.0.275/zulu8.50.51.263-ca-jdk8.0.275-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu-embedded/bin/zulu8.50.51.263-ca-jdk8.0.275-linux_aarch64.tar.gz",
-        ],
-        version = "8",
-    )
-    maybe(
-        remote_java_repository,
-        name = "remote_jdk8_linux_s390x",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:s390x",
-        ],
-        sha256 = "276a431c79b7e94bc1b1b4fd88523383ae2d635ea67114dfc8a6174267f8fb2c",
-        strip_prefix = "jdk8u292-b10",
-        urls = [
-            "https://github.com/AdoptOpenJDK/openjdk8-binaries/releases/download/jdk8u292-b10/OpenJDK8U-jdk_s390x_linux_hotspot_8u292b10.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:aarch64"],
+        sha256 = "82c46c65d57e187ef68fdd125ef760eaeb52ebfe1be1a6a251cf5b43cbebc78a",
+        strip_prefix = "zulu8.78.0.19-ca-jdk8.0.412-linux_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-linux_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-linux_aarch64.tar.gz"],
         version = "8",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remote_jdk8_linux",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "1db6b2fa642950ee1b4b1ec2b6bc8a9113d7a4cd723f79398e1ada7dab1c981c",
-        strip_prefix = "zulu8.50.0.51-ca-jdk8.0.275-linux_x64",
-        urls = [
-            "https://mirror.bazel.build/openjdk/azul-zulu-8.50.0.51-ca-jdk8.0.275/zulu8.50.0.51-ca-jdk8.0.275-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu8.50.0.51-ca-jdk8.0.275-linux_x64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
+        sha256 = "9c0ac5ebffa61520fee78ead52add0f4edd3b1b54b01b6a17429b719515caf90",
+        strip_prefix = "zulu8.78.0.19-ca-jdk8.0.412-linux_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-linux_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-linux_x64.tar.gz"],
         version = "8",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remote_jdk8_macos_aarch64",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "e5c84a46bbd985c3a53358db9c97a6fd4930f92b833c3163a0d1e47dab59768c",
-        strip_prefix = "zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu8.62.0.19-ca-jdk8.0.332-macosx_aarch64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
+        sha256 = "35bc35808379400e4a70e1f7ee379778881799b93c2cc9fe1ae515c03c2fb057",
+        strip_prefix = "zulu8.78.0.19-ca-jdk8.0.412-macosx_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-macosx_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-macosx_aarch64.tar.gz"],
         version = "8",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remote_jdk8_macos",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "b03176597734299c9a15b7c2cc770783cf14d121196196c1248e80c026b59c17",
-        strip_prefix = "zulu8.50.0.51-ca-jdk8.0.275-macosx_x64",
-        urls = [
-            "https://mirror.bazel.build/openjdk/azul-zulu-8.50.0.51-ca-jdk8.0.275/zulu8.50.0.51-ca-jdk8.0.275-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu8.50.0.51-ca-jdk8.0.275-macosx_x64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:x86_64"],
+        sha256 = "2bfa0506196962bddb21a604eaa2b0b39eaf3383d0bdad08bdbe7f42f25d8928",
+        strip_prefix = "zulu8.78.0.19-ca-jdk8.0.412-macosx_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-macosx_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-macosx_x64.tar.gz"],
         version = "8",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remote_jdk8_windows",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "49759b2bd2ab28231a21ff3a3bb45824ddef55d89b5b1a05a62e26a365da0774",
-        strip_prefix = "zulu8.50.0.51-ca-jdk8.0.275-win_x64",
-        urls = [
-            "https://mirror.bazel.build/openjdk/azul-zulu-8.50.0.51-ca-jdk8.0.275/zulu8.50.0.51-ca-jdk8.0.275-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu8.50.0.51-ca-jdk8.0.275-win_x64.zip",
-        ],
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:x86_64"],
+        sha256 = "ca5499c301d5b42604d8535b8c40a7f928a796247b8c66a600333dd799798ff7",
+        strip_prefix = "zulu8.78.0.19-ca-jdk8.0.412-win_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-win_x64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu8.78.0.19-ca-jdk8.0.412-win_x64.zip"],
         version = "8",
-    )
-
-def remote_jdk11_repos():
-    """Imports OpenJDK 11 repositories."""
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
+        name = "remote_jdk8_linux_s390x",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:s390x"],
+        sha256 = "276a431c79b7e94bc1b1b4fd88523383ae2d635ea67114dfc8a6174267f8fb2c",
+        strip_prefix = "jdk8u292-b10",
+        urls = ["https://github.com/AdoptOpenJDK/openjdk8-binaries/releases/download/jdk8u292-b10/OpenJDK8U-jdk_s390x_linux_hotspot_8u292b10.tar.gz", "https://mirror.bazel.build/github.com/AdoptOpenJDK/openjdk8-binaries/releases/download/jdk8u292-b10/OpenJDK8U-jdk_s390x_linux_hotspot_8u292b10.tar.gz"],
+        version = "8",
+    ),
+    struct(
+        name = "remotejdk11_linux_aarch64",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:aarch64"],
+        sha256 = "be7d7574253c893eb58f66e985c75adf48558c41885827d1f02f827e109530e0",
+        strip_prefix = "zulu11.72.19-ca-jdk11.0.23-linux_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-linux_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-linux_aarch64.tar.gz"],
+        version = "11",
+    ),
+    struct(
         name = "remotejdk11_linux",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "a34b404f87a08a61148b38e1416d837189e1df7a040d949e743633daf4695a3c",
-        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-linux_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_x64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
+        sha256 = "0a4d1bfc7a96a7f9f5329b72b9801b3c53366417b4753f1b658fa240204c7347",
+        strip_prefix = "zulu11.72.19-ca-jdk11.0.23-linux_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-linux_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-linux_x64.tar.gz"],
         version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk11_linux_aarch64",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "54174439f2b3fddd11f1048c397fe7bb45d4c9d66d452d6889b013d04d21c4de",
-        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-linux_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-linux_aarch64.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk11_macos_aarch64",
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
+        sha256 = "40fb1918385e03814b67b7608c908c7f945ccbeddbbf5ed062cdfb2602e21c83",
+        strip_prefix = "zulu11.72.19-ca-jdk11.0.23-macosx_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-macosx_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-macosx_aarch64.tar.gz"],
         version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
+        name = "remotejdk11_macos",
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:x86_64"],
+        sha256 = "e5b19b82045826ae09c9d17742691bc9e40312c44be7bd7598ae418a3d4edb1c",
+        strip_prefix = "zulu11.72.19-ca-jdk11.0.23-macosx_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-macosx_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-macosx_x64.tar.gz"],
+        version = "11",
+    ),
+    struct(
+        name = "remotejdk11_win",
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:x86_64"],
+        sha256 = "1295b2affe498018c45f6f15187b58c4456d51dce5eb608ee73ef7665d4566d2",
+        strip_prefix = "zulu11.72.19-ca-jdk11.0.23-win_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-win_x64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.72.19-ca-jdk11.0.23-win_x64.zip"],
+        version = "11",
+    ),
+    struct(
         name = "remotejdk11_linux_ppc64le",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:ppc",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:ppc"],
         sha256 = "a8fba686f6eb8ae1d1a9566821dbd5a85a1108b96ad857fdbac5c1e4649fc56f",
         strip_prefix = "jdk-11.0.15+10",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_ppc64le_linux_hotspot_11.0.15_10.tar.gz",
-            "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_ppc64le_linux_hotspot_11.0.15_10.tar.gz",
-        ],
+        urls = ["https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_ppc64le_linux_hotspot_11.0.15_10.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_ppc64le_linux_hotspot_11.0.15_10.tar.gz"],
         version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk11_linux_s390x",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:s390x",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:s390x"],
         sha256 = "a58fc0361966af0a5d5a31a2d8a208e3c9bb0f54f345596fd80b99ea9a39788b",
         strip_prefix = "jdk-11.0.15+10",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_s390x_linux_hotspot_11.0.15_10.tar.gz",
-            "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_s390x_linux_hotspot_11.0.15_10.tar.gz",
-        ],
-        version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk11_macos",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "bcaab11cfe586fae7583c6d9d311c64384354fb2638eb9a012eca4c3f1a1d9fd",
-        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-macosx_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_x64.tar.gz",
-        ],
-        version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk11_macos_aarch64",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "7632bc29f8a4b7d492b93f3bc75a7b61630894db85d136456035ab2a24d38885",
-        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-macosx_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-macosx_aarch64.tar.gz",
-        ],
+        urls = ["https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_s390x_linux_hotspot_11.0.15_10.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15+10/OpenJDK11U-jdk_s390x_linux_hotspot_11.0.15_10.tar.gz"],
         version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk11_win",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "43408193ce2fa0862819495b5ae8541085b95660153f2adcf91a52d3a1710e83",
-        strip_prefix = "zulu11.66.15-ca-jdk11.0.20-win_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu11.66.15-ca-jdk11.0.20-win_x64.zip",
-        ],
-        version = "11",
-    )
-
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk11_win_arm64",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:arm64",
-        ],
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:arm64"],
         sha256 = "b8a28e6e767d90acf793ea6f5bed0bb595ba0ba5ebdf8b99f395266161e53ec2",
         strip_prefix = "jdk-11.0.13+8",
-        urls = [
-            "https://mirror.bazel.build/aka.ms/download-jdk/microsoft-jdk-11.0.13.8.1-windows-aarch64.zip",
-        ],
+        urls = ["https://aka.ms/download-jdk/microsoft-jdk-11.0.13.8.1-windows-aarch64.zip", "https://mirror.bazel.build/aka.ms/download-jdk/microsoft-jdk-11.0.13.8.1-windows-aarch64.zip"],
         version = "11",
-    )
-
-def remote_jdk17_repos():
-    """Imports OpenJDK 17 repositories."""
-    maybe(
-        remote_java_repository,
-        name = "remotejdk17_linux",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "b9482f2304a1a68a614dfacddcf29569a72f0fac32e6c74f83dc1b9a157b8340",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-linux_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_x64.tar.gz",
-        ],
-        version = "17",
-    )
-
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk17_linux_aarch64",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "6531cef61e416d5a7b691555c8cf2bdff689201b8a001ff45ab6740062b44313",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-linux_aarch64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:aarch64"],
+        sha256 = "518cc455c0c7b49c0ae7d809c0bb87ab371bb850d46abb8efad5010c6a06faec",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-linux_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-linux_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-linux_aarch64.tar.gz"],
         version = "17",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk17_linux_s390x",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:s390x",
-        ],
-        sha256 = "ffacba69c6843d7ca70d572489d6cc7ab7ae52c60f0852cedf4cf0d248b6fc37",
-        strip_prefix = "jdk-17.0.8.1+1",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz",
-            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk17_linux",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
+        sha256 = "a1e8ac9ae5804b84dc07cf9d8ebe1b18247d70c92c1e0de97ea10109563f4379",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-linux_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-linux_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-linux_x64.tar.gz"],
         version = "17",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk17_linux_ppc64le",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:ppc",
-        ],
-        sha256 = "00a4c07603d0218cd678461b5b3b7e25b3253102da4022d31fc35907f21a2efd",
-        strip_prefix = "jdk-17.0.8.1+1",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz",
-            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1%2B1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk17_macos_aarch64",
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
+        sha256 = "dd1a82d57e80cdefb045066e5c28b5bd41e57eea9c57303ec7e012b57230bb9c",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-macosx_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-macosx_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-macosx_aarch64.tar.gz"],
         version = "17",
-    )
-
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk17_macos",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "640453e8afe8ffe0fb4dceb4535fb50db9c283c64665eebb0ba68b19e65f4b1f",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-macosx_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_x64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:x86_64"],
+        sha256 = "b384991e93af39abe5229c7f5efbe912a7c5a6480674a6e773f3a9128f96a764",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-macosx_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-macosx_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-macosx_x64.tar.gz"],
         version = "17",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk17_macos_aarch64",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "314b04568ec0ae9b36ba03c9cbd42adc9e1265f74678923b19297d66eb84dcca",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-macosx_aarch64.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk17_win_arm64",
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:arm64"],
+        sha256 = "b8833d272eb31f54f8c881139807a28a74de9deae07d2cc37688ff72043e32c9",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-win_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-win_aarch64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-win_aarch64.zip"],
         version = "17",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk17_win",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "192f2afca57701de6ec496234f7e45d971bf623ff66b8ee4a5c81582054e5637",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-win_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_x64.zip",
-        ],
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:x86_64"],
+        sha256 = "43f0f1bdecf48ba9763d46ee7784554c95b442ffdd39ebd62dc8b297cc82e116",
+        strip_prefix = "zulu17.50.19-ca-jdk17.0.11-win_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-win_x64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.50.19-ca-jdk17.0.11-win_x64.zip"],
         version = "17",
-    )
-    maybe(
-        remote_java_repository,
-        name = "remotejdk17_win_arm64",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:arm64",
-        ],
-        sha256 = "6802c99eae0d788e21f52d03cab2e2b3bf42bc334ca03cbf19f71eb70ee19f85",
-        strip_prefix = "zulu17.44.53-ca-jdk17.0.8.1-win_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_aarch64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu17.44.53-ca-jdk17.0.8.1-win_aarch64.zip",
-        ],
+    ),
+    struct(
+        name = "remotejdk17_linux_ppc64le",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:ppc"],
+        sha256 = "00a4c07603d0218cd678461b5b3b7e25b3253102da4022d31fc35907f21a2efd",
+        strip_prefix = "jdk-17.0.8.1+1",
+        urls = ["https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1+1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1+1/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.8.1_1.tar.gz"],
         version = "17",
-    )
-
-def remote_jdk21_repos():
-    """Imports OpenJDK 21 repositories."""
-    maybe(
-        remote_java_repository,
-        name = "remotejdk21_linux",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "5ad730fbee6bb49bfff10bf39e84392e728d89103d3474a7e5def0fd134b300a",
-        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-linux_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_x64.tar.gz",
-        ],
-        version = "21",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
+        name = "remotejdk17_linux_s390x",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:s390x"],
+        sha256 = "ffacba69c6843d7ca70d572489d6cc7ab7ae52c60f0852cedf4cf0d248b6fc37",
+        strip_prefix = "jdk-17.0.8.1+1",
+        urls = ["https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1+1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8.1+1/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.8.1_1.tar.gz"],
+        version = "17",
+    ),
+    struct(
         name = "remotejdk21_linux_aarch64",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "ce7df1af5d44a9f455617c4b8891443fbe3e4b269c777d8b82ed66f77167cfe0",
-        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-linux_aarch64",
-        urls = [
-            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_aarch64.tar.gz",
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-linux_aarch64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:aarch64"],
+        sha256 = "da3c2d7db33670bcf66532441aeb7f33dcf0d227c8dafe7ce35cee67f6829c4c",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-linux_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-linux_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-linux_aarch64.tar.gz"],
         version = "21",
-    )
-    maybe(
-        remote_java_repository,
-        name = "remotejdk21_linux_ppc64le",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:ppc",
-        ],
-        sha256 = "d08de863499d8851811c893e8915828f2cd8eb67ed9e29432a6b4e222d80a12f",
-        strip_prefix = "jdk-21.0.2+13",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.2_13.tar.gz",
-            "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.2_13.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk21_linux",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
+        sha256 = "318d0c2ed3c876fb7ea2c952945cdcf7decfb5264ca51aece159e635ac53d544",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-linux_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-linux_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-linux_x64.tar.gz"],
         version = "21",
-    )
-    maybe(
-        remote_java_repository,
-        name = "remotejdk21_linux_s390x",
-        target_compatible_with = [
-            "@platforms//os:linux",
-            "@platforms//cpu:s390x",
-        ],
-        sha256 = "0d5676c50821e0d0b951bf3ffd717e7a13be2a89d8848a5c13b4aedc6f982c78",
-        strip_prefix = "jdk-21.0.2+13",
-        urls = [
-            "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.2_13.tar.gz",
-            "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.2_13.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk21_macos_aarch64",
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:aarch64"],
+        sha256 = "bc2750f81a166cc6e9c30ae8aaba54f253a8c8ec9d8cfc04a555fe20712c7bff",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-macosx_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-macosx_aarch64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-macosx_aarch64.tar.gz"],
         version = "21",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk21_macos",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "3ad8fe288eb57d975c2786ae453a036aa46e47ab2ac3d81538ebae2a54d3c025",
-        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-macosx_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_x64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_x64.tar.gz",
-        ],
+        target_compatible_with = ["@platforms//os:macos", "@platforms//cpu:x86_64"],
+        sha256 = "5ce75a6a247c7029b74c4ca7cf6f60fd2b2d68ce1e8956fb448d2984316b5fea",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-macosx_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-macosx_x64.tar.gz", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-macosx_x64.tar.gz"],
         version = "21",
-    )
-
-    maybe(
-        remote_java_repository,
-        name = "remotejdk21_macos_aarch64",
-        target_compatible_with = [
-            "@platforms//os:macos",
-            "@platforms//cpu:aarch64",
-        ],
-        sha256 = "e8260516de8b60661422a725f1df2c36ef888f6fb35393566b00e7325db3d04e",
-        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-macosx_aarch64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_aarch64.tar.gz",
-            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-macosx_aarch64.tar.gz",
-        ],
+    ),
+    struct(
+        name = "remotejdk21_win_arm64",
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:arm64"],
+        sha256 = "9f873eccf030b1d3dc879ec1eb0ff5e11bf76002dc81c5c644c3462bf6c5146b",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-win_aarch64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-win_aarch64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-win_aarch64.zip"],
         version = "21",
-    )
-    maybe(
-        remote_java_repository,
+    ),
+    struct(
         name = "remotejdk21_win",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:x86_64",
-        ],
-        sha256 = "f7cc15ca17295e69c907402dfe8db240db446e75d3b150da7bf67243cded93de",
-        strip_prefix = "zulu21.32.17-ca-jdk21.0.2-win_x64",
-        urls = [
-            "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-win_x64.zip",
-            "https://cdn.azul.com/zulu/bin/zulu21.32.17-ca-jdk21.0.2-win_x64.zip",
-        ],
+        target_compatible_with = ["@platforms//os:windows", "@platforms//cpu:x86_64"],
+        sha256 = "d771dad10d3f0b440c3686d1f3d2b68b320802ac97b212d87671af3f2eef8848",
+        strip_prefix = "zulu21.36.17-ca-jdk21.0.4-win_x64",
+        urls = ["https://cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-win_x64.zip", "https://mirror.bazel.build/cdn.azul.com/zulu/bin/zulu21.36.17-ca-jdk21.0.4-win_x64.zip"],
         version = "21",
-    )
-    maybe(
-        remote_java_repository,
-        name = "remotejdk21_win_arm64",
-        target_compatible_with = [
-            "@platforms//os:windows",
-            "@platforms//cpu:arm64",
-        ],
-        sha256 = "975603e684f2ec5a525b3b5336d6aa0b09b5b7d2d0d9e271bd6a9892ad550181",
-        strip_prefix = "jdk-21+35",
-        urls = [
-            "https://mirror.bazel.build/aka.ms/download-jdk/microsoft-jdk-21.0.0-windows-aarch64.zip",
-            "https://aka.ms/download-jdk/microsoft-jdk-21.0.0-windows-aarch64.zip",
-        ],
+    ),
+    struct(
+        name = "remotejdk21_linux_ppc64le",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:ppc"],
+        sha256 = "c208cd0fb90560644a90f928667d2f53bfe408c957a5e36206585ad874427761",
+        strip_prefix = "jdk-21.0.4+7",
+        urls = ["https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4+7/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.4_7.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4+7/OpenJDK21U-jdk_ppc64le_linux_hotspot_21.0.4_7.tar.gz"],
         version = "21",
-    )
+    ),
+    struct(
+        name = "remotejdk21_linux_s390x",
+        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:s390x"],
+        sha256 = "c900c8d64fab1e53274974fa4a4c736a5a3754485a5c56f4947281480773658a",
+        strip_prefix = "jdk-21.0.4+7",
+        urls = ["https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4+7/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.4_7.tar.gz", "https://mirror.bazel.build/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4+7/OpenJDK21U-jdk_s390x_linux_hotspot_21.0.4_7.tar.gz"],
+        version = "21",
+    ),
+]
 
-def rules_java_dependencies():
-    """An utility method to load all dependencies of rules_java.
+def _make_version_to_remote_jdks():
+    result = {}
+    for cfg in _REMOTE_JDK_CONFIGS_LIST:
+        result.setdefault(cfg.version, [])
+        result[cfg.version].append(cfg)
+    return result
 
-    Loads the remote repositories used by default in Bazel.
+# visible for testing
+REMOTE_JDK_CONFIGS = _make_version_to_remote_jdks()
+
+def _remote_jdk_repos_for_version(version):
+    for item in REMOTE_JDK_CONFIGS[version]:
+        maybe(
+            remote_java_repository,
+            name = item.name,
+            target_compatible_with = item.target_compatible_with,
+            sha256 = item.sha256,
+            strip_prefix = item.strip_prefix,
+            urls = item.urls,
+            version = item.version,
+        )
+
+def remote_jdk8_repos(name = ""):
+    """Imports OpenJDK 8 repositories.
+
+    Args:
+        name: The name of this macro (not used)
     """
+    _remote_jdk_repos_for_version("8")
 
-    local_jdk_repo()
-    remote_jdk8_repos()
-    remote_jdk11_repos()
-    remote_jdk17_repos()
-    remote_jdk21_repos()
-    java_tools_repos()
+def remote_jdk11_repos():
+    """Imports OpenJDK 11 repositories."""
+    _remote_jdk_repos_for_version("11")
+
+def remote_jdk17_repos():
+    """Imports OpenJDK 17 repositories."""
+    _remote_jdk_repos_for_version("17")
+
+def remote_jdk21_repos():
+    """Imports OpenJDK 21 repositories."""
+    _remote_jdk_repos_for_version("21")
+
+def rules_java_dependencies():
+    """DEPRECATED: No-op, kept for backwards compatibility"""
+    print("DEPRECATED: use rules_java_dependencies() from rules_java_deps.bzl")  # buildifier: disable=print
 
 def rules_java_toolchains(name = "toolchains"):
     """An utility method to load all Java toolchains.
@@ -568,26 +372,21 @@ def rules_java_toolchains(name = "toolchains"):
     Args:
         name: The name of this macro (not used)
     """
-    JDKS = {
-        # Must match JDK repos defined in remote_jdk8_repos()
-        "8": ["linux", "linux_aarch64", "linux_s390x", "macos", "macos_aarch64", "windows"],
-        # Must match JDK repos defined in remote_jdk11_repos()
-        "11": ["linux", "linux_aarch64", "linux_ppc64le", "linux_s390x", "macos", "macos_aarch64", "win", "win_arm64"],
-        # Must match JDK repos defined in remote_jdk17_repos()
-        "17": ["linux", "linux_aarch64", "linux_ppc64le", "linux_s390x", "macos", "macos_aarch64", "win", "win_arm64"],
-        # Must match JDK repos defined in remote_jdk21_repos()
-        "21": ["linux", "linux_aarch64", "macos", "macos_aarch64", "win"],
-    }
-
-    REMOTE_JDK_REPOS = [(("remote_jdk" if version == "8" else "remotejdk") + version + "_" + platform) for version in JDKS for platform in JDKS[version]]
+    local_jdk_repo()
+    remote_jdk8_repos()
+    remote_jdk11_repos()
+    remote_jdk17_repos()
+    remote_jdk21_repos()
+    java_tools_repos()
 
     native.register_toolchains(
         "//toolchains:all",
         "@local_jdk//:runtime_toolchain_definition",
         "@local_jdk//:bootstrap_runtime_toolchain_definition",
     )
-    for name in REMOTE_JDK_REPOS:
-        native.register_toolchains(
-            "@" + name + "_toolchain_config_repo//:toolchain",
-            "@" + name + "_toolchain_config_repo//:bootstrap_runtime_toolchain",
-        )
+    for items in REMOTE_JDK_CONFIGS.values():
+        for item in items:
+            native.register_toolchains(
+                "@" + item.name + "_toolchain_config_repo//:toolchain",
+                "@" + item.name + "_toolchain_config_repo//:bootstrap_runtime_toolchain",
+            )
diff --git a/java/rules_java_deps.bzl b/java/rules_java_deps.bzl
new file mode 100644
index 0000000..98a2907
--- /dev/null
+++ b/java/rules_java_deps.bzl
@@ -0,0 +1,154 @@
+"""Module extension for compatibility with previous Bazel versions"""
+
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
+
+def _compatibility_proxy_repo_impl(rctx):
+    # TODO: use @bazel_features
+    bazel = native.bazel_version
+    if not bazel or bazel >= "8":
+        rctx.file(
+            "BUILD.bazel",
+            """
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+exports_files(['proxy.bzl'], visibility = ["@rules_java//test:__pkg__"])
+bzl_library(
+    name = "proxy_bzl",
+    srcs = ["proxy.bzl"],
+    deps = [
+        "@rules_java//java/bazel/rules",
+        "@rules_java//java/common/rules:toolchain_rules",
+        "@rules_java//java/private:internals",
+        "@rules_java//java/bazel:http_jar_bzl",
+    ],
+    visibility = ["//visibility:public"]
+)
+            """,
+        )
+        rctx.file(
+            "proxy.bzl",
+            """
+load("@rules_java//java/bazel/rules:bazel_java_binary_wrapper.bzl", _java_binary = "java_binary")
+load("@rules_java//java/bazel/rules:bazel_java_import.bzl", _java_import = "java_import")
+load("@rules_java//java/bazel/rules:bazel_java_library.bzl", _java_library = "java_library")
+load("@rules_java//java/bazel/rules:bazel_java_plugin.bzl", _java_plugin = "java_plugin")
+load("@rules_java//java/bazel/rules:bazel_java_test.bzl", _java_test = "java_test")
+load("@rules_java//java/bazel:http_jar.bzl", _http_jar = "http_jar")
+load("@rules_java//java/common/rules:java_package_configuration.bzl", _java_package_configuration = "java_package_configuration")
+load("@rules_java//java/common/rules:java_runtime.bzl", _java_runtime = "java_runtime")
+load("@rules_java//java/common/rules:java_toolchain.bzl", _java_toolchain = "java_toolchain")
+load("@rules_java//java/private:java_common.bzl", _java_common = "java_common")
+load("@rules_java//java/private:java_common_internal.bzl", _java_common_internal_compile = "compile")
+load("@rules_java//java/private:java_info.bzl", _JavaInfo = "JavaInfo", _JavaPluginInfo = "JavaPluginInfo", _java_info_internal_merge = "merge")
+
+java_binary = _java_binary
+java_import = _java_import
+java_library = _java_library
+java_plugin = _java_plugin
+java_test = _java_test
+java_package_configuration = _java_package_configuration
+java_runtime = _java_runtime
+java_toolchain = _java_toolchain
+java_common = _java_common
+JavaInfo = _JavaInfo
+JavaPluginInfo = _JavaPluginInfo
+java_common_internal_compile = _java_common_internal_compile
+java_info_internal_merge = _java_info_internal_merge
+http_jar = _http_jar
+            """,
+        )
+    else:
+        rctx.file(
+            "BUILD.bazel",
+            """
+load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+exports_files(['proxy.bzl'], visibility = ["@rules_java//test:__pkg__"])
+bzl_library(
+    name = "proxy_bzl",
+    srcs = ["proxy.bzl"],
+    deps = [
+        "@rules_java//java/private:native_bzl",
+        "@bazel_tools//tools:bzl_srcs",
+    ],
+    visibility = ["//visibility:public"]
+)
+            """,
+        )
+        rctx.file(
+            "proxy.bzl",
+            """
+load("@bazel_tools//tools/build_defs/repo:http.bzl", _http_jar = "http_jar")
+load("@rules_java//java/private:native.bzl", "native_java_common", "NativeJavaInfo", "NativeJavaPluginInfo")
+
+java_binary = native.java_binary
+java_import = native.java_import
+java_library = native.java_library
+java_plugin = native.java_plugin
+java_test = native.java_test
+
+java_package_configuration = native.java_package_configuration
+java_runtime = native.java_runtime
+java_toolchain = native.java_toolchain
+
+java_common = native_java_common
+JavaInfo = NativeJavaInfo
+JavaPluginInfo = NativeJavaPluginInfo
+java_common_internal_compile = None
+java_info_internal_merge = None
+
+http_jar = _http_jar
+            """,
+        )
+
+_compatibility_proxy_repo_rule = repository_rule(
+    _compatibility_proxy_repo_impl,
+    # force reruns on server restarts to use correct native.bazel_version
+    local = True,
+)
+
+def compatibility_proxy_repo():
+    maybe(_compatibility_proxy_repo_rule, name = "compatibility_proxy")
+
+def _compat_proxy_impl(_unused):
+    compatibility_proxy_repo()
+
+compatibility_proxy = module_extension(_compat_proxy_impl)
+
+def protobuf_repo():
+    maybe(
+        http_archive,
+        name = "com_google_protobuf",
+        sha256 = "ce5d00b78450a0ca400bf360ac00c0d599cc225f049d986a27e9a4e396c5a84a",
+        strip_prefix = "protobuf-29.0-rc2",
+        url = "https://github.com/protocolbuffers/protobuf/releases/download/v29.0-rc2/protobuf-29.0-rc2.tar.gz",
+    )
+
+def rules_cc_repo():
+    maybe(
+        http_archive,
+        name = "rules_cc",
+        sha256 = "f4aadd8387f381033a9ad0500443a52a0cea5f8ad1ede4369d3c614eb7b2682e",
+        strip_prefix = "rules_cc-0.0.15",
+        urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.15/rules_cc-0.0.15.tar.gz"],
+    )
+
+def bazel_skylib_repo():
+    maybe(
+        http_archive,
+        name = "bazel_skylib",
+        sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
+        urls = [
+            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
+            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
+        ],
+    )
+
+def rules_java_dependencies():
+    """An utility method to load non-toolchain dependencies of rules_java.
+
+    Loads the remote repositories used by default in Bazel.
+    """
+    compatibility_proxy_repo()
+    bazel_skylib_repo()
+    rules_cc_repo()
+    protobuf_repo()
diff --git a/java/runfiles/BUILD b/java/runfiles/BUILD
new file mode 100644
index 0000000..05a8104
--- /dev/null
+++ b/java/runfiles/BUILD
@@ -0,0 +1,13 @@
+alias(
+    name = "runfiles",
+    actual = "//java/runfiles/src/main/java/com/google/devtools/build/runfiles",
+    visibility = ["//visibility:public"],
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]) + [
+        "//java/runfiles/src/main/java/com/google/devtools/build/runfiles:srcs",
+    ],
+    visibility = ["//java:__pkg__"],
+)
diff --git a/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepository.java b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepository.java
new file mode 100644
index 0000000..6dc5330
--- /dev/null
+++ b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepository.java
@@ -0,0 +1,29 @@
+// Copyright 2022 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Annotating a class {@code Fooer} with this annotation generates a class {@code
+ * AutoBazelRepository_Fooer} defining a {@link String} constant {@code NAME} containing the
+ * canonical name of the repository containing the Bazel target that compiled the annotated class.
+ */
+@Retention(RetentionPolicy.SOURCE)
+@Target(ElementType.TYPE)
+public @interface AutoBazelRepository {}
diff --git a/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepositoryProcessor.java b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepositoryProcessor.java
new file mode 100644
index 0000000..2b0ce9d
--- /dev/null
+++ b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/AutoBazelRepositoryProcessor.java
@@ -0,0 +1,121 @@
+// Copyright 2022 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+import java.io.IOException;
+import java.io.PrintWriter;
+import java.util.ArrayDeque;
+import java.util.Deque;
+import java.util.Set;
+import javax.annotation.processing.AbstractProcessor;
+import javax.annotation.processing.RoundEnvironment;
+import javax.annotation.processing.SupportedAnnotationTypes;
+import javax.annotation.processing.SupportedOptions;
+import javax.lang.model.SourceVersion;
+import javax.lang.model.element.Element;
+import javax.lang.model.element.TypeElement;
+import javax.tools.Diagnostic.Kind;
+
+/** Processor for {@link AutoBazelRepository}. */
+@SupportedAnnotationTypes("com.google.devtools.build.runfiles.AutoBazelRepository")
+@SupportedOptions(AutoBazelRepositoryProcessor.BAZEL_REPOSITORY_OPTION)
+public final class AutoBazelRepositoryProcessor extends AbstractProcessor {
+
+  static final String BAZEL_REPOSITORY_OPTION = "bazel.repository";
+
+  @Override
+  public SourceVersion getSupportedSourceVersion() {
+    return SourceVersion.latestSupported();
+  }
+
+  @Override
+  public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+    annotations.stream()
+        .flatMap(element -> roundEnv.getElementsAnnotatedWith(element).stream())
+        .map(element -> (TypeElement) element)
+        .forEach(this::emitClass);
+    return false;
+  }
+
+  private void emitClass(TypeElement annotatedClass) {
+    // This option is always provided by the Java rule implementations.
+    if (!processingEnv.getOptions().containsKey(BAZEL_REPOSITORY_OPTION)) {
+      processingEnv
+          .getMessager()
+          .printMessage(
+              Kind.ERROR,
+              String.format(
+                  "The %1$s annotation processor option is not set. To use this annotation"
+                      + " processor, provide the canonical repository name of the current target as"
+                      + " the value of the -A%1$s flag.",
+                  BAZEL_REPOSITORY_OPTION),
+              annotatedClass);
+      return;
+    }
+    String repositoryName = processingEnv.getOptions().get(BAZEL_REPOSITORY_OPTION);
+    if (repositoryName == null) {
+      // javac translates '-Abazel.repository=' into a null value.
+      // https://github.com/openjdk/jdk/blob/7a49c9baa1d4ad7df90e7ca626ec48ba76881822/src/jdk.compiler/share/classes/com/sun/tools/javac/processing/JavacProcessingEnvironment.java#L651
+      repositoryName = "";
+    }
+
+    // For a nested class Outer.Middle.Inner, generate a class with simple name
+    // AutoBazelRepository_Outer_Middle_Inner.
+    // Note: There can be collisions when local classes are involved, but since the definition of a
+    // class depends only on the containing Bazel target, this does not result in ambiguity.
+    Deque<String> classNameSegments = new ArrayDeque<>();
+    Element element = annotatedClass;
+    while (element instanceof TypeElement) {
+      classNameSegments.addFirst(element.getSimpleName().toString());
+      element = element.getEnclosingElement();
+    }
+    classNameSegments.addFirst("AutoBazelRepository");
+    String generatedClassSimpleName = String.join("_", classNameSegments);
+
+    String generatedClassPackage =
+        processingEnv.getElementUtils().getPackageOf(annotatedClass).getQualifiedName().toString();
+
+    String generatedClassName =
+        generatedClassPackage.isEmpty()
+            ? generatedClassSimpleName
+            : generatedClassPackage + "." + generatedClassSimpleName;
+
+    try (PrintWriter out =
+        new PrintWriter(
+            processingEnv.getFiler().createSourceFile(generatedClassName).openWriter())) {
+      if (!generatedClassPackage.isEmpty()) {
+        // This annotation may exist on a class which is at the root package
+        out.printf("package %s;\n", generatedClassPackage);
+      }
+      out.printf("\n");
+      out.printf("class %s {\n", generatedClassSimpleName);
+      out.printf("  /**\n");
+      out.printf("   * The canonical name of the repository containing the Bazel target that\n");
+      out.printf("   * compiled {@link %s}.\n", annotatedClass.getQualifiedName().toString());
+      out.printf("   */\n");
+      out.printf("  static final String NAME = \"%s\";\n", repositoryName);
+      out.printf("\n");
+      out.printf("  private %s() {}\n", generatedClassSimpleName);
+      out.printf("}\n");
+    } catch (IOException e) {
+      processingEnv
+          .getMessager()
+          .printMessage(
+              Kind.ERROR,
+              String.format("Failed to generate %s: %s", generatedClassName, e.getMessage()),
+              annotatedClass);
+    }
+  }
+}
diff --git a/java/runfiles/src/main/java/com/google/devtools/build/runfiles/BUILD b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/BUILD
new file mode 100644
index 0000000..ee1bd83
--- /dev/null
+++ b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/BUILD
@@ -0,0 +1,29 @@
+load("//java:defs.bzl", "java_library", "java_plugin")
+
+java_library(
+    name = "runfiles",
+    srcs = [
+        "Runfiles.java",
+        "Util.java",
+    ],
+    exported_plugins = [":auto_bazel_repository_processor"],
+    visibility = ["//java/runfiles:__pkg__"],
+    exports = [":auto_bazel_repository"],
+)
+
+java_library(
+    name = "auto_bazel_repository",
+    srcs = ["AutoBazelRepository.java"],
+)
+
+java_plugin(
+    name = "auto_bazel_repository_processor",
+    srcs = ["AutoBazelRepositoryProcessor.java"],
+    processor_class = "com.google.devtools.build.runfiles.AutoBazelRepositoryProcessor",
+)
+
+filegroup(
+    name = "srcs",
+    srcs = glob(["**"]),
+    visibility = ["//java/runfiles:__pkg__"],
+)
diff --git a/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Runfiles.java b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Runfiles.java
new file mode 100644
index 0000000..bec2091
--- /dev/null
+++ b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Runfiles.java
@@ -0,0 +1,582 @@
+// Copyright 2018 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+import java.io.BufferedReader;
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.IOException;
+import java.io.InputStreamReader;
+import java.lang.ref.SoftReference;
+import java.nio.charset.StandardCharsets;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Objects;
+import java.util.stream.Collectors;
+
+/**
+ * Runfiles lookup library for Bazel-built Java binaries and tests.
+ *
+ * <p>USAGE:
+ *
+ * <p>1. Depend on this runfiles library from your build rule:
+ *
+ * <pre>
+ *   java_binary(
+ *       name = "my_binary",
+ *       ...
+ *       deps = ["@rules_java//java/runfiles"],
+ *   )
+ * </pre>
+ *
+ * <p>2. Import the runfiles library.
+ *
+ * <pre>
+ *   import com.google.devtools.build.runfiles.Runfiles;
+ * </pre>
+ *
+ * <p>3. Create a {@link Runfiles.Preloaded} object:
+ *
+ * <pre>
+ *   public void myFunction() {
+ *     Runfiles.Preloaded runfiles = Runfiles.preload();
+ *     ...
+ * </pre>
+ *
+ * <p>4. To look up a runfile, use either of the following approaches:
+ *
+ * <p>4a. Annotate the class from which runfiles should be looked up with {@link
+ * AutoBazelRepository} and obtain the name of the Bazel repository containing the class from a
+ * constant generated by this annotation:
+ *
+ * <pre>
+ *   import com.google.devtools.build.runfiles.AutoBazelRepository;
+ *   &#64;AutoBazelRepository
+ *   public class MyClass {
+ *     public void myFunction() {
+ *       Runfiles.Preloaded runfiles = Runfiles.preload();
+ *       String path = runfiles.withSourceRepository(AutoBazelRepository_MyClass.NAME)
+ *                             .rlocation("my_workspace/path/to/my/data.txt");
+ *       ...
+ *
+ * </pre>
+ *
+ * <p>4b. Let Bazel compute the path passed to rlocation and pass it into a <code>java_binary</code>
+ * via an argument or an environment variable:
+ *
+ * <pre>
+ *   java_binary(
+ *       name = "my_binary",
+ *       srcs = ["MyClass.java"],
+ *       data = ["@my_workspace//path/to/my:data.txt"],
+ *       env = {"MY_RUNFILE": "$(rlocationpath @my_workspace//path/to/my:data.txt)"},
+ *   )
+ * </pre>
+ *
+ * <pre>
+ *   public class MyClass {
+ *     public void myFunction() {
+ *       Runfiles.Preloaded runfiles = Runfiles.preload();
+ *       String path = runfiles.unmapped().rlocation(System.getenv("MY_RUNFILE"));
+ *       ...
+ *
+ * </pre>
+ *
+ * For more details on why it is required to pass in the current repository name, see {@see
+ * https://bazel.build/build/bzlmod#repository-names}.
+ *
+ * <h3>Subprocesses</h3>
+ *
+ * <p>If you want to start subprocesses that also need runfiles, you need to set the right
+ * environment variables for them:
+ *
+ * <pre>
+ *   String path = r.rlocation("path/to/binary");
+ *   ProcessBuilder pb = new ProcessBuilder(path);
+ *   pb.environment().putAll(r.getEnvVars());
+ *   ...
+ *   Process p = pb.start();
+ * </pre>
+ *
+ * <h3>{@link Runfiles.Preloaded} vs. {@link Runfiles}</h3>
+ *
+ * <p>Instances of {@link Runfiles.Preloaded} are meant to be stored and passed around to other
+ * components that need to access runfiles. They are created by calling {@link Runfiles#preload()}
+ * {@link Runfiles#preload(java.util.Map)} and immutably encapsulate all data required to look up
+ * runfiles with the repository mapping of any Bazel repository specified at a later time.
+ *
+ * <p>Creating {@link Runfiles.Preloaded} instances can be costly, so applications should try to
+ * create as few instances as possible. {@link Runfiles#preload()}, but not {@link
+ * Runfiles#preload(java.util.Map)}, returns a single global, softly cached instance of {@link
+ * Runfiles.Preloaded} that is constructed based on the JVM's environment variables.
+ *
+ * <p>Instance of {@link Runfiles} are only meant to be used by code located in a single Bazel
+ * repository and should not be passed around. They are created by calling {@link
+ * Runfiles.Preloaded#withSourceRepository(String)} or {@link Runfiles.Preloaded#unmapped()} and in
+ * addition to the data in {@link Runfiles.Preloaded} also fix a source repository relative to which
+ * apparent repository names are resolved.
+ *
+ * <p>Creating {@link Runfiles.Preloaded} instances is cheap.
+ */
+public final class Runfiles {
+
+  /**
+   * A class that encapsulates all data required to look up runfiles relative to any Bazel
+   * repository fixed at a later time.
+   *
+   * <p>This class is immutable.
+   */
+  public abstract static class Preloaded {
+
+    /** See {@link com.google.devtools.build.lib.analysis.RepoMappingManifestAction.Entry}. */
+    static class RepoMappingKey {
+
+      public final String sourceRepo;
+      public final String targetRepoApparentName;
+
+      public RepoMappingKey(String sourceRepo, String targetRepoApparentName) {
+        this.sourceRepo = sourceRepo;
+        this.targetRepoApparentName = targetRepoApparentName;
+      }
+
+      @Override
+      public boolean equals(Object o) {
+        if (this == o) {
+          return true;
+        }
+        if (o == null || !(o instanceof RepoMappingKey)) {
+          return false;
+        }
+        RepoMappingKey that = (RepoMappingKey) o;
+        return sourceRepo.equals(that.sourceRepo)
+            && targetRepoApparentName.equals(that.targetRepoApparentName);
+      }
+
+      @Override
+      public int hashCode() {
+        return Objects.hash(sourceRepo, targetRepoApparentName);
+      }
+    }
+
+    /**
+     * Returns a {@link Runfiles} instance that uses the provided source repository's repository
+     * mapping to translate apparent into canonical repository names.
+     *
+     * <p>{@see https://bazel.build/build/bzlmod#repository-names}
+     *
+     * @param sourceRepository the canonical name of the Bazel repository relative to which apparent
+     *     repository names should be resolved. Should generally coincide with the Bazel repository
+     *     that contains the caller of this method, which can be obtained via {@link
+     *     AutoBazelRepository}.
+     * @return a {@link Runfiles} instance that looks up runfiles relative to the provided source
+     *     repository and shares all other data with this {@link Runfiles.Preloaded} instance.
+     */
+    public final Runfiles withSourceRepository(String sourceRepository) {
+      Util.checkArgument(sourceRepository != null);
+      return new Runfiles(this, sourceRepository);
+    }
+
+    /**
+     * Returns a {@link Runfiles} instance backed by the preloaded runfiles data that can be used to
+     * look up runfiles paths with canonical repository names only.
+     *
+     * @return a {@link Runfiles} instance that can only look up paths with canonical repository
+     *     names and shared all data with this {@link Runfiles.Preloaded} instance.
+     */
+    public final Runfiles unmapped() {
+      return new Runfiles(this, null);
+    }
+
+    protected abstract Map<String, String> getEnvVars();
+
+    protected abstract String rlocationChecked(String path);
+
+    protected abstract Map<RepoMappingKey, String> getRepoMapping();
+
+    // Private constructor, so only nested classes may extend it.
+    private Preloaded() {}
+  }
+
+  private static final String MAIN_REPOSITORY = "";
+
+  private static SoftReference<Preloaded> defaultInstance = new SoftReference<>(null);
+
+  private final Preloaded preloadedRunfiles;
+  private final String sourceRepository;
+
+  private Runfiles(Preloaded preloadedRunfiles, String sourceRepository) {
+    this.preloadedRunfiles = preloadedRunfiles;
+    this.sourceRepository = sourceRepository;
+  }
+
+  /**
+   * Returns the softly cached global {@link Runfiles.Preloaded} instance, creating it if needed.
+   *
+   * <p>This method passes the JVM's environment variable map to {@link #create(java.util.Map)}.
+   */
+  public static synchronized Preloaded preload() throws IOException {
+    Preloaded instance = defaultInstance.get();
+    if (instance != null) {
+      return instance;
+    }
+    instance = preload(System.getenv());
+    defaultInstance = new SoftReference<>(instance);
+    return instance;
+  }
+
+  /**
+   * Returns a new {@link Runfiles.Preloaded} instance.
+   *
+   * <p>The returned object is either:
+   *
+   * <ul>
+   *   <li>manifest-based, meaning it looks up runfile paths from a manifest file, or
+   *   <li>directory-based, meaning it looks up runfile paths under a given directory path
+   * </ul>
+   *
+   * <p>If {@code env} contains "RUNFILES_MANIFEST_ONLY" with value "1", this method returns a
+   * manifest-based implementation. The manifest's path is defined by the "RUNFILES_MANIFEST_FILE"
+   * key's value in {@code env}.
+   *
+   * <p>Otherwise this method returns a directory-based implementation. The directory's path is
+   * defined by the value in {@code env} under the "RUNFILES_DIR" key, or if absent, then under the
+   * "JAVA_RUNFILES" key.
+   *
+   * <p>Note about performance: the manifest-based implementation eagerly reads and caches the whole
+   * manifest file upon instantiation.
+   *
+   * @throws java.io.IOException if RUNFILES_MANIFEST_ONLY=1 is in {@code env} but there's no
+   *     "RUNFILES_MANIFEST_FILE", "RUNFILES_DIR", or "JAVA_RUNFILES" key in {@code env} or their
+   *     values are empty, or some IO error occurs
+   */
+  public static Preloaded preload(Map<String, String> env) throws IOException {
+    if (isManifestOnly(env)) {
+      // On Windows, Bazel sets RUNFILES_MANIFEST_ONLY=1.
+      // On every platform, Bazel also sets RUNFILES_MANIFEST_FILE, but on Linux and macOS it's
+      // faster to use RUNFILES_DIR.
+      return new ManifestBased(getManifestPath(env));
+    } else {
+      return new DirectoryBased(getRunfilesDir(env));
+    }
+  }
+
+  /**
+   * Returns a new {@link Runfiles} instance.
+   *
+   * <p>This method passes the JVM's environment variable map to {@link #create(java.util.Map)}.
+   *
+   * @deprecated Use {@link #preload()} instead. With {@code --enable_bzlmod}, this function does
+   *     not work correctly.
+   */
+  @Deprecated
+  public static Runfiles create() throws IOException {
+    return preload().withSourceRepository(MAIN_REPOSITORY);
+  }
+
+  /**
+   * Returns a new {@link Runfiles} instance.
+   *
+   * <p>The returned object is either:
+   *
+   * <ul>
+   *   <li>manifest-based, meaning it looks up runfile paths from a manifest file, or
+   *   <li>directory-based, meaning it looks up runfile paths under a given directory path
+   * </ul>
+   *
+   * <p>If {@code env} contains "RUNFILES_MANIFEST_ONLY" with value "1", this method returns a
+   * manifest-based implementation. The manifest's path is defined by the "RUNFILES_MANIFEST_FILE"
+   * key's value in {@code env}.
+   *
+   * <p>Otherwise this method returns a directory-based implementation. The directory's path is
+   * defined by the value in {@code env} under the "RUNFILES_DIR" key, or if absent, then under the
+   * "JAVA_RUNFILES" key.
+   *
+   * <p>Note about performance: the manifest-based implementation eagerly reads and caches the whole
+   * manifest file upon instantiation.
+   *
+   * @throws IOException if RUNFILES_MANIFEST_ONLY=1 is in {@code env} but there's no
+   *     "RUNFILES_MANIFEST_FILE", "RUNFILES_DIR", or "JAVA_RUNFILES" key in {@code env} or their
+   *     values are empty, or some IO error occurs
+   * @deprecated Use {@link #preload(java.util.Map)} instead. With {@code --enable_bzlmod}, this
+   *     function does not work correctly.
+   */
+  @Deprecated
+  public static Runfiles create(Map<String, String> env) throws IOException {
+    return preload(env).withSourceRepository(MAIN_REPOSITORY);
+  }
+
+  /**
+   * Returns the runtime path of a runfile (a Bazel-built binary's/test's data-dependency).
+   *
+   * <p>The returned path may not be valid. The caller should check the path's validity and that the
+   * path exists.
+   *
+   * <p>The function may return null. In that case the caller can be sure that the rule does not
+   * know about this data-dependency.
+   *
+   * @param path runfiles-root-relative path of the runfile
+   * @throws IllegalArgumentException if {@code path} fails validation, for example if it's null or
+   *     empty, or not normalized (contains "./", "../", or "//")
+   */
+  public String rlocation(String path) {
+    Util.checkArgument(path != null);
+    Util.checkArgument(!path.isEmpty());
+    Util.checkArgument(
+        !path.startsWith("../")
+            && !path.contains("/..")
+            && !path.startsWith("./")
+            && !path.contains("/./")
+            && !path.endsWith("/.")
+            && !path.contains("//"),
+        "path is not normalized: \"%s\"",
+        path);
+    Util.checkArgument(
+        !path.startsWith("\\"), "path is absolute without a drive letter: \"%s\"", path);
+    if (new File(path).isAbsolute()) {
+      return path;
+    }
+
+    if (sourceRepository == null) {
+      return preloadedRunfiles.rlocationChecked(path);
+    }
+    String[] apparentTargetAndRemainder = path.split("/", 2);
+    if (apparentTargetAndRemainder.length < 2) {
+      return preloadedRunfiles.rlocationChecked(path);
+    }
+    String targetCanonical = getCanonicalRepositoryName(apparentTargetAndRemainder[0]);
+    return preloadedRunfiles.rlocationChecked(
+        targetCanonical + "/" + apparentTargetAndRemainder[1]);
+  }
+
+  /**
+   * Returns environment variables for subprocesses.
+   *
+   * <p>The caller should add the returned key-value pairs to the environment of subprocesses in
+   * case those subprocesses are also Bazel-built binaries that need to use runfiles.
+   */
+  public Map<String, String> getEnvVars() {
+    return preloadedRunfiles.getEnvVars();
+  }
+
+  String getCanonicalRepositoryName(String apparentRepositoryName) {
+    return preloadedRunfiles
+        .getRepoMapping()
+        .getOrDefault(
+            new Preloaded.RepoMappingKey(sourceRepository, apparentRepositoryName),
+            apparentRepositoryName);
+  }
+
+  /** Returns true if the platform supports runfiles only via manifests. */
+  private static boolean isManifestOnly(Map<String, String> env) {
+    return "1".equals(env.get("RUNFILES_MANIFEST_ONLY"));
+  }
+
+  private static String getManifestPath(Map<String, String> env) throws IOException {
+    String value = env.get("RUNFILES_MANIFEST_FILE");
+    if (Util.isNullOrEmpty(value)) {
+      throw new IOException(
+          "Cannot load runfiles manifest: $RUNFILES_MANIFEST_ONLY is 1 but"
+              + " $RUNFILES_MANIFEST_FILE is empty or undefined");
+    }
+    return value;
+  }
+
+  private static String getRunfilesDir(Map<String, String> env) throws IOException {
+    String value = env.get("RUNFILES_DIR");
+    if (Util.isNullOrEmpty(value)) {
+      value = env.get("JAVA_RUNFILES");
+    }
+    if (Util.isNullOrEmpty(value)) {
+      throw new IOException(
+          "Cannot find runfiles: $RUNFILES_DIR and $JAVA_RUNFILES are both unset or empty");
+    }
+    return value;
+  }
+
+  private static Map<Preloaded.RepoMappingKey, String> loadRepositoryMapping(String path)
+      throws IOException {
+    if (path == null || !new File(path).exists()) {
+      return Collections.emptyMap();
+    }
+
+    try (BufferedReader r =
+        new BufferedReader(
+            new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
+      return Collections.unmodifiableMap(
+          r.lines()
+              .filter(line -> !line.isEmpty())
+              .map(
+                  line -> {
+                    String[] split = line.split(",");
+                    if (split.length != 3) {
+                      throw new IllegalArgumentException(
+                          "Invalid line in repository mapping: '" + line + "'");
+                    }
+                    return split;
+                  })
+              .collect(
+                  Collectors.toMap(
+                      split -> new Preloaded.RepoMappingKey(split[0], split[1]),
+                      split -> split[2])));
+    }
+  }
+
+  /** {@link Runfiles} implementation that parses a runfiles-manifest file to look up runfiles. */
+  private static final class ManifestBased extends Preloaded {
+
+    private final Map<String, String> runfiles;
+    private final String manifestPath;
+    private final Map<RepoMappingKey, String> repoMapping;
+
+    ManifestBased(String manifestPath) throws IOException {
+      Util.checkArgument(manifestPath != null);
+      Util.checkArgument(!manifestPath.isEmpty());
+      this.manifestPath = manifestPath;
+      this.runfiles = loadRunfiles(manifestPath);
+      this.repoMapping = loadRepositoryMapping(rlocationChecked("_repo_mapping"));
+    }
+
+    @Override
+    protected String rlocationChecked(String path) {
+      String exactMatch = runfiles.get(path);
+      if (exactMatch != null) {
+        return exactMatch;
+      }
+      // If path references a runfile that lies under a directory that itself is a runfile, then
+      // only the directory is listed in the manifest. Look up all prefixes of path in the manifest
+      // and append the relative path from the prefix if there is a match.
+      int prefixEnd = path.length();
+      while ((prefixEnd = path.lastIndexOf('/', prefixEnd - 1)) != -1) {
+        String prefixMatch = runfiles.get(path.substring(0, prefixEnd));
+        if (prefixMatch != null) {
+          return prefixMatch + '/' + path.substring(prefixEnd + 1);
+        }
+      }
+      return null;
+    }
+
+    @Override
+    protected Map<String, String> getEnvVars() {
+      HashMap<String, String> result = new HashMap<>(4);
+      result.put("RUNFILES_MANIFEST_ONLY", "1");
+      result.put("RUNFILES_MANIFEST_FILE", manifestPath);
+      String runfilesDir = findRunfilesDir(manifestPath);
+      result.put("RUNFILES_DIR", runfilesDir);
+      // TODO(laszlocsomor): remove JAVA_RUNFILES once the Java launcher can pick up RUNFILES_DIR.
+      result.put("JAVA_RUNFILES", runfilesDir);
+      return result;
+    }
+
+    @Override
+    protected Map<RepoMappingKey, String> getRepoMapping() {
+      return repoMapping;
+    }
+
+    private static Map<String, String> loadRunfiles(String path) throws IOException {
+      HashMap<String, String> result = new HashMap<>();
+      try (BufferedReader r =
+          new BufferedReader(
+              new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
+        String line;
+        while ((line = r.readLine()) != null) {
+          String runfile;
+          String realPath;
+          if (line.startsWith(" ")) {
+            // In lines starting with a space, the runfile path contains spaces and backslashes
+            // escaped with a backslash. The real path is the rest of the line after the first
+            // unescaped space.
+            int firstSpace = line.indexOf(' ', 1);
+            if (firstSpace == -1) {
+              throw new IOException(
+                  "Invalid runfiles manifest line, expected at least one space after the leading"
+                      + " space: "
+                      + line);
+            }
+            runfile =
+                line.substring(1, firstSpace)
+                    .replace("\\s", " ")
+                    .replace("\\n", "\n")
+                    .replace("\\b", "\\");
+            realPath = line.substring(firstSpace + 1).replace("\\n", "\n").replace("\\b", "\\");
+          } else {
+            int firstSpace = line.indexOf(' ');
+            if (firstSpace == -1) {
+              throw new IOException(
+                  "Invalid runfiles manifest line, expected at least one space: " + line);
+            }
+            runfile = line.substring(0, firstSpace);
+            realPath = line.substring(firstSpace + 1);
+          }
+          result.put(runfile, realPath);
+        }
+      }
+      return Collections.unmodifiableMap(result);
+    }
+
+    private static String findRunfilesDir(String manifest) {
+      if (manifest.endsWith("/MANIFEST")
+          || manifest.endsWith("\\MANIFEST")
+          || manifest.endsWith(".runfiles_manifest")) {
+        String path = manifest.substring(0, manifest.length() - 9);
+        if (new File(path).isDirectory()) {
+          return path;
+        }
+      }
+      return "";
+    }
+  }
+
+  /** {@link Runfiles} implementation that appends runfiles paths to the runfiles root. */
+  private static final class DirectoryBased extends Preloaded {
+
+    private final String runfilesRoot;
+    private final Map<RepoMappingKey, String> repoMapping;
+
+    DirectoryBased(String runfilesDir) throws IOException {
+      Util.checkArgument(!Util.isNullOrEmpty(runfilesDir));
+      Util.checkArgument(new File(runfilesDir).isDirectory());
+      this.runfilesRoot = runfilesDir;
+      this.repoMapping = loadRepositoryMapping(rlocationChecked("_repo_mapping"));
+    }
+
+    @Override
+    protected String rlocationChecked(String path) {
+      return runfilesRoot + "/" + path;
+    }
+
+    @Override
+    protected Map<RepoMappingKey, String> getRepoMapping() {
+      return repoMapping;
+    }
+
+    @Override
+    protected Map<String, String> getEnvVars() {
+      HashMap<String, String> result = new HashMap<>(2);
+      result.put("RUNFILES_DIR", runfilesRoot);
+      // TODO(laszlocsomor): remove JAVA_RUNFILES once the Java launcher can pick up RUNFILES_DIR.
+      result.put("JAVA_RUNFILES", runfilesRoot);
+      return result;
+    }
+  }
+
+  static Preloaded createManifestBasedForTesting(String manifestPath) throws IOException {
+    return new ManifestBased(manifestPath);
+  }
+
+  static Preloaded createDirectoryBasedForTesting(String runfilesDir) throws IOException {
+    return new DirectoryBased(runfilesDir);
+  }
+}
diff --git a/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Util.java b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Util.java
new file mode 100644
index 0000000..73f0b98
--- /dev/null
+++ b/java/runfiles/src/main/java/com/google/devtools/build/runfiles/Util.java
@@ -0,0 +1,49 @@
+// Copyright 2018 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+/**
+ * Utilities for the other classes in this package.
+ *
+ * <p>These functions are implementations of some basic utilities in the Guava library. We
+ * reimplement these functions instead of depending on Guava, so that the Runfiles library has no
+ * third-party dependencies, thus any Java project can depend on it without the risk of pulling
+ * unwanted or conflicting dependencies (for example if the project already depends on Guava, or
+ * wishes not to depend on it at all).
+ */
+class Util {
+  private Util() {}
+
+  /** Returns true when {@code s} is null or an empty string. */
+  public static boolean isNullOrEmpty(String s) {
+    return s == null || s.isEmpty();
+  }
+
+  /** Throws an {@code IllegalArgumentException} if {@code condition} is false. */
+  public static void checkArgument(boolean condition) {
+    checkArgument(condition, null, null);
+  }
+
+  /** Throws an {@code IllegalArgumentException} if {@code condition} is false. */
+  public static void checkArgument(boolean condition, String error, Object arg1) {
+    if (!condition) {
+      if (isNullOrEmpty(error)) {
+        throw new IllegalArgumentException("argument validation failed");
+      } else {
+        throw new IllegalArgumentException(String.format(error, arg1));
+      }
+    }
+  }
+}
diff --git a/java/test/BUILD b/java/test/BUILD
new file mode 100644
index 0000000..8a52e41
--- /dev/null
+++ b/java/test/BUILD
@@ -0,0 +1,3 @@
+load(":merge_attrs_tests.bzl", "merge_attrs_test_suite")
+
+merge_attrs_test_suite(name = "merge_attrs_tests")
diff --git a/java/test/merge_attrs_tests.bzl b/java/test/merge_attrs_tests.bzl
new file mode 100644
index 0000000..84b340e
--- /dev/null
+++ b/java/test/merge_attrs_tests.bzl
@@ -0,0 +1,38 @@
+"""Tests for merge_attrsfunction"""
+
+load("@bazel_skylib//lib:unittest.bzl", "asserts", "unittest")
+load(
+    "//java/common/rules:rule_util.bzl",
+    "merge_attrs",
+)
+
+_attr_string = attr.string()
+_attr_string_different_ref = attr.string()
+_attr_string_different = attr.string(default = "Some default")
+
+def _merge_attrs_merges_impl(ctx):
+    env = unittest.begin(ctx)
+
+    attrs = merge_attrs(
+        {"A": _attr_string},
+        {"B": _attr_string_different_ref, "C": _attr_string_different},
+        override_attrs = {"B": _attr_string_different},
+        remove_attrs = ["C"],
+    )
+
+    asserts.equals(env, attrs, {"A": _attr_string, "B": _attr_string_different})
+
+    return unittest.end(env)
+
+merge_attrs_merges_test = unittest.make(_merge_attrs_merges_impl)
+
+def merge_attrs_test_suite(name):
+    """Sets up util test suite
+
+    Args:
+        name: the name of the test suite target
+    """
+    unittest.suite(
+        name,
+        merge_attrs_merges_test,
+    )
diff --git a/java/toolchains/BUILD b/java/toolchains/BUILD
index 894cf44..29a572a 100644
--- a/java/toolchains/BUILD
+++ b/java/toolchains/BUILD
@@ -14,7 +14,7 @@ bzl_library(
     name = "toolchain_rules",
     srcs = glob(["*.bzl"]),
     visibility = ["//visibility:public"],
-    deps = ["//java/private"],
+    deps = ["@compatibility_proxy//:proxy_bzl"],
 )
 
 filegroup(
diff --git a/java/toolchains/java_package_configuration.bzl b/java/toolchains/java_package_configuration.bzl
index 09d8e1e..7ef0728 100644
--- a/java/toolchains/java_package_configuration.bzl
+++ b/java/toolchains/java_package_configuration.bzl
@@ -13,6 +13,8 @@
 # limitations under the License.
 """java_package_configuration rule"""
 
+load("@compatibility_proxy//:proxy.bzl", _java_package_configuration = "java_package_configuration")
+
 def java_package_configuration(**attrs):
     """Bazel java_package_configuration rule.
 
@@ -22,5 +24,4 @@ def java_package_configuration(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_package_configuration(**attrs)
+    _java_package_configuration(**attrs)
diff --git a/java/toolchains/java_runtime.bzl b/java/toolchains/java_runtime.bzl
index 3657a88..c1d1641 100644
--- a/java/toolchains/java_runtime.bzl
+++ b/java/toolchains/java_runtime.bzl
@@ -13,6 +13,8 @@
 # limitations under the License.
 """java_runtime rule"""
 
+load("@compatibility_proxy//:proxy.bzl", _java_runtime = "java_runtime")
+
 def java_runtime(**attrs):
     """Bazel java_runtime rule.
 
@@ -22,5 +24,4 @@ def java_runtime(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_runtime(**attrs)
+    _java_runtime(**attrs)
diff --git a/java/toolchains/java_toolchain.bzl b/java/toolchains/java_toolchain.bzl
index 5b07292..5207f8c 100644
--- a/java/toolchains/java_toolchain.bzl
+++ b/java/toolchains/java_toolchain.bzl
@@ -13,6 +13,8 @@
 # limitations under the License.
 """java_toolchain rule"""
 
+load("@compatibility_proxy//:proxy.bzl", _java_toolchain = "java_toolchain")
+
 def java_toolchain(**attrs):
     """Bazel java_toolchain rule.
 
@@ -22,5 +24,4 @@ def java_toolchain(**attrs):
       **attrs: Rule attributes
     """
 
-    # buildifier: disable=native-java
-    native.java_toolchain(**attrs)
+    _java_toolchain(**attrs)
diff --git a/test/BUILD.bazel b/test/BUILD.bazel
new file mode 100644
index 0000000..c9dd65b
--- /dev/null
+++ b/test/BUILD.bazel
@@ -0,0 +1,68 @@
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
+load("@rules_shell//shell:sh_test.bzl", "sh_test")
+load("//java:repositories.bzl", "JAVA_TOOLS_CONFIG", "REMOTE_JDK_CONFIGS")
+load(":check_remotejdk_configs_match.bzl", "validate_configs")
+
+sh_test(
+    name = "check_remote_jdk_configs_test",
+    srcs = ["check_remote_jdk_configs.sh"],
+    args = [
+        ",".join([
+            config.name,
+            config.urls[0],
+            config.urls[1] if len(config.urls) > 1 else "",
+            config.sha256,
+            config.strip_prefix,
+        ])
+        for configs in REMOTE_JDK_CONFIGS.values()
+        for config in configs
+    ],
+)
+
+sh_test(
+    name = "check_remote_java_tools_configs_test",
+    srcs = ["check_remote_java_tools_configs.sh"],
+    args = [
+        ",".join([
+            name,
+            config["mirror_url"],
+            config["github_url"],
+            config["sha"],
+        ])
+        for name, config in JAVA_TOOLS_CONFIG["artifacts"].items()
+    ],
+)
+
+diff_test(
+    name = "docs_up_to_date_test",
+    failure_message = """
+    Docs are no longer up to date. Regenerate them by running:
+
+    bazel build //java/docs:rules_docs && \
+    cp bazel-bin/java/docs/rules_docs.out java/docs/rules.md
+    """,
+    file1 = "//java/docs:rules.md",
+    file2 = "//java/docs:rules_docs",
+)
+
+validate_configs()
+
+starlark_doc_extract(
+    name = "proxy_bzl_graph",
+    src = "@compatibility_proxy//:proxy.bzl",
+    deps = ["@compatibility_proxy//:proxy_bzl"],
+)
diff --git a/test/analysis/BUILD.bazel b/test/analysis/BUILD.bazel
new file mode 100644
index 0000000..754e1dd
--- /dev/null
+++ b/test/analysis/BUILD.bazel
@@ -0,0 +1,5 @@
+load(":bootclasspath_tests.bzl", "bootclasspath_tests")
+
+bootclasspath_tests(
+    name = "bootclasspath_tests",
+)
diff --git a/test/analysis/bootclasspath_tests.bzl b/test/analysis/bootclasspath_tests.bzl
new file mode 100644
index 0000000..5eb436a
--- /dev/null
+++ b/test/analysis/bootclasspath_tests.bzl
@@ -0,0 +1,77 @@
+"""Tests for the bootclasspath rule."""
+
+load("@rules_testing//lib:analysis_test.bzl", "analysis_test", "test_suite")
+load("@rules_testing//lib:truth.bzl", "subjects")
+load("//java/common:java_common.bzl", "java_common")
+
+def _test_utf_8_environment(name):
+    analysis_test(
+        name = name,
+        impl = _test_utf_8_environment_impl,
+        target = Label("//toolchains:platformclasspath"),
+    )
+
+def _test_utf_8_environment_impl(env, target):
+    for action in target.actions:
+        env_subject = env.expect.where(action = action).that_dict(action.env)
+        env_subject.keys().contains("LC_CTYPE")
+        env_subject.get("LC_CTYPE", factory = subjects.str).contains("UTF-8")
+
+def _test_incompatible_language_version_bootclasspath_disabled(name):
+    analysis_test(
+        name = name,
+        impl = _test_incompatible_language_version_bootclasspath_disabled_impl,
+        target = Label("//toolchains:platformclasspath"),
+        config_settings = {
+            "//command_line_option:java_language_version": "11",
+            "//command_line_option:java_runtime_version": "remotejdk_17",
+            str(Label("//toolchains:incompatible_language_version_bootclasspath")): False,
+        },
+    )
+
+def _test_incompatible_language_version_bootclasspath_disabled_impl(env, target):
+    system_path = target[java_common.BootClassPathInfo]._system_path
+    env.expect.that_str(system_path).contains("remotejdk17_")
+
+def _test_incompatible_language_version_bootclasspath_enabled_versioned(name):
+    analysis_test(
+        name = name,
+        impl = _test_incompatible_language_version_bootclasspath_enabled_versioned_impl,
+        target = Label("//toolchains:platformclasspath"),
+        config_settings = {
+            "//command_line_option:java_language_version": "11",
+            "//command_line_option:java_runtime_version": "remotejdk_17",
+            str(Label("//toolchains:incompatible_language_version_bootclasspath")): True,
+        },
+    )
+
+def _test_incompatible_language_version_bootclasspath_enabled_versioned_impl(env, target):
+    system_path = target[java_common.BootClassPathInfo]._system_path
+    env.expect.that_str(system_path).contains("remotejdk11_")
+
+def _test_incompatible_language_version_bootclasspath_enabled_unversioned(name):
+    analysis_test(
+        name = name,
+        impl = _test_incompatible_language_version_bootclasspath_enabled_unversioned_impl,
+        target = Label("//toolchains:platformclasspath"),
+        config_settings = {
+            "//command_line_option:java_language_version": "11",
+            "//command_line_option:java_runtime_version": "local_jdk",
+            str(Label("//toolchains:incompatible_language_version_bootclasspath")): True,
+        },
+    )
+
+def _test_incompatible_language_version_bootclasspath_enabled_unversioned_impl(env, target):
+    system_path = target[java_common.BootClassPathInfo]._system_path
+    env.expect.that_str(system_path).contains("local_jdk")
+
+def bootclasspath_tests(name):
+    test_suite(
+        name = name,
+        tests = [
+            _test_utf_8_environment,
+            _test_incompatible_language_version_bootclasspath_disabled,
+            _test_incompatible_language_version_bootclasspath_enabled_versioned,
+            _test_incompatible_language_version_bootclasspath_enabled_unversioned,
+        ],
+    )
diff --git a/test/check_remote_java_tools_configs.sh b/test/check_remote_java_tools_configs.sh
new file mode 100755
index 0000000..7e69dc0
--- /dev/null
+++ b/test/check_remote_java_tools_configs.sh
@@ -0,0 +1,36 @@
+#!/usr/bin/env bash
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
+echo "Checking hashes for $# configs"
+
+function download_and_check_hash() {
+    name=$1
+    url=$2
+    hash=$3
+    TMP_FILE=$(mktemp -q /tmp/remotejavatools.XXXXXX)
+    echo "fetching $name from $url to ${TMP_FILE}"
+    curl --silent -o ${TMP_FILE} -L "$url"
+    actual_hash=`sha256sum ${TMP_FILE} | cut -d' ' -f1`
+    if [ "${hash}" != "${actual_hash}" ]; then
+      echo "ERROR: wrong hash for ${name}! wanted: ${hash}, got: ${actual_hash}"
+      exit 1
+    fi
+}
+
+for config in "$@"; do
+    IFS=, read -r name mirror_url gh_url hash <<< "${config}"
+    download_and_check_hash ${name} ${mirror_url} ${hash}
+    download_and_check_hash ${name} ${gh_url} ${hash}
+done
\ No newline at end of file
diff --git a/test/check_remote_jdk_configs.sh b/test/check_remote_jdk_configs.sh
new file mode 100755
index 0000000..1b58c96
--- /dev/null
+++ b/test/check_remote_jdk_configs.sh
@@ -0,0 +1,53 @@
+#!/usr/bin/env bash
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
+echo "Checking hashes and strip_prefix for $# configs"
+
+_MISSING_MIRRORS=()
+for config in "$@"; do
+    TMP_FILE=$(mktemp -q /tmp/remotejdk.XXXXXX)
+    IFS=, read -r name url mirror_url hash strip_prefix <<< "${config}"
+    echo "fetching $name from $url to ${TMP_FILE}"
+    curl --silent -o ${TMP_FILE} -L "$url"
+    actual_hash=$(sha256sum ${TMP_FILE} | cut -d' ' -f1)
+    if [ "${hash}" != "${actual_hash}" ]; then
+      echo "ERROR: wrong hash for ${name}! wanted: ${hash}, got: ${actual_hash}"
+      exit 1
+    fi
+    if [[ -z "${url##*.tar.gz}" ]]; then
+      root_dir=$(tar ztf ${TMP_FILE} --exclude='*/*')
+    elif [[ -z "${url##*.zip}" ]]; then
+      root_dir=$(unzip -Z1 ${TMP_FILE} | head -n1)
+    else
+      echo "ERROR: unexpected archive type for ${name}"
+      exit 1
+    fi
+    if [ "${root_dir}" != "${strip_prefix}/" ]; then
+      echo "ERROR: bad strip_prefix for ${name}, wanted: ${strip_prefix}/, got: ${root_dir}"
+      exit 1
+    fi
+    if [[ -n "${mirror_url}" ]]; then
+      echo "checking mirror: ${mirror_url}"
+      curl --silent --fail -I -L ${mirror_url} > /dev/null || { _MISSING_MIRRORS+=("${mirror_url}"); }
+    fi
+done
+
+if [[ ${#_MISSING_MIRRORS[@]} -gt 0 ]]; then
+  echo "Missing mirror URLs:"
+  for m in "${_MISSING_MIRRORS[@]}"; do
+    echo "  ${m}"
+  done
+  exit 1
+fi
\ No newline at end of file
diff --git a/test/check_remotejdk_configs_match.bzl b/test/check_remotejdk_configs_match.bzl
new file mode 100644
index 0000000..5060cda
--- /dev/null
+++ b/test/check_remotejdk_configs_match.bzl
@@ -0,0 +1,27 @@
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
+"""Checks for keeping repository_util.bzl and repositories.bzl in sync"""
+
+load("//java:repositories.bzl", "REMOTE_JDK_CONFIGS")
+load("//java/bazel:repositories_util.bzl", "FLAT_CONFIGS")
+
+def validate_configs():
+    """Ensures repository_util.bzl and repositories.bzl are in sync"""
+    for expected in FLAT_CONFIGS:
+        actual = [cfg for cfg in REMOTE_JDK_CONFIGS[expected.version] if cfg.name == expected.name]
+        if len(actual) != 1:
+            fail("Expected to find exactly one configuration for:", expected.name, "found: ", actual)
+        actual = actual[0]
+        if expected.urls != actual.urls or expected.strip_prefix != actual.strip_prefix:
+            fail("config mismatch! wanted:", expected, "got:", actual)
diff --git a/test/repo/.bazelrc b/test/repo/.bazelrc
new file mode 100644
index 0000000..e8aef35
--- /dev/null
+++ b/test/repo/.bazelrc
@@ -0,0 +1,3 @@
+build:bzlmod --experimental_enable_bzlmod
+
+common --incompatible_disallow_empty_glob
diff --git a/test/repo/BUILD.bazel b/test/repo/BUILD.bazel
new file mode 100644
index 0000000..7f6887a
--- /dev/null
+++ b/test/repo/BUILD.bazel
@@ -0,0 +1,30 @@
+load("@rules_java//java:defs.bzl", "java_binary", "java_library", "java_test")  # copybara-use-repo-external-label
+load("@rules_java//toolchains:default_java_toolchain.bzl", "default_java_toolchain")  # copybara-use-repo-external-label
+
+java_library(
+    name = "lib",
+    srcs = ["src/Main.java"],
+)
+
+java_binary(
+    name = "bin",
+    main_class = "Main",
+    runtime_deps = [":lib"],
+)
+
+java_test(
+    name = "MyTest",
+    srcs = ["src/MyTest.java"],
+    data = [
+        "src/data.txt",
+    ],
+    deps = [
+        "@my_jar//jar",
+        "@rules_java//java/runfiles",
+    ],
+)
+
+default_java_toolchain(
+    name = "my_funky_toolchain",
+    bootclasspath = ["@bazel_tools//tools/jdk:platformclasspath"],
+)
diff --git a/test/repo/MODULE.bazel b/test/repo/MODULE.bazel
new file mode 100644
index 0000000..c582bf4
--- /dev/null
+++ b/test/repo/MODULE.bazel
@@ -0,0 +1,45 @@
+module(name = "integration_test_repo")
+
+bazel_dep(name = "rules_java", version = "7.5.0")
+archive_override(
+    module_name = "rules_java",
+    urls = ["file:///tmp/rules_java-HEAD.tar.gz"],
+)
+
+http_jar = use_repo_rule("@rules_java//java:http_jar.bzl", "http_jar")
+
+http_jar(
+    name = "my_jar",
+    urls = ["file:///tmp/my_jar.jar"],
+)
+
+java_toolchains = use_extension("@rules_java//java:extensions.bzl", "toolchains")
+use_repo(
+    java_toolchains,
+    "local_jdk",
+    "remote_java_tools",
+    "remote_java_tools_darwin_arm64",
+    "remote_java_tools_darwin_x86_64",
+    "remote_java_tools_linux",
+    "remote_java_tools_windows",
+    "remotejdk11_linux",
+    "remotejdk11_linux_aarch64",
+    "remotejdk11_linux_ppc64le",
+    "remotejdk11_linux_s390x",
+    "remotejdk11_macos",
+    "remotejdk11_macos_aarch64",
+    "remotejdk11_win",
+    "remotejdk11_win_arm64",
+    "remotejdk17_linux",
+    "remotejdk17_linux_s390x",
+    "remotejdk17_macos",
+    "remotejdk17_macos_aarch64",
+    "remotejdk17_win",
+    "remotejdk17_win_arm64",
+    "remotejdk21_linux",
+    "remotejdk21_macos",
+    "remotejdk21_macos_aarch64",
+    "remotejdk21_win",
+)
+
+register_toolchains("//:all")
diff --git a/test/repo/WORKSPACE b/test/repo/WORKSPACE
new file mode 100644
index 0000000..872e89a
--- /dev/null
+++ b/test/repo/WORKSPACE
@@ -0,0 +1,27 @@
+workspace(name = "integration_test_repo")
+
+local_repository(
+    name = "rules_java",
+    path = "../../",
+)
+
+load("@rules_java//java:rules_java_deps.bzl", "rules_java_dependencies")
+
+rules_java_dependencies()
+
+load("@com_google_protobuf//bazel/private:proto_bazel_features.bzl", "proto_bazel_features")  # buildifier: disable=bzl-visibility
+
+proto_bazel_features(name = "proto_bazel_features")
+
+register_toolchains("//:all")
+
+load("@rules_java//java:repositories.bzl", "rules_java_toolchains")
+
+rules_java_toolchains()
+
+load("@rules_java//java:http_jar.bzl", "http_jar")
+
+http_jar(
+    name = "my_jar",
+    urls = ["file:///tmp/my_jar.jar"],
+)
diff --git a/test/repo/WORKSPACE.bzlmod b/test/repo/WORKSPACE.bzlmod
new file mode 100644
index 0000000..e69de29
diff --git a/test/repo/setup.sh b/test/repo/setup.sh
new file mode 100755
index 0000000..7e3b369
--- /dev/null
+++ b/test/repo/setup.sh
@@ -0,0 +1,7 @@
+#!/usr/bin/env bash
+
+cd ../../
+bazel build //distro:all //test/testdata:my_jar
+cp -f bazel-bin/distro/rules_java-*.tar.gz /tmp/rules_java-HEAD.tar.gz
+cp -f bazel-bin/test/testdata/libmy_jar.jar /tmp/my_jar.jar
+
diff --git a/test/repo/src/Main.java b/test/repo/src/Main.java
new file mode 100644
index 0000000..6029b2a
--- /dev/null
+++ b/test/repo/src/Main.java
@@ -0,0 +1 @@
+public class Main {}
diff --git a/test/repo/src/MyTest.java b/test/repo/src/MyTest.java
new file mode 100644
index 0000000..d2c2108
--- /dev/null
+++ b/test/repo/src/MyTest.java
@@ -0,0 +1,29 @@
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+
+import com.google.devtools.build.runfiles.AutoBazelRepository;
+import com.google.devtools.build.runfiles.Runfiles;
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import mypackage.MyLib;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+@AutoBazelRepository
+public class MyTest {
+  @Test
+  public void main() {
+    assertEquals(MyLib.myStr(), "my_string");
+  }
+
+  @Test
+  public void runfiles() throws IOException {
+    Runfiles runfiles = Runfiles.preload().withSourceRepository(AutoBazelRepository_MyTest.NAME);
+    Path path = Paths.get(runfiles.rlocation("integration_test_repo/src/data.txt"));
+    assertTrue(Files.exists(path));
+  }
+}
diff --git a/test/repo/src/data.txt b/test/repo/src/data.txt
new file mode 100644
index 0000000..e69de29
diff --git a/test/repositories.bzl b/test/repositories.bzl
new file mode 100644
index 0000000..5d4f568
--- /dev/null
+++ b/test/repositories.bzl
@@ -0,0 +1,23 @@
+"""Test dependencies for rules_java."""
+
+load("@bazel_skylib//lib:modules.bzl", "modules")
+
+# TODO: Use http_jar from //java:http_jar.bzl once it doesn't refert to cache.bzl from @bazel_tools
+# anymore, which isn't available in Bazel 6.
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
+
+def test_repositories():
+    http_file(
+        name = "guava",
+        url = "https://repo1.maven.org/maven2/com/google/guava/guava/33.3.1-jre/guava-33.3.1-jre.jar",
+        integrity = "sha256-S/Dixa+ORSXJbo/eF6T3MH+X+EePEcTI41oOMpiuTpA=",
+        downloaded_file_path = "guava.jar",
+    )
+    http_file(
+        name = "truth",
+        url = "https://repo1.maven.org/maven2/com/google/truth/truth/1.4.4/truth-1.4.4.jar",
+        integrity = "sha256-Ushs3a3DG8hFfB4VaJ/Gt14ul84qg9i1S3ldVW1In4w=",
+        downloaded_file_path = "truth.jar",
+    )
+
+test_repositories_ext = modules.as_extension(test_repositories)
diff --git a/test/runfiles/src/test/java/com/google/devtools/build/runfiles/BUILD.bazel b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/BUILD.bazel
new file mode 100644
index 0000000..67a11ca
--- /dev/null
+++ b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/BUILD.bazel
@@ -0,0 +1,34 @@
+load("@rules_java//java:java_import.bzl", "java_import")
+load("@rules_java//java:java_test.bzl", "java_test")
+
+java_test(
+    name = "RunfilesTest",
+    srcs = ["RunfilesTest.java"],
+    test_class = "com.google.devtools.build.runfiles.RunfilesTest",
+    deps = [
+        ":guava",
+        ":truth",
+        "//java/runfiles",
+    ],
+)
+
+java_test(
+    name = "UtilTest",
+    srcs = ["UtilTest.java"],
+    test_class = "com.google.devtools.build.runfiles.UtilTest",
+    deps = [
+        ":guava",
+        ":truth",
+        "//java/runfiles",
+    ],
+)
+
+java_import(
+    name = "guava",
+    jars = ["@guava//file"],
+)
+
+java_import(
+    name = "truth",
+    jars = ["@truth//file"],
+)
diff --git a/test/runfiles/src/test/java/com/google/devtools/build/runfiles/RunfilesTest.java b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/RunfilesTest.java
new file mode 100644
index 0000000..035a0b5
--- /dev/null
+++ b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/RunfilesTest.java
@@ -0,0 +1,601 @@
+// Copyright 2018 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
+import java.io.File;
+import java.io.IOException;
+import java.nio.charset.StandardCharsets;
+import java.nio.file.FileSystems;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.Map;
+import javax.annotation.Nullable;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+/** Unit tests for {@link Runfiles}. */
+@RunWith(JUnit4.class)
+public final class RunfilesTest {
+
+  @Rule
+  public TemporaryFolder tempDir = new TemporaryFolder(new File(System.getenv("TEST_TMPDIR")));
+
+  private static boolean isWindows() {
+    return File.separatorChar == '\\';
+  }
+
+  private void assertRlocationArg(Runfiles runfiles, String path, @Nullable String error) {
+    IllegalArgumentException e =
+        assertThrows(IllegalArgumentException.class, () -> runfiles.rlocation(path));
+    if (error != null) {
+      assertThat(e).hasMessageThat().contains(error);
+    }
+  }
+
+  @Test
+  public void testRlocationArgumentValidation() throws Exception {
+    Path dir =
+        Files.createTempDirectory(
+            FileSystems.getDefault().getPath(System.getenv("TEST_TMPDIR")), null);
+
+    Runfiles r = Runfiles.create(ImmutableMap.of("RUNFILES_DIR", dir.toString()));
+    assertRlocationArg(r, null, null);
+    assertRlocationArg(r, "", null);
+    assertRlocationArg(r, "../foo", "is not normalized");
+    assertRlocationArg(r, "foo/..", "is not normalized");
+    assertRlocationArg(r, "foo/../bar", "is not normalized");
+    assertRlocationArg(r, "./foo", "is not normalized");
+    assertRlocationArg(r, "foo/.", "is not normalized");
+    assertRlocationArg(r, "foo/./bar", "is not normalized");
+    assertRlocationArg(r, "//foobar", "is not normalized");
+    assertRlocationArg(r, "foo//", "is not normalized");
+    assertRlocationArg(r, "foo//bar", "is not normalized");
+    assertRlocationArg(r, "\\foo", "path is absolute without a drive letter");
+  }
+
+  @Test
+  public void testCreatesManifestBasedRunfiles() throws Exception {
+    Path mf = tempFile("foo.runfiles_manifest", ImmutableList.of("a/b c/d"));
+    Runfiles r =
+        Runfiles.create(
+            ImmutableMap.of(
+                "RUNFILES_MANIFEST_ONLY", "1",
+                "RUNFILES_MANIFEST_FILE", mf.toString(),
+                "RUNFILES_DIR", "ignored when RUNFILES_MANIFEST_ONLY=1",
+                "JAVA_RUNFILES", "ignored when RUNFILES_DIR has a value",
+                "TEST_SRCDIR", "should always be ignored"));
+    assertThat(r.rlocation("a/b")).isEqualTo("c/d");
+    assertThat(r.rlocation("foo")).isNull();
+
+    if (isWindows()) {
+      assertThat(r.rlocation("c:/foo")).isEqualTo("c:/foo");
+      assertThat(r.rlocation("c:\\foo")).isEqualTo("c:\\foo");
+    } else {
+      assertThat(r.rlocation("/foo")).isEqualTo("/foo");
+    }
+  }
+
+  @Test
+  public void testCreatesDirectoryBasedRunfiles() throws Exception {
+    Path dir =
+        Files.createTempDirectory(
+            FileSystems.getDefault().getPath(System.getenv("TEST_TMPDIR")), null);
+
+    Runfiles r =
+        Runfiles.create(
+            ImmutableMap.of(
+                "RUNFILES_MANIFEST_FILE", "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+                "RUNFILES_DIR", dir.toString(),
+                "JAVA_RUNFILES", "ignored when RUNFILES_DIR has a value",
+                "TEST_SRCDIR", "should always be ignored"));
+    assertThat(r.rlocation("a/b")).endsWith("/a/b");
+    assertThat(r.rlocation("foo")).endsWith("/foo");
+
+    r =
+        Runfiles.create(
+            ImmutableMap.of(
+                "RUNFILES_MANIFEST_FILE", "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+                "RUNFILES_DIR", "",
+                "JAVA_RUNFILES", dir.toString(),
+                "TEST_SRCDIR", "should always be ignored"));
+    assertThat(r.rlocation("a/b")).endsWith("/a/b");
+    assertThat(r.rlocation("foo")).endsWith("/foo");
+  }
+
+  @Test
+  public void testIgnoresTestSrcdirWhenJavaRunfilesIsUndefinedAndJustFails() throws Exception {
+    Path dir =
+        Files.createTempDirectory(
+            FileSystems.getDefault().getPath(System.getenv("TEST_TMPDIR")), null);
+
+    Runfiles.create(
+        ImmutableMap.of(
+            "RUNFILES_DIR", dir.toString(),
+            "RUNFILES_MANIFEST_FILE", "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+            "TEST_SRCDIR", "should always be ignored"));
+
+    Runfiles.create(
+        ImmutableMap.of(
+            "JAVA_RUNFILES", dir.toString(),
+            "RUNFILES_MANIFEST_FILE", "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+            "TEST_SRCDIR", "should always be ignored"));
+
+    IOException e =
+        assertThrows(
+            IOException.class,
+            () ->
+                Runfiles.create(
+                    ImmutableMap.of(
+                        "RUNFILES_DIR",
+                        "",
+                        "JAVA_RUNFILES",
+                        "",
+                        "RUNFILES_MANIFEST_FILE",
+                        "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+                        "TEST_SRCDIR",
+                        "should always be ignored")));
+    assertThat(e).hasMessageThat().contains("$RUNFILES_DIR and $JAVA_RUNFILES");
+  }
+
+  @Test
+  public void testFailsToCreateManifestBasedBecauseManifestDoesNotExist() {
+    IOException e =
+        assertThrows(
+            IOException.class,
+            () ->
+                Runfiles.create(
+                    ImmutableMap.of(
+                        "RUNFILES_MANIFEST_ONLY", "1",
+                        "RUNFILES_MANIFEST_FILE", "non-existing path")));
+    assertThat(e).hasMessageThat().contains("non-existing path");
+  }
+
+  @Test
+  public void testManifestBasedEnvVars() throws Exception {
+    Path mf = tempFile("MANIFEST", ImmutableList.of());
+    Map<String, String> envvars =
+        Runfiles.create(
+                ImmutableMap.of(
+                    "RUNFILES_MANIFEST_ONLY", "1",
+                    "RUNFILES_MANIFEST_FILE", mf.toString(),
+                    "RUNFILES_DIR", "ignored when RUNFILES_MANIFEST_ONLY=1",
+                    "JAVA_RUNFILES", "ignored when RUNFILES_DIR has a value",
+                    "TEST_SRCDIR", "should always be ignored"))
+            .getEnvVars();
+    assertThat(envvars.keySet())
+        .containsExactly(
+            "RUNFILES_MANIFEST_ONLY", "RUNFILES_MANIFEST_FILE", "RUNFILES_DIR", "JAVA_RUNFILES");
+    assertThat(envvars.get("RUNFILES_MANIFEST_ONLY")).isEqualTo("1");
+    assertThat(envvars.get("RUNFILES_MANIFEST_FILE")).isEqualTo(mf.toString());
+    assertThat(envvars.get("RUNFILES_DIR")).isEqualTo(tempDir.getRoot().toString());
+    assertThat(envvars.get("JAVA_RUNFILES")).isEqualTo(tempDir.getRoot().toString());
+
+    Path rfDir = tempDir.getRoot().toPath().resolve("foo.runfiles");
+    Files.createDirectories(rfDir);
+    mf = tempFile("foo.runfiles_manifest", ImmutableList.of());
+    envvars =
+        Runfiles.create(
+                ImmutableMap.of(
+                    "RUNFILES_MANIFEST_ONLY", "1",
+                    "RUNFILES_MANIFEST_FILE", mf.toString(),
+                    "RUNFILES_DIR", "ignored when RUNFILES_MANIFEST_ONLY=1",
+                    "JAVA_RUNFILES", "ignored when RUNFILES_DIR has a value",
+                    "TEST_SRCDIR", "should always be ignored"))
+            .getEnvVars();
+    assertThat(envvars.get("RUNFILES_MANIFEST_ONLY")).isEqualTo("1");
+    assertThat(envvars.get("RUNFILES_MANIFEST_FILE")).isEqualTo(mf.toString());
+    assertThat(envvars.get("RUNFILES_DIR")).isEqualTo(rfDir.toString());
+    assertThat(envvars.get("JAVA_RUNFILES")).isEqualTo(rfDir.toString());
+  }
+
+  @Test
+  public void testDirectoryBasedEnvVars() throws Exception {
+    Map<String, String> envvars =
+        Runfiles.create(
+                ImmutableMap.of(
+                    "RUNFILES_MANIFEST_FILE",
+                    "ignored when RUNFILES_MANIFEST_ONLY is not set to 1",
+                    "RUNFILES_DIR",
+                    tempDir.getRoot().toString(),
+                    "JAVA_RUNFILES",
+                    "ignored when RUNFILES_DIR has a value",
+                    "TEST_SRCDIR",
+                    "should always be ignored"))
+            .getEnvVars();
+    assertThat(envvars.keySet()).containsExactly("RUNFILES_DIR", "JAVA_RUNFILES");
+    assertThat(envvars.get("RUNFILES_DIR")).isEqualTo(tempDir.getRoot().toString());
+    assertThat(envvars.get("JAVA_RUNFILES")).isEqualTo(tempDir.getRoot().toString());
+  }
+
+  @Test
+  public void testDirectoryBasedRlocation() throws IOException {
+    // The DirectoryBased implementation simply joins the runfiles directory and the runfile's path
+    // on a "/". DirectoryBased does not perform any normalization, nor does it check that the path
+    // exists.
+    File dir = new File(System.getenv("TEST_TMPDIR"), "mock/runfiles");
+    assertThat(dir.mkdirs()).isTrue();
+    Runfiles r = Runfiles.createDirectoryBasedForTesting(dir.toString()).withSourceRepository("");
+    // Escaping for "\": once for string and once for regex.
+    assertThat(r.rlocation("arg")).matches(".*[/\\\\]mock[/\\\\]runfiles[/\\\\]arg");
+  }
+
+  @Test
+  public void testManifestBasedRlocation() throws Exception {
+    Path mf =
+        tempFile(
+            "MANIFEST",
+            ImmutableList.of(
+                "Foo/runfile1 C:/Actual Path\\runfile1",
+                "Foo/Bar/runfile2 D:\\the path\\run file 2.txt",
+                "Foo/Bar/Dir E:\\Actual Path\\bDirectory",
+                " h/\\si F:\\bjk",
+                " dir\\swith\\sspaces F:\\bj k\\bdir with spaces",
+                " h/\\s\\n\\bi F:\\bjk\\nb"));
+    Runfiles r = Runfiles.createManifestBasedForTesting(mf.toString()).withSourceRepository("");
+    assertThat(r.rlocation("Foo/runfile1")).isEqualTo("C:/Actual Path\\runfile1");
+    assertThat(r.rlocation("Foo/Bar/runfile2")).isEqualTo("D:\\the path\\run file 2.txt");
+    assertThat(r.rlocation("Foo/Bar/Dir")).isEqualTo("E:\\Actual Path\\bDirectory");
+    assertThat(r.rlocation("Foo/Bar/Dir/File")).isEqualTo("E:\\Actual Path\\bDirectory/File");
+    assertThat(r.rlocation("Foo/Bar/Dir/Deeply/Nested/File"))
+        .isEqualTo("E:\\Actual Path\\bDirectory/Deeply/Nested/File");
+    assertThat(r.rlocation("Foo/Bar/Dir/Deeply/Nested/File With Spaces"))
+        .isEqualTo("E:\\Actual Path\\bDirectory/Deeply/Nested/File With Spaces");
+    assertThat(r.rlocation("h/ i")).isEqualTo("F:\\jk");
+    assertThat(r.rlocation("h/ \n\\i")).isEqualTo("F:\\jk\nb");
+    assertThat(r.rlocation("dir with spaces")).isEqualTo("F:\\j k\\dir with spaces");
+    assertThat(r.rlocation("dir with spaces/file")).isEqualTo("F:\\j k\\dir with spaces/file");
+    assertThat(r.rlocation("unknown")).isNull();
+  }
+
+  @Test
+  public void testManifestBasedRlocationWithRepoMapping_fromMain() throws Exception {
+    Path rm =
+        tempFile(
+            "foo.repo_mapping",
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Path mf =
+        tempFile(
+            "foo.runfiles_manifest",
+            ImmutableList.of(
+                "_repo_mapping " + rm,
+                "config.json /etc/config.json",
+                "protobuf+3.19.2/foo/runfile C:/Actual Path\\protobuf\\runfile",
+                "_main/bar/runfile /the/path/./to/other//other runfile.txt",
+                "protobuf+3.19.2/bar/dir E:\\Actual Path\\Directory"));
+    Runfiles r = Runfiles.createManifestBasedForTesting(mf.toString()).withSourceRepository("");
+
+    assertThat(r.rlocation("my_module/bar/runfile"))
+        .isEqualTo("/the/path/./to/other//other runfile.txt");
+    assertThat(r.rlocation("my_workspace/bar/runfile"))
+        .isEqualTo("/the/path/./to/other//other runfile.txt");
+    assertThat(r.rlocation("my_protobuf/foo/runfile"))
+        .isEqualTo("C:/Actual Path\\protobuf\\runfile");
+    assertThat(r.rlocation("my_protobuf/bar/dir")).isEqualTo("E:\\Actual Path\\Directory");
+    assertThat(r.rlocation("my_protobuf/bar/dir/file"))
+        .isEqualTo("E:\\Actual Path\\Directory/file");
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes ted/fi+le"))
+        .isEqualTo("E:\\Actual Path\\Directory/de eply/nes ted/fi+le");
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir/file")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir/dir/de eply/nes ted/fi+le")).isNull();
+
+    assertThat(r.rlocation("_main/bar/runfile"))
+        .isEqualTo("/the/path/./to/other//other runfile.txt");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo("C:/Actual Path\\protobuf\\runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo("E:\\Actual Path\\Directory");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo("E:\\Actual Path\\Directory/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo("E:\\Actual Path\\Directory/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo("/etc/config.json");
+    assertThat(r.rlocation("_main")).isNull();
+    assertThat(r.rlocation("my_module")).isNull();
+    assertThat(r.rlocation("protobuf")).isNull();
+  }
+
+  @Test
+  public void testManifestBasedRlocationUnmapped() throws Exception {
+    Path rm =
+        tempFile(
+            "foo.repo_mapping",
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Path mf =
+        tempFile(
+            "foo.runfiles_manifest",
+            ImmutableList.of(
+                "_repo_mapping " + rm,
+                "config.json /etc/config.json",
+                "protobuf+3.19.2/foo/runfile C:/Actual Path\\protobuf\\runfile",
+                "_main/bar/runfile /the/path/./to/other//other runfile.txt",
+                "protobuf+3.19.2/bar/dir E:\\Actual Path\\Directory"));
+    Runfiles r = Runfiles.createManifestBasedForTesting(mf.toString()).unmapped();
+
+    assertThat(r.rlocation("my_module/bar/runfile")).isNull();
+    assertThat(r.rlocation("my_workspace/bar/runfile")).isNull();
+    assertThat(r.rlocation("my_protobuf/foo/runfile")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir/file")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes ted/fi+le")).isNull();
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir/file")).isNull();
+    assertThat(r.rlocation("protobuf/bar/dir/dir/de eply/nes ted/fi+le")).isNull();
+
+    assertThat(r.rlocation("_main/bar/runfile"))
+        .isEqualTo("/the/path/./to/other//other runfile.txt");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo("C:/Actual Path\\protobuf\\runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo("E:\\Actual Path\\Directory");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo("E:\\Actual Path\\Directory/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo("E:\\Actual Path\\Directory/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo("/etc/config.json");
+    assertThat(r.rlocation("_main")).isNull();
+    assertThat(r.rlocation("my_module")).isNull();
+    assertThat(r.rlocation("protobuf")).isNull();
+  }
+
+  @Test
+  public void testManifestBasedRlocationWithRepoMapping_fromOtherRepo() throws Exception {
+    Path rm =
+        tempFile(
+            "foo.repo_mapping",
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Path mf =
+        tempFile(
+            "foo.runfiles/MANIFEST",
+            ImmutableList.of(
+                "_repo_mapping " + rm,
+                "config.json /etc/config.json",
+                "protobuf+3.19.2/foo/runfile C:/Actual Path\\protobuf\\runfile",
+                "_main/bar/runfile /the/path/./to/other//other runfile.txt",
+                "protobuf+3.19.2/bar/dir E:\\Actual Path\\Directory"));
+    Runfiles r =
+        Runfiles.createManifestBasedForTesting(mf.toString())
+            .withSourceRepository("protobuf+3.19.2");
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isEqualTo("C:/Actual Path\\protobuf\\runfile");
+    assertThat(r.rlocation("protobuf/bar/dir")).isEqualTo("E:\\Actual Path\\Directory");
+    assertThat(r.rlocation("protobuf/bar/dir/file")).isEqualTo("E:\\Actual Path\\Directory/file");
+    assertThat(r.rlocation("protobuf/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo("E:\\Actual Path\\Directory/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("my_module/bar/runfile")).isNull();
+    assertThat(r.rlocation("my_protobuf/foo/runfile")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir/file")).isNull();
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes  ted/fi+le")).isNull();
+
+    assertThat(r.rlocation("_main/bar/runfile"))
+        .isEqualTo("/the/path/./to/other//other runfile.txt");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo("C:/Actual Path\\protobuf\\runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo("E:\\Actual Path\\Directory");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo("E:\\Actual Path\\Directory/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo("E:\\Actual Path\\Directory/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo("/etc/config.json");
+    assertThat(r.rlocation("_main")).isNull();
+    assertThat(r.rlocation("my_module")).isNull();
+    assertThat(r.rlocation("protobuf")).isNull();
+  }
+
+  @Test
+  public void testDirectoryBasedRlocationWithRepoMapping_fromMain() throws Exception {
+    Path dir = tempDir.newFolder("foo.runfiles").toPath();
+    Path unused =
+        tempFile(
+            dir.resolve("_repo_mapping").toString(),
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Runfiles r = Runfiles.createDirectoryBasedForTesting(dir.toString()).withSourceRepository("");
+
+    assertThat(r.rlocation("my_module/bar/runfile")).isEqualTo(dir + "/_main/bar/runfile");
+    assertThat(r.rlocation("my_workspace/bar/runfile")).isEqualTo(dir + "/_main/bar/runfile");
+    assertThat(r.rlocation("my_protobuf/foo/runfile"))
+        .isEqualTo(dir + "/protobuf+3.19.2/foo/runfile");
+    assertThat(r.rlocation("my_protobuf/bar/dir")).isEqualTo(dir + "/protobuf+3.19.2/bar/dir");
+    assertThat(r.rlocation("my_protobuf/bar/dir/file"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/file");
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes ted/fi+le"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/de eply/nes ted/fi+le");
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isEqualTo(dir + "/protobuf/foo/runfile");
+    assertThat(r.rlocation("protobuf/bar/dir/dir/de eply/nes ted/fi+le"))
+        .isEqualTo(dir + "/protobuf/bar/dir/dir/de eply/nes ted/fi+le");
+
+    assertThat(r.rlocation("_main/bar/runfile")).isEqualTo(dir + "/_main/bar/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo(dir + "/protobuf+3.19.2/foo/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo(dir + "/protobuf+3.19.2/bar/dir");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo(dir + "/config.json");
+  }
+
+  @Test
+  public void testDirectoryBasedRlocationUnmapped() throws Exception {
+    Path dir = tempDir.newFolder("foo.runfiles").toPath();
+    Path unused =
+        tempFile(
+            dir.resolve("_repo_mapping").toString(),
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Runfiles r = Runfiles.createDirectoryBasedForTesting(dir.toString()).unmapped();
+
+    assertThat(r.rlocation("my_module/bar/runfile")).isEqualTo(dir + "/my_module/bar/runfile");
+    assertThat(r.rlocation("my_workspace/bar/runfile"))
+        .isEqualTo(dir + "/my_workspace/bar/runfile");
+    assertThat(r.rlocation("my_protobuf/foo/runfile")).isEqualTo(dir + "/my_protobuf/foo/runfile");
+    assertThat(r.rlocation("my_protobuf/bar/dir")).isEqualTo(dir + "/my_protobuf/bar/dir");
+    assertThat(r.rlocation("my_protobuf/bar/dir/file"))
+        .isEqualTo(dir + "/my_protobuf/bar/dir/file");
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes ted/fi+le"))
+        .isEqualTo(dir + "/my_protobuf/bar/dir/de eply/nes ted/fi+le");
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isEqualTo(dir + "/protobuf/foo/runfile");
+    assertThat(r.rlocation("protobuf/bar/dir/dir/de eply/nes ted/fi+le"))
+        .isEqualTo(dir + "/protobuf/bar/dir/dir/de eply/nes ted/fi+le");
+
+    assertThat(r.rlocation("_main/bar/runfile")).isEqualTo(dir + "/_main/bar/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo(dir + "/protobuf+3.19.2/foo/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo(dir + "/protobuf+3.19.2/bar/dir");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo(dir + "/config.json");
+  }
+
+  @Test
+  public void testDirectoryBasedRlocationWithRepoMapping_fromOtherRepo() throws Exception {
+    Path dir = tempDir.newFolder("foo.runfiles").toPath();
+    Path unused =
+        tempFile(
+            dir.resolve("_repo_mapping").toString(),
+            ImmutableList.of(
+                ",config.json,config.json+1.2.3",
+                ",my_module,_main",
+                ",my_protobuf,protobuf+3.19.2",
+                ",my_workspace,_main",
+                "protobuf+3.19.2,config.json,config.json+1.2.3",
+                "protobuf+3.19.2,protobuf,protobuf+3.19.2"));
+    Runfiles r =
+        Runfiles.createDirectoryBasedForTesting(dir.toString())
+            .withSourceRepository("protobuf+3.19.2");
+
+    assertThat(r.rlocation("protobuf/foo/runfile")).isEqualTo(dir + "/protobuf+3.19.2/foo/runfile");
+    assertThat(r.rlocation("protobuf/bar/dir")).isEqualTo(dir + "/protobuf+3.19.2/bar/dir");
+    assertThat(r.rlocation("protobuf/bar/dir/file"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/file");
+    assertThat(r.rlocation("protobuf/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("my_module/bar/runfile")).isEqualTo(dir + "/my_module/bar/runfile");
+    assertThat(r.rlocation("my_protobuf/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo(dir + "/my_protobuf/bar/dir/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("_main/bar/runfile")).isEqualTo(dir + "/_main/bar/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/foo/runfile"))
+        .isEqualTo(dir + "/protobuf+3.19.2/foo/runfile");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir")).isEqualTo(dir + "/protobuf+3.19.2/bar/dir");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/file"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/file");
+    assertThat(r.rlocation("protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le"))
+        .isEqualTo(dir + "/protobuf+3.19.2/bar/dir/de eply/nes  ted/fi+le");
+
+    assertThat(r.rlocation("config.json")).isEqualTo(dir + "/config.json");
+  }
+
+  @Test
+  public void testDirectoryBasedCtorArgumentValidation() throws IOException {
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> Runfiles.createDirectoryBasedForTesting(null).withSourceRepository(""));
+
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> Runfiles.createDirectoryBasedForTesting("").withSourceRepository(""));
+
+    assertThrows(
+        IllegalArgumentException.class,
+        () ->
+            Runfiles.createDirectoryBasedForTesting("non-existent directory is bad")
+                .withSourceRepository(""));
+
+    Runfiles unused =
+        Runfiles.createDirectoryBasedForTesting(System.getenv("TEST_TMPDIR"))
+            .withSourceRepository("");
+  }
+
+  @Test
+  public void testManifestBasedCtorArgumentValidation() throws Exception {
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> Runfiles.createManifestBasedForTesting(null).withSourceRepository(""));
+
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> Runfiles.createManifestBasedForTesting("").withSourceRepository(""));
+
+    Path mf = tempFile("foobar", ImmutableList.of("a b"));
+    Runfiles unused = Runfiles.createManifestBasedForTesting(mf.toString()).withSourceRepository("");
+  }
+
+  @Test
+  public void testInvalidRepoMapping() throws Exception {
+    Path rm = tempFile("foo.repo_mapping", ImmutableList.of("a,b,c,d"));
+    Path mf = tempFile("foo.runfiles/MANIFEST", ImmutableList.of("_repo_mapping " + rm));
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> Runfiles.createManifestBasedForTesting(mf.toString()).withSourceRepository(""));
+  }
+
+  private Path tempFile(String path, ImmutableList<String> lines) throws IOException {
+    Path file = tempDir.getRoot().toPath().resolve(path.replace('/', File.separatorChar));
+    Files.createDirectories(file.getParent());
+    return Files.write(file, lines, StandardCharsets.UTF_8);
+  }
+}
diff --git a/test/runfiles/src/test/java/com/google/devtools/build/runfiles/UtilTest.java b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/UtilTest.java
new file mode 100644
index 0000000..3827326
--- /dev/null
+++ b/test/runfiles/src/test/java/com/google/devtools/build/runfiles/UtilTest.java
@@ -0,0 +1,47 @@
+// Copyright 2018 The Bazel Authors. All rights reserved.
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
+package com.google.devtools.build.runfiles;
+
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+/** Unit tests for {@link Util}. */
+@RunWith(JUnit4.class)
+public final class UtilTest {
+
+  @Test
+  public void testIsNullOrEmpty() {
+    assertThat(Util.isNullOrEmpty(null)).isTrue();
+    assertThat(Util.isNullOrEmpty("")).isTrue();
+    assertThat(Util.isNullOrEmpty("\0")).isFalse();
+    assertThat(Util.isNullOrEmpty("some text")).isFalse();
+  }
+
+  @Test
+  public void testCheckArgument() {
+    Util.checkArgument(true, null, null);
+
+    IllegalArgumentException e =
+        assertThrows(IllegalArgumentException.class, () -> Util.checkArgument(false, null, null));
+    assertThat(e).hasMessageThat().isEqualTo("argument validation failed");
+
+    e = assertThrows(IllegalArgumentException.class, () -> Util.checkArgument(false, "foo-%s", 42));
+    assertThat(e).hasMessageThat().isEqualTo("foo-42");
+  }
+}
diff --git a/test/testdata/BUILD.bazel b/test/testdata/BUILD.bazel
new file mode 100644
index 0000000..ffcc5c3
--- /dev/null
+++ b/test/testdata/BUILD.bazel
@@ -0,0 +1,7 @@
+load("//java:java_library.bzl", "java_library")
+
+# Make a sample jar for the http_jar test.
+java_library(
+    name = "my_jar",
+    srcs = ["MyLib.java"],
+)
diff --git a/test/testdata/MyLib.java b/test/testdata/MyLib.java
new file mode 100644
index 0000000..48428f1
--- /dev/null
+++ b/test/testdata/MyLib.java
@@ -0,0 +1,9 @@
+package mypackage;
+
+/** A simple library for the http_jar test. */
+public class MyLib {
+  public static String myStr() {
+    return "my_string";
+  }
+}
+
diff --git a/toolchains/BUILD b/toolchains/BUILD
index 81126c2..99c4456 100644
--- a/toolchains/BUILD
+++ b/toolchains/BUILD
@@ -1,10 +1,15 @@
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-load("@rules_cc//cc:defs.bzl", "cc_library")
+load("@bazel_skylib//rules:common_settings.bzl", "bool_flag", "string_setting")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load(
+    ":bootclasspath.bzl",
+    "bootclasspath",
+    "language_version_bootstrap_runtime",
+)
 load(
     ":default_java_toolchain.bzl",
     "DEFAULT_TOOLCHAIN_CONFIGURATION",
     "PREBUILT_TOOLCHAIN_CONFIGURATION",
-    "bootclasspath",
     "default_java_toolchain",
     "java_runtime_files",
 )
@@ -15,6 +20,7 @@ load(
     "java_runtime_version_alias",
     "java_toolchain_alias",
 )
+load(":utf8_environment.bzl", "utf8_environment")
 
 package(default_visibility = ["//visibility:public"])
 
@@ -30,6 +36,15 @@ filegroup(
     srcs = glob(["*.bzl"]),
 )
 
+# If enabled, the bootclasspath for Java compilation will be extracted from a Java runtime matching
+# the version specified with `--java_language_version` rather than the runtime specified with
+# `--java_runtime_version`.
+bool_flag(
+    name = "incompatible_language_version_bootclasspath",
+    build_setting_default = False,
+    visibility = ["//visibility:private"],
+)
+
 # A single binary distribution of a JDK (e.g., OpenJDK 17 for Windows arm64) provides three
 # different types of toolchains from the perspective of Bazel:
 
@@ -136,9 +151,9 @@ cc_library(
         "@bazel_tools//src/conditions:darwin": ["include/darwin"],
         "@bazel_tools//src/conditions:freebsd": ["include/freebsd"],
         "@bazel_tools//src/conditions:linux_aarch64": ["include/linux"],
-        "@bazel_tools//src/conditions:linux_mips64": [":include/linux"],
+        "@bazel_tools//src/conditions:linux_mips64": ["include/linux"],
         "@bazel_tools//src/conditions:linux_ppc64le": ["include/linux"],
-        "@bazel_tools//src/conditions:linux_riscv64": [":include/linux"],
+        "@bazel_tools//src/conditions:linux_riscv64": ["include/linux"],
         "@bazel_tools//src/conditions:linux_s390x": ["include/linux"],
         "@bazel_tools//src/conditions:linux_x86_64": ["include/linux"],
         "@bazel_tools//src/conditions:openbsd": ["include/openbsd"],
@@ -160,6 +175,11 @@ cc_library(
             actual = "@remote_java_tools_%s//:prebuilt_singlejar" % OS,
             visibility = ["//visibility:private"],
         ),
+        alias(
+            name = "prebuilt_one_version_%s" % OS,
+            actual = "@remote_java_tools_%s//:prebuilt_one_version" % OS,
+            visibility = ["//visibility:private"],
+        ),
         alias(
             name = "turbine_direct_graal_%s" % OS,
             actual = "@remote_java_tools_%s//:turbine_direct_graal" % OS,
@@ -225,6 +245,32 @@ alias(
     }),
 )
 
+alias(
+    name = "one_version",
+    actual = ":one_version_prebuilt_or_cc_binary",
+)
+
+alias(
+    name = "one_version_prebuilt_or_cc_binary",
+    actual = select({
+        "@bazel_tools//src/conditions:darwin_arm64": ":prebuilt_one_version_darwin_arm64",
+        "@bazel_tools//src/conditions:darwin_x86_64": ":prebuilt_one_version_darwin_x86_64",
+        "@bazel_tools//src/conditions:linux_x86_64": ":prebuilt_one_version_linux",
+        "@bazel_tools//src/conditions:windows": ":prebuilt_one_version_windows",
+        "//conditions:default": "@remote_java_tools//:one_version_cc_bin",
+    }),
+)
+
+alias(
+    name = "prebuilt_one_version",
+    actual = select({
+        "@bazel_tools//src/conditions:darwin_arm64": ":prebuilt_one_version_darwin_arm64",
+        "@bazel_tools//src/conditions:darwin_x86_64": ":prebuilt_one_version_darwin_x86_64",
+        "@bazel_tools//src/conditions:linux_x86_64": ":prebuilt_one_version_linux",
+        "@bazel_tools//src/conditions:windows": ":prebuilt_one_version_windows",
+    }),
+)
+
 alias(
     name = "turbine_direct",
     actual = ":turbine_direct_graal_or_java",
@@ -251,10 +297,46 @@ alias(
     }),
 )
 
+string_setting(
+    name = "java_language_version",
+    build_setting_default = "",
+    visibility = ["//visibility:private"],
+)
+
+string_setting(
+    name = "java_runtime_version",
+    build_setting_default = "",
+    visibility = ["//visibility:private"],
+)
+
+language_version_bootstrap_runtime(
+    name = "language_version_bootstrap_runtime",
+    java_language_version = ":java_language_version",
+    java_runtime_version = ":java_runtime_version",
+    visibility = ["//visibility:private"],
+)
+
+utf8_environment(
+    name = "utf8_environment",
+    visibility = ["//visibility:private"],
+)
+
+config_setting(
+    name = "incompatible_language_version_bootclasspath_enabled",
+    flag_values = {
+        ":incompatible_language_version_bootclasspath": "True",
+    },
+    visibility = ["//visibility:private"],
+)
+
 bootclasspath(
     name = "platformclasspath",
     src = "DumpPlatformClassPath.java",
     java_runtime_alias = ":current_java_runtime",
+    language_version_bootstrap_runtime = select({
+        ":incompatible_language_version_bootclasspath_enabled": ":language_version_bootstrap_runtime",
+        "//conditions:default": None,
+    }),
 )
 
 default_java_toolchain(
@@ -293,18 +375,6 @@ java_runtime_version_alias(
     visibility = ["//visibility:public"],
 )
 
-java_runtime_version_alias(
-    name = "remotejdk_15",
-    runtime_version = "remotejdk_15",
-    visibility = ["//visibility:public"],
-)
-
-java_runtime_version_alias(
-    name = "remotejdk_16",
-    runtime_version = "remotejdk_16",
-    visibility = ["//visibility:public"],
-)
-
 java_runtime_version_alias(
     name = "remotejdk_17",
     runtime_version = "remotejdk_17",
diff --git a/toolchains/BUILD.java_tools b/toolchains/BUILD.java_tools
new file mode 100644
index 0000000..9c68b75
--- /dev/null
+++ b/toolchains/BUILD.java_tools
@@ -0,0 +1,669 @@
+load("@com_google_protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
+load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")
+load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
+load("@rules_java//java:java_binary.bzl", "java_binary")
+load("@rules_java//java:java_import.bzl", "java_import")
+
+package(default_visibility = ["//visibility:public"])
+
+exports_files(glob(["**/*.jar"]))
+
+licenses(["notice"])  # Apache 2.0
+
+SUPRESSED_WARNINGS = select({
+    ":windows": [],
+    "//conditions:default": [
+        "-Wno-error",
+        "-Wno-old-style-cast",
+    ],
+})
+
+filegroup(
+    name = "GenClass",
+    srcs = ["java_tools/GenClass_deploy.jar"],
+)
+
+filegroup(
+    name = "jacoco_coverage_runner_filegroup",
+    srcs = ["java_tools/JacocoCoverage_jarjar_deploy.jar"],
+)
+
+java_import(
+    name = "jacoco_coverage_runner",
+    jars = ["java_tools/JacocoCoverage_jarjar_deploy.jar"],
+)
+
+filegroup(
+    name = "JacocoCoverage",
+    srcs = ["java_tools/JacocoCoverage_jarjar_deploy.jar"],
+)
+
+filegroup(
+    name = "JavaBuilder",
+    srcs = ["java_tools/JavaBuilder_deploy.jar"],
+)
+
+filegroup(
+    name = "Runner",
+    srcs = ["java_tools/Runner_deploy.jar"],
+)
+
+filegroup(
+    name = "VanillaJavaBuilder",
+    srcs = ["java_tools/VanillaJavaBuilder_deploy.jar"],
+)
+
+filegroup(
+    name = "TurbineDirect",
+    srcs = ["java_tools/turbine_direct_binary_deploy.jar"],
+)
+
+java_import(
+    name = "jacoco-agent",
+    jars = ["java_tools/third_party/java/jacoco/org.jacoco.agent-0.8.11.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/org.jacoco.agent-0.8.11-sources.jar",
+)
+
+java_import(
+    name = "jacoco-core",
+    jars = ["java_tools/third_party/java/jacoco/org.jacoco.core-0.8.11.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/org.jacoco.core-0.8.11-sources.jar",
+    exports = [
+        ":asm",
+        ":asm-commons",
+        ":asm-tree",
+    ],
+)
+
+filegroup(
+    name = "jacoco-core-jars",
+    srcs = ["java_tools/third_party/java/jacoco/org.jacoco.core-0.8.11.jar"],
+)
+
+java_import(
+    name = "jacoco-report",
+    jars = ["java_tools/third_party/java/jacoco/org.jacoco.report-0.8.11.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/org.jacoco.report-0.8.11-sources.jar",
+    exports = [
+        ":asm",
+        ":jacoco-core",
+    ],
+)
+
+java_import(
+    name = "bazel-jacoco-agent",
+    jars = ["java_tools/third_party/java/jacoco/jacocoagent-0.8.11.jar"],
+)
+
+java_import(
+    name = "bazel-jacoco-agent-neverlink",
+    jars = ["java_tools/third_party/java/jacoco/jacocoagent-0.8.11.jar"],
+    neverlink = 1,
+)
+
+java_import(
+    name = "asm",
+    jars = ["java_tools/third_party/java/jacoco/asm-9.6.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/asm-9.6-sources.jar",
+)
+
+java_import(
+    name = "asm-commons",
+    jars = ["java_tools/third_party/java/jacoco/asm-commons-9.6.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/asm-commons-9.6-sources.jar",
+    runtime_deps = [":asm-tree"],
+)
+
+java_import(
+    name = "asm-tree",
+    jars = ["java_tools/third_party/java/jacoco/asm-tree-9.6.jar"],
+    srcjar = "java_tools/third_party/java/jacoco/asm-tree-9.6-sources.jar",
+    runtime_deps = [":asm"],
+)
+
+config_setting(
+    name = "windows",
+    constraint_values = ["@platforms//os:windows"],
+)
+
+config_setting(
+    name = "freebsd",
+    constraint_values = ["@platforms//os:freebsd"],
+    visibility = ["//visibility:public"],
+)
+
+config_setting(
+    name = "openbsd",
+    constraint_values = ["@platforms//os:openbsd"],
+    visibility = ["//visibility:public"],
+)
+
+# Create intermediate cc_library, which does not implicitly depend on "malloc"
+# and "link_extra_lib" in @bazel_tools//tools/cpp, and thereby avoids include
+# path /Iexternal/tools being used in compiling actions which would result in
+# the wrong headers being picked up.
+cc_library(
+    name = "ijar_cc_binary_main",
+    srcs = [
+        "java_tools/ijar/classfile.cc",
+        "java_tools/ijar/ijar.cc",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    linkstatic = 1,  # provides main()
+    deps = [":zip"],
+    alwayslink = 1,
+)
+
+cc_binary(
+    name = "ijar_cc_binary",
+    deps = [":ijar_cc_binary_main"],
+)
+
+cc_library(
+    name = "zip",
+    srcs = [
+        "java_tools/ijar/zip.cc",
+    ] + select({
+        ":windows": [
+            "java_tools/ijar/mapped_file_windows.cc",
+        ],
+        "//conditions:default": [
+            "java_tools/ijar/mapped_file_unix.cc",
+        ],
+    }),
+    hdrs = [
+        "java_tools/ijar/common.h",
+        "java_tools/ijar/mapped_file.h",
+        "java_tools/ijar/zip.h",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    include_prefix = "third_party",
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":platform_utils",
+        ":zlib_client",
+    ] + select({
+        ":windows": [
+            ":errors",
+            ":filesystem",
+            ":logging",
+            ":strings",
+        ],
+        "//conditions:default": [
+        ],
+    }),
+)
+
+cc_library(
+    name = "platform_utils",
+    srcs = ["java_tools/ijar/platform_utils.cc"],
+    hdrs = [
+        "java_tools/ijar/common.h",
+        "java_tools/ijar/platform_utils.h",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    include_prefix = "third_party",
+    strip_include_prefix = "java_tools",
+    visibility = ["//visibility:private"],
+    deps = [
+        ":errors",
+        ":filesystem",
+        ":logging",
+    ],
+)
+
+cc_library(
+    name = "cpp_util",
+    hdrs = [
+        "java_tools/src/main/cpp/util/errors.h",
+        "java_tools/src/main/cpp/util/file.h",
+        "java_tools/src/main/cpp/util/file_platform.h",
+        "java_tools/src/main/cpp/util/md5.h",
+        "java_tools/src/main/cpp/util/numbers.h",
+        "java_tools/src/main/cpp/util/path.h",
+        "java_tools/src/main/cpp/util/path_platform.h",
+        "java_tools/src/main/cpp/util/port.h",
+    ],
+    strip_include_prefix = "java_tools",
+    visibility = ["//visibility:public"],
+    deps = [
+        ":blaze_exit_code",
+        ":errors",
+        ":filesystem",
+        ":md5",
+        ":numbers",
+        ":port",
+        ":strings",
+    ],
+)
+
+cc_library(
+    name = "md5",
+    srcs = ["java_tools/src/main/cpp/util/md5.cc"],
+    hdrs = ["java_tools/src/main/cpp/util/md5.h"],
+    strip_include_prefix = "java_tools",
+)
+
+cc_library(
+    name = "numbers",
+    srcs = ["java_tools/src/main/cpp/util/numbers.cc"],
+    hdrs = ["java_tools/src/main/cpp/util/numbers.h"],
+    strip_include_prefix = "java_tools",
+    deps = [":strings"],
+)
+
+cc_library(
+    name = "filesystem",
+    srcs = [
+        "java_tools/src/main/cpp/util/file.cc",
+        "java_tools/src/main/cpp/util/path.cc",
+    ] + select({
+        ":windows": [
+            "java_tools/src/main/cpp/util/file_windows.cc",
+            "java_tools/src/main/cpp/util/path_windows.cc",
+        ],
+        "//conditions:default": [
+            "java_tools/src/main/cpp/util/file_posix.cc",
+            "java_tools/src/main/cpp/util/path_posix.cc",
+        ],
+    }),
+    hdrs = [
+        "java_tools/src/main/cpp/util/file.h",
+        "java_tools/src/main/cpp/util/file_platform.h",
+        "java_tools/src/main/cpp/util/path.h",
+        "java_tools/src/main/cpp/util/path_platform.h",
+    ],
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":blaze_exit_code",
+        ":errors",
+        ":logging",
+        ":strings",
+    ] + select({
+        ":windows": [":lib-file"],
+        "//conditions:default": [],
+    }),
+)
+
+cc_library(
+    name = "lib-file",
+    srcs = [
+        "java_tools/src/main/native/windows/file.cc",
+        "java_tools/src/main/native/windows/util.cc",
+    ],
+    hdrs = [
+        "java_tools/src/main/native/windows/file.h",
+        "java_tools/src/main/native/windows/util.h",
+    ],
+    linkopts = [
+        "-DEFAULTLIB:advapi32.lib",
+    ],
+    strip_include_prefix = "java_tools",
+)
+
+cc_library(
+    name = "errors",
+    srcs = select({
+        ":windows": ["java_tools/src/main/cpp/util/errors_windows.cc"],
+        "//conditions:default": ["java_tools/src/main/cpp/util/errors_posix.cc"],
+    }),
+    hdrs = ["java_tools/src/main/cpp/util/errors.h"],
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":logging",
+        ":port",
+        ":strings",
+    ],
+)
+
+cc_library(
+    name = "strings",
+    srcs = ["java_tools/src/main/cpp/util/strings.cc"],
+    hdrs = ["java_tools/src/main/cpp/util/strings.h"],
+    copts = SUPRESSED_WARNINGS,
+    # Automatically propagate the symbol definition to rules depending on this.
+    defines = [
+        "BLAZE_OPENSOURCE",
+    ],
+    strip_include_prefix = "java_tools",
+    deps = [":blaze_exit_code"],
+)
+
+cc_library(
+    name = "blaze_exit_code",
+    hdrs = ["java_tools/src/main/cpp/util/exit_code.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+)
+
+cc_library(
+    name = "port",
+    srcs = ["java_tools/src/main/cpp/util/port.cc"],
+    hdrs = ["java_tools/src/main/cpp/util/port.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+)
+
+cc_library(
+    name = "logging",
+    srcs = ["java_tools/src/main/cpp/util/logging.cc"],
+    hdrs = ["java_tools/src/main/cpp/util/logging.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":blaze_exit_code",
+        ":strings",
+    ],
+)
+
+cc_library(
+    name = "zlib_client",
+    srcs = ["java_tools/ijar/zlib_client.cc"],
+    hdrs = [
+        "java_tools/ijar/common.h",
+        "java_tools/ijar/zlib_client.h",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    include_prefix = "third_party",
+    strip_include_prefix = "java_tools",
+    deps = ["//java_tools/zlib"],
+)
+
+##################### singlejar
+
+# See comment for ":ijar_cc_binary_main".
+cc_library(
+    name = "singlejar_cc_bin_main",
+    srcs = [
+        "java_tools/src/tools/singlejar/singlejar_main.cc",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    linkopts = select({
+        ":freebsd": ["-lm"],
+        ":openbsd": ["-lm"],
+        "//conditions:default": [],
+    }),
+    linkstatic = 1,  # provides main()
+    deps = [
+        ":combiners",
+        ":diag",
+        ":options",
+        ":output_jar",
+        "//java_tools/zlib",
+    ],
+    alwayslink = 1,
+)
+
+cc_binary(
+    name = "singlejar_cc_bin",
+    linkstatic = 1,
+    visibility = ["//visibility:public"],
+    deps = [":singlejar_cc_bin_main"],
+)
+
+cc_binary(
+    name = "singlejar_local",
+    srcs = [
+        "java_tools/src/tools/singlejar/singlejar_local_main.cc",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    linkopts = select({
+        ":freebsd": ["-lm"],
+        ":openbsd": ["-lm"],
+        "//conditions:default": [],
+    }),
+    linkstatic = 1,
+    visibility = ["//visibility:public"],
+    deps = [
+        ":combiners",
+        ":desugar_checking",
+        ":options",
+        ":output_jar",
+        "//java_tools/zlib",
+    ],
+)
+
+cc_library(
+    name = "combiners",
+    srcs = [
+        "java_tools/src/tools/singlejar/combiners.cc",
+    ],
+    hdrs = [
+        "java_tools/src/tools/singlejar/combiners.h",
+        ":transient_bytes",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        "//java_tools/zlib",
+    ],
+)
+
+proto_library(
+    name = "desugar_deps_proto",
+    srcs = ["java_tools/src/main/protobuf/desugar_deps.proto"],
+)
+
+cc_proto_library(
+    name = "desugar_deps_cc_proto",
+    deps = [":desugar_deps_proto"],
+)
+
+cc_library(
+    name = "desugar_checking",
+    srcs = ["java_tools/src/tools/singlejar/desugar_checking.cc"],
+    hdrs = ["java_tools/src/tools/singlejar/desugar_checking.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":combiners",
+        ":desugar_deps_cc_proto",
+    ],
+)
+
+cc_library(
+    name = "diag",
+    hdrs = ["java_tools/src/tools/singlejar/diag.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    visibility = ["//visibility:private"],
+)
+
+cc_library(
+    name = "singlejar_port",
+    hdrs = ["java_tools/src/tools/singlejar/port.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    visibility = ["//visibility:private"],
+)
+
+cc_library(
+    name = "mapped_file",
+    srcs = ["java_tools/src/tools/singlejar/mapped_file.cc"],
+    hdrs = ["java_tools/src/tools/singlejar/mapped_file.h"] +
+           select({
+               ":windows": ["java_tools/src/tools/singlejar/mapped_file_windows.inc"],
+               "//conditions:default": ["java_tools/src/tools/singlejar/mapped_file_posix.inc"],
+           }),
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    visibility = ["//visibility:private"],
+    deps = [
+        ":cpp_util",
+        ":diag",
+        ":singlejar_port",
+    ],
+)
+
+cc_library(
+    name = "input_jar",
+    srcs = [
+        "java_tools/src/tools/singlejar/input_jar.cc",
+    ],
+    hdrs = [
+        "java_tools/src/tools/singlejar/input_jar.h",
+        "java_tools/src/tools/singlejar/zip_headers.h",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":diag",
+        ":mapped_file",
+    ],
+)
+
+cc_library(
+    name = "options",
+    srcs = [
+        "java_tools/src/tools/singlejar/options.cc",
+        "java_tools/src/tools/singlejar/options.h",
+    ],
+    hdrs = ["java_tools/src/tools/singlejar/options.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":diag",
+        ":token_stream",
+    ],
+)
+
+cc_library(
+    name = "output_jar",
+    srcs = [
+        "java_tools/src/tools/singlejar/output_jar.cc",
+        "java_tools/src/tools/singlejar/output_jar.h",
+        ":zip_headers",
+    ],
+    hdrs = ["java_tools/src/tools/singlejar/output_jar.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":combiners",
+        ":cpp_util",
+        ":diag",
+        ":input_jar",
+        ":mapped_file",
+        ":options",
+        ":singlejar_port",
+        "//java_tools/zlib",
+    ],
+)
+
+cc_library(
+    name = "token_stream",
+    hdrs = ["java_tools/src/tools/singlejar/token_stream.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":diag",
+        ":filesystem",
+    ],
+)
+
+filegroup(
+    name = "transient_bytes",
+    srcs = [
+        "java_tools/src/tools/singlejar/diag.h",
+        "java_tools/src/tools/singlejar/transient_bytes.h",
+        "java_tools/src/tools/singlejar/zlib_interface.h",
+        ":zip_headers",
+    ],
+)
+
+filegroup(
+    name = "zip_headers",
+    srcs = ["java_tools/src/tools/singlejar/zip_headers.h"],
+)
+
+################### Proguard ###################
+java_import(
+    name = "proguard_import",
+    jars = ["java_tools/third_party/java/proguard/proguard.jar"],
+)
+
+java_binary(
+    name = "proguard",
+    main_class = "proguard.ProGuard",
+    visibility = ["//visibility:public"],
+    runtime_deps = [":proguard_import"],
+)
+
+##################### one_version
+
+# See comment for ":ijar_cc_binary_main".
+cc_library(
+    name = "one_version_cc_bin_main",
+    srcs = [
+        "java_tools/src/tools/one_version/one_version_main.cc",
+    ],
+    copts = SUPRESSED_WARNINGS,
+    linkopts = select({
+        ":freebsd": ["-lm"],
+        ":openbsd": ["-lm"],
+        "//conditions:default": [],
+    }),
+    linkstatic = 1,  # provides main()
+    deps = [
+        ":allowlist",
+        ":duplicate_class_collector",
+        ":input_jar",
+        ":one_version",
+        ":token_stream",
+        "@com_google_absl//absl/container:flat_hash_map",
+        "@com_google_absl//absl/container:flat_hash_set",
+        "@com_google_absl//absl/log:die_if_null",
+        "@com_google_absl//absl/strings",
+    ],
+    alwayslink = 1,
+)
+
+cc_binary(
+    name = "one_version_cc_bin",
+    linkstatic = 1,
+    visibility = ["//visibility:public"],
+    deps = [":one_version_cc_bin_main"],
+)
+
+cc_library(
+    name = "duplicate_class_collector",
+    srcs = ["java_tools/src/tools/one_version/duplicate_class_collector.cc"],
+    hdrs = ["java_tools/src/tools/one_version/duplicate_class_collector.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        "@com_google_absl//absl/container:flat_hash_map",
+        "@com_google_absl//absl/strings",
+    ],
+)
+
+cc_library(
+    name = "allowlist",
+    srcs = ["java_tools/src/tools/one_version/allowlist.cc"],
+    hdrs = ["java_tools/src/tools/one_version/allowlist.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":duplicate_class_collector",
+        "@com_google_absl//absl/container:flat_hash_map",
+        "@com_google_absl//absl/container:flat_hash_set",
+        "@com_google_absl//absl/strings",
+        "@com_google_absl//absl/types:span",
+    ],
+)
+
+cc_library(
+    name = "one_version",
+    srcs = ["java_tools/src/tools/one_version/one_version.cc"],
+    hdrs = ["java_tools/src/tools/one_version/one_version.h"],
+    copts = SUPRESSED_WARNINGS,
+    strip_include_prefix = "java_tools",
+    deps = [
+        ":allowlist",
+        ":duplicate_class_collector",
+        ":input_jar",
+        "@com_google_absl//absl/log:die_if_null",
+        "@com_google_absl//absl/memory",
+        "@com_google_absl//absl/strings",
+    ],
+)
diff --git a/toolchains/bootclasspath.bzl b/toolchains/bootclasspath.bzl
new file mode 100644
index 0000000..b6f57e0
--- /dev/null
+++ b/toolchains/bootclasspath.bzl
@@ -0,0 +1,246 @@
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
+"""Rules for extracting a platform classpath from Java runtimes."""
+
+load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
+load("//java/common:java_common.bzl", "java_common")
+load(":utf8_environment.bzl", "Utf8EnvironmentInfo")
+
+visibility("private")
+
+# TODO: This provider and is only necessary since --java_{language,runtime}_version
+# are not available directly to Starlark.
+_JavaVersionsInfo = provider(
+    "Exposes the --java_{language,runtime}_version value as extracted from a transition to a dependant.",
+    fields = {
+        "java_language_version": "The value of --java_language_version",
+        "java_runtime_version": "The value of --java_runtime_version",
+    },
+)
+
+def _language_version_bootstrap_runtime(ctx):
+    providers = [
+        _JavaVersionsInfo(
+            java_language_version = ctx.attr.java_language_version[BuildSettingInfo].value,
+            java_runtime_version = ctx.attr.java_runtime_version[BuildSettingInfo].value,
+        ),
+    ]
+
+    bootstrap_runtime = ctx.toolchains["@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type"]
+    if bootstrap_runtime:
+        providers.append(bootstrap_runtime.java_runtime)
+
+    return providers
+
+language_version_bootstrap_runtime = rule(
+    implementation = _language_version_bootstrap_runtime,
+    attrs = {
+        "java_language_version": attr.label(
+            providers = [BuildSettingInfo],
+        ),
+        "java_runtime_version": attr.label(
+            providers = [BuildSettingInfo],
+        ),
+    },
+    toolchains = [
+        config_common.toolchain_type("@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type", mandatory = False),
+    ],
+)
+
+def _get_bootstrap_runtime_version(*, java_language_version, java_runtime_version):
+    """Returns the runtime version to use for bootstrapping the given language version.
+
+    If the runtime version is not versioned, e.g. "local_jdk", it is used as is.
+    Otherwise, the language version replaces the numeric part of the runtime version, e.g.,
+    "remotejdk_17" becomes "remotejdk_8".
+    """
+    prefix, separator, version = java_runtime_version.rpartition("_")
+    if version and version.isdigit():
+        new_version = java_language_version
+    else:
+        # The runtime version is not versioned, e.g. "local_jdk". Use it as is.
+        new_version = version
+
+    return prefix + separator + new_version
+
+def _bootclasspath_transition_impl(settings, _):
+    java_language_version = settings["//command_line_option:java_language_version"]
+    java_runtime_version = settings["//command_line_option:java_runtime_version"]
+
+    return {
+        "//command_line_option:java_runtime_version": _get_bootstrap_runtime_version(
+            java_language_version = java_language_version,
+            java_runtime_version = java_runtime_version,
+        ),
+        "//toolchains:java_language_version": java_language_version,
+        "//toolchains:java_runtime_version": java_runtime_version,
+    }
+
+_bootclasspath_transition = transition(
+    implementation = _bootclasspath_transition_impl,
+    inputs = [
+        "//command_line_option:java_language_version",
+        "//command_line_option:java_runtime_version",
+    ],
+    outputs = [
+        "//command_line_option:java_runtime_version",
+        "//toolchains:java_language_version",
+        "//toolchains:java_runtime_version",
+    ],
+)
+
+_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE = Label("@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type")
+
+# Opt the Java bootstrap actions into path mapping:
+# https://github.com/bazelbuild/bazel/commit/a239ea84832f18ee8706682145e9595e71b39680
+_SUPPORTS_PATH_MAPPING = {"supports-path-mapping": "1"}
+
+def _java_home(java_executable):
+    return java_executable.dirname[:-len("/bin")]
+
+def _bootclasspath_impl(ctx):
+    exec_javabase = ctx.attr.java_runtime_alias[java_common.JavaRuntimeInfo]
+    env = ctx.attr._utf8_environment[Utf8EnvironmentInfo].environment
+
+    class_dir = ctx.actions.declare_directory("%s_classes" % ctx.label.name)
+
+    args = ctx.actions.args()
+    args.add("-source")
+    args.add("8")
+    args.add("-target")
+    args.add("8")
+    args.add("-Xlint:-options")
+    args.add("-J-XX:-UsePerfData")
+    args.add("-d")
+    args.add_all([class_dir], expand_directories = False)
+    args.add(ctx.file.src)
+
+    ctx.actions.run(
+        executable = "%s/bin/javac" % exec_javabase.java_home,
+        mnemonic = "JavaToolchainCompileClasses",
+        inputs = [ctx.file.src] + ctx.files.java_runtime_alias,
+        outputs = [class_dir],
+        arguments = [args],
+        env = env,
+        execution_requirements = _SUPPORTS_PATH_MAPPING,
+    )
+
+    bootclasspath = ctx.outputs.output_jar
+
+    args = ctx.actions.args()
+    args.add("-XX:+IgnoreUnrecognizedVMOptions")
+    args.add("-XX:-UsePerfData")
+    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED")
+    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.platform=ALL-UNNAMED")
+    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED")
+    args.add_all("-cp", [class_dir], expand_directories = False)
+    args.add("DumpPlatformClassPath")
+    args.add(bootclasspath)
+
+    if ctx.attr.language_version_bootstrap_runtime:
+        # The attribute is subject to a split transition.
+        language_version_bootstrap_runtime = ctx.attr.language_version_bootstrap_runtime[0]
+        if java_common.JavaRuntimeInfo in language_version_bootstrap_runtime:
+            any_javabase = language_version_bootstrap_runtime[java_common.JavaRuntimeInfo]
+        else:
+            java_versions_info = language_version_bootstrap_runtime[_JavaVersionsInfo]
+            bootstrap_runtime_version = _get_bootstrap_runtime_version(
+                java_language_version = java_versions_info.java_language_version,
+                java_runtime_version = java_versions_info.java_runtime_version,
+            )
+            is_exec = "-exec" in ctx.bin_dir.path
+            tool_prefix = "tool_" if is_exec else ""
+            fail("""
+No Java runtime found to extract the bootclasspath from for --{tool_prefix}java_language_version={language_version} and --{tool_prefix}java_runtime_version={runtime_version}.
+You can:
+
+    * register a Java runtime with name "{bootstrap_runtime_version}" to provide the bootclasspath or
+    * set --java_language_version to the Java version of an available runtime.
+
+Rerun with --toolchain_resolution_debug='@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type' to see more details about toolchain resolution.
+""".format(
+                language_version = java_versions_info.java_language_version,
+                runtime_version = java_versions_info.java_runtime_version,
+                bootstrap_runtime_version = bootstrap_runtime_version,
+                tool_prefix = tool_prefix,
+            ))
+    else:
+        any_javabase = ctx.toolchains[_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE].java_runtime
+    any_javabase_files = any_javabase.files.to_list()
+
+    # If possible, add the Java executable to the command line as a File so that it can be path
+    # mapped.
+    java_executable = [f for f in any_javabase_files if f.path == any_javabase.java_executable_exec_path]
+    if len(java_executable) == 1:
+        args.add_all(java_executable, map_each = _java_home)
+    else:
+        args.add(any_javabase.java_home)
+
+    system_files = ("release", "modules", "jrt-fs.jar")
+    system = [f for f in any_javabase_files if f.basename in system_files]
+    if len(system) != len(system_files):
+        system = None
+
+    inputs = depset([class_dir] + ctx.files.java_runtime_alias, transitive = [any_javabase.files])
+    ctx.actions.run(
+        executable = str(exec_javabase.java_executable_exec_path),
+        mnemonic = "JavaToolchainCompileBootClasspath",
+        inputs = inputs,
+        outputs = [bootclasspath],
+        arguments = [args],
+        env = env,
+        execution_requirements = _SUPPORTS_PATH_MAPPING,
+    )
+    return [
+        DefaultInfo(files = depset([bootclasspath])),
+        java_common.BootClassPathInfo(
+            bootclasspath = [bootclasspath],
+            system = system,
+        ),
+        OutputGroupInfo(jar = [bootclasspath]),
+    ]
+
+_bootclasspath = rule(
+    implementation = _bootclasspath_impl,
+    attrs = {
+        "java_runtime_alias": attr.label(
+            cfg = "exec",
+            providers = [java_common.JavaRuntimeInfo],
+        ),
+        "language_version_bootstrap_runtime": attr.label(
+            cfg = _bootclasspath_transition,
+        ),
+        "output_jar": attr.output(mandatory = True),
+        "src": attr.label(
+            cfg = "exec",
+            allow_single_file = True,
+        ),
+        "_allowlist_function_transition": attr.label(
+            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
+        ),
+        "_utf8_environment": attr.label(
+            default = ":utf8_environment",
+            cfg = "exec",
+        ),
+    },
+    toolchains = [_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE],
+)
+
+def bootclasspath(name, **kwargs):
+    _bootclasspath(
+        name = name,
+        output_jar = name + ".jar",
+        **kwargs
+    )
diff --git a/toolchains/default_java_toolchain.bzl b/toolchains/default_java_toolchain.bzl
index 020b101..4ec8961 100644
--- a/toolchains/default_java_toolchain.bzl
+++ b/toolchains/default_java_toolchain.bzl
@@ -14,8 +14,8 @@
 
 """Rules for defining default_java_toolchain"""
 
-load("//java:defs.bzl", "java_toolchain")
-load("//java/common:java_common.bzl", "java_common")
+load("//java/toolchains:java_toolchain.bzl", "java_toolchain")
+load(":bootclasspath.bzl", _bootclasspath = "bootclasspath")
 
 # JVM options, without patching java.compiler and jdk.compiler modules.
 BASE_JDK9_JVM_OPTS = [
@@ -56,6 +56,7 @@ JDK9_JVM_OPTS = BASE_JDK9_JVM_OPTS
 DEFAULT_JAVACOPTS = [
     "-XDskipDuplicateBridges=true",
     "-XDcompilePolicy=simple",
+    "--should-stop=ifError=FLOW",  # See b/27049950, https://github.com/google/error-prone/issues/4595
     "-g",
     "-parameters",
     # https://github.com/bazelbuild/bazel/issues/15219
@@ -68,6 +69,10 @@ DEFAULT_JAVACOPTS = [
     "-Xep:UseCorrectAssertInTests:OFF",
 ]
 
+# If this is changed, the docs for "{,tool_}java_language_version" also
+# need to be updated in the Bazel user manual
+_DEFAULT_JAVA_LANGUAGE_VERSION = "11"
+
 # Default java_toolchain parameters
 _BASE_TOOLCHAIN_CONFIGURATION = dict(
     forcibly_disable_header_compilation = False,
@@ -88,12 +93,13 @@ _BASE_TOOLCHAIN_CONFIGURATION = dict(
     # Code to enumerate target JVM boot classpath uses host JVM. Because
     # java_runtime-s are involved, its implementation is in @bazel_tools.
     bootclasspath = [Label("//toolchains:platformclasspath")],
-    source_version = "8",
-    target_version = "8",
+    source_version = _DEFAULT_JAVA_LANGUAGE_VERSION,
+    target_version = _DEFAULT_JAVA_LANGUAGE_VERSION,
     reduced_classpath_incompatible_processors = [
         "dagger.hilt.processor.internal.root.RootProcessor",  # see b/21307381
     ],
     java_runtime = Label("//toolchains:remotejdk_21"),
+    oneversion = Label("//toolchains:one_version"),
 )
 
 DEFAULT_TOOLCHAIN_CONFIGURATION = _BASE_TOOLCHAIN_CONFIGURATION
@@ -125,6 +131,7 @@ VANILLA_TOOLCHAIN_CONFIGURATION = dict(
 PREBUILT_TOOLCHAIN_CONFIGURATION = dict(
     ijar = [Label("//toolchains:ijar_prebuilt_binary")],
     singlejar = [Label("//toolchains:prebuilt_singlejar")],
+    oneversion = Label("//toolchains:prebuilt_one_version"),
 )
 
 # The new toolchain is using all the tools from sources.
@@ -132,12 +139,9 @@ NONPREBUILT_TOOLCHAIN_CONFIGURATION = dict(
     ijar = [Label("@remote_java_tools//:ijar_cc_binary")],
     singlejar = [Label("@remote_java_tools//:singlejar_cc_bin")],
     header_compiler_direct = [Label("@remote_java_tools//:TurbineDirect")],
+    oneversion = Label("@remote_java_tools//:one_version_cc_bin"),
 )
 
-# If this is changed, the docs for "{,tool_}java_language_version" also
-# need to be updated in the Bazel user manual
-_DEFAULT_SOURCE_VERSION = "8"
-
 def default_java_toolchain(name, configuration = DEFAULT_TOOLCHAIN_CONFIGURATION, toolchain_definition = True, exec_compatible_with = [], target_compatible_with = [], **kwargs):
     """Defines a remote java_toolchain with appropriate defaults for Bazel.
 
@@ -161,7 +165,7 @@ def default_java_toolchain(name, configuration = DEFAULT_TOOLCHAIN_CONFIGURATION
     )
     if toolchain_definition:
         source_version = toolchain_args["source_version"]
-        if source_version == _DEFAULT_SOURCE_VERSION:
+        if source_version == _DEFAULT_JAVA_LANGUAGE_VERSION:
             native.config_setting(
                 name = name + "_default_version_setting",
                 values = {"java_language_version": ""},
@@ -208,94 +212,4 @@ def java_runtime_files(name, srcs):
             tags = ["manual"],
         )
 
-_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE = Label("@bazel_tools//tools/jdk:bootstrap_runtime_toolchain_type")
-
-# Opt the Java bootstrap actions into path mapping:
-# https://github.com/bazelbuild/bazel/commit/a239ea84832f18ee8706682145e9595e71b39680
-_SUPPORTS_PATH_MAPPING = {"supports-path-mapping": "1"}
-
-def _bootclasspath_impl(ctx):
-    exec_javabase = ctx.attr.java_runtime_alias[java_common.JavaRuntimeInfo]
-
-    class_dir = ctx.actions.declare_directory("%s_classes" % ctx.label.name)
-
-    args = ctx.actions.args()
-    args.add("-source")
-    args.add("8")
-    args.add("-target")
-    args.add("8")
-    args.add("-Xlint:-options")
-    args.add("-J-XX:-UsePerfData")
-    args.add("-d")
-    args.add_all([class_dir], expand_directories = False)
-    args.add(ctx.file.src)
-
-    ctx.actions.run(
-        executable = "%s/bin/javac" % exec_javabase.java_home,
-        mnemonic = "JavaToolchainCompileClasses",
-        inputs = [ctx.file.src] + ctx.files.java_runtime_alias,
-        outputs = [class_dir],
-        arguments = [args],
-        execution_requirements = _SUPPORTS_PATH_MAPPING,
-    )
-
-    bootclasspath = ctx.outputs.output_jar
-
-    args = ctx.actions.args()
-    args.add("-XX:+IgnoreUnrecognizedVMOptions")
-    args.add("-XX:-UsePerfData")
-    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED")
-    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.platform=ALL-UNNAMED")
-    args.add("--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED")
-    args.add_all("-cp", [class_dir], expand_directories = False)
-    args.add("DumpPlatformClassPath")
-    args.add(bootclasspath)
-
-    any_javabase = ctx.toolchains[_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE].java_runtime
-    args.add(any_javabase.java_home)
-
-    system_files = ("release", "modules", "jrt-fs.jar")
-    system = [f for f in any_javabase.files.to_list() if f.basename in system_files]
-    if len(system) != len(system_files):
-        system = None
-
-    inputs = depset([class_dir] + ctx.files.java_runtime_alias, transitive = [any_javabase.files])
-    ctx.actions.run(
-        executable = str(exec_javabase.java_executable_exec_path),
-        mnemonic = "JavaToolchainCompileBootClasspath",
-        inputs = inputs,
-        outputs = [bootclasspath],
-        arguments = [args],
-        execution_requirements = _SUPPORTS_PATH_MAPPING,
-    )
-    return [
-        DefaultInfo(files = depset([bootclasspath])),
-        java_common.BootClassPathInfo(
-            bootclasspath = [bootclasspath],
-            system = system,
-        ),
-        OutputGroupInfo(jar = [bootclasspath]),
-    ]
-
-_bootclasspath = rule(
-    implementation = _bootclasspath_impl,
-    attrs = {
-        "java_runtime_alias": attr.label(
-            cfg = "exec",
-            providers = [java_common.JavaRuntimeInfo],
-        ),
-        "output_jar": attr.output(mandatory = True),
-        "src": attr.label(
-            cfg = "exec",
-            allow_single_file = True,
-        ),
-    },
-    toolchains = [_JAVA_BOOTSTRAP_RUNTIME_TOOLCHAIN_TYPE],
-)
-
-def bootclasspath(name, **kwargs):
-    _bootclasspath(
-        name = name,
-        output_jar = name + ".jar",
-        **kwargs
-    )
+bootclasspath = _bootclasspath
diff --git a/toolchains/java_toolchain_alias.bzl b/toolchains/java_toolchain_alias.bzl
index 8d8a7e4..3488925 100644
--- a/toolchains/java_toolchain_alias.bzl
+++ b/toolchains/java_toolchain_alias.bzl
@@ -85,6 +85,9 @@ java_runtime_version_alias = rule(
     toolchains = ["@bazel_tools//tools/jdk:runtime_toolchain_type"],
     attrs = {
         "runtime_version": attr.string(mandatory = True),
+        "_allowlist_function_transition": attr.label(
+            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
+        ),
     },
     cfg = _java_runtime_transition,
 )
diff --git a/toolchains/jdk_build_file.bzl b/toolchains/jdk_build_file.bzl
index 1e08f37..c0ed160 100644
--- a/toolchains/jdk_build_file.bzl
+++ b/toolchains/jdk_build_file.bzl
@@ -14,7 +14,7 @@
 
 """A templated BUILD file for Java repositories."""
 
-JDK_BUILD_TEMPLATE = """load("@rules_java//java:defs.bzl", "java_runtime")
+JDK_BUILD_TEMPLATE = """load("@rules_java//java/toolchains:java_runtime.bzl", "java_runtime")
 
 package(default_visibility = ["//visibility:public"])
 
diff --git a/toolchains/local_java_repository.bzl b/toolchains/local_java_repository.bzl
index 3f28baa..627f8ab 100644
--- a/toolchains/local_java_repository.bzl
+++ b/toolchains/local_java_repository.bzl
@@ -14,7 +14,7 @@
 
 """Rules for importing a local JDK."""
 
-load("//java:defs.bzl", "java_runtime")
+load("//java/toolchains:java_runtime.bzl", "java_runtime")
 load(":default_java_toolchain.bzl", "default_java_toolchain")
 
 def _detect_java_version(repository_ctx, java_bin):
@@ -178,8 +178,7 @@ def _local_java_repository_impl(repository_ctx):
 
     java_home = _determine_java_home(repository_ctx)
 
-    # When Bzlmod is enabled, the Java runtime name should be the last segment of the repository name.
-    local_java_runtime_name = repository_ctx.name.split("~")[-1]
+    local_java_runtime_name = repository_ctx.attr.runtime_name
 
     repository_ctx.file(
         "WORKSPACE",
@@ -293,6 +292,7 @@ _local_java_repository_rule = repository_rule(
     configure = True,
     environ = ["JAVA_HOME"],
     attrs = {
+        "runtime_name": attr.string(),
         "build_file": attr.label(),
         "build_file_content": attr.string(),
         "java_home": attr.string(),
@@ -332,4 +332,4 @@ def local_java_repository(name, java_home = "", version = "", build_file = None,
       version: optionally java version
       **kwargs: additional arguments for repository rule
     """
-    _local_java_repository_rule(name = name, java_home = java_home, version = version, build_file = build_file, build_file_content = build_file_content, **kwargs)
+    _local_java_repository_rule(name = name, runtime_name = name, java_home = java_home, version = version, build_file = build_file, build_file_content = build_file_content, **kwargs)
diff --git a/toolchains/utf8_environment.bzl b/toolchains/utf8_environment.bzl
new file mode 100644
index 0000000..5b4d554
--- /dev/null
+++ b/toolchains/utf8_environment.bzl
@@ -0,0 +1,48 @@
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
+"""
+Determines the environment required for Java actions to support UTF-8.
+"""
+
+visibility("private")
+
+Utf8EnvironmentInfo = provider(
+    doc = "The environment required for Java actions to support UTF-8.",
+    fields = {
+        "environment": "The environment to use for Java actions to support UTF-8.",
+    },
+)
+
+# The default UTF-8 locale on all recent Linux distributions. It is also available in Cygwin and
+# MSYS2, but doesn't matter for determining the JVM's platform encoding on Windows, which always
+# uses the active code page.
+_DEFAULT_UTF8_ENVIRONMENT = Utf8EnvironmentInfo(environment = {"LC_CTYPE": "C.UTF-8"})
+
+# macOS doesn't have the C.UTF-8 locale, but en_US.UTF-8 is available and works the same way.
+_MACOS_UTF8_ENVIRONMENT = Utf8EnvironmentInfo(environment = {"LC_CTYPE": "en_US.UTF-8"})
+
+def _utf8_environment_impl(ctx):
+    if ctx.target_platform_has_constraint(ctx.attr._macos_constraint[platform_common.ConstraintValueInfo]):
+        return _MACOS_UTF8_ENVIRONMENT
+    else:
+        return _DEFAULT_UTF8_ENVIRONMENT
+
+utf8_environment = rule(
+    _utf8_environment_impl,
+    attrs = {
+        "_macos_constraint": attr.label(default = "@platforms//os:macos"),
+    },
+    doc = "Returns a suitable environment for Java actions to support UTF-8.",
+)
```

