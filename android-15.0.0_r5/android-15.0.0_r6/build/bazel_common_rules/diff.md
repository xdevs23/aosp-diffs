```diff
diff --git a/OWNERS b/OWNERS
index a9c7465..8577705 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,5 @@
-# Platform build
-include platform/build/soong:/OWNERS
-
 # Kernel build
 #
 # The kernel follows a different branching model than that of platform, which
-# needs the 'master' branch to be explicitly declared.
+# needs the 'main' branch to be explicitly declared.
 include kernel/build:main:/OWNERS
diff --git a/README.md b/README.md
index 21dbb5a..70efe6b 100644
--- a/README.md
+++ b/README.md
@@ -1,11 +1,7 @@
 # Bazel Common Rules
 
-This directory contains common Bazel rules and tools shared between the Platform
-and Kernel builds.
-
-For platform-specific rules, place them in the platform checkout's
-[//build/bazel/rules](https://android.googlesource.com/platform/build/bazel/+/master/rules/)
-directory.
+This directory contains common Bazel rules and tools for Android Kernel builds
+and possibly other Bazel based builds.
 
 For kernel-specific rules, place them in kernel checkout's [//build/kleaf
 directory](https://android.googlesource.com/kernel/build/+/master/kleaf/).
diff --git a/dist/BUILD b/dist/BUILD
index 3f531ef..b12e866 100644
--- a/dist/BUILD
+++ b/dist/BUILD
@@ -1,5 +1,5 @@
-load(":dist.bzl", "copy_to_dist_dir")
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
+load(":dist.bzl", "copy_to_dist_dir")
 
 exports_files(["dist.py"])
 
@@ -8,7 +8,7 @@ bzl_library(
     srcs = ["dist.bzl"],
     visibility = ["//visibility:public"],
     deps = [
-        "//build/bazel_common_rules/exec:embedded_exec",
+        "//build/bazel_common_rules/exec/impl:embedded_exec",
         "@bazel_skylib//rules:copy_file",
     ],
 )
diff --git a/dist/dist.bzl b/dist/dist.bzl
index 154d09b..1d44d4c 100644
--- a/dist/dist.bzl
+++ b/dist/dist.bzl
@@ -13,6 +13,10 @@ def _label_list_to_manifest(lst):
     return all_dist_files, "\n".join([dist_file.short_path for dist_file in all_dist_files])
 
 def _generate_dist_manifest_impl(ctx):
+    if ctx.attr.archives:
+        # buildifier: disable=print
+        print("archives is deprecated. Please file a bug if you are using it.")
+
     # Create a manifest of dist files to differentiate them from other runfiles.
     dist_manifest = ctx.actions.declare_file(ctx.attr.name + "_dist_manifest.txt")
     all_dist_files, dist_manifest_content = _label_list_to_manifest(ctx.attr.data)
@@ -85,8 +89,13 @@ def copy_to_dist_dir(
     Args:
         name: name of this rule
         data: A list of labels, whose outputs are copied to `--dist_dir`.
-        archives: A list of labels, whose outputs are treated as tarballs and
+        archives: **DEPRECATED**. A list of labels, whose outputs are treated as tarballs and
           extracted to `--dist_dir`.
+
+          Deprecated:
+
+            This is deprecated due to inactive usage. If you are using it, please file
+            a bug.
         flat: If true, `--flat` is provided to the script by default. Flatten the distribution
           directory.
         strip_components: If specified, `--strip_components <prefix>` is provided to the script. Strip
@@ -94,8 +103,13 @@ def copy_to_dist_dir(
           (if specified).
         prefix: If specified, `--prefix <prefix>` is provided to the script by default. Path prefix
           to apply within dist_dir for copied files.
-        archive_prefix: If specified, `--archive_prefix <prefix>` is provided to the script by
+        archive_prefix: **DEPRECATED**. If specified, `--archive_prefix <prefix>` is provided to the script by
           default. Path prefix to apply within dist_dir for extracted archives.
+
+          Deprecated:
+
+            This is deprecated due to inactive usage. If you are using it, please file
+            a bug.
         dist_dir: If specified, `--dist_dir <dist_dir>` is provided to the script by default.
 
           In particular, if this is a relative path, it is interpreted as a relative path
@@ -170,6 +184,9 @@ def copy_to_dist_dir(
     if log != None:
         default_args += ["--log", log]
 
+    # Separate flags from BUILD with flags from command line
+    default_args.append("CMDLINE_FLAGS_SENTINEL")
+
     _generate_dist_manifest(
         name = name + "_dist_manifest",
         data = data,
diff --git a/dist/dist.py b/dist/dist.py
index c9f7be9..127e828 100644
--- a/dist/dist.py
+++ b/dist/dist.py
@@ -41,6 +41,31 @@ import pathlib
 import shutil
 import sys
 import tarfile
+import textwrap
+
+
+_CMDLINE_FLAGS_SENTINEL = "CMDLINE_FLAGS_SENTINEL"
+
+# Arguments that should not be specified in the command line, but only
+# in BUILD files.
+_DEPRECATED_CMDLINE_OPTIONS = {
+    "--dist_dir": "Use --destdir instead.",
+    "--log": "Use -q instead.",
+    "--archive_prefix": "",
+    "--flat": "Specify it in the BUILD file (e.g. copy_to_dist_dir(flat=True))",
+    "--strip_components": "Specify it in the BUILD file "
+                          "(e.g. copy_to_dist_dir(strip_components=1))",
+    "--prefix": "Specify it in the BUILD file "
+                "(e.g. copy_to_dist_dir(prefix='prefix'))",
+    "--wipe_dist_dir": "Specify it in the BUILD file "
+                       "(e.g. copy_to_dist_dir(wipe_dist_dir=True))",
+    "--allow_duplicate_filenames":
+        "Specify it in the BUILD file "
+        "(e.g. copy_to_dist_dir(allow_duplicate_filenames=True))",
+    "--mode_override":
+        "Specify it in the BUILD file "
+        "(e.g. copy_to_dist_dir(mode_overrides=[('*.sh', '755')]))",
+}
 
 
 def copy_with_modes(src, dst, mode_overrides):
@@ -158,49 +183,113 @@ def config_logging(log_level_str):
     logging.basicConfig(level=level, format="[dist] %(levelname)s: %(message)s")
 
 
-def main():
+class CheckDeprecationAction(argparse.Action):
+    """Checks if a deprecated option is used, then do nothing."""
+    def __call__(self, parser, namespace, values, option_string=None):
+        if option_string in _DEPRECATED_CMDLINE_OPTIONS:
+            logging.warning("%s is deprecated! %s", option_string,
+                            _DEPRECATED_CMDLINE_OPTIONS[option_string])
+
+
+class StoreAndCheckDeprecationAction(CheckDeprecationAction):
+    """Sotres the value, and checks if a deprecated option is used."""
+    def __call__(self, parser, namespace, values, option_string=None):
+        super().__call__(parser, namespace, values, option_string)
+        setattr(namespace, self.dest, values)
+
+
+class StoreTrueAndCheckDeprecationAction(CheckDeprecationAction):
+    """Sotres true, and checks if a deprecated option is used."""
+    def __call__(self, parser, namespace, values, option_string=None):
+        super().__call__(parser, namespace, values, option_string)
+        setattr(namespace, self.dest, True)
+
+
+class AppendAndCheckDeprecationAction(CheckDeprecationAction):
+    """Appends the value, and checks if a deprecated option is used."""
+    def __call__(self, parser, namespace, values, option_string=None):
+        super().__call__(parser, namespace, values, option_string)
+        if not values:
+            return
+        metavar_len = len(self.metavar)if self.metavar else 1
+        value_groups = [values[i:i + metavar_len]
+                        for i in range(0, len(values), metavar_len)]
+        setattr(namespace, self.dest,
+                getattr(namespace, self.dest, []) + value_groups)
+
+
+def _get_parser(cmdline=False) -> argparse.ArgumentParser:
     parser = argparse.ArgumentParser(
-        description="Dist Bazel output files into a custom directory.")
+        description="Dist Bazel output files into a custom directory.",
+        formatter_class=argparse.RawTextHelpFormatter)
+    deprecated = parser.add_argument_group(
+        "Deprecated command line options",
+        description=textwrap.dedent("""\
+            List of command line options that are deprecated.
+            Most of them should be specified in the BUILD file instead.
+        """))
     parser.add_argument(
-        "--dist_dir", required=True, help="""path to the dist dir.
+        "--destdir", "--dist_dir", required=not cmdline, dest="dist_dir",
+        help=textwrap.dedent("""\
+            path to the dist dir.
             If relative, it is interpreted as relative to Bazel workspace root
             set by the BUILD_WORKSPACE_DIRECTORY environment variable, or
-            PWD if BUILD_WORKSPACE_DIRECTORY is not set.""")
-    parser.add_argument(
+            PWD if BUILD_WORKSPACE_DIRECTORY is not set.
+
+            Note: --dist_dir is deprecated; use --destdir instead."""),
+        action=StoreAndCheckDeprecationAction if cmdline else "store")
+    deprecated.add_argument(
         "--flat",
-        action="store_true",
+        action=StoreTrueAndCheckDeprecationAction if cmdline else "store_true",
         help="ignore subdirectories in the manifest")
-    parser.add_argument(
+    deprecated.add_argument(
         "--strip_components", type=int, default=0,
-        help="number of leading components to strip from paths before applying --prefix")
-    parser.add_argument(
+        help="number of leading components to strip from paths before applying --prefix",
+        action=StoreAndCheckDeprecationAction if cmdline else "store")
+    deprecated.add_argument(
         "--prefix", default="",
-        help="path prefix to apply within dist_dir for copied files")
-    parser.add_argument(
+        help="path prefix to apply within dist_dir for copied files",
+        action=StoreAndCheckDeprecationAction if cmdline else "store")
+    deprecated.add_argument(
         "--archive_prefix", default="",
         help="Path prefix to apply within dist_dir for extracted archives. " +
-             "Supported archives: tar.")
-    parser.add_argument("--log", help="Log level (debug, info, warning, error)", default="debug")
-    parser.add_argument(
+             "Supported archives: tar.",
+        action=StoreAndCheckDeprecationAction if cmdline else "store")
+    deprecated.add_argument("--log", help="Log level (debug, info, warning, error)",
+        default="debug",
+        action=StoreAndCheckDeprecationAction if cmdline else "store")
+    parser.add_argument("-q", "--quiet", action="store_const", default=False,
+                        help="Same as --log=error", const="error", dest="log")
+    deprecated.add_argument(
         "--wipe_dist_dir",
-        action="store_true",
-        help="remove existing dist_dir prior to running"
+        action=StoreTrueAndCheckDeprecationAction if cmdline else "store_true",
+        help="remove existing dist_dir prior to running",
     )
-    parser.add_argument(
+    deprecated.add_argument(
         "--allow_duplicate_filenames",
-        action="store_true",
+        action=StoreTrueAndCheckDeprecationAction if cmdline else "store_true",
         help="allow multiple files with the same name to be copied to dist_dir (overwriting)"
     )
-    parser.add_argument(
+    deprecated.add_argument(
         "--mode_override",
         metavar=("PATTERN", "MODE"),
-        action="append",
+        action=AppendAndCheckDeprecationAction if cmdline else "append",
         nargs=2,
         default=[],
         help='glob pattern and mode to set on files matching pattern (e.g. --mode_override "*.sh" "755")'
     )
+    return parser
 
-    args = parser.parse_args(sys.argv[1:])
+def main():
+    args = sys.argv[1:]
+    args.remove(_CMDLINE_FLAGS_SENTINEL)
+    args = _get_parser().parse_args(args)
+
+    config_logging(args.log)
+
+    # Warn about arguments that should not be set in command line.
+    _get_parser(cmdline=True).parse_args(
+        sys.argv[sys.argv.index(_CMDLINE_FLAGS_SENTINEL) + 1:])
 
     mode_overrides = []
     for (pattern, mode) in args.mode_override:
@@ -210,8 +299,6 @@ def main():
             logging.error("invalid octal permissions: %s", mode)
             sys.exit(1)
 
-    config_logging(args.log)
-
     if not os.path.isabs(args.dist_dir):
         # BUILD_WORKSPACE_DIRECTORY is the root of the Bazel workspace containing
         # this binary target.
diff --git a/exec/BUILD b/exec/BUILD
index bb4a111..1d51548 100644
--- a/exec/BUILD
+++ b/exec/BUILD
@@ -14,15 +14,6 @@
 
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
 
-bzl_library(
-    name = "exec_aspect",
-    srcs = ["exec_aspect.bzl"],
-    visibility = ["//visibility:public"],
-    deps = [
-        "//build/bazel_common_rules/exec/impl:exec_aspect",
-    ],
-)
-
 bzl_library(
     name = "embedded_exec",
     srcs = ["embedded_exec.bzl"],
@@ -33,14 +24,3 @@ bzl_library(
         "@bazel_skylib//lib:shell",
     ],
 )
-
-bzl_library(
-    name = "exec",
-    srcs = ["exec.bzl"],
-    visibility = ["//visibility:public"],
-    deps = [
-        ":exec_aspect",
-        "//build/bazel_common_rules/exec/impl:exec",
-        "@bazel_skylib//lib:shell",
-    ],
-)
diff --git a/exec/exec.bzl b/exec/exec.bzl
deleted file mode 100644
index f64cbdc..0000000
--- a/exec/exec.bzl
+++ /dev/null
@@ -1,164 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Helps embedding `args` of an executable target."""
-
-load(
-    "//build/bazel_common_rules/exec/impl:exec.bzl",
-    _exec = "exec",
-    _exec_rule = "exec_rule",
-    _exec_test = "exec_test",
-)
-
-visibility("public")
-
-def exec(
-        name,
-        data = None,
-        hashbang = None,
-        script = None,
-        **kwargs):
-    """Runs a script when `bazel run` this target.
-
-    See [documentation] for the `args` attribute.
-
-    **NOTE**: Like [genrule](https://bazel.build/reference/be/general#genrule)s,
-    hermeticity is not enforced or guaranteed, especially if `script` accesses PATH.
-    See [`Genrule Environment`](https://bazel.build/reference/be/general#genrule-environment)
-    for details.
-
-    Args:
-        name: name of the target
-        data: A list of labels providing runfiles. Labels may be used in `script`.
-
-            Executables in `data` must not have the `args` and `env` attribute. Use
-            [`embedded_exec`](#embedded_exec) to wrap the depended target so its env and args
-            are preserved.
-        hashbang: hashbang of the script, default is `"/bin/bash -e"`.
-        script: The script.
-
-            Use `$(rootpath <label>)` to refer to the path of a target specified in `data`. See
-            [documentation](https://bazel.build/reference/be/make-variables#predefined_label_variables).
-
-            Use `$@` to refer to the args attribute of this target.
-
-            See `build/bazel_common_rules/exec/tests/BUILD` for examples.
-        **kwargs: Additional attributes to the internal rule, e.g.
-            [`visibility`](https://docs.bazel.build/versions/main/visibility.html).
-            See complete list
-            [here](https://docs.bazel.build/versions/main/be/common-definitions.html#common-attributes).
-
-    Deprecated:
-        Use `hermetic_exec` for stronger hermeticity.
-    """
-
-    # buildifier: disable=print
-    print("WARNING: {}: exec is deprecated. Use `hermetic_exec` instead.".format(
-        native.package_relative_label(name),
-    ))
-
-    kwargs.setdefault("deprecation", "Use hermetic_exec for stronger hermeticity")
-
-    _exec(
-        name = name,
-        data = data,
-        hashbang = hashbang,
-        script = script,
-        **kwargs
-    )
-
-def exec_test(
-        name,
-        data = None,
-        hashbang = None,
-        script = None,
-        **kwargs):
-    """Runs a script when `bazel test` this target.
-
-    See [documentation] for the `args` attribute.
-
-    **NOTE**: Like [genrule](https://bazel.build/reference/be/general#genrule)s,
-    hermeticity is not enforced or guaranteed, especially if `script` accesses PATH.
-    See [`Genrule Environment`](https://bazel.build/reference/be/general#genrule-environment)
-    for details.
-
-    Args:
-        name: name of the target
-        data: A list of labels providing runfiles. Labels may be used in `script`.
-
-            Executables in `data` must not have the `args` and `env` attribute. Use
-            [`embedded_exec`](#embedded_exec) to wrap the depended target so its env and args
-            are preserved.
-        hashbang: hashbang of the script, default is `"/bin/bash -e"`.
-        script: The script.
-
-            Use `$(rootpath <label>)` to refer to the path of a target specified in `data`. See
-            [documentation](https://bazel.build/reference/be/make-variables#predefined_label_variables).
-
-            Use `$@` to refer to the args attribute of this target.
-
-            See `build/bazel_common_rules/exec/tests/BUILD` for examples.
-        **kwargs: Additional attributes to the internal rule, e.g.
-            [`visibility`](https://docs.bazel.build/versions/main/visibility.html).
-            See complete list
-            [here](https://docs.bazel.build/versions/main/be/common-definitions.html#common-attributes).
-
-    Deprecated:
-        Use `hermetic_exec` for stronger hermeticity.
-    """
-
-    # buildifier: disable=print
-    print("WARNING: {}: exec_test is deprecated. Use `hermetic_exec_test` instead.".format(
-        native.package_relative_label(name),
-    ))
-
-    kwargs.setdefault("deprecation", "Use hermetic_exec_test for stronger hermeticity")
-
-    _exec_test(
-        name = name,
-        data = data,
-        hashbang = hashbang,
-        script = script,
-        **kwargs
-    )
-
-# buildifier: disable=unnamed-macro
-def exec_rule(
-        cfg = None,
-        attrs = None):
-    """Returns a rule() that is similar to `exec`, but with the given incoming transition.
-
-    **NOTE**: Like [genrule](https://bazel.build/reference/be/general#genrule)s,
-    hermeticity is not enforced or guaranteed for targets of the returned
-    rule, especially if a target specifies `script` that accesses PATH.
-    See [`Genrule Environment`](https://bazel.build/reference/be/general#genrule-environment)
-    for details.
-
-    Args:
-        cfg: [Incoming edge transition](https://bazel.build/extending/config#incoming-edge-transitions)
-            on the rule
-        attrs: Additional attributes to be added to the rule.
-
-            Specify `_allowlist_function_transition` if you need a transition.
-    Returns:
-        a rule
-    """
-
-    # buildifier: disable=print
-    print("WARNING: exec_rule is deprecated.")
-
-    _exec_rule(
-        cfg = cfg,
-        attrs = attrs,
-    )
diff --git a/exec/exec_aspect.bzl b/exec/exec_aspect.bzl
deleted file mode 100644
index 6e7aa1f..0000000
--- a/exec/exec_aspect.bzl
+++ /dev/null
@@ -1,30 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Helps embedding `args` of an executable target.
-
-**DEPRECTED**. This is an implementation detail and should not be relied upon.
-"""
-
-load(
-    "//build/bazel_common_rules/exec/impl:exec_aspect.bzl",
-    _ExecAspectInfo = "ExecAspectInfo",
-    _exec_aspect = "exec_aspect",
-)
-
-# TODO(b/329305827): make this private
-visibility("public")
-
-ExecAspectInfo = _ExecAspectInfo
-exec_aspect = _exec_aspect
diff --git a/platforms/BUILD.bazel b/platforms/BUILD.bazel
deleted file mode 100644
index fb9120c..0000000
--- a/platforms/BUILD.bazel
+++ /dev/null
@@ -1 +0,0 @@
-# Used to denote the //build/bazel_common_rules/platforms package.
diff --git a/platforms/arch/BUILD b/platforms/arch/BUILD
deleted file mode 100644
index 98938f9..0000000
--- a/platforms/arch/BUILD
+++ /dev/null
@@ -1,68 +0,0 @@
-# Standard cpu name constraint_setting and constraint_values
-
-licenses(["notice"])
-
-package(
-    default_visibility = ["//visibility:public"],
-)
-
-alias(
-    name = "arm",
-    actual = "@platforms//cpu:arm",
-    deprecation = "Use @platforms//cpu:arm directly.",
-)
-
-alias(
-    name = "arm64",
-    actual = "@platforms//cpu:arm64",
-    deprecation = "Use @platforms//cpu:arm64 directly.",
-)
-
-alias(
-    name = "riscv64",
-    actual = "@platforms//cpu:riscv64",
-    deprecation = "Use @platforms//cpu:riscv64 directly.",
-)
-
-alias(
-    name = "x86",
-    actual = "@platforms//cpu:x86_32",
-    deprecation = "Use @platforms//cpu:x86_32 directly.",
-)
-
-# Alias to the local_jdk's toolchain constraint to make local_jdk resolve
-# correctly with --tool_java_runtime_version=local_jdk and the checked-in JDK.
-alias(
-    name = "x86_64",
-    actual = "@platforms//cpu:x86_64",
-    deprecation = "Use @platforms//cpu:x86_64 directly.",
-)
-
-constraint_setting(
-    name = "secondary_arch_constraint",
-)
-
-constraint_value(
-    name = "secondary_arm",
-    constraint_setting = ":secondary_arch_constraint",
-)
-
-constraint_value(
-    name = "secondary_arm64",
-    constraint_setting = ":secondary_arch_constraint",
-)
-
-constraint_value(
-    name = "secondary_riscv64",
-    constraint_setting = ":secondary_arch_constraint",
-)
-
-constraint_value(
-    name = "secondary_x86",
-    constraint_setting = ":secondary_arch_constraint",
-)
-
-constraint_value(
-    name = "secondary_x86_64",
-    constraint_setting = ":secondary_arch_constraint",
-)
diff --git a/platforms/constants.bzl b/platforms/constants.bzl
deleted file mode 100644
index 8eb05c5..0000000
--- a/platforms/constants.bzl
+++ /dev/null
@@ -1,49 +0,0 @@
-"""Constants related to Bazel platforms."""
-
-# This dict denotes the suffixes for host platforms (keys) and the constraints
-# associated with them (values). Used in transitions and tests, in addition to
-# here.
-host_platforms = {
-    "linux_x86": [
-        "@platforms//cpu:x86_32",
-        "@platforms//os:linux",
-    ],
-    "linux_x86_64": [
-        "@platforms//cpu:x86_64",
-        "@platforms//os:linux",
-    ],
-    "linux_musl_x86": [
-        "@platforms//cpu:x86_32",
-        "@//build/bazel_common_rules/platforms/os:linux_musl",
-    ],
-    "linux_musl_x86_64": [
-        "@platforms//cpu:x86_64",
-        "@//build/bazel_common_rules/platforms/os:linux_musl",
-    ],
-    # linux_bionic is the OS for the Linux kernel plus the Bionic libc runtime,
-    # but without the rest of Android.
-    "linux_bionic_arm64": [
-        "@platforms//cpu:arm64",
-        "@//build/bazel_common_rules/platforms/os:linux_bionic",
-    ],
-    "linux_bionic_x86_64": [
-        "@platforms//cpu:x86_64",
-        "@//build/bazel_common_rules/platforms/os:linux_bionic",
-    ],
-    "darwin_arm64": [
-        "@platforms//cpu:arm64",
-        "@platforms//os:macos",
-    ],
-    "darwin_x86_64": [
-        "@platforms//cpu:x86_64",
-        "@platforms//os:macos",
-    ],
-    "windows_x86": [
-        "@platforms//cpu:x86_32",
-        "@platforms//os:windows",
-    ],
-    "windows_x86_64": [
-        "@platforms//cpu:x86_64",
-        "@platforms//os:windows",
-    ],
-}
diff --git a/platforms/os/BUILD b/platforms/os/BUILD
deleted file mode 100644
index 88fbf0a..0000000
--- a/platforms/os/BUILD
+++ /dev/null
@@ -1,73 +0,0 @@
-# Standard constraint_setting and constraint_values to be used in platforms.
-
-load("@bazel_skylib//lib:selects.bzl", "selects")
-
-licenses(["notice"])
-
-package(
-    default_visibility = ["//visibility:public"],
-)
-
-alias(
-    name = "android",
-    actual = "@platforms//os:android",
-    deprecation = "Use @platforms//os:android directly.",
-)
-
-config_setting(
-    name = "android_config_setting",
-    constraint_values = [
-        ":android",
-    ],
-)
-
-# Alias to the local_jdk's toolchain constraint to make local_jdk resolve
-# correctly with --tool_java_runtime_version=local_jdk and the checked-in JDK.
-alias(
-    name = "linux",
-    actual = "@platforms//os:linux",
-    deprecation = "Use @platforms//os:linux directly.",
-)
-
-alias(
-    name = "linux_glibc",
-    actual = "@platforms//os:linux",
-    deprecation = "Use @platforms//os:linux directly.",
-)
-
-constraint_value(
-    name = "linux_musl",
-    constraint_setting = "@platforms//os:os",
-)
-
-constraint_value(
-    name = "linux_bionic",
-    constraint_setting = "@platforms//os:os",
-)
-
-config_setting(
-    name = "linux_bionic_config_setting",
-    constraint_values = [
-        ":linux_bionic",
-    ],
-)
-
-alias(
-    name = "windows",
-    actual = "@platforms//os:windows",
-    deprecation = "Use @platforms//os:windows directly.",
-)
-
-alias(
-    name = "darwin",
-    actual = "@platforms//os:macos",
-    deprecation = "Use @platforms//os:macos directly.",
-)
-
-selects.config_setting_group(
-    name = "bionic",
-    match_any = [
-        ":android_config_setting",
-        ":linux_bionic_config_setting",
-    ],
-)
diff --git a/platforms/os_arch/BUILD.bazel b/platforms/os_arch/BUILD.bazel
deleted file mode 100644
index 21b6a81..0000000
--- a/platforms/os_arch/BUILD.bazel
+++ /dev/null
@@ -1,82 +0,0 @@
-load("//build/bazel_common_rules/platforms:constants.bzl", "host_platforms")
-
-config_setting(
-    name = "android_arm",
-    constraint_values = [
-        "@platforms//cpu:arm",
-        "@platforms//os:android",
-    ],
-)
-
-config_setting(
-    name = "android_arm64",
-    constraint_values = [
-        "@platforms//cpu:arm64",
-        "@platforms//os:android",
-    ],
-)
-
-config_setting(
-    name = "android_riscv64",
-    constraint_values = [
-        "@platforms//cpu:riscv64",
-        "@platforms//os:android",
-    ],
-)
-
-config_setting(
-    name = "android_x86",
-    constraint_values = [
-        "@platforms//cpu:x86_32",
-        "@platforms//os:android",
-    ],
-)
-
-config_setting(
-    name = "android_x86_64",
-    constraint_values = [
-        "@platforms//cpu:x86_64",
-        "@platforms//os:android",
-    ],
-)
-
-[
-    config_setting(
-        name = name,
-        constraint_values = constraints,
-    )
-    for name, constraints in host_platforms.items()
-]
-
-# These settings must exist, but are not yet supported by our toolchains
-config_setting(
-    name = "linux_glibc_x86",
-    constraint_values = [
-        "@platforms//cpu:x86_32",
-        "@platforms//os:linux",
-    ],
-)
-
-config_setting(
-    name = "linux_glibc_x86_64",
-    constraint_values = [
-        "@platforms//cpu:x86_64",
-        "@platforms//os:linux",
-    ],
-)
-
-config_setting(
-    name = "linux_musl_arm",
-    constraint_values = [
-        "@platforms//cpu:arm",
-        "//build/bazel_common_rules/platforms/os:linux_musl",
-    ],
-)
-
-config_setting(
-    name = "linux_musl_arm64",
-    constraint_values = [
-        "@platforms//cpu:arm64",
-        "//build/bazel_common_rules/platforms/os:linux_musl",
-    ],
-)
diff --git a/rules/coverage/remote_coverage_tools/BUILD b/rules/coverage/remote_coverage_tools/BUILD
deleted file mode 100644
index 80a6d03..0000000
--- a/rules/coverage/remote_coverage_tools/BUILD
+++ /dev/null
@@ -1,17 +0,0 @@
-# This is a stub BUILD to override remote_coverage_tools.
-# See b/201242197 for more information.
-
-package(default_visibility = ["//visibility:public"])
-
-filegroup(
-    name = "coverage_report_generator",
-    srcs = ["coverage_report_generator.sh"],
-)
-
-# TODO(b/201242197): vendor remote_coverage_tools.
-#
-# Necessary to keep cc_test's implicit dep lookup from complaining.
-filegroup(
-    name = "lcov_merger",
-    srcs = ["stub.sh"],
-)
diff --git a/rules/coverage/remote_coverage_tools/WORKSPACE b/rules/coverage/remote_coverage_tools/WORKSPACE
deleted file mode 100644
index bd9e913..0000000
--- a/rules/coverage/remote_coverage_tools/WORKSPACE
+++ /dev/null
@@ -1,2 +0,0 @@
-# This is a stub WORKSPACE to override remote_coverage_tools.
-# See b/201242197 for more information.
diff --git a/workspace/BUILD b/workspace/BUILD
deleted file mode 100644
index c8bc792..0000000
--- a/workspace/BUILD
+++ /dev/null
@@ -1,27 +0,0 @@
-# Copyright (C) 2022 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-
-bzl_library(
-    name = "workspace",
-    srcs = [
-        "external.bzl",
-        # The Bazel prebuilt is not updated to define
-        # @bazel_tools//tools/build_defs/repo:lib,
-        # so using sources directly for now.
-        "@bazel_tools//tools:bzl_srcs",
-    ],
-    visibility = ["//visibility:public"],
-)
diff --git a/workspace/README.md b/workspace/README.md
deleted file mode 100644
index 15c5406..0000000
--- a/workspace/README.md
+++ /dev/null
@@ -1 +0,0 @@
-These extensions are expected to be loaded by `WORKSPACE` files only.
diff --git a/workspace/external.bzl b/workspace/external.bzl
deleted file mode 100644
index 15a29f4..0000000
--- a/workspace/external.bzl
+++ /dev/null
@@ -1,63 +0,0 @@
-# Copyright (C) 2022 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
-
-def import_external_repositories(
-        workspace_root = None,
-        bazel_skylib = None,
-        io_abseil_py = None,
-        io_bazel_stardoc = None):
-    """Import repositories in `{root}/external/` that are common to Bazel builds for Android.
-
-    In particular, these external projects are shared by Android platform
-    repo manifest and Android kernel repo manifest.
-
-    Caller of this function (in the `WORKSPACE` file) should manage a list
-    of repositories imported by providing them in the arguments.
-
-    Args:
-        workspace_root: Root under which the `external/` directory may be found, relative
-            to the main workspace.
-
-            When calling `import_external_repositories` in the main workspace's
-            `WORKSPACE` file, leave `root = None`.
-        bazel_skylib: If `True`, load `bazel_skylib`.
-        io_abseil_py: If `True`, load `io_abseil_py`.
-        io_bazel_stardoc: If `True`, load `io_bazel_stardoc`.
-    """
-    workspace_prefix = workspace_root or ""
-    if workspace_prefix:
-        workspace_prefix += "/"
-
-    if bazel_skylib:
-        maybe(
-            repo_rule = native.local_repository,
-            name = "bazel_skylib",
-            path = "{}external/bazel-skylib".format(workspace_prefix),
-        )
-
-    if io_abseil_py:
-        maybe(
-            repo_rule = native.local_repository,
-            name = "io_abseil_py",
-            path = "{}external/python/absl-py".format(workspace_prefix),
-        )
-
-    if io_bazel_stardoc:
-        maybe(
-            repo_rule = native.local_repository,
-            name = "io_bazel_stardoc",
-            path = "{}external/stardoc".format(workspace_prefix),
-        )
```

