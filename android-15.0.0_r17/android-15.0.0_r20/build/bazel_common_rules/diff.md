```diff
diff --git a/dist/dist.bzl b/dist/dist.bzl
index 1d44d4c..f2c0569 100644
--- a/dist/dist.bzl
+++ b/dist/dist.bzl
@@ -161,6 +161,9 @@ def copy_to_dist_dir(
           These additional attributes are only passed to the underlying embedded_exec rule.
     """
 
+    unhandled_attrs = []
+    unsupported_attrs = []
+
     default_args = []
     if flat:
         default_args.append("--flat")
@@ -168,19 +171,26 @@ def copy_to_dist_dir(
         if strip_components < 0:
             fail("strip_components must greater than 0, but is %s" % strip_components)
         default_args += ["--strip_components", str(strip_components)]
+    if strip_components:
+        unhandled_attrs.append("strip_components")
     if prefix != None:
         default_args += ["--prefix", prefix]
+        unhandled_attrs.append("archive_prefix")
     if archive_prefix != None:
         default_args += ["--archive_prefix", archive_prefix]
+        unsupported_attrs.append("archive_prefix")
     if dist_dir != None:
         default_args += ["--dist_dir", dist_dir]
     if wipe_dist_dir:
         default_args.append("--wipe_dist_dir")
+        unsupported_attrs.append("wipe_dist_dir")
     if allow_duplicate_filenames:
         default_args.append("--allow_duplicate_filenames")
+        unsupported_attrs.append("allow_duplicate_filenames")
     if mode_overrides != None:
         for (pattern, mode) in mode_overrides.items():
             default_args += ["--mode_override", pattern, str(mode)]
+        unhandled_attrs.append("mode_overrides")
     if log != None:
         default_args += ["--log", log]
 
@@ -214,6 +224,34 @@ def copy_to_dist_dir(
         args = default_args,
     )
 
+    kwargs.setdefault("deprecation", """copy_to_dist_dir() is deprecated. Use pkg_install() instead.
+
+Suggested edit:
+
+load("@rules_pkg//pkg:install.bzl", "pkg_install")
+load("@rules_pkg//pkg:mappings.bzl", "pkg_files", "strip_prefix")
+pkg_files(
+    name = {name_files},
+    srcs = {data},
+    strip_prefix = {strip_prefix},
+    visibility = ["//visibility:private"],
+)
+pkg_install(
+    name = {name},
+    srcs = [{colon_name_files}],
+    destdir = {dist_dir},
+){unhandled_attrs}{unsupported_attrs}""".format(
+        name = repr(name),
+        name_files = repr(name + "_files"),
+        colon_name_files = repr(":" + name + "_files"),
+        dist_dir = repr(dist_dir),
+        strip_prefix = "strip_prefix.files_only()" if flat else "None",
+        data = repr(data),
+        unhandled_attrs = "" if not unhandled_attrs else "\nThe following attributes are not converted; read the API reference of rules_pkg " +
+                                                         "for an alternative: {}".format(repr(unhandled_attrs)),
+        unsupported_attrs = "" if not unsupported_attrs else "\nThe following attributes may not be supported by rules_pkg: {}".format(repr(unsupported_attrs)),
+    ))
+
     embedded_exec(
         name = name,
         actual = name + "_internal",
diff --git a/exec/impl/embedded_exec.bzl b/exec/impl/embedded_exec.bzl
index 2ff33d9..9b5882f 100644
--- a/exec/impl/embedded_exec.bzl
+++ b/exec/impl/embedded_exec.bzl
@@ -23,6 +23,10 @@ visibility([
 ])
 
 def _impl(ctx):
+    # buildifier: disable=print
+    print(("\nWARNING: {}: embedded_exec is deprecated. Consider writing a custom rule with " +
+           "arguments specified at the wrapper rule instead.").format(ctx.label))
+
     target = ctx.attr.actual
     files_to_run = target[DefaultInfo].files_to_run
     if not files_to_run or not files_to_run.executable:
diff --git a/exec/impl/exec.bzl b/exec/impl/exec.bzl
index b78728b..96f07a6 100644
--- a/exec/impl/exec.bzl
+++ b/exec/impl/exec.bzl
@@ -112,41 +112,3 @@ See `build/bazel_common_rules/exec/tests/BUILD` for examples.
     },
     test = True,
 )
-
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
-    fixed_attrs = {
-        "data": attr.label_list(aspects = [exec_aspect], allow_files = True),
-        "hashbang": attr.string(default = _DEFAULT_HASHBANG),
-        "script": attr.string(),
-    }
-
-    if attrs == None:
-        attrs = {}
-    attrs = attrs | fixed_attrs
-
-    return rule(
-        implementation = _impl,
-        attrs = attrs,
-        cfg = cfg,
-        executable = True,
-    )
```

