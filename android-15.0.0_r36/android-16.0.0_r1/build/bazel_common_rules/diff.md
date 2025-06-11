```diff
diff --git a/dist/dist.bzl b/dist/dist.bzl
index f2c0569..7ed8ca4 100644
--- a/dist/dist.bzl
+++ b/dist/dist.bzl
@@ -224,7 +224,9 @@ def copy_to_dist_dir(
         args = default_args,
     )
 
-    kwargs.setdefault("deprecation", """copy_to_dist_dir() is deprecated. Use pkg_install() instead.
+    # buildifier: disable=print
+    print("""
+WARNING: copy_to_dist_dir() is deprecated. Use pkg_install() instead.
 
 Suggested edit:
 
diff --git a/dist/dist.py b/dist/dist.py
index 127e828..2b7e277 100644
--- a/dist/dist.py
+++ b/dist/dist.py
@@ -261,7 +261,7 @@ def _get_parser(cmdline=False) -> argparse.ArgumentParser:
     parser.add_argument("-q", "--quiet", action="store_const", default=False,
                         help="Same as --log=error", const="error", dest="log")
     deprecated.add_argument(
-        "--wipe_dist_dir",
+        "--wipe_dist_dir", "--wipe_destdir",
         action=StoreTrueAndCheckDeprecationAction if cmdline else "store_true",
         help="remove existing dist_dir prior to running",
     )
diff --git a/exec/impl/embedded_exec.bzl b/exec/impl/embedded_exec.bzl
index 9b5882f..8fff03b 100644
--- a/exec/impl/embedded_exec.bzl
+++ b/exec/impl/embedded_exec.bzl
@@ -24,8 +24,8 @@ visibility([
 
 def _impl(ctx):
     # buildifier: disable=print
-    print(("\nWARNING: {}: embedded_exec is deprecated. Consider writing a custom rule with " +
-           "arguments specified at the wrapper rule instead.").format(ctx.label))
+    print(("\nWARNING: {}: embedded_exec is deprecated. Consider run_binary from skylib, or " +
+           "writing a custom rule with arguments specified at the wrapper rule instead.").format(ctx.label))
 
     target = ctx.attr.actual
     files_to_run = target[DefaultInfo].files_to_run
```

