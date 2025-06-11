```diff
diff --git a/build/Android.bp b/build/Android.bp
index 9f62bbf..1fcd54f 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -39,9 +39,4 @@ python_test_host {
     test_options: {
         unit_test: true,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
diff --git a/cuttlefish/build_cf_hybrid_device.py b/cuttlefish/build_cf_hybrid_device.py
index 14c0dde..dada181 100644
--- a/cuttlefish/build_cf_hybrid_device.py
+++ b/cuttlefish/build_cf_hybrid_device.py
@@ -44,7 +44,7 @@ def _parse_args() -> argparse.Namespace:
   """
   parser = argparse.ArgumentParser()
 
-  parser.add_argument('--build_id', required=True,
+  parser.add_argument('--build_id', default='',
                       help='Build id.')
   parser.add_argument('--target', required=True,
                       help='Target name of the cuttlefish hybrid build.')
@@ -82,9 +82,10 @@ def run(temp_dir: str) -> None:
   # merge target files
   framework_target_files = matched_framework_target_files[0]
   vendor_target_files = matched_vendor_target_files[0]
+  build_id_str = f'-{args.build_id}' if args.build_id else ''
   merged_target_files = os.path.join(
       args.output_dir,
-      f'{args.target}-target_files-{args.build_id}.zip')
+      f'{args.target}-target_files{build_id_str}.zip')
   command = [
       os.path.join(otatools, 'bin', 'merge_target_files'),
       '--path', otatools,
@@ -97,7 +98,7 @@ def run(temp_dir: str) -> None:
 
   # create images from the merged target files
   img_zip_path = os.path.join(args.output_dir,
-                              f'{args.target}-img-{args.build_id}.zip')
+                              f'{args.target}-img{build_id_str}.zip')
   command = [
       os.path.join(otatools, 'bin', 'img_from_target_files'),
       merged_target_files,
diff --git a/split/Android.bp b/split/Android.bp
index 210e731..65de147 100644
--- a/split/Android.bp
+++ b/split/Android.bp
@@ -5,9 +5,6 @@ package {
 python_defaults {
     name: "treble_split_default",
     pkg_path: "treble/split",
-    libs: [
-        "py-setuptools",
-    ],
 }
 
 python_binary_host {
@@ -20,11 +17,6 @@ python_binary_host {
     data: [
         "default_config.xml",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_library_host {
@@ -62,9 +54,4 @@ python_test_host {
     ],
     test_config: "test.xml",
     test_suites: ["general-tests"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
```

