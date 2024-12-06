```diff
diff --git a/Android.bp b/Android.bp
index 672c64f3..6a3fd873 100644
--- a/Android.bp
+++ b/Android.bp
@@ -60,7 +60,7 @@ rust_library {
     ],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "//apex_available:anyapex",
     ],
     product_available: true,
     vendor_available: true,
diff --git a/Cargo.toml b/Cargo.toml
index e17251cf..71ad7b37 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -85,7 +85,7 @@ features = ["vendored"]
 optional = true
 
 [build-dependencies.bindgen]
-version = "0.69.1"
+version = "0.69.4"
 features = ["runtime"]
 optional = true
 default-features = false
@@ -125,4 +125,4 @@ openssl-vendored = [
 ]
 
 [target."cfg(not(all(any(target_os = \"linux\", target_os = \"macos\"), any(target_arch = \"x86_64\", target_arch = \"aarch64\"))))".build-dependencies.bindgen]
-version = "0.69.1"
+version = "0.69.4"
diff --git a/cargo_embargo.json b/cargo_embargo.json
index c3bb051b..2ed57596 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -1,8 +1,4 @@
 {
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.btservices"
-  ],
   "features": [
     "boringssl",
     "_gen-bindings",
diff --git a/patches/Cargo.toml.diff b/patches/Cargo.toml.diff
index 9b56e0dc..0f459387 100644
--- a/patches/Cargo.toml.diff
+++ b/patches/Cargo.toml.diff
@@ -24,7 +24,7 @@ index 5f3f4c25..e17251cf 100644
  
  [build-dependencies.bindgen]
 -version = "0.59.0"
-+version = "0.69.1"
++version = "0.69.4"
  features = ["runtime"]
  optional = true
  default-features = false
@@ -52,4 +52,4 @@ index 5f3f4c25..e17251cf 100644
  
  [target."cfg(not(all(any(target_os = \"linux\", target_os = \"macos\"), any(target_arch = \"x86_64\", target_arch = \"aarch64\"))))".build-dependencies.bindgen]
 -version = "0.59.0"
-+version = "0.69.1"
++version = "0.69.4"
```

