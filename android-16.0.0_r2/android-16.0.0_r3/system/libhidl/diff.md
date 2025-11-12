```diff
diff --git a/transport/memory/1.0/default/Android.bp b/transport/memory/1.0/default/Android.bp
index e631215..6069a47 100644
--- a/transport/memory/1.0/default/Android.bp
+++ b/transport/memory/1.0/default/Android.bp
@@ -23,15 +23,26 @@ package {
 
 cc_library_shared {
     name: "android.hidl.memory@1.0-impl",
-    vendor_available: true,
+    defaults: ["android.hidl.memory@1.0-impl-defaults"],
+    system_ext_specific: true,
+}
+
+cc_library_shared {
+    name: "android.hidl.memory@1.0-impl.vendor",
+    defaults: ["android.hidl.memory@1.0-impl-defaults"],
+    vendor: true,
+}
+
+cc_defaults {
+    name: "android.hidl.memory@1.0-impl-defaults",
+    stem: "android.hidl.memory@1.0-impl",
     compile_multilib: "both",
     relative_install_path: "hw",
-    system_ext_specific: true,
     defaults: ["libhidl-defaults"],
     srcs: [
         "AshmemMapper.cpp",
         "AshmemMemory.cpp",
-        "HidlFetch.cpp"
+        "HidlFetch.cpp",
     ],
     shared_libs: [
         "libcutils",
```

