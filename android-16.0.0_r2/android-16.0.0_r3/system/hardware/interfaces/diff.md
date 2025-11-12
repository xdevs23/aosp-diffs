```diff
diff --git a/keystore2/aidl/Android.bp b/keystore2/aidl/Android.bp
index 9119489..9f2c8d5 100644
--- a/keystore2/aidl/Android.bp
+++ b/keystore2/aidl/Android.bp
@@ -70,3 +70,68 @@ aidl_interface_defaults {
         "android.system.keystore2-V5",
     ],
 }
+
+// java_defaults that includes the latest Keystore2 AIDL library.
+// Modules that depend on Keystore2 directly can include this java_defaults to avoid
+// managing dependency versions explicitly.
+java_defaults {
+    name: "keystore2_use_latest_aidl_java_static",
+    static_libs: [
+        "android.system.keystore2-V5-java-source",
+    ],
+}
+
+java_defaults {
+    name: "keystore2_use_latest_aidl_java_shared",
+    libs: [
+        "android.system.keystore2-V5-java-source",
+    ],
+}
+
+java_defaults {
+    name: "keystore2_use_latest_aidl_java",
+    libs: [
+        "android.system.keystore2-V5-java",
+    ],
+}
+
+// cc_defaults that includes the latest Keystore2 AIDL library.
+// Modules that depend on Keystore directly can include this cc_defaults to avoid
+// managing dependency versions explicitly.
+cc_defaults {
+    name: "keystore2_use_latest_aidl_ndk_static",
+    static_libs: [
+        "android.system.keystore2-V5-ndk",
+    ],
+}
+
+cc_defaults {
+    name: "keystore2_use_latest_aidl_ndk_shared",
+    shared_libs: [
+        "android.system.keystore2-V5-ndk",
+    ],
+}
+
+cc_defaults {
+    name: "keystore2_use_latest_aidl_cpp_shared",
+    shared_libs: [
+        "android.system.keystore2-V5-cpp",
+    ],
+}
+
+cc_defaults {
+    name: "keystore2_use_latest_aidl_cpp_static",
+    static_libs: [
+        "android.system.keystore2-V5-cpp",
+    ],
+}
+
+// A rust_defaults that includes the latest Keystore2 AIDL library.
+// Modules that depend on Keystore2 directly can include this rust_defaults to avoid
+// managing dependency versions explicitly.
+rust_defaults {
+    name: "keystore2_use_latest_aidl_rust",
+    rustlibs: [
+        "android.system.keystore2-V5-rust",
+    ],
+}
```

