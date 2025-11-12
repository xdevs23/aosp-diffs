```diff
diff --git a/OWNERS b/OWNERS
index 2ed9b20..64aaec1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
-alisher@google.com
 georgekgchang@google.com
 jackcwyu@google.com
diff --git a/secure_element/aidl/Android.bp b/secure_element/aidl/Android.bp
index 0f227ea..b64b484 100644
--- a/secure_element/aidl/Android.bp
+++ b/secure_element/aidl/Android.bp
@@ -37,7 +37,7 @@ cc_binary {
     name: "android.hardware.secure_element-service.thales",
     relative_install_path: "hw",
     init_rc: ["android.hardware.secure_element_gto.rc"],
-    vintf_fragments: ["android.hardware.secure_element_gto.xml"],
+    vintf_fragment_modules: ["android.hardware.secure_element_gto.xml"],
     vendor: true,
     srcs: [
         "SecureElement.cpp",
@@ -53,11 +53,17 @@ cc_binary {
     },
 }
 
+vintf_fragment {
+    name: "android.hardware.secure_element_gto.xml",
+    src: "android.hardware.secure_element_gto.xml",
+    vendor: true,
+}
+
 cc_binary {
     name: "android.hardware.secure_element-service.thales-ese2",
     relative_install_path: "hw",
     init_rc: ["android.hardware.secure_element_gto-ese2.rc"],
-    vintf_fragments: ["android.hardware.secure_element_gto-ese2.xml"],
+    vintf_fragment_modules: ["android.hardware.secure_element_gto-ese2.xml"],
     vendor: true,
     srcs: [
         "SecureElement.cpp",
@@ -73,11 +79,17 @@ cc_binary {
     },
 }
 
+vintf_fragment {
+    name: "android.hardware.secure_element_gto-ese2.xml",
+    src: "android.hardware.secure_element_gto-ese2.xml",
+    vendor: true,
+}
+
 cc_binary {
     name: "android.hardware.secure_element-service.thales-st33",
     relative_install_path: "hw",
     init_rc: ["android.hardware.secure_element_gto-st33.rc"],
-    vintf_fragments: ["android.hardware.secure_element_gto-st33.xml"],
+    vintf_fragment_modules: ["android.hardware.secure_element_gto-st33.xml"],
     vendor: true,
     srcs: [
         "SecureElement.cpp",
@@ -86,3 +98,9 @@ cc_binary {
 
     defaults: ["thales_aidl_defaults"],
 }
+
+vintf_fragment {
+    name: "android.hardware.secure_element_gto-st33.xml",
+    src: "android.hardware.secure_element_gto-st33.xml",
+    vendor: true,
+}
```

