```diff
diff --git a/Android.bp b/Android.bp
index 142865a06..ee1b70430 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,5 +1,34 @@
 package {
     default_applicable_licenses: ["external_freetype_license"],
+    // FreeType will be deprecated and migrate to Skrifa. (b/405267306)
+    default_visibility: [
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2016-10244",
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2019-1988",
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2023-21261",
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2024-43091",
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2024-43097",
+        "//cts/hostsidetests/securitybulletin/securityPatch/CVE-2024-43767",
+        "//device/google/cuttlefish/host/frontend/webrtc",
+        "//device/google/cuttlefish/host/libs/confui",
+        "//device/google/cuttlefish/host/libs/screen_connector",
+        "//external/igt-gpu-tools",
+        "//external/cairo",
+        "//external/pdfium",
+        "//external/skia",
+        "//frameworks/base/core/jni",
+        "//frameworks/base/libs/hwui",
+        "//frameworks/minikin:__subpackages__",
+        "//frameworks/opt/wear/jni",
+        "//frameworks/rs",
+        "//hardware/interfaces/graphics/allocator/aidl/vts",
+        "//packages/providers/MediaProvider/pdf/framework/libs/pdfClient",
+        "//system/teeui/libteeui",
+        "//system/teeui/libteeui/example",
+        "//system/teeui/libteeui_jni",
+        "//system/teeui/test",
+        "//tools/security/fuzzing/orphans/libskia",
+        "//vendor:__subpackages__",
+    ],
 }
 
 // Added automatically by a large-scale-change that took the approach of
```

