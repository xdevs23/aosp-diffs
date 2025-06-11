```diff
diff --git a/OWNERS b/OWNERS
index 2e8f086e1..a2a426857 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/Tools/MediaDriverTools/Android/mk/cmrt.tpl b/Tools/MediaDriverTools/Android/mk/cmrt.tpl
index 470cc64b3..4d0e6c20c 100644
--- a/Tools/MediaDriverTools/Android/mk/cmrt.tpl
+++ b/Tools/MediaDriverTools/Android/mk/cmrt.tpl
@@ -44,8 +44,7 @@ ifeq ($(CMRT_BUILD_TYPE), debug)
         -O0
 else
     LOCAL_CFLAGS += \
-        -fno-strict-aliasing \
-        -D_FORTIFY_SOURCE=2
+        -fno-strict-aliasing
 endif
 
 
diff --git a/cmrtlib/Android.bp b/cmrtlib/Android.bp
index cb74de394..2b7ca8c16 100644
--- a/cmrtlib/Android.bp
+++ b/cmrtlib/Android.bp
@@ -18,6 +18,24 @@
 // ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 // OTHER DEALINGS IN THE SOFTWARE.
 
+cc_library_headers {
+    name: "libcmrt_headers",
+    export_include_dirs: [
+        "agnostic/share",
+        "agnostic/hardware",
+        "linux/share",
+        "linux/hardware",
+    ],
+
+    vendor: true,
+    enabled: false,
+    arch: {
+        x86_64: {
+            enabled: true,
+        },
+    },
+}
+
 cc_library_shared {
     name: "libigfxcmrt",
 
@@ -39,13 +57,6 @@ cc_library_shared {
         "linux/hardware/cm_timer_os.cpp",
     ],
 
-    local_include_dirs: [
-        "agnostic/share",
-        "agnostic/hardware",
-        "linux/share",
-        "linux/hardware",
-    ],
-
     cflags: [
         "-Werror",
         "-Wno-unused-variable",
@@ -61,6 +72,7 @@ cc_library_shared {
 
     header_libs: [
         "libva_headers",
+        "libcmrt_headers",
     ],
 
     shared_libs: [
@@ -81,18 +93,3 @@ cc_library_shared {
         },
     },
 }
-
-cc_library_headers {
-    name: "libcmrt_headers",
-    export_include_dirs: [
-        "linux/hardware",
-    ],
-
-    vendor: true,
-    enabled: false,
-    arch: {
-        x86_64: {
-            enabled: true,
-        },
-    },
-}
```

