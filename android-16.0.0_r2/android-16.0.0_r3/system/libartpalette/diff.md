```diff
diff --git a/Android.bp b/Android.bp
index e8b565e..0a07f19 100644
--- a/Android.bp
+++ b/Android.bp
@@ -69,6 +69,7 @@ cc_library {
             "2",
             "3",
             "4",
+            "5",
         ],
         symbol_file: "libartpalette.map.txt",
     },
diff --git a/libartpalette.map.txt b/libartpalette.map.txt
index 3727451..1418cef 100644
--- a/libartpalette.map.txt
+++ b/libartpalette.map.txt
@@ -57,3 +57,10 @@ LIBARTPALETTE_4 { # introduced=36
     # --- VERSION 04 API ---
     PaletteDebugStoreGetString; # systemapi
 } LIBARTPALETTE_3;
+
+LIBARTPALETTE_5 { # introduced=37
+# Also available in 36.1
+  global:
+    # --- VERSION 05 API ---
+    PaletteMapPriority; # systemapi
+} LIBARTPALETTE_4;
diff --git a/palette_android.cc b/palette_android.cc
index f9a7253..5be3e7f 100644
--- a/palette_android.cc
+++ b/palette_android.cc
@@ -42,7 +42,7 @@
 // Conversion map for "nice" values.
 //
 // We use Android thread priority constants to be consistent with the rest
-// of the system.  In some cases adjacent entries may overlap.
+// of the system.
 //
 static const int kNiceValues[art::palette::kNumManagedThreadPriorities] = {
     ANDROID_PRIORITY_LOWEST,  // 1 (MIN_PRIORITY)
@@ -98,6 +98,17 @@ palette_status_t PaletteSchedGetPriority(int32_t tid, /*out*/ int32_t* managed_p
   return PALETTE_STATUS_OK;
 }
 
+// Introduced in version 5 API, corresponding to SDK level 36.1.
+// Intended as a replacement for the above.
+palette_status_t PaletteMapPriority(int32_t managed_priority, /*out*/ int* result) {
+  if (managed_priority < art::palette::kMinManagedThreadPriority ||
+      managed_priority > art::palette::kMaxManagedThreadPriority) {
+    return PALETTE_STATUS_INVALID_ARGUMENT;
+  }
+  *result = kNiceValues[managed_priority - art::palette::kMinManagedThreadPriority];
+  return PALETTE_STATUS_OK;
+}
+
 palette_status_t PaletteWriteCrashThreadStacks(/*in*/ const char* stacks, size_t stacks_len) {
   android::base::unique_fd tombstone_fd;
   android::base::unique_fd output_fd;
@@ -270,4 +281,4 @@ palette_status_t PaletteDebugStoreGetString(char* result, size_t max_size) {
   strncpy(result, store_string.c_str(), max_size - 1);
   result[max_size - 1] = '\0';
   return PALETTE_STATUS_OK;
-}
\ No newline at end of file
+}
diff --git a/palette_fake.cc b/palette_fake.cc
index 08711b3..a5c2e49 100644
--- a/palette_fake.cc
+++ b/palette_fake.cc
@@ -14,6 +14,10 @@
  * limitations under the License.
  */
 
+// This is essentially, but not quite, a copy of art/libartpalette/system/palette_fake.cc.
+// THEY SHOULD BE UPDATED AT THE SAME TIME.
+// TODO(b/265435354): Reconstruct if / why this is necessary.
+
 #include "palette/palette.h"
 
 #include <stdbool.h>
@@ -27,6 +31,8 @@
 #include "palette_system.h"
 
 // Cached thread priority for testing. No thread priorities are ever affected.
+// Assumes thread priority is adjusted only through this interface, which is incorrect for
+// production code, but valid for relevant tests.
 static std::mutex g_tid_priority_map_mutex;
 static std::map<int32_t, int32_t> g_tid_priority_map;
 
@@ -53,6 +59,18 @@ palette_status_t PaletteSchedGetPriority(int32_t tid,
   return PALETTE_STATUS_OK;
 }
 
+// Introduced in version 5 API, corresponding to SDK level 36.1.
+palette_status_t PaletteMapPriority(int32_t managed_priority, /*out*/ int* result) {
+  if (managed_priority < art::palette::kMinManagedThreadPriority ||
+      managed_priority > art::palette::kMaxManagedThreadPriority) {
+    return PALETTE_STATUS_INVALID_ARGUMENT;
+  }
+  // Some test code assumes these are monotically decreasing, so we can reconstruct priority
+  // from niceness.
+  *result = 10 - 2 * managed_priority;
+  return PALETTE_STATUS_OK;
+}
+
 palette_status_t PaletteWriteCrashThreadStacks(/*in*/ const char* stacks, size_t stacks_len) {
   LOG(INFO) << std::string_view(stacks, stacks_len);
   return PALETTE_STATUS_OK;
@@ -153,4 +171,4 @@ palette_status_t PaletteDebugStoreGetString(char* result ATTRIBUTE_UNUSED,
                                             size_t max_size ATTRIBUTE_UNUSED) {
   result[0] = '\0';
   return PALETTE_STATUS_OK;
-}
\ No newline at end of file
+}
```

