```diff
diff --git a/Android.bp b/Android.bp
index 47a63697..2290bdc1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,6 +16,7 @@ cc_library_static {
     host_supported: true,
     vendor_available: true,
     product_available: true,
+    recovery_available: true,
     srcs: [
         "absl/**/*.cc",
     ],
@@ -46,14 +47,19 @@ cc_library_static {
         "com.android.ondevicepersonalization",
     ],
     visibility: [
+        // go/keep-sorted start
+        "//external/anonymous-counting-tokens:__subpackages__",
         "//external/federated-compute:__subpackages__",
         "//external/grpc-grpc:__subpackages__",
-        "//external/libtextclassifier:__subpackages__",
+        "//external/iamf_tools:__subpackages__",
         "//external/kythe:__subpackages__",
+        "//external/libtextclassifier:__subpackages__",
+        "//external/private-join-and-compute:__subpackages__",
         "//external/tensorflow:__subpackages__",
         "//external/tflite-support:__subpackages__",
         "//external/webrtc:__subpackages__",
         "//frameworks/av/media/libeffects/preprocessing",
+        // go/keep-sorted end
     ],
 }
 
diff --git a/absl/container/internal/layout.h b/absl/container/internal/layout.h
index 384929af..f04c7174 100644
--- a/absl/container/internal/layout.h
+++ b/absl/container/internal/layout.h
@@ -192,7 +192,6 @@
 #include <typeinfo>
 #include <utility>
 
-#include "absl/base/attributes.h"
 #include "absl/base/config.h"
 #include "absl/debugging/internal/demangle.h"
 #include "absl/meta/type_traits.h"
@@ -596,10 +595,10 @@ class LayoutImpl<
   //
   // Requires: `p` is aligned to `Alignment()`.
   //
-  // Note: We mark the parameter as unused because GCC detects it is not used
-  // when `SizeSeq` is empty [-Werror=unused-but-set-parameter].
+  // Note: We mark the parameter as maybe_unused because GCC detects it is not
+  // used when `SizeSeq` is empty [-Werror=unused-but-set-parameter].
   template <class Char>
-  auto Slices(ABSL_ATTRIBUTE_UNUSED Char* p) const {
+  auto Slices([[maybe_unused]] Char* p) const {
     return std::tuple<SliceType<CopyConst<Char, ElementType<SizeSeq>>>...>(
         Slice<SizeSeq>(p)...);
   }
```

