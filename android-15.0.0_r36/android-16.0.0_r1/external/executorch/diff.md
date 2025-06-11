```diff
diff --git a/Android.bp b/Android.bp
index fffbc8bc6..bea1b2f97 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,11 +1,15 @@
 cc_library {
-    name: "libexecutorch",
+    name: "libexecutorch_runtime",
     srcs: [
         "extension/data_loader/file_data_loader.cpp",
         "extension/data_loader/mmap_data_loader.cpp",
         "extension/evalue_util/print_evalue.cpp",
+        "extension/module/*.cpp",
         "extension/runner_util/inputs.cpp",
         "extension/runner_util/inputs_portable.cpp",
+        "extension/training/module/training_module.cpp",
+        "extension/training/optimizer/sgd.cpp",
+        "extension/tensor/*.cpp",
         ":executorch_portable_ops_gen_cpp",
         "kernels/portable/cpu/*.cpp",
         "kernels/portable/cpu/pattern/*.cpp",
@@ -44,7 +48,7 @@ cc_library {
     host_supported: true,
     apex_available: ["com.android.ondevicepersonalization"],
     sdk_version: "current",
-    min_sdk_version: "33",
+    min_sdk_version: "apex_inherit",
     visibility: ["//packages/modules/OnDevicePersonalization:__subpackages__"],
 }
 
@@ -55,7 +59,19 @@ cc_binary {
         "libgflags",
     ],
     whole_static_libs: [
-        "libexecutorch",
+        "libexecutorch_runtime",
+    ],
+    host_supported: true,
+}
+
+cc_binary {
+    name: "train_runner",
+    srcs: ["extension/training/examples/XOR/train.cpp"],
+    static_libs: [
+        "libgflags",
+    ],
+    whole_static_libs: [
+        "libexecutorch_runtime",
     ],
     host_supported: true,
 }
@@ -141,3 +157,53 @@ cc_genrule {
         "--functions_yaml_path=$(location :executorch_portable_yaml) " +
         "--install_dir=$(genDir)/",
 }
+
+java_library_static {
+    name: "executorch_java",
+    sdk_version: "current",
+    min_sdk_version: "33",
+    srcs: [
+        "extension/android/src/main/java/org/pytorch/executorch/annotations/*.java",
+        "extension/android/src/main/java/org/pytorch/executorch/*.java",
+        "java/com/facebook/soloader/nativeloader/*.java",
+    ],
+    apex_available: [
+        "com.android.ondevicepersonalization",
+    ],
+    static_libs: [
+        "libfbjni_java",
+    ],
+    visibility: [
+        "//packages/modules/OnDevicePersonalization:__subpackages__",
+    ],
+}
+
+cc_library_shared {
+    name: "libexecutorch",
+    srcs: [
+        "extension/android/jni/jni_layer.cpp",
+        "extension/android/jni/log.cpp",
+    ],
+    header_libs: [
+        "jni_headers",
+    ],
+    whole_static_libs: [
+        "libexecutorch_runtime",
+    ],
+    static_libs: [
+        "libfbjni",
+    ],
+    shared_libs: [
+        "liblog",
+    ],
+    stl: "libc++_static",
+    apex_available: ["com.android.ondevicepersonalization"],
+    sdk_version: "current",
+    min_sdk_version: "apex_inherit",
+    visibility: [
+        "//packages/modules/OnDevicePersonalization:__subpackages__",
+    ],
+    cflags: [
+        "-fexceptions",
+    ],
+}
diff --git a/OWNERS b/OWNERS
index c956c29b1..a2a426857 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
-include platform/system/core:main:/janitors/OWNERS
\ No newline at end of file
+include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/executorch/examples b/executorch/examples
new file mode 120000
index 000000000..a6573af9c
--- /dev/null
+++ b/executorch/examples
@@ -0,0 +1 @@
+../examples
\ No newline at end of file
diff --git a/extension/tensor/tensor_ptr.cpp b/extension/tensor/tensor_ptr.cpp
index 514537b2c..ffa853cf6 100644
--- a/extension/tensor/tensor_ptr.cpp
+++ b/extension/tensor/tensor_ptr.cpp
@@ -183,39 +183,6 @@ TensorPtr clone_tensor_ptr(const exec_aten::Tensor& tensor) {
             dynamism);
 }
 
-TensorPtr clone_tensor_ptr(const exec_aten::Tensor& tensor) {
-  std::vector<exec_aten::SizesType> sizes(
-      tensor.sizes().begin(), tensor.sizes().end());
-  std::vector<exec_aten::DimOrderType> dim_order{
-#ifndef USE_ATEN_LIB
-      tensor.dim_order().begin(), tensor.dim_order().end()
-#endif // USE_ATEN_LIB
-  };
-  std::vector<exec_aten::StridesType> strides(
-      tensor.strides().begin(), tensor.strides().end());
-  auto dynamism = exec_aten::TensorShapeDynamism::DYNAMIC_BOUND;
-#ifndef USE_ATEN_LIB
-  dynamism = tensor.shape_dynamism();
-#endif // USE_ATEN_LIB
-  return tensor.const_data_ptr()
-      ? make_tensor_ptr(
-            std::move(sizes),
-            std::vector<uint8_t>(
-                (uint8_t*)tensor.const_data_ptr(),
-                (uint8_t*)tensor.const_data_ptr() + tensor.nbytes()),
-            std::move(dim_order),
-            std::move(strides),
-            tensor.scalar_type(),
-            dynamism)
-      : make_tensor_ptr(
-            std::move(sizes),
-            nullptr,
-            std::move(dim_order),
-            std::move(strides),
-            tensor.scalar_type(),
-            dynamism);
-}
-
 runtime::Error resize_tensor_ptr(
     TensorPtr& tensor,
     const std::vector<exec_aten::SizesType>& sizes) {
@@ -225,4 +192,4 @@ runtime::Error resize_tensor_ptr(
 }
 
 } // namespace extension
-} // namespace executorch
+} // namespace executorch
\ No newline at end of file
diff --git a/extension/tensor/tensor_ptr.h b/extension/tensor/tensor_ptr.h
index eb5d1eb08..ff00bf97b 100644
--- a/extension/tensor/tensor_ptr.h
+++ b/extension/tensor/tensor_ptr.h
@@ -74,30 +74,6 @@ inline TensorPtr make_tensor_ptr(
       std::move(sizes), data, {}, {}, type, dynamism, std::move(deleter));
 }
 
-/**
- * Creates a TensorPtr that manages a Tensor with the specified properties.
- *
- * @param sizes A vector specifying the size of each dimension.
- * @param data A pointer to the data buffer.
- * @param type The scalar type of the tensor elements.
- * @param dynamism Specifies the mutability of the tensor's shape.
- * @param deleter A custom deleter function for managing the lifetime of the
- * data buffer. If provided, this deleter will be called when the managed Tensor
- * object is destroyed.
- * @return A TensorPtr that manages the newly created Tensor.
- */
-inline TensorPtr make_tensor_ptr(
-    std::vector<executorch::aten::SizesType> sizes,
-    void* data,
-    const executorch::aten::ScalarType type =
-        executorch::aten::ScalarType::Float,
-    const executorch::aten::TensorShapeDynamism dynamism =
-        executorch::aten::TensorShapeDynamism::DYNAMIC_BOUND,
-    std::function<void(void*)> deleter = nullptr) {
-  return make_tensor_ptr(make_tensor_impl_ptr(
-      std::move(sizes), data, {}, {}, type, dynamism, std::move(deleter)));
-}
-
 /**
  * Creates a TensorPtr that manages a Tensor with the specified properties.
  *
@@ -363,29 +339,6 @@ inline TensorPtr make_tensor_ptr(const executorch::aten::Tensor& tensor) {
   );
 }
 
-/**
- * Creates a TensorPtr that manages a Tensor with the specified properties.
- *
- * This overload accepts a raw memory buffer stored in a std::vector<uint8_t>
- * and a scalar type to interpret the data. The vector is managed, and the
- * memory's lifetime is tied to the TensorImpl.
- *
- * @param sizes A vector specifying the size of each dimension.
- * @param data A vector containing the raw memory for the tensor's data.
- * @param type The scalar type of the tensor elements.
- * @param dynamism Specifies the mutability of the tensor's shape.
- * @return A TensorPtr managing the newly created Tensor.
- */
-inline TensorPtr make_tensor_ptr(
-    std::vector<executorch::aten::SizesType> sizes,
-    std::vector<uint8_t> data,
-    executorch::aten::ScalarType type = executorch::aten::ScalarType::Float,
-    executorch::aten::TensorShapeDynamism dynamism =
-        executorch::aten::TensorShapeDynamism::DYNAMIC_BOUND) {
-  return make_tensor_ptr(
-      make_tensor_impl_ptr(std::move(sizes), std::move(data), type, dynamism));
-}
-
 /**
  * Creates a TensorPtr that manages a new Tensor with the same properties
  * as the given Tensor, but with a copy of the data owned by the returned
@@ -422,4 +375,4 @@ runtime::Error resize_tensor_ptr(
     const std::vector<executorch::aten::SizesType>& sizes);
 
 } // namespace extension
-} // namespace executorch
+} // namespace executorch
\ No newline at end of file
diff --git a/java/com/facebook/soloader/nativeloader/NativeLoader.java b/java/com/facebook/soloader/nativeloader/NativeLoader.java
new file mode 100644
index 000000000..035253808
--- /dev/null
+++ b/java/com/facebook/soloader/nativeloader/NativeLoader.java
@@ -0,0 +1,43 @@
+package com.facebook.soloader.nativeloader;
+
+/** Facade to load native libraries for android */
+public class NativeLoader {
+
+  private static SystemDelegate sDelegate;
+
+  /** Blocked default constructor */
+  private NativeLoader() {}
+
+  /**
+   * Initializes native code loading for this app. Should be called only once, before any calls to
+   * {@link #loadLibrary(String)}.
+   *
+   * @param delegate Delegate to use for all {@code loadLibrary} calls.
+   */
+  public static void init(SystemDelegate delegate) {
+    synchronized (NativeLoader.class) {
+      if (sDelegate != null) {
+        throw new IllegalStateException("Cannot re-initialize NativeLoader.");
+      }
+      sDelegate = delegate;
+    }
+  }
+
+  /**
+   * Determine whether {@code NativeLoader} has already been initialized. This method should not
+   * normally be used, because initialization should be performed only once during app startup.
+   * However, libraries that want to provide a default initialization for {@code NativeLoader} to
+   * hide its existence from the app can use this method to avoid re-initializing.
+   *
+   * @return True if {@link #init(NativeLoaderDelegate)} has been called.
+   */
+  public static boolean isInitialized() {
+    synchronized (NativeLoader.class) {
+      return sDelegate != null;
+    }
+  }
+
+  public static boolean loadLibrary(String shortName) {
+    return System.loadLibrary(shortName);
+  }
+}
\ No newline at end of file
diff --git a/java/com/facebook/soloader/nativeloader/SystemDelegate.java b/java/com/facebook/soloader/nativeloader/SystemDelegate.java
new file mode 100644
index 000000000..f52ccc378
--- /dev/null
+++ b/java/com/facebook/soloader/nativeloader/SystemDelegate.java
@@ -0,0 +1,4 @@
+package com.facebook.soloader.nativeloader;
+
+/** Class which connects system's native library loader to NativeLoader */
+public class SystemDelegate {}
\ No newline at end of file
```

