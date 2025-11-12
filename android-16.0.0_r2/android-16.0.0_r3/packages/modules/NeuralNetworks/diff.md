```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 296f1874e..99e9e86db 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -67,6 +67,10 @@ apex {
         true: ["com.android.ondeviceintelligence-systemserverclasspath-fragment"],
         default: [],
     }),
+    licenses: [
+        "packages_modules_NeuralNetworks_license",
+        "opensourcerequest",
+    ],
 }
 
 sdk {
diff --git a/common/Android.bp b/common/Android.bp
index 34e5458b5..77b94a12b 100644
--- a/common/Android.bp
+++ b/common/Android.bp
@@ -250,7 +250,7 @@ cc_defaults {
     name: "neuralnetworks_cl_defaults",
     host_supported: false,
     vendor_available: false,
-    cpp_std: "gnu++17",
+    cpp_std: "gnu++17", // To match external/tensorflow.
     stl: "libc++_static",
     sdk_version: "current",
     min_sdk_version: "29",
diff --git a/common/ExecutionBurstServer.cpp b/common/ExecutionBurstServer.cpp
index d119b2f90..7bfe04029 100644
--- a/common/ExecutionBurstServer.cpp
+++ b/common/ExecutionBurstServer.cpp
@@ -25,6 +25,7 @@
 #include <limits>
 #include <map>
 #include <memory>
+#include <mutex>
 #include <thread>
 #include <tuple>
 #include <utility>
diff --git a/common/cpu_operations/TransposeConv2D.cpp b/common/cpu_operations/TransposeConv2D.cpp
index 9262c2fa5..31562e7b6 100644
--- a/common/cpu_operations/TransposeConv2D.cpp
+++ b/common/cpu_operations/TransposeConv2D.cpp
@@ -22,6 +22,7 @@
 #include <cfloat>
 #include <cmath>
 #include <memory>
+#include <mutex>
 #include <vector>
 
 #include "OperationResolver.h"
diff --git a/driver/sample_aidl/SampleDriverAidl.h b/driver/sample_aidl/SampleDriverAidl.h
index b0d444d26..fbb3d3956 100644
--- a/driver/sample_aidl/SampleDriverAidl.h
+++ b/driver/sample_aidl/SampleDriverAidl.h
@@ -21,6 +21,7 @@
 #include <nnapi/hal/aidl/BufferTracker.h>
 #include <nnapi/hal/aidl/HalInterfaces.h>
 
+#include <atomic>
 #include <memory>
 #include <string>
 #include <utility>
diff --git a/runtime/test/fuzzing/RandomVariable.cpp b/runtime/test/fuzzing/RandomVariable.cpp
index f1067e184..8b78bff09 100644
--- a/runtime/test/fuzzing/RandomVariable.cpp
+++ b/runtime/test/fuzzing/RandomVariable.cpp
@@ -17,6 +17,7 @@
 #include "RandomVariable.h"
 
 #include <algorithm>
+#include <iterator>
 #include <memory>
 #include <set>
 #include <string>
```

