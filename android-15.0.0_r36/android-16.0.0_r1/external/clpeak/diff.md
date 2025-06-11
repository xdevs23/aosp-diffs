```diff
diff --git a/.gitmodules b/.gitmodules
deleted file mode 100644
index b1145c3..0000000
--- a/.gitmodules
+++ /dev/null
@@ -1,4 +0,0 @@
-[submodule "libopencl-stub"]
-	path = android/app/src/main/cpp/libopencl-stub
-	url = https://github.com/krrishnarraj/libopencl-stub
-	branch = master
diff --git a/METADATA b/METADATA
index 754a9eb..2449494 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,21 @@
-name: "clpeak"
-description:
-    "A synthetic benchmarking tool to measure peak capabilities of opencl devices."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/clpeak
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "clpeak"
+description: "A synthetic benchmarking tool to measure peak capabilities of opencl devices."
 third_party {
-homepage: "https://github.com/krrishnarraj/clpeak"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 16
+  }
+  homepage: "https://github.com/krrishnarraj/clpeak"
   identifier {
     type: "Archive"
-    value: "https://github.com/krrishnarraj/clpeak"
+    value: "https://github.com/krrishnarraj/clpeak/archive/1.1.4.zip"
+    version: "1.1.4"
     primary_source: true
   }
-  version: "1.1.2"
-  last_upgrade_date { year: 2024 month: 5 day: 30 }
-  license_type: NOTICE
 }
-
diff --git a/OWNERS b/OWNERS
index 07b6a34..7887cd8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,3 +6,4 @@ jpakaravoor@google.com
 kevindubois@google.com
 include platform/system/core:main:/janitors/OWNERS
 
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/cmake/common.cmake b/cmake/common.cmake
index c96551f..141b785 100644
--- a/cmake/common.cmake
+++ b/cmake/common.cmake
@@ -1,7 +1,7 @@
 
 set(VERSION_MAJOR 1)
 set(VERSION_MINOR 1)
-set(VERSION_PATCH 2)
+set(VERSION_PATCH 4)
 set(VERSION_SUFFIX "")
 set(VERSION_STR "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_SUFFIX}")
 
diff --git a/results/Moore_Threads_OpenCL/MTT_S80.log b/results/Moore_Threads_OpenCL/MTT_S80.log
new file mode 100644
index 0000000..463ca61
--- /dev/null
+++ b/results/Moore_Threads_OpenCL/MTT_S80.log
@@ -0,0 +1,73 @@
+Platform: Moore Threads OpenCL
+  Device: MUSA GEN1-104
+    Driver version  : 20241010 release kuae1.3.0_musa3.1.0 db329f8fb@20241009  (Linux x64)
+    Compute units   : 32
+    Clock frequency : 1799 MHz
+
+    Global memory bandwidth (GBPS)
+      float   : 273.11
+      float2  : 374.98
+      float4  : 387.00
+      float8  : 391.09
+      float16 : 399.77
+
+    Single-precision compute (GFLOPS)
+      float   : 14176.27
+      float2  : 13376.75
+      float4  : 13451.20
+      float8  : 13425.36
+      float16 : 13350.33
+
+    Half-precision compute (GFLOPS)
+      half   : 13296.25
+      half2  : 13387.43
+      half4  : 13450.06
+      half8  : 13437.34
+      half16 : 13368.42
+
+    Double-precision compute (GFLOPS)
+      double   : 35.60
+      double2  : 30.19
+      double4  : 21.89
+      double8  : 13.00
+      double16 : 7.04
+
+    Integer compute (GIOPS)
+      int   : 2094.24
+      int2  : 2092.97
+      int4  : 2096.44
+      int8  : 2096.89
+      int16 : 2099.12
+
+    Integer compute Fast 24bit (GIOPS)
+      int   : 2094.74
+      int2  : 2092.97
+      int4  : 2095.84
+      int8  : 2097.56
+      int16 : 2099.13
+
+    Integer char (8bit) compute (GIOPS)
+      char   : 2095.43
+      char2  : 2093.63
+      char4  : 2097.98
+      char8  : 2097.77
+      char16 : 2100.38
+
+    Integer short (16bit) compute (GIOPS)
+      short   : 2095.20
+      short2  : 2093.82
+      short4  : 2096.92
+      short8  : 2098.04
+      short16 : 2099.83
+
+    Transfer bandwidth (GBPS)
+      enqueueWriteBuffer              : 5.84
+      enqueueReadBuffer               : 5.92
+      enqueueWriteBuffer non-blocking : 5.85
+      enqueueReadBuffer non-blocking  : 5.91
+      enqueueMapBuffer(for read)      : 5743.47
+        memcpy from mapped ptr        : 0.02
+      enqueueUnmap(after write)       : 6042.44
+        memcpy to mapped ptr          : 5.03
+
+    Kernel launch latency : 48.02 us
diff --git a/results/NVIDIA_CUDA/GeForce_GTX_1660_Ti.log b/results/NVIDIA_CUDA/GeForce_GTX_1660_Ti.log
new file mode 100644
index 0000000..9856d3d
--- /dev/null
+++ b/results/NVIDIA_CUDA/GeForce_GTX_1660_Ti.log
@@ -0,0 +1,68 @@
+Platform: NVIDIA CUDA
+  Device: NVIDIA GeForce GTX 1660 Ti
+    Driver version  : 565.57.01 (Linux x64)
+    Compute units   : 24
+    Clock frequency : 1590 MHz
+
+    Global memory bandwidth (GBPS)
+      float   : 235.92
+      float2  : 247.28
+      float4  : 260.64
+      float8  : 254.10
+      float16 : 217.35
+
+    Single-precision compute (GFLOPS)
+      float   : 5692.43
+      float2  : 5705.85
+      float4  : 5697.71
+      float8  : 5497.52
+      float16 : 4822.71
+
+    No half precision support! Skipped
+
+    Double-precision compute (GFLOPS)
+      double   : 166.56
+      double2  : 169.71
+      double4  : 151.43
+      double8  : 152.88
+      double16 : 163.43
+
+    Integer compute (GIOPS)
+      int   : 5009.23
+      int2  : 5025.67
+      int4  : 4511.78
+      int8  : 4535.21
+      int16 : 4828.46
+
+    Integer compute Fast 24bit (GIOPS)
+      int   : 5030.41
+      int2  : 5000.83
+      int4  : 5002.84
+      int8  : 4461.20
+      int16 : 4415.56
+
+    Integer char (8bit) compute (GIOPS)
+      char   : 4137.69
+      char2  : 4238.38
+      char4  : 4174.55
+      char8  : 4234.00
+      char16 : 3432.68
+
+    Integer short (16bit) compute (GIOPS)
+      short   : 4185.20
+      short2  : 4014.07
+      short4  : 4125.94
+      short8  : 3622.42
+      short16 : 3496.44
+
+    Transfer bandwidth (GBPS)
+      enqueueWriteBuffer              : 6.85
+      enqueueReadBuffer               : 6.92
+      enqueueWriteBuffer non-blocking : 6.14
+      enqueueReadBuffer non-blocking  : 6.08
+      enqueueMapBuffer(for read)      : 9.77
+        memcpy from mapped ptr        : 11.68
+      enqueueUnmap(after write)       : 12.33
+        memcpy to mapped ptr          : 11.99
+
+    Kernel launch latency : 4.14 us
diff --git a/results/NVIDIA_CUDA/Tesla_P40.log b/results/NVIDIA_CUDA/Tesla_P40.log
new file mode 100644
index 0000000..ceb26b9
--- /dev/null
+++ b/results/NVIDIA_CUDA/Tesla_P40.log
@@ -0,0 +1,68 @@
+Platform: NVIDIA CUDA
+  Device: Tesla P40
+    Driver version  : 550.54.14 (Linux x64)
+    Compute units   : 30
+    Clock frequency : 1531 MHz
+
+    Global memory bandwidth (GBPS)
+      float   : 282.85
+      float2  : 294.10
+      float4  : 301.39
+      float8  : 279.29
+      float16 : 193.72
+
+    Single-precision compute (GFLOPS)
+      float   : 11153.70
+      float2  : 11505.40
+      float4  : 11475.82
+      float8  : 11410.92
+      float16 : 11367.69
+
+    No half precision support! Skipped
+
+    Double-precision compute (GFLOPS)
+      double   : 367.62
+      double2  : 367.05
+      double4  : 366.32
+      double8  : 365.52
+      double16 : 362.97
+
+    Integer compute (GIOPS)
+      int   : 3897.08
+      int2  : 3889.65
+      int4  : 3904.29
+      int8  : 3610.75
+      int16 : 3540.68
+
+    Integer compute Fast 24bit (GIOPS)
+      int   : 3895.72
+      int2  : 3901.65
+      int4  : 3895.32
+      int8  : 3882.49
+      int16 : 3866.57
+
+    Integer char (8bit) compute (GIOPS)
+      char   : 10813.47
+      char2  : 11447.82
+      char4  : 11485.37
+      char8  : 11522.07
+      char16 : 11404.32
+
+    Integer short (16bit) compute (GIOPS)
+      short   : 10708.50
+      short2  : 11449.04
+      short4  : 11481.69
+      short8  : 11518.50
+      short16 : 11333.30
+
+    Transfer bandwidth (GBPS)
+      enqueueWriteBuffer              : 6.17
+      enqueueReadBuffer               : 6.45
+      enqueueWriteBuffer non-blocking : 5.68
+      enqueueReadBuffer non-blocking  : 6.37
+      enqueueMapBuffer(for read)      : 5.75
+        memcpy from mapped ptr        : 9.36
+      enqueueUnmap(after write)       : 6.27
+        memcpy to mapped ptr          : 9.36
+
+    Kernel launch latency : 3.78 us
\ No newline at end of file
diff --git a/results/NVIDIA_CUDA/Tesla_T4.log b/results/NVIDIA_CUDA/Tesla_T4.log
new file mode 100644
index 0000000..375f057
--- /dev/null
+++ b/results/NVIDIA_CUDA/Tesla_T4.log
@@ -0,0 +1,45 @@
+Platform: NVIDIA CUDA
+  Device: Tesla T4
+    Driver version  : 560.35.03 (Linux x64)
+    Compute units   : 40
+    Clock frequency : 1590 MHz
+
+    Global memory bandwidth (GBPS)
+      float   : 235.00
+      float2  : 247.01
+      float4  : 253.11
+      float8  : 263.44
+      float16 : 252.38
+
+    Single-precision compute (GFLOPS)
+      float   : 8030.45
+      float2  : 8034.32
+      float4  : 7985.38
+      float8  : 7848.48
+      float16 : 7651.69
+
+    No half precision support! Skipped
+
+    Double-precision compute (GFLOPS)
+      double   : 256.45
+      double2  : 256.03
+      double4  : 253.74
+      double8  : 252.76
+      double16 : 251.68
+
+    Integer compute (GIOPS)
+      int   : 5802.79
+      int2  : 5715.24
+      int4  : 5742.30
+      int8  : 5863.19
+      int16 : 5711.99
+
+    Transfer bandwidth (GBPS)
+      enqueueWriteBuffer         : 4.73
+      enqueueReadBuffer          : 4.78
+      enqueueMapBuffer(for read) : 8.73
+        memcpy from mapped ptr   : 5.39
+      enqueueUnmap(after write)  : 12.17
+        memcpy to mapped ptr     : 5.39
+
+    Kernel launch latency : 5.82 us
diff --git a/src/clpeak.cpp b/src/clpeak.cpp
index 5ce2a5b..55bba64 100644
--- a/src/clpeak.cpp
+++ b/src/clpeak.cpp
@@ -22,12 +22,12 @@ extern "C"
 }
 #endif
 
-clPeak::clPeak() : forcePlatform(false), forceDevice(false), forceTest(false), useEventTimer(false),
-                   isGlobalBW(true), isComputeHP(true), isComputeSP(true), isComputeDP(true), isComputeIntFast(true), isComputeInt(true),
-                   isComputeChar(true), isComputeShort(true),
-                   isTransferBW(true), isKernelLatency(true),
+clPeak::clPeak() : forcePlatform(false), forcePlatformName(false), forceDevice(false),
+                   forceDeviceName(false), forceTest(false), useEventTimer(false),
+                   isGlobalBW(true), isComputeHP(true), isComputeSP(true), isComputeDP(true),
+                   isComputeIntFast(true), isComputeInt(true),
+                   isTransferBW(true), isKernelLatency(true), isComputeChar(true), isComputeShort(true),
                    specifiedPlatform(0), specifiedDevice(0),
-                   forcePlatformName(false), forceDeviceName(false),
                    specifiedPlatformName(0), specifiedDeviceName(0), specifiedTestName(0)
 {
 }
@@ -60,7 +60,7 @@ int clPeak::runAll()
       std::string platformName = platforms[p].getInfo<CL_PLATFORM_NAME>();
       trimString(platformName);
 
-      if (forcePlatformName && (!strcmp(platformName.c_str(), specifiedPlatformName) == 0))
+      if (forcePlatformName && !(strcmp(platformName.c_str(), specifiedPlatformName) == 0))
         continue;
 
       log->print(NEWLINE "Platform: " + platformName + NEWLINE);
@@ -84,7 +84,7 @@ int clPeak::runAll()
 
         device_info_t devInfo = getDeviceInfo(devices[d]);
 
-        if (forceDeviceName && (!strcmp(devInfo.deviceName.c_str(), specifiedDeviceName) == 0))
+        if (forceDeviceName && !(strcmp(devInfo.deviceName.c_str(), specifiedDeviceName) == 0))
           continue;
 
         log->print(TAB "Device: " + devInfo.deviceName + NEWLINE);
diff --git a/src/transfer_bandwidth.cpp b/src/transfer_bandwidth.cpp
index 1b4e084..f889d23 100644
--- a/src/transfer_bandwidth.cpp
+++ b/src/transfer_bandwidth.cpp
@@ -1,4 +1,5 @@
 #include <clpeak.h>
+#include <cstdlib>
 
 int clPeak::runTransferBandwidthTest(cl::CommandQueue &queue, cl::Program &prog, device_info_t &devInfo)
 {
@@ -17,7 +18,7 @@ int clPeak::runTransferBandwidthTest(cl::CommandQueue &queue, cl::Program &prog,
 
   try
   {
-    arr = new float[numItems];
+    arr = static_cast<float *>(aligned_alloc(64, numItems * sizeof(float)));
     memset(arr, 0, numItems * sizeof(float));
     cl::Buffer clBuffer = cl::Buffer(ctx, (CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR), (numItems * sizeof(float)));
 
@@ -324,7 +325,7 @@ int clPeak::runTransferBandwidthTest(cl::CommandQueue &queue, cl::Program &prog,
     log->xmlCloseTag(); // transfer_bandwidth
 
     if (arr)
-      delete[] arr;
+      std::free(arr);
   }
   catch (cl::Error &error)
   {
@@ -335,7 +336,7 @@ int clPeak::runTransferBandwidthTest(cl::CommandQueue &queue, cl::Program &prog,
 
     if (arr)
     {
-      delete[] arr;
+      std::free(arr);
     }
     return -1;
   }
```

