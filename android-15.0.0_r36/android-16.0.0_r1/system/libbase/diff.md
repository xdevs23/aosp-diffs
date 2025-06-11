```diff
diff --git a/Android.bp b/Android.bp
index 0679889..d132bc9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -173,6 +173,7 @@ cc_library_static {
     whole_static_libs: ["fmtlib_ndk"],
     apex_available: [
         "//apex_available:platform",
+        "com.android.media",
         "com.android.mediaprovider",
     ],
 }
@@ -257,40 +258,10 @@ cc_test {
     test_suites: ["device_tests"],
 }
 
-// Can be removed when we move to c++20
-cc_test {
-    name: "libbase_result_constraint_test",
-    defaults: ["libbase_cflags_defaults"],
-    host_supported: true,
-    srcs: [
-        "result_test_constraint.cpp",
-    ],
-    target: {
-        android: {
-            sanitize: {
-                misc_undefined: ["integer"],
-            },
-        },
-    },
-    cpp_std: "gnu++20",
-    local_include_dirs: ["."],
-    shared_libs: ["libbase"],
-    static_libs: ["libgmock"],
-    compile_multilib: "both",
-    multilib: {
-        lib32: {
-            suffix: "32",
-        },
-        lib64: {
-            suffix: "64",
-        },
-    },
-    test_suites: ["device-tests"],
-}
-
 cc_benchmark {
     name: "libbase_benchmark",
     defaults: ["libbase_cflags_defaults"],
+    host_supported: true,
 
     srcs: [
         "file_benchmark.cpp",
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..cfa5095 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,4 +5,3 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/file_benchmark.cpp b/file_benchmark.cpp
index 86252ce..bf41a09 100644
--- a/file_benchmark.cpp
+++ b/file_benchmark.cpp
@@ -16,6 +16,7 @@
 
 #include <fcntl.h>
 #include <sys/mman.h>
+#include <sys/syscall.h>
 #include <unistd.h>
 
 #include <benchmark/benchmark.h>
@@ -23,8 +24,8 @@
 #include "android-base/file.h"
 #include "android-base/logging.h"
 
-static void BenchmarkReadFdToString(benchmark::State& state) {
-  android::base::unique_fd fd(memfd_create("memfile", 0));
+static void BM_ReadFdToString(benchmark::State& state) {
+  android::base::unique_fd fd(syscall(__NR_memfd_create, "memfile", 0));
   CHECK(fd.get() > 0);
   CHECK_EQ(ftruncate(fd, state.range(0)), 0);
   for (auto _ : state) {
@@ -35,4 +36,4 @@ static void BenchmarkReadFdToString(benchmark::State& state) {
   state.SetBytesProcessed(state.iterations() * state.range(0));
 }
 
-BENCHMARK_RANGE(BenchmarkReadFdToString, 0, 1024 * 1024);
+BENCHMARK_RANGE(BM_ReadFdToString, 0, 1024 * 1024);
diff --git a/format_benchmark.cpp b/format_benchmark.cpp
index 9590b23..3633e6c 100644
--- a/format_benchmark.cpp
+++ b/format_benchmark.cpp
@@ -16,6 +16,8 @@
 
 #include "android-base/format.h"
 
+#include <unistd.h>
+
 #include <limits>
 
 #include <benchmark/benchmark.h>
@@ -24,57 +26,74 @@
 
 using android::base::StringPrintf;
 
-static void BenchmarkFormatInt(benchmark::State& state) {
+static pid_t pid = getpid();
+static int fd = 123;
+
+static void BM_format_fmt_format_ints(benchmark::State& state) {
   for (auto _ : state) {
-    benchmark::DoNotOptimize(fmt::format("{} {} {}", 42, std::numeric_limits<int>::min(),
-                                         std::numeric_limits<int>::max()));
+    benchmark::DoNotOptimize(fmt::format("/proc/{}/fd/{}", pid, fd));
   }
 }
+BENCHMARK(BM_format_fmt_format_ints);
 
-BENCHMARK(BenchmarkFormatInt);
-
-static void BenchmarkStringPrintfInt(benchmark::State& state) {
+static void BM_format_std_format_ints(benchmark::State& state) {
   for (auto _ : state) {
-    benchmark::DoNotOptimize(StringPrintf("%d %d %d", 42, std::numeric_limits<int>::min(),
-                                          std::numeric_limits<int>::max()));
+    benchmark::DoNotOptimize(std::format("/proc/{}/fd/{}", pid, fd));
   }
 }
+BENCHMARK(BM_format_std_format_ints);
 
-BENCHMARK(BenchmarkStringPrintfInt);
+static void BM_format_StringPrintf_ints(benchmark::State& state) {
+  for (auto _ : state) {
+    benchmark::DoNotOptimize(StringPrintf("/proc/%d/fd/%d", pid, fd));
+  }
+}
+BENCHMARK(BM_format_StringPrintf_ints);
 
-static void BenchmarkFormatFloat(benchmark::State& state) {
+static void BM_format_fmt_format_floats(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(fmt::format("{} {} {}", 42.42, std::numeric_limits<float>::min(),
                                          std::numeric_limits<float>::max()));
   }
 }
+BENCHMARK(BM_format_fmt_format_floats);
 
-BENCHMARK(BenchmarkFormatFloat);
+static void BM_format_std_format_floats(benchmark::State& state) {
+  for (auto _ : state) {
+    benchmark::DoNotOptimize(std::format("{} {} {}", 42.42, std::numeric_limits<float>::min(),
+                                         std::numeric_limits<float>::max()));
+  }
+}
+BENCHMARK(BM_format_std_format_floats);
 
-static void BenchmarkStringPrintfFloat(benchmark::State& state) {
+static void BM_format_StringPrintf_floats(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(StringPrintf("%f %f %f", 42.42, std::numeric_limits<float>::min(),
                                           std::numeric_limits<float>::max()));
   }
 }
+BENCHMARK(BM_format_StringPrintf_floats);
 
-BENCHMARK(BenchmarkStringPrintfFloat);
-
-static void BenchmarkFormatStrings(benchmark::State& state) {
+static void BM_format_fmt_format_strings(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(fmt::format("{} hello there {}", "hi,", "!!"));
   }
 }
+BENCHMARK(BM_format_fmt_format_strings);
 
-BENCHMARK(BenchmarkFormatStrings);
+static void BM_format_std_format_strings(benchmark::State& state) {
+  for (auto _ : state) {
+    benchmark::DoNotOptimize(std::format("{} hello there {}", "hi,", "!!"));
+  }
+}
+BENCHMARK(BM_format_std_format_strings);
 
-static void BenchmarkStringPrintfStrings(benchmark::State& state) {
+static void BM_format_StringPrintf_strings(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(StringPrintf("%s hello there %s", "hi,", "!!"));
   }
 }
-
-BENCHMARK(BenchmarkStringPrintfStrings);
+BENCHMARK(BM_format_StringPrintf_strings);
 
 // Run the benchmark
 BENCHMARK_MAIN();
diff --git a/function_ref_benchmark.cpp b/function_ref_benchmark.cpp
index 404043e..36a2c6f 100644
--- a/function_ref_benchmark.cpp
+++ b/function_ref_benchmark.cpp
@@ -36,36 +36,36 @@ template <class Callable, class... Args>
 
 using Func = decltype(testFunc);
 
-static void BenchmarkFuncRaw(benchmark::State& state) {
+static void BM_FuncRaw(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(testFunc, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkFuncRaw);
+BENCHMARK(BM_FuncRaw);
 
-static void BenchmarkFuncPtr(benchmark::State& state) {
+static void BM_FuncPtr(benchmark::State& state) {
   auto ptr = &testFunc;
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(ptr, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkFuncPtr);
+BENCHMARK(BM_FuncPtr);
 
-static void BenchmarkStdFunction(benchmark::State& state) {
+static void BM_StdFunction(benchmark::State& state) {
   std::function<Func> f(testFunc);
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(f, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkStdFunction);
+BENCHMARK(BM_StdFunction);
 
-static void BenchmarkFunctionRef(benchmark::State& state) {
+static void BM_FunctionRef(benchmark::State& state) {
   function_ref<Func> f(testFunc);
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(f, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkFunctionRef);
+BENCHMARK(BM_FunctionRef);
 
 namespace {
 struct BigFunc {
@@ -76,39 +76,39 @@ struct BigFunc {
 static BigFunc bigFunc;
 }  // namespace
 
-static void BenchmarkBigRaw(benchmark::State& state) {
+static void BM_BigRaw(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(bigFunc, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkBigRaw);
+BENCHMARK(BM_BigRaw);
 
-static void BenchmarkBigStdFunction(benchmark::State& state) {
+static void BM_BigStdFunction(benchmark::State& state) {
   std::function<Func> f(bigFunc);
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(f, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkBigStdFunction);
+BENCHMARK(BM_BigStdFunction);
 
-static void BenchmarkBigFunctionRef(benchmark::State& state) {
+static void BM_BigFunctionRef(benchmark::State& state) {
   function_ref<Func> f(bigFunc);
   for (auto _ : state) {
     benchmark::DoNotOptimize(call(f, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkBigFunctionRef);
+BENCHMARK(BM_BigFunctionRef);
 
-static void BenchmarkMakeFunctionRef(benchmark::State& state) {
+static void BM_MakeFunctionRef(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(call<function_ref<Func>>(bigFunc, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkMakeFunctionRef);
+BENCHMARK(BM_MakeFunctionRef);
 
-static void BenchmarkMakeStdFunction(benchmark::State& state) {
+static void BM_MakeStdFunction(benchmark::State& state) {
   for (auto _ : state) {
     benchmark::DoNotOptimize(call<std::function<Func>>(bigFunc, 1, "1", '1'));
   }
 }
-BENCHMARK(BenchmarkMakeStdFunction);
+BENCHMARK(BM_MakeStdFunction);
diff --git a/hex.cpp b/hex.cpp
index a4b7715..60dc31a 100644
--- a/hex.cpp
+++ b/hex.cpp
@@ -38,5 +38,36 @@ std::string HexString(const void* bytes, size_t len) {
   return result;
 }
 
+static uint8_t HexNybbleToValue(char c) {
+  if (c >= '0' && c <= '9') {
+    return c - '0';
+  }
+  if (c >= 'a' && c <= 'f') {
+    return c - 'a' + 10;
+  }
+  if (c >= 'A' && c <= 'Z') {
+    return c - 'A' + 10;
+  }
+  return 0xff;
+}
+
+bool HexToBytes(const std::string& hex, std::vector<uint8_t>* bytes) {
+  if (hex.size() % 2 != 0) {
+    LOG(ERROR) << "HexToBytes: Invalid size: " << hex.size();
+    return false;
+  }
+  bytes->resize(hex.size() / 2);
+  for (unsigned i = 0; i < bytes->size(); i++) {
+    uint8_t hi = HexNybbleToValue(hex[i * 2]);
+    uint8_t lo = HexNybbleToValue(hex[i * 2 + 1]);
+    if (lo > 0xf || hi > 0xf) {
+      LOG(ERROR) << "HexToBytes: Invalid characters: " << hex[i * 2] << ", " << hex[i * 2 + 1];
+      return false;
+    }
+    (*bytes)[i] = (hi << 4) | lo;
+  }
+  return true;
+}
+
 }  // namespace base
 }  // namespace android
diff --git a/hex_test.cpp b/hex_test.cpp
index ebf798c..6c17a44 100644
--- a/hex_test.cpp
+++ b/hex_test.cpp
@@ -29,6 +29,25 @@ TEST(hex, short) {
   ASSERT_EQ("efbe", android::base::HexString(&kShortData, 2));
   ASSERT_EQ("efbead", android::base::HexString(&kShortData, 3));
   ASSERT_EQ("efbeadde", android::base::HexString(&kShortData, 4));
+
+  std::vector<uint8_t> bytes;
+  std::string hex;
+
+  hex = android::base::HexString(&kShortData, 1);
+  ASSERT_TRUE(android::base::HexToBytes(hex, &bytes));
+  ASSERT_EQ("ef", android::base::HexString(bytes.data(), bytes.size()));
+
+  hex = android::base::HexString(&kShortData, 2);
+  ASSERT_TRUE(android::base::HexToBytes(hex, &bytes));
+  ASSERT_EQ("efbe", android::base::HexString(bytes.data(), bytes.size()));
+
+  hex = android::base::HexString(&kShortData, 3);
+  ASSERT_TRUE(android::base::HexToBytes(hex, &bytes));
+  ASSERT_EQ("efbead", android::base::HexString(bytes.data(), bytes.size()));
+
+  hex = android::base::HexString(&kShortData, 4);
+  ASSERT_TRUE(android::base::HexToBytes(hex, &bytes));
+  ASSERT_EQ("efbeadde", android::base::HexString(bytes.data(), bytes.size()));
 }
 
 TEST(hex, all) {
@@ -46,4 +65,32 @@ TEST(hex, all) {
       "b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"
       "e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
       android::base::HexString(&kLongData, kSize));
+
+  std::vector<uint8_t> bytes;
+  std::string hex;
+
+  hex = android::base::HexString(&kLongData, kSize);
+  ASSERT_TRUE(android::base::HexToBytes(hex, &bytes));
+  ASSERT_EQ(
+      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d"
+      "2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
+      "5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586878889"
+      "8a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7"
+      "b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"
+      "e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
+      android::base::HexString(bytes.data(), bytes.size()));
+}
+
+TEST(HexToBytesTest, InvalidCharacters) {
+  std::string hex_string = "12GX";
+  std::vector<uint8_t> bytes;
+
+  ASSERT_FALSE(android::base::HexToBytes(hex_string, &bytes));
+}
+
+TEST(HexToBytesTest, InvalidLength) {
+  std::string hex_string = "123";
+  std::vector<uint8_t> bytes;
+
+  ASSERT_FALSE(android::base::HexToBytes(hex_string, &bytes));
 }
diff --git a/include/android-base/hex.h b/include/android-base/hex.h
index cbb26a8..8c7677c 100644
--- a/include/android-base/hex.h
+++ b/include/android-base/hex.h
@@ -17,6 +17,9 @@
 #pragma once
 
 #include <string>
+#include <vector>
+
+#include <stdint.h>
 
 namespace android {
 namespace base {
@@ -27,5 +30,13 @@ namespace base {
 // Android is little-endian.
 std::string HexString(const void* bytes, size_t len);
 
+// Converts hexString to binary data.
+//
+// hex: Input hexString
+// bytes: Output binary data
+//
+// Returns true on success, false on failure
+bool HexToBytes(const std::string& hex, std::vector<uint8_t>* bytes);
+
 }  // namespace base
 }  // namespace android
diff --git a/logging.cpp b/logging.cpp
index 51f0ef9..6ba8ea7 100644
--- a/logging.cpp
+++ b/logging.cpp
@@ -433,14 +433,14 @@ class LogMessageData {
  public:
   LogMessageData(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                  int error)
-      : file_(GetFileBasename(file)),
+      : file_(file),
         line_number_(line),
         severity_(severity),
         tag_(tag),
         error_(error) {}
 
   const char* GetFile() const {
-    return file_;
+    return GetFileBasename(file_);
   }
 
   unsigned int GetLineNumber() const {
diff --git a/result_test_constraint.cpp b/result_test_constraint.cpp
deleted file mode 100644
index 253a276..0000000
--- a/result_test_constraint.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// Since result has c++20 conditional behavior, we compile with std=c++20 to
-// ensure functionality in both cases. Instead of duplicating the file, we will
-// include, since this test is not linked against anything.
-// This test can be removed when we move to c++20.
-#include "result_test.cpp"
```

