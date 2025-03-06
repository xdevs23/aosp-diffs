```diff
diff --git a/Parcel.cpp b/Parcel.cpp
index 190a364..b7cd0b5 100644
--- a/Parcel.cpp
+++ b/Parcel.cpp
@@ -402,31 +402,6 @@ status_t Parcel::finishWrite(size_t len)
     return NO_ERROR;
 }
 
-status_t Parcel::writeUnpadded(const void* data, size_t len)
-{
-    if (len > INT32_MAX) {
-        // don't accept size_t values which may have come from an
-        // inadvertent conversion from a negative int.
-        return BAD_VALUE;
-    }
-
-    size_t end = mDataPos + len;
-    if (end < mDataPos) {
-        // integer overflow
-        return BAD_VALUE;
-    }
-
-    if (end <= mDataCapacity) {
-restart_write:
-        memcpy(mData+mDataPos, data, len);
-        return finishWrite(len);
-    }
-
-    status_t err = growData(len);
-    if (err == NO_ERROR) goto restart_write;
-    return err;
-}
-
 status_t Parcel::write(const void* data, size_t len)
 {
     if (len > INT32_MAX) {
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 07320c9..e56bb83 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -4,20 +4,10 @@
       "name": "libbinderthreadstateutils_test"
     },
     {
-      "name": "SettingsGoogleUnitTests",
-      "options": [
-        {
-          "exclude-annotation": "androidx.test.filters.FlakyTest"
-        }
-      ]
+      "name": "SettingsGoogleUnitTests"
     },
     {
-       "name": "CtsOsTestCases",
-       "options": [
-           {
-              "include-filter": "android.os.cts.HwBinderTest"
-           }
-       ]
+      "name": "CtsOsTestCases_cts_hwbindertest"
     }
   ]
 }
diff --git a/include/hwbinder/Parcel.h b/include/hwbinder/Parcel.h
index f86fabe..8d7af38 100644
--- a/include/hwbinder/Parcel.h
+++ b/include/hwbinder/Parcel.h
@@ -95,7 +95,6 @@ public:
 
     status_t            write(const void* data, size_t len);
     void*               writeInplace(size_t len);
-    status_t            writeUnpadded(const void* data, size_t len);
     status_t            writeInt8(int8_t val);
     status_t            writeUint8(uint8_t val);
     status_t            writeInt16(int16_t val);
diff --git a/vts/performance/Benchmark_binder.cpp b/vts/performance/Benchmark_binder.cpp
index 1458fc9..41c941e 100644
--- a/vts/performance/Benchmark_binder.cpp
+++ b/vts/performance/Benchmark_binder.cpp
@@ -33,6 +33,8 @@ using android::OK;
 using android::sp;
 using android::status_t;
 using android::String16;
+using android::IBinder;
+using android::BBinder;
 
 // libbinder:
 using android::getService;
@@ -58,6 +60,10 @@ class BenchmarkServiceAidl : public BnBenchmark {
         *_aidl_return = data;
         return Status::ok();
     }
+    Status sendBinderVec(const vector<sp<IBinder>>& data, vector<sp<IBinder>>* _aidl_return) {
+        *_aidl_return = data;
+        return Status::ok();
+    }
 };
 
 bool startServer() {
@@ -92,6 +98,28 @@ static void BM_sendVec_binder(benchmark::State& state) {
 
 BENCHMARK(BM_sendVec_binder)->RangeMultiplier(2)->Range(4, 65536);
 
+static void BM_sendBinderVec_binder(benchmark::State& state) {
+    sp<IBenchmark> service;
+    // Prepare data to IPC
+    vector<sp<IBinder>> data_vec;
+    vector<sp<IBinder>> data_return;
+    data_vec.resize(state.range(0));
+    for (int i = 0; i < state.range(0); i++) {
+       data_vec[i] = sp<BBinder>::make();
+    }
+    // getService automatically retries
+    status_t status = getService(String16(kServiceName), &service);
+    if (status != OK) {
+        state.SkipWithError("Failed to retrieve benchmark service.");
+    }
+    // Start running
+    while (state.KeepRunning()) {
+       service->sendBinderVec(data_vec, &data_return);
+    }
+}
+
+BENCHMARK(BM_sendBinderVec_binder)->RangeMultiplier(2)->Range(4, 65536);
+
 int main(int argc, char* argv []) {
     ::benchmark::Initialize(&argc, argv);
 
```

