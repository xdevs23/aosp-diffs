```diff
diff --git a/tests/c2_e2e_test/jni/Android.bp b/tests/c2_e2e_test/jni/Android.bp
index 7507c30..8052d1c 100644
--- a/tests/c2_e2e_test/jni/Android.bp
+++ b/tests/c2_e2e_test/jni/Android.bp
@@ -31,6 +31,4 @@ cc_library_shared {
     sdk_version: "28",
     stl: "c++_static",
     static_libs: ["libgtest_ndk_c++"],
-    // TODO(stevensd): Fix and reenable warnings
-    cflags: ["-Wno-everything"],
 }
diff --git a/tests/c2_e2e_test/jni/common.h b/tests/c2_e2e_test/jni/common.h
index 1425b62..4e749fe 100644
--- a/tests/c2_e2e_test/jni/common.h
+++ b/tests/c2_e2e_test/jni/common.h
@@ -71,6 +71,7 @@ class InputFile {
 public:
     explicit InputFile(std::string file_path);
     InputFile(std::string file_path, std::ios_base::openmode openmode);
+    virtual ~InputFile() = default;
 
     // Check if the file is valid.
     bool IsValid() const;
diff --git a/tests/c2_e2e_test/jni/e2e_test_jni.cpp b/tests/c2_e2e_test/jni/e2e_test_jni.cpp
index 841cb83..4b394bc 100644
--- a/tests/c2_e2e_test/jni/e2e_test_jni.cpp
+++ b/tests/c2_e2e_test/jni/e2e_test_jni.cpp
@@ -23,7 +23,7 @@ class JniConfigureCallback : public android::ConfigureCallback {
 public:
     JniConfigureCallback(JNIEnv* env, jobject thiz) : env_(env), thiz_(thiz) {}
 
-    static constexpr char* kClassName = "org/chromium/c2/test/E2eTestActivity";
+    static constexpr char kClassName[] = "org/chromium/c2/test/E2eTestActivity";
 
     void OnCodecReady(void* codec) override {
         jclass cls = env_->FindClass(kClassName);
@@ -72,7 +72,7 @@ JNIEXPORT jint JNICALL Java_org_chromium_c2_test_E2eTestActivity_c2VideoTest(
     }
 
     char** final_args = new char*[test_args_count + 1];
-    final_args[0] = "e2e_test_jni";
+    final_args[0] = const_cast<char*>("e2e_test_jni");
     memcpy(final_args + 1, args, sizeof(args[0]) * test_args_count);
 
     ANativeWindow* native_window = ANativeWindow_fromSurface(env, surface);
diff --git a/tests/c2_e2e_test/jni/encoded_data_helper.cpp b/tests/c2_e2e_test/jni/encoded_data_helper.cpp
index 54e4382..643fbe9 100644
--- a/tests/c2_e2e_test/jni/encoded_data_helper.cpp
+++ b/tests/c2_e2e_test/jni/encoded_data_helper.cpp
@@ -124,7 +124,7 @@ EncodedDataHelper::EncodedDataHelper(const std::string& file_path, VideoCodecTyp
 
 EncodedDataHelper::~EncodedDataHelper() {}
 
-const EncodedDataHelper::Fragment* const EncodedDataHelper::GetNextFragment() {
+const EncodedDataHelper::Fragment* EncodedDataHelper::GetNextFragment() {
     if (ReachEndOfStream()) return nullptr;
     return next_fragment_iter_++->get();
 }
diff --git a/tests/c2_e2e_test/jni/encoded_data_helper.h b/tests/c2_e2e_test/jni/encoded_data_helper.h
index 9ec5086..538d570 100644
--- a/tests/c2_e2e_test/jni/encoded_data_helper.h
+++ b/tests/c2_e2e_test/jni/encoded_data_helper.h
@@ -30,7 +30,7 @@ public:
 
     // Return the next fragment to be sent to the decoder, and advance the
     // iterator to after the returned fragment.
-    const Fragment* const GetNextFragment();
+    const Fragment* GetNextFragment();
 
     void Rewind() { next_fragment_iter_ = fragments_.begin(); }
     bool IsValid() const { return !fragments_.empty(); }
```

