```diff
diff --git a/OWNERS b/OWNERS
index ff7a6cf..3c6125c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,3 @@
 enh@google.com
 narayan@google.com
-xunchang@google.com
+zyy@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..cfa5095 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,4 +5,3 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/incfs_support/include/incfs_support/signal_handling.h b/incfs_support/include/incfs_support/signal_handling.h
index 73e65ba..8c721d0 100644
--- a/incfs_support/include/incfs_support/signal_handling.h
+++ b/incfs_support/include/incfs_support/signal_handling.h
@@ -180,7 +180,10 @@ class ScopedJmpBuf final {
 
 class SignalHandler final {
  public:
-  static SignalHandler& instance();
+  static SignalHandler& instance() {
+    static SignalHandler self;
+    return self;
+  }
 
  private:
   SignalHandler();
diff --git a/incfs_support/signal_handling.cpp b/incfs_support/signal_handling.cpp
index 39cb0c6..0f660b6 100644
--- a/incfs_support/signal_handling.cpp
+++ b/incfs_support/signal_handling.cpp
@@ -31,11 +31,6 @@ static void enableSignal(int code) {
 
 ScopedJmpBuf::~ScopedJmpBuf() { SignalHandler::mJmpBuf = mPrev; }
 
-SignalHandler& SignalHandler::instance() {
-  static SignalHandler self;
-  return self;
-}
-
 SignalHandler::SignalHandler() {
   const struct sigaction action = {
       .sa_sigaction = &handler,
diff --git a/testdata/hugefile.zip b/testdata/hugefile.zip
new file mode 100644
index 0000000..1268fb5
Binary files /dev/null and b/testdata/hugefile.zip differ
diff --git a/zip_archive.cc b/zip_archive.cc
index c720eb4..5a0271f 100644
--- a/zip_archive.cc
+++ b/zip_archive.cc
@@ -1257,7 +1257,8 @@ class FileWriter final : public zip_archive::Writer {
       return {};
     }
 
-    if (declared_length > SIZE_MAX || declared_length > INT64_MAX) {
+    // fallocate() takes a signed size, so restrict the length to avoid errors.
+    if (declared_length > INT64_MAX) {
       ALOGE("Zip: file size %" PRIu64 " is too large to extract.", declared_length);
       return {};
     }
@@ -1276,7 +1277,7 @@ class FileWriter final : public zip_archive::Writer {
       long result = TEMP_FAILURE_RETRY(fallocate(fd, 0, current_offset, declared_length));
       if (result == -1 && errno == ENOSPC) {
         ALOGE("Zip: unable to allocate %" PRIu64 " bytes at offset %" PRId64 ": %s",
-              declared_length, static_cast<int64_t>(current_offset), strerror(errno));
+              declared_length, current_offset, strerror(errno));
         return {};
       }
     }
@@ -1290,10 +1291,15 @@ class FileWriter final : public zip_archive::Writer {
 
     // Block device doesn't support ftruncate(2).
     if (!S_ISBLK(sb.st_mode)) {
-      long result = TEMP_FAILURE_RETRY(ftruncate(fd, declared_length + current_offset));
+      uint64_t truncate_length;
+      if (__builtin_add_overflow(declared_length, current_offset, &truncate_length)) {
+        ALOGE("Zip: overflow truncating file (length %" PRId64 ", offset %" PRId64 ")",
+              declared_length, current_offset);
+        return {};
+      }
+      long result = TEMP_FAILURE_RETRY(ftruncate(fd, truncate_length));
       if (result == -1) {
-        ALOGE("Zip: unable to truncate file to %" PRId64 ": %s",
-              static_cast<int64_t>(declared_length + current_offset), strerror(errno));
+        ALOGE("Zip: unable to truncate file to %" PRId64 ": %s", truncate_length, strerror(errno));
         return {};
       }
     }
@@ -1303,8 +1309,8 @@ class FileWriter final : public zip_archive::Writer {
 
   virtual bool Append(uint8_t* buf, size_t buf_size) override {
     if (declared_length_ < buf_size || total_bytes_written_ > declared_length_ - buf_size) {
-      ALOGE("Zip: Unexpected size %zu  (declared) vs %zu (actual)", declared_length_,
-            total_bytes_written_ + buf_size);
+      ALOGE("Zip: Unexpected size %" PRIu64 "  (declared) vs %" PRIu64 " (actual)",
+            declared_length_, total_bytes_written_ + buf_size);
       return false;
     }
 
@@ -1319,17 +1325,12 @@ class FileWriter final : public zip_archive::Writer {
   }
 
   explicit FileWriter(const int fd = -1, const uint64_t declared_length = 0)
-      : Writer(),
-        fd_(fd),
-        declared_length_(static_cast<size_t>(declared_length)),
-        total_bytes_written_(0) {
-    CHECK_LE(declared_length, SIZE_MAX);
-  }
+      : Writer(), fd_(fd), declared_length_(declared_length), total_bytes_written_(0) {}
 
  private:
   int fd_;
-  const size_t declared_length_;
-  size_t total_bytes_written_;
+  const uint64_t declared_length_;
+  uint64_t total_bytes_written_;
 };
 
 class EntryReader final : public zip_archive::Reader {
diff --git a/zip_archive_test.cc b/zip_archive_test.cc
index 1c4861b..1e4f69a 100644
--- a/zip_archive_test.cc
+++ b/zip_archive_test.cc
@@ -1429,3 +1429,15 @@ TEST(ziparchive, Bug174945959) {
   }
   EndIteration(cookie);
 }
+
+TEST(ziparchive, ExtractHugeFileOn32Bit) {
+  ZipArchiveHandle handle;
+  ASSERT_EQ(0, OpenArchiveWrapper("hugefile.zip", &handle));
+
+  ZipEntry64 entry;
+  ASSERT_EQ(0, FindEntry(handle, "hugefile", &entry));
+
+  TemporaryFile tmp;
+  ASSERT_NE(-1, tmp.fd);
+  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, tmp.fd));
+}
```

