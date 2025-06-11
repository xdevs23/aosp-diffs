```diff
diff --git a/header_only_include/nativehelper/scoped_utf_chars.h b/header_only_include/nativehelper/scoped_utf_chars.h
index 25de0fc..7db3a28 100644
--- a/header_only_include/nativehelper/scoped_utf_chars.h
+++ b/header_only_include/nativehelper/scoped_utf_chars.h
@@ -41,7 +41,7 @@
 // Also consider using `GET_UTF_OR_RETURN`, a shorthand for the 4 lines above.
 class ScopedUtfChars {
  public:
-  ScopedUtfChars(JNIEnv* env, jstring s) : env_(env), string_(s) {
+  ScopedUtfChars(JNIEnv* env, jstring s) noexcept : env_(env), string_(s) {
     if (s == nullptr) {
       utf_chars_ = nullptr;
       jniThrowNullPointerException(env);
@@ -57,16 +57,14 @@ class ScopedUtfChars {
     rhs.utf_chars_ = nullptr;
   }
 
-  ~ScopedUtfChars() {
-    if (utf_chars_) {
-      env_->ReleaseStringUTFChars(string_, utf_chars_);
-    }
+  ~ScopedUtfChars() noexcept {
+    release_string();
   }
 
   ScopedUtfChars& operator=(ScopedUtfChars&& rhs) noexcept {
     if (this != &rhs) {
       // Delete the currently owned UTF chars.
-      this->~ScopedUtfChars();
+      release_string();
 
       // Move the rhs ScopedUtfChars and zero it out.
       env_ = rhs.env_;
@@ -79,23 +77,29 @@ class ScopedUtfChars {
     return *this;
   }
 
-  const char* c_str() const {
+  const char* c_str() const noexcept {
     return utf_chars_;
   }
 
-  size_t size() const {
+  size_t size() const noexcept {
     return strlen(utf_chars_);
   }
 
-  const char& operator[](size_t n) const {
+  const char& operator[](size_t n) const noexcept {
     return utf_chars_[n];
   }
 
 #if __has_include(<string_view>)
-  operator std::string_view() const { return utf_chars_; }
+  operator std::string_view() const noexcept { return utf_chars_; }
 #endif
 
  private:
+  void release_string() noexcept {
+    if (utf_chars_) {
+      env_->ReleaseStringUTFChars(string_, utf_chars_);
+    }
+  }
+
   JNIEnv* env_;
   jstring string_;
   const char* utf_chars_;
```

