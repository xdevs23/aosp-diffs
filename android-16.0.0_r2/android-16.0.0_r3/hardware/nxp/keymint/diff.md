```diff
diff --git a/KM200/JavacardSharedSecret.cpp b/KM200/JavacardSharedSecret.cpp
index cc42e60..a0c809d 100644
--- a/KM200/JavacardSharedSecret.cpp
+++ b/KM200/JavacardSharedSecret.cpp
@@ -28,7 +28,7 @@
  * 20 retry as per transport layer retry logic.
  * Each retry logic takes 11~12 secs*/
 /* OMAPI may take longer to load after a factory reset. */
-#define MAX_SHARED_SECRET_RETRY_COUNT 120
+#define MAX_SHARED_SECRET_RETRY_COUNT 180
 
 namespace aidl::android::hardware::security::sharedsecret {
 using ::keymint::javacard::Instruction;
diff --git a/OWNERS b/OWNERS
index f5070eb..04af5ce 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
+necip@google.com
 tfred@google.com
```

