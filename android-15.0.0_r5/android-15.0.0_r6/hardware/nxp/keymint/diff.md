```diff
diff --git a/KM200/JavacardSharedSecret.cpp b/KM200/JavacardSharedSecret.cpp
index b32a92b..1992734 100644
--- a/KM200/JavacardSharedSecret.cpp
+++ b/KM200/JavacardSharedSecret.cpp
@@ -26,7 +26,8 @@
 /* 1 sec delay till OMAPI service initialized (~ 30 to 40 secs)
  * 20 retry as per transport layer retry logic.
  * Each retry logic takes 11~12 secs*/
-#define MAX_SHARED_SECRET_RETRY_COUNT 60
+/* OMAPI may take longer to load after a factory reset. */
+#define MAX_SHARED_SECRET_RETRY_COUNT 120
 
 namespace aidl::android::hardware::security::sharedsecret {
 using namespace ::keymint::javacard;
```

