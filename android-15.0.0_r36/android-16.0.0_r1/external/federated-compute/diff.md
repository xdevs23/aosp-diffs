```diff
diff --git a/Android.bp b/Android.bp
index 2afe5a6..667d9c1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -188,7 +188,6 @@ cc_test {
         "federated-compute-cc-proto-lite",
         "libabsl",
         "libbase_ndk",
-        "libc++fs", // used by filesystem
         "libgmock",
         "liblog",
         "libprotobuf-cpp-lite-ndk",
diff --git a/OWNERS b/OWNERS
index f73eb47..200b5ca 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 qiaoli@google.com
 tarading@google.com
 ymu@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/fcp/protos/federatedcompute/common.proto b/fcp/protos/federatedcompute/common.proto
index 9862d53..c60589c 100644
--- a/fcp/protos/federatedcompute/common.proto
+++ b/fcp/protos/federatedcompute/common.proto
@@ -159,6 +159,12 @@ message RejectionReason {
 
     // The device is not authenticated to the server.
     UNAUTHENTICATED = 3;
+
+    // The device version does not match the required versions specified by the server.
+    CLIENT_VERSION_MISMATCH = 4;
+
+    // No active task exists for the given population name.
+    NO_ACTIVE_TASK_EXISTS = 5;
   }
 }
 
```

