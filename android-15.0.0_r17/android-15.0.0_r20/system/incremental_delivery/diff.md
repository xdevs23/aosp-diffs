```diff
diff --git a/incfs/incfsdump/dump.cpp b/incfs/incfsdump/dump.cpp
index 523992f..3ce7ab0 100644
--- a/incfs/incfsdump/dump.cpp
+++ b/incfs/incfsdump/dump.cpp
@@ -235,7 +235,10 @@ typedef union {
 class Dump {
 public:
     Dump(std::string_view backingFile)
-          : mBackingFile(android::base::Basename(std::string(backingFile))), mIn(backingFile) {}
+          : mBackingFile(android::base::Basename(backingFile)) {
+            std::string backingFileStr(backingFile);
+              mIn.open(backingFileStr);
+    }
 
     void run() {
         if (!mIn) {
```

