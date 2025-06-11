```diff
diff --git a/OWNERS b/OWNERS
index 28cff0a..b2c8369 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,10 +1,5 @@
-amitmahajan@google.com
 jackyu@google.com
 rgreenwalt@google.com
 fionaxu@google.com
-jminjie@google.com
 mpq@google.com
-shuoq@google.com
-refuhoo@google.com
 sarahchin@google.com
-dbright@google.com
diff --git a/librilutils/Android.bp b/librilutils/Android.bp
index e7af5b5..eb4fea0 100644
--- a/librilutils/Android.bp
+++ b/librilutils/Android.bp
@@ -25,7 +25,7 @@ cc_library {
         "-Wall",
         "-Wextra",
         "-Werror",
-        "-DPB_FIELD_32BIT"
+        "-DPB_FIELD_32BIT",
     ],
 
     proto: {
@@ -47,6 +47,6 @@ java_library {
     sdk_version: "current",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
 }
diff --git a/reference-ril/OWNERS b/reference-ril/OWNERS
index 98dba3e..6d0c330 100644
--- a/reference-ril/OWNERS
+++ b/reference-ril/OWNERS
@@ -1,9 +1,5 @@
-amitmahajan@google.com
 jackyu@google.com
 rgreenwalt@google.com
 fionaxu@google.com
-jminjie@google.com
 mpq@google.com
-shuoq@google.com
-refuhoo@google.com
 bohu@google.com
```

