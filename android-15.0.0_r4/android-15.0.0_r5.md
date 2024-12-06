**build/make**
```
a4bbca172b: Version bump to AP3A.241105.008 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
```

**manifest**
```
66da5f6db: Manifest for Android 15.0.0 Release 5 (The Android Open Source Project <initial-contrib...)
```

**build/make**
```diff
diff --git a/core/build_id.mk b/core/build_id.mk
index 015f677cd5..841db4457b 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=AP3A.241105.007
+BUILD_ID=AP3A.241105.008
```

**manifest**
```diff
diff --git a/default.xml b/default.xml
index e5678717e..02b220a40 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r4"
+  <default revision="refs/tags/android-15.0.0_r5"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r4"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r5"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

