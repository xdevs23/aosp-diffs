```diff
diff --git a/tests/robotests/src/com/android/tv/testing/TvRobolectricTestRunner.java b/tests/robotests/src/com/android/tv/testing/TvRobolectricTestRunner.java
index d1c16a8d..6ac721cd 100644
--- a/tests/robotests/src/com/android/tv/testing/TvRobolectricTestRunner.java
+++ b/tests/robotests/src/com/android/tv/testing/TvRobolectricTestRunner.java
@@ -50,9 +50,9 @@ public class TvRobolectricTestRunner extends RobolectricTestRunner {
         // By adding any resources from libraries we need the AndroidManifest, we can access
         // them from within the parallel universe's resource loader.
         return new AndroidManifest(
-                Fs.fileFromPath(config.manifest()),
-                Fs.fileFromPath(config.resourceDir()),
-                Fs.fileFromPath(config.assetDir()),
+                Fs.fromUrl(config.manifest()),
+                Fs.fromUrl(config.resourceDir()),
+                Fs.fromUrl(config.assetDir()),
                 packageName) {
             @Override
             public List<ResourcePath> getIncludedResourcePaths() {
@@ -67,22 +67,22 @@ public class TvRobolectricTestRunner extends RobolectricTestRunner {
         paths.add(
                 new ResourcePath(
                         null,
-                        Fs.fileFromPath("./packages/apps/TV/res"),
+                        Fs.fromUrl("./packages/apps/TV/res"),
                         null));
         paths.add(
                 new ResourcePath(
                         null,
-                        Fs.fileFromPath("./packages/apps/TV/common/res"),
+                        Fs.fromUrl("./packages/apps/TV/common/res"),
                         null));
         paths.add(
                 new ResourcePath(
                         null,
-                        Fs.fileFromPath("./packages/apps/TV/material_res"),
+                        Fs.fromUrl("./packages/apps/TV/material_res"),
                         null));
 	paths.add(
                 new ResourcePath(
                         null,
-                        Fs.fileFromPath("./prebuilts/sdk/current/support/v17/leanback/res"),
+                        Fs.fromUrl("./prebuilts/sdk/current/support/v17/leanback/res"),
                         null));
     }
 }
diff --git a/tuner/tests/robotests/javatests/com/android/tv/tuner/testing/TvTunerRobolectricTestRunner.java b/tuner/tests/robotests/javatests/com/android/tv/tuner/testing/TvTunerRobolectricTestRunner.java
index ab0955e5..ee8b0e56 100644
--- a/tuner/tests/robotests/javatests/com/android/tv/tuner/testing/TvTunerRobolectricTestRunner.java
+++ b/tuner/tests/robotests/javatests/com/android/tv/tuner/testing/TvTunerRobolectricTestRunner.java
@@ -50,9 +50,9 @@ public class TvTunerRobolectricTestRunner extends RobolectricTestRunner {
         // By adding any resources from libraries we need the AndroidManifest, we can access
         // them from within the parallel universe's resource loader.
         return new AndroidManifest(
-                Fs.fileFromPath(config.manifest()),
-                Fs.fileFromPath(config.resourceDir()),
-                Fs.fileFromPath(config.assetDir()),
+                Fs.fromUrl(config.manifest()),
+                Fs.fromUrl(config.resourceDir()),
+                Fs.fromUrl(config.assetDir()),
                 packageName) {
             @Override
             public List<ResourcePath> getIncludedResourcePaths() {
@@ -64,6 +64,6 @@ public class TvTunerRobolectricTestRunner extends RobolectricTestRunner {
     }
 
     public static void getIncludedResourcePaths(List<ResourcePath> paths) {
-        paths.add(new ResourcePath(null, Fs.fileFromPath("./packages/apps/TV/tuner/res"), null));
+        paths.add(new ResourcePath(null, Fs.fromUrl("./packages/apps/TV/tuner/res"), null));
     }
 }
```

