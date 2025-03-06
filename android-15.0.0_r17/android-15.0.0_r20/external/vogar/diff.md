```diff
diff --git a/src/vogar/android/AndroidSdk.java b/src/vogar/android/AndroidSdk.java
index 220e6a6..3834b1b 100644
--- a/src/vogar/android/AndroidSdk.java
+++ b/src/vogar/android/AndroidSdk.java
@@ -54,7 +54,6 @@ public class AndroidSdk {
     private final Mkdir mkdir;
     private final File[] compilationClasspath;
     private final String androidJarPath;
-    private final String desugarJarPath;
     private final Md5Cache dexCache;
     private final Language language;
     private final boolean serialDexing;
@@ -101,14 +100,12 @@ public class AndroidSdk {
          *  ${ANDROID_BUILD_TOP}/out/host/linux-x86/bin/aapt
          *  ${ANDROID_BUILD_TOP}/out/host/linux-x86/bin/adb
          *  ${ANDROID_BUILD_TOP}/out/host/linux-x86/bin/d8
-         *  ${ANDROID_BUILD_TOP}/out/host/linux-x86/bin/desugar.jar
          *  ${ANDROID_BUILD_TOP}/out/target/common/obj/JAVA_LIBRARIES/core-libart_intermediates
          *      /classes.jar
          */
 
         File[] compilationClasspath;
         String androidJarPath;
-        String desugarJarPath = null;
 
         // Accept that we are running in an SDK if the user has added the build-tools or
         // platform-tools to their path.
@@ -126,13 +123,6 @@ public class AndroidSdk {
             androidJarPath = new File(newestPlatform.getAbsolutePath(), "android.jar")
                     .getAbsolutePath();
             log.verbose("using android sdk: " + sdkRoot);
-
-            // There must be a desugar.jar in the build tool directory.
-            desugarJarPath = buildToolDirString + "/desugar.jar";
-            File desugarJarFile = new File(desugarJarPath);
-            if (!desugarJarFile.exists()) {
-                throw new RuntimeException("Could not find " + desugarJarPath);
-            }
         } else if ("bin".equals(buildToolDirString)) {
             log.verbose("Using android source build mode to find dependencies.");
             String tmpJarPath = "prebuilts/sdk/current/public/android.jar";
@@ -168,15 +158,6 @@ public class AndroidSdk {
                 hostOutDir = outDir + "/host/linux-x86";
             }
 
-            String desugarPattern = hostOutDir + "/framework/desugar.jar";
-            File desugarJar = new File(desugarPattern);
-
-            if (!desugarJar.exists()) {
-                throw new RuntimeException("Could not find " + desugarPattern);
-            }
-
-            desugarJarPath = desugarJar.getPath();
-
             if (!supportBuildFromSource) {
                 compilationClasspath = new File[]{};
             } else {
@@ -220,7 +201,7 @@ public class AndroidSdk {
                     + ARBITRARY_BUILD_TOOL_NAME);
         }
 
-        return new AndroidSdk(log, mkdir, compilationClasspath, androidJarPath, desugarJarPath,
+        return new AndroidSdk(log, mkdir, compilationClasspath, androidJarPath,
                 new HostFileCache(log, mkdir), language, serialDexing, verboseDexStats);
     }
 
@@ -262,13 +243,12 @@ public class AndroidSdk {
 
     @VisibleForTesting
     AndroidSdk(Log log, Mkdir mkdir, File[] compilationClasspath, String androidJarPath,
-               String desugarJarPath, HostFileCache hostFileCache, Language language,
+               HostFileCache hostFileCache, Language language,
                boolean serialDexing, boolean verboseDexStats) {
         this.log = log;
         this.mkdir = mkdir;
         this.compilationClasspath = compilationClasspath;
         this.androidJarPath = androidJarPath;
-        this.desugarJarPath = desugarJarPath;
         this.dexCache = new Md5Cache(log, "dex", hostFileCache);
         this.language = language;
         this.serialDexing = serialDexing;
diff --git a/test/vogar/android/AbstractModeTest.java b/test/vogar/android/AbstractModeTest.java
index f6f379a..1a34e7f 100644
--- a/test/vogar/android/AbstractModeTest.java
+++ b/test/vogar/android/AbstractModeTest.java
@@ -71,7 +71,7 @@ public abstract class AbstractModeTest {
         rm = new Rm(console);
 
         androidSdk = new AndroidSdk(console, mkdir,
-                new File[] {new File("classpath")}, "android.jar", "desugar.jar",
+                new File[] {new File("classpath")}, "android.jar",
                 new HostFileCache(console, mkdir),
                 Language.CUR, false, false);
         Target target = createTarget();
```

