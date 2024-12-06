```diff
diff --git a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
index d681ea1..45943b7 100644
--- a/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
+++ b/plugins/src/main/java/org/robolectric/android/plugins/AndroidNativeRuntimeLoader.java
@@ -45,9 +45,11 @@ import org.robolectric.versioning.AndroidVersions;
 import org.robolectric.versioning.AndroidVersions.U;
 import org.robolectric.versioning.AndroidVersions.V;
 
+import java.io.File;
 import java.io.IOException;
 import java.net.URL;
 import java.nio.file.Path;
+import java.nio.file.Paths;
 import java.util.Locale;
 import java.util.Objects;
 
@@ -175,18 +177,54 @@ public class AndroidNativeRuntimeLoader extends DefaultNativeRuntimeLoader {
                   System.setProperty(
                       "graphics_native_classes", String.join(",", GRAPHICS_CLASS_NATIVES));
                   System.setProperty("method_binding_format", METHOD_BINDING_FORMAT);
-                }
-                loadLibrary(extractDirectory);
-                if (isAndroidVOrAbove()) {
+                  if (Boolean.parseBoolean(System.getProperty(
+                          "android.robolectric.loadLibraryFromPath", "false"))) {
+                    loadLibraryFromPath();
+                  } else {
+                    loadLibrary(extractDirectory);
+                  }
                   invokeDeferredStaticInitializers();
                   Typeface.loadPreinstalledSystemFontMap();
+                } else {
+                  loadLibrary(extractDirectory);
                 }
+
               });
     } catch (IOException e) {
       throw new AssertionError("Unable to load Robolectric native runtime library", e);
     }
   }
 
+  private void loadLibraryFromPath() {
+    // find the libandroid_runtime.so file in java.library.path, and create a copy of it so
+    // it can be loaded across different sandboxes
+    var path = System.getProperty("java.library.path");
+    var filename = "libandroid_runtime.so";
+
+
+    try {
+      if (path == null) {
+          throw new UnsatisfiedLinkError("Cannot load library " + filename + "."
+                + " Property java.library.path not set!");
+      }
+      for (var dir : path.split(":")) {
+          var libraryPath = Paths.get(dir, filename);
+          if (java.nio.file.Files.exists(libraryPath)) {
+              // create a copy of the file
+              File tmpLibraryFile = java.nio.file.Files.createTempFile("", "android_runtime").toFile();
+              tmpLibraryFile.deleteOnExit();
+              Files.copy(libraryPath.toFile().getAbsoluteFile(), tmpLibraryFile);
+              System.load(tmpLibraryFile.getAbsolutePath());
+              return;
+         }
+      }
+      throw new UnsatisfiedLinkError("Library " + filename + " not found in "
+              + "java.library.path: " + path);
+    } catch (IOException e) {
+      throw new AssertionError("Failed to copy " + filename, e);
+    }
+  }
+
   /** Attempts to load the ICU dat file. This is only relevant for native graphics. */
   private void maybeCopyIcuData(TempDirectory tempDirectory) throws IOException {
     String icuDatFile = isAndroidVOrAbove() ? "icudt.dat" : "icudt68l.dat";
diff --git a/scripts/run-android-test.sh b/scripts/run-android-test.sh
new file mode 100755
index 0000000..d8f8180
--- /dev/null
+++ b/scripts/run-android-test.sh
@@ -0,0 +1,68 @@
+#!/bin/bash
+
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+# Experimental, simple script to run a robolectric test in AOSP development environment.
+# Intended for faster iteration and more specific options than atest.
+#
+# In particular this script will:
+#  - only run tests on current SDK (35)
+#  - use sqlite native mode
+#  - load native libandroid_runtime built from HEAD
+#  - output stdout and stderr directly to terminal
+#
+# Usage:
+# [m -j <test_module_name> libandroid_runtime]
+# run-android-test.sh <test_module_name> <test_class_name>
+
+set -e
+
+if [[ ${ANDROID_HOST_OUT_TESTCASES:-"unset"} == "unset" ]]; then
+    echo "ERROR: android build environment not initialized. Run build/envsetup.sh and lunch."
+    exit -1
+fi
+
+if [ $# -lt 2 -o $# -gt 2 ]; then
+  echo "ERROR: invalid number of arguments. Usage: run-android-test.sh <test_module_name> <test_class_name>."
+  exit -1
+fi
+
+MODULE_NAME=$1
+CLASS_NAME=$2
+
+# uncomment this to wait for debugger to attach
+#DEBUGGER=' -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=8000 '
+DEBUGGER=' '
+
+# android build system integration assumes working directory = test case directory. See https://robolectric.org/build-system-integration/
+cd $ANDROID_HOST_OUT_TESTCASES/$MODULE_NAME
+
+java -cp $ANDROID_HOST_OUT_TESTCASES/$MODULE_NAME/$MODULE_NAME.jar:$ANDROID_HOST_OUT_TESTCASES/android-all/android-all-current-robolectric-r0.jar \
+    -Drobolectric.dependency.dir=$ANDROID_HOST_OUT_TESTCASES/android-all \
+    -Drobolectric.logging=stdout \
+    -Drobolectric.logging.enabled=true \
+    -Drobolectric.offline=true \
+    -Drobolectric.resourcesMode=BINARY \
+    -Drobolectric.usePreinstrumentedJars=false \
+    -Drobolectric.enabledSdks=35 \
+    -Drobolectric.alwaysIncludeVariantMarkersInTestName=true \
+    -Dandroid.robolectric.loadLibraryFromPath=true \
+    -Djava.library.path=$ANDROID_HOST_OUT/lib64:/usr/java/packages/lib:/usr/lib64:/lib64:/lib:/usr/lib \
+    -Drobolectric.sqliteMode=NATIVE \
+    $DEBUGGER \
+    org.junit.runner.JUnitCore \
+    $CLASS_NAME
\ No newline at end of file
```

