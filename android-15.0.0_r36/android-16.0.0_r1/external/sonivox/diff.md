```diff
diff --git a/test/AndroidTest.xml b/test/AndroidTest.xml
index 57fde9e..8658a08 100644
--- a/test/AndroidTest.xml
+++ b/test/AndroidTest.xml
@@ -26,12 +26,12 @@
     </target_preparer>
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.MediaPreparer">
         <option name="push-all" value="true" />
-        <option name="media-folder-name" value="SonivoxTestRes-1.0"/>
+        <option name="media-folder-name" value="/data/local/tmp/SonivoxTestRes-1.0"/>
         <option name="dynamic-config-module" value="SonivoxTest" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="SonivoxTest" />
-        <option name="native-test-flag" value="-P /sdcard/test/SonivoxTestRes-1.0/" />
+        <option name="native-test-flag" value="-P /data/local/tmp/SonivoxTestRes-1.0/" />
     </test>
 </configuration>
diff --git a/test/README.md b/test/README.md
index 9232b24..09f2c9e 100644
--- a/test/README.md
+++ b/test/README.md
@@ -25,12 +25,12 @@ adb push ${OUT}/data/nativetest/SonivoxTest/SonivoxTest /data/local/tmp/
 The resource file for the tests is taken from [here](https://dl.google.com/android-unittest/media/external/sonivox/test/SonivoxTestRes-1.0.zip). Download, unzip and push these files into device for testing.
 
 ```
-adb push SonivoxTestRes-1.0 /sdcard/test/
+adb push SonivoxTestRes-1.0 /data/local/tmp/
 ```
 
 usage: SonivoxTest -P \<path_to_res_folder\> -C <remove_output_file>
 ```
-adb shell /data/local/tmp/SonivoxTest -P /sdcard/test/SonivoxTestRes-1.0/ -C true
+adb shell /data/local/tmp/SonivoxTest -P /data/local/tmp/SonivoxTestRes-1.0/ -C true
 ```
 Alternatively, the test can also be run using atest command.
 
diff --git a/test/SonivoxTest.cpp b/test/SonivoxTest.cpp
index 5894b50..3ec1cc3 100644
--- a/test/SonivoxTest.cpp
+++ b/test/SonivoxTest.cpp
@@ -72,6 +72,18 @@ class SonivoxTest : public ::testing::TestWithParam<tuple</*fileName*/ string,
         mTotalAudioChannels = get<2>(params);
         mAudioSampleRate = get<3>(params);
 
+        // b/384791354: we're having presubmit failures that appear to be
+        // flaky non-population of the data to the device.
+        // To help diagnose, let's see what's in that directory. to see if it is
+        // non-population, incorrect permissions, or something novel+interesting.
+        {
+            string cmd;
+            // this will also show the directory itself....
+            cmd = "ls -la " + gEnv->getRes() + "/";
+            printf("Output from running %s\n", cmd.c_str());
+            system(cmd.c_str());
+        }
+
         mFd = open(mInputMediaFile.c_str(), O_RDONLY | O_LARGEFILE);
         ASSERT_GE(mFd, 0) << "Failed to get the file descriptor for file: " << mInputMediaFile;
 
```

