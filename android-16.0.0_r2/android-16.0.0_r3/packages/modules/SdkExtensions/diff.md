```diff
diff --git a/Android.bp b/Android.bp
index ab8a357..fa7333a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,6 +32,10 @@ apex {
     ],
     manifest: "manifest.json",
     visibility: ["//packages/modules/common/build"],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 apex_defaults {
diff --git a/derive_sdk/derive_sdk.cpp b/derive_sdk/derive_sdk.cpp
index 94964a1..65b061f 100644
--- a/derive_sdk/derive_sdk.cpp
+++ b/derive_sdk/derive_sdk.cpp
@@ -85,6 +85,8 @@ void ReadSystemProperties(std::map<std::string, std::string>& properties) {
         android::base::GetProperty(kSystemPropertiesPrefix + dessert, default_);
   }
   properties["ro.build.version.sdk"] = android::base::GetProperty("ro.build.version.sdk", default_);
+  properties["ro.build.version.sdk_full"] =
+      android::base::GetProperty("ro.build.version.sdk_full", default_);
 }
 
 bool ReadDatabase(const std::string& db_path, ExtensionDatabase& db) {
diff --git a/gen_sdk/extensions_db.textpb b/gen_sdk/extensions_db.textpb
index 390c367..c2aeb4c 100644
--- a/gen_sdk/extensions_db.textpb
+++ b/gen_sdk/extensions_db.textpb
@@ -1531,3 +1531,108 @@ versions {
     }
   }
 }
+versions {
+  version: 18
+  requirements {
+    module: ART
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: CONSCRYPT
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: IPSEC
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: MEDIA
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: MEDIA_PROVIDER
+    version {
+      version: 18
+    }
+  }
+  requirements {
+    module: PERMISSIONS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: SCHEDULING
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: SDK_EXTENSIONS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: STATSD
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: TETHERING
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: AD_SERVICES
+    version {
+      version: 18
+    }
+  }
+  requirements {
+    module: APPSEARCH
+    version {
+      version: 18
+    }
+  }
+  requirements {
+    module: ON_DEVICE_PERSONALIZATION
+    version {
+      version: 18
+    }
+  }
+  requirements {
+    module: CONFIG_INFRASTRUCTURE
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: HEALTH_FITNESS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: EXT_SERVICES
+    version {
+      version: 18
+    }
+  }
+  requirements {
+    module: NEURAL_NETWORKS
+    version {
+      version: 17
+    }
+  }
+}
diff --git a/java/com/android/os/ext/testing/DeriveSdk.java b/java/com/android/os/ext/testing/DeriveSdk.java
index a87a171..1e073fd 100644
--- a/java/com/android/os/ext/testing/DeriveSdk.java
+++ b/java/com/android/os/ext/testing/DeriveSdk.java
@@ -23,8 +23,8 @@ public class DeriveSdk {
 
     private DeriveSdk() {}
 
-    public static String[] dump() {
-        return native_dump().split("\n");
+    public static String dump() {
+        return native_dump();
     }
 
     private static native String native_dump();
diff --git a/javatests/com/android/os/ext/SdkExtensionsTest.java b/javatests/com/android/os/ext/SdkExtensionsTest.java
index b6d3a7b..eb8c2d7 100644
--- a/javatests/com/android/os/ext/SdkExtensionsTest.java
+++ b/javatests/com/android/os/ext/SdkExtensionsTest.java
@@ -30,9 +30,8 @@ import static com.android.os.ext.testing.CurrentVersion.R_BASE_VERSION;
 import static com.android.os.ext.testing.CurrentVersion.S_BASE_VERSION;
 import static com.android.os.ext.testing.CurrentVersion.T_BASE_VERSION;
 
-import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.Truth.assertWithMessage;
 
-import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertThrows;
 
 import android.app.ActivityManager;
@@ -42,7 +41,6 @@ import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.os.SystemProperties;
 import android.os.ext.SdkExtensions;
-import android.util.Log;
 
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.runner.AndroidJUnit4;
@@ -50,18 +48,25 @@ import androidx.test.runner.AndroidJUnit4;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.os.ext.testing.DeriveSdk;
 
+import com.google.common.truth.StandardSubjectBuilder;
+
 import org.junit.BeforeClass;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.util.HashSet;
 import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 @RunWith(AndroidJUnit4.class)
 public class SdkExtensionsTest {
 
     private static final String TAG = "SdkExtensionsTest";
 
+    // This runs the copy of the dump code that is bundled inside the test APK.
+    private static final String DERIVE_SDK_DUMP = DeriveSdk.dump();
+
     private enum Expectation {
         /**
          * Expect an extension to be the current / latest defined version, or later (which may be
@@ -79,6 +84,15 @@ public class SdkExtensionsTest {
     private static final Expectation MISSING = Expectation.MISSING;
     private static final Expectation AT_LEAST_BASE = Expectation.AT_LEAST_BASE;
 
+    private static StandardSubjectBuilder assertWithHeader() {
+        // This runs the copy of the dump code that is bundled inside the test APK.
+        return assertWithMessage(DERIVE_SDK_DUMP);
+    }
+
+    private static StandardSubjectBuilder assertWithHeader(String message) {
+        return assertWithMessage(DERIVE_SDK_DUMP + "\n" + message);
+    }
+
     private static void assertAtLeastBaseVersion(int version) {
         int minVersion = R_BASE_VERSION;
         if (SdkLevel.isAtLeastU()) {
@@ -88,27 +102,27 @@ public class SdkExtensionsTest {
         } else if (SdkLevel.isAtLeastS()) {
             minVersion = S_BASE_VERSION;
         }
-        assertThat(version).isAtLeast(minVersion);
-        assertThat(version).isAtMost(CURRENT_TRAIN_VERSION);
+        assertWithHeader().that(version).isAtLeast(minVersion);
+        assertWithHeader().that(version).isAtMost(CURRENT_TRAIN_VERSION);
     }
 
     private static void assertVersion(Expectation expectation, int version) {
         switch (expectation) {
             case AT_LEAST_CURRENT:
-                assertThat(version).isAtLeast(CURRENT_TRAIN_VERSION);
+                assertWithHeader().that(version).isAtLeast(CURRENT_TRAIN_VERSION);
                 break;
             case AT_LEAST_BASE:
                 assertAtLeastBaseVersion(version);
                 break;
             case MISSING:
-                assertEquals(0, version);
+                assertWithHeader().that(version).isEqualTo(0);
                 break;
         }
     }
 
     private static void assertVersion(Expectation expectation, String propValue) {
         if (expectation == Expectation.MISSING) {
-            assertEquals("", propValue);
+            assertWithHeader().that(propValue).isEqualTo("");
         } else {
             int version = Integer.parseInt(propValue);
             assertVersion(expectation, version);
@@ -125,14 +139,38 @@ public class SdkExtensionsTest {
         }
     }
 
-    /* This method runs the copy of the dump code that is bundled inside the test APK. */
-    @BeforeClass
-    public static void runTestDeriveSdkDump() {
-        Log.i(TAG, "derive_sdk dump (bundled with test):");
-
-        for (String line : DeriveSdk.dump()) {
-            Log.i(TAG, "  " + line);
+    private static int readSdkExtensionsVersion() throws Exception {
+        Pattern regex = Pattern.compile("SDK_EXTENSIONS:(\\d+)");
+        Matcher matcher = regex.matcher(DERIVE_SDK_DUMP);
+        if (!matcher.find()) {
+            throw new IllegalStateException("failed to read SdkExtensions version");
         }
+        return Integer.parseInt(matcher.group(1));
+    }
+
+    @BeforeClass
+    public static void setupBeforeTest() throws Exception {
+        int sdkExtensionsVersion = readSdkExtensionsVersion();
+        assertWithMessage(
+                        "\n"
+                                + "\n"
+                                + "* * * * * * * * * * * * * * * * * * * * * * * * * *\n"
+                                + "\n"
+                                + "INVALID TEST CONFIGURATION, THE TESTS WILL NOT RUN\n"
+                                + "\n"
+                                + "The version of the SdkExtensions module installed on\n"
+                                + "device is older than the SdkExtensionsTest. This is\n"
+                                + "not a supported configuration, and the tests will not\n"
+                                + "run.\n"
+                                + "\n"
+                                + "Verify that the tests do not come from a more recent\n"
+                                + "train than what is installed on the device. If you are\n"
+                                + "manually installing a new train on the device, remember\n"
+                                + "to reboot your device as part of the installation.\n"
+                                + "\n"
+                                + "* * * * * * * * * * * * * * * * * * * * * * * * * *\n")
+                .that(/* version of the SdkExtensions module on device */ sdkExtensionsVersion)
+                .isAtLeast(/* version of the test */ CURRENT_TRAIN_VERSION);
     }
 
     /** Verify that getExtensionVersion only accepts valid extension SDKs */
@@ -160,7 +198,9 @@ public class SdkExtensionsTest {
             }
             // No extension SDKs yet.
             int version = SdkExtensions.getExtensionVersion(sdk);
-            assertEquals("Extension ID " + sdk + " has non-zero version", 0, version);
+            assertWithHeader("Extension ID " + sdk + " has non-zero version")
+                    .that(version)
+                    .isEqualTo(0);
         }
     }
 
@@ -185,7 +225,7 @@ public class SdkExtensionsTest {
             expectedKeys.add(BAKLAVA);
         }
         Set<Integer> actualKeys = SdkExtensions.getAllExtensionVersions().keySet();
-        assertThat(actualKeys).containsExactlyElementsIn(expectedKeys);
+        assertWithHeader().that(actualKeys).containsExactlyElementsIn(expectedKeys);
     }
 
     @Test
diff --git a/sdk-extensions-info.xml b/sdk-extensions-info.xml
index eefefa9..9ddeb62 100644
--- a/sdk-extensions-info.xml
+++ b/sdk-extensions-info.xml
@@ -106,6 +106,46 @@
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.QUERY_ARG_LATEST_SELECTION_ONLY"
       sdks="U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.EXTRA_PICK_IMAGES_HIGHLIGHT_MEDIA"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.KEY_PICK_IMAGES_HIGHLIGHT_MEDIA_TEXT_QUERY"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.KEY_PICK_IMAGES_HIGHLIGHT_TYPE"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_TYPE_COLLAPSED"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_TYPE_EXPANDED"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_ALBUM_FAVORITES"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_ALBUM_CAMERA"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_ALBUM_SCREENSHOTS"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_ALBUM_VIDEOS"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+      jar="framework-mediaprovider"
+      pattern="android.provider.MediaStore.PICK_IMAGES_HIGHLIGHT_ALBUM_DOWNLOADS"
+      sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.getPickImagesMaxLimit"
@@ -134,6 +174,10 @@
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.ACCESS_OEM_METADATA_PERMISSION"
     sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.UPDATE_OEM_METADATA_PERMISSION"
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.QUERY_ARG_MEDIA_STANDARD_SORT_ORDER"
@@ -166,6 +210,10 @@
     jar="framework-mediaprovider"
     pattern="android.provider.OemMetadataService"
     sdks="T-ext,U-ext,V-ext,B-ext" />
+  <symbol
+    jar="framework-mediaprovider"
+    pattern="android.provider.MediaStore.bulkUpdateOemMetadataInNextScan"
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.CloudMediaProvider"
@@ -765,4 +813,44 @@
     pattern="android.health.connect.datatypes.ActivityIntensityRecord.Builder"
     sdks="U-ext,V-ext,B-ext" />
 
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.changelog.ChangeLogsResponse.DeletedMedicalResource"
+    sdks="U-ext,V-ext,B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.backuprestore.GetLatestMetadataForBackupResponse"
+    sdks="B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.backuprestore.BackupMetadata"
+    sdks="B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.backuprestore.GetChangesForBackupResponse"
+    sdks="B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.backuprestore.BackupChange"
+    sdks="B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.backuprestore.RestoreChange"
+    sdks="B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.permission.health.START_ONBOARDING"
+    sdks="U-ext,V-ext,B-ext" />
+
+  <symbol
+    jar="framework-healthfitness"
+    pattern="android.health.connect.action.SHOW_ONBOARDING"
+    sdks="U-ext,V-ext,B-ext" />
+
 </sdk-extensions-info>
```

