```diff
diff --git a/README.android b/README.android
index 79df842..423fda5 100644
--- a/README.android
+++ b/README.android
@@ -159,6 +159,7 @@ Versions mapping
 
 |Android release|Major version|
 |---------------|-------------|
+|Android B      | 9           |
 |Android V      | 8           |
 |Android U      | 7           |
 |Android T      | 6           |
@@ -178,6 +179,8 @@ Changing the Time Zone Data Set Version
       * CURRENT_FORMAT_MAJOR_VERSION and CURRENT_FORMAT_MINOR_VERSION fields.
     * external/icu/android_icu4j/src/main/java/android/icu/platform/AndroidDataFiles.java
       * CURRENT_MAJOR_VERSION field.
+    * external/icu/libandroidicuinit/IcuRegistration.cpp
+      * CURRENT_MAJOR_FORMAT_VERSION field.
     * Version mapping table above.
     * system/timezone/output_data/icu_overlay/Android.bp and system/timezone/output_data/android/Android.bp.
       * Update `relative_install_path` in `prebuilt_root_host` targets.
diff --git a/TEST_MAPPING b/TEST_MAPPING
index a2e98cc..57f9fae 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -3,5 +3,30 @@
     {
       "path": "system/apex/tests"
     }
+  ],
+  "presubmit": [
+    {
+      "name": "MtsTimeZoneDataTestCases"
+    }
+  ],
+  "postsubmit": [
+    {
+      "name": "CtsBionicTestCases"
+    },
+    {
+      "name": "CtsIcu4cTestCases"
+    },
+    {
+      "name": "CtsIcuTestCases"
+    },
+    {
+      "name": "CtsLibcoreOjTestCases"
+    },
+    {
+      "name": "CtsLibcoreTestCases"
+    },
+    {
+      "name": "CtsTextTestCases"
+    }
   ]
 }
diff --git a/apex/Android.bp b/apex/Android.bp
index 9bcd0a7..a782005 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -71,5 +71,10 @@ apex {
         "apex_telephonylookup.xml_ver8",
         "apex_tzdata_ver8",
         "apex_icu_res_files_ver8",
+        "apex_tz_version_ver9",
+        "apex_tzlookup.xml_ver9",
+        "apex_telephonylookup.xml_ver9",
+        "apex_tzdata_ver9",
+        "apex_icu_res_files_ver9",
     ],
 }
diff --git a/apex/tests/Android.bp b/apex/tests/Android.bp
index 454f696..52b3251 100644
--- a/apex/tests/Android.bp
+++ b/apex/tests/Android.bp
@@ -29,7 +29,10 @@ android_test {
     srcs: ["src/**/*.java"],
 
     sdk_version: "current",
-    libs: ["android.test.base.stubs"],
+    libs: [
+        "android.test.base.stubs",
+        "legacy.i18n.module.platform.api.stubs",
+    ],
 
     // Tag this module as an mts test artifact
     test_suites: [
diff --git a/apex/tests/AndroidTest.xml b/apex/tests/AndroidTest.xml
index 2e23740..8e09742 100644
--- a/apex/tests/AndroidTest.xml
+++ b/apex/tests/AndroidTest.xml
@@ -23,6 +23,8 @@
         <option name="test-file-name" value="MtsTimeZoneDataTestCases.apk" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <!-- To get current major version. -->
+        <option name="hidden-api-checks" value="false"/>
         <option name="package" value="android.tzdata.mts" />
         <option name="runtime-hint" value="1m" />
     </test>
diff --git a/apex/tests/src/java/android/tzdata/mts/TimeZoneRulesTest.java b/apex/tests/src/java/android/tzdata/mts/TimeZoneRulesTest.java
index c1050cc..501f710 100644
--- a/apex/tests/src/java/android/tzdata/mts/TimeZoneRulesTest.java
+++ b/apex/tests/src/java/android/tzdata/mts/TimeZoneRulesTest.java
@@ -44,11 +44,11 @@ public class TimeZoneRulesTest {
 
     @Test
     public void preHistoricInDaylightTime() {
-        // A zone that lacks an explicit transition at Integer.MIN_VALUE with zic 2019a and 2019a
+        // A zone that lacks an explicit transition at Integer.MIN_VALUE with zic 2023a and 2024b
         // data.
         TimeZone tz = TimeZone.getTimeZone("CET");
 
-        long firstTransitionTimeMillis = -1693706400000L; // Apr 30, 1916 22:00:00 GMT
+        long firstTransitionTimeMillis = -1693702800000L; // Apr 30, 1916 23:00:00 GMT
         assertEquals(7200000L, tz.getOffset(firstTransitionTimeMillis));
         assertTrue(tz.inDaylightTime(new Date(firstTransitionTimeMillis)));
 
diff --git a/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java b/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
index a03241f..baf7d0a 100644
--- a/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
+++ b/apex/tests/src/java/android/tzdata/mts/TimeZoneVersionTest.java
@@ -16,18 +16,29 @@
 package android.tzdata.mts;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeTrue;
+
+import static java.util.stream.Collectors.toMap;
 
 import android.icu.util.VersionInfo;
 import android.os.Build;
 import android.util.TimeUtils;
 
+import com.android.i18n.timezone.TzDataSetVersion;
+
 import org.junit.Test;
 
 import java.io.File;
 import java.io.FileInputStream;
 import java.io.IOException;
+import java.io.UncheckedIOException;
+import java.lang.reflect.Method;
 import java.nio.charset.StandardCharsets;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
 
 /**
  * Tests concerning version information associated with, or affected by, the time zone data module.
@@ -41,9 +52,19 @@ public class TimeZoneVersionTest {
     private static final File TIME_ZONE_MODULE_VERSION_FILE =
             new File("/apex/com.android.tzdata/etc/tz/tz_version");
 
+    private static final String VERSIONED_DATA_LOCATION =
+            "/apex/com.android.tzdata/etc/tz/versioned/";
+
+    // Android V.
+    private static final int MINIMAL_SUPPORTED_MAJOR_VERSION = 8;
+    // Android B.
+    // LINT.IfChange
+    private static final int THE_LATEST_MAJOR_VERSION = 9;
+    // LINT.ThenChange(/android_icu4j/libcore_bridge/src/java/com/android/i18n/timezone/TzDataSetVersion.java)
+
     @Test
-    public void timeZoneModuleIsCompatibleWithThisRelease() throws Exception {
-        String majorVersion = readMajorFormatVersionFromModuleVersionFile();
+    public void timeZoneModuleIsCompatibleWithThisRelease() {
+        String majorVersion = readMajorFormatVersionForVersion(getCurrentFormatMajorVersion());
 
         // Each time a release version of Android is declared, this list needs to be updated to
         // map the Android release to the time zone format version it uses.
@@ -61,20 +82,21 @@ public class TimeZoneVersionTest {
         } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
             assertEquals("007", majorVersion);
         } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            assertEquals("008", majorVersion);
+        } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.BAKLAVA) {
             // The "main" branch is also the staging area for the next Android release that won't
             // have an Android release constant yet. Instead, we have to infer what the expected tz
             // data set version should be when the SDK_INT identifies it as the latest Android release
             // in case it is actually the "main" branch. Below we assume that an increment to ICU is
             // involved with each release of Android and requires an tz data set version increment.
-            // TODO(b/319103072) A future tzdata module will be installed to a range of Android
-            // releases. This test might beed to be reworked because the ICU version may no longer
-            // imply the tz data set to expect.
-            if (VersionInfo.ICU_VERSION.getMajor() > 75) {
-                // ICU version in V is 75. When we update it in a next release major version
-                // should be updated too.
-                assertEquals("009", majorVersion);
+
+
+            // ICU version in B is 76. When we update it in a next release major version
+            // should be updated too.
+            if (VersionInfo.ICU_VERSION.getMajor() > 76) {
+                assertEquals("010", majorVersion);
             } else {
-                assertEquals("008", majorVersion);
+                assertEquals("009", majorVersion);
             }
         } else {
             // If this fails, a new API level has likely been finalized and can be made
@@ -89,7 +111,7 @@ public class TimeZoneVersionTest {
      * Confirms that tzdb version information available via published APIs is consistent.
      */
     @Test
-    public void tzdbVersionIsConsistentAcrossApis() throws Exception {
+    public void tzdbVersionIsConsistentAcrossApis() {
         String tzModuleTzdbVersion = readTzDbVersionFromModuleVersionFile();
 
         String icu4jTzVersion = android.icu.util.TimeZone.getTZDataVersion();
@@ -98,11 +120,70 @@ public class TimeZoneVersionTest {
         assertEquals(tzModuleTzdbVersion, TimeUtils.getTimeZoneDatabaseVersion());
     }
 
+    @Test
+    public void majorVersion_isValid() {
+        String msg = "THE_LATEST_MAJOR_VERSION is "
+                + THE_LATEST_MAJOR_VERSION
+                + " but getCurrentMajorFormatVersion() is greater: "
+                + getCurrentFormatMajorVersion();
+        assertTrue(msg, THE_LATEST_MAJOR_VERSION >= getCurrentFormatMajorVersion());
+    }
+
+    @Test
+    public void versionFiles_areConsistent() {
+        // Test validates data installed in /versioned/ directory. It was introduced in tzdata6,
+        // and it is targeted to Android V+ only.
+        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM);
+
+        // Version in tz_version under versioned/N should be N.
+        for (int version = MINIMAL_SUPPORTED_MAJOR_VERSION;
+             version <= THE_LATEST_MAJOR_VERSION;
+             ++version) {
+            // Version in tz_version is zero padded.
+            String expectedVersion = "%03d".formatted(version);
+            assertEquals(expectedVersion, readMajorFormatVersionForVersion(version));
+        }
+
+        // IANA version should be the same across tz_version files.
+        Set<File> versionFiles = new HashSet<>();
+        versionFiles.add(TIME_ZONE_MODULE_VERSION_FILE);
+
+        for (int version = MINIMAL_SUPPORTED_MAJOR_VERSION;
+             version <= THE_LATEST_MAJOR_VERSION;
+             ++version) {
+            versionFiles.add(
+                    new File("%s/%d/tz_version".formatted(VERSIONED_DATA_LOCATION, version)));
+        }
+
+        Map<String, String> ianaVersionInVersionFile = versionFiles.stream()
+                .collect(toMap(File::toString, TimeZoneVersionTest::readTzDbVersionFrom));
+
+        String msg = "Versions are not consistent: " + ianaVersionInVersionFile;
+        assertEquals(msg, 1, Set.of(ianaVersionInVersionFile.values()).size());
+    }
+
+    private static int getCurrentFormatMajorVersion() {
+        // TzDataSetVersion was moved from /libcore to /external/icu in S.
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
+            return TzDataSetVersion.currentFormatMajorVersion();
+        } else {
+            try {
+                Class<?> libcoreTzDataSetVersion =
+                        Class.forName("libcore.timezone.TzDataSetVersion");
+                Method m = libcoreTzDataSetVersion.getDeclaredMethod("currentFormatMajorVersion");
+                m.setAccessible(true);
+                return (int) m.invoke(null);
+            } catch (ReflectiveOperationException roe) {
+                throw new AssertionError(roe);
+            }
+        }
+    }
+
     /**
      * Reads up to {@code maxBytes} bytes from the specified file. The returned array can be
      * shorter than {@code maxBytes} if the file is shorter.
      */
-    private static byte[] readBytes(File file, int maxBytes) throws IOException {
+    private static byte[] readBytes(File file, int maxBytes) {
         if (maxBytes <= 0) {
             throw new IllegalArgumentException("maxBytes ==" + maxBytes);
         }
@@ -113,11 +194,13 @@ public class TimeZoneVersionTest {
             byte[] toReturn = new byte[bytesRead];
             System.arraycopy(max, 0, toReturn, 0, bytesRead);
             return toReturn;
+        } catch (IOException ioe) {
+            throw new UncheckedIOException(ioe);
         }
     }
 
-    private static String readTzDbVersionFromModuleVersionFile() throws IOException {
-        byte[] versionBytes = readBytes(TIME_ZONE_MODULE_VERSION_FILE, 13);
+    private static String readTzDbVersionFrom(File file) {
+        byte[] versionBytes = readBytes(file, 13);
         assertEquals(13, versionBytes.length);
 
         String versionString = new String(versionBytes, StandardCharsets.US_ASCII);
@@ -126,8 +209,12 @@ public class TimeZoneVersionTest {
         return dataSetVersionComponents[1];
     }
 
-    private static String readMajorFormatVersionFromModuleVersionFile() throws IOException {
-        byte[] versionBytes = readBytes(TIME_ZONE_MODULE_VERSION_FILE, 7);
+    private static String readTzDbVersionFromModuleVersionFile() {
+        return readTzDbVersionFrom(TIME_ZONE_MODULE_VERSION_FILE);
+    }
+
+    private static String readMajorFormatVersionFrom(File file) {
+        byte[] versionBytes = readBytes(file, 7);
         assertEquals(7, versionBytes.length);
 
         String versionString = new String(versionBytes, StandardCharsets.US_ASCII);
@@ -135,4 +222,15 @@ public class TimeZoneVersionTest {
         String[] dataSetVersionComponents = versionString.split("\\.");
         return dataSetVersionComponents[0];
     }
+
+    private static String readMajorFormatVersionForVersion(int version) {
+        File tzVersion;
+        if (version >= 8) {
+            tzVersion = new File(
+                    "%s/%d/tz_version".formatted(VERSIONED_DATA_LOCATION, version));
+        } else {
+            tzVersion = TIME_ZONE_MODULE_VERSION_FILE;
+        }
+        return readMajorFormatVersionFrom(tzVersion);
+    }
 }
diff --git a/input_data/android/countryzones.txt b/input_data/android/countryzones.txt
index 486eb1c..d1a64ff 100644
--- a/input_data/android/countryzones.txt
+++ b/input_data/android/countryzones.txt
@@ -25,7 +25,7 @@
 # a time zone for an Android device.
 
 # ianaVersion: The version of the IANA rules this file matches.
-ianaVersion:"2024a"
+ianaVersion:"2025a"
 
 # countries:
 #
@@ -2211,14 +2211,9 @@ countries:<
     id:"Asia/Ulaanbaatar"
     # 1.145M
     priority:1145
+    alternativeIds: "Asia/Choibalsan"
     alternativeIds: "Asia/Ulan_Bator"
   >
-  timeZoneMappings:<
-    utcOffset:"8:00"
-    id:"Asia/Choibalsan"
-    # 38K
-    priority:38
-  >
 
   timeZoneMappings:<
     utcOffset:"7:00"
@@ -2734,7 +2729,7 @@ countries:<
 countries:<
   isoCode:"py"
   timeZoneMappings:<
-    utcOffset:"-4:00"
+    utcOffset:"-3:00"
     id:"America/Asuncion"
   >
 >
diff --git a/input_data/iana/tzdata2024a.tar.gz b/input_data/iana/tzdata2024a.tar.gz
deleted file mode 100644
index febf30b..0000000
Binary files a/input_data/iana/tzdata2024a.tar.gz and /dev/null differ
diff --git a/input_data/iana/tzdata2024a.tar.gz.asc b/input_data/iana/tzdata2024a.tar.gz.asc
deleted file mode 100644
index a8d198f..0000000
--- a/input_data/iana/tzdata2024a.tar.gz.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEEfjeSqdis99YzvBWI7ZfpDmKqfjQFAmW716sACgkQ7ZfpDmKq
-fjTkQQ/6AqS/VNV6+RbbyLbLuOzh4GvYDMq1xTxGnjj7nwr80ob/wwSVmX7Gf5xt
-gVgagC75EJyskY6dfUPbSHwmOx8Dk2ttQtEprhhzk+1WpUSPZoy/RYMdWN+JzO3s
-LekrzU86SAh7yP21qSovYRM5rW02Da5RmiLUmknzBpP2cuZsq3qSPYUEMjB3JO39
-OzBq0nyLbUR9nqew/f6fcPviyweqTkZdcDsr/+jNUGDI/kezGQ0u3ExlGc0EmGU0
-ISAFB7uSDWgoJlwH3ZBtI4lOxiVQRKXafFcdvmLka0hYDGOm6f2zvkhvLEHVN9xK
-/V680qKy1vIOkyDRp664P9qZ0951+tpb9I47ip7SLqqBoyWhlfb/SJ2eFfb3k+kx
-fPkCX89QsqkfSPXySJCO13YYEQXpI2VPdWi0JxDI+LD/VEHITiydrYT+afnn0iyZ
-bM/TKnqaQ4bhAXdLBj3oUSwFQHEgPgeLOrTmWEdN9YmO5Cwbm1gZvOKZ4u2CYW6I
-ZM+ZwCuNO1hqYRSoeIaN60fUOneXaOcAejlOS/bJr7hNKUtmAjsSS7S7YGeNgQld
-LXRDRD3vou/qIHlIhmGpTUlOBl5NXVrP42w91nBYEwNyY4lbKLw22GS4FRF1cu9+
-wfMfJqY4wwDp/uDMXAfWIXU1AdMg7t1NephMIGg4mivKGYmQmvY=
-=CvSR
------END PGP SIGNATURE-----
diff --git a/input_data/iana/tzdata2025a.tar.gz b/input_data/iana/tzdata2025a.tar.gz
new file mode 100644
index 0000000..fee077f
Binary files /dev/null and b/input_data/iana/tzdata2025a.tar.gz differ
diff --git a/input_data/iana/tzdata2025a.tar.gz.asc b/input_data/iana/tzdata2025a.tar.gz.asc
new file mode 100644
index 0000000..a4ce3e2
--- /dev/null
+++ b/input_data/iana/tzdata2025a.tar.gz.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEEfjeSqdis99YzvBWI7ZfpDmKqfjQFAmeIA2oACgkQ7ZfpDmKq
+fjREhxAAjB1QDroFoq07V+56IIrJR3pK/x4Z2jBbg53N49Cam1oMZK5Wxm291d0G
+lPutNQvjiNubnBG4pgMMQ2xEF6jgYY0eFfLlORGK9IoW8e3lnlAqSR9BsOQvWjeA
+lKfmBkhFXetSJ8gu2ModVybpVIqDaJJ73sNQSsA01MHwz0RLV5CLOHXitJ8lBO68
+vdSArRhalLUEIVytAKyy1a0msFdzrrDj/7q6tMV9NDY1xQg4V9TLxnPNds29H0x8
+xO2zrDug6zrbg9z994JYkhq9h9DLe5h4F3StnaDwRK8eLLRq5D7ryK77Z8dtyXZf
+tDPgiNc1MquSg48481dDiUfsRdN5S2OLVFqjyWUuwVKBSkSRv/nBQqisGEybY86T
+H84D5WA0zlj8mFJyuKFmvGHzzKZ6X7mUNrTObaY3G+QHgHjIKWqO7oog447YOYOG
+DSA5rSmYrzZp2RXP/doeFZD+2kbNVPlN8zBh6lANABwvFH6IhDI+/OJzGJqeYotz
+ZWVoU3um6aToMS4Uv2PdBNbH1W1P1pzzMM5TJ/bQO/ujCwaBSTwoDPJT6tW9BLrO
+gJUWd1AumocieAWc0Vyzbrpzbo7Vc//1LF+s1eI+zWt8925unFrBArvQ4h/PyXsc
+O5LhOQVm1986y9xy2YyF+Cy5s+xsKvKENQ0NbLIDa+l5MdEdEXc=
+=NQgW
+-----END PGP SIGNATURE-----
diff --git a/output_data/Android.bp b/output_data/Android.bp
index 86b294b..a7549f1 100644
--- a/output_data/Android.bp
+++ b/output_data/Android.bp
@@ -61,7 +61,7 @@ prebuilt_etc {
 
 prebuilt_etc {
     name: "apex_tz_version_ver8",
-    src: "version/tz_version",
+    src: "versioned/8/version/tz_version",
     filename: "tz_version",
     sub_dir: "tz/versioned/8",
     installable: false,
@@ -105,6 +105,52 @@ prebuilt_etc {
     installable: false,
 }
 
+prebuilt_etc {
+    name: "apex_tz_version_ver9",
+    src: "version/tz_version",
+    filename: "tz_version",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzdata_ver9",
+    src: "iana/tzdata",
+    licenses: ["system_timezone_output_data_iana_licence"],
+    filename: "tzdata",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzlookup.xml_ver9",
+    src: "android/tzlookup.xml",
+    filename: "tzlookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_telephonylookup.xml_ver9",
+    src: "android/telephonylookup.xml",
+    filename: "telephonylookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_icu_res_files_ver9",
+    srcs: [
+        "icu_overlay/zoneinfo64.res",
+        "icu_overlay/metaZones.res",
+        "icu_overlay/timezoneTypes.res",
+        "icu_overlay/windowsZones.res",
+    ],
+    licenses: ["system_timezone_output_data_icu_licence"],
+    sub_dir: "tz/versioned/9/icu",
+    installable: false,
+}
+
 // tzdata packaged into a jar for use in robolectric
 java_genrule_host {
     name: "robolectric_tzdata",
diff --git a/output_data/android/Android.bp b/output_data/android/Android.bp
index 4cbbf2e..b681f08 100644
--- a/output_data/android/Android.bp
+++ b/output_data/android/Android.bp
@@ -22,5 +22,5 @@ prebuilt_root_host {
         "tzlookup.xml",
         "telephonylookup.xml",
     ],
-    relative_install_path: "com.android.tzdata/etc/tz/versioned/8",
+    relative_install_path: "com.android.tzdata/etc/tz/versioned/9",
 }
diff --git a/output_data/android/tzids.prototxt b/output_data/android/tzids.prototxt
index e5c54b6..ba603e0 100644
--- a/output_data/android/tzids.prototxt
+++ b/output_data/android/tzids.prototxt
@@ -1,5 +1,5 @@
 # Autogenerated file - DO NOT EDIT.
-ianaVersion: "2024a"
+ianaVersion: "2025a"
 countryMappings {
   isoCode: "ad"
   timeZoneIds: "Europe/Andorra"
@@ -1195,13 +1195,12 @@ countryMappings {
   timeZoneIds: "Asia/Ulaanbaatar"
   timeZoneIds: "Asia/Hovd"
   timeZoneLinks {
-    alternativeId: "Asia/Ulan_Bator"
+    alternativeId: "Asia/Choibalsan"
     preferredId: "Asia/Ulaanbaatar"
   }
-  timeZoneReplacements {
-    replacedId: "Asia/Choibalsan"
-    replacementId: "Asia/Ulaanbaatar"
-    fromMillis: 1206889200000
+  timeZoneLinks {
+    alternativeId: "Asia/Ulan_Bator"
+    preferredId: "Asia/Ulaanbaatar"
   }
 }
 countryMappings {
@@ -1275,7 +1274,7 @@ countryMappings {
   timeZoneReplacements {
     replacedId: "America/Merida"
     replacementId: "America/Mexico_City"
-    fromMillis: 407653200000
+    fromMillis: 405068400000
   }
   timeZoneReplacements {
     replacedId: "America/Monterrey"
diff --git a/output_data/android/tzlookup.xml b/output_data/android/tzlookup.xml
index 1a75f97..da38859 100644
--- a/output_data/android/tzlookup.xml
+++ b/output_data/android/tzlookup.xml
@@ -2,7 +2,7 @@
 
  **** Autogenerated file - DO NOT EDIT ****
 
---><timezones ianaversion="2024a">
+--><timezones ianaversion="2025a">
  <countryzones>
   <country code="ad" default="Europe/Andorra" everutc="n">
    <id>Europe/Andorra</id>
@@ -531,8 +531,7 @@
    <id alts="Asia/Rangoon">Asia/Yangon</id>
   </country>
   <country code="mn" default="Asia/Ulaanbaatar" everutc="n">
-   <id alts="Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
-   <id notafter="1206889200000" repl="Asia/Ulaanbaatar">Asia/Choibalsan</id>
+   <id alts="Asia/Choibalsan,Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
    <id>Asia/Hovd</id>
   </country>
   <country code="mo" default="Asia/Macau" everutc="n">
@@ -564,7 +563,7 @@
   </country>
   <country code="mx" default="America/Mexico_City" everutc="n">
    <id alts="Mexico/General">America/Mexico_City</id>
-   <id notafter="407653200000" repl="America/Mexico_City">America/Merida</id>
+   <id notafter="405068400000" repl="America/Mexico_City">America/Merida</id>
    <id notafter="594198000000" repl="America/Mexico_City">America/Monterrey</id>
    <id notafter="1667116800000" repl="America/Mexico_City">America/Chihuahua</id>
    <id notafter="1270371600000" repl="America/Mexico_City">America/Bahia_Banderas</id>
diff --git a/output_data/iana/tzdata b/output_data/iana/tzdata
index 7f21189..2dd2c26 100644
Binary files a/output_data/iana/tzdata and b/output_data/iana/tzdata differ
diff --git a/output_data/icu_overlay/Android.bp b/output_data/icu_overlay/Android.bp
index e436877..13ce33b 100644
--- a/output_data/icu_overlay/Android.bp
+++ b/output_data/icu_overlay/Android.bp
@@ -53,5 +53,5 @@ prebuilt_root_host {
         "windowsZones.res",
         "zoneinfo64.res",
     ],
-    relative_install_path: "com.android.tzdata/etc/tz/versioned/8/icu",
+    relative_install_path: "com.android.tzdata/etc/tz/versioned/9/icu",
 }
diff --git a/output_data/icu_overlay/metaZones.res b/output_data/icu_overlay/metaZones.res
index d88fa0f..b225f75 100644
Binary files a/output_data/icu_overlay/metaZones.res and b/output_data/icu_overlay/metaZones.res differ
diff --git a/output_data/icu_overlay/timezoneTypes.res b/output_data/icu_overlay/timezoneTypes.res
index 8d898f0..5023ea2 100644
Binary files a/output_data/icu_overlay/timezoneTypes.res and b/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/output_data/icu_overlay/windowsZones.res b/output_data/icu_overlay/windowsZones.res
index 4bc82bb..02197f7 100644
Binary files a/output_data/icu_overlay/windowsZones.res and b/output_data/icu_overlay/windowsZones.res differ
diff --git a/output_data/icu_overlay/zoneinfo64.res b/output_data/icu_overlay/zoneinfo64.res
index 156f082..3d809cf 100644
Binary files a/output_data/icu_overlay/zoneinfo64.res and b/output_data/icu_overlay/zoneinfo64.res differ
diff --git a/output_data/version/tz_version b/output_data/version/tz_version
index d4b0216..183987b 100644
--- a/output_data/version/tz_version
+++ b/output_data/version/tz_version
@@ -1 +1 @@
-008.001|2024a|001
\ No newline at end of file
+009.001|2025a|001
\ No newline at end of file
diff --git a/output_data/versioned/8/version/tz_version b/output_data/versioned/8/version/tz_version
new file mode 100644
index 0000000..aa9aca1
--- /dev/null
+++ b/output_data/versioned/8/version/tz_version
@@ -0,0 +1 @@
+008.001|2025a|001
diff --git a/testing/data/test1/apex/Android.bp b/testing/data/test1/apex/Android.bp
index 501ba24..bc647e9 100644
--- a/testing/data/test1/apex/Android.bp
+++ b/testing/data/test1/apex/Android.bp
@@ -35,6 +35,11 @@ apex {
         "apex_telephonylookup.xml_ver8_test1",
         "apex_tzdata_ver8_test1",
         "apex_icu_res_files_ver8_test1",
+        "apex_tz_version_ver9_test1",
+        "apex_tzlookup.xml_ver9_test1",
+        "apex_telephonylookup.xml_ver9_test1",
+        "apex_tzdata_ver9_test1",
+        "apex_icu_res_files_ver9_test1",
     ],
 
     // installable: false as we do not want test APEX versions in the system
diff --git a/testing/data/test1/output_data/Android.bp b/testing/data/test1/output_data/Android.bp
index adea730..a2cde90 100644
--- a/testing/data/test1/output_data/Android.bp
+++ b/testing/data/test1/output_data/Android.bp
@@ -120,3 +120,49 @@ prebuilt_etc {
     sub_dir: "tz/versioned/8/icu",
     installable: false,
 }
+
+prebuilt_etc {
+    name: "apex_tz_version_ver9_test1",
+    src: "version/tz_version",
+    filename: "tz_version",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzlookup.xml_ver9_test1",
+    src: "android/tzlookup.xml",
+    filename: "tzlookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_telephonylookup.xml_ver9_test1",
+    src: "android/telephonylookup.xml",
+    filename: "telephonylookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzdata_ver9_test1",
+    src: "iana/tzdata",
+    licenses: ["system_timezone_testing_test1_output_data_iana_licence"],
+    filename: "tzdata",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_icu_res_files_ver9_test1",
+    srcs: [
+        "icu_overlay/zoneinfo64.res",
+        "icu_overlay/metaZones.res",
+        "icu_overlay/timezoneTypes.res",
+        "icu_overlay/windowsZones.res",
+    ],
+    licenses: ["system_timezone_testing_test1_output_data_icu_licence"],
+    sub_dir: "tz/versioned/9/icu",
+    installable: false,
+}
diff --git a/testing/data/test1/output_data/android/tzlookup.xml b/testing/data/test1/output_data/android/tzlookup.xml
index 8008972..8610778 100644
--- a/testing/data/test1/output_data/android/tzlookup.xml
+++ b/testing/data/test1/output_data/android/tzlookup.xml
@@ -531,8 +531,7 @@
    <id alts="Asia/Rangoon">Asia/Yangon</id>
   </country>
   <country code="mn" default="Asia/Ulaanbaatar" everutc="n">
-   <id alts="Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
-   <id notafter="1206889200000" repl="Asia/Ulaanbaatar">Asia/Choibalsan</id>
+   <id alts="Asia/Choibalsan,Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
    <id>Asia/Hovd</id>
   </country>
   <country code="mo" default="Asia/Macau" everutc="n">
@@ -564,7 +563,7 @@
   </country>
   <country code="mx" default="America/Mexico_City" everutc="n">
    <id alts="Mexico/General">America/Mexico_City</id>
-   <id notafter="407653200000" repl="America/Mexico_City">America/Merida</id>
+   <id notafter="405068400000" repl="America/Mexico_City">America/Merida</id>
    <id notafter="594198000000" repl="America/Mexico_City">America/Monterrey</id>
    <id notafter="1667116800000" repl="America/Mexico_City">America/Chihuahua</id>
    <id notafter="1270371600000" repl="America/Mexico_City">America/Bahia_Banderas</id>
diff --git a/testing/data/test1/output_data/iana/tzdata b/testing/data/test1/output_data/iana/tzdata
index 8da93d9..6909eb9 100644
Binary files a/testing/data/test1/output_data/iana/tzdata and b/testing/data/test1/output_data/iana/tzdata differ
diff --git a/testing/data/test1/output_data/icu_overlay/metaZones.res b/testing/data/test1/output_data/icu_overlay/metaZones.res
index d88fa0f..b225f75 100644
Binary files a/testing/data/test1/output_data/icu_overlay/metaZones.res and b/testing/data/test1/output_data/icu_overlay/metaZones.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/timezoneTypes.res b/testing/data/test1/output_data/icu_overlay/timezoneTypes.res
index 8d898f0..5023ea2 100644
Binary files a/testing/data/test1/output_data/icu_overlay/timezoneTypes.res and b/testing/data/test1/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/windowsZones.res b/testing/data/test1/output_data/icu_overlay/windowsZones.res
index 4bc82bb..02197f7 100644
Binary files a/testing/data/test1/output_data/icu_overlay/windowsZones.res and b/testing/data/test1/output_data/icu_overlay/windowsZones.res differ
diff --git a/testing/data/test1/output_data/icu_overlay/zoneinfo64.res b/testing/data/test1/output_data/icu_overlay/zoneinfo64.res
index aba8d72..fdffb07 100644
Binary files a/testing/data/test1/output_data/icu_overlay/zoneinfo64.res and b/testing/data/test1/output_data/icu_overlay/zoneinfo64.res differ
diff --git a/testing/data/test1/output_data/version/tz_version b/testing/data/test1/output_data/version/tz_version
index 3802869..4ecc552 100644
--- a/testing/data/test1/output_data/version/tz_version
+++ b/testing/data/test1/output_data/version/tz_version
@@ -1 +1 @@
-008.001|2030a|001
\ No newline at end of file
+009.001|2030a|001
\ No newline at end of file
diff --git a/testing/data/test3/apex/Android.bp b/testing/data/test3/apex/Android.bp
index f818e88..84d29fe 100644
--- a/testing/data/test3/apex/Android.bp
+++ b/testing/data/test3/apex/Android.bp
@@ -36,6 +36,11 @@ apex {
         "apex_telephonylookup.xml_ver8_test3",
         "apex_tzdata_ver8_test3",
         "apex_icu_res_files_ver8_test3",
+        "apex_tz_version_ver9_test3",
+        "apex_tzlookup.xml_ver9_test3",
+        "apex_telephonylookup.xml_ver9_test3",
+        "apex_tzdata_ver9_test3",
+        "apex_icu_res_files_ver9_test3",
     ],
 
     // installable: false as we do not want test APEX versions in the system
diff --git a/testing/data/test3/output_data/Android.bp b/testing/data/test3/output_data/Android.bp
index 855b5c8..17dbaff 100644
--- a/testing/data/test3/output_data/Android.bp
+++ b/testing/data/test3/output_data/Android.bp
@@ -120,3 +120,49 @@ prebuilt_etc {
     sub_dir: "tz/versioned/8/icu",
     installable: false,
 }
+
+prebuilt_etc {
+    name: "apex_tz_version_ver9_test3",
+    src: "version/tz_version",
+    filename: "tz_version",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzlookup.xml_ver9_test3",
+    src: "android/tzlookup.xml",
+    filename: "tzlookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_telephonylookup.xml_ver9_test3",
+    src: "android/telephonylookup.xml",
+    filename: "telephonylookup.xml",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_tzdata_ver9_test3",
+    src: "iana/tzdata",
+    licenses: ["system_timezone_testing_test3_output_data_iana_licence"],
+    filename: "tzdata",
+    sub_dir: "tz/versioned/9",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "apex_icu_res_files_ver9_test3",
+    srcs: [
+        "icu_overlay/zoneinfo64.res",
+        "icu_overlay/metaZones.res",
+        "icu_overlay/timezoneTypes.res",
+        "icu_overlay/windowsZones.res",
+    ],
+    licenses: ["system_timezone_testing_test3_output_data_icu_licence"],
+    sub_dir: "tz/versioned/9/icu",
+    installable: false,
+}
diff --git a/testing/data/test3/output_data/android/tzlookup.xml b/testing/data/test3/output_data/android/tzlookup.xml
index 8008972..8610778 100644
--- a/testing/data/test3/output_data/android/tzlookup.xml
+++ b/testing/data/test3/output_data/android/tzlookup.xml
@@ -531,8 +531,7 @@
    <id alts="Asia/Rangoon">Asia/Yangon</id>
   </country>
   <country code="mn" default="Asia/Ulaanbaatar" everutc="n">
-   <id alts="Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
-   <id notafter="1206889200000" repl="Asia/Ulaanbaatar">Asia/Choibalsan</id>
+   <id alts="Asia/Choibalsan,Asia/Ulan_Bator">Asia/Ulaanbaatar</id>
    <id>Asia/Hovd</id>
   </country>
   <country code="mo" default="Asia/Macau" everutc="n">
@@ -564,7 +563,7 @@
   </country>
   <country code="mx" default="America/Mexico_City" everutc="n">
    <id alts="Mexico/General">America/Mexico_City</id>
-   <id notafter="407653200000" repl="America/Mexico_City">America/Merida</id>
+   <id notafter="405068400000" repl="America/Mexico_City">America/Merida</id>
    <id notafter="594198000000" repl="America/Mexico_City">America/Monterrey</id>
    <id notafter="1667116800000" repl="America/Mexico_City">America/Chihuahua</id>
    <id notafter="1270371600000" repl="America/Mexico_City">America/Bahia_Banderas</id>
diff --git a/testing/data/test3/output_data/iana/tzdata b/testing/data/test3/output_data/iana/tzdata
index 8da93d9..6909eb9 100644
Binary files a/testing/data/test3/output_data/iana/tzdata and b/testing/data/test3/output_data/iana/tzdata differ
diff --git a/testing/data/test3/output_data/icu_overlay/metaZones.res b/testing/data/test3/output_data/icu_overlay/metaZones.res
index 9e4712c..c4e9a78 100644
Binary files a/testing/data/test3/output_data/icu_overlay/metaZones.res and b/testing/data/test3/output_data/icu_overlay/metaZones.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/timezoneTypes.res b/testing/data/test3/output_data/icu_overlay/timezoneTypes.res
index 4744c94..c6ba2cf 100644
Binary files a/testing/data/test3/output_data/icu_overlay/timezoneTypes.res and b/testing/data/test3/output_data/icu_overlay/timezoneTypes.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/windowsZones.res b/testing/data/test3/output_data/icu_overlay/windowsZones.res
index 1926dec..fb242db 100644
Binary files a/testing/data/test3/output_data/icu_overlay/windowsZones.res and b/testing/data/test3/output_data/icu_overlay/windowsZones.res differ
diff --git a/testing/data/test3/output_data/icu_overlay/zoneinfo64.res b/testing/data/test3/output_data/icu_overlay/zoneinfo64.res
index 329c430..f504759 100644
Binary files a/testing/data/test3/output_data/icu_overlay/zoneinfo64.res and b/testing/data/test3/output_data/icu_overlay/zoneinfo64.res differ
diff --git a/testing/data/test3/output_data/version/tz_version b/testing/data/test3/output_data/version/tz_version
index 3802869..4ecc552 100644
--- a/testing/data/test3/output_data/version/tz_version
+++ b/testing/data/test3/output_data/version/tz_version
@@ -1 +1 @@
-008.001|2030a|001
\ No newline at end of file
+009.001|2030a|001
\ No newline at end of file
```

