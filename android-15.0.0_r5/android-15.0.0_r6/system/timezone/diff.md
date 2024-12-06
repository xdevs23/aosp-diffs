```diff
diff --git a/input_data/android/telephonylookup.txt b/input_data/android/telephonylookup.txt
index a88802e..9e73e14 100644
--- a/input_data/android/telephonylookup.txt
+++ b/input_data/android/telephonylookup.txt
@@ -58,3 +58,10 @@ networks:<
   countryIsoCode: "gu"
 >
 
+networks:<
+  # American Samoa Telecommunications ASTCA  http://b/328151581
+  mcc: "311"
+  mnc: "780"
+  countryIsoCode: "as"
+>
+
diff --git a/output_data/android/Android.bp b/output_data/android/Android.bp
index af0cb85..4cbbf2e 100644
--- a/output_data/android/Android.bp
+++ b/output_data/android/Android.bp
@@ -16,38 +16,6 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-// Module definition producing a tzlookup.xml prebuilt file in
-// /system/etc/tzdata_module/etc/tz for standalone ART testing purposes.
-// This is a temporary change needed until the ART Buildbot and Golem both
-// fully support the Runtime APEX (see b/121117762). This module should
-// never be shipped by default (i.e. should never be part of
-// `PRODUCT_PACKAGE`.)
-
-// TODO(b/121117762, b/129332183): Remove this module definition when
-// the ART Buildbot and Golem have full support for the Time Zone Data APEX.
-prebuilt_etc {
-    name: "tzlookup.xml-art-test-tzdata",
-    src: "tzlookup.xml",
-    filename_from_src: true,
-    sub_dir: "tzdata_module/etc/tz",
-}
-
-// Module definition producing a telephonylookup.xml prebuilt file in
-// /system/etc/tzdata_module/etc/tz for standalone ART testing purposes.
-// This is a temporary change needed until the ART Buildbot and Golem both
-// fully support the Runtime APEX (see b/121117762). This module should
-// never be shipped by default (i.e. should never be part of
-// `PRODUCT_PACKAGE`.)
-
-// TODO(b/121117762, b/129332183): Remove this module definition when
-// the ART Buildbot and Golem have full support for the Time Zone Data APEX.
-prebuilt_etc {
-    name: "telephonylookup.xml-art-test-tzdata",
-    src: "telephonylookup.xml",
-    filename_from_src: true,
-    sub_dir: "tzdata_module/etc/tz",
-}
-
 prebuilt_root_host {
     name: "tzlookup.xml_host_tzdata_apex",
     srcs: [
diff --git a/output_data/android/telephonylookup.xml b/output_data/android/telephonylookup.xml
index 34808ea..17a7e9c 100644
--- a/output_data/android/telephonylookup.xml
+++ b/output_data/android/telephonylookup.xml
@@ -6,5 +6,6 @@
  <networks>
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
+  <network mcc="311" mnc="780" country="as"/>
  </networks>
 </telephony_lookup>
diff --git a/output_data/iana/Android.bp b/output_data/iana/Android.bp
index 1070786..5e7470e 100644
--- a/output_data/iana/Android.bp
+++ b/output_data/iana/Android.bp
@@ -73,21 +73,6 @@ prebuilt_usr_share_host {
     },
 }
 
-// Module definition producing a tzdata prebuilt file in
-// /system/etc/tzdata_module/etc/tz for standalone ART testing purposes.
-// This is a temporary change needed until the ART Buildbot and Golem both
-// fully support the Runtime APEX (see b/121117762). This module should never
-// be shipped by default (i.e. should never be part of `PRODUCT_PACKAGE`.)
-
-// TODO(b/121117762, b/129332183): Remove this module definition when
-// the ART Buildbot and Golem have full support for the Time Zone Data APEX.
-prebuilt_etc {
-    name: "tzdata-art-test-tzdata",
-    src: "tzdata",
-    filename_from_src: true,
-    sub_dir: "tzdata_module/etc/tz",
-}
-
 prebuilt_root_host {
     name: "tzdata_host_tzdata_apex",
     src: "tzdata",
diff --git a/output_data/icu_overlay/Android.bp b/output_data/icu_overlay/Android.bp
index d9977a8..e436877 100644
--- a/output_data/icu_overlay/Android.bp
+++ b/output_data/icu_overlay/Android.bp
@@ -46,8 +46,7 @@ license {
 }
 
 prebuilt_root_host {
-    // TODO(mingaleev) Rename this. It's no longer tzdata.dat.
-    name: "icu_tzdata.dat_host_tzdata_apex",
+    name: "tzdata_icu_res_files_host_prebuilts",
     srcs: [
         "metaZones.res",
         "timezoneTypes.res",
diff --git a/output_data/version/Android.bp b/output_data/version/Android.bp
index e5816f5..2518d96 100644
--- a/output_data/version/Android.bp
+++ b/output_data/version/Android.bp
@@ -39,21 +39,6 @@ prebuilt_usr_share_host {
     },
 }
 
-// Module definition producing a tz_version prebuilt file in
-// /system/etc/tzdata_module/etc/tz for standalone ART testing purposes.
-// This is a temporary change needed until the ART Buildbot and Golem both fully
-// support the Runtime APEX (see b/121117762). This module should never
-// be shipped by default (i.e. should never be part of `PRODUCT_PACKAGE`.)
-
-// TODO(b/121117762, b/129332183): Remove this module definition when
-// the ART Buildbot and Golem have full support for the Time Zone Data APEX.
-prebuilt_etc {
-    name: "tz_version-art-test-tzdata",
-    src: "tz_version",
-    filename_from_src: true,
-    sub_dir: "tzdata_module/etc/tz",
-}
-
 prebuilt_root_host {
     name: "tz_version_host_tzdata_apex",
     src: "tz_version",
diff --git a/testing/data/test1/output_data/android/telephonylookup.xml b/testing/data/test1/output_data/android/telephonylookup.xml
index 34808ea..17a7e9c 100644
--- a/testing/data/test1/output_data/android/telephonylookup.xml
+++ b/testing/data/test1/output_data/android/telephonylookup.xml
@@ -6,5 +6,6 @@
  <networks>
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
+  <network mcc="311" mnc="780" country="as"/>
  </networks>
 </telephony_lookup>
diff --git a/testing/data/test3/output_data/android/telephonylookup.xml b/testing/data/test3/output_data/android/telephonylookup.xml
index 34808ea..17a7e9c 100644
--- a/testing/data/test3/output_data/android/telephonylookup.xml
+++ b/testing/data/test3/output_data/android/telephonylookup.xml
@@ -6,5 +6,6 @@
  <networks>
   <network mcc="310" mnc="370" country="gu"/>
   <network mcc="310" mnc="470" country="gu"/>
+  <network mcc="311" mnc="780" country="as"/>
  </networks>
 </telephony_lookup>
```

