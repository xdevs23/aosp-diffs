```diff
diff --git a/Android.bp b/Android.bp
index 53f01ce2..b4ca44d7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -119,7 +119,7 @@ java_library {
         "mockito-target-extended",
     ],
     libs: [
-        "android.test.mock",
+        "android.test.mock.stubs",
     ],
     java_version: "1.7",
 }
diff --git a/README.version b/README.version
index b2832b62..631baa72 100644
--- a/README.version
+++ b/README.version
@@ -1,3 +1,3 @@
 URL: https://github.com/googlei18n/libphonenumber/
-Version: 8.13.39
+Version: 8.13.45
 BugComponent: 20868
diff --git a/carrier/pom.xml b/carrier/pom.xml
index 6cb0b551..43f73206 100644
--- a/carrier/pom.xml
+++ b/carrier/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>carrier</artifactId>
-  <version>1.223</version>
+  <version>1.229</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.39</version>
+    <version>8.13.45</version>
   </parent>
 
   <build>
@@ -79,12 +79,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.39</version>
+      <version>8.13.45</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.233</version>
+      <version>2.239</version>
     </dependency>
   </dependencies>
 
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/220_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/220_en
index 3b6437d0..1e579951 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/220_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/220_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/226_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/226_en
index b186cdec..b764a65e 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/226_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/226_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/230_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/230_en
index 103c0b3b..88736a11 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/230_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/230_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/235_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/235_en
index 13f66097..b10b1297 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/235_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/235_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/237_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/237_en
index afc0f175..e537c4bd 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/237_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/237_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/244_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/244_en
index 8ef0a285..13af82fc 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/244_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/244_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en
index 2d19a2ec..3180ca17 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/32_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/32_en
index 9826eafa..62818a56 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/32_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/32_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en
index c336df63..aae78632 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en
index b545f1fc..2dd4b5b7 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/40_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/40_en
index 002ce42f..cba7e23f 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/40_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/40_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en
index c3447393..0bd61f8f 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/420_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/420_en
index d234d8b5..80dad968 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/420_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/420_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en
index 1da42ba0..6d9ac27b 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/591_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/591_en
index c768061f..d6cf57af 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/591_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/591_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en
index 1b25ea1b..179e1561 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/61_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/61_en
index 99218d83..917e4ee4 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/61_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/61_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en
index f7c4c11d..d0b45bfb 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/673_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/673_en
index a9393d6c..f80692e6 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/673_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/673_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en
index 4209fd1c..b72426c5 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh
index 18a925b6..b349c327 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/880_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/880_en
index 47549659..33e80e63 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/880_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/880_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en
index a8c02bbd..95837b64 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en
index a6ecdb5c..581deeee 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en
index 5c79e440..86e8e92a 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en differ
diff --git a/demo/pom.xml b/demo/pom.xml
index d7fbb38c..7894663b 100644
--- a/demo/pom.xml
+++ b/demo/pom.xml
@@ -3,13 +3,13 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>demo</artifactId>
-  <version>8.13.39</version>
+  <version>8.13.45</version>
   <packaging>war</packaging>
   <url>https://github.com/google/libphonenumber/</url>
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.39</version>
+    <version>8.13.45</version>
   </parent>
 
   <properties>
@@ -68,17 +68,17 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.39</version>
+      <version>8.13.45</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>geocoder</artifactId>
-      <version>2.233</version>
+      <version>2.239</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>carrier</artifactId>
-      <version>1.223</version>
+      <version>1.229</version>
     </dependency>
   </dependencies>
 
diff --git a/geocoder/pom.xml b/geocoder/pom.xml
index 4ea3b7ad..b0258282 100644
--- a/geocoder/pom.xml
+++ b/geocoder/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>geocoder</artifactId>
-  <version>2.233</version>
+  <version>2.239</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.39</version>
+    <version>8.13.45</version>
   </parent>
 
   <build>
@@ -87,12 +87,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.39</version>
+      <version>8.13.45</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.233</version>
+      <version>2.239</version>
     </dependency>
   </dependencies>
 
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1807_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1807_en
index d9cd36a2..92c22554 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1807_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1807_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/234_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/234_en
index 4eb79f89..12f1479d 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/234_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/234_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/243_fr b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/243_fr
index ac48d421..f4b027c2 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/243_fr and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/243_fr differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/251_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/251_en
index 04919d16..f54e9add 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/251_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/251_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_en
index f8a99552..2112cb36 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_es b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_es
index 7fc1659b..289df96c 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_es and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/52_es differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/54_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/54_en
index ebb6ba97..39fe0661 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/54_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/54_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en
index 48ea7c2d..a42f4fb8 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh
index 2ab9c681..80b79b00 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data
index ca76e39b..51deae9a 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data and b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/internal/prefixmapper/pom.xml b/internal/prefixmapper/pom.xml
index f498043a..ea0ac921 100644
--- a/internal/prefixmapper/pom.xml
+++ b/internal/prefixmapper/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>prefixmapper</artifactId>
-  <version>2.233</version>
+  <version>2.239</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.39</version>
+    <version>8.13.45</version>
     <relativePath>../../pom.xml</relativePath>
   </parent>
 
@@ -75,7 +75,7 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.39</version>
+      <version>8.13.45</version>
     </dependency>
   </dependencies>
 
diff --git a/libphonenumber/pom.xml b/libphonenumber/pom.xml
index 0947d535..1d795f0a 100644
--- a/libphonenumber/pom.xml
+++ b/libphonenumber/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber</artifactId>
-  <version>8.13.39</version>
+  <version>8.13.45</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.39</version>
+    <version>8.13.45</version>
   </parent>
 
   <build>
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java b/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
index c49189fa..fb85fc13 100644
--- a/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
+++ b/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
@@ -85,6 +85,9 @@ public class PhoneNumberUtil {
   // considered to be an area code.
   private static final Set<Integer> GEO_MOBILE_COUNTRIES_WITHOUT_MOBILE_AREA_CODES;
 
+  // Set of country codes that doesn't have national prefix, but it has area codes.
+  private static final Set<Integer> COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES;
+
   // Set of country calling codes that have geographically assigned mobile numbers. This may not be
   // complete; we add calling codes case by case, as we find geographical mobile numbers or hear
   // from user reports. Note that countries like the US, where we can't distinguish between
@@ -127,6 +130,11 @@ public class PhoneNumberUtil {
     GEO_MOBILE_COUNTRIES_WITHOUT_MOBILE_AREA_CODES =
         Collections.unmodifiableSet(geoMobileCountriesWithoutMobileAreaCodes);
 
+    HashSet<Integer> countriesWithoutNationalPrefixWithAreaCodes = new HashSet<>();
+    countriesWithoutNationalPrefixWithAreaCodes.add(52);  // Mexico
+    COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES =
+    		Collections.unmodifiableSet(countriesWithoutNationalPrefixWithAreaCodes);
+
     HashSet<Integer> geoMobileCountries = new HashSet<>();
     geoMobileCountries.add(52);  // Mexico
     geoMobileCountries.add(54);  // Argentina
@@ -893,14 +901,18 @@ public class PhoneNumberUtil {
     if (metadata == null) {
       return 0;
     }
+
+    PhoneNumberType type = getNumberType(number);
+    int countryCallingCode = number.getCountryCode();
     // If a country doesn't use a national prefix, and this number doesn't have an Italian leading
     // zero, we assume it is a closed dialling plan with no area codes.
-    if (!metadata.hasNationalPrefix() && !number.isItalianLeadingZero()) {
+    // Note:this is our general assumption, but there are exceptions which are tracked in
+    // COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES.
+    if (!metadata.hasNationalPrefix() && !number.isItalianLeadingZero() 
+    && !COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES.contains(countryCallingCode)) {
       return 0;
     }
 
-    PhoneNumberType type = getNumberType(number);
-    int countryCallingCode = number.getCountryCode();
     if (type == PhoneNumberType.MOBILE
         // Note this is a rough heuristic; it doesn't cover Indonesia well, for example, where area
         // codes are present for some mobile phones but not for others. We have no better way of
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO
index d151ed36..5345c505 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 83747d80..96c51a32 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD
index 5a9d6c27..5c4cb85a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF
index 4b6926d7..fb8d8103 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ
index fbfc2abf..0c0ce52d 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO
index 5fce8b4a..028a73fe 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD
index 214136ad..cee18e96 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM
index dc81d2a4..283a2aca 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN
index e1049482..43dc62fb 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ
index 8b8fc592..c571a37a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index 6701ed48..be51fb2a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ
index c21cb67f..fe704f35 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG
index 39f8f4e0..5270ea38 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET
index 260021e0..c7de6f75 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI
index 1497e868..2ed02254 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR
index d2a8a4a2..3d3ebbb4 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE
index 27f9e4f1..894199b9 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM
index 6015e71f..79ffc4e3 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY
index 4aefd41e..66e2a80e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index b6f41a7b..055831c6 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID
index 37464e02..0a67a1a2 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL
index 43c43462..d588ee97 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR
index f009b199..ce4de563 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA
index ba2ac979..3f67e0ac 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU
index 5358c7f0..d650f761 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX
index 7813a32b..0a76e17f 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY
index 3719025a..f42ad826 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG
index c7360320..436d7522 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ
index 39f9504e..34fd143c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO
index 6fe8c1f9..c2a71717 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC
index 9c2098bd..0340ea64 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index bb2ea5cb..8076c004 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 42448b19..9e985017 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD
index 79b852fa..3916ac2d 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index 65b17207..69b68c9b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY
index 13f5d072..850ac2f3 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI
index bcd66fc1..e6a606ea 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA
index a35282cb..340306dc 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_AT b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_AT
index fec271cb..2a8a93b9 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_AT and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_AT differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CA b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CA
index 22555fdb..3a78361e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CN b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CN
index 5d648671..062fdcaf 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_CN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DE b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DE
index ab1b4aa2..644e116e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI
index 46b65272..ee615e75 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI differ
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
index cb56077e..a8bfec34 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
@@ -309,6 +309,9 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     // Italian numbers - there is no national prefix, but it still has an area code.
     assertEquals(2, phoneUtil.getLengthOfGeographicalAreaCode(IT_NUMBER));
 
+    // Mexico numbers - there is no national prefix, but it still has an area code.
+    assertEquals(2, phoneUtil.getLengthOfGeographicalAreaCode(MX_NUMBER1));
+
     // Google Singapore. Singapore has no area code and no national prefix.
     assertEquals(0, phoneUtil.getLengthOfGeographicalAreaCode(SG_NUMBER));
 
diff --git a/pom.xml b/pom.xml
index ca10fdd7..981dca76 100644
--- a/pom.xml
+++ b/pom.xml
@@ -3,7 +3,7 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber-parent</artifactId>
-  <version>8.13.39</version>
+  <version>8.13.45</version>
   <packaging>pom</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
@@ -34,7 +34,7 @@
     <connection>scm:git:https://github.com/google/libphonenumber.git</connection>
     <developerConnection>scm:git:git@github.com:googlei18n/libphonenumber.git</developerConnection>
     <url>https://github.com/google/libphonenumber/</url>
-    <tag>v8.13.39</tag>
+    <tag>v8.13.45</tag>
   </scm>
 
   <properties>
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1807_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1807_en
index d9cd36a2..92c22554 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1807_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1807_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/234_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/234_en
index 4eb79f89..12f1479d 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/234_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/234_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/243_fr b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/243_fr
index ac48d421..f4b027c2 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/243_fr and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/243_fr differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/251_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/251_en
index 04919d16..f54e9add 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/251_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/251_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_en
index f8a99552..2112cb36 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_es b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_es
index 7fc1659b..289df96c 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_es and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/52_es differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/54_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/54_en
index ebb6ba97..39fe0661 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/54_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/54_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en
index 48ea7c2d..a42f4fb8 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh
index 2ab9c681..80b79b00 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data
index ca76e39b..51deae9a 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
index 5bdbcb29..8fa35148 100644
--- a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
+++ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
@@ -87,6 +87,9 @@ public class PhoneNumberUtil {
   // considered to be an area code.
   private static final Set<Integer> GEO_MOBILE_COUNTRIES_WITHOUT_MOBILE_AREA_CODES;
 
+  // Set of country codes that doesn't have national prefix, but it has area codes.
+  private static final Set<Integer> COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES;
+
   // Set of country calling codes that have geographically assigned mobile numbers. This may not be
   // complete; we add calling codes case by case, as we find geographical mobile numbers or hear
   // from user reports. Note that countries like the US, where we can't distinguish between
@@ -129,6 +132,11 @@ public class PhoneNumberUtil {
     GEO_MOBILE_COUNTRIES_WITHOUT_MOBILE_AREA_CODES =
         Collections.unmodifiableSet(geoMobileCountriesWithoutMobileAreaCodes);
 
+    HashSet<Integer> countriesWithoutNationalPrefixWithAreaCodes = new HashSet<>();
+    countriesWithoutNationalPrefixWithAreaCodes.add(52);  // Mexico
+    COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES = 
+    		Collections.unmodifiableSet(countriesWithoutNationalPrefixWithAreaCodes);
+
     HashSet<Integer> geoMobileCountries = new HashSet<>();
     geoMobileCountries.add(52);  // Mexico
     geoMobileCountries.add(54);  // Argentina
@@ -926,14 +934,18 @@ public class PhoneNumberUtil {
     if (metadata == null) {
       return 0;
     }
+
+    PhoneNumberType type = getNumberType(number);
+    int countryCallingCode = number.getCountryCode();
     // If a country doesn't use a national prefix, and this number doesn't have an Italian leading
     // zero, we assume it is a closed dialling plan with no area codes.
-    if (!metadata.hasNationalPrefix() && !number.isItalianLeadingZero()) {
+    // Note:this is our general assumption, but there are exceptions which are tracked in
+    // COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES.
+    if (!metadata.hasNationalPrefix() && !number.isItalianLeadingZero() 
+    && !COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES.contains(countryCallingCode)) {
       return 0;
     }
 
-    PhoneNumberType type = getNumberType(number);
-    int countryCallingCode = number.getCountryCode();
     if (type == PhoneNumberType.MOBILE
         // Note this is a rough heuristic; it doesn't cover Indonesia well, for example, where area
         // codes are present for some mobile phones but not for others. We have no better way of
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO
index d151ed36..5345c505 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 83747d80..96c51a32 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD
index 5a9d6c27..5c4cb85a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BD differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF
index 4b6926d7..fb8d8103 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ
index fbfc2abf..0c0ce52d 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO
index 5fce8b4a..028a73fe 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD
index 214136ad..cee18e96 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CD differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM
index dc81d2a4..283a2aca 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN
index e1049482..43dc62fb 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ
index 8b8fc592..c571a37a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index 6701ed48..be51fb2a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ
index c21cb67f..fe704f35 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG
index 39f8f4e0..5270ea38 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET
index 260021e0..c7de6f75 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ET differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI
index 1497e868..2ed02254 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR
index d2a8a4a2..3d3ebbb4 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE
index 27f9e4f1..894199b9 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM
index 6015e71f..79ffc4e3 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY
index 4aefd41e..66e2a80e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index b6f41a7b..055831c6 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID
index 37464e02..0a67a1a2 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ID differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL
index 43c43462..d588ee97 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR
index f009b199..ce4de563 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA
index ba2ac979..3f67e0ac 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU
index 5358c7f0..d650f761 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX
index 7813a32b..0a76e17f 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MX differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY
index 3719025a..f42ad826 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG
index c7360320..436d7522 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ
index 39f9504e..34fd143c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO
index 6fe8c1f9..c2a71717 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC
index 9c2098bd..0340ea64 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SC differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index bb2ea5cb..8076c004 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 42448b19..9e985017 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD
index 79b852fa..3916ac2d 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TD differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index 65b17207..69b68c9b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY
index 13f5d072..850ac2f3 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI
index bcd66fc1..e6a606ea 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VI differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA
index a35282cb..340306dc 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_AT b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_AT
index fec271cb..2a8a93b9 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_AT and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_AT differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CA
index 22555fdb..3a78361e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CN
index 5d648671..062fdcaf 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_CN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DE
index ab1b4aa2..644e116e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI
index 46b65272..ee615e75 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI differ
```

