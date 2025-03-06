```diff
diff --git a/README.version b/README.version
index 631baa72..bac5648c 100644
--- a/README.version
+++ b/README.version
@@ -1,3 +1,3 @@
 URL: https://github.com/googlei18n/libphonenumber/
-Version: 8.13.45
+Version: 8.13.51
 BugComponent: 20868
diff --git a/build.xml b/build.xml
index f010e7cf..cd682382 100644
--- a/build.xml
+++ b/build.xml
@@ -77,8 +77,9 @@
       <arg value="--output-dir=${libphonenumber.test.dir}/com/google/i18n/phonenumbers"/>
       <arg value="--data-prefix=data/PhoneNumberMetadataProtoForTesting"/>
       <arg value="--mapping-class=CountryCodeToRegionCodeMapForTesting"/>
-      <arg value="--copyright=2010"/>
+      <arg value="--copyright=2011"/>
       <arg value="--lite-build=false"/>
+      <arg value="--build-regioncode=true"/>
     </exec>
   </target>
 
diff --git a/carrier/pom.xml b/carrier/pom.xml
index 43f73206..54fc9f6d 100644
--- a/carrier/pom.xml
+++ b/carrier/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>carrier</artifactId>
-  <version>1.229</version>
+  <version>1.235</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.45</version>
+    <version>8.13.51</version>
   </parent>
 
   <build>
@@ -79,12 +79,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.45</version>
+      <version>8.13.51</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.239</version>
+      <version>2.245</version>
     </dependency>
   </dependencies>
 
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/1671_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/1671_en
index 8a02131d..495356a7 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/1671_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/1671_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en
index 636058a2..b82ba94a 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/228_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/228_en
index 92f91335..18bae74b 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/228_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/228_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en
index e4de5329..85f95a78 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en
index 52fd817a..f323c6fd 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/262_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/262_en
index 4f062dfe..335a1ca9 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/262_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/262_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en
index 3180ca17..e98322a6 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/27_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en
index 2dd4b5b7..0b11a8b0 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/34_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en
index a5469a9f..ccdf13b0 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/372_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/372_en
index 26ed948f..434537e5 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/372_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/372_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/380_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/380_en
index 496d88e3..dd5d58ef 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/380_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/380_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/385_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/385_en
index cb80acaf..bbfaa628 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/385_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/385_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/44_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/44_en
index e539f1c4..7fafff65 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/44_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/44_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en
index 6d9ac27b..c9667369 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/47_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en
index aa12ffb3..b452b489 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/508_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/508_en
index 9d4d7daa..1867f2ad 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/508_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/508_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/57_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/57_en
index 85331b20..07e076f4 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/57_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/57_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/590_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/590_en
index dae8dfa9..bb71c263 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/590_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/590_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/594_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/594_en
index a1223017..d58c2890 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/594_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/594_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/596_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/596_en
index 7983842b..5ceee9a8 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/596_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/596_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en
index d0b45bfb..1886f222 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/81_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/81_en
index dd4b1752..e217c2b0 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/81_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/81_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en
index b72426c5..6535d4b6 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh
index b349c327..3e93c9a1 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/963_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/963_en
index ee4fe314..c0fce956 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/963_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/963_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en
index 95837b64..90fb6bca 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en
index 581deeee..7098642d 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en
index 86e8e92a..db4b1344 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/995_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/998_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/998_en
index d13f53f5..02298a59 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/998_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/998_en differ
diff --git a/demo/pom.xml b/demo/pom.xml
index 7894663b..78c4652c 100644
--- a/demo/pom.xml
+++ b/demo/pom.xml
@@ -3,13 +3,13 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>demo</artifactId>
-  <version>8.13.45</version>
+  <version>8.13.51</version>
   <packaging>war</packaging>
   <url>https://github.com/google/libphonenumber/</url>
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.45</version>
+    <version>8.13.51</version>
   </parent>
 
   <properties>
@@ -68,17 +68,17 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.45</version>
+      <version>8.13.51</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>geocoder</artifactId>
-      <version>2.239</version>
+      <version>2.245</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>carrier</artifactId>
-      <version>1.229</version>
+      <version>1.235</version>
     </dependency>
   </dependencies>
 
diff --git a/geocoder/pom.xml b/geocoder/pom.xml
index b0258282..5b483b0b 100644
--- a/geocoder/pom.xml
+++ b/geocoder/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>geocoder</artifactId>
-  <version>2.239</version>
+  <version>2.245</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.45</version>
+    <version>8.13.51</version>
   </parent>
 
   <build>
@@ -87,12 +87,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.45</version>
+      <version>8.13.51</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.239</version>
+      <version>2.245</version>
     </dependency>
   </dependencies>
 
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1327_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1327_en
new file mode 100644
index 00000000..e63e5ea3
Binary files /dev/null and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1327_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1942_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1942_en
new file mode 100644
index 00000000..7e9c88e6
Binary files /dev/null and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1942_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/261_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/261_en
index ea4488fd..9a8b1130 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/261_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/261_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/372_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/372_en
deleted file mode 100644
index aaaa3388..00000000
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/372_en and /dev/null differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_en
index 32b5f398..f839f03d 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_uk b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_uk
index 6e8a6da3..220b72b9 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_uk and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/380_uk differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/51_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/51_en
index 7f84d3eb..3bedb6af 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/51_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/51_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/95_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/95_en
index 953ca978..049d4fe1 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/95_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/95_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/960_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/960_en
index eeece06b..4953cd1b 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/960_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/960_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config
index 37ebe58b..2f071797 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data
index 51deae9a..6e69f69b 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data and b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/internal/prefixmapper/pom.xml b/internal/prefixmapper/pom.xml
index ea0ac921..d4cfa0a2 100644
--- a/internal/prefixmapper/pom.xml
+++ b/internal/prefixmapper/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>prefixmapper</artifactId>
-  <version>2.239</version>
+  <version>2.245</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.45</version>
+    <version>8.13.51</version>
     <relativePath>../../pom.xml</relativePath>
   </parent>
 
@@ -75,7 +75,7 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.45</version>
+      <version>8.13.51</version>
     </dependency>
   </dependencies>
 
diff --git a/libphonenumber/pom.xml b/libphonenumber/pom.xml
index 1d795f0a..76f91093 100644
--- a/libphonenumber/pom.xml
+++ b/libphonenumber/pom.xml
@@ -3,14 +3,14 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber</artifactId>
-  <version>8.13.45</version>
+  <version>8.13.51</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.45</version>
+    <version>8.13.51</version>
   </parent>
 
   <build>
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_870
index 88811a54..45c6e6c5 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 96c51a32..6b9e1b97 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ
index 0c0ce52d..de4ca80b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL
index c526b117..dd7a0335 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA
index 63cb8320..f9eb1d80 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO
index b6620e90..e0800e7a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index be51fb2a..311b564a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE
index 46353126..dad2e528 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI
index 2ed02254..0a0c7a07 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE
index 894199b9..731ec6eb 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF
index 29517f04..70249b0c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP
index 90000a48..a4adefa5 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU
index 11ca7d80..366ed893 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index 055831c6..8689e496 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN
index 9d6485f3..64788dca 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR
index 11de9fc1..826f7a0e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF
index 860eebf4..31f7d0e8 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG
index ebf6d810..0cfbd651 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM
index f641a4a7..18252a2c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ
index 1b8f3992..e32597f7 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV
index 2c596fed..3e121e0a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO
index 04228695..b807aa3d 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA
index 2d929aa0..86ad315f 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE
index 57e1c024..c8fffa02 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL
index 2b67a8f4..2dce227b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM
index fa0ef997..ef99436c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE
index c609c279..f755038c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index 8076c004..5eeee4c3 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ
index 32d32547..a475b19a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 9e985017..4ebef4fe 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY
index f97556dd..a73cca47 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG
index 894d9b32..f7cb84e0 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index 69b68c9b..a233a31c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA
index 4e191668..72e05da7 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG
index 773f1eb1..e652952b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US
index 749325de..0e1c1170 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ
index d2c566b4..6ca9f7e7 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF
index 79c23086..1f75adec 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT
index f0434782..749d8675 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ
index 0eaebea7..cc5edf44 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI
index ee615e75..e50ad8f1 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_FI differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ
index 4635c055..f4965bc7 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO
index dd20c8dc..bbfcdd63 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_PM b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_PM
index 69812492..45a4de64 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_PM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_PM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ
index 87adfef1..14b46668 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_UY b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_UY
index cbae98bc..b7df6b37 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_UY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_UY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java b/libphonenumber/src/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
index 0d9adb5e..c8a3270a 100644
--- a/libphonenumber/src/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
+++ b/libphonenumber/src/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
@@ -16,7 +16,6 @@
 
 package com.google.i18n.phonenumbers.metadata.source;
 
-import java.util.regex.Pattern;
 
 /**
  * {@link PhoneMetadataFileNameProvider} implementation which appends key as a suffix to the
@@ -25,7 +24,6 @@ import java.util.regex.Pattern;
 public final class MultiFileModeFileNameProvider implements PhoneMetadataFileNameProvider {
 
   private final String phoneMetadataFileNamePrefix;
-  private static final Pattern ALPHANUMERIC = Pattern.compile("^[\\p{L}\\p{N}]+$");
 
   public MultiFileModeFileNameProvider(String phoneMetadataFileNameBase) {
     this.phoneMetadataFileNamePrefix = phoneMetadataFileNameBase + "_";
@@ -34,9 +32,27 @@ public final class MultiFileModeFileNameProvider implements PhoneMetadataFileNam
   @Override
   public String getFor(Object key) {
     String keyAsString = key.toString();
-    if (!ALPHANUMERIC.matcher(keyAsString).matches()) {
+    if (!isAlphanumeric(keyAsString)) {
       throw new IllegalArgumentException("Invalid key: " + keyAsString);
     }
     return phoneMetadataFileNamePrefix + key;
   }
+
+  private boolean isAlphanumeric(String key) {
+    if (key == null || key.length() == 0) {
+      return false;
+    }
+    // String#length doesn't actually return the number of
+    // code points in the String, it returns the number
+    // of char values.
+    int size = key.length();
+    for (int charIdx = 0; charIdx < size; ) {
+      final int codePoint = key.codePointAt(charIdx);
+      if (!Character.isLetterOrDigit(codePoint)) {
+        return false;
+      }
+      charIdx += Character.charCount(codePoint);
+    }
+    return true;
+  }
 }
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/CountryCodeToRegionCodeMapForTesting.java b/libphonenumber/test/com/google/i18n/phonenumbers/CountryCodeToRegionCodeMapForTesting.java
index a68d45fe..3a8c65c0 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/CountryCodeToRegionCodeMapForTesting.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/CountryCodeToRegionCodeMapForTesting.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2010 The Libphonenumber Authors
+ * Copyright (C) 2011 The Libphonenumber Authors
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
index a8bfec34..6bdef41a 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
@@ -415,7 +415,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     // We have data for the US, but no data for VOICEMAIL, so return null.
     assertNull(phoneUtil.getExampleNumberForType(RegionCode.US, PhoneNumberType.VOICEMAIL));
     // CS is an invalid region, so we have no data for it.
-    assertNull(phoneUtil.getExampleNumberForType(RegionCode.CS, PhoneNumberType.MOBILE));
+    assertNull(phoneUtil.getExampleNumberForType("CS", PhoneNumberType.MOBILE));
     // RegionCode 001 is reserved for supporting non-geographical country calling code. We don't
     // support getting an example number for it with this method.
     assertNull(phoneUtil.getExampleNumber(RegionCode.UN001));
@@ -425,7 +425,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     // RegionCode 001 is reserved for supporting non-geographical country calling codes. We don't
     // support getting an invalid example number for it with getInvalidExampleNumber.
     assertNull(phoneUtil.getInvalidExampleNumber(RegionCode.UN001));
-    assertNull(phoneUtil.getInvalidExampleNumber(RegionCode.CS));
+    assertNull(phoneUtil.getInvalidExampleNumber("CS"));
     PhoneNumber usInvalidNumber = phoneUtil.getInvalidExampleNumber(RegionCode.US);
     assertEquals(1, usInvalidNumber.getCountryCode());
     assertFalse(usInvalidNumber.getNationalNumber() == 0);
@@ -658,7 +658,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     // AQ/Antarctica isn't a valid region code for phone number formatting,
     // so this falls back to intl formatting.
     assertEquals("+1 650 253 0000",
-                 phoneUtil.formatOutOfCountryCallingNumber(US_NUMBER, RegionCode.AQ));
+                 phoneUtil.formatOutOfCountryCallingNumber(US_NUMBER, "AQ"));
     // For region code 001, the out-of-country format always turns into the international format.
     assertEquals("+1 650 253 0000",
                  phoneUtil.formatOutOfCountryCallingNumber(US_NUMBER, RegionCode.UN001));
@@ -735,7 +735,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
                  phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, RegionCode.SG));
     // Testing the case of calling from a non-supported region.
     assertEquals("+61 1-800-SIX-FLAG",
-                 phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, RegionCode.AQ));
+                 phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, "AQ"));
 
     // Testing the case with an invalid country calling code.
     alphaNumericNumber.setCountryCode(0).setNationalNumber(18007493524L)
@@ -754,7 +754,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     alphaNumericNumber.setCountryCode(1).setNationalNumber(80749L).setRawInput("180-SIX");
     // No country-code stripping can be done since the number is invalid.
     assertEquals("+1 180-SIX",
-                 phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, RegionCode.AQ));
+                 phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, "AQ"));
   }
 
   public void testFormatWithCarrierCode() {
@@ -820,12 +820,12 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     assertEquals("030123456",
         phoneUtil.formatNumberForMobileDialing(DE_NUMBER, RegionCode.DE, false));
     assertEquals("+4930123456",
-        phoneUtil.formatNumberForMobileDialing(DE_NUMBER, RegionCode.CH, false));
+        phoneUtil.formatNumberForMobileDialing(DE_NUMBER, "CH", false));
     PhoneNumber deNumberWithExtn = new PhoneNumber().mergeFrom(DE_NUMBER).setExtension("1234");
     assertEquals("030123456",
         phoneUtil.formatNumberForMobileDialing(deNumberWithExtn, RegionCode.DE, false));
     assertEquals("+4930123456",
-        phoneUtil.formatNumberForMobileDialing(deNumberWithExtn, RegionCode.CH, false));
+        phoneUtil.formatNumberForMobileDialing(deNumberWithExtn, "CH", false));
 
     // US toll free numbers are marked as noInternationalDialling in the test metadata for testing
     // purposes. For such numbers, we expect nothing to be returned when the region code is not the
@@ -1336,7 +1336,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     assertEquals(0, phoneUtil.getCountryCodeForRegion(RegionCode.ZZ));
     assertEquals(0, phoneUtil.getCountryCodeForRegion(RegionCode.UN001));
     // CS is already deprecated so the library doesn't support it.
-    assertEquals(0, phoneUtil.getCountryCodeForRegion(RegionCode.CS));
+    assertEquals(0, phoneUtil.getCountryCodeForRegion("CS"));
   }
 
   public void testGetNationalDiallingPrefixForRegion() {
@@ -1353,7 +1353,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     assertEquals(null, phoneUtil.getNddPrefixForRegion(RegionCode.ZZ, false));
     assertEquals(null, phoneUtil.getNddPrefixForRegion(RegionCode.UN001, false));
     // CS is already deprecated so the library doesn't support it.
-    assertEquals(null, phoneUtil.getNddPrefixForRegion(RegionCode.CS, false));
+    assertEquals(null, phoneUtil.getNddPrefixForRegion("CS", false));
   }
 
   public void testIsNANPACountry() {
@@ -2430,7 +2430,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     }
     try {
       String someNumber = "123 456 7890";
-      phoneUtil.parse(someNumber, RegionCode.CS);
+      phoneUtil.parse(someNumber, "CS");
       fail("Deprecated region code not allowed: should fail.");
     } catch (NumberParseException e) {
       // Expected this exception.
@@ -2854,7 +2854,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
 
     // Invalid region code supplied.
     try {
-      phoneUtil.parseAndKeepRawInput("123 456 7890", RegionCode.CS);
+      phoneUtil.parseAndKeepRawInput("123 456 7890", "CS");
       fail("Deprecated region code not allowed: should fail.");
     } catch (NumberParseException e) {
       // Expected this exception.
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/RegionCode.java b/libphonenumber/test/com/google/i18n/phonenumbers/RegionCode.java
index 20fc1212..acd55ba0 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/RegionCode.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/RegionCode.java
@@ -14,6 +14,10 @@
  * limitations under the License.
  */
 
+/* This file is automatically generated by {@link BuildMetadataProtoFromXml}.
+ * Please don't modify it directly.
+ */
+
 package com.google.i18n.phonenumbers;
 
 /**
@@ -26,7 +30,6 @@ final class RegionCode {
   static final String AE = "AE";
   static final String AM = "AM";
   static final String AO = "AO";
-  static final String AQ = "AQ";
   static final String AR = "AR";
   static final String AU = "AU";
   static final String BB = "BB";
@@ -34,31 +37,28 @@ final class RegionCode {
   static final String BS = "BS";
   static final String BY = "BY";
   static final String CA = "CA";
-  static final String CH = "CH";
-  static final String CL = "CL";
+  static final String CC = "CC";
   static final String CN = "CN";
   static final String CO = "CO";
-  static final String CS = "CS";
   static final String CX = "CX";
   static final String DE = "DE";
   static final String FR = "FR";
   static final String GB = "GB";
-  static final String HU = "HU";
+  static final String GG = "GG";
   static final String IT = "IT";
   static final String JP = "JP";
   static final String KR = "KR";
   static final String MX = "MX";
   static final String NZ = "NZ";
-  static final String PG = "PG";
   static final String PL = "PL";
   static final String RE = "RE";
   static final String RU = "RU";
   static final String SE = "SE";
   static final String SG = "SG";
+  static final String TA = "TA";
   static final String US = "US";
   static final String UZ = "UZ";
   static final String YT = "YT";
-  static final String ZW = "ZW";
   // Official code for the unknown region.
   static final String ZZ = "ZZ";
 }
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/ShortNumberInfoTest.java b/libphonenumber/test/com/google/i18n/phonenumbers/ShortNumberInfoTest.java
index b83a680c..b08f82e1 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/ShortNumberInfoTest.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/ShortNumberInfoTest.java
@@ -241,14 +241,14 @@ public class ShortNumberInfoTest extends TestMetadataTestCase {
   }
 
   public void testConnectsToEmergencyNumber_CL() {
-    assertTrue(shortInfo.connectsToEmergencyNumber("131", RegionCode.CL));
-    assertTrue(shortInfo.connectsToEmergencyNumber("133", RegionCode.CL));
+    assertTrue(shortInfo.connectsToEmergencyNumber("131", "CL"));
+    assertTrue(shortInfo.connectsToEmergencyNumber("133", "CL"));
   }
 
   public void testConnectsToEmergencyNumberLongNumber_CL() {
     // Chilean emergency numbers don't work when additional digits are appended.
-    assertFalse(shortInfo.connectsToEmergencyNumber("1313", RegionCode.CL));
-    assertFalse(shortInfo.connectsToEmergencyNumber("1330", RegionCode.CL));
+    assertFalse(shortInfo.connectsToEmergencyNumber("1313", "CL"));
+    assertFalse(shortInfo.connectsToEmergencyNumber("1330", "CL"));
   }
 
   public void testConnectsToEmergencyNumber_AO() {
@@ -260,9 +260,9 @@ public class ShortNumberInfoTest extends TestMetadataTestCase {
 
   public void testConnectsToEmergencyNumber_ZW() {
     // Zimbabwe doesn't have any metadata in the test metadata.
-    assertFalse(shortInfo.connectsToEmergencyNumber("911", RegionCode.ZW));
-    assertFalse(shortInfo.connectsToEmergencyNumber("01312345", RegionCode.ZW));
-    assertFalse(shortInfo.connectsToEmergencyNumber("0711234567", RegionCode.ZW));
+    assertFalse(shortInfo.connectsToEmergencyNumber("911", "ZW"));
+    assertFalse(shortInfo.connectsToEmergencyNumber("01312345", "ZW"));
+    assertFalse(shortInfo.connectsToEmergencyNumber("0711234567", "ZW"));
   }
 
   public void testIsEmergencyNumber_US() {
@@ -315,9 +315,9 @@ public class ShortNumberInfoTest extends TestMetadataTestCase {
 
   public void testIsEmergencyNumber_ZW() {
     // Zimbabwe doesn't have any metadata in the test metadata.
-    assertFalse(shortInfo.isEmergencyNumber("911", RegionCode.ZW));
-    assertFalse(shortInfo.isEmergencyNumber("01312345", RegionCode.ZW));
-    assertFalse(shortInfo.isEmergencyNumber("0711234567", RegionCode.ZW));
+    assertFalse(shortInfo.isEmergencyNumber("911", "ZW"));
+    assertFalse(shortInfo.isEmergencyNumber("01312345", "ZW"));
+    assertFalse(shortInfo.isEmergencyNumber("0711234567", "ZW"));
   }
 
   public void testEmergencyNumberForSharedCountryCallingCode() {
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProviderTest.java b/libphonenumber/test/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProviderTest.java
index c7ad7ddc..f3fb03af 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProviderTest.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProviderTest.java
@@ -42,4 +42,15 @@ public final class MultiFileModeFileNameProviderTest extends TestCase {
           }
         });
   }
+
+  public void getFor_shouldThrowExceptionForEmptyKey() {
+    assertThrows(
+        IllegalArgumentException.class,
+        new ThrowingRunnable() {
+          @Override
+          public void run() {
+            metadataFileNameProvider.getFor("");
+          }
+        });
+  }
 }
diff --git a/pom.xml b/pom.xml
index 981dca76..f2492c6e 100644
--- a/pom.xml
+++ b/pom.xml
@@ -3,7 +3,7 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber-parent</artifactId>
-  <version>8.13.45</version>
+  <version>8.13.51</version>
   <packaging>pom</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
@@ -34,7 +34,7 @@
     <connection>scm:git:https://github.com/google/libphonenumber.git</connection>
     <developerConnection>scm:git:git@github.com:googlei18n/libphonenumber.git</developerConnection>
     <url>https://github.com/google/libphonenumber/</url>
-    <tag>v8.13.45</tag>
+    <tag>v8.13.51</tag>
   </scm>
 
   <properties>
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1327_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1327_en
new file mode 100644
index 00000000..e63e5ea3
Binary files /dev/null and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1327_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1942_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1942_en
new file mode 100644
index 00000000..7e9c88e6
Binary files /dev/null and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1942_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/261_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/261_en
index ea4488fd..9a8b1130 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/261_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/261_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/372_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/372_en
deleted file mode 100644
index aaaa3388..00000000
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/372_en and /dev/null differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_en
index 32b5f398..f839f03d 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_uk b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_uk
index 6e8a6da3..220b72b9 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_uk and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/380_uk differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/51_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/51_en
index 7f84d3eb..3bedb6af 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/51_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/51_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/95_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/95_en
index 953ca978..049d4fe1 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/95_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/95_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/960_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/960_en
index eeece06b..4953cd1b 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/960_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/960_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config
index 37ebe58b..2f071797 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data
index 51deae9a..6e69f69b 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_870
index 88811a54..45c6e6c5 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_870 differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 96c51a32..6b9e1b97 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ
index 0c0ce52d..de4ca80b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL
index c526b117..dd7a0335 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA
index 63cb8320..f9eb1d80 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO
index b6620e90..e0800e7a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index be51fb2a..311b564a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE
index 46353126..dad2e528 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI
index 2ed02254..0a0c7a07 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_FI differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE
index 894199b9..731ec6eb 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF
index 29517f04..70249b0c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP
index 90000a48..a4adefa5 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU
index 11ca7d80..366ed893 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GU differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index 055831c6..8689e496 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN
index 9d6485f3..64788dca 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR
index 11de9fc1..826f7a0e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF
index 860eebf4..31f7d0e8 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG
index ebf6d810..0cfbd651 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM
index f641a4a7..18252a2c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ
index 1b8f3992..e32597f7 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MQ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV
index 2c596fed..3e121e0a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MV differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO
index 04228695..b807aa3d 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA
index 2d929aa0..86ad315f 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE
index 57e1c024..c8fffa02 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL
index 2b67a8f4..2dce227b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM
index fa0ef997..ef99436c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE
index c609c279..f755038c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index 8076c004..5eeee4c3 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ
index 32d32547..a475b19a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 9e985017..4ebef4fe 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY
index f97556dd..a73cca47 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG
index 894d9b32..f7cb84e0 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index 69b68c9b..a233a31c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA
index 4e191668..72e05da7 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG
index 773f1eb1..e652952b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US
index 749325de..0e1c1170 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ
index d2c566b4..6ca9f7e7 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF
index 79c23086..1f75adec 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_WF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT
index f0434782..749d8675 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_YT differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ
index 0eaebea7..cc5edf44 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_BJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI
index ee615e75..e50ad8f1 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_FI differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ
index 4635c055..f4965bc7 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_MQ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO
index dd20c8dc..bbfcdd63 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_PM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_PM
index 69812492..45a4de64 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_PM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_PM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ
index 87adfef1..14b46668 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_SJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_UY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_UY
index cbae98bc..b7df6b37 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_UY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_UY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
index b8ee7c91..f31e0323 100644
--- a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
+++ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/metadata/source/MultiFileModeFileNameProvider.java
@@ -17,7 +17,6 @@
 
 package com.android.i18n.phonenumbers.metadata.source;
 
-import java.util.regex.Pattern;
 
 /**
  * {@link PhoneMetadataFileNameProvider} implementation which appends key as a suffix to the
@@ -27,7 +26,6 @@ import java.util.regex.Pattern;
 public final class MultiFileModeFileNameProvider implements PhoneMetadataFileNameProvider {
 
   private final String phoneMetadataFileNamePrefix;
-  private static final Pattern ALPHANUMERIC = Pattern.compile("^[\\p{L}\\p{N}]+$");
 
   public MultiFileModeFileNameProvider(String phoneMetadataFileNameBase) {
     this.phoneMetadataFileNamePrefix = phoneMetadataFileNameBase + "_";
@@ -36,9 +34,27 @@ public final class MultiFileModeFileNameProvider implements PhoneMetadataFileNam
   @Override
   public String getFor(Object key) {
     String keyAsString = key.toString();
-    if (!ALPHANUMERIC.matcher(keyAsString).matches()) {
+    if (!isAlphanumeric(keyAsString)) {
       throw new IllegalArgumentException("Invalid key: " + keyAsString);
     }
     return phoneMetadataFileNamePrefix + key;
   }
+
+  private boolean isAlphanumeric(String key) {
+    if (key == null || key.length() == 0) {
+      return false;
+    }
+    // String#length doesn't actually return the number of
+    // code points in the String, it returns the number
+    // of char values.
+    int size = key.length();
+    for (int charIdx = 0; charIdx < size; ) {
+      final int codePoint = key.codePointAt(charIdx);
+      if (!Character.isLetterOrDigit(codePoint)) {
+        return false;
+      }
+      charIdx += Character.charCount(codePoint);
+    }
+    return true;
+  }
 }
```

