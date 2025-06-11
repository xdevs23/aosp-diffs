```diff
diff --git a/METADATA b/METADATA
index 3274c5f2..2adc5b52 100644
--- a/METADATA
+++ b/METADATA
@@ -9,11 +9,11 @@ third_party {
     type: ARCHIVE
     value: "https://github.com/google/libphonenumber/archive/refs/tags/v8.13.16.tar.gz"
   }
-  version: "v8.13.16"
+  version: "9.0.0"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 7
-    day: 11
+    year: 2025
+    month: 03
+    day: 04
   }
 }
diff --git a/OWNERS b/OWNERS
index b9902397..f9919da5 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@
 # Please update this list if you find better candidates.
 sarahchin@google.com
 tgunn@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.version b/README.version
index bac5648c..4ee09c2d 100644
--- a/README.version
+++ b/README.version
@@ -1,3 +1,3 @@
 URL: https://github.com/googlei18n/libphonenumber/
-Version: 8.13.51
+Version: 9.0.0
 BugComponent: 20868
diff --git a/carrier/pom.xml b/carrier/pom.xml
index 54fc9f6d..f6a6c8c8 100644
--- a/carrier/pom.xml
+++ b/carrier/pom.xml
@@ -1,16 +1,15 @@
 <?xml version="1.0"?>
 <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <modelVersion>4.0.0</modelVersion>
-  <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>carrier</artifactId>
-  <version>1.235</version>
+  <version>2.0</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.51</version>
+    <version>9.0.0</version>
   </parent>
 
   <build>
@@ -24,8 +23,10 @@
     </resources>
     <testResources>
       <testResource>
-        <directory>test/com/google/i18n/phonenumbers/carrier/testing_data</directory>
-        <targetPath>com/google/i18n/phonenumbers/carrier/testing_data</targetPath>
+        <directory>test/com/google/i18n/phonenumbers/carrier/testing_data
+        </directory>
+        <targetPath>com/google/i18n/phonenumbers/carrier/testing_data
+        </targetPath>
       </testResource>
     </testResources>
     <plugins>
@@ -35,24 +36,25 @@
         <version>5.1.9</version>
         <configuration>
           <instructions>
-          	<Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
+            <Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
           </instructions>
         </configuration>
       </plugin>
       <plugin>
         <artifactId>maven-jar-plugin</artifactId>
-        <version>3.3.0</version>
         <executions>
           <execution>
             <id>default-jar</id>
             <configuration>
               <archive>
-                <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                <manifestFile>
+                  ${project.build.outputDirectory}/META-INF/MANIFEST.MF
+                </manifestFile>
               </archive>
             </configuration>
           </execution>
-		</executions>
-	  </plugin>
+        </executions>
+      </plugin>
       <plugin>
         <groupId>org.codehaus.mojo</groupId>
         <artifactId>animal-sniffer-maven-plugin</artifactId>
@@ -79,12 +81,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.51</version>
+      <version>9.0.0</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.245</version>
+      <version>3.0</version>
     </dependency>
   </dependencies>
 
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/212_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/212_en
index b173e5d7..74ee9700 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/212_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/212_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en
index b82ba94a..ebde3cd1 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/221_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/223_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/223_en
index f8217c8f..705230d8 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/223_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/223_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en
index 85f95a78..d719a4c3 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/229_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/252_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/252_en
index 8b5fb834..252fad78 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/252_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/252_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/255_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/255_en
index 06fd1718..f494b662 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/255_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/255_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en
index f323c6fd..22a8977a 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/256_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/268_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/268_en
index 9acfa852..5c96722a 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/268_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/268_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en
index aae78632..0d074e3a 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/33_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en
index ccdf13b0..85e2dc60 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/351_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/371_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/371_en
index 50125ca1..83b90a40 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/371_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/371_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/389_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/389_en
index 8c771513..3e32409d 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/389_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/389_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en
index 0bd61f8f..2df6c400 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/41_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/45_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/45_en
index 34184fff..b0e58db8 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/45_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/45_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en
index b452b489..0065bd96 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/48_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/503_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/503_en
index 8b9b6636..b346f29d 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/503_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/503_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/51_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/51_en
index 6c14e640..71773fde 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/51_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/51_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/58_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/58_en
index e08335a8..6253b44d 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/58_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/58_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en
index 179e1561..368eea88 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/592_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/597_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/597_en
index 21ccd71c..460725f3 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/597_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/597_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en
index 1886f222..c3d21d45 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/65_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/680_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/680_en
index adb64379..6ba563be 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/680_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/680_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en
index 6535d4b6..7f3e19f1 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh
index 3e93c9a1..cdc539c3 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/852_zh differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/90_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/90_en
index 586d7388..0f0752bc 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/90_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/90_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/92_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/92_en
index edc99eea..48810499 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/92_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/92_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en
index 90fb6bca..d218d600 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/972_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/976_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/976_en
index a5719fbf..2d657db2 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/976_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/976_en differ
diff --git a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en
index 7098642d..259ba826 100644
Binary files a/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en and b/carrier/src/com/google/i18n/phonenumbers/carrier/data/992_en differ
diff --git a/demo/pom.xml b/demo/pom.xml
index 78c4652c..e7f756a1 100644
--- a/demo/pom.xml
+++ b/demo/pom.xml
@@ -3,21 +3,21 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>demo</artifactId>
-  <version>8.13.51</version>
+  <version>9.0.0</version>
   <packaging>war</packaging>
   <url>https://github.com/google/libphonenumber/</url>
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.51</version>
+    <version>9.0.0</version>
   </parent>
 
   <properties>
     <app.deploy.project>libphonenumber-hrd</app.deploy.project>
     <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
     <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
-    <maven.compiler.source>11</maven.compiler.source>
-    <maven.compiler.target>11</maven.compiler.target>
+    <maven.compiler.source>17</maven.compiler.source>
+    <maven.compiler.target>17</maven.compiler.target>
     <maven.compiler.showDeprecation>true</maven.compiler.showDeprecation>
     <archiveClasses>true</archiveClasses>
     <soy.root>${project.basedir}/src/main/resources/com/google/phonenumbers/demo</soy.root>
@@ -68,17 +68,17 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.51</version>
+      <version>9.0.0</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>geocoder</artifactId>
-      <version>2.245</version>
+      <version>3.0</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>carrier</artifactId>
-      <version>1.235</version>
+      <version>2.0</version>
     </dependency>
   </dependencies>
 
diff --git a/demo/src/main/resources/com/google/phonenumbers/demo/result.soy b/demo/src/main/resources/com/google/phonenumbers/demo/result.soy
index e3107109..baaa9d41 100644
--- a/demo/src/main/resources/com/google/phonenumbers/demo/result.soy
+++ b/demo/src/main/resources/com/google/phonenumbers/demo/result.soy
@@ -101,44 +101,42 @@
       <TH>Result from isPossibleNumber()</TH>
       <TD>{$isPossibleNumber}</TD>
     </TR>
-{if $isPossibleNumber}
-  {if $validationResult == "IS_POSSIBLE_LOCAL_ONLY"}
     <TR>
       <TH>Result from isPossibleNumberWithReason()</TH>
       <TD>{$validationResult}</TD>
     </TR>
-    <TR>
-      <TD colspan=2>Number is considered invalid as it is not a possible national number.</TD>
-    </TR>
-  {else}
     <TR>
       <TH>Result from isValidNumber()</TH>
       <TD>{$isValidNumber}</TD>
     </TR>
+    {if $isValidNumber}
+     {if $validationResult != "IS_POSSIBLE"}
+      <TR>
+        <TD colspan=2 style="color:red">
+          Warning: This number represents a known <a href="https://issuetracker.google.com/issues/335892662">
+          edge case</a> - it is a valid number, but it is not considered (strictly) possible
+        </TD>
+      </TR>
+    {/if}
     {if $isValidNumberForRegion != null}
-    <TR>
-      <TH>Result from isValidNumberForRegion()</TH>
-      <TD>{$isValidNumberForRegion}</TD>
-    </TR>
+      <TR>
+        <TH>Result from isValidNumberForRegion()</TH>
+        <TD>{$isValidNumberForRegion}</TD>
+      </TR>
     {/if}
     <TR>
       <TH>Phone Number region</TH>
-      <TD>{$phoneNumberRegion ?: ""}</TD>
+      <TD>{$phoneNumberRegion}</TD>
     </TR>
     <TR>
       <TH>Result from getNumberType()</TH>
       <TD>{$numberType}</TD>
     </TR>
-  {/if}
-{else}
-    <TR>
-      <TH>Result from isPossibleNumberWithReason()</TH>
-      <TD>{$validationResult}</TD>
-    </TR>
-    <TR>
-      <TD colspan=2>Note: Numbers that are not possible have type UNKNOWN, an unknown region, and are considered invalid.</TD>
-    </TR>
-{/if}
+    {else}
+     <TR>
+       <TD colspan=2>Note: Invalid numbers have type UNKNOWN and no region.</TD>
+     </TR>
+     {/if}
   </TABLE>
 </DIV>
 
diff --git a/demo/src/main/webapp/WEB-INF/appengine-web.xml b/demo/src/main/webapp/WEB-INF/appengine-web.xml
index 5a7e622c..840614b0 100644
--- a/demo/src/main/webapp/WEB-INF/appengine-web.xml
+++ b/demo/src/main/webapp/WEB-INF/appengine-web.xml
@@ -2,7 +2,7 @@
 <appengine-web-app xmlns="http://appengine.google.com/ns/1.0">
   <application>libphonenumber-hrd</application>
   <version>1</version>
-  <runtime>java11</runtime>
+  <runtime>java17</runtime>
   <threadsafe>true</threadsafe>
 
   <!-- Configure java.util.logging -->
diff --git a/geocoder/pom.xml b/geocoder/pom.xml
index 5b483b0b..e6a25815 100644
--- a/geocoder/pom.xml
+++ b/geocoder/pom.xml
@@ -1,16 +1,15 @@
 <?xml version="1.0"?>
 <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <modelVersion>4.0.0</modelVersion>
-  <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>geocoder</artifactId>
-  <version>2.245</version>
+  <version>3.0</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.51</version>
+    <version>9.0.0</version>
   </parent>
 
   <build>
@@ -28,12 +27,16 @@
     </resources>
     <testResources>
       <testResource>
-        <directory>test/com/google/i18n/phonenumbers/geocoding/testing_data</directory>
-        <targetPath>com/google/i18n/phonenumbers/geocoding/testing_data</targetPath>
+        <directory>test/com/google/i18n/phonenumbers/geocoding/testing_data
+        </directory>
+        <targetPath>com/google/i18n/phonenumbers/geocoding/testing_data
+        </targetPath>
       </testResource>
       <testResource>
-        <directory>test/com/google/i18n/phonenumbers/timezones/testing_data</directory>
-        <targetPath>com/google/i18n/phonenumbers/timezones/testing_data</targetPath>
+        <directory>test/com/google/i18n/phonenumbers/timezones/testing_data
+        </directory>
+        <targetPath>com/google/i18n/phonenumbers/timezones/testing_data
+        </targetPath>
       </testResource>
     </testResources>
     <plugins>
@@ -43,24 +46,25 @@
         <version>5.1.9</version>
         <configuration>
           <instructions>
-          	<Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
+            <Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
           </instructions>
         </configuration>
       </plugin>
       <plugin>
         <artifactId>maven-jar-plugin</artifactId>
-        <version>3.3.0</version>
         <executions>
           <execution>
             <id>default-jar</id>
             <configuration>
               <archive>
-                <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                <manifestFile>
+                  ${project.build.outputDirectory}/META-INF/MANIFEST.MF
+                </manifestFile>
               </archive>
             </configuration>
           </execution>
-		</executions>
-	  </plugin>
+        </executions>
+      </plugin>
       <plugin>
         <groupId>org.codehaus.mojo</groupId>
         <artifactId>animal-sniffer-maven-plugin</artifactId>
@@ -87,12 +91,12 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.51</version>
+      <version>9.0.0</version>
     </dependency>
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>prefixmapper</artifactId>
-      <version>2.245</version>
+      <version>3.0</version>
     </dependency>
   </dependencies>
 
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1274_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1274_en
new file mode 100644
index 00000000..506e71d3
Binary files /dev/null and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1274_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1345_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1345_en
index bd11fc2e..fb73f3eb 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1345_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/1345_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/27_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/27_en
index 4f13f91d..04e749fe 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/27_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/27_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en
index a42f4fb8..48ea7c2d 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_en differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh
index 80b79b00..2ab9c681 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/86_zh differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config
index 2f071797..7bf0232b 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config and b/geocoder/src/com/google/i18n/phonenumbers/geocoding/data/config differ
diff --git a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data
index 6e69f69b..feecbd05 100644
Binary files a/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data and b/geocoder/src/com/google/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/internal/prefixmapper/pom.xml b/internal/prefixmapper/pom.xml
index d4cfa0a2..40b9fc1f 100644
--- a/internal/prefixmapper/pom.xml
+++ b/internal/prefixmapper/pom.xml
@@ -1,16 +1,15 @@
 <?xml version="1.0"?>
 <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <modelVersion>4.0.0</modelVersion>
-  <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>prefixmapper</artifactId>
-  <version>2.245</version>
+  <version>3.0</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.51</version>
+    <version>9.0.0</version>
     <relativePath>../../pom.xml</relativePath>
   </parent>
 
@@ -19,8 +18,11 @@
     <testSourceDirectory>test</testSourceDirectory>
     <testResources>
       <testResource>
-        <directory>../../geocoder/test/com/google/i18n/phonenumbers/geocoding/testing_data</directory>
-        <targetPath>com/google/i18n/phonenumbers/geocoding/testing_data</targetPath>
+        <directory>
+          ../../geocoder/test/com/google/i18n/phonenumbers/geocoding/testing_data
+        </directory>
+        <targetPath>com/google/i18n/phonenumbers/geocoding/testing_data
+        </targetPath>
       </testResource>
     </testResources>
     <plugins>
@@ -30,24 +32,30 @@
         <version>5.1.9</version>
         <configuration>
           <instructions>
-          	<Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
+            <Fragment-Host>com.googlecode.libphonenumber</Fragment-Host>
           </instructions>
         </configuration>
       </plugin>
       <plugin>
         <artifactId>maven-jar-plugin</artifactId>
-        <version>3.3.0</version>
         <executions>
           <execution>
             <id>default-jar</id>
             <configuration>
               <archive>
-                <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                <manifestFile>
+                  ${project.build.outputDirectory}/META-INF/MANIFEST.MF
+                </manifestFile>
+                <manifestEntries>
+                  <Automatic-Module-Name>
+                    com.google.i18n.phonenumbers.prefixmapper
+                  </Automatic-Module-Name>
+                </manifestEntries>
               </archive>
             </configuration>
           </execution>
-		</executions>
-	  </plugin>
+        </executions>
+      </plugin>
 
       <plugin>
         <groupId>org.codehaus.mojo</groupId>
@@ -75,7 +83,7 @@
     <dependency>
       <groupId>com.googlecode.libphonenumber</groupId>
       <artifactId>libphonenumber</artifactId>
-      <version>8.13.51</version>
+      <version>9.0.0</version>
     </dependency>
   </dependencies>
 
diff --git a/libphonenumber/pom.xml b/libphonenumber/pom.xml
index 76f91093..80823a29 100644
--- a/libphonenumber/pom.xml
+++ b/libphonenumber/pom.xml
@@ -1,16 +1,15 @@
 <?xml version="1.0"?>
 <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <modelVersion>4.0.0</modelVersion>
-  <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber</artifactId>
-  <version>8.13.51</version>
+  <version>9.0.0</version>
   <packaging>jar</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
   <parent>
     <groupId>com.googlecode.libphonenumber</groupId>
     <artifactId>libphonenumber-parent</artifactId>
-    <version>8.13.51</version>
+    <version>9.0.0</version>
   </parent>
 
   <build>
@@ -35,20 +34,26 @@
         <version>5.1.9</version>
         <configuration>
           <instructions>
-          	<Eclipse-ExtensibleAPI>true</Eclipse-ExtensibleAPI>
+            <Eclipse-ExtensibleAPI>true</Eclipse-ExtensibleAPI>
             <Export-Package>com.google.i18n.phonenumbers</Export-Package>
           </instructions>
         </configuration>
       </plugin>
       <plugin>
         <artifactId>maven-jar-plugin</artifactId>
-        <version>3.3.0</version>
         <executions>
           <execution>
             <id>default-jar</id>
             <configuration>
               <archive>
-                <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                <manifestFile>
+                  ${project.build.outputDirectory}/META-INF/MANIFEST.MF
+                </manifestFile>
+                <manifestEntries>
+                  <Automatic-Module-Name>
+                    com.google.i18n.phonenumbers.libphonenumber
+                  </Automatic-Module-Name>
+                </manifestEntries>
               </archive>
             </configuration>
           </execution>
@@ -61,7 +66,14 @@
             <configuration>
               <classifier>no-metadata</classifier>
               <archive>
-                <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                <manifestFile>
+                  ${project.build.outputDirectory}/META-INF/MANIFEST.MF
+                </manifestFile>
+                <manifestEntries>
+                  <Automatic-Module-Name>
+                    com.google.i18n.phonenumbers.libphonenumber
+                  </Automatic-Module-Name>
+                </manifestEntries>
               </archive>
               <excludes>
                 <exclude>com/google/i18n/phonenumbers/data/*</exclude>
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java b/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
index fb85fc13..6d8004f1 100644
--- a/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
+++ b/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java
@@ -132,7 +132,7 @@ public class PhoneNumberUtil {
 
     HashSet<Integer> countriesWithoutNationalPrefixWithAreaCodes = new HashSet<>();
     countriesWithoutNationalPrefixWithAreaCodes.add(52);  // Mexico
-    COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES =
+    COUNTRIES_WITHOUT_NATIONAL_PREFIX_WITH_AREA_CODES = 
     		Collections.unmodifiableSet(countriesWithoutNationalPrefixWithAreaCodes);
 
     HashSet<Integer> geoMobileCountries = new HashSet<>();
@@ -1878,8 +1878,11 @@ public class PhoneNumberUtil {
     String regionCode = getRegionCodeForCountryCode(countryCode);
     // Metadata cannot be null because the country calling code is valid.
     PhoneMetadata metadataForRegion = getMetadataForRegionOrCallingCode(countryCode, regionCode);
-    maybeAppendFormattedExtension(number, metadataForRegion,
-                                  PhoneNumberFormat.INTERNATIONAL, formattedNumber);
+    // Strip any extension
+    maybeStripExtension(formattedNumber);
+    // Append the formatted extension
+    maybeAppendFormattedExtension(
+        number, metadataForRegion, PhoneNumberFormat.INTERNATIONAL, formattedNumber);
     if (internationalPrefixForFormatting.length() > 0) {
       formattedNumber.insert(0, " ").insert(0, countryCode).insert(0, " ")
           .insert(0, internationalPrefixForFormatting);
@@ -2705,6 +2708,13 @@ public class PhoneNumberUtil {
    *        length (obviously includes the length of area codes for fixed line numbers), it will
    *        return false for the subscriber-number-only version.
    * </ol>
+   *
+   * <p>There is a known <a href="https://issuetracker.google.com/issues/335892662">issue</a> with this
+   * method: if a number is possible only in a certain region among several regions that share the
+   * same country calling code, this method will consider only the "main" region. For example,
+   * +1310xxxx are valid numbers in Canada. However, they are not possible in the US. As a result,
+   * this method will return IS_POSSIBLE_LOCAL_ONLY for +1310xxxx.
+   *
    * @param number  the number that needs to be checked
    * @return  a ValidationResult object which indicates whether the number is possible
    */
@@ -2734,6 +2744,12 @@ public class PhoneNumberUtil {
    *        return false for the subscriber-number-only version.
    * </ol>
    *
+   * <p>There is a known <a href="https://issuetracker.google.com/issues/335892662">issue</a> with this
+   * method: if a number is possible only in a certain region among several regions that share the
+   * same country calling code, this method will consider only the "main" region. For example,
+   * +1310xxxx are valid numbers in Canada. However, they are not possible in the US. As a result,
+   * this method will return IS_POSSIBLE_LOCAL_ONLY for +1310xxxx.
+   *
    * @param number  the number that needs to be checked
    * @param type  the type we are interested in
    * @return  a ValidationResult object which indicates whether the number is possible
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385
index 4460dc38..16155832 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 6b9e1b97..16a904e8 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE
index 688f0edd..d7bcbb98 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL
index dd7a0335..fe5fbd02 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA
index f9eb1d80..11377bd0 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ
index c571a37a..1b05f7bc 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index 311b564a..7c4587b9 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK
index 12e00d6e..b2af72b6 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH
index 12b7b456..c41ae3d1 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF
index 70249b0c..1d25a82b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP
index a4adefa5..a1167b64 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY
index 66e2a80e..68f578db 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index 8689e496..e01b5d4a 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL
index d588ee97..08d38b9c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY
index ec90682d..83f0907f 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV
index d870a902..66312168 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA
index 0aa3a540..8fa04333 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF
index 31f7d0e8..71b78cec 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK
index 2962a523..12b2210e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML
index f29019b7..3fcae753 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM
index 18252a2c..8fb67ba7 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN
index f0495fc4..0ecbc977 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU
index d650f761..5a117233 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC
index afaaa519..ce011214 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL
index 2dce227b..81cb8f49 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW
index 0dc5a303..3783c6a8 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE
index f755038c..59beac28 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index 5eeee4c3..53525170 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL
index a27ce044..9fb64332 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 4ebef4fe..e9f77e3d 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO
index 543b1fb0..c4a80bde 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR
index d9f7ed7d..54f40263 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index a233a31c..264add0e 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG
index e652952b..a32febd9 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US
index 0e1c1170..bcbffc14 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_US differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ
index 6ca9f7e7..e2d5881c 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE
index 3c4ad741..bdfb7d7b 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA
index 340306dc..d15576a1 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA and b/libphonenumber/src/com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DK b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DK
index b3875151..b6e571ba 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DK and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_DK differ
diff --git a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO
index bbfcdd63..7f073133 100644
Binary files a/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO and b/libphonenumber/src/com/google/i18n/phonenumbers/data/ShortNumberMetadataProto_NO differ
diff --git a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
index 6bdef41a..2b9345c4 100644
--- a/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
+++ b/libphonenumber/test/com/google/i18n/phonenumbers/PhoneNumberUtilTest.java
@@ -675,7 +675,7 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
                  phoneUtil.formatOutOfCountryCallingNumber(IT_NUMBER, RegionCode.UZ));
   }
 
-  public void testFormatOutOfCountryKeepingAlphaChars() {
+  public void testFormatOutOfCountryKeepingAlphaChars() throws Exception {
     PhoneNumber alphaNumericNumber = new PhoneNumber();
     alphaNumericNumber.setCountryCode(1).setNationalNumber(8007493524L)
         .setRawInput("1800 six-flag");
@@ -701,6 +701,13 @@ public class PhoneNumberUtilTest extends TestMetadataTestCase {
     assertEquals("1 800 SIX-FLAG",
                  phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumber, RegionCode.BS));
 
+    // Testing a number with extension.
+    PhoneNumber alphaNumericNumberWithExtn =
+        phoneUtil.parseAndKeepRawInput("800 SIX-flag ext. 1234", RegionCode.US);
+    assertEquals(
+        "0011 1 800 SIX-FLAG extn. 1234",
+        phoneUtil.formatOutOfCountryKeepingAlphaChars(alphaNumericNumberWithExtn, RegionCode.AU));
+
     // Testing that if the raw input doesn't exist, it is formatted using
     // formatOutOfCountryCallingNumber.
     alphaNumericNumber.clearRawInput();
diff --git a/pom.xml b/pom.xml
index f2492c6e..1b7a91d2 100644
--- a/pom.xml
+++ b/pom.xml
@@ -3,7 +3,7 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.googlecode.libphonenumber</groupId>
   <artifactId>libphonenumber-parent</artifactId>
-  <version>8.13.51</version>
+  <version>9.0.0</version>
   <packaging>pom</packaging>
   <url>https://github.com/google/libphonenumber/</url>
 
@@ -14,7 +14,8 @@
   </parent>
 
   <description>
-    Google's common Java library for parsing, formatting, storing and validating international phone numbers.
+    Google's common Java library for parsing, formatting, storing and validating
+    international phone numbers.
     Optimized for running on smartphones.
   </description>
 
@@ -31,10 +32,12 @@
   </licenses>
 
   <scm>
-    <connection>scm:git:https://github.com/google/libphonenumber.git</connection>
-    <developerConnection>scm:git:git@github.com:googlei18n/libphonenumber.git</developerConnection>
+    <connection>scm:git:https://github.com/google/libphonenumber.git
+    </connection>
+    <developerConnection>scm:git:git@github.com:googlei18n/libphonenumber.git
+    </developerConnection>
     <url>https://github.com/google/libphonenumber/</url>
-    <tag>v8.13.51</tag>
+    <tag>v9.0.0</tag>
   </scm>
 
   <properties>
@@ -106,7 +109,10 @@
         <plugin>
           <groupId>org.codehaus.mojo</groupId>
           <artifactId>animal-sniffer-maven-plugin</artifactId>
-          <version>1.15</version>
+        </plugin>
+        <plugin>
+          <artifactId>maven-jar-plugin</artifactId>
+          <version>3.3.0</version>
         </plugin>
       </plugins>
     </pluginManagement>
@@ -161,21 +167,21 @@
         <artifactId>maven-compiler-plugin</artifactId>
         <version>3.11.0</version>
         <configuration>
-          <source>1.7</source>
-	  <target>1.7</target>
-	  <encoding>UTF-8</encoding>
+          <source>8</source>
+          <target>8</target>
+          <encoding>UTF-8</encoding>
         </configuration>
       </plugin>
       <plugin>
         <groupId>org.sonatype.plugins</groupId>
         <artifactId>nexus-staging-maven-plugin</artifactId>
-	<version>1.6.13</version>
+        <version>1.6.13</version>
         <extensions>true</extensions>
         <configuration>
           <serverId>sonatype-nexus-staging</serverId>
           <nexusUrl>https://oss.sonatype.org/</nexusUrl>
           <stagingProfileId>23ed8fbc71e875</stagingProfileId>
-	  <skipStagingRepositoryClose>true</skipStagingRepositoryClose>
+          <skipStagingRepositoryClose>true</skipStagingRepositoryClose>
         </configuration>
       </plugin>
     </plugins>
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1274_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1274_en
new file mode 100644
index 00000000..506e71d3
Binary files /dev/null and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1274_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1345_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1345_en
index bd11fc2e..fb73f3eb 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1345_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/1345_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/27_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/27_en
index 4f13f91d..04e749fe 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/27_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/27_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en
index a42f4fb8..48ea7c2d 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_en differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh
index 80b79b00..2ab9c681 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/86_zh differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config
index 2f071797..7bf0232b 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/geocoding/data/config differ
diff --git a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data
index 6e69f69b..feecbd05 100644
Binary files a/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data and b/repackaged/geocoder/src/com/android/i18n/phonenumbers/timezones/data/map_data differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
index 8fa35148..cbe63fbd 100644
--- a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
+++ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/PhoneNumberUtil.java
@@ -1914,8 +1914,11 @@ public class PhoneNumberUtil {
     String regionCode = getRegionCodeForCountryCode(countryCode);
     // Metadata cannot be null because the country calling code is valid.
     PhoneMetadata metadataForRegion = getMetadataForRegionOrCallingCode(countryCode, regionCode);
-    maybeAppendFormattedExtension(number, metadataForRegion,
-                                  PhoneNumberFormat.INTERNATIONAL, formattedNumber);
+    // Strip any extension
+    maybeStripExtension(formattedNumber);
+    // Append the formatted extension
+    maybeAppendFormattedExtension(
+        number, metadataForRegion, PhoneNumberFormat.INTERNATIONAL, formattedNumber);
     if (internationalPrefixForFormatting.length() > 0) {
       formattedNumber.insert(0, " ").insert(0, countryCode).insert(0, " ")
           .insert(0, internationalPrefixForFormatting);
@@ -2747,6 +2750,13 @@ public class PhoneNumberUtil {
    *        length (obviously includes the length of area codes for fixed line numbers), it will
    *        return false for the subscriber-number-only version.
    * </ol>
+   *
+   * <p>There is a known <a href="https://issuetracker.google.com/issues/335892662">issue</a> with this
+   * method: if a number is possible only in a certain region among several regions that share the
+   * same country calling code, this method will consider only the "main" region. For example,
+   * +1310xxxx are valid numbers in Canada. However, they are not possible in the US. As a result,
+   * this method will return IS_POSSIBLE_LOCAL_ONLY for +1310xxxx.
+   *
    * @param number  the number that needs to be checked
    * @return  a ValidationResult object which indicates whether the number is possible
    */
@@ -2777,6 +2787,12 @@ public class PhoneNumberUtil {
    *        return false for the subscriber-number-only version.
    * </ol>
    *
+   * <p>There is a known <a href="https://issuetracker.google.com/issues/335892662">issue</a> with this
+   * method: if a number is possible only in a certain region among several regions that share the
+   * same country calling code, this method will consider only the "main" region. For example,
+   * +1310xxxx are valid numbers in Canada. However, they are not possible in the US. As a result,
+   * this method will return IS_POSSIBLE_LOCAL_ONLY for +1310xxxx.
+   *
    * @param number  the number that needs to be checked
    * @param type  the type we are interested in
    * @return  a ValidationResult object which indicates whether the number is possible
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385
index 4460dc38..16155832 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberAlternateFormatsProto_385 differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR
index 6b9e1b97..16a904e8 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_AR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE
index 688f0edd..d7bcbb98 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL
index dd7a0335..fe5fbd02 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_BL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA
index f9eb1d80..11377bd0 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ
index c571a37a..1b05f7bc 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_CZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE
index 311b564a..7c4587b9 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK
index 12e00d6e..b2af72b6 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_DK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH
index 12b7b456..c41ae3d1 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_EH differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF
index 70249b0c..1d25a82b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP
index a4adefa5..a1167b64 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GP differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY
index 66e2a80e..68f578db 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_GY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK
index 8689e496..e01b5d4a 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_HK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL
index d588ee97..08d38b9c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_IL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY
index ec90682d..83f0907f 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_KY differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV
index d870a902..66312168 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_LV differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA
index 0aa3a540..8fa04333 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF
index 31f7d0e8..71b78cec 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MF differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK
index 2962a523..12b2210e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML
index f29019b7..3fcae753 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ML differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM
index 18252a2c..8fb67ba7 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MM differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN
index f0495fc4..0ecbc977 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU
index d650f761..5a117233 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_MU differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC
index afaaa519..ce011214 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_NC differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL
index 2dce227b..81cb8f49 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW
index 0dc5a303..3783c6a8 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_PW differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE
index f755038c..59beac28 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_RE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG
index 5eeee4c3..53525170 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL
index a27ce044..9fb64332 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SL differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN
index 4ebef4fe..e9f77e3d 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SN differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO
index 543b1fb0..c4a80bde 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SO differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR
index d9f7ed7d..54f40263 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_SR differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ
index a233a31c..264add0e 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_TJ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG
index e652952b..a32febd9 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UG differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US
index 0e1c1170..bcbffc14 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_US differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ
index 6ca9f7e7..e2d5881c 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_UZ differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE
index 3c4ad741..bdfb7d7b 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_VE differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA
index 340306dc..d15576a1 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/PhoneNumberMetadataProto_ZA differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DK b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DK
index b3875151..b6e571ba 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DK and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_DK differ
diff --git a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO
index bbfcdd63..7f073133 100644
Binary files a/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO and b/repackaged/libphonenumber/src/com/android/i18n/phonenumbers/data/ShortNumberMetadataProto_NO differ
diff --git a/update-from-external.sh b/update-from-external.sh
index 7cb64ed0..5a5e9640 100755
--- a/update-from-external.sh
+++ b/update-from-external.sh
@@ -38,5 +38,19 @@ do
     sed "s|Version: .*$|Version: $VERSION|" < $tmp/$i > $DIR/$i
     (cd $DIR; git add $i)
 done
+
+YEAR=$(date +%Y)
+MONTH=$(date +%m)
+DAY=$(date +%d)
+cp $DIR/METADATA $tmp
+echo "Updating METADATA"
+sed -e "s/\(version: \)\(.*\)/\1\"$VERSION\"/
+        s/\(year: \)\(.*\)/\1$YEAR/
+        s/\(month: \)\(.*\)/\1$MONTH/
+        s/\(day: \)\(.*\)/\1$DAY/" < $tmp/METADATA > $DIR/METADATA
+
+(cd $DIR; git add METADATA)
+
 ${DIR}/srcgen/generate_android_src.sh
+
 git add repackaged
```

