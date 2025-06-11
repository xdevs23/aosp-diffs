```diff
diff --git a/.github/workflows/build.yaml b/.github/workflows/build.yaml
new file mode 100644
index 0000000..dcee386
--- /dev/null
+++ b/.github/workflows/build.yaml
@@ -0,0 +1,26 @@
+name: Java CI
+
+on:
+  push:
+    branches:
+      - main
+  pull_request:
+
+permissions:
+  contents: read
+
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+    - uses: actions/checkout@v4
+    - name: Set up JDK 17
+      uses: actions/setup-java@v4
+      with:
+        java-version: '17'
+        distribution: 'temurin'
+    - name: Run build
+      run: |
+        mvn -B install -PtestJakarta
+
+
diff --git a/.gitignore b/.gitignore
index ab4a6f9..140b296 100644
--- a/.gitignore
+++ b/.gitignore
@@ -18,3 +18,5 @@ nb-configuration.xml
 /jsp/target/
 /esapi/target/
 /target/
+/jakarta/target/
+/jakarta-test/target/
diff --git a/.java-version b/.java-version
new file mode 100644
index 0000000..03b6389
--- /dev/null
+++ b/.java-version
@@ -0,0 +1 @@
+17.0
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 5206c1e..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,14 +0,0 @@
-language: java
-dist: trusty
-
-jdk:
-  - openjdk8
-  - oraclejdk8
-# to compile using JDK 9+ we must move from source and target 1.5 to 1.6 
-#  - openjdk9
-#  - openjdk10
-#  - openjdk11
-#  - oraclejdk9
-#  - oraclejdk10
-
-script: mvn test -B -X
diff --git a/METADATA b/METADATA
index 83dd041..1880f0f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
-name: "owasp-java-encoder"
-description:
-    "The OWASP Java Encoder is a Java 1.5+ simple-to-use drop-in "
-    "high-performance encoder class with no dependencies and little baggage. "
-    "This project will help Java web developers defend against Cross Site "
-    "Scripting!"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/owasp/java-encoder
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "owasp-java-encoder"
+description: "The OWASP Java Encoder is a Java 1.5+ simple-to-use drop-in high-performance encoder class with no dependencies and little baggage. This project will help Java web developers defend against Cross Site Scripting!"
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://owasp.org/www-project-java-encoder/"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 16
   }
-  url {
-    type: GIT
+  homepage: "https://owasp.org/www-project-java-encoder/"
+  identifier {
+    type: "Git"
     value: "https://github.com/OWASP/owasp-java-encoder.git"
+    version: "v1.3.1"
   }
-  version: "6309c0ad5d5a339f41dfa94384930f630d46bc4a"
-  last_upgrade_date { year: 2023 month: 2 day: 14 }
-  license_type: NOTICE
 }
diff --git a/README.md b/README.md
index e7dfd4f..21e2b42 100644
--- a/README.md
+++ b/README.md
@@ -1,10 +1,10 @@
 OWASP Java Encoder Project
 ==========================
 
-[![Build Status](https://travis-ci.org/OWASP/owasp-java-encoder.svg?branch=main)](https://travis-ci.org/OWASP/owasp-java-encoder) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause) [![javadoc](https://javadoc.io/badge2/org.owasp.encoder/encoder/javadoc.svg)](https://javadoc.io/doc/org.owasp.encoder/encoder)
+![Build Status](https://github.com/OWASP/owasp-java-encoder/actions/workflows/build.yaml/badge.svg?branch=main) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause) [![javadoc](https://javadoc.io/badge2/org.owasp.encoder/encoder/javadoc.svg)](https://javadoc.io/doc/org.owasp.encoder/encoder)
 
 Contextual Output Encoding is a computer programming technique necessary to stop
-Cross-Site Scripting. This project is a Java 1.5+ simple-to-use drop-in high-performance
+Cross-Site Scripting. This project is a Java 1.8+ simple-to-use drop-in high-performance
 encoder class with little baggage.
 
 For more detailed documentation on the OWASP Javca Encoder please visit https://owasp.org/www-project-java-encoder/.
@@ -13,21 +13,31 @@ Start using the OWASP Java Encoders
 -----------------------------------
 You can download a JAR from [Maven Central](https://search.maven.org/#search|ga|1|g%3A%22org.owasp.encoder%22%20a%3A%22encoder%22).
 
-JSP tags and EL functions are available in the encoder-jsp, also available in [Central](http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder-jsp/1.2.3/encoder-jsp-1.2.3.jar).
+JSP tags and EL functions are available in the encoder-jsp, also available:
+- [encoder-jakarta-jsp](http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder-jakarta-jsp/1.2.3/encoder-jakarta-jsp-1.2.3.jar) - Servlet Spec 5.0
+- [encoder-jsp](http://search.maven.org/remotecontent?filepath=org/owasp/encoder/encoder-jsp/1.2.3/encoder-jsp-1.2.3.jar) - Servlet Spec 3.0
 
-The jars are also available in Maven:
+The jars are also available in Central:
 
 ```xml
 <dependency>
     <groupId>org.owasp.encoder</groupId>
     <artifactId>encoder</artifactId>
-    <version>1.2.3</version>
+    <version>1.3.0</version>
 </dependency>
 
+<!-- using Servlet Spec 5 in the jakarta.servlet package use: -->
+<dependency>
+    <groupId>org.owasp.encoder</groupId>
+    <artifactId>encoder-jakarta-jsp</artifactId>
+    <version>1.3.0</version>
+</dependency>
+
+<!-- using the Legacy Servlet Spec in the javax.servlet package use: -->
 <dependency>
     <groupId>org.owasp.encoder</groupId>
     <artifactId>encoder-jsp</artifactId>
-    <version>1.2.3</version>
+    <version>1.3.0</version>
 </dependency>
 ```
 
@@ -48,8 +58,60 @@ Please look at the javadoc for Encode to see the variety of contexts for which y
 
 Happy Encoding!
 
+Building
+--------
+
+Due to test cases for the `encoder-jakarta-jsp` project Java 17 is required to package and test
+the project. Simply run:
+
+```shell
+mvn package
+```
+
+To run the Jakarta JSP intgration test, to validate that the JSP Tags and EL work correctly run:
+
+```shell
+mvn verify -PtestJakarta
+```
+
+* Note that the above test may fail on modern Apple silicon.
+
+Java 9+ Module Names
+--------------------
+
+| JAR                 | Module Name           |
+|---------------------|-----------------------|
+| encoder             | owasp.encoder         |
+| encoder-jakarta-jsp | owasp.encoder.jakarta |
+| encoder-jsp         | owasp.encoder.jsp     |
+| encoder-espai       | owasp.encoder.esapi   |
+
+
+TagLib
+--------------------
+
+| Lib                 | TagLib                                                                                        |
+|---------------------|-----------------------------------------------------------------------------------------------|
+| encoder-jakarta-jsp | &lt;%@taglib prefix="e" uri="owasp.encoder.jakarta"%&gt;                                      |
+| encoder-jsp         | &lt;%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project"%&gt; |
+
+
 News
 ----
+### 2024-08-20 - 1.3.1 Release
+The team is happy to announce that version 1.3.1 has been released!
+* fix: add OSGi related entries in the MANIFEST.MF file (#82).
+* fix: java.lang.NoSuchMethodError when running on Java 8 (#80).
+
+### 2024-08-02 - 1.3.0 Release
+The team is happy to announce that version 1.3.0 has been released!
+* Minimum JDK Requirement is now Java 8
+  - Requires Java 17 to build due to test case dependencies.
+* Adds Java 9 Module name via Multi-Release Jars (#77).
+* Fixed compilation errors with the ESAPI Thunk (#76).
+* Adds support for Servlet Spec 5 using the `jakarta.servlet.*` (#75).
+  - taglib : &lt;%@taglib prefix="e" uri="owasp.encoder.jakarta"%&gt;
+
 ### 2020-11-08 - 1.2.3 Release
 The team is happy to announce that version 1.2.3 has been released! 
 * Update to  make the manifest OSGi-compliant (#39).
diff --git a/core/pom.xml b/core/pom.xml
index 29baed5..4ae9ce6 100644
--- a/core/pom.xml
+++ b/core/pom.xml
@@ -42,7 +42,7 @@
     <parent>
         <groupId>org.owasp.encoder</groupId>
         <artifactId>encoder-parent</artifactId>
-        <version>1.2.3</version>
+        <version>1.3.1</version>
     </parent>
 
     <artifactId>encoder</artifactId>
diff --git a/core/src/main/java/org/owasp/encoder/Encode.java b/core/src/main/java/org/owasp/encoder/Encode.java
index 165635c..67972d1 100644
--- a/core/src/main/java/org/owasp/encoder/Encode.java
+++ b/core/src/main/java/org/owasp/encoder/Encode.java
@@ -243,7 +243,7 @@ public final class Encode {
      *
      * <b>Example JSP Usage</b>
      * <pre>
-     *     &lt;div&gt;&lt;%=Encode.forHtmlAttribute(unsafeData)%&gt;&lt;/div&gt;
+     *     &lt;input value=&quot;&lt;%=Encode.forHtmlAttribute(unsafeData)%&gt;&quot; title=&#39;&lt;%=Encode.forHtmlAttribute(moreUnsafeData)%&gt;&#39; /&gt;
      * </pre>
      *
      * <table border="0" class="memberSummary" summary="Shows the input and results of encoding">
@@ -276,6 +276,8 @@ public final class Encode {
      *
      * <p><b>Additional Notes</b></p>
      * <ul>
+     * <li>When using this method, the caller must provide quotes around the attribute value.</li>
+     *
      * <li>Both the single-quote character ({@code '}) and the
      * double-quote character ({@code "}) are encoded so this is safe
      * for HTML attributes with either enclosing character.</li>
diff --git a/core/src/main/java9/module-info.java b/core/src/main/java9/module-info.java
new file mode 100644
index 0000000..fabb12a
--- /dev/null
+++ b/core/src/main/java9/module-info.java
@@ -0,0 +1,3 @@
+module owasp.encoder {
+    exports org.owasp.encoder;
+}
diff --git a/esapi/pom.xml b/esapi/pom.xml
index cc26851..b4b55a3 100644
--- a/esapi/pom.xml
+++ b/esapi/pom.xml
@@ -42,7 +42,7 @@
     <parent>
         <groupId>org.owasp.encoder</groupId>
         <artifactId>encoder-parent</artifactId>
-        <version>1.2.3</version>
+        <version>1.3.1</version>
     </parent>
 
     <artifactId>encoder-esapi</artifactId>
@@ -67,7 +67,7 @@
         <dependency>
             <groupId>org.owasp.esapi</groupId>
             <artifactId>esapi</artifactId>
-            <version>[2.2.3.1,3)</version>
+            <version>[2.5.1.0,3)</version>
         </dependency>
     </dependencies>
 </project>
diff --git a/esapi/src/main/java/org/owasp/encoder/esapi/ESAPIEncoder.java b/esapi/src/main/java/org/owasp/encoder/esapi/ESAPIEncoder.java
index 02334bd..f84b3d1 100644
--- a/esapi/src/main/java/org/owasp/encoder/esapi/ESAPIEncoder.java
+++ b/esapi/src/main/java/org/owasp/encoder/esapi/ESAPIEncoder.java
@@ -141,114 +141,148 @@ public final class ESAPIEncoder {
         private final Encoder _referenceEncoder = DefaultEncoder.getInstance();
 
         /** {@inheritDoc} */
+        @Override
         public String canonicalize(String s) {
             return _referenceEncoder.canonicalize(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String canonicalize(String s, boolean strict) {
             return _referenceEncoder.canonicalize(s, strict);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String canonicalize(String s, boolean restrictMultiple, boolean restrictMixed) {
             return _referenceEncoder.canonicalize(s, restrictMultiple, restrictMixed);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String getCanonicalizedURI(URI dirtyUri) {
             return _referenceEncoder.getCanonicalizedURI(dirtyUri);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForCSS(String s) {
             return Encode.forCssString(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForHTML(String s) {
             return Encode.forHtml(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String decodeForHTML(String s) {
             return _referenceEncoder.decodeForHTML(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForHTMLAttribute(String s) {
             return Encode.forHtmlAttribute(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForJavaScript(String s) {
             return Encode.forJavaScript(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForVBScript(String s) {
             return _referenceEncoder.encodeForVBScript(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForSQL(Codec codec, String s) {
             return _referenceEncoder.encodeForSQL(codec, s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForOS(Codec codec, String s) {
             return _referenceEncoder.encodeForOS(codec, s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForLDAP(String s) {
             return _referenceEncoder.encodeForLDAP(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForLDAP(String s, boolean b) {
             return _referenceEncoder.encodeForLDAP(s, b);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForDN(String s) {
             return _referenceEncoder.encodeForDN(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForXPath(String s) {
             return _referenceEncoder.encodeForXPath(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForXML(String s) {
             return Encode.forXml(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForXMLAttribute(String s) {
             return Encode.forXmlAttribute(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForURL(String s) throws EncodingException {
             return Encode.forUri(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String decodeFromURL(String s) throws EncodingException {
             return _referenceEncoder.decodeFromURL(s);
         }
 
         /** {@inheritDoc} */
+        @Override
         public String encodeForBase64(byte[] bytes, boolean wrap) {
             return _referenceEncoder.encodeForBase64(bytes, wrap);
         }
 
         /** {@inheritDoc} */
+        @Override
         public byte[] decodeFromBase64(String s) throws IOException {
             return _referenceEncoder.decodeFromBase64(s);
         }
 
+        /** {@inheritDoc} */
+        @Override
+        public String encodeForJSON(String s) {
+            return _referenceEncoder.encodeForJSON(s);
+        }
+
+        /** {@inheritDoc} */
+        @Override
+        public String decodeFromJSON(String s) {
+            return _referenceEncoder.decodeFromJSON(s);
+        }
+
     }
 }
diff --git a/esapi/src/main/java9/module-info.java b/esapi/src/main/java9/module-info.java
new file mode 100644
index 0000000..e5e1e41
--- /dev/null
+++ b/esapi/src/main/java9/module-info.java
@@ -0,0 +1,5 @@
+module owasp.encoder.esapi {
+    requires owasp.encoder;
+    
+    exports org.owasp.encoder.esapi;
+}
\ No newline at end of file
diff --git a/esapi/src/test/resources/esapi-java-logging.properties b/esapi/src/test/resources/esapi-java-logging.properties
deleted file mode 100644
index 71011ac..0000000
--- a/esapi/src/test/resources/esapi-java-logging.properties
+++ /dev/null
@@ -1,6 +0,0 @@
-handlers= java.util.logging.ConsoleHandler
-.level= INFO
-java.util.logging.ConsoleHandler.level = INFO
-java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter
-java.util.logging.SimpleFormatter.format=[%1$tF %1$tT] [%3$-7s] %5$s %n
-#https://www.logicbig.com/tutorials/core-java-tutorial/logging/customizing-default-format.html
\ No newline at end of file
diff --git a/jakarta-test/pom.xml b/jakarta-test/pom.xml
new file mode 100644
index 0000000..db39bac
--- /dev/null
+++ b/jakarta-test/pom.xml
@@ -0,0 +1,126 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
+    <modelVersion>4.0.0</modelVersion>
+    <parent>
+        <groupId>org.springframework.boot</groupId>
+        <artifactId>spring-boot-starter-parent</artifactId>
+        <version>3.3.2</version>
+        <relativePath/> <!-- lookup parent from repository -->
+    </parent>
+    <groupId>org.owasp.encoder.testing</groupId>
+    <artifactId>jakarta-test</artifactId>
+    <version>0.0.1-SNAPSHOT</version>
+    <packaging>war</packaging>
+    <name>jakarta-test</name>
+    <description>Test for OWASP encoder jakarta JSP</description>
+    <properties>
+        <java.version>17</java.version>
+    </properties>
+    <dependencies>
+        <dependency>
+            <groupId>org.owasp.encoder</groupId>
+            <artifactId>encoder-jakarta-jsp</artifactId>
+            <version>1.3.1</version>
+        </dependency>
+        <dependency>
+            <groupId>org.springframework.boot</groupId>
+            <artifactId>spring-boot-starter-web</artifactId>
+        </dependency>
+        <dependency>
+            <groupId>org.apache.tomcat.embed</groupId>
+            <artifactId>tomcat-embed-jasper</artifactId>
+            <version>10.1.18</version>
+            <scope>provided</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.springframework.boot</groupId>
+            <artifactId>spring-boot-starter-tomcat</artifactId>
+            <version>3.2.2</version>
+            <scope>provided</scope>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.servlet</groupId>
+            <artifactId>jakarta.servlet-api</artifactId>
+            <version>6.0.0</version>
+            <scope>provided</scope>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.servlet.jsp</groupId>
+            <artifactId>jakarta.servlet.jsp-api</artifactId>
+            <version>3.1.0</version>
+            <scope>provided</scope>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.servlet.jsp.jstl</groupId>
+            <artifactId>jakarta.servlet.jsp.jstl-api</artifactId>
+            <version>3.0.0</version>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.el</groupId>
+            <artifactId>jakarta.el-api</artifactId>
+            <version>5.0.1</version>
+        </dependency>
+        <dependency>
+            <groupId>org.glassfish.web</groupId>
+            <artifactId>jakarta.servlet.jsp.jstl</artifactId>
+            <version>3.0.1</version>
+        </dependency>
+        
+        <dependency>
+            <groupId>org.springframework.boot</groupId>
+            <artifactId>spring-boot-starter-test</artifactId>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.springframework.boot</groupId>
+            <artifactId>spring-boot-testcontainers</artifactId>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.testcontainers</groupId>
+            <artifactId>selenium</artifactId>
+            <version>1.20.0</version>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.seleniumhq.selenium</groupId>
+            <artifactId>selenium-remote-driver</artifactId>
+            <version>4.23.0</version>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.seleniumhq.selenium</groupId>
+            <artifactId>selenium-chrome-driver</artifactId>
+            <version>4.23.0</version>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.testcontainers</groupId>
+            <artifactId>junit-jupiter</artifactId>
+            <version>1.20.0</version>
+            <scope>test</scope>
+        </dependency>
+    </dependencies>
+
+    <build>
+        <finalName>jakarta-test</finalName>
+        <plugins>
+            <plugin>
+                <groupId>org.springframework.boot</groupId>
+                <artifactId>spring-boot-maven-plugin</artifactId>
+                <configuration>
+                    <mainClass>org.owasp.encoder.testing.jakarta_test.JakartaTestApplication</mainClass>
+                </configuration>
+                <executions>
+                    <execution>
+                        <goals>
+                            <goal>repackage</goal>
+                        </goals>
+                    </execution>
+                </executions>
+            </plugin>
+        </plugins>
+    </build>
+
+</project>
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplication.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplication.java
new file mode 100644
index 0000000..9c0c237
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplication.java
@@ -0,0 +1,20 @@
+package org.owasp.encoder.testing.jakarta_test;
+
+import org.springframework.boot.SpringApplication;
+import org.springframework.boot.autoconfigure.SpringBootApplication;
+import org.springframework.boot.builder.SpringApplicationBuilder;
+import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
+
+@SpringBootApplication(scanBasePackages = "org.owasp.encoder.testing.jakarta_test")
+public class JakartaTestApplication extends SpringBootServletInitializer {
+
+    @Override
+    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
+        return builder.sources(JakartaTestApplication.class);
+    }
+
+    public static void main(String[] args) {
+        SpringApplication.run(JakartaTestApplication.class, args);
+    }
+
+}
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/HomeController.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/HomeController.java
new file mode 100644
index 0000000..8b36a25
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/HomeController.java
@@ -0,0 +1,19 @@
+package org.owasp.encoder.testing.jakarta_test.controller;
+
+import org.springframework.stereotype.Controller;
+import org.springframework.web.bind.annotation.GetMapping;
+import org.springframework.web.bind.annotation.RequestMapping;
+
+/**
+ *
+ * @author jeremy
+ */
+@Controller
+@RequestMapping("/")
+public class HomeController {
+
+    @GetMapping("")
+    public String index() {
+        return "index";
+    }
+}
\ No newline at end of file
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/ItemController.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/ItemController.java
new file mode 100644
index 0000000..3b22a6f
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/controller/ItemController.java
@@ -0,0 +1,28 @@
+package org.owasp.encoder.testing.jakarta_test.controller;
+
+import org.owasp.encoder.testing.jakarta_test.service.ItemService;
+import org.springframework.stereotype.Controller;
+import org.springframework.ui.Model;
+import org.springframework.web.bind.annotation.GetMapping;
+import org.springframework.web.bind.annotation.RequestMapping;
+
+/**
+ *
+ * @author jeremy
+ */
+@Controller
+@RequestMapping("/item")
+public class ItemController {
+
+    private final ItemService itemService;
+
+    public ItemController(ItemService itemService) {
+        this.itemService = itemService;
+    }
+
+    @GetMapping("/viewItems")
+    public String viewItems(Model model) {
+        model.addAttribute("items", itemService.getItems());
+        return "view-items";
+    }
+}
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/dto/Item.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/dto/Item.java
new file mode 100644
index 0000000..4cda55c
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/dto/Item.java
@@ -0,0 +1,77 @@
+package org.owasp.encoder.testing.jakarta_test.dto;
+
+/**
+ *
+ * @author jeremy
+ */
+public class Item {
+
+    private int id;
+
+    private String name;
+    
+    private String description;
+
+    public Item() {
+    }
+
+    public Item(int id, String name, String description) {
+        this.id = id;
+        this.name = name;
+        this.description = description;
+    }
+
+    /**
+     * Get the value of id
+     *
+     * @return the value of id
+     */
+    public int getId() {
+        return id;
+    }
+
+    /**
+     * Set the value of id
+     *
+     * @param id new value of id
+     */
+    public void setId(int id) {
+        this.id = id;
+    }
+
+    /**
+     * Get the value of name
+     *
+     * @return the value of name
+     */
+    public String getName() {
+        return name;
+    }
+
+    /**
+     * Set the value of name
+     *
+     * @param name new value of name
+     */
+    public void setName(String name) {
+        this.name = name;
+    }
+
+        /**
+     * Get the value of description
+     *
+     * @return the value of description
+     */
+    public String getDescription() {
+        return description;
+    }
+
+    /**
+     * Set the value of description
+     *
+     * @param description new value of description
+     */
+    public void setDescription(String description) {
+        this.description = description;
+    }
+}
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/ItemService.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/ItemService.java
new file mode 100644
index 0000000..fe2a45f
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/ItemService.java
@@ -0,0 +1,14 @@
+package org.owasp.encoder.testing.jakarta_test.service;
+
+import java.util.Collection;
+import org.owasp.encoder.testing.jakarta_test.dto.Item;
+
+/**
+ *
+ * @author jeremy
+ */
+public interface ItemService {
+    Collection<Item> getItems();
+
+    Item addItem(Item item);
+}
diff --git a/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/impl/ItemServiceImpl.java b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/impl/ItemServiceImpl.java
new file mode 100644
index 0000000..4807594
--- /dev/null
+++ b/jakarta-test/src/main/java/org/owasp/encoder/testing/jakarta_test/service/impl/ItemServiceImpl.java
@@ -0,0 +1,29 @@
+package org.owasp.encoder.testing.jakarta_test.service.impl;
+
+import java.util.ArrayList;
+import java.util.Collection;
+import org.owasp.encoder.testing.jakarta_test.dto.Item;
+import org.owasp.encoder.testing.jakarta_test.service.ItemService;
+import org.springframework.stereotype.Service;
+
+/**
+ *
+ * @author jeremy
+ */
+@Service
+public class ItemServiceImpl implements ItemService {
+
+    @Override
+    public Collection<Item> getItems() {
+        Collection<Item> items = new ArrayList<>();
+        items.add(new Item(1, "menu", "blob"));
+        items.add(new Item(2, "top<script>alert(1)</script>", "fancy <script>alert(1)</script>"));
+        return items;
+    }
+
+    @Override
+    public Item addItem(Item item) {
+        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
+    }
+
+}
diff --git a/jakarta-test/src/main/resources/application.properties b/jakarta-test/src/main/resources/application.properties
new file mode 100644
index 0000000..899d450
--- /dev/null
+++ b/jakarta-test/src/main/resources/application.properties
@@ -0,0 +1,4 @@
+spring.application.name=jakarta-test
+server.servlet.context-path=/jakarta-test
+spring.mvc.view.prefix=/WEB-INF/jsp/
+spring.mvc.view.suffix=.jsp
diff --git a/jakarta-test/src/main/resources/static/css/common.css b/jakarta-test/src/main/resources/static/css/common.css
new file mode 100644
index 0000000..a32d81c
--- /dev/null
+++ b/jakarta-test/src/main/resources/static/css/common.css
@@ -0,0 +1,10 @@
+table {
+    font-family: arial, sans-serif;
+    border-collapse: collapse;
+}
+
+td, th {
+    border: 1px solid #dddddd;
+    text-align: left;
+    padding: 8px;
+}
\ No newline at end of file
diff --git a/jakarta-test/src/main/resources/static/error/4xx.html b/jakarta-test/src/main/resources/static/error/4xx.html
new file mode 100644
index 0000000..c798239
--- /dev/null
+++ b/jakarta-test/src/main/resources/static/error/4xx.html
@@ -0,0 +1,10 @@
+<!DOCTYPE html>
+<html lang="en">
+<head>
+    <meta charset="UTF-8">
+    <title>Error</title>
+</head>
+<body>
+Apparently you don't know what you are looking for?<br/><br/>4xx Error Occurred
+</body>
+</html>
diff --git a/jakarta-test/src/main/webapp/WEB-INF/jsp/index.jsp b/jakarta-test/src/main/webapp/WEB-INF/jsp/index.jsp
new file mode 100644
index 0000000..7abf69b
--- /dev/null
+++ b/jakarta-test/src/main/webapp/WEB-INF/jsp/index.jsp
@@ -0,0 +1,12 @@
+<%@page contentType="text/html" pageEncoding="UTF-8"%>
+<!DOCTYPE html>
+<html>
+    <head>
+        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
+        <title>OWASP Java Encoder Jakarta JSP Test</title>
+    </head>
+    <body>
+        <h1>Hello World!</h1>
+        You are likely looking for the test page located <a href="/jakarta-test/item/viewItems">here</a>.
+    </body>
+</html>
diff --git a/jakarta-test/src/main/webapp/WEB-INF/jsp/view-items.jsp b/jakarta-test/src/main/webapp/WEB-INF/jsp/view-items.jsp
new file mode 100644
index 0000000..69e2488
--- /dev/null
+++ b/jakarta-test/src/main/webapp/WEB-INF/jsp/view-items.jsp
@@ -0,0 +1,29 @@
+<%@page contentType="text/html;charset=UTF-8" language="java"%>
+<%@taglib prefix="c" uri="jakarta.tags.core"%>
+<%@taglib prefix="e" uri="owasp.encoder.jakarta"%>
+<html>
+    <head>
+        <title>View Items</title>
+        <link href="<c:url value="/css/common.css"/>" rel="stylesheet" type="text/css">
+    </head>
+    <body>
+        <table>
+            <thead>
+                <tr>
+                    <th>ID</th>
+                    <th>Name</th>
+                    <th>Description</th>
+                </tr>
+            </thead>
+            <tbody>
+                <c:forEach items="${items}" var="item">
+                    <tr>
+                        <td id="a${item.id}">${item.id}</td>
+                        <td id="b${item.id}"><e:forHtml  value="${item.name}"/></td>
+                        <td id="c${item.id}">${e:forHtml(item.description)}</td>
+                    </tr>
+                </c:forEach>
+            </tbody>
+        </table>
+    </body>
+</html>
\ No newline at end of file
diff --git a/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/ItemControllerTest.java b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/ItemControllerTest.java
new file mode 100644
index 0000000..c08cbb4
--- /dev/null
+++ b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/ItemControllerTest.java
@@ -0,0 +1,65 @@
+package org.owasp.encoder.testing.jakarta_test;
+
+import static org.junit.jupiter.api.Assertions.assertEquals;
+import static org.junit.jupiter.api.Assertions.assertNotNull;
+import org.junit.jupiter.api.BeforeAll;
+import org.junit.jupiter.api.Test;
+import org.openqa.selenium.By;
+import org.openqa.selenium.NoSuchElementException;
+import org.openqa.selenium.WebElement;
+import org.openqa.selenium.chrome.ChromeOptions;
+import org.openqa.selenium.remote.RemoteWebDriver;
+import org.springframework.beans.factory.annotation.Autowired;
+import org.springframework.boot.test.context.SpringBootTest;
+import org.springframework.boot.test.web.server.LocalServerPort;
+import org.springframework.core.env.Environment;
+import org.testcontainers.Testcontainers;
+import org.testcontainers.containers.BrowserWebDriverContainer;
+import org.testcontainers.junit.jupiter.Container;
+
+/**
+ *
+ * @author jeremy
+ */
+@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
+public class ItemControllerTest {
+
+    @Container
+    static BrowserWebDriverContainer<?> container = new BrowserWebDriverContainer<>().
+            withCapabilities(new ChromeOptions());
+
+    @LocalServerPort
+    private int port;
+
+    @BeforeAll
+    static void beforeAll(@Autowired Environment environment) {
+        Testcontainers.exposeHostPorts(environment.getProperty("local.server.port", Integer.class));
+        container.start();
+    }
+
+    @Test
+    void shouldDisplayMessage() {
+        RemoteWebDriver browser = new RemoteWebDriver(container.getSeleniumAddress(), new ChromeOptions());
+        browser.get("http://host.testcontainers.internal:" + port + "/jakarta-test/item/viewItems");
+        WebElement first = browser.findElement(By.id("b2"));
+        WebElement second = browser.findElement(By.id("c2"));
+        assertEquals("top<script>alert(1)</script>", first.getText());
+        assertEquals("fancy <script>alert(1)</script>", second.getText());
+        //todo yes - there are much better ways to check for an exception in junit
+        NoSuchElementException exception = null;
+        try {
+            first.findElement(By.tagName("script"));
+        } catch (NoSuchElementException ex) {
+            exception = ex;
+        }
+        assertNotNull(exception);
+
+        exception = null;
+        try {
+            second.findElement(By.tagName("script"));
+        } catch (NoSuchElementException ex) {
+            exception = ex;
+        }
+        assertNotNull(exception);
+    }
+}
diff --git a/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplicationTests.java b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplicationTests.java
new file mode 100644
index 0000000..55a46fd
--- /dev/null
+++ b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/JakartaTestApplicationTests.java
@@ -0,0 +1,15 @@
+package org.owasp.encoder.testing.jakarta_test;
+
+import org.junit.jupiter.api.Test;
+import org.springframework.boot.test.context.SpringBootTest;
+import org.springframework.context.annotation.Import;
+
+@Import(TestcontainersConfiguration.class)
+@SpringBootTest
+class JakartaTestApplicationTests {
+
+	@Test
+	void contextLoads() {
+	}
+
+}
diff --git a/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestJakartaTestApplication.java b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestJakartaTestApplication.java
new file mode 100644
index 0000000..d2f0dd1
--- /dev/null
+++ b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestJakartaTestApplication.java
@@ -0,0 +1,11 @@
+package org.owasp.encoder.testing.jakarta_test;
+
+import org.springframework.boot.SpringApplication;
+
+public class TestJakartaTestApplication {
+
+	public static void main(String[] args) {
+		SpringApplication.from(JakartaTestApplication::main).with(TestcontainersConfiguration.class).run(args);
+	}
+
+}
diff --git a/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestcontainersConfiguration.java b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestcontainersConfiguration.java
new file mode 100644
index 0000000..d838525
--- /dev/null
+++ b/jakarta-test/src/test/java/org/owasp/encoder/testing/jakarta_test/TestcontainersConfiguration.java
@@ -0,0 +1,8 @@
+package org.owasp.encoder.testing.jakarta_test;
+
+import org.springframework.boot.test.context.TestConfiguration;
+
+@TestConfiguration(proxyBeanMethods = false)
+class TestcontainersConfiguration {
+
+}
diff --git a/jakarta/pom.xml b/jakarta/pom.xml
new file mode 100644
index 0000000..4270a04
--- /dev/null
+++ b/jakarta/pom.xml
@@ -0,0 +1,93 @@
+<?xml version="1.0" encoding="US-ASCII"?>
+<!--
+~ Copyright (c) 2015 OWASP.
+~ All rights reserved.
+~
+~ Redistribution and use in source and binary forms, with or without
+~ modification, are permitted provided that the following conditions
+~ are met:
+~
+~     * Redistributions of source code must retain the above
+~       copyright notice, this list of conditions and the following
+~       disclaimer.
+~
+~     * Redistributions in binary form must reproduce the above
+~       copyright notice, this list of conditions and the following
+~       disclaimer in the documentation and/or other materials
+~       provided with the distribution.
+~
+~     * Neither the name of the OWASP nor the names of its
+~       contributors may be used to endorse or promote products
+~       derived from this software without specific prior written
+~       permission.
+~
+~ THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+~ "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+~ LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+~ FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+~ COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+~ INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+~ (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+~ SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+~ HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+~ STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+~ ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+~ OF THE POSSIBILITY OF SUCH DAMAGE.
+-->
+
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
+    <modelVersion>4.0.0</modelVersion>
+
+    <parent>
+        <groupId>org.owasp.encoder</groupId>
+        <artifactId>encoder-parent</artifactId>
+        <version>1.3.1</version>
+    </parent>
+
+    <artifactId>encoder-jakarta-jsp</artifactId>
+    <packaging>jar</packaging>
+
+    <name>Jakarta JSP Encoder</name>
+    <description>
+        The OWASP Encoder Jakarta JSP package contains JSP tag definitions and TLDs to allow
+        easy use of the OWASP Encoder Project's core API. The TLDs contain both tag
+        definitions and JSP EL functions.
+    </description>
+
+    <properties>
+        <jigsaw.module.name>org.owasp.encoder.jakarta</jigsaw.module.name>
+    </properties>
+
+    <dependencies>
+        <dependency>
+            <groupId>org.owasp.encoder</groupId>
+            <artifactId>encoder</artifactId>
+            <version>${project.parent.version}</version>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.servlet.jsp</groupId>
+            <artifactId>jakarta.servlet.jsp-api</artifactId>
+            <version>3.0.0</version>
+            <scope>provided</scope>
+        </dependency>
+        <dependency>
+            <groupId>jakarta.servlet</groupId>
+            <artifactId>jakarta.servlet-api</artifactId>
+            <version>6.0.0</version>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.springframework</groupId>
+            <artifactId>spring-test</artifactId>
+            <version>6.0.22</version>
+            <scope>test</scope>
+        </dependency>
+        <dependency>
+            <groupId>org.springframework</groupId>
+            <artifactId>spring-core</artifactId>
+            <version>5.3.19</version>
+            <scope>test</scope>
+        </dependency>
+    </dependencies>
+</project>
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/EncodingTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/EncodingTag.java
new file mode 100644
index 0000000..3696cbd
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/EncodingTag.java
@@ -0,0 +1,57 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import jakarta.servlet.jsp.tagext.SimpleTagSupport;
+
+/**
+ * The base class for the encoding tags within this package.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public abstract class EncodingTag extends SimpleTagSupport {
+    /**
+     * The value to be written out by the tag.
+     */
+    protected String _value;
+    /**
+     * Sets the value to be written out by the tag.
+     * @param value the value to be written out by the tag.
+     */
+    public void setValue(String value) {
+        this._value = value;
+    }
+
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForCDATATag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForCDATATag.java
new file mode 100644
index 0000000..85d7e4a
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForCDATATag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform encoding sufficient to place into a CDATA block.
+ * This wraps the {@link org.owasp.encoder.Encode#forCDATA(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCDATATag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forCDATA(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForCssStringTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForCssStringTag.java
new file mode 100644
index 0000000..5abcc9b
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForCssStringTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform CSS encoding for CSS strings.
+ * This wraps the {@link org.owasp.encoder.Encode#forCssString(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCssStringTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forCssString(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForCssUrlTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForCssUrlTag.java
new file mode 100644
index 0000000..d4bdbbf
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForCssUrlTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform CSS encoding for CSS URL contexts.
+ * This wraps the {@link org.owasp.encoder.Encode#forCssUrl(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCssUrlTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forCssUrl(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlAttributeTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlAttributeTag.java
new file mode 100644
index 0000000..686920a
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlAttributeTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform HTML encoding for HTML text attributes.
+ * This wraps the {@link org.owasp.encoder.Encode#forHtmlAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlAttributeTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forHtmlAttribute(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlContentTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlContentTag.java
new file mode 100644
index 0000000..78b9201
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlContentTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform HTML encoding for text content.
+ * This wraps the {@link org.owasp.encoder.Encode#forHtmlContent(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlContentTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forHtmlContent(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlTag.java
new file mode 100644
index 0000000..d5030e4
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform HTML encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forHtml(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forHtml(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTag.java
new file mode 100644
index 0000000..f28ea01
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform HTML Attribute encoding for an unquoted attribute.
+ * This wraps the {@link org.owasp.encoder.Encode#forHtmlUnquotedAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlUnquotedAttributeTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forHtmlUnquotedAttribute(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptAttributeTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptAttributeTag.java
new file mode 100644
index 0000000..159d487
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptAttributeTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform JavaScript Attribute encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forJavaScriptAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptAttributeTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forJavaScriptAttribute(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptBlockTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptBlockTag.java
new file mode 100644
index 0000000..c5412a9
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptBlockTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform JavaScript Block encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forJavaScriptBlock(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptBlockTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forJavaScriptBlock(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptSourceTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptSourceTag.java
new file mode 100644
index 0000000..8370f7f
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptSourceTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform JavaScript Source encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forJavaScriptSource(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptSourceTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forJavaScriptSource(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptTag.java
new file mode 100644
index 0000000..6211699
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForJavaScriptTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform JavaScript encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forJavaScript(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forJavaScript(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForUriComponentTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForUriComponentTag.java
new file mode 100644
index 0000000..e93aa98
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForUriComponentTag.java
@@ -0,0 +1,53 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag that performs percent-encoding for a component of a URI, such as a query
+ * parameter name or value, path, or query-string.
+ * This wraps the {@link org.owasp.encoder.Encode#forUriComponent(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForUriComponentTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forUriComponent(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForUriTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForUriTag.java
new file mode 100644
index 0000000..e68903f
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForUriTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform percent-encoding of a URL according to RFC 3986.
+ * This wraps the {@link org.owasp.encoder.Encode#forUri(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForUriTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forUri(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlAttributeTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlAttributeTag.java
new file mode 100644
index 0000000..a9c99c4
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlAttributeTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform XML Attribute Encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forXmlAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlAttributeTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forXmlAttribute(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlCommentTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlCommentTag.java
new file mode 100644
index 0000000..0e6da88
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlCommentTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform XML Comment Encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forXmlAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlCommentTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forXmlComment(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlContentTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlContentTag.java
new file mode 100644
index 0000000..23de3a5
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlContentTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform XML Content Encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forXmlAttribute(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlContentTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forXmlContent(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlTag.java b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlTag.java
new file mode 100644
index 0000000..550dcc3
--- /dev/null
+++ b/jakarta/src/main/java/org/owasp/encoder/tag/ForXmlTag.java
@@ -0,0 +1,52 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import java.io.IOException;
+import jakarta.servlet.jsp.JspException;
+import org.owasp.encoder.Encode;
+
+/**
+ * A tag to perform XML Encoding.
+ * This wraps the {@link org.owasp.encoder.Encode#forXml(java.lang.String)}.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlTag extends EncodingTag {
+    @Override
+    public void doTag() throws JspException, IOException {
+        Encode.forXml(getJspContext().getOut(), _value);
+    }
+}
diff --git a/jakarta/src/main/java9/module-info.java b/jakarta/src/main/java9/module-info.java
new file mode 100644
index 0000000..6f079b3
--- /dev/null
+++ b/jakarta/src/main/java9/module-info.java
@@ -0,0 +1,5 @@
+module owasp.encoder.jakarta {
+    requires owasp.encoder;
+    
+    exports org.owasp.encoder.tag;
+}
\ No newline at end of file
diff --git a/jakarta/src/main/resources/META-INF/LICENSE b/jakarta/src/main/resources/META-INF/LICENSE
new file mode 100644
index 0000000..f66c375
--- /dev/null
+++ b/jakarta/src/main/resources/META-INF/LICENSE
@@ -0,0 +1,33 @@
+Copyright (c) 2015 Jeff Ichnowski
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions
+are met:
+
+    * Redistributions of source code must retain the above
+      copyright notice, this list of conditions and the following
+      disclaimer.
+
+    * Redistributions in binary form must reproduce the above
+      copyright notice, this list of conditions and the following
+      disclaimer in the documentation and/or other materials
+      provided with the distribution.
+
+    * Neither the name of the OWASP nor the names of its
+      contributors may be used to endorse or promote products
+      derived from this software without specific prior written
+      permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+OF THE POSSIBILITY OF SUCH DAMAGE.
\ No newline at end of file
diff --git a/jakarta/src/main/resources/META-INF/java-encoder-advanced.tld b/jakarta/src/main/resources/META-INF/java-encoder-advanced.tld
new file mode 100644
index 0000000..335477e
--- /dev/null
+++ b/jakarta/src/main/resources/META-INF/java-encoder-advanced.tld
@@ -0,0 +1,560 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<taglib version="2.1" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-jsptaglibrary_2_1.xsd" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
+    <display-name>OWASP Java Encoder Project</display-name>
+    <tlib-version>1.0</tlib-version>
+    <short-name>java-encoder</short-name>
+    <uri>owasp.encoder.jakarta.advanced</uri>
+    <tag>
+        <description>
+            Encodes data for an XML CDATA section.  On the chance that the input
+            contains a terminating
+            &quot;]]&amp;gt;&quot;, it will be replaced by
+            &amp;quot;]]&amp;gt;]]&amp;lt;![CDATA[&amp;gt;&amp;quot;.
+            As with all XML contexts, characters that are invalid according to the
+            XML specification will be replaced by a space character.  Caller must
+            provide the CDATA section boundaries.
+        </description>
+        <display-name>forCDATA</display-name>
+        <name>forCDATA</name>
+        <tag-class>org.owasp.encoder.tag.ForCDATATag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>The value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			This method encodes for HTML text content.  It does not escape
+			quotation characters and is thus unsafe for use with
+			HTML attributes.  Use either forHtml or forHtmlAttribute for those
+			methods.
+        </description>
+        <display-name>forHtmlContent</display-name>
+        <name>forHtmlContent</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlContentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for XML and XHTML attribute content.</description>
+        <display-name>forXmlAttribute</display-name>
+        <name>forXmlAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for XML and XHTML.</description>
+        <display-name>forXml</display-name>
+        <name>forXml</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for a JavaScript string.  It is safe for use in HTML
+			script attributes (such as onclick), script
+			blocks, JSON files, and JavaScript source.  The caller MUST
+			provide the surrounding quotation characters for the string.
+			Since this performs additional encoding so it can work in all
+			of the JavaScript contexts listed, it may be slightly less
+			efficient then using one of the methods targetted to a specific
+			JavaScript context: forJavaScriptAttribute,
+			forJavaScriptBlock, or forJavaScriptSource.
+
+			Unless you are interested in saving a few bytes of output or
+			are writing a framework on top of this library, it is recommend
+			that you use this method over the others.
+        </description>
+        <display-name>forJavaScript</display-name>
+        <name>forJavaScript</name>
+        <tag-class>org.owasp.encoder.tag.ForJavaScriptTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			This method encodes for JavaScript strings contained within
+			HTML script attributes (such as onclick).  It is
+			NOT safe for use in script blocks.  The caller MUST provide the
+			surrounding quotation characters.  This method performs the
+			same encode as Encode.forJavaScript(String) with the
+			exception that / is not escaped.
+        </description>
+        <display-name>forJavaScriptAttribute</display-name>
+        <name>forJavaScriptAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForJavaScriptAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			This method encodes for JavaScript strings contained within
+			HTML script blocks.  It is NOT safe for use in script
+			attributes (such as onclick).  The caller must
+			provide the surrounding quotation characters.  This method
+			performs the same encode as Encode.forJavaScript(String)} with
+			the exception that " and ' are encoded as \" and \' respectively.
+        </description>
+        <display-name>forJavaScriptBlock</display-name>
+        <name>forJavaScriptBlock</name>
+        <tag-class>org.owasp.encoder.tag.ForJavaScriptBlockTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			This method encodes for JavaScript strings contained within
+			a JavaScript or JSON file. This method is NOT safe for
+			use in ANY context embedded in HTML. The caller must
+			provide the surrounding quotation characters.  This method
+			performs the same encode as Encode.forJavaScript(String) with
+			the exception that / and &amp; are not escaped and " and ' are
+			encoded as \" and \' respectively.
+        </description>
+        <display-name>forJavaScriptSource</display-name>
+        <name>forJavaScriptSource</name>
+        <tag-class>org.owasp.encoder.tag.ForJavaScriptSourceTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for unquoted HTML attribute values. forHtml(String) or
+			forHtmlAttribute(String) should usually be preferred over this
+			method as quoted attributes are XHTML compliant.
+        </description>
+        <display-name>forHtmlUnquotedAttribute</display-name>
+        <name>forHtmlUnquotedAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlUnquotedAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Performs percent-encoding of a URL according to RFC 3986.  The provided
+			URL is assumed to a valid URL.  This method does not do any checking on
+			the quality or safety of the URL itself.  In many applications it may
+			be better to use java.net.URI instead.  Note: this is a
+			particularly dangerous context to put untrusted content in, as for
+			example a "javascript:" URL provided by a malicious user would be
+			"properly" escaped, and still execute.
+        </description>
+        <display-name>forUri</display-name>
+        <name>forUri</name>
+        <tag-class>org.owasp.encoder.tag.ForUriTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for CSS URL contexts. The context must be surrounded by "url()".  It
+			is safe for use in both style blocks and attributes in HTML. Note: this does
+			not do any checking on the quality or safety of the URL itself.  The caller
+			should insure that the URL is safe for embedding (e.g. input validation) by
+			other means.
+        </description>
+        <display-name>forCssUrl</display-name>
+        <name>forCssUrl</name>
+        <tag-class>org.owasp.encoder.tag.ForCssUrlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encoder for XML comments. NOT FOR USE WITH (X)HTML CONTEXTS.
+			(X)HTML comments may be interpreted by browsers as something
+			other than a comment, typically in vendor specific extensions
+			(e.g. &amp;lt;--if[IE]--&amp;gt;.
+			For (X)HTML it is recommend that unsafe content never be included
+			in a comment.
+        </description>
+        <display-name>forXmlComment</display-name>
+        <name>forXmlComment</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlCommentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for HTML text attributes.</description>
+        <display-name>forHtmlAttribute</display-name>
+        <name>forHtmlAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for (X)HTML text content and text attributes.
+        </description>
+        <display-name>forHtml</display-name>
+        <name>forHtml</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for HTML text content.  It does not escape
+			quotation characters and is thus unsafe for use with
+			HTML attributes.  Use either forHtml or forHtmlAttribute for those
+			methods.
+        </description>
+        <display-name>forXmlContent</display-name>
+        <name>forXmlContent</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlContentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Performs percent-encoding for a component of a URI, such as a query
+			parameter name or value, path or query-string.  In particular this
+			method insures that special characters in the component do not get
+			interpreted as part of another component.
+        </description>
+        <display-name>forUriComponent</display-name>
+        <name>forUriComponent</name>
+        <tag-class>org.owasp.encoder.tag.ForUriComponentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+			Encodes for CSS strings. The context must be surrounded by quotation characters.
+			It is safe for use in both style blocks and attributes in HTML.
+        </description>
+        <display-name>forCssString</display-name>
+        <name>forCssString</name>
+        <tag-class>org.owasp.encoder.tag.ForCssStringTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <function>
+        <description>
+			Encodes for (X)HTML text content and text attributes.
+        </description>
+        <display-name>forHtml</display-name>
+        <name>forHtml</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtml(java.lang.String)</function-signature>
+        <example>forHtml(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			This method encodes for HTML text content.  It does not escape
+			quotation characters and is thus unsafe for use with
+			HTML attributes.  Use either forHtml or forHtmlAttribute for those
+			methods.
+        </description>
+        <display-name>forHtmlContent</display-name>
+        <name>forHtmlContent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlContent(java.lang.String)</function-signature>
+        <example>forHtmlContent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for HTML text attributes.</description>
+        <name>forHtmlAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlAttribute(java.lang.String)</function-signature>
+        <example>forHtmlAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encodes for unquoted HTML attribute values. forHtml(String) or
+			forHtmlAttribute(String) should usually be preferred over this
+			method as quoted attributes are XHTML compliant.
+        </description>
+        <display-name>forHtmlUnquotedAttribute</display-name>
+        <name>forHtmlUnquotedAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlUnquotedAttribute(java.lang.String)</function-signature>
+        <example>forHtmlUnquotedAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encodes for CSS strings. The context must be surrounded by quotation characters.
+			It is safe for use in both style blocks and attributes in HTML.
+        </description>
+        <display-name>forCssString</display-name>
+        <name>forCssString</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCssString(java.lang.String)</function-signature>
+        <example>forCssString(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encodes for CSS URL contexts. The context must be surrounded by "url()".  It
+			is safe for use in both style blocks and attributes in HTML. Note: this does
+			not do any checking on the quality or safety of the URL itself.  The caller
+			should insure that the URL is safe for embedding (e.g. input validation) by
+			other means.
+        </description>
+        <display-name>forCssUrl</display-name>
+        <name>forCssUrl</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCssUrl(java.lang.String)</function-signature>
+        <example>forCssUrl(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Performs percent-encoding of a URL according to RFC 3986.  The provided
+			URL is assumed to a valid URL.  This method does not do any checking on
+			the quality or safety of the URL itself.  In many applications it may
+			be better to use java.net.URI instead.  Note: this is a
+			particularly dangerous context to put untrusted content in, as for
+			example a "javascript:" URL provided by a malicious user would be
+			"properly" escaped, and still execute.
+        </description>
+        <display-name>forUri</display-name>
+        <name>forUri</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forUri(java.lang.String)</function-signature>
+        <example>forUri(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Performs percent-encoding for a component of a URI, such as a query
+			parameter name or value, path or query-string.  In particular this
+			method insures that special characters in the component do not get
+			interpreted as part of another component.
+        </description>
+        <display-name>forUriComponent</display-name>
+        <name>forUriComponent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forUriComponent(java.lang.String)</function-signature>
+        <example>forUriComponent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for XML and XHTML.</description>
+        <display-name>forXml</display-name>
+        <name>forXml</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXml(java.lang.String)</function-signature>
+        <example>forXml(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encodes for HTML text content.  It does not escape
+			quotation characters and is thus unsafe for use with
+			HTML attributes.  Use either forHtml or forHtmlAttribute for those
+			methods.
+        </description>
+        <display-name>forXmlContent</display-name>
+        <name>forXmlContent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXmlContent(java.lang.String)</function-signature>
+        <example>forXmlContent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for XML and XHTML attribute content.</description>
+        <display-name>forXmlAttribute</display-name>
+        <name>forXmlAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXmlAttribute(java.lang.String)</function-signature>
+        <example>forXmlAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encoder for XML comments. NOT FOR USE WITH (X)HTML CONTEXTS.
+			(X)HTML comments may be interpreted by browsers as something
+			other than a comment, typically in vendor specific extensions
+			(e.g. &amp;lt;--if[IE]--&amp;gt;.
+			For (X)HTML it is recommend that unsafe content never be included
+			in a comment.
+        </description>
+        <name>forXmlComment</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXmlComment(java.lang.String)</function-signature>
+        <example>forXmlComment(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes data for an XML CDATA section.  On the chance that the input
+            contains a terminating
+            &quot;]]&amp;gt;&quot;, it will be replaced by
+            &amp;quot;]]&amp;gt;]]&amp;lt;![CDATA[&amp;gt;&amp;quot;.
+            As with all XML contexts, characters that are invalid according to the
+            XML specification will be replaced by a space character.  Caller must
+            provide the CDATA section boundaries.
+        </description>
+        <display-name>forCDATA</display-name>
+        <name>forCDATA</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCDATA(java.lang.String)</function-signature>
+        <example>forCDATA(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			Encodes for a JavaScript string.  It is safe for use in HTML
+			script attributes (such as onclick), script
+			blocks, JSON files, and JavaScript source.  The caller MUST
+			provide the surrounding quotation characters for the string.
+			Since this performs additional encoding so it can work in all
+			of the JavaScript contexts listed, it may be slightly less
+			efficient then using one of the methods targetted to a specific
+			JavaScript context: forJavaScriptAttribute,
+			forJavaScriptBlock, or forJavaScriptSource.
+
+			Unless you are interested in saving a few bytes of output or
+			are writing a framework on top of this library, it is recommend
+			that you use this method over the others.
+        </description>
+        <display-name>forJavaScript</display-name>
+        <name>forJavaScript</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forJavaScript(java.lang.String)</function-signature>
+        <example>forJavaScript(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			This method encodes for JavaScript strings contained within
+			HTML script attributes (such as onclick).  It is
+			NOT safe for use in script blocks.  The caller MUST provide the
+			surrounding quotation characters.  This method performs the
+			same encode as Encode.forJavaScript(String) with the
+			exception that / is not escaped.
+        </description>
+        <display-name>forJavaScriptAttribute</display-name>
+        <name>forJavaScriptAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forJavaScriptAttribute(java.lang.String)</function-signature>
+        <example>forJavaScriptAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			This method encodes for JavaScript strings contained within
+			HTML script blocks.  It is NOT safe for use in script
+			attributes (such as onclick).  The caller must
+			provide the surrounding quotation characters.  This method
+			performs the same encode as Encode.forJavaScript(String)} with
+			the exception that " and ' are encoded as \" and \' respectively.
+        </description>
+        <display-name>forJavaScriptBlock</display-name>
+        <name>forJavaScriptBlock</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forJavaScriptBlock(java.lang.String)</function-signature>
+        <example>forJavaScriptBlock(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+			This method encodes for JavaScript strings contained within
+			a JavaScript or JSON file. This method is NOT safe for
+			use in ANY context embedded in HTML. The caller must
+			provide the surrounding quotation characters.  This method
+			performs the same encode as Encode.forJavaScript(String) with
+			the exception that / and &amp; are not escaped and " and ' are
+			encoded as \" and \' respectively.
+        </description>
+        <display-name>forJavaScriptSource</display-name>
+        <name>forJavaScriptSource</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forJavaScriptSource(java.lang.String)</function-signature>
+        <example>
+			&lt;%@page contentType="text/javascript; charset=UTF-8"%>
+			var data = '${forJavaScriptSource(unsafeData)}';
+        </example>
+    </function>
+</taglib>
\ No newline at end of file
diff --git a/jakarta/src/main/resources/META-INF/java-encoder.tld b/jakarta/src/main/resources/META-INF/java-encoder.tld
new file mode 100644
index 0000000..85dab09
--- /dev/null
+++ b/jakarta/src/main/resources/META-INF/java-encoder.tld
@@ -0,0 +1,406 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<taglib version="2.1" 
+        xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-jsptaglibrary_2_1.xsd" 
+        xmlns="http://java.sun.com/xml/ns/javaee" 
+        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
+    <display-name>OWASP Java Encoder Project</display-name>
+    <tlib-version>1.0</tlib-version>
+    <short-name>e</short-name>
+    <uri>owasp.encoder.jakarta</uri>
+    <tag>
+        <description>
+            Encodes data for an XML CDATA section.  On the chance that the input
+            contains a terminating
+            &quot;]]&amp;gt;&quot;, it will be replaced by
+            &amp;quot;]]&amp;gt;]]&amp;lt;![CDATA[&amp;gt;&amp;quot;.
+            As with all XML contexts, characters that are invalid according to the
+            XML specification will be replaced by a space character.  Caller must
+            provide the CDATA section boundaries.
+        </description>
+        <display-name>forCDATA</display-name>
+        <name>forCDATA</name>
+        <tag-class>org.owasp.encoder.tag.ForCDATATag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>The value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            This method encodes for HTML text content.  It does not escape
+            quotation characters and is thus unsafe for use with
+            HTML attributes.  Use either forHtml or forHtmlAttribute for those
+            methods.
+        </description>
+        <display-name>forHtmlContent</display-name>
+        <name>forHtmlContent</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlContentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for XML and XHTML attribute content.</description>
+        <display-name>forXmlAttribute</display-name>
+        <name>forXmlAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for XML and XHTML.</description>
+        <display-name>forXml</display-name>
+        <name>forXml</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for a JavaScript string.  It is safe for use in HTML
+            script attributes (such as onclick), script
+            blocks, JSON files, and JavaScript source.  The caller MUST
+            provide the surrounding quotation characters for the string.
+            Since this performs additional encoding so it can work in all
+            of the JavaScript contexts listed, it may be slightly less
+            efficient then using one of the methods targetted to a specific
+            JavaScript context: forJavaScriptAttribute,
+            forJavaScriptBlock, or forJavaScriptSource.
+
+            Unless you are interested in saving a few bytes of output or
+            are writing a framework on top of this library, it is recommend
+            that you use this method over the others.
+        </description>
+        <display-name>forJavaScript</display-name>
+        <name>forJavaScript</name>
+        <tag-class>org.owasp.encoder.tag.ForJavaScriptTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for unquoted HTML attribute values. forHtml(String) or
+            forHtmlAttribute(String) should usually be preferred over this
+            method as quoted attributes are XHTML compliant.
+        </description>
+        <display-name>forHtmlUnquotedAttribute</display-name>
+        <name>forHtmlUnquotedAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlUnquotedAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Performs percent-encoding of a URL according to RFC 3986.  The provided
+            URL is assumed to a valid URL.  This method does not do any checking on
+            the quality or safety of the URL itself.  In many applications it may
+            be better to use java.net.URI instead.  Note: this is a
+            particularly dangerous context to put untrusted content in, as for
+            example a "javascript:" URL provided by a malicious user would be
+            "properly" escaped, and still execute.
+        </description>
+        <display-name>forUri</display-name>
+        <name>forUri</name>
+        <tag-class>org.owasp.encoder.tag.ForUriTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for CSS URL contexts. The context must be surrounded by "url()".  It
+            is safe for use in both style blocks and attributes in HTML. Note: this does
+            not do any checking on the quality or safety of the URL itself.  The caller
+            should insure that the URL is safe for embedding (e.g. input validation) by
+            other means.
+        </description>
+        <display-name>forCssUrl</display-name>
+        <name>forCssUrl</name>
+        <tag-class>org.owasp.encoder.tag.ForCssUrlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>Encodes for HTML text attributes.</description>
+        <display-name>forHtmlAttribute</display-name>
+        <name>forHtmlAttribute</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlAttributeTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for (X)HTML text content and text attributes.
+        </description>
+        <display-name>forHtml</display-name>
+        <name>forHtml</name>
+        <tag-class>org.owasp.encoder.tag.ForHtmlTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for HTML text content.  It does not escape
+            quotation characters and is thus unsafe for use with
+            HTML attributes.  Use either forHtml or forHtmlAttribute for those
+            methods.
+        </description>
+        <display-name>forXmlContent</display-name>
+        <name>forXmlContent</name>
+        <tag-class>org.owasp.encoder.tag.ForXmlContentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Performs percent-encoding for a component of a URI, such as a query
+            parameter name or value, path or query-string.  In particular this
+            method insures that special characters in the component do not get
+            interpreted as part of another component.
+        </description>
+        <display-name>forUriComponent</display-name>
+        <name>forUriComponent</name>
+        <tag-class>org.owasp.encoder.tag.ForUriComponentTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <tag>
+        <description>
+            Encodes for CSS strings. The context must be surrounded by quotation characters.
+            It is safe for use in both style blocks and attributes in HTML.
+        </description>
+        <display-name>forCssString</display-name>
+        <name>forCssString</name>
+        <tag-class>org.owasp.encoder.tag.ForCssStringTag</tag-class>
+        <body-content>empty</body-content>
+        <attribute>
+            <description>value to be written out</description>
+            <name>value</name>
+            <required>true</required>
+            <rtexprvalue>true</rtexprvalue>
+            <type>java.lang.String</type>
+        </attribute>
+    </tag>
+    <function>
+        <description>
+            Encodes for (X)HTML text content and text attributes.
+        </description>
+        <display-name>forHtml</display-name>
+        <name>forHtml</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtml(java.lang.String)</function-signature>
+        <example>forHtml(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            This method encodes for HTML text content.  It does not escape
+            quotation characters and is thus unsafe for use with
+            HTML attributes.  Use either forHtml or forHtmlAttribute for those
+            methods.
+        </description>
+        <display-name>forHtmlContent</display-name>
+        <name>forHtmlContent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlContent(java.lang.String)</function-signature>
+        <example>forHtmlContent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for HTML text attributes.</description>
+        <name>forHtmlAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlAttribute(java.lang.String)</function-signature>
+        <example>forHtmlAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes for unquoted HTML attribute values. forHtml(String) or
+            forHtmlAttribute(String) should usually be preferred over this
+            method as quoted attributes are XHTML compliant.
+        </description>
+        <display-name>forHtmlUnquotedAttribute</display-name>
+        <name>forHtmlUnquotedAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forHtmlUnquotedAttribute(java.lang.String)</function-signature>
+        <example>forHtmlUnquotedAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes for CSS strings. The context must be surrounded by quotation characters.
+            It is safe for use in both style blocks and attributes in HTML.
+        </description>
+        <display-name>forCssString</display-name>
+        <name>forCssString</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCssString(java.lang.String)</function-signature>
+        <example>forCssString(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes for CSS URL contexts. The context must be surrounded by "url()".  It
+            is safe for use in both style blocks and attributes in HTML. Note: this does
+            not do any checking on the quality or safety of the URL itself.  The caller
+            should insure that the URL is safe for embedding (e.g. input validation) by
+            other means.
+        </description>
+        <display-name>forCssUrl</display-name>
+        <name>forCssUrl</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCssUrl(java.lang.String)</function-signature>
+        <example>forCssUrl(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Performs percent-encoding of a URL according to RFC 3986.  The provided
+            URL is assumed to a valid URL.  This method does not do any checking on
+            the quality or safety of the URL itself.  In many applications it may
+            be better to use java.net.URI instead.  Note: this is a
+            particularly dangerous context to put untrusted content in, as for
+            example a "javascript:" URL provided by a malicious user would be
+            "properly" escaped, and still execute.
+        </description>
+        <display-name>forUri</display-name>
+        <name>forUri</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forUri(java.lang.String)</function-signature>
+        <example>forUri(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Performs percent-encoding for a component of a URI, such as a query
+            parameter name or value, path or query-string.  In particular this
+            method insures that special characters in the component do not get
+            interpreted as part of another component.
+        </description>
+        <display-name>forUriComponent</display-name>
+        <name>forUriComponent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forUriComponent(java.lang.String)</function-signature>
+        <example>forUriComponent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for XML and XHTML.</description>
+        <display-name>forXml</display-name>
+        <name>forXml</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXml(java.lang.String)</function-signature>
+        <example>forXml(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes for HTML text content.  It does not escape
+            quotation characters and is thus unsafe for use with
+            HTML attributes.  Use either forHtml or forHtmlAttribute for those
+            methods.
+        </description>
+        <display-name>forXmlContent</display-name>
+        <name>forXmlContent</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXmlContent(java.lang.String)</function-signature>
+        <example>forXmlContent(unsafeData)</example>
+    </function>
+    <function>
+        <description>Encodes for XML and XHTML attribute content.</description>
+        <display-name>forXmlAttribute</display-name>
+        <name>forXmlAttribute</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forXmlAttribute(java.lang.String)</function-signature>
+        <example>forXmlAttribute(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes data for an XML CDATA section.  On the chance that the input
+            contains a terminating
+            &quot;]]&amp;gt;&quot;, it will be replaced by
+            &amp;quot;]]&amp;gt;]]&amp;lt;![CDATA[&amp;gt;&amp;quot;.
+            As with all XML contexts, characters that are invalid according to the
+            XML specification will be replaced by a space character.  Caller must
+            provide the CDATA section boundaries.
+        </description>
+        <display-name>forCDATA</display-name>
+        <name>forCDATA</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forCDATA(java.lang.String)</function-signature>
+        <example>forCDATA(unsafeData)</example>
+    </function>
+    <function>
+        <description>
+            Encodes for a JavaScript string.  It is safe for use in HTML
+            script attributes (such as onclick), script
+            blocks, JSON files, and JavaScript source.  The caller MUST
+            provide the surrounding quotation characters for the string.
+        </description>
+        <display-name>forJavaScript</display-name>
+        <name>forJavaScript</name>
+        <function-class>org.owasp.encoder.Encode</function-class>
+        <function-signature>java.lang.String forJavaScript(java.lang.String)</function-signature>
+        <example>forJavaScript(unsafeData)</example>
+    </function>
+</taglib>
\ No newline at end of file
diff --git a/jakarta/src/site/markdown/index.md b/jakarta/src/site/markdown/index.md
new file mode 100644
index 0000000..e2c305a
--- /dev/null
+++ b/jakarta/src/site/markdown/index.md
@@ -0,0 +1,31 @@
+## OWASP JSP
+
+The OWASP JSP Encoder is a collection of high-performance low-overhead
+contextual encoders that, when utilized correctly, is an effective tool in
+preventing Web Application security vulnerabilities such as Cross-Site
+Scripting (XSS).
+
+Please see the [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
+for more information on preventing XSS.
+
+### JSP Usage
+
+The JSP Encoder makes the use of the Java Encoder within JSP simple via a TLD that
+includes tags and a set of JSP EL functions:
+
+```xml
+<dependency>
+    <groupId>org.owasp.encoder</groupId>
+    <artifactId>encoder-jsp</artifactId>
+    <version>1.2.3</version>
+</dependency>
+```
+
+```JSP
+<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
+
+<%-- ... --%>
+
+<p>Dynamic data via EL: ${e:forHtml(param.value)}</p>
+<p>Dynamic data via tag: <e:forHtml value="${param.value}" /></p>
+```
diff --git a/jakarta/src/site/site.xml b/jakarta/src/site/site.xml
new file mode 100644
index 0000000..dde2b60
--- /dev/null
+++ b/jakarta/src/site/site.xml
@@ -0,0 +1,41 @@
+<?xml version="1.0" encoding="ISO-8859-1"?>
+<!--
+Copyright (c) 2015 Jeremy Long
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions
+are met:
+
+    * Redistributions of source code must retain the above
+      copyright notice, this list of conditions and the following
+      disclaimer.
+
+    * Redistributions in binary form must reproduce the above
+      copyright notice, this list of conditions and the following
+      disclaimer in the documentation and/or other materials
+      provided with the distribution.
+
+    * Neither the name of the OWASP nor the names of its
+      contributors may be used to endorse or promote products
+      derived from this software without specific prior written
+      permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+OF THE POSSIBILITY OF SUCH DAMAGE.
+
+-->
+<project name="JSP">
+    <body>
+    </body>
+</project>
\ No newline at end of file
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/EncodingTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/EncodingTagTest.java
new file mode 100644
index 0000000..4f49e8b
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/EncodingTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+package org.owasp.encoder.tag;
+
+import junit.framework.TestCase;
+import org.springframework.mock.web.MockHttpServletRequest;
+import org.springframework.mock.web.MockHttpServletResponse;
+import org.springframework.mock.web.MockPageContext;
+import org.springframework.mock.web.MockServletContext;
+
+/**
+ * EncodingTagTest is the base class for all unit tests for the tags.
+ * This sets up the ServletContext so that tags can be tested.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public abstract class EncodingTagTest extends TestCase {
+
+    protected MockServletContext _servletContext;
+    protected MockPageContext _pageContext;
+    protected MockHttpServletRequest _request;
+    protected MockHttpServletResponse _response;
+
+    /**
+     * Constructor for the EncodingTagTest
+     * @param testName the name of the test
+     */
+    public EncodingTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+        _servletContext = new MockServletContext();
+        _request = new MockHttpServletRequest();
+        _response = new MockHttpServletResponse();
+        _pageContext = new MockPageContext(_servletContext, _request, _response);
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForCDATATagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForCDATATagTest.java
new file mode 100644
index 0000000..c8e3847
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForCDATATagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForCDATATag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCDATATagTest extends EncodingTagTest {
+
+    public ForCDATATagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForCDATATag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForCDATATag instance = new ForCDATATag();
+        String value = "<div>]]></div>";
+        String expected = "<div>]]]]><![CDATA[></div>";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForCssStringTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForCssStringTagTest.java
new file mode 100644
index 0000000..0c9d6e8
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForCssStringTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForCssStringTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCssStringTagTest extends EncodingTagTest {
+
+    public ForCssStringTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForCssStringTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForCssStringTag instance = new ForCssStringTag();
+        String value = "<div>";
+        String expected = "\\3c div\\3e";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForCssUrlTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForCssUrlTagTest.java
new file mode 100644
index 0000000..77936c3
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForCssUrlTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForCssUrlTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForCssUrlTagTest extends EncodingTagTest {
+
+    public ForCssUrlTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForCssUrlTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForCssUrlTag instance = new ForCssUrlTag();
+        String value = "\\';";
+        String expected = "\\5c\\27;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected, results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlAttributeTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlAttributeTagTest.java
new file mode 100644
index 0000000..3c0c64f
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlAttributeTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForHtmlAttributeTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlAttributeTagTest extends EncodingTagTest {
+
+    public ForHtmlAttributeTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForHtmlAttributeTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForHtmlAttributeTag instance = new ForHtmlAttributeTag();
+        String value = "<div>";
+        String expected = "&lt;div>";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlContentTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlContentTagTest.java
new file mode 100644
index 0000000..ef6e389
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlContentTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForHtmlContentTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlContentTagTest extends EncodingTagTest {
+
+    public ForHtmlContentTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForHtmlContentTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForHtmlContentTag instance = new ForHtmlContentTag();
+        String value = "<div>";
+        String expected = "&lt;div&gt;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlTagTest.java
new file mode 100644
index 0000000..03897a7
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForHtmlTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlTagTest extends EncodingTagTest {
+
+    public ForHtmlTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForHtmlTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForHtmlTag instance = new ForHtmlTag();
+        String value = "<div>";
+        String expected = "&lt;div&gt;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTagTest.java
new file mode 100644
index 0000000..bce53a4
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForHtmlUnquotedAttributeTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForHtmlUnquotedAttributeTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForHtmlUnquotedAttributeTagTest extends EncodingTagTest {
+
+    public ForHtmlUnquotedAttributeTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForHtmlUnquotedAttributeTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForHtmlUnquotedAttributeTag instance = new ForHtmlUnquotedAttributeTag();
+        String value = "<div> </div>";
+        String expected = "&lt;div&gt;&#32;&lt;&#47;div&gt;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptAttributeTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptAttributeTagTest.java
new file mode 100644
index 0000000..ad38c07
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptAttributeTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForJavaScriptAttributeTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptAttributeTagTest extends EncodingTagTest {
+
+    public ForJavaScriptAttributeTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForJavaScriptAttributeTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForJavaScriptAttributeTag instance = new ForJavaScriptAttributeTag();
+        String value = "<div>\"\'";
+        String expected = "<div>\\x22\\x27";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptBlockTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptBlockTagTest.java
new file mode 100644
index 0000000..75cf97e
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptBlockTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForJavaScriptBlockTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptBlockTagTest extends EncodingTagTest {
+
+    public ForJavaScriptBlockTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForJavaScriptBlockTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForJavaScriptBlockTag instance = new ForJavaScriptBlockTag();
+        String value = "'\"\0";
+        String expected = "\\'\\\"\\x00";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptSourceTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptSourceTagTest.java
new file mode 100644
index 0000000..0ea95fc
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptSourceTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForJavaScriptSourceTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptSourceTagTest extends EncodingTagTest {
+
+    public ForJavaScriptSourceTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForJavaScriptSourceTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForJavaScriptSourceTag instance = new ForJavaScriptSourceTag();
+        String value = "\0'\"";
+        String expected = "\\x00\\'\\\"";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptTagTest.java
new file mode 100644
index 0000000..2d4f67a
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForJavaScriptTagTest.java
@@ -0,0 +1,46 @@
+/*
+ * To change this template, choose Tools | Templates
+ * and open the template in the editor.
+ */
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForJavaScriptTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForJavaScriptTagTest extends EncodingTagTest {
+
+    public ForJavaScriptTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForJavaScriptTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForJavaScriptTag instance = new ForJavaScriptTag();
+        String value = "\0'\"";
+        String expected = "\\x00\\x27\\x22";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForUriComponentTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForUriComponentTagTest.java
new file mode 100644
index 0000000..3d9d11c
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForUriComponentTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForUriComponentTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForUriComponentTagTest extends EncodingTagTest {
+
+    public ForUriComponentTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForUriComponentTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForUriComponentTag instance = new ForUriComponentTag();
+        String value = "&amp;=test";
+        String expected = "%26amp%3B%3Dtest";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForUriTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForUriTagTest.java
new file mode 100644
index 0000000..ac16812
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForUriTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForUriTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForUriTagTest extends EncodingTagTest {
+
+    public ForUriTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForUriTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForUriTag instance = new ForUriTag();
+        String value = "\\\"";
+        String expected = "%5C%22";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlAttributeTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlAttributeTagTest.java
new file mode 100644
index 0000000..4246516
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlAttributeTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForXmlAttributeTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlAttributeTagTest extends EncodingTagTest {
+
+    public ForXmlAttributeTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForXmlAttributeTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForXmlAttributeTag instance = new ForXmlAttributeTag();
+        String value = "<div>";
+        String expected = "&lt;div>";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlCommentTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlCommentTagTest.java
new file mode 100644
index 0000000..cea3db3
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlCommentTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForXmlCommentTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlCommentTagTest extends EncodingTagTest {
+
+    public ForXmlCommentTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForXmlCommentTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForXmlCommentTag instance = new ForXmlCommentTag();
+        String value = "--><script>alert(0)</script><!--";
+        String expected = "-~><script>alert(0)</script><!-~";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlContentTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlContentTagTest.java
new file mode 100644
index 0000000..536c265
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlContentTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForXmlContentTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlContentTagTest extends EncodingTagTest {
+
+    public ForXmlContentTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForXmlContentTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForXmlContentTag instance = new ForXmlContentTag();
+        String value = "<div>";
+        String expected = "&lt;div&gt;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlTagTest.java b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlTagTest.java
new file mode 100644
index 0000000..b55d2be
--- /dev/null
+++ b/jakarta/src/test/java/org/owasp/encoder/tag/ForXmlTagTest.java
@@ -0,0 +1,77 @@
+// Copyright (c) 2012 Jeff Ichnowski
+// All rights reserved.
+//
+// Redistribution and use in source and binary forms, with or without
+// modification, are permitted provided that the following conditions
+// are met:
+//
+//     * Redistributions of source code must retain the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer.
+//
+//     * Redistributions in binary form must reproduce the above
+//       copyright notice, this list of conditions and the following
+//       disclaimer in the documentation and/or other materials
+//       provided with the distribution.
+//
+//     * Neither the name of the OWASP nor the names of its
+//       contributors may be used to endorse or promote products
+//       derived from this software without specific prior written
+//       permission.
+//
+// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
+// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
+// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
+// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
+// OF THE POSSIBILITY OF SUCH DAMAGE.
+
+
+package org.owasp.encoder.tag;
+
+/**
+ * Simple tests for the ForXmlTag.
+ *
+ * @author Jeremy Long (jeremy.long@gmail.com)
+ */
+public class ForXmlTagTest extends EncodingTagTest {
+
+    public ForXmlTagTest(String testName) {
+        super(testName);
+    }
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Test of doTag method, of class ForXmlTag.
+     * This is a very simple test that doesn't fully
+     * exercise/test the encoder - only that the
+     * tag itself works.
+     * @throws Exception is thrown if the tag fails.
+     */
+    public void testDoTag() throws Exception {
+        System.out.println("doTag");
+        ForXmlTag instance = new ForXmlTag();
+        String value = "<div>";
+        String expected = "&lt;div&gt;";
+        instance.setJspContext(_pageContext);
+        instance.setValue(value);
+        instance.doTag();
+        String results = _response.getContentAsString();
+        assertEquals(expected,results);
+    }
+}
diff --git a/jsp/pom.xml b/jsp/pom.xml
index 2b9024c..6e9a08b 100644
--- a/jsp/pom.xml
+++ b/jsp/pom.xml
@@ -42,7 +42,7 @@
     <parent>
         <groupId>org.owasp.encoder</groupId>
         <artifactId>encoder-parent</artifactId>
-        <version>1.2.3</version>
+        <version>1.3.1</version>
     </parent>
 
     <artifactId>encoder-jsp</artifactId>
diff --git a/jsp/src/main/java9/module-info.java b/jsp/src/main/java9/module-info.java
new file mode 100644
index 0000000..8a1154a
--- /dev/null
+++ b/jsp/src/main/java9/module-info.java
@@ -0,0 +1,5 @@
+module owasp.encoder.jsp {
+    requires owasp.encoder;
+    
+    exports org.owasp.encoder.tag;
+}
\ No newline at end of file
diff --git a/pom.xml b/pom.xml
index 069f16f..deacc07 100755
--- a/pom.xml
+++ b/pom.xml
@@ -41,7 +41,7 @@
 
     <groupId>org.owasp.encoder</groupId>
     <artifactId>encoder-parent</artifactId>
-    <version>1.2.3</version>
+    <version>1.3.1</version>
     <packaging>pom</packaging>
 
     <name>OWASP Java Encoder Project</name>
@@ -55,6 +55,7 @@
     <modules>
         <module>core</module>
         <module>jsp</module>
+        <module>jakarta</module>
         <module>esapi</module>
     </modules>
 
@@ -93,11 +94,11 @@
     </distributionManagement>
     <mailingLists>
         <mailingList>
-            <name>Owasp-java-encoder-project</name>
-            <subscribe>https://lists.owasp.org/mailman/listinfo/owasp-java-encoder-project</subscribe>
-            <unsubscribe>https://lists.owasp.org/mailman/listinfo/owasp-java-encoder-project</unsubscribe>
-            <post>owasp-java-encoder-project@lists.owasp.org</post>
-            <archive>http://lists.owasp.org/pipermail/owasp-java-encoder-project/</archive>
+            <name>OWASP Java Encoder Issues at GitHub</name>
+            <subscribe>https://github.com/OWASP/owasp-java-encoder/issues</subscribe>
+            <unsubscribe>https://github.com/OWASP/owasp-java-encoder/issues</unsubscribe>
+            <post>https://github.com/OWASP/owasp-java-encoder/issues</post>
+            <archive>https://github.com/OWASP/owasp-java-encoder/issues</archive>
         </mailingList>
     </mailingLists>
 
@@ -167,7 +168,7 @@
                 <plugin>
                     <groupId>org.apache.maven.plugins</groupId>
                     <artifactId>maven-jar-plugin</artifactId>
-                    <version>3.2.2</version>
+                    <version>3.3.0</version>
                 </plugin>
                 <plugin>
                     <groupId>org.apache.maven.plugins</groupId>
@@ -241,7 +242,7 @@
                 <plugin>
                     <groupId>org.apache.felix</groupId>
                     <artifactId>maven-bundle-plugin</artifactId>
-                    <version>3.3.0</version>
+                    <version>3.5.1</version>
                 </plugin>
                 <plugin>
                     <groupId>org.codehaus.mojo</groupId>
@@ -265,10 +266,31 @@
             <plugin>
                 <groupId>org.apache.maven.plugins</groupId>
                 <artifactId>maven-compiler-plugin</artifactId>
-                <configuration>
-                    <source>1.6</source>
-                    <target>1.6</target>
-                </configuration>
+                <executions>
+                    <execution>
+                        <id>compile-java-8</id>
+                        <goals>
+                            <goal>compile</goal>
+                        </goals>
+                        <configuration>
+                            <release>8</release>
+                        </configuration>
+                    </execution>
+                    <execution>
+                        <id>compile-java-9</id>
+                        <phase>compile</phase>
+                        <goals>
+                            <goal>compile</goal>
+                        </goals>
+                        <configuration>
+                            <release>9</release>
+                            <compileSourceRoots> 
+                                <compileSourceRoot>${project.basedir}/src/main/java9</compileSourceRoot> 
+                            </compileSourceRoots> 
+                            <multiReleaseOutput>true</multiReleaseOutput>
+                        </configuration>
+                    </execution>
+                </executions>
             </plugin>
             <plugin>
                 <groupId>org.apache.felix</groupId>
@@ -319,15 +341,14 @@
             <plugin>
                 <groupId>org.apache.maven.plugins</groupId>
                 <artifactId>maven-jar-plugin</artifactId>
-                <executions>
-                    <execution>
-                        <id>default-jar</id>
-                        <phase>package</phase>
-                        <goals>
-                            <goal>jar</goal>
-                        </goals>
-                    </execution>
-                </executions>
+                <configuration>
+                    <archive>
+                        <manifestFile>${project.build.outputDirectory}/META-INF/MANIFEST.MF</manifestFile>
+                        <manifestEntries>
+                            <Multi-Release>true</Multi-Release>
+                        </manifestEntries>
+                    </archive>
+                </configuration>
             </plugin>
             <plugin>
                 <groupId>org.apache.maven.plugins</groupId>
@@ -345,6 +366,10 @@
             <plugin>
                 <groupId>org.apache.maven.plugins</groupId>
                 <artifactId>maven-javadoc-plugin</artifactId>
+                <configuration>
+                    <source>8</source>
+                    <failOnError>false</failOnError>
+                </configuration>
                 <executions>
                     <execution>
                         <id>attach-javadocs</id>
@@ -352,10 +377,6 @@
                         <goals>
                             <goal>jar</goal>
                         </goals>
-                        <configuration>
-                            <source>1.6</source>
-                            <failOnError>false</failOnError>
-                        </configuration>
                     </execution>
                 </executions>
             </plugin>
@@ -430,7 +451,7 @@
                 <groupId>org.apache.maven.plugins</groupId>
                 <artifactId>maven-pmd-plugin</artifactId>
                 <configuration>
-                    <targetJdk>1.5</targetJdk>
+                    <targetJdk>1.8</targetJdk>
                     <linkXref>true</linkXref>
                     <sourceEncoding>utf-8</sourceEncoding>
                 </configuration>
@@ -445,7 +466,7 @@
                             <report>javadoc</report>
                         </reports>
                         <configuration>
-                            <source>1.6</source>
+                            <source>8</source>
                             <failOnError>false</failOnError>
                         </configuration>
                     </reportSet>
@@ -492,5 +513,14 @@
                 </plugins>
             </build>
         </profile>
+        <profile>
+            <id>testJakarta</id>
+            <activation>
+                <activeByDefault>false</activeByDefault>
+            </activation>
+            <modules>
+                <module>jakarta-test</module>
+            </modules>
+        </profile>
     </profiles>
 </project>
```

