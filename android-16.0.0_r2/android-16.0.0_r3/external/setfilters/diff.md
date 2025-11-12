```diff
diff --git a/.github/workflows/maven.yml b/.github/workflows/maven.yml
new file mode 100644
index 0000000..98de559
--- /dev/null
+++ b/.github/workflows/maven.yml
@@ -0,0 +1,32 @@
+# This workflow will build a Java project with Maven, and cache/restore any dependencies to improve the workflow execution time
+# For more information see: https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-java-with-maven
+
+# This workflow uses actions that are not certified by GitHub.
+# They are provided by a third-party and are governed by
+# separate terms of service, privacy policy, and support
+# documentation.
+
+name: Java CI with Maven
+
+on:
+  push:
+    branches: [ "master" ]
+  pull_request:
+    branches: [ "master" ]
+
+jobs:
+  build:
+
+    runs-on: ubuntu-latest
+
+    steps:
+    - uses: actions/checkout@v4
+    - name: Set up JDK 17
+      uses: actions/setup-java@v3
+      with:
+        java-version: '17'
+        distribution: 'temurin'
+        cache: maven
+    - name: Build with Maven
+      run: mvn -B package --file pom.xml
+      
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..55120d0
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,18 @@
+name: setfilters release action
+run-name: ${{ github.actor }} is publishing release ${{ github.ref_name }}
+on:
+  release:
+    types: [published]
+jobs:
+  sha256:
+    name: sha256
+    runs-on: ubuntu-latest
+    steps:
+      - name: zip url
+        run: echo "${{ github.server_url }}/${{ github.repository }}/archive/refs/tags/${{ github.ref_name }}.zip"
+      - name: Create zip SHA256
+        run: curl -sL "${{ github.server_url }}/${{ github.repository }}/archive/refs/tags/${{ github.ref_name }}.zip" | shasum -a 256 | cut -d " " -f 1
+      - name: Tarball url
+        run: echo "${{ github.server_url }}/${{ github.repository }}/archive/refs/tags/${{ github.ref_name }}.tar.gz"
+      - name: Create tarball SHA256
+        run: curl -sL "${{ github.server_url }}/${{ github.repository }}/archive/refs/tags/${{ github.ref_name }}.tar.gz" | shasum -a 256 | cut -d " " -f 1
diff --git a/Android.bp b/Android.bp
index 5abb1cb..3a16453 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,13 +1,13 @@
 filegroup {
     name: "cuckoofilter_srcs",
-    srcs: ["java/com/google/setfilters/cuckoofilter/*.java"],
+    srcs: ["setfilters/src/com/google/setfilters/cuckoofilter/*.java"],
 }
 
 filegroup {
     name: "cuckoofilter_test_srcs",
-    srcs: ["javatests/com/google/setfilters/cuckoofilter/*.java"],
+    srcs: ["setfilters-tests/test/com/google/setfilters/cuckoofilter/*.java"],
     // For now exclude tests with mocks.
-    exclude_srcs: ["javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java"],
+    exclude_srcs: ["setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java"],
 }
 
 java_library {
diff --git a/METADATA b/METADATA
index 43dd621..4dfef18 100644
--- a/METADATA
+++ b/METADATA
@@ -1,14 +1,19 @@
-name: "setfilters"
-description:
-    "A library which contains a collection of space efficient set filters data "
-    "structures such as cuckoo filter."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/setfilters
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "setfilters"
+description: "A library which contains a collection of space efficient set filters data structures such as cuckoo filter."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/setfilters"
-  }
-  version: "1.0.0"
   license_type: NOTICE
-  last_upgrade_date { year: 2022 month: 9 day: 1 }
+  last_upgrade_date {
+    year: 2025
+    month: 4
+    day: 25
+  }
+  identifier {
+    type: "Archive"
+    value: "https://github.com/google/setfilters/archive/cb6a484fd6766c01743c7acd73971309ad3218f2.zip"
+    version: "cb6a484fd6766c01743c7acd73971309ad3218f2"
+  }
 }
diff --git a/OWNERS b/OWNERS
index b7dcc1a..7c38b19 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,3 @@
 kwlyeo@google.com
 jyseo@google.com
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
+include platform/system/core:main:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 27fe2dc..49386c8 100644
--- a/README.md
+++ b/README.md
@@ -1,6 +1,27 @@
-# Set filters library
+[![Build Status](https://github.com/google/setfilters/workflows/CI/badge.svg?branch=master)](https://github.com/google/setfilters/actions)
 
-This repository contains implementations of a collection set filter data structures.
+# Setfilters Library
+
+This repository contains implementations of a collection of set filter data structures, also commonly referred to as approximate membership query data structures. We will use the pronoun "Setfilters" to refer to the library.
+
+## Adding Setfilters library to your Java project
+
+### Maven
+
+Setfilters' Maven group ID is `com.google.setfilters`, and its artifact id is `setfilters`. To add dependency using Maven, add the following lines to your project's `pom.xml`: 
+
+```xml
+<dependency>
+  <groupId>com.google.setfilters</groupId>
+  <artifactId>setfilters</artifactId>
+  <version>1.0.0</version>
+</dependency>
+```
+
+## Supported Data Structures
+
+### Cuckoo Filter
+Cuckoo filter is a space efficient, approximate membershp query data structure that supports insertions and deletions. False positives are allowed (e.g. a non-member element may incorrectly be labeled as a member), but false negatives are not. The code for the cuckoo filter is located in [setfilters/src/com/google/setfilters/cuckoofilter/](https://github.com/google/setfilters/tree/master/setfilters/src/com/google/setfilters/cuckoofilter) directory. For example code on how to use the library, please see [examples/cuckoofilter/](https://github.com/google/setfilters/tree/master/examples/cuckoofilter).
 
 ## Note
 
diff --git a/WORKSPACE b/WORKSPACE
deleted file mode 100644
index 3d92a12..0000000
--- a/WORKSPACE
+++ /dev/null
@@ -1,47 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
-
-RULES_JVM_EXTERNAL_TAG = "4.2"
-
-RULES_JVM_EXTERNAL_SHA = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca"
-
-http_archive(
-    name = "rules_jvm_external",
-    sha256 = RULES_JVM_EXTERNAL_SHA,
-    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
-    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
-)
-
-load("@rules_jvm_external//:defs.bzl", "maven_install")
-
-GUAVA_VERSION = "27.1"
-
-ERROR_PRONE_VERSION = "2.14.0"
-
-maven_install(
-    artifacts = [
-        "com.google.errorprone:error_prone_annotation:%s" % ERROR_PRONE_VERSION,
-        "com.google.guava:guava:%s-jre" % GUAVA_VERSION,
-        "com.google.truth:truth:1.1",
-        "com.google.truth.extensions:truth-java8-extension:1.1.3",
-        "junit:junit:4.13",
-        "org.mockito:mockito-core:2.28.2",
-    ],
-    repositories = [
-        "https://repo1.maven.org/maven2",
-        "https://maven.google.com",
-    ],
-)
diff --git a/examples/cuckoofilter/README.md b/examples/cuckoofilter/README.md
new file mode 100644
index 0000000..172e6b7
--- /dev/null
+++ b/examples/cuckoofilter/README.md
@@ -0,0 +1,8 @@
+# Cuckoo Filter Example Code
+
+To run the code:
+
+```
+mvn package
+java -cp target/cuckoofilter-example-HEAD-jre-SNAPSHOT.jar com.google.setfilters.examples.cuckoofilter.CuckooFilterExample
+```
diff --git a/examples/cuckoofilter/pom.xml b/examples/cuckoofilter/pom.xml
new file mode 100644
index 0000000..059acce
--- /dev/null
+++ b/examples/cuckoofilter/pom.xml
@@ -0,0 +1,106 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
+  <modelVersion>4.0.0</modelVersion>
+
+  <groupId>com.google.setfilters</groupId>
+  <artifactId>cuckoofilter-example</artifactId>
+  <version>HEAD-jre-SNAPSHOT</version>
+  <url>https://github.com/google/setfilters</url>
+
+  <name>Cuckoo Filter Example</name>
+
+  <licenses>
+    <license>
+      <name>Apache License, Version 2.0</name>
+      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
+      <distribution>repo</distribution>
+    </license>
+  </licenses>
+
+  <build>
+    <sourceDirectory>src</sourceDirectory>
+    <testSourceDirectory>test</testSourceDirectory>
+    <resources>
+      <resource>
+        <directory>..</directory>
+        <includes>
+          <include>LICENSE</include>
+        </includes>
+        <targetPath>META-INF</targetPath>
+      </resource>
+    </resources>
+    <plugins>
+      <plugin>
+        <groupId>org.apache.maven.plugins</groupId>
+        <artifactId>maven-shade-plugin</artifactId>
+        <version>3.5.3</version>
+        <executions>
+          <execution>
+            <phase>package</phase>
+            <goals>
+              <goal>shade</goal>
+            </goals>
+            <configuration>
+              <transformers>
+                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
+                  <mainClass>
+                    com.google.setfilters.examples.cuckoofilter.CuckooFilterExample
+                  </mainClass>
+                </transformer>
+              </transformers>
+            </configuration>
+          </execution>
+        </executions>
+      </plugin>
+      <plugin>
+        <artifactId>maven-compiler-plugin</artifactId>
+        <version>3.8.1</version>
+        <configuration>
+          <source>1.8</source>
+          <target>1.8</target>
+          <encoding>UTF-8</encoding>
+          <parameters>true</parameters>
+          <compilerArgs>
+            <arg>-sourcepath</arg>
+            <arg>doesnotexist</arg>
+            <!-- https://errorprone.info/docs/installation#maven -->
+            <arg>-XDcompilePolicy=simple</arg>
+            <!-- -Xplugin:ErrorProne is set conditionally by a profile. -->
+          </compilerArgs>
+          <fork>true</fork>
+        </configuration>
+      </plugin>
+      <plugin>
+        <artifactId>maven-jar-plugin</artifactId>
+        <version>3.2.0</version>
+      </plugin>
+      <plugin>
+        <groupId>org.apache.maven.plugins</groupId>
+        <artifactId>maven-source-plugin</artifactId>
+        <version>2.2.1</version>
+        <executions>
+          <execution>
+            <id>attach-sources</id>
+            <goals>
+              <goal>jar-no-fork</goal>
+            </goals>
+          </execution>
+        </executions>
+      </plugin>
+    </plugins>
+  </build>
+
+  <dependencies>
+    <dependency>
+      <groupId>com.google.setfilters</groupId>
+      <artifactId>setfilters</artifactId>
+      <version>1.0.0</version>
+    </dependency>
+    <dependency>
+      <groupId>com.google.guava</groupId>
+      <artifactId>guava</artifactId>
+      <version>32.0.0-jre</version>
+    </dependency>
+  </dependencies>
+</project>
diff --git a/examples/cuckoofilter/src/CuckooFilterExample.java b/examples/cuckoofilter/src/CuckooFilterExample.java
new file mode 100644
index 0000000..1a3d728
--- /dev/null
+++ b/examples/cuckoofilter/src/CuckooFilterExample.java
@@ -0,0 +1,112 @@
+package com.google.setfilters.examples.cuckoofilter;
+
+import com.google.common.hash.Funnels;
+import com.google.setfilters.cuckoofilter.CuckooFilter;
+import com.google.setfilters.cuckoofilter.CuckooFilterConfig;
+import com.google.setfilters.cuckoofilter.CuckooFilterConfig.Size;
+import com.google.setfilters.cuckoofilter.CuckooFilterHashFunctions;
+import com.google.setfilters.cuckoofilter.CuckooFilterStrategies;
+import com.google.setfilters.cuckoofilter.SerializedCuckooFilterTable;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Random;
+
+public class CuckooFilterExample {
+
+  /**
+   * In this example code, we create a new cuckoo filter with 1,000,000 integers and configure the
+   * target false positive probability as 0.01.
+   */
+  public static void simpleExample() {
+    // Create a new cuckoo filter with 1,000,000 elements.
+    int numElements = 1000000;
+    CuckooFilterConfig config = CuckooFilterConfig.newBuilder()
+        .setSize(Size.computeEfficientSize(0.01, numElements))
+        .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
+        .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+        .build();
+    CuckooFilter<Integer> cuckooFilter = CuckooFilter.createNew(config, Funnels.integerFunnel());
+
+    // Insert 1,000,000 integers to the empty cuckoo filter.
+    HashSet<Integer> elements = new HashSet<>();
+    for (int i = 0; i < numElements; i++) {
+      elements.add(i);
+    }
+    for (int element : elements) {
+      if (!cuckooFilter.insert(element)) {
+        // This should not print.
+        System.out.println("Element " + element + " could not be inserted!");
+      }
+    }
+
+    // Verifies that all inserted elements are in the cuckoo filter, e.g. no false negatives.
+    if (hasFalseNegative(cuckooFilter, elements)) {
+      System.out.println("False negative in the cuckoo filter!");
+    }
+
+    // Computes (approximate) false positive rate. The printed false positive rate should be
+    // < 0.01, or approximately equal to it.
+    System.out.println("Estimated false positive rate: "
+        + computeFalsePositiveRate(cuckooFilter, elements, /* numRuns= */100000));
+
+    // Serialize the cuckoo filter.
+    SerializedCuckooFilterTable table = cuckooFilter.serializeTable();
+    byte [] rawTableBytes = table.asByteArray();
+    System.out.println("Serialized cuckoo filter size in bytes: " + rawTableBytes.length);
+
+    // Deserialize the serialized cuckoo filter.
+    SerializedCuckooFilterTable table2 =
+        SerializedCuckooFilterTable.createFromByteArray(rawTableBytes);
+    // Note that the hash function, strategy, and funnel objects are NOT part of the serialization.
+    // The same hash function, strategy, and funnel that were used to create the original cuckoo
+    // filter object must be supplied.
+    CuckooFilter<Integer> cuckooFilter2 =
+        CuckooFilter.createFromSerializedTable(table2, config.hashFunction(), config.strategy(),
+            Funnels.integerFunnel());
+
+    // Verify correctness of the deserialized filter.
+    // Verifies that all inserted elements are in the cuckoo filter, e.g. no false negatives.
+    if (hasFalseNegative(cuckooFilter2, elements)) {
+      System.out.println("False negative in the cuckoo filter!");
+    }
+
+    // Computes (approximate) false positive rate. The printed false positive rate should be
+    // < 0.01, or approximately equal to it.
+    System.out.println("Estimated false positive rate of deserialized cuckoo filter: "
+        + computeFalsePositiveRate(cuckooFilter2, elements, /* numRuns= */100000));
+  }
+
+  // Returns whether the given cuckoo filter has false negatives, with original elements
+  // as {@code elements}.
+  private static boolean hasFalseNegative(CuckooFilter<Integer> cuckooFilter,
+      HashSet<Integer> elements) {
+    for (int element : elements) {
+      if (!cuckooFilter.contains(element)) {
+        return true;
+      }
+    }
+    return false;
+  }
+
+  // Computes an estimated false positive rate of the given cuckoo filter by querying
+  // random non-member elements {@code numRuns} times.
+  private static double computeFalsePositiveRate(CuckooFilter<Integer> cuckooFilter,
+      HashSet<Integer> elements, int numRuns) {
+    Random random = new Random();
+    int falsePositiveCount = 0;
+    for (int i = 0; i < numRuns; i++) {
+      int randomElement;
+      do {
+        randomElement = random.nextInt();
+      } while (elements.contains(randomElement));
+      if (cuckooFilter.contains(randomElement)) {
+        falsePositiveCount++;
+      }
+    }
+    return (falsePositiveCount + 0.0) / numRuns;
+  }
+
+  public static void main (String[] args) {
+    simpleExample();
+  }
+}
diff --git a/java/com/google/setfilters/cuckoofilter/BUILD b/java/com/google/setfilters/cuckoofilter/BUILD
deleted file mode 100644
index 3fa3fc6..0000000
--- a/java/com/google/setfilters/cuckoofilter/BUILD
+++ /dev/null
@@ -1,28 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "cuckoofilter",
-    srcs = glob(
-        ["*.java"],
-    ),
-    deps = [
-        "//third_party/java/guava",
-        "//third_party/java/errorprone:annotations",
-    ],
-)
diff --git a/javatests/com/google/setfilters/cuckoofilter/BUILD b/javatests/com/google/setfilters/cuckoofilter/BUILD
deleted file mode 100644
index da4e5aa..0000000
--- a/javatests/com/google/setfilters/cuckoofilter/BUILD
+++ /dev/null
@@ -1,130 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_test")
-
-package(default_visibility = ["//visibility:public"])
-
-java_test(
-	name = "CuckooFilterArrayTest",
-	srcs = [
-		"CuckooFilterArrayTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "CuckooFilterTest",
-	srcs = [
-		"CuckooFilterTest.java",
-	],
-	size = "medium",
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "CuckooFilterConfigTest",
-	srcs = [
-		"CuckooFilterConfigTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "CuckooFilterHashFunctionsTest",
-	srcs = [
-		"CuckooFilterHashFunctionsTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "CuckooFilterStrategiesTest",
-	srcs = [
-		"CuckooFilterStrategiesTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "CuckooFilterTableTest",
-	srcs = [
-		"CuckooFilterTableTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "SemiSortedCuckooFilterTableTest",
-	srcs = [
-		"SemiSortedCuckooFilterTableTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
-
-java_test(
-	name = "SerializedCuckooFilterTableTest",
-	srcs = [
-		"SerializedCuckooFilterTableTest.java",
-	],
-	deps = [
-		"//third_party/java/guava",
-		"//third_party/java/junit",
-		"//third_party/java/truth",
-		"//third_party/java/mockito",
-		"//java/com/google/setfilters/cuckoofilter",
-	]
-)
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTest.java b/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTest.java
deleted file mode 100644
index 94d4e8d..0000000
--- a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTest.java
+++ /dev/null
@@ -1,323 +0,0 @@
-// Copyright 2022 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//    https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package com.google.setfilters.cuckoofilter;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import com.google.common.hash.Funnels;
-import java.util.Arrays;
-import java.util.List;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.Parameterized;
-import org.junit.runners.Parameterized.Parameter;
-import org.junit.runners.Parameterized.Parameters;
-
-@RunWith(Parameterized.class)
-public final class CuckooFilterTest {
-
-  @Parameters
-  public static List<? extends Object> data() {
-    return Arrays.asList(true, false);
-  }
-
-  @Parameter public boolean useSpaceOptimization;
-
-  private CuckooFilterConfig config =
-      CuckooFilterConfig.newBuilder()
-          .setSize(
-              CuckooFilterConfig.Size.newBuilder()
-                  .setBucketCount(100)
-                  .setBucketCapacity(4)
-                  .setFingerprintLength(16)
-                  .build())
-          .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
-          .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
-          .build();
-
-  private CuckooFilter<Integer> cuckooFilter;
-
-  @Before
-  public void setUp() {
-    config =
-        CuckooFilterConfig.newBuilder()
-            .setSize(
-                CuckooFilterConfig.Size.newBuilder()
-                    .setBucketCount(100)
-                    .setBucketCapacity(4)
-                    .setFingerprintLength(16)
-                    .build())
-            .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
-            .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
-            .setUseSpaceOptimization(useSpaceOptimization)
-            .build();
-    cuckooFilter = CuckooFilter.createNew(config, Funnels.integerFunnel());
-  }
-
-  @Test
-  public void insertAndContains() {
-    final int insertedElementsCount = 380;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.insert(i)).isTrue();
-    }
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.contains(i)).isTrue();
-    }
-
-    final int testCountNonExistentElements = 300;
-
-    for (int i = 0; i < testCountNonExistentElements; i++) {
-      assertThat(cuckooFilter.contains(i + insertedElementsCount)).isFalse();
-    }
-  }
-
-  @Test
-  public void insert_failsWhenFull_insertSameElements() {
-    // Exhaust two buckets that element 0 can belong to.
-    for (int i = 0; i < 2 * config.size().bucketCapacity(); i++) {
-      assertThat(cuckooFilter.insert(0)).isTrue();
-    }
-
-    assertThat(cuckooFilter.insert(0)).isFalse();
-  }
-
-  @Test
-  public void insert_insertFailureReversesTheReplacements() {
-    int insertedCount = 0;
-    while (true) {
-      if (!cuckooFilter.insert(insertedCount)) {
-        break;
-      }
-      insertedCount++;
-    }
-
-    for (int i = 0; i < insertedCount; i++) {
-      assertThat(cuckooFilter.contains(i)).isTrue();
-    }
-    assertThat(cuckooFilter.contains(insertedCount)).isFalse();
-  }
-
-  @Test
-  public void delete_deletesExistingElements() {
-    final int insertedElementsCount = 150;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.insert(i)).isTrue();
-      assertThat(cuckooFilter.insert(i)).isTrue();
-    }
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.delete(i)).isTrue();
-      assertThat(cuckooFilter.delete(i)).isTrue();
-    }
-  }
-
-  @Test
-  public void delete_deletingNonExistingElementsFails() {
-    final int insertedElementsCount = 150;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.delete(i)).isFalse();
-    }
-  }
-
-  @Test
-  public void size() {
-    assertThat(cuckooFilter.size()).isEqualTo(config.size());
-  }
-
-  @Test
-  public void count() {
-    final int insertedElementsCount = 300;
-    final int deletedElementCount = 150;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.insert(i)).isTrue();
-    }
-    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount);
-
-    for (int i = 0; i < deletedElementCount; i++) {
-      assertThat(cuckooFilter.delete(i)).isTrue();
-    }
-    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount - deletedElementCount);
-
-    // Attempt to delete non existing elements.
-    for (int i = 0; i < deletedElementCount; i++) {
-      assertThat(cuckooFilter.delete(insertedElementsCount + i)).isFalse();
-    }
-    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount - deletedElementCount);
-  }
-
-  @Test
-  public void serializeAndDeserialize() {
-    final int insertedElementsCount = 300;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.insert(i)).isTrue();
-    }
-
-    SerializedCuckooFilterTable serializedTable = cuckooFilter.serializeTable();
-
-    CuckooFilter<Integer> anotherCuckooFilter =
-        CuckooFilter.createFromSerializedTable(
-            serializedTable, config.hashFunction(), config.strategy(), Funnels.integerFunnel());
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(anotherCuckooFilter.contains(i)).isTrue();
-    }
-    assertThat(anotherCuckooFilter.contains(insertedElementsCount)).isFalse();
-  }
-
-  @Test
-  public void load() {
-    final int insertedElementsCount = 300;
-
-    for (int i = 0; i < insertedElementsCount; i++) {
-      assertThat(cuckooFilter.insert(i)).isTrue();
-    }
-
-    assertThat(cuckooFilter.load())
-        .isWithin(0.00000001)
-        .of(
-            (double) insertedElementsCount
-                / (config.size().bucketCount() * config.size().bucketCapacity()));
-  }
-
-  @Test
-  public void loadIsHigh() {
-    final int[] bucketCounts = {1000, 10000, 100000, 1000000};
-    final int[] bucketCapacities = {4, 5, 6, 7, 8};
-    final int fingerprintLength = 16;
-
-    for (int bucketCount : bucketCounts) {
-      for (int bucketCapacity : bucketCapacities) {
-        CuckooFilter<Integer> cuckooFilter =
-            CuckooFilter.createNew(
-                CuckooFilterConfig.newBuilder()
-                    .setSize(
-                        CuckooFilterConfig.Size.newBuilder()
-                            .setBucketCount(bucketCount)
-                            .setBucketCapacity(bucketCapacity)
-                            .setFingerprintLength(fingerprintLength)
-                            .build())
-                    .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
-                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
-                    .setUseSpaceOptimization(useSpaceOptimization)
-                    .build(),
-                Funnels.integerFunnel());
-
-        int element = 0;
-        while (cuckooFilter.insert(element)) {
-          element++;
-        }
-
-        assertThat(cuckooFilter.load()).isAtLeast(0.95);
-      }
-    }
-  }
-
-  @Test
-  public void computeEfficientSize_achievesTargetFalsePositiveRateAndCapacity() {
-    final double[] targetFalsePositiveRates = {0.05, 0.01, 0.001};
-    final long[] elementsCountUpperBounds = {100, 1000, 10000};
-
-    for (double targetFalsePositiveRate : targetFalsePositiveRates) {
-      for (long elementsCountUpperBound : elementsCountUpperBounds) {
-        CuckooFilter<Integer> cuckooFilter =
-            CuckooFilter.createNew(
-                CuckooFilterConfig.newBuilder()
-                    .setSize(
-                        CuckooFilterConfig.Size.computeEfficientSize(
-                            targetFalsePositiveRate, elementsCountUpperBound))
-                    .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
-                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
-                    .build(),
-                Funnels.integerFunnel());
-
-        int element = 0;
-        while (cuckooFilter.insert(element)) {
-          element++;
-        }
-
-        assertThat(computeFalsePositiveRate(cuckooFilter, 1000000))
-            .isAtMost(targetFalsePositiveRate);
-        assertThat(cuckooFilter.count()).isAtLeast(elementsCountUpperBound);
-      }
-    }
-  }
-
-  @Test
-  public void closeToTheoreticalFalsePositiveRate() {
-    final int bucketCount = 1000;
-    final int[] bucketCapacities = {2, 3, 4, 5, 6, 7, 8};
-    for (int bucketCapacity : bucketCapacities) {
-      // Due to time out issue, we only go up to 12 bits (otherwise we have to sample too many times
-      // to get a reliable measurement).
-      // TODO: Add a separate benchmark to test for longer fingerprint length.
-      for (int fingerprintLength = 8; fingerprintLength <= 12; fingerprintLength++) {
-        CuckooFilter<Integer> cuckooFilter =
-            CuckooFilter.createNew(
-                CuckooFilterConfig.newBuilder()
-                    .setSize(
-                        CuckooFilterConfig.Size.newBuilder()
-                            .setBucketCount(bucketCount)
-                            .setBucketCapacity(bucketCapacity)
-                            .setFingerprintLength(fingerprintLength)
-                            .build())
-                    .setHashFunction(CuckooFilterHashFunctions.MURMUR3_128)
-                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
-                    .build(),
-                Funnels.integerFunnel());
-
-        int element = 0;
-        while (cuckooFilter.insert(element)) {
-          element++;
-        }
-
-        // Let f = fingerprintLength. A random element not in the cuckoo filter has 1 / (2^f - 1)
-        // probability of matching a random fingerprint, and the probability it matches at least one
-        // of the x fingerprints is 1 - (1 - 1 / (2^f - 1))^x which is approximately x / (2^f - 1)
-        // when x << 2^f - 1.
-        //
-        // If X is a random variable denoting number of fingerprints in a randomly chosen two
-        // buckets, false positive probability is roughly E[X / (2^f - 1)] = E[X] / (2^f - 1).
-        // Let a be the cuckoo filter's load and b be the bucketCapacity. Then E[X] = a * 2b.
-        // Thus, theoretical false positive rate is ~ a * 2b / (2^f - 1).
-        double load = cuckooFilter.load();
-        double theoreticalFalsePositiveRate =
-            load * 2 * bucketCapacity / ((1 << fingerprintLength) - 1);
-
-        double relativeDiff =
-            Math.abs(computeFalsePositiveRate(cuckooFilter, 2000000) - theoreticalFalsePositiveRate)
-                / theoreticalFalsePositiveRate;
-        assertThat(relativeDiff).isAtMost(0.03);
-      }
-    }
-  }
-
-  private static double computeFalsePositiveRate(
-      CuckooFilter<Integer> cuckooFilter, int sampleCount) {
-    int falsePositiveCount = 0;
-    for (int i = 0; i < sampleCount; i++) {
-      if (cuckooFilter.contains(-i - 1)) {
-        falsePositiveCount++;
-      }
-    }
-    return (double) falsePositiveCount / sampleCount;
-  }
-}
diff --git a/pom.xml b/pom.xml
new file mode 100644
index 0000000..0f116ec
--- /dev/null
+++ b/pom.xml
@@ -0,0 +1,166 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
+  <modelVersion>4.0.0</modelVersion>
+
+  <groupId>com.google.setfilters</groupId>
+  <artifactId>setfilters-parent</artifactId>
+  <version>HEAD-jre-SNAPSHOT</version>
+  <packaging>pom</packaging>
+  <url>https://github.com/google/setfilters</url>
+
+  <name>Setfilters Main Parent</name>
+
+  <properties>
+    <errorprone.version>2.26.1</errorprone.version>
+    <guava.version>32.0.0-jre</guava.version>
+    <truth.version>1.1</truth.version>
+    <javac.version>9+181-r4173-1</javac.version>
+  </properties>
+
+  <licenses>
+    <license>
+      <name>Apache License, Version 2.0</name>
+      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
+      <distribution>repo</distribution>
+    </license>
+  </licenses>
+
+  <modules>
+    <module>setfilters</module>
+    <module>setfilters-tests</module>
+  </modules>
+
+  <distributionManagement>
+    <snapshotRepository>
+      <id>ossrh</id>
+      <url>https://s01.oss.sonatype.org/content/repositories/snapshots</url>
+    </snapshotRepository>
+    <repository>
+      <id>ossrh</id>
+      <url>https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/</url>
+    </repository>
+  </distributionManagement>
+
+  <build>
+    <sourceDirectory>src</sourceDirectory>
+    <testSourceDirectory>test</testSourceDirectory>
+    <resources>
+      <resource>
+        <directory>..</directory>
+        <includes>
+          <include>LICENSE</include>
+        </includes>
+        <targetPath>META-INF</targetPath>
+      </resource>
+    </resources>
+    <pluginManagement>
+      <plugins>
+        <plugin>
+          <artifactId>maven-compiler-plugin</artifactId>
+          <version>3.8.1</version>
+          <configuration>
+            <source>1.8</source>
+            <target>1.8</target>
+            <encoding>UTF-8</encoding>
+            <parameters>true</parameters>
+            <compilerArgs>
+              <arg>-sourcepath</arg>
+              <arg>doesnotexist</arg>
+              <!-- https://errorprone.info/docs/installation#maven -->
+              <arg>-XDcompilePolicy=simple</arg>
+              <!-- -Xplugin:ErrorProne is set conditionally by a profile. -->
+            </compilerArgs>
+            <annotationProcessorPaths>
+              <path>
+                <groupId>com.google.errorprone</groupId>
+                <artifactId>error_prone_core</artifactId>
+                <version>2.23.0</version>
+              </path>
+            </annotationProcessorPaths>
+            <fork>true</fork>
+          </configuration>
+        </plugin>
+        <plugin>
+          <artifactId>maven-jar-plugin</artifactId>
+          <version>3.2.0</version>
+        </plugin>
+        <plugin>
+          <groupId>org.apache.maven.plugins</groupId>
+          <artifactId>maven-source-plugin</artifactId>
+          <version>2.2.1</version>
+          <executions>
+            <execution>
+              <id>attach-sources</id>
+              <goals>
+                <goal>jar-no-fork</goal>
+              </goals>
+            </execution>
+          </executions>
+        </plugin>
+        <plugin>
+          <groupId>org.apache.maven.plugins</groupId>
+          <artifactId>maven-javadoc-plugin</artifactId>
+          <version>3.5.0</version>
+          <executions>
+            <execution>
+              <id>attach-javadocs</id>
+              <goals>
+                <goal>jar</goal>
+              </goals>
+            </execution>
+          </executions>
+          <configuration>
+            <javadocExecutable>${java.home}/bin/javadoc</javadocExecutable>
+          </configuration>
+        </plugin>
+        <plugin>
+          <artifactId>maven-dependency-plugin</artifactId>
+          <version>3.1.1</version>
+        </plugin>
+        <plugin>
+          <groupId>org.apache.maven.plugins</groupId>
+          <artifactId>maven-gpg-plugin</artifactId>
+          <version>1.5</version>
+          <executions>
+            <execution>
+              <id>sign-artifacts</id>
+              <phase>verify</phase>
+              <goals>
+                <goal>sign</goal>
+              </goals>
+            </execution>
+          </executions>
+        </plugin>
+      </plugins>
+    </pluginManagement>
+    <plugins>
+      <plugin>
+        <groupId>org.sonatype.plugins</groupId>
+        <artifactId>nexus-staging-maven-plugin</artifactId>
+        <version>1.6.7</version>
+        <extensions>true</extensions>
+        <configuration>
+          <serverId>ossrh</serverId>
+          <nexusUrl>https://s01.oss.sonatype.org/</nexusUrl>
+          <autoReleaseAfterClose>true</autoReleaseAfterClose>
+        </configuration>
+      </plugin>
+    </plugins>
+  </build>
+
+  <dependencyManagement>
+    <dependencies>
+      <dependency>
+        <groupId>com.google.errorprone</groupId>
+        <artifactId>error_prone_annotations</artifactId>
+        <version>${errorprone.version}</version>
+      </dependency>
+      <dependency>
+        <groupId>com.google.guava</groupId>
+        <artifactId>guava</artifactId>
+        <version>${guava.version}</version>
+      </dependency>
+    </dependencies>
+  </dependencyManagement>
+</project>
diff --git a/setfilters-tests/pom.xml b/setfilters-tests/pom.xml
new file mode 100644
index 0000000..8ec5c8d
--- /dev/null
+++ b/setfilters-tests/pom.xml
@@ -0,0 +1,70 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
+  <modelVersion>4.0.0</modelVersion>
+  <parent>
+    <groupId>com.google.setfilters</groupId>
+    <artifactId>setfilters-parent</artifactId>
+    <version>HEAD-jre-SNAPSHOT</version>
+  </parent>
+
+  <artifactId>setfilters-tests</artifactId>
+  <name>Setfilters Unit Tests</name>
+
+  <dependencies>
+    <dependency>
+      <groupId>${project.groupId}</groupId>
+      <artifactId>setfilters</artifactId>
+      <version>${project.version}</version>
+    </dependency>
+    <dependency>
+      <groupId>com.google.guava</groupId>
+      <artifactId>guava</artifactId>
+    </dependency>
+    <dependency>
+      <groupId>junit</groupId>
+      <artifactId>junit</artifactId>
+      <version>4.13.2</version>
+      <scope>test</scope>
+    </dependency>
+    <dependency>
+      <groupId>org.mockito</groupId>
+      <artifactId>mockito-core</artifactId>
+      <version>4.11.0</version>
+      <scope>test</scope>
+    </dependency>
+    <dependency>
+      <groupId>com.google.truth</groupId>
+      <artifactId>truth</artifactId>
+      <version>${truth.version}</version>
+      <scope>test</scope>
+    </dependency>
+    <dependency>
+      <groupId>com.google.truth.extensions</groupId>
+      <artifactId>truth-java8-extension</artifactId>
+      <version>${truth.version}</version>
+      <scope>test</scope>
+    </dependency>
+  </dependencies>
+
+  <build>
+    <resources>
+      <resource>
+        <directory>..</directory>
+        <includes>
+          <include>LICENSE</include>
+          <include>proguard/*</include>
+        </includes>
+        <targetPath>META-INF</targetPath>
+      </resource>
+    </resources>
+    <plugins>
+      <plugin>
+        <artifactId>maven-compiler-plugin</artifactId>
+      </plugin>
+      <plugin>
+        <artifactId>maven-source-plugin</artifactId>
+      </plugin>
+    </plugins>
+  </build>
+</project>
\ No newline at end of file
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterArrayTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterArrayTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/CuckooFilterArrayTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterArrayTest.java
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterConfigTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterConfigTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/CuckooFilterConfigTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterConfigTest.java
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctionsTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctionsTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctionsTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctionsTest.java
diff --git a/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterLargeTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterLargeTest.java
new file mode 100644
index 0000000..54d243f
--- /dev/null
+++ b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterLargeTest.java
@@ -0,0 +1,229 @@
+// Copyright 2024 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package com.google.setfilters.cuckoofilter;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.google.common.hash.Funnel;
+import com.google.common.hash.Funnels;
+import com.google.common.hash.HashCode;
+import com.google.common.hash.Hashing;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Random;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+
+@RunWith(Parameterized.class)
+public final class CuckooFilterLargeTest {
+
+  private static class GoodFastHashFunction implements CuckooFilterConfig.HashFunction {
+
+    @Override
+    public <T> HashCode hash(T element, Funnel<? super T> funnel) {
+      return Hashing.goodFastHash(128).hashObject(element, funnel);
+    }
+  }
+
+  @Parameters
+  public static List<Object[]> data() {
+    return Arrays.asList(new Object[][]{{new GoodFastHashFunction(), false},
+        {CuckooFilterHashFunctions.MURMUR3_128, true}});
+  }
+
+  @Parameter(0)
+  public CuckooFilterConfig.HashFunction hashFunction;
+
+  @Parameter(1)
+  public boolean useSpaceOptimization;
+
+  @Test
+  public void serializeAndDeserialize() {
+    final int insertedElementsCount = 100000000;
+    final double targetFalsePositiveRate = 0.001;
+
+    CuckooFilterConfig config =
+        CuckooFilterConfig.newBuilder()
+            .setSize(CuckooFilterConfig.Size.computeEfficientSize(
+                targetFalsePositiveRate, insertedElementsCount))
+            .setHashFunction(hashFunction)
+            .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+            .setUseSpaceOptimization(useSpaceOptimization)
+            .build();
+
+    CuckooFilter<Long> cuckooFilter = CuckooFilter.createNew(config, Funnels.longFunnel());
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.insert((long)i)).isTrue();
+    }
+
+    SerializedCuckooFilterTable serializedTable = cuckooFilter.serializeTable();
+
+    CuckooFilter<Long> anotherCuckooFilter =
+        CuckooFilter.createFromSerializedTable(
+            serializedTable, config.hashFunction(), config.strategy(), Funnels.longFunnel());
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(anotherCuckooFilter.contains((long)i)).isTrue();
+    }
+    assertThat(anotherCuckooFilter.contains((long)insertedElementsCount)).isFalse();
+  }
+
+  @Test
+  public void loadIsHigh() {
+    Random random = new Random();
+
+    final int[] bucketCounts = {1000, 10000, 100000, 1000000};
+    final int[] bucketCapacities = {4, 5, 6, 7, 8};
+    final int fingerprintLength = 16;
+
+    for (int bucketCount : bucketCounts) {
+      for (int bucketCapacity : bucketCapacities) {
+        CuckooFilter<Long> cuckooFilter =
+            CuckooFilter.createNew(
+                CuckooFilterConfig.newBuilder()
+                    .setSize(
+                        CuckooFilterConfig.Size.newBuilder()
+                            .setBucketCount(bucketCount)
+                            .setBucketCapacity(bucketCapacity)
+                            .setFingerprintLength(fingerprintLength)
+                            .build())
+                    .setHashFunction(hashFunction)
+                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+                    .setUseSpaceOptimization(useSpaceOptimization)
+                    .build(),
+                Funnels.longFunnel());
+
+        long element = 0;
+        do {
+          element = Math.abs(random.nextLong());
+        } while (cuckooFilter.insert(element));
+
+        assertThat(cuckooFilter.load()).isAtLeast(0.95);
+      }
+    }
+  }
+
+  @Test
+  public void computeEfficientSize_achievesTargetFalsePositiveRateAndCapacity() {
+    Random random = new Random();
+
+    final double[] targetFalsePositiveRates = {0.05, 0.01, 0.001};
+    final long[] elementsCountUpperBounds = {1, 5, 10, 50, 100, 500, 1000, 5000, 10000};
+
+    for (double targetFalsePositiveRate : targetFalsePositiveRates) {
+      for (long elementsCountUpperBound : elementsCountUpperBounds) {
+        CuckooFilter<Long> cuckooFilter =
+            CuckooFilter.createNew(
+                CuckooFilterConfig.newBuilder()
+                    .setSize(
+                        CuckooFilterConfig.Size.computeEfficientSize(
+                            targetFalsePositiveRate, elementsCountUpperBound))
+                    .setHashFunction(hashFunction)
+                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+                    .setUseSpaceOptimization(useSpaceOptimization)
+                    .build(),
+                Funnels.longFunnel());
+
+        long element = 0;
+        do {
+          element = Math.abs(random.nextLong());
+        } while (cuckooFilter.insert(element));
+
+        assertThat(computeFalsePositiveRate(cuckooFilter, 2000000))
+            .isAtMost(targetFalsePositiveRate);
+
+        if (elementsCountUpperBound < 10) {
+          assertThat(cuckooFilter.count()).isAtLeast(
+              (int) Math.ceil(0.5 * elementsCountUpperBound));
+        } else if (elementsCountUpperBound < 100) {
+          assertThat(cuckooFilter.count()).isAtLeast(
+              (int) Math.ceil(0.70 * elementsCountUpperBound));
+        } else if (elementsCountUpperBound == 100) {
+          assertThat(cuckooFilter.count()).isAtLeast(
+              (int) Math.ceil(0.95 * elementsCountUpperBound));
+        } else {
+          assertThat(cuckooFilter.count()).isAtLeast(elementsCountUpperBound);
+        }
+      }
+    }
+  }
+
+  @Test
+  public void closeToTheoreticalFalsePositiveRate() {
+    Random random = new Random();
+
+    final int bucketCount = 1000;
+    final int[] bucketCapacities = {2, 3, 4, 5, 6, 7, 8};
+    for (int bucketCapacity : bucketCapacities) {
+      // Due to time out issue, we only go up to 12 bits (otherwise we have to sample too many times
+      // to get a reliable measurement).
+      // TODO: Add a separate benchmark to test for longer fingerprint length.
+      for (int fingerprintLength = 8; fingerprintLength <= 12; fingerprintLength++) {
+        CuckooFilter<Long> cuckooFilter =
+            CuckooFilter.createNew(
+                CuckooFilterConfig.newBuilder()
+                    .setSize(
+                        CuckooFilterConfig.Size.newBuilder()
+                            .setBucketCount(bucketCount)
+                            .setBucketCapacity(bucketCapacity)
+                            .setFingerprintLength(fingerprintLength)
+                            .build())
+                    .setHashFunction(hashFunction)
+                    .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+                    .setUseSpaceOptimization(useSpaceOptimization)
+                    .build(),
+                Funnels.longFunnel());
+
+        long element = 0;
+        do {
+          element = Math.abs(random.nextLong());
+        } while (cuckooFilter.insert(element));
+
+        // Let f = fingerprintLength. A random element not in the cuckoo filter has 1 / (2^f - 1)
+        // probability of matching a random fingerprint, and the probability it matches at least one
+        // of the x fingerprints is 1 - (1 - 1 / (2^f - 1))^x which is approximately x / (2^f - 1)
+        // when x << 2^f - 1.
+        //
+        // If X is a random variable denoting number of fingerprints in a randomly chosen two
+        // buckets, false positive probability is roughly E[X / (2^f - 1)] = E[X] / (2^f - 1).
+        // Let a be the cuckoo filter's load and b be the bucketCapacity. Then E[X] = a * 2b.
+        // Thus, theoretical false positive rate is ~ a * 2b / (2^f - 1).
+        double load = cuckooFilter.load();
+        double theoreticalFalsePositiveRate =
+            load * 2 * bucketCapacity / ((1 << fingerprintLength) - 1);
+
+        double relativeDiff =
+            Math.abs(computeFalsePositiveRate(cuckooFilter, 2000000) - theoreticalFalsePositiveRate)
+                / theoreticalFalsePositiveRate;
+        assertThat(relativeDiff).isAtMost(0.04);
+      }
+    }
+  }
+
+  private static double computeFalsePositiveRate(
+      CuckooFilter<Long> cuckooFilter, int sampleCount) {
+    int falsePositiveCount = 0;
+    for (int i = 0; i < sampleCount; i++) {
+      if (cuckooFilter.contains((long)(-i - 1))) {
+        falsePositiveCount++;
+      }
+    }
+    return (double) falsePositiveCount / sampleCount;
+  }
+}
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterStrategiesTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterStrategiesTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/CuckooFilterStrategiesTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterStrategiesTest.java
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
similarity index 97%
rename from javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
index b5acf1a..5527682 100644
--- a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
+++ b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
@@ -15,9 +15,11 @@
 package com.google.setfilters.cuckoofilter;
 
 import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.Truth8.assertThat;
 import static org.junit.Assert.assertThrows;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
+import static org.mockito.Mockito.withSettings;
 
 import java.util.Arrays;
 import java.util.List;
@@ -72,7 +74,7 @@ public final class CuckooFilterTableTest {
 
   @Before
   public void setUp() {
-    random = mock(Random.class);
+    random = mock(Random.class, withSettings().withoutAnnotations());
     table =
         tableFactory.create(
             CuckooFilterConfig.Size.newBuilder()
diff --git a/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTest.java
new file mode 100644
index 0000000..ab8fc0b
--- /dev/null
+++ b/setfilters-tests/test/com/google/setfilters/cuckoofilter/CuckooFilterTest.java
@@ -0,0 +1,188 @@
+// Copyright 2022 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package com.google.setfilters.cuckoofilter;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.google.common.hash.Funnel;
+import com.google.common.hash.Funnels;
+import com.google.common.hash.HashCode;
+import com.google.common.hash.Hashing;
+import java.util.Arrays;
+import java.util.List;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+
+@RunWith(Parameterized.class)
+public final class CuckooFilterTest {
+
+  private static class Sha256HashFunction implements CuckooFilterConfig.HashFunction {
+    @Override
+    public <T> HashCode hash(T element, Funnel<? super T> funnel) {
+      return Hashing.sha256().hashObject(element, funnel);
+    }
+  }
+
+  @Parameters
+  public static List<Object[]> data() {
+    return Arrays.asList(new Object[][]{{new Sha256HashFunction(), true},
+        {CuckooFilterHashFunctions.MURMUR3_128, false}});
+  }
+
+  @Parameter(0)
+  public CuckooFilterConfig.HashFunction hashFunction;
+  @Parameter(1)
+  public boolean useSpaceOptimization;
+
+  private CuckooFilterConfig config;
+  private CuckooFilter<Integer> cuckooFilter;
+
+  @Before
+  public void setUp() {
+    config =
+        CuckooFilterConfig.newBuilder()
+            .setSize(
+                CuckooFilterConfig.Size.newBuilder()
+                    .setBucketCount(100)
+                    .setBucketCapacity(4)
+                    .setFingerprintLength(16)
+                    .build())
+            .setHashFunction(hashFunction)
+            .setStrategy(CuckooFilterStrategies.SIMPLE_MOD)
+            .setUseSpaceOptimization(useSpaceOptimization)
+            .build();
+    cuckooFilter = CuckooFilter.createNew(config, Funnels.integerFunnel());
+  }
+
+  @Test
+  public void insertAndContains() {
+    final int insertedElementsCount = 380;
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.insert(i)).isTrue();
+    }
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.contains(i)).isTrue();
+    }
+
+    final int testCountNonExistentElements = 300;
+
+    for (int i = 0; i < testCountNonExistentElements; i++) {
+      assertThat(cuckooFilter.contains(i + insertedElementsCount)).isFalse();
+    }
+  }
+
+  @Test
+  public void insert_failsWhenFull_insertSameElements() {
+    // Exhaust two buckets that element 0 can belong to.
+    for (int i = 0; i < 2 * config.size().bucketCapacity(); i++) {
+      assertThat(cuckooFilter.insert(0)).isTrue();
+    }
+
+    assertThat(cuckooFilter.insert(0)).isFalse();
+  }
+
+  @Test
+  public void insert_insertFailureReversesTheReplacements() {
+    int insertedCount = 0;
+    while (true) {
+      if (!cuckooFilter.insert(insertedCount)) {
+        break;
+      }
+      insertedCount++;
+    }
+
+    for (int i = 0; i < insertedCount; i++) {
+      assertThat(cuckooFilter.contains(i)).isTrue();
+    }
+    assertThat(cuckooFilter.contains(insertedCount)).isFalse();
+  }
+
+  @Test
+  public void delete_deletesExistingElements() {
+    final int insertedElementsCount = 150;
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.insert(i)).isTrue();
+      assertThat(cuckooFilter.insert(i)).isTrue();
+    }
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.delete(i)).isTrue();
+      assertThat(cuckooFilter.delete(i)).isTrue();
+    }
+  }
+
+  @Test
+  public void delete_deletingNonExistingElementsFails() {
+    final int insertedElementsCount = 150;
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.delete(i)).isFalse();
+    }
+  }
+
+  @Test
+  public void size() {
+    assertThat(cuckooFilter.size()).isEqualTo(config.size());
+  }
+
+  @Test
+  public void count() {
+    final int insertedElementsCount = 300;
+    final int deletedElementCount = 150;
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.insert(i)).isTrue();
+    }
+    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount);
+
+    for (int i = 0; i < deletedElementCount; i++) {
+      assertThat(cuckooFilter.delete(i)).isTrue();
+    }
+    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount - deletedElementCount);
+
+    // Attempt to delete non existing elements.
+    for (int i = 0; i < deletedElementCount; i++) {
+      assertThat(cuckooFilter.delete(insertedElementsCount + i)).isFalse();
+    }
+    assertThat(cuckooFilter.count()).isEqualTo(insertedElementsCount - deletedElementCount);
+  }
+
+  @Test
+  public void serializeAndDeserialize() {
+    final int insertedElementsCount = 300;
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(cuckooFilter.insert(i)).isTrue();
+    }
+
+    SerializedCuckooFilterTable serializedTable = cuckooFilter.serializeTable();
+
+    CuckooFilter<Integer> anotherCuckooFilter =
+        CuckooFilter.createFromSerializedTable(
+            serializedTable, config.hashFunction(), config.strategy(), Funnels.integerFunnel());
+
+    for (int i = 0; i < insertedElementsCount; i++) {
+      assertThat(anotherCuckooFilter.contains(i)).isTrue();
+    }
+    assertThat(anotherCuckooFilter.contains(insertedElementsCount)).isFalse();
+  }
+}
diff --git a/javatests/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTableTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTableTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTableTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTableTest.java
diff --git a/javatests/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTableTest.java b/setfilters-tests/test/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTableTest.java
similarity index 100%
rename from javatests/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTableTest.java
rename to setfilters-tests/test/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTableTest.java
diff --git a/setfilters/pom.xml b/setfilters/pom.xml
new file mode 100644
index 0000000..adc51c2
--- /dev/null
+++ b/setfilters/pom.xml
@@ -0,0 +1,52 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
+    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
+  <modelVersion>4.0.0</modelVersion>
+  <parent>
+    <groupId>com.google.setfilters</groupId>
+    <artifactId>setfilters-parent</artifactId>
+    <version>HEAD-jre-SNAPSHOT</version>
+  </parent>
+
+  <artifactId>setfilters</artifactId>
+  <name>Setfilters Main</name>
+  <url>https://github.com/google/setfilters</url>
+
+  <dependencies>
+    <dependency>
+      <groupId>com.google.errorprone</groupId>
+      <artifactId>error_prone_annotations</artifactId>
+    </dependency>
+    <dependency>
+      <groupId>com.google.guava</groupId>
+      <artifactId>guava</artifactId>
+    </dependency>
+  </dependencies>
+
+  <build>
+    <resources>
+      <resource>
+        <directory>..</directory>
+        <includes>
+          <include>LICENSE</include>
+          <include>proguard/*</include>
+        </includes>
+        <targetPath>META-INF</targetPath>
+      </resource>
+    </resources>
+    <plugins>
+      <plugin>
+        <artifactId>maven-compiler-plugin</artifactId>
+      </plugin>
+      <plugin>
+        <artifactId>maven-source-plugin</artifactId>
+      </plugin>
+      <plugin>
+        <artifactId>maven-javadoc-plugin</artifactId>
+      </plugin>
+      <plugin>
+        <artifactId>maven-gpg-plugin</artifactId>
+      </plugin>
+    </plugins>
+  </build>
+</project>
\ No newline at end of file
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilter.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilter.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilter.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilter.java
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilterArray.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterArray.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilterArray.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterArray.java
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java
similarity index 98%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java
index e8e2849..e42b6e6 100644
--- a/java/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java
+++ b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterConfig.java
@@ -162,7 +162,7 @@ public final class CuckooFilterConfig {
      * probability) with the given {@code targetFalsePositiveRate}.
      *
      * @throws IllegalArgumentException if {@code targetFalsePositiveRate} is not in range [0, 1] or
-     *     {@code elementsCountUpperBound} is <= 0, or a suitable cuckoo filter size could not be
+     *     {@code elementsCountUpperBound} is &lt;= 0, or a suitable cuckoo filter size could not be
      *     computed based on the given input.
      */
     public static Size computeEfficientSize(
@@ -245,7 +245,7 @@ public final class CuckooFilterConfig {
       /**
        * Sets the number of buckets in the cuckoo filter.
        *
-       * <p>{@code bucketCount} must be > 0.
+       * <p>{@code bucketCount} must be &gt; 0.
        */
       @CanIgnoreReturnValue
       public Builder setBucketCount(int bucketCount) {
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctions.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctions.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctions.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterHashFunctions.java
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java
similarity index 97%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java
index aeabb1d..0beaad2 100644
--- a/java/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java
+++ b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterStrategies.java
@@ -24,7 +24,7 @@ public enum CuckooFilterStrategies implements CuckooFilterConfig.Strategy {
    * A strategy that uses a mod operator to produce the desired outputs.
    *
    * <p>The {@link HashCode} generated with the hash function should be at least 64 bits. This will
-   * achieve good false positive rate when fingerprintLength <= 32.
+   * achieve good false positive rate when fingerprintLength &lt;= 32.
    */
   SIMPLE_MOD() {
     @Override
diff --git a/java/com/google/setfilters/cuckoofilter/CuckooFilterTable.java b/setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterTable.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/CuckooFilterTable.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/CuckooFilterTable.java
diff --git a/java/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTable.java b/setfilters/src/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTable.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTable.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/SemiSortedCuckooFilterTable.java
diff --git a/java/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTable.java b/setfilters/src/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTable.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTable.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/SerializedCuckooFilterTable.java
diff --git a/java/com/google/setfilters/cuckoofilter/UncompressedCuckooFilterTable.java b/setfilters/src/com/google/setfilters/cuckoofilter/UncompressedCuckooFilterTable.java
similarity index 100%
rename from java/com/google/setfilters/cuckoofilter/UncompressedCuckooFilterTable.java
rename to setfilters/src/com/google/setfilters/cuckoofilter/UncompressedCuckooFilterTable.java
diff --git a/third_party/java/errorprone/BUILD b/third_party/java/errorprone/BUILD
deleted file mode 100644
index c37a3f3..0000000
--- a/third_party/java/errorprone/BUILD
+++ /dev/null
@@ -1,23 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "annotations",
-    tags = ["maven:compile_only"],
-    exports = ["@maven//:com_google_errorprone_error_prone_annotations"],
-)
diff --git a/third_party/java/guava/BUILD b/third_party/java/guava/BUILD
deleted file mode 100644
index 93f6146..0000000
--- a/third_party/java/guava/BUILD
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "guava",
-    exports = [
-        "@maven//:com_google_guava_guava",
-    ],
-)
diff --git a/third_party/java/junit/BUILD b/third_party/java/junit/BUILD
deleted file mode 100644
index bb5ef43..0000000
--- a/third_party/java/junit/BUILD
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "junit",
-    testonly = 1,
-    exports = ["@maven//:junit_junit"],
-    #runtime_deps = ["//third_party/java/hamcrest"],
-)
diff --git a/third_party/java/mockito/BUILD b/third_party/java/mockito/BUILD
deleted file mode 100644
index fc03a5f..0000000
--- a/third_party/java/mockito/BUILD
+++ /dev/null
@@ -1,23 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "mockito",
-    testonly = 1,
-    exports = ["@maven//:org_mockito_mockito_core"],
-)
diff --git a/third_party/java/truth/BUILD b/third_party/java/truth/BUILD
deleted file mode 100644
index cbe2452..0000000
--- a/third_party/java/truth/BUILD
+++ /dev/null
@@ -1,26 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#    https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-load("@rules_java//java:defs.bzl", "java_library")
-
-package(default_visibility = ["//visibility:public"])
-
-java_library(
-    name = "truth",
-    testonly = 1,
-    exports = [
-        "@maven//:com_google_truth_extensions_truth_java8_extension",
-        "@maven//:com_google_truth_truth",
-    ],
-)
```

