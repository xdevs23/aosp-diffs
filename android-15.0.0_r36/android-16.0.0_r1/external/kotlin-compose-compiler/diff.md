```diff
diff --git a/Android.bp b/Android.bp
index 03d366d..5419b19 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,14 +5,14 @@ package {
 }
 
 java_import_host {
-    name: "kotlin-compose-compiler-plugin",
-    jars: ["org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar"],
+    name: "kotlin-compose-compiler-hosted",
+    jars: ["org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar"],
     sdk_version: "core_current",
 }
 
 java_import_host {
-    name: "kotlin-compose-compiler-plugin-embeddable",
-    jars: ["org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar"],
+    name: "kotlin-compose-compiler-embeddable",
+    jars: ["org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar"],
     sdk_version: "core_current",
 }
 
diff --git a/METADATA b/METADATA
index d5de636..7a7b2fa 100644
--- a/METADATA
+++ b/METADATA
@@ -3,14 +3,14 @@ description: "Contains the Kotlin compiler plugin for Compose"
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 6
-    day: 13
+    year: 2025
+    month: 03
+    day: 03
   }
   homepage: "https://kotlinlang.org/"
   identifier {
     type: "Archive"
-    value: "/placer/prod/home/kokoro-dedicated/build_artifacts/prod/android-studio/kotlin-verification-pipeline/verify-artifacts/release/729/20240711-053618/maven-2.0.0-release-341.zip"
+    value: "/placer/prod/home/kokoro-dedicated/build_artifacts/prod/android-studio/kotlin-verification-pipeline/verify-artifacts/release/992/20250228-105448/maven-2.1.10-release-473.zip"
   }
 }
 
diff --git a/OWNERS b/OWNERS
index b038ba9..335ca29 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,3 +4,4 @@ alanv@google.com
 ccross@android.com
 dwillemsen@google.com
 
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar
deleted file mode 100644
index 5e145fc..0000000
Binary files a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar and /dev/null differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.md5
deleted file mode 100644
index d713b57..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.md5
+++ /dev/null
@@ -1 +0,0 @@
-18ecffd5baf335760929d48885758b5a
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.sha1
deleted file mode 100644
index 4ca9d4a..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-2fb44a0a13396500655e91a66f292f0c9cb672dc
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.md5
deleted file mode 100644
index 9b43a79..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.md5
+++ /dev/null
@@ -1 +0,0 @@
-8533425f7736141d744b62024aeb429e
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.sha1
deleted file mode 100644
index 5a42c65..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom.sha1
+++ /dev/null
@@ -1 +0,0 @@
-068cc84640756ac043024a479158f1170689e445
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.md5
deleted file mode 100644
index f880fa6..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.md5
+++ /dev/null
@@ -1 +0,0 @@
-e7da4e3bb484677984d5da56c7671b24
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.sha1
deleted file mode 100644
index 7430251..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json.sha1
+++ /dev/null
@@ -1 +0,0 @@
-0e9743d9bed598f53ece0294e29971083f5f6ed0
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar.md5
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar.md5
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar.md5
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar.sha1
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-javadoc.jar.sha1
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-javadoc.jar.sha1
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar
new file mode 100644
index 0000000..5ab35e0
Binary files /dev/null and b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.md5
new file mode 100644
index 0000000..68e30f0
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.md5
@@ -0,0 +1 @@
+f691f0851d8f7100a61c1ad4744efaeb
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.sha1
new file mode 100644
index 0000000..5eb8626
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10-sources.jar.sha1
@@ -0,0 +1 @@
+0f059b150ac89e9c855d2759bbb5ec899af12824
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar
new file mode 100644
index 0000000..05271af
Binary files /dev/null and b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.md5
new file mode 100644
index 0000000..51cf496
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.md5
@@ -0,0 +1 @@
+e9904c356ad856a103822a39e133916d
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.sha1
new file mode 100644
index 0000000..1f1c1bf
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.jar.sha1
@@ -0,0 +1 @@
+dcfc85077bba083d6ab455950e439ec292ebef6a
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom
similarity index 97%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom
index 5444e4c..87bb3e6 100644
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.pom
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom
@@ -3,7 +3,7 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>org.jetbrains.kotlin</groupId>
   <artifactId>kotlin-compose-compiler-plugin-embeddable</artifactId>
-  <version>2.0.0</version>
+  <version>2.1.10</version>
   <name>Compose Compiler</name>
   <description>Compiler plugin that enables Compose</description>
   <url>https://kotlinlang.org/</url>
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.md5
new file mode 100644
index 0000000..6b3eb81
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.md5
@@ -0,0 +1 @@
+76f03d632be74468add0e48fba6a9ad3
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.sha1
new file mode 100644
index 0000000..adefe89
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.pom.sha1
@@ -0,0 +1 @@
+eb906d0ab7147c992f0d28ae4208a5b31f53a8fa
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json
similarity index 78%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json
index 5b2b0fa..621162b 100644
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0.spdx.json
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json
@@ -2,12 +2,12 @@
   "SPDXID" : "SPDXRef-DOCUMENT",
   "spdxVersion" : "SPDX-2.3",
   "creationInfo" : {
-    "created" : "2024-07-11T13:51:47Z",
+    "created" : "2025-02-28T20:16:45Z",
     "creators" : [ "Tool: spdx-gradle-plugin", "Organization: JetBrains s.r.o." ]
   },
   "name" : "compiler",
   "dataLicense" : "CC0-1.0",
-  "documentNamespace" : "https://www.jetbrains.com/spdxdocs/911cd5bc-e66b-4dfa-8258-f254267a8762",
+  "documentNamespace" : "https://www.jetbrains.com/spdxdocs/379a5a21-aff1-4d19-b941-213cdb82b4f2",
   "packages" : [ {
     "SPDXID" : "SPDXRef-gnrtd0",
     "copyrightText" : "NOASSERTION",
@@ -18,9 +18,9 @@
     "licenseDeclared" : "NOASSERTION",
     "licenseInfoFromFiles" : [ ],
     "name" : "compiler",
-    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.0.0#compiler[:plugins:compose-compiler-plugin:temp:compiler]",
+    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.1.10#compiler[:plugins:compose-compiler-plugin:compiler]",
     "supplier" : "Organization: JetBrains s.r.o.",
-    "versionInfo" : "2.0.0"
+    "versionInfo" : "2.1.10"
   } ],
   "relationships" : [ {
     "spdxElementId" : "SPDXRef-DOCUMENT",
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.md5
new file mode 100644
index 0000000..7228a2a
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.md5
@@ -0,0 +1 @@
+5635531c3ede4036c352629dea8e51af
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.sha1
new file mode 100644
index 0000000..6ae8ea1
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.1.10/kotlin-compose-compiler-plugin-embeddable-2.1.10.spdx.json.sha1
@@ -0,0 +1 @@
+ab46f8de2e4e3c759ef67a9ffe72a85acbe8459c
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar
deleted file mode 100644
index 1a746a2..0000000
Binary files a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar and /dev/null differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.md5
deleted file mode 100644
index e603965..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.md5
+++ /dev/null
@@ -1 +0,0 @@
-f43436d6bec321290f6af228ad602604
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.sha1
deleted file mode 100644
index 73cb899..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-javadoc.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-2ad14aed781c4a73ed4dbb421966d408a0a06686
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar
deleted file mode 100644
index 7a961da..0000000
Binary files a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar and /dev/null differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.md5
deleted file mode 100644
index fa4d300..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.md5
+++ /dev/null
@@ -1 +0,0 @@
-9c32852b10c8145978fb5555a2ba507f
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.sha1
deleted file mode 100644
index fbd0369..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0-sources.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-cb2f466e59f91fe706a233e768f0949157280869
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar
deleted file mode 100644
index 42524a8..0000000
Binary files a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar and /dev/null differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.md5
deleted file mode 100644
index be6d3f6..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.md5
+++ /dev/null
@@ -1 +0,0 @@
-db53e43931e83d29dbdb8c75aadd7a70
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.sha1
deleted file mode 100644
index 0af0859..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-877dd27cc13f50dd277cf35e4c6d017a3a2fc9f3
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.md5
deleted file mode 100644
index 7ab0b39..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.md5
+++ /dev/null
@@ -1 +0,0 @@
-3747495814c8bf5af06dfbdd9f39c2f6
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.sha1
deleted file mode 100644
index 1e1a989..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom.sha1
+++ /dev/null
@@ -1 +0,0 @@
-d9ede456fb8dcbbbb06348d8a60fd02a8cdc1159
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.md5
deleted file mode 100644
index 6bc8f20..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.md5
+++ /dev/null
@@ -1 +0,0 @@
-4a608bb9d3ec71e8428e96921760c450
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.sha1
deleted file mode 100644
index e397cca..0000000
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json.sha1
+++ /dev/null
@@ -1 +0,0 @@
-a6a49668815c4feaa2a6ac691559f7a322782902
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/MANIFEST.MF b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/MANIFEST.MF
new file mode 100644
index 0000000..58630c0
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/MANIFEST.MF
@@ -0,0 +1,2 @@
+Manifest-Version: 1.0
+
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CommandLineProcessor b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CommandLineProcessor
new file mode 100644
index 0000000..0141e62
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CommandLineProcessor
@@ -0,0 +1 @@
+androidx.compose.compiler.plugins.kotlin.ComposeCommandLineProcessor
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CompilerPluginRegistrar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CompilerPluginRegistrar
new file mode 100644
index 0000000..c98e915
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.compiler.plugin.CompilerPluginRegistrar
@@ -0,0 +1 @@
+androidx.compose.compiler.plugins.kotlin.ComposePluginRegistrar
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.diagnostics.rendering.DefaultErrorMessages$Extension b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.diagnostics.rendering.DefaultErrorMessages$Extension
new file mode 100644
index 0000000..d5259a2
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.diagnostics.rendering.DefaultErrorMessages$Extension
@@ -0,0 +1 @@
+androidx.compose.compiler.plugins.kotlin.k1.ComposeErrorMessages
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.fir.extensions.FirExtensionRegistrar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.fir.extensions.FirExtensionRegistrar
new file mode 100644
index 0000000..8e888e0
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/META-INF/services/org.jetbrains.kotlin.fir.extensions.FirExtensionRegistrar
@@ -0,0 +1 @@
+androidx.compose.compiler.plugins.kotlin.k2.ComposeFirExtensionRegistrar
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar.md5
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar.md5
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar.md5
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar.sha1
similarity index 100%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin-embeddable/2.0.0/kotlin-compose-compiler-plugin-embeddable-2.0.0-sources.jar.sha1
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-javadoc.jar.sha1
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar
new file mode 100644
index 0000000..5ab35e0
Binary files /dev/null and b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.md5
new file mode 100644
index 0000000..68e30f0
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.md5
@@ -0,0 +1 @@
+f691f0851d8f7100a61c1ad4744efaeb
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.sha1
new file mode 100644
index 0000000..5eb8626
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10-sources.jar.sha1
@@ -0,0 +1 @@
+0f059b150ac89e9c855d2759bbb5ec899af12824
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar
new file mode 100644
index 0000000..65fc631
Binary files /dev/null and b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar differ
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.md5
new file mode 100644
index 0000000..9dfc8b1
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.md5
@@ -0,0 +1 @@
+ffa3f1515a32355b0b45cfe8c1ddca86
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.sha1
new file mode 100644
index 0000000..d1793ff
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.jar.sha1
@@ -0,0 +1 @@
+c16a8c2d4f75dbf59d30d92703d8d78f0a3a4a68
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom
similarity index 96%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom
index 55728ae..fd36839 100644
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.pom
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom
@@ -3,7 +3,7 @@
   <modelVersion>4.0.0</modelVersion>
   <groupId>org.jetbrains.kotlin</groupId>
   <artifactId>kotlin-compose-compiler-plugin</artifactId>
-  <version>2.0.0</version>
+  <version>2.1.10</version>
   <name>AndroidX Compose Hosted Compiler Plugin</name>
   <description>Contains the Kotlin compiler plugin for Compose used in Android Studio and IDEA</description>
   <url>https://kotlinlang.org/</url>
@@ -32,7 +32,7 @@
     <dependency>
       <groupId>org.jetbrains.kotlin</groupId>
       <artifactId>kotlin-stdlib</artifactId>
-      <version>2.0.0</version>
+      <version>2.1.10</version>
       <scope>runtime</scope>
     </dependency>
   </dependencies>
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.md5
new file mode 100644
index 0000000..5c08116
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.md5
@@ -0,0 +1 @@
+f3518de9333a3b71c965cffba42fe6ad
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.sha1
new file mode 100644
index 0000000..f13c029
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.pom.sha1
@@ -0,0 +1 @@
+1342481884a9424edf8cd01da9f21c059fbf998f
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json
similarity index 88%
rename from org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json
rename to org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json
index ef600c8..48f301b 100644
--- a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.0.0/kotlin-compose-compiler-plugin-2.0.0.spdx.json
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json
@@ -2,12 +2,12 @@
   "SPDXID" : "SPDXRef-DOCUMENT",
   "spdxVersion" : "SPDX-2.3",
   "creationInfo" : {
-    "created" : "2024-07-11T13:51:47Z",
+    "created" : "2025-02-28T20:38:51Z",
     "creators" : [ "Tool: spdx-gradle-plugin", "Organization: JetBrains s.r.o." ]
   },
   "name" : "compiler-hosted",
   "dataLicense" : "CC0-1.0",
-  "documentNamespace" : "https://www.jetbrains.com/spdxdocs/c492a05e-18b2-40ea-a5c8-f643a5472dfd",
+  "documentNamespace" : "https://www.jetbrains.com/spdxdocs/a6ab0d06-53dd-4656-801d-b5d4363b65fc",
   "packages" : [ {
     "SPDXID" : "SPDXRef-gnrtd0",
     "copyrightText" : "NOASSERTION",
@@ -18,9 +18,9 @@
     "licenseDeclared" : "NOASSERTION",
     "licenseInfoFromFiles" : [ ],
     "name" : "compiler-hosted",
-    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.0.0#compiler-hosted[:plugins:compose-compiler-plugin:temp:compiler-hosted]",
+    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.1.10#compiler-hosted[:plugins:compose-compiler-plugin:compiler-hosted]",
     "supplier" : "Organization: JetBrains s.r.o.",
-    "versionInfo" : "2.0.0"
+    "versionInfo" : "2.1.10"
   }, {
     "SPDXID" : "SPDXRef-gnrtd1",
     "copyrightText" : "NOASSERTION",
@@ -31,9 +31,9 @@
     "licenseDeclared" : "NOASSERTION",
     "licenseInfoFromFiles" : [ ],
     "name" : "kotlin-stdlib",
-    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.0.0#kotlin-stdlib[:kotlin-stdlib]",
+    "sourceInfo" : "git+https://github.com/JetBrains/kotlin.git@v2.1.10#kotlin-stdlib[:kotlin-stdlib]",
     "supplier" : "Organization: JetBrains s.r.o.",
-    "versionInfo" : "2.0.0"
+    "versionInfo" : "2.1.10"
   }, {
     "SPDXID" : "SPDXRef-gnrtd2",
     "checksums" : [ {
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.md5 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.md5
new file mode 100644
index 0000000..c5b0f0b
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.md5
@@ -0,0 +1 @@
+f6033c7ae186cd9a3c0d03ab0646d290
\ No newline at end of file
diff --git a/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.sha1 b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.sha1
new file mode 100644
index 0000000..111dcd4
--- /dev/null
+++ b/org/jetbrains/kotlin/kotlin-compose-compiler-plugin/2.1.10/kotlin-compose-compiler-plugin-2.1.10.spdx.json.sha1
@@ -0,0 +1 @@
+d2ebc15455006fc36508f6e7b084ae125e49ccbe
\ No newline at end of file
```

