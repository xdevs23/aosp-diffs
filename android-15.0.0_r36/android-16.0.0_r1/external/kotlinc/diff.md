```diff
diff --git a/Android.bp b/Android.bp
index f6cadb5..859b5de 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,6 +32,12 @@ java_import {
     jars: ["lib/annotations-13.0.jar"],
 }
 
+
+kotlin_plugin {
+    name: "kotlin-compose-compiler-plugin",
+    static_libs: ["kotlin-compose-compiler-hosted"],
+}
+
 // exclude_dirs is used to remove META-INF resources for java multi-release
 // jar support that soong does not support. https://openjdk.java.net/jeps/238
 
@@ -103,6 +109,18 @@ kotlin_plugin {
     static_libs: ["kotlin-serialize-compiler-plugin-lib"],
 }
 
+java_import_host {
+    name: "kotlin-parcelize-compiler-plugin-lib",
+    jars: ["lib/parcelize-compiler.jar"],
+    sdk_version: "core_current",
+    exclude_dirs: ["META-INF/versions"],
+}
+
+kotlin_plugin {
+    name: "kotlin-parcelize-compiler-plugin",
+    static_libs: ["kotlin-parcelize-compiler-plugin-lib"],
+}
+
 // See: http://go/android-license-faq
 license {
     name: "external_kotlinc_license",
diff --git a/METADATA b/METADATA
index 5227c55..74ff03f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/kotlinc
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "kotlinc"
 description: "Standalone Kotlin command-line compiler tools."
@@ -8,15 +8,15 @@ third_party {
   license_type: RESTRICTED
   license_note: "would be RECIPROCAL save for:\n   license/third_party/rhino_LICENSE.txt\n   license/third_party/testdata/findbugs_license.txt\n   license/third_party/trove_license.txt\n   license/third_party/trove_readme_license.txt"
   last_upgrade_date {
-    year: 2024
-    month: 3
-    day: 18
+    year: 2025
+    month: 2
+    day: 24
   }
   homepage: "https://kotlinlang.org/"
   identifier {
     type: "Archive"
-    value: "https://github.com/JetBrains/kotlin/releases/download/v1.9.23/kotlin-compiler-1.9.23.zip"
-    version: "v1.9.23"
+    value: "https://github.com/JetBrains/kotlin/releases/download/v2.1.10/kotlin-compiler-2.1.10.zip"
+    version: "v2.1.10"
   }
   identifier {
     type: "Archive"
diff --git a/OWNERS b/OWNERS
index 56b8e30..a683c8e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@
 ccross@android.com
 dwillemsen@google.com
 pszczepaniak@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/bin/kotlin-dce-js b/bin/kotlin-dce-js
deleted file mode 100755
index 5526054..0000000
--- a/bin/kotlin-dce-js
+++ /dev/null
@@ -1,11 +0,0 @@
-#!/usr/bin/env bash
-
-# Copyright 2010-2021 JetBrains s.r.o. and Kotlin Programming Language contributors.
-# Use of this source code is governed by the Apache 2.0 license that can be found in the license/LICENSE.txt file.
-
-export KOTLIN_COMPILER=org.jetbrains.kotlin.cli.js.dce.K2JSDce
-
-DIR="${BASH_SOURCE[0]%/*}"
-: ${DIR:="."}
-
-"${DIR}"/kotlinc "$@"
diff --git a/bin/kotlin-dce-js.bat b/bin/kotlin-dce-js.bat
deleted file mode 100644
index fca25f7..0000000
--- a/bin/kotlin-dce-js.bat
+++ /dev/null
@@ -1,9 +0,0 @@
-@echo off
-
-rem Copyright 2010-2021 JetBrains s.r.o. and Kotlin Programming Language contributors.
-rem Use of this source code is governed by the Apache 2.0 license that can be found in the license/LICENSE.txt file.
-
-setlocal
-set _KOTLIN_COMPILER=org.jetbrains.kotlin.cli.js.dce.K2JSDce
-
-call %~dps0kotlinc.bat %*
diff --git a/bin/kotlinc b/bin/kotlinc
index 1c41064..56bee04 100755
--- a/bin/kotlinc
+++ b/bin/kotlinc
@@ -39,7 +39,7 @@ if $cygwin; then
     KOTLIN_HOME=`cygpath --windows --short-name "$KOTLIN_HOME"`
 fi
 
-[ -n "$JAVA_OPTS" ] || JAVA_OPTS="-Xmx256M -Xms128M"
+[ -n "$JAVA_OPTS" ] || JAVA_OPTS="-Xmx512M -Xms128M"
 
 declare -a java_args
 declare -a kotlin_args
diff --git a/bin/kotlinc.bat b/bin/kotlinc.bat
index c62a00f..60d1198 100644
--- a/bin/kotlinc.bat
+++ b/bin/kotlinc.bat
@@ -20,7 +20,7 @@ if not "%JAVA_HOME%"=="" (
 )
 
 rem We use the value of the JAVA_OPTS environment variable if defined
-if "%JAVA_OPTS%"=="" set JAVA_OPTS=-Xmx256M -Xms128M
+if "%JAVA_OPTS%"=="" set JAVA_OPTS=-Xmx512M -Xms128M
 
 rem Iterate through arguments and split them into java and kotlin ones
 :loop
diff --git a/build.txt b/build.txt
index a0a323c..df4a6b0 100644
--- a/build.txt
+++ b/build.txt
@@ -1 +1 @@
-1.9.23-release-779
\ No newline at end of file
+2.1.10-release-473
\ No newline at end of file
diff --git a/lib/allopen-compiler-plugin.jar b/lib/allopen-compiler-plugin.jar
index 18266d6..842dbdd 100644
Binary files a/lib/allopen-compiler-plugin.jar and b/lib/allopen-compiler-plugin.jar differ
diff --git a/lib/android-extensions-compiler.jar b/lib/android-extensions-compiler.jar
index 804e8b1..80581a4 100644
Binary files a/lib/android-extensions-compiler.jar and b/lib/android-extensions-compiler.jar differ
diff --git a/lib/android-extensions-runtime.jar b/lib/android-extensions-runtime.jar
index e3d97f1..520bf31 100644
Binary files a/lib/android-extensions-runtime.jar and b/lib/android-extensions-runtime.jar differ
diff --git a/lib/assignment-compiler-plugin.jar b/lib/assignment-compiler-plugin.jar
index 3ff9f78..84503c0 100644
Binary files a/lib/assignment-compiler-plugin.jar and b/lib/assignment-compiler-plugin.jar differ
diff --git a/lib/compose-compiler-plugin.jar b/lib/compose-compiler-plugin.jar
new file mode 100644
index 0000000..65fc631
Binary files /dev/null and b/lib/compose-compiler-plugin.jar differ
diff --git a/lib/js.engines.jar b/lib/js.engines.jar
index a4cf396..9c50d01 100644
Binary files a/lib/js.engines.jar and b/lib/js.engines.jar differ
diff --git a/lib/jvm-abi-gen.jar b/lib/jvm-abi-gen.jar
index 531220d..0c2dd00 100644
Binary files a/lib/jvm-abi-gen.jar and b/lib/jvm-abi-gen.jar differ
diff --git a/lib/kotlin-annotation-processing-cli.jar b/lib/kotlin-annotation-processing-cli.jar
index 559a76f..e32854b 100644
Binary files a/lib/kotlin-annotation-processing-cli.jar and b/lib/kotlin-annotation-processing-cli.jar differ
diff --git a/lib/kotlin-annotation-processing-compiler.jar b/lib/kotlin-annotation-processing-compiler.jar
index a97c7a8..42cc241 100644
Binary files a/lib/kotlin-annotation-processing-compiler.jar and b/lib/kotlin-annotation-processing-compiler.jar differ
diff --git a/lib/kotlin-annotation-processing-runtime.jar b/lib/kotlin-annotation-processing-runtime.jar
index 822338f..7b331a8 100644
Binary files a/lib/kotlin-annotation-processing-runtime.jar and b/lib/kotlin-annotation-processing-runtime.jar differ
diff --git a/lib/kotlin-annotation-processing.jar b/lib/kotlin-annotation-processing.jar
index 9e56620..30ef2e5 100644
Binary files a/lib/kotlin-annotation-processing.jar and b/lib/kotlin-annotation-processing.jar differ
diff --git a/lib/kotlin-annotations-jvm-sources.jar b/lib/kotlin-annotations-jvm-sources.jar
index ff9ccbd..5456fef 100644
Binary files a/lib/kotlin-annotations-jvm-sources.jar and b/lib/kotlin-annotations-jvm-sources.jar differ
diff --git a/lib/kotlin-annotations-jvm.jar b/lib/kotlin-annotations-jvm.jar
index ed1d861..0169d4a 100644
Binary files a/lib/kotlin-annotations-jvm.jar and b/lib/kotlin-annotations-jvm.jar differ
diff --git a/lib/kotlin-ant.jar b/lib/kotlin-ant.jar
index 4f998d8..9baf1a0 100644
Binary files a/lib/kotlin-ant.jar and b/lib/kotlin-ant.jar differ
diff --git a/lib/kotlin-compiler.jar b/lib/kotlin-compiler.jar
index 08538d7..ec2e6fd 100644
Binary files a/lib/kotlin-compiler.jar and b/lib/kotlin-compiler.jar differ
diff --git a/lib/kotlin-daemon-client.jar b/lib/kotlin-daemon-client.jar
index cb39328..d3304b5 100644
Binary files a/lib/kotlin-daemon-client.jar and b/lib/kotlin-daemon-client.jar differ
diff --git a/lib/kotlin-daemon.jar b/lib/kotlin-daemon.jar
index 8fe9849..44be6b5 100644
Binary files a/lib/kotlin-daemon.jar and b/lib/kotlin-daemon.jar differ
diff --git a/lib/kotlin-imports-dumper-compiler-plugin.jar b/lib/kotlin-imports-dumper-compiler-plugin.jar
index 852c863..ea5e2bf 100644
Binary files a/lib/kotlin-imports-dumper-compiler-plugin.jar and b/lib/kotlin-imports-dumper-compiler-plugin.jar differ
diff --git a/lib/kotlin-main-kts.jar b/lib/kotlin-main-kts.jar
index 9dd00d1..70284d1 100644
Binary files a/lib/kotlin-main-kts.jar and b/lib/kotlin-main-kts.jar differ
diff --git a/lib/kotlin-preloader.jar b/lib/kotlin-preloader.jar
index 10b5541..caead85 100644
Binary files a/lib/kotlin-preloader.jar and b/lib/kotlin-preloader.jar differ
diff --git a/lib/kotlin-reflect-sources.jar b/lib/kotlin-reflect-sources.jar
index 6efc4d8..f974d60 100644
Binary files a/lib/kotlin-reflect-sources.jar and b/lib/kotlin-reflect-sources.jar differ
diff --git a/lib/kotlin-reflect.jar b/lib/kotlin-reflect.jar
index fdab454..0a478aa 100644
Binary files a/lib/kotlin-reflect.jar and b/lib/kotlin-reflect.jar differ
diff --git a/lib/kotlin-runner.jar b/lib/kotlin-runner.jar
index fc59a46..8999433 100644
Binary files a/lib/kotlin-runner.jar and b/lib/kotlin-runner.jar differ
diff --git a/lib/kotlin-script-runtime-sources.jar b/lib/kotlin-script-runtime-sources.jar
index df232cf..6980c24 100644
Binary files a/lib/kotlin-script-runtime-sources.jar and b/lib/kotlin-script-runtime-sources.jar differ
diff --git a/lib/kotlin-script-runtime.jar b/lib/kotlin-script-runtime.jar
index a3d0a3d..a3d0516 100644
Binary files a/lib/kotlin-script-runtime.jar and b/lib/kotlin-script-runtime.jar differ
diff --git a/lib/kotlin-scripting-common.jar b/lib/kotlin-scripting-common.jar
index 1a59b5f..42757d5 100644
Binary files a/lib/kotlin-scripting-common.jar and b/lib/kotlin-scripting-common.jar differ
diff --git a/lib/kotlin-scripting-compiler-impl.jar b/lib/kotlin-scripting-compiler-impl.jar
index c55af2d..ecb98ca 100644
Binary files a/lib/kotlin-scripting-compiler-impl.jar and b/lib/kotlin-scripting-compiler-impl.jar differ
diff --git a/lib/kotlin-scripting-compiler.jar b/lib/kotlin-scripting-compiler.jar
index 235fdcf..b0b1bd8 100644
Binary files a/lib/kotlin-scripting-compiler.jar and b/lib/kotlin-scripting-compiler.jar differ
diff --git a/lib/kotlin-scripting-jvm.jar b/lib/kotlin-scripting-jvm.jar
index 697ccc9..3601ec2 100644
Binary files a/lib/kotlin-scripting-jvm.jar and b/lib/kotlin-scripting-jvm.jar differ
diff --git a/lib/kotlin-serialization-compiler-plugin.jar b/lib/kotlin-serialization-compiler-plugin.jar
index 6b4487b..067cdfe 100644
Binary files a/lib/kotlin-serialization-compiler-plugin.jar and b/lib/kotlin-serialization-compiler-plugin.jar differ
diff --git a/lib/kotlin-stdlib-jdk7.jar b/lib/kotlin-stdlib-jdk7.jar
index 6fea5e1..b8e2371 100644
Binary files a/lib/kotlin-stdlib-jdk7.jar and b/lib/kotlin-stdlib-jdk7.jar differ
diff --git a/lib/kotlin-stdlib-jdk8.jar b/lib/kotlin-stdlib-jdk8.jar
index aeebf1f..0aa678d 100644
Binary files a/lib/kotlin-stdlib-jdk8.jar and b/lib/kotlin-stdlib-jdk8.jar differ
diff --git a/lib/kotlin-stdlib-js-sources.jar b/lib/kotlin-stdlib-js-sources.jar
index 7a526a3..34b980a 100644
Binary files a/lib/kotlin-stdlib-js-sources.jar and b/lib/kotlin-stdlib-js-sources.jar differ
diff --git a/lib/kotlin-stdlib-js.jar b/lib/kotlin-stdlib-js.jar
deleted file mode 100644
index 8587c79..0000000
Binary files a/lib/kotlin-stdlib-js.jar and /dev/null differ
diff --git a/lib/kotlin-stdlib-js.klib b/lib/kotlin-stdlib-js.klib
index 64237a8..60e6f93 100644
Binary files a/lib/kotlin-stdlib-js.klib and b/lib/kotlin-stdlib-js.klib differ
diff --git a/lib/kotlin-stdlib-sources.jar b/lib/kotlin-stdlib-sources.jar
index 99b799e..e205b08 100644
Binary files a/lib/kotlin-stdlib-sources.jar and b/lib/kotlin-stdlib-sources.jar differ
diff --git a/lib/kotlin-stdlib.jar b/lib/kotlin-stdlib.jar
index b0728ef..30c64b7 100644
Binary files a/lib/kotlin-stdlib.jar and b/lib/kotlin-stdlib.jar differ
diff --git a/lib/kotlin-test-js-sources.jar b/lib/kotlin-test-js-sources.jar
index ec82620..414a59f 100644
Binary files a/lib/kotlin-test-js-sources.jar and b/lib/kotlin-test-js-sources.jar differ
diff --git a/lib/kotlin-test-js.jar b/lib/kotlin-test-js.jar
deleted file mode 100644
index 76282c8..0000000
Binary files a/lib/kotlin-test-js.jar and /dev/null differ
diff --git a/lib/kotlin-test-js.klib b/lib/kotlin-test-js.klib
new file mode 100644
index 0000000..d75ad26
Binary files /dev/null and b/lib/kotlin-test-js.klib differ
diff --git a/lib/kotlin-test-junit-sources.jar b/lib/kotlin-test-junit-sources.jar
index 6a3dd8c..a7511e4 100644
Binary files a/lib/kotlin-test-junit-sources.jar and b/lib/kotlin-test-junit-sources.jar differ
diff --git a/lib/kotlin-test-junit.jar b/lib/kotlin-test-junit.jar
index 06a7f5f..b60eb89 100644
Binary files a/lib/kotlin-test-junit.jar and b/lib/kotlin-test-junit.jar differ
diff --git a/lib/kotlin-test-junit5-sources.jar b/lib/kotlin-test-junit5-sources.jar
index 66987f4..d7802f3 100644
Binary files a/lib/kotlin-test-junit5-sources.jar and b/lib/kotlin-test-junit5-sources.jar differ
diff --git a/lib/kotlin-test-junit5.jar b/lib/kotlin-test-junit5.jar
index 89c880b..b69e966 100644
Binary files a/lib/kotlin-test-junit5.jar and b/lib/kotlin-test-junit5.jar differ
diff --git a/lib/kotlin-test-sources.jar b/lib/kotlin-test-sources.jar
index 34de918..5c386b8 100644
Binary files a/lib/kotlin-test-sources.jar and b/lib/kotlin-test-sources.jar differ
diff --git a/lib/kotlin-test-testng-sources.jar b/lib/kotlin-test-testng-sources.jar
index aa9f0cf..642b0b5 100644
Binary files a/lib/kotlin-test-testng-sources.jar and b/lib/kotlin-test-testng-sources.jar differ
diff --git a/lib/kotlin-test-testng.jar b/lib/kotlin-test-testng.jar
index b6f0826..ce0f002 100644
Binary files a/lib/kotlin-test-testng.jar and b/lib/kotlin-test-testng.jar differ
diff --git a/lib/kotlin-test.jar b/lib/kotlin-test.jar
index b7d1112..4302e51 100644
Binary files a/lib/kotlin-test.jar and b/lib/kotlin-test.jar differ
diff --git a/lib/kotlinx-coroutines-core-jvm.jar b/lib/kotlinx-coroutines-core-jvm.jar
index cfb2698..fb7d7d9 100644
Binary files a/lib/kotlinx-coroutines-core-jvm.jar and b/lib/kotlinx-coroutines-core-jvm.jar differ
diff --git a/lib/kotlinx-serialization-compiler-plugin.jar b/lib/kotlinx-serialization-compiler-plugin.jar
index 6b4487b..067cdfe 100644
Binary files a/lib/kotlinx-serialization-compiler-plugin.jar and b/lib/kotlinx-serialization-compiler-plugin.jar differ
diff --git a/lib/lombok-compiler-plugin.jar b/lib/lombok-compiler-plugin.jar
index 4b720ad..2c3fca5 100644
Binary files a/lib/lombok-compiler-plugin.jar and b/lib/lombok-compiler-plugin.jar differ
diff --git a/lib/noarg-compiler-plugin.jar b/lib/noarg-compiler-plugin.jar
index b75e48a..4493b7b 100644
Binary files a/lib/noarg-compiler-plugin.jar and b/lib/noarg-compiler-plugin.jar differ
diff --git a/lib/parcelize-compiler.jar b/lib/parcelize-compiler.jar
index 205e843..4179be3 100644
Binary files a/lib/parcelize-compiler.jar and b/lib/parcelize-compiler.jar differ
diff --git a/lib/parcelize-runtime.jar b/lib/parcelize-runtime.jar
index 0e7e295..6219c0f 100644
Binary files a/lib/parcelize-runtime.jar and b/lib/parcelize-runtime.jar differ
diff --git a/lib/power-assert-compiler-plugin.jar b/lib/power-assert-compiler-plugin.jar
new file mode 100644
index 0000000..0632390
Binary files /dev/null and b/lib/power-assert-compiler-plugin.jar differ
diff --git a/lib/sam-with-receiver-compiler-plugin.jar b/lib/sam-with-receiver-compiler-plugin.jar
index e410936..47deb4d 100644
Binary files a/lib/sam-with-receiver-compiler-plugin.jar and b/lib/sam-with-receiver-compiler-plugin.jar differ
diff --git a/lib/scripting-compiler.jar b/lib/scripting-compiler.jar
index 235fdcf..b0b1bd8 100644
Binary files a/lib/scripting-compiler.jar and b/lib/scripting-compiler.jar differ
diff --git a/license/COPYRIGHT.txt b/license/COPYRIGHT.txt
index 889fda8..8dc8226 100644
--- a/license/COPYRIGHT.txt
+++ b/license/COPYRIGHT.txt
@@ -1,5 +1,5 @@
 /*
- * Copyright 2010-2023 JetBrains s.r.o. and Kotlin Programming Language contributors.
+ * Copyright 2010-2024 JetBrains s.r.o. and Kotlin Programming Language contributors.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
diff --git a/license/COPYRIGHT_HEADER.txt b/license/COPYRIGHT_HEADER.txt
index 5c5ac72..3e86cd5 100644
--- a/license/COPYRIGHT_HEADER.txt
+++ b/license/COPYRIGHT_HEADER.txt
@@ -1,4 +1,4 @@
 /*
- * Copyright 2010-2023 JetBrains s.r.o. and Kotlin Programming Language contributors.
+ * Copyright 2010-2024 JetBrains s.r.o. and Kotlin Programming Language contributors.
  * Use of this source code is governed by the Apache 2.0 license that can be found in the license/LICENSE.txt file.
  */
\ No newline at end of file
diff --git a/license/NOTICE.txt b/license/NOTICE.txt
index dad8493..80dbbef 100644
--- a/license/NOTICE.txt
+++ b/license/NOTICE.txt
@@ -5,4 +5,4 @@
    =========================================================================
 
    Kotlin Compiler
-   Copyright 2010-2023 JetBrains s.r.o and respective authors and developers
+   Copyright 2010-2024 JetBrains s.r.o and respective authors and developers
diff --git a/license/README.md b/license/README.md
index 60cabbb..f6f281f 100644
--- a/license/README.md
+++ b/license/README.md
@@ -7,7 +7,7 @@ may apply:
 The following modules contain third-party code and are incorporated into the Kotlin compiler and/or
 the Kotlin IntelliJ IDEA plugin:
 
- - Path: compiler/backend/src/org/jetbrains/kotlin/codegen/inline/MaxStackFrameSizeAndLocalsCalculator.java
+ - Path: compiler/backend/src/org/jetbrains/kotlin/codegen/inline/MaxStackFrameSizeAndLocalsCalculator.kt
      - License: BSD ([license/third_party/asm_license.txt][asm])
      - Origin: Derived from ASM: a very small and fast Java bytecode manipulation framework, Copyright (c) 2000-2011 INRIA, France Telecom
    
@@ -65,7 +65,15 @@ the Kotlin IntelliJ IDEA plugin:
       - License: Apache 2 ([license/third_party/gwt_license.txt][gwt])
       - Origin: Derived from GWT, (C) 2007-08 Google Inc.
 
- - Path: libraries/stdlib/unsigned/src/kotlin/UnsignedUtils.kt
+ - Path: libraries/stdlib/js/src/kotlin/UnsignedJs.kt
+      - License: Apache 2 ([license/third_party/guava_license.txt][guava])
+      - Origin: Derived from Guava's UnsignedLongs, (C) 2011 The Guava Authors
+
+ - Path: libraries/stdlib/jvm/src/kotlin/util/UnsignedJVM.kt
+      - License: Apache 2 ([license/third_party/guava_license.txt][guava])
+      - Origin: Derived from Guava's UnsignedLongs, (C) 2011 The Guava Authors
+
+ - Path: kotlin-native/runtime/src/main/kotlin/kotlin/Unsigned.kt
       - License: Apache 2 ([license/third_party/guava_license.txt][guava])
       - Origin: Derived from Guava's UnsignedLongs, (C) 2011 The Guava Authors
 
@@ -81,14 +89,10 @@ the Kotlin IntelliJ IDEA plugin:
       - License: Apache 2 ([license/third_party/gwt_license.txt][gwt])
       - Origin: Derived from GWT, (C) 2007-08 Google Inc.
 
- - Path: libraries/stdlib/js-v1/src/js/long.js
+ - Path: libraries/stdlib/js/runtime/longJs.kt
       - License: Apache 2 ([license/third_party/closure-compiler_LICENSE.txt][closure-compiler])
       - Origin: Google Closure Library, Copyright 2009 The Closure Library Authors
 
- - Path: libraries/stdlib/js-v1/src/js/polyfills.js
-      - License: Boost Software License 1.0 ([license/third_party/boost_LICENSE.txt][boost])
-      - Origin: Derived from boost special math functions, Copyright Eric Ford & Hubert Holin 2001.
-
  - Path: libraries/stdlib/js/src/kotlin/js/math.polyfills.kt
       - License: Boost Software License 1.0 ([license/third_party/boost_LICENSE.txt][boost])
       - Origin: Derived from boost special math functions, Copyright Eric Ford & Hubert Holin 2001.
@@ -97,6 +101,14 @@ the Kotlin IntelliJ IDEA plugin:
       - License: Apache 2 ([license/third_party/assemblyscript_license.txt][assemblyscript])
       - Origin: Derived from assemblyscript standard library
 
+ - Path: libraries/tools/kotlin-power-assert
+      - License: Apache 2 ([license/third_party/power_assert_license.txt][power-assert])
+      - Origin: Copyright (C) 2020-2023 Brian Norman
+
+ - Path: plugins/compose
+      - License: Apache 2 ([license/third_party/compose_license.txt][compose])
+      - Origin: Copyright 2019-2024 The Android Open Source Project
+
  - Path: plugins/lint/android-annotations
       - License: Apache 2 ([license/third_party/aosp_license.txt][aosp])
       - Origin: Copyright (C) 2011-15 The Android Open Source Project
@@ -112,7 +124,11 @@ the Kotlin IntelliJ IDEA plugin:
  - Path: plugins/lint/lint-idea
       - License: Apache 2 ([license/third_party/aosp_license.txt][aosp])
       - Origin: Copyright (C) 2011-15 The Android Open Source Project
-          
+
+ - Path: plugins/power-assert
+      - License: Apache 2 ([license/third_party/power_assert_license.txt][power-assert])
+      - Origin: Copyright (C) 2020-2023 Brian Norman
+
  - Path: wasm/ir/src/org/jetbrains/kotlin/wasm/ir/convertors
       - License: MIT ([license/third_party/asmble_license.txt][asmble])
       - Origin: Copyright (C) 2018 Chad Retz
@@ -234,28 +250,13 @@ any distributions of the tools or libraries:
              and Eclipse Distribution License - v1.0 ([license/third_party/testdata/eclipse_distribution_license.txt][eclipse-distribution])
       - Origin: javax.persistence, Copyright (c) 2008, 2017 Sun Microsystems, Oracle Corporation.
 
+ - Path: libraries/tools/kotlin-gradle-plugin-integration-tests/src/test/resources/testProject/powerAssertSimple
+      - License: Apache 2 ([license/third_party/power_assert_license.txt][power-assert])
+      - Origin: Copyright (C) 2020-2023 Brian Norman
+
  - Path: libraries/tools/kotlin-gradle-plugin/src/common/kotlin/org/jetbrains/kotlin/gradle/targets/js/nodejs/Platform.kt
       - License: Apache License 2.0 ([license/third_party/gradle-node-plugin_LICENSE.txt](third_party/gradle-node-plugin_LICENSE.txt))
       - Origin: Copyright (c) 2013 node-gradle/gradle-node-plugin
-      
- - Path: libraries/tools/kotlin-test-js-runner/karma-kotlin-reporter.js
-      - License: MIT ([license/third_party/karma_LICENSE.txt](third_party/karma_LICENSE.txt)
-             and [license/third_party/karma-teamcity-reporter_LICENSE.txt](third_party/karma-teamcity-reporter_LICENSE.txt))
-      - Origin: Copyright (C) 2011-2019 Google, Inc. and Copyright (C) 2011-2013 Vojta Jína and contributors.
-      
- - Path: libraries/tools/kotlin-test-js-runner/mocha-kotlin-reporter.js
-      - License: MIT ([license/third_party/mocha-teamcity-reporter_LICENSE.txt](third_party/mocha-teamcity-reporter_LICENSE.txt))
-      - Origin: Copyright (c) 2016 Jamie Sherriff
-      
- - Path: libraries/tools/kotlin-test-js-runner/src/utils.ts
-      - License: MIT ([license/third_party/teamcity-service-messages_LICENSE.txt](third_party/teamcity-service-messages_LICENSE.txt)
-             and [license/third_party/lodash_LICENSE.txt](third_party/lodash_LICENSE.txt))
-      - Origin: Copyright (c) 2013 Aaron Forsander and Copyright JS Foundation and other contributors <https://js.foundation/>
-      
- - Path: libraries/tools/kotlin-test-js-runner/src/teamcity-format.js
-      - License: MIT ([license/third_party/mocha-teamcity-reporter_LICENSE.txt](third_party/mocha-teamcity-reporter_LICENSE.txt)
-             and [license/third_party/teamcity-service-messages_LICENSE.txt](third_party/teamcity-service-messages_LICENSE.txt))
-      - Origin: Copyright (c) 2016 Jamie Sherriff and Copyright (c) 2013 Aaron Forsander
 
 ## Example Code
 
@@ -276,6 +277,7 @@ any distributions of the compiler, libraries or plugin:
 [assemblyscript]: third_party/assemblyscript_license.txt
 [boost]: third_party/boost_LICENSE.txt
 [closure-compiler]: third_party/closure-compiler_LICENSE.txt
+[compose]: third_party/compose_license.txt
 [dagger]: third_party/testdata/dagger_license.txt
 [dart]: third_party/dart_LICENSE.txt
 [eclipse]: third_party/testdata/eclipse_license.txt
@@ -287,6 +289,7 @@ any distributions of the compiler, libraries or plugin:
 [jquery]: third_party/jquery_license.txt
 [jspecify]: third_party/testdata/jspecify_license.txt
 [lombok]: third_party/testdata/lombok_license.txt
+[power-assert]: third_party/power_assert_license.txt
 [qunit]: third_party/qunit_license.txt
 [rhino]: third_party/rhino_LICENSE.txt
 [rxjava]: third_party/testdata/rxjava_license.txt
diff --git a/license/third_party/compose_license.txt b/license/third_party/compose_license.txt
new file mode 100644
index 0000000..e454a52
--- /dev/null
+++ b/license/third_party/compose_license.txt
@@ -0,0 +1,178 @@
+
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
diff --git a/license/third_party/power_assert_license.txt b/license/third_party/power_assert_license.txt
new file mode 100644
index 0000000..d645695
--- /dev/null
+++ b/license/third_party/power_assert_license.txt
@@ -0,0 +1,202 @@
+
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
+   APPENDIX: How to apply the Apache License to your work.
+
+      To apply the Apache License to your work, attach the following
+      boilerplate notice, with the fields enclosed by brackets "[]"
+      replaced with your own identifying information. (Don't include
+      the brackets!)  The text should be enclosed in the appropriate
+      comment syntax for the file format. We also recommend that a
+      file or class name and description of purpose be included on the
+      same "printed page" as the copyright notice for easier
+      identification within third-party archives.
+
+   Copyright [yyyy] [name of copyright owner]
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+   You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+   Unless required by applicable law or agreed to in writing, software
+   distributed under the License is distributed on an "AS IS" BASIS,
+   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+   See the License for the specific language governing permissions and
+   limitations under the License.
```

