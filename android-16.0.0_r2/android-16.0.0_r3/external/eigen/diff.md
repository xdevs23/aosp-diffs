```diff
diff --git a/Android.bp b/Android.bp
index b25791bd7..a14e05891 100644
--- a/Android.bp
+++ b/Android.bp
@@ -92,6 +92,7 @@ cc_library_headers {
         "com.android.neuralnetworks",
         "//apex_available:platform",
         "com.android.ondevicepersonalization",
+        "com.android.appsearch",
     ],
     min_sdk_version: "apex_inherit",
     sdk_version: "current",
diff --git a/METADATA b/METADATA
index 368b974e0..c532d4dd7 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "eigen"
-description:
-    "C++ template library for linear algebra: matrices, vectors, numerical solvers, and related algorithms."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/eigen
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "eigen"
+description: "C++ template library for linear algebra: matrices, vectors, numerical solvers, and related algorithms."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://eigen.tuxfamily.org/"
+  license_type: RECIPROCAL
+  last_upgrade_date {
+    year: 2022
+    month: 2
+    day: 25
   }
-  url {
-    type: GIT
+  homepage: "https://eigen.tuxfamily.org/"
+  identifier {
+    type: "Git"
     value: "https://gitlab.com/libeigen/eigen.git"
+    version: "3.4.0"
   }
-  version: "3.4.0"
-  last_upgrade_date { year: 2022 month: 2 day: 25 }
-  license_type: RECIPROCAL
 }
diff --git a/OWNERS b/OWNERS
index 8888d2cab..41d78a706 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,4 @@
 miaowang@google.com
 timmurray@google.com
 ianhua@google.com
-include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
+include platform/system/core:main:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.android b/README.android
deleted file mode 100644
index b08a68565..000000000
--- a/README.android
+++ /dev/null
@@ -1,13 +0,0 @@
-Eigen 3.2.2
------------
-
-Eigen is a C++ template library for linear algebra: matrices, vectors,
-numerical solvers, and related algorithms.
-
-Website: http://eigen.tuxfamily.org/
-
-v3.2.2. Released on August 4, 2014. This is a copy of the source
-distribution from http://bitbucket.org/eigen/eigen/get/3.2.2.tar.bz2.
-
-Non MPL2 license code is disabled. Trying to include such files will
-lead to an error. See ./Eigen/src/Core/util/NonMPL2.h for details.
diff --git a/README.version b/README.version
deleted file mode 100644
index 8e2e25a0b..000000000
--- a/README.version
+++ /dev/null
@@ -1,3 +0,0 @@
-URL: https://gitlab.com/libeigen/eigen/-/archive/3.4.0/eigen-3.4.0.tar.bz2
-Version: 3.4.0
-BugComponent: 99023
```

