```diff
diff --git a/METADATA b/METADATA
index 6ec085a..4bad470 100644
--- a/METADATA
+++ b/METADATA
@@ -1,20 +1,20 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/google-fruit
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "google-fruit"
 description: "Fruit is a dependency injection framework for C++, loosely inspired by the Guice framework for Java. It uses C++ metaprogramming together with some new C++11 features to detect most injection problems at compile-time. It allows to split the implementation code in \"components\" (aka modules) that can be assembled to form other components. From a component with no requirements it\'s then possible to create an injector, that provides an instance of the interfaces exposed by the component."
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 5
-    day: 22
+    year: 2025
+    month: 1
+    day: 16
   }
   homepage: "https://github.com/google/fruit"
   identifier {
     type: "Git"
     value: "https://github.com/google/fruit.git"
-    version: "dab5bdfe01eb9f90a2b688c7f3be177a9bd8d5c6"
+    version: "f47f76e4cf02843e9ebc88e3e2f8181553ac3ab2"
   }
 }
diff --git a/extras/bazel_usage_example/WORKSPACE b/extras/bazel_usage_example/WORKSPACE
index e037168..4677568 100644
--- a/extras/bazel_usage_example/WORKSPACE
+++ b/extras/bazel_usage_example/WORKSPACE
@@ -9,7 +9,12 @@ git_repository(
 load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
 boost_deps()
 
-load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
+git_repository(
+    name = "com_google_googletest",
+    remote = "https://github.com/google/googletest",
+    # GTest HEAD as of August 2018.
+    commit = "9c96f500a39df6915f8f1ab53b60be9889f1572b",
+)
 
 git_repository(
     name = "com_google_fruit",
```

