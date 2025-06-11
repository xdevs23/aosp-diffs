```diff
diff --git a/OWNERS b/OWNERS
index 2a33850..2eaf9f2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ ascull@google.com
 drewry@google.com
 swillden@google.com
 manishdwivedi@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/esed/Android.bp b/esed/Android.bp
index e2048ac..b4c5fc9 100644
--- a/esed/Android.bp
+++ b/esed/Android.bp
@@ -27,7 +27,6 @@ cc_defaults {
     name: "esed_defaults",
     proprietary: true,
     cflags: [
-        "-pedantic",
         "-Wall",
         "-Wextra",
         "-Werror",
diff --git a/libapdu/Android.bp b/libapdu/Android.bp
index 4577693..b09897f 100644
--- a/libapdu/Android.bp
+++ b/libapdu/Android.bp
@@ -29,7 +29,6 @@ cc_defaults {
     name: "libapdu_defaults",
     proprietary: true,
     cflags: [
-        "-pedantic",
         "-Wall",
         "-Wextra",
         "-Werror",
diff --git a/libese-cpp/Android.bp b/libese-cpp/Android.bp
index 18a980d..aa045ef 100644
--- a/libese-cpp/Android.bp
+++ b/libese-cpp/Android.bp
@@ -27,7 +27,6 @@ cc_defaults {
     name: "libese_cpp_defaults",
     proprietary: true,
     cflags: [
-        "-pedantic",
         "-Wall",
         "-Wextra",
         "-Werror",
diff --git a/libese/Android.bp b/libese/Android.bp
index 7ee1395..30b26db 100644
--- a/libese/Android.bp
+++ b/libese/Android.bp
@@ -29,7 +29,6 @@ cc_defaults {
     proprietary: true,
     cflags: [
         "-std=c99",
-        "-D_FORTIFY_SOURCE=2",
         "-Wall",
         "-Werror",
     ],
diff --git a/apps/weaver/card/src/com/android/weaver/Consts.java b/ready_se/google/weaver/Applet/src/com/android/weaver/Consts.java
similarity index 100%
rename from apps/weaver/card/src/com/android/weaver/Consts.java
rename to ready_se/google/weaver/Applet/src/com/android/weaver/Consts.java
diff --git a/apps/weaver/card/src/com/android/weaver/Slots.java b/ready_se/google/weaver/Applet/src/com/android/weaver/Slots.java
similarity index 100%
rename from apps/weaver/card/src/com/android/weaver/Slots.java
rename to ready_se/google/weaver/Applet/src/com/android/weaver/Slots.java
diff --git a/apps/weaver/card/src/com/android/weaver/Weaver.java b/ready_se/google/weaver/Applet/src/com/android/weaver/Weaver.java
similarity index 100%
rename from apps/weaver/card/src/com/android/weaver/Weaver.java
rename to ready_se/google/weaver/Applet/src/com/android/weaver/Weaver.java
diff --git a/apps/weaver/card/src/com/android/weaver/core/CoreSlots.java b/ready_se/google/weaver/Applet/src/com/android/weaver/core/CoreSlots.java
similarity index 100%
rename from apps/weaver/card/src/com/android/weaver/core/CoreSlots.java
rename to ready_se/google/weaver/Applet/src/com/android/weaver/core/CoreSlots.java
diff --git a/apps/weaver/card/src/com/android/weaver/core/WeaverCore.java b/ready_se/google/weaver/Applet/src/com/android/weaver/core/WeaverCore.java
similarity index 100%
rename from apps/weaver/card/src/com/android/weaver/core/WeaverCore.java
rename to ready_se/google/weaver/Applet/src/com/android/weaver/core/WeaverCore.java
diff --git a/tools/ese_relay/Android.bp b/tools/ese_relay/Android.bp
index 63e59cb..d9dcac2 100644
--- a/tools/ese_relay/Android.bp
+++ b/tools/ese_relay/Android.bp
@@ -34,7 +34,6 @@ cc_defaults {
     },
     cflags: [
         "-std=c99",
-        "-D_FORTIFY_SOURCE=2",
         "-Wall",
         "-Werror",
         "-Wno-error=unused-variable",
```

