```diff
diff --git a/proguard.flags b/proguard.flags
index a934979..3ca07c2 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1 +1,4 @@
--keep class * extends android.app.Activity
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class * extends android.app.Activity {
+    void <init>();
+}
```

