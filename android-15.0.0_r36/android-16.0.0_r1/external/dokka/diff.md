```diff
diff --git a/Android.bp b/Android.bp
index dbfdb50..32d7088 100644
--- a/Android.bp
+++ b/Android.bp
@@ -52,4 +52,5 @@ java_binary_host {
     java_version: "1.8",
     use_tools_jar: true,
     java_resource_dirs: ["core/src/main/resources"],
+    kotlin_lang_version: "1.9",
 }
diff --git a/OWNERS b/OWNERS
index d5b339a..65731a7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ asfalcone@google.com
 aurimas@google.com
 lpf@google.com
 tiem@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

