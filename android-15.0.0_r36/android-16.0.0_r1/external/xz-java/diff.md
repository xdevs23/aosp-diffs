```diff
diff --git a/Android.bp b/Android.bp
index c3c678f..02e546e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,7 +26,7 @@ license {
         "legacy_unencumbered",
     ],
     license_text: [
-        "COPYING",
+        "LICENSE",
     ],
 }
 
diff --git a/LICENSE b/LICENSE
new file mode 120000
index 0000000..d24842f
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1 @@
+COPYING
\ No newline at end of file
diff --git a/METADATA b/METADATA
index abad0ef..42674c9 100644
--- a/METADATA
+++ b/METADATA
@@ -11,12 +11,9 @@ third_party {
     month: 11
     day: 28
   }
+  homepage: "https://tukaani.org/xz/java.html"
   identifier {
-    type: "HOMEPAGE"
-    value: "https://tukaani.org/xz/java.html"
-  }
-  identifier {
-    type: "GIT"
+    type: "Git"
     value: "https://github.com/tukaani-project/xz-java.git"
     version: "v1.9"
   }
```

