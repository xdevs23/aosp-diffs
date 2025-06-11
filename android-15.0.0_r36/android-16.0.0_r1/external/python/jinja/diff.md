```diff
diff --git a/LICENSE b/LICENSE
new file mode 120000
index 0000000..bf2a4e0
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1 @@
+LICENSE.rst
\ No newline at end of file
diff --git a/METADATA b/METADATA
new file mode 100644
index 0000000..234fdee
--- /dev/null
+++ b/METADATA
@@ -0,0 +1,18 @@
+name: "Jinja"
+description:
+    "Jinja is a fast, expressive, extensible templating engine. Special "
+    "placeholders in the template allow writing code similar to Python syntax. "
+    "Then the template is passed data to render the final document."
+
+third_party {
+  url {
+    type: HOMEPAGE
+    value: "https://palletsprojects.com/p/jinja/"
+  }
+  url {
+    type: GIT
+    value: "https://github.com/pallets/jinja"
+  }
+  version: "03c719f3ec4db9660aa4dea30bef9ac8e47aa933"
+  last_upgrade_date { year: 2020 month: 7 day: 13 }
+}
diff --git a/src/Android.bp b/src/Android.bp
index e8a5e50..c9def21 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -8,6 +8,5 @@ python_library {
     srcs: ["jinja2/*.py"],
     libs: [
         "py-markupsafe",
-        "py-setuptools",
     ],
 }
```

