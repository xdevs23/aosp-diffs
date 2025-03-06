```diff
diff --git a/switcher4.py b/switcher4.py
index 58f1ba3..4ac9388 100644
--- a/switcher4.py
+++ b/switcher4.py
@@ -88,31 +88,46 @@ def insert_stub(doc, java, both):
     print("File: ", stubs, fn[1], end="\r")
 
   if (java):
-      java_stubs = java_stubs + 1
+    java_stubs = java_stubs + 1
   else:
-      kotlin_stubs = kotlin_stubs + 1
-
+    kotlin_stubs = kotlin_stubs + 1
 
   if (work):
+    with open(doc, "r") as f:
+      file_content = f.read()
+
     if (java):
-      file_path = doc[len(java_ref_root)+1:]
-      stub = doc.replace(java_source_abs_path, kotlin_source_abs_path)
+      file_path = doc[len(java_ref_root) + 1 :]
       if (both):
-        slug1 = "sed -i 's/<\/h1>/{}/' {}".format("<\/h1>\\n{% setvar page_path %}_page_path_{% endsetvar %}\\n{% setvar can_switch %}1{% endsetvar %}\\n{% include \"reference\/_java_switcher2.md\" %}",doc)
+        file_content = file_content.replace(
+            "</h1>",
+            "</h1>\n{% setvar page_path %}_page_path_{% endsetvar %}\n{% setvar"
+            " can_switch %}1{% endsetvar %}\n{% include"
+            ' "reference/_java_switcher2.md" %}',
+        )
+        file_content = file_content.replace("_page_path_", file_path)
       else:
-        slug1 = "sed -i 's/<\/h1>/{}/' {}".format("<\/h1>\\n{% include \"reference\/_java_switcher2.md\" %}",doc)
+        file_content = file_content.replace(
+            "</h1>", '</h1>\n{% include "reference/_java_switcher2.md" %}'
+        )
     else:
-      file_path = doc[len(kotlin_ref_root)+1:]
-      stub = doc.replace(kotlin_source_abs_path, java_source_abs_path)
+      file_path = doc[len(kotlin_ref_root) + 1 :]
       if (both):
-        slug1 = "sed -i 's/<\/h1>/{}/' {}".format("<\/h1>\\n{% setvar page_path %}_page_path_{% endsetvar %}\\n{% setvar can_switch %}1{% endsetvar %}\\n{% include \"reference\/_kotlin_switcher2.md\" %}",doc)
+        file_content = file_content.replace(
+            "</h1>",
+            "</h1>\n{% setvar page_path %}_page_path_{% endsetvar %}\n{% setvar"
+            " can_switch %}1{% endsetvar %}\n{% include"
+            ' "reference/_kotlin_switcher2.md" %}',
+        )
+        file_content = file_content.replace("_page_path_", file_path)
       else:
-        slug1 = "sed -i 's/<\/h1>/{}/' {}".format("<\/h1>\\n{% include \"reference\/_kotlin_switcher2.md\" %}",doc)
+        file_content = file_content.replace(
+            "</h1>", '</h1>\n{% include "reference/_kotlin_switcher2.md" %}'
+        )
 
-    os.system(slug1)
-    if (both):
-      page_path_slug = "sed -i 's/_page_path_/{}/' {}".format(file_path.replace("/","\/"),doc)
-      os.system(page_path_slug)
+    with open(doc, "w") as f:
+      f.write(file_content)
+    os.chmod(doc, 0o644)
 
 
 def scan_files(stem):
```

