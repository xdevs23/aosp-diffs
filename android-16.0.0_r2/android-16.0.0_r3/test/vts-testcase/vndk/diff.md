```diff
diff --git a/dependency/vts_vndk_dependency_test.py b/dependency/vts_vndk_dependency_test.py
index 1fc503f..562cce4 100644
--- a/dependency/vts_vndk_dependency_test.py
+++ b/dependency/vts_vndk_dependency_test.py
@@ -201,6 +201,19 @@ class VtsVndkDependencyTest(unittest.TestCase):
 
         return True
 
+    @staticmethod
+    def _IsSymlinkToApexFile(target_path):
+        """Checks whether the target path is a symlink pointing to an APEX file
+
+        Args:
+            target_path: The path to the file on target.
+
+        Returns:
+            A boolean, whether the path is a link to a file in APEX.
+        """
+        return (os.path.islink(target_path) and
+                os.path.realpath(target_path).startswith("/apex/"))
+
     @staticmethod
     def _IterateFiles(target_dir):
         """Iterates files in a directory.
@@ -236,6 +249,11 @@ class VtsVndkDependencyTest(unittest.TestCase):
                 logging.debug("%s is not an ELF file", target_path)
                 continue
             try:
+                if self._IsSymlinkToApexFile(target_path):
+                    # APEX ELF objects have their inter-container dependencies
+                    # checked in Soong.
+                    logging.info("%s is a link to a file in APEX", target_path)
+                    continue
                 if not self._IsElfObjectForAp(elf, target_path, abi_list):
                     logging.info("%s is not for application processor",
                                  target_path)
```

