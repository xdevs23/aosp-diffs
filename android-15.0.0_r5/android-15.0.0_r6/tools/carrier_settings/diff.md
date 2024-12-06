```diff
diff --git a/main.sh b/main.sh
index 0ee351c..7026bfb 100644
--- a/main.sh
+++ b/main.sh
@@ -117,7 +117,8 @@ echo 'Done.'
 echo 'step 3. Copy generated files to output directory ...'
 
 mkdir -p $OUTPUT_DIR > /dev/null
-rm -rf "${OUTPUT_DIR:?}"/* > /dev/null
+# Ignore error if first time running
+rm -rf "${OUTPUT_DIR:?}"/* > /dev/null  || true
 cp -r "$INNER_TMP_DIR"/pb  $OUTPUT_DIR > /dev/null
 cp -r "$INNER_TMP_DIR"/textpb  $OUTPUT_DIR > /dev/null
 rm -rf "${TMP_DIR:?}" > /dev/null
diff --git a/python/update_apn.py b/python/update_apn.py
index 2a74149..1c3b23e 100644
--- a/python/update_apn.py
+++ b/python/update_apn.py
@@ -28,9 +28,9 @@ import collections
 from xml.dom import minidom
 from google.protobuf import text_format
 
-import carrier_list_pb2
-import carrier_settings_pb2
-import carrierId_pb2
+from proto import carrier_list_pb2
+from proto import carrier_settings_pb2
+from src import carrierId_pb2
 
 parser = argparse.ArgumentParser()
 parser.add_argument(
diff --git a/python/update_carrier_data.py b/python/update_carrier_data.py
index 631e54b..1e66901 100644
--- a/python/update_carrier_data.py
+++ b/python/update_carrier_data.py
@@ -31,10 +31,10 @@ from __future__ import print_function
 import argparse
 import copy
 import os
-import compare
+from python import compare
 from google.protobuf import text_format
-import carrier_list_pb2
-import carrier_settings_pb2
+from proto import carrier_list_pb2
+from proto import carrier_settings_pb2
 
 parser = argparse.ArgumentParser()
 parser.add_argument(
```

