```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 412016a..5009eb4 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -13,7 +13,6 @@ bpfmt = -s
 ktfmt = --kotlinlang-style
 
 [Hook Scripts]
-aosp_first = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} ${PREUPLOAD_FILES}
 # google_java_format only fixes indentation. This has Android specific checks like "m" prefix.
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
                   --config_xml checkstyle.xml
```

