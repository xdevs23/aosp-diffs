```diff
diff --git a/scripts/repackage-common.sh b/scripts/repackage-common.sh
index a11fa5c..1fea27d 100644
--- a/scripts/repackage-common.sh
+++ b/scripts/repackage-common.sh
@@ -108,6 +108,7 @@ CORE_PLATFORM_API_FILE=${SRCGEN_DIR}/core-platform-api.txt
 STABLE_CORE_PLATFORM_API_FILE=${SRCGEN_DIR}/stable-core-platform-api.txt
 INTRA_CORE_API_FILE=${SRCGEN_DIR}/intra-core-api.txt
 UNSUPPORTED_APP_USAGE_FILE=${SRCGEN_DIR}/unsupported-app-usage.json
+FLAGGED_API_FILE=${SRCGEN_DIR}/flagged-api.json
 
 TAB_SIZE=${TAB_SIZE-4}
 
@@ -152,6 +153,12 @@ if [[ -f "${UNSUPPORTED_APP_USAGE_FILE}" ]]; then
   fi
 fi
 
+if [[ -f "${FLAGGED_API_FILE}" ]]; then
+  echo "Adding FlaggedApi annotations from ${FLAGGED_API_FILE}"
+  REPACKAGE_ARGS="${REPACKAGE_ARGS}${SEP}--flagged-api-file ${FLAGGED_API_FILE}"
+  SEP=" "
+fi
+
 if [[ -n "${TAB_SIZE}" ]]; then
   echo "Using tab size of ${TAB_SIZE}"
   REPACKAGE_ARGS="${REPACKAGE_ARGS}${SEP}--tab-size ${TAB_SIZE}"
@@ -215,6 +222,10 @@ function checkChangeLog {
   fi
 }
 
+function extractLocationsFromJson {
+    grep @location "$1" | grep -vE "[[:space:]]*//" | cut -f4 -d\" | sort -u
+}
+
 if [[ -f "${DEFAULT_CONSTRUCTORS_FILE}" ]]; then
   # Check to ensure that all the requested default constructors were added.
   checkChangeLog <(sort -u "${DEFAULT_CONSTRUCTORS_FILE}" | grep -v '^#') "AddDefaultConstructor" \
@@ -241,11 +252,18 @@ fi
 
 if [[ -f "${UNSUPPORTED_APP_USAGE_FILE}" ]]; then
   # Check to ensure that all the requested annotations were added.
-  checkChangeLog <(grep @location "${UNSUPPORTED_APP_USAGE_FILE}" | grep -vE "[[:space:]]*//" | cut -f4 -d\" | sort -u) \
+  checkChangeLog <(extractLocationsFromJson "${UNSUPPORTED_APP_USAGE_FILE}") \
       "@android.compat.annotation.UnsupportedAppUsage" \
       "UnsupportedAppUsage annotations were not added at the following locations from ${UNSUPPORTED_APP_USAGE_FILE}:"
 fi
 
+if [[ -f "${FLAGGED_API_FILE}" ]]; then
+  # Check to ensure that all the requested annotations were added.
+  checkChangeLog <(extractLocationsFromJson "${FLAGGED_API_FILE}") \
+      "@android.annotation.FlaggedApi" \
+      "FlaggedApi annotations were not added at the following locations from ${FLAGGED_API_FILE}:"
+fi
+
 if [[ $ERROR = 1 ]]; then
   echo "Errors found during transformation, see above.\n" >&2
   exit 1
```

