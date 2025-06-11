```diff
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..73c5682
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1 @@
+licenses/licenses.db
diff --git a/METADATA b/METADATA
index 14dbe33..0b98b8d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update licenseclassifier
-# For more info, check https://cs.android.com/android/platform/superproject/+/master:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/licenseclassifier
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "licenseclassifier"
 description: "The license classifier is a library and set of tools that can analyze text to determine what type of license it contains."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/licenseclassifier.git"
-  }
-  version: "v2.0.0"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 3
-    day: 2
+    year: 2025
+    month: 2
+    day: 13
+  }
+  version: "b5d1a336974976c0d89915a602c6834de4c7824b"
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/licenseclassifier.git"
+    version: "b5d1a336974976c0d89915a602c6834de4c7824b"
   }
 }
diff --git a/OWNERS b/OWNERS
index 02b358e..2e8f086 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1 @@
-file:platform/build/soong:/compliance/OWNERS
+include platform/system/core:main:/janitors/OWNERS
diff --git a/README.md b/README.md
index 902c150..cbdddd6 100644
--- a/README.md
+++ b/README.md
@@ -14,6 +14,30 @@ A "confidence level" is associated with each result indicating how close the
 match was. A confidence level of `1.0` indicates an exact match, while a
 confidence level of `0.0` indicates that no license was able to match the text.
 
+## Usage
+
+### One-time setup
+
+Use the `license_serializer` tool to regenerate the `licenses.db` archive.
+The archive contains preprocessed license texts for quicker comparisons against
+unknown texts.
+
+```shell
+$ go run tools/license_serializer/license_serializer.go -output licenses
+```
+
+### Identifying licenses
+
+Use the `identify_license` command line tool to identify the license(s)
+within a file.
+
+```shell
+$ go run tools/identify_license/identify_license.go /path/to/LICENSE
+LICENSE: GPL-2.0 (confidence: 1, offset: 0, extent: 14794)
+LICENSE: LGPL-2.1 (confidence: 1, offset: 18366, extent: 23829)
+LICENSE: MIT (confidence: 1, offset: 17255, extent: 1059)
+```
+
 ## Adding a new license
 
 Adding a new license is straight-forward:
@@ -37,30 +61,6 @@ Adding a new license is straight-forward:
 4.  Create and run appropriate tests to verify that the license is indeed
     present.
 
-## Tools
-
-### Identify license
-
-`identify_license` is a command line tool that can identify the license(s)
-within a file.
-
-```shell
-$ identify_license LICENSE
-LICENSE: GPL-2.0 (confidence: 1, offset: 0, extent: 14794)
-LICENSE: LGPL-2.1 (confidence: 1, offset: 18366, extent: 23829)
-LICENSE: MIT (confidence: 1, offset: 17255, extent: 1059)
-```
-
-### License serializer
-
-The `license_serializer` tool regenerates the `licenses.db` archive. The archive
-contains preprocessed license texts for quicker comparisons against unknown
-texts.
-
-```shell
-$ license_serializer -output licenseclassifier/licenses
-```
-
 ----
 This is not an official Google product (experimental or otherwise), it is just
 code that happens to be owned by Google.
diff --git a/license_type.go b/license_type.go
index 6cfcbb2..893cd55 100644
--- a/license_type.go
+++ b/license_type.go
@@ -92,7 +92,7 @@ const (
 	CommonsClause               = "Commons-Clause"
 	CPAL10                      = "CPAL-1.0"
 	CPL10                       = "CPL-1.0"
-	eGenix                      = "eGenix"
+	EGenix                      = "eGenix"
 	EPL10                       = "EPL-1.0"
 	EPL20                       = "EPL-2.0"
 	EUPL10                      = "EUPL-1.0"
@@ -180,7 +180,7 @@ var (
 	// Licenses Categorized by Type
 
 	// restricted - Licenses in this category require mandatory source
-	// distribution if we ships a product that includes third-party code
+	// distribution if we ship a product that includes third-party code
 	// protected by such a license.
 	restrictedType = sets.NewStringSet(
 		BCL,
diff --git a/licenses/embed.go b/licenses/embed.go
index 7b31574..e7f682b 100644
--- a/licenses/embed.go
+++ b/licenses/embed.go
@@ -5,7 +5,7 @@ import (
 	"io/fs"
 )
 
-// go:embed *.db *.txt
+//go:embed *.db *.txt
 var licenseFS embed.FS
 
 // ReadLicenseFile locates and reads the license archive file.  Absolute paths are used unmodified.  Relative paths are expected to be in the licenses directory of the licenseclassifier package.
diff --git a/licenses/empty.db b/licenses/empty.db
new file mode 100644
index 0000000..e69de29
```

