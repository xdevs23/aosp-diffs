```diff
diff --git a/.bazelci/tests.yml b/.bazelci/tests.yml
index 68fc0ae..9d84083 100644
--- a/.bazelci/tests.yml
+++ b/.bazelci/tests.yml
@@ -2,7 +2,8 @@
 default_tests: &default_tests
   test_targets:
     - "//tests/..."
-    - "//examples/..."
+    - "//examples/policy_checker/..."
+    - "//examples/sboms/..."
 
 #
 # Bazel releases
@@ -32,9 +33,8 @@ windows: &windows
   platform: windows
   test_targets:
     - "//tests/..."
-    - "//examples/..."
-    - "-//examples/manifest/..."
-
+    - "//examples/policy_checker/..."
+    - "//examples/sboms/..."
 
 
 # The cross product of bazel releases X platforms
diff --git a/.gitignore b/.gitignore
index 7445377..c96b2d0 100644
--- a/.gitignore
+++ b/.gitignore
@@ -3,3 +3,4 @@ bazel-bin
 bazel-out
 bazel-rules_license
 bazel-testlogs
+MODULE.bazel.lock
diff --git a/BUILD b/BUILD
index 31520c4..44ada8b 100644
--- a/BUILD
+++ b/BUILD
@@ -12,9 +12,9 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@rules_license//:version.bzl", "version")
 load("@rules_license//rules:license.bzl", "license")
 load("@rules_license//rules:package_info.bzl", "package_info")
-load("@rules_license//:version.bzl", "version")
 
 package(
     default_applicable_licenses = [":license", ":package_info"],
@@ -55,10 +55,20 @@ filegroup(
         "*.bzl",
         "*.md",
     ]) + [
-        "MODULE.bazel",
         "BUILD",
         "LICENSE",
+        "MODULE.bazel",
         "WORKSPACE.bzlmod",
     ],
     visibility = ["//distro:__pkg__"],
 )
+
+filegroup(
+    name = "docs_deps",
+    srcs = [
+        ":standard_package",
+        "//rules:standard_package",
+        "//rules_gathering:standard_package",
+    ],
+    visibility = ["//visibility:public"],
+)
diff --git a/METADATA b/METADATA
index 7d83584..0a24b8f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "rules_license"
-description:
-    "Software license related rules and tools for the Bazel build system."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/bazelbuild-rules_license
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "rules_license"
+description: "Software license related rules and tools for the Bazel build system."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/bazelbuild/rules_license"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 12
+    day: 10
   }
-  url {
-    type: GIT
+  homepage: "https://github.com/bazelbuild/rules_license"
+  identifier {
+    type: "Git"
     value: "https://github.com/bazelbuild/rules_license.git"
+    version: "1.0.0"
   }
-  version: "bb6f02d8ce7e51587e600671d41e801960d16bf1"
-  last_upgrade_date { year: 2023 month: 3 day: 22 }
-  license_type: NOTICE
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index 114446a..639c7c3 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,6 +1,6 @@
 module(
     name = "rules_license",
-    version = "0.0.4",  # Keep in sync with version.bzl
+    version = "1.0.0",  # Keep in sync with version.bzl
     compatibility_level = 1,
 )
 
@@ -12,5 +12,7 @@ module(
 # do not need //tools.
 
 # Only for development
-bazel_dep(name = "rules_pkg", version = "0.7.0", dev_dependency = True)
-bazel_dep(name = "stardoc", version = "0.5.3", dev_dependency = True)
+bazel_dep(name = "bazel_skylib", version = "1.7.1", dev_dependency = True)
+bazel_dep(name = "rules_pkg", version = "1.0.1", dev_dependency = True)
+bazel_dep(name = "rules_python", version = "0.35.0", dev_dependency = True)
+bazel_dep(name = "stardoc", version = "0.6.2", dev_dependency = True)
diff --git a/README.md b/README.md
index 1527f74..c12fb06 100644
--- a/README.md
+++ b/README.md
@@ -8,19 +8,55 @@ This repository contains a set of rules and tools for
   - the canonical package name and version
   - copyright information
   - ... and more TBD in the future
-- gathering those license declarations into artifacts to ship with code
+- gathering license declarations into artifacts to ship with code
 - applying organization specific compliance constriants against the
   set of packages used by a target.
-- (eventually) producing SBOMs for built artifacts.
+- producing SBOMs for built artifacts.
 
 WARNING: The code here is still in active initial development and will churn a lot.
 
+## Contact
+
 If you want to follow along:
 - Mailing list: [bazel-ssc@bazel.build](https://groups.google.com/a/bazel.build/g/bazel-ssc)  
 - Monthly eng meeting: [calendar link](MjAyMjA4MjJUMTYwMDAwWiBjXzUzcHBwZzFudWthZXRmb3E5NzhxaXViNmxzQGc&tmsrc=c_53pppg1nukaetfoq978qiub6ls%40group.calendar.google.com&scp=ALL)
 - [Latest docs](https://bazelbuild.github.io/rules_license/latest.html)
 
-Background reading:
+## Roadmap
+
+*Last update: October 22, 2023*
+
+### Q4 2023
+
+- Reference implementation for "packages used" tool
+  - produce JSON output usable for SBOM generation or other compliance reporting.
+- Reference implementation for an SPDX SBOMM generator
+  - Support for reading bzlmod lock file
+  - Support for reading maven lock file
+- "How To" guides
+  - produce a license audit
+  - produce an SBOM
+
+### Q1 2024
+
+- Add support for other package manager lock file formats
+  - ? Python
+  - Golang
+  - NodeJS
+- More SPDX SBOM fields
+  - support for including vendor SBOMs
+  - 
+
+### Beyond
+
+- Performance improvements
+- Sub-SBOMs for tools
+
+
+- TBD
+
+## Background reading:
+
 These is for learning about the problem space, and our approach to solutions. Concrete specifications will always appear in checked in code rather than documents.
 - [License Checking with Bazel](https://docs.google.com/document/d/1uwBuhAoBNrw8tmFs-NxlssI6VRolidGYdYqagLqHWt8/edit#).
 - [OSS Licenses and Bazel Dependency Management](https://docs.google.com/document/d/1oY53dQ0pOPEbEvIvQ3TvHcFKClkimlF9AtN89EPiVJU/edit#)
diff --git a/WORKSPACE b/WORKSPACE
index 654ea78..ab6fd03 100644
--- a/WORKSPACE
+++ b/WORKSPACE
@@ -14,37 +14,55 @@
 
 workspace(name = "rules_license")
 
-# You only need the dependencies if you intend to use any of the tools.
-load("@rules_license//:deps.bzl", "rules_license_dependencies")
-
-rules_license_dependencies()
-
+# rules_license has no dependencies for basic license and package_info
+# declarations.
+#
+# If you want to use any of the reporting or SBOM tools, and you are using a
+# WORKSPACE file instead of bzlmod, then you should explicitly depend on
+# rules_python in your WORKSPACE.
+ 
 ### INTERNAL ONLY - lines after this are not included in the release packaging.
 
 load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
 
 http_archive(
-    name = "rules_pkg",
+    name = "bazel_skylib",
+    sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.8.0/rules_pkg-0.8.0.tar.gz",
-        "https://github.com/bazelbuild/rules_pkg/releases/download/0.8.0/rules_pkg-0.8.0.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
+        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
     ],
-    sha256 = "eea0f59c28a9241156a47d7a8e32db9122f3d50b505fae0f33de6ce4d9b61834",
 )
 
-load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
+http_archive(
+    name = "rules_python",
+    sha256 = "be04b635c7be4604be1ef20542e9870af3c49778ce841ee2d92fcb42f9d9516a",
+    strip_prefix = "rules_python-0.35.0",
+    url = "https://github.com/bazelbuild/rules_python/releases/download/0.35.0/rules_python-0.35.0.tar.gz",
+)
 
-rules_pkg_dependencies()
+http_archive(
+    name = "rules_pkg",
+    urls = [
+        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz",
+        "https://github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz",
+    ],
+    sha256 = "d20c951960ed77cb7b341c2a59488534e494d5ad1d30c4818c736d57772a9fef",
+)
 
 http_archive(
-    name = "io_bazel_stardoc",
-    sha256 = "3fd8fec4ddec3c670bd810904e2e33170bedfe12f90adf943508184be458c8bb",
+    name = "bazel_stardoc",
+    sha256 = "c9794dcc8026a30ff67cf7cf91ebe245ca294b20b071845d12c192afe243ad72",
     urls = [
-        "https://mirror.bazel.build/github.com/bazelbuild/stardoc/releases/download/0.5.3/stardoc-0.5.3.tar.gz",
-        "https://github.com/bazelbuild/stardoc/releases/download/0.5.3/stardoc-0.5.3.tar.gz",
+        "https://mirror.bazel.build/github.com/bazelbuild/stardoc/releases/download/0.5.0/stardoc-0.5.0.tar.gz",
+        "https://github.com/bazelbuild/stardoc/releases/download/0.5.0/stardoc-0.5.0.tar.gz",
     ],
 )
 
-load("@io_bazel_stardoc//:setup.bzl", "stardoc_repositories")
+load("@rules_python//python:repositories.bzl", "py_repositories")
+
+py_repositories()
+
+load("@bazel_stardoc//:setup.bzl", "stardoc_repositories")
 
 stardoc_repositories()
diff --git a/admin/refresh_spdx/add_licenses.py b/admin/refresh_spdx/add_licenses.py
index 117626b..fa34207 100755
--- a/admin/refresh_spdx/add_licenses.py
+++ b/admin/refresh_spdx/add_licenses.py
@@ -2,7 +2,7 @@
 """Refresh the BUILD file of SPDX license_kinds with new ones from licenses.json.
 
 Usage:
-  wget https://github.com/spdx/license-list-data/raw/master/json/licenses.json
+  wget https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json
   LC_ALL="en_US.UTF-8" admin/refresh_spdx/add_licenses.py
   git diff
   git commit
diff --git a/deps.bzl b/deps.bzl
index 7e2a69a..24a27bd 100644
--- a/deps.bzl
+++ b/deps.bzl
@@ -14,14 +14,5 @@
 
 """Workspace dependencies for rules_license/rules."""
 
-load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
-load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
-
 def rules_license_dependencies():
-    maybe(
-        http_archive,
-        name = "rules_python",
-        sha256 = "a30abdfc7126d497a7698c29c46ea9901c6392d6ed315171a6df5ce433aa4502",
-        strip_prefix = "rules_python-0.6.0",
-        url = "https://github.com/bazelbuild/rules_python/archive/0.6.0.tar.gz",
-    )
+    pass
diff --git a/distro/BUILD b/distro/BUILD
index 693d1ac..7291cad 100644
--- a/distro/BUILD
+++ b/distro/BUILD
@@ -37,7 +37,9 @@ pkg_tar(
         "//licenses/generic:standard_package",
         "//licenses/spdx:standard_package",
         "//rules:standard_package",
+        "//rules_gathering:standard_package",
         "//rules/private:standard_package",
+        "//sample_reports:standard_package",
         "//tools:standard_package",
     ],
     extension = "tar.gz",
diff --git a/distro/check_build.sh b/distro/check_build.sh
new file mode 100755
index 0000000..bfcae6d
--- /dev/null
+++ b/distro/check_build.sh
@@ -0,0 +1,59 @@
+#!/bin/bash -ef
+#
+# This is a temporary hack to verify the distribution archive is sound.
+#
+# The intent is to create a rule which does this and add to
+# rules_pkg. Comments within it are mostly for future me
+# while writing that.
+
+TARBALL=$(bazel build //distro:distro 2>&1 | grep 'rules_license-.*\.tar\.gz' | sed -e 's/ //g')
+REPO_NAME='rules_license'
+
+# This part can be standard from the rule
+
+
+TARNAME=$(basename "$TARBALL")
+
+TMP=$(mktemp -d) 
+trap '/bin/rm -rf "$TMP"; exit 0' 0 1 2 3 15
+
+cp "$TARBALL" "$TMP"
+
+cd "$TMP"
+cat >WORKSPACE <<INP
+workspace(name = "test")
+
+load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
+
+http_archive(
+    name = "$REPO_NAME",
+    urls = ["file:$TARNAME"],
+)
+INP
+
+#
+# The rest is specific to the package under test.
+#
+
+# You always need a BUILD, so that can be an attribute
+cat >BUILD <<INP
+load("@rules_license//rules:license.bzl", "license")
+
+license(
+   name = "license",
+   license_kinds = ["@rules_license//licenses/generic:notice"],
+   license_text = "LICENSE"
+)
+INP
+
+# Need for a script to set up other files
+# Or it folds into the tests cases?
+echo license >LICENSE
+
+# Then a list of commands to run. This can be a template
+# too so we can substitute the path to bazel.
+bazel build ...
+bazel build @rules_license//rules/... 
+bazel build @rules_license//licenses/...
+bazel query @rules_license//licenses/generic/...
+bazel query ...
diff --git a/doc_build/BUILD b/doc_build/BUILD
index c50e2d4..2856deb 100644
--- a/doc_build/BUILD
+++ b/doc_build/BUILD
@@ -20,7 +20,7 @@ How to:
 """
 
 load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
-load("@io_bazel_stardoc//stardoc:stardoc.bzl", "stardoc")
+load("@stardoc//stardoc:stardoc.bzl", "stardoc")
 load("@rules_python//python:defs.bzl", "py_library")
 load("//:version.bzl", "version")
 
@@ -59,6 +59,9 @@ ORDER = [
     ("LicenseInfo",     "//rules:providers.bzl"),
     ("LicenseKindInfo", "//rules:providers.bzl"),
     ("PackageInfo",     "//rules:providers.bzl"),
+    ("gather_metadata_info",           "//rules_gathering:gather_metadata.bzl"),
+    ("gather_metadata_info_and_write", "//rules_gathering:gather_metadata.bzl"),
+    ("trace",           "//rules_gathering:trace.bzl"),
 ]
 
 genrule(
@@ -89,8 +92,7 @@ bzl_library(
     srcs = [
         "//:version.bzl",
         "//rules:standard_package",
-        "//rules/private:standard_package",
-        # "@bazel_skylib//lib:paths",
+        "//rules_gathering:standard_package",
     ],
     visibility = ["//visibility:public"],
 )
diff --git a/docs/latest.md b/docs/latest.md
index a7c373f..c326cb7 100755
--- a/docs/latest.md
+++ b/docs/latest.md
@@ -9,7 +9,7 @@ Rules for declaring the compliance licenses used by a package.
 ## license
 
 <pre>
-license(<a href="#license-name">name</a>, <a href="#license-copyright_notice">copyright_notice</a>, <a href="#license-license_kinds">license_kinds</a>, <a href="#license-license_text">license_text</a>, <a href="#license-namespace">namespace</a>, <a href="#license-package_name">package_name</a>, <a href="#license-package_url">package_url</a>,
+license(<a href="#license-name">name</a>, <a href="#license-copyright_notice">copyright_notice</a>, <a href="#license-license_kinds">license_kinds</a>, <a href="#license-license_text">license_text</a>, <a href="#license-package_name">package_name</a>, <a href="#license-package_url">package_url</a>,
          <a href="#license-package_version">package_version</a>)
 </pre>
 
@@ -24,7 +24,6 @@ license(<a href="#license-name">name</a>, <a href="#license-copyright_notice">co
 | <a id="license-copyright_notice"></a>copyright_notice |  Copyright notice.   | String | optional | <code>""</code> |
 | <a id="license-license_kinds"></a>license_kinds |  License kind(s) of this license. If multiple license kinds are listed in the LICENSE file, and they all apply, then all should be listed here. If the user can choose a single one of many, then only list one here.   | <a href="https://bazel.build/concepts/labels">List of labels</a> | optional | <code>[]</code> |
 | <a id="license-license_text"></a>license_text |  The license file.   | <a href="https://bazel.build/concepts/labels">Label</a> | optional | <code>LICENSE</code> |
-| <a id="license-namespace"></a>namespace |  A human readable name used to organize licenses into categories. This is used in google3 to differentiate third party licenses used for compliance versus internal licenses used by SLAsan for internal teams' SLAs.   | String | optional | <code>""</code> |
 | <a id="license-package_name"></a>package_name |  A human readable name identifying this package. This may be used to produce an index of OSS packages used by an applicatation.   | String | optional | <code>""</code> |
 | <a id="license-package_url"></a>package_url |  The URL this instance of the package was download from. This may be used to produce an index of OSS packages used by an applicatation.   | String | optional | <code>""</code> |
 | <a id="license-package_version"></a>package_version |  A human readable version string identifying this package. This may be used to produce an index of OSS packages used by an applicatation.  It should be a value that increases over time, rather than a commit hash.   | String | optional | <code>""</code> |
@@ -86,15 +85,20 @@ package_info(<a href="#package_info-name">name</a>, <a href="#package_info-packa
 
 <!-- Generated with Stardoc: http://skydoc.bazel.build -->
 
-Providers for license rules.
+Basic providers for license rules.
+
+This file should only contain the basic providers needed to create
+license and package_info declarations. Providers needed to gather
+them are declared in other places.
+
 
 <a id="LicenseInfo"></a>
 
 ## LicenseInfo
 
 <pre>
-LicenseInfo(<a href="#LicenseInfo-copyright_notice">copyright_notice</a>, <a href="#LicenseInfo-label">label</a>, <a href="#LicenseInfo-license_kinds">license_kinds</a>, <a href="#LicenseInfo-license_text">license_text</a>, <a href="#LicenseInfo-namespace">namespace</a>, <a href="#LicenseInfo-package_name">package_name</a>,
-            <a href="#LicenseInfo-package_url">package_url</a>, <a href="#LicenseInfo-package_version">package_version</a>)
+LicenseInfo(<a href="#LicenseInfo-copyright_notice">copyright_notice</a>, <a href="#LicenseInfo-label">label</a>, <a href="#LicenseInfo-license_kinds">license_kinds</a>, <a href="#LicenseInfo-license_text">license_text</a>, <a href="#LicenseInfo-package_name">package_name</a>, <a href="#LicenseInfo-package_url">package_url</a>,
+            <a href="#LicenseInfo-package_version">package_version</a>)
 </pre>
 
 Provides information about a license instance.
@@ -108,7 +112,6 @@ Provides information about a license instance.
 | <a id="LicenseInfo-label"></a>label |  Label: label of the license rule    |
 | <a id="LicenseInfo-license_kinds"></a>license_kinds |  list(LicenseKindInfo): License kinds    |
 | <a id="LicenseInfo-license_text"></a>license_text |  string: The license file path    |
-| <a id="LicenseInfo-namespace"></a>namespace |  string: namespace of the license rule    |
 | <a id="LicenseInfo-package_name"></a>package_name |  string: Human readable package name    |
 | <a id="LicenseInfo-package_url"></a>package_url |  URL from which this package was downloaded.    |
 | <a id="LicenseInfo-package_version"></a>package_version |  Human readable version string    |
@@ -117,7 +120,12 @@ Provides information about a license instance.
 
 <!-- Generated with Stardoc: http://skydoc.bazel.build -->
 
-Providers for license rules.
+Basic providers for license rules.
+
+This file should only contain the basic providers needed to create
+license and package_info declarations. Providers needed to gather
+them are declared in other places.
+
 
 <a id="LicenseKindInfo"></a>
 
@@ -143,7 +151,12 @@ Provides information about a license_kind instance.
 
 <!-- Generated with Stardoc: http://skydoc.bazel.build -->
 
-Providers for license rules.
+Basic providers for license rules.
+
+This file should only contain the basic providers needed to create
+license and package_info declarations. Providers needed to gather
+them are declared in other places.
+
 
 <a id="PackageInfo"></a>
 
@@ -168,3 +181,93 @@ Provides information about a package.
 
 
 
+<!-- Generated with Stardoc: http://skydoc.bazel.build -->
+
+Rules and macros for collecting LicenseInfo providers.
+
+<a id="gather_metadata_info"></a>
+
+## gather_metadata_info
+
+<pre>
+gather_metadata_info(<a href="#gather_metadata_info-name">name</a>)
+</pre>
+
+Collects LicenseInfo providers into a single TransitiveMetadataInfo provider.
+
+**ASPECT ATTRIBUTES**
+
+
+| Name | Type |
+| :------------- | :------------- |
+| *| String |
+
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="gather_metadata_info-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |   |
+
+
+
+<!-- Generated with Stardoc: http://skydoc.bazel.build -->
+
+Rules and macros for collecting LicenseInfo providers.
+
+<a id="gather_metadata_info_and_write"></a>
+
+## gather_metadata_info_and_write
+
+<pre>
+gather_metadata_info_and_write(<a href="#gather_metadata_info_and_write-name">name</a>)
+</pre>
+
+Collects TransitiveMetadataInfo providers and writes JSON representation to a file.
+
+    Usage:
+      bazel build //some:target           --aspects=@rules_license//rules_gathering:gather_metadata.bzl%gather_metadata_info_and_write
+          --output_groups=licenses
+    
+
+**ASPECT ATTRIBUTES**
+
+
+| Name | Type |
+| :------------- | :------------- |
+| *| String |
+
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="gather_metadata_info_and_write-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |   |
+
+
+
+<!-- Generated with Stardoc: http://skydoc.bazel.build -->
+
+Rules and macros for collecting package metdata providers.
+
+<a id="trace"></a>
+
+## trace
+
+<pre>
+trace(<a href="#trace-name">name</a>)
+</pre>
+
+Used to allow the specification of a target to trace while collecting license dependencies.
+
+**ATTRIBUTES**
+
+
+| Name  | Description | Type | Mandatory | Default |
+| :------------- | :------------- | :------------- | :------------- | :------------- |
+| <a id="trace-name"></a>name |  A unique name for this target.   | <a href="https://bazel.build/concepts/labels#target-names">Name</a> | required |  |
+
+
+
diff --git a/examples/manifest/android_mock.bzl b/examples/manifest/android_mock.bzl
index 0dee3c9..81b7417 100644
--- a/examples/manifest/android_mock.bzl
+++ b/examples/manifest/android_mock.bzl
@@ -1,4 +1,4 @@
-load("@rules_license//rules:compliance.bzl", "manifest")
+load("manifest.bzl", "manifest")
 
 """This is a proof of concept to show how to modify a macro definition to
 create a sub-graph allowing for build time injection of license information. We
diff --git a/examples/manifest/manifest.bzl b/examples/manifest/manifest.bzl
new file mode 100644
index 0000000..13309ae
--- /dev/null
+++ b/examples/manifest/manifest.bzl
@@ -0,0 +1,89 @@
+# Copyright 2023 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""An example using gather_licenses_info as input to another action."""
+
+load(
+    "@rules_license//rules:gather_licenses_info.bzl",
+    "gather_licenses_info",
+)
+load(
+    "@rules_license//rules_gathering:gathering_providers.bzl",
+    "TransitiveLicensesInfo",
+)
+
+def get_licenses_mapping(deps, warn = False):
+    """Creates list of entries representing all licenses for the deps.
+
+    Args:
+
+      deps: a list of deps which should have TransitiveLicensesInfo providers.
+            This requires that you have run the gather_licenses_info
+            aspect over them
+
+      warn: boolean, if true, display output about legacy targets that need
+            update
+
+    Returns:
+      {File:package_name}
+    """
+    tls = []
+    for dep in deps:
+        lds = dep[TransitiveLicensesInfo].licenses
+        tls.append(lds)
+
+    ds = depset(transitive = tls)
+
+    # Ignore any legacy licenses that may be in the report
+    mappings = {}
+    for lic in ds.to_list():
+        if type(lic.license_text) == "File":
+            mappings[lic.license_text] = lic.package_name
+        elif warn:
+            print("Legacy license %s not included, rule needs updating" % lic.license_text)
+    return mappings
+
+
+def _manifest_impl(ctx):
+    # Gather all licenses and make it available as deps for downstream rules
+    # Additionally write the list of license filenames to a file that can
+    # also be used as an input to downstream rules.
+    licenses_file = ctx.actions.declare_file(ctx.attr.out.name)
+    mappings = get_licenses_mapping(ctx.attr.deps, ctx.attr.warn_on_legacy_licenses)
+    ctx.actions.write(
+        output = licenses_file,
+        content = "\n".join([",".join([f.path, p]) for (f, p) in mappings.items()]),
+    )
+    return [DefaultInfo(files = depset(mappings.keys()))]
+
+_manifest = rule(
+    implementation = _manifest_impl,
+    doc = """Internal tmplementation method for manifest().""",
+    attrs = {
+        "deps": attr.label_list(
+            doc = """List of targets to collect license files for.""",
+            aspects = [gather_licenses_info],
+        ),
+        "out": attr.output(
+            doc = """Output file.""",
+            mandatory = True,
+        ),
+        "warn_on_legacy_licenses": attr.bool(default = False),
+    },
+)
+
+def manifest(name, deps, out = None, **kwargs):
+    if not out:
+        out = name + ".manifest"
+    _manifest(name = name, deps = deps, out = out, **kwargs)
+
diff --git a/examples/policy_checker/BUILD b/examples/policy_checker/BUILD
index 49f77aa..1b89067 100644
--- a/examples/policy_checker/BUILD
+++ b/examples/policy_checker/BUILD
@@ -47,7 +47,7 @@ license_policy(
 license_policy_check(
     name = "check_server",
     policy = ":production_service",
-    target = "//examples/src:my_server",
+    targets = ["//examples/src:my_server"],
 )
 
 
@@ -59,5 +59,5 @@ license_policy_check(
     tags = [
         "manual",
     ],
-    target = "//examples/src:my_violating_server",
+    targets = ["//examples/src:my_violating_server"],
 )
diff --git a/examples/policy_checker/license_policy_check.bzl b/examples/policy_checker/license_policy_check.bzl
index bb35eee..9b4045d 100644
--- a/examples/policy_checker/license_policy_check.bzl
+++ b/examples/policy_checker/license_policy_check.bzl
@@ -23,33 +23,36 @@ load(
     "gather_licenses_info",
 )
 load("@rules_license//rules:providers.bzl", "LicenseInfo")
-load("@rules_license//rules/private:gathering_providers.bzl", "TransitiveLicensesInfo")
+load("@rules_license//rules_gathering:gathering_providers.bzl", "TransitiveLicensesInfo")
 
-# This is a crude example of the kind of thing which can be done.
+# This is a crude example of the kind of license reporting which can be done.
 def _license_policy_check_impl(ctx):
     policy = ctx.attr.policy[LicensePolicyInfo]
     allowed_conditions = policy.conditions
-    if TransitiveLicensesInfo in ctx.attr.target:
-        for license in ctx.attr.target[TransitiveLicensesInfo].licenses.to_list():
-            for kind in license.license_kinds:
-                # print(kind.conditions)
-                for condition in kind.conditions:
-                    if condition not in allowed_conditions:
-                        fail("Condition %s violates policy %s" % (
-                            condition,
-                            policy.label,
-                        ))
 
-    if LicenseInfo in ctx.attr.target:
-        for license in ctx.attr.target[LicenseInfo].licenses.to_list():
-            for kind in license.license_kinds:
-                # print(kind.conditions)
-                for condition in kind.conditions:
-                    if condition not in allowed_conditions:
-                        fail("Condition %s violates policy %s" % (
-                            condition,
-                            policy.label,
-                        ))
+    for target in ctx.attr.targets:
+        if TransitiveLicensesInfo in target:
+            for license in target[TransitiveLicensesInfo].licenses.to_list():
+                for kind in license.license_kinds:
+                    for condition in kind.conditions:
+                        if condition not in allowed_conditions:
+                            fail("Condition %s violates policy %s of %s" % (
+                                condition,
+                                policy.label,
+                                target.label,
+                            ))
+
+    for target in ctx.attr.targets:
+        if LicenseInfo in target:
+            for license in target[LicenseInfo].licenses.to_list():
+                for kind in license.license_kinds:
+                    for condition in kind.conditions:
+                        if condition not in allowed_conditions:
+                            fail("Condition %s violates policy %s of %s" % (
+                                condition,
+                                policy.label,
+                                target.label,
+                            ))
     return [DefaultInfo()]
 
 _license_policy_check = rule(
@@ -61,21 +64,20 @@ _license_policy_check = rule(
             mandatory = True,
             providers = [LicensePolicyInfo],
         ),
-        "target": attr.label(
+        "targets": attr.label_list(
             doc = """Target to collect LicenseInfo for.""",
             aspects = [gather_licenses_info],
             mandatory = True,
-            allow_single_file = True,
         ),
     },
 )
 
-def license_policy_check(name, target, policy, **kwargs):
-    """Checks a target against a policy.
+def license_policy_check(name, targets, policy, **kwargs):
+    """Checks a list of targets against a policy.
 
     Args:
       name: The target.
-      target: A target to test for compliance with a policy
+      targets: A list of targets to test for compliance with a policy
       policy: A rule providing LicensePolicyInfo.
       **kwargs: other args.
 
@@ -83,8 +85,8 @@ def license_policy_check(name, target, policy, **kwargs):
 
       license_policy_check(
           name = "license_info",
-          target = ":my_app",
+          targets = [":my_app"],
           policy = "//my_org/compliance/policies:mobile_application",
       )
     """
-    _license_policy_check(name = name, target = target, policy = policy, **kwargs)
+    _license_policy_check(name = name, targets = targets, policy = policy, **kwargs)
diff --git a/examples/sboms/BUILD b/examples/sboms/BUILD
index 0c31a04..6af210c 100644
--- a/examples/sboms/BUILD
+++ b/examples/sboms/BUILD
@@ -1,13 +1,13 @@
 # Demonstrate the generate_sbom rule
 
-load("@rules_license//rules:sbom.bzl", "generate_sbom")
+load("@rules_license//rules_gathering:generate_sbom.bzl", "generate_sbom")
 
 # There are not a lot of targets in this rule set to build a SBOM from
 # so we will (in a very self-referential way) generate one for the tool
 # which generates the SBOMs
 # See the output in bazel-bin/examples/sboms/write_sbom.txt
 generate_sbom(
-    name = "write_sbom_sbom",
+    name = "write_sbom",
     out = "write_sbom.txt",
     deps = ["//tools:write_sbom"],
 )
diff --git a/examples/src/BUILD b/examples/src/BUILD
index cd5e985..b9476b3 100644
--- a/examples/src/BUILD
+++ b/examples/src/BUILD
@@ -13,8 +13,9 @@
 # limitations under the License.
 # Examples of applications and interactions with licenses
 
-load("@rules_license//rules:compliance.bzl", "check_license", "licenses_used")
 load("@rules_license//examples/vndor/constant_gen:defs.bzl", "constant_gen")
+load("@rules_license//rules:compliance.bzl", "check_license")
+load("@rules_license//sample_reports:licenses_used.bzl", "licenses_used")
 
 package(
     default_package_metadata = ["//:license", "//:package_info"],
diff --git a/examples/vndor/constant_gen/BUILD b/examples/vndor/constant_gen/BUILD
index 5f2ff43..dcde9e3 100644
--- a/examples/vndor/constant_gen/BUILD
+++ b/examples/vndor/constant_gen/BUILD
@@ -13,8 +13,8 @@
 # limitations under the License.
 # An example of a code generator with a distinct license for the generated code.
 
-load("@rules_license//rules:compliance.bzl", "licenses_used")
 load("@rules_license//rules:license.bzl", "license")
+load("@rules_license//sample_reports:licenses_used.bzl", "licenses_used")
 load(":defs.bzl", "constant_gen")
 
 package(
diff --git a/licenses/spdx/BUILD b/licenses/spdx/BUILD
index feb0580..280ed42 100644
--- a/licenses/spdx/BUILD
+++ b/licenses/spdx/BUILD
@@ -72,6 +72,12 @@ license_kind(
     url = "https://spdx.org/licenses/0BSD.html",
 )
 
+license_kind(
+    name = "3D-Slicer-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/3D-Slicer-1.0.html",
+)
+
 license_kind(
     name = "AAL",
     conditions = [],
@@ -84,18 +90,36 @@ license_kind(
     url = "https://spdx.org/licenses/Abstyles.html",
 )
 
+license_kind(
+    name = "AdaCore-doc",
+    conditions = [],
+    url = "https://spdx.org/licenses/AdaCore-doc.html",
+)
+
 license_kind(
     name = "Adobe-2006",
     conditions = [],
     url = "https://spdx.org/licenses/Adobe-2006.html",
 )
 
+license_kind(
+    name = "Adobe-Display-PostScript",
+    conditions = [],
+    url = "https://spdx.org/licenses/Adobe-Display-PostScript.html",
+)
+
 license_kind(
     name = "Adobe-Glyph",
     conditions = [],
     url = "https://spdx.org/licenses/Adobe-Glyph.html",
 )
 
+license_kind(
+    name = "Adobe-Utopia",
+    conditions = [],
+    url = "https://spdx.org/licenses/Adobe-Utopia.html",
+)
+
 license_kind(
     name = "ADSL",
     conditions = [],
@@ -180,6 +204,12 @@ license_kind(
     url = "https://spdx.org/licenses/Aladdin.html",
 )
 
+license_kind(
+    name = "AMD-newlib",
+    conditions = [],
+    url = "https://spdx.org/licenses/AMD-newlib.html",
+)
+
 license_kind(
     name = "AMDPLPA",
     conditions = [],
@@ -192,6 +222,12 @@ license_kind(
     url = "https://spdx.org/licenses/AML.html",
 )
 
+license_kind(
+    name = "AML-glslang",
+    conditions = [],
+    url = "https://spdx.org/licenses/AML-glslang.html",
+)
+
 license_kind(
     name = "AMPAS",
     conditions = [],
@@ -210,6 +246,12 @@ license_kind(
     url = "https://spdx.org/licenses/ANTLR-PD-fallback.html",
 )
 
+license_kind(
+    name = "any-OSI",
+    conditions = [],
+    url = "https://spdx.org/licenses/any-OSI.html",
+)
+
 license_kind(
     name = "Apache-1.0",
     conditions = [],
@@ -300,6 +342,18 @@ license_kind(
     url = "https://spdx.org/licenses/Artistic-2.0.html",
 )
 
+license_kind(
+    name = "ASWF-Digital-Assets-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/ASWF-Digital-Assets-1.0.html",
+)
+
+license_kind(
+    name = "ASWF-Digital-Assets-1.1",
+    conditions = [],
+    url = "https://spdx.org/licenses/ASWF-Digital-Assets-1.1.html",
+)
+
 license_kind(
     name = "Baekmuk",
     conditions = [],
@@ -318,12 +372,24 @@ license_kind(
     url = "https://spdx.org/licenses/Barr.html",
 )
 
+license_kind(
+    name = "bcrypt-Solar-Designer",
+    conditions = [],
+    url = "https://spdx.org/licenses/bcrypt-Solar-Designer.html",
+)
+
 license_kind(
     name = "Beerware",
     conditions = [],
     url = "https://spdx.org/licenses/Beerware.html",
 )
 
+license_kind(
+    name = "Bitstream-Charter",
+    conditions = [],
+    url = "https://spdx.org/licenses/Bitstream-Charter.html",
+)
+
 license_kind(
     name = "Bitstream-Vera",
     conditions = [],
@@ -354,12 +420,30 @@ license_kind(
     url = "https://spdx.org/licenses/BlueOak-1.0.0.html",
 )
 
+license_kind(
+    name = "Boehm-GC",
+    conditions = [],
+    url = "https://spdx.org/licenses/Boehm-GC.html",
+)
+
 license_kind(
     name = "Borceux",
     conditions = [],
     url = "https://spdx.org/licenses/Borceux.html",
 )
 
+license_kind(
+    name = "Brian-Gladman-2-Clause",
+    conditions = [],
+    url = "https://spdx.org/licenses/Brian-Gladman-2-Clause.html",
+)
+
+license_kind(
+    name = "Brian-Gladman-3-Clause",
+    conditions = [],
+    url = "https://spdx.org/licenses/Brian-Gladman-3-Clause.html",
+)
+
 license_kind(
     name = "BSD-1-Clause",
     conditions = [],
@@ -372,6 +456,18 @@ license_kind(
     url = "https://spdx.org/licenses/BSD-2-Clause.html",
 )
 
+license_kind(
+    name = "BSD-2-Clause-Darwin",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-2-Clause-Darwin.html",
+)
+
+license_kind(
+    name = "BSD-2-Clause-first-lines",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-2-Clause-first-lines.html",
+)
+
 license_kind(
     name = "BSD-2-Clause-FreeBSD",
     conditions = [],
@@ -402,6 +498,12 @@ license_kind(
     url = "https://spdx.org/licenses/BSD-3-Clause.html",
 )
 
+license_kind(
+    name = "BSD-3-Clause-acpica",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-3-Clause-acpica.html",
+)
+
 license_kind(
     name = "BSD-3-Clause-Attribution",
     conditions = [],
@@ -414,6 +516,18 @@ license_kind(
     url = "https://spdx.org/licenses/BSD-3-Clause-Clear.html",
 )
 
+license_kind(
+    name = "BSD-3-Clause-flex",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-3-Clause-flex.html",
+)
+
+license_kind(
+    name = "BSD-3-Clause-HP",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-3-Clause-HP.html",
+)
+
 license_kind(
     name = "BSD-3-Clause-LBNL",
     conditions = [],
@@ -456,6 +570,12 @@ license_kind(
     url = "https://spdx.org/licenses/BSD-3-Clause-Open-MPI.html",
 )
 
+license_kind(
+    name = "BSD-3-Clause-Sun",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-3-Clause-Sun.html",
+)
+
 license_kind(
     name = "BSD-4-Clause",
     conditions = [],
@@ -474,18 +594,66 @@ license_kind(
     url = "https://spdx.org/licenses/BSD-4-Clause-UC.html",
 )
 
+license_kind(
+    name = "BSD-4.3RENO",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-4.3RENO.html",
+)
+
+license_kind(
+    name = "BSD-4.3TAHOE",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-4.3TAHOE.html",
+)
+
+license_kind(
+    name = "BSD-Advertising-Acknowledgement",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Advertising-Acknowledgement.html",
+)
+
+license_kind(
+    name = "BSD-Attribution-HPND-disclaimer",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Attribution-HPND-disclaimer.html",
+)
+
+license_kind(
+    name = "BSD-Inferno-Nettverk",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Inferno-Nettverk.html",
+)
+
 license_kind(
     name = "BSD-Protection",
     conditions = [],
     url = "https://spdx.org/licenses/BSD-Protection.html",
 )
 
+license_kind(
+    name = "BSD-Source-beginning-file",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Source-beginning-file.html",
+)
+
 license_kind(
     name = "BSD-Source-Code",
     conditions = [],
     url = "https://spdx.org/licenses/BSD-Source-Code.html",
 )
 
+license_kind(
+    name = "BSD-Systemics",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Systemics.html",
+)
+
+license_kind(
+    name = "BSD-Systemics-W3Works",
+    conditions = [],
+    url = "https://spdx.org/licenses/BSD-Systemics-W3Works.html",
+)
+
 license_kind(
     name = "BSL-1.0",
     conditions = [],
@@ -534,6 +702,18 @@ license_kind(
     url = "https://spdx.org/licenses/Caldera.html",
 )
 
+license_kind(
+    name = "Caldera-no-preamble",
+    conditions = [],
+    url = "https://spdx.org/licenses/Caldera-no-preamble.html",
+)
+
+license_kind(
+    name = "Catharon",
+    conditions = [],
+    url = "https://spdx.org/licenses/Catharon.html",
+)
+
 license_kind(
     name = "CATOSL-1.1",
     conditions = [],
@@ -576,12 +756,24 @@ license_kind(
     url = "https://spdx.org/licenses/CC-BY-3.0-AT.html",
 )
 
+license_kind(
+    name = "CC-BY-3.0-AU",
+    conditions = [],
+    url = "https://spdx.org/licenses/CC-BY-3.0-AU.html",
+)
+
 license_kind(
     name = "CC-BY-3.0-DE",
     conditions = [],
     url = "https://spdx.org/licenses/CC-BY-3.0-DE.html",
 )
 
+license_kind(
+    name = "CC-BY-3.0-IGO",
+    conditions = [],
+    url = "https://spdx.org/licenses/CC-BY-3.0-IGO.html",
+)
+
 license_kind(
     name = "CC-BY-3.0-NL",
     conditions = [],
@@ -690,6 +882,12 @@ license_kind(
     url = "https://spdx.org/licenses/CC-BY-NC-SA-2.0.html",
 )
 
+license_kind(
+    name = "CC-BY-NC-SA-2.0-DE",
+    conditions = [],
+    url = "https://spdx.org/licenses/CC-BY-NC-SA-2.0-DE.html",
+)
+
 license_kind(
     name = "CC-BY-NC-SA-2.0-FR",
     conditions = [],
@@ -816,6 +1014,12 @@ license_kind(
     url = "https://spdx.org/licenses/CC-BY-SA-3.0-DE.html",
 )
 
+license_kind(
+    name = "CC-BY-SA-3.0-IGO",
+    conditions = [],
+    url = "https://spdx.org/licenses/CC-BY-SA-3.0-IGO.html",
+)
+
 license_kind(
     name = "CC-BY-SA-4.0",
     conditions = [],
@@ -936,12 +1140,48 @@ license_kind(
     url = "https://spdx.org/licenses/CERN-OHL-W-2.0.html",
 )
 
+license_kind(
+    name = "CFITSIO",
+    conditions = [],
+    url = "https://spdx.org/licenses/CFITSIO.html",
+)
+
+license_kind(
+    name = "check-cvs",
+    conditions = [],
+    url = "https://spdx.org/licenses/check-cvs.html",
+)
+
+license_kind(
+    name = "checkmk",
+    conditions = [],
+    url = "https://spdx.org/licenses/checkmk.html",
+)
+
 license_kind(
     name = "ClArtistic",
     conditions = [],
     url = "https://spdx.org/licenses/ClArtistic.html",
 )
 
+license_kind(
+    name = "Clips",
+    conditions = [],
+    url = "https://spdx.org/licenses/Clips.html",
+)
+
+license_kind(
+    name = "CMU-Mach",
+    conditions = [],
+    url = "https://spdx.org/licenses/CMU-Mach.html",
+)
+
+license_kind(
+    name = "CMU-Mach-nodoc",
+    conditions = [],
+    url = "https://spdx.org/licenses/CMU-Mach-nodoc.html",
+)
+
 license_kind(
     name = "CNRI-Jython",
     conditions = [],
@@ -990,6 +1230,12 @@ license_kind(
     url = "https://spdx.org/licenses/copyleft-next-0.3.1.html",
 )
 
+license_kind(
+    name = "Cornell-Lossless-JPEG",
+    conditions = [],
+    url = "https://spdx.org/licenses/Cornell-Lossless-JPEG.html",
+)
+
 license_kind(
     name = "CPAL-1.0",
     conditions = [],
@@ -1008,6 +1254,12 @@ license_kind(
     url = "https://spdx.org/licenses/CPOL-1.02.html",
 )
 
+license_kind(
+    name = "Cronyx",
+    conditions = [],
+    url = "https://spdx.org/licenses/Cronyx.html",
+)
+
 license_kind(
     name = "Crossword",
     conditions = [],
@@ -1038,12 +1290,24 @@ license_kind(
     url = "https://spdx.org/licenses/curl.html",
 )
 
+license_kind(
+    name = "cve-tou",
+    conditions = [],
+    url = "https://spdx.org/licenses/cve-tou.html",
+)
+
 license_kind(
     name = "D-FSL-1.0",
     conditions = [],
     url = "https://spdx.org/licenses/D-FSL-1.0.html",
 )
 
+license_kind(
+    name = "DEC-3-Clause",
+    conditions = [],
+    url = "https://spdx.org/licenses/DEC-3-Clause.html",
+)
+
 license_kind(
     name = "diffmark",
     conditions = [],
@@ -1056,12 +1320,36 @@ license_kind(
     url = "https://spdx.org/licenses/DL-DE-BY-2.0.html",
 )
 
+license_kind(
+    name = "DL-DE-ZERO-2.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/DL-DE-ZERO-2.0.html",
+)
+
 license_kind(
     name = "DOC",
     conditions = [],
     url = "https://spdx.org/licenses/DOC.html",
 )
 
+license_kind(
+    name = "DocBook-Schema",
+    conditions = [],
+    url = "https://spdx.org/licenses/DocBook-Schema.html",
+)
+
+license_kind(
+    name = "DocBook-Stylesheet",
+    conditions = [],
+    url = "https://spdx.org/licenses/DocBook-Stylesheet.html",
+)
+
+license_kind(
+    name = "DocBook-XML",
+    conditions = [],
+    url = "https://spdx.org/licenses/DocBook-XML.html",
+)
+
 license_kind(
     name = "Dotseqn",
     conditions = [],
@@ -1074,12 +1362,24 @@ license_kind(
     url = "https://spdx.org/licenses/DRL-1.0.html",
 )
 
+license_kind(
+    name = "DRL-1.1",
+    conditions = [],
+    url = "https://spdx.org/licenses/DRL-1.1.html",
+)
+
 license_kind(
     name = "DSDP",
     conditions = [],
     url = "https://spdx.org/licenses/DSDP.html",
 )
 
+license_kind(
+    name = "dtoa",
+    conditions = [],
+    url = "https://spdx.org/licenses/dtoa.html",
+)
+
 license_kind(
     name = "dvipdfm",
     conditions = [],
@@ -1200,12 +1500,24 @@ license_kind(
     url = "https://spdx.org/licenses/Fair.html",
 )
 
+license_kind(
+    name = "FBM",
+    conditions = [],
+    url = "https://spdx.org/licenses/FBM.html",
+)
+
 license_kind(
     name = "FDK-AAC",
     conditions = [],
     url = "https://spdx.org/licenses/FDK-AAC.html",
 )
 
+license_kind(
+    name = "Ferguson-Twofish",
+    conditions = [],
+    url = "https://spdx.org/licenses/Ferguson-Twofish.html",
+)
+
 license_kind(
     name = "Frameworx-1.0",
     conditions = [],
@@ -1230,6 +1542,12 @@ license_kind(
     url = "https://spdx.org/licenses/FSFAP.html",
 )
 
+license_kind(
+    name = "FSFAP-no-warranty-disclaimer",
+    conditions = [],
+    url = "https://spdx.org/licenses/FSFAP-no-warranty-disclaimer.html",
+)
+
 license_kind(
     name = "FSFUL",
     conditions = [],
@@ -1242,12 +1560,36 @@ license_kind(
     url = "https://spdx.org/licenses/FSFULLR.html",
 )
 
+license_kind(
+    name = "FSFULLRWD",
+    conditions = [],
+    url = "https://spdx.org/licenses/FSFULLRWD.html",
+)
+
 license_kind(
     name = "FTL",
     conditions = [],
     url = "https://spdx.org/licenses/FTL.html",
 )
 
+license_kind(
+    name = "Furuseth",
+    conditions = [],
+    url = "https://spdx.org/licenses/Furuseth.html",
+)
+
+license_kind(
+    name = "fwlw",
+    conditions = [],
+    url = "https://spdx.org/licenses/fwlw.html",
+)
+
+license_kind(
+    name = "GCR-docs",
+    conditions = [],
+    url = "https://spdx.org/licenses/GCR-docs.html",
+)
+
 license_kind(
     name = "GD",
     conditions = [],
@@ -1530,6 +1872,12 @@ license_kind(
     url = "https://spdx.org/licenses/GPL-3.0-with-GCC-exception.html",
 )
 
+license_kind(
+    name = "Graphics-Gems",
+    conditions = [],
+    url = "https://spdx.org/licenses/Graphics-Gems.html",
+)
+
 license_kind(
     name = "gSOAP-1.3b",
     conditions = [],
@@ -1537,57 +1885,237 @@ license_kind(
 )
 
 license_kind(
-    name = "HaskellReport",
+    name = "gtkbook",
     conditions = [],
-    url = "https://spdx.org/licenses/HaskellReport.html",
+    url = "https://spdx.org/licenses/gtkbook.html",
 )
 
 license_kind(
-    name = "Hippocratic-2.1",
+    name = "Gutmann",
     conditions = [],
-    url = "https://spdx.org/licenses/Hippocratic-2.1.html",
+    url = "https://spdx.org/licenses/Gutmann.html",
 )
 
 license_kind(
-    name = "HPND",
+    name = "HaskellReport",
     conditions = [],
-    url = "https://spdx.org/licenses/HPND.html",
+    url = "https://spdx.org/licenses/HaskellReport.html",
 )
 
 license_kind(
-    name = "HPND-sell-variant",
+    name = "hdparm",
     conditions = [],
-    url = "https://spdx.org/licenses/HPND-sell-variant.html",
+    url = "https://spdx.org/licenses/hdparm.html",
 )
 
 license_kind(
-    name = "HTMLTIDY",
+    name = "HIDAPI",
     conditions = [],
-    url = "https://spdx.org/licenses/HTMLTIDY.html",
+    url = "https://spdx.org/licenses/HIDAPI.html",
 )
 
 license_kind(
-    name = "IBM-pibs",
+    name = "Hippocratic-2.1",
     conditions = [],
-    url = "https://spdx.org/licenses/IBM-pibs.html",
+    url = "https://spdx.org/licenses/Hippocratic-2.1.html",
 )
 
 license_kind(
-    name = "ICU",
+    name = "HP-1986",
     conditions = [],
-    url = "https://spdx.org/licenses/ICU.html",
+    url = "https://spdx.org/licenses/HP-1986.html",
 )
 
 license_kind(
-    name = "IJG",
+    name = "HP-1989",
     conditions = [],
-    url = "https://spdx.org/licenses/IJG.html",
+    url = "https://spdx.org/licenses/HP-1989.html",
 )
 
 license_kind(
-    name = "ImageMagick",
+    name = "HPND",
     conditions = [],
-    url = "https://spdx.org/licenses/ImageMagick.html",
+    url = "https://spdx.org/licenses/HPND.html",
+)
+
+license_kind(
+    name = "HPND-DEC",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-DEC.html",
+)
+
+license_kind(
+    name = "HPND-doc",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-doc.html",
+)
+
+license_kind(
+    name = "HPND-doc-sell",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-doc-sell.html",
+)
+
+license_kind(
+    name = "HPND-export-US",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-export-US.html",
+)
+
+license_kind(
+    name = "HPND-export-US-acknowledgement",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-export-US-acknowledgement.html",
+)
+
+license_kind(
+    name = "HPND-export-US-modify",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-export-US-modify.html",
+)
+
+license_kind(
+    name = "HPND-export2-US",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-export2-US.html",
+)
+
+license_kind(
+    name = "HPND-Fenneberg-Livingston",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Fenneberg-Livingston.html",
+)
+
+license_kind(
+    name = "HPND-INRIA-IMAG",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-INRIA-IMAG.html",
+)
+
+license_kind(
+    name = "HPND-Intel",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Intel.html",
+)
+
+license_kind(
+    name = "HPND-Kevlin-Henney",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Kevlin-Henney.html",
+)
+
+license_kind(
+    name = "HPND-Markus-Kuhn",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Markus-Kuhn.html",
+)
+
+license_kind(
+    name = "HPND-merchantability-variant",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-merchantability-variant.html",
+)
+
+license_kind(
+    name = "HPND-MIT-disclaimer",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-MIT-disclaimer.html",
+)
+
+license_kind(
+    name = "HPND-Netrek",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Netrek.html",
+)
+
+license_kind(
+    name = "HPND-Pbmplus",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-Pbmplus.html",
+)
+
+license_kind(
+    name = "HPND-sell-MIT-disclaimer-xserver",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-sell-MIT-disclaimer-xserver.html",
+)
+
+license_kind(
+    name = "HPND-sell-regexpr",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-sell-regexpr.html",
+)
+
+license_kind(
+    name = "HPND-sell-variant",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-sell-variant.html",
+)
+
+license_kind(
+    name = "HPND-sell-variant-MIT-disclaimer",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-sell-variant-MIT-disclaimer.html",
+)
+
+license_kind(
+    name = "HPND-sell-variant-MIT-disclaimer-rev",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-sell-variant-MIT-disclaimer-rev.html",
+)
+
+license_kind(
+    name = "HPND-UC",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-UC.html",
+)
+
+license_kind(
+    name = "HPND-UC-export-US",
+    conditions = [],
+    url = "https://spdx.org/licenses/HPND-UC-export-US.html",
+)
+
+license_kind(
+    name = "HTMLTIDY",
+    conditions = [],
+    url = "https://spdx.org/licenses/HTMLTIDY.html",
+)
+
+license_kind(
+    name = "IBM-pibs",
+    conditions = [],
+    url = "https://spdx.org/licenses/IBM-pibs.html",
+)
+
+license_kind(
+    name = "ICU",
+    conditions = [],
+    url = "https://spdx.org/licenses/ICU.html",
+)
+
+license_kind(
+    name = "IEC-Code-Components-EULA",
+    conditions = [],
+    url = "https://spdx.org/licenses/IEC-Code-Components-EULA.html",
+)
+
+license_kind(
+    name = "IJG",
+    conditions = [],
+    url = "https://spdx.org/licenses/IJG.html",
+)
+
+license_kind(
+    name = "IJG-short",
+    conditions = [],
+    url = "https://spdx.org/licenses/IJG-short.html",
+)
+
+license_kind(
+    name = "ImageMagick",
+    conditions = [],
+    url = "https://spdx.org/licenses/ImageMagick.html",
 )
 
 license_kind(
@@ -1608,6 +2136,12 @@ license_kind(
     url = "https://spdx.org/licenses/Info-ZIP.html",
 )
 
+license_kind(
+    name = "Inner-Net-2.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/Inner-Net-2.0.html",
+)
+
 license_kind(
     name = "Intel",
     conditions = [],
@@ -1644,6 +2178,12 @@ license_kind(
     url = "https://spdx.org/licenses/ISC.html",
 )
 
+license_kind(
+    name = "ISC-Veillard",
+    conditions = [],
+    url = "https://spdx.org/licenses/ISC-Veillard.html",
+)
+
 license_kind(
     name = "Jam",
     conditions = [],
@@ -1656,6 +2196,12 @@ license_kind(
     url = "https://spdx.org/licenses/JasPer-2.0.html",
 )
 
+license_kind(
+    name = "JPL-image",
+    conditions = [],
+    url = "https://spdx.org/licenses/JPL-image.html",
+)
+
 license_kind(
     name = "JPNIC",
     conditions = [],
@@ -1668,12 +2214,30 @@ license_kind(
     url = "https://spdx.org/licenses/JSON.html",
 )
 
+license_kind(
+    name = "Kastrup",
+    conditions = [],
+    url = "https://spdx.org/licenses/Kastrup.html",
+)
+
+license_kind(
+    name = "Kazlib",
+    conditions = [],
+    url = "https://spdx.org/licenses/Kazlib.html",
+)
+
 license_kind(
     name = "KiCad-libraries-exception",
     conditions = [],
     url = "https://spdx.org/licenses/KiCad-libraries-exception.html",
 )
 
+license_kind(
+    name = "Knuth-CTAN",
+    conditions = [],
+    url = "https://spdx.org/licenses/Knuth-CTAN.html",
+)
+
 license_kind(
     name = "LAL-1.2",
     conditions = [],
@@ -1692,6 +2256,12 @@ license_kind(
     url = "https://spdx.org/licenses/Latex2e.html",
 )
 
+license_kind(
+    name = "Latex2e-translated-notice",
+    conditions = [],
+    url = "https://spdx.org/licenses/Latex2e-translated-notice.html",
+)
+
 license_kind(
     name = "Leptonica",
     conditions = [],
@@ -1800,6 +2370,12 @@ license_kind(
     url = "https://spdx.org/licenses/libtiff.html",
 )
 
+license_kind(
+    name = "libutil-David-Nugent",
+    conditions = [],
+    url = "https://spdx.org/licenses/libutil-David-Nugent.html",
+)
+
 license_kind(
     name = "LiLiQ-P-1.1",
     conditions = [],
@@ -1818,18 +2394,48 @@ license_kind(
     url = "https://spdx.org/licenses/LiLiQ-Rplus-1.1.html",
 )
 
+license_kind(
+    name = "Linux-man-pages-1-para",
+    conditions = [],
+    url = "https://spdx.org/licenses/Linux-man-pages-1-para.html",
+)
+
 license_kind(
     name = "Linux-man-pages-copyleft",
     conditions = [],
     url = "https://spdx.org/licenses/Linux-man-pages-copyleft.html",
 )
 
+license_kind(
+    name = "Linux-man-pages-copyleft-2-para",
+    conditions = [],
+    url = "https://spdx.org/licenses/Linux-man-pages-copyleft-2-para.html",
+)
+
+license_kind(
+    name = "Linux-man-pages-copyleft-var",
+    conditions = [],
+    url = "https://spdx.org/licenses/Linux-man-pages-copyleft-var.html",
+)
+
 license_kind(
     name = "Linux-OpenIB",
     conditions = [],
     url = "https://spdx.org/licenses/Linux-OpenIB.html",
 )
 
+license_kind(
+    name = "LOOP",
+    conditions = [],
+    url = "https://spdx.org/licenses/LOOP.html",
+)
+
+license_kind(
+    name = "LPD-document",
+    conditions = [],
+    url = "https://spdx.org/licenses/LPD-document.html",
+)
+
 license_kind(
     name = "LPL-1.0",
     conditions = [],
@@ -1872,12 +2478,84 @@ license_kind(
     url = "https://spdx.org/licenses/LPPL-1.3c.html",
 )
 
+license_kind(
+    name = "lsof",
+    conditions = [],
+    url = "https://spdx.org/licenses/lsof.html",
+)
+
+license_kind(
+    name = "Lucida-Bitmap-Fonts",
+    conditions = [],
+    url = "https://spdx.org/licenses/Lucida-Bitmap-Fonts.html",
+)
+
+license_kind(
+    name = "LZMA-SDK-9.11-to-9.20",
+    conditions = [],
+    url = "https://spdx.org/licenses/LZMA-SDK-9.11-to-9.20.html",
+)
+
+license_kind(
+    name = "LZMA-SDK-9.22",
+    conditions = [],
+    url = "https://spdx.org/licenses/LZMA-SDK-9.22.html",
+)
+
+license_kind(
+    name = "Mackerras-3-Clause",
+    conditions = [],
+    url = "https://spdx.org/licenses/Mackerras-3-Clause.html",
+)
+
+license_kind(
+    name = "Mackerras-3-Clause-acknowledgment",
+    conditions = [],
+    url = "https://spdx.org/licenses/Mackerras-3-Clause-acknowledgment.html",
+)
+
+license_kind(
+    name = "magaz",
+    conditions = [],
+    url = "https://spdx.org/licenses/magaz.html",
+)
+
+license_kind(
+    name = "mailprio",
+    conditions = [],
+    url = "https://spdx.org/licenses/mailprio.html",
+)
+
 license_kind(
     name = "MakeIndex",
     conditions = [],
     url = "https://spdx.org/licenses/MakeIndex.html",
 )
 
+license_kind(
+    name = "Martin-Birgmeier",
+    conditions = [],
+    url = "https://spdx.org/licenses/Martin-Birgmeier.html",
+)
+
+license_kind(
+    name = "McPhee-slideshow",
+    conditions = [],
+    url = "https://spdx.org/licenses/McPhee-slideshow.html",
+)
+
+license_kind(
+    name = "metamail",
+    conditions = [],
+    url = "https://spdx.org/licenses/metamail.html",
+)
+
+license_kind(
+    name = "Minpack",
+    conditions = [],
+    url = "https://spdx.org/licenses/Minpack.html",
+)
+
 license_kind(
     name = "MirOS",
     conditions = [],
@@ -1902,6 +2580,12 @@ license_kind(
     url = "https://spdx.org/licenses/MIT-advertising.html",
 )
 
+license_kind(
+    name = "MIT-Click",
+    conditions = [],
+    url = "https://spdx.org/licenses/MIT-Click.html",
+)
+
 license_kind(
     name = "MIT-CMU",
     conditions = [],
@@ -1920,6 +2604,18 @@ license_kind(
     url = "https://spdx.org/licenses/MIT-feh.html",
 )
 
+license_kind(
+    name = "MIT-Festival",
+    conditions = [],
+    url = "https://spdx.org/licenses/MIT-Festival.html",
+)
+
+license_kind(
+    name = "MIT-Khronos-old",
+    conditions = [],
+    url = "https://spdx.org/licenses/MIT-Khronos-old.html",
+)
+
 license_kind(
     name = "MIT-Modern-Variant",
     conditions = [],
@@ -1932,18 +2628,48 @@ license_kind(
     url = "https://spdx.org/licenses/MIT-open-group.html",
 )
 
+license_kind(
+    name = "MIT-testregex",
+    conditions = [],
+    url = "https://spdx.org/licenses/MIT-testregex.html",
+)
+
+license_kind(
+    name = "MIT-Wu",
+    conditions = [],
+    url = "https://spdx.org/licenses/MIT-Wu.html",
+)
+
 license_kind(
     name = "MITNFA",
     conditions = [],
     url = "https://spdx.org/licenses/MITNFA.html",
 )
 
+license_kind(
+    name = "MMIXware",
+    conditions = [],
+    url = "https://spdx.org/licenses/MMIXware.html",
+)
+
 license_kind(
     name = "Motosoto",
     conditions = [],
     url = "https://spdx.org/licenses/Motosoto.html",
 )
 
+license_kind(
+    name = "MPEG-SSG",
+    conditions = [],
+    url = "https://spdx.org/licenses/MPEG-SSG.html",
+)
+
+license_kind(
+    name = "mpi-permissive",
+    conditions = [],
+    url = "https://spdx.org/licenses/mpi-permissive.html",
+)
+
 license_kind(
     name = "mpich2",
     conditions = [],
@@ -1980,6 +2706,12 @@ license_kind(
     url = "https://spdx.org/licenses/mplus.html",
 )
 
+license_kind(
+    name = "MS-LPL",
+    conditions = [],
+    url = "https://spdx.org/licenses/MS-LPL.html",
+)
+
 license_kind(
     name = "MS-PL",
     conditions = [],
@@ -2046,12 +2778,24 @@ license_kind(
     url = "https://spdx.org/licenses/NBPL-1.0.html",
 )
 
+license_kind(
+    name = "NCBI-PD",
+    conditions = [],
+    url = "https://spdx.org/licenses/NCBI-PD.html",
+)
+
 license_kind(
     name = "NCGL-UK-2.0",
     conditions = [],
     url = "https://spdx.org/licenses/NCGL-UK-2.0.html",
 )
 
+license_kind(
+    name = "NCL",
+    conditions = [],
+    url = "https://spdx.org/licenses/NCL.html",
+)
+
 license_kind(
     name = "NCSA",
     conditions = [],
@@ -2082,6 +2826,12 @@ license_kind(
     url = "https://spdx.org/licenses/NGPL.html",
 )
 
+license_kind(
+    name = "NICTA-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/NICTA-1.0.html",
+)
+
 license_kind(
     name = "NIST-PD",
     conditions = [],
@@ -2094,6 +2844,12 @@ license_kind(
     url = "https://spdx.org/licenses/NIST-PD-fallback.html",
 )
 
+license_kind(
+    name = "NIST-Software",
+    conditions = [],
+    url = "https://spdx.org/licenses/NIST-Software.html",
+)
+
 license_kind(
     name = "NLOD-1.0",
     conditions = [],
@@ -2178,6 +2934,12 @@ license_kind(
     url = "https://spdx.org/licenses/O-UDA-1.0.html",
 )
 
+license_kind(
+    name = "OAR",
+    conditions = [],
+    url = "https://spdx.org/licenses/OAR.html",
+)
+
 license_kind(
     name = "OCCT-PL",
     conditions = [],
@@ -2202,6 +2964,12 @@ license_kind(
     url = "https://spdx.org/licenses/ODC-By-1.0.html",
 )
 
+license_kind(
+    name = "OFFIS",
+    conditions = [],
+    url = "https://spdx.org/licenses/OFFIS.html",
+)
+
 license_kind(
     name = "OFL-1.0",
     conditions = [],
@@ -2376,24 +3144,54 @@ license_kind(
     url = "https://spdx.org/licenses/OLDAP-2.8.html",
 )
 
+license_kind(
+    name = "OLFL-1.3",
+    conditions = [],
+    url = "https://spdx.org/licenses/OLFL-1.3.html",
+)
+
 license_kind(
     name = "OML",
     conditions = [],
     url = "https://spdx.org/licenses/OML.html",
 )
 
+license_kind(
+    name = "OpenPBS-2.3",
+    conditions = [],
+    url = "https://spdx.org/licenses/OpenPBS-2.3.html",
+)
+
 license_kind(
     name = "OpenSSL",
     conditions = [],
     url = "https://spdx.org/licenses/OpenSSL.html",
 )
 
+license_kind(
+    name = "OpenSSL-standalone",
+    conditions = [],
+    url = "https://spdx.org/licenses/OpenSSL-standalone.html",
+)
+
+license_kind(
+    name = "OpenVision",
+    conditions = [],
+    url = "https://spdx.org/licenses/OpenVision.html",
+)
+
 license_kind(
     name = "OPL-1.0",
     conditions = [],
     url = "https://spdx.org/licenses/OPL-1.0.html",
 )
 
+license_kind(
+    name = "OPL-UK-3.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/OPL-UK-3.0.html",
+)
+
 license_kind(
     name = "OPUBL-1.0",
     conditions = [],
@@ -2436,6 +3234,12 @@ license_kind(
     url = "https://spdx.org/licenses/OSL-3.0.html",
 )
 
+license_kind(
+    name = "PADL",
+    conditions = [],
+    url = "https://spdx.org/licenses/PADL.html",
+)
+
 license_kind(
     name = "Parity-6.0.0",
     conditions = [],
@@ -2466,12 +3270,30 @@ license_kind(
     url = "https://spdx.org/licenses/PHP-3.01.html",
 )
 
+license_kind(
+    name = "Pixar",
+    conditions = [],
+    url = "https://spdx.org/licenses/Pixar.html",
+)
+
+license_kind(
+    name = "pkgconf",
+    conditions = [],
+    url = "https://spdx.org/licenses/pkgconf.html",
+)
+
 license_kind(
     name = "Plexus",
     conditions = [],
     url = "https://spdx.org/licenses/Plexus.html",
 )
 
+license_kind(
+    name = "pnmstitch",
+    conditions = [],
+    url = "https://spdx.org/licenses/pnmstitch.html",
+)
+
 license_kind(
     name = "PolyForm-Noncommercial-1.0.0",
     conditions = [],
@@ -2490,6 +3312,12 @@ license_kind(
     url = "https://spdx.org/licenses/PostgreSQL.html",
 )
 
+license_kind(
+    name = "PPL",
+    conditions = [],
+    url = "https://spdx.org/licenses/PPL.html",
+)
+
 license_kind(
     name = "PSF-2.0",
     conditions = [],
@@ -2514,6 +3342,18 @@ license_kind(
     url = "https://spdx.org/licenses/Python-2.0.html",
 )
 
+license_kind(
+    name = "Python-2.0.1",
+    conditions = [],
+    url = "https://spdx.org/licenses/Python-2.0.1.html",
+)
+
+license_kind(
+    name = "python-ldap",
+    conditions = [],
+    url = "https://spdx.org/licenses/python-ldap.html",
+)
+
 license_kind(
     name = "Qhull",
     conditions = [],
@@ -2526,6 +3366,18 @@ license_kind(
     url = "https://spdx.org/licenses/QPL-1.0.html",
 )
 
+license_kind(
+    name = "QPL-1.0-INRIA-2004",
+    conditions = [],
+    url = "https://spdx.org/licenses/QPL-1.0-INRIA-2004.html",
+)
+
+license_kind(
+    name = "radvd",
+    conditions = [],
+    url = "https://spdx.org/licenses/radvd.html",
+)
+
 license_kind(
     name = "Rdisc",
     conditions = [],
@@ -2574,12 +3426,24 @@ license_kind(
     url = "https://spdx.org/licenses/Ruby.html",
 )
 
+license_kind(
+    name = "Ruby-pty",
+    conditions = [],
+    url = "https://spdx.org/licenses/Ruby-pty.html",
+)
+
 license_kind(
     name = "SAX-PD",
     conditions = [],
     url = "https://spdx.org/licenses/SAX-PD.html",
 )
 
+license_kind(
+    name = "SAX-PD-2.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/SAX-PD-2.0.html",
+)
+
 license_kind(
     name = "Saxpath",
     conditions = [],
@@ -2628,6 +3492,18 @@ license_kind(
     url = "https://spdx.org/licenses/SGI-B-2.0.html",
 )
 
+license_kind(
+    name = "SGI-OpenGL",
+    conditions = [],
+    url = "https://spdx.org/licenses/SGI-OpenGL.html",
+)
+
+license_kind(
+    name = "SGP4",
+    conditions = [],
+    url = "https://spdx.org/licenses/SGP4.html",
+)
+
 license_kind(
     name = "SHL-0.5",
     conditions = [],
@@ -2658,6 +3534,12 @@ license_kind(
     url = "https://spdx.org/licenses/SISSL-1.2.html",
 )
 
+license_kind(
+    name = "SL",
+    conditions = [],
+    url = "https://spdx.org/licenses/SL.html",
+)
+
 license_kind(
     name = "Sleepycat",
     conditions = [],
@@ -2682,6 +3564,24 @@ license_kind(
     url = "https://spdx.org/licenses/SNIA.html",
 )
 
+license_kind(
+    name = "snprintf",
+    conditions = [],
+    url = "https://spdx.org/licenses/snprintf.html",
+)
+
+license_kind(
+    name = "softSurfer",
+    conditions = [],
+    url = "https://spdx.org/licenses/softSurfer.html",
+)
+
+license_kind(
+    name = "Soundex",
+    conditions = [],
+    url = "https://spdx.org/licenses/Soundex.html",
+)
+
 license_kind(
     name = "Spencer-86",
     conditions = [],
@@ -2706,6 +3606,12 @@ license_kind(
     url = "https://spdx.org/licenses/SPL-1.0.html",
 )
 
+license_kind(
+    name = "ssh-keyscan",
+    conditions = [],
+    url = "https://spdx.org/licenses/ssh-keyscan.html",
+)
+
 license_kind(
     name = "SSH-OpenSSH",
     conditions = [],
@@ -2718,6 +3624,12 @@ license_kind(
     url = "https://spdx.org/licenses/SSH-short.html",
 )
 
+license_kind(
+    name = "SSLeay-standalone",
+    conditions = [],
+    url = "https://spdx.org/licenses/SSLeay-standalone.html",
+)
+
 license_kind(
     name = "SSPL-1.0",
     conditions = [],
@@ -2736,12 +3648,42 @@ license_kind(
     url = "https://spdx.org/licenses/SugarCRM-1.1.3.html",
 )
 
+license_kind(
+    name = "Sun-PPP",
+    conditions = [],
+    url = "https://spdx.org/licenses/Sun-PPP.html",
+)
+
+license_kind(
+    name = "Sun-PPP-2000",
+    conditions = [],
+    url = "https://spdx.org/licenses/Sun-PPP-2000.html",
+)
+
+license_kind(
+    name = "SunPro",
+    conditions = [],
+    url = "https://spdx.org/licenses/SunPro.html",
+)
+
 license_kind(
     name = "SWL",
     conditions = [],
     url = "https://spdx.org/licenses/SWL.html",
 )
 
+license_kind(
+    name = "swrule",
+    conditions = [],
+    url = "https://spdx.org/licenses/swrule.html",
+)
+
+license_kind(
+    name = "Symlinks",
+    conditions = [],
+    url = "https://spdx.org/licenses/Symlinks.html",
+)
+
 license_kind(
     name = "TAPR-OHL-1.0",
     conditions = [],
@@ -2760,6 +3702,24 @@ license_kind(
     url = "https://spdx.org/licenses/TCP-wrappers.html",
 )
 
+license_kind(
+    name = "TermReadKey",
+    conditions = [],
+    url = "https://spdx.org/licenses/TermReadKey.html",
+)
+
+license_kind(
+    name = "TGPPL-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/TGPPL-1.0.html",
+)
+
+license_kind(
+    name = "threeparttable",
+    conditions = [],
+    url = "https://spdx.org/licenses/threeparttable.html",
+)
+
 license_kind(
     name = "TMate",
     conditions = [],
@@ -2778,6 +3738,36 @@ license_kind(
     url = "https://spdx.org/licenses/TOSL.html",
 )
 
+license_kind(
+    name = "TPDL",
+    conditions = [],
+    url = "https://spdx.org/licenses/TPDL.html",
+)
+
+license_kind(
+    name = "TPL-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/TPL-1.0.html",
+)
+
+license_kind(
+    name = "TrustedQSL",
+    conditions = [],
+    url = "https://spdx.org/licenses/TrustedQSL.html",
+)
+
+license_kind(
+    name = "TTWL",
+    conditions = [],
+    url = "https://spdx.org/licenses/TTWL.html",
+)
+
+license_kind(
+    name = "TTYP0",
+    conditions = [],
+    url = "https://spdx.org/licenses/TTYP0.html",
+)
+
 license_kind(
     name = "TU-Berlin-1.0",
     conditions = [],
@@ -2790,12 +3780,42 @@ license_kind(
     url = "https://spdx.org/licenses/TU-Berlin-2.0.html",
 )
 
+license_kind(
+    name = "Ubuntu-font-1.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/Ubuntu-font-1.0.html",
+)
+
+license_kind(
+    name = "UCAR",
+    conditions = [],
+    url = "https://spdx.org/licenses/UCAR.html",
+)
+
 license_kind(
     name = "UCL-1.0",
     conditions = [],
     url = "https://spdx.org/licenses/UCL-1.0.html",
 )
 
+license_kind(
+    name = "ulem",
+    conditions = [],
+    url = "https://spdx.org/licenses/ulem.html",
+)
+
+license_kind(
+    name = "UMich-Merit",
+    conditions = [],
+    url = "https://spdx.org/licenses/UMich-Merit.html",
+)
+
+license_kind(
+    name = "Unicode-3.0",
+    conditions = [],
+    url = "https://spdx.org/licenses/Unicode-3.0.html",
+)
+
 license_kind(
     name = "Unicode-DFS-2015",
     conditions = [],
@@ -2814,6 +3834,12 @@ license_kind(
     url = "https://spdx.org/licenses/Unicode-TOU.html",
 )
 
+license_kind(
+    name = "UnixCrypt",
+    conditions = [],
+    url = "https://spdx.org/licenses/UnixCrypt.html",
+)
+
 license_kind(
     name = "Unlicense",
     conditions = [],
@@ -2826,6 +3852,12 @@ license_kind(
     url = "https://spdx.org/licenses/UPL-1.0.html",
 )
 
+license_kind(
+    name = "URT-RLE",
+    conditions = [],
+    url = "https://spdx.org/licenses/URT-RLE.html",
+)
+
 license_kind(
     name = "Vim",
     conditions = [],
@@ -2862,12 +3894,24 @@ license_kind(
     url = "https://spdx.org/licenses/W3C-20150513.html",
 )
 
+license_kind(
+    name = "w3m",
+    conditions = [],
+    url = "https://spdx.org/licenses/w3m.html",
+)
+
 license_kind(
     name = "Watcom-1.0",
     conditions = [],
     url = "https://spdx.org/licenses/Watcom-1.0.html",
 )
 
+license_kind(
+    name = "Widget-Workshop",
+    conditions = [],
+    url = "https://spdx.org/licenses/Widget-Workshop.html",
+)
+
 license_kind(
     name = "Wsuipa",
     conditions = [],
@@ -2898,12 +3942,30 @@ license_kind(
     url = "https://spdx.org/licenses/X11-distribute-modifications-variant.html",
 )
 
+license_kind(
+    name = "X11-swapped",
+    conditions = [],
+    url = "https://spdx.org/licenses/X11-swapped.html",
+)
+
+license_kind(
+    name = "Xdebug-1.03",
+    conditions = [],
+    url = "https://spdx.org/licenses/Xdebug-1.03.html",
+)
+
 license_kind(
     name = "Xerox",
     conditions = [],
     url = "https://spdx.org/licenses/Xerox.html",
 )
 
+license_kind(
+    name = "Xfig",
+    conditions = [],
+    url = "https://spdx.org/licenses/Xfig.html",
+)
+
 license_kind(
     name = "XFree86-1.1",
     conditions = [],
@@ -2916,6 +3978,18 @@ license_kind(
     url = "https://spdx.org/licenses/xinetd.html",
 )
 
+license_kind(
+    name = "xkeyboard-config-Zinoviev",
+    conditions = [],
+    url = "https://spdx.org/licenses/xkeyboard-config-Zinoviev.html",
+)
+
+license_kind(
+    name = "xlock",
+    conditions = [],
+    url = "https://spdx.org/licenses/xlock.html",
+)
+
 license_kind(
     name = "Xnet",
     conditions = [],
@@ -2934,6 +4008,12 @@ license_kind(
     url = "https://spdx.org/licenses/XSkat.html",
 )
 
+license_kind(
+    name = "xzoom",
+    conditions = [],
+    url = "https://spdx.org/licenses/xzoom.html",
+)
+
 license_kind(
     name = "YPL-1.0",
     conditions = [],
@@ -2952,6 +4032,12 @@ license_kind(
     url = "https://spdx.org/licenses/Zed.html",
 )
 
+license_kind(
+    name = "Zeeff",
+    conditions = [],
+    url = "https://spdx.org/licenses/Zeeff.html",
+)
+
 license_kind(
     name = "Zend-2.0",
     conditions = [],
diff --git a/rules/BUILD b/rules/BUILD
index 83e8c14..387019a 100644
--- a/rules/BUILD
+++ b/rules/BUILD
@@ -15,7 +15,7 @@
 # limitations under the License.
 """Rules for making license declarations."""
 
-load("@rules_license//rules:licenses_core.bzl", "trace")
+load("@rules_license//rules_gathering:trace.bzl", "trace")
 
 package(
     default_applicable_licenses = ["//:license"],
@@ -35,7 +35,10 @@ trace(
 
 filegroup(
     name = "standard_package",
-    srcs = glob(["**"]),
+    srcs = glob([
+        "**/BUILD",
+        "**/*.bzl",
+    ]),
 )
 
 # Do not create a bzl_library(). That would create a dependency loop back
diff --git a/rules/compliance.bzl b/rules/compliance.bzl
index 2fb04ab..c4010f0 100644
--- a/rules/compliance.bzl
+++ b/rules/compliance.bzl
@@ -20,10 +20,18 @@ load(
     "write_licenses_info",
 )
 load(
-    "@rules_license//rules/private:gathering_providers.bzl",
+    "@rules_license//rules_gathering:gathering_providers.bzl",
     "TransitiveLicensesInfo",
 )
 
+# Forward licenses used until users migrate. Delete at 0.0.7 or 0.1.0.
+load(
+    "@rules_license//sample_reports:licenses_used.bzl",
+    _licenses_used = "licenses_used",
+)
+
+licenses_used = _licenses_used
+
 # This rule is proof of concept, and may not represent the final
 # form of a rule for compliance validation.
 def _check_license_impl(ctx):
@@ -59,8 +67,10 @@ def _check_license_impl(ctx):
         executable = ctx.executable._checker,
         arguments = [args],
     )
-    outputs.append(licenses_file)  # also make the json file available.
-    return [DefaultInfo(files = depset(outputs))]
+    return [
+        DefaultInfo(files = depset(outputs)),
+        OutputGroupInfo(licenses_file = depset([licenses_file])),
+    ]
 
 _check_license = rule(
     implementation = _check_license_impl,
@@ -119,26 +129,6 @@ def manifest(name, deps, out = None, **kwargs):
 
     _manifest(name = name, deps = deps, out = out, **kwargs)
 
-def _licenses_used_impl(ctx):
-    # Gather all licenses and make it available as JSON
-    write_licenses_info(ctx, ctx.attr.deps, ctx.outputs.out)
-    return [DefaultInfo(files = depset([ctx.outputs.out]))]
-
-_licenses_used = rule(
-    implementation = _licenses_used_impl,
-    doc = """Internal tmplementation method for licenses_used().""",
-    attrs = {
-        "deps": attr.label_list(
-            doc = """List of targets to collect LicenseInfo for.""",
-            aspects = [gather_licenses_info_and_write],
-        ),
-        "out": attr.output(
-            doc = """Output file.""",
-            mandatory = True,
-        ),
-    },
-)
-
 def get_licenses_mapping(deps, warn = False):
     """Creates list of entries representing all licenses for the deps.
 
@@ -170,28 +160,3 @@ def get_licenses_mapping(deps, warn = False):
             print("Legacy license %s not included, rule needs updating" % lic.license_text)
 
     return mappings
-
-def licenses_used(name, deps, out = None, **kwargs):
-    """Collects LicensedInfo providers for a set of targets and writes as JSON.
-
-    The output is a single JSON array, with an entry for each license used.
-    See gather_licenses_info.bzl:write_licenses_info() for a description of the schema.
-
-    Args:
-      name: The target.
-      deps: A list of targets to get LicenseInfo for. The output is the union of
-            the result, not a list of information for each dependency.
-      out: The output file name. Default: <name>.json.
-      **kwargs: Other args
-
-    Usage:
-
-      licenses_used(
-          name = "license_info",
-          deps = [":my_app"],
-          out = "license_info.json",
-      )
-    """
-    if not out:
-        out = name + ".json"
-    _licenses_used(name = name, deps = deps, out = out, **kwargs)
diff --git a/rules/gather_licenses_info.bzl b/rules/gather_licenses_info.bzl
index 9dd1cbc..518d5ff 100644
--- a/rules/gather_licenses_info.bzl
+++ b/rules/gather_licenses_info.bzl
@@ -15,18 +15,14 @@
 
 load(
     "@rules_license//rules:licenses_core.bzl",
-    "TraceInfo",
     "gather_metadata_info_common",
     "should_traverse",
 )
 load(
-    "@rules_license//rules/private:gathering_providers.bzl",
+    "@rules_license//rules_gathering:gathering_providers.bzl",
     "TransitiveLicensesInfo",
 )
-
-# Definition for compliance namespace, used for filtering licenses
-# based on the namespace to which they belong.
-NAMESPACES = ["compliance"]
+load("@rules_license//rules_gathering:trace.bzl", "TraceInfo")
 
 def _strip_null_repo(label):
     """Removes the null repo name (e.g. @//) from a string.
@@ -41,7 +37,7 @@ def _strip_null_repo(label):
     return s
 
 def _gather_licenses_info_impl(target, ctx):
-    return gather_metadata_info_common(target, ctx, TransitiveLicensesInfo, NAMESPACES, [], should_traverse)
+    return gather_metadata_info_common(target, ctx, TransitiveLicensesInfo, [], should_traverse)
 
 gather_licenses_info = aspect(
     doc = """Collects LicenseInfo providers into a single TransitiveLicensesInfo provider.""",
@@ -76,7 +72,8 @@ def _write_licenses_info_impl(target, ctx):
 
     # Write the output file for the target
     name = "%s_licenses_info.json" % ctx.label.name
-    content = "[\n%s\n]\n" % ",\n".join(licenses_info_to_json(info))
+    lic_info, _ = licenses_info_to_json(info)
+    content = "[\n%s\n]\n" % ",\n".join(lic_info)
     out = ctx.actions.declare_file(name)
     ctx.actions.write(
         output = out,
@@ -130,8 +127,14 @@ def write_licenses_info(ctx, deps, json_out):
 
       def _foo_impl(ctx):
         ...
-        out = ctx.actions.declare_file("%s_licenses.json" % ctx.label.name)
-        write_licenses_info(ctx, ctx.attr.deps, licenses_file)
+        json_file = ctx.actions.declare_file("%s_licenses.json" % ctx.label.name)
+        license_files = write_licenses_info(ctx, ctx.attr.deps, json_file)
+
+        // process the json file and the license_files referenced by it
+        ctx.actions.run(
+          inputs = [json_file] + license_files
+          executable = ...
+        )
 
     Args:
       ctx: context of the caller
@@ -139,15 +142,26 @@ def write_licenses_info(ctx, deps, json_out):
             This requires that you have run the gather_licenses_info
             aspect over them
       json_out: output handle to write the JSON info
+
+    Returns:
+      A list of License File objects for each of the license paths referenced in the json.
     """
-    licenses = []
+    licenses_json = []
+    licenses_files = []
     for dep in deps:
         if TransitiveLicensesInfo in dep:
-            licenses.extend(licenses_info_to_json(dep[TransitiveLicensesInfo]))
+            transitive_licenses_info = dep[TransitiveLicensesInfo]            
+            lic_info, _ = licenses_info_to_json(transitive_licenses_info)
+            licenses_json.extend(lic_info)
+            for info in transitive_licenses_info.licenses.to_list():
+                if info.license_text:
+                    licenses_files.append(info.license_text)
+
     ctx.actions.write(
         output = json_out,
-        content = "[\n%s\n]\n" % ",\n".join(licenses),
+        content = "[\n%s\n]\n" % ",\n".join(licenses_json),
     )
+    return licenses_files
 
 def licenses_info_to_json(licenses_info):
     """Render a single LicenseInfo provider to JSON
@@ -157,6 +171,7 @@ def licenses_info_to_json(licenses_info):
 
     Returns:
       [(str)] list of LicenseInfo values rendered as JSON.
+      [(File)] list of Files containing license texts.
     """
 
     main_template = """  {{
@@ -195,6 +210,7 @@ def licenses_info_to_json(licenses_info):
           {{
             "target": "{kind_path}",
             "name": "{kind_name}",
+            "long_name": "{kind_long_name}",
             "conditions": {kind_conditions}
           }}"""
 
@@ -209,11 +225,17 @@ def licenses_info_to_json(licenses_info):
             used_by[license].append(_strip_null_repo(dep.target_under_license))
 
     all_licenses = []
+    all_license_text_files = []
     for license in sorted(licenses_info.licenses.to_list(), key = lambda x: x.label):
         kinds = []
         for kind in sorted(license.license_kinds, key = lambda x: x.name):
+            if hasattr(kind, "long_name"):
+                long_name = kind.long_name
+            else:
+                long_name = ""
             kinds.append(kind_template.format(
                 kind_name = kind.name,
+                kind_long_name = long_name,
                 kind_path = kind.label,
                 kind_conditions = kind.conditions,
             ))
@@ -231,11 +253,12 @@ def licenses_info_to_json(licenses_info):
                 label = _strip_null_repo(license.label),
                 used_by = ",\n          ".join(sorted(['"%s"' % x for x in used_by[str(license.label)]])),
             ))
-
+            # Additionally return all File references so that other rules invoking
+            # this method can load license text file contents from external repos
+            # using runfiles
+            all_license_text_files.append(license.license_text)
     all_deps = []
     for dep in sorted(licenses_info.deps.to_list(), key = lambda x: x.target_under_license):
-        licenses_used = []
-
         # Undo the concatenation applied when stored in the provider.
         dep_licenses = dep.licenses.split(",")
         all_deps.append(dep_template.format(
@@ -247,4 +270,4 @@ def licenses_info_to_json(licenses_info):
         top_level_target = _strip_null_repo(licenses_info.target_under_license),
         dependencies = ",".join(all_deps),
         licenses = ",".join(all_licenses),
-    )]
+    )], all_license_text_files
diff --git a/rules/gather_metadata.bzl b/rules/gather_metadata.bzl
index 162ea97..2be8bfa 100644
--- a/rules/gather_metadata.bzl
+++ b/rules/gather_metadata.bzl
@@ -1,4 +1,4 @@
-# Copyright 2022 Google LLC
+# Copyright 2023 Google LLC
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -11,299 +11,15 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-"""Rules and macros for collecting LicenseInfo providers."""
+"""Forwarder for gather_metadata_info.
 
+To be deleted before version 0.1.0
+"""
 load(
-    "@rules_license//rules:licenses_core.bzl",
-    "TraceInfo",
-    "gather_metadata_info_common",
-    "should_traverse",
+    "@rules_license//rules_gathering:gather_metadata.bzl",
+    _gather_metadata_info = "gather_metadata_info",
+    _gather_metadata_info_and_write = "gather_metadata_info_and_write",
 )
-load(
-    "@rules_license//rules:providers.bzl",
-    "ExperimentalMetadataInfo",
-    "PackageInfo",
-)
-load(
-    "@rules_license//rules/private:gathering_providers.bzl",
-    "TransitiveMetadataInfo",
-)
-
-# Definition for compliance namespace, used for filtering licenses
-# based on the namespace to which they belong.
-NAMESPACES = ["compliance"]
-
-def _strip_null_repo(label):
-    """Removes the null repo name (e.g. @//) from a string.
-
-    The is to make str(label) compatible between bazel 5.x and 6.x
-    """
-    s = str(label)
-    if s.startswith('@//'):
-        return s[1:]
-    elif s.startswith('@@//'):
-        return s[2:]
-    return s
-
-def _bazel_package(label):
-    clean_label = _strip_null_repo(label)
-    return clean_label[0:-(len(label.name) + 1)]
-
-def _gather_metadata_info_impl(target, ctx):
-    return gather_metadata_info_common(
-        target,
-        ctx,
-        TransitiveMetadataInfo,
-        NAMESPACES,
-        [ExperimentalMetadataInfo, PackageInfo],
-        should_traverse)
-
-gather_metadata_info = aspect(
-    doc = """Collects LicenseInfo providers into a single TransitiveMetadataInfo provider.""",
-    implementation = _gather_metadata_info_impl,
-    attr_aspects = ["*"],
-    attrs = {
-        "_trace": attr.label(default = "@rules_license//rules:trace_target"),
-    },
-    provides = [TransitiveMetadataInfo],
-    apply_to_generating_rules = True,
-)
-
-def _write_metadata_info_impl(target, ctx):
-    """Write transitive license info into a JSON file
-
-    Args:
-      target: The target of the aspect.
-      ctx: The aspect evaluation context.
-
-    Returns:
-      OutputGroupInfo
-    """
-
-    if not TransitiveMetadataInfo in target:
-        return [OutputGroupInfo(licenses = depset())]
-    info = target[TransitiveMetadataInfo]
-    outs = []
-
-    # If the result doesn't contain licenses, we simply return the provider
-    if not hasattr(info, "target_under_license"):
-        return [OutputGroupInfo(licenses = depset())]
-
-    # Write the output file for the target
-    name = "%s_metadata_info.json" % ctx.label.name
-    content = "[\n%s\n]\n" % ",\n".join(metadata_info_to_json(info))
-    out = ctx.actions.declare_file(name)
-    ctx.actions.write(
-        output = out,
-        content = content,
-    )
-    outs.append(out)
-
-    if ctx.attr._trace[TraceInfo].trace:
-        trace = ctx.actions.declare_file("%s_trace_info.json" % ctx.label.name)
-        ctx.actions.write(output = trace, content = "\n".join(info.traces))
-        outs.append(trace)
-
-    return [OutputGroupInfo(licenses = depset(outs))]
-
-gather_metadata_info_and_write = aspect(
-    doc = """Collects TransitiveMetadataInfo providers and writes JSON representation to a file.
-
-    Usage:
-      bazel build //some:target \
-          --aspects=@rules_license//rules:gather_metadata_info.bzl%gather_metadata_info_and_write
-          --output_groups=licenses
-    """,
-    implementation = _write_metadata_info_impl,
-    attr_aspects = ["*"],
-    attrs = {
-        "_trace": attr.label(default = "@rules_license//rules:trace_target"),
-    },
-    provides = [OutputGroupInfo],
-    requires = [gather_metadata_info],
-    apply_to_generating_rules = True,
-)
-
-def write_metadata_info(ctx, deps, json_out):
-    """Writes TransitiveMetadataInfo providers for a set of targets as JSON.
-
-    TODO(aiuto): Document JSON schema. But it is under development, so the current
-    best place to look is at tests/hello_licenses.golden.
-
-    Usage:
-      write_metadata_info must be called from a rule implementation, where the
-      rule has run the gather_metadata_info aspect on its deps to
-      collect the transitive closure of LicenseInfo providers into a
-      LicenseInfo provider.
-
-      foo = rule(
-        implementation = _foo_impl,
-        attrs = {
-           "deps": attr.label_list(aspects = [gather_metadata_info])
-        }
-      )
-
-      def _foo_impl(ctx):
-        ...
-        out = ctx.actions.declare_file("%s_licenses.json" % ctx.label.name)
-        write_metadata_info(ctx, ctx.attr.deps, metadata_file)
-
-    Args:
-      ctx: context of the caller
-      deps: a list of deps which should have TransitiveMetadataInfo providers.
-            This requires that you have run the gather_metadata_info
-            aspect over them
-      json_out: output handle to write the JSON info
-    """
-    licenses = []
-    for dep in deps:
-        if TransitiveMetadataInfo in dep:
-            licenses.extend(metadata_info_to_json(dep[TransitiveMetadataInfo]))
-    ctx.actions.write(
-        output = json_out,
-        content = "[\n%s\n]\n" % ",\n".join(licenses),
-    )
-
-def metadata_info_to_json(metadata_info):
-    """Render a single LicenseInfo provider to JSON
-
-    Args:
-      metadata_info: A LicenseInfo.
-
-    Returns:
-      [(str)] list of LicenseInfo values rendered as JSON.
-    """
-
-    main_template = """  {{
-    "top_level_target": "{top_level_target}",
-    "dependencies": [{dependencies}
-    ],
-    "licenses": [{licenses}
-    ],
-    "packages": [{packages}
-    ]\n  }}"""
-
-    dep_template = """
-      {{
-        "target_under_license": "{target_under_license}",
-        "licenses": [
-          {licenses}
-        ]
-      }}"""
-
-    license_template = """
-      {{
-        "label": "{label}",
-        "bazel_package": "{bazel_package}",
-        "license_kinds": [{kinds}
-        ],
-        "copyright_notice": "{copyright_notice}",
-        "package_name": "{package_name}",
-        "package_url": "{package_url}",
-        "package_version": "{package_version}",
-        "license_text": "{license_text}",
-        "used_by": [
-          {used_by}
-        ]
-      }}"""
-
-    kind_template = """
-          {{
-            "target": "{kind_path}",
-            "name": "{kind_name}",
-            "conditions": {kind_conditions}
-          }}"""
-
-    package_info_template = """
-          {{
-            "target": "{label}",
-            "bazel_package": "{bazel_package}",
-            "package_name": "{package_name}",
-            "package_url": "{package_url}",
-            "package_version": "{package_version}"
-          }}"""
-
-    # Build reverse map of license to user
-    used_by = {}
-    for dep in metadata_info.deps.to_list():
-        # Undo the concatenation applied when stored in the provider.
-        dep_licenses = dep.licenses.split(",")
-        for license in dep_licenses:
-            if license not in used_by:
-                used_by[license] = []
-            used_by[license].append(_strip_null_repo(dep.target_under_license))
-
-    all_licenses = []
-    for license in sorted(metadata_info.licenses.to_list(), key = lambda x: x.label):
-        kinds = []
-        for kind in sorted(license.license_kinds, key = lambda x: x.name):
-            kinds.append(kind_template.format(
-                kind_name = kind.name,
-                kind_path = kind.label,
-                kind_conditions = kind.conditions,
-            ))
-
-        if license.license_text:
-            # Special handling for synthetic LicenseInfo
-            text_path = (license.license_text.package + "/" + license.license_text.name if type(license.license_text) == "Label" else license.license_text.path)
-            all_licenses.append(license_template.format(
-                copyright_notice = license.copyright_notice,
-                kinds = ",".join(kinds),
-                license_text = text_path,
-                package_name = license.package_name,
-                package_url = license.package_url,
-                package_version = license.package_version,
-                label = _strip_null_repo(license.label),
-                bazel_package =  _bazel_package(license.label),
-                used_by = ",\n          ".join(sorted(['"%s"' % x for x in used_by[str(license.label)]])),
-            ))
-
-    all_deps = []
-    for dep in sorted(metadata_info.deps.to_list(), key = lambda x: x.target_under_license):
-        # Undo the concatenation applied when stored in the provider.
-        dep_licenses = dep.licenses.split(",")
-        all_deps.append(dep_template.format(
-            target_under_license = _strip_null_repo(dep.target_under_license),
-            licenses = ",\n          ".join(sorted(['"%s"' % _strip_null_repo(x) for x in dep_licenses])),
-        ))
-
-    all_packages = []
-    # We would use this if we had distinct depsets for every provider type.
-    #for package in sorted(metadata_info.package_info.to_list(), key = lambda x: x.label):
-    #    all_packages.append(package_info_template.format(
-    #        label = _strip_null_repo(package.label),
-    #        package_name = package.package_name,
-    #        package_url = package.package_url,
-    #        package_version = package.package_version,
-    #    ))
-
-    for mi in sorted(metadata_info.other_metadata.to_list(), key = lambda x: x.label):
-        # Maybe use a map of provider class to formatter.  A generic dict->json function
-        # in starlark would help
-
-        # This format is for using distinct providers.  I like the compile time safety.
-        if mi.type == "package_info":
-            all_packages.append(package_info_template.format(
-                label = _strip_null_repo(mi.label),
-                bazel_package =  _bazel_package(mi.label),
-                package_name = mi.package_name,
-                package_url = mi.package_url,
-                package_version = mi.package_version,
-            ))
-        # experimental: Support the ExperimentalMetadataInfo bag of data
-        if mi.type == "package_info_alt":
-            all_packages.append(package_info_template.format(
-                label = _strip_null_repo(mi.label),
-                bazel_package =  _bazel_package(mi.label),
-                # data is just a bag, so we need to use get() or ""
-                package_name = mi.data.get("package_name") or "",
-                package_url = mi.data.get("package_url") or "",
-                package_version = mi.data.get("package_version") or "",
-            ))
 
-    return [main_template.format(
-        top_level_target = _strip_null_repo(metadata_info.target_under_license),
-        dependencies = ",".join(all_deps),
-        licenses = ",".join(all_licenses),
-        packages = ",".join(all_packages),
-    )]
+gather_metadata_info = _gather_metadata_info
+gather_metadata_info_and_write = _gather_metadata_info_and_write
diff --git a/rules/license.bzl b/rules/license.bzl
index 032599d..a5c0379 100644
--- a/rules/license.bzl
+++ b/rules/license.bzl
@@ -69,12 +69,6 @@ _license = rule(
                   " by an applicatation.  It should be a value that" +
                   " increases over time, rather than a commit hash."
         ),
-        "namespace": attr.string(
-            doc = "A human readable name used to organize licenses into categories." +
-                  " This is used in google3 to differentiate third party licenses used" +
-                  " for compliance versus internal licenses used by SLAsan for internal" +
-                  " teams' SLAs.",
-        ),
     },
 )
 
@@ -88,7 +82,7 @@ def license(
         package_name = None,
         package_url = None,
         package_version = None,
-        namespace = "compliance",
+        namespace = None,
         tags = [],
         visibility = ["//visibility:public"]):
     """Wrapper for license rule.
@@ -107,7 +101,6 @@ def license(
                     an application.
       package_url: str The canonical URL this package was downloaded from.
       package_version: str The version corresponding the the URL.
-      namespace: str Undocumened. Internal.
       tags: list(str) tags applied to the rule
       visibility: list(label) visibility spec.
     """
@@ -123,6 +116,11 @@ def license(
         if len(srcs) != 1 or srcs[0] != license_text:
             fail("Specified license file doesn't exist: %s" % license_text)
 
+    # TODO(0.0.6 release): Remove this warning and fail hard instead.
+    if namespace:
+        # buildifier: disable=print
+        print("license(namespace=<str>) is deprecated.")
+
     _license(
         name = name,
         license_kinds = license_kinds,
@@ -131,7 +129,6 @@ def license(
         package_name = package_name,
         package_url = package_url,
         package_version = package_version,
-        namespace = namespace,
         applicable_licenses = [],
         visibility = visibility,
         tags = tags,
diff --git a/rules/license_impl.bzl b/rules/license_impl.bzl
index 03477c6..18b8570 100644
--- a/rules/license_impl.bzl
+++ b/rules/license_impl.bzl
@@ -36,12 +36,11 @@ def license_rule_impl(ctx):
     provider = LicenseInfo(
         license_kinds = tuple([k[LicenseKindInfo] for k in ctx.attr.license_kinds]),
         copyright_notice = ctx.attr.copyright_notice,
-        package_name = ctx.attr.package_name or ctx.build_file_path.rstrip("/BUILD"),
+        package_name = ctx.attr.package_name or ctx.label.package,
         package_url = ctx.attr.package_url,
         package_version = ctx.attr.package_version,
         license_text = ctx.file.license_text,
         label = ctx.label,
-        namespace = ctx.attr.namespace,
     )
     _debug(0, provider)
     return [provider]
diff --git a/rules/licenses_core.bzl b/rules/licenses_core.bzl
index 9bb37cb..fff3b82 100644
--- a/rules/licenses_core.bzl
+++ b/rules/licenses_core.bzl
@@ -14,33 +14,14 @@
 """Rules and macros for collecting LicenseInfo providers."""
 
 load("@rules_license//rules:filtered_rule_kinds.bzl", "aspect_filters")
+load("@rules_license//rules:providers.bzl", "LicenseInfo")
 load("@rules_license//rules:user_filtered_rule_kinds.bzl", "user_aspect_filters")
 load(
-    "@rules_license//rules:providers.bzl",
-    "LicenseInfo",
-)
-load(
-    "@rules_license//rules/private:gathering_providers.bzl",
+    "@rules_license//rules_gathering:gathering_providers.bzl",
     "LicensedTargetInfo",
     "TransitiveLicensesInfo",
 )
-
-
-TraceInfo = provider(
-    doc = """Provides a target (as a string) to assist in debugging dependency issues.""",
-    fields = {
-        "trace": "String: a target to trace dependency edges to.",
-    },
-)
-
-def _trace_impl(ctx):
-    return TraceInfo(trace = ctx.build_setting_value)
-
-trace = rule(
-    doc = """Used to allow the specification of a target to trace while collecting license dependencies.""",
-    implementation = _trace_impl,
-    build_setting = config.string(flag = True),
-)
+load("@rules_license//rules_gathering:trace.bzl", "TraceInfo")
 
 def should_traverse(ctx, attr):
     """Checks if the dependent attribute should be traversed.
@@ -106,6 +87,7 @@ def _get_transitive_metadata(ctx, trans_licenses, trans_other_metadata, trans_pa
                 if hasattr(info, "other_metadata"):
                     if info.other_metadata:
                         trans_other_metadata.append(info.other_metadata)
+
                 # But if we want more precise type safety, we would have a
                 # trans_* for each type of metadata. That is not user
                 # extensibile.
@@ -113,7 +95,7 @@ def _get_transitive_metadata(ctx, trans_licenses, trans_other_metadata, trans_pa
                     if info.package_info:
                         trans_package_info.append(info.package_info)
 
-def gather_metadata_info_common(target, ctx, provider_factory, namespaces, metadata_providers, filter_func):
+def gather_metadata_info_common(target, ctx, provider_factory, metadata_providers, filter_func):
     """Collect license and other metadata info from myself and my deps.
 
     Any single target might directly depend on a license, or depend on
@@ -122,17 +104,16 @@ def gather_metadata_info_common(target, ctx, provider_factory, namespaces, metad
     in new direct license deps found and forward up the transitive information
     collected so far.
 
-    This is a common abstraction for crawling the dependency graph. It is parameterized
-    to allow specifying the provider that is populated with results. It is
-    configurable to select only licenses matching a certain namespace. It is also
-    configurable to specify which dependency edges should not be traced for the
-    purpose of tracing the graph.
+    This is a common abstraction for crawling the dependency graph. It is
+    parameterized to allow specifying the provider that is populated with
+    results. It is configurable to select only a subset of providers. It
+    is also configurable to specify which dependency edges should not
+    be traced for the purpose of tracing the graph.
 
     Args:
       target: The target of the aspect.
       ctx: The aspect evaluation context.
       provider_factory: abstracts the provider returned by this aspect
-      namespaces: a list of namespaces licenses must match to be included
       metadata_providers: a list of other providers of interest
       filter_func: a function that returns true iff the dep edge should be ignored
 
@@ -151,22 +132,26 @@ def gather_metadata_info_common(target, ctx, provider_factory, namespaces, metad
         pass
     else:
         if hasattr(ctx.rule.attr, "applicable_licenses"):
-            for dep in ctx.rule.attr.applicable_licenses:
-                if LicenseInfo in dep:
-                    lic = dep[LicenseInfo]
-
-                    # This check shouldn't be necessary since any license created
-                    # by the official code will have this set. However, one of the
-                    # tests has its own implementation of license that had to be fixed
-                    # so this is just a conservative safety check.
-                    if hasattr(lic, "namespace"):
-                        if lic.namespace in namespaces:
-                            licenses.append(lic)
-                    else:
-                        fail("should have a namespace")
-                for m_p in metadata_providers:
-                    if m_p in dep:
-                        other_metadata.append(dep[m_p])
+            package_metadata = ctx.rule.attr.applicable_licenses
+        elif hasattr(ctx.rule.attr, "package_metadata"):
+            package_metadata = ctx.rule.attr.package_metadata
+        else:
+            package_metadata = []
+
+        for dep in package_metadata:
+            if LicenseInfo in dep:
+                lic = dep[LicenseInfo]
+                licenses.append(lic)
+
+            for m_p in metadata_providers:
+                if m_p in dep:
+                    other_metadata.append(dep[m_p])
+
+    # A hack until https://github.com/bazelbuild/rules_license/issues/89 is
+    # fully resolved. If exec is in the bin_dir path, then the current
+    # configuration is probably cfg = exec.
+    if "-exec-" in ctx.bin_dir.path:
+        return [provider_factory(deps = depset(), licenses = depset(), traces = [])]
 
     # Now gather transitive collection of providers from the targets
     # this target depends upon.
@@ -175,6 +160,7 @@ def gather_metadata_info_common(target, ctx, provider_factory, namespaces, metad
     trans_package_info = []
     trans_deps = []
     traces = []
+
     _get_transitive_metadata(ctx, trans_licenses, trans_other_metadata, trans_package_info, trans_deps, traces, provider_factory, filter_func)
 
     if not licenses and not trans_licenses:
diff --git a/rules/package_info.bzl b/rules/package_info.bzl
index c79545f..fcbaa8e 100644
--- a/rules/package_info.bzl
+++ b/rules/package_info.bzl
@@ -34,7 +34,9 @@ def _package_info_impl(ctx):
         package_name = ctx.attr.package_name or ctx.build_file_path.rstrip("/BUILD"),
         package_url = ctx.attr.package_url,
         package_version = ctx.attr.package_version,
+        purl = ctx.attr.purl,
     )
+
     # Experimental alternate design, using a generic 'data' back to hold things
     generic_provider = ExperimentalMetadataInfo(
         type = "package_info_alt",
@@ -42,8 +44,9 @@ def _package_info_impl(ctx):
         data = {
             "package_name": ctx.attr.package_name or ctx.build_file_path.rstrip("/BUILD"),
             "package_url": ctx.attr.package_url,
-            "package_version": ctx.attr.package_version
-        }
+            "package_version": ctx.attr.package_version,
+            "purl": ctx.attr.purl,
+        },
     )
     return [provider, generic_provider]
 
@@ -53,18 +56,23 @@ _package_info = rule(
         "package_name": attr.string(
             doc = "A human readable name identifying this package." +
                   " This may be used to produce an index of OSS packages used by" +
-                  " an applicatation.",
+                  " an application.",
         ),
         "package_url": attr.string(
             doc = "The URL this instance of the package was download from." +
                   " This may be used to produce an index of OSS packages used by" +
-                  " an applicatation.",
+                  " an application.",
         ),
         "package_version": attr.string(
             doc = "A human readable version string identifying this package." +
                   " This may be used to produce an index of OSS packages used" +
-                  " by an applicatation.  It should be a value that" +
-                  " increases over time, rather than a commit hash."
+                  " by an application.  It should be a value that" +
+                  " increases over time, rather than a commit hash.",
+        ),
+        "purl": attr.string(
+            doc = "A pURL conforming to the spec outlined in" +
+                  " https://github.com/package-url/purl-spec. This may be used when" +
+                  " generating an SBOM.",
         ),
     },
 )
@@ -75,20 +83,25 @@ def package_info(
         package_name = None,
         package_url = None,
         package_version = None,
+        purl = None,
         **kwargs):
     """Wrapper for package_info rule.
 
     @wraps(_package_info)
 
+    The purl attribute should be a valid pURL, as defined in the
+    [pURL spec](https://github.com/package-url/purl-spec).
+
     Args:
       name: str target name.
       package_name: str A human readable name identifying this package. This
                     may be used to produce an index of OSS packages used by
                     an application.
       package_url: str The canoncial URL this package distribution was retrieved from.
-                       Note that, because of local mirroring, that might not be the 
+                       Note that, because of local mirroring, that might not be the
                        physical URL it was retrieved from.
       package_version: str A human readable name identifying version of this package.
+      purl: str The canonical pURL by which this package is known.
       kwargs: other args. Most are ignored.
     """
     visibility = kwargs.get("visibility") or ["//visibility:public"]
@@ -97,6 +110,7 @@ def package_info(
         package_name = package_name,
         package_url = package_url,
         package_version = package_version,
+        purl = purl,
         applicable_licenses = [],
         visibility = visibility,
         tags = [],
diff --git a/rules/private/gathering_providers.bzl b/rules/private/gathering_providers.bzl
index 1c3740f..be31dce 100644
--- a/rules/private/gathering_providers.bzl
+++ b/rules/private/gathering_providers.bzl
@@ -1,4 +1,4 @@
-# Copyright 2022 Google LLC
+# Copyright 2023 Google LLC
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -11,44 +11,14 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-"""Providers for transitively gathering all license and package_info targets.
+"""Temporary forwarder.
 
-Warning: This is private to the aspect that walks the tree. The API is subject
-to change at any release.
+TODO(2023-07-01): Delete this file.
 """
 
-LicensedTargetInfo = provider(
-    doc = """Lists the licenses directly used by a single target.""",
-    fields = {
-        "target_under_license": "Label: The target label",
-        "licenses": "list(label of a license rule)",
-    },
+load(
+    "@rules_license//rules_gathering:gathering_providers.bzl",
+    _private_TransitiveLicensesInfo = "TransitiveLicensesInfo",
 )
 
-def licenses_info():
-    return provider(
-        doc = """The transitive set of licenses used by a target.""",
-        fields = {
-            "target_under_license": "Label: The top level target label.",
-            "deps": "depset(LicensedTargetInfo): The transitive list of dependencies that have licenses.",
-            "licenses": "depset(LicenseInfo)",
-            "traces": "list(string) - diagnostic for tracing a dependency relationship to a target.",
-        },
-    )
-
-# This provider is used by the aspect that is used by manifest() rules.
-TransitiveLicensesInfo = licenses_info()
-
-TransitiveMetadataInfo = provider(
-    doc = """The transitive set of licenses used by a target.""",
-    fields = {
-        "top_level_target": "Label: The top level target label we are examining.",
-        "other_metadata": "depset(ExperimentalMetatdataInfo)",
-        "licenses": "depset(LicenseInfo)",
-        "package_info": "depset(PackageInfo)",
-
-        "target_under_license": "Label: A target which will be associated with some licenses.",
-        "deps": "depset(LicensedTargetInfo): The transitive list of dependencies that have licenses.",
-        "traces": "list(string) - diagnostic for tracing a dependency relationship to a target.",
-    },
-)
+TransitiveLicensesInfo = _private_TransitiveLicensesInfo
diff --git a/rules/providers.bzl b/rules/providers.bzl
index 33a7fb5..b6a352f 100644
--- a/rules/providers.bzl
+++ b/rules/providers.bzl
@@ -18,6 +18,11 @@ license and package_info declarations. Providers needed to gather
 them are declared in other places.
 """
 
+load(
+    "@rules_license//rules_gathering:gathering_providers.bzl",
+    _private_TransitiveLicensesInfo = "TransitiveLicensesInfo",
+)
+
 LicenseKindInfo = provider(
     doc = """Provides information about a license_kind instance.""",
     fields = {
@@ -35,7 +40,6 @@ LicenseInfo = provider(
         "label": "Label: label of the license rule",
         "license_kinds": "list(LicenseKindInfo): License kinds ",
         "license_text": "string: The license file path",
-        "namespace": "string: namespace of the license rule",
         # TODO(aiuto): move to PackageInfo
         "package_name": "string: Human readable package name",
         "package_url": "URL from which this package was downloaded.",
@@ -51,6 +55,7 @@ PackageInfo = provider(
         "package_name": "string: Human readable package name",
         "package_url": "string: URL from which this package was downloaded.",
         "package_version": "string: Human readable version string",
+        "purl": "string: package url matching the purl spec (https://github.com/package-url/purl-spec)",
     },
 )
 
@@ -63,5 +68,8 @@ ExperimentalMetadataInfo = provider(
         "type": "string: How to interpret data",
         "label": "Label: label of the metadata rule",
         "data": "String->any: Map of names to values",
-    }
+    },
 )
+
+# Deprecated: Use write_licenses_info instead.
+TransitiveLicensesInfo = _private_TransitiveLicensesInfo
diff --git a/rules/sbom.bzl b/rules/sbom.bzl
deleted file mode 100644
index 73c1861..0000000
--- a/rules/sbom.bzl
+++ /dev/null
@@ -1,136 +0,0 @@
-# Copyright 2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-# https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-"""SBOM generation"""
-
-load(
-    "@rules_license//rules:gather_metadata.bzl",
-    "gather_metadata_info",
-    "gather_metadata_info_and_write",
-    "write_metadata_info",
-)
-load(
-    "@rules_license//rules/private:gathering_providers.bzl",
-    "TransitiveLicensesInfo",
-)
-
-# This rule is proof of concept, and may not represent the final
-# form of a rule for compliance validation.
-def _generate_sbom_impl(ctx):
-    # Gather all licenses and write information to one place
-
-    licenses_file = ctx.actions.declare_file("_%s_licenses_info.json" % ctx.label.name)
-    write_metadata_info(ctx, ctx.attr.deps, licenses_file)
-
-    # Now turn the big blob of data into something consumable.
-    inputs = [licenses_file]
-    outputs = [ctx.outputs.out]
-    args = ctx.actions.args()
-    args.add("--licenses_info", licenses_file.path)
-    args.add("--out", ctx.outputs.out.path)
-    ctx.actions.run(
-        mnemonic = "CreateSBOM",
-        progress_message = "Creating SBOM for %s" % ctx.label,
-        inputs = inputs,
-        outputs = outputs,
-        executable = ctx.executable._sbom_generator,
-        arguments = [args],
-    )
-    outputs.append(licenses_file)  # also make the json file available.
-    return [DefaultInfo(files = depset(outputs))]
-
-_generate_sbom = rule(
-    implementation = _generate_sbom_impl,
-    attrs = {
-        "deps": attr.label_list(
-            aspects = [gather_metadata_info],
-        ),
-        "out": attr.output(mandatory = True),
-        "_sbom_generator": attr.label(
-            default = Label("@rules_license//tools:write_sbom"),
-            executable = True,
-            allow_files = True,
-            cfg = "exec",
-        ),
-    },
-)
-
-def generate_sbom(**kwargs):
-    _generate_sbom(**kwargs)
-
-def _manifest_impl(ctx):
-    # Gather all licenses and make it available as deps for downstream rules
-    # Additionally write the list of license filenames to a file that can
-    # also be used as an input to downstream rules.
-    licenses_file = ctx.actions.declare_file(ctx.attr.out.name)
-    mappings = get_licenses_mapping(ctx.attr.deps, ctx.attr.warn_on_legacy_licenses)
-    ctx.actions.write(
-        output = licenses_file,
-        content = "\n".join([",".join([f.path, p]) for (f, p) in mappings.items()]),
-    )
-    return [DefaultInfo(files = depset(mappings.keys()))]
-
-_manifest = rule(
-    implementation = _manifest_impl,
-    doc = """Internal tmplementation method for manifest().""",
-    attrs = {
-        "deps": attr.label_list(
-            doc = """List of targets to collect license files for.""",
-            aspects = [gather_metadata_info],
-        ),
-        "out": attr.output(
-            doc = """Output file.""",
-            mandatory = True,
-        ),
-        "warn_on_legacy_licenses": attr.bool(default = False),
-    },
-)
-
-def manifest(name, deps, out = None, **kwargs):
-    if not out:
-        out = name + ".manifest"
-
-    _manifest(name = name, deps = deps, out = out, **kwargs)
-
-def get_licenses_mapping(deps, warn = False):
-    """Creates list of entries representing all licenses for the deps.
-
-    Args:
-
-      deps: a list of deps which should have TransitiveLicensesInfo providers.
-            This requires that you have run the gather_licenses_info
-            aspect over them
-
-      warn: boolean, if true, display output about legacy targets that need
-            update
-
-    Returns:
-      {File:package_name}
-    """
-    tls = []
-    for dep in deps:
-        lds = dep[TransitiveLicensesInfo].licenses
-        tls.append(lds)
-
-    ds = depset(transitive = tls)
-
-    # Ignore any legacy licenses that may be in the report
-    mappings = {}
-    for lic in ds.to_list():
-        if type(lic.license_text) == "File":
-            mappings[lic.license_text] = lic.package_name
-        elif warn:
-            # buildifier: disable=print
-            print("Legacy license %s not included, rule needs updating" % lic.license_text)
-
-    return mappings
diff --git a/rules/sbom.bzl b/rules/sbom.bzl
new file mode 120000
index 0000000..8485c5f
--- /dev/null
+++ b/rules/sbom.bzl
@@ -0,0 +1 @@
+../rules_gathering/generate_sbom.bzl
\ No newline at end of file
diff --git a/rules_gathering/BUILD b/rules_gathering/BUILD
new file mode 100644
index 0000000..6798eb6
--- /dev/null
+++ b/rules_gathering/BUILD
@@ -0,0 +1,33 @@
+# Copyright 2023 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Rules for making license declarations."""
+
+package(
+    default_applicable_licenses = ["//:license"],
+    default_visibility = ["//visibility:public"],
+)
+
+filegroup(
+    name = "standard_package",
+    srcs = glob(["**"]),
+)
+
+# Do not create a bzl_library(). That would create a dependency loop back
+# to bazel-skylib. We export the .bzl files to the documentation maker.
+exports_files(
+    glob([
+        "*.bzl",
+    ]),
+    visibility = ["//doc_build:__pkg__"],
+)
diff --git a/rules_gathering/README.md b/rules_gathering/README.md
new file mode 100644
index 0000000..333182d
--- /dev/null
+++ b/rules_gathering/README.md
@@ -0,0 +1,11 @@
+# Rules and aspects to gather gather package metadata
+
+This folder contains tools used to walk dependency trees and gather
+`LicenseInfo` or similar providers specified by `default_package_metadata`
+and `applicable_licenses`.
+
+
+
+# Known issues:
+
+- [exports_files() is not included](https://github.com/bazelbuild/rules_license/issues/107)
diff --git a/rules_gathering/gather_metadata.bzl b/rules_gathering/gather_metadata.bzl
new file mode 100644
index 0000000..aae5b69
--- /dev/null
+++ b/rules_gathering/gather_metadata.bzl
@@ -0,0 +1,308 @@
+# Copyright 2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Rules and macros for collecting LicenseInfo providers."""
+
+load(
+    "@rules_license//rules:licenses_core.bzl",
+    "gather_metadata_info_common",
+    "should_traverse",
+)
+load(
+    "@rules_license//rules:providers.bzl",
+    "ExperimentalMetadataInfo",
+    "PackageInfo",
+)
+load(
+    "@rules_license//rules_gathering:gathering_providers.bzl",
+    "TransitiveMetadataInfo",
+)
+load("@rules_license//rules_gathering:trace.bzl", "TraceInfo")
+
+def _strip_null_repo(label):
+    """Removes the null repo name (e.g. @//) from a string.
+
+    The is to make str(label) compatible between bazel 5.x and 6.x
+    """
+    s = str(label)
+    if s.startswith('@//'):
+        return s[1:]
+    elif s.startswith('@@//'):
+        return s[2:]
+    return s
+
+def _bazel_package(label):
+    clean_label = _strip_null_repo(label)
+    return clean_label[0:-(len(label.name) + 1)]
+
+def _gather_metadata_info_impl(target, ctx):
+    return gather_metadata_info_common(
+        target,
+        ctx,
+        TransitiveMetadataInfo,
+        [ExperimentalMetadataInfo, PackageInfo],
+        should_traverse)
+
+gather_metadata_info = aspect(
+    doc = """Collects LicenseInfo providers into a single TransitiveMetadataInfo provider.""",
+    implementation = _gather_metadata_info_impl,
+    attr_aspects = ["*"],
+    attrs = {
+        "_trace": attr.label(default = "@rules_license//rules:trace_target"),
+    },
+    provides = [TransitiveMetadataInfo],
+    apply_to_generating_rules = True,
+)
+
+def _write_metadata_info_impl(target, ctx):
+    """Write transitive license info into a JSON file
+
+    Args:
+      target: The target of the aspect.
+      ctx: The aspect evaluation context.
+
+    Returns:
+      OutputGroupInfo
+    """
+
+    if not TransitiveMetadataInfo in target:
+        return [OutputGroupInfo(licenses = depset())]
+    info = target[TransitiveMetadataInfo]
+    outs = []
+
+    # If the result doesn't contain licenses, we simply return the provider
+    if not hasattr(info, "target_under_license"):
+        return [OutputGroupInfo(licenses = depset())]
+
+    # Write the output file for the target
+    name = "%s_metadata_info.json" % ctx.label.name
+    content = "[\n%s\n]\n" % ",\n".join(metadata_info_to_json(info))
+    out = ctx.actions.declare_file(name)
+    ctx.actions.write(
+        output = out,
+        content = content,
+    )
+    outs.append(out)
+
+    if ctx.attr._trace[TraceInfo].trace:
+        trace = ctx.actions.declare_file("%s_trace_info.json" % ctx.label.name)
+        ctx.actions.write(output = trace, content = "\n".join(info.traces))
+        outs.append(trace)
+
+    return [OutputGroupInfo(licenses = depset(outs))]
+
+gather_metadata_info_and_write = aspect(
+    doc = """Collects TransitiveMetadataInfo providers and writes JSON representation to a file.
+
+    Usage:
+      bazel build //some:target \
+          --aspects=@rules_license//rules_gathering:gather_metadata.bzl%gather_metadata_info_and_write
+          --output_groups=licenses
+    """,
+    implementation = _write_metadata_info_impl,
+    attr_aspects = ["*"],
+    attrs = {
+        "_trace": attr.label(default = "@rules_license//rules:trace_target"),
+    },
+    provides = [OutputGroupInfo],
+    requires = [gather_metadata_info],
+    apply_to_generating_rules = True,
+)
+
+def write_metadata_info(ctx, deps, json_out):
+    """Writes TransitiveMetadataInfo providers for a set of targets as JSON.
+
+    TODO(aiuto): Document JSON schema. But it is under development, so the current
+    best place to look is at tests/hello_licenses.golden.
+
+    Usage:
+      write_metadata_info must be called from a rule implementation, where the
+      rule has run the gather_metadata_info aspect on its deps to
+      collect the transitive closure of LicenseInfo providers into a
+      LicenseInfo provider.
+
+      foo = rule(
+        implementation = _foo_impl,
+        attrs = {
+           "deps": attr.label_list(aspects = [gather_metadata_info])
+        }
+      )
+
+      def _foo_impl(ctx):
+        ...
+        out = ctx.actions.declare_file("%s_licenses.json" % ctx.label.name)
+        write_metadata_info(ctx, ctx.attr.deps, metadata_file)
+
+    Args:
+      ctx: context of the caller
+      deps: a list of deps which should have TransitiveMetadataInfo providers.
+            This requires that you have run the gather_metadata_info
+            aspect over them
+      json_out: output handle to write the JSON info
+    """
+    licenses = []
+    for dep in deps:
+        if TransitiveMetadataInfo in dep:
+            licenses.extend(metadata_info_to_json(dep[TransitiveMetadataInfo]))
+    ctx.actions.write(
+        output = json_out,
+        content = "[\n%s\n]\n" % ",\n".join(licenses),
+    )
+
+def metadata_info_to_json(metadata_info):
+    """Render a single LicenseInfo provider to JSON
+
+    Args:
+      metadata_info: A LicenseInfo.
+
+    Returns:
+      [(str)] list of LicenseInfo values rendered as JSON.
+    """
+
+    main_template = """  {{
+    "top_level_target": "{top_level_target}",
+    "dependencies": [{dependencies}
+    ],
+    "licenses": [{licenses}
+    ],
+    "packages": [{packages}
+    ]\n  }}"""
+
+    dep_template = """
+      {{
+        "target_under_license": "{target_under_license}",
+        "licenses": [
+          {licenses}
+        ]
+      }}"""
+
+    license_template = """
+      {{
+        "label": "{label}",
+        "bazel_package": "{bazel_package}",
+        "license_kinds": [{kinds}
+        ],
+        "copyright_notice": "{copyright_notice}",
+        "package_name": "{package_name}",
+        "package_url": "{package_url}",
+        "package_version": "{package_version}",
+        "license_text": "{license_text}",
+        "used_by": [
+          {used_by}
+        ]
+      }}"""
+
+    kind_template = """
+          {{
+            "target": "{kind_path}",
+            "name": "{kind_name}",
+            "conditions": {kind_conditions}
+          }}"""
+
+    package_info_template = """
+          {{
+            "target": "{label}",
+            "bazel_package": "{bazel_package}",
+            "package_name": "{package_name}",
+            "package_url": "{package_url}",
+            "package_version": "{package_version}",
+            "purl": "{purl}"
+          }}"""
+
+    # Build reverse map of license to user
+    used_by = {}
+    for dep in metadata_info.deps.to_list():
+        # Undo the concatenation applied when stored in the provider.
+        dep_licenses = dep.licenses.split(",")
+        for license in dep_licenses:
+            if license not in used_by:
+                used_by[license] = []
+            used_by[license].append(_strip_null_repo(dep.target_under_license))
+
+    all_licenses = []
+    for license in sorted(metadata_info.licenses.to_list(), key = lambda x: x.label):
+        kinds = []
+        for kind in sorted(license.license_kinds, key = lambda x: x.name):
+            kinds.append(kind_template.format(
+                kind_name = kind.name,
+                kind_path = kind.label,
+                kind_conditions = kind.conditions,
+            ))
+
+        if license.license_text:
+            # Special handling for synthetic LicenseInfo
+            text_path = (license.license_text.package + "/" + license.license_text.name if type(license.license_text) == "Label" else license.license_text.path)
+            all_licenses.append(license_template.format(
+                copyright_notice = license.copyright_notice,
+                kinds = ",".join(kinds),
+                license_text = text_path,
+                package_name = license.package_name,
+                package_url = license.package_url,
+                package_version = license.package_version,
+                label = _strip_null_repo(license.label),
+                bazel_package =  _bazel_package(license.label),
+                used_by = ",\n          ".join(sorted(['"%s"' % x for x in used_by[str(license.label)]])),
+            ))
+
+    all_deps = []
+    for dep in sorted(metadata_info.deps.to_list(), key = lambda x: x.target_under_license):
+        # Undo the concatenation applied when stored in the provider.
+        dep_licenses = dep.licenses.split(",")
+        all_deps.append(dep_template.format(
+            target_under_license = _strip_null_repo(dep.target_under_license),
+            licenses = ",\n          ".join(sorted(['"%s"' % _strip_null_repo(x) for x in dep_licenses])),
+        ))
+
+    all_packages = []
+    # We would use this if we had distinct depsets for every provider type.
+    #for package in sorted(metadata_info.package_info.to_list(), key = lambda x: x.label):
+    #    all_packages.append(package_info_template.format(
+    #        label = _strip_null_repo(package.label),
+    #        package_name = package.package_name,
+    #        package_url = package.package_url,
+    #        package_version = package.package_version,
+    #    ))
+
+    for mi in sorted(metadata_info.other_metadata.to_list(), key = lambda x: x.label):
+        # Maybe use a map of provider class to formatter.  A generic dict->json function
+        # in starlark would help
+
+        # This format is for using distinct providers.  I like the compile time safety.
+        if mi.type == "package_info":
+            all_packages.append(package_info_template.format(
+                label = _strip_null_repo(mi.label),
+                bazel_package =  _bazel_package(mi.label),
+                package_name = mi.package_name,
+                package_url = mi.package_url,
+                package_version = mi.package_version,
+                purl = mi.purl,
+            ))
+        # experimental: Support the ExperimentalMetadataInfo bag of data
+        # WARNING: Do not depend on this. It will change without notice.
+        if mi.type == "package_info_alt":
+            all_packages.append(package_info_template.format(
+                label = _strip_null_repo(mi.label),
+                bazel_package =  _bazel_package(mi.label),
+                # data is just a bag, so we need to use get() or ""
+                package_name = mi.data.get("package_name") or "",
+                package_url = mi.data.get("package_url") or "",
+                package_version = mi.data.get("package_version") or "",
+                purl = mi.data.get("purl") or "",
+            ))
+
+    return [main_template.format(
+        top_level_target = _strip_null_repo(metadata_info.target_under_license),
+        dependencies = ",".join(all_deps),
+        licenses = ",".join(all_licenses),
+        packages = ",".join(all_packages),
+    )]
diff --git a/rules_gathering/gathering_providers.bzl b/rules_gathering/gathering_providers.bzl
new file mode 100644
index 0000000..1c3740f
--- /dev/null
+++ b/rules_gathering/gathering_providers.bzl
@@ -0,0 +1,54 @@
+# Copyright 2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Providers for transitively gathering all license and package_info targets.
+
+Warning: This is private to the aspect that walks the tree. The API is subject
+to change at any release.
+"""
+
+LicensedTargetInfo = provider(
+    doc = """Lists the licenses directly used by a single target.""",
+    fields = {
+        "target_under_license": "Label: The target label",
+        "licenses": "list(label of a license rule)",
+    },
+)
+
+def licenses_info():
+    return provider(
+        doc = """The transitive set of licenses used by a target.""",
+        fields = {
+            "target_under_license": "Label: The top level target label.",
+            "deps": "depset(LicensedTargetInfo): The transitive list of dependencies that have licenses.",
+            "licenses": "depset(LicenseInfo)",
+            "traces": "list(string) - diagnostic for tracing a dependency relationship to a target.",
+        },
+    )
+
+# This provider is used by the aspect that is used by manifest() rules.
+TransitiveLicensesInfo = licenses_info()
+
+TransitiveMetadataInfo = provider(
+    doc = """The transitive set of licenses used by a target.""",
+    fields = {
+        "top_level_target": "Label: The top level target label we are examining.",
+        "other_metadata": "depset(ExperimentalMetatdataInfo)",
+        "licenses": "depset(LicenseInfo)",
+        "package_info": "depset(PackageInfo)",
+
+        "target_under_license": "Label: A target which will be associated with some licenses.",
+        "deps": "depset(LicensedTargetInfo): The transitive list of dependencies that have licenses.",
+        "traces": "list(string) - diagnostic for tracing a dependency relationship to a target.",
+    },
+)
diff --git a/rules_gathering/generate_sbom.bzl b/rules_gathering/generate_sbom.bzl
new file mode 100644
index 0000000..96947b6
--- /dev/null
+++ b/rules_gathering/generate_sbom.bzl
@@ -0,0 +1,138 @@
+# Copyright 2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""SBOM generation"""
+
+load(
+    "@rules_license//rules_gathering:gather_metadata.bzl",
+    "gather_metadata_info",
+    "gather_metadata_info_and_write",
+    "write_metadata_info",
+)
+load(
+    "@rules_license//rules_gathering:gathering_providers.bzl",
+    "TransitiveLicensesInfo",
+)
+
+# This rule is proof of concept, and may not represent the final
+# form of a rule for compliance validation.
+def _generate_sbom_impl(ctx):
+    # Gather all licenses and write information to one place
+
+    licenses_file = ctx.actions.declare_file("_%s_licenses_info.json" % ctx.label.name)
+    write_metadata_info(ctx, ctx.attr.deps, licenses_file)
+
+    # Now turn the big blob of data into something consumable.
+    inputs = [licenses_file]
+    outputs = [ctx.outputs.out]
+    args = ctx.actions.args()
+    args.add("--licenses_info", licenses_file.path)
+    args.add("--out", ctx.outputs.out.path)
+    ctx.actions.run(
+        mnemonic = "CreateSBOM",
+        progress_message = "Creating SBOM for %s" % ctx.label,
+        inputs = inputs,
+        outputs = outputs,
+        executable = ctx.executable._sbom_generator,
+        arguments = [args],
+    )
+    return [
+        DefaultInfo(files = depset(outputs)),
+        OutputGroupInfo(licenses_file = depset([licenses_file])),
+    ]
+
+_generate_sbom = rule(
+    implementation = _generate_sbom_impl,
+    attrs = {
+        "deps": attr.label_list(
+            aspects = [gather_metadata_info],
+        ),
+        "out": attr.output(mandatory = True),
+        "_sbom_generator": attr.label(
+            default = Label("@rules_license//tools:write_sbom"),
+            executable = True,
+            allow_files = True,
+            cfg = "exec",
+        ),
+    },
+)
+
+def generate_sbom(**kwargs):
+    _generate_sbom(**kwargs)
+
+def _manifest_impl(ctx):
+    # Gather all licenses and make it available as deps for downstream rules
+    # Additionally write the list of license filenames to a file that can
+    # also be used as an input to downstream rules.
+    licenses_file = ctx.actions.declare_file(ctx.attr.out.name)
+    mappings = get_licenses_mapping(ctx.attr.deps, ctx.attr.warn_on_legacy_licenses)
+    ctx.actions.write(
+        output = licenses_file,
+        content = "\n".join([",".join([f.path, p]) for (f, p) in mappings.items()]),
+    )
+    return [DefaultInfo(files = depset(mappings.keys()))]
+
+_manifest = rule(
+    implementation = _manifest_impl,
+    doc = """Internal tmplementation method for manifest().""",
+    attrs = {
+        "deps": attr.label_list(
+            doc = """List of targets to collect license files for.""",
+            aspects = [gather_metadata_info],
+        ),
+        "out": attr.output(
+            doc = """Output file.""",
+            mandatory = True,
+        ),
+        "warn_on_legacy_licenses": attr.bool(default = False),
+    },
+)
+
+def manifest(name, deps, out = None, **kwargs):
+    if not out:
+        out = name + ".manifest"
+
+    _manifest(name = name, deps = deps, out = out, **kwargs)
+
+def get_licenses_mapping(deps, warn = False):
+    """Creates list of entries representing all licenses for the deps.
+
+    Args:
+
+      deps: a list of deps which should have TransitiveLicensesInfo providers.
+            This requires that you have run the gather_licenses_info
+            aspect over them
+
+      warn: boolean, if true, display output about legacy targets that need
+            update
+
+    Returns:
+      {File:package_name}
+    """
+    tls = []
+    for dep in deps:
+        lds = dep[TransitiveLicensesInfo].licenses
+        tls.append(lds)
+
+    ds = depset(transitive = tls)
+
+    # Ignore any legacy licenses that may be in the report
+    mappings = {}
+    for lic in ds.to_list():
+        if type(lic.license_text) == "File":
+            mappings[lic.license_text] = lic.package_name
+        elif warn:
+            # buildifier: disable=print
+            print("Legacy license %s not included, rule needs updating" % lic.license_text)
+
+    return mappings
diff --git a/rules_gathering/trace.bzl b/rules_gathering/trace.bzl
new file mode 100644
index 0000000..f4a7b25
--- /dev/null
+++ b/rules_gathering/trace.bzl
@@ -0,0 +1,30 @@
+# Copyright 2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Rules and macros for collecting package metdata providers."""
+
+TraceInfo = provider(
+    doc = """Provides a target (as a string) to assist in debugging dependency issues.""",
+    fields = {
+        "trace": "String: a target to trace dependency edges to.",
+    },
+)
+
+def _trace_impl(ctx):
+    return TraceInfo(trace = ctx.build_setting_value)
+
+trace = rule(
+    doc = """Used to allow the specification of a target to trace while collecting license dependencies.""",
+    implementation = _trace_impl,
+    build_setting = config.string(flag = True),
+)
diff --git a/sample_reports/BUILD b/sample_reports/BUILD
new file mode 100644
index 0000000..62aafba
--- /dev/null
+++ b/sample_reports/BUILD
@@ -0,0 +1,37 @@
+# BUILD file defining reference implementations for reporting tools
+#
+# Copyright 2023 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Rules for making license declarations."""
+
+package(
+    default_applicable_licenses = ["//:license"],
+    default_visibility = ["//visibility:public"],
+)
+
+licenses(["notice"])
+
+filegroup(
+    name = "standard_package",
+    srcs = glob(["**"]),
+)
+
+# Do not create a bzl_library(). That would create a dependency loop back
+# to bazel-skylib. We export the .bzl files to the documentation maker.
+exports_files(
+    glob([
+        "*.bzl",
+    ]),
+    visibility = ["//doc_build:__pkg__"],
+)
diff --git a/sample_reports/licenses_used.bzl b/sample_reports/licenses_used.bzl
new file mode 100644
index 0000000..ccb1eb0
--- /dev/null
+++ b/sample_reports/licenses_used.bzl
@@ -0,0 +1,65 @@
+# Copyright 2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""License compliance checking."""
+
+load(
+    "@rules_license//rules:gather_licenses_info.bzl",
+    "gather_licenses_info",
+    "write_licenses_info",
+)
+
+def _licenses_used_impl(ctx):
+    # Gather all licenses and make it available as JSON
+    write_licenses_info(ctx, ctx.attr.deps, ctx.outputs.out)
+    return [DefaultInfo(files = depset([ctx.outputs.out]))]
+
+_licenses_used = rule(
+    implementation = _licenses_used_impl,
+    doc = """Internal tmplementation method for licenses_used().""",
+    attrs = {
+        "deps": attr.label_list(
+            doc = """List of targets to collect LicenseInfo for.""",
+            aspects = [gather_licenses_info],
+        ),
+        "out": attr.output(
+            doc = """Output file.""",
+            mandatory = True,
+        ),
+    },
+)
+
+def licenses_used(name, deps, out = None, **kwargs):
+    """Collects LicensedInfo providers for a set of targets and writes as JSON.
+
+    The output is a single JSON array, with an entry for each license used.
+    See gather_licenses_info.bzl:write_licenses_info() for a description of the schema.
+
+    Args:
+      name: The target.
+      deps: A list of targets to get LicenseInfo for. The output is the union of
+            the result, not a list of information for each dependency.
+      out: The output file name. Default: <name>.json.
+      **kwargs: Other args
+
+    Usage:
+
+      licenses_used(
+          name = "license_info",
+          deps = [":my_app"],
+          out = "license_info.json",
+      )
+    """
+    if not out:
+        out = name + ".json"
+    _licenses_used(name = name, deps = deps, out = out, **kwargs)
diff --git a/tests/BUILD b/tests/BUILD
index 6ceee9a..dc1bcfa 100644
--- a/tests/BUILD
+++ b/tests/BUILD
@@ -1,8 +1,9 @@
 # Test cases for license rules.
 
-load("@rules_license//rules:compliance.bzl", "check_license", "licenses_used")
+load("@rules_license//rules:compliance.bzl", "check_license")
 load("@rules_license//rules:license.bzl", "license")
 load("@rules_license//rules:license_kind.bzl", "license_kind")
+load("@rules_license//sample_reports:licenses_used.bzl", "licenses_used")
 
 package(
     default_applicable_licenses = [":license"],
@@ -48,14 +49,6 @@ license(
     license_text = "LICENSE.extra",
 )
 
-# This license is not in the "compliance" namespace and
-# therefore should not show up in the report verified by
-# :verify_cc_app_test
-license(
-    name = "internal_non_compliance_license",
-    namespace = "test_namespace",
-)
-
 cc_binary(
     name = "hello",
     srcs = ["hello.cc"],
@@ -72,7 +65,6 @@ cc_library(
     applicable_licenses = [
         ":license",
         ":license_for_extra_feature",
-        ":internal_non_compliance_license",
     ],
     deps = [
         "@rules_license//tests/legacy:another_library_with_legacy_license_clause",
diff --git a/tests/apps/BUILD b/tests/apps/BUILD
index 2c0778f..c8b59df 100644
--- a/tests/apps/BUILD
+++ b/tests/apps/BUILD
@@ -1,6 +1,7 @@
 # Test cases for license rules: Sample app
 
-load("@rules_license//rules:compliance.bzl", "licenses_used")
+load("@rules_license//sample_reports:licenses_used.bzl", "licenses_used")
+load("@rules_python//python:defs.bzl", "py_test")
 
 package(default_visibility = ["//examples:__subpackages__"])
 
diff --git a/tools/BUILD b/tools/BUILD
index 2b56a34..d42f4b7 100644
--- a/tools/BUILD
+++ b/tools/BUILD
@@ -14,6 +14,8 @@
 
 """License declaration and compliance checking tools."""
 
+load("@rules_python//python:defs.bzl", "py_binary", "py_library")
+
 package(
     default_applicable_licenses = ["//:license", "//:package_info"],
     default_visibility = ["//visibility:public"],
@@ -36,9 +38,24 @@ py_binary(
     visibility = ["//visibility:public"],
 )
 
+py_library(
+    name = "sbom_lib",
+    srcs = ["sbom.py"],
+    visibility = ["//visibility:public"],
+)
+
 py_binary(
     name = "write_sbom",
     srcs = ["write_sbom.py"],
+    deps = [":sbom_lib"],
+    python_version = "PY3",
+    visibility = ["//visibility:public"],
+)
+
+py_binary(
+    name = "write_workspace_sbom",
+    srcs = ["write_workspace_sbom.py"],
+    deps = [":sbom_lib"],
     python_version = "PY3",
     visibility = ["//visibility:public"],
 )
diff --git a/tools/checker_demo.py b/tools/checker_demo.py
index 6cdf07f..cbd8ee1 100644
--- a/tools/checker_demo.py
+++ b/tools/checker_demo.py
@@ -31,11 +31,6 @@ def _load_license_data(licenses_info):
     return json.loads(licenses_file.read())
 
 
-def unique_licenses(licenses):
-  for target in licenses:
-    for lic in target.get('licenses') or []:
-      yield lic
-
 def _do_report(out, licenses):
   """Produce a report showing the set of licenses being used.
 
@@ -47,13 +42,12 @@ def _do_report(out, licenses):
     0 for no restricted licenses.
   """
 
-  for target in unique_licenses(licenses):
-    for lic in target.get('licenses') or []:
-      print("lic:", lic)
-      rule = lic['rule']
-      for kind in lic['license_kinds']:
-        out.write('= %s\n  kind: %s\n' % (rule, kind['target']))
-        out.write('  conditions: %s\n' % kind['conditions'])
+  for lic in licenses:
+    print("lic:", lic)
+    rule = lic['rule']
+    for kind in lic['license_kinds']:
+      out.write('= %s\n  kind: %s\n' % (rule, kind['target']))
+      out.write('  conditions: %s\n' % kind['conditions'])
 
 
 def _check_conditions(out, licenses, allowed_conditions):
@@ -94,7 +88,7 @@ def _do_copyright_notices(out, licenses):
 
 
 def _do_licenses(out, licenses):
-  for lic in unique_licenses(licenses):
+  for lic in licenses:
     path = lic['license_text']
     with codecs.open(path, encoding='utf-8') as license_file:
       out.write('= %s\n' % path)
diff --git a/tools/sbom.py b/tools/sbom.py
new file mode 100644
index 0000000..7d7f03b
--- /dev/null
+++ b/tools/sbom.py
@@ -0,0 +1,53 @@
+import datetime
+import getpass
+import json
+
+
+class SBOMWriter:
+    def __init__(self, tool, out):
+        self.out = out
+        self.tool = tool
+
+    def write_header(self, package):
+        header = [
+            'SPDXVersion: SPDX-2.2',
+            'DataLicense: CC0-1.0',
+            'SPDXID: SPDXRef-DOCUMENT',
+            'DocumentName: %s' % package,
+            # TBD
+            # 'DocumentNamespace: https://swinslow.net/spdx-examples/example1/hello-v3
+            'Creator: Person: %s' % getpass.getuser(),
+            'Creator: Tool: %s' % self.tool,
+            datetime.datetime.utcnow().strftime('Created: %Y-%m-%d-%H:%M:%SZ'),
+            '',
+            '##### Package: %s' % package,
+        ]
+        self.out.write('\n'.join(header))
+    
+    def write_packages(self, packages):
+        for p in packages:
+            name = p.get('package_name') or '<unknown>'
+            self.out.write('\n')
+            self.out.write('SPDXID: "%s"\n' % name)
+            self.out.write('  name: "%s"\n' % name)
+
+            if p.get('package_version'):
+                self.out.write('  versionInfo: "%s"\n' % p['package_version'])
+            
+            # IGNORE_COPYRIGHT: Not a copyright notice. It is a variable holding one.
+            cn = p.get('copyright_notice')
+            if cn:
+                self.out.write('  copyrightText: "%s"\n' % cn)
+            
+            kinds = p.get('license_kinds')
+            if kinds:
+                self.out.write('  licenseDeclared: "%s"\n' %
+                    ','.join([k['name'] for k in kinds]))
+            
+            url = p.get('package_url')
+            if url:
+                self.out.write('  downloadLocation: %s\n' % url)
+
+            purl = p.get('purl')
+            if purl:
+                self.out.write('  externalRef: PACKAGE-MANAGER purl %s\n' % purl)
diff --git a/tools/test_helpers.bzl b/tools/test_helpers.bzl
index 3ffb9b7..a748c5a 100644
--- a/tools/test_helpers.bzl
+++ b/tools/test_helpers.bzl
@@ -45,7 +45,6 @@ def golden_cmd_test(
         golden,  # Required
         toolchains = [],
         tools = None,
-        exec_tools = None,
         srcs = [],  # Optional
         **kwargs):  # Rest
     """Compares cmd output to golden output, passes if they are identical.
@@ -56,18 +55,11 @@ def golden_cmd_test(
       golden: The golden file to be compared.
       toolchains: List of toolchains needed to run the command, passed to genrule.
       tools: List of tools needed to run the command, passed to genrule.
-      exec_tools: List of tools needed to run the command, passed to genrule.
       srcs: List of sources needed as input to the command, passed to genrule.
       **kwargs: Any additional parameters for the generated golden_test.
     """
     actual = name + ".output"
 
-    # There are some cases where tools are provided and exec_tools are provided.
-    # Specifying both in the same genrule, confuses the host vs exec rules,
-    # which prevents python3 from execution.
-    if tools and exec_tools:
-        fail("Only set one: tools or exec_tools.  " +
-             "Setting both confuses python execution mode (host vs exec).")
     native.genrule(
         name = name + "_output",
         srcs = srcs,
@@ -75,7 +67,6 @@ def golden_cmd_test(
         cmd = cmd + " > '$@'",  # Redirect to collect output
         toolchains = toolchains,
         tools = tools,
-        exec_tools = exec_tools,
         testonly = True,
     )
 
diff --git a/tools/write_sbom.py b/tools/write_sbom.py
index 18286ab..58ed6dd 100644
--- a/tools/write_sbom.py
+++ b/tools/write_sbom.py
@@ -20,10 +20,8 @@ This is only a demonstration. It will be replaced with other tools.
 
 import argparse
 import codecs
-import datetime
 import json
-import os
-
+from tools import sbom
 
 TOOL = 'https//github.com/bazelbuild/rules_license/tools:write_sbom'
 
@@ -31,51 +29,6 @@ def _load_package_data(package_info):
   with codecs.open(package_info, encoding='utf-8') as inp:
     return json.loads(inp.read())
 
-def _write_sbom_header(out, package):
-  header = [
-    'SPDXVersion: SPDX-2.2',
-    'DataLicense: CC0-1.0',
-    'SPDXID: SPDXRef-DOCUMENT',
-    'DocumentName: %s' % package,
-    # TBD
-    # 'DocumentNamespace: https://swinslow.net/spdx-examples/example1/hello-v3
-    'Creator: Person: %s' % os.getlogin(),
-    'Creator: Tool: %s' % TOOL,
-    datetime.datetime.utcnow().strftime('Created: %Y-%m-%d-%H:%M:%SZ'),
-    '',
-    '##### Package: %s' % package,
-  ]
-  out.write('\n'.join(header))
-
-
-
-def _write_sbom(out, packages):
-  """Produce a basic SBOM
-
-  Args:
-    out: file object to write to
-    packages: package metadata. A big blob of JSON.
-  """
-  for p in packages:
-    name = p.get('package_name') or '<unknown>'
-    out.write('\n')
-    out.write('SPDXID: "%s"\n' % name)
-    out.write('  name: "%s"\n' % name)
-    if p.get('package_version'):
-      out.write('  versionInfo: "%s"\n' % p['package_version'])
-    # IGNORE_COPYRIGHT: Not a copyright notice. It is a variable holding one.
-    cn = p.get('copyright_notice')
-    if cn:
-      out.write('  copyrightText: "%s"\n' % cn)
-    kinds = p.get('license_kinds')
-    if kinds:
-      out.write('  licenseDeclared: "%s"\n' %
-                ','.join([k['name'] for k in kinds]))
-    url = p.get('package_url')
-    if url:
-      out.write('  downloadLocation: %s\n' % url)
-
-
 def main():
   parser = argparse.ArgumentParser(
       description='Demonstraton license compliance checker')
@@ -106,11 +59,10 @@ def main():
     else:
       all[pi['bazel_package']] = pi
 
-  err = 0
   with codecs.open(args.out, mode='w', encoding='utf-8') as out:
-    _write_sbom_header(out, package=top_level_target)
-    _write_sbom(out, all.values())
-  return err
+    sbom_writer = sbom.SBOMWriter(TOOL, out)
+    sbom_writer.write_header(package=top_level_target)
+    sbom_writer.write_packages(packages=all.values())
 
 
 if __name__ == '__main__':
diff --git a/tools/write_workspace_sbom.py b/tools/write_workspace_sbom.py
new file mode 100644
index 0000000..90a7df2
--- /dev/null
+++ b/tools/write_workspace_sbom.py
@@ -0,0 +1,76 @@
+#!/usr/bin/env python3
+# Copyright 2020 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+# https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Proof of a WORKSPACE SBOM generator.
+
+This is only a demonstration. It will be replaced with other tools.
+"""
+
+import argparse
+import codecs
+import json
+from tools import sbom
+import subprocess
+import os
+
+TOOL = 'https//github.com/bazelbuild/rules_license/tools:write_workspace_sbom'
+
+def main():
+    parser = argparse.ArgumentParser(
+      description='Demonstraton license compliance checker')
+
+    parser.add_argument('--out', default='sbom.out', help='SBOM output')
+    args = parser.parse_args()
+
+    if "BUILD_WORKING_DIRECTORY" in os.environ:
+        os.chdir(os.environ["BUILD_WORKING_DIRECTORY"])
+
+    external_query_process = subprocess.run(
+        ['bazel', 'query', '--output', 'streamed_jsonproto', '//external:*'],
+        stdout=subprocess.PIPE,
+    )
+    sbom_packages = []
+    for dep_string in external_query_process.stdout.decode('utf-8').splitlines():
+        dep = json.loads(dep_string)
+        if dep["type"] != "RULE":
+            continue
+
+        rule = dep["rule"]
+        if rule["ruleClass"] == "http_archive":
+            sbom_package = {}
+            sbom_packages.append(sbom_package)
+            
+            if "attribute" not in rule:
+                continue
+
+            attributes = {attribute["name"]: attribute for attribute in rule["attribute"]}
+            
+            if "name" in attributes:
+                sbom_package["package_name"] = attributes["name"]["stringValue"]
+            
+            if "url" in attributes:
+                sbom_package["package_url"] = attributes["url"]["stringValue"]
+            elif "urls" in attributes:
+                urls = attributes["urls"]["stringListValue"]
+                if urls and len(urls) > 0:
+                    sbom_package["package_url"] = attributes["urls"]["stringListValue"][0]
+
+    with codecs.open(args.out, mode='w', encoding='utf-8') as out:
+        sbom_writer = sbom.SBOMWriter(TOOL, out)
+        sbom_writer.write_header(package="Bazel's Workspace SBOM")
+        sbom_writer.write_packages(packages=sbom_packages)
+
+if __name__ == '__main__':
+  main()
diff --git a/version.bzl b/version.bzl
index 0acecb6..8c7217c 100644
--- a/version.bzl
+++ b/version.bzl
@@ -13,4 +13,4 @@
 # limitations under the License.
 """The version of rules_license."""
 
-version = "0.0.4"
+version = "1.0.0"
```

