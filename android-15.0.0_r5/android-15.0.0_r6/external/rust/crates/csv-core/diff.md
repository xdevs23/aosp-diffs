```diff
diff --git a/Android.bp b/Android.bp
index 3336547..d38c353 100644
--- a/Android.bp
+++ b/Android.bp
@@ -7,36 +7,14 @@ package {
     default_applicable_licenses: ["external_rust_crates_csv-core_license"],
 }
 
-// Added automatically by a large-scale-change that took the approach of
-// 'apply every license found to every target'. While this makes sure we respect
-// every license restriction, it may not be entirely correct.
-//
-// e.g. GPL in an MIT project might only apply to the contrib/ directory.
-//
-// Please consider splitting the single license below into multiple licenses,
-// taking care not to lose any license_kind information, and overriding the
-// default license using the 'licenses: [...]' property on targets as needed.
-//
-// For unused files, consider creating a 'fileGroup' with "//visibility:private"
-// to attach the license to, and including a comment whether the files may be
-// used in the current project.
-//
-// large-scale-change included anything that looked like it might be a license
-// text as a license_text. e.g. LICENSE, NOTICE, COPYING etc.
-//
-// Please consider removing redundant or irrelevant files from 'license_text:'.
-// See: http://go/android-license-faq
 license {
     name: "external_rust_crates_csv-core_license",
     visibility: [":__subpackages__"],
     license_kinds: [
         "SPDX-license-identifier-MIT",
-        "SPDX-license-identifier-Unlicense",
     ],
     license_text: [
-        "COPYING",
         "LICENSE",
-        "UNLICENSE",
     ],
 }
 
diff --git a/LICENSE b/LICENSE
deleted file mode 100644
index 3b0a5dc..0000000
--- a/LICENSE
+++ /dev/null
@@ -1,21 +0,0 @@
-The MIT License (MIT)
-
-Copyright (c) 2015 Andrew Gallant
-
-Permission is hereby granted, free of charge, to any person obtaining a copy
-of this software and associated documentation files (the "Software"), to deal
-in the Software without restriction, including without limitation the rights
-to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-copies of the Software, and to permit persons to whom the Software is
-furnished to do so, subject to the following conditions:
-
-The above copyright notice and this permission notice shall be included in
-all copies or substantial portions of the Software.
-
-THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-THE SOFTWARE.
diff --git a/LICENSE b/LICENSE
new file mode 120000
index 0000000..7f9a88e
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1 @@
+LICENSE-MIT
\ No newline at end of file
```

