```diff
diff --git a/.github/workflows/freebsd.yml b/.github/workflows/freebsd.yml
index a126c67..7b0e14a 100644
--- a/.github/workflows/freebsd.yml
+++ b/.github/workflows/freebsd.yml
@@ -10,7 +10,7 @@ on:
     - '.github/workflows/**'
     - '!.github/workflows/freebsd.yml'
 
-permissions: read
+permissions: read-all
 
 jobs:
   freebsd:
diff --git a/.github/workflows/ubuntu.yml b/.github/workflows/ubuntu.yml
index 5061e9b..a5eebb3 100644
--- a/.github/workflows/ubuntu.yml
+++ b/.github/workflows/ubuntu.yml
@@ -10,7 +10,7 @@ on:
     - '.github/workflows/**'
     - '!.github/workflows/ubuntu.yml'
 
-permissions: read
+permissions: read-all
 
 jobs:
   ubuntu-20-04:
diff --git a/.github/workflows/windows.yml b/.github/workflows/windows.yml
index 4d6dfc9..9fed962 100644
--- a/.github/workflows/windows.yml
+++ b/.github/workflows/windows.yml
@@ -12,7 +12,7 @@ on:
     - '!.github/workflows/windows.yml'
     - '!.github/workflows/EnterDevShell.ps1'
 
-permissions: read
+permissions: read-all
 
 jobs:
   windows-msvc:
diff --git a/METADATA b/METADATA
index be31d91..b38ea77 100644
--- a/METADATA
+++ b/METADATA
@@ -8,9 +8,8 @@ third_party {
     type: "Git"
     value: "https://github.com/intel/libva-utils"
     primary_source: true
-    version: "libva-utils-2.21.0"
+    version: "2.22.0"
   }
-  version: "libva-utils-2.21.0"
   last_upgrade_date { year: 2024 month: 10 day: 30 }
 
   # The header in code specifies different licenses:
diff --git a/NEWS b/NEWS
index b186deb..148d3fb 100644
--- a/NEWS
+++ b/NEWS
@@ -1,6 +1,12 @@
-libva-utils NEWS -- summary of changes.  2024-03-12
+libva-utils NEWS -- summary of changes.  2024-06-20
 Copyright (C) 2009-2024 Intel Corporation
 
+Version 2.22.0 - 20.Jun.2024
+* ci:  correct the permission of workflows
+* fix: Fixed possible memory leak in h264encode
+* doc: Fix meson build options in README
+* test/CheckEntrypointsForProfile: fix for limited profiles
+
 Version 2.21.0 - 12.Mar.2024
 * vainfo: Print VAConfigAttribEncMaxTileRows and VAConfigAttribEncMaxTileCols
 * test: Add Prime3 memtype support
@@ -101,7 +107,7 @@ Version 2.10.0 - 18.Dec.2020
 * add Mediacopy Sample code
 * Enable new caps for rate control TCBRC
 * Add support for a --repeat command line option to vp8enc.
-* fix one null pointer dereference risk 
+* fix one null pointer dereference risk
 
 Version 2.9.0 - 11.Sep.2020
 * Fix KW issues
diff --git a/README.md b/README.md
index e583505..8fc97ea 100644
--- a/README.md
+++ b/README.md
@@ -40,7 +40,7 @@ or build using Meson
 ```
 mkdir build
 cd build
-meson .. or meson .. -Denable-tests
+meson .. or meson .. -Dtests=true
 ninja
 sudo ninja install
 ```
@@ -74,4 +74,4 @@ vainfo: Supported profile and entrypoints
       VAProfileVP9Profile0            : VAEntrypointVLD
       VAProfileVP9Profile2            : VAEntrypointVLD
       ...
-```
\ No newline at end of file
+```
diff --git a/configure.ac b/configure.ac
index 38acfea..f6160d9 100644
--- a/configure.ac
+++ b/configure.ac
@@ -29,7 +29,7 @@
 # - micro version is libva_micro_version
 # - pre version is libva_pre_version, usually development version
 m4_define([libva_utils_major_version], [2])
-m4_define([libva_utils_minor_version], [21])
+m4_define([libva_utils_minor_version], [22])
 m4_define([libva_utils_micro_version], [0])
 m4_define([libva_utils_pre_version],   [0])
 
diff --git a/encode/h264encode.c b/encode/h264encode.c
index 04df28b..4509955 100644
--- a/encode/h264encode.c
+++ b/encode/h264encode.c
@@ -1165,6 +1165,7 @@ static int init_va(void)
     /* check the interested configattrib */
     if ((attrib[VAConfigAttribRTFormat].value & VA_RT_FORMAT_YUV420) == 0) {
         printf("Not find desired YUV420 RT format\n");
+	free(entrypoints);
         exit(1);
     } else {
         config_attrib[config_attrib_num].type = VAConfigAttribRTFormat;
diff --git a/meson.build b/meson.build
index f1738d1..ca0dbe2 100644
--- a/meson.build
+++ b/meson.build
@@ -1,5 +1,5 @@
 project('libva-utils', 'c', 'cpp',
-        version : '2.21.0',
+        version : '2.22.0',
         default_options : [
           'warning_level=2',
           'c_std=gnu99',
diff --git a/test/test_va_api_query_config.cpp b/test/test_va_api_query_config.cpp
index 39a8d1a..51eff18 100644
--- a/test/test_va_api_query_config.cpp
+++ b/test/test_va_api_query_config.cpp
@@ -50,6 +50,8 @@ TEST_P(VAAPIQueryConfig, CheckEntrypointsForProfile)
     EXPECT_TRUE(numProfiles > 0)
             << numProfiles << " profiles are supported by driver";
 
+    profiles.resize(numProfiles);
+
     const int maxEntrypoints = vaMaxNumEntrypoints(m_vaDisplay);
     EXPECT_TRUE(maxEntrypoints > 0)
             << maxEntrypoints << " entrypoints are reported";
```

