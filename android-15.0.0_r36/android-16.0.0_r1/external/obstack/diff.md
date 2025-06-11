```diff
diff --git a/METADATA b/METADATA
index 1e1d850..0469d25 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/obstack
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "obstack"
 description: "obstack.c and obstack.h from the GCC libiberty library."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://gcc.gnu.org/onlinedocs/libiberty/Obstacks.html"
-  }
-  url {
-    type: ARCHIVE
-    value: "https://github.com/gcc-mirror/gcc/archive/releases/gcc-12.2.0.tar.gz"
-  }
-  version: "releases/gcc-12.2.0"
   license_type: RESTRICTED
   last_upgrade_date {
-    year: 2022
-    month: 10
-    day: 7
+    year: 2025
+    month: 1
+    day: 9
+  }
+  homepage: "https://gcc.gnu.org/onlinedocs/libiberty/Obstacks.html"
+  identifier {
+    type: "Archive"
+    value: "https://github.com/gcc-mirror/gcc/archive/releases/gcc-14.2.0.tar.gz"
+    version: "releases/gcc-14.2.0"
   }
 }
diff --git a/OWNERS b/OWNERS
index f08b334..e72fafa 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 ccross@android.com
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/include/obstack.h b/include/obstack.h
index ee71cda..0b0e29d 100644
--- a/include/obstack.h
+++ b/include/obstack.h
@@ -1,5 +1,5 @@
 /* obstack.h - object stack macros
-   Copyright (C) 1988-2022 Free Software Foundation, Inc.
+   Copyright (C) 1988-2024 Free Software Foundation, Inc.
    This file is part of the GNU C Library.
 
    The GNU C Library is free software; you can redistribute it and/or
diff --git a/libiberty/obstack.c b/libiberty/obstack.c
index 1415a87..f6d4eb7 100644
--- a/libiberty/obstack.c
+++ b/libiberty/obstack.c
@@ -1,5 +1,5 @@
 /* obstack.c - subroutines used implicitly by object stack macros
-   Copyright (C) 1988-2022 Free Software Foundation, Inc.
+   Copyright (C) 1988-2024 Free Software Foundation, Inc.
    This file is part of the GNU C Library.
 
    The GNU C Library is free software; you can redistribute it and/or
```

