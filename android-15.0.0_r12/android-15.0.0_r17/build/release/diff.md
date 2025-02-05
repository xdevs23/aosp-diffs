```diff
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
deleted file mode 100644
index 25d88905..00000000
--- a/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_shortcuts_flashing"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
deleted file mode 100644
index 0cc18ccc..00000000
--- a/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_shortcuts_flashing"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
index 40b54638..5f21ca54 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_AKITA_DIR"
 value: {
-  string_value: "device/google/akita-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/akita-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
index 3d446863..55a588b3 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_BLUEJAY_DIR"
 value: {
-  string_value: "device/google/bluejay-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/bluejay-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
index 38a4373a..e4667b61 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_CAIMAN_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
index 3ddeeb5d..5b761ca3 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_CHEETAH_DIR"
 value: {
-  string_value: "device/google/pantah-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/pantah-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
index 1740e869..c3005891 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_COMET_DIR"
 value: {
-  string_value: "device/google/comet-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/comet-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
index d7813990..f7c3b491 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_FELIX_DIR"
 value: {
-  string_value: "device/google/felix-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/felix-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
index 5705f982..44c32c07 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_HUSKY_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/shusky-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
index 46bfe9d3..00220b79 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_KOMODO_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
index e15625d2..2170b11e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_LYNX_DIR"
 value: {
-  string_value: "device/google/lynx-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/lynx-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
index 63f778f6..e3394e4c 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_ORIOLE_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/raviole-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
index b678dfbe..983ae137 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_PANTHER_DIR"
 value: {
-  string_value: "device/google/pantah-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/pantah-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
index f2c64423..d0e996bb 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_RAVEN_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/raviole-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
index c64f47b4..92eb744e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_SHIBA_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/shusky-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
index b462bf0b..1d62908e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_TANGORPRO_DIR"
 value: {
-  string_value: "device/google/tangorpro-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/tangorpro-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
index c7e1accd..02e2d6ec 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_TOKAY_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index 8853c743..46d856b6 100644
--- a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,5 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2025-01-05"
+  string_value: "2025-02-05"
 }
+
diff --git a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index ce29523c..46d856b6 100644
--- a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,5 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2024-11-05"
+  string_value: "2025-02-05"
 }
+
```

