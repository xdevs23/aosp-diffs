```diff
diff --git a/.clang-tidy b/.clang-tidy
index 6349aa8..1f59ae9 100644
--- a/.clang-tidy
+++ b/.clang-tidy
@@ -2,19 +2,10 @@
 Checks: "-*,\
 boost-*,\
 bugprone-*,\
--bugprone-assignment-in-if-condition,\
--bugprone-branch-clone,\
 -bugprone-easily-swappable-parameters,\
--bugprone-implicit-widening-of-multiplication-result,\
--bugprone-macro-parentheses,\
--bugprone-misplaced-widening-cast,\
 -bugprone-narrowing-conversions,\
--bugprone-reserved-identifier,\
 -bugprone-signed-char-misuse,\
--bugprone-suspicious-string-compare,\
 -bugprone-switch-missing-default-case,\
--bugprone-unsafe-functions,\
--bugprone-too-small-loop-variable,\
 clang-analyzer-*,\
 -clang-analyzer-core.NullDereference,\
 -clang-analyzer-deadcode.DeadStores,\
@@ -36,12 +27,8 @@ readability-*,\
 -readability-else-after-return,\
 -readability-identifier-length,\
 -readability-function-cognitive-complexity,\
--readability-inconsistent-declaration-parameter-name,\
 -readability-isolate-declaration,\
 -readability-magic-numbers,\
--readability-non-const-parameter,\
--readability-uppercase-literal-suffix,\
--readability-misleading-indentation,\
 "
 #WarningsAsErrors: "*"
 ...
diff --git a/Android.bp b/Android.bp
index c9e49a4..967c26b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,8 +37,8 @@ license {
     ],
 }
 
-cc_library {
-    name: "libusb",
+cc_defaults {
+    name: "libusb_defaults",
     host_supported: true,
     vendor_available: true,
 
@@ -51,20 +51,6 @@ cc_library {
         "libusb/strerror.c",
     ],
 
-    local_include_dirs: [
-        "libusb",
-        "libusb/os",
-    ],
-
-    cflags: [
-        "-Wall",
-        "-Wno-error=sign-compare",
-        "-Wno-error=switch",
-        "-Wno-error=unused-function",
-        "-Wno-unused-parameter",
-"-DENABLE_LOGGING=1",
-    ],
-
     target: {
         linux: {
             srcs: [
@@ -98,7 +84,7 @@ cc_library {
                 "-framework CoreFoundation",
                 "-framework IOKit",
                 "-framework Security",
-                "-lobjc"
+                "-lobjc",
             ],
 
             cflags: [
@@ -138,6 +124,43 @@ cc_library {
         },
     },
 
+    local_include_dirs: [
+        "libusb",
+        "libusb/os",
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Wno-error=sign-compare",
+        "-Wno-error=switch",
+        "-Wno-error=unused-function",
+        "-Wno-unused-parameter",
+        "-DENABLE_LOGGING=1",
+    ],
+
     shared_libs: ["liblog"],
     export_include_dirs: ["include"],
 }
+
+cc_library {
+    name: "libusb",
+    defaults: ["libusb_defaults"],
+}
+
+// "libusb_plaform" should be depended upon only by programs running on Android
+// at OS level (e.g. Android platform services). The reason is that programs
+// using "libusb_platform" must have permission to access netlink sockets.
+cc_library {
+    name: "libusb_platform",
+    defaults: ["libusb_defaults"],
+    target: {
+        android: {
+            cflags: [
+                "-Werror",
+                "-DANDROID_OS", // ANDROID_OS flag signals that the program
+                // using libusb runs at Android OS level and allows netlink
+                // event monitoring. See libusb/os/linux_usbfs.h.
+            ],
+        },
+    },
+}
diff --git a/KEYS b/KEYS
new file mode 100644
index 0000000..06d0148
--- /dev/null
+++ b/KEYS
@@ -0,0 +1,123 @@
+This file contains the PGP keys of libusb release managers.
+
+Users:
+       pgp < KEYS
+or
+       gpg --import KEYS
+
+Maintainers:
+    pgp -kxa <your name> and append it to this file.
+or
+    (pgpk -ll <your name> && pgpk -xa <your name>) >> this file.
+or
+    (gpg --list-sigs <your name> && gpg --armor --export <your name>) >> this file.
+
+pub   rsa4096 2020-06-23 [SC]
+      C68187379B23DE9EFC46651E2C80FF56C6830A0E
+uid           [ultimate] Tormod Volden <debian.tormod@gmail.com>
+sub   rsa4096 2020-06-23 [E]
+sub   rsa4096 2020-06-23 [S]
+
+-----BEGIN PGP PUBLIC KEY BLOCK-----
+
+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
+=5EaQ
+-----END PGP PUBLIC KEY BLOCK-----
diff --git a/METADATA b/METADATA
index 6db0d54..ee4e958 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libusb
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libusb"
 description: "libusb is a library for USB device access from Linux, macOS, Windows, OpenBSD/NetBSD and Haiku userspace."
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 28
+    month: 11
+    day: 14
   }
   homepage: "https://libusb.info/"
   identifier {
     type: "Git"
     value: "https://github.com/libusb/libusb"
-    version: "2a138c6f12988c42eaa9dd663581faa700c44abe"
+    version: "de38189e8014fa393f4d8c1d9d3fdf5e2a95899d"
   }
 }
diff --git a/Xcode/libusb.xcodeproj/project.pbxproj b/Xcode/libusb.xcodeproj/project.pbxproj
index 4fe9462..680bc19 100644
--- a/Xcode/libusb.xcodeproj/project.pbxproj
+++ b/Xcode/libusb.xcodeproj/project.pbxproj
@@ -231,22 +231,22 @@
 
 /* Begin PBXFileReference section */
 		006AD41C1C8C5A90007F8C6A /* hotplugtest */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.executable"; includeInIndex = 0; path = hotplugtest; sourceTree = BUILT_PRODUCTS_DIR; };
-		006AD4231C8C5AAE007F8C6A /* hotplugtest.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = hotplugtest.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
+		006AD4231C8C5AAE007F8C6A /* hotplugtest.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = hotplugtest.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		008A23C6236C8445004854AA /* stress.c */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.c.c; path = stress.c; sourceTree = "<group>"; usesTabs = 1; };
 		008A23CA236C849A004854AA /* libusb_testlib.h */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.c.h; path = libusb_testlib.h; sourceTree = "<group>"; usesTabs = 1; };
 		008A23CB236C849A004854AA /* testlib.c */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.c.c; path = testlib.c; sourceTree = "<group>"; usesTabs = 1; };
 		008A23D3236C8594004854AA /* stress */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.executable"; includeInIndex = 0; path = stress; sourceTree = BUILT_PRODUCTS_DIR; };
 		008FBF311628B79300BC5BE2 /* libusb-1.0.0.dylib */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.dylib"; includeInIndex = 0; path = "libusb-1.0.0.dylib"; sourceTree = BUILT_PRODUCTS_DIR; };
-		008FBF541628B7E800BC5BE2 /* core.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = core.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
-		008FBF551628B7E800BC5BE2 /* descriptor.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = descriptor.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
-		008FBF561628B7E800BC5BE2 /* io.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = io.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
+		008FBF541628B7E800BC5BE2 /* core.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = core.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
+		008FBF551628B7E800BC5BE2 /* descriptor.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = descriptor.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
+		008FBF561628B7E800BC5BE2 /* io.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = io.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		008FBF5A1628B7E800BC5BE2 /* libusb.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = libusb.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		008FBF671628B7E800BC5BE2 /* libusbi.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = libusbi.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		008FBF6C1628B7E800BC5BE2 /* darwin_usb.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 2; lastKnownFileType = sourcecode.c.c; path = darwin_usb.c; sourceTree = "<group>"; tabWidth = 2; usesTabs = 0; };
 		008FBF6D1628B7E800BC5BE2 /* darwin_usb.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 2; lastKnownFileType = sourcecode.c.h; path = darwin_usb.h; sourceTree = "<group>"; tabWidth = 2; usesTabs = 0; };
 		008FBF741628B7E800BC5BE2 /* threads_posix.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = threads_posix.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		008FBF751628B7E800BC5BE2 /* threads_posix.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = threads_posix.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
-		008FBF7A1628B7E800BC5BE2 /* sync.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = sync.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
+		008FBF7A1628B7E800BC5BE2 /* sync.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = sync.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		008FBF7B1628B7E800BC5BE2 /* version.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = version.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		008FBF7C1628B7E800BC5BE2 /* version_nano.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = version_nano.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		008FBFA41628B84200BC5BE2 /* config.h */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = config.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
@@ -264,7 +264,7 @@
 		008FC0051628BBDB00BC5BE2 /* dpfp_threaded */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.executable"; includeInIndex = 0; path = dpfp_threaded; sourceTree = BUILT_PRODUCTS_DIR; };
 		008FC0151628BC0300BC5BE2 /* fxload */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.executable"; includeInIndex = 0; path = fxload; sourceTree = BUILT_PRODUCTS_DIR; };
 		008FC0261628BC6B00BC5BE2 /* listdevs */ = {isa = PBXFileReference; explicitFileType = "compiled.mach-o.executable"; includeInIndex = 0; path = listdevs; sourceTree = BUILT_PRODUCTS_DIR; };
-		1438D77817A2ED9F00166101 /* hotplug.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = hotplug.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
+		1438D77817A2ED9F00166101 /* hotplug.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = hotplug.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		1438D77E17A2F0EA00166101 /* strerror.c */ = {isa = PBXFileReference; fileEncoding = 4; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = strerror.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 1; };
 		1443EE8416417E63007E0579 /* common.xcconfig */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = text.xcconfig; path = common.xcconfig; sourceTree = SOURCE_ROOT; tabWidth = 4; usesTabs = 1; };
 		1443EE8516417E63007E0579 /* debug.xcconfig */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = text.xcconfig; path = debug.xcconfig; sourceTree = SOURCE_ROOT; tabWidth = 4; usesTabs = 1; };
@@ -278,17 +278,17 @@
 		14EC13E42B3D5BBE00CF9AD0 /* netbsd_usb.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = netbsd_usb.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13E52B3D5BBE00CF9AD0 /* events_windows.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = events_windows.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13E62B3D5BBE00CF9AD0 /* haiku_usb_raw.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = haiku_usb_raw.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		14EC13E72B3D5BBE00CF9AD0 /* linux_netlink.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = linux_netlink.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
+		14EC13E72B3D5BBE00CF9AD0 /* linux_netlink.c */ = {isa = PBXFileReference; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = linux_netlink.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		14EC13E82B3D5BBE00CF9AD0 /* haiku_usb_backend.cpp */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.cpp.cpp; path = haiku_usb_backend.cpp; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13E92B3D5BBE00CF9AD0 /* haiku_usb_raw.cpp */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.cpp.cpp; path = haiku_usb_raw.cpp; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13EA2B3D5BBE00CF9AD0 /* linux_usbfs.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = linux_usbfs.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13EB2B3D5BBE00CF9AD0 /* sunos_usb.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = sunos_usb.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		14EC13EC2B3D5BBE00CF9AD0 /* linux_udev.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = linux_udev.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
+		14EC13EC2B3D5BBE00CF9AD0 /* linux_udev.c */ = {isa = PBXFileReference; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = linux_udev.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		14EC13ED2B3D5BBE00CF9AD0 /* haiku_usb.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = haiku_usb.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13EE2B3D5BBE00CF9AD0 /* events_windows.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = events_windows.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13EF2B3D5BBE00CF9AD0 /* null_usb.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = null_usb.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13F02B3D5BBE00CF9AD0 /* haiku_pollfs.cpp */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.cpp.cpp; path = haiku_pollfs.cpp; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		14EC13F12B3D5BBE00CF9AD0 /* linux_usbfs.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = linux_usbfs.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
+		14EC13F12B3D5BBE00CF9AD0 /* linux_usbfs.c */ = {isa = PBXFileReference; indentWidth = 8; lastKnownFileType = sourcecode.c.c; path = linux_usbfs.c; sourceTree = "<group>"; tabWidth = 8; usesTabs = 1; };
 		14EC13F22B3D5BC800CF9AD0 /* windows_common.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = windows_common.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13F32B3D5BC800CF9AD0 /* threads_windows.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = threads_windows.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13F42B3D5BC800CF9AD0 /* windows_winusb.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = windows_winusb.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
@@ -297,10 +297,10 @@
 		14EC13F72B3D5BC800CF9AD0 /* threads_windows.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = threads_windows.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13F82B3D5BC800CF9AD0 /* windows_usbdk.h */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.h; path = windows_usbdk.h; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		14EC13F92B3D5BC800CF9AD0 /* windows_usbdk.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = windows_usbdk.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		1472E1592B43D66B00850BA3 /* init_context.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = init_context.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
+		1472E1592B43D66B00850BA3 /* init_context.c */ = {isa = PBXFileReference; indentWidth = 2; lastKnownFileType = sourcecode.c.c; path = init_context.c; sourceTree = "<group>"; tabWidth = 2; usesTabs = 0; };
 		1472E15A2B43D68600850BA3 /* stress_mt.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = stress_mt.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		1472E15D2B43D68600850BA3 /* macos.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = macos.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
-		1472E15F2B43D68600850BA3 /* set_option.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = set_option.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
+		1472E15D2B43D68600850BA3 /* macos.c */ = {isa = PBXFileReference; indentWidth = 2; lastKnownFileType = sourcecode.c.c; path = macos.c; sourceTree = "<group>"; tabWidth = 2; usesTabs = 0; };
+		1472E15F2B43D68600850BA3 /* set_option.c */ = {isa = PBXFileReference; indentWidth = 2; lastKnownFileType = sourcecode.c.c; path = set_option.c; sourceTree = "<group>"; tabWidth = 2; usesTabs = 0; };
 		1472E1602B43D69800850BA3 /* umockdev.c */ = {isa = PBXFileReference; indentWidth = 4; lastKnownFileType = sourcecode.c.c; path = umockdev.c; sourceTree = "<group>"; tabWidth = 4; usesTabs = 0; };
 		2018D95E24E453BA001589B2 /* events_posix.c */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.c.c; path = events_posix.c; sourceTree = "<group>"; };
 		2018D96024E453D0001589B2 /* events_posix.h */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.c.h; path = events_posix.h; sourceTree = "<group>"; };
diff --git a/examples/dpfp.c b/examples/dpfp.c
index 2949383..6a63cd9 100644
--- a/examples/dpfp.c
+++ b/examples/dpfp.c
@@ -388,7 +388,7 @@ static int save_to_file(unsigned char *data)
 		return -1;
 
 	fputs("P5 384 289 255 ", f);
-	(void)fwrite(data + 64, 1, 384*289, f);
+	(void)fwrite(data + 64, 1, 384L*289L, f);
 	fclose(f);
 	printf("saved image to %s\n", filename);
 	return 0;
diff --git a/examples/ezusb.c b/examples/ezusb.c
index 4bed12a..75cdd4f 100644
--- a/examples/ezusb.c
+++ b/examples/ezusb.c
@@ -815,7 +815,12 @@ int ezusb_load_ram(libusb_device_handle *device, const char *path, int fx_type,
 		}
 
 		/* at least write the interrupt vectors (at 0x0000) for reset! */
-		rewind(image);
+		status = fseek(image, 0L, SEEK_SET);
+		if (status < 0) {
+			logerror("unable to rewind file %s\n", path);
+			ret = status;
+			goto exit;
+		}
 		if (verbose)
 			logerror("2nd stage: write on-chip memory\n");
 		status = parse_ihex(image, &ctx, is_external, ram_poke);
diff --git a/examples/fxload.c b/examples/fxload.c
index 2526083..0e5fdf4 100644
--- a/examples/fxload.c
+++ b/examples/fxload.c
@@ -38,7 +38,9 @@
 #include <syslog.h>
 static bool dosyslog = false;
 #include <strings.h>
-#define _stricmp strcasecmp
+#define libusb_strcasecmp strcasecmp
+#else
+#define libusb_strcasecmp _stricmp
 #endif
 
 #ifndef FXLOAD_VERSION
@@ -263,13 +265,13 @@ int main(int argc, char*argv[])
 	for (i=0; i<ARRAYSIZE(path); i++) {
 		if (path[i] != NULL) {
 			ext = path[i] + strlen(path[i]) - 4;
-			if ((_stricmp(ext, ".hex") == 0) || (strcmp(ext, ".ihx") == 0))
+			if ((libusb_strcasecmp(ext, ".hex") == 0) || (libusb_strcasecmp(ext, ".ihx") == 0))
 				img_type[i] = IMG_TYPE_HEX;
-			else if (_stricmp(ext, ".iic") == 0)
+			else if (libusb_strcasecmp(ext, ".iic") == 0)
 				img_type[i] = IMG_TYPE_IIC;
-			else if (_stricmp(ext, ".bix") == 0)
+			else if (libusb_strcasecmp(ext, ".bix") == 0)
 				img_type[i] = IMG_TYPE_BIX;
-			else if (_stricmp(ext, ".img") == 0)
+			else if (libusb_strcasecmp(ext, ".img") == 0)
 				img_type[i] = IMG_TYPE_IMG;
 			else {
 				logerror("%s is not a recognized image type\n", path[i]);
diff --git a/examples/xusb.c b/examples/xusb.c
index 1ee4639..65c2d6a 100644
--- a/examples/xusb.c
+++ b/examples/xusb.c
@@ -66,7 +66,7 @@ static void perr(char const *format, ...)
 	va_end(args);
 }
 
-#define ERR_EXIT(errcode) do { perr("   %s\n", libusb_strerror((enum libusb_error)errcode)); return -1; } while (0)
+#define ERR_EXIT(errcode) do { perr("   %s\n", libusb_strerror((enum libusb_error)(errcode))); return -1; } while (0)
 #define CALL_CHECK(fcall) do { int _r=fcall; if (_r < 0) ERR_EXIT(_r); } while (0)
 #define CALL_CHECK_CLOSE(fcall, hdl) do { int _r=fcall; if (_r < 0) { libusb_close(hdl); ERR_EXIT(_r); } } while (0)
 #define B(x) (((x)!=0)?1:0)
@@ -546,11 +546,14 @@ static int test_mass_storage(libusb_device_handle *handle, uint8_t endpoint_in,
 		get_sense(handle, endpoint_in, endpoint_out);
 	} else {
 		display_buffer_hex(data, size);
-		if ((binary_dump) && ((fd = fopen(binary_name, "w")) != NULL)) {
-			if (fwrite(data, 1, (size_t)size, fd) != (unsigned int)size) {
-				perr("   unable to write binary data\n");
+		if (binary_dump) {
+			fd = fopen(binary_name, "w");
+			if (fd != NULL) {
+				if (fwrite(data, 1, (size_t)size, fd) != (unsigned int)size) {
+					perr("   unable to write binary data\n");
+				}
+				fclose(fd);
 			}
-			fclose(fd);
 		}
 	}
 	free(data);
@@ -559,16 +562,16 @@ static int test_mass_storage(libusb_device_handle *handle, uint8_t endpoint_in,
 }
 
 // HID
-static int get_hid_record_size(uint8_t *hid_report_descriptor, int size, int type)
+static int get_hid_record_size(const uint8_t *hid_report_descriptor, int size, int type)
 {
-	uint8_t i, j = 0;
+	uint8_t j = 0;
 	uint8_t offset;
 	int record_size[3] = {0, 0, 0};
 	unsigned int nb_bits = 0, nb_items = 0;
 	bool found_record_marker;
 
 	found_record_marker = false;
-	for (i = hid_report_descriptor[0]+1; i < size; i += offset) {
+	for (int i = hid_report_descriptor[0]+1; i < size; i += offset) {
 		offset = (hid_report_descriptor[i]&0x03) + 1;
 		if (offset == 4)
 			offset = 5;
@@ -628,11 +631,14 @@ static int test_hid(libusb_device_handle *handle, uint8_t endpoint_in)
 		return -1;
 	}
 	display_buffer_hex(hid_report_descriptor, (unsigned int)descriptor_size);
-	if ((binary_dump) && ((fd = fopen(binary_name, "w")) != NULL)) {
-		if (fwrite(hid_report_descriptor, 1, (size_t)descriptor_size, fd) != (size_t)descriptor_size) {
-			printf("   Error writing descriptor to file\n");
+	if (binary_dump) {
+		fd = fopen(binary_name, "w");
+		if (fd != NULL) {
+			if (fwrite(hid_report_descriptor, 1, (size_t)descriptor_size, fd) != (size_t)descriptor_size) {
+				printf("   Error writing descriptor to file\n");
+			}
+			fclose(fd);
 		}
-		fclose(fd);
 	}
 
 	size = get_hid_record_size(hid_report_descriptor, descriptor_size, HID_REPORT_TYPE_FEATURE);
@@ -1077,9 +1083,25 @@ static int test_device(uint16_t vid, uint16_t pid)
 	return 0;
 }
 
+static void display_help(const char *progname)
+{
+	printf("usage: %s [-h] [-d] [-i] [-k] [-b file] [-l lang] [-j] [-x] [-s] [-p] [-w] [vid:pid]\n", progname);
+	printf("   -h      : display usage\n");
+	printf("   -d      : enable debug output\n");
+	printf("   -i      : print topology and speed info\n");
+	printf("   -j      : test composite FTDI based JTAG device\n");
+	printf("   -k      : test Mass Storage device\n");
+	printf("   -b file : dump Mass Storage data to file 'file'\n");
+	printf("   -p      : test Sony PS3 SixAxis controller\n");
+	printf("   -s      : test Microsoft Sidewinder Precision Pro (HID)\n");
+	printf("   -x      : test Microsoft XBox Controller Type S\n");
+	printf("   -l lang : language to report errors in (ISO 639-1)\n");
+	printf("   -w      : force the use of device requests when querying WCID descriptors\n");
+	printf("If only the vid:pid is provided, xusb attempts to run the most appropriate test\n");
+}
+
 int main(int argc, char** argv)
 {
-	bool show_help = false;
 	bool debug_mode = false;
 	const struct libusb_version* version;
 	int j, r;
@@ -1096,7 +1118,12 @@ int main(int argc, char** argv)
 	if (((uint8_t*)&endian_test)[0] == 0xBE) {
 		printf("Despite their natural superiority for end users, big endian\n"
 			"CPUs are not supported with this program, sorry.\n");
-		return 0;
+		return EXIT_FAILURE;
+	}
+
+	if ((argc == 1) || (argc > 7)) {
+		display_help(argv[0]);
+		return EXIT_FAILURE;
 	}
 
 	if (argc >= 2) {
@@ -1117,7 +1144,7 @@ int main(int argc, char** argv)
 				case 'b':
 					if ((j+1 >= argc) || (argv[j+1][0] == '-') || (argv[j+1][0] == '/')) {
 						printf("   Option -b requires a file name\n");
-						return 1;
+						return EXIT_FAILURE;
 					}
 					binary_name = argv[++j];
 					binary_dump = true;
@@ -1125,7 +1152,7 @@ int main(int argc, char** argv)
 				case 'l':
 					if ((j+1 >= argc) || (argv[j+1][0] == '-') || (argv[j+1][0] == '/')) {
 						printf("   Option -l requires an ISO 639-1 language parameter\n");
-						return 1;
+						return EXIT_FAILURE;
 					}
 					error_lang = argv[++j];
 					break;
@@ -1162,9 +1189,12 @@ int main(int argc, char** argv)
 					PID = 0x0289;
 					test_mode = USE_XBOX;
 					break;
+				case 'h':
+					display_help(argv[0]);
+					return EXIT_SUCCESS;
 				default:
-					show_help = true;
-					break;
+					display_help(argv[0]);
+					return EXIT_FAILURE;
 				}
 			} else {
 				for (i=0; i<arglen; i++) {
@@ -1174,34 +1204,18 @@ int main(int argc, char** argv)
 				if (i != arglen) {
 					if (sscanf(argv[j], "%x:%x" , &tmp_vid, &tmp_pid) != 2) {
 						printf("   Please specify VID & PID as \"vid:pid\" in hexadecimal format\n");
-						return 1;
+						return EXIT_FAILURE;
 					}
 					VID = (uint16_t)tmp_vid;
 					PID = (uint16_t)tmp_pid;
 				} else {
-					show_help = true;
+					display_help(argv[0]);
+					return EXIT_FAILURE;
 				}
 			}
 		}
 	}
 
-	if ((show_help) || (argc == 1) || (argc > 7)) {
-		printf("usage: %s [-h] [-d] [-i] [-k] [-b file] [-l lang] [-j] [-x] [-s] [-p] [-w] [vid:pid]\n", argv[0]);
-		printf("   -h      : display usage\n");
-		printf("   -d      : enable debug output\n");
-		printf("   -i      : print topology and speed info\n");
-		printf("   -j      : test composite FTDI based JTAG device\n");
-		printf("   -k      : test Mass Storage device\n");
-		printf("   -b file : dump Mass Storage data to file 'file'\n");
-		printf("   -p      : test Sony PS3 SixAxis controller\n");
-		printf("   -s      : test Microsoft Sidewinder Precision Pro (HID)\n");
-		printf("   -x      : test Microsoft XBox Controller Type S\n");
-		printf("   -l lang : language to report errors in (ISO 639-1)\n");
-		printf("   -w      : force the use of device requests when querying WCID descriptors\n");
-		printf("If only the vid:pid is provided, xusb attempts to run the most appropriate test\n");
-		return 0;
-	}
-
 	version = libusb_get_version();
 	printf("Using libusb v%d.%d.%d.%d\n\n", version->major, version->minor, version->micro, version->nano);
 
@@ -1214,7 +1228,7 @@ int main(int argc, char** argv)
 	}
 
 	if (r < 0)
-		return r;
+		return EXIT_FAILURE;
 
 	// If not set externally, and no debug option was given, use info log level
 	if ((old_dbg_str == NULL) && (!debug_mode))
@@ -1225,14 +1239,18 @@ int main(int argc, char** argv)
 			printf("Invalid or unsupported locale '%s': %s\n", error_lang, libusb_strerror((enum libusb_error)r));
 	}
 
-	test_device(VID, PID);
+	r = test_device(VID, PID);
 
 	libusb_exit(NULL);
 
+	if (r < 0)
+		return EXIT_FAILURE;
+
+
 	if (debug_mode) {
 		snprintf(str, sizeof(str), "LIBUSB_DEBUG=%s", (old_dbg_str == NULL)?"":old_dbg_str);
 		str[sizeof(str) - 1] = 0;	// Windows may not NUL terminate the string
 	}
 
-	return 0;
+	return EXIT_SUCCESS;
 }
diff --git a/libusb/core.c b/libusb/core.c
index 7461737..676c397 100644
--- a/libusb/core.c
+++ b/libusb/core.c
@@ -2380,14 +2380,19 @@ int API_EXPORTEDV libusb_set_option(libusb_context *ctx,
  */
 static enum libusb_log_level get_env_debug_level(void)
 {
+	enum libusb_log_level level = LIBUSB_LOG_LEVEL_NONE;
 	const char *dbg = getenv("LIBUSB_DEBUG");
-	enum libusb_log_level level;
 	if (dbg) {
-		int dbg_level = atoi(dbg);
+		char *end = NULL;
+		long dbg_level = strtol(dbg, &end, 10);
+		if (dbg == end ||
+			*end != '\0' ||
+			dbg_level < LIBUSB_LOG_LEVEL_NONE ||
+			dbg_level > LIBUSB_LOG_LEVEL_DEBUG) {
+			usbi_warn(NULL, "LIBUSB_DEBUG is invalid or out of range; clamping");
+		}
 		dbg_level = CLAMP(dbg_level, LIBUSB_LOG_LEVEL_NONE, LIBUSB_LOG_LEVEL_DEBUG);
 		level = (enum libusb_log_level)dbg_level;
-	} else {
-		level = LIBUSB_LOG_LEVEL_NONE;
 	}
 	return level;
 }
diff --git a/libusb/descriptor.c b/libusb/descriptor.c
index 493507f..e8f9581 100644
--- a/libusb/descriptor.c
+++ b/libusb/descriptor.c
@@ -30,54 +30,18 @@
  * for detected devices
  */
 
-#define READ_LE16(p) ((uint16_t)	\
-	(((uint16_t)((p)[1]) << 8) |	\
-	 ((uint16_t)((p)[0]))))
-
-#define READ_LE32(p) ((uint32_t)	\
-	(((uint32_t)((p)[3]) << 24) |	\
-	 ((uint32_t)((p)[2]) << 16) |	\
-	 ((uint32_t)((p)[1]) <<  8) |	\
-	 ((uint32_t)((p)[0]))))
-
-static void parse_descriptor(const void *source, const char *descriptor, void *dest)
+static inline uint16_t ReadLittleEndian16(const uint8_t p[2])
 {
-	const uint8_t *sp = source;
-	uint8_t *dp = dest;
-	char field_type;
-
-	while (*descriptor) {
-		field_type = *descriptor++;
-		switch (field_type) {
-		case 'b':	/* 8-bit byte */
-			*dp++ = *sp++;
-			break;
-		case 'w':	/* 16-bit word, convert from little endian to CPU */
-			dp += ((uintptr_t)dp & 1);	/* Align to 16-bit word boundary */
-
-			*((uint16_t *)dp) = READ_LE16(sp);
-			sp += 2;
-			dp += 2;
-			break;
-		case 'd':	/* 32-bit word, convert from little endian to CPU (4-byte align dst before write). */
-			dp += 4 - ((uintptr_t)dp & 3);	/* Align to 32-bit word boundary */
+	return (uint16_t)((uint16_t)p[1] << 8 |
+			  (uint16_t)p[0]);
+}
 
-			*((uint32_t *)dp) = READ_LE32(sp);
-			sp += 4;
-			dp += 4;
-			break;
-		case 'i':	/* 32-bit word, convert from little endian to CPU (no dst alignment before write) */
-			*((uint32_t *)dp) = READ_LE32(sp);
-			sp += 4;
-			dp += 4;
-			break;
-		case 'u':	/* 16 byte UUID */
-			memcpy(dp, sp, 16);
-			sp += 16;
-			dp += 16;
-			break;
-		}
-	}
+static inline uint32_t ReadLittleEndian32(const uint8_t p[4])
+{
+	return (uint32_t)((uint32_t)p[3] << 24 |
+			  (uint32_t)p[2] << 16 |
+			  (uint32_t)p[1] << 8 |
+			  (uint32_t)p[0]);
 }
 
 static void clear_endpoint(struct libusb_endpoint_descriptor *endpoint)
@@ -92,7 +56,6 @@ static int parse_endpoint(struct libusb_context *ctx,
 	const uint8_t *begin;
 	void *extra;
 	int parsed = 0;
-	int len;
 
 	if (size < DESC_HEADER_LENGTH) {
 		usbi_err(ctx, "short endpoint descriptor read %d/%d",
@@ -114,10 +77,16 @@ static int parse_endpoint(struct libusb_context *ctx,
 		return parsed;
 	}
 
-	if (header->bLength >= LIBUSB_DT_ENDPOINT_AUDIO_SIZE)
-		parse_descriptor(buffer, "bbbbwbbb", endpoint);
-	else
-		parse_descriptor(buffer, "bbbbwb", endpoint);
+	endpoint->bLength = buffer[0];
+	endpoint->bDescriptorType = buffer[1];
+	endpoint->bEndpointAddress = buffer[2];
+	endpoint->bmAttributes = buffer[3];
+	endpoint->wMaxPacketSize = ReadLittleEndian16(&buffer[4]);
+	endpoint->bInterval = buffer[6];
+	if (header->bLength >= LIBUSB_DT_ENDPOINT_AUDIO_SIZE) {
+		endpoint->bRefresh = buffer[7];
+		endpoint->bSynchAddress = buffer[8];
+	}
 
 	buffer += header->bLength;
 	size -= header->bLength;
@@ -153,7 +122,7 @@ static int parse_endpoint(struct libusb_context *ctx,
 
 	/* Copy any unknown descriptors into a storage area for drivers */
 	/*  to later parse */
-	len = (int)(buffer - begin);
+	ptrdiff_t len = buffer - begin;
 	if (len <= 0)
 		return parsed;
 
@@ -163,7 +132,7 @@ static int parse_endpoint(struct libusb_context *ctx,
 
 	memcpy(extra, begin, (size_t)len);
 	endpoint->extra = extra;
-	endpoint->extra_length = len;
+	endpoint->extra_length = (int)len;
 
 	return parsed;
 }
@@ -196,7 +165,6 @@ static void clear_interface(struct libusb_interface *usb_interface)
 static int parse_interface(libusb_context *ctx,
 	struct libusb_interface *usb_interface, const uint8_t *buffer, int size)
 {
-	int len;
 	int r;
 	int parsed = 0;
 	int interface_number = -1;
@@ -217,7 +185,15 @@ static int parse_interface(libusb_context *ctx,
 		usb_interface->altsetting = altsetting;
 
 		ifp = altsetting + usb_interface->num_altsetting;
-		parse_descriptor(buffer, "bbbbbbbbb", ifp);
+		ifp->bLength = buffer[0];
+		ifp->bDescriptorType = buffer[1];
+		ifp->bInterfaceNumber = buffer[2];
+		ifp->bAlternateSetting = buffer[3];
+		ifp->bNumEndpoints = buffer[4];
+		ifp->bInterfaceClass = buffer[5];
+		ifp->bInterfaceSubClass = buffer[6];
+		ifp->bInterfaceProtocol = buffer[7];
+		ifp->iInterface = buffer[8];
 		if (ifp->bDescriptorType != LIBUSB_DT_INTERFACE) {
 			usbi_err(ctx, "unexpected descriptor 0x%x (expected 0x%x)",
 				 ifp->bDescriptorType, LIBUSB_DT_INTERFACE);
@@ -282,7 +258,7 @@ static int parse_interface(libusb_context *ctx,
 
 		/* Copy any unknown descriptors into a storage area for */
 		/*  drivers to later parse */
-		len = (int)(buffer - begin);
+		ptrdiff_t len = buffer - begin;
 		if (len > 0) {
 			void *extra = malloc((size_t)len);
 
@@ -293,7 +269,7 @@ static int parse_interface(libusb_context *ctx,
 
 			memcpy(extra, begin, (size_t)len);
 			ifp->extra = extra;
-			ifp->extra_length = len;
+			ifp->extra_length = (int)len;
 		}
 
 		if (ifp->bNumEndpoints > 0) {
@@ -363,7 +339,14 @@ static int parse_configuration(struct libusb_context *ctx,
 		return LIBUSB_ERROR_IO;
 	}
 
-	parse_descriptor(buffer, "bbwbbbbb", config);
+	config->bLength = buffer[0];
+	config->bDescriptorType = buffer[1];
+	config->wTotalLength = ReadLittleEndian16(&buffer[2]);
+	config->bNumInterfaces = buffer[4];
+	config->bConfigurationValue = buffer[5];
+	config->iConfiguration = buffer[6];
+	config->bmAttributes = buffer[7];
+	config->MaxPower = buffer[8];
 	if (config->bDescriptorType != LIBUSB_DT_CONFIG) {
 		usbi_err(ctx, "unexpected descriptor 0x%x (expected 0x%x)",
 			 config->bDescriptorType, LIBUSB_DT_CONFIG);
@@ -390,7 +373,6 @@ static int parse_configuration(struct libusb_context *ctx,
 	size -= config->bLength;
 
 	for (i = 0; i < config->bNumInterfaces; i++) {
-		int len;
 		const uint8_t *begin;
 
 		/* Skip over the rest of the Class Specific or Vendor */
@@ -426,10 +408,10 @@ static int parse_configuration(struct libusb_context *ctx,
 
 		/* Copy any unknown descriptors into a storage area for */
 		/*  drivers to later parse */
-		len = (int)(buffer - begin);
+		ptrdiff_t len = buffer - begin;
 		if (len > 0) {
 			uint8_t *extra = realloc((void *)config->extra,
-						 (size_t)(config->extra_length + len));
+						 (size_t)(config->extra_length) + (size_t)len);
 
 			if (!extra) {
 				r = LIBUSB_ERROR_NO_MEM;
@@ -438,10 +420,10 @@ static int parse_configuration(struct libusb_context *ctx,
 
 			memcpy(extra + config->extra_length, begin, (size_t)len);
 			config->extra = extra;
-			config->extra_length += len;
+			config->extra_length += (int)len;
 		}
 
-		r = parse_interface(ctx, usb_interface + i, buffer, size);
+		r = parse_interface(ctx, usb_interface + i, buffer, (int)size);
 		if (r < 0)
 			goto err;
 		if (r == 0) {
@@ -712,14 +694,14 @@ int API_EXPORTED libusb_get_ss_endpoint_companion_descriptor(
 	const struct libusb_endpoint_descriptor *endpoint,
 	struct libusb_ss_endpoint_companion_descriptor **ep_comp)
 {
-	struct usbi_descriptor_header *header;
+	const struct usbi_descriptor_header *header;
 	const uint8_t *buffer = endpoint->extra;
 	int size = endpoint->extra_length;
 
 	*ep_comp = NULL;
 
 	while (size >= DESC_HEADER_LENGTH) {
-		header = (struct usbi_descriptor_header *)buffer;
+		header = (const struct usbi_descriptor_header *)buffer;
 		if (header->bDescriptorType != LIBUSB_DT_SS_ENDPOINT_COMPANION) {
 			if (header->bLength < DESC_HEADER_LENGTH) {
 				usbi_err(ctx, "invalid descriptor length %u",
@@ -742,7 +724,11 @@ int API_EXPORTED libusb_get_ss_endpoint_companion_descriptor(
 		*ep_comp = malloc(sizeof(**ep_comp));
 		if (!*ep_comp)
 			return LIBUSB_ERROR_NO_MEM;
-		parse_descriptor(buffer, "bbbbw", *ep_comp);
+		(*ep_comp)->bLength = buffer[0];
+		(*ep_comp)->bDescriptorType = buffer[1];
+		(*ep_comp)->bMaxBurst = buffer[2];
+		(*ep_comp)->bmAttributes = buffer[3];
+		(*ep_comp)->wBytesPerInterval = ReadLittleEndian16(&buffer[4]);
 		return LIBUSB_SUCCESS;
 	}
 	return LIBUSB_ERROR_NOT_FOUND;
@@ -795,7 +781,10 @@ static int parse_bos(struct libusb_context *ctx,
 	if (!_bos)
 		return LIBUSB_ERROR_NO_MEM;
 
-	parse_descriptor(buffer, "bbwb", _bos);
+	_bos->bLength = buffer[0];
+	_bos->bDescriptorType = buffer[1];
+	_bos->wTotalLength = ReadLittleEndian16(&buffer[2]);
+	_bos->bNumDeviceCaps = buffer[4];
 	buffer += _bos->bLength;
 	size -= _bos->bLength;
 
@@ -915,7 +904,7 @@ void API_EXPORTED libusb_free_bos_descriptor(struct libusb_bos_descriptor *bos)
  *
  * \param ctx the context to operate on, or NULL for the default context
  * \param dev_cap Device Capability descriptor with a bDevCapabilityType of
- * \ref libusb_capability_type::LIBUSB_BT_USB_2_0_EXTENSION
+ * \ref libusb_bos_type::LIBUSB_BT_USB_2_0_EXTENSION
  * LIBUSB_BT_USB_2_0_EXTENSION
  * \param usb_2_0_extension output location for the USB 2.0 Extension
  * descriptor. Only valid if 0 was returned. Must be freed with
@@ -945,7 +934,10 @@ int API_EXPORTED libusb_get_usb_2_0_extension_descriptor(
 	if (!_usb_2_0_extension)
 		return LIBUSB_ERROR_NO_MEM;
 
-	parse_descriptor(dev_cap, "bbbd", _usb_2_0_extension);
+	_usb_2_0_extension->bLength = dev_cap->bLength;
+	_usb_2_0_extension->bDescriptorType = dev_cap->bDescriptorType;
+	_usb_2_0_extension->bDevCapabilityType = dev_cap->bDevCapabilityType;
+	_usb_2_0_extension->bmAttributes = ReadLittleEndian32(dev_cap->dev_capability_data);
 
 	*usb_2_0_extension = _usb_2_0_extension;
 	return LIBUSB_SUCCESS;
@@ -970,7 +962,7 @@ void API_EXPORTED libusb_free_usb_2_0_extension_descriptor(
  *
  * \param ctx the context to operate on, or NULL for the default context
  * \param dev_cap Device Capability descriptor with a bDevCapabilityType of
- * \ref libusb_capability_type::LIBUSB_BT_SS_USB_DEVICE_CAPABILITY
+ * \ref libusb_bos_type::LIBUSB_BT_SS_USB_DEVICE_CAPABILITY
  * LIBUSB_BT_SS_USB_DEVICE_CAPABILITY
  * \param ss_usb_device_cap output location for the SuperSpeed USB Device
  * Capability descriptor. Only valid if 0 was returned. Must be freed with
@@ -1000,24 +992,48 @@ int API_EXPORTED libusb_get_ss_usb_device_capability_descriptor(
 	if (!_ss_usb_device_cap)
 		return LIBUSB_ERROR_NO_MEM;
 
-	parse_descriptor(dev_cap, "bbbbwbbw", _ss_usb_device_cap);
+	_ss_usb_device_cap->bLength = dev_cap->bLength;
+	_ss_usb_device_cap->bDescriptorType = dev_cap->bDescriptorType;
+	_ss_usb_device_cap->bDevCapabilityType = dev_cap->bDevCapabilityType;
+	_ss_usb_device_cap->bmAttributes = dev_cap->dev_capability_data[0];
+	_ss_usb_device_cap->wSpeedSupported = ReadLittleEndian16(&dev_cap->dev_capability_data[1]);
+	_ss_usb_device_cap->bFunctionalitySupport = dev_cap->dev_capability_data[3];
+	_ss_usb_device_cap->bU1DevExitLat = dev_cap->dev_capability_data[4];
+	_ss_usb_device_cap->bU2DevExitLat = ReadLittleEndian16(&dev_cap->dev_capability_data[5]);
 
 	*ss_usb_device_cap = _ss_usb_device_cap;
 	return LIBUSB_SUCCESS;
 }
 
-/* We use this private struct only to parse a SuperSpeedPlus device capability
-   descriptor according to section 9.6.2.5 of the USB 3.1 specification.
-   We don't expose it. */
+/// @cond DEV
+/** \internal \ingroup libusb_desc
+ * We use this private struct only to parse a SuperSpeedPlus device capability
+ * descriptor according to section 9.6.2.5 of the USB 3.1 specification.
+ * We don't expose it.
+ */
 struct internal_ssplus_capability_descriptor {
+	/** The length of the descriptor. Must be equal to LIBUSB_BT_SSPLUS_USB_DEVICE_CAPABILITY_SIZE */
 	uint8_t  bLength;
+
+	/** The type of the descriptor */
 	uint8_t  bDescriptorType;
+
+	/** Must be equal to LIBUSB_BT_SUPERSPEED_PLUS_CAPABILITY */
 	uint8_t  bDevCapabilityType;
+
+	/** Unused */
 	uint8_t  bReserved;
+
+	/** Contains the number of SublinkSpeedIDs */
 	uint32_t bmAttributes;
+
+	/** Contains the ssid, minRxLaneCount, and minTxLaneCount */
 	uint16_t wFunctionalitySupport;
+
+	/** Unused */
 	uint16_t wReserved;
 };
+/// @endcond
 
 int API_EXPORTED libusb_get_ssplus_usb_device_capability_descriptor(
 	libusb_context *ctx,
@@ -1041,8 +1057,14 @@ int API_EXPORTED libusb_get_ssplus_usb_device_capability_descriptor(
 		return LIBUSB_ERROR_IO;
 	}
 
-	/* We can only parse the non-variable size part of the SuperSpeedPlus descriptor. The attributes have to be read "manually". */
-	parse_descriptor(dev_cap, "bbbbiww", &parsedDescriptor);
+	const uint8_t* dev_capability_data = dev_cap->dev_capability_data;
+	parsedDescriptor.bLength = dev_cap->bLength;
+	parsedDescriptor.bDescriptorType = dev_cap->bDescriptorType;
+	parsedDescriptor.bDevCapabilityType = dev_cap->bDevCapabilityType;
+	parsedDescriptor.bReserved = dev_capability_data[0];
+	parsedDescriptor.bmAttributes = ReadLittleEndian32(&dev_capability_data[1]);
+	parsedDescriptor.wFunctionalitySupport = ReadLittleEndian16(&dev_capability_data[5]);
+	parsedDescriptor.wReserved = ReadLittleEndian16(&dev_capability_data[7]);
 
 	uint8_t numSublikSpeedAttributes = (parsedDescriptor.bmAttributes & 0xF) + 1;
 	_ssplus_cap = malloc(sizeof(struct libusb_ssplus_usb_device_capability_descriptor) + numSublikSpeedAttributes * sizeof(struct libusb_ssplus_sublink_attribute));
@@ -1067,7 +1089,7 @@ int API_EXPORTED libusb_get_ssplus_usb_device_capability_descriptor(
 	/* Read the attributes */
 	uint8_t* base = ((uint8_t*)dev_cap) + LIBUSB_BT_SSPLUS_USB_DEVICE_CAPABILITY_SIZE;
 	for(uint8_t i = 0 ; i < _ssplus_cap->numSublinkSpeedAttributes ; i++) {
-		uint32_t attr = READ_LE32(base + i * sizeof(uint32_t));
+		uint32_t attr = ReadLittleEndian32(base + i * sizeof(uint32_t));
 		_ssplus_cap->sublinkSpeedAttributes[i].ssid = attr & 0x0f;
 		_ssplus_cap->sublinkSpeedAttributes[i].mantissa = attr >> 16;
 		_ssplus_cap->sublinkSpeedAttributes[i].exponent = (attr >> 4) & 0x3 ;
@@ -1108,7 +1130,7 @@ void API_EXPORTED libusb_free_ss_usb_device_capability_descriptor(
  *
  * \param ctx the context to operate on, or NULL for the default context
  * \param dev_cap Device Capability descriptor with a bDevCapabilityType of
- * \ref libusb_capability_type::LIBUSB_BT_CONTAINER_ID
+ * \ref libusb_bos_type::LIBUSB_BT_CONTAINER_ID
  * LIBUSB_BT_CONTAINER_ID
  * \param container_id output location for the Container ID descriptor.
  * Only valid if 0 was returned. Must be freed with
@@ -1137,7 +1159,11 @@ int API_EXPORTED libusb_get_container_id_descriptor(libusb_context *ctx,
 	if (!_container_id)
 		return LIBUSB_ERROR_NO_MEM;
 
-	parse_descriptor(dev_cap, "bbbbu", _container_id);
+	_container_id->bLength = dev_cap->bLength;
+	_container_id->bDescriptorType = dev_cap->bDescriptorType;
+	_container_id->bDevCapabilityType = dev_cap->bDevCapabilityType;
+	_container_id->bReserved = dev_cap->dev_capability_data[0];
+	memcpy(_container_id->ContainerID, &dev_cap->dev_capability_data[1], 16);
 
 	*container_id = _container_id;
 	return LIBUSB_SUCCESS;
@@ -1164,7 +1190,7 @@ void API_EXPORTED libusb_free_container_id_descriptor(
  *
  * \param ctx the context to operate on, or NULL for the default context
  * \param dev_cap Device Capability descriptor with a bDevCapabilityType of
- * \ref libusb_capability_type::LIBUSB_BT_PLATFORM_DESCRIPTOR
+ * \ref libusb_bos_type::LIBUSB_BT_PLATFORM_DESCRIPTOR
  * LIBUSB_BT_PLATFORM_DESCRIPTOR
  * \param platform_descriptor output location for the Platform descriptor.
  * Only valid if 0 was returned. Must be freed with
@@ -1193,13 +1219,17 @@ int API_EXPORTED libusb_get_platform_descriptor(libusb_context *ctx,
 	if (!_platform_descriptor)
 		return LIBUSB_ERROR_NO_MEM;
 
-	parse_descriptor(dev_cap, "bbbbu", _platform_descriptor);
+	_platform_descriptor->bLength = dev_cap->bLength;
+	_platform_descriptor->bDescriptorType = dev_cap->bDescriptorType;
+	_platform_descriptor->bDevCapabilityType = dev_cap->bDevCapabilityType;
+	_platform_descriptor->bReserved = dev_cap->dev_capability_data[0];
+	memcpy(_platform_descriptor->PlatformCapabilityUUID, &(dev_cap->dev_capability_data[1]), 16);
 
-	/* Capability data is located after reserved byte and 128-bit UUID */
+	/* Capability data is located after reserved byte and 16 byte UUID */
 	uint8_t* capability_data = dev_cap->dev_capability_data + 1 + 16;
 
 	/* Capability data length is total descriptor length minus initial fields */
-	size_t capability_data_length = _platform_descriptor->bLength - (16 + 4);
+	size_t capability_data_length = dev_cap->bLength - (3 + 1 + 16);
 
 	memcpy(_platform_descriptor->CapabilityData, capability_data, capability_data_length);
 
@@ -1255,9 +1285,7 @@ int API_EXPORTED libusb_get_string_descriptor_ascii(libusb_device_handle *dev_ha
 	r = libusb_get_string_descriptor(dev_handle, 0, 0, str.buf, 4);
 	if (r < 0)
 		return r;
-	else if (r != 4 || str.desc.bLength < 4)
-		return LIBUSB_ERROR_IO;
-	else if (str.desc.bDescriptorType != LIBUSB_DT_STRING)
+	else if (r != 4 || str.desc.bLength < 4 || str.desc.bDescriptorType != LIBUSB_DT_STRING)
 		return LIBUSB_ERROR_IO;
 	else if (str.desc.bLength & 1)
 		usbi_warn(HANDLE_CTX(dev_handle), "suspicious bLength %u for language ID string descriptor", str.desc.bLength);
@@ -1266,9 +1294,7 @@ int API_EXPORTED libusb_get_string_descriptor_ascii(libusb_device_handle *dev_ha
 	r = libusb_get_string_descriptor(dev_handle, desc_index, langid, str.buf, sizeof(str.buf));
 	if (r < 0)
 		return r;
-	else if (r < DESC_HEADER_LENGTH || str.desc.bLength > r)
-		return LIBUSB_ERROR_IO;
-	else if (str.desc.bDescriptorType != LIBUSB_DT_STRING)
+	else if (r < DESC_HEADER_LENGTH || str.desc.bLength > r || str.desc.bDescriptorType != LIBUSB_DT_STRING)
 		return LIBUSB_ERROR_IO;
 	else if ((str.desc.bLength & 1) || str.desc.bLength != r)
 		usbi_warn(HANDLE_CTX(dev_handle), "suspicious bLength %u for string descriptor (read %d)", str.desc.bLength, r);
@@ -1314,12 +1340,18 @@ static int parse_iad_array(struct libusb_context *ctx,
 	/* First pass: Iterate through desc list, count number of IADs */
 	iad_array->length = 0;
 	while (consumed < size) {
-		parse_descriptor(buf, "bb", &header);
-		if (header.bLength < 2) {
+		header.bLength = buf[0];
+		header.bDescriptorType = buf[1];
+		if (header.bLength < DESC_HEADER_LENGTH) {
 			usbi_err(ctx, "invalid descriptor bLength %d",
 				 header.bLength);
 			return LIBUSB_ERROR_IO;
 		}
+		else if (header.bLength > size) {
+			usbi_warn(ctx, "short config descriptor read %d/%u",
+					  size, header.bLength);
+			return LIBUSB_ERROR_IO;
+		}
 		if (header.bDescriptorType == LIBUSB_DT_INTERFACE_ASSOCIATION)
 			iad_array->length++;
 		buf += header.bLength;
@@ -1335,15 +1367,29 @@ static int parse_iad_array(struct libusb_context *ctx,
 		iad_array->iad = iad;
 
 		/* Second pass: Iterate through desc list, fill IAD structures */
-		consumed = 0;
+		int remaining = size;
 		i = 0;
-		while (consumed < size) {
-		   parse_descriptor(buffer, "bb", &header);
-		   if (header.bDescriptorType == LIBUSB_DT_INTERFACE_ASSOCIATION)
-			  parse_descriptor(buffer, "bbbbbbbb", &iad[i++]);
-		   buffer += header.bLength;
-		   consumed += header.bLength;
-		}
+		do {
+			header.bLength = buffer[0];
+			header.bDescriptorType = buffer[1];
+			if (header.bDescriptorType == LIBUSB_DT_INTERFACE_ASSOCIATION && (remaining >= LIBUSB_DT_INTERFACE_ASSOCIATION_SIZE)) {
+				iad[i].bLength = buffer[0];
+				iad[i].bDescriptorType = buffer[1];
+				iad[i].bFirstInterface = buffer[2];
+				iad[i].bInterfaceCount = buffer[3];
+				iad[i].bFunctionClass = buffer[4];
+				iad[i].bFunctionSubClass = buffer[5];
+				iad[i].bFunctionProtocol = buffer[6];
+				iad[i].iFunction = buffer[7];
+				i++;
+			}
+
+			remaining -= header.bLength;
+			if (remaining < DESC_HEADER_LENGTH) {
+				break;
+			}
+			buffer += header.bLength;
+		} while (1);
 	}
 
 	return LIBUSB_SUCCESS;
diff --git a/libusb/libusb.h b/libusb/libusb.h
index fa1ca6b..f0f15ca 100644
--- a/libusb/libusb.h
+++ b/libusb/libusb.h
@@ -335,6 +335,7 @@ enum libusb_descriptor_type {
 #define LIBUSB_DT_SS_ENDPOINT_COMPANION_SIZE	6
 #define LIBUSB_DT_BOS_SIZE			5
 #define LIBUSB_DT_DEVICE_CAPABILITY_SIZE	3
+#define LIBUSB_DT_INTERFACE_ASSOCIATION_SIZE	8
 
 /* BOS descriptor sizes */
 #define LIBUSB_BT_USB_2_0_EXTENSION_SIZE	7
@@ -565,7 +566,7 @@ enum libusb_bos_type {
 	/** Platform descriptor */
 	LIBUSB_BT_PLATFORM_DESCRIPTOR = 0x05,
 
-	/* SuperSpeedPlus device capability */
+	/** SuperSpeedPlus device capability */
 	LIBUSB_BT_SUPERSPEED_PLUS_CAPABILITY = 0x0A,
 };
 
@@ -931,7 +932,7 @@ struct libusb_usb_2_0_extension_descriptor {
 	uint8_t  bDescriptorType;
 
 	/** Capability type. Will have value
-	 * \ref libusb_capability_type::LIBUSB_BT_USB_2_0_EXTENSION
+	 * \ref libusb_bos_type::LIBUSB_BT_USB_2_0_EXTENSION
 	 * LIBUSB_BT_USB_2_0_EXTENSION in this context. */
 	uint8_t  bDevCapabilityType;
 
@@ -957,7 +958,7 @@ struct libusb_ss_usb_device_capability_descriptor {
 	uint8_t  bDescriptorType;
 
 	/** Capability type. Will have value
-	 * \ref libusb_capability_type::LIBUSB_BT_SS_USB_DEVICE_CAPABILITY
+	 * \ref libusb_bos_type::LIBUSB_BT_SS_USB_DEVICE_CAPABILITY
 	 * LIBUSB_BT_SS_USB_DEVICE_CAPABILITY in this context. */
 	uint8_t  bDevCapabilityType;
 
@@ -1074,7 +1075,7 @@ struct libusb_ssplus_usb_device_capability_descriptor {
 	/** This field indicates the minimum transmit lane count*/
 	uint8_t minTxLaneCount;
 
-	/** num attrtibutes=  \ref libusb_ssplus_usb_device_capability_descriptor.numSublinkSpeedAttributes= */
+	/** Array size is \ref libusb_ssplus_usb_device_capability_descriptor.numSublinkSpeedAttributes */
 	struct libusb_ssplus_sublink_attribute sublinkSpeedAttributes[];
 };
 
@@ -1093,7 +1094,7 @@ struct libusb_container_id_descriptor {
 	uint8_t  bDescriptorType;
 
 	/** Capability type. Will have value
-	 * \ref libusb_capability_type::LIBUSB_BT_CONTAINER_ID
+	 * \ref libusb_bos_type::LIBUSB_BT_CONTAINER_ID
 	 * LIBUSB_BT_CONTAINER_ID in this context. */
 	uint8_t  bDevCapabilityType;
 
@@ -1118,7 +1119,7 @@ struct libusb_platform_descriptor {
 	uint8_t  bDescriptorType;
 
 	/** Capability type. Will have value
-	 * \ref libusb_capability_type::LIBUSB_BT_PLATFORM_DESCRIPTOR
+	 * \ref libusb_bos_type::LIBUSB_BT_PLATFORM_DESCRIPTOR
 	 * LIBUSB_BT_CONTAINER_ID in this context. */
 	uint8_t  bDevCapabilityType;
 
@@ -1682,7 +1683,7 @@ void LIBUSB_CALL libusb_set_debug(libusb_context *ctx, int level);
 void LIBUSB_CALL libusb_set_log_cb(libusb_context *ctx, libusb_log_cb cb, int mode);
 const struct libusb_version * LIBUSB_CALL libusb_get_version(void);
 int LIBUSB_CALL libusb_has_capability(uint32_t capability);
-const char * LIBUSB_CALL libusb_error_name(int errcode);
+const char * LIBUSB_CALL libusb_error_name(int error_code);
 int LIBUSB_CALL libusb_setlocale(const char *locale);
 const char * LIBUSB_CALL libusb_strerror(int errcode);
 
@@ -2142,16 +2143,16 @@ static inline unsigned char *libusb_get_iso_packet_buffer_simple(
 /* sync I/O */
 
 int LIBUSB_CALL libusb_control_transfer(libusb_device_handle *dev_handle,
-	uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
+	uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
 	unsigned char *data, uint16_t wLength, unsigned int timeout);
 
 int LIBUSB_CALL libusb_bulk_transfer(libusb_device_handle *dev_handle,
 	unsigned char endpoint, unsigned char *data, int length,
-	int *actual_length, unsigned int timeout);
+	int *transferred, unsigned int timeout);
 
 int LIBUSB_CALL libusb_interrupt_transfer(libusb_device_handle *dev_handle,
 	unsigned char endpoint, unsigned char *data, int length,
-	int *actual_length, unsigned int timeout);
+	int *transferred, unsigned int timeout);
 
 /** \ingroup libusb_desc
  * Retrieve a descriptor from the default control pipe.
diff --git a/libusb/os/darwin_usb.c b/libusb/os/darwin_usb.c
index 7bb496b..6f64c3e 100644
--- a/libusb/os/darwin_usb.c
+++ b/libusb/os/darwin_usb.c
@@ -252,7 +252,7 @@ struct darwin_pipe_properties {
   uint8_t number;
   uint8_t direction;
   uint8_t transfer_type;
-  uint16_t max_packet_size;
+  uint16_t max_packet_size; // without multipliers, not "full"
   uint8_t interval;
 };
 typedef struct darwin_pipe_properties darwin_pipe_properties_t;
@@ -262,8 +262,16 @@ static IOReturn darwin_get_pipe_properties(struct darwin_interface *cInterface,
 
 #if (MAX_INTERFACE_VERSION >= 550)
   if (get_interface_interface_version() >= 550) {
+    // GetPipePropertiesV3 returns a "cooked" wMaxPacketSize (premultiplied by burst and mul). This not what we want.
+    // We only call GetPipePropertiesV3 to fill the fields needed to call GetEndpointPropertiesV3.
     IOUSBEndpointProperties pipe_properties = {.bVersion = kUSBEndpointPropertiesVersion3};
     kresult = (*IOINTERFACE_V(cInterface, 550))->GetPipePropertiesV3 (IOINTERFACE(cInterface), pipe, &pipe_properties);
+    if (kIOReturnSuccess != kresult) {
+        return kresult;
+    }
+
+    // GetEndpointPropertiesV3 returns the wMaxPacketSize without burst and mul multipliers.
+    kresult = (*IOINTERFACE_V(cInterface, 550))->GetEndpointPropertiesV3 (IOINTERFACE(cInterface), &pipe_properties);
     if (kIOReturnSuccess == kresult) {
       out->number = pipe_properties.bEndpointNumber;
       out->direction = pipe_properties.bDirection;
@@ -274,9 +282,26 @@ static IOReturn darwin_get_pipe_properties(struct darwin_interface *cInterface,
     return kresult;
   }
 #endif
-  return (*IOINTERFACE(cInterface))->GetPipeProperties(IOINTERFACE(cInterface), pipe, &out->direction,
+  // GetPipeProperties returns a "cooked" version of max_packet_size which includes burst and mul. What we want is the
+  // original maxPacketSize so we can send zero-length packet when requested by users.
+  // We only call GetPipeProperties to retrieve the parameters needed to call GetEndpointProperties.
+  kresult = (*IOINTERFACE(cInterface))->GetPipeProperties(IOINTERFACE(cInterface), pipe, &out->direction,
                                                                &out->number, &out->transfer_type, &out->max_packet_size,
                                                                &out->interval);
+  if (kIOReturnSuccess != kresult) {
+      return kresult;
+  }
+
+  // To call GetEndpointProperties we also need altSetting
+  UInt8 altSetting;
+  kresult = (*IOINTERFACE(cInterface))->GetAlternateSetting(IOINTERFACE(cInterface), &altSetting);
+  if (kIOReturnSuccess != kresult) {
+     return kresult;
+  }
+  // Retrieve "uncooked" version of maxPacketSize
+  return (*IOINTERFACE(cInterface))->GetEndpointProperties(IOINTERFACE(cInterface), altSetting, out->number,
+                                                           out->direction, &out->transfer_type, &out->max_packet_size,
+                                                           &out->interval);
 }
 
 #if defined(ENABLE_LOGGING)
@@ -694,7 +719,7 @@ static void darwin_devices_detached (void *ptr, io_iterator_t rem_devices) {
 static void darwin_hotplug_poll (void)
 {
   /* not sure if 1 ms will be too long/short but it should work ok */
-  mach_timespec_t timeout = {.tv_sec = 0, .tv_nsec = 1000000ul};
+  mach_timespec_t timeout = {.tv_sec = 0, .tv_nsec = 1000000UL};
 
   /* since a kernel thread may notify the IOIterators used for
    * hotplug notification we can't just clear the iterators.
@@ -2123,7 +2148,7 @@ static int darwin_reenumerate_device (struct libusb_device_handle *dev_handle, b
   /* compare descriptors */
   usbi_dbg (ctx, "darwin/reenumerate_device: checking whether descriptors changed");
 
-  if (memcmp (&descriptor, &dpriv->dev_descriptor, sizeof (descriptor))) {
+  if (memcmp (&descriptor, &dpriv->dev_descriptor, sizeof (descriptor)) != 0) {
     /* device descriptor changed. need to return not found. */
     usbi_dbg (ctx, "darwin/reenumerate_device: device descriptor changed");
     return LIBUSB_ERROR_NOT_FOUND;
@@ -2131,7 +2156,7 @@ static int darwin_reenumerate_device (struct libusb_device_handle *dev_handle, b
 
   for (i = 0 ; i < descriptor.bNumConfigurations ; ++i) {
     (void) (*dpriv->device)->GetConfigurationDescriptorPtr (dpriv->device, i, &cached_configuration);
-    if (memcmp (cached_configuration, cached_configurations + i, sizeof (cached_configurations[i]))) {
+    if (memcmp (cached_configuration, cached_configurations + i, sizeof (cached_configurations[i])) != 0) {
       usbi_dbg (ctx, "darwin/reenumerate_device: configuration descriptor %d changed", i);
       return LIBUSB_ERROR_NOT_FOUND;
     }
@@ -2409,10 +2434,10 @@ static int submit_iso_transfer(struct usbi_transfer *itransfer) {
 
   if (LIBUSB_SPEED_FULL == transfer->dev_handle->dev->speed)
     /* Full speed */
-    cInterface->frames[transfer->endpoint] = frame + (UInt32)transfer->num_iso_packets * (1U << (pipe_properties.interval - 1));
+    cInterface->frames[transfer->endpoint] = frame + (UInt64)transfer->num_iso_packets * (1UL << (pipe_properties.interval - 1));
   else
     /* High/super speed */
-    cInterface->frames[transfer->endpoint] = frame + (UInt32)transfer->num_iso_packets * (1U << (pipe_properties.interval - 1)) / 8;
+    cInterface->frames[transfer->endpoint] = frame + (UInt64)transfer->num_iso_packets * (1UL << (pipe_properties.interval - 1)) / 8;
 
   if (kresult != kIOReturnSuccess) {
     usbi_err (TRANSFER_CTX (transfer), "isochronous transfer failed (dir: %s): %s", IS_XFERIN(transfer) ? "In" : "Out",
@@ -2701,7 +2726,8 @@ static int darwin_alloc_streams (struct libusb_device_handle *dev_handle, uint32
 
   /* find the minimum number of supported streams on the endpoint list */
   for (i = 0 ; i < num_endpoints ; ++i) {
-    if (0 != (rc = ep_to_pipeRef (dev_handle, endpoints[i], &pipeRef, NULL, &cInterface))) {
+    rc = ep_to_pipeRef (dev_handle, endpoints[i], &pipeRef, NULL, &cInterface);
+    if (0 != rc) {
       return rc;
     }
 
@@ -2734,7 +2760,8 @@ static int darwin_free_streams (struct libusb_device_handle *dev_handle, unsigne
   int rc;
 
   for (int i = 0 ; i < num_endpoints ; ++i) {
-    if (0 != (rc = ep_to_pipeRef (dev_handle, endpoints[i], &pipeRef, NULL, &cInterface)))
+    rc = ep_to_pipeRef (dev_handle, endpoints[i], &pipeRef, NULL, &cInterface);
+    if (0 != rc)
       return rc;
 
     (*IOINTERFACE_V(cInterface, 550))->SupportsStreams (IOINTERFACE(cInterface), pipeRef, &supportsStreams);
diff --git a/libusb/os/emscripten_webusb.cpp b/libusb/os/emscripten_webusb.cpp
index ced9ad8..0d7fec9 100644
--- a/libusb/os/emscripten_webusb.cpp
+++ b/libusb/os/emscripten_webusb.cpp
@@ -586,12 +586,17 @@ unsigned long getDeviceSessionId(val& web_usb_device) {
 }
 
 val getDeviceList(libusb_context* ctx, discovered_devs** devs) {
+	// Check if browser supports USB
+	val navigator_usb = val::global("navigator")["usb"];
+	if (navigator_usb == val::undefined()) {
+		co_return (int) LIBUSB_ERROR_NOT_SUPPORTED;
+	}
 	// C++ equivalent of `await navigator.usb.getDevices()`. Note: at this point
 	// we must already have some devices exposed - caller must have called
 	// `await navigator.usb.requestDevice(...)` in response to user interaction
 	// before going to LibUSB. Otherwise this list will be empty.
 	auto web_usb_devices =
-		co_await_try(val::global("navigator")["usb"].call<val>("getDevices"));
+		co_await_try(navigator_usb.call<val>("getDevices"));
 	for (auto&& web_usb_device : web_usb_devices) {
 		auto session_id = getDeviceSessionId(web_usb_device);
 
diff --git a/libusb/os/linux_usbfs.c b/libusb/os/linux_usbfs.c
index 8c7b3a9..049d565 100644
--- a/libusb/os/linux_usbfs.c
+++ b/libusb/os/linux_usbfs.c
@@ -541,7 +541,7 @@ static int read_sysfs_attr(struct libusb_context *ctx,
 
 	errno = 0;
 	value = strtol(buf, &endptr, 10);
-	if (value < 0 || value > (long)max_value || errno) {
+	if (buf == endptr || value < 0 || value > (long)max_value || errno) {
 		usbi_err(ctx, "attribute %s contains an invalid value: '%s'", attr, buf);
 		return LIBUSB_ERROR_INVALID_PARAM;
 	} else if (*endptr != '\0') {
@@ -1033,7 +1033,7 @@ static int linux_get_parent_info(struct libusb_device *dev, const char *sysfs_di
 {
 	struct libusb_context *ctx = DEVICE_CTX(dev);
 	struct libusb_device *it;
-	char *parent_sysfs_dir, *tmp;
+	char *parent_sysfs_dir, *tmp, *end;
 	int ret, add_parent = 1;
 
 	/* XXX -- can we figure out the topology when using usbfs? */
@@ -1048,7 +1048,16 @@ static int linux_get_parent_info(struct libusb_device *dev, const char *sysfs_di
 
 	if ((tmp = strrchr(parent_sysfs_dir, '.')) ||
 	    (tmp = strrchr(parent_sysfs_dir, '-'))) {
-	        dev->port_number = atoi(tmp + 1);
+		const char *start = tmp + 1;
+		long port_number = strtol(start, &end, 10);
+		if (port_number < 0 || port_number > INT_MAX || start == end || '\0' != *end) {
+			usbi_warn(ctx, "Can not parse sysfs_dir: %s, unexpected parent info",
+				parent_sysfs_dir);
+			free(parent_sysfs_dir);
+			return LIBUSB_ERROR_OTHER;
+		} else {
+			dev->port_number = (int)port_number;
+		}
 		*tmp = '\0';
 	} else {
 		usbi_warn(ctx, "Can not parse sysfs_dir: %s, no parent info",
diff --git a/libusb/os/linux_usbfs.h b/libusb/os/linux_usbfs.h
index 1238ffa..5c64674 100644
--- a/libusb/os/linux_usbfs.h
+++ b/libusb/os/linux_usbfs.h
@@ -174,7 +174,17 @@ static inline int linux_start_event_monitor(void)
 {
 #if defined(HAVE_LIBUDEV)
 	return linux_udev_start_event_monitor();
-#elif !defined(__ANDROID__)
+/*
+* __ANDROID__: preprocessor macro defined automatically by GCC for all Android
+*              targets (i.e. both Android native applications, and Android OS-level
+*              services)
+*
+* ANDROID_OS: compilation flag that should be set for using libusb from programs
+*             running on Android at OS level (e.g. Android platform services).
+*             The programs using libusb built with the ANDROID_OS flag must have
+*             permission to access netlink sockets.
+*/
+#elif !defined(__ANDROID__) || defined(ANDROID_OS)
 	return linux_netlink_start_event_monitor();
 #else
 	return LIBUSB_SUCCESS;
@@ -185,7 +195,7 @@ static inline void linux_stop_event_monitor(void)
 {
 #if defined(HAVE_LIBUDEV)
 	linux_udev_stop_event_monitor();
-#elif !defined(__ANDROID__)
+#elif !defined(__ANDROID__) || defined(ANDROID_OS)
 	linux_netlink_stop_event_monitor();
 #endif
 }
@@ -194,7 +204,7 @@ static inline void linux_hotplug_poll(void)
 {
 #if defined(HAVE_LIBUDEV)
 	linux_udev_hotplug_poll();
-#elif !defined(__ANDROID__)
+#elif !defined(__ANDROID__) || defined(ANDROID_OS)
 	linux_netlink_hotplug_poll();
 #endif
 }
diff --git a/libusb/os/netbsd_usb.c b/libusb/os/netbsd_usb.c
index ebafdf0..a9a50b2 100644
--- a/libusb/os/netbsd_usb.c
+++ b/libusb/os/netbsd_usb.c
@@ -444,6 +444,8 @@ netbsd_handle_transfer_completion(struct usbi_transfer *itransfer)
 int
 _errno_to_libusb(int err)
 {
+	usbi_dbg(NULL, "error: %s (%d)", strerror(err), err);
+
 	switch (err) {
 	case EIO:
 		return LIBUSB_ERROR_IO;
@@ -456,11 +458,9 @@ _errno_to_libusb(int err)
 	case EWOULDBLOCK:
 	case ETIMEDOUT:
 		return LIBUSB_ERROR_TIMEOUT;
+	default:
+		return LIBUSB_ERROR_OTHER;
 	}
-
-	usbi_dbg(NULL, "error: %s (%d)", strerror(err), err);
-
-	return LIBUSB_ERROR_OTHER;
 }
 
 int
diff --git a/libusb/os/openbsd_usb.c b/libusb/os/openbsd_usb.c
index 2a85d1f..13bda30 100644
--- a/libusb/os/openbsd_usb.c
+++ b/libusb/os/openbsd_usb.c
@@ -495,9 +495,9 @@ _errno_to_libusb(int err)
 		return LIBUSB_ERROR_NO_MEM;
 	case ETIMEDOUT:
 		return LIBUSB_ERROR_TIMEOUT;
+	default:
+		return LIBUSB_ERROR_OTHER;
 	}
-
-	return LIBUSB_ERROR_OTHER;
 }
 
 int
diff --git a/libusb/os/windows_winusb.c b/libusb/os/windows_winusb.c
index a30f3de..c77bd20 100644
--- a/libusb/os/windows_winusb.c
+++ b/libusb/os/windows_winusb.c
@@ -29,6 +29,7 @@
 #include <setupapi.h>
 #include <ctype.h>
 #include <stdio.h>
+#include <stdlib.h>
 
 #include "libusbi.h"
 #include "windows_winusb.h"
@@ -1229,6 +1230,9 @@ static bool get_dev_port_number(HDEVINFO dev_info, SP_DEVINFO_DATA *dev_info_dat
 {
 	char buffer[MAX_KEY_LENGTH];
 	DWORD size;
+	const char *start = NULL;
+	char *end = NULL;
+	long long port;
 
 	// First try SPDRP_LOCATION_INFORMATION, which returns a REG_SZ. The string *may* have a format
 	// similar to "Port_#0002.Hub_#000D", in which case we can extract the port number. However, we
@@ -1237,7 +1241,15 @@ static bool get_dev_port_number(HDEVINFO dev_info, SP_DEVINFO_DATA *dev_info_dat
 			NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
 		// Check for the required format.
 		if (strncmp(buffer, "Port_#", 6) == 0) {
-			*port_nr = atoi(buffer + 6);
+			start = buffer + 6;
+			// Note that 0 is both strtoll's sentinel return value to indicate failure, as well
+			// as (obviously) the return value for the literal "0". Fortunately we can always treat
+			// 0 as a failure, since Windows USB port numbers are numbered 1..n.
+			port = strtoll(start, &end, 10);
+			if (port <= 0 || port >= ULONG_MAX || end == start || (*end != '.' && *end != '\0')) {
+				return false;
+			}
+			*port_nr = (DWORD)port;
 			return true;
 		}
 	}
@@ -1251,7 +1263,12 @@ static bool get_dev_port_number(HDEVINFO dev_info, SP_DEVINFO_DATA *dev_info_dat
 		// Find the last "#USB(x)" substring
 		for (char *token = strrchr(buffer, '#'); token != NULL; token = strrchr(buffer, '#')) {
 			if (strncmp(token, "#USB(", 5) == 0) {
-				*port_nr = atoi(token + 5);
+				start = token + 5;
+				port = strtoll(start, &end, 10);
+				if (port <= 0 || port >= ULONG_MAX || end == start || (*end != ')' && *end != '\0')) {
+					return false;
+				}
+				*port_nr = (DWORD)port;
 				return true;
 			}
 			// Shorten the string and try again.
@@ -3499,24 +3516,26 @@ static int _hid_wcslen(WCHAR *str)
 	return i;
 }
 
-static int _hid_get_device_descriptor(struct hid_device_priv *hid_priv, void *data, size_t *size)
+static int _hid_get_device_descriptor(struct libusb_device *dev, struct hid_device_priv *hid_priv, void *data, size_t *size)
 {
 	struct libusb_device_descriptor d;
 
+	/* Copy some values from the cached device descriptor
+	 * because we cannot get them through HID */
 	d.bLength = LIBUSB_DT_DEVICE_SIZE;
 	d.bDescriptorType = LIBUSB_DT_DEVICE;
-	d.bcdUSB = 0x0200; /* 2.00 */
-	d.bDeviceClass = 0;
-	d.bDeviceSubClass = 0;
-	d.bDeviceProtocol = 0;
-	d.bMaxPacketSize0 = 64; /* fix this! */
+	d.bcdUSB = dev->device_descriptor.bcdUSB;
+	d.bDeviceClass = dev->device_descriptor.bDeviceClass;
+	d.bDeviceSubClass = dev->device_descriptor.bDeviceSubClass;
+	d.bDeviceProtocol = dev->device_descriptor.bDeviceProtocol;
+	d.bMaxPacketSize0 = dev->device_descriptor.bMaxPacketSize0;
 	d.idVendor = (uint16_t)hid_priv->vid;
 	d.idProduct = (uint16_t)hid_priv->pid;
-	d.bcdDevice = 0x0100;
+	d.bcdDevice = dev->device_descriptor.bcdDevice;
 	d.iManufacturer = hid_priv->string_index[0];
 	d.iProduct = hid_priv->string_index[1];
 	d.iSerialNumber = hid_priv->string_index[2];
-	d.bNumConfigurations = 1;
+	d.bNumConfigurations = dev->device_descriptor.bNumConfigurations;
 
 	if (*size > LIBUSB_DT_DEVICE_SIZE)
 		*size = LIBUSB_DT_DEVICE_SIZE;
@@ -3744,7 +3763,7 @@ static int _hid_get_descriptor(struct libusb_device *dev, HANDLE hid_handle, int
 	switch (type) {
 	case LIBUSB_DT_DEVICE:
 		usbi_dbg(DEVICE_CTX(dev), "LIBUSB_DT_DEVICE");
-		return _hid_get_device_descriptor(priv->hid, data, size);
+		return _hid_get_device_descriptor(dev, priv->hid, data, size);
 	case LIBUSB_DT_CONFIG:
 		usbi_dbg(DEVICE_CTX(dev), "LIBUSB_DT_CONFIG");
 		if (!_index)
diff --git a/libusb/version_nano.h b/libusb/version_nano.h
index 0fa03f1..de724b2 100644
--- a/libusb/version_nano.h
+++ b/libusb/version_nano.h
@@ -1 +1 @@
-#define LIBUSB_NANO 11906
+#define LIBUSB_NANO 11941
diff --git a/tests/stress_mt.c b/tests/stress_mt.c
index 3a8f321..ab0a36f 100644
--- a/tests/stress_mt.c
+++ b/tests/stress_mt.c
@@ -114,7 +114,8 @@ static thread_return_t THREAD_CALL_TYPE init_and_exit(void * arg)
 	for (ti->iteration = 0; ti->iteration < ITERS && !ti->err; ti->iteration++) {
 		libusb_context *ctx = NULL;
 
-		if ((ti->err = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0)) != 0) {
+		ti->err = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0);
+		if (ti->err != 0) {
 			break;
 		}
 		if (ti->enumerate) {
@@ -127,7 +128,8 @@ static thread_return_t THREAD_CALL_TYPE init_and_exit(void * arg)
 			for (int i = 0; i < ti->devcount && ti->err == 0; i++) {
 				libusb_device *dev = devs[i];
 				struct libusb_device_descriptor desc;
-				if ((ti->err = libusb_get_device_descriptor(dev, &desc)) != 0) {
+				ti->err = libusb_get_device_descriptor(dev, &desc);
+				if (ti->err != 0) {
 					break;
 				}
 				if (no_access[i]) {
```

