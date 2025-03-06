```diff
diff --git a/srcs/Android.bp b/srcs/Android.bp
index 1ca4e99..e584604 100644
--- a/srcs/Android.bp
+++ b/srcs/Android.bp
@@ -29,6 +29,7 @@ sysprop_library {
         "com.android.art.debug",
         "com.android.btservices",
         "com.android.compos",
+        "com.android.crashrecovery",
         "com.android.nfcservices",
         "com.android.media.swcodec",
         "com.android.tethering",
diff --git a/srcs/android/sysprop/BackportedFixesProperties.sysprop b/srcs/android/sysprop/BackportedFixesProperties.sysprop
new file mode 100644
index 0000000..be2ff98
--- /dev/null
+++ b/srcs/android/sysprop/BackportedFixesProperties.sysprop
@@ -0,0 +1,16 @@
+module: "android.sysprop.BackportedFixesProperties"
+owner: Platform
+
+# BitSet where the index of the bits are aliases for known issues that are backported and fixed on
+# the device.
+# Encoded as a long array containing a little-endian representation of a sequence of bits
+# as defined by java.util.BitSet.valueof(long[])
+#
+# The list 10,9 means alias 1,4,64 and 67 are fixed on this device.
+prop {
+    api_name: "alias_bitset"
+    type: LongList
+    scope: Public
+    access: Readonly
+    prop_name: "ro.build.backported_fixes.alias_bitset.long_list"
+}
diff --git a/srcs/android/sysprop/BluetoothProperties.sysprop b/srcs/android/sysprop/BluetoothProperties.sysprop
index e307b79..d6b8e4f 100644
--- a/srcs/android/sysprop/BluetoothProperties.sysprop
+++ b/srcs/android/sysprop/BluetoothProperties.sysprop
@@ -380,6 +380,16 @@ prop {
     prop_name: "bluetooth.profile.gatt.enabled"
 }
 
+# Whether the Gaming Audio profile (GMAP) is enabled on this device.
+# Set by vendors overlay, read at Bluetooth initialization
+prop {
+    api_name: "isProfileGmapEnabled"
+    type: Boolean
+    scope: Public
+    access: Readonly
+    prop_name: "bluetooth.profile.gmap.enabled"
+}
+
 # Whether the Hearing Aid Profile (HAP) client role is enabled on this device.
 # Set by vendors overlay, read at Bluetooth initialization
 prop {
diff --git a/srcs/android/sysprop/CrashRecoveryProperties.sysprop b/srcs/android/sysprop/CrashRecoveryProperties.sysprop
index c9aaa71..34c44d8 100644
--- a/srcs/android/sysprop/CrashRecoveryProperties.sysprop
+++ b/srcs/android/sysprop/CrashRecoveryProperties.sysprop
@@ -18,7 +18,7 @@ owner: Platform
 prop {
     api_name: "lastFactoryResetTimeMs"
     type: Long
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "persist.crashrecovery.last_factory_reset"
 }
@@ -28,7 +28,7 @@ prop {
 prop {
     api_name: "rescueBootStart"
     type: Long
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.rescue_boot_start"
 }
@@ -36,7 +36,7 @@ prop {
 prop {
     api_name: "rescueBootCount"
     type: Integer
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.rescue_boot_count"
 }
@@ -46,7 +46,7 @@ prop {
 prop {
     api_name: "bootMitigationStart"
     type: Long
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.boot_mitigation_start"
 }
@@ -54,7 +54,7 @@ prop {
 prop {
     api_name: "bootMitigationCount"
     type: Integer
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.boot_mitigation_count"
 }
@@ -62,7 +62,7 @@ prop {
 prop {
     api_name: "attemptingReboot"
     type: Boolean
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.attempting_reboot"
 }
@@ -70,7 +70,7 @@ prop {
 prop {
     api_name: "attemptingFactoryReset"
     type: Boolean
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.attempting_factory_reset"
 }
@@ -78,7 +78,7 @@ prop {
 prop {
     api_name: "maxRescueLevelAttempted"
     type: Integer
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "crashrecovery.max_rescue_level_attempted"
 }
@@ -86,7 +86,7 @@ prop {
 prop {
     api_name: "enableRescueParty"
     type: Boolean
-    scope: Internal
+    scope: Public
     access: ReadWrite
     prop_name: "persist.crashrecovery.enable_rescue"
 }
diff --git a/srcs/android/sysprop/InputProperties.sysprop b/srcs/android/sysprop/InputProperties.sysprop
index 769002a..4059654 100644
--- a/srcs/android/sysprop/InputProperties.sysprop
+++ b/srcs/android/sysprop/InputProperties.sysprop
@@ -33,16 +33,6 @@ prop {
     prop_name: "persist.input.enable_motion_prediction"
 }
 
-# A flag to enable the new Keyboard backlight controller introduced in Android U, that allows
-# Framework to control keyboard backlight on supported devices.
-prop {
-    api_name: "enable_keyboard_backlight_control"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "persist.input.keyboard.backlight_control.enabled"
-}
-
 # A flag to force showing a pointer icon for stylus pointers, even when the device is not
 # configured for it. Used for debugging stylus pointer icons. Requires restart.
 prop {
@@ -71,22 +61,3 @@ prop {
     prop_name: "persist.debug.input.enable_input_device_usage_metrics"
 }
 
-# A flag to enable the Custom levels provided via IDC files for Keyboard backlight
-# introduced in Android U-QPR1.
-prop {
-    api_name: "enable_keyboard_backlight_custom_levels"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "persist.input.keyboard.backlight_custom_levels.enabled"
-}
-
-
-# A flag to enable ALS based keyboard backlight control introduced in Android U-QPR1.
-prop {
-    api_name: "enable_ambient_keyboard_backlight_control"
-    type: Boolean
-    scope: Internal
-    access: Readonly
-    prop_name: "persist.input.keyboard.ambient_backlight_control.enabled"
-}
diff --git a/srcs/android/sysprop/MediaProperties.sysprop b/srcs/android/sysprop/MediaProperties.sysprop
index 06890d1..f8f28ea 100644
--- a/srcs/android/sysprop/MediaProperties.sysprop
+++ b/srcs/android/sysprop/MediaProperties.sysprop
@@ -57,3 +57,10 @@ prop {
     scope: Public
     prop_name: "media.c2.hal.selection"
 }
+prop {
+    api_name: "codec2_remove_rendering_depth"
+    type: Boolean
+    access: Readonly
+    scope: Public
+    prop_name: "media.c2.remove_rendering_depth"
+}
diff --git a/srcs/api/PlatformProperties-current.txt b/srcs/api/PlatformProperties-current.txt
index e54d05c..ddd908b 100644
--- a/srcs/api/PlatformProperties-current.txt
+++ b/srcs/api/PlatformProperties-current.txt
@@ -7,6 +7,14 @@ props {
     prop_name: "ro.apk_verity.mode"
   }
 }
+props {
+  module: "android.sysprop.BackportedFixesProperties"
+  prop {
+    api_name: "alias_bitset"
+    type: LongList
+    prop_name: "ro.build.backported_fixes.alias_bitset.long_list"
+  }
+}
 props {
   module: "android.sysprop.BluetoothProperties"
   prop {
@@ -146,6 +154,10 @@ props {
     api_name: "isProfileGattEnabled"
     prop_name: "bluetooth.profile.gatt.enabled"
   }
+  prop {
+    api_name: "isProfileGmapEnabled"
+    prop_name: "bluetooth.profile.gmap.enabled"
+  }
   prop {
     api_name: "isProfileHapClientEnabled"
     prop_name: "bluetooth.profile.hap.client.enabled"
@@ -268,6 +280,60 @@ props {
     enum_values: "empty|disabled|filtered|full"
   }
 }
+props {
+  module: "android.sysprop.CrashRecoveryProperties"
+  prop {
+    api_name: "attemptingFactoryReset"
+    access: ReadWrite
+    prop_name: "crashrecovery.attempting_factory_reset"
+  }
+  prop {
+    api_name: "attemptingReboot"
+    access: ReadWrite
+    prop_name: "crashrecovery.attempting_reboot"
+  }
+  prop {
+    api_name: "bootMitigationCount"
+    type: Integer
+    access: ReadWrite
+    prop_name: "crashrecovery.boot_mitigation_count"
+  }
+  prop {
+    api_name: "bootMitigationStart"
+    type: Long
+    access: ReadWrite
+    prop_name: "crashrecovery.boot_mitigation_start"
+  }
+  prop {
+    api_name: "enableRescueParty"
+    access: ReadWrite
+    prop_name: "persist.crashrecovery.enable_rescue"
+  }
+  prop {
+    api_name: "lastFactoryResetTimeMs"
+    type: Long
+    access: ReadWrite
+    prop_name: "persist.crashrecovery.last_factory_reset"
+  }
+  prop {
+    api_name: "maxRescueLevelAttempted"
+    type: Integer
+    access: ReadWrite
+    prop_name: "crashrecovery.max_rescue_level_attempted"
+  }
+  prop {
+    api_name: "rescueBootCount"
+    type: Integer
+    access: ReadWrite
+    prop_name: "crashrecovery.rescue_boot_count"
+  }
+  prop {
+    api_name: "rescueBootStart"
+    type: Long
+    access: ReadWrite
+    prop_name: "crashrecovery.rescue_boot_start"
+  }
+}
 props {
   owner: Odm
   module: "android.sysprop.DeviceProperties"
@@ -306,6 +372,10 @@ props {
     prop_name: "media.c2.hal.selection"
     enum_values: "aidl|hidl"
   }
+  prop {
+    api_name: "codec2_remove_rendering_depth"
+    prop_name: "media.c2.remove_rendering_depth"
+  }
   prop {
     api_name: "resolution_limit_32bit"
     type: Integer
```

