```diff
diff --git a/UsbDebugger/Android.bp b/UsbDebugger/Android.bp
new file mode 100644
index 0000000..a621010
--- /dev/null
+++ b/UsbDebugger/Android.bp
@@ -0,0 +1,58 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_app {
+    name: "UsbDisableDebugger",
+
+    srcs: ["src/**/*.kt"],
+    resource_dirs: ["res"],
+    min_sdk_version: "33",
+    target_sdk_version: "33",
+    certificate: "platform",
+    privileged: true,
+    product_specific: true,
+    sdk_version: "current",
+    dex_preopt: {
+        enabled: false,
+    },
+
+    static_libs: [
+        "kotlinx_coroutines_android",
+        "kotlinx_coroutines",
+        "androidx.appcompat_appcompat",
+        "androidx.annotation_annotation",
+        "androidx.activity_activity-compose",
+        "androidx.compose.material_material-icons-core",
+        "androidx.compose.material3_material3",
+        "androidx.lifecycle_lifecycle-common",
+        "androidx.activity_activity-ktx",
+        "com.google.android.material_material",
+    ],
+    manifest: "AndroidManifest.xml",
+    required: ["privapp_whitelist_com.android.usb.testing.debuggertool.datasignal"],
+}
+
+prebuilt_etc {
+    name: "privapp_whitelist_com.android.usb.testing.debuggertool.datasignal",
+    product_specific: true,
+    sub_dir: "permissions",
+    src: "com.android.usb.testing.debuggertool.datasignal.xml",
+    filename_from_src: true,
+}
diff --git a/UsbDebugger/AndroidManifest.xml b/UsbDebugger/AndroidManifest.xml
new file mode 100644
index 0000000..016d1d3
--- /dev/null
+++ b/UsbDebugger/AndroidManifest.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.usb.testing.debuggertool.datasignal">
+<uses-sdk android:minSdkVersion="34"
+          android:targetSdkVersion="34"
+          android:maxSdkVersion="34" />
+  <application
+      android:icon="@mipmap/ic_launcher"
+      android:roundIcon="@mipmap/ic_launcher_round"
+      android:label="UsbDataSignalTestApp"
+      android:theme="@style/Theme.Material3.DayNight.NoActionBar"
+      tools:targetApi="31">
+    <activity
+        android:name=".MainActivity"
+        android:exported="true">
+      <intent-filter>
+        <action android:name="android.intent.action.MAIN" />
+        <category android:name="android.intent.category.LAUNCHER" />
+      </intent-filter>
+    </activity>
+  </application>
+  <uses-permission android:name="android.permission.MANAGE_USB"
+      tools:ignore="ProtectedPermissions" />
+</manifest>
\ No newline at end of file
diff --git a/UsbDebugger/OWNERS b/UsbDebugger/OWNERS
new file mode 100644
index 0000000..e24e463
--- /dev/null
+++ b/UsbDebugger/OWNERS
@@ -0,0 +1,2 @@
+georgechan@google.com
+maunik@google.com
\ No newline at end of file
diff --git a/UsbDebugger/com.android.usb.testing.debuggertool.datasignal.xml b/UsbDebugger/com.android.usb.testing.debuggertool.datasignal.xml
new file mode 100644
index 0000000..ffc09d2
--- /dev/null
+++ b/UsbDebugger/com.android.usb.testing.debuggertool.datasignal.xml
@@ -0,0 +1,10 @@
+<!--
+This XML file declares which signature|privileged permissions should be granted to privileged
+applications in /system on GMS or Google-branded devices.
+It allows additional grants on top of privapp-permissions-platform.xml
+-->
+<permissions>
+    <privapp-permissions package="com.android.usb.testing.debuggertool.datasignal">
+        <permission name="android.permission.MANAGE_USB"/>
+    </privapp-permissions>
+</permissions>
diff --git a/UsbDebugger/res/drawable/ic_launcher_background.xml b/UsbDebugger/res/drawable/ic_launcher_background.xml
new file mode 100644
index 0000000..61bb79e
--- /dev/null
+++ b/UsbDebugger/res/drawable/ic_launcher_background.xml
@@ -0,0 +1,170 @@
+<?xml version="1.0" encoding="utf-8"?>
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="108dp"
+    android:height="108dp"
+    android:viewportHeight="108"
+    android:viewportWidth="108">
+  <path
+      android:fillColor="#3DDC84"
+      android:pathData="M0,0h108v108h-108z" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M9,0L9,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,0L19,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M29,0L29,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M39,0L39,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M49,0L49,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M59,0L59,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M69,0L69,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M79,0L79,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M89,0L89,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M99,0L99,108"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,9L108,9"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,19L108,19"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,29L108,29"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,39L108,39"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,49L108,49"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,59L108,59"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,69L108,69"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,79L108,79"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,89L108,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M0,99L108,99"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,29L89,29"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,39L89,39"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,49L89,49"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,59L89,59"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,69L89,69"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M19,79L89,79"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M29,19L29,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M39,19L39,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M49,19L49,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M59,19L59,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M69,19L69,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+  <path
+      android:fillColor="#00000000"
+      android:pathData="M79,19L79,89"
+      android:strokeColor="#33FFFFFF"
+      android:strokeWidth="0.8" />
+</vector>
diff --git a/UsbDebugger/res/drawable/ic_launcher_foreground.xml b/UsbDebugger/res/drawable/ic_launcher_foreground.xml
new file mode 100644
index 0000000..966abaf
--- /dev/null
+++ b/UsbDebugger/res/drawable/ic_launcher_foreground.xml
@@ -0,0 +1,30 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:aapt="http://schemas.android.com/aapt"
+    android:width="108dp"
+    android:height="108dp"
+    android:viewportHeight="108"
+    android:viewportWidth="108">
+  <path android:pathData="M31,63.928c0,0 6.4,-11 12.1,-13.1c7.2,-2.6 26,-1.4 26,-1.4l38.1,38.1L107,108.928l-32,-1L31,63.928z">
+    <aapt:attr name="android:fillColor">
+      <gradient
+          android:endX="85.84757"
+          android:endY="92.4963"
+          android:startX="42.9492"
+          android:startY="49.59793"
+          android:type="linear">
+        <item
+            android:color="#44000000"
+            android:offset="0.0" />
+        <item
+            android:color="#00000000"
+            android:offset="1.0" />
+      </gradient>
+    </aapt:attr>
+  </path>
+  <path
+      android:fillColor="#FFFFFF"
+      android:fillType="nonZero"
+      android:pathData="M65.3,45.828l3.8,-6.6c0.2,-0.4 0.1,-0.9 -0.3,-1.1c-0.4,-0.2 -0.9,-0.1 -1.1,0.3l-3.9,6.7c-6.3,-2.8 -13.4,-2.8 -19.7,0l-3.9,-6.7c-0.2,-0.4 -0.7,-0.5 -1.1,-0.3C38.8,38.328 38.7,38.828 38.9,39.228l3.8,6.6C36.2,49.428 31.7,56.028 31,63.928h46C76.3,56.028 71.8,49.428 65.3,45.828zM43.4,57.328c-0.8,0 -1.5,-0.5 -1.8,-1.2c-0.3,-0.7 -0.1,-1.5 0.4,-2.1c0.5,-0.5 1.4,-0.7 2.1,-0.4c0.7,0.3 1.2,1 1.2,1.8C45.3,56.528 44.5,57.328 43.4,57.328L43.4,57.328zM64.6,57.328c-0.8,0 -1.5,-0.5 -1.8,-1.2s-0.1,-1.5 0.4,-2.1c0.5,-0.5 1.4,-0.7 2.1,-0.4c0.7,0.3 1.2,1 1.2,1.8C66.5,56.528 65.6,57.328 64.6,57.328L64.6,57.328z"
+      android:strokeColor="#00000000"
+      android:strokeWidth="1" />
+</vector>
\ No newline at end of file
diff --git a/UsbDebugger/res/layout/activity_main.xml b/UsbDebugger/res/layout/activity_main.xml
new file mode 100644
index 0000000..87d2d79
--- /dev/null
+++ b/UsbDebugger/res/layout/activity_main.xml
@@ -0,0 +1,71 @@
+<?xml version="1.0" encoding="utf-8"?>
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:paddingLeft="16dp"
+    android:paddingRight="16dp"
+    android:orientation="vertical" >
+  <LinearLayout
+      android:layout_width="match_parent"
+      android:layout_marginTop="50dp"
+      android:layout_height="20dp">
+    <TextView
+        android:layout_width="200dp"
+        android:text="Android HAL Version"
+        android:layout_height="wrap_content" />
+    <TextView
+        android:id="@+id/hal_version_text"
+        android:layout_width="match_parent"
+        android:text="Unknown"
+        android:layout_height="wrap_content" />
+  </LinearLayout>
+  <LinearLayout
+      android:layout_width="match_parent"
+      android:layout_height="20dp">
+    <TextView
+        android:layout_width="200dp"
+        android:text="Android USB Data Status"
+        android:layout_height="wrap_content" />
+    <TextView
+        android:id="@+id/usb_data_status_text"
+        android:layout_width="match_parent"
+        android:text="Unknown"
+        android:layout_height="wrap_content" />
+  </LinearLayout>
+  <LinearLayout
+      android:layout_width="match_parent"
+      android:layout_height="20dp">
+    <TextView
+        android:layout_width="200dp"
+        android:text="Battery current mA"
+        android:layout_height="wrap_content" />
+    <TextView
+        android:id="@+id/battery_current_text"
+        android:layout_width="match_parent"
+        android:text="Unknown"
+        android:layout_height="wrap_content" />
+  </LinearLayout>
+  <Button
+      android:id="@+id/usb_button_on"
+      android:layout_width="match_parent"
+      android:layout_height="wrap_content"
+      android:onClick="toggleUsbOn"
+      android:text="Turn On USB Data Signal" />
+  <Button
+      android:id="@+id/usb_button_off"
+      android:layout_width="match_parent"
+      android:layout_height="wrap_content"
+      android:onClick="toggleUsbOff"
+      android:text="Turn Off USB Data Signal" />
+  <TextView
+      android:layout_width="match_parent"
+      android:text="Error"
+      android:layout_height="wrap_content" />
+  <TextView
+      android:id="@+id/error_text"
+      android:layout_width="match_parent"
+      android:text=""
+      android:layout_height="match_parent"
+      android:gravity="bottom" />
+</LinearLayout>
\ No newline at end of file
diff --git a/UsbDebugger/res/mipmap-anydpi/ic_launcher.xml b/UsbDebugger/res/mipmap-anydpi/ic_launcher.xml
new file mode 100644
index 0000000..5ad9ce1
--- /dev/null
+++ b/UsbDebugger/res/mipmap-anydpi/ic_launcher.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+  <background android:drawable="@drawable/ic_launcher_background" />
+  <foreground android:drawable="@drawable/ic_launcher_foreground" />
+  <monochrome android:drawable="@drawable/ic_launcher_foreground" />
+</adaptive-icon>
\ No newline at end of file
diff --git a/UsbDebugger/res/mipmap-anydpi/ic_launcher_round.xml b/UsbDebugger/res/mipmap-anydpi/ic_launcher_round.xml
new file mode 100644
index 0000000..5ad9ce1
--- /dev/null
+++ b/UsbDebugger/res/mipmap-anydpi/ic_launcher_round.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+  <background android:drawable="@drawable/ic_launcher_background" />
+  <foreground android:drawable="@drawable/ic_launcher_foreground" />
+  <monochrome android:drawable="@drawable/ic_launcher_foreground" />
+</adaptive-icon>
\ No newline at end of file
diff --git a/UsbDebugger/res/mipmap-hdpi/ic_launcher.webp b/UsbDebugger/res/mipmap-hdpi/ic_launcher.webp
new file mode 100644
index 0000000..c209e78
Binary files /dev/null and b/UsbDebugger/res/mipmap-hdpi/ic_launcher.webp differ
diff --git a/UsbDebugger/res/mipmap-hdpi/ic_launcher_round.webp b/UsbDebugger/res/mipmap-hdpi/ic_launcher_round.webp
new file mode 100644
index 0000000..b2dfe3d
Binary files /dev/null and b/UsbDebugger/res/mipmap-hdpi/ic_launcher_round.webp differ
diff --git a/UsbDebugger/res/mipmap-mdpi/ic_launcher.webp b/UsbDebugger/res/mipmap-mdpi/ic_launcher.webp
new file mode 100644
index 0000000..4f0f1d6
Binary files /dev/null and b/UsbDebugger/res/mipmap-mdpi/ic_launcher.webp differ
diff --git a/UsbDebugger/res/mipmap-mdpi/ic_launcher_round.webp b/UsbDebugger/res/mipmap-mdpi/ic_launcher_round.webp
new file mode 100644
index 0000000..62b611d
Binary files /dev/null and b/UsbDebugger/res/mipmap-mdpi/ic_launcher_round.webp differ
diff --git a/UsbDebugger/res/mipmap-xhdpi/ic_launcher.webp b/UsbDebugger/res/mipmap-xhdpi/ic_launcher.webp
new file mode 100644
index 0000000..948a307
Binary files /dev/null and b/UsbDebugger/res/mipmap-xhdpi/ic_launcher.webp differ
diff --git a/UsbDebugger/res/mipmap-xhdpi/ic_launcher_round.webp b/UsbDebugger/res/mipmap-xhdpi/ic_launcher_round.webp
new file mode 100644
index 0000000..1b9a695
Binary files /dev/null and b/UsbDebugger/res/mipmap-xhdpi/ic_launcher_round.webp differ
diff --git a/UsbDebugger/res/mipmap-xxhdpi/ic_launcher.webp b/UsbDebugger/res/mipmap-xxhdpi/ic_launcher.webp
new file mode 100644
index 0000000..28d4b77
Binary files /dev/null and b/UsbDebugger/res/mipmap-xxhdpi/ic_launcher.webp differ
diff --git a/UsbDebugger/res/mipmap-xxhdpi/ic_launcher_round.webp b/UsbDebugger/res/mipmap-xxhdpi/ic_launcher_round.webp
new file mode 100644
index 0000000..9287f50
Binary files /dev/null and b/UsbDebugger/res/mipmap-xxhdpi/ic_launcher_round.webp differ
diff --git a/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher.webp b/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher.webp
new file mode 100644
index 0000000..aa7d642
Binary files /dev/null and b/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher.webp differ
diff --git a/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher_round.webp b/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher_round.webp
new file mode 100644
index 0000000..9126ae3
Binary files /dev/null and b/UsbDebugger/res/mipmap-xxxhdpi/ic_launcher_round.webp differ
diff --git a/UsbDebugger/src/com/android/usb/testing/debuggertool/datasignal/MainActivity.kt b/UsbDebugger/src/com/android/usb/testing/debuggertool/datasignal/MainActivity.kt
new file mode 100644
index 0000000..976bfe9
--- /dev/null
+++ b/UsbDebugger/src/com/android/usb/testing/debuggertool/datasignal/MainActivity.kt
@@ -0,0 +1,254 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.usb.testing.debuggertool.datasignal
+
+import android.annotation.SuppressLint
+import android.content.BroadcastReceiver
+import android.content.Context
+import android.content.Intent
+import android.content.IntentFilter
+import android.graphics.Color
+import android.hardware.usb.UsbManager
+import android.os.BatteryManager
+import android.os.Bundle
+import android.os.Handler
+import android.os.Looper
+import android.text.method.ScrollingMovementMethod
+import android.util.Log
+import android.view.View
+import android.widget.TextView
+import android.widget.Toast
+import androidx.activity.enableEdgeToEdge
+import androidx.appcompat.app.AppCompatActivity
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.android.asCoroutineDispatcher
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.launch
+
+const val USB_PORT_CLASS_NAME = "android.hardware.usb.UsbPort"
+const val USB_PORT_STATUS_CLASS_NAME = "android.hardware.usb.UsbPortStatus"
+const val USB_PORT_STATUS_GET_DATA_STATUS_METHOD = "getUsbDataStatus"
+const val POLLING_MILLIS = 1000L
+const val GET_USB_HAL_METHOD = "getUsbHalVersion"
+const val ENABLE_USB_DATA_SIGNAL_METHOD = "enableUsbDataSignal"
+const val IS_PORT_DISABLED_METHOD = "isPortDisabled"
+const val GET_PORTS_METHOD = "getPorts"
+const val ACTION_USB_PORT_CHANGED = "android.hardware.usb.action.USB_PORT_CHANGED"
+const val USB_EXTRA_PORT_STATUS = "portStatus"
+const val DATA_STATUS_DISABLED_FORCE = 8
+
+val REQUIRED_METHODS =
+    setOf(
+        GET_USB_HAL_METHOD,
+        ENABLE_USB_DATA_SIGNAL_METHOD,
+        IS_PORT_DISABLED_METHOD,
+        GET_PORTS_METHOD,
+    )
+const val TAG = "USB_DEBUG_TEST"
+
+class MainActivity : AppCompatActivity() {
+    private val usbPortStatuses = mutableMapOf<String, Boolean>()
+    private val logDivider = "\n" + "-".repeat(25) + "\n"
+
+    private val mBroadcastReceiver =
+        object : BroadcastReceiver() {
+            override fun onReceive(context: Context, intent: Intent) {
+                if (ACTION_USB_PORT_CHANGED == intent.action) {
+                    val portStatus =
+                        intent.getParcelableExtra(
+                            USB_EXTRA_PORT_STATUS,
+                            Class.forName(USB_PORT_STATUS_CLASS_NAME),
+                        )
+                    // Validation for case
+                    val portStatusString =
+                        Class.forName(USB_PORT_STATUS_CLASS_NAME)
+                            .getDeclaredMethod("toString")
+                            .invoke(portStatus) as String
+                    val portStatusDataStatus =
+                        Class.forName(USB_PORT_STATUS_CLASS_NAME)
+                            .getDeclaredMethod(USB_PORT_STATUS_GET_DATA_STATUS_METHOD)
+                            .invoke(portStatus) as Int
+                    // temp for now to only test against devices with 1 USB
+                    if (
+                        DATA_STATUS_DISABLED_FORCE == portStatusDataStatus &&
+                            usbPortStatuses.size == 1 &&
+                            usbPortStatuses.any { it.value }
+                    ) {
+                        usbPortEventEvenWhenDataDisabledOccurred = true
+                        mStatusText.setTextColor(Color.GREEN)
+                        log("Usb event detected when data disabled. Confirmed behavior.", true)
+                    }
+                    log(portStatusString, true)
+                } else if (
+                    intent.action in
+                        setOf(
+                            UsbManager.ACTION_USB_DEVICE_ATTACHED,
+                            UsbManager.ACTION_USB_ACCESSORY_ATTACHED,
+                        )
+                ) {
+                    log(intent.action + " event caught", true)
+                }
+            }
+        }
+
+    private lateinit var mStatusText: TextView
+    private lateinit var mBatteryCurrentText: TextView
+    private lateinit var mUsbManager: UsbManager
+    private lateinit var mBatteryManager: BatteryManager
+    private lateinit var mErrorTextView: TextView
+
+    private var job: Job? = null
+    private var portStatusString: CharSequence = ""
+    private var usbPortEventEvenWhenDataDisabledOccurred = false
+
+    @SuppressLint("SetTextI18n")
+    private fun log(message: String, debug: Boolean = false) {
+        val logType = if (debug) "DEBUG:" else "EXCEPTION:"
+        mErrorTextView.text = mErrorTextView.text.toString() + logType + message + logDivider
+        Log.d(TAG, message)
+    }
+
+    @SuppressLint("SetTextI18n")
+    override fun onCreate(savedInstanceState: Bundle?) {
+        mUsbManager = getSystemService(Context.USB_SERVICE) as UsbManager
+        mBatteryManager = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
+        super.onCreate(savedInstanceState)
+        enableEdgeToEdge()
+        setContentView(R.layout.activity_main)
+        try {
+            mErrorTextView = findViewById<View>(R.id.error_text) as TextView
+            mErrorTextView.movementMethod = ScrollingMovementMethod()
+            mStatusText = findViewById<View>(R.id.usb_data_status_text) as TextView
+            mBatteryCurrentText = findViewById<View>(R.id.battery_current_text) as TextView
+            val usbHalVersionTextview = findViewById<View>(R.id.hal_version_text) as TextView
+
+            checkApiAvailability()
+            usbHalVersionTextview.text = getUsbHalVersion().toString()
+            job =
+                CoroutineScope(Job() + Handler(Looper.getMainLooper()).asCoroutineDispatcher())
+                    .launch {
+                        try {
+                            while (true) {
+                                mStatusText.text = formattedUsbDataStatus()
+                                if (mStatusText.text.equals(portStatusString)) {
+                                    log(
+                                        "usbPortStatus changed: mStatusText: ${mStatusText.text}",
+                                        true,
+                                    )
+                                }
+                                mBatteryCurrentText.text =
+                                    (mBatteryManager.getIntProperty(
+                                            BatteryManager.BATTERY_PROPERTY_CURRENT_NOW
+                                        ) / 1000)
+                                        .toString()
+                                delay(POLLING_MILLIS)
+                            }
+                        } catch (ex: Exception) {
+                            log("${ex.message} ${ex.stackTraceToString()}")
+                        }
+                    }
+            val intentFilter = IntentFilter()
+            intentFilter.addAction(ACTION_USB_PORT_CHANGED)
+            intentFilter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
+            intentFilter.addAction(UsbManager.ACTION_USB_ACCESSORY_ATTACHED)
+            registerReceiver(mBroadcastReceiver, intentFilter)
+        } catch (ex: Exception) {
+            log("${ex.message} ${ex.stackTraceToString()}")
+        }
+    }
+
+    override fun onStop() {
+        super.onStop()
+    }
+
+    fun toggleUsbOn(v: View) {
+        try {
+            setUsbDataSignal(true)
+        } catch (ex: Exception) {
+            log("${ex.message} ${ex.stackTraceToString()}")
+        }
+        log("Attempt to turn on USB occurred", true)
+        Toast.makeText(this, "Attempting to turn ON USB data", Toast.LENGTH_LONG).show()
+    }
+
+    fun toggleUsbOff(v: View) {
+        try {
+            setUsbDataSignal(false)
+        } catch (ex: Exception) {
+            log("${ex.message} ${ex.stackTraceToString()}")
+        }
+        log("Attempt to turn off USB occurred", true)
+        Toast.makeText(this, "Attempting to turn OFF USB data", Toast.LENGTH_LONG).show()
+    }
+
+    private fun getUsbHalVersion(): Int {
+        val halVersion =
+            UsbManager::class.java.getMethod(GET_USB_HAL_METHOD).invoke(mUsbManager) as Int
+        return halVersion
+    }
+
+    private fun checkApiAvailability() {
+        val declaredMethodNames = UsbManager::class.java.declaredMethods.map { it.name }
+        val methodNames = UsbManager::class.java.methods.map { it.name }
+        val missingMethods =
+            REQUIRED_METHODS.filterNot { method ->
+                declaredMethodNames.any { it == method } or methodNames.any { it == method }
+            }
+        if (missingMethods.isNotEmpty()) {
+            val sb = StringBuilder()
+            sb.append("Not all required found: Missing methods: $missingMethods \n")
+            sb.append("Current API methods:\n")
+            UsbManager::class.java.methods.map { sb.append(it.name).append("\n") }
+            sb.append("Current API declared methods:\n")
+            UsbManager::class.java.declaredMethods.map { sb.append(it.name).append("\n") }
+            throw Exception(sb.toString())
+        }
+    }
+
+    private fun setUsbDataSignal(enable: Boolean): Boolean {
+        val result =
+            UsbManager::class
+                .java
+                .getMethod(ENABLE_USB_DATA_SIGNAL_METHOD, Boolean::class.java)
+                .invoke(mUsbManager, enable) as Boolean
+        return result
+    }
+
+    @SuppressLint("PrivateApi", "SoonBlockedPrivateApi")
+    private fun formattedUsbDataStatus(): String {
+        val sb = StringBuilder()
+        val ports =
+            UsbManager::class.java.getMethod(GET_PORTS_METHOD).invoke(mUsbManager) as List<*>
+
+        for (port in ports) {
+            val portId =
+                Class.forName(USB_PORT_CLASS_NAME).getDeclaredMethod("getId").invoke(port) as String
+            sb.append(portId).append(": ")
+            val method =
+                UsbManager::class
+                    .java
+                    .getDeclaredMethod(IS_PORT_DISABLED_METHOD, Class.forName(USB_PORT_CLASS_NAME))
+            method.isAccessible = true
+            val enabled = if (method.invoke(mUsbManager, port) as Boolean) "disabled" else "enabled"
+            usbPortStatuses[portId] = enabled == "enabled"
+            sb.append(enabled)
+            sb.append("\n")
+        }
+        return sb.toString()
+    }
+}
diff --git a/gsi_arm64.mk b/gsi_arm64.mk
index f81942f..7f796ce 100644
--- a/gsi_arm64.mk
+++ b/gsi_arm64.mk
@@ -51,6 +51,12 @@ $(call inherit-product, device/generic/common/gsi_product.mk)
 #
 $(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
 
+#
+# Flag build to add in Usb Debugging Test App
+#
+ifneq ($(filter userdebug,$(TARGET_BUILD_VARIANT)),)
+    $(call soong_config_set_bool, gsi, import_usb_debugging_test_app, true)
+endif
 
 PRODUCT_NAME := gsi_arm64
 PRODUCT_DEVICE := generic_arm64
@@ -60,3 +66,5 @@ PRODUCT_MODEL := GSI on ARM64
 PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
 PRODUCT_USE_SOONG_NOTICE_XML := true
 USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+
+PRODUCT_PACKAGES_DEBUG += UsbDisableDebugger
diff --git a/gsi_product.mk b/gsi_product.mk
index 47f5c54..7eb728f 100644
--- a/gsi_product.mk
+++ b/gsi_product.mk
@@ -23,6 +23,7 @@ PRODUCT_PACKAGES += \
     Camera2 \
     Dialer \
     LatinIME \
+    messaging \
     frameworks-base-overlays \
 
 # Default AOSP sounds
diff --git a/gsi_system_ext.mk b/gsi_system_ext.mk
index 026e8c0..136fcfc 100644
--- a/gsi_system_ext.mk
+++ b/gsi_system_ext.mk
@@ -26,6 +26,9 @@ PRODUCT_PACKAGES += \
     StorageManager \
     SystemUI
 
+# Allowlist for system packages included in handheld_system_ext.mk
+PRODUCT_PACKAGES += preinstalled_packages_handheld_system_ext.xml
+
 #  telephony packages
 PRODUCT_PACKAGES += \
     CarrierConfig
```

