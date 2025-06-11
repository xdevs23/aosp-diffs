```diff
diff --git a/DeviceDiagnosticsLib/src/androidTest/java/com/android/devicediagnostics/MainActivityTest.kt b/DeviceDiagnosticsLib/src/androidTest/java/com/android/devicediagnostics/MainActivityTest.kt
index 677a9d7..2ab88dd 100644
--- a/DeviceDiagnosticsLib/src/androidTest/java/com/android/devicediagnostics/MainActivityTest.kt
+++ b/DeviceDiagnosticsLib/src/androidTest/java/com/android/devicediagnostics/MainActivityTest.kt
@@ -77,13 +77,12 @@ private fun touchDownAndUp(): ViewAction? {
             val coordinates =
                 floatArrayOf(
                     view.width.toFloat() / 2 + location[0],
-                    view.height.toFloat() / 2 + location[1]
+                    view.height.toFloat() / 2 + location[1],
                 )
             val precision = floatArrayOf(1f, 1f)
 
             // Send down event, pause, and send up
             val down = MotionEvents.sendDown(uiController, coordinates, precision).down
-            uiController.loopMainThreadForAtLeast(50)
             MotionEvents.sendUp(uiController, down, coordinates)
         }
     }
@@ -157,6 +156,8 @@ class MainActivityTest : ActivityTest() {
 
         assert(report.tests.screenTest)
         assert(!report.tests.touchTest)
+        assert(report.attestation.certificates.isEmpty() != report.attestation.error.isEmpty())
+        assert(report.oldAttestation.isEmpty())
     }
 
     @Test
@@ -229,7 +230,7 @@ class MainActivityTest : ActivityTest() {
                 ByteArray(0),
                 ByteArray(0),
                 authorizationList,
-                authorizationList
+                authorizationList,
             )
 
         val attestationResult = Pair(attestationRecord, AttestationResult.UNVERIFIED)
@@ -239,6 +240,7 @@ class MainActivityTest : ActivityTest() {
     private fun generateConnectionData(challenge: ByteArray): BluetoothConnectionData {
         return BluetoothConnectionData(100, challenge)
     }
+
     private fun generateQrPayload(challenge: ByteArray): String {
         return generateConnectionData(challenge).toString()
     }
diff --git a/DeviceDiagnosticsLib/src/main/Android.bp b/DeviceDiagnosticsLib/src/main/Android.bp
index 11eba54..00eb00b 100644
--- a/DeviceDiagnosticsLib/src/main/Android.bp
+++ b/DeviceDiagnosticsLib/src/main/Android.bp
@@ -28,5 +28,6 @@ android_library {
         "kotlin-reflect",
         "zxing-core-1.7",
         "aconfig_trade_in_mode_flags_java_lib",
+        "tradeinmode_attestation_lib",
     ],
 }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/ApplicationInterface.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/ApplicationInterface.kt
index 4931664..4ddba71 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/ApplicationInterface.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/ApplicationInterface.kt
@@ -56,9 +56,9 @@ open class ApplicationInterface {
 
     open fun verifyAttestation(
         attestation: ByteArray,
-        challenge: ByteArray
+        challenge: ByteArray,
     ): Pair<ParsedAttestationRecord?, AttestationResult> {
-        return getAttestation(attestation, challenge)
+        return checkAttestation(attestation, challenge)
     }
 
     open fun getLaunchLevel(): Int {
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/AttestationController.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/AttestationController.kt
new file mode 100644
index 0000000..fa4f747
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/AttestationController.kt
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.devicediagnostics
+
+import android.app.Activity
+import com.android.devicediagnostics.Protos.DeviceReport
+import com.google.android.attestation.ParsedAttestationRecord
+
+private const val TAG = "Attestation"
+
+class AttestationController(val challenge: ByteArray, val selfCheck: Boolean) {
+    interface Callbacks {
+        fun onAttestationReceived(result: Pair<ParsedAttestationRecord, AttestationResult>)
+
+        fun onAttestationRetry()
+
+        fun onAttestationError()
+    }
+
+    // If "selfCheck" is true, we allow network verification to soft fail.
+    fun verifyAttestation(activity: Activity, report: DeviceReport, callbacks: Callbacks) {
+        // Attestation check does a network lookup, so must be on separate thread
+        runInBackground {
+            var attestation =
+                ApplicationInterface.app.verifyAttestation(
+                    report.attestation.toByteArray(),
+                    challenge,
+                )
+            if (attestation.second == AttestationResult.NETWORK_ERROR && selfCheck)
+                attestation = Pair(attestation.first, AttestationResult.SKIPPED_VERIFICATION)
+
+            activity.runOnUiThread {
+                if (attestation.second == AttestationResult.GENERIC_ERROR) {
+                    callbacks.onAttestationError()
+                } else if (attestation.second == AttestationResult.NETWORK_ERROR) {
+                    callbacks.onAttestationRetry()
+                } else {
+                    callbacks.onAttestationReceived(Pair(attestation.first!!, attestation.second))
+                }
+            }
+        }
+    }
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
index c632fe7..cab3b82 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
@@ -19,6 +19,7 @@ import android.util.Base64
 import com.android.devicediagnostics.Protos.BatteryInfo
 import com.android.devicediagnostics.Protos.DeviceReport
 import com.android.devicediagnostics.Protos.LockInfo
+import com.android.devicediagnostics.Protos.ProductInfo
 import com.android.devicediagnostics.Protos.StorageInfo
 import com.android.devicediagnostics.Protos.TestResults
 import org.json.JSONObject
@@ -58,6 +59,16 @@ private fun batteryInfoToJson(battery: BatteryInfo): JSONObject {
     return obj
 }
 
+private fun productInfoToJson(product: ProductInfo): JSONObject {
+    val obj = JSONObject()
+    obj.putIfPresent(product.hasBrand(), "brand", product.brand)
+    obj.putIfPresent(product.hasDevice(), "device", product.device)
+    obj.putIfPresent(product.hasManufacturer(), "manufacturer", product.manufacturer)
+    obj.putIfPresent(product.hasModel(), "model", product.model)
+    obj.putIfPresent(product.hasName(), "name", product.name)
+    return obj
+}
+
 private fun storageInfoToJson(storage: StorageInfo): JSONObject {
     val obj = JSONObject()
     obj.putIfPresent(
@@ -78,14 +89,23 @@ private fun lockInfoToJson(info: LockInfo): JSONObject {
 fun deviceReportToJson(report: DeviceReport): JSONObject {
     val obj = JSONObject()
     if (report.hasTests()) putIfNotEmpty(obj, "tests", testResultsToJson(report.tests))
-    if (!report.attestation.isEmpty)
-        obj.put(
-            "attestation",
-            Base64.encodeToString(report.attestation.toByteArray(), Base64.DEFAULT),
-        )
+    if (report.hasAttestation()) {
+        val info = JSONObject()
+        if (!report.attestation.certificates.isEmpty) {
+            info.put(
+                "certificates",
+                Base64.encodeToString(report.attestation.certificates.toByteArray(), Base64.DEFAULT),
+            )
+        }
+        if (!report.attestation.error.isEmpty()) {
+            info.put("error", report.attestation.error)
+        }
+        obj.put("attestation", info)
+    }
     if (report.hasBattery()) putIfNotEmpty(obj, "battery", batteryInfoToJson(report.battery))
     if (report.hasStorage()) putIfNotEmpty(obj, "storage", storageInfoToJson(report.storage))
     obj.putIfPresent(report.hasLaunchLevel(), "launch_level", report.launchLevel)
     obj.put("locks", lockInfoToJson(report.locks))
+    if (report.hasProduct()) putIfNotEmpty(obj, "product", productInfoToJson(report.product))
     return obj
 }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DisplayAttestationResultFragment.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DisplayAttestationResultFragment.kt
index 6e6581d..5761955 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DisplayAttestationResultFragment.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DisplayAttestationResultFragment.kt
@@ -20,12 +20,11 @@ import androidx.preference.Preference
 import androidx.preference.PreferenceFragmentCompat
 import com.google.android.attestation.AuthorizationList
 import com.google.android.attestation.ParsedAttestationRecord
-import com.google.android.attestation.RootOfTrust
 import java.util.Optional
 
 class DisplayAttestationResultFragment(
     private val record: ParsedAttestationRecord,
-    private val result: AttestationResult
+    private val result: AttestationResult,
 ) : PreferenceFragmentCompat() {
     override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
         setPreferencesFromResource(R.xml.attestation_details, rootKey)
@@ -48,13 +47,16 @@ class DisplayAttestationResultFragment(
             show("attestation_serial", activity!!.resources.getString(R.string.attestation_failed))
         }
 
-        if (isDeviceLocked()) {
+        if (isDeviceLocked(record)) {
             show("attestation_device_locked", activity!!.resources.getString(R.string.yes))
         } else {
             show("attestation_device_locked", activity!!.resources.getString(R.string.no))
         }
 
-        show("attestation_verified_boot_state", activity!!.resources.getString(getVerifiedBootStateResId(record)))
+        show(
+            "attestation_verified_boot_state",
+            activity!!.resources.getString(getVerifiedBootStateResId(record)),
+        )
         show("attestation_security_level", record.attestationSecurityLevel.name)
         show("attestation_keymaster_version", record.keymasterVersion.toString())
         show("attestation_keymaster_security_level", record.keymasterSecurityLevel.name)
@@ -77,11 +79,6 @@ class DisplayAttestationResultFragment(
         showInt("attestation_boot_patch_level", list.bootPatchLevel)
     }
 
-    private fun isDeviceLocked(): Boolean {
-        val root = record.teeEnforced.rootOfTrust
-        return root.isPresent && root.get().deviceLocked
-    }
-
     private fun showInt(key: String, value: Optional<Int>?) {
         if (value != null && value.isPresent) return show(key, value.get().toString())
     }
@@ -100,12 +97,10 @@ class DisplayAttestationResultFragment(
         findPreference<Preference>(key)!!.isVisible = false
     }
 }
+
 fun getVerifiedBootStateResId(record: ParsedAttestationRecord): Int {
-    val root = record.teeEnforced.rootOfTrust
-    if (
-        root.isPresent && root.get().verifiedBootState == RootOfTrust.VerifiedBootState.VERIFIED
-    ) {
+    if (getVerifiedBootState(record)) {
         return R.string.avb_verified
     }
     return R.string.avb_not_verified
-}
\ No newline at end of file
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EnterEvaluationMode.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EnterEvaluationMode.kt
deleted file mode 100644
index cc0284a..0000000
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EnterEvaluationMode.kt
+++ /dev/null
@@ -1,53 +0,0 @@
-/*
- * Copyright 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      https://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.devicediagnostics
-
-import android.app.Activity
-import android.content.Intent
-import android.os.Bundle
-import android.os.IBinder
-import android.os.ITradeInMode
-import android.os.ServiceManager
-import android.util.Slog
-import com.android.tradeinmode.flags.Flags.enableTradeInMode
-
-class EnterEvaluationMode : Activity() {
-    override fun onCreate(savedInstanceState: Bundle?) {
-        super.onCreate(savedInstanceState)
-
-        if (!enableTradeInMode()) {
-            return
-        }
-
-        var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
-        var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
-        if (!service.isEvaluationModeAllowed()) {
-            Slog.e("EnterEvaluationMode", "Evaluation mode is not allowed on this device.")
-            return
-        }
-
-        if (service.enterEvaluationMode()) {
-            // Dismiss suw
-            val intent = Intent(Intent.ACTION_MAIN)
-            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
-            intent.setAction("com.android.setupwizard.TIM")
-            startActivity(intent)
-        }
-
-        finish()
-    }
-}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt
new file mode 100644
index 0000000..72089bf
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt
@@ -0,0 +1,141 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.android.devicediagnostics
+
+import android.content.ContentProvider
+import android.content.ContentValues
+import android.content.Context
+import android.content.Intent
+import android.database.AbstractCursor
+import android.database.Cursor
+import android.net.Uri
+import android.os.IBinder
+import android.os.ITradeInMode
+import android.os.ServiceManager
+import android.util.Log
+
+private const val TAG = "Evaluate"
+
+class EvaluateContentProvider : ContentProvider() {
+    override fun onCreate(): Boolean {
+        return true
+    }
+
+    override fun query(
+        uri: Uri,
+        projection: Array<out String>?,
+        selection: String?,
+        selectionArgs: Array<out String>?,
+        sortOrder: String?,
+    ): Cursor? {
+        return StatusCursor(context!!, selection)
+    }
+
+    override fun getType(uri: Uri): String? {
+        Log.d(TAG, "Not implemented")
+        return null
+    }
+
+    override fun insert(uri: Uri, values: ContentValues?): Uri? {
+        Log.d(TAG, "Not implemented")
+        return null
+    }
+
+    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
+        Log.d(TAG, "Not implemented")
+        return 0
+    }
+
+    override fun update(
+        uri: Uri,
+        values: ContentValues?,
+        selection: String?,
+        selectionArgs: Array<out String>?,
+    ): Int {
+        Log.d(TAG, "Not implemented")
+        return 0
+    }
+
+    class StatusCursor(val context: Context, val selection: String?) : AbstractCursor() {
+        override fun getCount(): Int {
+            return 1
+        }
+
+        override fun getColumnNames(): Array<String> {
+            return arrayOf("Status")
+        }
+
+        override fun getString(column: Int): String {
+            var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
+            var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
+            if (!service.isEvaluationModeAllowed()) {
+                throw IllegalStateException("Trade-in mode is not available on this device.")
+            }
+
+            if (!service.enterEvaluationMode()) {
+                throw IllegalStateException("Evaluation mode is not available.")
+            }
+
+            if (tryActivityDismissal()) {
+                return ""
+            }
+
+            // Dismiss suw the new way via a broadcast
+            val broadcast = Intent()
+            broadcast.setAction("com.google.android.setupwizard.ENTER_TRADE_IN_MODE")
+            broadcast.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND)
+            context.sendBroadcast(broadcast)
+            return ""
+        }
+
+        private fun tryActivityDismissal(): Boolean {
+            // Dismiss suw the old way via an activity
+            try {
+                val intent = Intent(Intent.ACTION_MAIN)
+                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
+                intent.setAction("com.android.setupwizard.TIM")
+                context.startActivity(intent)
+                return true
+            } catch (e: Exception) {
+                return false
+            }
+        }
+
+        override fun getShort(column: Int): Short {
+            TODO("Not implemented")
+        }
+
+        override fun getInt(column: Int): Int {
+            TODO("Not implemented")
+        }
+
+        override fun getLong(column: Int): Long {
+            TODO("Not implemented")
+        }
+
+        override fun getFloat(column: Int): Float {
+            TODO("Not implemented")
+        }
+
+        override fun getDouble(column: Int): Double {
+            TODO("Not implemented")
+        }
+
+        override fun isNull(column: Int): Boolean {
+            TODO("Not implemented")
+        }
+    }
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
index dfb4608..eb116e5 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
@@ -28,8 +28,8 @@ import com.android.devicediagnostics.Protos.DeviceReport
 import com.android.devicediagnostics.evaluated.createAttestationRecord
 import com.android.devicediagnostics.evaluated.getBatteryInfo
 import com.android.devicediagnostics.evaluated.getLockInfo
+import com.android.devicediagnostics.evaluated.getProductInfo
 import com.android.devicediagnostics.evaluated.getStorageInfo
-import com.google.protobuf.ByteString
 import org.json.JSONArray
 
 private const val TAG = "GetStatus"
@@ -84,6 +84,13 @@ class GetStatusContentProvider : ContentProvider() {
         }
 
         override fun getString(column: Int): String {
+            val challenge: ByteArray
+            if (selection == null) {
+                challenge = ByteArray(0)
+            } else {
+                challenge = selection.toByteArray(Charsets.UTF_8)
+            }
+
             val report =
                 DeviceReport.newBuilder().run {
                     setLocks(getLockInfo(context))
@@ -91,11 +98,8 @@ class GetStatusContentProvider : ContentProvider() {
                         setBattery(getBatteryInfo(context))
                         setStorage(getStorageInfo(context))
                         setLaunchLevel(ApplicationInterface.app.getLaunchLevel())
-                        selection?.run {
-                            setAttestation(
-                                ByteString.copyFrom(createAttestationRecord(toByteArray()))
-                            )
-                        }
+                        setProduct(getProductInfo())
+                        selection?.run { setAttestation(createAttestationRecord(challenge)) }
                     }
                     build()
                 }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/TradeInModeTestingContentProvider.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/TradeInModeTestingContentProvider.kt
new file mode 100644
index 0000000..adf4559
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/TradeInModeTestingContentProvider.kt
@@ -0,0 +1,130 @@
+/*
+ * Copyright 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.devicediagnostics
+
+import android.content.ContentProvider
+import android.content.ContentValues
+import android.content.Context
+import android.database.AbstractCursor
+import android.database.Cursor
+import android.net.Uri
+import android.os.IBinder
+import android.os.ITradeInMode
+import android.os.ServiceManager
+import android.util.Slog
+import com.android.tradeinmode.flags.Flags.enableTradeInMode
+
+private const val TAG = "TradeInMode"
+
+class TradeInModeTestingContentProvider : ContentProvider() {
+    override fun onCreate(): Boolean {
+        return true
+    }
+
+    override fun query(
+        uri: Uri,
+        projection: Array<out String>?,
+        selection: String?,
+        selectionArgs: Array<out String>?,
+        sortOrder: String?,
+    ): Cursor? {
+        return TestingCursor(context!!, selection)
+    }
+
+    override fun getType(uri: Uri): String? {
+        Slog.d(TAG, "Not implemented")
+        return null
+    }
+
+    override fun insert(uri: Uri, values: ContentValues?): Uri? {
+        Slog.d(TAG, "Not implemented")
+        return null
+    }
+
+    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
+        Slog.d(TAG, "Not implemented")
+        return 0
+    }
+
+    override fun update(
+        uri: Uri,
+        values: ContentValues?,
+        selection: String?,
+        selectionArgs: Array<out String>?,
+    ): Int {
+        Slog.d(TAG, "Not implemented")
+        return 0
+    }
+
+    class TestingCursor(val context: Context, val selection: String?) : AbstractCursor() {
+        override fun getCount(): Int {
+            return 1
+        }
+
+        override fun getColumnNames(): Array<String> {
+            return arrayOf("Status")
+        }
+
+        override fun getString(column: Int): String {
+            if (!enableTradeInMode()) {
+                throw Exception("Trade-in mode flag not enabled")
+            }
+
+            var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
+            var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
+            if (selection == "start") {
+                service.startTesting()
+            } else if (selection == "wipe") {
+                service.scheduleWipeForTesting()
+            } else if (selection == "stop") {
+                service.stopTesting()
+            } else if (selection == "status") {
+                if (service.isTesting()) {
+                    return "testing"
+                }
+                return "none"
+            } else {
+                throw Exception("Invalid selection: " + selection)
+            }
+            return "ok"
+        }
+
+        override fun getShort(column: Int): Short {
+            TODO("Not implemented")
+        }
+
+        override fun getInt(column: Int): Int {
+            TODO("Not implemented")
+        }
+
+        override fun getLong(column: Int): Long {
+            TODO("Not implemented")
+        }
+
+        override fun getFloat(column: Int): Float {
+            TODO("Not implemented")
+        }
+
+        override fun getDouble(column: Int): Double {
+            TODO("Not implemented")
+        }
+
+        override fun isNull(column: Int): Boolean {
+            TODO("Not implemented")
+        }
+    }
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/bluetooth/BluetoothHelpers.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/bluetooth/BluetoothHelpers.kt
index 0a77748..d5093f3 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/bluetooth/BluetoothHelpers.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/bluetooth/BluetoothHelpers.kt
@@ -27,7 +27,8 @@ const val BT_READ_SIZE = 4096
 const val BT_MAX_PACKET_SIZE = 1024 * 1024
 const val BT_VERSION = 1
 
-private const val QRCODE_VERSION = 4
+private const val OLDEST_QRCODE_VERSION = 4
+private const val QRCODE_VERSION = 5
 
 private fun readFully(socket: BluetoothSocket, n: Int): ByteArray {
     val b = ByteArray(n)
@@ -70,7 +71,11 @@ fun writeBluetoothPacket(socket: BluetoothSocket, packetBuilder: BluetoothPacket
     socket.outputStream.write(bytes)
 }
 
-class BluetoothConnectionData(val psm: Int = 0, val challenge: ByteArray) {
+class BluetoothConnectionData(
+    val psm: Int = 0,
+    val challenge: ByteArray,
+    val version: Int = QRCODE_VERSION,
+) {
     companion object Helpers {
         private const val JSON_PSM_KEY = "PSM"
         private const val JSON_VERSION_KEY = "version"
@@ -82,13 +87,13 @@ class BluetoothConnectionData(val psm: Int = 0, val challenge: ByteArray) {
             if (obj.has(JSON_VERSION_KEY)) {
                 version = obj.getInt(JSON_VERSION_KEY)
             }
-            if (version < QRCODE_VERSION) {
+            if (version < OLDEST_QRCODE_VERSION) {
                 throw Exception("Unsupported version")
             }
             val psm = obj.getInt(JSON_PSM_KEY)
             val challengeBase64 = obj.getString(JSON_CHALLENGE_KEY)
             val challenge = Base64.decode(challengeBase64, Base64.URL_SAFE)
-            return BluetoothConnectionData(psm, challenge)
+            return BluetoothConnectionData(psm, challenge, version)
         }
     }
 
@@ -96,7 +101,7 @@ class BluetoothConnectionData(val psm: Int = 0, val challenge: ByteArray) {
         val challengeBase64 = Base64.encodeToString(challenge, Base64.URL_SAFE)
         return JSONObject()
             .put(JSON_PSM_KEY, psm)
-            .put(JSON_VERSION_KEY, QRCODE_VERSION)
+            .put(JSON_VERSION_KEY, version)
             .put(JSON_CHALLENGE_KEY, challengeBase64)
             .toString()
     }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/EvaluationFinalizeActivity.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/EvaluationFinalizeActivity.kt
index 7d7570b..4add447 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/EvaluationFinalizeActivity.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/EvaluationFinalizeActivity.kt
@@ -35,7 +35,6 @@ import com.android.devicediagnostics.Protos.DeviceReport
 import com.android.devicediagnostics.R
 import com.android.devicediagnostics.runInBackground
 import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity
-import com.google.protobuf.ByteString
 
 private const val TAG = "EvaluationFinalize"
 
@@ -85,7 +84,15 @@ class EvaluationFinalizeActivity : CollapsingToolbarBaseActivity() {
             val launchLevel = ApplicationInterface.app.getLaunchLevel()
 
             val attestation = createAttestationRecord(state.trustedDevice.challenge.toByteArray())
-            reportBuilder.setAttestation(ByteString.copyFrom(attestation))
+
+            val bluetoothClient = ApplicationInterface.app.getBluetoothClient()
+            val connectionData = bluetoothClient.connectionData
+            if (connectionData != null && connectionData.version == 4) {
+                reportBuilder.setOldAttestation(attestation.certificates)
+            } else {
+                reportBuilder.setAttestation(attestation)
+            }
+
             reportBuilder.setBattery(batteryInfo)
             reportBuilder.setStorage(storageInfo)
             reportBuilder.setLaunchLevel(launchLevel)
@@ -112,7 +119,7 @@ class EvaluationFinalizeActivity : CollapsingToolbarBaseActivity() {
             setReorderingAllowed(true)
             replace(
                 R.id.fragment_container_view,
-                DisplayResultFragment(report, attestationController)
+                DisplayResultFragment(report, attestationController),
             )
         }
     }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/GetAttestation.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/GetAttestation.kt
index eafb78f..8099f6c 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/GetAttestation.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/GetAttestation.kt
@@ -16,19 +16,22 @@
 
 package com.android.devicediagnostics.evaluated
 
+import android.security.KeyStoreException
 import android.security.keystore.KeyGenParameterSpec
 import android.security.keystore.KeyProperties
 import android.util.Log
+import com.android.devicediagnostics.Protos.AttestationInfo
+import com.google.protobuf.ByteString
 import java.nio.ByteBuffer
 import java.security.KeyPairGenerator
 import java.security.KeyStore
 import java.security.spec.ECGenParameterSpec
 
-private const val TAG = "GetAttestation"
+private const val TAG = "Attestation"
 private const val EC_CURVE = "secp256r1"
 private const val KEYSTORE_ALIAS = "attestation_collector_key"
 
-private fun getAttestation(challenge: ByteArray, withImei: Boolean): ByteArray {
+private fun getAttestation(challenge: ByteArray): ByteArray {
     val keyStore = KeyStore.getInstance("AndroidKeyStore")
     keyStore.load(null)
     keyStore.deleteEntry(KEYSTORE_ALIAS)
@@ -40,18 +43,14 @@ private fun getAttestation(challenge: ByteArray, withImei: Boolean): ByteArray {
             .setAttestationChallenge(challenge)
 
     // Use reflection to call this system API so we can still build in Android Studio
-    if (withImei)
-        builder =
-            builder::class
-                .members
-                .firstOrNull { it.name == "setAttestationIds" }
-                ?.call(
-                    builder,
-                    intArrayOf(
-                        1,
-                        2,
-                    ), // AttestationUtils.ID_TYPE_SERIAL, AttestationUtils.ID_TYPE_IMEI
-                ) as KeyGenParameterSpec.Builder
+    builder =
+        builder::class
+            .members
+            .firstOrNull { it.name == "setAttestationIds" }
+            ?.call(
+                builder,
+                intArrayOf(1, 2), // AttestationUtils.ID_TYPE_SERIAL, AttestationUtils.ID_TYPE_IMEI
+            ) as KeyGenParameterSpec.Builder
 
     val spec = builder.build()
 
@@ -69,24 +68,67 @@ private fun getAttestation(challenge: ByteArray, withImei: Boolean): ByteArray {
     return report
 }
 
-fun createAttestationRecord(challenge: ByteArray): ByteArray {
-    // On devices without device IDs provisioned, the above code will throw ProviderException
-    // Continue without this data to support testing other functionality
-    try {
-        return getAttestation(challenge, true)
-    } catch (e: java.security.ProviderException) {
-        Log.e(TAG, "Could not get attestation with IMEI, retrying without: $e")
-    } catch (e: SecurityException) {
-        Log.e(TAG, "Could not get attestation with IMEI, retrying without: $e")
-    } catch (e: Exception) {
-        Log.e(TAG, "Could not create attestation record: $e")
-        return ByteArray(0)
+fun attestationCodeToString(code: Int): String {
+    return when (code) {
+        KeyStoreException.ERROR_ATTESTATION_CHALLENGE_TOO_LARGE -> "Challenge too large"
+        KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE -> "Attestation keys unavailable"
+        KeyStoreException.ERROR_ID_ATTESTATION_FAILURE -> "Device identifier error"
+        KeyStoreException.ERROR_INCORRECT_USAGE -> "Incorrect usage"
+        KeyStoreException.ERROR_INTERNAL_SYSTEM_ERROR -> "Internal system error"
+        KeyStoreException.ERROR_KEYMINT_FAILURE -> "KeyMint error"
+        KeyStoreException.ERROR_KEYSTORE_FAILURE -> "KeyStore error"
+        KeyStoreException.ERROR_KEYSTORE_UNINITIALIZED -> "Keystore is uninitialized"
+        KeyStoreException.ERROR_KEY_CORRUPTED -> "Key is corrupted"
+        KeyStoreException.ERROR_KEY_DOES_NOT_EXIST -> "Key does not exist"
+        KeyStoreException.ERROR_KEY_NOT_TEMPORALLY_VALID -> "Key expired or not yet usable"
+        KeyStoreException.ERROR_KEY_OPERATION_EXPIRED -> "Key operation expired"
+        KeyStoreException.ERROR_PERMISSION_DENIED -> "Permission denied"
+        else -> "Unexpected KeyStore error"
     }
+}
 
+fun createAttestationRecord(challenge: ByteArray): AttestationInfo {
+    val builder = AttestationInfo.newBuilder()
+
+    var certs: ByteArray? = null
+    var exception: Throwable? = null
     try {
-        return getAttestation(challenge, false)
+        certs = getAttestation(challenge)
     } catch (e: Exception) {
-        Log.e(TAG, "Could not create attestation record: $e")
-        return ByteArray(0)
+        exception = e
+    }
+
+    var error: String? = null
+
+    if (exception != null) {
+        Log.e(TAG, "Attestation failed", exception)
+
+        val providerException = exception as java.security.ProviderException?
+        if (providerException != null && providerException.cause != null) {
+            exception = providerException.cause
+            Log.e(TAG, "Provider threw exception", exception)
+        }
+
+        val kse = exception as android.security.KeyStoreException?
+        if (kse != null) {
+            if (
+                kse.isTransientFailure() &&
+                    kse.getRetryPolicy() == KeyStoreException.RETRY_WHEN_CONNECTIVITY_AVAILABLE
+            ) {
+                error = "Network connection needed for attestation"
+            } else {
+                // toString() dumps too much info, so we reduce it.
+                error = attestationCodeToString(kse.numericErrorCode)
+            }
+        }
+    }
+
+    if (certs != null) {
+        builder.setCertificates(ByteString.copyFrom(certs))
+    } else if (error != null) {
+        builder.setError(error)
+    } else {
+        builder.setError(exception!!.message)
     }
+    return builder.build()
 }
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ProductUtilities.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ProductUtilities.kt
new file mode 100644
index 0000000..89ad7e0
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ProductUtilities.kt
@@ -0,0 +1,29 @@
+/*
+ * Copyright 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.android.devicediagnostics.evaluated
+
+import android.os.SystemProperties
+import com.android.devicediagnostics.Protos.ProductInfo
+
+fun getProductInfo(): ProductInfo {
+    val builder = ProductInfo.newBuilder()
+    builder.setBrand(SystemProperties.get("ro.product.brand", ""))
+    builder.setDevice(SystemProperties.get("ro.product.device", ""))
+    builder.setManufacturer(SystemProperties.get("ro.product.manufacturer", ""))
+    builder.setModel(SystemProperties.get("ro.product.model", ""))
+    builder.setName(SystemProperties.get("ro.product.name", ""))
+    return builder.build()
+}
diff --git a/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto b/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
index 5d43f0a..20cbcd4 100644
--- a/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
+++ b/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
@@ -22,54 +22,72 @@ option java_outer_classname = "Protos";
 // When updating this file, update DeviceReportJsonFormatter.kt as well.
 
 message TestResults {
-    optional bool screen_test = 1;
-    optional bool touch_test = 2;
+  optional bool screen_test = 1;
+  optional bool touch_test = 2;
 }
 
 message BatteryInfo {
-    reserved 2, 3;
-    optional int32 cycle_count = 1;
-    optional int32 state_of_health = 4;
-    optional string serial = 5;
-    optional string part_status = 6;
-    int32 legacy_health = 7;
-    optional int64 manufacture_timestamp = 8;
-    optional int64 first_usage_timestamp = 9;
+  reserved 2, 3;
+  optional int32 cycle_count = 1;
+  optional int32 state_of_health = 4;
+  optional string serial = 5;
+  optional string part_status = 6;
+  int32 legacy_health = 7;
+  optional int64 manufacture_timestamp = 8;
+  optional int64 first_usage_timestamp = 9;
 }
 
-message LockInfo {
-    bool factory_reset_protection = 1;
-}
+message LockInfo { bool factory_reset_protection = 1; }
 
 message StorageInfo {
-    reserved 1, 2;
-    optional int32 useful_lifetime_remaining = 3;
-    int64 capacity_bytes = 4;
+  reserved 1, 2;
+  optional int32 useful_lifetime_remaining = 3;
+  int64 capacity_bytes = 4;
 }
 
-message TrustedDeviceInfo {
-    bytes challenge = 1;
+message HingeInfo {
+  optional int32 hinge_count = 1;
+  repeated int32 num_times_folded = 2;
+  repeated int32 expected_lifespan = 3;
 }
 
+message TrustedDeviceInfo { bytes challenge = 1; }
+
 message DeviceReport {
-    TestResults tests = 1;
-    bytes attestation = 2;
-    BatteryInfo battery = 3;
-    StorageInfo storage = 4;
-    optional int32 launch_level = 5;
-    LockInfo locks = 6;
+  TestResults tests = 1;
+  bytes old_attestation = 2;
+  BatteryInfo battery = 3;
+  StorageInfo storage = 4;
+  optional int32 launch_level = 5;
+  LockInfo locks = 6;
+  ProductInfo product = 7;
+  HingeInfo hinge = 8;
+  optional AttestationInfo attestation = 9;
 }
 
 enum PacketCommand {
-    COMMAND_ACK = 0;
-    COMMAND_CLOSE = 1;
+  COMMAND_ACK = 0;
+  COMMAND_CLOSE = 1;
 };
 
 message BluetoothPacket {
-    int32 version = 1;
-    oneof payload {
-        TrustedDeviceInfo trusted_device_info = 2;
-        DeviceReport device_report = 3;
-        PacketCommand command = 4;
-    }
-}
\ No newline at end of file
+  int32 version = 1;
+  oneof payload {
+    TrustedDeviceInfo trusted_device_info = 2;
+    DeviceReport device_report = 3;
+    PacketCommand command = 4;
+  }
+}
+
+message ProductInfo {
+  optional string brand = 1;
+  optional string device = 2;
+  optional string manufacturer = 3;
+  optional string model = 4;
+  optional string name = 5;
+}
+
+message AttestationInfo {
+  bytes certificates = 1;
+  string error = 2;
+}
diff --git a/DeviceDiagnosticsLib/src/main/res/values-bg/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-bg/strings.xml
index d92403f..4e5a5ef 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-bg/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-bg/strings.xml
@@ -84,7 +84,7 @@
     <string name="try_again_button" msgid="6015477950108798246">"Нов опит"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"Резултат от теста за докосване"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"Това е резултатът от теста за докосване. Можете да го проведете отново, като се върнете назад."</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"Тестът на сензора за докосване бе издържан"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"Тестът на сензора за докосване бе успешен"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Тестът на сензора за докосване не бе издържан"</string>
     <string name="pass" msgid="6411665547268368837">"Успешно"</string>
     <string name="fail" msgid="3918028202746427731">"Неуспешно"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
index 65f885f..182f252 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
@@ -82,7 +82,7 @@
     <string name="grant_eval_permissions_dialog" msgid="4732263095697870167">"Dajte zatražena odobrenja da nastavite u načinu rada za procjenu."</string>
     <string name="cancel_button" msgid="7011882021431169180">"Otkaži"</string>
     <string name="try_again_button" msgid="6015477950108798246">"Pokušaj ponovo"</string>
-    <string name="touch_test_result_title" msgid="8236119653054988245">"Rezultat testa senzora za dodir"</string>
+    <string name="touch_test_result_title" msgid="8236119653054988245">"Rezultat testa dodira"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"Ovo je rezultat testa dodira. Vratite se ako želite ponovo izvršiti test."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"Test senzora za dodir je uspio"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Test senzora za dodir nije uspio"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
index 493efd5..170eb4a 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"Al dispositiu que vulguis avaluar, ves a Configuració, Sistema, Diagnòstic del dispositiu, Mode d\'avaluació i Dispositiu avaluat. Segueix les indicacions al dispositiu en qüestió."</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"Ara se\'t mostraran diverses pantalles. Examina-les i cerca els defectes. Quan hagis acabat, toca la pantalla per passar a la següent. Al final, se\'t preguntarà si les pantalles estan impecables."</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"Ara se\'t mostraran diverses pantalles. Examina-les i cerca els defectes. Toca la pantalla per passar a la següent."</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"Selecciona l\'opció que coincideixi millor amb l\'estat de la pantalla."</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"Selecciona l\'opció que descrigui millor l\'estat de la pantalla."</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"Ara se\'t mostrarà una pantalla vermella.\n \n Fes lliscar el dit per la pantalla fins que quedi completament blanca. Si no pots fer que part de la pantalla es torni blanca, toca-la breument per indicar que el sensor tàctil no funciona de manera adequada.\n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-de/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-de/strings.xml
index 0e0bb1d..6ddbb86 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-de/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-de/strings.xml
@@ -29,7 +29,7 @@
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Ein Gerät verwenden, um ein anderes zu bewerten"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Manuelle Tests"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Displaytest"</string>
-    <string name="touch_test_title" msgid="4347784874948129736">"Touchsensortest"</string>
+    <string name="touch_test_title" msgid="4347784874948129736">"Touchsensor-Test"</string>
     <string name="component_title" msgid="6580046234562555655">"Komponentenstatus"</string>
     <string name="storage_title" msgid="5921235202250843966">"Speicherstatus"</string>
     <string name="battery_title" msgid="6707361668941323259">"Akkustatus"</string>
@@ -84,8 +84,8 @@
     <string name="try_again_button" msgid="6015477950108798246">"Noch mal versuchen"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"Ergebnis des Touchsensortests"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"Dies ist das Ergebnis des Touchsensortests. Du kannst den Test wiederholen, indem du zurückgehst."</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"Touchsensortest bestanden"</string>
-    <string name="touch_test_bad_title" msgid="6888320344429184690">"Touchsensortest nicht bestanden"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"Touchsensor-Test bestanden"</string>
+    <string name="touch_test_bad_title" msgid="6888320344429184690">"Touchsensor-Test nicht bestanden"</string>
     <string name="pass" msgid="6411665547268368837">"Bestanden"</string>
     <string name="fail" msgid="3918028202746427731">"Nicht bestanden"</string>
     <string name="attestation_verified" msgid="6535873137799452259">"Verifiziertes Zertifikat"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-es-rUS/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-es-rUS/strings.xml
index d5acc0f..92fe67f 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-es-rUS/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-es-rUS/strings.xml
@@ -84,7 +84,7 @@
     <string name="try_again_button" msgid="6015477950108798246">"Reintentar"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"Resultado de la prueba táctil"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"Este es el resultado de la prueba táctil. Para volver a hacer la prueba, navega hacia atrás."</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"Prueba del sensor táctil realizada correctamente"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"Prueba del sensor táctil exitosa"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Falló la prueba del sensor táctil"</string>
     <string name="pass" msgid="6411665547268368837">"Aprobado"</string>
     <string name="fail" msgid="3918028202746427731">"Reprobado"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
index d72e5ec..9e47287 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
@@ -83,7 +83,7 @@
     <string name="cancel_button" msgid="7011882021431169180">"Cancelar"</string>
     <string name="try_again_button" msgid="6015477950108798246">"Reintentar"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"Resultado de la prueba táctil"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"Este es el resultado de la prueba táctil. Puedes volver a ejecutar la prueba volviendo a la página anterior."</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"Este es el resultado de la prueba táctil. Puedes ejecutar de nuevo la prueba volviendo a la página anterior."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"Prueba del sensor táctil superada"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Prueba del sensor táctil no superada"</string>
     <string name="pass" msgid="6411665547268368837">"Superada"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
index d5d8614..6c50310 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"Sur l\'appareil que vous souhaitez évaluer, sélectionnez \"Paramètres\", \"Système\", \"Diagnostic de l\'appareil\", \"Mode évaluation\", puis \"Appareil évalué\". Suivez les invites sur cet appareil."</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"Une série d\'écrans s\'affiche alors. Étudiez chacun d\'entre eux et recherchez les défauts. Une fois que c\'est fait, touchez l\'écran pour passer à l\'écran suivant. À la fin, on vous demandera si les écrans semblent intacts."</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"Une série d\'écrans va s\'afficher. Étudiez chacun d\'entre eux et recherchez les défauts. Touchez l\'écran pour passer à l\'écran suivant."</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"Veuillez sélectionner l\'option ci-dessous qui correspond le mieux à l\'état de l\'écran."</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"Veuillez sélectionner ci-dessous l\'option qui correspond le mieux à l\'état de l\'écran."</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"Un écran rouge va s\'afficher.\n \nBalayez l\'écran avec votre doigt jusqu\'à ce qu\'il devienne entièrement blanc. Si vous ne parvenez pas à rendre une partie de l\'écran blanche, appuyez brièvement sur l\'écran pour indiquer que le capteur tactile ne fonctionne pas complètement.\n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-gl/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-gl/strings.xml
index 49c464b..c7193b2 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-gl/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-gl/strings.xml
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"No dispositivo que queiras avaliar, vai a Configuración &gt; Sistema &gt; Diagnóstico do dispositivo &gt; Modo de avaliación &gt; Dispositivo avaliado. Sigue as indicacións nese dispositivo."</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"Aparecerá unha serie de pantallas. Revisa cada unha delas en busca de defectos. Cando esteas conforme, toca a pantalla para pasar á seguinte. Ao final, preguntaráseche se as pantallas están perfectas."</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"Aparecerá unha serie de pantallas. Revisa cada unha delas en busca de defectos. Toca a pantalla para pasar á seguinte."</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"Das seguintes opcións, selecciona a que mellor describa a condición da pantalla."</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"Das seguintes opcións, selecciona a que mellor describa o estado da pantalla."</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"Mostraráseche unha pantalla vermella.\n \n Pasa o dedo por toda a pantalla ata que estea completamente branca. Se non es quen de poñer branca unha parte, toca brevemente a pantalla para indicar que o sensor táctil non funciona como é debido.\n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
index 5b5fdca..2bdf857 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
@@ -62,7 +62,7 @@
     <string name="battery_health_title" msgid="3945318982701313271">"બૅટરીની ક્ષમતા"</string>
     <string name="battery_manufacturing_date" msgid="5243620020486093692">"ઉત્પાદનની તારીખ"</string>
     <string name="battery_first_usage_date" msgid="1183985039020984695">"પહેલા વપરાશની તારીખ"</string>
-    <string name="battery_cycle_count" msgid="1002728954996996785">"ચક્રની સંખ્યા"</string>
+    <string name="battery_cycle_count" msgid="1002728954996996785">"ચાર્જિંગ સાઇકલની સંખ્યા"</string>
     <string name="battery_serial_number" msgid="2784394586800439008">"અનુક્રમ નંબર"</string>
     <string name="battery_part_status" msgid="504091754655232085">"બૅટરીના ભાગનું સ્ટેટસ"</string>
     <string name="battery_original" msgid="2552600989411644999">"ઑરિજિનલ"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
index 206ed68..41ef669 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
@@ -82,8 +82,8 @@
     <string name="grant_eval_permissions_dialog" msgid="4732263095697870167">"आकलन करने वाले मोड का इस्तेमाल जारी रखने के लिए, अनुरोध की गई अनुमतियों को मंज़ूरी दें."</string>
     <string name="cancel_button" msgid="7011882021431169180">"रद्द करें"</string>
     <string name="try_again_button" msgid="6015477950108798246">"फिर से कोशिश करें"</string>
-    <string name="touch_test_result_title" msgid="8236119653054988245">"टच टेस्ट का नतीजा"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"यहां टच सेंसर से जुड़ी जांच का नतीजा मौजूद है. आपके पास, वापस जाकर टेस्ट को फिर से चलाने का विकल्प है."</string>
+    <string name="touch_test_result_title" msgid="8236119653054988245">"टच सेंसर की जांच का नतीजा"</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"यहां टच सेंसर से जुड़ी जांच का नतीजा दिया गया है. आपके पास, वापस जाकर टेस्ट को फिर से चलाने का विकल्प है."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"टच सेंसर की जांच सफल रही"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"टच सेंसर की जांच फ़ेल हो गई"</string>
     <string name="pass" msgid="6411665547268368837">"पास"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-iw/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-iw/strings.xml
index 9e16190..bd965f6 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-iw/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-iw/strings.xml
@@ -84,7 +84,7 @@
     <string name="try_again_button" msgid="6015477950108798246">"ניסיון חוזר"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"התוצאה של בדיקת המגע"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"זאת התוצאה של בדיקת המגע. כדי להריץ שוב את הבדיקה, יש לחזור לעמוד הקודם."</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"חיישן המגע עבר את הבדיקה"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"חיישן המגע עבר את הבדיקה בהצלחה"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"חיישן המגע נכשל בבדיקה"</string>
     <string name="pass" msgid="6411665547268368837">"עובר"</string>
     <string name="fail" msgid="3918028202746427731">"הפעולה נכשלה"</string>
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"במכשיר שרוצים לבדוק, עוברים אל \'הגדרות\', \'מערכת\', \'מצב החומרה במכשיר\', \'מצב בדיקה\' ואז \'מכשיר שנבדק\'. פועלים לפי ההנחיות במכשיר."</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"עכשיו תוצג לך סדרה של מסכים. עליך לבחון אותם ולחפש פגמים. בסיום הבדיקה, צריך לגעת במסך כדי לעבור למסך הבא. בסיום, תוצג לך שאלה אם המסכים נקיים מפגמים."</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"עכשיו תוצג לך סדרה של מסכים. עליך לבחון אותם ולחפש פגמים. צריך לגעת במסך כדי לעבור למסך הבא."</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"צריך לבחור מהרשימה הבאה את האפשרות שמתאימה ביותר למצב המסך."</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"צריך לבחור למטה באפשרות שהכי שמתאימה למצב המסך."</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"עכשיו יוצג לך מסך אדום.\n \n עליך להחליק את האצבע על המסך עד שהמסך יהיה לבן לגמרי. אם לא הצלחת להפוך חלק מהמסך ללבן, צריך ללחוץ לחיצה קצרה על המסך כדי לציין שחיישן המגע לא עובד כמו שצריך.\n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
index e5dc21e..01e78b6 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
@@ -29,7 +29,7 @@
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Бір құрылғыны бағалау үшін басқасын пайдаланыңыз."</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Қолмен жүргізілетін сынақтар"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Дисплей сынағы"</string>
-    <string name="touch_test_title" msgid="4347784874948129736">"Сенсорлық сынақ"</string>
+    <string name="touch_test_title" msgid="4347784874948129736">"Сенсорлық датчик сынағы"</string>
     <string name="component_title" msgid="6580046234562555655">"Құрамдас күйі"</string>
     <string name="storage_title" msgid="5921235202250843966">"Жад күйі"</string>
     <string name="battery_title" msgid="6707361668941323259">"Батарея күйі"</string>
@@ -82,8 +82,8 @@
     <string name="grant_eval_permissions_dialog" msgid="4732263095697870167">"Бағалау режимінде жалғастыру үшін қажетті рұқсаттарды беріңіз."</string>
     <string name="cancel_button" msgid="7011882021431169180">"Бас тарту"</string>
     <string name="try_again_button" msgid="6015477950108798246">"Қайталау"</string>
-    <string name="touch_test_result_title" msgid="8236119653054988245">"Сенсорлық сынақтың нәтижесі"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"Бұл — сенсорлық сынақтың нәтижесі. Артқа өту арқылы сынақты қайта жүргізе аласыз."</string>
+    <string name="touch_test_result_title" msgid="8236119653054988245">"Нәтиже"</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"Бұл — сенсорлық датчик сынағының нәтижесі. Артқа өту арқылы сынақты қайта жүргізе аласыз."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"Сенсорлық датчик сынағы сәтті аяқталды"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Сенсорлық датчик сынағы қатемен аяқталды"</string>
     <string name="pass" msgid="6411665547268368837">"Өтті"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ky/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ky/strings.xml
index 09365ef..7938b14 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ky/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ky/strings.xml
@@ -29,7 +29,7 @@
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Бир түзмөктү башка түзмөктүн жардамы менен текшериңиз"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Кол менен аткарылган сыноолор"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Экранды сыноо"</string>
-    <string name="touch_test_title" msgid="4347784874948129736">"Тийүүлөрдү сыноо"</string>
+    <string name="touch_test_title" msgid="4347784874948129736">"Тийүү сенсорун сыноо"</string>
     <string name="component_title" msgid="6580046234562555655">"Компоненттин статусу"</string>
     <string name="storage_title" msgid="5921235202250843966">"Сактагычтын абалы"</string>
     <string name="battery_title" msgid="6707361668941323259">"Батареянын абалы"</string>
@@ -82,7 +82,7 @@
     <string name="grant_eval_permissions_dialog" msgid="4732263095697870167">"Текшерүү режиминде улантуу үчүн суралган уруксаттарды бериңиз."</string>
     <string name="cancel_button" msgid="7011882021431169180">"Жокко чыгаруу"</string>
     <string name="try_again_button" msgid="6015477950108798246">"Кайталоо"</string>
-    <string name="touch_test_result_title" msgid="8236119653054988245">"Тийүүлөрдү сыноонун натыйжасы"</string>
+    <string name="touch_test_result_title" msgid="8236119653054988245">"Тийүү сенсорун сыноо натыйжасы"</string>
     <string name="touch_test_result_summary" msgid="9215663453308287653">"Бул тийүү сенсорун сыноо жыйынтыгы. Артка кайтып, кайра сынап көрсөңүз болот."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"Тийүү сенсору сыноодон өттү"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Сыналган жок"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-mr/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-mr/strings.xml
index ea2cf42..8be4964 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-mr/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-mr/strings.xml
@@ -28,7 +28,7 @@
     <string name="evaluation_mode_title" msgid="5845218248059550975">"मूल्यांकन मोड"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"एका डिव्हाइसचे मूल्यांकन करण्यासाठी दुसरे डिव्हाइस वापरा"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"मॅन्युअल चाचण्या"</string>
-    <string name="screen_test_title" msgid="2748510049598105155">"चाचणी प्रदर्शित करा"</string>
+    <string name="screen_test_title" msgid="2748510049598105155">"डिस्प्लेची चाचणी"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"स्पर्श चाचणी"</string>
     <string name="component_title" msgid="6580046234562555655">"घटकाचे स्टेटस"</string>
     <string name="storage_title" msgid="5921235202250843966">"स्टोरेजचे स्टेटस"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
index 6526f5d..facaf47 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"အကဲဖြတ်မည့် စက်ပေါ်တွင် ဆက်တင်များ၊ စနစ်၊ စက်၏ ပြဿနာ ရှာဖွေဖော်ထုတ်ခြင်း၊ အကဲဖြတ်ခြင်း မုဒ်၊ ထို့နောက် အကဲဖြတ်နေသည့်စက် သို့သွားပါ။ ထိုစက်ပေါ်ရှိ တိုက်တွန်းချက်များအတိုင်း လုပ်ဆောင်ပါ။"</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"ယခု သင့်အား စခရင်များကို အတွဲလိုက် ပြပါမည်။ စခရင်တစ်ခုစီကို လေ့လာ၍ ချွတ်ယွင်းချက်များ ရှာဖွေပါ။ စိတ်ကျေနပ်သည်နှင့် စခရင်ကို ထိ၍ နောက်တစ်ခုသို့ ရွှေ့ပါ။ နောက်ဆုံးတွင် စခရင်များ ချွတ်ယွင်းချက်ရှိပုံ ရ၊ မရ သင့်ကို မေးပါမည်။"</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"ယခု သင့်အား စခရင်များကို အတွဲလိုက် ပြပါမည်။ စခရင်တစ်ခုစီကို လေ့လာ၍ ချွတ်ယွင်းချက်များ ရှာဖွေပါ။ စခရင်ကို ထိ၍ နောက်တစ်ခုသို့ ရွှေ့ပါ။"</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"စခရင်အခြေအနေနှင့် အကိုက်ညီဆုံးဖြစ်သည့် တစ်ခုကို အောက်တွင် ရွေးပါ။"</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"စခရင်အခြေအနေအား အနီးစပ်ဆုံးဖော်ပြချက်ကို အောက်တွင် ရွေးပါ။"</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"ယခု သင့်အား အနီရောင်စခရင် ပြပါမည်။\n \n စခရင်တစ်ခုလုံး ဖြူသွားသည်အထိ သင့်လက်ချောင်းဖြင့် စခရင်ကို ပွတ်ဆွဲပါ။ စခရင် တစ်စိတ်တစ်ပိုင်းကို ဖြူအောင်မပြောင်းနိုင်ပါက ထိတွေ့မှု အာရုံခံကိရိယာ အပြည့်အဝ အလုပ်မလုပ်ကြောင်း ဖော်ပြရန် စခရင်ကို အမြန်တစ်ချက်တို့ပါ။ \n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ne/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ne/strings.xml
index 3da2248..3f97b4d 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ne/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ne/strings.xml
@@ -28,8 +28,8 @@
     <string name="evaluation_mode_title" msgid="5845218248059550975">"मूल्याङ्कन मोड"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"एउटा डिभाइस मूल्याङ्कन गर्न अर्को डिभाइस प्रयोग गर्नुहोस्"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"म्यानुअल परीक्षणहरू"</string>
-    <string name="screen_test_title" msgid="2748510049598105155">"डिस्प्लेसम्बन्धी परीक्षण"</string>
-    <string name="touch_test_title" msgid="4347784874948129736">"टचसम्बन्धी परीक्षण"</string>
+    <string name="screen_test_title" msgid="2748510049598105155">"डिस्प्ले परीक्षण"</string>
+    <string name="touch_test_title" msgid="4347784874948129736">"टच परीक्षण"</string>
     <string name="component_title" msgid="6580046234562555655">"कम्पोनेन्टको स्थिति"</string>
     <string name="storage_title" msgid="5921235202250843966">"भण्डारणको स्थिति"</string>
     <string name="battery_title" msgid="6707361668941323259">"ब्याट्रीको स्थिति"</string>
@@ -83,9 +83,9 @@
     <string name="cancel_button" msgid="7011882021431169180">"रद्द गर्नुहोस्"</string>
     <string name="try_again_button" msgid="6015477950108798246">"फेरि प्रयास गर्नुहोस्"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"टचसम्बन्धी परीक्षणको परिणाम"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"यो टचसम्बन्धी परीक्षणको परिणाम हो। तपाईं पछाडि गएर फेरि यो परीक्षण गर्न सक्नुहुन्छ।"</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"टच सेन्सरसम्बन्धी परीक्षण पास भएको छ"</string>
-    <string name="touch_test_bad_title" msgid="6888320344429184690">"टच सेन्सरसम्बन्धी परीक्षण फेल भएको छ"</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"यो टच परीक्षणको परिणाम हो। तपाईं पछाडि गएर फेरि यो परीक्षण गर्न सक्नुहुन्छ।"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"टच सेन्सर परीक्षण पास भएको छ"</string>
+    <string name="touch_test_bad_title" msgid="6888320344429184690">"टच सेन्सर परीक्षण फेल भएको छ"</string>
     <string name="pass" msgid="6411665547268368837">"पास"</string>
     <string name="fail" msgid="3918028202746427731">"फेल"</string>
     <string name="attestation_verified" msgid="6535873137799452259">"पुष्टि गरिएको प्रमाणपत्र"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-pl/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-pl/strings.xml
index 787c66d..0d85906 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-pl/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-pl/strings.xml
@@ -83,7 +83,7 @@
     <string name="cancel_button" msgid="7011882021431169180">"Anuluj"</string>
     <string name="try_again_button" msgid="6015477950108798246">"Spróbuj ponownie"</string>
     <string name="touch_test_result_title" msgid="8236119653054988245">"Wynik testu dotyku"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"Oto wynik testu dotyku. Możesz ponownie go uruchomić, przechodząc wstecz."</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"Oto wynik testu czujnika dotykowego. Aby uruchomić test ponownie, przejdź wstecz."</string>
     <string name="touch_test_good_title" msgid="4008967693136685770">"Test czujnika dotykowego się powiódł"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"Test czujnika dotykowego się nie powiódł"</string>
     <string name="pass" msgid="6411665547268368837">"Test udany"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-pt-rBR/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-pt-rBR/strings.xml
index dbd5813..03692ef 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-pt-rBR/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-pt-rBR/strings.xml
@@ -52,7 +52,7 @@
     <string name="evaluation_complete_title" msgid="2503185542217582851">"Avaliação concluída"</string>
     <string name="evaluation_complete_summary" msgid="1899365605498435450">"Os resultados agora vão aparecer no dispositivo de confiança"</string>
     <string name="screen_test_result_title" msgid="4741510800317631056">"Resultado do teste de tela"</string>
-    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Bom"</string>
+    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Boa"</string>
     <string name="screen_test_good_result_summary" msgid="1995033654279054797">"Não há defeitos aparentes"</string>
     <string name="screen_test_bad_result_title" msgid="2287969677501836657">"Ruim"</string>
     <string name="screen_test_bad_result_summary" msgid="2826928400358426952">"A tela tem defeitos"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-pt-rPT/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-pt-rPT/strings.xml
index dfd7e89..3207eea 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-pt-rPT/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-pt-rPT/strings.xml
@@ -52,7 +52,7 @@
     <string name="evaluation_complete_title" msgid="2503185542217582851">"Avaliação concluída"</string>
     <string name="evaluation_complete_summary" msgid="1899365605498435450">"Os resultados aparecem agora no dispositivo fidedigno"</string>
     <string name="screen_test_result_title" msgid="4741510800317631056">"Resultado do teste do ecrã"</string>
-    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Bom"</string>
+    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Boa qualidade"</string>
     <string name="screen_test_good_result_summary" msgid="1995033654279054797">"Nenhum defeito evidente"</string>
     <string name="screen_test_bad_result_title" msgid="2287969677501836657">"Má qualidade"</string>
     <string name="screen_test_bad_result_summary" msgid="2826928400358426952">"O ecrã apresenta defeitos"</string>
@@ -139,6 +139,6 @@
     <string name="trusted_scan_now_summary" msgid="578587921199486348">"No dispositivo que quer avaliar, aceda a Definições, Sistema, Diagnóstico do dispositivo, Modo de avaliação e Dispositivo avaliado. Siga as instruções nesse dispositivo."</string>
     <string name="screen_test_summary" msgid="6565006807310186664">"Agora, vai ver uma série de ecrãs. Analise cada um deles e procure defeitos. Quando terminar, toque no ecrã para passar ao próximo. No fim, é-lhe perguntado se os ecrãs estão imaculados."</string>
     <string name="screen_test_summary_one_shot" msgid="7447685087916591748">"Agora, vai ver uma série de ecrãs. Analise cada um deles e procure defeitos. Toque no ecrã para passar ao próximo."</string>
-    <string name="screen_test_finalize" msgid="9147123495799275930">"Selecione a opção abaixo que melhor corresponde à condição do ecrã."</string>
+    <string name="screen_test_finalize" msgid="9147123495799275930">"Selecione a opção abaixo que melhor corresponde ao estado do ecrã."</string>
     <string name="touch_test_summary" msgid="5989536270591433560">"Agora, vai ver um ecrã vermelho.\n \n Deslize o dedo no ecrã até que este fique totalmente branco. Se não conseguir que uma parte do ecrã fique branca, toque brevemente no ecrã para indicar que o sensor tátil não está a funcionar totalmente.\n \n"</string>
 </resources>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-pt/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-pt/strings.xml
index dbd5813..03692ef 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-pt/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-pt/strings.xml
@@ -52,7 +52,7 @@
     <string name="evaluation_complete_title" msgid="2503185542217582851">"Avaliação concluída"</string>
     <string name="evaluation_complete_summary" msgid="1899365605498435450">"Os resultados agora vão aparecer no dispositivo de confiança"</string>
     <string name="screen_test_result_title" msgid="4741510800317631056">"Resultado do teste de tela"</string>
-    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Bom"</string>
+    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Boa"</string>
     <string name="screen_test_good_result_summary" msgid="1995033654279054797">"Não há defeitos aparentes"</string>
     <string name="screen_test_bad_result_title" msgid="2287969677501836657">"Ruim"</string>
     <string name="screen_test_bad_result_summary" msgid="2826928400358426952">"A tela tem defeitos"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-sk/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-sk/strings.xml
index c579fa4..2c01e36 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-sk/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-sk/strings.xml
@@ -52,9 +52,9 @@
     <string name="evaluation_complete_title" msgid="2503185542217582851">"Hodnotenie bolo dokončené"</string>
     <string name="evaluation_complete_summary" msgid="1899365605498435450">"Výsledky sa teraz budú zobrazovať v dôveryhodnom zariadení"</string>
     <string name="screen_test_result_title" msgid="4741510800317631056">"Výsledok testu obrazovky"</string>
-    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Dobré"</string>
+    <string name="screen_test_good_result_title" msgid="8032695232528965724">"Dobrý výsledok"</string>
     <string name="screen_test_good_result_summary" msgid="1995033654279054797">"Žiadne očividné chyby"</string>
-    <string name="screen_test_bad_result_title" msgid="2287969677501836657">"Zlé"</string>
+    <string name="screen_test_bad_result_title" msgid="2287969677501836657">"Zlý výsledok"</string>
     <string name="screen_test_bad_result_summary" msgid="2826928400358426952">"Obrazovka má chyby"</string>
     <string name="manual_testing_title" msgid="4512384040828953255">"Manuálne testovanie"</string>
     <string name="visual_test_warning_summary" msgid="8088295720348050370">"Nasledujúci test vyžaduje vizuálnu kontrolu a potvrdenie fyzickej obrazovky. Naozaj chcete pokračovať?"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
index 7a4ca4c..9e62e9e 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
@@ -29,7 +29,7 @@
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"ஒரு சாதனத்தைப் பயன்படுத்தி மற்றொரு சாதனத்தை மதிப்பிடவும்"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"நேரடிப் பரிசோதனைகள்"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"டிஸ்ப்ளே பரிசோதனை"</string>
-    <string name="touch_test_title" msgid="4347784874948129736">"தொடும் பரிசோதனை"</string>
+    <string name="touch_test_title" msgid="4347784874948129736">"டச் சென்சார் பரிசோதனை"</string>
     <string name="component_title" msgid="6580046234562555655">"பாகங்களின் நிலை"</string>
     <string name="storage_title" msgid="5921235202250843966">"சேமிப்பகத்தின் நிலை"</string>
     <string name="battery_title" msgid="6707361668941323259">"பேட்டரி நிலை"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-vi/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-vi/strings.xml
index ad9beac..a22b412 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-vi/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-vi/strings.xml
@@ -103,7 +103,7 @@
     <string name="attestation_second_imei" msgid="7566064584445017361">"Số IMEI thứ hai"</string>
     <string name="attestation_meid" msgid="6837237287403480594">"MEID"</string>
     <string name="attestation_manufacturer" msgid="2043278400561674518">"Nhà sản xuất"</string>
-    <string name="attestation_model" msgid="8223243376214262662">"Mẫu"</string>
+    <string name="attestation_model" msgid="8223243376214262662">"Kiểu máy"</string>
     <string name="attestation_vendor_patch_level" msgid="5961013660410857720">"Cấp độ bản vá của nhà cung cấp"</string>
     <string name="attestation_boot_patch_level" msgid="6266071138457400006">"Cấp độ bản vá của trình khởi động"</string>
     <string name="yes" msgid="6686215078709381643">"Có"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-zh-rCN/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-zh-rCN/strings.xml
index 0dd3001..67ebed9 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-zh-rCN/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-zh-rCN/strings.xml
@@ -82,9 +82,9 @@
     <string name="grant_eval_permissions_dialog" msgid="4732263095697870167">"请授予必要权限，以便继续使用评估模式。"</string>
     <string name="cancel_button" msgid="7011882021431169180">"取消"</string>
     <string name="try_again_button" msgid="6015477950108798246">"请重试"</string>
-    <string name="touch_test_result_title" msgid="8236119653054988245">"触摸测试结果"</string>
-    <string name="touch_test_result_summary" msgid="9215663453308287653">"这是触摸测试的结果。您可以返回并重新运行测试。"</string>
-    <string name="touch_test_good_title" msgid="4008967693136685770">"已通过触摸传感器测试"</string>
+    <string name="touch_test_result_title" msgid="8236119653054988245">"触控测试结果"</string>
+    <string name="touch_test_result_summary" msgid="9215663453308287653">"这是触控测试的结果。您可以返回并重新运行测试。"</string>
+    <string name="touch_test_good_title" msgid="4008967693136685770">"已通过触控传感器测试"</string>
     <string name="touch_test_bad_title" msgid="6888320344429184690">"未通过触摸传感器测试"</string>
     <string name="pass" msgid="6411665547268368837">"通过"</string>
     <string name="fail" msgid="3918028202746427731">"未通过"</string>
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index cba4f08..e8d96ee 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -7,7 +7,7 @@ ktfmt = --kotlinlang-style
 
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
-ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
+ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES} --disabled-rules standard:filename
 
 [Tool Paths]
 ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/app/src/main/AndroidManifest.xml b/app/src/main/AndroidManifest.xml
index 2dadfae..d0caae6 100644
--- a/app/src/main/AndroidManifest.xml
+++ b/app/src/main/AndroidManifest.xml
@@ -17,6 +17,7 @@
   <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
   <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
   <uses-permission android:name="android.permission.ENTER_TRADE_IN_MODE"/>
+  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
 
   <application
       android:icon="@mipmap/ic_launcher"
@@ -26,10 +27,22 @@
       android:theme="@style/Theme.DeviceDiagnostics">
     <provider
         android:name="com.android.devicediagnostics.GetStatusContentProvider"
-        android:authorities="com.android.devicediagnostics"
+        android:authorities="com.android.devicediagnostics.GetStatusContentProvider"
         android:enabled="true"
         android:exported="true"
         android:permission="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
+    <provider
+        android:name="com.android.devicediagnostics.TradeInModeTestingContentProvider"
+        android:authorities="com.android.devicediagnostics.TradeInModeTestingContentProvider"
+        android:enabled="true"
+        android:exported="true"
+        android:permission="android.permission.ENTER_TRADE_IN_MODE"/>
+    <provider
+        android:name="com.android.devicediagnostics.EvaluateContentProvider"
+        android:authorities="com.android.devicediagnostics.EvaluateContentProvider"
+        android:enabled="true"
+        android:exported="true"
+        android:permission="android.permission.ENTER_TRADE_IN_MODE"/>
     <activity
         android:name="com.android.devicediagnostics.MainActivity"
         android:exported="true">
@@ -67,9 +80,6 @@
               android:taskAffinity="com.android.devicediagnostics.evaluated" />
     <activity android:name="com.android.devicediagnostics.BatteryActivity" />
     <activity android:name="com.android.devicediagnostics.StorageActivity" />
-    <activity android:name="com.android.devicediagnostics.EnterEvaluationMode"
-              android:exported="true"
-              android:theme="@android:style/Theme.NoDisplay" />
     <receiver android:name="com.android.devicediagnostics.BootCompleteReceiver"
         android:exported="true">
       <intent-filter>
diff --git a/tradeinmode/Android.bp b/tradeinmode/Android.bp
index 4b377aa..3c301c9 100644
--- a/tradeinmode/Android.bp
+++ b/tradeinmode/Android.bp
@@ -26,10 +26,34 @@ prebuilt_etc {
 
 java_binary {
     name: "tradeinmode",
-    srcs: ["src/**/*.kt"],
+    srcs: ["src/**/Commands.kt"],
     main_class: "com.android.devicediagnostics.commands.Commands",
     required: ["tradeinmode.rc"],
     dex_preopt: {
         enabled: false,
     },
 }
+
+java_library {
+    name: "tradeinmode_attestation_lib",
+    srcs: [
+        "src/com/android/devicediagnostics/AttestationHelpers.kt",
+    ],
+    libs: [
+        "android-key-attestation",
+    ],
+    host_supported: true,
+}
+
+java_binary_host {
+    name: "parse_tim_attestation",
+    srcs: ["src/**/AttestationCli.kt"],
+    main_class: "com.android.devicediagnostics.commands.AttestationCli",
+    static_libs: [
+        "android-key-attestation",
+        "gson",
+        "guava",
+        "json-prebuilt",
+        "tradeinmode_attestation_lib",
+    ],
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/KeyAttestationParser.kt b/tradeinmode/src/com/android/devicediagnostics/AttestationHelpers.kt
similarity index 51%
rename from DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/KeyAttestationParser.kt
rename to tradeinmode/src/com/android/devicediagnostics/AttestationHelpers.kt
index bfe64f4..3140146 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/KeyAttestationParser.kt
+++ b/tradeinmode/src/com/android/devicediagnostics/AttestationHelpers.kt
@@ -1,10 +1,11 @@
-/* Copyright 2016, The Android Open Source Project, Inc.
+/*
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
- *   http://www.apache.org/licenses/LICENSE-2.0
+ *      http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
@@ -14,12 +15,10 @@
  */
 package com.android.devicediagnostics
 
-import android.app.Activity
-import android.util.Log
-import com.android.devicediagnostics.Protos.DeviceReport
 import com.google.android.attestation.CertificateRevocationStatus
 import com.google.android.attestation.Constants
 import com.google.android.attestation.ParsedAttestationRecord
+import com.google.android.attestation.RootOfTrust
 import com.google.common.collect.ImmutableList
 import java.io.ByteArrayInputStream
 import java.io.IOException
@@ -29,28 +28,6 @@ import java.security.cert.CertificateFactory
 import java.security.cert.X509Certificate
 import org.bouncycastle.util.encoders.Base64
 
-private const val TAG = "Attestation"
-
-/**
- * This is an illustration of how you can use the Bouncy Castle ASN.1 parser to extract information
- * from an Android attestation data structure. On a secure server that you trust, create similar
- * logic to verify that a key pair has been generated in an Android device. The app on the device
- * must retrieve the key's certificate chain using KeyStore.getCertificateChain(), then send the
- * contents to the trusted server.
- *
- * In this example, the certificate chain includes hard-coded excerpts of each certificate.
- *
- * This example demonstrates the following tasks:
- * 1. Loading the certificates from PEM-encoded strings.
- * 2. Verifying the certificate chain, up to the root. Note that this example does NOT require the
- *    root certificate to appear within Google's list of root certificates. However, if you're
- *    verifying the properties of hardware-backed keys on a device that ships with hardware-level
- *    key attestation, Android 7.0 (API level 24) or higher, and Google Play services, your
- *    production code should enforce this requirement.
- * 3. Checking if any certificate in the chain has been revoked or suspended.
- * 4. Extracting the attestation extension data from the attestation certificate.
- * 5. Verifying (and printing) several important data elements from the attestation extension.
- */
 enum class AttestationResult {
     // There was a non-network error performing attestation.
     GENERIC_ERROR,
@@ -60,47 +37,17 @@ enum class AttestationResult {
     UNVERIFIED,
     // No attempt was made to verify the certificate.
     SKIPPED_VERIFICATION,
+    // Certificate was verified but the challenge was incorrect.
+    BAD_CHALLENGE,
     // The certificate was verified.
     VERIFIED,
 }
 
-class AttestationController(val challenge: ByteArray, val selfCheck: Boolean) {
-    interface Callbacks {
-        fun onAttestationReceived(result: Pair<ParsedAttestationRecord, AttestationResult>)
-
-        fun onAttestationRetry()
-
-        fun onAttestationError()
-    }
-
-    // If "selfCheck" is true, we allow network verification to soft fail.
-    fun verifyAttestation(activity: Activity, report: DeviceReport, callbacks: Callbacks) {
-        // Attestation check does a network lookup, so must be on separate thread
-        runInBackground {
-            var attestation =
-                ApplicationInterface.app.verifyAttestation(
-                    report.attestation.toByteArray(),
-                    challenge,
-                )
-            if (attestation.second == AttestationResult.NETWORK_ERROR && selfCheck)
-                attestation = Pair(attestation.first, AttestationResult.SKIPPED_VERIFICATION)
-
-            activity.runOnUiThread {
-                if (attestation.second == AttestationResult.GENERIC_ERROR) {
-                    callbacks.onAttestationError()
-                } else if (attestation.second == AttestationResult.NETWORK_ERROR) {
-                    callbacks.onAttestationRetry()
-                } else {
-                    callbacks.onAttestationReceived(Pair(attestation.first!!, attestation.second))
-                }
-            }
-        }
-    }
-}
-
-fun getAttestation(
+// Verify a device's attestation record. If a challenge is provided, verify the
+// challenge as well.
+public fun checkAttestation(
     attestation: ByteArray,
-    challenge: ByteArray,
+    challenge: ByteArray?,
 ): Pair<ParsedAttestationRecord?, AttestationResult> {
     var certs: ImmutableList<X509Certificate>?
     var record: ParsedAttestationRecord? = null
@@ -108,16 +55,15 @@ fun getAttestation(
     try {
         certs = loadCertificates(attestation)
         record = ParsedAttestationRecord.createParsedAttestationRecord(certs)
-        if (verifyCertificateChain(certs)) {
-            if (record.attestationChallenge.contentEquals(challenge)) {
-                return Pair(record, AttestationResult.VERIFIED)
-            }
-            Log.e(TAG, "Attestation failed: challenge does not match")
+        if (!verifyCertificateChain(certs)) {
+            return Pair(record, AttestationResult.UNVERIFIED)
         }
-        return Pair(record, AttestationResult.UNVERIFIED)
+        if (challenge != null && !record.attestationChallenge.contentEquals(challenge)) {
+            return Pair(record, AttestationResult.BAD_CHALLENGE)
+        }
+        return Pair(record, AttestationResult.VERIFIED)
     } catch (e: Exception) {
         // Note: set record so we can distinguish between parsing errors and network errors.
-        Log.e(TAG, "Attestation failed: $e")
         if (record != null && e is IOException) {
             return Pair(record, AttestationResult.NETWORK_ERROR)
         }
@@ -125,6 +71,19 @@ fun getAttestation(
     }
 }
 
+public fun isDeviceLocked(record: ParsedAttestationRecord): Boolean {
+    val root = record.teeEnforced.rootOfTrust
+    return root.isPresent && root.get().deviceLocked
+}
+
+public fun getVerifiedBootState(record: ParsedAttestationRecord): Boolean {
+    val root = record.teeEnforced.rootOfTrust
+    if (root.isPresent && root.get().verifiedBootState == RootOfTrust.VerifiedBootState.VERIFIED) {
+        return true
+    }
+    return false
+}
+
 private fun verifyCertificateChain(certs: List<X509Certificate>): Boolean {
     var parent = certs[certs.size - 1]
     for (i in certs.indices.reversed()) {
diff --git a/tradeinmode/src/com/android/devicediagnostics/commands/AttestationCli.kt b/tradeinmode/src/com/android/devicediagnostics/commands/AttestationCli.kt
new file mode 100644
index 0000000..ecb0d55
--- /dev/null
+++ b/tradeinmode/src/com/android/devicediagnostics/commands/AttestationCli.kt
@@ -0,0 +1,206 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.devicediagnostics.commands
+
+import com.android.devicediagnostics.AttestationResult
+import com.android.devicediagnostics.checkAttestation
+import com.android.devicediagnostics.getVerifiedBootState
+import com.android.devicediagnostics.isDeviceLocked
+import com.google.android.attestation.AuthorizationList
+import com.google.android.attestation.ParsedAttestationRecord
+import com.google.common.io.CharStreams
+import java.io.InputStream
+import java.io.InputStreamReader
+import java.nio.charset.StandardCharsets
+import java.nio.file.Files
+import java.nio.file.Paths
+import java.util.Optional
+import kotlin.system.exitProcess
+import org.bouncycastle.util.encoders.Base64
+import org.json.JSONArray
+import org.json.JSONObject
+
+private class Tokenizer(private val args: Array<String>) {
+    private var cursor = 0
+
+    fun next(): String? {
+        if (cursor >= args.size) return null
+        return args[cursor++]
+    }
+
+    fun more(): Boolean {
+        return cursor < args.size
+    }
+}
+
+class AttestationCli {
+    companion object {
+        @JvmStatic
+        fun main(args: Array<String>) {
+            try {
+                doMain(Tokenizer(args))
+            } catch (e: Exception) {
+                System.err.println("Error: $e")
+                exitProcess(1)
+            }
+        }
+    }
+}
+
+private fun doMain(args: Tokenizer) {
+    var challenge: ByteArray? = null
+
+    var path = args.next()
+    if (path == "--challenge") {
+        val challengeString = args.next()
+        if (challengeString == null) {
+            throw IllegalArgumentException("Expected challenge string")
+        }
+
+        challenge = challengeString.toByteArray(StandardCharsets.UTF_8)
+        path = args.next()
+    }
+
+    var stream: InputStream?
+    if (path != null) {
+        stream = Files.newInputStream(Paths.get(path))
+    } else {
+        stream = System.`in`
+    }
+
+    val text = CharStreams.toString(InputStreamReader(stream, Charsets.UTF_8))
+    val root = JSONObject(text)
+    if (!root.has("attestation")) {
+        throw IllegalArgumentException("No attestation record was found")
+    }
+    var attestation = root.getJSONObject("attestation")
+    if (!attestation.has("certificates")) {
+        throw IllegalArgumentException("No attestation record was found")
+    }
+
+    val encodedData = attestation.getString("certificates")
+    if (encodedData.isEmpty()) {
+        throw IllegalArgumentException("No attestation record was found")
+    }
+
+    val decodedData = java.util.Base64.getMimeDecoder().decode(encodedData)
+    val result = checkAttestation(decodedData, null)
+    val output = JSONObject()
+    output.put("certificate", result.second.toString().lowercase())
+    output.put("record", recordToJson(result.first))
+    output.put("trustworthy", getTrustworthiness(result.first, result.second, challenge))
+    println(output.toString(2))
+}
+
+private fun recordToJson(record: ParsedAttestationRecord?): JSONObject? {
+    if (record == null) {
+        return null
+    }
+
+    val root = JSONObject()
+    root.put("bootloader_locked", isDeviceLocked(record))
+    root.put("verified_boot", getVerifiedBootState(record))
+    root.put("security_level", record.attestationSecurityLevel.name)
+    root.put("keymaster_version", record.keymasterVersion.toString())
+    root.put("keymaster_security_level", record.keymasterSecurityLevel.name)
+
+    var attrs = authorizationListToJson(record.teeEnforced)
+    if (attrs != null) {
+        attrs.put("source", "hardware")
+    } else {
+        attrs = authorizationListToJson(record.softwareEnforced)
+        if (attrs != null) {
+            attrs.put("source", "software")
+        }
+    }
+    root.put("attributes", attrs)
+
+    return root
+}
+
+private fun authorizationListToJson(list: AuthorizationList?): JSONObject? {
+    if (list == null) {
+        return null
+    }
+
+    val root = JSONObject()
+    putOptionalInt(root, "os_version", list.osVersion)
+    putOptionalString(root, "brand", list.attestationIdBrand)
+    putOptionalString(root, "device", list.attestationIdDevice)
+    putOptionalString(root, "product", list.attestationIdProduct)
+    putOptionalString(root, "serial", list.attestationIdSerial)
+    putOptionalString(root, "meid", list.attestationIdMeid)
+    putOptionalString(root, "manufacturer", list.attestationIdManufacturer)
+    putOptionalString(root, "model", list.attestationIdModel)
+    putOptionalInt(root, "vendor_patch_level", list.vendorPatchLevel)
+    putOptionalInt(root, "boot_patch_level", list.bootPatchLevel)
+
+    val imeis = JSONArray()
+    putOptionalString(imeis, list.attestationIdImei)
+    putOptionalString(imeis, list.attestationIdSecondImei)
+    if (imeis.length() > 0) {
+        root.put("imeis", imeis)
+    }
+
+    if (root.length() == 0) {
+        return null
+    }
+    return root
+}
+
+private fun getTrustworthiness(
+    record: ParsedAttestationRecord?,
+    result: AttestationResult,
+    challenge: ByteArray?,
+): String {
+    if (record == null || result != AttestationResult.VERIFIED) {
+        return "unverified certificate"
+    }
+    if (challenge != null && !record.attestationChallenge.contentEquals(challenge)) {
+        return "bad challenge"
+    }
+    if (!getVerifiedBootState(record)) {
+        return "verified boot disabled"
+    }
+    if (!isDeviceLocked(record)) {
+        return "bootloader unlocked"
+    }
+    if (challenge == null) {
+        return "no challenge"
+    }
+    return "yes"
+}
+
+private fun putOptionalString(list: JSONArray, value: Optional<ByteArray>?) {
+    if (value == null || !value.isPresent) {
+        return
+    }
+    list.put(value.get().toString(Charsets.UTF_8))
+}
+
+private fun putOptionalString(root: JSONObject, key: String, value: Optional<ByteArray>?) {
+    if (value == null || !value.isPresent) {
+        return
+    }
+    root.put(key, value.get().toString(Charsets.UTF_8))
+}
+
+private fun putOptionalInt(root: JSONObject, key: String, value: Optional<Int>?) {
+    if (value == null || !value.isPresent) {
+        return
+    }
+    root.put(key, value.get())
+}
diff --git a/tradeinmode/src/com/android/devicediagnostics/commands/Commands.kt b/tradeinmode/src/com/android/devicediagnostics/commands/Commands.kt
index 7a7b8a5..f52f6a7 100644
--- a/tradeinmode/src/com/android/devicediagnostics/commands/Commands.kt
+++ b/tradeinmode/src/com/android/devicediagnostics/commands/Commands.kt
@@ -19,7 +19,6 @@ import android.app.ActivityManager
 import android.app.ContentProviderHolder
 import android.content.AttributionSource
 import android.content.ContentResolver
-import android.content.IContentProvider
 import android.database.Cursor
 import android.net.Uri
 import android.os.Binder
@@ -31,6 +30,8 @@ import android.os.UserHandle
 import java.io.FileDescriptor
 import kotlin.system.exitProcess
 
+const val STATE_PROP = "persist.adb.tradeinmode"
+
 class Tokenizer(private val args: Array<String>) {
     private var cursor = 0
 
@@ -49,7 +50,11 @@ fun isDebuggable(): Boolean {
 }
 
 fun isTradeInModeEnabled(): Boolean {
-    return SystemProperties.getInt("persist.adb.tradeinmode", 0) > 0
+    return SystemProperties.getInt(STATE_PROP, 0) > 0
+}
+
+fun isBootCompleted(): Boolean {
+    return SystemProperties.getInt("sys.boot_completed", 0) != 0
 }
 
 fun ensureTradeInModeAllowed() {
@@ -62,35 +67,54 @@ class Commands {
     companion object {
         @JvmStatic
         fun main(args: Array<String>) {
-            if (SystemProperties.getInt("sys.boot_completed", 0) != 1) {
-                System.err.println("Device not fully booted")
-                exitProcess(1)
-            }
             try {
-                main_wrapper(Tokenizer(args))
+                doMain(Tokenizer(args))
             } catch (e: Exception) {
                 System.err.println("Error: $e")
                 exitProcess(1)
             }
         }
+    }
+}
 
-        fun main_wrapper(args: Tokenizer) {
-            val cmd = args.next()
-            if (cmd == null) {
-                throw IllegalArgumentException("Expected command.")
-            }
+fun doMain(args: Tokenizer) {
+    var cmd = args.next()
+    if (cmd == null) {
+        throw IllegalArgumentException("Expected command.")
+    }
 
-            ensureTradeInModeAllowed()
+    // Optional wait-until-ready prefix to make testing easier.
+    if (cmd == "wait-until-ready") {
+        doWaitUntilReady()
 
-            if (cmd == "getstatus") {
-                doGetStatus(args)
-            } else if (cmd == "evaluate") {
-                doEvaluate(args)
-            } else {
-                throw IllegalArgumentException("Unknown command.")
-            }
+        cmd = args.next()
+        if (cmd == null) {
+            return
         }
     }
+
+    if (cmd == "testing" && isDebuggable()) {
+        doTesting(args)
+        return
+    }
+
+    if (!isBootCompleted()) {
+        throw Exception("Device not fully booted")
+    }
+
+    ensureTradeInModeAllowed()
+
+    if (cmd == "getstatus") {
+        doGetStatus(args)
+    } else if (cmd == "evaluate") {
+        doEvaluate(args)
+    } else if (cmd == "poweroff") {
+        SystemProperties.set("sys.powerctl", "shutdown")
+    } else if (cmd == "reboot") {
+        SystemProperties.set("sys.powerctl", "reboot")
+    } else {
+        throw IllegalArgumentException("Unknown command.")
+    }
 }
 
 fun callingPackage(): String? {
@@ -101,18 +125,13 @@ fun callingPackage(): String? {
     }
 }
 
-fun doEvaluate(args: Tokenizer) {
-    if (args.more()) {
-        throw IllegalArgumentException("Unexpected argument.")
-    }
-
+fun startActivity(activity: String) {
     val am = ActivityManager.getService()
     if (am == null) {
         throw Exception("ActivityManager is not available.")
     }
 
-    val path = "com.android.devicediagnostics/.EnterEvaluationMode"
-    val shellArgs = arrayOf("start", "-n", path)
+    val shellArgs = arrayOf("start", "-n", activity)
     am.asBinder()
         .shellCommand(
             FileDescriptor.`in`,
@@ -124,49 +143,62 @@ fun doEvaluate(args: Tokenizer) {
         )
 }
 
-fun queryGetStatusProvider(provider: IContentProvider, uri: Uri, extras: Bundle): Int {
-    val cursor =
-        provider.query(
-            AttributionSource(Binder.getCallingUid(), callingPackage(), null),
-            uri,
-            arrayOf<String>(),
-            extras,
-            null,
-        )
-    if (cursor == null) {
-        System.err.println("No result found.")
-        return 1
+fun doTesting(args: Tokenizer) {
+    if (!args.more()) {
+        throw IllegalArgumentException("Expected argument.")
     }
-    try {
-        if (!cursor.moveToFirst()) {
-            System.err.println("No result found.")
-            return 1
-        }
-        if (cursor.getColumnCount() < 1) {
-            System.err.println("No result found.")
-            return 1
-        }
-        if (cursor.getType(0) != Cursor.FIELD_TYPE_STRING) {
-            System.err.println("No result found.")
-            return 1
-        }
-        println(cursor.getString(0))
-    } finally {
-        cursor.close()
+
+    val uriString = "content://com.android.devicediagnostics.TradeInModeTestingContentProvider"
+
+    val cmd = args.next()
+
+    if (cmd == "status") {
+        val result = queryStringContentProvider(uriString, cmd)
+        println(result)
+        return
+    }
+
+    var reboot: Boolean = false
+    if (cmd == "start") {
+        println("Device will reboot in trade-in mode.")
+        reboot = true
+    } else if (cmd == "wipe") {
+        println("Device will reboot to wipe userdata.")
+        reboot = true
+    } else if (cmd == "stop") {
+        println("Device will restart adb.")
+    } else {
+        throw IllegalArgumentException("Unknown argument.")
+    }
+
+    val result = queryStringContentProvider(uriString, cmd)
+    if (result != "ok") {
+        throw Exception("Failed to query testing content provider")
+    }
+
+    if (reboot) {
+        SystemProperties.set("sys.powerctl", "reboot")
     }
-    return 0
 }
 
-fun doGetStatus(args: Tokenizer) {
-    val extras = Bundle()
+fun doEvaluate(args: Tokenizer) {
+    if (args.more()) {
+        throw IllegalArgumentException("Unexpected argument.")
+    }
+
+    val uriString = "content://com.android.devicediagnostics.EvaluateContentProvider"
+    queryStringContentProvider(uriString, null)
+    println("Entering evaluation mode.")
+}
 
+fun doGetStatus(args: Tokenizer) {
     val arg = args.next()
+    var challenge: String? = null
     if (arg == "--challenge") {
-        val challenge = args.next()
+        challenge = args.next()
         if (challenge == null) {
             throw IllegalArgumentException("Expected challenge.")
         }
-        extras.putString(ContentResolver.QUERY_ARG_SQL_SELECTION, challenge)
     } else if (arg != null) {
         throw IllegalArgumentException("Unexpected argument.")
     }
@@ -175,13 +207,27 @@ fun doGetStatus(args: Tokenizer) {
         throw IllegalArgumentException("Unexpected argument.")
     }
 
+    val uriString = "content://com.android.devicediagnostics.GetStatusContentProvider"
+    val result = queryStringContentProvider(uriString, challenge)
+    if (result == null) {
+        System.err.println("No result found.")
+        return
+    }
+    println(result)
+}
+
+fun queryStringContentProvider(uriString: String, selection: String?): String? {
     val am = ActivityManager.getService()
     if (am == null) {
         throw Exception("ActivityManager is not available.")
     }
 
+    val extras = Bundle()
+    if (selection != null) {
+        extras.putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection)
+    }
+
     val token = Binder()
-    val uriString = "content://com.android.devicediagnostics/.GetStatusContentProvider"
     val uri = Uri.parse(uriString)
     var holder: ContentProviderHolder? = null
     try {
@@ -190,10 +236,67 @@ fun doGetStatus(args: Tokenizer) {
         if (holder == null) {
             throw Exception("Could not find provider: " + uri.authority)
         }
-        queryGetStatusProvider(holder.provider, uri, extras)
+        val cursor =
+            holder.provider.query(
+                AttributionSource(Binder.getCallingUid(), callingPackage(), null),
+                uri,
+                arrayOf<String>(),
+                extras,
+                null,
+            )
+        if (cursor == null) {
+            return null
+        }
+        try {
+            if (!cursor.moveToFirst()) {
+                return null
+            }
+            if (cursor.getColumnCount() < 1) {
+                return null
+            }
+            if (cursor.getType(0) != Cursor.FIELD_TYPE_STRING) {
+                return null
+            }
+            return cursor.getString(0)
+        } finally {
+            cursor.close()
+        }
     } finally {
         if (holder != null && holder.provider != null) {
             am.removeContentProviderExternalAsUser(uri.authority, token, UserHandle.USER_SYSTEM)
         }
     }
 }
+
+fun isTradeInModeReady(): Boolean {
+    if (!isBootCompleted()) {
+        return false
+    }
+
+    val am = ActivityManager.getService()
+    if (am == null) {
+        return false
+    }
+
+    val token = Binder()
+    val uriString = "content://com.android.devicediagnostics.GetStatusContentProvider"
+    val uri = Uri.parse(uriString)
+    var holder: ContentProviderHolder? = null
+    try {
+        holder =
+            am.getContentProviderExternal(uri.authority, UserHandle.USER_SYSTEM, token, "*cmd*")
+        return holder != null && holder.provider != null
+    } catch (e: Exception) {
+        return false
+    } finally {
+        if (holder != null && holder.provider != null) {
+            am.removeContentProviderExternalAsUser(uri.authority, token, UserHandle.USER_SYSTEM)
+        }
+    }
+}
+
+fun doWaitUntilReady() {
+    while (!isTradeInModeReady()) {
+        Thread.sleep(500)
+    }
+}
```

