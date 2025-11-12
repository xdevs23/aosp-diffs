```diff
diff --git a/.gitignore b/.gitignore
index 5f98509..27273db 100644
--- a/.gitignore
+++ b/.gitignore
@@ -3,3 +3,4 @@
 /.idea
 /build
 local.properties
+kls_database.db
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
index cab3b82..080084f 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/DeviceReportJsonFormatter.kt
@@ -18,10 +18,14 @@ package com.android.devicediagnostics
 import android.util.Base64
 import com.android.devicediagnostics.Protos.BatteryInfo
 import com.android.devicediagnostics.Protos.DeviceReport
+import com.android.devicediagnostics.Protos.HingeInfo
 import com.android.devicediagnostics.Protos.LockInfo
 import com.android.devicediagnostics.Protos.ProductInfo
+import com.android.devicediagnostics.Protos.ScreenInfo
+import com.android.devicediagnostics.Protos.SensorInfo
 import com.android.devicediagnostics.Protos.StorageInfo
 import com.android.devicediagnostics.Protos.TestResults
+import org.json.JSONArray
 import org.json.JSONObject
 
 private fun putIfNotEmpty(holder: JSONObject, key: String, obj: JSONObject) {
@@ -47,14 +51,14 @@ private fun batteryInfoToJson(battery: BatteryInfo): JSONObject {
     obj.putIfPresent(battery.hasPartStatus(), "part_status", battery.partStatus)
     obj.put("state", battery.legacyHealth)
     obj.putIfPresent(
-        battery.hasManufactureTimestamp(),
-        "manufacturing_date",
-        battery.manufactureTimestamp,
+            battery.hasManufactureTimestamp(),
+            "manufacturing_date",
+            battery.manufactureTimestamp,
     )
     obj.putIfPresent(
-        battery.hasFirstUsageTimestamp(),
-        "first_usage_date",
-        battery.firstUsageTimestamp,
+            battery.hasFirstUsageTimestamp(),
+            "first_usage_date",
+            battery.firstUsageTimestamp,
     )
     return obj
 }
@@ -72,14 +76,53 @@ private fun productInfoToJson(product: ProductInfo): JSONObject {
 private fun storageInfoToJson(storage: StorageInfo): JSONObject {
     val obj = JSONObject()
     obj.putIfPresent(
-        storage.hasUsefulLifetimeRemaining(),
-        "useful_lifetime_remaining",
-        storage.usefulLifetimeRemaining,
+            storage.hasUsefulLifetimeRemaining(),
+            "useful_lifetime_remaining",
+            storage.usefulLifetimeRemaining,
     )
     obj.put("capacity_bytes", storage.capacityBytes.toString())
     return obj
 }
 
+private fun hingeInfoToJson(hinge: HingeInfo): JSONObject {
+    val obj = JSONObject()
+    if (hinge.hingeCount != 0) {
+        val hinges = JSONArray()
+        for (i in 0 until hinge.hingeCount) {
+            val h = JSONObject()
+            h.put("num_times_folded", hinge.numTimesFoldedList[i])
+            h.put("rated_lifespan", hinge.expectedLifespanList[i])
+            hinges.put(h)
+        }
+        obj.put("hinges", hinges)
+    }
+    return obj
+}
+
+private fun sensorInfoToJson(sensor: SensorInfo): JSONObject {
+    val obj = JSONObject()
+    obj.putIfPresent(
+            sensor.hasMoistureIntrusion(),
+            "moisture_intrusion",
+            sensor.moistureIntrusion,
+    )
+    return obj
+}
+
+private fun screenInfoToJson(screen: ScreenInfo): JSONObject {
+    val obj = JSONObject()
+    val screens = JSONArray()
+    for (i in 0 until screen.screenPartStatusCount) {
+        val s = JSONObject()
+        s.put("part_status", screen.screenPartStatusList[i])
+        screens.put(s)
+    }
+    if (screens.length() != 0) {
+        obj.put("screens", screens)
+    }
+    return obj
+}
+
 private fun lockInfoToJson(info: LockInfo): JSONObject {
     val obj = JSONObject()
     obj.put("factory_reset_protection", info.factoryResetProtection)
@@ -93,8 +136,11 @@ fun deviceReportToJson(report: DeviceReport): JSONObject {
         val info = JSONObject()
         if (!report.attestation.certificates.isEmpty) {
             info.put(
-                "certificates",
-                Base64.encodeToString(report.attestation.certificates.toByteArray(), Base64.DEFAULT),
+                    "certificates",
+                    Base64.encodeToString(
+                            report.attestation.certificates.toByteArray(),
+                            Base64.DEFAULT
+                    ),
             )
         }
         if (!report.attestation.error.isEmpty()) {
@@ -104,6 +150,9 @@ fun deviceReportToJson(report: DeviceReport): JSONObject {
     }
     if (report.hasBattery()) putIfNotEmpty(obj, "battery", batteryInfoToJson(report.battery))
     if (report.hasStorage()) putIfNotEmpty(obj, "storage", storageInfoToJson(report.storage))
+    if (report.hasHinge()) putIfNotEmpty(obj, "hinge", hingeInfoToJson(report.hinge))
+    if (report.hasScreen()) putIfNotEmpty(obj, "screen", screenInfoToJson(report.screen))
+    if (report.hasSensor()) putIfNotEmpty(obj, "sensors", sensorInfoToJson(report.sensor))
     obj.putIfPresent(report.hasLaunchLevel(), "launch_level", report.launchLevel)
     obj.put("locks", lockInfoToJson(report.locks))
     if (report.hasProduct()) putIfNotEmpty(obj, "product", productInfoToJson(report.product))
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt
index 72089bf..49039a7 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/EvaluateContentProvider.kt
@@ -89,11 +89,12 @@ class EvaluateContentProvider : ContentProvider() {
                 throw IllegalStateException("Evaluation mode is not available.")
             }
 
-            if (tryActivityDismissal()) {
-                return ""
-            }
+            // Support older releases of GMSCore that used an activity to
+            // dimiss SUW.
+            tryActivityDismissal()
 
-            // Dismiss suw the new way via a broadcast
+            // Dismiss SUW the new way via a broadcast. Do this unconditionally
+            // so that custom SUWs can work in conjunction with older GMSCore.
             val broadcast = Intent()
             broadcast.setAction("com.google.android.setupwizard.ENTER_TRADE_IN_MODE")
             broadcast.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND)
@@ -101,17 +102,13 @@ class EvaluateContentProvider : ContentProvider() {
             return ""
         }
 
-        private fun tryActivityDismissal(): Boolean {
-            // Dismiss suw the old way via an activity
+        private fun tryActivityDismissal() {
             try {
                 val intent = Intent(Intent.ACTION_MAIN)
                 intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                 intent.setAction("com.android.setupwizard.TIM")
                 context.startActivity(intent)
-                return true
-            } catch (e: Exception) {
-                return false
-            }
+            } catch (e: Exception) {}
         }
 
         override fun getShort(column: Int): Short {
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
index eb116e5..bdb9d0d 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/GetStatusContentProvider.kt
@@ -27,61 +27,66 @@ import android.util.Log
 import com.android.devicediagnostics.Protos.DeviceReport
 import com.android.devicediagnostics.evaluated.createAttestationRecord
 import com.android.devicediagnostics.evaluated.getBatteryInfo
+import com.android.devicediagnostics.evaluated.getHingeInfo
 import com.android.devicediagnostics.evaluated.getLockInfo
 import com.android.devicediagnostics.evaluated.getProductInfo
+import com.android.devicediagnostics.evaluated.getScreenInfo
+import com.android.devicediagnostics.evaluated.getSensorInfo
 import com.android.devicediagnostics.evaluated.getStorageInfo
 import org.json.JSONArray
 
 private const val TAG = "GetStatus"
 
 class GetStatusContentProvider : ContentProvider() {
-    override fun onCreate(): Boolean {
-        return true
-    }
+    override fun onCreate(): Boolean = true
 
     override fun query(
-        uri: Uri,
-        projection: Array<out String>?,
-        selection: String?,
-        selectionArgs: Array<out String>?,
-        sortOrder: String?,
-    ): Cursor? {
-        return StatusCursor(context!!, selection)
-    }
+            uri: Uri,
+            projection: Array<out String>?,
+            selection: String?,
+            selectionArgs: Array<out String>?,
+            sortOrder: String?,
+    ): Cursor? = StatusCursor(context!!, selection)
 
     override fun getType(uri: Uri): String? {
         Log.d(TAG, "Not implemented")
         return null
     }
 
-    override fun insert(uri: Uri, values: ContentValues?): Uri? {
+    override fun insert(
+            uri: Uri,
+            values: ContentValues?,
+    ): Uri? {
         Log.d(TAG, "Not implemented")
         return null
     }
 
-    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
+    override fun delete(
+            uri: Uri,
+            selection: String?,
+            selectionArgs: Array<out String>?,
+    ): Int {
         Log.d(TAG, "Not implemented")
         return 0
     }
 
     override fun update(
-        uri: Uri,
-        values: ContentValues?,
-        selection: String?,
-        selectionArgs: Array<out String>?,
+            uri: Uri,
+            values: ContentValues?,
+            selection: String?,
+            selectionArgs: Array<out String>?,
     ): Int {
         Log.d(TAG, "Not implemented")
         return 0
     }
 
-    class StatusCursor(val context: Context, val selection: String?) : AbstractCursor() {
-        override fun getCount(): Int {
-            return 1
-        }
+    class StatusCursor(
+            val context: Context,
+            val selection: String?,
+    ) : AbstractCursor() {
+        override fun getCount(): Int = 1
 
-        override fun getColumnNames(): Array<String> {
-            return arrayOf("Status")
-        }
+        override fun getColumnNames(): Array<String> = arrayOf("Status")
 
         override fun getString(column: Int): String {
             val challenge: ByteArray
@@ -92,17 +97,20 @@ class GetStatusContentProvider : ContentProvider() {
             }
 
             val report =
-                DeviceReport.newBuilder().run {
-                    setLocks(getLockInfo(context))
-                    if (!locks.factoryResetProtection) {
-                        setBattery(getBatteryInfo(context))
-                        setStorage(getStorageInfo(context))
-                        setLaunchLevel(ApplicationInterface.app.getLaunchLevel())
-                        setProduct(getProductInfo())
-                        selection?.run { setAttestation(createAttestationRecord(challenge)) }
+                    DeviceReport.newBuilder().run {
+                        setLocks(getLockInfo(context))
+                        if (!locks.factoryResetProtection) {
+                            setBattery(getBatteryInfo(context))
+                            setStorage(getStorageInfo(context))
+                            setLaunchLevel(ApplicationInterface.app.getLaunchLevel())
+                            setProduct(getProductInfo())
+                            setHinge(getHingeInfo())
+                            setSensor(getSensorInfo())
+                            setScreen(getScreenInfo())
+                            selection?.run { setAttestation(createAttestationRecord(challenge)) }
+                        }
+                        build()
                     }
-                    build()
-                }
             val json = deviceReportToJson(report)
             if (!report.locks.factoryResetProtection) {
                 val tm = context.getSystemService(TelephonyManager::class.java)!!
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/BatteryUtilities.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/BatteryUtilities.kt
index 6124a64..f77f2ed 100644
--- a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/BatteryUtilities.kt
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/BatteryUtilities.kt
@@ -30,12 +30,12 @@ fun getBatteryInfo(context: Context): BatteryInfo {
 
     try {
         var date = bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_MANUFACTURING_DATE)
-        if (date >= 0) {
+        if (date > 0) {
             builder.setManufactureTimestamp(date)
         }
 
         date = bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_FIRST_USAGE_DATE)
-        if (date >= 0) {
+        if (date > 0) {
             builder.setFirstUsageTimestamp(date)
         }
     } catch (e: Exception) {}
@@ -45,17 +45,15 @@ fun getBatteryInfo(context: Context): BatteryInfo {
         builder.setStateOfHealth(stateOfHealth)
     }
 
-    if (android.os.Flags.batteryPartStatusApi()) {
-        val status = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_PART_STATUS)
-        if (status == BatteryManager.PART_STATUS_ORIGINAL) {
-            builder.setPartStatus(context.resources.getString(R.string.battery_original))
-        } else if (status == BatteryManager.PART_STATUS_REPLACED) {
-            builder.setPartStatus(context.resources.getString(R.string.battery_replaced))
-        }
-        val serial = bm.getStringProperty(BatteryManager.BATTERY_PROPERTY_SERIAL_NUMBER)
-        if (!serial.isNullOrEmpty()) {
-            builder.setSerial(serial)
-        }
+    val status = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_PART_STATUS)
+    if (status == BatteryManager.PART_STATUS_ORIGINAL) {
+        builder.setPartStatus(context.resources.getString(R.string.battery_original))
+    } else if (status == BatteryManager.PART_STATUS_REPLACED) {
+        builder.setPartStatus(context.resources.getString(R.string.battery_replaced))
+    }
+    val serial = bm.getStringProperty(BatteryManager.BATTERY_PROPERTY_SERIAL_NUMBER)
+    if (!serial.isNullOrEmpty()) {
+        builder.setSerial(serial)
     }
 
     val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/HingeUtilities.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/HingeUtilities.kt
new file mode 100644
index 0000000..128e36e
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/HingeUtilities.kt
@@ -0,0 +1,38 @@
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
+package com.android.devicediagnostics.evaluated
+
+import android.os.IBinder
+import android.os.ITradeInMode
+import android.os.ServiceManager
+import com.android.devicediagnostics.Protos.HingeInfo
+
+fun getHingeInfo(): HingeInfo {
+    var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
+    var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
+    val builder = HingeInfo.newBuilder()
+
+    val hingeCount = service.getHingeCount()
+    builder.setHingeCount(hingeCount)
+
+    for (hinge in 0 until hingeCount) {
+        var foldCount = service.getFoldCount(hinge)
+        var lifeSpan = service.getHingeLifeSpan(hinge)
+        builder.addNumTimesFolded(foldCount)
+        builder.addExpectedLifespan(lifeSpan)
+    }
+    return builder.build()
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ScreenUtilities.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ScreenUtilities.kt
new file mode 100644
index 0000000..5cdcb5d
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/ScreenUtilities.kt
@@ -0,0 +1,40 @@
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
+package com.android.devicediagnostics.evaluated
+
+import android.os.IBinder
+import android.os.ITradeInMode
+import android.os.ITradeInMode.ScreenPartStatus
+import android.os.ServiceManager
+import com.android.devicediagnostics.Protos.ScreenInfo
+
+fun getScreenInfo(): ScreenInfo {
+    var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
+    var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
+    val builder = ScreenInfo.newBuilder()
+
+    val screenPartStatuses: IntArray = service.getScreenPartStatus()
+    screenPartStatuses.forEachIndexed { _, screenPartStatus ->
+        if (screenPartStatus == ITradeInMode.ScreenPartStatus.ORIGINAL) {
+            builder.addScreenPartStatus("original")
+        }
+        if (screenPartStatus == ITradeInMode.ScreenPartStatus.REPLACED) {
+            builder.addScreenPartStatus("replaced")
+        }
+    }
+
+    return builder.build()
+}
diff --git a/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/SensorUtilities.kt b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/SensorUtilities.kt
new file mode 100644
index 0000000..43a2576
--- /dev/null
+++ b/DeviceDiagnosticsLib/src/main/java/com/android/devicediagnostics/evaluated/SensorUtilities.kt
@@ -0,0 +1,38 @@
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
+package com.android.devicediagnostics.evaluated
+
+import android.os.IBinder
+import android.os.ITradeInMode
+import android.os.ServiceManager
+import com.android.devicediagnostics.Protos.SensorInfo
+
+const val SENSOR_TIMEOUT_MILLIS: Long = 1000
+
+fun getSensorInfo(): SensorInfo {
+    var b: IBinder = ServiceManager.getServiceOrThrow("tradeinmode")
+    var service: ITradeInMode = ITradeInMode.Stub.asInterface(b)
+    val builder = SensorInfo.newBuilder()
+
+    val moistureIntrusion = service.getMoistureIntrusionDetected(SENSOR_TIMEOUT_MILLIS)
+    if (moistureIntrusion == ITradeInMode.MoistureIntrusionStatus.DETECTED) {
+        builder.setMoistureIntrusion(true)
+    } else if (moistureIntrusion == ITradeInMode.MoistureIntrusionStatus.UNDETECTED) {
+        builder.setMoistureIntrusion(false)
+    }
+
+    return builder.build()
+}
diff --git a/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto b/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
index 20cbcd4..878b7a0 100644
--- a/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
+++ b/DeviceDiagnosticsLib/src/main/proto/diagnostics.proto
@@ -51,6 +51,10 @@ message HingeInfo {
   repeated int32 expected_lifespan = 3;
 }
 
+message SensorInfo { optional bool moisture_intrusion = 1; }
+
+message ScreenInfo { repeated string screen_part_status = 1; }
+
 message TrustedDeviceInfo { bytes challenge = 1; }
 
 message DeviceReport {
@@ -63,6 +67,8 @@ message DeviceReport {
   ProductInfo product = 7;
   HingeInfo hinge = 8;
   optional AttestationInfo attestation = 9;
+  ScreenInfo screen = 10;
+  SensorInfo sensor = 11;
 }
 
 enum PacketCommand {
diff --git a/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
index 182f252..9a5dd77 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-bs/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"Ručni testovi"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Test ekrana"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Test dodira"</string>
-    <string name="component_title" msgid="6580046234562555655">"Status komponente"</string>
+    <string name="component_title" msgid="6580046234562555655">"Status komponenti"</string>
     <string name="storage_title" msgid="5921235202250843966">"Status pohrane"</string>
     <string name="battery_title" msgid="6707361668941323259">"Status baterije"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Pouzdani uređaj"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
index 170eb4a..c8ab5bb 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ca/strings.xml
@@ -23,7 +23,7 @@
     <string name="proceed" msgid="8922926495095369132">"Continua"</string>
     <string name="unavailable" msgid="7842920330665850121">"No disponible"</string>
     <string name="bluetooth_connecting" msgid="7966802493158307502">"S\'està connectant..."</string>
-    <string name="component_health_title" msgid="6177813132789269842">"Estat del component"</string>
+    <string name="component_health_title" msgid="6177813132789269842">"Estat dels components"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"Executa proves manuals i consulta l\'estat de la bateria i de l\'emmagatzematge"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"Mode d\'avaluació"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Utilitza un dispositiu per avaluar-ne un altre"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
index 9e47287..089a5fe 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-es/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"Pruebas manuales"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Prueba de pantalla"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Prueba táctil"</string>
-    <string name="component_title" msgid="6580046234562555655">"Estado del componente"</string>
+    <string name="component_title" msgid="6580046234562555655">"Estado de los componentes"</string>
     <string name="storage_title" msgid="5921235202250843966">"Estado del almacenamiento"</string>
     <string name="battery_title" msgid="6707361668941323259">"Estado de la batería"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Dispositivo de confianza"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-et/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-et/strings.xml
index d7dff4f..2ae930c 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-et/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-et/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"Käsitsi tehtavad testid"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Ekraani test"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Puutetest"</string>
-    <string name="component_title" msgid="6580046234562555655">"Komponendi olek"</string>
+    <string name="component_title" msgid="6580046234562555655">"Komponentide olek"</string>
     <string name="storage_title" msgid="5921235202250843966">"Salvestusruumi olek"</string>
     <string name="battery_title" msgid="6707361668941323259">"Aku olek"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Usaldusväärne seade"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-eu/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-eu/strings.xml
index 589f0aa..d55d501 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-eu/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-eu/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"Eskuzko probak"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Pantailaren proba"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Ukipen-proba"</string>
-    <string name="component_title" msgid="6580046234562555655">"Osagaiaren egoera"</string>
+    <string name="component_title" msgid="6580046234562555655">"Osagaien egoera"</string>
     <string name="storage_title" msgid="5921235202250843966">"Biltegiaren egoera"</string>
     <string name="battery_title" msgid="6707361668941323259">"Bateriaren egoera"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Gailu fidagarria"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-fr-rCA/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-fr-rCA/strings.xml
index fac3452..bc71f67 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-fr-rCA/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-fr-rCA/strings.xml
@@ -23,14 +23,14 @@
     <string name="proceed" msgid="8922926495095369132">"Continuer"</string>
     <string name="unavailable" msgid="7842920330665850121">"Non accessible"</string>
     <string name="bluetooth_connecting" msgid="7966802493158307502">"Connexion en cours…"</string>
-    <string name="component_health_title" msgid="6177813132789269842">"Santé du composant"</string>
-    <string name="component_health_summary" msgid="2799337555706868947">"Exécuter des tests manuels et consulter l\'état de la pile et de l\'espace de stockage"</string>
+    <string name="component_health_title" msgid="6177813132789269842">"Santé des composants"</string>
+    <string name="component_health_summary" msgid="2799337555706868947">"Exécutez des tests manuels et consultez l\'état de la pile et de l\'espace de stockage"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"Mode d\'évaluation"</string>
-    <string name="evaluation_mode_summary" msgid="7327453519906858863">"Utiliser un appareil pour en évaluer un autre"</string>
+    <string name="evaluation_mode_summary" msgid="7327453519906858863">"Utilisez un appareil pour en évaluer un autre"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Tests manuels"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Test relatif à l\'écran"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Test tactile"</string>
-    <string name="component_title" msgid="6580046234562555655">"État du composant"</string>
+    <string name="component_title" msgid="6580046234562555655">"État des composants"</string>
     <string name="storage_title" msgid="5921235202250843966">"État de l\'espace de stockage"</string>
     <string name="battery_title" msgid="6707361668941323259">"État de la pile"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Appareil de confiance"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
index 6c50310..438e45c 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-fr/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"Tests manuels"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Test de l\'écran"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Test du capteur tactile"</string>
-    <string name="component_title" msgid="6580046234562555655">"État du composant"</string>
+    <string name="component_title" msgid="6580046234562555655">"État des composants"</string>
     <string name="storage_title" msgid="5921235202250843966">"État de l\'espace de stockage"</string>
     <string name="battery_title" msgid="6707361668941323259">"État de la batterie"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Appareil vérifié"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
index 2bdf857..7e4cfe6 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-gu/strings.xml
@@ -26,7 +26,7 @@
     <string name="component_health_title" msgid="6177813132789269842">"ઘટકની ક્ષમતા"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"મેન્યુઅલ પરીક્ષણો ચલાવો તેમજ બૅટરી અને સ્ટોરેજની ક્ષમતા ચેક કરી જુઓ"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"મૂલ્યાંકનનો મોડ"</string>
-    <string name="evaluation_mode_summary" msgid="7327453519906858863">"એક ડિવાઇસ વડે બીજા ડિવાઇસનું મૂલ્યાંકન કરો"</string>
+    <string name="evaluation_mode_summary" msgid="7327453519906858863">"એક ડિવાઇસ વડે કોઈ અન્ય ડિવાઇસનું મૂલ્યાંકન કરો"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"મેન્યુઅલ પરીક્ષણો"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"ડિસ્પ્લેનું પરીક્ષણ"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"ટચનું પરીક્ષણ"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
index 41ef669..d1fdbaf 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-hi/strings.xml
@@ -99,7 +99,7 @@
     <string name="attestation_device" msgid="1984309818766961098">"डिवाइस"</string>
     <string name="attestation_product" msgid="7325714994397112640">"प्रॉडक्ट"</string>
     <string name="attestation_serial" msgid="5001580041093391656">"सीरियल नंबर"</string>
-    <string name="attestation_imei" msgid="8985230697018835192">"IMEI"</string>
+    <string name="attestation_imei" msgid="8985230697018835192">"आईएमईआई"</string>
     <string name="attestation_second_imei" msgid="7566064584445017361">"दूसरा IMEI नंबर"</string>
     <string name="attestation_meid" msgid="6837237287403480594">"MEID"</string>
     <string name="attestation_manufacturer" msgid="2043278400561674518">"मैन्युफ़ैक्चरर"</string>
@@ -114,7 +114,7 @@
     <string name="avb_not_verified" msgid="6853341577991139767">"पुष्टि नहीं हुई"</string>
     <string name="evaluation_results" msgid="1584774109554324406">"जांच के नतीजे"</string>
     <string name="attestation_results" msgid="9089126954790727665">"प्रमाणित करने से जुड़े नतीजे"</string>
-    <string name="imei_title" msgid="4360390946838995750">"IMEI"</string>
+    <string name="imei_title" msgid="4360390946838995750">"आईएमईआई"</string>
     <string name="imei2_title" msgid="4414064408324667040">"दूसरा IMEI नंबर"</string>
     <string name="serial_number_title" msgid="1361280023487536604">"सीरियल नंबर"</string>
     <string name="bootloader_locked_title" msgid="4498089738937695995">"बूटलोडर को लॉक किया गया है"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ja/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ja/strings.xml
index 58e75c5..8c82ff1 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ja/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ja/strings.xml
@@ -30,7 +30,7 @@
     <string name="manual_eval_title" msgid="4335717606581762762">"手動テスト"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"ディスプレイをテスト"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"タッチテスト"</string>
-    <string name="component_title" msgid="6580046234562555655">"コンポーネントのステータス"</string>
+    <string name="component_title" msgid="6580046234562555655">"コンポーネントの状態"</string>
     <string name="storage_title" msgid="5921235202250843966">"ストレージの状態"</string>
     <string name="battery_title" msgid="6707361668941323259">"バッテリーの状態"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"信頼できるデバイス"</string>
@@ -69,7 +69,7 @@
     <string name="battery_replaced" msgid="2356023769075469649">"交換済み"</string>
     <string name="battery_part_history" msgid="5669260842330985767">"パーツの履歴"</string>
     <string name="battery_health_summary_fmt" msgid="4363832259742003306">"元の容量の %1$s"</string>
-    <string name="battery_health_unavailable" msgid="5093923315136769788">"バッテリーの健全性機能を使用できません"</string>
+    <string name="battery_health_unavailable" msgid="5093923315136769788">"バッテリー ヘルス機能を使用できません"</string>
     <string name="battery_health_cold" msgid="4164463402047143412">"低温"</string>
     <string name="battery_health_dead" msgid="3658507844189988433">"残量なし"</string>
     <string name="battery_health_good" msgid="4850784608550784236">"良好"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
index 01e78b6..19f8eea 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-kk/strings.xml
@@ -34,7 +34,7 @@
     <string name="storage_title" msgid="5921235202250843966">"Жад күйі"</string>
     <string name="battery_title" msgid="6707361668941323259">"Батарея күйі"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Сенімді құрылғы"</string>
-    <string name="eval_mode_trusted_device_summary" msgid="8217291325895255590">"Басқа құрылғыда бағалау жүргізіңіз. Интернет қажет."</string>
+    <string name="eval_mode_trusted_device_summary" msgid="8217291325895255590">"Басқа құрылғыға баға беріңіз. Интернет қажет."</string>
     <string name="evaluated_device_title" msgid="5546625787928257821">"Бағаланатын құрылғы"</string>
     <string name="eval_mode_evaluated_device_summary" msgid="3636314493314426253">"Басқа құрылғыда тексерілетін диагностикалық сынақтар жүргізіңіз."</string>
     <string name="evaluated_scan_now" msgid="5413803134686672845">"Қазір сканерлеу"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-kn/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-kn/strings.xml
index ad93502..adb2f1c 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-kn/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-kn/strings.xml
@@ -23,7 +23,7 @@
     <string name="proceed" msgid="8922926495095369132">"ಮುಂದುವರಿಸಿ"</string>
     <string name="unavailable" msgid="7842920330665850121">"ಲಭ್ಯವಿಲ್ಲ"</string>
     <string name="bluetooth_connecting" msgid="7966802493158307502">"ಕನೆಕ್ಟ್ ಮಾಡಲಾಗುತ್ತಿದೆ..."</string>
-    <string name="component_health_title" msgid="6177813132789269842">"ಘಟಕದ ಆರೋಗ್ಯ"</string>
+    <string name="component_health_title" msgid="6177813132789269842">"ಘಟಕದ ಸುಸ್ಥಿತಿ"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"ಮ್ಯಾನುವಲ್ ಪರೀಕ್ಷೆಗಳನ್ನು ರನ್ ಮಾಡಿ ಮತ್ತು ಬ್ಯಾಟರಿ ಮತ್ತು ಸಂಗ್ರಹಣಾ ಆರೋಗ್ಯವನ್ನು ವೀಕ್ಷಿಸಿ"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"ಮೌಲ್ಯಮಾಪನ ಮೋಡ್"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"ಇನ್ನೊಂದು ಸಾಧನವನ್ನು ನಿರ್ಣಯಿಸಲು ಒಂದು ಸಾಧನವನ್ನು ಬಳಸಿ"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ms/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ms/strings.xml
index 1611adf..9c0961c 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ms/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ms/strings.xml
@@ -25,7 +25,7 @@
     <string name="bluetooth_connecting" msgid="7966802493158307502">"Menyambung..."</string>
     <string name="component_health_title" msgid="6177813132789269842">"Kesihatan komponen"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"Jalankan ujian manual dan lihat kesihatan bateri dan storan"</string>
-    <string name="evaluation_mode_title" msgid="5845218248059550975">"Cara penilaian"</string>
+    <string name="evaluation_mode_title" msgid="5845218248059550975">"Mod penilaian"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Gunakan satu peranti untuk menilai peranti lain"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Ujian manual"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Ujian paparan"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
index facaf47..99b0d14 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-my/strings.xml
@@ -103,7 +103,7 @@
     <string name="attestation_second_imei" msgid="7566064584445017361">"ဒုတိယ IMEI"</string>
     <string name="attestation_meid" msgid="6837237287403480594">"MEID"</string>
     <string name="attestation_manufacturer" msgid="2043278400561674518">"ထုတ်လုပ်သူ"</string>
-    <string name="attestation_model" msgid="8223243376214262662">"မော်ဒယ်"</string>
+    <string name="attestation_model" msgid="8223243376214262662">"မိုဒယ်"</string>
     <string name="attestation_vendor_patch_level" msgid="5961013660410857720">"ရောင်းသူ၏ ပက်ချ်အဆင့်"</string>
     <string name="attestation_boot_patch_level" msgid="6266071138457400006">"စနစ်စတင်မှု ပက်ချ်အဆင့်"</string>
     <string name="yes" msgid="6686215078709381643">"ဟုတ်ပါသည်"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
index 9e62e9e..010d711 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-ta/strings.xml
@@ -18,15 +18,15 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="4531685026837318886">"DeviceDiagnostics"</string>
-    <string name="app_title" msgid="2766786539301072967">"Device diagnostics"</string>
+    <string name="app_title" msgid="2766786539301072967">"சாதனத் திறன் கண்டறிதல்"</string>
     <string name="activity_continue" msgid="2190118984182069151">"தொடர்க"</string>
     <string name="proceed" msgid="8922926495095369132">"தொடர்க"</string>
     <string name="unavailable" msgid="7842920330665850121">"இல்லை"</string>
     <string name="bluetooth_connecting" msgid="7966802493158307502">"இணைக்கிறது..."</string>
     <string name="component_health_title" msgid="6177813132789269842">"காம்பனென்ட் நிலை"</string>
-    <string name="component_health_summary" msgid="2799337555706868947">"நேரடிப் பரிசோதனைகளை இயக்கி, பேட்டரியையும் சேமிப்பகத்தின் நிலையையும் பார்க்கவும்"</string>
+    <string name="component_health_summary" msgid="2799337555706868947">"நீங்களாகப் பரிசோதனைகளை இயக்கி, பேட்டரி மற்றும் சேமிப்பகத்தின் நிலையைப் பார்க்கலாம்"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"மதிப்பீட்டுப் பயன்முறை"</string>
-    <string name="evaluation_mode_summary" msgid="7327453519906858863">"ஒரு சாதனத்தைப் பயன்படுத்தி மற்றொரு சாதனத்தை மதிப்பிடவும்"</string>
+    <string name="evaluation_mode_summary" msgid="7327453519906858863">"ஒரு சாதனத்தைப் பயன்படுத்தி மற்றொரு சாதனத்தை மதிப்பிடலாம்"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"நேரடிப் பரிசோதனைகள்"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"டிஸ்ப்ளே பரிசோதனை"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"டச் சென்சார் பரிசோதனை"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-te/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-te/strings.xml
index dc42cb9..e12822b 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-te/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-te/strings.xml
@@ -26,20 +26,20 @@
     <string name="component_health_title" msgid="6177813132789269842">"కాంపోనెంట్ హెల్త్"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"మాన్యువల్ పరీక్షలను రన్ చేయండి, బ్యాటరీ, స్టోరేజ్ హెల్త్‌ను చూడండి"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"ఎవాల్యుయేషన్ మోడ్"</string>
-    <string name="evaluation_mode_summary" msgid="7327453519906858863">"మరొక పరికరాన్ని అంచనా వేయడానికి ఒక పరికరాన్ని ఉపయోగించండి"</string>
+    <string name="evaluation_mode_summary" msgid="7327453519906858863">"మరొక డివైజ్‌‌ను అంచనా వేయడానికి ఒక డివైజ్‌‌ను ఉపయోగించండి"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"మాన్యువల్ టెస్ట్‌లు"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"డిస్‌ప్లే టెస్ట్"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"టచ్ టెస్ట్"</string>
     <string name="component_title" msgid="6580046234562555655">"కాంపోనెంట్ స్టేటస్"</string>
     <string name="storage_title" msgid="5921235202250843966">"స్టోరేజ్ స్టేటస్"</string>
     <string name="battery_title" msgid="6707361668941323259">"బ్యాటరీ స్టేటస్"</string>
-    <string name="trusted_device_title" msgid="6291497999963968533">"విశ్వసనీయ పరికరం"</string>
-    <string name="eval_mode_trusted_device_summary" msgid="8217291325895255590">"మరొక పరికరాన్ని అంచనా వేయండి. ఇంటర్నెట్ కనెక్షన్ అవసరం."</string>
-    <string name="evaluated_device_title" msgid="5546625787928257821">"ఎవాల్యుయేట్ అయిన పరికరం"</string>
-    <string name="eval_mode_evaluated_device_summary" msgid="3636314493314426253">"మరొక పరికరం ద్వారా వాలిడేట్ చేసే సమస్య విశ్లేషణల టెస్ట్‌లను రన్ చేయండి."</string>
+    <string name="trusted_device_title" msgid="6291497999963968533">"విశ్వసనీయ డివైజ్"</string>
+    <string name="eval_mode_trusted_device_summary" msgid="8217291325895255590">"మరొక డివైజ్‌‌ను అంచనా వేయండి. ఇంటర్నెట్ కనెక్షన్ అవసరం."</string>
+    <string name="evaluated_device_title" msgid="5546625787928257821">"ఎవాల్యుయేట్ అయిన డివైజ్‌‌"</string>
+    <string name="eval_mode_evaluated_device_summary" msgid="3636314493314426253">"మరొక డివైజ్‌‌ ద్వారా వాలిడేట్ చేసే సమస్య విశ్లేషణల టెస్ట్‌లను రన్ చేయండి."</string>
     <string name="evaluated_scan_now" msgid="5413803134686672845">"ఇప్పుడే స్కాన్ చేయండి"</string>
     <string name="evaluated_scan_now_summary" msgid="4225756086513777639">"దిగువున ఉన్న దీర్ఘచతురస్రాకారంలో, విశ్వసనీయ పరికరంతో QR కోడ్‌ను స్కాన్ చేయండి"</string>
-    <string name="evaluated_scan_continue_summary" msgid="4316722493724296922">"మీరు QR కోడ్‌ను విజయవంతంగా స్కాన్ చేసిన తర్వాత, ఈ పరికరం ఆటోమేటిక్‌గా కొన్ని టెస్ట్‌లను ప్రారంభిస్తుంది."</string>
+    <string name="evaluated_scan_continue_summary" msgid="4316722493724296922">"మీరు QR కోడ్‌ను విజయవంతంగా స్కాన్ చేసిన తర్వాత, ఈ డివైజ్ ఆటోమేటిక్‌గా కొన్ని టెస్ట్‌లను ప్రారంభిస్తుంది."</string>
     <string name="evaluated_scan_select_device_title" msgid="7981800769200920339">"విశ్వసనీయ పరికరాన్ని ఎంచుకోండి"</string>
     <string name="evaluated_scan_select_device_summary" msgid="1455560796129881500">"ప్రత్యామ్నాయంగా, దిగువున ఉన్న లిస్ట్ నుండి పరికరాన్ని ఎంచుకోండి"</string>
     <string name="evaluated_bt_fail_title" msgid="4085858793778843205">"కనెక్షన్ విఫలమైంది, దయచేసి మళ్లీ ట్రై చేయండి."</string>
@@ -89,14 +89,14 @@
     <string name="pass" msgid="6411665547268368837">"పాస్"</string>
     <string name="fail" msgid="3918028202746427731">"విఫలమైంది"</string>
     <string name="attestation_verified" msgid="6535873137799452259">"వెరిఫై చేయబడిన సర్టిఫికెట్"</string>
-    <string name="attestation_device_locked" msgid="1423476869833029478">"పరికరం లాక్ చేయబడింది"</string>
+    <string name="attestation_device_locked" msgid="1423476869833029478">"డివైజ్ లాక్ చేయబడింది"</string>
     <string name="attestation_verified_boot_state" msgid="6360953823092860181">"వెరిఫై చేయబడిన బూట్ స్టేట్"</string>
     <string name="attestation_security_level" msgid="6633918464653325429">"సెక్యూరిటీ స్థాయి"</string>
     <string name="attestation_keymaster_version" msgid="7041962401293637901">"కీమాస్టర్ వెర్షన్"</string>
     <string name="attestation_keymaster_security_level" msgid="6412203863981781483">"కీమాస్టర్ సెక్యూరిటీ స్థాయి"</string>
     <string name="attestation_os_version" msgid="4351993398048033601">"OS వెర్షన్"</string>
     <string name="attestation_brand" msgid="5238699762448331155">"బ్రాండ్"</string>
-    <string name="attestation_device" msgid="1984309818766961098">"పరికరం"</string>
+    <string name="attestation_device" msgid="1984309818766961098">"డివైజ్"</string>
     <string name="attestation_product" msgid="7325714994397112640">"ప్రోడక్ట్"</string>
     <string name="attestation_serial" msgid="5001580041093391656">"సీరియల్ నంబర్"</string>
     <string name="attestation_imei" msgid="8985230697018835192">"IMEI"</string>
@@ -118,12 +118,12 @@
     <string name="imei2_title" msgid="4414064408324667040">"రెండవ IMEI"</string>
     <string name="serial_number_title" msgid="1361280023487536604">"సీరియల్ నంబర్"</string>
     <string name="bootloader_locked_title" msgid="4498089738937695995">"బూట్‌లోడర్ లాక్ చేయబడింది"</string>
-    <string name="trustworthy_title" msgid="5360267928618795351">"పరికరం విశ్వసనీయమైనది"</string>
+    <string name="trustworthy_title" msgid="5360267928618795351">"డివైజ్ విశ్వసనీయమైనది"</string>
     <string name="display_status_title" msgid="7827806798539639832">"డిస్‌ప్లే స్టేటస్"</string>
     <string name="touch_sensor_status_title" msgid="5595027618553558639">"టచ్ సెన్సార్ స్టేటస్"</string>
     <string name="attestation_details_title" msgid="7637645023797408279">"అటెస్టేషన్ వివరాలు"</string>
     <string name="attestation_local_failure_title" msgid="3071623434519219695">"అటెస్టేషన్ విఫలమైంది"</string>
-    <string name="attestation_local_failure_summary" msgid="8657460343196696219">"పరికరం విశ్వసనీయమైనదో కాదో నిర్ధారించడం సాధ్యం కాలేదు"</string>
+    <string name="attestation_local_failure_summary" msgid="8657460343196696219">"డివైజ్ విశ్వసనీయమైనదో కాదో నిర్ధారించడం సాధ్యం కాలేదు"</string>
     <string name="attestation_remote_failure_title" msgid="8025019568951127574">"అటెస్టేషన్‌ను మళ్లీ ట్రై చేయండి"</string>
     <string name="attestation_remote_failure_summary" msgid="4213703209008514612">"అటెస్టేషన్ వెరిఫికేషన్ విఫలమైంది, మీ కనెక్షన్‌ను చెక్ చేసి, మళ్లీ ట్రై చేయండి."</string>
     <string name="evaluate_mode_next_action_title" msgid="5476169052061576163">"తర్వాతి దశలు"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values-uz/strings.xml b/DeviceDiagnosticsLib/src/main/res/values-uz/strings.xml
index fc361bd..ccd3bed 100644
--- a/DeviceDiagnosticsLib/src/main/res/values-uz/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values-uz/strings.xml
@@ -23,14 +23,14 @@
     <string name="proceed" msgid="8922926495095369132">"Davom etish"</string>
     <string name="unavailable" msgid="7842920330665850121">"Mavjud emas"</string>
     <string name="bluetooth_connecting" msgid="7966802493158307502">"Ulanmoqda..."</string>
-    <string name="component_health_title" msgid="6177813132789269842">"Komponent ahvoli"</string>
+    <string name="component_health_title" msgid="6177813132789269842">"Tarkibiy qismlar ahvoli"</string>
     <string name="component_health_summary" msgid="2799337555706868947">"Batareya va xotira holatini koʻrish uchun testlarni mustaqil ishga tushiring"</string>
     <string name="evaluation_mode_title" msgid="5845218248059550975">"Baholash rejimi"</string>
     <string name="evaluation_mode_summary" msgid="7327453519906858863">"Boshqa qurilmada ochishda bitta qurilmadan foydalaning"</string>
     <string name="manual_eval_title" msgid="4335717606581762762">"Qoʻlda bajariladigan testlar"</string>
     <string name="screen_test_title" msgid="2748510049598105155">"Displey testi"</string>
     <string name="touch_test_title" msgid="4347784874948129736">"Sensor testi"</string>
-    <string name="component_title" msgid="6580046234562555655">"Komponent holati"</string>
+    <string name="component_title" msgid="6580046234562555655">"Tarkibiy qismlar holati"</string>
     <string name="storage_title" msgid="5921235202250843966">"Xotira holati"</string>
     <string name="battery_title" msgid="6707361668941323259">"Batareya holati"</string>
     <string name="trusted_device_title" msgid="6291497999963968533">"Ishonchli qurilma"</string>
diff --git a/DeviceDiagnosticsLib/src/main/res/values/strings.xml b/DeviceDiagnosticsLib/src/main/res/values/strings.xml
index df81948..b055437 100644
--- a/DeviceDiagnosticsLib/src/main/res/values/strings.xml
+++ b/DeviceDiagnosticsLib/src/main/res/values/strings.xml
@@ -86,6 +86,7 @@
   <string name="battery_health_overheat">Overheat</string>
   <string name="battery_health_over_voltage">Over voltage</string>
 
+
   <!-- Storage screen -->
   <string name="storage_health_title">Storage health</string>
   <string name="storage_total_capacity_title">Total capacity</string>
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 0dbba98..9e3a49e 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -4,7 +4,7 @@
       "name": "DeviceDiagnosticsTests"
     },
     {
-      "name": "tradeinmode_test"
+      "name": "TradeInModeTests"
     }
   ]
 }
diff --git a/TradeInModeTests/Android.bp b/TradeInModeTests/Android.bp
deleted file mode 100644
index 0525232..0000000
--- a/TradeInModeTests/Android.bp
+++ /dev/null
@@ -1,45 +0,0 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-package {
-    default_team: "trendy_team_android_kernel",
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-python_test_host {
-    name: "tradeinmode_test",
-    main: "tradeinmode_test.py",
-    srcs: [
-        "tradeinmode_test.py",
-    ],
-    libs: [
-        "vndk_utils",
-        "vts_kernel_utils",
-        "vts_vndk_utils",
-    ],
-    test_suites: [
-        "device-tests",
-    ],
-    test_options: {
-        unit_test: false,
-    },
-    test_config: "tradeinmode_test.xml",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
-}
diff --git a/TradeInModeTests/tradeinmode_test.py b/TradeInModeTests/tradeinmode_test.py
deleted file mode 100644
index ad092d9..0000000
--- a/TradeInModeTests/tradeinmode_test.py
+++ /dev/null
@@ -1,102 +0,0 @@
-#!/usr/bin/env python
-#
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-import json
-import os
-import time
-import unittest
-
-from vts.testcases.kernel.utils import adb
-from vts.testcases.vndk import utils
-
-class TradeInModeTest(unittest.TestCase):
-
-    def setUp(self):
-        serial_number = os.environ.get("ANDROID_SERIAL")
-        self.assertTrue(serial_number, "$ANDROID_SERIAL is empty.")
-        self.dut = utils.AndroidDevice(serial_number)
-        self.adb = adb.ADB(serial_number)
-        self.buildType = self.dut.Execute("getprop ro.build.type")[0].strip()
-
-    def userBuild(self):
-        if (self.buildType == "user"):
-          return True
-        self.assertTrue(self.buildType in ["userdebug", "eng"])
-        return False
-
-    def reboot(self):
-        self.adb.Execute(["reboot"])
-        try:
-          self.adb.Execute(["wait-for-device"], timeout=900)
-        except self.adb.AdbError as e:
-          self.fail("Exception thrown waiting for device:" + e.msg())
-        for i in range(300):
-          out, err, return_code = self.dut.Execute("getprop sys.boot_completed")
-          if "1" in out:
-            return
-          time.sleep(1)
-        self.fail("Did not boot completely")
-
-    def testEnterTradeInMode(self):
-        if (self.userBuild()):
-          return
-
-        out, err, return_code = self.dut.Execute("su root setprop persist.adb.tradeinmode 1")
-        self.assertEqual(return_code, 0, "Failed to set tradeinmode property")
-        out, err, return_code = self.dut.Execute("su root setprop ctl.restart adbd")
-        self.assertEqual(return_code, 255, "Failed to restart adbd")
-
-        for i in range(30):
-          out, err, return_code = self.dut.Execute("tradeinmode getstatus")
-          if return_code == 0:
-            break
-          time.sleep(1)
-
-        self.assertEquals(return_code, 0, "Failed to getstatus")
-        j = json.loads(out[out.find('{'):])
-        self.assertTrue("serial" in j)
-
-        out, err, return_code = self.dut.Execute("touch /data/local/tmp/tim")
-        self.assertEqual(return_code, 1, "Used shell in TIM foyer")
-
-        # Enter evaluation mode. This can return either 0 (success) or 255 (adb disconnected)
-        # depending on whether the tool returns before adb restarts or not.
-        out, err, return_code = self.dut.Execute("tradeinmode evaluate")
-        self.assertIn(return_code, [0, 255], "Failed to enter evaluation mode")
-
-        for i in range(30):
-          out, err, return_code = self.dut.Execute("touch /data/local/tmp/tim")
-          if return_code == 0:
-            break
-          time.sleep(1)
-        self.assertEqual(return_code, 0, "Failed to use shell")
-        out, err, return_code = self.dut.Execute("ls /data/local/tmp")
-        self.assertEqual(return_code, 0, "Failed to ls tmp dir")
-        self.assertTrue("tim" in out, "Failed to create tim file")
-
-        self.reboot()
-
-        out, err, return_code = self.dut.Execute("su root am start -a com.android.setupwizard.EXIT")
-        self.assertEqual(return_code, 0, "Failed to skip setup wizard")
-        out, err, return_code = self.dut.Execute("ls /data/local/tmp")
-        self.assertEqual(return_code, 0, "Failed to ls tmp dir")
-        self.assertFalse("tim" in out, "Failed to wipe device")
-
-if __name__ == "__main__":
-    # Setting verbosity is required to generate output that the TradeFed test
-    # runner can parse.
-    unittest.main(verbosity=3)
diff --git a/tradeinmode/tests/Android.bp b/tradeinmode/tests/Android.bp
new file mode 100644
index 0000000..e42e932
--- /dev/null
+++ b/tradeinmode/tests/Android.bp
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2025 Google LLC.
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
+    default_team: "trendy_team_android_kernel",
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "vendor_xts_license"
+    // to get the below license kinds:
+    //   legacy_proprietary
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+}
+
+java_library_host {
+    name: "tradeinmode_test_lib",
+    srcs: ["lib/**/*.kt"],
+    libs: [
+        "compatibility-host-util",
+        "tradefed",
+    ],
+}
+
+java_test_host {
+    name: "TradeInModeTests",
+    srcs: ["src/**/*.kt"],
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "compatibility-host-util",
+        "tradefed",
+    ],
+    static_libs: [
+        "tradeinmode_test_lib",
+    ],
+    test_config: "TradeInModeTestCases.xml",
+}
diff --git a/TradeInModeTests/tradeinmode_test.xml b/tradeinmode/tests/TradeInModeTestCases.xml
similarity index 55%
rename from TradeInModeTests/tradeinmode_test.xml
rename to tradeinmode/tests/TradeInModeTestCases.xml
index 7ffc95e..20e16e4 100644
--- a/TradeInModeTests/tradeinmode_test.xml
+++ b/tradeinmode/tests/TradeInModeTestCases.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2024 The Android Open Source Project
+<!-- Copyright (C) 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,9 +13,13 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Config to run tradeinmode_test unittests">
-    <test class="com.android.tradefed.testtype.python.PythonBinaryHostTest" >
-        <option name="par-file-name" value="tradeinmode_test" />
-        <option name="test-timeout" value="10m" />
+<configuration description="Config for Trade-in Mode test cases">
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-suite-tag" value="tradeinmode" />
+    <option name="config-descriptor:metadata" key="parameter" value="all_foldable_states" />
+    <test class="com.android.compatibility.common.tradefed.testtype.JarHostTest" >
+      <option name="jar" value="TradeInModeTests.jar" />
+      <option name="runtime-hint" value="300s" />
     </test>
 </configuration>
+
diff --git a/tradeinmode/tests/lib/com/android/tradeinmode/TradeInModeTestBase.kt b/tradeinmode/tests/lib/com/android/tradeinmode/TradeInModeTestBase.kt
new file mode 100644
index 0000000..c1ae1b6
--- /dev/null
+++ b/tradeinmode/tests/lib/com/android/tradeinmode/TradeInModeTestBase.kt
@@ -0,0 +1,335 @@
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
+
+package com.android.tradeinmode
+
+import com.android.compatibility.common.util.FeatureUtil
+import com.android.ddmlib.TimeoutException
+import com.android.tradefed.device.ITestDevice
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test
+import com.android.tradefed.util.CommandResult
+import com.android.tradefed.util.CommandStatus
+import com.android.tradefed.util.RunUtil
+import com.google.common.io.Files
+import java.io.File
+import kotlin.time.DurationUnit
+import kotlin.time.TimeSource
+import kotlin.time.toDuration
+import org.json.JSONObject
+import org.junit.After
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertFalse
+import org.junit.Assert.assertNotEquals
+import org.junit.Assert.assertTrue
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+
+private val ONE_MINUTE_MS: Long = 1000 * 60
+public val DEVICE_BOOT_TIMEOUT_MS: Long = 5 * ONE_MINUTE_MS
+public val PAUSE_MS: Long = 6000
+
+/** Tests trade-in mode functionality. */
+@RunWith(DeviceJUnit4ClassRunner::class)
+abstract class TradeInModeTestBase : BaseHostJUnit4Test() {
+    protected lateinit var mDevice: ITestDevice
+
+    @Before
+    public fun setUp() {
+        mDevice = getDevice()
+    }
+
+    @After
+    public fun tearDown() {
+        restoreDevice()
+    }
+
+    @Test
+    public fun checkGetStatusFlow() {
+        if (!shouldTestTradeInMode()) {
+            return
+        }
+
+        val hasTelephony = FeatureUtil.hasTelephony(mDevice)
+
+        enterTradeInMode()
+
+        // Normal shell commands should not work.
+        var result = mDevice.executeShellV2Command("ls -l /")
+        assertNotEquals(result.getExitCode(), 0)
+
+        result = mDevice.executeShellV2Command("tradeinmode wait-until-ready getstatus")
+        assertEquals(result.getExitCode(), 0)
+
+        val root = JSONObject(result.getStdout())
+        checkGetStatus(root, hasTelephony)
+    }
+
+    @Test
+    public fun checkEvaluateFlow() {
+        if (!shouldTestTradeInMode()) {
+            return
+        }
+
+        enterTradeInMode()
+
+        // Normal shell commands should not work.
+        var result = mDevice.executeShellV2Command("stat /")
+        assertNotEquals(result.getExitCode(), 0)
+
+        result = mDevice.executeShellV2Command("tradeinmode wait-until-ready evaluate")
+        RunUtil.getDefault().sleep(PAUSE_MS)
+        mDevice.waitForDeviceOnline()
+
+        // Normal shell commands should work now.
+        result = mDevice.executeShellV2Command("stat /")
+        assertEquals(result.getExitCode(), 0)
+
+        // Wait for the "settings" service to be online.
+        waitForCommandService("settings")
+
+        // Setup should be complete.
+        assertEquals(getSettingInt("global", "device_provisioned", 0), 1)
+        assertEquals(getSettingInt("secure", "user_setup_complete", 0), 1)
+
+        // Create a temporary file and validate that it exists.
+        val tempData = "test string"
+        val tempFile = File.createTempFile("tradeinmode", ".placeholder")
+        tempFile.deleteOnExit()
+        Files.write(tempData.toByteArray(Charsets.UTF_8), tempFile)
+        val remotePath = "/data/local/tmp/" + tempFile.getName()
+        mDevice.pushFile(tempFile, remotePath)
+        assertEquals(mDevice.executeShellCommand("cat " + remotePath), tempData)
+
+        // Reboot. A wipe should have been performed and the file should be gone.
+        mDevice.rebootUntilOnline()
+        result = mDevice.executeShellV2Command("cat " + remotePath)
+        assertNotEquals(result.getExitCode(), 0)
+
+        // We should be back in SUW.
+        assertEquals(getSettingInt("global", "device_provisioned", 0), 0)
+        assertEquals(getSettingInt("secure", "user_setup_complete", 0), 0)
+    }
+
+    // This checks that tradeinmode evaluate works in userdebug, without
+    // specifically enabling TIM. We don't need an explicit userdebug
+    // check since our tests are never run on non-root devices, so the
+    // same test will work on user builds with ro.debuggable=1.
+    @Test
+    public fun checkUserdebugEvaluateFlow() {
+        if (!shouldTestTradeInMode()) {
+            return
+        }
+
+        performWipe()
+
+        // Normal shell commands should work.
+        var result = mDevice.executeShellV2Command("stat /")
+        assertEquals(result.getExitCode(), 0)
+
+        // SUW should be active.
+        assertEquals(getSettingInt("global", "device_provisioned", 0), 0)
+        assertEquals(getSettingInt("secure", "user_setup_complete", 0), 0)
+
+        result = mDevice.executeShellV2Command("tradeinmode wait-until-ready evaluate")
+        RunUtil.getDefault().sleep(PAUSE_MS)
+        mDevice.waitForDeviceOnline()
+
+        // Wait for the "settings" service to be online.
+        waitForCommandService("settings")
+
+        // Setup should be complete.
+        assertEquals(getSettingInt("global", "device_provisioned", 0), 1)
+        assertEquals(getSettingInt("secure", "user_setup_complete", 0), 1)
+
+        // Create a temporary file and validate that it exists.
+        val tempData = "test string"
+        val tempFile = File.createTempFile("tradeinmode", ".placeholder")
+        tempFile.deleteOnExit()
+        Files.write(tempData.toByteArray(Charsets.UTF_8), tempFile)
+        val remotePath = "/data/local/tmp/" + tempFile.getName()
+        mDevice.pushFile(tempFile, remotePath)
+        assertEquals(mDevice.executeShellCommand("cat " + remotePath), tempData)
+
+        // Reboot. A wipe should have been performed and the file should be gone.
+        mDevice.rebootUntilOnline()
+        result = mDevice.executeShellV2Command("cat " + remotePath)
+        assertNotEquals(result.getExitCode(), 0)
+
+        // We should be back in SUW.
+        assertEquals(getSettingInt("global", "device_provisioned", 0), 0)
+        assertEquals(getSettingInt("secure", "user_setup_complete", 0), 0)
+    }
+
+    public fun checkGetStatus(root: JSONObject, hasTelephony: Boolean) {
+        assertTrue(root.has("serial"))
+        assertNotEquals(root.getString("serial"), "")
+        assertTrue(root.has("launch_level"))
+        assertTrue(root.getInt("launch_level") > 0)
+
+        assertTrue(root.has("product"))
+        val product = root.getJSONObject("product")
+        assertTrue(product.has("brand"))
+        assertTrue(product.has("manufacturer"))
+        assertTrue(product.has("model"))
+        assertTrue(product.optString("brand") != "")
+        assertTrue(product.optString("manufacturer") != "")
+        assertTrue(product.optString("model") != "")
+
+        assertTrue(root.has("storage"))
+        val storage = root.getJSONObject("storage")
+        assertTrue(storage.has("capacity_bytes"))
+        assertTrue(storage.optLong("capacity_bytes") > 0)
+        if (storage.has("useful_lifetime_remaining")) {
+            assertTrue(storage.optInt("useful_lifetime_remaining") > 0)
+        }
+
+        assertTrue(root.has("battery"))
+        val battery = root.getJSONObject("battery")
+        assertTrue(battery.optInt("cycle_count") >= 0)
+        assertTrue(battery.optInt("health") >= 0)
+        assertTrue(battery.has("state"))
+        if (battery.has("manufacturing_date")) {
+            assertTrue(battery.optInt("manufacturing_date") > 0)
+        }
+        if (battery.has("first_usage_date")) {
+            assertTrue(battery.optInt("first_usage_date") > 0)
+        }
+        assertTrue(battery.optInt("state") > 0)
+        if (battery.has("part_status")) {
+            assertTrue(battery.optString("part_status") != "")
+        }
+        if (battery.has("serial")) {
+            assertTrue(battery.optString("serial") != "")
+        }
+
+        if (root.has("sensors")) {
+            val sensors = root.getJSONObject("sensors")
+            if (sensors.has("moisture_intrusion")) {
+                assertTrue(sensors.optBoolean("moisture_intrusion"))
+            }
+        }
+
+        assertTrue(root.has("locks"))
+        val locks = root.getJSONObject("locks")
+        assertFalse(locks.getBoolean("factory_reset_protection"))
+
+        if (hasTelephony) {
+            assertTrue(root.has("imeis"))
+            val imeis = root.getJSONArray("imeis")
+            assertNotEquals(imeis.length(), 0)
+            assertFalse(imeis.getString(0).isEmpty())
+        }
+    }
+
+    protected fun enterTradeInMode() {
+        performWipe()
+
+        // Second reboot to put adbd into trade-in mode. We set a property to
+        // detect whether the reboot already happened or not. This is purely
+        // for the test harness and has nothing to do with the actual trade-in
+        // mode functionality.
+        mDevice.setProperty("debug.tradeinmode", "1")
+        assertTrue(mDevice.startTradeInModeTesting(DEVICE_BOOT_TIMEOUT_MS.toInt()))
+        waitForDevice({ !inRecovery() && device.getProperty("debug.tradeinmode") != "1" })
+    }
+
+    protected fun performWipe() {
+        // Initial reboot to wipe the device.
+        val result = mDevice.executeShellV2Command("tradeinmode wait-until-ready testing wipe")
+        if (!checkFlakyCommandResult(result)) {
+            throw AssertionError("failed to wipe device for trade-in mode")
+        }
+
+        RunUtil.getDefault().sleep(PAUSE_MS)
+        waitForDevice({ !inRecovery() })
+    }
+
+    protected fun waitForDevice(cond: () -> Boolean) {
+        val start = TimeSource.Monotonic.markNow()
+        val end = start + DEVICE_BOOT_TIMEOUT_MS.toDuration(DurationUnit.MILLISECONDS)
+        while (true) {
+            if (cond()) {
+                return
+            }
+            val now = TimeSource.Monotonic.markNow()
+            if (now > end) {
+                throw TimeoutException("Timed out waiting to leave recovery")
+            }
+            RunUtil.getDefault().sleep(PAUSE_MS)
+            mDevice.waitForDeviceOnline((end - now).inWholeMilliseconds)
+        }
+    }
+
+    protected fun inRecovery(): Boolean {
+        if (device.getProperty("init.svc.running") == "running") {
+            return true
+        }
+        if (device.getProperty("ro.boot.mode") == "recovery") {
+            return true
+        }
+        return false
+    }
+
+    abstract fun shouldTestTradeInMode(): Boolean
+
+    protected fun isTradeInModeSupported(): Boolean {
+        return !FeatureUtil.isTV(mDevice) &&
+            !FeatureUtil.isWatch(mDevice) &&
+            !FeatureUtil.isAutomotive(mDevice)
+    }
+
+    protected fun restoreDevice() {
+        val result = mDevice.executeShellCommand("tradeinmode wait-until-ready testing status")
+
+        if (result.trim().equals("testing")) {
+            mDevice.stopTradeInModeTesting()
+        }
+    }
+
+    protected fun checkFlakyCommandResult(result: CommandResult): Boolean {
+        if (CommandStatus.SUCCESS.equals(result.getStatus())) {
+            return true
+        }
+        // If the device disconnects adb too fast, the exit code can be 255.
+        if (CommandStatus.FAILED.equals(result.getStatus())) {
+            if (result.getExitCode() == 255) {
+                return true
+            }
+        }
+        return false
+    }
+
+    private fun waitForCommandService(cmd: String) {
+        val services = mDevice.executeShellCommand("cmd -l")
+        for (i in 1..10) {
+            if (services.contains(" $cmd")) {
+                break
+            }
+            RunUtil.getDefault().sleep(PAUSE_MS)
+        }
+    }
+
+    private fun getSettingInt(namespace: String, key: String, defaultValue: Int): Int {
+        try {
+            val result = mDevice.getSetting(namespace, key)
+            return result.toInt()
+        } catch (e: NumberFormatException) {
+            return defaultValue
+        }
+    }
+}
diff --git a/tradeinmode/tests/src/com/android/tradeinmode/Tests.kt b/tradeinmode/tests/src/com/android/tradeinmode/Tests.kt
new file mode 100644
index 0000000..74127ae
--- /dev/null
+++ b/tradeinmode/tests/src/com/android/tradeinmode/Tests.kt
@@ -0,0 +1,41 @@
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
+
+package com.android.tradeinmode
+
+import com.android.compatibility.common.util.FeatureUtil
+import org.json.JSONObject
+import org.junit.Assert.assertEquals
+import org.junit.Test
+
+class UserdebugTradeInModeTests : TradeInModeTestBase() {
+    @Test
+    public fun testDeveloperGetStatus() {
+        if (!shouldTestTradeInMode()) {
+            return
+        }
+
+        val result = mDevice.executeShellV2Command("tradeinmode wait-until-ready getstatus")
+        assertEquals(result.getExitCode(), 0)
+
+        val root = JSONObject(result.getStdout())
+        checkGetStatus(root, FeatureUtil.hasTelephony(mDevice))
+    }
+
+    override fun shouldTestTradeInMode(): Boolean {
+        return isTradeInModeSupported()
+    }
+}
```

