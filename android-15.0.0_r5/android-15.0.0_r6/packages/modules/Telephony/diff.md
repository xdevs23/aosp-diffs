```diff
diff --git a/libs/TelephonyStatsLib/Android.bp b/libs/TelephonyStatsLib/Android.bp
index 11a4cbd..10a1159 100644
--- a/libs/TelephonyStatsLib/Android.bp
+++ b/libs/TelephonyStatsLib/Android.bp
@@ -35,9 +35,9 @@ android_test {
         "tests/**/*.java",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
diff --git a/services/QualifiedNetworksService/Android.bp b/services/QualifiedNetworksService/Android.bp
index addebd8..0e78894 100644
--- a/services/QualifiedNetworksService/Android.bp
+++ b/services/QualifiedNetworksService/Android.bp
@@ -45,8 +45,8 @@ android_app {
         "telephony-common",
         "ims-common",
         "framework-annotations-lib",
-        "framework-connectivity",
-        "framework-wifi",
+        "framework-connectivity.stubs.module_lib",
+        "framework-wifi.stubs.module_lib",
     ],
 
     plugins: ["auto_value_plugin"],
@@ -83,11 +83,11 @@ android_test {
         ":statslog-qns-java-gen",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
         "ims-common",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "androidx.appcompat_appcompat",
diff --git a/services/QualifiedNetworksService/src/com/android/telephony/qns/QnsCarrierConfigManager.java b/services/QualifiedNetworksService/src/com/android/telephony/qns/QnsCarrierConfigManager.java
index ac5b561..496907e 100644
--- a/services/QualifiedNetworksService/src/com/android/telephony/qns/QnsCarrierConfigManager.java
+++ b/services/QualifiedNetworksService/src/com/android/telephony/qns/QnsCarrierConfigManager.java
@@ -62,10 +62,10 @@ import java.lang.annotation.RetentionPolicy;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
-import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Locale;
+import java.util.Map;
 import java.util.Set;
 import java.util.stream.Collectors;
 
@@ -682,40 +682,31 @@ class QnsCarrierConfigManager {
     public static final String KEY_QNS_CELLULAR_SIGNAL_STRENGTH_HYSTERESIS_DB_STRING_ARRAY =
             "qns.cellular_signal_strength_hysteresis_db_string_array";
 
-    static HashMap<Integer, String> sAccessNetworkMap =
-            new HashMap<>() {
-                {
-                    put(AccessNetworkConstants.AccessNetworkType.EUTRAN, "eutran");
-                    put(AccessNetworkConstants.AccessNetworkType.UTRAN, "utran");
-                    put(AccessNetworkConstants.AccessNetworkType.NGRAN, "ngran");
-                    put(AccessNetworkConstants.AccessNetworkType.GERAN, "geran");
-                    put(AccessNetworkConstants.AccessNetworkType.IWLAN, "wifi");
-                }
-            };
-
-    static HashMap<Integer, String> sMeasTypeMap =
-            new HashMap<>() {
-                {
-                    put(SIGNAL_MEASUREMENT_TYPE_RSRP, "rsrp");
-                    put(SIGNAL_MEASUREMENT_TYPE_RSRQ, "rsrq");
-                    put(SIGNAL_MEASUREMENT_TYPE_RSSNR, "rssnr");
-                    put(SIGNAL_MEASUREMENT_TYPE_SSRSRP, "ssrsrp");
-                    put(SIGNAL_MEASUREMENT_TYPE_SSRSRQ, "ssrsrq");
-                    put(SIGNAL_MEASUREMENT_TYPE_SSSINR, "sssinr");
-                    put(SIGNAL_MEASUREMENT_TYPE_RSCP, "rscp");
-                    put(SIGNAL_MEASUREMENT_TYPE_RSSI, "rssi");
-                    put(SIGNAL_MEASUREMENT_TYPE_ECNO, "ecno");
-                }
-            };
-
-    static HashMap<Integer, String> sCallTypeMap =
-            new HashMap<>() {
-                {
-                    put(QnsConstants.CALL_TYPE_IDLE, "idle");
-                    put(QnsConstants.CALL_TYPE_VOICE, "voice");
-                    put(QnsConstants.CALL_TYPE_VIDEO, "video");
-                }
-            };
+    private static final Map<Integer, String> sAccessNetworkMap = Map.of(
+            AccessNetworkConstants.AccessNetworkType.EUTRAN, "eutran",
+            AccessNetworkConstants.AccessNetworkType.UTRAN, "utran",
+            AccessNetworkConstants.AccessNetworkType.NGRAN, "ngran",
+            AccessNetworkConstants.AccessNetworkType.GERAN, "geran",
+            AccessNetworkConstants.AccessNetworkType.IWLAN, "wifi"
+    );
+
+    private static final Map<Integer, String> sMeasTypeMap = Map.of(
+            SIGNAL_MEASUREMENT_TYPE_RSRP, "rsrp",
+            SIGNAL_MEASUREMENT_TYPE_RSRQ, "rsrq",
+            SIGNAL_MEASUREMENT_TYPE_RSSNR, "rssnr",
+            SIGNAL_MEASUREMENT_TYPE_SSRSRP, "ssrsrp",
+            SIGNAL_MEASUREMENT_TYPE_SSRSRQ, "ssrsrq",
+            SIGNAL_MEASUREMENT_TYPE_SSSINR, "sssinr",
+            SIGNAL_MEASUREMENT_TYPE_RSCP, "rscp",
+            SIGNAL_MEASUREMENT_TYPE_RSSI, "rssi",
+            SIGNAL_MEASUREMENT_TYPE_ECNO, "ecno"
+    );
+
+    private static final Map<Integer, String> sCallTypeMap = Map.of(
+            QnsConstants.CALL_TYPE_IDLE, "idle",
+            QnsConstants.CALL_TYPE_VOICE, "voice",
+            QnsConstants.CALL_TYPE_VIDEO, "video"
+    );
 
     private final String mLogTag;
     private final int mSlotIndex;
@@ -2437,14 +2428,12 @@ class QnsCarrierConfigManager {
         return netCapabilities;
     }
 
-    private static HashMap<Integer, String> sRatStringMatcher;
-    static {
-        sRatStringMatcher = new HashMap<>();
-        sRatStringMatcher.put(AccessNetworkConstants.AccessNetworkType.EUTRAN, "LTE");
-        sRatStringMatcher.put(AccessNetworkConstants.AccessNetworkType.NGRAN, "NR");
-        sRatStringMatcher.put(AccessNetworkConstants.AccessNetworkType.UTRAN, "3G");
-        sRatStringMatcher.put(AccessNetworkConstants.AccessNetworkType.GERAN, "2G");
-    }
+    private static final Map<Integer, String> sRatStringMatcher = Map.of(
+            AccessNetworkConstants.AccessNetworkType.EUTRAN, "LTE",
+            AccessNetworkConstants.AccessNetworkType.NGRAN, "NR",
+            AccessNetworkConstants.AccessNetworkType.UTRAN, "3G",
+            AccessNetworkConstants.AccessNetworkType.GERAN, "2G"
+    );
 
     /**
      * This method returns Allowed cellular RAT for IMS
diff --git a/services/QualifiedNetworksService/src/com/android/telephony/qns/RestrictManager.java b/services/QualifiedNetworksService/src/com/android/telephony/qns/RestrictManager.java
index aefa469..18bb076 100644
--- a/services/QualifiedNetworksService/src/com/android/telephony/qns/RestrictManager.java
+++ b/services/QualifiedNetworksService/src/com/android/telephony/qns/RestrictManager.java
@@ -37,7 +37,6 @@ import com.android.telephony.qns.DataConnectionStatusTracker.DataConnectionChang
 
 import java.io.PrintWriter;
 import java.util.ArrayList;
-import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.concurrent.ConcurrentHashMap;
@@ -102,40 +101,39 @@ class RestrictManager {
 
     @VisibleForTesting static final int GUARDING_TIMER_HANDOVER_INIT = 30000;
 
-    static final HashMap<Integer, int[]> sReleaseEventMap =
-            new HashMap<Integer, int[]>() {
-                {
-                    put(
+    static final Map<Integer, int[]> sReleaseEventMap = Map.ofEntries(
+                    Map.entry(
                             RESTRICT_TYPE_GUARDING,
                             new int[] {
                                 RELEASE_EVENT_DISCONNECT, RELEASE_EVENT_WFC_PREFER_MODE_CHANGED
-                            });
-                    put(
+                            }),
+                    Map.entry(
                             RESTRICT_TYPE_RTP_LOW_QUALITY,
-                            new int[] {RELEASE_EVENT_CALL_END, RELEASE_EVENT_WIFI_AP_CHANGED});
-                    put(RESTRICT_TYPE_RESTRICT_IWLAN_IN_CALL, new int[] {RELEASE_EVENT_CALL_END});
-                    put(
+                            new int[] {RELEASE_EVENT_CALL_END, RELEASE_EVENT_WIFI_AP_CHANGED}),
+                    Map.entry(
+                            RESTRICT_TYPE_RESTRICT_IWLAN_IN_CALL,
+                            new int[] {RELEASE_EVENT_CALL_END}),
+                    Map.entry(
                             RESTRICT_TYPE_FALLBACK_TO_WWAN_IMS_REGI_FAIL,
                             new int[] {
                                 RELEASE_EVENT_DISCONNECT, RELEASE_EVENT_IMS_NOT_SUPPORT_RAT
-                            });
-                    put(
+                            }),
+                    Map.entry(
                             RESTRICT_TYPE_FALLBACK_ON_DATA_CONNECTION_FAIL,
                             new int[] {
                                 RELEASE_EVENT_DISCONNECT,
                                 RELEASE_EVENT_WIFI_AP_CHANGED,
                                 RELEASE_EVENT_WFC_PREFER_MODE_CHANGED,
                                 RELEASE_EVENT_IMS_NOT_SUPPORT_RAT
-                            });
-                    put(
+                            }),
+                    Map.entry(
                             RESTRICT_TYPE_FALLBACK_TO_WWAN_RTT_BACKHAUL_FAIL,
                             new int[] {
                                 RELEASE_EVENT_DISCONNECT,
                                 RELEASE_EVENT_WIFI_AP_CHANGED,
                                 RELEASE_EVENT_IMS_NOT_SUPPORT_RAT
-                            });
-                }
-            };
+                            })
+            );
     private static final int[] ignorableRestrictionsOnSingleRat =
             new int[] {
                 RESTRICT_TYPE_GUARDING,
diff --git a/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/AccessNetworkSelectionPolicyBuilderTest.java b/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/AccessNetworkSelectionPolicyBuilderTest.java
index e0131f8..7fa7f49 100644
--- a/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/AccessNetworkSelectionPolicyBuilderTest.java
+++ b/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/AccessNetworkSelectionPolicyBuilderTest.java
@@ -48,8 +48,8 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.stubbing.Answer;
 
 import java.util.ArrayList;
-import java.util.HashMap;
 import java.util.List;
+import java.util.Map;
 
 @RunWith(JUnit4.class)
 public class AccessNetworkSelectionPolicyBuilderTest {
@@ -72,10 +72,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
     static final int GERAN = AccessNetworkType.GERAN;
     static final int IWLAN = AccessNetworkType.IWLAN;
 
-    private HashMap<String, QnsConfigArray> mTestConfigsMap =
-            new HashMap<>() {
-                {
-                    put(
+    private final Map<String, QnsConfigArray> mTestConfigsMap = Map.ofEntries(
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRP
@@ -83,8 +81,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-100, -115, -120));
-                    put(
+                            new QnsConfigArray(-100, -115, -120)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRQ
@@ -92,8 +90,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-10, -15, -20));
-                    put(
+                            new QnsConfigArray(-10, -15, -20)),
+            Map.entry(
                             AccessNetworkType.IWLAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSSI
@@ -101,8 +99,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-75, -85));
-                    put(
+                            new QnsConfigArray(-75, -85)),
+            Map.entry(
                             AccessNetworkType.NGRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_SSRSRP
@@ -110,8 +108,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-102, -117, -122));
-                    put(
+                            new QnsConfigArray(-102, -117, -122)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRP
@@ -119,8 +117,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-95, -110, -115));
-                    put(
+                            new QnsConfigArray(-95, -110, -115)),
+            Map.entry(
                             AccessNetworkType.IWLAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSSI
@@ -128,8 +126,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-76, -86));
-                    put(
+                            new QnsConfigArray(-76, -86)),
+            Map.entry(
                             AccessNetworkType.NGRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_SSRSRP
@@ -137,8 +135,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.WIFI_PREF,
-                            new QnsConfigArray(-92, -102, -112));
-                    put(
+                            new QnsConfigArray(-92, -102, -112)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRP
@@ -146,8 +144,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-103, -118, -123));
-                    put(
+                            new QnsConfigArray(-103, -118, -123)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRQ
@@ -155,8 +153,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-12, -16, -18));
-                    put(
+                            new QnsConfigArray(-12, -16, -18)),
+            Map.entry(
                             AccessNetworkType.IWLAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSSI
@@ -164,8 +162,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-60, -75));
-                    put(
+                            new QnsConfigArray(-60, -75)),
+            Map.entry(
                             AccessNetworkType.NGRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_SSRSRP
@@ -173,8 +171,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_IDLE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-100, -110, -120));
-                    put(
+                            new QnsConfigArray(-100, -110, -120)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRP
@@ -182,8 +180,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-101, -116, -121));
-                    put(
+                            new QnsConfigArray(-101, -116, -121)),
+            Map.entry(
                             AccessNetworkType.EUTRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSRQ
@@ -191,8 +189,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-11, -16, -20));
-                    put(
+                            new QnsConfigArray(-11, -16, -20)),
+            Map.entry(
                             AccessNetworkType.IWLAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_RSSI
@@ -200,8 +198,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-70, -80));
-                    put(
+                            new QnsConfigArray(-70, -80)),
+            Map.entry(
                             AccessNetworkType.NGRAN
                                     + "-"
                                     + SIGNAL_MEASUREMENT_TYPE_SSRSRP
@@ -209,9 +207,8 @@ public class AccessNetworkSelectionPolicyBuilderTest {
                                     + QnsConstants.CALL_TYPE_VOICE
                                     + "-"
                                     + QnsConstants.CELL_PREF,
-                            new QnsConfigArray(-90, -100, -110));
-                }
-            };
+                            new QnsConfigArray(-90, -100, -110))
+    );
 
     @Before
     public void setUp() {
```

