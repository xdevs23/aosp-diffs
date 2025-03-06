```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 4a419f0..5749621 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -39,7 +39,4 @@ apex {
     apps: [
         "QualifiedNetworksService",
     ],
-    java_libs: [
-        "TelephonyStatsLib",
-    ],
 }
diff --git a/services/QualifiedNetworksService/src/com/android/telephony/qns/IwlanNetworkStatusTracker.java b/services/QualifiedNetworksService/src/com/android/telephony/qns/IwlanNetworkStatusTracker.java
index 1377077..cef9690 100644
--- a/services/QualifiedNetworksService/src/com/android/telephony/qns/IwlanNetworkStatusTracker.java
+++ b/services/QualifiedNetworksService/src/com/android/telephony/qns/IwlanNetworkStatusTracker.java
@@ -29,6 +29,7 @@ import android.net.NetworkSpecifier;
 import android.net.TelephonyNetworkSpecifier;
 import android.net.TransportInfo;
 import android.net.vcn.VcnTransportInfo;
+import android.net.vcn.VcnUtils;
 import android.os.Handler;
 import android.os.HandlerThread;
 import android.os.Looper;
@@ -192,7 +193,7 @@ class IwlanNetworkStatusTracker {
                     specifier = nc.getNetworkSpecifier();
                     TransportInfo transportInfo = nc.getTransportInfo();
                     if (transportInfo instanceof VcnTransportInfo) {
-                        activeDataSub = ((VcnTransportInfo) transportInfo).getSubId();
+                        activeDataSub = VcnUtils.getSubIdFromVcnCaps(mConnectivityManager, nc);
                     } else if (specifier instanceof TelephonyNetworkSpecifier) {
                         activeDataSub = ((TelephonyNetworkSpecifier) specifier).getSubscriptionId();
                     }
@@ -476,7 +477,8 @@ class IwlanNetworkStatusTracker {
                         NetworkSpecifier specifier = nc.getNetworkSpecifier();
                         TransportInfo transportInfo = nc.getTransportInfo();
                         if (transportInfo instanceof VcnTransportInfo) {
-                            mConnectedDataSub = ((VcnTransportInfo) transportInfo).getSubId();
+                            mConnectedDataSub =
+                                    VcnUtils.getSubIdFromVcnCaps(mConnectivityManager, nc);
                         } else if (specifier instanceof TelephonyNetworkSpecifier) {
                             mConnectedDataSub =
                                     ((TelephonyNetworkSpecifier) specifier).getSubscriptionId();
@@ -563,7 +565,7 @@ class IwlanNetworkStatusTracker {
                     NetworkSpecifier specifier = nc.getNetworkSpecifier();
                     TransportInfo transportInfo = nc.getTransportInfo();
                     if (transportInfo instanceof VcnTransportInfo) {
-                        activeDataSub = ((VcnTransportInfo) transportInfo).getSubId();
+                        activeDataSub = VcnUtils.getSubIdFromVcnCaps(mConnectivityManager, nc);
                     } else if (specifier instanceof TelephonyNetworkSpecifier) {
                         activeDataSub = ((TelephonyNetworkSpecifier) specifier).getSubscriptionId();
                     }
diff --git a/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/IwlanNetworkStatusTrackerTest.java b/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/IwlanNetworkStatusTrackerTest.java
index 9a41a6f..801411f 100644
--- a/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/IwlanNetworkStatusTrackerTest.java
+++ b/services/QualifiedNetworksService/tests/src/com/android/telephony/qns/IwlanNetworkStatusTrackerTest.java
@@ -41,6 +41,7 @@ import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 
+import java.util.Collections;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
@@ -211,12 +212,25 @@ public class IwlanNetworkStatusTrackerTest extends QnsTest {
         assertTrue(mIwlanAvailabilityInfo.isCrossWfc());
     }
 
+    static Network newCellNetwork(ConnectivityManager connectivityMgr, int subId) {
+        Network cellNetwork = mock(Network.class);
+        NetworkCapabilities caps =
+                new NetworkCapabilities.Builder()
+                        .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
+                        .setNetworkSpecifier(new TelephonyNetworkSpecifier(subId))
+                        .build();
+        when(connectivityMgr.getNetworkCapabilities(cellNetwork)).thenReturn(caps);
+        return cellNetwork;
+    }
+
     private void prepareNetworkCapabilitiesForTest(int subId, boolean isVcn) {
         NetworkCapabilities.Builder builder =
                 new NetworkCapabilities.Builder()
                         .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR);
         if (isVcn) {
-            builder.setTransportInfo(new VcnTransportInfo(subId));
+            Network underlyingCell = newCellNetwork(mMockConnectivityManager, subId);
+            builder.setTransportInfo(new VcnTransportInfo.Builder().build())
+                    .setUnderlyingNetworks(Collections.singletonList(underlyingCell));
         } else {
             builder.setNetworkSpecifier(new TelephonyNetworkSpecifier(subId));
         }
```

