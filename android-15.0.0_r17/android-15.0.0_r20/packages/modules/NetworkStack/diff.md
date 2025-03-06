```diff
diff --git a/Android.bp b/Android.bp
index 8f4997c6..734797a3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -275,11 +275,13 @@ java_defaults {
     ],
     libs: [
         "error_prone_annotations",
+        "framework-annotations-lib",
         "unsupportedappusage",
     ],
     static_libs: [
         "androidx.annotation_annotation",
         "modules-utils-build_system",
+        "modules-utils-expresslog",
         "modules-utils-preconditions",
         "modules-utils-shell-command-handler",
         "modules-utils-statemachine",
diff --git a/apishim/29/com/android/networkstack/apishim/api29/CaptivePortalDataShimImpl.java b/apishim/29/com/android/networkstack/apishim/api29/CaptivePortalDataShimImpl.java
deleted file mode 100644
index 1b2cc781..00000000
--- a/apishim/29/com/android/networkstack/apishim/api29/CaptivePortalDataShimImpl.java
+++ /dev/null
@@ -1,104 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.networkstack.apishim.api29;
-
-import android.net.Uri;
-import android.os.Build;
-
-import androidx.annotation.NonNull;
-import androidx.annotation.RequiresApi;
-import androidx.annotation.VisibleForTesting;
-
-import com.android.networkstack.apishim.common.CaptivePortalDataShim;
-import com.android.networkstack.apishim.common.UnsupportedApiLevelException;
-
-import org.json.JSONException;
-import org.json.JSONObject;
-
-/**
- * Compatibility implementation of {@link CaptivePortalData}.
- *
- * <p>Use {@link com.android.networkstack.apishim.CaptivePortalDataShimImpl} instead of this
- * fallback implementation.
- */
-@RequiresApi(Build.VERSION_CODES.Q)
-public abstract class CaptivePortalDataShimImpl implements CaptivePortalDataShim {
-    protected CaptivePortalDataShimImpl() {}
-
-    /**
-     * Parse a {@link android.net.CaptivePortalDataShim} from JSON.
-     *
-     * <p>Use
-     * {@link com.android.networkstack.apishim.CaptivePortalDataShimImpl#fromJson(JSONObject)}
-     * instead of this API 29 compatibility version.
-     */
-    @NonNull
-    public static CaptivePortalDataShim fromJson(JSONObject object) throws JSONException,
-            UnsupportedApiLevelException {
-        // Data class not supported in API 29
-        throw new UnsupportedApiLevelException("CaptivePortalData not supported on API 29");
-    }
-
-    @Override
-    public CharSequence getVenueFriendlyName() {
-        // Not supported in API level 29
-        return null;
-    }
-
-    @Override
-    public int getUserPortalUrlSource() {
-        // Not supported in API level 29
-        return ConstantsShim.CAPTIVE_PORTAL_DATA_SOURCE_OTHER;
-    }
-
-    @VisibleForTesting
-    public static boolean isSupported() {
-        return false;
-    }
-
-    /**
-     * Generate a {@link CaptivePortalDataShim} object with a friendly name set
-     *
-     * @param friendlyName The friendly name to set
-     * @return a {@link CaptivePortalData} object with a friendly name set
-     */
-    @Override
-    public CaptivePortalDataShim withVenueFriendlyName(String friendlyName)
-            throws UnsupportedApiLevelException {
-        // Not supported in API level 29
-        throw new UnsupportedApiLevelException("CaptivePortalData not supported on API 29");
-    }
-
-    /**
-     * Generate a {@link CaptivePortalDataShim} object with a friendly name and Passpoint external
-     * URLs set
-     *
-     * @param friendlyName The friendly name to set
-     * @param venueInfoUrl Venue information URL
-     * @param termsAndConditionsUrl Terms and conditions URL
-     *
-     * @return a {@link CaptivePortalDataShim} object with friendly name, venue info URL and terms
-     * and conditions URL set
-     */
-    @Override
-    public CaptivePortalDataShim withPasspointInfo(@NonNull String friendlyName,
-            @NonNull Uri venueInfoUrl, @NonNull Uri termsAndConditionsUrl)
-            throws UnsupportedApiLevelException {
-        // Not supported in API level 29
-        throw new UnsupportedApiLevelException("CaptivePortalData not supported on API 29");
-    }
-}
diff --git a/apishim/29/com/android/networkstack/apishim/api29/BroadcastOptionsShimImpl.java b/apishim/30/com/android/networkstack/apishim/api30/BroadcastOptionsShimImpl.java
similarity index 97%
rename from apishim/29/com/android/networkstack/apishim/api29/BroadcastOptionsShimImpl.java
rename to apishim/30/com/android/networkstack/apishim/api30/BroadcastOptionsShimImpl.java
index ab58dc28..2db73c0e 100644
--- a/apishim/29/com/android/networkstack/apishim/api29/BroadcastOptionsShimImpl.java
+++ b/apishim/30/com/android/networkstack/apishim/api30/BroadcastOptionsShimImpl.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.networkstack.apishim.api29;
+package com.android.networkstack.apishim.api30;
 
 import android.app.BroadcastOptions;
 import android.os.Build;
diff --git a/apishim/30/com/android/networkstack/apishim/api30/CaptivePortalDataShimImpl.java b/apishim/30/com/android/networkstack/apishim/api30/CaptivePortalDataShimImpl.java
index 8dce1706..d84bb524 100644
--- a/apishim/30/com/android/networkstack/apishim/api30/CaptivePortalDataShimImpl.java
+++ b/apishim/30/com/android/networkstack/apishim/api30/CaptivePortalDataShimImpl.java
@@ -22,12 +22,10 @@ import android.net.Uri;
 import android.os.Build;
 import android.os.RemoteException;
 
-import androidx.annotation.ChecksSdkIntAtLeast;
 import androidx.annotation.NonNull;
 import androidx.annotation.RequiresApi;
 
 import com.android.networkstack.apishim.common.CaptivePortalDataShim;
-import com.android.networkstack.apishim.common.ShimUtils;
 import com.android.networkstack.apishim.common.UnsupportedApiLevelException;
 
 import org.json.JSONException;
@@ -37,8 +35,7 @@ import org.json.JSONObject;
  * Compatibility implementation of {@link CaptivePortalDataShim}.
  */
 @RequiresApi(Build.VERSION_CODES.R)
-public class CaptivePortalDataShimImpl
-        extends com.android.networkstack.apishim.api29.CaptivePortalDataShimImpl {
+public class CaptivePortalDataShimImpl implements CaptivePortalDataShim {
     @NonNull
     protected final CaptivePortalData mData;
 
@@ -53,16 +50,9 @@ public class CaptivePortalDataShimImpl
     /**
      * Parse a {@link CaptivePortalDataShim} from a JSON object.
      * @throws JSONException The JSON is not a representation of correct captive portal data.
-     * @throws UnsupportedApiLevelException CaptivePortalData is not available on this API level.
      */
-    @RequiresApi(Build.VERSION_CODES.Q)
     @NonNull
-    public static CaptivePortalDataShim fromJson(JSONObject obj) throws JSONException,
-            UnsupportedApiLevelException {
-        if (!isSupported()) {
-            return com.android.networkstack.apishim.api29.CaptivePortalDataShimImpl.fromJson(obj);
-        }
-
+    public static CaptivePortalDataShim fromJson(JSONObject obj) throws JSONException {
         final long refreshTimeMs = System.currentTimeMillis();
         final long secondsRemaining = getLongOrDefault(obj, "seconds-remaining", -1L);
         final long millisRemaining = secondsRemaining <= Long.MAX_VALUE / 1000
@@ -81,10 +71,8 @@ public class CaptivePortalDataShimImpl
                 .build());
     }
 
-    @RequiresApi(Build.VERSION_CODES.Q)
-    @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.R)
     public static boolean isSupported() {
-        return ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q);
+        return true;
     }
 
     private static long getLongOrDefault(JSONObject o, String key, long def) throws JSONException {
@@ -122,6 +110,18 @@ public class CaptivePortalDataShimImpl
         return mData.getVenueInfoUrl();
     }
 
+    @Override
+    public CharSequence getVenueFriendlyName() {
+        // Not supported in API level 30
+        return null;
+    }
+
+    @Override
+    public int getUserPortalUrlSource() {
+        // Not supported in API level 30
+        return ConstantsShim.CAPTIVE_PORTAL_DATA_SOURCE_OTHER;
+    }
+
     @Override
     public void notifyChanged(INetworkMonitorCallbacks cb) throws RemoteException {
         cb.notifyCaptivePortalDataChanged(mData);
diff --git a/apishim/33/com/android/networkstack/apishim/api33/BroadcastOptionsShimImpl.java b/apishim/33/com/android/networkstack/apishim/api33/BroadcastOptionsShimImpl.java
index 5e38766b..87c8e947 100644
--- a/apishim/33/com/android/networkstack/apishim/api33/BroadcastOptionsShimImpl.java
+++ b/apishim/33/com/android/networkstack/apishim/api33/BroadcastOptionsShimImpl.java
@@ -31,7 +31,7 @@ import com.android.networkstack.apishim.common.BroadcastOptionsShim;
  */
 @RequiresApi(Build.VERSION_CODES.TIRAMISU)
 public class BroadcastOptionsShimImpl
-        extends com.android.networkstack.apishim.api29.BroadcastOptionsShimImpl {
+        extends com.android.networkstack.apishim.api30.BroadcastOptionsShimImpl {
     protected BroadcastOptionsShimImpl(@NonNull BroadcastOptions options) {
         super(options);
     }
@@ -42,7 +42,7 @@ public class BroadcastOptionsShimImpl
     @RequiresApi(Build.VERSION_CODES.TIRAMISU)
     public static BroadcastOptionsShim newInstance(@NonNull BroadcastOptions options) {
         if (!isAtLeastT()) {
-            return com.android.networkstack.apishim.api29.BroadcastOptionsShimImpl.newInstance(
+            return com.android.networkstack.apishim.api30.BroadcastOptionsShimImpl.newInstance(
                     options);
         }
         return new BroadcastOptionsShimImpl(options);
diff --git a/apishim/common/com/android/networkstack/apishim/common/ShimUtils.java b/apishim/common/com/android/networkstack/apishim/common/ShimUtils.java
index 648751b8..a7bf9218 100644
--- a/apishim/common/com/android/networkstack/apishim/common/ShimUtils.java
+++ b/apishim/common/com/android/networkstack/apishim/common/ShimUtils.java
@@ -43,13 +43,6 @@ public final class ShimUtils {
         return devApiLevel > apiLevel;
     }
 
-    /**
-     * Check whether the device supports in-development or final R networking APIs.
-     */
-    public static boolean isAtLeastR() {
-        return isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q);
-    }
-
     /**
      * Check whether the device supports in-development or final S networking APIs.
      */
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 2267cd43..5e227182 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -21,6 +21,6 @@
     <string name="notification_channel_name_network_venue_info" msgid="6526543187249265733">"מידע על מקום הרשת"</string>
     <string name="notification_channel_description_network_venue_info" msgid="5131499595382733605">"התראות המוצגות כדי לציין שלרשת יש דף מידע על מקום"</string>
     <string name="connected" msgid="4563643884927480998">"המכשיר מחובר"</string>
-    <string name="tap_for_info" msgid="6849746325626883711">"מחוברת / יש להקיש כדי להציג את האתר"</string>
+    <string name="tap_for_info" msgid="6849746325626883711">"מחוברת / יש ללחוץ כדי להציג את האתר"</string>
     <string name="application_label" msgid="1322847171305285454">"ניהול רשתות"</string>
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index 16364d6b..8d6b64e3 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -61,6 +61,10 @@
 
     <!-- Configuration for including DHCP client hostname option -->
     <bool name="config_dhcp_client_hostname">false</bool>
+    <!-- Customized preferred properties for filling DHCP client hostname option,
+    replacing the default device name (Dependent on config_dhcp_client_hostname is true).-->
+    <string-array name="config_dhcp_client_hostname_preferred_props" translatable="false">
+    </string-array>
 
     <!-- Customized neighbor unreachable probe parameters. -->
     <integer name="config_nud_steadystate_solicit_num">10</integer>
diff --git a/res/values/overlayable.xml b/res/values/overlayable.xml
index 08a27786..0aeaaec7 100644
--- a/res/values/overlayable.xml
+++ b/res/values/overlayable.xml
@@ -46,7 +46,8 @@
             <!-- Configuration value for DhcpResults -->
             <item type="array" name="config_default_dns_servers"/>
             <!-- Configuration for including DHCP client hostname option.
-            If this option is true, client hostname set in Settings.Global.DEVICE_NAME will be
+            If this option is true, client hostname set in Settings.Global.DEVICE_NAME
+            (default value, if config_dhcp_client_hostname_preferred_props is not set) will be
             included in DHCPDISCOVER/DHCPREQUEST, otherwise, the DHCP hostname option will not
             be sent. RFC952 and RFC1123 stipulates an valid hostname should be only comprised of
             'a-z', 'A-Z' and '-', and the length should be up to 63 octets or less (RFC1035#2.3.4),
@@ -55,6 +56,17 @@
             random number and etc.
             -->
             <item type="bool" name="config_dhcp_client_hostname"/>
+            <!-- Customized preferred properties for filling DHCP client hostname option,
+            replacing the default device name (Dependent on config_dhcp_client_hostname is true).
+            If this value is set, the DHCP hostname option will be filled in with the value of
+            the first property in the list that is not empty. Otherwise, the DHCP hostname option
+            will be filled in with the device name set in Settings.Global.DEVICE_NAME.
+            For example:
+            <item>ro.product.model</item>
+            <item>ro.product.name</item>
+            -->
+            <item type="array" name="config_dhcp_client_hostname_preferred_props"/>
+
             <!-- Customized neighbor unreachable probe parameters.
             Legal config_*_num value should be in the range of 5-15; and config_*_interval value
             should be in the range of 750-1000ms.
diff --git a/src/android/net/apf/AndroidPacketFilter.java b/src/android/net/apf/AndroidPacketFilter.java
index c88587b3..c9f8abaf 100644
--- a/src/android/net/apf/AndroidPacketFilter.java
+++ b/src/android/net/apf/AndroidPacketFilter.java
@@ -120,4 +120,9 @@ public interface AndroidPacketFilter {
     default boolean shouldEnableMdnsOffload() {
         return false;
     }
+
+    /**
+     * Update the multicast addresses that will be used by APF.
+     */
+    default void updateIPv4MulticastAddrs() {}
 }
diff --git a/src/android/net/apf/ApfCounterTracker.java b/src/android/net/apf/ApfCounterTracker.java
index 9700b5bc..5bd98777 100644
--- a/src/android/net/apf/ApfCounterTracker.java
+++ b/src/android/net/apf/ApfCounterTracker.java
@@ -102,6 +102,10 @@ public class ApfCounterTracker {
         DROPPED_ARP_REQUEST_REPLIED,
         DROPPED_ARP_UNKNOWN,
         DROPPED_ARP_V6_ONLY,
+        DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED,
+        DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED,
+        DROPPED_IGMP_INVALID,
+        DROPPED_IGMP_REPORT,
         DROPPED_GARP_REPLY;  // see also MAX_DROP_COUNTER below
 
         /**
diff --git a/src/android/net/apf/ApfFilter.java b/src/android/net/apf/ApfFilter.java
index 90bd8324..52b80ba3 100644
--- a/src/android/net/apf/ApfFilter.java
+++ b/src/android/net/apf/ApfFilter.java
@@ -93,6 +93,7 @@ import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS;
+import static android.net.apf.ApfCounterTracker.getCounterValue;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
@@ -161,7 +162,6 @@ import android.util.Log;
 import android.util.Pair;
 import android.util.SparseArray;
 
-import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.HexDump;
 import com.android.internal.util.IndentingPrintWriter;
@@ -260,29 +260,18 @@ public class ApfFilter implements AndroidPacketFilter {
     public final byte[] mHardwareAddress;
     private final RaPacketReader mRaPacketReader;
     private final Handler mHandler;
-    @GuardedBy("this")
-    private long mUniqueCounter;
-    @GuardedBy("this")
     private boolean mMulticastFilter;
-    @GuardedBy("this")
     private boolean mInDozeMode;
     private final boolean mDrop802_3Frames;
     private final int[] mEthTypeBlackList;
 
     private final ApfCounterTracker mApfCounterTracker = new ApfCounterTracker();
-    @GuardedBy("this")
     private final long mSessionStartMs;
-    @GuardedBy("this")
     private int mNumParseErrorRas = 0;
-    @GuardedBy("this")
     private int mNumZeroLifetimeRas = 0;
-    @GuardedBy("this")
     private int mLowestRouterLifetimeSeconds = Integer.MAX_VALUE;
-    @GuardedBy("this")
     private long mLowestPioValidLifetimeSeconds = Long.MAX_VALUE;
-    @GuardedBy("this")
     private long mLowestRioRouteLifetimeSeconds = Long.MAX_VALUE;
-    @GuardedBy("this")
     private long mLowestRdnssLifetimeSeconds = Long.MAX_VALUE;
 
     // Ignore non-zero RDNSS lifetimes below this value.
@@ -351,22 +340,21 @@ public class ApfFilter implements AndroidPacketFilter {
     private boolean mIsApfShutdown;
 
     // Our IPv4 address, if we have just one, otherwise null.
-    @GuardedBy("this")
     private byte[] mIPv4Address;
     // The subnet prefix length of our IPv4 network. Only valid if mIPv4Address is not null.
-    @GuardedBy("this")
     private int mIPv4PrefixLength;
 
     // Our IPv6 non-tentative addresses
-    @GuardedBy("this")
     private Set<Inet6Address> mIPv6NonTentativeAddresses = new ArraySet<>();
 
     // Our tentative IPv6 addresses
-    @GuardedBy("this")
     private Set<Inet6Address> mIPv6TentativeAddresses = new ArraySet<>();
 
+    // Our joined IPv4 multicast addresses
+    @VisibleForTesting
+    public Set<Inet4Address> mIPv4MulticastAddresses = new ArraySet<>();
+
     // Whether CLAT is enabled.
-    @GuardedBy("this")
     private boolean mHasClat;
 
     // mIsRunning is reflects the state of the ApfFilter during integration tests. ApfFilter can be
@@ -417,7 +405,7 @@ public class ApfFilter implements AndroidPacketFilter {
                 new Dependencies(context));
     }
 
-    private synchronized void maybeCleanUpApfRam() {
+    private void maybeCleanUpApfRam() {
         // Clear the APF memory to reset all counters upon connecting to the first AP
         // in an SSID. This is limited to APFv3 devices because this large write triggers
         // a crash on some older devices (b/78905546).
@@ -480,11 +468,9 @@ public class ApfFilter implements AndroidPacketFilter {
 
         mHardwareAddress = mInterfaceParams.macAddr.toByteArray();
         // TODO: ApfFilter should not generate programs until IpClient sends provisioning success.
-        synchronized (this) {
-            maybeCleanUpApfRam();
-            // Install basic filters
-            installNewProgramLocked();
-        }
+        maybeCleanUpApfRam();
+        // Install basic filters
+        installNewProgram();
 
         mRaPacketReader = new RaPacketReader(mHandler, mInterfaceParams.index);
         // The class constructor must be called from the IpClient's handler thread
@@ -621,10 +607,18 @@ public class ApfFilter implements AndroidPacketFilter {
         public int getNdTrafficClass(@NonNull String ifname) {
             return ProcfsParsingUtils.getNdTrafficClass(ifname);
         }
+
+        /**
+         * Loads the existing IPv4 multicast addresses from the file
+         * `/proc/net/igmp`.
+         */
+        public List<Inet4Address> getIPv4MulticastAddresses(@NonNull String ifname) {
+            return ProcfsParsingUtils.getIPv4MulticastAddresses(ifname);
+        }
     }
 
     @Override
-    public synchronized String setDataSnapshot(byte[] data) {
+    public String setDataSnapshot(byte[] data) {
         mDataSnapshot = data;
         if (mIsRunning) {
             mApfCounterTracker.updateCountersFromData(data);
@@ -636,11 +630,6 @@ public class ApfFilter implements AndroidPacketFilter {
         Log.d(TAG, "(" + mInterfaceParams.name + "): " + s);
     }
 
-    @GuardedBy("this")
-    private long getUniqueNumberLocked() {
-        return mUniqueCounter++;
-    }
-
     private static int[] filterEthTypeBlackList(int[] ethTypeBlackList) {
         ArrayList<Integer> bl = new ArrayList<>();
 
@@ -670,8 +659,7 @@ public class ApfFilter implements AndroidPacketFilter {
     }
 
     // Returns seconds since device boot.
-    @VisibleForTesting
-    protected int secondsSinceBoot() {
+    private int secondsSinceBoot() {
         return (int) (mDependencies.elapsedRealtime() / DateUtils.SECOND_IN_MILLIS);
     }
 
@@ -1113,7 +1101,7 @@ public class ApfFilter implements AndroidPacketFilter {
                     case 4: lft = getUint32(newRa.mPacket, section.start); break;
                 }
 
-                // WARNING: keep this in sync with Ra#generateFilterLocked()!
+                // WARNING: keep this in sync with Ra#generateFilter()!
                 if (section.lifetime == 0) {
                     // Case 1) old lft == 0
                     if (section.min > 0) {
@@ -1215,8 +1203,7 @@ public class ApfFilter implements AndroidPacketFilter {
 
         // Append a filter for this RA to {@code gen}. Jump to DROP_LABEL if it should be dropped.
         // Jump to the next filter if packet doesn't match this RA.
-        @GuardedBy("ApfFilter.this")
-        void generateFilterLocked(ApfV4GeneratorBase<?> gen, int timeSeconds)
+        void generateFilter(ApfV4GeneratorBase<?> gen, int timeSeconds)
                 throws IllegalInstructionException {
             String nextFilterLabel = gen.getUniqueLabel();
             // Skip if packet is not the right size
@@ -1316,7 +1303,7 @@ public class ApfFilter implements AndroidPacketFilter {
         // Append a filter for this keepalive ack to {@code gen}.
         // Jump to drop if it matches the keepalive ack.
         // Jump to the next filter if packet doesn't match the keepalive ack.
-        abstract void generateFilterLocked(ApfV4GeneratorBase<?> gen)
+        abstract void generateFilter(ApfV4GeneratorBase<?> gen)
                 throws IllegalInstructionException;
     }
 
@@ -1359,8 +1346,7 @@ public class ApfFilter implements AndroidPacketFilter {
         }
 
         @Override
-        @GuardedBy("ApfFilter.this")
-        void generateFilterLocked(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
+        void generateFilter(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
             final String nextFilterLabel = gen.getUniqueLabel();
 
             gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
@@ -1461,7 +1447,7 @@ public class ApfFilter implements AndroidPacketFilter {
         // Append a filter for this keepalive ack to {@code gen}.
         // Jump to drop if it matches the keepalive ack.
         // Jump to the next filter if packet doesn't match the keepalive ack.
-        abstract void generateFilterLocked(ApfV4GeneratorBase<?> gen)
+        abstract void generateFilter(ApfV4GeneratorBase<?> gen)
                 throws IllegalInstructionException;
     }
 
@@ -1475,8 +1461,7 @@ public class ApfFilter implements AndroidPacketFilter {
         }
 
         @Override
-        @GuardedBy("ApfFilter.this")
-        void generateFilterLocked(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
+        void generateFilter(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
             final String nextFilterLabel = gen.getUniqueLabel();
 
             gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
@@ -1518,7 +1503,7 @@ public class ApfFilter implements AndroidPacketFilter {
         }
 
         @Override
-        void generateFilterLocked(ApfV4GeneratorBase<?> gen) {
+        void generateFilter(ApfV4GeneratorBase<?> gen) {
             throw new UnsupportedOperationException("IPv6 TCP Keepalive is not supported yet");
         }
     }
@@ -1526,11 +1511,8 @@ public class ApfFilter implements AndroidPacketFilter {
     // Maximum number of RAs to filter for.
     private static final int MAX_RAS = 10;
 
-    @GuardedBy("this")
     private final ArrayList<Ra> mRas = new ArrayList<>();
-    @GuardedBy("this")
     private final SparseArray<KeepalivePacket> mKeepalivePackets = new SparseArray<>();
-    @GuardedBy("this")
     // TODO: change the mMdnsAllowList to proper type for APFv6 based mDNS offload
     private final List<String[]> mMdnsAllowList = new ArrayList<>();
 
@@ -1540,14 +1522,11 @@ public class ApfFilter implements AndroidPacketFilter {
     private static final int FRACTION_OF_LIFETIME_TO_FILTER = 6;
 
     // When did we last install a filter program? In seconds since Unix Epoch.
-    @GuardedBy("this")
     private int mLastTimeInstalledProgram;
     // How long should the last installed filter program live for? In seconds.
-    @GuardedBy("this")
     private int mLastInstalledProgramMinLifetime;
 
     // For debugging only. The last program installed.
-    @GuardedBy("this")
     private byte[] mLastInstalledProgram;
 
     /**
@@ -1557,17 +1536,14 @@ public class ApfFilter implements AndroidPacketFilter {
      * IWifiStaIface#readApfPacketFilterData(), and the APF interpreter advertised support for
      * the opcodes to access the data buffer (LDDW and STDW).
      */
-    @GuardedBy("this") @Nullable
+    @Nullable
     private byte[] mDataSnapshot;
 
     // How many times the program was updated since we started.
-    @GuardedBy("this")
     private int mNumProgramUpdates = 0;
     // The maximum program size that updated since we started.
-    @GuardedBy("this")
     private int mMaxProgramSize = 0;
     // The maximum number of distinct RAs
-    @GuardedBy("this")
     private int mMaxDistinctRas = 0;
 
     private ApfV6Generator tryToConvertToApfV6Generator(ApfV4GeneratorBase<?> gen) {
@@ -1583,8 +1559,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * Preconditions:
      *  - Packet being filtered is ARP
      */
-    @GuardedBy("this")
-    private void generateArpFilterLocked(ApfV4GeneratorBase<?> gen)
+    private void generateArpFilter(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         // Here's a basic summary of what the ARP filter program does:
         //
@@ -1695,8 +1670,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * Preconditions:
      *  - Packet being filtered is IPv4
      */
-    @GuardedBy("this")
-    private void generateIPv4FilterLocked(ApfV4GeneratorBase<?> gen)
+    private void generateIPv4Filter(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         // Here's a basic summary of what the IPv4 filter program does:
         //
@@ -1788,7 +1762,7 @@ public class ApfFilter implements AndroidPacketFilter {
         generateV4NattKeepaliveFilters(gen);
 
         // If TCP unicast on port 7, drop
-        generateV4TcpPort7FilterLocked(gen);
+        generateV4TcpPort7Filter(gen);
 
         if (mMulticastFilter) {
             // Otherwise, this is an IPv4 unicast, pass
@@ -1803,7 +1777,6 @@ public class ApfFilter implements AndroidPacketFilter {
         gen.addCountAndPass(Counter.PASSED_IPV4);
     }
 
-    @GuardedBy("this")
     private void generateKeepaliveFilters(ApfV4GeneratorBase<?> gen, Class<?> filterType, int proto,
             int offset, String label) throws IllegalInstructionException {
         final boolean haveKeepaliveResponses = CollectionUtils.any(mKeepalivePackets,
@@ -1819,20 +1792,18 @@ public class ApfFilter implements AndroidPacketFilter {
         // Drop Keepalive responses
         for (int i = 0; i < mKeepalivePackets.size(); ++i) {
             final KeepalivePacket response = mKeepalivePackets.valueAt(i);
-            if (filterType.isInstance(response)) response.generateFilterLocked(gen);
+            if (filterType.isInstance(response)) response.generateFilter(gen);
         }
 
         gen.defineLabel(label);
     }
 
-    @GuardedBy("this")
     private void generateV4KeepaliveFilters(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         generateKeepaliveFilters(gen, TcpKeepaliveAckV4.class, IPPROTO_TCP, IPV4_PROTOCOL_OFFSET,
                 gen.getUniqueLabel());
     }
 
-    @GuardedBy("this")
     private void generateV4NattKeepaliveFilters(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         generateKeepaliveFilters(gen, NattKeepaliveResponse.class,
@@ -1848,7 +1819,6 @@ public class ApfFilter implements AndroidPacketFilter {
         return suffixes;
     }
 
-    @GuardedBy("this")
     private List<byte[]> getIpv6Addresses(
             boolean includeNonTentative, boolean includeTentative, boolean includeAnycast) {
         final List<byte[]> addresses = new ArrayList<>();
@@ -1870,7 +1840,6 @@ public class ApfFilter implements AndroidPacketFilter {
         return addresses;
     }
 
-    @GuardedBy("this")
     private List<byte[]> getKnownMacAddresses() {
         final List<byte[]> addresses = new ArrayList<>();
         addresses.addAll(mDependencies.getEtherMulticastAddresses(mInterfaceParams.name));
@@ -1882,8 +1851,7 @@ public class ApfFilter implements AndroidPacketFilter {
     /**
      * Generate allocate and transmit code to send ICMPv6 non-DAD NA packets.
      */
-    @GuardedBy("this")
-    private void generateNonDadNaTransmitLocked(ApfV6GeneratorBase<?> gen)
+    private void generateNonDadNaTransmit(ApfV6GeneratorBase<?> gen)
             throws IllegalInstructionException {
         final int ipv6PayloadLen = ICMPV6_NA_HEADER_LEN + ICMPV6_ND_OPTION_TLLA_LEN;
         final int pktLen = ETH_HEADER_LEN + IPV6_HEADER_LEN + ipv6PayloadLen;
@@ -1927,8 +1895,7 @@ public class ApfFilter implements AndroidPacketFilter {
         );
     }
 
-    @GuardedBy("this")
-    private void generateNsFilterLocked(ApfV6Generator v6Gen)
+    private void generateNsFilter(ApfV6Generator v6Gen)
             throws IllegalInstructionException {
         final List<byte[]> allIPv6Addrs = getIpv6Addresses(
                 true /* includeNonTentative */,
@@ -2028,7 +1995,7 @@ public class ApfFilter implements AndroidPacketFilter {
         // if multicast MAC in SLLA option -> drop
         v6Gen.addLoad8(R0, ICMP6_NS_OPTION_TYPE_OFFSET + 2)
                 .addCountAndDropIfR0AnyBitsSet(1, DROPPED_IPV6_NS_INVALID);
-        generateNonDadNaTransmitLocked(v6Gen);
+        generateNonDadNaTransmit(v6Gen);
         v6Gen.addCountAndDrop(Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD);
     }
 
@@ -2038,8 +2005,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * Preconditions:
      *  - Packet being filtered is IPv6
      */
-    @GuardedBy("this")
-    private void generateIPv6FilterLocked(ApfV4GeneratorBase<?> gen)
+    private void generateIPv6Filter(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         // Here's a basic summary of what the IPv6 filter program does:
         //
@@ -2133,9 +2099,9 @@ public class ApfFilter implements AndroidPacketFilter {
         if (v6Gen != null && mShouldHandleNdOffload) {
             final String skipNsPacketFilter = v6Gen.getUniqueLabel();
             v6Gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_SOLICITATION, skipNsPacketFilter);
-            generateNsFilterLocked(v6Gen);
-            // End of NS filter. generateNsFilterLocked() method is terminal, so NS packet will be
-            // either dropped or passed inside generateNsFilterLocked().
+            generateNsFilter(v6Gen);
+            // End of NS filter. generateNsFilter() method is terminal, so NS packet will be
+            // either dropped or passed inside generateNsFilter().
             v6Gen.defineLabel(skipNsPacketFilter);
         }
 
@@ -2161,8 +2127,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * Generate filter code to process mDNS packets. Execution of this code ends in * DROP_LABEL
      * or PASS_LABEL if the packet is mDNS packets. Otherwise, skip this check.
      */
-    @GuardedBy("this")
-    private void generateMdnsFilterLocked(ApfV4GeneratorBase<?> gen)
+    private void generateMdnsFilter(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         final String skipMdnsv4Filter = gen.getUniqueLabel();
         final String skipMdnsFilter = gen.getUniqueLabel();
@@ -2237,8 +2202,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * On entry, we know it is IPv4 ethertype, but don't know anything else.
      * R0/R1 have nothing useful in them, and can be clobbered.
      */
-    @GuardedBy("this")
-    private void generateV4TcpPort7FilterLocked(ApfV4GeneratorBase<?> gen)
+    private void generateV4TcpPort7Filter(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         final String skipPort7V4Filter = gen.getUniqueLabel();
 
@@ -2262,7 +2226,6 @@ public class ApfFilter implements AndroidPacketFilter {
         gen.defineLabel(skipPort7V4Filter);
     }
 
-    @GuardedBy("this")
     private void generateV6KeepaliveFilters(ApfV4GeneratorBase<?> gen)
             throws IllegalInstructionException {
         generateKeepaliveFilters(gen, TcpKeepaliveAckV6.class, IPPROTO_TCP, IPV6_NEXT_HEADER_OFFSET,
@@ -2283,15 +2246,13 @@ public class ApfFilter implements AndroidPacketFilter {
      * <li>Pass all non-IPv4 and non-IPv6 packets,
      * <li>Drop IPv6 ICMPv6 NAs to anything in ff02::/120.
      * <li>Drop IPv6 ICMPv6 RSs.
-     * <li>Filter IPv4 packets (see generateIPv4FilterLocked())
-     * <li>Filter IPv6 packets (see generateIPv6FilterLocked())
+     * <li>Filter IPv4 packets (see generateIPv4Filter())
+     * <li>Filter IPv6 packets (see generateIPv6Filter())
      * <li>Let execution continue off the end of the program for IPv6 ICMPv6 packets. This allows
      *     insertion of RA filters here, or if there aren't any, just passes the packets.
      * </ul>
      */
-    @GuardedBy("this")
-    @VisibleForTesting
-    public ApfV4GeneratorBase<?> emitPrologueLocked() throws IllegalInstructionException {
+    private ApfV4GeneratorBase<?> emitPrologue() throws IllegalInstructionException {
         // This is guaranteed to succeed because of the check in maybeCreate.
         ApfV4GeneratorBase<?> gen;
         if (shouldUseApfV6Generator()) {
@@ -2371,17 +2332,17 @@ public class ApfFilter implements AndroidPacketFilter {
         // Add ARP filters:
         String skipArpFiltersLabel = gen.getUniqueLabel();
         gen.addJumpIfR0NotEquals(ETH_P_ARP, skipArpFiltersLabel);
-        generateArpFilterLocked(gen);
+        generateArpFilter(gen);
         gen.defineLabel(skipArpFiltersLabel);
 
         // Add mDNS filter:
-        generateMdnsFilterLocked(gen);
+        generateMdnsFilter(gen);
         gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);
 
         // Add IPv4 filters:
         String skipIPv4FiltersLabel = gen.getUniqueLabel();
         gen.addJumpIfR0NotEquals(ETH_P_IP, skipIPv4FiltersLabel);
-        generateIPv4FilterLocked(gen);
+        generateIPv4Filter(gen);
         gen.defineLabel(skipIPv4FiltersLabel);
 
         // Check for IPv6:
@@ -2398,7 +2359,7 @@ public class ApfFilter implements AndroidPacketFilter {
 
         // Add IPv6 filters:
         gen.defineLabel(ipv6FilterLabel);
-        generateIPv6FilterLocked(gen);
+        generateIPv6Filter(gen);
         return gen;
     }
 
@@ -2408,7 +2369,6 @@ public class ApfFilter implements AndroidPacketFilter {
      * Currently, the epilogue consists of two trampolines which count passed and dropped packets
      * before jumping to the actual PASS and DROP labels.
      */
-    @GuardedBy("this")
     private void emitEpilogue(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
         // Execution will reach here if none of the filters match, which will pass the packet to
         // the application processor.
@@ -2421,10 +2381,8 @@ public class ApfFilter implements AndroidPacketFilter {
     /**
      * Generate and install a new filter program.
      */
-    @GuardedBy("this")
-    @SuppressWarnings("GuardedBy") // errorprone false positive on ra#generateFilterLocked
     @VisibleForTesting
-    public void installNewProgramLocked() {
+    public void installNewProgram() {
         ArrayList<Ra> rasToFilter = new ArrayList<>();
         final byte[] program;
         int programMinLft = Integer.MAX_VALUE;
@@ -2434,7 +2392,7 @@ public class ApfFilter implements AndroidPacketFilter {
             final int timeSeconds = secondsSinceBoot();
             mLastTimeInstalledProgram = timeSeconds;
             // Step 1: Determine how many RA filters we can fit in the program.
-            ApfV4GeneratorBase<?> gen = emitPrologueLocked();
+            ApfV4GeneratorBase<?> gen = emitPrologue();
 
             // The epilogue normally goes after the RA filters, but add it early to include its
             // length when estimating the total.
@@ -2450,7 +2408,7 @@ public class ApfFilter implements AndroidPacketFilter {
             for (Ra ra : mRas) {
                 // skip filter if it has expired.
                 if (ra.getRemainingFilterLft(timeSeconds) <= 0) continue;
-                ra.generateFilterLocked(gen, timeSeconds);
+                ra.generateFilter(gen, timeSeconds);
                 // Stop if we get too big.
                 if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                     if (VDBG) Log.d(TAG, "Past maximum program size, skipping RAs");
@@ -2461,10 +2419,14 @@ public class ApfFilter implements AndroidPacketFilter {
                 rasToFilter.add(ra);
             }
 
+            // Increase the counter before we generate the program.
+            // This keeps the APF_PROGRAM_ID counter in sync with the program.
+            mNumProgramUpdates++;
+
             // Step 2: Actually generate the program
-            gen = emitPrologueLocked();
+            gen = emitPrologue();
             for (Ra ra : rasToFilter) {
-                ra.generateFilterLocked(gen, timeSeconds);
+                ra.generateFilter(gen, timeSeconds);
                 programMinLft = Math.min(programMinLft, ra.getRemainingFilterLft(timeSeconds));
             }
             emitEpilogue(gen);
@@ -2475,15 +2437,12 @@ public class ApfFilter implements AndroidPacketFilter {
             return;
         }
         if (mIsRunning) {
-            // Update data snapshot every time we install a new program
-            mIpClientCallback.startReadPacketFilter("new program install");
             if (!mIpClientCallback.installPacketFilter(program)) {
                 sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
             }
         }
         mLastInstalledProgramMinLifetime = programMinLft;
         mLastInstalledProgram = program;
-        mNumProgramUpdates++;
         mMaxProgramSize = Math.max(mMaxProgramSize, program.length);
 
         if (VDBG) {
@@ -2514,7 +2473,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * if the current APF program should be updated.
      */
     @VisibleForTesting
-    public synchronized void processRa(byte[] packet, int length) {
+    public void processRa(byte[] packet, int length) {
         if (VDBG) hexDump("Read packet = ", packet, length);
 
         final Ra ra;
@@ -2561,7 +2520,7 @@ public class ApfFilter implements AndroidPacketFilter {
 
                 // Rate limit program installation
                 if (mTokenBucket.get()) {
-                    installNewProgramLocked();
+                    installNewProgram();
                 } else {
                     Log.e(TAG, "Failed to install prog for tracked RA, too many updates. " + ra);
                 }
@@ -2580,7 +2539,7 @@ public class ApfFilter implements AndroidPacketFilter {
         mRas.add(0, ra);
         // Rate limit program installation
         if (mTokenBucket.get()) {
-            installNewProgramLocked();
+            installNewProgram();
         } else {
             Log.e(TAG, "Failed to install prog for new RA, too many updates. " + ra);
         }
@@ -2606,7 +2565,7 @@ public class ApfFilter implements AndroidPacketFilter {
                 networkQuirkMetrics);
     }
 
-    private synchronized void collectAndSendMetrics() {
+    private void collectAndSendMetrics() {
         if (mIpClientRaInfoMetrics == null || mApfSessionInfoMetrics == null) return;
         final long sessionDurationMs = mDependencies.elapsedRealtime() - mSessionStartMs;
         if (sessionDurationMs < mMinMetricsSessionDurationMs) return;
@@ -2636,7 +2595,7 @@ public class ApfFilter implements AndroidPacketFilter {
         mApfSessionInfoMetrics.statsWrite();
     }
 
-    public synchronized void shutdown() {
+    public void shutdown() {
         collectAndSendMetrics();
         // The shutdown() must be called from the IpClient's handler thread
         mRaPacketReader.stop();
@@ -2648,22 +2607,17 @@ public class ApfFilter implements AndroidPacketFilter {
         }
     }
 
-    public synchronized void setMulticastFilter(boolean isEnabled) {
+    public void setMulticastFilter(boolean isEnabled) {
         if (mMulticastFilter == isEnabled) return;
         mMulticastFilter = isEnabled;
-        installNewProgramLocked();
+        installNewProgram();
     }
 
     @VisibleForTesting
-    public synchronized void setDozeMode(boolean isEnabled) {
+    public void setDozeMode(boolean isEnabled) {
         if (mInDozeMode == isEnabled) return;
         mInDozeMode = isEnabled;
-        installNewProgramLocked();
-    }
-
-    @VisibleForTesting
-    public synchronized boolean isInDozeMode() {
-        return mInDozeMode;
+        installNewProgram();
     }
 
     /** Retrieve the single IPv4 LinkAddress if there is one, otherwise return null. */
@@ -2706,7 +2660,7 @@ public class ApfFilter implements AndroidPacketFilter {
         return new Pair<>(tentativeAddrs, nonTentativeAddrs);
     }
 
-    public synchronized void setLinkProperties(LinkProperties lp) {
+    public void setLinkProperties(LinkProperties lp) {
         // NOTE: Do not keep a copy of LinkProperties as it would further duplicate state.
         final LinkAddress ipv4Address = retrieveIPv4LinkAddress(lp);
         final byte[] addr = (ipv4Address != null) ? ipv4Address.getAddress().getAddress() : null;
@@ -2726,16 +2680,27 @@ public class ApfFilter implements AndroidPacketFilter {
         mIPv6TentativeAddresses = ipv6Addresses.first;
         mIPv6NonTentativeAddresses = ipv6Addresses.second;
 
-        installNewProgramLocked();
+        installNewProgram();
     }
 
     @Override
-    public synchronized void updateClatInterfaceState(boolean add) {
+    public void updateClatInterfaceState(boolean add) {
         if (mHasClat == add) {
             return;
         }
         mHasClat = add;
-        installNewProgramLocked();
+        installNewProgram();
+    }
+
+    @Override
+    public void updateIPv4MulticastAddrs() {
+        final Set<Inet4Address> mcastAddrs =
+                new ArraySet<>(mDependencies.getIPv4MulticastAddresses(mInterfaceParams.name));
+
+        if (!mIPv4MulticastAddresses.equals(mcastAddrs)) {
+            mIPv4MulticastAddresses = mcastAddrs;
+            installNewProgram();
+        }
     }
 
     @Override
@@ -2761,7 +2726,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * @param slot The index used to access the filter.
      * @param sentKeepalivePacket The attributes of the sent keepalive packet.
      */
-    public synchronized void addTcpKeepalivePacketFilter(final int slot,
+    public void addTcpKeepalivePacketFilter(final int slot,
             final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
         log("Adding keepalive ack(" + slot + ")");
         if (null != mKeepalivePackets.get(slot)) {
@@ -2771,7 +2736,7 @@ public class ApfFilter implements AndroidPacketFilter {
         mKeepalivePackets.put(slot, (ipVersion == 4)
                 ? new TcpKeepaliveAckV4(sentKeepalivePacket)
                 : new TcpKeepaliveAckV6(sentKeepalivePacket));
-        installNewProgramLocked();
+        installNewProgram();
     }
 
     /**
@@ -2781,7 +2746,7 @@ public class ApfFilter implements AndroidPacketFilter {
      * @param slot The index used to access the filter.
      * @param sentKeepalivePacket The attributes of the sent keepalive packet.
      */
-    public synchronized void addNattKeepalivePacketFilter(final int slot,
+    public void addNattKeepalivePacketFilter(final int slot,
             final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
         log("Adding NAT-T keepalive packet(" + slot + ")");
         if (null != mKeepalivePackets.get(slot)) {
@@ -2794,7 +2759,7 @@ public class ApfFilter implements AndroidPacketFilter {
         }
 
         mKeepalivePackets.put(slot, new NattKeepaliveResponse(sentKeepalivePacket));
-        installNewProgramLocked();
+        installNewProgram();
     }
 
     /**
@@ -2802,13 +2767,13 @@ public class ApfFilter implements AndroidPacketFilter {
      *
      * @param slot The index used to access the filter.
      */
-    public synchronized void removeKeepalivePacketFilter(int slot) {
+    public void removeKeepalivePacketFilter(int slot) {
         log("Removing keepalive packet(" + slot + ")");
         mKeepalivePackets.remove(slot);
-        installNewProgramLocked();
+        installNewProgram();
     }
 
-    public synchronized void dump(IndentingPrintWriter pw) {
+    public void dump(IndentingPrintWriter pw) {
         // TODO: use HandlerUtils.runWithScissors() to dump APF on the handler thread.
         pw.println(String.format(
                 "Capabilities: { apfVersionSupported: %d, maximumApfProgramSize: %d }",
@@ -2861,14 +2826,19 @@ public class ApfFilter implements AndroidPacketFilter {
             return;
         }
         pw.println("Program updates: " + mNumProgramUpdates);
+        int filterAgeSeconds = secondsSinceBoot() - mLastTimeInstalledProgram;
         pw.println(String.format(
                 "Last program length %d, installed %ds ago, lifetime %ds",
-                mLastInstalledProgram.length, secondsSinceBoot() - mLastTimeInstalledProgram,
+                mLastInstalledProgram.length, filterAgeSeconds,
                 mLastInstalledProgramMinLifetime));
-
-        pw.print("Denylisted Ethertypes:");
-        for (int p : mEthTypeBlackList) {
-            pw.print(String.format(" %04x", p));
+        if (SdkLevel.isAtLeastV()) {
+            pw.print("Hardcoded Allowlisted Ethertypes:");
+            pw.println(" 0800(IPv4) 0806(ARP) 86DD(IPv6) 888E(EAPOL) 88B4(WAPI)");
+        } else {
+            pw.print("Denylisted Ethertypes:");
+            for (int p : mEthTypeBlackList) {
+                pw.print(String.format(" %04x", p));
+            }
         }
         pw.println();
         pw.println("RA filters:");
@@ -2930,16 +2900,61 @@ public class ApfFilter implements AndroidPacketFilter {
         } else {
             try {
                 Counter[] counters = Counter.class.getEnumConstants();
+                long counterFilterAgeSeconds =
+                        getCounterValue(mDataSnapshot, Counter.FILTER_AGE_SECONDS);
+                long counterApfProgramId =
+                        getCounterValue(mDataSnapshot, Counter.APF_PROGRAM_ID);
                 for (Counter c : Arrays.asList(counters).subList(1, counters.length)) {
-                    long value = ApfCounterTracker.getCounterValue(mDataSnapshot, c);
-                    // Only print non-zero counters
-                    if (value != 0) {
-                        pw.println(c.toString() + ": " + value);
+                    long value = getCounterValue(mDataSnapshot, c);
+
+                    String note = "";
+                    boolean checkValueIncreases = true;
+                    switch (c) {
+                        case FILTER_AGE_SECONDS:
+                            checkValueIncreases = false;
+                            if (value != counterFilterAgeSeconds) {
+                                note = " [ERROR: impossible]";
+                            } else if (counterApfProgramId < mNumProgramUpdates) {
+                                note = " [IGNORE: obsolete program]";
+                            } else if (value > filterAgeSeconds) {
+                                long offset = value - filterAgeSeconds;
+                                note = " [ERROR: in the future by " + offset + "s]";
+                            }
+                            break;
+                        case FILTER_AGE_16384THS:
+                            if (mApfVersionSupported > BaseApfGenerator.APF_VERSION_4) {
+                                checkValueIncreases = false;
+                                if (value % 16384 == 0) {
+                                    // valid, but unlikely
+                                    note = " [INFO: zero fractional portion]";
+                                }
+                                if (value / 16384 != counterFilterAgeSeconds) {
+                                    // should not be able to happen
+                                    note = " [ERROR: mismatch with FILTER_AGE_SECONDS]";
+                                }
+                            } else if (value != 0) {
+                                note = " [UNEXPECTED: APF<=4, yet non-zero]";
+                            }
+                            break;
+                        case APF_PROGRAM_ID:
+                            if (value != counterApfProgramId) {
+                                note = " [ERROR: impossible]";
+                            } else if (value < mNumProgramUpdates) {
+                                note = " [WARNING: OBSOLETE PROGRAM]";
+                            } else if (value > mNumProgramUpdates) {
+                                note = " [ERROR: INVALID FUTURE ID]";
+                            }
+                            break;
+                        default:
+                            break;
+                    }
+
+                    // Only print non-zero counters (or those with a note)
+                    if (value != 0 || !note.equals("")) {
+                        pw.println(c.toString() + ": " + value + note);
                     }
 
-                    final Set<Counter> skipCheckCounters = Set.of(FILTER_AGE_SECONDS,
-                            FILTER_AGE_16384THS);
-                    if (!skipCheckCounters.contains(c)) {
+                    if (checkValueIncreases) {
                         // If the counter's value decreases, it may have been cleaned up or there
                         // may be a bug.
                         long oldValue = mApfCounterTracker.getCounters().getOrDefault(c, 0L);
@@ -2982,7 +2997,7 @@ public class ApfFilter implements AndroidPacketFilter {
     }
 
     /** Return data snapshot as hex string for testing purposes. */
-    public synchronized @Nullable String getDataSnapshotHexString() {
+    public @Nullable String getDataSnapshotHexString() {
         if (mDataSnapshot == null) {
             return null;
         }
diff --git a/src/android/net/apf/ProcfsParsingUtils.java b/src/android/net/apf/ProcfsParsingUtils.java
index 4bac0f80..0d931a7b 100644
--- a/src/android/net/apf/ProcfsParsingUtils.java
+++ b/src/android/net/apf/ProcfsParsingUtils.java
@@ -15,18 +15,23 @@
  */
 package android.net.apf;
 
+import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ALL_HOST_MULTICAST;
+
 import android.annotation.NonNull;
 import android.net.MacAddress;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.internal.util.HexDump;
+import com.android.net.module.util.HexDump;
 
 import java.io.BufferedReader;
 import java.io.IOException;
+import java.net.Inet4Address;
 import java.net.Inet6Address;
 import java.net.InetAddress;
 import java.net.UnknownHostException;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
 import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Paths;
@@ -39,6 +44,7 @@ public final class ProcfsParsingUtils {
     private static final String IPV6_CONF_PATH = "/proc/sys/net/ipv6/conf/";
     private static final String IPV6_ANYCAST_PATH = "/proc/net/anycast6";
     private static final String ETHER_MCAST_PATH = "/proc/net/dev_mcast";
+    private static final String IPV4_MCAST_PATH = "/proc/net/igmp";
     private static final String IPV6_MCAST_PATH = "/proc/net/igmp6";
 
     private ProcfsParsingUtils() {
@@ -172,6 +178,75 @@ public final class ProcfsParsingUtils {
 
         return addresses;
     }
+
+    /**
+     * Parses IPv4 multicast addresses associated with a specific interface from a list of strings.
+     *
+     * @param lines A list of strings, each containing interface and IPv4 address information.
+     * @param ifname The name of the network interface for which to extract multicast addresses.
+     * @param endian The byte order of the address, almost always use native order.
+     * @return A list of Inet4Address objects representing the parsed IPv4 multicast addresses.
+     *         If an error occurs during parsing,
+     *         a list contains IPv4 all host (224.0.0.1) is returned.
+     */
+    @VisibleForTesting
+    public static List<Inet4Address> parseIPv4MulticastAddresses(
+            @NonNull List<String> lines, @NonNull String ifname, @NonNull ByteOrder endian) {
+        final List<Inet4Address> ipAddresses = new ArrayList<>();
+
+        try {
+            String name = "";
+            // parse output similar to `ip maddr` command (iproute2/ip/ipmaddr.c#read_igmp())
+            for (String line : lines) {
+                final String[] parts = line.trim().split("\\s+");
+                if (!line.startsWith("\t")) {
+                    name = parts[1];
+                    if (name.endsWith(":")) {
+                        name = name.substring(0, name.length() - 1);
+                    }
+                    continue;
+                }
+
+                if (!name.equals(ifname)) {
+                    continue;
+                }
+
+                final String hexIp = parts[0];
+                final byte[] ipArray = HexDump.hexStringToByteArray(hexIp);
+                final byte[] convertArray =
+                    (endian == ByteOrder.LITTLE_ENDIAN)
+                        ? convertIPv4BytesToBigEndian(ipArray) : ipArray;
+                final Inet4Address ipv4Address =
+                        (Inet4Address) InetAddress.getByAddress(convertArray);
+
+                ipAddresses.add(ipv4Address);
+            }
+        } catch (UnknownHostException | IllegalArgumentException e) {
+            Log.wtf(TAG, "failed to convert to Inet4Address.", e);
+            // always return IPv4 all host address (224.0.0.1) if any error during parsing.
+            // this aligns with kernel behavior, it will join 224.0.0.1 when the interface is up.
+            ipAddresses.clear();
+            ipAddresses.add(IPV4_ADDR_ALL_HOST_MULTICAST);
+        }
+
+        return ipAddresses;
+    }
+
+    /**
+     * Converts an IPv4 address from little-endian byte order to big-endian byte order.
+     *
+     * @param bytes The IPv4 address in little-endian byte order.
+     * @return The IPv4 address in big-endian byte order.
+     */
+    private static byte[] convertIPv4BytesToBigEndian(byte[] bytes) {
+        final ByteBuffer buffer = ByteBuffer.wrap(bytes);
+        buffer.order(ByteOrder.LITTLE_ENDIAN);
+        final ByteBuffer bigEndianBuffer = ByteBuffer.allocate(4);
+        bigEndianBuffer.order(ByteOrder.BIG_ENDIAN);
+        bigEndianBuffer.putInt(buffer.getInt());
+        return bigEndianBuffer.array();
+    }
+
     /**
      * Returns the traffic class for the specified interface.
      * The function loads the existing traffic class from the file
@@ -228,4 +303,19 @@ public final class ProcfsParsingUtils {
         final List<String> lines = readFile(IPV6_MCAST_PATH);
         return parseIPv6MulticastAddresses(lines, ifname);
     }
+
+    /**
+     * The function loads the existing IPv4 multicast addresses from the file `/proc/net/igmp6`.
+     * If the file does not exist or the interface is not found, the function returns empty list.
+     *
+     * @param ifname The name of the network interface to query.
+     * @return A list of Inet4Address objects representing the IPv4 multicast addresses
+     *         found for the interface.
+     *         If the file cannot be read or there are no addresses, an empty list is returned.
+     */
+    public static List<Inet4Address> getIPv4MulticastAddresses(@NonNull String ifname) {
+        final List<String> lines = readFile(IPV4_MCAST_PATH);
+        // follow the same pattern as NetlinkMonitor#handlePacket() for device's endian order
+        return parseIPv4MulticastAddresses(lines, ifname, ByteOrder.nativeOrder());
+    }
 }
diff --git a/src/android/net/dhcp/DhcpClient.java b/src/android/net/dhcp/DhcpClient.java
index 4b949687..7ef63647 100644
--- a/src/android/net/dhcp/DhcpClient.java
+++ b/src/android/net/dhcp/DhcpClient.java
@@ -81,10 +81,12 @@ import android.os.Handler;
 import android.os.Message;
 import android.os.PowerManager;
 import android.os.SystemClock;
+import android.os.SystemProperties;
 import android.provider.Settings;
 import android.stats.connectivity.DhcpFeature;
 import android.system.ErrnoException;
 import android.system.Os;
+import android.text.TextUtils;
 import android.util.EventLog;
 import android.util.Log;
 import android.util.SparseArray;
@@ -104,7 +106,6 @@ import com.android.net.module.util.NetworkStackConstants;
 import com.android.net.module.util.PacketReader;
 import com.android.net.module.util.arp.ArpPacket;
 import com.android.networkstack.R;
-import com.android.networkstack.apishim.CaptivePortalDataShimImpl;
 import com.android.networkstack.apishim.SocketUtilsShimImpl;
 import com.android.networkstack.metrics.IpProvisioningMetrics;
 import com.android.networkstack.util.NetworkStackUtils;
@@ -308,9 +309,7 @@ public class DhcpClient extends StateMachine {
         final ByteArrayOutputStream params =
                 new ByteArrayOutputStream(DEFAULT_REQUESTED_PARAMS.length + numOptionalParams);
         params.write(DEFAULT_REQUESTED_PARAMS, 0, DEFAULT_REQUESTED_PARAMS.length);
-        if (isCapportApiEnabled()) {
-            params.write(DHCP_CAPTIVE_PORTAL);
-        }
+        params.write(DHCP_CAPTIVE_PORTAL);
         params.write(DHCP_IPV6_ONLY_PREFERRED);
         // Customized DHCP options to be put in PRL.
         for (DhcpOption option : mConfiguration.options) {
@@ -323,10 +322,6 @@ public class DhcpClient extends StateMachine {
         return params.toByteArray();
     }
 
-    private static boolean isCapportApiEnabled() {
-        return CaptivePortalDataShimImpl.isSupported();
-    }
-
     // DHCP flag that means "yes, we support unicast."
     private static final boolean DO_UNICAST   = false;
 
@@ -431,6 +426,31 @@ public class DhcpClient extends StateMachine {
             return context.getResources().getBoolean(R.bool.config_dhcp_client_hostname);
         }
 
+        private boolean isValidCustomHostnameProperty(String prop) {
+            return "ro.product.model".equals(prop)
+                    || "ro.product.name".equals(prop)
+                    || prop.startsWith("ro.vendor.");
+        }
+
+        /**
+         * Get the customized hostname from RRO to fill hostname option.
+         */
+        public String getCustomHostname(final Context context) {
+            final String[] prefHostnameProps = context.getResources().getStringArray(
+                    R.array.config_dhcp_client_hostname_preferred_props);
+            if (prefHostnameProps == null || prefHostnameProps.length == 0) {
+                return getDeviceName(context);
+            }
+            for (final String prop : prefHostnameProps) {
+                if (!isValidCustomHostnameProperty(prop)) continue;
+                String prefHostname = getSystemProperty(prop);
+                if (!TextUtils.isEmpty(prefHostname)) {
+                    return prefHostname;
+                }
+            }
+            return getDeviceName(context);
+        }
+
         /**
          * Get the device name from system settings.
          */
@@ -439,6 +459,13 @@ public class DhcpClient extends StateMachine {
                     Settings.Global.DEVICE_NAME);
         }
 
+        /**
+         * Read a system property.
+         */
+        public String getSystemProperty(String name) {
+            return SystemProperties.get(name, "" /* default*/);
+        }
+
         /**
          * Get a IpMemoryStore instance.
          */
@@ -544,7 +571,7 @@ public class DhcpClient extends StateMachine {
         mRebindAlarm = makeWakeupMessage("REBIND", CMD_REBIND_DHCP);
         mExpiryAlarm = makeWakeupMessage("EXPIRY", CMD_EXPIRE_DHCP);
 
-        mHostname = new HostnameTransliterator().transliterate(deps.getDeviceName(mContext));
+        mHostname = new HostnameTransliterator().transliterate(deps.getCustomHostname(mContext));
         mMetrics.setHostnameTransinfo(deps.getSendHostnameOverlaySetting(context),
                 mHostname != null);
     }
@@ -657,7 +684,6 @@ public class DhcpClient extends StateMachine {
 
     private byte[] getOptionsToSkip() {
         final ByteArrayOutputStream optionsToSkip = new ByteArrayOutputStream(2);
-        if (!isCapportApiEnabled()) optionsToSkip.write(DHCP_CAPTIVE_PORTAL);
         if (!mConfiguration.isWifiManagedProfile) {
             optionsToSkip.write(DHCP_DOMAIN_SEARCHLIST);
         }
diff --git a/src/android/net/ip/IpClient.java b/src/android/net/ip/IpClient.java
index 0c90fe60..7447fc58 100644
--- a/src/android/net/ip/IpClient.java
+++ b/src/android/net/ip/IpClient.java
@@ -44,7 +44,6 @@ import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_APF_CAPABILITI
 import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_APF_DATA_SNAPSHOT;
 import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_HTTP_PROXY;
 import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_L2INFORMATION;
-import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_L2KEY_CLUSTER;
 import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_TCP_BUFFER_SIZES;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_DHCPACTION_TIMEOUT;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_IPV6_AUTOCONF_TIMEOUT;
@@ -52,11 +51,13 @@ import static android.net.ip.IpClient.IpClientCommands.EVENT_NETLINK_LINKPROPERT
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_FAILURE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_SUCCESS;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_TIMEOUT;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_PIO_PREFIX_UPDATE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_PRE_DHCP_ACTION_COMPLETE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_PROVISIONING_TIMEOUT;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_READ_PACKET_FILTER_COMPLETE;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor.INetlinkMessageProcessor;
+import static android.net.ip.IpClientLinkObserver.PrefixInfo;
 import static android.net.ip.IpReachabilityMonitor.INVALID_REACHABILITY_LOSS_TYPE;
 import static android.net.ip.IpReachabilityMonitor.nudEventTypeToInt;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
@@ -84,6 +85,7 @@ import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ARP_OFF
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ND_OFFLOAD;
 import static com.android.networkstack.util.NetworkStackUtils.APF_NEW_RA_FILTER_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.APF_POLLING_COUNTERS_VERSION;
+import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_DHCPV6_PREFIX_DELEGATION_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_GARP_NA_ROAMING_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_IGNORE_LOW_RA_LIFETIME_VERSION;
@@ -134,7 +136,6 @@ import android.net.shared.Layer2Information;
 import android.net.shared.ProvisioningConfiguration;
 import android.net.shared.ProvisioningConfiguration.ScanResultInfo;
 import android.net.shared.ProvisioningConfiguration.ScanResultInfo.InformationElement;
-import android.os.Build;
 import android.os.ConditionVariable;
 import android.os.Handler;
 import android.os.IBinder;
@@ -152,7 +153,6 @@ import android.text.TextUtils;
 import android.text.format.DateUtils;
 import android.util.LocalLog;
 import android.util.Log;
-import android.util.Pair;
 import android.util.SparseArray;
 
 import androidx.annotation.NonNull;
@@ -166,6 +166,7 @@ import com.android.internal.util.MessageUtils;
 import com.android.internal.util.State;
 import com.android.internal.util.StateMachine;
 import com.android.internal.util.WakeupMessage;
+import com.android.modules.expresslog.Counter;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.CollectionUtils;
 import com.android.net.module.util.ConnectivityUtils;
@@ -600,16 +601,16 @@ public class IpClient extends StateMachine {
         static final int EVENT_READ_PACKET_FILTER_COMPLETE = 12;
         static final int CMD_ADD_KEEPALIVE_PACKET_FILTER_TO_APF = 13;
         static final int CMD_REMOVE_KEEPALIVE_PACKET_FILTER_FROM_APF = 14;
-        static final int CMD_UPDATE_L2KEY_CLUSTER = 15;
-        static final int CMD_COMPLETE_PRECONNECTION = 16;
-        static final int CMD_UPDATE_L2INFORMATION = 17;
-        static final int CMD_SET_DTIM_MULTIPLIER_AFTER_DELAY = 18;
-        static final int CMD_UPDATE_APF_CAPABILITIES = 19;
-        static final int EVENT_IPV6_AUTOCONF_TIMEOUT = 20;
-        static final int CMD_UPDATE_APF_DATA_SNAPSHOT = 21;
-        static final int EVENT_NUD_FAILURE_QUERY_TIMEOUT = 22;
-        static final int EVENT_NUD_FAILURE_QUERY_SUCCESS = 23;
-        static final int EVENT_NUD_FAILURE_QUERY_FAILURE = 24;
+        static final int CMD_COMPLETE_PRECONNECTION = 15;
+        static final int CMD_UPDATE_L2INFORMATION = 16;
+        static final int CMD_SET_DTIM_MULTIPLIER_AFTER_DELAY = 17;
+        static final int CMD_UPDATE_APF_CAPABILITIES = 18;
+        static final int EVENT_IPV6_AUTOCONF_TIMEOUT = 19;
+        static final int CMD_UPDATE_APF_DATA_SNAPSHOT = 20;
+        static final int EVENT_NUD_FAILURE_QUERY_TIMEOUT = 21;
+        static final int EVENT_NUD_FAILURE_QUERY_SUCCESS = 22;
+        static final int EVENT_NUD_FAILURE_QUERY_FAILURE = 23;
+        static final int EVENT_PIO_PREFIX_UPDATE = 24;
         // Internal commands to use instead of trying to call transitionTo() inside
         // a given State's enter() method. Calling transitionTo() from enter/exit
         // encounters a Log.wtf() that can cause trouble on eng builds.
@@ -633,11 +634,6 @@ public class IpClient extends StateMachine {
     private static final int MAX_LOG_RECORDS = 500;
     private static final int MAX_PACKET_RECORDS = 100;
 
-    @VisibleForTesting
-    static final String CONFIG_MIN_RDNSS_LIFETIME = "ipclient_min_rdnss_lifetime";
-    private static final int DEFAULT_MIN_RDNSS_LIFETIME =
-            ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q) ? 120 : 0;
-
     @VisibleForTesting
     static final String CONFIG_ACCEPT_RA_MIN_LFT = "ipclient_accept_ra_min_lft";
     @VisibleForTesting
@@ -647,7 +643,7 @@ public class IpClient extends StateMachine {
     static final String CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS =
             "ipclient_apf_counter_polling_interval_secs";
     @VisibleForTesting
-    static final int DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS = 1800;
+    static final int DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS = 300;
 
     // Used to wait for the provisioning to complete eventually and then decide the target
     // network type, which gives the accurate hint to set DTIM multiplier. Per current IPv6
@@ -798,9 +794,6 @@ public class IpClient extends StateMachine {
     @Nullable
     private final DevicePolicyManager mDevicePolicyManager;
 
-    // Ignore nonzero RDNSS option lifetimes below this value. 0 = disabled.
-    private final int mMinRdnssLifetimeSec;
-
     // Ignore any nonzero RA section with lifetime below this value.
     private final int mAcceptRaMinLft;
 
@@ -820,6 +813,7 @@ public class IpClient extends StateMachine {
     private final boolean mApfShouldHandleNdOffload;
     private final boolean mApfShouldHandleMdnsOffload;
     private final boolean mIgnoreNudFailureEnabled;
+    private final boolean mDhcp6PdPreferredFlagEnabled;
 
     private InterfaceParams mInterfaceParams;
 
@@ -848,15 +842,24 @@ public class IpClient extends StateMachine {
     private ApfCapabilities mCurrentApfCapabilities;
     private WakeupMessage mIpv6AutoconfTimeoutAlarm = null;
     private boolean mIgnoreNudFailure;
-    // An array of NUD failure event count associated with the query database since the timestamps
-    // in the past, and is always initialized to null in StoppedState. Currently supported array
-    // elements are as follows:
-    // element 0: failures in the past week
-    // element 1: failures in the past day
-    // element 2: failures in the past 6h
+    /**
+     * An array of NUD failure event counts retrieved from the memory store  since the timestamps
+     * in the past, and is always initialized to null in StoppedState. Currently supported array
+     * elements are as follows:
+     * element 0: failures in the past week
+     * element 1: failures in the past day
+     * element 2: failures in the past 6h
+     */
     @Nullable
     private int[] mNudFailureEventCounts = null;
 
+    /**
+     * The number of NUD failure events that were stored in the memory store since this IpClient
+     * was last started. Always set to zero in StoppedState. Used to prevent writing excessive NUD
+     * failure events to the memory store.
+     */
+    private int mNudFailuresStoredSinceStart = 0;
+
     /**
      * Reading the snapshot is an asynchronous operation initiated by invoking
      * Callback.startReadPacketFilter() and completed when the WiFi Service responds with an
@@ -1062,8 +1065,6 @@ public class IpClient extends StateMachine {
         mDhcp6PrefixDelegationEnabled = mDependencies.isFeatureEnabled(mContext,
                 IPCLIENT_DHCPV6_PREFIX_DELEGATION_VERSION);
 
-        mMinRdnssLifetimeSec = mDependencies.getDeviceConfigPropertyInt(
-                CONFIG_MIN_RDNSS_LIFETIME, DEFAULT_MIN_RDNSS_LIFETIME);
         mAcceptRaMinLft = mDependencies.getDeviceConfigPropertyInt(CONFIG_ACCEPT_RA_MIN_LFT,
                 DEFAULT_ACCEPT_RA_MIN_LFT);
         mApfCounterPollingIntervalMs = mDependencies.getDeviceConfigPropertyInt(
@@ -1092,9 +1093,11 @@ public class IpClient extends StateMachine {
         mNudFailureCountWeeklyThreshold = mDependencies.getDeviceConfigPropertyInt(
                 CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD,
                 DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD);
+        mDhcp6PdPreferredFlagEnabled =
+                mDependencies.isFeatureEnabled(mContext, IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION);
 
         IpClientLinkObserver.Configuration config = new IpClientLinkObserver.Configuration(
-                mMinRdnssLifetimeSec, mPopulateLinkAddressLifetime);
+                mAcceptRaMinLft, mPopulateLinkAddressLifetime);
 
         mLinkObserver = new IpClientLinkObserver(
                 mContext, getHandler(),
@@ -1141,6 +1144,12 @@ public class IpClient extends StateMachine {
                             }
                         });
                     }
+
+                    @Override
+                    public void onNewPrefix(PrefixInfo info) {
+                        if (!mDhcp6PdPreferredFlagEnabled) return;
+                        sendMessage(EVENT_PIO_PREFIX_UPDATE, info);
+                    }
                 },
                 config, mLog, mDependencies
         );
@@ -1204,7 +1213,8 @@ public class IpClient extends StateMachine {
         @Override
         public void setL2KeyAndGroupHint(String l2Key, String cluster) {
             enforceNetworkStackCallingPermission();
-            IpClient.this.setL2KeyAndCluster(l2Key, cluster);
+            // This method is not supported anymore. The caller should call
+            // #updateLayer2Information() instead.
         }
         @Override
         public void setTcpBufferSizes(String tcpBufferSizes) {
@@ -1397,18 +1407,6 @@ public class IpClient extends StateMachine {
         sendMessage(CMD_UPDATE_TCP_BUFFER_SIZES, tcpBufferSizes);
     }
 
-    /**
-     * Set the L2 key and cluster for storing info into the memory store.
-     *
-     * This method is only supported on Q devices. For R or above releases,
-     * caller should call #updateLayer2Information() instead.
-     */
-    public void setL2KeyAndCluster(String l2Key, String cluster) {
-        if (!ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q)) {
-            sendMessage(CMD_UPDATE_L2KEY_CLUSTER, new Pair<>(l2Key, cluster));
-        }
-    }
-
     /**
      * Set the HTTP Proxy configuration to use.
      *
@@ -2543,11 +2541,24 @@ public class IpClient extends StateMachine {
 
     // In order to avoid overflowing the database (the maximum is 10MB) in case of a NUD failure
     // happens frequently (e.g, every 30s in a broken network), we stop writing the NUD failure
-    // event to database if the event count in past 6h has exceeded the daily threshold.
+    // event to database if the total event count in past 6h, plus the number of events written
+    // since IpClient was started, has exceeded the daily threshold.
+    //
+    // The code also counts the number of events written since this IpClient was last started.
+    // Otherwise, if NUD failures are already being ignored due to a (daily or weekly) threshold
+    // being hit by events that happened more than 6 hours ago, but there have been no failures in
+    // the last 6 hours, the code would never stop logging failures (filling up the memory store)
+    // until IpClient is restarted and queries the memory store again.
+    //
+    // The 6-hour count is still useful, even though the code looks at the number of NUD failures
+    // since IpClient was last started, because it ensures that even if the network disconnects and
+    // reconnects frequently for any other reason, the code will never store more than 10 NUD
+    // failures every 6 hours.
     private boolean shouldStopWritingNudFailureEventToDatabase() {
         // NUD failure query has not completed yet.
         if (mNudFailureEventCounts == null) return true;
-        return mNudFailureEventCounts[2] >= mNudFailureCountDailyThreshold;
+        return mNudFailureEventCounts[2] + mNudFailuresStoredSinceStart
+                >= mNudFailureCountDailyThreshold;
     }
 
     private void maybeStoreNudFailureToDatabase(final NudEventType type) {
@@ -2566,6 +2577,7 @@ public class IpClient extends StateMachine {
                         Log.e(TAG, "Failed to store NUD failure event");
                     }
                 });
+        mNudFailuresStoredSinceStart++;
         if (DBG) {
             Log.d(TAG, "store network event " + type
                     + " at " + now
@@ -2585,7 +2597,10 @@ public class IpClient extends StateMachine {
                         @Override
                         public void notifyLost(String logMsg, NudEventType type) {
                             maybeStoreNudFailureToDatabase(type);
-                            if (mIgnoreNudFailure) return;
+                            if (mIgnoreNudFailure) {
+                                Counter.logIncrement("core_networking.value_nud_failure_ignored");
+                                return;
+                            }
                             final int version = mCallback.getInterfaceVersion();
                             if (version >= VERSION_ADDED_REACHABILITY_FAILURE) {
                                 final int reason = nudEventTypeToInt(type);
@@ -2744,7 +2759,7 @@ public class IpClient extends StateMachine {
         apfConfig.multicastFilter = mMulticastFiltering;
         // Get the Configuration for ApfFilter from Context
         // Resource settings were moved from ApfCapabilities APIs to NetworkStack resources in S
-        if (ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.R)) {
+        if (ShimUtils.isAtLeastS()) {
             final Resources res = mContext.getResources();
             apfConfig.ieee802_3Filter = res.getBoolean(R.bool.config_apfDrop802_3Frames);
             apfConfig.ethTypeBlackList = res.getIntArray(R.array.config_apfEthTypeDenyList);
@@ -2753,7 +2768,9 @@ public class IpClient extends StateMachine {
             apfConfig.ethTypeBlackList = ApfCapabilities.getApfEtherTypeBlackList();
         }
 
-        apfConfig.minRdnssLifetimeSec = mMinRdnssLifetimeSec;
+        // The RDNSS option is not processed by the kernel, so lifetime filtering
+        // can occur independent of kernel support for accept_ra_min_lft.
+        apfConfig.minRdnssLifetimeSec = mAcceptRaMinLft;
         // Check the feature flag first before reading IPv6 sysctl, which can prevent from
         // triggering a potential kernel bug about the sysctl.
         // TODO: add unit test to check if the setIpv6Sysctl() is called or not.
@@ -2801,6 +2818,7 @@ public class IpClient extends StateMachine {
             mMulticastNsSourceAddresses.clear();
             mDelegatedPrefixes.clear();
             mNudFailureEventCounts = null;
+            mNudFailuresStoredSinceStart = 0;
 
             resetLinkProperties();
             if (mStartTimeMillis > 0) {
@@ -2844,13 +2862,6 @@ public class IpClient extends StateMachine {
                     handleLinkPropertiesUpdate(NO_CALLBACKS);
                     break;
 
-                case CMD_UPDATE_L2KEY_CLUSTER: {
-                    final Pair<String, String> args = (Pair<String, String>) msg.obj;
-                    mL2Key = args.first;
-                    mCluster = args.second;
-                    break;
-                }
-
                 case CMD_SET_MULTICAST_FILTER:
                     mMulticastFiltering = (boolean) msg.obj;
                     break;
@@ -3208,20 +3219,6 @@ public class IpClient extends StateMachine {
                     transitionToStoppingState(DisconnectCode.forNumber(msg.arg1));
                     break;
 
-                case CMD_UPDATE_L2KEY_CLUSTER: {
-                    final Pair<String, String> args = (Pair<String, String>) msg.obj;
-                    mL2Key = args.first;
-                    mCluster = args.second;
-                    // TODO : attributes should be saved to the memory store with
-                    // these new values if they differ from the previous ones.
-                    // If the state machine is in pure StartedState, then the values to input
-                    // are not known yet and should be updated when the LinkProperties are updated.
-                    // If the state machine is in RunningState (which is a child of StartedState)
-                    // then the next NUD check should be used to store the new values to avoid
-                    // inputting current values for what may be a different L3 network.
-                    break;
-                }
-
                 case CMD_UPDATE_L2INFORMATION:
                     handleUpdateL2Information((Layer2InformationParcelable) msg.obj);
                     break;
@@ -3296,6 +3293,7 @@ public class IpClient extends StateMachine {
             sinceTimes[2] = now - SIX_HOURS_IN_MS;
             mIpMemoryStore.retrieveNetworkEventCount(mCluster, sinceTimes,
                     NETWORK_EVENT_NUD_FAILURE_TYPES, mListener);
+            Counter.logIncrement("core_networking.value_nud_failure_queried");
         }
 
         @Override
diff --git a/src/android/net/ip/IpClientLinkObserver.java b/src/android/net/ip/IpClientLinkObserver.java
index 8f2856ff..718f5884 100644
--- a/src/android/net/ip/IpClientLinkObserver.java
+++ b/src/android/net/ip/IpClientLinkObserver.java
@@ -20,6 +20,7 @@ import static android.system.OsConstants.AF_INET6;
 import static android.system.OsConstants.AF_UNSPEC;
 import static android.system.OsConstants.IFF_LOOPBACK;
 
+import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_PIO;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
 import static com.android.net.module.util.NetworkStackConstants.INFINITE_LEASE;
 import static com.android.net.module.util.netlink.NetlinkConstants.IFF_LOWER_UP;
@@ -55,12 +56,14 @@ import com.android.net.module.util.netlink.NetlinkConstants;
 import com.android.net.module.util.netlink.NetlinkMessage;
 import com.android.net.module.util.netlink.RtNetlinkAddressMessage;
 import com.android.net.module.util.netlink.RtNetlinkLinkMessage;
+import com.android.net.module.util.netlink.RtNetlinkPrefixMessage;
 import com.android.net.module.util.netlink.RtNetlinkRouteMessage;
 import com.android.net.module.util.netlink.StructIfacacheInfo;
 import com.android.net.module.util.netlink.StructIfaddrMsg;
 import com.android.net.module.util.netlink.StructIfinfoMsg;
 import com.android.net.module.util.netlink.StructNdOptPref64;
 import com.android.net.module.util.netlink.StructNdOptRdnss;
+import com.android.net.module.util.netlink.StructPrefixMsg;
 import com.android.networkstack.apishim.NetworkInformationShimImpl;
 import com.android.networkstack.apishim.common.NetworkInformationShim;
 
@@ -131,6 +134,13 @@ public class IpClientLinkObserver {
          *            False: clat interface was removed.
          */
         void onClatInterfaceStateUpdate(boolean add);
+
+        /**
+         * Called when the prefix information was updated via RTM_NEWPREFIX netlink message.
+         *
+         * @param info prefix information.
+         */
+        void onNewPrefix(PrefixInfo info);
     }
 
     /** Configuration parameters for IpClientLinkObserver. */
@@ -144,6 +154,21 @@ public class IpClientLinkObserver {
         }
     }
 
+    /** Prefix information received from RTM_NEWPREFIX netlink message. */
+    public static class PrefixInfo {
+        public final IpPrefix prefix;
+        public short flags;
+        public long preferred;
+        public long valid;
+
+        public PrefixInfo(@NonNull final IpPrefix prefix, short flags, long preferred, long valid) {
+            this.prefix = prefix;
+            this.flags = flags;
+            this.preferred = preferred;
+            this.valid = valid;
+        }
+    }
+
     private final Context mContext;
     private final String mInterfaceName;
     private final Callback mCallback;
@@ -389,7 +414,8 @@ public class IpClientLinkObserver {
                             | NetlinkConstants.RTMGRP_LINK
                             | NetlinkConstants.RTMGRP_IPV4_IFADDR
                             | NetlinkConstants.RTMGRP_IPV6_IFADDR
-                            | NetlinkConstants.RTMGRP_IPV6_ROUTE),
+                            | NetlinkConstants.RTMGRP_IPV6_ROUTE
+                            | NetlinkConstants.RTMGRP_IPV6_PREFIX),
                     sockRcvbufSize);
             mHandler = h;
             mNetlinkMessageProcessor = p;
@@ -630,6 +656,18 @@ public class IpClientLinkObserver {
         }
     }
 
+    private void processRtNetlinkPrefixMessage(RtNetlinkPrefixMessage msg) {
+        final StructPrefixMsg prefixmsg = msg.getPrefixMsg();
+        if (prefixmsg.prefix_family != AF_INET6) return;
+        if (prefixmsg.prefix_ifindex != mIfindex) return;
+        if (prefixmsg.prefix_type != ICMPV6_ND_OPTION_PIO) return;
+        final PrefixInfo info = new PrefixInfo(msg.getPrefix(),
+                prefixmsg.prefix_flags,
+                msg.getPreferredLifetime(),
+                msg.getValidLifetime());
+        mCallback.onNewPrefix(info);
+    }
+
     private void processNetlinkMessage(NetlinkMessage nlMsg, long whenMs) {
         if (nlMsg instanceof NduseroptMessage) {
             processNduseroptMessage((NduseroptMessage) nlMsg, whenMs);
@@ -639,6 +677,8 @@ public class IpClientLinkObserver {
             processRtNetlinkAddressMessage((RtNetlinkAddressMessage) nlMsg);
         } else if (nlMsg instanceof RtNetlinkRouteMessage) {
             processRtNetlinkRouteMessage((RtNetlinkRouteMessage) nlMsg);
+        } else if (nlMsg instanceof RtNetlinkPrefixMessage) {
+            processRtNetlinkPrefixMessage((RtNetlinkPrefixMessage) nlMsg);
         } else {
             Log.e(mTag, "Unknown netlink message: " + nlMsg);
         }
diff --git a/src/android/net/ip/IpReachabilityMonitor.java b/src/android/net/ip/IpReachabilityMonitor.java
index 462de907..9cdbc5dd 100644
--- a/src/android/net/ip/IpReachabilityMonitor.java
+++ b/src/android/net/ip/IpReachabilityMonitor.java
@@ -281,7 +281,7 @@ public class IpReachabilityMonitor {
                 IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION);
         mIgnoreOrganicNudFailure = dependencies.isFeatureEnabled(context,
                 IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION);
-        mIgnoreNeverReachableNeighbor = dependencies.isFeatureEnabled(context,
+        mIgnoreNeverReachableNeighbor = dependencies.isFeatureNotChickenedOut(context,
                 IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION);
         mMetricsLog = metricsLog;
         mNetd = netd;
diff --git a/src/android/net/util/RawPacketTracker.java b/src/android/net/util/RawPacketTracker.java
new file mode 100644
index 00000000..e73834b4
--- /dev/null
+++ b/src/android/net/util/RawPacketTracker.java
@@ -0,0 +1,242 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.net.util;
+
+import static com.android.internal.annotations.VisibleForTesting.Visibility.PRIVATE;
+
+import android.net.ip.ConnectivityPacketTracker;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.Looper;
+import android.os.Message;
+import android.util.ArrayMap;
+import android.util.LocalLog;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.net.module.util.InterfaceParams;
+
+import java.util.Objects;
+
+/**
+ * Tracks and manages raw packet captures on a network interface.
+ *
+ * <p>This class is not a thread-safe and should be only run on the handler thread.
+ * It utilizes a dedicated {@link HandlerThread} to perform capture operations, allowing
+ * the caller to interact with it asynchronously through methods like
+ * {@link #startCapture(String, long)}, {@link #stopCapture(String)},
+ * and {@link #getMatchedPacketCount(String, String)}.</p>
+ *
+ */
+public class RawPacketTracker {
+    /**
+     * Dependencies class for testing.
+     */
+    @VisibleForTesting(visibility = PRIVATE)
+    static class Dependencies {
+        public @NonNull ConnectivityPacketTracker createPacketTracker(
+                Handler handler, InterfaceParams ifParams, int maxPktRecords) {
+            return new ConnectivityPacketTracker(
+                    handler, ifParams, new LocalLog(maxPktRecords));
+        }
+
+        public @NonNull HandlerThread createHandlerThread() {
+            final HandlerThread handlerThread = new HandlerThread(TAG + "-handler");
+            handlerThread.start();
+            return handlerThread;
+        }
+
+        public @NonNull Looper getLooper(HandlerThread handlerThread) {
+            return handlerThread.getLooper();
+        }
+    }
+
+    // Maximum number of packet records to store.
+    private static final int MAX_PACKET_RECORDS = 100;
+    // Maximum duration for a packet capture session in milliseconds.
+    public static final long MAX_CAPTURE_TIME_MS = 300_000;
+    @VisibleForTesting(visibility = PRIVATE)
+    public static final int CMD_STOP_CAPTURE = 1;
+    private static final String TAG = RawPacketTracker.class.getSimpleName();
+
+    private final @NonNull HandlerThread mHandlerThread;
+    private final @NonNull Dependencies mDeps;
+    private final @NonNull Handler mHandler;
+
+    /**
+     * A map that stores ConnectivityPacketTracker objects, keyed by their associated
+     * network interface name, e.g: wlan0. This allows for tracking connectivity
+     * packets on a per-interface basis. This is only accessed by handler thread.
+     */
+    private final ArrayMap<String, ConnectivityPacketTracker> mTrackerMap = new ArrayMap<>();
+
+    public RawPacketTracker() {
+        this(new Dependencies());
+    }
+
+    @VisibleForTesting(visibility = PRIVATE)
+    public RawPacketTracker(
+            @NonNull Dependencies deps
+    ) {
+        mDeps = deps;
+        mHandlerThread = deps.createHandlerThread();
+        mHandler = new RawPacketTrackerHandler(deps.getLooper(mHandlerThread), this);
+    }
+
+    private static class RawPacketTrackerHandler extends Handler {
+        private final RawPacketTracker mRawPacketTracker;
+        private RawPacketTrackerHandler(
+                @NonNull Looper looper,
+                @NonNull RawPacketTracker rawPacketTracker) {
+            super(looper);
+            mRawPacketTracker = rawPacketTracker;
+        }
+
+        @Override
+        public void handleMessage(Message msg) {
+            final String ifaceName;
+            switch (msg.what) {
+                case CMD_STOP_CAPTURE:
+                    ifaceName = (String) msg.obj;
+                    mRawPacketTracker.processStopCapture(ifaceName);
+                    break;
+                default:
+                    Log.e(TAG, "unrecognized message: " + msg.what);
+            }
+        }
+    }
+
+    /**
+     * Starts capturing packets on the specified network interface.
+     *
+     * <p>Initiates a packet capture session if one is not already running for the given interface.
+     * A capture timeout is set to automatically stop the capture after {@code maxCaptureTimeMs}
+     * milliseconds. If a previous stop capture event was scheduled, it is canceled.</p>
+     *
+     * @param ifaceName      The name of the network interface to capture packets on.
+     * @param maxCaptureTimeMs The maximum capture duration in milliseconds.
+     * @throws IllegalArgumentException If {@code maxCaptureTimeMs} is less than or equal to 0.
+     * @throws RuntimeException If a capture is already running on the specified interface.
+     * @throws IllegalStateException If this method is not running on handler thread
+     */
+    public void startCapture(
+            String ifaceName, long maxCaptureTimeMs
+    ) throws IllegalArgumentException, RuntimeException, IllegalStateException {
+        ensureRunOnHandlerThread();
+        if (maxCaptureTimeMs <= 0) {
+            throw new IllegalArgumentException("maxCaptureTimeMs " + maxCaptureTimeMs + " <= 0");
+        }
+
+        if (mTrackerMap.containsKey(ifaceName)) {
+            throw new RuntimeException(ifaceName + " is already capturing");
+        }
+
+        final InterfaceParams ifParams = InterfaceParams.getByName(ifaceName);
+        Objects.requireNonNull(ifParams, "invalid interface " + ifaceName);
+
+        final ConnectivityPacketTracker tracker =
+                mDeps.createPacketTracker(mHandler, ifParams, MAX_PACKET_RECORDS);
+        tracker.start(TAG + "." + ifaceName);
+        mTrackerMap.putIfAbsent(ifaceName, tracker);
+        tracker.setCapture(true);
+
+        // remove scheduled stop events if it already in the queue
+        mHandler.removeMessages(CMD_STOP_CAPTURE, ifaceName);
+
+        // capture up to configured capture time and stop capturing
+        final Message stopMsg = mHandler.obtainMessage(CMD_STOP_CAPTURE, ifaceName);
+        mHandler.sendMessageDelayed(stopMsg, maxCaptureTimeMs);
+    }
+
+    /**
+     * Stops capturing packets on the specified network interface.
+     *
+     * <p>Terminates the packet capture session if one is active for the given interface.
+     * Any pending stop capture events for the interface are canceled.</p>
+     *
+     * @param ifaceName The name of the network interface to stop capturing on.
+     * @throws RuntimeException If no capture is running on the specified interface.
+     * @throws IllegalStateException If this method is not running on handler thread
+     */
+    public void stopCapture(String ifaceName) throws RuntimeException, IllegalStateException {
+        ensureRunOnHandlerThread();
+        if (!mTrackerMap.containsKey(ifaceName)) {
+            throw new RuntimeException(ifaceName + " is already stopped");
+        }
+
+        final Message msg = mHandler.obtainMessage(CMD_STOP_CAPTURE, ifaceName);
+        // remove scheduled stop events if it already in the queue
+        mHandler.removeMessages(CMD_STOP_CAPTURE, ifaceName);
+        mHandler.sendMessage(msg);
+    }
+
+    /**
+     * Returns the {@link Handler} associated with this RawTracker.
+     *
+     * <p>This handler is used for posting tasks to the RawTracker's internal thread.
+     * You can use it to execute code that needs to interact with the RawTracker
+     * in a thread-safe manner.
+     *
+     * @return The non-null {@link Handler} instance.
+     */
+    public @NonNull Handler getHandler() {
+        return mHandler;
+    }
+
+    /**
+     * Retrieves the number of captured packets matching a specific pattern.
+     *
+     * <p>Queries the packet capture data for the specified interface and counts the occurrences
+     * of packets that match the provided {@code packet} string. The count is performed
+     * asynchronously on the capture thread.</p>
+     *
+     * @param ifaceName The name of the network interface.
+     * @param packetPattern The packet pattern to match.
+     * @return The number of matched packets, or 0 if an error occurs or no matching packets are
+     *         found.
+     * @throws RuntimeException If no capture is running on the specified interface.
+     * @throws IllegalStateException If this method is not running on handler thread
+     */
+    public int getMatchedPacketCount(
+            String ifaceName, String packetPattern
+    ) throws RuntimeException, IllegalStateException {
+        ensureRunOnHandlerThread();
+        final ConnectivityPacketTracker tracker;
+        tracker = mTrackerMap.getOrDefault(ifaceName, null);
+        if (tracker == null) {
+            throw new RuntimeException(ifaceName + " is not capturing");
+        }
+
+        return tracker.getMatchedPacketCount(packetPattern);
+    }
+
+    private void processStopCapture(String ifaceName) {
+        final ConnectivityPacketTracker tracker = mTrackerMap.get(ifaceName);
+        mTrackerMap.remove(ifaceName);
+        tracker.setCapture(false);
+    }
+
+    private void ensureRunOnHandlerThread() {
+        if (mHandler.getLooper() != Looper.myLooper()) {
+            throw new IllegalStateException(
+                "Not running on Handler thread: " + Thread.currentThread().getName()
+            );
+        }
+    }
+}
diff --git a/src/android/net/util/RawSocketUtils.java b/src/android/net/util/RawSocketUtils.java
index a6c8a40b..5823dc49 100644
--- a/src/android/net/util/RawSocketUtils.java
+++ b/src/android/net/util/RawSocketUtils.java
@@ -92,9 +92,9 @@ public class RawSocketUtils {
     }
 
     @RequiresPermission(NETWORK_SETTINGS)
-    private static void enforceTetheredInterface(@NonNull Context context,
+    public static void enforceTetheredInterface(@NonNull Context context,
                                                @NonNull String interfaceName)
-            throws ExecutionException, InterruptedException, TimeoutException {
+            throws ExecutionException, InterruptedException, TimeoutException, SecurityException {
         final TetheringManager tm = context.getSystemService(TetheringManager.class);
         final CompletableFuture<List<String>> tetheredInterfaces = new CompletableFuture<>();
         final TetheringManager.TetheringEventCallback callback =
diff --git a/src/com/android/server/NetworkStackService.java b/src/com/android/server/NetworkStackService.java
index 4d10c3b2..686a3996 100644
--- a/src/com/android/server/NetworkStackService.java
+++ b/src/com/android/server/NetworkStackService.java
@@ -19,6 +19,7 @@ package com.android.server;
 import static android.net.dhcp.IDhcpServer.STATUS_INVALID_ARGUMENT;
 import static android.net.dhcp.IDhcpServer.STATUS_SUCCESS;
 import static android.net.dhcp.IDhcpServer.STATUS_UNKNOWN_ERROR;
+import static android.net.util.RawPacketTracker.MAX_CAPTURE_TIME_MS;
 import static android.net.util.RawSocketUtils.sendRawPacketDownStream;
 
 import static com.android.net.module.util.DeviceConfigUtils.getResBooleanConfig;
@@ -50,7 +51,8 @@ import android.net.ip.IIpClientCallbacks;
 import android.net.ip.IpClient;
 import android.net.networkstack.aidl.NetworkMonitorParameters;
 import android.net.shared.PrivateDnsConfig;
-import android.os.Build;
+import android.net.util.RawPacketTracker;
+import android.net.util.RawSocketUtils;
 import android.os.HandlerThread;
 import android.os.IBinder;
 import android.os.Looper;
@@ -67,10 +69,10 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.internal.util.IndentingPrintWriter;
 import com.android.modules.utils.BasicShellCommandHandler;
 import com.android.net.module.util.DeviceConfigUtils;
+import com.android.net.module.util.HandlerUtils;
 import com.android.net.module.util.SharedLog;
 import com.android.networkstack.NetworkStackNotifier;
 import com.android.networkstack.R;
-import com.android.networkstack.apishim.common.ShimUtils;
 import com.android.networkstack.ipmemorystore.IpMemoryStoreService;
 import com.android.server.connectivity.NetworkMonitor;
 import com.android.server.util.PermissionUtil;
@@ -90,6 +92,8 @@ import java.util.ListIterator;
 import java.util.Objects;
 import java.util.SortedSet;
 import java.util.TreeSet;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeoutException;
 
 /**
  * Android service used to start the network stack when bound to via an intent.
@@ -99,6 +103,7 @@ import java.util.TreeSet;
 public class NetworkStackService extends Service {
     private static final String TAG = NetworkStackService.class.getSimpleName();
     private static NetworkStackConnector sConnector;
+    private static final RawPacketTracker sRawPacketTracker = new RawPacketTracker();
 
     /**
      * Create a binder connector for the system server to communicate with the network stack.
@@ -201,7 +206,6 @@ public class NetworkStackService extends Service {
         @GuardedBy("mIpClients")
         private final ArrayList<WeakReference<IpClient>> mIpClients = new ArrayList<>();
         private final IpMemoryStoreService mIpMemoryStoreService;
-        @Nullable
         private final NetworkStackNotifier mNotifier;
 
         private static final int MAX_VALIDATION_LOGS = 10;
@@ -296,15 +300,10 @@ public class NetworkStackService extends Service {
             mNetd = INetd.Stub.asInterface(
                     (IBinder) context.getSystemService(Context.NETD_SERVICE));
             mIpMemoryStoreService = mDeps.makeIpMemoryStoreService(context);
-            // NetworkStackNotifier only shows notifications relevant for API level > Q
-            if (ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q)) {
-                final HandlerThread notifierThread = new HandlerThread(
-                        NetworkStackNotifier.class.getSimpleName());
-                notifierThread.start();
-                mNotifier = mDeps.makeNotifier(context, notifierThread.getLooper());
-            } else {
-                mNotifier = null;
-            }
+            final HandlerThread notifierThread = new HandlerThread(
+                    NetworkStackNotifier.class.getSimpleName());
+            notifierThread.start();
+            mNotifier = mDeps.makeNotifier(context, notifierThread.getLooper());
 
             int netdVersion;
             String netdHash;
@@ -523,6 +522,8 @@ public class NetworkStackService extends Service {
         }
 
         private class ShellCmd extends BasicShellCommandHandler {
+            private static final long MAX_CAPTURE_CMD_WAITING_TIMEOUT_MS = 30_000L;
+
             @Override
             public int onCommand(String cmd) {
                 if (cmd == null) {
@@ -567,6 +568,14 @@ public class NetworkStackService extends Service {
                         }
                         return 0;
                     }
+                    case "capture":
+                        // Usage: cmd network_stack capture <cmd>
+                        HandlerUtils.runWithScissorsForDump(
+                                sRawPacketTracker.getHandler(),
+                                () -> captureShellCommand(mContext, peekRemainingArgs()),
+                                MAX_CAPTURE_CMD_WAITING_TIMEOUT_MS
+                        );
+                        return 0;
                     case "apf":
                         // Usage: cmd network_stack apf <iface> <cmd>
                         final String iface = getNextArg();
@@ -609,6 +618,18 @@ public class NetworkStackService extends Service {
                 pw.println("      to tethering downstream for security considerations.");
                 pw.println("    <packet_in_hex>: A valid hexadecimal representation of ");
                 pw.println("      a packet starting from L2 header.");
+                pw.println("  capture <cmd>");
+                pw.println("    APF utility commands for multi-devices tests.");
+                pw.println("    start <interface>");
+                pw.println("      start capture packets in the received buffer.");
+                pw.println("      The capture is up to 300 sec, then it will stop.");
+                pw.println("      <interface>: Target interface name, note that this is limited");
+                pw.println("        to tethering downstream for security considerations.");
+                pw.println("    stop <interface>");
+                pw.println("      stop capture packets and clear the received buffer.");
+                pw.println("    matched-packet-counts <interface> <pkt-hex-string>");
+                pw.println("      the <pkt-hex-string> starts from ether header.");
+                pw.println("      Expect to do full packet match.");
                 pw.println("  apf <iface> <cmd>");
                 pw.println("    APF utility commands for integration tests.");
                 pw.println("    <iface>: the network interface the provided command operates on.");
@@ -628,17 +649,79 @@ public class NetworkStackService extends Service {
                 pw.println("      read");
                 pw.println("        reads and returns the current state of APF memory.");
             }
+
+            private void captureShellCommand(
+                    @NonNull Context context,
+                    @NonNull String[] args
+            ) {
+                if (args.length < 2) {
+                    throw new IllegalArgumentException("Incorrect number of arguments");
+                }
+
+                final String cmd = args[0];
+                final String ifaceName = args[1];
+                try {
+                    RawSocketUtils.enforceTetheredInterface(context, ifaceName);
+                } catch (ExecutionException
+                         | InterruptedException
+                         | TimeoutException
+                         | SecurityException e) {
+                    throw new RuntimeException(e.getMessage());
+                }
+
+                final PrintWriter pw = getOutPrintWriter();
+                switch(cmd) {
+                    case "start":
+                        // Usage : cmd network_stack capture start <interface>
+                        if (args.length != 2) {
+                            throw new IllegalArgumentException("Incorrect number of arguments");
+                        }
+
+                        sRawPacketTracker.startCapture(ifaceName, MAX_CAPTURE_TIME_MS);
+                        pw.println("success");
+                        break;
+                    case "matched-packet-counts":
+                        // Usage : cmd network_stack capture matched-packet-counts
+                        //         <interface> <packet-in-hex>
+                        // for example, there is an usage to get matched arp reply packet count
+                        // in hex string format on the wlan0 interface
+                        // cmd network_stack capture matched-packet-counts wlan0 \
+                        // "00010203040501020304050608060001080006040002010203040506c0a80101" +
+                        // "000102030405c0a80102"
+                        if (args.length != 3) {
+                            throw new IllegalArgumentException("Incorrect number of arguments");
+                        }
+
+                        final String packetInHex = args[2];
+
+                        // limit the input hex string up to 3000 (1500 bytes)
+                        if (packetInHex.length() > 3000) {
+                            throw new IllegalArgumentException("Packet Hex String over the limit");
+                        }
+
+                        final int pktCnt =
+                                sRawPacketTracker.getMatchedPacketCount(ifaceName, packetInHex);
+                        pw.println(pktCnt);
+                        break;
+                    case "stop":
+                        // Usage : cmd network_stack capture stop <interface>
+                        if (args.length != 2) {
+                            throw new IllegalArgumentException("Incorrect number of arguments");
+                        }
+
+                        sRawPacketTracker.stopCapture(ifaceName);
+                        pw.println("success");
+                        break;
+                    default:
+                        throw new IllegalArgumentException("Invalid apf command: " + cmd);
+                }
+            }
         }
 
         /**
          * Dump version information of the module and detected system version.
          */
         private void dumpVersion(@NonNull PrintWriter fout) {
-            if (!ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q)) {
-                dumpVersionNumberOnly(fout);
-                return;
-            }
-
             fout.println("LocalInterface:" + this.VERSION + ":" + this.HASH);
             synchronized (mAidlVersions) {
                 // Sort versions for deterministic order in output
diff --git a/src/com/android/server/connectivity/NetworkMonitor.java b/src/com/android/server/connectivity/NetworkMonitor.java
index 60bb9279..659e911d 100755
--- a/src/com/android/server/connectivity/NetworkMonitor.java
+++ b/src/com/android/server/connectivity/NetworkMonitor.java
@@ -125,7 +125,6 @@ import android.net.util.DataStallUtils.EvaluationType;
 import android.net.util.Stopwatch;
 import android.net.wifi.WifiInfo;
 import android.net.wifi.WifiManager;
-import android.os.Build;
 import android.os.Bundle;
 import android.os.CancellationSignal;
 import android.os.Message;
@@ -177,7 +176,6 @@ import com.android.networkstack.apishim.common.CaptivePortalDataShim;
 import com.android.networkstack.apishim.common.NetworkAgentConfigShim;
 import com.android.networkstack.apishim.common.NetworkInformationShim;
 import com.android.networkstack.apishim.common.ShimUtils;
-import com.android.networkstack.apishim.common.UnsupportedApiLevelException;
 import com.android.networkstack.metrics.DataStallDetectionStats;
 import com.android.networkstack.metrics.DataStallStatsUtils;
 import com.android.networkstack.metrics.NetworkValidationMetrics;
@@ -477,7 +475,6 @@ public class NetworkMonitor extends StateMachine {
     private final TelephonyManager mTelephonyManager;
     private final WifiManager mWifiManager;
     private final ConnectivityManager mCm;
-    @Nullable
     private final NetworkStackNotifier mNotifier;
     private final IpConnectivityLog mMetricsLog;
     private final Dependencies mDependencies;
@@ -611,13 +608,6 @@ public class NetworkMonitor extends StateMachine {
         } catch (RemoteException e) {
             version = 0;
         }
-        // The AIDL was freezed from Q beta 5 but it's unfreezing from R before releasing. In order
-        // to distinguish the behavior between R and Q beta 5 and before Q beta 5, add SDK and
-        // CODENAME check here. Basically, it's only expected to return 0 for Q beta 4 and below
-        // because the test result has changed.
-        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q
-                && Build.VERSION.CODENAME.equals("REL")
-                && version == Build.VERSION_CODES.CUR_DEVELOPMENT) version = 0;
         return version;
     }
 
@@ -1447,7 +1437,7 @@ public class NetworkMonitor extends StateMachine {
                     final CaptivePortalProbeResult probeRes = mLastPortalProbeResult;
                     // Use redirect URL from AP if exists.
                     final String portalUrl =
-                            (useRedirectUrlForPortal() && makeURL(probeRes.redirectUrl) != null)
+                            (makeURL(probeRes.redirectUrl) != null)
                             ? probeRes.redirectUrl : probeRes.detectUrl;
                     appExtras.putString(EXTRA_CAPTIVE_PORTAL_URL, portalUrl);
                     if (probeRes.probeSpec != null) {
@@ -1456,9 +1446,7 @@ public class NetworkMonitor extends StateMachine {
                     }
                     appExtras.putString(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_USER_AGENT,
                             mCaptivePortalUserAgent);
-                    if (mNotifier != null) {
-                        mNotifier.notifyCaptivePortalValidationPending(network);
-                    }
+                    mNotifier.notifyCaptivePortalValidationPending(network);
                     mCm.startCaptivePortalApp(network, appExtras);
                     return HANDLED;
                 default:
@@ -1466,12 +1454,6 @@ public class NetworkMonitor extends StateMachine {
             }
         }
 
-        private boolean useRedirectUrlForPortal() {
-            // It must match the conditions in CaptivePortalLogin in which the redirect URL is not
-            // used to validate that the portal is gone.
-            return ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q);
-        }
-
         @Override
         public void exit() {
             if (mLaunchCaptivePortalAppBroadcastReceiver != null) {
@@ -3359,11 +3341,6 @@ public class NetworkMonitor extends StateMachine {
             } catch (JSONException e) {
                 validationLog("Could not parse capport API JSON: " + e.getMessage());
                 return null;
-            } catch (UnsupportedApiLevelException e) {
-                // This should never happen because LinkProperties would not have a capport URL
-                // before R.
-                validationLog("Platform API too low to support capport API");
-                return null;
             }
         }
 
diff --git a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
index f7e1c4d0..e162da99 100644
--- a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
+++ b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
@@ -36,14 +36,12 @@ import static android.net.dhcp.DhcpPacket.ENCAP_L2;
 import static android.net.dhcp.DhcpPacket.INADDR_BROADCAST;
 import static android.net.dhcp.DhcpPacket.INFINITE_LEASE;
 import static android.net.dhcp.DhcpPacket.MIN_V6ONLY_WAIT_MS;
-import static android.net.dhcp6.Dhcp6Packet.PrefixDelegation;
 import static android.net.ip.IIpClientCallbacks.DTIM_MULTIPLIER_RESET;
 import static android.net.ip.IpClient.CONFIG_IPV6_AUTOCONF_TIMEOUT;
 import static android.net.ip.IpClient.CONFIG_ACCEPT_RA_MIN_LFT;
 import static android.net.ip.IpClient.CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS;
 import static android.net.ip.IpClient.CONFIG_NUD_FAILURE_COUNT_DAILY_THRESHOLD;
 import static android.net.ip.IpClient.CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD;
-import static android.net.ip.IpClient.DEFAULT_ACCEPT_RA_MIN_LFT;
 import static android.net.ip.IpClient.DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS;
 import static android.net.ip.IpClient.DEFAULT_NUD_FAILURE_COUNT_DAILY_THRESHOLD;
 import static android.net.ip.IpClient.DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD;
@@ -128,6 +126,7 @@ import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
 import android.app.AlarmManager;
@@ -194,7 +193,6 @@ import android.os.ParcelFileDescriptor;
 import android.os.PowerManager;
 import android.os.RemoteException;
 import android.os.SystemClock;
-import android.os.SystemProperties;
 import android.provider.Settings;
 import android.stats.connectivity.NudEventType;
 import android.system.ErrnoException;
@@ -228,8 +226,6 @@ import com.android.net.module.util.structs.PrefixInformationOption;
 import com.android.net.module.util.structs.RdnssOption;
 import com.android.networkstack.R;
 import com.android.networkstack.apishim.CaptivePortalDataShimImpl;
-import com.android.networkstack.apishim.ConstantsShim;
-import com.android.networkstack.apishim.common.ShimUtils;
 import com.android.networkstack.ipmemorystore.IpMemoryStoreService;
 import com.android.networkstack.metrics.IpProvisioningMetrics;
 import com.android.networkstack.metrics.IpReachabilityMonitorMetrics;
@@ -242,7 +238,7 @@ import com.android.testutils.CompatUtil;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;
 import com.android.testutils.HandlerUtils;
-import com.android.testutils.TapPacketReader;
+import com.android.testutils.PollPacketReader;
 import com.android.testutils.TestableNetworkAgent;
 import com.android.testutils.TestableNetworkCallback;
 
@@ -392,7 +388,7 @@ public abstract class IpClientIntegrationTestCommon {
     private String mIfaceName;
     private HandlerThread mPacketReaderThread;
     private Handler mHandler;
-    private TapPacketReader mPacketReader;
+    private PollPacketReader mPacketReader;
     private FileDescriptor mTapFd;
     private byte[] mClientMac;
     private InetAddress mClientIpAddress;
@@ -851,7 +847,6 @@ public abstract class IpClientIntegrationTestCommon {
             return null;
         }).when(mIpMemoryStore).retrieveNetworkEventCount(eq(TEST_CLUSTER), any(), any(), any());
 
-        setDeviceConfigProperty(IpClient.CONFIG_MIN_RDNSS_LIFETIME, 67);
         setDeviceConfigProperty(DhcpClient.DHCP_RESTART_CONFIG_DELAY, 10);
         setDeviceConfigProperty(DhcpClient.ARP_FIRST_PROBE_DELAY_MS, 10);
         setDeviceConfigProperty(DhcpClient.ARP_PROBE_MIN_MS, 10);
@@ -869,7 +864,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         // Set the minimal RA lifetime value, any RA section with liftime below this value will be
         // ignored.
-        setDeviceConfigProperty(CONFIG_ACCEPT_RA_MIN_LFT, DEFAULT_ACCEPT_RA_MIN_LFT);
+        setDeviceConfigProperty(CONFIG_ACCEPT_RA_MIN_LFT, 67);
 
         // Set the polling interval to update APF data snapshot.
         setDeviceConfigProperty(CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS,
@@ -929,7 +924,7 @@ public abstract class IpClientIntegrationTestCommon {
         // go out of scope.
         mTapFd = new FileDescriptor();
         mTapFd.setInt$(iface.getFileDescriptor().detachFd());
-        mPacketReader = new TapPacketReader(mHandler, mTapFd, DATA_BUFFER_LEN);
+        mPacketReader = new PollPacketReader(mHandler, mTapFd, DATA_BUFFER_LEN);
         mHandler.post(() -> mPacketReader.start());
     }
 
@@ -1300,23 +1295,13 @@ public abstract class IpClientIntegrationTestCommon {
             final List<DhcpPacket> packetList) throws Exception {
         for (DhcpPacket packet : packetList) {
             if (!expectSendHostname || hostname == null) {
-                assertNoHostname(packet.getHostname());
+                assertNull(packet.getHostname());
             } else {
                 assertEquals(hostnameAfterTransliteration, packet.getHostname());
             }
         }
     }
 
-    private void assertNoHostname(String hostname) {
-        if (ShimUtils.isAtLeastR()) {
-            assertNull(hostname);
-        } else {
-            // Until Q, if no hostname is set, the device falls back to the hostname set via
-            // system property, to avoid breaking Q devices already launched with that setup.
-            assertEquals(SystemProperties.get("net.hostname"), hostname);
-        }
-    }
-
     // Helper method to complete DHCP 2-way or 4-way handshake
     private List<DhcpPacket> performDhcpHandshake(final boolean isSuccessLease,
             final Integer leaseTimeSec, final boolean shouldReplyRapidCommitAck, final int mtu,
@@ -1767,7 +1752,7 @@ public abstract class IpClientIntegrationTestCommon {
         assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_DEFAULT_MTU);
     }
 
-    @Test @IgnoreUpTo(Build.VERSION_CODES.Q)
+    @Test
     public void testRollbackFromRapidCommitOption() throws Exception {
         startIpClientProvisioning(true /* isDhcpRapidCommitEnabled */,
                 false /* isPreConnectionEnabled */,
@@ -1853,10 +1838,8 @@ public abstract class IpClientIntegrationTestCommon {
         assertTrue(packet instanceof DhcpDiscoverPacket);
     }
 
-    @Test @IgnoreUpTo(Build.VERSION_CODES.Q)
+    @Test
     public void testDhcpServerInLinkProperties() throws Exception {
-        assumeTrue(ConstantsShim.VERSION > Build.VERSION_CODES.Q);
-
         performDhcpHandshake();
         ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
         verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
@@ -2264,13 +2247,13 @@ public abstract class IpClientIntegrationTestCommon {
 
         LinkProperties lp = doIpv6OnlyProvisioning(inOrder, ra);
 
-        // Expect that DNS servers with lifetimes below CONFIG_MIN_RDNSS_LIFETIME are not accepted.
+        // Expect that DNS servers with lifetimes below CONFIG_ACCEPT_RA_MIN_LFT are not accepted.
         assertNotNull(lp);
         assertEquals(1, lp.getDnsServers().size());
         assertTrue(lp.getDnsServers().contains(InetAddress.getByName(dnsServer)));
 
         // If the RDNSS lifetime is above the minimum, the DNS server is accepted.
-        rdnss1 = buildRdnssOption(68, lowlifeDnsServer);
+        rdnss1 = buildRdnssOption(67, lowlifeDnsServer);
         ra = buildRaPacket(pio, rdnss1, rdnss2);
         mPacketReader.sendResponse(ra);
         inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(captor.capture());
@@ -2335,11 +2318,9 @@ public abstract class IpClientIntegrationTestCommon {
 
     }
 
-    @Test @IgnoreUpTo(Build.VERSION_CODES.Q)
+    @Test
     @SignatureRequiredTest(reason = "TODO: evaluate whether signature perms are required")
     public void testPref64Option() throws Exception {
-        assumeTrue(ConstantsShim.VERSION > Build.VERSION_CODES.Q);
-
         ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                 .withoutIpReachabilityMonitor()
                 .withoutIPv4()
@@ -2812,8 +2793,6 @@ public abstract class IpClientIntegrationTestCommon {
                 argThat(lp -> lp.getMtu() == testMtu));
 
         // Ensure that the URL was set as expected in the callbacks.
-        // Can't verify the URL up to Q as there is no such attribute in LinkProperties.
-        if (!ShimUtils.isAtLeastR()) return null;
         verify(mCb, atLeastOnce()).onLinkPropertiesChange(captor.capture());
         final LinkProperties expectedLp = captor.getAllValues().stream().findFirst().get();
         assertNotNull(expectedLp);
@@ -4110,6 +4089,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_probeFailed() throws Exception {
         runIpReachabilityMonitorProbeFailedTest();
         assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
@@ -4117,6 +4097,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test @SignatureRequiredTest(reason = "requires mock callback object")
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_probeFailed_legacyCallback() throws Exception {
         when(mCb.getInterfaceVersion()).thenReturn(12 /* assign an older interface aidl version */);
 
@@ -4158,6 +4139,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_mcastResolicitProbeFailed() throws Exception {
         runIpReachabilityMonitorMcastResolicitProbeFailedTest();
         assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
@@ -4165,6 +4147,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test @SignatureRequiredTest(reason = "requires mock callback object")
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_mcastResolicitProbeFailed_legacyCallback()
             throws Exception {
         when(mCb.getInterfaceVersion()).thenReturn(12 /* assign an older interface aidl version */);
@@ -4300,6 +4283,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION, enabled = false)
     public void testIpReachabilityMonitor_ignoreIpv4DefaultRouterOrganicNudFailure_flagoff()
             throws Exception {
@@ -4362,21 +4346,24 @@ public abstract class IpClientIntegrationTestCommon {
         final Inet6Address dnsServerIp = ipv6Addr(dnsServer);
         final LinkProperties lp = performDualStackProvisioning(ra, dnsServerIp);
         runAsShell(MANAGE_TEST_NETWORKS, () -> createTestNetworkAgentAndRegister(lp));
+    }
 
-        // Send a UDP packet to IPv6 DNS server to trigger address resolution process for IPv6
-        // on-link DNS server or default router(if the target is default router, we should pass
-        // in an IPv6 off-link DNS server such as 2001:db8:4860:4860::64).
+    /**
+     * Send a UDP packet to dstIp to trigger address resolution for targetIp, and possibly expect a
+     * neighbor lost callback.
+     * If dstIp is on-link, then dstIp and targetIp should be the same.
+     * If dstIp is off-link, then targetIp should be the IPv6 default router.
+     * The ND cache should not have an entry for targetIp.
+     */
+    private void sendPacketToUnreachableNeighbor(Inet6Address dstIp) throws Exception {
         final Random random = new Random();
         final byte[] data = new byte[100];
         random.nextBytes(data);
-        sendUdpPacketToNetwork(mNetworkAgent.getNetwork(), dnsServerIp, 1234 /* port */, data);
+        sendUdpPacketToNetwork(mNetworkAgent.getNetwork(), dstIp, 1234 /* port */, data);
     }
 
-    private void runIpReachabilityMonitorAddressResolutionTest(final String dnsServer,
-            final Inet6Address targetIp,
-            final boolean expectNeighborLost) throws Exception {
-        prepareIpReachabilityMonitorAddressResolutionTest(dnsServer, targetIp);
-
+    private void expectAndDropMulticastNses(Inet6Address targetIp, boolean expectNeighborLost)
+            throws Exception {
         // Wait for the multicast NSes but never respond to them, that results in the on-link
         // DNS gets lost and onReachabilityLost callback will be invoked.
         final List<NeighborSolicitation> nsList = new ArrayList<NeighborSolicitation>();
@@ -4400,6 +4387,14 @@ public abstract class IpClientIntegrationTestCommon {
         }
     }
 
+    private void runIpReachabilityMonitorAddressResolutionTest(final String dnsServer,
+            final Inet6Address targetIp,
+            final boolean expectNeighborLost) throws Exception {
+        prepareIpReachabilityMonitorAddressResolutionTest(dnsServer, targetIp);
+        sendPacketToUnreachableNeighbor(ipv6Addr(dnsServer));
+        expectAndDropMulticastNses(targetIp, expectNeighborLost);
+    }
+
     @Test
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = true)
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
@@ -4414,6 +4409,7 @@ public abstract class IpClientIntegrationTestCommon {
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_incompleteIpv6DnsServerInDualStack_flagoff()
             throws Exception {
         final Inet6Address targetIp = ipv6Addr(IPV6_ON_LINK_DNS_SERVER);
@@ -4436,6 +4432,7 @@ public abstract class IpClientIntegrationTestCommon {
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_incompleteIpv6DefaultRouterInDualStack_flagoff()
             throws Exception {
         runIpReachabilityMonitorAddressResolutionTest(IPV6_OFF_LINK_DNS_SERVER,
@@ -4458,6 +4455,7 @@ public abstract class IpClientIntegrationTestCommon {
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_ignoreOnLinkIpv6DnsOrganicNudFailure_flagoff()
             throws Exception {
         final Inet6Address targetIp = ipv6Addr(IPV6_ON_LINK_DNS_SERVER);
@@ -4480,6 +4478,7 @@ public abstract class IpClientIntegrationTestCommon {
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     public void testIpReachabilityMonitor_ignoreIpv6DefaultRouterOrganicNudFailure_flagoff()
             throws Exception {
         runIpReachabilityMonitorAddressResolutionTest(IPV6_OFF_LINK_DNS_SERVER,
@@ -4490,6 +4489,7 @@ public abstract class IpClientIntegrationTestCommon {
     private void runIpReachabilityMonitorEverReachableIpv6NeighborTest(final String dnsServer,
             final Inet6Address targetIp) throws Exception {
         prepareIpReachabilityMonitorAddressResolutionTest(dnsServer, targetIp);
+        sendPacketToUnreachableNeighbor(ipv6Addr(dnsServer));
 
         // Simulate the default router/DNS was reachable by responding to multicast NS(not for DAD).
         NeighborSolicitation ns;
@@ -6049,6 +6049,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastDay_flagOff() throws Exception {
@@ -6063,6 +6064,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastDay_notUpToThreshold()
@@ -6096,6 +6098,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastWeek_flagOff() throws Exception {
@@ -6115,6 +6118,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastWeek_notUpToThreshold() throws Exception {
@@ -6148,6 +6152,42 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresStopWritingEvents() throws Exception {
+        // Add enough failures that NUD failures are ignored.
+        long when = (long) (System.currentTimeMillis() - SIX_HOURS_IN_MS * 1.1);
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 10, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+
+        // Add enough recent failures to almost, but not quite reach the 6-hour threshold.
+        when = (long) (System.currentTimeMillis() - SIX_HOURS_IN_MS * 0.1);
+        expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+
+        prepareIpReachabilityMonitorAddressResolutionTest(IPV6_ON_LINK_DNS_SERVER,
+                ROUTER_LINK_LOCAL);
+
+        // The first new failure is ignored and written to the database.
+        // The total is 10 failures in the last 6 hours.
+        sendPacketToUnreachableNeighbor(ipv6Addr(IPV6_OFF_LINK_DNS_SERVER));
+        expectAndDropMulticastNses(ROUTER_LINK_LOCAL, false /* expectNeighborLost */);
+        verify(mIpMemoryStore).storeNetworkEvent(any(), anyLong(), anyLong(),
+                eq(IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC), any());
+
+        // The second new failure is ignored, but not written.
+        reset(mIpMemoryStore);
+        sendPacketToUnreachableNeighbor(ipv6Addr(IPV6_ON_LINK_DNS_SERVER));
+        expectAndDropMulticastNses(ipv6Addr(IPV6_ON_LINK_DNS_SERVER),
+                false /* expectNeighborLost */);
+        verifyNoMoreInteractions(mIpMemoryStore);
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastWeek_stopWritingEvent_flagOff()
@@ -6164,6 +6204,7 @@ public abstract class IpClientIntegrationTestCommon {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION, enabled = false)
     @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
     @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
     public void testIgnoreNudFailuresIfTooManyInPastWeek_stopWritingEvent_notUpToThreshold()
diff --git a/tests/integration/root/android/net/ip/IpClientRootTest.kt b/tests/integration/root/android/net/ip/IpClientRootTest.kt
index 3a56139f..7ef0d8a7 100644
--- a/tests/integration/root/android/net/ip/IpClientRootTest.kt
+++ b/tests/integration/root/android/net/ip/IpClientRootTest.kt
@@ -19,6 +19,7 @@ package android.net.ip
 import android.Manifest.permission.INTERACT_ACROSS_USERS_FULL
 import android.Manifest.permission.NETWORK_SETTINGS
 import android.Manifest.permission.READ_DEVICE_CONFIG
+import android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG
 import android.Manifest.permission.WRITE_DEVICE_CONFIG
 import android.net.IIpMemoryStore
 import android.net.IIpMemoryStoreCallbacks
@@ -191,7 +192,11 @@ class IpClientRootTest : IpClientIntegrationTestCommon() {
     private val mOriginalPropertyValues = ArrayMap<String, String>()
 
     override fun setDeviceConfigProperty(name: String?, value: String?) {
-        automation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG, WRITE_DEVICE_CONFIG)
+        automation.adoptShellPermissionIdentity(
+            READ_DEVICE_CONFIG,
+            WRITE_DEVICE_CONFIG,
+            WRITE_ALLOWLISTED_DEVICE_CONFIG
+        )
         try {
             // Do not use computeIfAbsent as it would overwrite null values,
             // property originally unset.
@@ -214,7 +219,11 @@ class IpClientRootTest : IpClientIntegrationTestCommon() {
     @After
     fun tearDownDeviceConfigProperties() {
         if (testSkipped()) return
-        automation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG, WRITE_DEVICE_CONFIG)
+        automation.adoptShellPermissionIdentity(
+            READ_DEVICE_CONFIG,
+            WRITE_DEVICE_CONFIG,
+            WRITE_ALLOWLISTED_DEVICE_CONFIG
+        )
         try {
             for (key in mOriginalPropertyValues.keys) {
                 if (key == null) continue
diff --git a/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt b/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
index f5c06a18..29e6237a 100644
--- a/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
+++ b/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
@@ -58,7 +58,7 @@ import com.android.net.module.util.structs.PrefixInformationOption
 import com.android.networkstack.util.NetworkStackUtils
 import com.android.testutils.ArpRequestFilter
 import com.android.testutils.IPv4UdpFilter
-import com.android.testutils.TapPacketReader
+import com.android.testutils.PollPacketReader
 import java.io.FileDescriptor
 import java.net.Inet4Address
 import java.net.Inet6Address
@@ -94,7 +94,7 @@ class NetworkStackUtilsIntegrationTest {
     private val readerHandler = HandlerThread(
             NetworkStackUtilsIntegrationTest::class.java.simpleName)
     private lateinit var iface: TestNetworkInterface
-    private lateinit var reader: TapPacketReader
+    private lateinit var reader: PollPacketReader
 
     @Before
     fun setUp() {
@@ -106,7 +106,7 @@ class NetworkStackUtilsIntegrationTest {
             inst.uiAutomation.dropShellPermissionIdentity()
         }
         readerHandler.start()
-        reader = TapPacketReader(readerHandler.threadHandler, iface.fileDescriptor.fileDescriptor,
+        reader = PollPacketReader(readerHandler.threadHandler, iface.fileDescriptor.fileDescriptor,
                 1500 /* maxPacketSize */)
         readerHandler.threadHandler.post { reader.start() }
     }
diff --git a/tests/unit/jni/apf_jni.cpp b/tests/unit/jni/apf_jni.cpp
index 873b217c..841f6e54 100644
--- a/tests/unit/jni/apf_jni.cpp
+++ b/tests/unit/jni/apf_jni.cpp
@@ -284,21 +284,43 @@ static jobjectArray com_android_server_ApfTest_disassembleApf(
     return disassembleOutput;
 }
 
-jbyteArray com_android_server_ApfTest_getTransmittedPacket(JNIEnv* env,
-                                                           jclass) {
-    jbyteArray jdata = env->NewByteArray((jint) apf_test_tx_packet_len);
-    if (jdata == NULL) { return NULL; }
-    if (apf_test_tx_packet_len == 0) { return jdata; }
-
-    env->SetByteArrayRegion(jdata, 0, (jint) apf_test_tx_packet_len,
-                            reinterpret_cast<jbyte*>(apf_test_buffer));
+static jobjectArray com_android_server_ApfTest_getAllTransmittedPackets(JNIEnv* env,
+                                                                        jclass) {
+    jclass arrayListClass = env->FindClass("java/util/ArrayList");
+    jmethodID arrayListConstructor = env->GetMethodID(arrayListClass, "<init>", "()V");
+    jobject arrayList = env->NewObject(arrayListClass, arrayListConstructor);
+
+    jmethodID addMethod = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");
+    packet_buffer *ptr = head;
+    while (ptr) {
+        jbyteArray jdata = env->NewByteArray((jint) ptr->len);
+        if (jdata == NULL) {
+            return static_cast<jobjectArray>(arrayList);
+        }
+
+        env->SetByteArrayRegion(jdata, 0, (jint) ptr->len,
+                                reinterpret_cast<jbyte*>(ptr->data));
+        env->CallBooleanMethod(arrayList, addMethod, jdata);
+        env->DeleteLocalRef(jdata);
+
+        ptr = ptr->next;
+    }
 
-    return jdata;
+    env->DeleteLocalRef(arrayListClass);
+    return static_cast<jobjectArray>(arrayList);
 }
 
 void com_android_server_ApfTest_resetTransmittedPacketMemory(JNIEnv, jclass) {
-    apf_test_tx_packet_len = 0;
-    memset(apf_test_buffer, 0xff, sizeof(apf_test_buffer));
+    packet_buffer* current = head;
+    packet_buffer* tmp = NULL;
+    while (current) {
+        tmp = current->next;
+        free(current);
+        current = tmp;
+    }
+
+    head = NULL;
+    tail = NULL;
 }
 
 extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
@@ -319,8 +341,8 @@ extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
                     (void*)com_android_server_ApfTest_dropsAllPackets },
             { "disassembleApf", "([B)[Ljava/lang/String;",
               (void*)com_android_server_ApfTest_disassembleApf },
-            { "getTransmittedPacket", "()[B",
-              (void*)com_android_server_ApfTest_getTransmittedPacket },
+            { "getAllTransmittedPackets", "()Ljava/util/List;",
+                    (void*)com_android_server_ApfTest_getAllTransmittedPackets },
             { "resetTransmittedPacketMemory", "()V",
               (void*)com_android_server_ApfTest_resetTransmittedPacketMemory },
     };
diff --git a/tests/unit/src/android/net/apf/ApfFilterTest.kt b/tests/unit/src/android/net/apf/ApfFilterTest.kt
index 15ff2241..0645cdd8 100644
--- a/tests/unit/src/android/net/apf/ApfFilterTest.kt
+++ b/tests/unit/src/android/net/apf/ApfFilterTest.kt
@@ -60,6 +60,7 @@ import android.net.apf.ApfCounterTracker.Counter.PASSED_MLD
 import android.net.apf.ApfFilter.Dependencies
 import android.net.apf.ApfTestHelpers.Companion.TIMEOUT_MS
 import android.net.apf.ApfTestHelpers.Companion.consumeInstalledProgram
+import android.net.apf.ApfTestHelpers.Companion.consumeTransmittedPackets
 import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
 import android.net.apf.BaseApfGenerator.APF_VERSION_3
 import android.net.apf.BaseApfGenerator.APF_VERSION_6
@@ -97,6 +98,7 @@ import com.android.testutils.DevSdkIgnoreRunner
 import com.android.testutils.quitResources
 import com.android.testutils.waitForIdle
 import java.io.FileDescriptor
+import java.net.Inet4Address
 import java.net.Inet6Address
 import java.net.InetAddress
 import kotlin.test.assertContentEquals
@@ -1309,7 +1311,7 @@ class ApfFilterTest {
             DROPPED_ARP_REQUEST_REPLIED
         )
 
-        val transmittedPacket = ApfJniUtils.getTransmittedPacket()
+        val transmittedPackets = consumeTransmittedPackets(1)
         val expectedArpReplyBuf = ArpPacket.buildArpPacket(
             senderMacAddress,
             apfFilter.mHardwareAddress,
@@ -1322,7 +1324,7 @@ class ApfFilterTest {
         expectedArpReplyBuf.get(expectedArpReplyPacket)
         assertContentEquals(
             expectedArpReplyPacket + ByteArray(18) { 0 },
-            transmittedPacket
+            transmittedPackets[0]
         )
     }
 
@@ -1848,6 +1850,7 @@ class ApfFilterTest {
         apfFilter.setLinkProperties(lp)
         val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
         val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
+        val expectPackets = mutableListOf<ByteArray>()
         for (addr in validIpv6Addresses) {
             // unicast solicited NS request
             val receivedUcastNsPacket = generateNsPacket(
@@ -1865,7 +1868,6 @@ class ApfFilterTest {
                 DROPPED_IPV6_NS_REPLIED_NON_DAD
             )
 
-            val transmittedUcastPacket = ApfJniUtils.getTransmittedPacket()
             val expectedUcastNaPacket = generateNaPacket(
                 apfFilter.mHardwareAddress,
                 senderMacAddress,
@@ -1874,11 +1876,7 @@ class ApfFilterTest {
                 0xe0000000.toInt(), //  R=1, S=1, O=1
                 addr
             )
-
-            assertContentEquals(
-                expectedUcastNaPacket,
-                transmittedUcastPacket
-            )
+            expectPackets.add(expectedUcastNaPacket)
 
             val solicitedMcastAddr = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(
                 InetAddress.getByAddress(addr) as Inet6Address
@@ -1902,7 +1900,6 @@ class ApfFilterTest {
                 DROPPED_IPV6_NS_REPLIED_NON_DAD
             )
 
-            val transmittedMcastPacket = ApfJniUtils.getTransmittedPacket()
             val expectedMcastNaPacket = generateNaPacket(
                 apfFilter.mHardwareAddress,
                 senderMacAddress,
@@ -1911,11 +1908,12 @@ class ApfFilterTest {
                 0xe0000000.toInt(), // R=1, S=1, O=1
                 addr
             )
+            expectPackets.add(expectedMcastNaPacket)
+        }
 
-            assertContentEquals(
-                expectedMcastNaPacket,
-                transmittedMcastPacket
-            )
+        val transmitPackets = consumeTransmittedPackets(expectPackets.size)
+        for (i in transmitPackets.indices) {
+            assertContentEquals(expectPackets[i], transmitPackets[i])
         }
     }
 
@@ -1950,7 +1948,7 @@ class ApfFilterTest {
             DROPPED_IPV6_NS_REPLIED_NON_DAD
         )
 
-        val transmitPkt = ApfJniUtils.getTransmittedPacket()
+        val transmitPkts = consumeTransmittedPackets(1)
         // Using scapy to generate IPv6 NA packet:
         // eth = Ether(src="02:03:04:05:06:07", dst="00:01:02:03:04:05")
         // ip6 = IPv6(src="2001::200:1a:3344:1122", dst="2001::200:1a:1122:3344", hlim=255, tc=20)
@@ -1964,7 +1962,7 @@ class ApfFilterTest {
         """.replace("\\s+".toRegex(), "").trim()
         assertContentEquals(
             HexDump.hexStringToByteArray(expectedNaPacket),
-            transmitPkt
+            transmitPkts[0]
         )
     }
 
@@ -2143,4 +2141,29 @@ class ApfFilterTest {
         val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
         assertContentEquals(ByteArray(4096) { 0 }, program)
     }
+
+    @Test
+    fun testApfIPv4MulticastAddrsUpdate() {
+        val apfFilter = getApfFilter()
+        // mock IPv4 multicast address from /proc/net/igmp
+        val mcastAddrs = mutableListOf(
+            InetAddress.getByName("224.0.0.1") as Inet4Address
+        )
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+
+        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
+        apfFilter.updateIPv4MulticastAddrs()
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
+
+        val addr = InetAddress.getByName("239.0.0.1") as Inet4Address
+        mcastAddrs.add(addr)
+        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
+        apfFilter.updateIPv4MulticastAddrs()
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
+
+        apfFilter.updateIPv4MulticastAddrs()
+        verify(ipClientCallback, never()).installPacketFilter(any())
+    }
 }
diff --git a/tests/unit/src/android/net/apf/ApfGeneratorTest.kt b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
index 98b2a428..85182d47 100644
--- a/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
+++ b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
@@ -29,6 +29,7 @@ import android.net.apf.ApfTestHelpers.Companion.PASS
 import android.net.apf.ApfTestHelpers.Companion.assertDrop
 import android.net.apf.ApfTestHelpers.Companion.assertPass
 import android.net.apf.ApfTestHelpers.Companion.assertVerdict
+import android.net.apf.ApfTestHelpers.Companion.consumeTransmittedPackets
 import android.net.apf.ApfTestHelpers.Companion.decodeCountersIntoMap
 import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
 import android.net.apf.BaseApfGenerator.APF_VERSION_2
@@ -52,6 +53,7 @@ import java.nio.ByteBuffer
 import kotlin.test.assertContentEquals
 import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
+import org.junit.After
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -75,6 +77,11 @@ class ApfGeneratorTest {
 
     private val testPacket = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
 
+    @After
+    fun tearDown() {
+        ApfJniUtils.resetTransmittedPacketMemory()
+    }
+
     @Test
     fun testDataInstructionMustComeFirst() {
         var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
@@ -561,14 +568,14 @@ class ApfGeneratorTest {
                 byteArrayOf(
                         encodeInstruction(opcode = 14, immLength = 2, register = 1), 1, 0
                 ) + largeByteArray + byteArrayOf(
-                        encodeInstruction(opcode = 21, immLength = 1, register = 0), 48, 6, 9
+                        encodeInstruction(opcode = 21, immLength = 1, register = 0), 48, 5, -7
                 ),
                 program
         )
         assertContentEquals(
                 listOf(
                         "0: data        256, " + "01".repeat(256),
-                        "259: debugbuf    size=1545"
+                        "259: debugbuf    size=1529"
                 ),
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
@@ -806,12 +813,13 @@ class ApfGeneratorTest {
                 .addTransmitWithoutChecksum()
                 .generate()
         assertPass(APF_VERSION_6, program, ByteArray(MIN_PKT_SIZE))
+        val transmitPackets = consumeTransmittedPackets(1)
         assertContentEquals(
                 byteArrayOf(
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff.toByte(),
                         0xff.toByte(), 0xff.toByte(), 0xfe.toByte(), 0xff.toByte(), 0xfe.toByte(),
                         0xfd.toByte(), 0xfc.toByte(), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07),
-                ApfJniUtils.getTransmittedPacket()
+                transmitPackets[0]
         )
     }
 
@@ -836,9 +844,10 @@ class ApfGeneratorTest {
                 .addTransmitWithoutChecksum()
                 .generate()
         assertPass(APF_VERSION_6, program, testPacket)
+        val transmitPackets = consumeTransmittedPackets(1)
         assertContentEquals(
                 byteArrayOf(33, 34, 35, 1, 2, 3, 4, 33, 34, 35, 1, 2, 3, 4),
-                ApfJniUtils.getTransmittedPacket()
+                transmitPackets[0]
         )
     }
 
@@ -854,7 +863,7 @@ class ApfGeneratorTest {
                 .generate()
         assertContentEquals(listOf(
                 "0: data        9, 112233445566778899",
-                "12: debugbuf    size=1772",
+                "12: debugbuf    size=1756",
                 "16: allocate    18",
                 "20: datacopy    src=3, len=6",
                 "23: datacopy    src=4, len=3",
@@ -863,7 +872,8 @@ class ApfGeneratorTest {
                 "32: transmit    ip_ofs=255"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
         assertPass(APF_VERSION_6, program, testPacket)
-        val transmitPkt = HexDump.toHexString(ApfJniUtils.getTransmittedPacket())
+        val transmitPackets = consumeTransmittedPackets(1)
+        val transmitPkt = HexDump.toHexString(transmitPackets[0])
         assertEquals("112233445566223344778899112233445566", transmitPkt)
     }
 
@@ -1337,7 +1347,8 @@ class ApfGeneratorTest {
                 )
                 .generate()
         assertPass(APF_VERSION_6, program, testPacket)
-        val txBuf = ByteBuffer.wrap(ApfJniUtils.getTransmittedPacket())
+        val transmitPackets = consumeTransmittedPackets(1)
+        val txBuf = ByteBuffer.wrap(transmitPackets[0])
         Struct.parse(EthernetHeader::class.java, txBuf)
         val ipv4Hdr = Struct.parse(Ipv4Header::class.java, txBuf)
         val udpHdr = Struct.parse(UdpHeader::class.java, txBuf)
diff --git a/tests/unit/src/android/net/apf/ApfJniUtils.java b/tests/unit/src/android/net/apf/ApfJniUtils.java
index e6a7ad72..f61bd4ce 100644
--- a/tests/unit/src/android/net/apf/ApfJniUtils.java
+++ b/tests/unit/src/android/net/apf/ApfJniUtils.java
@@ -15,6 +15,8 @@
  */
 package android.net.apf;
 
+import java.util.List;
+
 /**
  * The class contains the helper method for interacting with native apf code.
  */
@@ -61,9 +63,9 @@ public class ApfJniUtils {
     public static native String[] disassembleApf(byte[] program);
 
     /**
-     * Get the transmitted packet.
+     * Get all transmitted packets.
      */
-    public static native byte[] getTransmittedPacket();
+    public static native List<byte[]> getAllTransmittedPackets();
 
     /**
      * Reset the memory region that stored the transmitted packet.
diff --git a/tests/unit/src/android/net/apf/ApfTest.java b/tests/unit/src/android/net/apf/ApfTest.java
index 14e2122d..9a4a2242 100644
--- a/tests/unit/src/android/net/apf/ApfTest.java
+++ b/tests/unit/src/android/net/apf/ApfTest.java
@@ -2355,7 +2355,7 @@ public class ApfTest {
         mCurrentTimeMs += timePassedSeconds * DateUtils.SECOND_IN_MILLIS;
         doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
+            apfFilter.installNewProgram();
         }
         byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         verifyRaLifetime(program, basePacket, routerLifetime, timePassedSeconds);
@@ -2365,7 +2365,7 @@ public class ApfTest {
                 ((routerLifetime / 6) - timePassedSeconds - 1) * DateUtils.SECOND_IN_MILLIS;
         doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
+            apfFilter.installNewProgram();
         }
         program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, basePacket.array());
@@ -2373,7 +2373,7 @@ public class ApfTest {
         mCurrentTimeMs += DateUtils.SECOND_IN_MILLIS;
         doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
+            apfFilter.installNewProgram();
         }
         program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertPass(program, basePacket.array());
@@ -2810,7 +2810,7 @@ public class ApfTest {
         verify(mNetworkQuirkMetrics).statsWrite();
         reset(mNetworkQuirkMetrics);
         synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
+            apfFilter.installNewProgram();
         }
         verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
         verify(mNetworkQuirkMetrics).statsWrite();
@@ -2836,12 +2836,12 @@ public class ApfTest {
     public void testGenerateApfProgramException() {
         final ApfConfiguration config = getDefaultConfig();
         ApfFilter apfFilter = getApfFilter(config);
-        // Simulate exception during installNewProgramLocked() by mocking
+        // Simulate exception during installNewProgram() by mocking
         // mDependencies.elapsedRealtime() to throw an exception (this method doesn't throw in
         // real-world scenarios).
         doThrow(new IllegalStateException("test exception")).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
+            apfFilter.installNewProgram();
         }
         verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_GENERATE_FILTER_EXCEPTION);
         verify(mNetworkQuirkMetrics).statsWrite();
diff --git a/tests/unit/src/android/net/apf/ApfTestHelpers.kt b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
index 6a5688ed..72394f7d 100644
--- a/tests/unit/src/android/net/apf/ApfTestHelpers.kt
+++ b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
@@ -330,5 +330,14 @@ class ApfTestHelpers private constructor() {
             clearInvocations<Any>(ipClientCb)
             return programCaptor.value
         }
+
+        fun consumeTransmittedPackets(
+            expectCnt: Int
+        ): List<ByteArray> {
+            val transmittedPackets = ApfJniUtils.getAllTransmittedPackets()
+            assertEquals(expectCnt, transmittedPackets.size)
+            ApfJniUtils.resetTransmittedPacketMemory()
+            return transmittedPackets
+        }
     }
 }
diff --git a/tests/unit/src/android/net/ip/DhcpClientTest.kt b/tests/unit/src/android/net/ip/DhcpClientTest.kt
new file mode 100644
index 00000000..6210bc5b
--- /dev/null
+++ b/tests/unit/src/android/net/ip/DhcpClientTest.kt
@@ -0,0 +1,102 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.net.ip
+
+import android.content.Context
+import android.content.res.Resources
+import android.net.NetworkStackIpMemoryStore
+import android.net.dhcp.DhcpClient
+import androidx.test.filters.SmallTest
+import androidx.test.ext.junit.runners.AndroidJUnit4
+
+import com.android.networkstack.R
+import com.android.networkstack.metrics.IpProvisioningMetrics
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.Mockito.any
+import org.mockito.Mockito.doReturn
+import org.mockito.Mockito.mock
+import org.mockito.Mockito.spy
+import kotlin.test.assertEquals
+
+const val HOSTNAME = "myhostname"
+const val HOSTNAME1 = "myhostname1"
+const val HOSTNAME2 = "myhostname2"
+const val HOSTNAME3 = "myhostname3"
+const val PROP1 = "ro.product.model"
+const val PROP2 = "ro.product.name"
+const val PROP3 = "ro.vendor.specialname"
+const val PROP_EMPTY = "ro.product.name_empty"
+const val PROP_INVALID = "ro.notproduct.and.notvendor"
+
+/**
+ * Unit tests for DhcpClient (currently only for its Dependencies class). Note that most of
+ * DhcpClient's functionality is (and should be) tested in the IpClient integration tests and in the
+ * DhcpPacket unit tests, not here. This test class is mostly intended to test small bits of
+ * functionality that would be difficult to exercise in those larger tests.
+ */
+@RunWith(AndroidJUnit4::class)
+@SmallTest
+class DhcpClientTest {
+    private val context = mock(Context::class.java)
+    private val resources = mock(Resources::class.java)
+
+    // This is a spy because DhcpClient.Dependencies is the actual class under test.
+    // The tests mock some of the class's methods, exercise certain methods that end up calling
+    // the mocked methods, and checks the results.
+    private val deps = spy(DhcpClient.Dependencies(
+        mock(NetworkStackIpMemoryStore::class.java),
+        mock(IpProvisioningMetrics::class.java)))
+
+    @Before
+    fun setUp() {
+        doReturn(resources).`when`(context).resources
+        doReturn(HOSTNAME).`when`(deps).getDeviceName(any())
+        doReturn(HOSTNAME1).`when`(deps).getSystemProperty(PROP1)
+        doReturn(HOSTNAME2).`when`(deps).getSystemProperty(PROP2)
+        doReturn(HOSTNAME2).`when`(deps).getSystemProperty(PROP_INVALID)
+        doReturn(HOSTNAME3).`when`(deps).getSystemProperty(PROP3)
+        doReturn("").`when`(deps).getSystemProperty(PROP_EMPTY)
+    }
+
+    private fun setHostnameProps(props: Array<String>?) {
+        doReturn(props).`when`(resources).getStringArray(
+            R.array.config_dhcp_client_hostname_preferred_props)
+    }
+
+    @Test
+    fun testGetHostname_PropsSet() {
+        setHostnameProps(null)
+        assertEquals(HOSTNAME, deps.getCustomHostname(context))
+
+        setHostnameProps(emptyArray())
+        assertEquals(HOSTNAME, deps.getCustomHostname(context))
+
+        setHostnameProps(arrayOf(PROP1, PROP2))
+        assertEquals(HOSTNAME1, deps.getCustomHostname(context))
+
+        setHostnameProps(arrayOf(PROP_INVALID, PROP1, PROP2))
+        assertEquals(HOSTNAME1, deps.getCustomHostname(context))
+
+        setHostnameProps(arrayOf(PROP_EMPTY, PROP2))
+        assertEquals(HOSTNAME2, deps.getCustomHostname(context))
+
+        setHostnameProps(arrayOf(PROP_EMPTY, PROP3))
+        assertEquals(HOSTNAME3, deps.getCustomHostname(context))
+    }
+}
diff --git a/tests/unit/src/android/net/ip/IpClientTest.java b/tests/unit/src/android/net/ip/IpClientTest.java
index 3fc843e3..2fb0a7fd 100644
--- a/tests/unit/src/android/net/ip/IpClientTest.java
+++ b/tests/unit/src/android/net/ip/IpClientTest.java
@@ -531,19 +531,20 @@ public class IpClientTest {
         final IpClient ipc = makeIpClient(iface);
         final String l2Key = TEST_L2KEY;
         final String cluster = TEST_CLUSTER;
+        final MacAddress bssid = MacAddress.fromString(TEST_BSSID);
 
         ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                 .withoutIPv4()
                 .withoutIpReachabilityMonitor()
                 .withInitialConfiguration(
                         conf(links(TEST_LOCAL_ADDRESSES), prefixes(TEST_PREFIXES), ips()))
+                .withLayer2Information(new Layer2Information(l2Key, cluster, bssid))
                 .build();
 
         ipc.startProvisioning(config);
         verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
         verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setFallbackMulticastFilter(false);
         verify(mCb, never()).onProvisioningFailure(any());
-        ipc.setL2KeyAndCluster(l2Key, cluster);
 
         for (String addr : TEST_LOCAL_ADDRESSES) {
             String[] parts = addr.split("/");
diff --git a/tests/unit/src/android/net/ip/IpReachabilityMonitorTest.kt b/tests/unit/src/android/net/ip/IpReachabilityMonitorTest.kt
index 98dbd647..518cec7c 100644
--- a/tests/unit/src/android/net/ip/IpReachabilityMonitorTest.kt
+++ b/tests/unit/src/android/net/ip/IpReachabilityMonitorTest.kt
@@ -290,24 +290,15 @@ class IpReachabilityMonitorTest {
         }.`when`(dependencies).makeIpNeighborMonitor(any(), any(), any())
         doReturn(mIpReachabilityMonitorMetrics)
                 .`when`(dependencies).getIpReachabilityMonitorMetrics()
-        doReturn(true).`when`(dependencies).isFeatureNotChickenedOut(
-            any(),
-            eq(IP_REACHABILITY_MCAST_RESOLICIT_VERSION)
-        )
-
-        // TODO: test with non-default flag combinations.
-        // Note: because dependencies is a mock, all features that are not specified here are
-        // neither enabled nor chickened out.
-        doReturn(true).`when`(dependencies).isFeatureNotChickenedOut(
-            any(),
-            eq(IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION)
-        )
 
         // Set flags based on test method annotations.
+        // Note: because dependencies is a mock, all features that are not specified in flag
+        // annotations are either disabled or chickened out.
         var testMethod = this::class.java.getMethod(mTestName.methodName)
         val flags = testMethod.getAnnotationsByType(Flag::class.java)
-        for (flag in flags) {
-            doReturn(flag.enabled).`when`(dependencies).isFeatureEnabled(any(), eq(flag.name))
+        for (f in flags) {
+            doReturn(f.enabled).`when`(dependencies).isFeatureEnabled(any(), eq(f.name))
+            doReturn(f.enabled).`when`(dependencies).isFeatureNotChickenedOut(any(), eq(f.name))
         }
 
         val monitorFuture = CompletableFuture<IpReachabilityMonitor>()
@@ -1032,6 +1023,8 @@ class IpReachabilityMonitorTest {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_MCAST_RESOLICIT_VERSION, true)
+    @Flag(name = IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION, enabled = true)
     fun testNudProbeFailedMetrics_defaultIPv6GatewayMacAddrChangedAfterRoaming() {
         prepareNeighborReachableButMacAddrChangedTest(
             TEST_LINK_PROPERTIES,
@@ -1043,6 +1036,8 @@ class IpReachabilityMonitorTest {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_MCAST_RESOLICIT_VERSION, true)
+    @Flag(name = IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION, enabled = true)
     fun testNudProbeFailedMetrics_defaultIPv4GatewayMacAddrChangedAfterRoaming() {
         prepareNeighborReachableButMacAddrChangedTest(
             TEST_LINK_PROPERTIES,
@@ -1055,6 +1050,8 @@ class IpReachabilityMonitorTest {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_MCAST_RESOLICIT_VERSION, true)
+    @Flag(name = IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION, enabled = true)
     fun testNudProbeFailedMetrics_defaultIPv6GatewayMacAddrChangedAfterConfirm() {
         prepareNeighborReachableButMacAddrChangedTest(
             TEST_LINK_PROPERTIES,
@@ -1067,6 +1064,8 @@ class IpReachabilityMonitorTest {
     }
 
     @Test
+    @Flag(name = IP_REACHABILITY_MCAST_RESOLICIT_VERSION, true)
+    @Flag(name = IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION, enabled = true)
     fun testNudProbeFailedMetrics_defaultIPv6GatewayMacAddrChangedAfterOrganic() {
         prepareNeighborReachableButMacAddrChangedTest(
             TEST_LINK_PROPERTIES,
diff --git a/tests/unit/src/android/net/util/RawPacketTrackerTest.kt b/tests/unit/src/android/net/util/RawPacketTrackerTest.kt
new file mode 100644
index 00000000..cecd7a06
--- /dev/null
+++ b/tests/unit/src/android/net/util/RawPacketTrackerTest.kt
@@ -0,0 +1,195 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package android.net.util
+
+import android.net.ip.ConnectivityPacketTracker
+import android.os.HandlerThread
+import androidx.test.filters.SmallTest
+import com.android.testutils.DevSdkIgnoreRunner
+import com.android.testutils.FunctionalUtils.ThrowingSupplier
+import com.android.testutils.assertThrows
+import com.android.testutils.visibleOnHandlerThread
+import kotlin.test.assertEquals
+import kotlin.test.assertTrue
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.ArgumentMatchers.eq
+import org.mockito.Mockito
+import org.mockito.Mockito.clearInvocations
+import org.mockito.Mockito.doReturn
+import org.mockito.Mockito.mock
+import org.mockito.Mockito.timeout
+import org.mockito.Mockito.verify
+import org.mockito.Mockito.verifyZeroInteractions
+
+/**
+ * Test for RawPacketTracker.
+ */
+@SmallTest
+@DevSdkIgnoreRunner.MonitorThreadLeak
+class RawPacketTrackerTest {
+    companion object {
+        private const val TEST_TIMEOUT_MS: Long = 1000
+        private const val TEST_MAX_CAPTURE_TIME_MS: Long = 1000
+        private const val TAG = "RawPacketTrackerTest"
+    }
+
+    private val deps = mock(RawPacketTracker.Dependencies::class.java)
+    private val tracker = mock(ConnectivityPacketTracker::class.java)
+    private val ifaceName = "lo"
+    private val handlerThread by lazy {
+        HandlerThread("$TAG-handler-thread").apply { start() }
+    }
+    private lateinit var rawTracker: RawPacketTracker
+
+    @Before
+    fun setUp() {
+        doReturn(handlerThread).`when`(deps).createHandlerThread()
+        doReturn(handlerThread.looper).`when`(deps).getLooper(any())
+        doReturn(tracker).`when`(deps).createPacketTracker(any(), any(), anyInt())
+        rawTracker = RawPacketTracker(deps)
+    }
+
+    @After
+    fun tearDown() {
+        Mockito.framework().clearInlineMocks()
+        handlerThread.quitSafely()
+        handlerThread.join()
+    }
+
+    @Test
+    fun testStartCapture() {
+        // start capturing
+        startCaptureOnHandler(ifaceName)
+        verifySetCapture(true, 1)
+
+        assertTrue(rawTracker.handler.hasMessages(RawPacketTracker.CMD_STOP_CAPTURE))
+    }
+
+    @Test
+    fun testInvalidStartCapture() {
+        // start capturing with negative timeout
+        assertThrows(IllegalArgumentException::class.java) {
+            startCaptureOnHandler(ifaceName, -1)
+        }
+    }
+
+    @Test
+    fun testStopCapture() {
+        // start capturing
+        startCaptureOnHandler(ifaceName)
+        // simulate capture status for stop capturing
+        verifySetCapture(true, 1)
+
+        // stop capturing
+        stopCaptureOnHandler(ifaceName)
+        verifySetCapture(false, 1)
+        verifyZeroInteractions(tracker)
+    }
+
+    @Test
+    fun testDuplicatedStartAndStop() {
+        // start capture with a long timeout
+        startCaptureOnHandler(ifaceName, 10_000)
+        verifySetCapture(true, 1)
+
+        // start capturing for multiple times
+        for (i in 1..10) {
+            assertThrows(RuntimeException::class.java) {
+                startCaptureOnHandler(ifaceName)
+            }
+        }
+
+        // expect no duplicated start capture
+        verifySetCapture(true, 0)
+
+        // stop capturing for multiple times
+        stopCaptureOnHandler(ifaceName)
+        verifySetCapture(false, 1)
+        for (i in 1..10) {
+            assertThrows(RuntimeException::class.java) {
+                stopCaptureOnHandler(ifaceName)
+            }
+        }
+
+        verifySetCapture(false, 0)
+        verifyZeroInteractions(tracker)
+    }
+
+    @Test
+    fun testMatchedPacketCount() {
+        val matchedPkt = "12345"
+        val notMatchedPkt = "54321"
+
+        // simulate get matched packet count
+        doReturn(1).`when`(tracker).getMatchedPacketCount(matchedPkt)
+        // simulate get not matched packet count
+        doReturn(0).`when`(tracker).getMatchedPacketCount(notMatchedPkt)
+
+        // start capture
+        startCaptureOnHandler(ifaceName)
+
+        assertEquals(1, getMatchedPktCntOnHandler(ifaceName, matchedPkt))
+        assertEquals(0, getMatchedPktCntOnHandler(ifaceName, notMatchedPkt))
+
+        // for non-existed interface
+        val nonExistedIface = "non-existed-iface"
+        assertThrows(RuntimeException::class.java) {
+            getMatchedPktCntOnHandler(nonExistedIface, matchedPkt)
+            getMatchedPktCntOnHandler(nonExistedIface, notMatchedPkt)
+        }
+
+        // stop capture
+        stopCaptureOnHandler(ifaceName)
+
+        // expect no matched packet after stop capturing
+        assertThrows(RuntimeException::class.java) {
+            getMatchedPktCntOnHandler(ifaceName, matchedPkt)
+            getMatchedPktCntOnHandler(ifaceName, notMatchedPkt)
+        }
+    }
+
+    private fun startCaptureOnHandler(
+        ifaceName: String, maxCaptureTime: Long = TEST_MAX_CAPTURE_TIME_MS
+    ) {
+        visibleOnHandlerThread(rawTracker.handler) {
+            rawTracker.startCapture(ifaceName, maxCaptureTime)
+        }
+    }
+
+    private fun stopCaptureOnHandler(ifaceName: String) {
+        visibleOnHandlerThread(rawTracker.handler) {
+            rawTracker.stopCapture(ifaceName)
+        }
+    }
+
+    private fun getMatchedPktCntOnHandler(ifaceName: String, packetPattern: String): Int {
+        return visibleOnHandlerThread(rawTracker.handler, ThrowingSupplier {
+            rawTracker.getMatchedPacketCount(ifaceName, packetPattern)
+        })
+    }
+
+    private fun verifySetCapture(
+        isCapture: Boolean,
+        receiveCnt: Int
+    ) {
+        verify(tracker, timeout(TEST_TIMEOUT_MS).times(receiveCnt)).setCapture(eq(isCapture))
+        clearInvocations<Any>(tracker)
+    }
+}
\ No newline at end of file
diff --git a/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt b/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
index 7f8cacb6..f23f7f6c 100644
--- a/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
+++ b/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
@@ -18,9 +18,11 @@ package com.android.networkstack.util
 import android.net.MacAddress
 import android.net.apf.ProcfsParsingUtils
 import androidx.test.filters.SmallTest
-import com.android.internal.util.HexDump
+import com.android.net.module.util.HexDump
+import java.net.Inet4Address
 import java.net.Inet6Address
 import java.net.InetAddress
+import java.nio.ByteOrder
 import kotlin.test.assertEquals
 import org.junit.Test
 
@@ -135,4 +137,149 @@ class ProcfsParsingUtilsTest {
             ProcfsParsingUtils.parseIPv6MulticastAddresses(inputString, "wlan0")
         )
     }
+
+    @Test
+    fun testParseIpv4MulticastAddressLittleEndian() {
+        val order = ByteOrder.LITTLE_ENDIAN
+
+        // the format refer to net/ipv4/igmp.c#igmp_mc_seq_show
+        val inputString = listOf(
+            "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter",
+            "1\tlo        :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0",
+            "2\tdummy0    :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0",
+            "47\twlan0     :     1      V3",
+            "\t\t\t\t020000EF     1 0:00000000\t\t0",
+            "\t\t\t\t010000EF     1 0:00000000\t\t0",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0",
+            "51\tv4-wlan0  :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0"
+        )
+
+        val expectedResult = listOf(
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("EF000002")
+            ) as Inet4Address,
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("EF000001")
+            ) as Inet4Address,
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("E0000001")
+            ) as Inet4Address,
+        )
+
+        assertEquals(
+            expectedResult,
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "wlan0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "eth0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                emptyList<String>(), "eth0", order)
+        )
+    }
+
+    @Test
+    fun testParseIpv4MulticastAddressBigEndian() {
+        val order = ByteOrder.BIG_ENDIAN
+
+        // the format refer to net/ipv4/igmp.c#igmp_mc_seq_show
+        val inputString = listOf(
+            "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter",
+            "1\tlo        :     1      V3",
+            "\t\t\t\tE0000001     1 0:00000000\t\t0",
+            "2\tdummy0    :     1      V3",
+            "\t\t\t\tE0000001     1 0:00000000\t\t0",
+            "47\twlan0     :     1      V3",
+            "\t\t\t\tEF000002     1 0:00000000\t\t0",
+            "\t\t\t\tEF000001     1 0:00000000\t\t0",
+            "\t\t\t\tE0000001     1 0:00000000\t\t0",
+            "51\tv4-wlan0  :     1      V3",
+            "\t\t\t\tE0000001     1 0:00000000\t\t0"
+        )
+
+        val expectedResult = listOf(
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("EF000002")
+            ) as Inet4Address,
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("EF000001")
+            ) as Inet4Address,
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("E0000001")
+            ) as Inet4Address,
+        )
+
+        assertEquals(
+            expectedResult,
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "wlan0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "eth0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                emptyList<String>(), "eth0", order)
+        )
+    }
+
+    @Test
+    fun testParseIpv4MulticastAddressError() {
+        val order = ByteOrder.LITTLE_ENDIAN
+
+        // the format refer to net/ipv4/igmp.c#igmp_mc_seq_show
+        // wlan0 addresses contain invalid char 'X'
+        val inputString = listOf(
+            "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter",
+            "1\tlo        :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0",
+            "2\tdummy0    :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0",
+            "47\twlan0     :     1      V3",
+            "\t\t\t\t02XXXXEF     1 0:00000000\t\t0",
+            "\t\t\t\t01XXXXEF     1 0:00000000\t\t0",
+            "\t\t\t\t01XXXXE0     1 0:00000000\t\t0",
+            "51\tv4-wlan0  :     1      V3",
+            "\t\t\t\t010000E0     1 0:00000000\t\t0"
+        )
+
+        val expectedResult = listOf(
+            InetAddress.getByAddress(
+                HexDump.hexStringToByteArray("E0000001")
+            ) as Inet4Address
+        )
+
+        assertEquals(
+            expectedResult,
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "wlan0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                inputString, "eth0", order)
+        )
+
+        assertEquals(
+            emptyList<Inet4Address>(),
+            ProcfsParsingUtils.parseIPv4MulticastAddresses(
+                emptyList<String>(), "eth0", order)
+        )
+    }
 }
diff --git a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
index 4273d952..37b157b0 100644
--- a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
+++ b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
@@ -208,7 +208,6 @@ import org.mockito.Spy;
 import java.io.ByteArrayInputStream;
 import java.io.IOException;
 import java.io.InputStream;
-import java.lang.reflect.Constructor;
 import java.net.HttpURLConnection;
 import java.net.Inet6Address;
 import java.net.InetAddress;
@@ -2519,9 +2518,9 @@ public class NetworkMonitorTest {
         verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                 .notifyPrivateDnsConfigResolved(any());
 
-        // Change the mode to opportunistic mode. Verify the callback.
+        // Change the mode to opportunistic mode. Verify the callback is fired a second time.
         wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
-        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(2)).notifyPrivateDnsConfigResolved(
                 matchPrivateDnsConfigParcelWithDohOnly("some.doh.name" /* dohName */,
                         new String[0] /* dohIps */, "/dns-query{?dns}" /* dohPath */,
                         443 /* dohPort */));
```

