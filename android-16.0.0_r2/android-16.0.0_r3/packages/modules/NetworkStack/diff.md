```diff
diff --git a/Android.bp b/Android.bp
index 5898d047..35dc6780 100644
--- a/Android.bp
+++ b/Android.bp
@@ -295,6 +295,7 @@ java_defaults {
         "net-utils-device-common-netlink",
         "net-utils-device-common-struct",
         "net-utils-device-common-struct-base",
+        "net-utils-networkstack",
     ],
 }
 
@@ -481,6 +482,10 @@ android_app {
         "privapp_whitelist_com.android.networkstack",
     ],
     updatable: true,
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 cc_library_shared {
diff --git a/TEST_MAPPING b/TEST_MAPPING
index ab504783..ac5432ae 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -39,6 +39,16 @@
       "name": "NetworkStackRootTests"
     }
   ],
+  "hsum-presubmit": [
+    {
+      "name": "NetworkStackIntegrationTests",
+      "options": [
+        {
+          "exclude-annotation": "com.android.testutils.SkipPresubmit"
+        }
+      ]
+    }
+  ],
   "mainline-presubmit": [
     // These are unit tests only, so they don't actually require any modules to be installed.
     // We must specify at least one module here or the tests won't run. Use the same set as CTS
diff --git a/jni/network_stack_utils_jni.cpp b/jni/network_stack_utils_jni.cpp
index b82f797a..33f4efeb 100644
--- a/jni/network_stack_utils_jni.cpp
+++ b/jni/network_stack_utils_jni.cpp
@@ -124,47 +124,6 @@ static void network_stack_utils_attachDhcpFilter(JNIEnv *env, jclass clazz, jobj
     }
 }
 
-// fd is a "socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)"
-static void network_stack_units_attachEgressIgmpReportFilter(
-        JNIEnv *env, jclass clazz, jobject javaFd) {
-    static sock_filter filter_code[] = {
-        // Check if skb->pkt_type is PACKET_OUTGOING
-        BPF_LOAD_SKB_PKTTYPE,
-        BPF2_REJECT_IF_NOT_EQUAL(PACKET_OUTGOING),
-
-        // Check if skb->protocol is ETH_P_IP
-        BPF_LOAD_SKB_PROTOCOL,
-        BPF2_REJECT_IF_NOT_EQUAL(ETH_P_IP),
-
-        // Check the protocol is IGMP.
-        BPF_LOAD_IPV4_U8(protocol),
-        BPF2_REJECT_IF_NOT_EQUAL(IPPROTO_IGMP),
-
-        // Check this is not a fragment.
-        BPF_LOAD_IPV4_BE16(frag_off),
-        BPF2_REJECT_IF_ANY_MASKED_BITS_SET(IP_MF | IP_OFFMASK),
-
-        // Get the IP header length.
-        BPF_LOADX_NET_RELATIVE_IPV4_HLEN,
-
-        // Check if IGMPv2/IGMPv3 join/leave message.
-        BPF_LOAD_NETX_RELATIVE_IGMP_TYPE,
-        BPF2_ACCEPT_IF_EQUAL(IGMPV2_HOST_MEMBERSHIP_REPORT),
-        BPF2_ACCEPT_IF_EQUAL(IGMP_HOST_LEAVE_MESSAGE),
-        BPF2_ACCEPT_IF_EQUAL(IGMPV3_HOST_MEMBERSHIP_REPORT),
-        BPF_REJECT,
-    };
-    static const sock_fprog filter = {
-        sizeof(filter_code) / sizeof(filter_code[0]),
-        filter_code,
-    };
-
-    int fd = netjniutils::GetNativeFileDescriptor(env, javaFd);
-    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) != 0) {
-        jniThrowErrnoException(env, "setsockopt(SO_ATTACH_FILTER)", errno);
-    }
-}
-
 // fd is a "socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)"
 static void network_stack_units_attachEgressMulticastReportFilter(
         JNIEnv *env, jclass clazz, jobject javaFd) {
@@ -339,7 +298,6 @@ static const JNINativeMethod gNetworkStackUtilsMethods[] = {
     { "addArpEntry", "([B[BLjava/lang/String;Ljava/io/FileDescriptor;)V", (void*) network_stack_utils_addArpEntry },
     { "attachDhcpFilter", "(Ljava/io/FileDescriptor;)V", (void*) network_stack_utils_attachDhcpFilter },
     { "attachRaFilter", "(Ljava/io/FileDescriptor;)V", (void*) network_stack_utils_attachRaFilter },
-    { "attachEgressIgmpReportFilter", "(Ljava/io/FileDescriptor;)V", (void*) network_stack_units_attachEgressIgmpReportFilter },
     { "attachEgressMulticastReportFilter", "(Ljava/io/FileDescriptor;)V", (void*) network_stack_units_attachEgressMulticastReportFilter },
     { "attachControlPacketFilter", "(Ljava/io/FileDescriptor;)V", (void*) network_stack_utils_attachControlPacketFilter },
 };
diff --git a/src/android/net/apf/ApfCounterTracker.java b/src/android/net/apf/ApfCounterTracker.java
index 6b15bee0..17229ec6 100644
--- a/src/android/net/apf/ApfCounterTracker.java
+++ b/src/android/net/apf/ApfCounterTracker.java
@@ -16,11 +16,17 @@
 
 package android.net.apf;
 
+import static android.net.apf.ApfCounterTracker.Counter.APF_PROGRAM_ID;
+import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_SECONDS;
+
+import android.annotation.NonNull;
 import android.util.ArrayMap;
 import android.util.Log;
+import android.util.Pair;
 
 import com.android.internal.annotations.VisibleForTesting;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Map;
@@ -64,7 +70,8 @@ public class ApfCounterTracker {
         PASSED_IPV6_NON_ICMP,
         PASSED_IPV6_UNICAST_NON_ICMP,
         PASSED_NON_IP_UNICAST,
-        PASSED_MDNS, // see also MAX_PASS_COUNTER below
+        PASSED_MDNS,
+        PASSED_RA, // see also MAX_PASS_COUNTER below
         DROPPED_ETH_BROADCAST,  // see also MIN_DROP_COUNTER below
         DROPPED_ETHER_OUR_SRC_MAC,
         DROPPED_RA,
@@ -173,7 +180,7 @@ public class ApfCounterTracker {
     public static final Counter MIN_DROP_COUNTER = Counter.DROPPED_ETH_BROADCAST;
     public static final Counter MAX_DROP_COUNTER = Counter.DROPPED_GARP_REPLY;
     public static final Counter MIN_PASS_COUNTER = Counter.PASSED_ARP_BROADCAST_REPLY;
-    public static final Counter MAX_PASS_COUNTER = Counter.PASSED_MDNS;
+    public static final Counter MAX_PASS_COUNTER = Counter.PASSED_RA;
 
     private static final String TAG = ApfCounterTracker.class.getSimpleName();
 
@@ -253,4 +260,84 @@ public class ApfCounterTracker {
     public void clearCounters() {
         mCounters.clear();
     }
+
+    /**
+     * Return readable counter for testing purposes.
+     */
+    public List<Pair<Counter, String>> dumpCountersFromData(
+            @NonNull byte[] data,
+            int filterAgeSeconds,
+            int numProgramUpdates,
+            int apfVersionSupported) throws ArrayIndexOutOfBoundsException {
+        List<Pair<Counter, String>> counterList = new ArrayList<>();
+        Counter[] counters = Counter.class.getEnumConstants();
+        long counterFilterAgeSeconds =
+                getCounterValue(data, FILTER_AGE_SECONDS);
+        long counterApfProgramId =
+                getCounterValue(data, APF_PROGRAM_ID);
+
+        for (Counter c : Arrays.asList(counters).subList(1, counters.length)) {
+            long value = getCounterValue(data, c);
+
+            String note = "";
+            boolean checkValueIncreases = true;
+            switch (c) {
+                case FILTER_AGE_SECONDS:
+                    checkValueIncreases = false;
+                    if (value != counterFilterAgeSeconds) {
+                        note = " [ERROR: impossible]";
+                    } else if (counterApfProgramId < numProgramUpdates) {
+                        note = " [IGNORE: obsolete program]";
+                    } else if (value > filterAgeSeconds) {
+                        long offset = value - filterAgeSeconds;
+                        note = " [ERROR: in the future by " + offset + "s]";
+                    }
+                    break;
+                case FILTER_AGE_16384THS:
+                    if (apfVersionSupported > BaseApfGenerator.APF_VERSION_4) {
+                        checkValueIncreases = false;
+                        if (value % 16384 == 0) {
+                            // valid, but unlikely
+                            note = " [INFO: zero fractional portion]";
+                        }
+                        if (value / 16384 != counterFilterAgeSeconds) {
+                            // should not be able to happen
+                            note = " [ERROR: mismatch with FILTER_AGE_SECONDS]";
+                        }
+                    } else if (value != 0) {
+                        note = " [UNEXPECTED: APF<=4, yet non-zero]";
+                    }
+                    break;
+                case APF_PROGRAM_ID:
+                    if (value != counterApfProgramId) {
+                        note = " [ERROR: impossible]";
+                    } else if (value < numProgramUpdates) {
+                        note = " [WARNING: OBSOLETE PROGRAM]";
+                    } else if (value > numProgramUpdates) {
+                        note = " [ERROR: INVALID FUTURE ID]";
+                    }
+                    break;
+                default:
+                    break;
+            }
+
+            // Only print non-zero counters (or those with a note)
+            if (value != 0 || !note.equals("")) {
+                counterList.add(new Pair<>(c, value + note));
+            }
+
+            if (checkValueIncreases) {
+                // If the counter's value decreases, it may have been cleaned up or there
+                // may be a bug.
+                long oldValue = getCounters().getOrDefault(c, 0L);
+                if (value < oldValue) {
+                    Log.e(TAG, String.format(
+                            "Apf Counter: %s unexpectedly decreased. oldValue: %d. "
+                            + "newValue: %d", c.toString(), oldValue, value));
+                }
+            }
+        }
+
+        return counterList;
+    }
 }
diff --git a/src/android/net/apf/ApfFilter.java b/src/android/net/apf/ApfFilter.java
index 249a1e51..60b8fb57 100644
--- a/src/android/net/apf/ApfFilter.java
+++ b/src/android/net/apf/ApfFilter.java
@@ -189,7 +189,6 @@ import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_UNICAST_NON_
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST;
 import static android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS;
-import static android.net.apf.ApfCounterTracker.getCounterValue;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
@@ -279,6 +278,7 @@ import com.android.net.module.util.CollectionUtils;
 import com.android.net.module.util.ConnectivityUtils;
 import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.PacketReader;
+import com.android.net.module.util.ProcfsParsingUtils;
 import com.android.networkstack.metrics.ApfSessionInfoMetrics;
 import com.android.networkstack.metrics.IpClientRaInfoMetrics;
 import com.android.networkstack.metrics.NetworkQuirkMetrics;
@@ -347,6 +347,7 @@ public class ApfFilter {
         public boolean handleMldOffload;
         public boolean handleIpv4PingOffload;
         public boolean handleIpv6PingOffload;
+        public boolean skipMdnsRecordWithoutPriority;
     }
 
 
@@ -416,6 +417,7 @@ public class ApfFilter {
     private final boolean mHandleMldOffload;
     private final boolean mHandleIpv4PingOffload;
     private final boolean mHandleIpv6PingOffload;
+    private final boolean mSkipMdnsRecordWithoutPriority;
 
     private final NetworkQuirkMetrics mNetworkQuirkMetrics;
     private final IpClientRaInfoMetrics mIpClientRaInfoMetrics;
@@ -562,6 +564,7 @@ public class ApfFilter {
         mHandleMldOffload = config.handleMldOffload;
         mHandleIpv4PingOffload = config.handleIpv4PingOffload;
         mHandleIpv6PingOffload = config.handleIpv6PingOffload;
+        mSkipMdnsRecordWithoutPriority = config.skipMdnsRecordWithoutPriority;
         mDependencies = dependencies;
         mNetworkQuirkMetrics = networkQuirkMetrics;
         mIpClientRaInfoMetrics = dependencies.getIpClientRaInfoMetrics();
@@ -612,7 +615,9 @@ public class ApfFilter {
                         mOffloadRules.clear();
                         mOffloadRules.addAll(allRules);
                         installNewProgram();
-                    });
+                    },
+                    mSkipMdnsRecordWithoutPriority
+                    );
             mApfMdnsOffloadEngine.registerOffloadEngine();
         } else {
             mApfMdnsOffloadEngine = null;
@@ -658,24 +663,6 @@ public class ApfFilter {
             return socket;
         }
 
-        /**
-         * Create a socket to read egress IGMPv2/v3 reports.
-         */
-        @Nullable
-        public FileDescriptor createEgressIgmpReportsReaderSocket(int ifIndex) {
-            FileDescriptor socket;
-            try {
-                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
-                NetworkStackUtils.attachEgressIgmpReportFilter(socket);
-                Os.bind(socket, makePacketSocketAddress(ETH_P_ALL, ifIndex));
-            } catch (SocketException | ErrnoException e) {
-                Log.wtf(TAG, "Error starting filter", e);
-                return null;
-            }
-
-            return socket;
-        }
-
         /**
          * Create a socket to read egress IGMPv2/v3, MLDv1/v2 reports.
          */
@@ -829,16 +816,35 @@ public class ApfFilter {
         return mApfCounterTracker.getCounters().toString();
     }
 
+    /**
+     * Dumps a list of counters and their associated string representations.
+     * This method retrieves counter data from a snapshot.
+     *
+     * @return A {@link List} of {@link Pair} objects, where each {@link Pair} contains a
+     * {@link Counter} object and its corresponding {@link String} representation.
+     * Returns {@code null} if the data snapshot is not available.
+     */
+    public @Nullable List<Pair<Counter, String>> dumpCounters() {
+        try {
+            if (mDataSnapshot == null) {
+                return null;
+            }
+
+            int filterAgeSeconds = secondsSinceBoot() - mLastTimeInstalledProgram;
+            return mApfCounterTracker.dumpCountersFromData(
+                mDataSnapshot, filterAgeSeconds, mNumProgramUpdates, mApfVersionSupported);
+        } catch (ArrayIndexOutOfBoundsException e) {
+            Log.wtf(TAG, "counter out of bound", e);
+            return null;
+        }
+    }
+
     private MulticastReportMonitor createMulticastReportMonitor() {
         FileDescriptor socketFd = null;
 
-        // Check if MLD report monitor is enabled first, it includes the IGMP report monitor.
-        if (enableMldReportsMonitor()) {
-            socketFd =
-                mDependencies.createEgressMulticastReportsReaderSocket(mInterfaceParams.index);
-        } else if (enableIgmpReportsMonitor()) {
+        if (enableMldReportsMonitor() || enableIgmpReportsMonitor()) {
             socketFd =
-                mDependencies.createEgressIgmpReportsReaderSocket(mInterfaceParams.index);
+                    mDependencies.createEgressMulticastReportsReaderSocket(mInterfaceParams.index);
         }
 
         return socketFd != null ? new MulticastReportMonitor(
@@ -3590,7 +3596,7 @@ public class ApfFilter {
         //   pass
         // insert IPv6 filter to drop, pass, or fall off the end for ICMPv6 packets
 
-        if (NetworkStackUtils.isAtLeast25Q2()) {
+        if (SdkLevel.isAtLeastB()) {
             gen.addCountAndDropIfBytesAtOffsetEqual(ETHER_SRC_ADDR_OFFSET, mHardwareAddress,
                     DROPPED_ETHER_OUR_SRC_MAC);
         } else {
@@ -4530,71 +4536,15 @@ public class ApfFilter {
             pw.println("No last snapshot.");
         } else {
             try {
-                Counter[] counters = Counter.class.getEnumConstants();
-                long counterFilterAgeSeconds =
-                        getCounterValue(mDataSnapshot, FILTER_AGE_SECONDS);
-                long counterApfProgramId =
-                        getCounterValue(mDataSnapshot, APF_PROGRAM_ID);
-                for (Counter c : Arrays.asList(counters).subList(1, counters.length)) {
-                    long value = getCounterValue(mDataSnapshot, c);
-
-                    String note = "";
-                    boolean checkValueIncreases = true;
-                    switch (c) {
-                        case FILTER_AGE_SECONDS:
-                            checkValueIncreases = false;
-                            if (value != counterFilterAgeSeconds) {
-                                note = " [ERROR: impossible]";
-                            } else if (counterApfProgramId < mNumProgramUpdates) {
-                                note = " [IGNORE: obsolete program]";
-                            } else if (value > filterAgeSeconds) {
-                                long offset = value - filterAgeSeconds;
-                                note = " [ERROR: in the future by " + offset + "s]";
-                            }
-                            break;
-                        case FILTER_AGE_16384THS:
-                            if (mApfVersionSupported > BaseApfGenerator.APF_VERSION_4) {
-                                checkValueIncreases = false;
-                                if (value % 16384 == 0) {
-                                    // valid, but unlikely
-                                    note = " [INFO: zero fractional portion]";
-                                }
-                                if (value / 16384 != counterFilterAgeSeconds) {
-                                    // should not be able to happen
-                                    note = " [ERROR: mismatch with FILTER_AGE_SECONDS]";
-                                }
-                            } else if (value != 0) {
-                                note = " [UNEXPECTED: APF<=4, yet non-zero]";
-                            }
-                            break;
-                        case APF_PROGRAM_ID:
-                            if (value != counterApfProgramId) {
-                                note = " [ERROR: impossible]";
-                            } else if (value < mNumProgramUpdates) {
-                                note = " [WARNING: OBSOLETE PROGRAM]";
-                            } else if (value > mNumProgramUpdates) {
-                                note = " [ERROR: INVALID FUTURE ID]";
-                            }
-                            break;
-                        default:
-                            break;
-                    }
-
-                    // Only print non-zero counters (or those with a note)
-                    if (value != 0 || !note.equals("")) {
-                        pw.println(c.toString() + ": " + value + note);
-                    }
-
-                    if (checkValueIncreases) {
-                        // If the counter's value decreases, it may have been cleaned up or there
-                        // may be a bug.
-                        long oldValue = mApfCounterTracker.getCounters().getOrDefault(c, 0L);
-                        if (value < oldValue) {
-                            Log.e(TAG, String.format(
-                                    "Apf Counter: %s unexpectedly decreased. oldValue: %d. "
-                                            + "newValue: %d", c.toString(), oldValue, value));
-                        }
-                    }
+                final List<Pair<Counter, String>> counters =
+                        mApfCounterTracker.dumpCountersFromData(
+                            mDataSnapshot,
+                            filterAgeSeconds,
+                            mNumProgramUpdates,
+                            mApfVersionSupported
+                        );
+                for (Pair<Counter, String> entry : counters) {
+                    pw.println(entry.first.toString() + ": " + entry.second);
                 }
             } catch (ArrayIndexOutOfBoundsException e) {
                 pw.println("Uh-oh: " + e);
diff --git a/src/android/net/apf/ApfMdnsOffloadEngine.java b/src/android/net/apf/ApfMdnsOffloadEngine.java
index 3aee08f8..46ea23f5 100644
--- a/src/android/net/apf/ApfMdnsOffloadEngine.java
+++ b/src/android/net/apf/ApfMdnsOffloadEngine.java
@@ -24,6 +24,8 @@ import android.os.Build;
 import android.os.Handler;
 import android.util.Log;
 
+import com.android.net.module.util.CollectionUtils;
+
 import java.io.IOException;
 import java.util.ArrayList;
 import java.util.List;
@@ -60,16 +62,19 @@ public class ApfMdnsOffloadEngine implements OffloadEngine {
     private final NsdManager mNsdManager;
     @NonNull
     private final Callback mCallback;
+    private final boolean mSkipMdnsRecordWithoutPriority;
 
     /**
      * Constructor for ApfOffloadEngine.
      */
     public ApfMdnsOffloadEngine(@NonNull String interfaceName, @NonNull Handler handler,
-            @NonNull NsdManager nsdManager, @NonNull Callback callback) {
+            @NonNull NsdManager nsdManager, @NonNull Callback callback,
+            boolean skipMdnsRecordWithoutPriority) {
         mInterfaceName = interfaceName;
         mHandler = handler;
         mNsdManager = nsdManager;
         mCallback = callback;
+        mSkipMdnsRecordWithoutPriority = skipMdnsRecordWithoutPriority;
     }
 
     @Override
@@ -90,8 +95,14 @@ public class ApfMdnsOffloadEngine implements OffloadEngine {
             mOffloadServiceInfos.add(info);
         }
         try {
+            final List<OffloadServiceInfo> filteredOffloadServiceInfo = CollectionUtils.filter(
+                    mOffloadServiceInfos, offloadServiceInfo -> {
+                        final boolean shouldSkip = mSkipMdnsRecordWithoutPriority
+                                && offloadServiceInfo.getPriority() == Integer.MAX_VALUE;
+                        return !shouldSkip;
+                    });
             List<MdnsOffloadRule> offloadRules = ApfMdnsUtils.extractOffloadReplyRule(
-                    mOffloadServiceInfos);
+                    filteredOffloadServiceInfo);
             mCallback.onOffloadRulesUpdated(offloadRules);
         } catch (IOException e) {
             Log.e(TAG, "Failed to extract offload reply rule", e);
diff --git a/src/android/net/apf/ApfV4Generator.java b/src/android/net/apf/ApfV4Generator.java
index fe081df1..77b0ebf1 100644
--- a/src/android/net/apf/ApfV4Generator.java
+++ b/src/android/net/apf/ApfV4Generator.java
@@ -386,6 +386,8 @@ public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {
 
     @Override
     public int getDefaultPacketHandlingSizeOverEstimate() {
+        // addLoad8intoR0(ICMP6_TYPE_OFFSET); -> 2 bytes
+        // addCountAndPassIfR0Equals(ICMPV6_ROUTER_ADVERTISEMENT, PASSED_RA); -> 11 bytes
         // addCountAndPass(PASSED_IPV6_ICMP); -> 7 bytes
         // defineLabel(mCountAndPassLabel)
         // .addLoadData(R0, 0) ->  1 bytes
@@ -397,7 +399,7 @@ public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {
         // .addAdd(1) -> 2 bytes
         // .addStoreData(R0, 0) -> 1 bytes
         // .addJump(DROP_LABEL); -> 5 bytes
-        return 25;
+        return 38;
     }
 
     /**
diff --git a/src/android/net/apf/ApfV4GeneratorBase.java b/src/android/net/apf/ApfV4GeneratorBase.java
index d7502299..77f9e783 100644
--- a/src/android/net/apf/ApfV4GeneratorBase.java
+++ b/src/android/net/apf/ApfV4GeneratorBase.java
@@ -16,15 +16,19 @@
 
 package android.net.apf;
 
+import static android.net.apf.ApfConstants.ICMP6_TYPE_OFFSET;
 import static android.net.apf.ApfConstants.IPV4_FRAGMENT_MORE_FRAGS_MASK;
 import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_MASK;
 import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_OFFSET;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_RA;
 import static android.net.apf.BaseApfGenerator.Rbit.Rbit0;
 import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
 
 
+import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
+
 import android.annotation.NonNull;
 
 import com.android.internal.annotations.VisibleForTesting;
@@ -744,7 +748,10 @@ public abstract class ApfV4GeneratorBase<Type extends ApfV4GeneratorBase<Type>>
     /**
      * Appends default packet handling and counting to the APF program.
      * This method adds logic to:
-     * 1. Increment the {@code PASSED_IPV6_ICMP} counter and pass the packet.
+     * 1. Increment the {@code PASSED_RA} counter and pass the packet if it is a Router
+     *    Advertisement packet.
+     * 2. Increment the {@code PASSED_IPV6_ICMP} counter and pass the packet if it is other
+     *    ICMPv6 packet.
      * 3. Add trampoline logic for counter processing.
      *
      *
@@ -752,6 +759,8 @@ public abstract class ApfV4GeneratorBase<Type extends ApfV4GeneratorBase<Type>>
      * @throws IllegalInstructionException If an error occurs while adding instructions.
      */
     public final Type addDefaultPacketHandling() throws IllegalInstructionException {
+        addLoad8intoR0(ICMP6_TYPE_OFFSET);
+        addCountAndPassIfR0Equals(ICMPV6_ROUTER_ADVERTISEMENT, PASSED_RA);
         addCountAndPass(PASSED_IPV6_ICMP);
         return addCountTrampoline();
     }
diff --git a/src/android/net/apf/ApfV61GeneratorBase.java b/src/android/net/apf/ApfV61GeneratorBase.java
index c60de725..1b998744 100644
--- a/src/android/net/apf/ApfV61GeneratorBase.java
+++ b/src/android/net/apf/ApfV61GeneratorBase.java
@@ -375,4 +375,31 @@ public abstract class ApfV61GeneratorBase<Type extends ApfV61GeneratorBase<Type>
         mInstructions.get(0).maybeUpdateBytesImm(data, 0, data.length);
         return self();
     }
+
+    @Override
+    public int getDataCopyChunkSize() {
+        return 511;
+    }
+
+    @Override
+    public Type addDataCopy(int src, int len) {
+        if (len < 1 || len > 511) {
+            throw new IllegalArgumentException("len must be in [1, 511], current len: " + len);
+        }
+        if (len > 255) {
+            return append(new Instruction(Opcodes.PKTDATACOPY, Rbit1).addDataOffset(src)
+                    .addU8(0).addU8(len - 256));
+        } else {
+            return append(new Instruction(Opcodes.PKTDATACOPY, Rbit1).addDataOffset(src)
+                    .addU8(len));
+        }
+    }
+
+    @Override
+    public final int getDefaultPacketHandlingSizeOverEstimate() {
+        // addLoad8intoR0(ICMP6_TYPE_OFFSET); -> 2 bytes
+        // addCountAndPassIfR0Equals(ICMPV6_ROUTER_ADVERTISEMENT, PASSED_RA); -> 9 bytes
+        // addCountAndPass(PASSED_IPV6_ICMP); -> 2 bytes
+        return 13;
+    }
 }
diff --git a/src/android/net/apf/ApfV6Generator.java b/src/android/net/apf/ApfV6Generator.java
index 07bd191c..0cf3a0cd 100644
--- a/src/android/net/apf/ApfV6Generator.java
+++ b/src/android/net/apf/ApfV6Generator.java
@@ -310,4 +310,22 @@ public final class ApfV6Generator extends ApfV6GeneratorBase<ApfV6Generator> {
                                               int partialCsum, boolean isUdp) {
         return false;
     }
+
+    @Override
+    public int getDataCopyChunkSize() {
+        return 255;
+    }
+
+    @Override
+    public ApfV6Generator addDataCopy(int src, int len) {
+        return append(new Instruction(Opcodes.PKTDATACOPY, Rbit1).addDataOffset(src).addU8(len));
+    }
+
+    @Override
+    public int getDefaultPacketHandlingSizeOverEstimate() {
+        // addLoad8intoR0(ICMP6_TYPE_OFFSET); -> 2 bytes
+        // addCountAndPassIfR0Equals(ICMPV6_ROUTER_ADVERTISEMENT, PASSED_RA); -> 11 bytes
+        // addCountAndPass(PASSED_IPV6_ICMP); -> 2 bytes
+        return 15;
+    }
 }
diff --git a/src/android/net/apf/ApfV6GeneratorBase.java b/src/android/net/apf/ApfV6GeneratorBase.java
index 90f0a281..1ad49b0c 100644
--- a/src/android/net/apf/ApfV6GeneratorBase.java
+++ b/src/android/net/apf/ApfV6GeneratorBase.java
@@ -251,6 +251,8 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
         return append(new Instruction(ExtendedOpcodes.EWRITE4, reg));
     }
 
+    abstract int getDataCopyChunkSize();
+
     /**
      * Add instructions to the end of the program to copy data from APF program/data region to
      * output buffer and auto-increment the output buffer pointer.
@@ -258,14 +260,14 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
      * It will first attempt to match {@code content} with existing data bytes. If not exist, then
      * append the {@code content} to the data bytes.
      * The method copies the content using multiple datacopy instructions if the content size
-     * exceeds 255 bytes. Each instruction will copy a maximum of 255 bytes.
+     * exceeds 255 bytes in APFv6 or 511 bytes in APFv6.1.
      */
     public final Type addDataCopy(@NonNull byte[] content) throws IllegalInstructionException {
         if (mInstructions.isEmpty()) {
             throw new IllegalInstructionException("There is no instructions");
         }
         Objects.requireNonNull(content);
-        final int chunkSize = 255;
+        final int chunkSize = getDataCopyChunkSize();
         for (int fromIndex = 0; fromIndex < content.length; fromIndex += chunkSize) {
             final int toIndex = Math.min(content.length, fromIndex + chunkSize);
             final int copySrc = mInstructions.get(0).maybeUpdateBytesImm(content, fromIndex,
@@ -292,13 +294,11 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
      * output buffer and auto-increment the output buffer pointer.
      *
      * @param src the offset inside the APF program/data region for where to start copy.
-     * @param len the length of bytes needed to be copied, only <= 255 bytes can be copied at
-     *               one time.
+     * @param len the length of bytes needed to be copied, only <= 255 bytes(APFv6) or 511 bytes
+     *            (APFv6.1) can be copied at one time.
      * @return the Type object
      */
-    public final Type addDataCopy(int src, int len) {
-        return append(new Instruction(Opcodes.PKTDATACOPY, Rbit1).addDataOffset(src).addU8(len));
-    }
+    public abstract Type addDataCopy(int src, int len);
 
     /**
      * Add an instruction to the end of the program to copy data from input packet to output
@@ -568,14 +568,6 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
     public abstract Type addJumpIfBytesAtOffsetEqualsNoneOf(int offset,
             @NonNull List<byte[]> bytesList, short tgt) throws IllegalInstructionException;
 
-    /**
-     * Check if the byte is valid dns character: A-Z,0-9,-,_,%,@
-     */
-    private static boolean isValidDnsCharacter(byte c) {
-        return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '%'
-                || c == '@';
-    }
-
     static void validateNames(@NonNull byte[] names) {
         final int len = names.length;
         if (len < 4) {
@@ -595,12 +587,7 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
             if (i + label_len >= len - 1) {
                 throw new IllegalArgumentException(errorMessage);
             }
-            while (label_len-- > 0) {
-                if (!isValidDnsCharacter(names[i++])) {
-                    throw new IllegalArgumentException("qname: " + HexDump.toHexString(names)
-                            + " contains invalid character");
-                }
-            }
+            i += label_len;
             if (names[i] == 0) {
                 i++; // skip null terminator.
             }
@@ -726,10 +713,4 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
     public final Type addCountTrampoline() {
         return self();
     }
-
-    @Override
-    public final int getDefaultPacketHandlingSizeOverEstimate() {
-        // addCountAndPass(PASSED_IPV6_ICMP); -> 2 bytes
-        return 2;
-    }
 }
diff --git a/src/android/net/apf/BaseApfGenerator.java b/src/android/net/apf/BaseApfGenerator.java
index 21d8be37..b9bc17be 100644
--- a/src/android/net/apf/BaseApfGenerator.java
+++ b/src/android/net/apf/BaseApfGenerator.java
@@ -1012,8 +1012,7 @@ public abstract class BaseApfGenerator {
     public static final int APF_VERSION_3 = 3;
     public static final int APF_VERSION_4 = 4;
     public static final int APF_VERSION_6 = 6000;
-    // TODO: update the version code once we finalized APFv6.1.
-    public static final int APF_VERSION_61 = 20250228;
+    public static final int APF_VERSION_61 = 6100;
 
 
     final ArrayList<Instruction> mInstructions = new ArrayList<Instruction>();
diff --git a/src/android/net/apf/ProcfsParsingUtils.java b/src/android/net/apf/ProcfsParsingUtils.java
deleted file mode 100644
index 16fd4b1d..00000000
--- a/src/android/net/apf/ProcfsParsingUtils.java
+++ /dev/null
@@ -1,354 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package android.net.apf;
-
-import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ALL_HOST_MULTICAST;
-
-import android.annotation.NonNull;
-import android.net.MacAddress;
-import android.util.Log;
-
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.net.module.util.HexDump;
-
-import java.io.BufferedReader;
-import java.io.IOException;
-import java.net.Inet4Address;
-import java.net.Inet6Address;
-import java.net.InetAddress;
-import java.net.UnknownHostException;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
-import java.nio.file.Paths;
-import java.util.ArrayList;
-import java.util.List;
-
-public final class ProcfsParsingUtils {
-    public static final String TAG = ProcfsParsingUtils.class.getSimpleName();
-
-    private static final String IPV6_CONF_PATH = "/proc/sys/net/ipv6/conf/";
-    private static final String IPV6_ANYCAST_PATH = "/proc/net/anycast6";
-    private static final String ETHER_MCAST_PATH = "/proc/net/dev_mcast";
-    private static final String IPV4_MCAST_PATH = "/proc/net/igmp";
-    private static final String IPV6_MCAST_PATH = "/proc/net/igmp6";
-    private static final String IPV4_DEFAULT_TTL_PATH = "/proc/sys/net/ipv4/ip_default_ttl";
-
-    private ProcfsParsingUtils() {
-    }
-
-    /**
-     * Reads the contents of a text file line by line.
-     *
-     * @param filePath The absolute path to the file to read.
-     * @return A List of Strings where each String represents a line from the file.
-     *         If an error occurs during reading, an empty list is returned, and an error is logged.
-     */
-    private static List<String> readFile(final String filePath) {
-        final List<String> lines = new ArrayList<>();
-        try (BufferedReader reader =
-                     Files.newBufferedReader(Paths.get(filePath), StandardCharsets.UTF_8)) {
-            String line;
-            while ((line = reader.readLine()) != null) {
-                lines.add(line);
-            }
-        } catch (IOException e) {
-            Log.wtf(TAG, "failed to read " + filePath, e);
-        }
-
-        return lines;
-    }
-
-    /**
-     * Parses the Neighbor Discovery traffic class from a list of strings.
-     *
-     * This function expects a list containing a single string representing the ND traffic class.
-     * If the list is empty or contains multiple lines, it assumes a default traffic class of 0.
-     *
-     * @param lines A list of strings, ideally containing one line with the ND traffic class.
-     * @return The parsed ND traffic class as an integer, or 0 if the input is invalid.
-     */
-    @VisibleForTesting
-    public static int parseNdTrafficClass(final List<String> lines) {
-        if (lines.size() != 1) {
-            return 0;   // default
-        }
-
-        return Integer.parseInt(lines.get(0));
-    }
-
-    /**
-     * Parses the default TTL value from the procfs file lines.
-     */
-    @VisibleForTesting
-    public static int parseDefaultTtl(final List<String> lines) {
-        if (lines.size() != 1) {
-            return 64;  // default ttl value as per rfc1700
-        }
-        try {
-            // ttl must be in the range [1, 255]
-            return Math.max(1, Math.min(255, Integer.parseInt(lines.get(0))));
-        } catch (NumberFormatException e) {
-            Log.e(TAG, "failed to parse default ttl.", e);
-            return 64; // default ttl value as per rfc1700
-        }
-    }
-
-    /**
-     * Parses anycast6 addresses associated with a specific interface from a list of strings.
-     *
-     * This function searches the input list for a line containing the specified interface name.
-     * If found, it extracts the IPv6 address from that line and
-     * converts it into an `Inet6Address` object.
-     *
-     * @param lines   A list of strings where each line is expected to contain
-     *                interface and address information.
-     * @param ifname  The name of the network interface to search for.
-     * @return        A list of The `Inet6Address` representing the anycast address
-     *                associated with the specified interface,
-     *                If an error occurs during parsing, an empty list is returned.
-     */
-    @VisibleForTesting
-    public static List<Inet6Address> parseAnycast6Addresses(
-            @NonNull List<String> lines, @NonNull String ifname) {
-        final List<Inet6Address> addresses = new ArrayList<>();
-        try {
-            for (String line : lines) {
-                final String[] fields = line.split("\\s+");
-                if (!fields[1].equals(ifname)) {
-                    continue;
-                }
-
-                final byte[] addr = HexDump.hexStringToByteArray(fields[2]);
-                addresses.add((Inet6Address) InetAddress.getByAddress(addr));
-            }
-        } catch (UnknownHostException e) {
-            Log.wtf("failed to convert to Inet6Address.", e);
-            addresses.clear();
-        }
-        return addresses;
-    }
-
-    /**
-     * Parses Ethernet multicast MAC addresses with a specific interface from a list of strings.
-     *
-     * @param lines A list of strings, each containing interface and MAC address information.
-     * @param ifname The name of the network interface for which to extract multicast addresses.
-     * @return A list of MacAddress objects representing the parsed multicast addresses.
-     */
-    @VisibleForTesting
-    public static List<MacAddress> parseEtherMulticastAddresses(
-            @NonNull List<String> lines, @NonNull String ifname) {
-        final List<MacAddress> addresses = new ArrayList<>();
-        for (String line: lines) {
-            final String[] fields = line.split("\\s+");
-            if (!fields[1].equals(ifname)) {
-                continue;
-            }
-
-            final byte[] addr = HexDump.hexStringToByteArray(fields[4]);
-            addresses.add(MacAddress.fromBytes(addr));
-        }
-
-        return addresses;
-    }
-
-    /**
-     * Parses IPv6 multicast addresses associated with a specific interface from a list of strings.
-     *
-     * @param lines A list of strings, each containing interface and IPv6 address information.
-     * @param ifname The name of the network interface for which to extract multicast addresses.
-     * @return A list of Inet6Address objects representing the parsed IPv6 multicast addresses.
-     *         If an error occurs during parsing, an empty list is returned.
-     */
-    @VisibleForTesting
-    public static List<Inet6Address> parseIPv6MulticastAddresses(
-            @NonNull List<String> lines, @NonNull String ifname) {
-        final List<Inet6Address> addresses = new ArrayList<>();
-        try {
-            for (String line: lines) {
-                final String[] fields = line.split("\\s+");
-                if (!fields[1].equals(ifname)) {
-                    continue;
-                }
-
-                final byte[] addr = HexDump.hexStringToByteArray(fields[2]);
-                addresses.add((Inet6Address) InetAddress.getByAddress(addr));
-            }
-        } catch (UnknownHostException e) {
-            Log.wtf(TAG, "failed to convert to Inet6Address.", e);
-            addresses.clear();
-        }
-
-        return addresses;
-    }
-
-    /**
-     * Parses IPv4 multicast addresses associated with a specific interface from a list of strings.
-     *
-     * @param lines A list of strings, each containing interface and IPv4 address information.
-     * @param ifname The name of the network interface for which to extract multicast addresses.
-     * @param endian The byte order of the address, almost always use native order.
-     * @return A list of Inet4Address objects representing the parsed IPv4 multicast addresses.
-     *         If an error occurs during parsing,
-     *         a list contains IPv4 all host (224.0.0.1) is returned.
-     */
-    @VisibleForTesting
-    public static List<Inet4Address> parseIPv4MulticastAddresses(
-            @NonNull List<String> lines, @NonNull String ifname, @NonNull ByteOrder endian) {
-        final List<Inet4Address> ipAddresses = new ArrayList<>();
-
-        try {
-            String name = "";
-            // parse output similar to `ip maddr` command (iproute2/ip/ipmaddr.c#read_igmp())
-            for (String line : lines) {
-                final String[] parts = line.trim().split("\\s+");
-                if (!line.startsWith("\t")) {
-                    name = parts[1];
-                    if (name.endsWith(":")) {
-                        name = name.substring(0, name.length() - 1);
-                    }
-                    continue;
-                }
-
-                if (!name.equals(ifname)) {
-                    continue;
-                }
-
-                final String hexIp = parts[0];
-                final byte[] ipArray = HexDump.hexStringToByteArray(hexIp);
-                final byte[] convertArray =
-                    (endian == ByteOrder.LITTLE_ENDIAN)
-                        ? convertIPv4BytesToBigEndian(ipArray) : ipArray;
-                final Inet4Address ipv4Address =
-                        (Inet4Address) InetAddress.getByAddress(convertArray);
-
-                ipAddresses.add(ipv4Address);
-            }
-        } catch (Exception e) {
-            Log.wtf(TAG, "failed to convert to Inet4Address.", e);
-            // always return IPv4 all host address (224.0.0.1) if any error during parsing.
-            // this aligns with kernel behavior, it will join 224.0.0.1 when the interface is up.
-            ipAddresses.clear();
-            ipAddresses.add(IPV4_ADDR_ALL_HOST_MULTICAST);
-        }
-
-        return ipAddresses;
-    }
-
-    /**
-     * Converts an IPv4 address from little-endian byte order to big-endian byte order.
-     *
-     * @param bytes The IPv4 address in little-endian byte order.
-     * @return The IPv4 address in big-endian byte order.
-     */
-    private static byte[] convertIPv4BytesToBigEndian(byte[] bytes) {
-        final ByteBuffer buffer = ByteBuffer.wrap(bytes);
-        buffer.order(ByteOrder.LITTLE_ENDIAN);
-        final ByteBuffer bigEndianBuffer = ByteBuffer.allocate(4);
-        bigEndianBuffer.order(ByteOrder.BIG_ENDIAN);
-        bigEndianBuffer.putInt(buffer.getInt());
-        return bigEndianBuffer.array();
-    }
-
-    /**
-     * Returns the default TTL value for IPv4 packets.
-     */
-    public static int getIpv4DefaultTtl() {
-        return parseDefaultTtl(readFile(IPV4_DEFAULT_TTL_PATH));
-    }
-
-    /**
-     * Returns the default HopLimit value for IPv6 packets.
-     */
-    public static int getIpv6DefaultHopLimit(@NonNull String ifname) {
-        final String hopLimitPath = IPV6_CONF_PATH + ifname + "/hop_limit";
-        return parseDefaultTtl(readFile(hopLimitPath));
-    }
-
-    /**
-     * Returns the traffic class for the specified interface.
-     * The function loads the existing traffic class from the file
-     * `/proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass`. If the file does not exist, the
-     * function returns 0.
-     *
-     * @param ifname The name of the interface.
-     * @return The traffic class for the interface.
-     */
-    public static int getNdTrafficClass(final String ifname) {
-        final String ndTcPath = IPV6_CONF_PATH + ifname + "/ndisc_tclass";
-        final List<String> lines = readFile(ndTcPath);
-        return parseNdTrafficClass(lines);
-    }
-
-    /**
-     * The function loads the existing IPv6 anycast address from the file `/proc/net/anycast6`.
-     * If the file does not exist or the interface is not found, the function
-     * returns an empty list.
-     *
-     * @param ifname The name of the interface.
-     * @return A list of the IPv6 anycast addresses for the interface.
-     */
-    public static List<Inet6Address> getAnycast6Addresses(@NonNull String ifname) {
-        final List<String> lines = readFile(IPV6_ANYCAST_PATH);
-        return parseAnycast6Addresses(lines, ifname);
-    }
-
-    /**
-     * The function loads the existing Ethernet multicast addresses from
-     * the file `/proc/net/dev_mcast`.
-     * If the file does not exist or the interface is not found, the function returns empty list.
-     *
-     * @param ifname The name of the interface.
-     * @return A list of MacAddress objects representing the multicast addresses
-     *         found for the interface.
-     *         If the file cannot be read or there are no addresses, an empty list is returned.
-     */
-    public static List<MacAddress> getEtherMulticastAddresses(@NonNull String ifname) {
-        final List<String> lines = readFile(ETHER_MCAST_PATH);
-        return parseEtherMulticastAddresses(lines, ifname);
-    }
-
-    /**
-     * The function loads the existing IPv6 multicast addresses from the file `/proc/net/igmp6`.
-     * If the file does not exist or the interface is not found, the function returns empty list.
-     *
-     * @param ifname The name of the network interface to query.
-     * @return A list of Inet6Address objects representing the IPv6 multicast addresses
-     *         found for the interface.
-     *         If the file cannot be read or there are no addresses, an empty list is returned.
-     */
-    public static List<Inet6Address> getIpv6MulticastAddresses(@NonNull String ifname) {
-        final List<String> lines = readFile(IPV6_MCAST_PATH);
-        return parseIPv6MulticastAddresses(lines, ifname);
-    }
-
-    /**
-     * The function loads the existing IPv4 multicast addresses from the file `/proc/net/igmp6`.
-     * If the file does not exist or the interface is not found, the function returns empty list.
-     *
-     * @param ifname The name of the network interface to query.
-     * @return A list of Inet4Address objects representing the IPv4 multicast addresses
-     *         found for the interface.
-     *         If the file cannot be read or there are no addresses, an empty list is returned.
-     */
-    public static List<Inet4Address> getIPv4MulticastAddresses(@NonNull String ifname) {
-        final List<String> lines = readFile(IPV4_MCAST_PATH);
-        // follow the same pattern as NetlinkMonitor#handlePacket() for device's endian order
-        return parseIPv4MulticastAddresses(lines, ifname, ByteOrder.nativeOrder());
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6AdvertisePacket.java b/src/android/net/dhcp6/Dhcp6AdvertisePacket.java
deleted file mode 100644
index 263ab5ff..00000000
--- a/src/android/net/dhcp6/Dhcp6AdvertisePacket.java
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 ADVERTISE packet class, a server sends an Advertise message to indicate that it's
- * available for DHCP service, in response to a Solicit message received from a client.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6AdvertisePacket extends Dhcp6Packet {
-    /**
-     * Generates an advertise packet with the specified parameters.
-     */
-    Dhcp6AdvertisePacket(int transId, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid, final byte[] iapd) {
-        super(transId, 0 /* elapsedTime */, clientDuid, serverDuid, iapd);
-    }
-
-    /**
-     * Build a DHCPv6 Advertise message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_ADVERTISE << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
-        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6Client.java b/src/android/net/dhcp6/Dhcp6Client.java
index 99f75381..3278885c 100644
--- a/src/android/net/dhcp6/Dhcp6Client.java
+++ b/src/android/net/dhcp6/Dhcp6Client.java
@@ -16,14 +16,14 @@
 
 package android.net.dhcp6;
 
-import static android.net.dhcp6.Dhcp6Packet.IAID;
-import static android.net.dhcp6.Dhcp6Packet.PrefixDelegation;
 import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
 import static android.system.OsConstants.AF_INET6;
 import static android.system.OsConstants.IPPROTO_UDP;
 import static android.system.OsConstants.SOCK_DGRAM;
 import static android.system.OsConstants.SOCK_NONBLOCK;
 
+import static com.android.net.module.util.dhcp6.Dhcp6Packet.IAID;
+import static com.android.net.module.util.dhcp6.Dhcp6Packet.PrefixDelegation;
 import static com.android.net.module.util.NetworkStackConstants.ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
 import static com.android.net.module.util.NetworkStackConstants.DHCP6_CLIENT_PORT;
 import static com.android.net.module.util.NetworkStackConstants.DHCP6_SERVER_PORT;
@@ -50,6 +50,9 @@ import com.android.internal.util.WakeupMessage;
 import com.android.net.module.util.DeviceConfigUtils;
 import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.PacketReader;
+import com.android.net.module.util.dhcp6.Dhcp6AdvertisePacket;
+import com.android.net.module.util.dhcp6.Dhcp6Packet;
+import com.android.net.module.util.dhcp6.Dhcp6ReplyPacket;
 import com.android.net.module.util.structs.IaPrefixOption;
 
 import java.io.FileDescriptor;
@@ -82,6 +85,9 @@ public class Dhcp6Client extends StateMachine {
     // Notification from DHCPv6 state machine post DHCPv6 discovery/renewal. Indicates
     // success/failure
     public static final int CMD_DHCP6_RESULT = PUBLIC_BASE + 3;
+    // Commands from controller to force doing a DHCPv6 PD Rebind.
+    public static final int CMD_REBIND_DHCP6 = PUBLIC_BASE + 4;
+
     // Message.arg1 arguments to CMD_DHCP6_RESULT notification
     public static final int DHCP6_PD_SUCCESS = 1;
     public static final int DHCP6_PD_PREFIX_EXPIRED = 2;
@@ -278,9 +284,9 @@ public class Dhcp6Client extends StateMachine {
             // prefix, e.g. the list of prefix is empty). However, if prefix(es) do exist and all
             // prefixes are invalid, then we should just ignore this packet.
             if (!packet.isValid(mTransId, mClientDuid)) return;
-            if (!packet.mPrefixDelegation.ipos.isEmpty()) {
+            if (!packet.getPrefixDelegation().ipos.isEmpty()) {
                 boolean allInvalidPrefixes = true;
-                for (IaPrefixOption ipo : packet.mPrefixDelegation.ipos) {
+                for (IaPrefixOption ipo : packet.getPrefixDelegation().ipos) {
                     if (ipo != null && ipo.isValid()) {
                         allInvalidPrefixes = false;
                         break;
@@ -547,7 +553,7 @@ public class Dhcp6Client extends StateMachine {
 
         @Override
         protected void receivePacket(Dhcp6Packet packet) {
-            final PrefixDelegation pd = packet.mPrefixDelegation;
+            final PrefixDelegation pd = packet.getPrefixDelegation();
             // Ignore any Advertise or Reply for Solicit(with Rapid Commit) with NoPrefixAvail
             // status code, retransmit Solicit to see if any valid response from other Servers.
             if (pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
@@ -557,7 +563,7 @@ public class Dhcp6Client extends StateMachine {
             if (packet instanceof Dhcp6AdvertisePacket) {
                 Log.d(TAG, "Get prefix delegation option from Advertise: " + pd);
                 mAdvertise = pd;
-                mServerDuid = packet.mServerDuid;
+                mServerDuid = packet.getServerDuid();
                 mSolMaxRtMs = packet.getSolMaxRtMs().orElse(mSolMaxRtMs);
                 transitionTo(mRequestState);
             } else if (packet instanceof Dhcp6ReplyPacket) {
@@ -568,7 +574,7 @@ public class Dhcp6Client extends StateMachine {
                 }
                 Log.d(TAG, "Get prefix delegation option from RapidCommit Reply: " + pd);
                 mReply = pd;
-                mServerDuid = packet.mServerDuid;
+                mServerDuid = packet.getServerDuid();
                 mSolMaxRtMs = packet.getSolMaxRtMs().orElse(mSolMaxRtMs);
                 transitionTo(mBoundState);
             }
@@ -593,7 +599,7 @@ public class Dhcp6Client extends StateMachine {
         @Override
         protected void receivePacket(Dhcp6Packet packet) {
             if (!(packet instanceof Dhcp6ReplyPacket)) return;
-            final PrefixDelegation pd = packet.mPrefixDelegation;
+            final PrefixDelegation pd = packet.getPrefixDelegation();
             if (pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
                 Log.w(TAG, "Server responded to Request without available prefix, restart Solicit");
                 transitionTo(mSolicitState);
@@ -658,13 +664,15 @@ public class Dhcp6Client extends StateMachine {
                 case CMD_DHCP6_PD_RENEW:
                     transitionTo(mRenewState);
                     return HANDLED;
+                case CMD_REBIND_DHCP6:
+                    transitionTo(mRebindState);
+                    return HANDLED;
                 default:
                     return NOT_HANDLED;
             }
         }
     }
 
-
     /**
      *  Per RFC8415 section 18.2.10.1: Reply for renew or Rebind.
      * - If all binding IA_PDs were renewed/rebound(so far we only support one IA_PD option per
@@ -698,7 +706,7 @@ public class Dhcp6Client extends StateMachine {
         @Override
         protected void receivePacket(Dhcp6Packet packet) {
             if (!(packet instanceof Dhcp6ReplyPacket)) return;
-            final PrefixDelegation pd = packet.mPrefixDelegation;
+            final PrefixDelegation pd = packet.getPrefixDelegation();
             // Stay at Renew/Rebind state if the Reply message takes NoPrefixAvail status code,
             // retransmit Renew/Rebind message to server, to retry obtaining the prefixes.
             if (pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
@@ -710,7 +718,7 @@ public class Dhcp6Client extends StateMachine {
             Log.d(TAG, "Get prefix delegation option from Reply as response to Renew/Rebind " + pd);
             if (pd.ipos.isEmpty()) return;
             mReply = pd;
-            mServerDuid = packet.mServerDuid;
+            mServerDuid = packet.getServerDuid();
             // Once the delegated prefix gets refreshed successfully we have to extend the
             // preferred lifetime and valid lifetime of global IPv6 addresses, otherwise
             // these addresses will become depreacated finally and then provisioning failure
@@ -766,6 +774,13 @@ public class Dhcp6Client extends StateMachine {
             super(REB_TIMEOUT, REB_MAX_RT);
         }
 
+        @Override
+        public void enter() {
+            super.enter();
+            mRenewAlarm.cancel();
+            mRebindAlarm.cancel();
+        }
+
         @Override
         protected boolean sendPacket(int transId, long elapsedTimeMs) {
             final List<IaPrefixOption> toBeRebound = mReply.getRenewableIaPrefixes();
diff --git a/src/android/net/dhcp6/Dhcp6Packet.java b/src/android/net/dhcp6/Dhcp6Packet.java
deleted file mode 100644
index ff7b036d..00000000
--- a/src/android/net/dhcp6/Dhcp6Packet.java
+++ /dev/null
@@ -1,737 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_OPTION_LEN;
-
-import android.net.MacAddress;
-import android.util.Log;
-
-import androidx.annotation.NonNull;
-
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.internal.util.HexDump;
-import com.android.net.module.util.Struct;
-import com.android.net.module.util.structs.IaPdOption;
-import com.android.net.module.util.structs.IaPrefixOption;
-
-import java.nio.BufferUnderflowException;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
-import java.util.ArrayList;
-import java.util.Arrays;
-import java.util.List;
-import java.util.Objects;
-import java.util.OptionalInt;
-
-/**
- * Defines basic data and operations needed to build and use packets for the
- * DHCPv6 protocol. Subclasses create the specific packets used at each
- * stage of the negotiation.
- *
- * @hide
- */
-public class Dhcp6Packet {
-    private static final String TAG = Dhcp6Packet.class.getSimpleName();
-    /**
-     * DHCPv6 Message Type.
-     */
-    public static final byte DHCP6_MESSAGE_TYPE_SOLICIT = 1;
-    public static final byte DHCP6_MESSAGE_TYPE_ADVERTISE = 2;
-    public static final byte DHCP6_MESSAGE_TYPE_REQUEST = 3;
-    public static final byte DHCP6_MESSAGE_TYPE_CONFIRM = 4;
-    public static final byte DHCP6_MESSAGE_TYPE_RENEW = 5;
-    public static final byte DHCP6_MESSAGE_TYPE_REBIND = 6;
-    public static final byte DHCP6_MESSAGE_TYPE_REPLY = 7;
-    public static final byte DHCP6_MESSAGE_TYPE_RELEASE = 8;
-    public static final byte DHCP6_MESSAGE_TYPE_DECLINE = 9;
-    public static final byte DHCP6_MESSAGE_TYPE_RECONFIGURE = 10;
-    public static final byte DHCP6_MESSAGE_TYPE_INFORMATION_REQUEST = 11;
-    public static final byte DHCP6_MESSAGE_TYPE_RELAY_FORW = 12;
-    public static final byte DHCP6_MESSAGE_TYPE_RELAY_REPL = 13;
-
-    /**
-     * DHCPv6 Optional Type: Client Identifier.
-     * DHCPv6 message from client must have this option.
-     */
-    public static final byte DHCP6_CLIENT_IDENTIFIER = 1;
-    @NonNull
-    protected final byte[] mClientDuid;
-
-    /**
-     * DHCPv6 Optional Type: Server Identifier.
-     */
-    public static final byte DHCP6_SERVER_IDENTIFIER = 2;
-    protected final byte[] mServerDuid;
-
-    /**
-     * DHCPv6 Optional Type: Option Request Option.
-     */
-    public static final byte DHCP6_OPTION_REQUEST_OPTION = 6;
-
-    /**
-     * DHCPv6 Optional Type: Elapsed time.
-     * This time is expressed in hundredths of a second.
-     */
-    public static final byte DHCP6_ELAPSED_TIME = 8;
-    protected final int mElapsedTime;
-
-    /**
-     * DHCPv6 Optional Type: Status Code.
-     */
-    public static final byte DHCP6_STATUS_CODE = 13;
-    private static final byte MIN_STATUS_CODE_OPT_LEN = 6;
-    protected short mStatusCode;
-
-    public static final short STATUS_SUCCESS           = 0;
-    public static final short STATUS_UNSPEC_FAIL       = 1;
-    public static final short STATUS_NO_ADDRS_AVAIL    = 2;
-    public static final short STATUS_NO_BINDING        = 3;
-    public static final short STATUS_NOT_ONLINK        = 4;
-    public static final short STATUS_USE_MULTICAST     = 5;
-    public static final short STATUS_NO_PREFIX_AVAIL   = 6;
-
-    /**
-     * DHCPv6 zero-length Optional Type: Rapid Commit. Per RFC4039, both DHCPDISCOVER and DHCPACK
-     * packet may include this option.
-     */
-    public static final byte DHCP6_RAPID_COMMIT = 14;
-    public boolean mRapidCommit;
-
-    /**
-     * DHCPv6 Optional Type: IA_PD.
-     */
-    public static final byte DHCP6_IA_PD = 25;
-    @NonNull
-    protected final byte[] mIaPd;
-    @NonNull
-    protected PrefixDelegation mPrefixDelegation;
-
-    /**
-     * DHCPv6 Optional Type: IA Prefix Option.
-     */
-    public static final byte DHCP6_IAPREFIX = 26;
-
-    /**
-     * DHCPv6 Optional Type: SOL_MAX_RT.
-     */
-    public static final byte DHCP6_SOL_MAX_RT = 82;
-    private OptionalInt mSolMaxRt;
-
-    /**
-     * The transaction identifier used in this particular DHCPv6 negotiation
-     */
-    protected final int mTransId;
-
-    /**
-     * The unique identifier for IA_NA, IA_TA, IA_PD used in this particular DHCPv6 negotiation
-     */
-    protected int mIaId;
-    // Per rfc8415#section-12, the IAID MUST be consistent across restarts.
-    // Since currently only one IAID is supported, a well-known value can be used (0).
-    public static final int IAID = 0;
-
-    Dhcp6Packet(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
-            final byte[] serverDuid, @NonNull final byte[] iapd) {
-        mTransId = transId;
-        mElapsedTime = elapsedTime;
-        mClientDuid = clientDuid;
-        mServerDuid = serverDuid;
-        mIaPd = iapd;
-    }
-
-    /**
-     * Returns the transaction ID.
-     */
-    public int getTransactionId() {
-        return mTransId;
-    }
-
-    /**
-     * Returns decoded IA_PD options associated with IA_ID.
-     */
-    @VisibleForTesting
-    public PrefixDelegation getPrefixDelegation() {
-        return mPrefixDelegation;
-    }
-
-    /**
-     * Returns IA_ID associated to IA_PD.
-     */
-    public int getIaId() {
-        return mIaId;
-    }
-
-    /**
-     * Returns the client's DUID.
-     */
-    @NonNull
-    public byte[] getClientDuid() {
-        return mClientDuid;
-    }
-
-    /**
-     * Returns the server's DUID.
-     */
-    public byte[] getServerDuid() {
-        return mServerDuid;
-    }
-
-    /**
-     * Returns the SOL_MAX_RT option value in milliseconds.
-     */
-    public OptionalInt getSolMaxRtMs() {
-        return mSolMaxRt;
-    }
-
-    /**
-     * A class to take DHCPv6 IA_PD option allocated from server.
-     * https://www.rfc-editor.org/rfc/rfc8415.html#section-21.21
-     */
-    public static class PrefixDelegation {
-        public final int iaid;
-        public final int t1;
-        public final int t2;
-        @NonNull
-        public final List<IaPrefixOption> ipos;
-        public final short statusCode;
-
-        @VisibleForTesting
-        public PrefixDelegation(int iaid, int t1, int t2,
-                @NonNull final List<IaPrefixOption> ipos, short statusCode) {
-            Objects.requireNonNull(ipos);
-            this.iaid = iaid;
-            this.t1 = t1;
-            this.t2 = t2;
-            this.ipos = ipos;
-            this.statusCode = statusCode;
-        }
-
-        public PrefixDelegation(int iaid, int t1, int t2,
-                @NonNull final List<IaPrefixOption> ipos) {
-            this(iaid, t1, t2, ipos, STATUS_SUCCESS /* statusCode */);
-        }
-
-        /**
-         * Check whether or not the IA_PD option in DHCPv6 message is valid.
-         *
-         * TODO: ensure that the prefix has a reasonable lifetime, and the timers aren't too short.
-         */
-        public boolean isValid() {
-            if (iaid != IAID) {
-                Log.w(TAG, "IA_ID doesn't match, expected: " + IAID + ", actual: " + iaid);
-                return false;
-            }
-            if (t1 < 0 || t2 < 0) {
-                Log.e(TAG, "IA_PD option with invalid T1 " + t1 + " or T2 " + t2);
-                return false;
-            }
-            // Generally, t1 must be smaller or equal to t2 (except when t2 is 0).
-            if (t2 != 0 && t1 > t2) {
-                Log.e(TAG, "IA_PD option with T1 " + t1 + " greater than T2 " + t2);
-                return false;
-            }
-            return true;
-        }
-
-        /**
-         * Decode an IA_PD option from the byte buffer.
-         */
-        public static PrefixDelegation decode(@NonNull final ByteBuffer buffer)
-                throws ParseException {
-            try {
-                final int iaid = buffer.getInt();
-                final int t1 = buffer.getInt();
-                final int t2 = buffer.getInt();
-                final List<IaPrefixOption> ipos = new ArrayList<IaPrefixOption>();
-                short statusCode = STATUS_SUCCESS;
-                while (buffer.remaining() > 0) {
-                    final int original = buffer.position();
-                    final short optionType = buffer.getShort();
-                    final int optionLen = buffer.getShort() & 0xFFFF;
-                    switch (optionType) {
-                        case DHCP6_IAPREFIX:
-                            buffer.position(original);
-                            final IaPrefixOption ipo = Struct.parse(IaPrefixOption.class, buffer);
-                            Log.d(TAG, "IA Prefix Option: " + ipo);
-                            ipos.add(ipo);
-                            break;
-                        case DHCP6_STATUS_CODE:
-                            statusCode = buffer.getShort();
-                            // Skip the status message if any.
-                            if (optionLen > 2) {
-                                skipOption(buffer, optionLen - 2);
-                            }
-                            break;
-                        default:
-                            skipOption(buffer, optionLen);
-                    }
-                }
-                return new PrefixDelegation(iaid, t1, t2, ipos, statusCode);
-            } catch (BufferUnderflowException e) {
-                throw new ParseException(e.getMessage());
-            }
-        }
-
-        /**
-         * Build an IA_PD option from given specific parameters, including IA_PREFIX options.
-         */
-        public ByteBuffer build() {
-            return build(ipos);
-        }
-
-        /**
-         * Build an IA_PD option from given specific parameters, including IA_PREFIX options.
-         *
-         * Per RFC8415 section 21.13 if the Status Code option does not appear in a message in
-         * which the option could appear, the status of the message is assumed to be Success. So
-         * only put the Status Code option in IA_PD when the status code is not Success.
-         */
-        public ByteBuffer build(@NonNull final List<IaPrefixOption> input) {
-            final ByteBuffer iapd = ByteBuffer.allocate(IaPdOption.LENGTH
-                    + Struct.getSize(IaPrefixOption.class) * input.size()
-                    + (statusCode != STATUS_SUCCESS ? MIN_STATUS_CODE_OPT_LEN : 0));
-            iapd.putInt(iaid);
-            iapd.putInt(t1);
-            iapd.putInt(t2);
-            for (IaPrefixOption ipo : input) {
-                ipo.writeToByteBuffer(iapd);
-            }
-            if (statusCode != STATUS_SUCCESS) {
-                iapd.putShort(DHCP6_STATUS_CODE);
-                iapd.putShort((short) 2);
-                iapd.putShort(statusCode);
-            }
-            iapd.flip();
-            return iapd;
-        }
-
-        /**
-         * Return valid IA prefix options to be used and extended in the Reply message. It may
-         * return empty list if there isn't any valid IA prefix option in the Reply message.
-         *
-         * TODO: ensure that the prefix has a reasonable lifetime, and the timers aren't too short.
-         * and handle status code such as NoPrefixAvail.
-         */
-        public List<IaPrefixOption> getValidIaPrefixes() {
-            final List<IaPrefixOption> validIpos = new ArrayList<IaPrefixOption>();
-            for (IaPrefixOption ipo : ipos) {
-                if (!ipo.isValid()) continue;
-                validIpos.add(ipo);
-            }
-            return validIpos;
-        }
-
-        @Override
-        public String toString() {
-            return String.format("Prefix Delegation, iaid: %s, t1: %s, t2: %s, status code: %s,"
-                    + " IA prefix options: %s", iaid, t1, t2, statusCodeToString(statusCode), ipos);
-        }
-
-        /**
-         * Compare the preferred lifetime in the IA prefix optin list and return the minimum one.
-         */
-        public long getMinimalPreferredLifetime() {
-            long min = Long.MAX_VALUE;
-            for (IaPrefixOption ipo : ipos) {
-                min = (ipo.preferred != 0 && min > ipo.preferred) ? ipo.preferred : min;
-            }
-            return min;
-        }
-
-        /**
-         * Compare the valid lifetime in the IA prefix optin list and return the minimum one.
-         */
-        public long getMinimalValidLifetime() {
-            long min = Long.MAX_VALUE;
-            for (IaPrefixOption ipo : ipos) {
-                min = (ipo.valid != 0 && min > ipo.valid) ? ipo.valid : min;
-            }
-            return min;
-        }
-
-        /**
-         * Return IA prefix option list to be renewed/rebound.
-         *
-         * Per RFC8415#section-18.2.4, client must not include any prefixes that it didn't obtain
-         * from server or that are no longer valid (that have a valid lifetime of 0). Section-18.3.4
-         * also mentions that server can inform client that it will not extend the prefix by setting
-         * T1 and T2 to values equal to the valid lifetime, so in this case client has no point in
-         * renewing as well.
-         */
-        public List<IaPrefixOption> getRenewableIaPrefixes() {
-            final List<IaPrefixOption> toBeRenewed = getValidIaPrefixes();
-            toBeRenewed.removeIf(ipo -> ipo.preferred == 0 && ipo.valid == 0);
-            toBeRenewed.removeIf(ipo -> t1 == ipo.valid && t2 == ipo.valid);
-            return toBeRenewed;
-        }
-    }
-
-    /**
-     * DHCPv6 packet parsing exception.
-     */
-    public static class ParseException extends Exception {
-        ParseException(String msg) {
-            super(msg);
-        }
-    }
-
-    private static String statusCodeToString(short statusCode) {
-        switch (statusCode) {
-            case STATUS_SUCCESS:
-                return "Success";
-            case STATUS_UNSPEC_FAIL:
-                return "UnspecFail";
-            case STATUS_NO_ADDRS_AVAIL:
-                return "NoAddrsAvail";
-            case STATUS_NO_BINDING:
-                return "NoBinding";
-            case STATUS_NOT_ONLINK:
-                return "NotOnLink";
-            case STATUS_USE_MULTICAST:
-                return "UseMulticast";
-            case STATUS_NO_PREFIX_AVAIL:
-                return "NoPrefixAvail";
-            default:
-                return "Unknown";
-        }
-    }
-
-    private static void skipOption(@NonNull final ByteBuffer packet, int optionLen)
-            throws BufferUnderflowException {
-        for (int i = 0; i < optionLen; i++) {
-            packet.get();
-        }
-    }
-
-    /**
-     * Creates a concrete Dhcp6Packet from the supplied ByteBuffer.
-     *
-     * The buffer only starts with a UDP encapsulation (i.e. DHCPv6 message). A subset of the
-     * optional parameters are parsed and are stored in object fields. Client/Server message
-     * format:
-     *
-     *  0                   1                   2                   3
-     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     * |    msg-type   |               transaction-id                  |
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     * |                                                               |
-     * .                            options                            .
-     * .                 (variable number and length)                  .
-     * |                                                               |
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     */
-    private static Dhcp6Packet decode(@NonNull final ByteBuffer packet) throws ParseException {
-        int elapsedTime = 0;
-        byte[] iapd = null;
-        byte[] serverDuid = null;
-        byte[] clientDuid = null;
-        short statusCode = STATUS_SUCCESS;
-        boolean rapidCommit = false;
-        int solMaxRt = 0;
-        PrefixDelegation pd = null;
-
-        packet.order(ByteOrder.BIG_ENDIAN);
-
-        // DHCPv6 message contents.
-        final int msgTypeAndTransId = packet.getInt();
-        final byte messageType = (byte) (msgTypeAndTransId >> 24);
-        final int transId = msgTypeAndTransId & 0xffffff;
-
-        /**
-         * Parse DHCPv6 options, option format:
-         *
-         * 0                   1                   2                   3
-         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-         * |          option-code          |           option-len          |
-         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-         * |                          option-data                          |
-         * |                      (option-len octets)                      |
-         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-         */
-        while (packet.hasRemaining()) {
-            try {
-                final short optionType = packet.getShort();
-                final int optionLen = packet.getShort() & 0xFFFF;
-                int expectedLen = 0;
-
-                switch(optionType) {
-                    case DHCP6_SERVER_IDENTIFIER:
-                        expectedLen = optionLen;
-                        final byte[] sduid = new byte[expectedLen];
-                        packet.get(sduid, 0 /* offset */, expectedLen);
-                        serverDuid = sduid;
-                        break;
-                    case DHCP6_CLIENT_IDENTIFIER:
-                        expectedLen = optionLen;
-                        final byte[] cduid = new byte[expectedLen];
-                        packet.get(cduid, 0 /* offset */, expectedLen);
-                        clientDuid = cduid;
-                        break;
-                    case DHCP6_IA_PD:
-                        expectedLen = optionLen;
-                        final byte[] bytes = new byte[expectedLen];
-                        packet.get(bytes, 0 /* offset */, expectedLen);
-                        iapd = bytes;
-                        pd = PrefixDelegation.decode(ByteBuffer.wrap(iapd));
-                        break;
-                    case DHCP6_RAPID_COMMIT:
-                        expectedLen = 0;
-                        rapidCommit = true;
-                        break;
-                    case DHCP6_ELAPSED_TIME:
-                        expectedLen = 2;
-                        elapsedTime = (int) (packet.getShort() & 0xFFFF);
-                        break;
-                    case DHCP6_STATUS_CODE:
-                        expectedLen = optionLen;
-                        statusCode = packet.getShort();
-                        // Skip the status message (if any), which is a UTF-8 encoded text string
-                        // suitable for display to the end user, but is not useful for Dhcp6Client
-                        // to decide how to properly handle the status code.
-                        if (optionLen - 2 > 0) {
-                            skipOption(packet, optionLen - 2);
-                        }
-                        break;
-                    case DHCP6_SOL_MAX_RT:
-                        expectedLen = 4;
-                        solMaxRt = packet.getInt();
-                        break;
-                    default:
-                        expectedLen = optionLen;
-                        // BufferUnderflowException will be thrown if option is truncated.
-                        skipOption(packet, optionLen);
-                        break;
-                }
-                if (expectedLen != optionLen) {
-                    throw new ParseException(
-                            "Invalid length " + optionLen + " for option " + optionType
-                                    + ", expected " + expectedLen);
-                }
-            } catch (BufferUnderflowException e) {
-                throw new ParseException(e.getMessage());
-            }
-        }
-
-        Dhcp6Packet newPacket;
-
-        switch(messageType) {
-            case DHCP6_MESSAGE_TYPE_SOLICIT:
-                newPacket = new Dhcp6SolicitPacket(transId, elapsedTime, clientDuid, iapd,
-                        rapidCommit);
-                break;
-            case DHCP6_MESSAGE_TYPE_ADVERTISE:
-                newPacket = new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iapd);
-                break;
-            case DHCP6_MESSAGE_TYPE_REQUEST:
-                newPacket = new Dhcp6RequestPacket(transId, elapsedTime, clientDuid, serverDuid,
-                        iapd);
-                break;
-            case DHCP6_MESSAGE_TYPE_REPLY:
-                newPacket = new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iapd,
-                        rapidCommit);
-                break;
-            case DHCP6_MESSAGE_TYPE_RENEW:
-                newPacket = new Dhcp6RenewPacket(transId, elapsedTime, clientDuid, serverDuid,
-                        iapd);
-                break;
-            case DHCP6_MESSAGE_TYPE_REBIND:
-                newPacket = new Dhcp6RebindPacket(transId, elapsedTime, clientDuid, iapd);
-                break;
-            default:
-                throw new ParseException("Unimplemented DHCP6 message type %d" + messageType);
-        }
-
-        if (pd != null) {
-            newPacket.mPrefixDelegation = pd;
-            newPacket.mIaId = pd.iaid;
-        }
-        newPacket.mStatusCode = statusCode;
-        newPacket.mRapidCommit = rapidCommit;
-        newPacket.mSolMaxRt =
-                (solMaxRt >= 60 && solMaxRt <= 86400)
-                        ? OptionalInt.of(solMaxRt * 1000)
-                        : OptionalInt.empty();
-
-        return newPacket;
-    }
-
-    /**
-     * Parse a packet from an array of bytes, stopping at the given length.
-     */
-    public static Dhcp6Packet decode(@NonNull final byte[] packet, int length)
-            throws ParseException {
-        final ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);
-        return decode(buffer);
-    }
-
-    /**
-     * Follow RFC8415 section 18.2.9 and 18.2.10 to check if the received DHCPv6 message is valid.
-     */
-    public boolean isValid(int transId, @NonNull final byte[] clientDuid) {
-        if (mClientDuid == null) {
-            Log.e(TAG, "DHCPv6 message without Client DUID option");
-            return false;
-        }
-        if (!Arrays.equals(mClientDuid, clientDuid)) {
-            Log.e(TAG, "Unexpected client DUID " + HexDump.toHexString(mClientDuid)
-                    + ", expected " + HexDump.toHexString(clientDuid));
-            return false;
-        }
-        if (mTransId != transId) {
-            Log.e(TAG, "Unexpected transaction ID " + mTransId + ", expected " + transId);
-            return false;
-        }
-        if (mPrefixDelegation == null) {
-            Log.e(TAG, "DHCPv6 message without IA_PD option, ignoring");
-            return false;
-        }
-        if (!mPrefixDelegation.isValid()) {
-            Log.e(TAG, "DHCPv6 message takes invalid IA_PD option, ignoring");
-            return false;
-        }
-        //TODO: check if the status code is success or not.
-        return true;
-    }
-
-    /**
-     * Returns the client DUID, follows RFC 8415 and creates a client DUID
-     * based on the link-layer address(DUID-LL).
-     *
-     * TODO: use Struct to build and parse DUID.
-     *
-     * 0                   1                   2                   3
-     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     * |         DUID-Type (3)         |    hardware type (16 bits)    |
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     * .                                                               .
-     * .             link-layer address (variable length)              .
-     * .                                                               .
-     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-     */
-    public static byte[] createClientDuid(@NonNull final MacAddress macAddress) {
-        final byte[] duid = new byte[10];
-        // type: Link-layer address(3)
-        duid[0] = (byte) 0x00;
-        duid[1] = (byte) 0x03;
-        // hardware type: Ethernet(1)
-        duid[2] = (byte) 0x00;
-        duid[3] = (byte) 0x01;
-        System.arraycopy(macAddress.toByteArray() /* src */, 0 /* srcPos */, duid /* dest */,
-                4 /* destPos */, 6 /* length */);
-        return duid;
-    }
-
-    /**
-     * Adds an optional parameter containing an array of bytes.
-     */
-    protected static void addTlv(ByteBuffer buf, short type, @NonNull byte[] payload) {
-        if (payload.length > DHCP_MAX_OPTION_LEN) {
-            throw new IllegalArgumentException("DHCP option too long: "
-                    + payload.length + " vs. " + DHCP_MAX_OPTION_LEN);
-        }
-        buf.putShort(type);
-        buf.putShort((short) payload.length);
-        buf.put(payload);
-    }
-
-    /**
-     * Adds an optional parameter containing a short integer.
-     */
-    protected static void addTlv(ByteBuffer buf, short type, short value) {
-        buf.putShort(type);
-        buf.putShort((short) 2);
-        buf.putShort(value);
-    }
-
-    /**
-     * Adds an optional parameter containing zero-length value.
-     */
-    protected static void addTlv(ByteBuffer buf, short type) {
-        buf.putShort(type);
-        buf.putShort((short) 0);
-    }
-
-    /**
-     * Builds a DHCPv6 SOLICIT packet from the required specified parameters.
-     */
-    public static ByteBuffer buildSolicitPacket(int transId, long millisecs,
-            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid, boolean rapidCommit) {
-        final Dhcp6SolicitPacket pkt =
-                new Dhcp6SolicitPacket(transId, (int) (millisecs / 10) /* elapsed time */,
-                        clientDuid, iapd, rapidCommit);
-        return pkt.buildPacket();
-    }
-
-    /**
-     * Builds a DHCPv6 ADVERTISE packet from the required specified parameters.
-     */
-    public static ByteBuffer buildAdvertisePacket(int transId, @NonNull final byte[] iapd,
-            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid) {
-        final Dhcp6AdvertisePacket pkt =
-                new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iapd);
-        return pkt.buildPacket();
-    }
-
-    /**
-     * Builds a DHCPv6 REPLY packet from the required specified parameters.
-     */
-    public static ByteBuffer buildReplyPacket(int transId, @NonNull final byte[] iapd,
-            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid,
-            boolean rapidCommit) {
-        final Dhcp6ReplyPacket pkt =
-                new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iapd, rapidCommit);
-        return pkt.buildPacket();
-    }
-
-    /**
-     * Builds a DHCPv6 REQUEST packet from the required specified parameters.
-     */
-    public static ByteBuffer buildRequestPacket(int transId, long millisecs,
-            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid) {
-        final Dhcp6RequestPacket pkt =
-                new Dhcp6RequestPacket(transId, (int) (millisecs / 10) /* elapsed time */,
-                        clientDuid, serverDuid, iapd);
-        return pkt.buildPacket();
-    }
-
-    /**
-     * Builds a DHCPv6 RENEW packet from the required specified parameters.
-     */
-    public static ByteBuffer buildRenewPacket(int transId, long millisecs,
-            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid) {
-        final Dhcp6RenewPacket pkt =
-                new Dhcp6RenewPacket(transId, (int) (millisecs / 10) /* elapsed time */, clientDuid,
-                        serverDuid, iapd);
-        return pkt.buildPacket();
-    }
-
-    /**
-     * Builds a DHCPv6 REBIND packet from the required specified parameters.
-     */
-    public static ByteBuffer buildRebindPacket(int transId, long millisecs,
-            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid) {
-        final Dhcp6RebindPacket pkt = new Dhcp6RebindPacket(transId,
-                (int) (millisecs / 10) /* elapsed time */, clientDuid, iapd);
-        return pkt.buildPacket();
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6RebindPacket.java b/src/android/net/dhcp6/Dhcp6RebindPacket.java
deleted file mode 100644
index 87f2f45b..00000000
--- a/src/android/net/dhcp6/Dhcp6RebindPacket.java
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 REBIND packet class, a client sends a Rebind message to any available server to extend
- * the lifetimes on the leases assigned to the client and to update other configuration parameters.
- * This message is sent after a client receives no response to a Renew message.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6RebindPacket extends Dhcp6Packet {
-    /**
-     * Generates a rebind packet with the specified parameters.
-     */
-    Dhcp6RebindPacket(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] iapd) {
-        super(transId, elapsedTime, clientDuid, null /* serverDuid */, iapd);
-    }
-
-    /**
-     * Build a DHCPv6 Rebind message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_REBIND << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, getClientDuid());
-        addTlv(packet, DHCP6_ELAPSED_TIME, (short) (mElapsedTime & 0xFFFF));
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6RenewPacket.java b/src/android/net/dhcp6/Dhcp6RenewPacket.java
deleted file mode 100644
index 8c6686c7..00000000
--- a/src/android/net/dhcp6/Dhcp6RenewPacket.java
+++ /dev/null
@@ -1,57 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 RENEW packet class, a client sends an Renew message to the server that originally
- * provided the client's leases and configuration parameters to extend the lifetimes on the
- * leases assigned to the client and to update other configuration parameters.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6RenewPacket extends Dhcp6Packet {
-    /**
-     * Generates a renew packet with the specified parameters.
-     */
-    Dhcp6RenewPacket(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid, final byte[] iapd) {
-        super(transId, elapsedTime, clientDuid, serverDuid, iapd);
-    }
-
-    /**
-     * Build a DHCPv6 Renew message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_RENEW << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
-        addTlv(packet, DHCP6_ELAPSED_TIME, (short) (mElapsedTime & 0xFFFF));
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6ReplyPacket.java b/src/android/net/dhcp6/Dhcp6ReplyPacket.java
deleted file mode 100644
index d68fbdb7..00000000
--- a/src/android/net/dhcp6/Dhcp6ReplyPacket.java
+++ /dev/null
@@ -1,60 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 REPLY packet class, a server sends an Reply message containing assigned leases
- * and configuration parameters in response to a Solicit, Request, Renew or Rebind messages
- * received from a client.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6ReplyPacket extends Dhcp6Packet {
-    /**
-     * Generates a reply packet with the specified parameters.
-     */
-    Dhcp6ReplyPacket(int transId, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid, final byte[] iapd, boolean rapidCommit) {
-        super(transId, 0 /* elapsedTime */, clientDuid, serverDuid, iapd);
-        mRapidCommit = rapidCommit;
-    }
-
-    /**
-     * Build a DHCPv6 Reply message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_REPLY << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
-        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-        if (mRapidCommit) {
-            addTlv(packet, DHCP6_RAPID_COMMIT);
-        }
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6RequestPacket.java b/src/android/net/dhcp6/Dhcp6RequestPacket.java
deleted file mode 100644
index 6d4dfdf1..00000000
--- a/src/android/net/dhcp6/Dhcp6RequestPacket.java
+++ /dev/null
@@ -1,57 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 REQUEST packet class, a client sends a Request message to request configuration
- * parameters, including addresses and/or delegated prefixes from a specific server.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6RequestPacket extends Dhcp6Packet {
-    /**
-     * Generates a request packet with the specified parameters.
-     */
-    Dhcp6RequestPacket(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
-            @NonNull final byte[] serverDuid, final byte[] iapd) {
-        super(transId, elapsedTime, clientDuid, serverDuid, iapd);
-    }
-
-    /**
-     * Build a DHCPv6 Request message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_REQUEST << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
-        addTlv(packet, DHCP6_ELAPSED_TIME, (short) (mElapsedTime & 0xFFFF));
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-        addTlv(packet, DHCP6_OPTION_REQUEST_OPTION, DHCP6_SOL_MAX_RT);
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/dhcp6/Dhcp6SolicitPacket.java b/src/android/net/dhcp6/Dhcp6SolicitPacket.java
deleted file mode 100644
index 5cf5d013..00000000
--- a/src/android/net/dhcp6/Dhcp6SolicitPacket.java
+++ /dev/null
@@ -1,59 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.dhcp6;
-
-import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
-
-import androidx.annotation.NonNull;
-
-import java.nio.ByteBuffer;
-
-/**
- * DHCPv6 SOLICIT packet class, a client sends a Solicit message to locate DHCPv6 servers.
- *
- * https://tools.ietf.org/html/rfc8415#page-24
- */
-public class Dhcp6SolicitPacket extends Dhcp6Packet {
-    /**
-     * Generates a solicit packet with the specified parameters.
-     */
-    Dhcp6SolicitPacket(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
-            final byte[] iapd, boolean rapidCommit) {
-        super(transId, elapsedTime, clientDuid, null /* serverDuid */, iapd);
-        mRapidCommit = rapidCommit;
-    }
-
-    /**
-     * Build a DHCPv6 Solicit message with the specific parameters.
-     */
-    public ByteBuffer buildPacket() {
-        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
-        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_SOLICIT << 24) | mTransId;
-        packet.putInt(msgTypeAndTransId);
-
-        addTlv(packet, DHCP6_ELAPSED_TIME, (short) (mElapsedTime & 0xFFFF));
-        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
-        addTlv(packet, DHCP6_IA_PD, mIaPd);
-        addTlv(packet, DHCP6_OPTION_REQUEST_OPTION, DHCP6_SOL_MAX_RT);
-        if (mRapidCommit) {
-            addTlv(packet, DHCP6_RAPID_COMMIT);
-        }
-
-        packet.flip();
-        return packet;
-    }
-}
diff --git a/src/android/net/ip/ConnectivityPacketTracker.java b/src/android/net/ip/ConnectivityPacketTracker.java
index 35a71c7c..b0cd3937 100644
--- a/src/android/net/ip/ConnectivityPacketTracker.java
+++ b/src/android/net/ip/ConnectivityPacketTracker.java
@@ -94,6 +94,8 @@ public class ConnectivityPacketTracker {
             FileDescriptor socket = null;
             try {
                 socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
+                // for production code, 'attachFilter' must always be `true`.
+                // setting it to `false` is exclusively for testing purpose.
                 if (attachFilter) {
                     NetworkStackUtils.attachControlPacketFilter(socket);
                 }
diff --git a/src/android/net/ip/IpClient.java b/src/android/net/ip/IpClient.java
index 7631a1c2..2438b486 100644
--- a/src/android/net/ip/IpClient.java
+++ b/src/android/net/ip/IpClient.java
@@ -33,6 +33,9 @@ import static android.net.ip.IpClient.IpClientCommands.CMD_ADDRESSES_CLEARED;
 import static android.net.ip.IpClient.IpClientCommands.CMD_ADD_KEEPALIVE_PACKET_FILTER_TO_APF;
 import static android.net.ip.IpClient.IpClientCommands.CMD_COMPLETE_PRECONNECTION;
 import static android.net.ip.IpClient.IpClientCommands.CMD_CONFIRM;
+import static android.net.ip.IpClient.IpClientCommands.CMD_DHCP6_PD_REBIND;
+import static android.net.ip.IpClient.IpClientCommands.CMD_DHCP6_PD_START;
+import static android.net.ip.IpClient.IpClientCommands.CMD_DHCP6_PD_STOP;
 import static android.net.ip.IpClient.IpClientCommands.CMD_JUMP_RUNNING_TO_STOPPING;
 import static android.net.ip.IpClient.IpClientCommands.CMD_JUMP_STOPPING_TO_STOPPED;
 import static android.net.ip.IpClient.IpClientCommands.CMD_REMOVE_KEEPALIVE_PACKET_FILTER_FROM_APF;
@@ -52,19 +55,18 @@ import static android.net.ip.IpClient.IpClientCommands.EVENT_NETLINK_LINKPROPERT
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_FAILURE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_SUCCESS;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_TIMEOUT;
-import static android.net.ip.IpClient.IpClientCommands.EVENT_PIO_PREFIX_UPDATE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_PRE_DHCP_ACTION_COMPLETE;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_PROVISIONING_TIMEOUT;
 import static android.net.ip.IpClient.IpClientCommands.EVENT_READ_PACKET_FILTER_COMPLETE;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor.INetlinkMessageProcessor;
-import static android.net.ip.IpClientLinkObserver.PrefixInfo;
 import static android.net.ip.IpReachabilityMonitor.INVALID_REACHABILITY_LOSS_TYPE;
 import static android.net.ip.IpReachabilityMonitor.nudEventTypeToInt;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
 import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
 import static android.stats.connectivity.NetworkQuirkEvent.QE_DHCP6_HEURISTIC_TRIGGERED;
 import static android.stats.connectivity.NetworkQuirkEvent.QE_DHCP6_PD_PROVISIONED;
+import static android.stats.connectivity.NetworkQuirkEvent.QE_DHCP6_PFLAG_TRIGGERED;
 import static android.system.OsConstants.AF_PACKET;
 import static android.system.OsConstants.ARPHRD_ETHER;
 import static android.system.OsConstants.ETH_P_ARP;
@@ -86,6 +88,7 @@ import static com.android.networkstack.util.NetworkStackUtils.APF_ENABLE;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ARP_OFFLOAD;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_IGMP_OFFLOAD;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_IGMP_OFFLOAD_VERSION;
+import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_MDNS_ADVERTISING_OFFLOAD_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_MLD_OFFLOAD;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_MLD_OFFLOAD_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ND_OFFLOAD;
@@ -100,7 +103,6 @@ import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_POPULATE_
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_REPLACE_NETD_WITH_NETLINK_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.createInet6AddressFromEui64;
-import static com.android.networkstack.util.NetworkStackUtils.isAtLeast25Q2;
 import static com.android.networkstack.util.NetworkStackUtils.macAddressToEui64;
 import static com.android.server.util.PermissionUtil.enforceNetworkStackCallingPermission;
 
@@ -127,6 +129,7 @@ import android.net.RouteInfo;
 import android.net.TcpKeepalivePacketDataParcelable;
 import android.net.Uri;
 import android.net.apf.ApfCapabilities;
+import android.net.apf.ApfCounterTracker;
 import android.net.apf.ApfFilter;
 import android.net.dhcp.DhcpClient;
 import android.net.dhcp.DhcpPacket;
@@ -154,12 +157,14 @@ import android.os.UserHandle;
 import android.stats.connectivity.DisconnectCode;
 import android.stats.connectivity.NetworkQuirkEvent;
 import android.stats.connectivity.NudEventType;
+import android.stats.connectivity.TransportType;
 import android.system.ErrnoException;
 import android.system.Os;
 import android.text.TextUtils;
 import android.text.format.DateUtils;
 import android.util.LocalLog;
 import android.util.Log;
+import android.util.Pair;
 import android.util.SparseArray;
 
 import androidx.annotation.NonNull;
@@ -593,6 +598,8 @@ public class IpClient extends StateMachine {
     @VisibleForTesting
     static final String ACCEPT_RA_MIN_LFT = "accept_ra_min_lft";
     private static final String DAD_TRANSMITS = "dad_transmits";
+    @VisibleForTesting
+    public static final String RA_HONOR_PIO_PFLAG = "ra_honor_pio_pflag";
 
     /**
      * The IpClientCommands constant values.
@@ -628,7 +635,9 @@ public class IpClient extends StateMachine {
         static final int EVENT_NUD_FAILURE_QUERY_TIMEOUT = 21;
         static final int EVENT_NUD_FAILURE_QUERY_SUCCESS = 22;
         static final int EVENT_NUD_FAILURE_QUERY_FAILURE = 23;
-        static final int EVENT_PIO_PREFIX_UPDATE = 24;
+        static final int CMD_DHCP6_PD_START = 24;
+        static final int CMD_DHCP6_PD_STOP = 25;
+        static final int CMD_DHCP6_PD_REBIND = 26;
         // Internal commands to use instead of trying to call transitionTo() inside
         // a given State's enter() method. Calling transitionTo() from enter/exit
         // encounters a Log.wtf() that can cause trouble on eng builds.
@@ -637,6 +646,28 @@ public class IpClient extends StateMachine {
         static final int CMD_JUMP_STOPPING_TO_STOPPED = 102;
     }
 
+    /**
+     * The ApfShellCommands constant values.
+     *
+     * @hide
+     */
+    public static class ApfShellCommands {
+        private ApfShellCommands() {
+        }
+
+        static final String CMD_READ_APF_DATA = "read";
+        static final String CMD_GET_APF_FILTER_STATUS = "status";
+        static final String CMD_PAUSE_APF_FILTER = "pause";
+        static final String CMD_RESUME_APF_FILTER = "resume";
+        static final String CMD_INSTALL_APF_PROGRAM = "install";
+        static final String CMD_GET_APF_CAPABILITIES = "capabilities";
+        static final String CMD_DUMP_APF_COUNTERS = "dump-counters";
+
+        static boolean shouldUpdateDataSnapshot(final String cmd) {
+            return cmd.equals(CMD_READ_APF_DATA) || cmd.equals(CMD_DUMP_APF_COUNTERS);
+        }
+    }
+
     private static final int ARG_LINKPROP_CHANGED_LINKSTATE_DOWN = 0;
     private static final int ARG_LINKPROP_CHANGED_LINKSTATE_UP = 1;
 
@@ -837,6 +868,7 @@ public class IpClient extends StateMachine {
     private final boolean mIgnoreNudFailureEnabled;
     private final boolean mDhcp6PdPreferredFlagEnabled;
     private final boolean mReplaceNetdWithNetlinkEnabled;
+    private final boolean mIsTvDevice;
 
     private InterfaceParams mInterfaceParams;
 
@@ -1109,26 +1141,28 @@ public class IpClient extends StateMachine {
         mApfHandleNdOffload = mDependencies.isFeatureNotChickenedOut(
                 mContext, APF_HANDLE_ND_OFFLOAD);
         // TODO: turn on APF mDNS offload on handhelds.
-        mApfHandleMdnsOffload = isAtLeast25Q2() && context.getPackageManager().hasSystemFeature(
-                FEATURE_LEANBACK);
+        mIsTvDevice = context.getPackageManager().hasSystemFeature(FEATURE_LEANBACK);
+        mApfHandleMdnsOffload =
+                SdkLevel.isAtLeastB() && (mIsTvDevice || mDependencies.isFeatureEnabled(context,
+                        APF_HANDLE_MDNS_ADVERTISING_OFFLOAD_VERSION));
         mApfHandleIgmpOffload =
                 mDependencies.isFeatureNotChickenedOut(mContext, APF_HANDLE_IGMP_OFFLOAD)
-                    && (isAtLeast25Q2()
+                    && (SdkLevel.isAtLeastB()
                         || mDependencies.isFeatureEnabled(context, APF_HANDLE_IGMP_OFFLOAD_VERSION)
                     );
         mApfHandleMldOffload =
                 mDependencies.isFeatureNotChickenedOut(mContext, APF_HANDLE_MLD_OFFLOAD)
-                    && (isAtLeast25Q2()
+                    && (SdkLevel.isAtLeastB()
                         || mDependencies.isFeatureEnabled(context, APF_HANDLE_MLD_OFFLOAD_VERSION)
                     );
         mApfHandleIpv4PingOffload =
                 mDependencies.isFeatureNotChickenedOut(mContext, APF_HANDLE_PING4_OFFLOAD)
-                    && (isAtLeast25Q2()
+                    && (SdkLevel.isAtLeastB()
                         || mDependencies.isFeatureEnabled(context, APF_HANDLE_PING4_OFFLOAD_VERSION)
                     );
         mApfHandleIpv6PingOffload =
                 mDependencies.isFeatureNotChickenedOut(mContext, APF_HANDLE_PING6_OFFLOAD)
-                    && (isAtLeast25Q2()
+                    && (SdkLevel.isAtLeastB()
                         || mDependencies.isFeatureEnabled(context, APF_HANDLE_PING6_OFFLOAD_VERSION)
                 );
         mPopulateLinkAddressLifetime = mDependencies.isFeatureEnabled(context,
@@ -1141,8 +1175,8 @@ public class IpClient extends StateMachine {
         mNudFailureCountWeeklyThreshold = mDependencies.getDeviceConfigPropertyInt(
                 CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD,
                 DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD);
-        mDhcp6PdPreferredFlagEnabled =
-                mDependencies.isFeatureEnabled(mContext, IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION);
+        mDhcp6PdPreferredFlagEnabled = mDependencies.isFeatureNotChickenedOut(mContext,
+                    IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION);
         mReplaceNetdWithNetlinkEnabled = mDependencies.isFeatureEnabled(mContext,
                 IPCLIENT_REPLACE_NETD_WITH_NETLINK_VERSION);
         IpClientLinkObserver.Configuration config = new IpClientLinkObserver.Configuration(
@@ -1195,9 +1229,18 @@ public class IpClient extends StateMachine {
                     }
 
                     @Override
-                    public void onNewPrefix(PrefixInfo info) {
-                        if (!mDhcp6PdPreferredFlagEnabled) return;
-                        sendMessage(EVENT_PIO_PREFIX_UPDATE, info);
+                    public void startDhcp6() {
+                        sendMessage(CMD_DHCP6_PD_START);
+                    }
+
+                    @Override
+                    public void stopDhcp6() {
+                        sendMessage(CMD_DHCP6_PD_STOP);
+                    }
+
+                    @Override
+                    public void rebindDhcp6() {
+                        sendMessage(CMD_DHCP6_PD_REBIND);
                     }
                 },
                 config, mLog, mDependencies
@@ -1618,7 +1661,7 @@ public class IpClient extends StateMachine {
 
         // Waiting for a "read" result cannot block the handler thread, since the result gets
         // processed on it. This is test only code, so mApfFilter going away is not a concern.
-        if (cmd.equals("read")) {
+        if (ApfShellCommands.shouldUpdateDataSnapshot(cmd)) {
             if (mApfFilter == null) {
                 throw new IllegalStateException("Error: No active APF filter");
             }
@@ -1639,18 +1682,18 @@ public class IpClient extends StateMachine {
                     throw new IllegalStateException("No active APF filter.");
                 }
                 switch (cmd) {
-                    case "status":
+                    case ApfShellCommands.CMD_GET_APF_FILTER_STATUS:
                         result.complete(mApfFilter.isRunning() ? "running" : "paused");
                         break;
-                    case "pause":
+                    case ApfShellCommands.CMD_PAUSE_APF_FILTER:
                         mApfFilter.pause();
                         result.complete("success");
                         break;
-                    case "resume":
+                    case ApfShellCommands.CMD_RESUME_APF_FILTER:
                         mApfFilter.resume();
                         result.complete("success");
                         break;
-                    case "install":
+                    case ApfShellCommands.CMD_INSTALL_APF_PROGRAM:
                         Objects.requireNonNull(optarg, "No program provided");
                         if (mApfFilter.isRunning()) {
                             throw new IllegalStateException("APF filter must first be paused");
@@ -1659,18 +1702,35 @@ public class IpClient extends StateMachine {
                                 HexDump.hexStringToByteArray(optarg), "program from shell command");
                         result.complete("success");
                         break;
-                    case "capabilities":
+                    case ApfShellCommands.CMD_GET_APF_CAPABILITIES:
                         final StringJoiner joiner = new StringJoiner(",");
                         joiner.add(Integer.toString(mCurrentApfCapabilities.apfVersionSupported));
                         joiner.add(Integer.toString(mCurrentApfCapabilities.maximumApfProgramSize));
                         joiner.add(Integer.toString(mCurrentApfCapabilities.apfPacketFormat));
                         result.complete(joiner.toString());
                         break;
-                    case "read":
+                    case ApfShellCommands.CMD_READ_APF_DATA:
                         final String snapshot = mApfFilter.getDataSnapshotHexString();
                         Objects.requireNonNull(snapshot, "No data snapshot recorded.");
                         result.complete(snapshot);
                         break;
+                    case ApfShellCommands.CMD_DUMP_APF_COUNTERS:
+                        final List<Pair<ApfCounterTracker.Counter, String>> counters =
+                                mApfFilter.dumpCounters();
+                        if (counters == null || counters.isEmpty()) {
+                            result.complete("No counter available.");
+                            break;
+                        }
+
+                        final StringBuilder sb = new StringBuilder();
+                        for (Pair<ApfCounterTracker.Counter, String> entry: counters) {
+                            sb.append(entry.first.name())
+                                    .append(": ")
+                                    .append(entry.second)
+                                    .append("\n");
+                        }
+                        result.complete(sb.toString());
+                        break;
                     default:
                         throw new IllegalArgumentException("Invalid apf command: " + cmd);
                 }
@@ -2343,8 +2403,7 @@ public class IpClient extends StateMachine {
         // doesn't complete with success after timeout. This check also handles IPv6-only link
         // local mode case, since there will be no IPv6 default route in that mode even with Prefix
         // Delegation experiment flag enabled.
-        if (newLp.hasIpv6DefaultRoute()
-                && mIpv6AutoconfTimeoutAlarm == null) {
+        if (newLp.hasIpv6DefaultRoute() && mIpv6AutoconfTimeoutAlarm == null) {
             mIpv6AutoconfTimeoutAlarm = new WakeupMessage(mContext, getHandler(),
                     mTag + ".EVENT_IPV6_AUTOCONF_TIMEOUT", EVENT_IPV6_AUTOCONF_TIMEOUT);
             final long alarmTime = SystemClock.elapsedRealtime()
@@ -2553,18 +2612,25 @@ public class IpClient extends StateMachine {
                 setIpv6Sysctl(DAD_TRANSMITS, 0 /* dad_transmits */);
             }
         }
+        if (mDhcp6PdPreferredFlagEnabled
+                && mDependencies.hasIpv6Sysctl(mInterfaceName, RA_HONOR_PIO_PFLAG)) {
+            // If "accept_ra" sysctl is 0 (e.g. in IPv6 link-local provisioning mode),
+            // kernel only processes the SLLA option (see ndisc_router_discovery in ndisc.c
+            // for details), but not PIO. So always enable the "ra_honor_pio_flag" sysctl
+            // regardless of the provisioning mode.
+            setIpv6Sysctl(RA_HONOR_PIO_PFLAG, 1);
+        }
         return mInterfaceCtrl.setIPv6PrivacyExtensions(true)
                 && mInterfaceCtrl.setIPv6AddrGenModeIfSupported(mConfiguration.mIPv6AddrGenMode)
                 && mInterfaceCtrl.enableIPv6();
     }
 
+    /** Creates Dhcp6Client and starts DHCPv6-PD. It is safe to call this function multiple times */
     private void startDhcp6PrefixDelegation() {
-        if (mDhcp6Client != null) {
-            Log.wtf(mTag, "Dhcp6Client should never be non-null in startDhcp6PrefixDelegation");
-            return;
+        if (mDhcp6Client == null) {
+            mDhcp6Client = mDependencies.makeDhcp6Client(mContext, IpClient.this,
+                    mInterfaceParams, mDependencies.getDhcp6ClientDependencies());
         }
-        mDhcp6Client = mDependencies.makeDhcp6Client(mContext, IpClient.this, mInterfaceParams,
-                mDependencies.getDhcp6ClientDependencies());
         mDhcp6Client.sendMessage(Dhcp6Client.CMD_START_DHCP6);
     }
 
@@ -2685,6 +2751,10 @@ public class IpClient extends StateMachine {
                 && mDependencies.hasIpv6Sysctl(mInterfaceName, ACCEPT_RA_MIN_LFT)) {
             setIpv6Sysctl(ACCEPT_RA_MIN_LFT, 0 /* sysctl default */);
         }
+        if (mDhcp6PdPreferredFlagEnabled
+                && mDependencies.hasIpv6Sysctl(mInterfaceName, RA_HONOR_PIO_PFLAG)) {
+            setIpv6Sysctl(RA_HONOR_PIO_PFLAG, 0 /* sysctl default */);
+        }
     }
 
     private void maybeSaveNetworkToIpMemoryStore() {
@@ -2710,7 +2780,8 @@ public class IpClient extends StateMachine {
         if (params.defaultMtu == mInterfaceParams.defaultMtu) return;
 
         if (mReplaceNetdWithNetlinkEnabled) {
-            if (!NetlinkUtils.setInterfaceMtu(mInterfaceName, mInterfaceParams.defaultMtu)) {
+            if (!NetlinkUtils.setInterfaceMtu(mInterfaceParams.index,
+                    mInterfaceParams.defaultMtu)) {
                 logError("Couldn't reset MTU on " + mInterfaceName + " from "
                         + params.defaultMtu + " to " + mInterfaceParams.defaultMtu);
             }
@@ -2779,7 +2850,7 @@ public class IpClient extends StateMachine {
     @Nullable
     private ApfFilter maybeCreateApfFilter(final ApfCapabilities apfCaps) {
         ApfFilter.ApfConfiguration apfConfig = new ApfFilter.ApfConfiguration();
-        if (apfCaps == null || !mEnableApf) {
+        if (!isApfSupported(apfCaps) || !mEnableApf) {
             return null;
         }
         // For now only support generating programs for Ethernet frames. If this restriction is
@@ -2833,6 +2904,14 @@ public class IpClient extends StateMachine {
         apfConfig.handleArpOffload = mApfHandleArpOffload;
         apfConfig.handleNdOffload = mApfHandleNdOffload;
         apfConfig.handleMdnsOffload = mApfHandleMdnsOffload;
+        // In Android 16 for Android TV, the mDNS offload fail-open mechanism is not functional
+        // due to the need to coexist with Wake on LAN filters. Specifically, during CPU
+        // suspend, APF is used for offload, and the Wake on LAN filter exclusively decides if a
+        // packet wakes the CPU. This means mDNS packets will be dropped by the Wake on LAN
+        // filter even if APF intends to pass them. Therefore, mDNS records will either be fully
+        // offloaded or dropped. To ensure high-priority mDNS records are offloaded and to
+        // manage RAM usage, we skip offloading records without proper priority settings.
+        apfConfig.skipMdnsRecordWithoutPriority = mIsTvDevice;
         apfConfig.handleIgmpOffload = mApfHandleIgmpOffload;
         // TODO: Turn on MLD offload on devices with 2048 ~ 2999 bytes of APF RAM.
         apfConfig.handleMldOffload = mApfHandleMldOffload && apfConfig.apfRamSize >= 3000;
@@ -2841,19 +2920,28 @@ public class IpClient extends StateMachine {
         apfConfig.handleIpv6PingOffload = mApfHandleIpv6PingOffload && apfConfig.apfRamSize >= 3000;
         apfConfig.minMetricsSessionDurationMs = mApfCounterPollingIntervalMs;
         apfConfig.hasClatInterface = mHasSeenClatInterface;
+        // Report APF version and RAM size upon creation. only reporting the metrics when
+        // IpClient stops is problematic for devices like TVs that remain connected to Wi-Fi all
+        // days.
+        NetworkStackStatsLog.write(NetworkStackStatsLog.APF_SESSION_INFO_REPORTED,
+                apfConfig.apfVersionSupported, apfConfig.apfRamSize);
         return mDependencies.maybeCreateApfFilter(getHandler(), mContext, apfConfig,
                 mInterfaceParams, mIpClientApfController, mNetworkQuirkMetrics);
     }
 
+    private boolean isApfSupported(ApfCapabilities apfCapabilities) {
+        return apfCapabilities != null && apfCapabilities.apfVersionSupported >= 2;
+    }
+
     private boolean handleUpdateApfCapabilities(@NonNull final ApfCapabilities apfCapabilities) {
         // For the use case where the wifi interface switches from secondary to primary, the
         // secondary interface does not support APF by default see the overlay config about
         // {@link config_wifiEnableApfOnNonPrimarySta}. so we should see empty ApfCapabilities
         // in {@link ProvisioningConfiguration} when wifi starts provisioning on the secondary
         // interface. For other cases, we should not accept the updateApfCapabilities call.
-        if (mCurrentApfCapabilities != null || apfCapabilities == null) {
-            Log.wtf(mTag, "current ApfCapabilities " + mCurrentApfCapabilities
-                    + " is not null or new ApfCapabilities " + apfCapabilities + " is null");
+        if (isApfSupported(mCurrentApfCapabilities) || !isApfSupported(apfCapabilities)) {
+            Log.wtf(mTag, "Invalid update: current ApfCapabilities: " + mCurrentApfCapabilities
+                    + " new ApfCapabilities: " + apfCapabilities);
             return false;
         }
         if (mApfFilter != null) {
@@ -3243,10 +3331,21 @@ public class IpClient extends StateMachine {
         }
     }
 
+    private static TransportType guessTransportType(@NonNull String interfaceName) {
+        if (interfaceName.startsWith("wlan")) {
+            return TransportType.TT_WIFI;
+        }
+        if (interfaceName.startsWith("usb") || interfaceName.startsWith("eth")) {
+            return TransportType.TT_ETHERNET;
+        }
+        return TransportType.TT_UNKNOWN;
+    }
+
     class StartedState extends State {
         @Override
         public void enter() {
             mIpProvisioningMetrics.reset();
+            mIpProvisioningMetrics.setTransportType(guessTransportType(mInterfaceName));
             mStartTimeMillis = SystemClock.elapsedRealtime();
 
             if (mConfiguration.mProvisioningTimeoutMs > 0) {
@@ -3831,6 +3930,29 @@ public class IpClient extends StateMachine {
                     }
                     break;
 
+                case CMD_DHCP6_PD_START:
+                    // Cancelling autoconf timeout alarm on best effort basis. Dhcp6Client handles
+                    // multiple START commands correctly (i.e. only the first START has any effect).
+                    // It is of course also possible that the autoconf timer has already fired
+                    // when the first P-flag arrives.
+                    if (mIpv6AutoconfTimeoutAlarm != null) mIpv6AutoconfTimeoutAlarm.cancel();
+
+                    // Note that this event may be logged multiple times, for example, when a
+                    // P-flag prefix expires and a new one is received. QE_DHCP6_PFLAG_TRIGGERED
+                    // and QE_DHCP6_PD_PROVISIONED are not mutually exclusive.
+                    mNetworkQuirkMetrics.setEvent(QE_DHCP6_PFLAG_TRIGGERED);
+                    mNetworkQuirkMetrics.statsWrite();
+                    startDhcp6PrefixDelegation();
+                    break;
+
+                case CMD_DHCP6_PD_STOP:
+                    mDhcp6Client.sendMessage(Dhcp6Client.CMD_STOP_DHCP6);
+                    break;
+
+                case CMD_DHCP6_PD_REBIND:
+                    mDhcp6Client.sendMessage(Dhcp6Client.CMD_REBIND_DHCP6);
+                    break;
+
                 case Dhcp6Client.CMD_DHCP6_RESULT:
                     switch(msg.arg1) {
                         case Dhcp6Client.DHCP6_PD_SUCCESS:
diff --git a/src/android/net/ip/IpClientLinkObserver.java b/src/android/net/ip/IpClientLinkObserver.java
index 516ab017..d7e75273 100644
--- a/src/android/net/ip/IpClientLinkObserver.java
+++ b/src/android/net/ip/IpClientLinkObserver.java
@@ -23,6 +23,7 @@ import static android.system.OsConstants.IFF_LOOPBACK;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_PIO;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
 import static com.android.net.module.util.NetworkStackConstants.INFINITE_LEASE;
+import static com.android.net.module.util.NetworkStackConstants.PIO_FLAG_DHCPV6_PD_PREFERRED;
 import static com.android.net.module.util.netlink.NetlinkConstants.IFF_LOWER_UP;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_F_CLONED;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTN_UNICAST;
@@ -40,6 +41,7 @@ import android.net.RouteInfo;
 import android.os.Handler;
 import android.os.SystemClock;
 import android.system.OsConstants;
+import android.util.ArrayMap;
 import android.util.Log;
 
 import androidx.annotation.NonNull;
@@ -74,6 +76,7 @@ import java.util.Arrays;
 import java.util.Collections;
 import java.util.HashMap;
 import java.util.HashSet;
+import java.util.Map;
 import java.util.Set;
 import java.util.concurrent.TimeUnit;
 
@@ -136,11 +139,23 @@ public class IpClientLinkObserver {
         void onClatInterfaceStateUpdate(boolean add);
 
         /**
-         * Called when the prefix information was updated via RTM_NEWPREFIX netlink message.
-         *
-         * @param info prefix information.
+         * Start requesting a prefix via DHCPv6-PD when the length of the prefix list
+         * with DHCPv6 preferred flag increases to one.
+         */
+        void startDhcp6();
+
+        /**
+         * Stop requesting a prefix via DHCPv6-PD when the length of the prefix list
+         * with DHCPv6 preferred flag decreases to zero.
+         */
+        void stopDhcp6();
+
+        /**
+         * Perform a DHCPv6 Rebind whenever the prefix list with DHCPv6 preferred flag
+         * has update (e.g. a prefix is added to or removed) if the client already has
+         * received delegated prefix(es) from one or more servers.
          */
-        void onNewPrefix(PrefixInfo info);
+        void rebindDhcp6();
     }
 
     /** Configuration parameters for IpClientLinkObserver. */
@@ -157,21 +172,6 @@ public class IpClientLinkObserver {
         }
     }
 
-    /** Prefix information received from RTM_NEWPREFIX netlink message. */
-    public static class PrefixInfo {
-        public final IpPrefix prefix;
-        public short flags;
-        public long preferred;
-        public long valid;
-
-        public PrefixInfo(@NonNull final IpPrefix prefix, short flags, long preferred, long valid) {
-            this.prefix = prefix;
-            this.flags = flags;
-            this.preferred = preferred;
-            this.valid = valid;
-        }
-    }
-
     private final Context mContext;
     private final String mInterfaceName;
     private final Callback mCallback;
@@ -186,6 +186,9 @@ public class IpClientLinkObserver {
     private final IpClientNetlinkMonitor mNetlinkMonitor;
     private final NetworkInformationShim mShim;
     private final AlarmManager.OnAlarmListener mExpirePref64Alarm;
+    // Map of prefix in PIO with P flag and its preferred lifetime expiry in milliseconds since boot
+    private final Map<IpPrefix, Long> mDhcp6PdPreferredPrefixes = new ArrayMap<>();
+    private final AlarmManager.OnAlarmListener mExpireDhcp6PdPreferredPrefixAlarm;
 
     private long mNat64PrefixExpiry;
 
@@ -232,6 +235,7 @@ public class IpClientLinkObserver {
                 (nlMsg, whenMs) -> processNetlinkMessage(nlMsg, whenMs));
         mShim = NetworkInformationShimImpl.newInstance();
         mExpirePref64Alarm = new IpClientObserverAlarmListener();
+        mExpireDhcp6PdPreferredPrefixAlarm = new Dhcp6PdPreferredPrefixAlarmListener();
         mHandler.post(() -> {
             if (!mNetlinkMonitor.start()) {
                 Log.wtf(mTag, "Fail to start NetlinkMonitor.");
@@ -240,7 +244,10 @@ public class IpClientLinkObserver {
     }
 
     public void shutdown() {
-        mHandler.post(mNetlinkMonitor::stop);
+        mHandler.post(() -> {
+            mNetlinkMonitor.stop();
+            mDhcp6PdPreferredPrefixes.clear();
+        });
     }
 
     private void maybeLog(String operation, String iface, LinkAddress address) {
@@ -354,6 +361,7 @@ public class IpClientLinkObserver {
         // mLinkProperties, as desired.
         mDnsServerRepository = new DnsServerRepository(mConfig.minRdnssLifetime);
         cancelPref64Alarm();
+        mAlarmManager.cancel(mExpireDhcp6PdPreferredPrefixAlarm);
         mLinkProperties.clear();
         mLinkProperties.setInterfaceName(mInterfaceName);
     }
@@ -663,16 +671,83 @@ public class IpClientLinkObserver {
         }
     }
 
+    private class Dhcp6PdPreferredPrefixAlarmListener implements AlarmManager.OnAlarmListener {
+        @Override
+        public void onAlarm() {
+            final long now = SystemClock.elapsedRealtime();
+            mDhcp6PdPreferredPrefixes.values().removeIf(expiry -> expiry <= now);
+            if (mDhcp6PdPreferredPrefixes.isEmpty()) {
+                mCallback.stopDhcp6();
+                return;
+            }
+            mCallback.rebindDhcp6();
+            updateDhcp6PdPreferredPrefixAlarm();
+        }
+    }
+
+    private void updateDhcp6PdPreferredPrefixAlarm() {
+        // There may be an existing alarm, so try to cancel first.
+        mAlarmManager.cancel(mExpireDhcp6PdPreferredPrefixAlarm);
+        if (mDhcp6PdPreferredPrefixes.isEmpty()) return;
+
+        final long expiry = Collections.min(mDhcp6PdPreferredPrefixes.values());
+        final String tag = mTag + ".DHCPV6PDPREFERRED";
+        mAlarmManager.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP,
+                expiry,
+                tag,
+                mExpireDhcp6PdPreferredPrefixAlarm,
+                mHandler);
+    }
+
+    /** Implements PD-preferred prefix tracking as described in rfc9762 */
+    private void trackPdPreferredPrefix(IpPrefix prefix, long preferredLifetime, boolean pflag) {
+        // The kernel does not send an RTM_NEWPREFIX message for a link-local prefix, but just in
+        // case, ignore it. The p-flag is meaningless for link-local prefixes.
+        if (prefix.getAddress().isLinkLocalAddress()) return;
+
+        // If pflag is false or preferredLifetime is 0, set expiry to now. This ensures the prefix
+        // is removed immediately by the removeIf below. Otherwise, calculate the actual expiry time
+        // based on the preferred lifetime.
+        final long now = SystemClock.elapsedRealtime();
+        final long expiry = pflag ? now + preferredLifetime * 1000 : now;
+
+        // Note that while expired prefixes are supposed to be removed when the alarm fires, it is
+        // possible that this has yet to happen when this function runs. In this (very unlikely)
+        // case, the subsequent call to removeIf may affect multiple prefixes. This could cause a
+        // situation where a prefix is added and an expired prefix is removed at the same time, so
+        // initialSize == finalSize returns true and no REBIND is triggered.
+        // Given the low likelihood (and relatively minor impact) of this race, special handling is
+        // not required.
+        final int initialSize = mDhcp6PdPreferredPrefixes.size();
+        mDhcp6PdPreferredPrefixes.put(prefix, expiry);
+        mDhcp6PdPreferredPrefixes.values().removeIf(v -> v <= now);
+        final int finalSize = mDhcp6PdPreferredPrefixes.size();
+
+        updateDhcp6PdPreferredPrefixAlarm();
+
+        // Size unchanged, nothing to do here:
+        if (initialSize == finalSize) return;
+        switch (finalSize) {
+            case 0:
+                mCallback.stopDhcp6();
+                break;
+            case 1:
+                mCallback.startDhcp6();
+                break;
+            default:
+                mCallback.rebindDhcp6();
+                break;
+        }
+    }
+
     private void processRtNetlinkPrefixMessage(RtNetlinkPrefixMessage msg) {
         final StructPrefixMsg prefixmsg = msg.getPrefixMsg();
         if (prefixmsg.prefix_family != AF_INET6) return;
         if (prefixmsg.prefix_ifindex != mIfindex) return;
         if (prefixmsg.prefix_type != ICMPV6_ND_OPTION_PIO) return;
-        final PrefixInfo info = new PrefixInfo(msg.getPrefix(),
-                prefixmsg.prefix_flags,
-                msg.getPreferredLifetime(),
-                msg.getValidLifetime());
-        mCallback.onNewPrefix(info);
+
+        final boolean pflag = (prefixmsg.prefix_flags & PIO_FLAG_DHCPV6_PD_PREFERRED) != 0;
+        trackPdPreferredPrefix(msg.getPrefix(), msg.getPreferredLifetime(), pflag);
     }
 
     private void processNetlinkMessage(NetlinkMessage nlMsg, long whenMs) {
diff --git a/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java b/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
index 14cb6ff4..ffde7a4d 100644
--- a/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
+++ b/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
@@ -16,6 +16,7 @@
 
 package com.android.networkstack.metrics;
 
+import static android.net.apf.ApfCounterTracker.Counter.CORRUPT_DNS_PACKET;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_802_3_FRAME;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST;
@@ -55,7 +56,10 @@ import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ROUTER_SOLICITATION;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS_REPLIED;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_NON_UNICAST_TDLS;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_RA;
+import static android.net.apf.ApfCounterTracker.Counter.EXCEPTIONS;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ALLOCATE_FAILURE;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY;
@@ -69,8 +73,11 @@ import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_UNICAST_NON_ICMP;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_RA;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_TRANSMIT_FAILURE;
 import static android.net.apf.ApfCounterTracker.Counter.RESERVED_OOB;
 import static android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS;
+import static android.stats.connectivity.CounterName.CN_CORRUPT_DNS_PACKET;
 import static android.stats.connectivity.CounterName.CN_DROPPED_802_3_FRAME;
 import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_NON_IPV4;
 import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_OTHER_HOST;
@@ -110,7 +117,10 @@ import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_REPLIED_
 import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_ROUTER_SOLICITATION;
 import static android.stats.connectivity.CounterName.CN_DROPPED_MDNS;
 import static android.stats.connectivity.CounterName.CN_DROPPED_MDNS_REPLIED;
+import static android.stats.connectivity.CounterName.CN_DROPPED_NON_UNICAST_TDLS;
 import static android.stats.connectivity.CounterName.CN_DROPPED_RA;
+import static android.stats.connectivity.CounterName.CN_EXCEPTIONS;
+import static android.stats.connectivity.CounterName.CN_PASSED_ALLOCATE_FAILURE;
 import static android.stats.connectivity.CounterName.CN_PASSED_ARP_BROADCAST_REPLY;
 import static android.stats.connectivity.CounterName.CN_PASSED_ARP_REQUEST;
 import static android.stats.connectivity.CounterName.CN_PASSED_ARP_UNICAST_REPLY;
@@ -124,6 +134,8 @@ import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NON_ICMP;
 import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_UNICAST_NON_ICMP;
 import static android.stats.connectivity.CounterName.CN_PASSED_NON_IP_UNICAST;
 import static android.stats.connectivity.CounterName.CN_PASSED_OUR_SRC_MAC;
+import static android.stats.connectivity.CounterName.CN_PASSED_RA;
+import static android.stats.connectivity.CounterName.CN_PASSED_TRANSMIT_FAILURE;
 import static android.stats.connectivity.CounterName.CN_TOTAL_PACKETS;
 import static android.stats.connectivity.CounterName.CN_UNKNOWN;
 
@@ -208,6 +220,12 @@ public class ApfSessionInfoMetrics {
                     CN_DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED),
                 Map.entry(DROPPED_IGMP_INVALID, CN_DROPPED_IGMP_INVALID),
                 Map.entry(DROPPED_IGMP_REPORT, CN_DROPPED_IGMP_REPORT),
+                Map.entry(PASSED_ALLOCATE_FAILURE, CN_PASSED_ALLOCATE_FAILURE),
+                Map.entry(PASSED_TRANSMIT_FAILURE, CN_PASSED_TRANSMIT_FAILURE),
+                Map.entry(CORRUPT_DNS_PACKET, CN_CORRUPT_DNS_PACKET),
+                Map.entry(EXCEPTIONS, CN_EXCEPTIONS),
+                Map.entry(PASSED_RA, CN_PASSED_RA),
+                Map.entry(DROPPED_NON_UNICAST_TDLS, CN_DROPPED_NON_UNICAST_TDLS),
                 Map.entry(DROPPED_GARP_REPLY, CN_DROPPED_GARP_REPLY)
             )
     );
diff --git a/src/com/android/networkstack/metrics/IpProvisioningMetrics.java b/src/com/android/networkstack/metrics/IpProvisioningMetrics.java
index daaf207d..ca63281f 100644
--- a/src/com/android/networkstack/metrics/IpProvisioningMetrics.java
+++ b/src/com/android/networkstack/metrics/IpProvisioningMetrics.java
@@ -24,6 +24,7 @@ import android.stats.connectivity.DhcpFeature;
 import android.stats.connectivity.DisconnectCode;
 import android.stats.connectivity.HostnameTransResult;
 import android.stats.connectivity.Ipv6ProvisioningMode;
+import android.stats.connectivity.TransportType;
 
 import com.android.net.module.util.ConnectivityUtils;
 
@@ -65,9 +66,10 @@ public class IpProvisioningMetrics {
 
     /**
      * Write the TransportType into mStatsBuilder.
-     * TODO: implement this
      */
-    public void setTransportType() {}
+    public void setTransportType(TransportType transportType) {
+        mStatsBuilder.setTransportType(transportType);
+    }
 
     /**
      * Write the IPv4Provisioned latency into mStatsBuilder.
diff --git a/src/com/android/networkstack/util/NetworkStackUtils.java b/src/com/android/networkstack/util/NetworkStackUtils.java
index b0252dcb..46f44c74 100755
--- a/src/com/android/networkstack/util/NetworkStackUtils.java
+++ b/src/com/android/networkstack/util/NetworkStackUtils.java
@@ -18,7 +18,6 @@ package com.android.networkstack.util;
 
 import static android.net.apf.ApfConstants.IPV6_SOLICITED_NODES_PREFIX;
 import static android.os.Build.VERSION.CODENAME;
-import static android.os.Build.VERSION.SDK_INT;
 import static android.system.OsConstants.IFA_F_DEPRECATED;
 import static android.system.OsConstants.IFA_F_TENTATIVE;
 
@@ -30,7 +29,6 @@ import android.net.MacAddress;
 import android.system.ErrnoException;
 import android.util.Log;
 
-import androidx.annotation.ChecksSdkIntAtLeast;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
@@ -243,6 +241,12 @@ public class NetworkStackUtils {
     public static final String IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION =
             "ipclient_dhcpv6_pd_preferred_flag_version";
 
+    /**
+     * Experiment flag to support the self-generated IPv6 address registration using DHCPv6.
+     */
+    public static final String IPCLIENT_DHCPV6_ADDR_REGISTER_VERSION =
+            "ipclient_dhcpv6_addr_register_version";
+
     /**
      * Experiment flag to replace INetd usage with netlink in IpClient.
      */
@@ -285,6 +289,12 @@ public class NetworkStackUtils {
     public static final String APF_HANDLE_MLD_OFFLOAD_VERSION =
             "apf_handle_mld_offload_version";
 
+    /**
+     * Experiment flag to enable the feature of handle MDNS advertising offload in Apf.
+     */
+    public static final String APF_HANDLE_MDNS_ADVERTISING_OFFLOAD_VERSION =
+            "apf_handle_mdns_advertising_offload_version";
+
     /**** BEGIN Feature Kill Switch Flags ****/
 
     /**
@@ -463,12 +473,6 @@ public class NetworkStackUtils {
         }
     }
 
-    /** Checks if the device is running on a release version of Android Baklava or newer */
-    @ChecksSdkIntAtLeast(api = 36 /* BUILD_VERSION_CODES.Baklava */)
-    public static boolean isAtLeast25Q2() {
-        return SDK_INT >= 36 || (SDK_INT == 35 && isAtLeastPreReleaseCodename("Baklava"));
-    }
-
     private static boolean isAtLeastPreReleaseCodename(@NonNull String codename) {
         // Special case "REL", which means the build is not a pre-release build.
         if ("REL".equals(CODENAME)) {
@@ -543,16 +547,6 @@ public class NetworkStackUtils {
         addArpEntry(ethAddr.toByteArray(), ipv4Addr.getAddress(), ifname, fd);
     }
 
-    /**
-     * Attaches a socket filter that accepts egress IGMPv2/IGMPv3 reports to the given socket.
-     *
-     * This filter doesn't include IGMPv1 report since device will not send out IGMPv1 report
-     * when the device leaves a multicast address group.
-     *
-     * @param fd the socket's {@link FileDescriptor}.
-     */
-    public static native void attachEgressIgmpReportFilter(FileDescriptor fd) throws ErrnoException;
-
     /**
      * Attaches a socket filter that accepts egress IGMPv2/v3, MLDv1/v2 reports to the given socket.
      *
diff --git a/src/com/android/server/NetworkStackService.java b/src/com/android/server/NetworkStackService.java
index 68d5a21c..d97a129b 100644
--- a/src/com/android/server/NetworkStackService.java
+++ b/src/com/android/server/NetworkStackService.java
@@ -645,6 +645,8 @@ public class NetworkStackService extends Service {
                 pw.println("        Format: <apfVersion>,<maxProgramSize>,<packetFormat>");
                 pw.println("      read");
                 pw.println("        reads and returns the current state of APF memory.");
+                pw.println("      dump-counters");
+                pw.println("        dump APF packet counters.");
             }
 
             private void captureShellCommand(
diff --git a/src/com/android/server/connectivity/DdrTracker.java b/src/com/android/server/connectivity/DdrTracker.java
index 81d881dd..3e337f98 100644
--- a/src/com/android/server/connectivity/DdrTracker.java
+++ b/src/com/android/server/connectivity/DdrTracker.java
@@ -27,6 +27,7 @@ import static com.android.net.module.util.DnsPacket.TYPE_SVCB;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.SuppressLint;
 import android.net.DnsResolver;
 import android.net.LinkProperties;
 import android.net.Network;
@@ -82,6 +83,12 @@ class DdrTracker {
 
     private static final String ALPN_DOH3 = "h3";
 
+    /**
+     * Matches the (non-API) constant in DnsResolver/include/netd_resolv/resolv.h
+     */
+    @VisibleForTesting
+    static final int FLAG_TRY_ALL_SERVERS = 1 << 31;
+
     interface Callback {
         /**
          * Called on a given execution thread `mExecutor` when a SVCB lookup finishes, unless
@@ -231,15 +238,6 @@ class DdrTracker {
         return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getDohPath(alpn) : null;
     }
 
-    @NonNull
-    private String createHostnameForSvcbQuery() {
-        final String hostname = getStrictModeHostname();
-        if (!TextUtils.isEmpty(hostname)) {
-            return "_dns." + hostname;
-        }
-        return DDR_HOSTNAME;
-    }
-
     /** Performs a DNS SVCB Lookup asynchronously. */
     void startSvcbLookup() {
         if (getPrivateDnsMode() == PRIVATE_DNS_MODE_OFF) {
@@ -268,7 +266,9 @@ class DdrTracker {
         // This is for network revalidation in strict mode that a SVCB lookup can be performed
         // and its result can be accepted even if there is no DNS configuration change.
         final int token = ++mTokenId;
-        final String hostname = createHostnameForSvcbQuery();
+        final String strictModeHostname = getStrictModeHostname();
+        final boolean strictMode = !TextUtils.isEmpty(strictModeHostname);
+        final String hostname = strictMode ? "_dns." + strictModeHostname : DDR_HOSTNAME;
         final DnsResolver.Callback<byte[]> callback = new DnsResolver.Callback<byte[]>() {
             boolean isResultFresh() {
                 return token == mTokenId;
@@ -314,7 +314,7 @@ class DdrTracker {
                 }
             }
         };
-        sendDnsSvcbQuery(hostname, mCancelSignal, callback);
+        sendDnsSvcbQuery(hostname, strictMode, mCancelSignal, callback);
     }
 
     /**
@@ -426,14 +426,17 @@ class DdrTracker {
     /**
      * A non-blocking call doing DNS SVCB lookup.
      */
-    private void sendDnsSvcbQuery(String host, @NonNull CancellationSignal cancelSignal,
+    @SuppressLint("WrongConstant") // FLAG_TRY_ALL_SERVERS is a hidden flag
+    private void sendDnsSvcbQuery(String host, boolean strictMode,
+            @NonNull CancellationSignal cancelSignal,
             @NonNull DnsResolver.Callback<byte[]> callback) {
         // Note: the even though this code does not pass FLAG_NO_CACHE_LOOKUP, the query is
         // currently not cached, because the DNS resolver cache does not cache SVCB records.
         // TODO: support caching SVCB records in the DNS resolver cache.
         // This should just work but will need testing.
-        mDnsResolver.rawQuery(mCleartextDnsNetwork, host, CLASS_IN, TYPE_SVCB, 0 /* flags */,
-                mExecutor, cancelSignal, callback);
+        final int flags = strictMode ? 0 : FLAG_TRY_ALL_SERVERS;
+        mDnsResolver.rawQuery(mCleartextDnsNetwork, host, CLASS_IN, TYPE_SVCB,
+                flags, mExecutor, cancelSignal, callback);
     }
 
     private static InetAddress[] toArray(List<InetAddress> list) {
diff --git a/tests/integration/Android.bp b/tests/integration/Android.bp
index d728c6b5..cf53f156 100644
--- a/tests/integration/Android.bp
+++ b/tests/integration/Android.bp
@@ -48,6 +48,7 @@ java_defaults {
         "androidx.test.rules",
         "mockito-target-extended-minus-junit4",
         "net-tests-utils",
+        "net-utils-networkstack",
         "testables",
     ],
     libs: [
@@ -84,6 +85,9 @@ android_test {
     test_suites: ["device-tests"],
     jarjar_rules: ":NetworkStackJarJarRules",
     host_required: ["net-tests-utils-host-common"],
+    host_common_data: [
+        ":net-tests-utils-host-common",
+    ],
     test_config_template: "AndroidTestTemplate_Integration.xml",
 }
 
@@ -107,6 +111,9 @@ android_test {
     test_suites: ["device-tests"],
     jarjar_rules: ":NetworkStackJarJarRules",
     host_required: ["net-tests-utils-host-common"],
+    host_common_data: [
+        ":net-tests-utils-host-common",
+    ],
     test_config_template: "AndroidTestTemplate_Integration.xml",
 }
 
@@ -133,6 +140,9 @@ android_test {
     manifest: "AndroidManifest_root.xml",
     jarjar_rules: ":NetworkStackJarJarRules",
     host_required: ["net-tests-utils-host-common"],
+    host_common_data: [
+        ":net-tests-utils-host-common",
+    ],
     test_config_template: "AndroidTestTemplate_Integration.xml",
 }
 
diff --git a/tests/integration/AndroidTestTemplate_Integration.xml b/tests/integration/AndroidTestTemplate_Integration.xml
index 6107ccc1..606c1b63 100644
--- a/tests/integration/AndroidTestTemplate_Integration.xml
+++ b/tests/integration/AndroidTestTemplate_Integration.xml
@@ -14,6 +14,10 @@
      limitations under the License.
 -->
 <configuration description="Test config for {MODULE}">
+    <!-- Needed to run signature tests in HSUM mode. By default, in this mode the test package is
+         not installed for the system user, but the first full user instead which breaks the
+         sharedUserId these tests rely on. -->
+    <target_preparer class="com.android.tradefed.targetprep.RunOnSystemUserTargetPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="cleanup-apks" value="true" />
         <option name="test-file-name" value="{MODULE}.apk" />
diff --git a/tests/integration/AndroidTest_Coverage.xml b/tests/integration/AndroidTest_Coverage.xml
index eb0ba16d..42de2f89 100644
--- a/tests/integration/AndroidTest_Coverage.xml
+++ b/tests/integration/AndroidTest_Coverage.xml
@@ -14,6 +14,10 @@
      limitations under the License.
 -->
 <configuration description="Runs coverage tests for NetworkStack">
+    <!-- Needed to run signature tests in HSUM mode. By default, in this mode the test package is
+         not installed for the system user, but the first full user instead which breaks the
+         sharedUserId these tests rely on. -->
+    <target_preparer class="com.android.tradefed.targetprep.RunOnSystemUserTargetPreparer"/>
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="test-file-name" value="NetworkStackCoverageTests.apk" />
     </target_preparer>
diff --git a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
index 7ec958ac..76cd7d17 100644
--- a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
+++ b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
@@ -85,6 +85,7 @@ import static com.android.net.module.util.NetworkStackConstants.NEIGHBOR_ADVERTI
 import static com.android.net.module.util.NetworkStackConstants.NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED;
 import static com.android.net.module.util.NetworkStackConstants.PIO_FLAG_AUTONOMOUS;
 import static com.android.net.module.util.NetworkStackConstants.PIO_FLAG_ON_LINK;
+import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_POPULATE_LINK_ADDRESS_LIFETIME_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION;
@@ -163,12 +164,6 @@ import android.net.dhcp.DhcpPacket;
 import android.net.dhcp.DhcpPacket.ParseException;
 import android.net.dhcp.DhcpRequestPacket;
 import android.net.dhcp6.Dhcp6Client;
-import android.net.dhcp6.Dhcp6Packet;
-import android.net.dhcp6.Dhcp6Packet.PrefixDelegation;
-import android.net.dhcp6.Dhcp6RebindPacket;
-import android.net.dhcp6.Dhcp6RenewPacket;
-import android.net.dhcp6.Dhcp6RequestPacket;
-import android.net.dhcp6.Dhcp6SolicitPacket;
 import android.net.ipmemorystore.NetworkAttributes;
 import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener;
 import android.net.ipmemorystore.OnNetworkEventCountRetrievedListener;
@@ -211,6 +206,12 @@ import com.android.net.module.util.PacketBuilder;
 import com.android.net.module.util.SharedLog;
 import com.android.net.module.util.Struct;
 import com.android.net.module.util.arp.ArpPacket;
+import com.android.net.module.util.dhcp6.Dhcp6Packet;
+import com.android.net.module.util.dhcp6.Dhcp6Packet.PrefixDelegation;
+import com.android.net.module.util.dhcp6.Dhcp6RebindPacket;
+import com.android.net.module.util.dhcp6.Dhcp6RenewPacket;
+import com.android.net.module.util.dhcp6.Dhcp6RequestPacket;
+import com.android.net.module.util.dhcp6.Dhcp6SolicitPacket;
 import com.android.net.module.util.ip.IpNeighborMonitor;
 import com.android.net.module.util.ip.IpNeighborMonitor.NeighborEventConsumer;
 import com.android.net.module.util.netlink.NetlinkUtils;
@@ -322,6 +323,9 @@ public abstract class IpClientIntegrationTestCommon {
     private static final int TEST_ARP_LOCKTIME_MS = 1500;
     private static final int TEST_DELAY_FIRST_PROBE_TIME_S = 2;
 
+    private static final byte TEST_PIO_FLAGS_P_UNSET = (byte) 0xC0; // L=1,A=1,R=0,P=0
+    private static final byte TEST_PIO_FLAGS_P_SET = (byte) 0xD0;   // L=1,A=1,R=0,P=1
+
     @Rule
     public final DevSdkIgnoreRule mIgnoreRule = new DevSdkIgnoreRule();
     @Rule
@@ -445,7 +449,9 @@ public abstract class IpClientIntegrationTestCommon {
     private static final String IPV4_ANY_ADDRESS_PREFIX = "0.0.0.0/0";
     private static final String HOSTNAME = "testhostname";
     private static final String TEST_IPV6_PREFIX = "2001:db8:1::/64";
+    private static final String TEST_IPV6_ULA_PREFIX = "fd00:1234:5678:9abc::/64";
     private static final String IPV6_OFF_LINK_DNS_SERVER = "2001:4860:4860::64";
+    private static final String TEST_DHCP6_DELEGATED_PREFIX = "2001:db8:dead:beef::/64";
     private static final String IPV6_ON_LINK_DNS_SERVER = "2001:db8:1::64";
     private static final int TEST_DEFAULT_MTU = 1500;
     private static final int TEST_MIN_MTU = 1280;
@@ -1523,7 +1529,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         if (shouldChangeMtu) {
             // Pretend that ConnectivityService set the MTU.
-            NetlinkUtils.setInterfaceMtu(mIfaceName, mtu);
+            NetlinkUtils.setInterfaceMtu(mDependencies.getInterfaceParams(mIfaceName).index, mtu);
             assertEquals(NetworkInterface.getByName(mIfaceName).getMTU(), mtu);
         }
 
@@ -2042,7 +2048,8 @@ public abstract class IpClientIntegrationTestCommon {
         assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_MIN_MTU);
 
         // Pretend that ConnectivityService set the MTU.
-        NetlinkUtils.setInterfaceMtu(mIfaceName, TEST_MIN_MTU);
+        NetlinkUtils.setInterfaceMtu(
+                mDependencies.getInterfaceParams(mIfaceName).index, TEST_MIN_MTU);
         assertEquals(NetworkInterface.getByName(mIfaceName).getMTU(), TEST_MIN_MTU);
 
         reset(mCb);
@@ -2173,8 +2180,13 @@ public abstract class IpClientIntegrationTestCommon {
     // TODO: move this and the following method to a common location and use them in ApfTest.
     private static ByteBuffer buildPioOption(int valid, int preferred, String prefixString)
             throws Exception {
-        return PrefixInformationOption.build(new IpPrefix(prefixString),
-                (byte) (PIO_FLAG_ON_LINK | PIO_FLAG_AUTONOMOUS), valid, preferred);
+        return buildPioOption(valid, preferred, (byte) (PIO_FLAG_ON_LINK | PIO_FLAG_AUTONOMOUS),
+                prefixString);
+    }
+
+    private static ByteBuffer buildPioOption(int valid, int preferred, byte flags,
+            String prefixString) throws Exception {
+        return PrefixInformationOption.build(new IpPrefix(prefixString), flags, valid, preferred);
     }
 
     private static ByteBuffer buildRdnssOption(int lifetime, String... servers) throws Exception {
@@ -5282,7 +5294,7 @@ public abstract class IpClientIntegrationTestCommon {
         ByteBuffer iapd;
         Dhcp6Packet packet;
         while ((packet = getNextDhcp6Packet()) != null) {
-            final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), t1, t2, ipos);
+            final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), t1, t2, ipos);
             iapd = pd.build();
             if (packet instanceof Dhcp6SolicitPacket) {
                 if (shouldReplyRapidCommit) {
@@ -5598,7 +5610,7 @@ public abstract class IpClientIntegrationTestCommon {
                 7200 /* valid */);
         final IaPrefixOption ipo1 = buildIaPrefixOption(prefix1, 5000 /* preferred */,
                 6000 /* valid */);
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 4500 /* t2 */, Arrays.asList(ipo, ipo1));
         final ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5636,7 +5648,7 @@ public abstract class IpClientIntegrationTestCommon {
         final IpPrefix prefix1 = new IpPrefix("2001:db8:2::/64");
         final IaPrefixOption ipo = buildIaPrefixOption(prefix1, 4500 /* preferred */,
                 7200 /* valid */);
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 4500 /* t2 */, Arrays.asList(ipo));
         final ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5672,7 +5684,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         // Reply with IA_PD but IA_Prefix is absent, client should still stay at the RenewState
         // and restransmit the Renew message, that should not result in any LinkProperties update.
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 4500 /* t2 */, new ArrayList<IaPrefixOption>(0));
         final ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5702,7 +5714,7 @@ public abstract class IpClientIntegrationTestCommon {
                 0 /* valid */);
         final IaPrefixOption ipo1 = buildIaPrefixOption(prefix1, 5000 /* preferred */,
                 6000 /* valid */);
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 4500 /* t2 */, Arrays.asList(ipo, ipo1));
         final ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5751,7 +5763,7 @@ public abstract class IpClientIntegrationTestCommon {
         final IpPrefix prefix = new IpPrefix("2001:db8:1::/64");
         final IaPrefixOption ipo = buildIaPrefixOption(prefix, 3600 /* preferred */,
                 3600 /* valid */);
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 3600 /* t2 */, Collections.singletonList(ipo));
         final ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5817,7 +5829,7 @@ public abstract class IpClientIntegrationTestCommon {
         Dhcp6Packet packet = getNextDhcp6Packet(PACKET_TIMEOUT_MS);
         assertTrue(packet instanceof Dhcp6SolicitPacket);
 
-        final PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 0 /* t1 */, 0 /* t2 */,
+        final PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 0 /* t1 */, 0 /* t2 */,
                 new ArrayList<IaPrefixOption>() /* ipos */, Dhcp6Packet.STATUS_NO_PREFIX_AVAIL);
         final ByteBuffer iapd = pd.build();
         if (shouldReplyWithAdvertise) {
@@ -5855,7 +5867,7 @@ public abstract class IpClientIntegrationTestCommon {
         final IpPrefix prefix = new IpPrefix("2001:db8:1::/64");
         final IaPrefixOption ipo = buildIaPrefixOption(prefix, 4500 /* preferred */,
                 7200 /* valid */);
-        PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 1000 /* t1 */,
+        PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 1000 /* t1 */,
                 2000 /* t2 */, Arrays.asList(ipo));
         ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Advertise(packet, iapd.array(), mClientMac,
@@ -5866,7 +5878,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         // Reply for Request with NoPrefixAvail status code. Not sure if this is reasonable in
         // practice, but Server can do everything it wants.
-        pd = new PrefixDelegation(packet.getIaId(), 0 /* t1 */, 0 /* t2 */,
+        pd = new PrefixDelegation(packet.getIaid(), 0 /* t1 */, 0 /* t2 */,
                 new ArrayList<IaPrefixOption>() /* ipos */, Dhcp6Packet.STATUS_NO_PREFIX_AVAIL);
         iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5897,7 +5909,7 @@ public abstract class IpClientIntegrationTestCommon {
         final IpPrefix prefix = new IpPrefix("2001:db8:1::/64");
         final IaPrefixOption ipo = buildIaPrefixOption(prefix, 4500 /* preferred */,
                 7200 /* valid */);
-        PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 1000 /* t1 */,
+        PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 1000 /* t1 */,
                 2000 /* t2 */, Arrays.asList(ipo));
         ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5913,7 +5925,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         // Reply for Renew with NoPrefixAvail status code, check if client will retransmit the
         // Renew message.
-        pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */, 4500 /* t2 */,
+        pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */, 4500 /* t2 */,
                 new ArrayList<IaPrefixOption>(0) /* ipos */, Dhcp6Packet.STATUS_NO_PREFIX_AVAIL);
         iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5949,7 +5961,7 @@ public abstract class IpClientIntegrationTestCommon {
         final IpPrefix prefix = new IpPrefix("2001:db8:1::/64");
         final IaPrefixOption ipo = buildIaPrefixOption(prefix, 4500 /* preferred */,
                 7200 /* valid */);
-        PrefixDelegation pd = new PrefixDelegation(packet.getIaId(), 1000 /* t1 */,
+        PrefixDelegation pd = new PrefixDelegation(packet.getIaid(), 1000 /* t1 */,
                 2000 /* t2 */, Arrays.asList(ipo));
         ByteBuffer iapd = pd.build();
         mPacketReader.sendResponse(buildDhcp6Reply(packet, iapd.array(), mClientMac,
@@ -5971,7 +5983,7 @@ public abstract class IpClientIntegrationTestCommon {
 
         // Reply for Rebind with NoPrefixAvail status code, check if client will retransmit the
         // Rebind message.
-        pd = new PrefixDelegation(packet.getIaId(), 3600 /* t1 */,
+        pd = new PrefixDelegation(packet.getIaid(), 3600 /* t1 */,
                 4500 /* t2 */, new ArrayList<IaPrefixOption>(0) /* ipos */,
                 Dhcp6Packet.STATUS_NO_PREFIX_AVAIL);
         iapd = pd.build();
@@ -6511,4 +6523,108 @@ public abstract class IpClientIntegrationTestCommon {
         assertRetrievedNetworkEventCount(TEST_CLUSTER, 10 /* expectedCountInPastWeek */,
                 10 /* expectedCountInPastDay */, 10 /* expectedCountInPastSixHours */);
     }
+
+    private void prepareDhcp6PrefixDelegationPreferredFlagTests(byte flags, boolean hasUlaPio)
+            throws Exception {
+        // DHCPv6 prefix delegation preferred flag relevant test cases require the kernel to support
+        // "ra_honor_pio_pflag" sysctl, which lands since 6.12 kernel version.
+        final String ra_honor_pio_flag =
+                "/proc/sys/net/ipv6/conf/" + mIfaceName + "/ra_honor_pio_pflag";
+        assumeTrue(new File(ra_honor_pio_flag).exists());
+
+        final List<ByteBuffer> options = new ArrayList<>();
+        final ByteBuffer pio =
+                buildPioOption(3600 /* valid */, 1800 /* preferred */, flags, TEST_IPV6_PREFIX);
+        final ByteBuffer ulaPio =
+                buildPioOption(200 /* valid */, 100 /* preferred */, TEST_IPV6_ULA_PREFIX);
+        final ByteBuffer rdnss = buildRdnssOption(3600, IPV6_OFF_LINK_DNS_SERVER);
+        options.add(pio);
+        if (hasUlaPio) options.add(ulaPio);
+        options.add(rdnss);
+        final ByteBuffer ra = buildRaPacket(options.toArray(new ByteBuffer[options.size()]));
+
+        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
+                .withoutIPv4()
+                .build();
+        startIpClientProvisioning(config);
+
+        waitForRouterSolicitation();
+        mPacketReader.sendResponse(ra);
+    }
+
+    @Test
+    @Flag(name = IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION, enabled = true)
+    public void testDhcp6PrefixDelegationPreferred() throws Exception {
+        prepareDhcp6PrefixDelegationPreferredFlagTests(TEST_PIO_FLAGS_P_SET, false /* hasUlaPio */);
+
+        // Verify that DHCPv6 Prefix Delegation should be used for IPv6 provisioning when P bit
+        // is set in the PIO, and device should ignore the A bit and haven't any SLAAC address
+        // derived from that on-link prefix.
+        final IpPrefix delegatedPrefix = new IpPrefix(TEST_DHCP6_DELEGATED_PREFIX);
+        handleDhcp6Packets(delegatedPrefix, true /* shouldReplyRapidCommit */);
+        final ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
+        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
+        final LinkProperties lp = captor.getValue();
+        assertTrue(hasIpv6AddressPrefixedWith(lp, delegatedPrefix));
+        assertFalse(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_IPV6_PREFIX)));
+    }
+
+    @Test
+    @Flag(name = IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION, enabled = true)
+    public void testDhcp6PrefixDelegationPreferred_withoutPFlag() throws Exception {
+        prepareDhcp6PrefixDelegationPreferredFlagTests(TEST_PIO_FLAGS_P_UNSET,
+                false /* hasUlaPio */);
+
+        // Verify that DHCPv6 Prefix Delegation should not be used for IPv6 provisioning when P bit
+        // is not set in the PIO, and device should do SLAAC based on the on-link prefix in PIO.
+        assertNull(getNextDhcp6Packet(PACKET_TIMEOUT_MS));
+        final ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
+        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
+        final LinkProperties lp = captor.getValue();
+        assertTrue(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_IPV6_PREFIX)));
+        assertFalse(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_DHCP6_DELEGATED_PREFIX)));
+    }
+
+    @Test
+    @Flag(name = IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION, enabled = true)
+    public void testDhcp6PrefixDelegationPreferred_multiplePiosWithPFlag() throws Exception {
+        prepareDhcp6PrefixDelegationPreferredFlagTests(TEST_PIO_FLAGS_P_SET, true /* hasUlaPio */);
+
+        // Verify that DHCPv6 Prefix Delegation should be used for IPv6 provisioning when the
+        // P bit is set in the PIO, apart of that, RA also includes a PIO with ULA prefix, so
+        // the device ignore the A bit in the PIO and have the ULA address based on the ULA prefix.
+        final IpPrefix delegatedPrefix = new IpPrefix(TEST_DHCP6_DELEGATED_PREFIX);
+        handleDhcp6Packets(delegatedPrefix, true /* shouldReplyRapidCommit */);
+        final ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
+        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
+        final LinkProperties lp = captor.getValue();
+        assertTrue(hasIpv6AddressPrefixedWith(lp, delegatedPrefix));
+        assertTrue(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_IPV6_ULA_PREFIX)));
+        assertFalse(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_IPV6_PREFIX)));
+    }
+
+    @Test
+    @Flag(name = IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION, enabled = true)
+    public void testDhcp6PrefixDelegationPreferred_withPFlag_preferredLifetimeBecomesZero()
+            throws Exception {
+        prepareDhcp6PrefixDelegationPreferredFlagTests(TEST_PIO_FLAGS_P_SET, true /* hasUlaPio */);
+
+        final IpPrefix delegatedPrefix = new IpPrefix(TEST_DHCP6_DELEGATED_PREFIX);
+        handleDhcp6Packets(delegatedPrefix, true /* shouldReplyRapidCommit */);
+        final ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
+        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
+        final LinkProperties lp = captor.getValue();
+        assertTrue(hasIpv6AddressPrefixedWith(lp, delegatedPrefix));
+        assertFalse(hasIpv6AddressPrefixedWith(lp, new IpPrefix(TEST_IPV6_PREFIX)));
+
+        clearInvocations(mCb);
+
+        // Send another PIO with P flag but 0 preferred lifetime in the RA, this will result in the
+        // prefix being removed from the list, but the lifetimes of any prefixes already obtained
+        // via DHCPv6 are unaffected, i.e. there should be no any change on the LinkProperties.
+        final ByteBuffer pio = buildPioOption(3600 /* valid */, 0 /* preferred */,
+                TEST_PIO_FLAGS_P_SET, TEST_IPV6_PREFIX);
+        sendRouterAdvertisement(false /* waitForRs*/, (short) 1800 /* router lifetime */, pio);
+        verify(mCb, never()).onLinkPropertiesChange(any());
+    }
 }
diff --git a/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt b/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
index ea6f35a1..a8474a15 100644
--- a/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
+++ b/tests/integration/signature/android/net/util/NetworkStackUtilsIntegrationTest.kt
@@ -52,6 +52,7 @@ import com.android.net.module.util.IpUtils
 import com.android.net.module.util.Ipv6Utils
 import com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN
 import com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN
+import com.android.net.module.util.NetworkStackConstants.ETHER_DST_ADDR_OFFSET
 import com.android.net.module.util.NetworkStackConstants.ETHER_SRC_ADDR_OFFSET
 import com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ANY
 import com.android.net.module.util.NetworkStackConstants.IPV4_CHECKSUM_OFFSET
@@ -243,38 +244,12 @@ class NetworkStackUtilsIntegrationTest {
     }
 
     @Test
-    fun testAttachEgressIgmpReportFilter() {
+    fun testAttachEgressMulticastReportFilterForMulticastGroupChange() {
         val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
         val ifParams = InterfaceParams.getByName(iface.interfaceName)
             ?: fail("Could not obtain interface params for ${iface.interfaceName}")
         val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_ALL, ifParams.index)
-        NetworkStackUtils.attachEgressIgmpReportFilter(socket)
-        Os.bind(socket, socketAddr)
-        Os.setsockoptTimeval(
-            socket,
-            SOL_SOCKET,
-            SO_RCVTIMEO,
-            StructTimeval.fromMillis(TEST_TIMEOUT_MS)
-        )
-
-        val sendSocket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
-        Os.bind(sendSocket, socketAddr)
-
-        testExpectedPacketsReceived(sendSocket, socket)
-
-        // shorten the socket timeout to prevent waiting too long in the test
-        Os.setsockoptTimeval(socket, SOL_SOCKET, SO_RCVTIMEO, StructTimeval.fromMillis(100))
-
-        testExpectedPacketsNotReceived(sendSocket, socket)
-    }
-
-    @Test
-    fun testAttachEgressIgmpReportFilterForMulticastGroupChange() {
-        val socket = Os.socket(AF_PACKET, SOCK_RAW or SOCK_CLOEXEC, 0)
-        val ifParams = InterfaceParams.getByName(iface.interfaceName)
-            ?: fail("Could not obtain interface params for ${iface.interfaceName}")
-        val socketAddr = SocketUtils.makePacketSocketAddress(ETH_P_ALL, ifParams.index)
-        NetworkStackUtils.attachEgressIgmpReportFilter(socket)
+        NetworkStackUtils.attachEgressMulticastReportFilter(socket)
         Os.bind(socket, socketAddr)
         Os.setsockoptTimeval(
             socket,
@@ -288,6 +263,8 @@ class NetworkStackUtilsIntegrationTest {
         val networkInterface = NetworkInterface.getByName(iface.interfaceName)
 
         multicastSock.joinGroup(mcastAddr, networkInterface)
+
+        val igmpv3ReportPacketFilter = { pkt: ByteArray -> isIgmpv3ReportPacket(pkt) }
         // Using scapy to generate IGMPv3 membership report:
         // ether = Ether(src='02:03:04:05:06:07', dst='01:00:5e:00:00:16')
         // ip = IP(src='0.0.0.0', dst='224.0.0.22', id=0, flags='DF', options=[IPOption_Router_Alert()])
@@ -301,7 +278,12 @@ class NetworkStackUtilsIntegrationTest {
         val expectedJoinPkt = HexDump.hexStringToByteArray(
             joinReport.replace("020304050607", srcMac)
         )
-        assertNextPacketEquals(socket, expectedJoinPkt, "IGMPv3 join report")
+        assertUntilPacketEquals(
+            socket,
+            expectedJoinPkt,
+            "IGMPv3 join report",
+            igmpv3ReportPacketFilter
+        )
 
         multicastSock.leaveGroup(mcastAddr, networkInterface)
         // Using scapy to generate IGMPv3 membership report:
@@ -316,7 +298,12 @@ class NetworkStackUtilsIntegrationTest {
         val expectedLeavePkt = HexDump.hexStringToByteArray(
             leaveReport.replace("020304050607", srcMac)
         )
-        assertNextPacketEquals(socket, expectedLeavePkt, "IGMPv3 leave report")
+        assertUntilPacketEquals(
+            socket,
+            expectedLeavePkt,
+            "IGMPv3 leave report",
+            igmpv3ReportPacketFilter
+        )
     }
 
     @Test
@@ -528,7 +515,9 @@ class NetworkStackUtilsIntegrationTest {
     private fun assertUntilPacketEquals(
         socket: FileDescriptor,
         expected: ByteArray,
-        descr: String
+        descr: String,
+        filter: (ByteArray) -> Boolean =
+            { pkt: ByteArray -> !isTestInterfaceEgressPacket(pkt) }
     ) {
         val buffer = ByteArray(TEST_MTU)
         var readBytes: Int
@@ -537,7 +526,7 @@ class NetworkStackUtilsIntegrationTest {
             .also { readBytes = it } > 0
         ) {
             actualPkt = buffer.copyOfRange(0, readBytes)
-            if (!isTestInterfaceEgressPacket(actualPkt)) break
+            if (filter(actualPkt)) break
         }
 
         assertNotNull(actualPkt, "no received packets")
@@ -549,7 +538,13 @@ class NetworkStackUtilsIntegrationTest {
         )
     }
 
-    private fun assertUntilSocketReadErrno(msg: String, socket: FileDescriptor, errno: Int) {
+    private fun assertUntilSocketReadErrno(
+        msg: String,
+        socket: FileDescriptor,
+        errno: Int,
+        filter: (ByteArray) -> Boolean =
+            { pkt: ByteArray -> !isTestInterfaceEgressPacket(pkt) }
+    ) {
         val buffer = ByteArray(TEST_MTU)
         var readBytes: Int
         var actualPkt: ByteArray? = null
@@ -558,7 +553,7 @@ class NetworkStackUtilsIntegrationTest {
                     .also { readBytes = it } > 0
             ) {
                 actualPkt = buffer.copyOfRange(0, readBytes)
-                if (!isTestInterfaceEgressPacket(actualPkt)) break
+                if (filter(actualPkt)) break
             }
             fail(msg + ": " + HexDump.toHexString(actualPkt))
         } catch (expected: ErrnoException) {
@@ -694,6 +689,16 @@ class NetworkStackUtilsIntegrationTest {
         return srcMac.contentEquals(ifParams.macAddr.toByteArray())
     }
 
+    // Assume only IGMPv3 reports with ether destination 01:00:5E:00:00:16
+    private fun isIgmpv3ReportPacket(packet: ByteArray): Boolean {
+        val dstMac = packet.copyOfRange(
+            ETHER_DST_ADDR_OFFSET,
+            ETHER_DST_ADDR_OFFSET + ETHER_ADDR_LEN
+        )
+
+        return dstMac.contentEquals(MacAddress.fromString("01:00:5E:00:00:16").toByteArray())
+    }
+
     private fun doTestDhcpResponseWithMfBitDropped(generic: Boolean) {
         val ifindex = InterfaceParams.getByName(iface.interfaceName).index
         val packetSock = Os.socket(AF_PACKET, SOCK_RAW or SOCK_NONBLOCK, /*protocol=*/0)
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 47fd29ba..d63ca9f2 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -116,7 +116,6 @@ java_defaults {
     name: "libnetworkstackutilsjni_deps",
     jni_libs: [
         "libnativehelper_compat_libc++",
-        "libapfjniv6",
-        "libapfjninext",
+        "libapfjni",
     ],
 }
diff --git a/tests/unit/jni/Android.bp b/tests/unit/jni/Android.bp
index 0dc31a38..61b66110 100644
--- a/tests/unit/jni/Android.bp
+++ b/tests/unit/jni/Android.bp
@@ -40,30 +40,12 @@ cc_defaults {
         "libapf",
         "libapfdisassembler",
         "libpcap",
-        "libapfbuf",
     ],
     sdk_version: "30",
     stl: "c++_static",
 }
 
 cc_library_shared {
-    name: "libapfjniv6",
+    name: "libapfjni",
     defaults: ["libapfjni_defaults"],
-    cflags: [
-        "-DAPF_INTERPRETER_V6",
-    ],
-    static_libs: [
-        "libapf_v6",
-    ],
-}
-
-cc_library_shared {
-    name: "libapfjninext",
-    defaults: ["libapfjni_defaults"],
-    cflags: [
-        "-DAPF_INTERPRETER_NEXT",
-    ],
-    static_libs: [
-        "libapf_next",
-    ],
 }
diff --git a/tests/unit/jni/apf_jni.cpp b/tests/unit/jni/apf_jni.cpp
index 98078c97..50c02b3c 100644
--- a/tests/unit/jni/apf_jni.cpp
+++ b/tests/unit/jni/apf_jni.cpp
@@ -23,35 +23,15 @@
 #include <string>
 #include <vector>
 
-#include "v4/apf_interpreter.h"
 #include "disassembler.h"
 #include "nativehelper/scoped_primitive_array.h"
 
 #include "next/test_buf_allocator.h"
-
-#ifdef APF_INTERPRETER_NEXT
-#include "next/apf_interpreter.h"
-#endif
-
-#ifdef APF_INTERPRETER_V6
-#include "v6/apf_interpreter.h"
-#endif
+#include "apflib.h"
 
 #define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
 #define LOG_TAG "ApfJniUtils"
 
-static int run_apf_interpreter(int apf_version, uint32_t* program,
-                               uint32_t program_len, uint32_t ram_len,
-                               const uint8_t* packet, uint32_t packet_len,
-                               uint32_t filter_age) {
-  if (apf_version <= 4) {
-    return accept_packet((uint8_t*)program, program_len, ram_len, packet, packet_len,
-                         filter_age);
-  } else {
-    return apf_run(nullptr, program, program_len, ram_len, packet, packet_len,
-                         filter_age << 14);
-  }
-}
 
 // JNI function acting as simply call-through to native APF interpreter.
 static jint
@@ -63,15 +43,18 @@ com_android_server_ApfTest_apfSimulate(JNIEnv* env, jclass, jint apf_version,
     uint32_t packet_len = (uint32_t)packet.size();
     uint32_t program_len = env->GetArrayLength(jprogram);
     uint32_t data_len = jdata ? env->GetArrayLength(jdata) : 0;
-    // we need to guarantee room for APFv6's 5 u32 counters (20 bytes)
-    // and APFv6.1's 6 u32 counters (24 bytes)
-    // and we need to make sure ram_len is a multiple of 4 bytes,
-    // so that the counters (which are indexed from the back are aligned.
+    // For APFv6+ we need to make sure ram_len is a multiple of 4 bytes,
+    // so that the counters (which are indexed from the back) are aligned.
+    // We also need to guarantee room for APFv6's 5 u32 counters (20 bytes),
+    // and APFv6.1's 6 u32 counters (24 bytes).
+    // Furthermore APFv6.1 has a 1024 byte minimum ram_len.
     uint32_t ram_len = program_len + data_len;
-    if (apf_version > 4) {
+    if (apf_version >= 6000) {
+        uint32_t builtin_counters = (apf_version >= 6100) ? 6 : 5;
+        uint32_t required_data_len = builtin_counters * sizeof(uint32_t);
+        if (data_len < required_data_len) ram_len = program_len + required_data_len;
         ram_len += 3; ram_len &= ~3;
-        uint32_t need = 24; // TODO: (apf_version > 6000) ? 24 : 20;
-        if (data_len < need) ram_len += need;
+        if (apf_version >= 6100 && ram_len < 1024) ram_len = 1024;
     }
     std::vector<uint32_t> buf((ram_len + 3) / 4, 0);
     jbyte* jbuf = reinterpret_cast<jbyte*>(buf.data());
@@ -82,10 +65,10 @@ com_android_server_ApfTest_apfSimulate(JNIEnv* env, jclass, jint apf_version,
         env->GetByteArrayRegion(jdata, 0, data_len, jbuf + ram_len - data_len);
     }
 
-    jint result = run_apf_interpreter(
+    jint result = apf_run_generic(
         apf_version, buf.data(), program_len, ram_len,
         reinterpret_cast<const uint8_t *>(packet.get()), packet_len,
-        filter_age);
+        filter_age << 14);
 
     if (jdata) {
         env->SetByteArrayRegion(jdata, 0, data_len, jbuf + ram_len - data_len);
@@ -205,7 +188,7 @@ static jboolean com_android_server_ApfTest_compareBpfApf(
         const uint8_t* apf_packet;
         do {
             apf_packet = pcap_next(apf_pcap.get(), &apf_header);
-        } while (apf_packet != NULL && !run_apf_interpreter(apf_version,
+        } while (apf_packet != NULL && !apf_run_generic(apf_version,
                 apf_program.data(), program_len, ram_len,
                 apf_packet, apf_header.len, 0 /* filter_age */));
 
@@ -223,52 +206,6 @@ static jboolean com_android_server_ApfTest_compareBpfApf(
     return true;
 }
 
-static jboolean com_android_server_ApfTest_dropsAllPackets(
-    JNIEnv* env, jclass, jint apf_version, jbyteArray jprogram,
-    jbyteArray jdata, jstring jpcap_filename) {
-    ScopedUtfChars pcap_filename(env, jpcap_filename);
-    ScopedByteArrayRO apf_program(env, jprogram);
-    uint32_t apf_program_len = (uint32_t)apf_program.size();
-    uint32_t data_len = env->GetArrayLength(jdata);
-    uint32_t ram_len = apf_program_len + data_len;
-    if (apf_version > 4) {
-        ram_len += 3; ram_len &= ~3;
-        if (data_len < 20) ram_len += 20;
-    }
-    pcap_pkthdr apf_header;
-    const uint8_t* apf_packet;
-    char pcap_error[PCAP_ERRBUF_SIZE];
-    std::vector<uint32_t> buf((ram_len + 3) / 4, 0);
-    jbyte* jbuf = reinterpret_cast<jbyte*>(buf.data());
-
-    // Merge program and data into a single buffer.
-    env->GetByteArrayRegion(jprogram, 0, apf_program_len, jbuf);
-    env->GetByteArrayRegion(jdata, 0, data_len, jbuf + ram_len - data_len);
-
-    // Open pcap file
-    ScopedFILE apf_fp(fopen(pcap_filename.c_str(), "rb"));
-    ScopedPcap apf_pcap(pcap_fopen_offline(apf_fp.get(), pcap_error));
-
-    if (apf_pcap.get() == NULL) {
-        throwException(env, "pcap_fopen_offline failed: " + std::string(pcap_error));
-        return false;
-    }
-
-    while ((apf_packet = pcap_next(apf_pcap.get(), &apf_header)) != NULL) {
-        int result = run_apf_interpreter(
-            apf_version, buf.data(), apf_program_len, ram_len, apf_packet, apf_header.len, 0);
-
-        // Return false once packet passes the filter
-        if (result) {
-            env->SetByteArrayRegion(jdata, 0, data_len, jbuf + ram_len - data_len);
-            return false;
-         }
-    }
-
-    env->SetByteArrayRegion(jdata, 0, data_len, jbuf + ram_len - data_len);
-    return true;
-}
-
 static jobjectArray com_android_server_ApfTest_disassembleApf(
     JNIEnv* env, jclass, jbyteArray jprogram) {
     uint32_t program_len = env->GetArrayLength(jprogram);
@@ -345,20 +282,18 @@ extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
     }
 
     static JNINativeMethod gMethods[] = {
-            { "apfSimulate", "(I[B[B[BI)I",
-                    (void*)com_android_server_ApfTest_apfSimulate },
-            { "compileToBpf", "(Ljava/lang/String;)Ljava/lang/String;",
-                    (void*)com_android_server_ApfTest_compileToBpf },
-            { "compareBpfApf", "(ILjava/lang/String;Ljava/lang/String;[B)Z",
-                    (void*)com_android_server_ApfTest_compareBpfApf },
-            { "dropsAllPackets", "(I[B[BLjava/lang/String;)Z",
-                    (void*)com_android_server_ApfTest_dropsAllPackets },
-            { "disassembleApf", "([B)[Ljava/lang/String;",
-              (void*)com_android_server_ApfTest_disassembleApf },
-            { "getAllTransmittedPackets", "()Ljava/util/List;",
-                    (void*)com_android_server_ApfTest_getAllTransmittedPackets },
-            { "resetTransmittedPacketMemory", "()V",
-              (void*)com_android_server_ApfTest_resetTransmittedPacketMemory },
+        {"apfSimulate", "(I[B[B[BI)I",
+         (void *)com_android_server_ApfTest_apfSimulate},
+        {"compileToBpf", "(Ljava/lang/String;)Ljava/lang/String;",
+         (void *)com_android_server_ApfTest_compileToBpf},
+        {"compareBpfApf", "(ILjava/lang/String;Ljava/lang/String;[B)Z",
+         (void *)com_android_server_ApfTest_compareBpfApf},
+        {"disassembleApf", "([B)[Ljava/lang/String;",
+         (void *)com_android_server_ApfTest_disassembleApf},
+        {"getAllTransmittedPackets", "()Ljava/util/List;",
+         (void *)com_android_server_ApfTest_getAllTransmittedPackets},
+        {"resetTransmittedPacketMemory", "()V",
+         (void *)com_android_server_ApfTest_resetTransmittedPacketMemory},
     };
 
     jniRegisterNativeMethods(env, "android/net/apf/ApfJniUtils",
diff --git a/tests/unit/res/raw/apfPcap.pcap b/tests/unit/res/raw/apfPcap.pcap
deleted file mode 100644
index 0206d25d..00000000
Binary files a/tests/unit/res/raw/apfPcap.pcap and /dev/null differ
diff --git a/tests/unit/src/android/net/apf/ApfFilterTest.kt b/tests/unit/src/android/net/apf/ApfFilterTest.kt
index 5cfeaad5..8ac2a9f3 100644
--- a/tests/unit/src/android/net/apf/ApfFilterTest.kt
+++ b/tests/unit/src/android/net/apf/ApfFilterTest.kt
@@ -75,6 +75,7 @@ import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
 import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP
 import android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS
 import android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST
+import android.net.apf.ApfCounterTracker.Counter.PASSED_RA
 import android.net.apf.ApfFilter.Dependencies
 import android.net.apf.ApfTestHelpers.Companion.TIMEOUT_MS
 import android.net.apf.BaseApfGenerator.APF_VERSION_3
@@ -92,6 +93,7 @@ import android.system.OsConstants.SOCK_STREAM
 import android.util.Log
 import androidx.test.filters.SmallTest
 import com.android.internal.annotations.GuardedBy
+import com.android.modules.utils.build.SdkLevel
 import com.android.net.module.util.HexDump
 import com.android.net.module.util.InterfaceParams
 import com.android.net.module.util.NetworkStackConstants.ARP_ETHER_IPV4_LEN
@@ -108,10 +110,12 @@ import com.android.networkstack.metrics.NetworkQuirkMetrics
 import com.android.networkstack.packets.NeighborAdvertisement
 import com.android.networkstack.packets.NeighborSolicitation
 import com.android.networkstack.util.NetworkStackUtils
-import com.android.networkstack.util.NetworkStackUtils.isAtLeast25Q2
 import com.android.testutils.DevSdkIgnoreRule
 import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
 import com.android.testutils.DevSdkIgnoreRunner
+import com.android.testutils.EtherPkt
+import com.android.testutils.Ip6Pkt
+import com.android.testutils.RaPkt
 import com.android.testutils.quitResources
 import com.android.testutils.tryTest
 import com.android.testutils.visibleOnHandlerThread
@@ -442,11 +446,9 @@ class ApfFilterTest {
     private lateinit var raReadSocket: FileDescriptor
     private var raWriterSocket = FileDescriptor()
     private var mcastWriteSocket = FileDescriptor()
-    private lateinit var apfTestHelpers: ApfTestHelpers
 
     @Before
     fun setUp() {
-        apfTestHelpers = ApfTestHelpers(apfInterpreterVersion)
         MockitoAnnotations.initMocks(this)
         // mock anycast6 address from /proc/net/anycast6
         doReturn(hostAnycast6Addresses).`when`(dependencies).getAnycast6Addresses(any())
@@ -467,8 +469,6 @@ class ApfFilterTest {
         doReturn(raReadSocket).`when`(dependencies).createPacketReaderSocket(anyInt())
         val mcastReadSocket = FileDescriptor()
         Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mcastWriteSocket, mcastReadSocket)
-        doReturn(mcastReadSocket)
-                .`when`(dependencies).createEgressIgmpReportsReaderSocket(anyInt())
         doReturn(mcastReadSocket)
                 .`when`(dependencies).createEgressMulticastReportsReaderSocket(anyInt())
         doReturn(nsdManager).`when`(context).getSystemService(NsdManager::class.java)
@@ -501,7 +501,7 @@ class ApfFilterTest {
         shutdownApfFilters()
         handler.waitForIdle(TIMEOUT_MS)
         Mockito.framework().clearInlineMocks()
-        apfTestHelpers.resetTransmittedPacketMemory()
+        ApfJniUtils.resetTransmittedPacketMemory()
         handlerThread.quitSafely()
         handlerThread.join()
     }
@@ -561,7 +561,7 @@ class ApfFilterTest {
     }
 
     private fun doTestEtherTypeAllowListFilter(apfFilter: ApfFilter) {
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
 
         // Using scapy to generate IPv4 mDNS packet:
         //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
@@ -573,7 +573,7 @@ class ApfFilterTest {
             01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
             b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(mdnsPkt),
@@ -589,17 +589,17 @@ class ApfFilterTest {
             333300000001e89f806660bb86dd6000000000103afffe800000000000000000000000
             000001ff0200000000000000000000000000018600600700080e100000000000000e10
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(raPkt),
-            PASSED_IPV6_ICMP
+            PASSED_RA
         )
 
         // Using scapy to generate ethernet packet with type 0x88A2:
         //  p = Ether(type=0x88A2)/Raw(load="01")
         val ethPkt = "ffffffffffff047bcb463fb588a23031"
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ethPkt),
@@ -681,7 +681,7 @@ class ApfFilterTest {
     fun testIPv4PacketFilterOnV6OnlyNetwork() {
         val apfFilter = getApfFilter()
         apfFilter.updateClatInterfaceState(true)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
 
         // Using scapy to generate IPv4 mDNS packet:
         //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
@@ -693,7 +693,7 @@ class ApfFilterTest {
             01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
             b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(mdnsPkt),
@@ -707,7 +707,7 @@ class ApfFilterTest {
         val nonUdpPkt = """
             ffffffffffff00112233445508004500001400010000400cb934c0a80101ffffffff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonUdpPkt),
@@ -721,7 +721,7 @@ class ApfFilterTest {
         val fragmentUdpPkt = """
             ffffffffffff0011223344550800450000140001200a40119925c0a80101ffffffff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(fragmentUdpPkt),
@@ -736,7 +736,7 @@ class ApfFilterTest {
         val nonDhcpServerPkt = """
             ffffffffffff00112233445508004500001c000100004011b927c0a80101ffffffff0035004600083dba
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpServerPkt),
@@ -771,7 +771,7 @@ class ApfFilterTest {
             0000000000000000000000000000000000000000000000000000638253633501023604c0
             a801010104ffffff000304c0a80101330400015180060408080808ff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(dhcp4Pkt),
@@ -790,7 +790,7 @@ class ApfFilterTest {
             0000000000000000000000000000000000000000000000000000638253633501023604c0
             a801010104ffffff000304c0a80101330400015180060408080808ff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(dhcp4PktDf),
@@ -809,7 +809,7 @@ class ApfFilterTest {
             01005e0000fbe89f806660bb08004500001d000100034011f75dc0a8010ac0a8
             01146f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(fragmentedUdpPkt),
@@ -821,7 +821,7 @@ class ApfFilterTest {
     fun testLoopbackFilter() {
         val apfConfig = getDefaultConfig()
         val apfFilter = getApfFilter(apfConfig)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // Using scapy to generate echo-ed broadcast packet:
         //   ether = Ether(src=${ifParams.macAddr}, dst='ff:ff:ff:ff:ff:ff')
         //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=21)
@@ -829,11 +829,11 @@ class ApfFilterTest {
         val nonDhcpBcastPkt = """
             ffffffffffff020304050607080045000014000100004015b92bc0a80101ffffffff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfFilter.mApfVersionSupported,
                 program,
                 HexDump.hexStringToByteArray(nonDhcpBcastPkt),
-                if (isAtLeast25Q2()) DROPPED_ETHER_OUR_SRC_MAC else PASSED_ETHER_OUR_SRC_MAC
+                if (SdkLevel.isAtLeastB()) DROPPED_ETHER_OUR_SRC_MAC else PASSED_ETHER_OUR_SRC_MAC
         )
     }
 
@@ -841,7 +841,7 @@ class ApfFilterTest {
     @Test
     fun testInvalidIgmpPacketDropped() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate invalid length IGMPv1 general query packet:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1', len=24, proto=2)
@@ -851,7 +851,7 @@ class ApfFilterTest {
             01005e00000100112233445508004500001800010000400290e00a000002e00000011100eeff010203040506
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(payloadLen10Pkt),
@@ -867,7 +867,7 @@ class ApfFilterTest {
             01005e00000100112233445508004500001400010000400290e40a000002e00000011100eeff010203
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(payloadLen7Pkt),
@@ -884,7 +884,7 @@ class ApfFilterTest {
             01005e00000300112233445508004500001c000100000102cfda0a000002e00000031100eeff00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pktWithWrongDst),
@@ -900,7 +900,7 @@ class ApfFilterTest {
             01005e00000100112233445508004500001c000100000102cfdc0a000002e00000015100aeff00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pktWithWrongType),
@@ -912,7 +912,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV1ReportDropped() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv1 report packet:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
         //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
@@ -922,7 +922,7 @@ class ApfFilterTest {
             01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011200fefdef000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -934,7 +934,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV1GeneralQueryPassed() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv1 general query packet:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
@@ -944,7 +944,7 @@ class ApfFilterTest {
             01005e00000100112233445508004500001c000100000102cfdc0a000002e00000011100eeff00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -956,7 +956,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV2ReportDropped() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv2 report packet:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
         //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
@@ -966,7 +966,7 @@ class ApfFilterTest {
             01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011614fae9ef000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(v2ReportPkt),
@@ -982,7 +982,7 @@ class ApfFilterTest {
             01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011714f9e9ef000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(v2LeaveReportPkt),
@@ -994,7 +994,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV2GeneralQueryReplied() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv2 general query packet without router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
@@ -1004,7 +1004,7 @@ class ApfFilterTest {
             01005e00000100112233445508004500001c000100000102cfdc0a000002e00000011114eeeb00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1114,7 +1114,7 @@ class ApfFilterTest {
             """.replace("\\s+".toRegex(), "").trim().uppercase()
         )
 
-        val transmitPackets = apfTestHelpers.getAllTransmittedPackets()
+        val transmitPackets = ApfJniUtils.getAllTransmittedPackets()
             .map { HexDump.toHexString(it).uppercase() }.toSet()
         assertEquals(igmpv2ReportPkts, transmitPackets)
     }
@@ -1123,7 +1123,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV2GeneralQueryWithRouterAlertOptionReplied() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv2 general query packet with router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1', options=[IPOption_Router_Alert()])
@@ -1134,7 +1134,7 @@ class ApfFilterTest {
             00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1245,7 +1245,7 @@ class ApfFilterTest {
             """.replace("\\s+".toRegex(), "").trim().uppercase()
         )
 
-        val transmitPackets = apfTestHelpers.getAllTransmittedPackets()
+        val transmitPackets = ApfJniUtils.getAllTransmittedPackets()
             .map { HexDump.toHexString(it).uppercase() }.toSet()
         assertEquals(igmpv2ReportPkts, transmitPackets)
     }
@@ -1254,7 +1254,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV2GroupSpecificQueryPassed() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv2 group specific query packet without router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
         //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
@@ -1264,7 +1264,7 @@ class ApfFilterTest {
             01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011114ffe9ef000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1276,7 +1276,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV3ReportDropped() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv3 report packet without router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:16')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.22')
@@ -1287,7 +1287,7 @@ class ApfFilterTest {
             0102000000ef000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1299,7 +1299,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV3GeneralQueryReplied() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv3 general query packet without router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
@@ -1310,14 +1310,14 @@ class ApfFilterTest {
             00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
             DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED
         )
 
-        val transmittedIgmpv3Reports = apfTestHelpers.consumeTransmittedPackets(1)
+        val transmittedIgmpv3Reports = ApfTestHelpers.consumeTransmittedPackets(1)
 
         // ###[ Ethernet ]###
         //   dst       = 01:00:5e:00:00:16
@@ -1384,7 +1384,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV3GeneralQueryWithRouterAlertOptionReplied() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv3 general query packet with router alert option:
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
         //   ip = IP(src='10.0.0.2', dst='224.0.0.1', options=[IPOption_Router_Alert()])
@@ -1395,14 +1395,14 @@ class ApfFilterTest {
             000000000000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
             DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED
         )
 
-        val transmittedIgmpv3Reports = apfTestHelpers.consumeTransmittedPackets(1)
+        val transmittedIgmpv3Reports = ApfTestHelpers.consumeTransmittedPackets(1)
 
         // ###[ Ethernet ]###
         //   dst       = 01:00:5e:00:00:16
@@ -1469,7 +1469,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV3GroupSpecificQueryPassed() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv3 group specific query packet
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
         //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
@@ -1480,7 +1480,7 @@ class ApfFilterTest {
             00000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1492,7 +1492,7 @@ class ApfFilterTest {
     @Test
     fun testIgmpV3GroupAndSourceSpecificQueryPassed() {
         val apfFilter = getIgmpApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IGMPv3 group and source specific query packet
         //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
         //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
@@ -1503,7 +1503,7 @@ class ApfFilterTest {
             00000010a000001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1534,7 +1534,7 @@ class ApfFilterTest {
     @Test
     fun testIPv6PacketWithNonMldHopByHopPassed() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 general query with different HOPOPTS
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:11:11:11:11')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::1:1111:1111', hlim=1)
@@ -1547,7 +1547,7 @@ class ApfFilterTest {
             0000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidHopOptPkt),
@@ -1559,7 +1559,7 @@ class ApfFilterTest {
     @Test
     fun testInvalidMldPacketDropped() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 general query with invalid source addr
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:11:11:11:11')
         //  ipv6 = IPv6(src='ff02::1:4444:4444', dst='ff02::1:1111:1111', hlim=1)
@@ -1571,7 +1571,7 @@ class ApfFilterTest {
             00000000000000001111111113a000502000001008200adea2710000000000000000000000000000000
             000000
         """.replace("\\s+".toRegex(), "").trim().uppercase()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidSrcIpPkt),
@@ -1589,7 +1589,7 @@ class ApfFilterTest {
             00000000000000001111111113a000502000001008200813b2710000000000000000000000000000000
             000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidHopLimitPkt),
@@ -1607,7 +1607,7 @@ class ApfFilterTest {
             00000000000000000000000013a000502000001008200a35c2710000000000000000000000000000000
             000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1625,7 +1625,7 @@ class ApfFilterTest {
             000000000000000000000013a000502000001008200a35927100000000000000000000000000000000000
             00000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidPayloadLength27Pkt),
@@ -1637,7 +1637,7 @@ class ApfFilterTest {
     @Test
     fun testMldV1ReportDropped() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 report
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:11:11:11:11')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff12::1:1111:1111', hlim=1)
@@ -1650,7 +1650,7 @@ class ApfFilterTest {
             111111
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1662,7 +1662,7 @@ class ApfFilterTest {
     @Test
     fun testMldV1DoneDropped() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 done
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:02')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::2', hlim=1)
@@ -1674,7 +1674,7 @@ class ApfFilterTest {
             0000000000000000000000023a000502000001008400a73600000000ff12000000000000000000011111
             1111
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1686,7 +1686,7 @@ class ApfFilterTest {
     @Test
     fun testMldV2ReportDropped() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv2 report
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:16')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::16', hlim=1)
@@ -1698,7 +1698,7 @@ class ApfFilterTest {
             0000000000000000000000163a000502000001008f00982d0000000104000000ff020000000000000000
             000111111111
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1710,7 +1710,7 @@ class ApfFilterTest {
     @Test
     fun testMldV1GeneralQueryReplied() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 general query
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:01')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::1', hlim=1)
@@ -1722,7 +1722,7 @@ class ApfFilterTest {
             00000000000000000000000013a000502000001008200a35d2710000000000000000000000000000000
             000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1834,7 +1834,7 @@ class ApfFilterTest {
             """.replace("\\s+".toRegex(), "").trim().uppercase()
         )
 
-        val transmitPackets = apfTestHelpers.getAllTransmittedPackets()
+        val transmitPackets = ApfJniUtils.getAllTransmittedPackets()
             .map { HexDump.toHexString(it).uppercase() }.toSet()
         assertEquals(mldV1ReportPkts, transmitPackets)
     }
@@ -1843,7 +1843,7 @@ class ApfFilterTest {
     @Test
     fun testMldV2GeneralQueryReplied() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv2 general query
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:01')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::1', hlim=1)
@@ -1855,14 +1855,14 @@ class ApfFilterTest {
             00000000000000000000000013a000502000001008200a3592710000000000000000000000000000000
             00000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
             DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED
         )
 
-        val transmittedMldV2Reports = apfTestHelpers.consumeTransmittedPackets(1)
+        val transmittedMldV2Reports = ApfTestHelpers.consumeTransmittedPackets(1)
         //  ###[ Ethernet ]###
         //    dst       = 33:33:00:00:00:16
         //    src       = 02:03:04:05:06:07
@@ -1929,7 +1929,7 @@ class ApfFilterTest {
     @Test
     fun testMldV1GroupSpecificQueryPassed() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv1 group specific query
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:01')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::1:1111:1111', hlim=1)
@@ -1941,7 +1941,7 @@ class ApfFilterTest {
             0000000000000001111111113a000502000001008200601527100000ff02000000000000000000011111
             1111
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1953,7 +1953,7 @@ class ApfFilterTest {
     @Test
     fun testMldV2GroupSpecificQueryPassed() {
         val apfFilter = getMldApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate MLDv2 group specific query
         //  ether = Ether(src='00:11:22:33:44:55', dst='33:33:00:00:00:01')
         //  ipv6 = IPv6(src='fe80::fc01:83ff:fea6:3712', dst='ff02::1:1111:1111', hlim=1)
@@ -1965,7 +1965,7 @@ class ApfFilterTest {
             0000000000000001111111113a000502000001008200601127100000ff02000000000000000000011111
             111100000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(pkt),
@@ -1978,12 +1978,12 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.multicastFilter = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // Using scapy to generate DHCP4 offer packet:
         //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
@@ -2013,7 +2013,7 @@ class ApfFilterTest {
             0000000000000000000000000000000000000000000000000000638253633501023604c0
             a801010104ffffff000304c0a80101330400015180060408080808ff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(dhcp4Pkt),
@@ -2027,7 +2027,7 @@ class ApfFilterTest {
         val nonDhcpMcastPkt = """
             ffffffffffff001122334455080045000014000100004015d929c0a80101e0000001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpMcastPkt),
@@ -2041,7 +2041,7 @@ class ApfFilterTest {
         val nonDhcpBcastPkt = """
             ffffffffffff001122334455080045000014000100004015b92bc0a80101ffffffff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpBcastPkt),
@@ -2055,7 +2055,7 @@ class ApfFilterTest {
         val nonDhcpNetBcastPkt = """
             ffffffffffff001122334455080045000014000100004015ae2cc0a801010a0000ff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpNetBcastPkt),
@@ -2069,7 +2069,7 @@ class ApfFilterTest {
         val nonDhcpUcastPkt = """
             020304050607001122334455080045000014000100004015f780c0a80101c0a80102
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpUcastPkt),
@@ -2083,7 +2083,7 @@ class ApfFilterTest {
         val nonDhcpUcastL2BcastPkt = """
             ffffffffffff001122334455080045000014000100004015f780c0a80101c0a80102
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDhcpUcastL2BcastPkt),
@@ -2094,9 +2094,9 @@ class ApfFilterTest {
     @Test
     fun testArpFilterDropPktsOnV6OnlyNetwork() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         apfFilter.updateClatInterfaceState(true)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // Drop ARP request packet when clat is enabled
         // Using scapy to generate ARP request packet:
@@ -2106,7 +2106,7 @@ class ApfFilterTest {
         val arpPkt = """
             010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(arpPkt),
@@ -2137,9 +2137,9 @@ class ApfFilterTest {
         apfConfig.multicastFilter = true
         apfConfig.ieee802_3Filter = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         apfFilter.addTcpKeepalivePacketFilter(1, parcel)
-        var program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        var program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // Drop IPv4 keepalive ack
         // Using scapy to generate IPv4 TCP keepalive ack packet with seq + 1:
@@ -2151,7 +2151,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800010000400666c50a0000060a000005d4313039499602d2
             7e916116501020004b4f0000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(keepaliveAckPkt),
@@ -2168,7 +2168,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800010000400666c50a0000060a000005d431303949960336
             7e916115501020004aec0000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonKeepaliveAckPkt1),
@@ -2186,7 +2186,7 @@ class ApfFilterTest {
             01020304050600010203040508004500003200010000400666bb0a0000060a000005d4313039499602d27
             e91611650102000372c000000010203040506070809
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonKeepaliveAckPkt2),
@@ -2203,7 +2203,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800010000400666c40a0000070a0000055ba0ff987e91610c4
             2f697155010200066e60000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
@@ -2212,15 +2212,15 @@ class ApfFilterTest {
 
         // test IPv4 packets when TCP keepalive filter is removed
         apfFilter.removeKeepalivePacketFilter(1)
-        program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
-        apfTestHelpers.verifyProgramRun(
+        program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(keepaliveAckPkt),
             PASSED_IPV4_UNICAST
         )
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
@@ -2247,9 +2247,9 @@ class ApfFilterTest {
         apfConfig.multicastFilter = true
         apfConfig.ieee802_3Filter = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         apfFilter.addNattKeepalivePacketFilter(1, parcel)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // Drop IPv4 keepalive response packet
         // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xff:
@@ -2261,7 +2261,7 @@ class ApfFilterTest {
         val validNattPkt = """
             01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d73cff
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(validNattPkt),
@@ -2278,7 +2278,7 @@ class ApfFilterTest {
         val invalidNattPkt = """
             01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d83cfe
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidNattPkt),
@@ -2296,7 +2296,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002600010000401166bc0a0000060a000005119404000012c2120
             0010203040506070809
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonNattPkt),
@@ -2314,7 +2314,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002600010000401166bb0a0000070a000005119404000012c2110
             0010203040506070809
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(otherSrcNonNattPkt),
@@ -2325,7 +2325,7 @@ class ApfFilterTest {
     @Test
     fun testIPv4TcpPort7Filter() {
         val apfFilter = getApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
 
         // Drop IPv4 TCP port 7 packet
         // Using scapy to generate IPv4 TCP port 7 packet:
@@ -2337,7 +2337,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800010000400666c50a0000060a00000500140007000000000
             0000000500220007bbd0000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(tcpPort7Pkt),
@@ -2354,7 +2354,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800012000400646c50a0000060a00000500140050000000000
             0000000500220007b740000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(initialFragmentTcpPkt),
@@ -2371,7 +2371,7 @@ class ApfFilterTest {
             01020304050600010203040508004500002800012064400646610a0000060a00000500140050000000000
             0000000500220007b740000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(fragmentTcpPkt),
@@ -2384,14 +2384,14 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.multicastFilter = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val lp = LinkProperties()
         for (addr in hostIpv6Addresses) {
             lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
         }
         apfFilter.setLinkProperties(lp)
         apfFilter.setDozeMode(true)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // Using scapy to generate non ICMPv6 sent to ff00::/8 (multicast prefix) packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
         // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff00::1", nh=59)
@@ -2400,7 +2400,7 @@ class ApfFilterTest {
             ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a11223344ff00000
             0000000000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonIcmpv6McastPkt),
@@ -2416,7 +2416,7 @@ class ApfFilterTest {
             02030405060700010203040586dd6000000000083aff20010000000000000200001a11223344ff00000
             000000000000000000000000180001a3a00000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(icmpv6EchoPkt),
@@ -2427,13 +2427,13 @@ class ApfFilterTest {
     @Test
     fun testIPv6PacketFilter() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val lp = LinkProperties()
         for (addr in hostIpv6Addresses) {
             lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
         }
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         // Using scapy to generate non ICMPv6 packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
         // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", nh=59)
@@ -2442,7 +2442,7 @@ class ApfFilterTest {
             ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a112233442001000
             0000000000200001a33441122
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonIcmpv6Pkt),
@@ -2458,7 +2458,7 @@ class ApfFilterTest {
             01020304050600010203040586dd6000000000183aff20010000000000000200001a11223344ff02000
             000000000000000000000000188007227a000000000000000000000000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(icmpv6McastNaPkt),
@@ -2473,7 +2473,7 @@ class ApfFilterTest {
             01020304050600010203040586dd600000000000004020010000000000000200001a112233442001000
             0000000000200001a33441122
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(ipv6WithHopByHopOptionPkt),
@@ -2484,13 +2484,13 @@ class ApfFilterTest {
     @Test
     fun testRaFilterIgnoreReservedFieldInRdnssOption() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val lp = LinkProperties()
         for (addr in hostIpv6Addresses) {
             lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
         }
         apfFilter.setLinkProperties(lp)
-        var program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        var program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         val ra1 = """
             33330000000100c0babecafe86dd6e00000000783afffe800000000000002a0079e12e003f01ff0
             200000000000000000000000000018600571140000e100000000000000000010100c0babecafe05
@@ -2501,9 +2501,9 @@ class ApfFilterTest {
         val ra1Bytes = HexDump.hexStringToByteArray(ra1)
         Os.write(raWriterSocket, ra1Bytes, 0, ra1Bytes.size)
 
-        program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             ra1Bytes,
@@ -2518,7 +2518,7 @@ class ApfFilterTest {
             2a0079e12e003f010000000000000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(ra2),
@@ -2529,7 +2529,7 @@ class ApfFilterTest {
     @Test
     fun testArpFilterDropPktsNoIPv4() {
         val apfFilter = getApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
 
         // Drop ARP request packet with invalid hw type
         // Using scapy to generate ARP request packet with invalid hw type :
@@ -2539,7 +2539,7 @@ class ApfFilterTest {
         val invalidHwTypePkt = """
             01020304050600010203040508060003080000040001c0a8012200000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidHwTypePkt),
@@ -2554,7 +2554,7 @@ class ApfFilterTest {
         val invalidProtoTypePkt = """
             010203040506000102030405080600010014060000015c857e3c74e1000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidProtoTypePkt),
@@ -2571,7 +2571,7 @@ class ApfFilterTest {
             0000000000000000c0a8012200000000000000000000000000000000000000000000
             0000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidHwLenPkt),
@@ -2588,7 +2588,7 @@ class ApfFilterTest {
             00000000000000000000000000000000000000000000000000000000000000000000
             000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidProtoLenPkt),
@@ -2603,7 +2603,7 @@ class ApfFilterTest {
         val invalidOpPkt = """
             010203040506000102030405080600010800060400055c857e3c74e1c0a8012200000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(invalidOpPkt),
@@ -2618,7 +2618,7 @@ class ApfFilterTest {
         val noHostArpReplyPkt = """
             010203040506000102030405080600010800060400025c857e3c74e10000000000000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(noHostArpReplyPkt),
@@ -2633,7 +2633,7 @@ class ApfFilterTest {
         val garpReplyPkt = """
             ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(garpReplyPkt),
@@ -2644,7 +2644,7 @@ class ApfFilterTest {
     @Test
     fun testArpFilterPassPktsNoIPv4() {
         val apfFilter = getApfFilter()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // Pass non-broadcast ARP reply packet
         // Using scapy to generate unicast ARP reply packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
@@ -2653,7 +2653,7 @@ class ApfFilterTest {
         val nonBcastArpReplyPkt = """
             010203040506000102030405080600010800060400025c857e3c74e10102030400000000000000000000
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(nonBcastArpReplyPkt),
@@ -2668,7 +2668,7 @@ class ApfFilterTest {
         val arpRequestPkt = """
             ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(arpRequestPkt),
@@ -2679,12 +2679,12 @@ class ApfFilterTest {
     @Test
     fun testArpFilterDropPktsWithIPv4() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         // Drop ARP reply packet is not for the device
         // Using scapy to generate ARP reply packet not for the device:
         // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
@@ -2693,7 +2693,7 @@ class ApfFilterTest {
         val otherHostArpReplyPkt = """
             ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000001020304
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(otherHostArpReplyPkt),
@@ -2708,7 +2708,7 @@ class ApfFilterTest {
         val otherHostArpRequestPkt = """
             ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(otherHostArpRequestPkt),
@@ -2719,12 +2719,12 @@ class ApfFilterTest {
     @Test
     fun testArpFilterPassPktsWithIPv4() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // Using scapy to generate ARP broadcast reply packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
@@ -2733,7 +2733,7 @@ class ApfFilterTest {
         val bcastArpReplyPkt = """
             ffffffffffff000102030405080600010800060400025c857e3c74e1c0a801220000000000000a000001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(bcastArpReplyPkt),
@@ -2746,12 +2746,12 @@ class ApfFilterTest {
     @Test
     fun testArpTransmit() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         val receivedArpPacketBuf = ArpPacket.buildArpPacket(
             arpBroadcastMacAddress,
             senderMacAddress,
@@ -2762,14 +2762,14 @@ class ApfFilterTest {
         )
         val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
         receivedArpPacketBuf.get(receivedArpPacket)
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             receivedArpPacket,
             DROPPED_ARP_REQUEST_REPLIED
         )
 
-        val transmittedPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        val transmittedPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         val expectedArpReplyBuf = ArpPacket.buildArpPacket(
             senderMacAddress,
             apfFilter.mHardwareAddress,
@@ -2791,12 +2791,12 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.handleArpOffload = false
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         val receivedArpPacketBuf = ArpPacket.buildArpPacket(
             arpBroadcastMacAddress,
             senderMacAddress,
@@ -2807,7 +2807,7 @@ class ApfFilterTest {
         )
         val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
         receivedArpPacketBuf.get(receivedArpPacket)
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             receivedArpPacket,
@@ -2821,7 +2821,7 @@ class ApfFilterTest {
         doReturn(listOf<ByteArray>()).`when`(dependencies).getAnycast6Addresses(any())
         val apfFilter = getApfFilter()
         // validate NS packet check when there is no IPv6 address
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // Using scapy to generate IPv6 NS packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
         // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
@@ -2833,7 +2833,7 @@ class ApfFilterTest {
             00000020010000000000000200001A33441122
         """.replace("\\s+".toRegex(), "").trim()
         // when there is no IPv6 addresses -> pass NS packet
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nsPkt),
@@ -2845,7 +2845,7 @@ class ApfFilterTest {
     @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
     fun testNsFilter() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val lp = LinkProperties()
         for (addr in hostIpv6Addresses) {
             lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
@@ -2863,9 +2863,9 @@ class ApfFilterTest {
         }
 
         apfFilter.setLinkProperties(lp)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         apfFilter.updateClatInterfaceState(true)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // validate Ethernet dst address check
         // Using scapy to generate IPv6 NS packet:
@@ -2880,7 +2880,7 @@ class ApfFilterTest {
             000020010000000000000200001A334411220201000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // invalid unicast ether dst -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonHostDstMacNsPkt),
@@ -2899,7 +2899,7 @@ class ApfFilterTest {
             0000000020010000000000000200001A334411220201000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // mcast dst mac is not one of solicited mcast mac derived from one of device's ip -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonMcastDstMacNsPkt),
@@ -2919,7 +2919,7 @@ class ApfFilterTest {
         """.replace("\\s+".toRegex(), "").trim()
         // mcast dst mac is one of solicited mcast mac derived from one of device's ip
         // -> drop and replied
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(hostMcastDstMacNsPkt),
@@ -2938,7 +2938,7 @@ class ApfFilterTest {
             00000000000200001A334411220101000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // mcast dst mac is broadcast address -> drop and replied
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(broadcastNsPkt),
@@ -2959,7 +2959,7 @@ class ApfFilterTest {
             00000020010000000000000200001A334411220101000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // dst ip is one of device's ip -> drop and replied
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(validHostDstIpNsPkt),
@@ -2979,7 +2979,7 @@ class ApfFilterTest {
             0101000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // dst ip is device's anycast address -> drop and replied
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(validHostAnycastDstIpNsPkt),
@@ -2998,7 +2998,7 @@ class ApfFilterTest {
             E30000000020010000000000000200001A334411220101000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // unicast dst ip is not one of device's ip -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonHostUcastDstIpNsPkt),
@@ -3017,7 +3017,7 @@ class ApfFilterTest {
             1C0000000020010000000000000200001A334411220101000102030405
         """.replace("\\s+".toRegex(), "").trim()
         // mcast dst ip is not one of solicited mcast ip derived from one of device's ip -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonHostMcastDstIpNsPkt),
@@ -3036,7 +3036,7 @@ class ApfFilterTest {
                     "000020010000000000000200001A334411220101000102030405"
         // mcast dst ip is one of solicited mcast ip derived from one of device's ip
         //   -> drop and replied
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
@@ -3057,7 +3057,7 @@ class ApfFilterTest {
             000200001A334411220101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // payload len < 24 -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(shortNsPkt),
@@ -3076,7 +3076,7 @@ class ApfFilterTest {
             00000000000200001A444455550101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // target ip is not one of device's ip -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(otherHostNsPkt),
@@ -3095,7 +3095,7 @@ class ApfFilterTest {
             00000020010000000000000200001A334411220101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // hoplimit is not 255 -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidHoplimitNsPkt),
@@ -3114,7 +3114,7 @@ class ApfFilterTest {
             00000020010000000000000200001A334411220101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // icmp6 code is not 0 -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidIcmpCodeNsPkt),
@@ -3133,7 +3133,7 @@ class ApfFilterTest {
             16CE0000000020010000000000000200001A123456780101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // target ip is one of tentative address -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tentativeTargetIpNsPkt),
@@ -3152,7 +3152,7 @@ class ApfFilterTest {
             00000020010000000000000200001C225566660101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // target ip is none of {non-tentative, anycast} -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(invalidTargetIpNsPkt),
@@ -3171,7 +3171,7 @@ class ApfFilterTest {
             00001A334411220201020304050607
         """.replace("\\s+".toRegex(), "").trim()
         // DAD NS request -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(dadNsPkt),
@@ -3189,7 +3189,7 @@ class ApfFilterTest {
             000000000200001A33441122
         """.replace("\\s+".toRegex(), "").trim()
         // payload len < 32 -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(noOptionNsPkt),
@@ -3208,7 +3208,7 @@ class ApfFilterTest {
             000020010000000000000200001A334411220101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // non-DAD src IPv6 is FF::/8 -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDadMcastSrcIpPkt),
@@ -3227,7 +3227,7 @@ class ApfFilterTest {
             140000000020010000000000000200001A334411220101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // non-DAD src IPv6 is 00::/8 -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(nonDadLoopbackSrcIpPkt),
@@ -3248,7 +3248,7 @@ class ApfFilterTest {
             05060101010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // non-DAD with multiple options, SLLA in 2nd option -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(sllaNotFirstOptionNsPkt),
@@ -3267,7 +3267,7 @@ class ApfFilterTest {
             20010000000000000200001A334411220201010203040506
         """.replace("\\s+".toRegex(), "").trim()
         // non-DAD with one option but not SLLA -> pass
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(noSllaOptionNsPkt),
@@ -3287,7 +3287,7 @@ class ApfFilterTest {
             0506
         """.replace("\\s+".toRegex(), "").trim()
         // non-DAD, SLLA is multicast MAC -> drop
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(mcastMacSllaOptionNsPkt),
@@ -3306,7 +3306,7 @@ class ApfFilterTest {
         }
 
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
         val expectPackets = mutableListOf<ByteArray>()
         for (addr in validIpv6Addresses) {
@@ -3319,7 +3319,7 @@ class ApfFilterTest {
                 addr
             )
 
-            apfTestHelpers.verifyProgramRun(
+            ApfTestHelpers.verifyProgramRun(
                 apfFilter.mApfVersionSupported,
                 program,
                 receivedUcastNsPacket,
@@ -3351,7 +3351,7 @@ class ApfFilterTest {
                 addr
             )
 
-            apfTestHelpers.verifyProgramRun(
+            ApfTestHelpers.verifyProgramRun(
                 apfFilter.mApfVersionSupported,
                 program,
                 receivedMcastNsPacket,
@@ -3369,7 +3369,7 @@ class ApfFilterTest {
             expectPackets.add(expectedMcastNaPacket)
         }
 
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(expectPackets.size)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(expectPackets.size)
         for (i in transmitPackets.indices) {
             assertContentEquals(expectPackets[i], transmitPackets[i])
         }
@@ -3387,7 +3387,7 @@ class ApfFilterTest {
             lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
         }
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         // Using scapy to generate IPv6 NS packet:
         // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
         // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255, tc=20)
@@ -3399,14 +3399,14 @@ class ApfFilterTest {
             0200001A11223344FF0200000000000000000001FF4411228700952D0000
             000020010000000000000200001A334411220101000102030405
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
             DROPPED_IPV6_NS_REPLIED_NON_DAD
         )
 
-        val transmitPkts = apfTestHelpers.consumeTransmittedPackets(1)
+        val transmitPkts = ApfTestHelpers.consumeTransmittedPackets(1)
         // Using scapy to generate IPv6 NA packet:
         // eth = Ether(src="02:03:04:05:06:07", dst="00:01:02:03:04:05")
         // ip6 = IPv6(src="2001::200:1a:3344:1122", dst="2001::200:1a:1122:3344", hlim=255, tc=20)
@@ -3435,7 +3435,7 @@ class ApfFilterTest {
         }
 
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
         for (addr in validIpv6Addresses) {
             // unicast solicited NS request
@@ -3447,7 +3447,7 @@ class ApfFilterTest {
                 addr
             )
 
-            apfTestHelpers.verifyProgramRun(
+            ApfTestHelpers.verifyProgramRun(
                 apfFilter.mApfVersionSupported,
                 program,
                 receivedUcastNsPacket,
@@ -3469,7 +3469,7 @@ class ApfFilterTest {
                 addr
             )
 
-            apfTestHelpers.verifyProgramRun(
+            ApfTestHelpers.verifyProgramRun(
                 apfFilter.mApfVersionSupported,
                 program,
                 receivedMcastNsPacket,
@@ -3486,15 +3486,15 @@ class ApfFilterTest {
         apfConfig.multicastFilter = enableMultiCastFilter
         apfConfig.handleIpv6PingOffload = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         if (inDozeMode) {
             apfFilter.setDozeMode(inDozeMode)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         }
         val lp = LinkProperties()
         lp.addLinkAddress(LinkAddress(hostLinkLocalIpv6Address, 64))
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         return Pair(apfFilter, program)
     }
 
@@ -3514,13 +3514,13 @@ class ApfFilterTest {
             656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv6EchoRequestPkt),
             DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED
         )
-        val transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        val transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //  dst       = 01:02:03:04:05:06
@@ -3569,13 +3569,13 @@ class ApfFilterTest {
             656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv6EchoRequestPkt),
             DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED
         )
-        val transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        val transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //  dst       = 01:02:03:04:05:06
@@ -3623,7 +3623,7 @@ class ApfFilterTest {
             0000000000001fe8000000000000000000000000000038000823b000100
         """.replace("\\s+".toRegex(), "").trim()
 
-         apfTestHelpers.verifyProgramRun(
+         ApfTestHelpers.verifyProgramRun(
              apfFilter.mApfVersionSupported,
              program,
              HexDump.hexStringToByteArray(ipv6EchoRequestPkt),
@@ -3646,7 +3646,7 @@ class ApfFilterTest {
             656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv6EchoRequestPkt),
@@ -3668,7 +3668,7 @@ class ApfFilterTest {
             0000000000001fe8000000000000000000000000000038100813b0001007b
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv6EchoReplyPkt),
@@ -3683,12 +3683,12 @@ class ApfFilterTest {
         apfConfig.multicastFilter = enableMultiCastFilter
         apfConfig.handleIpv4PingOffload = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         val lp = LinkProperties()
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         return Pair(apfFilter, program)
     }
 
@@ -3707,14 +3707,14 @@ class ApfFilterTest {
             000010800b3b10001007b68656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
             DROPPED_IPV4_PING_REQUEST_REPLIED
         )
 
-        val transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        val transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //   dst       = 01:02:03:04:05:06
@@ -3766,7 +3766,7 @@ class ApfFilterTest {
             0000168656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
@@ -3788,7 +3788,7 @@ class ApfFilterTest {
             00001940400000800b3b10001007b68656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
@@ -3810,7 +3810,7 @@ class ApfFilterTest {
             0006f0800b3b10001007b68656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
@@ -3832,7 +3832,7 @@ class ApfFilterTest {
             000ff0800b3b10001007b68656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
@@ -3854,7 +3854,7 @@ class ApfFilterTest {
             000010000bbb10001007b68656c6c6f
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ipv4EchoReplyPkt),
@@ -3868,7 +3868,7 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.handleMdnsOffload = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
         verify(nsdManager).registerOffloadEngine(
             eq(ifParams.name),
@@ -3894,7 +3894,7 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.handleMdnsOffload = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
         verify(nsdManager).registerOffloadEngine(
             eq(ifParams.name),
@@ -3907,7 +3907,7 @@ class ApfFilterTest {
         visibleOnHandlerThread(handler) {
             offloadEngine.onOffloadServiceUpdated(castOffloadInfo.value)
         }
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         val corruptedOffloadInfo = OffloadServiceInfo(
             OffloadServiceInfo.Key("gambit", "_${"a".repeat(63)}._tcp"),
             listOf(),
@@ -3945,7 +3945,7 @@ class ApfFilterTest {
             apfConfig.multicastFilter = true
         }
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
         verify(localNsdManager).registerOffloadEngine(
             eq(ifParams.name),
@@ -3958,7 +3958,7 @@ class ApfFilterTest {
         val lp = LinkProperties()
         if (v6Only) {
             apfFilter.updateClatInterfaceState(true)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         } else {
             val ipv4LinkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
             lp.addLinkAddress(ipv4LinkAddress)
@@ -3966,13 +3966,13 @@ class ApfFilterTest {
         val ipv6LinkAddress = LinkAddress(hostLinkLocalIpv6Address, 64)
         lp.addLinkAddress(ipv6LinkAddress)
         apfFilter.setLinkProperties(lp)
-        var program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        var program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         if (addedOffloadInfos.isNotEmpty()) {
             visibleOnHandlerThread(handler) {
                 addedOffloadInfos.forEach { offloadEngine.onOffloadServiceUpdated(it.value) }
             }
-            program = apfTestHelpers.consumeInstalledProgram(
+            program = ApfTestHelpers.consumeInstalledProgram(
                 apfController,
                 installCnt = addedOffloadInfos.size
             )
@@ -3981,7 +3981,7 @@ class ApfFilterTest {
             visibleOnHandlerThread(handler) {
                 removedOffloadInfos.forEach { offloadEngine.onOffloadServiceRemoved(it.value) }
             }
-            program = apfTestHelpers.consumeInstalledProgram(
+            program = ApfTestHelpers.consumeInstalledProgram(
                 apfController,
                 installCnt = removedOffloadInfos.size
             )
@@ -4005,14 +4005,14 @@ class ApfFilterTest {
             617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        var transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        var transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //   dst       = 01:00:5e:00:00:fb
@@ -4159,14 +4159,14 @@ class ApfFilterTest {
             6563617374c01500100001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsTxtQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         assertContentEquals(
             HexDump.hexStringToByteArray(expectedIPv4CastMdnsReply),
@@ -4191,14 +4191,14 @@ class ApfFilterTest {
             6563617374c01500210001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsSRVQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         assertContentEquals(
             HexDump.hexStringToByteArray(expectedIPv4CastMdnsReply),
@@ -4217,14 +4217,14 @@ class ApfFilterTest {
             747672656d6f746532045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //  dst       = 01:00:5e:00:00:fb
@@ -4366,7 +4366,7 @@ class ApfFilterTest {
             045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(airplayIPv4MdnsPtrQuery),
@@ -4385,7 +4385,7 @@ class ApfFilterTest {
             747672656d6f746532045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQuery),
@@ -4409,7 +4409,7 @@ class ApfFilterTest {
             676c6563617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQueryWithOption),
@@ -4433,7 +4433,7 @@ class ApfFilterTest {
             617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQuery),
@@ -4459,7 +4459,7 @@ class ApfFilterTest {
             6f63616c00
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrAnswer),
@@ -4482,14 +4482,14 @@ class ApfFilterTest {
             3616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv6MdnsPtrQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        var transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        var transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         //  dst       = 33:33:00:00:00:fb
@@ -4632,14 +4632,14 @@ class ApfFilterTest {
             336432383930313363633061650b5f676f6f676c6563617374c01500100001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv6MdnsTxtQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         assertContentEquals(
             HexDump.hexStringToByteArray(expectedIPv6CastMdnsReply),
@@ -4659,14 +4659,14 @@ class ApfFilterTest {
             46370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrQuery),
             DROPPED_MDNS_REPLIED
         )
 
-        transmitPkt = apfTestHelpers.consumeTransmittedPackets(1)[0]
+        transmitPkt = ApfTestHelpers.consumeTransmittedPackets(1)[0]
 
         // ###[ Ethernet ]###
         // dst       = 33:33:00:00:00:fb
@@ -4805,7 +4805,7 @@ class ApfFilterTest {
             0000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(airplayIPv6MdnsPtrQuery),
@@ -4825,7 +4825,7 @@ class ApfFilterTest {
             46370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrQuery),
@@ -4851,7 +4851,7 @@ class ApfFilterTest {
             726f6964747672656d6f746532045f746370056c6f63616c00
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrAnswer),
@@ -4927,8 +4927,8 @@ class ApfFilterTest {
         val raBytes = HexDump.hexStringToByteArray(ra)
         Os.write(raWriterSocket, raBytes, 0, raBytes.size)
 
-        program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
-        apfTestHelpers.verifyProgramRun(
+        program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             raBytes,
@@ -4951,7 +4951,7 @@ class ApfFilterTest {
             000fb14e914e900319b020000010000010000000000000c5f74657374737562
             74797065045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(typePtrQuery),
@@ -4969,7 +4969,7 @@ class ApfFilterTest {
             000fb14e914e9003b1b3f0000010000010000000000000473756231045f7375
             620c5f7465737473756274797065045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(subTypePtrQuery),
@@ -5065,14 +5065,14 @@ class ApfFilterTest {
         val raBytes = HexDump.hexStringToByteArray(ra)
         Os.write(raWriterSocket, raBytes, 0, raBytes.size)
 
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         assertThat(program.size).isLessThan(apfRam + 1)
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             raBytes,
-            PASSED_IPV6_ICMP
+            PASSED_RA
         )
     }
 
@@ -5101,7 +5101,7 @@ class ApfFilterTest {
             617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQueryForOffload),
@@ -5120,7 +5120,7 @@ class ApfFilterTest {
             747672656d6f746532045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQueryForOffload),
@@ -5138,7 +5138,7 @@ class ApfFilterTest {
             000fb14e914e9003b1b3f0000010000010000000000000473756231045f7375
             620c5f7465737473756274797065045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(subTypePtrQueryForPassthrough),
@@ -5182,7 +5182,7 @@ class ApfFilterTest {
             617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQueryForOffload),
@@ -5201,7 +5201,7 @@ class ApfFilterTest {
             747672656d6f746532045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQueryForPassthrough),
@@ -5219,7 +5219,7 @@ class ApfFilterTest {
             000fb14e914e9003b1b3f0000010000010000000000000473756231045f7375
             620c5f7465737473756274797065045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(subTypePtrQueryForPassthrough),
@@ -5258,7 +5258,7 @@ class ApfFilterTest {
             617374045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(castIPv4MdnsPtrQueryForPassthrough),
@@ -5277,7 +5277,7 @@ class ApfFilterTest {
             747672656d6f746532045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQueryForPassthrough),
@@ -5295,7 +5295,7 @@ class ApfFilterTest {
             000fb14e914e9003b1b3f0000010000010000000000000473756231045f7375
             620c5f7465737473756274797065045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(subTypePtrQueryForPassthrough),
@@ -5314,7 +5314,7 @@ class ApfFilterTest {
             045f746370056c6f63616c00000c0001
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(airplayIPv4MdnsPtrQueryForPassthrough),
@@ -5325,13 +5325,13 @@ class ApfFilterTest {
     @Test
     fun testApfProgramUpdate() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // add IPv4 address, expect to have apf program update
         val lp = LinkProperties()
         val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
         lp.addLinkAddress(linkAddress)
         apfFilter.setLinkProperties(lp)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // add the same IPv4 address, expect to have no apf program update
         apfFilter.setLinkProperties(lp)
@@ -5343,7 +5343,7 @@ class ApfFilterTest {
         }
 
         apfFilter.setLinkProperties(lp)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // add the same IPv6 addresses, expect to have no apf program update
         apfFilter.setLinkProperties(lp)
@@ -5362,7 +5362,7 @@ class ApfFilterTest {
         }
 
         apfFilter.setLinkProperties(lp)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         // add the same IPv6 addresses, expect to have no apf program update
         apfFilter.setLinkProperties(lp)
@@ -5380,13 +5380,13 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.handleIgmpOffload = true
         val apfFilter = getApfFilter(apfConfig)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         val addr = InetAddress.getByName("239.0.0.1") as Inet4Address
         mcastAddrs.add(addr)
         doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
         val testPacket = HexDump.hexStringToByteArray("000000")
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
         Thread.sleep(NO_CALLBACK_TIMEOUT_MS)
@@ -5395,7 +5395,7 @@ class ApfFilterTest {
         mcastAddrs.remove(addr)
         doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
     }
 
     @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@@ -5413,18 +5413,18 @@ class ApfFilterTest {
         val lp = LinkProperties()
         lp.addLinkAddress(ipv6LinkAddress)
         apfFilter.setLinkProperties(lp)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 3)
         val addr = InetAddress.getByName("ff0e::1") as Inet6Address
         mcastAddrs.add(addr)
         updateIPv6MulticastAddrs(apfFilter, mcastAddrs)
         val testPacket = HexDump.hexStringToByteArray("000000")
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         var solicitedNodeMcastAddr = InetAddress.getByName("ff02::1:ff12:3456") as Inet6Address
         mcastAddrs.add(solicitedNodeMcastAddr)
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
         Thread.sleep(NO_CALLBACK_TIMEOUT_MS)
@@ -5433,7 +5433,7 @@ class ApfFilterTest {
         mcastAddrs.remove(addr)
         updateIPv6MulticastAddrs(apfFilter, mcastAddrs)
         Os.write(mcastWriteSocket, testPacket, 0, testPacket.size)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
     }
 
     @Test
@@ -5449,9 +5449,9 @@ class ApfFilterTest {
     @Test
     fun testApfFilterResumeWillCleanUpTheApfMemoryRegion() {
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         apfFilter.resume()
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         assertContentEquals(ByteArray(4096) { 0 }, program)
     }
 
@@ -5467,7 +5467,7 @@ class ApfFilterTest {
         )
         doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
         val apfFilter = getApfFilter()
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
         assertEquals(mcastAddrsExcludeAllHost.toSet(), apfFilter.mIPv4McastAddrsExcludeAllHost)
 
@@ -5475,7 +5475,7 @@ class ApfFilterTest {
         mcastAddrs.add(addr)
         mcastAddrsExcludeAllHost.add(addr)
         updateIPv4MulticastAddrs(apfFilter, mcastAddrs)
-        apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+        ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
         assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
         assertEquals(mcastAddrsExcludeAllHost.toSet(), apfFilter.mIPv4McastAddrsExcludeAllHost)
 
@@ -5488,7 +5488,7 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.apfRamSize = 512
         val apfFilter = getApfFilter(apfConfig)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         assertContentEquals(
             ByteArray(apfConfig.apfRamSize - ApfCounterTracker.Counter.totalSize()) { 0 },
             program
@@ -5499,15 +5499,14 @@ class ApfFilterTest {
     @Test
     fun testCreateEgressReportReaderSocket() {
         var apfFilter = getApfFilter()
-        verify(dependencies, never()).createEgressIgmpReportsReaderSocket(anyInt())
         verify(dependencies, never()).createEgressMulticastReportsReaderSocket(anyInt())
         clearInvocations(dependencies)
 
         val apfConfig = getDefaultConfig()
+        apfConfig.handleIgmpOffload = false
         apfConfig.handleMldOffload = true
         apfFilter = getApfFilter(apfConfig)
 
-        verify(dependencies, never()).createEgressIgmpReportsReaderSocket(anyInt())
         verify(dependencies, times(1)).createEgressMulticastReportsReaderSocket(anyInt())
         clearInvocations(dependencies)
 
@@ -5515,15 +5514,15 @@ class ApfFilterTest {
         apfConfig.handleMldOffload = false
         apfFilter = getApfFilter(apfConfig)
 
-        verify(dependencies, never()).createEgressMulticastReportsReaderSocket(anyInt())
-        verify(dependencies, times(1)).createEgressIgmpReportsReaderSocket(anyInt())
+        verify(dependencies, times(1)).createEgressMulticastReportsReaderSocket(anyInt())
         clearInvocations(dependencies)
 
         apfConfig.handleIgmpOffload = true
         apfConfig.handleMldOffload = true
         apfFilter = getApfFilter(apfConfig)
-        verify(dependencies, never()).createEgressIgmpReportsReaderSocket(anyInt())
+
         verify(dependencies, times(1)).createEgressMulticastReportsReaderSocket(anyInt())
+        clearInvocations(dependencies)
     }
 
     fun getProgramWithAllFeatureEnabled(
@@ -5568,7 +5567,7 @@ class ApfFilterTest {
             apfConfig.handleIpv6PingOffload = true
             apfConfig.handleMdnsOffload = true
             val apfFilter = getApfFilter(apfConfig)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
 
             val srcAddr = byteArrayOf(10, 0, 0, 5)
             val dstAddr = byteArrayOf(10, 0, 0, 6)
@@ -5580,7 +5579,7 @@ class ApfFilterTest {
             parcel.dstAddress = InetAddress.getByAddress(dstAddr).address
             parcel.dstPort = dstPort
             apfFilter.addNattKeepalivePacketFilter(1, parcel)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
             verify(localNsdManager).registerOffloadEngine(
@@ -5601,7 +5600,7 @@ class ApfFilterTest {
                 lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
             }
             apfFilter.setLinkProperties(lp)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             visibleOnHandlerThread(handler) {
                 offloadEngine.onOffloadServiceUpdated(castOffloadInfo.value)
@@ -5610,35 +5609,31 @@ class ApfFilterTest {
                 offloadEngine.onOffloadServiceUpdated(raopOffloadInfo.value)
             }
 
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 4)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 4)
 
-            val ra1 = """
-                333300000001f434f06452fe86dd60010c0000503afffe800000000000001cb6b5bc353b7cfdff0
-                2000000000000000000000000000186000fab000000000000000000000000030440c00000070800
-                00070800000000fdeed0c47546534400000000000000001802400000000708fd0c8be643ee00001
-                a018000000000000101f434f06452fe
-            """.replace("\\s+".toRegex(), "").trim()
-            val ra1Bytes = HexDump.hexStringToByteArray(ra1)
+            val ra1Bytes = run {
+                val eth = EtherPkt(src = "f4:34:f0:64:52:fe", dst = "33:33:00:00:00:01")
+                val ip6 = Ip6Pkt(src = "fe80::1cb6:b5bc:353b:7cfd", dst = "ff02::1")
+                val ra = RaPkt(lft = 0)
+                ra.addPioOption("fdee:d0c4:7546::/64", valid = 1800, preferred = 1800, flags = "la")
+                ra.addRioOption(prefix = "fd0c:8be6:43ee::/64")
+                ra.addSllaOption("f4:34:f0:64:52:fe")
+                (eth / ip6 / ra).build()
+            }
             Os.write(localRaWriterSocket, ra1Bytes, 0, ra1Bytes.size)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
-
-            // Using scapy to generate packet:
-            // eth = Ether(src="E8:9F:80:66:60:BC", dst="f2:9c:70:2c:39:5a")
-            // ip6 = IPv6(src="fe80::2", dst="ff02::1")
-            // icmpra = ICMPv6ND_RA(routerlifetime=360, retranstimer=360)
-            // pio1 = ICMPv6NDOptPrefixInfo(prefixlen=64, prefix="2002:db8::")
-            // rio = ICMPv6NDOptRouteInfo(prefix="2002:db8:cafe::")
-            // ra = eth/ip6/icmpra/pio1/rio
-            val ra2 = """
-                f29c702c395ae89f806660bc86dd6000000000483afffe800000000000000000000000000002ff0
-                200000000000000000000000000018600f6e3000801680000000000000168030440c0ffffffffff
-                ffffff0000000020020db800000000000000000000000018030000ffffffff20020db8cafe00000
-                000000000000000
-            """.replace("\\s+".toRegex(), "").trim()
-            val ra2Bytes = HexDump.hexStringToByteArray(ra2)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+
+            val ra2Bytes = run {
+                val eth = EtherPkt(src = "e8:9f:80:66:60:bc", dst = "f2:9c:70:2c:39:5a")
+                val ip6 = Ip6Pkt(src = "fe80::2", dst = "ff02::1")
+                val ra = RaPkt(lft = 360, retransTimer = 360)
+                        .addPioOption(prefix = "2002:db8::/64", flags = "LA")
+                        .addRioOption(prefix = "2002:db8:cafe::/48")
+                (eth / ip6 / ra).build()
+            }
             val beforeNs = SystemClock.elapsedRealtimeNanos()
             Os.write(localRaWriterSocket, ra2Bytes, 0, ra2Bytes.size)
-            program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
             val afterNs = SystemClock.elapsedRealtimeNanos()
             generationTime = (afterNs - beforeNs) / 1000000
         } cleanup {
@@ -5720,11 +5715,11 @@ class ApfFilterTest {
             apfConfig.handleMdnsOffload = false
             val apfFilter = getApfFilter(apfConfig)
             if (apfVersion > 2) {
-                apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+                ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
             } else {
                 // If the APF version is less than 3, only one program will be installed because
                 // APFv2 lacks counter support, and therefore, counter region cleanup is unnecessary
-                apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+                ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
             }
 
             val lp = LinkProperties()
@@ -5736,7 +5731,7 @@ class ApfFilterTest {
                 lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
             }
             apfFilter.setLinkProperties(lp)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             val ra1 = """
                  333300000001f434f06452fe86dd60010c0000503afffe800000000000001cb6b5bc353b7cfdff0
@@ -5746,7 +5741,7 @@ class ApfFilterTest {
              """.replace("\\s+".toRegex(), "").trim()
             val ra1Bytes = HexDump.hexStringToByteArray(ra1)
             Os.write(localRaWriterSocket, ra1Bytes, 0, ra1Bytes.size)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             // Using scapy to generate packet:
             // eth = Ether(src="E8:9F:80:66:60:BC", dst="f2:9c:70:2c:39:5a")
@@ -5764,7 +5759,7 @@ class ApfFilterTest {
             val ra2Bytes = HexDump.hexStringToByteArray(ra2)
             val beforeNs = SystemClock.elapsedRealtimeNanos()
             Os.write(localRaWriterSocket, ra2Bytes, 0, ra2Bytes.size)
-            program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
             val afterNs = SystemClock.elapsedRealtimeNanos()
             generationTime = (afterNs - beforeNs) / 1000000
         } cleanup {
@@ -5861,7 +5856,7 @@ class ApfFilterTest {
             val apfConfig = getDefaultConfig()
             apfConfig.apfRamSize = apfRamSize
             val apfFilter = getApfFilter(apfConfig)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
 
             val lp = LinkProperties()
             val ipv4LinkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
@@ -5872,7 +5867,7 @@ class ApfFilterTest {
                 lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
             }
             apfFilter.setLinkProperties(lp)
-            program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             val ra1 = """
                 333300000001f434f06452fe86dd60010c0000503afffe800000000000001cb6b5bc353b7cfdff0
@@ -5882,7 +5877,7 @@ class ApfFilterTest {
             """.replace("\\s+".toRegex(), "").trim()
             val ra1Bytes = HexDump.hexStringToByteArray(ra1)
             Os.write(localRaWriterSocket, ra1Bytes, 0, ra1Bytes.size)
-            apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
 
             // Using scapy to generate packet:
             // eth = Ether(src="E8:9F:80:66:60:BC", dst="f2:9c:70:2c:39:5a")
@@ -5899,7 +5894,7 @@ class ApfFilterTest {
             """.replace("\\s+".toRegex(), "").trim()
             val ra2Bytes = HexDump.hexStringToByteArray(ra2)
             Os.write(localRaWriterSocket, ra2Bytes, 0, ra2Bytes.size)
-            program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
+            program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 1)
             overEstimatedProgramSize = apfFilter.overEstimatedProgramSize
         } cleanup {
             IoUtils.closeQuietly(localRaWriterSocket)
@@ -5928,17 +5923,17 @@ class ApfFilterTest {
             000000000000000
         """.replace("\\s+".toRegex(), "").trim()
 
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(ra2),
             DROPPED_RA
         )
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             HexDump.hexStringToByteArray(ra1),
-            PASSED_IPV6_ICMP
+            PASSED_RA
         )
     }
 
@@ -5948,11 +5943,11 @@ class ApfFilterTest {
         val apfConfig = getDefaultConfig()
         apfConfig.apfRamSize = 1500
         val apfFilter = getApfFilter(apfConfig)
-        val program = apfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
+        val program = ApfTestHelpers.consumeInstalledProgram(apfController, installCnt = 2)
         // Using scapy to generate packet:
         // pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x890D)/Raw(load="01")
         val bcastTDLSPkt = "ffffffffffff000000000000890d3031"
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(bcastTDLSPkt),
@@ -5962,7 +5957,7 @@ class ApfFilterTest {
         // Using scapy to generate packet:
         // pkt = Ether(dst="02:03:04:05:06:07", type=0x890D)/Raw(load="01")
         val ucastTDLSPkt = "020304050607000000000000890d3031"
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfFilter.mApfVersionSupported,
             program,
             HexDump.hexStringToByteArray(ucastTDLSPkt),
diff --git a/tests/unit/src/android/net/apf/ApfGeneratorTest.kt b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
index 1c383bcd..dee01ca5 100644
--- a/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
+++ b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
@@ -51,7 +51,6 @@ import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
 import org.junit.After
 import org.junit.Assume.assumeTrue
-import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -90,16 +89,10 @@ class ApfGeneratorTest {
     private val clampSize = 2048
 
     private val testPacket = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
-    private lateinit var apfTestHelpers: ApfTestHelpers
-
-    @Before
-    fun setUp() {
-        apfTestHelpers = ApfTestHelpers(apfInterpreterVersion)
-    }
 
     @After
     fun tearDown() {
-        apfTestHelpers.resetTransmittedPacketMemory()
+        ApfJniUtils.resetTransmittedPacketMemory()
     }
 
     @Test
@@ -132,16 +125,6 @@ class ApfGeneratorTest {
                 256,
                 ApfV4Generator.DROP_LABEL
         ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
-                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
-                0x0c,
-                ApfV4Generator.DROP_LABEL
-        ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
-                byteArrayOf(1, '.'.code.toByte(), 0, 0),
-                0x0c,
-                ApfV4Generator.DROP_LABEL
-        ) }
         assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                 byteArrayOf(0, 0),
                 0xc0,
@@ -172,16 +155,6 @@ class ApfGeneratorTest {
                 256,
                 ApfV4Generator.DROP_LABEL
         ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
-                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
-                0x0c,
-                ApfV4Generator.DROP_LABEL
-        ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
-                byteArrayOf(1, '.'.code.toByte(), 0, 0),
-                0x0c,
-                ApfV4Generator.DROP_LABEL
-        ) }
         assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                 byteArrayOf(0, 0),
                 0xc0,
@@ -207,14 +180,6 @@ class ApfGeneratorTest {
                 0xc0,
                 ApfV4Generator.DROP_LABEL
         ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
-                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
-                ApfV4Generator.DROP_LABEL
-        ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
-                byteArrayOf(1, '.'.code.toByte(), 0, 0),
-                ApfV4Generator.DROP_LABEL
-        ) }
         assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                 byteArrayOf(0, 0),
                 ApfV4Generator.DROP_LABEL
@@ -235,14 +200,6 @@ class ApfGeneratorTest {
                 byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                 ApfV4Generator.DROP_LABEL
         ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
-                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
-                ApfV4Generator.DROP_LABEL
-        ) }
-        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
-                byteArrayOf(1, '.'.code.toByte(), 0, 0),
-                ApfV4Generator.DROP_LABEL
-        ) }
         assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                 byteArrayOf(0, 0),
                 ApfV4Generator.DROP_LABEL
@@ -462,7 +419,7 @@ class ApfGeneratorTest {
         )
         assertContentEquals(
                 listOf("0: pass"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         var gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -475,7 +432,7 @@ class ApfGeneratorTest {
         )
         assertContentEquals(
                 listOf("0: drop"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -491,7 +448,7 @@ class ApfGeneratorTest {
         )
         assertContentEquals(
                 listOf("0: pass        counter=129"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -508,7 +465,7 @@ class ApfGeneratorTest {
         )
         assertContentEquals(
                 listOf("0: drop        counter=1000"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -525,7 +482,7 @@ class ApfGeneratorTest {
         val expectedCounterValue1 = PASSED_ARP_REQUEST.value()
         assertContentEquals(
                 listOf("0: pass        counter=$expectedCounterValue1"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -542,7 +499,7 @@ class ApfGeneratorTest {
         val expectedCounterValue2 = DROPPED_ETHERTYPE_NOT_ALLOWED.value()
         assertContentEquals(
                 listOf("0: drop        counter=$expectedCounterValue2"),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -565,7 +522,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: allocate    r0",
                 "2: allocate    1500"
-        ), apfTestHelpers.disassembleApf(program).map { it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addTransmitWithoutChecksum()
@@ -581,7 +538,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: transmit    ip_ofs=255",
                 "4: transmitudp ip_ofs=30, csum_ofs=40, csum_start=50, partial_csum=0x0100",
-        ), apfTestHelpers.disassembleApf(program).map { it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         val largeByteArray = ByteArray(256) { 0x01 }
         gen = ApfV6Generator(largeByteArray, apfInterpreterVersion, ramSize, clampSize)
@@ -601,7 +558,7 @@ class ApfGeneratorTest {
                         "0: data        256, " + "01".repeat(256),
                         "259: debugbuf    size=$debugBufferSize"
                 ),
-                apfTestHelpers.disassembleApf(program).map { it.trim() }
+                ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -643,7 +600,7 @@ class ApfGeneratorTest {
                 "25: write       0x80000000",
                 "30: write       0xfffffffe",
                 "35: write       0xfffefdfc"
-        ), apfTestHelpers.disassembleApf(program).map { it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addWriteU8(R0)
@@ -668,7 +625,7 @@ class ApfGeneratorTest {
                 "6: ewrite1     r1",
                 "8: ewrite2     r1",
                 "10: ewrite4     r1"
-        ), apfTestHelpers.disassembleApf(program).map { it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addDataCopy(0, 2)
@@ -685,7 +642,7 @@ class ApfGeneratorTest {
                 "0: datacopy    src=0, (2)c902",
                 "2: datacopy    src=1, (1)02",
                 "5: pktcopy     src=1000, len=255"
-        ), apfTestHelpers.disassembleApf(program).map { it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addDataCopyFromR0(5)
@@ -704,7 +661,7 @@ class ApfGeneratorTest {
                 "3: epktcopy    src=r0, len=5",
                 "6: edatacopy   src=r0, len=r1",
                 "8: epktcopy    src=r0, len=r1"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfBytesAtR0Equal(byteArrayOf('a'.code.toByte()), ApfV4Generator.DROP_LABEL)
@@ -717,7 +674,7 @@ class ApfGeneratorTest {
         ), program)
         assertContentEquals(listOf(
                 "0: jbseq       r0, (1), DROP, 61"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         val qnames = byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0, 0)
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -732,7 +689,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: jdnsqne     r0, DROP, PTR, (1)A(1)B(0)(0)",
                 "10: jdnsqeq     r0, DROP, PTR, (1)A(1)B(0)(0)"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsQSafe(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
@@ -746,7 +703,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: jdnsqnesafe r0, DROP, PTR, (1)A(1)B(0)(0)",
                 "10: jdnsqeqsafe r0, DROP, PTR, (1)A(1)B(0)(0)"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
@@ -760,7 +717,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: jdnsane     r0, DROP, (1)A(1)B(0)(0)",
                 "9: jdnsaeq     r0, DROP, (1)A(1)B(0)(0)"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsASafe(qnames, ApfV4Generator.DROP_LABEL)
@@ -774,7 +731,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: jdnsanesafe r0, DROP, (1)A(1)B(0)(0)",
                 "9: jdnsaeqsafe r0, DROP, (1)A(1)B(0)(0)"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfOneOf(R1, List(32) { (it + 1).toLong() }.toSet(), DROP_LABEL)
@@ -797,7 +754,7 @@ class ApfGeneratorTest {
         assertContentEquals(listOf(
                 "0: joneof      r0, DROP, { 0, 128, 256, 65536 }",
                 "20: jnoneof     r1, DROP, { 0, 128, 256, 65536 }"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addJumpIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DROP_LABEL)
@@ -816,7 +773,7 @@ class ApfGeneratorTest {
                 "0: jbseq       r0, (2), DROP, { 0102, 0304 }[2]",
                 "9: jbsne       r0, (2), DROP, { 0102, 0304 }[2]",
                 "18: jbsne       r0, (2), DROP, 0101"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
     }
 
     @Test
@@ -857,8 +814,8 @@ class ApfGeneratorTest {
                 .addWriteU32(R1)
                 .addTransmitWithoutChecksum()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, ByteArray(MIN_PKT_SIZE))
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, ByteArray(MIN_PKT_SIZE))
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         assertContentEquals(
                 byteArrayOf(
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff.toByte(),
@@ -893,8 +850,8 @@ class ApfGeneratorTest {
                 .addPacketCopyFromR0LenR1()
                 .addTransmitWithoutChecksum()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         assertContentEquals(
                 byteArrayOf(33, 34, 35, 1, 2, 3, 4, 33, 34, 35, 1, 2, 3, 4),
                 transmitPackets[0]
@@ -920,9 +877,9 @@ class ApfGeneratorTest {
                 "26: datacopy    src=9, (3)778899",
                 "29: datacopy    src=3, (6)112233445566",
                 "32: transmit    ip_ofs=255"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         val transmitPkt = HexDump.toHexString(transmitPackets[0])
         assertEquals("112233445566223344778899112233445566", transmitPkt)
     }
@@ -952,9 +909,9 @@ class ApfGeneratorTest {
             "277: datacopy    src=258, (5)" + "02".repeat(5),
             "281: datacopy    src=255, (5)" + "01".repeat(3) + "02".repeat(2),
             "284: transmit    ip_ofs=255"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         val transmitPkt = HexDump.toHexString(transmitPackets[0])
         assertEquals(
             "01".repeat(290) + "02".repeat(5) + "01".repeat(3) + "02".repeat(2),
@@ -979,9 +936,9 @@ class ApfGeneratorTest {
             "311: datacopy    src=3, (255)" + "03".repeat(255),
             "314: datacopy    src=258, (45)" + "04".repeat(45),
             "318: transmit    ip_ofs=255"
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         val transmitPkt = HexDump.toHexString(transmitPackets[0])
         assertEquals( "03".repeat(255) + "04".repeat(45), transmitPkt)
     }
@@ -1058,7 +1015,7 @@ class ApfGeneratorTest {
             "98: jbsne       r0, (2), PASS, 0203",
             "103: li          r0, 6",
             "105: jbsne       r0, (34), PASS, ${HexDump.toHexString(joinedBytes)}",
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         val largePrefix = ByteArray(510) { 0 }
         program = ApfV61Generator(apfInterpreterVersion, ramSize, clampSize)
@@ -1072,7 +1029,7 @@ class ApfGeneratorTest {
             "557: jbsptreq    pktofs=1, (2), PASS, @510[0102]",
             "562: li          r0, 1",
             "564: jbseq       r0, (2), PASS, 0304",
-        ), apfTestHelpers.disassembleApf(program).map{ it.trim() })
+        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
     }
 
     @Test
@@ -1081,12 +1038,12 @@ class ApfGeneratorTest {
                 .addDrop()
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1096,7 +1053,7 @@ class ApfGeneratorTest {
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addCountAndPass(Counter.PASSED_ARP_REQUEST)
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1125,7 +1082,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .generate()
         var dataRegion = ByteArray(Counter.totalSize()) { 0 }
-        apfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
+        ApfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
         var counterMap = decodeCountersIntoMap(dataRegion)
         var expectedMap = getInitialMap()
         expectedMap[PASSED_ARP_REQUEST] = 2
@@ -1167,7 +1124,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1181,7 +1138,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1195,7 +1152,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1209,7 +1166,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1223,7 +1180,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1237,7 +1194,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1251,7 +1208,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1265,7 +1222,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1280,7 +1237,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1295,7 +1252,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1309,7 +1266,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1323,7 +1280,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1337,7 +1294,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1351,7 +1308,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1365,7 +1322,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1379,7 +1336,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1393,7 +1350,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1407,7 +1364,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1421,7 +1378,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1435,7 +1392,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1452,7 +1409,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1469,7 +1426,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1486,7 +1443,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1503,7 +1460,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1518,7 +1475,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1533,7 +1490,7 @@ class ApfGeneratorTest {
                 .addPass()
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1548,7 +1505,7 @@ class ApfGeneratorTest {
                 .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
                 apfInterpreterVersion,
                 program,
                 testPacket,
@@ -1560,7 +1517,7 @@ class ApfGeneratorTest {
                 .addCountAndPass(Counter.PASSED_ARP_REQUEST)
                 .addCountTrampoline()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1576,7 +1533,7 @@ class ApfGeneratorTest {
                 .addCountTrampoline()
                 .generate()
         var dataRegion = ByteArray(Counter.totalSize()) { 0 }
-        apfTestHelpers.assertVerdict(apfInterpreterVersion, DROP, program, testPacket, dataRegion)
+        ApfTestHelpers.assertVerdict(apfInterpreterVersion, DROP, program, testPacket, dataRegion)
         assertContentEquals(ByteArray(Counter.totalSize()) { 0 }, dataRegion)
 
         program = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
@@ -1584,7 +1541,7 @@ class ApfGeneratorTest {
                 .addCountTrampoline()
                 .generate()
         dataRegion = ByteArray(Counter.totalSize()) { 0 }
-        apfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
+        ApfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
         assertContentEquals(ByteArray(Counter.totalSize()) { 0 }, dataRegion)
     }
 
@@ -1595,7 +1552,7 @@ class ApfGeneratorTest {
                 .addAllocate(65535)
                 .addDrop()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1613,7 +1570,7 @@ class ApfGeneratorTest {
                 .addTransmitWithoutChecksum()
                 .addDrop()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             testPacket,
@@ -1657,8 +1614,8 @@ class ApfGeneratorTest {
                         true // isUdp
                 )
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
-        val transmitPackets = apfTestHelpers.consumeTransmittedPackets(1)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        val transmitPackets = ApfTestHelpers.consumeTransmittedPackets(1)
         val txBuf = ByteBuffer.wrap(transmitPackets[0])
         Struct.parse(EthernetHeader::class.java, txBuf)
         val ipv4Hdr = Struct.parse(Ipv4Header::class.java, txBuf)
@@ -1698,28 +1655,28 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
 
         val badUdpPayload = intArrayOf(
                 0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
@@ -1741,7 +1698,7 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             badUdpPayload,
@@ -1754,7 +1711,7 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             badUdpPayload,
@@ -1799,28 +1756,28 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, udpPayload)
 
         val badUdpPayload = intArrayOf(
                 0x00, 0x00, 0x84, 0x00, // tid = 0x00, flags = 0x8400,
@@ -1846,7 +1803,7 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             badUdpPayload,
@@ -1859,7 +1816,7 @@ class ApfGeneratorTest {
                 .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.verifyProgramRun(
+        ApfTestHelpers.verifyProgramRun(
             apfInterpreterVersion,
             program,
             badUdpPayload,
@@ -1885,7 +1842,7 @@ class ApfGeneratorTest {
                 )
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 2)
@@ -1895,7 +1852,7 @@ class ApfGeneratorTest {
                 )
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 1)
@@ -1905,7 +1862,7 @@ class ApfGeneratorTest {
                 )
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
@@ -1915,7 +1872,7 @@ class ApfGeneratorTest {
                 )
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
     }
 
     @Test
@@ -1925,28 +1882,28 @@ class ApfGeneratorTest {
                 .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 254)
                 .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 254)
                 .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertDrop(apfInterpreterVersion, program, testPacket)
 
         program = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
                 .addLoadImmediate(R0, 255)
                 .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
-        apfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
+        ApfTestHelpers.assertPass(apfInterpreterVersion, program, testPacket)
     }
 
     @Test
@@ -1956,7 +1913,7 @@ class ApfGeneratorTest {
                 .generate()
         val dataRegion = ByteArray(ramSize - program.size) { 0 }
 
-        apfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
+        ApfTestHelpers.assertVerdict(apfInterpreterVersion, PASS, program, testPacket, dataRegion)
         // offset 3 in the data region should contain if the interpreter is APFv6 mode or not
         assertEquals(1, dataRegion[3])
     }
@@ -1980,7 +1937,16 @@ class ApfGeneratorTest {
         val gen = ApfV6Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addDefaultPacketHandling()
         val size = gen.programLengthOverEstimate() - gen.baseProgramSize
-        assertEquals(2, size)
+        assertEquals(15, size)
+        assertEquals(size, gen.defaultPacketHandlingSizeOverEstimate)
+    }
+
+    @Test
+    fun testGetApfV61DefaultPacketHandlingSizeOverEstimate() {
+        val gen = ApfV61Generator(apfInterpreterVersion, ramSize, clampSize)
+        gen.addDefaultPacketHandling()
+        val size = gen.programLengthOverEstimate() - gen.baseProgramSize
+        assertEquals(13, size)
         assertEquals(size, gen.defaultPacketHandlingSizeOverEstimate)
     }
 
@@ -1989,7 +1955,7 @@ class ApfGeneratorTest {
         val gen = ApfV4Generator(apfInterpreterVersion, ramSize, clampSize)
         gen.addDefaultPacketHandling()
         val size = gen.programLengthOverEstimate() - gen.baseProgramSize
-        assertEquals(25, size)
+        assertEquals(38, size)
         assertEquals(size, gen.defaultPacketHandlingSizeOverEstimate)
     }
 
diff --git a/tests/unit/src/android/net/apf/ApfJniUtils.java b/tests/unit/src/android/net/apf/ApfJniUtils.java
index 85f76b9e..f4837f10 100644
--- a/tests/unit/src/android/net/apf/ApfJniUtils.java
+++ b/tests/unit/src/android/net/apf/ApfJniUtils.java
@@ -23,32 +23,23 @@ import java.util.List;
 public class ApfJniUtils {
     static final int APF_INTERPRETER_VERSION_V6 = 6000;
     static final int APF_INTERPRETER_VERSION_NEXT = 99999999;
-    public ApfJniUtils(int apfInterpreterVersion) {
-        // Load up native shared library containing APF interpreter exposed via JNI.
-        if (apfInterpreterVersion == APF_INTERPRETER_VERSION_V6) {
-            System.loadLibrary("apfjniv6");
-        } else if (apfInterpreterVersion == APF_INTERPRETER_VERSION_NEXT) {
-            System.loadLibrary("apfjninext");
-        } else {
-            throw new IllegalArgumentException(
-                "apfInterpreterVersion must be "
-                    + APF_INTERPRETER_VERSION_V6 + " or "
-                    + APF_INTERPRETER_VERSION_NEXT);
-        }
+    static {
+        // Load up native shared library libapfjni containing all APF interpreters exposed via JNI.
+        System.loadLibrary("apfjni");
     }
 
     /**
      * Call the APF interpreter to run {@code program} on {@code packet} with persistent memory
      * segment {@data} pretending the filter was installed {@code filter_age} seconds ago.
      */
-    public native int apfSimulate(int apfVersion, byte[] program, byte[] packet,
+    public static native int apfSimulate(int apfVersion, byte[] program, byte[] packet,
             byte[] data, int filterAge);
 
     /**
      * Compile a tcpdump human-readable filter (e.g. "icmp" or "tcp port 54") into a BPF
      * prorgam and return a human-readable dump of the BPF program identical to "tcpdump -d".
      */
-    public native String compileToBpf(String filter);
+    public static native String compileToBpf(String filter);
 
     /**
      * Open packet capture file {@code pcap_filename} and filter the packets using tcpdump
@@ -56,29 +47,21 @@ public class ApfJniUtils {
      * at the same time using APF program {@code apf_program}.  Return {@code true} if
      * both APF and BPF programs filter out exactly the same packets.
      */
-    public native boolean compareBpfApf(int apfVersion, String filter,
+    public static native boolean compareBpfApf(int apfVersion, String filter,
             String pcapFilename, byte[] apfProgram);
 
-    /**
-     * Open packet capture file {@code pcapFilename} and run it through APF filter. Then
-     * checks whether all the packets are dropped and populates data[] {@code data} with
-     * the APF counters.
-     */
-    public native boolean dropsAllPackets(int apfVersion, byte[] program, byte[] data,
-            String pcapFilename);
-
     /**
      * Disassemble the Apf program into human-readable text.
      */
-    public native String[] disassembleApf(byte[] program);
+    public static native String[] disassembleApf(byte[] program);
 
     /**
      * Get all transmitted packets.
      */
-    public native List<byte[]> getAllTransmittedPackets();
+    public static native List<byte[]> getAllTransmittedPackets();
 
     /**
      * Reset the memory region that stored the transmitted packet.
      */
-    public native void resetTransmittedPacketMemory();
+    public static native void resetTransmittedPacketMemory();
 }
diff --git a/tests/unit/src/android/net/apf/ApfMdnsOffloadEngineTest.kt b/tests/unit/src/android/net/apf/ApfMdnsOffloadEngineTest.kt
index d2841ba9..1bd8da3b 100644
--- a/tests/unit/src/android/net/apf/ApfMdnsOffloadEngineTest.kt
+++ b/tests/unit/src/android/net/apf/ApfMdnsOffloadEngineTest.kt
@@ -83,7 +83,14 @@ class ApfMdnsOffloadEngineTest {
     @Test
     fun testOffloadEngineRegistration() {
         val callback = mock(Callback::class.java)
-        val apfOffloadEngine = ApfMdnsOffloadEngine(interfaceName, handler, nsdManager, callback)
+        val apfOffloadEngine =
+            ApfMdnsOffloadEngine(
+                interfaceName,
+                handler,
+                nsdManager,
+                callback,
+                false /* skipMdnsRecordWithoutPriority */
+            )
         apfOffloadEngine.registerOffloadEngine()
         verify(nsdManager).registerOffloadEngine(
             eq(interfaceName),
@@ -131,10 +138,68 @@ class ApfMdnsOffloadEngineTest {
         verify(nsdManager).unregisterOffloadEngine(eq(apfOffloadEngine))
     }
 
+    @Test
+    fun testOnlyOffloadRecordsWithPriority() {
+        val callback = mock(Callback::class.java)
+        val apfOffloadEngine =
+            ApfMdnsOffloadEngine(
+                interfaceName,
+                handler,
+                nsdManager,
+                callback,
+                true /* skipMdnsRecordWithoutPriority */
+            )
+        apfOffloadEngine.registerOffloadEngine()
+        verify(nsdManager).registerOffloadEngine(
+            eq(interfaceName),
+            anyLong(),
+            anyLong(),
+            any(),
+            eq(apfOffloadEngine)
+        )
+        val infoWithoutPriority = OffloadServiceInfo(
+            OffloadServiceInfo.Key("TestServiceName2", "_advertisertest._tcp"),
+            listOf(),
+            "Android_test.local",
+            byteArrayOf(0x01, 0x02, 0x03, 0x04),
+            Int.MAX_VALUE,
+            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+        val infoWithPriority = OffloadServiceInfo(
+            OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
+            listOf(),
+            "Android_test.local",
+            byteArrayOf(0x01, 0x02, 0x03, 0x04),
+            0,
+            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+        visibleOnHandlerThread(handler) {
+            apfOffloadEngine.onOffloadServiceUpdated(
+                infoWithoutPriority
+            )
+        }
+        verify(callback).onOffloadRulesUpdated(eq(extractOffloadReplyRule(listOf())))
+        visibleOnHandlerThread(handler) {
+            apfOffloadEngine.onOffloadServiceUpdated(
+                infoWithPriority
+            )
+        }
+        verify(callback).onOffloadRulesUpdated(
+            eq(extractOffloadReplyRule(listOf(infoWithPriority)))
+        )
+    }
+
     @Test
     fun testCorruptedOffloadServiceInfoUpdateNotTriggerUpdate() {
         val callback = mock(Callback::class.java)
-        val apfOffloadEngine = ApfMdnsOffloadEngine(interfaceName, handler, nsdManager, callback)
+        val apfOffloadEngine =
+            ApfMdnsOffloadEngine(
+                interfaceName,
+                handler,
+                nsdManager,
+                callback,
+                false /* skipMdnsRecordWithoutPriority */
+            )
         apfOffloadEngine.registerOffloadEngine()
         val corruptedOffloadInfo = OffloadServiceInfo(
             OffloadServiceInfo.Key("gambit", "_${"a".repeat(63)}._tcp"),
diff --git a/tests/unit/src/android/net/apf/ApfStandaloneTest.kt b/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
index 21dc8fbf..eaf87359 100644
--- a/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
+++ b/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
@@ -38,7 +38,6 @@ import com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_OFFSET
 import com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_SOLICITATION
 import com.android.testutils.DevSdkIgnoreRunner
 import kotlin.test.assertEquals
-import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.junit.runners.Parameterized
@@ -63,12 +62,6 @@ class ApfStandaloneTest {
     private val etherTypeDenyList = listOf(0x88A2, 0x88A4, 0x88B8, 0x88CD, 0x88E1, 0x88E3)
     private val ramSize = 1024
     private val clampSize = 1024
-    private lateinit var apfTestHelpers: ApfTestHelpers
-
-    @Before
-    fun setUp() {
-        apfTestHelpers = ApfTestHelpers(apfInterpreterVersion)
-    }
 
     fun runApfTest(isSuspendMode: Boolean) {
         val program = generateApfV4Program(isSuspendMode)
@@ -91,7 +84,7 @@ class ApfStandaloneTest {
         val packetBadEtherType =
                 HexDump.hexStringToByteArray("ffffffffffff047bcb463fb588a201")
         val dataRegion = ByteArray(Counter.totalSize()) { 0 }
-        apfTestHelpers.assertVerdict(
+        ApfTestHelpers.assertVerdict(
             APF_VERSION_4,
             ApfTestHelpers.DROP,
             program,
@@ -167,7 +160,7 @@ class ApfStandaloneTest {
             c0a801013204c0a80164ff
         """.replace("\\s+".toRegex(), "").trim()
         val dhcpRequestPkt = HexDump.hexStringToByteArray(dhcpRequestPktRawBytes)
-        apfTestHelpers.assertVerdict(
+        ApfTestHelpers.assertVerdict(
             APF_VERSION_4,
             ApfTestHelpers.DROP,
             program,
@@ -208,7 +201,7 @@ class ApfStandaloneTest {
             0000000000000000000000028500c81d00000000
         """.replace("\\s+".toRegex(), "").trim()
         val rsPkt = HexDump.hexStringToByteArray(rsPktRawBytes)
-        apfTestHelpers.assertVerdict(APF_VERSION_4, ApfTestHelpers.DROP, program, rsPkt, dataRegion)
+        ApfTestHelpers.assertVerdict(APF_VERSION_4, ApfTestHelpers.DROP, program, rsPkt, dataRegion)
         assertEquals(mapOf<Counter, Long>(
                 Counter.TOTAL_PACKETS to 3,
                 Counter.DROPPED_RS to 1,
@@ -251,7 +244,7 @@ class ApfStandaloneTest {
                 00000000
             """.replace("\\s+".toRegex(), "").trim()
             val pingRequestPkt = HexDump.hexStringToByteArray(pingRequestPktRawBytes)
-            apfTestHelpers.assertVerdict(
+            ApfTestHelpers.assertVerdict(
                 APF_VERSION_4,
                 ApfTestHelpers.DROP,
                 program,
diff --git a/tests/unit/src/android/net/apf/ApfTest.java b/tests/unit/src/android/net/apf/ApfTest.java
index 64f3b110..abac1032 100644
--- a/tests/unit/src/android/net/apf/ApfTest.java
+++ b/tests/unit/src/android/net/apf/ApfTest.java
@@ -22,9 +22,11 @@ import static android.net.apf.ApfTestHelpers.DROP;
 import static android.net.apf.ApfTestHelpers.MIN_PKT_SIZE;
 import static android.net.apf.ApfTestHelpers.PASS;
 import static android.net.apf.ApfTestHelpers.assertProgramEquals;
+import static android.net.apf.BaseApfGenerator.APF_VERSION_2;
 import static android.net.apf.BaseApfGenerator.APF_VERSION_3;
 import static android.net.apf.BaseApfGenerator.APF_VERSION_4;
 import static android.net.apf.BaseApfGenerator.APF_VERSION_6;
+import static android.net.apf.BaseApfGenerator.APF_VERSION_61;
 import static android.net.apf.BaseApfGenerator.DROP_LABEL;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.PASS_LABEL;
@@ -81,7 +83,6 @@ import android.system.Os;
 import android.text.TextUtils;
 import android.text.format.DateUtils;
 import android.util.ArrayMap;
-import android.util.Log;
 import android.util.Pair;
 
 import androidx.test.InstrumentationRegistry;
@@ -98,7 +99,6 @@ import com.android.net.module.util.PacketBuilder;
 import com.android.networkstack.metrics.ApfSessionInfoMetrics;
 import com.android.networkstack.metrics.IpClientRaInfoMetrics;
 import com.android.networkstack.metrics.NetworkQuirkMetrics;
-import com.android.server.networkstack.tests.R;
 import com.android.testutils.ConcurrentUtils;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRunner;
@@ -108,6 +108,7 @@ import libcore.io.IoUtils;
 import libcore.io.Streams;
 
 import org.junit.After;
+import org.junit.Assume;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
@@ -148,7 +149,6 @@ import java.util.concurrent.atomic.AtomicReference;
 @RunWith(DevSdkIgnoreRunner.class)
 @SmallTest
 public class ApfTest {
-    private static final int APF_VERSION_2 = 2;
     private int mRamSize = 1024;
     private int mClampSize = 1024;
 
@@ -160,7 +160,12 @@ public class ApfTest {
 
     @Parameterized.Parameters
     public static Iterable<? extends Object> data() {
-        return Arrays.asList(4, 6);
+        return Arrays.asList(APF_VERSION_2, APF_VERSION_3, APF_VERSION_4, APF_VERSION_6,
+                APF_VERSION_61, 99999999);
+    }
+
+    private void assumeHasData() {
+         Assume.assumeTrue(mApfVersion >= APF_VERSION_3);
     }
 
     @Mock private Context mContext;
@@ -178,7 +183,6 @@ public class ApfTest {
     private HandlerThread mHandlerThread;
     private Handler mHandler;
     private long mCurrentTimeMs;
-    private ApfTestHelpers mApfTestHelpers;
 
     @Before
     public void setUp() throws Exception {
@@ -202,7 +206,6 @@ public class ApfTest {
         mHandlerThread = new HandlerThread("ApfTestThread");
         mHandlerThread.start();
         mHandler = new Handler(mHandlerThread.getLooper());
-        mApfTestHelpers = new ApfTestHelpers(ApfJniUtils.APF_INTERPRETER_VERSION_V6);
     }
 
     private void shutdownApfFilters() throws Exception {
@@ -275,58 +278,58 @@ public class ApfTest {
     }
 
     private void assertPass(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        mApfTestHelpers.assertPass(mApfVersion, gen);
+        ApfTestHelpers.assertPass(mApfVersion, gen);
     }
 
     private void assertDrop(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        mApfTestHelpers.assertDrop(mApfVersion, gen);
+        ApfTestHelpers.assertDrop(mApfVersion, gen);
     }
 
     private void assertPass(byte[] program, byte[] packet) {
-        mApfTestHelpers.assertPass(mApfVersion, program, packet);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet);
     }
 
     private void assertDrop(byte[] program, byte[] packet) {
-        mApfTestHelpers.assertDrop(mApfVersion, program, packet);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet);
     }
 
     private void assertPass(byte[] program, byte[] packet, int filterAge) {
-        mApfTestHelpers.assertPass(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet, filterAge);
     }
 
     private void assertDrop(byte[] program, byte[] packet, int filterAge) {
-        mApfTestHelpers.assertDrop(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet, filterAge);
     }
 
     private void assertPass(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        mApfTestHelpers.assertPass(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDrop(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        mApfTestHelpers.assertDrop(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDataMemoryContents(int expected, byte[] program, byte[] packet,
             byte[] data, byte[] expectedData) throws Exception {
-        mApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, false /* ignoreInterpreterVersion */);
     }
 
     private void assertDataMemoryContentsIgnoreVersion(int expected, byte[] program,
             byte[] packet, byte[] data, byte[] expectedData) throws Exception {
-        mApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, true /* ignoreInterpreterVersion */);
     }
 
     private void assertVerdict(String msg, int expected, byte[] program,
             byte[] packet, int filterAge) {
-        mApfTestHelpers.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
+        ApfTestHelpers.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
     }
 
     private void assertVerdict(int expected, byte[] program, byte[] packet) {
-        mApfTestHelpers.assertVerdict(mApfVersion, expected, program, packet);
+        ApfTestHelpers.assertVerdict(mApfVersion, expected, program, packet);
     }
 
     /**
@@ -781,22 +784,22 @@ public class ApfTest {
         ApfV4Generator gen;
 
         // 0-byte immediate: li R0, 0
-        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 0);
         assertProgramEquals(new byte[]{LI_OP | SIZE0}, gen.generate());
 
         // 1-byte immediate: li R0, 42
-        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 42);
         assertProgramEquals(new byte[]{LI_OP | SIZE8, 42}, gen.generate());
 
         // 2-byte immediate: li R1, 0x1234
-        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 0x1234);
         assertProgramEquals(new byte[]{LI_OP | SIZE16 | R1_REG, 0x12, 0x34}, gen.generate());
 
         // 4-byte immediate: li R0, 0x12345678
-        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 0x12345678);
         assertProgramEquals(
                 new byte[]{LI_OP | SIZE32, 0x12, 0x34, 0x56, 0x78},
@@ -811,18 +814,18 @@ public class ApfTest {
         ApfV4Generator gen;
 
         // 1-byte negative immediate: li R0, -42
-        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, -42);
         assertProgramEquals(new byte[]{LI_OP | SIZE8, -42}, gen.generate());
 
         // 2-byte negative immediate: li R1, -0x1122
-        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, -0x1122);
         assertProgramEquals(new byte[]{LI_OP | SIZE16 | R1_REG, (byte)0xEE, (byte)0xDE},
                 gen.generate());
 
         // 4-byte negative immediate: li R0, -0x11223344
-        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, -0x11223344);
         assertProgramEquals(
                 new byte[]{LI_OP | SIZE32, (byte)0xEE, (byte)0xDD, (byte)0xCC, (byte)0xBC},
@@ -866,6 +869,8 @@ public class ApfTest {
      */
     @Test
     public void testApfDataWrite() throws IllegalInstructionException, Exception {
+        assumeHasData();
+
         byte[] packet = new byte[MIN_PKT_SIZE];
         byte[] data = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
         byte[] expected_data = data.clone();
@@ -892,6 +897,8 @@ public class ApfTest {
      */
     @Test
     public void testApfDataRead() throws IllegalInstructionException, Exception {
+        assumeHasData();
+
         // Program that DROPs if address 10 (-6) contains 0x87654321.
         ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1000);
@@ -922,6 +929,8 @@ public class ApfTest {
      */
     @Test
     public void testApfDataReadModifyWrite() throws IllegalInstructionException, Exception {
+        assumeHasData();
+
         ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, -22);
         gen.addLoadData(R0, 0);  // Load from address 32 -22 + 0 = 10
@@ -944,6 +953,8 @@ public class ApfTest {
 
     @Test
     public void testApfDataBoundChecking() throws IllegalInstructionException, Exception {
+        assumeHasData();
+
         byte[] packet = new byte[MIN_PKT_SIZE];
         byte[] data = new byte[32];
         byte[] expected_data = data;
@@ -961,10 +972,12 @@ public class ApfTest {
         // APFv6 needs to round this up to be a multiple of 4, so 40.
         gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
-        if (mApfVersion == 4) {
-            gen.addLoadData(R1, 15);  // R0(20)+15+U32[0..3] >= 6 prog + 32 data, so invalid
-        } else {
+        if (mApfVersion >= APF_VERSION_61) {
+            gen.addLoadData(R1, -20 + 1024 - 3);  // R0(20)-20+1024-3+U32[0..3] >= 1024 ram, invalid
+        } else if (mApfVersion == APF_VERSION_6) {
             gen.addLoadData(R1, 17);  // R0(20)+17+U32[0..3] >= 6 prog + 2 pad + 32 data, so invalid
+        } else {
+            gen.addLoadData(R1, 15);  // R0(20)+15+U32[0..3] >= 6 prog + 32 data, so invalid
         }
         gen.addJump(DROP_LABEL);  // Not reached.
         assertDataMemoryContents(PASS, gen.generate(), packet, data, expected_data);
@@ -986,7 +999,7 @@ public class ApfTest {
         // ...but doesn't allow accesses before the start of the buffer
         gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
-        gen.addLoadData(R1, -1000);
+        gen.addLoadData(R1, -20 - 1024 - 1);
         gen.addJump(DROP_LABEL);  // Not reached.
         assertDataMemoryContents(PASS, gen.generate(), packet, data, expected_data);
     }
@@ -1005,39 +1018,6 @@ public class ApfTest {
         return apfFilter.get();
     }
 
-    /**
-     * Generate APF program, run pcap file though APF filter, then check all the packets in the file
-     * should be dropped.
-     */
-    @Test
-    public void testApfFilterPcapFile() throws Exception {
-        final byte[] MOCK_PCAP_IPV4_ADDR = {(byte) 172, 16, 7, (byte) 151};
-        String pcapFilename = stageFile(R.raw.apfPcap);
-        LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_PCAP_IPV4_ADDR), 16);
-        LinkProperties lp = new LinkProperties();
-        lp.addLinkAddress(link);
-
-        ApfConfiguration config = getDefaultConfig();
-        config.apfVersionSupported = 4;
-        config.apfRamSize = 1700;
-        config.multicastFilter = DROP_MULTICAST;
-        config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 2 /* installCnt */);
-        apfFilter.setLinkProperties(lp);
-        byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
-        byte[] data = new byte[Counter.totalSize()];
-        final boolean result;
-
-        result = mApfTestHelpers.dropsAllPackets(
-            mApfVersion, program, data, pcapFilename);
-        Log.i(TAG, "testApfFilterPcapFile(): Data counters: " + HexDump.toHexString(data, false));
-
-        assertTrue("Failed to drop all packets by filter. \nAPF counters:" +
-            HexDump.toHexString(data, false), result);
-    }
-
     private static final int ETH_HEADER_LEN               = 14;
     private static final int ETH_DEST_ADDR_OFFSET         = 0;
     private static final int ETH_ETHERTYPE_OFFSET         = 12;
@@ -1173,11 +1153,11 @@ public class ApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         apfFilter.setLinkProperties(lp);
 
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
         if (SdkLevel.isAtLeastV()) {
@@ -1230,7 +1210,7 @@ public class ApfTest {
         ApfConfiguration config = getDefaultConfig();
         ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify empty IPv6 packet is passed
         ByteBuffer packet = makeIpv6Packet(IPPROTO_UDP);
@@ -1471,11 +1451,11 @@ public class ApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         apfFilter.setLinkProperties(lp);
 
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Construct IPv4 and IPv6 multicast packets.
         ByteBuffer mcastv4packet = makeIpv4Packet(IPPROTO_UDP);
@@ -1510,7 +1490,7 @@ public class ApfTest {
 
         // Turn on multicast filter and verify it works
         apfFilter.setMulticastFilter(true);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, mcastv4packet.array());
         assertDrop(program, mcastv6packet.array());
         assertDrop(program, bcastv4packet1.array());
@@ -1519,7 +1499,7 @@ public class ApfTest {
 
         // Turn off multicast filter and verify it's off
         apfFilter.setMulticastFilter(false);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertPass(program, mcastv4packet.array());
         assertPass(program, mcastv6packet.array());
         assertPass(program, bcastv4packet1.array());
@@ -1531,9 +1511,9 @@ public class ApfTest {
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         clearInvocations(mApfController);
         final ApfFilter apfFilter2 = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         apfFilter2.setLinkProperties(lp);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, mcastv4packet.array());
         assertDrop(program, mcastv6packet.array());
         assertDrop(program, bcastv4packet1.array());
@@ -1559,7 +1539,7 @@ public class ApfTest {
         final ApfConfiguration configuration = getDefaultConfig();
         final ApfFilter apfFilter = getApfFilter(configuration);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         final ArgumentCaptor<BroadcastReceiver> receiverCaptor =
                 ArgumentCaptor.forClass(BroadcastReceiver.class);
         verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture());
@@ -1581,13 +1561,13 @@ public class ApfTest {
             doReturn(true).when(mPowerManager).isDeviceIdleMode();
             receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
         }
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         // ...and even while dozing...
         assertPass(program, packet.array());
 
         // ...but when the multicast filter is also enabled, drop the multicast pings to save power.
         apfFilter.setMulticastFilter(true);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, packet.array());
 
         // However, we should still let through all other ICMPv6 types.
@@ -1606,7 +1586,7 @@ public class ApfTest {
             doReturn(false).when(mPowerManager).isDeviceIdleMode();
             receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
         }
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertPass(program, packet.array());
     }
 
@@ -1616,7 +1596,7 @@ public class ApfTest {
         ApfConfiguration config = getDefaultConfig();
         ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify empty packet of 100 zero bytes is passed
         // Note that eth-type = 0 makes it an IEEE802.3 frame
@@ -1634,7 +1614,7 @@ public class ApfTest {
         // Now turn on the filter
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         apfFilter = getApfFilter(config);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify that IEEE802.3 frame is dropped
         // In this case ethtype is used for payload length
@@ -1660,7 +1640,7 @@ public class ApfTest {
         ApfConfiguration config = getDefaultConfig();
         ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify empty packet of 100 zero bytes is passed
         // Note that eth-type = 0 makes it an IEEE802.3 frame
@@ -1678,7 +1658,7 @@ public class ApfTest {
         // Now add IPv4 to the black list
         config.ethTypeBlackList = ipv4BlackList;
         apfFilter = getApfFilter(config);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify that IPv4 frame will be dropped
         setIpv4VersionFields(packet);
@@ -1691,7 +1671,7 @@ public class ApfTest {
         // Now let us have both IPv4 and IPv6 in the black list
         config.ethTypeBlackList = ipv4Ipv6BlackList;
         apfFilter = getApfFilter(config);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify that IPv4 frame will be dropped
         setIpv4VersionFields(packet);
@@ -1730,7 +1710,7 @@ public class ApfTest {
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Verify initially ARP request filter is off, and GARP filter is on.
         verifyArpFilter(program, PASS);
@@ -1740,11 +1720,11 @@ public class ApfTest {
         LinkProperties lp = new LinkProperties();
         assertTrue(lp.addLinkAddress(linkAddress));
         apfFilter.setLinkProperties(lp);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         verifyArpFilter(program, DROP);
 
         apfFilter.setLinkProperties(new LinkProperties());
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         // Inform ApfFilter of loss of IP and verify ARP filtering is off
         verifyArpFilter(program, PASS);
     }
@@ -2015,7 +1995,7 @@ public class ApfTest {
         clearInvocations(mApfController);
         pretendPacketReceived(packet.array());
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         verifyRaLifetime(program, packet, lifetime);
         return program;
     }
@@ -2035,7 +2015,7 @@ public class ApfTest {
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         final int ROUTER_LIFETIME = 1000;
         final int PREFIX_VALID_LIFETIME = 200;
@@ -2120,7 +2100,7 @@ public class ApfTest {
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         final ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         final int RA_REACHABLE_TIME = 1800;
         final int RA_RETRANSMISSION_TIMER = 1234;
 
@@ -2135,7 +2115,7 @@ public class ApfTest {
 
         // Assume apf is shown the given RA, it generates program to filter it.
         pretendPacketReceived(raPacket);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, raPacket);
 
         // A packet with different reachable time should be passed.
@@ -2160,7 +2140,7 @@ public class ApfTest {
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         final int routerLifetime = 1000;
         final int timePassedSeconds = 12;
@@ -2176,7 +2156,7 @@ public class ApfTest {
             apfFilter.installNewProgram();
         }
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         verifyRaLifetime(program, basePacket, routerLifetime, timePassedSeconds);
 
         // Packet should be passed if the program is installed after 1/6 * lifetime from last seen
@@ -2186,7 +2166,7 @@ public class ApfTest {
         synchronized (apfFilter) {
             apfFilter.installNewProgram();
         }
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, basePacket.array());
 
         mCurrentTimeMs += DateUtils.SECOND_IN_MILLIS;
@@ -2194,7 +2174,7 @@ public class ApfTest {
         synchronized (apfFilter) {
             apfFilter.installNewProgram();
         }
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertPass(program, basePacket.array());
     }
 
@@ -2267,13 +2247,13 @@ public class ApfTest {
     @Test
     public void testMatchedRaUpdatesLifetime() throws Exception {
         final ApfFilter apfFilter = getApfFilter(getDefaultConfig());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // lifetime dropped significantly, assert pass
         ra = new RaPacketBuilder(200 /* router lifetime */).build();
@@ -2281,7 +2261,7 @@ public class ApfTest {
 
         // update program with the new RA
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // assert program was updated and new lifetimes were taken into account.
         assertDrop(program, ra);
@@ -2292,7 +2272,7 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         // Template packet:
         // Frame 1: 150 bytes on wire (1200 bits), 150 bytes captured (1200 bits)
         // Ethernet II, Src: Netgear_23:67:2c (28:c6:8e:23:67:2c), Dst: IPv6mcast_01 (33:33:00:00:00:01)
@@ -2344,7 +2324,7 @@ public class ApfTest {
                     String.format(packetStringFmt, lifetime + lifetime));
             // feed the RA into APF and generate the filter, the filter shouldn't crash.
             pretendPacketReceived(ra);
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         }
     }
 
@@ -2356,7 +2336,7 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */)
@@ -2365,7 +2345,7 @@ public class ApfTest {
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2385,7 +2365,7 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */)
@@ -2394,7 +2374,7 @@ public class ApfTest {
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2421,14 +2401,14 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(0 /* router lifetime */).build();
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2450,14 +2430,14 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(100 /* router lifetime */).build();
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2487,14 +2467,14 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(200 /* router lifetime */).build();
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2520,14 +2500,14 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
 
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2559,13 +2539,13 @@ public class ApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
         pretendPacketReceived(ra);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // repeated RA is dropped.
         assertDrop(program, ra);
@@ -2574,37 +2554,37 @@ public class ApfTest {
         ra = new RaPacketBuilder(599 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(180 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(0 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(180 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(599 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(1800 /* router lifetime */).build();
         assertPass(program, ra);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         assertDrop(program, ra);
     }
 
@@ -2650,13 +2630,15 @@ public class ApfTest {
         config.apfVersionSupported = 2;
         config.apfRamSize = 256;
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
         verify(mNetworkQuirkMetrics).statsWrite();
     }
 
     @Test
     public void testApfSessionInfoMetrics() throws Exception {
+        assumeHasData();
+
         final ApfConfiguration config = getDefaultConfig();
         config.apfVersionSupported = 4;
         config.apfRamSize = 4096;
@@ -2665,7 +2647,7 @@ public class ApfTest {
         doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
         final ApfFilter apfFilter = getApfFilter(config);
         byte[] program =
-            mApfTestHelpers.consumeInstalledProgram(mApfController, 2 /* installCnt */);
+            ApfTestHelpers.consumeInstalledProgram(mApfController, 2 /* installCnt */);
         int maxProgramSize = 0;
         int numProgramUpdated = 0;
         maxProgramSize = Math.max(maxProgramSize, program.length);
@@ -2674,24 +2656,24 @@ public class ApfTest {
         final byte[] data = new byte[Counter.totalSize()];
         final byte[] expectedData = data.clone();
         final int totalPacketsCounterIdx = Counter.totalSize() + Counter.TOTAL_PACKETS.offset();
-        final int passedIpv6IcmpCounterIdx =
-                Counter.totalSize() + Counter.PASSED_IPV6_ICMP.offset();
+        final int passedRaCounterIdx =
+                Counter.totalSize() + Counter.PASSED_RA.offset();
         final int droppedIpv4MulticastIdx =
                 Counter.totalSize() + Counter.DROPPED_IPV4_MULTICAST.offset();
 
         // Receive an RA packet (passed).
         final byte[] ra = buildLargeRa();
         expectedData[totalPacketsCounterIdx + 3] += 1;
-        expectedData[passedIpv6IcmpCounterIdx + 3] += 1;
+        expectedData[passedRaCounterIdx + 3] += 1;
         assertDataMemoryContentsIgnoreVersion(PASS, program, ra, data, expectedData);
         pretendPacketReceived(ra);
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         maxProgramSize = Math.max(maxProgramSize, program.length);
         numProgramUpdated++;
 
         apfFilter.setMulticastFilter(true);
         // setMulticastFilter will trigger program installation.
-        program = mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        program = ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         maxProgramSize = Math.max(maxProgramSize, program.length);
         numProgramUpdated++;
 
@@ -2717,7 +2699,7 @@ public class ApfTest {
 
         // Verify Counters
         final Map<Counter, Long> expectedCounters = Map.of(Counter.TOTAL_PACKETS, 2L,
-                Counter.PASSED_IPV6_ICMP, 1L, Counter.DROPPED_IPV4_MULTICAST, 1L);
+                Counter.PASSED_RA, 1L, Counter.DROPPED_IPV4_MULTICAST, 1L);
         final ArgumentCaptor<Counter> counterCaptor = ArgumentCaptor.forClass(Counter.class);
         final ArgumentCaptor<Long> valueCaptor = ArgumentCaptor.forClass(Long.class);
         verify(mApfSessionInfoMetrics, times(expectedCounters.size())).addApfCounter(
@@ -2744,7 +2726,7 @@ public class ApfTest {
         final long durationTimeMs = config.minMetricsSessionDurationMs;
         doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
         final ApfFilter apfFilter = getApfFilter(config);
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         final int routerLifetime = 1000;
         final int prefixValidLifetime = 200;
@@ -2782,20 +2764,20 @@ public class ApfTest {
         // Inject RA packets. Calling assertProgramUpdateAndGet()/assertNoProgramUpdate() is to make
         // sure that the RA packet has been processed.
         pretendPacketReceived(ra1.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         pretendPacketReceived(ra2.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         pretendPacketReceived(raInvalid.build());
         Thread.sleep(NO_CALLBACK_TIMEOUT_MS);
         verify(mApfController, never()).installPacketFilter(any(), any());
         pretendPacketReceived(raZeroRouterLifetime.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         pretendPacketReceived(raZeroPioValidLifetime.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         pretendPacketReceived(raZeroRdnssLifetime.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
         pretendPacketReceived(raZeroRioRouteLifetime.build());
-        mApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
+        ApfTestHelpers.consumeInstalledProgram(mApfController, 1 /* installCnt */);
 
         // Write metrics data to statsd pipeline when shutdown.
         doReturn(startTimeMs + durationTimeMs).when(mDependencies).elapsedRealtime();
diff --git a/tests/unit/src/android/net/apf/ApfTestHelpers.kt b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
index ae225ebe..32ff8c9d 100644
--- a/tests/unit/src/android/net/apf/ApfTestHelpers.kt
+++ b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
@@ -28,12 +28,12 @@ import org.mockito.Mockito.clearInvocations
 import org.mockito.Mockito.timeout
 import org.mockito.Mockito.verify
 
-class ApfTestHelpers(apfInterpreterVersion: Int){
-    private val apfJniUtils = ApfJniUtils(apfInterpreterVersion)
+class ApfTestHelpers private constructor() {
     companion object {
         const val TIMEOUT_MS: Long = 1000
         const val PASS: Int = 1
         const val DROP: Int = 0
+        const val EXCEPTION: Int = 2
 
         // Interpreter will just accept packets without link layer headers, so pad fake packet to at
         // least the minimum packet size.
@@ -42,6 +42,7 @@ class ApfTestHelpers(apfInterpreterVersion: Int){
             return when (code) {
                 PASS -> "PASS"
                 DROP -> "DROP"
+                EXCEPTION -> "EXCEPTION"
                 else -> "UNKNOWN"
             }
         }
@@ -54,6 +55,63 @@ class ApfTestHelpers(apfInterpreterVersion: Int){
             assertEquals(label(expected), label(got))
         }
 
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            data: ByteArray?,
+            filterAge: Int
+        ) {
+            val msg = "Unexpected APF verdict. To debug: \n" + """
+                apf_run
+                    --program ${HexDump.toHexString(program)}
+                    --packet ${HexDump.toHexString(packet)}
+                    ${if (data != null) "--data ${HexDump.toHexString(data)}" else ""}
+                    --age $filterAge
+                    ${if (apfVersion > 4) "--v6" else ""}
+                    --trace | less
+            """.replace("\n", " ").replace("\\s+".toRegex(), " ") + "\n"
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, filterAge)
+            )
+        }
+
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            filterAge: Int
+        ) {
+            val msg = """Unexpected APF verdict. To debug:
+                apf_run
+                    --program ${HexDump.toHexString(program)}
+                    --packet ${HexDump.toHexString(packet)}
+                    --age $filterAge
+                    ${if (apfVersion > 4) " --v6" else ""}
+                    --trace " + " | less\n
+            """
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
+            )
+        }
+
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            gen: ApfV4Generator,
+            packet: ByteArray,
+            filterAge: Int
+        ) {
+            assertVerdict(apfVersion, expected, gen.generate(), packet, null, filterAge)
+        }
+
         /**
          * Checks the generated APF program equals to the expected value.
          */
@@ -85,283 +143,204 @@ class ApfTestHelpers(apfInterpreterVersion: Int){
             }
             return ret
         }
-    }
-
-    private fun assertVerdict(
-        apfVersion: Int,
-        expected: Int,
-        program: ByteArray,
-        packet: ByteArray,
-        filterAge: Int
-    ) {
-        val msg = """Unexpected APF verdict. To debug:
-                apf_run
-                    --program ${HexDump.toHexString(program)}
-                    --packet ${HexDump.toHexString(packet)}
-                    --age $filterAge
-                    ${if (apfVersion > 4) " --v6" else ""}
-                    --trace " + " | less\n
-            """
-        assertReturnCodesEqual(
-            msg,
-            expected,
-            apfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
-        )
-    }
 
-    @Throws(BaseApfGenerator.IllegalInstructionException::class)
-    private fun assertVerdict(
-        apfVersion: Int,
-        expected: Int,
-        gen: ApfV4Generator,
-        packet: ByteArray,
-        filterAge: Int
-    ) {
-        assertVerdict(apfVersion, expected, gen.generate(), packet, null, filterAge)
-    }
-
-    private fun assertVerdict(
-        apfVersion: Int,
-        expected: Int,
-        program: ByteArray,
-        packet: ByteArray,
-        data: ByteArray?,
-        filterAge: Int
-    ) {
-        val msg = "Unexpected APF verdict. To debug: \n" + """
-                apf_run
-                    --program ${HexDump.toHexString(program)}
-                    --packet ${HexDump.toHexString(packet)}
-                    ${if (data != null) "--data ${HexDump.toHexString(data)}" else ""}
-                    --age $filterAge
-                    ${if (apfVersion > 4) "--v6" else ""}
-                    --trace | less
-            """.replace("\n", " ").replace("\\s+".toRegex(), " ") + "\n"
-        assertReturnCodesEqual(
-            msg,
-            expected,
-            apfJniUtils.apfSimulate(apfVersion, program, packet, data, filterAge)
-        )
-    }
-
-    /**
-     * Runs the APF program with customized data region and checks the return code.
-     */
-    fun assertVerdict(
-        apfVersion: Int,
-        expected: Int,
-        program: ByteArray,
-        packet: ByteArray,
-        data: ByteArray?
-    ) {
-        assertVerdict(apfVersion, expected, program, packet, data, filterAge = 0)
-    }
+        /**
+         * Runs the APF program with customized data region and checks the return code.
+         */
+        fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            data: ByteArray?
+        ) {
+            assertVerdict(apfVersion, expected, program, packet, data, filterAge = 0)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is equals to expected value. If not, the
-     * customized message is printed.
-     */
-    fun assertVerdict(
-        apfVersion: Int,
-        msg: String,
-        expected: Int,
-        program: ByteArray?,
-        packet: ByteArray?,
-        filterAge: Int
-    ) {
-        assertReturnCodesEqual(
-            msg,
-            expected,
-            apfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
-        )
-    }
+        /**
+         * Runs the APF program and checks the return code is equals to expected value. If not, the
+         * customized message is printed.
+         */
+        @JvmStatic
+        fun assertVerdict(
+            apfVersion: Int,
+            msg: String,
+            expected: Int,
+            program: ByteArray?,
+            packet: ByteArray?,
+            filterAge: Int
+        ) {
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
+            )
+        }
 
-    /**
-     * Runs the APF program and checks the return code is equals to expected value.
-     */
-    fun assertVerdict(apfVersion: Int, expected: Int, program: ByteArray, packet: ByteArray) {
-        assertVerdict(apfVersion, expected, program, packet, 0)
-    }
+        /**
+         * Runs the APF program and checks the return code is equals to expected value.
+         */
+        @JvmStatic
+        fun assertVerdict(apfVersion: Int, expected: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, expected, program, packet, 0)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
-        assertVerdict(apfVersion, PASS, program, packet, filterAge)
-    }
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @JvmStatic
+        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, PASS, program, packet, filterAge)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray) {
-        assertVerdict(apfVersion, PASS, program, packet)
-    }
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @JvmStatic
+        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, PASS, program, packet)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
-        assertVerdict(apfVersion, DROP, program, packet, filterAge)
-    }
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, DROP, program, packet, filterAge)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray) {
-        assertVerdict(apfVersion, DROP, program, packet)
-    }
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, DROP, program, packet)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    @Throws(BaseApfGenerator.IllegalInstructionException::class)
-    fun assertPass(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
-        assertVerdict(apfVersion, PASS, gen, packet, filterAge)
-    }
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertPass(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, PASS, gen, packet, filterAge)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    @Throws(BaseApfGenerator.IllegalInstructionException::class)
-    fun assertDrop(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
-        assertVerdict(apfVersion, DROP, gen, packet, filterAge)
-    }
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, DROP, gen, packet, filterAge)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    @Throws(BaseApfGenerator.IllegalInstructionException::class)
-    fun assertPass(apfVersion: Int, gen: ApfV4Generator) {
-        assertVerdict(apfVersion, PASS, gen, ByteArray(MIN_PKT_SIZE), 0)
-    }
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertPass(apfVersion: Int, gen: ApfV4Generator) {
+            assertVerdict(apfVersion, PASS, gen, ByteArray(MIN_PKT_SIZE), 0)
+        }
 
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    @Throws(BaseApfGenerator.IllegalInstructionException::class)
-    fun assertDrop(apfVersion: Int, gen: ApfV4Generator) {
-        assertVerdict(apfVersion, DROP, gen, ByteArray(MIN_PKT_SIZE), 0)
-    }
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, gen: ApfV4Generator) {
+            assertVerdict(apfVersion, DROP, gen, ByteArray(MIN_PKT_SIZE), 0)
+        }
 
-    /**
-     * Runs the APF program and checks the return code and data regions
-     * equals to expected value.
-     */
-    @Throws(BaseApfGenerator.IllegalInstructionException::class, Exception::class)
-    fun assertDataMemoryContents(
-        apfVersion: Int,
-        expected: Int,
-        program: ByteArray?,
-        packet: ByteArray?,
-        data: ByteArray,
-        expectedData: ByteArray,
-        ignoreInterpreterVersion: Boolean
-    ) {
-        assertReturnCodesEqual(
-            expected,
-            apfJniUtils.apfSimulate(apfVersion, program, packet, data, 0)
-        )
+        /**
+         * Runs the APF program and checks the return code and data regions
+         * equals to expected value.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class, Exception::class)
+        @JvmStatic
+        fun assertDataMemoryContents(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray?,
+            packet: ByteArray?,
+            data: ByteArray,
+            expectedData: ByteArray,
+            ignoreInterpreterVersion: Boolean
+        ) {
+            assertReturnCodesEqual(
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, 0)
+            )
 
-        if (ignoreInterpreterVersion) {
-            val apfVersionIdx = (Counter.totalSize() +
-                    APF_VERSION.offset())
-            val apfProgramIdIdx = (Counter.totalSize() +
-                    APF_PROGRAM_ID.offset())
-            for (i in 0..3) {
-                data[apfVersionIdx + i] = 0
-                data[apfProgramIdIdx + i] = 0
+            if (ignoreInterpreterVersion) {
+                val apfVersionIdx = (Counter.totalSize() +
+                        APF_VERSION.offset())
+                val apfProgramIdIdx = (Counter.totalSize() +
+                        APF_PROGRAM_ID.offset())
+                for (i in 0..3) {
+                    data[apfVersionIdx + i] = 0
+                    data[apfProgramIdIdx + i] = 0
+                }
+            }
+            // assertArrayEquals() would only print one byte, making debugging difficult.
+            if (!expectedData.contentEquals(data)) {
+                throw Exception(
+                    ("\nprogram:     " + HexDump.toHexString(program) +
+                            "\ndata memory: " + HexDump.toHexString(data) +
+                            "\nexpected:    " + HexDump.toHexString(expectedData))
+                )
             }
         }
-        // assertArrayEquals() would only print one byte, making debugging difficult.
-        if (!expectedData.contentEquals(data)) {
-            throw Exception(
-                ("\nprogram:     " + HexDump.toHexString(program) +
-                        "\ndata memory: " + HexDump.toHexString(data) +
-                        "\nexpected:    " + HexDump.toHexString(expectedData))
-            )
-        }
-    }
 
-    fun verifyProgramRun(
-        version: Int,
-        program: ByteArray,
-        pkt: ByteArray,
-        targetCnt: Counter,
-        cntMap: MutableMap<Counter, Long> = mutableMapOf(),
-        dataRegion: ByteArray = ByteArray(Counter.totalSize()) { 0 },
-        incTotal: Boolean = true,
-        result: Int = if (targetCnt.name.startsWith("PASSED")) PASS else DROP
-    ) {
-        assertVerdict(version, result, program, pkt, dataRegion)
-        cntMap[targetCnt] = cntMap.getOrDefault(targetCnt, 0) + 1
-        if (incTotal) {
-            cntMap[TOTAL_PACKETS] = cntMap.getOrDefault(TOTAL_PACKETS, 0) + 1
+        fun verifyProgramRun(
+            version: Int,
+            program: ByteArray,
+            pkt: ByteArray,
+            targetCnt: Counter,
+            cntMap: MutableMap<Counter, Long> = mutableMapOf(),
+            dataRegion: ByteArray = ByteArray(Counter.totalSize()) { 0 },
+            incTotal: Boolean = true,
+            result: Int = if (targetCnt.name.startsWith("PASSED")) PASS else DROP
+        ) {
+            assertVerdict(version, result, program, pkt, dataRegion)
+            cntMap[targetCnt] = cntMap.getOrDefault(targetCnt, 0) + 1
+            if (incTotal) {
+                cntMap[TOTAL_PACKETS] = cntMap.getOrDefault(TOTAL_PACKETS, 0) + 1
+            }
+            val errMsg = "Counter is not increased properly. To debug: \n" +
+                    " apf_run --program ${HexDump.toHexString(program)} " +
+                    "--packet ${HexDump.toHexString(pkt)} " +
+                    "--data ${HexDump.toHexString(dataRegion)} --age 0 " +
+                    "${if (version == APF_VERSION_6) "--v6" else "" } --trace  | less \n"
+            assertEquals(cntMap, decodeCountersIntoMap(dataRegion), errMsg)
         }
-        val errMsg = "Counter is not increased properly. To debug: \n" +
-                " apf_run --program ${HexDump.toHexString(program)} " +
-                "--packet ${HexDump.toHexString(pkt)} " +
-                "--data ${HexDump.toHexString(dataRegion)} --age 0 " +
-                "${if (version == APF_VERSION_6) "--v6" else "" } --trace  | less \n"
-        assertEquals(cntMap, decodeCountersIntoMap(dataRegion), errMsg)
-    }
-
-    fun consumeInstalledProgram(
-        apfController: ApfFilter.IApfController,
-        installCnt: Int
-    ): ByteArray {
-        val programCaptor = ArgumentCaptor.forClass(
-            ByteArray::class.java
-        )
-
-        verify(apfController, timeout(TIMEOUT_MS).times(installCnt)).installPacketFilter(
-            programCaptor.capture(),
-            any()
-        )
 
-        clearInvocations<Any>(apfController)
-        return programCaptor.value
-    }
-
-    fun consumeTransmittedPackets(
-        expectCnt: Int
-    ): List<ByteArray> {
-        val transmittedPackets = apfJniUtils.getAllTransmittedPackets()
-        assertEquals(expectCnt, transmittedPackets.size)
-        resetTransmittedPacketMemory()
-        return transmittedPackets
-    }
-
-    fun resetTransmittedPacketMemory() {
-        apfJniUtils.resetTransmittedPacketMemory()
-    }
-
-    fun disassembleApf(program: ByteArray): Array<String> {
-        return apfJniUtils.disassembleApf(program)
-    }
-
-    fun getAllTransmittedPackets(): List<ByteArray> {
-        return apfJniUtils.allTransmittedPackets
-    }
+        @JvmStatic
+        fun consumeInstalledProgram(
+            apfController: ApfFilter.IApfController,
+            installCnt: Int
+        ): ByteArray {
+            val programCaptor = ArgumentCaptor.forClass(
+                ByteArray::class.java
+            )
 
-    fun compareBpfApf(
-        apfVersion: Int,
-        filter: String,
-        pcapFilename: String,
-        apfProgram: ByteArray
-    ): Boolean {
-        return apfJniUtils.compareBpfApf(apfVersion, filter, pcapFilename, apfProgram)
-    }
+            verify(apfController, timeout(TIMEOUT_MS).times(installCnt)).installPacketFilter(
+                programCaptor.capture(),
+                any()
+            )
 
-    fun compileToBpf(filter: String): String {
-        return apfJniUtils.compileToBpf(filter)
-    }
+            clearInvocations<Any>(apfController)
+            return programCaptor.value
+        }
 
-    fun dropsAllPackets(
-        apfVersion: Int,
-        program: ByteArray,
-        data: ByteArray,
-        pcapFilename: String
-    ): Boolean {
-        return apfJniUtils.dropsAllPackets(apfVersion, program, data, pcapFilename)
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
diff --git a/tests/unit/src/android/net/dhcp6/Dhcp6PacketTest.kt b/tests/unit/src/android/net/dhcp6/Dhcp6PacketTest.kt
index 8e100e4c..2aec48fb 100644
--- a/tests/unit/src/android/net/dhcp6/Dhcp6PacketTest.kt
+++ b/tests/unit/src/android/net/dhcp6/Dhcp6PacketTest.kt
@@ -19,6 +19,10 @@ package android.net.dhcp6
 import androidx.test.filters.SmallTest
 import androidx.test.runner.AndroidJUnit4
 import com.android.net.module.util.HexDump
+import com.android.net.module.util.dhcp6.Dhcp6AdvertisePacket
+import com.android.net.module.util.dhcp6.Dhcp6Packet
+import com.android.net.module.util.dhcp6.Dhcp6ReplyPacket
+import com.android.net.module.util.dhcp6.Dhcp6SolicitPacket
 import com.android.testutils.assertThrows
 import kotlin.test.assertEquals
 import kotlin.test.assertTrue
@@ -230,10 +234,10 @@ class Dhcp6PacketTest {
         val bytes = HexDump.hexStringToByteArray(replyHex)
         val packet = Dhcp6Packet.decode(bytes, bytes.size)
         assertTrue(packet is Dhcp6ReplyPacket)
-        assertEquals(0, packet.mPrefixDelegation.iaid)
-        assertEquals(0, packet.mPrefixDelegation.t1)
-        assertEquals(0, packet.mPrefixDelegation.t2)
-        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.mStatusCode)
+        assertEquals(0, packet.getPrefixDelegation().iaid)
+        assertEquals(0, packet.getPrefixDelegation().t1)
+        assertEquals(0, packet.getPrefixDelegation().t2)
+        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getStatusCode())
     }
 
     @Test
@@ -258,10 +262,10 @@ class Dhcp6PacketTest {
         val bytes = HexDump.hexStringToByteArray(replyHex)
         val packet = Dhcp6Packet.decode(bytes, bytes.size)
         assertTrue(packet is Dhcp6ReplyPacket)
-        assertEquals(0, packet.mPrefixDelegation.iaid)
-        assertEquals(0, packet.mPrefixDelegation.t1)
-        assertEquals(0, packet.mPrefixDelegation.t2)
-        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.mStatusCode)
+        assertEquals(0, packet.getPrefixDelegation().iaid)
+        assertEquals(0, packet.getPrefixDelegation().t1)
+        assertEquals(0, packet.getPrefixDelegation().t2)
+        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getStatusCode())
     }
 
     @Test
@@ -286,10 +290,10 @@ class Dhcp6PacketTest {
         val bytes = HexDump.hexStringToByteArray(replyHex)
         val packet = Dhcp6Packet.decode(bytes, bytes.size)
         assertTrue(packet is Dhcp6ReplyPacket)
-        assertEquals(0, packet.mPrefixDelegation.iaid)
-        assertEquals(0, packet.mPrefixDelegation.t1)
-        assertEquals(0, packet.mPrefixDelegation.t2)
-        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.mPrefixDelegation.statusCode)
+        assertEquals(0, packet.getPrefixDelegation().iaid)
+        assertEquals(0, packet.getPrefixDelegation().t1)
+        assertEquals(0, packet.getPrefixDelegation().t2)
+        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getPrefixDelegation().statusCode)
     }
 
     @Test
@@ -312,10 +316,10 @@ class Dhcp6PacketTest {
         val bytes = HexDump.hexStringToByteArray(replyHex)
         val packet = Dhcp6Packet.decode(bytes, bytes.size)
         assertTrue(packet is Dhcp6ReplyPacket)
-        assertEquals(0, packet.mPrefixDelegation.iaid)
-        assertEquals(0, packet.mPrefixDelegation.t1)
-        assertEquals(0, packet.mPrefixDelegation.t2)
-        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.mPrefixDelegation.statusCode)
+        assertEquals(0, packet.getPrefixDelegation().iaid)
+        assertEquals(0, packet.getPrefixDelegation().t1)
+        assertEquals(0, packet.getPrefixDelegation().t2)
+        assertEquals(Dhcp6Packet.STATUS_NO_PREFIX_AVAIL, packet.getPrefixDelegation().statusCode)
     }
 
     @Test
diff --git a/tests/unit/src/android/net/ip/IpClientTest.java b/tests/unit/src/android/net/ip/IpClientTest.java
index 1527714d..8d3b09d0 100644
--- a/tests/unit/src/android/net/ip/IpClientTest.java
+++ b/tests/unit/src/android/net/ip/IpClientTest.java
@@ -25,12 +25,15 @@ import static android.system.OsConstants.IFA_F_PERMANENT;
 import static android.system.OsConstants.IFA_F_TENTATIVE;
 import static android.system.OsConstants.RT_SCOPE_UNIVERSE;
 
+import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION;
+import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_PIO;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWLINK;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTPROT_KERNEL;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_DELROUTE;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWADDR;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWNDUSEROPT;
+import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWPREFIX;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWROUTE;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTN_UNICAST;
 import static com.android.net.module.util.netlink.StructNlMsgHdr.NLM_F_ACK;
@@ -45,8 +48,11 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.contains;
+import static org.mockito.ArgumentMatchers.longThat;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
+import static org.mockito.Mockito.anyLong;
 import static org.mockito.Mockito.anyString;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doReturn;
@@ -64,6 +70,7 @@ import static java.util.Collections.emptySet;
 
 import android.annotation.SuppressLint;
 import android.app.AlarmManager;
+import android.app.AlarmManager.OnAlarmListener;
 import android.content.ContentResolver;
 import android.content.Context;
 import android.content.pm.PackageManager;
@@ -80,6 +87,7 @@ import android.net.RouteInfo;
 import android.net.apf.ApfCapabilities;
 import android.net.apf.ApfFilter;
 import android.net.apf.ApfFilter.ApfConfiguration;
+import android.net.dhcp6.Dhcp6Client;
 import android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
 import android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor.INetlinkMessageProcessor;
 import android.net.ipmemorystore.NetworkAttributes;
@@ -89,6 +97,9 @@ import android.net.shared.Layer2Information;
 import android.net.shared.ProvisioningConfiguration;
 import android.net.shared.ProvisioningConfiguration.ScanResultInfo;
 import android.os.Build;
+import android.os.Handler;
+import android.os.SystemClock;
+import android.stats.connectivity.NetworkQuirkEvent;
 import android.system.OsConstants;
 
 import androidx.test.filters.SmallTest;
@@ -99,14 +110,17 @@ import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.netlink.NduseroptMessage;
 import com.android.net.module.util.netlink.RtNetlinkAddressMessage;
 import com.android.net.module.util.netlink.RtNetlinkLinkMessage;
+import com.android.net.module.util.netlink.RtNetlinkPrefixMessage;
 import com.android.net.module.util.netlink.RtNetlinkRouteMessage;
 import com.android.net.module.util.netlink.StructIfaddrMsg;
 import com.android.net.module.util.netlink.StructIfinfoMsg;
 import com.android.net.module.util.netlink.StructNdOptRdnss;
 import com.android.net.module.util.netlink.StructNlMsgHdr;
+import com.android.net.module.util.netlink.StructPrefixMsg;
 import com.android.net.module.util.netlink.StructRtMsg;
 import com.android.networkstack.R;
 import com.android.networkstack.ipmemorystore.IpMemoryStoreService;
+import com.android.networkstack.metrics.NetworkQuirkMetrics;
 import com.android.server.NetworkStackService;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRule.IgnoreAfter;
@@ -135,7 +149,6 @@ import java.util.List;
 import java.util.Random;
 import java.util.Set;
 
-
 /**
  * Tests for IpClient.
  */
@@ -159,6 +172,8 @@ public class IpClientTest {
     private static final String TEST_SSID = "test_ssid";
     private static final String TEST_BSSID = "00:11:22:33:44:55";
     private static final String TEST_BSSID2 = "00:1A:11:22:33:44";
+    private static final byte TEST_PIO_FLAGS_P_UNSET = (byte) 0xC0; // L=1,A=1,R=0,P=0
+    private static final byte TEST_PIO_FLAGS_P_SET = (byte) 0xD0; // L=1,A=1,R=0,P=1
 
     private static final String TEST_GLOBAL_ADDRESS = "1234:4321::548d:2db2:4fcf:ef75/64";
     private static final String[] TEST_LOCAL_ADDRESSES = {
@@ -194,6 +209,8 @@ public class IpClientTest {
     @Mock private IpClientNetlinkMonitor mNetlinkMonitor;
     @Mock private PackageManager mPackageManager;
     @Mock private ApfFilter mApfFilter;
+    @Mock private Dhcp6Client mDhcp6Client;
+    @Mock private NetworkQuirkMetrics mQuirkMetrics;
 
     private InterfaceParams mIfParams;
     private INetlinkMessageProcessor mNetlinkMessageProcessor;
@@ -219,6 +236,8 @@ public class IpClientTest {
         when(mDependencies.makeIpClientNetlinkMonitor(
                 any(), any(), any(), anyInt(), anyBoolean(), any())).thenReturn(mNetlinkMonitor);
         when(mNetlinkMonitor.start()).thenReturn(true);
+        when(mDependencies.makeDhcp6Client(any(), any(), any(), any())).thenReturn(mDhcp6Client);
+        when(mDependencies.getNetworkQuirkMetrics()).thenReturn(mQuirkMetrics);
         doReturn(mPackageManager).when(mContext).getPackageManager();
         doReturn(true).when(mDependencies).isFeatureNotChickenedOut(mContext, APF_ENABLE);
 
@@ -331,6 +350,17 @@ public class IpClientTest {
         return RtNetlinkLinkMessage.build(nlmsghdr, ifInfoMsg, 0 /* mtu */, TEST_MAC, ifaceName);
     }
 
+    private static RtNetlinkPrefixMessage buildRtmPrefixMessage(final IpPrefix prefix, byte flags,
+            long preferred, long valid) {
+        final StructNlMsgHdr nlmsghdr = makeNetlinkMessageHeader(RTM_NEWPREFIX, (short) 0);
+        final StructPrefixMsg prefixmsg =
+                new StructPrefixMsg((short) OsConstants.AF_INET6 /* family */, TEST_IFINDEX,
+                        (short) ICMPV6_ND_OPTION_PIO /* type */,
+                        (short) prefix.getPrefixLength(),
+                        (short) flags);
+        return new RtNetlinkPrefixMessage(nlmsghdr, prefixmsg, prefix, preferred, valid);
+    }
+
     private void onInterfaceAddressUpdated(final LinkAddress la, int flags) {
         final RtNetlinkAddressMessage msg =
                 buildRtmAddressMessage(RTM_NEWADDR, la, TEST_IFINDEX, flags);
@@ -357,6 +387,11 @@ public class IpClientTest {
         mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
     }
 
+    private void onNewPrefix(final IpPrefix prefix, byte flags, long preferred, long valid) {
+        final RtNetlinkPrefixMessage msg = buildRtmPrefixMessage(prefix, flags, preferred, valid);
+        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
+    }
+
     @Test
     public void testNullInterfaceNameMostDefinitelyThrows() throws Exception {
         setTestInterfaceParams(null);
@@ -958,6 +993,25 @@ public class IpClientTest {
         verifyShutdown(ipc);
     }
 
+    @Test
+    public void testApfForceDisable() throws Exception {
+        doReturn(false).when(mDependencies).isFeatureNotChickenedOut(mContext, APF_ENABLE);
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        ProvisioningConfiguration.Builder config = new ProvisioningConfiguration.Builder()
+                .withoutIPv4()
+                .withoutIpReachabilityMonitor()
+                .withInitialConfiguration(
+                        conf(links(TEST_LOCAL_ADDRESSES), prefixes(TEST_PREFIXES), ips()))
+                .withApfCapabilities(
+                        new ApfCapabilities(3 /* version */, 2048 /* maxProgramSize */,
+                                ARPHRD_ETHER));
+        ipc.startProvisioning(config.build());
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).maybeCreateApfFilter(
+                any(), any(), any(), any(), any(), any());
+        verifyShutdown(ipc);
+    }
+
     @Test
     public void testDumpApfFilter_withNoException() throws Exception {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
@@ -1004,6 +1058,23 @@ public class IpClientTest {
         verifyShutdown(ipc);
     }
 
+    @Test
+    public void testApfUpdateCapabilities_newApfCapabilitiesWithVersionZero() throws Exception {
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
+                true /* isApfSupported */);
+        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
+        assertEquals(4096, config.apfRamSize);
+        clearInvocations(mDependencies);
+
+        ipc.updateApfCapabilities(
+                new ApfCapabilities(0 /* version */, 0 /* maxProgramSize */, ARPHRD_ETHER));
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).maybeCreateApfFilter(any(), any(), any(), any(), any(),
+                any());
+        verifyShutdown(ipc);
+    }
+
     @Test
     public void testApfUpdateCapabilities_raceBetweenStopAndStartIpClient() throws Exception {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
@@ -1263,6 +1334,278 @@ public class IpClientTest {
         ipc.shutdown();
     }
 
+    private OnAlarmListener verifyPrefixLifetimeAlarmSet(long afterSeconds, Handler handler) {
+        final long when = SystemClock.elapsedRealtime() + afterSeconds * 1000;
+        final long min = when - 1 * 1000;
+        final long max = when + 1 * 1000;
+        ArgumentCaptor<OnAlarmListener> captor = ArgumentCaptor.forClass(OnAlarmListener.class);
+        verify(mAlarm).setExact(
+                eq(AlarmManager.ELAPSED_REALTIME_WAKEUP),
+                longThat(x -> x >= min && x <= max),
+                contains("DHCPV6PDPREFERRED"),
+                captor.capture(),
+                eq(handler));
+        return captor.getValue();
+    }
+
+    private void verifyPrefixLifetimeAlarmNeverSet(Handler handler) {
+        verify(mAlarm, never()).setExact(
+                eq(AlarmManager.ELAPSED_REALTIME_WAKEUP),
+                anyLong(),
+                contains("DHCPV6PDPREFERRED"),
+                any(),
+                eq(handler));
+    }
+
+    private IpClient prepareDhcp6PdPreferredFlagTest() throws Exception {
+        doReturn(true).when(mDependencies)
+                .isFeatureEnabled(any(), eq(IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION));
+        return doProvisioningWithDefaultConfiguration();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_prefixWithPFlagButZeroPreferredLft() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 0 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmNeverSet(handler);
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_quirkMetricLogged() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 1000 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mQuirkMetrics).setEvent(NetworkQuirkEvent.QE_DHCP6_PFLAG_TRIGGERED);
+        verify(mQuirkMetrics).statsWrite();
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_prefixWithPFlagAndUpdatePreferredLftLater()
+            throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 1000 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mDependencies);
+
+        // Trigger PIO update with the same preifx with a new non-zero preferred lifetime.
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 2000 /* preferred */, 2500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(2000, handler);
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_prefixWithPFlagAndPreferredLftDecreaseToZero()
+            throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 1000 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mDependencies);
+
+        // Trigger PIO update with the same prefix but with zero preferred lifetime, this
+        // should remove the prefix from the list and stop Dhcp6Client, no crash should
+        // happen.
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 0 /* preferred */, 2500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_prefixWithPFlagAndPFlagDisappearsLater()
+            throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 1000 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mDependencies);
+
+        // Trigger PIO update with the same prefix but P bit disappears later, this
+        // should remove the prefix from the list and stop Dhcp6Client, no crash should
+        // happen.
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_UNSET, 2000 /* preferred */, 2500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_multiplePrefixesWithPFlag() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix1 = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix1, TEST_PIO_FLAGS_P_SET, 1000 /* preferred */, 1500 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mDependencies);
+
+        // Add a second prefix with P flag but shorter preferred lifetime, verify the alarm
+        // updates with the shorter lifetime(500).
+        final IpPrefix prefix2 = new IpPrefix("2002:db8:1:2::/64");
+        onNewPrefix(prefix2, TEST_PIO_FLAGS_P_SET, 500 /* preferred */, 750 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(500, handler);
+
+        clearInvocations(mAlarm);
+
+        // Update prefix2 preferred lifetime to a larger value (1500), verify the alarm changes
+        // back to previous minimum value (1000).
+        onNewPrefix(prefix2, TEST_PIO_FLAGS_P_SET, 1500 /* preferred */, 2000 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mAlarm);
+
+        // Add a third prefix without P flag, verify the alarm does not change.
+        final IpPrefix prefix3 = new IpPrefix("2003:db8:1:2::/64");
+        onNewPrefix(prefix3, TEST_PIO_FLAGS_P_UNSET, 2000 /* preferred */, 3000 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verifyPrefixLifetimeAlarmSet(1000, handler);
+
+        clearInvocations(mAlarm);
+
+        // Update prefix1 preferred lifetime to 0, then prefix1 should be removed from the prefix
+        // list, verify the alarm changes back to prefix2 preferred lifetime given that's the only
+        // prefix left in the list, and Dhcp6Client doesn't stop neither.
+        onNewPrefix(prefix1, TEST_PIO_FLAGS_P_SET, 0 /* preferred */, 2000 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verifyPrefixLifetimeAlarmSet(1500, handler);
+
+        clearInvocations(mAlarm);
+
+        // Update prefix2 without P flag, verify the alarm should be cancelled and Dhcp6Client
+        // should stop as well.
+        onNewPrefix(prefix2, TEST_PIO_FLAGS_P_UNSET, 1500 /* preferred */, 2000 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verifyPrefixLifetimeAlarmNeverSet(handler);
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_prefixExpiresAndRestartClient() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix1 = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix1, TEST_PIO_FLAGS_P_SET, 5 /* preferred */, 10 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        final OnAlarmListener alarm = verifyPrefixLifetimeAlarmSet(5, handler);
+
+        clearInvocations(mDependencies);
+        clearInvocations(mAlarm);
+
+        // Wait until the prefix1 expires.
+        Thread.sleep(5000);
+
+        // Trigger prefix expiration. The prefix is removed from the list and the alarm
+        // is not rescheduled.
+        handler.post(() -> alarm.onAlarm());
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        // Simulate the RunningState handles the Dhcp6Client.CMD_ON_QUIT.
+        ipc.sendMessage(Dhcp6Client.CMD_ON_QUIT);
+        verifyPrefixLifetimeAlarmNeverSet(handler);
+
+        clearInvocations(mAlarm);
+
+        // Add a second prefix with P flag, verify the client restarts without crash.
+        final IpPrefix prefix2 = new IpPrefix("2002:db8:1:2::/64");
+        onNewPrefix(prefix2, TEST_PIO_FLAGS_P_SET, 500 /* preferred */, 750 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(500, handler);
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_twoPrefixesExpire() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        final IpPrefix prefix1 = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix1, TEST_PIO_FLAGS_P_SET, 10 /* preferred */, 20 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies).makeDhcp6Client(any(), any(), any(), any());
+        final OnAlarmListener alarm = verifyPrefixLifetimeAlarmSet(10, handler);
+
+        clearInvocations(mDependencies);
+
+        final IpPrefix prefix2 = new IpPrefix("2002:db8:1:2::/64");
+        onNewPrefix(prefix2, TEST_PIO_FLAGS_P_SET, 5 /* preferred */, 10 /* valid */);
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, never()).makeDhcp6Client(any(), any(), any(), any());
+        verifyPrefixLifetimeAlarmSet(5, handler);
+
+        clearInvocations(mAlarm);
+
+        // Wait until prefix1 expires.
+        Thread.sleep(5000);
+
+        // Trigger prefix2 expiration, and the alarm changes back to prefix1 lifetime.
+        handler.post(() -> alarm.onAlarm());
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verifyPrefixLifetimeAlarmSet(5, handler);
+
+        ipc.shutdown();
+    }
+
+    @Test
+    public void testDhcp6PdPreferredFlag_raceBetweenStartAndStopDhcp6Client() throws Exception {
+        final IpClient ipc = prepareDhcp6PdPreferredFlagTest();
+        final Handler handler = ipc.getHandler();
+
+        // Add/remove the prefix to/from the prefix list with P flag multiple times, and verify
+        // that no crash happens.
+        final IpPrefix prefix = new IpPrefix("2001:db8:1:2::/64");
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 100 /* preferred */, 200 /* valid */);
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_UNSET, 100 /* preferred */, 200 /* valid */);
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_SET, 100 /* preferred */, 200 /* valid */);
+        onNewPrefix(prefix, TEST_PIO_FLAGS_P_UNSET, 100 /* preferred */, 200 /* valid */);
+
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        verify(mDependencies, times(1)).makeDhcp6Client(any(), any(), any(), any());
+
+        ipc.shutdown();
+    }
+
     interface Fn<A,B> {
         B call(A a) throws Exception;
     }
diff --git a/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java b/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
index 3e23a149..2660d7b0 100644
--- a/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
+++ b/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
@@ -16,6 +16,19 @@
 
 package com.android.networkstack.metrics;
 
+import static android.net.apf.ApfCounterTracker.Counter.CORRUPT_DNS_PACKET;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_NON_UNICAST_TDLS;
+import static android.net.apf.ApfCounterTracker.Counter.EXCEPTIONS;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ALLOCATE_FAILURE;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_RA;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_TRANSMIT_FAILURE;
+import static android.stats.connectivity.CounterName.CN_CORRUPT_DNS_PACKET;
+import static android.stats.connectivity.CounterName.CN_DROPPED_NON_UNICAST_TDLS;
+import static android.stats.connectivity.CounterName.CN_EXCEPTIONS;
+import static android.stats.connectivity.CounterName.CN_PASSED_ALLOCATE_FAILURE;
+import static android.stats.connectivity.CounterName.CN_PASSED_RA;
+import static android.stats.connectivity.CounterName.CN_PASSED_TRANSMIT_FAILURE;
+
 import static org.junit.Assert.assertEquals;
 
 import android.net.apf.ApfCounterTracker.Counter;
@@ -176,5 +189,11 @@ public class ApfSessionInfoMetricsTest {
         verifyCounterName(Counter.DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED,
                 CounterName.CN_DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED);
         verifyCounterName(Counter.DROPPED_IGMP_REPORT, CounterName.CN_DROPPED_IGMP_REPORT);
+        verifyCounterName(PASSED_ALLOCATE_FAILURE, CN_PASSED_ALLOCATE_FAILURE);
+        verifyCounterName(PASSED_TRANSMIT_FAILURE, CN_PASSED_TRANSMIT_FAILURE);
+        verifyCounterName(CORRUPT_DNS_PACKET, CN_CORRUPT_DNS_PACKET);
+        verifyCounterName(EXCEPTIONS, CN_EXCEPTIONS);
+        verifyCounterName(PASSED_RA, CN_PASSED_RA);
+        verifyCounterName(DROPPED_NON_UNICAST_TDLS, CN_DROPPED_NON_UNICAST_TDLS);
     }
 }
diff --git a/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt b/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
index 7f99aca3..8207744f 100644
--- a/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
+++ b/tests/unit/src/com/android/networkstack/util/ProcfsParsingUtilsTest.kt
@@ -16,9 +16,9 @@
 package com.android.networkstack.util
 
 import android.net.MacAddress
-import android.net.apf.ProcfsParsingUtils
 import androidx.test.filters.SmallTest
 import com.android.net.module.util.HexDump
+import com.android.net.module.util.ProcfsParsingUtils
 import java.net.Inet4Address
 import java.net.Inet6Address
 import java.net.InetAddress
diff --git a/tests/unit/src/com/android/server/connectivity/FakeDns.java b/tests/unit/src/com/android/server/connectivity/FakeDns.java
index 2f16e234..0052e6fc 100644
--- a/tests/unit/src/com/android/server/connectivity/FakeDns.java
+++ b/tests/unit/src/com/android/server/connectivity/FakeDns.java
@@ -60,6 +60,8 @@ import java.util.concurrent.TimeoutException;
  */
 public class FakeDns {
     private static final int HANDLER_TIMEOUT_MS = 1000;
+    public static final int QUERY_FLAGS_ANY = -1;
+    public static final int QUERY_FLAGS_NONE = 0;
 
     @NonNull
     private final Network mNetwork;
@@ -78,15 +80,18 @@ public class FakeDns {
         final String mHostname;
         final int mType;
         final AnswerSupplier mAnswerSupplier;
-        DnsEntry(String host, int type, AnswerSupplier answerSupplier) {
+        final int mFlags;
+        DnsEntry(String host, int type, int flags, AnswerSupplier answerSupplier) {
             mHostname = host;
             mType = type;
             mAnswerSupplier = answerSupplier;
+            mFlags = flags;
         }
         // Full match or partial match that target host contains the entry hostname to support
         // random private dns probe hostname.
-        private boolean matches(String hostname, int type) {
-            return hostname.endsWith(mHostname) && type == mType;
+        private boolean matches(String hostname, int type, int flags) {
+            return hostname.endsWith(mHostname) && type == mType
+                    && (mFlags == QUERY_FLAGS_ANY || mFlags == flags);
         }
     }
 
@@ -122,7 +127,7 @@ public class FakeDns {
 
     /** Returns the answer for a given name and type on the given mock network. */
     private CompletableFuture<String[]> getAnswer(Network mockNetwork, String hostname,
-            int type) {
+            int type, int flags) {
         if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
             return CompletableFuture.completedFuture(null);
         }
@@ -131,7 +136,7 @@ public class FakeDns {
 
         synchronized (mAnswers) {
             answerSupplier = mAnswers.stream()
-                    .filter(e -> e.matches(hostname, type))
+                    .filter(e -> e.matches(hostname, type, flags))
                     .map(answer -> answer.mAnswerSupplier).findFirst().orElse(null);
         }
         if (answerSupplier == null) {
@@ -161,10 +166,15 @@ public class FakeDns {
 
     /** Sets the answer for a given name and type. */
     public void setAnswer(String hostname, AnswerSupplier answerSupplier, int type) {
-        DnsEntry record = new DnsEntry(hostname, type, answerSupplier);
+        setAnswer(hostname, answerSupplier, type, QUERY_FLAGS_ANY);
+    }
+
+    /** Sets the answer for a given name, type and flags. */
+    public void setAnswer(String hostname, AnswerSupplier answerSupplier, int type, int flags) {
+        DnsEntry record = new DnsEntry(hostname, type, flags, answerSupplier);
         synchronized (mAnswers) {
             // Remove the existing one.
-            mAnswers.removeIf(entry -> entry.matches(hostname, type));
+            mAnswers.removeIf(entry -> entry.matches(hostname, type, flags));
             // Add or replace a new record.
             mAnswers.add(record);
         }
@@ -184,8 +194,8 @@ public class FakeDns {
             throws UnknownHostException {
         final List<InetAddress> answer;
         try {
-            answer = stringsToInetAddresses(queryAllTypes(mockNetwork, hostname).get(
-                    HANDLER_TIMEOUT_MS, TimeUnit.MILLISECONDS));
+            answer = stringsToInetAddresses(queryAllTypes(mockNetwork, hostname, QUERY_FLAGS_NONE)
+                    .get(HANDLER_TIMEOUT_MS, TimeUnit.MILLISECONDS));
         } catch (ExecutionException | InterruptedException | TimeoutException e) {
             throw new AssertionError("No mock DNS reply within timeout", e);
         }
@@ -198,16 +208,16 @@ public class FakeDns {
     // Regardless of the type, depends on what the responses contained in the network.
     @SuppressWarnings("FutureReturnValueIgnored")
     private CompletableFuture<String[]> queryAllTypes(
-            Network mockNetwork, String hostname) {
+            Network mockNetwork, String hostname, int flags) {
         if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
             return CompletableFuture.completedFuture(null);
         }
 
         final CompletableFuture<String[]> aFuture =
-                getAnswer(mockNetwork, hostname, TYPE_A)
+                getAnswer(mockNetwork, hostname, TYPE_A, flags)
                         .exceptionally(e -> new String[0]);
         final CompletableFuture<String[]> aaaaFuture =
-                getAnswer(mockNetwork, hostname, TYPE_AAAA)
+                getAnswer(mockNetwork, hostname, TYPE_AAAA, flags)
                         .exceptionally(e -> new String[0]);
 
         final CompletableFuture<String[]> combinedFuture = new CompletableFuture<>();
@@ -223,27 +233,27 @@ public class FakeDns {
     /** Starts mocking DNS queries. */
     public void startMocking() throws UnknownHostException {
         // Queries on mNetwork using getAllByName.
-        doAnswer(invocation -> {
-            return getAllByName((Network) invocation.getMock(), invocation.getArgument(0));
-        }).when(mNetwork).getAllByName(any());
+        doAnswer(invocation ->
+                getAllByName((Network) invocation.getMock(), invocation.getArgument(0))
+        ).when(mNetwork).getAllByName(any());
 
         // Queries on mCleartextDnsNetwork using DnsResolver#query.
-        doAnswer(invocation -> {
-            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
-                    3 /* posExecutor */, 5 /* posCallback */, -1 /* posType */);
-        }).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());
+        doAnswer(invocation ->
+                mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    3 /* posExecutor */, 5 /* posCallback */, -1 /* posType */, 2 /* posFlags */)
+        ).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());
 
         // Queries on mCleartextDnsNetwork using DnsResolver#query with QueryType.
-        doAnswer(invocation -> {
-            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
-                    4 /* posExecutor */, 6 /* posCallback */, 2 /* posType */);
-        }).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());
+        doAnswer(invocation ->
+                mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    4 /* posExecutor */, 6 /* posCallback */, 2 /* posType */, 3 /* posFlags */)
+        ).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());
 
         // Queries using rawQuery. Currently, mockQuery only supports TYPE_SVCB.
-        doAnswer(invocation -> {
-            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
-                    5 /* posExecutor */, 7 /* posCallback */, 3 /* posType */);
-        }).when(mDnsResolver).rawQuery(any(), any(), anyInt(), anyInt(), anyInt(), any(),
+        doAnswer(invocation ->
+                mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    5 /* posExecutor */, 7 /* posCallback */, 3 /* posType */, 4 /* posFlags */)
+        ).when(mDnsResolver).rawQuery(any(), any(), anyInt(), anyInt(), anyInt(), any(),
                 any(), any());
     }
 
@@ -259,15 +269,16 @@ public class FakeDns {
     // Mocks all the DnsResolver query methods used in this test.
     @SuppressWarnings("FutureReturnValueIgnored")
     private Answer mockQuery(InvocationOnMock invocation, int posNetwork, int posHostname,
-            int posExecutor, int posCallback, int posType) {
+            int posExecutor, int posCallback, int posType, int posFlags) {
         String hostname = invocation.getArgument(posHostname);
         Executor executor = invocation.getArgument(posExecutor);
         Network network = invocation.getArgument(posNetwork);
         DnsResolver.Callback callback = invocation.getArgument(posCallback);
 
+        final int flags = invocation.getArgument(posFlags);
         final CompletableFuture<String[]> answerFuture = (posType != -1)
-                ? getAnswer(network, hostname, invocation.getArgument(posType))
-                : queryAllTypes(network, hostname);
+                ? getAnswer(network, hostname, invocation.getArgument(posType), flags)
+                : queryAllTypes(network, hostname, flags);
 
         answerFuture.whenComplete((answer, exception) -> {
             new Handler(Looper.getMainLooper()).post(() -> executor.execute(() -> {
diff --git a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
index e9bd6166..809824eb 100644
--- a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
+++ b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
@@ -72,6 +72,8 @@ import static com.android.networkstack.util.NetworkStackUtils.DNS_DDR_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.DNS_PROBE_PRIVATE_IP_NO_INTERNET_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION;
 import static com.android.networkstack.util.NetworkStackUtils.REEVALUATE_WHEN_RESUME;
+import static com.android.server.connectivity.DdrTracker.FLAG_TRY_ALL_SERVERS;
+import static com.android.server.connectivity.FakeDns.QUERY_FLAGS_NONE;
 import static com.android.server.connectivity.NetworkMonitor.CONFIG_ASYNC_PRIVDNS_PROBE_TIMEOUT_MS;
 import static com.android.server.connectivity.NetworkMonitor.INITIAL_REEVALUATE_DELAY_MS;
 import static com.android.server.connectivity.NetworkMonitor.extractCharset;
@@ -408,6 +410,10 @@ public class NetworkMonitorTest {
             }
             return null;
         }).when(mDependencies).onExecutorServiceCreated(any());
+        doAnswer(invocation -> {
+            waitForSerialProbes(invocation.getArgument(0));
+            return null;
+        }).when(mDependencies).sleep(anyInt());
         doReturn(mValidationLogger).when(mValidationLogger).forSubComponent(any());
 
         doReturn(mCleartextDnsNetwork).when(mNetwork).getPrivateDnsBypassingCopy();
@@ -2455,7 +2461,8 @@ public class NetworkMonitorTest {
                 + "ipv6hint=2001:db8::100 dohpath=/dns-query{?dns}";
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
-        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb1, svcb2 }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.resolver.arpa", () -> new String[] { svcb1, svcb2 }, TYPE_SVCB,
+                FLAG_TRY_ALL_SERVERS);
 
         WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
         wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
@@ -2500,9 +2507,12 @@ public class NetworkMonitorTest {
                 + "ipv6hint=2001:db8::1,2001:db8::100 dohpath=/dns-query{?dns}";
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
-        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb2 }, TYPE_SVCB);
-        mFakeDns.setAnswer("_dns.dot.google", new String[] { svcb1 }, TYPE_SVCB);
-        mFakeDns.setAnswer("_dns.doh.google", new String[] { svcb2 }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.resolver.arpa", () -> new String[] { svcb2 }, TYPE_SVCB,
+                FLAG_TRY_ALL_SERVERS);
+        mFakeDns.setAnswer("_dns.dot.google", () -> new String[] { svcb1 }, TYPE_SVCB,
+                QUERY_FLAGS_NONE);
+        mFakeDns.setAnswer("_dns.doh.google", () -> new String[] { svcb2 }, TYPE_SVCB,
+                QUERY_FLAGS_NONE);
         mFakeDns.setAnswer("dot.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
         mFakeDns.setAnswer("doh.google", new String[] { "2001:db8::854" }, TYPE_AAAA);
 
@@ -2554,8 +2564,10 @@ public class NetworkMonitorTest {
         final String svcb = "1 doh.google alpn=h2 ipv4hint=192.0.2.100 dohpath=/dns-query{?dns}";
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
-        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb }, TYPE_SVCB);
-        mFakeDns.setAnswer("_dns.dns.google", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.resolver.arpa", () -> new String[] { svcb }, TYPE_SVCB,
+                FLAG_TRY_ALL_SERVERS);
+        mFakeDns.setAnswer("_dns.dns.google", () -> new String[] { svcb }, TYPE_SVCB,
+                QUERY_FLAGS_NONE);
         mFakeDns.setAnswer("dns.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
 
         WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
@@ -2601,8 +2613,10 @@ public class NetworkMonitorTest {
         final String svcb = "1 doh.google alpn=h3 ipv4hint=192.0.2.100 dohpath=/dns-query{?dns}";
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
-        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb }, TYPE_SVCB);
-        mFakeDns.setAnswer("_dns.dns.google", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.resolver.arpa", () -> new String[] { svcb }, TYPE_SVCB,
+                FLAG_TRY_ALL_SERVERS);
+        mFakeDns.setAnswer("_dns.dns.google", () -> new String[] { svcb }, TYPE_SVCB,
+                QUERY_FLAGS_NONE);
         mFakeDns.setAnswer("dns.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
 
         // Verify the callback for opportunistic mode.
@@ -3670,10 +3684,6 @@ public class NetworkMonitorTest {
         final WrappedNetworkMonitor monitor = makeMonitor(CELL_METERED_CAPABILITIES);
         notifyNetworkConnected(monitor, TEST_AGENT_CONFIG,
                 TEST_LINK_PROPERTIES, CELL_METERED_CAPABILITIES);
-        doAnswer(invocation -> {
-            waitForSerialProbes(invocation.getArgument(0));
-            return null;
-        }).when(mDependencies).sleep(anyInt());
         verifyNetworkTested(testResult, probesSucceeded, 1);
     }
 
```

