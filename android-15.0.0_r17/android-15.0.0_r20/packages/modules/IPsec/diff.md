```diff
diff --git a/Android.bp b/Android.bp
index dd6a6198..19000d7e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -117,6 +117,7 @@ java_library {
         "bouncycastle_ike_digests",
         "modules-utils-build",
         "modules-utils-statemachine",
+        "net-utils-framework-ipsec",
     ],
     sdk_version: "module_current",
 }
diff --git a/jarjar-rules-shared.txt b/jarjar-rules-shared.txt
index 3f16574e..e51adf84 100644
--- a/jarjar-rules-shared.txt
+++ b/jarjar-rules-shared.txt
@@ -1,6 +1,7 @@
 rule android.annotation.StringDef com.android.internal.net.ipsec.annotation.StringDef
 rule android.telephony.Annotation* com.android.internal.net.eap.telephony.Annotation@1
-rule com.android.server.vcn.util.PersistableBundleUtils* com.android.internal.net.vcn.util.PersistableBundleUtils@1
+rule android.net.vcn.util.PersistableBundleUtils* com.android.internal.net.vcn.util.PersistableBundleUtils@1
 rule com.android.internal.util.** com.android.internal.net.ipsec.ike.utils.@1
 rule com.android.modules.utils.** com.android.internal.net.utils.@1
+rule com.android.net.module.util.** com.android.internal.net.ipsec.ike.utils.@1
 rule org.bouncycastle.** com.android.internal.net.org.bouncycastle.@1
diff --git a/jarjar-rules-test.txt b/jarjar-rules-test.txt
index 80993ab1..f6aa8430 100644
--- a/jarjar-rules-test.txt
+++ b/jarjar-rules-test.txt
@@ -3,7 +3,7 @@ rule android.net.ipsec.** android.net.ipsec.test.@1
 rule com.android.internal.net.**.** com.android.internal.net.@1.test.@2
 rule android.annotation.StringDef com.android.internal.net.ipsec.test.annotation.StringDef
 rule android.telephony.Annotation* com.android.internal.net.eap.test.telephony.Annotation@1
-rule com.android.server.vcn.util.PersistableBundleUtils* com.android.internal.net.vcn.test.util.PersistableBundleUtils@1
+rule android.net.vcn.util.PersistableBundleUtils* com.android.internal.net.vcn.test.util.PersistableBundleUtils@1
 rule com.android.internal.util.** com.android.internal.net.ipsec.test.ike.utils.@1
 rule com.android.modules.utils.** com.android.internal.net.utils.test.@1
 rule org.bouncycastle.** com.android.internal.net.org.bouncycastle.test.@1
diff --git a/src/java/android/net/eap/EapSessionConfig.java b/src/java/android/net/eap/EapSessionConfig.java
index e661bc75..110fe3ee 100644
--- a/src/java/android/net/eap/EapSessionConfig.java
+++ b/src/java/android/net/eap/EapSessionConfig.java
@@ -20,12 +20,12 @@ import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 import android.telephony.Annotation.UiccAppType;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.net.ipsec.ike.utils.IkeCertUtils;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/src/java/android/net/ipsec/ike/ChildSaProposal.java b/src/java/android/net/ipsec/ike/ChildSaProposal.java
index b1c8f343..ce9d8ee2 100644
--- a/src/java/android/net/ipsec/ike/ChildSaProposal.java
+++ b/src/java/android/net/ipsec/ike/ChildSaProposal.java
@@ -21,6 +21,7 @@ import static com.android.internal.net.ipsec.ike.message.IkeSaPayload.EsnTransfo
 import android.annotation.NonNull;
 import android.annotation.SuppressLint;
 import android.net.IpSecAlgorithm;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 import android.util.ArraySet;
 
@@ -33,7 +34,6 @@ import com.android.internal.net.ipsec.ike.message.IkeSaPayload.EsnTransform;
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.IntegrityTransform;
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.Transform;
 import com.android.modules.utils.build.SdkLevel;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.util.Arrays;
 import java.util.List;
diff --git a/src/java/android/net/ipsec/ike/ChildSessionParams.java b/src/java/android/net/ipsec/ike/ChildSessionParams.java
index efc3e0bf..87c90515 100644
--- a/src/java/android/net/ipsec/ike/ChildSessionParams.java
+++ b/src/java/android/net/ipsec/ike/ChildSessionParams.java
@@ -21,10 +21,9 @@ import android.annotation.NonNull;
 import android.annotation.SuppressLint;
 import android.annotation.SystemApi;
 import android.net.InetAddresses;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 
-import com.android.server.vcn.util.PersistableBundleUtils;
-
 import java.net.InetAddress;
 import java.util.Arrays;
 import java.util.LinkedList;
diff --git a/src/java/android/net/ipsec/ike/IkeDerAsn1DnIdentification.java b/src/java/android/net/ipsec/ike/IkeDerAsn1DnIdentification.java
index 074ddefc..76f427e5 100644
--- a/src/java/android/net/ipsec/ike/IkeDerAsn1DnIdentification.java
+++ b/src/java/android/net/ipsec/ike/IkeDerAsn1DnIdentification.java
@@ -17,10 +17,9 @@ package android.net.ipsec.ike;
 
 import android.annotation.NonNull;
 import android.net.ipsec.ike.exceptions.AuthenticationFailedException;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 
-import com.android.server.vcn.util.PersistableBundleUtils;
-
 import java.security.cert.X509Certificate;
 import java.util.Objects;
 
diff --git a/src/java/android/net/ipsec/ike/IkeKeyIdIdentification.java b/src/java/android/net/ipsec/ike/IkeKeyIdIdentification.java
index 48cc29f7..0b992a19 100644
--- a/src/java/android/net/ipsec/ike/IkeKeyIdIdentification.java
+++ b/src/java/android/net/ipsec/ike/IkeKeyIdIdentification.java
@@ -18,10 +18,9 @@ package android.net.ipsec.ike;
 
 import android.annotation.NonNull;
 import android.net.ipsec.ike.exceptions.AuthenticationFailedException;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 
-import com.android.server.vcn.util.PersistableBundleUtils;
-
 import java.security.cert.X509Certificate;
 import java.util.Arrays;
 import java.util.Objects;
diff --git a/src/java/android/net/ipsec/ike/IkeSaProposal.java b/src/java/android/net/ipsec/ike/IkeSaProposal.java
index abbbbc2a..3b965b67 100644
--- a/src/java/android/net/ipsec/ike/IkeSaProposal.java
+++ b/src/java/android/net/ipsec/ike/IkeSaProposal.java
@@ -18,6 +18,7 @@ package android.net.ipsec.ike;
 
 import android.annotation.NonNull;
 import android.annotation.SuppressLint;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 import android.util.ArraySet;
 
@@ -28,7 +29,6 @@ import com.android.internal.net.ipsec.ike.message.IkeSaPayload.IntegrityTransfor
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.PrfTransform;
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.Transform;
 import com.android.modules.utils.build.SdkLevel;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.util.ArrayList;
 import java.util.Arrays;
diff --git a/src/java/android/net/ipsec/ike/IkeSessionParams.java b/src/java/android/net/ipsec/ike/IkeSessionParams.java
index 1460aafd..01fb0067 100644
--- a/src/java/android/net/ipsec/ike/IkeSessionParams.java
+++ b/src/java/android/net/ipsec/ike/IkeSessionParams.java
@@ -34,6 +34,7 @@ import android.net.ConnectivityManager;
 import android.net.Network;
 import android.net.eap.EapSessionConfig;
 import android.net.ipsec.ike.ike3gpp.Ike3gppExtension;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 import android.util.SparseArray;
 
@@ -44,7 +45,6 @@ import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribu
 import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.IkeConfigAttribute;
 import com.android.internal.net.ipsec.ike.message.IkePayload;
 import com.android.modules.utils.build.SdkLevel;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.io.PrintWriter;
 import java.lang.annotation.Retention;
diff --git a/src/java/android/net/ipsec/ike/SaProposal.java b/src/java/android/net/ipsec/ike/SaProposal.java
index a48d8557..0506532d 100644
--- a/src/java/android/net/ipsec/ike/SaProposal.java
+++ b/src/java/android/net/ipsec/ike/SaProposal.java
@@ -18,6 +18,7 @@ package android.net.ipsec.ike;
 
 import android.annotation.IntDef;
 import android.annotation.NonNull;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 import android.util.Pair;
 import android.util.SparseArray;
@@ -29,7 +30,6 @@ import com.android.internal.net.ipsec.ike.message.IkeSaPayload.IntegrityTransfor
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.PrfTransform;
 import com.android.internal.net.ipsec.ike.message.IkeSaPayload.Transform;
 import com.android.modules.utils.build.SdkLevel;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/src/java/android/net/ipsec/ike/TunnelModeChildSessionParams.java b/src/java/android/net/ipsec/ike/TunnelModeChildSessionParams.java
index 5cf2b40e..8b8cda84 100644
--- a/src/java/android/net/ipsec/ike/TunnelModeChildSessionParams.java
+++ b/src/java/android/net/ipsec/ike/TunnelModeChildSessionParams.java
@@ -25,6 +25,7 @@ import android.annotation.Nullable;
 import android.annotation.SuppressLint;
 import android.annotation.SystemApi;
 import android.net.LinkAddress;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 
 import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribute;
@@ -35,7 +36,6 @@ import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttribu
 import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Address;
 import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.ConfigAttributeIpv6Dns;
 import com.android.internal.net.ipsec.ike.message.IkeConfigPayload.TunnelModeChildConfigAttribute;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.net.Inet4Address;
 import java.net.Inet6Address;
diff --git a/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java b/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
index 28c69fe1..9b91b241 100644
--- a/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
+++ b/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
@@ -6218,8 +6218,10 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
     // This call will be only fired when mIkeConnectionCtrl.isMobilityEnabled() is true
     @Override
     public void onUnderlyingNetworkUpdated() {
-        // Send event for mobility.
-        sendMessage(CMD_UNDERLYING_NETWORK_UPDATED_WITH_MOBILITY);
+        if (ShimUtils.getInstance().suspendOnNetworkLossEnabled()) {
+            // Send event for mobility.
+            sendMessage(CMD_UNDERLYING_NETWORK_UPDATED_WITH_MOBILITY);
+        }
 
         // UPDATE_SA
         sendMessage(
@@ -6230,8 +6232,10 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
     @Override
     public void onUnderlyingNetworkDied(Network network) {
         if (mIkeConnectionCtrl.isMobilityEnabled()) {
-            // Send event for mobility.
-            sendMessage(CMD_UNDERLYING_NETWORK_DIED_WITH_MOBILITY);
+            if (ShimUtils.getInstance().suspendOnNetworkLossEnabled()) {
+                // Send event for mobility.
+                sendMessage(CMD_UNDERLYING_NETWORK_DIED_WITH_MOBILITY);
+            }
 
             // Do not tear down the session because 1) callers might want to migrate the IKE Session
             // when another network is available; 2) the termination from IKE Session might be
diff --git a/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayload.java b/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayload.java
index 57baceb0..6c2d1ba5 100644
--- a/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayload.java
+++ b/src/java/com/android/internal/net/ipsec/ike/message/IkeConfigPayload.java
@@ -31,10 +31,10 @@ import android.net.ipsec.ike.TunnelModeChildSessionParams.ConfigRequestIpv6Addre
 import android.net.ipsec.ike.TunnelModeChildSessionParams.ConfigRequestIpv6DnsServer;
 import android.net.ipsec.ike.TunnelModeChildSessionParams.TunnelModeChildConfigRequest;
 import android.net.ipsec.ike.exceptions.InvalidSyntaxException;
+import android.net.vcn.util.PersistableBundleUtils;
 import android.os.PersistableBundle;
 
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.server.vcn.util.PersistableBundleUtils;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
diff --git a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtils.java b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtils.java
index ecc9c0fb..cdfd6aea 100644
--- a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtils.java
+++ b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtils.java
@@ -20,6 +20,7 @@ import android.content.Context;
 import android.net.Network;
 import android.net.SocketKeepalive;
 import android.net.ipsec.ike.exceptions.IkeException;
+import android.os.Build;
 
 import com.android.internal.net.ipsec.ike.net.IkeConnectionController;
 import com.android.modules.utils.build.SdkLevel;
@@ -38,8 +39,8 @@ public abstract class ShimUtils {
     private static final ShimUtils INSTANCE;
 
     static {
-        if (SdkLevel.isAtLeastV()) {
-            INSTANCE = new ShimUtilsMinV();
+        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            INSTANCE = new ShimUtilsMinW();
         } else if (SdkLevel.isAtLeastU()) {
             INSTANCE = new ShimUtilsU();
         } else if (SdkLevel.isAtLeastT()) {
@@ -92,4 +93,7 @@ public abstract class ShimUtils {
 
     /** Returns if the device supports kernel migration without encap socket changes. */
     public abstract boolean supportsSameSocketKernelMigration(Context context);
+
+    /** Returns if supports suspend on network loss. */
+    public abstract boolean suspendOnNetworkLossEnabled();
 }
diff --git a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinV.java b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
similarity index 78%
rename from src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinV.java
rename to src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
index affbc939..46729257 100644
--- a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinV.java
+++ b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsMinW.java
@@ -16,10 +16,15 @@
 
 package com.android.internal.net.ipsec.ike.shim;
 
-/** Shim utilities for SDK V and above */
-public class ShimUtilsMinV extends ShimUtilsU {
+/** Shim utilities for SDK W and above */
+public class ShimUtilsMinW extends ShimUtilsU {
     // Package protected constructor for ShimUtils to access
-    ShimUtilsMinV() {
+    ShimUtilsMinW() {
         super();
     }
+
+    @Override
+    public boolean suspendOnNetworkLossEnabled() {
+        return true;
+    }
 }
diff --git a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsRAndS.java b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsRAndS.java
index f8751abd..a64ec676 100644
--- a/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsRAndS.java
+++ b/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsRAndS.java
@@ -81,4 +81,9 @@ public class ShimUtilsRAndS extends ShimUtils {
     public boolean supportsSameSocketKernelMigration(Context context) {
         return false;
     }
+
+    @Override
+    public boolean suspendOnNetworkLossEnabled() {
+        return false;
+    }
 }
diff --git a/tests/iketests/assets/pem/end-cert-a.pem b/tests/iketests/assets/pem/end-cert-a.pem
index 89411f8e..79b82e64 100644
--- a/tests/iketests/assets/pem/end-cert-a.pem
+++ b/tests/iketests/assets/pem/end-cert-a.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-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
+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
-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
+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
 -----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/end-cert-b.pem b/tests/iketests/assets/pem/end-cert-b.pem
index f25d3524..c3631114 100644
--- a/tests/iketests/assets/pem/end-cert-b.pem
+++ b/tests/iketests/assets/pem/end-cert-b.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-MIIDWDCCAkCgAwIBAgIIRs9N2RKvOUYwDQYJKoZIhvcNAQELBQAwQTELMAkGA1UE
+MIIDWjCCAkKgAwIBAgIIXCCYKXKvCY4wDQYJKoZIhvcNAQELBQAwQTELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIDAeBgNVBAMTF3R3by5jYS50ZXN0LmFu
-ZHJvaWQubmV0MB4XDTE5MDkzMDE4NDg1MVoXDTI0MDkyODE4NDg1MVowQTELMAkG
-A1UEBhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIDAeBgNVBAMTF3NlcnZlci50ZXN0
-LmFuZHJvaWQubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxmhy
-posM/dhFPvmHpiqk+bJR2yfw5AeWhspnjuIJB1X3/TFCRTmLLsQ8VGRQnSKYlAYJ
-2r5XpgYQ09r4DYAbHwL2oSYtktMzqax22JlR73czZH4D3UTtKk7CdLtc1NPFXYFm
-lJ9uE/TD1pXvXwj9vdYp8tVuls2Rv+hBNtgM4nT1FqyMpp1sr5t2LIdx+WpDR4PC
-8C7HExeuw4wOBY6mWp4uErWqDFBfQNI3dzwpySRtnuMVKSX5Qcj6Z+bqKmtAgAnZ
-qdoLegn4sBbELDFW1QYNqp9QgdJO9P9R2lI8LZvKcd2yB8zJ2+JK1Efh9ErzhqFn
-Rc1BzbsBxKJBbppZXQIDAQABo1QwUjAfBgNVHSMEGDAWgBRypK7W5FhP8MtsugM1
-TPfyca8IpDAaBgNVHREEEzARgg9pa2UuYW5kcm9pZC5uZXQwEwYDVR0lBAwwCgYI
-KwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBADJu4bfbDO/PUSjTMuH1u6x9iTdx
-PKVkzFHqeiAsEKccyenuFKrwkkoIF+gieJeKKDj6lKFDP4uPOYIuNxs9td8G52+1
-5XKX2v9heaw6uFU3AlMmoAHKwIiM+U6eweuG+rVG2doTbMW2OOrEfJ5mgQtky7tx
-EIPUL9gUpAKqvsC7pJ7nrakm6TBkhYaTtDYOvdD97LyH9/5h32WKn9zU2H4dog+4
-87K6icdjBpd4ViPXbOBuOLvEsnMDmbSC3/12hv59swAf865SZN10B7ScYbg/yS9V
-x2YtMxPMNOOqC71Z/JE5mc80Un0nd9eJFxPueWqeH/4cGA6gL7ZtAeor0BE=
------END CERTIFICATE-----
\ No newline at end of file
+ZHJvaWQubmV0MCAXDTI0MDcyMzIwMzg1OVoYDzIwNzQwNzExMjAzODU5WjBBMQsw
+CQYDVQQGEwJVUzEQMA4GA1UEChMHQW5kcm9pZDEgMB4GA1UEAxMXc2VydmVyLnRl
+c3QuYW5kcm9pZC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV
+DNXj819d12tl+WnwdsfjodwXSkfQ8TJ28v85z022P04wGY0cNEbVBeJfM0hzn41f
+8NrFI/kHEJjJUgVD1/5vKa5h9G4P75tIfJi+zQwdJSxRtJ9ae43+DZtpT7U2Vyis
+LW4S/a52kFRBmSSS3htun4cKF6tM/8HxkpaSAlTVIM9QembKxrYIu7NtZ8ieNtD5
+SVKMRIbjMGzK88qLg8KKiv0n4Re5uxyvPpY+ogmMGrfWiNxg1EzgkVsmofpk4ap4
+HUyKzwnq9VJl39kxLg5Y2/XRDf6CArkqHr5BilKtAWK5Bbr7pHgp/YBQV31GdaQv
+m9gMW1qTUtgZhW3xBG/nAgMBAAGjVDBSMB8GA1UdIwQYMBaAFM0h3ZxF/9HfBl32
+xgy6SnDF3RhiMBoGA1UdEQQTMBGCD2lrZS5hbmRyb2lkLm5ldDATBgNVHSUEDDAK
+BggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAsn5qFf2dw1J0GUSRvBXTHOfn
+XNPeebA3kn6Gmgp1dJe3Cms3pPedu9hkW64TSvZTPO0WoFwRabcy0fTMnauRlsFj
+EYmVYIygIXbCLxGE6eHslZ7WrhAVpzhjk0MH3kX3mHUWe0nad27mWn+QiA0s6g1V
+TgxgX1tskSUG5l4BJtV190J1gJSvNQZXosEnSwA4Pkt8Cu5/1yfXQFMnsZ16bEyP
+B5FnAU8iyons1593ujAtWg6SPcYZvMBauRE3gvqEhvgiF7fYmdE0rZ6JWNznO0qU
+uRT/La7FrB8OPYzQgBvU4fP0WAF6vmH3KilDOdGE0dhe1lRZvwlCJZinFFv39g==
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/end-cert-small-2.pem b/tests/iketests/assets/pem/end-cert-small-2.pem
new file mode 100644
index 00000000..cad5f713
--- /dev/null
+++ b/tests/iketests/assets/pem/end-cert-small-2.pem
@@ -0,0 +1,12 @@
+-----BEGIN CERTIFICATE-----
+MIIBuDCCAWKgAwIBAgIIdmgDVa6DXSIwDQYJKoZIhvcNAQELBQAwQzELMAkGA1UE
+BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIjAgBgNVBAMTGXNtYWxsLmNhLnRlc3Qu
+YW5kcm9pZC5uZXQwIBcNMjQwNzIzMjAzODU5WhgPMjA3NDA3MTEyMDM4NTlaMEcx
+CzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdBbmRyb2lkMSYwJAYDVQQDEx1zbWFsbC5z
+ZXJ2ZXIudGVzdC5hbmRyb2lkLm5ldDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCb
+9vjoSEThr/1k2ta93xMvnBwCS/Ib3NIOqg/Bo9ab9vTdgSvTOicPPWJv2LunkD8x
+pe3r9qOyRPmxNFdffHtnAgMBAAGjNDAyMB8GA1UdIwQYMBaAFOFC7nd0d42fZl4E
+uGP7aX2TViMwMA8GA1UdEQQIMAaHBMCoK4owDQYJKoZIhvcNAQELBQADQQAxaWUn
+1ZPsi+qVF8mRlcrR58xnEuC/0+DMReCGzkh84i7hWRS+qj3WyLiNPwhhUXTycNvX
+3ktRbQjKRYvTqyVL
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/intermediate-ca-b-one.pem b/tests/iketests/assets/pem/intermediate-ca-b-one.pem
index 707e575b..73657df3 100644
--- a/tests/iketests/assets/pem/intermediate-ca-b-one.pem
+++ b/tests/iketests/assets/pem/intermediate-ca-b-one.pem
@@ -1,21 +1,21 @@
 -----BEGIN CERTIFICATE-----
-MIIDaDCCAlCgAwIBAgIIIbjMyRn2770wDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
+MIIDajCCAlKgAwIBAgIIdzwG6JkadAcwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxITAfBgNVBAMTGHJvb3QuY2EudGVzdC5h
-bmRyb2lkLm5ldDAeFw0xOTA5MzAxODQzMThaFw0yNDA5MjgxODQzMThaMEExCzAJ
-BgNVBAYTAlVTMRAwDgYDVQQKEwdBbmRyb2lkMSAwHgYDVQQDExdvbmUuY2EudGVz
-dC5hbmRyb2lkLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNN
-sRr5Z30rAEw2jrAh/BIekbEy/MvOucAr1w0lxH71p+ybRBx5Bj7G07UGXbL659gm
-meMV6nabY4HjQXNMq22POiJBZj+U+rw34br6waljBttxCmmJac1VvgqNsSspXjRy
-NbiVQdFjyKSX0NOPcEkwANk15mZbOgJBaYYc8jQCY2G/p8eARVBTLJCy8LEwEU6j
-XRv/4eYST79qpBFc7gQQj2FLmh9oppDIvcIVBHwtd1tBoVuehRSud1o8vQRkl/HJ
-Mrwp24nO5YYhmVNSFRtBpmWMSu1KknFUwkOebINUNsKXXHebVa7cP4XIQUL8mRT3
-5X9rFJFSQJE01S3NjNMCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
-Af8EBAMCAQYwHQYDVR0OBBYEFHK3FIm7g8dxEIwK9zMAO8EWhRYxMB8GA1UdIwQY
-MBaAFEmfqEeF14Nj91ekIpR+sVhCEoAaMA0GCSqGSIb3DQEBCwUAA4IBAQAeMlXT
-TnxZo8oz0204gKZ63RzlgDpJ7SqA3qFG+pV+TiqGfSuVkXuIdOskjxJnA9VxUzrr
-LdMTCn5e0FK6wCYjZ2GT/CD7oD3vSMkzGbLGNcNJhhDHUq8BOLPkPzz/rwQFPBSb
-zr6hsiVXphEt/psGoN7Eu9blPeQaIwMfWnaufAwF664S/3dmCRbNMWSam1qzzz8q
-jr0cDOIMa//ZIAcM16cvoBK6pFGnUmuoJYYRtfpY5MmfCWz0sCJxENIX/lxyhd7N
-FdRALA1ZP3E//Tn2vQoeFjbKaAba527RE26HgHJ9zZDo1nn8J8J/YwYRJdBWM/3S
-LYebNiMtcyB5nIkj
------END CERTIFICATE-----
\ No newline at end of file
+bmRyb2lkLm5ldDAgFw0yNDA3MjMyMDM4NTlaGA8yMDc0MDcxMTIwMzg1OVowQTEL
+MAkGA1UEBhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIDAeBgNVBAMTF29uZS5jYS50
+ZXN0LmFuZHJvaWQubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
+sfrQPKBsPtsUTQ6qJsLln5A+YM2g/olWEaSE6ukwvIYZf3oMyF13nit6HNPGbZwR
+Vo9MHq776gnUTwzutef5/SKKZo2e3DkRRMmJOAMP+ClnIy29lTPSpVsZ5y6g6qPg
+atkgl+EYtqTq/6n2n/3lQ28Sza3ZRX9buHTQS+LYIg8IJxRkEBzNjn8mLRuS/cEI
+WeW+yJL9wSjVkJhDf7ur4+Z4NXEeewbM+7SAYCVFmaiCCG7bzlck+Im8cO1EsdwS
+qaOGbu/uqGNTvfJ8hM01YMAIq/p7km91hPZLR/UXiRhkrRPWPRyu5+6StNWps51P
+B7193c5yDHFTz/zxxCm5mQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
+DwEB/wQEAwIBBjAdBgNVHQ4EFgQUjetyWQuW2x4FV3aJKXYnjjf/HLkwHwYDVR0j
+BBgwFoAUXItVwnYN3ehOnbmmIrkilTmAAMQwDQYJKoZIhvcNAQELBQADggEBAJge
+B0kURc0FtdJ//bjFUb1sI8N/4RcW8l6HQAfOxABKz1sktdcM6adSLU6zNCJTUfNR
+NF6nhJNCW17WMxRcoriIfdpTgW67Bcw67mAafsuiLS0k2pMwQGsWuqpanDODdTNM
+l2oPnnTUrI2IQUA0hVk2+zQr8LIIWZKHdcFYZkoP3MRPqmIf9XajLJ3FC2bkbNMp
+77bHcsI4Uh8s2JmRXWV9y4kcOcO97cNSttyVg9sEXbmqZRA3s6rdfHTrSzGSJDvC
+GWIB79qqzFI9WJaozQE4oXDuaAk0XYRZ9l3fIVgEwBX/X7yUojV/zfmO1kNbs4wB
+jNKx7YRdXWFDAneE5Jo=
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/intermediate-ca-b-two.pem b/tests/iketests/assets/pem/intermediate-ca-b-two.pem
index 39808f88..85bbd99b 100644
--- a/tests/iketests/assets/pem/intermediate-ca-b-two.pem
+++ b/tests/iketests/assets/pem/intermediate-ca-b-two.pem
@@ -1,21 +1,21 @@
 -----BEGIN CERTIFICATE-----
-MIIDZzCCAk+gAwIBAgIIKWCREnNCs+wwDQYJKoZIhvcNAQELBQAwQTELMAkGA1UE
+MIIDaTCCAlGgAwIBAgIIXIoCdyOuU3YwDQYJKoZIhvcNAQELBQAwQTELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIDAeBgNVBAMTF29uZS5jYS50ZXN0LmFu
-ZHJvaWQubmV0MB4XDTE5MDkzMDE4NDQwMloXDTI0MDkyODE4NDQwMlowQTELMAkG
-A1UEBhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIDAeBgNVBAMTF3R3by5jYS50ZXN0
-LmFuZHJvaWQubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxLUa
-RqkYl2m7lUmMnkooqO0DNNY1aN9r7mJc3ndYn5gjkpb3yLgOYPDNLcQerV6uWk/u
-qKudNHed2dInGonl3oxwwv7++6oUvvtrSWLDZlRg16GsdIE1Y98DSMQWkSxevYy9
-Nh6FGTdlBFQVMpiMa8qHEkrOyKsy85yCW1sgzlpGTIBwbDAqYtwe3rgbwyHwUtfy
-0EU++DBcR4ll/pDqB0OQtW5E3AOq2GH1iaGeFLKSUQ5KAbdI8y4/b8IkSDffvxcc
-kXig7S54aLrNlL/ZjQ+H4Chgjj2A5wMucd81+Fb60Udej73ICL9PpMPnXQ1+BVYd
-MJ/txjLNmrOJG9yEHQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
-/wQEAwIBBjAdBgNVHQ4EFgQUcqSu1uRYT/DLbLoDNUz38nGvCKQwHwYDVR0jBBgw
-FoAUcrcUibuDx3EQjAr3MwA7wRaFFjEwDQYJKoZIhvcNAQELBQADggEBADY461GT
-Rw0dGnD07xaGJcI0i0pV+WnGSrl1s1PAIdMYihJAqYnh10fXbFXLm2WMWVmv/pxs
-FI/xDJno+pd4mCa/sIhm63ar/Nv+lFQmcpIlvSlKnhhV4SLNBeqbVhPBGTCHfrG4
-aIyCwm1KJsnkWbf03crhSskR/2CXIjX6lcAy7K3fE2u1ELpAdH0kMJR7VXkLFLUm
-gqe9YCluR0weMpe2sCaOGzdVzQSmMMCzGP5cxeFR5U6K40kMOpiW11JNmQ06xI/m
-YVkMNwoiV/ITT0/C/g9FxJmkO0mVSLEqxaLS/hNiQNDlroVM0rbxhzviXLI3R3AO
-50VvlOQYGxWed/I=
------END CERTIFICATE-----
\ No newline at end of file
+ZHJvaWQubmV0MCAXDTI0MDcyMzIwMzg1OVoYDzIwNzQwNzExMjAzODU5WjBBMQsw
+CQYDVQQGEwJVUzEQMA4GA1UEChMHQW5kcm9pZDEgMB4GA1UEAxMXdHdvLmNhLnRl
+c3QuYW5kcm9pZC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6
+NYaEk1ER7dl8/5FgbObsLe7OGTLFAbK+t7jgts5rGOkvDbGi5bKDuyzP0evqUgX1
+0MjdGLZoiMtnnxeirPvXyhc04JfgEQ5F/hIWkb7SC2gaq7v0p0aylVVHmJzIMAee
+PyUeFWA4IsuqWHczwxzQkUpuokEMYcnBv0E5OsaUgx5mBOCNF5Q5zao6QD4ZaZVn
+DySkMl1jW/8vRsXe4RHPwhHzogUY+dpcvZam3chbUkEnUKAsWyCTFr9xgVuTyKjt
+t8bsz2zItEW6NN3MooCkUnzaQ10bpD46f6GalE0zXIu+MjUt3vtyUzCi7UJjy6y7
+rsTjjynTmqPP3YsoB/BFAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
+AQH/BAQDAgEGMB0GA1UdDgQWBBTNId2cRf/R3wZd9sYMukpwxd0YYjAfBgNVHSME
+GDAWgBSN63JZC5bbHgVXdokpdieON/8cuTANBgkqhkiG9w0BAQsFAAOCAQEAD6nd
+B79+SzkkF27ExxZ/su44VZorKt0Vv3CutIo84nFncV3Uxv/uJmeXAoOk8v01oHr5
+JrgBtaqZ8n0XBNFHR5i5boBq47rzPuvd82QiiJ0osGBtk7/aGsLe5l0N4uR5clen
+jvPQf8riPFur3lG/PmMYUqyCL6RYgIe8xD9AFE53YJDrD8lfVbBQbEzZk7fb6FK9
+irBqJtiC/IpDh2KIgaTTUFRF5jIYx+kkTj1o4iS8n/lqwLsf6DbnBrEzSf4fj9NX
+zevH3c0P9WCXbt26l326VtoI+Pa+wMI8oI5vmx/2sGrNFIOrwzT1MjOS8DQlGrkZ
+hSxLqo8CL3XEtdsrtQ==
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/self-signed-ca-a.pem b/tests/iketests/assets/pem/self-signed-ca-a.pem
index e4ad5b4b..ebc35de8 100644
--- a/tests/iketests/assets/pem/self-signed-ca-a.pem
+++ b/tests/iketests/assets/pem/self-signed-ca-a.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-MIIDPjCCAiagAwIBAgIIOLCjfFfLlBQwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
+MIIDQDCCAiigAwIBAgIIOoN9AxlVUFEwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxHDAaBgNVBAMTE2NhLnRlc3QuYW5kcm9p
-ZC5uZXQwHhcNMjQwNzE3MjAzMzQwWhcNMzQwNzE1MjAzMzQwWjA9MQswCQYDVQQG
-EwJVUzEQMA4GA1UEChMHQW5kcm9pZDEcMBoGA1UEAxMTY2EudGVzdC5hbmRyb2lk
-Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALeEtPaf/FZfS79U
-FKsINkw1FkFgpmAjDqcqAChDXHhUZc1U1i2F81q97gC4sTTVgmIdHGqRGdOK/28l
-LnRXfxsVi6QDZxjqcbaUhoO8TF3Mqa60eTOFr9ItKWCnuORvbIGA6Q5D8XGHEiZ6
-P16gFXHDJzU69I+WPqQjtCKyK4WhOpZZPXz2+zv5ZWrlnPVXHmHzwyYK6OhzS4Jr
-aDICWPmhsfTI4ph3rSSlWW5tmzs0wis/BDOfi28WQfbF8tsUETLK6au6qF8ZR8qY
-lD/rjM9WmBcq8sjwAzvU4d1e4C6SpN80MsYdgSd1MyxMdMZL2MW66csGqd7grj/B
-8zP2xsECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
-HQYDVR0OBBYEFGU7dEeh4jcm9I4JjiDZu5cGAfVsMA0GCSqGSIb3DQEBCwUAA4IB
-AQC0wd9zAVofbow0aORvBA7nA9J3JFzIoOkeBTJzlJaP/SmfduS13CXEdzMwLgNv
-5kE0NXzI29kPxhFjY7h7kdx4YuxlyxfS2jTqkt66XzTuAlXW+2LrmfDhjUZc3IVR
-SrYESzxbCnv9oa/or70lXAOhvzkH7NrmIy7xzRObLouGpuhLo2qpwFFac1NVshJq
-4YlgOunDI3/IXnhFofJAUXDAoD8TIVQUbH7+HoY9pC0Ozv4BbgKTskVqrHG6vxe3
-HJNP+/9QTMT9viLeYol2Ttzqg0wyWdD7Gt5twMBE1J7/pCY9ZNTo/IUhmJ/nMsw4
-gkT0pO/v+ILI1Z0l4UGwP62K
+ZC5uZXQwIBcNMjQwNzIzMjAzODQ2WhgPMjA3NDA3MTEyMDM4NDZaMD0xCzAJBgNV
+BAYTAlVTMRAwDgYDVQQKEwdBbmRyb2lkMRwwGgYDVQQDExNjYS50ZXN0LmFuZHJv
+aWQubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1tdo6atSOwpa
+2lYpsRBKrwK3tmY4fikVOamhI9TuJX2FNdqzdv2PikjB5UTaJR1OlEGGaao/vKhy
+WkO/rSaj38cKf1nGCLMSRhD8lA5+q39CB86zMl0XSDD/yLpDW5JBALyPEvqsW2dR
+j8dOMRYnhtIZg0WrfLS6jbjnwv2bE55WUT/pyM94pgdPN2uKDQYjPFy1SybWsrSk
+WghocIF3Kpp7evHTG68lHmno7eHXpvr9yfSKrTwta9ycnUq/zJteoXk/QlNXqrSf
+d42k2F2U4w43BtxWZWH8cdqfpyd3eBh9kGHZcHWKOd13BkTnI3Ql/Fdj1Kq6rZB9
+tHGjt48nxwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
+BjAdBgNVHQ4EFgQUF/VM1MOyxYjUteZRSJGRP/UgjsswDQYJKoZIhvcNAQELBQAD
+ggEBAIdZG5FXeKakaUaRH9slpVdkOrmETJ1UUgthjWJfY2MpLRPb2k78KwUpBgsx
+7F/xJlrj25PYTL4nwqpERmQNWpti3do1FSWQMcKizDO8Y0RwP4RrjmxVTBME8D6O
+OtYqrdGQKAIa3FbD72mYuJp5IKqghdMxG2DOPYmRj+M5i2EzOqqTXGr0H8rDbd4w
+Vwh8UO6yvKUQ1ldIE/Yb4tFqwDhgzoFRYvN0GCgFGr/L4cRviJGgmR/r4M7jAybd
+WUY1ZBbAGEpfhZnkr9aMsdEwVNfC/2SN3ho5BRnbeDsyHzBQWY66sVLYaUk1/2A0
+/TGQ4mwTotHO10O5w0RghvvVpac=
 -----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/self-signed-ca-b.pem b/tests/iketests/assets/pem/self-signed-ca-b.pem
index 972fd553..471d81ff 100644
--- a/tests/iketests/assets/pem/self-signed-ca-b.pem
+++ b/tests/iketests/assets/pem/self-signed-ca-b.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-MIIDSDCCAjCgAwIBAgIITJQJ6HC1rjwwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
+MIIDSjCCAjKgAwIBAgIIGnKBE/IIn8QwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxITAfBgNVBAMTGHJvb3QuY2EudGVzdC5h
-bmRyb2lkLm5ldDAeFw0xOTA5MzAxNzU1NTJaFw0yOTA5MjcxNzU1NTJaMEIxCzAJ
-BgNVBAYTAlVTMRAwDgYDVQQKEwdBbmRyb2lkMSEwHwYDVQQDExhyb290LmNhLnRl
-c3QuYW5kcm9pZC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCT
-q3hGF+JvLaB1xW7KGKmaxiQ7BxX2Sn7cbp7ggoVYXsFlBUuPPv3+Vg5PfPCPhsJ8
-/7w4HyKo3uc/vHs5HpQ7rSd9blhAkfmJci2ULLq73FB8Mix4CzPwMx29RrN1X9bU
-z4G0vJMczIBGxbZ0uw7n8bKcXBV7AIeax+J8lseEZ3k8iSuBkUJqGIpPFKTqByFZ
-A1Lvt47xkON5SZh6c/Oe+o6291wXaCOJUSAKv6PAWZkq9HeD2fqKA/ck9dBaz1M3
-YvzQ9V/7so3/dECjAfKia388h1I6XSGNUM+d5hpxMXpAFgG42eUXHpJ10OjDvSwd
-7ZSC91/kRQewUomEKBK1AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
-AQH/BAQDAgEGMB0GA1UdDgQWBBRJn6hHhdeDY/dXpCKUfrFYQhKAGjANBgkqhkiG
-9w0BAQsFAAOCAQEAig/94aGfHBhZuvbbhwAK4rUNpizmR567u0ZJ+QUEKyAlo9lT
-ZWYHSm7qTAZYvPEjzTQIptnAlxCHePXh3Cfwgo+r82lhG2rcdI03iRyvHWjM8gyk
-BXCJTi0Q08JHHpTP6GnAqpz58qEIFkk8P766zNXdhYrGPOydF+p7MFcb1Zv1gum3
-zmRLt0XUAMfjPUv1Bl8kTKFxH5lkMBLR1E0jnoJoTTfgRPrf9CuFSoh48n7YhoBT
-KV75xZY8b8+SuB0v6BvQmkpKZGoxBjuVsShyG7q1+4JTAtwhiP7BlkDvVkaBEi7t
-WIMFp2r2ZDisHgastNaeYFyzHYz9g1FCCrHQ4w==
------END CERTIFICATE-----
\ No newline at end of file
+bmRyb2lkLm5ldDAgFw0yNDA3MjMyMDM4NDZaGA8yMDc0MDcxMTIwMzg0NlowQjEL
+MAkGA1UEBhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxITAfBgNVBAMTGHJvb3QuY2Eu
+dGVzdC5hbmRyb2lkLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
+AN8nOxlRb6aKu2qwyZtt+u9X/c2rUuWhPRMNTyvr5nGl86EcFRdDRO3uuZCo+/iz
+v8mcEaw/1OUJWpBos9jWvXgugoy5O7G96NNNdR5Gb9lF2NiCelnOsjnPA0ATZLMJ
++Ir3ITX598vJazuYLVwfPDrkGPUaU5lzZ7NCEwb7tpGkGuVjFTNE1crTgnRj0aS8
+gX2N7tIMQ6iWnTw0De7+xFWtdKYKCn7AWppfOOKK6sV4TiHSs8dYPMhwc/QmP8lp
+Ve0kW7vWmuVdUHRXfawmTa86hwaPWLbj5ahViOsuMOoE7tQK6JBiGPdPgOUZttOz
+ichN02gOoC2ezeYSmzp9d1kCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
+HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFyLVcJ2Dd3oTp25piK5IpU5gADEMA0GCSqG
+SIb3DQEBCwUAA4IBAQDI83PK8aDJjnklkLyc8IzAFw/AdotlcAWbMFvP2CK6HKUU
+ZO9A9+1QWyp44enFOjDQjBX1QhCuBBMhlOFVZIyzY4ljndPMwiGzesC65TTzGzF9
+yjV6qx112E6ctPIKoppsRi1cQHYU23lxTxrBJIOthwhs4iggzbQgQCUyhCWOcxTO
+996hKuieHmTfQ5984bnLssqr2LP88ncOBwWd6oB606gW2Rl5o3oggHRMkIcQPqp3
+I5KaSf2WqUo++WnlN0dmwtE1mZFe6VG/s2R5wfGVj9prlgEVNNIQLzHj+OqcWDCr
+CDWGNsYqWfaeZvni6sPPcRSv5GuQ2snzOk1MKPf3
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/self-signed-ca-small-2.pem b/tests/iketests/assets/pem/self-signed-ca-small-2.pem
new file mode 100644
index 00000000..dbbcd992
--- /dev/null
+++ b/tests/iketests/assets/pem/self-signed-ca-small-2.pem
@@ -0,0 +1,12 @@
+-----BEGIN CERTIFICATE-----
+MIIBwjCCAWygAwIBAgIIHAdRver6x8swDQYJKoZIhvcNAQELBQAwQzELMAkGA1UE
+BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxIjAgBgNVBAMTGXNtYWxsLmNhLnRlc3Qu
+YW5kcm9pZC5uZXQwIBcNMjQwNzIzMjAzODQ2WhgPMjA3NDA3MTEyMDM4NDZaMEMx
+CzAJBgNVBAYTAlVTMRAwDgYDVQQKEwdBbmRyb2lkMSIwIAYDVQQDExlzbWFsbC5j
+YS50ZXN0LmFuZHJvaWQubmV0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALD+0foo
+GW5AckbgdhqReaBKkau0XGKII3hyWOZYhpVKplWIS0lextGPYXJuPqH58aTLPw+4
+buJMjAjkFxfvtsMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
+BAMCAQYwHQYDVR0OBBYEFOFC7nd0d42fZl4EuGP7aX2TViMwMA0GCSqGSIb3DQEB
+CwUAA0EAJTH3KQ2yvzp2h74c+RzJc7+H54JBtNcmQg0RFifpVjArHZH56vxo9x6g
+HJvfddlsTvPY8PD3jkOTSsVyusxolQ==
+-----END CERTIFICATE-----
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
index 747c5b16..7674bddd 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
@@ -153,6 +153,7 @@ import android.net.ipsec.test.ike.ike3gpp.Ike3gppExtension;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppExtension.Ike3gppDataListener;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppN1ModeInformation;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppParams;
+import android.os.Build;
 import android.os.Handler;
 import android.os.test.TestLooper;
 import android.telephony.TelephonyManager;
@@ -7460,6 +7461,41 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         assertTrue(expectedStateOfResumed.isInstance(mIkeSessionStateMachine.getCurrentState()));
     }
 
+    private void verifyRetransmitContinuesAndSessionTerminatedByTimeout(Class<?> expectedState) {
+        // Make sure the retransmit flag is not set to suspended.
+        assertFalse(mIkeSessionStateMachine.mIsRetransmitSuspended);
+
+        // Make sure the state machine is still alive.
+        assertTrue(expectedState.isInstance(mIkeSessionStateMachine.getCurrentState()));
+
+        // Elapse all retransmission timeouts.
+        int[] timeouts =
+                mIkeSessionStateMachine.mIkeSessionParams.getRetransmissionTimeoutsMillis();
+        for (long delay : timeouts) {
+            mLooper.dispatchAll();
+            mLooper.moveTimeForward(delay);
+        }
+        mLooper.dispatchAll();
+
+        assertNull(mIkeSessionStateMachine.getCurrentState());
+        if (SdkLevel.isAtLeastT()) {
+            verify(mMockIkeSessionCallback)
+                    .onClosedWithException(
+                            argThat(
+                                    e ->
+                                            e instanceof IkeIOException
+                                                    && e.getCause()
+                                                            instanceof IkeTimeoutException));
+        } else {
+            verify(mMockIkeSessionCallback)
+                    .onClosedWithException(
+                            argThat(
+                                    e ->
+                                            e instanceof IkeInternalException
+                                                    && e.getCause() instanceof IOException));
+        }
+    }
+
     @Test
     @SdkSuppress(minSdkVersion = 31, codeName = "S")
     public void testSuspendRetransmission_inDpd() throws Exception {
@@ -7478,9 +7514,14 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
 
-        verifyRetransmitSuspendedAndResumedOnNewNetwork(
-                IkeSessionStateMachine.DpdIkeLocalInfo.class,
-                IkeSessionStateMachine.DpdIkeLocalInfo.class);
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            verifyRetransmitContinuesAndSessionTerminatedByTimeout(
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class);
+        } else {
+            verifyRetransmitSuspendedAndResumedOnNewNetwork(
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class,
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class);
+        }
     }
 
     @Test
@@ -7496,10 +7537,15 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
                 CMD_FORCE_TRANSITION, mIkeSessionStateMachine.mDpdIkeLocalInfo);
         mLooper.dispatchAll();
 
-        verifyRetransmitSuspendedAndResumedOnNewNetwork(
-                IkeSessionStateMachine.DpdIkeLocalInfo.class,
-                IkeSessionStateMachine.DpdIkeLocalInfo.class);
-        verifyEmptyInformationalSent(1, false /* expectedResp*/);
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            verifyRetransmitContinuesAndSessionTerminatedByTimeout(
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class);
+        } else {
+            verifyRetransmitSuspendedAndResumedOnNewNetwork(
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class,
+                    IkeSessionStateMachine.DpdIkeLocalInfo.class);
+            verifyEmptyInformationalSent(1, false /* expectedResp*/);
+        }
     }
 
     @Test
@@ -7511,8 +7557,14 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
 
-        verifyRetransmitSuspendedAndResumedOnNewNetwork(
-                IkeSessionStateMachine.Idle.class, IkeSessionStateMachine.MobikeLocalInfo.class);
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            // Make sure the retransmit flag is not set to suspended.
+            assertFalse(mIkeSessionStateMachine.mIsRetransmitSuspended);
+        } else {
+            verifyRetransmitSuspendedAndResumedOnNewNetwork(
+                    IkeSessionStateMachine.Idle.class,
+                    IkeSessionStateMachine.MobikeLocalInfo.class);
+        }
     }
 
     @Test
@@ -7541,10 +7593,20 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         // Disconnect from the underlying network.
         mIkeSessionStateMachine.onUnderlyingNetworkDied(mMockDefaultNetwork);
         mLooper.dispatchAll();
-        // Make sure the retransmit flag is set to suspended.
-        assertTrue(mIkeSessionStateMachine.mIsRetransmitSuspended);
-        // Make sure if there is no future retransmission.
-        verifyRetransmissionStopped();
+
+        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            // Make sure the retransmit flag is not set to suspended.
+            assertFalse(mIkeSessionStateMachine.mIsRetransmitSuspended);
+            // Verify that retransmission has started.
+            verifyRetransmissionStarted();
+            // Stop testing
+            return;
+        } else {
+            // Make sure the retransmit flag is set to suspended.
+            assertTrue(mIkeSessionStateMachine.mIsRetransmitSuspended);
+            // Make sure if there is no future retransmission.
+            verifyRetransmissionStopped();
+        }
 
         // Step 3. Receive a response with the last packet before the network dies, verify child
         // notifies to send the RekeyChildDelete request but should not be sent.
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeCertPayloadTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeCertPayloadTest.java
index 5883595e..31fafac4 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeCertPayloadTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeCertPayloadTest.java
@@ -60,10 +60,10 @@ public final class IkeCertPayloadTest {
                         CertUtils.createCertFromPemFile("self-signed-ca-b.pem"),
                         null /*nameConstraints*/);
 
-        mEndCertSmall = CertUtils.createCertFromPemFile("end-cert-small.pem");
+        mEndCertSmall = CertUtils.createCertFromPemFile("end-cert-small-2.pem");
         mTrustAnchorSmall =
                 new TrustAnchor(
-                        CertUtils.createCertFromPemFile("self-signed-ca-small.pem"),
+                        CertUtils.createCertFromPemFile("self-signed-ca-small-2.pem"),
                         null /*nameConstraints*/);
     }
 
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeIdPayloadTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeIdPayloadTest.java
index 385f9eb5..4137cefa 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeIdPayloadTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/message/IkeIdPayloadTest.java
@@ -100,7 +100,7 @@ public final class IkeIdPayloadTest {
     @BeforeClass
     public static void setUpBeforeClass() throws Exception {
         sEndCertWithSanDns = CertUtils.createCertFromPemFile("end-cert-a.pem");
-        sEndCertWithSanIp = CertUtils.createCertFromPemFile("end-cert-small.pem");
+        sEndCertWithSanIp = CertUtils.createCertFromPemFile("end-cert-small-2.pem");
     }
 
     @Test
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsTest.java
index 16c87892..07a91b4c 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsTest.java
@@ -18,6 +18,8 @@ package com.android.internal.net.ipsec.test.ike.shim;
 
 import static org.junit.Assert.assertTrue;
 
+import android.os.Build;
+
 import com.android.modules.utils.build.SdkLevel;
 
 import org.junit.Test;
@@ -27,8 +29,8 @@ public class ShimUtilsTest {
     public void testGetInstance() {
         final ShimUtils shim = ShimUtils.getInstance();
         assertTrue(shim instanceof ShimUtils);
-        if (SdkLevel.isAtLeastV()) {
-            assertTrue(shim instanceof ShimUtilsMinV);
+        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            assertTrue(shim instanceof ShimUtilsMinW);
         } else if (SdkLevel.isAtLeastU()) {
             assertTrue(shim instanceof ShimUtilsU);
         } else if (SdkLevel.isAtLeastT()) {
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java
new file mode 100644
index 00000000..88930aaa
--- /dev/null
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/shim/ShimUtilsWTest.java
@@ -0,0 +1,31 @@
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
+package com.android.internal.net.ipsec.test.ike.shim;
+
+import static org.junit.Assert.assertTrue;
+
+import org.junit.Test;
+
+public class ShimUtilsWTest {
+    private ShimUtilsT mShim = new ShimUtilsMinW();
+
+    @Test
+    public void testSuspendOnNetworkLossEnabled() {
+        boolean enabled = mShim.suspendOnNetworkLossEnabled();
+        assertTrue(enabled);
+    }
+}
```

