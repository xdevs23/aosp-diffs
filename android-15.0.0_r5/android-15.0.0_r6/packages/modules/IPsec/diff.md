```diff
diff --git a/Android.bp b/Android.bp
index 79cede72..dd6a6198 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,8 +37,8 @@ java_sdk_library {
     libs: [
         "unsupportedappusage",
         "framework-annotations-lib",
-        "conscrypt.module.public.api",
-        "framework-configinfrastructure",
+        "conscrypt.module.public.api.stubs.module_lib",
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-connectivity.stubs.module_lib",
         "framework-connectivity-t.stubs.module_lib",
         "framework-statsd.stubs.module_lib",
@@ -56,10 +56,6 @@ java_sdk_library {
         "android.net.ipsec.ike.ike3gpp",
     ],
 
-    hidden_api_packages: [
-        "com.android.internal.net",
-    ],
-
     aconfig_declarations: [
         "ipsec_aconfig_flags",
     ],
@@ -131,7 +127,7 @@ java_library {
     srcs: [":ike-srcs"],
     libs: [
         "unsupportedappusage",
-        "conscrypt.module.public.api",
+        "conscrypt.module.public.api.stubs",
     ],
     static_libs: ["ike-internals"],
 
diff --git a/lint-baseline.xml b/lint-baseline.xml
index 9f5c4855..5456a86a 100644
--- a/lint-baseline.xml
+++ b/lint-baseline.xml
@@ -12,4 +12,774 @@
             column="21"/>
     </issue>
 
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSession.java"
+            line="461"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dumpsys_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSession.java"
+            line="471"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="325"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="325"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dpd_disable_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="373"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dpd_disable_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="373"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="876"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="876"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.enabled_ike_options_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="914"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="2185"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="2185"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSession.java"
+            line="461"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dumpsys_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSession.java"
+            line="471"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="52"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="62"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="72"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="82"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="94"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="111"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="325"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionCallback.java"
+            line="325"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dpd_disable_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="373"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.dpd_disable_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="373"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="876"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="876"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.ipsec.flags.enabled_ike_options_api&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="914"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="2185"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.ipsec.flags.liveness_check_api&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/IPsec/src/java/android/net/ipsec/ike/IkeSessionParams.java"
+            line="2185"
+            column="21"/>
+    </issue>
+
 </issues>
\ No newline at end of file
diff --git a/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachine.java b/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachine.java
index e7cee928..2fd9b077 100644
--- a/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachine.java
+++ b/src/java/com/android/internal/net/ipsec/ike/ChildSessionStateMachine.java
@@ -2473,7 +2473,7 @@ public class ChildSessionStateMachine extends AbstractSessionStateMachine {
                     IkePayload.getPayloadForTypeInProvidedList(
                             IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class, reqPayloads);
             if (saPayload != null) {
-                saPayload.releaseChildSpiResourcesIfExists();
+                saPayload.releaseSpiResources();
             }
         }
 
diff --git a/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java b/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
index 228b2993..28c69fe1 100644
--- a/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
+++ b/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachine.java
@@ -559,12 +559,13 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
                 mDeps.newIkeConnectionController(
                         mIkeContext,
                         new IkeConnectionController.Config(
+                                getHandler(),
                                 mIkeSessionParams,
                                 mIkeSessionId,
                                 CMD_ALARM_FIRED,
                                 CMD_SEND_KEEPALIVE,
                                 this));
-        mIkeSpiGenerator = new IkeSpiGenerator(mIkeContext.getRandomnessFactory());
+        mIkeSpiGenerator = mDeps.newIkeSpiGenerator(mIkeContext.getRandomnessFactory());
         mIpSecSpiGenerator =
                 new IpSecSpiGenerator(mIpSecManager, mIkeContext.getRandomnessFactory());
 
@@ -798,6 +799,11 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
         public IkeAlarm newExactAndAllowWhileIdleAlarm(IkeAlarmConfig alarmConfig) {
             return IkeAlarm.newExactAndAllowWhileIdleAlarm(alarmConfig);
         }
+
+        /** Builds and returns a new IkeSpiGenerator */
+        public IkeSpiGenerator newIkeSpiGenerator(RandomnessFactory randomnessFactory) {
+            return new IkeSpiGenerator(randomnessFactory);
+        }
     }
 
     private boolean hasChildSessionCallback(ChildSessionCallback callback) {
@@ -3333,13 +3339,6 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
 
         @Override
         protected void handleResponseIkeMessage(IkeMessage ikeMessage) {
-            // IKE_SA_INIT exchange and IKE SA setup succeed
-            boolean ikeInitSuccess = false;
-
-            // IKE INIT is not finished. IKE_SA_INIT request was re-sent with Notify-Cookie,
-            // and the same INIT SPI and other payloads.
-            boolean ikeInitRetriedWithCookie = false;
-
             try {
                 int exchangeType = ikeMessage.ikeHeader.exchangeType;
                 if (exchangeType != IkeHeader.EXCHANGE_TYPE_IKE_SA_INIT) {
@@ -3356,7 +3355,6 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
                             buildReqWithCookie(mRetransmitter.getMessage(), outCookiePayload);
 
                     sendRequest(initReq);
-                    ikeInitRetriedWithCookie = true;
                     return;
                 }
 
@@ -3375,7 +3373,6 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
                                 buildSaLifetimeAlarmScheduler(mRemoteIkeSpiResource.getSpi()));
 
                 addIkeSaRecord(mCurrentIkeSaRecord);
-                ikeInitSuccess = true;
 
                 List<Integer> integrityAlgorithms = mSaProposal.getIntegrityAlgorithms();
 
@@ -3439,17 +3436,6 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
                 }
 
                 handleIkeFatalError(e);
-            } finally {
-                if (!ikeInitSuccess && !ikeInitRetriedWithCookie) {
-                    if (mLocalIkeSpiResource != null) {
-                        mLocalIkeSpiResource.close();
-                        mLocalIkeSpiResource = null;
-                    }
-                    if (mRemoteIkeSpiResource != null) {
-                        mRemoteIkeSpiResource.close();
-                        mRemoteIkeSpiResource = null;
-                    }
-                }
             }
         }
 
@@ -3694,6 +3680,15 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
             if (mRetransmitter != null) {
                 mRetransmitter.stopRetransmitting();
             }
+
+            if (mLocalIkeSpiResource != null) {
+                mLocalIkeSpiResource.close();
+                mLocalIkeSpiResource = null;
+            }
+            if (mRemoteIkeSpiResource != null) {
+                mRemoteIkeSpiResource.close();
+                mRemoteIkeSpiResource = null;
+            }
         }
 
         private class UnencryptedRetransmitter extends Retransmitter {
@@ -5024,10 +5019,13 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
 
     /** RekeyIkeLocalCreate represents state when IKE library initiates Rekey IKE exchange. */
     class RekeyIkeLocalCreate extends RekeyIkeHandlerBase {
+        private IkeMessage mRekeyRequestMsg;
+
         @Override
         public void enterState() {
             try {
-                mRetransmitter = new EncryptedRetransmitter(buildIkeRekeyReq());
+                mRekeyRequestMsg = buildIkeRekeyReq();
+                mRetransmitter = new EncryptedRetransmitter(mRekeyRequestMsg);
             } catch (IOException e) {
                 loge("Fail to assign IKE SPI for rekey. Schedule a retry.", e);
                 mCurrentIkeSaRecord.rescheduleRekey(RETRY_INTERVAL_MS);
@@ -5035,6 +5033,17 @@ public class IkeSessionStateMachine extends AbstractSessionStateMachine
             }
         }
 
+        @Override
+        public void exitState() {
+            IkeSaPayload saPayload =
+                    mRekeyRequestMsg.getPayloadForType(
+                            IkePayload.PAYLOAD_TYPE_SA, IkeSaPayload.class);
+            if (saPayload != null) {
+                saPayload.releaseSpiResources();
+            }
+            mRekeyRequestMsg = null;
+        }
+
         @Override
         protected void triggerRetransmit() {
             mRetransmitter.retransmit();
diff --git a/src/java/com/android/internal/net/ipsec/ike/SaRecord.java b/src/java/com/android/internal/net/ipsec/ike/SaRecord.java
index b46d4bbd..16aea21c 100644
--- a/src/java/com/android/internal/net/ipsec/ike/SaRecord.java
+++ b/src/java/com/android/internal/net/ipsec/ike/SaRecord.java
@@ -675,6 +675,8 @@ public abstract class SaRecord implements AutoCloseable {
 
             mInitiatorSpiResource = initSpi;
             mResponderSpiResource = respSpi;
+            mInitiatorSpiResource.bindToIkeSaRecord();
+            mResponderSpiResource.bindToIkeSaRecord();
 
             mSkD = skD;
             mSkPi = skPi;
@@ -925,6 +927,8 @@ public abstract class SaRecord implements AutoCloseable {
         @Override
         public void close() {
             super.close();
+            mInitiatorSpiResource.unbindFromIkeSaRecord();
+            mResponderSpiResource.unbindFromIkeSaRecord();
             mInitiatorSpiResource.close();
             mResponderSpiResource.close();
         }
diff --git a/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayload.java b/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayload.java
index 9c20a7ad..fa38731f 100644
--- a/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayload.java
+++ b/src/java/com/android/internal/net/ipsec/ike/message/IkeSaPayload.java
@@ -583,17 +583,16 @@ public final class IkeSaPayload extends IkePayload {
     }
 
     /**
-     * Release IPsec SPI resources in the outbound Create Child request
+     * Release SPI resources in the outbound Create IKE/Child request
      *
-     * <p>This method is usually called when an IKE library fails to receive a Create Child response
-     * before it is terminated. It is also safe to call after the Create Child exchange has
-     * succeeded because the newly created IpSecTransform pair will hold the IPsec SPI resource.
+     * <p>This method is usually called when an IKE library fails to receive a Create IKE/Child
+     * response before it is terminated. It is also safe to call after the Create IKE/Child exchange
+     * has succeeded because the newly created IkeSaRecord or ChildSaRecord (IpSecTransform pair)
+     * will hold the SPI resource.
      */
-    public void releaseChildSpiResourcesIfExists() {
+    public void releaseSpiResources() {
         for (Proposal proposal : proposalList) {
-            if (proposal instanceof ChildProposal) {
-                proposal.releaseSpiResourceIfExists();
-            }
+            proposal.releaseSpiResourceIfExists();
         }
     }
 
diff --git a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
index 02f201ce..847d27b1 100644
--- a/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
+++ b/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionController.java
@@ -256,6 +256,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
 
     /** Config includes all configurations to build an IkeConnectionController */
     public static class Config {
+        public final Handler ikeHandler;
         public final IkeSessionParams ikeParams;
         public final int ikeSessionId;
         public final int alarmCmd;
@@ -264,11 +265,13 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
 
         /** Constructor for IkeConnectionController.Config */
         public Config(
+                Handler ikeHandler,
                 IkeSessionParams ikeParams,
                 int ikeSessionId,
                 int alarmCmd,
                 int sendKeepaliveCmd,
                 Callback callback) {
+            this.ikeHandler = ikeHandler;
             this.ikeParams = ikeParams;
             this.ikeSessionId = ikeSessionId;
             this.alarmCmd = alarmCmd;
@@ -386,15 +389,15 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
     }
 
     private static IkeAlarmConfig buildInitialKeepaliveAlarmConfig(
-            Handler handler,
             IkeContext ikeContext,
             Config config,
             IkeSessionParams ikeParams,
             NetworkCapabilities nc) {
-        final Message keepaliveMsg = handler.obtainMessage(
-                config.alarmCmd /* what */,
-                config.ikeSessionId /* arg1 */,
-                config.sendKeepaliveCmd /* arg2 */);
+        final Message keepaliveMsg =
+                config.ikeHandler.obtainMessage(
+                        config.alarmCmd /* what */,
+                        config.ikeSessionId /* arg1 */,
+                        config.sendKeepaliveCmd /* arg2 */);
         final PendingIntent keepaliveIntent = IkeAlarm.buildIkeAlarmIntent(ikeContext.getContext(),
                 ACTION_KEEPALIVE, getIntentIdentifier(config.ikeSessionId), keepaliveMsg);
 
@@ -507,8 +510,8 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         // mixing callbacks and synchronous polling methods.
         LinkProperties linkProperties = mConnectivityManager.getLinkProperties(mNetwork);
         mNc = mConnectivityManager.getNetworkCapabilities(mNetwork);
-        mKeepaliveAlarmConfig = buildInitialKeepaliveAlarmConfig(
-                new Handler(mIkeContext.getLooper()), mIkeContext, mConfig, mIkeParams, mNc);
+        mKeepaliveAlarmConfig =
+                buildInitialKeepaliveAlarmConfig(mIkeContext, mConfig, mIkeParams, mNc);
         try {
             if (linkProperties == null || mNc == null) {
                 // Throw NPE to preserve the existing behaviour for backward compatibility
@@ -1015,6 +1018,11 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         return false;
     }
 
+    private boolean isNattSupported() {
+        return mNatStatus != NAT_TRAVERSAL_UNSUPPORTED
+                && mNatStatus != NAT_TRAVERSAL_SUPPORT_NOT_CHECKED;
+    }
+
     /**
      * Set the remote address for the peer.
      *
@@ -1108,7 +1116,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
     public void enableMobility() throws IkeException {
         mMobilityEnabled = true;
 
-        if (mNatStatus != NAT_TRAVERSAL_UNSUPPORTED
+        if (isNattSupported()
                 && mIkeSocket.getIkeServerPort() != IkeSocket.SERVER_PORT_UDP_ENCAPSULATED) {
             getAndSwitchToIkeSocket(
                     mRemoteAddress instanceof Inet4Address, true /* useEncapPort */);
@@ -1261,9 +1269,8 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
         boolean isIpv4 = mRemoteAddress instanceof Inet4Address;
 
         // If it is known that the server supports NAT-T, use port 4500. Otherwise, use port 500.
-        boolean nattSupported = mNatStatus != NAT_TRAVERSAL_UNSUPPORTED;
         int serverPort =
-                nattSupported
+                isNattSupported()
                         ? IkeSocket.SERVER_PORT_UDP_ENCAPSULATED
                         : IkeSocket.SERVER_PORT_NON_UDP_ENCAPSULATED;
 
@@ -1286,7 +1293,7 @@ public class IkeConnectionController implements IkeNetworkUpdater, IkeSocket.Cal
             }
 
             if (!mNetwork.equals(oldNetwork)) {
-                boolean useEncapPort = mForcePort4500 || nattSupported;
+                boolean useEncapPort = mForcePort4500 || isNattSupported();
                 getAndSwitchToIkeSocket(mLocalAddress instanceof Inet4Address, useEncapPort);
             }
 
diff --git a/src/java/com/android/internal/net/ipsec/ike/utils/IkeSecurityParameterIndex.java b/src/java/com/android/internal/net/ipsec/ike/utils/IkeSecurityParameterIndex.java
index 73369485..c7c28ca3 100644
--- a/src/java/com/android/internal/net/ipsec/ike/utils/IkeSecurityParameterIndex.java
+++ b/src/java/com/android/internal/net/ipsec/ike/utils/IkeSecurityParameterIndex.java
@@ -48,10 +48,17 @@ public final class IkeSecurityParameterIndex implements AutoCloseable {
     private final long mSpi;
     private final CloseGuard mCloseGuard = new CloseGuard();
 
+    /**
+     * Whether this SPI has been used to construct an IkeSaRecord. If it is bound, then this SPI
+     * cannot be released unless it is unbound from the IkeSaRecord.
+     */
+    private boolean mIsBoundToIkeSaRecord;
+
     // Package private constructor that MUST only be called from IkeSpiGenerator
     IkeSecurityParameterIndex(InetAddress sourceAddress, long spi) {
         mSourceAddress = sourceAddress;
         mSpi = spi;
+        mIsBoundToIkeSaRecord = false;
         mCloseGuard.open("close");
     }
 
@@ -73,6 +80,10 @@ public final class IkeSecurityParameterIndex implements AutoCloseable {
     /** Release an SPI that was previously reserved. */
     @Override
     public void close() {
+        if (mIsBoundToIkeSaRecord) {
+            return;
+        }
+
         sAssignedIkeSpis.remove(new Pair<InetAddress, Long>(mSourceAddress, mSpi));
         mCloseGuard.close();
     }
@@ -106,4 +117,25 @@ public final class IkeSecurityParameterIndex implements AutoCloseable {
         sAssignedIkeSpis.remove(new Pair<InetAddress, Long>(mSourceAddress, mSpi));
         mSourceAddress = newSourceAddress;
     }
+
+    /**
+     * Bind this SPI to an IkeSaRecord
+     *
+     * <p>This MUST ONLY be called from an IkeSaRecord
+     */
+    public void bindToIkeSaRecord() {
+        if (mIsBoundToIkeSaRecord) {
+            throw new IllegalStateException("Already bound");
+        }
+        mIsBoundToIkeSaRecord = true;
+    }
+
+    /**
+     * Unbind this SPI from an IkeSaRecord
+     *
+     * <p>This MUST ONLY be called from an IkeSaRecord
+     */
+    public void unbindFromIkeSaRecord() {
+        mIsBoundToIkeSaRecord = false;
+    }
 }
diff --git a/src/java/com/android/internal/net/package-info.java b/src/java/com/android/internal/net/package-info.java
new file mode 100644
index 00000000..2c68eeb7
--- /dev/null
+++ b/src/java/com/android/internal/net/package-info.java
@@ -0,0 +1,22 @@
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
+/**
+ * Exclude from API surfaces
+ *
+ * @hide
+ */
+package com.android.internal.net;
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index 6bfb8287..a16b1788 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -26,7 +26,7 @@ android_test {
 
     libs: [
         "android.net.ipsec.ike.stubs.system",
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
 
     srcs: [
diff --git a/tests/cts/AndroidTest.xml b/tests/cts/AndroidTest.xml
index 404bda48..852eec3d 100644
--- a/tests/cts/AndroidTest.xml
+++ b/tests/cts/AndroidTest.xml
@@ -19,6 +19,7 @@
     <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
     <option name="config-descriptor:metadata" key="parameter" value="no_foldable_states" />
     <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
     <option name="not-shardable" value="true" />
     <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.ipsec.apex" />
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
diff --git a/tests/cts/src/android/ipsec/ike/cts/IkeSessionTestBase.java b/tests/cts/src/android/ipsec/ike/cts/IkeSessionTestBase.java
index 9ef9e299..85c6bc5d 100644
--- a/tests/cts/src/android/ipsec/ike/cts/IkeSessionTestBase.java
+++ b/tests/cts/src/android/ipsec/ike/cts/IkeSessionTestBase.java
@@ -169,11 +169,11 @@ abstract class IkeSessionTestBase extends IkeTestNetworkBase {
         for (String pkg : new String[] {"com.android.shell", sContext.getPackageName()}) {
             String cmd =
                     String.format(
-                            "appops set %s %s %s --user %d",
+                            "appops set --user %d %s %s %s",
+                            UserHandle.myUserId(), // user id
                             pkg, // Package name
                             opName, // Appop
-                            (allow ? "allow" : "deny"), // Action
-                            UserHandle.myUserId());
+                            (allow ? "allow" : "deny")); // Action
 
             SystemUtil.runShellCommand(cmd);
         }
diff --git a/tests/iketests/Android.bp b/tests/iketests/Android.bp
index ab215bec..0bcb5892 100644
--- a/tests/iketests/Android.bp
+++ b/tests/iketests/Android.bp
@@ -27,7 +27,7 @@ android_test {
 
     compile_multilib: "both",
 
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs"],
 
     test_config: "FrameworksIkeTests.xml",
 
diff --git a/tests/iketests/assets/pem/end-cert-a.pem b/tests/iketests/assets/pem/end-cert-a.pem
index 2e872952..89411f8e 100644
--- a/tests/iketests/assets/pem/end-cert-a.pem
+++ b/tests/iketests/assets/pem/end-cert-a.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-MIIDRzCCAi+gAwIBAgIIZSciRUaEUakwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
+MIIDXDCCAkSgAwIBAgIIKhyy9FBvmqowDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxHDAaBgNVBAMTE2NhLnRlc3QuYW5kcm9p
-ZC5uZXQwHhcNMTkwNzE2MTcxODMxWhcNMjQwNzE0MTcxODMxWjBBMQswCQYDVQQG
+ZC5uZXQwHhcNMjQwNzE3MjEwNDU0WhcNMzQwNzE1MjEwNDU0WjBBMQswCQYDVQQG
 EwJVUzEQMA4GA1UEChMHQW5kcm9pZDEgMB4GA1UEAxMXc2VydmVyLnRlc3QuYW5k
-cm9pZC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpU5M+c3Qg
-Sej5NeCboB5T6R0XaODqo/hpZFkjTXt5ku2lvsioLU0xC38K9Cym7kPU0kGMAl1p
-tatMZ2Uxde/sDiLyFwYgx//TniDNnxdDXYYxcZNbfV4ERcuPmTexq9t86MneVkxn
-hJ9dEBJcr2goFaFIebCUlj3DF827/JQhWgV54M9trPOGOyoRy5HvH+IxOOt8PXaL
-vySQZxo4bC6m+qeQQZCgZAwvGagFF9KjVFyKt9ZAVp97wQi7yo+Bzm5I54C4EUbT
-XnTRITQXqFKOUXVGYPChwgZTEz/2s6Wh1CR0LjNFTaDMlsUJkUbGn27iZc90nd5w
-6WAXYQgsmXnTAgMBAAGjRzBFMB8GA1UdIwQYMBaAFGYUzuvZUaVJl8mcxejuFiUN
-GcTfMCIGA1UdEQQbMBmCF3NlcnZlci50ZXN0LmFuZHJvaWQubmV0MA0GCSqGSIb3
-DQEBCwUAA4IBAQByajAzcLrMc2gjDSzTd+5/VTgLhoJfJul3FgsUzZHa9EiRUChV
-O94ZCLWWoZxeB0iejaUqrLz/xCJqeC3wbNP7LejiW2qgUAoJdOvNtDGiVx2P7wid
-iXS4y49+IYP+T1BVWNNrI+zcAycN2uiQlEKR5KQ3cNXVHZoiVOroheHzi8ezSeYM
-j5bhJ2GbpOw9/4PkaBonnQNs9sljkyZ2keYrir1xzf4PI9gieXniJcNuAjYNaAAA
-oaHKXah9NggbAVEXEZjLoKtQQqWFz9wNE8AXsIdoD4gOeBuwNQSyn+FmDJdI/mpA
-enbz3qbTVurltTHySye0+nhlP7XTifyEanXM
------END CERTIFICATE-----
\ No newline at end of file
+cm9pZC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlaV4GnQd7
+vxAwZ9tIadkknDYXpfMkLr8AnKnzvr99XBqLQKubKa1DGX8rzz84uwCs3qLH9Y8F
+szSXh0eylzCFWHXKQBme1Y4ZXKBbyW+E90H6+XnWf8bpUPvxutC4OnehdTPaz48z
+WQMKVRAVRtO+vEuHHnevobHnDphBP6592E0IB8/Ct9coHSwDj4t17U1vSyJn7Fgo
+Lee2ILySQt+SvAoV5lK/9twBNuG51SoRw+vcTYyNyIPU0M+LNoAFH7B5BNlBQc7h
+FUZOT8tfbWZ1g3qNhvCdk7CB4Ol5gCFx9+csHgrB/ceMcOMv+J0Qu853/oQcqnfE
+A2lkNt/fbB3zAgMBAAGjXDBaMB8GA1UdIwQYMBaAFGU7dEeh4jcm9I4JjiDZu5cG
+AfVsMCIGA1UdEQQbMBmCF3NlcnZlci50ZXN0LmFuZHJvaWQubmV0MBMGA1UdJQQM
+MAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQAkda/LaiRL0FqcxHEo4y7J
+zX7Z3YY/oV/vnCJ/HgloJNBri/VT15Ycudts6lhL22NRXuvbh4nFgALrRqzs8a/L
++nyxDzE8m4sVDv9rzpP4ukydle4BRSg/kvcW6nDIF9YqulbLHKEP8kfMcKIlwWa4
+hBPDxb4Bss2UfQj21pYDGDzsGb4/Bp1GF7RXy/1FMJLc8sIxjgkSzzBJede4eif8
+6QjIwXSLSPIW6z6kzTIuofR7yLTHZSylx8PR2pNgssulzmzsZEmYbo3hO4ydhpMW
+DCRg99Db8MJQWBnrneATbjVWK3l8WFkoT7zxEoLHl3/UAaGxnLhIRMah+cehVaJE
+-----END CERTIFICATE-----
diff --git a/tests/iketests/assets/pem/self-signed-ca-a.pem b/tests/iketests/assets/pem/self-signed-ca-a.pem
index 5135ea70..e4ad5b4b 100644
--- a/tests/iketests/assets/pem/self-signed-ca-a.pem
+++ b/tests/iketests/assets/pem/self-signed-ca-a.pem
@@ -1,20 +1,20 @@
 -----BEGIN CERTIFICATE-----
-MIIDPjCCAiagAwIBAgIICrKLpR7LxlowDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
+MIIDPjCCAiagAwIBAgIIOLCjfFfLlBQwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UE
 BhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxHDAaBgNVBAMTE2NhLnRlc3QuYW5kcm9p
-ZC5uZXQwHhcNMTkwNzE2MTcxNTUyWhcNMjkwNzEzMTcxNTUyWjA9MQswCQYDVQQG
+ZC5uZXQwHhcNMjQwNzE3MjAzMzQwWhcNMzQwNzE1MjAzMzQwWjA9MQswCQYDVQQG
 EwJVUzEQMA4GA1UEChMHQW5kcm9pZDEcMBoGA1UEAxMTY2EudGVzdC5hbmRyb2lk
-Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANsvTwad2Nie0VOy
-Xb1VtHL0R760Jm4vr14JWMcX4oiE6jUdTNdXQ0CGb65wvulP2aEeukFH0D/cvBMR
-Bv9+haEwo9/grIXg9ALNKp+GfuZYw/dfnUMHFn3g2+SUgP6BoMZc4lkHktjkDKxp
-99Q6h4NP/ip1labkhBeB9+Z6l78LTixKRKspNITWASJed9bjzshYxKHi6dJy3maQ
-1LwYKmK7PEGRpoDoT8yZhFbxsVDUojGnJKH1RLXVOn/psG6dI/+IsbTipAttj5zc
-g2VAD56PZG2Jd+vsup+g4Dy72hyy242x5c/H2LKZn4X0B0B+IXyii/ZVc+DJldQ5
-JqplOL8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
-HQYDVR0OBBYEFGYUzuvZUaVJl8mcxejuFiUNGcTfMA0GCSqGSIb3DQEBCwUAA4IB
-AQDQYeqjvHsK2ZqSqxakDp0nu36Plbj48Wvx1ru7GW2faz7i0w/Zkxh06zniILCb
-QJRjDebSTHc5SSbCFrRTvqagaLDhbH42/hQncWqIoJqW+pmznJET4JiBO0sqzm05
-yQWsLI/h9Ir28Y2g5N+XPBU0VVVejQqH4iI0iwQx7y7ABssQ0Xa/K73VPbeGaKd6
-Prt4wjJvTlIL2yE2+0MggJ3F2rNptL5SDpg3g+4/YQ6wVRBFil95kUqplEsCtU4P
-t+8RghiEmsRx/8CywKfZ5Hex87ODhsSDmDApcefbd5gxoWVkqxZUkPcKwYv1ucm8
-u4r44fj4/9W0Zeooav5Yoh1q
------END CERTIFICATE-----
\ No newline at end of file
+Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALeEtPaf/FZfS79U
+FKsINkw1FkFgpmAjDqcqAChDXHhUZc1U1i2F81q97gC4sTTVgmIdHGqRGdOK/28l
+LnRXfxsVi6QDZxjqcbaUhoO8TF3Mqa60eTOFr9ItKWCnuORvbIGA6Q5D8XGHEiZ6
+P16gFXHDJzU69I+WPqQjtCKyK4WhOpZZPXz2+zv5ZWrlnPVXHmHzwyYK6OhzS4Jr
+aDICWPmhsfTI4ph3rSSlWW5tmzs0wis/BDOfi28WQfbF8tsUETLK6au6qF8ZR8qY
+lD/rjM9WmBcq8sjwAzvU4d1e4C6SpN80MsYdgSd1MyxMdMZL2MW66csGqd7grj/B
+8zP2xsECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
+HQYDVR0OBBYEFGU7dEeh4jcm9I4JjiDZu5cGAfVsMA0GCSqGSIb3DQEBCwUAA4IB
+AQC0wd9zAVofbow0aORvBA7nA9J3JFzIoOkeBTJzlJaP/SmfduS13CXEdzMwLgNv
+5kE0NXzI29kPxhFjY7h7kdx4YuxlyxfS2jTqkt66XzTuAlXW+2LrmfDhjUZc3IVR
+SrYESzxbCnv9oa/or70lXAOhvzkH7NrmIy7xzRObLouGpuhLo2qpwFFac1NVshJq
+4YlgOunDI3/IXnhFofJAUXDAoD8TIVQUbH7+HoY9pC0Ozv4BbgKTskVqrHG6vxe3
+HJNP+/9QTMT9viLeYol2Ttzqg0wyWdD7Gt5twMBE1J7/pCY9ZNTo/IUhmJ/nMsw4
+gkT0pO/v+ILI1Z0l4UGwP62K
+-----END CERTIFICATE-----
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
index 99a127cb..747c5b16 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/IkeSessionStateMachineTest.java
@@ -153,6 +153,7 @@ import android.net.ipsec.test.ike.ike3gpp.Ike3gppExtension;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppExtension.Ike3gppDataListener;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppN1ModeInformation;
 import android.net.ipsec.test.ike.ike3gpp.Ike3gppParams;
+import android.os.Handler;
 import android.os.test.TestLooper;
 import android.telephony.TelephonyManager;
 
@@ -450,6 +451,7 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
     private EapAuthenticator mMockEapAuthenticator;
 
     private IkeConnectionController mSpyIkeConnectionCtrl;
+    private IkeSpiGenerator mSpyIkeSpiGenerator;
 
     private Ike3gppDataListener mMockIke3gppDataListener;
     private Ike3gppExtension mIke3gppExtension;
@@ -891,6 +893,9 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
                 .when(spyDeps)
                 .newIkeConnectionController(
                         any(IkeContext.class), any(IkeConnectionController.Config.class));
+        doReturn(mSpyIkeSpiGenerator)
+                .when(spyDeps)
+                .newIkeSpiGenerator(any(RandomnessFactory.class));
         injectChildSessionInSpyDeps(spyDeps, child, childCb);
 
 
@@ -989,12 +994,16 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
                         new IkeConnectionController(
                                 ikeContext,
                                 new IkeConnectionController.Config(
+                                        new Handler(mLooper.getLooper()),
                                         ikeParams,
                                         FAKE_SESSION_ID,
                                         CMD_ALARM_FIRED,
                                         CMD_SEND_KEEPALIVE,
                                         mockIkeConnectionCtrlCb),
                                 spyIkeConnectionCtrlDeps));
+
+        mSpyIkeSpiGenerator = spy(new IkeSpiGenerator(createMockRandomFactory()));
+
         mSpyDeps =
                 buildSpyDepsWithChildSession(
                         mMockChildSessionStateMachine, mMockChildSessionCallback);
@@ -1016,6 +1025,7 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         ikeSession.setDbg(true);
 
         mLooper.dispatchAll();
+
         mMockCurrentIkeSocket = mSpyIkeConnectionCtrl.getIkeSocket();
         assertEquals(expectedRemoteAddress, mSpyIkeConnectionCtrl.getRemoteAddress());
 
@@ -1723,6 +1733,48 @@ public final class IkeSessionStateMachineTest extends IkeSessionTestBase {
         assertEquals(expectedDhGroup, kePayload.dhGroup);
     }
 
+    @Test
+    public void testCreateIkeLocalIkeInit_closeSpi_ikeTerminated() throws Exception {
+        // Setup
+        final IkeSecurityParameterIndex mockIkeSpi = mock(IkeSecurityParameterIndex.class);
+        doReturn(mockIkeSpi).when(mSpyIkeSpiGenerator).allocateSpi(any(InetAddress.class));
+
+        // Send out IKE INIT request
+        mIkeSessionStateMachine.sendMessage(IkeSessionStateMachine.CMD_LOCAL_REQUEST_CREATE_IKE);
+        mLooper.dispatchAll();
+
+        // Verifications
+        verify(mSpyIkeSpiGenerator).allocateSpi(any(InetAddress.class));
+
+        mIkeSessionStateMachine.killSession();
+        mLooper.dispatchAll();
+
+        verify(mockIkeSpi).close();
+    }
+
+    @Test
+    public void testRekeyIkeLocalCreate_closeSpi_ikeTerminated() throws Exception {
+        // Setup
+        setupIdleStateMachine();
+        final IkeSecurityParameterIndex mockIkeSpi = mock(IkeSecurityParameterIndex.class);
+        doReturn(mockIkeSpi).when(mSpyIkeSpiGenerator).allocateSpi(any(InetAddress.class));
+
+        // Send Rekey-Create request
+        mIkeSessionStateMachine.sendMessage(
+                IkeSessionStateMachine.CMD_EXECUTE_LOCAL_REQ,
+                mLocalRequestFactory.getIkeLocalRequest(
+                        IkeSessionStateMachine.CMD_LOCAL_REQUEST_REKEY_IKE));
+        mLooper.dispatchAll();
+
+        // Verifications
+        verify(mSpyIkeSpiGenerator).allocateSpi(any(InetAddress.class));
+
+        mIkeSessionStateMachine.killSession();
+        mLooper.dispatchAll();
+
+        verify(mockIkeSpi).close();
+    }
+
     @Test
     public void testCreateIkeLocalIkeInitNegotiatesDhGroup() throws Exception {
         // Clear the calls triggered by starting IkeSessionStateMachine in #setup()
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
index 8551dce0..344b53d8 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/SaRecordTest.java
@@ -21,12 +21,14 @@ import static com.android.internal.net.TestUtils.createMockRandomFactory;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
 import static org.mockito.AdditionalMatchers.aryEq;
 import static org.mockito.Matchers.anyInt;
 import static org.mockito.Matchers.anyObject;
 import static org.mockito.Matchers.anyString;
 import static org.mockito.Matchers.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
@@ -177,9 +179,9 @@ public final class SaRecordTest {
         byte[] nonceResp = TestUtils.hexStringToByteArray(IKE_NONCE_RESP_HEX_STRING);
 
         IkeSecurityParameterIndex ikeInitSpi =
-                IKE_SPI_GENERATOR.allocateSpi(LOCAL_ADDRESS, IKE_INIT_SPI);
+                spy(IKE_SPI_GENERATOR.allocateSpi(LOCAL_ADDRESS, IKE_INIT_SPI));
         IkeSecurityParameterIndex ikeRespSpi =
-                IKE_SPI_GENERATOR.allocateSpi(REMOTE_ADDRESS, IKE_RESP_SPI);
+                spy(IKE_SPI_GENERATOR.allocateSpi(REMOTE_ADDRESS, IKE_RESP_SPI));
         IkeSaRecordConfig ikeSaRecordConfig =
                 new IkeSaRecordConfig(
                         ikeInitSpi,
@@ -221,9 +223,13 @@ public final class SaRecordTest {
         assertArrayEquals(
                 TestUtils.hexStringToByteArray(IKE_SK_PRF_RESP_HEX_STRING), ikeSaRecord.getSkPr());
         verify(mMockLifetimeAlarmScheduler).scheduleLifetimeExpiryAlarm(anyString());
+        verify(ikeInitSpi).bindToIkeSaRecord();
+        verify(ikeRespSpi).bindToIkeSaRecord();
 
         ikeSaRecord.close();
         verify(mMockLifetimeAlarmScheduler).cancelLifetimeExpiryAlarm(anyString());
+        verify(ikeInitSpi).unbindFromIkeSaRecord();
+        verify(ikeRespSpi).unbindFromIkeSaRecord();
     }
 
     // Test generating keying material and building IpSecTransform for making Child SA.
@@ -379,4 +385,29 @@ public final class SaRecordTest {
     public void testRemoteInitChildKeyExchange() throws Exception {
         verifyChildKeyExchange(false /* isLocalInit */);
     }
+
+    @Test
+    public void testBindIkeSpiToSaRecord() throws Exception {
+        IkeSecurityParameterIndex ikeInitSpi =
+                IKE_SPI_GENERATOR.allocateSpi(LOCAL_ADDRESS, IKE_INIT_SPI);
+
+        // Try closing SPI that is bound to an IKE SA
+        ikeInitSpi.bindToIkeSaRecord();
+        ikeInitSpi.close();
+
+        try {
+            IKE_SPI_GENERATOR.allocateSpi(LOCAL_ADDRESS, IKE_INIT_SPI);
+            fail("Expect to fail since this SPI-address combo is not released");
+        } catch (Exception expected) {
+        }
+
+        // Try closing SPI that is no longer bound to an IKE SA
+        ikeInitSpi.unbindFromIkeSaRecord();
+        ikeInitSpi.close();
+
+        IkeSecurityParameterIndex ikeInitSpiAnother =
+                IKE_SPI_GENERATOR.allocateSpi(LOCAL_ADDRESS, IKE_INIT_SPI);
+        assertEquals(LOCAL_ADDRESS, ikeInitSpiAnother.getSourceAddress());
+        assertEquals(IKE_INIT_SPI, ikeInitSpiAnother.getSpi());
+    }
 }
diff --git a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
index 58e5252d..52324fde 100644
--- a/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
+++ b/tests/iketests/src/java/com/android/internal/net/ipsec/ike/net/IkeConnectionControllerTest.java
@@ -77,6 +77,7 @@ import android.net.ipsec.test.ike.exceptions.IkeException;
 import android.net.ipsec.test.ike.exceptions.IkeIOException;
 import android.net.ipsec.test.ike.exceptions.IkeInternalException;
 import android.os.Build.VERSION_CODES;
+import android.os.Handler;
 import android.os.Looper;
 
 import com.android.internal.net.TestUtils;
@@ -127,6 +128,7 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
 
     private static final int KEEPALIVE_DELAY_CALLER_CONFIGURED = 50;
 
+    private Handler mIkeHandler;
     private IkeSessionParams mMockIkeParams;
     private IkeAlarmConfig mMockAlarmConfig;
     private IkeNattKeepalive mMockIkeNattKeepalive;
@@ -144,6 +146,7 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
     private IkeConnectionController mIkeConnectionCtrl;
 
     private IkeConnectionController buildIkeConnectionCtrl() throws Exception {
+        mIkeHandler = new Handler(mIkeContext.getLooper());
         mMockConnectionCtrlCb = mock(IkeConnectionController.Callback.class);
         mMockConnectionCtrlDeps = mock(IkeConnectionController.Dependencies.class);
 
@@ -168,7 +171,11 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
         return new IkeConnectionController(
                 mIkeContext,
                 new IkeConnectionController.Config(
-                        mMockIkeParams, FAKE_SESSION_ID, MOCK_ALARM_CMD, MOCK_KEEPALIVE_CMD,
+                        mIkeHandler,
+                        mMockIkeParams,
+                        FAKE_SESSION_ID,
+                        MOCK_ALARM_CMD,
+                        MOCK_KEEPALIVE_CMD,
                         mMockConnectionCtrlCb),
                 mMockConnectionCtrlDeps);
     }
@@ -1093,6 +1100,20 @@ public class IkeConnectionControllerTest extends IkeSessionTestBase {
         verifyKeepalive(false /* hasOldKeepalive */, false /* isKeepaliveExpected */);
     }
 
+    @Test
+    public void testEnableIpv6MobilityWithNatNotChecked() throws Exception {
+        setupLocalAddressForNetwork(mMockDefaultNetwork, LOCAL_ADDRESS_V6);
+        setupRemoteAddressForNetwork(mMockDefaultNetwork, REMOTE_ADDRESS_V6);
+
+        mIkeConnectionCtrl = buildIkeConnectionCtrl();
+        mIkeConnectionCtrl.setUp();
+        mIkeConnectionCtrl.enableMobility();
+
+        assertTrue(mIkeConnectionCtrl.getIkeSocket() instanceof IkeUdp6Socket);
+        assertFalse(mIkeConnectionCtrl.getIkeSocket() instanceof IkeUdp6WithEncapPortSocket);
+        verifyKeepalive(false /* hasOldKeepalive */, false /* isKeepaliveExpected */);
+    }
+
     @Test
     public void handleNatDetectionResultInMobike() throws Exception {
         mIkeConnectionCtrl.handleNatDetectionResultInMobike(true /* isNatDetected */);
```

