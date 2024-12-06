```diff
diff --git a/Android.bp b/Android.bp
index c2872ca..fe33720 100644
--- a/Android.bp
+++ b/Android.bp
@@ -27,9 +27,6 @@ android_app {
         "telephony-common",
         "app-compat-annotations",
     ],
-    static_libs: [
-        "telephony_flags_core_java_lib",
-    ],
     srcs: [
         "src/**/*.java",
         ":statslog-ons-java-gen",
diff --git a/src/com/android/ons/ONSProfileSelector.java b/src/com/android/ons/ONSProfileSelector.java
index d9e5d07..ba2c877 100644
--- a/src/com/android/ons/ONSProfileSelector.java
+++ b/src/com/android/ons/ONSProfileSelector.java
@@ -323,7 +323,13 @@ public class ONSProfileSelector {
         return null;
     }
 
-    public boolean isOpprotunisticSub(int subId) {
+    /**
+     * Return whether the subId is for an opportunistic subscription.
+     *
+     * @param subId the subId of the subscription.
+     * @return true if the subscription is opportunistic
+     */
+    public boolean isOpportunisticSub(int subId) {
         if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.size() == 0)) {
             return false;
         }
@@ -344,7 +350,7 @@ public class ONSProfileSelector {
         }
 
         for (AvailableNetworkInfo availableNetworkInfo : availableNetworks) {
-            if (!isOpprotunisticSub(availableNetworkInfo.getSubId())) {
+            if (!isOpportunisticSub(availableNetworkInfo.getSubId())) {
                 return false;
             }
         }
@@ -840,7 +846,7 @@ public class ONSProfileSelector {
     public void selectProfileForData(int subId, boolean needValidation,
             ISetOpportunisticDataCallback callbackStub) {
         if ((subId == SubscriptionManager.DEFAULT_SUBSCRIPTION_ID)
-                || (isOpprotunisticSub(subId) && mSubscriptionManager.isActiveSubId(subId))) {
+                || (isOpportunisticSub(subId) && mSubscriptionManager.isActiveSubId(subId))) {
             try {
                 mSubscriptionManager.setPreferredDataSubscriptionId(subId, needValidation,
                         mHandler::post, result -> sendSetOpptCallbackHelper(callbackStub, result));
@@ -862,7 +868,7 @@ public class ONSProfileSelector {
             log("Inactive sub passed for preferred data " + subId);
             if (Compatibility.isChangeEnabled(
                     OpportunisticNetworkService.CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
-                if (isOpprotunisticSub(subId)) {
+                if (isOpportunisticSub(subId)) {
                     sendSetOpptCallbackHelper(callbackStub,
                             TelephonyManager.SET_OPPORTUNISTIC_SUB_INACTIVE_SUBSCRIPTION);
                 } else {
@@ -877,7 +883,10 @@ public class ONSProfileSelector {
     }
 
     public int getPreferredDataSubscriptionId() {
-        return mSubscriptionManager.getPreferredDataSubscriptionId();
+        final int preferredDataSubId = mSubscriptionManager.getPreferredDataSubscriptionId();
+        return isOpportunisticSub(preferredDataSubId)
+            ? preferredDataSubId
+            : SubscriptionManager.DEFAULT_SUBSCRIPTION_ID;
     }
 
     /**
diff --git a/tests/Android.bp b/tests/Android.bp
index a8c2774..a5aa34b 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -21,10 +21,10 @@ android_test {
     name: "ONSTests",
     srcs: ["src/com/android/ons//**/*.java"],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.mock",
-        "android.test.base",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
```

