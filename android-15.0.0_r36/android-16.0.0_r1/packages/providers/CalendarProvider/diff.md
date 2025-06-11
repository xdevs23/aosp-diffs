```diff
diff --git a/Android.bp b/Android.bp
index 26493e0..1f14b0f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,6 +26,7 @@ android_app {
         "guava",
         "android-common",
         "calendar-common",
+        "calendarprovider_flags_java_lib",
     ],
     srcs: [
         "src/**/*.java",
@@ -49,3 +50,15 @@ platform_compat_config {
     name: "calendar-provider-compat-config",
     src: ":CalendarProvider",
 }
+
+java_aconfig_library {
+    name: "calendarprovider_flags_java_lib",
+    aconfig_declarations: "calendarprovider_flags",
+}
+
+aconfig_declarations {
+    name: "calendarprovider_flags",
+    container: "system",
+    package: "com.android.providers.calendar",
+    srcs: ["**/calendarprovider_flags.aconfig"],
+}
diff --git a/calendarprovider_flags.aconfig b/calendarprovider_flags.aconfig
new file mode 100644
index 0000000..9d2a0c5
--- /dev/null
+++ b/calendarprovider_flags.aconfig
@@ -0,0 +1,12 @@
+package: "com.android.providers.calendar"
+container: "system"
+
+flag {
+    name: "defer_post_initialize_work"
+    namespace: "backstage_power"
+    description: "Defer the post initialization work after BOOT_COMPLETED is handled"
+    bug: "388910023"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+    }
+}
diff --git a/src/com/android/providers/calendar/CalendarProvider2.java b/src/com/android/providers/calendar/CalendarProvider2.java
index 68ba5a0..4044854 100644
--- a/src/com/android/providers/calendar/CalendarProvider2.java
+++ b/src/com/android/providers/calendar/CalendarProvider2.java
@@ -479,6 +479,13 @@ public class CalendarProvider2 extends SQLiteContentProvider implements OnAccoun
 
     private int mParentUserId;
 
+    // Indicates that the post-init work is in progress and additional work in the BOOT_COMPLETED
+    // broadcast shouldn't be executed to avoid contention.
+    private volatile boolean mPostInitializeWorkRunning = false;
+    // Indicates that the removal of scheduled alarms (as part of the BOOT_COMPLETED work) is
+    // pending because the post-init work was running concurrently.
+    private volatile boolean mPendingScheduledAlarmsRemoval = false;
+
     /**
      * Listens for timezone changes and disk-no-longer-full events
      */
@@ -595,6 +602,7 @@ public class CalendarProvider2 extends SQLiteContentProvider implements OnAccoun
     private class PostInitializeThread extends Thread {
         @Override
         public void run() {
+            mPostInitializeWorkRunning = true;
             Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
 
             verifyAccounts();
@@ -607,6 +615,13 @@ public class CalendarProvider2 extends SQLiteContentProvider implements OnAccoun
 
                 // Nothing actionable here anyways.
             }
+            mPostInitializeWorkRunning = false;
+            if (Flags.deferPostInitializeWork()) {
+                if (mPendingScheduledAlarmsRemoval) {
+                    mPendingScheduledAlarmsRemoval = false;
+                    CalendarReceiver.removeScheduledAlarms(mContentResolver);
+                }
+            }
         }
     }
 
@@ -2315,6 +2330,13 @@ public class CalendarProvider2 extends SQLiteContentProvider implements OnAccoun
 
     @Override
     public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
+        if (Flags.deferPostInitializeWork()
+                && uri.equals(CalendarAlarmManager.SCHEDULE_ALARM_REMOVE_URI)) {
+            if (mPostInitializeWorkRunning) {
+                mPendingScheduledAlarmsRemoval = true;
+                return 0;
+            }
+        }
         if (!applyingBatch()) {
             mCallingUid.set(Binder.getCallingUid());
         }
diff --git a/src/com/android/providers/calendar/CalendarReceiver.java b/src/com/android/providers/calendar/CalendarReceiver.java
index f59968b..1ff377f 100644
--- a/src/com/android/providers/calendar/CalendarReceiver.java
+++ b/src/com/android/providers/calendar/CalendarReceiver.java
@@ -85,7 +85,7 @@ public class CalendarReceiver extends BroadcastReceiver {
      * We don't expect this to be called more than once.  If it were, we would have to
      * worry about serializing the use of the service.
      */
-    private void removeScheduledAlarms(ContentResolver resolver) {
+    static void removeScheduledAlarms(ContentResolver resolver) {
         resolver.update(CalendarAlarmManager.SCHEDULE_ALARM_REMOVE_URI, null /* values */,
                 null /* where */, null /* selectionArgs */);
     }
```

