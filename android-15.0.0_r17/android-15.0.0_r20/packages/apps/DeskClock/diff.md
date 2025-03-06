```diff
diff --git a/README b/README
new file mode 100644
index 000000000..1372f2874
--- /dev/null
+++ b/README
@@ -0,0 +1,4 @@
+This app is not actively supported and the source is only available as a
+reference. This project will be removed from the source manifest sometime in the
+future.
+
diff --git a/src/com/android/deskclock/LabelDialogFragment.kt b/src/com/android/deskclock/LabelDialogFragment.kt
index 77f0b7b35..811e47ade 100644
--- a/src/com/android/deskclock/LabelDialogFragment.kt
+++ b/src/com/android/deskclock/LabelDialogFragment.kt
@@ -150,7 +150,7 @@ class LabelDialogFragment : DialogFragment() {
      * Handles completing the label edit from the IME keyboard.
      */
     private inner class ImeDoneListener : OnEditorActionListener {
-        override fun onEditorAction(v: TextView, actionId: Int, event: KeyEvent): Boolean {
+        override fun onEditorAction(v: TextView, actionId: Int, event: KeyEvent?): Boolean {
             if (actionId == EditorInfo.IME_ACTION_DONE) {
                 setLabel()
                 dismissAllowingStateLoss()
@@ -227,4 +227,4 @@ class LabelDialogFragment : DialogFragment() {
             fragment.show(tx, TAG)
         }
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/deskclock/data/TimerModel.kt b/src/com/android/deskclock/data/TimerModel.kt
index 2b97af719..639799326 100644
--- a/src/com/android/deskclock/data/TimerModel.kt
+++ b/src/com/android/deskclock/data/TimerModel.kt
@@ -744,6 +744,7 @@ internal class TimerModel(
         val notification: Notification = mNotificationBuilder.buildMissed(mContext,
                 mNotificationModel, missed)
         val notificationId = mNotificationModel.missedTimerNotificationId
+        mNotificationBuilder.buildChannel(mContext, mNotificationManager)
         mNotificationManager.notify(notificationId, notification)
     }
 
@@ -769,6 +770,7 @@ internal class TimerModel(
         // Otherwise build and post a foreground notification reflecting the latest expired timers.
         val notification: Notification = mNotificationBuilder.buildHeadsUp(mContext, expired)
         val notificationId = mNotificationModel.expiredTimerNotificationId
+        mNotificationBuilder.buildChannel(mContext, mNotificationManager)
         mService!!.startForeground(notificationId, notification)
     }
 
```

