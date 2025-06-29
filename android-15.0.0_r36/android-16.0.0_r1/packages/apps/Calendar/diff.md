```diff
diff --git a/OWNERS b/OWNERS
index 4a486a6d..1a3e7f09 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # This project has no significant updates recently.
 # Please update this list if you find better candidates.
-rtenneti@google.com
 delphij@google.com
 spickl@google.com
diff --git a/proguard.flags b/proguard.flags
index 3f08b97f..335c28e7 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1,5 +1,11 @@
--keep class com.android.calendar.OtherPreferences
--keep class com.android.calendar.GeneralPreferences
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.calendar.OtherPreferences {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.calendar.GeneralPreferences {
+  void <init>();
+}
 -keepclassmembers class com.android.calendar.AllInOneActivity {
   *** setControlsOffset(...);
 }
diff --git a/src/com/android/calendar/CalendarViewAdapter.kt b/src/com/android/calendar/CalendarViewAdapter.kt
index 44590b8f..3c0f9629 100644
--- a/src/com/android/calendar/CalendarViewAdapter.kt
+++ b/src/com/android/calendar/CalendarViewAdapter.kt
@@ -260,7 +260,7 @@ class CalendarViewAdapter(context: Context, viewType: Int, showDate: Boolean) :
             DateUtils.formatDateRange(mContext, mFormatter, mMilliTime, mMilliTime,
                     DateUtils.FORMAT_SHOW_WEEKDAY, mTimeZone).toString()
         }
-        return dayOfWeek.toUpperCase()
+        return dayOfWeek.uppercase()
     }
 
     // Builds strings with different formats:
@@ -367,4 +367,4 @@ class CalendarViewAdapter(context: Context, viewType: Int, showDate: Boolean) :
             refresh(context)
         }
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/calendar/DayView.kt b/src/com/android/calendar/DayView.kt
index d5f4f483..7f0cd7a0 100644
--- a/src/com/android/calendar/DayView.kt
+++ b/src/com/android/calendar/DayView.kt
@@ -469,11 +469,11 @@ class DayView(
             val index: Int = i - Calendar.SUNDAY
             // e.g. Tue for Tuesday
             mDayStrs!![index] = DateUtils.getDayOfWeekString(i, DateUtils.LENGTH_MEDIUM)
-                .toUpperCase()
+                .uppercase()
             mDayStrs!![index + 7] = mDayStrs!![index]
             // e.g. Tu for Tuesday
             mDayStrs2Letter!![index] = DateUtils.getDayOfWeekString(i, DateUtils.LENGTH_SHORT)
-                .toUpperCase()
+                .uppercase()
 
             // If we don't have 2-letter day strings, fall back to 1-letter.
             if (mDayStrs2Letter!![index]!!.equals(mDayStrs!![index])) {
@@ -494,8 +494,8 @@ class DayView(
         p.setTextSize(HOURS_TEXT_SIZE)
         p.setTypeface(null)
         handleOnResume()
-        mAmString = DateUtils.getAMPMString(Calendar.AM).toUpperCase()
-        mPmString = DateUtils.getAMPMString(Calendar.PM).toUpperCase()
+        mAmString = DateUtils.getAMPMString(Calendar.AM).uppercase()
+        mPmString = DateUtils.getAMPMString(Calendar.PM).uppercase()
         val ampm = arrayOf(mAmString, mPmString)
         p.setTextSize(AMPM_TEXT_SIZE)
         mHoursWidth = Math.max(
diff --git a/src/com/android/calendar/EventInfoFragment.kt b/src/com/android/calendar/EventInfoFragment.kt
index 139da7bb..cc2a0a5a 100644
--- a/src/com/android/calendar/EventInfoFragment.kt
+++ b/src/com/android/calendar/EventInfoFragment.kt
@@ -377,7 +377,7 @@ class EventInfoFragment : DialogFragment, OnCheckedChangeListener, CalendarContr
 
     // Implements OnCheckedChangeListener
     @Override
-    override fun onCheckedChanged(group: RadioGroup?, checkedId: Int) {
+    override fun onCheckedChanged(group: RadioGroup, checkedId: Int) {
     }
 
     fun onNothingSelected(parent: AdapterView<*>?) {}
diff --git a/src/com/android/calendar/Utils.kt b/src/com/android/calendar/Utils.kt
index 52af887c..502a0353 100644
--- a/src/com/android/calendar/Utils.kt
+++ b/src/com/android/calendar/Utils.kt
@@ -1310,7 +1310,7 @@ object Utils {
             mTZUtils?.formatDateRange(context, millis, millis, flags)
                 .toString()
         }
-        dayViewText = dayViewText.toUpperCase()
+        dayViewText = dayViewText.uppercase()
         return dayViewText
     }
 
@@ -1574,4 +1574,4 @@ object Utils {
         var color = 0 // Calendar color or black for conflicts =
         var day = 0 // quick reference to the day this segment is on =
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/calendar/month/MonthByWeekFragment.kt b/src/com/android/calendar/month/MonthByWeekFragment.kt
index b6882b74..ea50ecde 100644
--- a/src/com/android/calendar/month/MonthByWeekFragment.kt
+++ b/src/com/android/calendar/month/MonthByWeekFragment.kt
@@ -286,7 +286,7 @@ class MonthByWeekFragment @JvmOverloads constructor(
             mDayLabels[i - Calendar.SUNDAY] = DateUtils.getDayOfWeekString(
                     i,
                     DateUtils.LENGTH_MEDIUM
-            ).toUpperCase()
+            ).uppercase()
         }
     }
 
@@ -494,4 +494,4 @@ class MonthByWeekFragment @JvmOverloads constructor(
         // changing
         private const val LOADER_THROTTLE_DELAY = 500
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/calendar/month/SimpleDayPickerFragment.kt b/src/com/android/calendar/month/SimpleDayPickerFragment.kt
index c0bce5d3..6147561f 100644
--- a/src/com/android/calendar/month/SimpleDayPickerFragment.kt
+++ b/src/com/android/calendar/month/SimpleDayPickerFragment.kt
@@ -224,7 +224,7 @@ open class SimpleDayPickerFragment(initialTime: Long) : ListFragment(), OnScroll
         mDayLabels = arrayOfNulls(7)
         for (i in Calendar.SUNDAY..Calendar.SATURDAY) {
             mDayLabels[i - Calendar.SUNDAY] = DateUtils.getDayOfWeekString(i,
-                    DateUtils.LENGTH_SHORTEST).toUpperCase()
+                    DateUtils.LENGTH_SHORTEST).uppercase()
         }
     }
 
@@ -613,4 +613,4 @@ open class SimpleDayPickerFragment(initialTime: Long) : ListFragment(), OnScroll
         goTo(initialTime, false, true, true)
         mHandler = Handler()
     }
-}
\ No newline at end of file
+}
diff --git a/src/com/android/calendar/widget/CalendarAppWidgetProvider.kt b/src/com/android/calendar/widget/CalendarAppWidgetProvider.kt
index 1bb66b92..e8d51362 100644
--- a/src/com/android/calendar/widget/CalendarAppWidgetProvider.kt
+++ b/src/com/android/calendar/widget/CalendarAppWidgetProvider.kt
@@ -146,7 +146,8 @@ class CalendarAppWidgetProvider : AppWidgetProvider() {
             launchCalendarIntent
                 .setData(Uri.parse("content://com.android.calendar/time/$millis"))
             val launchCalendarPendingIntent: PendingIntent = PendingIntent.getActivity(
-                context, 0 /* no requestCode */, launchCalendarIntent, 0 /* no flags */
+                context, 0 /* no requestCode */, launchCalendarIntent,
+                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
             )
             views.setOnClickPendingIntent(R.id.header, launchCalendarPendingIntent)
 
@@ -187,7 +188,7 @@ class CalendarAppWidgetProvider : AppWidgetProvider() {
             intent.setDataAndType(CalendarContract.CONTENT_URI, Utils.APPWIDGET_DATA_TYPE)
             return PendingIntent.getBroadcast(
                 context, 0 /* no requestCode */, intent,
-                PendingIntent.FLAG_IMMUTABLE
+                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
             )
         }
 
@@ -205,7 +206,7 @@ class CalendarAppWidgetProvider : AppWidgetProvider() {
             launchIntent.setClass(context as Context, AllInOneActivity::class.java)
             return PendingIntent.getActivity(
                 context, 0 /* no requestCode */, launchIntent,
-                PendingIntent.FLAG_UPDATE_CURRENT
+                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
             )
         }
 
@@ -248,4 +249,4 @@ class CalendarAppWidgetProvider : AppWidgetProvider() {
             return fillInIntent
         }
     }
-}
\ No newline at end of file
+}
```

