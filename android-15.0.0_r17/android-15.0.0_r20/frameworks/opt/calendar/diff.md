```diff
diff --git a/src/com/android/calendarcommon2/RecurrenceProcessor.java b/src/com/android/calendarcommon2/RecurrenceProcessor.java
index 24decce..802de7e 100644
--- a/src/com/android/calendarcommon2/RecurrenceProcessor.java
+++ b/src/com/android/calendarcommon2/RecurrenceProcessor.java
@@ -497,7 +497,6 @@ bysetpos:
             int[] byday, bydayNum, bymonthday;
             int j, lastDayThisMonth;
             int first; // Time.SUNDAY, etc
-            int k;
 
             lastDayThisMonth = generated.getActualMaximum(Time.MONTH_DAY);
 
@@ -861,7 +860,6 @@ bysetpos:
             }
 
             // go until the end of the range or we're done with this event
-            boolean eventEnded = false;
             int failsafe = 0; // Avoid infinite loops
             events: {
                 while (true) {
diff --git a/src/com/android/calendarcommon2/RecurrenceSet.java b/src/com/android/calendarcommon2/RecurrenceSet.java
index e42c0e9..9a153b6 100644
--- a/src/com/android/calendarcommon2/RecurrenceSet.java
+++ b/src/com/android/calendarcommon2/RecurrenceSet.java
@@ -35,7 +35,6 @@ public class RecurrenceSet {
     private final static String TAG = "RecurrenceSet";
 
     private final static String RULE_SEPARATOR = "\n";
-    private final static String FOLDING_SEPARATOR = "\n ";
 
     // TODO: make these final?
     public EventRecurrence[] rrules = null;
```

