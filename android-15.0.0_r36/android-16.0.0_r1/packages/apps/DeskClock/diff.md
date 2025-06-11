```diff
diff --git a/OWNERS b/OWNERS
index 6c60e5a92..ba786267c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,4 +2,3 @@
 # Please update this list if you find better candidates.
 iankaz@google.com
 amithds@google.com
-rtenneti@google.com
diff --git a/src/com/android/deskclock/stopwatch/LapsAdapter.kt b/src/com/android/deskclock/stopwatch/LapsAdapter.kt
index b9264d499..85f436383 100644
--- a/src/com/android/deskclock/stopwatch/LapsAdapter.kt
+++ b/src/com/android/deskclock/stopwatch/LapsAdapter.kt
@@ -40,7 +40,7 @@ import kotlin.math.max
  * Displays a list of lap times in reverse order. That is, the newest lap is at the top, the oldest
  * lap is at the bottom.
  */
-internal class LapsAdapter(context: Context) : RecyclerView.Adapter<LapItemHolder?>() {
+internal class LapsAdapter(context: Context) : RecyclerView.Adapter<LapItemHolder>() {
     private val mInflater: LayoutInflater
     private val mContext: Context
 
@@ -357,4 +357,4 @@ internal class LapsAdapter(context: Context) : RecyclerView.Adapter<LapItemHolde
             return sTimeBuilder.toString()
         }
     }
-}
\ No newline at end of file
+}
```

