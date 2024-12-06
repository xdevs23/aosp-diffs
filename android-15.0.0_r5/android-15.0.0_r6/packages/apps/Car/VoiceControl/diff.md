```diff
diff --git a/src/com/android/car/voicecontrol/LogUtils.java b/src/com/android/car/voicecontrol/LogUtils.java
index c61e70a..e731ea6 100644
--- a/src/com/android/car/voicecontrol/LogUtils.java
+++ b/src/com/android/car/voicecontrol/LogUtils.java
@@ -96,31 +96,33 @@ public class LogUtils {
         sb.append("]");
     }
 
-    private static final Map<Long, String> PLAYBACK_STATES = new HashMap<Long, String>() {
-        {
-            put(PlaybackStateCompat.ACTION_STOP, "STOP");
-            put(PlaybackStateCompat.ACTION_PAUSE, "ACTION_PAUSE");
-            put(PlaybackStateCompat.ACTION_PLAY, "ACTION_PLAY");
-            put(PlaybackStateCompat.ACTION_REWIND, "ACTION_REWIND");
-            put(PlaybackStateCompat.ACTION_SKIP_TO_PREVIOUS, "ACTION_SKIP_TO_PREVIOUS");
-            put(PlaybackStateCompat.ACTION_SKIP_TO_NEXT, "ACTION_SKIP_TO_NEXT");
-            put(PlaybackStateCompat.ACTION_FAST_FORWARD, "ACTION_FAST_FORWARD");
-            put(PlaybackStateCompat.ACTION_SET_RATING, "ACTION_SET_RATING");
-            put(PlaybackStateCompat.ACTION_SEEK_TO, "ACTION_SEEK_TO");
-            put(PlaybackStateCompat.ACTION_PLAY_PAUSE, "ACTION_PLAY_PAUSE");
-            put(PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID, "ACTION_PLAY_FROM_MEDIA_ID");
-            put(PlaybackStateCompat.ACTION_PLAY_FROM_SEARCH, "ACTION_PLAY_FROM_SEARCH");
-            put(PlaybackStateCompat.ACTION_SKIP_TO_QUEUE_ITEM, "ACTION_SKIP_TO_QUEUE_ITEM");
-            put(PlaybackStateCompat.ACTION_PLAY_FROM_URI, "ACTION_PLAY_FROM_URI");
-            put(PlaybackStateCompat.ACTION_PREPARE, "ACTION_PREPARE");
-            put(PlaybackStateCompat.ACTION_PREPARE_FROM_MEDIA_ID, "ACTION_PREPARE_FROM_MEDIA_ID");
-            put(PlaybackStateCompat.ACTION_PREPARE_FROM_SEARCH, "ACTION_PREPARE_FROM_SEARCH");
-            put(PlaybackStateCompat.ACTION_PREPARE_FROM_URI, "ACTION_PREPARE_FROM_URI");
-            put(PlaybackStateCompat.ACTION_SET_REPEAT_MODE, "ACTION_SET_REPEAT_MODE");
-            put(PlaybackStateCompat.ACTION_SET_CAPTIONING_ENABLED, "ACTION_SET_CAPTIONING_ENABLED");
-            put(PlaybackStateCompat.ACTION_SET_SHUFFLE_MODE, "ACTION_SET_SHUFFLE_MODE");
-        }
-    };
+    private static final Map<Long, String> PLAYBACK_STATES = Map.ofEntries(
+            Map.entry(PlaybackStateCompat.ACTION_STOP, "STOP"),
+            Map.entry(PlaybackStateCompat.ACTION_PAUSE, "ACTION_PAUSE"),
+            Map.entry(PlaybackStateCompat.ACTION_PLAY, "ACTION_PLAY"),
+            Map.entry(PlaybackStateCompat.ACTION_REWIND, "ACTION_REWIND"),
+            Map.entry(PlaybackStateCompat.ACTION_SKIP_TO_PREVIOUS, "ACTION_SKIP_TO_PREVIOUS"),
+            Map.entry(PlaybackStateCompat.ACTION_SKIP_TO_NEXT, "ACTION_SKIP_TO_NEXT"),
+            Map.entry(PlaybackStateCompat.ACTION_FAST_FORWARD, "ACTION_FAST_FORWARD"),
+            Map.entry(PlaybackStateCompat.ACTION_SET_RATING, "ACTION_SET_RATING"),
+            Map.entry(PlaybackStateCompat.ACTION_SEEK_TO, "ACTION_SEEK_TO"),
+            Map.entry(PlaybackStateCompat.ACTION_PLAY_PAUSE, "ACTION_PLAY_PAUSE"),
+            Map.entry(PlaybackStateCompat.ACTION_PLAY_FROM_MEDIA_ID, "ACTION_PLAY_FROM_MEDIA_ID"),
+            Map.entry(PlaybackStateCompat.ACTION_PLAY_FROM_SEARCH, "ACTION_PLAY_FROM_SEARCH"),
+            Map.entry(PlaybackStateCompat.ACTION_SKIP_TO_QUEUE_ITEM, "ACTION_SKIP_TO_QUEUE_ITEM"),
+            Map.entry(PlaybackStateCompat.ACTION_PLAY_FROM_URI, "ACTION_PLAY_FROM_URI"),
+            Map.entry(PlaybackStateCompat.ACTION_PREPARE, "ACTION_PREPARE"),
+            Map.entry(
+                    PlaybackStateCompat.ACTION_PREPARE_FROM_MEDIA_ID,
+                    "ACTION_PREPARE_FROM_MEDIA_ID"),
+            Map.entry(PlaybackStateCompat.ACTION_PREPARE_FROM_SEARCH, "ACTION_PREPARE_FROM_SEARCH"),
+            Map.entry(PlaybackStateCompat.ACTION_PREPARE_FROM_URI, "ACTION_PREPARE_FROM_URI"),
+            Map.entry(PlaybackStateCompat.ACTION_SET_REPEAT_MODE, "ACTION_SET_REPEAT_MODE"),
+            Map.entry(
+                    PlaybackStateCompat.ACTION_SET_CAPTIONING_ENABLED,
+                    "ACTION_SET_CAPTIONING_ENABLED"),
+            Map.entry(PlaybackStateCompat.ACTION_SET_SHUFFLE_MODE, "ACTION_SET_SHUFFLE_MODE")
+    );
 
     /**
      * Converts a {@link PlaybackStateCompat} action to readable string.
```

