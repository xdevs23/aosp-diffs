```diff
diff --git a/src/com/android/se/Terminal.java b/src/com/android/se/Terminal.java
index e9b0e6c..8ef86b9 100644
--- a/src/com/android/se/Terminal.java
+++ b/src/com/android/se/Terminal.java
@@ -80,6 +80,7 @@ public class Terminal {
     private static final boolean DEBUG = Build.isDebuggable();
     private static final int GET_SERVICE_DELAY_MILLIS = 4 * 1000;
     private static final int EVENT_GET_HAL = 1;
+    private static final int EVENT_NOTIFY_STATE_CHANGE = 2;
 
     private final int mMaxGetHalRetryCount = 5;
     private int mGetHalRetryCount = 0;
@@ -183,7 +184,7 @@ public class Terminal {
                         mName);
             }
 
-            sendStateChangedBroadcast(state);
+            mHandler.sendMessage(mHandler.obtainMessage(EVENT_NOTIFY_STATE_CHANGE, state));
         }
     }
 
@@ -221,6 +222,7 @@ public class Terminal {
                     mAccessControlEnforcer.reset();
                 }
             }
+            mGetHalRetryCount = 0;
             mHandler.sendMessageDelayed(mHandler.obtainMessage(EVENT_GET_HAL, 0),
                     GET_SERVICE_DELAY_MILLIS);
         }
@@ -250,6 +252,9 @@ public class Terminal {
                         }
                     }
                     break;
+                case EVENT_NOTIFY_STATE_CHANGE:
+                    sendStateChangedBroadcast((boolean) message.obj);
+                    break;
                 default:
                     break;
             }
```

