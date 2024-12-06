```diff
diff --git a/bcmdhd/wifi_hal/wifi_hal.cpp b/bcmdhd/wifi_hal/wifi_hal.cpp
index c057019..99aad5f 100644
--- a/bcmdhd/wifi_hal/wifi_hal.cpp
+++ b/bcmdhd/wifi_hal/wifi_hal.cpp
@@ -626,7 +626,9 @@ static void internal_cleaned_up_handler(wifi_handle handle)
     if (info->cmd_sock != 0) {
         ALOGI("cmd_sock non null. clean up");
         close(info->cleanup_socks[0]);
+        info->cleanup_socks[0] = -1;
         close(info->cleanup_socks[1]);
+        info->cleanup_socks[1] = -1;
         nl_socket_free(info->cmd_sock);
         nl_socket_free(info->event_sock);
         info->cmd_sock = NULL;
@@ -643,6 +645,7 @@ static void internal_cleaned_up_handler(wifi_handle handle)
     DestroyResponseLock();
     pthread_mutex_destroy(&info->cb_lock);
     free(info);
+    info = NULL;
 
     ALOGI("Internal cleanup completed");
 }
@@ -737,8 +740,6 @@ void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler cleaned_up_handler
     }
     pthread_mutex_unlock(&info->cb_lock);
 
-    info->clean_up = true;
-
     /* global func ptr be invalidated and will not call any command from legacy hal */
     if (cleaned_up_handler) {
         ALOGI("cleaned_up_handler to invalidates func ptr");
@@ -747,9 +748,12 @@ void wifi_cleanup(wifi_handle handle, wifi_cleaned_up_handler cleaned_up_handler
         ALOGI("cleaned up handler is null");
     }
 
-    if (TEMP_FAILURE_RETRY(write(info->cleanup_socks[0], "Exit", 4)) < 1) {
-        // As a fallback set the cleanup flag to TRUE
-        ALOGE("could not write to the cleanup socket");
+    info->clean_up = true;
+    if (info && info->cleanup_socks[0] != -1) {
+        if (TEMP_FAILURE_RETRY(write(info->cleanup_socks[0], "Exit", 4)) < 1) {
+	    // As a fallback set the cleanup flag to TRUE
+	    ALOGE("could not write to the cleanup socket");
+	}
     }
     ALOGE("wifi_clean_up done");
 }
```

