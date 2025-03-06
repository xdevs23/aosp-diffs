```diff
diff --git a/shared/config/wireless b/shared/config/wireless
index 7152192..eefefb8 100644
--- a/shared/config/wireless
+++ b/shared/config/wireless
@@ -24,6 +24,7 @@ config wifi-device 'radio1'
 config wifi-iface 'default_radio1'
 	option device 'radio1'
 	option mode 'ap'
-	option encryption 'none'
+	option encryption 'psk2'
+	option key 'password'
 	option network 'wifi1'
 	option ssid 'VirtWifi2'
```

