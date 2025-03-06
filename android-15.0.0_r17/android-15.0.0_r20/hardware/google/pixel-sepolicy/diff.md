```diff
diff --git a/hardware_info_app/file.te b/hardware_info_app/file.te
index 651f612..c3c4f9d 100644
--- a/hardware_info_app/file.te
+++ b/hardware_info_app/file.te
@@ -11,3 +11,6 @@ type sysfs_display, sysfs_type, fs_type;
 # SoC
 type sysfs_soc, sysfs_type, fs_type;
 type sysfs_chip_id, sysfs_type, fs_type;
+
+# Application Processor
+type sysfs_ap, sysfs_type, fs_type;
```

