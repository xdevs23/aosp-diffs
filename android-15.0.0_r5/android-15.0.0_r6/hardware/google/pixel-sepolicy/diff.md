```diff
diff --git a/common/vendor/attributes b/common/vendor/attributes
index 25b59ac..51e6703 100644
--- a/common/vendor/attributes
+++ b/common/vendor/attributes
@@ -1,2 +1,5 @@
 attribute pixel_battery_domain;
 attribute pixel_battery_service_type;
+
+#touch attribute for touch-related properties.
+attribute touch_property_type;
diff --git a/hardware_info_app/file.te b/hardware_info_app/file.te
index f891722..651f612 100644
--- a/hardware_info_app/file.te
+++ b/hardware_info_app/file.te
@@ -1,5 +1,6 @@
 # Storage Health HAL
 type sysfs_scsi_devices_0000, sysfs_type, fs_type;
+type vendor_sysfs_mmc_devices, sysfs_type, fs_type;
 
 # PixelStats_vendor
 type sysfs_pixelstats, fs_type, sysfs_type;
diff --git a/pixelstats/file.te b/pixelstats/file.te
index b8de8a5..66a1552 100644
--- a/pixelstats/file.te
+++ b/pixelstats/file.te
@@ -1,3 +1,4 @@
 type debugfs_mgm, debugfs_type, fs_type;
 type sysfs_pixel_stat, fs_type, sysfs_type;
 type proc_vendor_mm, fs_type, proc_type;
+type sysfs_vendor_mm, fs_type, sysfs_type;
diff --git a/pixelstats/genfs_contexts b/pixelstats/genfs_contexts
index 5146b85..9bb4caa 100644
--- a/pixelstats/genfs_contexts
+++ b/pixelstats/genfs_contexts
@@ -1,3 +1,4 @@
 genfscon debugfs /physical-memory-group-manager                          u:object_r:debugfs_mgm:s0
 genfscon sysfs /kernel/pixel_stat                                        u:object_r:sysfs_pixel_stat:s0
 genfscon proc  /vendor_mm                                                u:object_r:proc_vendor_mm:s0
+genfscon sysfs /kernel/vendor_mm                                         u:object_r:sysfs_vendor_mm:s0
diff --git a/pixelstats/pixelstats_vendor.te b/pixelstats/pixelstats_vendor.te
index 335f28f..5242c79 100644
--- a/pixelstats/pixelstats_vendor.te
+++ b/pixelstats/pixelstats_vendor.te
@@ -43,4 +43,4 @@ allow pixelstats_vendor sysfs_zram:file r_file_perms;
 
 # Pixel MM Metrics 2024a2
 r_dir_file(pixelstats_vendor, proc_vendor_mm)
-
+r_dir_file(pixelstats_vendor, sysfs_vendor_mm)
```

