```diff
diff --git a/common/vendor/attributes b/common/vendor/attributes
index 51e6703..38d5e8b 100644
--- a/common/vendor/attributes
+++ b/common/vendor/attributes
@@ -3,3 +3,6 @@ attribute pixel_battery_service_type;
 
 #touch attribute for touch-related properties.
 attribute touch_property_type;
+
+# bluetooth attribute for bluetooth-related properties.
+attribute pixel_bluetooth_service_type;
diff --git a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.te b/connectivity_thermal_power_manager/connectivity_thermal_power_manager.te
deleted file mode 100644
index 54b2e8c..0000000
--- a/connectivity_thermal_power_manager/connectivity_thermal_power_manager.te
+++ /dev/null
@@ -1,15 +0,0 @@
-# platform_apps cannot access PowerHAL, so we need to define our own domain.
-# Since we're defining and moving CTPM to its own domain, we need to assign
-# all of the previous permissions that we had as a platform_app
-
-type connectivity_thermal_power_manager, domain, coredomain, system_suspend_internal_server;
-
-app_domain(connectivity_thermal_power_manager)
-
-# register previous permissions we had as a platform_app
-allow connectivity_thermal_power_manager radio_service:service_manager find;
-allow connectivity_thermal_power_manager app_api_service:service_manager find;
-allow connectivity_thermal_power_manager system_api_service:service_manager find;
-
-# access power stats
-hal_client_domain(connectivity_thermal_power_manager, hal_power_stats);
diff --git a/connectivity_thermal_power_manager/seapp_contexts b/connectivity_thermal_power_manager/seapp_contexts
deleted file mode 100644
index 28b2e0c..0000000
--- a/connectivity_thermal_power_manager/seapp_contexts
+++ /dev/null
@@ -1 +0,0 @@
-user=_app seinfo=platform name=com.google.android.connectivitythermalpowermanager domain=connectivity_thermal_power_manager type=app_data_file levelFrom=all
diff --git a/googlebattery/google_gauge.te b/googlebattery/google_gauge.te
new file mode 100644
index 0000000..930e623
--- /dev/null
+++ b/googlebattery/google_gauge.te
@@ -0,0 +1,2 @@
+# To allow Google Battery HAL to read logbuffers
+allow hal_googlebattery logbuffer_device:chr_file r_file_perms;
diff --git a/h2omg/file.te b/h2omg/file.te
deleted file mode 100644
index 9aeacc7..0000000
--- a/h2omg/file.te
+++ /dev/null
@@ -1,3 +0,0 @@
-type sysfs_h2omg_drv, fs_type, sysfs_type;
-type sysfs_h2omg_fuse, fs_type, sysfs_type;
-type sysfs_h2omg_dev, fs_type, sysfs_type;
diff --git a/h2omg/file_contexts b/h2omg/file_contexts
deleted file mode 100644
index 5b0cd1e..0000000
--- a/h2omg/file_contexts
+++ /dev/null
@@ -1,2 +0,0 @@
-# h2omg init script
-/vendor/bin/hw/init.h2omg.sh           u:object_r:h2omg_vendor_exec:s0
diff --git a/h2omg/genfs_contexts b/h2omg/genfs_contexts
deleted file mode 100644
index 14ebe30..0000000
--- a/h2omg/genfs_contexts
+++ /dev/null
@@ -1,5 +0,0 @@
-genfscon sysfs /bus/i2c/drivers/h2omg   u:object_r:sysfs_h2omg_drv:s0
-genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0070 u:object_r:sysfs_h2omg_dev:s0
-genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0071 u:object_r:sysfs_h2omg_dev:s0
-genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0070/fuse/enable u:object_r:sysfs_h2omg_fuse:s0
-genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0071/fuse/enable u:object_r:sysfs_h2omg_fuse:s0
diff --git a/h2omg/h2omg_exec.te b/h2omg/h2omg_exec.te
deleted file mode 100644
index aa3d10e..0000000
--- a/h2omg/h2omg_exec.te
+++ /dev/null
@@ -1,9 +0,0 @@
-type h2omg_vendor, domain;
-type h2omg_vendor_exec, exec_type, vendor_file_type, file_type;
-
-init_daemon_domain(h2omg_vendor);
-
-allow h2omg_vendor sysfs_batteryinfo:dir search;
-allow h2omg_vendor sysfs_h2omg_drv:dir r_dir_perms;
-allow h2omg_vendor sysfs_h2omg_dev:dir r_dir_perms;
-allow h2omg_vendor sysfs_h2omg_fuse:file rw_file_perms;
diff --git a/h2omg/pixelstats_vendor.te b/h2omg/pixelstats_vendor.te
deleted file mode 100644
index be6183d..0000000
--- a/h2omg/pixelstats_vendor.te
+++ /dev/null
@@ -1,8 +0,0 @@
-# Access needed for pixelstatus
-allow pixelstats_vendor sysfs_h2omg_drv:dir search;
-allow pixelstats_vendor sysfs_h2omg_dev:dir search;
-allow pixelstats_vendor sysfs_h2omg_drv:dir r_dir_perms;
-allow pixelstats_vendor sysfs_h2omg_dev:dir r_dir_perms;
-allow pixelstats_vendor sysfs_h2omg_dev:file r_file_perms;
-allow pixelstats_vendor sysfs_h2omg_fuse:file r_file_perms;
-
diff --git a/pixelstats/file.te b/pixelstats/file.te
index 66a1552..2c9d4be 100644
--- a/pixelstats/file.te
+++ b/pixelstats/file.te
@@ -1,4 +1,3 @@
 type debugfs_mgm, debugfs_type, fs_type;
 type sysfs_pixel_stat, fs_type, sysfs_type;
-type proc_vendor_mm, fs_type, proc_type;
 type sysfs_vendor_mm, fs_type, sysfs_type;
diff --git a/pixelstats/genfs_contexts b/pixelstats/genfs_contexts
index 9bb4caa..c84b0a0 100644
--- a/pixelstats/genfs_contexts
+++ b/pixelstats/genfs_contexts
@@ -1,4 +1 @@
 genfscon debugfs /physical-memory-group-manager                          u:object_r:debugfs_mgm:s0
-genfscon sysfs /kernel/pixel_stat                                        u:object_r:sysfs_pixel_stat:s0
-genfscon proc  /vendor_mm                                                u:object_r:proc_vendor_mm:s0
-genfscon sysfs /kernel/vendor_mm                                         u:object_r:sysfs_vendor_mm:s0
diff --git a/pixelstats/pixelstats_vendor.te b/pixelstats/pixelstats_vendor.te
index 7e4c687..8979ff6 100644
--- a/pixelstats/pixelstats_vendor.te
+++ b/pixelstats/pixelstats_vendor.te
@@ -1,45 +1,3 @@
 # define pixelstats
 type pixelstats_vendor, domain;
 type pixelstats_vendor_exec, exec_type, vendor_file_type, file_type;
-
-# UeventListener
-r_dir_file(pixelstats_vendor, sysfs_batteryinfo)
-allow pixelstats_vendor sysfs_batteryinfo:file w_file_perms;
-allow pixelstats_vendor self:netlink_kobject_uevent_socket create_socket_perms_no_ioctl;
-
-allow pixelstats_vendor mnt_vendor_file:dir search;
-allow pixelstats_vendor sysfs_scsi_devices_0000:dir search;
-allow pixelstats_vendor sysfs_scsi_devices_0000:file rw_file_perms;
-allow pixelstats_vendor sysfs_fs_f2fs:dir search;
-allow pixelstats_vendor sysfs_fs_f2fs:file rw_file_perms;
-get_prop(pixelstats_vendor, boottime_public_prop)
-get_prop(pixelstats_vendor, smart_idle_maint_enabled_prop)
-
-allow pixelstats_vendor fwk_stats_service:service_manager find;
-binder_call(pixelstats_vendor, stats_service_server)
-
-# Pixel MM Metrics: (Atoms: PixelMmMetricsPerHour, PixelMmMetricsPerDay,
-#                    CmaStatus, CmaStatusExt, ZramBdStat, ZramMmStat)
-allow pixelstats_vendor kernel:dir search;
-allow pixelstats_vendor kernel:file r_file_perms;
-allow pixelstats_vendor proc_meminfo:file r_file_perms;
-allow pixelstats_vendor proc_pressure_cpu:file r_file_perms;
-allow pixelstats_vendor proc_pressure_io:file r_file_perms;
-allow pixelstats_vendor proc_pressure_mem:file r_file_perms;
-allow pixelstats_vendor proc_stat:file r_file_perms;
-allow pixelstats_vendor proc_vmstat:file r_file_perms;
-allow pixelstats_vendor sysfs_dma_heap:dir search;
-allow pixelstats_vendor sysfs_dma_heap:file r_file_perms;
-allow pixelstats_vendor sysfs_ion:dir search;
-allow pixelstats_vendor sysfs_ion:file r_file_perms;
-allow pixelstats_vendor sysfs_pixel_stat:dir r_dir_perms;
-allow pixelstats_vendor sysfs_pixel_stat:file r_file_perms;
-allow pixelstats_vendor sysfs_zram:dir search;
-allow pixelstats_vendor sysfs_zram:file r_file_perms;
-
-# Pixel MM Metrics 2024a2
-r_dir_file(pixelstats_vendor, proc_vendor_mm)
-r_dir_file(pixelstats_vendor, sysfs_vendor_mm)
-
-# Pixel Water Intrusion Stats (h2omg)
-#  see h2omg/pixelstats_vendor.te for additional access policies
```

