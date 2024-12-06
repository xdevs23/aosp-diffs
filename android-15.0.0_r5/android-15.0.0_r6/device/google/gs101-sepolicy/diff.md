```diff
diff --git a/display/gs101/genfs_contexts b/display/gs101/genfs_contexts
index 99badab..6144af6 100644
--- a/display/gs101/genfs_contexts
+++ b/display/gs101/genfs_contexts
@@ -2,12 +2,14 @@ genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/backlight
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/panel_name                u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/serial_number             u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/refresh_rate              u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/power_state               u:object_r:sysfs_display:s0
 genfscon sysfs /firmware/devicetree/base/drmdsim@0x1C2C0000/panel@0/compatible                 u:object_r:sysfs_display:s0
 
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/backlight                 u:object_r:sysfs_leds:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/panel_name                u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/serial_number             u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/refresh_rate              u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/power_state               u:object_r:sysfs_display:s0
 genfscon sysfs /firmware/devicetree/base/drmdsim@0x1C2D0000/panel@0/compatible                 u:object_r:sysfs_display:s0
 
 genfscon sysfs /module/drm/parameters/vblankoffdelay                                           u:object_r:sysfs_display:s0
diff --git a/tracking_denials/bug_map b/tracking_denials/bug_map
index 737d604..0f17944 100644
--- a/tracking_denials/bug_map
+++ b/tracking_denials/bug_map
@@ -1,6 +1,9 @@
 
+battery_mitigation sysfs file b/364446534
 chre vendor_data_file dir b/301948771
 dump_display sysfs file b/340722772
+dump_modem sscoredump_vendor_data_coredump_file dir b/366115873
+dump_modem sscoredump_vendor_data_logcat_file dir b/366115873
 hal_power_default hal_power_default capability b/240632824
 hal_sensors_default sysfs file b/340723303
 hal_vibrator_default default_android_service service_manager b/317316478
@@ -12,7 +15,11 @@ kernel kernel capability b/340723030
 kernel tmpfs chr_file b/315907959
 rfsd vendor_cbd_prop file b/317734418
 shell sysfs_net file b/329380904
+ssr_detector_app default_prop file b/350831964
 surfaceflinger selinuxfs file b/313804340
+system_server vendor_default_prop file b/366115457
+system_server vendor_default_prop file b/366116435
+system_server vendor_default_prop file b/366116587
 untrusted_app nativetest_data_file dir b/305600845
 untrusted_app shell_test_data_file dir b/305600845
 untrusted_app system_data_root_file dir b/305600845
@@ -21,3 +28,5 @@ vendor_init debugfs_trace_marker file b/340723222
 vendor_init default_prop file b/315104713
 vendor_init default_prop file b/316817111
 vendor_init default_prop property_service b/315104713
+vendor_init default_prop property_service b/366115458
+vendor_init default_prop property_service b/366116214
diff --git a/whitechapel/vendor/google/device.te b/whitechapel/vendor/google/device.te
index 4662a07..1e1f25d 100644
--- a/whitechapel/vendor/google/device.te
+++ b/whitechapel/vendor/google/device.te
@@ -1,8 +1,5 @@
 # Block Devices
-type efs_block_device, dev_type;
 type modem_block_device, dev_type;
-type modem_userdata_block_device, dev_type;
-type persist_block_device, dev_type;
 type mfg_data_block_device, dev_type;
 
 # Exynos devices
@@ -39,3 +36,4 @@ type st33spi_device, dev_type;
 
 # GPS
 type vendor_gnss_device, dev_type;
+
diff --git a/whitechapel/vendor/google/dump_power.te b/whitechapel/vendor/google/dump_power.te
new file mode 100644
index 0000000..d745b20
--- /dev/null
+++ b/whitechapel/vendor/google/dump_power.te
@@ -0,0 +1,15 @@
+# Allow dumpstate to execute dump_power
+pixel_bugreport(dump_power);
+
+allow dump_power sysfs_acpm_stats:dir r_dir_perms;
+allow dump_power sysfs_acpm_stats:file r_file_perms;
+allow dump_power sysfs_cpu:file r_file_perms;
+allow dump_power sysfs_wlc:file r_file_perms;
+allow dump_power sysfs_wlc:dir search;
+allow dump_power sysfs_batteryinfo:dir r_dir_perms;
+allow dump_power sysfs_batteryinfo:file r_file_perms;
+allow dump_power logbuffer_device:chr_file r_file_perms;
+allow dump_power mitigation_vendor_data_file:dir r_dir_perms;
+allow dump_power mitigation_vendor_data_file:file r_file_perms;
+allow dump_power sysfs_bcl:dir r_dir_perms;
+allow dump_power sysfs_bcl:file r_file_perms;
diff --git a/whitechapel/vendor/google/file.te b/whitechapel/vendor/google/file.te
index 8c98555..db4d057 100644
--- a/whitechapel/vendor/google/file.te
+++ b/whitechapel/vendor/google/file.te
@@ -114,10 +114,6 @@ type sysfs_chargelevel, sysfs_type, fs_type;
 
 # ODPM
 type powerstats_vendor_data_file, file_type, data_file_type;
-type sysfs_odpm, sysfs_type, fs_type;
-
-# bcl
-type sysfs_bcl, sysfs_type, fs_type;
 
 # Chosen
 type sysfs_chosen, sysfs_type, fs_type;
@@ -165,3 +161,4 @@ type sysfs_bootctl, sysfs_type, fs_type;
 
 # WLC
 type sysfs_wlc, sysfs_type, fs_type;
+
diff --git a/whitechapel/vendor/google/file_contexts b/whitechapel/vendor/google/file_contexts
index 69e0d3a..e6dc12e 100644
--- a/whitechapel/vendor/google/file_contexts
+++ b/whitechapel/vendor/google/file_contexts
@@ -16,8 +16,7 @@
 /(vendor|system/vendor)/lib(64)?/libgpudataproducer\.so                                         u:object_r:same_process_hal_file:s0
 
 /vendor/bin/dumpsys                                                                             u:object_r:vendor_dumpsys:s0
-/vendor/bin/dump/dump_gs101.sh                                                                  u:object_r:dump_gs101_exec:s0
-
+/vendor/bin/dump/dump_power                                                                     u:object_r:dump_power_exec:s0
 #
 # HALs
 #
@@ -373,5 +372,6 @@
 
 # Statsd service to support EdgeTPU metrics logging service.
 /vendor/lib64/android\.frameworks\.stats-V1-ndk\.so u:object_r:same_process_hal_file:s0
+/vendor/lib64/android\.frameworks\.stats-V2-ndk\.so u:object_r:same_process_hal_file:s0
 /vendor/lib64/vendor-pixelatoms-cpp\.so u:object_r:same_process_hal_file:s0
 /vendor/lib64/libprotobuf-cpp-lite-(\d+\.){2,3}so u:object_r:same_process_hal_file:s0
diff --git a/whitechapel/vendor/google/genfs_contexts b/whitechapel/vendor/google/genfs_contexts
index 7261590..2a0642d 100644
--- a/whitechapel/vendor/google/genfs_contexts
+++ b/whitechapel/vendor/google/genfs_contexts
@@ -152,6 +152,8 @@ genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/panel_need_
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/panel_need_handle_idle_exit    u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/time_in_state                  u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/time_in_state                  u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/power_mode                     u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/power_mode                     u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/hs_clock                                          u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/hs_clock                                          u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c300000.drmdecon/counters                                         u:object_r:sysfs_display:s0
@@ -185,14 +187,38 @@ genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-me
 genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device0/enabled_rails        u:object_r:sysfs_odpm:s0
 genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/wakeup                           u:object_r:sysfs_wakeup:s0
 
-# bcl sysfs files
-genfscon sysfs /devices/virtual/pmic/mitigation                                        u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/tpu_heavy_clk_ratio        u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/gpu_heavy_clk_ratio        u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/cpu2_heavy_clk_ratio       u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/cpu2_light_clk_ratio       u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/tpu_light_clk_ratio        u:object_r:sysfs_bcl:s0
-genfscon sysfs /devices/virtual/pmic/mitigation/clock_ratio/gpu_light_clk_ratio        u:object_r:sysfs_bcl:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power0_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power1_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power2_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power3_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power4_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power5_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power6_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_power7_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power0_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power1_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power2_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power3_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power4_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power5_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power6_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_power7_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current0_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current1_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current2_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current3_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current4_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current5_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current6_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17500000/i2c-20/20-001f/s2mpg10-meter/s2mpg10-odpm/iio:device0/in_current7_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current0_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current1_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current2_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current3_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current4_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current5_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current6_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@17510000/i2c-21/21-002f/s2mpg11-meter/s2mpg11-odpm/iio:device1/in_current7_scale  u:object_r:sysfs_odpm:s0
 
 # Chosen
 genfscon sysfs /firmware/devicetree/base/chosen                                u:object_r:sysfs_chosen:s0
@@ -235,6 +261,7 @@ genfscon sysfs /devices/platform/1c500000.mali/dma_buf_gpu_mem
 genfscon sysfs /devices/platform/1c500000.mali/total_gpu_mem                                            u:object_r:sysfs_gpu:s0
 genfscon sysfs /devices/platform/1c500000.mali/kprcs                                                    u:object_r:sysfs_gpu:s0
 genfscon sysfs /devices/platform/1c500000.mali/power_policy                                             u:object_r:sysfs_gpu:s0
+genfscon sysfs /devices/platform/1c500000.mali/cur_freq                                                 u:object_r:sysfs_gpu:s0
 
 # nvmem (Non Volatile Memory layer)
 genfscon sysfs /devices/platform/10970000.hsi2c/i2c-8/8-0050/8-00500/nvmem                              u:object_r:sysfs_memory:s0
diff --git a/whitechapel/vendor/google/hal_camera_default.te b/whitechapel/vendor/google/hal_camera_default.te
index b488860..5697afe 100644
--- a/whitechapel/vendor/google/hal_camera_default.te
+++ b/whitechapel/vendor/google/hal_camera_default.te
@@ -91,6 +91,7 @@ allow hal_camera_default sysfs_devfreq_cur:file r_file_perms;
 # Allow camera HAL to read backlight of display
 allow hal_camera_default sysfs_leds:dir r_dir_perms;
 allow hal_camera_default sysfs_leds:file r_file_perms;
+allow hal_camera_default sysfs_display:file r_file_perms;
 
 # Allow camera HAL to query interrupts and set interrupt affinity
 allow hal_camera_default proc_irq:dir r_dir_perms;
diff --git a/whitechapel/vendor/google/hal_radioext_default.te b/whitechapel/vendor/google/hal_radioext_default.te
index eef71cf..0f561ac 100644
--- a/whitechapel/vendor/google/hal_radioext_default.te
+++ b/whitechapel/vendor/google/hal_radioext_default.te
@@ -4,6 +4,7 @@ init_daemon_domain(hal_radioext_default)
 
 hwbinder_use(hal_radioext_default)
 get_prop(hal_radioext_default, hwservicemanager_prop)
+set_prop(hal_radioext_default, vendor_gril_prop)
 add_hwservice(hal_radioext_default, hal_radioext_hwservice)
 
 binder_call(hal_radioext_default, grilservice_app)
diff --git a/whitechapel/vendor/google/modem_svc_sit.te b/whitechapel/vendor/google/modem_svc_sit.te
index 0eb7498..8e4ac3d 100644
--- a/whitechapel/vendor/google/modem_svc_sit.te
+++ b/whitechapel/vendor/google/modem_svc_sit.te
@@ -41,4 +41,10 @@ perfetto_producer(modem_svc_sit)
 # Allow modem_svc_sit to access modem image file/dir
 allow modem_svc_sit modem_img_file:dir r_dir_perms;
 allow modem_svc_sit modem_img_file:file r_file_perms;
-allow modem_svc_sit modem_img_file:lnk_file r_file_perms;
\ No newline at end of file
+allow modem_svc_sit modem_img_file:lnk_file r_file_perms;
+
+# Allow modem_svc_sit to access socket for UMI
+userdebug_or_eng(`
+  allow modem_svc_sit radio_vendor_data_file:sock_file { create unlink };
+')
+
diff --git a/whitechapel/vendor/google/property.te b/whitechapel/vendor/google/property.te
index 98da3e3..bbdce97 100644
--- a/whitechapel/vendor/google/property.te
+++ b/whitechapel/vendor/google/property.te
@@ -2,6 +2,7 @@
 vendor_internal_prop(vendor_prop)
 vendor_internal_prop(vendor_rcs_prop)
 vendor_internal_prop(vendor_rild_prop)
+vendor_internal_prop(vendor_gril_prop)
 vendor_internal_prop(sensors_prop)
 vendor_internal_prop(vendor_ssrdump_prop)
 vendor_internal_prop(vendor_usb_config_prop)
@@ -41,7 +42,7 @@ vendor_internal_prop(vendor_touchpanel_prop)
 vendor_internal_prop(vendor_tcpdump_log_prop)
 
 # Fingerprint
-vendor_internal_prop(vendor_fingerprint_prop)
+vendor_restricted_prop(vendor_fingerprint_prop)
 
 # Dynamic sensor
 vendor_internal_prop(vendor_dynamic_sensor_prop)
diff --git a/whitechapel/vendor/google/property_contexts b/whitechapel/vendor/google/property_contexts
index c9187a3..ba41d6a 100644
--- a/whitechapel/vendor/google/property_contexts
+++ b/whitechapel/vendor/google/property_contexts
@@ -8,6 +8,9 @@ vendor.ril.                      u:object_r:vendor_rild_prop:s0
 vendor.radio.                    u:object_r:vendor_rild_prop:s0
 ro.vendor.build.svn              u:object_r:vendor_rild_prop:s0
 
+# for GRIL
+vendor.gril.                               u:object_r:vendor_gril_prop:s0
+
 # Ramdump
 persist.vendor.sys.crash_rcu    u:object_r:vendor_ramdump_prop:s0
 
```

