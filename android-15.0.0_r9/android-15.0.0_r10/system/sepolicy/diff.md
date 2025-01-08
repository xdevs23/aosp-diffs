```diff
diff --git a/private/compat/202404/202404.cil b/private/compat/202404/202404.cil
index 5ba9b3f07..85eb601c6 100644
--- a/private/compat/202404/202404.cil
+++ b/private/compat/202404/202404.cil
@@ -2724,7 +2724,7 @@
 (typeattributeset virtual_camera_service_202404 (virtual_camera_service))
 (typeattributeset virtual_device_native_service_202404 (virtual_device_native_service))
 (typeattributeset virtual_device_service_202404 (virtual_device_service))
-(typeattributeset virtual_face_hal_prop_202404 (virtual_face_hal_prop))
+(typeattributeset virtual_face_hal_prop_202404 (virtual_face_hal_prop virtual_face_prop))
 (typeattributeset virtual_fingerprint_hal_prop_202404 (virtual_fingerprint_hal_prop virtual_fingerprint_prop))
 (typeattributeset virtual_touchpad_202404 (virtual_touchpad))
 (typeattributeset virtual_touchpad_exec_202404 (virtual_touchpad_exec))
diff --git a/private/compat/33.0/33.0.ignore.cil b/private/compat/33.0/33.0.ignore.cil
index a43f0fd46..a9a37a43f 100644
--- a/private/compat/33.0/33.0.ignore.cil
+++ b/private/compat/33.0/33.0.ignore.cil
@@ -80,6 +80,7 @@
     ublk_control_device
     usb_uvc_enabled_prop
     virtual_face_hal_prop
+    virtual_face_prop
     virtual_fingerprint_hal_prop
     virtual_fingerprint_prop
     hal_gatekeeper_service
diff --git a/private/property.te b/private/property.te
index 8cc91e423..64ddc3538 100644
--- a/private/property.te
+++ b/private/property.te
@@ -84,6 +84,7 @@ system_restricted_prop(page_size_prop)
 until_board_api(202504, `
     system_public_prop(bluetooth_finder_prop)
     system_public_prop(virtual_fingerprint_prop)
+    system_public_prop(virtual_face_prop)
 ')
 
 # These types will be public starting at board api 202504
diff --git a/private/property_contexts b/private/property_contexts
index 13dff313d..4f1d02d2c 100644
--- a/private/property_contexts
+++ b/private/property_contexts
@@ -1626,28 +1626,28 @@ composd.vm.art.memory_mib.config u:object_r:composd_vm_art_prop:s0 exact uint
 composd.vm.vendor.memory_mib.config u:object_r:composd_vm_vendor_prop:s0 exact int
 
 # properties for the virtual Face HAL
-persist.vendor.face.virtual.type u:object_r:virtual_face_hal_prop:s0 exact string
-persist.vendor.face.virtual.strength u:object_r:virtual_face_hal_prop:s0 exact string
-persist.vendor.face.virtual.enrollments u:object_r:virtual_face_hal_prop:s0 exact string
-persist.vendor.face.virtual.features u:object_r:virtual_face_hal_prop:s0 exact string
-persist.vendor.face.virtual.lockout_enable u:object_r:virtual_face_hal_prop:s0 exact bool
-persist.vendor.face.virtual.lockout_timed_enable u:object_r:virtual_face_hal_prop:s0 exact bool
-persist.vendor.face.virtual.lockout_timed_threshold u:object_r:virtual_face_hal_prop:s0 exact int
-persist.vendor.face.virtual.lockout_timed_duration u:object_r:virtual_face_hal_prop:s0 exact int
-persist.vendor.face.virtual.lockout_permanent_threshold u:object_r:virtual_face_hal_prop:s0 exact int
-vendor.face.virtual.no_human_face_detected u:object_r:virtual_face_hal_prop:s0 exact bool
-vendor.face.virtual.enrollment_hit u:object_r:virtual_face_hal_prop:s0 exact int
-vendor.face.virtual.next_enrollment u:object_r:virtual_face_hal_prop:s0 exact string
-vendor.face.virtual.authenticator_id u:object_r:virtual_face_hal_prop:s0 exact int
-vendor.face.virtual.challenge u:object_r:virtual_face_hal_prop:s0 exact int
-vendor.face.virtual.lockout u:object_r:virtual_face_hal_prop:s0 exact bool
-vendor.face.virtual.operation_authenticate_fails u:object_r:virtual_face_hal_prop:s0 exact bool
-vendor.face.virtual.operation_detect_interaction_fails u:object_r:virtual_face_hal_prop:s0 exact bool
-vendor.face.virtual.operation_enroll_fails u:object_r:virtual_face_hal_prop:s0 exact bool
-vendor.face.virtual.operation_authenticate_latency u:object_r:virtual_face_hal_prop:s0 exact string
-vendor.face.virtual.operation_detect_interaction_latency u:object_r:virtual_face_hal_prop:s0 exact string
-vendor.face.virtual.operation_enroll_latency u:object_r:virtual_face_hal_prop:s0 exact string
-vendor.face.virtual.operation_authenticate_duration u:object_r:virtual_face_hal_prop:s0 exact int
+persist.vendor.face.virtual.type u:object_r:virtual_face_prop:s0 exact string
+persist.vendor.face.virtual.strength u:object_r:virtual_face_prop:s0 exact string
+persist.vendor.face.virtual.enrollments u:object_r:virtual_face_prop:s0 exact string
+persist.vendor.face.virtual.features u:object_r:virtual_face_prop:s0 exact string
+persist.vendor.face.virtual.lockout_enable u:object_r:virtual_face_prop:s0 exact bool
+persist.vendor.face.virtual.lockout_timed_enable u:object_r:virtual_face_prop:s0 exact bool
+persist.vendor.face.virtual.lockout_timed_threshold u:object_r:virtual_face_prop:s0 exact int
+persist.vendor.face.virtual.lockout_timed_duration u:object_r:virtual_face_prop:s0 exact int
+persist.vendor.face.virtual.lockout_permanent_threshold u:object_r:virtual_face_prop:s0 exact int
+vendor.face.virtual.no_human_face_detected u:object_r:virtual_face_prop:s0 exact bool
+vendor.face.virtual.enrollment_hit u:object_r:virtual_face_prop:s0 exact int
+vendor.face.virtual.next_enrollment u:object_r:virtual_face_prop:s0 exact string
+vendor.face.virtual.authenticator_id u:object_r:virtual_face_prop:s0 exact int
+vendor.face.virtual.challenge u:object_r:virtual_face_prop:s0 exact int
+vendor.face.virtual.lockout u:object_r:virtual_face_prop:s0 exact bool
+vendor.face.virtual.operation_authenticate_fails u:object_r:virtual_face_prop:s0 exact bool
+vendor.face.virtual.operation_detect_interaction_fails u:object_r:virtual_face_prop:s0 exact bool
+vendor.face.virtual.operation_enroll_fails u:object_r:virtual_face_prop:s0 exact bool
+vendor.face.virtual.operation_authenticate_latency u:object_r:virtual_face_prop:s0 exact string
+vendor.face.virtual.operation_detect_interaction_latency u:object_r:virtual_face_prop:s0 exact string
+vendor.face.virtual.operation_enroll_latency u:object_r:virtual_face_prop:s0 exact string
+vendor.face.virtual.operation_authenticate_duration u:object_r:virtual_face_prop:s0 exact int
 
 # properties for the virtual Fingerprint HAL
 persist.vendor.fingerprint.virtual.type u:object_r:virtual_fingerprint_prop:s0 exact string
diff --git a/private/virtual_face.te b/private/virtual_face.te
index 0e33d6b26..9a805e817 100644
--- a/private/virtual_face.te
+++ b/private/virtual_face.te
@@ -4,3 +4,4 @@ type virtual_face_exec, system_file_type, exec_type, file_type;
 hal_server_domain(virtual_face, hal_face)
 typeattribute virtual_face coredomain;
 init_daemon_domain(virtual_face)
+set_prop(virtual_face, virtual_face_prop)
diff --git a/public/property.te b/public/property.te
index fa89cbb14..a186f0425 100644
--- a/public/property.te
+++ b/public/property.te
@@ -276,7 +276,10 @@ system_internal_prop(default_prop)
 vendor_internal_prop(rebootescrow_hal_prop)
 
 # Properties used in the default Face HAL implementations
-system_public_prop(virtual_face_hal_prop)
+vendor_internal_prop(virtual_face_hal_prop)
+starting_at_board_api(202504, `
+    system_public_prop(virtual_face_prop)
+')
 
 # Properties used in the default Fingerprint HAL implementations
 vendor_internal_prop(virtual_fingerprint_hal_prop)
diff --git a/vendor/hal_face_default.te b/vendor/hal_face_default.te
index 3d608cd10..b9815ec67 100644
--- a/vendor/hal_face_default.te
+++ b/vendor/hal_face_default.te
@@ -8,7 +8,10 @@ init_daemon_domain(hal_face_default)
 allow hal_face_default fwk_sensor_service:service_manager find;
 
 # virtual_face_hal_prop is only for debuggable builds
-userdebug_or_eng(`set_prop(hal_face_default, virtual_face_hal_prop)');
+starting_at_board_api(202504, `
+  set_prop(hal_face_default, virtual_face_prop)
+')
+
 neverallow { domain -init -dumpstate userdebug_or_eng(`-hal_face_default') not_compatible_property(`-vendor_init') } virtual_face_hal_prop:file no_rw_file_perms;
 neverallow { domain -init userdebug_or_eng(`-hal_face_default') not_compatible_property(`-vendor_init') } virtual_face_hal_prop:property_service set;
 
```

