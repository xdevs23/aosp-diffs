```diff
diff --git a/Android.bp b/Android.bp
index d590d80a..ace67054 100644
--- a/Android.bp
+++ b/Android.bp
@@ -53,9 +53,9 @@ license {
 }
 
 cc_library_headers {
-  name: "virgl_headers",
-  host_supported: true,
-  export_include_dirs: ["src"],
+    name: "virgl_headers",
+    host_supported: true,
+    export_include_dirs: ["src"],
 }
 
 cc_library {
@@ -121,14 +121,12 @@ cc_library {
         "src/vrend_tweaks.c",
         "src/vrend_winsys.c",
         "src/vrend_winsys_egl.c",
-        "src/vrend_winsys_gbm.c",
+        "src/vrend_winsys_gbm_stubs.c",
     ],
     target: {
         host_linux: {
             shared_libs: [
-                "libdrm",
                 "libepoxy",
-                "libgbm",
             ],
         },
         linux_glibc: {
@@ -165,9 +163,7 @@ cc_library {
                 "liblog",
             ],
             static_libs: [
-                "libdrm",
                 "libepoxy",
-                "libgbm",
             ],
         },
     },
diff --git a/OWNERS b/OWNERS
index e24efbb1..6e0bbdf3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
-adelva@google.com
-natsu@google.com
+gurchetansingh@google.com
+dextero@google.com
diff --git a/meson.build b/meson.build
index ddb74daa..e75d84ed 100644
--- a/meson.build
+++ b/meson.build
@@ -205,8 +205,7 @@ endif
 
 if with_egl
    if cc.has_header('epoxy/egl.h', dependencies: epoxy_dep) and epoxy_dep.get_pkgconfig_variable('epoxy_has_egl') == '1'
-      gbm_dep = dependency('gbm', version: '>= ' + _gbm_ver, required: require_egl)
-      have_egl = gbm_dep.found()
+      have_egl = true
       if (have_egl)
          conf_data.set('HAVE_EPOXY_EGL_H', 1)
       else
diff --git a/src/meson.build b/src/meson.build
index d78ac8c9..2888d22a 100644
--- a/src/meson.build
+++ b/src/meson.build
@@ -64,8 +64,7 @@ virglrenderer_sources = [
 ]
 
 vrend_winsys_egl_sources = [
-   'vrend_winsys_gbm.c',
-   'vrend_winsys_gbm.h',
+   'vrend_winsys_gbm_stubs.c',
    'vrend_winsys_egl.c',
    'vrend_winsys_egl.h',
 ]
@@ -188,7 +187,6 @@ virgl_sources += vrend_sources
 
 if have_egl
    virgl_sources += vrend_winsys_egl_sources
-   virgl_depends += [gbm_dep]
 endif
 
 if have_glx
diff --git a/src/vrend_winsys_egl.c b/src/vrend_winsys_egl.c
index 2c14dcf7..fb7c6bf9 100644
--- a/src/vrend_winsys_egl.c
+++ b/src/vrend_winsys_egl.c
@@ -36,16 +36,14 @@
 #include <poll.h>
 #include <stdbool.h>
 #include <unistd.h>
-#include <xf86drm.h>
 
 #include "util/u_memory.h"
-
+#include "virgl_hw.h"
+#include "virgl_util.h"
 #include "virglrenderer.h"
 #include "vrend_winsys.h"
 #include "vrend_winsys_egl.h"
-#include "virgl_hw.h"
 #include "vrend_winsys_gbm.h"
-#include "virgl_util.h"
 
 #define EGL_KHR_SURFACELESS_CONTEXT            BIT(0)
 #define EGL_KHR_CREATE_CONTEXT                 BIT(1)
diff --git a/src/vrend_winsys_gbm.h b/src/vrend_winsys_gbm.h
index 84943fba..b8d8149a 100644
--- a/src/vrend_winsys_gbm.h
+++ b/src/vrend_winsys_gbm.h
@@ -25,7 +25,6 @@
 #ifndef VIRGL_GBM_H
 #define VIRGL_GBM_H
 
-#include <gbm.h>
 #include "vrend_iov.h"
 #include "virglrenderer.h"
 
@@ -96,6 +95,10 @@ int gbm_get_default_device_fd(void);
  * query. If fd < 0, the gbm device was opened with the fd provided by the
  * (*get_drm_fd) hook.
  */
+
+struct gbm_device;
+struct gbm_bo;
+
 struct virgl_gbm {
    int fd;
    struct gbm_device *device;
diff --git a/src/vrend_winsys_gbm_stubs.c b/src/vrend_winsys_gbm_stubs.c
new file mode 100644
index 00000000..166755fb
--- /dev/null
+++ b/src/vrend_winsys_gbm_stubs.c
@@ -0,0 +1,66 @@
+/**************************************************************************
+ *
+ * Copyright (C) 2024 AOSP..
+ *
+ * Permission is hereby granted, free of charge, to any person obtaining a
+ * copy of this software and associated documentation files (the "Software"),
+ * to deal in the Software without restriction, including without limitation
+ * the rights to use, copy, modify, merge, publish, distribute, sublicense,
+ * and/or sell copies of the Software, and to permit persons to whom the
+ * Software is furnished to do so, subject to the following conditions:
+ *
+ * The above copyright notice and this permission notice shall be included
+ * in all copies or substantial portions of the Software.
+ *
+ * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
+ * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+ * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
+ * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
+ * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
+ * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
+ * OTHER DEALINGS IN THE SOFTWARE.
+ *
+ **************************************************************************/
+
+#include "vrend_winsys_gbm.h"
+#include <stddef.h>
+
+struct virgl_gbm *virgl_gbm_init(int fd) { return NULL; }
+
+void virgl_gbm_fini(struct virgl_gbm *gbm) {
+	return;
+}
+
+int virgl_gbm_convert_format(uint32_t *virgl_format, uint32_t *gbm_format) {
+  return 0;
+}
+
+int virgl_gbm_transfer(struct gbm_bo *bo, uint32_t direction,
+                       const struct iovec *iovecs, uint32_t num_iovecs,
+                       const struct vrend_transfer_info *info) {
+  return 0;
+}
+
+uint32_t virgl_gbm_convert_flags(uint32_t virgl_bind_flags) { return 0; }
+
+int virgl_gbm_export_fd(struct gbm_device *gbm, uint32_t handle,
+                        int32_t *out_fd) {
+  return 0;
+}
+
+int virgl_gbm_export_query(struct gbm_bo *bo,
+                           struct virgl_renderer_export_query *query) {
+  return 0;
+}
+
+int virgl_gbm_get_plane_width(struct gbm_bo *bo, int plane) { return 0; }
+
+int virgl_gbm_get_plane_height(struct gbm_bo *bo, int plane) { return 0; }
+
+int virgl_gbm_get_plane_bytes_per_pixel(struct gbm_bo *bo, int plane) {
+  return 0;
+}
+
+bool virgl_gbm_external_allocation_preferred(uint32_t flags) { return false; }
+
+bool virgl_gbm_gpu_import_required(uint32_t flags) { return false; }
```

